"""GAP-003 G3 operator override, remediation candidate (schema v2).

An override lets exactly one call through, once, before it expires, only when:

* the policy's denial is ``role_not_permitted`` (OQ-1 closed allowlist; every
  mandatory denial was already passed before the role was consulted);
* the document is signed with an Ed25519 key that the anchored, pinned key
  registry lists as valid at decision time (D-3);
* the signed context equals what the hook recomputes now: the request digest,
  the overridden rule, the resolved target, the target's filesystem identity,
  and the policy digest of the running enforcement manifest (R2, D-4);
* its nonce has not been used. The nonce is claimed only after every other
  check has passed (TX-1), by a unique-key insert (TX-2).

The hook holds only public keys. The private key stays with the operator, off
the agent's host or under an identity the agent cannot read.

Validation (``validate``) never consumes state. Consumption (``claim``) runs
afterwards, and the key's status is checked again after the claim (TX-3).
Baseline-format (v1) documents are refused with ``unknown_schema``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from core.authority.canonical import JCS_RFC8785, canonicalize
from core.authority.replay import ReplayStoreError
from runtime.claude_code_gate import registry as key_registry

OVERRIDE_SCHEMA = "weaver.claude_code_gate.override.v2"
MAX_LIFETIME = timedelta(minutes=15)
CLOCK_SKEW = timedelta(seconds=30)
SIGNED_FIELDS = (
    "schema", "operator_id", "key_id", "reason", "nonce", "issued_at", "expires_at",
    "policy_digest", "overridden_rule", "resolved_target", "target_identity", "request_sha256",
)
# Fields recomputed by the hook and compared to the signed values (C).
CONTEXT_FIELDS = ("request_sha256", "overridden_rule", "resolved_target", "target_identity")

_HEX = re.compile(r"^[0-9a-f]+$")


def _crypto():
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    return Ed25519PrivateKey, Ed25519PublicKey, InvalidSignature


@dataclass(frozen=True)
class LiveContext:
    """What the hook recomputed for this call."""
    request_sha256: str
    overridden_rule: str
    resolved_target: str | None
    target_identity: str | None
    policy_digest: str

    def signing_context(self) -> dict[str, Any]:
        return {
            "request_sha256": self.request_sha256,
            "overridden_rule": self.overridden_rule,
            "resolved_target": self.resolved_target if self.resolved_target is not None else "",
            "target_identity": self.target_identity if self.target_identity is not None else "",
            "policy_digest": self.policy_digest,
        }


def message(doc: Mapping[str, Any]) -> bytes:
    return canonicalize({k: doc[k] for k in SIGNED_FIELDS}, JCS_RFC8785).encode("utf-8")


def _parse_time(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("bad_timestamp")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("bad_timestamp")
    return parsed


def sign(private_key_bytes: bytes, *, key_id: str, operator_id: str, reason: str, nonce: str,
         issued_at: datetime, lifetime: timedelta, context: Mapping[str, Any]) -> dict[str, Any]:
    """Operator side. Never called by the hook. ``context`` is a pending request's signing context."""
    private_cls, _, _ = _crypto()
    key = private_cls.from_private_bytes(private_key_bytes)
    doc: dict[str, Any] = {
        "schema": OVERRIDE_SCHEMA,
        "operator_id": operator_id,
        "key_id": key_id,
        "reason": reason,
        "nonce": nonce,
        "issued_at": issued_at.astimezone(timezone.utc).isoformat(),
        "expires_at": (issued_at + lifetime).astimezone(timezone.utc).isoformat(),
        **{k: context[k] for k in ("policy_digest", *CONTEXT_FIELDS)},
    }
    doc["signature"] = key.sign(message(doc)).hex()
    return doc


def validate(doc: Any, *, live: LiveContext, keys: dict[str, key_registry.KeyEntry], now: datetime) -> str | None:
    """Step 8. Return None if the document would authorize this call, else the reason. Consumes nothing."""
    if not isinstance(doc, Mapping):
        return "malformed"
    if doc.get("schema") != OVERRIDE_SCHEMA:
        return "unknown_schema"
    if set(doc) != set(SIGNED_FIELDS) | {"signature"}:
        return "malformed"
    if any(not isinstance(doc[k], str) for k in (*SIGNED_FIELDS, "signature")):
        return "malformed"
    if any(not doc[k] for k in ("operator_id", "key_id", "nonce", "issued_at", "expires_at", "policy_digest",
                                "overridden_rule", "request_sha256", "signature")):
        return "malformed"
    try:
        issued, expires = _parse_time(doc["issued_at"]), _parse_time(doc["expires_at"])
    except ValueError:
        return "bad_timestamp"

    # K: key registered and valid at decision time.
    entry = keys.get(doc["key_id"])
    if entry is None:
        return "unknown_key"
    problem = key_registry.key_problem(entry, at=now, issued_at=issued)
    if problem:
        return problem

    # S: signature under that key.
    _, public_cls, invalid_signature = _crypto()
    if not _HEX.match(doc["signature"]):
        return "bad_signature"
    try:
        public_cls.from_public_bytes(bytes.fromhex(entry.public_key_hex)).verify(bytes.fromhex(doc["signature"]), message(doc))
    except (invalid_signature, ValueError):
        return "bad_signature"

    # Policy digest of the running enforcement manifest.
    if doc["policy_digest"] != live.policy_digest:
        return "policy_digest_mismatch"

    # C: signed context equals recomputed context; key bound to its operator.
    expected = live.signing_context()
    if any(doc[k] != expected[k] for k in CONTEXT_FIELDS) or doc["operator_id"] != entry.operator_id:
        return "context_mismatch"
    if live.overridden_rule != "role_not_permitted":  # defence in depth; the hook already applies OQ-1
        return "not_overridable"

    # Validity window.
    if expires - issued > MAX_LIFETIME:
        return "lifetime_too_long"
    if issued - now > CLOCK_SKEW:
        return "not_yet_valid"
    if now >= expires:
        return "expired"
    return None


def claim(doc: Mapping[str, Any], store) -> str | None:
    """Step 9. Claim the nonce by unique-key insert. None on success."""
    try:
        fresh = store.check_and_store(f"operator-override:{doc['nonce']}")
    except ReplayStoreError:
        return "nonce_store_unavailable"
    return None if fresh else "replayed"


def recheck_key(doc: Mapping[str, Any], keys: dict[str, key_registry.KeyEntry], now: datetime) -> str | None:
    """TX-3: the key's status, checked again after the claim."""
    entry = keys.get(doc["key_id"])
    if entry is None:
        return "key_revoked"
    return key_registry.key_problem(entry, at=now, issued_at=_parse_time(doc["issued_at"]))


def load_override(state_dir: Path, request_sha256: str) -> tuple[Any, str | None]:
    """(document, problem). (None, None) when no override file exists for this request."""
    path = state_dir / "overrides" / f"{request_sha256}.json"
    if not path.exists() and not path.is_symlink():
        return None, None
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except (OSError, ValueError, UnicodeDecodeError):
        return None, "malformed"


def audit_record(doc: Mapping[str, Any]) -> dict[str, Any]:
    return {k: doc.get(k) for k in ("schema", "operator_id", "key_id", "reason", "nonce", "issued_at",
                                    "expires_at", "policy_digest", "overridden_rule")}

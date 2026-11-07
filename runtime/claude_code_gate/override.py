"""GAP-003-G3: operator override, signed with a key the agent cannot use.

An override lets exactly one denied tool call through, once, before it
expires, and only when an operator signed it. The hook holds only the
operator's Ed25519 public key. The private key stays with the operator, off
the agent's host or under an identity the agent cannot read. So:

* the agent cannot produce a valid override, even if it can write files, read
  this code, or read the public key;
* the override is bound to one request (the sha256 of the tool, its input,
  role, ceiling and agent id), so it cannot be reused for another call;
* it is single-use (its nonce is consumed in a persistent replay store) and
  short-lived (at most 15 minutes);
* it cannot unlock the gate's own protected paths or malformed calls;
* every use, and every rejected attempt, is recorded in the chronicle.

Why not the shared-key HMAC override in core/authority/gate.py: a Claude Code
hook runs as the same user as the agent. Any key the hook can read to verify
an HMAC, the agent can read and use to sign one. Only an asymmetric signature
separates "can check" from "can issue".

The public key comes from WEAVER_GATE_OPERATOR_PUBKEY (hex, 32 bytes), which
.claude/settings.json sets. That file has to be protected from the agent at
the operating-system level (G1). If the agent could change it, it could pin
its own key.

Override files live at <project>/.weaver/gate/overrides/<request_sha256>.json.
Where they are written does not affect validity: a forged file fails the
signature check.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping

from core.authority.canonical import JCS_RFC8785, canonicalize
from core.authority.replay import SqliteReplayStore

OVERRIDE_SCHEMA = "weaver.claude_code_gate.override.v1"
MAX_LIFETIME = timedelta(minutes=15)
CLOCK_SKEW = timedelta(seconds=30)
SIGNED_FIELDS = ("schema", "request_sha256", "operator_id", "reason", "nonce", "issued_at", "expires_at", "key_fingerprint")

# Denials an override can never lift. The gate's own files are edited by the
# operator directly, not through the agent. The rest cannot be identified
# well enough to bind an override to them.
NON_OVERRIDABLE_RULES = frozenset({
    "protected_path",
    "bash_protected_path",
    "malformed_call",
    "unknown_role",
    "unknown_ceiling",
    "missing_path",
    "missing_command",
    "unparseable",
})

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class OverrideError(ValueError):
    pass


def _crypto():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    except ImportError:  # pragma: no cover - exercised when the package is absent
        return None
    return Ed25519PrivateKey, Ed25519PublicKey, InvalidSignature


def fingerprint(public_key_hex: str) -> str:
    return sha256(bytes.fromhex(public_key_hex)).hexdigest()


def pinned_public_key(env: Mapping[str, str]) -> str | None:
    """The operator's public key, from the environment only. None disables overrides."""
    raw = (env.get("WEAVER_GATE_OPERATOR_PUBKEY") or "").strip().lower()
    return raw if _HEX64.match(raw) else None


def _message(doc: Mapping[str, Any]) -> bytes:
    return canonicalize({k: doc[k] for k in SIGNED_FIELDS}, JCS_RFC8785).encode("utf-8")


def _parse_time(value: Any) -> datetime:
    if not isinstance(value, str):
        raise OverrideError("bad_timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise OverrideError("bad_timestamp") from exc
    if parsed.tzinfo is None:
        raise OverrideError("bad_timestamp")
    return parsed


def sign(private_key_bytes: bytes, *, request_sha256: str, operator_id: str, reason: str, nonce: str,
         issued_at: datetime, lifetime: timedelta) -> dict[str, Any]:
    """Operator side. Never called by the hook."""
    crypto = _crypto()
    if crypto is None:
        raise OverrideError("cryptography is not installed")
    private_cls, _, _ = crypto
    key = private_cls.from_private_bytes(private_key_bytes)
    public_hex = key.public_key().public_bytes_raw().hex()
    doc: dict[str, Any] = {
        "schema": OVERRIDE_SCHEMA,
        "request_sha256": request_sha256,
        "operator_id": operator_id,
        "reason": reason,
        "nonce": nonce,
        "issued_at": issued_at.astimezone(timezone.utc).isoformat(),
        "expires_at": (issued_at + lifetime).astimezone(timezone.utc).isoformat(),
        "key_fingerprint": fingerprint(public_hex),
    }
    doc["signature"] = key.sign(_message(doc)).hex()
    return doc


def check(doc: Any, *, request_sha256: str, public_key_hex: str | None, rule: str, now: datetime,
          replay_store: SqliteReplayStore) -> str | None:
    """Return None if the override is valid (and consume its nonce), else the reason it is not."""
    if public_key_hex is None:
        return "overrides_not_configured"
    crypto = _crypto()
    if crypto is None:
        return "crypto_unavailable"
    if rule in NON_OVERRIDABLE_RULES:
        return "not_overridable"
    if not isinstance(doc, Mapping) or set(doc) != set(SIGNED_FIELDS) | {"signature"}:
        return "malformed"
    if any(not isinstance(doc[k], str) or not doc[k] for k in (*SIGNED_FIELDS, "signature")):
        return "malformed"
    if doc["schema"] != OVERRIDE_SCHEMA:
        return "unknown_schema"
    if doc["request_sha256"] != request_sha256:
        return "wrong_request"
    if doc["key_fingerprint"] != fingerprint(public_key_hex):
        return "unknown_key"

    _, public_cls, invalid_signature = crypto
    try:
        public_cls.from_public_bytes(bytes.fromhex(public_key_hex)).verify(bytes.fromhex(doc["signature"]), _message(doc))
    except (invalid_signature, ValueError):
        return "bad_signature"

    # Timing is checked only after the signature, so an unsigned document
    # learns nothing and spends nothing.
    try:
        issued, expires = _parse_time(doc["issued_at"]), _parse_time(doc["expires_at"])
    except OverrideError as exc:
        return str(exc)
    if expires - issued > MAX_LIFETIME:
        return "lifetime_too_long"
    if issued - now > CLOCK_SKEW:
        return "not_yet_valid"
    if now >= expires:
        return "expired"
    if not replay_store.check_and_store(f"operator-override:{doc['nonce']}"):
        return "replayed"
    return None


def load_override(state_dir: Path, request_sha256: str) -> tuple[Any, str | None]:
    """(document, problem). (None, None) when no override file exists for this request."""
    path = state_dir / "overrides" / f"{request_sha256}.json"
    if not path.is_file():
        return None, None
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None, "malformed"


def audit_record(doc: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": doc.get("schema"),
        "operator_id": doc.get("operator_id"),
        "reason": doc.get("reason"),
        "nonce": doc.get("nonce"),
        "issued_at": doc.get("issued_at"),
        "expires_at": doc.get("expires_at"),
        "key_fingerprint": doc.get("key_fingerprint"),
    }

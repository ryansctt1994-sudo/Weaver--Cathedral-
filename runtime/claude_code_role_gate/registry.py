"""GAP-003 D-3: operator keys come from a registry pinned by the anchor.

Schema ``weaver.gate.key_registry.v1``:

    {"schema": "weaver.gate.key_registry.v1",
     "keys": [{"key_id": "op-2026-01", "algorithm": "ed25519",
               "public_key_hex": "<64 hex>", "fingerprint": "<sha256 of key bytes>",
               "operator_id": "<named operator>",
               "not_before": "<RFC 3339 UTC>", "not_after": "<RFC 3339 UTC>",
               "status": "active" | "retired" | "revoked", "revoked_at": null | "<RFC 3339>"}]}

The anchor carries the registry's SHA-256. A registry whose bytes do not match
that pin is not trusted, and every override is denied ``registry_untrusted``.

Validity at decision time t (and for retired keys, the document's issued_at):
* revoked, or revoked_at <= t        -> ``key_revoked`` (signing time does not rescue it)
* t < not_before                      -> ``key_not_yet_valid``
* t >= not_after                      -> ``key_expired``
* retired: issued_at must lie in [not_before, not_after), else ``key_expired``
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from pathlib import Path

REGISTRY_SCHEMA = "weaver.gate.key_registry.v1"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_STATUSES = frozenset({"active", "retired", "revoked"})


class RegistryError(Exception):
    def __init__(self, rule: str, detail: str = ""):
        super().__init__(f"{rule}: {detail}" if detail else rule)
        self.rule = rule


@dataclass(frozen=True)
class KeyEntry:
    key_id: str
    public_key_hex: str
    fingerprint: str
    operator_id: str
    not_before: datetime
    not_after: datetime
    status: str
    revoked_at: datetime | None


def _time(value) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must carry a time zone")
    return parsed


def fingerprint(public_key_hex: str) -> str:
    return sha256(bytes.fromhex(public_key_hex)).hexdigest()


def load_registry(path: Path | None, pinned_sha256: str | None) -> dict[str, KeyEntry]:
    if path is None or pinned_sha256 is None:
        raise RegistryError("overrides_not_configured", "the anchor names no key registry")
    try:
        raw = path.read_bytes()
    except OSError:
        raise RegistryError("registry_untrusted", "registry unreadable") from None
    if sha256(raw).hexdigest() != pinned_sha256:
        raise RegistryError("registry_untrusted", "registry does not match the anchored pin")
    try:
        doc = json.loads(raw.decode("utf-8"))
        if doc.get("schema") != REGISTRY_SCHEMA or not isinstance(doc.get("keys"), list):
            raise ValueError("schema")
        entries: dict[str, KeyEntry] = {}
        for k in doc["keys"]:
            pub = k["public_key_hex"]
            if k.get("algorithm") != "ed25519" or not _HEX64.match(pub) or k["fingerprint"] != fingerprint(pub):
                raise ValueError("key material")
            if k["status"] not in _STATUSES or not isinstance(k["key_id"], str) or not isinstance(k["operator_id"], str):
                raise ValueError("key fields")
            if k["key_id"] in entries:
                raise ValueError("duplicate key_id")
            entries[k["key_id"]] = KeyEntry(
                k["key_id"], pub, k["fingerprint"], k["operator_id"],
                _time(k["not_before"]), _time(k["not_after"]), k["status"],
                _time(k["revoked_at"]) if k.get("revoked_at") is not None else None,
            )
    except (KeyError, TypeError, ValueError, AttributeError):
        raise RegistryError("registry_untrusted", "registry malformed") from None
    return entries


def key_problem(entry: KeyEntry, *, at: datetime, issued_at: datetime) -> str | None:
    """None if entry may authorize a decision at time ``at``, else the denial reason."""
    if entry.status == "revoked" or (entry.revoked_at is not None and entry.revoked_at <= at):
        return "key_revoked"
    if at < entry.not_before:
        return "key_not_yet_valid"
    if at >= entry.not_after:
        return "key_expired"
    if entry.status == "retired" and not (entry.not_before <= issued_at < entry.not_after):
        return "key_expired"
    return None

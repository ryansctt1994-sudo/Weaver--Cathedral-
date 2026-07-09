"""Deterministic receipt utilities."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from .models import AuthorityEnvelope, Receipt


def canonical_json(value: Any) -> str:
    """Return stable JSON for hashing and replay.

    This is the tiny clockwork heart of Phase 1: sorted keys, compact
    separators, UTF-8 semantics, and no ambient randomness.
    """

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def payload_hash(payload: dict[str, Any]) -> str:
    return sha256_json(payload)


def generate_receipt(
    envelope: AuthorityEnvelope,
    *,
    accepted: bool,
    reason: str,
    created_at: datetime | None = None,
) -> Receipt:
    """Generate a deterministic receipt for a verification event.

    If created_at is omitted, the current UTC time is used. Tests may pass a
    fixed timestamp for deterministic assertions.
    """

    timestamp = created_at or datetime.now(timezone.utc)
    timestamp = timestamp.astimezone(timezone.utc)

    base = {
        "receipt_version": "weaver.authority.receipt.v1",
        "envelope_id": envelope.envelope_id,
        "issuer": envelope.issuer,
        "subject": envelope.subject,
        "claim": envelope.claim,
        "evidence_level": envelope.evidence_level,
        "accepted": accepted,
        "reason": reason,
        "payload_hash": envelope.payload_hash,
        "created_at": timestamp.isoformat(),
    }

    return Receipt(**base, receipt_hash=sha256_json(base))


def verify_receipt(receipt: Receipt) -> bool:
    base = receipt.model_dump(mode="json")
    expected = base.pop("receipt_hash")
    return sha256_json(base) == expected

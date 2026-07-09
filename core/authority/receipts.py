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


def canonical_timestamp(value: datetime) -> str:
    """Return the exact timestamp form used inside receipt hashes."""

    return value.astimezone(timezone.utc).isoformat()


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def payload_hash(payload: dict[str, Any]) -> str:
    return sha256_json(payload)


def receipt_hash_base(receipt: Receipt) -> dict[str, Any]:
    """Build the canonical hash base for a receipt.

    Pydantic may serialize UTC datetimes with a trailing ``Z`` in JSON mode,
    while ``datetime.isoformat()`` emits ``+00:00``. The receipt hash must not
    depend on that serializer detail, so we normalize explicitly here.
    """

    return {
        "receipt_version": receipt.receipt_version,
        "envelope_id": receipt.envelope_id,
        "issuer": receipt.issuer,
        "subject": receipt.subject,
        "claim": receipt.claim,
        "evidence_level": receipt.evidence_level,
        "accepted": receipt.accepted,
        "reason": receipt.reason,
        "payload_hash": receipt.payload_hash,
        "created_at": canonical_timestamp(receipt.created_at),
    }


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
        "created_at": canonical_timestamp(timestamp),
    }

    return Receipt(**base, receipt_hash=sha256_json(base))


def verify_receipt(receipt: Receipt) -> bool:
    return sha256_json(receipt_hash_base(receipt)) == receipt.receipt_hash

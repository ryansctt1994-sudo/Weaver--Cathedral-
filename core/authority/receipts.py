"""Deterministic receipt utilities."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from .canonical import DEFAULT_PROFILE, PROFILES, WEAVER_C14N_V1, profiled_sha256, verify_profiled_sha256
from .models import AuthorityEnvelope, Receipt

RECEIPT_V1 = "weaver.authority.receipt.v1"
RECEIPT_V2 = "weaver.authority.receipt.v2"


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

    v1: exactly the fields v1 receipts were always hashed over.
    v2: the same fields plus ``hash_profile``, so the profile is itself bound
    into the hash and can't be swapped after the fact.
    """

    base = {
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
    if receipt.receipt_version == RECEIPT_V2:
        base["hash_profile"] = receipt.hash_profile
    return base


def generate_receipt(
    envelope: AuthorityEnvelope,
    *,
    accepted: bool,
    reason: str,
    created_at: datetime | None = None,
    receipt_version: str = RECEIPT_V2,
    hash_profile: str = DEFAULT_PROFILE,
) -> Receipt:
    """Generate a deterministic receipt for a verification event.

    If created_at is omitted, the current UTC time is used. Tests may pass a
    fixed timestamp for deterministic assertions.

    New receipts are v2 under ``hash_profile`` (RFC 8785 JCS by default).
    ``receipt_version=RECEIPT_V1`` reproduces legacy receipts exactly.
    """

    timestamp = created_at or datetime.now(timezone.utc)
    if receipt_version == RECEIPT_V1:
        profile = None
    elif receipt_version == RECEIPT_V2:
        if hash_profile not in PROFILES:
            raise ValueError(f"unknown hash profile {hash_profile!r}")
        profile = hash_profile
    else:
        raise ValueError(f"unknown receipt version {receipt_version!r}")

    draft = Receipt(
        receipt_version=receipt_version,
        hash_profile=profile,
        envelope_id=envelope.envelope_id,
        issuer=envelope.issuer,
        subject=envelope.subject,
        claim=envelope.claim,
        evidence_level=envelope.evidence_level,
        accepted=accepted,
        reason=reason,
        payload_hash=envelope.payload_hash,
        created_at=timestamp,
        receipt_hash="0" * 64,
    )
    base = receipt_hash_base(draft)
    digest = sha256_json(base) if profile is None else profiled_sha256(base, profile)
    return draft.model_copy(update={"receipt_hash": digest})


def verify_receipt(receipt: Receipt) -> bool:
    """Recompute a receipt's hash under the rules of its own version. Fails closed."""

    if receipt.receipt_version == RECEIPT_V1:
        if receipt.hash_profile is not None:
            return False  # v1 has no profile; one present means it was altered
        return sha256_json(receipt_hash_base(receipt)) == receipt.receipt_hash
    if receipt.receipt_version == RECEIPT_V2:
        if receipt.hash_profile not in PROFILES:
            return False
        return verify_profiled_sha256(receipt_hash_base(receipt), receipt.receipt_hash, receipt.hash_profile)
    return False

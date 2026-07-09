"""Pydantic models for the Phase 1 authority spine."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


EvidenceLevel = Literal["E0", "E1", "E2", "E3", "E4", "E5", "E6"]


class AuthorityEnvelope(BaseModel):
    """A bounded claim submitted for verification.

    Phase 1 intentionally uses deterministic payload hashing rather than
    public-key signatures. Cryptographic signatures belong in a later phase.
    """

    model_config = ConfigDict(extra="forbid")

    envelope_id: str = Field(min_length=1)
    issuer: str = Field(min_length=1)
    subject: str = Field(min_length=1)
    claim: str = Field(min_length=1)
    evidence_level: EvidenceLevel
    nonce: str = Field(min_length=8)
    issued_at: datetime
    payload: dict[str, Any] = Field(default_factory=dict)
    payload_hash: str = Field(pattern=r"^[a-f0-9]{64}$")

    @field_validator("issued_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("issued_at must be timezone-aware")
        return value.astimezone(timezone.utc)


class VerificationResult(BaseModel):
    """Result from envelope verification."""

    model_config = ConfigDict(extra="forbid")

    accepted: bool
    envelope_id: str | None = None
    evidence_level: EvidenceLevel | None = None
    reason: str
    receipt_hash: str | None = None


class Receipt(BaseModel):
    """Deterministic receipt for a verification event."""

    model_config = ConfigDict(extra="forbid")

    receipt_version: str = "weaver.authority.receipt.v1"
    envelope_id: str
    issuer: str
    subject: str
    claim: str
    evidence_level: EvidenceLevel
    accepted: bool
    reason: str
    payload_hash: str
    created_at: datetime
    receipt_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class PromotionDecision(BaseModel):
    """Fail-closed promotion decision."""

    model_config = ConfigDict(extra="forbid")

    artifact_id: str = Field(min_length=1)
    requested_level: EvidenceLevel
    granted: bool
    reason: str
    required_missing: list[str] = Field(default_factory=list)

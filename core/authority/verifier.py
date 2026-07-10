"""Core authority verification functions."""

from __future__ import annotations

from typing import Iterable, Protocol

from pydantic import ValidationError

from .models import AuthorityEnvelope, PromotionDecision, Receipt, VerificationResult
from .receipts import generate_receipt, payload_hash
from .replay import InMemoryReplayCache


class ReplayCacheProtocol(Protocol):
    def check_and_store(
        self,
        nonce: str,
        *,
        payload_hash: str | None = None,
        envelope_id: str | None = None,
    ) -> bool: ...


PROMOTION_REQUIREMENTS: dict[str, set[str]] = {
    "E1": {"declared_claim", "file_scaffold", "risk_boundary"},
    "E2": {"executable_command", "local_tests", "expected_output", "failure_behavior"},
    "E3": {"receipt_bundle", "logs", "synthetic_fixtures", "replay_command", "artifact_hashes", "failure_path"},
    "E4": {"independent_witness", "reproduction_transcript", "environment_details"},
    "E5": {"domain_validation_plan", "qualified_reviewer", "limitations"},
    "E6": {"deployment_controls", "monitoring", "rollback", "incident_response", "compliance_review"},
}


def parse_envelope(raw: dict) -> AuthorityEnvelope:
    return AuthorityEnvelope.model_validate(raw)


def _result_from_receipt(envelope: AuthorityEnvelope, receipt: Receipt) -> VerificationResult:
    return VerificationResult(
        accepted=receipt.accepted,
        envelope_id=envelope.envelope_id,
        evidence_level=envelope.evidence_level,
        reason=receipt.reason,
        receipt_hash=receipt.receipt_hash,
    )


def verify_envelope_with_receipt(
    raw: dict,
    replay_cache: ReplayCacheProtocol | None = None,
) -> tuple[VerificationResult, Receipt | None]:
    """Validate an envelope and return both result and receipt when possible.

    Schema-invalid envelopes cannot produce a receipt because no trusted
    envelope object exists yet. Payload mismatch and replay failures do produce
    receipts because the envelope itself can be parsed and bounded.
    """

    cache = replay_cache or InMemoryReplayCache()

    try:
        envelope = parse_envelope(raw)
    except ValidationError as exc:
        return VerificationResult(accepted=False, reason=f"schema_invalid: {exc.errors()[0]['msg']}"), None

    expected_payload_hash = payload_hash(envelope.payload)
    if expected_payload_hash != envelope.payload_hash:
        receipt = generate_receipt(envelope, accepted=False, reason="payload_hash_mismatch")
        return _result_from_receipt(envelope, receipt), receipt

    if not cache.check_and_store(
        envelope.nonce,
        payload_hash=envelope.payload_hash,
        envelope_id=envelope.envelope_id,
    ):
        receipt = generate_receipt(envelope, accepted=False, reason="replay_detected")
        return _result_from_receipt(envelope, receipt), receipt

    receipt = generate_receipt(envelope, accepted=True, reason="accepted_phase1_bounded")
    return _result_from_receipt(envelope, receipt), receipt


def verify_envelope(raw: dict, replay_cache: ReplayCacheProtocol | None = None) -> VerificationResult:
    """Validate an envelope, reject replay, and generate a receipt hash.

    This is deliberately bounded. It checks schema, payload hash, and nonce
    replay. It does not yet verify public-key signatures.
    """

    result, _receipt = verify_envelope_with_receipt(raw, replay_cache)
    return result


def evaluate_promotion(
    artifact_id: str,
    requested_level: str,
    available_evidence: Iterable[str],
) -> PromotionDecision:
    """Fail-closed promotion evaluation."""

    available = set(available_evidence)
    required = PROMOTION_REQUIREMENTS.get(requested_level)

    if required is None:
        return PromotionDecision(
            artifact_id=artifact_id,
            requested_level="E0",
            granted=False,
            reason=f"unknown_requested_level:{requested_level}",
            required_missing=["valid_requested_level"],
        )

    missing = sorted(required - available)
    if missing:
        return PromotionDecision(
            artifact_id=artifact_id,
            requested_level=requested_level,  # type: ignore[arg-type]
            granted=False,
            reason="promotion_blocked_missing_evidence",
            required_missing=missing,
        )

    return PromotionDecision(
        artifact_id=artifact_id,
        requested_level=requested_level,  # type: ignore[arg-type]
        granted=True,
        reason="promotion_granted_with_declared_evidence",
        required_missing=[],
    )

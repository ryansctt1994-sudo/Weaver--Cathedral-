"""Minimal Weaver Cathedral authority spine.

This package is intentionally small and evidence-disciplined:
- validate envelopes
- reject replay
- generate deterministic receipts
- return promotion decisions without claiming production authority
- hash under named canonical-JSON profiles (RFC 8785 JCS for new formats)
- keep a tamper-evident, hash-chained chronicle
- gate actions on uncertainty, failing closed, with single-use signed overrides
"""

from .canonical import DEFAULT_PROFILE, canonicalize, profiled_sha256, verify_profiled_sha256
from .chronicle import Chronicle, verify_entries, verify_file
from .gate import GateDecision, GateRecord, UncertaintyGate, normalized_entropy, request_hash, sign_override
from .models import AuthorityEnvelope, PromotionDecision, Receipt, VerificationResult
from .replay import InMemoryReplayCache
from .receipts import generate_receipt, verify_receipt
from .verifier import verify_envelope, evaluate_promotion

__all__ = [
    "DEFAULT_PROFILE",
    "canonicalize",
    "profiled_sha256",
    "verify_profiled_sha256",
    "Chronicle",
    "verify_entries",
    "verify_file",
    "GateDecision",
    "GateRecord",
    "UncertaintyGate",
    "normalized_entropy",
    "request_hash",
    "sign_override",
    "AuthorityEnvelope",
    "PromotionDecision",
    "Receipt",
    "VerificationResult",
    "InMemoryReplayCache",
    "generate_receipt",
    "verify_receipt",
    "verify_envelope",
    "evaluate_promotion",
]

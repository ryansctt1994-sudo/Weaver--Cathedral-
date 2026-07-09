"""Minimal Weaver Cathedral authority spine.

This package is intentionally small and evidence-disciplined:
- validate envelopes
- reject replay
- generate deterministic receipts
- return promotion decisions without claiming production authority
"""

from .models import AuthorityEnvelope, PromotionDecision, Receipt, VerificationResult
from .replay import InMemoryReplayCache
from .receipts import generate_receipt, verify_receipt
from .verifier import verify_envelope, evaluate_promotion

__all__ = [
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

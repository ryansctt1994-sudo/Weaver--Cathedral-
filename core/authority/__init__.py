"""Minimal Weaver Cathedral authority spine.

This package is intentionally small and evidence-disciplined:
- validate envelopes
- reject replay
- generate deterministic receipts
- return promotion decisions without claiming production authority
"""

from .bundles import build_receipt_bundle, verify_receipt_bundle
from .models import AuthorityEnvelope, PromotionDecision, Receipt, VerificationResult
from .replay import InMemoryReplayCache, PersistentReplayCache
from .receipts import generate_receipt, verify_receipt
from .verifier import evaluate_promotion, verify_envelope, verify_envelope_with_receipt

__all__ = [
    "AuthorityEnvelope",
    "PromotionDecision",
    "Receipt",
    "VerificationResult",
    "InMemoryReplayCache",
    "PersistentReplayCache",
    "build_receipt_bundle",
    "generate_receipt",
    "verify_receipt",
    "verify_receipt_bundle",
    "verify_envelope",
    "verify_envelope_with_receipt",
    "evaluate_promotion",
]

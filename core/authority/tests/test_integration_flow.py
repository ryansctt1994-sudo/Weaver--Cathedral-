import json
from pathlib import Path

from core.authority.replay import InMemoryReplayCache
from core.authority.verifier import evaluate_promotion, verify_envelope


def test_full_verify_then_promote_e1_flow():
    raw = json.loads(Path("core/authority/fixtures/valid_envelope.json").read_text())
    verification = verify_envelope(raw, InMemoryReplayCache())

    assert verification.accepted
    assert verification.receipt_hash is not None

    decision = evaluate_promotion(
        artifact_id=raw["subject"],
        requested_level="E1",
        available_evidence=["declared_claim", "file_scaffold", "risk_boundary"],
    )

    assert decision.granted
    assert decision.required_missing == []

import json
from pathlib import Path

from core.authority.replay import InMemoryReplayCache
from core.authority.verifier import evaluate_promotion, verify_envelope


def load_fixture(name: str) -> dict:
    return json.loads(Path(f"core/authority/fixtures/{name}").read_text())


def test_verify_accepts_valid_envelope():
    result = verify_envelope(load_fixture("valid_envelope.json"), InMemoryReplayCache())
    assert result.accepted
    assert result.reason == "accepted_phase1_bounded"
    assert result.receipt_hash is not None


def test_verify_rejects_payload_hash_mismatch():
    result = verify_envelope(load_fixture("bad_hash_envelope.json"), InMemoryReplayCache())
    assert not result.accepted
    assert result.reason == "payload_hash_mismatch"


def test_verify_rejects_replay_nonce():
    cache = InMemoryReplayCache()
    raw = load_fixture("valid_envelope.json")
    first = verify_envelope(raw, cache)
    second = verify_envelope(raw, cache)
    assert first.accepted
    assert not second.accepted
    assert second.reason == "replay_detected"


def test_promotion_blocks_missing_evidence():
    decision = evaluate_promotion("artifact-1", "E2", ["local_tests"])
    assert not decision.granted
    assert "executable_command" in decision.required_missing


def test_promotion_grants_when_required_evidence_present():
    decision = evaluate_promotion(
        "artifact-1",
        "E1",
        ["declared_claim", "file_scaffold", "risk_boundary"],
    )
    assert decision.granted

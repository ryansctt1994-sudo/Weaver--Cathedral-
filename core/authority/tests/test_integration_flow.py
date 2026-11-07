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


def test_chronicle_verify_cli(tmp_path):
    from datetime import datetime, timezone

    from core.authority.chronicle import Chronicle
    from core.authority.cli import main

    path = tmp_path / "c.jsonl"
    chron = Chronicle(path)
    chron.append("cli.test", {"i": 1}, recorded_at=datetime(2026, 11, 7, tzinfo=timezone.utc))
    assert main(["chronicle-verify", str(path)]) == 0
    assert main(["chronicle-verify", str(path), "--expected-head", "0" * 64]) == 1
    path.write_text(path.read_text().replace('"i": 1', '"i": 2'))
    assert main(["chronicle-verify", str(path)]) == 1

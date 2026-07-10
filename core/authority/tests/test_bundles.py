from pathlib import Path
import sqlite3

from core.authority.bundles import (
    build_artifact_manifest,
    build_receipt_bundle,
    verify_receipt_bundle,
    write_json,
)


VALID_ENVELOPE = Path("core/authority/fixtures/valid_envelope.json")
BAD_HASH_ENVELOPE = Path("core/authority/fixtures/bad_hash_envelope.json")


def test_receipt_bundle_builds_required_files_and_verifies(tmp_path):
    bundle_dir = tmp_path / "demo_bundle"
    build_receipt_bundle(
        VALID_ENVELOPE,
        bundle_dir,
        failure_fixture_path=BAD_HASH_ENVELOPE,
        fresh=True,
    )

    for filename in [
        "envelope.json",
        "receipt.json",
        "verification_result.json",
        "failure_case_report.json",
        "replay.log",
        "replay.db",
        "REPLAY.md",
        "artifact_manifest.json",
    ]:
        assert (bundle_dir / filename).exists(), filename

    result = verify_receipt_bundle(bundle_dir)
    assert result["valid"]
    assert result["checks"]["receipt_hash_valid"]
    assert result["checks"]["artifact_manifest_valid"]
    assert result["checks"]["failure_cases_passed"]
    assert result["checks"]["replay_evidence_valid"]
    assert result["checks"]["replay_evidence_failures"] == []


def test_receipt_bundle_verification_fails_when_manifest_file_missing(tmp_path):
    bundle_dir = tmp_path / "demo_bundle"
    build_receipt_bundle(
        VALID_ENVELOPE,
        bundle_dir,
        failure_fixture_path=BAD_HASH_ENVELOPE,
        fresh=True,
    )

    (bundle_dir / "replay.log").unlink()
    result = verify_receipt_bundle(bundle_dir)
    assert not result["valid"]
    assert "replay.log" in result["checks"]["missing_files"]


def test_receipt_bundle_verification_rejects_semantically_tampered_replay_db(tmp_path):
    bundle_dir = tmp_path / "demo_bundle"
    build_receipt_bundle(
        VALID_ENVELOPE,
        bundle_dir,
        failure_fixture_path=BAD_HASH_ENVELOPE,
        fresh=True,
    )

    with sqlite3.connect(str(bundle_dir / "replay.db")) as conn:
        conn.execute(
            "UPDATE replay_log SET payload_hash = ?",
            ("f" * 64,),
        )
        conn.commit()

    write_json(bundle_dir / "artifact_manifest.json", build_artifact_manifest(bundle_dir))

    result = verify_receipt_bundle(bundle_dir)
    assert not result["valid"]
    assert not result["checks"]["replay_evidence_valid"]
    assert "replay_log_db_mismatch" in result["checks"]["replay_evidence_failures"]
    assert "replay_record_payload_hash_mismatch" in result["checks"]["replay_evidence_failures"]
    assert "replay_record_hash_mismatch" in result["checks"]["replay_evidence_failures"]

from pathlib import Path

from core.authority.bundles import build_receipt_bundle, verify_receipt_bundle


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

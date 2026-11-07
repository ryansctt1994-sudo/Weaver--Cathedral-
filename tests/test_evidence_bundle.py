"""The authority_spine_001 evidence bundle builds, verifies, replays, and detects tampering."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent.parent / "forge" / "demos" / "authority_spine_001" / "scripts"


def run(script: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(SCRIPTS / script), *args], capture_output=True, text=True)


@pytest.fixture(scope="module")
def bundle(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("evidence") / "bundle"
    result = run("bundle.py", str(out), "--skip-pytest")
    assert result.returncode == 0, result.stdout + result.stderr
    return out


@pytest.fixture
def copy_of(bundle, tmp_path) -> Path:
    import shutil

    dest = tmp_path / "bundle"
    shutil.copytree(bundle, dest)
    return dest


def test_bundle_has_the_gap_005_contents(bundle):
    manifest = json.loads((bundle / "MANIFEST.json").read_text())
    names = set(manifest["bundle_files"])
    assert {"receipts/accept_valid_envelope.json", "receipts/reject_bad_hash.json", "receipts/reject_replay.json"} <= names
    assert {"chronicle.jsonl", "environment.json", "REPLAY.md"} <= names
    failures = {n for n in names if n.startswith("failures/")}
    assert len(failures) == 8
    assert manifest["all_failure_paths_behaved_as_expected"] is True
    assert manifest["source_files"], "tracked source hashes recorded"


def test_bundle_verifies_and_replays_byte_identically(bundle):
    result = run("verify_bundle.py", str(bundle))
    assert result.returncode == 0, result.stdout
    assert "BUNDLE CHECK PASSED" in result.stdout


def test_two_builds_produce_identical_deterministic_files(bundle, tmp_path):
    second = tmp_path / "second"
    assert run("bundle.py", str(second), "--skip-pytest").returncode == 0
    m1 = json.loads((bundle / "MANIFEST.json").read_text())
    m2 = json.loads((second / "MANIFEST.json").read_text())
    for name in m1["deterministic_files"]:
        assert m1["bundle_files"][name] == m2["bundle_files"][name], name
    assert m1["chronicle_head"] == m2["chronicle_head"]


@pytest.mark.parametrize(
    ("tamper", "expected"),
    [
        (lambda b: (b / "receipts" / "accept_valid_envelope.json").write_text(
            (b / "receipts" / "accept_valid_envelope.json").read_text().replace('"accepted": true', '"accepted": false')), "sha256 mismatch"),
        (lambda b: (b / "failures" / "nonce_replay.json").unlink(), "listed in manifest but missing"),
        (lambda b: (b / "receipts" / "planted.json").write_text("{}"), "in bundle but not in manifest"),
        (lambda b: (b / "MANIFEST.json").write_text(
            (b / "MANIFEST.json").read_text().replace('"all_failure_paths_behaved_as_expected": true', '"all_failure_paths_behaved_as_expected": false')),
         "manifest_hash does not match"),
    ],
    ids=["edit-receipt", "delete-transcript", "plant-file", "edit-manifest"],
)
def test_tampered_bundle_fails_verification(copy_of, tamper, expected):
    tamper(copy_of)
    result = run("verify_bundle.py", str(copy_of), "--no-replay")
    assert result.returncode == 1
    assert expected in result.stdout, result.stdout


def test_consistently_re_hashed_receipt_edit_is_still_caught(copy_of):
    # An attacker who edits a receipt AND updates its manifest hash AND the
    # manifest hash still can't make the receipt itself verify.
    import hashlib

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from core.authority.canonical import canonicalize

    path = copy_of / "receipts" / "accept_valid_envelope.json"
    path.write_text(path.read_text().replace('"accepted": true', '"accepted": false'))
    manifest = json.loads((copy_of / "MANIFEST.json").read_text())
    manifest["bundle_files"]["receipts/accept_valid_envelope.json"] = hashlib.sha256(path.read_bytes()).hexdigest()
    body = {k: v for k, v in manifest.items() if k != "manifest_hash"}
    manifest["manifest_hash"] = hashlib.sha256(canonicalize(body, manifest["hash_profile_for_manifest_hash"]).encode()).hexdigest()
    (copy_of / "MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))
    result = run("verify_bundle.py", str(copy_of))
    assert result.returncode == 1
    assert "receipt hash does not verify" in result.stdout
    assert "replay: receipts/accept_valid_envelope.json differs when rebuilt" in result.stdout

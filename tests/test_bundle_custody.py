"""Bundle custody receipt: producer and verifier identities, and tamper detection."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "forge" / "demos" / "authority_spine_001" / "scripts" / "custody_receipt.py"


def run(*args):
    return subprocess.run([sys.executable, str(SCRIPT), *map(str, args)], capture_output=True, text=True)


@pytest.fixture
def bundle(tmp_path):
    b = tmp_path / "bundle"
    (b / "logs").mkdir(parents=True)
    (b / "MANIFEST.json").write_text('{"a": 1}\n')
    (b / "logs" / "pytest.txt").write_text("ok\n")
    assert run("produce", b, "--out", tmp_path / "producer.json").returncode == 0
    return b


def verify(tmp_path, b):
    out = tmp_path / "verifier.json"
    result = run("verify", b, "--producer", tmp_path / "producer.json", "--out", out)
    return result.returncode, json.loads(out.read_text())


def test_producer_records_identity_owner_mode_and_hash(tmp_path, bundle):
    doc = json.loads((tmp_path / "producer.json").read_text())
    assert doc["identity"]["euid"] == os.geteuid()
    assert set(doc["files"]["MANIFEST.json"]) == {"sha256", "size", "uid", "gid", "mode"}


def test_unchanged_bundle_verifies_and_names_both_identities(tmp_path, bundle):
    rc, doc = verify(tmp_path, bundle)
    assert rc == 0 and doc["result"] == "PASS" and doc["problems"] == []
    assert doc["identity"]["euid"] == os.geteuid() and "euid" in doc["producer_identity"]


@pytest.mark.parametrize("damage", ["content", "missing", "extra"])
def test_any_content_change_fails(tmp_path, bundle, damage):
    if damage == "content":
        (bundle / "MANIFEST.json").write_text('{"a": 2}\n')
    elif damage == "missing":
        (bundle / "logs" / "pytest.txt").unlink()
    else:
        (bundle / "planted.txt").write_text("x")
    rc, doc = verify(tmp_path, bundle)
    assert rc == 1 and doc["result"] == "FAIL" and doc["problems"]


def test_mode_change_is_noted_not_failed(tmp_path, bundle):
    os.chmod(bundle / "MANIFEST.json", 0o600)
    rc, doc = verify(tmp_path, bundle)
    assert rc == 0 and doc["notes"] == ["ownership or mode differs: MANIFEST.json"]

"""GAP-003-G1: the operating system, not the hook, stops writes to protected files.

Runs runtime/claude_code_gate/isolation_check.py, which tries 13 kinds of write
as the nobody user against root-owned gate files, and the same attempts against
an unprotected copy as a negative control. Needs root and runuser; skipped
otherwise. A pass here is G1_LOCAL_PASS for this machine only.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
OS_REFUSALS = ("Permission denied", "Operation not permitted", "EACCES", "EPERM")

pytestmark = pytest.mark.skipif(
    os.geteuid() != 0 or shutil.which("runuser") is None, reason="needs root and runuser to switch identity"
)


@pytest.fixture(scope="module")
def report(tmp_path_factory):
    out = tmp_path_factory.mktemp("g1") / "report.json"
    result = subprocess.run(
        [sys.executable, "-m", "runtime.claude_code_gate.isolation_check", "--json", str(out)],
        cwd=REPO, capture_output=True, text=True, timeout=300,
    )
    assert out.exists(), result.stdout + result.stderr
    return json.loads(out.read_text())


def layout(report, name):
    return next(entry for entry in report["layouts"] if entry["layout"] == name)


def test_status_is_local_pass_and_no_hook_is_involved(report):
    assert report["status"] == "G1_LOCAL_PASS"
    assert report["hook_involved"] is False
    assert "not a verification of any deployed environment" in report["scope"]


def test_attempts_ran_as_a_nonprivileged_identity(report):
    for name in ("protected", "control"):
        ident = layout(report, name)["effective_identity"]
        assert ident["uid"] != 0 and ident["user"] == "nobody"
        assert "uid=65534(nobody)" in ident["id_output"]


def test_protected_files_are_root_owned_and_root_is_sticky(report):
    perms = layout(report, "protected")["permissions"]
    for rel in (".claude/settings.json", "runtime/claude_code_gate/policy.py", ".weaver/gate/chronicle.jsonl"):
        assert perms[rel]["uid"] == 0 and perms[rel]["octal"] == "0o644"
    assert perms["."]["mode"] == "drwxrwxrwt"


def test_every_protected_attempt_is_refused_by_the_os_and_changes_nothing(report):
    attempts = layout(report, "protected")["attempts"]
    assert len(attempts) >= 11
    for attempt in attempts:
        assert attempt["changed"] == [], attempt["name"]
        assert attempt["before"] == attempt["after"], attempt["name"]
        assert attempt["exit_code"] != 0, attempt["name"]
        assert any(marker in attempt["stderr_tail"] for marker in OS_REFUSALS), (attempt["name"], attempt["stderr_tail"])


def test_negative_control_detects_writes(report):
    # Without OS protection the same attempts must succeed. Otherwise the denials
    # above could come from a broken harness rather than from the OS.
    control = layout(report, "control")
    assert len(control["attempts_that_changed_a_protected_file"]) >= 10
    for name in ("bash_redirect", "tee", "sed_in_place", "python_write", "rename_parent_dir"):
        assert name in control["attempts_that_changed_a_protected_file"], name


def test_every_protected_refusal_has_a_control_success_for_the_same_command(report):
    control = {a["name"]: a for a in layout(report, "control")["attempts"]}
    for attempt in layout(report, "protected")["attempts"]:
        if attempt["name"] == "chown":
            continue  # chown to the owner you already are is a no-op in the control
        assert control[attempt["name"]]["exit_code"] == 0, attempt["name"]


def test_sticky_bit_is_what_stops_the_rename_attack(report):
    check = report["sticky_bit_check"]
    assert check["sticky_bit_required"] is True
    assert check["changed"]

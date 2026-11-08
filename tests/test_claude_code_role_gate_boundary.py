"""Hook-level denial versus operating-system write protection.

The gate's hook only sees tool calls that go through Claude Code. A process the
agent starts outside that path is not checked by it. These tests show three
layers, so the boundary is explicit:

1. The hook denies an Edit of a protected file (hook level).
2. The same write, made by a process outside the hook, succeeds when the
   process runs with write access (no protection from the hook).
3. The same write, made by an unprivileged user against a root-owned file,
   fails (operating-system protection).

Layer 3 needs root, to switch to the nobody user. It is skipped otherwise.
The hook is advisory, and this file is the evidence for that.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from runtime.claude_code_role_gate.policy import decide

REPO = Path(__file__).resolve().parents[1]
PROTECTED_REL = Path(".claude") / "settings.json"


def test_hook_level_denies_edit_of_protected_settings(tmp_path):
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text("{}\n")
    decision = decide("Edit", {"file_path": str(PROTECTED_REL)}, tmp_path, "Builder")
    assert not decision.allowed and decision.rule == "protected_path"


def test_write_outside_the_hook_is_not_stopped_by_the_hook(tmp_path):
    # Layer 2: no hook is involved here, so the policy cannot see this write.
    target = tmp_path / ".claude" / "settings.json"
    target.parent.mkdir()
    target.write_text("{}\n")
    subprocess.run(
        [sys.executable, "-c", f"open({str(target)!r}, 'w').write('changed')"], check=True,
    )
    assert target.read_text() == "changed"


@pytest.mark.skipif(os.geteuid() != 0 or shutil.which("runuser") is None, reason="needs root and runuser")
def test_operating_system_permissions_stop_an_unprivileged_writer():
    # Layer 3: root owns the file, and the agent's user cannot write it.
    base = Path(tempfile.mkdtemp(prefix="gate-boundary-", dir="/tmp"))
    try:
        os.chmod(base, 0o755)
        target = base / ".claude" / "settings.json"
        target.parent.mkdir()
        target.write_text("{}\n")
        os.chmod(target.parent, 0o755)
        os.chmod(target, 0o644)
        os.chown(target, 0, 0)

        result = subprocess.run(
            ["runuser", "-u", "nobody", "--", sys.executable, "-c",
             f"open({str(target)!r}, 'w').write('changed')"],
            capture_output=True, text=True,
        )
        assert result.returncode != 0
        assert "Permission denied" in result.stderr
        assert target.read_text() == "{}\n"
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_boundary_demo_script_runs_the_layers_and_reports_them():
    # The demo prints the three results as JSON so a person can read the boundary.
    result = subprocess.run(
        [sys.executable, "-m", "runtime.claude_code_role_gate.boundary_demo"],
        cwd=REPO, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["hook_level"]["denied"] is True
    assert report["outside_hook"]["written"] is True
    assert report["os_permissions"]["status"] in {"blocked", "skipped"}

"""Tests for the Claude Code gate (GAP-003): policy, hook, wrapper and chronicle."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from core.authority.chronicle import Chronicle, verify_file
from runtime.claude_code_gate.policy import POLICY_VERSION, PROTECTED_PREFIXES, decide

REPO = Path(__file__).resolve().parents[1]
GATE_SH = REPO / "runtime" / "claude_code_gate" / "gate.sh"
CHRONICLE = Path(".weaver") / "gate" / "chronicle.jsonl"


@pytest.fixture
def project(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("x = 1\n")
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text("{}\n")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("[core]\n")
    return tmp_path


def payload(tool, tool_input, cwd="."):
    return {"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": tool_input, "cwd": cwd}


def run_hook(project, body):
    env = {**os.environ, "CLAUDE_PROJECT_DIR": str(project)}
    text = body if isinstance(body, str) else json.dumps(body)
    return subprocess.run(
        [sys.executable, "-m", "runtime.claude_code_gate.hook"],
        input=text, capture_output=True, text=True, cwd=REPO, env=env,
    )


def chronicle_entries(project):
    path = project / CHRONICLE
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


# --- Policy: default deny --------------------------------------------------------

ALLOWED_CALLS = [
    ("Read", {"file_path": "src/app.py"}),
    ("Read", {"file_path": ".claude/settings.json"}),
    ("Glob", {"pattern": "**/*.py"}),
    ("Grep", {"pattern": "x", "path": "src"}),
    ("Grep", {"pattern": "x"}),
    ("Edit", {"file_path": "src/app.py"}),
    ("Write", {"file_path": "docs/new.md"}),
    ("MultiEdit", {"file_path": "src/app.py"}),
    ("NotebookEdit", {"notebook_path": "nb.ipynb"}),
]

VETOED_CALLS = [
    ("Read", {"file_path": "/etc/passwd"}),
    ("Read", {"file_path": "../outside.txt"}),
    ("Grep", {"pattern": "x", "path": "/"}),
    ("Read", {}),
    ("Edit", {"file_path": ".claude/settings.json"}),
    ("Write", {"file_path": ".claude/settings.local.json"}),
    ("Write", {"file_path": ".weaver/gate/chronicle.jsonl"}),
    ("Edit", {"file_path": "runtime/claude_code_gate/policy.py"}),
    ("Write", {"file_path": "runtime/claude_code_gate/gate.sh"}),
    ("Edit", {"file_path": ".git/config"}),
    ("Edit", {"file_path": "src/../.claude/settings.json"}),
    ("Write", {"file_path": "/tmp/outside"}),
    ("Edit", {"file_path": "../escape"}),
    ("Edit", {}),
    ("Write", {"file_path": 5}),
    ("NotebookEdit", {"file_path": "nb.ipynb"}),
    ("WebFetch", {"url": "https://example.com"}),
    ("mcp__github__get_me", {}),
    ("Task", {}),
]

BASH_ALLOWED = [
    "ls", "ls -la src", "cat src/app.py", "wc -l src/app.py", "grep -n x src/app.py",
    "rg needle src", "pwd", "git status", "git log --oneline -3",
    "git diff HEAD~1 -- src/app.py", "git show HEAD --stat",
]

BASH_VETOED = [
    "rm -rf src",
    "echo x > src/a",
    "cat src/app.py | sh",
    "sed -i s/x/y/ src/app.py",
    "python -c 'print(1)'",
    "python3 -m pytest",
    "pytest",
    "make test",
    "git push",
    "git -c core.pager=sh log",
    "git diff --output=out.txt",
    "rg --pre=sh x src",
    "cat .claude/settings.json",
    "cat .weaver/gate/chronicle.jsonl",
    "cat .git/config",
    "cat runtime/claude_code_gate/policy.py",
    "cat src/.claude/settings.json",
    "cat /etc/passwd",
    "ls ~",
    "cat ../x",
    "echo $(id)",
    "cat `id`",
    "ls; rm -rf src",
    "ls && rm x",
    "cat 'unterminated",
    "",
    "   ",
    "curl http://x",
    "cat src/app.py\nrm x",
]


@pytest.mark.parametrize(("tool", "tool_input"), ALLOWED_CALLS)
def test_allowed_calls(project, tool, tool_input):
    assert decide(tool, tool_input, project).allowed


@pytest.mark.parametrize(("tool", "tool_input"), VETOED_CALLS)
def test_vetoed_calls(project, tool, tool_input):
    assert not decide(tool, tool_input, project).allowed


@pytest.mark.parametrize("command", BASH_ALLOWED)
def test_allowed_bash(project, command):
    assert decide("Bash", {"command": command}, project).allowed


@pytest.mark.parametrize("command", BASH_VETOED)
def test_vetoed_bash(project, command):
    decision = decide("Bash", {"command": command}, project)
    assert not decision.allowed, decision


def test_bash_input_must_be_a_mapping(project):
    assert not decide("Bash", "ls", project).allowed


def test_symlink_into_protected_area_is_vetoed(project):
    (project / "src" / "link.json").symlink_to(project / ".claude" / "settings.json")
    assert not decide("Edit", {"file_path": "src/link.json"}, project).allowed
    assert not decide("Write", {"file_path": "src/link.json"}, project).allowed


def test_nul_byte_in_path_raises_rather_than_passing(project):
    # The hook's wrapper turns this exception into a block.
    with pytest.raises(ValueError):
        decide("Edit", {"file_path": "src/app.py\0.claude"}, project)


def test_protected_prefixes_cover_gate_state_settings_and_git():
    assert {".claude", ".weaver", ".git", "runtime/claude_code_gate"} <= set(PROTECTED_PREFIXES)


# --- Hook: exit codes and chronicle ---------------------------------------------


def test_allowed_call_exits_zero_and_is_chronicled(project):
    result = run_hook(project, payload("Read", {"file_path": "src/app.py"}, str(project)))
    assert result.returncode == 0, result.stderr
    [entry] = chronicle_entries(project)
    assert entry["data"]["decision"] == "ALLOW"
    assert entry["data"]["context"] == {
        "policy_version": POLICY_VERSION, "tool": "Read", "rule": "read_inside_project", "target": "src/app.py",
    }
    assert verify_file(project / CHRONICLE).ok


def test_vetoed_call_exits_two_with_reason_on_stderr(project):
    result = run_hook(project, payload("Bash", {"command": "rm -rf src"}, str(project)))
    assert result.returncode == 2
    assert "Blocked by Weaver gate" in result.stderr
    assert "rm is not on the read-only allowlist" in result.stderr
    [entry] = chronicle_entries(project)
    assert entry["data"]["decision"] == "VETO"
    assert entry["data"]["context"]["rule"] == "bash_not_allowlisted"


@pytest.mark.parametrize(
    "body",
    [
        "not json",
        "[1, 2]",
        json.dumps({"hook_event_name": "PostToolUse", "tool_name": "Read", "tool_input": {}}),
        json.dumps({"tool_name": "Read", "tool_input": {"file_path": "src/app.py"}}),
        json.dumps({"hook_event_name": "PreToolUse", "tool_input": {}}),
    ],
)
def test_malformed_or_unexpected_input_is_blocked(project, body):
    assert run_hook(project, body).returncode == 2


def test_non_canonical_input_is_blocked(project):
    # NaN is accepted by json.loads but cannot be canonicalized, so the gate vetoes.
    body = '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls","x":NaN},"cwd":"."}'
    result = run_hook(project, body)
    assert result.returncode == 2
    assert "request_not_canonicalizable" in result.stderr


def test_corrupt_chronicle_blocks_every_call(project):
    (project / ".weaver" / "gate").mkdir(parents=True)
    (project / CHRONICLE).write_text("not a chronicle\n")
    result = run_hook(project, payload("Read", {"file_path": "src/app.py"}, str(project)))
    assert result.returncode == 2
    assert "Weaver gate error (ChronicleError)" in result.stderr


def test_unwritable_state_directory_blocks(project):
    (project / ".weaver").write_text("a file, not a directory")
    result = run_hook(project, payload("Read", {"file_path": "src/app.py"}, str(project)))
    assert result.returncode == 2


def test_parallel_hook_calls_keep_the_chain_valid(project):
    calls = [payload("Bash", {"command": "ls"}, str(project)) for _ in range(30)]
    calls += [payload("Read", {"file_path": "src/app.py"}, str(project)) for _ in range(30)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda body: run_hook(project, body), calls))
    assert all(r.returncode == 0 for r in results), [r.stderr for r in results if r.returncode]
    assert len(chronicle_entries(project)) == len(calls)
    assert verify_file(project / CHRONICLE).ok


# --- Wrapper: crashes become blocks ---------------------------------------------


def _wrapper(project, body, env):
    return subprocess.run(
        [shutil.which("bash"), str(GATE_SH)], input=json.dumps(body) if not isinstance(body, str) else body,
        capture_output=True, text=True, env=env,
    )


def test_wrapper_passes_allowed_calls_through(project):
    env = {**os.environ, "CLAUDE_PROJECT_DIR": str(project)}
    result = _wrapper(project, payload("Read", {"file_path": "src/app.py"}, str(project)), env)
    assert result.returncode == 0, result.stderr


def test_wrapper_passes_vetoes_through_as_two(project):
    env = {**os.environ, "CLAUDE_PROJECT_DIR": str(project)}
    result = _wrapper(project, payload("Bash", {"command": "rm x"}, str(project)), env)
    assert result.returncode == 2 and "Blocked by Weaver gate" in result.stderr


def test_wrapper_turns_a_missing_interpreter_into_a_block(project):
    # With no python3 on PATH the wrapper cannot run the gate at all. Claude Code
    # would treat a 127 as a non-blocking error, so the wrapper must return 2.
    env = {"CLAUDE_PROJECT_DIR": str(project), "PATH": "/nonexistent"}
    result = _wrapper(project, payload("Read", {"file_path": "src/app.py"}), env)
    assert result.returncode == 2
    assert "crashed" in result.stderr

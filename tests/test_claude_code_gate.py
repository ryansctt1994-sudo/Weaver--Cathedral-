"""Tests for the Claude Code gate (GAP-003): roles, policy, hook, wrapper and audit."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from core.authority.chronicle import verify_file
from runtime.claude_code_gate.hook import resolve_role
from runtime.claude_code_gate.policy import POLICY_VERSION, PROTECTED_PREFIXES, ROLE_PERMISSIONS, decide

REPO = Path(__file__).resolve().parents[1]
GATE_SH = REPO / "runtime" / "claude_code_gate" / "gate.sh"
CHRONICLE = Path(".weaver") / "gate" / "chronicle.jsonl"
ROLES = sorted(ROLE_PERMISSIONS)


@pytest.fixture
def project(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("x = 1\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_app.py").write_text("def test_x():\n    assert True\n")
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text("{}\n")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("[core]\n")
    return tmp_path


def payload(tool, tool_input, cwd=".", **extra):
    return {"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": tool_input, "cwd": cwd, **extra}


def run_hook(project, body, role="Builder", extra_env=None):
    env = {**os.environ, "CLAUDE_PROJECT_DIR": str(project)}
    if role is not None:
        env["WEAVER_GATE_ROLE"] = role
    else:
        env.pop("WEAVER_GATE_ROLE", None)
    env.update(extra_env or {})
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


# --- Role binding ---------------------------------------------------------------


def test_role_table_matches_spec_bindings():
    assert ROLE_PERMISSIONS["Planner"] == {"read", "bash_read"}
    assert "write" in ROLE_PERMISSIONS["Builder"] and "bash_test" not in ROLE_PERMISSIONS["Builder"]
    assert "bash_test" in ROLE_PERMISSIONS["Verifier"] and "write" not in ROLE_PERMISSIONS["Verifier"]
    assert ROLE_PERMISSIONS["Operator"] == frozenset()


def test_role_comes_from_agent_type_then_environment():
    assert resolve_role({"agent_type": "Builder"}, {"WEAVER_GATE_ROLE": "Planner"}) == "Builder"
    assert resolve_role({}, {"WEAVER_GATE_ROLE": "Planner"}) == "Planner"
    assert resolve_role({}, {}) is None


def test_subagent_without_agent_type_gets_no_role_even_with_environment_role():
    assert resolve_role({"agent_id": "a1"}, {"WEAVER_GATE_ROLE": "Builder"}) is None


@pytest.mark.parametrize("role", [None, "", "builder", "Root", "Operator", 5, ["Builder"]])
def test_missing_or_unknown_or_operator_role_denies_everything(project, role):
    for tool, tool_input in [("Read", {"file_path": "src/app.py"}), ("Bash", {"command": "ls"})]:
        assert not decide(tool, tool_input, project, role).allowed


# --- Role x tool permissions ----------------------------------------------------

READ_CALL = ("Read", {"file_path": "src/app.py"})
WRITE_CALL = ("Edit", {"file_path": "src/app.py"})
BASH_READ_CALL = ("Bash", {"command": "git status"})
BASH_TEST_CALL = ("Bash", {"command": "python -m pytest -q tests/test_app.py"})


@pytest.mark.parametrize("role", ROLES)
def test_read_permission(project, role):
    assert decide(*READ_CALL, project, role).allowed is (role != "Operator")


@pytest.mark.parametrize("role", ROLES)
def test_write_permission_only_for_builder(project, role):
    decision = decide(*WRITE_CALL, project, role)
    assert decision.allowed is (role == "Builder")
    if role != "Builder":
        assert decision.rule == "role_not_permitted"


@pytest.mark.parametrize("role", ROLES)
def test_bash_read_permission(project, role):
    assert decide(*BASH_READ_CALL, project, role).allowed is (role != "Operator")


@pytest.mark.parametrize("role", ROLES)
def test_test_runner_permission_only_for_verifier(project, role):
    decision = decide(*BASH_TEST_CALL, project, role)
    assert decision.allowed is (role == "Verifier")
    if role != "Verifier":
        assert decision.rule == "role_not_permitted"


@pytest.mark.parametrize("flag", ["-p", "-pno:cacheprovider", "-c", "--rootdir", "--override-ini"])
def test_pytest_plugin_and_config_flags_are_refused_for_verifier(project, flag):
    assert not decide("Bash", {"command": f"python -m pytest {flag} x tests/test_app.py"}, project, "Verifier").allowed


# --- Path rules (Builder) -------------------------------------------------------

ALLOWED_PATH_CALLS = [
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

VETOED_PATH_CALLS = [
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


@pytest.mark.parametrize(("tool", "tool_input"), ALLOWED_PATH_CALLS)
def test_allowed_path_calls_for_builder(project, tool, tool_input):
    assert decide(tool, tool_input, project, "Builder").allowed


@pytest.mark.parametrize(("tool", "tool_input"), VETOED_PATH_CALLS)
def test_vetoed_path_calls_for_builder(project, tool, tool_input):
    assert not decide(tool, tool_input, project, "Builder").allowed


def test_symlink_into_protected_area_is_vetoed(project):
    (project / "src" / "link.json").symlink_to(project / ".claude" / "settings.json")
    assert not decide("Edit", {"file_path": "src/link.json"}, project, "Builder").allowed
    assert not decide("Write", {"file_path": "src/link.json"}, project, "Builder").allowed


def test_nul_byte_in_path_raises_rather_than_passing(project):
    # The hook's wrapper turns this exception into a block.
    with pytest.raises(ValueError):
        decide("Edit", {"file_path": "src/app.py\0.claude"}, project, "Builder")


def test_protected_prefixes_cover_gate_state_settings_and_git():
    assert {".claude", ".weaver", ".git", "runtime/claude_code_gate"} <= set(PROTECTED_PREFIXES)


# --- Bash rules (Verifier, Builder and Planner alike) ---------------------------

BASH_READ_ALLOWED = [
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


@pytest.mark.parametrize("command", BASH_READ_ALLOWED)
def test_allowed_bash_for_builder(project, command):
    assert decide("Bash", {"command": command}, project, "Builder").allowed


@pytest.mark.parametrize("command", BASH_VETOED)
def test_vetoed_bash_for_verifier(project, command):
    assert not decide("Bash", {"command": command}, project, "Verifier").allowed


def test_bash_input_must_be_a_mapping(project):
    assert not decide("Bash", "ls", project, "Builder").allowed


def test_allowed_decision_names_the_program_for_the_audit(project):
    decision = decide("Bash", {"command": "git status"}, project, "Planner")
    assert decision.allowed and decision.target == "git"


# --- Hook: exit codes, role, structured denial, audit ---------------------------


def test_allowed_call_exits_zero_and_is_chronicled(project):
    result = run_hook(project, payload("Read", {"file_path": "src/app.py"}, str(project)), role="Planner")
    assert result.returncode == 0, result.stderr
    [entry] = chronicle_entries(project)
    assert entry["data"]["decision"] == "ALLOW"
    assert entry["data"]["context"] == {
        "policy_version": POLICY_VERSION,
        "role": "Planner",
        "tool": "Read",
        "rule": "read_inside_project",
        "target": "src/app.py",
    }
    assert verify_file(project / CHRONICLE).ok


def test_vetoed_call_exits_two_and_writes_a_structured_denial(project):
    result = run_hook(project, payload("Bash", {"command": "rm -rf src"}, str(project)), role="Builder")
    assert result.returncode == 2
    assert "Blocked by Weaver gate (role Builder" in result.stderr
    assert "rm is not on the allowlist" in result.stderr
    [entry] = chronicle_entries(project)
    assert entry["data"]["decision"] == "VETO"
    denial = entry["data"]["context"]["denial"]
    assert denial == {
        "schema": "weaver.claude_code_gate.denial.v1",
        "role": "Builder",
        "tool": "Bash",
        "rule": "bash_not_allowlisted",
        "reason": "rm is not on the allowlist",
        "target": "rm",
    }


def test_role_denial_is_recorded_with_its_rule(project):
    result = run_hook(project, payload("Edit", {"file_path": "src/app.py"}, str(project)), role="Planner")
    assert result.returncode == 2
    [entry] = chronicle_entries(project)
    assert entry["data"]["context"]["denial"]["rule"] == "role_not_permitted"


def test_subagent_with_no_agent_type_is_denied_even_with_a_builder_environment(project):
    body = payload("Edit", {"file_path": "src/app.py"}, str(project), agent_id="sub-1")
    result = run_hook(project, body, role="Builder")
    assert result.returncode == 2


def test_agent_type_from_hook_input_selects_the_role(project):
    body = payload("Read", {"file_path": "src/app.py"}, str(project), agent_type="Planner")
    assert run_hook(project, body, role="Builder").returncode == 0


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


def _wrapper(body, env):
    text = body if isinstance(body, str) else json.dumps(body)
    return subprocess.run(
        [shutil.which("bash"), str(GATE_SH)], input=text, capture_output=True, text=True, env=env,
    )


def test_wrapper_passes_allowed_calls_through(project):
    env = {**os.environ, "CLAUDE_PROJECT_DIR": str(project), "WEAVER_GATE_ROLE": "Builder"}
    result = _wrapper(payload("Read", {"file_path": "src/app.py"}, str(project)), env)
    assert result.returncode == 0, result.stderr


def test_wrapper_passes_vetoes_through_as_two(project):
    env = {**os.environ, "CLAUDE_PROJECT_DIR": str(project), "WEAVER_GATE_ROLE": "Builder"}
    result = _wrapper(payload("Bash", {"command": "rm x"}, str(project)), env)
    assert result.returncode == 2 and "Blocked by Weaver gate" in result.stderr


def test_wrapper_turns_a_missing_interpreter_into_a_block(project):
    # With no python3 on PATH the wrapper cannot run the gate at all. Claude Code
    # would treat a 127 as a non-blocking error, so the wrapper must return 2.
    env = {"CLAUDE_PROJECT_DIR": str(project), "PATH": "/nonexistent", "WEAVER_GATE_ROLE": "Builder"}
    result = _wrapper(payload("Read", {"file_path": "src/app.py"}), env)
    assert result.returncode == 2
    assert "crashed" in result.stderr


def test_hook_blocks_instead_of_waiting_forever_on_a_busy_lock(project):
    import fcntl
    import time

    state = project / ".weaver" / "gate"
    state.mkdir(parents=True)
    holder = open(state / "lock", "a")
    fcntl.flock(holder, fcntl.LOCK_EX)
    try:
        started = time.monotonic()
        result = run_hook(project, payload("Read", {"file_path": "src/app.py"}, str(project)),
                          extra_env={"WEAVER_GATE_LOCK_TIMEOUT": "0.5"})
        elapsed = time.monotonic() - started
    finally:
        fcntl.flock(holder, fcntl.LOCK_UN)
        holder.close()
    assert result.returncode == 2
    assert "chronicle lock busy" in result.stderr
    assert elapsed < 10, elapsed

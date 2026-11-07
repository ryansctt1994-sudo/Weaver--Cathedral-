"""GAP-003-G3: the operator override is authenticated, single-use, bound, audited,
and cannot be issued by the agent.

The hook runs as a subprocess with realistic PreToolUse events, as in
tests/test_claude_code_gate.py. "Operator" actions use the operator's private
key, which the hook never reads. "Agent" actions use everything the agent could
reach: the project files, the public key, this code, and a key of its own.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

cryptography = pytest.importorskip("cryptography")
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from core.authority.chronicle import verify_file  # noqa: E402
from core.authority.gate import request_hash  # noqa: E402
from runtime.claude_code_gate.override import MAX_LIFETIME, fingerprint, sign  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
STATE = Path(".weaver") / "gate"


def keypair():
    key = Ed25519PrivateKey.generate()
    return key.private_bytes_raw(), key.public_key().public_bytes_raw().hex()


@pytest.fixture
def operator():
    return keypair()


@pytest.fixture
def agent_key():
    return keypair()


@pytest.fixture
def project(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("x = 1\n")
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text("{}\n")
    return tmp_path


EDIT = {"file_path": "src/app.py", "old_string": "x = 1", "new_string": "x = 2"}


def event(tool="Edit", tool_input=None, project=None, **extra):
    return {"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": EDIT if tool_input is None else tool_input,
            "cwd": str(project), **extra}


def req_sha(tool="Edit", tool_input=None, role="Planner", ceiling="Planner", agent_id=None):
    return request_hash({"tool": tool, "input": EDIT if tool_input is None else tool_input, "role": role, "ceiling": ceiling, "agent_id": agent_id})


def run(project, body, pubkey=None, role="Planner"):
    env = {**os.environ, "CLAUDE_PROJECT_DIR": str(project), "WEAVER_GATE_ROLE": role}
    env.pop("WEAVER_GATE_OPERATOR_PUBKEY", None)
    if pubkey:
        env["WEAVER_GATE_OPERATOR_PUBKEY"] = pubkey
    return subprocess.run([sys.executable, "-m", "runtime.claude_code_gate.hook"], input=json.dumps(body),
                          capture_output=True, text=True, cwd=REPO, env=env)


def place(project, doc, sha=None):
    path = project / STATE / "overrides" / f"{sha or doc['request_sha256']}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc))
    return path


def signed(private, sha, *, minutes=10, issued=None, nonce="n-0001", reason="reviewed by operator"):
    issued = issued or datetime.now(timezone.utc)
    return sign(private, request_sha256=sha, operator_id="operator.ryan", reason=reason, nonce=nonce,
                issued_at=issued, lifetime=timedelta(minutes=minutes))


def chronicle(project):
    path = project / STATE / "chronicle.jsonl"
    return [json.loads(line)["data"] for line in path.read_text().splitlines()]


# --- Baseline ---------------------------------------------------------------------


def test_denial_prints_the_request_hash_the_operator_signs(project, operator):
    result = run(project, event(project=project), pubkey=operator[1])
    assert result.returncode == 2
    assert f"request {req_sha()}" in result.stderr


# --- Authenticated operator path ------------------------------------------------


def test_valid_operator_override_allows_exactly_that_call_once(project, operator):
    place(project, signed(operator[0], req_sha()))
    first = run(project, event(project=project), pubkey=operator[1])
    assert first.returncode == 0, first.stderr
    second = run(project, event(project=project), pubkey=operator[1])
    assert second.returncode == 2 and "override rejected: replayed" in second.stderr


def test_override_use_is_audited_in_the_chronicle(project, operator):
    doc = signed(operator[0], req_sha(), reason="hotfix approved in ticket 42")
    place(project, doc)
    run(project, event(project=project), pubkey=operator[1])
    [entry] = chronicle(project)
    assert entry["decision"] == "ALLOW"
    record = entry["context"]["override"]
    assert record["operator_id"] == "operator.ryan"
    assert record["reason"] == "hotfix approved in ticket 42"
    assert record["key_fingerprint"] == fingerprint(operator[1])
    assert record["nonce"] == doc["nonce"]
    assert record["overridden_rule"] == "role_not_permitted"
    assert "denial" not in entry["context"]
    assert verify_file(project / STATE / "chronicle.jsonl").ok


def test_override_is_bound_to_one_request(project, operator):
    # Signed for editing src/app.py, placed under the hash of a different call.
    other = {"file_path": "src/app.py", "old_string": "x = 1", "new_string": "x = 999"}
    place(project, signed(operator[0], req_sha()), sha=req_sha(tool_input=other))
    result = run(project, event(tool_input=other, project=project), pubkey=operator[1])
    assert result.returncode == 2 and "wrong_request" in result.stderr


def test_override_is_bound_to_role_and_agent(project, operator):
    # Signed for the main thread; the same edit from a subagent is a different request.
    place(project, signed(operator[0], req_sha()), sha=req_sha(role="Researcher", agent_id="sub-1"))
    body = event(project=project, agent_id="sub-1", agent_type="Researcher")
    result = run(project, body, pubkey=operator[1])
    assert result.returncode == 2 and "wrong_request" in result.stderr


@pytest.mark.parametrize(
    ("kwargs", "problem"),
    [
        ({"issued": datetime.now(timezone.utc) - timedelta(minutes=20)}, "expired"),
        ({"issued": datetime.now(timezone.utc) + timedelta(minutes=5)}, "not_yet_valid"),
        ({"minutes": 60}, "lifetime_too_long"),
    ],
)
def test_time_limits(project, operator, kwargs, problem):
    place(project, signed(operator[0], req_sha(), **kwargs))
    result = run(project, event(project=project), pubkey=operator[1])
    assert result.returncode == 2 and problem in result.stderr


def test_maximum_lifetime_is_fifteen_minutes():
    assert MAX_LIFETIME == timedelta(minutes=15)


@pytest.mark.parametrize(
    ("tool", "tool_input", "rule"),
    [
        ("Edit", {"file_path": ".claude/settings.json", "old_string": "{}", "new_string": "x"}, "protected_path"),
        ("Bash", {"command": "cat .weaver/gate/chronicle.jsonl"}, "bash_protected_path"),
        ("Edit", {}, "missing_path"),
    ],
)
def test_non_overridable_rules_stay_denied_even_with_a_valid_signature(project, operator, tool, tool_input, rule):
    sha = req_sha(tool=tool, tool_input=tool_input, role="Builder", ceiling="Builder")
    place(project, signed(operator[0], sha))
    result = run(project, event(tool=tool, tool_input=tool_input, project=project), pubkey=operator[1], role="Builder")
    assert result.returncode == 2 and "not_overridable" in result.stderr and f"rule {rule}" in result.stderr


def test_no_pinned_key_means_no_overrides(project, operator):
    place(project, signed(operator[0], req_sha()))
    result = run(project, event(project=project), pubkey=None)
    assert result.returncode == 2 and "overrides_not_configured" in result.stderr


def test_malformed_override_file_is_rejected(project, operator):
    path = project / STATE / "overrides" / f"{req_sha()}.json"
    path.parent.mkdir(parents=True)
    path.write_text("{not json")
    result = run(project, event(project=project), pubkey=operator[1])
    assert result.returncode == 2 and "override rejected: malformed" in result.stderr


# --- The agent cannot issue an override -----------------------------------------


def test_agent_signing_with_its_own_key_is_rejected(project, operator, agent_key):
    forged = signed(agent_key[0], req_sha())  # carries the agent key's fingerprint
    place(project, forged)
    result = run(project, event(project=project), pubkey=operator[1])
    assert result.returncode == 2 and "unknown_key" in result.stderr


def test_agent_claiming_the_operator_fingerprint_fails_the_signature(project, operator, agent_key):
    forged = signed(agent_key[0], req_sha())
    forged["key_fingerprint"] = fingerprint(operator[1])
    place(project, forged)
    result = run(project, event(project=project), pubkey=operator[1])
    assert result.returncode == 2 and "bad_signature" in result.stderr


@pytest.mark.parametrize("field,value", [("reason", "changed"), ("operator_id", "someone.else"), ("nonce", "n-9999"),
                                         ("expires_at", "2099-01-01T00:00:00+00:00")])
def test_editing_any_signed_field_breaks_the_signature(project, operator, field, value):
    doc = signed(operator[0], req_sha())
    doc[field] = value
    place(project, doc)
    result = run(project, event(project=project), pubkey=operator[1])
    assert result.returncode == 2 and "bad_signature" in result.stderr


def test_agent_cannot_write_into_the_overrides_directory_through_the_gate(project, operator):
    target = f".weaver/gate/overrides/{req_sha()}.json"
    body = event(tool="Write", tool_input={"file_path": target, "content": "{}"}, project=project)
    result = run(project, body, pubkey=operator[1], role="Builder")
    assert result.returncode == 2 and "rule protected_path" in result.stderr


def test_a_public_key_planted_in_the_project_is_ignored(project, operator, agent_key):
    # Only the environment pins the key. A key file the agent wrote does nothing.
    (project / STATE).mkdir(parents=True, exist_ok=True)
    (project / STATE / "operator.pub").write_text(agent_key[1])
    place(project, signed(agent_key[0], req_sha()))
    result = run(project, event(project=project), pubkey=None)
    assert result.returncode == 2 and "overrides_not_configured" in result.stderr


def test_rejected_attempts_are_audited_with_their_reason(project, operator, agent_key):
    place(project, signed(agent_key[0], req_sha()))
    run(project, event(project=project), pubkey=operator[1])
    [entry] = chronicle(project)
    assert entry["decision"] == "VETO"
    assert entry["context"]["override_rejected"] == "unknown_key"
    assert entry["context"]["denial"]["rule"] == "role_not_permitted"


def test_forged_override_does_not_burn_the_real_one(project, operator, agent_key):
    # An agent that guesses the nonce cannot spend it: nonces are consumed only after a valid signature.
    real = signed(operator[0], req_sha(), nonce="shared-nonce")
    forged = signed(agent_key[0], req_sha(), nonce="shared-nonce")
    forged["key_fingerprint"] = fingerprint(operator[1])
    place(project, forged)
    assert run(project, event(project=project), pubkey=operator[1]).returncode == 2
    place(project, real)
    assert run(project, event(project=project), pubkey=operator[1]).returncode == 0


# --- Separate control: the operator's key is not the agent's to read ------------


def test_operator_tool_writes_the_private_key_0600_and_never_into_the_hook(tmp_path):
    out = subprocess.run([sys.executable, "-m", "runtime.claude_code_gate.operator", "keygen", "--private", str(tmp_path / "op.key")],
                         cwd=REPO, capture_output=True, text=True, check=True)
    info = json.loads(out.stdout)
    assert oct((tmp_path / "op.key").stat().st_mode & 0o777) == "0o600"
    assert len(info["public_key"]) == 64
    hook_source = (REPO / "runtime" / "claude_code_gate" / "hook.py").read_text()
    override_source = (REPO / "runtime" / "claude_code_gate" / "override.py").read_text()
    assert "private" not in hook_source.lower()
    assert "from_private_bytes" not in override_source.split("def check(")[1]  # verification never touches a private key


def test_operator_tool_round_trip(project, tmp_path):
    key = tmp_path / "op.key"
    info = json.loads(subprocess.run([sys.executable, "-m", "runtime.claude_code_gate.operator", "keygen", "--private", str(key)],
                                     cwd=REPO, capture_output=True, text=True, check=True).stdout)
    out = project / STATE / "overrides" / f"{req_sha()}.json"
    subprocess.run([sys.executable, "-m", "runtime.claude_code_gate.operator", "sign", "--private", str(key),
                    "--request", req_sha(), "--operator", "operator.ryan", "--reason", "approved", "--minutes", "5", "--out", str(out)],
                   cwd=REPO, capture_output=True, text=True, check=True)
    assert run(project, event(project=project), pubkey=info["public_key"]).returncode == 0


def test_operator_tool_refuses_a_lifetime_over_the_maximum(tmp_path):
    key = tmp_path / "op.key"
    subprocess.run([sys.executable, "-m", "runtime.claude_code_gate.operator", "keygen", "--private", str(key)],
                   cwd=REPO, capture_output=True, text=True, check=True)
    result = subprocess.run([sys.executable, "-m", "runtime.claude_code_gate.operator", "sign", "--private", str(key),
                             "--request", "0" * 64, "--operator", "o", "--reason", "r", "--minutes", "60", "--out", str(tmp_path / "x.json")],
                            cwd=REPO, capture_output=True, text=True)
    assert result.returncode != 0 and not (tmp_path / "x.json").exists()


@pytest.mark.skipif(os.geteuid() != 0 or shutil.which("runuser") is None, reason="needs root and runuser")
def test_agent_identity_cannot_read_an_operator_key_it_does_not_own(tmp_path):
    key = tmp_path / "op.key"
    subprocess.run([sys.executable, "-m", "runtime.claude_code_gate.operator", "keygen", "--private", str(key)],
                   cwd=REPO, capture_output=True, text=True, check=True)
    os.chmod(tmp_path, 0o755)
    os.chown(key, 0, 0)
    result = subprocess.run(["runuser", "-u", "nobody", "--", "cat", str(key)], capture_output=True, text=True)
    assert result.returncode != 0 and "Permission denied" in result.stderr

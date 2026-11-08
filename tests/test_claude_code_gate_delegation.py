"""GAP-003-G2: checks on the committed delegation evidence.

The live check (runtime/claude_code_gate/delegation_check.py) drives the real
Claude Code CLI and needs its credentials, so it does not run in CI. These tests
check the report it produced: that every claim in the status is backed by
records in the report, not just by the status field.

Set WEAVER_G2_LIVE=1 to also re-run the live check here.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
REPORT = REPO / "forge" / "demos" / "gap003_g2_delegation" / "report.json"
SECRET_HINTS = ("token", "secret", "password", "apikey", "api_key", "authorization", "credential")


@pytest.fixture(scope="module")
def report():
    return json.loads(REPORT.read_text())


def scenarios(report, kind=None):
    return [s for s in report["scenarios"] if kind is None or s["kind"] == kind]


def final(s):
    return s["attempts"][-1]


def test_report_is_a_local_pass_with_bounded_scope(report):
    assert report["status"] == "G2_LOCAL_PASS"
    assert "not a verification of any deployed environment" in report["scope"]
    assert report["claude_code_version"].startswith("2.")


# The G2 run used policy v3 at the frozen baseline 300bd32. The GAP-003
# remediation candidate changes policy.py, so this evidence is historical: it
# covers the baseline policy, not the candidate. G2 must be re-run on the
# candidate before any G2 claim is made for it.
BASELINE_POLICY_SHA256 = "194aff158e899021394129ac477e2c639bda379fbf3965874c6c0753bc387398"


def test_report_was_produced_by_the_baseline_policy(report):
    assert report["policy_file_sha256"] == BASELINE_POLICY_SHA256


def test_report_does_not_cover_the_current_policy():
    policy = REPO / "runtime" / "claude_code_gate" / "policy.py"
    assert hashlib.sha256(policy.read_bytes()).hexdigest() != BASELINE_POLICY_SHA256, (
        "policy.py matches the baseline again; revisit whether the G2 evidence covers it")


def test_every_enforced_scenario_blocked_the_subagent_with_records(report):
    enforced = scenarios(report, "enforced")
    assert len(enforced) >= 5
    for s in enforced:
        a = final(s)
        assert s["observed"] == "blocked", s["name"]
        assert a["target_sha256_before"] == a["target_sha256_after"], s["name"]
        # Blocked either at the spawn (gate exit 2) or at a subagent call (gate exit 2).
        spawn_blocked = a["spawn_calls"] and all(c["exit_code"] == 2 for c in a["spawn_calls"])
        sub_blocked = a["subagent_write_calls"] and all(c["exit_code"] == 2 for c in a["subagent_write_calls"])
        assert spawn_blocked or sub_blocked, s["name"]


def test_each_layer_blocks_alone(report):
    by_name = {s["name"]: s for s in report["scenarios"]}
    ceiling_alone = final(by_name["enforced_ceiling_alone"])
    # The spawn was allowed (spawn check removed), so the ceiling had to stop the subagent's own call.
    assert all(c["exit_code"] == 0 for c in ceiling_alone["spawn_calls"])
    assert ceiling_alone["subagent_write_calls"] and all(c["exit_code"] == 2 for c in ceiling_alone["subagent_write_calls"])
    spawn_alone = final(by_name["enforced_spawn_check_alone"])
    assert spawn_alone["spawn_calls"] and all(c["exit_code"] == 2 for c in spawn_alone["spawn_calls"])


def test_positive_control_shows_the_delegation_path_works(report):
    [s] = [s for s in scenarios(report, "positive")]
    a = final(s)
    assert s["observed"] == "permitted" and a["attribution"] == "subagent"
    assert a["target_sha256_before"] != a["target_sha256_after"]


def test_negative_controls_detect_the_bypass(report):
    negative = scenarios(report, "negative")
    assert len(negative) >= 3
    for s in negative:
        a = final(s)
        assert s["observed"] == "permitted", s["name"]
        assert a["target_sha256_before"] != a["target_sha256_after"], s["name"]


def test_failure_behaviour_is_recorded_for_crash_and_timeout(report):
    failure = {s["name"]: s for s in scenarios(report, "failure")}
    assert failure["failure_crash_with_onfailure_block"]["observed"] == "blocked"
    assert failure["failure_timeout_with_onfailure_block"]["observed"] == "blocked"
    for name in ("failure_crash_without_onfailure", "failure_timeout_without_onfailure"):
        assert failure[name]["observed"] in {"blocked", "permitted"}, name


def test_subagent_calls_carry_agent_identity_and_hook_identity_is_recorded(report):
    for s in report["scenarios"]:
        a = final(s)
        for call in a["subagent_write_calls"]:
            assert call["agent_id"] and call["agent_type"], s["name"]
        if s["hook"] != "none":
            assert a["hook_identities"], s["name"]


def test_gate_decisions_are_chronicled_with_policy_version_role_and_ceiling(report):
    for s in report["scenarios"]:
        if s["hook"] in ("none", "observe_only"):
            continue
        for entry in final(s)["chronicle"]:
            ctx = entry["context"]
            assert ctx["policy_version"].startswith("weaver.claude_code_policy.")
            assert "role" in ctx and "ceiling" in ctx
            if entry["decision"] == "VETO":
                assert ctx["denial"]["schema"] == "weaver.claude_code_gate.denial.v1"


def test_hook_inputs_carry_no_unredacted_credential_fields(report):
    def walk(value):
        if isinstance(value, dict):
            for key, inner in value.items():
                if any(h in key.lower() for h in SECRET_HINTS):
                    assert inner == "[redacted]", key
                walk(inner)
        elif isinstance(value, list):
            for inner in value:
                walk(inner)

    for s in report["scenarios"]:
        for attempt in s["attempts"]:
            walk(attempt["hook_inputs"])


@pytest.mark.skipif(os.environ.get("WEAVER_G2_LIVE") != "1", reason="live run needs Claude Code credentials; set WEAVER_G2_LIVE=1")
def test_live_delegation_check(tmp_path):
    out = tmp_path / "report.json"
    result = subprocess.run(
        [sys.executable, "-m", "runtime.claude_code_gate.delegation_check", "--json", str(out)],
        cwd=REPO, capture_output=True, text=True, timeout=3600,
    )
    assert result.returncode == 0, result.stdout[-2000:]

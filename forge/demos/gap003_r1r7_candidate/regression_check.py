"""GAP-003 R1/R5: the baseline bypass scenarios, run through gate.sh against the candidate.

The same five scenarios as the REGENERATED baseline reproduction of 300bd32
(P1-P3 Planner precedence, B1 Builder outside the project, B2 Builder
protected path), plus a positive control (Planner write inside the project,
eligible for override) so that a gate denying everything cannot pass.

Each scenario: fresh project, root-owned anchor, pinned key registry,
disposable test key. Run 1 has no override; run 2 carries a validly signed
eligible-form override; run 3 replays it. Hook-level decisions only: Claude
Code is not run and no tool is executed.

Implementer-run evidence, not the R8 independent reproduction.

Usage: python forge/demos/gap003_r1r7_candidate/regression_check.py [--out report.json]
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from core.authority.gate import request_hash  # noqa: E402
from runtime.claude_code_role_gate.manifest import policy_digest  # noqa: E402
from runtime.claude_code_role_gate.override import LiveContext, sign  # noqa: E402
from runtime.claude_code_role_gate.policy import decide  # noqa: E402
from runtime.claude_code_role_gate.registry import fingerprint  # noqa: E402
from runtime.claude_code_role_gate.trusted_root import write_anchor  # noqa: E402

GATE = REPO / "runtime" / "claude_code_role_gate" / "gate.sh"
REQ = re.compile(r"request ([0-9a-f]{64})")

SCENARIOS = [
    # id, role, file_path ("OUTSIDE" = absolute path outside the project), expected run-2 rc, expected run-2 rule
    ("P1-planner-settings-json", "Planner", ".claude/settings.json", 2, "protected_path"),
    ("P2-planner-outside-absolute", "Planner", "OUTSIDE", 2, "outside_project"),
    ("P3-planner-symlink-into-claude", "Planner", "linkdir/settings.json", 2, "protected_path"),
    ("B1-builder-outside-absolute", "Builder", "OUTSIDE", 2, "outside_project"),
    ("B2-builder-settings-json", "Builder", ".claude/settings.json", 2, "protected_path"),
    ("CTRL-planner-inside-eligible", "Planner", "src/new.py", 0, None),
]


def run_gate(env: dict, body: dict) -> dict:
    res = subprocess.run(["bash", str(GATE)], input=json.dumps(body), capture_output=True, text=True,
                         cwd=str(REPO), env=env, timeout=60)
    m = REQ.search(res.stderr)
    rule = re.search(r"rule ([a-z_]+)", res.stderr)
    rejected = re.search(r"override rejected: ([a-z_]+)", res.stderr)
    return {"rc": res.returncode, "stderr": res.stderr.strip(), "request_sha256": m.group(1) if m else None,
            "rule": rule.group(1) if rule else None, "override_rejected": rejected.group(1) if rejected else None}


def snapshot(root: Path) -> str:
    items = []
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root).as_posix()
        if rel == ".weaver" or rel.startswith(".weaver/"):
            continue
        items.append((rel, os.readlink(p) if p.is_symlink() else sha256(p.read_bytes()).hexdigest() if p.is_file() else "dir"))
    return sha256(json.dumps(items).encode()).hexdigest()


def scenario(tmp: Path, sid: str, role: str, file_path: str, want_rc: int, want_rule: str | None) -> dict:
    base = tmp / sid
    root, outside, anchor_dir = base / "project", base / "outside", base / "anchor"
    for d in (root / ".claude", root / "src", outside, anchor_dir):
        d.mkdir(parents=True)
    (root / ".claude" / "settings.json").write_text("{}\n")
    os.symlink(".claude", root / "linkdir")
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes_raw().hex()
    now = datetime.now(timezone.utc)
    reg = json.dumps({"schema": "weaver.gate.key_registry.v1", "keys": [{
        "key_id": "test-key", "algorithm": "ed25519", "public_key_hex": pub, "fingerprint": fingerprint(pub),
        "operator_id": "regression-test-operator", "not_before": (now - timedelta(hours=1)).isoformat(),
        "not_after": (now + timedelta(hours=1)).isoformat(), "status": "active", "revoked_at": None}]}).encode()
    (anchor_dir / "key_registry.json").write_bytes(reg)
    write_anchor(anchor_dir / "anchor.json", root, registry_path=anchor_dir / "key_registry.json",
                 registry_sha256=sha256(reg).hexdigest())

    target = str(outside / "target.txt") if file_path == "OUTSIDE" else file_path
    tool_input = {"file_path": target, "content": "x"}
    body = {"hook_event_name": "PreToolUse", "tool_name": "Write", "tool_input": tool_input, "cwd": str(root)}
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONDONTWRITEBYTECODE": "1",
           "CLAUDE_PROJECT_DIR": str(root), "WEAVER_GATE_ROLE": role, "WEAVER_GATE_ANCHOR": str(anchor_dir / "anchor.json")}

    before = snapshot(root)
    r1 = run_gate(env, body)
    # The eligible-form context an operator would sign: overridden_rule role_not_permitted.
    d = decide("Write", tool_input, root, role, role)
    req = request_hash({"tool": "Write", "input": tool_input, "role": role, "ceiling": role, "agent_id": None, "resolved_target": d.target})
    ctx = LiveContext(req, "role_not_permitted", d.target, d.target_identity, policy_digest()).signing_context()
    doc = sign(key.private_bytes_raw(), key_id="test-key", operator_id="regression-test-operator", reason="regression check",
               nonce=f"nonce-{sid}", issued_at=datetime.now(timezone.utc), lifetime=timedelta(minutes=5), context=ctx)
    (root / ".weaver" / "gate" / "overrides").mkdir(parents=True, exist_ok=True)
    (root / ".weaver" / "gate" / "overrides" / f"{req}.json").write_text(json.dumps(doc))
    r2 = run_gate(env, body)
    r3 = run_gate(env, body)
    after = snapshot(root)

    checks = {
        "run1_denied": r1["rc"] == 2,
        "run1_request_matches_signed_request": r1["request_sha256"] == req,
        "run2_expected_rc": r2["rc"] == want_rc,
        "run2_expected_rule": want_rule is None or (r2["rule"] == want_rule and r2["override_rejected"] == "not_overridable"),
        "run3_denied": r3["rc"] == 2,
        "run3_replay_reason": r3["override_rejected"] == ("replayed" if want_rc == 0 else "not_overridable"),
        "no_crash": not any("crashed" in r["stderr"] or "gate error" in r["stderr"] for r in (r1, r2, r3)),
        "project_unchanged_outside_state": before == after,
        "outside_untouched": not (outside / "target.txt").exists(),
    }
    return {"scenario": sid, "role": role, "file_path": file_path, "expected_run2": {"rc": want_rc, "rule": want_rule},
            "runs": {"run1_no_override": r1, "run2_signed_override": r2, "run3_replay": r3},
            "checks": checks, "pass": all(checks.values())}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=Path(__file__).with_name("regression_report.json"))
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        os.chmod(tmp, 0o755)
        results = [scenario(Path(tmp), *s) for s in SCENARIOS]
    for r in results:
        print(f"{r['scenario']:32s} run1={r['runs']['run1_no_override']['rc']} run2={r['runs']['run2_signed_override']['rc']}"
              f" ({r['runs']['run2_signed_override']['rule']}, {r['runs']['run2_signed_override']['override_rejected']})"
              f" run3={r['runs']['run3_replay']['rc']} pass={r['pass']}")
    report = {
        "schema": "weaver.gap003.regression_report.v1",
        "classification": "IMPLEMENTER_RUN (not R8); hook-level decisions, Claude Code not run",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "python": platform.python_version(),
        "policy_digest": policy_digest(),
        "scenarios": results,
        "all_pass": all(r["pass"] for r in results),
    }
    # Absolute temporary paths are run-specific; strip them so the report reads cleanly.
    text = json.dumps(report, indent=2, sort_keys=True)
    text = re.sub(r"/tmp/tmp[^/\"]+", "<tmp>", text)
    args.out.write_text(text + "\n")
    print("all_pass:", report["all_pass"])
    return 0 if report["all_pass"] else 1


if __name__ == "__main__":
    sys.exit(main())

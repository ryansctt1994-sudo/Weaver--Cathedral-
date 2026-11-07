"""Claude Code PreToolUse hook.

Exit 0 lets the call continue to Claude Code's normal permission flow. Exit 2
blocks it, and Claude Code shows the stderr text to the model. Any internal
error also exits 2. gate.sh handles the cases where Python itself fails.

Every decision, allowed or blocked, is appended to the chronicle at
<project>/.weaver/gate/chronicle.jsonl, together with the policy version, the
tool, and the rule that applied. Appends are serialized with a lock file, so
parallel hook calls keep the chain valid.
"""

from __future__ import annotations

import fcntl
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, TextIO

from core.authority.chronicle import Chronicle
from core.authority.gate import UncertaintyGate
from runtime.claude_code_gate.policy import POLICY_VERSION, decide

THRESHOLD = 0.7
STATE_DIR = Path(".weaver") / "gate"


def run_hook(stdin: TextIO, stderr: TextIO, env: Mapping[str, str], now: datetime | None = None) -> int:
    payload = json.load(stdin)
    if not isinstance(payload, dict) or payload.get("hook_event_name") != "PreToolUse":
        print("Weaver gate: input is not a PreToolUse event; blocking.", file=stderr)
        return 2

    root = Path(env.get("CLAUDE_PROJECT_DIR") or payload.get("cwd") or os.getcwd())
    tool_name = payload.get("tool_name")
    tool_input = payload.get("tool_input")
    decision = decide(tool_name, tool_input, root)

    state = root / STATE_DIR
    state.mkdir(parents=True, exist_ok=True)
    with open(state / "lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        gate = UncertaintyGate(threshold=THRESHOLD, chronicle=Chronicle(state / "chronicle.jsonl"))
        record = gate.evaluate(
            {"tool": tool_name, "input": tool_input},
            0.0 if decision.allowed else 1.0,
            now=now or datetime.now(timezone.utc),
            context={
                "policy_version": POLICY_VERSION,
                "tool": tool_name,
                "rule": decision.rule,
                "target": decision.target,
            },
        )

    if record.allowed:
        return 0
    print(f"Blocked by Weaver gate ({record.reason}, rule {decision.rule}): {decision.reason}", file=stderr)
    return 2


def main() -> int:
    try:
        return run_hook(sys.stdin, sys.stderr, dict(os.environ))
    except Exception as exc:  # noqa: BLE001 - any failure must block, never pass
        print(f"Weaver gate error ({type(exc).__name__}); blocking.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

"""Claude Code PreToolUse hook.

Exit 0 lets the call continue to Claude Code's normal permission flow. Exit 2
blocks it, and Claude Code shows the stderr text to the model. Any internal
error also exits 2. gate.sh covers the cases where Python itself fails.

Role and ceiling. WEAVER_GATE_ROLE, set in .claude/settings.json, is the
session's ceiling. On the main thread the role is the ceiling. When Claude Code
sends agent_type (a subagent, or a session started with --agent), that is the
role, and the policy caps it at the ceiling, so delegation can only narrow
permissions. A subagent that has an agent_id but no agent_type gets no role and
is denied. With no ceiling set, every call is denied.

Operator override (G3). When the policy denies a call, the hook looks for
<project>/.weaver/gate/overrides/<request_sha256>.json. It lets the call
through only if that file is signed with the operator's Ed25519 key, pinned in
WEAVER_GATE_OPERATOR_PUBKEY, is bound to this exact request, has not expired,
and has not been used. See override.py. Every denial prints the request hash,
which is what an operator signs.

Audit. Every decision, allowed or blocked, is appended to the chronicle at
<project>/.weaver/gate/chronicle.jsonl. Each entry records the policy version,
role, tool, rule and target. A blocked entry also carries a structured
"denial" record. Appends are serialized with a lock file, so parallel hook
calls keep the chain valid.
"""

from __future__ import annotations

import fcntl
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, TextIO

from core.authority.chronicle import Chronicle
from core.authority.gate import UncertaintyGate, request_hash
from core.authority.replay import SqliteReplayStore
from runtime.claude_code_gate import override as operator_override
from runtime.claude_code_gate.policy import POLICY_VERSION, decide, effective_permissions

THRESHOLD = 0.7
STATE_DIR = Path(".weaver") / "gate"
DENIAL_SCHEMA = "weaver.claude_code_gate.denial.v1"
DEFAULT_LOCK_TIMEOUT_S = 5.0


class LockTimeout(RuntimeError):
    """The chronicle lock was not free within the deadline. The call is blocked."""


def acquire_lock(lock_file, timeout_s: float) -> None:
    """Take an exclusive lock, waiting at most timeout_s. Never waits without a bound."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            if time.monotonic() >= deadline:
                raise LockTimeout(f"chronicle lock busy for {timeout_s}s") from None
            time.sleep(0.02)


def lock_timeout(env: Mapping[str, str]) -> float:
    raw = env.get("WEAVER_GATE_LOCK_TIMEOUT")
    try:
        value = float(raw) if raw else DEFAULT_LOCK_TIMEOUT_S
    except ValueError:
        return DEFAULT_LOCK_TIMEOUT_S
    return value if value > 0 else DEFAULT_LOCK_TIMEOUT_S


def resolve_role(payload: Mapping[str, Any], env: Mapping[str, str]) -> tuple[Any, Any]:
    """Return (role, ceiling)."""
    ceiling = env.get("WEAVER_GATE_ROLE") or None
    if "agent_type" in payload:
        return payload["agent_type"], ceiling
    if "agent_id" in payload:
        return None, ceiling  # a subagent without an agent type gets no role
    return ceiling, ceiling


def run_hook(stdin: TextIO, stderr: TextIO, env: Mapping[str, str], now: datetime | None = None) -> int:
    payload = json.load(stdin)
    if not isinstance(payload, dict) or payload.get("hook_event_name") != "PreToolUse":
        print("Weaver gate: input is not a PreToolUse event; blocking.", file=stderr)
        return 2

    root = Path(env.get("CLAUDE_PROJECT_DIR") or payload.get("cwd") or os.getcwd())
    role, ceiling = resolve_role(payload, env)
    tool_name = payload.get("tool_name")
    tool_input = payload.get("tool_input")
    decision = decide(tool_name, tool_input, root, role, ceiling)
    perms = effective_permissions(role, ceiling)

    context: dict[str, Any] = {
        "policy_version": POLICY_VERSION,
        "role": role,
        "ceiling": ceiling,
        "agent_id": payload.get("agent_id"),
        "permissions": sorted(perms) if perms is not None else None,
        "tool": tool_name,
        "rule": decision.rule,
        "target": decision.target,
    }
    if not decision.allowed:
        context["denial"] = {
            "schema": DENIAL_SCHEMA,
            "role": role,
            "ceiling": ceiling,
            "agent_id": payload.get("agent_id"),
            "tool": tool_name,
            "rule": decision.rule,
            "reason": decision.reason,
            "target": decision.target,
        }

    request = {"tool": tool_name, "input": tool_input, "role": role, "ceiling": ceiling, "agent_id": payload.get("agent_id")}
    try:
        req_sha = request_hash(request)
    except Exception:  # noqa: BLE001 - the gate vetoes an unhashable request below
        req_sha = None
    context["request_sha256"] = req_sha
    when = now or datetime.now(timezone.utc)

    state = root / STATE_DIR
    state.mkdir(parents=True, exist_ok=True)
    overridden = False
    override_problem = None
    with open(state / "lock", "a") as lock:
        acquire_lock(lock, lock_timeout(env))
        if not decision.allowed and req_sha is not None:
            doc, load_problem = operator_override.load_override(state, req_sha)
            if doc is not None or load_problem is not None:
                override_problem = load_problem or operator_override.check(
                    doc,
                    request_sha256=req_sha,
                    public_key_hex=operator_override.pinned_public_key(env),
                    rule=decision.rule,
                    now=when,
                    replay_store=SqliteReplayStore(state / "override_nonces.sqlite"),
                )
                if override_problem is None:
                    overridden = True
                    context["override"] = {**operator_override.audit_record(doc), "overridden_rule": decision.rule}
                    context.pop("denial", None)
                else:
                    context["override_rejected"] = override_problem
        gate = UncertaintyGate(threshold=THRESHOLD, chronicle=Chronicle(state / "chronicle.jsonl"))
        record = gate.evaluate(request, 0.0 if (decision.allowed or overridden) else 1.0, now=when, context=context)

    if record.allowed:
        return 0
    extra = f"; operator override rejected: {override_problem}" if override_problem else ""
    print(
        f"Blocked by Weaver gate (role {role}, ceiling {ceiling}, rule {decision.rule}, {record.reason}): "
        f"{decision.reason}{extra}. request {req_sha}",
        file=stderr,
    )
    return 2


def main() -> int:
    try:
        return run_hook(sys.stdin, sys.stderr, dict(os.environ))
    except LockTimeout as exc:
        print(f"Weaver gate: {exc}; blocking.", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - any failure must block, never pass
        print(f"Weaver gate error ({type(exc).__name__}); blocking.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

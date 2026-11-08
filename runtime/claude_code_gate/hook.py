"""Claude Code PreToolUse hook, GAP-003 remediation candidate.

Exit 0 lets the call continue to Claude Code's normal permission flow. Exit 2
blocks it, and Claude Code shows the stderr text to the model. Any internal
error also exits 2. gate.sh covers the cases where Python itself fails.

Decision order (v0.3 §3). A failure at any step denies; nothing is consumed
before step 9.

 1. Trusted root from the protected anchor (trusted_root.py). Without one the
    call is denied and, having no trusted place to write, is not chronicled.
 2-4. Policy: mandatory, role-independent checks, then the role (policy.py).
 5. Role permits and no override material: allow (subject to step 10).
 6. Role permits and override material is present: deny
    ``unsolicited_override``. The nonce is not claimed (D-1).
 7. Denied for any reason other than ``role_not_permitted``: deny; an override
    cannot lift it (OQ-1).
 8. Validate the override without consuming it (override.validate).
 9. Claim the nonce (unique-key insert), then re-check the key (TX-3).
10. Write the decision record. If that fails the call is denied
    ``chronicle_write_failed`` and a claimed nonce stays spent.

Role and ceiling. WEAVER_GATE_ROLE, set in managed settings, is the session's
ceiling. On the main thread the role is the ceiling. When Claude Code sends
agent_type, that is the role, capped at the ceiling. A subagent that has an
agent_id but no agent_type gets no role and is denied.

Audit (R9). Every chronicle entry records the policy version and digest, the
role, tool, rule, the supplied target, the normalized target, its identity and
its resolution status, including for role denials.
"""

from __future__ import annotations

import fcntl
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, TextIO

from core.authority.chronicle import Chronicle
from core.authority.gate import UncertaintyGate, request_hash
from core.authority.replay import ReplayStoreError, SqliteReplayStore
from runtime.claude_code_gate import manifest as enforcement_manifest
from runtime.claude_code_gate import override as operator_override
from runtime.claude_code_gate import registry as key_registry
from runtime.claude_code_gate import trusted_root
from runtime.claude_code_gate.policy import POLICY_VERSION, decide, effective_permissions

THRESHOLD = 0.7
STATE_DIR = Path(".weaver") / "gate"
DENIAL_SCHEMA = "weaver.claude_code_gate.denial.v2"
PENDING_SCHEMA = "weaver.claude_code_gate.pending_override.v1"
DEFAULT_LOCK_TIMEOUT_S = 5.0
DEFAULT_NONCE_TIMEOUT_S = 2.0


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


def _positive_float(env: Mapping[str, str], name: str, default: float) -> float:
    raw = env.get(name)
    try:
        value = float(raw) if raw else default
    except ValueError:
        return default
    return value if value > 0 else default


def lock_timeout(env: Mapping[str, str]) -> float:
    return _positive_float(env, "WEAVER_GATE_LOCK_TIMEOUT", DEFAULT_LOCK_TIMEOUT_S)


def resolve_role(payload: Mapping[str, Any], env: Mapping[str, str]) -> tuple[Any, Any]:
    """Return (role, ceiling)."""
    ceiling = env.get("WEAVER_GATE_ROLE") or None
    if "agent_type" in payload:
        return payload["agent_type"], ceiling
    if "agent_id" in payload:
        return None, ceiling  # a subagent without an agent type gets no role
    return ceiling, ceiling


def _default_store(state: Path, env: Mapping[str, str]):
    return SqliteReplayStore(state / "override_nonces.sqlite",
                             timeout_s=_positive_float(env, "WEAVER_GATE_NONCE_TIMEOUT", DEFAULT_NONCE_TIMEOUT_S))


def run_hook(stdin: TextIO, stderr: TextIO, env: Mapping[str, str], now: datetime | None = None, *,
             store_factory: Callable[[Path, Mapping[str, str]], Any] | None = None) -> int:
    payload = json.load(stdin)
    if not isinstance(payload, dict) or payload.get("hook_event_name") != "PreToolUse":
        print("Weaver gate: input is not a PreToolUse event; blocking.", file=stderr)
        return 2
    when = now or datetime.now(timezone.utc)
    anchor_path = trusted_root.anchor_location(env)

    # Step 1: trusted root (T).
    try:
        anchor = trusted_root.load_anchor(anchor_path)
        root = trusted_root.establish_root(anchor, env)
    except trusted_root.TrustError as exc:
        print(f"Blocked by Weaver gate (rule {exc.rule}): {exc.detail}. Not chronicled: no trusted root.", file=stderr)
        return 2

    # Steps 2-4 (and the role check of step 5).
    role, ceiling = resolve_role(payload, env)
    tool_name = payload.get("tool_name")
    tool_input = payload.get("tool_input")
    decision = decide(tool_name, tool_input, root, role, ceiling)
    perms = effective_permissions(role, ceiling)
    try:
        digest = enforcement_manifest.policy_digest()
    except OSError:
        digest = None

    context: dict[str, Any] = {
        "policy_version": POLICY_VERSION,
        "policy_digest": digest,
        "role": role,
        "ceiling": ceiling,
        "agent_id": payload.get("agent_id"),
        "permissions": sorted(perms) if perms is not None else None,
        "tool": tool_name,
        "rule": decision.rule,
        "target": decision.target,
        "supplied_target": decision.supplied_target,
        "target_identity": decision.target_identity,
        "target_status": decision.target_status,
    }
    request = {"tool": tool_name, "input": tool_input, "role": role, "ceiling": ceiling,
               "agent_id": payload.get("agent_id"), "resolved_target": decision.target}
    try:
        req_sha = request_hash(request)
    except Exception:  # noqa: BLE001 - the gate vetoes an unhashable request below
        req_sha = None
    context["request_sha256"] = req_sha

    state = root / STATE_DIR
    state.mkdir(parents=True, exist_ok=True)
    allowed = decision.allowed
    final_rule = decision.rule
    final_reason = decision.reason
    override_problem: str | None = None
    overridden = False

    with open(state / "lock", "a") as lock:
        acquire_lock(lock, lock_timeout(env))
        doc, load_problem = (operator_override.load_override(state, req_sha) if req_sha is not None else (None, None))
        material = doc is not None or load_problem is not None

        if decision.allowed and material:
            # Step 6 (D-1): unsolicited material is denied, never ignored; nothing is consumed.
            allowed, final_rule = False, "unsolicited_override"
            final_reason = "override material is present for a call the role already permits"
            override_problem = "unsolicited_override"
        elif not decision.allowed and material:
            if not decision.overridable:
                override_problem = "not_overridable"                      # step 7 (OQ-1)
            elif load_problem is not None:
                override_problem = load_problem
            elif digest is None:
                override_problem = "policy_digest_unavailable"
            else:
                live = operator_override.LiveContext(req_sha, decision.rule, decision.target, decision.target_identity, digest)
                try:
                    keys = key_registry.load_registry(anchor.registry_path, anchor.registry_sha256)
                except key_registry.RegistryError as exc:
                    override_problem = exc.rule
                else:
                    override_problem = operator_override.validate(doc, live=live, keys=keys, now=when)  # step 8
                if override_problem is None:
                    try:                                                       # step 9
                        store = (store_factory or _default_store)(state, env)
                    except ReplayStoreError:
                        override_problem = "nonce_store_unavailable"
                    else:
                        override_problem = operator_override.claim(doc, store)
                if override_problem is None:
                    # TX-3: re-read the anchor and registry; a revocation now is honoured.
                    try:
                        fresh_anchor = trusted_root.load_anchor(anchor_path)
                        fresh_keys = key_registry.load_registry(fresh_anchor.registry_path, fresh_anchor.registry_sha256)
                        override_problem = operator_override.recheck_key(doc, fresh_keys, when)
                    except trusted_root.TrustError:
                        override_problem = "trusted_root_missing"
                    except key_registry.RegistryError as exc:
                        override_problem = exc.rule
                overridden = override_problem is None

        if overridden:
            context["override"] = {**operator_override.audit_record(doc), "overridden_rule": decision.rule}
        else:
            if override_problem is not None:
                context["override_rejected"] = override_problem
            if not allowed:
                context["rule"] = final_rule
                context["denial"] = {
                    "schema": DENIAL_SCHEMA,
                    "role": role,
                    "ceiling": ceiling,
                    "agent_id": payload.get("agent_id"),
                    "tool": tool_name,
                    "rule": final_rule,
                    "reason": final_reason,
                    "overridable": decision.overridable and final_rule == decision.rule,
                    "target": decision.target,
                    "supplied_target": decision.supplied_target,
                    "target_identity": decision.target_identity,
                    "target_status": decision.target_status,
                }
        # Step 10: the decision record. An unrecorded allow is not allowed.
        gate = UncertaintyGate(threshold=THRESHOLD, chronicle=Chronicle(state / "chronicle.jsonl"))
        record = gate.evaluate(request, 0.0 if (allowed or overridden) else 1.0, now=when, context=context)

        pending_written = False
        if not record.allowed and decision.overridable and final_rule == decision.rule and not overridden and digest is not None:
            pending = {
                "schema": PENDING_SCHEMA,
                "tool": tool_name, "input": tool_input, "role": role, "ceiling": ceiling,
                "agent_id": payload.get("agent_id"), "supplied_target": decision.supplied_target,
                "signing_context": operator_override.LiveContext(req_sha, decision.rule, decision.target,
                                                                 decision.target_identity, digest).signing_context(),
            }
            (state / "pending").mkdir(exist_ok=True)
            (state / "pending" / f"{req_sha}.json").write_text(json.dumps(pending, indent=2, sort_keys=True) + "\n")
            pending_written = True

    if record.allowed:
        return 0
    if (allowed or overridden) and record.reason.startswith("chronicle_write_failed"):
        final_rule, final_reason = "chronicle_write_failed", "the decision could not be recorded"
    extra = f"; operator override rejected: {override_problem}" if override_problem else ""
    hint = f"; an operator may sign .weaver/gate/pending/{req_sha}.json" if pending_written else ""
    print(
        f"Blocked by Weaver gate (role {role}, ceiling {ceiling}, rule {final_rule}, {record.reason}): "
        f"{final_reason}{extra}{hint}. request {req_sha}",
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

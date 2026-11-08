# Claude Code gate (GAP-003 candidate)

A PreToolUse hook that decides whether each Claude Code tool call may run, for the agent's role. It is an implementation candidate on branch `gap-003/claude-code-adapter`. It is not merged, not independently validated, and GAP-003 stays OPEN.

## What the hook can and cannot do

The hook is an **advisory enforcement layer**. It sees only tool calls that Claude Code routes through it. A process the agent starts outside that path, or a Bash command that writes through a route the text check misses, is not stopped by the hook. Protection for files the agent must not change has to come from the operating environment: file ownership and permissions that the agent's user cannot override. `tests/test_claude_code_gate_boundary.py` shows the difference, and `python -m runtime.claude_code_gate.boundary_demo` prints it.

## Behaviour

| Outcome | Exit code | Effect |
|---|---|---|
| Allowed by role and rule | 0 | The call continues to Claude Code's normal permission flow. The gate does not approve calls by itself. |
| Denied by role or rule, or any internal error | 2 | Blocked. The reason goes to stderr, and Claude Code shows it to the model. |
| Python crashes, is missing, or exits with any other code | 2 (from `gate.sh`) | Blocked. |

Every decision is appended to `.weaver/gate/chronicle.jsonl` (hash-chained). Each entry records the policy version, role, tool, rule and target. A blocked entry also carries a structured `denial` record, with schema `weaver.claude_code_gate.denial.v1`. Check the chain with `python -m core.authority chronicle-verify .weaver/gate/chronicle.jsonl`.

## Roles

The roles follow SKILL_SPEC's agent binding.

| Role | Permissions |
|---|---|
| Planner | Read tools; read-only Bash; delegate |
| Researcher, Sentinel | Read tools; read-only Bash |
| Builder | Read tools; read-only Bash; Edit, Write, MultiEdit and NotebookEdit inside the project; delegate |
| Verifier | Read tools; read-only Bash; `pytest` and `python -m pytest` (without plugin or config flags) |
| Operator | None. People approve single denied calls through signed operator overrides (see below), not through a role. |

Anything else is denied: no role, an unknown role, a subagent with no `agent_type`, unknown tools, MCP tools, and malformed input.

**Where the role comes from, and the ceiling.** `WEAVER_GATE_ROLE`, set in `.claude/settings.json`, is the session's **ceiling**. On the main thread, the role is the ceiling. When Claude Code sends `agent_type` (a subagent, or a session started with `--agent`), that is the role. Its permissions are **intersected with the ceiling**, so a subagent can never hold anything its session does not. A subagent with an `agent_id` but no `agent_type` gets no role. With no ceiling set, every call is denied.

**Delegation.** The `Agent` tool (also `Task`) needs the `delegate` permission. The `subagent_type` must be a known role. The spawn is refused (`delegation_escalation`) when that role would hold any permission the caller does not hold under its ceiling. A Planner therefore cannot hand writes to a Builder subagent. The ceiling also applies to every call the subagent makes, so the spawn check is not the only barrier.

Subagent definitions (`.claude/agents/*.md`) whose `name` is a role name get that role, capped by the ceiling. Any other agent type, such as `general-purpose`, is denied.

## Path and Bash rules

- **Read, Glob, Grep:** the target must resolve inside the project root, following symlinks.
- **Writes:** also outside `.claude/`, `.weaver/`, `.git/` and `runtime/claude_code_gate/`.
- **Bash:** no pipes, redirection, substitution, grouping, chaining or newlines. Arguments may not be absolute, home-relative, climb out of the root, name a protected path, or use flags that run code or write files.

**The Verifier role runs repository code.** Test code can write anything, so for Verifier the Bash rules do not limit what runs. Only operating-system permissions can. Grant the Verifier role only where that is acceptable.

## Operator override (G3)

Only a `role_not_permitted` denial can be lifted, and only after every mandatory check (paths, protected prefixes, symlinks, Bash rules, delegation escalation) has already passed. When the hook issues that denial it writes `.weaver/gate/pending/<request_sha256>.json`. An operator who approves that one call signs it:

```bash
python -m runtime.claude_code_gate.operator sign --private <key> --key-id <key_id> --operator <id> \
    --pending <project>/.weaver/gate/pending/<sha256>.json --reason "<why>" --minutes 10 \
    --out <project>/.weaver/gate/overrides/<sha256>.json
```

The same call then goes through once. The signature must come from a key in the anchored, pinned key registry, and it binds the request, the overridden rule, the resolved target, the target's filesystem identity and the policy digest. Mandatory denials, including protected paths and paths outside the project, cannot be lifted. (On the baseline `300bd32` they could; see the retraction in [`OVERRIDE.md`](OVERRIDE.md).) Every use and every rejected attempt is chronicled.

## Installing it (candidate)

A person adds this to `.claude/settings.json` (or managed settings) and commits it. The agent cannot change that file through the gate. An administrator also writes a root-owned anchor at `/etc/weaver-gate/anchor.json` naming the project root, its `(st_dev, st_ino)` and the pinned key registry; `trusted_root.write_anchor` produces one. Without an anchor every call is denied (`trusted_root_missing`).

```json
{
  "env": { "WEAVER_GATE_ROLE": "Builder" },
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "bash \"$CLAUDE_PROJECT_DIR/runtime/claude_code_gate/gate.sh\"",
            "timeout": 10,
            "onFailure": "block"
          }
        ]
      }
    ]
  }
}
```

`gate.sh` remains in place even with `onFailure`, so a crash is blocked on any Claude Code version that does not honour the field.

`timeout` is set because a timed-out hook fails open unless `onFailure` is `block`. Tested on 2.1.319: a hook that sleeps past a 2-second timeout let the write through with no `onFailure`, and blocked it with `onFailure: "block"`. The gate's own lock wait is bounded (`WEAVER_GATE_LOCK_TIMEOUT`, default 5 seconds) and fails closed, so the hook returns well inside the timeout.

## Verified in this environment

Against Claude Code 2.1.319 (`claude --version`), by running real sessions:

- exit 2 blocked the Write call, and the reason was shown to the model;
- exit 1 without `onFailure` let the Write go through, so a crash fails open;
- exit 1 with `onFailure: "block"` blocked the Write;
- `env` in `.claude/settings.json` reached the hook as the role: a Verifier session was denied a Write and a Builder session was allowed one, and the chronicle recorded each decision with its role.

Not verified: subagent behaviour end to end in this version, and any other Claude Code version.

## Limits

- **Advisory, not a sandbox.** See the top of this file.
- **Operator overrides are signed, not shared-key.** The hook holds only public keys from the pinned registry, and each private key must stay where the agent's user cannot read it. See [`OVERRIDE.md`](OVERRIDE.md) for the design, the flow and the deployment requirements.
- **One host, one project.** The chronicle is a local file serialized by a lock. It has no signed head and no multi-host storage.
- **Not independently validated.** GAP-003 stays OPEN until it is.

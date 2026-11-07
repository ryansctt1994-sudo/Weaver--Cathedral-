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
| Planner, Researcher, Sentinel | Read tools; read-only Bash |
| Builder | Read tools; read-only Bash; Edit, Write, MultiEdit and NotebookEdit inside the project |
| Verifier | Read tools; read-only Bash; `pytest` and `python -m pytest` (without plugin or config flags) |
| Operator | None. The human-authorized override path is not implemented. |

Anything else is denied: no role, an unknown role, a subagent with no `agent_type`, unknown tools, MCP tools, and malformed input.

**Where the role comes from.** The hook input's `agent_type` is used when Claude Code sends it, for a subagent or a session started with `--agent`. Otherwise the role comes from the `WEAVER_GATE_ROLE` environment variable, which `.claude/settings.json` sets for the main thread. A subagent with an `agent_id` but no `agent_type` is denied, so it cannot inherit the main thread's role.

## Path and Bash rules

- **Read, Glob, Grep:** the target must resolve inside the project root, following symlinks.
- **Writes:** also outside `.claude/`, `.weaver/`, `.git/` and `runtime/claude_code_gate/`.
- **Bash:** no pipes, redirection, substitution, grouping, chaining or newlines. Arguments may not be absolute, home-relative, climb out of the root, name a protected path, or use flags that run code or write files.

**The Verifier role runs repository code.** Test code can write anything, so for Verifier the Bash rules do not limit what runs. Only operating-system permissions can. Grant the Verifier role only where that is acceptable.

## Installing it (candidate)

A person adds this to `.claude/settings.json` and commits it. The agent cannot change that file through the gate.

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
            "onFailure": "block"
          }
        ]
      }
    ]
  }
}
```

`gate.sh` remains in place even with `onFailure`, so a crash is blocked on any Claude Code version that does not honour the field.

## Verified in this environment

Against Claude Code 2.1.319 (`claude --version`), by running real sessions:

- exit 2 blocked the Write call, and the reason was shown to the model;
- exit 1 without `onFailure` let the Write go through, so a crash fails open;
- exit 1 with `onFailure: "block"` blocked the Write;
- `env` in `.claude/settings.json` reached the hook as the role: a Verifier session was denied a Write and a Builder session was allowed one, and the chronicle recorded each decision with its role.

Not verified: subagent behaviour end to end in this version, and any other Claude Code version.

## Limits

- **Advisory, not a sandbox.** See the top of this file.
- **No keys and no override path.** The hook holds no signing key.
- **One host, one project.** The chronicle is a local file serialized by a lock. It has no signed head and no multi-host storage.
- **Not independently validated.** GAP-003 stays OPEN until it is.

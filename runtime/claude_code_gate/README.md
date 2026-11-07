# Claude Code gate

A PreToolUse hook that decides whether each Claude Code tool call may run. It closes GAP-003 in `governance/open_gap_ledger.md`: the agent harness was not connected to the governance gates.

## Behaviour

| Outcome | Exit code | Effect |
|---|---|---|
| Allowed by a rule | 0 | The call continues to Claude Code's normal permission flow. The gate does not approve calls by itself. |
| Denied by the policy, or any internal error | 2 | The call is blocked. The reason is written to stderr, and Claude Code shows it to the model. |
| Python crashes, is missing, or exits with any other code | 2 (from `gate.sh`) | Blocked. Claude Code treats other non-zero codes as non-blocking, so the wrapper converts them. |

Every decision is appended to `.weaver/gate/chronicle.jsonl` with the policy version, tool, rule and target. Each entry is hash-chained, so `weaver-authority chronicle-verify .weaver/gate/chronicle.jsonl` detects edits.

## Policy (`policy.py`)

The default is deny.

- **Read, Glob, Grep:** the target must resolve inside the project root, following symlinks.
- **Edit, Write, MultiEdit, NotebookEdit:** the target must resolve inside the project root and outside `.claude/`, `.weaver/`, `.git/` and `runtime/claude_code_gate/`.
- **Bash:** no pipes, redirection, substitution, grouping, chaining or newlines. The program must be `ls`, `cat`, `head`, `tail`, `wc`, `grep`, `rg`, `pwd`, or `git status|log|diff|show`. Arguments may not be absolute, home-relative, climb out of the root, name a protected path, or use flags that run code or write files.
- **Anything else** (other tools, MCP tools, unknown names, malformed input) is vetoed.

Programs that run code are not on the Bash allowlist. That includes `python`, `pytest`, `make` and `npm`, because test code can write anything. Under this gate the agent cannot run tests. Run them yourself, or extend the policy deliberately with a test for the new allow.

## Installing it

The gate lives in this repository. Add the hook in `.claude/settings.json`. A person should commit that file. The agent cannot write it through the gate.

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          { "type": "command", "command": "bash \"$CLAUDE_PROJECT_DIR/runtime/claude_code_gate/gate.sh\"" }
        ]
      }
    ]
  }
}
```

## Limits

- **Bash checks are a text match against an allowlist, not a sandbox.** Their strength depends on the allowlist and the syntax check. The gate's protections for protected paths hold for Edit and Write tools. For Bash, the real protection has to come from file permissions that stop the agent process from writing those paths.
- **No keys and no overrides.** The hook has no operator-override path, so it holds no signing key. Overrides belong in a later change with its own review.
- **One host, one project.** The chronicle is a local file serialized by a lock. It has no signed head and no multi-host storage.
- **Not yet checked against the current Claude Code hook documentation.** The exit-code behaviour and the `hook_event_name` and `CLAUDE_PROJECT_DIR` fields are taken from how the hook is designed to be used. Confirm them before relying on the gate.
- **Hooks run in the same process as the agent's permissions.** A user who edits `.claude/settings.json` by hand can remove the hook. This is intended.

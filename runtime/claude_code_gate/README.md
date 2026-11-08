# claude_code_gate: a fail-closed tool gate for Claude Code (GAP-003)

A Claude Code `PreToolUse` hook. Before Claude Code runs any tool, the hook asks
`core.authority.UncertaintyGate` whether the call may go ahead, and appends the
decision to a hash-chained Chronicle.

- **Vetoed calls are blocked** (exit code 2). Claude sees the reason, the policy
  rule, and the call's request hash.
- **Allowed calls are not approved.** The hook exits 0 with no output, so
  Claude Code's normal permission prompts still apply. The gate can only narrow
  what runs.
- **Anything the hook cannot decide is blocked**: a malformed event, a missing or
  invalid config, an unreadable key, an unwritable state directory, a Chronicle
  that fails verification.

## How a call is decided

1. **Protected paths.** A call that reaches the gate's own config, its state
   directory, its override key, any extra `protected_paths`, or a Claude Code
   `settings.json` / `settings.local.json` gets uncertainty 1.0. This covers path
   fields (resolved through symlinks) and any string in the tool input. This
   veto is final: no operator override lifts it.
2. **Rules,** in order. The first rule whose `tool` regex matches the tool name,
   and whose optional `path_glob` and `input_regex` match the input, sets the
   uncertainty.
3. **Default.** No match gets `default_uncertainty`, which must be at least the
   threshold, so unknown tools are vetoed.
4. **Gate.** Uncertainty below `threshold` passes. At or above it, the call is
   vetoed unless an operator has signed an override for that exact call. A
   protected-path veto (step 1) is the exception: it is never overridable.

Each Chronicle entry records the decision, the request hash, the uncertainty,
the threshold, and a `context` with the tool name, the rule id, the session id
and the SHA-256 of the config file the decision was made under.

## Setup

```bash
python3 -m venv ~/.weaver-gate/venv
~/.weaver-gate/venv/bin/pip install -e /path/to/Weaver--Cathedral-
cp runtime/claude_code_gate/gate.example.json ~/.weaver-gate/gate.json   # then edit the rules
```

Keep the config and its `state_dir` outside the repository the agent works in.
Then add the hook to Claude Code's settings, as in `settings.example.json`:

```json
"command": "~/.weaver-gate/venv/bin/weaver-claude-gate pre-tool-use --config ~/.weaver-gate/gate.json || exit 2"
```

Use the installed `weaver-claude-gate` script, not `python -m runtime.claude_code_gate`.
Claude Code runs hooks from inside your project, and `python -m` searches the current
directory first: a project with its own `runtime/` package would shadow the gate, and
every call would be blocked (`test_console_script_is_not_shadowed_by_the_project`).

The trailing `|| exit 2` matters. Claude Code treats exit codes other than 0 and
2 as non-blocking errors and runs the call. With the wrapper, a crash before
Python starts (a moved venv, a typo in the path) blocks instead
(`test_the_settings_wrapper_turns_any_crash_into_a_block`).

## Overrides

Overrides are off unless `override_key_file` is set. To turn them on, write a
32-byte key as hex somewhere the agent cannot read:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))" > /path/the/agent/cannot/read/gate.key
```

When a call is vetoed, the message includes its request hash. An operator then
runs:

```bash
weaver-claude-gate sign-override --config ~/.weaver-gate/gate.json \
  --request-hash <hash> --operator <name> --reason "<why>"
```

The override is an HMAC over that one request hash. It expires after
`override_max_age_seconds` (default 300), is spent the first time it is used,
and its nonce is kept until the override could no longer be accepted anyway
(GAP-002). An override moved to another call, an expired one, a replayed one,
and one signed with another key are all refused.

An override never lifts a protected-path veto. The gate does not pass it to
the decision, does not spend its nonce, and records `override_refused:
not_overridable` in the Chronicle. Change protected files outside the agent's
session. (Before this was fixed, a valid override did lift those vetoes.)

## Checking the record

```bash
weaver-claude-gate verify --config ~/.weaver-gate/gate.json
weaver-claude-gate verify --config ~/.weaver-gate/gate.json --expected-head <head you recorded>
```

Without `--expected-head`, edits, deletions, reorders and insertions are
detected, but cutting entries off the end is not. Record the head somewhere else
from time to time and pass it in.

## Limits

- **Text patterns can be evaded.** Rules over shell commands see text: aliases,
  `bash -c`, variables, encodings and new tools get around them. Treat Bash
  rules as a tripwire for mistakes, not as containment. Unknown tools are
  vetoed, which is the part that does not depend on patterns.
- **On one account, the agent can reach what the hook can reach.** The
  protected-path rule blocks the obvious routes to the config, the state and the
  key, but an agent that obfuscates a path can read or change them. Overrides
  mean something only if the key lives where the agent cannot get it: another
  account or another machine. Otherwise the Chronicle still records every
  override used, by whom it says it was signed.
- **The Chronicle is held by the operator.** It detects edits against itself and
  truncation against a head recorded elsewhere. A party who controls the file
  can rewrite all of it. This is W0 in portfolio terms.
- **Hook timeouts are Claude Code's.** What Claude Code does when a hook exceeds
  its `timeout` is not tested here. Use a generous timeout.
- **Cost grows with the Chronicle.** Every call re-verifies the whole chain. To
  start a fresh file, archive the old one and record its head.
- **Not run in a live session here.** The tests drive the hook with PreToolUse
  payloads shaped like Claude Code's. No end-to-end session is recorded as
  evidence.
- **POSIX only.** Concurrent hooks are serialized with `flock`; without it the
  hook refuses to run.

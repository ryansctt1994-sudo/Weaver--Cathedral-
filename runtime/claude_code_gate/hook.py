"""Claude Code PreToolUse hook: every tool call goes through the uncertainty gate.

Claude Code passes the hook a JSON object on stdin (``hook_event_name``,
``tool_name``, ``tool_input``, ``session_id``, ...). The exit code decides:

* **2 blocks the call**, and stderr is shown to Claude. Every VETO, and every
  error inside the hook, exits 2.
* **0 with no output** lets Claude Code carry on with its normal permission
  flow. The hook never prints a ``permissionDecision``, so it can only narrow
  what Claude Code would allow. It never approves anything by itself.
* Claude Code treats any other exit code as a non-blocking error and runs the
  call. So the settings command ends in ``|| exit 2``: a failure before this
  code runs (missing interpreter, wrong path) also blocks.

Every decision, allow or veto, is appended to the gate's Chronicle with the
tool name, the policy rule that set the uncertainty, and the config's SHA-256.
The Chronicle is loaded, verified and appended under an exclusive file lock,
because Claude Code may run hooks for parallel tool calls at the same time. A
Chronicle that fails verification stops the gate: every call is vetoed until
an operator deals with it.

Outside this code's control: what Claude Code does when a hook exceeds its
``timeout`` (not tested here), and anything the agent does on the same
account that the policy's patterns do not see. See README.md, "Limits".
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import secrets
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, TextIO

from core.authority.chronicle import Chronicle, verify_entries, verify_file
from core.authority.gate import GateDecision, GateRecord, UncertaintyGate, request_hash, sign_override
from core.authority.replay import SqliteReplayStore

from .policy import GateConfig, Match, load_config

ADAPTER_ID = "weaver.claude_code_gate.v1"
EXIT_ALLOW = 0
EXIT_BLOCK = 2
_HASH = re.compile(r"^[0-9a-f]{64}$")


class HookError(RuntimeError):
    """The hook cannot decide. The call is blocked."""


@dataclass(frozen=True)
class HookResult:
    exit_code: int
    message: str


@contextlib.contextmanager
def _exclusive(lock_path: Path) -> Iterator[None]:
    try:
        import fcntl
    except ImportError as exc:  # pragma: no cover - non-POSIX
        raise HookError("the gate needs POSIX file locking (fcntl) and refuses to run without it") from exc
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with open(lock_path, "a", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def read_override_key(config: GateConfig) -> bytes | None:
    """The HMAC key from ``override_key_file`` (hex), or None when overrides are off."""
    if config.override_key_file is None:
        return None
    try:
        key = bytes.fromhex(config.override_key_file.read_text(encoding="ascii").strip())
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        raise HookError(f"cannot read the override key file ({type(exc).__name__})") from exc
    if len(key) < 32:
        raise HookError("the override key must be at least 32 bytes (64 hex characters)")
    return key


def _parse_payload(text: str) -> tuple[str, dict[str, Any], str | None]:
    try:
        payload = json.loads(text)
    except ValueError as exc:
        raise HookError("hook input is not JSON") from exc
    if not isinstance(payload, dict):
        raise HookError("hook input must be a JSON object")
    if payload.get("hook_event_name") != "PreToolUse":
        raise HookError(f"expected a PreToolUse event, got {payload.get('hook_event_name')!r}")
    tool_name, tool_input = payload.get("tool_name"), payload.get("tool_input")
    if not isinstance(tool_name, str) or not tool_name:
        raise HookError("hook input has no tool_name")
    if not isinstance(tool_input, dict):
        raise HookError("hook input's tool_input must be an object")
    session = payload.get("session_id")
    return tool_name, tool_input, session if isinstance(session, str) and len(session) <= 200 else None


def _load_override(config: GateConfig, req_hash: str) -> Any:
    path = config.overrides_dir / f"{req_hash}.json"
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise HookError(f"override file for this call is unreadable ({type(exc).__name__})") from exc


def _veto_message(config: GateConfig, tool_name: str, match: Match, record: GateRecord, req_hash: str) -> str:
    lines = [
        f"Weaver gate VETO for {tool_name}: {match.reason}.",
        f"Rule {match.rule_id}: uncertainty {match.uncertainty:.2f}, threshold {config.threshold:.2f} ({record.reason}).",
        f"request_hash: {req_hash}",
    ]
    if record.chronicle_index is not None:
        lines.append(f"Recorded in the gate chronicle as entry {record.chronicle_index}.")
    if config.override_key_file is None:
        lines.append("Overrides are not configured for this gate.")
    else:
        lines.append(
            "An operator, not the agent, can allow this exact call once with: weaver-claude-gate sign-override "
            f"--config {config.path} --request-hash {req_hash} --operator NAME --reason TEXT"
        )
    return "\n".join(lines)


def pre_tool_use(config_path: str | Path, stdin_text: str, now: datetime) -> HookResult:
    """Decide one PreToolUse call. Raises on anything it cannot decide; callers block."""
    config = load_config(config_path)
    tool_name, tool_input, session_id = _parse_payload(stdin_text)
    match = config.classify(tool_name, tool_input)
    request = {"tool_name": tool_name, "tool_input": tool_input}
    req_hash = request_hash(request)
    key = read_override_key(config)
    override = _load_override(config, req_hash) if key is not None else None
    context = {
        "adapter": ADAPTER_ID,
        "tool_name": tool_name,
        "rule_id": match.rule_id,
        "config_sha256": config.sha256,
    }
    if session_id:
        context["session_id"] = session_id

    config.state_dir.mkdir(parents=True, exist_ok=True)
    with _exclusive(config.lock_path):
        gate = UncertaintyGate(
            threshold=config.threshold,
            override_key=key,
            replay_cache=SqliteReplayStore(config.replay_path) if key is not None else None,
            chronicle=Chronicle(config.chronicle_path),
            override_max_age=config.override_max_age,
        )
        record = gate.evaluate(request, match.uncertainty, now=now, override=override, context=context)

    if record.allowed and record.chronicle_index is not None:
        if record.decision is GateDecision.ALLOW_WITH_OVERRIDE:
            return HookResult(
                EXIT_ALLOW,
                f"Weaver gate: {tool_name} allowed once by an override from {record.override_operator} "
                f"(chronicle entry {record.chronicle_index}).",
            )
        return HookResult(EXIT_ALLOW, "")
    return HookResult(EXIT_BLOCK, _veto_message(config, tool_name, match, record, req_hash))


# --- CLI -----------------------------------------------------------------------


def _cmd_pre_tool_use(args: argparse.Namespace, stdin: TextIO, now: datetime) -> int:
    try:
        result = pre_tool_use(args.config, stdin.read(), now)
    except Exception as exc:  # noqa: BLE001 - every failure blocks the call
        print(
            f"Weaver gate: blocked because the gate could not decide ({type(exc).__name__}: {exc}). Failing closed.",
            file=sys.stderr,
        )
        return EXIT_BLOCK
    if result.message:
        print(result.message, file=sys.stderr)
    return result.exit_code


def _cmd_sign_override(args: argparse.Namespace, now: datetime) -> int:
    config = load_config(args.config)
    key = read_override_key(config)
    if key is None:
        print("overrides are not configured: set override_key_file in the gate config", file=sys.stderr)
        return 1
    if not _HASH.match(args.request_hash):
        print("request hash must be 64 lowercase hex characters", file=sys.stderr)
        return 1
    override = sign_override(
        key,
        operator_id=args.operator,
        reason=args.reason,
        request_hash=args.request_hash,
        nonce=args.nonce or secrets.token_hex(16),
        issued_at=now,
    )
    config.overrides_dir.mkdir(parents=True, exist_ok=True)
    target = config.overrides_dir / f"{args.request_hash}.json"
    staging = target.with_suffix(".json.tmp")
    staging.write_text(json.dumps(override, indent=2) + "\n", encoding="utf-8")
    os.replace(staging, target)
    print(target)
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    path = config.chronicle_path
    result = verify_file(path, args.expected_head) if path.exists() else verify_entries([], args.expected_head)
    print(json.dumps(asdict(result), indent=2))
    return 0 if result.ok else 1


def main(
    argv: list[str] | None = None,
    *,
    stdin: TextIO | None = None,
    clock: Callable[[], datetime] | None = None,
) -> int:
    parser = argparse.ArgumentParser(prog="weaver-claude-gate", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    hook = sub.add_parser("pre-tool-use", help="Run as a Claude Code PreToolUse hook (reads the event on stdin)")
    hook.add_argument("--config", required=True)

    sign = sub.add_parser("sign-override", help="Operator: allow one vetoed call, by its request hash")
    sign.add_argument("--config", required=True)
    sign.add_argument("--request-hash", required=True)
    sign.add_argument("--operator", required=True)
    sign.add_argument("--reason", required=True)
    sign.add_argument("--nonce")

    check = sub.add_parser("verify", help="Verify the gate chronicle")
    check.add_argument("--config", required=True)
    check.add_argument("--expected-head")

    args = parser.parse_args(argv)
    now = (clock or (lambda: datetime.now(timezone.utc)))()
    if args.command == "pre-tool-use":
        return _cmd_pre_tool_use(args, stdin or sys.stdin, now)
    if args.command == "sign-override":
        return _cmd_sign_override(args, now)
    return _cmd_verify(args)

"""Decide whether one Claude Code tool call may run.

Default deny: a call is vetoed unless a rule below allows it.

* Read, Glob, Grep: the target must resolve, after symlinks, inside the
  project root. Glob and Grep without a path search the root.
* Edit, Write, MultiEdit, NotebookEdit: the target must resolve inside the
  project root and outside the protected prefixes, which hold the gate's own
  code and state, Claude Code's settings, and the git directory.
* Bash: no shell syntax (pipes, redirection, substitution, grouping,
  chaining, newlines). The program must be on the read-only allowlist.
  Programs that run code (python, pytest, make, npm) are not on it, because
  test code could write anything. Arguments may not be absolute,
  home-relative, or climb out of the root, and may not name a protected path.

The Bash checks are a text match against an allowlist, not a sandbox. Their
strength is the allowlist and the syntax check, and they are not a substitute
for file permissions that stop the agent process from writing protected paths.
"""

from __future__ import annotations

import os
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

POLICY_VERSION = "weaver.claude_code_policy.v1"

READ_TOOLS = frozenset({"Read", "Glob", "Grep"})
WRITE_TOOLS = frozenset({"Edit", "Write", "MultiEdit", "NotebookEdit"})
PATH_FIELDS = {
    "Read": "file_path",
    "Glob": "path",
    "Grep": "path",
    "Edit": "file_path",
    "Write": "file_path",
    "MultiEdit": "file_path",
    "NotebookEdit": "notebook_path",
}
# Tools that search the whole root when no path is given.
OPTIONAL_PATH_TOOLS = frozenset({"Glob", "Grep"})

# Relative prefixes that no write tool may touch and no Bash argument may name.
PROTECTED_PREFIXES = (".claude", ".weaver", ".git", "runtime/claude_code_gate")
PROTECTED_COMPONENTS = frozenset({".claude", ".weaver", ".git"})

READ_ONLY_PROGRAMS = frozenset({"ls", "cat", "head", "tail", "wc", "grep", "rg", "pwd"})
READ_ONLY_GIT = frozenset({"status", "log", "diff", "show"})
# Flags that make a read-only program run code or write a file.
FORBIDDEN_FLAG_PREFIXES = ("--pre", "--exec", "--output", "--ext-diff", "--textconv")
SHELL_SYNTAX = frozenset(";&|<>`$(){}\\\n\r")


@dataclass(frozen=True)
class Decision:
    allowed: bool
    rule: str
    reason: str
    target: str | None = None


def _veto(rule: str, reason: str, target: str | None = None) -> Decision:
    return Decision(False, rule, reason, target)


def _allow(rule: str, target: str | None = None) -> Decision:
    return Decision(True, rule, "allowed", target)


def _relative_inside(root: Path, raw: str) -> str | None:
    """Resolve raw against root, following symlinks. None if it lands outside root."""
    real_root = os.path.realpath(root)
    candidate = raw if os.path.isabs(raw) else os.path.join(real_root, raw)
    rel = os.path.relpath(os.path.realpath(candidate), real_root)
    if rel == os.pardir or rel.startswith(os.pardir + os.sep) or os.path.isabs(rel):
        return None
    return Path(rel).as_posix()


def is_protected(rel: str) -> bool:
    return any(rel == prefix or rel.startswith(prefix + "/") for prefix in PROTECTED_PREFIXES)


def _names_protected(arg: str) -> bool:
    parts = Path(arg).parts
    if any(part in PROTECTED_COMPONENTS for part in parts):
        return True
    return os.path.normpath(arg).startswith("runtime/claude_code_gate")


def _decide_path(tool: str, tool_input: Mapping[str, Any], root: Path, *, write: bool) -> Decision:
    field = PATH_FIELDS[tool]
    raw = tool_input.get(field)
    if raw is None and tool in OPTIONAL_PATH_TOOLS:
        raw = "."
    if not isinstance(raw, str) or not raw:
        return _veto("missing_path", f"{tool} needs a string {field}")
    rel = _relative_inside(root, raw)
    if rel is None:
        return _veto("outside_project", f"{raw} is outside the project root", raw)
    if write and is_protected(rel):
        return _veto("protected_path", f"{rel} is protected from edits", rel)
    return _allow("write_inside_project" if write else "read_inside_project", rel)


def _decide_bash(tool_input: Mapping[str, Any]) -> Decision:
    command = tool_input.get("command")
    if not isinstance(command, str) or not command.strip():
        return _veto("missing_command", "Bash needs a non-empty command string")
    if any(ch in SHELL_SYNTAX for ch in command):
        return _veto("shell_syntax", "pipes, redirection, substitution, grouping, chaining and newlines are not allowed")
    try:
        argv = shlex.split(command)
    except ValueError:
        return _veto("unparseable", "command does not parse")
    if not argv:
        return _veto("missing_command", "Bash needs a non-empty command string")

    for arg in argv[1:]:
        if arg.startswith(("~", "/")) or ".." in Path(arg).parts:
            return _veto("bash_path_escape", f"argument {arg!r} is absolute, home-relative or climbs out of the project")
        if arg.startswith(FORBIDDEN_FLAG_PREFIXES):
            return _veto("bash_forbidden_flag", f"flag {arg!r} runs code or writes a file")
        if _names_protected(arg):
            return _veto("bash_protected_path", f"argument {arg!r} names a protected path")

    program = argv[0]
    if program == "git":
        if len(argv) < 2 or argv[1] not in READ_ONLY_GIT:
            return _veto("bash_not_allowlisted", "only git status, log, diff and show are allowed")
        return _allow("bash_read_only_git", "git " + argv[1])
    if program in READ_ONLY_PROGRAMS:
        return _allow("bash_read_only_program", program)
    return _veto("bash_not_allowlisted", f"{program} is not on the read-only allowlist", program)


def decide(tool_name: Any, tool_input: Any, root: str | os.PathLike) -> Decision:
    if not isinstance(tool_name, str) or not isinstance(tool_input, Mapping):
        return _veto("malformed_call", "tool name or input is malformed")
    root_path = Path(root)
    if tool_name == "Bash":
        return _decide_bash(tool_input)
    if tool_name in READ_TOOLS:
        return _decide_path(tool_name, tool_input, root_path, write=False)
    if tool_name in WRITE_TOOLS:
        return _decide_path(tool_name, tool_input, root_path, write=True)
    return _veto("unknown_tool", f"{tool_name} is not on the allowlist")

"""Decide whether one Claude Code tool call may run, for one agent role.

Two checks, in order:

1. Role. The role must be a known role, and it must hold the permission the
   call needs. The roles follow SKILL_SPEC's agent binding:
   Planner, Researcher and Sentinel read; Builder also writes inside the
   project; Verifier also runs the test suite; Planner and Builder may
   delegate; Operator holds nothing, because the human-authorized override
   path is not implemented.

   The session's configured role is a ceiling. A subagent's permissions are
   its own role's permissions intersected with the ceiling, so delegation can
   only narrow what is allowed, never widen it. A delegation call is refused
   outright when the target role holds anything the caller does not.
2. Rule. The target must pass the path rule or the Bash rule below.

Default deny: unknown roles, unknown tools, malformed calls and anything not
explicitly allowed are vetoed.

Path rules (Read, Glob, Grep, Edit, Write, MultiEdit, NotebookEdit): the
target must resolve, after symlinks, inside the project root. Writes must also
avoid the protected prefixes: the gate's own code and state, Claude Code's
settings, and the git directory.

Bash rules: no shell syntax (pipes, redirection, substitution, grouping,
chaining, newlines). Read programs are ls, cat, head, tail, wc, grep, rg, pwd,
and git status, log, diff and show. Test programs are pytest and
python -m pytest. Arguments may not be absolute, home-relative, climb out of
the root, name a protected path, or use flags that run code or write files.

The Bash rules are a text match, not a sandbox. Test programs execute code
from the repository, so for the Verifier role the Bash rules do not limit
what runs. Only operating-system permissions can limit that. The boundary
test in tests/test_claude_code_gate_boundary.py shows the difference.
"""

from __future__ import annotations

import os
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

POLICY_VERSION = "weaver.claude_code_policy.v3"

# Role -> permission categories. Operator is listed with none on purpose.
ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "Planner": frozenset({"read", "bash_read", "delegate"}),
    "Researcher": frozenset({"read", "bash_read"}),
    "Sentinel": frozenset({"read", "bash_read"}),
    "Builder": frozenset({"read", "write", "bash_read", "delegate"}),
    "Verifier": frozenset({"read", "bash_read", "bash_test"}),
    "Operator": frozenset(),
}

READ_TOOLS = frozenset({"Read", "Glob", "Grep"})
# Claude Code's delegation tool ("Agent"; older versions named it "Task").
DELEGATE_TOOLS = frozenset({"Agent", "Task"})
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
# Pytest flags that load plugins or change configuration from outside the call.
FORBIDDEN_TEST_FLAG_PREFIXES = ("-p", "-c", "--rootdir", "--confcutdir", "--override-ini", "--plugin")
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


def role_permits(role: Any, category: str) -> bool:
    return isinstance(role, str) and category in ROLE_PERMISSIONS.get(role, frozenset())


def _known(role: Any) -> bool:
    return isinstance(role, str) and role in ROLE_PERMISSIONS


def effective_permissions(role: Any, ceiling: Any) -> frozenset[str] | None:
    """Permissions of role, capped by the session ceiling. None if either is unknown."""
    if not _known(role) or not _known(ceiling):
        return None
    return ROLE_PERMISSIONS[role] & ROLE_PERMISSIONS[ceiling]


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
    if any(part in PROTECTED_COMPONENTS for part in Path(arg).parts):
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


def _decide_bash(tool_input: Mapping[str, Any]) -> tuple[Decision | None, str | None, str | None]:
    """Return (veto, category, program). With a veto, category and program are None."""
    command = tool_input.get("command")
    if not isinstance(command, str) or not command.strip():
        return _veto("missing_command", "Bash needs a non-empty command string"), None, None
    if any(ch in SHELL_SYNTAX for ch in command):
        return _veto("shell_syntax", "pipes, redirection, substitution, grouping, chaining and newlines are not allowed"), None, None
    try:
        argv = shlex.split(command)
    except ValueError:
        return _veto("unparseable", "command does not parse"), None, None
    if not argv:
        return _veto("missing_command", "Bash needs a non-empty command string"), None, None

    for arg in argv[1:]:
        if arg.startswith(("~", "/")) or ".." in Path(arg).parts:
            return _veto("bash_path_escape", f"argument {arg!r} is absolute, home-relative or climbs out of the project"), None, None
        if arg.startswith(FORBIDDEN_FLAG_PREFIXES):
            return _veto("bash_forbidden_flag", f"flag {arg!r} runs code or writes a file"), None, None
        if _names_protected(arg):
            return _veto("bash_protected_path", f"argument {arg!r} names a protected path"), None, None

    program = argv[0]
    if program == "git":
        if len(argv) >= 2 and argv[1] in READ_ONLY_GIT:
            return None, "bash_read", program
        return _veto("bash_not_allowlisted", "only git status, log, diff and show are allowed"), None, None
    if program in READ_ONLY_PROGRAMS:
        return None, "bash_read", program
    is_pytest = program == "pytest" or (program in {"python", "python3"} and argv[1:3] == ["-m", "pytest"])
    if is_pytest:
        tail = argv[1:] if program == "pytest" else argv[3:]
        if any(arg.startswith(FORBIDDEN_TEST_FLAG_PREFIXES) for arg in tail):
            return _veto("bash_forbidden_flag", "pytest plugin and configuration flags are not allowed"), None, None
        return None, "bash_test", program
    return _veto("bash_not_allowlisted", f"{program} is not on the allowlist", program), None, None


_SAME_AS_ROLE = object()


def decide(tool_name: Any, tool_input: Any, root: str | os.PathLike, role: Any, ceiling: Any = _SAME_AS_ROLE) -> Decision:
    """Decide one call. ceiling defaults to role (a main-thread call with no agent type)."""
    if ceiling is _SAME_AS_ROLE:
        ceiling = role
    if not _known(role):
        return _veto("unknown_role", f"role {role!r} is not a known role; nothing is allowed")
    if not _known(ceiling):
        return _veto("unknown_ceiling", f"session role {ceiling!r} is not set or not known; nothing is allowed")
    perms = effective_permissions(role, ceiling)
    if not isinstance(tool_name, str) or not isinstance(tool_input, Mapping):
        return _veto("malformed_call", "tool name or input is malformed")
    root_path = Path(root)

    def permitted(category: str) -> bool:
        return category in perms

    if tool_name == "Bash":
        veto, category, program = _decide_bash(tool_input)
        if veto is not None:
            return veto
        if not permitted(category):
            return _veto("role_not_permitted", f"role {role} under ceiling {ceiling} may not run {category} commands")
        return _allow(category, program)

    if tool_name in DELEGATE_TOOLS:
        if not permitted("delegate"):
            return _veto("role_not_permitted", f"role {role} under ceiling {ceiling} may not delegate")
        target = tool_input.get("subagent_type")
        if not _known(target):
            return _veto("unknown_subagent_role", f"subagent_type {target!r} is not a known role", str(target))
        if not ROLE_PERMISSIONS[target] <= perms:
            extra = sorted(ROLE_PERMISSIONS[target] - perms)
            return _veto("delegation_escalation", f"subagent role {target} would hold {extra}, which {role} under ceiling {ceiling} does not", target)
        return _allow("delegate_within_ceiling", target)

    if tool_name in READ_TOOLS:
        category = "read"
    elif tool_name in WRITE_TOOLS:
        category = "write"
    else:
        return _veto("unknown_tool", f"{tool_name} is not on the allowlist")

    if not permitted(category):
        return _veto("role_not_permitted", f"role {role} under ceiling {ceiling} may not {category}")
    if category == "read":
        return _decide_path(tool_name, tool_input, root_path, write=False)
    return _decide_path(tool_name, tool_input, root_path, write=True)

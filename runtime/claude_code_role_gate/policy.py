"""Decide whether one Claude Code tool call may run, for one agent role.

GAP-003 remediation candidate (policy v4). The order of checks is the fix:

1. Mandatory checks, independent of role. Unknown role or ceiling, malformed
   calls, unknown tools, path rules (outside the project, protected prefixes,
   symlinks resolving into them), Bash rules, and delegation that would widen
   permissions. A denial here is never overridable.
2. Role. Only after every mandatory check passes is the role's permission for
   the call's category consulted. A denial here is the only overridable denial
   (OQ-1: a closed allowlist containing ``role_not_permitted`` alone).

On the frozen baseline (300bd32) the role check ran first, so a role denial
reached the operator override before any path rule had been evaluated, and
override eligibility was a denylist that let unlisted reasons through.

Roles follow SKILL_SPEC's agent binding: Planner, Researcher and Sentinel read;
Builder also writes inside the project; Verifier also runs the test suite;
Planner and Builder may delegate; Operator holds nothing, because the override
path is signed by a person, not held by a role. The session's configured role
is a ceiling: a subagent's permissions are its own role's permissions
intersected with the ceiling.

Every decision carries the supplied target, the normalized target, its
filesystem identity and a resolution status, including role denials (R9).

The Bash rules are a text match, not a sandbox. Test programs execute code
from the repository, so for the Verifier role the Bash rules do not limit what
runs. Only operating-system permissions can limit that.
"""

from __future__ import annotations

import os
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

POLICY_VERSION = "weaver.claude_code_policy.v4"

# Role -> permission categories. Operator is listed with none on purpose.
ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "Planner": frozenset({"read", "bash_read", "delegate"}),
    "Researcher": frozenset({"read", "bash_read"}),
    "Sentinel": frozenset({"read", "bash_read"}),
    "Builder": frozenset({"read", "write", "bash_read", "delegate"}),
    "Verifier": frozenset({"read", "bash_read", "bash_test"}),
    "Operator": frozenset(),
}

# OQ-1: the only denial an operator override may lift. Everything else,
# including any reason added later, is non-overridable by construction.
ELIGIBLE_RULES = frozenset({"role_not_permitted"})

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
# Enforcement code is protected: this gate, and the separate gate in
# runtime/claude_code_gate (merged in #14), whichever of them is installed.
GATE_CODE_PREFIXES = ("runtime/claude_code_role_gate", "runtime/claude_code_gate")
PROTECTED_PREFIXES = (".claude", ".weaver", ".git", *GATE_CODE_PREFIXES)
PROTECTED_COMPONENTS = frozenset({".claude", ".weaver", ".git"})

READ_ONLY_PROGRAMS = frozenset({"ls", "cat", "head", "tail", "wc", "grep", "rg", "pwd"})
READ_ONLY_GIT = frozenset({"status", "log", "diff", "show"})
# Flags that make a read-only program run code or write a file.
FORBIDDEN_FLAG_PREFIXES = ("--pre", "--exec", "--output", "--ext-diff", "--textconv")
# Pytest flags that load plugins or change configuration from outside the call.
FORBIDDEN_TEST_FLAG_PREFIXES = ("-p", "-c", "--rootdir", "--confcutdir", "--override-ini", "--plugin")
SHELL_SYNTAX = frozenset(";&|<>`$(){}\\\n\r")

# Target resolution status recorded with every decision (R9).
RESOLVED = "resolved"            # path resolved inside the project root
OUTSIDE_ROOT = "outside_root"    # path resolved outside the project root
NOT_PATH = "not_path"            # Bash program or delegation target, not a path
MISSING = "missing"              # path-bearing tool with no usable path
NOT_EVALUATED = "not_evaluated"  # denied before the target was examined


@dataclass(frozen=True)
class Decision:
    allowed: bool
    rule: str
    reason: str
    target: str | None = None            # normalized target, or program / subagent role
    supplied_target: str | None = None   # the target exactly as the call named it
    target_identity: str | None = None   # "dev:ino[/remaining]" of the resolved path
    target_status: str = NOT_EVALUATED

    @property
    def overridable(self) -> bool:
        return (not self.allowed) and self.rule in ELIGIBLE_RULES


@dataclass(frozen=True)
class _Target:
    supplied: str | None
    normalized: str | None
    identity: str | None
    status: str
    inside: bool


def _veto(rule: str, reason: str, t: _Target | None = None) -> Decision:
    if t is None:
        return Decision(False, rule, reason)
    return Decision(False, rule, reason, t.normalized, t.supplied, t.identity, t.status)


def _allow(rule: str, t: _Target) -> Decision:
    return Decision(True, rule, "allowed", t.normalized, t.supplied, t.identity, t.status)


def role_permits(role: Any, category: str) -> bool:
    return isinstance(role, str) and category in ROLE_PERMISSIONS.get(role, frozenset())


def _known(role: Any) -> bool:
    return isinstance(role, str) and role in ROLE_PERMISSIONS


def effective_permissions(role: Any, ceiling: Any) -> frozenset[str] | None:
    """Permissions of role, capped by the session ceiling. None if either is unknown."""
    if not _known(role) or not _known(ceiling):
        return None
    return ROLE_PERMISSIONS[role] & ROLE_PERMISSIONS[ceiling]


def path_identity(real_path: str) -> str:
    """Filesystem identity of a resolved path: its own (dev, ino) if it exists,
    else the nearest existing ancestor's (dev, ino) plus the remaining suffix."""
    current = real_path
    remainder: list[str] = []
    while True:
        try:
            st = os.stat(current)
            suffix = "/".join(reversed(remainder))
            ident = f"{st.st_dev}:{st.st_ino}"
            return f"{ident}/{suffix}" if suffix else ident
        except FileNotFoundError:
            parent, name = os.path.split(current)
            if parent == current:
                raise
            remainder.append(name)
            current = parent


def resolve_path_target(root: Path, raw: str) -> _Target:
    """Resolve raw against root, following symlinks."""
    real_root = os.path.realpath(root)
    candidate = raw if os.path.isabs(raw) else os.path.join(real_root, raw)
    real = os.path.realpath(candidate)
    rel = os.path.relpath(real, real_root)
    identity = path_identity(real)
    if rel == os.pardir or rel.startswith(os.pardir + os.sep) or os.path.isabs(rel):
        return _Target(raw, real, identity, OUTSIDE_ROOT, False)
    return _Target(raw, Path(rel).as_posix(), identity, RESOLVED, True)


def is_protected(rel: str) -> bool:
    return any(rel == prefix or rel.startswith(prefix + "/") for prefix in PROTECTED_PREFIXES)


def _names_protected(arg: str) -> bool:
    if any(part in PROTECTED_COMPONENTS for part in Path(arg).parts):
        return True
    return os.path.normpath(arg).startswith(GATE_CODE_PREFIXES)


def _decide_bash(tool_input: Mapping[str, Any]) -> tuple[Decision | None, str | None, _Target]:
    """Mandatory Bash checks. Return (veto, category, target); with a veto, category is None."""
    command = tool_input.get("command")
    supplied = command if isinstance(command, str) else None
    t = _Target(supplied, None, None, MISSING, False)
    if not isinstance(command, str) or not command.strip():
        return _veto("missing_command", "Bash needs a non-empty command string", t), None, t
    if any(ch in SHELL_SYNTAX for ch in command):
        return _veto("shell_syntax", "pipes, redirection, substitution, grouping, chaining and newlines are not allowed", t), None, t
    try:
        argv = shlex.split(command)
    except ValueError:
        return _veto("unparseable", "command does not parse", t), None, t
    if not argv:
        return _veto("missing_command", "Bash needs a non-empty command string", t), None, t
    t = _Target(supplied, argv[0], None, NOT_PATH, False)

    for arg in argv[1:]:
        if arg.startswith(("~", "/")) or ".." in Path(arg).parts:
            return _veto("bash_path_escape", f"argument {arg!r} is absolute, home-relative or climbs out of the project", t), None, t
        if arg.startswith(FORBIDDEN_FLAG_PREFIXES):
            return _veto("bash_forbidden_flag", f"flag {arg!r} runs code or writes a file", t), None, t
        if _names_protected(arg):
            return _veto("bash_protected_path", f"argument {arg!r} names a protected path", t), None, t

    program = argv[0]
    if program == "git":
        if len(argv) >= 2 and argv[1] in READ_ONLY_GIT:
            return None, "bash_read", t
        return _veto("bash_not_allowlisted", "only git status, log, diff and show are allowed", t), None, t
    if program in READ_ONLY_PROGRAMS:
        return None, "bash_read", t
    is_pytest = program == "pytest" or (program in {"python", "python3"} and argv[1:3] == ["-m", "pytest"])
    if is_pytest:
        tail = argv[1:] if program == "pytest" else argv[3:]
        if any(arg.startswith(FORBIDDEN_TEST_FLAG_PREFIXES) for arg in tail):
            return _veto("bash_forbidden_flag", "pytest plugin and configuration flags are not allowed", t), None, t
        return None, "bash_test", t
    return _veto("bash_not_allowlisted", f"{program} is not on the allowlist", t), None, t


_SAME_AS_ROLE = object()


def decide(tool_name: Any, tool_input: Any, root: str | os.PathLike, role: Any, ceiling: Any = _SAME_AS_ROLE) -> Decision:
    """Decide one call. ceiling defaults to role (a main-thread call with no agent type).

    Mandatory checks run first and are never overridable. The role check runs
    last; its denial (``role_not_permitted``) is the only overridable one.
    """
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

    # Mandatory, role-independent checks.
    if tool_name == "Bash":
        veto, category, t = _decide_bash(tool_input)
        if veto is not None:
            return veto
    elif tool_name in DELEGATE_TOOLS:
        category = "delegate"
        target = tool_input.get("subagent_type")
        t = _Target(target if isinstance(target, str) else None, str(target), None, NOT_PATH, False)
        if not _known(target):
            return _veto("unknown_subagent_role", f"subagent_type {target!r} is not a known role", t)
        if not ROLE_PERMISSIONS[target] <= perms:
            extra = sorted(ROLE_PERMISSIONS[target] - perms)
            return _veto("delegation_escalation", f"subagent role {target} would hold {extra}, which {role} under ceiling {ceiling} does not", t)
    elif tool_name in READ_TOOLS or tool_name in WRITE_TOOLS:
        write = tool_name in WRITE_TOOLS
        category = "write" if write else "read"
        field = PATH_FIELDS[tool_name]
        raw = tool_input.get(field)
        if raw is None and tool_name in OPTIONAL_PATH_TOOLS:
            raw = "."
        if not isinstance(raw, str) or not raw:
            return _veto("missing_path", f"{tool_name} needs a string {field}", _Target(None, None, None, MISSING, False))
        t = resolve_path_target(root_path, raw)
        if not t.inside:
            return _veto("outside_project", f"{raw} is outside the project root", t)
        if write and is_protected(t.normalized):
            return _veto("protected_path", f"{t.normalized} is protected from edits", t)
    else:
        return _veto("unknown_tool", f"{tool_name} is not on the allowlist")

    # Role check, last. The only overridable denial.
    if category not in perms:
        return _veto("role_not_permitted", f"role {role} under ceiling {ceiling} may not {category}", t)
    if tool_name == "Bash":
        return _allow(category, t)
    if tool_name in DELEGATE_TOOLS:
        return _allow("delegate_within_ceiling", t)
    return _allow("write_inside_project" if category == "write" else "read_inside_project", t)

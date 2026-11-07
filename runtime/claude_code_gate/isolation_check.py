"""GAP-003-G1: operating-system isolation check for files the agent must not change.

Runs a set of write attempts as a nonprivileged identity (default: nobody)
against protected gate files, in two layouts built fresh for every attempt:

  protected  the files and their directories are owned by root, and the
             project root is root-owned with the sticky bit set, so the agent
             identity can create its own files but cannot modify, replace,
             rename or delete root's.
  control    the same files owned by the agent identity, with no OS
             protection. This is the negative control: at least one attempt
             must change a file here, which shows the check can see a
             successful write.

No hook is involved. A hook denial does not count as OS-level enforcement, so
every attempt runs as a plain process.

For each attempt the report records the exact argv, the exit code, the end of
stderr, and a fingerprint of every protected path (exists, sha256, mode, uid,
gid) before and after. Result: G1_LOCAL_PASS when no attempt changes anything
in the protected layout and the control detects at least one change. A local
pass says nothing about a deployed environment, which needs its own check.

Needs root (to set ownership and switch identity) and runuser.

Run: python -m runtime.claude_code_gate.isolation_check [--json PATH]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

PROTECTED_FILES = (
    ".claude/settings.json",
    "runtime/claude_code_gate/policy.py",
    ".weaver/gate/chronicle.jsonl",
)
SETTINGS = ".claude/settings.json"
POLICY = "runtime/claude_code_gate/policy.py"
CHRONICLE = ".weaver/gate/chronicle.jsonl"


def attempts(python: str, node: str | None) -> list[tuple[str, list[str]]]:
    """(name, argv) pairs. Every argv runs with the project root as cwd."""
    cases = [
        ("bash_redirect", ["bash", "-c", f"echo pwned > {SETTINGS}"]),
        ("bash_append", ["bash", "-c", f"echo pwned >> {CHRONICLE}"]),
        ("tee", ["bash", "-c", f"echo pwned | tee {SETTINGS}"]),
        ("sed_in_place", ["sed", "-i", "s/^/pwned/", SETTINGS]),
        ("truncate", ["truncate", "-s", "0", CHRONICLE]),
        ("rm", ["rm", "-f", SETTINGS]),
        ("chmod", ["chmod", "666", SETTINGS]),
        ("chown", ["chown", "nobody", SETTINGS]),
        ("rename_parent_dir", ["bash", "-c", f"mv .claude .claude.old && mkdir .claude && echo pwned > {SETTINGS}"]),
        ("python_write", [python, "-c", f"open({POLICY!r}, 'w').write('pwned')"]),
        ("python_atomic_replace", [python, "-c",
            f"import os; open('tmp-x', 'w').write('pwned'); os.replace('tmp-x', {SETTINGS!r})"]),
    ]
    if node:
        # The same filesystem calls Claude Code's Write tool makes (Node fs).
        cases += [
            ("node_write_file", [node, "-e", f"require('fs').writeFileSync({json.dumps(SETTINGS)}, 'pwned')"]),
            ("node_atomic_write", [node, "-e",
                "const fs=require('fs');fs.writeFileSync('tmp-y','pwned');"
                f"fs.renameSync('tmp-y',{json.dumps(SETTINGS)})"]),
        ]
    return cases


def fingerprint(path: Path) -> dict[str, Any]:
    if not path.exists() and not path.is_symlink():
        return {"exists": False}
    st = path.lstat()
    digest = hashlib.sha256(path.read_bytes()).hexdigest() if stat.S_ISREG(st.st_mode) else None
    return {"exists": True, "sha256": digest, "mode": oct(stat.S_IMODE(st.st_mode)), "uid": st.st_uid, "gid": st.st_gid}


def snapshot(root: Path) -> dict[str, Any]:
    return {rel: fingerprint(root / rel) for rel in PROTECTED_FILES}


def build(base: Path, *, protected: bool, agent: pwd.struct_passwd) -> Path:
    root = base / "project"
    for rel in PROTECTED_FILES:
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
    (root / SETTINGS).write_text('{"hooks": {}}\n')
    (root / POLICY).write_text("POLICY = 'original'\n")
    (root / CHRONICLE).write_text('{"index": 0}\n')

    owner = (0, 0) if protected else (agent.pw_uid, agent.pw_gid)
    for dirpath, dirnames, filenames in os.walk(root):
        os.chown(dirpath, *owner)
        os.chmod(dirpath, 0o755)
        for name in filenames:
            os.chown(Path(dirpath) / name, *owner)
            os.chmod(Path(dirpath) / name, 0o644)
    if protected:
        # Agent may create its own files at the root, but the sticky bit stops it
        # renaming or deleting entries it does not own (such as .claude/).
        os.chmod(root, 0o1777)
    return root


def permissions(root: Path) -> dict[str, Any]:
    paths = [Path("."), Path(".claude"), Path("runtime/claude_code_gate"), Path(".weaver/gate"), *map(Path, PROTECTED_FILES)]
    out = {}
    for rel in paths:
        st = (root / rel).lstat()
        out[str(rel)] = {"mode": stat.filemode(st.st_mode), "octal": oct(stat.S_IMODE(st.st_mode)), "uid": st.st_uid, "gid": st.st_gid}
    return out


def run_as(agent: str, argv: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(["runuser", "-u", agent, "--", *argv], cwd=cwd, capture_output=True, text=True, timeout=60)


def identity(agent: str, cwd: Path) -> dict[str, Any]:
    result = run_as(agent, ["id"], cwd)
    entry = pwd.getpwnam(agent)
    return {"user": agent, "uid": entry.pw_uid, "gid": entry.pw_gid, "id_output": result.stdout.strip()}


def run_layout(*, protected: bool, agent: str) -> dict[str, Any]:
    entry = pwd.getpwnam(agent)
    node = shutil.which("node")
    results = []
    layout_permissions = None
    effective_identity = None
    for name, argv in attempts(sys.executable, node):
        base = Path(tempfile.mkdtemp(prefix=f"g1-{'p' if protected else 'c'}-", dir="/tmp"))
        try:
            os.chmod(base, 0o755)
            root = build(base, protected=protected, agent=entry)
            if layout_permissions is None:
                layout_permissions = permissions(root)
                effective_identity = identity(agent, root)
            before = snapshot(root)
            proc = run_as(agent, argv, root)
            after = snapshot(root)
            changed = sorted(rel for rel in PROTECTED_FILES if before[rel] != after[rel])
            results.append({
                "name": name,
                "argv": argv,
                "exit_code": proc.returncode,
                "stderr_tail": proc.stderr.strip()[-300:],
                "before": before,
                "after": after,
                "changed": changed,
            })
        finally:
            shutil.rmtree(base, ignore_errors=True)
    return {
        "layout": "protected" if protected else "control",
        "effective_identity": effective_identity,
        "permissions": layout_permissions,
        "attempts": results,
        "attempts_that_changed_a_protected_file": [r["name"] for r in results if r["changed"]],
    }


def sticky_bit_check(agent: str) -> dict[str, Any]:
    """Same root-owned files, but the project root is world-writable without the
    sticky bit. If the rename attack then succeeds, root-owned files alone are not
    enough: the directories above them must not be agent-writable, or must be sticky."""
    entry = pwd.getpwnam(agent)
    argv = dict(attempts(sys.executable, None))["rename_parent_dir"]
    base = Path(tempfile.mkdtemp(prefix="g1-s-", dir="/tmp"))
    try:
        os.chmod(base, 0o755)
        root = build(base, protected=True, agent=entry)
        os.chmod(root, 0o777)
        before = snapshot(root)
        proc = run_as(agent, argv, root)
        after = snapshot(root)
        changed = sorted(rel for rel in PROTECTED_FILES if before[rel] != after[rel])
        return {
            "layout": "root-owned files, project root 0777 without sticky bit",
            "argv": argv,
            "exit_code": proc.returncode,
            "changed": changed,
            "sticky_bit_required": bool(changed),
        }
    finally:
        shutil.rmtree(base, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="GAP-003-G1 OS-level isolation check")
    parser.add_argument("--agent", default="nobody", help="nonprivileged identity to run attempts as")
    parser.add_argument("--json", type=Path, default=None, help="write the full report here")
    args = parser.parse_args(argv)

    if os.geteuid() != 0 or shutil.which("runuser") is None:
        print(json.dumps({"status": "G1_NOT_RUN", "reason": "needs root and runuser to set ownership and switch identity"}))
        return 2
    if pwd.getpwnam(args.agent).pw_uid == 0:
        print(json.dumps({"status": "G1_NOT_RUN", "reason": "agent identity must not be root"}))
        return 2

    protected = run_layout(protected=True, agent=args.agent)
    control = run_layout(protected=False, agent=args.agent)
    protected_ok = not protected["attempts_that_changed_a_protected_file"]
    control_detects = bool(control["attempts_that_changed_a_protected_file"])
    status = "G1_LOCAL_PASS" if protected_ok and control_detects else "G1_LOCAL_FAIL"

    report = {
        "schema": "weaver.gap003.g1.isolation_report.v1",
        "status": status,
        "scope": "local container only; not a verification of any deployed environment",
        "hook_involved": False,
        "agent_identity": args.agent,
        "harness_euid": os.geteuid(),
        "host": {"platform": platform.platform(), "python": sys.version.split()[0], "node": shutil.which("node")},
        "protected_layout_held": protected_ok,
        "negative_control_detected_writes": control_detects,
        "layouts": [protected, control],
        "sticky_bit_check": sticky_bit_check(args.agent),
    }
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    summary = {
        "status": status,
        "protected_changed": protected["attempts_that_changed_a_protected_file"],
        "control_changed": control["attempts_that_changed_a_protected_file"],
        "attempts": len(protected["attempts"]),
        "sticky_bit_required": report["sticky_bit_check"]["sticky_bit_required"],
    }
    print(json.dumps(summary, indent=2))
    return 0 if status == "G1_LOCAL_PASS" else 1


if __name__ == "__main__":
    sys.exit(main())

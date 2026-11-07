"""Show the three layers of the gate boundary and print them as JSON.

1. hook_level: the policy denies an Edit of a protected settings file.
2. outside_hook: a process the hook never sees writes the same file.
3. os_permissions: an unprivileged user cannot write a root-owned file, or
   the check is reported as skipped when this process is not root.

Run: python -m runtime.claude_code_gate.boundary_demo
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from runtime.claude_code_gate.policy import decide

PROTECTED_REL = Path(".claude") / "settings.json"


def hook_level(root: Path) -> dict:
    decision = decide("Edit", {"file_path": str(PROTECTED_REL)}, root, "Builder")
    return {"denied": not decision.allowed, "rule": decision.rule, "reason": decision.reason}


def outside_hook(root: Path) -> dict:
    target = root / PROTECTED_REL
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("{}\n")
    subprocess.run([sys.executable, "-c", f"open({str(target)!r}, 'w').write('changed')"], check=True)
    return {"written": target.read_text() == "changed"}


def os_permissions() -> dict:
    if os.geteuid() != 0 or shutil.which("runuser") is None:
        return {"status": "skipped", "reason": "needs root and runuser"}
    base = Path(tempfile.mkdtemp(prefix="gate-boundary-", dir="/tmp"))
    try:
        os.chmod(base, 0o755)
        target = base / PROTECTED_REL
        target.parent.mkdir(parents=True)
        target.write_text("{}\n")
        os.chmod(target.parent, 0o755)
        os.chmod(target, 0o644)
        os.chown(target, 0, 0)
        result = subprocess.run(
            ["runuser", "-u", "nobody", "--", sys.executable, "-c",
             f"open({str(target)!r}, 'w').write('changed')"],
            capture_output=True, text=True,
        )
        blocked = result.returncode != 0 and target.read_text() == "{}\n"
        return {"status": "blocked" if blocked else "not_blocked", "detail": result.stderr.strip()[-200:]}
    finally:
        shutil.rmtree(base, ignore_errors=True)


def main() -> int:
    root = Path(tempfile.mkdtemp(prefix="gate-demo-"))
    try:
        report = {
            "hook_level": hook_level(root),
            "outside_hook": outside_hook(root),
            "os_permissions": os_permissions(),
        }
    finally:
        shutil.rmtree(root, ignore_errors=True)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""GAP-003 R3: the trusted project root comes from a protected anchor file.

The baseline took the root from CLAUDE_PROJECT_DIR, else the event's cwd, else
os.getcwd(). The event's cwd is supplied by the caller, so the caller could
choose the root the path rules were evaluated against.

Here the root is established only from the anchor:

    {
      "schema": "weaver.gate.anchor.v1",
      "root": "/abs/path/to/project",
      "root_dev": <st_dev>, "root_ino": <st_ino>,
      "registry_path": "/abs/path/to/key_registry.json",   (optional)
      "registry_sha256": "<hex>"                           (optional; required with registry_path)
    }

* T-1: CLAUDE_PROJECT_DIR, cwd and os.getcwd() are never trust sources.
* T-2: if CLAUDE_PROJECT_DIR is set and resolves elsewhere, deny
  ``trusted_root_mismatch``. A root whose (st_dev, st_ino) no longer matches
  the anchor is also a mismatch.
* T-3: an absent, unreadable, malformed or untrusted anchor denies
  ``trusted_root_missing``.

Anchor location: /etc/weaver-gate/anchor.json, or WEAVER_GATE_ANCHOR. Either
way the anchor file and its directory must be owned by root and not writable
by group or others. An agent that runs as a non-root identity cannot create
such a file, so pointing WEAVER_GATE_ANCHOR at an agent-written anchor fails.
Residual: a lower-trust setting can still point WEAVER_GATE_ANCHOR at another
root-owned anchor. Whether managed settings win over lower-trust values is the
L-1 question and is not verified here.
"""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

ANCHOR_SCHEMA = "weaver.gate.anchor.v1"
DEFAULT_ANCHOR_PATH = Path("/etc/weaver-gate/anchor.json")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class TrustError(Exception):
    def __init__(self, rule: str, detail: str):
        super().__init__(f"{rule}: {detail}")
        self.rule = rule
        self.detail = detail


@dataclass(frozen=True)
class Anchor:
    path: Path
    root: Path
    root_dev: int
    root_ino: int
    registry_path: Path | None
    registry_sha256: str | None


def anchor_location(env: Mapping[str, str]) -> Path:
    raw = env.get("WEAVER_GATE_ANCHOR")
    return Path(raw) if raw else DEFAULT_ANCHOR_PATH


def _check_custody(path: Path) -> None:
    for p in (path, path.parent):
        st = os.lstat(p)
        if stat.S_ISLNK(st.st_mode):
            raise TrustError("trusted_root_missing", f"{p} is a symlink")
        if st.st_uid != 0:
            raise TrustError("trusted_root_missing", f"{p} is not owned by root")
        if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise TrustError("trusted_root_missing", f"{p} is writable by group or others")


def load_anchor(path: Path) -> Anchor:
    try:
        _check_custody(path)
        doc = json.loads(path.read_text(encoding="utf-8"))
    except TrustError:
        raise
    except FileNotFoundError:
        raise TrustError("trusted_root_missing", f"no anchor at {path}") from None
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        raise TrustError("trusted_root_missing", f"anchor unreadable ({type(exc).__name__})") from None
    if not isinstance(doc, dict) or doc.get("schema") != ANCHOR_SCHEMA:
        raise TrustError("trusted_root_missing", "anchor schema not recognized")
    root, dev, ino = doc.get("root"), doc.get("root_dev"), doc.get("root_ino")
    if not isinstance(root, str) or not os.path.isabs(root) or not isinstance(dev, int) or not isinstance(ino, int):
        raise TrustError("trusted_root_missing", "anchor root fields malformed")
    reg_path, reg_sha = doc.get("registry_path"), doc.get("registry_sha256")
    if reg_path is not None or reg_sha is not None:
        if not isinstance(reg_path, str) or not os.path.isabs(reg_path) or not isinstance(reg_sha, str) or not _HEX64.match(reg_sha):
            raise TrustError("trusted_root_missing", "anchor registry fields malformed")
    return Anchor(path, Path(root), dev, ino, Path(reg_path) if reg_path else None, reg_sha)


def establish_root(anchor: Anchor, env: Mapping[str, str]) -> Path:
    """Return the trusted root, or raise TrustError."""
    try:
        st = os.stat(anchor.root)
    except OSError:
        raise TrustError("trusted_root_missing", f"anchored root {anchor.root} is not reachable") from None
    if (st.st_dev, st.st_ino) != (anchor.root_dev, anchor.root_ino):
        raise TrustError("trusted_root_mismatch", "anchored root identity changed")
    claimed = env.get("CLAUDE_PROJECT_DIR")
    if claimed and os.path.realpath(claimed) != os.path.realpath(anchor.root):
        raise TrustError("trusted_root_mismatch", "CLAUDE_PROJECT_DIR differs from the anchored root")
    return anchor.root


def write_anchor(path: Path, root: Path, *, registry_path: Path | None = None, registry_sha256: str | None = None) -> dict:
    """Administrator/test helper: write an anchor for root. Not called by the hook."""
    st = os.stat(root)
    doc = {"schema": ANCHOR_SCHEMA, "root": str(root), "root_dev": st.st_dev, "root_ino": st.st_ino}
    if registry_path is not None:
        doc["registry_path"] = str(registry_path)
        doc["registry_sha256"] = registry_sha256
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    os.chmod(path, 0o644)
    return doc

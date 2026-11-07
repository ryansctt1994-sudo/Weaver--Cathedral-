"""Forge/Loom boundary enforcement (closes the executable half of GAP-008).

zorel-kernel names `test_no_liturgical_artifacts.py` as the enforcement point
for its Forge/Loom firewall, but the file was never written. This is that
test, for this repository.

The boundary:
  * Authority zones (core/, forge/, runtime/, agents/, skills/) hold code and
    evidence. They may carry operational authority once verified.
  * loom/ holds symbolic, narrative, prompt and orientation material. It
    carries no computational authority.

Rules checked:
  1. Every zone directory that exists declares its authority level in a
     STATUS.md, and the level is one that zone is allowed to hold.
  2. Code in an authority zone never imports from, or references a path in,
     loom/.
  3. loom/ contains no executable code.
  4. Code (.py / .sh) in an authority zone contains no liturgical markers:
     mythopoeic vocabulary belongs in loom/ or in docs, not in source.

The checker is tested against synthetic repos first, so the rules are shown
to fire. loom/ doesn't exist yet, so the real-repo check alone would prove
nothing.
"""

from __future__ import annotations

import ast
import os
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

AUTHORITY_ZONES = ("core", "forge", "runtime", "agents", "skills")
LOOM_ZONE = "loom"

# Authority levels from zorel-kernel KEEP_LIST.md section 6.
ALLOWED_LEVELS: dict[str, set[str]] = {
    **{zone: {"CANDIDATE_SPINE", "RECEIPT_EVIDENCE", "GOVERNANCE_CONTROL", "PHYSICAL_CONSTRAINT"} for zone in AUTHORITY_ZONES},
    "governance": {"GOVERNANCE_CONTROL"},
    LOOM_ZONE: {"ORIENTATION_ONLY", "CONTEXTUAL", "JUSTIFICATION_ONLY"},
}

EXECUTABLE_SUFFIXES = {".py", ".sh", ".bash", ".js", ".mjs", ".cjs", ".ts", ".ps1", ".bat", ".exe", ".so", ".dll"}
CODE_SUFFIXES = {".py", ".sh", ".bash"}

# Lower-case substrings. A deliberately small starting set, drawn from
# vocabulary the portfolio itself uses for Loom material. Extend it here.
LITURGICAL_MARKERS = ("liturg", "mythopoe", "(•ㅅ•)", "rabbit")

LEVEL_RE = re.compile(r"^\*\*Authority Level:\*\*\s*`?([A-Z_]+)`?", re.MULTILINE)
SKIP_DIRS = {"__pycache__", ".git", ".pytest_cache"}


def _files(base: Path):
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.endswith(".egg-info")]
        for name in filenames:
            yield Path(dirpath) / name


def check_status_declarations(root: Path) -> list[str]:
    problems = []
    for zone, allowed in ALLOWED_LEVELS.items():
        zone_dir = root / zone
        if not zone_dir.is_dir():
            continue
        status = zone_dir / "STATUS.md"
        if not status.is_file():
            problems.append(f"{zone}/: missing STATUS.md authority declaration")
            continue
        match = LEVEL_RE.search(status.read_text(encoding="utf-8"))
        if not match:
            problems.append(f"{zone}/STATUS.md: no '**Authority Level:**' line")
        elif match.group(1) not in allowed:
            problems.append(f"{zone}/STATUS.md: level {match.group(1)} not allowed here (allowed: {sorted(allowed)})")
    return problems


def _loom_references(path: Path, rel: str) -> list[str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except SyntaxError as exc:
        return [f"{rel}: cannot parse ({exc.msg}); boundary cannot be checked"]
    problems = []
    for node in ast.walk(tree):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            names = [node.module]
        for name in names:
            if name == LOOM_ZONE or name.startswith(LOOM_ZONE + "."):
                problems.append(f"{rel}:{node.lineno}: imports {name} from the Loom")
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if re.search(r"(^|[\\/])loom[\\/]", node.value):
                problems.append(f"{rel}:{node.lineno}: references Loom path {node.value!r}")
    return problems


def check_authority_code(root: Path) -> list[str]:
    problems = []
    for zone in AUTHORITY_ZONES:
        zone_dir = root / zone
        if not zone_dir.is_dir():
            continue
        for path in _files(zone_dir):
            if path.suffix not in CODE_SUFFIXES:
                continue
            rel = path.relative_to(root).as_posix()
            if path.suffix == ".py":
                problems.extend(_loom_references(path, rel))
            text = path.read_text(encoding="utf-8").lower()
            for marker in LITURGICAL_MARKERS:
                if marker in text:
                    problems.append(f"{rel}: liturgical marker {marker!r} in authority-zone code")
    return problems


def check_loom_is_not_executable(root: Path) -> list[str]:
    loom = root / LOOM_ZONE
    if not loom.is_dir():
        return []
    problems = []
    for path in _files(loom):
        rel = path.relative_to(root).as_posix()
        if path.suffix.lower() in EXECUTABLE_SUFFIXES:
            problems.append(f"{rel}: executable file type in the Loom")
        elif os.access(path, os.X_OK):
            problems.append(f"{rel}: executable bit set in the Loom")
    return problems


def check_boundary(root: Path) -> list[str]:
    return check_status_declarations(root) + check_authority_code(root) + check_loom_is_not_executable(root)


# --- The real repository ----------------------------------------------------


def test_repository_respects_forge_loom_boundary():
    problems = check_boundary(REPO_ROOT)
    assert not problems, "Forge/Loom boundary violations:\n" + "\n".join(problems)


# --- The checker itself, against synthetic repos ----------------------------


def _status(level: str) -> str:
    return f"# STATUS\n\n**Authority Level:** `{level}`\n"


@pytest.fixture
def clean_repo(tmp_path: Path) -> Path:
    (tmp_path / "core").mkdir()
    (tmp_path / "core" / "STATUS.md").write_text(_status("CANDIDATE_SPINE"))
    (tmp_path / "core" / "ok.py").write_text("import json\nVALUE = 'forge/demos'\n")
    (tmp_path / "loom").mkdir()
    (tmp_path / "loom" / "STATUS.md").write_text(_status("ORIENTATION_ONLY"))
    (tmp_path / "loom" / "doctrine.md").write_text("The Rabbit witnesses. (•ㅅ•)\n")
    return tmp_path


def test_clean_repo_passes(clean_repo):
    assert check_boundary(clean_repo) == []


def test_missing_status_is_flagged(clean_repo):
    (clean_repo / "core" / "STATUS.md").unlink()
    assert any("missing STATUS.md" in p for p in check_boundary(clean_repo))


def test_status_without_level_line_is_flagged(clean_repo):
    (clean_repo / "core" / "STATUS.md").write_text("# STATUS\n\nNo level here.\n")
    assert any("no '**Authority Level:**' line" in p for p in check_boundary(clean_repo))


@pytest.mark.parametrize(
    ("zone", "level"),
    [("core", "ORIENTATION_ONLY"), ("loom", "CANDIDATE_SPINE"), ("loom", "RECEIPT_EVIDENCE")],
)
def test_level_not_allowed_in_zone_is_flagged(clean_repo, zone, level):
    (clean_repo / zone / "STATUS.md").write_text(_status(level))
    assert any(f"level {level} not allowed" in p for p in check_boundary(clean_repo))


@pytest.mark.parametrize(
    "source",
    [
        "import loom\n",
        "import loom.doctrine as d\n",
        "from loom import prompts\n",
        "from loom.prompts.x import y\n",
        "def f():\n    import loom\n",
        "PATH = 'loom/prompts/system.md'\n",
        "PATH = '../loom/doctrine.md'\n",
    ],
)
def test_authority_code_reaching_into_loom_is_flagged(clean_repo, source):
    (clean_repo / "core" / "bad.py").write_text(source)
    assert any("core/bad.py" in p and "Loom" in p for p in check_boundary(clean_repo))


def test_lookalike_names_are_not_flagged(clean_repo):
    (clean_repo / "core" / "fine.py").write_text("import loomis\nfrom bloom import x\nS = 'heirloom/'\n")
    assert check_boundary(clean_repo) == []


def test_unparseable_authority_code_is_flagged(clean_repo):
    (clean_repo / "core" / "broken.py").write_text("def (:\n")
    assert any("cannot parse" in p for p in check_boundary(clean_repo))


@pytest.mark.parametrize("marker_text", ["# liturgical seal", "MOTIF = '(•ㅅ•)'", "# Mythopoeic layer", "echo 'The Rabbit'"])
def test_liturgical_marker_in_authority_code_is_flagged(clean_repo, marker_text):
    name = "seal.sh" if marker_text.startswith("echo") else "seal.py"
    (clean_repo / "core" / name).write_text(marker_text + "\n")
    assert any("liturgical marker" in p for p in check_boundary(clean_repo))


def test_markers_in_authority_zone_docs_and_data_are_allowed(clean_repo):
    (clean_repo / "core" / "README.md").write_text("Doctrine lives in the Loom; the Rabbit is a witness motif.\n")
    (clean_repo / "core" / "fixture.json").write_text('{"seal": "(•ㅅ•)"}\n')
    assert check_boundary(clean_repo) == []


@pytest.mark.parametrize("name", ["ritual.py", "invoke.sh", "prompt.js"])
def test_executable_file_in_loom_is_flagged(clean_repo, name):
    (clean_repo / "loom" / name).write_text("x\n")
    assert any("executable file type in the Loom" in p for p in check_boundary(clean_repo))


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_executable_bit_in_loom_is_flagged(clean_repo):
    path = clean_repo / "loom" / "chant"
    path.write_text("x\n")
    path.chmod(0o755)
    assert any("executable bit" in p for p in check_boundary(clean_repo))

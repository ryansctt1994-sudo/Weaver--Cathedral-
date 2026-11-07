"""Every skill package must meet skills/SKILL_SPEC.md before it can be used.

The pattern is borrowed from hermes-agent-self-evolution's ConstraintValidator:
a candidate is admitted only if it passes every check, and any failure means
rejection. Here the candidate is a skill package, and the checks are the spec's
required structure, manifest fields, SKILL.md sections and schemas.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

SKILLS = Path(__file__).resolve().parent.parent / "skills"
REQUIRED_FILES = ["SKILL.md", "manifest.json", "inputs.schema.json", "outputs.schema.json", "risk.md", "receipts.md"]
REQUIRED_DIRS = {"examples": "example_001.md", "tests": "test_skill_contract.py"}
REQUIRED_SECTIONS = [
    "Purpose", "When To Use", "When Not To Use", "Inputs", "Outputs", "Procedure",
    "Failure Modes", "Evidence Requirements", "Safety / Security Notes", "Example Invocation",
]
MANIFEST_FIELDS = {
    "id": str, "name": str, "version": str, "domain": str, "evidence_level": str, "allowed_agents": list,
    "requires_human_approval": bool, "network_access": str, "writes_files": bool, "executes_code": bool,
    "risk_level": str, "source_lineage": list,
}
AGENTS = {"Planner", "Builder", "Verifier", "Archivist", "Sentinel", "Researcher", "Operator"}
RISK_LEVELS = {"low", "medium", "high", "critical"}
# SKILL_SPEC "Skill Evidence Promotion" stops at E4 for skills.
SKILL_LEVELS = {"E0", "E1", "E2", "E3", "E4"}
MAX_SKILL_MD_BYTES = 15_000  # same ceiling Hermes uses for evolved SKILL.md files


def skill_dirs() -> list[Path]:
    return sorted(p.parent for p in SKILLS.glob("*/*/manifest.json"))


def check_package(skill: Path) -> list[str]:
    problems: list[str] = []
    rel = f"{skill.parent.name}/{skill.name}"
    for name in REQUIRED_FILES:
        if not (skill / name).is_file():
            problems.append(f"{rel}: missing {name}")
    for d, f in REQUIRED_DIRS.items():
        if not (skill / d / f).is_file():
            problems.append(f"{rel}: missing {d}/{f}")
    if problems:
        return problems

    manifest = json.loads((skill / "manifest.json").read_text())
    for field, kind in MANIFEST_FIELDS.items():
        if not isinstance(manifest.get(field), kind):
            problems.append(f"{rel}/manifest.json: {field} must be {kind.__name__}")
    domain, name = skill.parent.name, skill.name
    if manifest.get("id") != f"{domain}.{name}":
        problems.append(f"{rel}/manifest.json: id must be {domain}.{name} to match its directory")
    if manifest.get("domain") != domain:
        problems.append(f"{rel}/manifest.json: domain must be {domain}")
    if manifest.get("evidence_level") not in SKILL_LEVELS:
        problems.append(f"{rel}/manifest.json: evidence_level must be one of {sorted(SKILL_LEVELS)}")
    if manifest.get("risk_level") not in RISK_LEVELS:
        problems.append(f"{rel}/manifest.json: risk_level must be one of {sorted(RISK_LEVELS)}")
    if not set(manifest.get("allowed_agents", [])) <= AGENTS:
        problems.append(f"{rel}/manifest.json: unknown agents {sorted(set(manifest['allowed_agents']) - AGENTS)}")
    if manifest.get("risk_level") in {"high", "critical"} and not manifest.get("requires_human_approval"):
        problems.append(f"{rel}/manifest.json: {manifest['risk_level']} risk requires human approval (SKILL_SPEC risk table)")

    text = (skill / "SKILL.md").read_text(encoding="utf-8")
    if len(text.encode()) > MAX_SKILL_MD_BYTES:
        problems.append(f"{rel}/SKILL.md: over {MAX_SKILL_MD_BYTES} bytes")
    if not text.lstrip().startswith("# "):
        problems.append(f"{rel}/SKILL.md: must start with a '# Skill Name' heading")
    headings = {line[3:].strip() for line in text.splitlines() if line.startswith("## ")}
    for section in REQUIRED_SECTIONS:
        if section not in headings:
            problems.append(f"{rel}/SKILL.md: missing section '## {section}'")

    for schema_name in ("inputs.schema.json", "outputs.schema.json"):
        try:
            Draft202012Validator.check_schema(json.loads((skill / schema_name).read_text()))
        except Exception as exc:  # noqa: BLE001
            problems.append(f"{rel}/{schema_name}: not a valid draft 2020-12 schema ({exc.__class__.__name__})")
    return problems


def test_there_is_at_least_one_skill():
    assert skill_dirs(), "GAP-004: no concrete skills"


@pytest.mark.parametrize("skill", skill_dirs(), ids=lambda p: p.parent.name + "." + p.name)
def test_skill_package_meets_spec(skill):
    problems = check_package(skill)
    assert not problems, "\n".join(problems)


def test_checker_rejects_an_incomplete_package(tmp_path):
    bad = tmp_path / "governance" / "half_done"
    bad.mkdir(parents=True)
    (bad / "manifest.json").write_text("{}")
    problems = check_package(bad)
    assert any("missing SKILL.md" in p for p in problems)


def test_checker_rejects_bad_manifest_and_sections(tmp_path):
    import shutil

    src = SKILLS / "governance" / "claim_audit"
    pkg = tmp_path / "governance" / "claim_audit"
    shutil.copytree(src, pkg)
    manifest = json.loads((pkg / "manifest.json").read_text())
    manifest.update(id="governance.other", risk_level="high", requires_human_approval=False, allowed_agents=["Wizard"])
    (pkg / "manifest.json").write_text(json.dumps(manifest))
    (pkg / "SKILL.md").write_text((pkg / "SKILL.md").read_text().replace("## Failure Modes", "## Failures"))
    problems = "\n".join(check_package(pkg))
    for expected in ["id must be governance.claim_audit", "requires human approval", "unknown agents", "missing section '## Failure Modes'"]:
        assert expected in problems, expected

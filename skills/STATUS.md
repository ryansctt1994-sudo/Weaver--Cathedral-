# STATUS — skills/

**Folder:** `skills/`
**Purpose:** Governed skill packages for agents.
**Authority Level:** `CANDIDATE_SPINE`
**Evidence:** One concrete skill, `governance/claim_audit` (declared E1; contract tests run in CI). `tests/test_skill_packages.py` checks every package against `SKILL_SPEC.md` (GAP-004).

**Allowed contents:** Skill packages in the structure `SKILL_SPEC.md` defines: instructions, manifest, input/output schemas, examples, tests, risk and receipt notes.

**Forbidden contents:** Imports from or path references into `loom/`. Skill code with no tests. Prompt-only "authority" with no schema or receipt.

**Promotion rule:** A skill is trusted only after its declared tests pass and a receipt records the result.

**Audit owner:** Repository owner (`ryansctt1994-sudo`)
**Last reviewed:** 2026-11-07
**Enforced by:** `tests/test_no_liturgical_artifacts.py`

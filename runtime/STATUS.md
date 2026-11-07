# STATUS — runtime/

**Folder:** `runtime/`
**Purpose:** Execution-time controls. Currently one component: the Claude Code gate, which decides whether each agent tool call may run.
**Authority Level:** `CANDIDATE_SPINE`
**Evidence:** The policy and hook have unit and subprocess tests in `tests/test_claude_code_gate.py`, run in CI. Nothing here has been checked against an independent reproduction (GAP-006).

**Allowed contents:** Python and shell for execution-time controls, with tests. Gate documentation.

**Forbidden contents:** Imports from or path references into `loom/`. Symbolic or narrative material. Policy rules that allow an action without a test that exercises that allow.

**Promotion rule:** A rule is trusted only with tests that cover both the allowed and the denied side, and a chronicled decision trail (GAP-003).

**Audit owner:** Repository owner (`ryansctt1994-sudo`)
**Last reviewed:** 2026-11-07
**Enforced by:** `tests/test_no_liturgical_artifacts.py`

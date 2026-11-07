# STATUS — runtime/

**Folder:** `runtime/`
**Purpose:** Execution-time controls. One component: the role-bound Claude Code gate, which decides whether each agent tool call may run (GAP-003, candidate).
**Authority Level:** `CANDIDATE_SPINE`
**Evidence:** Unit and subprocess tests in `tests/test_claude_code_gate.py` and `tests/test_claude_code_gate_boundary.py`. The hook was run end to end against Claude Code 2.1.319 in one environment. Nothing here has been independently reproduced (GAP-006), and the candidate is not merged.

**Allowed contents:** Python and shell for execution-time controls, with tests. Gate documentation.

**Forbidden contents:** Imports from or path references into `loom/`. Symbolic or narrative material. Policy rules that allow an action without a test that exercises that allow.

**Promotion rule:** GAP-003 stays OPEN until independent validation. Each role permission needs tests for both the allowed and the denied side, and the hook's behaviour must be checked against the installed Claude Code version. Operating-system permissions, not the hook, are the protection for files the agent must not write.

**Audit owner:** Repository owner (`ryansctt1994-sudo`)
**Last reviewed:** 2026-11-07
**Enforced by:** `tests/test_no_liturgical_artifacts.py`

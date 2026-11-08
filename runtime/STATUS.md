# STATUS — runtime/

**Folder:** `runtime/`
**Purpose:** Adapters that connect agent harnesses to the authority spine. Two Claude Code `PreToolUse` gates are kept side by side for comparison (GAP-003); neither is activated automatically. `claude_code_gate` sends every tool call through `core.authority.UncertaintyGate` with an ordered rule policy and chronicles each decision. `claude_code_role_gate` is the role-bound candidate from the GAP-003 R1–R7 remediation (draft PR #15, not merged): default deny, per-role permissions, mandatory checks before the role, and signed operator overrides limited to role denials.
**Authority Level:** `CANDIDATE_SPINE`
**Evidence:** Local tests and CI. `claude_code_gate` is driven with PreToolUse payloads in tests; no run inside a live Claude Code session is recorded here. `claude_code_role_gate` has implementer tests, a regression check of the baseline bypasses and a mutation report in `forge/demos/gap003_r1r7_candidate/`; its earlier baseline was run against Claude Code 2.1.319 in one environment. Nothing here has been independently reproduced (GAP-006). E3 is not claimed.

**Allowed contents:** Python and shell source for execution-time controls, example configs, tests, gate documentation.

**Forbidden contents:** Imports from or path references into `loom/`. Liturgical or mythopoeic vocabulary in source code. Real keys or secrets: example configs ship with overrides off. Policy rules that allow an action without a test that exercises that allow.

**Promotion rule:** Moving up the evidence ladder requires the evidence listed in `core/authority/verifier.py` `PROMOTION_REQUIREMENTS`, recorded in `governance/open_gap_ledger.md`. Operating-system permissions, not a hook, are the protection for files the agent must not write.

**Audit owner:** Repository owner (`ryansctt1994-sudo`)
**Last reviewed:** 2026-11-08
**Enforced by:** `tests/test_no_liturgical_artifacts.py`

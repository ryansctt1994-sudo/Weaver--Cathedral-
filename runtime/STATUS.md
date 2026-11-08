# STATUS — runtime/

**Folder:** `runtime/`
**Purpose:** Adapters that connect agent harnesses to the authority spine. The first is `claude_code_gate`, a Claude Code `PreToolUse` hook that sends every tool call through `core.authority.UncertaintyGate` and chronicles each decision (GAP-003).
**Authority Level:** `CANDIDATE_SPINE`
**Evidence:** Local tests and CI. The hook is driven with PreToolUse payloads in tests; no run inside a live Claude Code session is recorded here. E3 is not claimed.

**Allowed contents:** Python source, example configs, tests.

**Forbidden contents:** Imports from or path references into `loom/`. Liturgical or mythopoeic vocabulary in source code. Real keys or secrets: example configs ship with overrides off.

**Promotion rule:** Moving up the evidence ladder requires the evidence listed in `core/authority/verifier.py` `PROMOTION_REQUIREMENTS`, recorded in `governance/open_gap_ledger.md`.

**Audit owner:** Repository owner (`ryansctt1994-sudo`)
**Last reviewed:** 2026-11-08
**Enforced by:** `tests/test_no_liturgical_artifacts.py`

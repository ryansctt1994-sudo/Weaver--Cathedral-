# STATUS — core/

**Folder:** `core/`
**Purpose:** Executable verification spine: authority envelopes, receipts, replay checks, promotion evaluation.
**Authority Level:** `CANDIDATE_SPINE`
**Evidence:** Phase 1 authority kernel is an E2 candidate (CI green). E3 is not claimed.

**Allowed contents:** Python source, JSON schemas, synthetic fixtures, tests. Test fixtures copied from other repos go under `authority/fixtures/external/` with a provenance note.

**Forbidden contents:** Imports from or path references into `loom/`. Liturgical or mythopoeic vocabulary in source code. Real personal data or secrets in fixtures.

**Promotion rule:** Moving up the evidence ladder requires the evidence listed in `core/authority/verifier.py` `PROMOTION_REQUIREMENTS`, recorded in `governance/open_gap_ledger.md`.

**Audit owner:** Repository owner (`ryansctt1994-sudo`)
**Last reviewed:** 2026-11-07
**Enforced by:** `tests/test_no_liturgical_artifacts.py`

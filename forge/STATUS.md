# STATUS — forge/

**Folder:** `forge/`
**Purpose:** Demonstration-as-evidence packages, and later receipts, benchmarks and failure exports.
**Authority Level:** `CANDIDATE_SPINE`
**Evidence:** `demos/authority_spine_001` is an E1 scaffold. Its scripts run in CI, but no E3 receipt bundle exists yet (GAP-005).

**Allowed contents:** Demo specs, run/verify scripts, synthetic inputs, generated logs and receipts once they are packaged as a bundle.

**Forbidden contents:** Imports from or path references into `loom/`. Liturgical or mythopoeic vocabulary in scripts. Network-dependent or secret-bearing demos.

**Promotion rule:** A demo moves past E2 only with the full E3 bundle: receipts, logs, deterministic fixture, failure path, replay instructions, artifact hashes.

**Audit owner:** Repository owner (`ryansctt1994-sudo`)
**Last reviewed:** 2026-11-07
**Enforced by:** `tests/test_no_liturgical_artifacts.py`

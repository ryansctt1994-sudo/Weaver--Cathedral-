# Open Gap Ledger

**Document:** Weaver Cathedral Master Build Open Gap Ledger  
**Status:** v0.1.2 Phase 1 post-merge update  
**Purpose:** Track what is not yet proven, built, reproduced, or authorized.

---

## Gap Severity

| Severity | Meaning |
|---|---|
| G0 | Cosmetic/editorial |
| G1 | Documentation incomplete |
| G2 | Implementation missing |
| G3 | Verification missing |
| G4 | Safety/security boundary unresolved |
| G5 | Blocks public authority claim |

---

## Closed Gaps

| ID | Gap | Resolution | SHA |
|----|-----|------------|-----|
| GAP-001 | Authority kernel not yet implemented in this repo | Phase 1 authority spine merged with models, schemas, receipts, bounded in-memory replay, verifier, CLI, fixtures, pytest suite, demo scaffold, and green CI. This closes the minimal implementation gap only. Persistent replay, signatures, and E3 receipt bundle remain separate open work. | `1cf86bc1ba7dd7d9c9bdd9270554041b7cc03579` |

---

## Active Gaps

| ID | Gap | Severity | Status | Resolution required |
|---|---:|---:|---|---|
| GAP-002 | Replay cache not yet persistent/atomic | G3 | OPEN | Implement persistent replay store or clearly bound in-memory use. Current Phase 1 cache is intentionally in-memory only. |
| GAP-003 | Agent harness not yet connected to governance gates | G4 | OPEN | Build role-policy-bound orchestrator adapter. |
| GAP-004 | Skill format not yet defined beyond scaffold/spec | G2 | PARTIAL | `skills/SKILL_SPEC.md` exists. Add concrete skills with schemas, examples, tests, and receipts. |
| GAP-005 | Demonstration-as-evidence package is not yet E3 complete | G3 | PARTIAL | Authority spine demo scaffold exists under `forge/demos/authority_spine_001`. Close after demo run logs, receipt bundle, artifact hashes, replay instructions, and failure transcript are captured. |
| GAP-006 | Independent reproduction absent | G5 | OPEN | External witness must replay E3 package. |
| GAP-007 | Source repos have mixed maturity and claims | G4 | OPEN | Import only bounded, tested pieces; quarantine unsupported claims. |
| GAP-008 | Symbolic/prompt systems not separated from runtime authority yet | G4 | PARTIAL | `tests/test_no_liturgical_artifacts.py` enforces it: STATUS.md authority declarations per zone, no Loom imports or paths from authority zones, no executable code in `loom/`, no liturgical markers in authority-zone code. The checker is tested against synthetic repos. Remaining: `loom/` does not exist yet, so no real symbolic material has been migrated under the rule. |
| GAP-009 | Local-first memory not implemented | G2 | PARTIAL | A hash-chained log and verification command exist (`core/authority/chronicle.py`, `weaver-authority chronicle-verify`). Remaining: Merkle proofs for single entries, memory classifications (scratch / working / canon / receipt / archive), export/import. |
| GAP-010 | CI exists for authority spine but not full master build | G3 | PARTIAL | GitHub Actions CI exists for authority tests. Add broader workflows for lint, schemas, receipts, demos, and future runtime packages. |
| GAP-011 | Security review absent | G4 | OPEN | Add threat model and dependency/security scan. |
| GAP-012 | Production deployment posture undefined | G5 | OPEN | Keep production authority at NONE until deployment controls exist. |
| GAP-013 | Canonical JSON serialization differs across portfolio repos | G3 | PARTIAL | Found: Cathedral (`ensure_ascii=False`), zorel-kernel (`ensure_ascii=True`) and Delta-717 (default separators) hash the same data three different ways. Resolved here: `core/authority/canonical.py` registers each form as a named profile (`weaver.c14n.v1`, `zorel.ascii.v1`, `jcs.rfc8785`), Cathedral verifies zorel's sealed receipt under its declared profile, and RFC 8785 JCS is the profile for every new format (Chronicle entries, gate overrides). Remaining: authority receipts are still `weaver.authority.receipt.v1` on the legacy profile. A receipt v2 should carry `hash_profile` and default to JCS. |

---

## Blocking Rule

Any public claim using the words below is blocked until corresponding evidence exists:

```text
production-ready
certified
validated
safe
secure
autonomous
AGI
ASI
clinical
legal authority
defense-ready
independently verified
```

---

## Current Gate

```text
NEXT_ALLOWED_PROMOTION: E2 -> E3 for authority spine only
REQUIRED WORK: receipt bundle, logs, replay package, artifact hashes, failure transcript, promotion report
BLOCKED: production, independent validation, autonomous authority, E3 claim, E4 claim
```

---

## Phase 1 Post-Merge Notes

Merged PR:

```text
PR #1: feat(core): implement Phase 1 authority verification spine
Merge SHA: 1cf86bc1ba7dd7d9c9bdd9270554041b7cc03579
CI: green
```

Current Phase 1 additions on main:

```text
core/authority/ package
core/authority/schemas/
core/authority/fixtures/
core/authority/tests/
forge/demos/authority_spine_001/
.github/workflows/ci.yml
pyproject.toml
```

Promotion posture:

```text
Master blueprint: E1 architecture/scaffold
Authority kernel: E2 candidate / locally executable prototype
E3: blocked until receipt bundle, logs, replay package, artifact hashes, and failure transcript exist
Production authority: none
```

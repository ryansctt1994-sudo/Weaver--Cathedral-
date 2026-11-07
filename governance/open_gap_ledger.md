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
| GAP-002 | Replay cache not yet persistent/atomic | G3 | PARTIAL | `SqliteReplayStore` (`core/authority/replay.py`) is persistent and atomic across processes and restarts on one host: in a test, 8 processes race for the same 50 nonces and each nonce is accepted exactly once. The verifier fails closed (`replay_store_unavailable`) when the store errors, and `weaver-authority verify --replay-db` rejects replays across runs. Remaining: retention/pruning policy, multi-host storage, and making the persistent store the default wherever overrides are accepted. |
| GAP-003 | Agent harness not yet connected to governance gates | G4 | OPEN | Build role-policy-bound orchestrator adapter. |
| GAP-004 | Skill format not yet defined beyond scaffold/spec | G2 | PARTIAL | First concrete skill: `skills/governance/claim_audit/` (manifest, SKILL.md, input/output schemas, example, risk, receipts, contract tests; declared E1). `tests/test_skill_packages.py` rejects any skill package that doesn't meet `SKILL_SPEC.md`. Remaining: the other skills in the spec's first-skills list, and skill receipts recorded in a chronicle. |
| GAP-005 | Demonstration-as-evidence package is not yet E3 complete | G3 | PARTIAL | `forge/demos/authority_spine_001/scripts/bundle.py` builds the package: receipts, 8 failure-path transcripts, a hash-chained chronicle, pytest log, environment, a manifest of bundle and source hashes, and REPLAY.md. `verify_bundle.py` checks every hash, the chronicle head and every receipt, and rebuilds the bundle to require byte-identical deterministic files. CI builds and verifies it on Python 3.11–3.13, uploads it, and requires the deterministic files to match across versions. Remaining: a promotion report and the governance decision. This is not independent reproduction (GAP-006). |
| GAP-006 | Independent reproduction absent | G5 | OPEN | External witness must replay E3 package. |
| GAP-007 | Source repos have mixed maturity and claims | G4 | OPEN | Import only bounded, tested pieces; quarantine unsupported claims. |
| GAP-008 | Symbolic/prompt systems not separated from runtime authority yet | G4 | PARTIAL | `tests/test_no_liturgical_artifacts.py` enforces it: STATUS.md authority declarations per zone, no Loom imports or paths from authority zones, no executable code in `loom/`, no liturgical markers in authority-zone code. The checker is tested against synthetic repos. Remaining: `loom/` does not exist yet, so no real symbolic material has been migrated under the rule. |
| GAP-009 | Local-first memory not implemented | G2 | PARTIAL | A hash-chained log and verification command exist (`core/authority/chronicle.py`, `weaver-authority chronicle-verify`). Remaining: Merkle proofs for single entries, memory classifications (scratch / working / canon / receipt / archive), export/import. |
| GAP-010 | CI exists for authority spine but not full master build | G3 | PARTIAL | GitHub Actions CI exists for authority tests. Add broader workflows for lint, schemas, receipts, demos, and future runtime packages. |
| GAP-011 | Security review absent | G4 | OPEN | Add threat model and dependency/security scan. |
| GAP-012 | Production deployment posture undefined | G5 | OPEN | Keep production authority at NONE until deployment controls exist. |
| GAP-013 | Canonical JSON serialization differs across portfolio repos | G3 | RESOLVED (pending merge) | Found: Cathedral (`ensure_ascii=False`), zorel-kernel (`ensure_ascii=True`) and Delta-717 (default separators) hash the same data three ways. Resolved: each is a named profile in `core/authority/canonical.py`, and RFC 8785 JCS is the default for new formats. Receipts v2 (`weaver.authority.receipt.v2`) record `hash_profile` and bind it into the hash. v1 receipts still verify byte-for-byte (golden tests), and zorel's sealed receipt verifies under `zorel.ascii.v1`. Move to Closed Gaps with the merge SHA. |

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

Enforced by `skills/governance/claim_audit` in CI. An unbacked use of any term above fails the build. A use that is true goes in `governance/claims.json` with its evidence files. A use that isn't a claim (a definition, or a quoted rule) is waived there with a reason, and waivers are counted as debt.

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

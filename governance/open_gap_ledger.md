# Open Gap Ledger

**Document:** Weaver Cathedral Master Build Open Gap Ledger  
**Status:** v0.1.4 E3 replay-evidence hardening  
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
| GAP-001 | Authority kernel not yet implemented in this repo | Phase 1 authority spine merged with models, schemas, receipts, bounded in-memory replay, verifier, CLI, fixtures, pytest suite, demo scaffold, and green CI. This closes the minimal implementation gap only. Persistent replay, signatures, and E3 receipt bundle remain separate work. | `1cf86bc1ba7dd7d9c9bdd9270554041b7cc03579` |

---

## Active Gaps

| ID | Gap | Severity | Status | Resolution required |
|---|---:|---:|---|---|
| GAP-002 | Replay cache not yet persistent/atomic | G3 | CANDIDATE-CLOSE ON MERGE | SQLite-backed replay cache persists nonce state across restart. Tests now require an actual post-restart replay attempt to be rejected. Close after the hardened PR head passes CI and merges. Distributed/production replay remains out of scope. |
| GAP-003 | Agent harness not yet connected to governance gates | G4 | OPEN | Build role-policy-bound orchestrator adapter. |
| GAP-004 | Skill format not yet defined beyond scaffold/spec | G2 | PARTIAL | `skills/SKILL_SPEC.md` exists. Add concrete skills with schemas, examples, tests, and receipts. |
| GAP-005 | Demonstration-as-evidence package is not yet E3 complete | G3 | CANDIDATE-CLOSE ON MERGE | Receipt bundle export/verify includes replay DB, replay log, artifact manifest, failure-case report, and REPLAY.md. Verification now reconciles DB rows, log rows, envelope identity, nonce, payload hash, and stored record hash. Close after the hardened PR head passes CI and merges. |
| GAP-006 | Independent reproduction absent | G5 | OPEN | External witness must replay E3 package. |
| GAP-007 | Source repos have mixed maturity and claims | G4 | OPEN | Import only bounded, tested pieces; quarantine unsupported claims. |
| GAP-008 | Symbolic/prompt systems not separated from runtime authority yet | G4 | OPEN | Enforce `loom/` versus `forge/` separation in tests. |
| GAP-009 | Local-first memory not implemented | G2 | OPEN | Add Merkle log prototype and verification command. |
| GAP-010 | CI exists for authority spine but not full master build | G3 | PARTIAL | CI covers authority tests and the receipt-bundle demo. Add broader workflows for lint, schemas, receipts, demos, and future runtime packages. |
| GAP-011 | Security review absent | G4 | OPEN | Add threat model and dependency/security scan. |
| GAP-012 | Production deployment posture undefined | G5 | OPEN | Keep production authority at NONE until deployment controls exist. |

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
NEXT_ALLOWED_PROMOTION: E2 -> E3 for authority spine only after hardened PR head passes CI and merges
REQUIRED WORK: pytest and replay_demo.sh must pass on the current head
BLOCKED: production, independent validation, autonomous authority, E4 claim
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

---

## E3 Hardening Branch Notes

Branch:

```text
feat/e3-authority-receipts
```

Candidate additions:

```text
Persistent SQLite replay cache
Post-restart replay rejection test
Receipt bundle builder/verifier
Semantic reconciliation of replay.db and replay.log
Envelope nonce, ID, and payload-hash checks against replay evidence
Stored replay record-hash verification
CLI: demo-receipt and verify-receipt
Replay demo script
Artifact manifest
Failure-case report
REPLAY.md instructions
CI replay demo step
```

Evidence history:

```text
GitHub Actions run #40: success on earlier PR head
Run tests: success
Run authority receipt bundle demo: success
Current hardened head: must pass the same CI gates before merge
```

Promotion posture:

```text
Authority kernel on main: E2 candidate / locally executable prototype
E3 branch: implementation and evidence hardening complete, pending current-head CI and merge
E4: blocked until independent reproduction
Production authority: none
```

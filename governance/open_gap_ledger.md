# Open Gap Ledger

**Document:** Weaver Cathedral Master Build Open Gap Ledger  
**Status:** v0.1.3 E3 hardening branch update  
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
| GAP-002 | Replay cache not yet persistent/atomic | G3 | CANDIDATE-CLOSE ON E3 BRANCH | SQLite-backed replay cache added for local reproducible bundles. Close only after PR CI proves tests and replay demo. Distributed/production replay remains out of scope. |
| GAP-003 | Agent harness not yet connected to governance gates | G4 | OPEN | Build role-policy-bound orchestrator adapter. |
| GAP-004 | Skill format not yet defined beyond scaffold/spec | G2 | PARTIAL | `skills/SKILL_SPEC.md` exists. Add concrete skills with schemas, examples, tests, and receipts. |
| GAP-005 | Demonstration-as-evidence package is not yet E3 complete | G3 | CANDIDATE-CLOSE ON E3 BRANCH | Receipt bundle export/verify path added with replay db, replay log, artifact manifest, failure-case report, and REPLAY.md. Close only after PR CI proves replay demo. |
| GAP-006 | Independent reproduction absent | G5 | OPEN | External witness must replay E3 package. |
| GAP-007 | Source repos have mixed maturity and claims | G4 | OPEN | Import only bounded, tested pieces; quarantine unsupported claims. |
| GAP-008 | Symbolic/prompt systems not separated from runtime authority yet | G4 | OPEN | Enforce `loom/` versus `forge/` separation in tests. |
| GAP-009 | Local-first memory not implemented | G2 | OPEN | Add Merkle log prototype and verification command. |
| GAP-010 | CI exists for authority spine but not full master build | G3 | PARTIAL | CI now covers authority tests and, on the E3 branch, the receipt bundle demo. Add broader workflows for lint, schemas, receipts, demos, and future runtime packages. |
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
NEXT_ALLOWED_PROMOTION: E2 -> E3-candidate for authority spine only
REQUIRED WORK: PR CI must pass pytest and replay_demo.sh
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
Receipt bundle builder/verifier
CLI: demo-receipt and verify-receipt
Replay demo script
Artifact manifest
Replay log
Failure-case report
REPLAY.md instructions
CI replay demo step
```

Promotion posture:

```text
Authority kernel: E2 candidate / locally executable prototype
E3 candidate: pending PR CI proof of pytest + replay demo
E4: blocked until independent reproduction
Production authority: none
```

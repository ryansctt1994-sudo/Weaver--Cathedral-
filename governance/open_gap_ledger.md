# Open Gap Ledger

**Document:** Weaver Cathedral Master Build Open Gap Ledger  
**Status:** v0.1  
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

## Active Gaps

| ID | Gap | Severity | Status | Resolution required |
|---|---:|---:|---|---|
| GAP-001 | Authority kernel not yet implemented in this repo | G2 | OPEN | Add core authority package, schemas, tests, CLI |
| GAP-002 | Replay cache not yet persistent/atomic | G3 | OPEN | Implement persistent replay store or clearly bound in-memory use |
| GAP-003 | Agent harness not yet connected to governance gates | G4 | OPEN | Build role-policy-bound orchestrator adapter |
| GAP-004 | Skill format not yet defined | G2 | OPEN | Add `skills/SKILL_SPEC.md`, schemas, examples |
| GAP-005 | Demonstration-as-evidence scaffold missing | G3 | OPEN | Add synthetic fixture demo with success and failure path |
| GAP-006 | Independent reproduction absent | G5 | OPEN | External witness must replay E3 package |
| GAP-007 | Source repos have mixed maturity and claims | G4 | OPEN | Import only bounded, tested pieces; quarantine unsupported claims |
| GAP-008 | Symbolic/prompt systems not separated from runtime authority yet | G4 | OPEN | Enforce `loom/` versus `forge/` separation in tests |
| GAP-009 | Local-first memory not implemented | G2 | OPEN | Add Merkle log prototype and verification command |
| GAP-010 | No CI workflow exists yet for the master build | G3 | OPEN | Add GitHub Actions for tests, lint, schemas, receipts |
| GAP-011 | Security review absent | G4 | OPEN | Add threat model and dependency/security scan |
| GAP-012 | Production deployment posture undefined | G5 | OPEN | Keep production authority at NONE until deployment controls exist |

---

## Blocking Rule

Any public claim using the words below is blocked until corresponding gaps are closed:

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
NEXT_ALLOWED_PROMOTION: E1 -> E2 only
REQUIRED WORK: implement minimal verification spine and tests
BLOCKED: production, independent validation, autonomous authority
```

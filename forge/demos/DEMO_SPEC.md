# Demonstration-as-Evidence Specification

**Status:** v0.1 draft  
**Purpose:** Define how demos become evidence instead of performance theater.

---

## Core Rule

A demo is evidence only when it can be executed, replayed, inspected, and failed safely.

```text
Demo without replay = presentation
Demo without receipts = claim
Demo without failure path = theater
Demo without fixture isolation = risk
```

---

## Required Structure

```text
forge/demos/<demo_id>/
  demo.yaml
  README.md
  fixtures/
  scripts/
    run.sh
    verify.sh
  expected/
  receipts/
  logs/
  failure_cases/
  promotion_report.md
```

---

## `demo.yaml`

Required fields:

```yaml
id: demo.authority_spine.001
name: Authority Spine Replay Demo
claim: Verifies a signed envelope, rejects replay, and emits a receipt.
evidence_level: E1
fixture_policy: synthetic-only
requires_network: false
requires_secrets: false
commands:
  run: ./scripts/run.sh
  verify: ./scripts/verify.sh
success_criteria:
  - valid envelope accepted
  - replayed envelope rejected
  - receipt hash generated
  - logs written
failure_cases:
  - missing signature
  - duplicate nonce
  - schema mismatch
promotion_blockers:
  - no receipt
  - no logs
  - no replay command
  - no failure case
```

---

## Required Receipts

Each demo must produce:

```text
receipt.json
run.log
verify.log
artifact_manifest.json
failure_case_report.json
promotion_report.md
```

---

## Promotion Rules

| Demo state | Evidence level |
|---|---|
| README only | E0 |
| Scaffold exists | E1 |
| Runs locally | E2 |
| Runs with receipts and replay | E3 |
| Independently reproduced | E4 |

---

## Failure Path Requirement

Every demo must include at least one expected failure case.

Examples:

```text
invalid schema rejected
missing signature rejected
replay attempt rejected
policy violation blocked
claim exceeds evidence level and is denied
```

A demo that only shows success cannot promote beyond E2.

---

## Synthetic Fixture Rule

Demos may not require production data, private user data, secrets, credentials, or live external systems unless the demo is explicitly scoped for that and approved.

Default:

```text
fixtures: synthetic-only
network: disabled
secrets: forbidden
```

---

## Auto-Blocker Rule

If a demo fails, the system should generate a blocker record:

```text
forge/issue_exports/<demo_id>-<timestamp>.md
```

Minimum blocker contents:

```text
Demo ID
Failed command
Expected behavior
Observed behavior
Logs path
Receipt status
Suggested owner
Promotion impact
```

---

## First Demo To Build

```text
demo.authority_spine.001
```

Claim:

```text
The system can verify a signed authority envelope, reject replay, validate schema, and produce a receipt from synthetic fixtures.
```

Required before E2:

```text
core/authority implemented
fixtures present
run.sh works
pytest passes
```

# CyberStrike Defensive Evidence Integration

**Status:** Clean-room implementation candidate; draft integration only  
**Authority:** O0 — withheld  
**Production authority:** Prohibited  
**Promotion posture:** HOLD until repository CI and independent reproduction

## Purpose

This integration preserves the most useful assurance pattern described by
[CyberStrike](https://github.com/ryansctt1994-sudo/CyberStrike): a finding should
not be reported from model speculation alone. It must pass an explicit scope
check, establish a baseline, execute a separately governed test, show a
measurable difference, reproduce that difference, and suppress duplicates.

The resulting Weaver Cathedral component is `core/findings/confirmation.py`.
It confirms already-captured structured observations. It does **not** select
targets, execute tests, generate payloads, handle credentials, or authorize any
action.

## Adopted Pattern

| CyberStrike concept | Weaver Cathedral adaptation | Boundary |
|---|---|---|
| Explicit scope control | Exact-match `ScopeBoundary` allowlist | Boundary membership is not proof of legal or organizational authorization |
| Baseline → test → compare | Structured baseline plus at least two test observations | Observation only; no execution capability |
| Measurable, reproducible difference | Stable canonical difference across all test runs | A difference is evidence, not a vulnerability severity claim |
| Duplicate suppression | SHA-256 fingerprint over scope + target + test vector | Session-local registry only |
| Structured findings | Deterministic result and receipt hash | `EVIDENCE_ONLY`, operational authority `O0` |

## Clean-Room and License Boundary

CyberStrike is licensed `AGPL-3.0-only`; Weaver Cathedral is MIT licensed. This
integration therefore adopts only the publicly described assurance pattern.
No CyberStrike source code, prompts, skills, payloads, schemas, or generated
assets are copied or adapted.

The following CyberStrike machinery is intentionally excluded:

- offensive and post-exploitation agents;
- browser/proxy interception and credential/session handling;
- exploit payloads and attack playbooks;
- shell, remote Bolt, MCP, or plugin execution;
- provider routing and autonomous orchestration;
- the 7,600+ security-skill corpus;
- vulnerability severity, exploitability, or production-readiness claims.

## Deterministic Protocol

```text
declared scope
    ↓ exact target check
baseline observation
    ↓
two or more test observations
    ↓ canonical comparison
reproducible difference?
    ├── no  → REJECTED receipt
    └── yes → duplicate fingerprint check
                 ├── seen → DUPLICATE receipt
                 └── new  → CONFIRMED evidence-only receipt (O0)
```

## Invariants

1. Confirmation never grants permission to execute a test.
2. Out-of-scope targets fail closed before comparison.
3. One test observation is insufficient for a confirmed result.
4. No measurable difference means no finding.
5. Inconsistent differences mean the result is not reproducible.
6. Duplicate identity is bound to scope, exact target, and test vector.
7. A confirmed result remains `EVIDENCE_ONLY` at operational authority `O0`.
8. No result self-promotes on the evidence ladder.
9. Scope-bound means inside the declared boundary; it does not mean execution was authorized.

## Verification

Run:

```bash
pytest core/authority/tests/test_finding_confirmation.py -q
```

The tests cover confirmed, out-of-scope, insufficient-reproduction,
no-difference, inconsistent-difference, duplicate, and deterministic-fingerprint
paths.

Passing local or CI tests can support an E2 implementation claim for this
bounded module. E3 still requires a committed receipt bundle, logs, artifact
hashes, replay instructions, and an exercised failure transcript. E4 requires
an identity-bound independent witness.

## Source Claims Not Inherited

CyberStrike's README makes broad capability and security claims about its own
runtime. Those claims are not imported into Weaver Cathedral. This document
records conceptual provenance only; it does not validate CyberStrike or promote
any part of the source repository.

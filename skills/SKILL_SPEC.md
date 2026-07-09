# Weaver Cathedral Skill Specification

**Status:** v0.1 draft  
**Purpose:** Define the reusable skill format for governed agents.

---

## Skill Philosophy

A skill is not just an instruction blob. A skill is a governed capability package.

```text
Skill = instruction + examples + schemas + tests + risk boundary + receipts
```

No skill may be treated as trusted unless it declares inputs, outputs, risks, and evidence level.

---

## Required Structure

```text
skills/<domain>/<skill_name>/
  SKILL.md
  manifest.json
  inputs.schema.json
  outputs.schema.json
  examples/
    example_001.md
  tests/
    test_skill_contract.py
  risk.md
  receipts.md
```

---

## `manifest.json`

Required fields:

```json
{
  "id": "research.eval.lm_eval",
  "name": "LM Evaluation Harness",
  "version": "0.1.0",
  "domain": "research.eval",
  "evidence_level": "E1",
  "allowed_agents": ["Researcher", "Verifier"],
  "requires_human_approval": false,
  "network_access": "declared-only",
  "writes_files": true,
  "executes_code": true,
  "risk_level": "medium",
  "source_lineage": []
}
```

---

## `SKILL.md`

Must include:

```text
# Skill Name

## Purpose
## When To Use
## When Not To Use
## Inputs
## Outputs
## Procedure
## Failure Modes
## Evidence Requirements
## Safety / Security Notes
## Example Invocation
```

---

## Risk Levels

| Level | Meaning | Required control |
|---|---|---|
| low | Docs, formatting, deterministic read-only work | Normal trace |
| medium | File writes, code generation, non-sensitive execution | Sandbox + tests |
| high | Network, credentials, autonomous loops, external systems | Human approval + receipt |
| critical | Legal/medical/financial/safety/security-sensitive action | Domain authority required; default block |

---

## Skill Evidence Promotion

```text
E1: skill scaffold exists
E2: local skill test passes
E3: skill produces replayable receipt bundle
E4: external reproduction of skill behavior
```

---

## Agent Binding

Agents do not get universal skill access. Skill permissions are role-bound.

```text
Planner: may read skill manifests, may not execute high-risk skills
Builder: may execute code/doc skills in sandbox
Verifier: may run tests, receipts, replay checks
Sentinel: may block any skill
Researcher: may run research skills with citation discipline
Operator: human-authorized override path
```

---

## Refusal Rule

A skill must refuse when:

- required input schema fails
- output schema cannot be satisfied
- risk exceeds current agent authority
- human approval is required but absent
- evidence requirements are missing
- task would overclaim validation or authority

---

## First Skills To Implement

```text
governance.claim_audit
governance.receipt_generator
governance.promotion_check
code.testgen
code.docs
code.security_audit
research.eval
research.rag
research.inference
research.safety
```

# Weaver Cathedral Master Build

**Status:** Master synthesis blueprint v0.1  
**Date:** 2026-07-08  
**Authority posture:** Architecture only. No production, safety, legal, medical, defense, AGI, ASI, or autonomous authority is claimed by this document.  
**Evidence posture:** Repository-derived synthesis. Implementation must pass gates before promotion.

---

## 1. Core Thesis

The strongest pattern across the current repository constellation is not one single app. It is a stack:

```text
Agents propose.
Skills execute.
Memory preserves.
Runtime constrains.
Receipts promote.
Governance decides.
```

The master build should therefore become a **governed agentic operating substrate** that combines:

1. **Ruflo-style agent harnessing** for CLI/MCP, swarms, hooks, memory, workflows, and coding-agent orchestration.
2. **Weaver OS verification** for signatures, replay protection, schema validation, provenance, release guardrails, and promotion discipline.
3. **ZOREL / Chronicle receipt doctrine** for authorship, artifact indexing, receipts, promotion locks, and Forge/Loom separation.
4. **T81 deterministic substrate** for bounded reproducibility, deterministic VM concepts, governance-at-execution, and reproducibility gates.
5. **AI Research Skills library** for model architecture, fine-tuning, inference, evaluation, RAG, safety, observability, and MLOps skill packs.
6. **Ouroboros/EDEN simulation concepts** for sandboxed adaptive policy experimentation, ECS-style simulation, benchmarks, and performance telemetry.
7. **FreeLattice local-first UX concepts** for single-user privacy, browser/local-first memory, no-surveillance principles, and Merkle-chained user knowledge.
8. **Swarms-style multi-agent orchestration** for hierarchical, graph, sequential, parallel, and mixture-of-agents workflows.
9. **Quillan HNMoE concepts** for council-style expert routing, ethical vigilance, fallback data handling, and experimental MoE research.
10. **ANGELA-style constitutional prompt architecture** only as symbolic/UX inspiration unless implemented with tests. It must not be treated as proof of autonomous agency.

---

## 2. Master Build Name

```text
WEAVER CATHEDRAL MASTER BUILD v0.1
Codename: FORGE-CROWN
```

Recommended public description:

> Weaver Cathedral is a governed multi-agent research and execution substrate that combines agent orchestration, research skills, deterministic replay, receipt-bound promotion, and local-first memory under explicit evidence gates.

---

## 3. Evidence Boundary

This repository is a **synthesis and staging repo**. It does not inherit every claim from the source repositories. Each imported idea must be reclassified.

```text
Architecture/specification: allowed
Executable implementation: allowed only when code and tests exist here
Authority claim: denied until receipts + tests + independent reproduction exist
Myth/symbolic language: archived or UX-layer only
Production claim: denied by default
Clinical/legal/safety-critical claim: denied by default
Autonomous authority: denied by default
```

Master invariant:

```text
NO RECEIPT = NO PROMOTION
NO TEST = NO EXECUTION CLAIM
NO REPLAY = NO TRUSTED STATE
NO BOUNDARY = NO AUTHORITY
```

---

## 4. Source Repo Contribution Map

| Source repo | Keep | Role in master build | Promotion status |
|---|---|---|---|
| `ruflo` | CLI/MCP harness, plugin model, swarms, memory, hooks, workflows, federation concepts | Agentic execution shell | Candidate implementation source, requires integration tests |
| `Weaver_Os` | replay cache, verifier, schemas, release guard, provenance CLI, promotion discipline | Verification spine | Highest fit for core governance |
| `zorel-kernel` | authorship receipt package, Chronicle manifest, artifact index, Forge/Loom boundary, invariants | Provenance and receipt doctrine | Preserve as governance doctrine, executable receipts preferred |
| `t81-foundation` | deterministic stack, TISC/VM concept, Axion policy kernel, repro gate, authority levels | Deterministic execution substrate | Future hard-runtime layer |
| `AI-Research-SKILLs` | 83 skills across research lifecycle, installer pattern, safety/RAG/eval/MLOps coverage | Skill library | Use as modular skill pack inspiration |
| `swarms` | production multi-agent orchestration, hierarchical/parallel/graph workflows, retries, async, type safety | Multi-agent workflow layer | Use as orchestration model, do not overclaim production readiness here |
| `FreeLattice` | local-first UX, IndexedDB persistence, Merkle Core, no surveillance, single-file portability | Human-facing local interface | UX layer and memory principles |
| `Ouroboros` | sandbox execution, patch management, IPC daemon/client, ECS simulation, Weaver policy sandbox, benchmarks | Simulation and experimental policy arena | Research sandbox only |
| `Quillan-v4.2-repo` | HNMoE/council routing idea, fallback data handling, training loop concepts | Experimental model research branch | Quarantine from authority path until cleaned/tested |
| `ANGELA` | constitutional self-description, prompt architecture, ethical framing | Narrative/prompt layer | Must remain non-executive unless formalized/tested |

---

## 5. Target Architecture

```text
weaver-cathedral/

  core/
    authority/              # signature, role, issuer, refusal, replay verification
    provenance/             # build/release receipts, manifests, SLSA-like records
    policy/                 # constitutional and operational policies
    schemas/                # JSON schemas and typed contracts

  runtime/
    orchestrator/           # task router, agent lifecycle, workflow graph
    sandbox/                # tool execution, patch execution, simulation safe zones
    determinism/            # deterministic replay adapters, repro gates, test fixtures
    memory/                 # local-first memory, Merkle logs, retrieval indexes

  agents/
    registry/               # agent definitions, roles, permissions, skill access
    councils/               # MoE/council-style expert routing experiments
    swarms/                 # graph, sequential, parallel, hierarchical workflows

  skills/
    research/               # model architecture, training, eval, RAG, inference, MLOps
    code/                   # testgen, docs, security audit, patch review
    governance/             # receipts, promotion checks, claim audits

  forge/
    demos/                  # executable demonstration-as-evidence packages
    receipts/               # generated receipts and logs
    benchmarks/             # performance, determinism, replay, safety checks
    issue_exports/          # failed demos auto-create blockers

  loom/
    doctrine/               # symbolic, interpretive, UX, philosophical material
    prompts/                # non-authoritative prompt templates
    archives/               # preserved but non-executive materials

  interfaces/
    cli/                    # command-line interface
    web/                    # local-first UI / dashboard
    api/                    # optional HTTP interface

  governance/
    promotion_rules.md
    evidence_ladder.md
    authority_passports.md
    source_boundary.md
    open_gap_ledger.md

  tests/
    unit/
    integration/
    replay/
    security/
    demos/
```

---

## 6. Execution Model

Every operation moves through five gates:

```text
1. Proposal Gate
   An agent, user, or workflow proposes an action.

2. Policy Gate
   Role, permission, risk, and scope are checked.

3. Evidence Gate
   Required inputs, receipts, schemas, tests, and provenance are verified.

4. Execution Gate
   Action runs in the correct sandbox with bounded permissions.

5. Promotion Gate
   Result becomes trusted only if logs, receipts, replay, and claims match.
```

No agent is allowed to promote its own output into trusted state without externalized evidence.

---

## 7. Master Components

### 7.1 Authority Kernel

Borrow from Weaver OS and ZOREL.

Responsibilities:

- issuer registry
- role policy
- signature envelope verification
- replay cache
- refusal verification
- schema validation
- promotion lock
- release provenance

Minimum viable commands:

```bash
weaver verify-envelope envelope.json
weaver verify-release dist/ manifest.json provenance.json
weaver promote --artifact artifact.json --evidence receipts/
weaver deny --artifact artifact.json --reason missing-replay
```

### 7.2 Agent Harness

Borrow from Ruflo and Swarms.

Responsibilities:

- agent registry
- skills routing
- multi-agent workflow graphs
- memory access controls
- background loops only when explicitly scheduled
- task traces
- model/provider abstraction
- tool permission boundaries

Agent classes:

```text
Planner       proposes decompositions
Builder       writes code/docs
Verifier      runs tests and validates receipts
Archivist     preserves source/provenance
Sentinel      blocks unsafe or overclaimed promotion
Researcher    uses skill packs and citation discipline
Operator      human-authorized execution interface
```

### 7.3 Skill Forge

Borrow from AI-Research-SKILLs and Ruflo plugins.

Skill categories to include first:

```text
research.eval
research.rag
research.safety
research.inference
research.finetuning
code.testgen
code.docs
code.security_audit
governance.receipts
governance.claim_audit
governance.promotion
```

Each skill must include:

```text
SKILL.md
examples/
tests/
inputs.schema.json
outputs.schema.json
risk.md
receipts.md
```

### 7.4 Deterministic/Repro Layer

Borrow from T81 and Weaver OS.

Responsibilities:

- deterministic fixtures
- pinned environment profiles
- replayable command logs
- artifact hash manifests
- bounded determinism registry
- reproducibility gate

Evidence rule:

```text
If an output cannot be replayed from repository materials, it cannot advance beyond E1/E2 depending on available scaffolding.
```

### 7.5 Local-First Memory and UX

Borrow from FreeLattice.

Responsibilities:

- user-owned local memory
- Merkle-chained memory entries
- export/import portability
- no hidden telemetry
- local browser UI option
- visible memory provenance

Memory classifications:

```text
scratch        temporary, discardable
working        task-bound context
canon          user-approved stable knowledge
receipt        immutable evidence record
archive        preserved but non-authoritative
```

### 7.6 Simulation and Policy Sandbox

Borrow from Ouroboros/EDEN.

Responsibilities:

- run adaptive policies against synthetic fixtures
- benchmark routing, latency, memory, and policy effects
- test failure paths
- isolate experimental self-improvement loops from authority path

Hard boundary:

```text
Simulation can generate hypotheses.
Simulation cannot certify deployment authority.
```

### 7.7 Council / MoE Research Track

Borrow from Quillan.

Use only as a research pattern:

- expert routing
- council adjudication
- fallback data behavior
- ethical vigilance logs
- hierarchical reduction

Do not carry over unsupported consciousness, peer-validation, or authority language into engineering claims.

---

## 8. Evidence Ladder

```text
E0  Idea or symbolic concept
E1  Scaffold exists
E2  Locally executable
E3  Reproducible package with receipts
E4  Independently reproduced by external witness
E5  Domain validation where applicable
E6  Production-certified deployment where applicable
```

Promotion rules:

```text
E0 -> E1 requires file scaffold and declared claim.
E1 -> E2 requires local executable command and passing tests.
E2 -> E3 requires receipts, logs, deterministic fixture, failure path, and replay instructions.
E3 -> E4 requires independent witness reproduction.
E4 -> E5 requires domain-specific validation.
E5 -> E6 requires operational certification and deployment controls.
```

Default status for this master build:

```text
Architecture: E1
Executable authority kernel: pending
Agent runtime: pending
Independent reproduction: absent
Production authority: none
```

---

## 9. Build Phases

### Phase 0 — Seal the Synthesis

Deliverables:

- this README
- source contribution map
- evidence ladder
- authority boundary
- open gap ledger

Exit gate:

```text
Docs are internally consistent and no source claim is promoted without evidence.
```

### Phase 1 — Minimal Verification Spine

Deliverables:

- `core/authority/` package
- schema validator
- replay cache
- receipt generator
- pytest suite
- CLI `weaver verify`

Exit gate:

```text
pytest -q passes and receipt demo replays from repo materials.
```

### Phase 2 — Agent Harness Adapter

Deliverables:

- agent registry
- skill manifest format
- role policy binding
- workflow trace format
- sandboxed task runner

Exit gate:

```text
A Planner -> Builder -> Verifier workflow runs on a synthetic task and produces receipts.
```

### Phase 3 — Skill Forge

Deliverables:

- installable skill package format
- first 10 governance/research/code skills
- skill tests
- skill risk metadata

Exit gate:

```text
Each skill has schema, examples, tests, and receipt instructions.
```

### Phase 4 — Local-First Memory

Deliverables:

- Merkle memory log
- import/export
- memory classification
- UI or CLI viewer

Exit gate:

```text
Memory entries can be created, hashed, exported, imported, and verified.
```

### Phase 5 — Demonstration-as-Evidence

Deliverables:

- executable demo scaffold
- synthetic fixtures
- success and failure paths
- auto blocker generation
- promotion report

Exit gate:

```text
A demo cannot self-promote without logs, receipts, and replay success.
```

---

## 10. Non-Negotiable Boundaries

1. Symbolic systems may inspire UI, language, archive structure, and pedagogy, but not runtime authority.
2. No model output is trusted by default.
3. No agent may grant itself permission.
4. No simulation result counts as real-world validation.
5. No clinical, legal, defense, safety-critical, or financial use claim exists until domain validation and human authority are documented.
6. Public materials must distinguish architecture, prototype, test result, and production capability.
7. Missing evidence causes HOLD, not narrative promotion.

---

## 11. Immediate Next Files To Add

```text
governance/evidence_ladder.md
governance/open_gap_ledger.md
governance/source_boundary.md
governance/authority_passports.md
core/authority/README.md
runtime/orchestrator/README.md
skills/SKILL_SPEC.md
forge/demos/DEMO_SPEC.md
```

---

## 12. Current Verdict

This master build should not be a giant merged pile. It should be a **governed synthesis layer**.

The best build is:

```text
Ruflo/Swarms for agent motion
AI-Research-SKILLs for capability packs
Weaver OS for verification
ZOREL for receipts and invariant doctrine
T81 for deterministic/reproducible runtime direction
FreeLattice for local-first UX and Merkle memory
Ouroboros for simulation sandboxing
Quillan for experimental council/MoE research
ANGELA for symbolic constitutional language only
```

Final posture:

```text
MASTER BUILD CREATED AS ARCHITECTURE
AUTHORITY DEFAULT: NONE
PROMOTION DEFAULT: HOLD
IMPLEMENTATION NEXT: VERIFICATION SPINE
```
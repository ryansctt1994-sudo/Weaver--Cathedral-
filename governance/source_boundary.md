# Source Boundary Policy

**Document:** Weaver Cathedral Source Boundary Policy  
**Status:** v0.1  
**Purpose:** Define how ideas, code, patterns, and claims from other repositories may enter the master build.

---

## Principle

The master build may learn from every repository, but it does not inherit authority from any of them.

```text
Imported idea != imported evidence
Imported code != trusted code
Imported claim != verified claim
Forked maturity != local maturity
```

---

## Source Classes

| Class | Description | Treatment |
|---|---|---|
| S0 | Symbolic, philosophical, mythic, or prompt-only material | Archive under `loom/`; no runtime authority |
| S1 | Architecture or design spec | May inform docs; must be tagged architecture only |
| S2 | Executable code without local tests | Quarantine until tests added |
| S3 | Executable code with local tests | Candidate implementation after integration testing |
| S4 | Reproducible artifact with receipts | Candidate for E3 promotion after replay here |
| S5 | Independently reproduced artifact | Candidate for E4 if reproduction is documented here |

---

## Repo-Specific Boundary Notes

### `ruflo`

Keep agent harness, plugins, hooks, CLI/MCP concepts, swarm coordination, memory patterns, and workflow scaffolding. Reclassify all production or ecosystem claims under local evidence rules.

### `Weaver_Os`

Highest-fit implementation source for authority verification, replay, signatures, schema validation, provenance, and release guard concepts. Import carefully into `core/authority/` and `core/provenance/`.

### `zorel-kernel`

Preserve receipt doctrine, authorship package structure, artifact index pattern, Chronicle-style manifests, and Forge/Loom boundary. Treat symbolic language as non-executive unless formalized.

### `t81-foundation`

Use deterministic runtime, repro gate, frozen spec, VM, ISA, and policy kernel concepts as north-star architecture. Do not claim T81-level deterministic behavior until implemented and tested here.

### `AI-Research-SKILLs`

Use as the skill-pack model for research engineering. Each imported skill must gain local schema, examples, tests, risk notes, and receipt instructions.

### `swarms`

Use workflow patterns: hierarchical, sequential, parallel, graph, retries, async, memory, and tool integration. Do not inherit production-ready claims.

### `FreeLattice`

Use local-first UX, Merkle Core, no-surveillance posture, export/import, browser-first interaction, and human-owned memory principles. Keep metaphysical AI-personhood claims out of runtime authority.

### `Ouroboros`

Use sandboxing, patch management, IPC concepts, ECS simulation, adaptive policy experiments, and benchmark discipline. Treat consciousness language as simulation metaphor only.

### `Quillan-v4.2-repo`

Use HNMoE/council routing as an experimental research pattern. Do not import unsupported validation language or unbounded model claims.

### `ANGELA`

Use constitutional prompt architecture as UX/prompt inspiration. ANGELA itself explicitly frames itself as a Custom GPT constitutional framework rather than independent autonomous execution; preserve that boundary.

---

## Import Checklist

Before importing any source file, idea, or module:

```text
[ ] What repo did it come from?
[ ] What class is it? S0-S5
[ ] Is it architecture, code, test, receipt, or claim language?
[ ] Does it require license attribution?
[ ] Does it include unsupported authority language?
[ ] Does it have local tests?
[ ] Does it have replay instructions?
[ ] Does it belong in forge/, loom/, core/, runtime/, agents/, or skills/?
[ ] What evidence level can it honestly claim here?
```

---

## Quarantine Rule

Anything with unclear provenance, unsupported validation language, missing license status, or unsafe authority leakage goes into quarantine:

```text
archive/quarantine/<source-repo>/<artifact>
```

Quarantined material may be read, summarized, or refactored. It may not execute or promote.

---

## License Note

Do not blindly copy code from external or forked upstream repositories without preserving license obligations. For now, prefer original implementation of the master spine and treat external repos as design references unless licensing is explicitly checked.

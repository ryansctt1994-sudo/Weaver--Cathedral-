# Portfolio source registry

Audit date: 2026-07-14  
Account: `ryansctt1994-sudo`  
Scope: 61 repositories, 24,306 tracked paths, 95 cross-repository duplicate-blob groups

## Decision rules

Every repository tree, root README, and root license signal was inspected. The
strongest candidates also received targeted source and test review. This is a
portfolio consolidation audit, not a claim that every upstream feature was
executed.

- **Core**: clean implementation belongs inside one of the three masters.
- **Adapter**: useful external capability stays behind the Agent OS boundary.
- **Reference**: ideas or documentation only; no source is copied.
- **Service**: license or risk requires process separation.
- **Quarantine**: unsupported safety/scientific claims, unsafe demos, or unclear provenance.
- **Exclude**: duplicate, broken, or outside the three-master architecture.

Unknown, absent, conflicting, placeholder, or all-rights-reserved licensing is
treated as no permission to copy. Third-party code is not placed in the
authority path. A repository's presence in this account is not treated as
proof of authorship.

## Three-master architecture

| Master | Responsibility | Selected internal sources |
|---|---|---|
| `Weaver_Os` | Assurance core: authority, canonicalization, replay, receipts, Chronicle, promotion, veto contract | Weaver_Os, Lumen, cathedral-verified, zorel-kernel |
| `Weaver--Cathedral-` | Governed Agent OS: orchestration, tools, evidence memory, skills, adapters, evolution | Weaver--Cathedral-, Cortex/Gbrain concepts through boundaries, external agent frameworks as adapters |
| `Math_Build1994` | Auto Scientist: lifecycle, experiments, proof checking, benchmarks, claim promotion | Math_Build1994, AutoProof lessons, A.G.I-Seed- benchmark concepts |

The Agent OS and Auto Scientist depend on the Assurance Core; neither can
mint its own authority or evidence level.

## Repository-by-repository disposition

| Repository | Paths | License/provenance signal | Decision | Destination or reason |
|---|---:|---|---|---|
| A.G.I-Seed- | 21 | MIT; account-authored | Core concepts | Auto Scientist; sufficiency score remains advisory until calibrated |
| agency-agents6 | 238 | Third-party head; README/tree mismatch | Quarantine | Agent role prompts may be indexed only after provenance review |
| AGI-to-ASI-TRANSITION-PROOF-LAYER | 7 | No root license; third-party head | Quarantine | Unsupported “proof” claims cannot enter evidence gates |
| ai-agent-terraform | 30 | AGPL-3.0; third-party | Service | Infrastructure reference, process-separated if ever used |
| AI-Research-SKILLs | 427 | MIT; third-party | Adapter | Skill-source metadata only; validate each imported skill |
| ai-ticket | 26 | MIT; third-party | Reference | Ticketing ideas; not part of core execution |
| ANGELA | 1,059 | MIT; t81dev | Adapter | Prompt-framework adapter only; prompts carry no authority |
| astryx | 3,707 | MIT; third-party | Adapter | Optional UI/design-system dependency |
| AutoProof | 24 | MIT; third-party | Core lessons | Auto Scientist; removed token-based demo “proof” fallback |
| awesome-agent-skills | 3 | MIT; third-party | Reference | External skill index, not executable trust material |
| cathedral-verified | 13 | MIT; account-authored | Core | Assurance Chronicle tests and fail-safe latch contract |
| claude-code-best-practice-Codex- | 454 | Third-party snapshot; terms need review | Reference | Documentation only pending provenance/license confirmation |
| Cortex | 88 | MIT; third-party | Adapter | Evidence-memory concepts behind verified-only Agent OS interface |
| Delta-717 | 22 | Third-party app scaffold; terms unclear | Exclude | Overlaps Quillan- scaffold and adds no core capability |
| Delta-RPM-Protocol | 268 | All rights reserved; third-party | Reference | No source copying; protocol ideas only with independent review |
| duotronic-computing | 47 | t81dev; terms need review | Reference | Hardware research only; no assurance claim |
| Echo-Root-Ve-Protocol | 170 | MIT; third-party | Adapter | External gate candidate; cannot bypass local policy |
| FreeLattice | 361 | MIT; third-party | Adapter | Optional local-first UX patterns |
| Gbrain-Reinforced | 1,033 | MIT; third-party/origin mixed | Adapter | Knowledge/memory service behind receipt-verifying boundary |
| hermes-agent-self-evolution | 29 | No root license; README terms unconfirmed | Reference | Evolution ideas only until license is confirmed |
| LogOS | 99 | No root license; third-party | Quarantine | Symbolic/formal claims require independent verification |
| Lumen | 46 | Apache-2.0; account-authored | Core | Receipt/replay/Chronicle MVP patterns; software-reset veto rejected |
| Lumen-Elpis | 2 | Account-authored docs; terms unclear | Reference | Narrative material only |
| Math_Build1994 | 18 | MIT; account-authored | Core | Auto Scientist master and existing Lean proof project |
| meta-meme | 123 | MIT; third-party | Exclude | Creative system outside governed runtime core |
| n00b | 30 | Third-party; terms need review | Reference | Learning material only |
| NexusGate | 3,263 | No root license; third-party | Exclude | Contains exact Cortex copies; standalone Cortex is canonical reference |
| OpenMythos | 23 | MIT; third-party | Reference | Theoretical model research, not runtime evidence |
| Ouroboros | 735 | MIT; account mirror | Adapter | Canonical reference for overlapping sandbox/ECS concepts |
| owl | 153 | No root license in snapshot; third-party | Adapter | Research framework only after license resolution |
| Pandora | 166 | MIT; third-party | Exclude | Significant exact overlap with Ouroboros; avoid duplicate source |
| Quillan- | 21 | Third-party app scaffold; terms unclear | Exclude | Prototype scaffold with no unique master capability |
| Quillan-v4.2-repo | 757 | Apache-2.0; third-party | Quarantine | Experimental HNMoE; validation/consciousness language not accepted as evidence |
| reson8-Labs | 319 | Third-party; terms need review | Reference | Context patterns only; duplicate overlap recorded |
| rosclaw | 85 | Third-party; terms need review | Adapter | Robotics adapter candidate; requires physical safety boundary |
| ruflo | 5,103 | MIT; third-party | Adapter | External orchestrator only; deterministic local gate remains authoritative |
| skills | 106 | Apache-2.0; Hugging Face source | Adapter | Skill-source metadata with provenance and risk validation |
| solfunmeme | 106 | MIT; third-party | Exclude | Generic Next.js template outside master scope |
| SpiralSafe | 1,016 | Dual terms; third-party | Reference | Concepts only; preserve separate code/document license obligations |
| spiralsafe-mono | 57 | No root license; merge-conflict markers | Exclude | Broken snapshot and unclear permission |
| strix | 189 | Apache-2.0; third-party | Adapter | Security-testing adapter with explicit authorization boundary |
| SuperAGI | 771 | MIT; third-party | Adapter | External agent framework; no direct authority |
| swarms | 493 | AGPL-3.0; third-party | Service | Network/process boundary only to contain license and runtime risk |
| Sym-Chaos- | 18 | Account-authored; terms need review | Reference | Research notes only pending stronger evidence |
| SynthaMed | 3 | MIT; account-authored docs | Reference | Domain pack; medical use requires separate clinical governance |
| system-prompts-and-models-of-ai-tools | 107 | GPL-3.0; third-party | Reference | Prompt research only; do not blend into core distribution |
| t81-benchmarks | 37 | No root license; t81dev | Reference | Benchmark ideas only, not copied |
| t81-docs | 52 | No root license; t81dev | Reference | Documentation only, not copied |
| t81-foundation | 1,713 | MIT; t81dev | Adapter | Rich deterministic external stack; dependency/reference, not authority core |
| t81-hardware | 28 | No root license; t81dev | Reference | Hardware concepts only; simulation is not silicon evidence |
| t81-roadmap | 72 | No root license; t81dev | Reference | Planning material only |
| t81lib | 165 | “MIT placeholder” license defect | Quarantine | Resolve legal provenance before any reuse |
| ternary | 12 | No root license; t81dev | Reference | Concepts only, not copied |
| ternary-tools | 9 | MIT; t81dev | Adapter | Optional tooling after interface and evidence review |
| tinyclaw | 134 | MIT; third-party | Adapter | Messaging interface; messages are untrusted proposals |
| trinity | 6 | Apache-2.0; account mirror | Exclude | README marks security use as playful/unsafe |
| trinity-pow | 6 | Apache-2.0; t81dev | Exclude | README marks security use as playful/unsafe |
| Weaver--Cathedral- | 31 | MIT; account-authored | Core | Agent OS master; preserves authority-spine history |
| Weaver_Os | 179 | MIT; account-authored | Core | Assurance master; retains strong triadic crypto/replay controls |
| Weavers-Forge- | 13 | MIT; account-authored | Reference | Community/contribution documentation |
| zorel-kernel | 13 | MIT; account-authored | Core concepts | Provenance receipt patterns; E3 label downgraded unless independently replayed |

## Known non-claims and open gates

- The audit found candidates; it did not certify all 61 repositories as safe,
  correct, original, or production-ready.
- Local tests are E2 evidence. A distinct environment/operator must produce the
  replay transcript required for E4.
- The veto latch is reference RTL. FPGA/ASIC timing, metastability, reset,
  fault-injection, and physical kill-path validation remain open.
- External frameworks, skills, prompts, and models are untrusted inputs until
  their exact version, license, hash, and behavior are recorded.
- Medical, robotics, security-testing, and autonomous infrastructure adapters
  require domain-specific authorization and safety cases.

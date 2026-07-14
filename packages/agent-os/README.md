# Weaver Cathedral Agent OS

A governed multi-agent execution layer built on Weaver Assurance Core.

Agents may propose work. They never receive direct execution authority. Every
tool call moves through a deterministic role policy, optional signed human
approval, replay protection, a bounded tool registry, Chronicle logging, and an
evidence receipt.

## Vertical slice

```text
agent proposal
  -> deterministic policy gate
  -> signed approval when required
  -> atomic replay boundary
  -> allow-listed tool
  -> Chronicle event
  -> execution receipt
  -> evidence memory
```

```bash
PYTHONPATH=../Weaver_Os/src:src python tests/run_tests.py
```

## What was consolidated

- Weaver/AGI Seed separation of reasoning from authority;
- Lumen transfer and skill-promotion discipline;
- Ruflo, OWL, Swarms, TinyClaw, and Agency Agents orchestration patterns;
- Cortex/GBrain local evidence-memory patterns;
- Hermes constraint-gated evolution patterns;
- FreeLattice local-first ownership posture;
- Strix security testing as an external adapter.

Large third-party frameworks are adapters, not vendored internals. AGPL/GPL
systems must remain process-separated. No-license and all-rights-reserved
sources are reference-only.


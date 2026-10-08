# Weaver Cathedral Agent OS — master consolidation v2

The new implementation lives in `packages/agent-os/`, preserving the existing
Cathedral authority-spine work during review. It consumes the assurance core
from `ryansctt1994-sudo/Weaver_Os`.

The package provides proposal-bound approvals, deterministic policy gates,
allow-listed tools, evidence-first memory, non-executable skill manifests,
candidate-promotion controls, and an orchestrator that records every decision
and result in a Chronicle before issuing a receipt.

Third-party agent frameworks remain adapters or process-separated services.
Their code is not copied into the authority path, and no external framework can
self-promote evidence or bypass the deterministic gate.

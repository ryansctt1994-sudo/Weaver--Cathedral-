"""Proposal-to-receipt execution flow."""

from __future__ import annotations

import time
import uuid

from weaver_assurance import Chronicle, EvidenceReceipt, SQLiteReplayCache
from weaver_assurance.canonical import sha256_json

from .gate import ApprovalToken, DeterministicGate
from .models import Decision, Proposal, RunResult
from .tools import ToolRegistry


def semantic_outcome_hash(*, ok: bool, data: dict, error: str | None) -> str:
    """Hash reproducible outcome fields; runtime telemetry is deliberately excluded."""
    return sha256_json({"ok": ok, "data": data, "error": error})


class Orchestrator:
    def __init__(
        self,
        *,
        gate: DeterministicGate,
        registry: ToolRegistry,
        replay: SQLiteReplayCache,
        chronicle: Chronicle,
        environment_hash: str,
        replay_ttl_seconds: int = 300,
    ) -> None:
        self.gate = gate
        self.registry = registry
        self.replay = replay
        self.chronicle = chronicle
        self.environment_hash = environment_hash
        self.replay_ttl_seconds = replay_ttl_seconds

    def run(self, proposal: Proposal, *, approval: ApprovalToken | None = None, now: int | None = None) -> RunResult:
        current = int(time.time()) if now is None else int(now)
        decision = self.gate.evaluate(proposal, approval=approval, now=current)
        self.chronicle.append(
            "AGENT_DECISION",
            {"proposal_id": proposal.proposal_id, "proposal_hash": decision.proposal_hash,
             "allowed": decision.allowed, "reason": decision.reason},
            timestamp_ns=current * 1_000_000_000,
        )
        if not decision.allowed:
            return RunResult(decision)

        replay_key = sha256_json(
            {"domain": "weaver.agent.proposal.v1", "proposal_hash": decision.proposal_hash}
        )
        if not self.replay.check_and_record(replay_key, current + self.replay_ttl_seconds, now=current):
            denied = Decision(False, "PROPOSAL_REPLAY_DETECTED", decision.proposal_hash, decision.requires_approval)
            self.chronicle.append(
                "AGENT_DECISION",
                {"proposal_id": proposal.proposal_id, "proposal_hash": decision.proposal_hash,
                 "allowed": False, "reason": denied.reason},
                timestamp_ns=current * 1_000_000_000 + 1,
            )
            return RunResult(denied)

        outcome = self.registry.execute(proposal.tool, proposal.arguments)
        output_hash = semantic_outcome_hash(ok=outcome.ok, data=outcome.data, error=outcome.error)
        event = self.chronicle.append(
            "TOOL_RESULT",
            {"proposal_id": proposal.proposal_id, "tool": proposal.tool, "ok": outcome.ok,
             "output_hash": output_hash, "duration_ns": outcome.duration_ns},
            timestamp_ns=current * 1_000_000_000 + 2,
        )
        receipt = EvidenceReceipt.create(
            receipt_id=str(uuid.uuid4()),
            subject=proposal.proposal_id,
            producer="weaver-agent-orchestrator",
            policy_version="weaver.agent.policy.v1",
            evidence_level="E2",
            input_hashes={"proposal": decision.proposal_hash},
            output_hashes={"tool_outcome": output_hash, "chronicle_event": event["hash"]},
            command=(proposal.tool,),
            exit_code=0 if outcome.ok else 1,
            environment_hash=self.environment_hash,
            replay_status="LOCAL_EXECUTION",
            created_at=f"unix:{current}",
        )
        return RunResult(decision, outcome, receipt.to_dict())

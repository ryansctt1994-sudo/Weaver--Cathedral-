from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from weaver_assurance import AuthorityVerifier, Chronicle, KeyGrant, SQLiteReplayCache, create_envelope, sign_envelope
from weaver_assurance.authority import public_key_b64
from weaver_agent import (
    ApprovalToken,
    DeterministicGate,
    EvidenceMemory,
    FunctionTool,
    Orchestrator,
    Proposal,
    RolePolicy,
    SkillManifest,
    ToolRegistry,
)
from weaver_agent.evolution import CandidateMetrics, evaluate_candidate
from weaver_agent.orchestrator import semantic_outcome_hash


def build_runtime(tmp_path):
    registry = ToolRegistry()
    registry.register(FunctionTool("math.add", lambda args: {"sum": args["a"] + args["b"]}))
    registry.register(FunctionTool("state.change", lambda args: {"changed": bool(args["value"])}))
    gate = DeterministicGate(
        [RolePolicy("builder", frozenset({"math.add", "state.change"}), max_risk=3, approval_at_or_above=2)]
    )
    return Orchestrator(
        gate=gate,
        registry=registry,
        replay=SQLiteReplayCache(tmp_path / "agent-replay.db"),
        chronicle=Chronicle(tmp_path / "agent-chronicle.jsonl"),
        environment_hash="e" * 64,
    )


def proposal(*, tool="math.add", risk=1, proposal_id="p1"):
    arguments = {"a": 2, "b": 3} if tool == "math.add" else {"value": 1}
    return Proposal(proposal_id, "agent-1", "builder", tool, arguments, risk, ("receipt-source",))


def test_low_risk_tool_executes_and_replay_is_blocked(tmp_path):
    runtime = build_runtime(tmp_path)
    first = runtime.run(proposal(), now=1000)
    assert first.decision.allowed
    assert first.outcome and first.outcome.data == {"sum": 5}
    assert first.receipt and first.receipt["receipt_hash"]
    second = runtime.run(proposal(), now=1000)
    assert not second.decision.allowed
    assert second.decision.reason == "PROPOSAL_REPLAY_DETECTED"


def test_unknown_tool_and_missing_evidence_fail_closed(tmp_path):
    runtime = build_runtime(tmp_path)
    unknown = Proposal("p2", "agent-1", "builder", "shell", {}, 0, ("r",))
    assert runtime.run(unknown, now=1000).decision.reason == "TOOL_NOT_ALLOWED_FOR_ROLE"
    no_evidence = Proposal("p3", "agent-1", "builder", "math.add", {"a": 1, "b": 1}, 0)
    assert runtime.run(no_evidence, now=1000).decision.reason == "MISSING_EVIDENCE_REFERENCE"


def test_high_risk_requires_signed_approval_bound_to_proposal(tmp_path):
    runtime = build_runtime(tmp_path)
    candidate = proposal(tool="state.change", risk=2, proposal_id="p4")
    assert runtime.run(candidate, now=1000).decision.reason == "HUMAN_APPROVAL_REQUIRED"

    key = Ed25519PrivateKey.generate()
    authority = AuthorityVerifier(
        [KeyGrant("human", public_key_b64(key), "HUMAN", 3, 900, 2000, ("agent.execute",))],
        SQLiteReplayCache(tmp_path / "authority-replay.db"),
    )
    envelope = create_envelope(
        envelope_id="approval-1",
        issuer="operator",
        subject=candidate.proposal_id,
        action="agent.execute",
        system_id="weaver-agent-test",
        scope_hash="f" * 64,
        nonce="approval-nonce",
        issued_at=1000,
        valid_until=1100,
        requested_authority=3,
        payload={"proposal_hash": candidate.hash()},
    )
    envelope = sign_envelope(envelope, "human", key)
    approval = ApprovalToken.from_verified(envelope, authority.verify(envelope, now=1000))
    result = runtime.run(candidate, approval=approval, now=1000)
    assert result.decision.allowed
    assert result.outcome and result.outcome.ok


def test_approval_cannot_be_reused_for_different_proposal(tmp_path):
    gate = DeterministicGate([RolePolicy("builder", frozenset({"state.change"}), 3, 1)])
    first = proposal(tool="state.change", risk=2, proposal_id="first")
    second = proposal(tool="state.change", risk=2, proposal_id="second")
    fake_bound = ApprovalToken(first.hash(), "env", ("key",), 2000)
    decision = gate.evaluate(second, approval=fake_bound, now=1000)
    assert not decision.allowed
    assert decision.reason == "APPROVAL_NOT_BOUND_TO_PROPOSAL"


def test_memory_defaults_to_verified_only(tmp_path):
    memory = EvidenceMemory(tmp_path / "memory.db")
    memory.put(memory_id="m1", kind="result", content={"topic": "alpha"}, receipt_hash="a", verified=True, created_at=1)
    memory.put(memory_id="m2", kind="guess", content={"topic": "alpha"}, receipt_hash="b", verified=False, created_at=2)
    assert [item["memory_id"] for item in memory.search("alpha")] == ["m1"]
    assert len(memory.search("alpha", verified_only=False)) == 2


def test_skill_manifest_is_metadata_not_code():
    manifest = SkillManifest.from_dict(
        {
            "skill_id": "research.audit",
            "version": "1.0.0",
            "description": "Audit an evidence bundle",
            "required_tools": ["evidence.verify"],
            "risk": 1,
            "minimum_authority": 1,
            "provenance": "original",
        }
    )
    assert manifest.required_tools == ("evidence.verify",)


def test_candidate_cannot_self_evaluate_or_hide_regression():
    self_rated = CandidateMetrics("c1", 700_000, 900_000, 0, True, False)
    assert not evaluate_candidate(self_rated).promote
    regressed = CandidateMetrics("c2", 700_000, 900_000, 40_000, True, True)
    assert not evaluate_candidate(regressed).promote


def test_semantic_outcome_hash_excludes_runtime_telemetry():
    first = semantic_outcome_hash(ok=True, data={"sum": 5}, error=None)
    second = semantic_outcome_hash(ok=True, data={"sum": 5}, error=None)
    assert first == second
    assert first != semantic_outcome_hash(ok=True, data={"sum": 6}, error=None)

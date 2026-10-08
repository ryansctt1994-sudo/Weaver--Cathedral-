"""Deterministic role policy and signed-approval binding."""

from __future__ import annotations

from dataclasses import dataclass

from weaver_assurance.authority import AuthorityEnvelope, VerificationResult

from .models import Decision, Proposal


@dataclass(frozen=True)
class RolePolicy:
    role: str
    allowed_tools: frozenset[str]
    max_risk: int
    approval_at_or_above: int = 1
    require_evidence: bool = True


@dataclass(frozen=True)
class ApprovalToken:
    proposal_hash: str
    envelope_id: str
    verified_keys: tuple[str, ...]
    valid_until: int

    @classmethod
    def from_verified(
        cls,
        envelope: AuthorityEnvelope,
        result: VerificationResult,
    ) -> "ApprovalToken":
        if not result.accepted:
            raise ValueError("authority verification did not accept the envelope")
        if envelope.action != "agent.execute":
            raise ValueError("authority envelope action must be agent.execute")
        proposal_hash = envelope.payload.get("proposal_hash")
        if not isinstance(proposal_hash, str) or len(proposal_hash) != 64:
            raise ValueError("authority envelope is not bound to a proposal hash")
        return cls(proposal_hash, envelope.envelope_id, result.verified_keys, envelope.valid_until)


class DeterministicGate:
    def __init__(self, policies: list[RolePolicy]) -> None:
        self.policies = {policy.role: policy for policy in policies}

    def evaluate(
        self,
        proposal: Proposal,
        *,
        approval: ApprovalToken | None = None,
        now: int,
    ) -> Decision:
        proposal_hash = proposal.hash()
        policy = self.policies.get(proposal.role)
        if policy is None:
            return Decision(False, "UNKNOWN_ROLE", proposal_hash)
        if proposal.tool not in policy.allowed_tools:
            return Decision(False, "TOOL_NOT_ALLOWED_FOR_ROLE", proposal_hash)
        if proposal.risk < 0 or proposal.risk > policy.max_risk:
            return Decision(False, "RISK_EXCEEDS_ROLE_LIMIT", proposal_hash)
        if policy.require_evidence and not proposal.evidence_refs:
            return Decision(False, "MISSING_EVIDENCE_REFERENCE", proposal_hash)

        requires_approval = proposal.risk >= policy.approval_at_or_above
        if requires_approval:
            if approval is None:
                return Decision(False, "HUMAN_APPROVAL_REQUIRED", proposal_hash, True)
            if approval.proposal_hash != proposal_hash:
                return Decision(False, "APPROVAL_NOT_BOUND_TO_PROPOSAL", proposal_hash, True)
            if now >= approval.valid_until:
                return Decision(False, "APPROVAL_EXPIRED", proposal_hash, True)

        return Decision(True, "POLICY_ACCEPTED", proposal_hash, requires_approval)


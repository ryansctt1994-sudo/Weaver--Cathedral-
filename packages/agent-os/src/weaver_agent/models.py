from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from weaver_assurance.canonical import sha256_json


@dataclass(frozen=True)
class Proposal:
    proposal_id: str
    agent_id: str
    role: str
    tool: str
    arguments: dict[str, Any]
    risk: int
    evidence_refs: tuple[str, ...] = ()

    def hash(self) -> str:
        value = asdict(self)
        value["evidence_refs"] = list(self.evidence_refs)
        return sha256_json(value)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    proposal_hash: str
    requires_approval: bool = False


@dataclass(frozen=True)
class ToolOutcome:
    ok: bool
    data: dict[str, Any]
    error: str | None
    duration_ns: int


@dataclass(frozen=True)
class RunResult:
    decision: Decision
    outcome: ToolOutcome | None = None
    receipt: dict[str, Any] | None = None


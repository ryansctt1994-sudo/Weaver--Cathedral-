"""Non-executable skill manifests."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SkillManifest:
    skill_id: str
    version: str
    description: str
    required_tools: tuple[str, ...]
    risk: int
    minimum_authority: int
    provenance: str

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "SkillManifest":
        required = {"skill_id", "version", "description", "required_tools", "risk", "minimum_authority", "provenance"}
        missing = sorted(required - value.keys())
        if missing:
            raise ValueError(f"missing skill fields: {', '.join(missing)}")
        tools = value["required_tools"]
        if not isinstance(tools, list) or not tools or not all(isinstance(item, str) and item for item in tools):
            raise ValueError("required_tools must be a non-empty list of names")
        risk = value["risk"]
        authority = value["minimum_authority"]
        if type(risk) is not int or not 0 <= risk <= 5:
            raise ValueError("risk must be an integer from 0 through 5")
        if type(authority) is not int or not 0 <= authority <= 6:
            raise ValueError("minimum_authority must be an integer from 0 through 6")
        return cls(
            skill_id=str(value["skill_id"]),
            version=str(value["version"]),
            description=str(value["description"]),
            required_tools=tuple(tools),
            risk=risk,
            minimum_authority=authority,
            provenance=str(value["provenance"]),
        )


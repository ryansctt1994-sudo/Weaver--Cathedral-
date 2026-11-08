"""A fail-closed Claude Code PreToolUse hook backed by ``core.authority.UncertaintyGate`` (GAP-003)."""

from .policy import GateConfig, GateConfigError, Match, load_config

__all__ = ["GateConfig", "GateConfigError", "Match", "load_config"]

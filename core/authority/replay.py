"""Replay cache primitives.

Phase 1 uses an in-memory replay cache. The open gap ledger still blocks
production claims until persistent, atomic, multi-process storage exists.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class InMemoryReplayCache:
    """Simple nonce replay cache for tests and local demos."""

    seen: set[str] = field(default_factory=set)

    def check_and_store(self, nonce: str) -> bool:
        """Return True if nonce is new and store it. Return False on replay."""

        if nonce in self.seen:
            return False
        self.seen.add(nonce)
        return True

    def contains(self, nonce: str) -> bool:
        return nonce in self.seen

    def clear(self) -> None:
        self.seen.clear()

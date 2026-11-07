"""Replay-protection stores.

A store answers one question atomically: "is this nonce new? if so, remember
it." Two implementations:

``InMemoryReplayCache``
    For tests and one-shot demos. Forgets everything on restart, and two
    processes each have their own, so it does **not** stop a replay across
    processes or restarts.

``SqliteReplayStore``
    Persistent and atomic across processes and restarts on one host. The
    nonce is the table's primary key, so of any number of concurrent inserts
    of the same nonce exactly one succeeds. SQLite serializes the writes.

Bounds: one host (SQLite file locking is not safe on network filesystems), no
expiry. The store keeps every nonce it has seen; pruning is left to an
explicit retention policy (see GAP-002).
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol, runtime_checkable


class ReplayStoreError(RuntimeError):
    """The store could not answer. Callers must treat this as a rejection."""


@runtime_checkable
class ReplayStore(Protocol):
    def check_and_store(self, nonce: str) -> bool:
        """Return True if nonce is new (and record it); False if already seen."""

    def contains(self, nonce: str) -> bool: ...


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


class SqliteReplayStore:
    """Persistent, multi-process nonce store backed by one SQLite file."""

    def __init__(self, path: str | Path, *, timeout_s: float = 10.0):
        self.path = Path(path)
        self.timeout_s = timeout_s
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ReplayStoreError(f"cannot create directory for replay store {self.path}: {exc}") from exc
        conn = self._connect()
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS nonces ("
                " nonce TEXT PRIMARY KEY NOT NULL,"
                " first_seen TEXT NOT NULL"
                ") WITHOUT ROWID"
            )
        except sqlite3.Error as exc:
            raise ReplayStoreError(f"cannot initialise replay store {self.path}: {exc}") from exc
        finally:
            conn.close()

    def _connect(self) -> sqlite3.Connection:
        # A fresh connection per call keeps the store safe to use from
        # threads and from processes created after construction.
        try:
            return sqlite3.connect(self.path, timeout=self.timeout_s, isolation_level=None)
        except sqlite3.Error as exc:
            raise ReplayStoreError(f"cannot open replay store {self.path}: {exc}") from exc

    def check_and_store(self, nonce: str) -> bool:
        if not isinstance(nonce, str) or not nonce:
            raise ReplayStoreError("nonce must be a non-empty string")
        now = datetime.now(timezone.utc).isoformat()
        conn = self._connect()
        try:
            conn.execute("INSERT INTO nonces (nonce, first_seen) VALUES (?, ?)", (nonce, now))
            return True
        except sqlite3.IntegrityError:
            return False
        except sqlite3.Error as exc:
            raise ReplayStoreError(f"replay store {self.path} failed: {exc}") from exc
        finally:
            conn.close()

    def contains(self, nonce: str) -> bool:
        conn = self._connect()
        try:
            return conn.execute("SELECT 1 FROM nonces WHERE nonce = ?", (nonce,)).fetchone() is not None
        except sqlite3.Error as exc:
            raise ReplayStoreError(f"replay store {self.path} failed: {exc}") from exc
        finally:
            conn.close()

    def __len__(self) -> int:
        conn = self._connect()
        try:
            return conn.execute("SELECT COUNT(*) FROM nonces").fetchone()[0]
        finally:
            conn.close()

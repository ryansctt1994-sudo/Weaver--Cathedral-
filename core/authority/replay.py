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

Retention (GAP-002)
-------------------
A nonce may be forgotten only once the message it protects can no longer be
accepted anyway. So the caller that knows that moment passes it as
``expires_at``, and ``prune_expired(now)`` removes only nonces whose
``expires_at`` is strictly before ``now``. A nonce stored without
``expires_at`` is kept forever: envelope nonces have no expiry, so pruning one
would reopen its replay. The gate stores each override nonce with the moment
after which that override is refused as expired (see ``gate.py``).

``now`` and ``expires_at`` must come from the same clock the gate uses for its
expiry check; the store does not read a clock for this.

Bounds: one host (SQLite file locking is not safe on network filesystems).
Pruning is explicit: nothing runs it on a schedule.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol, runtime_checkable

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class ReplayStoreError(RuntimeError):
    """The store could not answer. Callers must treat this as a rejection."""


def _micros(value: datetime, name: str) -> int:
    """Exact integer microseconds since the epoch for an aware datetime."""
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ReplayStoreError(f"{name} must be a timezone-aware datetime")
    delta = value.astimezone(timezone.utc) - _EPOCH
    return (delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds


@runtime_checkable
class ReplayStore(Protocol):
    def check_and_store(self, nonce: str, *, expires_at: datetime | None = None) -> bool:
        """Return True if nonce is new (and record it); False if already seen."""

    def contains(self, nonce: str) -> bool: ...


@dataclass
class InMemoryReplayCache:
    """Simple nonce replay cache for tests and local demos."""

    seen: set[str] = field(default_factory=set)
    expiry: dict[str, int] = field(default_factory=dict)

    def check_and_store(self, nonce: str, *, expires_at: datetime | None = None) -> bool:
        """Return True if nonce is new and store it. Return False on replay."""

        if nonce in self.seen:
            return False
        if expires_at is not None:
            self.expiry[nonce] = _micros(expires_at, "expires_at")
        self.seen.add(nonce)
        return True

    def contains(self, nonce: str) -> bool:
        return nonce in self.seen

    def prune_expired(self, now: datetime) -> int:
        cutoff = _micros(now, "now")
        expired = [nonce for nonce, at in self.expiry.items() if at < cutoff]
        for nonce in expired:
            self.seen.discard(nonce)
            del self.expiry[nonce]
        return len(expired)

    def clear(self) -> None:
        self.seen.clear()
        self.expiry.clear()


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
                " first_seen TEXT NOT NULL,"
                " expires_at_us INTEGER"
                ") WITHOUT ROWID"
            )
            # Stores created before retention existed lack the column. Their
            # nonces get NULL, which means "keep forever".
            columns = {row[1] for row in conn.execute("PRAGMA table_info(nonces)")}
            if "expires_at_us" not in columns:
                conn.execute("ALTER TABLE nonces ADD COLUMN expires_at_us INTEGER")
        except sqlite3.Error as exc:
            raise ReplayStoreError(f"cannot initialise replay store {self.path}: {exc}") from exc
        finally:
            conn.close()

    def _connect(self) -> sqlite3.Connection:
        # A fresh connection per call lets the store be used from threads
        # and from processes created after construction.
        try:
            return sqlite3.connect(self.path, timeout=self.timeout_s, isolation_level=None)
        except sqlite3.Error as exc:
            raise ReplayStoreError(f"cannot open replay store {self.path}: {exc}") from exc

    def check_and_store(self, nonce: str, *, expires_at: datetime | None = None) -> bool:
        if not isinstance(nonce, str) or not nonce:
            raise ReplayStoreError("nonce must be a non-empty string")
        expiry = None if expires_at is None else _micros(expires_at, "expires_at")
        now = datetime.now(timezone.utc).isoformat()
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO nonces (nonce, first_seen, expires_at_us) VALUES (?, ?, ?)",
                (nonce, now, expiry),
            )
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

    def prune_expired(self, now: datetime) -> int:
        """Delete nonces whose expiry is strictly before ``now``. Returns how many.

        Nonces stored without an expiry are never deleted.
        """
        cutoff = _micros(now, "now")
        conn = self._connect()
        try:
            cursor = conn.execute(
                "DELETE FROM nonces WHERE expires_at_us IS NOT NULL AND expires_at_us < ?",
                (cutoff,),
            )
            return cursor.rowcount
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

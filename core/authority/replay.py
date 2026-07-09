"""Replay cache primitives.

Phase 1 introduced an in-memory replay cache for local tests. The E3 path adds
an optional SQLite-backed cache that can be bundled with demo receipts and
replayed from repository materials.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _record_hash(record: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(record).encode("utf-8")).hexdigest()


@dataclass
class InMemoryReplayCache:
    """Simple nonce replay cache for tests and local demos."""

    seen: set[str] = field(default_factory=set)

    def check_and_store(
        self,
        nonce: str,
        *,
        payload_hash: str | None = None,
        envelope_id: str | None = None,
    ) -> bool:
        """Return True if nonce is new and store it. Return False on replay.

        ``payload_hash`` and ``envelope_id`` are accepted for interface
        compatibility with ``PersistentReplayCache``.
        """

        if nonce in self.seen:
            return False
        self.seen.add(nonce)
        return True

    def contains(self, nonce: str) -> bool:
        return nonce in self.seen

    def clear(self) -> None:
        self.seen.clear()


class PersistentReplayCache:
    """SQLite-backed nonce replay cache.

    This is intended for reproducible demo bundles, not production authority.
    It records enough metadata to prove that a nonce was accepted exactly once
    within a local replay database.
    """

    def __init__(self, db_path: str | Path = "forge/receipts/replay.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self) -> None:
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS replay_log (
                nonce TEXT PRIMARY KEY,
                envelope_id TEXT,
                payload_hash TEXT,
                created_at TEXT NOT NULL,
                record_hash TEXT NOT NULL
            )
            """
        )
        self.conn.commit()

    def check_and_store(
        self,
        nonce: str,
        *,
        payload_hash: str | None = None,
        envelope_id: str | None = None,
    ) -> bool:
        """Store a nonce if new. Return False when replay is detected."""

        created_at = _utc_now()
        base = {
            "nonce": nonce,
            "envelope_id": envelope_id,
            "payload_hash": payload_hash,
            "created_at": created_at,
        }
        record_hash = _record_hash(base)

        try:
            with self.conn:
                self.conn.execute(
                    """
                    INSERT INTO replay_log (nonce, envelope_id, payload_hash, created_at, record_hash)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (nonce, envelope_id, payload_hash, created_at, record_hash),
                )
        except sqlite3.IntegrityError:
            return False
        return True

    def contains(self, nonce: str) -> bool:
        cursor = self.conn.execute("SELECT 1 FROM replay_log WHERE nonce = ?", (nonce,))
        return cursor.fetchone() is not None

    def records(self) -> list[dict[str, Any]]:
        cursor = self.conn.execute(
            """
            SELECT nonce, envelope_id, payload_hash, created_at, record_hash
            FROM replay_log
            ORDER BY created_at, nonce
            """
        )
        return [dict(row) for row in cursor.fetchall()]

    def export_jsonl(self, path: str | Path) -> Path:
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("w", encoding="utf-8") as handle:
            for record in self.records():
                handle.write(_canonical_json(record) + "\n")
        return output

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "PersistentReplayCache":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

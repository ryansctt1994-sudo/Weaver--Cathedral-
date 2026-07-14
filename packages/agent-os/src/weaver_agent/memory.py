"""Local evidence memory with explicit trust state."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


class EvidenceMemory:
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS memories (
                    memory_id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    content TEXT NOT NULL,
                    receipt_hash TEXT NOT NULL,
                    verified INTEGER NOT NULL CHECK(verified IN (0,1)),
                    created_at INTEGER NOT NULL
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def put(
        self,
        *,
        memory_id: str,
        kind: str,
        content: dict[str, Any],
        receipt_hash: str,
        verified: bool,
        created_at: int,
    ) -> None:
        if not receipt_hash:
            raise ValueError("memory requires a receipt hash")
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO memories VALUES (?, ?, ?, ?, ?, ?)",
                (memory_id, kind, json.dumps(content, sort_keys=True), receipt_hash, int(verified), int(created_at)),
            )

    def search(self, query: str, *, verified_only: bool = True, limit: int = 20) -> list[dict[str, Any]]:
        pattern = f"%{query.lower()}%"
        where = "lower(content) LIKE ?"
        parameters: list[Any] = [pattern]
        if verified_only:
            where += " AND verified = 1"
        parameters.append(int(limit))
        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT * FROM memories WHERE {where} ORDER BY created_at DESC LIMIT ?",  # noqa: S608
                parameters,
            ).fetchall()
        return [
            {
                "memory_id": row["memory_id"],
                "kind": row["kind"],
                "content": json.loads(row["content"]),
                "receipt_hash": row["receipt_hash"],
                "verified": bool(row["verified"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]


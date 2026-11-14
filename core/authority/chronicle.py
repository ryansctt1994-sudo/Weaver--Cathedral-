"""Append-only, hash-chained event log (the Chronicle).

Rebuilt from Delta-717's ``ForensicLedger`` design, fixing its defects:

* Delta's ledger crashed on first start (``_create_block`` read ``self.chain``
  before it existed). Here a missing file simply means an empty chronicle.
* Delta hashed with ``datetime.now()`` inside the block and never checked the
  chain. Here every entry hash is recomputed and every link is checked on
  load, and the timestamp is supplied by the caller, so tests are deterministic.
* Delta used the default ``json.dumps`` separators (a third serialization,
  see GAP-013). Entries here name their hash profile, and new entries use RFC
  8785 JCS.

Each entry commits to the previous entry's hash. Editing, deleting,
reordering or inserting any entry breaks verification at that index. Cutting
entries off the *end* cannot be detected from the file alone: compare
``head_hash`` against a value you recorded elsewhere (``expected_head``).

Bounds: single writer, local file. No multi-process locking, no signatures.
"""

from __future__ import annotations

import copy
import json
import math
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .canonical import DEFAULT_PROFILE, PROFILES, CanonicalizationError, profiled_sha256

GENESIS_PREV_HASH = "0" * 64
ENTRY_VERSION = "weaver.chronicle.entry.v1"
_FIELDS = ("entry_version", "index", "prev_hash", "recorded_at", "kind", "data", "hash_profile", "entry_hash")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    parsed: dict[str, Any] = {}
    for key, value in pairs:
        if key in parsed:
            raise ValueError(f"duplicate Chronicle JSON key: {key}")
        parsed[key] = value
    return parsed


def _reject_constant(value: str) -> None:
    raise ValueError(f"nonstandard Chronicle JSON constant: {value}")


def _finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("nonfinite Chronicle JSON exponent")
    return number


def _strict_json_entry(line: str) -> Any:
    return json.loads(
        line, object_pairs_hook=_unique_keys,
        parse_constant=_reject_constant, parse_float=_finite_float,
    )


class ChronicleError(RuntimeError):
    """The chronicle is corrupt or an append would make it so."""


@dataclass(frozen=True)
class ChronicleVerification:
    ok: bool
    entries: int
    head_hash: str
    first_bad_index: int | None = None
    reason: str = "ok"


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ChronicleError("recorded_at must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat()


def _entry_hash(entry: dict[str, Any]) -> str:
    body = {k: entry[k] for k in _FIELDS if k != "entry_hash"}
    return profiled_sha256(body, entry["hash_profile"])


def verify_entries(entries: Iterable[dict[str, Any]], expected_head: str | None = None) -> ChronicleVerification:
    """Check every entry hash and every link. Stops at the first defect."""
    prev = GENESIS_PREV_HASH
    count = 0
    for position, entry in enumerate(entries):
        def bad(reason: str) -> ChronicleVerification:
            return ChronicleVerification(False, position, prev, position, reason)

        if not isinstance(entry, dict) or set(entry) != set(_FIELDS):
            return bad("malformed_entry")
        if type(entry["entry_version"]) is not str or entry["entry_version"] != ENTRY_VERSION:
            return bad("unknown_entry_version")
        if type(entry["hash_profile"]) is not str or entry["hash_profile"] not in PROFILES:
            return bad("unknown_hash_profile")
        if type(entry["index"]) is not int or entry["index"] != position:
            return bad("index_out_of_sequence")
        if type(entry["prev_hash"]) is not str or _SHA256.fullmatch(entry["prev_hash"]) is None:
            return bad("malformed_predecessor_hash")
        if type(entry["entry_hash"]) is not str or _SHA256.fullmatch(entry["entry_hash"]) is None:
            return bad("malformed_entry_hash")
        if type(entry["recorded_at"]) is not str or not entry["recorded_at"]:
            return bad("malformed_recorded_at")
        if type(entry["kind"]) is not str or not entry["kind"]:
            return bad("malformed_kind")
        if not isinstance(entry["data"], dict):
            return bad("malformed_data")
        if entry["prev_hash"] != prev:
            return bad("broken_link")
        try:
            recomputed = _entry_hash(entry)
        except (CanonicalizationError, TypeError, ValueError, OverflowError):
            return bad("not_canonicalizable")
        if recomputed != entry["entry_hash"]:
            return bad("entry_hash_mismatch")
        prev = entry["entry_hash"]
        count = position + 1

    if expected_head is not None and prev != expected_head:
        return ChronicleVerification(False, count, prev, count, "head_mismatch")
    return ChronicleVerification(True, count, prev)


class Chronicle:
    """A chronicle in memory, optionally backed by a JSON Lines file."""

    def __init__(self, path: str | Path | None = None, *, hash_profile: str = DEFAULT_PROFILE):
        if type(hash_profile) is not str or hash_profile not in PROFILES:
            raise ChronicleError(f"unknown hash profile {hash_profile!r}")
        self.path = Path(path) if path is not None else None
        self.hash_profile = hash_profile
        self._entries: list[dict[str, Any]] = []
        if self.path is not None and self.path.exists():
            self._entries = self._load(self.path)

    @staticmethod
    def _load(path: Path) -> list[dict[str, Any]]:
        entries = []
        with path.open(encoding="utf-8") as handle:
            for lineno, line in enumerate(handle, 1):
                if not line.strip():
                    raise ChronicleError(f"{path}:{lineno}: blank line in chronicle")
                try:
                    entries.append(_strict_json_entry(line))
                except (json.JSONDecodeError, ValueError, TypeError, OverflowError) as exc:
                    raise ChronicleError(f"{path}:{lineno}: invalid JSON ({exc})") from exc
        result = verify_entries(entries)
        if not result.ok:
            raise ChronicleError(f"{path}: chronicle fails verification at index {result.first_bad_index}: {result.reason}")
        return entries

    @property
    def entries(self) -> list[dict[str, Any]]:
        # Deep copies: callers must not be able to edit the live chain.
        return copy.deepcopy(self._entries)

    @property
    def head_hash(self) -> str:
        return self._entries[-1]["entry_hash"] if self._entries else GENESIS_PREV_HASH

    def __len__(self) -> int:
        return len(self._entries)

    def append(self, kind: str, data: dict[str, Any], *, recorded_at: datetime) -> dict[str, Any]:
        if not isinstance(kind, str) or not kind:
            raise ChronicleError("kind must be non-empty")
        if not isinstance(data, dict):
            raise ChronicleError("data must be a JSON object")
        entry: dict[str, Any] = {
            "entry_version": ENTRY_VERSION,
            "index": len(self._entries),
            "prev_hash": self.head_hash,
            "recorded_at": _timestamp(recorded_at),
            "kind": kind,
            "data": data,
            "hash_profile": self.hash_profile,
        }
        try:
            entry["entry_hash"] = _entry_hash(entry)
        except CanonicalizationError as exc:
            raise ChronicleError(f"entry data is not canonicalizable: {exc}") from exc
        # Round-trip through JSON so the in-memory entry equals what a reload
        # would read (e.g. tuples become lists), and re-verify before writing.
        line = json.dumps(entry, ensure_ascii=False, sort_keys=True)
        stored = json.loads(line)
        if _entry_hash(stored) != entry["entry_hash"]:
            raise ChronicleError("entry does not survive a JSON round-trip unchanged")
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        self._entries.append(stored)
        return copy.deepcopy(stored)

    def verify(self, expected_head: str | None = None) -> ChronicleVerification:
        return verify_entries(self._entries, expected_head)


def verify_file(path: str | Path, expected_head: str | None = None) -> ChronicleVerification:
    """Verify a chronicle file without raising. Fails closed on any defect."""
    entries = []
    try:
        with Path(path).open(encoding="utf-8") as handle:
            for line in handle:
                entries.append(_strict_json_entry(line))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError, ValueError, TypeError, OverflowError) as exc:
        return ChronicleVerification(False, len(entries), GENESIS_PREV_HASH, len(entries), f"unreadable: {type(exc).__name__}")
    return verify_entries(entries, expected_head)

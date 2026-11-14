"""Adversarial Chronicle intake checks on the dependent strict gate branch.

These tests preserve healthy hash vectors while rejecting ambiguity that can
otherwise be hidden by a recomputed, locally controlled SHA-256 hash chain.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from core.authority.chronicle import (
    Chronicle,
    ChronicleError,
    _entry_hash,
    verify_entries,
    verify_file,
)

T0 = datetime(2026, 11, 8, tzinfo=timezone.utc)


def _entry():
    ledger = Chronicle()
    return ledger.append("research.veto", {"decision": "VETO"}, recorded_at=T0)


@pytest.mark.parametrize(
    ("field", "bad_value", "reason"),
    [
        ("index", False, "index_out_of_sequence"),
        ("index", 0.0, "index_out_of_sequence"),
        ("kind", True, "malformed_kind"),
        ("recorded_at", True, "malformed_recorded_at"),
        ("data", ["VETO"], "malformed_data"),
        ("hash_profile", [], "unknown_hash_profile"),
        ("prev_hash", [], "malformed_predecessor_hash"),
        ("entry_hash", [], "malformed_entry_hash"),
    ],
)
def test_malformed_rehashed_fields_fail_without_exceptions(field, bad_value, reason):
    event = _entry()
    event[field] = bad_value
    if field not in ("hash_profile", "prev_hash", "entry_hash"):
        event["entry_hash"] = _entry_hash(event)
    result = verify_entries([event])
    assert result.ok is False
    assert result.reason == reason
    assert result.first_bad_index == 0


def test_duplicate_json_field_rejected_before_hash_validation(tmp_path):
    path = tmp_path / "chronicle.jsonl"
    Chronicle(path).append("research.veto", {"decision": "VETO"}, recorded_at=T0)
    original = path.read_text(encoding="utf-8")
    assert '"index": 0' in original
    path.write_text(original.replace('"index": 0', '"index": 0, "index": 0', 1), encoding="utf-8")
    with pytest.raises(ChronicleError, match="duplicate Chronicle JSON key"):
        Chronicle(path)
    assert not verify_file(path).ok
    assert path.read_text(encoding="utf-8").count('"index"') == 2


@pytest.mark.parametrize("token", ["NaN", "Infinity", "-Infinity", "1e9999"])
def test_nonfinite_file_json_rejected_before_load(tmp_path, token):
    path = tmp_path / "chronicle.jsonl"
    Chronicle(path).append("research.veto", {"sample": 1.0}, recorded_at=T0)
    source = path.read_text(encoding="utf-8")
    assert '"sample": 1.0' in source
    path.write_text(source.replace('"sample": 1.0', '"sample": ' + token), encoding="utf-8")
    with pytest.raises(ChronicleError):
        Chronicle(path)
    assert not verify_file(path).ok


def test_valid_historical_entry_roundtrips_unchanged(tmp_path):
    path = tmp_path / "chronicle.jsonl"
    ledger = Chronicle(path)
    source = ledger.append("research.veto", {"decision": "VETO"}, recorded_at=T0)
    saved = path.read_bytes()
    reopened = Chronicle(path)
    assert reopened.head_hash == ledger.head_hash
    assert reopened.entries == [source]
    assert verify_file(path).ok
    assert path.read_bytes() == saved


def test_invalid_in_memory_append_cannot_create_a_file(tmp_path):
    path = tmp_path / "chronicle.jsonl"
    ledger = Chronicle(path)
    for kind, data in ((123, {}), ("good", []), (True, {})):
        with pytest.raises(ChronicleError):
            ledger.append(kind, data, recorded_at=T0)
    assert not path.exists()
    assert len(ledger) == 0

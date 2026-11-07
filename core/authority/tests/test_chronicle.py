"""Tamper-evidence tests for the Chronicle."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from core.authority.canonical import JCS_RFC8785, WEAVER_C14N_V1
from core.authority.chronicle import (
    GENESIS_PREV_HASH,
    Chronicle,
    ChronicleError,
    verify_entries,
    verify_file,
)

T0 = datetime(2026, 11, 7, tzinfo=timezone.utc)


def build(n: int = 5, path: Path | None = None) -> Chronicle:
    chron = Chronicle(path)
    for i in range(n):
        chron.append("test.event", {"i": i, "note": f"event {i}"}, recorded_at=T0 + timedelta(seconds=i))
    return chron


def test_fresh_chronicle_starts_empty_without_crashing(tmp_path):
    # Delta-717's ForensicLedger raised AttributeError here.
    chron = Chronicle(tmp_path / "chronicle.jsonl")
    assert len(chron) == 0
    assert chron.head_hash == GENESIS_PREV_HASH
    assert chron.verify().ok


def test_entries_link_and_verify():
    chron = build()
    entries = chron.entries
    assert entries[0]["prev_hash"] == GENESIS_PREV_HASH
    assert all(entries[i]["prev_hash"] == entries[i - 1]["entry_hash"] for i in range(1, len(entries)))
    assert all(e["hash_profile"] == JCS_RFC8785 for e in entries)
    result = chron.verify()
    assert result.ok and result.entries == 5 and result.head_hash == chron.head_hash


def test_golden_first_entry_hash():
    chron = Chronicle()
    entry = chron.append("test.event", {"i": 0}, recorded_at=T0)
    assert entry["entry_hash"] == "e8bafe8330d6318afb413bb9183ffa6af0950e970cf7d3df69598844d3b623a1"


def test_persists_and_reloads(tmp_path):
    path = tmp_path / "c.jsonl"
    head = build(path=path).head_hash
    reloaded = Chronicle(path)
    assert len(reloaded) == 5 and reloaded.head_hash == head
    reloaded.append("test.event", {"i": 5}, recorded_at=T0 + timedelta(seconds=5))
    assert verify_file(path).entries == 6


@pytest.mark.parametrize(
    ("mutate", "bad_index", "reason"),
    [
        (lambda es: es[2]["data"].update(note="edited"), 2, "entry_hash_mismatch"),
        (lambda es: es[2].update(recorded_at=T0.isoformat()), 2, "entry_hash_mismatch"),
        (lambda es: es[2].update(kind="other.event"), 2, "entry_hash_mismatch"),
        (lambda es: es.pop(2), 2, "index_out_of_sequence"),
        (lambda es: es.insert(1, dict(es[3])), 1, "index_out_of_sequence"),
        (lambda es: es.__setitem__(slice(1, 3), [es[2], es[1]]), 1, "index_out_of_sequence"),
        (lambda es: es[0].update(prev_hash="f" * 64), 0, "broken_link"),
        (lambda es: es[3].update(hash_profile="made.up.v9"), 3, "unknown_hash_profile"),
        (lambda es: es[1].pop("kind"), 1, "malformed_entry"),
        (lambda es: es[1].update(extra=1), 1, "malformed_entry"),
    ],
    ids=["edit-data", "edit-time", "edit-kind", "delete", "insert", "reorder", "relink-genesis",
         "unknown-profile", "missing-field", "extra-field"],
)
def test_tampering_is_detected_at_the_tampered_index(mutate, bad_index, reason):
    entries = build().entries
    mutate(entries)
    result = verify_entries(entries)
    assert not result.ok
    assert result.first_bad_index == bad_index
    assert result.reason == reason


def test_rehashing_an_edited_entry_still_breaks_the_next_link():
    from core.authority.chronicle import _entry_hash

    entries = build().entries
    entries[2]["data"]["note"] = "edited"
    entries[2]["entry_hash"] = _entry_hash(entries[2])  # attacker recomputes this entry's hash
    result = verify_entries(entries)
    assert not result.ok and result.first_bad_index == 3 and result.reason == "broken_link"


def test_tail_truncation_needs_an_anchored_head():
    chron = build()
    anchored_head = chron.head_hash
    truncated = chron.entries[:3]
    assert verify_entries(truncated).ok  # undetectable from the file alone, as documented
    result = verify_entries(truncated, expected_head=anchored_head)
    assert not result.ok and result.reason == "head_mismatch"


def test_tampered_file_refuses_to_load(tmp_path):
    path = tmp_path / "c.jsonl"
    build(path=path)
    lines = path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[1])
    entry["data"]["note"] = "edited"
    lines[1] = json.dumps(entry)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(ChronicleError, match="index 1: entry_hash_mismatch"):
        Chronicle(path)
    assert not verify_file(path).ok


@pytest.mark.parametrize("content", ["not json\n", "\n", '{"index": 0}\n'])
def test_garbage_file_refuses_to_load(tmp_path, content):
    path = tmp_path / "c.jsonl"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ChronicleError):
        Chronicle(path)
    assert not verify_file(path).ok


def test_missing_file_verifies_as_unreadable(tmp_path):
    result = verify_file(tmp_path / "absent.jsonl")
    assert not result.ok and result.reason.startswith("unreadable")


def test_naive_timestamp_and_unhashable_data_are_refused_without_writing(tmp_path):
    path = tmp_path / "c.jsonl"
    chron = Chronicle(path)
    with pytest.raises(ChronicleError):
        chron.append("x", {}, recorded_at=datetime(2026, 11, 7))
    with pytest.raises(ChronicleError):
        chron.append("x", {"n": float("nan")}, recorded_at=T0)
    with pytest.raises(ChronicleError):
        chron.append("", {}, recorded_at=T0)
    assert len(chron) == 0 and not path.exists()


def test_legacy_profile_chronicles_still_verify():
    chron = Chronicle(hash_profile=WEAVER_C14N_V1)
    chron.append("x", {"i": 1}, recorded_at=T0)
    assert chron.entries[0]["hash_profile"] == WEAVER_C14N_V1 and chron.verify().ok


@settings(max_examples=100, deadline=None)
@given(
    st.lists(st.dictionaries(st.text(max_size=5), st.integers(-1000, 1000) | st.text(max_size=8), max_size=3), min_size=2, max_size=6),
    st.data(),
)
def test_any_single_value_edit_is_detected(payloads, data):
    chron = Chronicle()
    for i, payload in enumerate(payloads):
        chron.append("prop", payload, recorded_at=T0 + timedelta(seconds=i))
    entries = chron.entries
    target = data.draw(st.integers(0, len(entries) - 1))
    entries[target]["data"] = {**entries[target]["data"], "__tamper__": True}
    result = verify_entries(entries)
    assert not result.ok and result.first_bad_index == target


def test_returned_entries_cannot_edit_the_live_chain():
    chron = build(3)
    head = chron.head_hash
    chron.entries[1]["data"]["note"] = "edited through a returned copy"
    returned = chron.append("test.event", {"nested": {"k": 1}}, recorded_at=T0 + timedelta(seconds=9))
    returned["data"]["nested"]["k"] = 2
    assert chron.verify().ok
    assert chron.entries[1]["data"]["note"] == "event 1"
    assert chron.entries[-1]["data"]["nested"]["k"] == 1
    assert chron.entries[-2]["entry_hash"] == head

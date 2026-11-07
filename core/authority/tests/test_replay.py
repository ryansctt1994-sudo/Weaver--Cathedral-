from core.authority.replay import InMemoryReplayCache


def test_replay_cache_accepts_first_nonce_and_rejects_second():
    cache = InMemoryReplayCache()
    assert cache.check_and_store("nonce-123456")
    assert not cache.check_and_store("nonce-123456")
    assert cache.contains("nonce-123456")


def test_replay_cache_can_clear():
    cache = InMemoryReplayCache()
    cache.check_and_store("nonce-abcdef")
    cache.clear()
    assert cache.check_and_store("nonce-abcdef")


# --- Persistent store (GAP-002) -------------------------------------------------

import json
import multiprocessing as mp
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from core.authority.replay import ReplayStore, ReplayStoreError, SqliteReplayStore
from core.authority.verifier import verify_envelope

NONCES = [f"race-nonce-{i:03d}" for i in range(50)]


def _race_worker(db_path, use_sqlite, barrier, results):
    store = SqliteReplayStore(db_path) if use_sqlite else InMemoryReplayCache()
    barrier.wait()  # release every process at once
    results.put([nonce for nonce in NONCES if store.check_and_store(nonce)])


def _race(tmp_path: Path, use_sqlite: bool, workers: int = 8) -> list[list[str]]:
    ctx = mp.get_context("spawn")
    db = tmp_path / "replay.sqlite"
    if use_sqlite:
        SqliteReplayStore(db)  # create the schema before the race
    barrier, results = ctx.Barrier(workers), ctx.Queue()
    procs = [ctx.Process(target=_race_worker, args=(db, use_sqlite, barrier, results)) for _ in range(workers)]
    for p in procs:
        p.start()
    won = [results.get(timeout=60) for _ in procs]
    for p in procs:
        p.join(timeout=60)
        assert p.exitcode == 0
    return won


def test_sqlite_store_satisfies_the_protocol(tmp_path):
    assert isinstance(SqliteReplayStore(tmp_path / "r.sqlite"), ReplayStore)
    assert isinstance(InMemoryReplayCache(), ReplayStore)


def test_sqlite_store_rejects_second_use(tmp_path):
    store = SqliteReplayStore(tmp_path / "r.sqlite")
    assert store.check_and_store("nonce-123456")
    assert not store.check_and_store("nonce-123456")
    assert store.contains("nonce-123456") and not store.contains("nonce-other")


def test_sqlite_store_survives_restart(tmp_path):
    db = tmp_path / "r.sqlite"
    SqliteReplayStore(db).check_and_store("nonce-123456")
    reopened = SqliteReplayStore(db)
    assert not reopened.check_and_store("nonce-123456")
    assert len(reopened) == 1


def test_concurrent_processes_each_nonce_is_won_exactly_once(tmp_path):
    won = _race(tmp_path, use_sqlite=True)
    flat = [nonce for batch in won for nonce in batch]
    assert sorted(flat) == sorted(NONCES), "every nonce accepted exactly once across all processes"


def test_in_memory_cache_does_not_protect_across_processes(tmp_path):
    # Why GAP-002 mattered: separate processes each accept every nonce.
    won = _race(tmp_path, use_sqlite=False, workers=3)
    assert all(sorted(batch) == sorted(NONCES) for batch in won)


def test_unopenable_store_raises_store_error(tmp_path):
    db = tmp_path / "r.sqlite"
    db.write_bytes(b"this is not a sqlite database" * 100)
    with pytest.raises(ReplayStoreError):
        SqliteReplayStore(db)
    blocker = tmp_path / "file"
    blocker.write_text("x")
    with pytest.raises(ReplayStoreError):
        SqliteReplayStore(blocker / "sub" / "r.sqlite")


@pytest.mark.parametrize("nonce", ["", None, 123])
def test_invalid_nonce_raises_store_error(tmp_path, nonce):
    with pytest.raises(ReplayStoreError):
        SqliteReplayStore(tmp_path / "r.sqlite").check_and_store(nonce)


def _valid_envelope() -> dict:
    return json.loads(Path("core/authority/fixtures/valid_envelope.json").read_text())


def test_verifier_rejects_replay_across_store_instances(tmp_path):
    db = tmp_path / "r.sqlite"
    assert verify_envelope(_valid_envelope(), SqliteReplayStore(db)).accepted
    second = verify_envelope(_valid_envelope(), SqliteReplayStore(db))
    assert not second.accepted and second.reason == "replay_detected"


def test_verifier_fails_closed_when_store_errors():
    class BrokenStore:
        def check_and_store(self, nonce, *, expires_at=None):
            raise ReplayStoreError("disk gone")

        def contains(self, nonce):
            raise ReplayStoreError("disk gone")

    result = verify_envelope(_valid_envelope(), BrokenStore())
    assert not result.accepted and result.reason == "replay_store_unavailable"
    assert result.receipt_hash is not None


def test_gate_override_cannot_be_replayed_after_restart(tmp_path):
    from core.authority.gate import UncertaintyGate, request_hash, sign_override

    key, now, req = b"k" * 32, datetime(2026, 11, 7, 12, tzinfo=timezone.utc), {"action": "x"}
    ov = sign_override(key, operator_id="op", reason="r", request_hash=request_hash(req), nonce="n-1", issued_at=now)
    db = tmp_path / "r.sqlite"

    first = UncertaintyGate(threshold=0.7, override_key=key, replay_cache=SqliteReplayStore(db))
    assert first.evaluate(req, 0.9, now=now, override=ov).allowed
    restarted = UncertaintyGate(threshold=0.7, override_key=key, replay_cache=SqliteReplayStore(db))
    again = restarted.evaluate(req, 0.9, now=now, override=ov)
    assert not again.allowed and again.reason == "override_rejected:replayed"


def test_gate_vetoes_when_store_errors():
    from core.authority.gate import UncertaintyGate, request_hash, sign_override

    class BrokenStore:
        def check_and_store(self, nonce, *, expires_at=None):
            raise ReplayStoreError("disk gone")

        def contains(self, nonce):
            return False

    key, now, req = b"k" * 32, datetime(2026, 11, 7, 12, tzinfo=timezone.utc), {"action": "x"}
    ov = sign_override(key, operator_id="op", reason="r", request_hash=request_hash(req), nonce="n-1", issued_at=now)
    record = UncertaintyGate(threshold=0.7, override_key=key, replay_cache=BrokenStore()).evaluate(req, 0.9, now=now, override=ov)
    assert not record.allowed and record.reason == "gate_error:ReplayStoreError"


def test_cli_verify_rejects_replay_across_invocations_with_replay_db(tmp_path):
    db = tmp_path / "r.sqlite"
    cmd = [sys.executable, "-m", "core.authority", "verify", "core/authority/fixtures/valid_envelope.json"]
    assert subprocess.run(cmd + ["--replay-db", str(db)], capture_output=True).returncode == 0
    second = subprocess.run(cmd + ["--replay-db", str(db)], capture_output=True, text=True)
    assert second.returncode == 1 and "replay_detected" in second.stdout


# --- Retention (GAP-002) --------------------------------------------------------

from datetime import timedelta  # noqa: E402

T0 = datetime(2026, 11, 7, 12, tzinfo=timezone.utc)


@pytest.mark.parametrize("make", ["memory", "sqlite"])
def test_prune_removes_only_expired_nonces(tmp_path, make):
    store = InMemoryReplayCache() if make == "memory" else SqliteReplayStore(tmp_path / "r.sqlite")
    store.check_and_store("expires-early", expires_at=T0)
    store.check_and_store("expires-late", expires_at=T0 + timedelta(hours=1))
    store.check_and_store("never-expires")  # envelope nonces: no expiry, kept forever

    assert store.prune_expired(T0) == 0  # strictly before `now` only
    assert store.prune_expired(T0 + timedelta(microseconds=1)) == 1
    assert not store.contains("expires-early")
    assert store.contains("expires-late") and store.contains("never-expires")
    assert store.prune_expired(T0 + timedelta(days=365)) == 1
    assert store.contains("never-expires")


@pytest.mark.parametrize("make", ["memory", "sqlite"])
def test_naive_datetimes_are_refused(tmp_path, make):
    store = InMemoryReplayCache() if make == "memory" else SqliteReplayStore(tmp_path / "r.sqlite")
    with pytest.raises(ReplayStoreError):
        store.check_and_store("n", expires_at=datetime(2026, 11, 7, 12))
    with pytest.raises(ReplayStoreError):
        store.prune_expired(datetime(2026, 11, 7, 12))


def _gate(db):
    from core.authority.gate import UncertaintyGate

    return UncertaintyGate(threshold=0.7, override_key=b"k" * 32, replay_cache=SqliteReplayStore(db))


def _override(nonce="n-1"):
    from core.authority.gate import request_hash, sign_override

    return sign_override(
        b"k" * 32, operator_id="op", reason="r", request_hash=request_hash({"action": "x"}),
        nonce=nonce, issued_at=T0,
    )


def test_pruning_never_reopens_an_override_replay(tmp_path):
    db = tmp_path / "r.sqlite"
    gate, ov = _gate(db), _override()
    assert gate.evaluate({"action": "x"}, 0.9, now=T0, override=ov).allowed

    # Inside the override window the nonce cannot be pruned, so a replay is "replayed".
    max_age = gate.override_max_age
    assert SqliteReplayStore(db).prune_expired(T0 + max_age) == 0
    again = _gate(db).evaluate({"action": "x"}, 0.9, now=T0 + max_age, override=ov)
    assert again.reason == "override_rejected:replayed"

    # Once the nonce is prunable, the override is already refused as expired.
    later = T0 + max_age + timedelta(microseconds=1)
    assert SqliteReplayStore(db).prune_expired(later) == 1
    after = _gate(db).evaluate({"action": "x"}, 0.9, now=later, override=ov)
    assert not after.allowed and after.reason == "override_rejected:expired"


def test_envelope_nonces_are_never_pruned(tmp_path):
    db = tmp_path / "r.sqlite"
    assert verify_envelope(_valid_envelope(), SqliteReplayStore(db)).accepted
    assert SqliteReplayStore(db).prune_expired(T0 + timedelta(days=10_000)) == 0
    second = verify_envelope(_valid_envelope(), SqliteReplayStore(db))
    assert not second.accepted and second.reason == "replay_detected"


def test_store_created_before_retention_is_migrated(tmp_path):
    import sqlite3

    db = tmp_path / "old.sqlite"
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE nonces (nonce TEXT PRIMARY KEY NOT NULL, first_seen TEXT NOT NULL) WITHOUT ROWID"
    )
    conn.execute("INSERT INTO nonces VALUES ('old-nonce', '2026-01-01T00:00:00+00:00')")
    conn.commit()
    conn.close()

    store = SqliteReplayStore(db)
    assert not store.check_and_store("old-nonce")  # still remembered
    assert store.prune_expired(T0 + timedelta(days=10_000)) == 0  # no expiry: kept
    assert store.check_and_store("new-nonce", expires_at=T0)
    assert store.prune_expired(T0 + timedelta(seconds=1)) == 1

from core.authority.replay import InMemoryReplayCache, PersistentReplayCache


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


def test_persistent_replay_cache_records_and_rejects_replay(tmp_path):
    db_path = tmp_path / "replay.db"
    cache = PersistentReplayCache(db_path)
    try:
        assert cache.check_and_store(
            "nonce-persistent-001",
            payload_hash="a" * 64,
            envelope_id="env-persistent-001",
        )
        assert not cache.check_and_store(
            "nonce-persistent-001",
            payload_hash="a" * 64,
            envelope_id="env-persistent-001",
        )
        records = cache.records()
        assert len(records) == 1
        assert records[0]["nonce"] == "nonce-persistent-001"
        assert records[0]["record_hash"]
    finally:
        cache.close()

    reopened = PersistentReplayCache(db_path)
    try:
        assert reopened.contains("nonce-persistent-001")
    finally:
        reopened.close()

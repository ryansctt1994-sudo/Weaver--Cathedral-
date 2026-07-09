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

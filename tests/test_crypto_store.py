"""Tests for MemoryCryptoStore."""


from fresholm.crypto_store import MemoryCryptoStore


class MockSession:
    """Minimal mock with a session_id() method."""

    def __init__(self, sid: str, label: str = "") -> None:
        self._sid = sid
        self.label = label

    def session_id(self) -> str:
        return self._sid


# ---------------------------------------------------------------------------
# Account
# ---------------------------------------------------------------------------


class TestAccount:
    async def test_account_roundtrip(self):
        store = MemoryCryptoStore()
        assert await store.get_account() is None
        sentinel = object()
        await store.put_account(sentinel)
        assert await store.get_account() is sentinel


# ---------------------------------------------------------------------------
# Olm sessions
# ---------------------------------------------------------------------------


class TestSessions:
    async def test_sessions_put_get(self):
        store = MemoryCryptoStore()
        s1, s2 = MockSession("a"), MockSession("b")
        await store.put_sessions("key1", [s1, s2])
        result = await store.get_sessions("key1")
        assert len(result) == 2
        assert result[0] is s1
        assert result[1] is s2

    async def test_sessions_empty(self):
        store = MemoryCryptoStore()
        assert await store.get_sessions("nonexistent") == []

    async def test_add_session(self):
        store = MemoryCryptoStore()
        s1 = MockSession("a")
        await store.add_session("key1", s1)
        result = await store.get_sessions("key1")
        assert len(result) == 1
        assert result[0] is s1

    async def test_update_session_replaces(self):
        store = MemoryCryptoStore()
        original = MockSession("a", label="original")
        await store.add_session("key1", original)
        replacement = MockSession("a", label="replacement")
        await store.update_session("key1", replacement)
        result = await store.get_sessions("key1")
        assert len(result) == 1
        assert result[0].label == "replacement"

    async def test_update_session_appends_if_new(self):
        store = MemoryCryptoStore()
        s1 = MockSession("a")
        await store.add_session("key1", s1)
        s2 = MockSession("b")
        await store.update_session("key1", s2)
        result = await store.get_sessions("key1")
        assert len(result) == 2

    async def test_delete_session(self):
        store = MemoryCryptoStore()
        s1 = MockSession("a")
        s2 = MockSession("b")
        await store.add_session("key1", s1)
        await store.add_session("key1", s2)
        await store.delete_session("key1", "a")
        result = await store.get_sessions("key1")
        assert len(result) == 1
        assert result[0].session_id() == "b"

    async def test_delete_all_sessions(self):
        store = MemoryCryptoStore()
        await store.add_session("key1", MockSession("a"))
        await store.add_session("key1", MockSession("b"))
        await store.delete_all_sessions("key1")
        assert await store.get_sessions("key1") == []


# ---------------------------------------------------------------------------
# Group sessions
# ---------------------------------------------------------------------------


class TestGroupSessions:
    async def test_group_session_roundtrip(self):
        store = MemoryCryptoStore()
        sentinel = object()
        await store.put_group_session("!room:ex", "skey", "sid1", sentinel)
        result = await store.get_group_session("!room:ex", "skey", "sid1")
        assert result is sentinel

    async def test_group_session_missing(self):
        store = MemoryCryptoStore()
        assert await store.get_group_session("!r", "k", "s") is None

    async def test_has_group_session(self):
        store = MemoryCryptoStore()
        assert not await store.has_group_session("!r", "k", "s")
        await store.put_group_session("!r", "k", "s", object())
        assert await store.has_group_session("!r", "k", "s")

"""In-memory crypto store implementation."""

from typing import Optional

from .base import BaseCryptoStore


class MemoryCryptoStore(BaseCryptoStore):
    """Non-persistent, in-memory crypto store for testing and short-lived use."""

    def __init__(self) -> None:
        self._account: Optional[object] = None
        self._sessions: dict[str, list] = {}
        self._group_sessions: dict[str, object] = {}

    async def put_account(self, account) -> None:
        self._account = account

    async def get_account(self) -> Optional[object]:
        return self._account

    async def put_sessions(self, sender_key: str, sessions: list) -> None:
        self._sessions[sender_key] = list(sessions)

    async def get_sessions(self, sender_key: str) -> list:
        return list(self._sessions.get(sender_key, []))

    async def add_session(self, sender_key: str, session) -> None:
        self._sessions.setdefault(sender_key, []).append(session)

    async def update_session(self, sender_key: str, session) -> None:
        sid = session.session_id()
        sessions = self._sessions.get(sender_key, [])
        for i, existing in enumerate(sessions):
            if existing.session_id() == sid:
                sessions[i] = session
                return
        # Not found — append as new
        self._sessions.setdefault(sender_key, []).append(session)

    async def delete_session(self, sender_key: str, session_id: str) -> None:
        sessions = self._sessions.get(sender_key, [])
        self._sessions[sender_key] = [
            s for s in sessions if s.session_id() != session_id
        ]

    async def delete_all_sessions(self, sender_key: str) -> None:
        self._sessions.pop(sender_key, None)

    async def put_group_session(
        self, room_id: str, sender_key: str, session_id: str, session
    ) -> None:
        key = f"{room_id}|{sender_key}|{session_id}"
        self._group_sessions[key] = session

    async def get_group_session(
        self, room_id: str, sender_key: str, session_id: str
    ) -> Optional[object]:
        key = f"{room_id}|{sender_key}|{session_id}"
        return self._group_sessions.get(key)

    async def has_group_session(
        self, room_id: str, sender_key: str, session_id: str
    ) -> bool:
        key = f"{room_id}|{sender_key}|{session_id}"
        return key in self._group_sessions

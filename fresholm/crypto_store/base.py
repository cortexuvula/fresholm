"""Abstract base class for crypto session stores."""

from abc import ABC, abstractmethod
from typing import Optional


class BaseCryptoStore(ABC):
    """Abstract base for persisting Olm/Megolm session state."""

    @abstractmethod
    async def put_account(self, account) -> None: ...

    @abstractmethod
    async def get_account(self) -> Optional[object]: ...

    @abstractmethod
    async def put_sessions(self, sender_key: str, sessions: list) -> None: ...

    @abstractmethod
    async def get_sessions(self, sender_key: str) -> list: ...

    @abstractmethod
    async def add_session(self, sender_key: str, session) -> None: ...

    @abstractmethod
    async def update_session(self, sender_key: str, session) -> None: ...

    @abstractmethod
    async def delete_session(self, sender_key: str, session_id: str) -> None: ...

    @abstractmethod
    async def delete_all_sessions(self, sender_key: str) -> None: ...

    @abstractmethod
    async def put_group_session(
        self, room_id: str, sender_key: str, session_id: str, session
    ) -> None: ...

    @abstractmethod
    async def get_group_session(
        self, room_id: str, sender_key: str, session_id: str
    ) -> Optional[object]: ...

    @abstractmethod
    async def has_group_session(
        self, room_id: str, sender_key: str, session_id: str
    ) -> bool: ...

"""Python-olm compatible wrappers around fresholm native (vodozemac) bindings.

This module provides drop-in replacements for python-olm classes so that
libraries like mautrix-python can use fresholm without code changes.

NOTE: The method names 'pickle' and 'from_pickle' are required by the
python-olm API that mautrix and other Matrix clients depend on. The actual
serialization uses vodozemac's encrypted string format (not Python's
pickle module). These are safe serialization methods.
"""

from __future__ import annotations

from fresholm._native import Account as _NativeAccount
from fresholm._native import EncryptedMessage as _NativeEncryptedMessage
from fresholm._native import GroupSession as _NativeGroupSession
from fresholm._native import InboundGroupSession as _NativeInboundGroupSession
from fresholm._native import Session as _NativeSession

from .types import (
    CryptoStoreError,
    OlmAccountError,
    OlmError,
    OlmGroupSessionError,
    OlmSessionError,
    _passphrase_to_bytes,
)
from .sas import Sas, OlmSasError
from . import utility
from .utility import sha256, ed25519_verify, OlmVerifyError


# ---------------------------------------------------------------------------
# Message wrappers
# ---------------------------------------------------------------------------


class OlmMessage:
    """Wrapper for a normal Olm message (message_type=1)."""

    def __init__(self, ciphertext):
        if isinstance(ciphertext, str):
            self._ciphertext = ciphertext.encode("utf-8")
        elif isinstance(ciphertext, bytes):
            self._ciphertext = ciphertext
        else:
            raise TypeError(f"ciphertext must be str or bytes, got {type(ciphertext)}")

    @property
    def ciphertext(self) -> bytes:
        return self._ciphertext

    @property
    def message_type(self) -> int:
        return 1

    def __repr__(self) -> str:
        return f"OlmMessage(ciphertext=<{len(self._ciphertext)} bytes>)"


class OlmPreKeyMessage:
    """Wrapper for a pre-key Olm message (message_type=0)."""

    def __init__(self, ciphertext):
        if isinstance(ciphertext, str):
            self._ciphertext = ciphertext.encode("utf-8")
        elif isinstance(ciphertext, bytes):
            self._ciphertext = ciphertext
        else:
            raise TypeError(f"ciphertext must be str or bytes, got {type(ciphertext)}")

    @property
    def ciphertext(self) -> bytes:
        return self._ciphertext

    @property
    def message_type(self) -> int:
        return 0

    def __repr__(self) -> str:
        return f"OlmPreKeyMessage(ciphertext=<{len(self._ciphertext)} bytes>)"


def _wrap_encrypted(native_encrypted: _NativeEncryptedMessage):
    """Convert a native EncryptedMessage to the appropriate python-olm wrapper."""
    if native_encrypted.message_type == 0:
        return OlmPreKeyMessage(native_encrypted.ciphertext)
    return OlmMessage(native_encrypted.ciphertext)


# ---------------------------------------------------------------------------
# Account wrapper
# ---------------------------------------------------------------------------


class Account:
    """Python-olm compatible Account wrapper around vodozemac Account.

    Key differences from the native API:
    - identity_keys is a property (not a method)
    - one_time_keys is a property returning {"curve25519": {id: key, ...}}
    - max_one_time_keys is a property
    - sign() accepts str or bytes
    - Serialization uses string passphrases via the native encrypted-string methods
    """

    def __init__(self):
        self._native = _NativeAccount()

    @property
    def identity_keys(self) -> dict:
        """Return identity keys dict with 'ed25519' and 'curve25519' entries."""
        return self._native.identity_keys()

    @property
    def one_time_keys(self) -> dict:
        """Return one-time keys in python-olm format: {"curve25519": {id: key, ...}}."""
        raw = self._native.one_time_keys()
        return {"curve25519": raw}

    @property
    def max_one_time_keys(self) -> int:
        """Return the maximum number of one-time keys the account can hold."""
        return self._native.max_number_of_one_time_keys()

    def generate_one_time_keys(self, count: int) -> None:
        """Generate the given number of one-time keys."""
        self._native.generate_one_time_keys(count)

    def mark_keys_as_published(self) -> None:
        """Mark all current one-time keys as published."""
        self._native.mark_keys_as_published()

    def sign(self, message) -> str:
        """Sign a message. Accepts str or bytes, returns base64 signature string."""
        if isinstance(message, str):
            message = message.encode("utf-8")
        return self._native.sign(message)

    def new_outbound_session(self, identity_key: str, one_time_key: str) -> "Session":
        """Create a new outbound Olm session to the given identity/one-time key pair."""
        native_session = self._native.create_outbound_session(identity_key, one_time_key)
        sess = Session.__new__(Session)
        sess._native = native_session
        return sess

    def new_inbound_session(self, sender_key, message: OlmPreKeyMessage) -> "Session":
        """Create a new inbound Olm session from a pre-key message.

        Args:
            sender_key: The sender's curve25519 identity key (str or None).
                       If None, the key is extracted from the pre-key message.
            message: An OlmPreKeyMessage containing the initial pre-key ciphertext.

        Returns:
            A Session object for communicating with the sender.
        """
        native_session, _plaintext = self._native.create_inbound_session(
            sender_key or None, message.ciphertext
        )
        sess = Session.__new__(Session)
        sess._native = native_session
        return sess

    def remove_one_time_keys(self, session) -> None:
        """No-op: vodozemac handles one-time key removal automatically."""
        pass

    def pickle(self, passphrase="") -> bytes:
        """Serialize the account using the given passphrase.

        Returns bytes (UTF-8 encoded encrypted string) for python-olm compatibility.
        The internal format uses vodozemac's safe encrypted-string serialization.
        """
        key = _passphrase_to_bytes(passphrase)
        return self._native.to_encrypted_string(key).encode("utf-8")

    @classmethod
    def from_pickle(cls, data, passphrase="") -> "Account":
        """Deserialize an account from bytes data and passphrase.

        Supports subclassing via cls.__new__(cls).
        Uses vodozemac's safe encrypted-string deserialization internally.
        """
        key = _passphrase_to_bytes(passphrase)
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        native = _NativeAccount.from_encrypted_string(data, key)
        obj = cls.__new__(cls)
        obj._native = native
        return obj

    def __repr__(self) -> str:
        keys = self.identity_keys
        return f"Account(ed25519={keys['ed25519'][:8]}..., curve25519={keys['curve25519'][:8]}...)"


# ---------------------------------------------------------------------------
# Session wrapper
# ---------------------------------------------------------------------------


class Session:
    """Python-olm compatible Session wrapper around vodozemac Session.

    Key differences from the native API:
    - id is a property (not session_id() method)
    - encrypt() returns OlmMessage/OlmPreKeyMessage wrappers
    - decrypt() takes OlmMessage/OlmPreKeyMessage and returns str
    """

    def __init__(self):
        # Normally created via Account.new_outbound_session / new_inbound_session
        self._native = None

    @property
    def id(self) -> str:
        """Return the session ID."""
        return self._native.session_id()

    def encrypt(self, plaintext) -> OlmMessage | OlmPreKeyMessage:
        """Encrypt plaintext. Accepts str or bytes, returns message wrapper."""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        native_msg = self._native.encrypt(plaintext)
        return _wrap_encrypted(native_msg)

    def decrypt(self, message) -> str:
        """Decrypt a message. Takes OlmMessage/OlmPreKeyMessage, returns str."""
        plaintext_bytes = self._native.decrypt(message.message_type, message.ciphertext)
        return plaintext_bytes.decode("utf-8")

    def matches(self, message) -> bool:
        """Check if a pre-key message matches this session."""
        if not hasattr(message, 'ciphertext') or not hasattr(message, 'message_type'):
            return False
        if message.message_type != 0:
            return False
        return self._native.matches_prekey(message.ciphertext)

    def describe(self) -> str:
        """Return a human-readable description of the session."""
        return f"Session(id={self.id})"

    def pickle(self, passphrase="") -> bytes:
        """Serialize the session using the given passphrase.

        Uses vodozemac's safe encrypted-string serialization internally.
        """
        key = _passphrase_to_bytes(passphrase)
        return self._native.to_encrypted_string(key).encode("utf-8")

    @classmethod
    def from_pickle(cls, data, passphrase="") -> "Session":
        """Deserialize a session from bytes data and passphrase.

        Uses vodozemac's safe encrypted-string deserialization internally.
        """
        key = _passphrase_to_bytes(passphrase)
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        native = _NativeSession.from_encrypted_string(data, key)
        obj = cls.__new__(cls)
        obj._native = native
        return obj

    def __repr__(self) -> str:
        if self._native is None:
            return "Session(uninitialized)"
        return f"Session(id={self.id})"


# ---------------------------------------------------------------------------
# InboundSession / OutboundSession wrappers (matrix-nio compatibility)
# ---------------------------------------------------------------------------


class InboundSession(Session):
    """Inbound Olm session from a received pre-key message."""
    def __init__(self, account, message, identity_key=None):
        temp = account.new_inbound_session(identity_key, message)
        self._native = temp._native


class OutboundSession(Session):
    """Outbound Olm session to a recipient."""
    def __init__(self, account, identity_key, one_time_key):
        temp = account.new_outbound_session(identity_key, one_time_key)
        self._native = temp._native


# ---------------------------------------------------------------------------
# Outbound Group Session wrapper
# ---------------------------------------------------------------------------


class OutboundGroupSession:
    """Python-olm compatible OutboundGroupSession wrapper around vodozemac GroupSession."""

    def __init__(self):
        self._native = _NativeGroupSession()
        # Cache the initial session key so it always starts from index 0,
        # matching python-olm behavior where session_key is stable across
        # the lifetime of the session.
        self._initial_session_key: str = self._native.session_key()

    @property
    def id(self) -> str:
        """Return the session ID."""
        return self._native.session_id()

    @property
    def session_key(self) -> str:
        """Return the session key for sharing with recipients.

        In python-olm, session_key always returns the key that allows
        decryption from the initial message index (0), regardless of how
        many messages have been encrypted.  vodozemac's native session_key()
        advances with each encryption, so we cache the initial value.

        For sessions restored via from_pickle, the initial key is not
        available (vodozemac doesn't persist it separately), so we fall
        back to the native session_key() at the current ratchet index.
        """
        if self._initial_session_key is not None:
            return self._initial_session_key
        return self._native.session_key()

    @property
    def message_index(self) -> int:
        """Return the current message index."""
        return self._native.message_index()

    def encrypt(self, plaintext) -> str:
        """Encrypt plaintext. Accepts str or bytes, returns base64 ciphertext string."""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        return self._native.encrypt(plaintext)

    def pickle(self, passphrase="") -> bytes:
        """Serialize the session using the given passphrase.

        Uses vodozemac's safe encrypted-string serialization internally.
        """
        key = _passphrase_to_bytes(passphrase)
        return self._native.to_encrypted_string(key).encode("utf-8")

    @classmethod
    def from_pickle(cls, data, passphrase="") -> "OutboundGroupSession":
        """Deserialize an outbound group session from bytes data and passphrase.

        Uses vodozemac's safe encrypted-string deserialization internally.
        """
        key = _passphrase_to_bytes(passphrase)
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        native = _NativeGroupSession.from_encrypted_string(data, key)
        obj = cls.__new__(cls)
        obj._native = native
        obj._initial_session_key = None  # not available after deserialization
        return obj

    def __repr__(self) -> str:
        return f"OutboundGroupSession(id={self.id}, message_index={self.message_index})"


# Alias used by some code
GroupSession = OutboundGroupSession


# ---------------------------------------------------------------------------
# Inbound Group Session wrapper
# ---------------------------------------------------------------------------


class InboundGroupSession:
    """Python-olm compatible InboundGroupSession wrapper around vodozemac InboundGroupSession."""

    def __init__(self, session_key: str):
        self._native = _NativeInboundGroupSession(session_key)

    @property
    def id(self) -> str:
        """Return the session ID."""
        return self._native.session_id()

    @property
    def first_known_index(self) -> int:
        """Return the first message index the session can decrypt."""
        return self._native.first_known_index()

    def decrypt(self, ciphertext: str) -> tuple[str, int]:
        """Decrypt a Megolm ciphertext.

        Returns a tuple of (plaintext_string, message_index).
        """
        plaintext_bytes, index = self._native.decrypt(ciphertext)
        return plaintext_bytes.decode("utf-8"), index

    def export_session(self, index: int) -> str:
        """Export the session at the given message index.

        Returns a session key string that can be used with import_session().
        """
        result = self._native.export_at(index)
        if result is None:
            raise OlmGroupSessionError(
                f"Cannot export session at index {index}"
            )
        return result

    @classmethod
    def import_session(cls, exported_key: str) -> "InboundGroupSession":
        """Import a session from an exported session key string."""
        native = _NativeInboundGroupSession.import_session(exported_key)
        obj = cls.__new__(cls)
        obj._native = native
        return obj

    def pickle(self, passphrase="") -> bytes:
        """Serialize the session using the given passphrase.

        Uses vodozemac's safe encrypted-string serialization internally.
        """
        key = _passphrase_to_bytes(passphrase)
        return self._native.to_encrypted_string(key).encode("utf-8")

    @classmethod
    def from_pickle(cls, data, passphrase="") -> "InboundGroupSession":
        """Deserialize an inbound group session from bytes data and passphrase.

        Uses vodozemac's safe encrypted-string deserialization internally.
        """
        key = _passphrase_to_bytes(passphrase)
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        native = _NativeInboundGroupSession.from_encrypted_string(data, key)
        obj = cls.__new__(cls)
        obj._native = native
        return obj

    def __repr__(self) -> str:
        return f"InboundGroupSession(id={self.id}, first_known_index={self.first_known_index})"


# ---------------------------------------------------------------------------
# PkEncryption / PkDecryption wrappers
# ---------------------------------------------------------------------------


class PkEncryption:
    """Python-olm compatible PkEncryption wrapper around vodozemac PkEncryption."""

    def __init__(self, recipient_key: str):
        from fresholm._native import PkEncryption as _NativePkEncryption

        self._native = _NativePkEncryption(recipient_key)

    def encrypt(self, plaintext):
        """Encrypt plaintext. Accepts str or bytes, returns native PkMessage."""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        return self._native.encrypt(plaintext)


class PkDecryption:
    """Python-olm compatible PkDecryption wrapper around vodozemac PkDecryption."""

    def __init__(self, secret_key=None):
        from fresholm._native import PkDecryption as _NativePkDecryption

        self._native = _NativePkDecryption(secret_key)

    @property
    def public_key(self) -> str:
        """Return the public key as a base64 string."""
        return self._native.public_key

    def decrypt(self, ciphertext: str, mac: str, ephemeral_key: str) -> str:
        """Decrypt and return plaintext as a string (UTF-8 decoded)."""
        plaintext_bytes = self._native.decrypt(ciphertext, mac, ephemeral_key)
        return plaintext_bytes.decode("utf-8")


# ---------------------------------------------------------------------------
# Aliases for python-olm compatibility
# ---------------------------------------------------------------------------

OlmAccount = Account
OlmSession = Session
OlmInboundGroupSession = InboundGroupSession

__all__ = [
    "Account",
    "Session",
    "InboundSession",
    "OutboundSession",
    "OutboundGroupSession",
    "GroupSession",
    "InboundGroupSession",
    "OlmAccount",
    "OlmSession",
    "OlmInboundGroupSession",
    "OlmMessage",
    "OlmPreKeyMessage",
    "PkEncryption",
    "PkDecryption",
    "Sas",
    "sha256",
    "ed25519_verify",
    "utility",
    "OlmError",
    "OlmSessionError",
    "OlmGroupSessionError",
    "OlmAccountError",
    "OlmSasError",
    "OlmVerifyError",
    "CryptoStoreError",
]

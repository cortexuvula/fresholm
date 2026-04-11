"""Exception classes and helpers for python-olm compatibility."""


class OlmError(Exception):
    pass


class OlmSessionError(OlmError):
    pass


class OlmGroupSessionError(OlmError):
    pass


class OlmAccountError(OlmError):
    pass


class CryptoStoreError(Exception):
    pass


def _passphrase_to_bytes(passphrase) -> bytes:
    """Convert a passphrase to bytes for use with native serialization methods."""
    if isinstance(passphrase, str):
        return passphrase.encode("utf-8")
    if isinstance(passphrase, bytes):
        return passphrase
    raise TypeError(f"passphrase must be str or bytes, got {type(passphrase)}")

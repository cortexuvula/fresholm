"""Utility functions for olm compatibility."""

import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


class OlmVerifyError(Exception):
    """Ed25519 signature verification failed."""
    pass

def sha256(input_string):
    """SHA-256 hash, returns unpadded base64."""
    if isinstance(input_string, str):
        input_string = input_string.encode("utf-8")
    digest = hashlib.sha256(input_string).digest()
    return base64.b64encode(digest).rstrip(b"=").decode("ascii")

def ed25519_verify(key, message, signature):
    """Verify Ed25519 signature. Raises OlmVerifyError on failure.
    Handles padded and unpadded base64."""
    try:
        key_b64 = key + "=" * (-len(key) % 4)
        sig_b64 = signature + "=" * (-len(signature) % 4)
        key_bytes = base64.b64decode(key_b64)
        sig_bytes = base64.b64decode(sig_b64)
        if isinstance(message, str):
            message = message.encode("utf-8")
        pub_key = Ed25519PublicKey.from_public_bytes(key_bytes)
        pub_key.verify(sig_bytes, message)
    except InvalidSignature:
        raise OlmVerifyError("Ed25519 signature verification failed")
    except Exception as e:
        raise OlmVerifyError(f"Ed25519 verification error: {e}")

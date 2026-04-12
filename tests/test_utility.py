"""Tests for fresholm.compat.utility (sha256 and ed25519_verify)."""

import base64
import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fresholm.compat.utility import OlmVerifyError, ed25519_verify, sha256


# ---------------------------------------------------------------------------
# sha256 tests
# ---------------------------------------------------------------------------


class TestSha256:
    def test_sha256_string(self):
        result = sha256("test")
        assert isinstance(result, str)
        # Verify against known hash
        expected = base64.b64encode(hashlib.sha256(b"test").digest()).rstrip(b"=").decode("ascii")
        assert result == expected

    def test_sha256_bytes(self):
        result = sha256(b"test")
        expected = base64.b64encode(hashlib.sha256(b"test").digest()).rstrip(b"=").decode("ascii")
        assert result == expected

    def test_sha256_empty_string(self):
        result = sha256("")
        expected = base64.b64encode(hashlib.sha256(b"").digest()).rstrip(b"=").decode("ascii")
        assert result == expected

    def test_sha256_returns_str(self):
        result = sha256("hello")
        assert isinstance(result, str)

    def test_sha256_unpadded_base64(self):
        result = sha256("test")
        assert "=" not in result

    def test_sha256_consistent(self):
        assert sha256("foo") == sha256("foo")

    def test_sha256_different_inputs_differ(self):
        assert sha256("a") != sha256("b")


# ---------------------------------------------------------------------------
# ed25519_verify tests
# ---------------------------------------------------------------------------


def _make_ed25519_keypair():
    """Generate an Ed25519 keypair and return (private_key, public_key_b64_unpadded)."""
    private_key = Ed25519PrivateKey.generate()
    pub_bytes = private_key.public_key().public_bytes_raw()
    pub_b64 = base64.b64encode(pub_bytes).rstrip(b"=").decode("ascii")
    return private_key, pub_b64


def _sign(private_key, message):
    """Sign a message and return unpadded base64 signature."""
    if isinstance(message, str):
        message = message.encode("utf-8")
    sig_bytes = private_key.sign(message)
    return base64.b64encode(sig_bytes).rstrip(b"=").decode("ascii")


class TestEd25519Verify:
    def test_valid_signature(self):
        priv, pub = _make_ed25519_keypair()
        msg = "hello world"
        sig = _sign(priv, msg)
        # Should not raise
        ed25519_verify(pub, msg, sig)

    def test_bytes_message(self):
        priv, pub = _make_ed25519_keypair()
        msg = b"hello bytes"
        sig = _sign(priv, msg)
        ed25519_verify(pub, msg, sig)

    def test_invalid_signature_raises(self):
        priv, pub = _make_ed25519_keypair()
        msg = "hello"
        sig = _sign(priv, msg)
        with pytest.raises(OlmVerifyError):
            ed25519_verify(pub, "wrong message", sig)

    def test_wrong_key_raises(self):
        priv1, pub1 = _make_ed25519_keypair()
        _, pub2 = _make_ed25519_keypair()
        msg = "hello"
        sig = _sign(priv1, msg)
        with pytest.raises(OlmVerifyError):
            ed25519_verify(pub2, msg, sig)

    def test_unpadded_base64_keys(self):
        priv, pub = _make_ed25519_keypair()
        # Ensure the key has no padding
        assert "=" not in pub
        msg = "test unpadded"
        sig = _sign(priv, msg)
        ed25519_verify(pub, msg, sig)

    def test_padded_base64_keys(self):
        priv, pub = _make_ed25519_keypair()
        # Add padding manually
        pub_padded = pub + "=" * (-len(pub) % 4)
        msg = "test padded"
        sig = _sign(priv, msg)
        sig_padded = sig + "=" * (-len(sig) % 4)
        ed25519_verify(pub_padded, msg, sig_padded)

    def test_empty_message(self):
        priv, pub = _make_ed25519_keypair()
        msg = ""
        sig = _sign(priv, msg)
        ed25519_verify(pub, msg, sig)

    def test_garbage_key_raises(self):
        with pytest.raises(OlmVerifyError):
            ed25519_verify("notakey!!!", "msg", "notsig!!!")

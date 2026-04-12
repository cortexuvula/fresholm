"""Tests for PkSigning (ed25519 cross-signing keys)."""

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from fresholm.compat.olm import PkSigning


class TestPkSigning:
    def test_create_from_seed(self):
        seed = b"A" * 32
        signer = PkSigning(seed)
        assert isinstance(signer.public_key, str)
        assert len(signer.public_key) == 43  # 32 bytes -> 44 base64 chars -> 43 unpadded

    def test_generate_seed(self):
        seed = PkSigning.generate_seed()
        assert isinstance(seed, bytes)
        assert len(seed) == 32

    def test_two_signers_same_seed_same_key(self):
        seed = PkSigning.generate_seed()
        s1 = PkSigning(seed)
        s2 = PkSigning(seed)
        assert s1.public_key == s2.public_key

    def test_sign_returns_unpadded_base64(self):
        signer = PkSigning(PkSigning.generate_seed())
        sig = signer.sign("test message")
        assert isinstance(sig, str)
        assert "=" not in sig

    def test_sign_str(self):
        signer = PkSigning(PkSigning.generate_seed())
        sig = signer.sign("hello")
        # Verify using cryptography directly
        pub_bytes = base64.b64decode(signer.public_key + "==")
        pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        sig_bytes = base64.b64decode(sig + "==")
        pub_key.verify(sig_bytes, b"hello")

    def test_sign_bytes(self):
        signer = PkSigning(PkSigning.generate_seed())
        sig = signer.sign(b"bytes message")
        assert isinstance(sig, str)

    def test_verify_with_ed25519_verify(self):
        from fresholm.compat.utility import ed25519_verify
        signer = PkSigning(PkSigning.generate_seed())
        msg = "canonical json test"
        sig = signer.sign(msg)
        ed25519_verify(signer.public_key, msg, sig)

    def test_cross_sign_verify(self):
        """Two seeds, each signs, both verify against their own public key."""
        from fresholm.compat.utility import ed25519_verify
        s1 = PkSigning(PkSigning.generate_seed())
        s2 = PkSigning(PkSigning.generate_seed())
        msg = "cross-sign test"
        sig1 = s1.sign(msg)
        sig2 = s2.sign(msg)
        ed25519_verify(s1.public_key, msg, sig1)
        ed25519_verify(s2.public_key, msg, sig2)
        # Cross-verification should fail
        with pytest.raises(Exception):
            ed25519_verify(s1.public_key, msg, sig2)

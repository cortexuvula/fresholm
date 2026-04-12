"""Tests for PkEncryption/PkDecryption at native and compat layers."""

import pytest

from fresholm._native import PkDecryption as NativePkDecryption
from fresholm._native import PkEncryption as NativePkEncryption


# ---------------------------------------------------------------------------
# Native layer tests
# ---------------------------------------------------------------------------


class TestNativePkRoundtrip:
    """Test the native Rust PkEncryption/PkDecryption bindings."""

    def test_encrypt_decrypt_roundtrip(self):
        dec = NativePkDecryption()
        enc = NativePkEncryption(dec.public_key)
        msg = enc.encrypt(b"hello world")
        plaintext = dec.decrypt(msg.ciphertext, msg.mac, msg.ephemeral_key)
        assert plaintext == b"hello world"

    def test_different_messages_have_different_ephemeral_keys(self):
        dec = NativePkDecryption()
        enc = NativePkEncryption(dec.public_key)
        msg1 = enc.encrypt(b"message one")
        msg2 = enc.encrypt(b"message two")
        assert msg1.ephemeral_key != msg2.ephemeral_key

    def test_wrong_key_fails_to_decrypt(self):
        dec1 = NativePkDecryption()
        dec2 = NativePkDecryption()
        enc = NativePkEncryption(dec1.public_key)
        msg = enc.encrypt(b"secret")
        with pytest.raises(Exception):
            dec2.decrypt(msg.ciphertext, msg.mac, msg.ephemeral_key)

    def test_invalid_recipient_key_raises(self):
        with pytest.raises(Exception):
            NativePkEncryption("not-valid-base64-key!!!")

    def test_public_key_is_string(self):
        dec = NativePkDecryption()
        assert isinstance(dec.public_key, str)
        assert len(dec.public_key) > 0

    def test_two_decryptors_have_different_keys(self):
        dec1 = NativePkDecryption()
        dec2 = NativePkDecryption()
        assert dec1.public_key != dec2.public_key


# ---------------------------------------------------------------------------
# Compat layer tests
# ---------------------------------------------------------------------------


class TestCompatPk:
    """Test the Python compat wrappers for PkEncryption/PkDecryption."""

    def test_compat_roundtrip_with_string(self):
        from fresholm.compat.olm import PkDecryption, PkEncryption

        dec = PkDecryption()
        enc = PkEncryption(dec.public_key)
        msg = enc.encrypt("hello from compat")
        plaintext = dec.decrypt(msg.ciphertext, msg.mac, msg.ephemeral_key)
        assert plaintext == "hello from compat"
        assert isinstance(plaintext, str)

    def test_compat_encrypt_accepts_bytes(self):
        from fresholm.compat.olm import PkDecryption, PkEncryption

        dec = PkDecryption()
        enc = PkEncryption(dec.public_key)
        msg = enc.encrypt(b"bytes input")
        plaintext = dec.decrypt(msg.ciphertext, msg.mac, msg.ephemeral_key)
        assert plaintext == "bytes input"

    def test_compat_public_key_is_property(self):
        from fresholm.compat.olm import PkDecryption

        dec = PkDecryption()
        # Verify it's a property, not a method call
        assert isinstance(type(dec).public_key, property)
        assert isinstance(dec.public_key, str)

    def test_importable_from_olm_after_hook(self):
        import fresholm.import_hook  # noqa: F401
        from olm import PkDecryption, PkEncryption

        dec = PkDecryption()
        enc = PkEncryption(dec.public_key)
        msg = enc.encrypt("via olm import")
        plaintext = dec.decrypt(msg.ciphertext, msg.mac, msg.ephemeral_key)
        assert plaintext == "via olm import"

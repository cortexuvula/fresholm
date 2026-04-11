"""Tests for fresholm._native.Account bindings."""

import pytest

from fresholm._native import Account, OlmAccountError


class TestCreateAccount:
    def test_create_account(self):
        account = Account()
        assert account is not None

    def test_identity_keys(self):
        account = Account()
        keys = account.identity_keys()
        assert "ed25519" in keys
        assert "curve25519" in keys
        assert len(keys["ed25519"]) > 20
        assert len(keys["curve25519"]) > 20

    def test_sign(self):
        account = Account()
        sig = account.sign(b"test message")
        assert isinstance(sig, str)
        assert len(sig) > 20

    def test_one_time_keys(self):
        account = Account()
        account.generate_one_time_keys(5)
        otks = account.one_time_keys()
        assert isinstance(otks, dict)
        assert len(otks) == 5
        for key_id, key in otks.items():
            assert isinstance(key_id, str)
            assert isinstance(key, str)
            assert len(key) > 20

    def test_mark_keys_as_published(self):
        account = Account()
        account.generate_one_time_keys(3)
        assert len(account.one_time_keys()) == 3
        account.mark_keys_as_published()
        assert len(account.one_time_keys()) == 0

    def test_max_one_time_keys(self):
        account = Account()
        assert account.max_number_of_one_time_keys() > 0

    def test_serialization_roundtrip(self):
        account = Account()
        original_keys = account.identity_keys()
        passphrase = b"secret passphrase"

        encrypted = account.to_encrypted_string(passphrase)
        assert isinstance(encrypted, str)
        assert len(encrypted) > 0

        restored = Account.from_encrypted_string(encrypted, passphrase)
        restored_keys = restored.identity_keys()
        assert original_keys["ed25519"] == restored_keys["ed25519"]
        assert original_keys["curve25519"] == restored_keys["curve25519"]

    def test_wrong_passphrase_fails(self):
        account = Account()
        encrypted = account.to_encrypted_string(b"correct passphrase")
        with pytest.raises(OlmAccountError):
            Account.from_encrypted_string(encrypted, b"wrong passphrase")

    def test_repr(self):
        account = Account()
        r = repr(account)
        assert r.startswith("Account(")
        assert "ed25519=" in r
        assert "curve25519=" in r

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


# ---------------------------------------------------------------------------
# Compat layer tests
# ---------------------------------------------------------------------------

from fresholm.compat.olm import Account as CompatAccount


class TestCompatAccount:
    """Test the python-olm compatible Account wrapper."""

    def test_identity_keys_is_property(self):
        acct = CompatAccount()
        # identity_keys is a property, not a method
        keys = acct.identity_keys
        assert isinstance(keys, dict)
        assert "ed25519" in keys
        assert "curve25519" in keys

    def test_one_time_keys_nested_format(self):
        acct = CompatAccount()
        acct.generate_one_time_keys(3)
        otks = acct.one_time_keys
        assert "curve25519" in otks
        assert isinstance(otks["curve25519"], dict)
        assert len(otks["curve25519"]) == 3

    def test_max_one_time_keys_is_property(self):
        acct = CompatAccount()
        assert isinstance(acct.max_one_time_keys, int)
        assert acct.max_one_time_keys > 0

    def test_sign_accepts_str(self):
        acct = CompatAccount()
        sig = acct.sign("hello")
        assert isinstance(sig, str)
        assert len(sig) > 20

    def test_sign_accepts_bytes(self):
        acct = CompatAccount()
        sig = acct.sign(b"hello")
        assert isinstance(sig, str)
        assert len(sig) > 20

    def test_sign_str_and_bytes_match(self):
        acct = CompatAccount()
        sig_str = acct.sign("hello")
        sig_bytes = acct.sign(b"hello")
        assert sig_str == sig_bytes

    def test_string_passphrase_serialization(self):
        acct = CompatAccount()
        data = acct.pickle("my string passphrase")
        assert isinstance(data, bytes)
        restored = CompatAccount.from_pickle(data, "my string passphrase")
        assert restored.identity_keys["ed25519"] == acct.identity_keys["ed25519"]

    def test_bytes_passphrase_serialization(self):
        acct = CompatAccount()
        data = acct.pickle(b"my bytes passphrase")
        assert isinstance(data, bytes)
        restored = CompatAccount.from_pickle(data, b"my bytes passphrase")
        assert restored.identity_keys["ed25519"] == acct.identity_keys["ed25519"]

    def test_subclassing(self):
        class MyAccount(CompatAccount):
            def __init__(self):
                super().__init__()
                self.extra = True

        acct = MyAccount()
        assert acct.extra is True
        assert isinstance(acct.identity_keys, dict)

        data = acct.pickle("sub_pass")
        restored = MyAccount.from_pickle(data, "sub_pass")
        assert isinstance(restored, MyAccount)

    def test_remove_one_time_keys_noop(self):
        acct = CompatAccount()
        # Should not raise
        acct.remove_one_time_keys(None)

    def test_repr(self):
        acct = CompatAccount()
        r = repr(acct)
        assert "Account(" in r
        assert "ed25519=" in r
        assert "curve25519=" in r

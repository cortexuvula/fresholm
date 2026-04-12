"""Tests for fresholm.compat.sas (SAS key verification)."""


import pytest

from fresholm.compat.sas import OlmSasError, Sas


class TestSasPubkey:
    def test_pubkey_is_43_char_unpadded_base64(self):
        sas = Sas()
        pk = sas.pubkey
        assert isinstance(pk, str)
        assert len(pk) == 43  # 32 bytes -> 44 base64 chars -> 43 unpadded
        assert "=" not in pk

    def test_two_instances_have_different_keys(self):
        sas1 = Sas()
        sas2 = Sas()
        assert sas1.pubkey != sas2.pubkey


class TestSasKeyExchange:
    def test_other_key_set_initially_false(self):
        sas = Sas()
        assert sas.other_key_set is False

    def test_other_key_set_true_after_set(self):
        sas1 = Sas()
        sas2 = Sas()
        sas1.set_their_pubkey(sas2.pubkey)
        assert sas1.other_key_set is True

    def test_construct_with_other_key(self):
        sas1 = Sas()
        sas2 = Sas(other_users_pubkey=sas1.pubkey)
        assert sas2.other_key_set is True

    def test_padded_base64_accepted(self):
        sas1 = Sas()
        sas2 = Sas()
        # Add padding manually
        padded_key = sas2.pubkey + "=" * (-len(sas2.pubkey) % 4)
        sas1.set_their_pubkey(padded_key)
        assert sas1.other_key_set is True


class TestSasGenerateBytes:
    def test_generate_bytes_returns_requested_length(self):
        sas1 = Sas()
        sas2 = Sas()
        sas1.set_their_pubkey(sas2.pubkey)
        sas2.set_their_pubkey(sas1.pubkey)
        result = sas1.generate_bytes("info", 6)
        assert isinstance(result, bytes)
        assert len(result) == 6

    def test_both_sides_produce_same_bytes(self):
        sas1 = Sas()
        sas2 = Sas()
        sas1.set_their_pubkey(sas2.pubkey)
        sas2.set_their_pubkey(sas1.pubkey)
        b1 = sas1.generate_bytes("info", 6)
        b2 = sas2.generate_bytes("info", 6)
        assert b1 == b2

    def test_different_info_produces_different_bytes(self):
        sas1 = Sas()
        sas2 = Sas()
        sas1.set_their_pubkey(sas2.pubkey)
        sas2.set_their_pubkey(sas1.pubkey)
        b1 = sas1.generate_bytes("info_a", 32)
        b2 = sas1.generate_bytes("info_b", 32)
        assert b1 != b2

    def test_raises_if_key_not_set(self):
        sas = Sas()
        with pytest.raises(OlmSasError):
            sas.generate_bytes("info", 6)


class TestSasCalculateMac:
    def test_calculate_mac_returns_unpadded_base64(self):
        sas1 = Sas()
        sas2 = Sas()
        sas1.set_their_pubkey(sas2.pubkey)
        sas2.set_their_pubkey(sas1.pubkey)
        mac = sas1.calculate_mac("message", "info")
        assert isinstance(mac, str)
        assert "=" not in mac

    def test_both_sides_produce_same_mac(self):
        sas1 = Sas()
        sas2 = Sas()
        sas1.set_their_pubkey(sas2.pubkey)
        sas2.set_their_pubkey(sas1.pubkey)
        mac1 = sas1.calculate_mac("message", "info")
        mac2 = sas2.calculate_mac("message", "info")
        assert mac1 == mac2

    def test_different_message_produces_different_mac(self):
        sas1 = Sas()
        sas2 = Sas()
        sas1.set_their_pubkey(sas2.pubkey)
        sas2.set_their_pubkey(sas1.pubkey)
        mac1 = sas1.calculate_mac("message_a", "info")
        mac2 = sas1.calculate_mac("message_b", "info")
        assert mac1 != mac2


class TestSasCalculateMacLongKdf:
    def test_long_kdf_differs_from_standard(self):
        sas1 = Sas()
        sas2 = Sas()
        sas1.set_their_pubkey(sas2.pubkey)
        sas2.set_their_pubkey(sas1.pubkey)
        mac_std = sas1.calculate_mac("message", "info")
        mac_long = sas1.calculate_mac_long_kdf("message", "info")
        assert mac_std != mac_long

    def test_long_kdf_both_sides_match(self):
        sas1 = Sas()
        sas2 = Sas()
        sas1.set_their_pubkey(sas2.pubkey)
        sas2.set_their_pubkey(sas1.pubkey)
        mac1 = sas1.calculate_mac_long_kdf("msg", "info")
        mac2 = sas2.calculate_mac_long_kdf("msg", "info")
        assert mac1 == mac2


class TestSasSubclassable:
    def test_subclass(self):
        class MySas(Sas):
            def __init__(self):
                super().__init__()
                self.custom = True

        sas = MySas()
        assert sas.custom is True
        assert isinstance(sas.pubkey, str)
        assert len(sas.pubkey) == 43

"""Tests for the v2 pickle envelope and v1 fallback.

The four pickled types — Account, Session, GroupSession,
InboundGroupSession — share a common envelope. We exercise each one to
catch wiring mistakes (e.g., a missed call site that still uses the v1
encrypt path).
"""

import warnings

import pytest

from fresholm._native import (
    Account,
    GroupSession,
    InboundGroupSession,
    Session,
    _v1_encrypt_account_for_testing,
    _v1_encrypt_group_session_for_testing,
    _v1_encrypt_inbound_group_session_for_testing,
    _v1_encrypt_session_for_testing,
)


PASSPHRASE = b"correct horse battery staple"
WRONG_PASSPHRASE = b"a different passphrase"


def _fresh_session_pair():
    """Return (alice_account, alice_session, out_group_session, in_group_session).

    A bit of setup to obtain valid instances of all four pickled types.
    """
    alice = Account()
    bob = Account()
    bob.generate_one_time_keys(1)
    bob_otk = list(bob.one_time_keys().values())[0]
    bob_id = bob.identity_keys()["curve25519"]
    alice_session = alice.create_outbound_session(bob_id, bob_otk)
    out_group = GroupSession()
    in_group = InboundGroupSession(out_group.session_key())
    return alice, alice_session, out_group, in_group


# ---------------------------------------------------------------------------
# v2 round-trip
# ---------------------------------------------------------------------------


class TestV2RoundTrip:
    def test_account_v2_emits_prefix(self):
        a, _, _, _ = _fresh_session_pair()
        blob = a.to_encrypted_string(PASSPHRASE)
        assert blob.startswith("v2|"), blob[:8]

    def test_account_v2_round_trip(self):
        a, _, _, _ = _fresh_session_pair()
        blob = a.to_encrypted_string(PASSPHRASE)
        restored = Account.from_encrypted_string(blob, PASSPHRASE)
        assert restored.identity_keys() == a.identity_keys()

    def test_account_v2_salt_is_random(self):
        """Two pickles of the same account differ — confirms per-pickle salt."""
        a, _, _, _ = _fresh_session_pair()
        blob1 = a.to_encrypted_string(PASSPHRASE)
        blob2 = a.to_encrypted_string(PASSPHRASE)
        assert blob1 != blob2

    def test_session_v2_round_trip(self):
        _, sess, _, _ = _fresh_session_pair()
        blob = sess.to_encrypted_string(PASSPHRASE)
        assert blob.startswith("v2|")
        restored = Session.from_encrypted_string(blob, PASSPHRASE)
        assert restored.session_id() == sess.session_id()

    def test_group_session_v2_round_trip(self):
        _, _, out_group, _ = _fresh_session_pair()
        blob = out_group.to_encrypted_string(PASSPHRASE)
        assert blob.startswith("v2|")
        restored = GroupSession.from_encrypted_string(blob, PASSPHRASE)
        assert restored.session_id() == out_group.session_id()

    def test_inbound_group_session_v2_round_trip(self):
        _, _, _, in_group = _fresh_session_pair()
        blob = in_group.to_encrypted_string(PASSPHRASE)
        assert blob.startswith("v2|")
        restored = InboundGroupSession.from_encrypted_string(blob, PASSPHRASE)
        assert restored.session_id() == in_group.session_id()


# ---------------------------------------------------------------------------
# v1 legacy fallback
# ---------------------------------------------------------------------------


class TestV1LegacyDecode:
    def test_account_v1_does_not_have_v2_prefix(self):
        a, _, _, _ = _fresh_session_pair()
        blob = _v1_encrypt_account_for_testing(a, PASSPHRASE)
        assert not blob.startswith("v2|")

    def test_account_v1_decode_succeeds(self):
        a, _, _, _ = _fresh_session_pair()
        blob = _v1_encrypt_account_for_testing(a, PASSPHRASE)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            restored = Account.from_encrypted_string(blob, PASSPHRASE)
        assert restored.identity_keys() == a.identity_keys()
        # exactly one DeprecationWarning fired, mentioning v1 and Account
        dep = [w for w in caught if issubclass(w.category, DeprecationWarning)]
        assert len(dep) == 1
        msg = str(dep[0].message)
        assert "v1" in msg and "Account" in msg

    def test_session_v1_decode_with_warning(self):
        _, sess, _, _ = _fresh_session_pair()
        blob = _v1_encrypt_session_for_testing(sess, PASSPHRASE)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            restored = Session.from_encrypted_string(blob, PASSPHRASE)
        assert restored.session_id() == sess.session_id()
        dep = [w for w in caught if issubclass(w.category, DeprecationWarning)]
        assert len(dep) == 1
        msg = str(dep[0].message)
        assert "v1" in msg and "Session" in msg

    def test_group_session_v1_decode_with_warning(self):
        _, _, out_group, _ = _fresh_session_pair()
        blob = _v1_encrypt_group_session_for_testing(out_group, PASSPHRASE)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            restored = GroupSession.from_encrypted_string(blob, PASSPHRASE)
        assert restored.session_id() == out_group.session_id()
        dep = [w for w in caught if issubclass(w.category, DeprecationWarning)]
        assert len(dep) == 1
        msg = str(dep[0].message)
        assert "v1" in msg and "GroupSession" in msg

    def test_inbound_group_session_v1_decode_with_warning(self):
        _, _, _, in_group = _fresh_session_pair()
        blob = _v1_encrypt_inbound_group_session_for_testing(in_group, PASSPHRASE)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            restored = InboundGroupSession.from_encrypted_string(blob, PASSPHRASE)
        assert restored.session_id() == in_group.session_id()
        dep = [w for w in caught if issubclass(w.category, DeprecationWarning)]
        assert len(dep) == 1
        msg = str(dep[0].message)
        assert "v1" in msg and "InboundGroupSession" in msg


# ---------------------------------------------------------------------------
# Wrong passphrase rejection (both paths)
# ---------------------------------------------------------------------------


class TestWrongPassphrase:
    def test_v2_wrong_passphrase_fails(self):
        a, _, _, _ = _fresh_session_pair()
        blob = a.to_encrypted_string(PASSPHRASE)
        with pytest.raises(Exception):  # vodozemac raises OlmAccountError
            Account.from_encrypted_string(blob, WRONG_PASSPHRASE)

    def test_v1_wrong_passphrase_fails(self):
        a, _, _, _ = _fresh_session_pair()
        blob = _v1_encrypt_account_for_testing(a, PASSPHRASE)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            with pytest.raises(Exception):
                Account.from_encrypted_string(blob, WRONG_PASSPHRASE)


# ---------------------------------------------------------------------------
# Format detection edge cases
# ---------------------------------------------------------------------------


class TestEnvelopeDetection:
    def test_malformed_v2_envelope_errors(self):
        with pytest.raises(Exception):
            Account.from_encrypted_string("v2|not-valid-base64!|garbage", PASSPHRASE)

    def test_v2_with_truncated_inner_errors(self):
        # Real header, no inner payload after the second `|`
        a, _, _, _ = _fresh_session_pair()
        blob = a.to_encrypted_string(PASSPHRASE)
        # strip the inner blob, keeping "v2|<header>|"
        envelope = blob.rsplit("|", 1)[0] + "|"
        with pytest.raises(Exception):
            Account.from_encrypted_string(envelope, PASSPHRASE)

"""Tests for fresholm._native.Session and EncryptedMessage bindings."""

import pytest

from fresholm._native import Account, EncryptedMessage, OlmSessionError, Session


def _create_session_pair():
    """Create Alice+Bob session pair.

    Alice creates an outbound session to Bob, encrypts "Hello Bob!",
    Bob creates an inbound session from the pre-key message and decrypts.
    Returns (alice_account, bob_account, alice_session, bob_session, plaintext).
    """
    alice = Account()
    bob = Account()

    bob.generate_one_time_keys(1)
    bob_otks = bob.one_time_keys()
    bob_otk = list(bob_otks.values())[0]
    bob.mark_keys_as_published()

    bob_identity_key = bob.identity_keys()["curve25519"]
    alice_identity_key = alice.identity_keys()["curve25519"]

    alice_session = alice.create_outbound_session(bob_identity_key, bob_otk)

    # Alice encrypts a message
    msg = alice_session.encrypt(b"Hello Bob!")
    assert msg.message_type == 0  # Pre-key message

    # Bob creates inbound session from the pre-key message
    bob_session, plaintext = bob.create_inbound_session(
        alice_identity_key, msg.ciphertext
    )

    return alice, bob, alice_session, bob_session, plaintext


class TestCreateOutboundSession:
    def test_create_outbound_session(self):
        alice, bob, alice_session, bob_session, plaintext = _create_session_pair()
        assert plaintext == b"Hello Bob!"
        assert alice_session.session_id() == bob_session.session_id()


class TestEncryptReturnsEncryptedMessage:
    def test_encrypt_returns_encrypted_message(self):
        alice, bob, alice_session, bob_session, plaintext = _create_session_pair()
        # Alice sends another message (still pre-key until she receives one)
        msg = alice_session.encrypt(b"Another message")
        assert isinstance(msg, EncryptedMessage)
        assert msg.message_type in (0, 1)
        assert len(msg.ciphertext) > 0
        assert "EncryptedMessage" in repr(msg)


class TestEncryptDecryptRoundtrip:
    def test_encrypt_decrypt_roundtrip(self):
        alice, bob, alice_session, bob_session, plaintext = _create_session_pair()
        # Bob replies to Alice
        bob_msg = bob_session.encrypt(b"Hello Alice!")
        # Bob's message should be Normal (type 1) since he already received
        # a message from Alice
        assert bob_msg.message_type == 1

        # Alice decrypts Bob's reply
        decrypted = alice_session.decrypt(bob_msg.message_type, bob_msg.ciphertext)
        assert decrypted == b"Hello Alice!"


class TestSessionSerialization:
    def test_session_serialization_roundtrip(self):
        alice, bob, alice_session, bob_session, plaintext = _create_session_pair()
        passphrase = b"test passphrase 1234"
        original_id = alice_session.session_id()

        encrypted = alice_session.to_encrypted_string(passphrase)
        assert isinstance(encrypted, str)
        assert len(encrypted) > 0

        restored = Session.from_encrypted_string(encrypted, passphrase)
        assert restored.session_id() == original_id

    def test_invalid_key_raises(self):
        alice, bob, alice_session, bob_session, plaintext = _create_session_pair()
        encrypted = alice_session.to_encrypted_string(b"correct key")
        with pytest.raises(OlmSessionError):
            Session.from_encrypted_string(encrypted, b"wrong key")


class TestSessionProperties:
    def test_session_id(self):
        alice, bob, alice_session, bob_session, plaintext = _create_session_pair()
        sid = alice_session.session_id()
        assert isinstance(sid, str)
        assert len(sid) > 20

    def test_has_received_message(self):
        alice, bob, alice_session, bob_session, plaintext = _create_session_pair()
        # Alice hasn't received a message from Bob yet
        assert not alice_session.has_received_message()

        # Bob replies
        bob_msg = bob_session.encrypt(b"reply")
        alice_session.decrypt(bob_msg.message_type, bob_msg.ciphertext)

        # Now Alice has received a message
        assert alice_session.has_received_message()

    def test_repr(self):
        alice, bob, alice_session, bob_session, plaintext = _create_session_pair()
        r = repr(alice_session)
        assert r.startswith("Session(")
        assert "session_id=" in r


# ---------------------------------------------------------------------------
# Compat layer tests
# NOTE: Method names like 'pickle' and 'from_pickle' are the python-olm API
# names required for mautrix compatibility. Internally they use vodozemac's
# safe encrypted-string serialization.
# ---------------------------------------------------------------------------

from fresholm.compat.olm import (
    Account as CompatAccount,
    Session as CompatSession,
    OlmMessage,
    OlmPreKeyMessage,
)


def _create_compat_session_pair():
    """Create Alice+Bob session pair using the compat layer."""
    alice = CompatAccount()
    bob = CompatAccount()

    bob.generate_one_time_keys(1)
    bob_otk = list(bob.one_time_keys["curve25519"].values())[0]
    bob.mark_keys_as_published()

    alice_session = alice.new_outbound_session(
        bob.identity_keys["curve25519"], bob_otk
    )

    # Alice encrypts a message (pre-key)
    msg = alice_session.encrypt("Hello Bob!")
    assert isinstance(msg, OlmPreKeyMessage)
    assert msg.message_type == 0

    # Bob creates inbound session
    bob_session = bob.new_inbound_session(
        alice.identity_keys["curve25519"], msg
    )

    return alice, bob, alice_session, bob_session


class TestCompatSession:
    """Test the python-olm compatible Session wrapper."""

    def test_olm_roundtrip_through_compat(self):
        alice, bob, alice_session, bob_session = _create_compat_session_pair()

        # Alice sends another message
        msg = alice_session.encrypt("Second message")
        plaintext = bob_session.decrypt(msg)
        assert plaintext == "Second message"

    def test_bidirectional(self):
        alice, bob, alice_session, bob_session = _create_compat_session_pair()

        # Bob replies
        reply = bob_session.encrypt("Hello Alice!")
        assert isinstance(reply, OlmMessage)
        assert reply.message_type == 1

        decrypted = alice_session.decrypt(reply)
        assert decrypted == "Hello Alice!"

    def test_session_id_is_property(self):
        alice, bob, alice_session, bob_session = _create_compat_session_pair()
        assert isinstance(alice_session.id, str)
        assert len(alice_session.id) > 20

    def test_encrypt_accepts_str(self):
        alice, bob, alice_session, bob_session = _create_compat_session_pair()
        msg = alice_session.encrypt("string input")
        assert isinstance(msg, (OlmMessage, OlmPreKeyMessage))

    def test_encrypt_accepts_bytes(self):
        alice, bob, alice_session, bob_session = _create_compat_session_pair()
        msg = alice_session.encrypt(b"bytes input")
        assert isinstance(msg, (OlmMessage, OlmPreKeyMessage))

    def test_describe(self):
        alice, bob, alice_session, bob_session = _create_compat_session_pair()
        desc = alice_session.describe()
        assert "Session(" in desc
        assert "id=" in desc

    def test_serialization_with_string_passphrase(self):
        alice, bob, alice_session, bob_session = _create_compat_session_pair()
        data = alice_session.pickle("sess_pass")
        assert isinstance(data, bytes)
        restored = CompatSession.from_pickle(data, "sess_pass")
        assert restored.id == alice_session.id

    def test_subclassing(self):
        class MySession(CompatSession):
            pass

        alice, bob, alice_session, bob_session = _create_compat_session_pair()
        data = alice_session.pickle("sub_pass")
        restored = MySession.from_pickle(data, "sub_pass")
        assert isinstance(restored, MySession)
        assert restored.id == alice_session.id


class TestSessionMatches:
    def _make_prekey_message(self):
        from fresholm.compat.olm import Account, OlmPreKeyMessage
        alice = Account()
        bob = Account()
        bob.generate_one_time_keys(1)
        bob_keys = bob.identity_keys
        alice_keys = alice.identity_keys
        bob_otk = list(bob.one_time_keys["curve25519"].values())[0]
        alice_session = alice.new_outbound_session(bob_keys["curve25519"], bob_otk)
        first_msg = alice_session.encrypt("hello")
        assert isinstance(first_msg, OlmPreKeyMessage)
        return alice_session, first_msg, bob, alice_keys

    def test_matches_returns_true_for_matching(self):
        from fresholm.compat.olm import Account
        alice_session, first_msg, bob, alice_keys = self._make_prekey_message()
        bob_session = bob.new_inbound_session(alice_keys["curve25519"], first_msg)
        assert bob_session.matches(first_msg) is True

    def test_matches_returns_false_for_non_matching(self):
        from fresholm.compat.olm import Account
        _, first_msg, _, _ = self._make_prekey_message()
        charlie = Account()
        dave = Account()
        dave.generate_one_time_keys(1)
        dave_keys = dave.identity_keys
        dave_otk = list(dave.one_time_keys["curve25519"].values())[0]
        charlie_session = charlie.new_outbound_session(dave_keys["curve25519"], dave_otk)
        assert charlie_session.matches(first_msg) is False

    def test_matches_returns_false_for_normal_message(self):
        from fresholm.compat.olm import OlmMessage
        msg = OlmMessage(b"not a prekey")
        alice_session, first_msg, bob, alice_keys = self._make_prekey_message()
        bob_session = bob.new_inbound_session(alice_keys["curve25519"], first_msg)
        assert bob_session.matches(msg) is False

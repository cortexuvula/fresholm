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

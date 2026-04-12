"""Comprehensive tests for the python-olm compatibility layer.

Tests cover:
- Import hook (import olm -> fresholm.compat.olm)
- Mautrix-style subclass patterns
- Full Olm encryption roundtrip through compat layer
- Full Megolm encryption roundtrip through compat layer

NOTE: The 'pickle' and 'from_pickle' method names in this file are the
python-olm API names required for mautrix compatibility. They use safe
vodozemac encrypted-string serialization internally, not Python's
serialization module.
"""

import sys


from fresholm.compat.olm import (
    Account,
    CryptoStoreError,
    GroupSession,
    InboundGroupSession,
    OlmAccount,
    OlmAccountError,
    OlmError,
    OlmGroupSessionError,
    OlmInboundGroupSession,
    OlmMessage,
    OlmPreKeyMessage,
    OlmSession,
    OlmSessionError,
    OutboundGroupSession,
    Session,
)


# ---------------------------------------------------------------------------
# TestImportHook
# ---------------------------------------------------------------------------


class TestImportHook:
    """Verify that the import hook makes 'import olm' resolve to compat."""

    def test_import_olm_module(self):
        import fresholm.import_hook  # noqa: F401
        import olm

        assert olm.__name__ == "fresholm.compat.olm"

    def test_from_olm_import_account(self):
        import fresholm.import_hook  # noqa: F401
        from olm import Account as OlmAccountImported

        assert OlmAccountImported is Account

    def test_from_olm_import_session(self):
        import fresholm.import_hook  # noqa: F401
        from olm import Session as OlmSessionImported

        assert OlmSessionImported is Session

    def test_from_olm_import_group_sessions(self):
        import fresholm.import_hook  # noqa: F401
        from olm import InboundGroupSession, OutboundGroupSession

        assert OutboundGroupSession is OutboundGroupSession
        assert InboundGroupSession is InboundGroupSession

    def test_from_olm_import_messages(self):
        import fresholm.import_hook  # noqa: F401
        from olm import OlmMessage, OlmPreKeyMessage

        assert OlmMessage is OlmMessage
        assert OlmPreKeyMessage is OlmPreKeyMessage

    def test_from_olm_import_errors(self):
        import fresholm.import_hook  # noqa: F401
        from olm import OlmError, OlmSessionError, OlmAccountError

        assert issubclass(OlmSessionError, OlmError)
        assert issubclass(OlmAccountError, OlmError)

    def test_olm_in_sys_modules(self):
        import fresholm.import_hook  # noqa: F401

        assert "olm" in sys.modules

    def test_import_hook_installs(self):
        import fresholm.import_hook  # noqa: F401
        import olm

        assert hasattr(olm, "PkEncryption")
        assert hasattr(olm, "PkDecryption")


# ---------------------------------------------------------------------------
# TestMautrixSubclassPatterns
# ---------------------------------------------------------------------------


class TestMautrixSubclassPatterns:
    """Test that compat classes support the subclass patterns used by mautrix-python."""

    def test_account_subclass_with_super_init(self):
        class MyAccount(Account):
            def __init__(self):
                super().__init__()
                self.custom_field = "hello"

        acct = MyAccount()
        assert acct.custom_field == "hello"
        assert isinstance(acct.identity_keys, dict)
        assert "ed25519" in acct.identity_keys

    def test_account_subclass_from_serialized(self):
        """Verify from_pickle returns the subclass type."""

        class MyAccount(Account):
            pass

        acct = MyAccount()
        data = acct.pickle("pass123")
        restored = MyAccount.from_pickle(data, "pass123")
        assert isinstance(restored, MyAccount)
        assert restored.identity_keys["ed25519"] == acct.identity_keys["ed25519"]

    def test_session_subclass_with_new_override(self):
        class MySession(Session):
            def __new__(cls, *args, **kwargs):
                instance = super().__new__(cls)
                return instance

        # Sessions are normally created via Account, not directly
        alice = Account()
        bob = Account()
        bob.generate_one_time_keys(1)
        bob_otk = list(bob.one_time_keys["curve25519"].values())[0]
        bob.mark_keys_as_published()

        # Use native account to create a session, then wrap it
        native_session = alice._native.create_outbound_session(
            bob.identity_keys["curve25519"], bob_otk
        )
        sess = MySession.__new__(MySession)
        sess._native = native_session
        assert isinstance(sess, MySession)
        assert isinstance(sess.id, str)

    def test_session_subclass_from_serialized(self):
        """Verify Session.from_pickle returns the subclass type."""

        class MySession(Session):
            pass

        alice = Account()
        bob = Account()
        bob.generate_one_time_keys(1)
        bob_otk = list(bob.one_time_keys["curve25519"].values())[0]
        bob.mark_keys_as_published()

        sess = alice.new_outbound_session(bob.identity_keys["curve25519"], bob_otk)
        data = sess.pickle("sesspass")
        restored = MySession.from_pickle(data, "sesspass")
        assert isinstance(restored, MySession)
        assert restored.id == sess.id

    def test_outbound_group_session_subclass_with_room_id(self):
        class RoomGroupSession(OutboundGroupSession):
            def __init__(self, room_id=None):
                super().__init__()
                self.room_id = room_id

        sess = RoomGroupSession(room_id="!abc:example.com")
        assert sess.room_id == "!abc:example.com"
        assert isinstance(sess.id, str)
        assert isinstance(sess.session_key, str)
        ct = sess.encrypt("hello room")
        assert isinstance(ct, str)

    def test_outbound_group_session_subclass_from_serialized(self):
        class RoomGroupSession(OutboundGroupSession):
            pass

        sess = RoomGroupSession()
        data = sess.pickle("gspass")
        restored = RoomGroupSession.from_pickle(data, "gspass")
        assert isinstance(restored, RoomGroupSession)
        assert restored.id == sess.id

    def test_inbound_group_session_subclass_with_extra_args(self):
        class TrackedInboundSession(InboundGroupSession):
            def __init__(self, session_key, sender_key=None, forwarding_chain=None):
                super().__init__(session_key)
                self.sender_key = sender_key
                self.forwarding_chain = forwarding_chain or []

        outbound = OutboundGroupSession()
        sk = outbound.session_key
        sess = TrackedInboundSession(
            sk, sender_key="ABCD1234", forwarding_chain=["key1", "key2"]
        )
        assert sess.sender_key == "ABCD1234"
        assert sess.forwarding_chain == ["key1", "key2"]
        assert isinstance(sess.id, str)

    def test_inbound_group_session_subclass_from_serialized(self):
        class TrackedInboundSession(InboundGroupSession):
            pass

        outbound = OutboundGroupSession()
        inbound = TrackedInboundSession(outbound.session_key)
        data = inbound.pickle("igspass")
        restored = TrackedInboundSession.from_pickle(data, "igspass")
        assert isinstance(restored, TrackedInboundSession)
        assert restored.id == inbound.id


# ---------------------------------------------------------------------------
# TestFullEncryptionFlow - Olm roundtrip
# ---------------------------------------------------------------------------


class TestFullEncryptionFlow:
    """End-to-end Olm encryption roundtrip through the compat layer."""

    def test_alice_bob_olm_roundtrip(self):
        # Setup
        alice = Account()
        bob = Account()

        # Bob publishes one-time keys
        bob.generate_one_time_keys(1)
        bob_otk = list(bob.one_time_keys["curve25519"].values())[0]
        bob.mark_keys_as_published()

        # Alice creates an outbound session to Bob
        alice_session = alice.new_outbound_session(
            bob.identity_keys["curve25519"], bob_otk
        )

        # Alice encrypts a message
        encrypted = alice_session.encrypt("Hello Bob!")
        assert isinstance(encrypted, OlmPreKeyMessage)
        assert encrypted.message_type == 0

        # Bob creates an inbound session from the pre-key message
        bob_session = bob.new_inbound_session(
            alice.identity_keys["curve25519"], encrypted
        )

        # Bob's remove_one_time_keys is a no-op (vodozemac handles this)
        bob.remove_one_time_keys(bob_session)

        # Alice sends another message for Bob to decrypt
        encrypted2 = alice_session.encrypt("Second message")
        plaintext = bob_session.decrypt(encrypted2)
        assert plaintext == "Second message"

    def test_bidirectional_olm_communication(self):
        alice = Account()
        bob = Account()

        bob.generate_one_time_keys(1)
        bob_otk = list(bob.one_time_keys["curve25519"].values())[0]
        bob.mark_keys_as_published()

        alice_session = alice.new_outbound_session(
            bob.identity_keys["curve25519"], bob_otk
        )

        # Alice sends initial message
        msg1 = alice_session.encrypt("Hello Bob!")
        assert msg1.message_type == 0  # Pre-key

        # Bob creates inbound session
        bob_session = bob.new_inbound_session(
            alice.identity_keys["curve25519"], msg1
        )

        # Bob replies
        reply = bob_session.encrypt("Hello Alice!")
        assert reply.message_type == 1  # Normal message (Bob already received)

        # Alice decrypts Bob's reply
        decrypted_reply = alice_session.decrypt(reply)
        assert decrypted_reply == "Hello Alice!"

    def test_olm_session_serialization_roundtrip(self):
        alice = Account()
        bob = Account()

        bob.generate_one_time_keys(1)
        bob_otk = list(bob.one_time_keys["curve25519"].values())[0]
        bob.mark_keys_as_published()

        alice_session = alice.new_outbound_session(
            bob.identity_keys["curve25519"], bob_otk
        )

        # Serialize and restore the session
        session_data = alice_session.pickle("session_pass")
        restored_session = Session.from_pickle(session_data, "session_pass")
        assert restored_session.id == alice_session.id

    def test_message_types(self):
        msg = OlmMessage(b"test")
        assert msg.message_type == 1
        assert msg.ciphertext == b"test"

        pmsg = OlmPreKeyMessage(b"test")
        assert pmsg.message_type == 0
        assert pmsg.ciphertext == b"test"

        # String input
        msg2 = OlmMessage("test")
        assert msg2.ciphertext == b"test"

        pmsg2 = OlmPreKeyMessage("test")
        assert pmsg2.ciphertext == b"test"


# ---------------------------------------------------------------------------
# TestFullMegolmFlow - Megolm roundtrip
# ---------------------------------------------------------------------------


class TestFullMegolmFlow:
    """End-to-end Megolm encryption roundtrip through the compat layer."""

    def test_megolm_encrypt_decrypt(self):
        outbound = OutboundGroupSession()
        session_key = outbound.session_key
        inbound = InboundGroupSession(session_key)

        assert outbound.id == inbound.id

        # Encrypt
        ct = outbound.encrypt("Hello group!")
        assert isinstance(ct, str)
        assert outbound.message_index == 1

        # Decrypt
        pt, idx = inbound.decrypt(ct)
        assert pt == "Hello group!"
        assert idx == 0

    def test_megolm_multiple_messages(self):
        outbound = OutboundGroupSession()
        session_key = outbound.session_key
        inbound = InboundGroupSession(session_key)

        ciphertexts = []
        for i in range(5):
            ct = outbound.encrypt(f"Message {i}")
            ciphertexts.append(ct)

        assert outbound.message_index == 5

        for i, ct in enumerate(ciphertexts):
            pt, idx = inbound.decrypt(ct)
            assert pt == f"Message {i}"
            assert idx == i

    def test_megolm_export_import(self):
        outbound = OutboundGroupSession()
        session_key = outbound.session_key
        inbound = InboundGroupSession(session_key)

        # Encrypt and decrypt first message to advance ratchet
        ct0 = outbound.encrypt("msg 0")
        inbound.decrypt(ct0)

        # Export at index 1
        exported = inbound.export_session(1)
        assert isinstance(exported, str)

        # Import the exported session
        imported = InboundGroupSession.import_session(exported)
        assert imported.id == inbound.id
        assert imported.first_known_index == 1

        # The imported session can decrypt messages from index 1 onward
        ct1 = outbound.encrypt("msg 1")
        pt, idx = imported.decrypt(ct1)
        assert pt == "msg 1"
        assert idx == 1

    def test_megolm_serialization_roundtrip(self):
        outbound = OutboundGroupSession()
        session_key = outbound.session_key

        # Serialize outbound
        ob_data = outbound.pickle("ob_pass")
        restored_ob = OutboundGroupSession.from_pickle(ob_data, "ob_pass")
        assert restored_ob.id == outbound.id
        assert restored_ob.message_index == outbound.message_index

        # Serialize inbound
        inbound = InboundGroupSession(session_key)
        ib_data = inbound.pickle("ib_pass")
        restored_ib = InboundGroupSession.from_pickle(ib_data, "ib_pass")
        assert restored_ib.id == inbound.id
        assert restored_ib.first_known_index == inbound.first_known_index

    def test_megolm_group_session_alias(self):
        assert GroupSession is OutboundGroupSession
        gs = GroupSession()
        assert isinstance(gs, OutboundGroupSession)

    def test_megolm_string_and_bytes_input(self):
        outbound = OutboundGroupSession()
        session_key = outbound.session_key
        inbound = InboundGroupSession(session_key)

        # String input
        ct1 = outbound.encrypt("string input")
        pt1, _ = inbound.decrypt(ct1)
        assert pt1 == "string input"

        # Bytes input
        ct2 = outbound.encrypt(b"bytes input")
        pt2, _ = inbound.decrypt(ct2)
        assert pt2 == "bytes input"

    def test_inbound_first_known_index(self):
        outbound = OutboundGroupSession()
        inbound = InboundGroupSession(outbound.session_key)
        assert inbound.first_known_index == 0


# ---------------------------------------------------------------------------
# TestExceptionHierarchy
# ---------------------------------------------------------------------------


class TestExceptionHierarchy:
    """Test that exception classes follow python-olm's hierarchy."""

    def test_olm_session_error_is_olm_error(self):
        assert issubclass(OlmSessionError, OlmError)

    def test_olm_group_session_error_is_olm_error(self):
        assert issubclass(OlmGroupSessionError, OlmError)

    def test_olm_account_error_is_olm_error(self):
        assert issubclass(OlmAccountError, OlmError)

    def test_crypto_store_error_is_not_olm_error(self):
        assert not issubclass(CryptoStoreError, OlmError)

    def test_olm_error_is_exception(self):
        assert issubclass(OlmError, Exception)

    def test_crypto_store_error_is_exception(self):
        assert issubclass(CryptoStoreError, Exception)


# ---------------------------------------------------------------------------
# TestAliases
# ---------------------------------------------------------------------------


class TestAliases:
    """Test that python-olm aliases are correctly defined."""

    def test_olm_account_is_account(self):
        assert OlmAccount is Account

    def test_olm_session_is_session(self):
        assert OlmSession is Session

    def test_olm_inbound_group_session_is_inbound_group_session(self):
        assert OlmInboundGroupSession is InboundGroupSession

    def test_group_session_is_outbound_group_session(self):
        assert GroupSession is OutboundGroupSession

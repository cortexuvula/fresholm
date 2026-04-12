"""Tests for fresholm._native.GroupSession and InboundGroupSession bindings."""

import pytest

from fresholm._native import (
    GroupSession,
    InboundGroupSession,
    OlmGroupSessionError,
)
from fresholm.compat.olm import (
    OutboundGroupSession as CompatOutbound,
    InboundGroupSession as CompatInbound,
    GroupSession as CompatGroupSession,
)


class TestGroupSessionCreate:
    def test_create(self):
        session = GroupSession()
        assert session.session_id() is not None
        assert isinstance(session.session_id(), str)
        assert len(session.session_id()) > 20
        assert session.message_index() == 0


class TestGroupSessionEncrypt:
    def test_encrypt_increments_index(self):
        session = GroupSession()
        assert session.message_index() == 0
        session.encrypt(b"message 1")
        assert session.message_index() == 1
        session.encrypt(b"message 2")
        assert session.message_index() == 2
        session.encrypt(b"message 3")
        assert session.message_index() == 3


class TestGroupSessionKey:
    def test_session_key(self):
        session = GroupSession()
        key = session.session_key()
        assert isinstance(key, str)
        assert len(key) > 20


class TestMegolmRoundtrip:
    def test_megolm_roundtrip(self):
        outbound = GroupSession()
        session_key = outbound.session_key()

        inbound = InboundGroupSession(session_key)
        assert outbound.session_id() == inbound.session_id()

        ciphertext = outbound.encrypt(b"Hello group!")
        plaintext, index = inbound.decrypt(ciphertext)
        assert plaintext == b"Hello group!"
        assert index == 0

    def test_megolm_multiple_messages(self):
        outbound = GroupSession()
        inbound = InboundGroupSession(outbound.session_key())

        messages = []
        for i in range(5):
            ct = outbound.encrypt(f"Message {i}".encode())
            messages.append(ct)

        for i, ct in enumerate(messages):
            plaintext, index = inbound.decrypt(ct)
            assert plaintext == f"Message {i}".encode()
            assert index == i


class TestInboundGroupSessionProperties:
    def test_first_known_index(self):
        outbound = GroupSession()
        inbound = InboundGroupSession(outbound.session_key())
        assert inbound.first_known_index() == 0


class TestExportImport:
    def test_export_import_roundtrip(self):
        outbound = GroupSession()
        inbound = InboundGroupSession(outbound.session_key())

        # Encrypt and decrypt a message so the ratchet advances
        ct0 = outbound.encrypt(b"msg 0")
        inbound.decrypt(ct0)

        # Export at index 1
        exported = inbound.export_at(1)
        assert exported is not None
        assert isinstance(exported, str)
        assert len(exported) > 20

        # Import session from exported key
        imported = InboundGroupSession.import_session(exported)
        assert imported.session_id() == inbound.session_id()
        assert imported.first_known_index() == 1

        # The imported session cannot decrypt the first message (index 0)
        # but can decrypt subsequent ones
        ct1 = outbound.encrypt(b"msg 1")
        plaintext, index = imported.decrypt(ct1)
        assert plaintext == b"msg 1"
        assert index == 1

    def test_export_at_first_known_index(self):
        outbound = GroupSession()
        inbound = InboundGroupSession(outbound.session_key())
        exported = inbound.export_at_first_known_index()
        assert isinstance(exported, str)
        assert len(exported) > 20


class TestGroupSessionSerialization:
    def test_group_session_serialization_roundtrip(self):
        session = GroupSession()
        original_id = session.session_id()
        passphrase = b"group session passphrase"

        encrypted = session.to_encrypted_string(passphrase)
        assert isinstance(encrypted, str)
        assert len(encrypted) > 0

        restored = GroupSession.from_encrypted_string(encrypted, passphrase)
        assert restored.session_id() == original_id
        assert restored.message_index() == session.message_index()

    def test_group_session_wrong_key_raises(self):
        session = GroupSession()
        encrypted = session.to_encrypted_string(b"correct key")
        with pytest.raises(OlmGroupSessionError):
            GroupSession.from_encrypted_string(encrypted, b"wrong key")


class TestInboundGroupSessionSerialization:
    def test_inbound_group_session_serialization_roundtrip(self):
        outbound = GroupSession()
        inbound = InboundGroupSession(outbound.session_key())
        original_id = inbound.session_id()
        passphrase = b"inbound session passphrase"

        encrypted = inbound.to_encrypted_string(passphrase)
        assert isinstance(encrypted, str)
        assert len(encrypted) > 0

        restored = InboundGroupSession.from_encrypted_string(encrypted, passphrase)
        assert restored.session_id() == original_id
        assert restored.first_known_index() == inbound.first_known_index()

    def test_inbound_group_session_wrong_key_raises(self):
        outbound = GroupSession()
        inbound = InboundGroupSession(outbound.session_key())
        encrypted = inbound.to_encrypted_string(b"correct key")
        with pytest.raises(OlmGroupSessionError):
            InboundGroupSession.from_encrypted_string(encrypted, b"wrong key")


class TestRepr:
    def test_group_session_repr(self):
        session = GroupSession()
        r = repr(session)
        assert "GroupSession(" in r
        assert "session_id=" in r
        assert "message_index=" in r

    def test_inbound_group_session_repr(self):
        outbound = GroupSession()
        inbound = InboundGroupSession(outbound.session_key())
        r = repr(inbound)
        assert "InboundGroupSession(" in r
        assert "session_id=" in r
        assert "first_known_index=" in r


# ---------------------------------------------------------------------------
# Compat layer tests for group sessions
# These test the python-olm API compatibility wrapper.
# The serialization methods use vodozemac encrypted strings internally.
# ---------------------------------------------------------------------------


class TestCompatGroupSession:
    """Test the python-olm compatible group session wrappers."""

    def test_megolm_roundtrip_through_compat(self):
        outbound = CompatOutbound()
        session_key = outbound.session_key
        inbound = CompatInbound(session_key)

        assert outbound.id == inbound.id

        ct = outbound.encrypt("Hello group!")
        pt, idx = inbound.decrypt(ct)
        assert pt == "Hello group!"
        assert idx == 0

    def test_outbound_properties(self):
        outbound = CompatOutbound()
        assert isinstance(outbound.id, str)
        assert isinstance(outbound.session_key, str)
        assert outbound.message_index == 0

        outbound.encrypt("msg")
        assert outbound.message_index == 1

    def test_inbound_properties(self):
        outbound = CompatOutbound()
        inbound = CompatInbound(outbound.session_key)
        assert isinstance(inbound.id, str)
        assert inbound.first_known_index == 0

    def test_export_import(self):
        outbound = CompatOutbound()
        session_key = outbound.session_key
        inbound = CompatInbound(session_key)

        ct0 = outbound.encrypt("msg 0")
        inbound.decrypt(ct0)

        exported = inbound.export_session(1)
        imported = CompatInbound.import_session(exported)
        assert imported.id == inbound.id
        assert imported.first_known_index == 1

        ct1 = outbound.encrypt("msg 1")
        pt, idx = imported.decrypt(ct1)
        assert pt == "msg 1"
        assert idx == 1

    def test_outbound_serialization(self):
        outbound = CompatOutbound()
        data = outbound.pickle("pass1")
        restored = CompatOutbound.from_pickle(data, "pass1")
        assert restored.id == outbound.id

    def test_inbound_serialization(self):
        outbound = CompatOutbound()
        inbound = CompatInbound(outbound.session_key)
        data = inbound.pickle("pass2")
        restored = CompatInbound.from_pickle(data, "pass2")
        assert restored.id == inbound.id

    def test_group_session_alias(self):
        assert CompatGroupSession is CompatOutbound

    def test_encrypt_accepts_str_and_bytes(self):
        outbound = CompatOutbound()
        session_key = outbound.session_key
        inbound = CompatInbound(session_key)

        ct1 = outbound.encrypt("str input")
        pt1, _ = inbound.decrypt(ct1)
        assert pt1 == "str input"

        ct2 = outbound.encrypt(b"bytes input")
        pt2, _ = inbound.decrypt(ct2)
        assert pt2 == "bytes input"

    def test_outbound_subclassing(self):
        class MyOutbound(CompatOutbound):
            def __init__(self):
                super().__init__()
                self.room = "test"

        sess = MyOutbound()
        assert sess.room == "test"
        assert isinstance(sess.id, str)

        data = sess.pickle("sub_pass")
        restored = MyOutbound.from_pickle(data, "sub_pass")
        assert isinstance(restored, MyOutbound)

    def test_inbound_subclassing(self):
        class MyInbound(CompatInbound):
            pass

        outbound = CompatOutbound()
        inbound = MyInbound(outbound.session_key)
        data = inbound.pickle("sub_pass")
        restored = MyInbound.from_pickle(data, "sub_pass")
        assert isinstance(restored, MyInbound)

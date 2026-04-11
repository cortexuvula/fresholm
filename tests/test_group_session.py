"""Tests for fresholm._native.GroupSession and InboundGroupSession bindings."""

import pytest

from fresholm._native import (
    GroupSession,
    InboundGroupSession,
    OlmGroupSessionError,
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

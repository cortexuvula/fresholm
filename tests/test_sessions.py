"""Tests for InboundSession and OutboundSession (matrix-nio compat).

NOTE: Method names like 'pickle' and 'from_pickle' are the python-olm API
names required for mautrix compatibility. Internally they use vodozemac's
safe encrypted-string serialization.
"""

import pytest

from fresholm.compat.olm import (
    Account,
    InboundSession,
    OlmMessage,
    OlmPreKeyMessage,
    OutboundSession,
    Session,
)


def _setup_alice_bob():
    """Create Alice and Bob accounts with Bob having a published OTK."""
    alice = Account()
    bob = Account()
    bob.generate_one_time_keys(1)
    bob_otk = list(bob.one_time_keys["curve25519"].values())[0]
    bob.mark_keys_as_published()
    return alice, bob, bob_otk


# ---------------------------------------------------------------------------
# OutboundSession tests
# ---------------------------------------------------------------------------


class TestOutboundSession:
    def test_create(self):
        alice, bob, bob_otk = _setup_alice_bob()
        sess = OutboundSession(alice, bob.identity_keys["curve25519"], bob_otk)
        assert isinstance(sess, OutboundSession)
        assert isinstance(sess, Session)
        assert isinstance(sess.id, str)

    def test_encrypt(self):
        alice, bob, bob_otk = _setup_alice_bob()
        sess = OutboundSession(alice, bob.identity_keys["curve25519"], bob_otk)
        msg = sess.encrypt("Hello!")
        assert isinstance(msg, (OlmMessage, OlmPreKeyMessage))

    def test_subclass(self):
        class MyOutbound(OutboundSession):
            def __init__(self, account, identity_key, one_time_key):
                super().__init__(account, identity_key, one_time_key)
                self.custom = True

        alice, bob, bob_otk = _setup_alice_bob()
        sess = MyOutbound(alice, bob.identity_keys["curve25519"], bob_otk)
        assert isinstance(sess, MyOutbound)
        assert isinstance(sess, OutboundSession)
        assert isinstance(sess, Session)
        assert sess.custom is True
        assert isinstance(sess.id, str)


# ---------------------------------------------------------------------------
# InboundSession tests
# ---------------------------------------------------------------------------


class TestInboundSession:
    def test_create_with_identity_key(self):
        alice, bob, bob_otk = _setup_alice_bob()
        out_sess = OutboundSession(alice, bob.identity_keys["curve25519"], bob_otk)
        prekey_msg = out_sess.encrypt("Hello Bob!")
        assert isinstance(prekey_msg, OlmPreKeyMessage)

        in_sess = InboundSession(bob, prekey_msg, identity_key=alice.identity_keys["curve25519"])
        assert isinstance(in_sess, InboundSession)
        assert isinstance(in_sess, Session)
        assert isinstance(in_sess.id, str)

    def test_decrypt_roundtrip(self):
        alice, bob, bob_otk = _setup_alice_bob()
        out_sess = OutboundSession(alice, bob.identity_keys["curve25519"], bob_otk)
        prekey_msg = out_sess.encrypt("Hello Bob!")

        in_sess = InboundSession(bob, prekey_msg, identity_key=alice.identity_keys["curve25519"])

        # Send another message from alice and decrypt on bob side
        msg2 = out_sess.encrypt("Second message")
        plaintext = in_sess.decrypt(msg2)
        assert plaintext == "Second message"

    def test_bidirectional(self):
        alice, bob, bob_otk = _setup_alice_bob()
        out_sess = OutboundSession(alice, bob.identity_keys["curve25519"], bob_otk)
        prekey_msg = out_sess.encrypt("Hello Bob!")

        in_sess = InboundSession(bob, prekey_msg, identity_key=alice.identity_keys["curve25519"])

        # Bob replies
        reply = in_sess.encrypt("Hello Alice!")
        decrypted = out_sess.decrypt(reply)
        assert decrypted == "Hello Alice!"

    def test_subclass(self):
        class MyInbound(InboundSession):
            def __init__(self, account, message, identity_key=None):
                super().__init__(account, message, identity_key=identity_key)
                self.custom = True

        alice, bob, bob_otk = _setup_alice_bob()
        out_sess = OutboundSession(alice, bob.identity_keys["curve25519"], bob_otk)
        prekey_msg = out_sess.encrypt("Hello!")

        in_sess = MyInbound(bob, prekey_msg, identity_key=alice.identity_keys["curve25519"])
        assert isinstance(in_sess, MyInbound)
        assert isinstance(in_sess, InboundSession)
        assert isinstance(in_sess, Session)
        assert in_sess.custom is True


# ---------------------------------------------------------------------------
# matrix-nio pattern tests (subclass with super().__init__)
# ---------------------------------------------------------------------------


class TestMatrixNioPatterns:
    def test_outbound_session_nio_subclass(self):
        """matrix-nio subclasses OutboundSession with super().__init__."""
        class NioOutboundSession(OutboundSession):
            def __init__(self, account, identity_key, one_time_key):
                super().__init__(account, identity_key, one_time_key)

        alice, bob, bob_otk = _setup_alice_bob()
        sess = NioOutboundSession(alice, bob.identity_keys["curve25519"], bob_otk)
        assert isinstance(sess, NioOutboundSession)
        msg = sess.encrypt("test")
        assert isinstance(msg, (OlmMessage, OlmPreKeyMessage))

    def test_inbound_session_nio_subclass(self):
        """matrix-nio subclasses InboundSession with super().__init__."""
        class NioInboundSession(InboundSession):
            def __init__(self, account, message, identity_key=None):
                super().__init__(account, message, identity_key=identity_key)

        alice, bob, bob_otk = _setup_alice_bob()
        out_sess = OutboundSession(alice, bob.identity_keys["curve25519"], bob_otk)
        prekey_msg = out_sess.encrypt("Hello!")

        in_sess = NioInboundSession(bob, prekey_msg, identity_key=alice.identity_keys["curve25519"])
        assert isinstance(in_sess, NioInboundSession)

        # Verify it works for decrypt
        msg2 = out_sess.encrypt("Second")
        assert in_sess.decrypt(msg2) == "Second"

    def test_serialization_roundtrip(self):
        """OutboundSession serializes and restores as Session (base class).

        Uses vodozemac's safe encrypted-string serialization internally.
        """
        alice, bob, bob_otk = _setup_alice_bob()
        out_sess = OutboundSession(alice, bob.identity_keys["curve25519"], bob_otk)
        data = out_sess.pickle("pass")
        restored = Session.from_pickle(data, "pass")
        assert restored.id == out_sess.id


# ---------------------------------------------------------------------------
# Session uninitialized-state guards (Bug 1)
# ---------------------------------------------------------------------------


class TestUninitializedSession:
    """A bare Session() (not via Account or from_pickle) has _native=None.
    Each instance method must raise OlmSessionError, not AttributeError.
    """

    def test_id_raises(self):
        from fresholm.compat.olm import OlmSessionError
        sess = Session()
        with pytest.raises(OlmSessionError):
            _ = sess.id

    def test_encrypt_raises(self):
        from fresholm.compat.olm import OlmSessionError
        sess = Session()
        with pytest.raises(OlmSessionError):
            sess.encrypt("hello")

    def test_decrypt_raises(self):
        from fresholm.compat.olm import OlmSessionError
        sess = Session()
        with pytest.raises(OlmSessionError):
            sess.decrypt(OlmMessage(b"deadbeef"))

    def test_matches_raises(self):
        from fresholm.compat.olm import OlmSessionError
        sess = Session()
        with pytest.raises(OlmSessionError):
            sess.matches(OlmPreKeyMessage(b"deadbeef"))

    def test_describe_raises(self):
        from fresholm.compat.olm import OlmSessionError
        sess = Session()
        with pytest.raises(OlmSessionError):
            sess.describe()

    def test_pickle_raises(self):
        from fresholm.compat.olm import OlmSessionError
        sess = Session()
        with pytest.raises(OlmSessionError):
            sess.pickle()

    def test_repr_does_not_raise(self):
        # __repr__ already had the guard before this fix; verify it stays graceful.
        sess = Session()
        assert repr(sess) == "Session(uninitialized)"


# ---------------------------------------------------------------------------
# Initial pre-key plaintext stash (Bug 2)
# ---------------------------------------------------------------------------


class TestInboundSessionInitialPlaintext:
    """vodozemac's create_inbound_session decrypts the initial pre-key message
    as part of session establishment. The compat layer must surface that
    plaintext on a subsequent session.decrypt(prekey_msg) call to match
    python-olm's two-step contract used by mautrix-python and matrix-nio.
    """

    def test_decrypt_initial_prekey_via_inbound_session(self):
        """python-olm two-step: InboundSession then decrypt(same prekey)."""
        from fresholm.compat.olm import OlmPreKeyMessage  # noqa: F401
        alice, bob, bob_otk = _setup_alice_bob()
        out_sess = OutboundSession(alice, bob.identity_keys["curve25519"], bob_otk)
        prekey_msg = out_sess.encrypt("Hello Bob!")

        in_sess = InboundSession(
            bob, prekey_msg, identity_key=alice.identity_keys["curve25519"]
        )

        plaintext = in_sess.decrypt(prekey_msg)
        assert plaintext == "Hello Bob!"

    def test_decrypt_initial_prekey_via_account_new_inbound_session(self):
        """Same pattern, but via Account.new_inbound_session directly."""
        alice, bob, bob_otk = _setup_alice_bob()
        out_sess = alice.new_outbound_session(bob.identity_keys["curve25519"], bob_otk)
        prekey_msg = out_sess.encrypt("Hello Bob!")

        in_sess = bob.new_inbound_session(
            alice.identity_keys["curve25519"], prekey_msg
        )

        assert in_sess.decrypt(prekey_msg) == "Hello Bob!"

    def test_decrypt_initial_prekey_then_subsequent_messages(self):
        """Stash consumption does not break later normal decrypts."""
        alice, bob, bob_otk = _setup_alice_bob()
        out_sess = OutboundSession(alice, bob.identity_keys["curve25519"], bob_otk)
        prekey_msg = out_sess.encrypt("First")

        in_sess = InboundSession(
            bob, prekey_msg, identity_key=alice.identity_keys["curve25519"]
        )

        assert in_sess.decrypt(prekey_msg) == "First"

        msg2 = out_sess.encrypt("Second")
        assert in_sess.decrypt(msg2) == "Second"

    def test_decrypt_initial_prekey_only_works_once(self):
        """Calling decrypt(prekey) a second time fails — stash is one-shot."""
        from fresholm.compat.olm import OlmSessionError
        alice, bob, bob_otk = _setup_alice_bob()
        out_sess = OutboundSession(alice, bob.identity_keys["curve25519"], bob_otk)
        prekey_msg = out_sess.encrypt("First")
        in_sess = InboundSession(
            bob, prekey_msg, identity_key=alice.identity_keys["curve25519"]
        )

        assert in_sess.decrypt(prekey_msg) == "First"

        with pytest.raises(OlmSessionError):
            in_sess.decrypt(prekey_msg)

    def test_skipping_prekey_decrypt_does_not_break_later_decrypts(self):
        """Caller never decrypts the prekey; session still works for normal msgs."""
        alice, bob, bob_otk = _setup_alice_bob()
        out_sess = OutboundSession(alice, bob.identity_keys["curve25519"], bob_otk)
        prekey_msg = out_sess.encrypt("First (skipped)")
        in_sess = InboundSession(
            bob, prekey_msg, identity_key=alice.identity_keys["curve25519"]
        )

        msg2 = out_sess.encrypt("Second")
        assert in_sess.decrypt(msg2) == "Second"

    def test_outbound_session_has_no_stash(self):
        """OutboundSession is created without a stashed plaintext."""
        alice, bob, bob_otk = _setup_alice_bob()
        out_sess = OutboundSession(alice, bob.identity_keys["curve25519"], bob_otk)
        assert out_sess._stashed_prekey_plaintext is None

    def test_pickle_does_not_persist_stash(self):
        """Stash is in-memory only; pickle/from_pickle drop it.

        This documents that pickle-then-decrypt-initial-prekey is unsupported.
        Real callers either decrypt-then-pickle, or pickle-then-discard.
        """
        alice, bob, bob_otk = _setup_alice_bob()
        out_sess = OutboundSession(alice, bob.identity_keys["curve25519"], bob_otk)
        prekey_msg = out_sess.encrypt("Initial")
        in_sess = InboundSession(
            bob, prekey_msg, identity_key=alice.identity_keys["curve25519"]
        )

        assert in_sess._stashed_prekey_plaintext is not None

        blob = in_sess.pickle("pw")
        restored = Session.from_pickle(blob, "pw")

        assert restored._stashed_prekey_plaintext is None

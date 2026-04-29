# Bug Review Fixes Implementation Plan (Bugs 1, 2, 3)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix three correctness bugs in the python-olm compatibility layer: (1) defensive None guards on `Session` instance methods, (2) preserve and surface the initial pre-key plaintext to match python-olm's two-step decrypt contract, (3) replace tautological identity assertions in import-hook tests.

**Architecture:** All three fixes are localized to `fresholm/compat/olm.py` (Session class + Account.new_inbound_session) plus two test files. No Rust changes — `crates/vodozemac-python/src/account.rs::create_inbound_session` already returns `(session, plaintext)`; the Python wrapper just discards the plaintext. The fix is to stash the plaintext on the returned `Session` and serve it back on a matching `decrypt(prekey_msg)` call (one-shot, in-memory, not serialized through pickle).

**Tech Stack:** Python 3.10+, pytest, fresholm._native (PyO3 bindings).

**Out of scope:** Bug 4 (weak passphrase KDF) is a format-versioning + Rust crate-dependency change that warrants its own plan and a 0.3.0 cut. The migration design is already drafted in `docs/superpowers/notes/2026-04-27-vodozemac-pickle-kdf.md` (§ "Recommended next steps"). After this plan lands, that note should be promoted to its own implementation plan.

---

## File structure

**Files modified:**
- `fresholm/compat/olm.py` — Session class (None guards + plaintext stash), Account.new_inbound_session (capture plaintext), InboundSession.__init__ / OutboundSession.__init__ (propagate stash field).
- `tests/test_mautrix_compat.py` — replace two tautological tests at lines 63-75 with proper identity checks.
- `tests/test_sessions.py` — add Bug 1 None-guard tests and Bug 2 prekey-plaintext tests.

No new files. No Rust changes. No dependency changes.

---

## Task 1: Fix tautological import-hook tests (Bug 3)

These two tests in `tests/test_mautrix_compat.py` shadow their module-level imports with local `from olm import …` statements, then compare each name to itself. Fix by aliasing the locals and asserting identity against the module-level names. Apply the same pattern as the working tests at lines 51-61 (`from olm import Account as OlmAccountImported`).

**Files:**
- Modify: `tests/test_mautrix_compat.py:63-75`

- [ ] **Step 1: Replace `test_from_olm_import_group_sessions`**

Open `tests/test_mautrix_compat.py` and replace the body of `test_from_olm_import_group_sessions` (currently lines 63-68) with:

```python
    def test_from_olm_import_group_sessions(self):
        import fresholm.import_hook  # noqa: F401
        from olm import (
            InboundGroupSession as ImportedIGS,
            OutboundGroupSession as ImportedOGS,
        )

        assert ImportedOGS is OutboundGroupSession
        assert ImportedIGS is InboundGroupSession
```

- [ ] **Step 2: Replace `test_from_olm_import_messages`**

Replace the body of `test_from_olm_import_messages` (currently lines 70-75) with:

```python
    def test_from_olm_import_messages(self):
        import fresholm.import_hook  # noqa: F401
        from olm import (
            OlmMessage as ImportedOlmMessage,
            OlmPreKeyMessage as ImportedOlmPreKeyMessage,
        )

        assert ImportedOlmMessage is OlmMessage
        assert ImportedOlmPreKeyMessage is OlmPreKeyMessage
```

- [ ] **Step 3: Run the two tests to verify they pass**

Run: `pytest tests/test_mautrix_compat.py::TestImportHook::test_from_olm_import_group_sessions tests/test_mautrix_compat.py::TestImportHook::test_from_olm_import_messages -v`
Expected: both PASS. (They previously passed too, but the assertions were vacuous — the new ones actually verify the import hook routes the names through the same compat-module objects.)

- [ ] **Step 4: Verify the new assertions detect a regression**

Manually rename `OutboundGroupSession` to `OutboundGroupSession2` in `fresholm/compat/olm.py` (do not save), confirm tests fail, then revert. (Optional sanity check, not committed.)

Skip this step if obviously unnecessary.

- [ ] **Step 5: Commit**

```bash
git add tests/test_mautrix_compat.py
git commit -m "fix(test): replace tautological import-hook assertions

Both test_from_olm_import_group_sessions and test_from_olm_import_messages
shadowed their module-level imports with same-named locals, making the
identity checks compare each name to itself (always True). Alias the
imports so they actually verify the hook resolves olm.* to fresholm's
compat layer.
"
```

---

## Task 2: Add None guards to Session instance methods (Bug 1)

`Session.__init__` sets `self._native = None`, but `id`, `encrypt`, `decrypt`, `matches`, `describe`, and `pickle` all dereference `self._native` unconditionally. Direct construction via `Session()` (without going through `Account.new_*_session` or `from_pickle`) followed by any of these methods raises `AttributeError: 'NoneType' object has no attribute …`. The `__repr__` method already has the guard. Add a private `_check_initialized` helper and call it at the top of each instance method.

`matches` currently returns False for malformed input (missing attributes, wrong message_type) — but an uninitialized session is programmer error, not malformed input, so it should raise like the others.

**Files:**
- Modify: `fresholm/compat/olm.py:205-275` (Session class)
- Test: `tests/test_sessions.py` (add new test class `TestUninitializedSession`)

- [ ] **Step 1: Write failing tests for each guarded method**

Append this test class to the end of `tests/test_sessions.py`:

```python


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
```

You'll also need `import pytest` at the top of `tests/test_sessions.py` if it isn't already there. Check first; only add it if missing.

- [ ] **Step 2: Run new tests to verify they fail**

Run: `pytest tests/test_sessions.py::TestUninitializedSession -v`
Expected: 6 of 7 FAIL with `AttributeError: 'NoneType' object has no attribute …`. `test_repr_does_not_raise` PASSES.

- [ ] **Step 3: Add `_check_initialized` helper and guard each method**

In `fresholm/compat/olm.py`, in the `Session` class (starting around line 205), make these changes:

After the `__init__` method (currently lines 214-216), insert:

```python
    def _check_initialized(self) -> None:
        """Raise if the session has no native backing.

        Bare Session() construction (without going through
        Account.new_outbound_session, Account.new_inbound_session, or
        Session.from_pickle) leaves _native=None. Catch this in every
        instance method so callers see a typed OlmSessionError instead of
        AttributeError.
        """
        if self._native is None:
            raise OlmSessionError(
                "Session is uninitialized. Construct via "
                "Account.new_outbound_session(), Account.new_inbound_session(), "
                "or Session.from_pickle()."
            )
```

Then prefix the body of each of these methods with `self._check_initialized()` as the first line:

- `id` (currently line 218-221) — first line of the method body becomes `self._check_initialized()`
- `encrypt` (currently 223-228)
- `decrypt` (currently 230-233)
- `matches` (currently 235-241)
- `describe` (currently 243-245)
- `pickle` (currently 247-253)

Concretely, after the change, the methods read:

```python
    @property
    def id(self) -> str:
        """Return the session ID."""
        self._check_initialized()
        return self._native.session_id()

    def encrypt(self, plaintext) -> OlmMessage | OlmPreKeyMessage:
        """Encrypt plaintext. Accepts str or bytes, returns message wrapper."""
        self._check_initialized()
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        native_msg = self._native.encrypt(plaintext)
        return _wrap_encrypted(native_msg)

    def decrypt(self, message) -> str:
        """Decrypt a message. Takes OlmMessage/OlmPreKeyMessage, returns str."""
        self._check_initialized()
        plaintext_bytes = self._native.decrypt(message.message_type, message.ciphertext)
        return plaintext_bytes.decode("utf-8")

    def matches(self, message) -> bool:
        """Check if a pre-key message matches this session."""
        self._check_initialized()
        if not hasattr(message, 'ciphertext') or not hasattr(message, 'message_type'):
            return False
        if message.message_type != 0:
            return False
        return self._native.matches_prekey(message.ciphertext)

    def describe(self) -> str:
        """Return a human-readable description of the session."""
        self._check_initialized()
        return f"Session(id={self.id})"

    def pickle(self, passphrase="") -> bytes:
        """Serialize the session using the given passphrase.

        Uses vodozemac's safe encrypted-string serialization internally.
        """
        self._check_initialized()
        key = _passphrase_to_bytes(passphrase)
        return self._native.to_encrypted_string(key).encode("utf-8")
```

Leave `__repr__` (currently 272-275) unchanged — it has its own None branch.

- [ ] **Step 4: Run new tests; verify they pass**

Run: `pytest tests/test_sessions.py::TestUninitializedSession -v`
Expected: all 7 PASS.

- [ ] **Step 5: Run the full test suite to verify no regression**

Run: `pytest tests/ -v`
Expected: all tests pass. (No existing test exercises uninitialized Session, so no regression risk; but `_check_initialized` now runs on every Session method call — a one-attribute None check, negligible cost.)

- [ ] **Step 6: Commit**

```bash
git add fresholm/compat/olm.py tests/test_sessions.py
git commit -m "fix: raise OlmSessionError on uninitialized Session methods

Session.__init__ leaves _native=None to support __new__-based
construction by Account.new_*_session and from_pickle. Direct Session()
followed by .id / .encrypt / .decrypt / .matches / .describe / .pickle
previously raised AttributeError. Add _check_initialized() and call it
at the top of each method so callers get a typed OlmSessionError.
"
```

---

## Task 3: Stash and surface the initial pre-key plaintext (Bug 2)

vodozemac's `Account::create_inbound_session` both establishes the session and decrypts the initial pre-key message in one step, returning `(Session, Vec<u8> plaintext)`. The PyO3 wrapper at `crates/vodozemac-python/src/account.rs:91-109` exposes this faithfully as `(Session, plaintext)`. The Python compat layer at `fresholm/compat/olm.py:158` discards the plaintext:

```python
native_session, _plaintext = self._native.create_inbound_session(...)
```

After this, the session ratchet has advanced past the prekey message. python-olm's contract — `session = InboundSession(account, prekey); plaintext = session.decrypt(prekey)` — fails on a fresholm session because the native ratchet refuses to re-decrypt the consumed prekey. mautrix-python and matrix-nio both rely on the two-step pattern.

**Fix:** capture the plaintext alongside the prekey ciphertext bytes on the new Session as `_stashed_prekey_plaintext: Optional[tuple[bytes, bytes]]`. In `Session.decrypt`, before delegating to the native session, check whether the incoming message is a prekey whose ciphertext matches the stash; if so, return the stashed plaintext (one-shot — clear after serving). All other paths (subsequent normal messages, mismatched prekeys) fall through to native decrypt unchanged.

**Stash is in-memory only.** Pickle / from_pickle do not serialize it; that's intentional. Document in the test that pickle-then-decrypt-prekey is unsupported (no caller does this).

**Files:**
- Modify: `fresholm/compat/olm.py` — `Session.__init__`, `Session.decrypt`, `Session.from_pickle`, `Account.new_outbound_session`, `Account.new_inbound_session`, `InboundSession.__init__`, `OutboundSession.__init__`
- Test: `tests/test_sessions.py` (add new test class `TestInboundSessionInitialPlaintext`)

- [ ] **Step 1: Write failing tests for the python-olm two-step pattern**

Append this test class to `tests/test_sessions.py` (after `TestUninitializedSession` from Task 2):

```python


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
```

- [ ] **Step 2: Run new tests to verify they fail**

Run: `pytest tests/test_sessions.py::TestInboundSessionInitialPlaintext -v`
Expected: tests that call `in_sess.decrypt(prekey_msg)` FAIL with native `OlmSessionError: Decryption failed: …` (vodozemac refusing to re-decrypt). Tests that read `_stashed_prekey_plaintext` FAIL with `AttributeError`. The "skip prekey" test PASSES already.

- [ ] **Step 3: Add the `_stashed_prekey_plaintext` field to `Session.__init__`**

In `fresholm/compat/olm.py`, modify `Session.__init__` (currently lines 214-216) to:

```python
    def __init__(self):
        # Normally created via Account.new_outbound_session / new_inbound_session
        self._native = None
        # When this Session is created from a pre-key message (inbound), vodozemac
        # has already decrypted the initial plaintext as part of session
        # establishment. We stash (ciphertext_bytes, plaintext_bytes) here so that
        # the python-olm two-step `session.decrypt(prekey_msg)` can return the
        # already-known plaintext instead of failing in the native ratchet.
        # Cleared on first matching decrypt; never serialized through pickle.
        self._stashed_prekey_plaintext: tuple[bytes, bytes] | None = None
```

- [ ] **Step 4: Capture plaintext in `Account.new_inbound_session`**

In `fresholm/compat/olm.py`, replace `Account.new_inbound_session` (currently lines 147-163) with:

```python
    def new_inbound_session(self, sender_key, message: OlmPreKeyMessage) -> "Session":
        """Create a new inbound Olm session from a pre-key message.

        vodozemac decrypts the initial pre-key message as part of session
        creation. We stash the resulting plaintext on the returned Session so
        that the python-olm two-step pattern — ``session.decrypt(prekey_msg)``
        after construction — returns the same plaintext (matching mautrix and
        matrix-nio expectations).

        Args:
            sender_key: The sender's curve25519 identity key (str or None).
                       If None, the key is extracted from the pre-key message.
            message: An OlmPreKeyMessage containing the initial pre-key ciphertext.

        Returns:
            A Session object for communicating with the sender.
        """
        native_session, plaintext = self._native.create_inbound_session(
            sender_key or None, message.ciphertext
        )
        sess = Session.__new__(Session)
        sess._native = native_session
        sess._stashed_prekey_plaintext = (message.ciphertext, plaintext)
        return sess
```

- [ ] **Step 5: Initialize the stash field on `Account.new_outbound_session` and `Session.from_pickle`**

Both paths build a Session via `Session.__new__` and bypass `__init__`, so the new field needs an explicit assignment in each.

In `fresholm/compat/olm.py`, replace the body of `Account.new_outbound_session` (currently lines 140-145) with:

```python
    def new_outbound_session(self, identity_key: str, one_time_key: str) -> "Session":
        """Create a new outbound Olm session to the given identity/one-time key pair."""
        native_session = self._native.create_outbound_session(identity_key, one_time_key)
        sess = Session.__new__(Session)
        sess._native = native_session
        sess._stashed_prekey_plaintext = None
        return sess
```

Replace `Session.from_pickle` (currently lines 255-270) with:

```python
    @classmethod
    def from_pickle(cls, data, passphrase="", **kwargs) -> "Session":
        """Deserialize a session from bytes data and passphrase.

        Uses vodozemac's safe encrypted-string deserialization internally.

        Extra kwargs (creation_time, last_encrypted, last_decrypted, etc.)
        are accepted for mautrix compatibility but ignored.

        The pre-key plaintext stash (see Session.__init__) is in-memory only
        and is never persisted through pickle, so a restored Session has
        _stashed_prekey_plaintext=None.
        """
        key = _passphrase_to_bytes(passphrase)
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        native = _NativeSession.from_encrypted_string(data, key)
        obj = cls.__new__(cls)
        obj._native = native
        obj._stashed_prekey_plaintext = None
        return obj
```

- [ ] **Step 6: Make `Session.decrypt` consume the stash on a matching prekey**

Replace `Session.decrypt` (currently lines 230-233 — note Task 2 already added the `_check_initialized()` line at the top) with:

```python
    def decrypt(self, message) -> str:
        """Decrypt a message. Takes OlmMessage/OlmPreKeyMessage, returns str.

        If `message` is the same pre-key message that originally created this
        Session (matched by message_type==0 and exact ciphertext bytes), the
        plaintext returned by vodozemac at session-creation time is served
        from the stash and the stash is cleared. All other messages — normal
        type-1 messages, or different pre-key messages — go through the
        native session ratchet as usual.
        """
        self._check_initialized()
        stashed = self._stashed_prekey_plaintext
        if (
            stashed is not None
            and message.message_type == 0
            and message.ciphertext == stashed[0]
        ):
            self._stashed_prekey_plaintext = None
            return stashed[1].decode("utf-8")
        plaintext_bytes = self._native.decrypt(message.message_type, message.ciphertext)
        return plaintext_bytes.decode("utf-8")
```

- [ ] **Step 7: Propagate the stash through `InboundSession.__init__` and `OutboundSession.__init__`**

These subclasses construct via `account.new_*_session(...)` to a temp instance and copy `_native`. They must also copy the new field.

Replace `InboundSession` (currently lines 283-287) with:

```python
class InboundSession(Session):
    """Inbound Olm session from a received pre-key message."""
    def __init__(self, account, message, identity_key=None):
        temp = account.new_inbound_session(identity_key, message)
        self._native = temp._native
        self._stashed_prekey_plaintext = temp._stashed_prekey_plaintext
```

Replace `OutboundSession` (currently lines 290-294) with:

```python
class OutboundSession(Session):
    """Outbound Olm session to a recipient."""
    def __init__(self, account, identity_key, one_time_key):
        temp = account.new_outbound_session(identity_key, one_time_key)
        self._native = temp._native
        self._stashed_prekey_plaintext = None
```

- [ ] **Step 8: Run the new test class; verify all pass**

Run: `pytest tests/test_sessions.py::TestInboundSessionInitialPlaintext -v`
Expected: all 7 PASS.

- [ ] **Step 9: Run the full test suite**

Run: `pytest tests/ -v`
Expected: all tests pass (190+).

In particular, watch:
- `tests/test_session.py::TestEncryptDecryptRoundtrip` — Bob replies after Alice's prekey; bob_session is created via the bare `_native.create_inbound_session` path (not the compat wrapper), so it's unaffected.
- `tests/test_sessions.py::TestInboundSession::test_decrypt_roundtrip` — passes a *second* (normal) message, not the prekey, so it hits the native-decrypt branch and is unaffected.
- `tests/test_sessions.py::TestInboundSession::test_serialization_roundtrip` — pickle/from_pickle. The stash is dropped on round-trip; this test only verifies round-trip identity, so unaffected.

- [ ] **Step 10: Commit**

```bash
git add fresholm/compat/olm.py tests/test_sessions.py
git commit -m "fix: surface initial pre-key plaintext to match python-olm contract

vodozemac's create_inbound_session decrypts the initial pre-key message
as part of session establishment and returns (session, plaintext). The
compat layer was discarding the plaintext, so the python-olm two-step
pattern — session = InboundSession(account, prekey); session.decrypt(prekey)
— failed because the native ratchet refused to re-decrypt the consumed
message. mautrix-python and matrix-nio both rely on this pattern.

Stash (ciphertext, plaintext) on the returned Session and serve it back
on a matching decrypt() call (one-shot, in-memory; not serialized).
"
```

---

## Self-review notes

**Spec coverage:** Bugs 1, 2, 3 each have a dedicated task with TDD tests, code, and a commit. Bug 4 is explicitly deferred to a separate plan with reference to the existing KDF investigation note.

**Type/API consistency:**
- `_stashed_prekey_plaintext: tuple[bytes, bytes] | None` is the only new field; it's referenced consistently across `__init__`, `from_pickle`, both `Account.new_*_session` methods, both subclass `__init__`s, `decrypt`, and the tests.
- `_check_initialized` returns `None` and raises `OlmSessionError` on failure; called identically in all six methods.
- `OlmSessionError` is the existing exception class in `fresholm/compat/types.py:8` and is already re-exported from `compat/olm.py`. Tests import it via `from fresholm.compat.olm import OlmSessionError`.

**Risk: passing `tests/test_sessions.py::TestInboundSession::test_decrypt_roundtrip` after the change.** That test calls `in_sess.decrypt(msg2)` where `msg2` is a normal type-1 message. `_stashed_prekey_plaintext` is non-None at that point but the type/ciphertext don't match, so the stash branch is skipped and native decrypt runs as before. Verified by inspection.

**Risk: stash-vs-pickle.** A caller who pickles immediately after `InboundSession(...)` and never decrypts the prekey will lose the plaintext. No existing test or known caller does this; documented in `Session.from_pickle` docstring.

**Versioning:** This is a bugfix patch release (0.2.6 candidate). No breaking API or format changes.

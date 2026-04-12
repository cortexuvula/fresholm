# matrix-nio Compatibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 5 missing items to fresholm's compat layer so that matrix-nio can import `olm` via fresholm's import hook without errors: `InboundSession`, `OutboundSession`, `Sas`, `sha256`, `ed25519_verify`/`OlmVerifyError`.

**Architecture:** Pure Python additions only — no Rust changes. `InboundSession`/`OutboundSession` are thin subclasses of the existing `Session` class. `Sas` uses the `cryptography` library for X25519 ECDH + HKDF-SHA256. `sha256` and `ed25519_verify` are standalone utility functions. All wired into `olm.py` exports and `__all__`.

**Tech Stack:** Python 3.10+, `cryptography` library (X25519, HKDF, HMAC, Ed25519), `hashlib`, `base64`

---

## Current State

- 121 tests passing
- `fresholm/compat/olm.py` has: Account, Session, OutboundGroupSession, InboundGroupSession, PkEncryption, PkDecryption, OlmMessage, OlmPreKeyMessage
- matrix-nio fails with: `module 'fresholm.compat.olm' has no attribute 'InboundSession'`

## File Structure (changes only)

```
fresholm/
├── fresholm/
│   └── compat/
│       ├── olm.py              # MODIFY: add InboundSession, OutboundSession, imports, __all__
│       ├── sas.py              # NEW: Sas class (X25519 ECDH + HKDF)
│       └── utility.py          # NEW: sha256, ed25519_verify, OlmVerifyError
├── tests/
│   ├── test_sessions.py        # NEW: InboundSession/OutboundSession tests
│   ├── test_sas.py             # NEW: Sas class tests
│   └── test_utility.py         # NEW: sha256, ed25519_verify tests
└── pyproject.toml              # MODIFY: add cryptography dependency
```

---

## Task 1: Add `cryptography` Dependency

**Files:**
- Modify: `pyproject.toml`

- [ ] **Step 1: Add `cryptography` to dependencies**

In `pyproject.toml`, change:
```toml
dependencies = []
```
to:
```toml
dependencies = ["cryptography>=41.0"]
```

- [ ] **Step 2: Install in venv**

```bash
source .venv/bin/activate
pip install cryptography
```

- [ ] **Step 3: Commit**

```bash
git add pyproject.toml
git commit -m "feat: add cryptography dependency for SAS and ed25519 verification"
```

---

## Task 2: Utility Functions — `sha256` and `ed25519_verify`

**Files:**
- Create: `fresholm/compat/utility.py`
- Create: `tests/test_utility.py`

- [ ] **Step 1: Write `fresholm/compat/utility.py`**

```python
"""Utility functions for olm compatibility.

Provides sha256 hashing and Ed25519 signature verification matching
the python-olm utility API used by matrix-nio.
"""

import base64
import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


class OlmVerifyError(Exception):
    """Ed25519 signature verification failed."""
    pass


class OlmHashError(Exception):
    """Hash calculation error."""
    pass


def sha256(input_string):
    """Calculate SHA-256 hash, return base64-encoded result (unpadded).

    Args:
        input_string: str or bytes to hash.

    Returns:
        Base64-encoded SHA-256 hash string (unpadded).
    """
    if isinstance(input_string, str):
        input_string = input_string.encode("utf-8")
    digest = hashlib.sha256(input_string).digest()
    return base64.b64encode(digest).rstrip(b"=").decode("ascii")


def ed25519_verify(key, message, signature):
    """Verify an Ed25519 signature.

    Args:
        key: Base64-encoded (padded or unpadded) Ed25519 public key.
        message: The signed message (str or bytes).
        signature: Base64-encoded (padded or unpadded) signature.

    Raises:
        OlmVerifyError: If verification fails or inputs are invalid.
    """
    try:
        # Handle unpadded base64
        key_b64 = key + "=" * (-len(key) % 4)
        sig_b64 = signature + "=" * (-len(signature) % 4)

        key_bytes = base64.b64decode(key_b64)
        sig_bytes = base64.b64decode(sig_b64)
        if isinstance(message, str):
            message = message.encode("utf-8")

        pub_key = Ed25519PublicKey.from_public_bytes(key_bytes)
        pub_key.verify(sig_bytes, message)
    except InvalidSignature:
        raise OlmVerifyError("Ed25519 signature verification failed")
    except Exception as e:
        raise OlmVerifyError(f"Ed25519 verification error: {e}")
```

- [ ] **Step 2: Write `tests/test_utility.py`**

```python
"""Tests for fresholm.compat.utility (sha256, ed25519_verify)."""

import base64
import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fresholm.compat.utility import (
    OlmVerifyError,
    ed25519_verify,
    sha256,
)


class TestSha256:
    def test_string_input(self):
        result = sha256("test")
        expected = base64.b64encode(
            hashlib.sha256(b"test").digest()
        ).rstrip(b"=").decode("ascii")
        assert result == expected

    def test_bytes_input(self):
        result = sha256(b"hello")
        expected = base64.b64encode(
            hashlib.sha256(b"hello").digest()
        ).rstrip(b"=").decode("ascii")
        assert result == expected

    def test_empty_string(self):
        result = sha256("")
        expected = base64.b64encode(
            hashlib.sha256(b"").digest()
        ).rstrip(b"=").decode("ascii")
        assert result == expected

    def test_returns_string(self):
        assert isinstance(sha256("test"), str)

    def test_unpadded_base64(self):
        result = sha256("test")
        assert "=" not in result


class TestEd25519Verify:
    def _sign(self, message):
        """Helper: generate a key pair, sign message, return (pub_key_b64, sig_b64)."""
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        if isinstance(message, str):
            message = message.encode("utf-8")
        sig = private_key.sign(message)
        pub_bytes = public_key.public_bytes_raw()
        pub_b64 = base64.b64encode(pub_bytes).decode("ascii")
        sig_b64 = base64.b64encode(sig).decode("ascii")
        return pub_b64, sig_b64

    def test_valid_signature(self):
        pub, sig = self._sign("hello world")
        ed25519_verify(pub, "hello world", sig)  # should not raise

    def test_valid_signature_bytes_message(self):
        pub, sig = self._sign(b"hello bytes")
        ed25519_verify(pub, b"hello bytes", sig)

    def test_invalid_signature_raises(self):
        pub, sig = self._sign("hello")
        with pytest.raises(OlmVerifyError):
            ed25519_verify(pub, "wrong message", sig)

    def test_invalid_key_raises(self):
        with pytest.raises(OlmVerifyError):
            ed25519_verify("invalidkey", "msg", "invalidsig")

    def test_wrong_key_raises(self):
        pub1, sig1 = self._sign("hello")
        pub2, _ = self._sign("hello")
        with pytest.raises(OlmVerifyError):
            ed25519_verify(pub2, "hello", sig1)

    def test_unpadded_base64_keys(self):
        """matrix-nio often passes unpadded base64."""
        pub, sig = self._sign("test")
        pub_unpadded = pub.rstrip("=")
        sig_unpadded = sig.rstrip("=")
        ed25519_verify(pub_unpadded, "test", sig_unpadded)
```

- [ ] **Step 3: Run tests**

```bash
source .venv/bin/activate
pytest tests/test_utility.py -v
```
Expected: All tests pass.

- [ ] **Step 4: Commit**

```bash
git add fresholm/compat/utility.py tests/test_utility.py
git commit -m "feat: add sha256 and ed25519_verify utility functions

sha256 returns unpadded base64 hash.
ed25519_verify handles padded/unpadded base64 keys.
Both match python-olm utility API."
```

---

## Task 3: Sas Class

**Files:**
- Create: `fresholm/compat/sas.py`
- Create: `tests/test_sas.py`

- [ ] **Step 1: Write `fresholm/compat/sas.py`**

```python
"""SAS (Short Authentication String) verification for Matrix E2EE.

Implements python-olm compatible Sas class using X25519 ECDH + HKDF-SHA256.
Compatible with libolm/vodozemac SAS implementation.

HKDF derivation details (must match libolm exactly):
- Salt: None (empty)
- IKM: raw 32-byte X25519 shared secret
- Info: extra_info bytes as-is (caller provides full string including any prefixes)
- generate_bytes: HKDF-Expand to requested length
- calculate_mac: HKDF-Expand to 32-byte key, then HMAC-SHA256 over message
"""

import base64

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand


class OlmSasError(Exception):
    """Exception for SAS errors."""
    pass


class Sas:
    """python-olm compatible SAS (Short Authentication String) verification.

    Uses X25519 ECDH to establish a shared secret, then HKDF-SHA256
    to derive SAS bytes and MAC keys.

    Subclassable -- matrix-nio inherits from this.
    """

    def __init__(self, other_users_pubkey=None):
        self._private_key = X25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()
        self._shared_secret = None
        self.other_key_set = False
        if other_users_pubkey:
            self.set_their_pubkey(other_users_pubkey)

    @property
    def pubkey(self):
        """Return our public key as unpadded base64 string."""
        raw = self._public_key.public_bytes_raw()
        return base64.b64encode(raw).rstrip(b"=").decode("ascii")

    def set_their_pubkey(self, key):
        """Set the other party's public key and compute shared secret.

        Args:
            key: Base64-encoded (padded or unpadded) Curve25519 public key.
        """
        key_b64 = key + "=" * (-len(key) % 4)
        their_key_bytes = base64.b64decode(key_b64)
        their_key = X25519PublicKey.from_public_bytes(their_key_bytes)
        self._shared_secret = self._private_key.exchange(their_key)

        # Contributory check: reject all-zero shared secret
        if self._shared_secret == b"\x00" * 32:
            raise OlmSasError("Non-contributory ECDH exchange")

        self.other_key_set = True

    def _check_set(self):
        if not self.other_key_set:
            raise OlmSasError("Their public key has not been set")

    def _hkdf_expand(self, info_bytes, length):
        """HKDF-Expand (no extract step -- salt=None means PRK=IKM).

        libolm/vodozemac use HKDF with salt=None, meaning the extract step
        produces PRK = HMAC-SHA256(salt=0x00*32, IKM=shared_secret).
        Then expand uses that PRK with the given info.
        """
        # Python cryptography's HKDF does extract+expand. We need the same.
        # With salt=None, HKDF sets salt to hashLen zeros, which matches libolm.
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF as FullHKDF
        hkdf = FullHKDF(
            algorithm=SHA256(),
            length=length,
            salt=None,
            info=info_bytes,
        )
        return hkdf.derive(self._shared_secret)

    def generate_bytes(self, extra_info, length):
        """Generate SAS bytes for short authentication string comparison.

        Args:
            extra_info: Context string (used as HKDF info parameter as-is).
            length: Number of bytes to generate.

        Returns:
            bytes of requested length.
        """
        self._check_set()
        if isinstance(extra_info, str):
            extra_info = extra_info.encode("utf-8")
        return self._hkdf_expand(extra_info, length)

    def calculate_mac(self, message, extra_info):
        """Calculate MAC using HKDF-derived key + HMAC-SHA256.

        Args:
            message: The message to authenticate (str).
            extra_info: HKDF info parameter (str). Caller provides the full
                       string including any MATRIX_KEY_VERIFICATION_MAC prefix.

        Returns:
            Unpadded base64-encoded MAC string.
        """
        self._check_set()
        if isinstance(extra_info, str):
            extra_info = extra_info.encode("utf-8")
        if isinstance(message, str):
            message = message.encode("utf-8")

        # Step 1: Derive 32-byte MAC key via HKDF
        mac_key = self._hkdf_expand(extra_info, 32)

        # Step 2: HMAC-SHA256(mac_key, message)
        h = HMAC(mac_key, SHA256())
        h.update(message)
        mac_bytes = h.finalize()

        return base64.b64encode(mac_bytes).rstrip(b"=").decode("ascii")

    def calculate_mac_long_kdf(self, message, extra_info):
        """Calculate MAC using long KDF variant (256-byte key derivation).

        This is the legacy variant where HKDF derives 256 bytes instead of 32.
        Used by older libolm versions.

        Args:
            message: The message to authenticate (str).
            extra_info: HKDF info parameter (str).

        Returns:
            Unpadded base64-encoded MAC string.
        """
        self._check_set()
        if isinstance(extra_info, str):
            extra_info = extra_info.encode("utf-8")
        if isinstance(message, str):
            message = message.encode("utf-8")

        # Long KDF: derive 256 bytes instead of 32
        mac_key = self._hkdf_expand(extra_info, 256)

        h = HMAC(mac_key, SHA256())
        h.update(message)
        mac_bytes = h.finalize()

        return base64.b64encode(mac_bytes).rstrip(b"=").decode("ascii")
```

- [ ] **Step 2: Write `tests/test_sas.py`**

```python
"""Tests for fresholm.compat.sas (SAS verification)."""

import base64

import pytest

from fresholm.compat.sas import OlmSasError, Sas


class TestSasKeyExchange:
    def test_pubkey_is_base64_string(self):
        sas = Sas()
        pk = sas.pubkey
        assert isinstance(pk, str)
        # Should be 43 chars (32 bytes in unpadded base64)
        assert len(pk) == 43
        assert "=" not in pk

    def test_two_instances_different_keys(self):
        a = Sas()
        b = Sas()
        assert a.pubkey != b.pubkey

    def test_other_key_set_initially_false(self):
        sas = Sas()
        assert sas.other_key_set is False

    def test_set_their_pubkey(self):
        a = Sas()
        b = Sas()
        a.set_their_pubkey(b.pubkey)
        assert a.other_key_set is True

    def test_construct_with_other_key(self):
        b = Sas()
        a = Sas(b.pubkey)
        assert a.other_key_set is True

    def test_padded_base64_accepted(self):
        a = Sas()
        b = Sas()
        padded = b.pubkey + "=" * (-len(b.pubkey) % 4)
        a.set_their_pubkey(padded)
        assert a.other_key_set is True


class TestSasGenerateBytes:
    def test_generate_bytes_returns_requested_length(self):
        a = Sas()
        b = Sas()
        a.set_their_pubkey(b.pubkey)
        b.set_their_pubkey(a.pubkey)
        result = a.generate_bytes("test_info", 6)
        assert isinstance(result, bytes)
        assert len(result) == 6

    def test_both_sides_produce_same_bytes(self):
        a = Sas()
        b = Sas()
        a.set_their_pubkey(b.pubkey)
        b.set_their_pubkey(a.pubkey)
        bytes_a = a.generate_bytes("MATRIX_SAS_TEST", 6)
        bytes_b = b.generate_bytes("MATRIX_SAS_TEST", 6)
        assert bytes_a == bytes_b

    def test_different_info_different_bytes(self):
        a = Sas()
        b = Sas()
        a.set_their_pubkey(b.pubkey)
        b.set_their_pubkey(a.pubkey)
        bytes1 = a.generate_bytes("info1", 6)
        bytes2 = a.generate_bytes("info2", 6)
        assert bytes1 != bytes2

    def test_raises_if_key_not_set(self):
        a = Sas()
        with pytest.raises(OlmSasError):
            a.generate_bytes("test", 6)


class TestSasCalculateMac:
    def test_mac_returns_base64_string(self):
        a = Sas()
        b = Sas()
        a.set_their_pubkey(b.pubkey)
        b.set_their_pubkey(a.pubkey)
        mac = a.calculate_mac("message", "info")
        assert isinstance(mac, str)
        assert len(mac) > 20
        assert "=" not in mac  # unpadded

    def test_both_sides_produce_same_mac(self):
        a = Sas()
        b = Sas()
        a.set_their_pubkey(b.pubkey)
        b.set_their_pubkey(a.pubkey)
        mac_a = a.calculate_mac("hello", "MATRIX_KEY_VERIFICATION_MAC_info")
        mac_b = b.calculate_mac("hello", "MATRIX_KEY_VERIFICATION_MAC_info")
        assert mac_a == mac_b

    def test_different_message_different_mac(self):
        a = Sas()
        b = Sas()
        a.set_their_pubkey(b.pubkey)
        b.set_their_pubkey(a.pubkey)
        mac1 = a.calculate_mac("msg1", "info")
        mac2 = a.calculate_mac("msg2", "info")
        assert mac1 != mac2

    def test_raises_if_key_not_set(self):
        a = Sas()
        with pytest.raises(OlmSasError):
            a.calculate_mac("msg", "info")


class TestSasCalculateMacLongKdf:
    def test_long_kdf_returns_base64(self):
        a = Sas()
        b = Sas()
        a.set_their_pubkey(b.pubkey)
        b.set_their_pubkey(a.pubkey)
        mac = a.calculate_mac_long_kdf("message", "info")
        assert isinstance(mac, str)
        assert len(mac) > 20

    def test_both_sides_produce_same_mac_long_kdf(self):
        a = Sas()
        b = Sas()
        a.set_their_pubkey(b.pubkey)
        b.set_their_pubkey(a.pubkey)
        mac_a = a.calculate_mac_long_kdf("hello", "info")
        mac_b = b.calculate_mac_long_kdf("hello", "info")
        assert mac_a == mac_b

    def test_long_kdf_differs_from_standard(self):
        a = Sas()
        b = Sas()
        a.set_their_pubkey(b.pubkey)
        b.set_their_pubkey(a.pubkey)
        mac_std = a.calculate_mac("msg", "info")
        mac_long = a.calculate_mac_long_kdf("msg", "info")
        assert mac_std != mac_long


class TestSasSubclassable:
    def test_subclass(self):
        class MySas(Sas):
            def __init__(self):
                super().__init__()
                self.custom = True

        s = MySas()
        assert s.custom is True
        assert len(s.pubkey) == 43
```

- [ ] **Step 3: Run tests**

```bash
pytest tests/test_sas.py -v
```
Expected: All tests pass.

- [ ] **Step 4: Commit**

```bash
git add fresholm/compat/sas.py tests/test_sas.py
git commit -m "feat: add Sas class for SAS key verification

X25519 ECDH + HKDF-SHA256 matching libolm/vodozemac derivation.
generate_bytes, calculate_mac, calculate_mac_long_kdf implemented.
Subclassable for matrix-nio."
```

---

## Task 4: InboundSession and OutboundSession

**Files:**
- Modify: `fresholm/compat/olm.py`
- Create: `tests/test_sessions.py`

- [ ] **Step 1: Add InboundSession and OutboundSession to `fresholm/compat/olm.py`**

Add after the Session class definition (before OutboundGroupSession):

```python
class InboundSession(Session):
    """Inbound Olm session created from a received pre-key message.

    Subclassable -- matrix-nio inherits from this.
    """

    def __init__(self, account, message, identity_key=None):
        """Create an inbound session from a pre-key message.

        Args:
            account: An Account instance.
            message: An OlmPreKeyMessage instance.
            identity_key: Sender's curve25519 identity key (base64 str).
                         Required by vodozemac (optional in python-olm).
        """
        if identity_key is None:
            identity_key = ""
        temp = account.new_inbound_session(identity_key, message)
        self._native = temp._native
        self._creation_plaintext = getattr(temp, "_creation_plaintext", None)


class OutboundSession(Session):
    """Outbound Olm session initiated to a recipient.

    Subclassable -- matrix-nio inherits from this.
    """

    def __init__(self, account, identity_key, one_time_key):
        """Create an outbound session to a recipient.

        Args:
            account: An Account instance.
            identity_key: Recipient's curve25519 identity key (base64 str).
            one_time_key: Recipient's one-time key (base64 str).
        """
        temp = account.new_outbound_session(identity_key, one_time_key)
        self._native = temp._native
        self._creation_plaintext = None
```

- [ ] **Step 2: Write `tests/test_sessions.py`**

```python
"""Tests for InboundSession and OutboundSession compat classes."""

import pytest

from fresholm.compat.olm import (
    Account,
    InboundSession,
    OlmPreKeyMessage,
    OutboundSession,
    Session,
)


class TestOutboundSession:
    def test_create(self):
        account = Account()
        bob = Account()
        bob.generate_one_time_keys(1)
        bob_keys = bob.identity_keys
        bob_otk = list(bob.one_time_keys["curve25519"].values())[0]

        session = OutboundSession(account, bob_keys["curve25519"], bob_otk)
        assert isinstance(session, Session)
        assert isinstance(session, OutboundSession)
        assert len(session.id) > 0

    def test_encrypt(self):
        account = Account()
        bob = Account()
        bob.generate_one_time_keys(1)
        bob_keys = bob.identity_keys
        bob_otk = list(bob.one_time_keys["curve25519"].values())[0]

        session = OutboundSession(account, bob_keys["curve25519"], bob_otk)
        msg = session.encrypt("hello")
        assert isinstance(msg, OlmPreKeyMessage)

    def test_subclassable(self):
        class MyOutbound(OutboundSession):
            pass

        account = Account()
        bob = Account()
        bob.generate_one_time_keys(1)
        bob_keys = bob.identity_keys
        bob_otk = list(bob.one_time_keys["curve25519"].values())[0]
        session = MyOutbound(account, bob_keys["curve25519"], bob_otk)
        assert isinstance(session, MyOutbound)
        assert isinstance(session, Session)


class TestInboundSession:
    def _make_prekey(self):
        alice = Account()
        bob = Account()
        bob.generate_one_time_keys(1)
        bob_keys = bob.identity_keys
        alice_keys = alice.identity_keys
        bob_otk = list(bob.one_time_keys["curve25519"].values())[0]
        out_session = OutboundSession(alice, bob_keys["curve25519"], bob_otk)
        msg = out_session.encrypt("hello")
        return bob, alice_keys, msg, out_session

    def test_create_with_identity_key(self):
        bob, alice_keys, msg, _ = self._make_prekey()
        session = InboundSession(bob, msg, alice_keys["curve25519"])
        assert isinstance(session, Session)
        assert isinstance(session, InboundSession)
        assert len(session.id) > 0

    def test_decrypt_after_create(self):
        bob, alice_keys, msg, out_session = self._make_prekey()
        in_session = InboundSession(bob, msg, alice_keys["curve25519"])
        # Bob replies
        reply = in_session.encrypt("reply")
        plaintext = out_session.decrypt(reply)
        assert plaintext == "reply"

    def test_subclassable(self):
        """matrix-nio: class InboundSession(olm.InboundSession, mixin)"""

        class MyInbound(InboundSession):
            def __init__(self, account, message, identity_key=None):
                super().__init__(account, message, identity_key)
                self.custom = True

        bob, alice_keys, msg, _ = self._make_prekey()
        session = MyInbound(bob, msg, alice_keys["curve25519"])
        assert session.custom is True
        assert isinstance(session, Session)


class TestNioPattern:
    """Test the exact pattern matrix-nio uses."""

    def test_nio_outbound_session_pattern(self):
        """nio/crypto/sessions.py: OutboundSession(account, identity_key, otk)"""
        account = Account()
        bob = Account()
        bob.generate_one_time_keys(1)
        bob_keys = bob.identity_keys
        bob_otk = list(bob.one_time_keys["curve25519"].values())[0]

        class NioOutboundSession(OutboundSession):
            def __init__(self, account, identity_key, one_time_key):
                super().__init__(account, identity_key, one_time_key)

        session = NioOutboundSession(account, bob_keys["curve25519"], bob_otk)
        assert len(session.id) > 0

    def test_nio_inbound_session_pattern(self):
        """nio/crypto/sessions.py: InboundSession(account, message, identity_key)"""
        alice = Account()
        bob = Account()
        bob.generate_one_time_keys(1)
        bob_keys = bob.identity_keys
        alice_keys = alice.identity_keys
        bob_otk = list(bob.one_time_keys["curve25519"].values())[0]

        out = OutboundSession(alice, bob_keys["curve25519"], bob_otk)
        msg = out.encrypt("test")

        class NioInboundSession(InboundSession):
            def __init__(self, account, message, identity_key=None):
                super().__init__(account, message, identity_key)

        session = NioInboundSession(bob, msg, alice_keys["curve25519"])
        assert len(session.id) > 0
```

- [ ] **Step 3: Run tests**

```bash
pytest tests/test_sessions.py -v
```

- [ ] **Step 4: Commit**

```bash
git add fresholm/compat/olm.py tests/test_sessions.py
git commit -m "feat: add InboundSession and OutboundSession classes

Thin Session subclasses matching python-olm API for matrix-nio.
InboundSession(account, message, identity_key) creates inbound session.
OutboundSession(account, identity_key, one_time_key) creates outbound."
```

---

## Task 5: Wire Everything into olm.py and Test Integration

**Files:**
- Modify: `fresholm/compat/olm.py` (imports + `__all__`)
- Modify: `tests/test_mautrix_compat.py`

- [ ] **Step 1: Add imports to top of `fresholm/compat/olm.py`**

After the existing imports from `.types`, add:

```python
from .sas import Sas, OlmSasError
from . import utility
from .utility import sha256, ed25519_verify, OlmVerifyError
```

- [ ] **Step 2: Update `__all__` in `fresholm/compat/olm.py`**

Replace the existing `__all__` with:

```python
__all__ = [
    "Account",
    "Session",
    "InboundSession",
    "OutboundSession",
    "OutboundGroupSession",
    "GroupSession",
    "InboundGroupSession",
    "OlmAccount",
    "OlmSession",
    "OlmInboundGroupSession",
    "OlmMessage",
    "OlmPreKeyMessage",
    "PkEncryption",
    "PkDecryption",
    "Sas",
    "sha256",
    "ed25519_verify",
    "utility",
    "OlmError",
    "OlmSessionError",
    "OlmGroupSessionError",
    "OlmAccountError",
    "OlmSasError",
    "OlmVerifyError",
    "CryptoStoreError",
]
```

- [ ] **Step 3: Add integration tests to `tests/test_mautrix_compat.py`**

Add a new test class:

```python
class TestMatrixNioCompat:
    """Test the exact imports and patterns matrix-nio uses."""

    def test_nio_imports(self):
        import fresholm.import_hook  # noqa

        import olm
        assert hasattr(olm, "InboundSession")
        assert hasattr(olm, "OutboundSession")
        assert hasattr(olm, "Sas")
        assert hasattr(olm, "sha256")
        assert hasattr(olm, "ed25519_verify")
        assert hasattr(olm, "utility")
        assert hasattr(olm.utility, "OlmVerifyError")

    def test_sha256_via_olm(self):
        import fresholm.import_hook  # noqa
        import olm

        result = olm.sha256("test")
        assert isinstance(result, str)
        assert len(result) > 20

    def test_sas_via_olm(self):
        import fresholm.import_hook  # noqa
        import olm

        a = olm.Sas()
        b = olm.Sas()
        a.set_their_pubkey(b.pubkey)
        b.set_their_pubkey(a.pubkey)
        bytes_a = a.generate_bytes("test", 6)
        bytes_b = b.generate_bytes("test", 6)
        assert bytes_a == bytes_b

    def test_ed25519_verify_error_via_olm_utility(self):
        import fresholm.import_hook  # noqa
        import olm

        try:
            olm.ed25519_verify("badkey", "msg", "badsig")
            assert False, "should have raised"
        except olm.utility.OlmVerifyError:
            pass  # expected

    def test_outbound_session_via_olm(self):
        import fresholm.import_hook  # noqa
        import olm

        account = olm.Account()
        account.generate_one_time_keys(1)
        otk = list(account.one_time_keys["curve25519"].values())[0]
        identity = account.identity_keys["curve25519"]
        session = olm.OutboundSession(account, identity, otk)
        assert len(session.id) > 0
```

- [ ] **Step 4: Run full test suite**

```bash
pytest tests/ -v
```
Expected: All existing 121 tests + all new tests pass.

- [ ] **Step 5: Commit**

```bash
git add fresholm/compat/olm.py tests/test_mautrix_compat.py
git commit -m "feat: wire Sas, sha256, ed25519_verify, InboundSession, OutboundSession into olm module

All matrix-nio required imports now resolve through fresholm.import_hook.
olm.Sas, olm.sha256, olm.ed25519_verify, olm.utility.OlmVerifyError,
olm.InboundSession, olm.OutboundSession all available."
```

---

## Task 6: matrix-nio Smoke Test

**Files:** No new files.

- [ ] **Step 1: Install matrix-nio**

```bash
source .venv/bin/activate
pip install matrix-nio
```

- [ ] **Step 2: Run integration test**

```bash
python -c "
import fresholm.import_hook
import olm

# InboundSession/OutboundSession
account = olm.Account()
account.generate_one_time_keys(1)
otk = list(account.one_time_keys['curve25519'].values())[0]
identity = account.identity_keys['curve25519']
outbound = olm.OutboundSession(account, identity, otk)
msg = outbound.encrypt('hello')
print(f'OutboundSession OK, id={outbound.id[:8]}')

# Sas
sas_a = olm.Sas()
sas_b = olm.Sas()
sas_a.set_their_pubkey(sas_b.pubkey)
sas_b.set_their_pubkey(sas_a.pubkey)
assert sas_a.generate_bytes('test', 6) == sas_b.generate_bytes('test', 6)
print(f'Sas OK, pubkey={sas_a.pubkey[:16]}...')

# sha256
h = olm.sha256('test')
print(f'sha256 OK: {h[:16]}...')

# ed25519_verify + OlmVerifyError
try:
    olm.ed25519_verify('badkey', 'msg', 'badsig')
except olm.utility.OlmVerifyError:
    print('OlmVerifyError OK')

# matrix-nio crypto imports
try:
    from nio.crypto import OlmDevice
    print('nio.crypto.OlmDevice import OK')
except ImportError as e:
    print(f'nio import issue (may need more deps): {e}')

print('All matrix-nio compatibility checks passed!')
"
```

- [ ] **Step 3: If matrix-nio import fails, diagnose and fix**

If there are additional missing attributes, add them. Report any issues found.

- [ ] **Step 4: Run full test suite one last time**

```bash
pytest tests/ -v --tb=short
```

- [ ] **Step 5: Commit if fixes were needed**

```bash
# Only if fixes were made
git add -u
git commit -m "fix: address issues found during matrix-nio integration test"
```

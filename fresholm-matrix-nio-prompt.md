# Task: Add missing matrix-nio compatibility classes to fresholm's compat layer

## Context

fresholm (github.com/cortexuvula/fresholm) is a Python package providing
python-olm compatible wrappers around Rust/vodozemac native bindings. It
eliminates the need for libolm C library. The compat layer at
fresholm/compat/olm.py currently wraps: Account, Session, InboundGroupSession,
OutboundGroupSession, PkEncryption, PkDecryption, OlmMessage, OlmPreKeyMessage.

matrix-nio (the Matrix client library) needs 5 additional items from the `olm`
module that fresholm doesn't provide yet. When importing olm via fresholm's
import_hook, matrix-nio fails with "module 'fresholm.compat.olm' has no
attribute 'InboundSession'".

**Goal**: Add the following to fresholm/compat/olm.py so that `import fresholm.import_hook`
followed by `import olm` allows matrix-nio to work fully.

## Files to Modify

- `fresholm/compat/olm.py` (main compat layer, 482 lines)
- `fresholm/compat/types.py` (exception classes, 30 lines)

## Files to Create

- `fresholm/compat/sas.py` (Sas class implementation)
- `fresholm/compat/utility.py` (sha256, ed25519_verify, OlmVerifyError)

---

## Item 1: InboundSession (in olm.py)

matrix-nio usage (nio/crypto/sessions.py line 83-98):
```python
class InboundSession(olm.InboundSession, _SessionExpirationMixin):
    def __init__(self, account, message, identity_key=None):
        super().__init__(account, message, identity_key)
```

python-olm API:
- `__init__(self, account: Account, message: OlmPreKeyMessage, identity_key: Optional[str] = None)`
- Inherits from Session, has encrypt(), decrypt(), matches(), pickle(), from_pickle()

Implementation: Subclass of fresholm's Session. In __init__, delegate to
`account.new_inbound_session()` which already handles the native call.
The identity_key parameter is the sender's curve25519 key (optional in python-olm,
but fresholm's native create_inbound_session requires it).

```python
class InboundSession(Session):
    """Inbound Olm session created from a received pre-key message."""

    def __init__(self, account, message, identity_key=None):
        # Delegate to Account.new_inbound_session which handles the native call
        # identity_key is the sender's curve25519 key
        temp = account.new_inbound_session(identity_key or "", message)
        self._native = temp._native
```

---

## Item 2: OutboundSession (in olm.py)

matrix-nio usage (nio/crypto/sessions.py line 101-116):
```python
class OutboundSession(olm.OutboundSession, _SessionExpirationMixin):
    def __init__(self, account, identity_key, one_time_key):
        super().__init__(account, identity_key, one_time_key)
```

python-olm API:
- `__init__(self, account: Account, identity_key: str, one_time_key: str)`
- Inherits from Session

```python
class OutboundSession(Session):
    """Outbound Olm session initiated to a recipient's identity and one-time key."""

    def __init__(self, account, identity_key, one_time_key):
        temp = account.new_outbound_session(identity_key, one_time_key)
        self._native = temp._native
```

---

## Item 3: Sas class (NEW FILE: fresholm/compat/sas.py)

matrix-nio usage (nio/crypto/sas.py):
```python
class Sas(olm.Sas):
    # Uses: self.pubkey, self.other_key_set
    # Calls: self.set_their_pubkey(key), self.generate_bytes(extra_info, length)
    # Calls: self.calculate_mac(message, extra_info), self.calculate_mac_long_kdf(message, extra_info)
    # Also uses: olm.sha256(self.pubkey + string_content)
```

python-olm Sas API:
- `__init__(self, other_users_pubkey=None)`
- `pubkey` property -> base64-encoded Curve25519 public key
- `other_key_set` property -> bool
- `set_their_pubkey(key: str) -> None`
- `generate_bytes(extra_info: str, length: int) -> bytes`
- `calculate_mac(message: str, extra_info: str) -> str` (HKDF-HMAC-SHA256)
- `calculate_mac_long_kdf(message: str, extra_info: str) -> str` (HMAC-SHA256, legacy)

The SAS protocol:
1. Each side generates a Curve25519 keypair
2. They exchange public keys
3. Perform ECDH to get shared secret
4. Derive bytes/MAC from shared secret using HKDF

Implementation using Python's `cryptography` library:

```python
"""SAS (Short Authentication String) verification for Matrix E2EE."""

import base64
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.hmac import HMAC


class OlmSasError(Exception):
    """Exception for SAS errors."""


class Sas:
    """python-olm compatible Sas class for Matrix key verification.

    Uses Curve25519 ECDH + HKDF to derive shared secrets for
    short authentication string verification.
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
        """Return public key as base64 string."""
        return base64.b64encode(
            self._public_key.public_bytes_raw()
        ).decode("ascii")

    def set_their_pubkey(self, key):
        """Set the other party's public key and compute shared secret."""
        their_key_bytes = base64.b64decode(key)
        their_key = X25519PublicKey.from_public_bytes(their_key_bytes)
        self._shared_secret = self._private_key.exchange(their_key)
        self.other_key_set = True

    def _check_other_key(self):
        if not self.other_key_set:
            raise OlmSasError("The other public key isn't set.")

    def _hkdf(self, info: bytes, length: int) -> bytes:
        """Derive key material from shared secret using HKDF-SHA256."""
        hkdf = HKDF(
            algorithm=SHA256(),
            length=length,
            salt=b"",
            info=info,
        )
        return hkdf.derive(self._shared_secret)

    def generate_bytes(self, extra_info, length):
        """Generate SAS bytes for short authentication string.

        Args:
            extra_info: String context mixed into derivation.
            length: Number of bytes to generate.

        Returns:
            bytes of length `length` for SAS comparison.
        """
        self._check_other_key()
        if length < 1:
            raise ValueError("length must be positive")
        # The info string for SAS byte generation in libolm is:
        # "MATRIX_KEY_VERIFICATION_SAS" + extra_info
        # But actually libolm's olm_sas_generate_bytes uses the raw extra_info
        # concatenated. Verify against libolm source.
        info = b"MATRIX_KEY_VERIFICATION_SAS" + extra_info.encode("utf-8")
        return self._hkdf(info, length)

    def calculate_mac(self, message, extra_info):
        """Calculate MAC using HKDF-HMAC-SHA256.

        Args:
            message: The message to authenticate.
            extra_info: Additional context string.

        Returns:
            Base64-encoded MAC string.
        """
        self._check_other_key()
        # Derive MAC key using HKDF
        info = b"MATRIX_KEY_VERIFICATION_MAC" + extra_info.encode("utf-8")
        mac_key = self._hkdf(info, 32)
        h = HMAC(mac_key, SHA256())
        h.update(message.encode("utf-8"))
        return base64.b64encode(h.finalize()).decode("ascii")

    def calculate_mac_long_kdf(self, message, extra_info):
        """Calculate MAC using legacy HMAC-SHA256 (long KDF).

        Args:
            message: The message to authenticate.
            extra_info: Additional context string.

        Returns:
            Base64-encoded MAC string.
        """
        self._check_other_key()
        # Legacy: use raw shared secret as HMAC key
        h = HMAC(self._shared_secret, SHA256())
        h.update((message + extra_info).encode("utf-8"))
        return base64.b64encode(h.finalize()).decode("ascii")
```

**CRITICAL**: The HKDF info strings and derivation process MUST match what
python-olm/libolm does internally. The strings above are guesses based on
matrix-nio's higher-level code. You MUST:

1. Read the libolm C source for `olm_sas_generate_bytes`, `olm_sas_calculate_mac`
2. Or test empirically: install python-olm on a Linux box, create matching
   Sas objects on both sides, and compare outputs with fresholm
3. The info strings may be just the raw `extra_info` without "MATRIX_*" prefixes

---

## Item 4: olm.sha256 function

matrix-nio usage (nio/crypto/sas.py line 247):
```python
obj.commitment = olm.sha256(obj.pubkey + string_content)
```

python-olm API:
- `sha256(input_string: str) -> str`
- Returns base64-encoded SHA-256 hash
- Accepts str or bytes

Place in `fresholm/compat/utility.py`:

```python
"""Utility functions for olm compatibility."""

import base64
import hashlib


def sha256(input_string):
    """Calculate SHA-256 hash, return base64-encoded result."""
    if isinstance(input_string, str):
        input_string = input_string.encode("utf-8")
    return base64.b64encode(hashlib.sha256(input_string).digest()).decode("ascii")
```

---

## Item 5: olm.ed25519_verify and olm.utility.OlmVerifyError

matrix-nio usage (nio/crypto/olm_machine.py lines 1858-1860):
```python
olm.ed25519_verify(user_key, Api.to_canonical_json(json), signature_base64)
except olm.utility.OlmVerifyError:
```

python-olm API:
- `ed25519_verify(key: str, message: str, signature: str) -> None`
- Raises `OlmVerifyError` on failure
- key and signature are base64-encoded

Add to `fresholm/compat/utility.py`:

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class OlmVerifyError(Exception):
    """Ed25519 signature verification failed."""


class OlmHashError(Exception):
    """Hash calculation error."""


def ed25519_verify(key, message, signature):
    """Verify an Ed25519 signature.

    Args:
        key: Base64-encoded Ed25519 public key.
        message: The signed message (str or bytes).
        signature: Base64-encoded signature.

    Raises:
        OlmVerifyError: If verification fails.
    """
    try:
        key_bytes = base64.b64decode(key)
        sig_bytes = base64.b64decode(signature)
        if isinstance(message, str):
            message = message.encode("utf-8")

        pub_key = Ed25519PublicKey.from_public_bytes(key_bytes)
        pub_key.verify(sig_bytes, message)
    except Exception:
        raise OlmVerifyError("Ed25519 signature verification failed")
```

---

## Item 6: Wire everything into olm.py

At the top of olm.py, add imports:
```python
from .sas import Sas, OlmSasError
from . import utility
from .utility import sha256, ed25519_verify, OlmVerifyError
```

Add the new classes to `__all__`:
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
    "CryptoStoreError",
]
```

This ensures `olm.InboundSession`, `olm.OutboundSession`, `olm.Sas`,
`olm.sha256`, `olm.ed25519_verify`, `olm.utility`, and `olm.utility.OlmVerifyError`
all resolve correctly through the import_hook.

---

## Testing

After implementation, verify with:
```python
import fresholm.import_hook
import olm

# Test InboundSession/OutboundSession
account = olm.Account()
account.generate_one_time_keys(1)
otk = list(account.one_time_keys["curve25519"].values())[0]
identity = account.identity_keys["curve25519"]
outbound = olm.OutboundSession(account, identity, otk)
msg = outbound.encrypt("hello")
print(f"OutboundSession OK, session_id={outbound.id}")

# Test Sas
sas_a = olm.Sas()
sas_b = olm.Sas()
sas_a.set_their_pubkey(sas_b.pubkey)
sas_b.set_their_pubkey(sas_a.pubkey)
print(f"Sas pubkey: {sas_a.pubkey[:16]}...")
print(f"Shared bytes: {sas_a.generate_bytes('test', 5).hex()}")

# Test sha256
h = olm.sha256("test")
print(f"sha256: {h}")

# Test ed25519_verify + OlmVerifyError
try:
    olm.ed25519_verify("badkey", "badmsg", "badsig")
    print("ERROR: should have raised")
except olm.utility.OlmVerifyError:
    print("OlmVerifyError works!")

# Test with matrix-nio
from nio.crypto import OlmDevice, OutgoingKeyRequest
print("nio.crypto imports OK - integration complete!")
```

---

## Constraints

- Do NOT modify the Rust native module (`_native.cpython-*.so`)
- All new code must be pure Python using only: `hashlib`, `base64`, and
  the `cryptography` library (already a dependency of matrix-nio via pycryptodome)
- Follow the existing coding style in olm.py (type hints, docstrings, __repr__)
- The Sas HKDF derivation MUST produce identical output to python-olm's libolm
  binding for matrix-nio's key verification to work. Test carefully.
- Work on a branch and PR against `github.com/cortexuvula/fresholm`

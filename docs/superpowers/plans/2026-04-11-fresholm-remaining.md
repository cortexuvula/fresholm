# fresholm Remaining Work Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the remaining spec success criteria: PkEncryption/PkDecryption, Session.matches(), README, and mautrix-python validation.

**Architecture:** Extends the existing three-layer stack. PkEncryption/PkDecryption adds a new Rust module (`pk.rs`) behind vodozemac's `insecure-pk-encryption` feature flag, with corresponding Python compat wrappers. Session.matches() adds a Rust-side key comparison method. README and validation are non-code tasks.

**Tech Stack:** Rust 1.94+, vodozemac 0.9 (with `insecure-pk-encryption` feature), PyO3 0.28, base64 0.22, Python 3.10+, pytest

---

## Current State

- 107 tests passing
- 10 commits on main
- All Olm/Megolm operations working through compat layer
- Import hook verified
- Crypto store implemented
- CI workflows in place
- Native serialization methods named `to_encrypted_string`/`from_encrypted_string`

## Remaining Spec Success Criteria

| Criteria | Status |
|----------|--------|
| PkEncryption/PkDecryption works | **Not done** |
| Session.matches() works correctly | **Stubbed (returns False)** |
| `pip install fresholm` works cross-platform | **Needs GitHub push + release** |
| mautrix bridge end-to-end with E2EE | **Not tested** |

---

## File Structure (changes only)

```
fresholm/
├── crates/
│   └── vodozemac-python/
│       ├── Cargo.toml                 # Add insecure-pk-encryption feature + base64 dep
│       └── src/
│           ├── pk.rs                  # NEW: PkEncryption/PkDecryption bindings
│           ├── session.rs             # MODIFY: add matches_prekey method
│           └── lib.rs                 # MODIFY: register Pk classes
├── fresholm/
│   └── compat/
│       └── olm.py                    # MODIFY: add PkEncryption, PkDecryption, fix matches()
├── tests/
│   ├── test_pk.py                    # NEW: PkEncryption/PkDecryption tests
│   ├── test_session.py               # MODIFY: add matches() tests
│   └── test_mautrix_compat.py        # MODIFY: add Pk import tests
└── README.md                         # NEW
```

---

## Task 1: PkEncryption / PkDecryption

**Files:**
- Modify: `crates/vodozemac-python/Cargo.toml`
- Create: `crates/vodozemac-python/src/pk.rs`
- Modify: `crates/vodozemac-python/src/lib.rs`
- Modify: `fresholm/compat/olm.py`
- Create: `tests/test_pk.py`
- Modify: `tests/test_mautrix_compat.py`

- [ ] **Step 1: Add dependencies to `crates/vodozemac-python/Cargo.toml`**

Change the `[dependencies]` section to:
```toml
[dependencies]
vodozemac = { version = "0.9", features = ["insecure-pk-encryption"] }
pyo3 = { version = "0.28", features = ["extension-module"] }
base64 = "0.22"
```

- [ ] **Step 2: Verify it compiles**

```bash
cargo check
```
Expected: Compiles (vodozemac downloads with the new feature).

- [ ] **Step 3: Write `crates/vodozemac-python/src/pk.rs`**

```rust
use pyo3::prelude::*;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

use vodozemac::pk_encryption::{
    Message as VzPkMessage, PkDecryption as VzPkDecryption, PkEncryption as VzPkEncryption,
};
use vodozemac::{Curve25519PublicKey, Curve25519SecretKey};

use crate::errors::OlmError;

/// Result of PkEncryption.encrypt(). Contains ciphertext, mac, and ephemeral_key as base64.
#[pyclass]
#[derive(Clone)]
pub struct PkMessage {
    #[pyo3(get)]
    pub ciphertext: String,
    #[pyo3(get)]
    pub mac: String,
    #[pyo3(get)]
    pub ephemeral_key: String,
}

#[pymethods]
impl PkMessage {
    fn __repr__(&self) -> String {
        "<PkMessage>".to_string()
    }
}

#[pyclass]
pub struct PkEncryption {
    inner: VzPkEncryption,
}

#[pymethods]
impl PkEncryption {
    /// Create from a recipient's curve25519 public key (base64).
    #[new]
    fn new(recipient_key: &str) -> PyResult<Self> {
        let pubkey = Curve25519PublicKey::from_base64(recipient_key)
            .map_err(|e| OlmError::new_err(format!("Invalid recipient key: {e}")))?;
        Ok(Self {
            inner: VzPkEncryption::from_key(pubkey),
        })
    }

    /// Encrypt plaintext. Returns a PkMessage with ciphertext, mac, ephemeral_key (all base64).
    fn encrypt(&self, plaintext: &[u8]) -> PkMessage {
        let msg = self.inner.encrypt(plaintext);
        PkMessage {
            ciphertext: BASE64.encode(&msg.ciphertext),
            mac: BASE64.encode(&msg.mac),
            ephemeral_key: msg.ephemeral_key.to_base64(),
        }
    }
}

#[pyclass]
pub struct PkDecryption {
    inner: VzPkDecryption,
}

#[pymethods]
impl PkDecryption {
    /// Create a new PkDecryption with a random key pair, or from a secret key (base64).
    #[new]
    #[pyo3(signature = (secret_key=None))]
    fn new(secret_key: Option<&str>) -> PyResult<Self> {
        if let Some(sk) = secret_key {
            let key = Curve25519SecretKey::from_base64(sk)
                .map_err(|e| OlmError::new_err(format!("Invalid secret key: {e}")))?;
            Ok(Self {
                inner: VzPkDecryption::from_key(key),
            })
        } else {
            Ok(Self {
                inner: VzPkDecryption::new(),
            })
        }
    }

    /// Get the public key (base64).
    #[getter]
    fn public_key(&self) -> String {
        self.inner.public_key().to_base64()
    }

    /// Decrypt a message. Takes ciphertext, mac, ephemeral_key (all base64).
    /// Returns plaintext bytes.
    fn decrypt(
        &self,
        ciphertext: &str,
        mac: &str,
        ephemeral_key: &str,
    ) -> PyResult<Vec<u8>> {
        let msg = VzPkMessage::from_base64(ciphertext, mac, ephemeral_key)
            .map_err(|e| OlmError::new_err(format!("Invalid message: {e}")))?;
        self.inner
            .decrypt(&msg)
            .map_err(|e| OlmError::new_err(format!("Decryption failed: {e}")))
    }

    fn __repr__(&self) -> String {
        "<PkDecryption>".to_string()
    }
}
```

> **Note:** If `VzPkEncryption::from_key` takes ownership, or `Curve25519SecretKey::from_base64` has a different return type, adjust during compilation. If vodozemac uses unpadded base64, switch `STANDARD` to `STANDARD_NO_PAD`.

- [ ] **Step 4: Register in `lib.rs`**

Add `mod pk;` to the module declarations.

Add to the `fresholm_native` function body:
```rust
m.add_class::<pk::PkEncryption>()?;
m.add_class::<pk::PkDecryption>()?;
m.add_class::<pk::PkMessage>()?;
```

- [ ] **Step 5: Build**

```bash
source .venv/bin/activate
maturin develop
```

- [ ] **Step 6: Verify from Python**

```bash
python -c "
from fresholm._native import PkEncryption, PkDecryption, PkMessage
dec = PkDecryption()
print(f'Public key: {dec.public_key[:20]}...')
enc = PkEncryption(dec.public_key)
msg = enc.encrypt(b'hello')
print(f'Encrypted: ct={msg.ciphertext[:20]}..., mac={msg.mac[:10]}...')
pt = dec.decrypt(msg.ciphertext, msg.mac, msg.ephemeral_key)
assert pt == b'hello'
print('PK roundtrip OK')
"
```

- [ ] **Step 7: Add Python compat wrappers to `fresholm/compat/olm.py`**

Add after the InboundGroupSession class (before the aliases section):

```python
class PkEncryption:
    """Public-key encryption (one-way, anonymous).

    Encrypt messages to a recipient using their curve25519 public key.
    """

    def __init__(self, recipient_key):
        """Create from recipient's curve25519 public key (base64 string)."""
        from fresholm._native import PkEncryption as _NativePkEncryption
        self._native = _NativePkEncryption(recipient_key)

    def encrypt(self, plaintext):
        """Encrypt plaintext. Returns a PkMessage with .ciphertext, .mac, .ephemeral_key.

        Args:
            plaintext: str or bytes.
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        return self._native.encrypt(plaintext)


class PkDecryption:
    """Public-key decryption (counterpart to PkEncryption)."""

    def __init__(self, secret_key=None):
        """Create with a random key pair, or from an existing secret key (base64)."""
        from fresholm._native import PkDecryption as _NativePkDecryption
        self._native = _NativePkDecryption(secret_key)

    @property
    def public_key(self):
        """Public key (base64 string)."""
        return self._native.public_key

    def decrypt(self, ciphertext, mac, ephemeral_key):
        """Decrypt a message. Returns plaintext string.

        Args:
            ciphertext: base64 string.
            mac: base64 string.
            ephemeral_key: base64 string.
        """
        plaintext_bytes = self._native.decrypt(ciphertext, mac, ephemeral_key)
        return plaintext_bytes.decode("utf-8")
```

Add `"PkEncryption"` and `"PkDecryption"` to the `__all__` list.

- [ ] **Step 8: Write `tests/test_pk.py`**

```python
import pytest
from fresholm._native import (
    PkEncryption as NativePkEncryption,
    PkDecryption as NativePkDecryption,
    PkMessage,
)


class TestNativePkEncryption:
    def test_roundtrip(self):
        dec = NativePkDecryption()
        enc = NativePkEncryption(dec.public_key)
        msg = enc.encrypt(b"hello world")
        assert isinstance(msg, PkMessage)
        assert len(msg.ciphertext) > 0
        assert len(msg.mac) > 0
        assert len(msg.ephemeral_key) > 0
        pt = dec.decrypt(msg.ciphertext, msg.mac, msg.ephemeral_key)
        assert pt == b"hello world"

    def test_different_messages_different_ciphertext(self):
        dec = NativePkDecryption()
        enc = NativePkEncryption(dec.public_key)
        msg1 = enc.encrypt(b"aaa")
        msg2 = enc.encrypt(b"aaa")
        # Each encryption uses a new ephemeral key
        assert msg1.ephemeral_key != msg2.ephemeral_key

    def test_wrong_key_fails(self):
        dec1 = NativePkDecryption()
        dec2 = NativePkDecryption()
        enc = NativePkEncryption(dec1.public_key)
        msg = enc.encrypt(b"secret")
        with pytest.raises(Exception):
            dec2.decrypt(msg.ciphertext, msg.mac, msg.ephemeral_key)

    def test_invalid_recipient_key(self):
        with pytest.raises(Exception):
            NativePkEncryption("not_valid_base64!")

    def test_pk_decryption_public_key(self):
        dec = NativePkDecryption()
        pk = dec.public_key
        assert isinstance(pk, str)
        assert len(pk) > 20

    def test_two_decryptors_have_different_keys(self):
        dec1 = NativePkDecryption()
        dec2 = NativePkDecryption()
        assert dec1.public_key != dec2.public_key


from fresholm.compat.olm import (
    PkEncryption as CompatPkEncryption,
    PkDecryption as CompatPkDecryption,
)


class TestCompatPkEncryption:
    def test_roundtrip_with_strings(self):
        dec = CompatPkDecryption()
        enc = CompatPkEncryption(dec.public_key)
        msg = enc.encrypt("hello compat")
        pt = dec.decrypt(msg.ciphertext, msg.mac, msg.ephemeral_key)
        assert pt == "hello compat"
        assert isinstance(pt, str)

    def test_encrypt_accepts_bytes(self):
        dec = CompatPkDecryption()
        enc = CompatPkEncryption(dec.public_key)
        msg = enc.encrypt(b"bytes input")
        pt = dec.decrypt(msg.ciphertext, msg.mac, msg.ephemeral_key)
        assert pt == "bytes input"

    def test_public_key_is_property(self):
        dec = CompatPkDecryption()
        pk = dec.public_key  # property access
        assert isinstance(pk, str)
        assert len(pk) > 20

    def test_importable_from_olm(self):
        import fresholm.import_hook  # noqa
        from olm import PkEncryption, PkDecryption
        assert PkEncryption is not None
        assert PkDecryption is not None
```

- [ ] **Step 9: Add Pk assertions to `tests/test_mautrix_compat.py` TestImportHook**

In the `test_import_hook_installs` test, add:
```python
assert hasattr(olm, "PkEncryption")
assert hasattr(olm, "PkDecryption")
```

- [ ] **Step 10: Run all tests**

```bash
pytest tests/ -v
```
Expected: All tests pass (107 existing + ~10 new Pk tests).

- [ ] **Step 11: Commit**

```bash
git add crates/vodozemac-python/Cargo.toml crates/vodozemac-python/src/pk.rs crates/vodozemac-python/src/lib.rs fresholm/compat/olm.py tests/test_pk.py tests/test_mautrix_compat.py
git commit -m "feat: add PkEncryption/PkDecryption with insecure-pk-encryption feature

Rust bindings for vodozemac pk_encryption module.
Python compat wrappers with base64 string API.
All roundtrip tests passing."
```

---

## Task 2: Session.matches() Implementation

**Files:**
- Modify: `crates/vodozemac-python/src/session.rs`
- Modify: `fresholm/compat/olm.py`
- Modify: `tests/test_session.py`

- [ ] **Step 1: Add `matches_prekey` to Rust `session.rs`**

Add this method to the `#[pymethods] impl Session` block:

```rust
/// Check if a pre-key message was created for this session.
/// Compares session keys from the message with this session's keys.
/// Returns false if comparison cannot be performed.
fn matches_prekey(&self, pre_key_message_bytes: &[u8]) -> bool {
    let Ok(pre_key_msg) =
        vodozemac::olm::PreKeyMessage::from_bytes(pre_key_message_bytes)
    else {
        return false;
    };
    // Compare the session IDs derived from session keys
    let session_keys = self.inner.session_keys();
    let msg_keys = pre_key_msg.session_keys();
    session_keys.session_id() == msg_keys.session_id()
}
```

> **Note:** This assumes `Session::session_keys()` and `PreKeyMessage::session_keys()` both exist in vodozemac 0.9 and both return `SessionKeys` which has `session_id() -> String`. If `session_keys()` doesn't exist on either type, try alternatives:
> - If PreKeyMessage has `base_key()` and `identity_key()` methods, construct SessionKeys manually
> - If Session exposes `session_id()` and PreKeyMessage can produce one, compare those directly
> - As a last resort, keep returning `false` and document the limitation

- [ ] **Step 2: Build and verify**

```bash
maturin develop
python -c "
from fresholm._native import Account, Session
alice = Account()
bob = Account()
bob.generate_one_time_keys(1)
bob_keys = bob.identity_keys()
alice_keys = alice.identity_keys()
bob_otk = list(bob.one_time_keys().values())[0]
session = alice.create_outbound_session(bob_keys['curve25519'], bob_otk)
msg = session.encrypt(b'test')
if msg.message_type == 0:
    print(f'matches_prekey: {session.matches_prekey(msg.ciphertext)}')
else:
    print('First message was not PreKey type (unexpected)')
"
```

- [ ] **Step 3: Update Session.matches() in `fresholm/compat/olm.py`**

Replace the current `matches` method in the Session class:

```python
def matches(self, message):
    """Check if a pre-key message matches this session.

    Args:
        message: An OlmPreKeyMessage instance.

    Returns:
        True if the message was created for this session.
    """
    if not hasattr(message, 'ciphertext') or not hasattr(message, 'message_type'):
        return False
    if message.message_type != 0:
        return False
    return self._native.matches_prekey(message.ciphertext)
```

- [ ] **Step 4: Add tests to `tests/test_session.py`**

Add a new test class:

```python
class TestSessionMatches:
    def _make_prekey_message(self):
        """Create a session pair and return (session, pre_key_message, bob, alice_keys)."""
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

    def test_matches_returns_true_for_matching_message(self):
        from fresholm.compat.olm import Account
        alice_session, first_msg, bob, alice_keys = self._make_prekey_message()
        bob_session = bob.new_inbound_session(alice_keys["curve25519"], first_msg)
        assert bob_session.matches(first_msg) is True

    def test_matches_returns_false_for_non_matching(self):
        from fresholm.compat.olm import Account, OlmPreKeyMessage
        _, first_msg, _, _ = self._make_prekey_message()

        charlie = Account()
        dave = Account()
        dave.generate_one_time_keys(1)
        dave_keys = dave.identity_keys
        dave_otk = list(dave.one_time_keys["curve25519"].values())[0]
        charlie_session = charlie.new_outbound_session(
            dave_keys["curve25519"], dave_otk
        )
        assert charlie_session.matches(first_msg) is False

    def test_matches_returns_false_for_normal_message(self):
        from fresholm.compat.olm import OlmMessage
        msg = OlmMessage(b"not a prekey message")
        alice_session, first_msg, bob, alice_keys = self._make_prekey_message()
        bob_session = bob.new_inbound_session(alice_keys["curve25519"], first_msg)
        assert bob_session.matches(msg) is False
```

- [ ] **Step 5: Run tests**

```bash
pytest tests/test_session.py -v
```

- [ ] **Step 6: Run full suite**

```bash
pytest tests/ -v
```

- [ ] **Step 7: Commit**

```bash
git add crates/vodozemac-python/src/session.rs fresholm/compat/olm.py tests/test_session.py
git commit -m "feat: implement Session.matches() using session key comparison

Compares session IDs derived from session keys to determine if a
pre-key message was created for a given session."
```

---

## Task 3: README

**Files:**
- Create: `README.md`

- [ ] **Step 1: Write `README.md`**

````markdown
# fresholm

Python E2EE for [mautrix](https://github.com/mautrix/python) bridges, backed by [vodozemac](https://github.com/matrix-org/vodozemac).

Drop-in replacement for the archived `python-olm` package. Wraps the actively maintained vodozemac Rust library via PyO3 bindings.

## Why?

- `python-olm` is **archived** and won't build on modern platforms (macOS ARM64, Xcode 16+)
- `libolm` (the C library it wraps) is **deprecated** in favor of vodozemac
- `matrix-org/vodozemac-bindings` is **unmaintained**
- mautrix bridges still require python-olm for E2EE

fresholm solves this by providing API-compatible wrappers so mautrix bridges work with **zero code changes**.

## Install

```bash
pip install fresholm
```

## Usage

### Zero-change migration (recommended)

Add this **before** any mautrix imports:

```python
import fresholm.import_hook  # patches sys.modules['olm']
```

All existing `from olm import ...` statements will now use fresholm's vodozemac-backed implementation.

### Direct import

```python
from fresholm.compat.olm import Account, Session, OutboundGroupSession, InboundGroupSession
```

### Olm (1:1 encryption)

```python
from fresholm.compat.olm import Account

alice = Account()
bob = Account()
bob.generate_one_time_keys(1)

session = alice.new_outbound_session(
    bob.identity_keys["curve25519"],
    list(bob.one_time_keys["curve25519"].values())[0],
)

encrypted = session.encrypt("Hello Bob!")
bob_session = bob.new_inbound_session(alice.identity_keys["curve25519"], encrypted)

reply = bob_session.encrypt("Hello Alice!")
print(session.decrypt(reply))  # "Hello Alice!"
```

### Megolm (group encryption)

```python
from fresholm.compat.olm import OutboundGroupSession, InboundGroupSession

sender = OutboundGroupSession()
receiver = InboundGroupSession(sender.session_key)

ciphertext = sender.encrypt("Hello group!")
plaintext, index = receiver.decrypt(ciphertext)
```

## Compatibility

fresholm matches the python-olm API surface used by mautrix:

- `Account` with `identity_keys`, `one_time_keys`, `max_one_time_keys` as **properties**
- `Session` with `id` property, `encrypt()`/`decrypt()`, `matches()`
- `OutboundGroupSession` / `InboundGroupSession` with properties and serialization
- `PkEncryption` / `PkDecryption`
- All classes are **subclassable** (mautrix inherits from them)
- Serialization via `pickle(passphrase)`/`from_pickle(data, passphrase)` with string passphrases
- Import hook: `import fresholm.import_hook` patches `sys.modules['olm']`

### Known differences from python-olm

- **Serialization format**: Not compatible with libolm serialized data. Existing bridges need to clear crypto stores on first run or migrate using vodozemac's libolm compatibility functions.
- **No `_libolm` FFI**: Code that directly accesses `_libolm.ffi` or `_libolm.lib` will not work.

## Development

```bash
# Prerequisites: Rust toolchain, Python 3.10+
git clone https://github.com/cortexuvula/fresholm.git
cd fresholm
python3 -m venv .venv && source .venv/bin/activate
pip install maturin pytest pytest-asyncio
maturin develop
pytest tests/ -v
```

## License

MIT
````

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: add README with usage examples and compatibility notes"
```

---

## Task 4: mautrix-python Compatibility Validation

**Files:** No new files. This task validates fresholm against the actual mautrix-python crypto module.

- [ ] **Step 1: Install mautrix-python in the venv**

```bash
source .venv/bin/activate
pip install mautrix
```

- [ ] **Step 2: Verify mautrix crypto imports work with fresholm**

```bash
python -c "
import fresholm.import_hook  # Must come first

# These are the exact imports mautrix uses:
from olm import Account as OlmAccount
from olm import Session as OlmSession
from olm import OutboundGroupSession
from olm import InboundGroupSession
from olm import OlmPreKeyMessage, OlmMessage
from olm import OlmSessionError, OlmGroupSessionError

print('All mautrix crypto imports successful')

# Verify the subclass patterns mautrix uses
class CryptoAccount(OlmAccount):
    def __init__(self):
        super().__init__()
        self.shared = False

class CryptoSession(OlmSession):
    pass

class CryptoOutbound(OutboundGroupSession):
    def __init__(self, room_id='!test:matrix.org'):
        super().__init__()
        self.room_id = room_id

class CryptoInbound(InboundGroupSession):
    def __init__(self, session_key, **kwargs):
        super().__init__(session_key)
        self.extra = kwargs

print('Subclass patterns work')

# Full flow
acct = CryptoAccount()
acct.generate_one_time_keys(5)
keys = acct.identity_keys
otk = acct.one_time_keys
acct.mark_keys_as_published()
sig = acct.sign(b'test')
serialized = acct.pickle('secret')
restored = CryptoAccount.from_pickle(serialized, 'secret')
assert restored.identity_keys['ed25519'] == keys['ed25519']
print('Account flow works')

gs = CryptoOutbound()
assert gs.room_id == '!test:matrix.org'
ct = gs.encrypt('group msg')
igs = CryptoInbound(gs.session_key, sender_key='abc')
pt, idx = igs.decrypt(ct)
assert pt == 'group msg'
print('Megolm flow works')

print('All mautrix compatibility checks passed!')
"
```

- [ ] **Step 3: Run mautrix's own crypto tests (if available)**

```bash
python -c "import mautrix; print(mautrix.__file__)" 2>/dev/null
# If tests are available, run them. Otherwise, Step 2 validation is sufficient.
```

- [ ] **Step 4: Document results**

If any issues were found, fix them and commit. If all passes, no commit needed.

- [ ] **Step 5: Final full test suite**

```bash
pytest tests/ -v --tb=short
```
Expected: All tests pass.

---

## Post-Plan: Publishing Checklist (manual steps for project owner)

These are not automated — run after all tasks are complete:

1. **Create GitHub repo**: `gh repo create cortexuvula/fresholm --public --source=.`
2. **Push**: `git push -u origin main`
3. **Set PyPI token**: Add `PYPI_TOKEN` as a GitHub Actions secret
4. **Create release**: `gh release create v0.1.0 --generate-notes`
5. **Verify wheels build**: Check the Actions tab for the build-wheels workflow
6. **Verify install**: `pip install fresholm` from a clean venv after PyPI publish

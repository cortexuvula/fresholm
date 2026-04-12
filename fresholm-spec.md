# fresholm — Implementation Specification

## Project Overview

Build a Python package called `fresholm` that replaces the abandoned `python-olm` dependency in the mautrix Matrix bridge ecosystem with Rust-based vodozemac bindings.

### Problem
- `python-olm` (v3.2.16) is **archived** and cannot build on modern macOS ARM64 / Xcode 16+ / CMake 3.28+
- The bundled `libolm` C library is **deprecated** (since Aug 2025) in favor of vodozemac
- `matrix-org/vodozemac-bindings` is **unmaintained** ("no longer actively maintained")
- mautrix-python still hard-depends on python-olm for E2EE (`e2be` extra)
- There is no working Python bridge to vodozemac for the mautrix ecosystem

### Goal
Create a drop-in replacement so that any mautrix bridge can swap `python-olm` for our package with zero or minimal code changes. The package should:
1. Wrap vodozemac (Rust) in Python bindings via PyO3/maturin
2. Provide API-compatible shims for all types that python-olm exported
3. Provide a crypto store layer compatible with mautrix's interface
4. Ship pre-built wheels for macOS ARM64, Linux x64/aarch64, Windows
5. Be installable via `pip install fresholm`

---

## Architecture

```
mautrix bridges (Python)          ← unchanged or minimal import change
         │
         ▼
fresholm/compat/olm.py        ← Drop-in shim (replaces python-olm)
         │
         ▼
vodozemac_python/                 ← Rust→Python bindings (PyO3)
         │
         ▼
vodozemac (Rust crate)            ← The actual crypto library (actively maintained)
```

---

## Repository Structure

```
fresholm/
├── README.md
├── LICENSE                          # MIT or MPL-2.0
├── pyproject.toml                   # PEP 621, maturin backend
├── Cargo.toml                       # Rust workspace root
│
├── crates/
│   └── vodozemac-python/            # Rust→Python bindings crate
│       ├── Cargo.toml               # Depends on vodozemac + pyo3
│       ├── src/
│       │   ├── lib.rs               # PyO3 module entry point
│       │   ├── account.rs           # OlmAccount bindings
│       │   ├── session.rs           # OlmSession bindings
│       │   ├── prekey_message.rs    # PreKeyMessage bindings
│       │   ├── message.rs           # OlmMessage bindings
│       │   ├── group_session.rs     # OutboundGroupSession bindings
│       │   ├── inbound_group_session.rs  # InboundGroupSession bindings
│       │   ├── pk.rs                # PkEncryption / PkDecryption bindings
│       │   └── errors.rs            # Error types, PyO3 exceptions
│       └── stubs/
│           └── vodozemac_python.pyi # Type stubs for IDE / mypy
│
├── fresholm/                    # Python package
│   ├── __init__.py                  # Version, exports
│   ├── compat/
│   │   ├── __init__.py
│   │   ├── olm.py                   # Drop-in for `import olm`
│   │   ├── types.py                 # Message types, error classes
│   │   └── pickle_compat.py         # Serialize/deserialize helpers
│   ├── crypto_store/
│   │   ├── __init__.py
│   │   ├── base.py                  # Abstract base class
│   │   ├── memory.py                # In-memory store (for testing)
│   │   ├── asyncpg.py               # PostgreSQL store (production)
│   │   └── sqlite.py                # SQLite store (lightweight)
│   ├── import_hook.py               # sys.modules monkey-patch
│   └── key_utils.py                 # Cross-signing, key backup helpers
│
├── tests/
│   ├── __init__.py
│   ├── conftest.py                  # Fixtures, shared test data
│   ├── test_account.py              # Account creation, keys, signing
│   ├── test_session.py              # Olm encrypt/decrypt round-trip
│   ├── test_group_session.py        # Megolm encrypt/decrypt round-trip
│   ├── test_pickle.py               # Pickle/unpickle compatibility
│   ├── test_pk.py                   # Public key encryption
│   ├── test_crypto_store.py         # Store CRUD operations
│   ├── test_mautrix_compat.py       # Import shim tests
│   └── test_cross_platform.py       # Test against known python-olm pickles
│
├── .github/
│   └── workflows/
│       ├── ci.yml                   # Lint, test on push/PR
│       ├── build-wheels.yml         # cibuildwheel for PyPI
│       └── release.yml              # Publish to PyPI on tag
│
├── docs/
│   ├── architecture.md              # This document
│   ├── migration-guide.md           # How to switch from python-olm
│   └── api-reference.md             # Full API docs
│
└── scripts/
    ├── setup-dev.sh                 # Install Rust, maturin, deps
    ├── test-compat.sh               # Run compat tests against mautrix
    └── release.py                   # Bump version, tag, publish
```

---

## Cargo.toml (Rust Workspace)

```toml
[workspace]
members = ["crates/vodozemac-python"]
resolver = "2"
```

## crates/vodozemac-python/Cargo.toml

```toml
[package]
name = "vodozemac-python"
version = "0.1.0"
edition = "2021"

[lib]
name = "vodozemac_python"
crate-type = ["cdylib"]

[dependencies]
vodozemac = "0.8"          # Check latest version
pyo3 = { version = "0.22", features = ["extension-module"] }
base64 = "0.22"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
zeroize = { version = "1", features = ["derive"] }
```

---

## pyproject.toml

```toml
[build-system]
requires = ["maturin>=1.5,<2"]
build-backend = "maturin"

[project]
name = "fresholm"
version = "0.1.0"
description = "Python E2EE for mautrix bridges, backed by vodozemac"
readme = "README.md"
license = { text = "MIT" }
requires-python = ">=3.9"
dependencies = []

[project.optional-dependencies]
all = ["fresholm"]
store-postgres = ["asyncpg"]
store-sqlite = ["aiosqlite"]

[tool.maturin]
features = ["pyo3/extension-module"]
python-source = "."
module-name = "vodozemac_python._native"
manifest-path = "crates/vodozemac-python/Cargo.toml"

[tool.maturin.include]
"fresholm/**/*.py" = "fresholm/"

[tool.pytest.ini_options]
testpaths = ["tests"]
asyncio_mode = "auto"
```

---

## Rust Implementation Guide

### Module: lib.rs

```rust
use pyo3::prelude::*;

mod account;
mod session;
mod group_session;
mod inbound_group_session;
mod pk;
mod errors;

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<account::Account>()?;
    m.add_class::<session::Session>()?;
    m.add_class::<session::Message>()?;
    m.add_class::<session::PreKeyMessage>()?;
    m.add_class::<group_session::GroupSession>()?;
    m.add_class::<inbound_group_session::InboundGroupSession>()?;
    m.add_class::<pk::PkEncryption>()?;
    m.add_class::<pk::PkDecryption>()?;
    errors::register_exceptions(m)?;
    Ok(())
}
```

### Module: account.rs

```rust
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use vodozemac::olm::Account as VzAccount;
use vodozemac::Curve25519PublicKey;
use crate::session::Session;

#[pyclass]
pub struct Account {
    inner: VzAccount,
}

#[pymethods]
impl Account {
    #[new]
    #[pyo3(signature = (pickle_key=None))]
    fn new(pickle_key: Option<&[u8]>) -> PyResult<Self> {
        let inner = VzAccount::new();
        Ok(Self { inner })
    }

    fn identity_keys(&self, py: Python<'_>) -> PyResult<PyObject> {
        let keys = self.inner.identity_keys();
        let dict = PyDict::new(py);
        dict.set_item("ed25519", keys.ed25519.to_base64())?;
        dict.set_item("curve25519", keys.curve25519.to_base64())?;
        Ok(dict.into())
    }

    fn sign(&self, message: &str) -> String {
        self.inner.sign(message).to_base64()
    }

    fn generate_one_time_keys(&mut self, count: usize) {
        self.inner.generate_one_time_keys(count);
    }

    fn one_time_keys(&self, py: Python<'_>) -> PyResult<PyObject> {
        let keys = self.inner.one_time_keys();
        let dict = PyDict::new(py);
        for (id, key) in keys {
            dict.set_item(id.to_base64(), key.to_base64())?;
        }
        Ok(dict.into())
    }

    fn mark_keys_as_published(&mut self) {
        self.inner.mark_keys_as_published();
    }

    fn max_number_of_one_time_keys(&self) -> usize {
        self.inner.max_number_of_one_time_keys()
    }

    fn create_outbound_session(
        &self,
        their_identity_key: &str,
        their_one_time_key: &str,
    ) -> PyResult<Session> {
        let identity = Curve25519PublicKey::from_base64(their_identity_key)
            .map_err(|e| crate::errors::OlmError::new_err(format!("{}", e)))?;
        let otk = Curve25519PublicKey::from_base64(their_one_time_key)
            .map_err(|e| crate::errors::OlmError::new_err(format!("{}", e)))?;
        let session = self.inner.create_outbound_session(identity, otk);
        Ok(Session::from_inner(session))
    }

    fn create_inbound_session(
        &mut self,
        their_identity_key: &str,
        pre_key_message: &crate::session::PreKeyMessage,
    ) -> PyResult<(Session, String)> {
        let identity = Curve25519PublicKey::from_base64(their_identity_key)
            .map_err(|e| crate::errors::OlmError::new_err(format!("{}", e)))?;
        let (session, plaintext) = self.inner
            .create_inbound_session(&identity, &pre_key_message.inner)
            .map_err(|e| crate::errors::OlmError::new_err(format!("{}", e)))?;
        Ok((Session::from_inner(session), plaintext))
    }

    fn pickle(&self, py: Python<'_>, key: &[u8]) -> PyResult<PyObject> {
        let pickle_key = vodozemac::PickleKey::from_slice(key)
            .map_err(|e| crate::errors::OlmError::new_err(format!("{}", e)))?;
        let pickle = self.inner.pickle(&pickle_key);
        Ok(PyBytes::new(py, pickle.as_bytes()).into())
    }

    #[staticmethod]
    fn unpickle(key: &[u8], pickle: &[u8]) -> PyResult<Self> {
        let pickle_key = vodozemac::PickleKey::from_slice(key)
            .map_err(|e| crate::errors::OlmError::new_err(format!("{}", e)))?;
        let pickle_str = std::str::from_utf8(pickle)
            .map_err(|e| crate::errors::OlmError::new_err(format!("{}", e)))?;
        let inner = VzAccount::from_pickle(pickle_str, &pickle_key)
            .map_err(|e| crate::errors::OlmError::new_err(format!("{}", e)))?;
        Ok(Self { inner })
    }

    fn __repr__(&self) -> String {
        format!("<Account ed25519={}>", &self.inner.identity_keys().ed25519.to_base64()[..8])
    }
}
```

### Module: session.rs

```rust
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use vodozemac::olm::{Session as VzSession, Message as VzMessage, PreKeyMessage as VzPreKeyMessage};

#[pyclass]
pub struct Session {
    pub(crate) inner: VzSession,
}

impl Session {
    pub fn from_inner(inner: VzSession) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl Session {
    fn encrypt(&mut self, plaintext: &str) -> Message {
        let msg = self.inner.encrypt(plaintext);
        Message { inner: msg }
    }

    fn decrypt(&mut self, py: Python<'_>, message: &Bound<'_, PyAny>) -> PyResult<String> {
        // Accept either Message or PreKeyMessage
        if let Ok(msg) = message.extract::<RefCell<Message>>() {
            self.inner.decrypt(&msg.borrow().inner)
                .map_err(|e| crate::errors::OlmError::new_err(format!("{}", e)))
        } else if let Ok(msg) = message.extract::<RefCell<PreKeyMessage>>() {
            self.inner.decrypt(&msg.borrow().inner)
                .map_err(|e| crate::errors::OlmError::new_err(format!("{}", e)))
        } else {
            Err(crate::errors::OlmError::new_err("Expected Message or PreKeyMessage"))
        }
    }

    fn session_id(&self) -> String {
        self.inner.session_id()
    }

    fn pickle(&self, py: Python<'_>, key: &[u8]) -> PyResult<PyObject> {
        let pickle_key = vodozemac::PickleKey::from_slice(key)
            .map_err(|e| crate::errors::OlmError::new_err(format!("{}", e)))?;
        let pickle = self.inner.pickle(&pickle_key);
        Ok(PyBytes::new(py, pickle.as_bytes()).into())
    }

    #[staticmethod]
    fn unpickle(key: &[u8], pickle: &[u8]) -> PyResult<Self> {
        let pickle_key = vodozemac::PickleKey::from_slice(key)
            .map_err(|e| crate::errors::OlmError::new_err(format!("{}", e)))?;
        let pickle_str = std::str::from_utf8(pickle)
            .map_err(|e| crate::errors::OlmError::new_err(format!("{}", e)))?;
        let inner = VzSession::from_pickle(pickle_str, &pickle_key)
            .map_err(|e| crate::errors::OlmError::new_err(format!("{}", e)))?;
        Ok(Self { inner })
    }

    fn __repr__(&self) -> String {
        format!("<Session id={}>", &self.session_id()[..8])
    }
}

#[pyclass]
#[derive(Clone)]
pub struct Message {
    pub(crate) inner: VzMessage,
}

#[pymethods]
impl Message {
    #[getter]
    fn ciphertext(&self) -> String {
        self.inner.ciphertext().to_owned()
    }

    #[getter]
    fn message_type(&self) -> u32 {
        1 // OlmMessage::Normal
    }

    fn __repr__(&self) -> String {
        format!("<Message type={}>", self.message_type())
    }
}

#[pyclass]
#[derive(Clone)]
pub struct PreKeyMessage {
    pub(crate) inner: VzPreKeyMessage,
}

#[pymethods]
impl PreKeyMessage {
    #[getter]
    fn ciphertext(&self) -> String {
        self.inner.ciphertext().to_owned()
    }

    #[getter]
    fn message_type(&self) -> u32 {
        0 // OlmMessage::PreKey
    }

    fn __repr__(&self) -> String {
        "<PreKeyMessage>".to_string()
    }
}
```

### Module: group_session.rs

```rust
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use vodozemac::megolm::GroupSession as VzGroupSession;

#[pyclass]
pub struct GroupSession {
    inner: VzGroupSession,
}

#[pymethods]
impl GroupSession {
    #[new]
    #[pyo3(signature = (pickle_key=None))]
    fn new(pickle_key: Option<&[u8]>) -> PyResult<Self> {
        let inner = VzGroupSession::new(vodozemac::megolm::SessionConfig::version_2());
        Ok(Self { inner })
    }

    fn session_id(&self) -> String {
        self.inner.session_id()
    }

    fn session_key(&self) -> String {
        self.inner.session_key().to_base64()
    }

    fn encrypt(&mut self, plaintext: &str) -> String {
        self.inner.encrypt(plaintext).to_base64()
    }

    fn message_index(&self) -> u32 {
        self.inner.message_index()
    }

    fn pickle(&self, py: Python<'_>, key: &[u8]) -> PyResult<PyObject> {
        let pickle_key = vodozemac::PickleKey::from_slice(key)
            .map_err(|e| crate::errors::OlmError::new_err(format!("{}", e)))?;
        let pickle = self.inner.pickle(&pickle_key);
        Ok(PyBytes::new(py, pickle.as_bytes()).into())
    }

    #[staticmethod]
    fn unpickle(key: &[u8], pickle: &[u8]) -> PyResult<Self> {
        let pickle_key = vodozemac::PickleKey::from_slice(key)
            .map_err(|e| crate::errors::OlmError::new_err(format!("{}", e)))?;
        let pickle_str = std::str::from_utf8(pickle)
            .map_err(|e| crate::errors::OlmError::new_err(format!("{}", e)))?;
        let inner = VzGroupSession::from_pickle(pickle_str, &pickle_key)
            .map_err(|e| crate::errors::OlmError::new_err(format!("{}", e)))?;
        Ok(Self { inner })
    }

    fn __repr__(&self) -> String {
        format!("<GroupSession id={}>", &self.session_id()[..8])
    }
}
```

### Module: inbound_group_session.rs

```rust
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use vodozemac::megolm::InboundGroupSession as VzInboundGroupSession;

#[pyclass]
pub struct InboundGroupSession {
    inner: VzInboundGroupSession,
}

#[pymethods]
impl InboundGroupSession {
    #[new]
    fn new(session_key: &str) -> PyResult<Self> {
        let key = vodozemac::megolm::GroupSessionKey::from_base64(session_key)
            .map_err(|e| crate::errors::OlmError::new_err(format!("{}", e)))?;
        let inner = VzInboundGroupSession::new(&key);
        Ok(Self { inner })
    }

    fn decrypt(&mut self, py: Python<'_>, ciphertext: &str) -> PyResult<(String, u32)> {
        let msg = vodozemac::megolm::MegolmMessage::from_base64(ciphertext)
            .map_err(|e| crate::errors::OlmError::new_err(format!("{}", e)))?;
        let (plaintext, index) = self.inner.decrypt(&msg)
            .map_err(|e| crate::errors::MegolmError::new_err(format!("{}", e)))?;
        Ok((plaintext, index))
    }

    fn session_id(&self) -> String {
        self.inner.session_id()
    }

    fn first_known_index(&self) -> u32 {
        self.inner.first_known_index()
    }

    fn pickle(&self, py: Python<'_>, key: &[u8]) -> PyResult<PyObject> {
        let pickle_key = vodozemac::PickleKey::from_slice(key)
            .map_err(|e| crate::errors::OlmError::new_err(format!("{}", e)))?;
        let pickle = self.inner.pickle(&pickle_key);
        Ok(PyBytes::new(py, pickle.as_bytes()).into())
    }

    #[staticmethod]
    fn unpickle(key: &[u8], pickle: &[u8]) -> PyResult<Self> {
        let pickle_key = vodozemac::PickleKey::from_slice(key)
            .map_err(|e| crate::errors::OlmError::new_err(format!("{}", e)))?;
        let pickle_str = std::str::from_utf8(pickle)
            .map_err(|e| crate::errors::OlmError::new_err(format!("{}", e)))?;
        let inner = VzInboundGroupSession::from_pickle(pickle_str, &pickle_key)
            .map_err(|e| crate::errors::OlmError::new_err(format!("{}", e)))?;
        Ok(Self { inner })
    }

    fn __repr__(&self) -> String {
        format!("<InboundGroupSession id={}>", &self.session_id()[..8])
    }
}
```

### Module: pk.rs

```rust
use pyo3::prelude::*;
use vodozemac::pk::{PkEncryption as VzPkEncryption, PkDecryption as VzPkDecryption};

#[pyclass]
pub struct PkEncryption {
    inner: VzPkEncryption,
}

#[pymethods]
impl PkEncryption {
    #[staticmethod]
    fn from_recipient_key(key: &str) -> PyResult<Self> {
        let pubkey = vodozemac::Curve25519PublicKey::from_base64(key)
            .map_err(|e| crate::errors::OlmError::new_err(format!("{}", e)))?;
        let inner = VzPkEncryption::from_key(pubkey);
        Ok(Self { inner })
    }

    fn encrypt(&self, plaintext: &str) -> String {
        self.inner.encrypt(plaintext).to_base64()
    }
}

#[pyclass]
pub struct PkDecryption {
    inner: VzPkDecryption,
}

#[pymethods]
impl PkDecryption {
    #[new]
    #[pyo3(signature = (key=None))]
    fn new(key: Option<&str>) -> PyResult<Self> {
        if let Some(k) = key {
            let secret = vodozemac::Curve25519SecretKey::from_base64(k)
                .map_err(|e| crate::errors::OlmError::new_err(format!("{}", e)))?;
            let inner = VzPkDecryption::from_key(secret);
            Ok(Self { inner })
        } else {
            let inner = VzPkDecryption::new();
            Ok(Self { inner })
        }
    }

    fn get_public_key(&self) -> String {
        self.inner.public_key().to_base64()
    }

    fn decrypt(&self, ciphertext: &str) -> PyResult<String> {
        let msg = vodozemac::pk::Message::from_base64(ciphertext)
            .map_err(|e| crate::errors::OlmError::new_err(format!("{}", e)))?;
        self.inner.decrypt(&msg)
            .map_err(|e| crate::errors::OlmError::new_err(format!("{}", e)))
    }
}
```

### Module: errors.rs

```rust
use pyo3::create_exception;
use pyo3::prelude::*;

create_exception!(vodozemac_python, OlmError, pyo3::exceptions::PyException);
create_exception!(vodozemac_python, MegolmError, pyo3::exceptions::PyException);
create_exception!(vodozemac_python, CryptoStoreError, pyo3::exceptions::PyException);

pub fn register_exceptions(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("OlmError", m.py().get_type::<OlmError>())?;
    m.add("MegolmError", m.py().get_type::<MegolmError>())?;
    m.add("CryptoStoreError", m.py().get_type::<CryptoStoreError>())?;
    Ok(())
}
```

---

## Python Compatibility Layer

### fresholm/compat/olm.py

```python
"""
Drop-in replacement for `python-olm`.

Import this module as `olm` via the import hook or by replacing:
    from olm import Account
with:
    from fresholm.compat.olm import Account
"""

from vodozemac_python import (
    Account as OlmAccount,
    Session as OlmSession,
    GroupSession,
    InboundGroupSession as OlmInboundGroupSession,
    PkEncryption,
    PkDecryption,
)
from vodozemac_python import (
    Message as OlmMessage,
    PreKeyMessage as OlmPreKeyMessage,
)

from .types import CryptoStoreError


# Alias OutboundGroupSession → GroupSession
OutboundGroupSession = GroupSession


# python-olm's pickle function
def pickle(obj, key: bytes) -> bytes:
    """Pickle an olm object with the given key."""
    return obj.pickle(key)


def unpickle(cls, pickle_data: bytes, key: bytes):
    """Unpickle an olm object."""
    return cls.unpickle(key, pickle_data)


__all__ = [
    "OlmAccount",
    "OlmSession",
    "GroupSession",
    "OutboundGroupSession",
    "OlmInboundGroupSession",
    "OlmPreKeyMessage",
    "OlmMessage",
    "PkEncryption",
    "PkDecryption",
    "CryptoStoreError",
    "pickle",
    "unpickle",
]
```

### fresholm/compat/types.py

```python
"""Error types and message wrappers for python-olm compatibility."""


class CryptoStoreError(Exception):
    """Error in crypto store operations."""
    pass


class OlmError(Exception):
    """Error in Olm operations."""
    pass


class MegolmError(Exception):
    """Error in Megolm operations."""
    pass
```

### fresholm/import_hook.py

```python
"""
Import hook to monkey-patch `import olm` with our vodozemac-backed shim.

Usage:
    import fresholm.import_hook  # noqa — installs the hook

After this, any `from olm import ...` will get our compatibility layer.
This enables zero changes to mautrix source code.
"""

import sys
import fresholm.compat.olm as olm_compat

# Replace the olm module in sys.modules
sys.modules['olm'] = olm_compat

# Also register common sub-imports
sys.modules['olm.Account'] = olm_compat  # python-olm used a flat namespace
```

### fresholm/crypto_store/base.py

```python
"""Abstract base class for crypto stores."""

from abc import ABC, abstractmethod
from typing import Optional


class BaseCryptoStore(ABC):
    """
    Crypto store interface compatible with mautrix's CryptoStore protocol.
    
    mautrix expects these methods to exist on its crypto store objects.
    Implementations: MemoryCryptoStore, AsyncpgCryptoStore, SqliteCryptoStore
    """

    @abstractmethod
    async def put_account(self, account) -> None: ...

    @abstractmethod
    async def get_account(self) -> Optional[object]: ...

    @abstractmethod
    async def put_sessions(self, sender_key: str, sessions: list) -> None: ...

    @abstractmethod
    async def get_sessions(self, sender_key: str) -> list: ...

    @abstractmethod
    async def put_group_session(
        self, room_id: str, sender_key: str, session_id: str, session
    ) -> None: ...

    @abstractmethod
    async def get_group_session(
        self, room_id: str, sender_key: str, session_id: str
    ) -> Optional[object]: ...

    @abstractmethod
    async def has_group_session(
        self, room_id: str, sender_key: str, session_id: str
    ) -> bool: ...

    @abstractmethod
    async def add_session(self, sender_key: str, session) -> None: ...

    @abstractmethod
    async def update_session(self, sender_key: str, session) -> None: ...

    @abstractmethod
    async def delete_session(self, sender_key: str, session_id: str) -> None: ...

    @abstractmethod
    async def delete_all_sessions(self, sender_key: str) -> None: ...
```

### fresholm/crypto_store/memory.py

```python
"""In-memory crypto store for testing and lightweight deployments."""

from typing import Optional
from .base import BaseCryptoStore


class MemoryCryptoStore(BaseCryptoStore):
    """
    In-memory crypto store. Not persistent — use for testing or
    stateless bridge deployments only.
    """

    def __init__(self):
        self._account = None
        self._sessions: dict[str, list] = {}
        self._group_sessions: dict[str, dict] = {}
        self._outbound_group_sessions: dict[str, object] = {}

    async def put_account(self, account) -> None:
        self._account = account

    async def get_account(self) -> Optional[object]:
        return self._account

    async def put_sessions(self, sender_key: str, sessions: list) -> None:
        self._sessions[sender_key] = sessions

    async def get_sessions(self, sender_key: str) -> list:
        return self._sessions.get(sender_key, [])

    async def add_session(self, sender_key: str, session) -> None:
        if sender_key not in self._sessions:
            self._sessions[sender_key] = []
        self._sessions[sender_key].append(session)

    async def update_session(self, sender_key: str, session) -> None:
        sessions = self._sessions.get(sender_key, [])
        for i, s in enumerate(sessions):
            if s.session_id() == session.session_id():
                sessions[i] = session
                return
        sessions.append(session)

    async def delete_session(self, sender_key: str, session_id: str) -> None:
        sessions = self._sessions.get(sender_key, [])
        self._sessions[sender_key] = [
            s for s in sessions if s.session_id() != session_id
        ]

    async def delete_all_sessions(self, sender_key: str) -> None:
        self._sessions.pop(sender_key, None)

    async def put_group_session(
        self, room_id: str, sender_key: str, session_id: str, session
    ) -> None:
        key = f"{room_id}|{sender_key}|{session_id}"
        self._group_sessions[key] = {
            "room_id": room_id,
            "sender_key": sender_key,
            "session_id": session_id,
            "session": session,
        }

    async def get_group_session(
        self, room_id: str, sender_key: str, session_id: str
    ) -> Optional[object]:
        key = f"{room_id}|{sender_key}|{session_id}"
        data = self._group_sessions.get(key)
        return data["session"] if data else None

    async def has_group_session(
        self, room_id: str, sender_key: str, session_id: str
    ) -> bool:
        key = f"{room_id}|{sender_key}|{session_id}"
        return key in self._group_sessions
```

---

## Tests

### tests/test_account.py

```python
import pytest
from vodozemac_python import Account


class TestAccount:
    def test_create_account(self):
        account = Account()
        assert account is not None

    def test_identity_keys(self):
        account = Account()
        keys = account.identity_keys()
        assert "ed25519" in keys
        assert "curve25519" in keys
        assert len(keys["ed25519"]) > 20
        assert len(keys["curve25519"]) > 20

    def test_sign(self):
        account = Account()
        signature = account.sign("hello world")
        assert len(signature) > 20

    def test_one_time_keys(self):
        account = Account()
        account.generate_one_time_keys(5)
        otk = account.one_time_keys()
        assert len(otk) == 5

    def test_max_one_time_keys(self):
        account = Account()
        max_keys = account.max_number_of_one_time_keys()
        assert max_keys > 0

    def test_pickle_roundtrip(self):
        account = Account()
        account.generate_one_time_keys(3)
        key = b"a]b2c3d4e5f6g7h8a9b0c1d2e3f4g5h6"
        
        pickled = account.pickle(key)
        restored = Account.unpickle(key, pickled)
        
        orig_keys = account.identity_keys()
        restored_keys = restored.identity_keys()
        assert orig_keys["ed25519"] == restored_keys["ed25519"]

    def test_repr(self):
        account = Account()
        r = repr(account)
        assert "Account" in r
```

### tests/test_session.py

```python
import pytest
from vodozemac_python import Account, Message


class TestSession:
    def test_outbound_session(self):
        alice = Account()
        alice.generate_one_time_keys(1)
        bob = Account()
        bob.generate_one_time_keys(1)

        alice_keys = alice.identity_keys()
        bob_otk = bob.one_time_keys()

        # Get first one-time key
        bob_otk_value = list(bob_otk.values())[0]

        session = alice.create_outbound_session(
            alice_keys["curve25519"],  # Wait — this should be bob's keys
            bob_otk_value,
        )
        assert session is not None
        assert len(session.session_id()) > 0

    def test_encrypt_decrypt(self):
        alice = Account()
        bob = Account()
        bob.generate_one_time_keys(1)

        alice_keys = alice.identity_keys()
        bob_keys = bob.identity_keys()
        bob_otk = list(bob.one_time_keys().values())[0]

        alice_session = alice.create_outbound_session(
            bob_keys["curve25519"], bob_otk
        )

        message = alice_session.encrypt("Hello Bob!")
        assert isinstance(message, Message)
        assert message.message_type == 1

        # Bob creates inbound session
        bob_session, _ = bob.create_inbound_session(
            alice_keys["curve25519"], message
        )

        # This test may need adjustment depending on vodozemac's exact API
```

### tests/test_group_session.py

```python
import pytest
from vodozemac_python import GroupSession, InboundGroupSession


class TestGroupSession:
    def test_create(self):
        gs = GroupSession()
        assert gs is not None
        assert len(gs.session_id()) > 0
        assert gs.message_index() == 0

    def test_encrypt(self):
        gs = GroupSession()
        encrypted = gs.encrypt("Hello group!")
        assert len(encrypted) > 0
        assert gs.message_index() == 1

    def test_roundtrip(self):
        gs = GroupSession()
        key = gs.session_key()

        igs = InboundGroupSession(key)
        assert gs.session_id() == igs.session_id()

        encrypted = gs.encrypt("Test message")
        plaintext, index = igs.decrypt(encrypted)
        assert plaintext == "Test message"

    def test_pickle_roundtrip(self):
        gs = GroupSession()
        gs.encrypt("trigger index")
        key = b"a]b2c3d4e5f6g7h8a9b0c1d2e3f4g5h6"

        pickled = gs.pickle(key)
        restored = GroupSession.unpickle(key, pickled)
        assert gs.session_id() == restored.session_id()
```

### tests/test_mautrix_compat.py

```python
import pytest


class TestImportHook:
    def test_import_hook_replaces_olm(self):
        import fresholm.import_hook  # noqa — installs hook
        
        import olm  # Should now be our compat layer
        assert hasattr(olm, 'OlmAccount')
        assert hasattr(olm, 'OlmSession')
        assert hasattr(olm, 'GroupSession')
        assert hasattr(olm, 'InboundGroupSession')
        assert hasattr(olm, 'OutboundGroupSession')
        assert hasattr(olm, 'PkEncryption')
        assert hasattr(olm, 'PkDecryption')
        assert hasattr(olm, 'pickle')
        assert hasattr(olm, 'unpickle')

    def test_from_olm_import(self):
        import fresholm.import_hook  # noqa
        
        from olm import OlmAccount, OlmSession, GroupSession
        assert OlmAccount is not None
        assert OlmSession is not None
        assert GroupSession is not None

    def test_crypto_store_error_import(self):
        import fresholm.import_hook  # noqa
        
        from olm import CryptoStoreError
        assert issubclass(CryptoStoreError, Exception)
```

---

## GitHub Actions: CI

```yaml
# .github/workflows/ci.yml
name: CI
on: [push, pull_request]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions-rust-lang/setup-rust-toolchain@v1
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - run: pip install maturin ruff mypy
      - run: cargo clippy --all-targets -- -D warnings
      - run: ruff check fresholm/

  test:
    needs: lint
    strategy:
      matrix:
        os: [ubuntu-latest, macos-14, windows-latest]
        python: ["3.9", "3.11", "3.12"]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions-rust-lang/setup-rust-toolchain@v1
      - uses: actions/setup-python@v5
        with: { python-version: ${{ matrix.python }} }
      - run: pip install maturin pytest
      - run: maturin develop --release
      - run: pytest tests/ -v
```

## GitHub Actions: Build Wheels

```yaml
# .github/workflows/build-wheels.yml
name: Build Wheels
on:
  release:
    types: [published]

jobs:
  build:
    strategy:
      matrix:
        include:
          - os: ubuntu-latest
            target: x86_64
          - os: ubuntu-latest
            target: aarch64
          - os: macos-14      # Apple Silicon
            target: aarch64
          - os: macos-13      # Intel Mac
            target: x86_64
          - os: windows-latest
            target: x64
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - run: pip install cibuildwheel
      - run: cibuildwheel --output-dir wheelhouse
        env:
          CIBW_BUILD: "cp39-* cp310-* cp311-* cp312-* cp313-*"
          CIBW_ARCHS_LINUX: ${{ matrix.target }}
          CIBW_ARCHS_MACOS: ${{ matrix.target }}
          CIBW_ARCHS_WINDOWS: AMD64
      - uses: actions/upload-artifact@v4
        with:
          name: wheels-${{ matrix.os }}
          path: wheelhouse/*.whl

  publish:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with: { path: dist, merge-multiple: true }
      - uses: pypa/gh-action-pypi-publish@release/v1
        with:
          password: ${{ secrets.PYPI_TOKEN }}
```

---

## Critical Implementation Notes

### Pickle Format Compatibility
- python-olm pickles are **not compatible** with vodozemac's pickle format
- If bridges have existing pickled sessions in their database, a migration step is needed
- Solution: Write a `pickle_compat.py` that can detect old format and re-pickle
- OR: Clear crypto stores on first run (breaks existing E2EE sessions but regenerates quickly)

### Key Import Paths
python-olm exported from a flat `olm` namespace:
```python
from olm import Account, Session, GroupSession, InboundGroupSession, OutboundGroupSession, PkEncryption, PkDecryption
from olm import OlmMessage, OlmPreKeyMessage
from olm import pickle, unpickle
from olm import CryptoStoreError
```
Our shim must match this exactly.

### mautrix Integration Points
The following mautrix modules import from `olm`:
- `mautrix/crypto/account.py` → `OlmAccount`
- `mautrix/crypto/sessions.py` → `OlmSession`, `OlmPreKeyMessage`
- `mautrix/crypto/key_sharing.py` → `GroupSession`, `InboundGroupSession`
- `mautrix/crypto/store/abstract.py` → `CryptoStoreError`
- `mautrix/crypto/encrypt_megolm.py` → `OutboundGroupSession`
- `mautrix/crypto/decrypt_olm.py` → `OlmMessage`

Check the actual mautrix-python source at https://github.com/mautrix/python for exact imports.

### vodozemac Version
Pin to a specific vodozemac release. Do NOT use `*` or `latest`. Check https://github.com/matrix-org/vodozemac/releases for the latest stable version.

### Testing Against Real mautrix
After building, run the bridge's own test suite:
```bash
cd /path/to/mautrix-python
pip install -e /path/to/fresholm
pip install -e ".[all]"
pytest tests/crypto/ -v
```

---

## First Steps (Do These First)

1. **Create the GitHub repo**: `github.com/cortexuvula/fresholm`
2. **Initialize with maturin**: `maturin new --name vodozemac-python --bindings pyo3 crates/vodozemac-python`
3. **Verify vodozemac compiles**: `cargo check` in the Rust crate
4. **Build and test a minimal module**: Just `Account` + `identity_keys()`
5. **Write first test**: `pytest tests/test_account.py::test_create_account`
6. **Then expand**: Add Session, GroupSession, InboundGroupSession, PkEncryption, PkDecryption
7. **Then the Python compat layer**: `fresholm/compat/olm.py`
8. **Then the import hook**: `sys.modules['olm']` replacement
9. **Then test against a real mautrix bridge**: `mautrix-telegram` or `mautrix-signal`
10. **Then build wheels and publish**

---

## Success Criteria

- [ ] `pip install fresholm` works on macOS ARM64, Linux x64, Windows
- [ ] `from olm import Account, Session, GroupSession` works after import hook
- [ ] Olm 1:1 encrypt/decrypt round-trip passes
- [ ] Megolm group encrypt/decrypt round-trip passes
- [ ] Pickle/unpickle works for all types
- [ ] PkEncryption/PkDecryption works
- [ ] MemoryCryptoStore passes mautrix crypto store protocol tests
- [ ] At least one mautrix bridge (e.g., mautrix-telegram) works end-to-end with E2EE
- [ ] Wheels published to PyPI for all platforms
- [ ] No dependency on python-olm or libolm anywhere in the build

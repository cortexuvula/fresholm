# Pickle KDF v2 Migration Implementation Plan (Bug 4)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the zero-pad/truncate `passphrase_to_key` function with Argon2id key derivation, embedding a random per-pickle salt and a version prefix in the serialized blob. Maintain a one-release-window fallback that decodes legacy ("v1") blobs with a `DeprecationWarning`. This is a 0.3.0 breaking change in serialized format (forward-only — 0.3.x reads 0.2.x blobs; 0.2.x cannot read 0.3.x blobs). Decryption keys derived from short or empty passphrases stop being trivially recoverable.

**Architecture:**

- **Format** (always emitted in 0.3+):
  ```
  "v2|" || base64url(m_cost_be32 || t_cost_be32 || p_cost_be32 || salt[16]) || "|" || vodozemac_inner
  ```
  - `vodozemac_inner` is the base64 string returned by vodozemac's own `pickle().encrypt(&derived_key)`. We never alter vodozemac's bytes; we only wrap them with our header.
  - The literal prefix `"v2|"` is unambiguous: vodozemac's v1 base64 cannot contain `|` (not a base64url char), so `starts_with("v2|")` reliably distinguishes versions.
  - Argon2id parameters chosen per RFC 9106 / OWASP 2024 "second-recommended" profile: `m_cost = 19456` KiB (~19 MiB), `t_cost = 2`, `p_cost = 1`. Stored in the header so future tuning is forward-compatible.

- **Decode dispatch:** `from_encrypted_string` checks `starts_with("v2|")`. If yes, parse header → derive Argon2id key → hand `vodozemac_inner` to vodozemac. If no, fall back to the legacy `passphrase_to_key_v1` (zero-pad/truncate) path and emit `DeprecationWarning`.

- **Shared helper module:** all 8 call sites (Account, Session, GroupSession, InboundGroupSession × {to,from}_encrypted_string) share `pickle_format::encrypt_v2` and `pickle_format::decrypt_dispatch` to avoid 8 copies of the format logic.

- **Test-only encryption of v1 blobs:** to round-trip-test the legacy decode path without committing fixture binaries, expose a private PyO3 function `_v1_encrypt_for_testing(passphrase, plaintext_pickle_string) -> String` that re-encrypts an already-pickled inner blob using the legacy KDF. Tests call it; production callers do not.

**Tech Stack:** Rust (vodozemac-python crate), PyO3, `argon2` crate (new dependency), Python pytest.

**Out of scope:**
- Removing the v1 decode path entirely. That happens in a follow-up plan targeting 0.4.0.
- A standalone `fresholm migrate-pickle` CLI tool.
- Tuning Argon2id parameters per-deployment. Defaults are hard-coded; a future change can make them configurable.
- Any change to `PkSigning`, `PkEncryption`, `PkDecryption`. Those don't go through `passphrase_to_key`.

**Pre-requisite:** This plan assumes Bugs 1, 2, 3 from `docs/superpowers/plans/2026-04-28-bug-review-fixes.md` have already landed (it doesn't depend on them functionally, but landing them in 0.2.6 first keeps the 0.3.0 diff focused on the format change).

---

## File structure

**Files created:**
- `crates/vodozemac-python/src/pickle_format.rs` — shared Argon2id KDF + v2 encode/decode + legacy dispatcher.
- `tests/test_pickle_format.py` — Python-level tests for v2 round-trip, v1 fallback, deprecation warning, wrong-passphrase, format detection.

**Files modified:**
- `crates/vodozemac-python/Cargo.toml` — add `argon2` and `rand` dependencies.
- `crates/vodozemac-python/src/lib.rs` — register the new module and the test-only PyO3 function.
- `crates/vodozemac-python/src/account.rs` — rename `passphrase_to_key` → `passphrase_to_key_v1` (legacy-only), wire `Account::to/from_encrypted_string` to the new helpers, expose `_v1_encrypt_account_for_testing`.
- `crates/vodozemac-python/src/session.rs` — wire `Session::to/from_encrypted_string`, expose `_v1_encrypt_session_for_testing`.
- `crates/vodozemac-python/src/group_session.rs` — wire `GroupSession::to/from_encrypted_string`, expose `_v1_encrypt_group_session_for_testing`.
- `crates/vodozemac-python/src/inbound_group_session.rs` — wire `InboundGroupSession::to/from_encrypted_string`, expose `_v1_encrypt_inbound_group_session_for_testing`.
- `pyproject.toml` — bump version `0.2.6` → `0.3.0`.
- `docs/superpowers/notes/2026-04-27-vodozemac-pickle-kdf.md` — append a "Resolved in 0.3.0" footer linking back to this plan.

---

## Task 1: Add `argon2` and `rand` dependencies

Add the two crates needed for password-stretching and salt generation. Pin them to current stable releases. `rand` provides a CSPRNG (`OsRng`) for the per-pickle salt.

**Files:**
- Modify: `crates/vodozemac-python/Cargo.toml`

- [ ] **Step 1: Add the two dependencies**

In `crates/vodozemac-python/Cargo.toml`, replace the `[dependencies]` block with:

```toml
[dependencies]
vodozemac = { version = "0.9", features = ["insecure-pk-encryption"] }
pyo3 = { version = "0.28", features = ["extension-module"] }
base64 = "0.22"
argon2 = "0.5"
rand = "0.8"
```

- [ ] **Step 2: Verify the build still compiles**

Run: `cargo check --manifest-path crates/vodozemac-python/Cargo.toml`
Expected: clean, with new crates pulled into `Cargo.lock`.

- [ ] **Step 3: Commit**

```bash
git add crates/vodozemac-python/Cargo.toml Cargo.lock
git commit -m "deps: add argon2 0.5 and rand 0.8 to vodozemac-python

Prep for v2 pickle format (Argon2id-based KDF replacing the zero-pad
passphrase_to_key)."
```

---

## Task 2: Create the `pickle_format` module

A single Rust module with three concerns:

1. `passphrase_to_key_v1(passphrase: &[u8]) -> [u8; 32]` — the existing zero-pad function, kept for legacy decode + test-only legacy encrypt. Renamed to make its scope obvious.
2. `derive_v2(passphrase: &[u8], params: &Argon2Params, salt: &[u8; 16]) -> [u8; 32]` — Argon2id-derived 32-byte pickle key.
3. `encode_v2_envelope(params: &Argon2Params, salt: &[u8; 16], inner: &str) -> String` and `decode_envelope(encrypted: &str) -> EnvelopeKind` — wrap and unwrap the `"v2|<header_b64>|<inner>"` structure, with a fallback path returning `EnvelopeKind::V1` for strings without the prefix.

Default Argon2 params (RFC 9106 second profile): `m_cost = 19456`, `t_cost = 2`, `p_cost = 1`.

**Files:**
- Create: `crates/vodozemac-python/src/pickle_format.rs`
- Modify: `crates/vodozemac-python/src/lib.rs` (register module)

- [ ] **Step 1: Create the module file**

Create `crates/vodozemac-python/src/pickle_format.rs` with the following content:

```rust
//! Versioned wrapper around vodozemac's encrypted-pickle string format.
//!
//! Vodozemac's `pickle().encrypt(&[u8; 32])` takes a raw 32-byte AES key and
//! produces a base64 string; it does not stretch passphrases. This module
//! adds a password-based KDF (Argon2id) and a small versioned envelope so
//! that low-entropy passphrases produce keys that are not trivially
//! brute-forceable.
//!
//! ## Format
//!
//! - **v2 (current):** `"v2|" || base64url(m_cost_be32 || t_cost_be32 ||
//!   p_cost_be32 || salt[16]) || "|" || vodozemac_inner`
//!   - 28-byte header section: 3 × u32 BE Argon2id parameters + 16-byte salt
//!   - `vodozemac_inner` is the unmodified base64 string vodozemac would have
//!     produced if called directly with the derived 32-byte key.
//! - **v1 (legacy):** the unwrapped vodozemac base64 string. Detected by the
//!   *absence* of the `"v2|"` prefix. Decrypted with `passphrase_to_key_v1`
//!   (zero-pad/truncate to 32 bytes). Will be removed in 0.4.0.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use rand::RngCore;

/// Argon2id parameters baked into the v2 envelope. RFC 9106 second-recommended
/// profile / OWASP 2024 minimum: 19 MiB memory, 2 iterations, 1 lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Argon2Params {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Argon2Params {
    pub const fn default_v2() -> Self {
        Self {
            m_cost: 19_456,
            t_cost: 2,
            p_cost: 1,
        }
    }
}

/// What kind of envelope a given encrypted string is.
pub enum EnvelopeKind<'a> {
    V2 {
        params: Argon2Params,
        salt: [u8; 16],
        inner: &'a str,
    },
    V1 {
        inner: &'a str,
    },
}

/// Legacy zero-pad/truncate "KDF". Kept for v1 decode and test-only v1
/// encrypt. Do not use for new pickles.
pub fn passphrase_to_key_v1(passphrase: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    let len = passphrase.len().min(32);
    key[..len].copy_from_slice(&passphrase[..len]);
    key
}

/// Argon2id KDF: passphrase + salt → 32-byte vodozemac pickle key.
pub fn derive_v2(
    passphrase: &[u8],
    params: &Argon2Params,
    salt: &[u8; 16],
) -> Result<[u8; 32], String> {
    let argon_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(32))
        .map_err(|e| format!("invalid Argon2 params: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(passphrase, salt, &mut out)
        .map_err(|e| format!("Argon2id failed: {e}"))?;
    Ok(out)
}

/// Generate a fresh 16-byte salt from the OS CSPRNG.
pub fn fresh_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

const V2_PREFIX: &str = "v2|";

/// Wrap a vodozemac inner blob into a v2 envelope string.
pub fn encode_v2_envelope(params: &Argon2Params, salt: &[u8; 16], inner: &str) -> String {
    let mut header = [0u8; 28];
    header[0..4].copy_from_slice(&params.m_cost.to_be_bytes());
    header[4..8].copy_from_slice(&params.t_cost.to_be_bytes());
    header[8..12].copy_from_slice(&params.p_cost.to_be_bytes());
    header[12..28].copy_from_slice(salt);
    let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header);
    format!("{V2_PREFIX}{header_b64}|{inner}")
}

/// Inspect an encrypted string and tell us which envelope kind it is.
pub fn decode_envelope(encrypted: &str) -> Result<EnvelopeKind<'_>, String> {
    if let Some(rest) = encrypted.strip_prefix(V2_PREFIX) {
        let (header_b64, inner) = rest
            .split_once('|')
            .ok_or_else(|| "v2 envelope missing inner separator".to_string())?;
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(header_b64)
            .map_err(|e| format!("v2 header base64 decode failed: {e}"))?;
        if header.len() != 28 {
            return Err(format!(
                "v2 header has wrong length {} (expected 28)",
                header.len()
            ));
        }
        let m_cost = u32::from_be_bytes(header[0..4].try_into().unwrap());
        let t_cost = u32::from_be_bytes(header[4..8].try_into().unwrap());
        let p_cost = u32::from_be_bytes(header[8..12].try_into().unwrap());
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&header[12..28]);
        Ok(EnvelopeKind::V2 {
            params: Argon2Params {
                m_cost,
                t_cost,
                p_cost,
            },
            salt,
            inner,
        })
    } else {
        Ok(EnvelopeKind::V1 { inner: encrypted })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2_round_trip() {
        let params = Argon2Params::default_v2();
        let salt = [42u8; 16];
        let envelope = encode_v2_envelope(&params, &salt, "vodozemac-inner-blob");
        assert!(envelope.starts_with("v2|"));
        match decode_envelope(&envelope).unwrap() {
            EnvelopeKind::V2 {
                params: p,
                salt: s,
                inner,
            } => {
                assert_eq!(p, params);
                assert_eq!(s, salt);
                assert_eq!(inner, "vodozemac-inner-blob");
            }
            EnvelopeKind::V1 { .. } => panic!("expected v2"),
        }
    }

    #[test]
    fn v1_passthrough() {
        match decode_envelope("legacy-vodozemac-blob").unwrap() {
            EnvelopeKind::V1 { inner } => assert_eq!(inner, "legacy-vodozemac-blob"),
            EnvelopeKind::V2 { .. } => panic!("expected v1"),
        }
    }

    #[test]
    fn malformed_v2_errors() {
        assert!(decode_envelope("v2|notbase64!|inner").is_err());
        assert!(decode_envelope("v2|aGVsbG8|inner").is_err()); // wrong header length
        assert!(decode_envelope("v2|noinnerseparator").is_err());
    }

    #[test]
    fn argon2_derive_is_salt_dependent() {
        let params = Argon2Params::default_v2();
        let salt_a = [1u8; 16];
        let salt_b = [2u8; 16];
        let key_a = derive_v2(b"pw", &params, &salt_a).unwrap();
        let key_b = derive_v2(b"pw", &params, &salt_b).unwrap();
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn fresh_salt_is_random() {
        let a = fresh_salt();
        let b = fresh_salt();
        assert_ne!(a, b);
    }
}
```

- [ ] **Step 2: Register the module in `lib.rs`**

In `crates/vodozemac-python/src/lib.rs`, replace lines 3-9 with:

```rust
mod account;
mod errors;
mod group_session;
mod inbound_group_session;
mod pickle_format;
mod pk;
mod session;
```

(`pickle_format` inserted alphabetically.)

- [ ] **Step 3: Run the Rust tests**

Run: `cargo test --manifest-path crates/vodozemac-python/Cargo.toml pickle_format::`
Expected: all 5 unit tests in `pickle_format::tests` PASS.

If `cargo test` complains it can't find the `extension-module` feature in a test target, run `cargo test --manifest-path crates/vodozemac-python/Cargo.toml --no-default-features` instead — but the standard invocation should work because the `pickle_format` module has no PyO3 surface yet.

- [ ] **Step 4: Commit**

```bash
git add crates/vodozemac-python/src/pickle_format.rs crates/vodozemac-python/src/lib.rs
git commit -m "feat(crate): add pickle_format module with Argon2id v2 envelope

Pure-Rust helpers (no PyO3 surface yet) for v2 pickle format:
- Argon2Params struct with RFC 9106 second-recommended defaults
- encode_v2_envelope / decode_envelope for the \"v2|<hdr>|<inner>\" wrapper
- derive_v2 (Argon2id) and passphrase_to_key_v1 (legacy zero-pad)
- Unit tests cover round-trip, malformed input, salt sensitivity, RNG.

No call sites wired up yet; subsequent commits migrate Account, Session,
GroupSession, InboundGroupSession to use this module."
```

---

## Task 3: Migrate `Account` to v2 + expose test-only v1 helper

Replace `Account::to_encrypted_string` and `Account::from_encrypted_string` to go through the envelope helpers. Keep a `#[pyfunction]` named `_v1_encrypt_account_for_testing` so Python tests can produce v1 blobs without committing binary fixtures.

The same pattern repeats for the other three pickled types (Tasks 4-6). They are independent commits.

**Files:**
- Modify: `crates/vodozemac-python/src/account.rs`
- Modify: `crates/vodozemac-python/src/lib.rs` (register the test-only function)

- [ ] **Step 1: Update `account.rs`**

Replace the entire content of `crates/vodozemac-python/src/account.rs` with:

```rust
use pyo3::prelude::*;
use pyo3::types::PyDict;
use vodozemac::olm::{
    Account as VzAccount, AccountPickle, PreKeyMessage, SessionConfig,
};
use vodozemac::Curve25519PublicKey;

use crate::errors::OlmAccountError;
use crate::pickle_format::{
    decode_envelope, derive_v2, encode_v2_envelope, fresh_salt, passphrase_to_key_v1,
    Argon2Params, EnvelopeKind,
};
use crate::session::Session;

#[pyclass]
pub struct Account {
    pub(crate) inner: VzAccount,
}

#[pymethods]
impl Account {
    #[new]
    fn new() -> Self {
        Self {
            inner: VzAccount::new(),
        }
    }

    fn identity_keys<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let keys = self.inner.identity_keys();
        let dict = PyDict::new(py);
        dict.set_item("ed25519", keys.ed25519.to_base64())?;
        dict.set_item("curve25519", keys.curve25519.to_base64())?;
        Ok(dict)
    }

    fn sign(&self, message: &[u8]) -> String {
        self.inner.sign(message).to_base64()
    }

    fn generate_one_time_keys(&mut self, count: usize) {
        self.inner.generate_one_time_keys(count);
    }

    fn one_time_keys<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let otks = self.inner.one_time_keys();
        let dict = PyDict::new(py);
        for (key_id, key) in otks {
            dict.set_item(key_id.to_base64(), key.to_base64())?;
        }
        Ok(dict)
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
            .map_err(|e| OlmAccountError::new_err(format!("Invalid identity key: {e}")))?;
        let otk = Curve25519PublicKey::from_base64(their_one_time_key)
            .map_err(|e| OlmAccountError::new_err(format!("Invalid one-time key: {e}")))?;
        let session = self
            .inner
            .create_outbound_session(SessionConfig::version_2(), identity, otk);
        Ok(Session::from_vz(session))
    }

    #[pyo3(signature = (their_identity_key, pre_key_message_bytes))]
    fn create_inbound_session(
        &mut self,
        their_identity_key: Option<&str>,
        pre_key_message_bytes: &[u8],
    ) -> PyResult<(Session, Vec<u8>)> {
        let pre_key_message = PreKeyMessage::from_bytes(pre_key_message_bytes)
            .map_err(|e| OlmAccountError::new_err(format!("Invalid pre-key message: {e}")))?;
        let identity = match their_identity_key {
            Some(key) if !key.is_empty() => Curve25519PublicKey::from_base64(key)
                .map_err(|e| OlmAccountError::new_err(format!("Invalid identity key: {e}")))?,
            _ => pre_key_message.identity_key(),
        };
        let result = self
            .inner
            .create_inbound_session(identity, &pre_key_message)
            .map_err(|e| OlmAccountError::new_err(format!("Session creation failed: {e}")))?;
        let session = Session::from_vz(result.session);
        Ok((session, result.plaintext))
    }

    /// Serialize the account, deriving an AES key from the passphrase via
    /// Argon2id. Returns a v2 envelope string.
    fn to_encrypted_string(&self, passphrase: &[u8]) -> PyResult<String> {
        let params = Argon2Params::default_v2();
        let salt = fresh_salt();
        let key = derive_v2(passphrase, &params, &salt)
            .map_err(|e| OlmAccountError::new_err(e))?;
        let inner = self.inner.pickle().encrypt(&key);
        Ok(encode_v2_envelope(&params, &salt, &inner))
    }

    /// Restore an Account from an encrypted string. Detects v2 vs v1 from
    /// the prefix and dispatches to the correct KDF.
    #[staticmethod]
    fn from_encrypted_string(encrypted: &str, passphrase: &[u8]) -> PyResult<Self> {
        let (key, vodozemac_inner, was_legacy) = match decode_envelope(encrypted)
            .map_err(|e| OlmAccountError::new_err(e))?
        {
            EnvelopeKind::V2 {
                params,
                salt,
                inner,
            } => {
                let k = derive_v2(passphrase, &params, &salt)
                    .map_err(|e| OlmAccountError::new_err(e))?;
                (k, inner.to_string(), false)
            }
            EnvelopeKind::V1 { inner } => {
                (passphrase_to_key_v1(passphrase), inner.to_string(), true)
            }
        };
        if was_legacy {
            emit_v1_deprecation_warning("Account")?;
        }
        let ap = AccountPickle::from_encrypted(&vodozemac_inner, &key)
            .map_err(|e| OlmAccountError::new_err(format!("Deserialization failed: {e}")))?;
        Ok(Self {
            inner: VzAccount::from_pickle(ap),
        })
    }

    fn __repr__(&self) -> String {
        let keys = self.inner.identity_keys();
        format!(
            "Account(ed25519=\"{}\", curve25519=\"{}\")",
            keys.ed25519.to_base64(),
            keys.curve25519.to_base64()
        )
    }
}

/// Emit a Python `DeprecationWarning` indicating a legacy v1 pickle was just
/// loaded. Called once per `from_encrypted_string` call that hits the v1
/// branch. Python's default warning filter dedupes by call-site.
pub(crate) fn emit_v1_deprecation_warning(kind: &str) -> PyResult<()> {
    Python::with_gil(|py| {
        let warnings = py.import("warnings")?;
        let msg = format!(
            "Loaded legacy v1 pickle for {kind}. v1 used a weak passphrase \
             KDF (zero-pad, no salt). Re-pickle with this version of \
             fresholm to migrate to v2 (Argon2id). v1 support will be \
             removed in 0.4.0."
        );
        let warning_type = py.get_type::<pyo3::exceptions::PyDeprecationWarning>();
        warnings.call_method1("warn", (msg, warning_type))?;
        Ok(())
    })
}

/// Test-only: re-encrypt an Account using the legacy v1 KDF so Python tests
/// can exercise the v1 decode path without committing binary fixtures.
/// NOT a stable API. Underscored name signals internal-only.
#[pyfunction]
pub(crate) fn _v1_encrypt_account_for_testing(
    account: PyRef<'_, Account>,
    passphrase: &[u8],
) -> String {
    let key = passphrase_to_key_v1(passphrase);
    account.inner.pickle().encrypt(&key)
}
```

- [ ] **Step 2: Register the test-only function in `lib.rs`**

In `crates/vodozemac-python/src/lib.rs`, replace the body of `fresholm_native` with:

```rust
fn fresholm_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    errors::register_exceptions(m)?;
    m.add_class::<account::Account>()?;
    m.add_class::<session::Session>()?;
    m.add_class::<session::EncryptedMessage>()?;
    m.add_class::<group_session::GroupSession>()?;
    m.add_class::<inbound_group_session::InboundGroupSession>()?;
    m.add_class::<pk::PkEncryption>()?;
    m.add_class::<pk::PkDecryption>()?;
    m.add_class::<pk::PkMessage>()?;
    m.add_function(wrap_pyfunction!(account::_v1_encrypt_account_for_testing, m)?)?;
    Ok(())
}
```

And ensure the file imports `wrap_pyfunction` — replace line 1 with:

```rust
use pyo3::prelude::*;
use pyo3::wrap_pyfunction;
```

- [ ] **Step 3: Build the wheel and run existing Rust + Python tests**

Run:
```bash
maturin develop --release --manifest-path crates/vodozemac-python/Cargo.toml
pytest tests/test_account.py -v
```

Expected: all `test_account.py` tests PASS. The existing serialization tests there round-trip through `to_encrypted_string` / `from_encrypted_string` — they will now go through the v2 envelope, which round-trips correctly.

- [ ] **Step 4: Commit**

```bash
git add crates/vodozemac-python/src/account.rs crates/vodozemac-python/src/lib.rs
git commit -m "feat(crate): migrate Account pickle to v2 (Argon2id + salt)

Account.to_encrypted_string now emits the v2 envelope:
  \"v2|<base64(params||salt)>|<vodozemac_inner>\"
Argon2id derives the 32-byte key vodozemac uses for AES.

from_encrypted_string detects v2 by the \"v2|\" prefix and falls back to
the legacy zero-pad KDF for unprefixed strings, emitting a
DeprecationWarning. v1 read support is retained until 0.4.0.

Adds _v1_encrypt_account_for_testing to enable Python tests of the v1
fallback path without committing binary fixtures."
```

---

## Task 4: Migrate `Session` to v2

Same pattern as Task 3, applied to `Session`.

**Files:**
- Modify: `crates/vodozemac-python/src/session.rs`
- Modify: `crates/vodozemac-python/src/lib.rs` (register one more `_v1_encrypt_*_for_testing` function)

- [ ] **Step 1: Update `session.rs`**

In `crates/vodozemac-python/src/session.rs`, replace the imports block and the two pickle methods.

Replace lines 1-5 with:

```rust
use pyo3::prelude::*;
use vodozemac::olm::{OlmMessage, PreKeyMessage, Session as VzSession, SessionPickle};

use crate::errors::OlmSessionError;
use crate::pickle_format::{
    decode_envelope, derive_v2, encode_v2_envelope, fresh_salt, passphrase_to_key_v1,
    Argon2Params, EnvelopeKind,
};
```

(That is, drop the `use crate::account::passphrase_to_key;` line.)

Replace `to_encrypted_string` (currently lines 88-91) with:

```rust
    /// Serialize the session via Argon2id v2 envelope.
    fn to_encrypted_string(&self, passphrase: &[u8]) -> PyResult<String> {
        let params = Argon2Params::default_v2();
        let salt = fresh_salt();
        let key = derive_v2(passphrase, &params, &salt)
            .map_err(|e| OlmSessionError::new_err(e))?;
        let inner = self.inner.pickle().encrypt(&key);
        Ok(encode_v2_envelope(&params, &salt, &inner))
    }
```

Replace `from_encrypted_string` (currently lines 94-101) with:

```rust
    /// Restore a Session, dispatching v2/v1 based on the envelope.
    #[staticmethod]
    fn from_encrypted_string(encrypted: &str, passphrase: &[u8]) -> PyResult<Self> {
        let (key, vodozemac_inner, was_legacy) = match decode_envelope(encrypted)
            .map_err(|e| OlmSessionError::new_err(e))?
        {
            EnvelopeKind::V2 {
                params,
                salt,
                inner,
            } => {
                let k = derive_v2(passphrase, &params, &salt)
                    .map_err(|e| OlmSessionError::new_err(e))?;
                (k, inner.to_string(), false)
            }
            EnvelopeKind::V1 { inner } => {
                (passphrase_to_key_v1(passphrase), inner.to_string(), true)
            }
        };
        if was_legacy {
            crate::account::emit_v1_deprecation_warning("Session")?;
        }
        let sp = SessionPickle::from_encrypted(&vodozemac_inner, &key)
            .map_err(|e| OlmSessionError::new_err(format!("Deserialization failed: {e}")))?;
        Ok(Self {
            inner: VzSession::from_pickle(sp),
        })
    }
```

Then, after the closing `}` of `impl Session`'s `#[pymethods]` block (after line 117), append:

```rust

/// Test-only v1 encryption helper for Session — see Account analogue.
#[pyfunction]
pub(crate) fn _v1_encrypt_session_for_testing(
    session: PyRef<'_, Session>,
    passphrase: &[u8],
) -> String {
    let key = passphrase_to_key_v1(passphrase);
    session.inner.pickle().encrypt(&key)
}
```

- [ ] **Step 2: Register the test helper in `lib.rs`**

In `crates/vodozemac-python/src/lib.rs`, add this line inside `fresholm_native` after the existing `_v1_encrypt_account_for_testing` registration:

```rust
    m.add_function(wrap_pyfunction!(session::_v1_encrypt_session_for_testing, m)?)?;
```

- [ ] **Step 3: Build and test**

Run:
```bash
maturin develop --release --manifest-path crates/vodozemac-python/Cargo.toml
pytest tests/test_session.py tests/test_sessions.py -v
```

Expected: all PASS. Both existing test files exercise session pickle round-trips and will run through v2.

- [ ] **Step 4: Commit**

```bash
git add crates/vodozemac-python/src/session.rs crates/vodozemac-python/src/lib.rs
git commit -m "feat(crate): migrate Session pickle to v2 (Argon2id + salt)"
```

---

## Task 5: Migrate `GroupSession` to v2

Same pattern.

**Files:**
- Modify: `crates/vodozemac-python/src/group_session.rs`
- Modify: `crates/vodozemac-python/src/lib.rs`

- [ ] **Step 1: Update `group_session.rs`**

Replace the imports block (lines 1-7) with:

```rust
use pyo3::prelude::*;
use vodozemac::megolm::{
    GroupSession as VzGroupSession, GroupSessionPickle, SessionConfig,
};

use crate::errors::OlmGroupSessionError;
use crate::pickle_format::{
    decode_envelope, derive_v2, encode_v2_envelope, fresh_salt, passphrase_to_key_v1,
    Argon2Params, EnvelopeKind,
};
```

Replace `to_encrypted_string` (lines 44-47) with:

```rust
    /// Serialize the group session via Argon2id v2 envelope.
    fn to_encrypted_string(&self, passphrase: &[u8]) -> PyResult<String> {
        let params = Argon2Params::default_v2();
        let salt = fresh_salt();
        let key = derive_v2(passphrase, &params, &salt)
            .map_err(|e| OlmGroupSessionError::new_err(e))?;
        let inner = self.inner.pickle().encrypt(&key);
        Ok(encode_v2_envelope(&params, &salt, &inner))
    }
```

Replace `from_encrypted_string` (lines 50-57) with:

```rust
    /// Restore a GroupSession, dispatching v2/v1 by envelope.
    #[staticmethod]
    fn from_encrypted_string(encrypted: &str, passphrase: &[u8]) -> PyResult<Self> {
        let (key, vodozemac_inner, was_legacy) = match decode_envelope(encrypted)
            .map_err(|e| OlmGroupSessionError::new_err(e))?
        {
            EnvelopeKind::V2 {
                params,
                salt,
                inner,
            } => {
                let k = derive_v2(passphrase, &params, &salt)
                    .map_err(|e| OlmGroupSessionError::new_err(e))?;
                (k, inner.to_string(), false)
            }
            EnvelopeKind::V1 { inner } => {
                (passphrase_to_key_v1(passphrase), inner.to_string(), true)
            }
        };
        if was_legacy {
            crate::account::emit_v1_deprecation_warning("GroupSession")?;
        }
        let gp = GroupSessionPickle::from_encrypted(&vodozemac_inner, &key)
            .map_err(|e| OlmGroupSessionError::new_err(format!("Deserialization failed: {e}")))?;
        Ok(Self {
            inner: VzGroupSession::from_pickle(gp),
        })
    }
```

After the closing `}` of `impl GroupSession`'s `#[pymethods]` block, append:

```rust

#[pyfunction]
pub(crate) fn _v1_encrypt_group_session_for_testing(
    session: PyRef<'_, GroupSession>,
    passphrase: &[u8],
) -> String {
    let key = passphrase_to_key_v1(passphrase);
    session.inner.pickle().encrypt(&key)
}
```

- [ ] **Step 2: Register in `lib.rs`**

Add to `fresholm_native`:

```rust
    m.add_function(wrap_pyfunction!(group_session::_v1_encrypt_group_session_for_testing, m)?)?;
```

- [ ] **Step 3: Build and test**

Run:
```bash
maturin develop --release --manifest-path crates/vodozemac-python/Cargo.toml
pytest tests/test_group_session.py -v
```

Expected: all PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/vodozemac-python/src/group_session.rs crates/vodozemac-python/src/lib.rs
git commit -m "feat(crate): migrate GroupSession pickle to v2 (Argon2id + salt)"
```

---

## Task 6: Migrate `InboundGroupSession` to v2

Same pattern.

**Files:**
- Modify: `crates/vodozemac-python/src/inbound_group_session.rs`
- Modify: `crates/vodozemac-python/src/lib.rs`

- [ ] **Step 1: Update `inbound_group_session.rs`**

Replace the imports block (lines 1-8) with:

```rust
use pyo3::prelude::*;
use vodozemac::megolm::{
    ExportedSessionKey, InboundGroupSession as VzInboundGroupSession,
    InboundGroupSessionPickle, MegolmMessage, SessionConfig, SessionKey,
};

use crate::errors::OlmGroupSessionError;
use crate::pickle_format::{
    decode_envelope, derive_v2, encode_v2_envelope, fresh_salt, passphrase_to_key_v1,
    Argon2Params, EnvelopeKind,
};
```

Replace `to_encrypted_string` (lines 71-74) with:

```rust
    /// Serialize the inbound group session via Argon2id v2 envelope.
    fn to_encrypted_string(&self, passphrase: &[u8]) -> PyResult<String> {
        let params = Argon2Params::default_v2();
        let salt = fresh_salt();
        let key = derive_v2(passphrase, &params, &salt)
            .map_err(|e| OlmGroupSessionError::new_err(e))?;
        let inner = self.inner.pickle().encrypt(&key);
        Ok(encode_v2_envelope(&params, &salt, &inner))
    }
```

Replace `from_encrypted_string` (lines 77-84) with:

```rust
    /// Restore an InboundGroupSession, dispatching v2/v1 by envelope.
    #[staticmethod]
    fn from_encrypted_string(encrypted: &str, passphrase: &[u8]) -> PyResult<Self> {
        let (key, vodozemac_inner, was_legacy) = match decode_envelope(encrypted)
            .map_err(|e| OlmGroupSessionError::new_err(e))?
        {
            EnvelopeKind::V2 {
                params,
                salt,
                inner,
            } => {
                let k = derive_v2(passphrase, &params, &salt)
                    .map_err(|e| OlmGroupSessionError::new_err(e))?;
                (k, inner.to_string(), false)
            }
            EnvelopeKind::V1 { inner } => {
                (passphrase_to_key_v1(passphrase), inner.to_string(), true)
            }
        };
        if was_legacy {
            crate::account::emit_v1_deprecation_warning("InboundGroupSession")?;
        }
        let igp = InboundGroupSessionPickle::from_encrypted(&vodozemac_inner, &key)
            .map_err(|e| OlmGroupSessionError::new_err(format!("Deserialization failed: {e}")))?;
        Ok(Self {
            inner: VzInboundGroupSession::from_pickle(igp),
        })
    }
```

After the closing `}` of `impl InboundGroupSession`'s `#[pymethods]` block, append:

```rust

#[pyfunction]
pub(crate) fn _v1_encrypt_inbound_group_session_for_testing(
    session: PyRef<'_, InboundGroupSession>,
    passphrase: &[u8],
) -> String {
    let key = passphrase_to_key_v1(passphrase);
    session.inner.pickle().encrypt(&key)
}
```

- [ ] **Step 2: Register in `lib.rs`**

Add to `fresholm_native`:

```rust
    m.add_function(wrap_pyfunction!(inbound_group_session::_v1_encrypt_inbound_group_session_for_testing, m)?)?;
```

- [ ] **Step 3: Build and test**

Run:
```bash
maturin develop --release --manifest-path crates/vodozemac-python/Cargo.toml
pytest tests/test_group_session.py -v
```

Expected: all PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/vodozemac-python/src/inbound_group_session.rs crates/vodozemac-python/src/lib.rs
git commit -m "feat(crate): migrate InboundGroupSession pickle to v2 (Argon2id + salt)"
```

---

## Task 7: Add Python-level format tests

Cover the v2/v1 dispatch behavior end-to-end at the Python level: format detection by prefix, v2 round-trip with random salt (different blob each time), v1 fallback emits `DeprecationWarning` and decrypts correctly, wrong passphrase fails on both paths.

**Files:**
- Create: `tests/test_pickle_format.py`

- [ ] **Step 1: Write the test file**

Create `tests/test_pickle_format.py` with this content:

```python
"""Tests for the v2 pickle envelope and v1 fallback.

The four pickled types — Account, Session, GroupSession,
InboundGroupSession — share a common envelope. We exercise each one to
catch wiring mistakes (e.g., a missed call site that still uses the v1
encrypt path).
"""

import warnings

import pytest

from fresholm._native import (
    Account,
    GroupSession,
    InboundGroupSession,
    Session,
    _v1_encrypt_account_for_testing,
    _v1_encrypt_group_session_for_testing,
    _v1_encrypt_inbound_group_session_for_testing,
    _v1_encrypt_session_for_testing,
)


PASSPHRASE = b"correct horse battery staple"
WRONG_PASSPHRASE = b"a different passphrase"


def _fresh_session_pair():
    """Return (alice_account, alice_session, bob_inbound_group_session).

    A bit of setup to obtain valid instances of all four pickled types.
    """
    alice = Account()
    bob = Account()
    bob.generate_one_time_keys(1)
    bob_otk = list(bob.one_time_keys().values())[0]
    bob_id = bob.identity_keys()["curve25519"]
    alice_session = alice.create_outbound_session(bob_id, bob_otk)
    out_group = GroupSession()
    in_group = InboundGroupSession(out_group.session_key())
    return alice, alice_session, out_group, in_group


# ---------------------------------------------------------------------------
# v2 round-trip
# ---------------------------------------------------------------------------


class TestV2RoundTrip:
    def test_account_v2_emits_prefix(self):
        a, _, _, _ = _fresh_session_pair()
        blob = a.to_encrypted_string(PASSPHRASE)
        assert blob.startswith("v2|"), blob[:8]

    def test_account_v2_round_trip(self):
        a, _, _, _ = _fresh_session_pair()
        blob = a.to_encrypted_string(PASSPHRASE)
        restored = Account.from_encrypted_string(blob, PASSPHRASE)
        assert restored.identity_keys() == a.identity_keys()

    def test_account_v2_salt_is_random(self):
        """Two pickles of the same account differ — confirms per-pickle salt."""
        a, _, _, _ = _fresh_session_pair()
        blob1 = a.to_encrypted_string(PASSPHRASE)
        blob2 = a.to_encrypted_string(PASSPHRASE)
        assert blob1 != blob2

    def test_session_v2_round_trip(self):
        _, sess, _, _ = _fresh_session_pair()
        blob = sess.to_encrypted_string(PASSPHRASE)
        assert blob.startswith("v2|")
        restored = Session.from_encrypted_string(blob, PASSPHRASE)
        assert restored.session_id() == sess.session_id()

    def test_group_session_v2_round_trip(self):
        _, _, out_group, _ = _fresh_session_pair()
        blob = out_group.to_encrypted_string(PASSPHRASE)
        assert blob.startswith("v2|")
        restored = GroupSession.from_encrypted_string(blob, PASSPHRASE)
        assert restored.session_id() == out_group.session_id()

    def test_inbound_group_session_v2_round_trip(self):
        _, _, _, in_group = _fresh_session_pair()
        blob = in_group.to_encrypted_string(PASSPHRASE)
        assert blob.startswith("v2|")
        restored = InboundGroupSession.from_encrypted_string(blob, PASSPHRASE)
        assert restored.session_id() == in_group.session_id()


# ---------------------------------------------------------------------------
# v1 legacy fallback
# ---------------------------------------------------------------------------


class TestV1LegacyDecode:
    def test_account_v1_does_not_have_v2_prefix(self):
        a, _, _, _ = _fresh_session_pair()
        blob = _v1_encrypt_account_for_testing(a, PASSPHRASE)
        assert not blob.startswith("v2|")

    def test_account_v1_decode_succeeds(self):
        a, _, _, _ = _fresh_session_pair()
        blob = _v1_encrypt_account_for_testing(a, PASSPHRASE)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            restored = Account.from_encrypted_string(blob, PASSPHRASE)
        assert restored.identity_keys() == a.identity_keys()
        # exactly one DeprecationWarning fired, mentioning v1 and Account
        dep = [w for w in caught if issubclass(w.category, DeprecationWarning)]
        assert len(dep) == 1
        msg = str(dep[0].message)
        assert "v1" in msg and "Account" in msg

    def test_session_v1_decode_with_warning(self):
        _, sess, _, _ = _fresh_session_pair()
        blob = _v1_encrypt_session_for_testing(sess, PASSPHRASE)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            restored = Session.from_encrypted_string(blob, PASSPHRASE)
        assert restored.session_id() == sess.session_id()
        dep = [w for w in caught if issubclass(w.category, DeprecationWarning)]
        assert any("Session" in str(w.message) for w in dep)

    def test_group_session_v1_decode_with_warning(self):
        _, _, out_group, _ = _fresh_session_pair()
        blob = _v1_encrypt_group_session_for_testing(out_group, PASSPHRASE)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            restored = GroupSession.from_encrypted_string(blob, PASSPHRASE)
        assert restored.session_id() == out_group.session_id()
        dep = [w for w in caught if issubclass(w.category, DeprecationWarning)]
        assert any("GroupSession" in str(w.message) for w in dep)

    def test_inbound_group_session_v1_decode_with_warning(self):
        _, _, _, in_group = _fresh_session_pair()
        blob = _v1_encrypt_inbound_group_session_for_testing(in_group, PASSPHRASE)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            restored = InboundGroupSession.from_encrypted_string(blob, PASSPHRASE)
        assert restored.session_id() == in_group.session_id()
        dep = [w for w in caught if issubclass(w.category, DeprecationWarning)]
        assert any("InboundGroupSession" in str(w.message) for w in dep)


# ---------------------------------------------------------------------------
# Wrong passphrase rejection (both paths)
# ---------------------------------------------------------------------------


class TestWrongPassphrase:
    def test_v2_wrong_passphrase_fails(self):
        a, _, _, _ = _fresh_session_pair()
        blob = a.to_encrypted_string(PASSPHRASE)
        with pytest.raises(Exception):  # vodozemac raises OlmAccountError
            Account.from_encrypted_string(blob, WRONG_PASSPHRASE)

    def test_v1_wrong_passphrase_fails(self):
        a, _, _, _ = _fresh_session_pair()
        blob = _v1_encrypt_account_for_testing(a, PASSPHRASE)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            with pytest.raises(Exception):
                Account.from_encrypted_string(blob, WRONG_PASSPHRASE)


# ---------------------------------------------------------------------------
# Format detection edge cases
# ---------------------------------------------------------------------------


class TestEnvelopeDetection:
    def test_malformed_v2_envelope_errors(self):
        with pytest.raises(Exception):
            Account.from_encrypted_string("v2|not-valid-base64!|garbage", PASSPHRASE)

    def test_v2_with_truncated_inner_errors(self):
        # Real header, no inner payload after the second `|`
        a, _, _, _ = _fresh_session_pair()
        blob = a.to_encrypted_string(PASSPHRASE)
        # strip the inner blob, keeping "v2|<header>|"
        envelope = blob.rsplit("|", 1)[0] + "|"
        with pytest.raises(Exception):
            Account.from_encrypted_string(envelope, PASSPHRASE)
```

- [ ] **Step 2: Run the new test file**

Run: `pytest tests/test_pickle_format.py -v`
Expected: all tests PASS.

- [ ] **Step 3: Run the full test suite as a regression check**

Run: `pytest tests/ -v`
Expected: all PASS (including all existing pickle-round-trip tests in `test_account.py`, `test_session.py`, `test_sessions.py`, `test_group_session.py` — they now go through v2 transparently).

- [ ] **Step 4: Commit**

```bash
git add tests/test_pickle_format.py
git commit -m "test: cover v2 pickle envelope + v1 deprecation fallback

Verifies for all four pickled types (Account, Session, GroupSession,
InboundGroupSession): v2 prefix, salt randomness, v2 round-trip, v1
fallback decoding with DeprecationWarning, wrong-passphrase rejection
on both paths, and malformed-envelope rejection.

The _v1_encrypt_*_for_testing helpers in fresholm._native are used to
produce v1 blobs without committing binary fixtures."
```

---

## Task 8: Bump version and document the breaking change

**Files:**
- Modify: `pyproject.toml`
- Modify: `docs/superpowers/notes/2026-04-27-vodozemac-pickle-kdf.md` (add resolution footer)

- [ ] **Step 1: Bump the version**

In `pyproject.toml`, change:

```toml
version = "0.2.6"
```

to:

```toml
version = "0.3.0"
```

(If the working tree is still on `0.2.5`, bump from there directly to `0.3.0` — Bugs 1/2/3 may have shipped as `0.2.6` already, in which case the working tree should already say `0.2.6`. Either way, the target is `0.3.0`.)

- [ ] **Step 2: Append a resolution footer to the KDF investigation note**

Open `docs/superpowers/notes/2026-04-27-vodozemac-pickle-kdf.md` and append at the end:

```markdown

---

## Resolution

Implemented in 0.3.0 per `docs/superpowers/plans/2026-04-28-pickle-kdf-v2.md`.

- New `pickle_format` module in `crates/vodozemac-python/src/`.
- v2 envelope: `"v2|" || base64url(m_cost||t_cost||p_cost||salt[16]) || "|" || vodozemac_inner`.
- Argon2id, RFC 9106 second-recommended profile (m=19456, t=2, p=1).
- v1 blobs still decode; calling `from_encrypted_string` on a v1 blob emits a
  `DeprecationWarning`. v1 read support will be removed in 0.4.0.
```

- [ ] **Step 3: Run the full test suite one final time**

Run: `pytest tests/ -v`
Expected: all PASS.

- [ ] **Step 4: Commit**

```bash
git add pyproject.toml docs/superpowers/notes/2026-04-27-vodozemac-pickle-kdf.md
git commit -m "release: 0.3.0 — Argon2id pickle KDF (BREAKING)

Pickled blobs produced by 0.3.0 cannot be read by 0.2.x. 0.3.0 reads
both v2 (Argon2id) and v1 (legacy zero-pad) blobs; v1 decode emits a
DeprecationWarning and will be removed in 0.4.0.

See docs/superpowers/plans/2026-04-28-pickle-kdf-v2.md."
```

---

## Self-review notes

**Spec coverage (against `docs/superpowers/notes/2026-04-27-vodozemac-pickle-kdf.md` § Recommended next steps):**

1. *Choose a password hashing scheme* → Argon2id, RFC 9106 second profile. Tasks 1, 2.
2. *Define a new blob prefix* → `"v2|"` + base64-encoded 28-byte header. Task 2.
3. *Implement `passphrase_to_key_v2`* → `derive_v2` in `pickle_format`. Task 2.
4. *Keep dual-decode for one release window* → `decode_envelope` dispatches; v1 path emits `DeprecationWarning`. Tasks 3-6.
5. *Document as 0.3.0 breaking change* → Task 8 bumps version + appends resolution to the note.
6. *Update all five call sites* → Tasks 3-6 (Account, Session, GroupSession, InboundGroupSession). Note: the original recommendation said "five sites" because it counted by file. There are actually 8 method bodies (4 files × `to_/from_encrypted_string`). All migrated.
7. *Add a test that 1-character passphrase yields a different key per call* → `test_account_v2_salt_is_random` in Task 7. (The Rust unit test `argon2_derive_is_salt_dependent` from Task 2 also covers this directly.)

**Type/API consistency:**
- The shared envelope helpers (`encode_v2_envelope`, `decode_envelope`, `derive_v2`, `passphrase_to_key_v1`, `Argon2Params`, `EnvelopeKind`, `fresh_salt`) are referenced from each migrated file and from the unit tests. Names match across all uses.
- `emit_v1_deprecation_warning` is defined in `account.rs` and re-imported via `crate::account::emit_v1_deprecation_warning` from `session.rs`, `group_session.rs`, `inbound_group_session.rs`. Single source of truth.
- `_v1_encrypt_*_for_testing` PyO3 functions follow the same naming pattern across all four types.

**Risk: Argon2id work factor on CI.** RFC 9106 second profile uses ~19 MiB and 2 iterations — typically 50-150 ms per derivation on modern hardware. Each pickle test triggers one derivation per round-trip; the test suite has ~10 pickle tests across all files. Total added wall-clock cost: ~1-3 seconds, acceptable on CI.

**Risk: warning-emission semantics.** `warnings.warn(..., DeprecationWarning)` from PyO3 honors Python's warning filter. By default, `DeprecationWarning` is hidden in `__main__` but visible in pytest. The tests use `warnings.catch_warnings()` + `simplefilter("always")` to capture deterministically.

**Risk: cross-version compatibility window.**
- 0.3.0 reads v1 (legacy 0.2.x) blobs ✅
- 0.3.0 reads v2 blobs ✅
- 0.2.x reads v1 blobs ✅
- 0.2.x **cannot** read v2 blobs (it has no envelope parser; `AccountPickle::from_encrypted("v2|...")` will fail at base64 decode). Document this clearly in the 0.3.0 release notes — users cannot downgrade once they re-pickle.

**Versioning:** This plan delivers 0.3.0. Bugs 1/2/3 from the companion plan should ship as 0.2.6 first.

**Out of scope (explicit):**
- Removing v1 decode entirely → 0.4.0 follow-up plan.
- A `fresholm migrate-pickle` CLI → not planned; users get migration automatically the next time they pickle.
- Argon2id parameter tunability → defaults are hard-coded; can be exposed as a kwarg later without breaking the format (params are read from the header on decode).

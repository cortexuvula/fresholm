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

// TODO(Task6): remove this shim once session.rs / group_session.rs /
// inbound_group_session.rs have been migrated to import directly from
// crate::pickle_format::passphrase_to_key_v1.
pub(crate) use crate::pickle_format::passphrase_to_key_v1 as passphrase_to_key;

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

    /// Return the identity keys as a dict with "ed25519" and "curve25519" base64 strings.
    fn identity_keys<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let keys = self.inner.identity_keys();
        let dict = PyDict::new(py);
        dict.set_item("ed25519", keys.ed25519.to_base64())?;
        dict.set_item("curve25519", keys.curve25519.to_base64())?;
        Ok(dict)
    }

    /// Sign the given message bytes and return a base64 signature string.
    fn sign(&self, message: &[u8]) -> String {
        self.inner.sign(message).to_base64()
    }

    /// Generate `count` one-time keys.
    fn generate_one_time_keys(&mut self, count: usize) {
        self.inner.generate_one_time_keys(count);
    }

    /// Return unpublished one-time keys as a dict {key_id_b64: key_b64}.
    fn one_time_keys<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let otks = self.inner.one_time_keys();
        let dict = PyDict::new(py);
        for (key_id, key) in otks {
            dict.set_item(key_id.to_base64(), key.to_base64())?;
        }
        Ok(dict)
    }

    /// Mark all one-time keys as published.
    fn mark_keys_as_published(&mut self) {
        self.inner.mark_keys_as_published();
    }

    /// Return the maximum number of one-time keys the account can hold.
    fn max_number_of_one_time_keys(&self) -> usize {
        self.inner.max_number_of_one_time_keys()
    }

    /// Create an outbound Olm session with the given identity key and one-time key (both base64).
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

    /// Create an inbound Olm session from a pre-key message.
    /// Returns (Session, plaintext_bytes).
    /// If their_identity_key is None or empty, extracts it from the PreKeyMessage.
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
            .map_err(OlmAccountError::new_err)?;
        let inner = self.inner.pickle().encrypt(&key);
        Ok(encode_v2_envelope(&params, &salt, &inner))
    }

    /// Restore an Account from an encrypted string. Detects v2 vs v1 from
    /// the prefix and dispatches to the correct KDF.
    ///
    /// `py` is required because the legacy path calls
    /// `emit_v1_deprecation_warning`; pyo3 0.28 injects this token
    /// automatically when invoked from Python.
    #[staticmethod]
    fn from_encrypted_string(py: Python<'_>, encrypted: &str, passphrase: &[u8]) -> PyResult<Self> {
        let (key, vodozemac_inner, was_legacy) = match decode_envelope(encrypted)
            .map_err(OlmAccountError::new_err)?
        {
            EnvelopeKind::V2 {
                params,
                salt,
                inner,
            } => {
                let k = derive_v2(passphrase, &params, &salt)
                    .map_err(OlmAccountError::new_err)?;
                (k, inner.to_string(), false)
            }
            EnvelopeKind::V1 { inner } => {
                (passphrase_to_key_v1(passphrase), inner.to_string(), true)
            }
        };
        if was_legacy {
            emit_v1_deprecation_warning(py, "Account")?;
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
///
/// Callers must pass a `Python<'_>` token; this is always available in a
/// `#[pymethods]` context (pyo3 0.28 removed `Python::with_gil`).
pub(crate) fn emit_v1_deprecation_warning(py: Python<'_>, kind: &str) -> PyResult<()> {
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
}

/// Test-only: re-encrypt an Account using the legacy v1 KDF so Python tests
/// can exercise the v1 decode path without committing binary fixtures.
/// NOT a stable API. Underscored name signals internal-only. Will be
/// removed in 0.4.0 along with the v1 decode path itself.
#[pyfunction]
pub(crate) fn _v1_encrypt_account_for_testing(
    account: PyRef<'_, Account>,
    passphrase: &[u8],
) -> String {
    let key = passphrase_to_key_v1(passphrase);
    account.inner.pickle().encrypt(&key)
}

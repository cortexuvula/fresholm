use pyo3::prelude::*;
use vodozemac::megolm::{
    GroupSession as VzGroupSession, GroupSessionPickle, SessionConfig,
};

use crate::errors::OlmGroupSessionError;
use crate::pickle_format::{
    decode_envelope, derive_v2, encode_v2_envelope, fresh_salt, passphrase_to_key_v1,
    Argon2Params, EnvelopeKind,
};

#[pyclass]
pub struct GroupSession {
    inner: VzGroupSession,
}

#[pymethods]
impl GroupSession {
    #[new]
    fn new() -> Self {
        Self {
            inner: VzGroupSession::new(SessionConfig::version_2()),
        }
    }

    /// Return the globally unique session ID (base64-encoded).
    fn session_id(&self) -> String {
        self.inner.session_id()
    }

    /// Return the session key as a base64-encoded string.
    fn session_key(&self) -> String {
        self.inner.session_key().to_base64()
    }

    /// Encrypt the given plaintext bytes. Returns a base64-encoded MegolmMessage.
    fn encrypt(&mut self, plaintext: &[u8]) -> String {
        self.inner.encrypt(plaintext).to_base64()
    }

    /// Return the current message index.
    fn message_index(&self) -> u32 {
        self.inner.message_index()
    }

    /// Serialize the group session via Argon2id v2 envelope.
    fn to_encrypted_string(&self, passphrase: &[u8]) -> PyResult<String> {
        let params = Argon2Params::default_v2();
        let salt = fresh_salt();
        let key = derive_v2(passphrase, &params, &salt)
            .map_err(OlmGroupSessionError::new_err)?;
        let inner = self.inner.pickle().encrypt(&key);
        Ok(encode_v2_envelope(&params, &salt, &inner))
    }

    /// Restore a GroupSession, dispatching v2/v1 by envelope.
    ///
    /// `py` is required because the legacy path calls
    /// `emit_v1_deprecation_warning`; pyo3 0.28 injects this token
    /// automatically when invoked from Python.
    #[staticmethod]
    fn from_encrypted_string(py: Python<'_>, encrypted: &str, passphrase: &[u8]) -> PyResult<Self> {
        let (key, vodozemac_inner, was_legacy) = match decode_envelope(encrypted)
            .map_err(OlmGroupSessionError::new_err)?
        {
            EnvelopeKind::V2 {
                params,
                salt,
                inner,
            } => {
                let k = derive_v2(passphrase, &params, &salt)
                    .map_err(OlmGroupSessionError::new_err)?;
                (k, inner.to_string(), false)
            }
            EnvelopeKind::V1 { inner } => {
                (passphrase_to_key_v1(passphrase), inner.to_string(), true)
            }
        };
        if was_legacy {
            crate::account::emit_v1_deprecation_warning(py, "GroupSession")?;
        }
        let gp = GroupSessionPickle::from_encrypted(&vodozemac_inner, &key)
            .map_err(|e| OlmGroupSessionError::new_err(format!("Deserialization failed: {e}")))?;
        Ok(Self {
            inner: VzGroupSession::from_pickle(gp),
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "GroupSession(session_id=\"{}\", message_index={})",
            self.inner.session_id(),
            self.inner.message_index()
        )
    }
}

/// Test-only: re-encrypt a GroupSession using the legacy v1 KDF so Python
/// tests can exercise the v1 decode path without committing binary fixtures.
/// NOT a stable API. Underscored name signals internal-only. Will be
/// removed in 0.4.0 along with the v1 decode path itself.
#[pyfunction]
pub(crate) fn _v1_encrypt_group_session_for_testing(
    session: PyRef<'_, GroupSession>,
    passphrase: &[u8],
) -> String {
    let key = passphrase_to_key_v1(passphrase);
    session.inner.pickle().encrypt(&key)
}

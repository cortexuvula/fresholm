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

#[pyclass]
pub struct InboundGroupSession {
    inner: VzInboundGroupSession,
}

#[pymethods]
impl InboundGroupSession {
    /// Create a new InboundGroupSession from a base64-encoded session key.
    #[new]
    fn new(session_key: &str) -> PyResult<Self> {
        let key = SessionKey::from_base64(session_key)
            .map_err(|e| OlmGroupSessionError::new_err(format!("Invalid session key: {e}")))?;
        Ok(Self {
            inner: VzInboundGroupSession::new(&key, SessionConfig::version_2()),
        })
    }

    /// Decrypt a base64-encoded MegolmMessage.
    /// Returns a tuple of (plaintext_bytes, message_index).
    fn decrypt(&mut self, ciphertext: &str) -> PyResult<(Vec<u8>, u32)> {
        let message = MegolmMessage::from_base64(ciphertext)
            .map_err(|e| OlmGroupSessionError::new_err(format!("Invalid message: {e}")))?;
        let decrypted = self.inner.decrypt(&message)
            .map_err(|e| OlmGroupSessionError::new_err(format!("Decryption failed: {e}")))?;
        Ok((decrypted.plaintext, decrypted.message_index))
    }

    /// Return the globally unique session ID (base64-encoded).
    fn session_id(&self) -> String {
        self.inner.session_id()
    }

    /// Return the first known message index.
    fn first_known_index(&self) -> u32 {
        self.inner.first_known_index()
    }

    /// Export the session key at the given message index.
    /// Returns a base64-encoded exported session key, or None if the index is
    /// before the first known index.
    fn export_at(&mut self, index: u32) -> PyResult<Option<String>> {
        Ok(self.inner.export_at(index).map(|key| key.to_base64()))
    }

    /// Export the session key at the first known index.
    /// Returns a base64-encoded exported session key.
    fn export_at_first_known_index(&self) -> String {
        self.inner.export_at_first_known_index().to_base64()
    }

    /// Import an InboundGroupSession from a base64-encoded exported session key.
    #[staticmethod]
    fn import_session(exported_key: &str) -> PyResult<Self> {
        let key = ExportedSessionKey::from_base64(exported_key)
            .map_err(|e| OlmGroupSessionError::new_err(format!("Invalid exported key: {e}")))?;
        Ok(Self {
            inner: VzInboundGroupSession::import(&key, SessionConfig::version_2()),
        })
    }

    /// Serialize the inbound group session via Argon2id v2 envelope.
    fn to_encrypted_string(&self, passphrase: &[u8]) -> PyResult<String> {
        let params = Argon2Params::default_v2();
        let salt = fresh_salt();
        let key = derive_v2(passphrase, &params, &salt)
            .map_err(OlmGroupSessionError::new_err)?;
        let inner = self.inner.pickle().encrypt(&key);
        Ok(encode_v2_envelope(&params, &salt, &inner))
    }

    /// Restore an InboundGroupSession, dispatching v2/v1 by envelope.
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
            crate::account::emit_v1_deprecation_warning(py, "InboundGroupSession")?;
        }
        let igp = InboundGroupSessionPickle::from_encrypted(&vodozemac_inner, &key)
            .map_err(|e| OlmGroupSessionError::new_err(format!("Deserialization failed: {e}")))?;
        Ok(Self {
            inner: VzInboundGroupSession::from_pickle(igp),
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "InboundGroupSession(session_id=\"{}\", first_known_index={})",
            self.inner.session_id(),
            self.inner.first_known_index()
        )
    }
}

/// Test-only: re-encrypt an InboundGroupSession using the legacy v1 KDF so
/// Python tests can exercise the v1 decode path without committing binary
/// fixtures. NOT a stable API. Underscored name signals internal-only. Will
/// be removed in 0.4.0 along with the v1 decode path itself.
#[pyfunction]
pub(crate) fn _v1_encrypt_inbound_group_session_for_testing(
    session: PyRef<'_, InboundGroupSession>,
    passphrase: &[u8],
) -> String {
    let key = passphrase_to_key_v1(passphrase);
    session.inner.pickle().encrypt(&key)
}

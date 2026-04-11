use pyo3::prelude::*;
use vodozemac::megolm::{
    ExportedSessionKey, InboundGroupSession as VzInboundGroupSession,
    InboundGroupSessionPickle, MegolmMessage, SessionConfig, SessionKey,
};

use crate::account::passphrase_to_key;
use crate::errors::OlmGroupSessionError;

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

    /// Serialize the inbound group session with the given passphrase bytes.
    fn to_encrypted_string(&self, passphrase: &[u8]) -> PyResult<String> {
        let key = passphrase_to_key(passphrase);
        Ok(self.inner.pickle().encrypt(&key))
    }

    /// Restore an InboundGroupSession from an encrypted string and passphrase bytes.
    #[staticmethod]
    fn from_encrypted_string(encrypted: &str, passphrase: &[u8]) -> PyResult<Self> {
        let key = passphrase_to_key(passphrase);
        let igp = InboundGroupSessionPickle::from_encrypted(encrypted, &key)
            .map_err(|e| OlmGroupSessionError::new_err(format!("Deserialization failed: {e}")))?;
        let session = VzInboundGroupSession::from_pickle(igp);
        Ok(Self { inner: session })
    }

    fn __repr__(&self) -> String {
        format!(
            "InboundGroupSession(session_id=\"{}\", first_known_index={})",
            self.inner.session_id(),
            self.inner.first_known_index()
        )
    }
}

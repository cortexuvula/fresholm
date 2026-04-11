use pyo3::prelude::*;
use vodozemac::megolm::{
    GroupSession as VzGroupSession, GroupSessionPickle, SessionConfig,
};

use crate::account::passphrase_to_key;
use crate::errors::OlmGroupSessionError;

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

    /// Serialize the group session with the given passphrase bytes. Returns an encrypted string.
    fn to_encrypted_string(&self, passphrase: &[u8]) -> PyResult<String> {
        let key = passphrase_to_key(passphrase);
        Ok(self.inner.pickle().encrypt(&key))
    }

    /// Restore a GroupSession from an encrypted string and passphrase bytes.
    #[staticmethod]
    fn from_encrypted_string(encrypted: &str, passphrase: &[u8]) -> PyResult<Self> {
        let key = passphrase_to_key(passphrase);
        let gp = GroupSessionPickle::from_encrypted(encrypted, &key)
            .map_err(|e| OlmGroupSessionError::new_err(format!("Deserialization failed: {e}")))?;
        let session = VzGroupSession::from_pickle(gp);
        Ok(Self { inner: session })
    }

    fn __repr__(&self) -> String {
        format!(
            "GroupSession(session_id=\"{}\", message_index={})",
            self.inner.session_id(),
            self.inner.message_index()
        )
    }
}

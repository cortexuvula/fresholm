use pyo3::prelude::*;
use vodozemac::olm::{OlmMessage, Session as VzSession, SessionPickle};

use crate::account::passphrase_to_key;
use crate::errors::OlmSessionError;

/// An encrypted Olm message returned by `Session.encrypt()`.
#[pyclass]
pub struct EncryptedMessage {
    /// 0 = PreKey, 1 = Normal
    msg_type: u32,
    /// Raw ciphertext bytes (wire format)
    ciphertext_bytes: Vec<u8>,
}

#[pymethods]
impl EncryptedMessage {
    /// The message type: 0 for PreKey, 1 for Normal.
    #[getter]
    fn message_type(&self) -> u32 {
        self.msg_type
    }

    /// The raw ciphertext bytes.
    #[getter]
    fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext_bytes.clone()
    }

    fn __repr__(&self) -> String {
        let type_name = match self.msg_type {
            0 => "PreKey",
            1 => "Normal",
            _ => "Unknown",
        };
        format!(
            "EncryptedMessage(type={}, ciphertext_len={})",
            type_name,
            self.ciphertext_bytes.len()
        )
    }
}

#[pyclass]
pub struct Session {
    pub(crate) inner: VzSession,
}

impl Session {
    /// Rust-only constructor used by Account to wrap a vodozemac Session.
    pub fn from_vz(inner: VzSession) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl Session {
    /// Encrypt the given plaintext bytes and return an EncryptedMessage.
    fn encrypt(&mut self, plaintext: &[u8]) -> EncryptedMessage {
        let olm_message = self.inner.encrypt(plaintext);
        let (msg_type, ciphertext_bytes) = olm_message.to_parts();
        EncryptedMessage {
            msg_type: msg_type as u32,
            ciphertext_bytes,
        }
    }

    /// Decrypt a message given its type (0=PreKey, 1=Normal) and ciphertext bytes.
    fn decrypt(&mut self, message_type: u32, ciphertext: &[u8]) -> PyResult<Vec<u8>> {
        let olm_message = OlmMessage::from_parts(message_type as usize, ciphertext)
            .map_err(|e| OlmSessionError::new_err(format!("Invalid message: {e}")))?;
        self.inner
            .decrypt(&olm_message)
            .map_err(|e| OlmSessionError::new_err(format!("Decryption failed: {e}")))
    }

    /// Return the globally unique session ID (base64-encoded).
    fn session_id(&self) -> String {
        self.inner.session_id()
    }

    /// Whether we have received and decrypted at least one message from the other side.
    fn has_received_message(&self) -> bool {
        self.inner.has_received_message()
    }

    /// Serialize the session with the given passphrase bytes. Returns an encrypted string.
    fn to_encrypted_string(&self, passphrase: &[u8]) -> PyResult<String> {
        let key = passphrase_to_key(passphrase);
        Ok(self.inner.pickle().encrypt(&key))
    }

    /// Restore a Session from an encrypted string and passphrase bytes.
    #[staticmethod]
    fn from_encrypted_string(encrypted: &str, passphrase: &[u8]) -> PyResult<Self> {
        let key = passphrase_to_key(passphrase);
        let sp = SessionPickle::from_encrypted(encrypted, &key)
            .map_err(|e| OlmSessionError::new_err(format!("Deserialization failed: {e}")))?;
        let session = VzSession::from_pickle(sp);
        Ok(Self { inner: session })
    }

    fn __repr__(&self) -> String {
        format!("Session(session_id=\"{}\")", self.inner.session_id())
    }
}

use pyo3::prelude::*;
use vodozemac::olm::{OlmMessage, PreKeyMessage, Session as VzSession, SessionPickle};

use crate::errors::OlmSessionError;
use crate::pickle_format::{
    decode_envelope, derive_v2, encode_v2_envelope, fresh_salt, passphrase_to_key_v1,
    Argon2Params, EnvelopeKind,
};

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

    /// Serialize the session via Argon2id v2 envelope.
    fn to_encrypted_string(&self, passphrase: &[u8]) -> PyResult<String> {
        let params = Argon2Params::default_v2();
        let salt = fresh_salt();
        let key = derive_v2(passphrase, &params, &salt)
            .map_err(OlmSessionError::new_err)?;
        let inner = self.inner.pickle().encrypt(&key);
        Ok(encode_v2_envelope(&params, &salt, &inner))
    }

    /// Restore a Session, dispatching v2/v1 by envelope.
    ///
    /// `py` is required because the legacy path calls
    /// `emit_v1_deprecation_warning`; pyo3 0.28 injects this token
    /// automatically when invoked from Python.
    #[staticmethod]
    fn from_encrypted_string(py: Python<'_>, encrypted: &str, passphrase: &[u8]) -> PyResult<Self> {
        let (key, vodozemac_inner, was_legacy) = match decode_envelope(encrypted)
            .map_err(OlmSessionError::new_err)?
        {
            EnvelopeKind::V2 {
                params,
                salt,
                inner,
            } => {
                let k = derive_v2(passphrase, &params, &salt)
                    .map_err(OlmSessionError::new_err)?;
                (k, inner.to_string(), false)
            }
            EnvelopeKind::V1 { inner } => {
                (passphrase_to_key_v1(passphrase), inner.to_string(), true)
            }
        };
        if was_legacy {
            crate::account::emit_v1_deprecation_warning(py, "Session")?;
        }
        let sp = SessionPickle::from_encrypted(&vodozemac_inner, &key)
            .map_err(|e| OlmSessionError::new_err(format!("Deserialization failed: {e}")))?;
        Ok(Self {
            inner: VzSession::from_pickle(sp),
        })
    }

    /// Check whether a pre-key message was created using the same session keys
    /// as this session, i.e. whether the message "matches" this session.
    fn matches_prekey(&self, pre_key_message_bytes: &[u8]) -> bool {
        let Ok(pre_key_msg) = PreKeyMessage::from_bytes(pre_key_message_bytes) else {
            return false;
        };
        let session_keys = self.inner.session_keys();
        let msg_keys = pre_key_msg.session_keys();
        session_keys.session_id() == msg_keys.session_id()
    }

    fn __repr__(&self) -> String {
        format!("Session(session_id=\"{}\")", self.inner.session_id())
    }
}

/// Test-only: re-encrypt a Session using the legacy v1 KDF so Python tests
/// can exercise the v1 decode path without committing binary fixtures.
/// NOT a stable API. Underscored name signals internal-only. Will be
/// removed in 0.4.0 along with the v1 decode path itself.
#[pyfunction]
pub(crate) fn _v1_encrypt_session_for_testing(
    session: PyRef<'_, Session>,
    passphrase: &[u8],
) -> String {
    let key = passphrase_to_key_v1(passphrase);
    session.inner.pickle().encrypt(&key)
}

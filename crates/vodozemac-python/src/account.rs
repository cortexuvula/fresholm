use pyo3::prelude::*;
use pyo3::types::PyDict;
use vodozemac::olm::{
    Account as VzAccount, AccountPickle, PreKeyMessage, SessionConfig,
};
use vodozemac::Curve25519PublicKey;

use crate::errors::OlmAccountError;
use crate::session::Session;

pub(crate) fn passphrase_to_key(passphrase: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    let len = passphrase.len().min(32);
    key[..len].copy_from_slice(&passphrase[..len]);
    key
}

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
        let session =
            self.inner
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

    /// Serialize the account with the given passphrase bytes. Returns an encrypted string.
    fn to_encrypted_string(&self, passphrase: &[u8]) -> String {
        let key = passphrase_to_key(passphrase);
        self.inner.pickle().encrypt(&key)
    }

    /// Restore an Account from an encrypted string and passphrase bytes.
    #[staticmethod]
    fn from_encrypted_string(encrypted: &str, passphrase: &[u8]) -> PyResult<Self> {
        let key = passphrase_to_key(passphrase);
        let ap = AccountPickle::from_encrypted(encrypted, &key)
            .map_err(|e| OlmAccountError::new_err(format!("Deserialization failed: {e}")))?;
        let account = VzAccount::from_pickle(ap);
        Ok(Self { inner: account })
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

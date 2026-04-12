use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use pyo3::prelude::*;
use vodozemac::pk_encryption::{
    Message as VzPkMessage, PkDecryption as VzPkDecryption, PkEncryption as VzPkEncryption,
};
use vodozemac::{Curve25519PublicKey, Curve25519SecretKey};

use crate::errors::OlmError;

#[pyclass]
pub struct PkMessage {
    #[pyo3(get)]
    pub ciphertext: String,
    #[pyo3(get)]
    pub mac: String,
    #[pyo3(get)]
    pub ephemeral_key: String,
}

#[pyclass]
pub struct PkEncryption {
    inner: VzPkEncryption,
}

#[pymethods]
impl PkEncryption {
    #[new]
    fn new(recipient_key: &str) -> PyResult<Self> {
        let pubkey = Curve25519PublicKey::from_base64(recipient_key)
            .map_err(|e| OlmError::new_err(format!("Invalid recipient key: {e}")))?;
        Ok(Self {
            inner: VzPkEncryption::from_key(pubkey),
        })
    }

    fn encrypt(&self, plaintext: &[u8]) -> PkMessage {
        let msg = self.inner.encrypt(plaintext);
        PkMessage {
            ciphertext: STANDARD.encode(&msg.ciphertext),
            mac: STANDARD.encode(&msg.mac),
            ephemeral_key: msg.ephemeral_key.to_base64(),
        }
    }
}

#[pyclass]
pub struct PkDecryption {
    inner: VzPkDecryption,
}

#[pymethods]
impl PkDecryption {
    #[new]
    #[pyo3(signature = (secret_key=None))]
    fn new(secret_key: Option<&str>) -> PyResult<Self> {
        let inner = match secret_key {
            Some(sk) => {
                let bytes = STANDARD
                    .decode(sk)
                    .map_err(|e| OlmError::new_err(format!("Invalid base64 secret key: {e}")))?;
                let byte_array: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| OlmError::new_err("Secret key must be 32 bytes"))?;
                let key = Curve25519SecretKey::from_slice(&byte_array);
                VzPkDecryption::from_key(key)
            }
            None => VzPkDecryption::new(),
        };
        Ok(Self { inner })
    }

    #[getter]
    fn public_key(&self) -> String {
        self.inner.public_key().to_base64()
    }

    fn decrypt(&self, ciphertext: &str, mac: &str, ephemeral_key: &str) -> PyResult<Vec<u8>> {
        let msg = VzPkMessage::from_base64(ciphertext, mac, ephemeral_key)
            .map_err(|e| OlmError::new_err(format!("Invalid PK message: {e}")))?;
        self.inner
            .decrypt(&msg)
            .map_err(|e| OlmError::new_err(format!("Decryption failed: {e}")))
    }
}

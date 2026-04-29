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

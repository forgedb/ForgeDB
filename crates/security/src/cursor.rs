//! HMAC-signed opaque cursors for secure pagination.
//!
//! Provides the [`CursorSigner`] which wraps internal database IDs (like B-Tree keys)
//! in a signed, base64-encoded envelope. This prevents clients from guessing
//! or tampering with pagination offsets, as any modification to the cursor
//! results in an invalid signature.

use aws_lc_rs::hmac;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use forge_types::{ForgeError, Result};

/// Signs and verifies pagination cursors using HMAC-SHA256.
pub struct CursorSigner {
    key: hmac::Key,
}

impl CursorSigner {
    /// Create a new signer from a raw 32-byte key.
    pub fn new(key_bytes: &[u8; 32]) -> Self {
        Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, key_bytes),
        }
    }

    /// Wraps a raw document ID into an opaque, signed string.
    ///
    /// The output format is: `URL_SAFE_BASE64(HMAC_SIG || RAW_ID)`
    pub fn encode(&self, id: &str) -> String {
        let sig = hmac::sign(&self.key, id.as_bytes());
        let sig_bytes = sig.as_ref();

        let mut combined = Vec::with_capacity(sig_bytes.len() + id.len());
        combined.extend_from_slice(sig_bytes);
        combined.extend_from_slice(id.as_bytes());

        URL_SAFE_NO_PAD.encode(combined)
    }

    /// Verifies the signature and extracts the raw document ID.
    ///
    /// # Errors
    ///
    /// Returns [`ForgeError::Security`] if the signature is invalid or
    /// the base64 decoding fails.
    pub fn decode(&self, opaque: &str) -> Result<String> {
        let decoded = URL_SAFE_NO_PAD
            .decode(opaque)
            .map_err(|_| ForgeError::Security("invalid cursor encoding".into()))?;

        // HMAC-SHA256 signature is exactly 32 bytes
        if decoded.len() < 32 {
            return Err(ForgeError::Security("malformed cursor payload".into()));
        }

        let (sig_bytes, id_bytes) = decoded.split_at(32);

        // Verify the signature. constant-time comparison is handled by aws-lc-rs.
        if hmac::verify(&self.key, id_bytes, sig_bytes).is_err() {
            return Err(ForgeError::Security("cursor signature mismatch".into()));
        }

        String::from_utf8(id_bytes.to_vec())
            .map_err(|_| ForgeError::Security("invalid cursor utf8".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_valid_id() {
        let key = [0u8; 32];
        let signer = CursorSigner::new(&key);
        let original = "item_123";

        let opaque = signer.encode(original);
        let decoded = signer.decode(&opaque).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn rejects_tampered_cursor() {
        let key = [1u8; 32];
        let signer = CursorSigner::new(&key);
        let opaque = signer.encode("valid_id");

        // Slightly modify the base64 string
        let mut tampered = opaque.into_bytes();
        if tampered[0] == b'a' {
            tampered[0] = b'b';
        } else {
            tampered[0] = b'a';
        }
        let tampered_str = String::from_utf8(tampered).unwrap();

        assert!(signer.decode(&tampered_str).is_err());
    }

    #[test]
    fn rejects_malicious_id_swap() {
        let key = [2u8; 32];
        let signer = CursorSigner::new(&key);
        let opaque = signer.encode("id_1");

        // Try to decode it with a different key (simulating key rotation or attacker guess)
        let evil_signer = CursorSigner::new(&[3u8; 32]);
        assert!(evil_signer.decode(&opaque).is_err());
    }
}

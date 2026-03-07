//! MessagePack serialization helpers.
//!
//! Thin wrappers around `rmp-serde` that map errors into [`ForgeError::Serialization`].
//! Keeps the rest of the codebase from scattering `rmp_serde::` calls everywhere.

use serde::{Serialize, de::DeserializeOwned};

use forge_types::{ForgeError, Result};

/// Serialize a value to MessagePack bytes.
///
/// # Errors
///
/// Returns [`ForgeError::Serialization`] if encoding fails.
pub fn serialize_doc<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    rmp_serde::to_vec(value).map_err(|e| ForgeError::Serialization(format!("encode failed: {e}")))
}

/// Deserialize MessagePack bytes back into a typed value.
///
/// # Errors
///
/// Returns [`ForgeError::Serialization`] if decoding fails or the bytes
/// don't match the expected schema.
pub fn deserialize_doc<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    rmp_serde::from_slice(bytes)
        .map_err(|e| ForgeError::Serialization(format!("decode failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct TestDoc {
        name: String,
        value: i64,
    }

    #[test]
    fn round_trip() {
        let doc = TestDoc {
            name: "test".into(),
            value: 42,
        };
        let bytes = serialize_doc(&doc).unwrap();
        let restored: TestDoc = deserialize_doc(&bytes).unwrap();
        assert_eq!(doc, restored);
    }

    #[test]
    fn rejects_garbage_bytes() {
        let result: std::result::Result<TestDoc, _> = deserialize_doc(&[0xFF, 0x00, 0xDE]);
        assert!(result.is_err());
    }
}

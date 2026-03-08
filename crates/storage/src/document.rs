//! MessagePack serialization helpers for ForgeDB documents.
//!
//! Two paths live here on purpose — compact encoding for internal storage (saves bytes
//! on disk) and named encoding for the public API (self-describing so client SDKs
//! don't need to know field ordering). We funnel everything through `rmp-serde` and
//! translate errors into [`ForgeError::Serialization`] so callers never see raw codec panics.

use serde::{Serialize, de::DeserializeOwned};

use forge_types::{ForgeError, Result};

/// Serialize a value using compact (positional) MessagePack.
///
/// Fields are stored by index, not by name — significantly smaller on disk but
/// the output isn't self-describing. Use this for internal storage where both
/// the writer and reader share the same Rust struct definition.
///
/// # Errors
///
/// Returns [`ForgeError::Serialization`] if encoding fails.
pub fn serialize_doc<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    rmp_serde::to_vec(value).map_err(|e| ForgeError::Serialization(format!("encode failed: {e}")))
}

/// Serialize a value using named-field MessagePack for external consumption.
///
/// Every field gets its name written alongside its value, making the payload
/// self-describing — client SDKs in TS/Python/Go can decode this without ever
/// seeing our Rust structs. Slightly larger than compact, but that's the trade-off
/// for SDK-friendliness. The PRD explicitly mandates this for all public API responses.
///
/// # Errors
///
/// Returns [`ForgeError::Serialization`] if encoding fails.
pub fn serialize_doc_named<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(value)
        .map_err(|e| ForgeError::Serialization(format!("named encode failed: {e}")))
}

/// Deserialize MessagePack bytes back into a typed value.
///
/// Works with both compact and named encodings — `rmp_serde` handles both
/// transparently, which is honestly one of its nicer qualities.
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
    fn compact_round_trip() {
        let doc = TestDoc {
            name: "test".into(),
            value: 42,
        };
        let bytes = serialize_doc(&doc).unwrap();
        let restored: TestDoc = deserialize_doc(&bytes).unwrap();
        assert_eq!(doc, restored);
    }

    #[test]
    fn named_round_trip() {
        let doc = TestDoc {
            name: "hello".into(),
            value: 99,
        };
        let bytes = serialize_doc_named(&doc).unwrap();
        let restored: TestDoc = deserialize_doc(&bytes).unwrap();
        assert_eq!(doc, restored);
    }

    #[test]
    fn named_encoding_contains_field_names() {
        // The whole point of named encoding is self-describing payloads.
        // Field names should appear as raw strings in the binary output.
        let doc = TestDoc {
            name: "sdk-test".into(),
            value: 7,
        };
        let bytes = serialize_doc_named(&doc).unwrap();
        let as_str = String::from_utf8_lossy(&bytes);
        assert!(
            as_str.contains("name"),
            "named output should embed field name 'name'"
        );
        assert!(
            as_str.contains("value"),
            "named output should embed field name 'value'"
        );
    }

    #[test]
    fn compact_is_smaller_than_named() {
        let doc = TestDoc {
            name: "size-compare".into(),
            value: 12345,
        };
        let compact = serialize_doc(&doc).unwrap();
        let named = serialize_doc_named(&doc).unwrap();
        assert!(
            compact.len() < named.len(),
            "compact ({} bytes) should be smaller than named ({} bytes)",
            compact.len(),
            named.len(),
        );
    }

    #[test]
    fn rejects_garbage_bytes() {
        let result: std::result::Result<TestDoc, _> = deserialize_doc(&[0xFF, 0x00, 0xDE]);
        assert!(result.is_err());
    }
}

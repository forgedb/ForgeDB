//! Internal binary wire format for ForgeDB nodes.
//!
//! While external HTTP clients dictate JSON or MessagePack to keep things
//! flexible, internal Rust-to-Rust communication (like Raft replication and
//! cluster administration) uses `postcard`. It's a non-self-describing,
//! #![no_std] compatible binary format that is aggressively tiny and fast —
//! perfect for saturating memory bandwidth on high-throughput NVMe drives.

use serde::{Deserialize, Serialize};

use forge_types::{ForgeError, Result};

/// Encodes a typed Rust struct into the internal Postcard wire format.
///
/// # Errors
/// Returns [`ForgeError::Serialization`] if the struct cannot be serialized
/// (e.g. contains unsupported types, deeply nested recursive structures breaking limits).
pub fn encode_wire<T: Serialize>(payload: &T) -> Result<Vec<u8>> {
    postcard::to_allocvec(payload).map_err(|e| {
        tracing::error!("postcard wire serialization failed: {e}");
        ForgeError::Serialization(format!("postcard encode: {e}"))
    })
}

/// Decodes an internal Postcard wire payload back into a typed Rust struct.
///
/// # Errors
/// Returns [`ForgeError::Serialization`] if the byte slice is malformed,
/// short, or represents a structurally different type than `T`.
pub fn decode_wire<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T> {
    postcard::from_bytes(bytes).map_err(|e| {
        tracing::warn!("postcard wire deserialization failed: {e}");
        ForgeError::Serialization(format!("postcard decode: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct RaftAppendEntries {
        term: u64,
        leader_id: String,
        entries: Vec<Vec<u8>>,
    }

    #[test]
    fn postcard_roundtrip() {
        let msg = RaftAppendEntries {
            term: 42,
            leader_id: "node-1".into(),
            entries: vec![b"log1".to_vec(), b"log2".to_vec()],
        };

        let encoded = encode_wire(&msg).expect("serialization should succeed");
        // Postcard is extremely compact compared to JSON/MsgPack.
        assert!(encoded.len() < 50);

        let decoded: RaftAppendEntries =
            decode_wire(&encoded).expect("deserialization should succeed");
        assert_eq!(msg, decoded);
    }
}

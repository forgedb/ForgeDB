//! Persistence layer for ForgeDB.
//!
//! Built on redbx, which handles transparent page-level AES-256-GCM encryption.
//! Callers interact with documents through [`StorageEngine`] — no raw crypto needed.

pub mod document;
pub mod engine;

pub use document::{deserialize_doc, serialize_doc};
pub use engine::StorageEngine;

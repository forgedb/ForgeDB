//! Persistence layer for ForgeDB.
//!
//! Built on redbx, which handles transparent page-level AES-256-GCM encryption.
//! Callers interact with documents through [`StorageEngine`] — no raw crypto needed.

pub mod audit;
pub mod document;
pub mod engine;

pub use audit::AuditLog;
pub use document::{deserialize_doc, serialize_doc};
pub use engine::StorageEngine;

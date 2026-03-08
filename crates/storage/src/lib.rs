//! Persistence layer for ForgeDB.
//!
//! Built on redbx, which handles transparent page-level AES-256-GCM encryption.
//! Callers interact with documents through [`StorageEngine`] — no raw crypto needed.
//!
//! For high-throughput write paths, use the [`writer`] module's [`WriteSender`]
//! which coalesces concurrent inserts into batched transactions automatically.

pub mod audit;
pub mod document;
pub mod engine;
pub mod extract;
pub mod index;
pub mod writer;

pub use audit::AuditLog;
pub use document::{deserialize_doc, serialize_doc};
pub use engine::{StorageConfig, StorageEngine};
pub use index::{IndexRegistry, format_index_key, index_table_name};
pub use writer::{WriteSender, spawn_writer};

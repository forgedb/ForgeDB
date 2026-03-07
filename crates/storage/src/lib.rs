//! Persistence layer backed by redbx.
//!
//! Transparent page-level AES-256-GCM encryption is handled by redbx itself —
//! callers just read and write documents. Implementation in `feat/storage`.

pub mod audit;

pub use audit::AuditLog;

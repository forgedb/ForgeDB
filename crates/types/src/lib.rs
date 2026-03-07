//! Core types and error definitions shared across all ForgeDB crates.
//!
//! This is the foundation layer — deliberately kept lean (no I/O, no crypto,
//! no async runtime) so it can be depended on by everything without pulling
//! in half of crates.io.

pub mod audit;
pub mod config;
pub mod error;

pub use audit::{AuditEntry, Outcome};
pub use config::ForgeConfig;
pub use error::ForgeError;

/// Shorthand for `std::result::Result<T, ForgeError>`.
pub type Result<T> = std::result::Result<T, ForgeError>;

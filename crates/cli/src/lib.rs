//! CLI command implementations for ForgeDB.
//!
//! The binary in `crates/bin` dispatches to functions here.

pub mod init;

pub use init::run_init;

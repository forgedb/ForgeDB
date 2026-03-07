//! Mandatory-TLS network layer for ForgeDB.
//!
//! No plaintext connections. [`TlsListener`] wraps a tokio TCP listener with
//! a rustls acceptor so every connection is TLS 1.3 from the start.

pub mod listener;
pub mod wire;

pub use listener::TlsListener;
pub use wire::{decode_wire, encode_wire};

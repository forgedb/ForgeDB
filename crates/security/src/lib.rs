//! Cryptographic primitives and TLS configuration for ForgeDB.
//!
//! Everything that touches keys, certs, or encrypted channels lives here.
//! Other crates call into `forge-security` — they never handle raw crypto
//! material directly.

pub mod certgen;
pub mod tls;

pub use certgen::generate_self_signed_cert;
pub use tls::build_server_tls_config;

pub mod cursor;
pub use cursor::CursorSigner;

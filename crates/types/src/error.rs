//! Unified error type for ForgeDB.
//!
//! Every crate routes failures through [`ForgeError`] so callers get a single
//! enum to match on. We use `thiserror` for the derive — it keeps things
//! idiomatic and saves us from hand-rolling `Display`.
//!
//! `#[from]` is reserved for the two highest-traffic conversions (redbx, I/O).
//! Everything else gets a `String` payload because the upstream error types are
//! different enough that wrapping them all generically isn't worth the hassle.

use thiserror::Error;

/// Central error enum. If you're adding a new crate to the workspace, funnel
/// your failures through a variant here rather than inventing a local type.
///
/// # Examples
///
/// ```rust
/// use forge_types::{ForgeError, Result};
///
/// fn might_fail() -> Result<()> {
///     Err(ForgeError::Config("bind address is nonsense".into()))
/// }
/// ```
#[derive(Debug, Error)]
pub enum ForgeError {
    /// redbx storage failure — could be corruption, a transaction conflict,
    /// wrong password, etc.
    #[error("storage error: {0}")]
    Storage(#[from] redbx::Error),

    /// MessagePack encode/decode failure.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// TLS configuration or handshake problem.
    #[error("TLS error: {0}")]
    Tls(String),

    /// Filesystem I/O — missing dirs, permission denied, the usual suspects.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Invalid or incomplete configuration (missing paths, bad addresses, etc.).
    #[error("configuration error: {0}")]
    Config(String),

    /// Self-signed certificate generation failure.
    #[error("certificate generation error: {0}")]
    CertGen(String),

    /// PASETO token validation gone sideways — expired, tampered, unknown key,
    /// you name it. We don't differentiate on purpose; attackers shouldn't get
    /// a roadmap from our error messages.
    #[error("auth error: {0}")]
    Auth(String),

    /// Cedar policy evaluation or parse failure. Deny-by-default means this
    /// fires a lot when people forget to attach policies — and that's the point.
    #[error("policy error: {0}")]
    Policy(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_error_displays_message() {
        let err = ForgeError::Config("missing data_dir".into());
        assert!(format!("{err}").contains("missing data_dir"));
    }

    #[test]
    fn io_error_converts_via_from() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
        let forge_err: ForgeError = io_err.into();
        assert!(matches!(forge_err, ForgeError::Io(_)));
    }

    #[test]
    fn error_is_send_and_sync() {
        fn assert_bounds<T: Send + Sync>() {}
        assert_bounds::<ForgeError>();
    }

    #[test]
    fn all_variants_produce_nonempty_display() {
        let cases: Vec<ForgeError> = vec![
            ForgeError::Serialization("bad bytes".into()),
            ForgeError::Tls("cert expired".into()),
            ForgeError::Config("nope".into()),
            ForgeError::CertGen("keygen failed".into()),
            ForgeError::Auth("token tampered".into()),
            ForgeError::Policy("deny by default".into()),
            ForgeError::Io(std::io::Error::other("disk on fire")),
        ];
        for err in &cases {
            assert!(!format!("{err}").is_empty());
        }
    }
}

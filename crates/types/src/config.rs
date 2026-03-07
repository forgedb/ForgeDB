//! ForgeDB node configuration.
//!
//! Maps 1:1 to the `forgedb.toml` file on disk. `forgedb init` writes it,
//! `forgedb serve` reads it. The database password is deliberately excluded —
//! it's prompted at runtime or read from `FORGEDB_PASSWORD` env var.
//! We don't persist secrets in config files. Ever.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::ForgeError;

/// Localhost on port 5826 (hex for "FB"). Chosen to avoid the Postgres 5432 clash.
const DEFAULT_BIND_ADDR: &str = "127.0.0.1:5826";

/// Runtime configuration for a ForgeDB instance.
///
/// # Examples
///
/// ```rust
/// use forge_types::ForgeConfig;
/// use std::path::PathBuf;
///
/// let config = ForgeConfig::default_with_data_dir(PathBuf::from("./forgedb_data"));
/// assert_eq!(config.bind_address.port(), 5826);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForgeConfig {
    /// Root directory for all persisted data (redbx db, certs, keys).
    pub data_dir: PathBuf,

    /// Socket the TLS listener binds to.
    pub bind_address: SocketAddr,

    /// Path to PEM-encoded TLS certificate chain.
    pub tls_cert_path: PathBuf,

    /// Path to PEM-encoded TLS private key.
    pub tls_key_path: PathBuf,
}

impl ForgeConfig {
    /// Construct a config with sensible defaults for the given data directory.
    /// TLS paths default to `cert.pem` / `key.pem` inside `data_dir`.
    pub fn default_with_data_dir(data_dir: PathBuf) -> Self {
        let tls_cert_path = data_dir.join("cert.pem");
        let tls_key_path = data_dir.join("key.pem");

        Self {
            data_dir,
            bind_address: DEFAULT_BIND_ADDR
                .parse()
                .expect("hardcoded bind address is valid"),
            tls_cert_path,
            tls_key_path,
        }
    }

    /// Checks that every required path actually exists on disk. Called at
    /// startup so we fail loudly instead of halfway through a TLS handshake.
    ///
    /// # Errors
    ///
    /// Returns [`ForgeError::Config`] identifying the missing path.
    pub fn validate(&self) -> crate::Result<()> {
        Self::require_dir(&self.data_dir, "data directory")?;
        Self::require_file(&self.tls_cert_path, "TLS certificate")?;
        Self::require_file(&self.tls_key_path, "TLS private key")?;
        Ok(())
    }

    fn require_dir(path: &Path, label: &str) -> crate::Result<()> {
        if !path.is_dir() {
            return Err(ForgeError::Config(format!(
                "{label} not found at '{}'",
                path.display()
            )));
        }
        Ok(())
    }

    fn require_file(path: &Path, label: &str) -> crate::Result<()> {
        if !path.is_file() {
            return Err(ForgeError::Config(format!(
                "{label} not found at '{}'",
                path.display()
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn default_port_is_5826() {
        let cfg = ForgeConfig::default_with_data_dir(PathBuf::from("/tmp/fg"));
        assert_eq!(cfg.bind_address.port(), 5826);
    }

    #[test]
    fn default_binds_to_localhost() {
        let cfg = ForgeConfig::default_with_data_dir(PathBuf::from("/tmp/fg"));
        let expected: SocketAddr = "127.0.0.1:5826".parse().unwrap();
        assert_eq!(cfg.bind_address, expected);
    }

    #[test]
    fn cert_paths_derived_from_data_dir() {
        let dir = PathBuf::from("/var/lib/forgedb");
        let cfg = ForgeConfig::default_with_data_dir(dir.clone());
        assert_eq!(cfg.tls_cert_path, dir.join("cert.pem"));
        assert_eq!(cfg.tls_key_path, dir.join("key.pem"));
    }

    #[test]
    fn validate_rejects_missing_data_dir() {
        let cfg = ForgeConfig::default_with_data_dir(PathBuf::from("/no/such/path"));
        let msg = format!("{}", cfg.validate().unwrap_err());
        assert!(msg.contains("data directory"));
    }

    #[test]
    fn validate_rejects_missing_cert() {
        let tmp = std::env::temp_dir().join("forgedb_cfg_test");
        std::fs::create_dir_all(&tmp).unwrap();
        let cfg = ForgeConfig::default_with_data_dir(tmp.clone());
        let msg = format!("{}", cfg.validate().unwrap_err());
        assert!(msg.contains("TLS certificate"));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn config_roundtrips_through_toml() {
        let cfg = ForgeConfig::default_with_data_dir(PathBuf::from("./data"));
        let serialized = toml::to_string_pretty(&cfg).unwrap();
        let restored: ForgeConfig = toml::from_str(&serialized).unwrap();
        assert_eq!(cfg.bind_address, restored.bind_address);
        assert_eq!(cfg.data_dir, restored.data_dir);
    }
}

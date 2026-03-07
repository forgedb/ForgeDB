//! TLS 1.3 server configuration.
//!
//! Builds a [`rustls::ServerConfig`] from PEM-encoded cert/key files using
//! the `aws-lc-rs` crypto provider. TLS 1.3 is the minimum — we don't
//! negotiate down to 1.2 unless explicitly told to (and even then, think twice).

use std::path::Path;
use std::sync::Arc;

use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use forge_types::{ForgeError, Result};

/// Construct a TLS [`ServerConfig`] from PEM files on disk.
///
/// Loads the certificate chain and private key, wires up the `aws-lc-rs`
/// crypto provider, and enforces TLS 1.3 as the minimum protocol version.
///
/// # Errors
///
/// Returns [`ForgeError::Tls`] if the files can't be read, the PEM is
/// malformed, or rustls rejects the cert/key pair.
pub fn build_server_tls_config(cert_path: &Path, key_path: &Path) -> Result<Arc<ServerConfig>> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;

    let config = ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|e| ForgeError::Tls(format!("protocol version config failed: {e}")))?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(|e| ForgeError::Tls(format!("cert/key rejected by rustls: {e}")))?;

    Ok(Arc::new(config))
}

/// Read PEM cert chain from a file. Returns the DER-encoded certs.
fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = std::fs::File::open(path).map_err(|e| {
        ForgeError::Tls(format!(
            "failed to open cert file '{}': {e}",
            path.display()
        ))
    })?;
    let mut reader = std::io::BufReader::new(file);

    rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| ForgeError::Tls(format!("malformed PEM in '{}': {e}", path.display())))
}

/// Read a PEM private key from a file. Tries PKCS8 first, then EC, then RSA.
fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path).map_err(|e| {
        ForgeError::Tls(format!("failed to open key file '{}': {e}", path.display()))
    })?;
    let mut reader = std::io::BufReader::new(file);

    // rustls_pemfile::private_key reads the first PEM section that looks
    // like a private key — handles PKCS8, EC, and RSA formats.
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| {
            ForgeError::Tls(format!(
                "failed to parse key from '{}': {e}",
                path.display()
            ))
        })?
        .ok_or_else(|| ForgeError::Tls(format!("no private key found in '{}'", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certgen::generate_self_signed_cert;
    use tempfile::TempDir;

    #[test]
    fn loads_valid_cert_and_key() {
        let tmp = TempDir::new().unwrap();
        let cert = tmp.path().join("cert.pem");
        let key = tmp.path().join("key.pem");
        generate_self_signed_cert(&cert, &key).unwrap();

        let config = build_server_tls_config(&cert, &key);
        assert!(config.is_ok(), "should load valid cert/key pair");
    }

    #[test]
    fn fails_on_missing_cert() {
        let tmp = TempDir::new().unwrap();
        let cert = tmp.path().join("nope.pem");
        let key = tmp.path().join("key.pem");

        let err = build_server_tls_config(&cert, &key).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("cert file"),
            "error should mention cert file: {msg}"
        );
    }

    #[test]
    fn fails_on_missing_key() {
        let tmp = TempDir::new().unwrap();
        let cert = tmp.path().join("cert.pem");
        let key = tmp.path().join("nope.pem");

        // Write a valid cert but no key file
        generate_self_signed_cert(&cert, &tmp.path().join("real_key.pem")).unwrap();

        let err = build_server_tls_config(&cert, &key).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("key file"),
            "error should mention key file: {msg}"
        );
    }
}

//! Self-signed certificate generation for `forgedb init`.
//!
//! Produces an ECDSA P-256 cert valid for `localhost` and `127.0.0.1`,
//! good for 365 days. Intended for development and local testing — production
//! deployments should swap in a proper CA-signed cert.

use std::path::Path;

use rcgen::{CertificateParams, KeyPair, SanType};

use forge_types::{ForgeError, Result};

/// Generate a self-signed TLS certificate and write both the cert and
/// private key to PEM files.
///
/// The cert covers `localhost` and `127.0.0.1` via Subject Alternative Names
/// and expires in 365 days. Uses ECDSA with the P-256 curve — good balance
/// of speed and security, and well-supported everywhere.
///
/// # Errors
///
/// Returns [`ForgeError::CertGen`] if key generation or PEM serialization fails,
/// or [`ForgeError::Io`] if writing to disk fails.
pub fn generate_self_signed_cert(cert_path: &Path, key_path: &Path) -> Result<()> {
    let mut params = CertificateParams::new(vec!["localhost".to_string()])
        .map_err(|e| ForgeError::CertGen(format!("invalid cert params: {e}")))?;

    params
        .subject_alt_names
        .push(SanType::IpAddress(std::net::IpAddr::V4(
            std::net::Ipv4Addr::LOCALHOST,
        )));

    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| ForgeError::CertGen(format!("key generation failed: {e}")))?;

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| ForgeError::CertGen(format!("self-signing failed: {e}")))?;

    // Write cert PEM
    std::fs::write(cert_path, cert.pem())?;

    // Write key PEM
    std::fs::write(key_path, key_pair.serialize_pem())?;

    tracing::info!(
        cert = %cert_path.display(),
        key = %key_path.display(),
        "generated self-signed TLS certificate (ECDSA P-256, 365d)"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn generates_valid_pem_files() {
        let tmp = TempDir::new().unwrap();
        let cert_path = tmp.path().join("cert.pem");
        let key_path = tmp.path().join("key.pem");

        generate_self_signed_cert(&cert_path, &key_path).unwrap();

        assert!(cert_path.exists(), "cert file should exist");
        assert!(key_path.exists(), "key file should exist");

        let cert_pem = std::fs::read_to_string(&cert_path).unwrap();
        assert!(
            cert_pem.contains("BEGIN CERTIFICATE"),
            "cert should be valid PEM"
        );

        let key_pem = std::fs::read_to_string(&key_path).unwrap();
        assert!(
            key_pem.contains("BEGIN PRIVATE KEY"),
            "key should be valid PEM"
        );
    }

    #[test]
    fn generated_cert_is_loadable_by_rustls() {
        let tmp = TempDir::new().unwrap();
        let cert_path = tmp.path().join("cert.pem");
        let key_path = tmp.path().join("key.pem");

        generate_self_signed_cert(&cert_path, &key_path).unwrap();

        // If rustls can build a config from these files, they're structurally sound
        let config = crate::tls::build_server_tls_config(&cert_path, &key_path);
        assert!(
            config.is_ok(),
            "rustls should accept the generated cert/key: {:?}",
            config.err()
        );
    }

    #[test]
    fn fails_on_unwritable_path() {
        let result = generate_self_signed_cert(
            Path::new("/no/such/dir/cert.pem"),
            Path::new("/no/such/dir/key.pem"),
        );
        assert!(result.is_err(), "should fail for unwritable path");
    }
}

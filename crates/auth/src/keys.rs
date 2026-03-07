//! PASETO v4.public key management — generation, persistence, and loading.
//!
//! Ed25519 keypairs are the backbone of ForgeDB's identity system. We chose
//! v4.public (asymmetric) over v4.local (symmetric) deliberately: cluster
//! followers and future client SDKs only need the public key to verify tokens,
//! which keeps the private key surface area tiny. Only the leader/issuer
//! ever touches the secret key.
//!
//! Keys are saved as raw hex to keep things dead simple — no PEM ceremony,
//! no ASN.1 nightmares. Just 64 hex chars for the secret, 64 for the public.

use std::path::{Path, PathBuf};

use pasetors::keys::{AsymmetricKeyPair, AsymmetricPublicKey, AsymmetricSecretKey, Generate};
use pasetors::version4::V4;

use forge_types::{ForgeError, Result};

/// Default filenames — stashed next to the TLS certs in `data_dir`.
const SECRET_KEY_FILE: &str = "paseto_secret.key";
const PUBLIC_KEY_FILE: &str = "paseto_public.key";

/// Generates a fresh Ed25519 keypair suitable for PASETO v4.public tokens.
///
/// This wraps `pasetors`' RNG-backed generation, which uses the OS CSPRNG
/// under the hood. No custom entropy sources, no footguns.
///
/// # Errors
///
/// Returns [`ForgeError::Auth`] if the underlying crypto library fails to
/// produce a keypair — shouldn't happen unless something is deeply wrong
/// with the OS entropy pool.
pub fn generate_keypair() -> Result<AsymmetricKeyPair<V4>> {
    AsymmetricKeyPair::<V4>::generate()
        .map_err(|e| ForgeError::Auth(format!("keypair generation failed: {e}")))
}

/// Persists the keypair to disk as hex-encoded files.
///
/// Creates `paseto_secret.key` and `paseto_public.key` inside `dir`.
/// Overwrites any existing files — callers should guard against accidental
/// re-generation if that matters (the CLI `init` command does).
///
/// # Errors
///
/// Returns [`ForgeError::Io`] if the directory doesn't exist or we can't write.
pub fn save_keys(
    dir: &Path,
    secret: &AsymmetricSecretKey<V4>,
    public: &AsymmetricPublicKey<V4>,
) -> Result<()> {
    let sec_path = dir.join(SECRET_KEY_FILE);
    let pub_path = dir.join(PUBLIC_KEY_FILE);

    std::fs::write(&sec_path, hex::encode(secret.as_bytes()))?;
    std::fs::write(&pub_path, hex::encode(public.as_bytes()))?;

    Ok(())
}

/// Loads a previously saved keypair from `dir`.
///
/// Reads the hex-encoded files, decodes them, and reconstructs the pasetors
/// key types. Fails fast with a clear message if the files are missing, empty,
/// or contain invalid hex — better to blow up here than produce garbage tokens.
///
/// # Errors
///
/// Returns [`ForgeError::Auth`] for decode/construction failures,
/// or [`ForgeError::Io`] for missing files.
pub fn load_keys(dir: &Path) -> Result<(AsymmetricSecretKey<V4>, AsymmetricPublicKey<V4>)> {
    let sec_hex = std::fs::read_to_string(dir.join(SECRET_KEY_FILE))?;
    let pub_hex = std::fs::read_to_string(dir.join(PUBLIC_KEY_FILE))?;

    let sec_bytes = hex::decode(sec_hex.trim())
        .map_err(|e| ForgeError::Auth(format!("secret key hex decode: {e}")))?;
    let pub_bytes = hex::decode(pub_hex.trim())
        .map_err(|e| ForgeError::Auth(format!("public key hex decode: {e}")))?;

    let secret = AsymmetricSecretKey::<V4>::from(&sec_bytes)
        .map_err(|e| ForgeError::Auth(format!("secret key construction: {e}")))?;
    let public = AsymmetricPublicKey::<V4>::from(&pub_bytes)
        .map_err(|e| ForgeError::Auth(format!("public key construction: {e}")))?;

    Ok((secret, public))
}

/// Returns the expected path for the public key file — handy for config
/// validation without actually loading the key.
pub fn public_key_path(dir: &Path) -> PathBuf {
    dir.join(PUBLIC_KEY_FILE)
}

/// Same deal, but for the secret key.
pub fn secret_key_path(dir: &Path) -> PathBuf {
    dir.join(SECRET_KEY_FILE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_generates_successfully() {
        // If the OS entropy pool is broken we've got bigger problems,
        // but let's at least confirm it doesn't panic.
        let kp = generate_keypair().expect("keypair gen should work");
        assert!(!kp.secret.as_bytes().is_empty());
        assert!(!kp.public.as_bytes().is_empty());
    }

    #[test]
    fn save_and_load_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let kp = generate_keypair().unwrap();

        save_keys(dir.path(), &kp.secret, &kp.public).unwrap();
        let (loaded_sec, loaded_pub) = load_keys(dir.path()).unwrap();

        assert_eq!(kp.secret.as_bytes(), loaded_sec.as_bytes());
        assert_eq!(kp.public.as_bytes(), loaded_pub.as_bytes());
    }

    #[test]
    fn load_fails_on_missing_files() {
        let dir = tempfile::tempdir().unwrap();
        let result = load_keys(dir.path());
        assert!(result.is_err(), "should fail when key files don't exist");
    }

    #[test]
    fn load_fails_on_garbage_hex() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(SECRET_KEY_FILE), "not-hex!!").unwrap();
        std::fs::write(dir.path().join(PUBLIC_KEY_FILE), "also-garbage").unwrap();
        let result = load_keys(dir.path());
        assert!(result.is_err());
    }
}

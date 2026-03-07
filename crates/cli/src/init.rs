//! `forgedb init` — bootstrap a new ForgeDB data directory.
//!
//! Creates the data dir, generates self-signed TLS certs, creates an empty
//! encrypted database (prompting for a password), and writes `forgedb.toml`.

use std::path::PathBuf;

use forge_security::generate_self_signed_cert;
use forge_storage::StorageEngine;
use forge_types::{ForgeConfig, ForgeError, Result};

/// Options for the init command.
pub struct InitOptions {
    /// Where to create the data directory.
    pub data_dir: PathBuf,
    /// Whether to overwrite existing files.
    pub force: bool,
    /// Database password (from prompt or env var).
    pub password: String,
}

/// Run the `forgedb init` command.
///
/// 1. Creates `data_dir` if it doesn't exist
/// 2. Generates self-signed TLS cert + key
/// 3. Creates an empty encrypted redbx database
/// 4. Writes `forgedb.toml` config file
///
/// # Errors
///
/// Returns an error if any step fails — mkdir, cert gen, db creation, or
/// config writing.
pub fn run_init(opts: InitOptions) -> Result<()> {
    let config = ForgeConfig::default_with_data_dir(opts.data_dir.clone());

    // Guard against accidental overwrites
    let config_path = opts
        .data_dir
        .parent()
        .unwrap_or(opts.data_dir.as_path())
        .join("forgedb.toml");

    if !opts.force && config_path.exists() {
        return Err(ForgeError::Config(format!(
            "'{}' already exists. Use --force to overwrite.",
            config_path.display()
        )));
    }

    // 1. Create data directory
    std::fs::create_dir_all(&opts.data_dir)?;
    tracing::info!(path = %opts.data_dir.display(), "created data directory");

    // 2. Generate self-signed TLS cert + key
    generate_self_signed_cert(&config.tls_cert_path, &config.tls_key_path)?;

    // 3. Create empty encrypted database
    let db_path = opts.data_dir.join("forgedb.redbx");
    let _engine = StorageEngine::create(&db_path, &opts.password)?;
    tracing::info!("initialized encrypted database");

    // 4. Write config file
    let toml_str = toml::to_string_pretty(&config)
        .map_err(|e| ForgeError::Config(format!("failed to serialize config: {e}")))?;
    std::fs::write(&config_path, toml_str)?;
    tracing::info!(path = %config_path.display(), "wrote config file");

    println!();
    println!("  ForgeDB initialized successfully!");
    println!();
    println!("  Data directory:  {}", opts.data_dir.display());
    println!("  TLS certificate: {}", config.tls_cert_path.display());
    println!("  TLS private key: {}", config.tls_key_path.display());
    println!("  Database:        {}", db_path.display());
    println!("  Config:          {}", config_path.display());
    println!();
    println!("  ⚠  The generated certificate is self-signed (dev only).");
    println!("     Replace it with a CA-signed cert for production.");
    println!();
    println!("  Next: run `forgedb serve` to start the server.");
    println!();

    Ok(())
}

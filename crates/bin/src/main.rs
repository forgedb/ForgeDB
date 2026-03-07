//! ForgeDB — secure-by-default embedded document database.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use forge_cli::run_init;
use forge_types::{ForgeConfig, ForgeError};

#[derive(Parser)]
#[command(
    name = "forgedb",
    version,
    about = "ForgeDB — secure-by-default document database"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new ForgeDB data directory with TLS certs and encrypted storage.
    Init {
        /// Data directory path.
        #[arg(long, default_value = "./forgedb_data")]
        data_dir: PathBuf,

        /// Overwrite existing files.
        #[arg(long)]
        force: bool,
    },

    /// Start the ForgeDB server.
    Serve {
        /// Path to forgedb.toml config file.
        #[arg(long, default_value = "./forgedb.toml")]
        config: PathBuf,
    },
}

fn main() {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Init { data_dir, force } => cmd_init(data_dir, force),
        Commands::Serve { config } => cmd_serve(config),
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn cmd_init(data_dir: PathBuf, force: bool) -> forge_types::Result<()> {
    let password = prompt_password("Enter database password: ")?;
    let confirm = prompt_password("Confirm password: ")?;

    if password != confirm {
        return Err(ForgeError::Config("passwords do not match".into()));
    }

    if password.is_empty() {
        return Err(ForgeError::Config("password cannot be empty".into()));
    }

    run_init(forge_cli::init::InitOptions {
        data_dir,
        force,
        password,
    })
}

fn cmd_serve(config_path: PathBuf) -> forge_types::Result<()> {
    let toml_str = std::fs::read_to_string(&config_path).map_err(|e| {
        ForgeError::Config(format!(
            "failed to read config '{}': {e}",
            config_path.display()
        ))
    })?;

    let config: ForgeConfig = toml::from_str(&toml_str)
        .map_err(|e| ForgeError::Config(format!("failed to parse config: {e}")))?;

    config.validate()?;

    let password = match std::env::var("FORGEDB_PASSWORD") {
        Ok(p) => p,
        Err(_) => prompt_password("Enter database password: ")?,
    };

    let tls_config =
        forge_security::build_server_tls_config(&config.tls_cert_path, &config.tls_key_path)?;

    let db_path = config.data_dir.join("forgedb.redbx");
    let engine = forge_storage::StorageEngine::open(&db_path, &password)?;
    let engine = std::sync::Arc::new(engine);
    tracing::info!("database opened successfully");

    // We only need the public half for token verification. Keep the secret key
    // safely out of memory unless we're actively issuing tokens.
    let (_, public_key) = forge_auth::keys::load_keys(&config.data_dir)?;
    let public_key = std::sync::Arc::new(public_key);
    tracing::info!("PASETO public key loaded for token verification");

    // Load mandatory RLS Cedar policies. If missing, database refuses to start up.
    let policy_path = config.data_dir.join("policy.cedar");
    let policy_src = std::fs::read_to_string(&policy_path).map_err(|e| {
        ForgeError::Config(format!(
            "failed to read mandatory policy file '{}': {e}",
            policy_path.display()
        ))
    })?;
    let policy_engine = forge_query::policy::PolicyEngine::new(&policy_src)?;
    let policy_engine = std::sync::Arc::new(policy_engine);
    tracing::info!("Cedar enforcement policies loaded successfully");

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let listener = forge_protocol::TlsListener::bind(config.bind_address, tls_config).await?;
        println!("ForgeDB v0.1 listening on {}", config.bind_address);

        let app_state = forge_server::AppState {
            engine: engine.clone(),
            public_key: public_key.clone(),
            policy_engine: policy_engine.clone(),
        };
        let app = forge_server::app(app_state);

        loop {
            let (stream, _peer) = match listener.accept().await {
                Ok(res) => res,
                Err(e) => {
                    tracing::error!("listener error: {e}");
                    break;
                }
            };

            let app = app.clone();

            tokio::spawn(async move {
                forge_server::serve_connection(stream, app).await;
            });
        }
        Ok(())
    })
}

/// Prompt for a password on stderr so it works even when stdout is piped.
/// Falls back to reading from `FORGEDB_PASSWORD` env var for non-interactive use.
fn prompt_password(prompt: &str) -> forge_types::Result<String> {
    // Check env var first for CI / non-interactive scenarios
    if let Ok(pw) = std::env::var("FORGEDB_PASSWORD") {
        return Ok(pw);
    }

    eprint!("{prompt}");
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .map_err(|e| ForgeError::Config(format!("failed to read password: {e}")))?;
    Ok(input.trim().to_string())
}

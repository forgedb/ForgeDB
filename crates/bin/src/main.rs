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

        /// Instantly opens the TUI and connects to the running server.
        #[arg(long, default_value = "true")]
        with_tui: bool,
    },

    /// Start the Terminal Dashboard.
    Tui {
        /// Address to connect to
        #[arg(long, default_value = "https://127.0.0.1:5826")]
        url: String,

        /// PASETO token for authentication
        #[arg(long)]
        token: Option<String>,

        /// Path to the TLS certificate (required for self-signed development certs)
        #[arg(long)]
        cert: Option<PathBuf>,
    },
}

fn main() {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Init { data_dir, force } => cmd_init(data_dir, force),
        Commands::Serve { config, with_tui } => cmd_serve(config, with_tui),
        Commands::Tui { url, token, cert } => forge_cli::tui::run(url, token, cert),
    };

    if let Err(e) = result {
        eprintln!("\x1b[1;31merror:\x1b[0m {e}");
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

fn cmd_serve(config_path: PathBuf, with_tui: bool) -> forge_types::Result<()> {
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

    // We only need the public half for token verification.
    let (secret_key, public_key) = forge_auth::keys::load_keys(&config.data_dir)?;
    let public_key = std::sync::Arc::new(public_key);
    let secret_key = std::sync::Arc::new(secret_key);
    tracing::info!("PASETO keys loaded successfully");

    let admin_claims = forge_auth::TokenClaims::new("admin", 30 * 24 * 3600, Some("admin".into()));
    let admin_token = forge_auth::issue_token(&admin_claims, &secret_key)
        .map_err(|e| ForgeError::Auth(format!("failed to mint admin token: {e}")))?;

    println!(
        "\n  \x1b[1;36mDashboard Access Token (Valid 30 days):\x1b[0m \x1b[1;32m{admin_token}\x1b[0m\n"
    );

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
        // Spin up the write-coalescing background task. Concurrent POST requests
        // get batched into a single redbx transaction automatically.
        let writer = forge_storage::spawn_writer(engine.clone());

        let listener = forge_protocol::TlsListener::bind(config.bind_address, tls_config).await?;
        println!(
            "\x1b[1;32mForgeDB v{} listening on \x1b[1;36m{}\x1b[0m",
            env!("CARGO_PKG_VERSION"),
            config.bind_address
        );

        // Derive a 32-byte cursor signing key from the master password.
        let cursor_key_hash =
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, password.as_bytes());
        let mut cursor_key = [0u8; 32];
        cursor_key.copy_from_slice(cursor_key_hash.as_ref());
        let cursor_signer = std::sync::Arc::new(forge_security::CursorSigner::new(&cursor_key));

        let app_state = forge_server::AppState {
            engine: engine.clone(),
            writer,
            public_key: public_key.clone(),
            secret_key: secret_key.clone(),
            policy_engine: policy_engine.clone(),
            cursor_signer,
        };
        let app = forge_server::app(app_state);

        if with_tui {
            // Give the server a tiny bit to spin its sockets, then launch TUI in this thread.
            let ip = config.bind_address.ip();
            let connect_url = if ip.is_unspecified() {
                format!("https://127.0.0.1:{}", config.bind_address.port())
            } else {
                format!("https://{}", config.bind_address)
            };
            let token = admin_token.to_string();
            let cert_path = config.tls_cert_path.clone(); // Pass the local cert path
            tokio::task::spawn_blocking(move || {
                std::thread::sleep(std::time::Duration::from_millis(100));
                // ignore errors here, if TUI crashes just exit it
                let _ = forge_cli::tui::run(connect_url, Some(token), Some(cert_path));
                std::process::exit(0); // If user exits TUI, kill process.
            });
        }

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

    eprint!("\x1b[1;36m{prompt}\x1b[0m");
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .map_err(|e| ForgeError::Config(format!("failed to read password: {e}")))?;
    Ok(input.trim().to_string())
}

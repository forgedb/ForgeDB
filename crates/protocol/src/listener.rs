//! TLS-mandatory TCP listener.
//!
//! Wraps tokio's `TcpListener` with a `TlsAcceptor` so every accepted
//! connection is forced through a TLS 1.3 handshake. For v0.1, the default
//! handler just sends a banner and closes — proper HTTP routing comes later.

use std::net::SocketAddr;
use std::sync::Arc;

use rustls::ServerConfig;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use forge_types::Result;

/// A TCP listener that only speaks TLS.
pub struct TlsListener {
    tcp: TcpListener,
    acceptor: TlsAcceptor,
}

impl TlsListener {
    /// Bind to an address with the given TLS config.
    ///
    /// # Errors
    ///
    /// Returns [`ForgeError::Io`] if the bind fails (port in use, etc.).
    pub async fn bind(addr: SocketAddr, tls_config: Arc<ServerConfig>) -> Result<Self> {
        let tcp = TcpListener::bind(addr).await?;
        let acceptor = TlsAcceptor::from(tls_config);

        tracing::info!(%addr, "TLS listener bound");
        Ok(Self { tcp, acceptor })
    }

    /// Accept loop — runs forever, spawning a task per connection.
    ///
    /// For v0.1 each connection gets a "ForgeDB v0.1" banner then closes.
    /// This proves the TLS pipeline end-to-end; actual request handling
    /// comes in v0.2 when the server crate is wired up.
    pub async fn run(&self) -> Result<()> {
        loop {
            let (stream, peer) = self.tcp.accept().await?;
            let acceptor = self.acceptor.clone();

            tokio::spawn(async move {
                match acceptor.accept(stream).await {
                    Ok(mut tls_stream) => {
                        tracing::info!(%peer, "TLS handshake complete");
                        let banner = b"ForgeDB v0.1\n";
                        if let Err(e) = tls_stream.write_all(banner).await {
                            tracing::warn!(%peer, "failed to write banner: {e}");
                        }
                        let _ = tls_stream.shutdown().await;
                    }
                    Err(e) => {
                        tracing::warn!(%peer, "TLS handshake failed: {e}");
                    }
                }
            });
        }
    }
}

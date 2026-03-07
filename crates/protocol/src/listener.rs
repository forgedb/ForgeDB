//! TLS-mandatory TCP listener.
//!
//! Wraps tokio's `TcpListener` with a `TlsAcceptor` so every accepted
//! connection is forced through a TLS 1.3 handshake. For v0.1, the default
//! handler just sends a banner and closes — proper HTTP routing comes later.

use std::net::SocketAddr;
use std::sync::Arc;

use rustls::ServerConfig;
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

    /// Accept a single incoming connection and complete the TLS handshake.
    ///
    /// The caller is responsible for actually handling the HTTP protocol
    /// (e.g. passing this stream to `hyper`).
    ///
    /// # Errors
    ///
    /// Returns [`ForgeError::Io`] if the socket drops. Handshake failures
    /// are completely normal (e.g. probes, scans) and won't bubble up here —
    /// this function will simply log them and grab the next connection.
    pub async fn accept(
        &self,
    ) -> Result<(
        tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
        SocketAddr,
    )> {
        loop {
            let (stream, peer) = self.tcp.accept().await?;
            let acceptor = self.acceptor.clone();

            // Perform TLS handshake concurrently so we don't block the accept loop
            // if a client is slow to negotiate.
            let stream_result =
                tokio::spawn(async move { acceptor.accept(stream).await.map(|s| (s, peer)) }).await;

            match stream_result {
                Ok(Ok((tls_stream, peer))) => return Ok((tls_stream, peer)),
                Ok(Err(e)) => {
                    tracing::debug!(%peer, "TLS handshake failed: {e}");
                }
                Err(e) => {
                    tracing::warn!("TLS handshake task panicked: {e}");
                }
            }
        }
    }
}

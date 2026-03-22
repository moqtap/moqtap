//! Listeners for accepting incoming MoQT connections (QUIC and WebTransport).

use std::net::SocketAddr;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::error::ProxyError;

/// Configuration for the proxy's QUIC listener.
pub struct ListenerConfig {
    /// Address to bind to (e.g., `"0.0.0.0:4443"`).
    pub bind_addr: SocketAddr,
    /// TLS certificate chain (DER-encoded).
    pub cert_chain: Vec<CertificateDer<'static>>,
    /// TLS private key (DER-encoded).
    pub key_der: PrivateKeyDer<'static>,
    /// ALPN protocols to accept. Defaults to `[b"moq-00"]`.
    pub alpn: Vec<Vec<u8>>,
}

/// A QUIC listener that accepts incoming connections and detects the
/// negotiated ALPN protocol.
pub struct Listener {
    endpoint: quinn::Endpoint,
}

impl Listener {
    /// Bind to the configured address and start listening.
    pub fn bind(config: ListenerConfig) -> Result<Self, ProxyError> {
        let mut server_tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(config.cert_chain, config.key_der)
            .map_err(|e| ProxyError::TlsConfig(format!("server cert config: {e}")))?;

        server_tls.alpn_protocols = config.alpn;
        server_tls.max_early_data_size = u32::MAX;

        let quic_server_config: quinn::crypto::rustls::QuicServerConfig =
            server_tls.try_into().map_err(|e| ProxyError::TlsConfig(format!("{e}")))?;

        let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));

        let endpoint = quinn::Endpoint::server(server_config, config.bind_addr)
            .map_err(|e| ProxyError::Listener(e.to_string()))?;

        Ok(Self { endpoint })
    }

    /// Accept the next incoming QUIC connection.
    ///
    /// Returns the `quinn::Connection` and the negotiated ALPN protocol.
    pub async fn accept(&self) -> Result<(quinn::Connection, Vec<u8>), ProxyError> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| ProxyError::Listener("endpoint closed".to_string()))?;

        let conn = incoming.await.map_err(|e| ProxyError::Listener(e.to_string()))?;

        let alpn = conn
            .handshake_data()
            .and_then(|hd| hd.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            .and_then(|hd| hd.protocol)
            .map(|p| p.to_vec())
            .unwrap_or_default();

        Ok((conn, alpn))
    }

    /// Get the local address this listener is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, ProxyError> {
        self.endpoint.local_addr().map_err(|e| ProxyError::Listener(e.to_string()))
    }

    /// Stop accepting new connections.
    pub fn close(&self) {
        self.endpoint.close(0u32.into(), b"proxy shutting down");
    }
}

// ── WebTransport listener ─────────────────────────────────────

/// Configuration for the proxy's WebTransport listener.
#[cfg(feature = "webtransport")]
pub struct WtListenerConfig {
    /// Address to bind to (e.g., `"0.0.0.0:4443"`).
    pub bind_addr: SocketAddr,
    /// TLS certificate chain (DER-encoded).
    pub cert_chain: Vec<CertificateDer<'static>>,
    /// TLS private key (DER-encoded).
    pub key_der: PrivateKeyDer<'static>,
}

/// A WebTransport listener that accepts incoming sessions.
#[cfg(feature = "webtransport")]
pub struct WtListener {
    endpoint: wtransport::Endpoint<wtransport::endpoint::endpoint_side::Server>,
}

#[cfg(feature = "webtransport")]
impl WtListener {
    /// Bind to the configured address and start listening.
    pub fn bind(config: WtListenerConfig) -> Result<Self, ProxyError> {
        let mut server_tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(config.cert_chain, config.key_der)
            .map_err(|e| ProxyError::TlsConfig(format!("server cert config: {e}")))?;

        // WebTransport uses h3 ALPN
        server_tls.alpn_protocols = vec![b"h3".to_vec()];

        let wt_config = wtransport::ServerConfig::builder()
            .with_bind_address(config.bind_addr)
            .with_custom_tls(server_tls)
            .build();

        let endpoint = wtransport::Endpoint::server(wt_config)
            .map_err(|e| ProxyError::Listener(e.to_string()))?;

        Ok(Self { endpoint })
    }

    /// Accept the next incoming WebTransport connection.
    pub async fn accept(&self) -> Result<wtransport::Connection, ProxyError> {
        let incoming = self.endpoint.accept().await;
        let session_request = incoming.await.map_err(|e| ProxyError::Listener(e.to_string()))?;
        let conn =
            session_request.accept().await.map_err(|e| ProxyError::Listener(e.to_string()))?;
        Ok(conn)
    }

    /// Get the local address this listener is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, ProxyError> {
        self.endpoint.local_addr().map_err(|e| ProxyError::Listener(e.to_string()))
    }

    /// Stop accepting new connections.
    pub fn close(&self) {
        self.endpoint.close(wtransport::VarInt::from_u32(0), b"proxy shutting down");
    }
}

//! Unified listener — one UDP endpoint that accepts both raw-QUIC MoQT
//! and WebTransport clients, dispatching per connection based on the
//! ALPN the client negotiated during the TLS handshake.

use std::net::SocketAddr;
use std::sync::Arc;

use moqtap_codec::version::DraftVersion;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::error::ProxyError;

/// WebTransport ALPN identifier.
const H3_ALPN: &[u8] = b"h3";

/// Configuration for the proxy's listener.
pub struct ListenerConfig {
    /// Address to bind to (e.g., `"0.0.0.0:4443"`).
    pub bind_addr: SocketAddr,
    /// TLS certificate chain (DER-encoded).
    pub cert_chain: Vec<CertificateDer<'static>>,
    /// TLS private key (DER-encoded).
    pub key_der: PrivateKeyDer<'static>,
}

/// A client connection that has completed its handshake and is ready
/// for MoQT session handling.
///
/// Produced by [`Listener::accept`]. Each variant corresponds to a
/// distinct client-facing transport that MoQT can run over.
pub enum AcceptedConn {
    /// Raw QUIC connection speaking MoQT directly. The negotiated ALPN
    /// (`moq-00`, `moqt-15`, `moqt-16`, `moqt-17`, …) is returned so
    /// callers can resolve the draft version.
    Quic {
        /// The accepted QUIC connection.
        conn: quinn::Connection,
        /// The ALPN negotiated with the client.
        alpn: Vec<u8>,
    },
    /// WebTransport session, with the H3 + extended-CONNECT dance
    /// already completed by the listener.
    #[cfg(feature = "webtransport")]
    WebTransport(wtransport::Connection),
}

/// Build the ALPN list the server advertises to clients — every MoQT
/// QUIC ALPN we support, plus `h3` when the WebTransport feature is on.
///
/// The list is derived from [`DraftVersion::quic_alpn`] so adding a new
/// draft there automatically flows through to the proxy with no other
/// changes required.
fn advertised_alpns() -> Vec<Vec<u8>> {
    // Dedup: drafts 07–14 all map to `moq-00`, so iterate every draft
    // and keep unique ALPNs.
    let mut out: Vec<Vec<u8>> = Vec::new();
    for d in [
        DraftVersion::Draft07,
        DraftVersion::Draft08,
        DraftVersion::Draft09,
        DraftVersion::Draft10,
        DraftVersion::Draft11,
        DraftVersion::Draft12,
        DraftVersion::Draft13,
        DraftVersion::Draft14,
        DraftVersion::Draft15,
        DraftVersion::Draft16,
        DraftVersion::Draft17,
        DraftVersion::Draft18,
    ] {
        let alpn = d.quic_alpn().to_vec();
        if !out.iter().any(|existing| existing == &alpn) {
            out.push(alpn);
        }
    }
    #[cfg(feature = "webtransport")]
    out.push(H3_ALPN.to_vec());
    out
}

/// A transport-agnostic MoQT listener that accepts both raw-QUIC and
/// WebTransport clients on the same UDP port.
pub struct Listener {
    endpoint: quinn::Endpoint,
}

impl Listener {
    /// Bind to the configured address and start listening.
    ///
    /// The listener advertises every supported MoQT ALPN (`moq-00` and
    /// `moqt-<N>` for all known drafts) plus `h3` for WebTransport. The
    /// client picks which one to speak; the proxy forwards whatever
    /// arrives.
    pub fn bind(config: ListenerConfig) -> Result<Self, ProxyError> {
        let mut server_tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(config.cert_chain, config.key_der)
            .map_err(|e| ProxyError::TlsConfig(format!("server cert config: {e}")))?;

        server_tls.alpn_protocols = advertised_alpns();
        server_tls.max_early_data_size = u32::MAX;

        let quic_server_config: quinn::crypto::rustls::QuicServerConfig =
            server_tls.try_into().map_err(|e| ProxyError::TlsConfig(format!("{e}")))?;

        let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));

        let endpoint = quinn::Endpoint::server(server_config, config.bind_addr)
            .map_err(|e| ProxyError::Listener(e.to_string()))?;

        Ok(Self { endpoint })
    }

    /// Accept the next incoming connection and dispatch based on the
    /// ALPN negotiated during the TLS handshake.
    ///
    /// Raw-QUIC connections are returned immediately with the negotiated
    /// ALPN so the caller can pick the MoQT draft. For `h3` clients the
    /// listener drives the HTTP/3 + extended-CONNECT handshake to
    /// completion before returning a ready `wtransport::Connection`.
    pub async fn accept(&self) -> Result<AcceptedConn, ProxyError> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| ProxyError::Listener("endpoint closed".to_string()))?;

        let mut connecting = incoming.accept().map_err(|e| ProxyError::Listener(e.to_string()))?;

        // Peeking at handshake_data resolves as soon as the server has
        // processed the ClientHello, so the ALPN is known before the
        // full handshake completes — and the Connecting is still live.
        let hs_data = connecting
            .handshake_data()
            .await
            .map_err(|e| ProxyError::Listener(format!("handshake data: {e}")))?;

        let alpn = hs_data
            .downcast::<quinn::crypto::rustls::HandshakeData>()
            .ok()
            .and_then(|hd| hd.protocol)
            .map(|p| p.to_vec())
            .unwrap_or_default();

        if alpn == H3_ALPN {
            #[cfg(feature = "webtransport")]
            {
                let session_fut =
                    wtransport::endpoint::IncomingSessionFuture::with_quic_connecting(connecting);
                let session_request = session_fut
                    .await
                    .map_err(|e| ProxyError::Listener(format!("webtransport handshake: {e}")))?;
                let conn = session_request
                    .accept()
                    .await
                    .map_err(|e| ProxyError::Listener(format!("webtransport accept: {e}")))?;
                Ok(AcceptedConn::WebTransport(conn))
            }
            #[cfg(not(feature = "webtransport"))]
            {
                drop(connecting);
                Err(ProxyError::Listener(
                    "client negotiated h3 but webtransport feature is not enabled".to_string(),
                ))
            }
        } else {
            let conn = connecting.await.map_err(|e| ProxyError::Listener(e.to_string()))?;
            Ok(AcceptedConn::Quic { conn, alpn })
        }
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

//! Proxy error types.

use moqtap_client::transport::TransportError;
use moqtap_codec::error::CodecError;

/// Errors from the proxy layer.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    /// Error from the QUIC/WebTransport listener.
    #[error("listener error: {0}")]
    Listener(String),
    /// Error from the underlying transport.
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),
    /// Error decoding a MoQT frame.
    #[error("codec error: {0}")]
    Codec(#[from] CodecError),
    /// Failed to connect to the upstream relay.
    #[error("upstream connection failed: {0}")]
    UpstreamConnect(String),
    /// TLS configuration error.
    #[error("TLS config error: {0}")]
    TlsConfig(String),
    /// Certificate generation error.
    #[error("certificate generation error: {0}")]
    CertGen(String),
    /// Session was closed.
    #[error("session closed: {0}")]
    SessionClosed(String),
    /// Proxy is shutting down.
    #[error("proxy shutdown")]
    Shutdown,
}

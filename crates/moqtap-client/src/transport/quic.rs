//! QUIC transport implementation wrapping quinn.

use bytes::Bytes;

use super::{RecvStream, SendStream, TransportError};

/// QUIC transport wrapping a `quinn::Connection`.
pub struct QuicTransport {
    conn: quinn::Connection,
}

impl QuicTransport {
    /// Create a new QUIC transport from a quinn connection.
    pub fn new(conn: quinn::Connection) -> Self {
        Self { conn }
    }

    /// Open a bidirectional stream.
    pub async fn open_bi(&self) -> Result<(SendStream, RecvStream), TransportError> {
        let (send, recv) = self.conn.open_bi().await.map_err(conn_err)?;
        Ok((SendStream::Quic(send), RecvStream::Quic(recv)))
    }

    /// Accept an incoming bidirectional stream.
    pub async fn accept_bi(&self) -> Result<(SendStream, RecvStream), TransportError> {
        let (send, recv) = self.conn.accept_bi().await.map_err(conn_err)?;
        Ok((SendStream::Quic(send), RecvStream::Quic(recv)))
    }

    /// Open a unidirectional send stream.
    pub async fn open_uni(&self) -> Result<SendStream, TransportError> {
        let send = self.conn.open_uni().await.map_err(conn_err)?;
        Ok(SendStream::Quic(send))
    }

    /// Accept an incoming unidirectional stream.
    pub async fn accept_uni(&self) -> Result<RecvStream, TransportError> {
        let recv = self.conn.accept_uni().await.map_err(conn_err)?;
        Ok(RecvStream::Quic(recv))
    }

    /// Send a datagram.
    pub fn send_datagram(&self, data: Bytes) -> Result<(), TransportError> {
        self.conn.send_datagram(data).map_err(|e| TransportError::SendDatagram(e.to_string()))
    }

    /// Receive a datagram.
    pub async fn recv_datagram(&self) -> Result<Bytes, TransportError> {
        self.conn.read_datagram().await.map_err(conn_err)
    }

    /// Close the connection.
    pub fn close(&self, code: u32, reason: &[u8]) {
        self.conn.close(quinn::VarInt::from_u32(code), reason);
    }
}

/// Convert a quinn connection error to a TransportError.
fn conn_err(e: quinn::ConnectionError) -> TransportError {
    TransportError::Connection(e.to_string())
}

// ── From impls for quinn error types ────────────────────────

impl From<quinn::ConnectionError> for TransportError {
    fn from(e: quinn::ConnectionError) -> Self {
        TransportError::Connection(e.to_string())
    }
}

impl From<quinn::WriteError> for TransportError {
    /// `Stopped` keeps the peer's application error code as a typed
    /// [`TransportError::Stopped`] so a forwarder can mirror it; every
    /// other cause collapses to a message.
    fn from(e: quinn::WriteError) -> Self {
        match e {
            quinn::WriteError::Stopped(code) => TransportError::Stopped(code.into_inner()),
            other => TransportError::Write(other.to_string()),
        }
    }
}

impl From<quinn::ReadError> for TransportError {
    /// `Reset` keeps the peer's application error code as a typed
    /// [`TransportError::StreamReset`] so a forwarder can mirror it;
    /// every other cause collapses to a message.
    fn from(e: quinn::ReadError) -> Self {
        match e {
            quinn::ReadError::Reset(code) => TransportError::StreamReset(code.into_inner()),
            other => TransportError::Read(other.to_string()),
        }
    }
}

impl From<quinn::ReadExactError> for TransportError {
    fn from(e: quinn::ReadExactError) -> Self {
        match e {
            quinn::ReadExactError::ReadError(inner) => inner.into(),
            other => TransportError::Read(other.to_string()),
        }
    }
}

impl From<quinn::ConnectError> for TransportError {
    fn from(e: quinn::ConnectError) -> Self {
        TransportError::Connect(e.to_string())
    }
}

impl From<quinn::ClosedStream> for TransportError {
    fn from(_e: quinn::ClosedStream) -> Self {
        TransportError::StreamClosed
    }
}

impl From<quinn::SendDatagramError> for TransportError {
    fn from(e: quinn::SendDatagramError) -> Self {
        TransportError::SendDatagram(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Dialling
// ---------------------------------------------------------------------------

/// How a QUIC dial is configured, independent of any draft.
///
/// `alpn` is a list because ALPN is: one handshake offers several protocols and
/// the server picks, which is how a caller that does not know a peer's draft
/// finds out without dialling once per candidate.
pub struct QuicDialOptions {
    /// Skip TLS certificate verification. Testing only.
    pub skip_cert_verification: bool,
    /// Additional CA certificates to trust, DER-encoded.
    pub ca_certs: Vec<Vec<u8>>,
    /// ALPN protocols to offer, in preference order.
    ///
    /// [`dial_quic`] returns the one the server selected. An empty list offers
    /// nothing and is refused by any peer that requires ALPN, which every MoQT
    /// relay does.
    pub alpn: Vec<Vec<u8>>,
}

/// Why a QUIC dial did not produce a connection.
///
/// Separate from [`TransportError`] so the two failures that happen before any
/// packet is sent — a bad address, a TLS config this machine rejects — stay
/// distinguishable from a peer that would not talk to us.
#[derive(Debug, thiserror::Error)]
pub enum DialError {
    /// `addr` is not a `host:port` this machine can resolve to a socket address.
    #[error("invalid address: {0}")]
    InvalidAddress(String),
    /// The TLS client configuration could not be built.
    #[error("TLS configuration error: {0}")]
    TlsConfig(String),
    /// The dial itself failed.
    #[error(transparent)]
    Transport(#[from] TransportError),
}

/// Dial a QUIC server, and report which ALPN it chose.
///
/// The second return value is the protocol the server chose from `options.alpn`,
/// `None` if it selected none.
/// [`DraftVersion::from_alpn`](moqtap_codec::version::DraftVersion::from_alpn)
/// names a draft for five of the six; drafts 07-14 share `moq-00` and settle
/// their version in CLIENT_SETUP.
///
/// The endpoint is dropped when the dial returns — quinn keeps the connection's
/// driver alive independently.
pub async fn dial_quic(
    addr: &str,
    options: &QuicDialOptions,
) -> Result<(super::Transport, Option<Vec<u8>>), DialError> {
    use std::sync::Arc;

    let server_addr = addr
        .parse()
        .map_err(|e: std::net::AddrParseError| DialError::InvalidAddress(e.to_string()))?;

    let mut tls_config = if options.skip_cert_verification {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipVerification))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        for der in &options.ca_certs {
            roots
                .add(rustls::pki_types::CertificateDer::from(der.clone()))
                .map_err(|e| DialError::TlsConfig(format!("bad CA cert: {e}")))?;
        }
        rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth()
    };

    tls_config.alpn_protocols = options.alpn.clone();

    let quic_config: quinn::crypto::rustls::QuicClientConfig =
        tls_config.try_into().map_err(|e| DialError::TlsConfig(format!("{e}")))?;
    let client_config = quinn::ClientConfig::new(Arc::new(quic_config));

    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
        .map_err(|e| DialError::InvalidAddress(e.to_string()))?;
    endpoint.set_default_client_config(client_config);

    let server_name = addr.split(':').next().unwrap_or("localhost").to_string();

    let quic = endpoint
        .connect(server_addr, &server_name)
        .map_err(TransportError::from)?
        .await
        .map_err(TransportError::from)?;

    let negotiated = negotiated_alpn(&quic);
    Ok((super::Transport::Quic(QuicTransport::new(quic)), negotiated))
}

/// The ALPN the server selected, if the handshake recorded one.
fn negotiated_alpn(conn: &quinn::Connection) -> Option<Vec<u8>> {
    conn.handshake_data()?.downcast::<quinn::crypto::rustls::HandshakeData>().ok()?.protocol
}

/// TLS certificate verifier that skips all verification. Testing only.
#[derive(Debug)]
struct SkipVerification;

impl rustls::client::danger::ServerCertVerifier for SkipVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dcs: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dcs: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

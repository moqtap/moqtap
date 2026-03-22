use std::sync::Arc;

use bytes::{Buf, BytesMut};

use crate::event::{ClientEvent, Direction, StreamKind};
use crate::observer::ConnectionObserver;
use crate::session::request_id::Role;
use crate::transport::quic::QuicTransport;
use crate::transport::{RecvStream, SendStream, Transport, TransportError};
use moqtap_codec::dispatch::{
    AnyControlMessage, AnyDatagramHeader, AnyFetchHeader, AnyObjectHeader, AnySubgroupHeader,
};
use moqtap_codec::draft14::message::ControlMessage;
use moqtap_codec::error::CodecError;
use moqtap_codec::types::*;
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

use crate::endpoint::{Endpoint, EndpointError};

/// MoQT ALPN identifier (used by raw QUIC transport).
pub const MOQT_ALPN: &[u8] = b"moq-00";

/// Errors from the connection layer.
#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    /// Endpoint state machine error.
    #[error("endpoint error: {0}")]
    Endpoint(#[from] EndpointError),
    /// Wire codec error.
    #[error("codec error: {0}")]
    Codec(#[from] CodecError),
    /// Transport-level error.
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),
    /// Variable-length integer decoding error.
    #[error("varint error: {0}")]
    VarInt(#[from] moqtap_codec::varint::VarIntError),
    /// Control stream was not opened.
    #[error("control stream not open")]
    NoControlStream,
    /// Stream ended before a complete message was read.
    #[error("unexpected end of stream")]
    UnexpectedEnd,
    /// Stream was finished by the peer.
    #[error("stream finished")]
    StreamFinished,
    /// Invalid server address string.
    #[error("invalid server address: {0}")]
    InvalidAddress(String),
    /// TLS configuration error.
    #[error("TLS config error: {0}")]
    TlsConfig(String),
}

/// Transport type for the connection.
#[derive(Debug, Clone)]
pub enum TransportType {
    /// Raw QUIC via quinn. The `addr` field should be `host:port`.
    Quic,
    /// WebTransport via wtransport. The `url` field is the WebTransport URL.
    WebTransport {
        /// The WebTransport endpoint URL (e.g., `https://host:port/path`).
        url: String,
    },
}

/// Configuration for a MoQT client connection.
///
/// Both `draft` and `transport` are required — there is no `Default` impl.
pub struct ClientConfig {
    /// The MoQT draft version to use.
    pub draft: DraftVersion,
    /// The transport type (QUIC or WebTransport).
    pub transport: TransportType,
    /// Whether to skip TLS certificate verification (for testing).
    pub skip_cert_verification: bool,
    /// Custom CA certificates to trust (DER-encoded).
    pub ca_certs: Vec<Vec<u8>>,
}

impl ClientConfig {
    /// Returns the MoQT version varints for the CLIENT_SETUP message.
    pub fn supported_versions(&self) -> Vec<VarInt> {
        vec![self.draft.version_varint()]
    }

    /// Returns the ALPN protocol identifiers for the transport.
    pub fn alpn(&self) -> Vec<Vec<u8>> {
        match &self.transport {
            TransportType::Quic => vec![self.draft.quic_alpn().to_vec()],
            TransportType::WebTransport { .. } => vec![b"h3".to_vec()],
        }
    }
}

/// A framed writer for a send stream. Handles MoQT length-prefixed framing.
pub struct FramedSendStream {
    inner: SendStream,
    draft: DraftVersion,
}

impl FramedSendStream {
    /// Create a new framed send stream for the given draft version.
    pub fn new(inner: SendStream, draft: DraftVersion) -> Self {
        Self { inner, draft }
    }

    /// Write a control message to the stream with type+length framing.
    pub async fn write_control(&mut self, msg: &AnyControlMessage) -> Result<(), ConnectionError> {
        let mut buf = Vec::new();
        msg.encode(&mut buf)?;
        self.inner.write_all(&buf).await?;
        Ok(())
    }

    /// Write a subgroup stream header.
    pub async fn write_subgroup_header(
        &mut self,
        header: &AnySubgroupHeader,
    ) -> Result<(), ConnectionError> {
        let mut buf = Vec::new();
        header.encode(&mut buf);
        self.inner.write_all(&buf).await?;
        Ok(())
    }

    /// Write a fetch response header.
    pub async fn write_fetch_header(
        &mut self,
        header: &AnyFetchHeader,
    ) -> Result<(), ConnectionError> {
        let mut buf = Vec::new();
        header.encode(&mut buf);
        self.inner.write_all(&buf).await?;
        Ok(())
    }

    /// Write an object header followed by payload.
    pub async fn write_object(
        &mut self,
        header: &AnyObjectHeader,
        payload: &[u8],
    ) -> Result<(), ConnectionError> {
        let mut buf = Vec::new();
        header.encode(&mut buf);
        self.inner.write_all(&buf).await?;
        if !payload.is_empty() {
            self.inner.write_all(payload).await?;
        }
        Ok(())
    }

    /// Finish the stream (send FIN).
    pub async fn finish(&mut self) -> Result<(), ConnectionError> {
        self.inner.finish()?;
        Ok(())
    }

    /// Returns the draft version this stream is framed for.
    pub fn draft(&self) -> DraftVersion {
        self.draft
    }
}

/// A framed reader for a recv stream. Handles MoQT varint-length decoding.
pub struct FramedRecvStream {
    inner: RecvStream,
    buf: BytesMut,
    draft: DraftVersion,
}

impl FramedRecvStream {
    /// Create a new framed receive stream for the given draft version.
    pub fn new(inner: RecvStream, draft: DraftVersion) -> Self {
        Self { inner, buf: BytesMut::with_capacity(4096), draft }
    }

    /// Read more data from the stream into the internal buffer.
    async fn fill(&mut self) -> Result<bool, ConnectionError> {
        let mut tmp = [0u8; 4096];
        match self.inner.read(&mut tmp).await {
            Ok(Some(n)) => {
                self.buf.extend_from_slice(&tmp[..n]);
                Ok(true)
            }
            Ok(None) => Ok(false),
            Err(e) => Err(ConnectionError::Transport(e)),
        }
    }

    /// Ensure at least `n` bytes are available in the buffer.
    async fn ensure(&mut self, n: usize) -> Result<(), ConnectionError> {
        while self.buf.len() < n {
            if !self.fill().await? {
                return Err(ConnectionError::UnexpectedEnd);
            }
        }
        Ok(())
    }

    /// Read a control message from the stream.
    pub async fn read_control(&mut self) -> Result<AnyControlMessage, ConnectionError> {
        // Read type ID varint
        self.ensure(1).await?;
        let type_len = varint_len(self.buf[0]);
        self.ensure(type_len).await?;

        let mut cursor = &self.buf[..type_len];
        let _type_id = VarInt::decode(&mut cursor)?;

        // Read payload length varint
        self.ensure(type_len + 1).await?;
        let payload_len_start = type_len;
        let payload_len_varint_len = varint_len(self.buf[payload_len_start]);
        self.ensure(type_len + payload_len_varint_len).await?;

        let mut cursor = &self.buf[payload_len_start..type_len + payload_len_varint_len];
        let payload_len = VarInt::decode(&mut cursor)?.into_inner() as usize;

        // Read full payload
        let total = type_len + payload_len_varint_len + payload_len;
        self.ensure(total).await?;

        // Now decode the whole message
        let mut frame = &self.buf[..total];
        let msg = AnyControlMessage::decode(self.draft, &mut frame)?;
        self.buf.advance(total);
        Ok(msg)
    }

    /// Read a subgroup stream header.
    pub async fn read_subgroup_header(&mut self) -> Result<AnySubgroupHeader, ConnectionError> {
        self.ensure(4).await?;
        loop {
            let mut cursor = &self.buf[..];
            match AnySubgroupHeader::decode(self.draft, &mut cursor) {
                Ok(header) => {
                    let consumed = self.buf.len() - cursor.remaining();
                    self.buf.advance(consumed);
                    return Ok(header);
                }
                Err(_) => {
                    if !self.fill().await? {
                        return Err(ConnectionError::UnexpectedEnd);
                    }
                }
            }
        }
    }

    /// Read a fetch response header.
    pub async fn read_fetch_header(&mut self) -> Result<AnyFetchHeader, ConnectionError> {
        self.ensure(4).await?;
        loop {
            let mut cursor = &self.buf[..];
            match AnyFetchHeader::decode(self.draft, &mut cursor) {
                Ok(header) => {
                    let consumed = self.buf.len() - cursor.remaining();
                    self.buf.advance(consumed);
                    return Ok(header);
                }
                Err(_) => {
                    if !self.fill().await? {
                        return Err(ConnectionError::UnexpectedEnd);
                    }
                }
            }
        }
    }

    /// Read an object header.
    pub async fn read_object_header(&mut self) -> Result<AnyObjectHeader, ConnectionError> {
        self.ensure(2).await?;
        loop {
            let mut cursor = &self.buf[..];
            match AnyObjectHeader::decode(self.draft, &mut cursor) {
                Ok(header) => {
                    let consumed = self.buf.len() - cursor.remaining();
                    self.buf.advance(consumed);
                    return Ok(header);
                }
                Err(_) => {
                    if !self.fill().await? {
                        return Err(ConnectionError::UnexpectedEnd);
                    }
                }
            }
        }
    }

    /// Read exactly `n` bytes of object payload.
    pub async fn read_payload(&mut self, n: usize) -> Result<Vec<u8>, ConnectionError> {
        self.ensure(n).await?;
        let data = self.buf[..n].to_vec();
        self.buf.advance(n);
        Ok(data)
    }

    /// Returns the draft version this stream is framed for.
    pub fn draft(&self) -> DraftVersion {
        self.draft
    }
}

/// A live MoQT connection over QUIC or WebTransport, combining the endpoint
/// state machine with actual network I/O.
pub struct Connection {
    transport: Transport,
    endpoint: Endpoint,
    draft: DraftVersion,
    control_send: Option<FramedSendStream>,
    control_recv: Option<FramedRecvStream>,
    observer: Option<Box<dyn ConnectionObserver>>,
}

impl Connection {
    /// Connect to a MoQT server as a client.
    ///
    /// Establishes a QUIC or WebTransport connection (based on `config.transport`),
    /// opens a bidirectional control stream, performs the CLIENT_SETUP /
    /// SERVER_SETUP handshake, and returns a ready-to-use connection.
    pub async fn connect(addr: &str, config: ClientConfig) -> Result<Self, ConnectionError> {
        let draft = config.draft;
        let transport = match &config.transport {
            TransportType::Quic => Self::connect_quic(addr, &config).await?,
            TransportType::WebTransport { url } => {
                let url = url.clone();
                Self::connect_webtransport(&url, &config).await?
            }
        };

        // Open bidirectional control stream
        let (send, recv) = transport.open_bi().await?;
        let mut control_send = FramedSendStream::new(send, draft);
        let mut control_recv = FramedRecvStream::new(recv, draft);

        // Perform setup handshake
        let mut endpoint = Endpoint::new(Role::Client);
        endpoint.connect()?;
        let setup_msg = endpoint.send_client_setup(config.supported_versions())?;
        let any_setup = AnyControlMessage::Draft14(setup_msg);
        control_send.write_control(&any_setup).await?;

        let server_setup = control_recv.read_control().await?;
        // Unwrap to draft-14 for the endpoint (which is draft-14 only)
        match &server_setup {
            AnyControlMessage::Draft14(ControlMessage::ServerSetup(ref ss)) => {
                endpoint.receive_server_setup(ss)?;
            }
            _ => {
                return Err(ConnectionError::Endpoint(EndpointError::NotActive));
            }
        }

        Ok(Self {
            transport,
            endpoint,
            draft,
            control_send: Some(control_send),
            control_recv: Some(control_recv),
            observer: None,
        })
    }

    /// Establish a raw QUIC connection.
    async fn connect_quic(addr: &str, config: &ClientConfig) -> Result<Transport, ConnectionError> {
        let server_addr = addr.parse().map_err(|e: std::net::AddrParseError| {
            ConnectionError::InvalidAddress(e.to_string())
        })?;

        // Build TLS config
        let mut tls_config = if config.skip_cert_verification {
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(SkipVerification))
                .with_no_client_auth()
        } else {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            for der in &config.ca_certs {
                roots
                    .add(rustls::pki_types::CertificateDer::from(der.clone()))
                    .map_err(|e| ConnectionError::TlsConfig(format!("bad CA cert: {e}")))?;
            }
            rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth()
        };

        tls_config.alpn_protocols = config.alpn();

        let quic_config: quinn::crypto::rustls::QuicClientConfig =
            tls_config.try_into().map_err(|e| ConnectionError::TlsConfig(format!("{e}")))?;
        let client_config = quinn::ClientConfig::new(Arc::new(quic_config));

        let mut quinn_endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| ConnectionError::InvalidAddress(e.to_string()))?;
        quinn_endpoint.set_default_client_config(client_config);

        let server_name = addr.split(':').next().unwrap_or("localhost").to_string();

        let quic = quinn_endpoint
            .connect(server_addr, &server_name)
            .map_err(TransportError::from)?
            .await
            .map_err(TransportError::from)?;

        Ok(Transport::Quic(QuicTransport::new(quic)))
    }

    /// Establish a WebTransport connection.
    #[cfg(feature = "webtransport")]
    async fn connect_webtransport(
        url: &str,
        config: &ClientConfig,
    ) -> Result<Transport, ConnectionError> {
        use crate::transport::webtransport::WebTransportTransport;

        let wt_config = if config.skip_cert_verification {
            wtransport::ClientConfig::builder()
                .with_bind_default()
                .with_no_cert_validation()
                .build()
        } else {
            wtransport::ClientConfig::builder().with_bind_default().with_native_certs().build()
        };

        let endpoint = wtransport::Endpoint::client(wt_config)
            .map_err(|e| ConnectionError::Transport(TransportError::Connect(e.to_string())))?;

        let connection = endpoint
            .connect(url)
            .await
            .map_err(|e| ConnectionError::Transport(TransportError::Connect(e.to_string())))?;

        Ok(Transport::WebTransport(WebTransportTransport::new(connection)))
    }

    /// Stub for when the webtransport feature is not enabled.
    #[cfg(not(feature = "webtransport"))]
    async fn connect_webtransport(
        _url: &str,
        _config: &ClientConfig,
    ) -> Result<Transport, ConnectionError> {
        Err(ConnectionError::Transport(TransportError::Connect(
            "webtransport feature not enabled".into(),
        )))
    }

    // ── Observer ───────────────────────────────────────────────

    /// Attach an observer to receive connection events.
    pub fn set_observer(&mut self, observer: Box<dyn ConnectionObserver>) {
        self.observer = Some(observer);
    }

    /// Remove the observer.
    pub fn clear_observer(&mut self) {
        self.observer = None;
    }

    /// Emit an event to the observer, if one is attached.
    fn emit(&self, event: ClientEvent) {
        if let Some(ref obs) = self.observer {
            obs.on_event(&event);
        }
    }

    // ── Control message I/O ─────────────────────────────────

    /// Send a control message on the control stream.
    ///
    /// Wraps the draft-14 message in `AnyControlMessage::Draft14` for framing.
    pub async fn send_control(&mut self, msg: &ControlMessage) -> Result<(), ConnectionError> {
        let any = AnyControlMessage::Draft14(msg.clone());
        let send = self.control_send.as_mut().ok_or(ConnectionError::NoControlStream)?;
        send.write_control(&any).await?;
        self.emit(ClientEvent::ControlMessage { direction: Direction::Send, message: any });
        Ok(())
    }

    /// Read the next control message from the control stream.
    ///
    /// Returns the `AnyControlMessage` and also extracts the draft-14
    /// `ControlMessage` for internal endpoint dispatch.
    pub async fn recv_control(&mut self) -> Result<ControlMessage, ConnectionError> {
        let recv = self.control_recv.as_mut().ok_or(ConnectionError::NoControlStream)?;
        let any = recv.read_control().await?;
        self.emit(ClientEvent::ControlMessage {
            direction: Direction::Receive,
            message: any.clone(),
        });
        // Unwrap to draft-14 for the endpoint
        match any {
            AnyControlMessage::Draft14(msg) => Ok(msg),
            _ => Err(ConnectionError::Codec(CodecError::UnknownMessageType(0))),
        }
    }

    /// Read and dispatch the next incoming control message through the endpoint
    /// state machine. Returns the decoded message for inspection.
    pub async fn recv_and_dispatch(&mut self) -> Result<ControlMessage, ConnectionError> {
        let msg = self.recv_control().await?;
        self.endpoint.receive_message(msg.clone())?;

        // Emit draining event if this was a GoAway
        if let ControlMessage::GoAway(ref ga) = msg {
            self.emit(ClientEvent::Draining { new_session_uri: ga.new_session_uri.clone() });
        }

        Ok(msg)
    }

    // ── Subscribe flow ──────────────────────────────────────

    /// Send a SUBSCRIBE and return the allocated request ID.
    pub async fn subscribe(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        subscriber_priority: u8,
        group_order: GroupOrder,
        filter_type: FilterType,
    ) -> Result<VarInt, ConnectionError> {
        let (req_id, msg) = self.endpoint.subscribe(
            track_namespace,
            track_name,
            subscriber_priority,
            group_order,
            filter_type,
        )?;
        self.send_control(&msg).await?;
        Ok(req_id)
    }

    /// Send an UNSUBSCRIBE for the given request ID.
    pub async fn unsubscribe(&mut self, request_id: VarInt) -> Result<(), ConnectionError> {
        let msg = self.endpoint.unsubscribe(request_id)?;
        self.send_control(&msg).await
    }

    // ── Fetch flow ──────────────────────────────────────────

    /// Send a FETCH and return the allocated request ID.
    pub async fn fetch(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        start_group: VarInt,
        start_object: VarInt,
    ) -> Result<VarInt, ConnectionError> {
        let (req_id, msg) =
            self.endpoint.fetch(track_namespace, track_name, start_group, start_object)?;
        self.send_control(&msg).await?;
        Ok(req_id)
    }

    /// Send a FETCH_CANCEL for the given request ID.
    pub async fn fetch_cancel(&mut self, request_id: VarInt) -> Result<(), ConnectionError> {
        let msg = self.endpoint.fetch_cancel(request_id)?;
        self.send_control(&msg).await
    }

    // ── Namespace flows ─────────────────────────────────────

    /// Send a SUBSCRIBE_NAMESPACE and return the request ID.
    pub async fn subscribe_namespace(
        &mut self,
        track_namespace: TrackNamespace,
    ) -> Result<VarInt, ConnectionError> {
        let (req_id, msg) = self.endpoint.subscribe_namespace(track_namespace)?;
        self.send_control(&msg).await?;
        Ok(req_id)
    }

    /// Send a PUBLISH_NAMESPACE and return the request ID.
    pub async fn publish_namespace(
        &mut self,
        track_namespace: TrackNamespace,
    ) -> Result<VarInt, ConnectionError> {
        let (req_id, msg) = self.endpoint.publish_namespace(track_namespace)?;
        self.send_control(&msg).await?;
        Ok(req_id)
    }

    // ── Track Status flow ────────────────────────────────────

    /// Send a TRACK_STATUS and return the allocated request ID.
    pub async fn track_status(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
    ) -> Result<VarInt, ConnectionError> {
        let (req_id, msg) = self.endpoint.track_status(track_namespace, track_name)?;
        self.send_control(&msg).await?;
        Ok(req_id)
    }

    // ── Publish flow (publisher side) ───────────────────────

    /// Send a PUBLISH and return the allocated request ID.
    pub async fn publish(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        forward: Forward,
    ) -> Result<VarInt, ConnectionError> {
        let (req_id, msg) = self.endpoint.publish(track_namespace, track_name, forward)?;
        self.send_control(&msg).await?;
        Ok(req_id)
    }

    /// Send a PUBLISH_DONE for the given request ID.
    pub async fn publish_done(
        &mut self,
        request_id: VarInt,
        status_code: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<(), ConnectionError> {
        let msg = self.endpoint.send_publish_done(request_id, status_code, reason_phrase)?;
        self.send_control(&msg).await
    }

    // ── Data streams ────────────────────────────────────────

    /// Open a new unidirectional stream for sending subgroup data.
    pub async fn open_subgroup_stream(
        &self,
        header: &AnySubgroupHeader,
    ) -> Result<FramedSendStream, ConnectionError> {
        let send = self.transport.open_uni().await?;
        let mut framed = FramedSendStream::new(send, self.draft);
        framed.write_subgroup_header(header).await?;
        self.emit(ClientEvent::StreamOpened {
            direction: Direction::Send,
            stream_kind: StreamKind::Subgroup,
        });
        Ok(framed)
    }

    /// Accept an incoming unidirectional data stream and read its subgroup
    /// header.
    pub async fn accept_subgroup_stream(
        &self,
    ) -> Result<(AnySubgroupHeader, FramedRecvStream), ConnectionError> {
        let recv = self.transport.accept_uni().await?;
        let mut framed = FramedRecvStream::new(recv, self.draft);
        let header = framed.read_subgroup_header().await?;
        self.emit(ClientEvent::StreamOpened {
            direction: Direction::Receive,
            stream_kind: StreamKind::Subgroup,
        });
        Ok((header, framed))
    }

    /// Send an object via datagram.
    pub fn send_datagram(
        &self,
        header: &AnyDatagramHeader,
        payload: &[u8],
    ) -> Result<(), ConnectionError> {
        let mut buf = Vec::new();
        header.encode(&mut buf);
        buf.extend_from_slice(payload);
        self.transport.send_datagram(bytes::Bytes::from(buf))?;
        Ok(())
    }

    /// Receive a datagram and decode its header.
    pub async fn recv_datagram(&self) -> Result<(AnyDatagramHeader, Vec<u8>), ConnectionError> {
        let data = self.transport.recv_datagram().await?;
        let mut cursor = &data[..];
        let header = AnyDatagramHeader::decode(self.draft, &mut cursor)?;
        let payload = cursor.to_vec();
        Ok((header, payload))
    }

    // ── Accessors ───────────────────────────────────────────

    /// Access the underlying endpoint state machine.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Mutable access to the endpoint state machine.
    pub fn endpoint_mut(&mut self) -> &mut Endpoint {
        &mut self.endpoint
    }

    /// Get the negotiated MoQT version.
    pub fn negotiated_version(&self) -> Option<VarInt> {
        self.endpoint.negotiated_version()
    }

    /// Returns the draft version this connection is using.
    pub fn draft(&self) -> DraftVersion {
        self.draft
    }

    /// Close the connection.
    pub fn close(&self, code: u32, reason: &[u8]) {
        self.emit(ClientEvent::Closed { code, reason: reason.to_vec() });
        self.transport.close(code, reason);
    }
}

/// Determine the encoded length of a varint from its first byte.
fn varint_len(first_byte: u8) -> usize {
    1 << (first_byte >> 6)
}

/// TLS certificate verifier that skips all verification (for testing only).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_len_single_byte() {
        // 0b00xxxxxx -> 1 byte
        assert_eq!(varint_len(0x00), 1);
        assert_eq!(varint_len(0x3F), 1);
    }

    #[test]
    fn varint_len_two_bytes() {
        // 0b01xxxxxx -> 2 bytes
        assert_eq!(varint_len(0x40), 2);
        assert_eq!(varint_len(0x7F), 2);
    }

    #[test]
    fn varint_len_four_bytes() {
        // 0b10xxxxxx -> 4 bytes
        assert_eq!(varint_len(0x80), 4);
        assert_eq!(varint_len(0xBF), 4);
    }

    #[test]
    fn varint_len_eight_bytes() {
        // 0b11xxxxxx -> 8 bytes
        assert_eq!(varint_len(0xC0), 8);
        assert_eq!(varint_len(0xFF), 8);
    }

    #[test]
    fn client_config_supported_versions_draft14() {
        let config = ClientConfig {
            draft: DraftVersion::Draft14,
            transport: TransportType::Quic,
            skip_cert_verification: false,
            ca_certs: Vec::new(),
        };
        let versions = config.supported_versions();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].into_inner(), 0xff000000 + 14);
    }

    #[test]
    fn client_config_supported_versions_draft07() {
        let config = ClientConfig {
            draft: DraftVersion::Draft07,
            transport: TransportType::Quic,
            skip_cert_verification: false,
            ca_certs: Vec::new(),
        };
        let versions = config.supported_versions();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].into_inner(), 0xff000000 + 7);
    }

    #[test]
    fn client_config_alpn_quic() {
        let config = ClientConfig {
            draft: DraftVersion::Draft14,
            transport: TransportType::Quic,
            skip_cert_verification: false,
            ca_certs: Vec::new(),
        };
        assert_eq!(config.alpn(), vec![b"moq-00".to_vec()]);
    }

    #[test]
    fn client_config_alpn_webtransport() {
        let config = ClientConfig {
            draft: DraftVersion::Draft14,
            transport: TransportType::WebTransport { url: "https://example.com".to_string() },
            skip_cert_verification: false,
            ca_certs: Vec::new(),
        };
        assert_eq!(config.alpn(), vec![b"h3".to_vec()]);
    }

    #[test]
    fn moqt_alpn_value() {
        assert_eq!(MOQT_ALPN, b"moq-00");
    }

    #[test]
    fn transport_type_debug() {
        let quic = TransportType::Quic;
        assert!(format!("{quic:?}").contains("Quic"));

        let wt = TransportType::WebTransport { url: "https://example.com".to_string() };
        assert!(format!("{wt:?}").contains("WebTransport"));
    }
}

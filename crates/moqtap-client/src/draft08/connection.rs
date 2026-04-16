use std::sync::Arc;

use bytes::{Buf, Bytes, BytesMut};

use crate::draft08::endpoint::{Endpoint, EndpointError};
use crate::draft08::event::{ClientEvent, Direction, FetchObject, StreamKind, SubgroupObject};
use crate::draft08::observer::ConnectionObserver;
use crate::transport::quic::QuicTransport;
use crate::transport::{RecvStream, SendStream, Transport, TransportError};
use moqtap_codec::dispatch::{
    AnyControlMessage, AnyDatagramHeader, AnyFetchHeader, AnySubgroupHeader,
};
use moqtap_codec::draft08::data_stream::{FetchObjectHeader, ObjectHeader};
use moqtap_codec::draft08::message::ControlMessage;
use moqtap_codec::error::CodecError;
use moqtap_codec::types::*;
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

/// MoQT ALPN identifier (used by raw QUIC transport).
pub const MOQT_ALPN: &[u8] = b"moq-00";

/// Errors from the draft-08 connection layer.
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

/// Configuration for a draft-08 MoQT client connection.
pub struct ClientConfig {
    /// Additional draft versions to offer in CLIENT_SETUP (draft-08 is always
    /// offered first).
    pub additional_versions: Vec<DraftVersion>,
    /// The transport type (QUIC or WebTransport).
    pub transport: TransportType,
    /// Whether to skip TLS certificate verification (for testing).
    pub skip_cert_verification: bool,
    /// Custom CA certificates to trust (DER-encoded).
    pub ca_certs: Vec<Vec<u8>>,
    /// Setup parameters to include in CLIENT_SETUP (e.g., auth tokens).
    pub setup_parameters: Vec<moqtap_codec::kvp::KeyValuePair>,
}

impl ClientConfig {
    /// Returns the MoQT version varints for the CLIENT_SETUP message.
    /// Draft-08 first, then any additional versions.
    pub fn supported_versions(&self) -> Vec<VarInt> {
        let mut versions = vec![DraftVersion::Draft08.version_varint()];
        for v in &self.additional_versions {
            let varint = v.version_varint();
            if !versions.contains(&varint) {
                versions.push(varint);
            }
        }
        versions
    }

    /// Returns the ALPN protocol identifiers for the transport.
    pub fn alpn(&self) -> Vec<Vec<u8>> {
        match &self.transport {
            TransportType::Quic => vec![DraftVersion::Draft08.quic_alpn().to_vec()],
            TransportType::WebTransport { .. } => vec![b"h3".to_vec()],
        }
    }
}

/// A framed writer for a send stream. Handles MoQT length-prefixed framing.
pub struct FramedSendStream {
    inner: SendStream,
}

impl FramedSendStream {
    /// Create a new framed send stream.
    pub fn new(inner: SendStream) -> Self {
        Self { inner }
    }

    /// Get the transport-level stream ID.
    pub fn stream_id(&self) -> u64 {
        self.inner.stream_id()
    }

    /// Write a control message to the stream with type+length framing.
    /// Returns the raw bytes that were written (for event capture).
    pub async fn write_control(
        &mut self,
        msg: &AnyControlMessage,
    ) -> Result<Vec<u8>, ConnectionError> {
        let mut buf = Vec::new();
        msg.encode(&mut buf)?;
        self.inner.write_all(&buf).await?;
        Ok(buf)
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

    /// Append a draft-08 subgroup object (header + payload) to the stream.
    /// Draft-08 subgroup objects are stateless — no header-dependent bookkeeping.
    pub async fn write_subgroup_object(
        &mut self,
        object: &SubgroupObject,
    ) -> Result<(), ConnectionError> {
        let mut buf = Vec::new();
        object.header.encode(&mut buf);
        buf.extend_from_slice(&object.payload);
        self.inner.write_all(&buf).await?;
        Ok(())
    }

    /// Append a draft-08 fetch object (header + payload) to the stream.
    pub async fn write_fetch_object(
        &mut self,
        object: &FetchObject,
    ) -> Result<(), ConnectionError> {
        let mut buf = Vec::new();
        object.header.encode(&mut buf);
        buf.extend_from_slice(&object.payload);
        self.inner.write_all(&buf).await?;
        Ok(())
    }

    /// Finish the stream (send FIN).
    pub async fn finish(&mut self) -> Result<(), ConnectionError> {
        self.inner.finish()?;
        Ok(())
    }
}

/// A framed reader for a recv stream. Handles MoQT varint-length decoding.
pub struct FramedRecvStream {
    inner: RecvStream,
    buf: BytesMut,
}

impl FramedRecvStream {
    /// Create a new framed receive stream.
    pub fn new(inner: RecvStream) -> Self {
        Self { inner, buf: BytesMut::with_capacity(4096) }
    }

    /// Get the transport-level stream ID.
    pub fn stream_id(&self) -> u64 {
        self.inner.stream_id()
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
    ///
    /// When `capture_raw` is true, the returned tuple includes a clone of the
    /// framed wire bytes (for observer emission). When false, the second
    /// element is `None` and the payload clone is skipped.
    pub async fn read_control(
        &mut self,
        capture_raw: bool,
    ) -> Result<(AnyControlMessage, Option<Vec<u8>>), ConnectionError> {
        // Read type ID varint
        self.ensure(1).await?;
        let type_len = varint_len(self.buf[0]);
        self.ensure(type_len).await?;

        let mut cursor = &self.buf[..type_len];
        let _type_id = VarInt::decode(&mut cursor)?;

        // Draft-08 uses varint length framing.
        self.ensure(type_len + 1).await?;
        let payload_len_start = type_len;
        let payload_len_varint_len = varint_len(self.buf[payload_len_start]);
        self.ensure(type_len + payload_len_varint_len).await?;
        let mut cursor = &self.buf[payload_len_start..type_len + payload_len_varint_len];
        let payload_len = VarInt::decode(&mut cursor)?.into_inner() as usize;
        let len_field_size = payload_len_varint_len;

        // Read full payload
        let total = type_len + len_field_size + payload_len;
        self.ensure(total).await?;

        // Capture raw bytes only if requested (observer attached).
        let raw = capture_raw.then(|| self.buf[..total].to_vec());

        // Now decode the whole message using the draft-08 dispatcher
        let mut frame = &self.buf[..total];
        let msg = AnyControlMessage::decode(DraftVersion::Draft08, &mut frame)?;
        self.buf.advance(total);
        Ok((msg, raw))
    }

    /// Read a subgroup stream header.
    pub async fn read_subgroup_header(&mut self) -> Result<AnySubgroupHeader, ConnectionError> {
        self.ensure(1).await?;
        loop {
            let mut cursor = &self.buf[..];
            match AnySubgroupHeader::decode(DraftVersion::Draft08, &mut cursor) {
                Ok(header) => {
                    let consumed = self.buf.len() - cursor.remaining();
                    self.buf.advance(consumed);
                    return Ok(header);
                }
                Err(CodecError::UnexpectedEnd) => {
                    if !self.fill().await? {
                        return Err(ConnectionError::UnexpectedEnd);
                    }
                }
                Err(e) => return Err(ConnectionError::Codec(e)),
            }
        }
    }

    /// Read a fetch response header.
    pub async fn read_fetch_header(&mut self) -> Result<AnyFetchHeader, ConnectionError> {
        self.ensure(1).await?;
        loop {
            let mut cursor = &self.buf[..];
            match AnyFetchHeader::decode(DraftVersion::Draft08, &mut cursor) {
                Ok(header) => {
                    let consumed = self.buf.len() - cursor.remaining();
                    self.buf.advance(consumed);
                    return Ok(header);
                }
                Err(CodecError::UnexpectedEnd) => {
                    if !self.fill().await? {
                        return Err(ConnectionError::UnexpectedEnd);
                    }
                }
                Err(e) => return Err(ConnectionError::Codec(e)),
            }
        }
    }

    /// Read the next draft-08 subgroup object (header + payload). Since
    /// draft-08 subgroup objects are stateless, this does not require any
    /// prior header-decoding state.
    pub async fn read_subgroup_object(&mut self) -> Result<SubgroupObject, ConnectionError> {
        loop {
            let mut cursor = &self.buf[..];
            match ObjectHeader::decode(&mut cursor) {
                Ok(header) => {
                    let header_consumed = self.buf.len() - cursor.remaining();
                    let payload_len = header.payload_length.into_inner() as usize;
                    let total = header_consumed + payload_len;
                    if self.buf.len() < total {
                        if !self.fill().await? {
                            return Err(ConnectionError::UnexpectedEnd);
                        }
                        continue;
                    }
                    let payload = self.buf[header_consumed..total].to_vec();
                    self.buf.advance(total);
                    return Ok(SubgroupObject { header, payload });
                }
                Err(CodecError::UnexpectedEnd) => {
                    if !self.fill().await? {
                        return Err(ConnectionError::UnexpectedEnd);
                    }
                }
                Err(e) => return Err(ConnectionError::Codec(e)),
            }
        }
    }

    /// Read the next draft-08 fetch object (header + payload).
    pub async fn read_fetch_object(&mut self) -> Result<FetchObject, ConnectionError> {
        loop {
            let mut cursor = &self.buf[..];
            match FetchObjectHeader::decode(&mut cursor) {
                Ok(header) => {
                    let header_consumed = self.buf.len() - cursor.remaining();
                    let payload_len = header.payload_length.into_inner() as usize;
                    let total = header_consumed + payload_len;
                    if self.buf.len() < total {
                        if !self.fill().await? {
                            return Err(ConnectionError::UnexpectedEnd);
                        }
                        continue;
                    }
                    let payload = self.buf[header_consumed..total].to_vec();
                    self.buf.advance(total);
                    return Ok(FetchObject { header, payload });
                }
                Err(CodecError::UnexpectedEnd) => {
                    if !self.fill().await? {
                        return Err(ConnectionError::UnexpectedEnd);
                    }
                }
                Err(e) => return Err(ConnectionError::Codec(e)),
            }
        }
    }
}

/// A live draft-08 MoQT connection over QUIC or WebTransport.
pub struct Connection {
    transport: Transport,
    endpoint: Endpoint,
    control_send: Option<FramedSendStream>,
    control_recv: Option<FramedRecvStream>,
    observer: Option<Box<dyn ConnectionObserver>>,
}

impl Connection {
    /// Connect to a draft-08 MoQT server as a client.
    pub async fn connect(addr: &str, config: ClientConfig) -> Result<Self, ConnectionError> {
        let transport = match &config.transport {
            TransportType::Quic => Self::connect_quic(addr, &config).await?,
            TransportType::WebTransport { url } => {
                let url = url.clone();
                Self::connect_webtransport(&url, &config).await?
            }
        };

        // Open bidirectional control stream
        let (send, recv) = transport.open_bi().await?;
        let mut control_send = FramedSendStream::new(send);
        let mut control_recv = FramedRecvStream::new(recv);

        // Perform setup handshake
        let mut endpoint = Endpoint::new();
        endpoint.connect()?;
        let setup_msg = endpoint
            .send_client_setup(config.supported_versions(), config.setup_parameters.clone())?;
        let any_setup = AnyControlMessage::Draft08(setup_msg);
        let _raw_setup = control_send.write_control(&any_setup).await?;

        let (server_setup, _raw_server_setup) = control_recv.read_control(false).await?;
        match &server_setup {
            AnyControlMessage::Draft08(ControlMessage::ServerSetup(ref ss)) => {
                endpoint.receive_server_setup(ss)?;
            }
            _ => {
                return Err(ConnectionError::Endpoint(EndpointError::NotActive));
            }
        }

        let conn = Self {
            transport,
            endpoint,
            control_send: Some(control_send),
            control_recv: Some(control_recv),
            observer: None,
        };

        if let Some(v) = conn.endpoint.negotiated_version() {
            conn.emit(ClientEvent::SetupComplete { negotiated_version: v.into_inner() });
        }

        Ok(conn)
    }

    /// Establish a raw QUIC connection.
    async fn connect_quic(addr: &str, config: &ClientConfig) -> Result<Transport, ConnectionError> {
        let server_addr = addr.parse().map_err(|e: std::net::AddrParseError| {
            ConnectionError::InvalidAddress(e.to_string())
        })?;

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
            obs.on_event_owned(event);
        }
    }

    // ── Control message I/O ─────────────────────────────────

    /// Send a control message on the control stream.
    pub async fn send_control(&mut self, msg: &ControlMessage) -> Result<(), ConnectionError> {
        let any = AnyControlMessage::Draft08(msg.clone());
        let send = self.control_send.as_mut().ok_or(ConnectionError::NoControlStream)?;
        let raw = send.write_control(&any).await?;
        self.emit(ClientEvent::ControlMessage {
            direction: Direction::Send,
            message: any,
            raw: Some(raw),
        });
        Ok(())
    }

    /// Read the next control message from the control stream.
    pub async fn recv_control(&mut self) -> Result<ControlMessage, ConnectionError> {
        let recv = self.control_recv.as_mut().ok_or(ConnectionError::NoControlStream)?;
        let capture_raw = self.observer.is_some();
        let (any, raw) = recv.read_control(capture_raw).await?;
        if capture_raw {
            self.emit(ClientEvent::ControlMessage {
                direction: Direction::Receive,
                message: any.clone(),
                raw,
            });
        }
        match any {
            AnyControlMessage::Draft08(msg) => Ok(msg),
            _ => Err(ConnectionError::Codec(CodecError::UnknownMessageType(0))),
        }
    }

    /// Read and dispatch the next incoming control message through the endpoint
    /// state machine. Returns the decoded message for inspection.
    pub async fn recv_and_dispatch(&mut self) -> Result<ControlMessage, ConnectionError> {
        let msg = self.recv_control().await?;
        self.endpoint.receive_message(msg.clone())?;

        if let ControlMessage::GoAway(ref ga) = msg {
            self.emit(ClientEvent::Draining { new_session_uri: ga.new_session_uri.clone() });
        }

        Ok(msg)
    }

    // ── Subscribe flow ──────────────────────────────────────

    /// Send a SUBSCRIBE and return the allocated subscribe ID.
    #[allow(clippy::too_many_arguments)]
    pub async fn subscribe(
        &mut self,
        track_alias: VarInt,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        subscriber_priority: u8,
        group_order: GroupOrder,
        filter_type: FilterType,
    ) -> Result<VarInt, ConnectionError> {
        let (sub_id, msg) = self.endpoint.subscribe(
            track_alias,
            track_namespace,
            track_name,
            subscriber_priority,
            group_order,
            filter_type,
        )?;
        self.send_control(&msg).await?;
        Ok(sub_id)
    }

    /// Send an UNSUBSCRIBE for the given subscribe ID.
    pub async fn unsubscribe(&mut self, subscribe_id: VarInt) -> Result<(), ConnectionError> {
        let msg = self.endpoint.unsubscribe(subscribe_id)?;
        self.send_control(&msg).await
    }

    // ── Fetch flow ──────────────────────────────────────────

    /// Send a FETCH and return the allocated subscribe ID.
    #[allow(clippy::too_many_arguments)]
    pub async fn fetch(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        subscriber_priority: u8,
        group_order: GroupOrder,
        start_group: VarInt,
        start_object: VarInt,
        end_group: VarInt,
        end_object: VarInt,
    ) -> Result<VarInt, ConnectionError> {
        let (sub_id, msg) = self.endpoint.fetch(
            track_namespace,
            track_name,
            subscriber_priority,
            group_order,
            start_group,
            start_object,
            end_group,
            end_object,
        )?;
        self.send_control(&msg).await?;
        Ok(sub_id)
    }

    /// Send a FETCH_CANCEL for the given subscribe ID.
    pub async fn fetch_cancel(&mut self, subscribe_id: VarInt) -> Result<(), ConnectionError> {
        let msg = self.endpoint.fetch_cancel(subscribe_id)?;
        self.send_control(&msg).await
    }

    // ── Namespace flows ─────────────────────────────────────

    /// Send a SUBSCRIBE_ANNOUNCES.
    pub async fn subscribe_announces(
        &mut self,
        track_namespace_prefix: TrackNamespace,
    ) -> Result<(), ConnectionError> {
        let msg = self.endpoint.subscribe_announces(track_namespace_prefix)?;
        self.send_control(&msg).await
    }

    /// Send an ANNOUNCE.
    pub async fn announce(
        &mut self,
        track_namespace: TrackNamespace,
    ) -> Result<(), ConnectionError> {
        let msg = self.endpoint.announce(track_namespace)?;
        self.send_control(&msg).await
    }

    /// Send an UNANNOUNCE.
    pub async fn unannounce(
        &mut self,
        track_namespace: TrackNamespace,
    ) -> Result<(), ConnectionError> {
        let msg = self.endpoint.unannounce(track_namespace)?;
        self.send_control(&msg).await
    }

    // ── Track Status flow ────────────────────────────────────

    /// Send a TRACK_STATUS_REQUEST.
    pub async fn track_status_request(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
    ) -> Result<(), ConnectionError> {
        let msg = self.endpoint.track_status_request(track_namespace, track_name)?;
        self.send_control(&msg).await
    }

    // ── Data streams ────────────────────────────────────────

    /// Open a new unidirectional stream for sending subgroup data.
    pub async fn open_subgroup_stream(
        &self,
        header: &AnySubgroupHeader,
    ) -> Result<FramedSendStream, ConnectionError> {
        let send = self.transport.open_uni().await?;
        let mut framed = FramedSendStream::new(send);
        let sid = framed.stream_id();
        framed.write_subgroup_header(header).await?;
        self.emit(ClientEvent::StreamOpened {
            direction: Direction::Send,
            stream_kind: StreamKind::Subgroup,
            stream_id: sid,
        });
        self.emit(ClientEvent::DataStreamHeader {
            stream_id: sid,
            direction: Direction::Send,
            header: header.clone(),
        });
        Ok(framed)
    }

    /// Accept an incoming unidirectional data stream and read its subgroup
    /// header.
    pub async fn accept_subgroup_stream(
        &self,
    ) -> Result<(AnySubgroupHeader, FramedRecvStream), ConnectionError> {
        let recv = self.transport.accept_uni().await?;
        let mut framed = FramedRecvStream::new(recv);
        let sid = framed.stream_id();
        let header = framed.read_subgroup_header().await?;
        self.emit(ClientEvent::StreamOpened {
            direction: Direction::Receive,
            stream_kind: StreamKind::Subgroup,
            stream_id: sid,
        });
        self.emit(ClientEvent::DataStreamHeader {
            stream_id: sid,
            direction: Direction::Receive,
            header: header.clone(),
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
        self.emit(ClientEvent::DatagramReceived {
            direction: Direction::Send,
            header: header.clone(),
            payload_len: payload.len(),
        });
        self.transport.send_datagram(bytes::Bytes::from(buf))?;
        Ok(())
    }

    /// Receive a datagram and decode its header.
    pub async fn recv_datagram(&self) -> Result<(AnyDatagramHeader, Bytes), ConnectionError> {
        let data = self.transport.recv_datagram().await?;
        let mut cursor = &data[..];
        let header = AnyDatagramHeader::decode(DraftVersion::Draft08, &mut cursor)?;
        let consumed = data.len() - cursor.len();
        let payload = data.slice(consumed..);
        self.emit(ClientEvent::DatagramReceived {
            direction: Direction::Receive,
            header: header.clone(),
            payload_len: payload.len(),
        });
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
    fn client_config_supported_versions_default() {
        let config = ClientConfig {
            additional_versions: Vec::new(),
            transport: TransportType::Quic,
            skip_cert_verification: false,
            ca_certs: Vec::new(),
            setup_parameters: Vec::new(),
        };
        let versions = config.supported_versions();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].into_inner(), 0xff000000 + 8);
    }

    #[test]
    fn client_config_alpn_quic() {
        let config = ClientConfig {
            additional_versions: Vec::new(),
            transport: TransportType::Quic,
            skip_cert_verification: false,
            ca_certs: Vec::new(),
            setup_parameters: Vec::new(),
        };
        assert_eq!(config.alpn(), vec![DraftVersion::Draft08.quic_alpn().to_vec()]);
    }

    #[test]
    fn moqt_alpn_value() {
        assert_eq!(MOQT_ALPN, b"moq-00");
    }
}

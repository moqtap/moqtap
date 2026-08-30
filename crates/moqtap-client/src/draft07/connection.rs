use std::sync::Arc;

use bytes::{Buf, Bytes, BytesMut};

use crate::draft07::endpoint::{Endpoint, EndpointError, Role};
use crate::draft07::event::{ClientEvent, Direction, FetchObject, StreamKind, SubgroupObject};
use crate::draft07::observer::ConnectionObserver;
use crate::draft07::session::setup;
use crate::forwarding_preference::ObjectForwardingPreference;
use crate::transport::quic::QuicTransport;
use crate::transport::{RecvStream, SendStream, Transport, TransportError};
use moqtap_codec::dispatch::{
    AnyControlMessage, AnyDatagramHeader, AnyFetchHeader, AnySubgroupHeader,
};
use moqtap_codec::draft07::data_stream::{FetchObjectHeader, ObjectHeader};
use moqtap_codec::draft07::message::ControlMessage;
use moqtap_codec::error::CodecError;
use moqtap_codec::kvp::KeyValuePair;
use moqtap_codec::types::*;
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

/// MoQT ALPN identifier (used by raw QUIC transport).
pub const MOQT_ALPN: &[u8] = b"moq-00";

/// Errors from the draft-07 connection layer.
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
    /// Data stream used out of order: an object before its header, or an
    /// Object ID that does not advance on the last one written.
    #[error("data stream state error: {0}")]
    DataStreamState(&'static str),
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

/// Configuration for a draft-07 MoQT client connection.
pub struct ClientConfig {
    /// Additional draft versions to offer in CLIENT_SETUP (draft-07 is always
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
    /// Draft-07 first, then any additional versions.
    pub fn supported_versions(&self) -> Vec<VarInt> {
        let mut versions = vec![DraftVersion::Draft07.version_varint()];
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
            TransportType::Quic => vec![DraftVersion::Draft07.quic_alpn().to_vec()],
            TransportType::WebTransport { .. } => vec![b"h3".to_vec()],
        }
    }
}

/// A framed writer for a send stream. Handles MoQT length-prefixed framing.
pub struct FramedSendStream {
    inner: SendStream,
    /// The last Object ID written on this subgroup stream, once one has been.
    ///
    /// `None` before the first object; the outer `Option` is `None` until a
    /// subgroup header has been written, which is what makes an object sent
    /// before its header answerable rather than unframed bytes.
    subgroup_objects: Option<Option<u64>>,
}

impl FramedSendStream {
    /// Create a new framed send stream.
    pub fn new(inner: SendStream) -> Self {
        Self { inner, subgroup_objects: None }
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

    /// Write a subgroup stream header. Also opens the Object ID bookkeeping
    /// [`FramedSendStream::write_subgroup_object`] holds the stream to.
    ///
    /// Written through the checked encoder, which on this draft refuses
    /// nothing: SUBGROUP_HEADER has one shape here, every field goes out every
    /// time, and no type byte selects between them. The drafts that gained a
    /// header type table need the refusal, and one call site for all thirteen
    /// is what keeps this from being the draft where it was forgotten.
    pub async fn write_subgroup_header(
        &mut self,
        header: &AnySubgroupHeader,
    ) -> Result<(), ConnectionError> {
        let mut buf = Vec::new();
        header.encode_stream_checked(&mut buf)?;
        self.inner.write_all(&buf).await?;
        self.subgroup_objects = Some(None);
        Ok(())
    }

    /// Write a fetch response header.
    pub async fn write_fetch_header(
        &mut self,
        header: &AnyFetchHeader,
    ) -> Result<(), ConnectionError> {
        let mut buf = Vec::new();
        header.encode_stream(&mut buf);
        self.inner.write_all(&buf).await?;
        Ok(())
    }

    /// Append a draft-07 subgroup object (header + payload) to the stream.
    ///
    /// Section 7.3.1: "A publisher MUST NOT send an Object on a stream if its
    /// Object ID is less than a previously sent Object ID within a given group
    /// in that stream." A subgroup stream carries one group, so the Object IDs
    /// written here are exactly the ones that sentence compares, and the
    /// comparison needs the object before - which no per-header check can see.
    /// The state advances only once the object has been written, so declining to
    /// write an object leaves the next one measured against the last one kept.
    ///
    /// An equal Object ID is refused as well as a smaller one. The draft's own
    /// sentence forbids only "less than", but an Object ID names an Object
    /// within a Group: writing one twice on a stream describes the same Object
    /// with two different payloads, and a reader has no way to choose. The
    /// dispatch-level writer in the codec draws the line in the same place, and
    /// two writers that disagreed about it would be worse than either answer.
    ///
    /// # Errors
    ///
    /// [`ConnectionError::DataStreamState`] if no subgroup header has been
    /// written yet, or if `object` does not advance past the last one written.
    pub async fn write_subgroup_object(
        &mut self,
        object: &SubgroupObject,
    ) -> Result<(), ConnectionError> {
        let previous = self
            .subgroup_objects
            .as_mut()
            .ok_or(ConnectionError::DataStreamState("subgroup header not written yet"))?;
        let object_id = object.header.object_id.into_inner();
        if matches!(*previous, Some(prev) if object_id <= prev) {
            return Err(ConnectionError::DataStreamState(
                "object id does not advance on the last one written to this stream",
            ));
        }
        // The declared length comes from the payload rather than from the
        // caller's field: a header that disagrees with the bytes beside it
        // desynchronises every object after it on the stream, and nothing
        // downstream can recover.
        let mut header = object.header.clone();
        header.payload_length = VarInt::from_usize(object.payload.len());
        let mut buf = Vec::new();
        header.encode_checked(&mut buf)?;
        buf.extend_from_slice(&object.payload);
        self.inner.write_all(&buf).await?;
        *previous = Some(object_id);
        Ok(())
    }

    /// Append a draft-07 fetch object (header + payload) to the stream.
    pub async fn write_fetch_object(
        &mut self,
        object: &FetchObject,
    ) -> Result<(), ConnectionError> {
        // The declared length comes from the payload rather than from the
        // caller's field: a header that disagrees with the bytes beside it
        // desynchronises every object after it on the stream, and nothing
        // downstream can recover.
        let mut header = object.header.clone();
        header.payload_length = VarInt::from_usize(object.payload.len());
        let mut buf = Vec::new();
        header.encode_checked(&mut buf)?;
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

        // Draft-07 uses varint length framing.
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

        // Now decode the whole message using the draft-07 dispatcher
        let mut frame = &self.buf[..total];
        let msg = AnyControlMessage::decode(DraftVersion::Draft07, &mut frame)?;
        self.buf.advance(total);
        Ok((msg, raw))
    }

    /// Read a subgroup stream header.
    pub async fn read_subgroup_header(&mut self) -> Result<AnySubgroupHeader, ConnectionError> {
        self.ensure(1).await?;
        loop {
            let mut cursor = &self.buf[..];
            match AnySubgroupHeader::decode_stream(DraftVersion::Draft07, &mut cursor) {
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
            match AnyFetchHeader::decode_stream(DraftVersion::Draft07, &mut cursor) {
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

    /// Read the next draft-07 subgroup object (header + payload). Since
    /// draft-07 subgroup objects are stateless, this does not require any
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

    /// Read the next draft-07 fetch object (header + payload).
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

/// A live draft-07 MoQT connection over QUIC or WebTransport.
pub struct Connection {
    transport: Transport,
    endpoint: Endpoint,
    control_send: Option<FramedSendStream>,
    control_recv: Option<FramedRecvStream>,
    observer: Option<Box<dyn ConnectionObserver>>,
    /// Setup events buffered during `connect()` and replayed when an
    /// observer attaches via `set_observer` — without this, an observer
    /// attached after `connect` returns would never see the handshake.
    pending_events: Vec<ClientEvent>,
}

impl Connection {
    /// Connect to a draft-07 MoQT server as a client.
    pub async fn connect(addr: &str, config: ClientConfig) -> Result<Self, ConnectionError> {
        // PATH is for native QUIC only, and the transport is known here and
        // nowhere further in. Refusing before dialling means a session that
        // the server would close on sight is never opened.
        setup::validate_client_path_transport(
            &config.setup_parameters,
            matches!(config.transport, TransportType::WebTransport { .. }),
        )
        .map_err(EndpointError::from)?;

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
        let mut endpoint = Endpoint::new(Role::Client);
        endpoint.connect()?;
        let setup_msg = endpoint
            .send_client_setup(config.supported_versions(), config.setup_parameters.clone())?;
        let any_setup = AnyControlMessage::Draft07(setup_msg);
        let raw_setup = control_send.write_control(&any_setup).await?;

        let (server_setup, raw_server_setup) = control_recv.read_control(true).await?;
        match &server_setup {
            AnyControlMessage::Draft07(ControlMessage::ServerSetup(ref ss)) => {
                endpoint.receive_server_setup(ss)?;
            }
            _ => {
                return Err(ConnectionError::Endpoint(EndpointError::NotActive));
            }
        }

        let mut pending_events = Vec::with_capacity(3);
        pending_events.push(ClientEvent::ControlMessage {
            direction: Direction::Send,
            message: any_setup,
            raw: Some(raw_setup),
        });
        pending_events.push(ClientEvent::ControlMessage {
            direction: Direction::Receive,
            message: server_setup,
            raw: raw_server_setup,
        });
        if let Some(v) = endpoint.negotiated_version() {
            pending_events.push(ClientEvent::SetupComplete { negotiated_version: v.into_inner() });
        }

        Ok(Self {
            transport,
            endpoint,
            control_send: Some(control_send),
            control_recv: Some(control_recv),
            observer: None,
            pending_events,
        })
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

    /// Attach an observer. Buffered handshake events from `connect()` are
    /// flushed in arrival order before this returns.
    pub fn set_observer(&mut self, observer: Box<dyn ConnectionObserver>) {
        self.observer = Some(observer);
        for event in self.pending_events.drain(..) {
            if let Some(ref obs) = self.observer {
                obs.on_event_owned(event);
            }
        }
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
        let any = AnyControlMessage::Draft07(msg.clone());
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
        let (any, raw) = match recv.read_control(capture_raw).await {
            Ok(v) => v,
            Err(e) => return Err(self.close_for_codec(e)),
        };
        if capture_raw {
            self.emit(ClientEvent::ControlMessage {
                direction: Direction::Receive,
                message: any.clone(),
                raw,
            });
        }
        match any {
            AnyControlMessage::Draft07(msg) => Ok(msg),
            // `AnyControlMessage` carries one variant per enabled draft feature.
            // When draft 07 is the only one enabled the arm above is exhaustive
            // and this rejection arm is unreachable, so it is compiled only for
            // builds in which another draft's variant can actually turn up.
            #[cfg(any(
                feature = "draft08",
                feature = "draft09",
                feature = "draft10",
                feature = "draft11",
                feature = "draft12",
                feature = "draft13",
                feature = "draft14",
                feature = "draft15",
                feature = "draft16",
                feature = "draft17",
                feature = "draft18",
                feature = "draft19"
            ))]
            _ => Err(ConnectionError::Codec(CodecError::UnknownMessageType(0))),
        }
    }

    /// Read and dispatch the next incoming control message through the endpoint
    /// state machine. Returns the decoded message for inspection.
    pub async fn recv_and_dispatch(&mut self) -> Result<ControlMessage, ConnectionError> {
        let msg = self.recv_control().await?;
        self.endpoint.receive_message(msg.clone()).map_err(|e| self.close_if_session_fatal(e))?;

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

    /// Send a SUBSCRIBE for a range of the track and return the allocated ID.
    ///
    /// The Filter Type comes from the arguments, so the message cannot name a
    /// filter whose fields it does not carry.
    #[allow(clippy::too_many_arguments)]
    pub async fn subscribe_range(
        &mut self,
        track_alias: VarInt,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        subscriber_priority: u8,
        group_order: GroupOrder,
        start_location: Location,
        end_location: Option<Location>,
    ) -> Result<VarInt, ConnectionError> {
        let (sub_id, msg) = self.endpoint.subscribe_range(
            track_alias,
            track_namespace,
            track_name,
            subscriber_priority,
            group_order,
            start_location,
            end_location,
        )?;
        self.send_control(&msg).await?;
        Ok(sub_id)
    }

    /// Send an UNSUBSCRIBE for the given subscribe ID.
    pub async fn unsubscribe(&mut self, subscribe_id: VarInt) -> Result<(), ConnectionError> {
        let msg = self.endpoint.unsubscribe(subscribe_id)?;
        self.send_control(&msg).await
    }

    /// Accept a subscription the peer opened, sending SUBSCRIBE_OK.
    pub async fn subscribe_ok(
        &mut self,
        subscribe_id: VarInt,
        expires: VarInt,
        group_order: GroupOrder,
        parameters: Vec<KeyValuePair>,
    ) -> Result<(), ConnectionError> {
        let msg =
            self.endpoint.send_subscribe_ok(subscribe_id, expires, group_order, parameters)?;
        self.send_control(&msg).await
    }

    /// Reject a subscription the peer opened, sending SUBSCRIBE_ERROR.
    ///
    /// The Track Alias travels back with the refusal: under the 'Retry Track
    /// Alias' code it is the alias the peer should try again with, and under
    /// any other code it is ignored.
    pub async fn subscribe_error(
        &mut self,
        subscribe_id: VarInt,
        error_code: VarInt,
        reason_phrase: Vec<u8>,
        track_alias: VarInt,
    ) -> Result<(), ConnectionError> {
        let msg = self.endpoint.send_subscribe_error(
            subscribe_id,
            error_code,
            reason_phrase,
            track_alias,
        )?;
        self.send_control(&msg).await
    }

    /// End a subscription this endpoint accepted, sending SUBSCRIBE_DONE.
    pub async fn subscribe_done(
        &mut self,
        subscribe_id: VarInt,
        status_code: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<(), ConnectionError> {
        let msg = self.endpoint.send_subscribe_done(subscribe_id, status_code, reason_phrase)?;
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

    /// Accept a fetch the peer opened, sending FETCH_OK.
    ///
    /// The endpoint refuses a Joining Fetch naming a subscription this session
    /// cannot join and refuses a second answer to one FETCH, so nothing is
    /// written on the wire when it does either.
    pub async fn fetch_ok(
        &mut self,
        subscribe_id: VarInt,
        group_order: GroupOrder,
        end_of_track: u8,
        largest_group_id: Option<VarInt>,
        largest_object_id: Option<VarInt>,
        parameters: Vec<KeyValuePair>,
    ) -> Result<(), ConnectionError> {
        let msg = self.endpoint.send_fetch_ok(
            subscribe_id,
            group_order,
            end_of_track,
            largest_group_id,
            largest_object_id,
            parameters,
        )?;
        self.send_control(&msg).await
    }

    /// Refuse a fetch the peer opened, sending FETCH_ERROR.
    ///
    /// The endpoint refuses a second answer to one FETCH, so nothing is
    /// written on the wire when it does.
    pub async fn fetch_error(
        &mut self,
        subscribe_id: VarInt,
        error_code: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<(), ConnectionError> {
        let msg = self.endpoint.send_fetch_error(subscribe_id, error_code, reason_phrase)?;
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

    /// Accept a namespace subscription the peer made, sending SUBSCRIBE_ANNOUNCES_OK.
    ///
    /// The endpoint refuses a second answer to one SUBSCRIBE_ANNOUNCES, so nothing is
    /// written on the wire when it does.
    pub async fn subscribe_announces_ok(
        &mut self,
        track_namespace_prefix: TrackNamespace,
    ) -> Result<(), ConnectionError> {
        let msg = self.endpoint.send_subscribe_announces_ok(track_namespace_prefix)?;
        self.send_control(&msg).await
    }

    /// Refuse a namespace subscription the peer made, sending SUBSCRIBE_ANNOUNCES_ERROR.
    ///
    /// The other half of the same sentence: one answer, and this is the other
    /// one it can be.
    pub async fn subscribe_announces_error(
        &mut self,
        track_namespace_prefix: TrackNamespace,
        error_code: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<(), ConnectionError> {
        let msg = self.endpoint.send_subscribe_announces_error(
            track_namespace_prefix,
            error_code,
            reason_phrase,
        )?;
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

    /// Accept an announcement the peer made, sending ANNOUNCE_OK.
    ///
    /// The endpoint refuses a second answer to one ANNOUNCE, so nothing is
    /// written on the wire when it does.
    pub async fn announce_ok(
        &mut self,
        track_namespace: TrackNamespace,
    ) -> Result<(), ConnectionError> {
        let msg = self.endpoint.send_announce_ok(track_namespace)?;
        self.send_control(&msg).await
    }

    /// Refuse an announcement the peer made, sending ANNOUNCE_ERROR.
    ///
    /// The other half of the same sentence: one answer, and this is the other
    /// one it can be.
    pub async fn announce_error(
        &mut self,
        track_namespace: TrackNamespace,
        error_code: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<(), ConnectionError> {
        let msg = self.endpoint.send_announce_error(track_namespace, error_code, reason_phrase)?;
        self.send_control(&msg).await
    }

    /// Revoke an acceptance, sending ANNOUNCE_CANCEL.
    ///
    /// The endpoint refuses one for an announcement it never accepted, so
    /// nothing is written on the wire when it does.
    pub async fn announce_cancel(
        &mut self,
        track_namespace: TrackNamespace,
        error_code: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<(), ConnectionError> {
        let msg = self.endpoint.announce_cancel(track_namespace, error_code, reason_phrase)?;
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

    /// Answer a TRACK_STATUS_REQUEST the peer sent, sending TRACK_STATUS.
    ///
    /// The endpoint refuses a second answer to one request, so nothing is
    /// written on the wire when it does.
    pub async fn track_status(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        status_code: VarInt,
        last_group_id: VarInt,
        last_object_id: VarInt,
    ) -> Result<(), ConnectionError> {
        let msg = self.endpoint.send_track_status(
            track_namespace,
            track_name,
            status_code,
            last_group_id,
            last_object_id,
        )?;
        self.send_control(&msg).await
    }

    // ── Data streams ────────────────────────────────────────

    /// Open a new unidirectional stream for sending subgroup data.
    pub async fn open_subgroup_stream(
        &self,
        header: &AnySubgroupHeader,
    ) -> Result<FramedSendStream, ConnectionError> {
        // Before the stream is opened: the Original Publisher is who the rule
        // binds, so a header that would mix this track's framing is refused
        // here rather than written and answered by the peer.
        self.endpoint.note_object_forwarding_preference(
            header.track_alias(),
            ObjectForwardingPreference::Subgroup,
        )?;
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

    /// Open a new unidirectional stream for sending a FETCH's objects.
    ///
    /// The objects answering a FETCH do not go on the request's own stream:
    /// they go on a unidirectional stream of their own, which opens with a
    /// FETCH_HEADER naming the request they belong to. This writes that header
    /// and hands back the stream, the same way
    /// [`open_subgroup_stream`](Self::open_subgroup_stream) does for a
    /// subgroup.
    ///
    /// The caller owns the stream that comes back. Nothing here remembers
    /// which request it belongs to, so an endpoint serving several fetches at
    /// once keeps its own map from Request ID to stream.
    pub async fn open_fetch_stream(
        &self,
        header: &AnyFetchHeader,
    ) -> Result<FramedSendStream, ConnectionError> {
        let send = self.transport.open_uni().await?;
        let mut framed = FramedSendStream::new(send);
        let sid = framed.stream_id();
        framed.write_fetch_header(header).await?;
        self.emit(ClientEvent::StreamOpened {
            direction: Direction::Send,
            stream_kind: StreamKind::Fetch,
            stream_id: sid,
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
        // Every object on a subgroup stream has the Subgroup preference, so
        // the header settles the track's framing before a single object is
        // read.
        self.endpoint.note_object_forwarding_preference(
            header.track_alias(),
            ObjectForwardingPreference::Subgroup,
        )?;
        Ok((header, framed))
    }

    /// Send an object via datagram.
    ///
    /// The header goes through `AnyDatagramHeader::encode`, which refuses a
    /// header whose Object Status the framing it names cannot carry. Such a
    /// header errors here and nothing is sent, rather than going out as an
    /// ordinary payload datagram with the status quietly dropped.
    pub fn send_datagram(
        &self,
        header: &AnyDatagramHeader,
        payload: &[u8],
    ) -> Result<(), ConnectionError> {
        // Before anything is encoded, for the reason `open_subgroup_stream`
        // gives.
        self.endpoint.note_object_forwarding_preference(
            header.meta().track_alias,
            ObjectForwardingPreference::Datagram,
        )?;
        let mut buf = Vec::new();
        header.encode(&mut buf)?;
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
        let header = AnyDatagramHeader::decode(DraftVersion::Draft07, &mut cursor)?;
        let consumed = data.len() - cursor.len();
        let payload = data.slice(consumed..);
        self.emit(ClientEvent::DatagramReceived {
            direction: Direction::Receive,
            header: header.clone(),
            payload_len: payload.len(),
        });
        // A datagram is the other framing, and it settles the track's just as a
        // subgroup header does.
        self.endpoint.note_object_forwarding_preference(
            header.meta().track_alias,
            ObjectForwardingPreference::Datagram,
        )?;
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

    /// The code to close the session with when a message could not be decoded
    /// because the peer broke a rule draft-07 answers with a close.
    ///
    /// Every variant listed here comes from a sentence in this draft that names
    /// the consequence, and the list is per draft: answering a bound this draft
    /// does not state would close a session over traffic a conforming peer may
    /// send. This draft's list is the shortest of the thirteen and shares only
    /// two entries with draft-08's, which sits next to it.
    ///
    ///   - Duplicate parameters, a SHOULD rather than a MUST: "Receivers SHOULD
    ///     check that there are no duplicate parameters and close the session as
    ///     a 'Protocol Violation' if found." Unqualified here, as on drafts 08
    ///     through 10: there is no carve-out for repeats a message authorizes
    ///     and none for duplicates of unknown parameters, both of which arrive
    ///     at draft-11 and make the rule asymmetric there.
    ///   - Unknown control message type: "An endpoint that receives an unknown
    ///     message type MUST close the session." The sentence names no code, so
    ///     Protocol Violation is what carries it, as on every other draft.
    ///   - A parameter whose value does not match the length its type implies —
    ///     the one rule here **not** answered with a Protocol Violation: "If a
    ///     receiver understands a parameter type, and the parameter length
    ///     implied by that type does not match the Parameter Length field, the
    ///     receiver MUST terminate the session with error code 'Parameter Length
    ///     Mismatch'." Drafts 08, 09 and 10 carry the same sentence; drafts 11
    ///     and later drop it along with the Parameter framing it describes.
    ///
    /// **Not** the Track Namespace tuple size, and this is where draft-07 parts
    /// company with every draft above it. Section 2.3 states the range — "an
    /// ordered N-tuple of bytes where N can be between 1 and 32" — and stops
    /// there. It is draft-08 Section 2.4.1 that adds the consequence: "If an
    /// endpoint receives a Track Namespace tuple with an N of 0 or more than
    /// 32, it MUST close the session with a Protocol Violation." A tuple of 40
    /// fields is malformed on this draft and the session survives it, so the
    /// codec does not raise the variant here and this table would have nothing
    /// to answer if it did.
    ///
    /// **Not** the Reason Phrase maximum, the GOAWAY New Session URI maximum,
    /// the Full Track Name maximum or the parameter value maximum. Those enter
    /// the specification at draft-11 and this draft states none of them.
    ///
    /// **Not** the end-of-track Object ID rule either, which drafts 08, 09 and
    /// 10 do state: this draft assigns no Object Status 0x5 for it to be about.
    ///
    /// **Not** [`CodecError::UnexpectedEnd`], which reports no rule at all: the
    /// reader raises it whenever a message is still arriving, and
    /// `read_control` loops on it. Closing over it would end a session on an
    /// ordinary short read.
    ///
    /// **Not** the key-value pair serialization rule. Drafts 11 and later
    /// require a close with KEY_VALUE_FORMATTING_ERROR when a value does not
    /// match the serialization its Type defines; this draft has no Key-Value
    /// Pair at all. What it states instead is the Parameter Length Mismatch
    /// rule above, over the Parameter framing it has in its place.
    ///
    /// **Not** the unknown Message Parameter rule, which enters at draft-16 and
    /// requires a close for a Message Parameter type the negotiated version does
    /// not define. This draft states nothing of the kind, and its parameters are
    /// not Key-Value-Pairs at all.
    ///
    /// `None` for everything else, including [`CodecError::InvalidField`]. That
    /// variant is shared by a dozen unrelated malformations, only some of which
    /// the draft answers with a close, so a session cannot be ended on it
    /// without ending sessions the draft does not ask to be ended. Two of this
    /// draft's own rules are stuck behind it — an unknown data stream type, and
    /// a ContentExists field holding anything but 0 or 1, both of which this
    /// draft calls a protocol error. Splitting it is the way to bring them
    /// under this function; widening the match is not.
    fn codec_session_error_code(
        err: &CodecError,
    ) -> Option<moqtap_codec::draft07::error_codes::SessionErrorCode> {
        use moqtap_codec::draft07::error_codes::SessionErrorCode;
        use moqtap_codec::kvp::KvpError;
        match err {
            // The declared Length disagreeing with the fields, which every
            // draft answers with a close. Drafts 07 through 10 name no code for
            // it, so it takes the one their other unnamed rules take.
            CodecError::ControlMessageLengthMismatch { .. } => {
                Some(SessionErrorCode::ProtocolViolation)
            }
            // A Content Exists field that is neither zero nor one, Sections
            // 6.15 and 6.19: "Any other value is a protocol error and MUST
            // terminate the session with a Protocol Violation". Drafts 08
            // through 14 carry the field and the same sentence; draft-15 is
            // where it goes.
            CodecError::InvalidContentExists(_) => Some(SessionErrorCode::ProtocolViolation),
            CodecError::DuplicateParameter(_) | CodecError::UnknownMessageType(_) => {
                Some(SessionErrorCode::ProtocolViolation)
            }
            CodecError::ParameterLengthMismatch(_) => {
                Some(SessionErrorCode::ParameterLengthMismatch)
            }
            // An unknown data-plane type, Section 7: "An endpoint that
            // receives an unknown stream type MUST close the session." Draft-07
            // numbers its streams and its datagrams in one table, so the stream
            // variant carries both and the datagram variant never arrives here.
            CodecError::UnknownStreamType(_) | CodecError::UnknownDatagramType(_) => {
                Some(SessionErrorCode::ProtocolViolation)
            }
            // Everything this draft does not answer, named rather than swept up
            // by a wildcard. The arm is exhaustive deliberately: a new
            // `CodecError` variant will not compile until it has been placed on
            // one side or the other, on this draft, which is the decision a `_`
            // arm makes silently and invisibly on all thirteen at once.
            //
            // Adding one variant to `CodecError` was tried, and produces
            // thirteen `E0004`s, one per draft, each naming the variant that has
            // nowhere to go. That is the whole mechanism.
            //
            // The nesting stops at `VarInt`, whose variants report how the bytes
            // ran out rather than a rule an endpoint states, so there is nothing
            // in it for a draft to answer. `Kvp` is spelled out because it does
            // carry one.
            // Not `InvalidForward`: draft-07 has no Forward field. Not
            // `ParameterValueOutOfRange`: no parameter this draft defines
            // restricts its value's range. Both arrive with drafts above.
            CodecError::InvalidForward(_)
            | CodecError::ParameterValueOutOfRange { .. }
            | CodecError::UnexpectedEnd
            | CodecError::MessageTooLong(_)
            | CodecError::VarInt(_)
            | CodecError::InvalidField
            | CodecError::InvalidNamespaceTupleSize(_)
            | CodecError::EmptyNamespaceField
            | CodecError::TrackNameTooLong
            | CodecError::InvalidRange(..)
            | CodecError::EndOfTrackObjectId(_)
            | CodecError::KeyDeltaOverflow(..)
            // Not `TrackPropertyValueOutOfRange`: this draft has neither
            // namespace the variant is about. Draft-16 opens an extension header
            // registry with value rules of its own, and draft-17 renames it to
            // the Track Property registry. Before that, everything with a
            // restricted range is either a message field or a Message Parameter.
            | CodecError::TrackPropertyValueOutOfRange { .. }
            | CodecError::ParametersOutOfOrder(..)
            | CodecError::ObjectIdOverflow(..)
            | CodecError::ExtensionsOnNonExistentObject(_)
            | CodecError::InvalidRequiredRequestIdDelta(..)
            | CodecError::InvalidTypeValue { .. }
            | CodecError::ReasonPhraseTooLong
            | CodecError::GoAwayUriTooLong
            | CodecError::KeyValueFormatting { .. }
            | CodecError::UnknownMessageParameter(_)
            // Not `ParameterOutOfScope`: this draft states the scope rule and
            // answers it the other way. Section 6.1.1 Version Specific Parameters: "Each
            // version-specific parameter definition indicates the message types in which it can
            // appear. If it appears in some other type of message, it MUST be
            // ignored." The codec carries such a parameter on this draft and never
            // raises the variant, so this arm records a rule this draft has and
            // does not close over, not one it is missing. Draft-17 is where the
            // second sentence becomes a close.
            | CodecError::ParameterOutOfScope { .. }
            // A Filter Type outside the set this draft assigns. Section 6.4
            // states the rule and stops there: "A filter type other than the
            // above MUST be treated as error." No code, no close, and no
            // sentence elsewhere in the draft that turns an error into one — so
            // the message is refused and the session stays open.
            // Draft-14 Section 9.7 is where the same sentence gained "MUST be
            // close the session with PROTOCOL_VIOLATION", and it is answered
            // there.
            //
            // The assigned set is not the same on every draft either: 07 and 08
            // assign 0x1 as Latest Group, 09 and 10 withdraw it, and 11 and
            // later reinstate it as Next Group Start. The decoder holds each
            // draft to its own list; this arm only decides what a refusal does
            // to the session.
            //
            // The two rules below belong to the parameter form of the filter,
            // which arrives at draft-15. This draft carries the Filter Type as a
            // field of SUBSCRIBE, so there is no parameter for either to be
            // about.
            | CodecError::InvalidFilterType(_)
            | CodecError::SubscriptionFilterMalformed { .. }
            | CodecError::FilterEndGroupOverflow { .. }
            // Draft-07's FETCH (Section 6.7) carries no Fetch Type field at all:
            // every fetch on this draft is the standalone form, with a start and
            // an end and nothing to select between them. Draft-08 introduced the
            // field and the rule, and drafts 14 and later answer it with a close.
            | CodecError::InvalidFetchType(_)
            // The object payload rule, Section 7.1.1.1: "Any object with a status
            // code other than zero MUST have an empty payload." A MUST on the
            // sender with no receiver action named anywhere — the "SHOULD be
            // treated as a protocol error" in the same paragraph belongs to the
            // sentence before it, which is about a status value this draft does
            // not assign — so an object carrying a payload it may not is refused
            // and the session stays open.
            //
            // That was already the answer. The bytes used to arrive as
            // `InvalidField`, which is on this side too; naming the rule changes
            // nothing a peer can observe and makes the decision legible.
            | CodecError::PayloadNotPermitted { .. }
            | CodecError::UnsupportedDraft(_)
            | CodecError::Kvp(
                KvpError::ValueTooLong(_)
                | KvpError::MissingLength
                | KvpError::UnexpectedEnd
                | KvpError::VarInt(_),
            ) => None,
        }
    }

    /// Close the session on the wire when a decode failure is one draft-07
    /// answers with a close, and hand the error back unchanged.
    /// Without it every bound the decoder enforces would stop at *this endpoint
    /// refused the frame* while the peer, which is the one that broke the rule,
    /// saw a session that was still open and went on sending. "MUST close the
    /// session" is a statement about the wire.
    fn close_for_codec(&self, err: ConnectionError) -> ConnectionError {
        if let ConnectionError::Codec(inner) = &err {
            if let Some(code) = Self::codec_session_error_code(inner) {
                // QUIC application error codes are 62-bit; every code in this
                // registry is far below `u32::MAX`, and saturating rather than
                // truncating means a future code that is not could never be
                // reported as a different, assigned one.
                let wire_code = u32::try_from(code.as_u64()).unwrap_or(u32::MAX);
                self.close(wire_code, inner.to_string().as_bytes());
            }
        }
        err
    }

    /// Close the session on the wire when the endpoint says a violation is
    /// fatal to it, and hand the error back unchanged.
    ///
    /// [`EndpointError::session_error_code`] answers `Some` for exactly the
    /// errors this draft ends the session over, and the endpoint has already
    /// moved its own state machine to Closed by the time this runs. Without
    /// this step that move is purely internal: the local endpoint refuses to
    /// start anything new while the peer, which is the one that broke the
    /// rule, sees a session that is still open and goes on sending. A rule
    /// that names a session termination code is a statement about the wire,
    /// so it takes a CONNECTION_CLOSE to satisfy it.
    ///
    /// The reason phrase is the error's own `Display` text, which names the
    /// rule rather than repeating the numeric code the close already carries.
    ///
    /// Errors that answer `None` are recoverable and nothing is sent.
    fn close_for(&self, err: &EndpointError) {
        if let Some(code) = err.session_error_code() {
            // QUIC application error codes are 62-bit; every code in this
            // registry is far below `u32::MAX`, and saturating rather than
            // truncating means a future code that is not could never be
            // reported as a different, assigned one.
            let wire_code = u32::try_from(code.as_u64()).unwrap_or(u32::MAX);
            self.close(wire_code, err.to_string().as_bytes());
        }
    }

    /// [`close_for`](Self::close_for), then the error unchanged, for the
    /// common case where the endpoint's error is also what the caller returns.
    fn close_if_session_fatal(&self, err: EndpointError) -> ConnectionError {
        self.close_for(&err);
        ConnectionError::Endpoint(err)
    }

    /// Close the session over a rule broken on a data stream, reporting whether
    /// it did.
    ///
    /// A data stream cannot close for itself the way `recv_control` does:
    /// [`Connection::accept_subgroup_stream`] hands the caller a
    /// [`FramedRecvStream`] holding no connection, so the reader that finds the
    /// violation is not the object that can act on it. Keeping it a separate
    /// call is deliberate as well — a permissive caller, one reproducing a
    /// capture, can read a violating stream and report it without tearing the
    /// session down.
    ///
    /// The rule this draft answers here is the unknown stream type, Section 7,
    /// which arrives as the very first varint on a unidirectional stream and
    /// nowhere else. Every draft from 07 to 19 states it, in one of two
    /// phrasings — this one names streams alone because draft-07 numbers its
    /// datagrams in the same table, and drafts 08 through 16,
    /// draft-08 Section 8 among them, say "an unknown stream or datagram type"
    /// for the two tables they split it into. It shares
    /// `codec_session_error_code` with the control path, so a rule is answered
    /// with one code whichever stream carried it.
    ///
    /// Not every rule that reaches here is the decoder's. A track whose objects
    /// mix forwarding preferences is the endpoint's to notice — it takes the
    /// alias table to know which track an object belongs to — and it arrives on
    /// exactly these streams. Both kinds are asked for a code the same way, and
    /// a rule with no code is declined rather than guessed at.
    pub fn close_for_data_stream(&self, err: &ConnectionError) -> bool {
        match err {
            ConnectionError::Codec(inner) => {
                let Some(code) = Self::codec_session_error_code(inner) else { return false };
                let wire_code = u32::try_from(code.as_u64()).unwrap_or(u32::MAX);
                self.close(wire_code, inner.to_string().as_bytes());
                true
            }
            // A rule the endpoint raises rather than the decoder. The two
            // reach their codes through different tables and mean the same
            // thing here: `Some` is a rule this draft ends the session over.
            ConnectionError::Endpoint(inner) => {
                let Some(code) = inner.session_error_code() else { return false };
                let wire_code = u32::try_from(code.as_u64()).unwrap_or(u32::MAX);
                self.close(wire_code, inner.to_string().as_bytes());
                true
            }
            _ => false,
        }
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
        assert_eq!(versions[0].into_inner(), 0xff000000 + 7);
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
        assert_eq!(config.alpn(), vec![DraftVersion::Draft07.quic_alpn().to_vec()]);
    }

    #[test]
    fn moqt_alpn_value() {
        assert_eq!(MOQT_ALPN, b"moq-00");
    }
}

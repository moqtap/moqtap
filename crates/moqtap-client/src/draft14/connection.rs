use std::sync::Arc;

use bytes::{Buf, Bytes, BytesMut};

use crate::draft14::endpoint::{Endpoint, EndpointError};
use crate::draft14::event::{ClientEvent, Direction, StreamKind};
use crate::draft14::observer::ConnectionObserver;
use crate::draft14::session::request_id::Role;
use crate::draft14::session::setup;
use crate::forwarding_preference::ObjectForwardingPreference;
use crate::malformed_tracks::MalformedTrackCondition;
use crate::track_locations::{ObjectLocation, ObjectRole, TrackObjects};
use crate::transport::quic::QuicTransport;
use crate::transport::{RecvStream, SendStream, Transport, TransportError};
use moqtap_codec::dispatch::{
    AnyControlMessage, AnyDatagramHeader, AnyFetchHeader, AnySubgroupHeader,
};
use moqtap_codec::draft14::data_stream::{FetchObject, SubgroupObject, SubgroupObjectReader};
use moqtap_codec::draft14::message::ControlMessage;
use moqtap_codec::error::CodecError;
use moqtap_codec::kvp::KeyValuePair;
use moqtap_codec::types::*;
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

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
    /// Data stream used out of order (e.g. object before header).
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

/// Configuration for a MoQT client connection.
///
/// Both `draft` and `transport` are required — there is no `Default` impl.
pub struct ClientConfig {
    /// The MoQT draft version to use (primary, determines codec/framing).
    pub draft: DraftVersion,
    /// Additional draft versions to offer in CLIENT_SETUP.
    /// The primary `draft` is always included first.
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
    /// Primary draft first, then any additional versions.
    pub fn supported_versions(&self) -> Vec<VarInt> {
        let mut versions = vec![self.draft.version_varint()];
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
            TransportType::Quic => vec![self.draft.quic_alpn().to_vec()],
            TransportType::WebTransport { .. } => vec![b"h3".to_vec()],
        }
    }
}

/// A framed writer for a send stream. Handles MoQT length-prefixed framing.
pub struct FramedSendStream {
    inner: SendStream,
    draft: DraftVersion,
    /// Stateful subgroup object encoder. Initialized by
    /// [`FramedSendStream::write_subgroup_header`] and used by
    /// [`FramedSendStream::write_subgroup_object`] to track the delta-encoded
    /// object ID state.
    subgroup_io: Option<SubgroupObjectReader>,
}

impl FramedSendStream {
    /// Create a new framed send stream for the given draft version.
    pub fn new(inner: SendStream, draft: DraftVersion) -> Self {
        Self { inner, draft, subgroup_io: None }
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

    /// Write a subgroup stream header. Also initializes the internal
    /// delta-encoding state used by [`FramedSendStream::write_subgroup_object`].
    ///
    /// The header is refused, and nothing is written, if its fields disagree
    /// with its own stream type. That check has to happen here rather than at
    /// the first object: the type is what every object after it is framed
    /// against, so a header that went out saying the wrong thing cannot be
    /// taken back.
    pub async fn write_subgroup_header(
        &mut self,
        header: &AnySubgroupHeader,
    ) -> Result<(), ConnectionError> {
        let mut buf = Vec::new();
        header.encode_stream_checked(&mut buf)?;
        self.inner.write_all(&buf).await?;
        match header {
            AnySubgroupHeader::Draft14(ref d14) => {
                self.subgroup_io = Some(SubgroupObjectReader::new(d14));
            }
            // Only this draft's header seeds the object reader. With draft 14
            // as the only enabled draft `AnySubgroupHeader` has a single
            // variant, the arm above is exhaustive and this one unreachable.
            #[cfg(any(
                feature = "draft07",
                feature = "draft08",
                feature = "draft09",
                feature = "draft10",
                feature = "draft11",
                feature = "draft12",
                feature = "draft13",
                feature = "draft15",
                feature = "draft16",
                feature = "draft17",
                feature = "draft18",
                feature = "draft19"
            ))]
            _ => {}
        }
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

    /// Append a draft-14 subgroup object to the stream. Uses the stateful
    /// reader installed by [`FramedSendStream::write_subgroup_header`] to
    /// produce the correct delta-encoded object ID. Returns an error if
    /// called before a subgroup header was written.
    pub async fn write_subgroup_object(
        &mut self,
        object: &SubgroupObject,
    ) -> Result<(), ConnectionError> {
        let writer = self
            .subgroup_io
            .as_mut()
            .ok_or(ConnectionError::DataStreamState("subgroup header not written yet"))?;
        let mut buf = Vec::new();
        writer.write_object(object, &mut buf)?;
        self.inner.write_all(&buf).await?;
        Ok(())
    }

    /// Append a draft-14 fetch object to the stream. Fetch objects are
    /// self-contained (each carries its own group/subgroup/object IDs and
    /// priority), so no prior `write_fetch_header` bookkeeping is required.
    /// Append a fetch object to the stream.
    ///
    /// Draft-14 derives the declared length from the payload itself rather than
    /// holding it as a field, so there is nothing here for the two to disagree
    /// about - unlike the subgroup object, whose header carries the length and
    /// whose writer has to overwrite it.
    ///
    /// # Errors
    ///
    /// Whatever the checked encoder refuses: a payload beside a status that
    /// forbids one, or a status the draft leaves unassigned. This went through
    /// the unchecked encoder, so both were written.
    pub async fn write_fetch_object(
        &mut self,
        object: &FetchObject,
    ) -> Result<(), ConnectionError> {
        let mut buf = Vec::new();
        object.encode_checked(&mut buf)?;
        self.inner.write_all(&buf).await?;
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

/// What an Object Status makes of an object here.
///
/// Two answers where drafts 08 through 13 have three, and the missing one is
/// the point: the end-of-track status settles where the track ended and is
/// judged against nothing, because the rule about where one may be placed is
/// not in this draft. `a_track_may_end_where_it_has_already_been.rs` asserts
/// that acceptance.
///
/// Every other status is a statement about objects rather than one of them.
fn object_role(status: Option<u64>) -> ObjectRole {
    match status {
        None | Some(0x0) => ObjectRole::Produced,
        Some(0x4) => ObjectRole::EndsTrack(None),
        _ => ObjectRole::Neither,
    }
}

/// A framed reader for a recv stream. Handles MoQT varint-length decoding.
pub struct FramedRecvStream {
    inner: RecvStream,
    buf: BytesMut,
    draft: DraftVersion,
    /// Stateful subgroup object decoder. Initialized by
    /// [`FramedRecvStream::read_subgroup_header`] and used by
    /// [`FramedRecvStream::read_subgroup_object`] to track delta-encoded
    /// object IDs and whether extension headers are present.
    subgroup_io: Option<SubgroupObjectReader>,
    /// The record this stream's objects are measured against, and the Group ID
    /// its header named.
    ///
    /// One group for the whole stream: a subgroup header names it once and no
    /// object header repeats it. `None` on a stream that was never given one -
    /// a stream for an alias no live binding names, and every stream built
    /// outside [`Connection::accept_subgroup_stream`] - and such a stream reads
    /// exactly as it did before this existed.
    tracking: Option<(TrackObjects, u64)>,
}

impl FramedRecvStream {
    /// Create a new framed receive stream for the given draft version.
    pub fn new(inner: RecvStream, draft: DraftVersion) -> Self {
        Self { inner, buf: BytesMut::with_capacity(4096), draft, subgroup_io: None, tracking: None }
    }

    /// Get the transport-level stream ID.
    pub fn stream_id(&self) -> u64 {
        self.inner.stream_id()
    }

    /// Measure this stream's objects against `objects`, all of them in `group`.
    ///
    /// Called by [`Connection::accept_subgroup_stream`] once the header has
    /// been read, which is the only point at which both the track and the group
    /// are known.
    fn measure_objects_against(&mut self, objects: TrackObjects, group: u64) {
        self.tracking = Some((objects, group));
    }

    /// Judge one object this stream carried against where its track ended.
    ///
    /// The object's Group ID is the stream's and its Object ID is its own,
    /// already resolved from the delta the wire carries; what they are measured
    /// against is the end an end-of-track object settled on any stream.
    fn note_subgroup_object(
        &self,
        object: u64,
        status: Option<u64>,
    ) -> Result<(), ConnectionError> {
        let Some((objects, group)) = &self.tracking else { return Ok(()) };
        let at = ObjectLocation { group: *group, object };
        objects.note_past_final(at, object_role(status)).map_err(|end| {
            ConnectionError::Endpoint(EndpointError::ObjectPastFinalObject {
                alias: objects.alias(),
                group: at.group,
                object: at.object,
                final_group: end.group,
                final_object: end.object,
            })
        })
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

        // Read payload length (16-bit BE for draft-11+, varint for earlier drafts)
        let (payload_len, len_field_size) = if self.draft.uses_fixed_length_framing() {
            self.ensure(type_len + 2).await?;
            let hi = self.buf[type_len] as usize;
            let lo = self.buf[type_len + 1] as usize;
            ((hi << 8) | lo, 2)
        } else {
            self.ensure(type_len + 1).await?;
            let payload_len_start = type_len;
            let payload_len_varint_len = varint_len(self.buf[payload_len_start]);
            self.ensure(type_len + payload_len_varint_len).await?;
            let mut cursor = &self.buf[payload_len_start..type_len + payload_len_varint_len];
            let payload_len = VarInt::decode(&mut cursor)?.into_inner() as usize;
            (payload_len, payload_len_varint_len)
        };

        // Read full payload
        let total = type_len + len_field_size + payload_len;
        self.ensure(total).await?;

        // Capture raw bytes only if requested (observer attached).
        let raw = capture_raw.then(|| self.buf[..total].to_vec());

        // Now decode the whole message
        let mut frame = &self.buf[..total];
        let msg = AnyControlMessage::decode(self.draft, &mut frame)?;
        self.buf.advance(total);
        Ok((msg, raw))
    }

    /// Read a subgroup stream header. Also initializes the internal
    /// delta-decoding state used by
    /// [`FramedRecvStream::read_subgroup_object`].
    pub async fn read_subgroup_header(&mut self) -> Result<AnySubgroupHeader, ConnectionError> {
        self.ensure(1).await?;
        loop {
            let mut cursor = &self.buf[..];
            match AnySubgroupHeader::decode(self.draft, &mut cursor) {
                Ok(header) => {
                    let consumed = self.buf.len() - cursor.remaining();
                    self.buf.advance(consumed);
                    match header {
                        AnySubgroupHeader::Draft14(ref d14) => {
                            self.subgroup_io = Some(SubgroupObjectReader::new(d14));
                        }
                        // Only this draft's header seeds the object reader. With draft 14
                        // as the only enabled draft `AnySubgroupHeader` has a single
                        // variant, the arm above is exhaustive and this one unreachable.
                        #[cfg(any(
                            feature = "draft07",
                            feature = "draft08",
                            feature = "draft09",
                            feature = "draft10",
                            feature = "draft11",
                            feature = "draft12",
                            feature = "draft13",
                            feature = "draft15",
                            feature = "draft16",
                            feature = "draft17",
                            feature = "draft18",
                            feature = "draft19"
                        ))]
                        _ => {}
                    }
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
            match AnyFetchHeader::decode(self.draft, &mut cursor) {
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

    /// Read the next draft-14 subgroup object from this stream. Uses the
    /// stateful reader installed by
    /// [`FramedRecvStream::read_subgroup_header`] to decode the delta-
    /// encoded object ID and handle extension headers per the stream type.
    /// Returns an error if called before a subgroup header was read.
    pub async fn read_subgroup_object(&mut self) -> Result<SubgroupObject, ConnectionError> {
        if self.subgroup_io.is_none() {
            return Err(ConnectionError::DataStreamState("subgroup header not read yet"));
        }
        loop {
            let reader = self.subgroup_io.as_mut().unwrap();
            let mut probe = reader.clone();
            let mut cursor = &self.buf[..];
            match probe.read_object(&mut cursor) {
                Ok(obj) => {
                    let consumed = self.buf.len() - cursor.remaining();
                    self.buf.advance(consumed);
                    // Commit state from the successful probe decode.
                    *reader = probe;
                    self.note_subgroup_object(
                        obj.object_id.into_inner(),
                        obj.status.map(|s| s as u64),
                    )?;
                    return Ok(obj);
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

    /// Read the next draft-14 fetch object from this stream. Fetch objects
    /// are self-describing, so no prior `read_fetch_header` state is needed
    /// to decode each object.
    pub async fn read_fetch_object(&mut self) -> Result<FetchObject, ConnectionError> {
        loop {
            let mut cursor = &self.buf[..];
            match FetchObject::decode(&mut cursor) {
                Ok(obj) => {
                    let consumed = self.buf.len() - cursor.remaining();
                    self.buf.advance(consumed);
                    return Ok(obj);
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
    /// Behind a lock because a control message is written from two kinds of
    /// place. Most of them are the caller's own request, made through `&mut
    /// self`. The messages that answer a Malformed Track are not: the
    /// conditions that make a track malformed are detected on the data plane,
    /// where this connection is reached through a shared reference. The lock
    /// also makes one message the unit of writing, so two of them cannot
    /// interleave on the stream.
    control_send: Option<tokio::sync::Mutex<FramedSendStream>>,
    control_recv: Option<FramedRecvStream>,
    observer: Option<Box<dyn ConnectionObserver>>,
    /// Setup events buffered during `connect()` and replayed when an
    /// observer attaches via `set_observer` — without this, an observer
    /// attached after `connect` returns would never see the handshake.
    pending_events: Vec<ClientEvent>,
}

impl Connection {
    /// Connect to a MoQT server as a client.
    ///
    /// Establishes a QUIC or WebTransport connection (based on `config.transport`),
    /// opens a bidirectional control stream, performs the CLIENT_SETUP /
    /// SERVER_SETUP handshake, and returns a ready-to-use connection.
    pub async fn connect(addr: &str, config: ClientConfig) -> Result<Self, ConnectionError> {
        let draft = config.draft;
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
        let mut control_send = FramedSendStream::new(send, draft);
        let mut control_recv = FramedRecvStream::new(recv, draft);

        // Perform setup handshake
        let mut endpoint = Endpoint::new(Role::Client);
        endpoint.connect()?;
        let setup_msg = endpoint
            .send_client_setup(config.supported_versions(), config.setup_parameters.clone())?;
        let any_setup = AnyControlMessage::Draft14(setup_msg);
        let raw_setup = control_send.write_control(&any_setup).await?;

        let (server_setup, raw_server_setup) = control_recv.read_control(true).await?;
        // Unwrap to draft-14 for the endpoint (which is draft-14 only)
        match &server_setup {
            AnyControlMessage::Draft14(ControlMessage::ServerSetup(ref ss)) => {
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
            draft,
            control_send: Some(tokio::sync::Mutex::new(control_send)),
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
    ///
    /// Wraps the draft-14 message in `AnyControlMessage::Draft14` for framing.
    pub async fn send_control(&self, msg: &ControlMessage) -> Result<(), ConnectionError> {
        let any = AnyControlMessage::Draft14(msg.clone());
        let mut send =
            self.control_send.as_ref().ok_or(ConnectionError::NoControlStream)?.lock().await;
        let raw = send.write_control(&any).await?;
        drop(send);
        self.emit(ClientEvent::ControlMessage {
            direction: Direction::Send,
            message: any,
            raw: Some(raw),
        });
        Ok(())
    }

    /// Read the next control message from the control stream.
    ///
    /// Returns the `AnyControlMessage` and also extracts the draft-14
    /// `ControlMessage` for internal endpoint dispatch.
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
        // Unwrap to draft-14 for the endpoint
        match any {
            AnyControlMessage::Draft14(msg) => Ok(msg),
            // `AnyControlMessage` carries one variant per enabled draft feature.
            // When draft 14 is the only one enabled the arm above is exhaustive
            // and this rejection arm is unreachable, so it is compiled only for
            // builds in which another draft's variant can actually turn up.
            #[cfg(any(
                feature = "draft07",
                feature = "draft08",
                feature = "draft09",
                feature = "draft10",
                feature = "draft11",
                feature = "draft12",
                feature = "draft13",
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
        parameters: Vec<KeyValuePair>,
    ) -> Result<VarInt, ConnectionError> {
        let (req_id, msg) = self.endpoint.subscribe(
            track_namespace,
            track_name,
            subscriber_priority,
            group_order,
            filter_type,
            parameters,
        )?;
        self.send_control(&msg).await?;
        Ok(req_id)
    }

    /// Send a SUBSCRIBE for a range of the track, starting at a given
    /// location.
    ///
    /// The Filter Type is derived from the range, so the message cannot name a
    /// filter whose fields it does not carry.
    #[allow(clippy::too_many_arguments)]
    pub async fn subscribe_range(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        subscriber_priority: u8,
        group_order: GroupOrder,
        start_location: Location,
        end_group: Option<VarInt>,
        parameters: Vec<KeyValuePair>,
    ) -> Result<VarInt, ConnectionError> {
        let (req_id, msg) = self.endpoint.subscribe_range(
            track_namespace,
            track_name,
            subscriber_priority,
            group_order,
            start_location,
            end_group,
            parameters,
        )?;
        self.send_control(&msg).await?;
        Ok(req_id)
    }

    /// Send an UNSUBSCRIBE for the given request ID.
    pub async fn unsubscribe(&mut self, request_id: VarInt) -> Result<(), ConnectionError> {
        let msg = self.endpoint.unsubscribe(request_id)?;
        self.send_control(&msg).await
    }

    /// Accept a subscription the peer opened, sending SUBSCRIBE_OK and giving
    /// its track a Track Alias.
    ///
    /// The endpoint refuses an alias a live track of its own already holds and
    /// refuses a second answer to one SUBSCRIBE, so nothing is written on the
    /// wire when it does either.
    pub async fn subscribe_ok(
        &mut self,
        request_id: VarInt,
        track_alias: VarInt,
        expires: VarInt,
        group_order: GroupOrder,
        parameters: Vec<KeyValuePair>,
    ) -> Result<(), ConnectionError> {
        let msg = self.endpoint.send_subscribe_ok(
            request_id,
            track_alias,
            expires,
            group_order,
            parameters,
        )?;
        self.send_control(&msg).await
    }

    /// Reject a subscription the peer opened, sending SUBSCRIBE_ERROR.
    ///
    /// The endpoint refuses a second answer to one SUBSCRIBE, so nothing is
    /// written on the wire when it does.
    pub async fn subscribe_error(
        &mut self,
        request_id: VarInt,
        error_code: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<(), ConnectionError> {
        let msg = self.endpoint.send_subscribe_error(request_id, error_code, reason_phrase)?;
        self.send_control(&msg).await
    }

    /// Accept a PUBLISH the peer sent, which establishes the subscription it
    /// opened.
    ///
    /// The endpoint refuses a second answer to one PUBLISH, so nothing is
    /// written on the wire when it does.
    #[allow(clippy::too_many_arguments)]
    pub async fn publish_ok(
        &mut self,
        request_id: VarInt,
        forward: Forward,
        subscriber_priority: u8,
        group_order: GroupOrder,
        filter_type: FilterType,
        start_location: Option<Location>,
        end_group: Option<VarInt>,
    ) -> Result<(), ConnectionError> {
        let msg = self.endpoint.send_publish_ok(
            request_id,
            forward,
            subscriber_priority,
            group_order,
            filter_type,
            start_location,
            end_group,
        )?;
        self.send_control(&msg).await
    }

    /// Reject a PUBLISH the peer sent, which ends the subscription it opened
    /// before it was established.
    ///
    /// The endpoint refuses a second answer to one PUBLISH, so nothing is
    /// written on the wire when it does.
    pub async fn publish_error(
        &mut self,
        request_id: VarInt,
        error_code: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<(), ConnectionError> {
        let msg = self.endpoint.send_publish_error(request_id, error_code, reason_phrase)?;
        self.send_control(&msg).await
    }

    /// Send a SUBSCRIBE_UPDATE for an active subscription. Returns the
    /// allocated request ID of the update message.
    pub async fn subscribe_update(
        &mut self,
        subscription_request_id: VarInt,
        start_location: Location,
        end_group: VarInt,
        subscriber_priority: u8,
        forward: Forward,
        parameters: Vec<moqtap_codec::kvp::KeyValuePair>,
    ) -> Result<VarInt, ConnectionError> {
        let (req_id, msg) = self.endpoint.subscribe_update(
            subscription_request_id,
            start_location,
            end_group,
            subscriber_priority,
            forward,
            parameters,
        )?;
        self.send_control(&msg).await?;
        Ok(req_id)
    }

    // ── Fetch flow ──────────────────────────────────────────

    /// Send a FETCH and return the allocated request ID.
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
        parameters: Vec<KeyValuePair>,
    ) -> Result<VarInt, ConnectionError> {
        let (req_id, msg) = self.endpoint.fetch(
            track_namespace,
            track_name,
            subscriber_priority,
            group_order,
            start_group,
            start_object,
            end_group,
            end_object,
            parameters,
        )?;
        self.send_control(&msg).await?;
        Ok(req_id)
    }

    /// Send a Relative Joining Fetch and return the allocated request ID.
    ///
    /// `joining_start` is a count of groups back from the subscription's live
    /// edge. For the form that names the group outright, see
    /// [`absolute_joining_fetch`](Self::absolute_joining_fetch).
    pub async fn joining_fetch(
        &mut self,
        subscriber_priority: u8,
        group_order: GroupOrder,
        joining_request_id: VarInt,
        joining_start: VarInt,
        parameters: Vec<KeyValuePair>,
    ) -> Result<VarInt, ConnectionError> {
        let (req_id, msg) = self.endpoint.joining_fetch(
            subscriber_priority,
            group_order,
            joining_request_id,
            joining_start,
            parameters,
        )?;
        self.send_control(&msg).await?;
        Ok(req_id)
    }

    /// Send an Absolute Joining Fetch and return the allocated request ID.
    ///
    /// `joining_start` is the group to begin at.
    pub async fn absolute_joining_fetch(
        &mut self,
        subscriber_priority: u8,
        group_order: GroupOrder,
        joining_request_id: VarInt,
        joining_start: VarInt,
        parameters: Vec<KeyValuePair>,
    ) -> Result<VarInt, ConnectionError> {
        let (req_id, msg) = self.endpoint.absolute_joining_fetch(
            subscriber_priority,
            group_order,
            joining_request_id,
            joining_start,
            parameters,
        )?;
        self.send_control(&msg).await?;
        Ok(req_id)
    }

    /// Send a FETCH_CANCEL for the given request ID.
    pub async fn fetch_cancel(&mut self, request_id: VarInt) -> Result<(), ConnectionError> {
        let msg = self.endpoint.fetch_cancel(request_id)?;
        self.send_control(&msg).await
    }

    /// Accept a fetch the peer opened, sending FETCH_OK.
    ///
    /// The endpoint refuses a Joining Fetch naming a subscription this session
    /// cannot join and refuses a second answer to one FETCH, so nothing is
    /// written on the wire when it does either.
    pub async fn fetch_ok(
        &mut self,
        request_id: VarInt,
        group_order: GroupOrder,
        end_of_track: u8,
        end_location: Location,
        parameters: Vec<KeyValuePair>,
    ) -> Result<(), ConnectionError> {
        let msg = self.endpoint.send_fetch_ok(
            request_id,
            group_order,
            end_of_track,
            end_location,
            parameters,
        )?;
        self.send_control(&msg).await
    }

    /// Refuse a fetch the peer opened, sending FETCH_ERROR.
    ///
    /// The endpoint refuses a second answer to one FETCH, and refuses a
    /// Joining Fetch's refusal under any code but the one the draft names for
    /// it, so nothing is written on the wire when it does either.
    pub async fn fetch_error(
        &mut self,
        request_id: VarInt,
        error_code: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<(), ConnectionError> {
        let msg = self.endpoint.send_fetch_error(request_id, error_code, reason_phrase)?;
        self.send_control(&msg).await
    }

    // ── Namespace flows ─────────────────────────────────────

    /// Send a SUBSCRIBE_NAMESPACE and return the request ID.
    pub async fn subscribe_namespace(
        &mut self,
        track_namespace: TrackNamespace,
        parameters: Vec<KeyValuePair>,
    ) -> Result<VarInt, ConnectionError> {
        let (req_id, msg) = self.endpoint.subscribe_namespace(track_namespace, parameters)?;
        self.send_control(&msg).await?;
        Ok(req_id)
    }

    /// Accept a namespace subscription the peer made, sending SUBSCRIBE_NAMESPACE_OK.
    ///
    /// The endpoint refuses a second answer to one SUBSCRIBE_NAMESPACE, so nothing is
    /// written on the wire when it does.
    pub async fn subscribe_namespace_ok(
        &mut self,
        request_id: VarInt,
    ) -> Result<(), ConnectionError> {
        let msg = self.endpoint.send_subscribe_namespace_ok(request_id)?;
        self.send_control(&msg).await
    }

    /// Refuse a namespace subscription the peer made, sending SUBSCRIBE_NAMESPACE_ERROR.
    ///
    /// The other half of the same sentence: one answer, and this is the other
    /// one it can be.
    pub async fn subscribe_namespace_error(
        &mut self,
        request_id: VarInt,
        error_code: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<(), ConnectionError> {
        let msg =
            self.endpoint.send_subscribe_namespace_error(request_id, error_code, reason_phrase)?;
        self.send_control(&msg).await
    }

    /// Send a PUBLISH_NAMESPACE and return the request ID.
    pub async fn publish_namespace(
        &mut self,
        track_namespace: TrackNamespace,
        parameters: Vec<KeyValuePair>,
    ) -> Result<VarInt, ConnectionError> {
        let (req_id, msg) = self.endpoint.publish_namespace(track_namespace, parameters)?;
        self.send_control(&msg).await?;
        Ok(req_id)
    }

    /// Accept an announcement the peer made, sending PUBLISH_NAMESPACE_OK.
    ///
    /// The endpoint refuses a second answer to one PUBLISH_NAMESPACE, so
    /// nothing is written on the wire when it does.
    pub async fn publish_namespace_ok(
        &mut self,
        request_id: VarInt,
    ) -> Result<(), ConnectionError> {
        let msg = self.endpoint.send_publish_namespace_ok(request_id)?;
        self.send_control(&msg).await
    }

    /// Refuse an announcement the peer made, sending PUBLISH_NAMESPACE_ERROR.
    ///
    /// The other half of the same sentence: one answer, and this is the other
    /// one it can be.
    pub async fn publish_namespace_error(
        &mut self,
        request_id: VarInt,
        error_code: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<(), ConnectionError> {
        let msg =
            self.endpoint.send_publish_namespace_error(request_id, error_code, reason_phrase)?;
        self.send_control(&msg).await
    }

    /// Revoke an acceptance, sending PUBLISH_NAMESPACE_CANCEL.
    ///
    /// The endpoint refuses one for an announcement it never accepted, so
    /// nothing is written on the wire when it does.
    pub async fn publish_namespace_cancel(
        &mut self,
        track_namespace: TrackNamespace,
        error_code: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<(), ConnectionError> {
        let msg =
            self.endpoint.publish_namespace_cancel(track_namespace, error_code, reason_phrase)?;
        self.send_control(&msg).await
    }

    /// Withdraw an announcement this endpoint made, sending
    /// PUBLISH_NAMESPACE_DONE.
    ///
    /// The mirror of [`Self::publish_namespace`], and the counterpart of
    /// [`Self::publish_namespace_cancel`]: this one ends an announcement of
    /// this endpoint's, that one revokes the acceptance of one the peer made.
    pub async fn publish_namespace_done(
        &mut self,
        track_namespace: TrackNamespace,
    ) -> Result<(), ConnectionError> {
        let msg = self.endpoint.publish_namespace_done(track_namespace)?;
        self.send_control(&msg).await
    }
    // ── Track Status flow ────────────────────────────────────

    /// Send a TRACK_STATUS and return the allocated request ID.
    #[allow(clippy::too_many_arguments)]
    pub async fn track_status(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        subscriber_priority: u8,
        group_order: GroupOrder,
        forward: Forward,
        filter_type: FilterType,
        parameters: Vec<KeyValuePair>,
    ) -> Result<VarInt, ConnectionError> {
        let (req_id, msg) = self.endpoint.track_status(
            track_namespace,
            track_name,
            subscriber_priority,
            group_order,
            forward,
            filter_type,
            parameters,
        )?;
        self.send_control(&msg).await?;
        Ok(req_id)
    }

    /// Accept a track status the peer asked for, sending TRACK_STATUS_OK.
    ///
    /// The endpoint refuses a second answer to one request, so nothing is
    /// written on the wire when it does. It also chooses the Track Alias the
    /// message carries, because the draft leaves only one value open.
    pub async fn track_status_ok(
        &mut self,
        request_id: VarInt,
        expires: VarInt,
        group_order: GroupOrder,
        parameters: Vec<KeyValuePair>,
    ) -> Result<(), ConnectionError> {
        let msg =
            self.endpoint.send_track_status_ok(request_id, expires, group_order, parameters)?;
        self.send_control(&msg).await
    }

    /// Refuse a track status the peer asked for, sending TRACK_STATUS_ERROR.
    ///
    /// The other answer the request can have, and the endpoint holds it to the
    /// same count of one.
    pub async fn track_status_error(
        &mut self,
        request_id: VarInt,
        error_code: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<(), ConnectionError> {
        let msg = self.endpoint.send_track_status_error(request_id, error_code, reason_phrase)?;
        self.send_control(&msg).await
    }

    // ── Publish flow (publisher side) ───────────────────────

    /// Offer the peer a subscription to a track this endpoint publishes, and
    /// return the Request ID the offer was allocated.
    ///
    /// Nothing is written on the wire when the endpoint refuses to build the
    /// offer, which it does when the Track Alias is one another live track of
    /// this session already holds.
    #[allow(clippy::too_many_arguments)]
    pub async fn publish(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        track_alias: VarInt,
        group_order: GroupOrder,
        largest_location: Option<Location>,
        forward: Forward,
        parameters: Vec<KeyValuePair>,
    ) -> Result<VarInt, ConnectionError> {
        let (req_id, msg) = self.endpoint.publish(
            track_namespace,
            track_name,
            track_alias,
            group_order,
            largest_location,
            forward,
            parameters,
        )?;
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

    // ── Malformed Tracks ────────────────────────────────────

    /// Send what Section 2.5 asks for when this endpoint finds a track
    /// malformed.
    ///
    /// "it MUST UNSUBSCRIBE any subscription and FETCH_CANCEL any fetch for
    /// that Track from that publisher" — one message per request, in Request
    /// ID order, and the endpoint decides which message each request takes.
    ///
    /// A write that fails is not reported. The caller is on its way to
    /// returning an error that says what went wrong with the track, and a
    /// control stream that will not take an UNSUBSCRIBE is a session on its
    /// way out for a reason of its own; replacing the condition's report with
    /// a transport error would lose the only account of why the track was
    /// withdrawn. The rest of the withdrawal is abandoned, because a stream
    /// that refused one message will refuse the next.
    async fn withdraw_malformed_track(&self, alias: u64, condition: MalformedTrackCondition) {
        for msg in self.endpoint.withdraw_malformed_track(alias, condition) {
            if self.send_control(&msg).await.is_err() {
                break;
            }
        }
    }

    /// Record the framing an arriving object was sent with, and withdraw from
    /// the track when it is the second framing that track has been sent.
    ///
    /// The receiving half of a pair. The two writing paths call the endpoint
    /// directly and answer a mixed track by refusing to write it, because
    /// Section 2.5's sentence is a subscriber's: an endpoint about to send an
    /// object is that object's Original Publisher, and a publisher has no
    /// subscription of its own to withdraw and no fetch of its own to cancel.
    async fn note_received_framing(
        &self,
        alias: u64,
        seen: ObjectForwardingPreference,
    ) -> Result<(), ConnectionError> {
        let Err(err) = self.endpoint.note_object_forwarding_preference(alias, seen) else {
            return Ok(());
        };
        self.withdraw_malformed_track(alias, MalformedTrackCondition::MixedForwardingPreference)
            .await;
        Err(err.into())
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
        let mut framed = FramedSendStream::new(send, self.draft);
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
        let mut framed = FramedSendStream::new(send, self.draft);
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
        let mut framed = FramedRecvStream::new(recv, self.draft);
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
        self.note_received_framing(header.track_alias(), ObjectForwardingPreference::Subgroup)
            .await?;
        // The track is resolved here and not inside the stream: it takes the
        // endpoint's alias table, which a stream handle has no way back to.
        if let Some(objects) = self.endpoint.track_objects(header.track_alias()) {
            framed.measure_objects_against(objects, header.group_id());
        }
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
        let header = AnyDatagramHeader::decode(self.draft, &mut cursor)?;
        let consumed = data.len() - cursor.len();
        let payload = data.slice(consumed..);
        self.emit(ClientEvent::DatagramReceived {
            direction: Direction::Receive,
            header: header.clone(),
            payload_len: payload.len(),
        });
        // A datagram is the other framing, and it settles the track's just as a
        // subgroup header does.
        self.note_received_framing(header.meta().track_alias, ObjectForwardingPreference::Datagram)
            .await?;
        // A datagram is a whole object, so the connection can measure it
        // without help from the caller - and answer the condition itself,
        // because an UNSUBSCRIBE takes the connection an object on a stream
        // cannot reach.
        let meta = header.meta();
        if let Err(err) = self.endpoint.note_received_object(
            meta.track_alias,
            ObjectLocation { group: meta.group_id, object: meta.object_id },
            object_role(meta.status),
        ) {
            self.withdraw_malformed_track(
                meta.track_alias,
                MalformedTrackCondition::ObjectPastFinalObject,
            )
            .await;
            return Err(err.into());
        }
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

    /// The code to close the session with when a message could not be decoded
    /// because the peer broke a rule draft-14 answers with a close.
    ///
    /// Every variant listed here comes from a sentence in this draft that names
    /// the consequence, and the list is per draft: answering a bound this draft
    /// does not state would close a session over traffic a conforming peer may
    /// send.
    ///
    ///   - Reason Phrase, maximum 1024 bytes: "If an endpoint receives a length
    ///     exceeding the maximum, it MUST close the session with a
    ///     PROTOCOL_VIOLATION."
    ///   - GOAWAY New Session URI, maximum 8,192 bytes, with the same sentence.
    ///     Drafts 11 through 19 state it; 07 through 10 state no maximum for
    ///     the field at all.
    ///   - Key-Value-Pair value, maximum 2^16-1 bytes, with the same sentence.
    ///   - Track Namespace tuple size: "If an endpoint receives a Track
    ///     Namespace tuple with an N of 0 or more than 32, it MUST close the
    ///     session with a Protocol Violation." Note the lower bound - an empty
    ///     tuple is refused here, where drafts 17 and later permit one.
    ///   - Full Track Name, maximum 4,096 bytes, "computed as the sum of the
    ///     lengths of each Track Namespace tuple field and the Track Name
    ///     length field". This draft bounds the pair and not the namespace
    ///     alone; draft-16 widened it.
    ///   - Duplicate parameters, a SHOULD rather than a MUST: "Receivers SHOULD
    ///     check that there are no unauthorized duplicate parameters and close
    ///     the session as a PROTOCOL_VIOLATION if found." The rule is
    ///     asymmetric here - "Receivers MUST allow duplicates of unknown
    ///     parameters", and one known type is granted repeats - and the codec
    ///     reports only the repeats this draft actually forbids.
    ///   - Unknown control message type: "An endpoint that receives an unknown
    ///     message type MUST close the session."
    ///   - Extension headers on an Object whose status is Object Does Not
    ///     Exist, Section 10.2.1.2. That one arrives on a data stream or a
    ///     datagram, so [`Connection::close_for_data_stream`] is what carries
    ///     it.
    ///
    /// **Not** the zero-length Track Namespace Field, the delta-encoded
    /// parameter type overflow, or the Object ID delta wrap. Those enter the
    /// specification at drafts 16 and 18, and this draft states none of them.
    ///
    /// **Not** the 2^16-1 control message length either. This draft states the
    /// limit - "the total length of a control message is limited to 2^16-1
    /// bytes" - and states no consequence for exceeding it, so an oversized
    /// message is refused by the decoder and stops there.
    ///
    /// **Not** [`CodecError::UnexpectedEnd`], which reports no rule at all: the
    /// reader raises it whenever a message is still arriving, and
    /// `read_control` loops on it. Closing over it would end a session on an
    /// ordinary short read.
    ///
    /// **Not** the unknown Message Parameter rule. Drafts 16 through 19 require
    /// a close for a Message Parameter whose type the negotiated version does
    /// not define. This draft states the opposite and states it about the same
    /// parameters: "Receivers MUST allow duplicates of unknown parameters",
    /// which presumes an unknown parameter arrives and is carried. Refusing one
    /// here would close a session over an extension this draft leaves room for.
    ///
    /// `None` for everything else, including [`CodecError::InvalidField`]. That
    /// variant is shared by a dozen unrelated malformations, only some of which
    /// the draft answers with a close, so a session cannot be ended on it
    /// without ending sessions the draft does not ask to be ended. Splitting it
    /// is the way to bring the rest of those rules under this function;
    /// widening the match is not - the extension-header rule above reached this
    /// table by being split out of it.
    fn codec_session_error_code(
        err: &CodecError,
    ) -> Option<moqtap_codec::draft14::error_codes::SessionErrorCode> {
        use moqtap_codec::draft14::error_codes::SessionErrorCode;
        use moqtap_codec::kvp::KvpError;
        match err {
            // The declared Length disagreeing with the fields, which every
            // draft answers with a close. Drafts 07 through 10 name no code for
            // it, so it takes the one their other unnamed rules take.
            // A Filter Type outside the four this draft assigns, Section 9.7:
            // "An endpoint that receives a filter type other than the above MUST
            // be close the session with PROTOCOL_VIOLATION" — the missing word
            // is the draft's. This is the draft the rule gained a consequence
            // on. Drafts 07 through 13 write the same sentence as "MUST be
            // treated as error", which names none - draft-13 Section 8.7 among
            // them - and their tables leave it unanswered.
            CodecError::InvalidFilterType(_) => Some(SessionErrorCode::ProtocolViolation),
            // A Fetch Type outside the three this draft assigns, Section
            // 9.16: "An endpoint that receives a Fetch Type other than 0x1,
            // 0x2 or 0x3 MUST be close the session with a PROTOCOL_VIOLATION."
            // The missing word is the draft's, as it is for the filter type
            // above. The value decides which
            // fields follow it — a Standalone fetch carries a track name and a
            // range where a joining fetch carries a Request ID and an offset —
            // so a reader that cannot name the type cannot find the end of the
            // message.
            CodecError::InvalidFetchType(_) => Some(SessionErrorCode::ProtocolViolation),
            CodecError::ControlMessageLengthMismatch { .. } => {
                Some(SessionErrorCode::ProtocolViolation)
            }
            CodecError::ReasonPhraseTooLong
            | CodecError::GoAwayUriTooLong
            | CodecError::InvalidNamespaceTupleSize(_)
            | CodecError::TrackNameTooLong
            | CodecError::DuplicateParameter(_)
            | CodecError::UnknownMessageType(_)
            | CodecError::ExtensionsOnNonExistentObject(_)
            | CodecError::Kvp(KvpError::ValueTooLong(_)) => {
                Some(SessionErrorCode::ProtocolViolation)
            }
            // An unknown data-plane type, Section 10: "An endpoint that
            // receives an unknown stream or datagram type MUST close the
            // session." One sentence covering two tables, which is why both
            // variants sit here.
            // A Content Exists field that is neither zero nor one, Sections 9.8
            // and 9.13: "Any other value is a protocol error and MUST terminate
            // the session with a PROTOCOL_VIOLATION".
            CodecError::InvalidContentExists(_) => Some(SessionErrorCode::ProtocolViolation),
            // A Forward field that is neither zero nor one. Sections 9.7 and
            // 9.10 use the sentence above; Section 9.13 says "Any value other
            // than 0 or 1 is a PROTOCOL_VIOLATION". Section 9.14 names the two
            // legal values without a consequence and is answered the same way,
            // for the reason given on the variant. Draft-15 replaces the field
            // with the FORWARD parameter, which carries the same rule in a
            // different shape and reports it as `ParameterValueOutOfRange`.
            CodecError::InvalidForward(_) => Some(SessionErrorCode::ProtocolViolation),
            CodecError::UnknownStreamType(_) | CodecError::UnknownDatagramType(_) => {
                Some(SessionErrorCode::ProtocolViolation)
            }
            // A key-value pair whose value is not the serialization its own
            // Type defines, Section 1.4.2: "If a receiver understands a Type,
            // and the following Value or Length/Value does not match the
            // serialization defined by that Type, the receiver MUST terminate the
            // session with error code KEY_VALUE_FORMATTING_ERROR."
            //
            // Section 9.2.1.1 states the same answer for the one structure this
            // draft spells out: "If the Token structure cannot be decoded, the
            // receiver MUST close the Session with Key-Value Formatting error."
            //
            // The one rule in this table that names a code other than Protocol
            // Violation.
            CodecError::KeyValueFormatting { .. } => {
                Some(SessionErrorCode::KeyValueFormattingError)
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
            // Not `ParameterValueOutOfRange`: no parameter this draft defines
            // restricts its value's range. Forwarding is a message field here
            // and is answered above.
            CodecError::ParameterValueOutOfRange { .. }
            | CodecError::UnexpectedEnd
            | CodecError::MessageTooLong(_)
            | CodecError::VarInt(_)
            | CodecError::InvalidField
            | CodecError::EmptyNamespaceField
            | CodecError::InvalidRange(..)
            | CodecError::ParameterLengthMismatch(_)
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
            | CodecError::InvalidRequiredRequestIdDelta(..)
            | CodecError::InvalidTypeValue { .. }
            | CodecError::UnknownMessageParameter(_)
            // Not `ParameterOutOfScope`: this draft states the scope rule and
            // answers it the other way. Section 9.2.1 Version Specific Parameters: "Each
            // version-specific parameter definition indicates the message types in which it can
            // appear. If it appears in some other type of message, it MUST be
            // ignored." The codec carries such a parameter on this draft and never
            // raises the variant, so this arm records a rule this draft has and
            // does not close over, not one it is missing. Draft-17 is where the
            // second sentence becomes a close.
            | CodecError::ParameterOutOfScope { .. }
            // Both belong to the parameter form of the filter. Draft-15 moved
            // the Filter Type, Start Location and End Group out of SUBSCRIBE and
            // into one length-prefixed parameter; this draft still carries them
            // as fields, where a value that runs short is a truncated frame and
            // an End Group is written out rather than added to anything.
            | CodecError::SubscriptionFilterMalformed { .. }
            | CodecError::FilterEndGroupOverflow { .. }
            // The object payload rule, Section 10.2.1.1: "Any object with a status
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
                KvpError::MissingLength | KvpError::UnexpectedEnd | KvpError::VarInt(_),
            ) => None,
        }
    }

    /// Close the session on the wire when a decode failure is one draft-14
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

    /// Withdraw from a track a data stream found malformed, reporting whether
    /// it did.
    ///
    /// The Malformed Track twin of [`Connection::close_for_data_stream`], and
    /// separate from it for the same reason and one more. The same one: a
    /// [`FramedRecvStream`] holds no connection, so the reader that finds the
    /// fault is not the object that can send an UNSUBSCRIBE. The one more: the
    /// two answers are opposites - that call ends the session, this one gives
    /// up a track and leaves it running - and a single entry point would have
    /// to decide between them from the error alone, which is exactly the
    /// decision a caller reproducing a capture wants to make itself.
    ///
    /// The datagram path needs none of this. It is read through the connection,
    /// so [`Connection::recv_datagram`] answers the condition where it finds
    /// it, and this is only for the objects that arrive on a stream the caller
    /// holds.
    pub async fn withdraw_for_data_stream(&self, err: &ConnectionError) -> bool {
        let ConnectionError::Endpoint(EndpointError::ObjectPastFinalObject { alias, .. }) = err
        else {
            return false;
        };
        self.withdraw_malformed_track(*alias, MalformedTrackCondition::ObjectPastFinalObject).await;
        true
    }

    /// Close the session over a rule broken on a data stream, reporting whether
    /// it did.
    ///
    /// A data stream cannot close for itself the way `recv_control` does:
    /// [`Connection::accept_subgroup_stream`] hands the caller a
    /// [`FramedRecvStream`] holding no connection, so the reader that finds the
    /// violation is not the object that can act on it. Keeping it a separate
    /// call is deliberate as well - a permissive caller, one reproducing a
    /// capture, can read a violating stream and report it without tearing the
    /// session down.
    ///
    /// The rule this draft answers here is extension headers on an Object whose
    /// status is Object Does Not Exist, which reaches subgroup streams, fetch
    /// streams and status datagrams alike. It shares `codec_session_error_code`
    /// with the control path, so a rule is answered with one code whichever
    /// stream carried it.
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
            additional_versions: Vec::new(),
            transport: TransportType::Quic,
            skip_cert_verification: false,
            ca_certs: Vec::new(),
            setup_parameters: Vec::new(),
        };
        let versions = config.supported_versions();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].into_inner(), 0xff000000 + 14);
    }

    #[test]
    fn client_config_supported_versions_draft07() {
        let config = ClientConfig {
            draft: DraftVersion::Draft07,
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
            draft: DraftVersion::Draft14,
            additional_versions: Vec::new(),
            transport: TransportType::Quic,
            skip_cert_verification: false,
            ca_certs: Vec::new(),
            setup_parameters: Vec::new(),
        };
        assert_eq!(config.alpn(), vec![b"moq-00".to_vec()]);
    }

    #[test]
    fn client_config_alpn_webtransport() {
        let config = ClientConfig {
            draft: DraftVersion::Draft14,
            additional_versions: Vec::new(),
            transport: TransportType::WebTransport { url: "https://example.com".to_string() },
            skip_cert_verification: false,
            ca_certs: Vec::new(),
            setup_parameters: Vec::new(),
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

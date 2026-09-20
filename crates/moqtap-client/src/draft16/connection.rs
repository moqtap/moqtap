use std::collections::VecDeque;
use std::sync::Mutex;

use bytes::{Buf, Bytes, BytesMut};

use crate::draft16::endpoint::{Endpoint, EndpointError};
use crate::draft16::event::{ClientEvent, Direction, StreamKind};
use crate::draft16::observer::ConnectionObserver;
use crate::draft16::session::request_id::Role;
use crate::draft16::session::setup;
use crate::malformed_tracks::MalformedTrackCondition;
use crate::track_locations::{ObjectLocation, ObjectRole, TrackObjects};
use crate::transport::{RecvStream, SendStream, Transport, TransportError};
use moqtap_codec::dispatch::{
    AnyControlMessage, AnyDatagramHeader, AnyFetchHeader, AnySubgroupHeader,
};
use moqtap_codec::draft16::data_stream::{
    FetchHeader, FetchObjectHeader, SubgroupObject, SubgroupObjectReader,
};
use moqtap_codec::draft16::error_codes::DataStreamResetErrorCode;
use moqtap_codec::draft16::message::{ControlMessage, MessageType, RequestError, RequestOk};
use moqtap_codec::error::CodecError;
use moqtap_codec::kvp::KeyValuePair;
use moqtap_codec::types::*;
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

/// The ALPN identifier draft-16 uses on raw QUIC, `moqt-16`.
///
/// Drafts 07 to 14 share one ALPN, `moq-00`, and a peer that offers it has
/// said nothing about which of the eight it speaks. Draft-15 ended that:
/// from there each draft has an ALPN of its own, so the version is settled
/// by the TLS handshake before a byte of MoQT is written.
///
/// This is [`DraftVersion::Draft16`]'s own
/// [`quic_alpn`](DraftVersion::quic_alpn), which is what
/// [`ClientConfig::alpn`] offers; the test below holds the two together.
pub const MOQT_ALPN: &[u8] = b"moqt-16";

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
    /// A control message this build decoded for draft-16 and then could not
    /// narrow to draft-16's own message type.
    ///
    /// Unreachable, and that is not the same as harmless. `read_control`
    /// decodes with this connection's own draft, so the `AnyControlMessage` it
    /// hands back can only carry this draft's variant — but the narrowing arm
    /// is compiled in every configuration anyway, under
    /// `#[allow(unreachable_patterns)]` rather than a `cfg` naming the other
    /// thirteen drafts, because such a list has to be edited in fourteen
    /// places whenever a draft is added and a copy that omits one leaves the
    /// match non-exhaustive.
    ///
    /// Spelled as `CodecError::UnknownMessageType(0)` it would not stay inert:
    /// every draft's
    /// [`codec_session_error_code`](Connection::codec_session_error_code)
    /// answers that variant `Some(PROTOCOL_VIOLATION)`. So the day the
    /// narrowing did fail, this build's own defect would reach a caller as *the
    /// peer sent a control message type this draft does not assign, and the
    /// session must be closed with a Protocol Violation* — carrying `0x00` as
    /// the codepoint that proved it. A conformance report reading that
    /// publishes a named, well-evidenced accusation against a relay for
    /// something no relay did.
    ///
    /// A variant of its own is what stops that.
    /// [`draft_specific_cause`](Connection::draft_specific_cause) answers it
    /// [`LocalRefusal`], the facade turns that into [`ErrorCause::Facade`], and
    /// nothing downstream can read a rule out of a cause that says nothing
    /// reached the wire. What is pinned is the consequence rather than the
    /// unreachability: nothing pins the arm's reachability, which is exactly
    /// why the consequence must not be an accusation.
    ///
    /// [`LocalRefusal`]: crate::above_codec_rules::DraftSpecificCause::LocalRefusal
    /// [`ErrorCause::Facade`]: crate::dispatch::ErrorCause::Facade
    #[error(
        "a control message decoded for draft-16 did not narrow to draft-16: a defect in this          build, and evidence about nothing the peer did"
    )]
    ControlMessageNarrowing,
    /// A bidirectional stream the peer opened began with a message type other
    /// than SUBSCRIBE_NAMESPACE.
    ///
    /// Draft-16 Section 3.3: "This specification only specifies two uses of
    /// bidirectional streams, the control stream, which begins with
    /// CLIENT_SETUP, and SUBSCRIBE_NAMESPACE. Bidirectional streams MUST NOT
    /// begin with any other message type unless negotiated. If they do, the
    /// peer MUST close the Session with a Protocol Violation." The session has
    /// already been closed on the wire by the time this is returned, and the
    /// offending stream reset.
    #[error(
        "a bidirectional stream the peer opened began with {0:?}, which does not begin a namespace subscription; the session was closed"
    )]
    NonSubscribeNamespaceOnBidiStream(MessageType),
    /// A `respond_*` helper was called on a namespace subscription this
    /// endpoint opened.
    ///
    /// The answer to a SUBSCRIBE_NAMESPACE is owed by whoever received it, so
    /// only a stream that arrived through
    /// [`Connection::accept_namespace_stream`] can be answered here. Nothing
    /// was written and no state moved.
    #[error("request {0} was made by this endpoint, so there is nothing here to answer")]
    NotOursToAnswer(u64),
    /// An Object arrived carrying extension headers on a status that is not
    /// Normal.
    /// Draft-16 Section 10.2.1.2: "Any Object with status Normal can have
    /// extension headers", with a reference to Section 2.5 inside the sentence,
    /// and "If an endpoint receives extension headers on Objects with status
    /// that is not Normal, it MUST close the session with a
    /// PROTOCOL_VIOLATION."
    ///
    /// The codec decodes such an Object rather than refusing it — the frame is
    /// well formed, and a tool that reports non-conforming traffic has to be
    /// able to read it. Being an endpoint rather than an observer is what turns
    /// it into an error, so it is raised here, on the receive path, and not in
    /// the decoder.
    ///
    /// [`Connection::close_for_data_stream`] performs the close the sentence
    /// above requires. It is a separate call because the reader that raises
    /// this holds no connection, and because a deliberately permissive caller
    /// should be able to read a violating stream and report it without tearing
    /// the session down.
    #[error(
        "object {object_id} carries {extensions_len} bytes of extension headers on status {status:?}, which is not Normal"
    )]
    ExtensionsOnNonNormalStatus {
        /// The Object ID the extension headers arrived on.
        object_id: u64,
        /// Length in bytes of the extension-header block.
        extensions_len: usize,
        /// The Object's status, resolved through the encoding's elision rule.
        ///
        /// Spelled out in full because the glob import of `moqtap_codec::types`
        /// brings a different `ObjectStatus` into this module.
        status: moqtap_codec::draft16::types::ObjectStatus,
    },
}

impl From<crate::transport::DialError> for ConnectionError {
    /// Maps a dial failure onto the variants this error already has, so a
    /// caller matches `InvalidAddress` or `TlsConfig`.
    ///
    /// # `LocalSocket` joins `InvalidAddress`, and that is the answer being kept
    ///
    /// A socket this machine would not open has a variant of its own on
    /// [`DialError`](crate::transport::DialError), and it still arrives here.
    /// Not laziness about the churn — `InvalidAddress` is one of the
    /// variants the facade reads as
    /// [`ErrorCause::Facade`](crate::dispatch::ErrorCause::Facade), which
    /// `is_local` answers **true** for, and a failed bind is this side's by
    /// definition. Routing it to `Transport` would read better in prose and
    /// would publish this machine's missing IPv6 stack as the relay's doing.
    ///
    /// The phase is not lost, only unread on this path. A caller measuring
    /// which stage of a dial died reads
    /// [`DialError::phase`](crate::transport::DialError::phase) off the dial
    /// itself; a caller who arrived at this type named a `host:port` and asked
    /// for a connection, not for a measurement, and a public variant here for
    /// a distinction nothing on this path reads is churn with no reader, which
    /// is why this impl stays flat.
    fn from(e: crate::transport::DialError) -> Self {
        match e {
            // Two variants, one arm, deliberately — see above.
            crate::transport::DialError::InvalidAddress(s)
            | crate::transport::DialError::LocalSocket(s) => ConnectionError::InvalidAddress(s),
            crate::transport::DialError::TlsConfig(s) => ConnectionError::TlsConfig(s),
            crate::transport::DialError::Transport(e) => ConnectionError::Transport(e),
        }
    }
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
/// Both `draft` and `transport` are required -- there is no `Default` impl.
pub struct ClientConfig {
    /// The MoQT draft version to use (primary, determines codec/framing).
    pub draft: DraftVersion,
    /// The transport type (QUIC or WebTransport).
    pub transport: TransportType,
    /// Whether to skip TLS certificate verification (for testing).
    pub skip_cert_verification: bool,
    /// Custom CA certificates to trust (DER-encoded).
    pub ca_certs: Vec<Vec<u8>>,
    /// Setup parameters to include in CLIENT_SETUP (e.g., auth tokens).
    pub setup_parameters: Vec<KeyValuePair>,
}

impl ClientConfig {
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
    /// Stateful subgroup object writer.
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
    /// delta-encoding state used by
    /// [`FramedSendStream::write_subgroup_object`].
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
        // Clippy would rather see these two arms as an `if let`, and rustc rejects
        // that in a single-draft build, where the pattern is irrefutable. Only a
        // `match` satisfies both.
        #[allow(clippy::single_match)]
        match header {
            AnySubgroupHeader::Draft16(ref d16) => {
                self.subgroup_io = Some(SubgroupObjectReader::new(d16));
            }
            // Only this draft's header seeds the object reader. With draft 16 the only enabled
            // draft `AnySubgroupHeader` has a single variant, the arm above is exhaustive and this
            // one unreachable. Compiled in every configuration with the lint allowed, rather than
            // gated on a `cfg` naming the other thirteen drafts: such a list has to be edited in
            // every draft module whenever a draft is added, and a copy that omits one leaves this
            // match non-exhaustive.
            #[allow(unreachable_patterns)]
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

    /// Append a draft-16 subgroup object to the stream using the
    /// stateful writer seeded from
    /// [`FramedSendStream::write_subgroup_header`].
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

    /// Append a fetch object to the stream.
    ///
    /// The fetch stream had a header writer and no object writer, so a caller
    /// could open one and put nothing on it through this type. The subgroup
    /// stream has had both since the writer was introduced.
    ///
    /// The declared length comes from the payload rather than from the caller's
    /// field: a header that disagrees with the bytes beside it desynchronises
    /// every object after it on the stream, and nothing downstream can recover.
    ///
    /// # Errors
    ///
    /// [`ConnectionError::Codec`] if the header's fields disagree with the
    /// Serialization Flags that announce them, which the encoder refuses rather
    /// than writing a frame its own reader cannot take apart.
    pub async fn write_fetch_object(
        &mut self,
        header: &FetchObjectHeader,
        payload: &[u8],
    ) -> Result<(), ConnectionError> {
        let mut header = header.clone();
        header.payload_length = VarInt::from_usize(payload.len());
        let mut buf = Vec::new();
        header.encode(&mut buf)?;
        buf.extend_from_slice(payload);
        self.inner.write_all(&buf).await?;
        Ok(())
    }

    /// Finish the stream (send FIN).
    pub async fn finish(&mut self) -> Result<(), ConnectionError> {
        self.inner.finish()?;
        Ok(())
    }

    /// Abandon the stream, handing the peer `code` as the `RESET_STREAM`
    /// application error code.
    ///
    /// Dropping a send stream sends a FIN, which claims the stream ended
    /// cleanly; this is the only way to say the opposite. See
    /// [`SendStream::reset`].
    pub fn reset(&mut self, code: u64) -> Result<(), ConnectionError> {
        self.inner.reset(code)?;
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
    /// Stateful subgroup object reader.
    subgroup_io: Option<SubgroupObjectReader>,
    /// The record this stream's objects are measured against, and the Group ID
    /// its header named.
    ///
    /// One group for the whole stream: a subgroup header names it once and no
    /// object header repeats it. `None` on a stream that was never given one -
    /// a stream for an alias no live binding names, and every stream built
    /// outside [`Connection::accept_subgroup_stream`] - and such a stream reads
    /// without being measured, because `note_subgroup_object` has nothing to
    /// measure it against.
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

    /// Stop reading, telling the peer to stop transmitting with `code` as the
    /// `STOP_SENDING` application error code, discarding anything unread.
    ///
    /// Dropping a receive stream also stops it, but with a hard-coded 0. See
    /// [`RecvStream::stop`].
    pub fn stop(&mut self, code: u64) -> Result<(), ConnectionError> {
        self.inner.stop(code)?;
        Ok(())
    }

    /// Wait for the peer to reset this stream, consuming nothing.
    ///
    /// See [`RecvStream::received_reset`] for what `Ok(None)` means and why a
    /// caller must not re-poll after it.
    pub async fn received_reset(&mut self) -> Result<Option<u64>, ConnectionError> {
        Ok(self.inner.received_reset().await?)
    }

    /// Read the next control message, or report that the peer finished the
    /// stream at a message boundary.
    ///
    /// `Ok(None)` is a clean end and not an error: on a namespace
    /// subscription's stream it is one of the two ways Section 6.1 withdraws
    /// the subscription — "closing the stream with either a FIN or
    /// RESET_STREAM" — and the other is a reset, which surfaces as
    /// [`TransportError::StreamReset`] out of the read below.
    ///
    /// A stream that ends *inside* a message is a different thing and stays
    /// [`ConnectionError::UnexpectedEnd`]: the buffer is empty only at a
    /// boundary.
    pub async fn read_control_or_end(
        &mut self,
        capture_raw: bool,
    ) -> Result<Option<(AnyControlMessage, Option<Vec<u8>>)>, ConnectionError> {
        if self.buf.is_empty() && !self.fill().await? {
            return Ok(None);
        }
        self.read_control(capture_raw).await.map(Some)
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

        // Draft-16: 16-bit BE payload length
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
    /// delta-decoding state.
    pub async fn read_subgroup_header(&mut self) -> Result<AnySubgroupHeader, ConnectionError> {
        self.ensure(1).await?;
        loop {
            let mut cursor = &self.buf[..];
            match AnySubgroupHeader::decode(self.draft, &mut cursor) {
                Ok(header) => {
                    let consumed = self.buf.len() - cursor.remaining();
                    self.buf.advance(consumed);
                    // Clippy would rather see these two arms as an `if let`, and rustc rejects
                    // that in a single-draft build, where the pattern is irrefutable. Only a
                    // `match` satisfies both.
                    #[allow(clippy::single_match)]
                    match header {
                        AnySubgroupHeader::Draft16(ref d16) => {
                            self.subgroup_io = Some(SubgroupObjectReader::new(d16));
                        }
                        // Only this draft's header seeds the object reader. With draft 16 the only
                        // enabled draft `AnySubgroupHeader` has a single variant, the arm above is
                        // exhaustive and this one unreachable. Compiled in every configuration with
                        // the lint allowed, rather than gated on a `cfg` naming the other thirteen
                        // drafts: such a list has to be edited in every draft module whenever a
                        // draft is added, and a copy that omits one leaves this match
                        // non-exhaustive.
                        #[allow(unreachable_patterns)]
                        _ => {}
                    }
                    return Ok(header);
                }
                Err(e) if e.is_incomplete() => {
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
                Err(e) if e.is_incomplete() => {
                    if !self.fill().await? {
                        return Err(ConnectionError::UnexpectedEnd);
                    }
                }
                Err(e) => return Err(ConnectionError::Codec(e)),
            }
        }
    }

    /// Read the next draft-16 subgroup object from this stream using
    /// the stateful reader seeded by
    /// [`FramedRecvStream::read_subgroup_header`].
    ///
    /// Errors with [`ConnectionError::ExtensionsOnNonNormalStatus`] on an
    /// Object that carries extension headers on a status other than Normal,
    /// which draft-16 Section 10.2.1.2 answers with a session close. The Object
    /// is consumed from the stream before the check, so the reader stays in
    /// step with the wire and a caller that reports the violation and reads on
    /// sees the following Object rather than a re-parse of this one.
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
                    *reader = probe;
                    if !obj.extensions_permitted() {
                        return Err(ConnectionError::ExtensionsOnNonNormalStatus {
                            object_id: obj.object_id.into_inner(),
                            extensions_len: obj.extension_headers.len(),
                            status: obj.status(),
                        });
                    }
                    self.note_subgroup_object(
                        obj.object_id.into_inner(),
                        obj.object_status.map(|s| s as u64),
                    )?;
                    return Ok(obj);
                }
                Err(e) if e.is_incomplete() => {
                    if !self.fill().await? {
                        return Err(ConnectionError::UnexpectedEnd);
                    }
                }
                Err(e) => return Err(ConnectionError::Codec(e)),
            }
        }
    }

    /// Read the next draft-16 fetch header from this stream.
    pub async fn read_fetch_stream_header(&mut self) -> Result<FetchHeader, ConnectionError> {
        loop {
            let mut cursor = &self.buf[..];
            match FetchHeader::decode(&mut cursor) {
                Ok(hdr) => {
                    let consumed = self.buf.len() - cursor.remaining();
                    self.buf.advance(consumed);
                    return Ok(hdr);
                }
                Err(e) if e.is_incomplete() => {
                    if !self.fill().await? {
                        return Err(ConnectionError::UnexpectedEnd);
                    }
                }
                Err(e) => return Err(ConnectionError::Codec(e)),
            }
        }
    }

    /// Read the next draft-16 fetch object's header and payload.
    ///
    /// The mirror of [`FramedSendStream::write_fetch_object`], and the payload
    /// comes back with the header for the reason the codec leaves it on the
    /// wire: `payload_length` says how many bytes follow, and a reader that
    /// takes the wrong number of them desynchronises every later object on the
    /// stream. Doing it here is the only place that count and the buffer are
    /// both in hand.
    ///
    /// Stateless: the header comes back with its elided fields still absent —
    /// `group_id`, `object_id` and the Subgroup ID mode say what each Object
    /// inherited rather than what it is. Resolving them against the Object
    /// before takes a running
    /// [`FetchObjectReader`](moqtap_codec::draft16::data_stream::FetchObjectReader),
    /// which this draft's codec does offer and which this stream does not hold —
    /// where drafts 15 and 17 through 20 keep one on the stream itself.
    ///
    /// So a caller that wants Locations rather than inheritances carries the
    /// reader beside the stream and calls
    /// [`resolve`](moqtap_codec::draft16::data_stream::FetchObjectReader::resolve)
    /// on each header. `AnyConnection::accept_fetch` is that caller, and
    /// `Draft16FetchStream` is where it keeps the state — draft-16 is the one
    /// arm of the facade's fetch reader that is not a bare stream.
    ///
    /// # Errors
    ///
    /// [`ConnectionError::UnexpectedEnd`] when the stream ends inside the header
    /// or inside the payload it declared, and [`ConnectionError::Codec`] on a
    /// Serialization Flags value the draft does not define.
    pub async fn read_fetch_object(
        &mut self,
    ) -> Result<(FetchObjectHeader, Vec<u8>), ConnectionError> {
        let header = loop {
            let mut cursor = &self.buf[..];
            match FetchObjectHeader::decode(&mut cursor) {
                Ok(header) => {
                    let consumed = self.buf.len() - cursor.remaining();
                    self.buf.advance(consumed);
                    break header;
                }
                Err(e) if e.is_incomplete() => {
                    if !self.fill().await? {
                        return Err(ConnectionError::UnexpectedEnd);
                    }
                }
                Err(e) => return Err(ConnectionError::Codec(e)),
            }
        };
        let payload = self.read_object_payload(&header.payload_length).await?;
        Ok((header, payload))
    }

    /// Take the `length` payload bytes that follow a fetch object's header.
    ///
    /// Separate from the header read because the header is decoded from a probe
    /// cursor that may have to be retried after a fill, and the payload is a
    /// flat byte count that never is.
    async fn read_object_payload(&mut self, length: &VarInt) -> Result<Vec<u8>, ConnectionError> {
        let length = length.into_inner() as usize;
        self.ensure(length).await?;
        let payload = self.buf[..length].to_vec();
        self.buf.advance(length);
        Ok(payload)
    }

    /// Returns the draft version this stream is framed for.
    pub fn draft(&self) -> DraftVersion {
        self.draft
    }
}

/// Which side opened the bidirectional stream a namespace subscription
/// travels on.
///
/// Section 6.1 does not say who may subscribe to a namespace, and a relay
/// subscribing to what a client publishes is the ordinary case, so the stream
/// arrives in both directions. The two are not symmetric — one side owes an
/// answer and the other is waiting for it — so a [`NamespaceStream`] carries
/// this to say which side of that it is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestOrigin {
    /// This endpoint opened the stream and wrote the SUBSCRIBE_NAMESPACE on
    /// it. What comes back is the answer and the namespaces that follow it.
    Local,
    /// The peer opened the stream; this endpoint owes it an answer and writes
    /// the namespaces on it afterwards.
    Peer,
}

/// The application error code a namespace subscription's stream is abandoned
/// with when this endpoint never served it: `INTERNAL_ERROR`, 0x0.
///
/// Draft-16 assigns no code for this. Its only registry of stream error codes
/// is Section 13.4.4, "Data Stream Reset Error Codes", and every entry there is
/// specified by Section 10.4.3, which is about closing subgroup streams — a
/// namespace subscription's stream is not a data stream. Section 6.1 offers a
/// FIN as the alternative and names no number for the other form.
///
/// So this is a choice rather than a citation, and it is the one that claims
/// least: `INTERNAL_ERROR` is "an implementation specific error", which is
/// exactly what a stream abandoned mid-accept is. It is taken from the codec's
/// own registry rather than written as a literal so a renumbering in a later
/// draft cannot be missed here.
///
/// Only the paths that give up on a stream before it carries a subscription
/// use it — a request that could not be built, a first message that could not
/// be read, a Request ID the peer may not use. A caller cancelling a live
/// subscription picks its own code, or uses the FIN form and picks none.
const STREAM_ABANDONED: u64 = DataStreamResetErrorCode::InternalError as u64;

/// The largest value a QUIC application error code can carry, `2^62 - 1`.
///
/// Checked by [`NamespaceStream::cancel`] before either half of the stream is
/// touched, so an unrepresentable code cannot half-cancel a subscription.
const MAX_QUIC_VARINT: u64 = (1u64 << 62) - 1;

/// One SUBSCRIBE_NAMESPACE and everything answering it, on a bidirectional
/// stream of their own.
///
/// Draft-16 Section 3.3: "This specification only specifies two uses of
/// bidirectional streams, the control stream, which begins with CLIENT_SETUP,
/// and SUBSCRIBE_NAMESPACE." This is the second use, and the only request on
/// this draft that has a stream at all — every other one is still written on
/// the control stream and identified by its Request ID.
///
/// The stream matters because two of the four messages that travel on it carry
/// no Request ID. Section 9.21 puts NAMESPACE "on the response stream of a
/// SUBSCRIBE_NAMESPACE request" and Section 9.23 says the same of
/// NAMESPACE_DONE; both carry a Track Namespace **Suffix**, relative to a
/// prefix only this subscription knows. Without the stream they name nothing.
///
/// # Reading and writing go through the connection
///
/// This handle owns both halves of the stream but not the session, so the
/// endpoint state machine and the observer stay where they were. Read with
/// [`Connection::recv_on_namespace_stream`], answer the peer with
/// [`Connection::respond_ok_on_namespace_stream`] or
/// [`Connection::respond_error_on_namespace_stream`], report namespaces with
/// [`Connection::send_on_namespace_stream`], and withdraw with
/// [`Connection::cancel_namespace_stream`] or
/// [`Connection::finish_namespace_stream`].
///
/// [`cancel`](Self::cancel), [`finish`](Self::finish) and
/// [`peer_cancelled`](Self::peer_cancelled) are on the handle because a caller
/// may hold one without the connection. None of them moves the endpoint's
/// record of the subscription, which is why the connection carries a wrapper
/// for each.
///
/// # Dropping this cancels the subscription, and correctly
///
/// Section 6.1: "A SUBSCRIBE_NAMESPACE can be cancelled by closing the stream
/// with either a FIN or RESET_STREAM." Dropping a send stream sends a FIN and
/// dropping a receive stream sends `STOP_SENDING`, so a handle that falls out
/// of scope performs the first of those two forms exactly. That is why there
/// is no [`Drop`] impl here: on this draft the default *is* the cancellation,
/// and drafts 17 to 19 need one only because they made a FIN mean something
/// else.
///
/// What a drop cannot do is say so at the endpoint. It holds the stream and
/// not the session, so the subscription stays where it was in the endpoint's
/// record while the stream it travelled on is gone. Call
/// [`Connection::finish_namespace_stream`] wherever that record matters.
///
/// All fields are private so the shape can grow without breaking callers.
#[must_use = "dropping a namespace stream cancels the subscription; hold it while it is live"]
pub struct NamespaceStream {
    send: FramedSendStream,
    recv: FramedRecvStream,
    request_id: VarInt,
    draft: DraftVersion,
    stream_id: u64,
    origin: RequestOrigin,
    /// Whether this handle has already closed the stream, by either form.
    closed: bool,
    /// Whether a `respond_*` helper has written the answer on this stream.
    /// Only ever true on a [`RequestOrigin::Peer`] stream.
    responded: bool,
}

impl NamespaceStream {
    /// The Request ID the SUBSCRIBE_NAMESPACE on this stream carries.
    pub fn request_id(&self) -> VarInt {
        self.request_id
    }

    /// The transport-level stream identifier, the same one
    /// [`ClientEvent::StreamOpened`] reports.
    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }

    /// The draft version this stream is framed for.
    pub fn draft(&self) -> DraftVersion {
        self.draft
    }

    /// Which side opened this stream.
    ///
    /// [`RequestOrigin::Peer`] means this endpoint owes the answer and the
    /// `respond_*` helpers apply; [`RequestOrigin::Local`] means it is waiting
    /// for one.
    pub fn origin(&self) -> RequestOrigin {
        self.origin
    }

    /// Whether the answer has been written on this stream by one of the
    /// `respond_*` helpers.
    ///
    /// Always false on a [`RequestOrigin::Local`] stream, which is answered by
    /// the peer rather than here.
    pub fn responded(&self) -> bool {
        self.responded
    }

    /// Whether [`cancel`](Self::cancel) or [`finish`](Self::finish) has
    /// already run on this handle.
    ///
    /// Says nothing about the peer: a peer's cancel is learned from
    /// [`peer_cancelled`](Self::peer_cancelled) or from the next read.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Cancel the subscription by resetting the stream, handing the peer
    /// `code`.
    ///
    /// The second of the two forms Section 6.1 allows. Both halves are shut —
    /// a QUIC bidirectional stream has two independent halves, so resetting
    /// only the send half would leave the peer free to keep writing namespaces
    /// nobody will read. The send half is reset with `code` and the receive
    /// half is stopped with the same value.
    ///
    /// `code` is a plain `u64` and has no default here, because draft-16
    /// assigns none: its only registry of stream error codes is titled "Data
    /// Stream Reset Error Codes" and every entry in it is specified by Section
    /// 10.4.3, which is about closing subgroup streams. A namespace
    /// subscription's stream is not a data stream, so a caller that wants to
    /// end one without choosing a number should use [`finish`](Self::finish),
    /// the form that carries none.
    ///
    /// **This is the stream and nothing else.** The endpoint's record of the
    /// subscription does not move, so a namespace already in flight is still
    /// accepted after this returns. [`Connection::cancel_namespace_stream`]
    /// does both and is what a caller holding a connection should reach for.
    ///
    /// Idempotent, and errors from a stream that was already reset or finished
    /// are swallowed: the subscription is cancelled either way.
    ///
    /// # Errors
    ///
    /// [`ConnectionError::Transport`] carrying [`TransportError::Write`] if
    /// `code` is outside the QUIC varint range (`0..2^62`). Nothing is sent in
    /// that case and the handle is *not* marked closed, so a caller can retry
    /// with a representable code.
    pub fn cancel(&mut self, code: u64) -> Result<(), ConnectionError> {
        if self.closed {
            return Ok(());
        }
        // Rejected before either half is touched, so a failed call leaves the
        // stream exactly as it was.
        if code > MAX_QUIC_VARINT {
            return Err(ConnectionError::Transport(TransportError::Write(format!(
                "error code {code} exceeds the varint range"
            ))));
        }
        self.closed = true;
        // Already-finished or already-reset halves report StreamClosed; the
        // subscription ends regardless, so neither is worth raising.
        let _ = self.send.reset(code);
        let _ = self.recv.stop(code);
        Ok(())
    }

    /// Cancel the subscription by finishing the send half cleanly.
    ///
    /// The first of the two forms Section 6.1 allows, and the one that needs
    /// no error code. The receive half is left open on purpose: a publisher
    /// that has already written namespaces has them in flight, and stopping
    /// the half they arrive on would discard what was sent before the FIN.
    ///
    /// Like [`cancel`](Self::cancel), this is the stream and nothing else.
    /// [`Connection::finish_namespace_stream`] is the same act with the
    /// endpoint's record attached.
    ///
    /// Idempotent.
    pub async fn finish(&mut self) -> Result<(), ConnectionError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        self.send.finish().await
    }

    /// Wait for the peer to reset this stream, consuming nothing.
    ///
    /// This sees one of Section 6.1's two forms and not the other: a reset
    /// arrives here, a FIN arrives as `Ok(None)` from
    /// [`Connection::recv_on_namespace_stream`]. A caller that wants to
    /// observe both has to read.
    ///
    /// Returns `Ok(Some(code))` with the peer's application error code, or
    /// `Ok(None)` meaning **no reset is observable, now or ever — stop
    /// asking**. A caller that re-polls after `Ok(None)` spins.
    ///
    /// Records nothing at the endpoint;
    /// [`Connection::peer_cancelled_on_namespace_stream`] is the same wait
    /// with the record attached. Cancel-safe, and it grants no flow-control
    /// credit.
    ///
    /// On WebTransport this always answers `Ok(None)`: `wtransport` exposes no
    /// reset-only observable, so a WebTransport caller learns of a peer reset
    /// on its next read and not before.
    pub async fn peer_cancelled(&mut self) -> Result<Option<u64>, ConnectionError> {
        self.recv.received_reset().await
    }
}

/// Holds a peer-opened stream pair while its first message is being read, and
/// puts it back on the connection's queue if that read is abandoned.
///
/// [`Connection::accept_namespace_stream`] awaits a whole control message, and
/// a caller may drop that future — a `select!` against a shutdown signal is
/// the ordinary reason. Without this the stream, and every byte already read
/// off it into the reader's buffer, would go with the future: the peer would
/// see its subscription reset for no reason it could act on.
///
/// [`Drop`] is the only place this can run, because a cancelled future is
/// never polled again. Every path that finishes — success or error — takes the
/// pair out first, so a pair still present when this drops was cancelled.
struct PendingInbound<'a> {
    pair: Option<(FramedSendStream, FramedRecvStream)>,
    queue: &'a Mutex<VecDeque<(FramedSendStream, FramedRecvStream)>>,
}

impl Drop for PendingInbound<'_> {
    fn drop(&mut self) {
        if let Some(pair) = self.pair.take() {
            // Front, not back: this stream arrived before anything still
            // queued behind it, and a partially read message must not be
            // handed out after a stream that arrived later.
            self.queue.lock().unwrap_or_else(|p| p.into_inner()).push_front(pair);
        }
    }
}

/// A live MoQT connection over QUIC or WebTransport, combining the endpoint
/// state machine with actual network I/O.
pub struct Connection {
    transport: Transport,
    endpoint: Endpoint,
    draft: DraftVersion,
    /// The control stream's write half, behind an async lock.
    ///
    /// A lock rather than `&mut self` because Section 2.4.2's answer to a
    /// Malformed Track is a control message, and the condition is detected
    /// where objects arrive - on a datagram read that takes `&self`, and on a
    /// stream the caller holds, whose reader has no connection at all.
    control_send: Option<tokio::sync::Mutex<FramedSendStream>>,
    control_recv: Option<FramedRecvStream>,
    observer: Option<Box<dyn ConnectionObserver>>,
    /// Setup events buffered during `connect()` and replayed when an
    /// observer attaches via `set_observer` — without this, an observer
    /// attached after `connect` returns would never see the handshake.
    pending_events: Vec<ClientEvent>,
    /// The server's half of the setup handshake, kept whole.
    ///
    /// The endpoint acts on the parameters it recognises and retains none of
    /// them, and which parameters a server sends — in what order, with what
    /// values — is the sharpest thing a session says about the implementation
    /// behind it.
    server_setup: AnyControlMessage,
    /// The framed wire bytes of [`Self::server_setup`].
    server_setup_raw: Option<Vec<u8>>,
    /// Bidirectional streams the peer opened that
    /// [`accept_namespace_stream`](Connection::accept_namespace_stream) took
    /// off the transport but did not finish reading a first message from,
    /// because its future was dropped. In arrival order.
    ///
    /// Without this a caller could not put `accept_namespace_stream` in a
    /// `select!` at all: losing the race would lose a stream the peer had
    /// already opened and, with it, whatever of the request had arrived.
    ///
    /// Behind a mutex because the lock is only ever held for a push or a pop,
    /// never across an await.
    pending_inbound: Mutex<VecDeque<(FramedSendStream, FramedRecvStream)>>,
}

impl Connection {
    /// Connect to a MoQT server as a client.
    ///
    /// Establishes a QUIC or WebTransport connection (based on
    /// `config.transport`), opens a bidirectional control stream,
    /// performs the CLIENT_SETUP / SERVER_SETUP handshake, and returns
    /// a ready-to-use connection.
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

        Self::adopt(transport, config).await
    }

    /// Run the MoQT setup handshake over a transport somebody else established.
    ///
    /// For choosing the draft from what the server selected: dial once through
    /// [`crate::transport::dial_quic`] offering every ALPN, then bring the
    /// connection to the module its answer names. [`Self::connect`] cannot do
    /// this — it derives its single ALPN from the draft it was given.
    ///
    /// `config.draft` must match this module. The transport is adopted as
    /// given; nothing here re-checks the ALPN it was negotiated with.
    pub async fn adopt(
        transport: Transport,
        config: ClientConfig,
    ) -> Result<Self, ConnectionError> {
        let draft = config.draft;
        // PATH is for native QUIC only, and the transport is known here and
        // nowhere further in. Refusing before dialling means a session that
        // the server would close on sight is never opened.
        setup::validate_client_path_transport(
            &config.setup_parameters,
            matches!(config.transport, TransportType::WebTransport { .. }),
        )
        .map_err(EndpointError::from)?;

        // Open bidirectional control stream
        let (send, recv) = transport.open_bi().await?;
        let mut control_send = FramedSendStream::new(send, draft);
        let mut control_recv = FramedRecvStream::new(recv, draft);

        // Perform setup handshake (draft-16: no versions)
        let mut endpoint = Endpoint::new(Role::Client);
        endpoint.connect()?;
        let setup_msg = endpoint.send_client_setup(config.setup_parameters.clone())?;
        let any_setup = AnyControlMessage::Draft16(setup_msg);
        let raw_setup = control_send.write_control(&any_setup).await?;

        let (server_setup, raw_server_setup) = control_recv.read_control(true).await?;
        // Unwrap to draft-16 for the endpoint
        match &server_setup {
            AnyControlMessage::Draft16(ControlMessage::ServerSetup(ref ss)) => {
                endpoint.receive_server_setup(ss)?;
            }
            _ => {
                return Err(ConnectionError::Endpoint(EndpointError::NotActive));
            }
        }

        let pending_events = vec![
            ClientEvent::ControlMessage {
                direction: Direction::Send,
                message: any_setup,
                stream_id: None,
                raw: Some(raw_setup),
            },
            ClientEvent::ControlMessage {
                direction: Direction::Receive,
                message: server_setup.clone(),
                stream_id: None,
                raw: raw_server_setup.clone(),
            },
            ClientEvent::SetupComplete { negotiated_version: 0xff000000 + 16 },
        ];

        Ok(Self {
            transport,
            endpoint,
            draft,
            control_send: Some(tokio::sync::Mutex::new(control_send)),
            control_recv: Some(control_recv),
            observer: None,
            pending_events,
            server_setup,
            server_setup_raw: raw_server_setup,
            pending_inbound: Mutex::new(VecDeque::new()),
        })
    }

    /// Establish a raw QUIC connection.
    ///
    /// Offers this draft's ALPN alone; [`crate::transport::dial_quic`] holds the
    /// TLS and endpoint setup.
    async fn connect_quic(addr: &str, config: &ClientConfig) -> Result<Transport, ConnectionError> {
        let (transport, _negotiated) = crate::transport::dial_quic(
            addr,
            &crate::transport::QuicDialOptions {
                skip_cert_verification: config.skip_cert_verification,
                ca_certs: config.ca_certs.clone(),
                ..crate::transport::QuicDialOptions::new(config.alpn())
            },
        )
        .await?;
        Ok(transport)
    }

    /// Establish a WebTransport connection.
    ///
    /// [`crate::transport::dial_webtransport`] holds the TLS and endpoint
    /// setup, exactly as `connect_quic` above defers its own. That is not
    /// only deduplication: both dials must trust the same roots. Settling trust
    /// at this call site instead — from `wtransport`'s own builder settings, or
    /// from a second config of this draft's own — puts the decision in two
    /// places, where it can stop matching what the QUIC dial trusts, so one
    /// relay would pass on one transport and fail on the other and a caller's
    /// private CA would reach only the dials whose call site installed it.
    /// Both ask the same function what to trust.
    #[cfg(feature = "webtransport")]
    async fn connect_webtransport(
        url: &str,
        config: &ClientConfig,
    ) -> Result<Transport, ConnectionError> {
        Ok(crate::transport::dial_webtransport(
            url,
            &crate::transport::QuicDialOptions {
                skip_cert_verification: config.skip_cert_verification,
                ca_certs: config.ca_certs.clone(),
                // The draft's own protocol identifier. Section 3 gives this
                // draft two version-negotiation channels and one of them per
                // transport: an ALPN over QUIC, and the WT-Available-Protocols
                // header over WebTransport. `config.alpn()` above is `h3`,
                // which is the HTTP/3 name and settles no version, so without
                // this the draft would be named nowhere.
                wt_protocols: vec![config.draft.quic_alpn().to_vec()],
                ..crate::transport::QuicDialOptions::new(config.alpn())
            },
        )
        .await?)
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

    // -- Observer ---------------------------------------------------

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

    // -- Control message I/O ----------------------------------------

    /// Send a control message on the control stream.
    ///
    /// Wraps the draft-16 message in `AnyControlMessage::Draft16` for
    /// framing.
    pub async fn send_control(&self, msg: &ControlMessage) -> Result<(), ConnectionError> {
        let any = AnyControlMessage::Draft16(msg.clone());
        let mut send =
            self.control_send.as_ref().ok_or(ConnectionError::NoControlStream)?.lock().await;
        let raw = send.write_control(&any).await?;
        drop(send);
        self.emit(ClientEvent::ControlMessage {
            direction: Direction::Send,
            message: any,
            stream_id: None,
            raw: Some(raw),
        });
        Ok(())
    }

    /// Read the next control message from the control stream.
    ///
    /// Returns the `AnyControlMessage` and also extracts the draft-16
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
                stream_id: None,
                raw,
            });
        }
        // Unwrap to draft-16 for the endpoint
        match any {
            AnyControlMessage::Draft16(msg) => Ok(msg),
            // `AnyControlMessage` carries one variant per enabled draft feature. With draft 16 the
            // only one enabled the arm above is exhaustive and this rejection arm unreachable.
            // Compiled in every configuration with the lint allowed, rather than gated on a `cfg`
            // naming the other thirteen drafts: such a list has to be edited in every draft module
            // whenever a draft is added, and a copy that omits one leaves this match
            // non-exhaustive.
            #[allow(unreachable_patterns)]
            _ => Err(ConnectionError::ControlMessageNarrowing),
        }
    }

    /// Read and dispatch the next incoming control message through the
    /// endpoint state machine. Returns the decoded message for inspection.
    pub async fn recv_and_dispatch(&mut self) -> Result<ControlMessage, ConnectionError> {
        let msg = self.recv_control().await?;
        self.endpoint.receive_message(msg.clone()).map_err(|e| self.close_if_session_fatal(e))?;

        // Emit draining event if this was a GoAway
        if let ControlMessage::GoAway(ref ga) = msg {
            self.emit(ClientEvent::Draining { new_session_uri: ga.new_session_uri.clone() });
        }

        Ok(msg)
    }

    // -- Subscribe flow ---------------------------------------------

    /// Send a SUBSCRIBE and return the allocated request ID.
    pub async fn subscribe(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        parameters: Vec<KeyValuePair>,
    ) -> Result<VarInt, ConnectionError> {
        let (req_id, msg) = self.endpoint.subscribe(track_namespace, track_name, parameters)?;
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
        track_extensions: Vec<KeyValuePair>,
        parameters: Vec<KeyValuePair>,
    ) -> Result<(), ConnectionError> {
        let msg = self.endpoint.send_subscribe_ok(
            request_id,
            track_alias,
            track_extensions,
            parameters,
        )?;
        self.send_control(&msg).await
    }

    /// Refuse a request the peer opened, sending REQUEST_ERROR.
    ///
    /// One message refuses a SUBSCRIBE or a FETCH, and the endpoint finds
    /// which by the identifier. It refuses a second answer to either, and
    /// refuses a Joining Fetch's refusal under any code but the one the draft
    /// names for it, so nothing is written on the wire when it does.
    pub async fn request_error(
        &mut self,
        request_id: VarInt,
        error_code: VarInt,
        retry_interval: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<(), ConnectionError> {
        let msg = self.endpoint.send_request_error(
            request_id,
            error_code,
            retry_interval,
            reason_phrase,
        )?;
        self.send_control(&msg).await
    }

    /// Narrow a subscription this endpoint opened, sending REQUEST_UPDATE, and
    /// return the Request ID the update itself spent.
    pub async fn request_update(
        &mut self,
        existing_request_id: VarInt,
        parameters: Vec<KeyValuePair>,
    ) -> Result<VarInt, ConnectionError> {
        let (request_id, msg) = self.endpoint.request_update(existing_request_id, parameters)?;
        self.send_control(&msg).await?;
        Ok(request_id)
    }

    /// Accept a PUBLISH the peer sent, which establishes the subscription it
    /// opened.
    ///
    /// The endpoint refuses a second answer to one PUBLISH, so nothing is
    /// written on the wire when it does.
    pub async fn publish_ok(
        &mut self,
        request_id: VarInt,
        parameters: Vec<KeyValuePair>,
    ) -> Result<(), ConnectionError> {
        let msg = self.endpoint.send_publish_ok(request_id, parameters)?;
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
        retry_interval: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<(), ConnectionError> {
        let msg = self.endpoint.send_publish_error(
            request_id,
            error_code,
            retry_interval,
            reason_phrase,
        )?;
        self.send_control(&msg).await
    }

    // -- Fetch flow -------------------------------------------------

    /// Send a standalone FETCH and return the allocated request ID.
    #[allow(clippy::too_many_arguments)]
    pub async fn fetch(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        start_group: VarInt,
        start_object: VarInt,
        end_group: VarInt,
        end_object: VarInt,
        parameters: Vec<KeyValuePair>,
    ) -> Result<VarInt, ConnectionError> {
        let (req_id, msg) = self.endpoint.fetch(
            track_namespace,
            track_name,
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
    /// `joining_start` counts groups back from the subscription's largest
    /// group. To name the starting group outright, use
    /// [`absolute_joining_fetch`](Self::absolute_joining_fetch).
    pub async fn joining_fetch(
        &mut self,
        joining_request_id: VarInt,
        joining_start: VarInt,
        parameters: Vec<KeyValuePair>,
    ) -> Result<VarInt, ConnectionError> {
        let (req_id, msg) =
            self.endpoint.joining_fetch(joining_request_id, joining_start, parameters)?;
        self.send_control(&msg).await?;
        Ok(req_id)
    }

    /// Send an Absolute Joining Fetch and return the allocated request ID.
    ///
    /// Here `joining_start` is the group to begin at rather than an offset,
    /// which is what an application that knows the group it wants has: draft-16
    /// Section 9.16.2.1 has the publisher set the Start Location to
    /// {Joining Start, 0}.
    pub async fn absolute_joining_fetch(
        &mut self,
        joining_request_id: VarInt,
        joining_start: VarInt,
        parameters: Vec<KeyValuePair>,
    ) -> Result<VarInt, ConnectionError> {
        let (req_id, msg) =
            self.endpoint.absolute_joining_fetch(joining_request_id, joining_start, parameters)?;
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
        end_of_track: u8,
        end_group: VarInt,
        end_object: VarInt,
        parameters: Vec<KeyValuePair>,
        track_extensions: Vec<KeyValuePair>,
    ) -> Result<(), ConnectionError> {
        let msg = self.endpoint.send_fetch_ok(
            request_id,
            end_of_track,
            end_group,
            end_object,
            parameters,
            track_extensions,
        )?;
        self.send_control(&msg).await
    }

    // -- Namespace flows --------------------------------------------

    /// Send a SUBSCRIBE_NAMESPACE on a bidirectional stream of its own.
    ///
    /// Section 6.1: "The subscriber sends SUBSCRIBE_NAMESPACE on a new
    /// bidirectional stream and the publisher MUST send a single REQUEST_OK or
    /// REQUEST_ERROR as the first message on the bidirectional stream in
    /// response to a SUBSCRIBE_NAMESPACE." Every other draft-16 request is
    /// still written on the control stream; this is the one that is not.
    ///
    /// The returned [`NamespaceStream`] **must be held while the subscription
    /// is live**. Section 6.1 makes closing the stream the cancellation, so
    /// letting the handle fall out of scope withdraws the subscription — see
    /// the type's own note.
    ///
    /// `subscribe_options` selects what the publisher reports back: PUBLISH
    /// (0x00), NAMESPACE (0x01) or both (0x02), per Section 9.25.
    ///
    /// # Ordering
    ///
    /// The stream is opened before the Request ID is allocated, because a
    /// failed open would otherwise burn an id the endpoint cannot retract. If
    /// the endpoint refuses the request the stream is reset rather than
    /// dropped: dropping would FIN it, which on this draft says a
    /// subscription that was never made has been withdrawn.
    pub async fn subscribe_namespace(
        &mut self,
        namespace_prefix: TrackNamespace,
        subscribe_options: VarInt,
        parameters: Vec<KeyValuePair>,
    ) -> Result<NamespaceStream, ConnectionError> {
        let (send, recv) = self.transport.open_bi().await?;
        let mut send = FramedSendStream::new(send, self.draft);
        let mut recv = FramedRecvStream::new(recv, self.draft);

        let (req_id, msg) = match self.endpoint.subscribe_namespace(
            namespace_prefix,
            subscribe_options,
            parameters,
        ) {
            Ok(built) => built,
            Err(e) => {
                let _ = send.reset(STREAM_ABANDONED);
                let _ = recv.stop(STREAM_ABANDONED);
                return Err(ConnectionError::Endpoint(e));
            }
        };

        let stream_id = send.stream_id();
        self.emit(ClientEvent::StreamOpened {
            direction: Direction::Send,
            stream_kind: StreamKind::NamespaceSubscription,
            stream_id,
        });
        let any = AnyControlMessage::Draft16(msg);
        let raw = match send.write_control(&any).await {
            Ok(raw) => raw,
            Err(e) => {
                let _ = send.reset(STREAM_ABANDONED);
                let _ = recv.stop(STREAM_ABANDONED);
                return Err(e);
            }
        };
        self.emit(ClientEvent::ControlMessage {
            direction: Direction::Send,
            message: any,
            stream_id: Some(stream_id),
            raw: Some(raw),
        });
        Ok(NamespaceStream {
            send,
            recv,
            request_id: req_id,
            draft: self.draft,
            stream_id,
            origin: RequestOrigin::Local,
            closed: false,
            responded: false,
        })
    }

    /// Accept the next bidirectional stream the peer opened, read the
    /// SUBSCRIBE_NAMESPACE it begins with, and hand back that request and a
    /// handle to answer it on.
    ///
    /// The mirror of [`subscribe_namespace`](Self::subscribe_namespace).
    /// Section 3.3 does not say who may open the second kind of bidirectional
    /// stream, and a relay subscribing to what a client publishes is the
    /// ordinary case, so a client that never calls this can never be asked for
    /// its namespaces.
    ///
    /// The returned [`NamespaceStream`] carries [`RequestOrigin::Peer`].
    /// Answer it with
    /// [`respond_ok_on_namespace_stream`](Self::respond_ok_on_namespace_stream)
    /// or
    /// [`respond_error_on_namespace_stream`](Self::respond_error_on_namespace_stream),
    /// and **hold it for as long as the subscription lasts** — every NAMESPACE
    /// and NAMESPACE_DONE is written on it, and dropping it ends the
    /// subscription.
    ///
    /// # Two refusals, two codes
    ///
    /// Section 3.3, on a stream that begins with the wrong type:
    /// "Bidirectional streams MUST NOT begin with any other message type
    /// unless negotiated. If they do, the peer MUST close the Session with a
    /// Protocol Violation." Section 9.1, on the Request ID: "If an endpoint
    /// receives a Request ID that is not valid for the peer, or a new request
    /// with a Request ID that is not the next in sequence or exceeds the
    /// received MAX_REQUEST_ID, it MUST close the session with
    /// INVALID_REQUEST_ID." Both are closes of the session on the
    /// wire, with different codes, and both happen before this returns — the
    /// error handed back reports a session that is already gone, not one the
    /// caller must remember to close.
    ///
    /// The refusal cannot be built without the acceptance. An endpoint that
    /// took a bidirectional stream only to refuse everything on it would close
    /// sessions over the SUBSCRIBE_NAMESPACE the same sentence permits.
    ///
    /// # Cancelling this future loses nothing
    ///
    /// A stream taken off the transport but not yet read is put back on an
    /// internal queue, and the next call takes it before accepting anything
    /// new — including whatever bytes of the request had already arrived,
    /// which live in the stream's own reader. So this is safe to `select!`
    /// against a shutdown signal or a timer. See
    /// [`pending_inbound_count`](Self::pending_inbound_count).
    ///
    /// What it is **not** safe to do is run concurrently with another method
    /// on the same connection: this takes `&mut self` because registering the
    /// peer's request moves endpoint state.
    ///
    /// # Ordering
    ///
    /// The endpoint is told about the request last, after every step that can
    /// fail or be cancelled, and building the handle afterwards cannot fail.
    /// Registering earlier would let a cancelled accept leave a state machine
    /// keyed to a stream nobody holds, and the peer's next Request ID would
    /// then look out of sequence — a session close, over an id the peer used
    /// exactly once.
    ///
    /// # Errors
    ///
    /// - [`ConnectionError::NonSubscribeNamespaceOnBidiStream`] — the session
    ///   has been closed with PROTOCOL_VIOLATION and the stream reset.
    /// - [`ConnectionError::Endpoint`] carrying `RequestId` — the session has
    ///   been closed with INVALID_REQUEST_ID and the stream reset.
    /// - [`ConnectionError::Endpoint`] carrying `NotActive` or `Draining` —
    ///   the stream is reset, the session is left alone.
    /// - [`ConnectionError::Transport`] or [`ConnectionError::Codec`] — the
    ///   stream is reset, the session is left alone.
    pub async fn accept_namespace_stream(
        &mut self,
    ) -> Result<(ControlMessage, NamespaceStream), ConnectionError> {
        let pair = match self.take_pending_inbound() {
            Some(pair) => pair,
            None => {
                let (send, recv) = self.transport.accept_bi().await?;
                (FramedSendStream::new(send, self.draft), FramedRecvStream::new(recv, self.draft))
            }
        };
        let capture_raw = self.observer.is_some();

        let (any, raw, mut send, mut recv) = {
            let mut pending = PendingInbound { pair: Some(pair), queue: &self.pending_inbound };
            let read = {
                let (_, recv) = pending.pair.as_mut().expect("set on construction");
                recv.read_control(capture_raw).await
            };
            // Taken out before anything can return, so the guard's Drop puts
            // the pair back for exactly one reason: this future was cancelled.
            let (mut send, mut recv) = pending.pair.take().expect("set on construction");
            match read {
                Ok((any, raw)) => (any, raw, send, recv),
                Err(e) => {
                    // A stream whose first message could not be read is not
                    // worth queueing: the next accept would fail on it the
                    // same way. Reset rather than FIN — nothing was served.
                    let _ = send.reset(STREAM_ABANDONED);
                    let _ = recv.stop(STREAM_ABANDONED);
                    return Err(e);
                }
            }
        };

        // Reported once the request has actually arrived rather than when the
        // stream came off the transport, so a cancelled accept that is retried
        // does not report the same stream twice.
        let stream_id = send.stream_id();
        self.emit(ClientEvent::StreamOpened {
            direction: Direction::Receive,
            stream_kind: StreamKind::NamespaceSubscription,
            stream_id,
        });
        if capture_raw {
            self.emit(ClientEvent::ControlMessage {
                direction: Direction::Receive,
                message: any.clone(),
                stream_id: Some(stream_id),
                raw,
            });
        }

        let msg = match any {
            AnyControlMessage::Draft16(msg) => msg,
            // `AnyControlMessage` carries one variant per enabled draft feature. With draft 16 the
            // only one enabled the arm above is exhaustive and this rejection arm unreachable.
            // Compiled in every configuration with the lint allowed, rather than gated on a `cfg`
            // naming the other thirteen drafts: such a list has to be edited in every draft module
            // whenever a draft is added, and a copy that omits one leaves this match
            // non-exhaustive.
            #[allow(unreachable_patterns)]
            _ => {
                let _ = send.reset(STREAM_ABANDONED);
                let _ = recv.stop(STREAM_ABANDONED);
                return Err(ConnectionError::ControlMessageNarrowing);
            }
        };

        let ty = msg.message_type();
        if ty != MessageType::SubscribeNamespace {
            let err = self.endpoint.refuse_non_subscribe_namespace(ty);
            self.close_for(&err);
            let _ = send.reset(STREAM_ABANDONED);
            let _ = recv.stop(STREAM_ABANDONED);
            return Err(ConnectionError::NonSubscribeNamespaceOnBidiStream(ty));
        }

        let request_id = match self.endpoint.receive_subscribe_namespace_on_stream(&msg) {
            Ok(request_id) => request_id,
            Err(e) => {
                let _ = send.reset(STREAM_ABANDONED);
                let _ = recv.stop(STREAM_ABANDONED);
                return Err(self.close_if_session_fatal(e));
            }
        };

        Ok((
            msg,
            NamespaceStream {
                send,
                recv,
                request_id,
                draft: self.draft,
                stream_id,
                origin: RequestOrigin::Peer,
                closed: false,
                responded: false,
            },
        ))
    }

    /// Take the oldest stream pair a cancelled
    /// [`accept_namespace_stream`](Self::accept_namespace_stream) put back, if
    /// any.
    ///
    /// Synchronous on purpose: the guard is dropped before the caller awaits,
    /// so the lock is never held across a suspension point.
    fn take_pending_inbound(&self) -> Option<(FramedSendStream, FramedRecvStream)> {
        self.pending_inbound.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).pop_front()
    }

    /// How many peer-opened namespace streams a cancelled
    /// [`accept_namespace_stream`](Self::accept_namespace_stream) put back and
    /// a later call has not yet taken.
    ///
    /// Zero unless an accept future was dropped mid-read.
    pub fn pending_inbound_count(&self) -> usize {
        self.pending_inbound.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).len()
    }

    /// Read the next message off a namespace subscription's stream and
    /// dispatch it through the endpoint.
    ///
    /// Three things can come back, and each is one of the shapes Section 6.1
    /// and Section 9.25 describe:
    ///
    /// - `Ok(Some(msg))` — a REQUEST_OK or REQUEST_ERROR answering the
    ///   subscription, or a NAMESPACE or NAMESPACE_DONE reporting on it.
    /// - `Ok(None)` — the peer finished its half with a FIN. Section 6.1 makes
    ///   that a cancellation, and it is recorded here.
    /// - `Err` carrying [`TransportError::StreamReset`] — the peer reset the
    ///   stream, the other form of the same cancellation, also recorded.
    ///
    /// This blocks until a whole message has arrived. Backpressure is per
    /// subscription: a stream nobody reads stays unread, and the peer stays
    /// flow controlled on it alone.
    ///
    /// # A stream the peer opened reports but does not dispatch
    ///
    /// Draft-16 places nothing after the SUBSCRIBE_NAMESPACE on the
    /// subscriber's half, so on a [`RequestOrigin::Peer`] stream there is no
    /// state for a second message to move and none is attempted; what a
    /// responder reads for is the peer's FIN. A message that arrives anyway is
    /// handed back rather than refused, because no sentence in this draft
    /// forbids it.
    ///
    /// # Errors
    ///
    /// [`ConnectionError::Endpoint`] if the message does not fit the
    /// subscription's state, or names a different request than this stream
    /// carries. The message has already been emitted to the observer by
    /// then — what arrived is reported whether or not the endpoint accepts it.
    pub async fn recv_on_namespace_stream(
        &mut self,
        stream: &mut NamespaceStream,
    ) -> Result<Option<ControlMessage>, ConnectionError> {
        let capture_raw = self.observer.is_some();
        let read = match stream.recv.read_control_or_end(capture_raw).await {
            Ok(read) => read,
            Err(e) => {
                // A peer that reset this stream cancelled the subscription on
                // it, and this is where a caller reading normally learns of
                // it. The record is made and its verdict dropped: the read's
                // own error is what the caller has to act on, and returning a
                // state error in its place would hide a reset behind it.
                if matches!(e, ConnectionError::Transport(TransportError::StreamReset(_))) {
                    let _ = self.endpoint.cancel_namespace_subscription(stream.request_id);
                }
                return Err(e);
            }
        };
        let Some((any, raw)) = read else {
            // The other half of Section 6.1's sentence. Recorded the same way
            // and for the same reason as the reset above.
            let _ = self.endpoint.cancel_namespace_subscription(stream.request_id);
            return Ok(None);
        };
        if capture_raw {
            self.emit(ClientEvent::ControlMessage {
                direction: Direction::Receive,
                message: any.clone(),
                stream_id: Some(stream.stream_id),
                raw,
            });
        }
        let msg = match any {
            AnyControlMessage::Draft16(msg) => Ok::<_, ConnectionError>(msg),
            // `AnyControlMessage` carries one variant per enabled draft feature. With draft 16 the
            // only one enabled the arm above is exhaustive and this rejection arm unreachable.
            // Compiled in every configuration with the lint allowed, rather than gated on a `cfg`
            // naming the other thirteen drafts: such a list has to be edited in every draft module
            // whenever a draft is added, and a copy that omits one leaves this match
            // non-exhaustive.
            #[allow(unreachable_patterns)]
            _ => Err(ConnectionError::ControlMessageNarrowing),
        }?;
        if stream.origin == RequestOrigin::Local {
            self.endpoint
                .receive_on_namespace_stream(stream.request_id, &msg)
                .map_err(|e| self.close_if_session_fatal(e))?;
        }
        Ok(Some(msg))
    }

    /// Write a message on an open namespace subscription stream.
    ///
    /// This is for what follows the answer: Section 9.25 says the publisher
    /// "will send matching NAMESPACE messages on the response stream if they
    /// are requested", and NAMESPACE_DONE withdraws one of them on the same
    /// stream. The answer itself has its own helpers, which drive the endpoint
    /// as well as the wire.
    ///
    /// It does not refuse any message type: which messages may follow the
    /// answer is not something this implementation can settle, so the choice
    /// is left to the caller rather than guessed at.
    pub async fn send_on_namespace_stream(
        &mut self,
        stream: &mut NamespaceStream,
        msg: &ControlMessage,
    ) -> Result<(), ConnectionError> {
        let any = AnyControlMessage::Draft16(msg.clone());
        let raw = stream.send.write_control(&any).await?;
        self.emit(ClientEvent::ControlMessage {
            direction: Direction::Send,
            message: any,
            stream_id: Some(stream.stream_id),
            raw: Some(raw),
        });
        Ok(())
    }

    /// Accept the peer's SUBSCRIBE_NAMESPACE with a REQUEST_OK on its own
    /// stream.
    ///
    /// Section 6.1: "the publisher MUST send a single REQUEST_OK or
    /// REQUEST_ERROR as the first message on the bidirectional stream in
    /// response to a SUBSCRIBE_NAMESPACE." The Request ID is taken from the
    /// stream rather than from the caller, which is what makes the correlation
    /// unforgeable.
    ///
    /// The endpoint goes first and the message is written only if it agrees.
    ///
    /// # Errors
    ///
    /// [`ConnectionError::NotOursToAnswer`] if `stream` was opened by this
    /// endpoint, and [`ConnectionError::Endpoint`] if the subscription has
    /// already been answered or has ended.
    pub async fn respond_ok_on_namespace_stream(
        &mut self,
        stream: &mut NamespaceStream,
        parameters: Vec<KeyValuePair>,
    ) -> Result<(), ConnectionError> {
        self.respond_on_namespace_stream(
            stream,
            ControlMessage::RequestOk(RequestOk { request_id: stream.request_id, parameters }),
        )
        .await
    }

    /// Refuse the peer's SUBSCRIBE_NAMESPACE with a REQUEST_ERROR on its own
    /// stream, and finish the stream.
    ///
    /// Section 9.25 says what follows the refusal: "If it is an error, the
    /// stream will be immediately closed via FIN." So this writes and then
    /// finishes, and the handle is closed when it returns.
    ///
    /// # Errors
    ///
    /// As [`respond_ok_on_namespace_stream`](Self::respond_ok_on_namespace_stream).
    pub async fn respond_error_on_namespace_stream(
        &mut self,
        stream: &mut NamespaceStream,
        error_code: VarInt,
        retry_interval: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<(), ConnectionError> {
        self.respond_on_namespace_stream(
            stream,
            ControlMessage::RequestError(RequestError {
                request_id: stream.request_id,
                error_code,
                retry_interval,
                reason_phrase,
            }),
        )
        .await?;
        stream.finish().await
    }

    /// Drive the endpoint, then write the answer.
    ///
    /// The order is the one every request path here uses: a caller acts on a
    /// stream after the endpoint has accepted the step, never before.
    async fn respond_on_namespace_stream(
        &mut self,
        stream: &mut NamespaceStream,
        msg: ControlMessage,
    ) -> Result<(), ConnectionError> {
        if stream.origin != RequestOrigin::Peer {
            return Err(ConnectionError::NotOursToAnswer(stream.request_id.into_inner()));
        }
        // Which of the two answers this is, and the code it carries, are both
        // in the message, so nothing else has to be told them.
        let refusal_code = match &msg {
            ControlMessage::RequestError(e) => Some(e.error_code),
            _ => None,
        };
        let driven = self.endpoint.respond_on_namespace_stream(stream.request_id, refusal_code);
        driven.map_err(|e| self.close_if_session_fatal(e))?;
        let any = AnyControlMessage::Draft16(msg);
        let raw = stream.send.write_control(&any).await?;
        stream.responded = true;
        self.emit(ClientEvent::ControlMessage {
            direction: Direction::Send,
            message: any,
            stream_id: Some(stream.stream_id),
            raw: Some(raw),
        });
        Ok(())
    }

    /// Withdraw a namespace subscription by resetting its stream: record it at
    /// the endpoint, then reset.
    ///
    /// Section 6.1 puts the withdrawal at the stream — "A SUBSCRIBE_NAMESPACE
    /// can be cancelled by closing the stream with either a FIN or
    /// RESET_STREAM" — while the subscription's own state lives in the
    /// endpoint, so the two have to move together. This and
    /// [`finish_namespace_stream`](Self::finish_namespace_stream) are the only
    /// places that move both.
    ///
    /// The endpoint goes first and the stream is reset only if it agrees. A
    /// refused withdrawal therefore leaves the stream exactly as it was, and
    /// [`NamespaceStream::cancel`] is still there for a caller that wants the
    /// stream reset regardless.
    ///
    /// Idempotent from both ends: a subscription that has already ended
    /// accepts it and stays where it is, and a handle that is already closed
    /// resets nothing a second time.
    ///
    /// # Errors
    ///
    /// [`ConnectionError::Endpoint`] if no namespace subscription carries this
    /// stream's id or nothing was ever written on it, and
    /// [`ConnectionError::Transport`] if `code` is outside the QUIC varint
    /// range — see [`NamespaceStream::cancel`], which is what sends it.
    pub fn cancel_namespace_stream(
        &mut self,
        stream: &mut NamespaceStream,
        code: u64,
    ) -> Result<(), ConnectionError> {
        let recorded = self.endpoint.cancel_namespace_subscription(stream.request_id);
        recorded.map_err(|e| self.close_if_session_fatal(e))?;
        stream.cancel(code)
    }

    /// Withdraw a namespace subscription by finishing its stream: record it at
    /// the endpoint, then FIN.
    ///
    /// The other form Section 6.1 allows, and the one that needs no error
    /// code. See [`cancel_namespace_stream`](Self::cancel_namespace_stream)
    /// for the ordering and the idempotence, which are the same.
    pub async fn finish_namespace_stream(
        &mut self,
        stream: &mut NamespaceStream,
    ) -> Result<(), ConnectionError> {
        let recorded = self.endpoint.cancel_namespace_subscription(stream.request_id);
        recorded.map_err(|e| self.close_if_session_fatal(e))?;
        stream.finish().await
    }

    /// Wait for the peer to reset this subscription's stream, and record it if
    /// it does.
    ///
    /// [`NamespaceStream::peer_cancelled`] with the endpoint's record
    /// attached. A caller applying backpressure is deliberately not calling
    /// [`recv_on_namespace_stream`](Self::recv_on_namespace_stream), which is
    /// the other place a peer reset surfaces, so without this the subscription
    /// would end on the wire and stay open in the endpoint's record for as
    /// long as the backpressure lasts.
    ///
    /// It sees a reset and not a FIN — see
    /// [`NamespaceStream::peer_cancelled`]. Cancel-safe, and it grants no
    /// flow-control credit.
    pub async fn peer_cancelled_on_namespace_stream(
        &mut self,
        stream: &mut NamespaceStream,
    ) -> Result<Option<u64>, ConnectionError> {
        let code = stream.peer_cancelled().await?;
        if code.is_some() {
            // Discarded for the reason the read path discards it: the peer has
            // ended the subscription whatever the record said, and a state
            // error here would replace the answer the caller asked for.
            let _ = self.endpoint.cancel_namespace_subscription(stream.request_id);
        }
        Ok(code)
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

    /// Accept a request the peer opened, sending REQUEST_OK.
    ///
    /// The endpoint refuses a second answer to one request, so nothing is
    /// written on the wire when it does. On this draft an announcement and a
    /// track status are the requests REQUEST_OK accepts; a subscription, a
    /// publication and a fetch each have an acceptance of their own that
    /// carries more than this one can.
    pub async fn request_ok(
        &mut self,
        request_id: VarInt,
        parameters: Vec<KeyValuePair>,
    ) -> Result<(), ConnectionError> {
        let msg = self.endpoint.send_request_ok(request_id, parameters)?;
        self.send_control(&msg).await
    }

    /// Revoke an acceptance, sending PUBLISH_NAMESPACE_CANCEL.
    ///
    /// The endpoint refuses one for an announcement it never accepted, so
    /// nothing is written on the wire when it does.
    pub async fn publish_namespace_cancel(
        &mut self,
        request_id: VarInt,
        error_code: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<(), ConnectionError> {
        let msg = self.endpoint.publish_namespace_cancel(request_id, error_code, reason_phrase)?;
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
        request_id: VarInt,
    ) -> Result<(), ConnectionError> {
        let msg = self.endpoint.publish_namespace_done(request_id)?;
        self.send_control(&msg).await
    }
    // -- Track Status flow ------------------------------------------

    /// Send a TRACK_STATUS and return the allocated request ID.
    pub async fn track_status(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        parameters: Vec<KeyValuePair>,
    ) -> Result<VarInt, ConnectionError> {
        let (req_id, msg) = self.endpoint.track_status(track_namespace, track_name, parameters)?;
        self.send_control(&msg).await?;
        Ok(req_id)
    }

    // -- Publish flow (publisher side) ------------------------------

    /// Send a PUBLISH and return the allocated request ID.
    pub async fn publish(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        track_alias: VarInt,
        track_extensions: Vec<KeyValuePair>,
        parameters: Vec<KeyValuePair>,
    ) -> Result<VarInt, ConnectionError> {
        let (req_id, msg) = self.endpoint.publish(
            track_namespace,
            track_name,
            track_alias,
            track_extensions,
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
        stream_count: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<(), ConnectionError> {
        let msg = self.endpoint.send_publish_done(
            request_id,
            status_code,
            stream_count,
            reason_phrase,
        )?;
        self.send_control(&msg).await
    }

    // -- Data streams -----------------------------------------------

    /// Open a new unidirectional stream for sending subgroup data.
    pub async fn open_subgroup_stream(
        &self,
        header: &AnySubgroupHeader,
    ) -> Result<FramedSendStream, ConnectionError> {
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

    /// Accept the next unidirectional stream and read its fetch header.
    ///
    /// [`accept_subgroup_stream`](Self::accept_subgroup_stream)'s twin. The two
    /// are separate because the header decides how every object after it is
    /// framed, so a caller has to know which it is expecting before the first
    /// byte is read.
    ///
    /// Objects come off the returned stream with
    /// [`FramedRecvStream::read_fetch_object`].
    pub async fn accept_fetch_stream(
        &self,
    ) -> Result<(AnyFetchHeader, FramedRecvStream), ConnectionError> {
        let recv = self.transport.accept_uni().await?;
        let mut framed = FramedRecvStream::new(recv, self.draft);
        let sid = framed.stream_id();
        let header = framed.read_fetch_header().await?;
        self.emit(ClientEvent::StreamOpened {
            direction: Direction::Receive,
            stream_kind: StreamKind::Fetch,
            stream_id: sid,
        });
        self.emit(ClientEvent::FetchStreamHeader {
            stream_id: sid,
            direction: Direction::Receive,
            header: header.clone(),
        });
        // A fetch header goes out as `FetchStreamHeader`; `DataStreamHeader`
        // carries an `AnySubgroupHeader` and cannot express one. What
        // `accept_subgroup_stream` does beyond this - the forwarding-preference
        // note, the object measurement - is about a subgroup and has no
        // counterpart on a fetch stream.
        Ok((header, framed))
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
        // The track is resolved here and not inside the stream: it takes the
        // endpoint's alias table, which a stream handle has no way back to.
        // Handed over rather than offered, so measuring is not something a
        // caller has to remember to ask for.
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

    /// Send the messages Section 2.4.2 asks for when a track is found
    /// Send the messages Section 2.4.2 asks for when a track is found
    /// malformed, and stop at the first one the control stream refuses.
    ///
    /// "When a subscriber detects a Malformed Track, it MUST UNSUBSCRIBE any
    /// subscription and FETCH_CANCEL any fetch for that Track from that
    /// publisher" - one message per request, in Request ID order, and the
    /// endpoint decides which message each request takes.
    ///
    /// A write that fails is not reported. The caller is on its way to
    /// returning an error that says what went wrong with the track, and a
    /// control stream that will not take an UNSUBSCRIBE is a session on its way
    /// out for a reason of its own; replacing the condition's report with a
    /// transport error would lose the only account of why the track was
    /// withdrawn. The rest of the withdrawal is abandoned, because a stream
    /// that refused one message will refuse the next.
    async fn withdraw_malformed_track(&self, alias: u64, condition: MalformedTrackCondition) {
        for msg in self.endpoint.withdraw_malformed_track(alias, condition) {
            if self.send_control(&msg).await.is_err() {
                break;
            }
        }
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

    /// Close the session when a failure raised while reading a *data* stream is
    /// one draft-16 answers with a close. Reports whether it closed.
    ///
    /// [`accept_subgroup_stream`](Self::accept_subgroup_stream) hands the caller
    /// a [`FramedRecvStream`], which holds no connection and so cannot close
    /// one, and the read that raises this failure happens there. The caller is
    /// the only party holding both halves, which is what this is for.
    ///
    /// Splitting it this way rather than closing inside the reader keeps a
    /// caller that is deliberately permissive — a tool reproducing a capture,
    /// say — able to read a violating stream and report it without tearing the
    /// session down. The rule is stated at endpoints, and this is where an
    /// endpoint decides it is one.
    ///
    /// Answers the extension-header rule of Section 10.2.1.2, and any decode
    /// failure `codec_session_error_code` recognises, so a rule is answered
    /// with one code whichever stream carried it.
    pub fn close_for_data_stream(&self, err: &ConnectionError) -> bool {
        use crate::above_codec_rules::DraftSpecificCause;

        match err {
            ConnectionError::Codec(inner) => {
                let Some(code) = Self::codec_session_error_code(inner) else { return false };
                let wire_code = u32::try_from(code.as_u64()).unwrap_or(u32::MAX);
                self.close(wire_code, inner.to_string().as_bytes());
                true
            }
            // Not a `Codec` failure: the codec decodes such an Object without
            // complaint, because the frame is well formed. It is being an
            // endpoint that makes it a violation, so the variant is this
            // crate's own and the mapping table above never sees it.
            //
            // The code comes from `draft_specific_cause` rather than from a
            // constant here, so this draft's reading of its own sentence is
            // written down once and a caller who reads the error as a value
            // sees the same code the peer was sent.
            ConnectionError::ExtensionsOnNonNormalStatus { .. } => {
                let Some(DraftSpecificCause::PeerViolation { close: Some(code), .. }) =
                    Self::draft_specific_cause(err)
                else {
                    return false;
                };
                // Saturate rather than truncate, so a future code above
                // `u32::MAX` is never reported as a different assigned one.
                self.close(u32::try_from(code).unwrap_or(u32::MAX), err.to_string().as_bytes());
                true
            }
            _ => false,
        }
    }

    // -- Accessors --------------------------------------------------

    /// Access the underlying endpoint state machine.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Mutable access to the endpoint state machine.
    pub fn endpoint_mut(&mut self) -> &mut Endpoint {
        &mut self.endpoint
    }

    /// The SETUP message the server answered the handshake with.
    ///
    /// `SERVER_SETUP` through draft-16, the server's half of the unified
    /// `SETUP` from draft-17. [`AnyControlMessage::fields`] renders it under
    /// this draft's own parameter names, in the order they arrived.
    pub fn server_setup(&self) -> &AnyControlMessage {
        &self.server_setup
    }

    /// The framed wire bytes of [`Self::server_setup`], as they arrived.
    ///
    /// Kept beside the decoded form because the encoding is evidence the
    /// decoding discards: two relays sending the same parameter can still
    /// disagree on how wide a varint they wrote it in.
    pub fn server_setup_raw(&self) -> Option<&[u8]> {
        self.server_setup_raw.as_deref()
    }

    /// Returns the draft version this connection is using.
    pub fn draft(&self) -> DraftVersion {
        self.draft
    }

    /// Which of this draft's *own* `ConnectionError` variants this error is,
    /// and which kind of thing it says.
    ///
    /// The ten every draft carries answer `None` here: [`AnyConnectionError`]
    /// classifies those itself, once, and never asks a draft about them. What
    /// is left splits two ways, and the split is the reason this function
    /// exists — before it, both halves reached a caller as a sentence and read
    /// exactly alike. A [`LocalRefusal`] is this endpoint declining to write
    /// something, so nothing reached the wire and no relay is implicated; a
    /// [`PeerViolation`] is a peer having done something draft-16 forbids, and
    /// carries the session error code draft-16's own text answers it with.
    ///
    /// Matched exhaustively, with no wildcard arm and deliberately so: a
    /// variant added to this draft's error type has to arrive here as a compile
    /// error, beside the doc comment quoting the sentence it enforces, rather
    /// than as a silent [`ErrorCause::Unclassified`] in the facade.
    ///
    /// [`AnyConnectionError`]: crate::dispatch::AnyConnectionError
    /// [`ErrorCause::Unclassified`]: crate::dispatch::ErrorCause::Unclassified
    /// [`LocalRefusal`]: crate::above_codec_rules::DraftSpecificCause::LocalRefusal
    /// [`PeerViolation`]: crate::above_codec_rules::DraftSpecificCause::PeerViolation
    pub fn draft_specific_cause(
        err: &ConnectionError,
    ) -> Option<crate::above_codec_rules::DraftSpecificCause> {
        use crate::above_codec_rules::{AboveCodecRule, DraftSpecificCause};
        use moqtap_codec::draft16::error_codes::SessionErrorCode;

        match err {
            ConnectionError::Endpoint(_)
            | ConnectionError::Codec(_)
            | ConnectionError::Transport(_)
            | ConnectionError::VarInt(_)
            | ConnectionError::NoControlStream
            | ConnectionError::UnexpectedEnd
            | ConnectionError::StreamFinished
            | ConnectionError::InvalidAddress(_)
            | ConnectionError::TlsConfig(_)
            | ConnectionError::DataStreamState(_) => None,
            // This build decoding a message and then failing to narrow it to
            // its own draft. Nothing reached the wire and no peer is
            // implicated, which is the whole reason it is not
            // `ConnectionError::Codec`: under that name it would carry
            // `Some(PROTOCOL_VIOLATION)` out of `codec_session_error_code` and
            // publish a relay for this build's defect. See the variant's own
            // doc.
            ConnectionError::ControlMessageNarrowing => {
                Some(crate::above_codec_rules::DraftSpecificCause::LocalRefusal)
            }
            // Section 3.3: a bidirectional stream may begin with CLIENT_SETUP
            // or SUBSCRIBE_NAMESPACE and nothing else, "unless negotiated. If
            // they do, the peer MUST close the Session with a Protocol
            // Violation." The session has already been closed on the wire by
            // the time this is returned, so the code is carried here for a
            // caller to read which rule was answered, not for it to answer one
            // again.
            ConnectionError::NonSubscribeNamespaceOnBidiStream(_) => {
                Some(DraftSpecificCause::PeerViolation {
                    rule: AboveCodecRule::BidiStreamOpener,
                    close: Some(SessionErrorCode::ProtocolViolation.as_u64()),
                })
            }
            // A `respond_*` helper pointed at a namespace subscription this
            // endpoint opened. Nothing was written and no state moved: the
            // answer to a SUBSCRIBE_NAMESPACE is owed by whoever received it.
            ConnectionError::NotOursToAnswer(_) => Some(DraftSpecificCause::LocalRefusal),
            // Section 10.2.1.2 states the rule and names the code in the same
            // sentence. The codec decodes such an Object without complaint —
            // the frame is well formed — so this layer is the only one that
            // can raise it, and `close_for_data_stream` performs the close by
            // reading this same answer.
            ConnectionError::ExtensionsOnNonNormalStatus { .. } => {
                Some(DraftSpecificCause::PeerViolation {
                    rule: AboveCodecRule::PropertiesOnNonNormalStatus,
                    close: Some(SessionErrorCode::ProtocolViolation.as_u64()),
                })
            }
        }
    }

    /// The code to close the session with when a control message could not be
    /// decoded because the peer broke a rule draft-16 answers with a close.
    ///
    /// Every variant listed here comes from a sentence in this draft that names
    /// the consequence, and the list is deliberately shorter than draft-17's:
    /// the bounds are per draft, and answering one this draft does not state
    /// would close a session over traffic a conforming peer may send.
    ///
    ///   - Reason Phrase, maximum 1024 bytes: "If an endpoint receives a length
    ///     exceeding the maximum, it MUST close the session with a
    ///     PROTOCOL_VIOLATION."
    ///   - KVP value, maximum 2^16-1 bytes, with the same sentence.
    ///   - Track Namespace field count: "If an endpoint receives a Track
    ///     Namespace consisting of 0 or greater than 32 Track Namespace Fields,
    ///     it MUST close the session with a PROTOCOL_VIOLATION." Note the lower
    ///     bound — an empty tuple is refused here, where drafts 17 and later
    ///     permit it.
    ///   - Full Track Name, maximum 4,096 bytes. This draft widened the rule from
    ///     draft-15's: "If an endpoint receives a Track Namespace or a Full
    ///     Track Name exceeding 4,096 bytes".
    ///   - Duplicate parameters, a SHOULD rather than a MUST: "Receivers SHOULD
    ///     check that there are no unexpected duplicate parameters and close the
    ///     session as a PROTOCOL_VIOLATION"
    ///   - A Track Namespace Field of length zero, which draft-15 does not
    ///     state: "Each Track Namespace Field Value MUST contain at least one
    ///     byte."
    ///   - The delta-encoded parameter type overflow, which arrives with this
    ///     draft along with delta encoding itself.
    ///
    ///   - GOAWAY New Session URI, maximum 8,192 bytes: "If an endpoint
    ///     receives a length exceeding the maximum, it MUST close the session
    ///     with a PROTOCOL_VIOLATION." Every draft from 11 to 19 states it; 07
    ///     through 10 state no maximum for the field at all.
    ///   - Unknown control message type: "An endpoint that receives an unknown
    ///     message type MUST close the session." All fourteen drafts state it,
    ///     in the same words, and the sentence names no code, so Protocol
    ///     Violation is what carries it.
    ///
    /// `None` for everything else, including [`CodecError::InvalidField`]. That
    /// variant is shared by a dozen unrelated malformations, only some of which
    /// the draft answers with a close, so treating it as fatal would close
    /// sessions the draft does not ask to be closed. Splitting it is the way to
    /// bring the rest of those rules under this function; widening the match is
    /// not.
    pub fn codec_session_error_code(
        err: &CodecError,
    ) -> Option<moqtap_codec::draft16::error_codes::SessionErrorCode> {
        use moqtap_codec::draft16::error_codes::SessionErrorCode;
        use moqtap_codec::kvp::KvpError;
        match err {
            // The declared Length disagreeing with the fields, which every
            // draft answers with a close. Drafts 07 through 10 name no code for
            // it, so it takes the one their other unnamed rules take.
            // A Filter Type outside the four this draft assigns, Section 5.1.2:
            // "An endpoint that receives a filter type other than the above MUST
            // close the session with PROTOCOL_VIOLATION."
            //
            // Drafts 07 through 14 carried the Filter Type as a field of
            // SUBSCRIBE. From draft-15 it is the first field inside the
            // length-prefixed filter parameter, where a codec that carries the
            // value as opaque bytes never reads it — the rule did not change and
            // the place it has to be enforced did.
            CodecError::InvalidFilterType(_) => Some(SessionErrorCode::ProtocolViolation),
            // A filter parameter whose value is not a filter, Section 9.2.2.5:
            // "It is a length-prefixed Subscription Filter... If the length of
            // the Subscription Filter does not match the parameter length, the
            // publisher MUST close the session with PROTOCOL_VIOLATION."
            //
            // The one key-value malformation this draft answers with something
            // other than KEY_VALUE_FORMATTING_ERROR. The general rule covers the
            // same bytes and names that code; the sentence above is the specific
            // one, so it governs. Drafts 17 and later drop it and leave only the
            // general rule, which is why the same malformation ends a session
            // there under a different code.
            CodecError::SubscriptionFilterMalformed { .. } => {
                Some(SessionErrorCode::ProtocolViolation)
            }
            // A Fetch Type outside the three this draft assigns: "An endpoint
            // that receives a Fetch Type other than 0x1, 0x2 or 0x3 MUST close
            // the session with a PROTOCOL_VIOLATION." The value decides which
            // fields follow it — a Standalone fetch carries a track name and a
            // range where a joining fetch carries a Request ID and an offset —
            // so a reader that cannot name the type cannot find the end of the
            // message.
            CodecError::InvalidFetchType(_) => Some(SessionErrorCode::ProtocolViolation),
            CodecError::ControlMessageLengthMismatch { .. } => {
                Some(SessionErrorCode::ProtocolViolation)
            }
            CodecError::KeyDeltaOverflow(..)
            | CodecError::DuplicateParameter(_)
            | CodecError::TrackNameTooLong
            | CodecError::InvalidNamespaceTupleSize(_)
            | CodecError::ReasonPhraseTooLong
            | CodecError::GoAwayUriTooLong
            | CodecError::UnknownMessageType(_)
            | CodecError::Kvp(KvpError::ValueTooLong(_))
            | CodecError::EmptyNamespaceField => Some(SessionErrorCode::ProtocolViolation),
            // An unknown data-plane type, Section 10: "An endpoint that
            // receives an unknown stream or datagram type MUST close the
            // session." One sentence covering two tables, which is why both
            // variants sit here.
            // A Message Parameter whose value is outside the range its type
            // allows: DELIVERY_TIMEOUT in Section 9.2.2.2, FORWARD in Section
            // 9.2.2.8, GROUP_ORDER in Section 9.2.2.4 and SUBSCRIBER_PRIORITY in
            // Section 9.2.2.3.
            // Each states that a receiver "MUST close the session with
            // PROTOCOL_VIOLATION".
            CodecError::ParameterValueOutOfRange { .. } => {
                Some(SessionErrorCode::ProtocolViolation)
            }
            // A Track Extension or Track Property whose value is outside the
            // range its type allows: DELIVERY_TIMEOUT in Section 11.1,
            // DEFAULT_PUBLISHER_GROUP_ORDER in Section 11.1.1.2 and DYNAMIC_GROUPS in
            // Section 11.1.1.3.
            // Each states that a receiver "MUST close the session with
            // PROTOCOL_VIOLATION".
            //
            // A separate arm from the parameter rule above because the two
            // registries are separate: 0x22 is GROUP_ORDER as a parameter and
            // DEFAULT_PUBLISHER_GROUP_ORDER as a Track Extension, and a log that
            // named only the number would not say which.
            CodecError::TrackPropertyValueOutOfRange { .. } => {
                Some(SessionErrorCode::ProtocolViolation)
            }
            CodecError::UnknownStreamType(_) | CodecError::UnknownDatagramType(_) => {
                Some(SessionErrorCode::ProtocolViolation)
            }
            // A Type inside a form this draft defines but on a list it names as
            // invalid: Section 10.4.2 for a subgroup header whose SUBGROUP_ID_MODE
            // is the reserved 0b11, Section 10.3.1 for a datagram asking to be both
            // an object status and an end-of-group marker. Unlike the rule above,
            // these two name their code outright.
            CodecError::InvalidTypeValue { .. } => Some(SessionErrorCode::ProtocolViolation),
            // A key-value pair whose value is not the serialization its own
            // Type defines, Section 1.4.2: "If a receiver understands a Type,
            // and the following Value or Length/Value does not match the
            // serialization defined by that Type, the receiver MUST close the
            // session with error code KEY_VALUE_FORMATTING_ERROR."
            //
            // Section 9.2.2.1 states the same answer for the one structure this
            // draft spells out: "If the Token structure cannot be decoded, the
            // receiver MUST close the Session with KEY_VALUE_FORMATTING_ERROR."
            //
            // The one rule in this table that names a code other than Protocol
            // Violation.
            CodecError::KeyValueFormatting { .. } => {
                Some(SessionErrorCode::KeyValueFormattingError)
            }
            // A Message Parameter whose type this draft does not define, Section
            // 9.2: "All Message Parameters MUST be defined in the negotiated
            // version of MOQT or negotiated via Setup Parameters. An endpoint that
            // receives an unknown Message Parameter MUST close the session with
            // PROTOCOL_VIOLATION."
            //
            // One namespace only. This draft also says a receiver ignores an
            // unrecognised Setup Parameter, so an unknown type in a SETUP is carried and
            // the codec never raises this for one.
            CodecError::UnknownMessageParameter(_) => Some(SessionErrorCode::ProtocolViolation),
            // Everything this draft does not answer, named rather than swept up
            // by a wildcard. The arm is exhaustive deliberately: a new
            // `CodecError` variant will not compile until it has been placed on
            // one side or the other, on this draft, which is the decision a `_`
            // arm makes silently and invisibly in every draft module at once.
            //
            // Adding one variant to `CodecError` produces an `E0004` in every
            // draft module that matches it exhaustively, each naming the
            // variant that has nowhere to go. That is the whole mechanism.
            //
            // The nesting stops at `VarInt`, whose variants report how the bytes
            // ran out rather than a rule an endpoint states, so there is nothing
            // in it for a draft to answer. `Kvp` is spelled out because it does
            // carry one.
            // Neither field exists from draft-15 on. Forwarding became the
            // FORWARD parameter, which carries the same rule in a different
            // shape and is answered above under its own variant; Content Exists
            // became the presence or absence of a LARGEST_OBJECT parameter.
            CodecError::InvalidForward(_)
            | CodecError::InvalidContentExists(_)
            | CodecError::UnexpectedEnd
            | CodecError::MessageTooLong(_)
            | CodecError::VarInt(_)
            | CodecError::InvalidField
            | CodecError::InvalidRange(..)
            | CodecError::ParameterLengthMismatch(_)
            | CodecError::EndOfTrackObjectId(_)
            | CodecError::ParametersOutOfOrder(..)
            | CodecError::ObjectIdOverflow(..)
            | CodecError::ExtensionsOnNonExistentObject(_)
            | CodecError::InvalidRequiredRequestIdDelta(..)
            // Not `ParameterOutOfScope`, even though this draft is the one that
            // starts closing over an unknown Message Parameter above. The scope
            // rule is a separate sentence and it keeps the older answer. Section
            // 9.2.2: "Each message parameter definition indicates the message types
            // in which it can appear. If it appears in some other type of message,
            // it MUST be ignored." The two halves part company at draft-17, which
            // is where the second sentence becomes a close, so this draft carries an
            // out-of-scope parameter and the codec never raises the variant here.
            | CodecError::ParameterOutOfScope { .. }
            // The End Group is written out in full on this draft, so there is
            // nothing to add and nothing to overflow. Drafts 17 and later
            // replaced it with a delta measured from the Start Location's Group,
            // and 18 and 19 close the session when the sum leaves the range.
            | CodecError::FilterEndGroupOverflow { .. }
            // The object payload rule, Section 10.2.1.1: "Any object with a status
            // code other than zero MUST have an empty payload." A MUST on the
            // sender with no receiver action named anywhere — the "SHOULD be
            // treated as a protocol error" in the same paragraph belongs to the
            // sentence before it, which is about a status value this draft does
            // not assign — so an object carrying a payload it may not is refused
            // and the session stays open.
            | CodecError::PayloadNotPermitted { .. }
            | CodecError::UnsupportedDraft(_)
            | CodecError::Kvp(
                KvpError::MissingLength | KvpError::UnexpectedEnd | KvpError::VarInt(_),
            ) => None,
        }
    }

    /// Close the session on the wire when a decode failure is one draft-16
    /// answers with a close, and hand the error back unchanged.
    /// Without it every bound the decoder enforces would stop at *this endpoint
    /// refused the frame* while the peer, which is the one that broke the rule,
    /// saw a session that was still open and went on sending. "MUST close the
    /// session with a PROTOCOL_VIOLATION" is a statement about the wire.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// This build failing to narrow a message it decoded is never a finding
    /// about the peer.
    ///
    /// The arm that raises `ControlMessageNarrowing` is unreachable — this
    /// draft's decoder can only hand back this draft's variant — and nothing
    /// pins that. What is pinned here is the half that matters.
    /// `CodecError::UnknownMessageType(0)` is what the arm must not raise:
    /// `codec_session_error_code` answers it `Some(PROTOCOL_VIOLATION)` on
    /// every draft in range, so the day the narrowing failed a conformance
    /// probe would publish a relay for sending a control message type this
    /// draft does not assign — with `0x00` attached as the codepoint that
    /// proved it, which is an accusation better evidenced than any real one
    /// this build makes. The section stating that rule is numbered differently
    /// on every draft, and the point does not turn on the number.
    ///
    /// Ablated by putting the arm back to
    /// `ConnectionError::Codec(CodecError::UnknownMessageType(0))`: this test
    /// reddens on the cause, and so does the probe's own
    /// `violation::a_message_this_build_could_not_narrow_names_nobody`.
    #[test]
    fn a_message_this_build_could_not_narrow_names_nobody() {
        use crate::dispatch::{AnyConnectionError, ErrorCause};

        let err: AnyConnectionError = ConnectionError::ControlMessageNarrowing.into();
        assert!(err.is_local(), "a narrowing this build could not do is this build's");
        assert_eq!(
            err.cause(),
            &ErrorCause::Facade,
            "nothing reached the wire, so there is no rule and no close code to read"
        );
    }

    #[test]
    fn varint_len_single_byte() {
        assert_eq!(varint_len(0x00), 1);
        assert_eq!(varint_len(0x3F), 1);
    }

    #[test]
    fn varint_len_two_bytes() {
        assert_eq!(varint_len(0x40), 2);
        assert_eq!(varint_len(0x7F), 2);
    }

    #[test]
    fn varint_len_four_bytes() {
        assert_eq!(varint_len(0x80), 4);
        assert_eq!(varint_len(0xBF), 4);
    }

    #[test]
    fn varint_len_eight_bytes() {
        assert_eq!(varint_len(0xC0), 8);
        assert_eq!(varint_len(0xFF), 8);
    }

    #[test]
    fn client_config_alpn_quic_draft16() {
        let config = ClientConfig {
            draft: DraftVersion::Draft16,
            transport: TransportType::Quic,
            skip_cert_verification: false,
            ca_certs: Vec::new(),
            setup_parameters: Vec::new(),
        };
        assert_eq!(config.alpn(), vec![b"moqt-16".to_vec()]);
    }

    #[test]
    fn client_config_alpn_webtransport() {
        let config = ClientConfig {
            draft: DraftVersion::Draft16,
            transport: TransportType::WebTransport { url: "https://example.com".to_string() },
            skip_cert_verification: false,
            ca_certs: Vec::new(),
            setup_parameters: Vec::new(),
        };
        assert_eq!(config.alpn(), vec![b"h3".to_vec()]);
    }

    /// `MOQT_ALPN` is the ALPN a client configured for this draft offers.
    ///
    /// Putting `moq-00` back — the value this constant held on all five of
    /// drafts 15-19 — fails with:
    ///
    /// ```text
    /// assertion `left == right` failed: MOQT_ALPN is "moq-00"; a draft-19 client offers ["moqt-19"]
    /// ```
    #[test]
    fn moqt_alpn_is_the_one_a_client_offers() {
        // A literal on its own is what let this constant keep `moq-00` for
        // five drafts after draft-15 stopped using it, so the value is
        // checked against what a client configured for this draft actually
        // puts on the wire, and only then against the literal.
        let config = ClientConfig {
            draft: DraftVersion::Draft16,
            transport: TransportType::Quic,
            skip_cert_verification: false,
            ca_certs: Vec::new(),
            setup_parameters: Vec::new(),
        };
        assert_eq!(
            config.alpn(),
            vec![MOQT_ALPN.to_vec()],
            "MOQT_ALPN is {:?}; a draft-{} client offers {:?}",
            String::from_utf8_lossy(MOQT_ALPN),
            16,
            config
                .alpn()
                .iter()
                .map(|a| String::from_utf8_lossy(a).into_owned())
                .collect::<Vec<_>>(),
        );
        assert_eq!(MOQT_ALPN, b"moqt-16");
    }

    #[test]
    fn transport_type_debug() {
        let quic = TransportType::Quic;
        assert!(format!("{quic:?}").contains("Quic"));

        let wt = TransportType::WebTransport { url: "https://example.com".to_string() };
        assert!(format!("{wt:?}").contains("WebTransport"));
    }
}

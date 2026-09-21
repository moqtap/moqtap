use bytes::{Buf, Bytes, BytesMut};

use crate::draft15::endpoint::{Endpoint, EndpointError};
use crate::draft15::event::{ClientEvent, Direction, StreamKind};
use crate::draft15::observer::ConnectionObserver;
use crate::draft15::session::request_id::Role;
use crate::draft15::session::setup;
use crate::forwarding_preference::ObjectForwardingPreference;
use crate::malformed_tracks::MalformedTrackCondition;
use crate::track_locations::{ObjectLocation, ObjectRole, TrackObjects};
use crate::transport::{RecvStream, SendStream, Transport, TransportError};
use moqtap_codec::dispatch::{
    AnyControlMessage, AnyDatagramHeader, AnyFetchHeader, AnySubgroupHeader,
};
use moqtap_codec::draft15::data_stream::{
    FetchHeader, FetchObjectHeader, FetchObjectReader, SubgroupObject, SubgroupObjectReader,
};
use moqtap_codec::draft15::message::ControlMessage;
use moqtap_codec::error::CodecError;
use moqtap_codec::kvp::KeyValuePair;
use moqtap_codec::types::*;
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

/// The ALPN identifier draft-15 uses on raw QUIC, `moqt-15`.
///
/// Drafts 07 to 14 share one ALPN, `moq-00`, and a peer that offers it has
/// said nothing about which of the eight it speaks. Draft-15 ended that:
/// from there each draft has an ALPN of its own, so the version is settled
/// by the TLS handshake before a byte of MoQT is written.
///
/// This is [`DraftVersion::Draft15`]'s own
/// [`quic_alpn`](DraftVersion::quic_alpn), which is what
/// [`ClientConfig::alpn`] offers; the test below holds the two together.
pub const MOQT_ALPN: &[u8] = b"moqt-15";

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
    /// A control message this build decoded for draft-15 and then could not
    /// narrow to draft-15's own message type.
    ///
    /// Unreachable, and that is not the same as harmless. `read_control`
    /// decodes with this connection's own draft, so the `AnyControlMessage` it
    /// hands back can only carry this draft's variant — but the narrowing arm
    /// is compiled in every configuration anyway, under
    /// `#[allow(unreachable_patterns)]` rather than a `cfg` naming the other
    /// drafts, because such a list has to be edited in every per-draft
    /// module whenever a draft is added and a copy that omits one leaves the
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
        "a control message decoded for draft-15 did not narrow to draft-15: a defect in this          build, and evidence about nothing the peer did"
    )]
    ControlMessageNarrowing,
    /// An Object arrived carrying extension headers on a status that is not
    /// Normal.
    ///
    /// Draft-15 Section 10.2.1.2: "Any Object with status Normal can have
    /// extension headers. If an endpoint receives extension headers on Objects
    /// with status that is not Normal, it MUST close the session with a
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
        status: moqtap_codec::draft15::types::ObjectStatus,
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
    /// Stateful subgroup object writer (tracks delta encoding state and
    /// extension-presence flag, seeded from the stream's
    /// `SubgroupHeader`).
    subgroup_io: Option<SubgroupObjectReader>,
    /// Stateful fetch object writer, seeded from the stream's `FetchHeader`.
    /// A fetch object inherits fields from the object before it, so the writer
    /// has to have seen that object; without this the first one has nothing to
    /// inherit from and is refused.
    fetch_io: Option<FetchObjectReader>,
}

impl FramedSendStream {
    /// Create a new framed send stream for the given draft version.
    pub fn new(inner: SendStream, draft: DraftVersion) -> Self {
        Self { inner, draft, subgroup_io: None, fetch_io: None }
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
            AnySubgroupHeader::Draft15(ref d15) => {
                self.subgroup_io = Some(SubgroupObjectReader::new(d15));
            }
            // Only this draft's header seeds the object reader. With draft 15 the only enabled
            // draft `AnySubgroupHeader` has a single variant, the arm above is exhaustive and this
            // one unreachable. Compiled in every configuration with the lint allowed, rather than
            // gated on a `cfg` naming the other drafts: such a list has to be edited in
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
        self.fetch_io = Some(FetchObjectReader::new());
        Ok(())
    }

    /// Append a draft-15 subgroup object to the stream. Uses the
    /// stateful writer seeded from
    /// [`FramedSendStream::write_subgroup_header`] to produce correct
    /// delta-encoded object IDs.
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
    /// could open one and put nothing on it through this type.
    ///
    /// Draft-15 delta-encodes a fetch object against the one before it, so this
    /// needs the same stream state the subgroup path keeps, seeded by
    /// [`write_fetch_header`](Self::write_fetch_header). An object that inherits
    /// a field from a previous object that does not exist is refused there
    /// rather than written as a zero.
    ///
    /// The declared length comes from the payload rather than from the caller's
    /// field: a header that disagrees with the bytes beside it desynchronises
    /// every object after it on the stream, and nothing downstream can recover.
    ///
    /// # Errors
    ///
    /// [`ConnectionError::DataStreamState`] if no fetch header has been written
    /// on this stream, and [`ConnectionError::Codec`] for a header the writer
    /// refuses.
    pub async fn write_fetch_object(
        &mut self,
        header: &FetchObjectHeader,
        payload: &[u8],
    ) -> Result<(), ConnectionError> {
        let writer = self
            .fetch_io
            .as_mut()
            .ok_or(ConnectionError::DataStreamState("fetch header not written yet"))?;
        let mut header = header.clone();
        header.payload_length = VarInt::from_usize(payload.len());
        let mut buf = Vec::new();
        writer.write_object_header(&header, &mut buf)?;
        buf.extend_from_slice(payload);
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
    /// Stateful subgroup object reader (tracks delta-decode state and
    /// extension-presence flag).
    subgroup_io: Option<SubgroupObjectReader>,
    /// Stateful fetch object reader, holding the Object each following Object
    /// may inherit its Group ID, Subgroup ID, Object ID and Priority from.
    /// Seeded by [`FramedRecvStream::read_fetch_header`].
    fetch_io: Option<FetchObjectReader>,
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
        Self {
            inner,
            buf: BytesMut::with_capacity(4096),
            draft,
            subgroup_io: None,
            fetch_io: None,
            tracking: None,
        }
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

        // Draft-15: 16-bit BE payload length
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
                        AnySubgroupHeader::Draft15(ref d15) => {
                            self.subgroup_io = Some(SubgroupObjectReader::new(d15));
                        }
                        // Only this draft's header seeds the object reader. With draft 15 the only
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

    /// Read a fetch response header, and seed the object reader that follows it.
    ///
    /// The seeding is what makes [`FramedRecvStream::read_fetch_object`] usable:
    /// a draft-15 fetch object may leave out fields and take the prior Object's,
    /// so the objects of one stream have to be read through one reader and the
    /// header is where that reader begins.
    pub async fn read_fetch_header(&mut self) -> Result<AnyFetchHeader, ConnectionError> {
        self.ensure(1).await?;
        loop {
            let mut cursor = &self.buf[..];
            match AnyFetchHeader::decode(self.draft, &mut cursor) {
                Ok(header) => {
                    let consumed = self.buf.len() - cursor.remaining();
                    self.buf.advance(consumed);
                    self.fetch_io = Some(FetchObjectReader::new());
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

    /// Read the next draft-15 subgroup object from this stream. Uses
    /// the stateful reader seeded by
    /// [`FramedRecvStream::read_subgroup_header`] to decode the
    /// delta-encoded object ID and (when the stream type says so) the
    /// extension block. Returns an error if called before a subgroup
    /// header was read.
    ///
    /// Errors with [`ConnectionError::ExtensionsOnNonNormalStatus`] on an
    /// Object that carries extension headers on a status other than Normal,
    /// which draft-15 Section 10.2.1.2 answers with a session close. The Object
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

    /// Read the next draft-15 fetch header from this stream.
    ///
    /// The typed twin of [`read_fetch_header`](Self::read_fetch_header), and it
    /// has to do the same two things that one does.
    ///
    /// It seeds the object reader, because the two consume the same bytes: a
    /// version that left `fetch_io` unset would put the stream in a state no
    /// caller can leave, with the next
    /// [`read_fetch_object`](Self::read_fetch_object) returning its
    /// `fetch header not read yet` refusal about a header this method has just
    /// read, and the bytes it would need already spent.
    ///
    /// It fills before decoding, and treats a varint that ran out of buffer as
    /// a short read rather than a malformed header. `FetchHeader::decode`
    /// reports that as `CodecError::VarInt(VarIntError::UnexpectedEnd)` where
    /// [`AnyFetchHeader`] reports a bare `CodecError::UnexpectedEnd`, so a loop
    /// matching only the latter never reaches its own `fill` — and since the
    /// buffer starts empty, that is every first call on a fresh stream.
    pub async fn read_fetch_stream_header(&mut self) -> Result<FetchHeader, ConnectionError> {
        self.ensure(1).await?;
        loop {
            let mut cursor = &self.buf[..];
            match FetchHeader::decode(&mut cursor) {
                Ok(hdr) => {
                    let consumed = self.buf.len() - cursor.remaining();
                    self.buf.advance(consumed);
                    self.fetch_io = Some(FetchObjectReader::new());
                    return Ok(hdr);
                }
                Err(CodecError::UnexpectedEnd)
                | Err(CodecError::VarInt(moqtap_codec::varint::VarIntError::UnexpectedEnd)) => {
                    if !self.fill().await? {
                        return Err(ConnectionError::UnexpectedEnd);
                    }
                }
                Err(e) => return Err(ConnectionError::Codec(e)),
            }
        }
    }

    /// Read the next draft-15 fetch object's header and payload.
    ///
    /// The mirror of [`FramedSendStream::write_fetch_object`], and it needs the
    /// same state that one needs: draft-15 lets an Object leave out its Group
    /// ID, Subgroup ID, Object ID and Priority and take the prior Object's, so
    /// the reader carries the prior Object and this method is refused before
    /// [`FramedRecvStream::read_fetch_header`] has seeded it.
    ///
    /// The header that comes back is resolved — every field is a value rather
    /// than an inheritance — which is what makes draft-15 and draft-18
    /// different from the three drafts either side of them.
    ///
    /// The payload comes back with the header because `payload_length` says how
    /// many bytes follow it, and a reader that takes the wrong number of them
    /// desynchronises every later object on the stream.
    ///
    /// # Errors
    ///
    /// [`ConnectionError::DataStreamState`] when no fetch header has been read,
    /// [`ConnectionError::UnexpectedEnd`] when the stream ends inside the header
    /// or inside the payload it declared, and [`ConnectionError::Codec`] on
    /// every rule Section 10.4.4 states about the flags and about an Object that
    /// inherits from one that does not exist.
    pub async fn read_fetch_object(
        &mut self,
    ) -> Result<(FetchObjectHeader, Vec<u8>), ConnectionError> {
        if self.fetch_io.is_none() {
            return Err(ConnectionError::DataStreamState("fetch header not read yet"));
        }
        let header = loop {
            let reader = self.fetch_io.as_mut().unwrap();
            // The reader carries the prior Object, so it is advanced on a probe
            // and committed only once the whole header was there to read. A
            // reader advanced by a short read would resolve the next Object
            // against a half-read one.
            let mut probe = reader.clone();
            let mut cursor = &self.buf[..];
            match probe.read_object_header(&mut cursor) {
                Ok(header) => {
                    let consumed = self.buf.len() - cursor.remaining();
                    self.buf.advance(consumed);
                    *reader = probe;
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
    /// The server's half of the setup handshake, kept whole.
    ///
    /// The endpoint acts on the parameters it recognises and retains none of
    /// them, and which parameters a server sends — in what order, with what
    /// values — is the sharpest thing a session says about the implementation
    /// behind it.
    server_setup: AnyControlMessage,
    /// The framed wire bytes of [`Self::server_setup`].
    server_setup_raw: Option<Vec<u8>>,
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

        // Perform setup handshake (draft-15: no versions)
        let mut endpoint = Endpoint::new(Role::Client);
        endpoint.connect()?;
        let setup_msg = endpoint.send_client_setup(config.setup_parameters.clone())?;
        let any_setup = AnyControlMessage::Draft15(setup_msg);
        let raw_setup = control_send.write_control(&any_setup).await?;

        let (server_setup, raw_server_setup) = control_recv.read_control(true).await?;
        // Unwrap to draft-15 for the endpoint
        match &server_setup {
            AnyControlMessage::Draft15(ControlMessage::ServerSetup(ref ss)) => {
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
                raw: Some(raw_setup),
            },
            ClientEvent::ControlMessage {
                direction: Direction::Receive,
                message: server_setup.clone(),
                raw: raw_server_setup.clone(),
            },
            ClientEvent::SetupComplete { negotiated_version: 0xff000000 + 15 },
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
    /// Wraps the draft-15 message in `AnyControlMessage::Draft15` for
    /// framing.
    pub async fn send_control(&self, msg: &ControlMessage) -> Result<(), ConnectionError> {
        let any = AnyControlMessage::Draft15(msg.clone());
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
    /// Returns the `AnyControlMessage` and also extracts the draft-15
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
        // Unwrap to draft-15 for the endpoint
        match any {
            AnyControlMessage::Draft15(msg) => Ok(msg),
            // `AnyControlMessage` carries one variant per enabled draft feature. With draft 15 the
            // only one enabled the arm above is exhaustive and this rejection arm unreachable.
            // Compiled in every configuration with the lint allowed, rather than gated on a `cfg`
            // naming the other drafts: such a list has to be edited in every draft module
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
        parameters: Vec<KeyValuePair>,
    ) -> Result<(), ConnectionError> {
        let msg = self.endpoint.send_subscribe_ok(request_id, track_alias, parameters)?;
        self.send_control(&msg).await
    }

    /// Refuse a request the peer opened, sending REQUEST_ERROR.
    ///
    /// One message refuses a SUBSCRIBE, a FETCH, an announcement, a track
    /// status or a namespace subscription, and the endpoint finds which by the
    /// identifier. It refuses a second answer to any of them, and
    /// refuses a Joining Fetch's refusal under any code but the one the draft
    /// names for it, so nothing is written on the wire when it does.
    pub async fn request_error(
        &mut self,
        request_id: VarInt,
        error_code: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<(), ConnectionError> {
        let msg = self.endpoint.send_request_error(request_id, error_code, reason_phrase)?;
        self.send_control(&msg).await
    }

    /// Narrow a subscription this endpoint opened, sending SUBSCRIBE_UPDATE, and
    /// return the Request ID the update itself spent.
    pub async fn subscribe_update(
        &mut self,
        subscription_request_id: VarInt,
        parameters: Vec<KeyValuePair>,
    ) -> Result<VarInt, ConnectionError> {
        let (request_id, msg) =
            self.endpoint.subscribe_update(subscription_request_id, parameters)?;
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
        reason_phrase: Vec<u8>,
    ) -> Result<(), ConnectionError> {
        let msg = self.endpoint.send_publish_error(request_id, error_code, reason_phrase)?;
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
    /// which is what an application that knows the group it wants has: draft-15
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
    ) -> Result<(), ConnectionError> {
        let msg = self.endpoint.send_fetch_ok(
            request_id,
            end_of_track,
            end_group,
            end_object,
            parameters,
        )?;
        self.send_control(&msg).await
    }

    // -- Namespace flows --------------------------------------------

    /// Send a SUBSCRIBE_NAMESPACE and return the request ID.
    pub async fn subscribe_namespace(
        &mut self,
        namespace_prefix: TrackNamespace,
        parameters: Vec<KeyValuePair>,
    ) -> Result<VarInt, ConnectionError> {
        let (req_id, msg) = self.endpoint.subscribe_namespace(namespace_prefix, parameters)?;
        self.send_control(&msg).await?;
        Ok(req_id)
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
    /// written on the wire when it does. On this draft an announcement, a track
    /// status and a namespace subscription are the requests REQUEST_OK
    /// accepts; a subscription, a publication and a fetch each have an
    /// acceptance of their own that carries more than this one can.
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
        parameters: Vec<KeyValuePair>,
    ) -> Result<VarInt, ConnectionError> {
        let (req_id, msg) =
            self.endpoint.publish(track_namespace, track_name, track_alias, parameters)?;
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

    // -- Malformed Tracks -------------------------------------------

    /// Send what Section 2.4.2 asks for when this endpoint finds a track
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
    /// Section 2.4.2's sentence is a subscriber's: an endpoint about to send an
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

    // -- Data streams -----------------------------------------------

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

    /// Close the session when a failure raised while reading a *data* stream is
    /// one draft-15 answers with a close. Reports whether it closed.
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
    ///
    /// Not every rule that reaches here is the decoder's. A track whose objects
    /// mix forwarding preferences is the endpoint's to notice — it takes the
    /// alias table to know which track an object belongs to — and it arrives on
    /// exactly these streams. Both kinds are asked for a code the same way, and
    /// a rule with no code is declined rather than guessed at.
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
    /// [`PeerViolation`] is a peer having done something draft-15 forbids, and
    /// carries the session error code draft-15's own text answers it with.
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
        use moqtap_codec::draft15::error_codes::SessionErrorCode;

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
    /// decoded because the peer broke a rule draft-15 answers with a close.
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
    ///   - Full Track Name, maximum 4,096 bytes. Draft-15 states this of the Full Track
    ///     Name alone; draft-16 widened it to a Track Namespace on its own.
    ///   - Duplicate parameters, a SHOULD rather than a MUST: "Receivers SHOULD
    ///     check that there are no unauthorized duplicate parameters and close the
    ///     session as a PROTOCOL_VIOLATION"
    ///
    ///   - GOAWAY New Session URI, maximum 8,192 bytes: "If an endpoint
    ///     receives a length exceeding the maximum, it MUST close the session
    ///     with a PROTOCOL_VIOLATION." Every draft from 11 to 19 states it; 07
    ///     through 10 state no maximum for the field at all.
    ///   - Unknown control message type: "An endpoint that receives an unknown
    ///     message type MUST close the session." All the drafts state it,
    ///     in the same words, and the sentence names no code, so Protocol
    ///     Violation is what carries it.
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
    /// the draft answers with a close, so treating it as fatal would close
    /// sessions the draft does not ask to be closed. Splitting it is the way to
    /// bring the rest of those rules under this function; widening the match is
    /// not.
    pub fn codec_session_error_code(
        err: &CodecError,
    ) -> Option<moqtap_codec::draft15::error_codes::SessionErrorCode> {
        use moqtap_codec::draft15::error_codes::SessionErrorCode;
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
            // A filter parameter whose value is not a filter, Section 9.2.1.7:
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
            CodecError::DuplicateParameter(_)
            | CodecError::TrackNameTooLong
            | CodecError::InvalidNamespaceTupleSize(_)
            | CodecError::ReasonPhraseTooLong
            | CodecError::GoAwayUriTooLong
            | CodecError::UnknownMessageType(_)
            | CodecError::Kvp(KvpError::ValueTooLong(_)) => {
                Some(SessionErrorCode::ProtocolViolation)
            }
            // An unknown data-plane type, Section 10: "An endpoint that
            // receives an unknown stream or datagram type MUST close the
            // session." One sentence covering two tables, which is why both
            // variants sit here.
            // A Message Parameter whose value is outside the range its type
            // allows: FORWARD in Section 9.2.1.10, GROUP_ORDER in Section 9.2.1.6,
            // SUBSCRIBER_PRIORITY in Section 9.2.1.5 and DYNAMIC_GROUPS in
            // Section 9.2.1.11.
            // Each states that a receiver "MUST close the session with
            // PROTOCOL_VIOLATION".
            CodecError::ParameterValueOutOfRange { .. } => {
                Some(SessionErrorCode::ProtocolViolation)
            }
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
            // receiver MUST close the Session with KEY_VALUE_FORMATTING_ERROR."
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
            | CodecError::EmptyNamespaceField
            | CodecError::InvalidRange(..)
            | CodecError::ParameterLengthMismatch(_)
            | CodecError::EndOfTrackObjectId(_)
            | CodecError::KeyDeltaOverflow(..)
            // Not `TrackPropertyValueOutOfRange`: draft-15 has no extension
            // header or Track Property registry. DYNAMIC_GROUPS, which draft-16
            // moves into one, is a Message Parameter here - Section 9.2.1.11,
            // "Values larger than 1 are a Protocol Violation" - and arrives as
            // `ParameterValueOutOfRange` above.
            | CodecError::TrackPropertyValueOutOfRange { .. }
            | CodecError::ParametersOutOfOrder(..)
            | CodecError::ObjectIdOverflow(..)
            | CodecError::ExtensionsOnNonExistentObject(_)
            | CodecError::InvalidRequiredRequestIdDelta(..)
            | CodecError::InvalidStreamTypeValue { .. }
            | CodecError::InvalidDatagramTypeValue { .. }
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

    /// Close the session on the wire when a decode failure is one draft-15
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
    fn client_config_alpn_quic_draft15() {
        let config = ClientConfig {
            draft: DraftVersion::Draft15,
            transport: TransportType::Quic,
            skip_cert_verification: false,
            ca_certs: Vec::new(),
            setup_parameters: Vec::new(),
        };
        assert_eq!(config.alpn(), vec![b"moqt-15".to_vec()]);
    }

    #[test]
    fn client_config_alpn_webtransport() {
        let config = ClientConfig {
            draft: DraftVersion::Draft15,
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
            draft: DraftVersion::Draft15,
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
            15,
            config
                .alpn()
                .iter()
                .map(|a| String::from_utf8_lossy(a).into_owned())
                .collect::<Vec<_>>(),
        );
        assert_eq!(MOQT_ALPN, b"moqt-15");
    }

    #[test]
    fn transport_type_debug() {
        let quic = TransportType::Quic;
        assert!(format!("{quic:?}").contains("Quic"));

        let wt = TransportType::WebTransport { url: "https://example.com".to_string() };
        assert!(format!("{wt:?}").contains("WebTransport"));
    }
}

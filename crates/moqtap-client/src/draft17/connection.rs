use std::collections::VecDeque;
use std::sync::Mutex;

use bytes::{Buf, Bytes, BytesMut};

use crate::draft17::endpoint::{Endpoint, EndpointError};
use crate::draft17::event::{ClientEvent, Direction, StreamKind};
use crate::draft17::observer::ConnectionObserver;
use crate::draft17::session::request_id::Role;
use crate::draft17::session::setup;
use crate::malformed_tracks::MalformedTrackCondition;
use crate::track_locations::{ObjectLocation, ObjectRole, TrackObjects};
use crate::transport::{RecvStream, SendStream, Transport, TransportError};
use moqtap_codec::dispatch::{
    AnyControlMessage, AnyDatagramHeader, AnyFetchHeader, AnySubgroupHeader,
};
use moqtap_codec::draft17::data_stream::{
    FetchHeader, FetchObject, FetchObjectHeader, FetchObjectReader, SubgroupObject,
    SubgroupObjectReader,
};
use moqtap_codec::draft17::error_codes::DataStreamResetErrorCode;
use moqtap_codec::draft17::message::{
    ControlMessage, FetchOk, MessageType, PublishOk, RequestError, RequestOk, SubscribeOk,
};
use moqtap_codec::error::CodecError;
use moqtap_codec::kvp::KeyValuePair;
use moqtap_codec::types::*;
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

/// The ALPN identifier draft-17 uses on raw QUIC, `moqt-17`.
///
/// Drafts 07 to 14 share one ALPN, `moq-00`, and a peer that offers it has
/// said nothing about which of the eight it speaks. Draft-15 ended that:
/// from there each draft has an ALPN of its own, so the version is settled
/// by the TLS handshake before a byte of MoQT is written.
///
/// This is [`DraftVersion::Draft17`]'s own
/// [`quic_alpn`](DraftVersion::quic_alpn), which is what
/// [`ClientConfig::alpn`] offers; the test below holds the two together.
pub const MOQT_ALPN: &[u8] = b"moqt-17";

/// The unidirectional stream type that marks one direction of the control
/// plane, and the SETUP message type. On draft-17 they are one number,
/// 0x2F00: Section 3.4 (Unidirectional Stream Types) lists it as the type of
/// a SETUP stream, and Section 9.4 gives it as the SETUP message's own type
/// field.
///
/// Because they are the same number a control stream carries no separate
/// stream header. The varint a reader uses to recognise the stream is the
/// first field of the SETUP message it then decodes, and a writer that
/// encodes a SETUP onto a fresh unidirectional stream has already written the
/// stream type by writing the message.
///
/// Encoded with MoQT's variable-length integer, whose width is the number of
/// leading 1 bits in the first byte, 0x2F00 is the two bytes `AF 00` — four
/// under RFC 9000's encoding, which this draft does not use. Read it through
/// [`DraftVersion::decode_varint`] rather than assuming a width.
pub const CONTROL_STREAM_TYPE: u64 = 0x2F00;

/// The application error code a request stream is reset with when the
/// requester abandons it: `CANCELLED`, 0x1.
///
/// Draft-17 removed UNSUBSCRIBE and FETCH_CANCEL. Cancelling a request is
/// resetting the bidirectional stream it was made on, and `CANCELLED` is the
/// code draft-17 assigns for "the subscriber or publisher cancelled the
/// Request" — see [`DataStreamResetErrorCode::Cancelled`]. Taken from the
/// codec's own registry rather than written as a literal so a renumbering in
/// a later draft cannot be missed here.
///
/// This is what [`RequestStream::cancel`] uses when no code is chosen for it,
/// and what `RequestStream`'s [`Drop`] sends.
pub const REQUEST_CANCELLED: u64 = DataStreamResetErrorCode::Cancelled as u64;

/// The application error code a request stream **the peer opened** is reset
/// with when this endpoint abandons it: `INTERNAL_ERROR`, 0x0.
///
/// Dropping an inbound request is not the act [`REQUEST_CANCELLED`] describes.
/// Draft-17 Section 3.3.1 grants a responder a cancel — "Receivers cancel
/// requests if they are unable to or choose not to respond" — but a handle
/// that fell out of scope chose nothing; it failed to serve, which is what
/// [`DataStreamResetErrorCode::InternalError`], "an implementation specific
/// error", names. The two codes are on the wire, so a peer counting refusals
/// can tell a deliberate rejection from a dropped request only if they differ.
///
/// It is also what a responder that already answered is reset with when it is
/// dropped without finishing. A FIN there would claim the request completed,
/// and for a subscription it has not: PUBLISH_DONE is still owed.
pub const REQUEST_UNANSWERED: u64 = DataStreamResetErrorCode::InternalError as u64;

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
    /// A control message this build decoded for draft-17 and then could not
    /// narrow to draft-17's own message type.
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
        "a control message decoded for draft-17 did not narrow to draft-17: a defect in this          build, and evidence about nothing the peer did"
    )]
    ControlMessageNarrowing,
    /// An Object arrived carrying properties on a status that is not Normal.
    ///
    /// Draft-17 Section 10.2.1.2: "Any Object with status Normal can have
    /// properties (Section 2.5). If an endpoint receives properties on an
    /// Object with status that is not Normal, it MUST close the session with a
    /// PROTOCOL_VIOLATION."
    ///
    /// The codec decodes such an Object rather than refusing it — the frame is
    /// well formed, and a tool that reports non-conforming traffic has to be
    /// able to read it. Being an endpoint rather than an observer is what turns
    /// it into an error, so it is raised here, on the receive path, and not in
    /// the decoder.
    #[error(
        "object {object_id} carries {properties_len} bytes of properties on status {status:?}, which is not Normal"
    )]
    PropertiesOnNonNormalStatus {
        /// The Object ID the properties arrived on.
        object_id: u64,
        /// Length in bytes of the properties block.
        properties_len: usize,
        /// The Object's status, resolved through the encoding's elision rule.
        ///
        /// Spelled out in full because the glob import of `moqtap_codec::types`
        /// brings a different `ObjectStatus` into this module.
        status: moqtap_codec::draft17::types::ObjectStatus,
    },
    /// A message that begins a request stream was handed to
    /// [`Connection::send_control`]. Nothing was written.
    #[error(
        "{0:?} begins a request stream of its own and must not be written on the control stream"
    )]
    RequestOnControlStream(MessageType),
    /// A message draft-17 places on a request stream was handed to
    /// [`Connection::send_control`]. Nothing was written.
    ///
    /// Distinct from [`ConnectionError::RequestOnControlStream`], which is about
    /// a message that would *begin* a request stream of its own. This one is
    /// about a message that belongs on a request stream already open, and so has
    /// no meaning without one around it.
    #[error("{0:?} belongs on a request stream, not on the control stream")]
    RequestStreamMessageOnControlStream(MessageType),
    /// A datagram carrying an Object Status arrived with bytes after its
    /// header.
    ///
    /// Draft-17 Section 10.2.1.1: "Any object with a status code other than
    /// zero MUST have an empty payload." Section 10.3.1 says the same thing
    /// about the framing: a datagram with the STATUS bit set "is present and
    /// there is no Object Payload."
    ///
    /// The codec cannot see this. `DatagramHeader::decode` stops at the end of
    /// the header and never owns the datagram's tail, so the only layer that
    /// holds both the status and the bytes after it is this one. Without the
    /// check the application is handed, say, an End-of-Group object carrying
    /// four bytes of payload — a combination the draft forbids outright.
    ///
    /// Recoverable: the drafts state the rule as a property of a conforming
    /// object, not as one of the "MUST close the session" cases, so the datagram
    /// is refused and the session left running.
    #[error(
        "datagram for object {object_id} carries {payload_len} bytes after a header \
         whose status is {status:?}, which permits no payload"
    )]
    PayloadOnStatusDatagram {
        /// Object ID from the datagram header.
        object_id: u64,
        /// How many bytes followed the header.
        payload_len: usize,
        /// The status the header declared.
        ///
        /// Spelled out in full because the glob import of `moqtap_codec::types`
        /// brings a different `ObjectStatus` into this module.
        status: Option<moqtap_codec::draft17::types::ObjectStatus>,
    },
    /// A bidirectional stream the peer opened began with a message type that
    /// does not open a request stream.
    ///
    /// Draft-17 Section 3.3: "Bidirectional streams MUST NOT begin with any
    /// other message type unless negotiated. If they do, the peer MUST close
    /// the Session with a PROTOCOL_VIOLATION." The session has already been
    /// closed on the wire by the time this is returned, and the offending
    /// stream reset.
    #[error(
        "a bidirectional stream the peer opened began with {0:?}, which does not begin a request stream; the session was closed"
    )]
    NonRequestOnRequestStream(MessageType),
    /// A `respond_*` helper was handed a request stream this endpoint opened.
    /// Nothing was written and no state moved.
    #[error(
        "this endpoint opened request {0}; only the endpoint a request stream was opened toward may answer it"
    )]
    RespondedToOwnRequest(u64),
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
            AnySubgroupHeader::Draft17(ref d17) => {
                self.subgroup_io = Some(SubgroupObjectReader::new(d17));
            }
            // Only this draft's header seeds the object reader. With draft 17 the only enabled
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
        Ok(())
    }

    /// Append a draft-17 subgroup object to the stream using the
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

    /// Reset the stream with `code`, telling the peer transmission was
    /// abandoned rather than completed.
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
    /// Stateful fetch object reader, seeded by
    /// [`FramedRecvStream::read_fetch_header`]. Draft-17 needs nothing the
    /// fetch header does not carry, so unlike draft-18 there is no separate
    /// call to start it.
    fetch_io: Option<FetchObjectReader>,
    /// The record this stream's objects are measured against, and the Group ID
    /// its header named.
    ///
    /// One group for the whole stream: a subgroup header names it once and no
    /// object header repeats it. `None` on a stream that was never given one -
    /// a stream for an alias no live binding names, and every stream built
    /// outside [`Connection::accept_subgroup_stream`].
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
    fn measure_objects_against(&mut self, objects: TrackObjects, group: u64) {
        self.tracking = Some((objects, group));
    }

    /// Judge one object this stream carried against where its track ended.
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

    /// Read this stream's leading variable-length integer **without
    /// consuming it**, and return its value.
    ///
    /// Every unidirectional MoQT stream on draft-17 opens with a varint
    /// naming what it is (Section 3.4): 0x05 for FETCH_HEADER, 0x10-0x1D for
    /// SUBGROUP_HEADER, and [`CONTROL_STREAM_TYPE`] for SETUP. Telling the
    /// peer's control stream apart from a data stream means reading that
    /// varint, and taking it off the transport would destroy it: the control
    /// stream's type varint *is* the SETUP message's type field, so a stream
    /// whose type had been stripped would no longer decode as a SETUP.
    ///
    /// Nothing is stripped. The bytes land in this reader's own buffer, and
    /// every other method here — [`read_control`](Self::read_control),
    /// [`read_subgroup_header`](Self::read_subgroup_header),
    /// [`read_fetch_header`](Self::read_fetch_header) — decodes out of that
    /// buffer and advances it only on a successful decode. A stream this was
    /// called on is indistinguishable from one it was not, which is what
    /// makes it safe to peek a stream and then hand it to whichever reader
    /// the type turned out to call for.
    ///
    /// It reads, so it can block: a peer that opens a stream and then writes
    /// nothing leaves this pending until a byte arrives or the stream ends.
    ///
    /// # Errors
    ///
    /// - [`ConnectionError::UnexpectedEnd`] if the stream ends before a whole
    ///   varint has arrived.
    /// - [`ConnectionError::Transport`] if the peer reset the stream.
    /// - [`ConnectionError::VarInt`] if the bytes are not a valid varint.
    ///
    /// Whatever did arrive stays in the buffer in every case.
    pub async fn peek_stream_type(&mut self) -> Result<u64, ConnectionError> {
        self.ensure(1).await?;
        let type_len = self.draft.varint_len(self.buf[0]);
        self.ensure(type_len).await?;
        let mut cursor = &self.buf[..type_len];
        Ok(self.draft.decode_varint(&mut cursor)?.into_inner())
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
        let type_len = self.draft.varint_len(self.buf[0]);
        self.ensure(type_len).await?;

        let mut cursor = &self.buf[..type_len];
        let _type_id = self.draft.decode_varint(&mut cursor)?;

        // Draft-17: 16-bit BE payload length
        let (payload_len, len_field_size) = if self.draft.uses_fixed_length_framing() {
            self.ensure(type_len + 2).await?;
            let hi = self.buf[type_len] as usize;
            let lo = self.buf[type_len + 1] as usize;
            ((hi << 8) | lo, 2)
        } else {
            self.ensure(type_len + 1).await?;
            let payload_len_start = type_len;
            let payload_len_varint_len = self.draft.varint_len(self.buf[payload_len_start]);
            self.ensure(type_len + payload_len_varint_len).await?;
            let mut cursor = &self.buf[payload_len_start..type_len + payload_len_varint_len];
            let payload_len = self.draft.decode_varint(&mut cursor)?.into_inner() as usize;
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
                        AnySubgroupHeader::Draft17(ref d17) => {
                            self.subgroup_io = Some(SubgroupObjectReader::new(d17));
                        }
                        // Only this draft's header seeds the object reader. With draft 17 the only
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
                    // Seeding here is what makes `read_fetch_object` usable: a
                    // draft-17 fetch object may leave out fields and take the
                    // prior Object's, so the objects of one stream have to be
                    // read through one reader and the header is where that
                    // reader begins.
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

    /// Read the next draft-17 subgroup object from this stream using
    /// the stateful reader seeded by
    /// [`FramedRecvStream::read_subgroup_header`].
    ///
    /// Errors with [`ConnectionError::PropertiesOnNonNormalStatus`] on an
    /// Object that carries properties on a status other than Normal, which
    /// draft-17 Section 10.2.1.2 answers with a session close. The Object is
    /// consumed from the stream before the check, so the reader stays in step
    /// with the wire and a caller that reports the violation and reads on sees
    /// the following Object rather than a re-parse of this one.
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
                    if !obj.properties_permitted() {
                        return Err(ConnectionError::PropertiesOnNonNormalStatus {
                            object_id: obj.object_id.into_inner(),
                            properties_len: obj.extension_headers.len(),
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

    /// Read the next draft-17 fetch header from this stream.
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

    /// Stop accepting data on this stream with `code` as the `STOP_SENDING`
    /// application error code, discarding anything unread.
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

    /// Read the next draft-17 fetch object and its payload.
    ///
    /// The mirror of [`FramedSendStream::write_fetch_object`]. What comes back
    /// is a [`FetchObject`] rather than a header: draft-17's reader resolves the
    /// fields the Serialization Flags left off the wire, so the Group ID,
    /// Subgroup ID, Object ID and Priority it carries are the frame's own
    /// values, not the flags that say where to find them. `object.header` is
    /// the frame exactly as it arrived, for a caller forwarding the bytes on.
    ///
    /// The payload comes back with it for the reason the codec leaves it on the
    /// wire: `payload_length` says how many bytes follow, and a reader that
    /// takes the wrong number of them desynchronises every later object on the
    /// stream. Doing it here is the only place that count and the buffer are
    /// both in hand.
    ///
    /// # Errors
    ///
    /// [`ConnectionError::DataStreamState`] when
    /// [`FramedRecvStream::read_fetch_header`] has not been read first, since
    /// that is what seeds the reader; [`ConnectionError::UnexpectedEnd`] when
    /// the stream ends inside the header or inside the payload it declared; and
    /// [`ConnectionError::Codec`] on a Serialization Flags value the draft does
    /// not define, and on every rule Section 10.4.4.1 answers with a session
    /// close — a first Object that inherits a field no Object before it
    /// established, or an inherited Object ID or Subgroup ID one past the end of
    /// the space.
    pub async fn read_fetch_object(&mut self) -> Result<(FetchObject, Vec<u8>), ConnectionError> {
        if self.fetch_io.is_none() {
            return Err(ConnectionError::DataStreamState("fetch header not read yet"));
        }
        let object = loop {
            let reader = self.fetch_io.as_mut().unwrap();
            // Advanced on a probe and committed only once the whole header was
            // there to read: a reader advanced by a short read would resolve
            // the next Object against a half-read one.
            let mut probe = reader.clone();
            let mut cursor = &self.buf[..];
            match probe.read_object_header(&mut cursor) {
                Ok(object) => {
                    let consumed = self.buf.len() - cursor.remaining();
                    self.buf.advance(consumed);
                    *reader = probe;
                    break object;
                }
                Err(e) if e.is_incomplete() => {
                    if !self.fill().await? {
                        return Err(ConnectionError::UnexpectedEnd);
                    }
                }
                Err(e) => return Err(ConnectionError::Codec(e)),
            }
        };
        let payload = self.read_object_payload(&object.header.payload_length).await?;
        Ok((object, payload))
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

/// Which of the six message types draft-17 Section 3.3 lets a bidirectional
/// stream begin with opened a request stream.
///
/// Draft-17 Section 3.3: "A request stream begins with one of these six
/// message types: TRACK_STATUS, SUBSCRIBE, PUBLISH, FETCH, PUBLISH_NAMESPACE,
/// and SUBSCRIBE_NAMESPACE. Bidirectional streams MUST NOT begin with any
/// other message type unless negotiated."
///
/// The set is per draft and is not stable across drafts: draft-18 added
/// SUBSCRIBE_TRACKS and renumbered SUBSCRIBE_NAMESPACE from 0x11 to 0x50. A
/// six-variant enum here is what makes it impossible to name draft-18's
/// seventh kind in draft-17 code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestKind {
    /// TRACK_STATUS, 0x0D.
    TrackStatus,
    /// SUBSCRIBE, 0x03.
    Subscribe,
    /// PUBLISH, 0x1D.
    Publish,
    /// FETCH, 0x16 — standalone or joining.
    Fetch,
    /// PUBLISH_NAMESPACE, 0x06.
    PublishNamespace,
    /// SUBSCRIBE_NAMESPACE, 0x11 on this draft.
    SubscribeNamespace,
}

impl RequestKind {
    /// The message type a request stream of this kind begins with.
    pub const fn message_type(self) -> MessageType {
        match self {
            RequestKind::TrackStatus => MessageType::TrackStatus,
            RequestKind::Subscribe => MessageType::Subscribe,
            RequestKind::Publish => MessageType::Publish,
            RequestKind::Fetch => MessageType::Fetch,
            RequestKind::PublishNamespace => MessageType::PublishNamespace,
            RequestKind::SubscribeNamespace => MessageType::SubscribeNamespace,
        }
    }

    /// The kind of request stream `ty` opens, or `None` when it opens none.
    ///
    /// The inverse of [`message_type`](Self::message_type) and the classifier
    /// the accept path runs on the first message of a bidirectional stream the
    /// peer opened. `None` is the PROTOCOL_VIOLATION case of draft-17
    /// Section 3.3.
    ///
    /// Like [`starts_a_request_stream`] the match is exhaustive over
    /// [`MessageType`] with **no wildcard arm**, so a message type added in a
    /// later draft stops this compiling until someone classifies it; the unit
    /// test below holds the two functions to the same answer for every
    /// assigned type, so neither can drift from the other.
    pub const fn from_message_type(ty: MessageType) -> Option<RequestKind> {
        match ty {
            MessageType::TrackStatus => Some(RequestKind::TrackStatus),
            MessageType::Subscribe => Some(RequestKind::Subscribe),
            MessageType::Publish => Some(RequestKind::Publish),
            MessageType::Fetch => Some(RequestKind::Fetch),
            MessageType::PublishNamespace => Some(RequestKind::PublishNamespace),
            MessageType::SubscribeNamespace => Some(RequestKind::SubscribeNamespace),
            MessageType::Setup
            | MessageType::GoAway
            | MessageType::Namespace
            | MessageType::NamespaceDone
            | MessageType::PublishBlocked
            | MessageType::RequestUpdate
            | MessageType::SubscribeOk
            | MessageType::RequestOk
            | MessageType::RequestError
            | MessageType::FetchOk
            | MessageType::PublishDone
            | MessageType::PublishOk => None,
        }
    }
}

/// Which side opened the bidirectional stream a request travels on.
///
/// Draft-17 Section 3.3 gives every request a bidirectional stream, and either
/// endpoint may open one. The two directions are not symmetric — one side owes
/// a response and the other is waiting for it — so a [`RequestStream`] carries
/// this to say which side of that it is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestOrigin {
    /// This endpoint opened the stream and wrote the request on it. What comes
    /// back is a response, and dropping the handle cancels the request.
    Local,
    /// The peer opened the stream; this endpoint owes it a response. What
    /// comes back is a follow-up to the peer's request, never a response, and
    /// dropping the handle abandons a request that was asked of us.
    Peer,
}
/// Whether draft-17 places this message on a request stream that is already
/// open.
///
/// Four of them. REQUEST_UPDATE modifies the request its stream carries
/// (Section 9.10). NAMESPACE and NAMESPACE_DONE report and withdraw the
/// namespaces a SUBSCRIBE_NAMESPACE asked for, on that request's own response
/// stream (Sections 9.18 to 9.20), and PUBLISH_BLOCKED names a track in that
/// namespace the publisher cannot offer (Section 9.21) — draft-17 has no
/// SUBSCRIBE_TRACKS, so all three share one stream.
///
/// `Endpoint::receive_message` already closes the session over all four when
/// they arrive on the control stream. Without this the client would write on the
/// control stream exactly what its own peer half refuses to read there.
fn belongs_on_a_request_stream(ty: MessageType) -> bool {
    matches!(
        ty,
        MessageType::RequestUpdate
            | MessageType::Namespace
            | MessageType::NamespaceDone
            | MessageType::PublishBlocked
    )
}

/// Whether `ty` is one of the six message types draft-17 Section 3.3 lets a
/// bidirectional stream begin with.
///
/// The match is exhaustive over [`MessageType`] and deliberately has **no
/// wildcard arm**. That is the drift guard: `MessageType` is not
/// `#[non_exhaustive]`, so the day a draft gains a message type this stops
/// compiling until someone says here whether the new type opens a request
/// stream. A wildcard would silently answer "no" for it.
///
/// Classification is over the typed `MessageType`, never over a raw `u64`,
/// because the number alone does not say which registry it came from: on
/// draft-17, 0x10 is GOAWAY as a control message type and also a
/// SUBGROUP_HEADER as a unidirectional stream type.
pub const fn starts_a_request_stream(ty: MessageType) -> bool {
    match ty {
        // The six that begin a request stream.
        MessageType::TrackStatus
        | MessageType::Subscribe
        | MessageType::Publish
        | MessageType::Fetch
        | MessageType::PublishNamespace
        | MessageType::SubscribeNamespace => true,
        // These travel on a request stream too — NAMESPACE, NAMESPACE_DONE and
        // PUBLISH_BLOCKED on the response stream of the SUBSCRIBE_NAMESPACE
        // that asked for them (Sections 9.18 to 9.21), REQUEST_UPDATE on the
        // stream of the request it modifies (Section 9.10) — but none of them
        // may *begin* one, which is the only question asked here. SETUP is the
        // control stream's own type varint and belongs to no bidirectional
        // stream at all; GOAWAY drains the whole session.
        MessageType::Setup
        | MessageType::GoAway
        | MessageType::Namespace
        | MessageType::NamespaceDone
        | MessageType::PublishBlocked
        | MessageType::RequestUpdate => false,
        // Responses. They cannot begin a stream: they arrive on the request
        // stream their request opened, which is why they carry no request id
        // of their own on this draft.
        MessageType::SubscribeOk
        | MessageType::RequestOk
        | MessageType::RequestError
        | MessageType::FetchOk
        | MessageType::PublishDone
        | MessageType::PublishOk => false,
    }
}

/// One request and its answer, on a bidirectional stream of their own.
///
/// Draft-17 Section 3.3 moved requests off the control plane: each request is
/// the first message on a bidirectional stream it opens, and the response
/// comes back on that same stream. Responses carry no request id on this
/// draft — **the stream is the correlation**, which is why this handle exists
/// and why a bare request id is no longer enough to find an answer.
///
/// # Reading and writing go through the connection
///
/// This handle owns both halves of the stream but not the session, so the
/// endpoint state machine and the observer stay where they were. Read a
/// response with [`Connection::recv_on_request_stream`], write a follow-up with
/// [`Connection::send_on_request_stream`], and cancel with
/// [`Connection::cancel_request_stream`].
///
/// [`cancel`](Self::cancel) and [`peer_cancelled`](Self::peer_cancelled) are on
/// the handle because they touch the stream and nothing else, and [`Drop`]
/// needs the first of them. Neither moves the endpoint's record of the request,
/// which is why the connection carries a pair of its own.
///
/// # Dropping this cancels the request
///
/// A dropped handle resets the send half and sends `STOP_SENDING` on the
/// receive half, both with [`REQUEST_CANCELLED`], unless the stream was
/// already cancelled or finished. Letting the default drop stand would send a
/// FIN instead, telling the peer the request ended *cleanly* when it was
/// abandoned.
///
/// The consequence is sharp and worth stating: a live subscription's request
/// stream must be **held for the subscription's life**, because PUBLISH_DONE
/// arrives on it. Keeping only [`request_id`](Self::request_id) and letting
/// the handle fall out of scope cancels the subscription.
///
/// What a drop cannot do is say so at the endpoint. [`Drop`] holds the stream
/// and not the session, so the request stays where it was in the endpoint's
/// record while the stream it travelled on is gone. Call
/// [`Connection::cancel_request_stream`] wherever that record matters.
///
/// # Which side opened it changes what this handle does
///
/// [`origin`](Self::origin) says whether this endpoint opened the stream or
/// accepted it, and three behaviours turn on it: reads dispatch as responses
/// or as follow-ups to the peer's request, the `respond_*` helpers refuse a
/// stream this endpoint opened, and [`Drop`] resets with
/// [`REQUEST_UNANSWERED`] rather than [`REQUEST_CANCELLED`]. Everything else —
/// [`cancel`](Self::cancel), [`peer_cancelled`](Self::peer_cancelled),
/// [`finish`](Self::finish),
/// [`Connection::send_on_request_stream`] — is the same in both directions.
/// Draft-17 Section 3.3.1 is explicit that a cancel is available to both:
/// "Senders cancel requests if the response is no longer of interest;
/// Receivers cancel requests if they are unable to or choose not to respond."
///
/// All fields are private so the shape can grow without breaking callers.
#[must_use = "dropping a request stream cancels the request; hold it until the response arrives"]
pub struct RequestStream {
    send: FramedSendStream,
    recv: FramedRecvStream,
    request_id: VarInt,
    kind: RequestKind,
    draft: DraftVersion,
    stream_id: u64,
    cancelled: bool,
    finished: bool,
    origin: RequestOrigin,
    /// Whether a `respond_*` helper has written a response on this stream.
    /// True on a [`RequestOrigin::Peer`] stream from the response written on
    /// it, and on a [`RequestOrigin::Local`] one from the answer to an update
    /// the peer sent, which is the only response this endpoint writes on a
    /// stream of its own.
    responded: bool,
}

impl RequestStream {
    /// The request id the endpoint allocated for this request.
    ///
    /// Useful for logging and for endpoint calls that still take one. It is
    /// not enough to find the response: draft-17 responses carry no request
    /// id, so only this stream identifies them.
    pub fn request_id(&self) -> VarInt {
        self.request_id
    }

    /// Which of the six request types opened this stream.
    pub fn kind(&self) -> RequestKind {
        self.kind
    }

    /// The transport-level stream identifier, the same one
    /// [`ClientEvent::StreamOpened`] reports for data streams.
    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }

    /// The draft version this stream is framed for.
    pub fn draft(&self) -> DraftVersion {
        self.draft
    }

    /// Which side opened this stream.
    ///
    /// [`RequestOrigin::Peer`] means this endpoint owes a response and the
    /// `respond_*` helpers apply; [`RequestOrigin::Local`] means it is waiting
    /// for one.
    pub fn origin(&self) -> RequestOrigin {
        self.origin
    }

    /// Whether a response has been written on this stream by one of the
    /// `respond_*` helpers.
    ///
    /// On a [`RequestOrigin::Local`] stream this says an update the peer sent
    /// was answered here, not that the request itself was: that one is
    /// answered by the peer.
    pub fn responded(&self) -> bool {
        self.responded
    }

    /// Whether [`cancel`](Self::cancel) has already run on this handle.
    ///
    /// Says nothing about the peer: a peer reset is learned from
    /// [`peer_cancelled`](Self::peer_cancelled) or from the next read.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled
    }

    /// Cancel the request by resetting the stream, handing the peer `code`.
    ///
    /// Draft-17 removed UNSUBSCRIBE and FETCH_CANCEL: resetting the request
    /// stream is how a request is withdrawn. Both halves are shut — a QUIC
    /// bidirectional stream has two independent halves, so resetting only the
    /// send half would leave the peer free to keep writing a response nobody
    /// will read. The send half is reset with `code` and the receive half is
    /// stopped with the same value.
    ///
    /// [`REQUEST_CANCELLED`] is the ordinary choice. The parameter is a plain
    /// `u64` rather than a draft enum because draft-17's registry for these
    /// values is titled "Data Stream Reset Error Codes" and a request stream
    /// is not a data stream; a caller who wants a typed value has
    /// [`DataStreamResetErrorCode::as_u64`].
    ///
    /// **This is the stream and nothing else.** The endpoint's record of the
    /// request does not move, so a response already in flight is still accepted
    /// after this returns. [`Connection::cancel_request_stream`] does both and
    /// is what a caller holding a connection should reach for; this stays
    /// because [`Drop`] has no connection to reach.
    ///
    /// Idempotent, and it retires the [`Drop`] behaviour: a cancelled handle
    /// does nothing further when it goes out of scope. Errors from a stream
    /// that was already reset or stopped are swallowed for the same reason —
    /// the request is cancelled either way.
    ///
    /// # Errors
    ///
    /// [`ConnectionError::Transport`] carrying [`TransportError::Write`] if
    /// `code` is outside the QUIC varint range (`0..2^62`). Nothing is sent
    /// in that case, and the handle is *not* marked cancelled, so a caller
    /// can retry with a representable code.
    pub fn cancel(&mut self, code: u64) -> Result<(), ConnectionError> {
        if self.cancelled {
            return Ok(());
        }
        // Reject an unrepresentable code before either half is touched, so a
        // failed call leaves the stream exactly as it was.
        if code > MAX_QUIC_VARINT {
            return Err(ConnectionError::Transport(TransportError::Write(format!(
                "error code {code} exceeds the varint range"
            ))));
        }
        self.cancelled = true;
        // Already-finished or already-reset halves report StreamClosed; the
        // request ends up cancelled regardless, so neither is worth raising.
        let _ = self.send.reset(code);
        let _ = self.recv.stop(code);
        Ok(())
    }

    /// Wait for the peer to cancel this request, consuming nothing.
    ///
    /// A caller applying backpressure is deliberately not calling
    /// [`Connection::recv_on_request_stream`], which is the only other place a
    /// peer reset surfaces — so without this the abandonment goes unobserved
    /// for as long as the backpressure lasts. This grants no flow-control
    /// credit and is cancel-safe.
    ///
    /// Returns `Ok(Some(code))` with the peer's application error code, or
    /// `Ok(None)` meaning **no reset is observable, now or ever — stop
    /// asking**. A caller that re-polls after `Ok(None)` spins.
    ///
    /// Like [`cancel`](Self::cancel), this records nothing at the endpoint.
    /// [`Connection::peer_cancelled_on_request_stream`] is the same wait with
    /// the record attached.
    ///
    /// On WebTransport this always answers `Ok(None)`: `wtransport` exposes no
    /// reset-only observable, so a WebTransport caller learns of a peer cancel
    /// on its next read and not before.
    pub async fn peer_cancelled(&mut self) -> Result<Option<u64>, ConnectionError> {
        self.recv.received_reset().await
    }

    /// Finish the send half cleanly, leaving the receive half open.
    ///
    /// Whether a requester may FIN before its response arrives is not settled
    /// by anything this implementation can check, so no request helper calls
    /// this and the default is to leave the send half open for the request's
    /// life. It is offered for a caller that knows its peer.
    ///
    /// A finished handle, like a cancelled one, does nothing further on
    /// [`Drop`].
    pub async fn finish(&mut self) -> Result<(), ConnectionError> {
        if self.finished || self.cancelled {
            return Ok(());
        }
        self.finished = true;
        self.send.finish().await
    }
}

impl Drop for RequestStream {
    /// Reset the request unless it was already cancelled or finished.
    ///
    /// See the type-level note: the default drop would FIN the send half,
    /// which claims a clean end for a request the caller walked away from.
    ///
    /// The code says which walking away it was. A stream this endpoint opened
    /// is cancelled — [`REQUEST_CANCELLED`] — which is the requester act
    /// draft-17 Section 3.3.1 describes. A stream the peer opened is reset
    /// with [`REQUEST_UNANSWERED`] whether or not a response was already
    /// written: before one, the request was never served; after one, the
    /// obligations that follow it are still outstanding.
    fn drop(&mut self) {
        if self.cancelled || self.finished {
            return;
        }
        let code = match self.origin {
            RequestOrigin::Local => REQUEST_CANCELLED,
            RequestOrigin::Peer => REQUEST_UNANSWERED,
        };
        let _ = self.send.reset(code);
        let _ = self.recv.stop(code);
    }
}

/// Holds a peer-opened stream pair while its first message is being read, and
/// puts it back on the connection's queue if that read is abandoned.
///
/// [`Connection::accept_request_stream`] awaits a whole control message, and a
/// caller may drop that future — a `select!` against a shutdown signal is the
/// ordinary reason. Without this the stream, and every byte already read off
/// it into the reader's buffer, would go with the future: the peer would see a
/// request stream reset for no reason it could act on.
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

/// The largest value a QUIC application error code can carry, `2^62 - 1`.
///
/// Checked by [`RequestStream::cancel`] before either half of the stream is
/// touched, so an unrepresentable code cannot half-cancel a request.
const MAX_QUIC_VARINT: u64 = (1u64 << 62) - 1;

/// A live MoQT connection over QUIC or WebTransport, combining the endpoint
/// state machine with actual network I/O.
pub struct Connection {
    transport: Transport,
    endpoint: Endpoint,
    draft: DraftVersion,
    control_send: Option<FramedSendStream>,
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
    /// Unidirectional streams accepted while `connect` was looking for the
    /// peer's control stream, in arrival order.
    ///
    /// Data streams are allowed to arrive before the control streams on this
    /// draft, so the search cannot assume the first unidirectional stream is
    /// the control one — and dropping the ones that are not would silently
    /// lose objects the peer already sent.
    /// [`accept_subgroup_stream`](Connection::accept_subgroup_stream) empties
    /// this before it accepts anything new.
    ///
    /// Behind a mutex because that method takes `&self`. The lock is only
    /// ever held for a `pop_front`, never across an await.
    deferred_uni: Mutex<VecDeque<FramedRecvStream>>,
    /// Bidirectional streams the peer opened that
    /// [`accept_request_stream`](Connection::accept_request_stream) took off
    /// the transport but did not finish reading a first message from, because
    /// its future was dropped. In arrival order.
    ///
    /// Without this a caller could not put `accept_request_stream` in a
    /// `select!` at all: losing the race would lose a stream the peer had
    /// already opened and, with it, whatever of the request had arrived.
    /// [`accept_request_stream`](Connection::accept_request_stream) empties
    /// this before it accepts anything new.
    ///
    /// Behind a mutex for the same reason `deferred_uni` is: the lock is only
    /// ever held for a push or a pop, never across an await.
    pending_inbound: Mutex<VecDeque<(FramedSendStream, FramedRecvStream)>>,
}

impl Connection {
    /// Connect to a MoQT server as a client.
    ///
    /// Establishes a QUIC or WebTransport connection (based on
    /// `config.transport`), brings up the control plane, performs the SETUP
    /// handshake, and returns a ready-to-use connection.
    ///
    /// # The control plane is a pair of unidirectional streams
    ///
    /// Draft-17 Section 3.3: "MOQT uses a pair of unidirectional streams for
    /// creating the session and exchanging control messages. Each peer opens
    /// one control stream beginning with a SETUP message." So each direction
    /// is a separate stream opened by the peer that writes on it. This opens
    /// one with `open_uni` and writes SETUP on it, then finds the peer's by
    /// accepting unidirectional streams until one leads with
    /// [`CONTROL_STREAM_TYPE`].
    ///
    /// Nothing is written ahead of the SETUP: 0x2F00 is both the SETUP
    /// message type and the unidirectional stream type for a control stream,
    /// so the message's own first field is the stream header. See
    /// [`CONTROL_STREAM_TYPE`].
    ///
    /// A bidirectional stream is *not* the control stream here — the same
    /// section makes it a request stream, one that begins with TRACK_STATUS,
    /// SUBSCRIBE, PUBLISH, FETCH, PUBLISH_NAMESPACE or SUBSCRIBE_NAMESPACE:
    /// "Bidirectional streams MUST NOT begin with any other message type
    /// unless negotiated. If they do, the peer MUST close the Session with a
    /// PROTOCOL_VIOLATION." A SETUP written on a bidirectional stream is
    /// exactly that case, so a peer that enforces the topology answers it by
    /// closing the session.
    ///
    /// # Unidirectional streams that arrive before the peer's control stream
    ///
    /// They are kept, not dropped. Section 3.3 expects them: "Unidirectional
    /// streams containing Objects or bidirectional stream(s) beginning with a
    /// request message could arrive prior to the control streams, in which
    /// case the data SHOULD be buffered until both control streams arrive and
    /// setup is complete." Each such stream is set aside and handed to
    /// [`accept_subgroup_stream`](Self::accept_subgroup_stream) in arrival
    /// order, ahead of any newly accepted stream. Only the leading type
    /// varint is read from them here; the rest stays on the transport, unread
    /// and still flow-controlled, so nothing is buffered in this process
    /// beyond those few bytes.
    ///
    /// One limit worth knowing: the search waits for each stream's type
    /// varint in turn, so a peer that opens a unidirectional stream and then
    /// writes nothing on it stalls the handshake behind that stream.
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

        // Send half of the control plane: one unidirectional stream whose
        // first message is SETUP, which is also its stream header.
        let send = transport.open_uni().await?;
        let mut control_send = FramedSendStream::new(send, draft);

        // Perform setup handshake (draft-17: no versions)
        let mut endpoint = Endpoint::new(Role::Client);
        endpoint.connect()?;
        let setup_msg = endpoint.send_setup(config.setup_parameters.clone())?;
        let any_setup = AnyControlMessage::Draft17(setup_msg);
        let raw_setup = control_send.write_control(&any_setup).await?;

        // Receive half: the peer's control stream is whichever unidirectional
        // stream leads with CONTROL_STREAM_TYPE.
        let mut deferred_uni: VecDeque<FramedRecvStream> = VecDeque::new();
        let mut control_recv = loop {
            let recv = transport.accept_uni().await?;
            let mut framed = FramedRecvStream::new(recv, draft);
            match framed.peek_stream_type().await {
                Ok(CONTROL_STREAM_TYPE) => break framed,
                // Every other type is a data stream — and so is a stream that
                // ended or failed before its type arrived, not because it is
                // one but because there is nothing left to decide with. The
                // data path sees the same end one read later and reports it
                // the way it reports every other. Treating it as the control
                // stream would hand the session's control plane to a stream
                // that carried nothing.
                _ => deferred_uni.push_back(framed),
            }
        };

        let (server_setup, raw_server_setup) = control_recv.read_control(true).await?;
        // Unified SETUP in draft-17: server responds with the same message type.
        match &server_setup {
            AnyControlMessage::Draft17(ControlMessage::Setup(ref s)) => {
                endpoint.receive_setup(s)?;
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
            ClientEvent::SetupComplete { negotiated_version: 0xff000000 + 17 },
        ];

        Ok(Self {
            transport,
            endpoint,
            draft,
            control_send: Some(control_send),
            control_recv: Some(control_recv),
            observer: None,
            pending_events,
            server_setup,
            server_setup_raw: raw_server_setup,
            deferred_uni: Mutex::new(deferred_uni),
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
    /// Wraps the draft-17 message in `AnyControlMessage::Draft17` for
    /// framing. This is the route for the messages that belong to the session
    /// rather than to one request: GOAWAY, NAMESPACE, NAMESPACE_DONE,
    /// PUBLISH_BLOCKED and REQUEST_UPDATE, the last of which carries its own
    /// request id and is handled on the control stream by the peer's endpoint.
    /// SETUP is written by [`connect`](Self::connect) and is the control
    /// stream's own type varint.
    ///
    /// # Requests are refused here
    ///
    /// Draft-17 Section 3.3 moved requests off the control plane, in a
    /// sentence drafts 18 and 19 keep word for word: "In addition to the
    /// control streams, this specification uses bidirectional streams to
    /// carry requests." The response comes back on that same bidirectional
    /// stream, and resetting it cancels the request (Section 3.3.1).
    ///
    /// Which types may open one is not shared, so this method is written
    /// against draft-17's six and no further: they are [`RequestKind`], and
    /// draft-18 makes them seven by adding SUBSCRIBE_TRACKS.
    ///
    /// Handing one of those six to this method returns
    /// [`ConnectionError::RequestOnControlStream`] and writes **nothing** —
    /// an enforcing peer sees no bytes at all, not a misplaced request. Use
    /// the typed helpers, which open a bidirectional stream each:
    /// [`subscribe`](Self::subscribe), [`fetch`](Self::fetch),
    /// [`joining_fetch`](Self::joining_fetch), [`publish`](Self::publish),
    /// [`track_status`](Self::track_status),
    /// [`publish_namespace`](Self::publish_namespace) and
    /// [`subscribe_namespace`](Self::subscribe_namespace).
    ///
    /// Response types are still permitted. A response written here will be
    /// refused by a conforming peer, whose endpoint answers a response on the
    /// control stream with an error — but this is currently the only route
    /// for them at all, since nothing yet accepts a request stream the peer
    /// opened, and refusing them would remove capability rather than fix a
    /// misdirected write. [`publish_done`](Self::publish_done), the one
    /// response with a helper, does not come through here: it takes the
    /// request stream its PUBLISH opened.
    pub async fn send_control(&mut self, msg: &ControlMessage) -> Result<(), ConnectionError> {
        let ty = msg.message_type();
        if starts_a_request_stream(ty) {
            return Err(ConnectionError::RequestOnControlStream(ty));
        }
        // What this endpoint refuses to receive on the control stream it must
        // not write there either, or the client emits frames its own peer half
        // would close the session over.
        if belongs_on_a_request_stream(ty) {
            return Err(ConnectionError::RequestStreamMessageOnControlStream(ty));
        }
        let any = AnyControlMessage::Draft17(msg.clone());
        let send = self.control_send.as_mut().ok_or(ConnectionError::NoControlStream)?;
        let raw = send.write_control(&any).await?;
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
    /// Returns the `AnyControlMessage` and also extracts the draft-17
    /// `ControlMessage` for internal endpoint dispatch.
    pub async fn recv_control(&mut self) -> Result<ControlMessage, ConnectionError> {
        let recv = self.control_recv.as_mut().ok_or(ConnectionError::NoControlStream)?;
        let capture_raw = self.observer.is_some();
        let read = recv.read_control(capture_raw).await;
        let (any, raw) = match read {
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
        // Unwrap to draft-17 for the endpoint
        match any {
            AnyControlMessage::Draft17(msg) => Ok(msg),
            // `AnyControlMessage` carries one variant per enabled draft feature. With draft 17 the
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
    ///
    /// Responses never arrive here. Draft-17 responses carry no request id
    /// and belong on the request stream that asked for them, so the endpoint
    /// refuses a response that turns up on the control stream. Read them with
    /// [`recv_on_request_stream`](Self::recv_on_request_stream).
    pub async fn recv_and_dispatch(&mut self) -> Result<ControlMessage, ConnectionError> {
        let msg = self.recv_control().await?;
        self.endpoint.receive_message(msg.clone()).map_err(|e| self.close_if_session_fatal(e))?;

        // Emit draining event if this was a GoAway
        if let ControlMessage::GoAway(ref ga) = msg {
            self.emit(ClientEvent::Draining { new_session_uri: ga.new_session_uri.clone() });
        }

        Ok(msg)
    }

    // -- Request streams --------------------------------------------

    /// Open the bidirectional stream a request will be carried on.
    ///
    /// Opened *before* the endpoint allocates a request id, so a transport
    /// that refuses a new stream — the peer's `initial_max_streams_bidi` is
    /// exhausted, the connection is gone — costs nothing. The endpoint has no
    /// way to abandon a request it has already allocated, so every failure
    /// that can be moved ahead of the allocation is.
    ///
    /// Nothing is written here. A request stream carries no stream-type
    /// header: its first field is the leading message's own type field, which
    /// is what [`begin_request`](Self::begin_request) writes.
    async fn open_request_bi(
        &self,
    ) -> Result<(FramedSendStream, FramedRecvStream), ConnectionError> {
        let (send, recv) = self.transport.open_bi().await?;
        Ok((FramedSendStream::new(send, self.draft), FramedRecvStream::new(recv, self.draft)))
    }

    /// Reset a request stream that was opened but whose request could not be
    /// built, and pass the endpoint's error through.
    ///
    /// Without this, an endpoint refusal — the session is draining, the
    /// request-id range is exhausted — would leave a bidirectional stream
    /// open that never carries a first message, and dropping it would FIN it,
    /// telling the peer an empty stream ended cleanly.
    fn or_abandon<T>(
        halves: &mut (FramedSendStream, FramedRecvStream),
        built: Result<T, EndpointError>,
    ) -> Result<T, ConnectionError> {
        match built {
            Ok(value) => Ok(value),
            Err(e) => {
                let _ = halves.0.reset(REQUEST_CANCELLED);
                let _ = halves.1.stop(REQUEST_CANCELLED);
                Err(ConnectionError::Endpoint(e))
            }
        }
    }

    /// Write `msg` as the first message on an opened bidirectional stream and
    /// hand back the [`RequestStream`] that owns both halves.
    ///
    /// This is the one place a request reaches the wire. Every request helper
    /// funnels through it, so the ordering — open, allocate, write, emit — is
    /// stated once.
    ///
    /// A failed write resets both halves rather than leaving a half-written
    /// request stream behind. What it cannot undo is the endpoint's
    /// allocation: the request id and its state machine already exist, and
    /// there is no way to retract them, so a write that fails here leaves one
    /// pending request the endpoint will never see answered.
    async fn begin_request(
        &mut self,
        halves: (FramedSendStream, FramedRecvStream),
        kind: RequestKind,
        request_id: VarInt,
        msg: &ControlMessage,
    ) -> Result<RequestStream, ConnectionError> {
        debug_assert_eq!(
            msg.message_type(),
            kind.message_type(),
            "a request stream's first message must be the one its kind names"
        );
        let (mut send, mut recv) = halves;
        let stream_id = send.stream_id();
        self.emit(ClientEvent::StreamOpened {
            direction: Direction::Send,
            stream_kind: StreamKind::Request,
            stream_id,
        });
        let any = AnyControlMessage::Draft17(msg.clone());
        let raw = match send.write_control(&any).await {
            Ok(raw) => raw,
            Err(e) => {
                let _ = send.reset(REQUEST_CANCELLED);
                let _ = recv.stop(REQUEST_CANCELLED);
                return Err(e);
            }
        };
        self.emit(ClientEvent::ControlMessage {
            direction: Direction::Send,
            message: any,
            stream_id: Some(stream_id),
            raw: Some(raw),
        });
        Ok(RequestStream {
            send,
            recv,
            request_id,
            kind,
            draft: self.draft,
            stream_id,
            cancelled: false,
            finished: false,
            origin: RequestOrigin::Local,
            responded: false,
        })
    }

    /// Read the next message off a request stream and dispatch it through the
    /// endpoint with that stream's own request id.
    ///
    /// On draft-17 a response carries no request id; the stream is the
    /// correlation, so the id comes from the handle and not from the wire.
    ///
    /// This blocks until a whole message has arrived. Backpressure is per
    /// request: a stream nobody reads stays unread, and the peer stays flow
    /// controlled on it alone. A peer that reset the stream surfaces as
    /// [`ConnectionError::Transport`] carrying
    /// [`TransportError::StreamReset`] with the peer's code; a caller that is
    /// deliberately not reading should watch
    /// [`RequestStream::peer_cancelled`] instead.
    ///
    /// # Errors
    ///
    /// [`ConnectionError::Endpoint`] if the message is not one of this
    /// draft's response types, or if it does not fit the request's state.
    /// The message has already been emitted to the observer by then — what
    /// arrived is reported whether or not the endpoint accepts it.
    pub async fn recv_on_request_stream(
        &mut self,
        stream: &mut RequestStream,
    ) -> Result<ControlMessage, ConnectionError> {
        let capture_raw = self.observer.is_some();
        let (any, raw) = match stream.recv.read_control(capture_raw).await {
            Ok(read) => read,
            Err(e) => {
                // A peer that reset this stream cancelled the request on it,
                // and this is where a caller reading normally learns of it. The
                // record is made and its verdict dropped: the read's own error
                // is what the caller has to act on, and returning a state error
                // in its place would hide a reset behind it.
                if matches!(e, ConnectionError::Transport(TransportError::StreamReset(_))) {
                    let _ = self.endpoint.cancel_request(stream.request_id);
                }
                return Err(e);
            }
        };
        if capture_raw {
            self.emit(ClientEvent::ControlMessage {
                direction: Direction::Receive,
                message: any.clone(),
                stream_id: Some(stream.stream_id()),
                raw,
            });
        }
        let msg = match any {
            AnyControlMessage::Draft17(msg) => Ok::<_, ConnectionError>(msg),
            // `AnyControlMessage` carries one variant per enabled draft feature. With draft 17 the
            // only one enabled the arm above is exhaustive and this rejection arm unreachable.
            // Compiled in every configuration with the lint allowed, rather than gated on a `cfg`
            // naming the other drafts: such a list has to be edited in every draft module
            // whenever a draft is added, and a copy that omits one leaves this match
            // non-exhaustive.
            #[allow(unreachable_patterns)]
            _ => Err(ConnectionError::ControlMessageNarrowing),
        }?;
        // Which dispatcher this belongs to is decided by who opened the
        // stream, not by the message. On a stream this endpoint opened the
        // next message is the answer to our request; on one the peer opened it
        // cannot be, because we are the one who owes an answer. Feeding a
        // peer's REQUEST_UPDATE to the response dispatcher would look up a
        // request we never made.
        let dispatched = match stream.origin {
            RequestOrigin::Local => {
                self.endpoint.receive_response_on_stream(stream.request_id, msg.clone())
            }
            RequestOrigin::Peer => {
                self.endpoint.receive_on_peer_request_stream(stream.request_id, msg.clone())
            }
        };
        dispatched.map_err(|e| self.close_if_session_fatal(e))?;
        Ok(msg)
    }

    /// Write a follow-up message on an already-open request stream.
    ///
    /// The request itself was written when the stream was opened; this is for
    /// what comes after it on the same stream, PUBLISH_DONE among them — see
    /// [`publish_done`](Self::publish_done), which uses this.
    ///
    /// It does not refuse any message type. Which messages may follow a
    /// request on its own stream is not something this implementation can
    /// settle, so the choice is left to the caller rather than guessed at.
    pub async fn send_on_request_stream(
        &mut self,
        stream: &mut RequestStream,
        msg: &ControlMessage,
    ) -> Result<(), ConnectionError> {
        let any = AnyControlMessage::Draft17(msg.clone());
        let raw = stream.send.write_control(&any).await?;
        self.emit(ClientEvent::ControlMessage {
            direction: Direction::Send,
            message: any,
            stream_id: Some(stream.stream_id()),
            raw: Some(raw),
        });
        Ok(())
    }

    /// Cancel a request: record it at the endpoint, then terminate its stream.
    ///
    /// Section 3.3.1 puts the cancel at the stream — "Implementations SHOULD
    /// cancel requests by abruptly terminating any directions of a stream that
    /// are still open" — while the request's own state lives in the endpoint,
    /// so the two have to move together. This is the only place that moves
    /// both.
    ///
    /// The endpoint goes first and the stream is terminated only if it agrees,
    /// which is the order every request path here uses: a caller acts on a
    /// stream after the endpoint has accepted the step, never before. A refused
    /// cancel therefore leaves the stream exactly as it was, and
    /// [`RequestStream::cancel`] is still there for a caller that wants the
    /// stream reset regardless.
    ///
    /// Idempotent from both ends: a request that has already ended accepts the
    /// cancel and stays where it is, and a handle that has already been
    /// cancelled resets nothing a second time.
    ///
    /// # Errors
    ///
    /// [`ConnectionError::Endpoint`] if no request carries this stream's id or
    /// the request has not been written, and [`ConnectionError::Transport`] if
    /// `code` is outside the QUIC varint range — see
    /// [`RequestStream::cancel`], which is what sends it.
    pub fn cancel_request_stream(
        &mut self,
        stream: &mut RequestStream,
        code: u64,
    ) -> Result<(), ConnectionError> {
        let recorded = self.endpoint.cancel_request(stream.request_id);
        recorded.map_err(|e| self.close_if_session_fatal(e))?;
        stream.cancel(code)
    }

    /// Wait for the peer to cancel this request, and record it if it does.
    ///
    /// [`RequestStream::peer_cancelled`] with the endpoint's record attached. A
    /// caller applying backpressure is deliberately not calling
    /// [`recv_on_request_stream`](Self::recv_on_request_stream), which is the
    /// other place a peer reset surfaces, so without this the request would end
    /// on the wire and stay open in the endpoint's record for as long as the
    /// backpressure lasts.
    ///
    /// Returns what the handle's own method returns; see it for the `Ok(None)`
    /// case and for what WebTransport can and cannot observe. Cancel-safe, and
    /// it grants no flow-control credit.
    pub async fn peer_cancelled_on_request_stream(
        &mut self,
        stream: &mut RequestStream,
    ) -> Result<Option<u64>, ConnectionError> {
        let code = stream.peer_cancelled().await?;
        if code.is_some() {
            // Discarded for the reason the read path discards it: the peer has
            // ended the request whatever the record said, and a state error
            // here would replace the answer the caller asked for.
            let _ = self.endpoint.cancel_request(stream.request_id);
        }
        Ok(code)
    }

    // -- Accepting the peer's request streams -----------------------

    /// Accept the next bidirectional stream the peer opened, read the request
    /// it begins with, and hand back that request and a handle to answer it
    /// on.
    ///
    /// This is the mirror of the request helpers. Where
    /// [`subscribe`](Self::subscribe) and its siblings open a stream and write
    /// a request, this takes one the peer opened and reads one. Draft-17
    /// Section 3.3 puts requests in both directions on bidirectional streams,
    /// so a client that only ever calls the helpers can never be published to
    /// or subscribed from.
    ///
    /// The returned [`RequestStream`] carries [`RequestOrigin::Peer`]. Answer
    /// it with [`respond_subscribe_ok`](Self::respond_subscribe_ok),
    /// [`respond_fetch_ok`](Self::respond_fetch_ok),
    /// [`respond_publish_ok`](Self::respond_publish_ok),
    /// [`respond_ok`](Self::respond_ok) or
    /// [`respond_error`](Self::respond_error), and **hold it for as long as
    /// the request lasts** — a subscription's PUBLISH_DONE is written on it,
    /// and dropping it resets the stream.
    ///
    /// # Two refusals, two codes
    ///
    /// Draft-17 Section 3.3, on a stream that begins with the wrong type:
    /// "Bidirectional streams MUST NOT begin with any other message type
    /// unless negotiated. If they do, the peer MUST close the Session with a
    /// PROTOCOL_VIOLATION." Section 9.1, on the Request ID: "If an endpoint
    /// receives a Request ID where the least significant bit is incorrect for
    /// the sender, or a duplicate Request ID, it MUST close the session with
    /// INVALID_REQUEST_ID." Both are closes of the session on the wire, with
    /// different codes, and both happen before this returns — the error handed
    /// back reports a session that is already gone, not one the caller must
    /// remember to close.
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
    /// peer's request moves endpoint state, and no signature avoids that while
    /// the connection owns the endpoint. A caller blocked in
    /// [`recv_on_request_stream`](Self::recv_on_request_stream) waiting for
    /// its own response is not accepting, and the peer's request streams queue
    /// up in the transport behind it. One loop that never blocks indefinitely
    /// on a single read is the shape this supports.
    ///
    /// # Ordering
    ///
    /// The endpoint is told about the request last, after every step that can
    /// fail or be cancelled, and building the handle afterwards cannot fail.
    /// This is the inverse of the outbound path's reasoning — it opens the
    /// stream before allocating a Request ID for the same reason — and rests
    /// on the same fact: the endpoint has no way to
    /// abandon a request it has already registered. Registering earlier would
    /// let a cancelled accept leave a state machine keyed to a stream nobody
    /// holds, and the peer's next use of that Request ID would then be
    /// reported as a duplicate — a session close, over an id the peer used
    /// exactly once.
    ///
    /// # Errors
    ///
    /// - [`ConnectionError::NonRequestOnRequestStream`] — the session has been
    ///   closed with PROTOCOL_VIOLATION and the stream reset.
    /// - [`ConnectionError::Endpoint`] carrying `RequestId` or
    ///   `DuplicateRequestId` — the session has been closed with
    ///   INVALID_REQUEST_ID and the stream reset.
    /// - [`ConnectionError::Endpoint`] carrying `NotActive` or `Draining` —
    ///   the stream is reset, the session is left alone.
    /// - [`ConnectionError::Transport`] or [`ConnectionError::Codec`] — the
    ///   stream is reset, the session is left alone.
    pub async fn accept_request_stream(
        &mut self,
    ) -> Result<(ControlMessage, RequestStream), ConnectionError> {
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
                    let _ = send.reset(REQUEST_UNANSWERED);
                    let _ = recv.stop(REQUEST_UNANSWERED);
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
            stream_kind: StreamKind::Request,
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
            AnyControlMessage::Draft17(msg) => msg,
            // `AnyControlMessage` carries one variant per enabled draft feature. With draft 17 the
            // only one enabled the arm above is exhaustive and this rejection arm unreachable.
            // Compiled in every configuration with the lint allowed, rather than gated on a `cfg`
            // naming the other drafts: such a list has to be edited in every draft module
            // whenever a draft is added, and a copy that omits one leaves this match
            // non-exhaustive.
            #[allow(unreachable_patterns)]
            _ => {
                let _ = send.reset(REQUEST_UNANSWERED);
                let _ = recv.stop(REQUEST_UNANSWERED);
                return Err(ConnectionError::ControlMessageNarrowing);
            }
        };

        let ty = msg.message_type();
        let Some(kind) = RequestKind::from_message_type(ty) else {
            let err = self.endpoint.refuse_non_request(ty);
            self.close_for(&err);
            let _ = send.reset(REQUEST_UNANSWERED);
            let _ = recv.stop(REQUEST_UNANSWERED);
            return Err(ConnectionError::NonRequestOnRequestStream(ty));
        };

        let request_id = match self.endpoint.receive_request_on_stream(&msg) {
            Ok(request_id) => request_id,
            Err(e) => {
                let _ = send.reset(REQUEST_UNANSWERED);
                let _ = recv.stop(REQUEST_UNANSWERED);
                return Err(self.close_if_session_fatal(e));
            }
        };

        Ok((
            msg,
            RequestStream {
                send,
                recv,
                request_id,
                kind,
                draft: self.draft,
                stream_id,
                cancelled: false,
                finished: false,
                origin: RequestOrigin::Peer,
                responded: false,
            },
        ))
    }

    /// Take the oldest stream pair a cancelled
    /// [`accept_request_stream`](Self::accept_request_stream) put back, if any.
    ///
    /// Synchronous on purpose, like
    /// [`take_deferred_uni`](Self::take_deferred_uni): the guard is dropped
    /// before the caller awaits, so the lock is never held across a suspension
    /// point.
    fn take_pending_inbound(&self) -> Option<(FramedSendStream, FramedRecvStream)> {
        self.pending_inbound.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).pop_front()
    }

    /// How many peer-opened request streams a cancelled
    /// [`accept_request_stream`](Self::accept_request_stream) put back and a
    /// later call has not yet taken.
    ///
    /// Zero unless an accept future was dropped mid-read.
    pub fn pending_inbound_count(&self) -> usize {
        self.pending_inbound.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).len()
    }

    // -- Answering the peer's requests ------------------------------

    /// Write `msg` as the response to the request `stream` carries, driving
    /// the endpoint first and the wire second.
    ///
    /// The response goes on the request's own bidirectional stream and never
    /// on the control stream: draft-17 responses carry no Request ID, so the
    /// stream is the only thing that says what is being answered. Taking the
    /// id off the handle rather than from the caller makes that correlation
    /// unforgeable.
    ///
    /// `fin` is true only for REQUEST_ERROR. See
    /// [`respond_error`](Self::respond_error).
    async fn respond(
        &mut self,
        stream: &mut RequestStream,
        msg: ControlMessage,
        fin: bool,
    ) -> Result<(), ConnectionError> {
        // A request this endpoint made is answered by the peer, with one
        // exception the draft states outright: "A subscriber can also send
        // REQUEST_UPDATE to modify parameters of a subscription established
        // with PUBLISH", and the receiver of one "MUST respond with exactly one
        // REQUEST_OK or REQUEST_ERROR message indicating if the update was
        // successful". On a PUBLISH this endpoint sent, that receiver is this
        // endpoint, so the one response it may write on a stream of its own is
        // the answer to an update waiting there.
        let answers_an_update =
            matches!(msg, ControlMessage::RequestOk(_) | ControlMessage::RequestError(_))
                && self.endpoint.has_unanswered_update(stream.request_id);
        if stream.origin != RequestOrigin::Peer && !answers_an_update {
            return Err(ConnectionError::RespondedToOwnRequest(stream.request_id.into_inner()));
        }
        // The endpoint first, so a response that does not fit the request's
        // state is refused before any of it reaches the wire. What this cannot
        // undo is a write that fails afterwards, which leaves the state
        // machine one step ahead of the peer — the same asymmetry
        // `begin_request` carries on the outbound side.
        self.endpoint.send_response_on_stream(stream.request_id, &msg)?;
        self.send_on_request_stream(stream, &msg).await?;
        stream.responded = true;
        // `fin` says the message ends the exchange; owing a termination says
        // it does not, whatever the message looks like. A REQUEST_ERROR
        // answering an update is the case where the two disagree, and the
        // draft asks for a PUBLISH_DONE after it that a finished send half
        // could not carry.
        if fin && !self.endpoint.owes_update_failure(stream.request_id) {
            stream.finish().await?;
        }
        Ok(())
    }

    /// Answer a peer's PUBLISH_NAMESPACE, SUBSCRIBE_NAMESPACE or TRACK_STATUS
    /// with REQUEST_OK.
    ///
    /// The send half is left open. A SUBSCRIBE_NAMESPACE responder still owes
    /// the peer the namespaces it accepted, so finishing here would end the
    /// request before it had been served; a TRACK_STATUS responder owes
    /// nothing further and may call [`RequestStream::finish`] straight after.
    ///
    /// # Errors
    ///
    /// [`ConnectionError::RespondedToOwnRequest`] if `stream` is one this
    /// endpoint opened, and [`ConnectionError::Endpoint`] if no request of a
    /// kind REQUEST_OK answers is pending on it. Nothing is written either
    /// way.
    pub async fn respond_ok(
        &mut self,
        stream: &mut RequestStream,
        response: RequestOk,
    ) -> Result<(), ConnectionError> {
        self.respond(stream, ControlMessage::RequestOk(response), false).await
    }

    /// Answer a peer's SUBSCRIBE with SUBSCRIBE_OK.
    ///
    /// The send half is left open, and it must be: this endpoint is now the
    /// publisher of an established subscription and owes it a PUBLISH_DONE,
    /// which travels on this same stream —
    /// [`publish_done_on`](Self::publish_done_on).
    pub async fn respond_subscribe_ok(
        &mut self,
        stream: &mut RequestStream,
        response: SubscribeOk,
    ) -> Result<(), ConnectionError> {
        self.respond(stream, ControlMessage::SubscribeOk(response), false).await
    }

    /// Answer a peer's FETCH with FETCH_OK.
    ///
    /// The send half is left open. The fetched objects travel on separate
    /// unidirectional streams, so a fetch responder may call
    /// [`RequestStream::finish`] as soon as this returns; it is not done here
    /// because nothing about FETCH_OK says the responder has no more to write.
    pub async fn respond_fetch_ok(
        &mut self,
        stream: &mut RequestStream,
        response: FetchOk,
    ) -> Result<(), ConnectionError> {
        self.respond(stream, ControlMessage::FetchOk(response), false).await
    }

    /// Answer a peer's PUBLISH with PUBLISH_OK.
    ///
    /// Draft-17 has PUBLISH_OK as a message of its own, 0x1E; drafts 18 and 19
    /// folded it into REQUEST_OK. The send half is left open: accepting a
    /// PUBLISH establishes a subscription whose PUBLISH_DONE arrives on this
    /// stream.
    pub async fn respond_publish_ok(
        &mut self,
        stream: &mut RequestStream,
        response: PublishOk,
    ) -> Result<(), ConnectionError> {
        self.respond(stream, ControlMessage::PublishOk(response), false).await
    }

    /// Reject a peer's request with REQUEST_ERROR, and finish the send half.
    ///
    /// The FIN is part of the act, not a convenience: draft-17 Section 3.3.1
    /// says "When an endpoint rejects a request without performing any
    /// application processing, it SHOULD send a REQUEST_ERROR and FIN the
    /// stream." It is also the one response that can be finished immediately,
    /// because a rejected request leaves nothing further to send — every
    /// success path owes the peer something more.
    ///
    /// A finished handle does nothing further on [`Drop`], so the rejected
    /// stream is not then reset.
    pub async fn respond_error(
        &mut self,
        stream: &mut RequestStream,
        response: RequestError,
    ) -> Result<(), ConnectionError> {
        self.respond(stream, ControlMessage::RequestError(response), true).await
    }

    /// End a subscription this endpoint accepted, on the stream the peer's
    /// SUBSCRIBE opened.
    ///
    /// The mirror of [`publish_done`](Self::publish_done), which ends a
    /// publication this endpoint offered with PUBLISH. Both write PUBLISH_DONE
    /// on a request stream and take the Request ID off the handle; they differ
    /// in which state machine moves, and therefore in which one refuses.
    pub async fn publish_done_on(
        &mut self,
        stream: &mut RequestStream,
        status_code: VarInt,
        stream_count: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<(), ConnectionError> {
        let msg = ControlMessage::PublishDone(moqtap_codec::draft17::message::PublishDone {
            status_code,
            stream_count,
            reason_phrase,
        });
        self.respond(stream, msg, false).await
    }

    // -- Subscribe flow ---------------------------------------------

    /// Send a SUBSCRIBE on a bidirectional stream of its own.
    ///
    /// The returned [`RequestStream`] is where SUBSCRIBE_OK, REQUEST_ERROR
    /// and later PUBLISH_DONE arrive — read them with
    /// [`recv_on_request_stream`](Self::recv_on_request_stream). **Hold it for
    /// the subscription's life**: dropping it resets the stream, which
    /// cancels the subscription.
    pub async fn subscribe(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        parameters: Vec<KeyValuePair>,
    ) -> Result<RequestStream, ConnectionError> {
        let mut halves = self.open_request_bi().await?;
        let (req_id, msg) = Self::or_abandon(
            &mut halves,
            self.endpoint.subscribe(track_namespace, track_name, parameters),
        )?;
        self.begin_request(halves, RequestKind::Subscribe, req_id, &msg).await
    }

    // Draft-17: UNSUBSCRIBE removed. Subscribers end a subscription by
    // resetting its request stream — `RequestStream::cancel` — or wait for
    // PublishDone.

    // -- Fetch flow -------------------------------------------------

    /// Send a standalone FETCH on a bidirectional stream of its own.
    ///
    /// FETCH_OK or REQUEST_ERROR comes back on the returned
    /// [`RequestStream`]; the fetched objects arrive on separate
    /// unidirectional data streams. Dropping the handle cancels the fetch.
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
    ) -> Result<RequestStream, ConnectionError> {
        let mut halves = self.open_request_bi().await?;
        let (req_id, msg) = Self::or_abandon(
            &mut halves,
            self.endpoint.fetch(
                track_namespace,
                track_name,
                start_group,
                start_object,
                end_group,
                end_object,
                parameters,
            ),
        )?;
        self.begin_request(halves, RequestKind::Fetch, req_id, &msg).await
    }

    /// Send a Relative Joining Fetch (Fetch Type 0x2) on a bidirectional
    /// stream of its own.
    ///
    /// A joining FETCH names an existing subscription's request id but is
    /// still a FETCH, so it opens its own request stream rather than sharing
    /// the subscription's.
    ///
    /// `joining_start` counts groups back from the subscription's largest
    /// group. To name the starting group outright, use
    /// [`absolute_joining_fetch`](Self::absolute_joining_fetch).
    pub async fn joining_fetch(
        &mut self,
        joining_request_id: VarInt,
        joining_start: VarInt,
        parameters: Vec<KeyValuePair>,
    ) -> Result<RequestStream, ConnectionError> {
        let mut halves = self.open_request_bi().await?;
        let (req_id, msg) = Self::or_abandon(
            &mut halves,
            self.endpoint.joining_fetch(joining_request_id, joining_start, parameters),
        )?;
        self.begin_request(halves, RequestKind::Fetch, req_id, &msg).await
    }

    /// Send an Absolute Joining Fetch (Fetch Type 0x3) on a bidirectional
    /// stream of its own.
    ///
    /// Here `joining_start` is the group to begin at rather than an offset:
    /// draft-17 Section 9.14.2.1 has the publisher set the Start Location to
    /// {Joining Start, 0}.
    pub async fn absolute_joining_fetch(
        &mut self,
        joining_request_id: VarInt,
        joining_start: VarInt,
        parameters: Vec<KeyValuePair>,
    ) -> Result<RequestStream, ConnectionError> {
        let mut halves = self.open_request_bi().await?;
        let (req_id, msg) = Self::or_abandon(
            &mut halves,
            self.endpoint.absolute_joining_fetch(joining_request_id, joining_start, parameters),
        )?;
        self.begin_request(halves, RequestKind::Fetch, req_id, &msg).await
    }

    // Draft-17: FETCH_CANCEL removed. Fetchers abort with
    // `RequestStream::cancel`, which resets the request stream.

    // -- Namespace flows --------------------------------------------

    /// Send a SUBSCRIBE_NAMESPACE on a bidirectional stream of its own.
    ///
    /// `subscribe_options` is draft-17's; draft-18 removed the field.
    pub async fn subscribe_namespace(
        &mut self,
        namespace_prefix: TrackNamespace,
        subscribe_options: VarInt,
        parameters: Vec<KeyValuePair>,
    ) -> Result<RequestStream, ConnectionError> {
        let mut halves = self.open_request_bi().await?;
        let (req_id, msg) = Self::or_abandon(
            &mut halves,
            self.endpoint.subscribe_namespace(namespace_prefix, subscribe_options, parameters),
        )?;
        self.begin_request(halves, RequestKind::SubscribeNamespace, req_id, &msg).await
    }

    /// Send a PUBLISH_NAMESPACE on a bidirectional stream of its own.
    pub async fn publish_namespace(
        &mut self,
        track_namespace: TrackNamespace,
        parameters: Vec<KeyValuePair>,
    ) -> Result<RequestStream, ConnectionError> {
        let mut halves = self.open_request_bi().await?;
        let (req_id, msg) = Self::or_abandon(
            &mut halves,
            self.endpoint.publish_namespace(track_namespace, parameters),
        )?;
        self.begin_request(halves, RequestKind::PublishNamespace, req_id, &msg).await
    }

    // -- Track Status flow ------------------------------------------

    /// Send a TRACK_STATUS on a bidirectional stream of its own.
    pub async fn track_status(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        parameters: Vec<KeyValuePair>,
    ) -> Result<RequestStream, ConnectionError> {
        let mut halves = self.open_request_bi().await?;
        let (req_id, msg) = Self::or_abandon(
            &mut halves,
            self.endpoint.track_status(track_namespace, track_name, parameters),
        )?;
        self.begin_request(halves, RequestKind::TrackStatus, req_id, &msg).await
    }

    // -- Publish flow (publisher side) ------------------------------

    /// Send a PUBLISH on a bidirectional stream of its own.
    ///
    /// PUBLISH_OK or REQUEST_ERROR comes back on the returned
    /// [`RequestStream`], and [`publish_done`](Self::publish_done) is written
    /// back on it when the publication ends — so the handle must be held for
    /// as long as the publication lasts.
    pub async fn publish(
        &mut self,
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        track_alias: VarInt,
        parameters: Vec<KeyValuePair>,
        track_properties: Vec<KeyValuePair>,
    ) -> Result<RequestStream, ConnectionError> {
        let mut halves = self.open_request_bi().await?;
        let (req_id, msg) = Self::or_abandon(
            &mut halves,
            self.endpoint.publish(
                track_namespace,
                track_name,
                track_alias,
                parameters,
                track_properties,
            ),
        )?;
        self.begin_request(halves, RequestKind::Publish, req_id, &msg).await
    }

    /// Send a PUBLISH_DONE on the request stream the PUBLISH opened.
    ///
    /// PUBLISH_DONE is a response and carries no request id on the wire, so
    /// the stream is the only thing that says which publication ended. The id
    /// the endpoint needs is taken off `stream`, which makes the correlation
    /// unforgeable — there is no way to name one request and write on
    /// another's stream.
    pub async fn publish_done(
        &mut self,
        stream: &mut RequestStream,
        status_code: VarInt,
        stream_count: VarInt,
        reason_phrase: Vec<u8>,
    ) -> Result<(), ConnectionError> {
        let request_id = stream.request_id();
        let msg = self.endpoint.send_publish_done(
            request_id,
            status_code,
            stream_count,
            reason_phrase,
        )?;
        self.send_on_request_stream(stream, &msg).await
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

    /// Accept an incoming unidirectional data stream and read its subgroup
    /// header.
    ///
    /// Streams the peer opened before its control stream are returned first,
    /// in arrival order, before any new one is accepted from the transport:
    /// [`connect`](Self::connect) had to look at them to find the control
    /// stream and set the rest aside rather than drop them. They are
    /// otherwise ordinary — the type varint `connect` read is still on the
    /// front of each one.
    pub async fn accept_subgroup_stream(
        &self,
    ) -> Result<(AnySubgroupHeader, FramedRecvStream), ConnectionError> {
        let mut framed = match self.take_deferred_uni() {
            Some(framed) => framed,
            None => FramedRecvStream::new(self.transport.accept_uni().await?, self.draft),
        };
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
        let mut framed = match self.take_deferred_uni() {
            Some(framed) => framed,
            None => FramedRecvStream::new(self.transport.accept_uni().await?, self.draft),
        };
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

    /// Take the oldest stream [`connect`](Self::connect) set aside, if any.
    ///
    /// Synchronous on purpose: the guard is dropped before the caller awaits,
    /// so the lock is never held across a suspension point. A poisoned lock
    /// is recovered rather than propagated — nothing here can leave the queue
    /// in a state a later reader could be misled by, since the only mutation
    /// is a `pop_front`.
    fn take_deferred_uni(&self) -> Option<FramedRecvStream> {
        self.deferred_uni.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).pop_front()
    }

    /// How many unidirectional streams [`connect`](Self::connect) set aside
    /// and [`accept_subgroup_stream`](Self::accept_subgroup_stream) has not
    /// yet handed back.
    ///
    /// Zero for a peer that opened its control stream first, which is the
    /// ordinary case.
    pub fn deferred_stream_count(&self) -> usize {
        self.deferred_uni.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).len()
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
        // Refutable only in a build with more than one draft enabled;
        // in a single-draft build `AnyDatagramHeader` has one variant.
        #[allow(irrefutable_let_patterns)]
        if let AnyDatagramHeader::Draft17(h) = &header {
            if !h.permits_payload() && !payload.is_empty() {
                return Err(ConnectionError::PayloadOnStatusDatagram {
                    object_id: h.object_id.into_inner(),
                    payload_len: payload.len(),
                    status: h.object_status,
                });
            }
        }
        // A datagram is a whole object, so the connection can measure it
        // without help from the caller. It cannot *answer* the condition,
        // though: the answer is a reset of a request stream the caller holds,
        // so both data paths report and neither withdraws - see
        // `Connection::requests_to_cancel`.
        let meta = header.meta();
        self.endpoint.note_received_object(
            meta.track_alias,
            ObjectLocation { group: meta.group_id, object: meta.object_id },
            object_role(meta.status),
        )?;
        Ok((header, payload))
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

    /// Close the session on the wire when the endpoint says a violation is
    /// fatal to it.
    ///
    /// [`EndpointError::session_error_code`] answers `Some` for exactly the
    /// errors draft-17 tells the receiver to close the session over, and the
    /// endpoint has already moved its own state machine to Closed by the time
    /// this runs. Without this step that move is purely internal: the local
    /// endpoint refuses to start anything new while the peer, which is the one
    /// that broke the rule, sees a session that is still open and goes on
    /// sending. "MUST close the session with a PROTOCOL_VIOLATION" is a
    /// statement about the wire, so it takes a CONNECTION_CLOSE to satisfy it.
    ///
    /// The reason phrase is the error's own `Display` text, which names the
    /// message and the rule rather than repeating the numeric code the close
    /// already carries.
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

    /// Which of this draft's *own* `ConnectionError` variants this error is,
    /// and which kind of thing it says.
    ///
    /// The ten every draft carries answer `None` here: [`AnyConnectionError`]
    /// classifies those itself, once, and never asks a draft about them. What
    /// is left splits two ways, and the split is the reason this function
    /// exists — before it, both halves reached a caller as a sentence and read
    /// exactly alike. A [`LocalRefusal`] is this endpoint declining to write
    /// something, so nothing reached the wire and no relay is implicated; a
    /// [`PeerViolation`] is a peer having done something draft-17 forbids, and
    /// carries the session error code draft-17's own text answers it with.
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
        use moqtap_codec::draft17::error_codes::SessionErrorCode;

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
            ConnectionError::PropertiesOnNonNormalStatus { .. } => {
                Some(DraftSpecificCause::PeerViolation {
                    rule: AboveCodecRule::PropertiesOnNonNormalStatus,
                    close: Some(SessionErrorCode::ProtocolViolation.as_u64()),
                })
            }
            // Section 10.2.1.1 states this one as a property of a conforming
            // Object rather than as one of the cases a draft answers with a
            // close. That phrase carries no quotation marks and must not: it
            // is this crate naming a shape of drafting, and the marks would
            // file the words on the section named right beside them — which is
            // the one section here that pointedly does not carry them. The
            // datagram is refused and the session is left running. `None` is
            // that reading, and it is what keeps a relay from being published
            // for a rule its draft attaches no consequence to.
            ConnectionError::PayloadOnStatusDatagram { .. } => {
                Some(DraftSpecificCause::PeerViolation {
                    rule: AboveCodecRule::PayloadOnStatusDatagram,
                    close: None,
                })
            }
            // Section 3.3: "Bidirectional streams MUST NOT begin with any
            // other message type unless negotiated. If they do, the peer MUST
            // close the Session with a PROTOCOL_VIOLATION." The session has
            // already been closed on the wire by the time this is returned, so
            // the code is carried here for a caller to read which rule was
            // answered, not for it to answer one again.
            ConnectionError::NonRequestOnRequestStream(_) => {
                Some(DraftSpecificCause::PeerViolation {
                    rule: AboveCodecRule::BidiStreamOpener,
                    close: Some(SessionErrorCode::ProtocolViolation.as_u64()),
                })
            }
            // Three ways of handing this endpoint a message it will not write,
            // and one answer: nothing reached the wire, so nothing here is
            // evidence about a peer. Two are messages put on the control stream
            // that belong on a request stream of their own; the third is a
            // `respond_*` helper pointed at a request this endpoint opened,
            // which only the endpoint a request was opened *toward* may answer.
            ConnectionError::RequestOnControlStream(_)
            | ConnectionError::RequestStreamMessageOnControlStream(_)
            | ConnectionError::RespondedToOwnRequest(_) => Some(DraftSpecificCause::LocalRefusal),
        }
    }

    /// The code to close the session with when a control message could not be
    /// decoded because the peer broke a rule draft-17 answers with a close.
    ///
    /// Every variant listed here comes from a sentence in the draft that names
    /// the consequence: the reason phrase and GOAWAY URI maxima (Sections
    /// 1.4.4 and 9.5), the KVP value maximum and the delta-encoded
    /// type overflow (Section 1.4.3), the duplicate-parameter rule (Section
    /// 9.3), and the Track Namespace field, count and length rules
    /// (Section 2.4.1). Each of those reads "MUST close the session with a
    /// PROTOCOL_VIOLATION". The Required Request ID Delta bound of Section 9.2 is
    /// the one that names a different code, INVALID_REQUIRED_REQUEST_ID.
    ///
    /// One more rule reaches this table without naming a code: "An endpoint
    /// that receives an unknown message type MUST close the session", stated in
    /// those words by all the drafts. Protocol Violation is what carries
    /// it, as it does on every draft below this one.
    ///
    /// [`CodecError::ObjectIdOverflow`] is absent on purpose, and this is the
    /// one draft where that is so. Section 10.4.2 gives the same Object ID
    /// delta arithmetic drafts 18 and 19 give, and the codec reports the wrap
    /// on all three, but only those two go on to say "the endpoint MUST close
    /// the session with a PROTOCOL_VIOLATION". Draft-17 states no consequence,
    /// so the wrap stops here at a refused frame rather than a closed session.
    ///
    /// `None` for everything else, including [`CodecError::InvalidField`]. That
    /// variant is shared by a dozen unrelated malformations, only some of which
    /// the draft answers with a close, so treating it as fatal would close
    /// sessions the draft does not ask to be closed. Splitting it is the way to
    /// bring the rest of those rules under this function; widening the match is
    /// not.
    pub fn codec_session_error_code(
        err: &CodecError,
    ) -> Option<moqtap_codec::draft17::error_codes::SessionErrorCode> {
        use moqtap_codec::draft17::error_codes::SessionErrorCode;
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
            CodecError::InvalidRequiredRequestIdDelta(..) => {
                Some(SessionErrorCode::InvalidRequiredRequestId)
            }
            // An unknown data-plane type. Drafts 17 and later split the sentence
            // in two: Section 3.4 for streams, Section 10 for datagrams, both
            // ending "MUST close the session" and neither naming a code, so both
            // take the one this draft's other unnamed rules take.
            // A Message Parameter whose value is outside the range its type
            // allows: FORWARD in Section 9.3.10 and GROUP_ORDER in Section 9.3.6.
            // Each states that a receiver "MUST close the session with
            // PROTOCOL_VIOLATION".
            CodecError::ParameterValueOutOfRange { .. } => {
                Some(SessionErrorCode::ProtocolViolation)
            }
            // A Track Extension or Track Property whose value is outside the
            // range its type allows: DEFAULT_PUBLISHER_GROUP_ORDER in Section 11.4
            // and DYNAMIC_GROUPS in Section 11.5.
            // Each states that a receiver "MUST close the session with
            // PROTOCOL_VIOLATION".
            //
            // A separate arm from the parameter rule above because the two
            // registries are separate: 0x22 is GROUP_ORDER as a parameter and
            // DEFAULT_PUBLISHER_GROUP_ORDER as a Track Property, and a log that
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
            CodecError::InvalidStreamTypeValue { .. }
            | CodecError::InvalidDatagramTypeValue { .. } => {
                Some(SessionErrorCode::ProtocolViolation)
            }
            // A key-value pair whose value is not the serialization its own
            // Type defines, Section 1.4.3: "If a receiver understands a Type,
            // and the following Value or Length/Value does not match the
            // serialization defined by that Type, the receiver MUST close the
            // session with error code KEY_VALUE_FORMATTING_ERROR."
            //
            // Section 9.3.2 states the same answer for the one structure this
            // draft spells out: "If the Token structure cannot be decoded, the
            // receiver MUST close the Session with KEY_VALUE_FORMATTING_ERROR."
            //
            // The one rule in this table that names a code other than Protocol
            // Violation.
            CodecError::KeyValueFormatting { .. }
            // A filter parameter whose value is not a filter reaches the same
            // sentence. Drafts 15 and 16 answered it with PROTOCOL_VIOLATION
            // instead, on the strength of a sentence of the parameter's own that
            // this draft dropped; what remains is the general rule above, so the
            // code changed with it.
            | CodecError::SubscriptionFilterMalformed { .. } => {
                Some(SessionErrorCode::KeyValueFormattingError)
            }
            // A Message Parameter whose type this draft does not define, Section
            // 9.3: "All Message Parameters MUST be defined in the negotiated
            // version of MOQT or negotiated via Setup Options. An endpoint that
            // receives an unknown Message Parameter MUST close the session with
            // PROTOCOL_VIOLATION."
            //
            // One namespace only. This draft also says a receiver ignores an
            // unrecognised Setup Option, so an unknown type in a SETUP is carried and
            // the codec never raises this for one.
            CodecError::UnknownMessageParameter(_) => Some(SessionErrorCode::ProtocolViolation),
            // A Message Parameter in a message type its own definition does not
            // name, Section 9.3.1: "Each Message Parameter definition indicates
            // the message types in which it can appear. If it appears in some
            // other type of message, the receiving endpoint MUST close the
            // connection with a PROTOCOL_VIOLATION."
            //
            // Draft-16 and every draft before it end that same sentence "it MUST
            // be ignored", so this is a rule whose answer reverses rather than
            // one that arrives.
            CodecError::ParameterOutOfScope { .. } => Some(SessionErrorCode::ProtocolViolation),
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
            // This draft introduced the End Group Delta and states nothing
            // about the sum leaving the number space. Drafts 18 and 19 add, at
            // draft-18 Section 5.1.2, "If the resulting Group ID would be
            // greater than 2^64 - 1, the endpoint MUST close the session with a
            // PROTOCOL_VIOLATION" and answer it; refusing here would close a
            // session over a sentence this draft does not have.
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

    /// Close the session on the wire when a decode failure is one draft-17
    /// answers with a close, and hand the error back unchanged.
    ///
    /// The codec's counterpart to
    /// [`close_if_session_fatal`](Self::close_if_session_fatal). Without it
    /// every bound the decoder enforces would stop at *this endpoint refused the
    /// frame* while the peer, which is the one that broke the rule, saw a
    /// session that was still open and went on sending. "MUST close the session
    /// with a PROTOCOL_VIOLATION" is a statement about the wire.
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

    /// Name every request whose stream the caller must reset, for a track a
    /// data path has just found malformed.
    ///
    /// Section 2.4.2 answers its whole list of conditions at once: "it MUST
    /// cancel any corresponding subscription or fetches for that Track from
    /// that publisher". On this draft cancelling a request is a transport
    /// operation rather than a message — Section 3.3.1: "Implementations SHOULD cancel requests
    /// by abruptly terminating any directions of a stream that are still open
    /// using RESET_STREAM / RESET_STREAM_AT or STOP_SENDING."
    ///
    /// A SHOULD on this draft and on draft-18; draft-19 drops the keyword and
    /// states it outright.
    ///
    /// # Why this returns ids instead of doing it
    ///
    /// Because the streams are the caller's. Every request on this draft lives
    /// at the front of a bidirectional stream of its own, and
    /// [`Connection::recv_on_request_stream`] hands that stream back as a
    /// [`RequestStream`]. There is no handle here to reset. So the connection
    /// does the half it can — note the track, and work out which requests
    /// receive it — and the caller passes each id to
    /// [`Connection::cancel_request_stream`], which resets the stream *and*
    /// moves the endpoint's record.
    ///
    /// **This is the one place in this crate where the two halves of an answer
    /// are split across the API boundary**, and it is the draft that splits
    /// them: drafts 12 through 16 answer with a control message, which the
    /// connection owns, so `withdraw_for_data_stream` there does the whole
    /// thing.
    ///
    /// # Both data paths come here
    ///
    /// Unlike the drafts that answer with a message, where a datagram is read
    /// through the connection and answers itself. Here neither path can, for
    /// the same reason, so there is one entry point rather than two. Pass it
    /// whatever error a read returned; anything that is not this condition
    /// gives back an empty list.
    ///
    /// Empty is not "the track was fine" — it is also what an alias no live
    /// binding names gives, and what a track this endpoint only publishes
    /// gives.
    pub fn requests_to_cancel(&self, err: &ConnectionError) -> Vec<VarInt> {
        let ConnectionError::Endpoint(EndpointError::ObjectPastFinalObject { alias, .. }) = err
        else {
            return Vec::new();
        };
        self.endpoint
            .requests_for_malformed_track(*alias, MalformedTrackCondition::ObjectPastFinalObject)
    }

    /// Close the session when a failure raised while reading a *data* stream is
    /// one draft-17 answers with a close. Reports whether it closed.
    ///
    /// [`recv_control`](Self::recv_control) does this for itself, because it
    /// owns both the stream and the connection. A data stream does not:
    /// [`accept_subgroup_stream`](Self::accept_subgroup_stream) hands the caller
    /// a [`FramedRecvStream`], which holds no connection and so cannot close
    /// one, and the reads that raise these failures happen there. The caller is
    /// the only party holding both halves, which is what this is for.
    ///
    /// Splitting it this way rather than closing inside the reader keeps a
    /// caller that is deliberately permissive — a tool reproducing a capture,
    /// say — able to read a violating stream and report it without tearing the
    /// session down. The rule is stated at endpoints, and this is where an
    /// endpoint decides it is one.
    ///
    /// On this draft only one rule reaches here: properties beside a status
    /// that is not Normal, Section 10.2.1.2. Drafts 18 and 19 also answer the
    /// Object ID delta wrap of their Section 11.4.2, which draft-17 describes
    /// without stating a consequence — see
    /// `codec_session_error_code`.
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
            ConnectionError::PropertiesOnNonNormalStatus { .. } => {
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

    /// Close the connection.
    pub fn close(&self, code: u32, reason: &[u8]) {
        self.emit(ClientEvent::Closed { code, reason: reason.to_vec() });
        self.transport.close(code, reason);
    }
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

    /// Draft-17 uses MoQT's variable-length integer, whose length is the
    /// number of leading 1 bits in the first byte, not RFC 9000's two-bit
    /// prefix. Control framing measures the type field with it before any
    /// bytes past the first have arrived.
    #[test]
    fn varint_len_follows_the_moqt_encoding() {
        let draft = DraftVersion::Draft17;
        assert_eq!(draft.varint_len(0x00), 1);
        assert_eq!(draft.varint_len(0x7F), 1);
        assert_eq!(draft.varint_len(0x80), 2);
        assert_eq!(draft.varint_len(0xBF), 2);
        assert_eq!(draft.varint_len(0xC0), 3);
        assert_eq!(draft.varint_len(0xFF), 9);
        // SETUP's type id, 0x2F00, is two bytes here and four under RFC 9000.
        assert_eq!(draft.varint_len(0xAF), 2);
    }

    #[test]
    fn client_config_alpn_quic_draft17() {
        let config = ClientConfig {
            draft: DraftVersion::Draft17,
            transport: TransportType::Quic,
            skip_cert_verification: false,
            ca_certs: Vec::new(),
            setup_parameters: Vec::new(),
        };
        assert_eq!(config.alpn(), vec![b"moqt-17".to_vec()]);
    }

    #[test]
    fn client_config_alpn_webtransport() {
        let config = ClientConfig {
            draft: DraftVersion::Draft17,
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
            draft: DraftVersion::Draft17,
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
            17,
            config
                .alpn()
                .iter()
                .map(|a| String::from_utf8_lossy(a).into_owned())
                .collect::<Vec<_>>(),
        );
        assert_eq!(MOQT_ALPN, b"moqt-17");
    }

    /// Draft-17 Section 3.3 names six message types a bidirectional stream
    /// may begin with, and no others. The set is checked against the raw
    /// numbers this draft's registry assigns rather than against the names,
    /// so a variant that is renumbered — SUBSCRIBE_NAMESPACE moved from 0x11
    /// to 0x50 between draft-17 and draft-18 — is caught even though the
    /// spelling did not change.
    ///
    /// Every type this draft assigns is classified: the loop walks the whole
    /// assigned range and asks the classifier about each one it finds.
    ///
    /// Moving `MessageType::GoAway` into the true arm fails with:
    ///
    /// ```text
    /// assertion `left == right` failed: the types that open a request stream are [3, 6, 13, 16, 17, 22, 29]; draft-17 Section 3.3 names [3, 6, 13, 17, 22, 29]
    ///   left: [3, 6, 13, 16, 17, 22, 29]
    ///  right: [3, 6, 13, 17, 22, 29]
    /// ```
    #[test]
    fn only_six_message_types_open_a_request_stream() {
        // TRACK_STATUS, SUBSCRIBE, PUBLISH, FETCH, PUBLISH_NAMESPACE and
        // SUBSCRIBE_NAMESPACE, written as the numbers draft-17 assigns them.
        let mut expected = vec![0x0D, 0x03, 0x1D, 0x16, 0x06, 0x11];
        expected.sort_unstable();

        let mut opens = Vec::new();
        for id in 0..=CONTROL_STREAM_TYPE {
            if let Some(ty) = MessageType::from_id(id) {
                if starts_a_request_stream(ty) {
                    opens.push(id);
                }
            }
        }
        opens.sort_unstable();

        assert_eq!(
            opens, expected,
            "the types that open a request stream are {opens:?}; \
             draft-17 Section 3.3 names {expected:?}"
        );
    }

    /// The kind a request helper labels its stream with must name the message
    /// that helper actually writes, and the check is made against the type
    /// varint the encoded message leads with — the byte a peer reads to
    /// decide whether the bidirectional stream is legal.
    ///
    /// This is the mislabelling a port to another draft is most likely to
    /// introduce, because the numbers move between drafts while the names do
    /// not.
    ///
    /// Pointing `RequestKind::Fetch` at `MessageType::FetchOk` fails with:
    ///
    /// ```text
    /// assertion `left == right` failed: Fetch is labelled 24 but its message leads with 22
    ///   left: 24
    ///  right: 22
    /// ```
    #[test]
    fn each_request_kind_labels_the_message_its_helper_writes() {
        use crate::draft17::endpoint::Endpoint;
        use moqtap_codec::draft17::message::Setup;

        let v = |n: u64| VarInt::from_u64(n).unwrap();
        let ns = TrackNamespace(vec![b"ns".to_vec()]);

        let mut ep = Endpoint::new(Role::Client);
        ep.connect().unwrap();
        let _ = ep.send_setup(vec![]).unwrap();
        ep.receive_setup(&Setup { options: vec![] }).unwrap();

        let (sub_id, subscribe) = ep.subscribe(ns.clone(), b"t".to_vec(), vec![]).unwrap();
        let built = vec![
            (RequestKind::Subscribe, subscribe),
            (
                RequestKind::Fetch,
                ep.fetch(ns.clone(), b"t".to_vec(), v(0), v(0), v(1), v(1), vec![]).unwrap().1,
            ),
            (RequestKind::Fetch, ep.joining_fetch(sub_id, v(2), Vec::new()).unwrap().1),
            (
                RequestKind::SubscribeNamespace,
                ep.subscribe_namespace(ns.clone(), v(0), vec![]).unwrap().1,
            ),
            (RequestKind::PublishNamespace, ep.publish_namespace(ns.clone(), vec![]).unwrap().1),
            (
                RequestKind::TrackStatus,
                ep.track_status(ns.clone(), b"t".to_vec(), vec![]).unwrap().1,
            ),
            (
                RequestKind::Publish,
                ep.publish(ns.clone(), b"t".to_vec(), v(7), vec![], vec![]).unwrap().1,
            ),
        ];

        for (kind, msg) in built {
            let mut wire = Vec::new();
            msg.encode(&mut wire).unwrap();
            let mut cursor = &wire[..];
            let on_the_wire =
                DraftVersion::Draft17.decode_varint(&mut cursor).unwrap().into_inner();
            assert_eq!(
                kind.message_type().id(),
                on_the_wire,
                "{kind:?} is labelled {} but its message leads with {on_the_wire}",
                kind.message_type().id(),
            );
            assert!(
                starts_a_request_stream(kind.message_type()),
                "{kind:?} labels a message type that may not begin a bidirectional stream",
            );
        }
    }

    /// The classifier the accept path runs and the one
    /// [`Connection::send_control`] runs must answer alike for every message
    /// type this draft assigns, or a message could be refused on the control
    /// stream and refused again as the opening of a request stream — leaving
    /// no legal place for it.
    ///
    /// Dropping `MessageType::Publish` to `None` in `from_message_type` fails
    /// with:
    ///
    /// ```text
    /// assertion `left == right` failed: type 29 opens a request stream but from_message_type calls it None
    ///   left: false
    ///  right: true
    /// ```
    #[test]
    fn the_two_request_stream_classifiers_agree() {
        let mut classified = 0;
        for id in 0..=CONTROL_STREAM_TYPE {
            let Some(ty) = MessageType::from_id(id) else { continue };
            classified += 1;
            let kind = RequestKind::from_message_type(ty);
            assert_eq!(
                kind.is_some(),
                starts_a_request_stream(ty),
                "type {id} {} a request stream but from_message_type calls it {kind:?}",
                if starts_a_request_stream(ty) { "opens" } else { "does not open" },
            );
            if let Some(kind) = kind {
                assert_eq!(
                    kind.message_type(),
                    ty,
                    "from_message_type sent type {id} to {kind:?}, which names a different message",
                );
            }
        }
        assert!(classified > 6, "the loop found only {classified} assigned message types");
    }

    /// A stream this endpoint opened is cancelled when its handle is dropped;
    /// one the peer opened is reset as unserved. Both codes are on the wire,
    /// so they may not be the same number.
    #[test]
    fn the_two_abandonment_codes_are_distinct() {
        assert_eq!(REQUEST_CANCELLED, 0x1);
        assert_eq!(REQUEST_UNANSWERED, 0x0);
        assert_ne!(
            REQUEST_CANCELLED, REQUEST_UNANSWERED,
            "a peer cannot tell a rejected request from a dropped one if both reset with the same code",
        );
    }

    #[test]
    fn transport_type_debug() {
        let quic = TransportType::Quic;
        assert!(format!("{quic:?}").contains("Quic"));

        let wt = TransportType::WebTransport { url: "https://example.com".to_string() };
        assert!(format!("{wt:?}").contains("WebTransport"));
    }
}

#[cfg(test)]
mod accept_on_the_wire {
    //! The accept path against a real QUIC peer.
    //!
    //! The last of the request-stream drafts to get one. What a peer can see —
    //! which stream a response goes out on, and whether one is written at all —
    //! is not observable from an endpoint held on its own.

    use super::*;
    use std::sync::Arc;

    use std::net::SocketAddr;
    use std::time::Duration;

    use moqtap_codec::draft17::message::{PublishOk, Setup};

    /// Long enough that a loaded machine cannot fail a test that would
    /// otherwise pass, short enough that a hang is reported rather than run to
    /// the harness timeout.
    const PATIENCE: Duration = Duration::from_secs(10);

    fn v(n: u64) -> VarInt {
        VarInt::from_u64(n).unwrap()
    }

    fn ns() -> TrackNamespace {
        TrackNamespace(vec![b"live".to_vec()])
    }

    fn encode(msg: ControlMessage) -> Vec<u8> {
        let mut buf = Vec::new();
        AnyControlMessage::Draft17(msg).encode(&mut buf).expect("encode");
        buf
    }

    fn request_update(id: u64) -> ControlMessage {
        ControlMessage::RequestUpdate(moqtap_codec::draft17::message::RequestUpdate {
            request_id: v(id),
            required_request_id_delta: v(0),
            parameters: vec![],
        })
    }

    fn request_error() -> RequestError {
        RequestError { error_code: v(0x1), retry_interval: v(0), reason_phrase: b"no".to_vec() }
    }

    fn init_crypto() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    /// A quinn server on a loopback port, offering this draft's ALPN.
    fn server_endpoint() -> (quinn::Endpoint, SocketAddr) {
        use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("keypair");
        let params = CertificateParams::new(vec!["localhost".into()]).expect("params");
        let cert = params.self_signed(&key_pair).expect("self-sign");
        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

        let mut server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("server cert");
        server_crypto.alpn_protocols = vec![DraftVersion::Draft17.quic_alpn().to_vec()];
        let server_crypto =
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).expect("quic crypto");
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
        let endpoint = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap())
            .expect("bind server");
        let addr = endpoint.local_addr().expect("local_addr");
        (endpoint, addr)
    }

    async fn connect_client(addr: SocketAddr) -> Result<Connection, ConnectionError> {
        Connection::connect(
            &addr.to_string(),
            ClientConfig {
                draft: DraftVersion::Draft17,
                transport: TransportType::Quic,
                skip_cert_verification: true,
                ca_certs: Vec::new(),
                setup_parameters: Vec::new(),
            },
        )
        .await
    }

    /// The peer's half of the setup exchange: read the client's SETUP off its
    /// unidirectional control stream, answer with one of our own.
    ///
    /// Both control streams are handed back so they stay open for the
    /// connection's life. Dropping a quinn receive stream sends STOP_SENDING
    /// and dropping a send stream resets it, either of which would look to the
    /// client like the control plane failing.
    async fn peer_handshake(
        endpoint: &quinn::Endpoint,
    ) -> (quinn::Connection, quinn::SendStream, quinn::RecvStream) {
        let conn = endpoint.accept().await.expect("accept").await.expect("tls handshake");
        let mut client_control = conn.accept_uni().await.expect("accept_uni");
        let mut seen = Vec::new();
        let mut chunk = [0u8; 1024];
        while seen.len() < 3 {
            match client_control.read(&mut chunk).await.expect("read SETUP") {
                Some(n) => seen.extend_from_slice(&chunk[..n]),
                None => break,
            }
        }
        assert!(!seen.is_empty(), "the client sent no SETUP");
        let mut ours = conn.open_uni().await.expect("open_uni");
        ours.write_all(&encode(ControlMessage::Setup(Setup { options: Vec::new() })))
            .await
            .expect("write SETUP");
        (conn, ours, client_control)
    }

    /// A connected client and the peer holding the other end.
    struct Loopback {
        conn: Connection,
        peer: quinn::Connection,
        _endpoint: quinn::Endpoint,
        _control_send: quinn::SendStream,
        _control_recv: quinn::RecvStream,
    }

    async fn loopback() -> Loopback {
        init_crypto();
        let (endpoint, addr) = server_endpoint();
        let (client, peer) = tokio::join!(connect_client(addr), peer_handshake(&endpoint));
        let (peer, control_send, control_recv) = peer;
        Loopback {
            conn: client.expect("client connect"),
            peer,
            _endpoint: endpoint,
            _control_send: control_send,
            _control_recv: control_recv,
        }
    }

    /// One handshake, several ALPNs offered, and the server's pick reported.
    ///
    /// This is the capability `connect` cannot express: it derives its ALPN
    /// from the draft it was told to use, so it can only ever confirm a guess.
    /// The server here speaks draft-17 alone, and the dial that finds it offers
    /// 19 and 18 first — so a caller learns the draft from one handshake
    /// instead of dialling once per candidate and discarding the failures.
    #[tokio::test]
    async fn a_dial_offering_several_alpns_reports_the_one_chosen() {
        init_crypto();
        let (server, addr) = server_endpoint();
        let accepting = tokio::spawn(async move {
            let incoming = server.accept().await.expect("accept");
            let conn = incoming.await.expect("tls handshake");
            // Hold the server end open until the assertions have run.
            tokio::time::sleep(PATIENCE).await;
            drop(conn);
        });

        let (transport, negotiated) = crate::transport::dial_quic(
            &addr.to_string(),
            &crate::transport::QuicDialOptions::new(vec![
                DraftVersion::Draft19.quic_alpn().to_vec(),
                DraftVersion::Draft18.quic_alpn().to_vec(),
                DraftVersion::Draft17.quic_alpn().to_vec(),
            ])
            .insecure(true),
        )
        .await
        .expect("dial");

        let negotiated = negotiated.expect("the server selected no ALPN");
        assert_eq!(
            negotiated.as_slice(),
            DraftVersion::Draft17.quic_alpn(),
            "the server's pick was not reported back"
        );
        assert_eq!(
            DraftVersion::from_alpn(&negotiated),
            Some(DraftVersion::Draft17),
            "the reported ALPN does not name the draft that answered"
        );

        drop(transport);
        accepting.abort();
    }

    /// `adopt` completes a session on a transport somebody else dialled.
    ///
    /// The pair above and this one are the whole point of the split: dial once
    /// offering everything, read which draft answered, then bring the *same*
    /// connection to that draft's module. Nothing is closed and redialled.
    #[tokio::test]
    async fn adopt_runs_the_setup_handshake_on_a_transport_it_did_not_dial() {
        init_crypto();
        let (endpoint, addr) = server_endpoint();

        let dial = async {
            let (transport, negotiated) = crate::transport::dial_quic(
                &addr.to_string(),
                &crate::transport::QuicDialOptions::new(vec![
                    DraftVersion::Draft18.quic_alpn().to_vec(),
                    DraftVersion::Draft17.quic_alpn().to_vec(),
                ])
                .insecure(true),
            )
            .await
            .expect("dial");

            // The draft is chosen from the answer, not assumed beforehand.
            assert_eq!(
                DraftVersion::from_alpn(&negotiated.expect("no ALPN")),
                Some(DraftVersion::Draft17)
            );

            Connection::adopt(
                transport,
                ClientConfig {
                    draft: DraftVersion::Draft17,
                    transport: TransportType::Quic,
                    skip_cert_verification: true,
                    ca_certs: Vec::new(),
                    setup_parameters: Vec::new(),
                },
            )
            .await
        };

        let (client, peer) = tokio::join!(dial, peer_handshake(&endpoint));
        let conn = client.expect("adopt");
        assert_eq!(conn.draft(), DraftVersion::Draft17);

        drop(conn);
        drop(peer);
    }

    fn framed(recv: quinn::RecvStream) -> FramedRecvStream {
        FramedRecvStream::new(RecvStream::Quic(recv), DraftVersion::Draft17)
    }

    /// Read one control message the client wrote, failing rather than hanging.
    async fn next_control(recv: &mut FramedRecvStream) -> ControlMessage {
        let (any, _) = tokio::time::timeout(PATIENCE, recv.read_control(false))
            .await
            .expect("the client wrote nothing")
            .expect("read control");
        match any {
            AnyControlMessage::Draft17(msg) => msg,
            #[allow(unreachable_patterns)]
            other => panic!("expected a draft-17 message, got {other:?}"),
        }
    }

    /// An update on a PUBLISH this endpoint sent is answered here.
    ///
    /// Section 9.10 names the one case where a requester answers rather than
    /// asks: "A subscriber can also send REQUEST_UPDATE to modify parameters
    /// of a subscription established with PUBLISH." The receiver of that
    /// update "MUST respond with exactly one REQUEST_OK or REQUEST_ERROR
    /// message indicating if the update was successful", and on a PUBLISH this
    /// endpoint sent, the receiver is this endpoint.
    ///
    /// # What it catches
    ///
    /// Restoring the origin guard on this draft's `respond`, so that no
    /// response is written on a stream this endpoint opened:
    ///
    /// ```text
    /// the subscriber's update is this endpoint's to answer:
    /// RespondedToOwnRequest(0)
    /// ```
    ///
    /// It reddens this gate and the one below it, on draft-17's own line, and
    /// nothing else in the client or the proxy.
    #[tokio::test]
    async fn an_update_on_a_publish_we_sent_is_answered_here() {
        let mut lb = loopback().await;

        let mut outbound =
            lb.conn.publish(ns(), b"video".to_vec(), v(7), vec![], vec![]).await.expect("publish");
        let (mut their_send, their_recv) = tokio::time::timeout(PATIENCE, lb.peer.accept_bi())
            .await
            .expect("the client opened no request stream")
            .expect("accept_bi");
        let mut their_recv = framed(their_recv);
        assert!(matches!(next_control(&mut their_recv).await, ControlMessage::Publish(_)));

        // The subscriber accepts the publication, then updates it.
        their_send
            .write_all(&encode(ControlMessage::PublishOk(PublishOk { parameters: vec![] })))
            .await
            .expect("write PUBLISH_OK");
        let msg = tokio::time::timeout(PATIENCE, lb.conn.recv_on_request_stream(&mut outbound))
            .await
            .expect("no PUBLISH_OK arrived")
            .expect("read PUBLISH_OK");
        assert!(matches!(msg, ControlMessage::PublishOk(_)), "{msg:?}");

        their_send.write_all(&encode(request_update(0))).await.expect("write REQUEST_UPDATE");
        let msg = tokio::time::timeout(PATIENCE, lb.conn.recv_on_request_stream(&mut outbound))
            .await
            .expect("no REQUEST_UPDATE arrived")
            .expect("read REQUEST_UPDATE");
        assert!(matches!(msg, ControlMessage::RequestUpdate(_)), "{msg:?}");

        lb.conn
            .respond_ok(&mut outbound, RequestOk { parameters: vec![] })
            .await
            .expect("the subscriber's update is this endpoint's to answer");
        assert!(matches!(next_control(&mut their_recv).await, ControlMessage::RequestOk(_)));

        // The publication is untouched by the update, and the ending it still
        // owes goes out without complaint. Draft-19 keeps that obligation on
        // the request stream and can be asked; this draft does not, so the
        // ending being accepted is the observation.
        lb.conn
            .publish_done(&mut outbound, v(0), v(0), Vec::new())
            .await
            .expect("an accepted update leaves the ending free");
    }

    /// Refusing that update owes the same ending as refusing any other.
    ///
    /// Section 9.10.1: "When a subscription update is unsuccessful, the
    /// publisher MUST also terminate the subscription with PUBLISH_DONE with
    /// error code UPDATE_FAILED." Drafts 18 and 19 reword it around
    /// REQUEST_UPDATE; the obligation is the same one. The publisher of a
    /// subscription established
    /// with PUBLISH is the endpoint that sent it, and the ending goes on the
    /// stream that endpoint opened rather than on one the peer opened.
    ///
    /// # What it catches
    ///
    /// The same cut as the gate above, restoring the origin guard:
    ///
    /// ```text
    /// refuse the subscriber's update: RespondedToOwnRequest(0)
    /// ```
    ///
    /// And narrowing the refusal's debt back to a peer's SUBSCRIBE, so the
    /// endpoint that sent the PUBLISH owes nothing for refusing an update on
    /// it — after which the ending goes out under any status and the stream
    /// has already been finished:
    ///
    /// ```text
    /// transport error: write error: closed stream
    /// ```
    ///
    /// That second cut reddens this gate alone here, where on drafts 18 and 19
    /// it also takes the namespace close with it. Those are not rules of this
    /// draft, so there is nothing else on the same predicate to break.
    #[tokio::test]
    async fn a_refused_update_on_a_publish_we_sent_owes_its_ending() {
        let mut lb = loopback().await;

        let mut outbound =
            lb.conn.publish(ns(), b"video".to_vec(), v(7), vec![], vec![]).await.expect("publish");
        let (mut their_send, their_recv) = tokio::time::timeout(PATIENCE, lb.peer.accept_bi())
            .await
            .expect("the client opened no request stream")
            .expect("accept_bi");
        let mut their_recv = framed(their_recv);
        assert!(matches!(next_control(&mut their_recv).await, ControlMessage::Publish(_)));

        their_send
            .write_all(&encode(ControlMessage::PublishOk(PublishOk { parameters: vec![] })))
            .await
            .expect("write PUBLISH_OK");
        tokio::time::timeout(PATIENCE, lb.conn.recv_on_request_stream(&mut outbound))
            .await
            .expect("no PUBLISH_OK arrived")
            .expect("read PUBLISH_OK");

        their_send.write_all(&encode(request_update(0))).await.expect("write REQUEST_UPDATE");
        tokio::time::timeout(PATIENCE, lb.conn.recv_on_request_stream(&mut outbound))
            .await
            .expect("no REQUEST_UPDATE arrived")
            .expect("read REQUEST_UPDATE");

        lb.conn
            .respond_error(&mut outbound, request_error())
            .await
            .expect("refuse the subscriber's update");
        assert!(matches!(next_control(&mut their_recv).await, ControlMessage::RequestError(_)));

        // The ending is owed under one status, and asking for another leaves
        // the publication exactly where it was rather than half ended.
        let err = lb
            .conn
            .publish_done(&mut outbound, v(0), v(0), Vec::new())
            .await
            .expect_err("a refused update fixes the status of the ending");
        assert!(
            matches!(
                err,
                ConnectionError::Endpoint(EndpointError::WrongUpdateFailureStatus {
                    request: 0,
                    required: 0x8,
                })
            ),
            "{err}",
        );
        lb.conn
            .publish_done(&mut outbound, v(0x8), v(0), Vec::new())
            .await
            .expect("the termination the refusal owes");
        assert!(matches!(next_control(&mut their_recv).await, ControlMessage::PublishDone(_)));
    }
}

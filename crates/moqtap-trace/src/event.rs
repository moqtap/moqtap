use ciborium::Value;

use crate::error::MoqTraceError;
use crate::header::{as_i64, as_u64, normalised, store_entries, unrecognised, DetailLevel};

/// Direction of a message or stream relative to the recording endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Sent (outgoing). Wire value: `0`.
    Send,
    /// Received (incoming). Wire value: `1`.
    Receive,
}

impl Direction {
    fn from_cbor(v: &Value) -> Result<Self, MoqTraceError> {
        match as_u64(v) {
            Some(0) => Ok(Direction::Send),
            Some(1) => Ok(Direction::Receive),
            _ => Err(MoqTraceError::InvalidEvent("invalid direction value".into())),
        }
    }
}

/// Data stream type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamType {
    /// Subgroup stream. Wire value: `0`.
    Subgroup,
    /// Datagram. Wire value: `1`.
    Datagram,
    /// Fetch stream. Wire value: `2`.
    Fetch,
}

impl StreamType {
    fn from_cbor(v: &Value) -> Result<Self, MoqTraceError> {
        match as_u64(v) {
            Some(0) => Ok(StreamType::Subgroup),
            Some(1) => Ok(StreamType::Datagram),
            Some(2) => Ok(StreamType::Fetch),
            _ => Err(MoqTraceError::InvalidEvent("invalid stream type value".into())),
        }
    }
}

/// What sort of failure an [`Error`](EventData::Error) event records.
///
/// An open vocabulary. SPEC.md's Event 6 section names three kinds and says
/// others may be added without a format version bump, so a spelling this crate
/// does not know is kept verbatim in [`Other`](ErrorKind::Other) rather than
/// refused. That is the treatment [`Perspective`](crate::header::Perspective)
/// gets, and it is the rule SPEC.md points at for this key.
///
/// An enum and not a bare `String` because these three are the recorder's own
/// classification of what it just saw, chosen at the point the event is built:
/// a misspelling is a value no reader can group by, and the compiler is the
/// only thing that catches it before the trace is written. The wire spellings
/// live in [`as_str`](ErrorKind::as_str) alone, so a reader and a writer cannot
/// disagree about them.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The peer violated the protocol.
    Protocol,
    /// The QUIC or WebTransport layer failed.
    Transport,
    /// Bytes that would not parse as any message this recorder knows.
    Decode,
    /// A kind this version of the crate does not know, kept verbatim.
    Other(String),
}

impl ErrorKind {
    /// The wire spelling of this kind.
    pub fn as_str(&self) -> &str {
        match self {
            ErrorKind::Protocol => "protocol",
            ErrorKind::Transport => "transport",
            ErrorKind::Decode => "decode",
            ErrorKind::Other(s) => s,
        }
    }

    fn parse(s: &str) -> Self {
        match s {
            "protocol" => ErrorKind::Protocol,
            "transport" => ErrorKind::Transport,
            "decode" => ErrorKind::Decode,
            other => ErrorKind::Other(other.to_string()),
        }
    }
}

/// Which end of a relay a peer sits on.
///
/// This is the direction the *connection* was made in, not the direction
/// subscriptions flow. A downstream peer may publish and an upstream peer may
/// subscribe; for subscription causality see
/// [`EventData::SubscriptionDerivation`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Side {
    /// The peer connected to this relay.
    Downstream,
    /// This relay connected to the peer — an origin or an upstream relay.
    Upstream,
    /// A side this version of the crate does not know, kept verbatim.
    Other(String),
}

impl Side {
    /// The wire spelling of this side.
    pub fn as_str(&self) -> &str {
        match self {
            Side::Downstream => "downstream",
            Side::Upstream => "upstream",
            Side::Other(s) => s,
        }
    }

    fn parse(s: &str) -> Self {
        match s {
            "downstream" => Side::Downstream,
            "upstream" => Side::Upstream,
            other => Side::Other(other.to_string()),
        }
    }
}

/// Role a peer is acting in at connection time.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PeerRole {
    /// Peer is acting as a publisher.
    Publisher,
    /// Peer is acting as a subscriber.
    Subscriber,
    /// Peer is acting as both.
    Both,
    /// A role this version of the crate does not know, kept verbatim.
    Other(String),
}

impl PeerRole {
    /// The wire spelling of this role.
    pub fn as_str(&self) -> &str {
        match self {
            PeerRole::Publisher => "publisher",
            PeerRole::Subscriber => "subscriber",
            PeerRole::Both => "both",
            PeerRole::Other(s) => s,
        }
    }

    fn parse(s: &str) -> Self {
        match s {
            "publisher" => PeerRole::Publisher,
            "subscriber" => PeerRole::Subscriber,
            "both" => PeerRole::Both,
            other => PeerRole::Other(other.to_string()),
        }
    }
}

/// How an upstream subscription came to serve a downstream one.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DerivationKind {
    /// A new upstream subscription was created to satisfy downstream subs.
    Created,
    /// An existing upstream subscription now also serves an additional
    /// downstream sub — subscription fan-in.
    Shared,
    /// A kind this version of the crate does not know, kept verbatim.
    Other(String),
}

impl DerivationKind {
    /// The wire spelling of this kind.
    pub fn as_str(&self) -> &str {
        match self {
            DerivationKind::Created => "created",
            DerivationKind::Shared => "shared",
            DerivationKind::Other(s) => s,
        }
    }

    fn parse(s: &str) -> Self {
        match s {
            "created" => DerivationKind::Created,
            "shared" => DerivationKind::Shared,
            other => DerivationKind::Other(other.to_string()),
        }
    }
}

/// A `(peer, request id)` reference naming one subscription on one peer.
///
/// Request IDs are only unique within a peer's session, so neither half
/// identifies a subscription on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionRef {
    /// Source-local peer identifier.
    pub peer: String,
    /// Request ID of the subscription on that peer.
    pub request_id: u64,
}

impl SubscriptionRef {
    /// A reference to `request_id` on `peer`.
    pub fn new(peer: impl Into<String>, request_id: u64) -> Self {
        SubscriptionRef { peer: peer.into(), request_id }
    }

    fn to_value(&self) -> Value {
        Value::Array(vec![Value::Text(self.peer.clone()), Value::Integer(self.request_id.into())])
    }

    fn from_value(v: &Value) -> Result<Self, MoqTraceError> {
        let arr = match v {
            Value::Array(a) => a,
            _ => {
                return Err(MoqTraceError::InvalidEvent(
                    "subscription ref is not a CBOR array".into(),
                ))
            }
        };
        if arr.len() != 2 {
            return Err(MoqTraceError::InvalidEvent(
                "subscription ref must be [peer, request_id]".into(),
            ));
        }
        let peer = arr[0]
            .as_text()
            .ok_or_else(|| MoqTraceError::InvalidEvent("subscription ref peer is not text".into()))?
            .to_string();
        let request_id = as_u64(&arr[1]).ok_or_else(|| {
            MoqTraceError::InvalidEvent("subscription ref request_id is not uint".into())
        })?;
        Ok(SubscriptionRef { peer, request_id })
    }
}

/// Length of a trace ID, in bytes. Fixed by the format.
pub const TRACE_ID_LEN: usize = 16;

/// The most bytes a recorder may put in an [`Error`](EventData::Error) event's
/// `"raw"`. Fixed by the format — SPEC.md, Event 6, under the heading about
/// the cap and `"rawlen"`.
///
/// The cap binds the party building an event out of bytes it has just
/// observed, and nothing else. It is deliberately **not** enforced when an
/// event is serialized, and this crate does not enforce it there: a serializer
/// cannot tell a freshly recorded event from one that arrived by being read,
/// so a cap applied at that point either shortens evidence on a rewrite or
/// refuses a file the reader was required to accept — whichever it does, it
/// does to the wrong events. A `"raw"` longer than this reads back at its full
/// length and is written back at its full length.
///
/// [`EventData::error_observed`] is where the cap belongs and where this crate
/// applies it. A recorder assembling the variant by hand applies it here.
///
/// One obligation stays with the recorder and cannot live in a constructor at
/// all: SPEC.md allows `"raw"` once per flow — per stream where the error names
/// one, per peer where it does not. Later errors on that flow are still
/// recorded and simply carry no bytes. That is state across events, so it
/// belongs to whatever is holding the flow.
pub const ERROR_RAW_CAP: usize = 4096;

/// Event type discriminants, matching the specification's `"e"` values.
const EVENT_CONTROL_MESSAGE: u64 = 0;
const EVENT_STREAM_OPENED: u64 = 1;
const EVENT_STREAM_CLOSED: u64 = 2;
const EVENT_OBJECT_HEADER: u64 = 3;
const EVENT_OBJECT_PAYLOAD: u64 = 4;
const EVENT_STATE_CHANGE: u64 = 5;
const EVENT_ERROR: u64 = 6;
const EVENT_ANNOTATION: u64 = 7;
const EVENT_PEER_CONNECTED: u64 = 8;
const EVENT_PEER_DISCONNECTED: u64 = 9;
const EVENT_SUBSCRIPTION_DERIVATION: u64 = 10;

/// A single event in a `.moqtrace` file.
#[derive(Debug, Clone, PartialEq)]
pub struct TraceEvent {
    /// Monotonically increasing sequence number (0-based). Segment-local in a
    /// segmented trace, so ordering across segments is `(segment, seq)`.
    pub seq: u64,
    /// Timestamp in microseconds since the containing segment's start time.
    pub timestamp: i64,
    /// Which peer this event pertains to.
    ///
    /// Required when the trace's perspective is
    /// [`RelayTap`](crate::header::Perspective::RelayTap), where a single
    /// trace covers many concurrent sessions; omitted otherwise, since a
    /// single-session trace has only one peer to speak of. The identifier is
    /// **source-local**: the same string in two traces from different sources
    /// does not name the same peer.
    pub peer: Option<String>,
    /// Event-specific data.
    pub data: EventData,
    /// Keys on this event that this version of the crate could not use, kept
    /// verbatim.
    ///
    /// Optional keys may be added to an existing event type without a format
    /// version bump, so "unknown keys MUST be ignored" is a rule about
    /// *reading past* them. It is not a licence to drop them: a tool that
    /// reads a trace and writes it back — a redaction pass, a filter, a
    /// re-segmentation — would otherwise emit a valid file that looks like it
    /// never carried them, and one tool's ignorance would become permanent for
    /// every reader downstream of it.
    ///
    /// A key this crate *does* know lands here too when its value is not of a
    /// type that key can hold — `"ta": "hello"` on an event 1, say. SPEC.md
    /// treats such a key as unrecognised: the value is ignored for meaning,
    /// the field that would have held it reads `None`, and the entry is
    /// written back unchanged. Knowing more about a key must not mean
    /// preserving it less.
    ///
    /// [`EventData::Unknown`] already does this for an event type the crate
    /// cannot name. This is the same guarantee one level down, for a key on a
    /// type it can.
    ///
    /// Unchanged binds the value and not its encoding, exactly as it does for
    /// [`TraceHeader::extra`](crate::header::TraceHeader::extra): on the way
    /// out an integral float in a stored value is written as a CBOR integer
    /// and a byte string under RFC 8746's tag 64 as major type 2, at any
    /// depth. SPEC.md's two encoding rules are about every byte a writer
    /// emits rather than only the keys it understood, and the JavaScript
    /// implementation's decoder folds both shapes away before its own code
    /// runs, so it could not emit either however hard it tried. Nothing a
    /// comparison of the two values can see changes, with the single
    /// exception SPEC.md names: `-0.0` written as `0` loses its sign.
    ///
    /// A CBOR map may not carry one key twice, and this list can: it is an
    /// ordered list of pairs, not a map. So on the way out an entry naming a
    /// key the event writes from a field is dropped, and of two entries
    /// sharing a key the first is written — as it is for a map nested inside
    /// a stored value, which is a map this crate emits too.
    ///
    /// The same two passes govern the other opaque values an event carries:
    /// a control message's `"msg"`, an annotation's `"data"` and an
    /// [`EventData::Unknown`]'s fields.
    ///
    /// Empty for every event this crate constructs itself.
    pub extra: Vec<(Value, Value)>,
}

/// Event-specific payload, discriminated by type.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum EventData {
    /// A control-stream message was sent or received (event type 0).
    ControlMessage {
        /// Send or receive.
        direction: Direction,
        /// Wire message type ID (e.g. `0x03` for SUBSCRIBE).
        message_type: u64,
        /// Decoded message fields, and **not necessarily a map**: match on it
        /// rather than assuming, or use [`TraceEvent::request_id`].
        ///
        /// A *recorder* MUST write a CBOR map keyed in snake_case here, and an
        /// empty map when it decoded nothing. A *reader* has to take what
        /// earlier writers produced, and every `capture-*` case in the
        /// conformance corpus holds a text rendering of the message instead.
        /// Such a value is handed back verbatim — unaddressable by key, but
        /// not a reason to reject an event the format forbids dropping — and
        /// is written back unchanged, because replacing it would destroy the
        /// only record of a message nobody will see again.
        ///
        /// Unchanged binds what the value says and not how it is encoded.
        /// This is a value the reader never looked at, so the two encoding
        /// rules reach it on the way out like any other:
        /// [`TraceEvent::extra`] has the whole of it.
        message: Value,
        /// QUIC stream the message travelled on, when the recorder knows it.
        ///
        /// `None` means unknown, which a reader must not confuse with stream
        /// 0. Recorders should fill it in: from draft-17 each request has its
        /// own bidirectional stream and responses carry no request ID, so the
        /// stream is the only thing pairing a response with its request.
        stream_id: Option<u64>,
        /// Raw wire bytes (only at `full` detail level).
        raw: Option<Vec<u8>>,
    },
    /// A QUIC stream was opened (event type 1).
    ///
    /// The four optional identifiers are what a `headers` recording has
    /// instead of the stream header bytes. No detail level records the bytes
    /// of a `SUBGROUP_HEADER`, a fetch header or a datagram header, so a value
    /// carried only there has nothing left to be re-parsed from — and before
    /// these fields existed the model could express group, object, priority
    /// and status and nothing else, which left a `headers` trace unable to say
    /// which track a stream belonged to.
    ///
    /// Each is `None` when the recorder did not know it — and also when the
    /// file carried the key with a value that is not an unsigned integer, in
    /// which case the entry is kept verbatim in [`TraceEvent::extra`] instead
    /// of being read here. A reader must not refuse a stream for lacking one:
    /// every recording predating the keys lacks all four.
    StreamOpened {
        /// QUIC stream ID.
        stream_id: u64,
        /// Outgoing or incoming.
        direction: Direction,
        /// Stream type.
        stream_type: StreamType,
        /// Track alias the stream carries. Meaningful on any stream type.
        track_alias: Option<u64>,
        /// Subgroup ID, on a [`StreamType::Subgroup`] stream.
        subgroup_id: Option<u64>,
        /// Fetch request ID, on a [`StreamType::Fetch`] stream.
        ///
        /// A recorder must write it there. It is the only correlation between
        /// the stream and the FETCH that asked for it, and unlike a subgroup
        /// stream a fetch stream carries no track alias to identify it by
        /// instead — so without it a fetch stream in a `headers` trace names
        /// nothing at all.
        fetch_request_id: Option<u64>,
        /// Group ID, on a [`StreamType::Datagram`] stream.
        ///
        /// Scoped to datagrams because on a subgroup stream every object
        /// carries the group of the stream by construction, so a copy here
        /// would be a second field with no independent source. Where it does
        /// appear alongside an [`ObjectHeader`](EventData::ObjectHeader) for
        /// the same stream, the object header is authoritative: this copy
        /// serves a reader that has not yet seen an object, and a
        /// disagreement between the two is not corruption.
        group_id: Option<u64>,
    },
    /// A QUIC stream was closed (event type 2).
    StreamClosed {
        /// QUIC stream ID.
        stream_id: u64,
        /// Error code (0 = clean close).
        error_code: u64,
    },
    /// An object header was parsed from a data stream (event type 3).
    ObjectHeader {
        /// Stream ID this object arrived on.
        stream_id: u64,
        /// Group ID.
        group: u64,
        /// Object ID.
        object: u64,
        /// Publisher priority.
        publisher_priority: u64,
        /// Object status (0=normal, 1=end-of-group, etc.).
        object_status: u64,
    },
    /// Object payload bytes were received or sent (event type 4).
    ObjectPayload {
        /// Stream ID.
        stream_id: u64,
        /// Group ID.
        group: u64,
        /// Object ID.
        object: u64,
        /// Payload size in bytes.
        size: u64,
        /// Payload bytes (only at `headers+data` or `full` level).
        payload: Option<Vec<u8>>,
    },
    /// Session FSM phase transition (event type 5).
    StateChange {
        /// Previous session phase.
        from: String,
        /// New session phase.
        to: String,
    },
    /// Protocol or transport error (event type 6).
    ///
    /// The four optional fields are what makes the event evidence rather than
    /// an assertion. A peer that sends something malformed is one of the few
    /// things a shared trace is uniquely good for — the recording party can
    /// see it and the sending party cannot — and until these existed the only
    /// field in the format able to hold bytes was a control message's `"raw"`,
    /// so a recorder wanting to keep the offending bytes had to record the
    /// violation as a decodable message in order to have somewhere to put
    /// them.
    ///
    /// Each is `None` when the recorder did not write it — and also when the
    /// file carried the key with a value the field cannot hold, in which case
    /// the entry stays verbatim in [`TraceEvent::extra`] instead of being read
    /// here.
    ///
    /// [`error_observed`](EventData::error_observed) builds one of these from
    /// bytes a recorder has just seen, which is where the cap on `raw` and the
    /// detail levels the two byte-bearing fields sit at are applied.
    Error {
        /// Error code.
        error_code: u64,
        /// Human-readable reason.
        reason: String,
        /// QUIC stream the error was observed on, when there was one and the
        /// recorder knows it.
        ///
        /// Optional on the same terms as a control message's `"sid"`: `None`
        /// means there was no stream or none is known, which a reader must not
        /// confuse with stream 0.
        stream_id: Option<u64>,
        /// What sort of failure this was.
        kind: Option<ErrorKind>,
        /// Byte length of the input the recorder held for this error, before
        /// any truncation.
        ///
        /// Recorded from `headers+sizes` upwards, one level below the bytes
        /// themselves: how large a malformed message was is often enough on
        /// its own to tell a truncated message from a mistyped one, and it
        /// carries no content. It is still a size, and this format gates sizes
        /// deliberately, so it does not reach a `control`-level trace.
        ///
        /// Where both are present, a value larger than `raw`'s length is how a
        /// reader learns the capture is partial and by how much. Where this is
        /// absent, a `raw` of exactly [`ERROR_RAW_CAP`] bytes is the one length
        /// the cap makes ambiguous and must be taken as possibly truncated.
        raw_len: Option<u64>,
        /// The offending bytes, at `full` detail only.
        ///
        /// Payload-bearing, and gated a level above the event's own
        /// `control`+: an error naming a *data* stream has subgroup framing
        /// and object payload behind it, so inheriting the event's level would
        /// have put media into traces whose declared level excludes payloads
        /// outright.
        ///
        /// A recorder caps this at [`ERROR_RAW_CAP`] bytes. A reader does not:
        /// a longer one read from a file is neither shortened nor refused.
        raw: Option<Vec<u8>>,
    },
    /// User-defined annotation (event type 7).
    Annotation {
        /// User-defined label.
        label: String,
        /// User-defined data (any CBOR type).
        ///
        /// Opaque: nothing here reads it, and it is written back saying what
        /// it said. Its encoding is the writer's, though — see
        /// [`TraceEvent::extra`].
        data: Value,
    },
    /// A new peer session was established (event type 8).
    ///
    /// The identifier for the peer lives on [`TraceEvent::peer`]; every later
    /// event for that peer repeats it.
    PeerConnected {
        /// Peer-reported endpoint URI or remote address, best-effort.
        endpoint: Option<String>,
        /// Transport type (`"webtransport"`, `"raw-quic"`, …).
        transport: Option<String>,
        /// Role at connection time, if known then.
        role: Option<PeerRole>,
        /// Which end of the relay the peer connected from.
        side: Option<Side>,
    },
    /// A peer session ended (event type 9).
    PeerDisconnected {
        /// Error or close code (0 = clean close).
        error_code: u64,
        /// Human-readable reason.
        reason: Option<String>,
    },
    /// An upstream subscription was created or extended in causal response to
    /// downstream ones (event type 10).
    ///
    /// This is the primitive multi-hop correlation is built from: a collector
    /// reconstructs an end-to-end tree from these links plus the trace IDs
    /// propagated along them.
    ///
    /// The four timestamps share the `timestamp` field's timebase — the
    /// emitting source's own clock. Differences between them are therefore
    /// meaningful with no cross-hop clock agreement, which is the point: they
    /// measure how long *this* hop took. Never subtract one source's
    /// timestamp from another's.
    ///
    /// A source emits the event as soon as the downstream SUBSCRIBE arrives,
    /// carrying whichever timestamps it has, and may emit it again for the
    /// same pair as the rest arrive. A consumer treats the later event as an
    /// update to the earlier one, not as a second derivation.
    SubscriptionDerivation {
        /// The upstream subscription.
        upstream: SubscriptionRef,
        /// Every downstream subscription currently served by `upstream`.
        downstream: Vec<SubscriptionRef>,
        /// Whether the upstream sub was created here or was already running.
        kind: DerivationKind,
        /// Trace ID propagated along the subscription chain, carried as raw
        /// bytes at every layer so two implementations produce identical
        /// values for the same chain.
        trace_id: Option<[u8; TRACE_ID_LEN]>,
        /// Track namespace the subscription targets, one entry per field.
        namespace: Option<Vec<Vec<u8>>>,
        /// Track name the subscription targets.
        track_name: Option<Vec<u8>>,
        /// When the downstream SUBSCRIBE was received.
        t_downstream_received: Option<i64>,
        /// When the upstream SUBSCRIBE was transmitted. Absent for terminal
        /// subscriptions, where this source is the content origin.
        t_upstream_sent: Option<i64>,
        /// When SUBSCRIBE_OK was received from upstream. Absent for terminal
        /// or still-in-flight subscriptions.
        t_upstream_ok_received: Option<i64>,
        /// When SUBSCRIBE_OK was transmitted downstream. Absent while the
        /// subscription is still in flight.
        t_downstream_ok_sent: Option<i64>,
    },
    /// An event whose type this version of the crate does not know.
    ///
    /// New event types may be added without a format version bump, so a
    /// reader that rejected them would turn every future addition into a
    /// breaking change. The fields are kept verbatim, which means an unknown
    /// event survives a read-modify-write round trip intact — intact in what
    /// it says, since the encoding written back is this crate's own. See
    /// [`TraceEvent::extra`].
    Unknown {
        /// The event type discriminant that was read.
        event_type: u64,
        /// Every key and value from the event map other than `"n"`, `"t"`
        /// and `"e"` — and other than `"p"`, when a peer was read from it. A
        /// `"p"` that is not text is kept here like any other value this crate
        /// could not use.
        fields: Vec<(Value, Value)>,
    },
}

/// Where `detail` sits in the levels' ordering, or `None` for a level this
/// crate cannot place.
///
/// The levels are a chain — each records everything the one before it does —
/// so one rank answers every question about which of two a recorder is at.
/// A level this crate has never heard of has no place in the chain, which is
/// why this is an `Option` rather than a number with a default: a default
/// would guess, and the two ways of guessing wrong are not symmetric.
fn detail_rank(detail: &DetailLevel) -> Option<u8> {
    match detail {
        DetailLevel::Control => Some(0),
        DetailLevel::Headers => Some(1),
        DetailLevel::HeadersSizes => Some(2),
        DetailLevel::HeadersData => Some(3),
        DetailLevel::Full => Some(4),
        DetailLevel::Other(_) => None,
    }
}

/// Whether a recorder at `detail` records everything a recorder at `floor`
/// does.
///
/// `false` when either level is one this crate cannot place. A future level
/// might sit above `floor` or below it, and answering `true` on a guess would
/// put payload bytes into a trace whose declared level excludes them — a loss
/// of one diagnostic against a leak that cannot be taken back.
fn detail_reaches(detail: &DetailLevel, floor: &DetailLevel) -> bool {
    match (detail_rank(detail), detail_rank(floor)) {
        (Some(level), Some(floor)) => level >= floor,
        _ => false,
    }
}

impl EventData {
    /// An [`Error`](EventData::Error) built from the bytes a recorder has just
    /// observed, for a trace recorded at `detail`.
    ///
    /// This is where the cap on `"raw"` belongs and the only place this crate
    /// applies it: the party constructing an event out of traffic it just saw
    /// is the one SPEC.md addresses, and it is the only party that can tell a
    /// fresh event from one that arrived by being read. Serializing does not
    /// cap, and reading does not refuse — see [`ERROR_RAW_CAP`].
    ///
    /// `observed` is the whole input the recorder held, uncapped. What comes
    /// back depends on `detail`, because the two byte-bearing fields sit at
    /// different levels and that is deliberate:
    ///
    /// - `raw_len` is the full length of `observed`, from `headers+sizes`
    ///   upwards. It is a size, and sizes are gated; it is not gated *with*
    ///   the bytes, so it is available in every trace where the bytes must not
    ///   appear, which is the point of having it.
    /// - `raw` is the first [`ERROR_RAW_CAP`] bytes of `observed`, at `full`
    ///   only. Below that level nothing is copied.
    ///
    /// A level this crate cannot place yields neither.
    ///
    /// Where both come back, comparing them is how a reader learns the capture
    /// was truncated: `raw_len` is the length before the cap bit, not after.
    pub fn error_observed(
        error_code: u64,
        reason: impl Into<String>,
        kind: Option<ErrorKind>,
        stream_id: Option<u64>,
        observed: &[u8],
        detail: &DetailLevel,
    ) -> Self {
        let raw_len = detail_reaches(detail, &DetailLevel::HeadersSizes)
            .then(|| u64::try_from(observed.len()).unwrap_or(u64::MAX));
        let raw = detail_reaches(detail, &DetailLevel::Full)
            .then(|| observed[..observed.len().min(ERROR_RAW_CAP)].to_vec());
        EventData::Error { error_code, reason: reason.into(), stream_id, kind, raw_len, raw }
    }
}

impl TraceEvent {
    /// An event with no peer identifier — the single-session case.
    pub fn new(seq: u64, timestamp: i64, data: EventData) -> Self {
        TraceEvent { seq, timestamp, peer: None, data, extra: Vec::new() }
    }

    /// An event attributed to `peer` — the relay-tap case.
    pub fn for_peer(seq: u64, timestamp: i64, peer: impl Into<String>, data: EventData) -> Self {
        TraceEvent { seq, timestamp, peer: Some(peer.into()), data, extra: Vec::new() }
    }

    /// Attach unrecognised keys, for a caller reconstructing an event it did
    /// not decode itself.
    ///
    /// Keys that collide with ones the event writes from its own fields are
    /// dropped on serialization rather than written twice, since a CBOR map
    /// with a repeated key is malformed and the event's own value is the one
    /// the reader would have produced. A key the event's type merely *defines*
    /// does not collide: an optional field holding `None` writes nothing, so
    /// the entry here is the only copy of that key and is written.
    #[must_use]
    pub fn with_extra(mut self, extra: Vec<(Value, Value)>) -> Self {
        self.extra = extra;
        self
    }

    /// The event type discriminant this event serializes as.
    pub fn event_type(&self) -> u64 {
        match &self.data {
            EventData::ControlMessage { .. } => EVENT_CONTROL_MESSAGE,
            EventData::StreamOpened { .. } => EVENT_STREAM_OPENED,
            EventData::StreamClosed { .. } => EVENT_STREAM_CLOSED,
            EventData::ObjectHeader { .. } => EVENT_OBJECT_HEADER,
            EventData::ObjectPayload { .. } => EVENT_OBJECT_PAYLOAD,
            EventData::StateChange { .. } => EVENT_STATE_CHANGE,
            EventData::Error { .. } => EVENT_ERROR,
            EventData::Annotation { .. } => EVENT_ANNOTATION,
            EventData::PeerConnected { .. } => EVENT_PEER_CONNECTED,
            EventData::PeerDisconnected { .. } => EVENT_PEER_DISCONNECTED,
            EventData::SubscriptionDerivation { .. } => EVENT_SUBSCRIPTION_DERIVATION,
            EventData::Unknown { event_type, .. } => *event_type,
        }
    }

    /// Extract the `request_id` from a control message's decoded `"msg"`
    /// field, if present.
    ///
    /// Returns `None` for non-control-message events, for a `"msg"` that is
    /// not a map, and for a map that names the field something else. Drafts 07
    /// through 10 call it `subscribe_id`, and this does not answer for them:
    /// the two names sit on different messages with different meanings, and a
    /// reader that wants either can ask the map itself.
    ///
    /// The key is `request_id`, in the snake_case the drafts use, because that
    /// is what every writer of these files produces. It read `requestId` until
    /// draft-20, and matched nothing — not this crate's own corpus, and not a
    /// trace written by any other implementation.
    pub fn request_id(&self) -> Option<u64> {
        if let EventData::ControlMessage { message: Value::Map(ref pairs), .. } = self.data {
            for (k, v) in pairs {
                if k.as_text() == Some("request_id") {
                    return v.as_integer().and_then(|i| u64::try_from(i).ok());
                }
            }
        }
        None
    }

    /// Return the message type for control message events.
    pub fn message_type(&self) -> Option<u64> {
        if let EventData::ControlMessage { message_type, .. } = self.data {
            Some(message_type)
        } else {
            None
        }
    }

    /// Return the direction for events that have one.
    pub fn direction(&self) -> Option<Direction> {
        match &self.data {
            EventData::ControlMessage { direction, .. }
            | EventData::StreamOpened { direction, .. } => Some(*direction),
            _ => None,
        }
    }
}

// ── CBOR conversion ────────────────────────────────────────

/// Wrapper that serializes as a CBOR byte string (major type 2). Without this
/// wrapper, serializing `&[u8]` via generic `Serialize` produces a CBOR array
/// of u8.
struct ByteStr<'a>(&'a [u8]);

impl serde::Serialize for ByteStr<'_> {
    #[inline]
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(self.0)
    }
}

impl Direction {
    #[inline]
    fn to_u64(self) -> u64 {
        match self {
            Direction::Send => 0,
            Direction::Receive => 1,
        }
    }
}

impl StreamType {
    #[inline]
    fn to_u64(self) -> u64 {
        match self {
            StreamType::Subgroup => 0,
            StreamType::Datagram => 1,
            StreamType::Fetch => 2,
        }
    }
}

/// Build a CBOR [`Value`] from a [`TraceEvent`] by running it through the
/// crate's `Serialize` impl. Convenience for tests and inspection — the
/// hot write path in [`MoqTraceWriter`](crate::writer::MoqTraceWriter) uses
/// `Serialize` directly and never materializes a `Value`.
impl From<&TraceEvent> for Value {
    fn from(event: &TraceEvent) -> Self {
        Value::serialized(event).expect("TraceEvent serialization is infallible")
    }
}

impl serde::Serialize for TraceEvent {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;

        // Every value an event carries out of a file rather than out of a
        // typed field goes out through `normalised`: an unknown event type's
        // fields and the store here, a control message's `"msg"` and an
        // annotation's `"data"` below. The two encoding rules bind the bytes a
        // writer emits and so bind every value it emits, the ones it never
        // looked at included — SPEC.md, Interoperability. A typed field needs
        // none of this and gets none: `"raw"`, `"pl"`, `"traceId"`, `"tn"` and
        // every field of `"ns"` are `Vec<u8>` by the time they reach here and
        // go out as major type 2 by construction, and every integer field goes
        // out as a CBOR integer for the same reason.
        //
        // Filtered against the common fields on the way out, the same way the
        // store below is filtered against every field the event writes: an
        // unknown event type writes `"n"`, `"t"`, `"e"` and `"p"` from the
        // common fields, so an entry here naming one of those is dropped
        // rather than putting that key in the map twice. A caller can put one
        // in this list by hand, and a file that repeated a common key leaves
        // one here too — that is where the entry `seq` did not take now lives.
        let unknown_fields = match &self.data {
            EventData::Unknown { fields, .. } => {
                store_entries(fields, |key| writes_common_key(self.peer.as_deref(), key))
            }
            _ => Vec::new(),
        };

        // A key this event writes from one of its own fields is written from
        // there, so an `extra` entry naming it is dropped rather than written
        // twice: a CBOR map with a duplicate key is malformed, and the field
        // is what a reader produced. A key the type merely *defines* is not
        // one of those — an optional field holding `None` writes nothing, and
        // the entry here is then a value the decode could not use, which has
        // to go back out.
        //
        // The same pass the header's stores go through, for the same three
        // reasons: the filter above, the encoding rules, and no key twice.
        let extra = store_entries(&self.extra, |key| {
            writes_common_key(self.peer.as_deref(), key) || writes_variant_key(&self.data, key)
        });

        // Pre-count entries so the CBOR map is encoded with a definite length.
        let variant_entries = match &self.data {
            EventData::ControlMessage { stream_id, raw, .. } => {
                3 + usize::from(stream_id.is_some()) + usize::from(raw.is_some())
            }
            EventData::StreamOpened {
                track_alias,
                subgroup_id,
                fetch_request_id,
                group_id,
                ..
            } => {
                3 + usize::from(track_alias.is_some())
                    + usize::from(subgroup_id.is_some())
                    + usize::from(fetch_request_id.is_some())
                    + usize::from(group_id.is_some())
            }
            EventData::StreamClosed { .. } => 2,
            EventData::ObjectHeader { .. } => 5,
            EventData::ObjectPayload { payload, .. } => 4 + usize::from(payload.is_some()),
            EventData::StateChange { .. } => 2,
            EventData::Error { stream_id, kind, raw_len, raw, .. } => {
                2 + usize::from(stream_id.is_some())
                    + usize::from(kind.is_some())
                    + usize::from(raw_len.is_some())
                    + usize::from(raw.is_some())
            }
            EventData::Annotation { .. } => 2,
            EventData::PeerConnected { endpoint, transport, role, side } => {
                usize::from(endpoint.is_some())
                    + usize::from(transport.is_some())
                    + usize::from(role.is_some())
                    + usize::from(side.is_some())
            }
            EventData::PeerDisconnected { reason, .. } => 1 + usize::from(reason.is_some()),
            EventData::SubscriptionDerivation {
                trace_id,
                namespace,
                track_name,
                t_downstream_received,
                t_upstream_sent,
                t_upstream_ok_received,
                t_downstream_ok_sent,
                ..
            } => {
                3 + usize::from(trace_id.is_some())
                    + usize::from(namespace.is_some())
                    + usize::from(track_name.is_some())
                    + usize::from(t_downstream_received.is_some())
                    + usize::from(t_upstream_sent.is_some())
                    + usize::from(t_upstream_ok_received.is_some())
                    + usize::from(t_downstream_ok_sent.is_some())
            }
            EventData::Unknown { .. } => unknown_fields.len(),
        };

        let entries = 3 /* n, t, e */
            + usize::from(self.peer.is_some())
            + variant_entries
            + extra.len();

        let mut map = ser.serialize_map(Some(entries))?;
        map.serialize_entry("n", &self.seq)?;
        map.serialize_entry("t", &self.timestamp)?;
        if let Some(ref peer) = self.peer {
            map.serialize_entry("p", peer)?;
        }

        match &self.data {
            EventData::ControlMessage { direction, message_type, message, stream_id, raw } => {
                map.serialize_entry("e", &EVENT_CONTROL_MESSAGE)?;
                map.serialize_entry("d", &direction.to_u64())?;
                map.serialize_entry("mt", message_type)?;
                map.serialize_entry("msg", &normalised(message))?;
                if let Some(sid) = stream_id {
                    map.serialize_entry("sid", sid)?;
                }
                if let Some(raw) = raw {
                    map.serialize_entry("raw", &ByteStr(raw))?;
                }
            }
            EventData::StreamOpened {
                stream_id,
                direction,
                stream_type,
                track_alias,
                subgroup_id,
                fetch_request_id,
                group_id,
            } => {
                map.serialize_entry("e", &EVENT_STREAM_OPENED)?;
                map.serialize_entry("sid", stream_id)?;
                map.serialize_entry("d", &direction.to_u64())?;
                map.serialize_entry("st", &stream_type.to_u64())?;
                if let Some(ta) = track_alias {
                    map.serialize_entry("ta", ta)?;
                }
                if let Some(sg) = subgroup_id {
                    map.serialize_entry("sg", sg)?;
                }
                if let Some(fri) = fetch_request_id {
                    map.serialize_entry("fri", fri)?;
                }
                if let Some(g) = group_id {
                    map.serialize_entry("g", g)?;
                }
            }
            EventData::StreamClosed { stream_id, error_code } => {
                map.serialize_entry("e", &EVENT_STREAM_CLOSED)?;
                map.serialize_entry("sid", stream_id)?;
                map.serialize_entry("ec", error_code)?;
            }
            EventData::ObjectHeader {
                stream_id,
                group,
                object,
                publisher_priority,
                object_status,
            } => {
                map.serialize_entry("e", &EVENT_OBJECT_HEADER)?;
                map.serialize_entry("sid", stream_id)?;
                map.serialize_entry("g", group)?;
                map.serialize_entry("o", object)?;
                map.serialize_entry("pp", publisher_priority)?;
                map.serialize_entry("os", object_status)?;
            }
            EventData::ObjectPayload { stream_id, group, object, size, payload } => {
                map.serialize_entry("e", &EVENT_OBJECT_PAYLOAD)?;
                map.serialize_entry("sid", stream_id)?;
                map.serialize_entry("g", group)?;
                map.serialize_entry("o", object)?;
                map.serialize_entry("sz", size)?;
                if let Some(pl) = payload {
                    map.serialize_entry("pl", &ByteStr(pl))?;
                }
            }
            EventData::StateChange { from, to } => {
                map.serialize_entry("e", &EVENT_STATE_CHANGE)?;
                map.serialize_entry("from", from)?;
                map.serialize_entry("to", to)?;
            }
            EventData::Error { error_code, reason, stream_id, kind, raw_len, raw } => {
                map.serialize_entry("e", &EVENT_ERROR)?;
                map.serialize_entry("ec", error_code)?;
                map.serialize_entry("reason", reason)?;
                if let Some(sid) = stream_id {
                    map.serialize_entry("sid", sid)?;
                }
                if let Some(kind) = kind {
                    map.serialize_entry("ek", kind.as_str())?;
                }
                if let Some(raw_len) = raw_len {
                    map.serialize_entry("rawlen", raw_len)?;
                }
                // At whatever length it arrived. The cap is the recorder's,
                // and re-applying it here would shorten evidence read out of
                // somebody else's file — see [`ERROR_RAW_CAP`].
                if let Some(raw) = raw {
                    map.serialize_entry("raw", &ByteStr(raw))?;
                }
            }
            EventData::Annotation { label, data } => {
                map.serialize_entry("e", &EVENT_ANNOTATION)?;
                map.serialize_entry("label", label)?;
                map.serialize_entry("data", &normalised(data))?;
            }
            EventData::PeerConnected { endpoint, transport, role, side } => {
                map.serialize_entry("e", &EVENT_PEER_CONNECTED)?;
                if let Some(endpoint) = endpoint {
                    map.serialize_entry("endpoint", endpoint)?;
                }
                if let Some(transport) = transport {
                    map.serialize_entry("transport", transport)?;
                }
                if let Some(role) = role {
                    map.serialize_entry("role", role.as_str())?;
                }
                if let Some(side) = side {
                    map.serialize_entry("side", side.as_str())?;
                }
            }
            EventData::PeerDisconnected { error_code, reason } => {
                map.serialize_entry("e", &EVENT_PEER_DISCONNECTED)?;
                map.serialize_entry("ec", error_code)?;
                if let Some(reason) = reason {
                    map.serialize_entry("reason", reason)?;
                }
            }
            EventData::SubscriptionDerivation {
                upstream,
                downstream,
                kind,
                trace_id,
                namespace,
                track_name,
                t_downstream_received,
                t_upstream_sent,
                t_upstream_ok_received,
                t_downstream_ok_sent,
            } => {
                map.serialize_entry("e", &EVENT_SUBSCRIPTION_DERIVATION)?;
                map.serialize_entry("u", &upstream.to_value())?;
                let downstream_refs: Vec<Value> =
                    downstream.iter().map(SubscriptionRef::to_value).collect();
                map.serialize_entry("d", &Value::Array(downstream_refs))?;
                map.serialize_entry("kind", kind.as_str())?;
                if let Some(trace_id) = trace_id {
                    map.serialize_entry("traceId", &ByteStr(trace_id))?;
                }
                if let Some(namespace) = namespace {
                    let fields: Vec<Value> =
                        namespace.iter().map(|f| Value::Bytes(f.clone())).collect();
                    map.serialize_entry("ns", &Value::Array(fields))?;
                }
                if let Some(track_name) = track_name {
                    map.serialize_entry("tn", &ByteStr(track_name))?;
                }
                if let Some(t) = t_downstream_received {
                    map.serialize_entry("tdr", t)?;
                }
                if let Some(t) = t_upstream_sent {
                    map.serialize_entry("tus", t)?;
                }
                if let Some(t) = t_upstream_ok_received {
                    map.serialize_entry("tuo", t)?;
                }
                if let Some(t) = t_downstream_ok_sent {
                    map.serialize_entry("tdo", t)?;
                }
            }
            EventData::Unknown { event_type, .. } => {
                map.serialize_entry("e", event_type)?;
                for (k, v) in &unknown_fields {
                    map.serialize_entry(k, v)?;
                }
            }
        }

        // Last, so the event's own keys keep the positions a reader expects
        // and the file stays diffable against one written without them.
        for (k, v) in &extra {
            map.serialize_entry(k, v)?;
        }

        map.end()
    }
}

// ── decoding helpers ───────────────────────────────────────

/// Helper to extract a u64 from a CBOR map by key.
///
/// Accepts the float form an encoder may use for a value past 32 bits — see
/// [`as_u64`](crate::header::as_u64).
fn get_uint(pairs: &[(Value, Value)], key: &str) -> Option<u64> {
    pairs.iter().find_map(|(k, v)| if k.as_text() == Some(key) { as_u64(v) } else { None })
}

/// Helper to extract an i64 from a CBOR map by key. See [`get_uint`].
fn get_int(pairs: &[(Value, Value)], key: &str) -> Option<i64> {
    pairs.iter().find_map(|(k, v)| if k.as_text() == Some(key) { as_i64(v) } else { None })
}

/// Helper to extract a text string from a CBOR map by key.
fn get_text(pairs: &[(Value, Value)], key: &str) -> Option<String> {
    pairs.iter().find_map(|(k, v)| {
        if k.as_text() == Some(key) {
            v.as_text().map(|s| s.to_string())
        } else {
            None
        }
    })
}

/// Helper to extract a value from a CBOR map by key.
fn get_value(pairs: &[(Value, Value)], key: &str) -> Option<Value> {
    pairs.iter().find_map(|(k, v)| if k.as_text() == Some(key) { Some(v.clone()) } else { None })
}

/// Tag 64 marks a byte string as an array of unsigned 8-bit integers.
const TAG_UINT8_ARRAY: u64 = 64;

/// Read a byte string, unwrapping the typed-array tag some encoders add.
///
/// A byte string may arrive plain or wrapped in tag 64, and one of the two
/// implementations of this format wraps every one it writes. Reading only the
/// plain form meant every payload-bearing field that encoder produced — raw
/// wire bytes, object payloads, track names, trace ids — read as absent, and
/// a payload-bearing field that reads as absent is indistinguishable from one
/// the recorder chose not to capture.
fn as_bytes(value: &Value) -> Option<Vec<u8>> {
    match value {
        Value::Bytes(b) => Some(b.clone()),
        Value::Tag(TAG_UINT8_ARRAY, inner) => match inner.as_ref() {
            Value::Bytes(b) => Some(b.clone()),
            _ => None,
        },
        _ => None,
    }
}

/// Helper to extract byte string from a CBOR map by key.
fn get_bytes(pairs: &[(Value, Value)], key: &str) -> Option<Vec<u8>> {
    pairs.iter().find_map(|(k, v)| if k.as_text() == Some(key) { as_bytes(v) } else { None })
}

/// Read a control message's decoded `"msg"` field.
///
/// An absent key reads as the empty map a writer should have written, not as
/// an error. The format requires a writer with nothing decoded — an
/// unparseable message type, or a recorder not decoding bodies at all — to
/// emit `{}` rather than omit the key, but requires a reader to be more
/// tolerant still, and this is why: event 0 is one of the types sampling MUST
/// NOT drop, so refusing it over a missing `"msg"` discards exactly the events
/// the format promises to keep.
///
/// How much is lost depends on how the caller drives the reader, and the worse
/// case is the idiomatic one. [`MoqTraceReader::read_next`] returns the error,
/// so `collect::<Result<Vec<_>, _>>()` — what this crate's own tests use —
/// stops at the first offending event and yields none of the ones after it. A
/// caller that skips errors and continues loses only the offending events;
/// `moqtap trace` does that, and prints each one, so the loss was at least
/// visible there.
///
/// A value that is present is kept whatever its type. Recordings predating
/// the rule carry a text rendering of the message here — every `capture-*`
/// case in the conformance corpus is such a file — and they stay readable,
/// with the field simply not addressable by key.
fn get_message(pairs: &[(Value, Value)]) -> Value {
    get_value(pairs, "msg").unwrap_or_else(|| Value::Map(Vec::new()))
}

fn require_uint(pairs: &[(Value, Value)], key: &str) -> Result<u64, MoqTraceError> {
    get_uint(pairs, key).ok_or_else(|| MoqTraceError::InvalidEvent(format!("missing '{key}'")))
}

fn require_int(pairs: &[(Value, Value)], key: &str) -> Result<i64, MoqTraceError> {
    get_int(pairs, key).ok_or_else(|| MoqTraceError::InvalidEvent(format!("missing '{key}'")))
}

fn require_text(pairs: &[(Value, Value)], key: &str) -> Result<String, MoqTraceError> {
    get_text(pairs, key).ok_or_else(|| MoqTraceError::InvalidEvent(format!("missing '{key}'")))
}

fn require_value(pairs: &[(Value, Value)], key: &str) -> Result<Value, MoqTraceError> {
    get_value(pairs, key).ok_or_else(|| MoqTraceError::InvalidEvent(format!("missing '{key}'")))
}

fn require_direction(pairs: &[(Value, Value)], key: &str) -> Result<Direction, MoqTraceError> {
    let v = require_value(pairs, key)?;
    Direction::from_cbor(&v)
}

/// Read a trace ID, refusing any length but the one the format fixes.
///
/// A wrong-length value is malformed rather than something to pad or
/// truncate: the identifier exists so that two implementations independently
/// derive byte-identical values for one subscription chain, and a reader that
/// quietly reshapes it breaks exactly the property it is there for.
fn get_trace_id(pairs: &[(Value, Value)]) -> Result<Option<[u8; TRACE_ID_LEN]>, MoqTraceError> {
    let Some(bytes) = get_bytes(pairs, "traceId") else {
        return Ok(None);
    };
    <[u8; TRACE_ID_LEN]>::try_from(bytes.as_slice()).map(Some).map_err(|_| {
        MoqTraceError::InvalidEvent(format!(
            "'traceId' is {} bytes, must be {TRACE_ID_LEN}",
            bytes.len()
        ))
    })
}

/// Read a track namespace: an array of byte strings, tolerating text entries
/// from encoders that lose the distinction.
///
/// Answers `None` for anything else — a `"ns"` that is not an array, or an
/// array holding something that is neither bytes nor text. `"ns"` is optional,
/// and the rule for an optional key whose value this reader cannot use is that
/// the key is kept as an unrecognised one rather than that the event dies; the
/// caller then still has the derivation's upstream and downstream
/// subscriptions, which are what make it a derivation at all.
///
/// It used to return an error, which cost more than the field. `read_next`
/// propagates it, so `collect::<Result<Vec<_>, _>>()` — the documented idiom —
/// stopped at that event and yielded none of the ones after it. One namespace
/// an encoder wrote oddly took the rest of the recording with it.
fn get_namespace(pairs: &[(Value, Value)]) -> Option<Vec<Vec<u8>>> {
    let Some(Value::Array(items)) = get_value(pairs, "ns") else {
        return None;
    };
    let mut namespace = Vec::with_capacity(items.len());
    for item in items {
        let field = as_bytes(&item).or_else(|| item.as_text().map(|t| t.as_bytes().to_vec()))?;
        namespace.push(field);
    }
    Some(namespace)
}

/// The three keys every event carries whatever its type. All are required, so
/// a value the reader cannot use is a malformed event rather than something to
/// keep: there would be no event left to hang the kept key on.
const REQUIRED_COMMON_KEYS: [&str; 3] = ["n", "t", "e"];

/// Whether the common event fields account for `key` — the required three
/// always, and `"p"` only when a peer was actually read from it.
///
/// `"p"` is optional, and optional means it can also be *unusable*: a `"p"`
/// that is not text leaves [`TraceEvent::peer`] `None`, and the entry then
/// belongs in [`TraceEvent::extra`] like any other value the reader could not
/// use. Excluding the key unconditionally would delete it instead.
fn writes_common_key(peer: Option<&str>, key: &str) -> bool {
    REQUIRED_COMMON_KEYS.contains(&key) || (key == "p" && peer.is_some())
}

/// Whether `key` is written from one of `data`'s own fields — equivalently,
/// on an event that was decoded, whether the decode used it. The common keys
/// are not this function's business; [`writes_common_key`] answers for those.
///
/// Deliberately not "does this event type define `key`". The two part company
/// on a defined key whose value the decode could not use: SPEC.md treats such
/// a key as unrecognised, so its field stays `None` and the entry goes to
/// [`TraceEvent::extra`], from where the serializer writes it back unchanged.
/// Asking about the type's whole vocabulary instead keeps the key out of
/// `extra` while no field holds it either, and merely reading the file deletes
/// the value — which is how adding `"ta"`, `"sg"`, `"fri"` and `"g"` to event
/// 1 made this reader preserve *less* than while it had never heard of them.
///
/// The match is exhaustive on purpose: a new variant does not compile until
/// its keys are listed, and both ways of getting a list wrong are silent. A
/// key left out is written twice, once from the field and once from `extra`,
/// and a CBOR map with a duplicate key is malformed; a key wrongly listed is
/// dropped from every rewrite.
fn writes_variant_key(data: &EventData, key: &str) -> bool {
    /// `always` are the keys the variant writes unconditionally; `optional`
    /// pairs each of the rest with whether its field holds a value.
    fn among(key: &str, always: &[&str], optional: &[(&str, bool)]) -> bool {
        always.contains(&key) || optional.iter().any(|&(k, written)| written && k == key)
    }

    match data {
        EventData::ControlMessage { stream_id, raw, .. } => {
            among(key, &["d", "mt", "msg"], &[("sid", stream_id.is_some()), ("raw", raw.is_some())])
        }
        EventData::StreamOpened {
            track_alias, subgroup_id, fetch_request_id, group_id, ..
        } => among(
            key,
            &["sid", "d", "st"],
            &[
                ("ta", track_alias.is_some()),
                ("sg", subgroup_id.is_some()),
                ("fri", fetch_request_id.is_some()),
                ("g", group_id.is_some()),
            ],
        ),
        EventData::StreamClosed { .. } => among(key, &["sid", "ec"], &[]),
        EventData::ObjectHeader { .. } => among(key, &["sid", "g", "o", "pp", "os"], &[]),
        EventData::ObjectPayload { payload, .. } => {
            among(key, &["sid", "g", "o", "sz"], &[("pl", payload.is_some())])
        }
        EventData::StateChange { .. } => among(key, &["from", "to"], &[]),
        EventData::Error { stream_id, kind, raw_len, raw, .. } => among(
            key,
            &["ec", "reason"],
            &[
                ("sid", stream_id.is_some()),
                ("ek", kind.is_some()),
                ("rawlen", raw_len.is_some()),
                ("raw", raw.is_some()),
            ],
        ),
        EventData::Annotation { .. } => among(key, &["label", "data"], &[]),
        EventData::PeerConnected { endpoint, transport, role, side } => among(
            key,
            &[],
            &[
                ("endpoint", endpoint.is_some()),
                ("transport", transport.is_some()),
                ("role", role.is_some()),
                ("side", side.is_some()),
            ],
        ),
        EventData::PeerDisconnected { reason, .. } => {
            among(key, &["ec"], &[("reason", reason.is_some())])
        }
        EventData::SubscriptionDerivation {
            trace_id,
            namespace,
            track_name,
            t_downstream_received,
            t_upstream_sent,
            t_upstream_ok_received,
            t_downstream_ok_sent,
            ..
        } => among(
            key,
            &["u", "d", "kind"],
            &[
                ("traceId", trace_id.is_some()),
                ("ns", namespace.is_some()),
                ("tn", track_name.is_some()),
                ("tdr", t_downstream_received.is_some()),
                ("tus", t_upstream_sent.is_some()),
                ("tuo", t_upstream_ok_received.is_some()),
                ("tdo", t_downstream_ok_sent.is_some()),
            ],
        ),
        // An unknown event type writes every key it read straight back out of
        // `fields`, so those are the ones an `extra` entry would duplicate.
        // Decoding one collects nothing into `extra` — see the `Unknown` arm
        // below — but a caller may have attached some by hand.
        EventData::Unknown { fields, .. } => fields.iter().any(|(k, _)| k.as_text() == Some(key)),
    }
}

/// Every entry on `pairs` that the event decoded from it does not write back
/// out of a field of its own. See [`unrecognised`], which the header uses for
/// the same reason.
///
/// One difference from the header's use of it is worth naming, because it
/// decides *which* entry of a duplicate pair survives. A getter here searches
/// for the first entry it can **use**, where the header's lookup returns the
/// first entry for a key whatever it holds. So on a file repeating a key with
/// two different types — `"sid": "x"` and then `"sid": 9` — the field takes
/// the second and the walk drops the first. Both were lost before this walk
/// existed, and SPEC.md leaves readers free to disagree over which of a
/// duplicate pair wins, so nothing may depend on which one it is.
fn unrecognised_keys(
    pairs: &[(Value, Value)],
    peer: Option<&str>,
    data: &EventData,
) -> Vec<(Value, Value)> {
    unrecognised(pairs, |key| writes_common_key(peer, key) || writes_variant_key(data, key))
}

impl TryFrom<Value> for TraceEvent {
    type Error = MoqTraceError;

    fn try_from(value: Value) -> Result<Self, MoqTraceError> {
        let pairs = match value {
            Value::Map(pairs) => pairs,
            _ => return Err(MoqTraceError::InvalidEvent("event is not a CBOR map".into())),
        };

        let seq = require_uint(&pairs, "n")?;
        let timestamp = require_int(&pairs, "t")?;
        let peer = get_text(&pairs, "p");
        let event_type = require_uint(&pairs, "e")?;

        let data = match event_type {
            EVENT_CONTROL_MESSAGE => EventData::ControlMessage {
                direction: require_direction(&pairs, "d")?,
                message_type: require_uint(&pairs, "mt")?,
                message: get_message(&pairs),
                stream_id: get_uint(&pairs, "sid"),
                raw: get_bytes(&pairs, "raw"),
            },
            EVENT_STREAM_OPENED => {
                let st_val = require_value(&pairs, "st")?;
                EventData::StreamOpened {
                    stream_id: require_uint(&pairs, "sid")?,
                    direction: require_direction(&pairs, "d")?,
                    stream_type: StreamType::from_cbor(&st_val)?,
                    // Read whatever is usable, including a key outside the
                    // stream type it is scoped to. A writer must not produce
                    // one, but "ignore" is the same read-past-and-keep rule
                    // that governs `extra`: dropping it here would make this
                    // reader's opinion permanent for every reader downstream.
                    // A value that is not an unsigned integer is not usable —
                    // the field stays `None` and the key goes to `extra`,
                    // which is that same rule one step over. Neither reading
                    // past a key nor failing to understand its value is a
                    // licence to delete it.
                    track_alias: get_uint(&pairs, "ta"),
                    subgroup_id: get_uint(&pairs, "sg"),
                    fetch_request_id: get_uint(&pairs, "fri"),
                    group_id: get_uint(&pairs, "g"),
                }
            }
            EVENT_STREAM_CLOSED => EventData::StreamClosed {
                stream_id: require_uint(&pairs, "sid")?,
                error_code: require_uint(&pairs, "ec")?,
            },
            EVENT_OBJECT_HEADER => EventData::ObjectHeader {
                stream_id: require_uint(&pairs, "sid")?,
                group: require_uint(&pairs, "g")?,
                object: require_uint(&pairs, "o")?,
                publisher_priority: require_uint(&pairs, "pp")?,
                object_status: require_uint(&pairs, "os")?,
            },
            EVENT_OBJECT_PAYLOAD => EventData::ObjectPayload {
                stream_id: require_uint(&pairs, "sid")?,
                group: require_uint(&pairs, "g")?,
                object: require_uint(&pairs, "o")?,
                size: require_uint(&pairs, "sz")?,
                payload: get_bytes(&pairs, "pl"),
            },
            EVENT_STATE_CHANGE => EventData::StateChange {
                from: require_text(&pairs, "from")?,
                to: require_text(&pairs, "to")?,
            },
            EVENT_ERROR => EventData::Error {
                error_code: require_uint(&pairs, "ec")?,
                reason: require_text(&pairs, "reason")?,
                // All four optional, and every recording made before they
                // existed carries none of them. A `"raw"` longer than the cap
                // is read at the length the file gave it: the cap is addressed
                // to a recorder building an event from what it observed, and
                // re-truncating here would destroy evidence to make somebody
                // else's file conform to a rule it was never handed. Report
                // the non-conformance if it is worth reporting; do not repair
                // it. SPEC.md, Event 6.
                stream_id: get_uint(&pairs, "sid"),
                kind: get_text(&pairs, "ek").as_deref().map(ErrorKind::parse),
                raw_len: get_uint(&pairs, "rawlen"),
                raw: get_bytes(&pairs, "raw"),
            },
            EVENT_ANNOTATION => EventData::Annotation {
                label: require_text(&pairs, "label")?,
                data: require_value(&pairs, "data")?,
            },
            EVENT_PEER_CONNECTED => EventData::PeerConnected {
                endpoint: get_text(&pairs, "endpoint"),
                transport: get_text(&pairs, "transport"),
                role: get_text(&pairs, "role").as_deref().map(PeerRole::parse),
                side: get_text(&pairs, "side").as_deref().map(Side::parse),
            },
            EVENT_PEER_DISCONNECTED => EventData::PeerDisconnected {
                error_code: require_uint(&pairs, "ec")?,
                reason: get_text(&pairs, "reason"),
            },
            EVENT_SUBSCRIPTION_DERIVATION => {
                let upstream = SubscriptionRef::from_value(&require_value(&pairs, "u")?)?;
                let downstream = match require_value(&pairs, "d")? {
                    Value::Array(items) => items
                        .iter()
                        .map(SubscriptionRef::from_value)
                        .collect::<Result<Vec<_>, _>>()?,
                    _ => {
                        return Err(MoqTraceError::InvalidEvent(
                            "'d' (downstream subs) is not a CBOR array".into(),
                        ))
                    }
                };
                EventData::SubscriptionDerivation {
                    upstream,
                    downstream,
                    kind: DerivationKind::parse(&require_text(&pairs, "kind")?),
                    trace_id: get_trace_id(&pairs)?,
                    namespace: get_namespace(&pairs),
                    track_name: get_bytes(&pairs, "tn")
                        .or_else(|| get_text(&pairs, "tn").map(String::into_bytes)),
                    t_downstream_received: get_int(&pairs, "tdr"),
                    t_upstream_sent: get_int(&pairs, "tus"),
                    t_upstream_ok_received: get_int(&pairs, "tuo"),
                    t_downstream_ok_sent: get_int(&pairs, "tdo"),
                }
            }
            other => EventData::Unknown {
                event_type: other,
                // The same walk `unrecognised_keys` does, with only the common
                // fields to ask about: an unknown event type writes every
                // other key straight back out of here. It had the same defect
                // for the same reason — a repeated `"n"` was filtered out by
                // name, so the entry `seq` did not take reached neither — and
                // this variant collects nothing into `extra`, which makes
                // `fields` the only place such an entry can land.
                fields: unrecognised(&pairs, |key| writes_common_key(peer.as_deref(), key)),
            },
        };

        let extra = match &data {
            // `fields` already holds every key on this event the common
            // fields did not consume, a `"p"` this crate could not use among
            // them. Collecting them into `extra` as well would write each one
            // twice and produce a CBOR map with duplicate keys.
            EventData::Unknown { .. } => Vec::new(),
            other => unrecognised_keys(&pairs, peer.as_deref(), other),
        };
        Ok(TraceEvent { seq, timestamp, peer, data, extra })
    }
}

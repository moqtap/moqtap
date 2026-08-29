use ciborium::Value;

use crate::error::MoqTraceError;
use crate::header::{as_i64, as_u64};

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
        /// Decoded message fields as an opaque CBOR value.
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
    StreamOpened {
        /// QUIC stream ID.
        stream_id: u64,
        /// Outgoing or incoming.
        direction: Direction,
        /// Stream type.
        stream_type: StreamType,
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
    Error {
        /// Error code.
        error_code: u64,
        /// Human-readable reason.
        reason: String,
    },
    /// User-defined annotation (event type 7).
    Annotation {
        /// User-defined label.
        label: String,
        /// User-defined data (any CBOR type).
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
    /// event survives a read-modify-write round trip intact.
    Unknown {
        /// The event type discriminant that was read.
        event_type: u64,
        /// Every key and value from the event map other than `"n"`, `"t"`,
        /// `"p"` and `"e"`.
        fields: Vec<(Value, Value)>,
    },
}

impl TraceEvent {
    /// An event with no peer identifier — the single-session case.
    pub fn new(seq: u64, timestamp: i64, data: EventData) -> Self {
        TraceEvent { seq, timestamp, peer: None, data }
    }

    /// An event attributed to `peer` — the relay-tap case.
    pub fn for_peer(seq: u64, timestamp: i64, peer: impl Into<String>, data: EventData) -> Self {
        TraceEvent { seq, timestamp, peer: Some(peer.into()), data }
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
    /// Returns `None` for non-control-message events or if the `"msg"` map
    /// does not contain a `"requestId"` key.
    pub fn request_id(&self) -> Option<u64> {
        if let EventData::ControlMessage { message: Value::Map(ref pairs), .. } = self.data {
            for (k, v) in pairs {
                if k.as_text() == Some("requestId") {
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

        // Pre-count entries so the CBOR map is encoded with a definite length.
        let variant_entries = match &self.data {
            EventData::ControlMessage { stream_id, raw, .. } => {
                3 + usize::from(stream_id.is_some()) + usize::from(raw.is_some())
            }
            EventData::StreamOpened { .. } => 3,
            EventData::StreamClosed { .. } => 2,
            EventData::ObjectHeader { .. } => 5,
            EventData::ObjectPayload { payload, .. } => 4 + usize::from(payload.is_some()),
            EventData::StateChange { .. } => 2,
            EventData::Error { .. } => 2,
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
            EventData::Unknown { fields, .. } => fields.len(),
        };
        let entries = 3 /* n, t, e */ + usize::from(self.peer.is_some()) + variant_entries;

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
                map.serialize_entry("msg", message)?;
                if let Some(sid) = stream_id {
                    map.serialize_entry("sid", sid)?;
                }
                if let Some(raw) = raw {
                    map.serialize_entry("raw", &ByteStr(raw))?;
                }
            }
            EventData::StreamOpened { stream_id, direction, stream_type } => {
                map.serialize_entry("e", &EVENT_STREAM_OPENED)?;
                map.serialize_entry("sid", stream_id)?;
                map.serialize_entry("d", &direction.to_u64())?;
                map.serialize_entry("st", &stream_type.to_u64())?;
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
            EventData::Error { error_code, reason } => {
                map.serialize_entry("e", &EVENT_ERROR)?;
                map.serialize_entry("ec", error_code)?;
                map.serialize_entry("reason", reason)?;
            }
            EventData::Annotation { label, data } => {
                map.serialize_entry("e", &EVENT_ANNOTATION)?;
                map.serialize_entry("label", label)?;
                map.serialize_entry("data", data)?;
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
            EventData::Unknown { event_type, fields } => {
                map.serialize_entry("e", event_type)?;
                for (k, v) in fields {
                    map.serialize_entry(k, v)?;
                }
            }
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
fn get_namespace(pairs: &[(Value, Value)]) -> Result<Option<Vec<Vec<u8>>>, MoqTraceError> {
    match get_value(pairs, "ns") {
        None => Ok(None),
        Some(Value::Array(items)) => {
            let mut namespace = Vec::with_capacity(items.len());
            for item in items {
                match as_bytes(&item).or_else(|| item.as_text().map(|t| t.as_bytes().to_vec())) {
                    Some(field) => namespace.push(field),
                    None => {
                        return Err(MoqTraceError::InvalidEvent(
                            "'ns' entry is neither bytes nor text".into(),
                        ))
                    }
                }
            }
            Ok(Some(namespace))
        }
        Some(_) => Err(MoqTraceError::InvalidEvent("'ns' is not a CBOR array".into())),
    }
}

/// Keys the common event fields own. Everything else in an unknown event's
/// map belongs to the type this crate cannot name, and is kept verbatim.
const COMMON_KEYS: [&str; 4] = ["n", "t", "p", "e"];

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
                message: require_value(&pairs, "msg")?,
                stream_id: get_uint(&pairs, "sid"),
                raw: get_bytes(&pairs, "raw"),
            },
            EVENT_STREAM_OPENED => {
                let st_val = require_value(&pairs, "st")?;
                EventData::StreamOpened {
                    stream_id: require_uint(&pairs, "sid")?,
                    direction: require_direction(&pairs, "d")?,
                    stream_type: StreamType::from_cbor(&st_val)?,
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
                    namespace: get_namespace(&pairs)?,
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
                fields: pairs
                    .iter()
                    .filter(|(k, _)| !k.as_text().is_some_and(|s| COMMON_KEYS.contains(&s)))
                    .cloned()
                    .collect(),
            },
        };

        Ok(TraceEvent { seq, timestamp, peer, data })
    }
}

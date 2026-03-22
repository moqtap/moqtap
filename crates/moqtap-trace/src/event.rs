use ciborium::Value;

use crate::error::MoqTraceError;

/// Direction of a message or stream relative to the recording endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Sent (outgoing). Wire value: `0`.
    Send,
    /// Received (incoming). Wire value: `1`.
    Receive,
}

impl Direction {
    fn to_cbor(self) -> Value {
        Value::Integer(match self {
            Direction::Send => 0.into(),
            Direction::Receive => 1.into(),
        })
    }

    fn from_cbor(v: &Value) -> Result<Self, MoqTraceError> {
        match v.as_integer().and_then(|i| u64::try_from(i).ok()) {
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
    fn to_cbor(self) -> Value {
        Value::Integer(match self {
            StreamType::Subgroup => 0.into(),
            StreamType::Datagram => 1.into(),
            StreamType::Fetch => 2.into(),
        })
    }

    fn from_cbor(v: &Value) -> Result<Self, MoqTraceError> {
        match v.as_integer().and_then(|i| u64::try_from(i).ok()) {
            Some(0) => Ok(StreamType::Subgroup),
            Some(1) => Ok(StreamType::Datagram),
            Some(2) => Ok(StreamType::Fetch),
            _ => Err(MoqTraceError::InvalidEvent("invalid stream type value".into())),
        }
    }
}

/// Event type discriminant. Matches FORMAT.md `"e"` values.
const EVENT_CONTROL_MESSAGE: u64 = 0;
const EVENT_STREAM_OPENED: u64 = 1;
const EVENT_STREAM_CLOSED: u64 = 2;
const EVENT_OBJECT_HEADER: u64 = 3;
const EVENT_OBJECT_PAYLOAD: u64 = 4;
const EVENT_STATE_CHANGE: u64 = 5;
const EVENT_ERROR: u64 = 6;
const EVENT_ANNOTATION: u64 = 7;

/// A single event in a `.moqtrace` file.
#[derive(Debug, Clone, PartialEq)]
pub struct TraceEvent {
    /// Monotonically increasing sequence number (0-based).
    pub seq: u64,
    /// Timestamp in microseconds since the header's `startTime`.
    pub timestamp: i64,
    /// Event-specific data.
    pub data: EventData,
}

/// Event-specific payload, discriminated by type.
#[derive(Debug, Clone, PartialEq)]
pub enum EventData {
    /// A control-stream message was sent or received (event type 0).
    ControlMessage {
        /// Send or receive.
        direction: Direction,
        /// Wire message type ID (e.g. `0x03` for SUBSCRIBE).
        message_type: u64,
        /// Decoded message fields as an opaque CBOR value.
        message: Value,
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
}

impl TraceEvent {
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

/// Helper to push a key-value pair into a CBOR map's pair list.
fn push_text(pairs: &mut Vec<(Value, Value)>, key: &str, val: Value) {
    pairs.push((Value::Text(key.into()), val));
}

fn push_uint(pairs: &mut Vec<(Value, Value)>, key: &str, val: u64) {
    push_text(pairs, key, Value::Integer(val.into()));
}

impl From<&TraceEvent> for Value {
    fn from(event: &TraceEvent) -> Self {
        let mut pairs: Vec<(Value, Value)> = Vec::new();

        push_uint(&mut pairs, "n", event.seq);
        push_text(&mut pairs, "t", Value::Integer(event.timestamp.into()));

        match &event.data {
            EventData::ControlMessage { direction, message_type, message, raw } => {
                push_uint(&mut pairs, "e", EVENT_CONTROL_MESSAGE);
                push_text(&mut pairs, "d", direction.to_cbor());
                push_uint(&mut pairs, "mt", *message_type);
                push_text(&mut pairs, "msg", message.clone());
                if let Some(raw) = raw {
                    push_text(&mut pairs, "raw", Value::Bytes(raw.clone()));
                }
            }
            EventData::StreamOpened { stream_id, direction, stream_type } => {
                push_uint(&mut pairs, "e", EVENT_STREAM_OPENED);
                push_uint(&mut pairs, "sid", *stream_id);
                push_text(&mut pairs, "d", direction.to_cbor());
                push_text(&mut pairs, "st", stream_type.to_cbor());
            }
            EventData::StreamClosed { stream_id, error_code } => {
                push_uint(&mut pairs, "e", EVENT_STREAM_CLOSED);
                push_uint(&mut pairs, "sid", *stream_id);
                push_uint(&mut pairs, "ec", *error_code);
            }
            EventData::ObjectHeader {
                stream_id,
                group,
                object,
                publisher_priority,
                object_status,
            } => {
                push_uint(&mut pairs, "e", EVENT_OBJECT_HEADER);
                push_uint(&mut pairs, "sid", *stream_id);
                push_uint(&mut pairs, "g", *group);
                push_uint(&mut pairs, "o", *object);
                push_uint(&mut pairs, "pp", *publisher_priority);
                push_uint(&mut pairs, "os", *object_status);
            }
            EventData::ObjectPayload { stream_id, group, object, size, payload } => {
                push_uint(&mut pairs, "e", EVENT_OBJECT_PAYLOAD);
                push_uint(&mut pairs, "sid", *stream_id);
                push_uint(&mut pairs, "g", *group);
                push_uint(&mut pairs, "o", *object);
                push_uint(&mut pairs, "sz", *size);
                if let Some(pl) = payload {
                    push_text(&mut pairs, "pl", Value::Bytes(pl.clone()));
                }
            }
            EventData::StateChange { from, to } => {
                push_uint(&mut pairs, "e", EVENT_STATE_CHANGE);
                push_text(&mut pairs, "from", Value::Text(from.clone()));
                push_text(&mut pairs, "to", Value::Text(to.clone()));
            }
            EventData::Error { error_code, reason } => {
                push_uint(&mut pairs, "e", EVENT_ERROR);
                push_uint(&mut pairs, "ec", *error_code);
                push_text(&mut pairs, "reason", Value::Text(reason.clone()));
            }
            EventData::Annotation { label, data } => {
                push_uint(&mut pairs, "e", EVENT_ANNOTATION);
                push_text(&mut pairs, "label", Value::Text(label.clone()));
                push_text(&mut pairs, "data", data.clone());
            }
        }

        Value::Map(pairs)
    }
}

/// Helper to extract a u64 from a CBOR map by key.
fn get_uint(pairs: &[(Value, Value)], key: &str) -> Option<u64> {
    pairs.iter().find_map(|(k, v)| {
        if k.as_text() == Some(key) {
            v.as_integer().and_then(|i| u64::try_from(i).ok())
        } else {
            None
        }
    })
}

/// Helper to extract an i64 from a CBOR map by key.
fn get_int(pairs: &[(Value, Value)], key: &str) -> Option<i64> {
    pairs.iter().find_map(|(k, v)| {
        if k.as_text() == Some(key) {
            v.as_integer().and_then(|i| i64::try_from(i).ok())
        } else {
            None
        }
    })
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

/// Helper to extract byte string from a CBOR map by key.
fn get_bytes(pairs: &[(Value, Value)], key: &str) -> Option<Vec<u8>> {
    pairs.iter().find_map(|(k, v)| {
        if k.as_text() == Some(key) {
            v.as_bytes().map(|b| b.to_vec())
        } else {
            None
        }
    })
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

impl TryFrom<Value> for TraceEvent {
    type Error = MoqTraceError;

    fn try_from(value: Value) -> Result<Self, MoqTraceError> {
        let pairs = match value {
            Value::Map(pairs) => pairs,
            _ => return Err(MoqTraceError::InvalidEvent("event is not a CBOR map".into())),
        };

        let seq = require_uint(&pairs, "n")?;
        let timestamp = require_int(&pairs, "t")?;
        let event_type = require_uint(&pairs, "e")?;

        let data = match event_type {
            EVENT_CONTROL_MESSAGE => EventData::ControlMessage {
                direction: require_direction(&pairs, "d")?,
                message_type: require_uint(&pairs, "mt")?,
                message: require_value(&pairs, "msg")?,
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
            other => {
                return Err(MoqTraceError::InvalidEvent(format!("unknown event type: {other}")))
            }
        };

        Ok(TraceEvent { seq, timestamp, data })
    }
}

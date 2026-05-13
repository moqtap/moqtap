//! Draft-18 control message encoding and decoding.
//!
//! Key differences from draft-17:
//! - `Required Request ID Delta` field removed from every request message.
//! - SUBSCRIBE_NAMESPACE renumbered to 0x50 and `subscribe_options` removed.
//! - New SUBSCRIBE_TRACKS message (0x51); FORWARD parameter belongs here.
//! - PUBLISH_OK collapsed into REQUEST_OK (0x07); REQUEST_OK gains a trailing
//!   Track Properties block (length implicit from message length).
//! - GOAWAY gains an optional `request_id` (control stream only).
//! - REQUEST_ERROR gains REDIRECT (0x34) carrying a Redirect structure
//!   (connect_uri, track_namespace, track_name) appended after reason_phrase.
//! - PUBLISH_DONE status codes 0x5/0x6 swapped: 0x5 = TOO_FAR_BEHIND,
//!   0x6 = EXPIRED.
//! - DELIVERY_TIMEOUT (0x02) renamed to OBJECT_DELIVERY_TIMEOUT;
//!   new SUBGROUP_DELIVERY_TIMEOUT (0x06) and FILL_TIMEOUT (0x0A).
//! - New TRACK_NAMESPACE_PREFIX parameter (0x34) for REQUEST_UPDATE
//!   (length-prefixed encoded TrackNamespace).

pub use crate::error::{
    CodecError, MAX_GOAWAY_URI_LENGTH, MAX_MESSAGE_LENGTH, MAX_NAMESPACE_TUPLE_SIZE,
    MAX_REASON_PHRASE_LENGTH,
};
use crate::kvp::{KeyValuePair, KvpValue};
use crate::types::*;
use crate::varint::VarInt;
use bytes::{Buf, BufMut};

// ============================================================
// Parameter encoding helpers for draft-18
// ============================================================

/// How a parameter value is encoded on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParamEncoding {
    /// Bare varint.
    Varint,
    /// Single byte (uint8).
    Uint8,
    /// Length-prefixed bytes.
    LengthPrefixed,
}

fn param_encoding(key: u64) -> Option<ParamEncoding> {
    match key {
        // 0x02 = OBJECT_DELIVERY_TIMEOUT (renamed from DELIVERY_TIMEOUT)
        // 0x04 = MAX_CACHE_DURATION
        // 0x06 = SUBGROUP_DELIVERY_TIMEOUT (new in draft-18)
        // 0x08 = EXPIRES
        // 0x0A = FILL_TIMEOUT (new in draft-18, FETCH only)
        // 0x32 = NEW_GROUP_REQUEST
        0x02 | 0x04 | 0x06 | 0x08 | 0x0A | 0x32 => Some(ParamEncoding::Varint),
        // 0x10 = FORWARD, 0x20 = SUBSCRIBER_PRIORITY, 0x22 = GROUP_ORDER
        0x10 | 0x20 | 0x22 => Some(ParamEncoding::Uint8),
        // 0x03 = AUTHORIZATION_TOKEN
        // 0x09 = LARGEST_OBJECT (length-prefixed in draft-18; was bare two
        //         varints in draft-17)
        // 0x21 = SUBSCRIPTION_FILTER
        // 0x34 = TRACK_NAMESPACE_PREFIX (new in draft-18)
        0x03 | 0x09 | 0x21 | 0x34 => Some(ParamEncoding::LengthPrefixed),
        _ => None,
    }
}

/// Decode a count-prefixed list of parameters with delta-encoded types.
fn decode_parameters(buf: &mut impl Buf) -> Result<Vec<KeyValuePair>, CodecError> {
    let count = VarInt::decode(buf)?.into_inner() as usize;
    let mut params = Vec::with_capacity(count);
    let mut prev_key: u64 = 0;

    for _ in 0..count {
        let delta = VarInt::decode(buf)?.into_inner();
        let abs_key = prev_key + delta;
        prev_key = abs_key;

        let encoding = param_encoding(abs_key).ok_or(CodecError::InvalidField)?;

        let value = match encoding {
            ParamEncoding::Varint => {
                let v = VarInt::decode(buf)?;
                KvpValue::Varint(v)
            }
            ParamEncoding::Uint8 => {
                if buf.remaining() < 1 {
                    return Err(CodecError::UnexpectedEnd);
                }
                let byte = buf.get_u8();
                KvpValue::Varint(VarInt::from_u64(byte as u64).unwrap())
            }
            ParamEncoding::LengthPrefixed => {
                let len = VarInt::decode(buf)?.into_inner() as usize;
                let data = read_bytes(buf, len)?;
                KvpValue::Bytes(data)
            }
        };

        params.push(KeyValuePair { key: VarInt::from_u64(abs_key).unwrap(), value });
    }
    Ok(params)
}

/// Encode a count-prefixed list of parameters with delta-encoded types.
fn encode_parameters(params: &[KeyValuePair], buf: &mut impl BufMut) {
    VarInt::from_usize(params.len()).encode(buf);
    let mut prev_key: u64 = 0;

    for p in params {
        let abs_key = p.key.into_inner();
        let delta = abs_key - prev_key;
        prev_key = abs_key;
        VarInt::from_u64(delta).unwrap().encode(buf);

        let encoding = param_encoding(abs_key);
        match (&p.value, encoding) {
            (KvpValue::Varint(v), Some(ParamEncoding::Varint)) => {
                v.encode(buf);
            }
            (KvpValue::Varint(v), Some(ParamEncoding::Uint8)) => {
                buf.put_u8(v.into_inner() as u8);
            }
            (KvpValue::Bytes(b), Some(ParamEncoding::LengthPrefixed)) => {
                VarInt::from_usize(b.len()).encode(buf);
                buf.put_slice(b);
            }
            _ => {
                // Fallback: encode as KVP even/odd
                match &p.value {
                    KvpValue::Varint(v) => v.encode(buf),
                    KvpValue::Bytes(b) => {
                        VarInt::from_usize(b.len()).encode(buf);
                        buf.put_slice(b);
                    }
                }
            }
        }
    }
}

/// Decode delta-encoded KVPs with even/odd convention (for setup options
/// and track properties). Read until buffer is exhausted.
fn decode_kvp_delta(buf: &mut impl Buf) -> Result<Vec<KeyValuePair>, CodecError> {
    let mut pairs = Vec::new();
    let mut prev_key: u64 = 0;

    while buf.has_remaining() {
        let delta = VarInt::decode(buf)?.into_inner();
        let abs_key = prev_key + delta;
        prev_key = abs_key;

        let value = if abs_key % 2 == 0 {
            let v = VarInt::decode(buf)?;
            KvpValue::Varint(v)
        } else {
            let len = VarInt::decode(buf)?.into_inner() as usize;
            let data = read_bytes(buf, len)?;
            KvpValue::Bytes(data)
        };

        pairs.push(KeyValuePair { key: VarInt::from_u64(abs_key).unwrap(), value });
    }
    Ok(pairs)
}

/// Encode delta-encoded KVPs with even/odd convention.
fn encode_kvp_delta(pairs: &[KeyValuePair], buf: &mut impl BufMut) {
    let mut prev_key: u64 = 0;
    for p in pairs {
        let abs_key = p.key.into_inner();
        let delta = abs_key - prev_key;
        prev_key = abs_key;
        VarInt::from_u64(delta).unwrap().encode(buf);
        match &p.value {
            KvpValue::Varint(v) => v.encode(buf),
            KvpValue::Bytes(b) => {
                VarInt::from_usize(b.len()).encode(buf);
                buf.put_slice(b);
            }
        }
    }
}

// ============================================================
// Message Types
// ============================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum MessageType {
    RequestUpdate = 0x02,
    Subscribe = 0x03,
    SubscribeOk = 0x04,
    RequestError = 0x05,
    PublishNamespace = 0x06,
    /// REQUEST_OK (0x07). PUBLISH_OK is now an alias of this type.
    RequestOk = 0x07,
    Namespace = 0x08,
    PublishDone = 0x0B,
    TrackStatus = 0x0D,
    NamespaceDone = 0x0E,
    PublishBlocked = 0x0F,
    GoAway = 0x10,
    Fetch = 0x16,
    FetchOk = 0x18,
    Publish = 0x1D,
    /// SUBSCRIBE_NAMESPACE (renumbered to 0x50 in draft-18).
    SubscribeNamespace = 0x50,
    /// SUBSCRIBE_TRACKS (new message in draft-18).
    SubscribeTracks = 0x51,
    Setup = 0x2F00,
}

impl MessageType {
    pub fn from_id(id: u64) -> Option<Self> {
        match id {
            0x02 => Some(MessageType::RequestUpdate),
            0x03 => Some(MessageType::Subscribe),
            0x04 => Some(MessageType::SubscribeOk),
            0x05 => Some(MessageType::RequestError),
            0x06 => Some(MessageType::PublishNamespace),
            0x07 => Some(MessageType::RequestOk),
            0x08 => Some(MessageType::Namespace),
            0x0B => Some(MessageType::PublishDone),
            0x0D => Some(MessageType::TrackStatus),
            0x0E => Some(MessageType::NamespaceDone),
            0x0F => Some(MessageType::PublishBlocked),
            0x10 => Some(MessageType::GoAway),
            0x16 => Some(MessageType::Fetch),
            0x18 => Some(MessageType::FetchOk),
            0x1D => Some(MessageType::Publish),
            0x50 => Some(MessageType::SubscribeNamespace),
            0x51 => Some(MessageType::SubscribeTracks),
            0x2F00 => Some(MessageType::Setup),
            _ => None,
        }
    }

    pub fn id(&self) -> u64 {
        *self as u64
    }
}

// ============================================================
// Session Lifecycle Messages
// ============================================================

/// Unified SETUP (0x2F00).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setup {
    pub options: Vec<KeyValuePair>,
}

/// GOAWAY (0x10). Sent on the control stream (with `request_id`) or on an
/// individual request stream (without `request_id`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoAway {
    pub new_session_uri: Vec<u8>,
    pub timeout: VarInt,
    /// Present only when sent on the control stream — identifies the
    /// smallest peer Request ID that may not have been processed.
    pub request_id: Option<VarInt>,
}

// ============================================================
// Consolidated Response Messages
// ============================================================

/// REQUEST_OK (0x07). Used as a generic OK response and as the alias for
/// PUBLISH_OK / REQUEST_UPDATE_OK / TRACK_STATUS_OK / SUBSCRIBE_NAMESPACE_OK
/// / PUBLISH_NAMESPACE_OK.
///
/// `track_properties` is only populated for TRACK_STATUS_OK; for every
/// other shape it MUST be empty (length implicit from the message length).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestOk {
    pub parameters: Vec<KeyValuePair>,
    pub track_properties: Vec<KeyValuePair>,
}

/// Optional Redirect structure carried in REQUEST_ERROR with code 0x34.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirect {
    pub connect_uri: Vec<u8>,
    pub track_namespace: TrackNamespace,
    pub track_name: Vec<u8>,
}

/// REQUEST_ERROR (0x05). Adds an optional Redirect structure when
/// `error_code` is REDIRECT (0x34).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestError {
    pub error_code: VarInt,
    pub retry_interval: VarInt,
    pub reason_phrase: Vec<u8>,
    pub redirect: Option<Redirect>,
}

/// REQUEST_ERROR error codes that gain dedicated meaning in draft-18.
pub mod request_error_codes {
    /// New in draft-18: a Mandatory Track Property the receiver does not
    /// understand.
    pub const UNSUPPORTED_EXTENSION: u64 = 0x33;
    /// New in draft-18: response carries a [`super::Redirect`] structure.
    pub const REDIRECT: u64 = 0x34;
}

// ============================================================
// Subscribe Messages
// ============================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscribe {
    pub request_id: VarInt,
    pub track_namespace: TrackNamespace,
    pub track_name: Vec<u8>,
    pub parameters: Vec<KeyValuePair>,
}

/// SUBSCRIBE_OK (0x04).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeOk {
    pub track_alias: VarInt,
    pub parameters: Vec<KeyValuePair>,
    pub track_properties: Vec<KeyValuePair>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestUpdate {
    pub request_id: VarInt,
    pub parameters: Vec<KeyValuePair>,
}

// ============================================================
// Publish Messages
// ============================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publish {
    pub request_id: VarInt,
    pub track_namespace: TrackNamespace,
    pub track_name: Vec<u8>,
    pub track_alias: VarInt,
    pub parameters: Vec<KeyValuePair>,
    pub track_properties: Vec<KeyValuePair>,
}

/// PUBLISH_DONE (0x0B). Status codes 0x5/0x6 are swapped vs draft-17.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishDone {
    pub status_code: VarInt,
    pub stream_count: VarInt,
    pub reason_phrase: Vec<u8>,
}

/// Numeric values for the [`PublishDone::status_code`] field.
pub mod publish_done_codes {
    /// Draft-18: TOO_FAR_BEHIND is 0x05 (was 0x06 in draft-17).
    pub const TOO_FAR_BEHIND: u64 = 0x05;
    /// Draft-18: EXPIRED is 0x06 (was 0x05 in draft-17).
    pub const EXPIRED: u64 = 0x06;
}

// ============================================================
// Publish Namespace Messages
// ============================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishNamespace {
    pub request_id: VarInt,
    pub track_namespace: TrackNamespace,
    pub parameters: Vec<KeyValuePair>,
}

// ============================================================
// Namespace Messages
// ============================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Namespace {
    pub namespace_suffix: TrackNamespace,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceDone {
    pub namespace_suffix: TrackNamespace,
}

// ============================================================
// Subscribe Namespace / Tracks Messages
// ============================================================

/// SUBSCRIBE_NAMESPACE (0x50). Subscribes to NAMESPACE / NAMESPACE_DONE
/// advertisements for namespaces matching `namespace_prefix`. The
/// `subscribe_options` byte from draft-17 is removed; namespace subscriptions
/// only produce NAMESPACE / NAMESPACE_DONE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeNamespace {
    pub request_id: VarInt,
    pub namespace_prefix: TrackNamespace,
    pub parameters: Vec<KeyValuePair>,
}

/// SUBSCRIBE_TRACKS (0x51, new in draft-18). Subscribes to PUBLISH messages
/// for tracks whose namespace matches `namespace_prefix`. Carries the
/// FORWARD parameter (which previously lived on SUBSCRIBE_NAMESPACE).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeTracks {
    pub request_id: VarInt,
    pub namespace_prefix: TrackNamespace,
    pub parameters: Vec<KeyValuePair>,
}

// ============================================================
// Track Status Messages
// ============================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackStatus {
    pub request_id: VarInt,
    pub track_namespace: TrackNamespace,
    pub track_name: Vec<u8>,
    pub parameters: Vec<KeyValuePair>,
}

// ============================================================
// Fetch Messages
// ============================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum FetchType {
    Standalone = 1,
    RelativeJoining = 2,
    AbsoluteJoining = 3,
}

impl FetchType {
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            1 => Some(FetchType::Standalone),
            2 => Some(FetchType::RelativeJoining),
            3 => Some(FetchType::AbsoluteJoining),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetch {
    pub request_id: VarInt,
    pub fetch_type: FetchType,
    pub fetch_payload: FetchPayload,
    pub parameters: Vec<KeyValuePair>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchPayload {
    Standalone {
        track_namespace: TrackNamespace,
        track_name: Vec<u8>,
        start_group: VarInt,
        start_object: VarInt,
        end_group: VarInt,
        end_object: VarInt,
    },
    Joining {
        joining_request_id: VarInt,
        joining_start: VarInt,
    },
}

/// FETCH_OK (0x18). `end_of_track` is uint8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchOk {
    pub end_of_track: u8,
    pub end_group: VarInt,
    pub end_object: VarInt,
    pub parameters: Vec<KeyValuePair>,
    pub track_properties: Vec<KeyValuePair>,
}

// ============================================================
// Publish Blocked
// ============================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishBlocked {
    pub namespace_suffix: TrackNamespace,
    pub track_name: Vec<u8>,
}

// ============================================================
// Unified Message Enum
// ============================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlMessage {
    Setup(Setup),
    GoAway(GoAway),
    RequestOk(RequestOk),
    RequestError(RequestError),
    Subscribe(Subscribe),
    SubscribeOk(SubscribeOk),
    RequestUpdate(RequestUpdate),
    Publish(Publish),
    PublishDone(PublishDone),
    PublishNamespace(PublishNamespace),
    Namespace(Namespace),
    NamespaceDone(NamespaceDone),
    SubscribeNamespace(SubscribeNamespace),
    SubscribeTracks(SubscribeTracks),
    TrackStatus(TrackStatus),
    Fetch(Fetch),
    FetchOk(FetchOk),
    PublishBlocked(PublishBlocked),
}

impl ControlMessage {
    pub fn encode(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        let mut payload = Vec::with_capacity(256);
        self.encode_payload(&mut payload)?;

        if payload.len() > MAX_MESSAGE_LENGTH {
            return Err(CodecError::MessageTooLong(payload.len()));
        }

        let msg_type = self.message_type();
        VarInt::from_usize(msg_type.id() as usize).encode(buf);
        // Draft-18: 16-bit length (big-endian)
        buf.put_u16(payload.len() as u16);
        buf.put_slice(&payload);
        Ok(())
    }

    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let type_id = VarInt::decode(buf)?.into_inner();
        let msg_type =
            MessageType::from_id(type_id).ok_or(CodecError::UnknownMessageType(type_id))?;
        // Draft-18: 16-bit length (big-endian)
        if buf.remaining() < 2 {
            return Err(CodecError::UnexpectedEnd);
        }
        let payload_len = buf.get_u16() as usize;
        if buf.remaining() < payload_len {
            return Err(CodecError::UnexpectedEnd);
        }
        let payload_bytes = buf.copy_to_bytes(payload_len);
        let mut payload = &payload_bytes[..];
        Self::decode_payload(msg_type, &mut payload)
    }

    fn encode_payload(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        match self {
            ControlMessage::Setup(m) => {
                encode_kvp_delta(&m.options, buf);
            }
            ControlMessage::GoAway(m) => {
                if m.new_session_uri.len() > MAX_GOAWAY_URI_LENGTH {
                    return Err(CodecError::GoAwayUriTooLong);
                }
                VarInt::from_usize(m.new_session_uri.len()).encode(buf);
                buf.put_slice(&m.new_session_uri);
                m.timeout.encode(buf);
                if let Some(rid) = &m.request_id {
                    rid.encode(buf);
                }
            }
            ControlMessage::RequestOk(m) => {
                encode_parameters(&m.parameters, buf);
                encode_kvp_delta(&m.track_properties, buf);
            }
            ControlMessage::RequestError(m) => {
                if m.reason_phrase.len() > MAX_REASON_PHRASE_LENGTH {
                    return Err(CodecError::ReasonPhraseTooLong);
                }
                m.error_code.encode(buf);
                m.retry_interval.encode(buf);
                VarInt::from_usize(m.reason_phrase.len()).encode(buf);
                buf.put_slice(&m.reason_phrase);
                if let Some(r) = &m.redirect {
                    VarInt::from_usize(r.connect_uri.len()).encode(buf);
                    buf.put_slice(&r.connect_uri);
                    r.track_namespace.encode(buf);
                    VarInt::from_usize(r.track_name.len()).encode(buf);
                    buf.put_slice(&r.track_name);
                }
            }
            ControlMessage::Subscribe(m) => {
                m.request_id.encode(buf);
                m.track_namespace.encode(buf);
                VarInt::from_usize(m.track_name.len()).encode(buf);
                buf.put_slice(&m.track_name);
                encode_parameters(&m.parameters, buf);
            }
            ControlMessage::SubscribeOk(m) => {
                m.track_alias.encode(buf);
                encode_parameters(&m.parameters, buf);
                encode_kvp_delta(&m.track_properties, buf);
            }
            ControlMessage::RequestUpdate(m) => {
                m.request_id.encode(buf);
                encode_parameters(&m.parameters, buf);
            }
            ControlMessage::Publish(m) => {
                m.request_id.encode(buf);
                m.track_namespace.encode(buf);
                VarInt::from_usize(m.track_name.len()).encode(buf);
                buf.put_slice(&m.track_name);
                m.track_alias.encode(buf);
                encode_parameters(&m.parameters, buf);
                encode_kvp_delta(&m.track_properties, buf);
            }
            ControlMessage::PublishDone(m) => {
                if m.reason_phrase.len() > MAX_REASON_PHRASE_LENGTH {
                    return Err(CodecError::ReasonPhraseTooLong);
                }
                m.status_code.encode(buf);
                m.stream_count.encode(buf);
                VarInt::from_usize(m.reason_phrase.len()).encode(buf);
                buf.put_slice(&m.reason_phrase);
            }
            ControlMessage::PublishNamespace(m) => {
                m.request_id.encode(buf);
                m.track_namespace.encode(buf);
                encode_parameters(&m.parameters, buf);
            }
            ControlMessage::Namespace(m) => {
                m.namespace_suffix.encode(buf);
            }
            ControlMessage::NamespaceDone(m) => {
                m.namespace_suffix.encode(buf);
            }
            ControlMessage::SubscribeNamespace(m) => {
                m.request_id.encode(buf);
                m.namespace_prefix.encode(buf);
                encode_parameters(&m.parameters, buf);
            }
            ControlMessage::SubscribeTracks(m) => {
                m.request_id.encode(buf);
                m.namespace_prefix.encode(buf);
                encode_parameters(&m.parameters, buf);
            }
            ControlMessage::TrackStatus(m) => {
                m.request_id.encode(buf);
                m.track_namespace.encode(buf);
                VarInt::from_usize(m.track_name.len()).encode(buf);
                buf.put_slice(&m.track_name);
                encode_parameters(&m.parameters, buf);
            }
            ControlMessage::Fetch(m) => {
                m.request_id.encode(buf);
                VarInt::from_usize(m.fetch_type as usize).encode(buf);
                match &m.fetch_payload {
                    FetchPayload::Standalone {
                        track_namespace,
                        track_name,
                        start_group,
                        start_object,
                        end_group,
                        end_object,
                    } => {
                        track_namespace.encode(buf);
                        VarInt::from_usize(track_name.len()).encode(buf);
                        buf.put_slice(track_name);
                        start_group.encode(buf);
                        start_object.encode(buf);
                        end_group.encode(buf);
                        end_object.encode(buf);
                    }
                    FetchPayload::Joining { joining_request_id, joining_start } => {
                        joining_request_id.encode(buf);
                        joining_start.encode(buf);
                    }
                }
                encode_parameters(&m.parameters, buf);
            }
            ControlMessage::FetchOk(m) => {
                buf.put_u8(m.end_of_track);
                m.end_group.encode(buf);
                m.end_object.encode(buf);
                encode_parameters(&m.parameters, buf);
                encode_kvp_delta(&m.track_properties, buf);
            }
            ControlMessage::PublishBlocked(m) => {
                m.namespace_suffix.encode(buf);
                VarInt::from_usize(m.track_name.len()).encode(buf);
                buf.put_slice(&m.track_name);
            }
        }
        Ok(())
    }

    fn decode_payload(msg_type: MessageType, buf: &mut impl Buf) -> Result<Self, CodecError> {
        match msg_type {
            MessageType::Setup => {
                let options = decode_kvp_delta(buf)?;
                Ok(ControlMessage::Setup(Setup { options }))
            }
            MessageType::GoAway => {
                let uri_len = VarInt::decode(buf)?.into_inner() as usize;
                let uri = read_bytes(buf, uri_len)?;
                let timeout = VarInt::decode(buf)?;
                let request_id =
                    if buf.has_remaining() { Some(VarInt::decode(buf)?) } else { None };
                Ok(ControlMessage::GoAway(GoAway { new_session_uri: uri, timeout, request_id }))
            }
            MessageType::RequestOk => {
                let parameters = decode_parameters(buf)?;
                let track_properties = decode_kvp_delta(buf)?;
                Ok(ControlMessage::RequestOk(RequestOk { parameters, track_properties }))
            }
            MessageType::RequestError => {
                let error_code = VarInt::decode(buf)?;
                let retry_interval = VarInt::decode(buf)?;
                let reason_len = VarInt::decode(buf)?.into_inner() as usize;
                let reason_phrase = read_bytes(buf, reason_len)?;
                let redirect = if error_code.into_inner() == request_error_codes::REDIRECT {
                    let uri_len = VarInt::decode(buf)?.into_inner() as usize;
                    let connect_uri = read_bytes(buf, uri_len)?;
                    let track_namespace = TrackNamespace::decode_allow_empty(buf)?;
                    let name_len = VarInt::decode(buf)?.into_inner() as usize;
                    let track_name = read_bytes(buf, name_len)?;
                    Some(Redirect { connect_uri, track_namespace, track_name })
                } else {
                    None
                };
                Ok(ControlMessage::RequestError(RequestError {
                    error_code,
                    retry_interval,
                    reason_phrase,
                    redirect,
                }))
            }
            MessageType::Subscribe => {
                let request_id = VarInt::decode(buf)?;
                let track_namespace = TrackNamespace::decode(buf)?;
                let tn_len = VarInt::decode(buf)?.into_inner() as usize;
                let track_name = read_bytes(buf, tn_len)?;
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::Subscribe(Subscribe {
                    request_id,
                    track_namespace,
                    track_name,
                    parameters,
                }))
            }
            MessageType::SubscribeOk => {
                let track_alias = VarInt::decode(buf)?;
                let parameters = decode_parameters(buf)?;
                let track_properties = decode_kvp_delta(buf)?;
                Ok(ControlMessage::SubscribeOk(SubscribeOk {
                    track_alias,
                    parameters,
                    track_properties,
                }))
            }
            MessageType::RequestUpdate => {
                let request_id = VarInt::decode(buf)?;
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::RequestUpdate(RequestUpdate { request_id, parameters }))
            }
            MessageType::Publish => {
                let request_id = VarInt::decode(buf)?;
                let track_namespace = TrackNamespace::decode(buf)?;
                let tn_len = VarInt::decode(buf)?.into_inner() as usize;
                let track_name = read_bytes(buf, tn_len)?;
                let track_alias = VarInt::decode(buf)?;
                let parameters = decode_parameters(buf)?;
                let track_properties = decode_kvp_delta(buf)?;
                Ok(ControlMessage::Publish(Publish {
                    request_id,
                    track_namespace,
                    track_name,
                    track_alias,
                    parameters,
                    track_properties,
                }))
            }
            MessageType::PublishDone => {
                let status_code = VarInt::decode(buf)?;
                let stream_count = VarInt::decode(buf)?;
                let reason_len = VarInt::decode(buf)?.into_inner() as usize;
                let reason_phrase = read_bytes(buf, reason_len)?;
                Ok(ControlMessage::PublishDone(PublishDone {
                    status_code,
                    stream_count,
                    reason_phrase,
                }))
            }
            MessageType::PublishNamespace => {
                let request_id = VarInt::decode(buf)?;
                let track_namespace = TrackNamespace::decode(buf)?;
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::PublishNamespace(PublishNamespace {
                    request_id,
                    track_namespace,
                    parameters,
                }))
            }
            MessageType::Namespace => {
                let namespace_suffix = TrackNamespace::decode_allow_empty(buf)?;
                Ok(ControlMessage::Namespace(Namespace { namespace_suffix }))
            }
            MessageType::NamespaceDone => {
                let namespace_suffix = TrackNamespace::decode_allow_empty(buf)?;
                Ok(ControlMessage::NamespaceDone(NamespaceDone { namespace_suffix }))
            }
            MessageType::SubscribeNamespace => {
                let request_id = VarInt::decode(buf)?;
                let namespace_prefix = TrackNamespace::decode_allow_empty(buf)?;
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::SubscribeNamespace(SubscribeNamespace {
                    request_id,
                    namespace_prefix,
                    parameters,
                }))
            }
            MessageType::SubscribeTracks => {
                let request_id = VarInt::decode(buf)?;
                let namespace_prefix = TrackNamespace::decode_allow_empty(buf)?;
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::SubscribeTracks(SubscribeTracks {
                    request_id,
                    namespace_prefix,
                    parameters,
                }))
            }
            MessageType::TrackStatus => {
                let request_id = VarInt::decode(buf)?;
                let track_namespace = TrackNamespace::decode(buf)?;
                let tn_len = VarInt::decode(buf)?.into_inner() as usize;
                let track_name = read_bytes(buf, tn_len)?;
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::TrackStatus(TrackStatus {
                    request_id,
                    track_namespace,
                    track_name,
                    parameters,
                }))
            }
            MessageType::Fetch => {
                let request_id = VarInt::decode(buf)?;
                let fetch_type_val = VarInt::decode(buf)?.into_inner();
                let fetch_type =
                    FetchType::from_u64(fetch_type_val).ok_or(CodecError::InvalidField)?;
                let fetch_payload = match fetch_type {
                    FetchType::Standalone => {
                        let track_namespace = TrackNamespace::decode(buf)?;
                        let tn_len = VarInt::decode(buf)?.into_inner() as usize;
                        let track_name = read_bytes(buf, tn_len)?;
                        let start_group = VarInt::decode(buf)?;
                        let start_object = VarInt::decode(buf)?;
                        let end_group = VarInt::decode(buf)?;
                        let end_object = VarInt::decode(buf)?;
                        FetchPayload::Standalone {
                            track_namespace,
                            track_name,
                            start_group,
                            start_object,
                            end_group,
                            end_object,
                        }
                    }
                    FetchType::RelativeJoining | FetchType::AbsoluteJoining => {
                        let joining_request_id = VarInt::decode(buf)?;
                        let joining_start = VarInt::decode(buf)?;
                        FetchPayload::Joining { joining_request_id, joining_start }
                    }
                };
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::Fetch(Fetch {
                    request_id,
                    fetch_type,
                    fetch_payload,
                    parameters,
                }))
            }
            MessageType::FetchOk => {
                if buf.remaining() < 1 {
                    return Err(CodecError::UnexpectedEnd);
                }
                let end_of_track = buf.get_u8();
                let end_group = VarInt::decode(buf)?;
                let end_object = VarInt::decode(buf)?;
                let parameters = decode_parameters(buf)?;
                let track_properties = decode_kvp_delta(buf)?;
                Ok(ControlMessage::FetchOk(FetchOk {
                    end_of_track,
                    end_group,
                    end_object,
                    parameters,
                    track_properties,
                }))
            }
            MessageType::PublishBlocked => {
                let namespace_suffix = TrackNamespace::decode_allow_empty(buf)?;
                let tn_len = VarInt::decode(buf)?.into_inner() as usize;
                let track_name = read_bytes(buf, tn_len)?;
                Ok(ControlMessage::PublishBlocked(PublishBlocked { namespace_suffix, track_name }))
            }
        }
    }

    pub fn message_type(&self) -> MessageType {
        match self {
            ControlMessage::Setup(_) => MessageType::Setup,
            ControlMessage::GoAway(_) => MessageType::GoAway,
            ControlMessage::RequestOk(_) => MessageType::RequestOk,
            ControlMessage::RequestError(_) => MessageType::RequestError,
            ControlMessage::Subscribe(_) => MessageType::Subscribe,
            ControlMessage::SubscribeOk(_) => MessageType::SubscribeOk,
            ControlMessage::RequestUpdate(_) => MessageType::RequestUpdate,
            ControlMessage::Publish(_) => MessageType::Publish,
            ControlMessage::PublishDone(_) => MessageType::PublishDone,
            ControlMessage::PublishNamespace(_) => MessageType::PublishNamespace,
            ControlMessage::Namespace(_) => MessageType::Namespace,
            ControlMessage::NamespaceDone(_) => MessageType::NamespaceDone,
            ControlMessage::SubscribeNamespace(_) => MessageType::SubscribeNamespace,
            ControlMessage::SubscribeTracks(_) => MessageType::SubscribeTracks,
            ControlMessage::TrackStatus(_) => MessageType::TrackStatus,
            ControlMessage::Fetch(_) => MessageType::Fetch,
            ControlMessage::FetchOk(_) => MessageType::FetchOk,
            ControlMessage::PublishBlocked(_) => MessageType::PublishBlocked,
        }
    }
}

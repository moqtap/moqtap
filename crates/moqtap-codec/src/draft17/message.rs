//! Draft-17 control message encoding and decoding.
//!
//! Key differences from draft-16:
//! - Framing: Type (varint) + Length (16-bit fixed) + Payload.
//! - Unified SETUP (0x2F00) with delta-encoded KVP options (even/odd).
//! - Parameters: count-prefixed, delta-encoded types, type-specific value encoding.
//! - RequestOk/RequestError/PublishOk/PublishDone/FetchOk: no request_id.
//! - Request messages gain required_request_id_delta.
//! - New: PublishBlocked. FetchType gains AbsoluteJoining.
//! - SubscribeOk/Publish/FetchOk gain track_properties after parameters.
//! - Removed: ClientSetup, ServerSetup, MaxRequestId, RequestsBlocked, Unsubscribe,
//!   PublishNamespaceDone, PublishNamespaceCancel, FetchCancel.

pub use crate::error::{
    CodecError, MAX_GOAWAY_URI_LENGTH, MAX_MESSAGE_LENGTH, MAX_NAMESPACE_TUPLE_SIZE,
    MAX_REASON_PHRASE_LENGTH,
};
use crate::kvp::{KeyValuePair, KvpValue};
use crate::types::*;
use crate::varint::VarInt;
use bytes::{Buf, BufMut};

// ============================================================
// Parameter encoding helpers for draft-17
// ============================================================

/// How a parameter value is encoded on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParamEncoding {
    /// Bare varint.
    Varint,
    /// Single byte (uint8).
    Uint8,
    /// Two consecutive varints (group, object).
    Location,
    /// Length-prefixed bytes.
    LengthPrefixed,
}

fn param_encoding(key: u64) -> Option<ParamEncoding> {
    match key {
        0x02 | 0x04 | 0x08 | 0x32 => Some(ParamEncoding::Varint),
        0x10 | 0x20 | 0x22 => Some(ParamEncoding::Uint8),
        0x09 => Some(ParamEncoding::Location),
        0x03 | 0x21 => Some(ParamEncoding::LengthPrefixed),
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
            ParamEncoding::Location => {
                let group = VarInt::decode(buf)?;
                let object = VarInt::decode(buf)?;
                let mut encoded = Vec::new();
                group.encode(&mut encoded);
                object.encode(&mut encoded);
                KvpValue::Bytes(encoded)
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
            (KvpValue::Bytes(b), Some(ParamEncoding::Location)) => {
                buf.put_slice(b);
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
    RequestOk = 0x07,
    Namespace = 0x08,
    PublishDone = 0x0B,
    TrackStatus = 0x0D,
    NamespaceDone = 0x0E,
    PublishBlocked = 0x0F,
    GoAway = 0x10,
    SubscribeNamespace = 0x11,
    Fetch = 0x16,
    FetchOk = 0x18,
    Publish = 0x1D,
    PublishOk = 0x1E,
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
            0x11 => Some(MessageType::SubscribeNamespace),
            0x16 => Some(MessageType::Fetch),
            0x18 => Some(MessageType::FetchOk),
            0x1D => Some(MessageType::Publish),
            0x1E => Some(MessageType::PublishOk),
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

/// Unified SETUP (0x2F00). Replaces ClientSetup/ServerSetup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setup {
    pub options: Vec<KeyValuePair>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoAway {
    pub new_session_uri: Vec<u8>,
    pub timeout: VarInt,
}

// ============================================================
// Consolidated Response Messages
// ============================================================

/// REQUEST_OK (0x07). No request_id in draft-17.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestOk {
    pub parameters: Vec<KeyValuePair>,
}

/// REQUEST_ERROR (0x05). No request_id in draft-17.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestError {
    pub error_code: VarInt,
    pub retry_interval: VarInt,
    pub reason_phrase: Vec<u8>,
}

// ============================================================
// Subscribe Messages
// ============================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscribe {
    pub request_id: VarInt,
    pub required_request_id_delta: VarInt,
    pub track_namespace: TrackNamespace,
    pub track_name: Vec<u8>,
    pub parameters: Vec<KeyValuePair>,
}

/// SUBSCRIBE_OK (0x04). No request_id in draft-17. Gains track_properties.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeOk {
    pub track_alias: VarInt,
    pub parameters: Vec<KeyValuePair>,
    pub track_properties: Vec<KeyValuePair>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestUpdate {
    pub request_id: VarInt,
    pub required_request_id_delta: VarInt,
    pub parameters: Vec<KeyValuePair>,
}

// ============================================================
// Publish Messages
// ============================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publish {
    pub request_id: VarInt,
    pub required_request_id_delta: VarInt,
    pub track_namespace: TrackNamespace,
    pub track_name: Vec<u8>,
    pub track_alias: VarInt,
    pub parameters: Vec<KeyValuePair>,
    pub track_properties: Vec<KeyValuePair>,
}

/// PUBLISH_OK (0x1E). No request_id in draft-17.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishOk {
    pub parameters: Vec<KeyValuePair>,
}

/// PUBLISH_DONE (0x0B). No request_id in draft-17.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishDone {
    pub status_code: VarInt,
    pub stream_count: VarInt,
    pub reason_phrase: Vec<u8>,
}

// ============================================================
// Publish Namespace Messages
// ============================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishNamespace {
    pub request_id: VarInt,
    pub required_request_id_delta: VarInt,
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
// Subscribe Namespace Messages
// ============================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeNamespace {
    pub request_id: VarInt,
    pub required_request_id_delta: VarInt,
    pub namespace_prefix: TrackNamespace,
    pub subscribe_options: VarInt,
    pub parameters: Vec<KeyValuePair>,
}

// ============================================================
// Track Status Messages
// ============================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackStatus {
    pub request_id: VarInt,
    pub required_request_id_delta: VarInt,
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
    pub required_request_id_delta: VarInt,
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

/// FETCH_OK (0x18). No request_id in draft-17. end_of_track is uint8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchOk {
    pub end_of_track: u8,
    pub end_group: VarInt,
    pub end_object: VarInt,
    pub parameters: Vec<KeyValuePair>,
    pub track_properties: Vec<KeyValuePair>,
}

// ============================================================
// Publish Blocked (new in draft-17)
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
    PublishOk(PublishOk),
    PublishDone(PublishDone),
    PublishNamespace(PublishNamespace),
    Namespace(Namespace),
    NamespaceDone(NamespaceDone),
    SubscribeNamespace(SubscribeNamespace),
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
        // Draft-17: 16-bit length (big-endian)
        buf.put_u16(payload.len() as u16);
        buf.put_slice(&payload);
        Ok(())
    }

    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let type_id = VarInt::decode(buf)?.into_inner();
        let msg_type =
            MessageType::from_id(type_id).ok_or(CodecError::UnknownMessageType(type_id))?;
        // Draft-17: 16-bit length (big-endian)
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
            }
            ControlMessage::RequestOk(m) => {
                encode_parameters(&m.parameters, buf);
            }
            ControlMessage::RequestError(m) => {
                if m.reason_phrase.len() > MAX_REASON_PHRASE_LENGTH {
                    return Err(CodecError::ReasonPhraseTooLong);
                }
                m.error_code.encode(buf);
                m.retry_interval.encode(buf);
                VarInt::from_usize(m.reason_phrase.len()).encode(buf);
                buf.put_slice(&m.reason_phrase);
            }
            ControlMessage::Subscribe(m) => {
                m.request_id.encode(buf);
                m.required_request_id_delta.encode(buf);
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
                m.required_request_id_delta.encode(buf);
                encode_parameters(&m.parameters, buf);
            }
            ControlMessage::Publish(m) => {
                m.request_id.encode(buf);
                m.required_request_id_delta.encode(buf);
                m.track_namespace.encode(buf);
                VarInt::from_usize(m.track_name.len()).encode(buf);
                buf.put_slice(&m.track_name);
                m.track_alias.encode(buf);
                encode_parameters(&m.parameters, buf);
                encode_kvp_delta(&m.track_properties, buf);
            }
            ControlMessage::PublishOk(m) => {
                encode_parameters(&m.parameters, buf);
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
                m.required_request_id_delta.encode(buf);
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
                m.required_request_id_delta.encode(buf);
                m.namespace_prefix.encode(buf);
                m.subscribe_options.encode(buf);
                encode_parameters(&m.parameters, buf);
            }
            ControlMessage::TrackStatus(m) => {
                m.request_id.encode(buf);
                m.required_request_id_delta.encode(buf);
                m.track_namespace.encode(buf);
                VarInt::from_usize(m.track_name.len()).encode(buf);
                buf.put_slice(&m.track_name);
                encode_parameters(&m.parameters, buf);
            }
            ControlMessage::Fetch(m) => {
                m.request_id.encode(buf);
                m.required_request_id_delta.encode(buf);
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
                Ok(ControlMessage::GoAway(GoAway { new_session_uri: uri, timeout }))
            }
            MessageType::RequestOk => {
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::RequestOk(RequestOk { parameters }))
            }
            MessageType::RequestError => {
                let error_code = VarInt::decode(buf)?;
                let retry_interval = VarInt::decode(buf)?;
                let reason_len = VarInt::decode(buf)?.into_inner() as usize;
                let reason_phrase = read_bytes(buf, reason_len)?;
                Ok(ControlMessage::RequestError(RequestError {
                    error_code,
                    retry_interval,
                    reason_phrase,
                }))
            }
            MessageType::Subscribe => {
                let request_id = VarInt::decode(buf)?;
                let required_request_id_delta = VarInt::decode(buf)?;
                let track_namespace = TrackNamespace::decode(buf)?;
                let tn_len = VarInt::decode(buf)?.into_inner() as usize;
                let track_name = read_bytes(buf, tn_len)?;
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::Subscribe(Subscribe {
                    request_id,
                    required_request_id_delta,
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
                let required_request_id_delta = VarInt::decode(buf)?;
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::RequestUpdate(RequestUpdate {
                    request_id,
                    required_request_id_delta,
                    parameters,
                }))
            }
            MessageType::Publish => {
                let request_id = VarInt::decode(buf)?;
                let required_request_id_delta = VarInt::decode(buf)?;
                let track_namespace = TrackNamespace::decode(buf)?;
                let tn_len = VarInt::decode(buf)?.into_inner() as usize;
                let track_name = read_bytes(buf, tn_len)?;
                let track_alias = VarInt::decode(buf)?;
                let parameters = decode_parameters(buf)?;
                let track_properties = decode_kvp_delta(buf)?;
                Ok(ControlMessage::Publish(Publish {
                    request_id,
                    required_request_id_delta,
                    track_namespace,
                    track_name,
                    track_alias,
                    parameters,
                    track_properties,
                }))
            }
            MessageType::PublishOk => {
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::PublishOk(PublishOk { parameters }))
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
                let required_request_id_delta = VarInt::decode(buf)?;
                let track_namespace = TrackNamespace::decode(buf)?;
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::PublishNamespace(PublishNamespace {
                    request_id,
                    required_request_id_delta,
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
                let required_request_id_delta = VarInt::decode(buf)?;
                let namespace_prefix = TrackNamespace::decode_allow_empty(buf)?;
                let subscribe_options = VarInt::decode(buf)?;
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::SubscribeNamespace(SubscribeNamespace {
                    request_id,
                    required_request_id_delta,
                    namespace_prefix,
                    subscribe_options,
                    parameters,
                }))
            }
            MessageType::TrackStatus => {
                let request_id = VarInt::decode(buf)?;
                let required_request_id_delta = VarInt::decode(buf)?;
                let track_namespace = TrackNamespace::decode(buf)?;
                let tn_len = VarInt::decode(buf)?.into_inner() as usize;
                let track_name = read_bytes(buf, tn_len)?;
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::TrackStatus(TrackStatus {
                    request_id,
                    required_request_id_delta,
                    track_namespace,
                    track_name,
                    parameters,
                }))
            }
            MessageType::Fetch => {
                let request_id = VarInt::decode(buf)?;
                let required_request_id_delta = VarInt::decode(buf)?;
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
                    required_request_id_delta,
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
            ControlMessage::PublishOk(_) => MessageType::PublishOk,
            ControlMessage::PublishDone(_) => MessageType::PublishDone,
            ControlMessage::PublishNamespace(_) => MessageType::PublishNamespace,
            ControlMessage::Namespace(_) => MessageType::Namespace,
            ControlMessage::NamespaceDone(_) => MessageType::NamespaceDone,
            ControlMessage::SubscribeNamespace(_) => MessageType::SubscribeNamespace,
            ControlMessage::TrackStatus(_) => MessageType::TrackStatus,
            ControlMessage::Fetch(_) => MessageType::Fetch,
            ControlMessage::FetchOk(_) => MessageType::FetchOk,
            ControlMessage::PublishBlocked(_) => MessageType::PublishBlocked,
        }
    }
}

//! Draft-16 control message encoding and decoding.
//!
//! Key changes from draft-15:
//! - SubscribeUpdate → RequestUpdate, field renamed to existing_request_id
//! - New: Namespace (0x08), NamespaceDone (0x0e) — namespace_suffix only
//! - Removed: UnsubscribeNamespace (0x14)
//! - RequestError gains retry_interval field
//! - SubscribeNamespace gains subscribe_options varint
//! - PublishNamespaceDone simplifies to just request_id
//! - Framing: type_id(vi) + payload_length(16) + payload (same as draft-15)

pub use crate::error::{
    CodecError, MAX_GOAWAY_URI_LENGTH, MAX_MESSAGE_LENGTH, MAX_NAMESPACE_TUPLE_SIZE,
    MAX_REASON_PHRASE_LENGTH,
};
use crate::kvp::KeyValuePair;
use crate::types::*;
use crate::varint::VarInt;
use bytes::{Buf, BufMut};

/// Decode any remaining bytes in `buf` as a sequence of KVPs until `buf`
/// is empty. Used for draft-16 `track_extensions` which has no explicit
/// count — extensions simply fill the rest of the control-message payload.
fn decode_track_extensions(buf: &mut impl Buf) -> Result<Vec<KeyValuePair>, CodecError> {
    let mut out = Vec::new();
    while buf.has_remaining() {
        out.push(KeyValuePair::decode(buf)?);
    }
    Ok(out)
}

/// Encode `track_extensions` (each KVP back-to-back, no count prefix).
fn encode_track_extensions(exts: &[KeyValuePair], buf: &mut impl BufMut) {
    for kvp in exts {
        kvp.encode(buf);
    }
}

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
    PublishNamespaceDone = 0x09,
    Unsubscribe = 0x0A,
    PublishDone = 0x0B,
    PublishNamespaceCancel = 0x0C,
    TrackStatus = 0x0D,
    NamespaceDone = 0x0E,
    GoAway = 0x10,
    SubscribeNamespace = 0x11,
    MaxRequestId = 0x15,
    Fetch = 0x16,
    FetchCancel = 0x17,
    FetchOk = 0x18,
    RequestsBlocked = 0x1A,
    Publish = 0x1D,
    PublishOk = 0x1E,
    ClientSetup = 0x20,
    ServerSetup = 0x21,
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
            0x09 => Some(MessageType::PublishNamespaceDone),
            0x0A => Some(MessageType::Unsubscribe),
            0x0B => Some(MessageType::PublishDone),
            0x0C => Some(MessageType::PublishNamespaceCancel),
            0x0D => Some(MessageType::TrackStatus),
            0x0E => Some(MessageType::NamespaceDone),
            0x10 => Some(MessageType::GoAway),
            0x11 => Some(MessageType::SubscribeNamespace),
            0x15 => Some(MessageType::MaxRequestId),
            0x16 => Some(MessageType::Fetch),
            0x17 => Some(MessageType::FetchCancel),
            0x18 => Some(MessageType::FetchOk),
            0x1A => Some(MessageType::RequestsBlocked),
            0x1D => Some(MessageType::Publish),
            0x1E => Some(MessageType::PublishOk),
            0x20 => Some(MessageType::ClientSetup),
            0x21 => Some(MessageType::ServerSetup),
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSetup {
    pub parameters: Vec<KeyValuePair>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerSetup {
    pub parameters: Vec<KeyValuePair>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoAway {
    pub new_session_uri: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaxRequestId {
    pub request_id: VarInt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestsBlocked {
    pub maximum_request_id: VarInt,
}

// ============================================================
// Consolidated Response Messages
// ============================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestOk {
    pub request_id: VarInt,
    pub parameters: Vec<KeyValuePair>,
}

/// REQUEST_ERROR (0x05). Draft-16 adds retry_interval field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestError {
    pub request_id: VarInt,
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
    pub track_namespace: TrackNamespace,
    pub track_name: Vec<u8>,
    pub parameters: Vec<KeyValuePair>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeOk {
    pub request_id: VarInt,
    pub track_alias: VarInt,
    pub parameters: Vec<KeyValuePair>,
    /// Track extensions: KVPs that follow `parameters` and continue until
    /// the end of the control-message payload. Empty if none.
    pub track_extensions: Vec<KeyValuePair>,
}

/// REQUEST_UPDATE (0x02). Renamed from SubscribeUpdate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestUpdate {
    pub request_id: VarInt,
    pub existing_request_id: VarInt,
    pub parameters: Vec<KeyValuePair>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unsubscribe {
    pub request_id: VarInt,
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
    /// Track extensions: KVPs that follow `parameters` and continue until
    /// the end of the control-message payload. Empty if none.
    pub track_extensions: Vec<KeyValuePair>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishOk {
    pub request_id: VarInt,
    pub parameters: Vec<KeyValuePair>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishDone {
    pub request_id: VarInt,
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
    pub track_namespace: TrackNamespace,
    pub parameters: Vec<KeyValuePair>,
}

/// PUBLISH_NAMESPACE_DONE (0x09). Draft-16: just request_id (was namespace in d15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishNamespaceDone {
    pub request_id: VarInt,
}

/// PUBLISH_NAMESPACE_CANCEL (0x0C). Draft-16: request_id + error_code + reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishNamespaceCancel {
    pub request_id: VarInt,
    pub error_code: VarInt,
    pub reason_phrase: Vec<u8>,
}

// ============================================================
// Namespace Messages (new in draft-16)
// ============================================================

/// NAMESPACE (0x08). Carries namespace_suffix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Namespace {
    pub namespace_suffix: TrackNamespace,
}

/// NAMESPACE_DONE (0x0E). Carries namespace_suffix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceDone {
    pub namespace_suffix: TrackNamespace,
}

// ============================================================
// Subscribe Namespace Messages
// ============================================================

/// SUBSCRIBE_NAMESPACE (0x11). Draft-16: gains subscribe_options varint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeNamespace {
    pub request_id: VarInt,
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
    /// Standalone fetch with explicit track + range.
    Standalone = 1,
    /// Joining fetch using a relative group offset.
    RelativeJoining = 2,
    /// Joining fetch using an absolute group.
    AbsoluteJoining = 3,
}

impl FetchType {
    /// Map a varint value to a FetchType, returning None for unknown values.
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchOk {
    pub request_id: VarInt,
    pub end_of_track: VarInt,
    pub end_group: VarInt,
    pub end_object: VarInt,
    pub parameters: Vec<KeyValuePair>,
    /// Track extensions: KVPs that follow `parameters` and continue until
    /// the end of the control-message payload. Empty if none.
    pub track_extensions: Vec<KeyValuePair>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchCancel {
    pub request_id: VarInt,
}

// ============================================================
// Unified Message Enum
// ============================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlMessage {
    ClientSetup(ClientSetup),
    ServerSetup(ServerSetup),
    GoAway(GoAway),
    MaxRequestId(MaxRequestId),
    RequestsBlocked(RequestsBlocked),
    RequestOk(RequestOk),
    RequestError(RequestError),
    Subscribe(Subscribe),
    SubscribeOk(SubscribeOk),
    RequestUpdate(RequestUpdate),
    Unsubscribe(Unsubscribe),
    Publish(Publish),
    PublishOk(PublishOk),
    PublishDone(PublishDone),
    PublishNamespace(PublishNamespace),
    PublishNamespaceDone(PublishNamespaceDone),
    PublishNamespaceCancel(PublishNamespaceCancel),
    Namespace(Namespace),
    NamespaceDone(NamespaceDone),
    SubscribeNamespace(SubscribeNamespace),
    TrackStatus(TrackStatus),
    Fetch(Fetch),
    FetchOk(FetchOk),
    FetchCancel(FetchCancel),
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
        // Draft-16: 16-bit length (big-endian)
        buf.put_u16(payload.len() as u16);
        buf.put_slice(&payload);
        Ok(())
    }

    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let type_id = VarInt::decode(buf)?.into_inner();
        let msg_type =
            MessageType::from_id(type_id).ok_or(CodecError::UnknownMessageType(type_id))?;
        // Draft-16: 16-bit length (big-endian)
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
            ControlMessage::ClientSetup(m) => {
                KeyValuePair::encode_list(&m.parameters, buf);
            }
            ControlMessage::ServerSetup(m) => {
                KeyValuePair::encode_list(&m.parameters, buf);
            }
            ControlMessage::GoAway(m) => {
                if m.new_session_uri.len() > MAX_GOAWAY_URI_LENGTH {
                    return Err(CodecError::GoAwayUriTooLong);
                }
                VarInt::from_usize(m.new_session_uri.len()).encode(buf);
                buf.put_slice(&m.new_session_uri);
            }
            ControlMessage::MaxRequestId(m) => {
                m.request_id.encode(buf);
            }
            ControlMessage::RequestsBlocked(m) => {
                m.maximum_request_id.encode(buf);
            }
            ControlMessage::RequestOk(m) => {
                m.request_id.encode(buf);
                KeyValuePair::encode_list(&m.parameters, buf);
            }
            ControlMessage::RequestError(m) => {
                if m.reason_phrase.len() > MAX_REASON_PHRASE_LENGTH {
                    return Err(CodecError::ReasonPhraseTooLong);
                }
                m.request_id.encode(buf);
                m.error_code.encode(buf);
                m.retry_interval.encode(buf);
                VarInt::from_usize(m.reason_phrase.len()).encode(buf);
                buf.put_slice(&m.reason_phrase);
            }
            ControlMessage::Subscribe(m) => {
                m.request_id.encode(buf);
                m.track_namespace.encode(buf);
                VarInt::from_usize(m.track_name.len()).encode(buf);
                buf.put_slice(&m.track_name);
                KeyValuePair::encode_list(&m.parameters, buf);
            }
            ControlMessage::SubscribeOk(m) => {
                m.request_id.encode(buf);
                m.track_alias.encode(buf);
                KeyValuePair::encode_list(&m.parameters, buf);
                encode_track_extensions(&m.track_extensions, buf);
            }
            ControlMessage::RequestUpdate(m) => {
                m.request_id.encode(buf);
                m.existing_request_id.encode(buf);
                KeyValuePair::encode_list(&m.parameters, buf);
            }
            ControlMessage::Unsubscribe(m) => {
                m.request_id.encode(buf);
            }
            ControlMessage::Publish(m) => {
                m.request_id.encode(buf);
                m.track_namespace.encode(buf);
                VarInt::from_usize(m.track_name.len()).encode(buf);
                buf.put_slice(&m.track_name);
                m.track_alias.encode(buf);
                KeyValuePair::encode_list(&m.parameters, buf);
                encode_track_extensions(&m.track_extensions, buf);
            }
            ControlMessage::PublishOk(m) => {
                m.request_id.encode(buf);
                KeyValuePair::encode_list(&m.parameters, buf);
            }
            ControlMessage::PublishDone(m) => {
                if m.reason_phrase.len() > MAX_REASON_PHRASE_LENGTH {
                    return Err(CodecError::ReasonPhraseTooLong);
                }
                m.request_id.encode(buf);
                m.status_code.encode(buf);
                m.stream_count.encode(buf);
                VarInt::from_usize(m.reason_phrase.len()).encode(buf);
                buf.put_slice(&m.reason_phrase);
            }
            ControlMessage::PublishNamespace(m) => {
                m.request_id.encode(buf);
                m.track_namespace.encode(buf);
                KeyValuePair::encode_list(&m.parameters, buf);
            }
            ControlMessage::PublishNamespaceDone(m) => {
                m.request_id.encode(buf);
            }
            ControlMessage::PublishNamespaceCancel(m) => {
                if m.reason_phrase.len() > MAX_REASON_PHRASE_LENGTH {
                    return Err(CodecError::ReasonPhraseTooLong);
                }
                m.request_id.encode(buf);
                m.error_code.encode(buf);
                VarInt::from_usize(m.reason_phrase.len()).encode(buf);
                buf.put_slice(&m.reason_phrase);
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
                m.subscribe_options.encode(buf);
                KeyValuePair::encode_list(&m.parameters, buf);
            }
            ControlMessage::TrackStatus(m) => {
                m.request_id.encode(buf);
                m.track_namespace.encode(buf);
                VarInt::from_usize(m.track_name.len()).encode(buf);
                buf.put_slice(&m.track_name);
                KeyValuePair::encode_list(&m.parameters, buf);
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
                KeyValuePair::encode_list(&m.parameters, buf);
            }
            ControlMessage::FetchOk(m) => {
                m.request_id.encode(buf);
                m.end_of_track.encode(buf);
                m.end_group.encode(buf);
                m.end_object.encode(buf);
                KeyValuePair::encode_list(&m.parameters, buf);
                encode_track_extensions(&m.track_extensions, buf);
            }
            ControlMessage::FetchCancel(m) => {
                m.request_id.encode(buf);
            }
        }
        Ok(())
    }

    fn decode_payload(msg_type: MessageType, buf: &mut impl Buf) -> Result<Self, CodecError> {
        match msg_type {
            MessageType::ClientSetup => {
                let parameters = KeyValuePair::decode_list(buf)?;
                Ok(ControlMessage::ClientSetup(ClientSetup { parameters }))
            }
            MessageType::ServerSetup => {
                let parameters = KeyValuePair::decode_list(buf)?;
                Ok(ControlMessage::ServerSetup(ServerSetup { parameters }))
            }
            MessageType::GoAway => {
                let uri_len = VarInt::decode(buf)?.into_inner() as usize;
                let uri = read_bytes(buf, uri_len)?;
                Ok(ControlMessage::GoAway(GoAway { new_session_uri: uri }))
            }
            MessageType::MaxRequestId => {
                let request_id = VarInt::decode(buf)?;
                Ok(ControlMessage::MaxRequestId(MaxRequestId { request_id }))
            }
            MessageType::RequestsBlocked => {
                let maximum_request_id = VarInt::decode(buf)?;
                Ok(ControlMessage::RequestsBlocked(RequestsBlocked { maximum_request_id }))
            }
            MessageType::RequestOk => {
                let request_id = VarInt::decode(buf)?;
                let parameters = KeyValuePair::decode_list(buf)?;
                Ok(ControlMessage::RequestOk(RequestOk { request_id, parameters }))
            }
            MessageType::RequestError => {
                let request_id = VarInt::decode(buf)?;
                let error_code = VarInt::decode(buf)?;
                let retry_interval = VarInt::decode(buf)?;
                let reason_len = VarInt::decode(buf)?.into_inner() as usize;
                let reason_phrase = read_bytes(buf, reason_len)?;
                Ok(ControlMessage::RequestError(RequestError {
                    request_id,
                    error_code,
                    retry_interval,
                    reason_phrase,
                }))
            }
            MessageType::Subscribe => {
                let request_id = VarInt::decode(buf)?;
                let track_namespace = TrackNamespace::decode(buf)?;
                let track_name_len = VarInt::decode(buf)?.into_inner() as usize;
                let track_name = read_bytes(buf, track_name_len)?;
                let parameters = KeyValuePair::decode_list(buf)?;
                Ok(ControlMessage::Subscribe(Subscribe {
                    request_id,
                    track_namespace,
                    track_name,
                    parameters,
                }))
            }
            MessageType::SubscribeOk => {
                let request_id = VarInt::decode(buf)?;
                let track_alias = VarInt::decode(buf)?;
                let parameters = KeyValuePair::decode_list(buf)?;
                let track_extensions = decode_track_extensions(buf)?;
                Ok(ControlMessage::SubscribeOk(SubscribeOk {
                    request_id,
                    track_alias,
                    parameters,
                    track_extensions,
                }))
            }
            MessageType::RequestUpdate => {
                let request_id = VarInt::decode(buf)?;
                let existing_request_id = VarInt::decode(buf)?;
                let parameters = KeyValuePair::decode_list(buf)?;
                Ok(ControlMessage::RequestUpdate(RequestUpdate {
                    request_id,
                    existing_request_id,
                    parameters,
                }))
            }
            MessageType::Unsubscribe => {
                let request_id = VarInt::decode(buf)?;
                Ok(ControlMessage::Unsubscribe(Unsubscribe { request_id }))
            }
            MessageType::Publish => {
                let request_id = VarInt::decode(buf)?;
                let track_namespace = TrackNamespace::decode(buf)?;
                let track_name_len = VarInt::decode(buf)?.into_inner() as usize;
                let track_name = read_bytes(buf, track_name_len)?;
                let track_alias = VarInt::decode(buf)?;
                let parameters = KeyValuePair::decode_list(buf)?;
                let track_extensions = decode_track_extensions(buf)?;
                Ok(ControlMessage::Publish(Publish {
                    request_id,
                    track_namespace,
                    track_name,
                    track_alias,
                    parameters,
                    track_extensions,
                }))
            }
            MessageType::PublishOk => {
                let request_id = VarInt::decode(buf)?;
                let parameters = KeyValuePair::decode_list(buf)?;
                Ok(ControlMessage::PublishOk(PublishOk { request_id, parameters }))
            }
            MessageType::PublishDone => {
                let request_id = VarInt::decode(buf)?;
                let status_code = VarInt::decode(buf)?;
                let stream_count = VarInt::decode(buf)?;
                let reason_len = VarInt::decode(buf)?.into_inner() as usize;
                let reason_phrase = read_bytes(buf, reason_len)?;
                Ok(ControlMessage::PublishDone(PublishDone {
                    request_id,
                    status_code,
                    stream_count,
                    reason_phrase,
                }))
            }
            MessageType::PublishNamespace => {
                let request_id = VarInt::decode(buf)?;
                let track_namespace = TrackNamespace::decode(buf)?;
                let parameters = KeyValuePair::decode_list(buf)?;
                Ok(ControlMessage::PublishNamespace(PublishNamespace {
                    request_id,
                    track_namespace,
                    parameters,
                }))
            }
            MessageType::PublishNamespaceDone => {
                let request_id = VarInt::decode(buf)?;
                Ok(ControlMessage::PublishNamespaceDone(PublishNamespaceDone { request_id }))
            }
            MessageType::PublishNamespaceCancel => {
                let request_id = VarInt::decode(buf)?;
                let error_code = VarInt::decode(buf)?;
                let reason_len = VarInt::decode(buf)?.into_inner() as usize;
                let reason_phrase = read_bytes(buf, reason_len)?;
                Ok(ControlMessage::PublishNamespaceCancel(PublishNamespaceCancel {
                    request_id,
                    error_code,
                    reason_phrase,
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
                let namespace_prefix = TrackNamespace::decode(buf)?;
                let subscribe_options = VarInt::decode(buf)?;
                let parameters = KeyValuePair::decode_list(buf)?;
                Ok(ControlMessage::SubscribeNamespace(SubscribeNamespace {
                    request_id,
                    namespace_prefix,
                    subscribe_options,
                    parameters,
                }))
            }
            MessageType::TrackStatus => {
                let request_id = VarInt::decode(buf)?;
                let track_namespace = TrackNamespace::decode(buf)?;
                let track_name_len = VarInt::decode(buf)?.into_inner() as usize;
                let track_name = read_bytes(buf, track_name_len)?;
                let parameters = KeyValuePair::decode_list(buf)?;
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
                        let track_name_len = VarInt::decode(buf)?.into_inner() as usize;
                        let track_name = read_bytes(buf, track_name_len)?;
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
                let parameters = KeyValuePair::decode_list(buf)?;
                Ok(ControlMessage::Fetch(Fetch {
                    request_id,
                    fetch_type,
                    fetch_payload,
                    parameters,
                }))
            }
            MessageType::FetchOk => {
                let request_id = VarInt::decode(buf)?;
                let end_of_track = VarInt::decode(buf)?;
                let end_group = VarInt::decode(buf)?;
                let end_object = VarInt::decode(buf)?;
                let parameters = KeyValuePair::decode_list(buf)?;
                let track_extensions = decode_track_extensions(buf)?;
                Ok(ControlMessage::FetchOk(FetchOk {
                    request_id,
                    end_of_track,
                    end_group,
                    end_object,
                    parameters,
                    track_extensions,
                }))
            }
            MessageType::FetchCancel => {
                let request_id = VarInt::decode(buf)?;
                Ok(ControlMessage::FetchCancel(FetchCancel { request_id }))
            }
        }
    }

    pub fn message_type(&self) -> MessageType {
        match self {
            ControlMessage::ClientSetup(_) => MessageType::ClientSetup,
            ControlMessage::ServerSetup(_) => MessageType::ServerSetup,
            ControlMessage::GoAway(_) => MessageType::GoAway,
            ControlMessage::MaxRequestId(_) => MessageType::MaxRequestId,
            ControlMessage::RequestsBlocked(_) => MessageType::RequestsBlocked,
            ControlMessage::RequestOk(_) => MessageType::RequestOk,
            ControlMessage::RequestError(_) => MessageType::RequestError,
            ControlMessage::Subscribe(_) => MessageType::Subscribe,
            ControlMessage::SubscribeOk(_) => MessageType::SubscribeOk,
            ControlMessage::RequestUpdate(_) => MessageType::RequestUpdate,
            ControlMessage::Unsubscribe(_) => MessageType::Unsubscribe,
            ControlMessage::Publish(_) => MessageType::Publish,
            ControlMessage::PublishOk(_) => MessageType::PublishOk,
            ControlMessage::PublishDone(_) => MessageType::PublishDone,
            ControlMessage::PublishNamespace(_) => MessageType::PublishNamespace,
            ControlMessage::PublishNamespaceDone(_) => MessageType::PublishNamespaceDone,
            ControlMessage::PublishNamespaceCancel(_) => MessageType::PublishNamespaceCancel,
            ControlMessage::Namespace(_) => MessageType::Namespace,
            ControlMessage::NamespaceDone(_) => MessageType::NamespaceDone,
            ControlMessage::SubscribeNamespace(_) => MessageType::SubscribeNamespace,
            ControlMessage::TrackStatus(_) => MessageType::TrackStatus,
            ControlMessage::Fetch(_) => MessageType::Fetch,
            ControlMessage::FetchOk(_) => MessageType::FetchOk,
            ControlMessage::FetchCancel(_) => MessageType::FetchCancel,
        }
    }
}

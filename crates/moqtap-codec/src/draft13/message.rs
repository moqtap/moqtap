//! Draft-13 control message encoding and decoding.
//!
//! Key changes from draft-12:
//! - `subscribe_announces` → `subscribe_namespace` (same IDs 0x11–0x14)
//! - TrackStatusRequest (0x0D) → TrackStatus: subscribe-like request with
//!   subscriber_priority, group_order, forward, filter_type
//! - TrackStatus (0x0E) → TrackStatusOk: subscribe_ok-like response with
//!   track_alias, expires, group_order, content_exists, largest_location
//! - New TrackStatusError (0x0F): request_id + error_code + reason_phrase
//! - Publish/PublishOk/PublishError (0x1D-0x1F) added

pub use crate::error::{
    CodecError, MAX_GOAWAY_URI_LENGTH, MAX_MESSAGE_LENGTH, MAX_NAMESPACE_TUPLE_SIZE,
    MAX_REASON_PHRASE_LENGTH,
};
use crate::kvp::KeyValuePair;
use crate::types::*;
use crate::varint::VarInt;
use bytes::{Buf, BufMut};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum MessageType {
    SubscribeUpdate = 0x02,
    Subscribe = 0x03,
    SubscribeOk = 0x04,
    SubscribeError = 0x05,
    Announce = 0x06,
    AnnounceOk = 0x07,
    AnnounceError = 0x08,
    Unannounce = 0x09,
    Unsubscribe = 0x0A,
    SubscribeDone = 0x0B,
    AnnounceCancel = 0x0C,
    TrackStatus = 0x0D,
    TrackStatusOk = 0x0E,
    TrackStatusError = 0x0F,
    GoAway = 0x10,
    SubscribeNamespace = 0x11,
    SubscribeNamespaceOk = 0x12,
    SubscribeNamespaceError = 0x13,
    UnsubscribeNamespace = 0x14,
    MaxRequestId = 0x15,
    Fetch = 0x16,
    FetchCancel = 0x17,
    FetchOk = 0x18,
    FetchError = 0x19,
    RequestsBlocked = 0x1A,
    Publish = 0x1D,
    PublishOk = 0x1E,
    PublishError = 0x1F,
    ClientSetup = 0x20,
    ServerSetup = 0x21,
}

impl MessageType {
    pub fn from_id(id: u64) -> Option<Self> {
        match id {
            0x02 => Some(MessageType::SubscribeUpdate),
            0x03 => Some(MessageType::Subscribe),
            0x04 => Some(MessageType::SubscribeOk),
            0x05 => Some(MessageType::SubscribeError),
            0x06 => Some(MessageType::Announce),
            0x07 => Some(MessageType::AnnounceOk),
            0x08 => Some(MessageType::AnnounceError),
            0x09 => Some(MessageType::Unannounce),
            0x0A => Some(MessageType::Unsubscribe),
            0x0B => Some(MessageType::SubscribeDone),
            0x0C => Some(MessageType::AnnounceCancel),
            0x0D => Some(MessageType::TrackStatus),
            0x0E => Some(MessageType::TrackStatusOk),
            0x0F => Some(MessageType::TrackStatusError),
            0x10 => Some(MessageType::GoAway),
            0x11 => Some(MessageType::SubscribeNamespace),
            0x12 => Some(MessageType::SubscribeNamespaceOk),
            0x13 => Some(MessageType::SubscribeNamespaceError),
            0x14 => Some(MessageType::UnsubscribeNamespace),
            0x15 => Some(MessageType::MaxRequestId),
            0x16 => Some(MessageType::Fetch),
            0x17 => Some(MessageType::FetchCancel),
            0x18 => Some(MessageType::FetchOk),
            0x19 => Some(MessageType::FetchError),
            0x1A => Some(MessageType::RequestsBlocked),
            0x1D => Some(MessageType::Publish),
            0x1E => Some(MessageType::PublishOk),
            0x1F => Some(MessageType::PublishError),
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
    pub supported_versions: Vec<VarInt>,
    pub parameters: Vec<KeyValuePair>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerSetup {
    pub selected_version: VarInt,
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
// Subscribe Messages
// ============================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscribe {
    pub request_id: VarInt,
    pub track_namespace: TrackNamespace,
    pub track_name: Vec<u8>,
    pub subscriber_priority: u8,
    pub group_order: VarInt,
    pub forward: VarInt,
    pub filter_type: VarInt,
    pub start_group: Option<VarInt>,
    pub start_object: Option<VarInt>,
    pub end_group: Option<VarInt>,
    pub parameters: Vec<KeyValuePair>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeOk {
    pub request_id: VarInt,
    pub track_alias: VarInt,
    pub expires: VarInt,
    pub group_order: VarInt,
    pub content_exists: VarInt,
    pub largest_location: Option<Location>,
    pub parameters: Vec<KeyValuePair>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeError {
    pub request_id: VarInt,
    pub error_code: VarInt,
    pub reason_phrase: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeUpdate {
    pub request_id: VarInt,
    pub start_group: VarInt,
    pub start_object: VarInt,
    pub end_group: VarInt,
    pub subscriber_priority: u8,
    pub forward: VarInt,
    pub parameters: Vec<KeyValuePair>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeDone {
    pub request_id: VarInt,
    pub status_code: VarInt,
    pub stream_count: VarInt,
    pub reason_phrase: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unsubscribe {
    pub request_id: VarInt,
}

// ============================================================
// Announce Messages
// ============================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Announce {
    pub request_id: VarInt,
    pub track_namespace: TrackNamespace,
    pub parameters: Vec<KeyValuePair>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnounceOk {
    pub request_id: VarInt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnounceError {
    pub request_id: VarInt,
    pub error_code: VarInt,
    pub reason_phrase: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnounceCancel {
    pub track_namespace: TrackNamespace,
    pub error_code: VarInt,
    pub reason_phrase: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unannounce {
    pub track_namespace: TrackNamespace,
}

// ============================================================
// Subscribe Namespace Messages (renamed from Subscribe Announces)
// ============================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeNamespace {
    pub request_id: VarInt,
    pub track_namespace_prefix: TrackNamespace,
    pub parameters: Vec<KeyValuePair>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeNamespaceOk {
    pub request_id: VarInt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeNamespaceError {
    pub request_id: VarInt,
    pub error_code: VarInt,
    pub reason_phrase: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsubscribeNamespace {
    pub track_namespace_prefix: TrackNamespace,
}

// ============================================================
// Track Status Messages (restructured from draft-12)
// ============================================================

/// TRACK_STATUS message (type 0x0D). Draft-13: subscribe-like request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackStatus {
    pub request_id: VarInt,
    pub track_namespace: TrackNamespace,
    pub track_name: Vec<u8>,
    pub subscriber_priority: u8,
    pub group_order: VarInt,
    pub forward: VarInt,
    pub filter_type: VarInt,
    pub parameters: Vec<KeyValuePair>,
}

/// TRACK_STATUS_OK message (type 0x0E). Draft-13: subscribe_ok-like response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackStatusOk {
    pub request_id: VarInt,
    pub track_alias: VarInt,
    pub expires: VarInt,
    pub group_order: VarInt,
    pub content_exists: VarInt,
    pub largest_location: Option<Location>,
    pub parameters: Vec<KeyValuePair>,
}

/// TRACK_STATUS_ERROR message (type 0x0F). New in draft-13.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackStatusError {
    pub request_id: VarInt,
    pub error_code: VarInt,
    pub reason_phrase: Vec<u8>,
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
    pub subscriber_priority: u8,
    pub group_order: VarInt,
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
        joining_subscribe_id: VarInt,
        joining_start: VarInt,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchOk {
    pub request_id: VarInt,
    pub group_order: VarInt,
    pub end_of_track: VarInt,
    pub end_location: Location,
    pub parameters: Vec<KeyValuePair>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchError {
    pub request_id: VarInt,
    pub error_code: VarInt,
    pub reason_phrase: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchCancel {
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
    pub group_order: VarInt,
    pub content_exists: VarInt,
    pub largest_location: Option<Location>,
    pub forward: VarInt,
    pub parameters: Vec<KeyValuePair>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishOk {
    pub request_id: VarInt,
    pub forward: VarInt,
    pub subscriber_priority: u8,
    pub group_order: VarInt,
    pub filter_type: VarInt,
    pub start_group: Option<VarInt>,
    pub start_object: Option<VarInt>,
    pub end_group: Option<VarInt>,
    pub parameters: Vec<KeyValuePair>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishError {
    pub request_id: VarInt,
    pub error_code: VarInt,
    pub reason_phrase: Vec<u8>,
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
    Subscribe(Subscribe),
    SubscribeOk(SubscribeOk),
    SubscribeError(SubscribeError),
    SubscribeUpdate(SubscribeUpdate),
    SubscribeDone(SubscribeDone),
    Unsubscribe(Unsubscribe),
    Announce(Announce),
    AnnounceOk(AnnounceOk),
    AnnounceError(AnnounceError),
    AnnounceCancel(AnnounceCancel),
    Unannounce(Unannounce),
    SubscribeNamespace(SubscribeNamespace),
    SubscribeNamespaceOk(SubscribeNamespaceOk),
    SubscribeNamespaceError(SubscribeNamespaceError),
    UnsubscribeNamespace(UnsubscribeNamespace),
    TrackStatus(TrackStatus),
    TrackStatusOk(TrackStatusOk),
    TrackStatusError(TrackStatusError),
    Fetch(Fetch),
    FetchOk(FetchOk),
    FetchError(FetchError),
    FetchCancel(FetchCancel),
    Publish(Publish),
    PublishOk(PublishOk),
    PublishError(PublishError),
}

impl ControlMessage {
    /// Encode this control message to bytes.
    ///
    /// Draft-13 framing: type_id(vi) + payload_length(16) + payload.
    pub fn encode(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        let mut payload = Vec::with_capacity(256);
        self.encode_payload(&mut payload)?;

        if payload.len() > MAX_MESSAGE_LENGTH {
            return Err(CodecError::MessageTooLong(payload.len()));
        }

        VarInt::from_usize(self.message_type().id() as usize).encode(buf);
        // Draft-13: 16-bit length (big-endian)
        buf.put_u16(payload.len() as u16);
        buf.put_slice(&payload);
        Ok(())
    }

    /// Decode a control message from bytes.
    ///
    /// Draft-13 framing: type_id(vi) + payload_length(16) + payload.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let type_id = VarInt::decode(buf)?.into_inner();
        let msg_type =
            MessageType::from_id(type_id).ok_or(CodecError::UnknownMessageType(type_id))?;
        // Draft-13: 16-bit length (big-endian)
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
                VarInt::from_usize(m.supported_versions.len()).encode(buf);
                for v in &m.supported_versions {
                    v.encode(buf);
                }
                KeyValuePair::encode_list(&m.parameters, buf);
            }
            ControlMessage::ServerSetup(m) => {
                m.selected_version.encode(buf);
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
            ControlMessage::Subscribe(m) => {
                m.request_id.encode(buf);
                m.track_namespace.encode(buf);
                VarInt::from_usize(m.track_name.len()).encode(buf);
                buf.put_slice(&m.track_name);
                buf.put_u8(m.subscriber_priority);
                m.group_order.encode(buf);
                m.forward.encode(buf);
                m.filter_type.encode(buf);
                if let Some(sg) = &m.start_group {
                    sg.encode(buf);
                }
                if let Some(so) = &m.start_object {
                    so.encode(buf);
                }
                if let Some(eg) = &m.end_group {
                    eg.encode(buf);
                }
                KeyValuePair::encode_list(&m.parameters, buf);
            }
            ControlMessage::SubscribeOk(m) => {
                m.request_id.encode(buf);
                m.track_alias.encode(buf);
                m.expires.encode(buf);
                m.group_order.encode(buf);
                m.content_exists.encode(buf);
                if let Some(loc) = &m.largest_location {
                    loc.encode(buf);
                }
                KeyValuePair::encode_list(&m.parameters, buf);
            }
            ControlMessage::SubscribeError(m) => {
                if m.reason_phrase.len() > MAX_REASON_PHRASE_LENGTH {
                    return Err(CodecError::ReasonPhraseTooLong);
                }
                m.request_id.encode(buf);
                m.error_code.encode(buf);
                VarInt::from_usize(m.reason_phrase.len()).encode(buf);
                buf.put_slice(&m.reason_phrase);
            }
            ControlMessage::SubscribeUpdate(m) => {
                m.request_id.encode(buf);
                m.start_group.encode(buf);
                m.start_object.encode(buf);
                m.end_group.encode(buf);
                buf.put_u8(m.subscriber_priority);
                m.forward.encode(buf);
                KeyValuePair::encode_list(&m.parameters, buf);
            }
            ControlMessage::SubscribeDone(m) => {
                if m.reason_phrase.len() > MAX_REASON_PHRASE_LENGTH {
                    return Err(CodecError::ReasonPhraseTooLong);
                }
                m.request_id.encode(buf);
                m.status_code.encode(buf);
                m.stream_count.encode(buf);
                VarInt::from_usize(m.reason_phrase.len()).encode(buf);
                buf.put_slice(&m.reason_phrase);
            }
            ControlMessage::Unsubscribe(m) => {
                m.request_id.encode(buf);
            }
            ControlMessage::Announce(m) => {
                m.request_id.encode(buf);
                m.track_namespace.encode(buf);
                KeyValuePair::encode_list(&m.parameters, buf);
            }
            ControlMessage::AnnounceOk(m) => {
                m.request_id.encode(buf);
            }
            ControlMessage::AnnounceError(m) => {
                if m.reason_phrase.len() > MAX_REASON_PHRASE_LENGTH {
                    return Err(CodecError::ReasonPhraseTooLong);
                }
                m.request_id.encode(buf);
                m.error_code.encode(buf);
                VarInt::from_usize(m.reason_phrase.len()).encode(buf);
                buf.put_slice(&m.reason_phrase);
            }
            ControlMessage::AnnounceCancel(m) => {
                if m.reason_phrase.len() > MAX_REASON_PHRASE_LENGTH {
                    return Err(CodecError::ReasonPhraseTooLong);
                }
                m.track_namespace.encode(buf);
                m.error_code.encode(buf);
                VarInt::from_usize(m.reason_phrase.len()).encode(buf);
                buf.put_slice(&m.reason_phrase);
            }
            ControlMessage::Unannounce(m) => {
                m.track_namespace.encode(buf);
            }
            ControlMessage::SubscribeNamespace(m) => {
                m.request_id.encode(buf);
                m.track_namespace_prefix.encode(buf);
                KeyValuePair::encode_list(&m.parameters, buf);
            }
            ControlMessage::SubscribeNamespaceOk(m) => {
                m.request_id.encode(buf);
            }
            ControlMessage::SubscribeNamespaceError(m) => {
                if m.reason_phrase.len() > MAX_REASON_PHRASE_LENGTH {
                    return Err(CodecError::ReasonPhraseTooLong);
                }
                m.request_id.encode(buf);
                m.error_code.encode(buf);
                VarInt::from_usize(m.reason_phrase.len()).encode(buf);
                buf.put_slice(&m.reason_phrase);
            }
            ControlMessage::UnsubscribeNamespace(m) => {
                m.track_namespace_prefix.encode(buf);
            }
            ControlMessage::TrackStatus(m) => {
                m.request_id.encode(buf);
                m.track_namespace.encode(buf);
                VarInt::from_usize(m.track_name.len()).encode(buf);
                buf.put_slice(&m.track_name);
                buf.put_u8(m.subscriber_priority);
                m.group_order.encode(buf);
                m.forward.encode(buf);
                m.filter_type.encode(buf);
                KeyValuePair::encode_list(&m.parameters, buf);
            }
            ControlMessage::TrackStatusOk(m) => {
                m.request_id.encode(buf);
                m.track_alias.encode(buf);
                m.expires.encode(buf);
                m.group_order.encode(buf);
                m.content_exists.encode(buf);
                if let Some(loc) = &m.largest_location {
                    loc.encode(buf);
                }
                KeyValuePair::encode_list(&m.parameters, buf);
            }
            ControlMessage::TrackStatusError(m) => {
                if m.reason_phrase.len() > MAX_REASON_PHRASE_LENGTH {
                    return Err(CodecError::ReasonPhraseTooLong);
                }
                m.request_id.encode(buf);
                m.error_code.encode(buf);
                VarInt::from_usize(m.reason_phrase.len()).encode(buf);
                buf.put_slice(&m.reason_phrase);
            }
            ControlMessage::Fetch(m) => {
                m.request_id.encode(buf);
                buf.put_u8(m.subscriber_priority);
                m.group_order.encode(buf);
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
                    FetchPayload::Joining { joining_subscribe_id, joining_start } => {
                        joining_subscribe_id.encode(buf);
                        joining_start.encode(buf);
                    }
                }
                KeyValuePair::encode_list(&m.parameters, buf);
            }
            ControlMessage::FetchOk(m) => {
                m.request_id.encode(buf);
                m.group_order.encode(buf);
                m.end_of_track.encode(buf);
                m.end_location.encode(buf);
                KeyValuePair::encode_list(&m.parameters, buf);
            }
            ControlMessage::FetchError(m) => {
                if m.reason_phrase.len() > MAX_REASON_PHRASE_LENGTH {
                    return Err(CodecError::ReasonPhraseTooLong);
                }
                m.request_id.encode(buf);
                m.error_code.encode(buf);
                VarInt::from_usize(m.reason_phrase.len()).encode(buf);
                buf.put_slice(&m.reason_phrase);
            }
            ControlMessage::FetchCancel(m) => {
                m.request_id.encode(buf);
            }
            ControlMessage::Publish(m) => {
                m.request_id.encode(buf);
                m.track_namespace.encode(buf);
                VarInt::from_usize(m.track_name.len()).encode(buf);
                buf.put_slice(&m.track_name);
                m.track_alias.encode(buf);
                m.group_order.encode(buf);
                m.content_exists.encode(buf);
                if let Some(loc) = &m.largest_location {
                    loc.encode(buf);
                }
                m.forward.encode(buf);
                KeyValuePair::encode_list(&m.parameters, buf);
            }
            ControlMessage::PublishOk(m) => {
                m.request_id.encode(buf);
                m.forward.encode(buf);
                buf.put_u8(m.subscriber_priority);
                m.group_order.encode(buf);
                m.filter_type.encode(buf);
                if let Some(sg) = &m.start_group {
                    sg.encode(buf);
                }
                if let Some(so) = &m.start_object {
                    so.encode(buf);
                }
                if let Some(eg) = &m.end_group {
                    eg.encode(buf);
                }
                KeyValuePair::encode_list(&m.parameters, buf);
            }
            ControlMessage::PublishError(m) => {
                if m.reason_phrase.len() > MAX_REASON_PHRASE_LENGTH {
                    return Err(CodecError::ReasonPhraseTooLong);
                }
                m.request_id.encode(buf);
                m.error_code.encode(buf);
                VarInt::from_usize(m.reason_phrase.len()).encode(buf);
                buf.put_slice(&m.reason_phrase);
            }
        }
        Ok(())
    }

    fn decode_payload(msg_type: MessageType, buf: &mut impl Buf) -> Result<Self, CodecError> {
        match msg_type {
            MessageType::ClientSetup => {
                let num_versions = VarInt::decode(buf)?.into_inner() as usize;
                if num_versions == 0 {
                    return Err(CodecError::InvalidField);
                }
                let mut supported_versions = Vec::with_capacity(num_versions);
                for _ in 0..num_versions {
                    supported_versions.push(VarInt::decode(buf)?);
                }
                let parameters = KeyValuePair::decode_list(buf)?;
                Ok(ControlMessage::ClientSetup(ClientSetup { supported_versions, parameters }))
            }
            MessageType::ServerSetup => {
                let selected_version = VarInt::decode(buf)?;
                let parameters = KeyValuePair::decode_list(buf)?;
                Ok(ControlMessage::ServerSetup(ServerSetup { selected_version, parameters }))
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
            MessageType::Subscribe => {
                let request_id = VarInt::decode(buf)?;
                let track_namespace = TrackNamespace::decode(buf)?;
                let track_name_len = VarInt::decode(buf)?.into_inner() as usize;
                let track_name = read_bytes(buf, track_name_len)?;
                if buf.remaining() < 1 {
                    return Err(CodecError::UnexpectedEnd);
                }
                let subscriber_priority = buf.get_u8();
                let group_order = VarInt::decode(buf)?;
                let forward = VarInt::decode(buf)?;
                let filter_type = VarInt::decode(buf)?;
                let ft_val = filter_type.into_inner();
                if ft_val == 0 || ft_val > 4 {
                    return Err(CodecError::InvalidField);
                }
                let (start_group, start_object) = if ft_val == 3 || ft_val == 4 {
                    (Some(VarInt::decode(buf)?), Some(VarInt::decode(buf)?))
                } else {
                    (None, None)
                };
                let end_group = if ft_val == 4 { Some(VarInt::decode(buf)?) } else { None };
                let parameters = KeyValuePair::decode_list(buf)?;
                Ok(ControlMessage::Subscribe(Subscribe {
                    request_id,
                    track_namespace,
                    track_name,
                    subscriber_priority,
                    group_order,
                    forward,
                    filter_type,
                    start_group,
                    start_object,
                    end_group,
                    parameters,
                }))
            }
            MessageType::SubscribeOk => {
                let request_id = VarInt::decode(buf)?;
                let track_alias = VarInt::decode(buf)?;
                let expires = VarInt::decode(buf)?;
                let group_order = VarInt::decode(buf)?;
                let content_exists = VarInt::decode(buf)?;
                let largest_location = if content_exists.into_inner() != 0 {
                    Some(Location::decode(buf)?)
                } else {
                    None
                };
                let parameters = KeyValuePair::decode_list(buf)?;
                Ok(ControlMessage::SubscribeOk(SubscribeOk {
                    request_id,
                    track_alias,
                    expires,
                    group_order,
                    content_exists,
                    largest_location,
                    parameters,
                }))
            }
            MessageType::SubscribeError => {
                let request_id = VarInt::decode(buf)?;
                let error_code = VarInt::decode(buf)?;
                let reason_len = VarInt::decode(buf)?.into_inner() as usize;
                let reason_phrase = read_bytes(buf, reason_len)?;
                Ok(ControlMessage::SubscribeError(SubscribeError {
                    request_id,
                    error_code,
                    reason_phrase,
                }))
            }
            MessageType::SubscribeUpdate => {
                let request_id = VarInt::decode(buf)?;
                let start_group = VarInt::decode(buf)?;
                let start_object = VarInt::decode(buf)?;
                let end_group = VarInt::decode(buf)?;
                if buf.remaining() < 1 {
                    return Err(CodecError::UnexpectedEnd);
                }
                let subscriber_priority = buf.get_u8();
                let forward = VarInt::decode(buf)?;
                let parameters = KeyValuePair::decode_list(buf)?;
                Ok(ControlMessage::SubscribeUpdate(SubscribeUpdate {
                    request_id,
                    start_group,
                    start_object,
                    end_group,
                    subscriber_priority,
                    forward,
                    parameters,
                }))
            }
            MessageType::SubscribeDone => {
                let request_id = VarInt::decode(buf)?;
                let status_code = VarInt::decode(buf)?;
                let stream_count = VarInt::decode(buf)?;
                let reason_len = VarInt::decode(buf)?.into_inner() as usize;
                let reason_phrase = read_bytes(buf, reason_len)?;
                Ok(ControlMessage::SubscribeDone(SubscribeDone {
                    request_id,
                    status_code,
                    stream_count,
                    reason_phrase,
                }))
            }
            MessageType::Unsubscribe => {
                let request_id = VarInt::decode(buf)?;
                Ok(ControlMessage::Unsubscribe(Unsubscribe { request_id }))
            }
            MessageType::Announce => {
                let request_id = VarInt::decode(buf)?;
                let track_namespace = TrackNamespace::decode(buf)?;
                let parameters = KeyValuePair::decode_list(buf)?;
                Ok(ControlMessage::Announce(Announce { request_id, track_namespace, parameters }))
            }
            MessageType::AnnounceOk => {
                let request_id = VarInt::decode(buf)?;
                Ok(ControlMessage::AnnounceOk(AnnounceOk { request_id }))
            }
            MessageType::AnnounceError => {
                let request_id = VarInt::decode(buf)?;
                let error_code = VarInt::decode(buf)?;
                let reason_len = VarInt::decode(buf)?.into_inner() as usize;
                let reason_phrase = read_bytes(buf, reason_len)?;
                Ok(ControlMessage::AnnounceError(AnnounceError {
                    request_id,
                    error_code,
                    reason_phrase,
                }))
            }
            MessageType::AnnounceCancel => {
                let track_namespace = TrackNamespace::decode(buf)?;
                let error_code = VarInt::decode(buf)?;
                let reason_len = VarInt::decode(buf)?.into_inner() as usize;
                let reason_phrase = read_bytes(buf, reason_len)?;
                Ok(ControlMessage::AnnounceCancel(AnnounceCancel {
                    track_namespace,
                    error_code,
                    reason_phrase,
                }))
            }
            MessageType::Unannounce => {
                let track_namespace = TrackNamespace::decode(buf)?;
                Ok(ControlMessage::Unannounce(Unannounce { track_namespace }))
            }
            MessageType::SubscribeNamespace => {
                let request_id = VarInt::decode(buf)?;
                let track_namespace_prefix = TrackNamespace::decode(buf)?;
                let parameters = KeyValuePair::decode_list(buf)?;
                Ok(ControlMessage::SubscribeNamespace(SubscribeNamespace {
                    request_id,
                    track_namespace_prefix,
                    parameters,
                }))
            }
            MessageType::SubscribeNamespaceOk => {
                let request_id = VarInt::decode(buf)?;
                Ok(ControlMessage::SubscribeNamespaceOk(SubscribeNamespaceOk { request_id }))
            }
            MessageType::SubscribeNamespaceError => {
                let request_id = VarInt::decode(buf)?;
                let error_code = VarInt::decode(buf)?;
                let reason_len = VarInt::decode(buf)?.into_inner() as usize;
                let reason_phrase = read_bytes(buf, reason_len)?;
                Ok(ControlMessage::SubscribeNamespaceError(SubscribeNamespaceError {
                    request_id,
                    error_code,
                    reason_phrase,
                }))
            }
            MessageType::UnsubscribeNamespace => {
                let track_namespace_prefix = TrackNamespace::decode(buf)?;
                Ok(ControlMessage::UnsubscribeNamespace(UnsubscribeNamespace {
                    track_namespace_prefix,
                }))
            }
            MessageType::TrackStatus => {
                let request_id = VarInt::decode(buf)?;
                let track_namespace = TrackNamespace::decode(buf)?;
                let track_name_len = VarInt::decode(buf)?.into_inner() as usize;
                let track_name = read_bytes(buf, track_name_len)?;
                if buf.remaining() < 1 {
                    return Err(CodecError::UnexpectedEnd);
                }
                let subscriber_priority = buf.get_u8();
                let group_order = VarInt::decode(buf)?;
                let forward = VarInt::decode(buf)?;
                let filter_type = VarInt::decode(buf)?;
                let parameters = KeyValuePair::decode_list(buf)?;
                Ok(ControlMessage::TrackStatus(TrackStatus {
                    request_id,
                    track_namespace,
                    track_name,
                    subscriber_priority,
                    group_order,
                    forward,
                    filter_type,
                    parameters,
                }))
            }
            MessageType::TrackStatusOk => {
                let request_id = VarInt::decode(buf)?;
                let track_alias = VarInt::decode(buf)?;
                let expires = VarInt::decode(buf)?;
                let group_order = VarInt::decode(buf)?;
                let content_exists = VarInt::decode(buf)?;
                let largest_location = if content_exists.into_inner() != 0 {
                    Some(Location::decode(buf)?)
                } else {
                    None
                };
                let parameters = KeyValuePair::decode_list(buf)?;
                Ok(ControlMessage::TrackStatusOk(TrackStatusOk {
                    request_id,
                    track_alias,
                    expires,
                    group_order,
                    content_exists,
                    largest_location,
                    parameters,
                }))
            }
            MessageType::TrackStatusError => {
                let request_id = VarInt::decode(buf)?;
                let error_code = VarInt::decode(buf)?;
                let reason_len = VarInt::decode(buf)?.into_inner() as usize;
                let reason_phrase = read_bytes(buf, reason_len)?;
                Ok(ControlMessage::TrackStatusError(TrackStatusError {
                    request_id,
                    error_code,
                    reason_phrase,
                }))
            }
            MessageType::Fetch => {
                let request_id = VarInt::decode(buf)?;
                if buf.remaining() < 1 {
                    return Err(CodecError::UnexpectedEnd);
                }
                let subscriber_priority = buf.get_u8();
                let group_order = VarInt::decode(buf)?;
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
                        let joining_subscribe_id = VarInt::decode(buf)?;
                        let joining_start = VarInt::decode(buf)?;
                        FetchPayload::Joining { joining_subscribe_id, joining_start }
                    }
                };
                let parameters = KeyValuePair::decode_list(buf)?;
                Ok(ControlMessage::Fetch(Fetch {
                    request_id,
                    subscriber_priority,
                    group_order,
                    fetch_type,
                    fetch_payload,
                    parameters,
                }))
            }
            MessageType::FetchOk => {
                let request_id = VarInt::decode(buf)?;
                let group_order = VarInt::decode(buf)?;
                let end_of_track = VarInt::decode(buf)?;
                let end_location = Location::decode(buf)?;
                let parameters = KeyValuePair::decode_list(buf)?;
                Ok(ControlMessage::FetchOk(FetchOk {
                    request_id,
                    group_order,
                    end_of_track,
                    end_location,
                    parameters,
                }))
            }
            MessageType::FetchError => {
                let request_id = VarInt::decode(buf)?;
                let error_code = VarInt::decode(buf)?;
                let reason_len = VarInt::decode(buf)?.into_inner() as usize;
                let reason_phrase = read_bytes(buf, reason_len)?;
                Ok(ControlMessage::FetchError(FetchError { request_id, error_code, reason_phrase }))
            }
            MessageType::FetchCancel => {
                let request_id = VarInt::decode(buf)?;
                Ok(ControlMessage::FetchCancel(FetchCancel { request_id }))
            }
            MessageType::Publish => {
                let request_id = VarInt::decode(buf)?;
                let track_namespace = TrackNamespace::decode(buf)?;
                let track_name_len = VarInt::decode(buf)?.into_inner() as usize;
                let track_name = read_bytes(buf, track_name_len)?;
                let track_alias = VarInt::decode(buf)?;
                let group_order = VarInt::decode(buf)?;
                let content_exists = VarInt::decode(buf)?;
                let largest_location = if content_exists.into_inner() != 0 {
                    Some(Location::decode(buf)?)
                } else {
                    None
                };
                let forward = VarInt::decode(buf)?;
                let parameters = KeyValuePair::decode_list(buf)?;
                Ok(ControlMessage::Publish(Publish {
                    request_id,
                    track_namespace,
                    track_name,
                    track_alias,
                    group_order,
                    content_exists,
                    largest_location,
                    forward,
                    parameters,
                }))
            }
            MessageType::PublishOk => {
                let request_id = VarInt::decode(buf)?;
                let forward = VarInt::decode(buf)?;
                if buf.remaining() < 1 {
                    return Err(CodecError::UnexpectedEnd);
                }
                let subscriber_priority = buf.get_u8();
                let group_order = VarInt::decode(buf)?;
                let filter_type = VarInt::decode(buf)?;
                let ft_val = filter_type.into_inner();
                if ft_val == 0 || ft_val > 4 {
                    return Err(CodecError::InvalidField);
                }
                let (start_group, start_object) = if ft_val == 3 || ft_val == 4 {
                    (Some(VarInt::decode(buf)?), Some(VarInt::decode(buf)?))
                } else {
                    (None, None)
                };
                let end_group = if ft_val == 4 { Some(VarInt::decode(buf)?) } else { None };
                let parameters = KeyValuePair::decode_list(buf)?;
                Ok(ControlMessage::PublishOk(PublishOk {
                    request_id,
                    forward,
                    subscriber_priority,
                    group_order,
                    filter_type,
                    start_group,
                    start_object,
                    end_group,
                    parameters,
                }))
            }
            MessageType::PublishError => {
                let request_id = VarInt::decode(buf)?;
                let error_code = VarInt::decode(buf)?;
                let reason_len = VarInt::decode(buf)?.into_inner() as usize;
                let reason_phrase = read_bytes(buf, reason_len)?;
                Ok(ControlMessage::PublishError(PublishError {
                    request_id,
                    error_code,
                    reason_phrase,
                }))
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
            ControlMessage::Subscribe(_) => MessageType::Subscribe,
            ControlMessage::SubscribeOk(_) => MessageType::SubscribeOk,
            ControlMessage::SubscribeError(_) => MessageType::SubscribeError,
            ControlMessage::SubscribeUpdate(_) => MessageType::SubscribeUpdate,
            ControlMessage::SubscribeDone(_) => MessageType::SubscribeDone,
            ControlMessage::Unsubscribe(_) => MessageType::Unsubscribe,
            ControlMessage::Announce(_) => MessageType::Announce,
            ControlMessage::AnnounceOk(_) => MessageType::AnnounceOk,
            ControlMessage::AnnounceError(_) => MessageType::AnnounceError,
            ControlMessage::AnnounceCancel(_) => MessageType::AnnounceCancel,
            ControlMessage::Unannounce(_) => MessageType::Unannounce,
            ControlMessage::SubscribeNamespace(_) => MessageType::SubscribeNamespace,
            ControlMessage::SubscribeNamespaceOk(_) => MessageType::SubscribeNamespaceOk,
            ControlMessage::SubscribeNamespaceError(_) => MessageType::SubscribeNamespaceError,
            ControlMessage::UnsubscribeNamespace(_) => MessageType::UnsubscribeNamespace,
            ControlMessage::TrackStatus(_) => MessageType::TrackStatus,
            ControlMessage::TrackStatusOk(_) => MessageType::TrackStatusOk,
            ControlMessage::TrackStatusError(_) => MessageType::TrackStatusError,
            ControlMessage::Fetch(_) => MessageType::Fetch,
            ControlMessage::FetchOk(_) => MessageType::FetchOk,
            ControlMessage::FetchError(_) => MessageType::FetchError,
            ControlMessage::FetchCancel(_) => MessageType::FetchCancel,
            ControlMessage::Publish(_) => MessageType::Publish,
            ControlMessage::PublishOk(_) => MessageType::PublishOk,
            ControlMessage::PublishError(_) => MessageType::PublishError,
        }
    }
}

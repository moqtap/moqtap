//! Draft-11 control message encoding and decoding.
//!
//! Key changes from draft-09/10:
//! - Setup IDs: 0x40/0x41 -> 0x20/0x21
//! - `subscribe_id` -> `request_id` throughout
//! - MaxSubscribeId -> MaxRequestId, SubscribesBlocked -> RequestsBlocked
//! - Subscribe gains `track_alias` and `forward` fields; group_order/forward/filter_type as VarInt
//! - SubscribeOk: no track_alias; group_order/content_exists as VarInt
//! - SubscribeError gains trailing `track_alias`
//! - SubscribeDone gains `stream_count`
//! - SubscribeUpdate uses start_group/start_object (not Location); forward as VarInt
//! - Announce gains `request_id`; AnnounceOk/AnnounceError use `request_id`
//! - AnnounceCancel: `namespace + error_code + reason_phrase`
//! - SubscribeAnnounces gains `request_id`
//! - TrackStatusRequest gains `request_id` and `parameters`
//! - TrackStatus restructured: `request_id + status_code + largest_location + parameters`
//! - Fetch restructured: 3 fetch types (Standalone, RelativeJoining, AbsoluteJoining)
//! - FetchOk: group_order + end_of_track + end_location (no track_alias)
//! - Uses even/odd KVP encoding (not d07 format)
//! - Framing: type_id(vi) + payload_length(16) + payload

pub use crate::error::{
    CodecError, MAX_GOAWAY_URI_LENGTH, MAX_MESSAGE_LENGTH, MAX_NAMESPACE_TUPLE_SIZE,
    MAX_REASON_PHRASE_LENGTH,
};
use crate::kvp::KeyValuePair;
use crate::types::{self, *};
use crate::varint::VarInt;
use bytes::{Buf, BufMut};

/// Control message type IDs (draft-11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum MessageType {
    /// SubscribeUpdate (type 0x02).
    SubscribeUpdate = 0x02,
    /// Subscribe (type 0x03).
    Subscribe = 0x03,
    /// SubscribeOk (type 0x04).
    SubscribeOk = 0x04,
    /// SubscribeError (type 0x05).
    SubscribeError = 0x05,
    /// Announce (type 0x06).
    Announce = 0x06,
    /// AnnounceOk (type 0x07).
    AnnounceOk = 0x07,
    /// AnnounceError (type 0x08).
    AnnounceError = 0x08,
    /// Unannounce (type 0x09).
    Unannounce = 0x09,
    /// Unsubscribe (type 0x0A).
    Unsubscribe = 0x0A,
    /// SubscribeDone (type 0x0B).
    SubscribeDone = 0x0B,
    /// AnnounceCancel (type 0x0C).
    AnnounceCancel = 0x0C,
    /// TrackStatusRequest (type 0x0D).
    TrackStatusRequest = 0x0D,
    /// TrackStatus (type 0x0E).
    TrackStatus = 0x0E,
    /// GoAway (type 0x10).
    GoAway = 0x10,
    /// SubscribeAnnounces (type 0x11).
    SubscribeAnnounces = 0x11,
    /// SubscribeAnnouncesOk (type 0x12).
    SubscribeAnnouncesOk = 0x12,
    /// SubscribeAnnouncesError (type 0x13).
    SubscribeAnnouncesError = 0x13,
    /// UnsubscribeAnnounces (type 0x14).
    UnsubscribeAnnounces = 0x14,
    /// MaxRequestId (type 0x15).
    MaxRequestId = 0x15,
    /// Fetch (type 0x16).
    Fetch = 0x16,
    /// FetchCancel (type 0x17).
    FetchCancel = 0x17,
    /// FetchOk (type 0x18).
    FetchOk = 0x18,
    /// FetchError (type 0x19).
    FetchError = 0x19,
    /// RequestsBlocked (type 0x1A).
    RequestsBlocked = 0x1A,
    /// ClientSetup (type 0x20).
    ClientSetup = 0x20,
    /// ServerSetup (type 0x21).
    ServerSetup = 0x21,
}

impl MessageType {
    /// Look up a message type by its wire ID.
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
            0x0D => Some(MessageType::TrackStatusRequest),
            0x0E => Some(MessageType::TrackStatus),
            0x10 => Some(MessageType::GoAway),
            0x11 => Some(MessageType::SubscribeAnnounces),
            0x12 => Some(MessageType::SubscribeAnnouncesOk),
            0x13 => Some(MessageType::SubscribeAnnouncesError),
            0x14 => Some(MessageType::UnsubscribeAnnounces),
            0x15 => Some(MessageType::MaxRequestId),
            0x16 => Some(MessageType::Fetch),
            0x17 => Some(MessageType::FetchCancel),
            0x18 => Some(MessageType::FetchOk),
            0x19 => Some(MessageType::FetchError),
            0x1A => Some(MessageType::RequestsBlocked),
            0x20 => Some(MessageType::ClientSetup),
            0x21 => Some(MessageType::ServerSetup),
            _ => None,
        }
    }

    /// Return the wire ID for this message type.
    pub fn id(&self) -> u64 {
        *self as u64
    }
}

// ============================================================
// Session Lifecycle Messages
// ============================================================

/// CLIENT_SETUP message (type 0x20).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSetup {
    /// List of MoQT versions supported by the client.
    pub supported_versions: Vec<VarInt>,
    /// Setup parameters (even/odd KVP encoding).
    pub parameters: Vec<KeyValuePair>,
}

/// SERVER_SETUP message (type 0x21).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerSetup {
    /// The MoQT version selected by the server.
    pub selected_version: VarInt,
    /// Setup parameters (even/odd KVP encoding).
    pub parameters: Vec<KeyValuePair>,
}

/// GOAWAY message (type 0x10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoAway {
    /// URI for the new session to connect to.
    pub new_session_uri: Vec<u8>,
}

/// MAX_REQUEST_ID message (type 0x15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaxRequestId {
    /// The maximum request ID the peer may use.
    pub request_id: VarInt,
}

/// REQUESTS_BLOCKED message (type 0x1A).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestsBlocked {
    /// The request ID that is currently blocked on.
    pub maximum_request_id: VarInt,
}

// ============================================================
// Subscribe Messages
// ============================================================

/// SUBSCRIBE message (type 0x03).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscribe {
    /// The request ID for this subscription.
    pub request_id: VarInt,
    /// The track alias assigned by the subscriber.
    pub track_alias: VarInt,
    /// The track namespace.
    pub track_namespace: TrackNamespace,
    /// The track name within the namespace.
    pub track_name: Vec<u8>,
    /// Subscriber priority for this track.
    pub subscriber_priority: u8,
    /// Requested group delivery order (VarInt).
    pub group_order: VarInt,
    /// Whether to forward data on this subscription (VarInt).
    pub forward: VarInt,
    /// The filter type controlling which objects are delivered (VarInt).
    pub filter_type: VarInt,
    /// Present only for AbsoluteStart (3) and AbsoluteRange (4) filter types.
    pub start_group: Option<VarInt>,
    /// Present only for AbsoluteStart (3) and AbsoluteRange (4) filter types.
    pub start_object: Option<VarInt>,
    /// Present only for AbsoluteRange (4) filter type.
    pub end_group: Option<VarInt>,
    /// Subscribe parameters (even/odd KVP encoding).
    pub parameters: Vec<KeyValuePair>,
}

/// SUBSCRIBE_OK message (type 0x04).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeOk {
    /// The request ID this response corresponds to.
    pub request_id: VarInt,
    /// Subscription expiry in milliseconds (0 = no expiry).
    pub expires: VarInt,
    /// The group delivery order chosen by the publisher (VarInt).
    pub group_order: VarInt,
    /// Whether the largest location is included (VarInt).
    pub content_exists: VarInt,
    /// Present only when content_exists != 0.
    pub largest_location: Option<Location>,
    /// Response parameters (even/odd KVP encoding).
    pub parameters: Vec<KeyValuePair>,
}

/// SUBSCRIBE_ERROR message (type 0x05).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeError {
    /// The request ID this error corresponds to.
    pub request_id: VarInt,
    /// Application-defined error code.
    pub error_code: VarInt,
    /// Human-readable reason phrase.
    pub reason_phrase: Vec<u8>,
    /// The track alias.
    pub track_alias: VarInt,
}

/// SUBSCRIBE_UPDATE message (type 0x02).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeUpdate {
    /// The request ID of the subscription to update.
    pub request_id: VarInt,
    /// Updated start group.
    pub start_group: VarInt,
    /// Updated start object.
    pub start_object: VarInt,
    /// Updated end group (0 = open-ended).
    pub end_group: VarInt,
    /// Updated subscriber priority.
    pub subscriber_priority: u8,
    /// Updated forward preference (VarInt).
    pub forward: VarInt,
    /// Updated parameters (even/odd KVP encoding).
    pub parameters: Vec<KeyValuePair>,
}

/// SUBSCRIBE_DONE message (type 0x0B).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeDone {
    /// The request ID of the completed subscription.
    pub request_id: VarInt,
    /// Status code indicating the reason for completion.
    pub status_code: VarInt,
    /// The number of streams opened for this subscription.
    pub stream_count: VarInt,
    /// Human-readable reason phrase.
    pub reason_phrase: Vec<u8>,
}

/// UNSUBSCRIBE message (type 0x0A).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unsubscribe {
    /// The request ID of the subscription to cancel.
    pub request_id: VarInt,
}

// ============================================================
// Announce Messages
// ============================================================

/// ANNOUNCE message (type 0x06).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Announce {
    /// The request ID for this announcement.
    pub request_id: VarInt,
    /// The track namespace to announce.
    pub track_namespace: TrackNamespace,
    /// Announce parameters (even/odd KVP encoding).
    pub parameters: Vec<KeyValuePair>,
}

/// ANNOUNCE_OK message (type 0x07).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnounceOk {
    /// The request ID this response corresponds to.
    pub request_id: VarInt,
}

/// ANNOUNCE_ERROR message (type 0x08).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnounceError {
    /// The request ID this error corresponds to.
    pub request_id: VarInt,
    /// Application-defined error code.
    pub error_code: VarInt,
    /// Human-readable reason phrase.
    pub reason_phrase: Vec<u8>,
}

/// ANNOUNCE_CANCEL message (type 0x0C).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnounceCancel {
    /// The track namespace being cancelled.
    pub track_namespace: TrackNamespace,
    /// Application-defined error code.
    pub error_code: VarInt,
    /// Human-readable reason phrase.
    pub reason_phrase: Vec<u8>,
}

/// UNANNOUNCE message (type 0x09).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unannounce {
    /// The track namespace to unannounce.
    pub track_namespace: TrackNamespace,
}

// ============================================================
// Subscribe Announces Messages
// ============================================================

/// SUBSCRIBE_ANNOUNCES message (type 0x11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeAnnounces {
    /// The request ID for this subscription.
    pub request_id: VarInt,
    /// The track namespace prefix to subscribe to.
    pub track_namespace_prefix: TrackNamespace,
    /// Subscribe announces parameters (even/odd KVP encoding).
    pub parameters: Vec<KeyValuePair>,
}

/// SUBSCRIBE_ANNOUNCES_OK message (type 0x12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeAnnouncesOk {
    /// The request ID this response corresponds to.
    pub request_id: VarInt,
}

/// SUBSCRIBE_ANNOUNCES_ERROR message (type 0x13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeAnnouncesError {
    /// The request ID this error corresponds to.
    pub request_id: VarInt,
    /// Application-defined error code.
    pub error_code: VarInt,
    /// Human-readable reason phrase.
    pub reason_phrase: Vec<u8>,
}

/// UNSUBSCRIBE_ANNOUNCES message (type 0x14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsubscribeAnnounces {
    /// The track namespace prefix to unsubscribe from.
    pub track_namespace_prefix: TrackNamespace,
}

// ============================================================
// Track Status Messages
// ============================================================

/// TRACK_STATUS_REQUEST message (type 0x0D).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackStatusRequest {
    /// The request ID for this status query.
    pub request_id: VarInt,
    /// The track namespace to query.
    pub track_namespace: TrackNamespace,
    /// The track name within the namespace.
    pub track_name: Vec<u8>,
    /// Track status request parameters (even/odd KVP encoding).
    pub parameters: Vec<KeyValuePair>,
}

/// TRACK_STATUS message (type 0x0E).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackStatus {
    /// The request ID this status corresponds to.
    pub request_id: VarInt,
    /// The track status code.
    pub status_code: VarInt,
    /// The largest location (always present in draft-11).
    pub largest_location: Location,
    /// Track status parameters (even/odd KVP encoding).
    pub parameters: Vec<KeyValuePair>,
}

// ============================================================
// Fetch Messages
// ============================================================

/// Fetch type discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum FetchType {
    /// Standalone fetch with full track + range.
    Standalone = 1,
    /// Joining fetch relative to a subscribe.
    RelativeJoining = 2,
    /// Joining fetch with absolute group start.
    AbsoluteJoining = 3,
}

impl FetchType {
    /// Convert a raw u64 to a `FetchType`, if valid.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            1 => Some(FetchType::Standalone),
            2 => Some(FetchType::RelativeJoining),
            3 => Some(FetchType::AbsoluteJoining),
            _ => None,
        }
    }
}

/// FETCH message (type 0x16).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetch {
    /// The request ID for this fetch.
    pub request_id: VarInt,
    /// Subscriber priority for delivery ordering.
    pub subscriber_priority: u8,
    /// Requested group delivery order (VarInt).
    pub group_order: VarInt,
    /// The fetch type discriminant.
    pub fetch_type: FetchType,
    /// Fetch-type-specific payload.
    pub fetch_payload: FetchPayload,
    /// Fetch parameters (even/odd KVP encoding).
    pub parameters: Vec<KeyValuePair>,
}

/// Fetch-type-specific payload fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchPayload {
    /// Standalone fetch (type 1).
    Standalone {
        /// The track namespace.
        track_namespace: TrackNamespace,
        /// The track name.
        track_name: Vec<u8>,
        /// Start group ID.
        start_group: VarInt,
        /// Start object ID.
        start_object: VarInt,
        /// End group ID.
        end_group: VarInt,
        /// End object ID.
        end_object: VarInt,
    },
    /// Joining fetch (types 2 and 3).
    Joining {
        /// The subscribe request ID to join.
        joining_subscribe_id: VarInt,
        /// The joining start (offset for relative, group for absolute).
        joining_start: VarInt,
    },
}

/// FETCH_OK message (type 0x18).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchOk {
    /// The request ID this response corresponds to.
    pub request_id: VarInt,
    /// The group delivery order chosen by the publisher (VarInt).
    pub group_order: VarInt,
    /// Whether the end of the track has been reached (VarInt).
    pub end_of_track: VarInt,
    /// The end location of the fetch response.
    pub end_location: Location,
    /// Response parameters (even/odd KVP encoding).
    pub parameters: Vec<KeyValuePair>,
}

/// FETCH_ERROR message (type 0x19).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchError {
    /// The request ID this error corresponds to.
    pub request_id: VarInt,
    /// Application-defined error code.
    pub error_code: VarInt,
    /// Human-readable reason phrase.
    pub reason_phrase: Vec<u8>,
}

/// FETCH_CANCEL message (type 0x17).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchCancel {
    /// The request ID of the fetch to cancel.
    pub request_id: VarInt,
}

// ============================================================
// Unified Message Enum
// ============================================================

/// A parsed MoQT control message (draft-11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlMessage {
    /// ClientSetup (type 0x20).
    ClientSetup(ClientSetup),
    /// ServerSetup (type 0x21).
    ServerSetup(ServerSetup),
    /// GoAway (type 0x10).
    GoAway(GoAway),
    /// MaxRequestId (type 0x15).
    MaxRequestId(MaxRequestId),
    /// RequestsBlocked (type 0x1A).
    RequestsBlocked(RequestsBlocked),
    /// Subscribe (type 0x03).
    Subscribe(Subscribe),
    /// SubscribeOk (type 0x04).
    SubscribeOk(SubscribeOk),
    /// SubscribeError (type 0x05).
    SubscribeError(SubscribeError),
    /// SubscribeUpdate (type 0x02).
    SubscribeUpdate(SubscribeUpdate),
    /// SubscribeDone (type 0x0B).
    SubscribeDone(SubscribeDone),
    /// Unsubscribe (type 0x0A).
    Unsubscribe(Unsubscribe),
    /// Announce (type 0x06).
    Announce(Announce),
    /// AnnounceOk (type 0x07).
    AnnounceOk(AnnounceOk),
    /// AnnounceError (type 0x08).
    AnnounceError(AnnounceError),
    /// AnnounceCancel (type 0x0C).
    AnnounceCancel(AnnounceCancel),
    /// Unannounce (type 0x09).
    Unannounce(Unannounce),
    /// SubscribeAnnounces (type 0x11).
    SubscribeAnnounces(SubscribeAnnounces),
    /// SubscribeAnnouncesOk (type 0x12).
    SubscribeAnnouncesOk(SubscribeAnnouncesOk),
    /// SubscribeAnnouncesError (type 0x13).
    SubscribeAnnouncesError(SubscribeAnnouncesError),
    /// UnsubscribeAnnounces (type 0x14).
    UnsubscribeAnnounces(UnsubscribeAnnounces),
    /// TrackStatusRequest (type 0x0D).
    TrackStatusRequest(TrackStatusRequest),
    /// TrackStatus (type 0x0E).
    TrackStatus(TrackStatus),
    /// Fetch (type 0x16).
    Fetch(Fetch),
    /// FetchOk (type 0x18).
    FetchOk(FetchOk),
    /// FetchError (type 0x19).
    FetchError(FetchError),
    /// FetchCancel (type 0x17).
    FetchCancel(FetchCancel),
}

impl ControlMessage {
    /// Encode this control message to bytes (including type ID and length prefix).
    ///
    /// Draft-11 framing: type_id(vi) + payload_length(16) + payload.
    pub fn encode(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        let mut payload = Vec::with_capacity(256);
        self.encode_payload(&mut payload)?;

        if payload.len() > MAX_MESSAGE_LENGTH {
            return Err(CodecError::MessageTooLong(payload.len()));
        }

        VarInt::from_usize(self.message_type().id() as usize).encode(buf);
        // Draft-11: 16-bit length (big-endian)
        buf.put_u16(payload.len() as u16);
        buf.put_slice(&payload);
        Ok(())
    }

    /// Decode a control message from bytes (reads type ID and length prefix first).
    ///
    /// Draft-11 framing: type_id(vi) + payload_length(16) + payload.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let type_id = VarInt::decode(buf)?.into_inner();
        let msg_type =
            MessageType::from_id(type_id).ok_or(CodecError::UnknownMessageType(type_id))?;
        // Draft-11: 16-bit length (big-endian)
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
                m.track_alias.encode(buf);
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
                m.track_alias.encode(buf);
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
            ControlMessage::SubscribeAnnounces(m) => {
                m.request_id.encode(buf);
                m.track_namespace_prefix.encode(buf);
                KeyValuePair::encode_list(&m.parameters, buf);
            }
            ControlMessage::SubscribeAnnouncesOk(m) => {
                m.request_id.encode(buf);
            }
            ControlMessage::SubscribeAnnouncesError(m) => {
                if m.reason_phrase.len() > MAX_REASON_PHRASE_LENGTH {
                    return Err(CodecError::ReasonPhraseTooLong);
                }
                m.request_id.encode(buf);
                m.error_code.encode(buf);
                VarInt::from_usize(m.reason_phrase.len()).encode(buf);
                buf.put_slice(&m.reason_phrase);
            }
            ControlMessage::UnsubscribeAnnounces(m) => {
                m.track_namespace_prefix.encode(buf);
            }
            ControlMessage::TrackStatusRequest(m) => {
                m.request_id.encode(buf);
                m.track_namespace.encode(buf);
                VarInt::from_usize(m.track_name.len()).encode(buf);
                buf.put_slice(&m.track_name);
                KeyValuePair::encode_list(&m.parameters, buf);
            }
            ControlMessage::TrackStatus(m) => {
                m.request_id.encode(buf);
                m.status_code.encode(buf);
                m.largest_location.encode(buf);
                KeyValuePair::encode_list(&m.parameters, buf);
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
                let uri = types::read_bytes(buf, uri_len)?;
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
                let track_alias = VarInt::decode(buf)?;
                let track_namespace = TrackNamespace::decode(buf)?;
                let track_name_len = VarInt::decode(buf)?.into_inner() as usize;
                let track_name = types::read_bytes(buf, track_name_len)?;
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
                    track_alias,
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
                let reason_phrase = types::read_bytes(buf, reason_len)?;
                let track_alias = VarInt::decode(buf)?;
                Ok(ControlMessage::SubscribeError(SubscribeError {
                    request_id,
                    error_code,
                    reason_phrase,
                    track_alias,
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
                let reason_phrase = types::read_bytes(buf, reason_len)?;
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
                let reason_phrase = types::read_bytes(buf, reason_len)?;
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
                let reason_phrase = types::read_bytes(buf, reason_len)?;
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
            MessageType::SubscribeAnnounces => {
                let request_id = VarInt::decode(buf)?;
                let track_namespace_prefix = TrackNamespace::decode(buf)?;
                let parameters = KeyValuePair::decode_list(buf)?;
                Ok(ControlMessage::SubscribeAnnounces(SubscribeAnnounces {
                    request_id,
                    track_namespace_prefix,
                    parameters,
                }))
            }
            MessageType::SubscribeAnnouncesOk => {
                let request_id = VarInt::decode(buf)?;
                Ok(ControlMessage::SubscribeAnnouncesOk(SubscribeAnnouncesOk { request_id }))
            }
            MessageType::SubscribeAnnouncesError => {
                let request_id = VarInt::decode(buf)?;
                let error_code = VarInt::decode(buf)?;
                let reason_len = VarInt::decode(buf)?.into_inner() as usize;
                let reason_phrase = types::read_bytes(buf, reason_len)?;
                Ok(ControlMessage::SubscribeAnnouncesError(SubscribeAnnouncesError {
                    request_id,
                    error_code,
                    reason_phrase,
                }))
            }
            MessageType::UnsubscribeAnnounces => {
                let track_namespace_prefix = TrackNamespace::decode(buf)?;
                Ok(ControlMessage::UnsubscribeAnnounces(UnsubscribeAnnounces {
                    track_namespace_prefix,
                }))
            }
            MessageType::TrackStatusRequest => {
                let request_id = VarInt::decode(buf)?;
                let track_namespace = TrackNamespace::decode(buf)?;
                let track_name_len = VarInt::decode(buf)?.into_inner() as usize;
                let track_name = types::read_bytes(buf, track_name_len)?;
                let parameters = KeyValuePair::decode_list(buf)?;
                Ok(ControlMessage::TrackStatusRequest(TrackStatusRequest {
                    request_id,
                    track_namespace,
                    track_name,
                    parameters,
                }))
            }
            MessageType::TrackStatus => {
                let request_id = VarInt::decode(buf)?;
                let status_code = VarInt::decode(buf)?;
                let largest_location = Location::decode(buf)?;
                let parameters = KeyValuePair::decode_list(buf)?;
                Ok(ControlMessage::TrackStatus(TrackStatus {
                    request_id,
                    status_code,
                    largest_location,
                    parameters,
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
                        let track_name = types::read_bytes(buf, track_name_len)?;
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
                let reason_phrase = types::read_bytes(buf, reason_len)?;
                Ok(ControlMessage::FetchError(FetchError { request_id, error_code, reason_phrase }))
            }
            MessageType::FetchCancel => {
                let request_id = VarInt::decode(buf)?;
                Ok(ControlMessage::FetchCancel(FetchCancel { request_id }))
            }
        }
    }

    /// Get the message type ID for this message.
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
            ControlMessage::SubscribeAnnounces(_) => MessageType::SubscribeAnnounces,
            ControlMessage::SubscribeAnnouncesOk(_) => MessageType::SubscribeAnnouncesOk,
            ControlMessage::SubscribeAnnouncesError(_) => MessageType::SubscribeAnnouncesError,
            ControlMessage::UnsubscribeAnnounces(_) => MessageType::UnsubscribeAnnounces,
            ControlMessage::TrackStatusRequest(_) => MessageType::TrackStatusRequest,
            ControlMessage::TrackStatus(_) => MessageType::TrackStatus,
            ControlMessage::Fetch(_) => MessageType::Fetch,
            ControlMessage::FetchOk(_) => MessageType::FetchOk,
            ControlMessage::FetchError(_) => MessageType::FetchError,
            ControlMessage::FetchCancel(_) => MessageType::FetchCancel,
        }
    }
}

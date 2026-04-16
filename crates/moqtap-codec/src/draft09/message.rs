//! Draft-09 control message encoding and decoding.
//!
//! Wire format is identical to draft-08 except `filter_type=1`
//! (NextGroupStart/LatestGroup) is removed from SUBSCRIBE.

use crate::error::{
    CodecError, MAX_GOAWAY_URI_LENGTH, MAX_MESSAGE_LENGTH, MAX_REASON_PHRASE_LENGTH,
};
use crate::kvp::KeyValuePair;
use crate::types::read_bytes;
use crate::types::*;
use crate::varint::VarInt;
use bytes::{Buf, BufMut};

/// Control message type IDs (draft-09).
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
    /// MaxSubscribeId (type 0x15).
    MaxSubscribeId = 0x15,
    /// Fetch (type 0x16).
    Fetch = 0x16,
    /// FetchCancel (type 0x17).
    FetchCancel = 0x17,
    /// FetchOk (type 0x18).
    FetchOk = 0x18,
    /// FetchError (type 0x19).
    FetchError = 0x19,
    /// SubscribesBlocked (type 0x1A).
    SubscribesBlocked = 0x1A,
    /// ClientSetup (type 0x40).
    ClientSetup = 0x40,
    /// ServerSetup (type 0x41).
    ServerSetup = 0x41,
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
            0x15 => Some(MessageType::MaxSubscribeId),
            0x16 => Some(MessageType::Fetch),
            0x17 => Some(MessageType::FetchCancel),
            0x18 => Some(MessageType::FetchOk),
            0x19 => Some(MessageType::FetchError),
            0x1A => Some(MessageType::SubscribesBlocked),
            0x40 => Some(MessageType::ClientSetup),
            0x41 => Some(MessageType::ServerSetup),
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

/// CLIENT_SETUP message (type 0x40).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSetup {
    /// The list of MoQT versions supported by the client.
    pub supported_versions: Vec<VarInt>,
    /// Setup parameters sent by the client.
    pub parameters: Vec<KeyValuePair>,
}

/// SERVER_SETUP message (type 0x41).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerSetup {
    /// The MoQT version selected by the server.
    pub selected_version: VarInt,
    /// Setup parameters sent by the server.
    pub parameters: Vec<KeyValuePair>,
}

/// GOAWAY message (type 0x10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoAway {
    /// The URI for the new session the client should connect to.
    pub new_session_uri: Vec<u8>,
}

/// MAX_SUBSCRIBE_ID message (type 0x15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaxSubscribeId {
    /// The maximum subscribe ID the peer is willing to accept.
    pub subscribe_id: VarInt,
}

/// SUBSCRIBES_BLOCKED message (type 0x1A).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribesBlocked {
    /// The maximum subscribe ID advertised by the peer.
    pub maximum_subscribe_id: VarInt,
}

// ============================================================
// Subscribe Messages
// ============================================================

/// SUBSCRIBE message (type 0x03).
///
/// Draft-09: filter_type=1 (NextGroupStart) is rejected on decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscribe {
    /// The subscribe ID for this request.
    pub subscribe_id: VarInt,
    /// The track alias assigned by the subscriber.
    pub track_alias: VarInt,
    /// The track namespace to subscribe to.
    pub track_namespace: TrackNamespace,
    /// The track name within the namespace.
    pub track_name: Vec<u8>,
    /// The priority of this subscriber relative to others.
    pub subscriber_priority: u8,
    /// The requested group delivery order.
    pub group_order: GroupOrder,
    /// The filter type controlling which objects are delivered.
    pub filter_type: FilterType,
    /// Present only for AbsoluteStart and AbsoluteRange filter types.
    pub start_location: Option<Location>,
    /// Present only for AbsoluteRange filter type (end_group only, no end_object).
    pub end_group: Option<VarInt>,
    /// Subscribe parameters.
    pub parameters: Vec<KeyValuePair>,
}

/// SUBSCRIBE_OK message (type 0x04).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeOk {
    /// The subscribe ID this response corresponds to.
    pub subscribe_id: VarInt,
    /// The expiration time for this subscription in milliseconds.
    pub expires: VarInt,
    /// The group delivery order chosen by the publisher.
    pub group_order: GroupOrder,
    /// Whether the largest location is included.
    pub content_exists: ContentExists,
    /// Present only when content_exists == HasLargestLocation.
    pub largest_group_id: Option<VarInt>,
    /// Present only when content_exists == HasLargestLocation.
    pub largest_object_id: Option<VarInt>,
    /// Subscribe OK parameters.
    pub parameters: Vec<KeyValuePair>,
}

/// SUBSCRIBE_ERROR message (type 0x05).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeError {
    /// The subscribe ID this error corresponds to.
    pub subscribe_id: VarInt,
    /// The error code indicating the reason for failure.
    pub error_code: VarInt,
    /// A human-readable reason for the error.
    pub reason_phrase: Vec<u8>,
    /// The track alias from the original subscribe request.
    pub track_alias: VarInt,
}

/// SUBSCRIBE_UPDATE message (type 0x02).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeUpdate {
    /// The subscribe ID to update.
    pub subscribe_id: VarInt,
    /// The new start group.
    pub start_group: VarInt,
    /// The new start object.
    pub start_object: VarInt,
    /// The new end group.
    pub end_group: VarInt,
    /// The updated subscriber priority.
    pub subscriber_priority: u8,
    /// Updated subscribe parameters.
    pub parameters: Vec<KeyValuePair>,
}

/// SUBSCRIBE_DONE message (type 0x0B).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeDone {
    /// The subscribe ID this message refers to.
    pub subscribe_id: VarInt,
    /// The status code for the subscription completion.
    pub status_code: VarInt,
    /// Number of streams delivered.
    pub stream_count: VarInt,
    /// A human-readable reason phrase.
    pub reason_phrase: Vec<u8>,
}

/// UNSUBSCRIBE message (type 0x0A).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unsubscribe {
    /// The subscribe ID to unsubscribe from.
    pub subscribe_id: VarInt,
}

// ============================================================
// Announce Messages
// ============================================================

/// ANNOUNCE message (type 0x06).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Announce {
    /// The track namespace being announced.
    pub track_namespace: TrackNamespace,
    /// Announce parameters.
    pub parameters: Vec<KeyValuePair>,
}

/// ANNOUNCE_OK message (type 0x07).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnounceOk {
    /// The track namespace that was accepted.
    pub track_namespace: TrackNamespace,
}

/// ANNOUNCE_ERROR message (type 0x08).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnounceError {
    /// The track namespace that was rejected.
    pub track_namespace: TrackNamespace,
    /// The error code indicating the reason for failure.
    pub error_code: VarInt,
    /// A human-readable reason for the error.
    pub reason_phrase: Vec<u8>,
}

/// ANNOUNCE_CANCEL message (type 0x0C).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnounceCancel {
    /// The track namespace being cancelled.
    pub track_namespace: TrackNamespace,
    /// The error code indicating the reason for cancellation.
    pub error_code: VarInt,
    /// A human-readable reason for the cancellation.
    pub reason_phrase: Vec<u8>,
}

/// UNANNOUNCE message (type 0x09).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unannounce {
    /// The track namespace being unannounced.
    pub track_namespace: TrackNamespace,
}

// ============================================================
// Subscribe Announces Messages
// ============================================================

/// SUBSCRIBE_ANNOUNCES message (type 0x11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeAnnounces {
    /// The track namespace prefix to subscribe to announcements for.
    pub track_namespace_prefix: TrackNamespace,
    /// Subscribe announces parameters.
    pub parameters: Vec<KeyValuePair>,
}

/// SUBSCRIBE_ANNOUNCES_OK message (type 0x12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeAnnouncesOk {
    /// The track namespace prefix that was accepted.
    pub track_namespace_prefix: TrackNamespace,
}

/// SUBSCRIBE_ANNOUNCES_ERROR message (type 0x13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeAnnouncesError {
    /// The track namespace prefix that was rejected.
    pub track_namespace_prefix: TrackNamespace,
    /// The error code indicating the reason for failure.
    pub error_code: VarInt,
    /// A human-readable reason for the error.
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
    /// The track namespace to query status for.
    pub track_namespace: TrackNamespace,
    /// The track name to query status for.
    pub track_name: Vec<u8>,
}

/// TRACK_STATUS message (type 0x0E).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackStatus {
    /// The track namespace this status is for.
    pub track_namespace: TrackNamespace,
    /// The track name this status is for.
    pub track_name: Vec<u8>,
    /// The status code for the track.
    pub status_code: VarInt,
    /// The last group ID available on this track.
    pub last_group_id: VarInt,
    /// The last object ID available on this track.
    pub last_object_id: VarInt,
}

// ============================================================
// Fetch Messages
// ============================================================

/// Fetch type for FETCH message (draft-09).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum FetchType {
    /// Standalone fetch with explicit track and range.
    Standalone = 1,
    /// Joining fetch referencing an existing subscription.
    Joining = 2,
}

impl FetchType {
    /// Convert a raw value to a `FetchType`, if valid.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            1 => Some(FetchType::Standalone),
            2 => Some(FetchType::Joining),
            _ => None,
        }
    }
}

/// FETCH message (type 0x16).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetch {
    /// The subscribe ID for this fetch request.
    pub subscribe_id: VarInt,
    /// The priority of this subscriber relative to others.
    pub subscriber_priority: u8,
    /// The requested group delivery order.
    pub group_order: GroupOrder,
    /// The fetch type (standalone or joining).
    pub fetch_type: FetchType,
    /// Track namespace (standalone only).
    pub track_namespace: Option<TrackNamespace>,
    /// Track name (standalone only).
    pub track_name: Option<Vec<u8>>,
    /// Start group (standalone only).
    pub start_group: Option<VarInt>,
    /// Start object (standalone only).
    pub start_object: Option<VarInt>,
    /// End group (standalone only).
    pub end_group: Option<VarInt>,
    /// End object (standalone only).
    pub end_object: Option<VarInt>,
    /// Joining subscribe ID (joining only).
    pub joining_subscribe_id: Option<VarInt>,
    /// Preceding group offset (joining only).
    pub preceding_group_offset: Option<VarInt>,
    /// Fetch parameters.
    pub parameters: Vec<KeyValuePair>,
}

/// FETCH_OK message (type 0x18).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchOk {
    /// The subscribe ID this response corresponds to.
    pub subscribe_id: VarInt,
    /// The group delivery order chosen by the publisher.
    pub group_order: GroupOrder,
    /// Whether this fetch reaches the end of the track (1 = yes).
    pub end_of_track: u8,
    /// The largest group ID available.
    pub largest_group_id: VarInt,
    /// The largest object ID available.
    pub largest_object_id: VarInt,
    /// Fetch OK parameters.
    pub parameters: Vec<KeyValuePair>,
}

/// FETCH_ERROR message (type 0x19).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchError {
    /// The subscribe ID this error corresponds to.
    pub subscribe_id: VarInt,
    /// The error code indicating the reason for failure.
    pub error_code: VarInt,
    /// A human-readable reason for the error.
    pub reason_phrase: Vec<u8>,
}

/// FETCH_CANCEL message (type 0x17).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchCancel {
    /// The subscribe ID for the fetch to cancel.
    pub subscribe_id: VarInt,
}

// ============================================================
// Unified Message Enum
// ============================================================

/// A decoded MoQT control message (draft-09).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlMessage {
    /// ClientSetup (type 0x40).
    ClientSetup(ClientSetup),
    /// ServerSetup (type 0x41).
    ServerSetup(ServerSetup),
    /// GoAway (type 0x10).
    GoAway(GoAway),
    /// MaxSubscribeId (type 0x15).
    MaxSubscribeId(MaxSubscribeId),
    /// SubscribesBlocked (type 0x1A).
    SubscribesBlocked(SubscribesBlocked),
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
    /// Return the message type for this control message.
    pub fn message_type(&self) -> MessageType {
        match self {
            ControlMessage::ClientSetup(_) => MessageType::ClientSetup,
            ControlMessage::ServerSetup(_) => MessageType::ServerSetup,
            ControlMessage::GoAway(_) => MessageType::GoAway,
            ControlMessage::MaxSubscribeId(_) => MessageType::MaxSubscribeId,
            ControlMessage::SubscribesBlocked(_) => MessageType::SubscribesBlocked,
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

    /// Encode this control message (type ID + length prefix + payload).
    pub fn encode(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        let mut payload = Vec::with_capacity(256);
        self.encode_payload(&mut payload)?;

        if payload.len() > MAX_MESSAGE_LENGTH {
            return Err(CodecError::MessageTooLong(payload.len()));
        }

        VarInt::from_usize(self.message_type().id() as usize).encode(buf);
        VarInt::from_usize(payload.len()).encode(buf);
        buf.put_slice(&payload);
        Ok(())
    }

    /// Decode a control message from bytes.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let type_id = VarInt::decode(buf)?.into_inner();
        let msg_type =
            MessageType::from_id(type_id).ok_or(CodecError::UnknownMessageType(type_id))?;
        let payload_len = VarInt::decode(buf)?.into_inner() as usize;
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
                KeyValuePair::encode_list_d07(&m.parameters, buf);
            }
            ControlMessage::ServerSetup(m) => {
                m.selected_version.encode(buf);
                KeyValuePair::encode_list_d07(&m.parameters, buf);
            }
            ControlMessage::GoAway(m) => {
                if m.new_session_uri.len() > MAX_GOAWAY_URI_LENGTH {
                    return Err(CodecError::GoAwayUriTooLong);
                }
                VarInt::from_usize(m.new_session_uri.len()).encode(buf);
                buf.put_slice(&m.new_session_uri);
            }
            ControlMessage::MaxSubscribeId(m) => {
                m.subscribe_id.encode(buf);
            }
            ControlMessage::SubscribesBlocked(m) => {
                m.maximum_subscribe_id.encode(buf);
            }
            ControlMessage::Subscribe(m) => {
                m.subscribe_id.encode(buf);
                m.track_alias.encode(buf);
                m.track_namespace.encode(buf);
                VarInt::from_usize(m.track_name.len()).encode(buf);
                buf.put_slice(&m.track_name);
                buf.put_u8(m.subscriber_priority);
                buf.put_u8(m.group_order as u8);
                VarInt::from_usize(m.filter_type as usize).encode(buf);
                if let Some(loc) = &m.start_location {
                    loc.encode(buf);
                }
                if let Some(eg) = &m.end_group {
                    eg.encode(buf);
                }
                KeyValuePair::encode_list_d07(&m.parameters, buf);
            }
            ControlMessage::SubscribeOk(m) => {
                m.subscribe_id.encode(buf);
                m.expires.encode(buf);
                buf.put_u8(m.group_order as u8);
                buf.put_u8(m.content_exists as u8);
                if let Some(gid) = &m.largest_group_id {
                    gid.encode(buf);
                }
                if let Some(oid) = &m.largest_object_id {
                    oid.encode(buf);
                }
                KeyValuePair::encode_list_d07(&m.parameters, buf);
            }
            ControlMessage::SubscribeError(m) => {
                if m.reason_phrase.len() > MAX_REASON_PHRASE_LENGTH {
                    return Err(CodecError::ReasonPhraseTooLong);
                }
                m.subscribe_id.encode(buf);
                m.error_code.encode(buf);
                VarInt::from_usize(m.reason_phrase.len()).encode(buf);
                buf.put_slice(&m.reason_phrase);
                m.track_alias.encode(buf);
            }
            ControlMessage::SubscribeUpdate(m) => {
                m.subscribe_id.encode(buf);
                m.start_group.encode(buf);
                m.start_object.encode(buf);
                m.end_group.encode(buf);
                buf.put_u8(m.subscriber_priority);
                KeyValuePair::encode_list_d07(&m.parameters, buf);
            }
            ControlMessage::SubscribeDone(m) => {
                if m.reason_phrase.len() > MAX_REASON_PHRASE_LENGTH {
                    return Err(CodecError::ReasonPhraseTooLong);
                }
                m.subscribe_id.encode(buf);
                m.status_code.encode(buf);
                m.stream_count.encode(buf);
                VarInt::from_usize(m.reason_phrase.len()).encode(buf);
                buf.put_slice(&m.reason_phrase);
            }
            ControlMessage::Unsubscribe(m) => {
                m.subscribe_id.encode(buf);
            }
            ControlMessage::Announce(m) => {
                m.track_namespace.encode(buf);
                KeyValuePair::encode_list_d07(&m.parameters, buf);
            }
            ControlMessage::AnnounceOk(m) => {
                m.track_namespace.encode(buf);
            }
            ControlMessage::AnnounceError(m) => {
                if m.reason_phrase.len() > MAX_REASON_PHRASE_LENGTH {
                    return Err(CodecError::ReasonPhraseTooLong);
                }
                m.track_namespace.encode(buf);
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
                m.track_namespace_prefix.encode(buf);
                KeyValuePair::encode_list_d07(&m.parameters, buf);
            }
            ControlMessage::SubscribeAnnouncesOk(m) => {
                m.track_namespace_prefix.encode(buf);
            }
            ControlMessage::SubscribeAnnouncesError(m) => {
                if m.reason_phrase.len() > MAX_REASON_PHRASE_LENGTH {
                    return Err(CodecError::ReasonPhraseTooLong);
                }
                m.track_namespace_prefix.encode(buf);
                m.error_code.encode(buf);
                VarInt::from_usize(m.reason_phrase.len()).encode(buf);
                buf.put_slice(&m.reason_phrase);
            }
            ControlMessage::UnsubscribeAnnounces(m) => {
                m.track_namespace_prefix.encode(buf);
            }
            ControlMessage::TrackStatusRequest(m) => {
                m.track_namespace.encode(buf);
                VarInt::from_usize(m.track_name.len()).encode(buf);
                buf.put_slice(&m.track_name);
            }
            ControlMessage::TrackStatus(m) => {
                m.track_namespace.encode(buf);
                VarInt::from_usize(m.track_name.len()).encode(buf);
                buf.put_slice(&m.track_name);
                m.status_code.encode(buf);
                m.last_group_id.encode(buf);
                m.last_object_id.encode(buf);
            }
            ControlMessage::Fetch(m) => {
                m.subscribe_id.encode(buf);
                buf.put_u8(m.subscriber_priority);
                buf.put_u8(m.group_order as u8);
                VarInt::from_usize(m.fetch_type as usize).encode(buf);
                match m.fetch_type {
                    FetchType::Standalone => {
                        if let Some(ns) = &m.track_namespace {
                            ns.encode(buf);
                        }
                        if let Some(name) = &m.track_name {
                            VarInt::from_usize(name.len()).encode(buf);
                            buf.put_slice(name);
                        }
                        if let Some(sg) = &m.start_group {
                            sg.encode(buf);
                        }
                        if let Some(so) = &m.start_object {
                            so.encode(buf);
                        }
                        if let Some(eg) = &m.end_group {
                            eg.encode(buf);
                        }
                        if let Some(eo) = &m.end_object {
                            eo.encode(buf);
                        }
                    }
                    FetchType::Joining => {
                        if let Some(jsi) = &m.joining_subscribe_id {
                            jsi.encode(buf);
                        }
                        if let Some(pgo) = &m.preceding_group_offset {
                            pgo.encode(buf);
                        }
                    }
                }
                KeyValuePair::encode_list_d07(&m.parameters, buf);
            }
            ControlMessage::FetchOk(m) => {
                m.subscribe_id.encode(buf);
                buf.put_u8(m.group_order as u8);
                buf.put_u8(m.end_of_track);
                m.largest_group_id.encode(buf);
                m.largest_object_id.encode(buf);
                KeyValuePair::encode_list_d07(&m.parameters, buf);
            }
            ControlMessage::FetchError(m) => {
                if m.reason_phrase.len() > MAX_REASON_PHRASE_LENGTH {
                    return Err(CodecError::ReasonPhraseTooLong);
                }
                m.subscribe_id.encode(buf);
                m.error_code.encode(buf);
                VarInt::from_usize(m.reason_phrase.len()).encode(buf);
                buf.put_slice(&m.reason_phrase);
            }
            ControlMessage::FetchCancel(m) => {
                m.subscribe_id.encode(buf);
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
                let parameters = KeyValuePair::decode_list_d07(buf)?;
                Ok(ControlMessage::ClientSetup(ClientSetup { supported_versions, parameters }))
            }
            MessageType::ServerSetup => {
                let selected_version = VarInt::decode(buf)?;
                let parameters = KeyValuePair::decode_list_d07(buf)?;
                Ok(ControlMessage::ServerSetup(ServerSetup { selected_version, parameters }))
            }
            MessageType::GoAway => {
                let uri_len = VarInt::decode(buf)?.into_inner() as usize;
                let uri = read_bytes(buf, uri_len)?;
                Ok(ControlMessage::GoAway(GoAway { new_session_uri: uri }))
            }
            MessageType::MaxSubscribeId => {
                let subscribe_id = VarInt::decode(buf)?;
                Ok(ControlMessage::MaxSubscribeId(MaxSubscribeId { subscribe_id }))
            }
            MessageType::SubscribesBlocked => {
                let maximum_subscribe_id = VarInt::decode(buf)?;
                Ok(ControlMessage::SubscribesBlocked(SubscribesBlocked { maximum_subscribe_id }))
            }
            MessageType::Subscribe => {
                let subscribe_id = VarInt::decode(buf)?;
                let track_alias = VarInt::decode(buf)?;
                let track_namespace = TrackNamespace::decode(buf)?;
                let track_name_len = VarInt::decode(buf)?.into_inner() as usize;
                let track_name = read_bytes(buf, track_name_len)?;
                if buf.remaining() < 2 {
                    return Err(CodecError::UnexpectedEnd);
                }
                let subscriber_priority = buf.get_u8();
                let group_order =
                    GroupOrder::from_u8(buf.get_u8()).ok_or(CodecError::InvalidField)?;
                let filter_val = VarInt::decode(buf)?.into_inner();
                // Draft-09: filter_type=1 (NextGroupStart/LatestGroup) is removed.
                if filter_val == 1 {
                    return Err(CodecError::InvalidField);
                }
                let filter_type =
                    FilterType::from_u64(filter_val).ok_or(CodecError::InvalidField)?;
                let start_location = match filter_type {
                    FilterType::AbsoluteStart | FilterType::AbsoluteRange => {
                        Some(Location::decode(buf)?)
                    }
                    _ => None,
                };
                let end_group = match filter_type {
                    FilterType::AbsoluteRange => Some(VarInt::decode(buf)?),
                    _ => None,
                };
                let parameters = KeyValuePair::decode_list_d07(buf)?;
                Ok(ControlMessage::Subscribe(Subscribe {
                    subscribe_id,
                    track_alias,
                    track_namespace,
                    track_name,
                    subscriber_priority,
                    group_order,
                    filter_type,
                    start_location,
                    end_group,
                    parameters,
                }))
            }
            MessageType::SubscribeOk => {
                let subscribe_id = VarInt::decode(buf)?;
                let expires = VarInt::decode(buf)?;
                if buf.remaining() < 2 {
                    return Err(CodecError::UnexpectedEnd);
                }
                let group_order =
                    GroupOrder::from_u8(buf.get_u8()).ok_or(CodecError::InvalidField)?;
                let content_exists_val = buf.get_u8();
                let content_exists = match content_exists_val {
                    0 => ContentExists::NoLargestLocation,
                    1 => ContentExists::HasLargestLocation,
                    _ => return Err(CodecError::InvalidField),
                };
                let (largest_group_id, largest_object_id) =
                    if content_exists == ContentExists::HasLargestLocation {
                        let gid = VarInt::decode(buf)?;
                        let oid = VarInt::decode(buf)?;
                        (Some(gid), Some(oid))
                    } else {
                        (None, None)
                    };
                let parameters = KeyValuePair::decode_list_d07(buf)?;
                Ok(ControlMessage::SubscribeOk(SubscribeOk {
                    subscribe_id,
                    expires,
                    group_order,
                    content_exists,
                    largest_group_id,
                    largest_object_id,
                    parameters,
                }))
            }
            MessageType::SubscribeError => {
                let subscribe_id = VarInt::decode(buf)?;
                let error_code = VarInt::decode(buf)?;
                let reason_len = VarInt::decode(buf)?.into_inner() as usize;
                let reason_phrase = read_bytes(buf, reason_len)?;
                let track_alias = VarInt::decode(buf)?;
                Ok(ControlMessage::SubscribeError(SubscribeError {
                    subscribe_id,
                    error_code,
                    reason_phrase,
                    track_alias,
                }))
            }
            MessageType::SubscribeUpdate => {
                let subscribe_id = VarInt::decode(buf)?;
                let start_group = VarInt::decode(buf)?;
                let start_object = VarInt::decode(buf)?;
                let end_group = VarInt::decode(buf)?;
                if buf.remaining() < 1 {
                    return Err(CodecError::UnexpectedEnd);
                }
                let subscriber_priority = buf.get_u8();
                let parameters = KeyValuePair::decode_list_d07(buf)?;
                Ok(ControlMessage::SubscribeUpdate(SubscribeUpdate {
                    subscribe_id,
                    start_group,
                    start_object,
                    end_group,
                    subscriber_priority,
                    parameters,
                }))
            }
            MessageType::SubscribeDone => {
                let subscribe_id = VarInt::decode(buf)?;
                let status_code = VarInt::decode(buf)?;
                let stream_count = VarInt::decode(buf)?;
                let reason_len = VarInt::decode(buf)?.into_inner() as usize;
                let reason_phrase = read_bytes(buf, reason_len)?;
                Ok(ControlMessage::SubscribeDone(SubscribeDone {
                    subscribe_id,
                    status_code,
                    stream_count,
                    reason_phrase,
                }))
            }
            MessageType::Unsubscribe => {
                let subscribe_id = VarInt::decode(buf)?;
                Ok(ControlMessage::Unsubscribe(Unsubscribe { subscribe_id }))
            }
            MessageType::Announce => {
                let track_namespace = TrackNamespace::decode(buf)?;
                let parameters = KeyValuePair::decode_list_d07(buf)?;
                Ok(ControlMessage::Announce(Announce { track_namespace, parameters }))
            }
            MessageType::AnnounceOk => {
                let track_namespace = TrackNamespace::decode(buf)?;
                Ok(ControlMessage::AnnounceOk(AnnounceOk { track_namespace }))
            }
            MessageType::AnnounceError => {
                let track_namespace = TrackNamespace::decode(buf)?;
                let error_code = VarInt::decode(buf)?;
                let reason_len = VarInt::decode(buf)?.into_inner() as usize;
                let reason_phrase = read_bytes(buf, reason_len)?;
                Ok(ControlMessage::AnnounceError(AnnounceError {
                    track_namespace,
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
            MessageType::SubscribeAnnounces => {
                let track_namespace_prefix = TrackNamespace::decode(buf)?;
                let parameters = KeyValuePair::decode_list_d07(buf)?;
                Ok(ControlMessage::SubscribeAnnounces(SubscribeAnnounces {
                    track_namespace_prefix,
                    parameters,
                }))
            }
            MessageType::SubscribeAnnouncesOk => {
                let track_namespace_prefix = TrackNamespace::decode(buf)?;
                Ok(ControlMessage::SubscribeAnnouncesOk(SubscribeAnnouncesOk {
                    track_namespace_prefix,
                }))
            }
            MessageType::SubscribeAnnouncesError => {
                let track_namespace_prefix = TrackNamespace::decode(buf)?;
                let error_code = VarInt::decode(buf)?;
                let reason_len = VarInt::decode(buf)?.into_inner() as usize;
                let reason_phrase = read_bytes(buf, reason_len)?;
                Ok(ControlMessage::SubscribeAnnouncesError(SubscribeAnnouncesError {
                    track_namespace_prefix,
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
                let track_namespace = TrackNamespace::decode(buf)?;
                let track_name_len = VarInt::decode(buf)?.into_inner() as usize;
                let track_name = read_bytes(buf, track_name_len)?;
                Ok(ControlMessage::TrackStatusRequest(TrackStatusRequest {
                    track_namespace,
                    track_name,
                }))
            }
            MessageType::TrackStatus => {
                let track_namespace = TrackNamespace::decode(buf)?;
                let track_name_len = VarInt::decode(buf)?.into_inner() as usize;
                let track_name = read_bytes(buf, track_name_len)?;
                let status_code = VarInt::decode(buf)?;
                let last_group_id = VarInt::decode(buf)?;
                let last_object_id = VarInt::decode(buf)?;
                Ok(ControlMessage::TrackStatus(TrackStatus {
                    track_namespace,
                    track_name,
                    status_code,
                    last_group_id,
                    last_object_id,
                }))
            }
            MessageType::Fetch => {
                let subscribe_id = VarInt::decode(buf)?;
                if buf.remaining() < 2 {
                    return Err(CodecError::UnexpectedEnd);
                }
                let subscriber_priority = buf.get_u8();
                let group_order =
                    GroupOrder::from_u8(buf.get_u8()).ok_or(CodecError::InvalidField)?;
                let fetch_type_val = VarInt::decode(buf)?.into_inner();
                let fetch_type =
                    FetchType::from_u64(fetch_type_val).ok_or(CodecError::InvalidField)?;
                let (
                    track_namespace,
                    track_name,
                    start_group,
                    start_object,
                    end_group,
                    end_object,
                    joining_subscribe_id,
                    preceding_group_offset,
                ) = match fetch_type {
                    FetchType::Standalone => {
                        let ns = TrackNamespace::decode(buf)?;
                        let name_len = VarInt::decode(buf)?.into_inner() as usize;
                        let name = read_bytes(buf, name_len)?;
                        let sg = VarInt::decode(buf)?;
                        let so = VarInt::decode(buf)?;
                        let eg = VarInt::decode(buf)?;
                        let eo = VarInt::decode(buf)?;
                        (Some(ns), Some(name), Some(sg), Some(so), Some(eg), Some(eo), None, None)
                    }
                    FetchType::Joining => {
                        let jsi = VarInt::decode(buf)?;
                        let pgo = VarInt::decode(buf)?;
                        (None, None, None, None, None, None, Some(jsi), Some(pgo))
                    }
                };
                let parameters = KeyValuePair::decode_list_d07(buf)?;
                Ok(ControlMessage::Fetch(Fetch {
                    subscribe_id,
                    subscriber_priority,
                    group_order,
                    fetch_type,
                    track_namespace,
                    track_name,
                    start_group,
                    start_object,
                    end_group,
                    end_object,
                    joining_subscribe_id,
                    preceding_group_offset,
                    parameters,
                }))
            }
            MessageType::FetchOk => {
                let subscribe_id = VarInt::decode(buf)?;
                if buf.remaining() < 2 {
                    return Err(CodecError::UnexpectedEnd);
                }
                let group_order =
                    GroupOrder::from_u8(buf.get_u8()).ok_or(CodecError::InvalidField)?;
                let end_of_track = buf.get_u8();
                let largest_group_id = VarInt::decode(buf)?;
                let largest_object_id = VarInt::decode(buf)?;
                let parameters = KeyValuePair::decode_list_d07(buf)?;
                Ok(ControlMessage::FetchOk(FetchOk {
                    subscribe_id,
                    group_order,
                    end_of_track,
                    largest_group_id,
                    largest_object_id,
                    parameters,
                }))
            }
            MessageType::FetchError => {
                let subscribe_id = VarInt::decode(buf)?;
                let error_code = VarInt::decode(buf)?;
                let reason_len = VarInt::decode(buf)?.into_inner() as usize;
                let reason_phrase = read_bytes(buf, reason_len)?;
                Ok(ControlMessage::FetchError(FetchError {
                    subscribe_id,
                    error_code,
                    reason_phrase,
                }))
            }
            MessageType::FetchCancel => {
                let subscribe_id = VarInt::decode(buf)?;
                Ok(ControlMessage::FetchCancel(FetchCancel { subscribe_id }))
            }
        }
    }
}

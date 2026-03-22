pub use crate::error::{
    CodecError, MAX_FULL_TRACK_NAME_LENGTH, MAX_GOAWAY_URI_LENGTH, MAX_MESSAGE_LENGTH,
    MAX_NAMESPACE_TUPLE_SIZE, MAX_REASON_PHRASE_LENGTH,
};
use crate::kvp::KeyValuePair;
use crate::types::*;
use crate::varint::VarInt;
use bytes::{Buf, BufMut};

/// Control message type IDs (draft-14).
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
    /// PublishNamespace (type 0x06).
    PublishNamespace = 0x06,
    /// PublishNamespaceOk (type 0x07).
    PublishNamespaceOk = 0x07,
    /// PublishNamespaceError (type 0x08).
    PublishNamespaceError = 0x08,
    /// PublishNamespaceDone (type 0x09).
    PublishNamespaceDone = 0x09,
    /// Unsubscribe (type 0x0A).
    Unsubscribe = 0x0A,
    /// PublishDone (type 0x0B).
    PublishDone = 0x0B,
    /// PublishNamespaceCancel (type 0x0C).
    PublishNamespaceCancel = 0x0C,
    /// TrackStatus (type 0x0D).
    TrackStatus = 0x0D,
    /// TrackStatusOk (type 0x0E).
    TrackStatusOk = 0x0E,
    /// TrackStatusError (type 0x0F).
    TrackStatusError = 0x0F,
    /// GoAway (type 0x10).
    GoAway = 0x10,
    /// SubscribeNamespace (type 0x11).
    SubscribeNamespace = 0x11,
    /// SubscribeNamespaceOk (type 0x12).
    SubscribeNamespaceOk = 0x12,
    /// SubscribeNamespaceError (type 0x13).
    SubscribeNamespaceError = 0x13,
    /// UnsubscribeNamespace (type 0x14).
    UnsubscribeNamespace = 0x14,
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
    /// Publish (type 0x1D).
    Publish = 0x1D,
    /// PublishOk (type 0x1E).
    PublishOk = 0x1E,
    /// PublishError (type 0x1F).
    PublishError = 0x1F,
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
            0x06 => Some(MessageType::PublishNamespace),
            0x07 => Some(MessageType::PublishNamespaceOk),
            0x08 => Some(MessageType::PublishNamespaceError),
            0x09 => Some(MessageType::PublishNamespaceDone),
            0x0A => Some(MessageType::Unsubscribe),
            0x0B => Some(MessageType::PublishDone),
            0x0C => Some(MessageType::PublishNamespaceCancel),
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
    /// Setup parameters.
    pub parameters: Vec<KeyValuePair>,
}

/// SERVER_SETUP message (type 0x21).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerSetup {
    /// The MoQT version selected by the server.
    pub selected_version: VarInt,
    /// Setup parameters.
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
    /// The track namespace.
    pub track_namespace: TrackNamespace,
    /// The track name within the namespace.
    pub track_name: Vec<u8>,
    /// Subscriber priority for this track.
    pub subscriber_priority: u8,
    /// Requested group delivery order.
    pub group_order: GroupOrder,
    /// Whether to forward data on this subscription.
    pub forward: Forward,
    /// The filter type controlling which objects are delivered.
    pub filter_type: FilterType,
    /// Present only for AbsoluteStart and AbsoluteRange filter types.
    pub start_location: Option<Location>,
    /// Present only for AbsoluteRange filter type.
    pub end_group: Option<VarInt>,
    /// Subscribe parameters.
    pub parameters: Vec<KeyValuePair>,
}

/// SUBSCRIBE_OK message (type 0x04).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeOk {
    /// The request ID this response corresponds to.
    pub request_id: VarInt,
    /// The track alias assigned by the publisher.
    pub track_alias: VarInt,
    /// Subscription expiry in milliseconds (0 = no expiry).
    pub expires: VarInt,
    /// The group delivery order chosen by the publisher.
    pub group_order: GroupOrder,
    /// Whether the largest location is included.
    pub content_exists: ContentExists,
    /// Present only when content_exists == HasLargestLocation.
    pub largest_location: Option<Location>,
    /// Response parameters.
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
}

/// SUBSCRIBE_UPDATE message (type 0x02).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeUpdate {
    /// The request ID of the subscription to update.
    pub request_id: VarInt,
    /// Updated start location.
    pub start_location: Location,
    /// Updated end group.
    pub end_group: VarInt,
    /// Updated subscriber priority.
    pub subscriber_priority: u8,
    /// Updated forward preference.
    pub forward: Forward,
    /// Updated parameters.
    pub parameters: Vec<KeyValuePair>,
}

/// UNSUBSCRIBE message (type 0x0A).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unsubscribe {
    /// The request ID of the subscription to cancel.
    pub request_id: VarInt,
}

// ============================================================
// Publish Messages
// ============================================================

/// PUBLISH message (type 0x1D).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publish {
    /// The request ID for this publish intent.
    pub request_id: VarInt,
    /// The track namespace to publish under.
    pub track_namespace: TrackNamespace,
    /// The track name within the namespace.
    pub track_name: Vec<u8>,
    /// Whether to forward data on this track.
    pub forward: Forward,
    /// Publish parameters.
    pub parameters: Vec<KeyValuePair>,
}

/// PUBLISH_OK message (type 0x1E).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishOk {
    /// The request ID this response corresponds to.
    pub request_id: VarInt,
    /// The track alias assigned by the subscriber.
    pub track_alias: VarInt,
    /// The forward preference.
    pub forward: Forward,
    /// Response parameters.
    pub parameters: Vec<KeyValuePair>,
}

/// PUBLISH_ERROR message (type 0x1F).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishError {
    /// The request ID this error corresponds to.
    pub request_id: VarInt,
    /// Application-defined error code.
    pub error_code: VarInt,
    /// Human-readable reason phrase.
    pub reason_phrase: Vec<u8>,
}

/// PUBLISH_DONE message (type 0x0B).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishDone {
    /// The request ID of the completed publish.
    pub request_id: VarInt,
    /// Status code indicating the reason for completion.
    pub status_code: VarInt,
    /// Human-readable reason phrase.
    pub reason_phrase: Vec<u8>,
}

// ============================================================
// Publish Namespace Messages
// ============================================================

/// PUBLISH_NAMESPACE message (type 0x06).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishNamespace {
    /// The request ID for this namespace publish.
    pub request_id: VarInt,
    /// The track namespace to publish.
    pub track_namespace: TrackNamespace,
    /// Publish namespace parameters.
    pub parameters: Vec<KeyValuePair>,
}

/// PUBLISH_NAMESPACE_OK message (type 0x07).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishNamespaceOk {
    /// The request ID this response corresponds to.
    pub request_id: VarInt,
    /// Response parameters.
    pub parameters: Vec<KeyValuePair>,
}

/// PUBLISH_NAMESPACE_ERROR message (type 0x08).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishNamespaceError {
    /// The request ID this error corresponds to.
    pub request_id: VarInt,
    /// Application-defined error code.
    pub error_code: VarInt,
    /// Human-readable reason phrase.
    pub reason_phrase: Vec<u8>,
}

/// PUBLISH_NAMESPACE_DONE message (type 0x09).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishNamespaceDone {
    /// The request ID of the completed namespace publish.
    pub request_id: VarInt,
    /// Status code indicating the reason for completion.
    pub status_code: VarInt,
    /// Human-readable reason phrase.
    pub reason_phrase: Vec<u8>,
}

/// PUBLISH_NAMESPACE_CANCEL message (type 0x0C).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishNamespaceCancel {
    /// The request ID of the namespace publish to cancel.
    pub request_id: VarInt,
}

// ============================================================
// Subscribe Namespace Messages
// ============================================================

/// SUBSCRIBE_NAMESPACE message (type 0x11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeNamespace {
    /// The request ID for this namespace subscription.
    pub request_id: VarInt,
    /// The track namespace to subscribe to.
    pub track_namespace: TrackNamespace,
    /// Subscribe namespace parameters.
    pub parameters: Vec<KeyValuePair>,
}

/// SUBSCRIBE_NAMESPACE_OK message (type 0x12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeNamespaceOk {
    /// The request ID this response corresponds to.
    pub request_id: VarInt,
    /// Response parameters.
    pub parameters: Vec<KeyValuePair>,
}

/// SUBSCRIBE_NAMESPACE_ERROR message (type 0x13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeNamespaceError {
    /// The request ID this error corresponds to.
    pub request_id: VarInt,
    /// Application-defined error code.
    pub error_code: VarInt,
    /// Human-readable reason phrase.
    pub reason_phrase: Vec<u8>,
}

/// UNSUBSCRIBE_NAMESPACE message (type 0x14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsubscribeNamespace {
    /// The request ID of the namespace subscription to cancel.
    pub request_id: VarInt,
}

// ============================================================
// Fetch Messages
// ============================================================

/// FETCH message (type 0x16).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetch {
    /// The request ID for this fetch.
    pub request_id: VarInt,
    /// The track namespace to fetch from.
    pub track_namespace: TrackNamespace,
    /// The track name within the namespace.
    pub track_name: Vec<u8>,
    /// The starting group ID for the fetch range.
    pub start_group: VarInt,
    /// The starting object ID within the start group.
    pub start_object: VarInt,
    /// The ending group ID for the fetch range.
    pub end_group: VarInt,
    /// Fetch parameters.
    pub parameters: Vec<KeyValuePair>,
}

/// FETCH_OK message (type 0x18).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchOk {
    /// The request ID this response corresponds to.
    pub request_id: VarInt,
    /// The track alias assigned for this fetch.
    pub track_alias: VarInt,
    /// Indicates whether the end of the track has been reached.
    pub end_of_track: VarInt,
    /// Response parameters.
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
// Track Status Messages
// ============================================================

/// TRACK_STATUS message (type 0x0D).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackStatus {
    /// The request ID for this track status query.
    pub request_id: VarInt,
    /// The track namespace to query status for.
    pub track_namespace: TrackNamespace,
    /// The track name within the namespace.
    pub track_name: Vec<u8>,
    /// Track status parameters.
    pub parameters: Vec<KeyValuePair>,
}

/// TRACK_STATUS_OK message (type 0x0E).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackStatusOk {
    /// The request ID this response corresponds to.
    pub request_id: VarInt,
    /// The track status code.
    pub status_code: VarInt,
    /// The largest location, present for IN_PROGRESS and FINISHED statuses.
    pub largest_location: Option<Location>,
    /// Response parameters.
    pub parameters: Vec<KeyValuePair>,
}

/// TRACK_STATUS_ERROR message (type 0x0F).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackStatusError {
    /// The request ID this error corresponds to.
    pub request_id: VarInt,
    /// Application-defined error code.
    pub error_code: VarInt,
    /// Human-readable reason phrase.
    pub reason_phrase: Vec<u8>,
}

// ============================================================
// Unified Message Enum
// ============================================================

/// A parsed MoQT control message (draft-14).
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
    /// Unsubscribe (type 0x0A).
    Unsubscribe(Unsubscribe),
    /// Publish (type 0x1D).
    Publish(Publish),
    /// PublishOk (type 0x1E).
    PublishOk(PublishOk),
    /// PublishError (type 0x1F).
    PublishError(PublishError),
    /// PublishDone (type 0x0B).
    PublishDone(PublishDone),
    /// PublishNamespace (type 0x06).
    PublishNamespace(PublishNamespace),
    /// PublishNamespaceOk (type 0x07).
    PublishNamespaceOk(PublishNamespaceOk),
    /// PublishNamespaceError (type 0x08).
    PublishNamespaceError(PublishNamespaceError),
    /// PublishNamespaceDone (type 0x09).
    PublishNamespaceDone(PublishNamespaceDone),
    /// PublishNamespaceCancel (type 0x0C).
    PublishNamespaceCancel(PublishNamespaceCancel),
    /// SubscribeNamespace (type 0x11).
    SubscribeNamespace(SubscribeNamespace),
    /// SubscribeNamespaceOk (type 0x12).
    SubscribeNamespaceOk(SubscribeNamespaceOk),
    /// SubscribeNamespaceError (type 0x13).
    SubscribeNamespaceError(SubscribeNamespaceError),
    /// UnsubscribeNamespace (type 0x14).
    UnsubscribeNamespace(UnsubscribeNamespace),
    /// Fetch (type 0x16).
    Fetch(Fetch),
    /// FetchOk (type 0x18).
    FetchOk(FetchOk),
    /// FetchError (type 0x19).
    FetchError(FetchError),
    /// FetchCancel (type 0x17).
    FetchCancel(FetchCancel),
    /// TrackStatus (type 0x0D).
    TrackStatus(TrackStatus),
    /// TrackStatusOk (type 0x0E).
    TrackStatusOk(TrackStatusOk),
    /// TrackStatusError (type 0x0F).
    TrackStatusError(TrackStatusError),
}

impl ControlMessage {
    /// Encode this control message to bytes (including type ID and length prefix).
    ///
    /// Draft-14 framing: type_id(vi) + scope(vi=0) + payload_length(vi) + payload.
    pub fn encode(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        // First encode the payload to a temporary buffer
        let mut payload = Vec::new();
        self.encode_payload(&mut payload)?;

        // Write message type ID, scope (always 0), payload length, payload
        VarInt::from_u64(self.message_type().id()).unwrap().encode(buf);
        VarInt::from_u64(0).unwrap().encode(buf); // scope
        VarInt::from_u64(payload.len() as u64).unwrap().encode(buf);
        buf.put_slice(&payload);
        Ok(())
    }

    /// Decode a control message from bytes (reads type ID and length prefix first).
    ///
    /// Draft-14 framing: type_id(vi) + scope(vi) + payload_length(vi) + payload.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let type_id = VarInt::decode(buf)?.into_inner();
        let msg_type =
            MessageType::from_id(type_id).ok_or(CodecError::UnknownMessageType(type_id))?;
        let _scope = VarInt::decode(buf)?; // scope (reserved, always 0)
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
                VarInt::from_u64(m.supported_versions.len() as u64).unwrap().encode(buf);
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
                VarInt::from_u64(m.new_session_uri.len() as u64).unwrap().encode(buf);
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
                VarInt::from_u64(m.track_name.len() as u64).unwrap().encode(buf);
                buf.put_slice(&m.track_name);
                buf.put_u8(m.subscriber_priority);
                buf.put_u8(m.group_order as u8);
                buf.put_u8(m.forward as u8);
                buf.put_u8(m.filter_type as u8);
                if let Some(loc) = &m.start_location {
                    loc.encode(buf);
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
                buf.put_u8(m.group_order as u8);
                buf.put_u8(m.content_exists as u8);
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
                VarInt::from_u64(m.reason_phrase.len() as u64).unwrap().encode(buf);
                buf.put_slice(&m.reason_phrase);
            }
            ControlMessage::SubscribeUpdate(m) => {
                m.request_id.encode(buf);
                m.start_location.encode(buf);
                m.end_group.encode(buf);
                buf.put_u8(m.subscriber_priority);
                buf.put_u8(m.forward as u8);
                KeyValuePair::encode_list(&m.parameters, buf);
            }
            ControlMessage::Unsubscribe(m) => {
                m.request_id.encode(buf);
            }
            ControlMessage::Publish(m) => {
                m.request_id.encode(buf);
                m.track_namespace.encode(buf);
                VarInt::from_u64(m.track_name.len() as u64).unwrap().encode(buf);
                buf.put_slice(&m.track_name);
                buf.put_u8(m.forward as u8);
                KeyValuePair::encode_list(&m.parameters, buf);
            }
            ControlMessage::PublishOk(m) => {
                m.request_id.encode(buf);
                m.track_alias.encode(buf);
                buf.put_u8(m.forward as u8);
                KeyValuePair::encode_list(&m.parameters, buf);
            }
            ControlMessage::PublishError(m) => {
                if m.reason_phrase.len() > MAX_REASON_PHRASE_LENGTH {
                    return Err(CodecError::ReasonPhraseTooLong);
                }
                m.request_id.encode(buf);
                m.error_code.encode(buf);
                VarInt::from_u64(m.reason_phrase.len() as u64).unwrap().encode(buf);
                buf.put_slice(&m.reason_phrase);
            }
            ControlMessage::PublishDone(m) => {
                if m.reason_phrase.len() > MAX_REASON_PHRASE_LENGTH {
                    return Err(CodecError::ReasonPhraseTooLong);
                }
                m.request_id.encode(buf);
                m.status_code.encode(buf);
                VarInt::from_u64(m.reason_phrase.len() as u64).unwrap().encode(buf);
                buf.put_slice(&m.reason_phrase);
            }
            ControlMessage::PublishNamespace(m) => {
                m.request_id.encode(buf);
                m.track_namespace.encode(buf);
                KeyValuePair::encode_list(&m.parameters, buf);
            }
            ControlMessage::PublishNamespaceOk(m) => {
                m.request_id.encode(buf);
                KeyValuePair::encode_list(&m.parameters, buf);
            }
            ControlMessage::PublishNamespaceError(m) => {
                if m.reason_phrase.len() > MAX_REASON_PHRASE_LENGTH {
                    return Err(CodecError::ReasonPhraseTooLong);
                }
                m.request_id.encode(buf);
                m.error_code.encode(buf);
                VarInt::from_u64(m.reason_phrase.len() as u64).unwrap().encode(buf);
                buf.put_slice(&m.reason_phrase);
            }
            ControlMessage::PublishNamespaceDone(m) => {
                if m.reason_phrase.len() > MAX_REASON_PHRASE_LENGTH {
                    return Err(CodecError::ReasonPhraseTooLong);
                }
                m.request_id.encode(buf);
                m.status_code.encode(buf);
                VarInt::from_u64(m.reason_phrase.len() as u64).unwrap().encode(buf);
                buf.put_slice(&m.reason_phrase);
            }
            ControlMessage::PublishNamespaceCancel(m) => {
                m.request_id.encode(buf);
            }
            ControlMessage::SubscribeNamespace(m) => {
                m.request_id.encode(buf);
                m.track_namespace.encode(buf);
                KeyValuePair::encode_list(&m.parameters, buf);
            }
            ControlMessage::SubscribeNamespaceOk(m) => {
                m.request_id.encode(buf);
                KeyValuePair::encode_list(&m.parameters, buf);
            }
            ControlMessage::SubscribeNamespaceError(m) => {
                if m.reason_phrase.len() > MAX_REASON_PHRASE_LENGTH {
                    return Err(CodecError::ReasonPhraseTooLong);
                }
                m.request_id.encode(buf);
                m.error_code.encode(buf);
                VarInt::from_u64(m.reason_phrase.len() as u64).unwrap().encode(buf);
                buf.put_slice(&m.reason_phrase);
            }
            ControlMessage::UnsubscribeNamespace(m) => {
                m.request_id.encode(buf);
            }
            ControlMessage::Fetch(m) => {
                m.request_id.encode(buf);
                m.track_namespace.encode(buf);
                VarInt::from_u64(m.track_name.len() as u64).unwrap().encode(buf);
                buf.put_slice(&m.track_name);
                m.start_group.encode(buf);
                m.start_object.encode(buf);
                m.end_group.encode(buf);
                KeyValuePair::encode_list(&m.parameters, buf);
            }
            ControlMessage::FetchOk(m) => {
                m.request_id.encode(buf);
                m.track_alias.encode(buf);
                m.end_of_track.encode(buf);
                KeyValuePair::encode_list(&m.parameters, buf);
            }
            ControlMessage::FetchError(m) => {
                if m.reason_phrase.len() > MAX_REASON_PHRASE_LENGTH {
                    return Err(CodecError::ReasonPhraseTooLong);
                }
                m.request_id.encode(buf);
                m.error_code.encode(buf);
                VarInt::from_u64(m.reason_phrase.len() as u64).unwrap().encode(buf);
                buf.put_slice(&m.reason_phrase);
            }
            ControlMessage::FetchCancel(m) => {
                m.request_id.encode(buf);
            }
            ControlMessage::TrackStatus(m) => {
                m.request_id.encode(buf);
                m.track_namespace.encode(buf);
                VarInt::from_u64(m.track_name.len() as u64).unwrap().encode(buf);
                buf.put_slice(&m.track_name);
                KeyValuePair::encode_list(&m.parameters, buf);
            }
            ControlMessage::TrackStatusOk(m) => {
                m.request_id.encode(buf);
                m.status_code.encode(buf);
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
                VarInt::from_u64(m.reason_phrase.len() as u64).unwrap().encode(buf);
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
                if buf.remaining() < uri_len {
                    return Err(CodecError::UnexpectedEnd);
                }
                let mut uri = vec![0u8; uri_len];
                buf.copy_to_slice(&mut uri);
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
                if buf.remaining() < track_name_len {
                    return Err(CodecError::UnexpectedEnd);
                }
                let mut track_name = vec![0u8; track_name_len];
                buf.copy_to_slice(&mut track_name);
                if buf.remaining() < 4 {
                    return Err(CodecError::UnexpectedEnd);
                }
                let subscriber_priority = buf.get_u8();
                let group_order =
                    GroupOrder::from_u8(buf.get_u8()).ok_or(CodecError::InvalidField)?;
                let forward_val = buf.get_u8();
                let forward = match forward_val {
                    0 => Forward::DontForward,
                    1 => Forward::Forward,
                    _ => return Err(CodecError::InvalidField),
                };
                let filter_val = buf.get_u8();
                let filter_type =
                    FilterType::from_u8(filter_val).ok_or(CodecError::InvalidField)?;
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
                let parameters = KeyValuePair::decode_list(buf)?;
                Ok(ControlMessage::Subscribe(Subscribe {
                    request_id,
                    track_namespace,
                    track_name,
                    subscriber_priority,
                    group_order,
                    forward,
                    filter_type,
                    start_location,
                    end_group,
                    parameters,
                }))
            }
            MessageType::SubscribeOk => {
                let request_id = VarInt::decode(buf)?;
                let track_alias = VarInt::decode(buf)?;
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
                let largest_location = if content_exists == ContentExists::HasLargestLocation {
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
                if buf.remaining() < reason_len {
                    return Err(CodecError::UnexpectedEnd);
                }
                let mut reason_phrase = vec![0u8; reason_len];
                buf.copy_to_slice(&mut reason_phrase);
                Ok(ControlMessage::SubscribeError(SubscribeError {
                    request_id,
                    error_code,
                    reason_phrase,
                }))
            }
            MessageType::SubscribeUpdate => {
                let request_id = VarInt::decode(buf)?;
                let start_location = Location::decode(buf)?;
                let end_group = VarInt::decode(buf)?;
                if buf.remaining() < 2 {
                    return Err(CodecError::UnexpectedEnd);
                }
                let subscriber_priority = buf.get_u8();
                let forward_val = buf.get_u8();
                let forward = match forward_val {
                    0 => Forward::DontForward,
                    1 => Forward::Forward,
                    _ => return Err(CodecError::InvalidField),
                };
                let parameters = KeyValuePair::decode_list(buf)?;
                Ok(ControlMessage::SubscribeUpdate(SubscribeUpdate {
                    request_id,
                    start_location,
                    end_group,
                    subscriber_priority,
                    forward,
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
                if buf.remaining() < track_name_len {
                    return Err(CodecError::UnexpectedEnd);
                }
                let mut track_name = vec![0u8; track_name_len];
                buf.copy_to_slice(&mut track_name);
                if buf.remaining() < 1 {
                    return Err(CodecError::UnexpectedEnd);
                }
                let forward_val = buf.get_u8();
                let forward = match forward_val {
                    0 => Forward::DontForward,
                    1 => Forward::Forward,
                    _ => return Err(CodecError::InvalidField),
                };
                let parameters = KeyValuePair::decode_list(buf)?;
                Ok(ControlMessage::Publish(Publish {
                    request_id,
                    track_namespace,
                    track_name,
                    forward,
                    parameters,
                }))
            }
            MessageType::PublishOk => {
                let request_id = VarInt::decode(buf)?;
                let track_alias = VarInt::decode(buf)?;
                if buf.remaining() < 1 {
                    return Err(CodecError::UnexpectedEnd);
                }
                let forward_val = buf.get_u8();
                let forward = match forward_val {
                    0 => Forward::DontForward,
                    1 => Forward::Forward,
                    _ => return Err(CodecError::InvalidField),
                };
                let parameters = KeyValuePair::decode_list(buf)?;
                Ok(ControlMessage::PublishOk(PublishOk {
                    request_id,
                    track_alias,
                    forward,
                    parameters,
                }))
            }
            MessageType::PublishError => {
                let request_id = VarInt::decode(buf)?;
                let error_code = VarInt::decode(buf)?;
                let reason_len = VarInt::decode(buf)?.into_inner() as usize;
                if buf.remaining() < reason_len {
                    return Err(CodecError::UnexpectedEnd);
                }
                let mut reason_phrase = vec![0u8; reason_len];
                buf.copy_to_slice(&mut reason_phrase);
                Ok(ControlMessage::PublishError(PublishError {
                    request_id,
                    error_code,
                    reason_phrase,
                }))
            }
            MessageType::PublishDone => {
                let request_id = VarInt::decode(buf)?;
                let status_code = VarInt::decode(buf)?;
                let reason_len = VarInt::decode(buf)?.into_inner() as usize;
                if buf.remaining() < reason_len {
                    return Err(CodecError::UnexpectedEnd);
                }
                let mut reason_phrase = vec![0u8; reason_len];
                buf.copy_to_slice(&mut reason_phrase);
                Ok(ControlMessage::PublishDone(PublishDone {
                    request_id,
                    status_code,
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
            MessageType::PublishNamespaceOk => {
                let request_id = VarInt::decode(buf)?;
                let parameters = KeyValuePair::decode_list(buf)?;
                Ok(ControlMessage::PublishNamespaceOk(PublishNamespaceOk {
                    request_id,
                    parameters,
                }))
            }
            MessageType::PublishNamespaceError => {
                let request_id = VarInt::decode(buf)?;
                let error_code = VarInt::decode(buf)?;
                let reason_len = VarInt::decode(buf)?.into_inner() as usize;
                if buf.remaining() < reason_len {
                    return Err(CodecError::UnexpectedEnd);
                }
                let mut reason_phrase = vec![0u8; reason_len];
                buf.copy_to_slice(&mut reason_phrase);
                Ok(ControlMessage::PublishNamespaceError(PublishNamespaceError {
                    request_id,
                    error_code,
                    reason_phrase,
                }))
            }
            MessageType::PublishNamespaceDone => {
                let request_id = VarInt::decode(buf)?;
                let status_code = VarInt::decode(buf)?;
                let reason_len = VarInt::decode(buf)?.into_inner() as usize;
                if buf.remaining() < reason_len {
                    return Err(CodecError::UnexpectedEnd);
                }
                let mut reason_phrase = vec![0u8; reason_len];
                buf.copy_to_slice(&mut reason_phrase);
                Ok(ControlMessage::PublishNamespaceDone(PublishNamespaceDone {
                    request_id,
                    status_code,
                    reason_phrase,
                }))
            }
            MessageType::PublishNamespaceCancel => {
                let request_id = VarInt::decode(buf)?;
                Ok(ControlMessage::PublishNamespaceCancel(PublishNamespaceCancel { request_id }))
            }
            MessageType::SubscribeNamespace => {
                let request_id = VarInt::decode(buf)?;
                let track_namespace = TrackNamespace::decode(buf)?;
                let parameters = KeyValuePair::decode_list(buf)?;
                Ok(ControlMessage::SubscribeNamespace(SubscribeNamespace {
                    request_id,
                    track_namespace,
                    parameters,
                }))
            }
            MessageType::SubscribeNamespaceOk => {
                let request_id = VarInt::decode(buf)?;
                let parameters = KeyValuePair::decode_list(buf)?;
                Ok(ControlMessage::SubscribeNamespaceOk(SubscribeNamespaceOk {
                    request_id,
                    parameters,
                }))
            }
            MessageType::SubscribeNamespaceError => {
                let request_id = VarInt::decode(buf)?;
                let error_code = VarInt::decode(buf)?;
                let reason_len = VarInt::decode(buf)?.into_inner() as usize;
                if buf.remaining() < reason_len {
                    return Err(CodecError::UnexpectedEnd);
                }
                let mut reason_phrase = vec![0u8; reason_len];
                buf.copy_to_slice(&mut reason_phrase);
                Ok(ControlMessage::SubscribeNamespaceError(SubscribeNamespaceError {
                    request_id,
                    error_code,
                    reason_phrase,
                }))
            }
            MessageType::UnsubscribeNamespace => {
                let request_id = VarInt::decode(buf)?;
                Ok(ControlMessage::UnsubscribeNamespace(UnsubscribeNamespace { request_id }))
            }
            MessageType::Fetch => {
                let request_id = VarInt::decode(buf)?;
                let track_namespace = TrackNamespace::decode(buf)?;
                let track_name_len = VarInt::decode(buf)?.into_inner() as usize;
                if buf.remaining() < track_name_len {
                    return Err(CodecError::UnexpectedEnd);
                }
                let mut track_name = vec![0u8; track_name_len];
                buf.copy_to_slice(&mut track_name);
                let start_group = VarInt::decode(buf)?;
                let start_object = VarInt::decode(buf)?;
                let end_group = VarInt::decode(buf)?;
                let parameters = KeyValuePair::decode_list(buf)?;
                Ok(ControlMessage::Fetch(Fetch {
                    request_id,
                    track_namespace,
                    track_name,
                    start_group,
                    start_object,
                    end_group,
                    parameters,
                }))
            }
            MessageType::FetchOk => {
                let request_id = VarInt::decode(buf)?;
                let track_alias = VarInt::decode(buf)?;
                let end_of_track = VarInt::decode(buf)?;
                let parameters = KeyValuePair::decode_list(buf)?;
                Ok(ControlMessage::FetchOk(FetchOk {
                    request_id,
                    track_alias,
                    end_of_track,
                    parameters,
                }))
            }
            MessageType::FetchError => {
                let request_id = VarInt::decode(buf)?;
                let error_code = VarInt::decode(buf)?;
                let reason_len = VarInt::decode(buf)?.into_inner() as usize;
                if buf.remaining() < reason_len {
                    return Err(CodecError::UnexpectedEnd);
                }
                let mut reason_phrase = vec![0u8; reason_len];
                buf.copy_to_slice(&mut reason_phrase);
                Ok(ControlMessage::FetchError(FetchError { request_id, error_code, reason_phrase }))
            }
            MessageType::FetchCancel => {
                let request_id = VarInt::decode(buf)?;
                Ok(ControlMessage::FetchCancel(FetchCancel { request_id }))
            }
            MessageType::TrackStatus => {
                let request_id = VarInt::decode(buf)?;
                let track_namespace = TrackNamespace::decode(buf)?;
                let track_name_len = VarInt::decode(buf)?.into_inner() as usize;
                if buf.remaining() < track_name_len {
                    return Err(CodecError::UnexpectedEnd);
                }
                let mut track_name = vec![0u8; track_name_len];
                buf.copy_to_slice(&mut track_name);
                let parameters = KeyValuePair::decode_list(buf)?;
                Ok(ControlMessage::TrackStatus(TrackStatus {
                    request_id,
                    track_namespace,
                    track_name,
                    parameters,
                }))
            }
            MessageType::TrackStatusOk => {
                let request_id = VarInt::decode(buf)?;
                let status_code = VarInt::decode(buf)?;
                // Status codes 0 (IN_PROGRESS) and 3 (FINISHED) include
                // largest_location
                let has_location = matches!(status_code.into_inner(), 0 | 3);
                let largest_location =
                    if has_location { Some(Location::decode(buf)?) } else { None };
                let parameters = KeyValuePair::decode_list(buf)?;
                Ok(ControlMessage::TrackStatusOk(TrackStatusOk {
                    request_id,
                    status_code,
                    largest_location,
                    parameters,
                }))
            }
            MessageType::TrackStatusError => {
                let request_id = VarInt::decode(buf)?;
                let error_code = VarInt::decode(buf)?;
                let reason_len = VarInt::decode(buf)?.into_inner() as usize;
                if buf.remaining() < reason_len {
                    return Err(CodecError::UnexpectedEnd);
                }
                let mut reason_phrase = vec![0u8; reason_len];
                buf.copy_to_slice(&mut reason_phrase);
                Ok(ControlMessage::TrackStatusError(TrackStatusError {
                    request_id,
                    error_code,
                    reason_phrase,
                }))
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
            ControlMessage::Unsubscribe(_) => MessageType::Unsubscribe,
            ControlMessage::Publish(_) => MessageType::Publish,
            ControlMessage::PublishOk(_) => MessageType::PublishOk,
            ControlMessage::PublishError(_) => MessageType::PublishError,
            ControlMessage::PublishDone(_) => MessageType::PublishDone,
            ControlMessage::PublishNamespace(_) => MessageType::PublishNamespace,
            ControlMessage::PublishNamespaceOk(_) => MessageType::PublishNamespaceOk,
            ControlMessage::PublishNamespaceError(_) => MessageType::PublishNamespaceError,
            ControlMessage::PublishNamespaceDone(_) => MessageType::PublishNamespaceDone,
            ControlMessage::PublishNamespaceCancel(_) => MessageType::PublishNamespaceCancel,
            ControlMessage::SubscribeNamespace(_) => MessageType::SubscribeNamespace,
            ControlMessage::SubscribeNamespaceOk(_) => MessageType::SubscribeNamespaceOk,
            ControlMessage::SubscribeNamespaceError(_) => MessageType::SubscribeNamespaceError,
            ControlMessage::UnsubscribeNamespace(_) => MessageType::UnsubscribeNamespace,
            ControlMessage::Fetch(_) => MessageType::Fetch,
            ControlMessage::FetchOk(_) => MessageType::FetchOk,
            ControlMessage::FetchError(_) => MessageType::FetchError,
            ControlMessage::FetchCancel(_) => MessageType::FetchCancel,
            ControlMessage::TrackStatus(_) => MessageType::TrackStatus,
            ControlMessage::TrackStatusOk(_) => MessageType::TrackStatusOk,
            ControlMessage::TrackStatusError(_) => MessageType::TrackStatusError,
        }
    }
}

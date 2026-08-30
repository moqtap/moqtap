use crate::auth_token::{AuthorizationToken, AUTH_TOKEN_PARAMETER};
use crate::error::{
    CodecError, MAX_FULL_TRACK_NAME_LENGTH, MAX_GOAWAY_URI_LENGTH, MAX_MESSAGE_LENGTH,
    MAX_REASON_PHRASE_LENGTH,
};
use crate::kvp::{KeyValuePair, KvpValue};
use crate::types::*;
pub use crate::types::{check_group_range, check_location_range, check_open_ended_group_range};
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
    /// The request ID for this update message.
    pub request_id: VarInt,
    /// The request ID of the subscription being updated.
    pub subscription_request_id: VarInt,
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
    /// Request ID.
    pub request_id: VarInt,
    /// Track namespace.
    pub track_namespace: TrackNamespace,
    /// Track name.
    pub track_name: Vec<u8>,
    /// Track alias assigned by the publisher.
    pub track_alias: VarInt,
    /// Group delivery order.
    pub group_order: GroupOrder,
    /// Whether a largest location is included.
    pub content_exists: ContentExists,
    /// Largest location, present when content_exists == HasLargestLocation.
    pub largest_location: Option<Location>,
    /// Forward preference.
    pub forward: Forward,
    /// Publish parameters.
    pub parameters: Vec<KeyValuePair>,
}

/// PUBLISH_OK message (type 0x1E).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishOk {
    /// Request ID this response corresponds to.
    pub request_id: VarInt,
    /// Forward preference.
    pub forward: Forward,
    /// Subscriber priority.
    pub subscriber_priority: u8,
    /// Group order.
    pub group_order: GroupOrder,
    /// Filter type.
    pub filter_type: FilterType,
    /// Present only for AbsoluteStart and AbsoluteRange filter types.
    pub start_location: Option<Location>,
    /// Present only for AbsoluteRange filter type.
    pub end_group: Option<VarInt>,
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
    /// Request ID.
    pub request_id: VarInt,
    /// Status code describing why the publish finished.
    pub status_code: VarInt,
    /// Number of data streams used by this publish.
    pub stream_count: VarInt,
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
    /// Track namespace being finalized.
    pub track_namespace: TrackNamespace,
}

/// PUBLISH_NAMESPACE_CANCEL message (type 0x0C).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishNamespaceCancel {
    /// Track namespace being cancelled.
    pub track_namespace: TrackNamespace,
    /// Application-defined error code.
    pub error_code: VarInt,
    /// Human-readable reason phrase.
    pub reason_phrase: Vec<u8>,
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
    /// The namespace prefix of the namespace subscription to cancel.
    pub track_namespace_prefix: TrackNamespace,
}

// ============================================================
// Fetch Messages
// ============================================================

/// FETCH type discriminator (standalone vs joining).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum FetchType {
    /// Standalone fetch with explicit track and range.
    Standalone = 1,
    /// Joining fetch relative to a subscribe request.
    RelativeJoining = 2,
    /// Joining fetch at an absolute group.
    AbsoluteJoining = 3,
}

impl FetchType {
    /// Convert a raw wire value to a [`FetchType`].
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            1 => Some(FetchType::Standalone),
            2 => Some(FetchType::RelativeJoining),
            3 => Some(FetchType::AbsoluteJoining),
            _ => None,
        }
    }
}

/// FETCH payload — either a standalone fetch or a joining fetch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchPayload {
    /// Standalone fetch.
    Standalone {
        /// Track namespace.
        track_namespace: TrackNamespace,
        /// Track name.
        track_name: Vec<u8>,
        /// Starting group ID.
        start_group: VarInt,
        /// Starting object ID.
        start_object: VarInt,
        /// Ending group ID.
        end_group: VarInt,
        /// Ending object ID.
        end_object: VarInt,
    },
    /// Joining fetch.
    Joining {
        /// The Request ID of the subscription this fetch joins.
        ///
        /// Section 9.16.2 names the field Joining Request ID, as every draft
        /// from 12 on does. Drafts 08 through 11 spelled it Joining Subscribe
        /// ID.
        joining_request_id: VarInt,
        /// Joining start (relative offset or absolute group).
        joining_start: VarInt,
    },
}

/// FETCH message (type 0x16).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetch {
    /// The request ID for this fetch.
    pub request_id: VarInt,
    /// Subscriber priority.
    pub subscriber_priority: u8,
    /// Requested group order.
    pub group_order: GroupOrder,
    /// Fetch type discriminator.
    pub fetch_type: FetchType,
    /// Variant-specific payload.
    pub fetch_payload: FetchPayload,
    /// Fetch parameters.
    pub parameters: Vec<KeyValuePair>,
}

/// FETCH_OK message (type 0x18).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchOk {
    /// The request ID this response corresponds to.
    pub request_id: VarInt,
    /// Group order chosen by the publisher.
    pub group_order: GroupOrder,
    /// End-of-track flag. A single byte, per Figure 39.
    pub end_of_track: u8,
    /// End location (largest group / object in the fetch).
    pub end_location: Location,
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

/// TRACK_STATUS message (type 0x0D) — subscribe-like request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackStatus {
    /// The request ID for this track status query.
    pub request_id: VarInt,
    /// The track namespace to query status for.
    pub track_namespace: TrackNamespace,
    /// The track name within the namespace.
    pub track_name: Vec<u8>,
    /// Subscriber priority.
    pub subscriber_priority: u8,
    /// Requested group order.
    pub group_order: GroupOrder,
    /// Forward preference.
    pub forward: Forward,
    /// Filter type.
    pub filter_type: FilterType,
    /// Present only for AbsoluteStart and AbsoluteRange filter types.
    pub start_location: Option<Location>,
    /// Present only for AbsoluteRange filter type.
    pub end_group: Option<VarInt>,
    /// Track status parameters.
    pub parameters: Vec<KeyValuePair>,
}

/// TRACK_STATUS_OK message (type 0x0E) — subscribe_ok-like response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackStatusOk {
    /// The request ID this response corresponds to.
    pub request_id: VarInt,
    /// Track alias.
    pub track_alias: VarInt,
    /// Subscription expiry in milliseconds.
    pub expires: VarInt,
    /// Group order.
    pub group_order: GroupOrder,
    /// Whether content exists / largest location is present.
    pub content_exists: ContentExists,
    /// The largest location, present when content_exists == HasLargestLocation.
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

/// Read a Group Order from a message that must name a real order.
///
/// Draft-14 states it for four messages, in the same words each time: "Values
/// of 0x0 and those larger than 0x2 are a protocol error" — SUBSCRIBE_OK in
/// Section 9.8, PUBLISH in Section 9.13, PUBLISH_OK in Section 9.14 and FETCH_OK
/// in Section 9.17. TRACK_STATUS_OK takes the same reader without stating the
/// sentence itself, because Section 9.21 says its "message format is identical
/// to the SUBSCRIBE_OK message" and that a publisher "populates the fields of
/// TRACK_STATUS_OK exactly as it would have populated a SUBSCRIBE_OK".
///
/// SUBSCRIBE, FETCH and TRACK_STATUS are the requests and keep the ordinary
/// reader: there 0x0 is exactly how a subscriber says it has no preference —
/// "A value of 0x0 indicates the original publisher's Group Order SHOULD be
/// used" — and only values above 0x2 are called an error. The two readers
/// cannot be merged without either refusing traffic the requests permit or
/// accepting a reply that tells the subscriber nothing.
fn read_group_order_response(buf: &mut impl Buf) -> Result<GroupOrder, CodecError> {
    if !buf.has_remaining() {
        return Err(CodecError::UnexpectedEnd);
    }
    match GroupOrder::from_u8(buf.get_u8()).ok_or(CodecError::InvalidField)? {
        GroupOrder::Publisher => Err(CodecError::InvalidField),
        order => Ok(order),
    }
}

/// Refuse a Group Order of 0x0 on the messages that forbid it.
///
/// The decoders refuse it on the way in; without this the codec would still
/// write a frame its own reader rejects.
fn check_group_order(message: &ControlMessage) -> Result<(), CodecError> {
    let order = match message {
        ControlMessage::SubscribeOk(m) => m.group_order,
        ControlMessage::TrackStatusOk(m) => m.group_order,
        ControlMessage::FetchOk(m) => m.group_order,
        ControlMessage::Publish(m) => m.group_order,
        ControlMessage::PublishOk(m) => m.group_order,
        _ => return Ok(()),
    };
    if order == GroupOrder::Publisher {
        return Err(CodecError::InvalidField);
    }
    Ok(())
}

/// Hold a namespace-plus-name pair to the Full Track Name cap.
///
/// Draft-14 Section 2.4.1: "The maximum total length of a Full Track Name is
/// 4,096 bytes, computed as the sum of the lengths of each Track Namespace tuple
/// field and the Track Name length field. If an endpoint receives a Full Track
/// Name exceeding this length, it MUST close the session with a
/// PROTOCOL_VIOLATION."
///
/// The two lengths arrive as separate fields, so neither the namespace decoder
/// nor the name decoder can settle this alone: a namespace at 4,000 bytes and a
/// name at 500 are each legal by themselves. It has to live where a message
/// decodes both.
///
/// Draft-14 states no separate cap on a Track Namespace on its own — that
/// sentence arrives in draft-16 — so this pairwise sum is the only bound the
/// draft gives. A control message may be 65,535 bytes, so without it a peer can
/// hand the application a Full Track Name sixteen times the permitted size, and
/// two relays that disagree about whether it was legal disagree about cache
/// identity.
/// Refuse a message whose discriminator disagrees with the fields beside it.
///
/// Several draft-14 messages carry a field that says which of the following
/// fields are on the wire — FETCH's Fetch Type, SUBSCRIBE's Filter Type,
/// SUBSCRIBE_OK's ContentExists. This codec holds the optional halves in
/// `Option`s and an enum, so a value can say one thing in its discriminator and
/// another in its body, and the two sides of the codec resolve that differently:
/// the encoder writes whatever the body holds, and the decoder reads whatever
/// the discriminator announces.
///
/// The result is a message that does not survive its own round trip. A FETCH
/// whose type says Standalone and whose body is a joining pair encodes to a
/// request id and a start where a namespace and a name belong, and comes back
/// as a Standalone fetch of a track named after two integers — or, more often,
/// as an error, which at least is honest. Refusing at the encoder keeps the two
/// readings from ever diverging on the wire.
fn check_discriminators(message: &ControlMessage) -> Result<(), CodecError> {
    match message {
        ControlMessage::Fetch(m) => {
            let body_is_standalone = matches!(m.fetch_payload, FetchPayload::Standalone { .. });
            if body_is_standalone != (m.fetch_type == FetchType::Standalone) {
                return Err(CodecError::InvalidField);
            }
        }
        ControlMessage::Subscribe(m) => {
            let wants_start =
                matches!(m.filter_type, FilterType::AbsoluteStart | FilterType::AbsoluteRange);
            if wants_start != m.start_location.is_some() {
                return Err(CodecError::InvalidField);
            }
            if (m.filter_type == FilterType::AbsoluteRange) != m.end_group.is_some() {
                return Err(CodecError::InvalidField);
            }
        }
        ControlMessage::SubscribeOk(m) => {
            let has_location = m.content_exists == ContentExists::HasLargestLocation;
            if has_location != m.largest_location.is_some() {
                return Err(CodecError::InvalidField);
            }
        }
        _ => {}
    }
    Ok(())
}

/// Read a Reason Phrase, holding it to the cap the draft states for the reader.
///
/// Section 1.4.3: "The reason phrase length has a maximum length of 1024 bytes.
/// If an endpoint receives a length exceeding the maximum, it MUST close the
/// session with a PROTOCOL_VIOLATION".
///
/// The rule is written for the receiver, and the receiver is the side that was
/// missing it: every encoder here already refused an over-long phrase, so the
/// codec held itself to a rule it applied to nobody else. A control message may
/// be 65,535 bytes, so a peer could hand the application a reason phrase
/// sixty-four times the permitted length, on any of the nine messages that
/// carry one.
///
/// The length is checked before the bytes are read, so an over-long phrase
/// costs nothing to refuse.
fn read_reason_phrase(buf: &mut impl Buf) -> Result<Vec<u8>, CodecError> {
    let len = VarInt::decode(buf)?.into_inner() as usize;
    if len > MAX_REASON_PHRASE_LENGTH {
        return Err(CodecError::ReasonPhraseTooLong);
    }
    read_bytes(buf, len)
}

fn check_full_track_name(namespace: &TrackNamespace, track_name: &[u8]) -> Result<(), CodecError> {
    let total = namespace.field_bytes_len().saturating_add(track_name.len());
    if total > MAX_FULL_TRACK_NAME_LENGTH {
        return Err(CodecError::TrackNameTooLong);
    }
    Ok(())
}

/// Refuse a request whose range ends before it starts.
///
/// SUBSCRIBE's AbsoluteRange filter (Section 9.7), SUBSCRIBE_UPDATE
/// (Section 9.10) and FETCH (Section 9.16.3) each state it, and the fields
/// are not spelled the same way in the three places: an End Group is inclusive
/// on SUBSCRIBE and FETCH and is the last group plus one on SUBSCRIBE_UPDATE,
/// where zero means open ended, and an End Object is the last object plus one
/// with zero meaning the whole group. The helpers this calls carry those
/// conventions, one per shape.
///
/// Applied on both sides. A range that ends before it starts selects nothing,
/// and the peer's only recourse is an error response or a session close, so
/// writing one is not a way to ask for anything.
fn check_ranges(message: &ControlMessage) -> Result<(), CodecError> {
    match message {
        ControlMessage::Subscribe(m) => match (&m.start_location, &m.end_group) {
            (Some(start), Some(end_group)) => {
                check_group_range(start.group.into_inner(), end_group.into_inner())
            }
            _ => Ok(()),
        },
        ControlMessage::SubscribeUpdate(m) => check_open_ended_group_range(
            m.start_location.group.into_inner(),
            m.end_group.into_inner(),
        ),
        ControlMessage::Fetch(m) => match &m.fetch_payload {
            FetchPayload::Standalone {
                start_group, start_object, end_group, end_object, ..
            } => check_location_range(
                start_group.into_inner(),
                start_object.into_inner(),
                end_group.into_inner(),
                end_object.into_inner(),
            ),
            FetchPayload::Joining { .. } => Ok(()),
        },
        _ => Ok(()),
    }
}

/// The one parameter type whose own definition lets it repeat.
///
/// Section 9.2.1.1: "The AUTHORIZATION TOKEN parameter MAY be repeated within a
/// message." That is the "unless the parameter definition explicitly allows
/// multiple instances" carve-out of Section 9.2, and on this draft it is the
/// only one — the other two version-specific parameters and all five setup
/// parameters say nothing of the kind.
///
/// The same code point, 0x03, in both namespaces: Section 9.2.1.1 assigns it to
/// the message parameter and Section 9.3.2.5 defines the setup parameter as
/// "See Section 9.2.1.1", so a sender may repeat it in a SETUP as well.
const REPEATABLE_PARAMETER: u64 = 0x03;

/// Every version-specific parameter type draft-14 names, from Section 9.2.1.
///
/// AUTHORIZATION TOKEN (0x03, Section 9.2.1.1), DELIVERY TIMEOUT (0x02, Section
/// 9.2.1.2) and MAX_CACHE_DURATION (0x04, Section 9.2.1.3). Draft-14 publishes
/// no IANA table for these, so the sections are the registry.
///
/// The list exists for one rule and one direction. Section 9.2: "Receivers MUST
/// allow duplicates of unknown parameters." A receiver may therefore refuse a
/// repeat only of a type it can name, and a type outside this list belongs to an
/// extension this codec has no business closing a session over. Nothing else
/// reads it — an unknown parameter is still decoded and carried.
const KNOWN_VERSION_SPECIFIC_PARAMETERS: &[u64] = &[0x02, 0x03, 0x04];

/// Every setup parameter type draft-14 names, from Section 9.3.2.
///
/// PATH (0x01), MAX_REQUEST_ID (0x02), AUTHORIZATION TOKEN (0x03),
/// MAX_AUTH_TOKEN_CACHE_SIZE (0x04) and AUTHORITY (0x05). Section 9.3.2.6 gives
/// MOQT_IMPLEMENTATION the code point 0x05 as well, colliding with AUTHORITY in
/// Section 9.3.2.1; draft-15 moves it to 0x07. The collision does not change the
/// set of code points the draft names, which is all this list is for.
///
/// Setup parameters are a separate namespace — Section 9.2.1 says so outright:
/// "since Setup parameters use a separate namespace, it is impossible for these
/// parameters to appear in Setup messages" — so a receiver deciding whether it
/// can name a type has to know which of the two lists to consult.
const KNOWN_SETUP_PARAMETERS: &[u64] = &[0x01, 0x02, 0x03, 0x04, 0x05];

/// Refuse a parameter list a sender may not put on the wire.
///
/// Section 9.2: "Senders MUST NOT repeat the same parameter type in a message
/// unless the parameter definition explicitly allows multiple instances of that
/// type to be sent in a single message."
///
/// The sender's half names no exception for types the sender does not
/// recognise, so every repeat is refused here except
/// [`REPEATABLE_PARAMETER`]. A caller holding a parameter this codec has never
/// heard of still may not send it twice: it knows the type it is sending, and
/// the rule is about that knowledge, not this codec's.
fn check_no_duplicate_parameters_sent(parameters: &[KeyValuePair]) -> Result<(), CodecError> {
    for (i, parameter) in parameters.iter().enumerate() {
        let key = parameter.key.into_inner();
        if key == REPEATABLE_PARAMETER {
            continue;
        }
        if parameters[..i].iter().any(|earlier| earlier.key == parameter.key) {
            return Err(CodecError::DuplicateParameter(key));
        }
    }
    Ok(())
}

/// Refuse a received parameter list that repeats a type this draft names.
///
/// The receiver's half of the same sentence is narrower, and deliberately so.
/// Section 9.2: "Receivers SHOULD check that there are no unauthorized duplicate
/// parameters and close the session as a PROTOCOL_VIOLATION if found. Receivers
/// MUST allow duplicates of unknown parameters."
///
/// So a repeat of a type in `known` is refused, and a repeat of any other type
/// is carried. Mirroring the sender's check here instead would close sessions
/// over frames a conforming peer is entitled to send — an extension parameter
/// this codec does not know may legitimately repeat, and its own definition, not
/// this one, says whether it may.
///
/// Code that scans a parameter list for a key takes whichever copy it meets
/// first, so one frame carrying two values for one named type is read
/// differently by two conforming implementations. That is what the refusal is
/// for, and it is also why it stops at the types whose meaning is fixed here.
fn check_no_duplicate_parameters_received(
    parameters: &[KeyValuePair],
    known: &[u64],
) -> Result<(), CodecError> {
    for (i, parameter) in parameters.iter().enumerate() {
        let key = parameter.key.into_inner();
        if key == REPEATABLE_PARAMETER || !known.contains(&key) {
            continue;
        }
        if parameters[..i].iter().any(|earlier| earlier.key == parameter.key) {
            return Err(CodecError::DuplicateParameter(key));
        }
    }
    Ok(())
}

/// Hold every AUTHORIZATION TOKEN parameter to the Token structure it names.
///
/// Section 9.2.1.1: "If the Token structure cannot be decoded, the receiver
/// MUST close the Session with Key-Value Formatting error." That is the answer
/// Section 1.4.2 gives for any Type whose value does not match the
/// serialization that Type defines; the Token is the one structure this draft
/// spells out, and the only parameter value in it that is more than opaque
/// bytes.
///
/// Both namespaces carry the type on this draft, and both reach here.
///
/// A type this draft cannot name is left alone. The rule is conditional on the
/// receiver understanding the Type, and an extension's parameter carries bytes
/// no rule here describes.
fn check_authorization_tokens(parameters: &[KeyValuePair]) -> Result<(), CodecError> {
    for parameter in parameters {
        let key = parameter.key.into_inner();
        if key != AUTH_TOKEN_PARAMETER {
            continue;
        }
        match &parameter.value {
            KvpValue::Bytes(value) => {
                AuthorizationToken::decode(key, value)?;
            }
            // Unreachable from the decoder, which picks the shape from the
            // type and finds this one length-prefixed. A caller that built the
            // pair in memory can still get here, and it is the same rule: the
            // value is not the serialization the type defines.
            KvpValue::Varint(_) => {
                return Err(CodecError::KeyValueFormatting {
                    key,
                    detail: "its value is a bare varint where the type defines a Token structure",
                });
            }
        }
    }
    Ok(())
}

/// Decode a version-specific parameter list, refusing a repeated known type.
fn decode_parameters(buf: &mut impl Buf) -> Result<Vec<KeyValuePair>, CodecError> {
    let parameters = KeyValuePair::decode_list(buf)?;
    check_no_duplicate_parameters_received(&parameters, KNOWN_VERSION_SPECIFIC_PARAMETERS)?;
    check_authorization_tokens(&parameters)?;
    Ok(parameters)
}

/// Decode a SETUP message's parameter list, refusing a repeated known type.
///
/// Separate from [`decode_parameters`] only in which list of names it consults;
/// see [`KNOWN_SETUP_PARAMETERS`] for why the two cannot share one.
fn decode_setup_parameters(buf: &mut impl Buf) -> Result<Vec<KeyValuePair>, CodecError> {
    let parameters = KeyValuePair::decode_list(buf)?;
    check_no_duplicate_parameters_received(&parameters, KNOWN_SETUP_PARAMETERS)?;
    check_authorization_tokens(&parameters)?;
    Ok(parameters)
}

/// Encode a parameter list, refusing every repeat the sender's rule forbids and
/// every token that is not one.
///
/// One function for both namespaces, unlike the decode side: the sender's rule
/// exempts a parameter type rather than a namespace, and the exempt type has the
/// same code point in each. The token rule is the same in both namespaces too,
/// so the two decode functions that state it agree with the one here.
///
/// A token that cannot be decoded is one the receiver must close the session
/// over, so writing it is not a way to send it — the sender's first sign of
/// trouble would be the session going.
fn encode_parameters(parameters: &[KeyValuePair], buf: &mut impl BufMut) -> Result<(), CodecError> {
    check_no_duplicate_parameters_sent(parameters)?;
    check_authorization_tokens(parameters)?;
    KeyValuePair::encode_list_checked(parameters, buf)?;
    Ok(())
}

impl ControlMessage {
    /// Encode this control message to bytes (including type ID and length prefix).
    ///
    /// Draft-14 framing: type_id(vi) + payload_length(16) + payload.
    pub fn encode(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        check_discriminators(self)?;
        check_group_order(self)?;
        check_ranges(self)?;
        let mut payload = Vec::with_capacity(256);
        self.encode_payload(&mut payload)?;

        if payload.len() > MAX_MESSAGE_LENGTH {
            return Err(CodecError::MessageTooLong(payload.len()));
        }

        VarInt::from_usize(self.message_type().id() as usize).encode(buf);
        // Draft-14: 16-bit length (big-endian)
        buf.put_u16(payload.len() as u16);
        buf.put_slice(&payload);
        Ok(())
    }

    /// Decode a control message from bytes (reads type ID and length prefix first).
    ///
    /// Draft-14 framing: type_id(vi) + payload_length(16) + payload.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let type_id = VarInt::decode(buf)?.into_inner();
        let msg_type =
            MessageType::from_id(type_id).ok_or(CodecError::UnknownMessageType(type_id))?;
        // Draft-14: 16-bit length (big-endian)
        if buf.remaining() < 2 {
            return Err(CodecError::UnexpectedEnd);
        }
        let payload_len = buf.get_u16() as usize;
        if buf.remaining() < payload_len {
            return Err(CodecError::UnexpectedEnd);
        }
        let payload_bytes = buf.copy_to_bytes(payload_len);
        let mut payload = &payload_bytes[..];
        let msg = match Self::decode_payload(msg_type, &mut payload) {
            Ok(msg) => msg,
            // The fields wanted more bytes than the Length allowed. This buffer
            // is already bounded by that Length, so running out inside it cannot
            // mean the message is still arriving - which is what the same error
            // means everywhere else, and why a reader loops on it rather than
            // closing. Here there is nothing left to arrive.
            Err(
                CodecError::UnexpectedEnd
                | CodecError::Kvp(crate::kvp::KvpError::UnexpectedEnd)
                | CodecError::Kvp(crate::kvp::KvpError::VarInt(
                    crate::varint::VarIntError::UnexpectedEnd,
                ))
                | CodecError::VarInt(crate::varint::VarIntError::UnexpectedEnd),
            ) => {
                return Err(CodecError::ControlMessageLengthMismatch {
                    declared: payload_len,
                    detail: "its fields ran past the end",
                });
            }
            Err(e) => return Err(e),
        };
        check_ranges(&msg)?;
        // The declared length is part of the message, not a hint. Bytes left over
        // after the fields have been read mean the sender and this reader disagree
        // about the shape of the message, and guessing which of the two is right
        // is how a trailing field gets silently dropped.
        if payload.has_remaining() {
            return Err(CodecError::ControlMessageLengthMismatch {
                declared: payload_len,
                detail: "its fields left bytes unread",
            });
        }
        Ok(msg)
    }

    fn encode_payload(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        match self {
            ControlMessage::ClientSetup(m) => {
                VarInt::from_usize(m.supported_versions.len()).encode(buf);
                for v in &m.supported_versions {
                    v.encode(buf);
                }
                encode_parameters(&m.parameters, buf)?;
            }
            ControlMessage::ServerSetup(m) => {
                m.selected_version.encode(buf);
                encode_parameters(&m.parameters, buf)?;
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
                check_full_track_name(&m.track_namespace, &m.track_name)?;
                m.request_id.encode(buf);
                m.track_namespace.validate(TrackNamespaceRules::for_draft(14))?;
                m.track_namespace.encode(buf);
                VarInt::from_usize(m.track_name.len()).encode(buf);
                buf.put_slice(&m.track_name);
                buf.put_u8(m.subscriber_priority);
                buf.put_u8(m.group_order as u8);
                buf.put_u8(m.forward as u8);
                VarInt::from_u64(m.filter_type as u64).unwrap().encode(buf);
                if let Some(loc) = &m.start_location {
                    loc.encode(buf);
                }
                if let Some(eg) = &m.end_group {
                    eg.encode(buf);
                }
                encode_parameters(&m.parameters, buf)?;
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
                encode_parameters(&m.parameters, buf)?;
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
                m.subscription_request_id.encode(buf);
                m.start_location.encode(buf);
                m.end_group.encode(buf);
                buf.put_u8(m.subscriber_priority);
                buf.put_u8(m.forward as u8);
                encode_parameters(&m.parameters, buf)?;
            }
            ControlMessage::Unsubscribe(m) => {
                m.request_id.encode(buf);
            }
            ControlMessage::Publish(m) => {
                check_full_track_name(&m.track_namespace, &m.track_name)?;
                m.request_id.encode(buf);
                m.track_namespace.validate(TrackNamespaceRules::for_draft(14))?;
                m.track_namespace.encode(buf);
                VarInt::from_usize(m.track_name.len()).encode(buf);
                buf.put_slice(&m.track_name);
                m.track_alias.encode(buf);
                buf.put_u8(m.group_order as u8);
                buf.put_u8(m.content_exists as u8);
                if let Some(loc) = &m.largest_location {
                    loc.encode(buf);
                }
                buf.put_u8(m.forward as u8);
                encode_parameters(&m.parameters, buf)?;
            }
            ControlMessage::PublishOk(m) => {
                m.request_id.encode(buf);
                buf.put_u8(m.forward as u8);
                buf.put_u8(m.subscriber_priority);
                buf.put_u8(m.group_order as u8);
                VarInt::from_u64(m.filter_type as u64).unwrap().encode(buf);
                if let Some(loc) = &m.start_location {
                    loc.encode(buf);
                }
                if let Some(eg) = &m.end_group {
                    eg.encode(buf);
                }
                encode_parameters(&m.parameters, buf)?;
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
                m.track_namespace.validate(TrackNamespaceRules::for_draft(14))?;
                m.track_namespace.encode(buf);
                encode_parameters(&m.parameters, buf)?;
            }
            ControlMessage::PublishNamespaceOk(m) => {
                m.request_id.encode(buf);
            }
            ControlMessage::PublishNamespaceError(m) => {
                if m.reason_phrase.len() > MAX_REASON_PHRASE_LENGTH {
                    return Err(CodecError::ReasonPhraseTooLong);
                }
                m.request_id.encode(buf);
                m.error_code.encode(buf);
                VarInt::from_usize(m.reason_phrase.len()).encode(buf);
                buf.put_slice(&m.reason_phrase);
            }
            ControlMessage::PublishNamespaceDone(m) => {
                m.track_namespace.validate(TrackNamespaceRules::for_draft(14))?;
                m.track_namespace.encode(buf);
            }
            ControlMessage::PublishNamespaceCancel(m) => {
                if m.reason_phrase.len() > MAX_REASON_PHRASE_LENGTH {
                    return Err(CodecError::ReasonPhraseTooLong);
                }
                m.track_namespace.validate(TrackNamespaceRules::for_draft(14))?;
                m.track_namespace.encode(buf);
                m.error_code.encode(buf);
                VarInt::from_usize(m.reason_phrase.len()).encode(buf);
                buf.put_slice(&m.reason_phrase);
            }
            ControlMessage::SubscribeNamespace(m) => {
                m.request_id.encode(buf);
                m.track_namespace.validate(TrackNamespaceRules::for_draft(14))?;
                m.track_namespace.encode(buf);
                encode_parameters(&m.parameters, buf)?;
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
                m.track_namespace_prefix.validate(TrackNamespaceRules::for_draft(14))?;
                m.track_namespace_prefix.encode(buf);
            }
            ControlMessage::Fetch(m) => {
                m.request_id.encode(buf);
                buf.put_u8(m.subscriber_priority);
                buf.put_u8(m.group_order as u8);
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
                        check_full_track_name(track_namespace, track_name)?;
                        track_namespace.validate(TrackNamespaceRules::for_draft(14))?;
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
                encode_parameters(&m.parameters, buf)?;
            }
            ControlMessage::FetchOk(m) => {
                m.request_id.encode(buf);
                buf.put_u8(m.group_order as u8);
                buf.put_u8(m.end_of_track);
                m.end_location.encode(buf);
                encode_parameters(&m.parameters, buf)?;
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
            ControlMessage::TrackStatus(m) => {
                check_full_track_name(&m.track_namespace, &m.track_name)?;
                m.request_id.encode(buf);
                m.track_namespace.validate(TrackNamespaceRules::for_draft(14))?;
                m.track_namespace.encode(buf);
                VarInt::from_usize(m.track_name.len()).encode(buf);
                buf.put_slice(&m.track_name);
                buf.put_u8(m.subscriber_priority);
                buf.put_u8(m.group_order as u8);
                buf.put_u8(m.forward as u8);
                VarInt::from_u64(m.filter_type as u64).unwrap().encode(buf);
                if let Some(loc) = &m.start_location {
                    loc.encode(buf);
                }
                if let Some(eg) = &m.end_group {
                    eg.encode(buf);
                }
                encode_parameters(&m.parameters, buf)?;
            }
            ControlMessage::TrackStatusOk(m) => {
                m.request_id.encode(buf);
                m.track_alias.encode(buf);
                m.expires.encode(buf);
                buf.put_u8(m.group_order as u8);
                buf.put_u8(m.content_exists as u8);
                if let Some(loc) = &m.largest_location {
                    loc.encode(buf);
                }
                encode_parameters(&m.parameters, buf)?;
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
        }
        Ok(())
    }

    fn decode_payload(msg_type: MessageType, buf: &mut impl Buf) -> Result<Self, CodecError> {
        match msg_type {
            MessageType::ClientSetup => {
                let num_versions = VarInt::decode(buf)?.into_inner() as usize;
                // Not a rule this draft states. It says only that the server
                // "MUST reply with one of the versions offered by the client"
                // and that a peer with no version in common "MUST close the
                // session" - outcomes of negotiation rather than parse errors,
                // and a CLIENT_SETUP offering nothing decodes cleanly under the
                // figure. It is refused here because there is no version a
                // reply could name, so the session is already over and the
                // early close is the more useful answer than a well-formed
                // message no caller can act on.
                if num_versions == 0 {
                    return Err(CodecError::InvalidField);
                }
                let mut supported_versions = crate::types::reserve_bounded(num_versions, buf);
                for _ in 0..num_versions {
                    supported_versions.push(VarInt::decode(buf)?);
                }
                let parameters = decode_setup_parameters(buf)?;
                Ok(ControlMessage::ClientSetup(ClientSetup { supported_versions, parameters }))
            }
            MessageType::ServerSetup => {
                let selected_version = VarInt::decode(buf)?;
                let parameters = decode_setup_parameters(buf)?;
                Ok(ControlMessage::ServerSetup(ServerSetup { selected_version, parameters }))
            }
            MessageType::GoAway => {
                let uri_len = VarInt::decode(buf)?.into_inner() as usize;
                // Section 9.4: "The maxmimum length of the New Session URI is
                // 8,192 bytes. If an endpoint receives a length exceeding the
                // maximum, it MUST close the session with a
                // PROTOCOL_VIOLATION." Stated for the receiver, and checked
                // before the bytes are read.
                if uri_len > MAX_GOAWAY_URI_LENGTH {
                    return Err(CodecError::GoAwayUriTooLong);
                }
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
                check_full_track_name(&track_namespace, &track_name)?;
                if buf.remaining() < 3 {
                    return Err(CodecError::UnexpectedEnd);
                }
                let subscriber_priority = buf.get_u8();
                let group_order =
                    GroupOrder::from_u8(buf.get_u8()).ok_or(CodecError::InvalidField)?;
                let forward_val = buf.get_u8();
                let forward = match forward_val {
                    0 => Forward::DontForward,
                    1 => Forward::Forward,
                    other => return Err(CodecError::InvalidForward(other)),
                };
                // Filter Type is (i) in every figure that carries it, not a
                // fixed byte: the values 1 through 4 happen to share their
                // one-byte varint encoding with a bare byte, so the two
                // readings agree on everything legal and diverge only on the
                // longer encodings of the same values that a peer may send.
                let filter_val = VarInt::decode(buf)?.into_inner();
                let filter_type = FilterType::from_u64(filter_val)
                    .ok_or(CodecError::InvalidFilterType(filter_val))?;
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
                let parameters = decode_parameters(buf)?;
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
                let group_order = read_group_order_response(buf)?;
                let content_exists_val = buf.get_u8();
                let content_exists = match content_exists_val {
                    0 => ContentExists::NoLargestLocation,
                    1 => ContentExists::HasLargestLocation,
                    other => return Err(CodecError::InvalidContentExists(other)),
                };
                let largest_location = if content_exists == ContentExists::HasLargestLocation {
                    Some(Location::decode(buf)?)
                } else {
                    None
                };
                let parameters = decode_parameters(buf)?;
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
                let reason_phrase = read_reason_phrase(buf)?;
                Ok(ControlMessage::SubscribeError(SubscribeError {
                    request_id,
                    error_code,
                    reason_phrase,
                }))
            }
            MessageType::SubscribeUpdate => {
                let request_id = VarInt::decode(buf)?;
                let subscription_request_id = VarInt::decode(buf)?;
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
                    other => return Err(CodecError::InvalidForward(other)),
                };
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::SubscribeUpdate(SubscribeUpdate {
                    request_id,
                    subscription_request_id,
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
                let track_name = read_bytes(buf, track_name_len)?;
                check_full_track_name(&track_namespace, &track_name)?;
                let track_alias = VarInt::decode(buf)?;
                if buf.remaining() < 2 {
                    return Err(CodecError::UnexpectedEnd);
                }
                let group_order = read_group_order_response(buf)?;
                let content_exists_val = buf.get_u8();
                let content_exists = match content_exists_val {
                    0 => ContentExists::NoLargestLocation,
                    1 => ContentExists::HasLargestLocation,
                    other => return Err(CodecError::InvalidContentExists(other)),
                };
                let largest_location = if content_exists == ContentExists::HasLargestLocation {
                    Some(Location::decode(buf)?)
                } else {
                    None
                };
                if buf.remaining() < 1 {
                    return Err(CodecError::UnexpectedEnd);
                }
                let forward_val = buf.get_u8();
                let forward = match forward_val {
                    0 => Forward::DontForward,
                    1 => Forward::Forward,
                    other => return Err(CodecError::InvalidForward(other)),
                };
                let parameters = decode_parameters(buf)?;
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
                if buf.remaining() < 3 {
                    return Err(CodecError::UnexpectedEnd);
                }
                let forward_val = buf.get_u8();
                let forward = match forward_val {
                    0 => Forward::DontForward,
                    1 => Forward::Forward,
                    other => return Err(CodecError::InvalidForward(other)),
                };
                let subscriber_priority = buf.get_u8();
                let group_order = read_group_order_response(buf)?;
                let filter_val = VarInt::decode(buf)?.into_inner();
                let filter_type = FilterType::from_u64(filter_val)
                    .ok_or(CodecError::InvalidFilterType(filter_val))?;
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
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::PublishOk(PublishOk {
                    request_id,
                    forward,
                    subscriber_priority,
                    group_order,
                    filter_type,
                    start_location,
                    end_group,
                    parameters,
                }))
            }
            MessageType::PublishError => {
                let request_id = VarInt::decode(buf)?;
                let error_code = VarInt::decode(buf)?;
                let reason_phrase = read_reason_phrase(buf)?;
                Ok(ControlMessage::PublishError(PublishError {
                    request_id,
                    error_code,
                    reason_phrase,
                }))
            }
            MessageType::PublishDone => {
                let request_id = VarInt::decode(buf)?;
                let status_code = VarInt::decode(buf)?;
                let stream_count = VarInt::decode(buf)?;
                let reason_phrase = read_reason_phrase(buf)?;
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
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::PublishNamespace(PublishNamespace {
                    request_id,
                    track_namespace,
                    parameters,
                }))
            }
            MessageType::PublishNamespaceOk => {
                let request_id = VarInt::decode(buf)?;
                Ok(ControlMessage::PublishNamespaceOk(PublishNamespaceOk { request_id }))
            }
            MessageType::PublishNamespaceError => {
                let request_id = VarInt::decode(buf)?;
                let error_code = VarInt::decode(buf)?;
                let reason_phrase = read_reason_phrase(buf)?;
                Ok(ControlMessage::PublishNamespaceError(PublishNamespaceError {
                    request_id,
                    error_code,
                    reason_phrase,
                }))
            }
            MessageType::PublishNamespaceDone => {
                let track_namespace = TrackNamespace::decode(buf)?;
                Ok(ControlMessage::PublishNamespaceDone(PublishNamespaceDone { track_namespace }))
            }
            MessageType::PublishNamespaceCancel => {
                let track_namespace = TrackNamespace::decode(buf)?;
                let error_code = VarInt::decode(buf)?;
                let reason_phrase = read_reason_phrase(buf)?;
                Ok(ControlMessage::PublishNamespaceCancel(PublishNamespaceCancel {
                    track_namespace,
                    error_code,
                    reason_phrase,
                }))
            }
            MessageType::SubscribeNamespace => {
                let request_id = VarInt::decode(buf)?;
                let track_namespace = TrackNamespace::decode(buf)?;
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::SubscribeNamespace(SubscribeNamespace {
                    request_id,
                    track_namespace,
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
                let reason_phrase = read_reason_phrase(buf)?;
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
            MessageType::Fetch => {
                let request_id = VarInt::decode(buf)?;
                if buf.remaining() < 2 {
                    return Err(CodecError::UnexpectedEnd);
                }
                let subscriber_priority = buf.get_u8();
                let group_order =
                    GroupOrder::from_u8(buf.get_u8()).ok_or(CodecError::InvalidField)?;
                let fetch_type_val = VarInt::decode(buf)?.into_inner();
                let fetch_type = FetchType::from_u64(fetch_type_val)
                    .ok_or(CodecError::InvalidFetchType(fetch_type_val))?;
                let fetch_payload = match fetch_type {
                    FetchType::Standalone => {
                        let track_namespace = TrackNamespace::decode(buf)?;
                        let track_name_len = VarInt::decode(buf)?.into_inner() as usize;
                        let track_name = read_bytes(buf, track_name_len)?;
                        check_full_track_name(&track_namespace, &track_name)?;
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
                    subscriber_priority,
                    group_order,
                    fetch_type,
                    fetch_payload,
                    parameters,
                }))
            }
            MessageType::FetchOk => {
                let request_id = VarInt::decode(buf)?;
                if buf.remaining() < 2 {
                    return Err(CodecError::UnexpectedEnd);
                }
                let group_order = read_group_order_response(buf)?;
                // End Of Track is (8) in Figure 39, not a varint. The two agree
                // on the flag's only two values, so this is the shape of the
                // field rather than the values it carries.
                let end_of_track = buf.get_u8();
                let end_location = Location::decode(buf)?;
                let parameters = decode_parameters(buf)?;
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
                let reason_phrase = read_reason_phrase(buf)?;
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
                let track_name = read_bytes(buf, track_name_len)?;
                check_full_track_name(&track_namespace, &track_name)?;
                if buf.remaining() < 3 {
                    return Err(CodecError::UnexpectedEnd);
                }
                let subscriber_priority = buf.get_u8();
                let group_order =
                    GroupOrder::from_u8(buf.get_u8()).ok_or(CodecError::InvalidField)?;
                let forward_val = buf.get_u8();
                let forward = match forward_val {
                    0 => Forward::DontForward,
                    1 => Forward::Forward,
                    other => return Err(CodecError::InvalidForward(other)),
                };
                // Filter Type is (i) in every figure that carries it, not a
                // fixed byte: the values 1 through 4 happen to share their
                // one-byte varint encoding with a bare byte, so the two
                // readings agree on everything legal and diverge only on the
                // longer encodings of the same values that a peer may send.
                let filter_val = VarInt::decode(buf)?.into_inner();
                let filter_type = FilterType::from_u64(filter_val)
                    .ok_or(CodecError::InvalidFilterType(filter_val))?;
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
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::TrackStatus(TrackStatus {
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
            MessageType::TrackStatusOk => {
                let request_id = VarInt::decode(buf)?;
                let track_alias = VarInt::decode(buf)?;
                let expires = VarInt::decode(buf)?;
                if buf.remaining() < 2 {
                    return Err(CodecError::UnexpectedEnd);
                }
                let group_order = read_group_order_response(buf)?;
                let content_exists_val = buf.get_u8();
                let content_exists = match content_exists_val {
                    0 => ContentExists::NoLargestLocation,
                    1 => ContentExists::HasLargestLocation,
                    other => return Err(CodecError::InvalidContentExists(other)),
                };
                let largest_location = if content_exists == ContentExists::HasLargestLocation {
                    Some(Location::decode(buf)?)
                } else {
                    None
                };
                let parameters = decode_parameters(buf)?;
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
                let reason_phrase = read_reason_phrase(buf)?;
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

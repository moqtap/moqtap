//! Draft-11 control message encoding and decoding.
//!
//! Key changes from draft-09/10:
//! - Setup IDs: 0x40/0x41 -> 0x20/0x21
//! - `subscribe_id` -> `request_id` throughout
//! - MaxSubscribeId -> MaxRequestId, SubscribesBlocked -> RequestsBlocked
//! - Subscribe gains `track_alias` and `forward` fields
//! - SubscribeOk: no track_alias
//! - SubscribeError gains trailing `track_alias`
//! - SubscribeDone gains `stream_count`
//! - SubscribeUpdate uses start_group/start_object (not Location)
//! - Announce gains `request_id`; AnnounceOk/AnnounceError use `request_id`
//! - AnnounceCancel: `namespace + error_code + reason_phrase`
//! - SubscribeAnnounces gains `request_id`
//! - TrackStatusRequest gains `request_id` and `parameters`
//! - TrackStatus restructured: `request_id + status_code + largest_location + parameters`
//! - Fetch restructured: 3 fetch types (Standalone, RelativeJoining, AbsoluteJoining)
//! - FetchOk: group_order + end_of_track + end_location (no track_alias)
//! - Uses even/odd KVP encoding (not d07 format)
//! - Framing: type_id(vi) + payload_length(16) + payload

use crate::auth_token::{AuthorizationToken, AUTH_TOKEN_PARAMETER_D11};
use crate::error::{
    CodecError, MAX_FULL_TRACK_NAME_LENGTH, MAX_GOAWAY_URI_LENGTH, MAX_MESSAGE_LENGTH,
    MAX_REASON_PHRASE_LENGTH,
};
use crate::kvp::{KeyValuePair, KvpValue};
use crate::types::{self, *};
pub use crate::types::{check_group_range, check_location_range, check_open_ended_group_range};
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

    /// This type's name in the shared vector corpus: the `message_type` its
    /// draft's `codec/messages/*.json` files carry, in `snake_case`.
    pub fn name(&self) -> &'static str {
        match self {
            MessageType::SubscribeUpdate => "subscribe_update",
            MessageType::Subscribe => "subscribe",
            MessageType::SubscribeOk => "subscribe_ok",
            MessageType::SubscribeError => "subscribe_error",
            MessageType::Announce => "announce",
            MessageType::AnnounceOk => "announce_ok",
            MessageType::AnnounceError => "announce_error",
            MessageType::Unannounce => "unannounce",
            MessageType::Unsubscribe => "unsubscribe",
            MessageType::SubscribeDone => "subscribe_done",
            MessageType::AnnounceCancel => "announce_cancel",
            MessageType::TrackStatusRequest => "track_status_request",
            MessageType::TrackStatus => "track_status",
            MessageType::GoAway => "goaway",
            MessageType::SubscribeAnnounces => "subscribe_announces",
            MessageType::SubscribeAnnouncesOk => "subscribe_announces_ok",
            MessageType::SubscribeAnnouncesError => "subscribe_announces_error",
            MessageType::UnsubscribeAnnounces => "unsubscribe_announces",
            MessageType::MaxRequestId => "max_request_id",
            MessageType::Fetch => "fetch",
            MessageType::FetchCancel => "fetch_cancel",
            MessageType::FetchOk => "fetch_ok",
            MessageType::FetchError => "fetch_error",
            MessageType::RequestsBlocked => "requests_blocked",
            MessageType::ClientSetup => "client_setup",
            MessageType::ServerSetup => "server_setup",
        }
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
    /// Requested group delivery order.
    pub group_order: GroupOrder,
    /// Whether to forward data on this subscription.
    pub forward: Forward,
    /// The filter type controlling which objects are delivered.
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
    /// The group delivery order chosen by the publisher.
    pub group_order: GroupOrder,
    /// Whether the largest location is included.
    pub content_exists: ContentExists,
    /// Present only when content_exists says one is there.
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
    /// Updated forward preference.
    pub forward: Forward,
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
    /// Requested group delivery order.
    pub group_order: GroupOrder,
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
    /// The group delivery order chosen by the publisher.
    pub group_order: GroupOrder,
    /// Whether the end of the track has been reached.
    ///
    /// Held as a raw byte rather than an enum: the draft describes 1 and 0 and
    /// says nothing about any other value, where it does call an out-of-range
    /// Group Order, Forward or Content Exists a protocol error. Refusing a 2
    /// here would be this codec's rule and not the draft's.
    pub end_of_track: u8,
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

/// Take one byte, or report the end of the buffer instead of panicking.
fn read_u8(buf: &mut impl Buf) -> Result<u8, CodecError> {
    if !buf.has_remaining() {
        return Err(CodecError::UnexpectedEnd);
    }
    Ok(buf.get_u8())
}

/// Read a Group Order from a message that lets the publisher choose.
///
/// Every figure draws this field as a single byte, and the values are 0x1
/// Ascending, 0x2 Descending, and 0x0 for "the original publisher's Group Order
/// SHOULD be used".
///
/// Reading it as a varint instead is invisible for all three legal values —
/// each is a single byte below 64, where the two encodings coincide — and
/// diverges on everything a peer may send that is not legal. A two-byte varint
/// holding 1 passes as Ascending and shifts every field after it, while the
/// declared message length still adds up.
fn read_group_order(buf: &mut impl Buf) -> Result<GroupOrder, CodecError> {
    GroupOrder::from_u8(read_u8(buf)?).ok_or(CodecError::InvalidField)
}

/// Read a Forward flag: "Any other value is a protocol error and MUST terminate
/// the session with a Protocol Violation"
fn read_forward(buf: &mut impl Buf) -> Result<Forward, CodecError> {
    match read_u8(buf)? {
        0 => Ok(Forward::DontForward),
        1 => Ok(Forward::Forward),
        other => Err(CodecError::InvalidForward(other)),
    }
}

/// Read a Content Exists flag, which carries the same sentence as Forward and
/// also decides whether a Largest Location follows.
fn read_content_exists(buf: &mut impl Buf) -> Result<ContentExists, CodecError> {
    match read_u8(buf)? {
        0 => Ok(ContentExists::NoLargestLocation),
        1 => Ok(ContentExists::HasLargestLocation),
        other => Err(CodecError::InvalidContentExists(other)),
    }
}

/// Read a Group Order from a message that must name a real order.
///
/// SUBSCRIBE_OK and FETCH_OK each say
/// "Values of 0x0 and those larger than 0x2 are a protocol error": a responder
/// reports the order it settled on, so deferring to the publisher is not an
/// answer it can give. SUBSCRIBE and FETCH are the requests, and there
/// 0x0 is exactly how a subscriber says it has no preference — "the original
/// publisher's Group Order SHOULD be used". The two readers cannot be merged
/// without either refusing traffic the requests permit or accepting a reply
/// that tells the subscriber nothing.
fn read_group_order_response(buf: &mut impl Buf) -> Result<GroupOrder, CodecError> {
    if !buf.has_remaining() {
        return Err(CodecError::UnexpectedEnd);
    }
    match GroupOrder::from_u8(buf.get_u8()).ok_or(CodecError::InvalidField)? {
        GroupOrder::Publisher => Err(CodecError::InvalidField),
        order => Ok(order),
    }
}

/// Both halves of a Start Location travel together, and only the two absolute
/// filters put one on the wire. The Filter Type is still a raw varint on this
/// draft, so the range check the decoder applies belongs here too.
fn check_filter(
    filter_type: VarInt,
    start_group: &Option<VarInt>,
    start_object: &Option<VarInt>,
    end_group: &Option<VarInt>,
) -> Result<(), CodecError> {
    let value = filter_type.into_inner();
    if value == 0 || value > 4 {
        return Err(CodecError::InvalidFilterType(value));
    }
    let wants_start = value == 3 || value == 4;
    if wants_start != start_group.is_some() || wants_start != start_object.is_some() {
        return Err(CodecError::InvalidField);
    }
    if (value == 4) != end_group.is_some() {
        return Err(CodecError::InvalidField);
    }
    Ok(())
}

fn check_content(
    content_exists: ContentExists,
    largest_location: &Option<Location>,
) -> Result<(), CodecError> {
    if (content_exists == ContentExists::HasLargestLocation) != largest_location.is_some() {
        return Err(CodecError::InvalidField);
    }
    Ok(())
}

/// Hold a TRACK_STATUS Status Code and the fields after it to Section 8.18.
///
/// "Status Code: Provides additional information about the status of the track.
/// It MUST hold one of the following values. Any other value is a malformed
/// message." Two of those values - 0x01 and 0x02 - add "Subsequent fields MUST
/// be zero, and any other value is a malformed message".
///
/// Applied on both sides. A malformed message is one this codec must not read
/// and equally must not write: an encoder that emits an unassigned Status Code
/// hands a conforming peer a message it is required to reject.
fn check_track_status(status_code: VarInt, largest_location: Location) -> Result<(), CodecError> {
    let code = crate::draft11::error_codes::TrackStatusCode::from_u64(status_code.into_inner())
        .ok_or(CodecError::InvalidField)?;
    if code.requires_zero_location()
        && (largest_location.group.into_inner() != 0 || largest_location.object.into_inner() != 0)
    {
        return Err(CodecError::InvalidField);
    }
    Ok(())
}

/// Refuse a message whose optional fields disagree with the field that decides
/// whether they are on the wire.
///
/// Presence is not a property of the Rust value: the decoder derives it from a
/// Filter Type, a Content Exists flag or a Fetch Type, and reads exactly the
/// fields that discriminator names. An encoder that instead writes whatever
/// happens to be `Some` produces a frame its own reader refuses - short by the
/// missing fields, so the declared length runs out mid-payload, or long by the
/// surplus ones, so bytes are left over. Section 8 makes either a session
/// close, which is why this refuses rather than papering over it.
fn check_discriminators(message: &ControlMessage) -> Result<(), CodecError> {
    match message {
        ControlMessage::Subscribe(m) => {
            check_filter(m.filter_type, &m.start_group, &m.start_object, &m.end_group)
        }
        ControlMessage::SubscribeOk(m) => check_content(m.content_exists, &m.largest_location),
        ControlMessage::Fetch(m) => {
            let body_is_standalone = matches!(m.fetch_payload, FetchPayload::Standalone { .. });
            if body_is_standalone != (m.fetch_type == FetchType::Standalone) {
                return Err(CodecError::InvalidField);
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Refuse a Group Order of 0x0 on the messages that forbid it.
///
/// The decoders refuse it on the way in; without this the codec would still
/// write a frame its own reader rejects.
fn check_group_order(message: &ControlMessage) -> Result<(), CodecError> {
    let order = match message {
        ControlMessage::SubscribeOk(m) => m.group_order,
        ControlMessage::FetchOk(m) => m.group_order,
        _ => return Ok(()),
    };
    if order == GroupOrder::Publisher {
        return Err(CodecError::InvalidField);
    }
    Ok(())
}

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

fn check_full_track_name(namespace: &TrackNamespace, track_name: &[u8]) -> Result<(), CodecError> {
    let total = namespace.field_bytes_len().saturating_add(track_name.len());
    if total > MAX_FULL_TRACK_NAME_LENGTH {
        return Err(CodecError::TrackNameTooLong);
    }
    Ok(())
}

/// Read a Reason Phrase, holding it to the cap this draft states for a receiver.
///
/// "The reason phrase length has a maximum length of 1024 bytes. If an endpoint
/// receives a length exceeding the maximum, it MUST close the session with a
/// Protocol Violation". The sentence is about what an endpoint receives, and
/// receiving was the direction the cap was not applied to: the encoders refused
/// an over-long phrase and the decoders accepted one.
fn read_reason_phrase(buf: &mut impl Buf) -> Result<Vec<u8>, CodecError> {
    let len = VarInt::decode(buf)?.into_inner() as usize;
    if len > MAX_REASON_PHRASE_LENGTH {
        return Err(CodecError::ReasonPhraseTooLong);
    }
    types::read_bytes(buf, len)
}

/// Refuse a request whose range ends before it starts.
///
/// SUBSCRIBE's AbsoluteRange filter (Section 8.7), SUBSCRIBE_UPDATE
/// (Section 8.10) and FETCH (Section 8.13) each state it, and the fields
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
        ControlMessage::Subscribe(m) => match (&m.start_group, &m.end_group) {
            (Some(start_group), Some(end_group)) => {
                check_group_range(start_group.into_inner(), end_group.into_inner())
            }
            _ => Ok(()),
        },
        ControlMessage::SubscribeUpdate(m) => {
            check_open_ended_group_range(m.start_group.into_inner(), m.end_group.into_inner())
        }
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

/// AUTHORIZATION TOKEN, the Version Specific Parameter of Section 8.2.1.1.
///
/// The number is this draft's own. Draft-11 assigns AUTHORIZATION TOKEN
/// "Parameter Type 0x01"; drafts 12 and 13 move it to 0x03 and leave 0x01 to
/// the setup-side PATH parameter. Reading either draft's number into the other
/// would exempt the wrong type from the repeat rule below.
const AUTHORIZATION_TOKEN: u64 = 0x01;

/// DELIVERY TIMEOUT, the Version Specific Parameter of Section 8.2.1.2.
const DELIVERY_TIMEOUT: u64 = 0x02;

/// MAX_CACHE_DURATION, the Version Specific Parameter of Section 8.2.1.3.
const MAX_CACHE_DURATION: u64 = 0x04;

/// PATH, the Setup Parameter of Section 8.3.2.1.
const SETUP_PATH: u64 = 0x01;

/// MAX_REQUEST_ID, the Setup Parameter of Section 8.3.2.2.
const SETUP_MAX_REQUEST_ID: u64 = 0x02;

/// MAX_AUTH_TOKEN_CACHE_SIZE, the Setup Parameter of Section 8.3.2.3.
const SETUP_MAX_AUTH_TOKEN_CACHE_SIZE: u64 = 0x04;

/// Every Version Specific Parameter Type Section 8.2.1 names.
///
/// This list is what "unknown" means to the receiver's half of the Section 8.2
/// rule. A type absent from it is one some extension defined, and Section 8.2
/// requires a receiver to carry a repeat of such a type rather than refuse it.
const KNOWN_PARAMETERS: &[u64] = &[AUTHORIZATION_TOKEN, DELIVERY_TIMEOUT, MAX_CACHE_DURATION];

/// The Version Specific Parameter Types whose own definition allows a repeat.
///
/// Section 8.2.1.1: "The AUTHORIZATION TOKEN parameter MAY be repeated within a
/// message." It is the only parameter on this draft that says so, and the
/// exemption it earns holds on both sides.
const REPEATABLE_PARAMETERS: &[u64] = &[AUTHORIZATION_TOKEN];

/// Every Setup Parameter Type Section 8.3.2 names.
const KNOWN_SETUP_PARAMETERS: &[u64] =
    &[SETUP_PATH, SETUP_MAX_REQUEST_ID, SETUP_MAX_AUTH_TOKEN_CACHE_SIZE];

/// The Setup Parameter Types whose own definition allows a repeat.
///
/// Draft-11 defines three Setup Parameters - PATH, MAX_REQUEST_ID and
/// MAX_AUTH_TOKEN_CACHE_SIZE - and none of them says it may be repeated, so
/// this namespace has no carve-out. Drafts 12 and 13 add AUTHORIZATION TOKEN to
/// the setup side in Section 8.3.2.4 and gain one.
///
/// The two namespaces are kept apart because 0x01 means different things in
/// each: AUTHORIZATION TOKEN among Version Specific Parameters, PATH among
/// Setup Parameters. One shared exemption list would let a CLIENT_SETUP state
/// PATH twice.
const REPEATABLE_SETUP_PARAMETERS: &[u64] = &[];

/// Refuse a parameter list a sender is not allowed to put on the wire.
///
/// Section 8.2: "Senders MUST NOT repeat the same parameter type in a message
/// unless the parameter definition explicitly allows multiple instances of that
/// type to be sent in a single message."
///
/// This is the wider half of the rule. It names no exception for types the
/// sender does not recognise, so every repeat is refused here except the ones
/// `repeatable` lists. A caller holding a parameter this codec has never heard
/// of still may not send it twice: code that scans a parameter list for a key
/// takes whichever copy it meets first, so one frame carrying two values for one
/// type is read differently by two conforming implementations, and that is true
/// whoever defined the type.
fn check_sender_parameters(
    parameters: &[KeyValuePair],
    repeatable: &[u64],
) -> Result<(), CodecError> {
    for (i, parameter) in parameters.iter().enumerate() {
        let key = parameter.key.into_inner();
        if repeatable.contains(&key) {
            continue;
        }
        if parameters[..i].iter().any(|earlier| earlier.key == parameter.key) {
            return Err(CodecError::DuplicateParameter(key));
        }
    }
    Ok(())
}

/// Refuse a received parameter list only where Section 8.2 lets a receiver
/// refuse it.
///
/// Section 8.2: "Receivers SHOULD check that there are no unauthorized
/// duplicate parameters and close the session as a 'Protocol Violation' if
/// found. Receivers MUST allow duplicates of unknown parameters."
///
/// The second sentence is why this is not the mirror of
/// [`check_sender_parameters`]: a repeat of a type this draft names is refused,
/// and a repeat of any other type is carried. Making the two sides symmetric
/// would close sessions over parameters defined by an extension this codec does
/// not implement - traffic the draft requires an endpoint to tolerate - and the
/// first sentence is a SHOULD, which does not reach that far.
fn check_receiver_parameters(
    parameters: &[KeyValuePair],
    known: &[u64],
    repeatable: &[u64],
) -> Result<(), CodecError> {
    for (i, parameter) in parameters.iter().enumerate() {
        let key = parameter.key.into_inner();
        if repeatable.contains(&key) || !known.contains(&key) {
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
/// Draft-11 states the general rule alone, in Section 1.3.2: "If a receiver
/// understands a Type, and the following Value or Length/Value does not match
/// the serialization defined by that Type, the receiver MUST terminate the
/// session with error code 'Key-Value Formatting Error'." The Token is the one
/// value in this draft whose serialization is a structure rather than opaque
/// bytes, so it is the one the rule has anything to say about.
///
/// The type is 0x01 here, and only in the version-specific namespace. A setup
/// 0x01 on this draft is a PATH, whose value is opaque bytes; reading one as a
/// Token would refuse paths the draft permits. Draft-12 renumbered the token to
/// 0x03 and added it to the setup namespace, where the two stop colliding.
///
/// A type this draft cannot name is left alone. The rule is conditional on the
/// receiver understanding the Type, and an extension's parameter carries bytes
/// no rule here describes.
fn check_authorization_tokens(parameters: &[KeyValuePair]) -> Result<(), CodecError> {
    for parameter in parameters {
        let key = parameter.key.into_inner();
        if key != AUTH_TOKEN_PARAMETER_D11 {
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

/// Decode a Version Specific Parameter list.
fn decode_parameters(buf: &mut impl Buf) -> Result<Vec<KeyValuePair>, CodecError> {
    let parameters = KeyValuePair::decode_list(buf)?;
    check_receiver_parameters(&parameters, KNOWN_PARAMETERS, REPEATABLE_PARAMETERS)?;
    check_authorization_tokens(&parameters)?;
    Ok(parameters)
}

/// Encode a Version Specific Parameter list.
///
/// The token structure is held to on the way out as well as on the way in. A
/// value that is not the serialization its Type defines is one the receiver
/// must close the session over, so writing it is not a way to send it — the
/// sender's first sign of trouble would be the session going.
///
/// Version-specific parameters only, which is where this draft's 0x01 is the
/// token; the setup 0x01 beside it is a PATH and its value is opaque bytes.
fn encode_parameters(parameters: &[KeyValuePair], buf: &mut impl BufMut) -> Result<(), CodecError> {
    check_sender_parameters(parameters, REPEATABLE_PARAMETERS)?;
    check_authorization_tokens(parameters)?;
    KeyValuePair::encode_list_checked(parameters, buf)?;
    Ok(())
}

/// Decode the Setup Parameters of a CLIENT_SETUP or SERVER_SETUP message.
fn decode_setup_parameters(buf: &mut impl Buf) -> Result<Vec<KeyValuePair>, CodecError> {
    let parameters = KeyValuePair::decode_list(buf)?;
    check_receiver_parameters(&parameters, KNOWN_SETUP_PARAMETERS, REPEATABLE_SETUP_PARAMETERS)?;
    Ok(parameters)
}

/// Encode the Setup Parameters of a CLIENT_SETUP or SERVER_SETUP message.
fn encode_setup_parameters(
    parameters: &[KeyValuePair],
    buf: &mut impl BufMut,
) -> Result<(), CodecError> {
    check_sender_parameters(parameters, REPEATABLE_SETUP_PARAMETERS)?;
    KeyValuePair::encode_list_checked(parameters, buf)?;
    Ok(())
}

impl ControlMessage {
    /// Encode this control message to bytes (including type ID and length prefix).
    ///
    /// Draft-11 framing: type_id(vi) + payload_length(16) + payload.
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
                encode_setup_parameters(&m.parameters, buf)?;
            }
            ControlMessage::ServerSetup(m) => {
                m.selected_version.encode(buf);
                encode_setup_parameters(&m.parameters, buf)?;
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
                m.track_namespace.validate(TrackNamespaceRules::for_draft(11))?;
                m.track_namespace.encode(buf);
                check_full_track_name(&m.track_namespace, &m.track_name)?;
                VarInt::from_usize(m.track_name.len()).encode(buf);
                buf.put_slice(&m.track_name);
                buf.put_u8(m.subscriber_priority);
                buf.put_u8(m.group_order as u8);
                buf.put_u8(m.forward as u8);
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
                encode_parameters(&m.parameters, buf)?;
            }
            ControlMessage::SubscribeOk(m) => {
                m.request_id.encode(buf);
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
                m.track_alias.encode(buf);
            }
            ControlMessage::SubscribeUpdate(m) => {
                m.request_id.encode(buf);
                m.start_group.encode(buf);
                m.start_object.encode(buf);
                m.end_group.encode(buf);
                buf.put_u8(m.subscriber_priority);
                buf.put_u8(m.forward as u8);
                encode_parameters(&m.parameters, buf)?;
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
                m.track_namespace.validate(TrackNamespaceRules::for_draft(11))?;
                m.track_namespace.encode(buf);
                encode_parameters(&m.parameters, buf)?;
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
                m.track_namespace.validate(TrackNamespaceRules::for_draft(11))?;
                m.track_namespace.encode(buf);
                m.error_code.encode(buf);
                VarInt::from_usize(m.reason_phrase.len()).encode(buf);
                buf.put_slice(&m.reason_phrase);
            }
            ControlMessage::Unannounce(m) => {
                m.track_namespace.validate(TrackNamespaceRules::for_draft(11))?;
                m.track_namespace.encode(buf);
            }
            ControlMessage::SubscribeAnnounces(m) => {
                m.request_id.encode(buf);
                m.track_namespace_prefix.validate(TrackNamespaceRules::for_draft(11))?;
                m.track_namespace_prefix.encode(buf);
                encode_parameters(&m.parameters, buf)?;
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
                m.track_namespace_prefix.validate(TrackNamespaceRules::for_draft(11))?;
                m.track_namespace_prefix.encode(buf);
            }
            ControlMessage::TrackStatusRequest(m) => {
                m.request_id.encode(buf);
                m.track_namespace.validate(TrackNamespaceRules::for_draft(11))?;
                m.track_namespace.encode(buf);
                check_full_track_name(&m.track_namespace, &m.track_name)?;
                VarInt::from_usize(m.track_name.len()).encode(buf);
                buf.put_slice(&m.track_name);
                encode_parameters(&m.parameters, buf)?;
            }
            ControlMessage::TrackStatus(m) => {
                m.request_id.encode(buf);
                check_track_status(m.status_code, m.largest_location)?;
                m.status_code.encode(buf);
                m.largest_location.encode(buf);
                encode_parameters(&m.parameters, buf)?;
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
                        track_namespace.validate(TrackNamespaceRules::for_draft(11))?;
                        track_namespace.encode(buf);
                        check_full_track_name(track_namespace, track_name)?;
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
                if uri_len > MAX_GOAWAY_URI_LENGTH {
                    return Err(CodecError::GoAwayUriTooLong);
                }
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
                check_full_track_name(&track_namespace, &track_name)?;
                if buf.remaining() < 1 {
                    return Err(CodecError::UnexpectedEnd);
                }
                let subscriber_priority = buf.get_u8();
                let group_order = read_group_order(buf)?;
                let forward = read_forward(buf)?;
                let filter_type = VarInt::decode(buf)?;
                let ft_val = filter_type.into_inner();
                if ft_val == 0 || ft_val > 4 {
                    return Err(CodecError::InvalidFilterType(ft_val));
                }
                let (start_group, start_object) = if ft_val == 3 || ft_val == 4 {
                    (Some(VarInt::decode(buf)?), Some(VarInt::decode(buf)?))
                } else {
                    (None, None)
                };
                let end_group = if ft_val == 4 { Some(VarInt::decode(buf)?) } else { None };
                let parameters = decode_parameters(buf)?;
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
                let group_order = read_group_order_response(buf)?;
                let content_exists = read_content_exists(buf)?;
                let largest_location = if content_exists == ContentExists::HasLargestLocation {
                    Some(Location::decode(buf)?)
                } else {
                    None
                };
                let parameters = decode_parameters(buf)?;
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
                let reason_phrase = read_reason_phrase(buf)?;
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
                let forward = read_forward(buf)?;
                let parameters = decode_parameters(buf)?;
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
                let reason_phrase = read_reason_phrase(buf)?;
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
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::Announce(Announce { request_id, track_namespace, parameters }))
            }
            MessageType::AnnounceOk => {
                let request_id = VarInt::decode(buf)?;
                Ok(ControlMessage::AnnounceOk(AnnounceOk { request_id }))
            }
            MessageType::AnnounceError => {
                let request_id = VarInt::decode(buf)?;
                let error_code = VarInt::decode(buf)?;
                let reason_phrase = read_reason_phrase(buf)?;
                Ok(ControlMessage::AnnounceError(AnnounceError {
                    request_id,
                    error_code,
                    reason_phrase,
                }))
            }
            MessageType::AnnounceCancel => {
                let track_namespace = TrackNamespace::decode(buf)?;
                let error_code = VarInt::decode(buf)?;
                let reason_phrase = read_reason_phrase(buf)?;
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
                let parameters = decode_parameters(buf)?;
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
                let reason_phrase = read_reason_phrase(buf)?;
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
                check_full_track_name(&track_namespace, &track_name)?;
                let parameters = decode_parameters(buf)?;
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
                check_track_status(status_code, largest_location)?;
                let parameters = decode_parameters(buf)?;
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
                let group_order = read_group_order(buf)?;
                let fetch_type_val = VarInt::decode(buf)?.into_inner();
                let fetch_type = FetchType::from_u64(fetch_type_val)
                    .ok_or(CodecError::InvalidFetchType(fetch_type_val))?;
                let fetch_payload = match fetch_type {
                    FetchType::Standalone => {
                        let track_namespace = TrackNamespace::decode(buf)?;
                        let track_name_len = VarInt::decode(buf)?.into_inner() as usize;
                        let track_name = types::read_bytes(buf, track_name_len)?;
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
                        let joining_subscribe_id = VarInt::decode(buf)?;
                        let joining_start = VarInt::decode(buf)?;
                        FetchPayload::Joining { joining_subscribe_id, joining_start }
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
                let group_order = read_group_order_response(buf)?;
                let end_of_track = read_u8(buf)?;
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

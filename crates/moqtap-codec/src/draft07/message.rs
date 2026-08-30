use crate::error::CodecError;
use crate::kvp::KeyValuePair;
use crate::types::read_bytes;
use crate::types::*;
use crate::types::{check_location_range, check_open_ended_group_range};
use crate::varint::VarInt;
use bytes::{Buf, BufMut};

/// Control message type IDs (draft-07).
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

// ============================================================
// Subscribe Messages
// ============================================================

/// SUBSCRIBE message (type 0x03).
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
    /// Present only for AbsoluteRange filter type (end_group).
    pub end_group: Option<VarInt>,
    /// Present only for AbsoluteRange filter type (end_object).
    pub end_object: Option<VarInt>,
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
    /// The new end object.
    pub end_object: VarInt,
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
    /// A human-readable reason phrase.
    pub reason_phrase: Vec<u8>,
    /// Whether the final location is included.
    pub content_exists: ContentExists,
    /// Present only when content_exists == HasLargestLocation.
    pub final_group: Option<VarInt>,
    /// Present only when content_exists == HasLargestLocation.
    pub final_object: Option<VarInt>,
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

/// FETCH message (type 0x16).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetch {
    /// The subscribe ID for this fetch request.
    pub subscribe_id: VarInt,
    /// The track namespace to fetch from.
    pub track_namespace: TrackNamespace,
    /// The track name to fetch.
    pub track_name: Vec<u8>,
    /// The priority of this subscriber relative to others.
    pub subscriber_priority: u8,
    /// The requested group delivery order.
    pub group_order: GroupOrder,
    /// The start group for the fetch range.
    pub start_group: VarInt,
    /// The start object for the fetch range.
    pub start_object: VarInt,
    /// The end group for the fetch range.
    pub end_group: VarInt,
    /// The end object for the fetch range.
    pub end_object: VarInt,
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
    /// Present only when end_of_track == 1.
    pub largest_group_id: Option<VarInt>,
    /// Present only when end_of_track == 1.
    pub largest_object_id: Option<VarInt>,
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

/// Hold a TRACK_STATUS Status Code and the fields after it to Section 6.23.
///
/// "The 'Status Code' field provides additional information about the status of
/// the track. It MUST hold one of the following values. Any other value is a
/// malformed message." Two of those values - 0x01 and 0x02 - add "Subsequent
/// fields MUST be zero, and any other value is a malformed message".
///
/// Applied on both sides. A malformed message is one this codec must not read
/// and equally must not write: an encoder that emits an unassigned Status Code
/// hands a conforming peer a message it is required to reject.
fn check_track_status(
    status_code: VarInt,
    last_group_id: VarInt,
    last_object_id: VarInt,
) -> Result<(), CodecError> {
    let code = crate::draft07::error_codes::TrackStatusCode::from_u64(status_code.into_inner())
        .ok_or(CodecError::InvalidField)?;
    if code.requires_zero_location()
        && (last_group_id.into_inner() != 0 || last_object_id.into_inner() != 0)
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
/// surplus ones, so bytes are left over. Section 6 makes either a session
/// close, which is why this refuses rather than papering over it.
fn check_discriminators(message: &ControlMessage) -> Result<(), CodecError> {
    match message {
        ControlMessage::Subscribe(m) => {
            let wants_start =
                matches!(m.filter_type, FilterType::AbsoluteStart | FilterType::AbsoluteRange);
            if wants_start != m.start_location.is_some() {
                return Err(CodecError::InvalidField);
            }
            let wants_end = m.filter_type == FilterType::AbsoluteRange;
            if wants_end != m.end_group.is_some() || wants_end != m.end_object.is_some() {
                return Err(CodecError::InvalidField);
            }
            Ok(())
        }
        ControlMessage::SubscribeOk(m) => {
            let has = m.content_exists == ContentExists::HasLargestLocation;
            if has != m.largest_group_id.is_some() || has != m.largest_object_id.is_some() {
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

/// A decoded MoQT control message (draft-07).
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

/// Refuse a request whose range ends before it starts.
///
/// SUBSCRIBE's AbsoluteRange filter (Section 6.4), SUBSCRIBE_UPDATE
/// (Section 6.5) and FETCH (Section 6.7) each state it, and the fields
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
        ControlMessage::Subscribe(m) => match (&m.start_location, &m.end_group, &m.end_object) {
            (Some(start), Some(end_group), Some(end_object)) => check_location_range(
                start.group.into_inner(),
                start.object.into_inner(),
                end_group.into_inner(),
                end_object.into_inner(),
            ),
            _ => Ok(()),
        },
        ControlMessage::SubscribeUpdate(m) => {
            check_open_ended_group_range(m.start_group.into_inner(), m.end_group.into_inner())
        }
        ControlMessage::Fetch(m) => check_location_range(
            m.start_group.into_inner(),
            m.start_object.into_inner(),
            m.end_group.into_inner(),
            m.end_object.into_inner(),
        ),
        _ => Ok(()),
    }
}

/// Refuse a parameter list that names the same Parameter Type twice.
///
/// Section 6.1: "Senders MUST NOT repeat the same parameter type in a
/// message. Receivers SHOULD check that there are no duplicate
/// parameters and close the session as a 'Protocol Violation' if found."
///
/// Applied on both sides. Code that scans a parameter list for a key takes
/// whichever copy it meets first, so one frame carrying two values for one type
/// is read differently by two conforming implementations - which is what makes
/// the sender's half a MUST NOT rather than advice.
fn check_no_duplicate_parameters(parameters: &[KeyValuePair]) -> Result<(), CodecError> {
    for (i, parameter) in parameters.iter().enumerate() {
        if parameters[..i].iter().any(|earlier| earlier.key == parameter.key) {
            return Err(CodecError::DuplicateParameter(parameter.key.into_inner()));
        }
    }
    Ok(())
}

/// The setup parameters this draft describes as carrying a single integer.
///
/// Section 6.2.2.1 gives ROLE three values "which are of type varint", and
/// Section 6.2.2.3 gives MAX_SUBSCRIBE_ID as "an initial value for the Maximum
/// Subscribe ID". PATH (Section 6.2.2.2) is a URI string and carries no implied
/// length, so it is absent.
const SETUP_VARINT_PARAMETERS: &[u64] = &[0x00, 0x02];

/// The version-specific parameters this draft describes as carrying a single
/// integer.
///
/// Section 6.1.1.2 gives DELIVERY TIMEOUT as "the duration in milliseconds"
/// and Section 6.1.1.3 gives MAX CACHE DURATION as "An integer expressing a
/// number of milliseconds". AUTHORIZATION INFO is "an ASCII string" and is
/// absent for the same reason PATH is.
///
/// The two lists are not interchangeable. Setup parameters and version-specific
/// parameters use separate namespaces, and 0x02 is MAX_SUBSCRIBE_ID in one and
/// AUTHORIZATION INFO in the other - applying the setup list to a SUBSCRIBE
/// would refuse every authorization string that is not accidentally a varint.
const VERSION_VARINT_PARAMETERS: &[u64] = &[0x03, 0x04];

/// Refuse a parameter whose value is not the shape its type implies.
///
/// Section 6.1: "If a receiver understands a parameter type, and the parameter
/// length implied by that type does not match the Parameter Length field, the
/// receiver MUST terminate the session with error code 'Parameter Length
/// Mismatch'."
///
/// This draft frames every parameter as {Type, Length, Value} with no per-key
/// table, so a parameter that came off the wire always arrives as bytes and its
/// declared length is whatever the sender wrote. For a type whose definition
/// says the value is one integer, the implied length is that varint's own
/// length, and the two agree only when the value is exactly one varint with
/// nothing after it.
///
/// A value already held as a varint is not checked: [`KeyValuePair::encode_d07`]
/// derives its length field from the varint it is about to write, so those two
/// cannot disagree. Only bytes can.
fn check_parameter_lengths(
    parameters: &[KeyValuePair],
    varint_typed: &[u64],
) -> Result<(), CodecError> {
    for parameter in parameters {
        let key = parameter.key.into_inner();
        if !varint_typed.contains(&key) {
            continue;
        }
        if let crate::kvp::KvpValue::Bytes(bytes) = &parameter.value {
            let mut cursor = &bytes[..];
            let one_varint = VarInt::decode(&mut cursor).is_ok() && !cursor.has_remaining();
            if !one_varint {
                return Err(CodecError::ParameterLengthMismatch(key));
            }
        }
    }
    Ok(())
}

/// Decode a version-specific parameter list, refusing a repeated type and a
/// value whose length disagrees with its type.
fn decode_parameters(buf: &mut impl Buf) -> Result<Vec<KeyValuePair>, CodecError> {
    let parameters = KeyValuePair::decode_list_d07(buf)?;
    check_no_duplicate_parameters(&parameters)?;
    check_parameter_lengths(&parameters, VERSION_VARINT_PARAMETERS)?;
    Ok(parameters)
}

/// Encode a version-specific parameter list, refusing a repeated type and a
/// value whose length disagrees with its type.
fn encode_parameters(parameters: &[KeyValuePair], buf: &mut impl BufMut) -> Result<(), CodecError> {
    check_no_duplicate_parameters(parameters)?;
    check_parameter_lengths(parameters, VERSION_VARINT_PARAMETERS)?;
    KeyValuePair::encode_list_d07(parameters, buf);
    Ok(())
}

/// Decode a setup parameter list.
///
/// Setup parameters use a namespace of their own, so the same key number means
/// something different here than it does in every other message and the implied
/// lengths are read from a different list.
fn decode_setup_parameters(buf: &mut impl Buf) -> Result<Vec<KeyValuePair>, CodecError> {
    let parameters = KeyValuePair::decode_list_d07(buf)?;
    check_no_duplicate_parameters(&parameters)?;
    check_parameter_lengths(&parameters, SETUP_VARINT_PARAMETERS)?;
    Ok(parameters)
}

/// Encode a setup parameter list, under the setup namespace's implied lengths.
fn encode_setup_parameters(
    parameters: &[KeyValuePair],
    buf: &mut impl BufMut,
) -> Result<(), CodecError> {
    check_no_duplicate_parameters(parameters)?;
    check_parameter_lengths(parameters, SETUP_VARINT_PARAMETERS)?;
    KeyValuePair::encode_list_d07(parameters, buf);
    Ok(())
}

impl ControlMessage {
    /// Return the message type for this control message.
    pub fn message_type(&self) -> MessageType {
        match self {
            ControlMessage::ClientSetup(_) => MessageType::ClientSetup,
            ControlMessage::ServerSetup(_) => MessageType::ServerSetup,
            ControlMessage::GoAway(_) => MessageType::GoAway,
            ControlMessage::MaxSubscribeId(_) => MessageType::MaxSubscribeId,
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
        check_discriminators(self)?;
        check_group_order(self)?;
        check_ranges(self)?;
        let mut payload = Vec::with_capacity(256);
        self.encode_payload(&mut payload)?;

        // No cap here. This draft frames a control message with a varint
        // Length and states no maximum, and this module's own decoder applies
        // none either - a ceiling on encode would refuse to write a message
        // this codec will read. The 65,535-byte limit belongs to draft-11 and
        // later, where the Length field is 16 bits wide and the limit is a
        // consequence of the framing.

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
                VarInt::from_usize(m.new_session_uri.len()).encode(buf);
                buf.put_slice(&m.new_session_uri);
            }
            ControlMessage::MaxSubscribeId(m) => {
                m.subscribe_id.encode(buf);
            }
            ControlMessage::Subscribe(m) => {
                m.subscribe_id.encode(buf);
                m.track_alias.encode(buf);
                m.track_namespace.validate(TrackNamespaceRules::for_draft(7))?;
                m.track_namespace.encode(buf);
                VarInt::from_usize(m.track_name.len()).encode(buf);
                buf.put_slice(&m.track_name);
                buf.put_u8(m.subscriber_priority);
                buf.put_u8(m.group_order as u8);
                buf.put_u8(m.filter_type as u8);
                if let Some(loc) = &m.start_location {
                    loc.encode(buf);
                }
                if let Some(eg) = &m.end_group {
                    eg.encode(buf);
                }
                if let Some(eo) = &m.end_object {
                    eo.encode(buf);
                }
                encode_parameters(&m.parameters, buf)?;
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
                encode_parameters(&m.parameters, buf)?;
            }
            ControlMessage::SubscribeError(m) => {
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
                m.end_object.encode(buf);
                buf.put_u8(m.subscriber_priority);
                encode_parameters(&m.parameters, buf)?;
            }
            ControlMessage::SubscribeDone(m) => {
                m.subscribe_id.encode(buf);
                m.status_code.encode(buf);
                VarInt::from_usize(m.reason_phrase.len()).encode(buf);
                buf.put_slice(&m.reason_phrase);
                buf.put_u8(m.content_exists as u8);
                if let Some(fg) = &m.final_group {
                    fg.encode(buf);
                }
                if let Some(fo) = &m.final_object {
                    fo.encode(buf);
                }
            }
            ControlMessage::Unsubscribe(m) => {
                m.subscribe_id.encode(buf);
            }
            ControlMessage::Announce(m) => {
                m.track_namespace.validate(TrackNamespaceRules::for_draft(7))?;
                m.track_namespace.encode(buf);
                encode_parameters(&m.parameters, buf)?;
            }
            ControlMessage::AnnounceOk(m) => {
                m.track_namespace.validate(TrackNamespaceRules::for_draft(7))?;
                m.track_namespace.encode(buf);
            }
            ControlMessage::AnnounceError(m) => {
                m.track_namespace.validate(TrackNamespaceRules::for_draft(7))?;
                m.track_namespace.encode(buf);
                m.error_code.encode(buf);
                VarInt::from_usize(m.reason_phrase.len()).encode(buf);
                buf.put_slice(&m.reason_phrase);
            }
            ControlMessage::AnnounceCancel(m) => {
                m.track_namespace.validate(TrackNamespaceRules::for_draft(7))?;
                m.track_namespace.encode(buf);
                m.error_code.encode(buf);
                VarInt::from_usize(m.reason_phrase.len()).encode(buf);
                buf.put_slice(&m.reason_phrase);
            }
            ControlMessage::Unannounce(m) => {
                m.track_namespace.validate(TrackNamespaceRules::for_draft(7))?;
                m.track_namespace.encode(buf);
            }
            ControlMessage::SubscribeAnnounces(m) => {
                m.track_namespace_prefix.validate(TrackNamespaceRules::for_draft(7))?;
                m.track_namespace_prefix.encode(buf);
                encode_parameters(&m.parameters, buf)?;
            }
            ControlMessage::SubscribeAnnouncesOk(m) => {
                m.track_namespace_prefix.validate(TrackNamespaceRules::for_draft(7))?;
                m.track_namespace_prefix.encode(buf);
            }
            ControlMessage::SubscribeAnnouncesError(m) => {
                m.track_namespace_prefix.validate(TrackNamespaceRules::for_draft(7))?;
                m.track_namespace_prefix.encode(buf);
                m.error_code.encode(buf);
                VarInt::from_usize(m.reason_phrase.len()).encode(buf);
                buf.put_slice(&m.reason_phrase);
            }
            ControlMessage::UnsubscribeAnnounces(m) => {
                m.track_namespace_prefix.validate(TrackNamespaceRules::for_draft(7))?;
                m.track_namespace_prefix.encode(buf);
            }
            ControlMessage::TrackStatusRequest(m) => {
                m.track_namespace.validate(TrackNamespaceRules::for_draft(7))?;
                m.track_namespace.encode(buf);
                VarInt::from_usize(m.track_name.len()).encode(buf);
                buf.put_slice(&m.track_name);
            }
            ControlMessage::TrackStatus(m) => {
                m.track_namespace.validate(TrackNamespaceRules::for_draft(7))?;
                m.track_namespace.encode(buf);
                VarInt::from_usize(m.track_name.len()).encode(buf);
                buf.put_slice(&m.track_name);
                check_track_status(m.status_code, m.last_group_id, m.last_object_id)?;
                m.status_code.encode(buf);
                m.last_group_id.encode(buf);
                m.last_object_id.encode(buf);
            }
            ControlMessage::Fetch(m) => {
                m.subscribe_id.encode(buf);
                m.track_namespace.validate(TrackNamespaceRules::for_draft(7))?;
                m.track_namespace.encode(buf);
                VarInt::from_usize(m.track_name.len()).encode(buf);
                buf.put_slice(&m.track_name);
                buf.put_u8(m.subscriber_priority);
                buf.put_u8(m.group_order as u8);
                m.start_group.encode(buf);
                m.start_object.encode(buf);
                m.end_group.encode(buf);
                m.end_object.encode(buf);
                encode_parameters(&m.parameters, buf)?;
            }
            ControlMessage::FetchOk(m) => {
                m.subscribe_id.encode(buf);
                buf.put_u8(m.group_order as u8);
                buf.put_u8(m.end_of_track);
                if let Some(gid) = &m.largest_group_id {
                    gid.encode(buf);
                }
                if let Some(oid) = &m.largest_object_id {
                    oid.encode(buf);
                }
                encode_parameters(&m.parameters, buf)?;
            }
            ControlMessage::FetchError(m) => {
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
                let uri = read_bytes(buf, uri_len)?;
                Ok(ControlMessage::GoAway(GoAway { new_session_uri: uri }))
            }
            MessageType::MaxSubscribeId => {
                let subscribe_id = VarInt::decode(buf)?;
                Ok(ControlMessage::MaxSubscribeId(MaxSubscribeId { subscribe_id }))
            }
            MessageType::Subscribe => {
                let subscribe_id = VarInt::decode(buf)?;
                let track_alias = VarInt::decode(buf)?;
                let track_namespace = TrackNamespace::decode(buf)?;
                let track_name_len = VarInt::decode(buf)?.into_inner() as usize;
                let track_name = read_bytes(buf, track_name_len)?;
                if buf.remaining() < 3 {
                    return Err(CodecError::UnexpectedEnd);
                }
                let subscriber_priority = buf.get_u8();
                let group_order =
                    GroupOrder::from_u8(buf.get_u8()).ok_or(CodecError::InvalidField)?;
                let filter_val = buf.get_u8();
                let filter_type = FilterType::from_u8(filter_val)
                    .ok_or(CodecError::InvalidFilterType(filter_val as u64))?;
                let start_location = match filter_type {
                    FilterType::AbsoluteStart | FilterType::AbsoluteRange => {
                        Some(Location::decode(buf)?)
                    }
                    _ => None,
                };
                let (end_group, end_object) = match filter_type {
                    FilterType::AbsoluteRange => {
                        let eg = VarInt::decode(buf)?;
                        let eo = VarInt::decode(buf)?;
                        (Some(eg), Some(eo))
                    }
                    _ => (None, None),
                };
                let parameters = decode_parameters(buf)?;
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
                    end_object,
                    parameters,
                }))
            }
            MessageType::SubscribeOk => {
                let subscribe_id = VarInt::decode(buf)?;
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
                let (largest_group_id, largest_object_id) =
                    if content_exists == ContentExists::HasLargestLocation {
                        let gid = VarInt::decode(buf)?;
                        let oid = VarInt::decode(buf)?;
                        (Some(gid), Some(oid))
                    } else {
                        (None, None)
                    };
                let parameters = decode_parameters(buf)?;
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
                let end_object = VarInt::decode(buf)?;
                if buf.remaining() < 1 {
                    return Err(CodecError::UnexpectedEnd);
                }
                let subscriber_priority = buf.get_u8();
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::SubscribeUpdate(SubscribeUpdate {
                    subscribe_id,
                    start_group,
                    start_object,
                    end_group,
                    end_object,
                    subscriber_priority,
                    parameters,
                }))
            }
            MessageType::SubscribeDone => {
                let subscribe_id = VarInt::decode(buf)?;
                let status_code = VarInt::decode(buf)?;
                let reason_len = VarInt::decode(buf)?.into_inner() as usize;
                let reason_phrase = read_bytes(buf, reason_len)?;
                if buf.remaining() < 1 {
                    return Err(CodecError::UnexpectedEnd);
                }
                let content_exists_val = buf.get_u8();
                let content_exists = match content_exists_val {
                    0 => ContentExists::NoLargestLocation,
                    1 => ContentExists::HasLargestLocation,
                    other => return Err(CodecError::InvalidContentExists(other)),
                };
                let (final_group, final_object) =
                    if content_exists == ContentExists::HasLargestLocation {
                        let fg = VarInt::decode(buf)?;
                        let fo = VarInt::decode(buf)?;
                        (Some(fg), Some(fo))
                    } else {
                        (None, None)
                    };
                Ok(ControlMessage::SubscribeDone(SubscribeDone {
                    subscribe_id,
                    status_code,
                    reason_phrase,
                    content_exists,
                    final_group,
                    final_object,
                }))
            }
            MessageType::Unsubscribe => {
                let subscribe_id = VarInt::decode(buf)?;
                Ok(ControlMessage::Unsubscribe(Unsubscribe { subscribe_id }))
            }
            MessageType::Announce => {
                let track_namespace = TrackNamespace::decode(buf)?;
                let parameters = decode_parameters(buf)?;
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
                let parameters = decode_parameters(buf)?;
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
                check_track_status(status_code, last_group_id, last_object_id)?;
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
                let track_namespace = TrackNamespace::decode(buf)?;
                let track_name_len = VarInt::decode(buf)?.into_inner() as usize;
                let track_name = read_bytes(buf, track_name_len)?;
                if buf.remaining() < 2 {
                    return Err(CodecError::UnexpectedEnd);
                }
                let subscriber_priority = buf.get_u8();
                let group_order =
                    GroupOrder::from_u8(buf.get_u8()).ok_or(CodecError::InvalidField)?;
                let start_group = VarInt::decode(buf)?;
                let start_object = VarInt::decode(buf)?;
                let end_group = VarInt::decode(buf)?;
                let end_object = VarInt::decode(buf)?;
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::Fetch(Fetch {
                    subscribe_id,
                    track_namespace,
                    track_name,
                    subscriber_priority,
                    group_order,
                    start_group,
                    start_object,
                    end_group,
                    end_object,
                    parameters,
                }))
            }
            MessageType::FetchOk => {
                let subscribe_id = VarInt::decode(buf)?;
                if buf.remaining() < 2 {
                    return Err(CodecError::UnexpectedEnd);
                }
                let group_order = read_group_order_response(buf)?;
                let end_of_track = buf.get_u8();
                let largest_group_id = Some(VarInt::decode(buf)?);
                let largest_object_id = Some(VarInt::decode(buf)?);
                let parameters = decode_parameters(buf)?;
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

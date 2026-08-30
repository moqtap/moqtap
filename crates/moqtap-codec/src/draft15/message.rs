//! Draft-15 control message encoding and decoding.
//!
//! Key changes from draft-14:
//! - Version negotiation via ALPN — ClientSetup/ServerSetup have no versions
//! - Consolidated RequestOk (0x07) and RequestError (0x05)
//! - Subscribe simplified: request_id + ns + track_name + params
//! - SubscribeOk simplified: request_id + track_alias + params
//! - Publish simplified: request_id + ns + track_name + track_alias + params
//! - PublishOk simplified: request_id + params
//! - SubscribeUpdate: request_id + subscription_request_id + params
//! - FetchOk: request_id + end_of_track + end_group + end_object + params
//! - PublishDone (0x0B) replaces SubscribeDone
//! - Framing: type_id(vi) + payload_length(16) + payload

use crate::auth_token::{AuthorizationToken, AUTH_TOKEN_PARAMETER};
use crate::error::{
    CodecError, MAX_FULL_TRACK_NAME_LENGTH, MAX_GOAWAY_URI_LENGTH, MAX_MESSAGE_LENGTH,
    MAX_REASON_PHRASE_LENGTH,
};
use crate::kvp::{KeyValuePair, KvpValue};
use crate::subscription_filter::{SubscriptionFilter, SUBSCRIPTION_FILTER_PARAMETER};
pub use crate::types::check_location_range;
use crate::types::*;
use crate::varint::VarInt;
use bytes::{Buf, BufMut};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum MessageType {
    SubscribeUpdate = 0x02,
    Subscribe = 0x03,
    SubscribeOk = 0x04,
    RequestError = 0x05,
    PublishNamespace = 0x06,
    RequestOk = 0x07,
    PublishNamespaceDone = 0x09,
    Unsubscribe = 0x0A,
    PublishDone = 0x0B,
    PublishNamespaceCancel = 0x0C,
    TrackStatus = 0x0D,
    GoAway = 0x10,
    SubscribeNamespace = 0x11,
    UnsubscribeNamespace = 0x14,
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
            0x02 => Some(MessageType::SubscribeUpdate),
            0x03 => Some(MessageType::Subscribe),
            0x04 => Some(MessageType::SubscribeOk),
            0x05 => Some(MessageType::RequestError),
            0x06 => Some(MessageType::PublishNamespace),
            0x07 => Some(MessageType::RequestOk),
            0x09 => Some(MessageType::PublishNamespaceDone),
            0x0A => Some(MessageType::Unsubscribe),
            0x0B => Some(MessageType::PublishDone),
            0x0C => Some(MessageType::PublishNamespaceCancel),
            0x0D => Some(MessageType::TrackStatus),
            0x10 => Some(MessageType::GoAway),
            0x11 => Some(MessageType::SubscribeNamespace),
            0x14 => Some(MessageType::UnsubscribeNamespace),
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

/// CLIENT_SETUP (0x20). Draft-15: no versions, just parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSetup {
    pub parameters: Vec<KeyValuePair>,
}

/// SERVER_SETUP (0x21). Draft-15: no version, just parameters.
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

/// REQUEST_OK (0x07). Consolidated OK response for all request types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestOk {
    pub request_id: VarInt,
    pub parameters: Vec<KeyValuePair>,
}

/// REQUEST_ERROR (0x05). Consolidated error response for all request types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestError {
    pub request_id: VarInt,
    pub error_code: VarInt,
    pub reason_phrase: Vec<u8>,
}

// ============================================================
// Subscribe Messages
// ============================================================

/// SUBSCRIBE (0x03). Simplified: fields moved to parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscribe {
    pub request_id: VarInt,
    pub track_namespace: TrackNamespace,
    pub track_name: Vec<u8>,
    pub parameters: Vec<KeyValuePair>,
}

/// SUBSCRIBE_OK (0x04). Simplified: most fields moved to parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeOk {
    pub request_id: VarInt,
    pub track_alias: VarInt,
    pub parameters: Vec<KeyValuePair>,
}

/// SUBSCRIBE_UPDATE (0x02). request_id + subscription_request_id + params.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeUpdate {
    pub request_id: VarInt,
    pub subscription_request_id: VarInt,
    pub parameters: Vec<KeyValuePair>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unsubscribe {
    pub request_id: VarInt,
}

// ============================================================
// Publish Messages
// ============================================================

/// PUBLISH (0x1D). Simplified: request_id + ns + name + alias + params.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publish {
    pub request_id: VarInt,
    pub track_namespace: TrackNamespace,
    pub track_name: Vec<u8>,
    pub track_alias: VarInt,
    pub parameters: Vec<KeyValuePair>,
}

/// PUBLISH_OK (0x1E). Simplified: request_id + params.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishOk {
    pub request_id: VarInt,
    pub parameters: Vec<KeyValuePair>,
}

/// PUBLISH_DONE (0x0B). Replaces SubscribeDone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishDone {
    pub request_id: VarInt,
    pub status_code: VarInt,
    pub stream_count: VarInt,
    pub reason_phrase: Vec<u8>,
}

// ============================================================
// Publish Namespace Messages (renamed from Announce)
// ============================================================

/// PUBLISH_NAMESPACE (0x06). request_id + namespace + params.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishNamespace {
    pub request_id: VarInt,
    pub track_namespace: TrackNamespace,
    pub parameters: Vec<KeyValuePair>,
}

/// PUBLISH_NAMESPACE_DONE (0x09). Just namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishNamespaceDone {
    pub track_namespace: TrackNamespace,
}

/// PUBLISH_NAMESPACE_CANCEL (0x0C). namespace + error_code + reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishNamespaceCancel {
    pub track_namespace: TrackNamespace,
    pub error_code: VarInt,
    pub reason_phrase: Vec<u8>,
}

// ============================================================
// Subscribe Namespace Messages
// ============================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeNamespace {
    pub request_id: VarInt,
    pub namespace_prefix: TrackNamespace,
    pub parameters: Vec<KeyValuePair>,
}

/// UNSUBSCRIBE_NAMESPACE (0x14). Just request_id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsubscribeNamespace {
    pub request_id: VarInt,
}

// ============================================================
// Track Status Messages
// ============================================================

/// TRACK_STATUS (0x0D). Same structure as Subscribe.
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
    /// Whether the end of the track has been reached.
    ///
    /// Held as a raw byte rather than an enum: the draft describes 1 and 0 and
    /// says nothing about any other value, where it does call an out-of-range
    /// Group Order or Content Exists a protocol error. Refusing a 2 here would
    /// be this codec's rule and not the draft's.
    pub end_of_track: u8,
    pub end_group: VarInt,
    pub end_object: VarInt,
    pub parameters: Vec<KeyValuePair>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchCancel {
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
    SubscribeUpdate(SubscribeUpdate),
    Unsubscribe(Unsubscribe),
    Publish(Publish),
    PublishOk(PublishOk),
    PublishDone(PublishDone),
    PublishNamespace(PublishNamespace),
    PublishNamespaceDone(PublishNamespaceDone),
    PublishNamespaceCancel(PublishNamespaceCancel),
    SubscribeNamespace(SubscribeNamespace),
    UnsubscribeNamespace(UnsubscribeNamespace),
    TrackStatus(TrackStatus),
    Fetch(Fetch),
    FetchOk(FetchOk),
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
/// "The reason phrase length has a maximum value of 1024 bytes. If an endpoint
/// receives a length exceeding the maximum, it MUST close the session with a
/// PROTOCOL_VIOLATION". The sentence is about what an endpoint receives, and
/// receiving was the direction the cap was not applied to: the encoders refused
/// an over-long phrase and the decoders accepted one.
fn read_reason_phrase(buf: &mut impl Buf) -> Result<Vec<u8>, CodecError> {
    let len = VarInt::decode(buf)?.into_inner() as usize;
    if len > MAX_REASON_PHRASE_LENGTH {
        return Err(CodecError::ReasonPhraseTooLong);
    }
    read_bytes(buf, len)
}

/// Refuse a FETCH whose range ends before it starts.
///
/// Section 9.16.3: "Fetch specifies an inclusive range of Objects starting at
/// Start Location and ending at End Location. End Location MUST specify the
/// same or a larger Location than Start Location for Standalone and Absolute Joining Fetches." A Joining Fetch names
/// no explicit range - it is computed from the subscription it joins - so only
/// a standalone range is checked here.
///
/// SUBSCRIBE is not checked here. Its filter moved into the parameters on
/// this draft, and this codec carries a parameter value as the bytes it
/// arrived as, so the start and end are not fields this function can see.
///
/// Applied on both sides. A range that ends before it starts selects nothing,
/// and the peer's only recourse is an error response or a session close, so
/// writing one is not a way to ask for anything.
fn check_ranges(message: &ControlMessage) -> Result<(), CodecError> {
    match message {
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

/// Refuse a message whose discriminator disagrees with the fields beside it.
///
/// A discriminator is a field that says which of the fields after it are on the
/// wire. Where this codec holds the alternatives as an enum or an `Option`
/// beside the discriminator, a value can say one thing in the discriminator and
/// another in the body, and the two sides of the codec resolve that
/// disagreement differently: the encoder writes whatever the body holds, and
/// the decoder reads whatever the discriminator announces. The result is a
/// message that does not survive its own round trip, and the encoder is the
/// side that can still refuse it.
///
/// Draft-15 has exactly one such message, which is why this is shorter than the
/// same check on draft-14. Section 9.16 gives FETCH a Fetch Type — "There are
/// three types of Fetch messages... An endpoint that receives a Fetch Type other
/// than 0x1, 0x2 or 0x3 MUST close the session with a PROTOCOL_VIOLATION" — and
/// Section 9.16.3 puts the Standalone and Joining bodies in the message as
/// alternatives that the type selects between.
///
/// The messages that carried the other discriminators on draft-14 no longer do.
/// SUBSCRIBE's Filter Type became the SUBSCRIPTION_FILTER parameter of Section
/// 9.2.1.7, and SUBSCRIBE_OK's Content Exists became the LARGEST_OBJECT
/// parameter of Section 9.2.1.9; a parameter is present or it is absent, so
/// neither leaves a discriminator to disagree with. Copying draft-14's arms over
/// unchanged would not compile, and adding fields to make them compile would
/// invent a rule this draft does not have.
///
/// A mis-stated FETCH is the concrete case. A Standalone type beside a Joining
/// body writes a request id and a start where the peer reads a Track Namespace
/// and a Track Name, and the fetch that arrives names a track after two
/// integers — or, more often, fails to parse, which at least is honest.
fn check_discriminators(message: &ControlMessage) -> Result<(), CodecError> {
    if let ControlMessage::Fetch(m) = message {
        let body_is_standalone = matches!(m.fetch_payload, FetchPayload::Standalone { .. });
        if body_is_standalone != (m.fetch_type == FetchType::Standalone) {
            return Err(CodecError::InvalidField);
        }
    }
    Ok(())
}

/// The one parameter type whose own definition lets it repeat.
///
/// Section 9.2.1.1: "The AUTHORIZATION TOKEN parameter MAY be repeated within a
/// message as long as the combination of Token Type and Token Value are unique
/// after resolving any aliases." That is the "unless the parameter definition
/// explicitly allows multiple instances" carve-out of Section 9.2, and on this
/// draft it is the only one — none of the other eleven version-specific
/// parameters, nor any of the six setup parameters, says the like.
///
/// The trailing condition is not enforced here. Resolving an alias needs the
/// session's token cache, which a codec framing one message does not have;
/// uniqueness of the resolved pair is a session rule and not a wire rule. What
/// is enforced is the permission itself, which is what a duplicate check needs
/// to know.
///
/// The same code point, 0x03, in both namespaces: Section 9.2.1.1 assigns it to
/// the message parameter and Section 9.3.1.5 defines the setup parameter as "See
/// Section 9.2.1.1", so a sender may repeat it in a SETUP as well. The name is
/// the same on draft-14, whose Section 9.2.1.1 states the permission in the
/// shorter form; the earlier name, AUTHORIZATION INFO, belongs to drafts 07
/// through 10, which stated no permission at all.
const REPEATABLE_PARAMETER: u64 = 0x03;

/// Every version-specific parameter type draft-15 names, from the registry of
/// Section 13.2, Table 10.
///
/// DELIVERY_TIMEOUT (0x02), AUTHORIZATION_TOKEN (0x03), MAX_CACHE_DURATION
/// (0x04), EXPIRES (0x08), LARGEST_OBJECT (0x09), PUBLISHER_PRIORITY (0x0E),
/// FORWARD (0x10), SUBSCRIBER_PRIORITY (0x20), SUBSCRIPTION_FILTER (0x21),
/// GROUP_ORDER (0x22), DYNAMIC_GROUPS (0x30) and NEW_GROUP_REQUEST (0x32).
/// Four times the length of draft-14's list, because draft-15 is the draft that
/// moved SUBSCRIBE's and SUBSCRIBE_OK's fixed fields into parameters.
///
/// The list exists for one rule and one direction. Section 9.2: "Receivers MUST
/// allow duplicates of unknown parameters." A receiver may therefore refuse a
/// repeat only of a type it can name, and a type outside this list belongs to an
/// extension this codec has no business closing a session over. Nothing else
/// reads it — an unknown parameter is still decoded and carried.
const KNOWN_VERSION_SPECIFIC_PARAMETERS: &[u64] =
    &[0x02, 0x03, 0x04, 0x08, 0x09, 0x0E, 0x10, 0x20, 0x21, 0x22, 0x30, 0x32];

/// Every setup parameter type draft-15 names, from Section 9.3.1.
///
/// PATH (0x01), MAX_REQUEST_ID (0x02), AUTHORIZATION TOKEN (0x03),
/// MAX_AUTH_TOKEN_CACHE_SIZE (0x04), AUTHORITY (0x05) and MOQT_IMPLEMENTATION
/// (0x07). The last is what draft-14 numbered 0x05, colliding with AUTHORITY;
/// draft-15 is where it moved.
///
/// Setup parameters are a separate namespace — Section 9.2.1 says so outright:
/// "since Setup parameters use a separate namespace, it is impossible for these
/// parameters to appear in Setup messages" — so a receiver deciding whether it
/// can name a type has to know which of the two lists to consult. Reading a
/// SETUP against the version-specific list would tolerate a repeated PATH, which
/// this draft names and a receiver may refuse.
const KNOWN_SETUP_PARAMETERS: &[u64] = &[0x01, 0x02, 0x03, 0x04, 0x05, 0x07];

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
/// MUST close the Session with KEY_VALUE_FORMATTING_ERROR." That is the answer
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

/// Whether `value` is inside the range draft-15 allows for a version-specific
/// parameter type that restricts one.
///
/// Four types do. FORWARD, Section 9.2.1.10: "The allowed values are 0 (don't
/// forward) or 1 (forward). If an endpoint receives a value outside this range,
/// it MUST close the session with PROTOCOL_VIOLATION." GROUP_ORDER, Section
/// 9.2.1.6, says the same of Ascending (0x1) and Descending (0x2).
/// SUBSCRIBER_PRIORITY, Section 9.2.1.5: "The range is restricted to 0-255. If a
/// publisher receives a value outside this range, it MUST close the session with
/// PROTOCOL_VIOLATION." DYNAMIC_GROUPS, Section 9.2.1.11: "Values larger than 1
/// are a Protocol Violation."
///
/// Group Order is the one to read twice. Where drafts 07 through 14 carried it
/// as a message field and let a request send 0x0 to mean "no preference", the
/// parameter form has no such value: a subscriber with no preference omits the
/// parameter, and 0x0 closes the session in every message that carries it. The
/// asymmetry that governs the field form does not survive into this one.
///
/// PUBLISHER_PRIORITY (0x0E) is deliberately absent. Section 9.2.1.4 says "The
/// value is from 0 to 255 and lower numbers get higher priority", points at
/// Section 7 for the ordering itself, and adds "Priorities above 255 are
/// invalid." — and stops, where each of the four above names a consequence in
/// the next clause. Adding it here would close sessions on a sentence the draft
/// did not write.
fn parameter_value_in_range(key: u64, value: u64) -> bool {
    match key {
        // FORWARD (0x10) and DYNAMIC_GROUPS (0x30)
        0x10 | 0x30 => value <= 1,
        // SUBSCRIBER_PRIORITY (0x20)
        0x20 => value <= 255,
        // GROUP_ORDER (0x22)
        0x22 => value == 1 || value == 2,
        _ => true,
    }
}

/// Refuse a parameter whose value falls outside the range its type allows.
///
/// Only the varint-valued shape is examined. Every type with a range is an even
/// number, and draft-15 gives an even type a bare varint value, so a
/// length-prefixed value under one of these keys is already a
/// [`CodecError::KeyValueFormatting`] before it reaches here.
fn check_parameter_value_ranges(parameters: &[KeyValuePair]) -> Result<(), CodecError> {
    for parameter in parameters {
        if let KvpValue::Varint(value) = &parameter.value {
            let key = parameter.key.into_inner();
            let value = value.into_inner();
            if !parameter_value_in_range(key, value) {
                return Err(CodecError::ParameterValueOutOfRange { key, value });
            }
        }
    }
    Ok(())
}

/// Hold every SUBSCRIPTION_FILTER parameter to the filter structure it names.
///
/// Two sentences meet on this value. Section 5.1.2: "An endpoint that receives a
/// filter type other than the above MUST close the session with
/// PROTOCOL_VIOLATION." Section 9.2.1.7: "It is a length-prefixed Subscription
/// Filter... If the length of the Subscription Filter does not match the
/// parameter length, the publisher MUST close the session with
/// PROTOCOL_VIOLATION."
///
/// Draft-14 read the same three values as fields of SUBSCRIBE and checked them
/// there. This draft moved them inside a parameter, and a parameter whose value
/// is a run of bytes carries a Filter Type nothing reads: the rule went from
/// enforced to invisible without a word of either draft changing.
///
/// The filter is decoded and discarded. What is kept is the refusal — the value
/// stays on the parameter as the bytes that arrived, so a caller reads it
/// through [`SubscriptionFilter::decode`] when it wants the filter rather than
/// the frame.
///
/// Version-specific parameters only. Section 9.2.1 keeps the two namespaces
/// apart, and a setup 0x21 is not this parameter.
fn check_subscription_filters(parameters: &[KeyValuePair]) -> Result<(), CodecError> {
    for parameter in parameters {
        if parameter.key.into_inner() != SUBSCRIPTION_FILTER_PARAMETER {
            continue;
        }
        match &parameter.value {
            KvpValue::Bytes(value) => {
                SubscriptionFilter::decode(value)?;
            }
            // Unreachable from the decoder: 0x21 is odd, and Section 1.4.2
            // gives an odd Type a length-prefixed value. A caller that built
            // the pair in memory can still get here, and it is the same rule.
            KvpValue::Varint(_) => {
                return Err(CodecError::SubscriptionFilterMalformed {
                    detail: "its value is a bare varint where the type defines a filter",
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
    check_parameter_value_ranges(&parameters)?;
    check_subscription_filters(&parameters)?;
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

/// Encode a version-specific parameter list, refusing every list
/// [`decode_parameters`] would refuse.
///
/// The duplicate rule the sender is held to is its own — it exempts a parameter
/// type rather than a namespace, and the exempt type has the same code point in
/// each, which is why one call covers both. The three value rules are the
/// reader's, applied here for the reason each of them states a close: a value
/// that is not what its Type defines is one the receiver must close the session
/// over, so writing it is not a way to send it. The sender's first sign of
/// trouble would be the session going.
fn encode_parameters(parameters: &[KeyValuePair], buf: &mut impl BufMut) -> Result<(), CodecError> {
    check_no_duplicate_parameters_sent(parameters)?;
    check_authorization_tokens(parameters)?;
    check_parameter_value_ranges(parameters)?;
    check_subscription_filters(parameters)?;
    KeyValuePair::encode_list_checked(parameters, buf)?;
    Ok(())
}

/// Encode a SETUP message's parameter list.
///
/// Separate from [`encode_parameters`] for the reason the decode side is: two of
/// the three value rules are version-specific, and a setup 0x21 or 0x22 is not
/// the parameter either of them describes. The token is in both namespaces and
/// is held to its structure in both.
fn encode_setup_parameters(
    parameters: &[KeyValuePair],
    buf: &mut impl BufMut,
) -> Result<(), CodecError> {
    check_no_duplicate_parameters_sent(parameters)?;
    check_authorization_tokens(parameters)?;
    KeyValuePair::encode_list_checked(parameters, buf)?;
    Ok(())
}

impl ControlMessage {
    pub fn encode(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        check_discriminators(self)?;
        check_ranges(self)?;
        let mut payload = Vec::with_capacity(256);
        self.encode_payload(&mut payload)?;

        if payload.len() > MAX_MESSAGE_LENGTH {
            return Err(CodecError::MessageTooLong(payload.len()));
        }

        let msg_type = self.message_type();
        VarInt::from_usize(msg_type.id() as usize).encode(buf);
        // Draft-15: 16-bit length (big-endian)
        buf.put_u16(payload.len() as u16);
        buf.put_slice(&payload);
        Ok(())
    }

    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let type_id = VarInt::decode(buf)?.into_inner();
        let msg_type =
            MessageType::from_id(type_id).ok_or(CodecError::UnknownMessageType(type_id))?;
        // Draft-15: 16-bit length (big-endian)
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
        // Draft-15 Section 9: "The length is set to the number of bytes in
        // Message Payload... If the length does not match the length of the
        // Message Payload, the receiver MUST close the session with a
        // PROTOCOL_VIOLATION."
        //
        // A payload longer than its fields is the half that reads as success:
        // the declared length keeps the outer stream in sync, so bytes no field
        // consumed are simply dropped and nothing downstream notices. That hides
        // a real framing disagreement — a peer emitting a field this codec does
        // not know about looks identical to a peer sending nothing extra.
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
                encode_setup_parameters(&m.parameters, buf)?;
            }
            ControlMessage::ServerSetup(m) => {
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
            ControlMessage::RequestOk(m) => {
                m.request_id.encode(buf);
                encode_parameters(&m.parameters, buf)?;
            }
            ControlMessage::RequestError(m) => {
                if m.reason_phrase.len() > MAX_REASON_PHRASE_LENGTH {
                    return Err(CodecError::ReasonPhraseTooLong);
                }
                m.request_id.encode(buf);
                m.error_code.encode(buf);
                VarInt::from_usize(m.reason_phrase.len()).encode(buf);
                buf.put_slice(&m.reason_phrase);
            }
            ControlMessage::Subscribe(m) => {
                m.request_id.encode(buf);
                m.track_namespace.validate(TrackNamespaceRules::for_draft(15))?;
                m.track_namespace.encode(buf);
                check_full_track_name(&m.track_namespace, &m.track_name)?;
                VarInt::from_usize(m.track_name.len()).encode(buf);
                buf.put_slice(&m.track_name);
                encode_parameters(&m.parameters, buf)?;
            }
            ControlMessage::SubscribeOk(m) => {
                m.request_id.encode(buf);
                m.track_alias.encode(buf);
                encode_parameters(&m.parameters, buf)?;
            }
            ControlMessage::SubscribeUpdate(m) => {
                m.request_id.encode(buf);
                m.subscription_request_id.encode(buf);
                encode_parameters(&m.parameters, buf)?;
            }
            ControlMessage::Unsubscribe(m) => {
                m.request_id.encode(buf);
            }
            ControlMessage::Publish(m) => {
                m.request_id.encode(buf);
                m.track_namespace.validate(TrackNamespaceRules::for_draft(15))?;
                m.track_namespace.encode(buf);
                check_full_track_name(&m.track_namespace, &m.track_name)?;
                VarInt::from_usize(m.track_name.len()).encode(buf);
                buf.put_slice(&m.track_name);
                m.track_alias.encode(buf);
                encode_parameters(&m.parameters, buf)?;
            }
            ControlMessage::PublishOk(m) => {
                m.request_id.encode(buf);
                encode_parameters(&m.parameters, buf)?;
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
                m.track_namespace.validate(TrackNamespaceRules::for_draft(15))?;
                m.track_namespace.encode(buf);
                encode_parameters(&m.parameters, buf)?;
            }
            ControlMessage::PublishNamespaceDone(m) => {
                m.track_namespace.validate(TrackNamespaceRules::for_draft(15))?;
                m.track_namespace.encode(buf);
            }
            ControlMessage::PublishNamespaceCancel(m) => {
                if m.reason_phrase.len() > MAX_REASON_PHRASE_LENGTH {
                    return Err(CodecError::ReasonPhraseTooLong);
                }
                m.track_namespace.validate(TrackNamespaceRules::for_draft(15))?;
                m.track_namespace.encode(buf);
                m.error_code.encode(buf);
                VarInt::from_usize(m.reason_phrase.len()).encode(buf);
                buf.put_slice(&m.reason_phrase);
            }
            ControlMessage::SubscribeNamespace(m) => {
                m.request_id.encode(buf);
                m.namespace_prefix.validate(TrackNamespaceRules::for_draft(15))?;
                m.namespace_prefix.encode(buf);
                encode_parameters(&m.parameters, buf)?;
            }
            ControlMessage::UnsubscribeNamespace(m) => {
                m.request_id.encode(buf);
            }
            ControlMessage::TrackStatus(m) => {
                m.request_id.encode(buf);
                m.track_namespace.validate(TrackNamespaceRules::for_draft(15))?;
                m.track_namespace.encode(buf);
                check_full_track_name(&m.track_namespace, &m.track_name)?;
                VarInt::from_usize(m.track_name.len()).encode(buf);
                buf.put_slice(&m.track_name);
                encode_parameters(&m.parameters, buf)?;
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
                        track_namespace.validate(TrackNamespaceRules::for_draft(15))?;
                        track_namespace.encode(buf);
                        check_full_track_name(track_namespace, track_name)?;
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
                buf.put_u8(m.end_of_track);
                m.end_group.encode(buf);
                m.end_object.encode(buf);
                encode_parameters(&m.parameters, buf)?;
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
                let parameters = decode_setup_parameters(buf)?;
                Ok(ControlMessage::ClientSetup(ClientSetup { parameters }))
            }
            MessageType::ServerSetup => {
                let parameters = decode_setup_parameters(buf)?;
                Ok(ControlMessage::ServerSetup(ServerSetup { parameters }))
            }
            MessageType::GoAway => {
                let uri_len = VarInt::decode(buf)?.into_inner() as usize;
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
            MessageType::RequestOk => {
                let request_id = VarInt::decode(buf)?;
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::RequestOk(RequestOk { request_id, parameters }))
            }
            MessageType::RequestError => {
                let request_id = VarInt::decode(buf)?;
                let error_code = VarInt::decode(buf)?;
                let reason_phrase = read_reason_phrase(buf)?;
                Ok(ControlMessage::RequestError(RequestError {
                    request_id,
                    error_code,
                    reason_phrase,
                }))
            }
            MessageType::Subscribe => {
                let request_id = VarInt::decode(buf)?;
                let track_namespace = TrackNamespace::decode(buf)?;
                let track_name_len = VarInt::decode(buf)?.into_inner() as usize;
                let track_name = read_bytes(buf, track_name_len)?;
                check_full_track_name(&track_namespace, &track_name)?;
                let parameters = decode_parameters(buf)?;
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
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::SubscribeOk(SubscribeOk { request_id, track_alias, parameters }))
            }
            MessageType::SubscribeUpdate => {
                let request_id = VarInt::decode(buf)?;
                let subscription_request_id = VarInt::decode(buf)?;
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::SubscribeUpdate(SubscribeUpdate {
                    request_id,
                    subscription_request_id,
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
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::Publish(Publish {
                    request_id,
                    track_namespace,
                    track_name,
                    track_alias,
                    parameters,
                }))
            }
            MessageType::PublishOk => {
                let request_id = VarInt::decode(buf)?;
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::PublishOk(PublishOk { request_id, parameters }))
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
                let namespace_prefix = TrackNamespace::decode(buf)?;
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::SubscribeNamespace(SubscribeNamespace {
                    request_id,
                    namespace_prefix,
                    parameters,
                }))
            }
            MessageType::UnsubscribeNamespace => {
                let request_id = VarInt::decode(buf)?;
                Ok(ControlMessage::UnsubscribeNamespace(UnsubscribeNamespace { request_id }))
            }
            MessageType::TrackStatus => {
                let request_id = VarInt::decode(buf)?;
                let track_namespace = TrackNamespace::decode(buf)?;
                let track_name_len = VarInt::decode(buf)?.into_inner() as usize;
                let track_name = read_bytes(buf, track_name_len)?;
                check_full_track_name(&track_namespace, &track_name)?;
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
                    fetch_type,
                    fetch_payload,
                    parameters,
                }))
            }
            MessageType::FetchOk => {
                let request_id = VarInt::decode(buf)?;
                let end_of_track = read_u8(buf)?;
                let end_group = VarInt::decode(buf)?;
                let end_object = VarInt::decode(buf)?;
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::FetchOk(FetchOk {
                    request_id,
                    end_of_track,
                    end_group,
                    end_object,
                    parameters,
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
            ControlMessage::SubscribeUpdate(_) => MessageType::SubscribeUpdate,
            ControlMessage::Unsubscribe(_) => MessageType::Unsubscribe,
            ControlMessage::Publish(_) => MessageType::Publish,
            ControlMessage::PublishOk(_) => MessageType::PublishOk,
            ControlMessage::PublishDone(_) => MessageType::PublishDone,
            ControlMessage::PublishNamespace(_) => MessageType::PublishNamespace,
            ControlMessage::PublishNamespaceDone(_) => MessageType::PublishNamespaceDone,
            ControlMessage::PublishNamespaceCancel(_) => MessageType::PublishNamespaceCancel,
            ControlMessage::SubscribeNamespace(_) => MessageType::SubscribeNamespace,
            ControlMessage::UnsubscribeNamespace(_) => MessageType::UnsubscribeNamespace,
            ControlMessage::TrackStatus(_) => MessageType::TrackStatus,
            ControlMessage::Fetch(_) => MessageType::Fetch,
            ControlMessage::FetchOk(_) => MessageType::FetchOk,
            ControlMessage::FetchCancel(_) => MessageType::FetchCancel,
        }
    }
}

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

use crate::auth_token::{AuthorizationToken, AUTH_TOKEN_PARAMETER};
use crate::error::{
    CodecError, MAX_FULL_TRACK_NAME_LENGTH, MAX_GOAWAY_URI_LENGTH, MAX_MESSAGE_LENGTH,
    MAX_REASON_PHRASE_LENGTH,
};
use crate::kvp::{KeyValuePair, KvpError, KvpValue, MAX_KVP_VALUE_LEN};
use crate::subscription_filter::{SubscriptionFilter, SUBSCRIPTION_FILTER_PARAMETER};
pub use crate::types::check_location_range;
use crate::types::*;
use crate::varint::VarInt;
use bytes::{Buf, BufMut};

// ============================================================
// Key-Value-Pair Type delta encoding
// ============================================================
//
// Draft-16 Section 1.4.2: "Key-Value-Pairs encode a Type value as a delta from
// the previous Type value, or from 0 if there is no previous Type value."
//
// This is the wire shape for every Key-Value-Pair on this draft, and it arrived
// with draft-16 — drafts 15 and earlier write the Type absolutely. Draft-16
// Appendix A.1 records the change as "Delta encode Key-Value-Pairs for
// Parameters and Headers". Both users of the shape in this module are covered:
// the count-prefixed Parameters list carried by most control messages, and the
// Track Extensions run that fills the tail of SUBSCRIBE_OK, PUBLISH and
// FETCH_OK.
//
// The delta resets to 0 at the start of each run, so a message carrying both a
// Parameters list and a Track Extensions run restarts the count between them.
//
// Only the Type is delta-encoded. The value still follows the even/odd rule of
// Section 1.4.2 — "Length: Only present when Type is odd" — and it is the
// resolved Type that decides, not the delta that encoded it.
//
// Object Extension Headers in the data plane are Key-Value-Pairs too, but this
// codec carries that block as opaque bytes and never resolves a Type inside it,
// so it needs no change here.

/// Resolve a delta-encoded Type against the Type before it.
///
/// Draft-16 Section 1.4.2: "The previous Type value plus the Delta Type MUST NOT
/// be greater than 2^64 - 1. If a Delta Type is received that would be too
/// large, the Session MUST be closed with a PROTOCOL_VIOLATION." Deltas
/// accumulate, so a peer sending a handful of near-maximum deltas can drive the
/// running sum past the end; without the checked add a debug build panics on the
/// addition and a release build wraps and reports the pair under a Type its
/// sender never wrote.
///
/// A resolved Type also has to be a Type this draft can express. Draft-16 writes
/// every field as a varint, which tops out below the 2^64 - 1 the sentence
/// names, so a sum landing above the varint maximum is refused here as well: it
/// has no draft-16 wire form, and admitting one would produce a pair this codec
/// could decode but never write back.
fn add_delta(prev_key: u64, delta: u64) -> Result<VarInt, CodecError> {
    prev_key
        .checked_add(delta)
        .and_then(|sum| VarInt::from_u64(sum).ok())
        .ok_or(CodecError::KeyDeltaOverflow(prev_key, delta))
}

/// Read one Key-Value-Pair, resolving its Type against `prev_key` and advancing
/// `prev_key` to the resolved value.
fn decode_kvp_delta_pair(
    prev_key: &mut u64,
    buf: &mut impl Buf,
) -> Result<KeyValuePair, CodecError> {
    let delta = VarInt::decode(buf)?.into_inner();
    let key = add_delta(*prev_key, delta)?;
    let abs_key = key.into_inner();
    *prev_key = abs_key;

    let value = if abs_key.is_multiple_of(2) {
        KvpValue::Varint(VarInt::decode(buf)?)
    } else {
        let len = VarInt::decode(buf)?.into_inner() as usize;
        // Section 1.4.2: "The maximum length of a value is 2^16-1 bytes. If an
        // endpoint receives a length larger than the maximum, it MUST close the
        // session with a PROTOCOL_VIOLATION." `KeyValuePair::decode` applied
        // this before the Type became a delta, and dropping it here would trade
        // one defect for another.
        if len > MAX_KVP_VALUE_LEN {
            return Err(KvpError::ValueTooLong(len).into());
        }
        KvpValue::Bytes(read_bytes(buf, len)?)
    };

    Ok(KeyValuePair { key, value })
}

/// Write one Key-Value-Pair, encoding its Type as a delta from `prev_key` and
/// advancing `prev_key` to this pair's Type.
///
/// Refuses a Type below the one before it. The delta is an unsigned difference,
/// so a descending pair wraps the subtraction into a nine-byte delta that the
/// peer resolves to an unrelated Type — the codec would put a frame on the wire
/// that its own decoder reads as something else entirely.
fn encode_kvp_delta_pair(
    prev_key: &mut u64,
    pair: &KeyValuePair,
    buf: &mut impl BufMut,
) -> Result<(), CodecError> {
    let abs_key = pair.key.into_inner();
    let delta = abs_key
        .checked_sub(*prev_key)
        .ok_or(CodecError::ParametersOutOfOrder(*prev_key, abs_key))?;
    *prev_key = abs_key;
    // Both operands are valid varints and `delta` is their difference, so it is
    // in range by construction; the `?` is the type system's, not a rule's.
    VarInt::from_u64(delta)?.encode(buf);

    match &pair.value {
        KvpValue::Varint(v) => v.encode(buf),
        KvpValue::Bytes(bytes) => {
            if bytes.len() > MAX_KVP_VALUE_LEN {
                return Err(KvpError::ValueTooLong(bytes.len()).into());
            }
            VarInt::from_usize(bytes.len()).encode(buf);
            buf.put_slice(bytes);
        }
    }
    Ok(())
}

/// Immutable Extensions, Extension Header Type 0xB.
///
/// Section 11.2: "The Immutable Extensions (Extension Header Type 0xB) contains
/// a sequence of Key-Value-Pairs (see Figure 2) which are also Track or Object
/// Extension Headers." The Type is odd, so its value is length-prefixed bytes,
/// and those bytes are another delta-typed run starting from 0.
const IMMUTABLE_EXTENSIONS: u64 = 0x0B;

/// Whether `value` is inside the range draft-16 allows for an extension header
/// type that restricts one.
///
/// Three types do, each in Section 11 and each answering anything outside its
/// range with a session close.
///
/// DELIVERY_TIMEOUT (0x02), Section 11.1: "DELIVERY_TIMEOUT, if present, MUST
/// contain a value greater than 0. If an endpoint receives a DELIVERY_TIMEOUT
/// equal to 0 it MUST close the session with PROTOCOL_VIOLATION." Draft-16 is
/// the only draft that states this. Draft-17 renamed the type to
/// OBJECT_DELIVERY_TIMEOUT and gives it no range at all.
///
/// DEFAULT_PUBLISHER_GROUP_ORDER (0x22), Section 11.1.1.2: "The allowed values
/// are Ascending (0x1) or Descending (0x2). If an endpoint receives a value
/// outside this range, it MUST close the session with PROTOCOL_VIOLATION."
///
/// DYNAMIC_GROUPS (0x30), Section 11.1.1.3: "The allowed values are 0 or 1... If
/// an endpoint receives a value larger than 1, it MUST close the session with
/// PROTOCOL_VIOLATION." Draft-15 carried this as a Message Parameter, where it
/// is [`parameter_value_in_range`]'s business; draft-16 moved it to this
/// namespace, and the two registries number their entries independently.
///
/// DEFAULT_PUBLISHER_PRIORITY (0x0E) is not here. Section 11.1.1.1 says
/// "Priorities above 255 are invalid" and stops, where the three above name a
/// consequence in the next clause. A range stated without one is not a close.
fn track_extension_value_in_range(key: u64, value: u64) -> bool {
    match key {
        // DELIVERY_TIMEOUT (0x02)
        0x02 => value > 0,
        // DEFAULT_PUBLISHER_GROUP_ORDER (0x22)
        0x22 => value == 1 || value == 2,
        // DYNAMIC_GROUPS (0x30)
        0x30 => value <= 1,
        _ => true,
    }
}

/// Refuse a Track Extension whose value falls outside the range its type allows,
/// wherever in the run it is carried.
///
/// Extension headers only. The Message Parameter registry is a separate
/// namespace that gives the same numbers to different types — 0x22 is
/// GROUP_ORDER there and DEFAULT_PUBLISHER_GROUP_ORDER here — so the two lists
/// are checked against their own tables and neither table is consulted for the
/// other's types.
///
/// # Inside Immutable Extensions as well as beside them
///
/// The run is walked one level down through Immutable Extensions, whose contents
/// Section 11.2 defines as extension headers themselves. A rule applied only to
/// the outer run is a rule a peer opts out of by moving one pair inside the
/// block, and the block is not an obscure corner: it is where an Original
/// Publisher puts anything a relay must not rewrite, which is exactly where a
/// track's group order and dynamic-group support belong.
///
/// Bytes under 0xB that do not parse as a Key-Value-Pair run are left alone
/// rather than refused. Section 11.2 answers that with "A Track is considered
/// malformed", which Section 2.4.2 does not make a session close, and turning
/// it into one here would end sessions over a rule the draft answers otherwise.
/// A nested block that does parse is checked; one that does not is carried, and
/// the caller still has the bytes.
fn check_track_extension_values(extensions: &[KeyValuePair]) -> Result<(), CodecError> {
    for extension in extensions {
        let key = extension.key.into_inner();
        match &extension.value {
            KvpValue::Varint(value) => {
                let value = value.into_inner();
                if !track_extension_value_in_range(key, value) {
                    return Err(CodecError::TrackPropertyValueOutOfRange { key, value });
                }
            }
            KvpValue::Bytes(bytes) if key == IMMUTABLE_EXTENSIONS => {
                let mut inner = &bytes[..];
                let mut prev_key: u64 = 0;
                let mut nested = Vec::new();
                let mut readable = true;
                while inner.has_remaining() {
                    match decode_kvp_delta_pair(&mut prev_key, &mut inner) {
                        Ok(pair) => nested.push(pair),
                        // Not a Key-Value-Pair run. See the note above: this is
                        // a malformed Track and not a session close.
                        //
                        // `break` rather than ending the walk: Section 11.2's
                        // rule ("A Track is considered malformed ... A
                        // Key-Value-Pair cannot be parsed") is about the block
                        // whose pairs will not parse, and says nothing about
                        // its neighbours. Ending the walk would let a peer keep
                        // an out-of-range extension from being looked at by
                        // putting an unparseable block in front of it.
                        Err(_) => {
                            readable = false;
                            break;
                        }
                    }
                }
                // The pairs read before the failure are not checked either. A
                // run that stops mid-pair was being read under framing it does
                // not have, so the numbers ahead of the break are not reliably
                // the types and values they look like — and refusing on one
                // would close a session over a misparse. The whole block is
                // carried, which is what the note above promises.
                if readable {
                    check_track_extension_values(&nested)?;
                }
            }
            KvpValue::Bytes(_) => {}
        }
    }
    Ok(())
}

/// Decode any remaining bytes in `buf` as a run of delta-typed KVPs until `buf`
/// is empty. Used for draft-16 `track_extensions`, which has no explicit
/// count — extensions simply fill the rest of the control-message payload.
fn decode_track_extensions(buf: &mut impl Buf) -> Result<Vec<KeyValuePair>, CodecError> {
    let mut out = Vec::new();
    let mut prev_key: u64 = 0;
    while buf.has_remaining() {
        out.push(decode_kvp_delta_pair(&mut prev_key, buf)?);
    }
    check_track_extension_values(&out)?;
    Ok(out)
}

/// Encode `track_extensions` (each KVP back-to-back, no count prefix), with
/// Types delta-encoded from 0.
///
/// Held to the same value ranges as the decoder. A value this codec refuses to
/// read is one it must not write: the peer that receives it is required to close
/// the session, so the sender's first sign of trouble would be the session
/// going.
fn encode_track_extensions(exts: &[KeyValuePair], buf: &mut impl BufMut) -> Result<(), CodecError> {
    check_track_extension_values(exts)?;
    let mut prev_key: u64 = 0;
    for kvp in exts {
        encode_kvp_delta_pair(&mut prev_key, kvp, buf)?;
    }
    Ok(())
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

    /// This type's name in the shared vector corpus: the `message_type` its
    /// draft's `codec/messages/*.json` files carry, in `snake_case`.
    pub fn name(&self) -> &'static str {
        match self {
            MessageType::RequestUpdate => "request_update",
            MessageType::Subscribe => "subscribe",
            MessageType::SubscribeOk => "subscribe_ok",
            MessageType::RequestError => "request_error",
            MessageType::PublishNamespace => "publish_namespace",
            MessageType::RequestOk => "request_ok",
            MessageType::Namespace => "namespace",
            MessageType::PublishNamespaceDone => "publish_namespace_done",
            MessageType::Unsubscribe => "unsubscribe",
            MessageType::PublishDone => "publish_done",
            MessageType::PublishNamespaceCancel => "publish_namespace_cancel",
            MessageType::TrackStatus => "track_status",
            MessageType::NamespaceDone => "namespace_done",
            MessageType::GoAway => "goaway",
            MessageType::SubscribeNamespace => "subscribe_namespace",
            MessageType::MaxRequestId => "max_request_id",
            MessageType::Fetch => "fetch",
            MessageType::FetchCancel => "fetch_cancel",
            MessageType::FetchOk => "fetch_ok",
            MessageType::RequestsBlocked => "requests_blocked",
            MessageType::Publish => "publish",
            MessageType::PublishOk => "publish_ok",
            MessageType::ClientSetup => "client_setup",
            MessageType::ServerSetup => "server_setup",
        }
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

/// REQUEST_UPDATE (0x02). Drafts 15 and earlier name this codepoint
/// SUBSCRIBE_UPDATE.
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

/// PUBLISH_NAMESPACE_DONE (0x09). Draft-16 carries just request_id; draft-15
/// carries the track namespace instead.
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
/// wire. This codec holds the alternatives in an enum, so a value can say one
/// thing in its discriminator and another in its body, and the two sides of the
/// codec resolve that differently: the encoder writes whatever the body holds,
/// and the decoder reads whatever the discriminator announces.
///
/// The result is a message that does not survive its own round trip. A FETCH
/// whose Fetch Type says Standalone and whose body is a joining pair encodes to
/// a request id and a start where a namespace and a name belong, and comes back
/// as a Standalone fetch of a track named after two integers — or, more often,
/// as an error, which at least is honest. Refusing at the encoder keeps the two
/// readings from ever diverging on the wire.
///
/// FETCH is the only message on draft-16 with such a field. Drafts 07 through 14
/// have three: SUBSCRIBE's Filter Type and SUBSCRIBE_OK's ContentExists are the
/// other two, and both are gone from draft-16 — the filter moved into the
/// parameters as SUBSCRIPTION_FILTER, and SUBSCRIBE_OK's optional largest
/// location left with it.
fn check_discriminators(message: &ControlMessage) -> Result<(), CodecError> {
    if let ControlMessage::Fetch(m) = message {
        let body_is_standalone = matches!(m.fetch_payload, FetchPayload::Standalone { .. });
        if body_is_standalone != (m.fetch_type == FetchType::Standalone) {
            return Err(CodecError::InvalidField);
        }
    }
    Ok(())
}

// ============================================================
// Duplicate Parameter Types
// ============================================================
//
// Draft-16 Section 9.2 states the rule in three sentences, and they do not say
// the same thing to the two sides:
//
//   "Senders MUST NOT repeat the same parameter type in a message unless the
//   parameter definition explicitly allows multiple instances of that type to
//   be sent in a single message. Receivers SHOULD check that there are no
//   unexpected duplicate parameters and close the session as a
//   PROTOCOL_VIOLATION if found. Receivers MUST allow duplicates of unknown
//   Setup Parameters."
//
// The sender's half names no exception for types the sender does not
// recognise, so a caller holding a parameter this codec has never heard of
// still may not send it twice. The receiver's half has the opposite shape: the
// last sentence is a MUST, and it forbids closing the session over a repeat of
// a type the receiver cannot name. So the encoder refuses more than the decoder
// does, deliberately. Making the two symmetric breaks one rule whichever way it
// is done — a wide decoder closes sessions the draft says to keep open, and a
// narrow encoder emits repeats the draft says never to write.
//
// Both halves work on resolved Types rather than the deltas that encoded them,
// so a repeat is found the same way it always was; on the wire it now shows up
// as a delta of zero.

/// The one Parameter Type draft-16 lets a message carry more than once.
///
/// Section 9.2.2.1: "The AUTHORIZATION TOKEN parameter MAY be repeated within a
/// message as long as the combination of Token Type and Token Value are unique
/// after resolving any aliases." That is the "unless the parameter definition
/// explicitly allows multiple instances" carve-out of Section 9.2, and on
/// draft-16 it is the only one. The same number is the AUTHORIZATION TOKEN
/// Setup Parameter in Section 9.3.1.5, which describes itself as "funcionally
/// equivalient to the AUTHORIZATION TOKEN message parameter" and lets an
/// endpoint "specify one or more tokens", so the exemption holds in both
/// namespaces.
///
/// Uniqueness "after resolving any aliases" needs a session's token cache, which
/// a codec does not have. So repeats of this type are carried in both
/// directions and the caller decides.
const AUTHORIZATION_TOKEN: u64 = 0x03;

/// The Setup Parameter types draft-16 defines, from the definitions in Section
/// 9.3.1: PATH (0x01), MAX_REQUEST_ID (0x02), AUTHORIZATION TOKEN (0x03),
/// MAX_AUTH_TOKEN_CACHE_SIZE (0x04), AUTHORITY (0x05) and MOQT_IMPLEMENTATION
/// (0x07).
///
/// The list exists for one rule and one direction: "Receivers MUST allow
/// duplicates of unknown Setup Parameters." A type outside this list is one an
/// extension defined, and this codec has no business closing a session over it.
/// Nothing else reads the list — an unknown Setup Parameter is still decoded and
/// carried, as "Receivers ignore unrecognized Setup Parameters" requires.
const KNOWN_SETUP_PARAMETERS: &[u64] = &[0x01, 0x02, 0x03, 0x04, 0x05, 0x07];

/// The Message Parameter types draft-16 defines, from the registry in Section
/// 13.2: DELIVERY_TIMEOUT (0x02), AUTHORIZATION_TOKEN (0x03), EXPIRES (0x08),
/// LARGEST_OBJECT (0x09), FORWARD (0x10), SUBSCRIBER_PRIORITY (0x20),
/// SUBSCRIPTION_FILTER (0x21), GROUP_ORDER (0x22) and NEW_GROUP_REQUEST (0x32).
///
/// Setup Parameters and Message Parameters are separate namespaces — Section
/// 9.2: "Setup Parameters use a namespace that is constant across all MOQT
/// versions. All other messages use a version-specific namespace" — so the two
/// lists are kept apart rather than merged. Merging them would let a repeat of
/// 0x01 be refused in a SUBSCRIBE, where draft-16 assigns that number to
/// nothing at all.
const KNOWN_MESSAGE_PARAMETERS: &[u64] = &[0x02, 0x03, 0x08, 0x09, 0x10, 0x20, 0x21, 0x22, 0x32];

/// The sender's half: refuse every repeated Parameter Type but the one whose
/// definition allows it.
///
/// Wider than [`check_received_duplicate_parameters`] on purpose — see the
/// note above this function's neighbours. A repeat this codec writes is a frame
/// nothing downstream agrees on: code that scans a parameter list for a key
/// takes whichever copy it meets first, so one frame carrying two values for
/// one type is read two ways by two conforming implementations. That is what
/// makes the sender's half a MUST NOT rather than advice.
fn check_sent_duplicate_parameters(parameters: &[KeyValuePair]) -> Result<(), CodecError> {
    for (i, parameter) in parameters.iter().enumerate() {
        if parameter.key.into_inner() == AUTHORIZATION_TOKEN {
            continue;
        }
        if parameters[..i].iter().any(|earlier| earlier.key == parameter.key) {
            return Err(CodecError::DuplicateParameter(parameter.key.into_inner()));
        }
    }
    Ok(())
}

/// The receiver's half: refuse a repeated Parameter Type this draft names, and
/// carry a repeat of any other.
///
/// `known` is the registry for the namespace the message uses — Setup or
/// Message. A type outside it is one "Receivers MUST allow duplicates of"
/// covers, and refusing it would close a session over an extension this codec
/// was never told about.
fn check_received_duplicate_parameters(
    parameters: &[KeyValuePair],
    known: &[u64],
) -> Result<(), CodecError> {
    for (i, parameter) in parameters.iter().enumerate() {
        let key = parameter.key.into_inner();
        if key == AUTHORIZATION_TOKEN || !known.contains(&key) {
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
/// Section 9.2.2.1: "If the Token structure cannot be decoded, the receiver
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

/// Hold every SUBSCRIPTION_FILTER parameter to the filter structure it names.
///
/// Two sentences meet on this value. Section 5.1.2: "An endpoint that receives a
/// filter type other than the above MUST close the session with
/// PROTOCOL_VIOLATION." Section 9.2.2.5: "It is a length-prefixed Subscription
/// Filter... If the length of the Subscription Filter does not match the
/// parameter length, the publisher MUST close the session with
/// PROTOCOL_VIOLATION."
///
/// Draft-14 read the same three values as fields of SUBSCRIBE and checked them
/// there. Draft-15 moved them inside a parameter, and a parameter whose value is
/// a run of bytes carries a Filter Type nothing reads: the rule went from
/// enforced to invisible without a word of either draft changing.
///
/// The filter is decoded and discarded. What is kept is the refusal — the value
/// stays on the parameter as the bytes that arrived, so a caller reads it
/// through [`SubscriptionFilter::decode`] when it wants the filter rather than
/// the frame.
///
/// Message parameters only. This draft keeps the two namespaces apart, and a
/// setup 0x21 is not this parameter.
fn check_subscription_filters(parameters: &[KeyValuePair]) -> Result<(), CodecError> {
    for parameter in parameters {
        if parameter.key.into_inner() != SUBSCRIPTION_FILTER_PARAMETER {
            continue;
        }
        match &parameter.value {
            KvpValue::Bytes(value) => {
                SubscriptionFilter::decode(value)?;
            }
            // Unreachable from the decoder: 0x21 is odd, and an odd Type takes a
            // length-prefixed value. A caller that built the pair in memory can
            // still get here, and it is the same rule.
            KvpValue::Varint(_) => {
                return Err(CodecError::SubscriptionFilterMalformed {
                    detail: "its value is a bare varint where the type defines a filter",
                });
            }
        }
    }
    Ok(())
}

/// Refuse a Message Parameter whose type this draft does not define.
///
/// Section 9.2: "All Message Parameters MUST be defined in the negotiated
/// version of MOQT or negotiated via Setup Parameters. An endpoint that receives
/// an unknown Message Parameter MUST close the session with PROTOCOL_VIOLATION."
///
/// This is the one rule in the parameter paragraph that changed direction at
/// this draft. Drafts 11 through 15 say, at draft-15 Section 9.2, "Receivers
/// MUST allow duplicates of unknown parameters", which takes for granted that
/// unknown parameters arrive and are carried. Draft-16 narrows that sentence to
/// "unknown Setup Parameters" and adds this one beside it, in the same
/// paragraph — so a type this codec cannot name is carried in a SETUP and ends
/// the session anywhere else.
///
/// [`KNOWN_MESSAGE_PARAMETERS`] is what "defined in the negotiated version"
/// means here, and it is checked against Section 13.2 rather than assembled from
/// the types this codec happens to read. A missing entry would close sessions
/// over parameters the draft assigns, which is the expensive way to be wrong.
///
/// The other half of the sentence — "or negotiated via Setup Parameters" — is
/// not something a codec can settle. It describes an extension the two endpoints
/// agreed on in their SETUP, and this codec implements no such extension, so
/// every type outside the registry is unknown to it.
fn check_message_parameters_are_known(parameters: &[KeyValuePair]) -> Result<(), CodecError> {
    for parameter in parameters {
        let key = parameter.key.into_inner();
        if !KNOWN_MESSAGE_PARAMETERS.contains(&key) {
            return Err(CodecError::UnknownMessageParameter(key));
        }
    }
    Ok(())
}

/// Whether `value` is inside the range draft-16 allows for a Message Parameter
/// type that restricts one.
///
/// Four types do. FORWARD, Section 9.2.2.8: "The allowed values are 0 (don't
/// forward) or 1 (forward). If an endpoint receives a value outside this range,
/// it MUST close the session with PROTOCOL_VIOLATION." GROUP_ORDER, Section
/// 9.2.2.4, says the same of Ascending (0x1) and Descending (0x2).
/// SUBSCRIBER_PRIORITY, Section 9.2.2.3: "The range is restricted to 0-255. If a
/// publisher receives a value outside this range, it MUST close the session with
/// PROTOCOL_VIOLATION." DELIVERY_TIMEOUT, Section 9.2.2.2: "DELIVERY_TIMEOUT, if
/// present, MUST contain a value greater than 0. If an endpoint receives a
/// DELIVERY_TIMEOUT equal to 0 it MUST close the session with
/// PROTOCOL_VIOLATION."
///
/// The fourth is stated by draft-16 alone, and stated twice — once here and once
/// in Section 11.1 of the extension header namespace, which
/// [`track_extension_value_in_range`] answers. Draft-15 has no such sentence and
/// draft-17 renamed the type to OBJECT_DELIVERY_TIMEOUT and dropped the range,
/// so this is one draft wide in both namespaces. A zero timeout is the case
/// worth having: it reads as "no timeout" to an implementation that treats
/// absence and zero alike, which is the opposite of what a timeout of zero would
/// mean if it were legal.
///
/// Draft-15's fourth entry, DYNAMIC_GROUPS, is not here: draft-16 moved it out
/// of the parameter registry and into the extension header registry as a Track
/// Extension, where [`track_extension_value_in_range`] holds it to the range it
/// states there. Draft-15's PUBLISHER_PRIORITY is gone for a different reason —
/// draft-16 does not define the parameter at all.
fn parameter_value_in_range(key: u64, value: u64) -> bool {
    match key {
        // DELIVERY_TIMEOUT (0x02)
        0x02 => value > 0,
        // FORWARD (0x10)
        0x10 => value <= 1,
        // SUBSCRIBER_PRIORITY (0x20)
        0x20 => value <= 255,
        // GROUP_ORDER (0x22)
        0x22 => value == 1 || value == 2,
        _ => true,
    }
}

/// Refuse a Message Parameter whose value falls outside the range its type
/// allows.
///
/// Message Parameters only. Each rule is stated for a named Message Parameter,
/// and the Setup registry is a separate namespace that defines none of these
/// numbers, so a SETUP carrying type 0x22 is carrying something the draft has
/// not given a range to. Refusing it here would close the session on a reading
/// the draft never gives.
///
/// Only the varint-valued shape is examined. Every type with a range is an even
/// number, and draft-16 gives an even type a bare varint value, so a
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

/// Decode a count-prefixed parameter list with delta-encoded Types, refusing a
/// repeat of a type in `known`.
///
/// `message_namespace` says which of the two rules about unknown types applies.
/// The namespaces part company here and only here: an unknown Message Parameter
/// ends the session, and an unknown Setup Parameter is carried because "Receivers
/// ignore unrecognized Setup Parameters".
fn decode_parameters_in(
    buf: &mut impl Buf,
    known: &[u64],
    message_namespace: bool,
) -> Result<Vec<KeyValuePair>, CodecError> {
    let count = VarInt::decode(buf)?.into_inner() as usize;
    let mut parameters = crate::types::reserve_bounded(count, buf);
    let mut prev_key: u64 = 0;
    for _ in 0..count {
        parameters.push(decode_kvp_delta_pair(&mut prev_key, buf)?);
    }
    if message_namespace {
        check_message_parameters_are_known(&parameters)?;
        check_parameter_value_ranges(&parameters)?;
        check_subscription_filters(&parameters)?;
    }
    check_received_duplicate_parameters(&parameters, known)?;
    check_authorization_tokens(&parameters)?;
    Ok(parameters)
}

/// Decode the Message Parameters of a control message.
fn decode_parameters(buf: &mut impl Buf) -> Result<Vec<KeyValuePair>, CodecError> {
    decode_parameters_in(buf, KNOWN_MESSAGE_PARAMETERS, true)
}

/// Decode the Setup Parameters of a CLIENT_SETUP or SERVER_SETUP.
fn decode_setup_parameters(buf: &mut impl Buf) -> Result<Vec<KeyValuePair>, CodecError> {
    decode_parameters_in(buf, KNOWN_SETUP_PARAMETERS, false)
}

/// Encode a count-prefixed parameter list with delta-encoded Types, refusing
/// every list [`decode_parameters_in`] would refuse *over a value*.
///
/// The duplicate rule is the sender's own and does not consult a registry, so
/// there is nothing for the two namespaces to disagree about there. The value
/// rules are the reader's, and `message_namespace` says which of them apply for
/// the same reason it does on the decode side: a setup 0x21 or 0x22 is not the
/// parameter the version-specific rules describe.
///
/// They are applied on the way out because each of them states a close. A value
/// that is not what its Type defines is one the receiver must close the session
/// over, so writing it is not a way to send it — the sender's first sign of
/// trouble would be the session going.
///
/// # The one rule that is decode-only, and why
///
/// [`check_message_parameters_are_known`] is not called here. That is the rule
/// whose sentence has a second half: Section 9.2 says "All Message Parameters MUST be defined
/// in the negotiated version of MOQT or negotiated via Setup Parameters", and
/// it is that second clause the neighbouring function's own doc says a codec
/// cannot settle — it describes an extension the two endpoints agreed on in
/// their SETUP, which this codec does not implement.
///
/// A decoder has to resolve that the conservative way. It was handed bytes, it
/// has no record of what the two peers negotiated, and the draft's answer to a
/// parameter it cannot name is a close. An encoder is in the opposite position:
/// its caller *is* the endpoint that negotiated, and is the only party that
/// knows the type was agreed. Refusing here would make a negotiated extension
/// unsendable through this codec — and unreplayable, which is the same argument
/// `data_stream.rs`'s `extensions_permitted_at` makes about a rule that
/// addresses the receiving endpoint: a writer that refused it could not
/// reproduce a capture containing one.
///
/// Draft-17 takes the same position in the same place, with a fallback arm in
/// its `encode_parameters` that writes an unknown Type as a plain even/odd pair
/// while its decoder answers `UnknownMessageParameter` for the same number.
/// This is a difference between the two directions, not between the drafts.
///
/// It is also a gated one rather than an accident.
/// `tests/unknown_message_parameter.rs`'s `an_unknown_message_parameter_is_refused`
/// drives exactly this asymmetry on this draft: it hands the encoder type 0x41,
/// requires it to be written — its `expect` says in so many words that the
/// encoder writes the parameters it is given — and requires the decoder to
/// answer `UnknownMessageParameter`. A check here would fail that test on the
/// line before the one it is about.
fn encode_parameters_in(
    parameters: &[KeyValuePair],
    buf: &mut impl BufMut,
    message_namespace: bool,
) -> Result<(), CodecError> {
    check_sent_duplicate_parameters(parameters)?;
    if message_namespace {
        check_parameter_value_ranges(parameters)?;
        check_subscription_filters(parameters)?;
    }
    check_authorization_tokens(parameters)?;
    VarInt::from_usize(parameters.len()).encode(buf);
    let mut prev_key: u64 = 0;
    for parameter in parameters {
        encode_kvp_delta_pair(&mut prev_key, parameter, buf)?;
    }
    Ok(())
}

/// Encode the Message Parameters of a control message.
fn encode_parameters(parameters: &[KeyValuePair], buf: &mut impl BufMut) -> Result<(), CodecError> {
    encode_parameters_in(parameters, buf, true)
}

/// Encode the Setup Parameters of a CLIENT_SETUP or SERVER_SETUP.
fn encode_setup_parameters(
    parameters: &[KeyValuePair],
    buf: &mut impl BufMut,
) -> Result<(), CodecError> {
    encode_parameters_in(parameters, buf, false)
}

impl ControlMessage {
    pub fn encode(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        check_ranges(self)?;
        check_discriminators(self)?;
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
                m.retry_interval.encode(buf);
                VarInt::from_usize(m.reason_phrase.len()).encode(buf);
                buf.put_slice(&m.reason_phrase);
            }
            ControlMessage::Subscribe(m) => {
                m.request_id.encode(buf);
                m.track_namespace.validate(TrackNamespaceRules::for_draft(16))?;
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
                encode_track_extensions(&m.track_extensions, buf)?;
            }
            ControlMessage::RequestUpdate(m) => {
                m.request_id.encode(buf);
                m.existing_request_id.encode(buf);
                encode_parameters(&m.parameters, buf)?;
            }
            ControlMessage::Unsubscribe(m) => {
                m.request_id.encode(buf);
            }
            ControlMessage::Publish(m) => {
                m.request_id.encode(buf);
                m.track_namespace.validate(TrackNamespaceRules::for_draft(16))?;
                m.track_namespace.encode(buf);
                check_full_track_name(&m.track_namespace, &m.track_name)?;
                VarInt::from_usize(m.track_name.len()).encode(buf);
                buf.put_slice(&m.track_name);
                m.track_alias.encode(buf);
                encode_parameters(&m.parameters, buf)?;
                encode_track_extensions(&m.track_extensions, buf)?;
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
                m.track_namespace.validate(TrackNamespaceRules::for_draft(16))?;
                m.track_namespace.encode(buf);
                encode_parameters(&m.parameters, buf)?;
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
                m.namespace_suffix.validate(TrackNamespaceRules {
                    min_fields: 0,
                    ..TrackNamespaceRules::for_draft(16)
                })?;
                m.namespace_suffix.encode(buf);
            }
            ControlMessage::NamespaceDone(m) => {
                m.namespace_suffix.validate(TrackNamespaceRules {
                    min_fields: 0,
                    ..TrackNamespaceRules::for_draft(16)
                })?;
                m.namespace_suffix.encode(buf);
            }
            ControlMessage::SubscribeNamespace(m) => {
                m.request_id.encode(buf);
                // Section 9.25 gives the prefix its own field-count range:
                // "A Track Namespace structure as described in Section 2.4.1
                // with between 0 and 32 Track Namespace Fields", and its
                // session-closing clause names only "greater than than 32
                // Track Namespace Fields". The general rule in Section 2.4.1
                // closes the session on "0 or greater than 32", so a prefix is
                // the one position where an empty namespace is legal — it is
                // the prefix that matches every namespace.
                //
                // Only the field count is relaxed. The other Section 2.4.1
                // rules still apply, and one of them is easy to conflate with
                // this: "Each Track Namespace Field Value MUST contain at least
                // one byte." A prefix of zero fields is permitted; a prefix
                // holding a field of length zero is not, and inheriting the
                // rest of the draft-16 rules is what keeps that refusal.
                m.namespace_prefix.validate(TrackNamespaceRules {
                    min_fields: 0,
                    ..TrackNamespaceRules::for_draft(16)
                })?;
                m.namespace_prefix.encode(buf);
                m.subscribe_options.encode(buf);
                encode_parameters(&m.parameters, buf)?;
            }
            ControlMessage::TrackStatus(m) => {
                m.request_id.encode(buf);
                m.track_namespace.validate(TrackNamespaceRules::for_draft(16))?;
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
                        track_namespace.validate(TrackNamespaceRules::for_draft(16))?;
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
                encode_track_extensions(&m.track_extensions, buf)?;
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
                let retry_interval = VarInt::decode(buf)?;
                let reason_phrase = read_reason_phrase(buf)?;
                Ok(ControlMessage::RequestError(RequestError {
                    request_id,
                    error_code,
                    retry_interval,
                    reason_phrase,
                }))
            }
            MessageType::Subscribe => {
                let request_id = VarInt::decode(buf)?;
                let track_namespace =
                    TrackNamespace::decode_rules(buf, TrackNamespaceRules::for_draft(16))?;
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
                let parameters = decode_parameters(buf)?;
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
                let track_namespace =
                    TrackNamespace::decode_rules(buf, TrackNamespaceRules::for_draft(16))?;
                let track_name_len = VarInt::decode(buf)?.into_inner() as usize;
                let track_name = read_bytes(buf, track_name_len)?;
                check_full_track_name(&track_namespace, &track_name)?;
                let track_alias = VarInt::decode(buf)?;
                let parameters = decode_parameters(buf)?;
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
                let track_namespace =
                    TrackNamespace::decode_rules(buf, TrackNamespaceRules::for_draft(16))?;
                let parameters = decode_parameters(buf)?;
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
                let reason_phrase = read_reason_phrase(buf)?;
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
                // Section 9.25 permits a prefix of zero fields; see the encode
                // arm. The reader that allows it still holds the fields to
                // draft-16's content rules, so a zero-length field stays
                // refused.
                let namespace_prefix = TrackNamespace::decode_allow_empty(buf)?;
                let subscribe_options = VarInt::decode(buf)?;
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::SubscribeNamespace(SubscribeNamespace {
                    request_id,
                    namespace_prefix,
                    subscribe_options,
                    parameters,
                }))
            }
            MessageType::TrackStatus => {
                let request_id = VarInt::decode(buf)?;
                let track_namespace =
                    TrackNamespace::decode_rules(buf, TrackNamespaceRules::for_draft(16))?;
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
                        let track_namespace =
                            TrackNamespace::decode_rules(buf, TrackNamespaceRules::for_draft(16))?;
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

//! Draft-23 control message encoding and decoding.
//!
//! - The Message Length is a `vi64` (Section 9, Figure 6), bounded by the
//!   receiver's MAX_CONTROL_MESSAGE_SIZE (Section 9.1.8), 65535 unless the
//!   receiver advertised more. [`ControlMessage::decode`] and
//!   [`ControlMessage::encode`] use that default;
//!   [`ControlMessage::decode_with_limit`] and
//!   [`ControlMessage::encode_with_limit`] take the limit.
//! - FETCH is answered by REQUEST_OK; type 0x18 is reserved (Section 9,
//!   Table 5).
//! - REQUEST_ERROR ends in Error Details, Key-Value-Pairs (Section 9.4.1).
//! - NAMESPACE carries a parameter block (Section 9.15, Figure 20).
//! - `FILL_PARAMETERS` (0x23) is a parameter count followed by that many
//!   parameters, with no length (Section 9.19.15).
//! - `PAUSED` (0x11, Section 9.19.18) and `SUBSCRIBE_TRACKS_ID` (0x36,
//!   Section 9.19.21).
//!
//! Every section, table and figure reference in this module is draft-23's own.

use crate::auth_token::{AuthorizationToken, AUTH_TOKEN_PARAMETER};
use crate::error::MAX_FULL_TRACK_NAME_LENGTH;
pub use crate::error::{
    CodecError, MAX_GOAWAY_URI_LENGTH, MAX_MESSAGE_LENGTH, MAX_NAMESPACE_TUPLE_SIZE,
    MAX_REASON_PHRASE_LENGTH,
};
use crate::kvp::{KeyValuePair, KvpError, KvpValue, MAX_KVP_VALUE_LEN};
use crate::types::*;
use crate::varint::{Moqt18 as Wire, VarInt};
use bytes::{Buf, BufMut};

// ============================================================
// Parameter encoding helpers for draft-23
// ============================================================

/// How a parameter value is encoded on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParamEncoding {
    /// Bare varint.
    Varint,
    /// Single byte (uint8).
    Uint8,
    /// Two consecutive varints (group, object).
    Location,
    /// Length-prefixed bytes.
    LengthPrefixed,
    /// A Track Namespace as defined in draft-23 Section 8.7: a varint field
    /// count followed by that many length-prefixed fields.
    ///
    /// The fifth value encoding draft-23 Section 9.19 lists: "Track Namespace:
    /// A sequence of length-prefixed fields (Section 8.7)". TRACK_NAMESPACE_PREFIX
    /// is the parameter that uses it; the field count is the only length the
    /// wire carries.
    TrackNamespaceValue,
    /// A `Location Filter Type` followed by the zero to four `vi64` fields that
    /// type names (draft-23 Section 9.19.9).
    ///
    /// None of the five encodings Section 9.19 lists fits it. The parameter
    /// definition states its own structure, and that structure has no length:
    /// the type is the only thing that says where the value ends.
    LocationFilter,
    /// A `Number of Parameters` count and that many parameters (Section
    /// 9.19.15). Like a LOCATION_FILTER it has no length, so the inner
    /// parameters are read one by one to find where it ends.
    FillParameters,
}

fn param_encoding(key: u64) -> Option<ParamEncoding> {
    match key {
        // 0x02 = OBJECT_DELIVERY_TIMEOUT (Section 9.19.4)
        // 0x04 = RENDEZVOUS_TIMEOUT (Section 9.19.6). Not MAX_CACHE_DURATION:
        //        that is Property Type 0x04 in the separate Properties
        //        registry (Section 16.8), a different namespace that happens
        //        to reuse the number.
        // 0x06 = SUBGROUP_DELIVERY_TIMEOUT (Section 9.19.3)
        // 0x08 = EXPIRES (Section 9.19.16)
        // 0x0A = FILL_TIMEOUT (Section 9.19.5)
        // 0x32 = NEW_GROUP_REQUEST (Section 9.19.19)
        // 0x36 = SUBSCRIBE_TRACKS_ID. Section 9.19.21: "The
        //        SUBSCRIBE_TRACKS_ID parameter (Parameter Type 0x36) is a
        //        varint."
        0x02 | 0x04 | 0x06 | 0x08 | 0x0A | 0x32 | 0x36 => Some(ParamEncoding::Varint),
        // 0x11 = PAUSED. Section 9.19.18: "The PAUSED parameter (Parameter
        //        Type 0x11) is a uint8."
        // 0x20 = SUBSCRIBER_PRIORITY, 0x22 = GROUP_ORDER, and
        // 0x35 = INCLUDE_PROPERTIES. Section 9.19.22: "The
        //        INCLUDE_PROPERTIES parameter (Parameter Type 0x35) is a
        //        uint8."
        0x11 | 0x20 | 0x22 | 0x35 => Some(ParamEncoding::Uint8),
        // 0x09 = LARGEST_OBJECT. Draft-23 Section 9.19.17: "The LARGEST_OBJECT
        //        parameter (Parameter Type 0x9) is a Location." A Location is
        //        two consecutive varints (Section 9.19), with no length ahead
        //        of them. The type is odd, which on a Key-Value-Pair would mean
        //        length-prefixed; Message Parameters are not Key-Value-Pairs
        //        and the odd/even rule does not reach them.
        0x09 => Some(ParamEncoding::Location),
        // 0x34 = TRACK_NAMESPACE_PREFIX. Section 9.19.20: it "uses the Track
        //        Namespace encoding described in Section 8.7".
        0x34 => Some(ParamEncoding::TrackNamespaceValue),
        // 0x21 = LOCATION_FILTER. Section 9.19.9: "The Location Filter Type
        //        dictates which optional variable-length integer fields follow,
        //        and how they are interpreted." No length precedes the type,
        //        and the type is odd for the same reason 0x09's is: the
        //        odd/even rule is a Key-Value-Pair rule and does not reach
        //        Message Parameters.
        0x21 => Some(ParamEncoding::LocationFilter),
        // 0x23 = FILL_PARAMETERS. Section 9.19.15: "Its value is a Number of
        //        Parameters (vi64) followed by that many Parameters that apply
        //        to the fill fetch stream". No length precedes the count.
        0x23 => Some(ParamEncoding::FillParameters),
        // 0x03 = AUTHORIZATION_TOKEN
        // 0x25 = SUBGROUP_FILTER, 0x26 = OBJECTID_FILTER, 0x27 = PRIORITY_FILTER,
        // 0x28 = OBJECT_PROPERTY_FILTER, 0x29 = TRACK_PROPERTY_FILTER
        //        (Range Filters, Section 8.6)
        0x03 | 0x25 | 0x26 | 0x27 | 0x28 | 0x29 => Some(ParamEncoding::LengthPrefixed),
        _ => None,
    }
}

/// Whether `value` is inside the range draft-23 allows for a uint8-valued
/// parameter.
///
/// Three of the four uint8 parameters restrict their range and say the receiver
/// MUST close the session with INVALID_PARAMETER on anything outside it:
/// GROUP_ORDER allows only Ascending (0x1) and Descending (0x2) (Section
/// 9.19.8), PAUSED allows only 0 and 1 (Section 9.19.18), and
/// INCLUDE_PROPERTIES allows only 0 and 1 (Section 9.19.22).
/// SUBSCRIBER_PRIORITY (Section 9.19.7) uses the whole 0-255 range,
/// so it has no entry here.
fn uint8_value_in_range(key: u64, value: u8) -> bool {
    match key {
        // PAUSED (0x11), Section 9.19.18: "The allowed values are 0
        // (unpaused) or 1 (paused). If an endpoint receives a value outside
        // this range, it MUST close the session with INVALID_PARAMETER."
        0x11 => value <= 1,
        // GROUP_ORDER (0x22)
        0x22 => value == 1 || value == 2,
        // INCLUDE_PROPERTIES (0x35), Section 9.19.22: "The allowed values are
        // 0 (do not send Properties) or 1 (send Properties), and the default
        // is 1. If an endpoint receives a value outside this range, it MUST
        // close the session with INVALID_PARAMETER."
        0x35 => value <= 1,
        _ => true,
    }
}

/// AUTHORIZATION TOKEN, Parameter Type 0x03.
const AUTHORIZATION_TOKEN: u64 = 0x03;

/// Whether draft-23 lets a message carry parameter type `key` more than once.
///
/// Section 9.19 states the default: "Senders MUST NOT repeat the same Parameter
/// Type in a message unless the parameter definition explicitly allows multiple
/// instances of that type to be sent in a single message." Two definitions do.
///
/// * `AUTHORIZATION_TOKEN` (0x03), Section 8.9: "An Authorization Token MAY
///   be repeated within a message as long as the combination of Token Type and
///   Token Value are unique after resolving any aliases."
/// * The five Range Filters (0x25 through 0x29), Section 3.3.2: "The Track Property filter parameter MAY appear multiple times in a
///   SUBSCRIBE_TRACKS message or REQUEST_UPDATE for it. All other filter
///   parameters MAY appear multiple times in a FETCH, SUBSCRIBE,
///   SUBSCRIBE_TRACKS, or REQUEST_UPDATE (on a subscription, from the subscriber
///   only) message."
///
/// # A zero `Type Delta` is "the same type again", not an error
///
/// The two rules interact, and **the draft does not say how**. Section 9.19 also
/// requires that "Parameters MUST be serialized in ascending order by Type", so
/// a second instance of a repeatable type produces a `Type Delta` of 0 — well
/// formed only if the decoder reads a zero delta as a repeat rather than as a
/// malformation. That reading is the one taken here; the alternative makes
/// Section 3.3.2's permission unusable, because there is no other encoding for
/// a second filter of the same type.
///
/// What the filters may **not** do is repeat the same (Parameter Type, SetID,
/// Property Type) triple, and Section 3.3.2 answers that with a REQUEST_ERROR
/// carrying INVALID_FILTER rather than with a session close. A reply an endpoint
/// sends is not a frame a decoder refuses, so nothing here enforces it — see
/// [`crate::range_filter`] for the reader an endpoint uses to decide.
fn parameter_may_repeat(key: u64) -> bool {
    matches!(key, AUTHORIZATION_TOKEN | 0x25..=0x29)
}

/// Add a delta to the previous delta-encoded key.
///
/// Draft-23 Section 8.3: "The previous Type value plus the Delta Type MUST NOT
/// be greater than 2^64 - 1. If a Delta Type is received that would be too
/// large, the Session MUST be closed with DELTA_ENCODING_OVERFLOW." Section
/// 9.19 says the same of a Message Parameter's Type Delta.
fn add_delta(prev_key: u64, delta: u64) -> Result<u64, CodecError> {
    prev_key.checked_add(delta).ok_or(CodecError::KeyDeltaOverflow(prev_key, delta))
}

/// Hold a namespace-plus-name pair to the Full Track Name cap.
///
/// Draft-23 Section 8.7: "The maximum total length of a Full Track Name is
/// 4,096 bytes. The length of a Full Track Name is computed as the sum of the
/// Track Namespace Field Length fields and the Track Name Length field... If an
/// endpoint receives a Track Namespace or a Full Track Name exceeding 4,096
/// bytes, it MUST close the session with FIELD_LENGTH_EXCEEDED."
///
/// The namespace half of that sentence is enforced inside the namespace decoder,
/// which is the only place that sees a namespace with no name beside it. This is
/// the other half, and it has to live where the two are decoded together: a
/// namespace at 4,000 bytes and a name at 500 are each legal alone.
fn check_full_track_name(namespace: &TrackNamespace, track_name: &[u8]) -> Result<(), CodecError> {
    let total = namespace.field_bytes_len().saturating_add(track_name.len());
    if total > MAX_FULL_TRACK_NAME_LENGTH {
        return Err(CodecError::TrackNameTooLong);
    }
    Ok(())
}

/// Refuse an empty Track Name.
///
/// Draft-23 Section 2.4.1: "Each Track Name MUST contain at least one byte. If
/// an endpoint receives a Track Name with a length of 0, it MUST close the
/// session with a PROTOCOL_VIOLATION." The REDIRECT Error Detail is exempt:
/// Section 9.4.2.1 requires its Track Name to be empty for namespace-scoped
/// requests.
///
/// Decoders call it after the rest of the body, so a DELTA_ENCODING_OVERFLOW
/// or FIELD_LENGTH_EXCEEDED later in the message is the one reported. Section
/// 12.2: "When more than one code applies, an endpoint uses
/// DELTA_ENCODING_OVERFLOW or FIELD_LENGTH_EXCEEDED in preference to the
/// other codes."
fn check_track_name(track_name: &[u8]) -> Result<(), CodecError> {
    if track_name.is_empty() {
        return Err(CodecError::EmptyTrackName);
    }
    Ok(())
}

/// Hold every AUTHORIZATION TOKEN parameter to the Token structure it names.
///
/// Section 8.9: "If the Token structure cannot be decoded, including an
/// unknown Alias Type, the receiver MUST close the Session with
/// MALFORMED_AUTH_TOKEN." Both namespaces carry the type on this draft, and
/// both reach here.
fn check_authorization_tokens(parameters: &[KeyValuePair]) -> Result<(), CodecError> {
    for parameter in parameters {
        let key = parameter.key.into_inner();
        if key != AUTH_TOKEN_PARAMETER {
            continue;
        }
        match &parameter.value {
            KvpValue::Bytes(value) => {
                AuthorizationToken::decode_moqt::<Wire>(key, value).map_err(|e| match e {
                    CodecError::KeyValueFormatting { key, detail } => {
                        CodecError::MalformedAuthToken { key, detail }
                    }
                    other => other,
                })?;
            }
            // Unreachable from the decoder, which picks the shape from the
            // type and finds this one length-prefixed. A caller that built the
            // pair in memory can still get here.
            KvpValue::Varint(_) => {
                return Err(CodecError::MalformedAuthToken {
                    key,
                    detail: "its value is a bare varint where the type defines a Token structure",
                });
            }
        }
    }
    Ok(())
}

/// The parameter types draft-23 Section 9.19.15, Table 7 permits inside a
/// `FILL_PARAMETERS` value, in ascending order. "An endpoint that receives a
/// parameter inside FILL_PARAMETERS that is not listed above MUST close the
/// session with INVALID_PARAMETER."
const FILL_PARAMETERS_ALLOWED: &[u64] = &[0x0A, 0x20, 0x21, 0x22, 0x25, 0x26, 0x27, 0x28];

/// The LOCATION_FILTER parameter type, draft-23 Section 9.19.9.
pub const LOCATION_FILTER: u64 = 0x21;

/// The FILL_PARAMETERS parameter type, draft-23 Section 9.19.15.
pub const FILL_PARAMETERS: u64 = 0x23;

/// The `Location Filter Type` values draft-23 Section 9.19.9 assigns, named as
/// Table 6 names them.
pub mod location_filter_types {
    /// 0x00, None: "no fields follow and there is no Location Filter".
    pub const NONE: u64 = 0x00;
    /// 0x01, Relative Start: "a relative StartGroup follows".
    pub const RELATIVE_START: u64 = 0x01;
    /// 0x02, Absolute Start: "StartGroup and StartObject follow".
    pub const ABSOLUTE_START: u64 = 0x02;
    /// 0x03, Absolute Start, Group End: "StartGroup, StartObject, and
    /// EndGroupDelta follow".
    pub const ABSOLUTE_START_GROUP_END: u64 = 0x03;
    /// 0x04, Absolute Range: "StartGroup, StartObject, EndGroupDelta, and
    /// EndObject follow".
    pub const ABSOLUTE_RANGE: u64 = 0x04;
    /// 0x05, Next Object: "no fields follow and it specifies the Next Object".
    pub const NEXT_OBJECT: u64 = 0x05;
}

/// How many `vi64` fields follow a `Location Filter Type`, or `None` for a type
/// draft-23 does not assign.
///
/// Section 9.19.9 gives one sentence per type and closes the list: "If an
/// endpoint receives any other Location Filter Type, it MUST close the session
/// with INVALID_PARAMETER." The fields are always a
/// prefix of `StartGroup`, `StartObject`, `EndGroupDelta`, `EndObject`, so the
/// count is all a reader needs to know which ones arrived.
///
/// Types 0x00 and 0x05 both carry nothing and mean opposite things — no filter
/// at all, and a filter that starts at the Next Object — so a caller that wants
/// the meaning switches on the type, never on the count.
pub fn location_filter_field_count(filter_type: u64) -> Option<usize> {
    use location_filter_types as T;
    match filter_type {
        T::NONE | T::NEXT_OBJECT => Some(0),
        T::RELATIVE_START => Some(1),
        T::ABSOLUTE_START => Some(2),
        T::ABSOLUTE_START_GROUP_END => Some(3),
        T::ABSOLUTE_RANGE => Some(4),
        _ => None,
    }
}

/// Read one `LOCATION_FILTER` value off `buf`: the `Location Filter Type`, then
/// exactly the fields that type names.
///
/// `buf` is bounded by the enclosing message body, or by the enclosing
/// `FILL_PARAMETERS` value, and nothing narrower: the parameter carries no
/// length of its own. A field that would run past that bound is a parameter
/// that is not the structure its type defines, which is
/// [`CodecError::SubscriptionFilterMalformed`] rather than a short read — the
/// frame around it arrived whole.
///
/// A type outside Section 9.19.9's list is
/// [`CodecError::ParameterValueOutOfRange`], the INVALID_PARAMETER of Section
/// 12.2 ("has a value outside its allowed range"), and it is refused before any
/// field is read: the type is the only thing that
/// says where the value ends, so past an unknown one there is nothing a reader
/// can do but stop.
fn read_location_filter(buf: &mut impl Buf) -> Result<(u64, Vec<u64>), CodecError> {
    let filter_type = VarInt::decode_moqt::<Wire>(buf)
        .map_err(|_| CodecError::SubscriptionFilterMalformed {
            detail: "its Location Filter Type runs past the end of the message",
        })?
        .into_inner();
    let count = location_filter_field_count(filter_type)
        .ok_or(CodecError::ParameterValueOutOfRange { key: LOCATION_FILTER, value: filter_type })?;
    let mut fields = Vec::with_capacity(count);
    for _ in 0..count {
        let field = VarInt::decode_moqt::<Wire>(buf).map_err(|_| {
            CodecError::SubscriptionFilterMalformed {
                detail: "a field its Location Filter Type names runs past the end of the message",
            }
        })?;
        fields.push(field.into_inner());
    }
    Ok((filter_type, fields))
}

/// Write a `LOCATION_FILTER` value in its minimal encoding: the type, then the
/// fields, each the shortest `vi64` that holds it.
///
/// The decoder stores what it read through this, so a value that arrived with
/// a non-minimal varint anywhere in it — the type included, which Section 8.1
/// permits like any other — re-encodes to different bytes. That is the same
/// treatment a Location (0x09) gets, and it is what makes such a frame a
/// non-canonical one rather than one this codec silently rewrites on relay.
fn write_location_filter(filter_type: u64, fields: &[u64]) -> Vec<u8> {
    let mut encoded = Vec::new();
    VarInt::from_u64_moqt(filter_type).encode_moqt::<Wire>(&mut encoded);
    for field in fields {
        VarInt::from_u64_moqt(*field).encode_moqt::<Wire>(&mut encoded);
    }
    encoded
}

/// Decode a draft-23 `LOCATION_FILTER` value into its `Location Filter Type`
/// and the fields that type names.
///
/// The value is the bytes a decoded [`KeyValuePair`] holds under type 0x21: the
/// type and its fields, with no length ahead of them. The fields come back in
/// wire order, `StartGroup`, `StartObject`, `EndGroupDelta`, `EndObject`, as
/// many as [`location_filter_field_count`] gives for the type; Section 9.19.9,
/// Table 6 says what each type means.
///
/// Refuses a type draft-23 does not assign with
/// [`CodecError::ParameterValueOutOfRange`], and a value that holds fewer or more
/// bytes than its type's fields with [`CodecError::SubscriptionFilterMalformed`].
/// Every value the decoder stores passes; the refusals are for a value built in
/// memory, which the encoder holds to the same rule before writing it.
pub fn decode_location_filter(value: &[u8]) -> Result<(u64, Vec<u64>), CodecError> {
    let mut cursor = value;
    let (filter_type, fields) = read_location_filter(&mut cursor)?;
    if cursor.has_remaining() {
        return Err(CodecError::SubscriptionFilterMalformed {
            detail: "bytes follow the fields its Location Filter Type names",
        });
    }
    Ok((filter_type, fields))
}

/// Hold a decoded `LOCATION_FILTER` to the one arithmetic rule draft-23 states
/// about it.
///
/// Section 9.19.9: "EndGroupDelta is delta encoded from StartGroup, but both the
/// start and end groups are absolute, not relative to Largest Object. If
/// StartGroup + EndGroupDelta exceeds 2^64 - 1, the endpoint MUST close the
/// session with DELTA_ENCODING_OVERFLOW." The sum only exists on types 0x03 and
/// 0x04, the two that carry an `EndGroupDelta`, which are the two whose field
/// count reaches three.
///
/// There is deliberately no check that the end is at or after the start.
/// `EndGroupDelta` is unsigned and added to `StartGroup`, so the end group can
/// never precede the start group; and within one group draft-23 states no rule
/// about `EndObject` being below `StartObject`. Section 3.3.1 says the opposite
/// for subscriptions — "A Location Filter on a subscription is always valid,
/// even if it specifies a range entirely before Largest Object" — so refusing
/// one would close sessions over a sentence that is not there.
fn check_location_filter_fields(fields: &[u64]) -> Result<(), CodecError> {
    if fields.len() < 3 {
        return Ok(());
    }
    let start_group = fields[0];
    let delta = fields[2];
    if start_group.checked_add(delta).is_none() {
        return Err(CodecError::FilterEndGroupOverflow { start_group, delta });
    }
    Ok(())
}

/// Read one `FILL_PARAMETERS` value off `buf`: its `Number of Parameters` and
/// that many parameters.
///
/// Section 9.19.15: "Its value is a Number of Parameters (vi64) followed by
/// that many Parameters that apply to the fill fetch stream (see Section 3.4),
/// encoded as if they were Parameters for a separate message (see Section
/// 9.19)." Nothing states the value's length, so each inner parameter is read
/// in the shape its type names, as a message's own are.
///
/// "The value of FILL_PARAMETERS is a separate parameter scope. Parameters
/// inside it are not considered to appear in the enclosing message for the
/// purposes of Section 9.19". The inner `Type Delta` chain therefore starts
/// from 0, and the outer parameter after `FILL_PARAMETERS` deltas from `0x23`.
///
/// A type outside Table 7 is [`CodecError::ParameterOutOfScope`], reported
/// against `FILL_PARAMETERS` itself. A type draft-23 does not define at all is
/// [`CodecError::UnknownMessageParameter`], checked first.
fn read_fill_parameters(buf: &mut impl Buf) -> Result<Vec<KeyValuePair>, CodecError> {
    let count = VarInt::decode_moqt::<Wire>(buf)?.into_inner() as usize;
    let mut params = crate::types::reserve_bounded(count, buf);
    let mut prev_key: u64 = 0;

    for i in 0..count {
        let delta = VarInt::decode_moqt::<Wire>(buf)?.into_inner();
        let abs_key = add_delta(prev_key, delta)?;
        if i > 0 && delta == 0 && !parameter_may_repeat(abs_key) {
            return Err(CodecError::DuplicateParameter(abs_key));
        }
        prev_key = abs_key;

        let encoding =
            param_encoding(abs_key).ok_or(CodecError::UnknownMessageParameter(abs_key))?;
        if !FILL_PARAMETERS_ALLOWED.contains(&abs_key) {
            return Err(CodecError::ParameterOutOfScope {
                key: abs_key,
                message_type: FILL_PARAMETERS,
            });
        }

        let value = decode_parameter_value(encoding, abs_key, buf)?;
        params.push(KeyValuePair { key: VarInt::from_u64_moqt(abs_key), value });
    }
    check_location_filters(&params)?;
    Ok(params)
}

/// Write a `FILL_PARAMETERS` value: the count and the inner parameters, with
/// no length ahead of them.
fn write_fill_parameters(params: &[KeyValuePair]) -> Result<Vec<u8>, CodecError> {
    for p in params {
        let key = p.key.into_inner();
        if param_encoding(key).is_none() {
            return Err(CodecError::UnknownMessageParameter(key));
        }
        if !FILL_PARAMETERS_ALLOWED.contains(&key) {
            return Err(CodecError::ParameterOutOfScope { key, message_type: FILL_PARAMETERS });
        }
    }
    let mut encoded = Vec::new();
    encode_parameters(params, &mut encoded)?;
    Ok(encoded)
}

/// Decode the parameters a `FILL_PARAMETERS` value carries.
///
/// The value is the bytes a decoded [`KeyValuePair`] holds under type 0x23:
/// the `Number of Parameters` and the parameters, with no length ahead of
/// them. Refuses a value with bytes after its last parameter with
/// [`CodecError::SubscriptionFilterMalformed`]; the decoder never stores one.
pub fn decode_fill_parameters(value: &[u8]) -> Result<Vec<KeyValuePair>, CodecError> {
    let mut cursor = value;
    let params = read_fill_parameters(&mut cursor)?;
    if cursor.has_remaining() {
        return Err(CodecError::SubscriptionFilterMalformed {
            detail: "bytes follow the parameters FILL_PARAMETERS counts",
        });
    }
    Ok(params)
}

/// Encode `params` as a `FILL_PARAMETERS` value, the inverse of
/// [`decode_fill_parameters`].
pub fn encode_fill_parameters(params: &[KeyValuePair]) -> Result<Vec<u8>, CodecError> {
    write_fill_parameters(params)
}

/// Hold every LOCATION_FILTER and FILL_PARAMETERS parameter to the structure
/// its own type names.
///
/// Applied on both sides. A value the decoder refuses is one the peer must
/// close the session over, so writing it is a way to end a session rather than
/// a way to ask for anything.
///
/// The two are checked together because `FILL_PARAMETERS` can carry a
/// `LOCATION_FILTER` of its own, and a filter that is malformed one level down
/// is exactly as malformed. [`decode_fill_parameters`] recurses back into this
/// function for that reason; the nesting bottoms out because Table 7 does not
/// list `FILL_PARAMETERS` inside itself.
///
/// The values are otherwise decoded and discarded. What is kept is the refusal
/// — each stays on its parameter as bytes, so a caller reads one through
/// [`decode_location_filter`] or [`decode_fill_parameters`] when it wants the
/// structure rather than the frame.
///
/// On decode the `LOCATION_FILTER` half can only find the overflow: the
/// decoder read the value by its type, so its shape is already right. On
/// encode it finds everything, because a value built in memory can name one
/// type and carry another type's fields, and the encoder writes the value with
/// no length that would let a receiver notice.
fn check_location_filters(parameters: &[KeyValuePair]) -> Result<(), CodecError> {
    for parameter in parameters {
        let key = parameter.key.into_inner();
        if key != LOCATION_FILTER && key != FILL_PARAMETERS {
            continue;
        }
        match &parameter.value {
            KvpValue::Bytes(value) if key == LOCATION_FILTER => {
                check_location_filter_fields(&decode_location_filter(value)?.1)?;
            }
            KvpValue::Bytes(value) => {
                decode_fill_parameters(value)?;
            }
            // Unreachable from the decoder, which stores both of these as
            // bytes. A caller that built the pair in memory can still get here,
            // and it is the same rule.
            KvpValue::Varint(_) => {
                return Err(CodecError::SubscriptionFilterMalformed {
                    detail: "its value is a bare varint where the type defines a structure",
                });
            }
        }
    }
    Ok(())
}

/// Read one parameter's value in the shape its type names.
///
/// Shared by the message's own parameter block and by the nested block inside
/// `FILL_PARAMETERS`, so a type cannot be read one way in a message and another
/// way in a fill.
fn decode_parameter_value(
    encoding: ParamEncoding,
    abs_key: u64,
    buf: &mut impl Buf,
) -> Result<KvpValue, CodecError> {
    Ok(match encoding {
        ParamEncoding::Varint => KvpValue::Varint(VarInt::decode_moqt::<Wire>(buf)?),
        ParamEncoding::Uint8 => {
            if buf.remaining() < 1 {
                return Err(CodecError::UnexpectedEnd);
            }
            let byte = buf.get_u8();
            if !uint8_value_in_range(abs_key, byte) {
                return Err(CodecError::ParameterValueOutOfRange {
                    key: abs_key,
                    value: byte as u64,
                });
            }
            KvpValue::Varint(VarInt::from_u64_moqt(byte as u64))
        }
        ParamEncoding::Location => {
            let group = VarInt::decode_moqt::<Wire>(buf)?;
            let object = VarInt::decode_moqt::<Wire>(buf)?;
            let mut encoded = Vec::new();
            group.encode_moqt::<Wire>(&mut encoded);
            object.encode_moqt::<Wire>(&mut encoded);
            KvpValue::Bytes(encoded)
        }
        ParamEncoding::LengthPrefixed => {
            let len = VarInt::decode_moqt::<Wire>(buf)?.into_inner() as usize;
            KvpValue::Bytes(read_bytes(buf, len)?)
        }
        ParamEncoding::LocationFilter => {
            let (filter_type, fields) = read_location_filter(buf)?;
            KvpValue::Bytes(write_location_filter(filter_type, &fields))
        }
        // Stored re-encoded, as a LOCATION_FILTER is, so a value that arrived
        // with a non-minimal varint inside it is a non-canonical frame.
        ParamEncoding::FillParameters => {
            let inner = read_fill_parameters(buf)?;
            KvpValue::Bytes(write_fill_parameters(&inner)?)
        }
        ParamEncoding::TrackNamespaceValue => {
            // A prefix of zero fields is legal: Section 2.4.1 puts a Track
            // Namespace at "between 0 and 32 Track Namespace Fields", and
            // an empty prefix matches every namespace.
            let ns = TrackNamespace::decode_allow_empty_moqt::<Wire>(buf)?;
            let mut encoded = Vec::new();
            ns.encode_moqt::<Wire>(&mut encoded);
            KvpValue::Bytes(encoded)
        }
    })
}

/// Decode a count-prefixed list of parameters with delta-encoded types.
fn decode_parameters(buf: &mut impl Buf) -> Result<Vec<KeyValuePair>, CodecError> {
    let count = VarInt::decode_moqt::<Wire>(buf)?.into_inner() as usize;
    let mut params = crate::types::reserve_bounded(count, buf);
    let mut prev_key: u64 = 0;

    for i in 0..count {
        let delta = VarInt::decode_moqt::<Wire>(buf)?.into_inner();
        let abs_key = add_delta(prev_key, delta)?;
        // Types ascend, so a repeat is always a zero delta against the
        // parameter before it. Draft-23 Section 9.19: "Receivers SHOULD check
        // that there are no unexpected duplicate parameters and close the
        // session with INVALID_PARAMETER if found."
        //
        // "Unexpected" is what `parameter_may_repeat` reads: a zero delta on a
        // type whose own definition permits repeats is the second instance,
        // which is the only encoding such an instance has.
        if i > 0 && delta == 0 && !parameter_may_repeat(abs_key) {
            return Err(CodecError::DuplicateParameter(abs_key));
        }
        prev_key = abs_key;

        // Section 9.19: "All Message Parameters MUST be defined in the
        // negotiated version of MOQT or negotiated via Setup Options. An
        // endpoint that receives an unknown Message Parameter MUST close the
        // session with INVALID_PARAMETER."
        let encoding =
            param_encoding(abs_key).ok_or(CodecError::UnknownMessageParameter(abs_key))?;

        let value = decode_parameter_value(encoding, abs_key, buf)?;

        params.push(KeyValuePair { key: VarInt::from_u64_moqt(abs_key), value });
    }
    check_authorization_tokens(&params)?;
    check_location_filters(&params)?;
    Ok(params)
}

/// Whether `bytes` is exactly the wire form of a Location — two consecutive
/// varints and nothing after them.
///
/// `decode_parameters` builds this value by reading two varints and
/// re-serialising them, so every value it produces satisfies this. A value
/// built in memory need not, and the encode arm writes these bytes verbatim
/// because a Location carries no length of its own. Without this check a
/// caller could hand over one varint, or three, and the codec would put a
/// frame on the wire that its own decoder answers with an error.
fn is_location_value(bytes: &[u8]) -> bool {
    let mut buf = bytes;
    VarInt::decode_moqt::<Wire>(&mut buf).is_ok()
        && VarInt::decode_moqt::<Wire>(&mut buf).is_ok()
        && !buf.has_remaining()
}

/// Whether `bytes` is exactly the wire form of a Track Namespace, with
/// nothing after it. The same reasoning as [`is_location_value`]: the value
/// goes out verbatim, so it has to be something this draft can read back.
fn is_track_namespace_value(bytes: &[u8]) -> bool {
    let mut buf = bytes;
    TrackNamespace::decode_allow_empty_moqt::<Wire>(&mut buf).is_ok() && !buf.has_remaining()
}

/// Encode a count-prefixed list of parameters with delta-encoded types.
///
/// Errors with [`CodecError::InvalidField`] on a uint8-valued parameter whose
/// value [`decode_parameters`] would refuse, so the two directions accept the
/// same set of frames.
///
/// The check is not a mirror added for tidiness. A uint8 parameter's value is
/// written as one octet, and a value that does not fit one is otherwise
/// truncated to its low byte: GROUP_ORDER 258 becomes the byte 0x02, which is
/// Descending — a well-formed frame carrying a value the caller never asked
/// for, and one no receiver could tell from a genuine Descending. Refusing is
/// the only outcome that does not silently rewrite the message.
///
/// The two structure rules are here for a plainer reason. A value under a type
/// that defines a structure and is not that structure — a Token, a filter — is
/// one the receiver must close the session over, so writing it is not a way to
/// send it; the sender's first sign of trouble would be the session going.
fn encode_parameters(params: &[KeyValuePair], buf: &mut impl BufMut) -> Result<(), CodecError> {
    check_authorization_tokens(params)?;
    check_location_filters(params)?;
    VarInt::from_usize(params.len()).encode_moqt::<Wire>(buf);
    let mut prev_key: u64 = 0;

    for (i, p) in params.iter().enumerate() {
        let abs_key = p.key.into_inner();
        // The delta is a difference, so a descending pair wraps the subtraction
        // into a nine-byte delta the peer resolves to an unrelated key, and a
        // repeated type is a frame `decode_parameters` refuses. Both are
        // refused here so the two directions accept the same set of frames.
        let delta = abs_key
            .checked_sub(prev_key)
            .ok_or(CodecError::ParametersOutOfOrder(prev_key, abs_key))?;
        if i > 0 && delta == 0 && !parameter_may_repeat(abs_key) {
            return Err(CodecError::DuplicateParameter(abs_key));
        }
        prev_key = abs_key;
        VarInt::from_u64_moqt(delta).encode_moqt::<Wire>(buf);

        // Message Parameters are not Key-Value-Pairs and Section 9.19 gives
        // them no value maximum; the message is "limited by
        // MAX_CONTROL_MESSAGE_SIZE (Section 9.1.8)". A Length-prefixed value
        // is bounded only by that.

        let encoding = param_encoding(abs_key);
        match (&p.value, encoding) {
            (KvpValue::Varint(v), Some(ParamEncoding::Varint)) => {
                v.encode_moqt::<Wire>(buf);
            }
            (KvpValue::Varint(v), Some(ParamEncoding::Uint8)) => {
                let raw = v.into_inner();
                let byte = u8::try_from(raw).map_err(|_| CodecError::InvalidField)?;
                if !uint8_value_in_range(abs_key, byte) {
                    return Err(CodecError::ParameterValueOutOfRange {
                        key: abs_key,
                        value: byte as u64,
                    });
                }
                buf.put_u8(byte);
            }
            // These values are already stored in their own wire form — two
            // varints for a Location, a field count and its fields for a Track
            // Namespace, a type and its fields for a Location Filter — so they
            // go out as they are. Adding a length here is the bug these arms
            // exist to avoid.
            (KvpValue::Bytes(b), Some(ParamEncoding::Location)) => {
                if !is_location_value(b) {
                    return Err(CodecError::InvalidField);
                }
                buf.put_slice(b);
            }
            (KvpValue::Bytes(b), Some(ParamEncoding::TrackNamespaceValue)) => {
                if !is_track_namespace_value(b) {
                    return Err(CodecError::InvalidField);
                }
                buf.put_slice(b);
            }
            // `check_location_filters` above has already held the value to
            // its own type, which is the only check there is room for: the
            // receiver finds the end of these bytes by reading the type, so a
            // value whose fields disagree with its type desynchronises every
            // parameter after it rather than failing on its own.
            (KvpValue::Bytes(b), Some(ParamEncoding::LocationFilter)) => {
                buf.put_slice(b);
            }
            // Held to its structure by `check_location_filters` above, for the
            // same reason: the receiver finds its end by reading it.
            (KvpValue::Bytes(b), Some(ParamEncoding::FillParameters)) => {
                buf.put_slice(b);
            }
            (KvpValue::Bytes(b), Some(ParamEncoding::LengthPrefixed)) => {
                VarInt::from_usize(b.len()).encode_moqt::<Wire>(buf);
                buf.put_slice(b);
            }
            _ => {
                // Fallback: encode as KVP even/odd
                match &p.value {
                    KvpValue::Varint(v) => v.encode_moqt::<Wire>(buf),
                    KvpValue::Bytes(b) => {
                        VarInt::from_usize(b.len()).encode_moqt::<Wire>(buf);
                        buf.put_slice(b);
                    }
                }
            }
        }
    }
    Ok(())
}

/// Decode `bytes` as a run of Key-Value-Pairs, the shape of an Immutable
/// Properties value (Section 10.7).
pub(crate) fn decode_property_list(bytes: &[u8]) -> Result<Vec<KeyValuePair>, CodecError> {
    let mut cursor = bytes;
    decode_kvp_delta(&mut cursor)
}

/// Decode delta-encoded KVPs with even/odd convention (for setup options
/// and track properties). Read until buffer is exhausted.
fn decode_kvp_delta(buf: &mut impl Buf) -> Result<Vec<KeyValuePair>, CodecError> {
    let mut pairs = Vec::new();
    let mut prev_key: u64 = 0;

    while buf.has_remaining() {
        let delta = VarInt::decode_moqt::<Wire>(buf)?.into_inner();
        let abs_key = add_delta(prev_key, delta)?;
        prev_key = abs_key;

        let value = if abs_key.is_multiple_of(2) {
            let v = VarInt::decode_moqt::<Wire>(buf)?;
            KvpValue::Varint(v)
        } else {
            let len = VarInt::decode_moqt::<Wire>(buf)?.into_inner() as usize;
            // Draft-23 Section 8.3: "The maximum length of a value is 2^16-1
            // bytes. If an endpoint receives a length larger than the maximum,
            // it MUST close the session with FIELD_LENGTH_EXCEEDED."
            if len > MAX_KVP_VALUE_LEN {
                return Err(KvpError::ValueTooLong(len).into());
            }
            let data = read_bytes(buf, len)?;
            KvpValue::Bytes(data)
        };

        pairs.push(KeyValuePair { key: VarInt::from_u64_moqt(abs_key), value });
    }
    Ok(pairs)
}

/// Encode delta-encoded KVPs with even/odd convention.
///
/// Refuses a list that is not in ascending order by type, for the same reason
/// [`encode_parameters`] does: the delta is a difference, and a descending pair
/// wraps it into a nine-byte delta the peer resolves to an unrelated key.
fn encode_kvp_delta(pairs: &[KeyValuePair], buf: &mut impl BufMut) -> Result<(), CodecError> {
    let mut prev_key: u64 = 0;
    for p in pairs {
        let abs_key = p.key.into_inner();
        let delta = abs_key
            .checked_sub(prev_key)
            .ok_or(CodecError::ParametersOutOfOrder(prev_key, abs_key))?;
        prev_key = abs_key;
        VarInt::from_u64_moqt(delta).encode_moqt::<Wire>(buf);
        match &p.value {
            KvpValue::Varint(v) => v.encode_moqt::<Wire>(buf),
            KvpValue::Bytes(b) => {
                if b.len() > MAX_KVP_VALUE_LEN {
                    return Err(KvpError::ValueTooLong(b.len()).into());
                }
                VarInt::from_usize(b.len()).encode_moqt::<Wire>(buf);
                buf.put_slice(b);
            }
        }
    }
    Ok(())
}

/// Immutable Properties, Property Type 0xB.
///
/// Section 10.7: Immutable Properties are "a Track or Object Property that
/// contains a sequence of Key-Value-Pairs (see Figure 4) that are themselves
/// Track or Object Properties, respectively". The Type is odd, so its value is
/// length-prefixed bytes, and those bytes are another delta-typed run starting
/// from 0.
const IMMUTABLE_PROPERTIES: u64 = 0x0B;

/// Whether `value` is inside the range draft-23 allows for a Track Property
/// type that restricts one.
///
/// Three types do, and each answers anything outside its range with
/// MALFORMED_KEY_VALUE. DEFAULT_PUBLISHER_PRIORITY (0x0E), Section 10.4: "If an
/// endpoint receives a value above 255, it MUST close the session with
/// MALFORMED_KEY_VALUE." DEFAULT_PUBLISHER_GROUP_ORDER (0x22), Section 10.5:
/// "The allowed values are Ascending (0x1) or Descending (0x2). If an endpoint
/// receives a value outside this range, it MUST close the session with
/// MALFORMED_KEY_VALUE." DYNAMIC_GROUPS (0x30), Section 10.6: "If an endpoint
/// receives a value larger than 1, it MUST close the session with
/// MALFORMED_KEY_VALUE."
///
/// The numbers belong to the Property registry, not the Message Parameter one:
/// 0x22 is also GROUP_ORDER as a parameter.
fn track_property_value_in_range(key: u64, value: u64) -> bool {
    match key {
        // DEFAULT_PUBLISHER_PRIORITY (0x0E)
        0x0E => value <= 255,
        // DEFAULT_PUBLISHER_GROUP_ORDER (0x22)
        0x22 => value == 1 || value == 2,
        // DYNAMIC_GROUPS (0x30)
        0x30 => value <= 1,
        _ => true,
    }
}

/// Refuse a Track Property whose value falls outside the range its type allows,
/// wherever in the list it is carried.
///
/// # Inside Immutable Properties as well as beside them
///
/// The list is walked one level down through Immutable Properties, whose
/// contents Section 10.7 defines as properties themselves. The draft asks for
/// this in as many words: "When looking for the value of a property, processors
/// MUST search both the mutable properties and the contents of Immutable
/// Properties." A check applied only to the outer list is one a peer opts out of
/// by moving a pair inside the block, and the block is where an Original
/// Publisher puts what a relay must not rewrite — which is where a track's group
/// order and dynamic-group support belong.
///
/// Bytes under 0xB that do not parse as a Key-Value-Pair run are left alone
/// rather than refused. Section 10.7 says relays "MAY decode and view the
/// Properties in the Key-Value-Pairs", which is a permission and not a
/// requirement, so a block this codec cannot read is carried to the caller
/// intact instead of ending the session.
fn check_track_property_values(properties: &[KeyValuePair]) -> Result<(), CodecError> {
    for property in properties {
        let key = property.key.into_inner();
        match &property.value {
            KvpValue::Varint(value) => {
                let value = value.into_inner();
                if !track_property_value_in_range(key, value) {
                    return Err(CodecError::TrackPropertyValueOutOfRange { key, value });
                }
            }
            KvpValue::Bytes(bytes) if key == IMMUTABLE_PROPERTIES => {
                let mut inner = &bytes[..];
                // A block that is not a Key-Value-Pair run is skipped rather
                // than refused. See the note above: reading inside it is a
                // permission, so one that cannot be read is carried.
                //
                // Skipped means this block and only this block. The rule the
                // draft states here is about the block whose pairs will not
                // parse, and says nothing about its neighbours; ending the
                // whole walk would let a peer keep an out-of-range property
                // from being looked at by putting an unparseable block in
                // front of it.
                if let Ok(nested) = decode_kvp_delta(&mut inner) {
                    check_track_property_values(&nested)?;
                }
            }
            KvpValue::Bytes(_) => {}
        }
    }
    Ok(())
}

/// Decode the Track Properties that fill the tail of a control message.
///
/// [`decode_kvp_delta`] with the Property registry's value rules applied. The
/// two are separate because that function also reads Setup Options, which are a
/// third namespace numbering its entries independently of this one.
fn decode_track_properties(buf: &mut impl Buf) -> Result<Vec<KeyValuePair>, CodecError> {
    let properties = decode_kvp_delta(buf)?;
    check_track_property_values(&properties)?;
    Ok(properties)
}

/// Encode a control message's Track Properties.
///
/// Held to the same value ranges as the decoder. A value this codec refuses to
/// read is one it must not write: the peer that receives it is required to close
/// the session, so the sender's first sign of trouble would be the session
/// going.
fn encode_track_properties(
    properties: &[KeyValuePair],
    buf: &mut impl BufMut,
) -> Result<(), CodecError> {
    check_track_property_values(properties)?;
    encode_kvp_delta(properties, buf)
}

/// The Setup Option types this draft defines.
///
/// Section 9.1 assigns PATH, AUTHORIZATION TOKEN, MAX_AUTH_TOKEN_CACHE_SIZE, AUTHORITY,
/// MAX_FILTER_RANGES, MOQT_IMPLEMENTATION, MAX_REQUEST_UPDATES and
/// MAX_CONTROL_MESSAGE_SIZE.
///
/// The list exists for one rule and one direction. Section 9.1: "Receivers
/// MUST allow duplicates of unknown Setup Options." A receiver may therefore
/// refuse a repeat only of a type it can name, and an option outside this list
/// is one an extension defined and this codec has no business closing a session
/// over. Nothing else reads it - unknown options are still decoded and carried,
/// as "Receivers MUST ignore unrecognized Setup Options" requires.
const KNOWN_SETUP_OPTIONS: &[u64] =
    &[0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, MAX_CONTROL_MESSAGE_SIZE_OPTION];

/// The MAX_CONTROL_MESSAGE_SIZE Setup Option type, Section 9.1.8.
pub const MAX_CONTROL_MESSAGE_SIZE_OPTION: u64 = 0x09;

/// The MAX_CONTROL_MESSAGE_SIZE an endpoint uses for its peer until it has
/// the peer's SETUP, and when the SETUP carries none.
///
/// Section 9.1.8: "The value is encoded as a variable-length integer and MUST
/// be at least 65535. If not present, the default value is 65535. Until an
/// endpoint receives the peer's SETUP, it uses the default value, including for
/// SETUP itself."
pub const DEFAULT_MAX_CONTROL_MESSAGE_SIZE: u64 = 65535;

/// The value of a MAX_CONTROL_MESSAGE_SIZE option: the one `vi64` its bytes
/// hold.
///
/// Option Type 0x09 is odd, so Section 8.3 gives it a Length and "a sequence
/// of Length bytes", and Section 9.1.8 says "The value is encoded as a
/// variable-length integer". This codec reads the bytes as exactly one `vi64`;
/// anything else is a value that "does not match the serialization defined by
/// that Type", which Section 8.3 closes with MALFORMED_KEY_VALUE.
pub fn decode_max_control_message_size(value: &[u8]) -> Result<u64, CodecError> {
    const NOT_ONE_VARINT: &str = "its bytes are not exactly one variable-length integer";
    let mut cursor = value;
    let size =
        VarInt::decode_moqt::<Wire>(&mut cursor).map_err(|_| CodecError::KeyValueFormatting {
            key: MAX_CONTROL_MESSAGE_SIZE_OPTION,
            detail: NOT_ONE_VARINT,
        })?;
    if cursor.has_remaining() {
        return Err(CodecError::KeyValueFormatting {
            key: MAX_CONTROL_MESSAGE_SIZE_OPTION,
            detail: NOT_ONE_VARINT,
        });
    }
    Ok(size.into_inner())
}

/// The bytes of a MAX_CONTROL_MESSAGE_SIZE option carrying `size`.
pub fn encode_max_control_message_size(size: u64) -> Vec<u8> {
    let mut value = Vec::new();
    VarInt::from_u64_moqt(size).encode_moqt::<Wire>(&mut value);
    value
}

/// The MAX_CONTROL_MESSAGE_SIZE a SETUP's options advertise, or the default.
///
/// Section 9.1.8 states no receiver action for a value below 65535, so one is
/// returned as it arrived.
pub fn max_control_message_size(options: &[KeyValuePair]) -> Result<u64, CodecError> {
    for option in options {
        if option.key.into_inner() != MAX_CONTROL_MESSAGE_SIZE_OPTION {
            continue;
        }
        return match &option.value {
            KvpValue::Bytes(value) => decode_max_control_message_size(value),
            KvpValue::Varint(_) => Err(CodecError::KeyValueFormatting {
                key: MAX_CONTROL_MESSAGE_SIZE_OPTION,
                detail: "its value is a bare varint where the odd type requires a Length",
            }),
        };
    }
    Ok(DEFAULT_MAX_CONTROL_MESSAGE_SIZE)
}

/// The one Setup Option whose definition allows more than one instance.
///
/// Section 9.1.4: "The AUTHORIZATION TOKEN Setup Option (Option Type 0x03)
/// is functionally equivalent to the AUTHORIZATION TOKEN message parameter...
/// The endpoint can specify one or more tokens in SETUP that the peer can use to
/// authorize MOQT session establishment." That is Section 9.1's "unless the
/// option definition explicitly allows multiple instances" carve-out, and it is
/// the only one on this draft.
const REPEATABLE_SETUP_OPTION: u64 = 0x03;

/// Decode the Setup Options of a SETUP message.
///
/// Section 9.1: "Senders MUST NOT repeat the same Option Type in a message
/// unless the option definition explicitly allows multiple instances. Receivers
/// MUST allow duplicates of unknown Setup Options."
///
/// The second sentence is why this is not the mirror of
/// [`encode_setup_options`]: a repeat of a type this draft names is refused, and
/// a repeat of any other type is carried. Types ascend and are delta-encoded, so
/// a repeat is always a zero delta against the option before it.
fn decode_setup_options(buf: &mut impl Buf) -> Result<Vec<KeyValuePair>, CodecError> {
    let options = decode_kvp_delta(buf)?;
    for (i, option) in options.iter().enumerate() {
        let key = option.key.into_inner();
        if key == REPEATABLE_SETUP_OPTION || !KNOWN_SETUP_OPTIONS.contains(&key) {
            continue;
        }
        if options[..i].iter().any(|earlier| earlier.key == option.key) {
            return Err(CodecError::DuplicateParameter(key));
        }
    }
    check_authorization_tokens(&options)?;
    check_setup_token_aliases(&options)?;
    max_control_message_size(&options)?;
    Ok(options)
}

/// Refuse a SETUP token that names an Alias with DELETE or USE_ALIAS.
///
/// SETUP is the first message an endpoint sends, so an Alias can be registered
/// only by a REGISTER earlier in the same SETUP. The options are scanned in
/// wire order: REGISTER adds its Alias and DELETE of a registered Alias removes
/// it. Section 8.9: "The receiver of a message referencing an Alias that is not
/// currently registered MUST reject the message with UNKNOWN_AUTH_TOKEN_ALIAS."
/// A reference to an Alias not registered is refused at once, as
/// [`CodecError::UnregisteredTokenAliasInSetup`].
///
/// A reference to a registered Alias is refused once the scan ends, as
/// [`CodecError::TokenAliasInSetup`]. Section 9.1.4: "If a server receives
/// Alias Type DELETE (0x0) or USE_ALIAS (0x2) in a SETUP message, it MUST close
/// the session with ROLE_VIOLATION." At a client the REGISTER may not have
/// taken effect: Section 9.1.4 treats one over the receiver's
/// MAX_AUTH_TOKEN_CACHE_SIZE as USE_VALUE. The codec knows neither the role
/// nor the cache size.
fn check_setup_token_aliases(options: &[KeyValuePair]) -> Result<(), CodecError> {
    use crate::auth_token::TokenAliasType;
    let mut registered: Vec<u64> = Vec::new();
    let mut registered_reference = None;
    for option in options {
        let key = option.key.into_inner();
        let KvpValue::Bytes(value) = &option.value else { continue };
        if key != AUTH_TOKEN_PARAMETER {
            continue;
        }
        let token = AuthorizationToken::decode_moqt::<Wire>(key, value).map_err(|_| {
            CodecError::MalformedAuthToken { key, detail: "the Token does not parse" }
        })?;
        let alias_type = token.alias_type.id();
        match (token.alias_type, token.alias) {
            (TokenAliasType::Register, Some(alias)) => registered.push(alias),
            (TokenAliasType::Delete | TokenAliasType::UseAlias, Some(alias)) => {
                let Some(at) = registered.iter().position(|&r| r == alias) else {
                    return Err(CodecError::UnregisteredTokenAliasInSetup { alias_type, alias });
                };
                if token.alias_type == TokenAliasType::Delete {
                    registered.swap_remove(at);
                }
                registered_reference.get_or_insert(alias_type);
            }
            _ => {}
        }
    }
    match registered_reference {
        Some(alias_type) => Err(CodecError::TokenAliasInSetup { alias_type }),
        None => Ok(()),
    }
}

/// Encode the Setup Options of a SETUP message.
///
/// The sender's half of the same sentence, and it is the wider half: "Senders
/// MUST NOT repeat the same Option Type in a message" names no exception for
/// types the sender does not recognise, so every repeat is refused here except
/// the one the draft allows. A caller holding an option this codec has never
/// heard of still may not send it twice.
///
/// The token is in this namespace as well, and is held to its structure here for
/// the reason [`encode_parameters`] gives.
///
/// A MAX_CONTROL_MESSAGE_SIZE below 65535 is refused with
/// [`CodecError::InvalidField`]: Section 9.1.8 says the value "MUST be at
/// least 65535".
fn encode_setup_options(options: &[KeyValuePair], buf: &mut impl BufMut) -> Result<(), CodecError> {
    check_authorization_tokens(options)?;
    check_setup_token_aliases(options)?;
    if max_control_message_size(options)? < DEFAULT_MAX_CONTROL_MESSAGE_SIZE {
        return Err(CodecError::InvalidField);
    }
    for (i, option) in options.iter().enumerate() {
        if option.key.into_inner() == REPEATABLE_SETUP_OPTION {
            continue;
        }
        if options[..i].iter().any(|earlier| earlier.key == option.key) {
            return Err(CodecError::DuplicateParameter(option.key.into_inner()));
        }
    }
    encode_kvp_delta(options, buf)
}

// ============================================================
// Message Types
// ============================================================

/// The control message types draft-23 Section 9, Table 5 assigns.
///
/// Table 5 lists 0x18 as RESERVED, FETCH_OK in drafts up to 22: a FETCH is answered
/// with REQUEST_OK (Section 9.3), so 0x18 is an unknown type here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum MessageType {
    RequestUpdate = 0x02,
    Subscribe = 0x03,
    SubscribeOk = 0x04,
    RequestError = 0x05,
    PublishNamespace = 0x06,
    /// REQUEST_OK (0x07). Draft-23 Section 1.5: "This document uses the
    /// shorthand PUBLISH_OK, FETCH_OK, REQUEST_UPDATE_OK, TRACK_STATUS_OK,
    /// SUBSCRIBE_NAMESPACE_OK, SUBSCRIBE_TRACKS_OK and PUBLISH_NAMESPACE_OK to
    /// refer to a REQUEST_OK sent in response to the corresponding request
    /// type."
    RequestOk = 0x07,
    Namespace = 0x08,
    PublishDone = 0x0B,
    TrackStatus = 0x0D,
    NamespaceDone = 0x0E,
    PublishSkipped = 0x0F,
    GoAway = 0x10,
    Fetch = 0x16,
    Publish = 0x1D,
    PublishStateNotify = 0x22,
    SubscribeNamespace = 0x50,
    SubscribeTracks = 0x51,
    Setup = 0x2F00,
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
            0x0B => Some(MessageType::PublishDone),
            0x0D => Some(MessageType::TrackStatus),
            0x0E => Some(MessageType::NamespaceDone),
            0x0F => Some(MessageType::PublishSkipped),
            0x10 => Some(MessageType::GoAway),
            0x16 => Some(MessageType::Fetch),
            0x1D => Some(MessageType::Publish),
            0x22 => Some(MessageType::PublishStateNotify),
            0x50 => Some(MessageType::SubscribeNamespace),
            0x51 => Some(MessageType::SubscribeTracks),
            0x2F00 => Some(MessageType::Setup),
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
            MessageType::PublishDone => "publish_done",
            MessageType::TrackStatus => "track_status",
            MessageType::NamespaceDone => "namespace_done",
            MessageType::PublishSkipped => "publish_skipped",
            MessageType::GoAway => "goaway",
            MessageType::Fetch => "fetch",
            MessageType::Publish => "publish",
            MessageType::PublishStateNotify => "publish_state_notify",
            MessageType::SubscribeNamespace => "subscribe_namespace",
            MessageType::SubscribeTracks => "subscribe_tracks",
            MessageType::Setup => "setup",
        }
    }
}

// ============================================================
// Session Lifecycle Messages
// ============================================================

/// Unified SETUP (0x2F00).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setup {
    pub options: Vec<KeyValuePair>,
}

impl Setup {
    /// The MAX_CONTROL_MESSAGE_SIZE this SETUP advertises, or 65535 when it
    /// carries none (Section 9.1.8).
    pub fn max_control_message_size(&self) -> Result<u64, CodecError> {
        max_control_message_size(&self.options)
    }
}

/// GOAWAY (0x10). There is no Request ID field, so the control-stream and
/// request-stream forms are identical on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoAway {
    pub new_session_uri: Vec<u8>,
    pub timeout: VarInt,
}

// ============================================================
// Consolidated Response Messages
// ============================================================

/// REQUEST_OK (0x07), the response to PUBLISH, FETCH, REQUEST_UPDATE,
/// TRACK_STATUS, SUBSCRIBE_NAMESPACE, SUBSCRIBE_TRACKS and PUBLISH_NAMESPACE
/// (Section 9.3).
///
/// Nothing in the frame says which request it answers, so the decoder holds
/// its parameters to the union of Section 9.3's lists and accepts Track
/// Properties. [`RequestOk::check_answers`] applies the rules for one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestOk {
    pub parameters: Vec<KeyValuePair>,
    pub track_properties: Vec<KeyValuePair>,
}

/// The request a [`RequestOk`] answers, named by Section 1.5's shorthand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestOkKind {
    /// PUBLISH_OK.
    Publish,
    /// FETCH_OK.
    Fetch,
    /// REQUEST_UPDATE_OK.
    RequestUpdate,
    /// TRACK_STATUS_OK.
    TrackStatus,
    /// SUBSCRIBE_NAMESPACE_OK.
    SubscribeNamespace,
    /// SUBSCRIBE_TRACKS_OK.
    SubscribeTracks,
    /// PUBLISH_NAMESPACE_OK.
    PublishNamespace,
}

impl RequestOkKind {
    /// Whether Section 9.3 lists Message Parameter `key` for this response.
    ///
    /// Section 9.3: "The parameters that can appear depend on the request being
    /// answered", then one list per response: EXPIRES and LARGEST_OBJECT for
    /// FETCH_OK, REQUEST_UPDATE_OK and TRACK_STATUS_OK, and EXPIRES alone for
    /// PUBLISH_OK, SUBSCRIBE_NAMESPACE_OK, SUBSCRIBE_TRACKS_OK and
    /// PUBLISH_NAMESPACE_OK.
    pub fn allows_parameter(self, key: u64) -> bool {
        const EXPIRES: u64 = 0x08;
        const LARGEST_OBJECT: u64 = 0x09;
        match self {
            RequestOkKind::Fetch | RequestOkKind::RequestUpdate | RequestOkKind::TrackStatus => {
                key == EXPIRES || key == LARGEST_OBJECT
            }
            RequestOkKind::Publish
            | RequestOkKind::SubscribeNamespace
            | RequestOkKind::SubscribeTracks
            | RequestOkKind::PublishNamespace => key == EXPIRES,
        }
    }

    /// Whether this response may carry Track Properties.
    ///
    /// Section 9.3: "Track Properties are populated in TRACK_STATUS_OK and
    /// FETCH_OK; they are empty in PUBLISH_OK, REQUEST_UPDATE_OK,
    /// SUBSCRIBE_NAMESPACE_OK and PUBLISH_NAMESPACE_OK." SUBSCRIBE_TRACKS_OK
    /// is in neither list, so this does not refuse them there.
    pub fn allows_track_properties(self) -> bool {
        match self {
            RequestOkKind::Fetch | RequestOkKind::TrackStatus | RequestOkKind::SubscribeTracks => {
                true
            }
            RequestOkKind::Publish
            | RequestOkKind::RequestUpdate
            | RequestOkKind::SubscribeNamespace
            | RequestOkKind::PublishNamespace => false,
        }
    }
}

impl RequestOk {
    /// Hold this REQUEST_OK to the rules for the response `kind`.
    ///
    /// A parameter the response's list does not name is
    /// [`CodecError::ParameterOutOfScope`] (Section 9.19.1, INVALID_PARAMETER),
    /// and Track Properties where the response must have none are
    /// [`CodecError::TrackPropertiesNotPermitted`] (Section 9.3,
    /// INVALID_FIELD).
    pub fn check_answers(&self, kind: RequestOkKind) -> Result<(), CodecError> {
        for parameter in &self.parameters {
            let key = parameter.key.into_inner();
            if !kind.allows_parameter(key) {
                return Err(CodecError::ParameterOutOfScope {
                    key,
                    message_type: MessageType::RequestOk.id(),
                });
            }
        }
        if !kind.allows_track_properties() && !self.track_properties.is_empty() {
            return Err(CodecError::TrackPropertiesNotPermitted);
        }
        Ok(())
    }
}

/// The Error Detail types draft-23 Section 16.11, Table 19 assigns.
pub mod error_detail_types {
    /// REDIRECT (0x01), Section 9.4.2.1. Odd, so Length-prefixed.
    pub const REDIRECT: u64 = 0x01;
    /// UNSUPPORTED_PROPERTY (0x02), Section 9.4.2.2. Even, so a bare varint:
    /// "contains the Property Type (vi64) of a Mandatory Track Property".
    pub const UNSUPPORTED_PROPERTY: u64 = 0x02;
}

/// The value of a REDIRECT Error Detail (Section 9.4.2.1).
///
/// ```text
/// REDIRECT Error Detail {
///   Type (vi64) = 0x01,
///   Length (vi64),
///   Connect URI Length (vi64),
///   Connect URI (..),
///   Track Namespace (..),
///   Track Name Length (vi64),
///   Track Name (..),
/// }
/// ```
///
/// The Track Name may be empty: "Track Name is not meaningful for
/// namespace-scoped requests (SUBSCRIBE_NAMESPACE, PUBLISH_NAMESPACE,
/// SUBSCRIBE_TRACKS) and MUST be empty". Which request it answers is session
/// state, so neither that rule nor the Connect URI's ROLE_VIOLATION is
/// checked here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirect {
    pub connect_uri: Vec<u8>,
    pub track_namespace: TrackNamespace,
    pub track_name: Vec<u8>,
}

impl Redirect {
    /// Read a REDIRECT Error Detail's value.
    ///
    /// A value that is not the structure above is
    /// [`CodecError::MalformedErrorDetail`]. Section 8.3: "If a receiver
    /// understands a Type, and the following Value or Length/Value does not
    /// match the serialization defined by that Type, the receiver MUST close
    /// the session with MALFORMED_KEY_VALUE." The namespace's own rules
    /// (Section 8.7) keep their own errors.
    pub fn decode(value: &[u8]) -> Result<Self, CodecError> {
        const SHORT: &str = "its fields run past the end of the Error Detail";
        let malformed = |detail| CodecError::MalformedErrorDetail {
            detail_type: error_detail_types::REDIRECT,
            detail,
        };
        let mut buf = value;
        let uri_len =
            VarInt::decode_moqt::<Wire>(&mut buf).map_err(|_| malformed(SHORT))?.into_inner();
        let connect_uri = read_bytes(&mut buf, uri_len as usize).map_err(|_| malformed(SHORT))?;
        let track_namespace = TrackNamespace::decode_allow_empty_moqt::<Wire>(&mut buf)
            .map_err(|e| if e.is_incomplete() { malformed(SHORT) } else { e })?;
        let name_len =
            VarInt::decode_moqt::<Wire>(&mut buf).map_err(|_| malformed(SHORT))?.into_inner();
        let track_name = read_bytes(&mut buf, name_len as usize).map_err(|_| malformed(SHORT))?;
        if buf.has_remaining() {
            return Err(malformed("bytes follow its Track Name"));
        }
        check_full_track_name(&track_namespace, &track_name)?;
        Ok(Redirect { connect_uri, track_namespace, track_name })
    }

    /// The value of a REDIRECT Error Detail carrying this redirect.
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.track_namespace.validate_moqt()?;
        check_full_track_name(&self.track_namespace, &self.track_name)?;
        let mut value = Vec::new();
        VarInt::from_usize(self.connect_uri.len()).encode_moqt::<Wire>(&mut value);
        value.put_slice(&self.connect_uri);
        self.track_namespace.encode_moqt::<Wire>(&mut value);
        VarInt::from_usize(self.track_name.len()).encode_moqt::<Wire>(&mut value);
        value.put_slice(&self.track_name);
        Ok(value)
    }

    /// This redirect as a REDIRECT Error Detail.
    pub fn to_error_detail(&self) -> Result<KeyValuePair, CodecError> {
        Ok(KeyValuePair {
            key: VarInt::from_u64_moqt(error_detail_types::REDIRECT),
            value: KvpValue::Bytes(self.encode()?),
        })
    }
}

/// REQUEST_ERROR (0x05), Section 9.4.1, Figure 10.
///
/// `error_details` are Key-Value-Pairs (Section 8.3) filling the rest of the
/// message: "Receivers MUST ignore unknown Error Detail types, and MUST ignore
/// a known Error Detail type that accompanies an Error Code it is not defined
/// for" (Section 9.4.2). They are carried in wire order, unknown ones included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestError {
    pub error_code: VarInt,
    pub retry_interval: VarInt,
    pub reason_phrase: Vec<u8>,
    pub error_details: Vec<KeyValuePair>,
}

impl RequestError {
    /// The first REDIRECT Error Detail, decoded, if the error carries one.
    pub fn redirect(&self) -> Option<Result<Redirect, CodecError>> {
        self.error_details.iter().find_map(|detail| {
            (detail.key.into_inner() == error_detail_types::REDIRECT).then(|| match &detail.value {
                KvpValue::Bytes(value) => Redirect::decode(value),
                KvpValue::Varint(_) => Err(CodecError::MalformedErrorDetail {
                    detail_type: error_detail_types::REDIRECT,
                    detail: "its value is a bare varint where the odd type requires a Length",
                }),
            })
        })
    }

    /// The Property Types named by UNSUPPORTED_PROPERTY Error Details, in wire
    /// order. Section 9.4.2.2: "Multiple instances of this type are allowed."
    pub fn unsupported_properties(&self) -> Vec<u64> {
        self.error_details
            .iter()
            .filter(|detail| detail.key.into_inner() == error_detail_types::UNSUPPORTED_PROPERTY)
            .filter_map(|detail| match &detail.value {
                KvpValue::Varint(v) => Some(v.into_inner()),
                KvpValue::Bytes(_) => None,
            })
            .collect()
    }
}

/// REQUEST_ERROR error codes with dedicated meaning.
pub mod request_error_codes {
    /// UNAVAILABLE (0xA), Section 12.3: "The responder cannot fulfill this
    /// request at this time, but might be able to later".
    pub const UNAVAILABLE: u64 = 0x0A;
    /// A Mandatory Track Property the receiver does not understand. The
    /// UNSUPPORTED_PROPERTY Error Detail names it.
    pub const UNSUPPORTED_EXTENSION: u64 = 0x33;
    /// The REDIRECT Error Detail says where to retry.
    pub const REDIRECT: u64 = 0x34;
    /// SUBSCRIBE_TRACKS filter parameters conflict among too many subscribers
    /// to aggregate the subscription upstream.
    pub const CONFLICTING_FILTERS: u64 = 0x35;
    /// A Range Filter parameter is invalid or exceeds MAX_FILTER_RANGES.
    pub const INVALID_FILTER: u64 = 0x36;
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

/// SUBSCRIBE_OK (0x04).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeOk {
    pub track_alias: VarInt,
    pub parameters: Vec<KeyValuePair>,
    pub track_properties: Vec<KeyValuePair>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestUpdate {
    pub request_id: VarInt,
    pub parameters: Vec<KeyValuePair>,
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
    pub track_properties: Vec<KeyValuePair>,
}

/// PUBLISH_DONE (0x0B).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishDone {
    /// The reason the publisher is ending the subscription.
    ///
    /// Not validated against the registry. Draft-23 Section 13: "Receipt of an
    /// unknown error code in any error context (Session Termination,
    /// REQUEST_ERROR, PUBLISH_DONE, or Data Stream Reset) MUST be treated as
    /// equivalent to INTERNAL_ERROR for that context. An endpoint MUST NOT
    /// close the session because it received an unknown error code in a
    /// REQUEST_ERROR or PUBLISH_DONE."
    pub status_code: VarInt,
    /// The number of streams the publisher opened for this subscription,
    /// including fill fetch streams (Section 9.9). See
    /// [`publish_done_codes::STREAM_COUNT_UNKNOWN`] for the sentinel.
    pub stream_count: VarInt,
    pub reason_phrase: Vec<u8>,
}

/// Numeric values for the [`PublishDone`] fields.
pub mod publish_done_codes {
    /// TOO_FAR_BEHIND (0x5).
    pub const TOO_FAR_BEHIND: u64 = 0x05;
    /// EXPIRED (0x6).
    pub const EXPIRED: u64 = 0x06;
    /// EXPIRED_AUTH_TOKEN (0x7). Section 9.9: "A publisher that ends a
    /// subscription because the authorization token that authorized it has
    /// expired SHOULD send PUBLISH_DONE with status code EXPIRED_AUTH_TOKEN."
    pub const EXPIRED_AUTH_TOKEN: u64 = 0x07;

    /// The value [`super::PublishDone::stream_count`] carries when the
    /// publisher cannot state an exact count.
    ///
    /// Section 9.9: "If the publisher is unable to set Stream Count to the
    /// exact number of streams opened for the subscription, it MUST set
    /// Stream Count to 2^64 - 1." The sentinel is indistinguishable from an
    /// exact count of `2^64 - 1`.
    pub const STREAM_COUNT_UNKNOWN: u64 = u64::MAX;
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

// ============================================================
// Namespace Messages
// ============================================================

/// NAMESPACE (0x08), Section 9.15, Figure 20: a Track Namespace Suffix, then a
/// parameter block.
///
/// No Message Parameter definition names NAMESPACE, so under Section 9.19.1
/// any parameter here is out of scope; the block is read and every entry in it
/// refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Namespace {
    pub namespace_suffix: TrackNamespace,
    pub parameters: Vec<KeyValuePair>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceDone {
    pub namespace_suffix: TrackNamespace,
}

// ============================================================
// Subscribe Namespace / Tracks Messages
// ============================================================

/// SUBSCRIBE_NAMESPACE (0x50). Subscribes to NAMESPACE / NAMESPACE_DONE
/// advertisements for namespaces matching `namespace_prefix`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeNamespace {
    pub request_id: VarInt,
    pub namespace_prefix: TrackNamespace,
    pub parameters: Vec<KeyValuePair>,
}

/// SUBSCRIBE_TRACKS (0x51). Subscribes to PUBLISH messages for tracks whose
/// namespace matches `namespace_prefix`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeTracks {
    pub request_id: VarInt,
    pub namespace_prefix: TrackNamespace,
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

/// FETCH (0x16), Section 9.11, Figure 17.
///
/// ```text
/// FETCH Message {
///   Type (vi64) = 0x16,
///   Length (vi64),
///   Request ID (vi64),
///   Track Namespace (..),
///   Track Name Length (vi64),
///   Track Name (..),
///   Number of Parameters (vi64),
///   Parameters (..) ...
/// }
/// ```
///
/// The range travels in the `LOCATION_FILTER` parameter. Section 3.2: "If the
/// Location filter is relative (see Section 9.19.9), the publisher MUST return
/// REQUEST_ERROR with error code INVALID_RANGE." That is a reply rather than a
/// close, so every Location Filter Type decodes here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetch {
    pub request_id: VarInt,
    pub track_namespace: TrackNamespace,
    pub track_name: Vec<u8>,
    pub parameters: Vec<KeyValuePair>,
}

// ============================================================
// Publish State Notify
// ============================================================

/// PUBLISH_STATE_NOTIFY (0x22), Section 9.10, Figure 16.
///
/// No Request ID: the subscription's request stream identifies it. Section
/// 9.10's rules about who sends it and on which stream ("An endpoint that
/// receives a PUBLISH_STATE_NOTIFY for any other request type MUST close the
/// session with UNEXPECTED_MESSAGE. A publisher that receives a
/// PUBLISH_STATE_NOTIFY MUST close the session with ROLE_VIOLATION.") are
/// session state and belong to the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishStateNotify {
    pub parameters: Vec<KeyValuePair>,
}

// ============================================================
// Publish Skipped
// ============================================================

/// PUBLISH_SKIPPED (0x0F): a track namespace suffix, then a track name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishSkipped {
    pub namespace_suffix: TrackNamespace,
    pub track_name: Vec<u8>,
}

// ============================================================
// Unified Message Enum
// ============================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlMessage {
    Setup(Setup),
    GoAway(GoAway),
    RequestOk(RequestOk),
    RequestError(RequestError),
    Subscribe(Subscribe),
    SubscribeOk(SubscribeOk),
    RequestUpdate(RequestUpdate),
    Publish(Publish),
    PublishStateNotify(PublishStateNotify),
    PublishDone(PublishDone),
    PublishNamespace(PublishNamespace),
    Namespace(Namespace),
    NamespaceDone(NamespaceDone),
    SubscribeNamespace(SubscribeNamespace),
    SubscribeTracks(SubscribeTracks),
    TrackStatus(TrackStatus),
    Fetch(Fetch),
    PublishSkipped(PublishSkipped),
}

/// Hold a REQUEST_ERROR's Error Details to its Error Code.
///
/// Section 9.4.2.1: the REDIRECT Error Detail "accompanies Error Code REDIRECT
/// and MUST be present when the Error Code is REDIRECT. An endpoint that
/// receives a REQUEST_ERROR with Error Code REDIRECT and no REDIRECT Error
/// Detail MUST close the session with MALFORMED_MESSAGE." Under that code each
/// REDIRECT detail is also held to its structure. Under any other code a
/// REDIRECT detail is one the receiver "MUST ignore", so it is carried
/// unread.
///
/// Section 9.4.2 states no receiver action for a repeated REDIRECT detail, so
/// the decoder accepts one; [`check_error_details_to_send`] refuses it.
fn check_error_details(m: &RequestError) -> Result<(), CodecError> {
    if m.error_code.into_inner() != request_error_codes::REDIRECT {
        return Ok(());
    }
    let mut found = false;
    for detail in &m.error_details {
        if detail.key.into_inner() != error_detail_types::REDIRECT {
            continue;
        }
        found = true;
        match &detail.value {
            KvpValue::Bytes(value) => {
                Redirect::decode(value)?;
            }
            KvpValue::Varint(_) => {
                return Err(CodecError::MalformedErrorDetail {
                    detail_type: error_detail_types::REDIRECT,
                    detail: "its value is a bare varint where the odd type requires a Length",
                });
            }
        }
    }
    if !found {
        return Err(CodecError::MissingErrorDetail {
            error_code: request_error_codes::REDIRECT,
            detail_type: error_detail_types::REDIRECT,
        });
    }
    Ok(())
}

/// The sender's half of [`check_error_details`], plus Section 9.4.2:
/// "Senders MUST NOT repeat the same Error Detail type in a message unless
/// the type's definition explicitly allows multiple instances." Only
/// UNSUPPORTED_PROPERTY allows them, and a type this draft does not define is
/// the caller's to repeat or not.
fn check_error_details_to_send(m: &RequestError) -> Result<(), CodecError> {
    check_error_details(m)?;
    let redirects = m
        .error_details
        .iter()
        .filter(|detail| detail.key.into_inner() == error_detail_types::REDIRECT)
        .count();
    if redirects > 1 {
        return Err(CodecError::DuplicateParameter(error_detail_types::REDIRECT));
    }
    Ok(())
}

/// Whether draft-23 lets Message Parameter `key` appear in `message`.
///
/// Section 9.19.1: "Each Message Parameter definition indicates the message
/// types in which it can appear, and each control message definition lists the
/// parameters it allows. If a parameter appears in some other type of message,
/// the receiving endpoint MUST close the session with INVALID_PARAMETER." One
/// arm per entry in the Message Parameters registry (Section 16.7), carrying the
/// message types that entry's own definition names. The lists in the message
/// definitions say the same thing from the other side.
///
/// REQUEST_OK and REQUEST_UPDATE list their parameters per kind of request
/// (Section 9.3 and Section 9.5), and the request is session state, so each is
/// held to the union of its lists here. [`RequestOk::check_answers`] narrows a
/// REQUEST_OK to one list.
///
/// No definition names NAMESPACE, so every parameter is out of scope there.
///
/// The table decides scope only. A type this draft does not define has no scope
/// to be outside of and is answered by [`CodecError::UnknownMessageParameter`],
/// which is why the final arm carries rather than refuses.
pub fn parameter_in_scope(key: u64, message: MessageType) -> bool {
    use MessageType as M;
    match key {
        // Section 9.19.4 OBJECT_DELIVERY_TIMEOUT and Section 9.19.3
        // SUBGROUP_DELIVERY_TIMEOUT: "It MAY appear in a SUBSCRIBE, PUBLISH,
        // SUBSCRIBE_TRACKS, or REQUEST_UPDATE (for a subscription) message."
        0x02 | 0x06 => {
            matches!(message, M::Subscribe | M::Publish | M::SubscribeTracks | M::RequestUpdate)
        }
        // Section 9.19.2 AUTHORIZATION TOKEN: "It MAY appear in a PUBLISH,
        // SUBSCRIBE, REQUEST_UPDATE, SUBSCRIBE_NAMESPACE, SUBSCRIBE_TRACKS,
        // PUBLISH_NAMESPACE, TRACK_STATUS or FETCH message."
        0x03 => matches!(
            message,
            M::Publish
                | M::Subscribe
                | M::RequestUpdate
                | M::SubscribeNamespace
                | M::SubscribeTracks
                | M::PublishNamespace
                | M::TrackStatus
                | M::Fetch
        ),
        // Section 9.19.6 RENDEZVOUS TIMEOUT: "It MAY appear in a SUBSCRIBE
        // message."
        0x04 => matches!(message, M::Subscribe),
        // Section 9.19.16 EXPIRES: "It MAY appear in PUBLISH, SUBSCRIBE_OK,
        // FETCH_OK, or any REQUEST_OK."
        0x08 => matches!(message, M::Publish | M::SubscribeOk | M::RequestOk),
        // Section 9.19.17 LARGEST OBJECT: "It MAY appear in SUBSCRIBE_OK,
        // PUBLISH, REQUEST_UPDATE_OK, TRACK_STATUS_OK, FETCH_OK, or
        // PUBLISH_STATE_NOTIFY."
        0x09 => {
            matches!(message, M::SubscribeOk | M::Publish | M::RequestOk | M::PublishStateNotify)
        }
        // Section 9.19.5 FILL TIMEOUT: "It MAY appear in a FETCH message, or
        // inside a FILL_PARAMETERS parameter". The nested half is Table 7's.
        0x0A => matches!(message, M::Fetch),
        // Section 9.19.18 PAUSED: "It MAY appear in SUBSCRIBE, REQUEST_UPDATE
        // (for a subscription or a SUBSCRIBE_TRACKS request), PUBLISH,
        // SUBSCRIBE_TRACKS and PUBLISH_STATE_NOTIFY."
        0x11 => matches!(
            message,
            M::Subscribe
                | M::RequestUpdate
                | M::Publish
                | M::SubscribeTracks
                | M::PublishStateNotify
        ),
        // Section 9.19.7 SUBSCRIBER PRIORITY: "It MAY appear in a SUBSCRIBE,
        // PUBLISH, SUBSCRIBE_TRACKS, FETCH, or REQUEST_UPDATE (for a
        // subscription or FETCH), or inside a FILL_PARAMETERS parameter".
        0x20 => matches!(
            message,
            M::Subscribe | M::Publish | M::SubscribeTracks | M::Fetch | M::RequestUpdate
        ),
        // Section 9.19.9: "The LOCATION_FILTER parameter (Parameter Type 0x21)
        // MAY appear in a FETCH, SUBSCRIBE, PUBLISH, SUBSCRIBE_TRACKS,
        // REQUEST_UPDATE (for a subscription) or PUBLISH_STATE_NOTIFY message,
        // or inside a FILL_PARAMETERS parameter".
        0x21 => matches!(
            message,
            M::Fetch
                | M::Subscribe
                | M::Publish
                | M::SubscribeTracks
                | M::RequestUpdate
                | M::PublishStateNotify
        ),
        // Section 9.19.8 GROUP ORDER: "It MAY appear in a SUBSCRIBE, PUBLISH,
        // SUBSCRIBE_TRACKS, or FETCH, or inside a FILL_PARAMETERS parameter".
        0x22 => matches!(message, M::Subscribe | M::Publish | M::SubscribeTracks | M::Fetch),
        // Section 9.19.15: "The FILL_PARAMETERS parameter (Parameter Type
        // 0x23) MAY appear in a SUBSCRIBE, SUBSCRIBE_TRACKS, PUBLISH, or
        // REQUEST_UPDATE (for a subscription) message."
        0x23 => {
            matches!(message, M::Subscribe | M::SubscribeTracks | M::Publish | M::RequestUpdate)
        }
        // Section 3.3.2: "All other filter parameters MAY appear multiple times
        // in a FETCH, SUBSCRIBE, SUBSCRIBE_TRACKS, or REQUEST_UPDATE (on a
        // subscription, from the subscriber only) message." SUBGROUP_FILTER
        // (Section 9.19.10), OBJECTID_FILTER (Section 9.19.11), PRIORITY_FILTER
        // (Section 9.19.12) and OBJECT_PROPERTY_FILTER (Section 9.19.13).
        0x25..=0x28 => {
            matches!(message, M::Fetch | M::Subscribe | M::SubscribeTracks | M::RequestUpdate)
        }
        // Section 3.3.2, of TRACK_PROPERTY_FILTER (Section 9.19.14): "The Track
        // Property filter parameter MAY appear multiple times in a
        // SUBSCRIBE_TRACKS message or REQUEST_UPDATE for it."
        0x29 => matches!(message, M::SubscribeTracks | M::RequestUpdate),
        // Section 9.19.19 NEW GROUP REQUEST: "It MAY appear in SUBSCRIBE or
        // REQUEST_UPDATE for a subscription."
        0x32 => matches!(message, M::Subscribe | M::RequestUpdate),
        // Section 9.19.20 TRACK_NAMESPACE_PREFIX: "It MAY appear in
        // REQUEST_UPDATE for a SUBSCRIBE_NAMESPACE or SUBSCRIBE_TRACKS
        // request."
        0x34 => matches!(message, M::RequestUpdate),
        // Section 9.19.22 INCLUDE_PROPERTIES: "It MAY appear in SUBSCRIBE,
        // TRACK_STATUS, FETCH or SUBSCRIBE_TRACKS."
        0x35 => matches!(message, M::Subscribe | M::TrackStatus | M::Fetch | M::SubscribeTracks),
        // Section 9.19.21 SUBSCRIBE_TRACKS_ID: "It appears only in a PUBLISH
        // sent as a result of a SUBSCRIBE_TRACKS". Whether a PUBLISH was sent
        // for one is session state.
        0x36 => matches!(message, M::Publish),
        _ => true,
    }
}

/// Refuse a message carrying a Message Parameter its own definition does not
/// place there (Section 9.19.1).
///
/// Applied on both sides. A parameter outside its scope is one the peer must
/// close the session over, so writing one is a way to end a session rather than
/// a way to ask for anything.
fn check_parameter_scope(message: &ControlMessage) -> Result<(), CodecError> {
    let parameters = match message {
        ControlMessage::RequestOk(m) => &m.parameters,
        ControlMessage::Subscribe(m) => &m.parameters,
        ControlMessage::SubscribeOk(m) => &m.parameters,
        ControlMessage::RequestUpdate(m) => &m.parameters,
        ControlMessage::Publish(m) => &m.parameters,
        ControlMessage::PublishStateNotify(m) => &m.parameters,
        ControlMessage::PublishNamespace(m) => &m.parameters,
        ControlMessage::Namespace(m) => &m.parameters,
        ControlMessage::SubscribeNamespace(m) => &m.parameters,
        ControlMessage::SubscribeTracks(m) => &m.parameters,
        ControlMessage::TrackStatus(m) => &m.parameters,
        ControlMessage::Fetch(m) => &m.parameters,
        // No Message Parameters field. Section 9.19.1: "Note that since Setup
        // Options use a separate namespace, it is impossible for Message
        // Parameters to appear in Setup messages."
        ControlMessage::Setup(_)
        | ControlMessage::GoAway(_)
        | ControlMessage::RequestError(_)
        | ControlMessage::PublishDone(_)
        | ControlMessage::NamespaceDone(_)
        | ControlMessage::PublishSkipped(_) => return Ok(()),
    };

    let message_type = message.message_type();
    for parameter in parameters {
        let key = parameter.key.into_inner();
        if !parameter_in_scope(key, message_type) {
            return Err(CodecError::ParameterOutOfScope { key, message_type: message_type.id() });
        }
    }
    Ok(())
}

impl ControlMessage {
    /// Encode under the default MAX_CONTROL_MESSAGE_SIZE of 65535, which is the
    /// limit until the peer's SETUP arrives (Section 9.1.8).
    pub fn encode(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        self.encode_with_limit(buf, DEFAULT_MAX_CONTROL_MESSAGE_SIZE)
    }

    /// Encode for a peer whose MAX_CONTROL_MESSAGE_SIZE is `limit`.
    ///
    /// Section 9: "An endpoint MUST NOT send a control message with a length
    /// larger than the peer's MAX_CONTROL_MESSAGE_SIZE (Section 9.1.8)." The
    /// length is the Message Length field, the body alone.
    pub fn encode_with_limit(&self, buf: &mut impl BufMut, limit: u64) -> Result<(), CodecError> {
        if let ControlMessage::RequestError(m) = self {
            check_error_details_to_send(m)?;
        }
        check_parameter_scope(self)?;
        let mut body = Vec::with_capacity(256);
        self.encode_body(&mut body)?;

        if body.len() as u64 > limit {
            return Err(CodecError::ControlMessageExceedsLimit {
                length: body.len() as u64,
                limit,
            });
        }

        VarInt::from_u64_moqt(self.message_type().id()).encode_moqt::<Wire>(buf);
        // Section 9, Figure 6: "Message Length (vi64)".
        VarInt::from_usize(body.len()).encode_moqt::<Wire>(buf);
        buf.put_slice(&body);
        Ok(())
    }

    /// Decode under the default MAX_CONTROL_MESSAGE_SIZE of 65535: the limit
    /// of an endpoint that advertised none (Section 9.1.8).
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        Self::decode_with_limit(buf, DEFAULT_MAX_CONTROL_MESSAGE_SIZE)
    }

    /// Decode as an endpoint whose own MAX_CONTROL_MESSAGE_SIZE is `limit`.
    ///
    /// Section 9: "If an endpoint receives a control message with a length
    /// larger than its MAX_CONTROL_MESSAGE_SIZE, it MUST close the session with
    /// FIELD_LENGTH_EXCEEDED." The Length is checked before the body is
    /// waited for, so an oversized message is refused as soon as its Length
    /// has arrived.
    pub fn decode_with_limit(buf: &mut impl Buf, limit: u64) -> Result<Self, CodecError> {
        let type_id = VarInt::decode_moqt::<Wire>(buf)?.into_inner();
        let msg_type =
            MessageType::from_id(type_id).ok_or(CodecError::UnknownMessageType(type_id))?;
        let declared = VarInt::decode_moqt::<Wire>(buf)?.into_inner();
        if declared > limit {
            return Err(CodecError::ControlMessageExceedsLimit { length: declared, limit });
        }
        let body_len = declared as usize;
        if buf.remaining() < body_len {
            return Err(CodecError::UnexpectedEnd);
        }
        let body_bytes = buf.copy_to_bytes(body_len);
        let mut body = &body_bytes[..];
        let msg = match Self::decode_body(msg_type, &mut body) {
            Ok(msg) => msg,
            // The fields wanted more bytes than the Length gives. The buffer
            // is bounded by that Length, so nothing more can arrive.
            Err(
                CodecError::UnexpectedEnd
                | CodecError::Kvp(crate::kvp::KvpError::UnexpectedEnd)
                | CodecError::Kvp(crate::kvp::KvpError::VarInt(
                    crate::varint::VarIntError::UnexpectedEnd,
                ))
                | CodecError::VarInt(crate::varint::VarIntError::UnexpectedEnd),
            ) => {
                return Err(CodecError::ControlMessageLengthMismatch {
                    declared: body_len,
                    detail: "its fields need more bytes than its Length gives",
                });
            }
            Err(e) => return Err(e),
        };
        check_parameter_scope(&msg)?;
        // Draft-23 Section 9: "If the length does not match the length of the
        // Message Body, the receiver MUST close the session with
        // MALFORMED_MESSAGE."
        if body.has_remaining() {
            return Err(CodecError::ControlMessageLengthMismatch {
                declared: body_len,
                detail: "its fields left bytes unread",
            });
        }
        Ok(msg)
    }

    fn encode_body(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        match self {
            ControlMessage::Setup(m) => {
                encode_setup_options(&m.options, buf)?;
            }
            ControlMessage::GoAway(m) => {
                if m.new_session_uri.len() > MAX_GOAWAY_URI_LENGTH {
                    return Err(CodecError::GoAwayUriTooLong);
                }
                VarInt::from_usize(m.new_session_uri.len()).encode_moqt::<Wire>(buf);
                buf.put_slice(&m.new_session_uri);
                m.timeout.encode_moqt::<Wire>(buf);
            }
            ControlMessage::RequestOk(m) => {
                encode_parameters(&m.parameters, buf)?;
                encode_track_properties(&m.track_properties, buf)?;
            }
            ControlMessage::RequestError(m) => {
                if m.reason_phrase.len() > MAX_REASON_PHRASE_LENGTH {
                    return Err(CodecError::ReasonPhraseTooLong);
                }
                m.error_code.encode_moqt::<Wire>(buf);
                m.retry_interval.encode_moqt::<Wire>(buf);
                VarInt::from_usize(m.reason_phrase.len()).encode_moqt::<Wire>(buf);
                buf.put_slice(&m.reason_phrase);
                encode_kvp_delta(&m.error_details, buf)?;
            }
            ControlMessage::Subscribe(m) => {
                m.track_namespace.validate_moqt()?;
                check_track_name(&m.track_name)?;
                check_full_track_name(&m.track_namespace, &m.track_name)?;
                m.request_id.encode_moqt::<Wire>(buf);
                m.track_namespace.encode_moqt::<Wire>(buf);
                VarInt::from_usize(m.track_name.len()).encode_moqt::<Wire>(buf);
                buf.put_slice(&m.track_name);
                encode_parameters(&m.parameters, buf)?;
            }
            ControlMessage::SubscribeOk(m) => {
                m.track_alias.encode_moqt::<Wire>(buf);
                encode_parameters(&m.parameters, buf)?;
                encode_track_properties(&m.track_properties, buf)?;
            }
            ControlMessage::RequestUpdate(m) => {
                m.request_id.encode_moqt::<Wire>(buf);
                encode_parameters(&m.parameters, buf)?;
            }
            ControlMessage::Publish(m) => {
                m.track_namespace.validate_moqt()?;
                check_track_name(&m.track_name)?;
                check_full_track_name(&m.track_namespace, &m.track_name)?;
                m.request_id.encode_moqt::<Wire>(buf);
                m.track_namespace.encode_moqt::<Wire>(buf);
                VarInt::from_usize(m.track_name.len()).encode_moqt::<Wire>(buf);
                buf.put_slice(&m.track_name);
                m.track_alias.encode_moqt::<Wire>(buf);
                encode_parameters(&m.parameters, buf)?;
                encode_track_properties(&m.track_properties, buf)?;
            }
            ControlMessage::PublishStateNotify(m) => {
                encode_parameters(&m.parameters, buf)?;
            }
            ControlMessage::PublishDone(m) => {
                if m.reason_phrase.len() > MAX_REASON_PHRASE_LENGTH {
                    return Err(CodecError::ReasonPhraseTooLong);
                }
                m.status_code.encode_moqt::<Wire>(buf);
                m.stream_count.encode_moqt::<Wire>(buf);
                VarInt::from_usize(m.reason_phrase.len()).encode_moqt::<Wire>(buf);
                buf.put_slice(&m.reason_phrase);
            }
            ControlMessage::PublishNamespace(m) => {
                m.track_namespace.validate_moqt()?;
                m.request_id.encode_moqt::<Wire>(buf);
                m.track_namespace.encode_moqt::<Wire>(buf);
                encode_parameters(&m.parameters, buf)?;
            }
            ControlMessage::Namespace(m) => {
                m.namespace_suffix.validate_moqt()?;
                m.namespace_suffix.encode_moqt::<Wire>(buf);
                encode_parameters(&m.parameters, buf)?;
            }
            ControlMessage::NamespaceDone(m) => {
                m.namespace_suffix.validate_moqt()?;
                m.namespace_suffix.encode_moqt::<Wire>(buf);
            }
            ControlMessage::SubscribeNamespace(m) => {
                m.namespace_prefix.validate_moqt()?;
                m.request_id.encode_moqt::<Wire>(buf);
                m.namespace_prefix.encode_moqt::<Wire>(buf);
                encode_parameters(&m.parameters, buf)?;
            }
            ControlMessage::SubscribeTracks(m) => {
                m.namespace_prefix.validate_moqt()?;
                m.request_id.encode_moqt::<Wire>(buf);
                m.namespace_prefix.encode_moqt::<Wire>(buf);
                encode_parameters(&m.parameters, buf)?;
            }
            ControlMessage::TrackStatus(m) => {
                m.track_namespace.validate_moqt()?;
                check_track_name(&m.track_name)?;
                check_full_track_name(&m.track_namespace, &m.track_name)?;
                m.request_id.encode_moqt::<Wire>(buf);
                m.track_namespace.encode_moqt::<Wire>(buf);
                VarInt::from_usize(m.track_name.len()).encode_moqt::<Wire>(buf);
                buf.put_slice(&m.track_name);
                encode_parameters(&m.parameters, buf)?;
            }
            ControlMessage::Fetch(m) => {
                m.track_namespace.validate_moqt()?;
                check_track_name(&m.track_name)?;
                check_full_track_name(&m.track_namespace, &m.track_name)?;
                m.request_id.encode_moqt::<Wire>(buf);
                m.track_namespace.encode_moqt::<Wire>(buf);
                VarInt::from_usize(m.track_name.len()).encode_moqt::<Wire>(buf);
                buf.put_slice(&m.track_name);
                encode_parameters(&m.parameters, buf)?;
            }
            ControlMessage::PublishSkipped(m) => {
                m.namespace_suffix.validate_moqt()?;
                check_track_name(&m.track_name)?;
                check_full_track_name(&m.namespace_suffix, &m.track_name)?;
                m.namespace_suffix.encode_moqt::<Wire>(buf);
                VarInt::from_usize(m.track_name.len()).encode_moqt::<Wire>(buf);
                buf.put_slice(&m.track_name);
            }
        }
        Ok(())
    }

    fn decode_body(msg_type: MessageType, buf: &mut impl Buf) -> Result<Self, CodecError> {
        match msg_type {
            MessageType::Setup => {
                let options = decode_setup_options(buf)?;
                Ok(ControlMessage::Setup(Setup { options }))
            }
            MessageType::GoAway => {
                let uri_len = VarInt::decode_moqt::<Wire>(buf)?.into_inner() as usize;
                // Draft-23 Section 9.2: "The maximum length of the New Session
                // URI is 8,192 bytes. If an endpoint receives a length
                // exceeding the maximum, it MUST close the session with
                // FIELD_LENGTH_EXCEEDED."
                if uri_len > MAX_GOAWAY_URI_LENGTH {
                    return Err(CodecError::GoAwayUriTooLong);
                }
                let uri = read_bytes(buf, uri_len)?;
                let timeout = VarInt::decode_moqt::<Wire>(buf)?;
                Ok(ControlMessage::GoAway(GoAway { new_session_uri: uri, timeout }))
            }
            MessageType::RequestOk => {
                let parameters = decode_parameters(buf)?;
                let track_properties = decode_track_properties(buf)?;
                Ok(ControlMessage::RequestOk(RequestOk { parameters, track_properties }))
            }
            MessageType::RequestError => {
                let error_code = VarInt::decode_moqt::<Wire>(buf)?;
                let retry_interval = VarInt::decode_moqt::<Wire>(buf)?;
                let reason_len = VarInt::decode_moqt::<Wire>(buf)?.into_inner() as usize;
                // Draft-23 Section 8.5: "If an endpoint receives a length
                // exceeding the maximum, it MUST close the session with
                // FIELD_LENGTH_EXCEEDED."
                if reason_len > MAX_REASON_PHRASE_LENGTH {
                    return Err(CodecError::ReasonPhraseTooLong);
                }
                let reason_phrase = read_bytes(buf, reason_len)?;
                // Section 9.4.1: "Error Details: Structured information about
                // the error, serialized as Key-Value-Pairs (Figure 4) spanning
                // the remainder of the message, bounded by the message Length
                // field."
                let error_details = decode_kvp_delta(buf)?;
                let m = RequestError { error_code, retry_interval, reason_phrase, error_details };
                check_error_details(&m)?;
                Ok(ControlMessage::RequestError(m))
            }
            MessageType::Subscribe => {
                let request_id = VarInt::decode_moqt::<Wire>(buf)?;
                let track_namespace = TrackNamespace::decode_moqt::<Wire>(buf)?;
                let tn_len = VarInt::decode_moqt::<Wire>(buf)?.into_inner() as usize;
                let track_name = read_bytes(buf, tn_len)?;
                check_full_track_name(&track_namespace, &track_name)?;
                let parameters = decode_parameters(buf)?;
                check_track_name(&track_name)?;
                Ok(ControlMessage::Subscribe(Subscribe {
                    request_id,
                    track_namespace,
                    track_name,
                    parameters,
                }))
            }
            MessageType::SubscribeOk => {
                let track_alias = VarInt::decode_moqt::<Wire>(buf)?;
                let parameters = decode_parameters(buf)?;
                let track_properties = decode_track_properties(buf)?;
                Ok(ControlMessage::SubscribeOk(SubscribeOk {
                    track_alias,
                    parameters,
                    track_properties,
                }))
            }
            MessageType::RequestUpdate => {
                let request_id = VarInt::decode_moqt::<Wire>(buf)?;
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::RequestUpdate(RequestUpdate { request_id, parameters }))
            }
            MessageType::Publish => {
                let request_id = VarInt::decode_moqt::<Wire>(buf)?;
                let track_namespace = TrackNamespace::decode_moqt::<Wire>(buf)?;
                let tn_len = VarInt::decode_moqt::<Wire>(buf)?.into_inner() as usize;
                let track_name = read_bytes(buf, tn_len)?;
                let track_alias = VarInt::decode_moqt::<Wire>(buf)?;
                check_full_track_name(&track_namespace, &track_name)?;
                let parameters = decode_parameters(buf)?;
                let track_properties = decode_track_properties(buf)?;
                check_track_name(&track_name)?;
                Ok(ControlMessage::Publish(Publish {
                    request_id,
                    track_namespace,
                    track_name,
                    track_alias,
                    parameters,
                    track_properties,
                }))
            }
            MessageType::PublishStateNotify => {
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::PublishStateNotify(PublishStateNotify { parameters }))
            }
            MessageType::PublishDone => {
                // Carried whatever it is; see [`PublishDone::status_code`].
                let status_code = VarInt::decode_moqt::<Wire>(buf)?;
                let stream_count = VarInt::decode_moqt::<Wire>(buf)?;
                let reason_len = VarInt::decode_moqt::<Wire>(buf)?.into_inner() as usize;
                // Draft-23 Section 8.5, as for REQUEST_ERROR above.
                if reason_len > MAX_REASON_PHRASE_LENGTH {
                    return Err(CodecError::ReasonPhraseTooLong);
                }
                let reason_phrase = read_bytes(buf, reason_len)?;
                Ok(ControlMessage::PublishDone(PublishDone {
                    status_code,
                    stream_count,
                    reason_phrase,
                }))
            }
            MessageType::PublishNamespace => {
                let request_id = VarInt::decode_moqt::<Wire>(buf)?;
                let track_namespace = TrackNamespace::decode_moqt::<Wire>(buf)?;
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::PublishNamespace(PublishNamespace {
                    request_id,
                    track_namespace,
                    parameters,
                }))
            }
            MessageType::Namespace => {
                let namespace_suffix = TrackNamespace::decode_allow_empty_moqt::<Wire>(buf)?;
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::Namespace(Namespace { namespace_suffix, parameters }))
            }
            MessageType::NamespaceDone => {
                let namespace_suffix = TrackNamespace::decode_allow_empty_moqt::<Wire>(buf)?;
                Ok(ControlMessage::NamespaceDone(NamespaceDone { namespace_suffix }))
            }
            MessageType::SubscribeNamespace => {
                let request_id = VarInt::decode_moqt::<Wire>(buf)?;
                let namespace_prefix = TrackNamespace::decode_allow_empty_moqt::<Wire>(buf)?;
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::SubscribeNamespace(SubscribeNamespace {
                    request_id,
                    namespace_prefix,
                    parameters,
                }))
            }
            MessageType::SubscribeTracks => {
                let request_id = VarInt::decode_moqt::<Wire>(buf)?;
                let namespace_prefix = TrackNamespace::decode_allow_empty_moqt::<Wire>(buf)?;
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::SubscribeTracks(SubscribeTracks {
                    request_id,
                    namespace_prefix,
                    parameters,
                }))
            }
            MessageType::TrackStatus => {
                let request_id = VarInt::decode_moqt::<Wire>(buf)?;
                let track_namespace = TrackNamespace::decode_moqt::<Wire>(buf)?;
                let tn_len = VarInt::decode_moqt::<Wire>(buf)?.into_inner() as usize;
                let track_name = read_bytes(buf, tn_len)?;
                check_full_track_name(&track_namespace, &track_name)?;
                let parameters = decode_parameters(buf)?;
                check_track_name(&track_name)?;
                Ok(ControlMessage::TrackStatus(TrackStatus {
                    request_id,
                    track_namespace,
                    track_name,
                    parameters,
                }))
            }
            MessageType::Fetch => {
                let request_id = VarInt::decode_moqt::<Wire>(buf)?;
                let track_namespace = TrackNamespace::decode_moqt::<Wire>(buf)?;
                let tn_len = VarInt::decode_moqt::<Wire>(buf)?.into_inner() as usize;
                let track_name = read_bytes(buf, tn_len)?;
                check_full_track_name(&track_namespace, &track_name)?;
                let parameters = decode_parameters(buf)?;
                check_track_name(&track_name)?;
                Ok(ControlMessage::Fetch(Fetch {
                    request_id,
                    track_namespace,
                    track_name,
                    parameters,
                }))
            }
            MessageType::PublishSkipped => {
                let namespace_suffix = TrackNamespace::decode_allow_empty_moqt::<Wire>(buf)?;
                let tn_len = VarInt::decode_moqt::<Wire>(buf)?.into_inner() as usize;
                let track_name = read_bytes(buf, tn_len)?;
                check_track_name(&track_name)?;
                check_full_track_name(&namespace_suffix, &track_name)?;
                Ok(ControlMessage::PublishSkipped(PublishSkipped { namespace_suffix, track_name }))
            }
        }
    }

    pub fn message_type(&self) -> MessageType {
        match self {
            ControlMessage::Setup(_) => MessageType::Setup,
            ControlMessage::GoAway(_) => MessageType::GoAway,
            ControlMessage::RequestOk(_) => MessageType::RequestOk,
            ControlMessage::RequestError(_) => MessageType::RequestError,
            ControlMessage::Subscribe(_) => MessageType::Subscribe,
            ControlMessage::SubscribeOk(_) => MessageType::SubscribeOk,
            ControlMessage::RequestUpdate(_) => MessageType::RequestUpdate,
            ControlMessage::Publish(_) => MessageType::Publish,
            ControlMessage::PublishStateNotify(_) => MessageType::PublishStateNotify,
            ControlMessage::PublishDone(_) => MessageType::PublishDone,
            ControlMessage::PublishNamespace(_) => MessageType::PublishNamespace,
            ControlMessage::Namespace(_) => MessageType::Namespace,
            ControlMessage::NamespaceDone(_) => MessageType::NamespaceDone,
            ControlMessage::SubscribeNamespace(_) => MessageType::SubscribeNamespace,
            ControlMessage::SubscribeTracks(_) => MessageType::SubscribeTracks,
            ControlMessage::TrackStatus(_) => MessageType::TrackStatus,
            ControlMessage::Fetch(_) => MessageType::Fetch,
            ControlMessage::PublishSkipped(_) => MessageType::PublishSkipped,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Frame `body` as a draft-23 control message of `type_id`, declaring
    /// `declared_len` as its vi64 Message Length.
    fn frame_with_declared_len(type_id: u64, declared_len: u64, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        VarInt::from_u64_moqt(type_id).encode_moqt::<Wire>(&mut out);
        VarInt::from_u64_moqt(declared_len).encode_moqt::<Wire>(&mut out);
        out.put_slice(body);
        out
    }

    fn frame(type_id: u64, body: &[u8]) -> Vec<u8> {
        frame_with_declared_len(type_id, body.len() as u64, body)
    }

    /// A SUBSCRIBE body: request id 1, namespace ("a"), track name "b", and
    /// `params` already encoded.
    fn subscribe_body(params: &[u8]) -> Vec<u8> {
        let mut body = vec![0x01, 0x01, 0x01, b'a', 0x01, b'b'];
        body.extend_from_slice(params);
        body
    }

    fn param(key: u64, value: &[u8]) -> KeyValuePair {
        KeyValuePair { key: VarInt::from_u64_moqt(key), value: KvpValue::Bytes(value.to_vec()) }
    }

    fn varint_pair(key: u64, value: u64) -> KeyValuePair {
        KeyValuePair {
            key: VarInt::from_u64_moqt(key),
            value: KvpValue::Varint(VarInt::from_u64_moqt(value)),
        }
    }

    /// Section 9, Figure 6: "Message Length (vi64)". An empty REQUEST_OK is
    /// `07 01 00`.
    #[test]
    fn the_message_length_is_a_vi64() {
        let msg = ControlMessage::RequestOk(RequestOk {
            parameters: Vec::new(),
            track_properties: Vec::new(),
        });
        let mut out = Vec::new();
        msg.encode(&mut out).unwrap();
        assert_eq!(out, [0x07, 0x01, 0x00]);

        // A non-minimal Length is valid (Section 8.1).
        let again = ControlMessage::decode(&mut &[0x07, 0xc0, 0x00, 0x01, 0x00][..]).unwrap();
        assert_eq!(again, msg);

        // Two bytes of 16-bit Length read as a vi64 Length of 0 and a body
        // with no Number of Parameters.
        assert!(matches!(
            ControlMessage::decode(&mut &[0x07, 0x00, 0x01, 0x00][..]),
            Err(CodecError::ControlMessageLengthMismatch { declared: 0, .. })
        ));
    }

    /// Section 9: "If an endpoint receives a control message with a length
    /// larger than its MAX_CONTROL_MESSAGE_SIZE, it MUST close the session with
    /// FIELD_LENGTH_EXCEEDED." The Length alone is enough to refuse it.
    #[test]
    fn a_length_past_the_limit_is_refused_before_the_body_arrives() {
        let mut head = Vec::new();
        VarInt::from_u64_moqt(0x05).encode_moqt::<Wire>(&mut head);
        VarInt::from_u64_moqt(70_000).encode_moqt::<Wire>(&mut head);
        assert_eq!(
            ControlMessage::decode(&mut &head[..]),
            Err(CodecError::ControlMessageExceedsLimit { length: 70_000, limit: 65535 })
        );
        assert_eq!(
            ControlMessage::decode_with_limit(&mut &head[..], 70_000),
            Err(CodecError::UnexpectedEnd)
        );
    }

    /// Section 9: "An endpoint MUST NOT send a control message with a length
    /// larger than the peer's MAX_CONTROL_MESSAGE_SIZE (Section 9.1.8)."
    #[test]
    fn a_body_past_the_peers_limit_is_refused_on_encode() {
        let msg = ControlMessage::GoAway(GoAway {
            new_session_uri: vec![b'u'; 100],
            timeout: VarInt::from_u64_moqt(0),
        });
        let mut out = Vec::new();
        assert_eq!(
            msg.encode_with_limit(&mut out, 50),
            Err(CodecError::ControlMessageExceedsLimit { length: 102, limit: 50 })
        );
        assert!(out.is_empty());
        msg.encode_with_limit(&mut out, 102).unwrap();
    }

    /// Table 5 lists 0x18 as RESERVED.
    #[test]
    fn fetch_ok_is_an_unknown_type() {
        assert_eq!(MessageType::from_id(0x18), None);
        let bytes = frame(0x18, &[0x00, 0x0a, 0x03, 0x00]);
        assert_eq!(
            ControlMessage::decode(&mut &bytes[..]),
            Err(CodecError::UnknownMessageType(0x18))
        );
    }

    /// Draft-23 Section 9: "If the length does not match the length of the
    /// Message Body, the receiver MUST close the session with
    /// MALFORMED_MESSAGE."
    #[test]
    fn a_message_body_shorter_than_the_declared_length_is_refused() {
        let body = subscribe_body(&[0x00]);
        let mut junked = body.clone();
        junked.extend_from_slice(&[0xff, 0xff]);
        let bytes = frame_with_declared_len(0x03, (body.len() + 2) as u64, &junked);

        assert_eq!(
            ControlMessage::decode(&mut &bytes[..]),
            Err(CodecError::ControlMessageLengthMismatch {
                declared: (body.len() + 2),
                detail: "its fields left bytes unread",
            })
        );

        let honest = frame(0x03, &body);
        assert!(ControlMessage::decode(&mut &honest[..]).is_ok());
    }

    /// Draft-23 Section 8.5: "The reason phrase length has a maximum value of
    /// 1024 bytes. If an endpoint receives a length exceeding the maximum, it
    /// MUST close the session with FIELD_LENGTH_EXCEEDED."
    #[test]
    fn an_over_long_reason_phrase_is_refused_on_decode() {
        for (type_id, prefix) in [(0x05u64, vec![0x01, 0x00]), (0x0B, vec![0x01, 0x00])] {
            let mut body = prefix;
            let over = MAX_REASON_PHRASE_LENGTH + 976;
            VarInt::from_usize(over).encode_moqt::<Wire>(&mut body);
            body.extend(std::iter::repeat_n(b'x', over));
            let bytes = frame(type_id, &body);
            assert_eq!(
                ControlMessage::decode(&mut &bytes[..]),
                Err(CodecError::ReasonPhraseTooLong),
                "message type 0x{type_id:x}"
            );
        }
    }

    /// Draft-23 Section 9.2: "The maximum length of the New Session URI is
    /// 8,192 bytes. If an endpoint receives a length exceeding the maximum, it
    /// MUST close the session with FIELD_LENGTH_EXCEEDED."
    #[test]
    fn an_over_long_goaway_uri_is_refused_on_decode() {
        let over = MAX_GOAWAY_URI_LENGTH + 808;
        let mut body = Vec::new();
        VarInt::from_usize(over).encode_moqt::<Wire>(&mut body);
        body.extend(std::iter::repeat_n(b'u', over));
        body.push(0x00);
        let bytes = frame(0x10, &body);
        assert_eq!(ControlMessage::decode(&mut &bytes[..]), Err(CodecError::GoAwayUriTooLong));
    }

    /// GROUP_ORDER allows 1 and 2 (Section 9.19.8) and PAUSED 0 and 1 (Section
    /// 9.19.18). 0x10 is not a draft-23 parameter.
    #[test]
    fn a_uint8_parameter_outside_its_range_is_refused() {
        let cases = [(0x22u8, 7u8, 2u8), (0x11, 2, 1)];
        for (key, bad, good) in cases {
            let bytes = frame(0x03, &subscribe_body(&[0x01, key, bad]));
            assert_eq!(
                ControlMessage::decode(&mut &bytes[..]),
                Err(CodecError::ParameterValueOutOfRange { key: key as u64, value: bad as u64 }),
                "parameter 0x{key:x} value {bad}"
            );
            let bytes = frame(0x03, &subscribe_body(&[0x01, key, good]));
            assert!(ControlMessage::decode(&mut &bytes[..]).is_ok(), "0x{key:x} = {good}");
        }
        let bytes = frame(0x03, &subscribe_body(&[0x01, 0x10, 0x01]));
        assert_eq!(
            ControlMessage::decode(&mut &bytes[..]),
            Err(CodecError::UnknownMessageParameter(0x10))
        );
    }

    #[test]
    fn subscriber_priority_still_accepts_the_whole_byte_range() {
        for value in [0u8, 1, 2, 128, 255] {
            let bytes = frame(0x03, &subscribe_body(&[0x01, 0x20, value]));
            assert!(ControlMessage::decode(&mut &bytes[..]).is_ok(), "priority {value}");
        }
    }

    /// Section 9.19.17: "The LARGEST_OBJECT parameter (Parameter Type 0x9) is
    /// a Location." Two bare varints, no length.
    #[test]
    fn largest_object_is_two_bare_varints() {
        let bytes = frame(0x07, &[0x01, 0x09, 0x0a, 0x03]);
        let msg = ControlMessage::decode(&mut &bytes[..]).expect("spec-correct frame must decode");
        let ControlMessage::RequestOk(ok) = &msg else {
            panic!("expected REQUEST_OK, got {msg:?}")
        };
        assert_eq!(ok.parameters, vec![param(0x09, &[0x0a, 0x03])]);
        let mut out = Vec::new();
        msg.encode(&mut out).expect("re-encode");
        assert_eq!(out, bytes);
    }

    #[test]
    fn a_location_value_that_is_not_two_varints_is_refused_on_encode() {
        for value in [vec![0x0a], vec![0x0a, 0x03, 0x05]] {
            let msg = ControlMessage::RequestOk(RequestOk {
                parameters: vec![param(0x09, &value)],
                track_properties: Vec::new(),
            });
            assert!(msg.encode(&mut Vec::new()).is_err(), "{value:02x?}");
        }
    }

    /// Section 9.19.20: TRACK_NAMESPACE_PREFIX "uses the Track Namespace
    /// encoding described in Section 8.7". No outer length.
    #[test]
    fn track_namespace_prefix_is_a_bare_track_namespace() {
        let namespace: Vec<u8> = [&[0x02, 0x04][..], b"live", &[0x06][..], b"sports"].concat();
        let body: Vec<u8> = [&[0x07, 0x01, 0x34][..], &namespace].concat();
        let bytes = frame(0x02, &body);
        let msg = ControlMessage::decode(&mut &bytes[..]).expect("spec-correct frame must decode");
        let ControlMessage::RequestUpdate(update) = &msg else { panic!("{msg:?}") };
        assert_eq!(update.parameters, vec![param(0x34, &namespace)]);
        let mut out = Vec::new();
        msg.encode(&mut out).unwrap();
        assert_eq!(out, bytes);
    }

    /// Section 9.19.15: "Its value is a Number of Parameters (vi64) followed by
    /// that many Parameters". `23 02 0A 81 F4 17 01 01` is FILL_TIMEOUT 500 and
    /// a relative-start LOCATION_FILTER, and the outer chain resumes from 0x23.
    #[test]
    fn fill_parameters_is_a_count_and_no_length() {
        let params = [0x03, 0x21, 0x05, 0x02, 0x02, 0x0A, 0x81, 0xF4, 0x17, 0x01, 0x01, 0x0F, 0x40];
        let bytes = frame(0x03, &subscribe_body(&params));
        let msg = ControlMessage::decode(&mut &bytes[..]).expect("decodes");
        let ControlMessage::Subscribe(sub) = &msg else { panic!("{msg:?}") };
        assert_eq!(sub.parameters.len(), 3);
        assert_eq!(sub.parameters[1].key.into_inner(), FILL_PARAMETERS);
        assert_eq!(sub.parameters[2], varint_pair(0x32, 0x40));
        let KvpValue::Bytes(fill) = &sub.parameters[1].value else { panic!("{sub:?}") };
        let inner = decode_fill_parameters(fill).unwrap();
        assert_eq!(inner[0], varint_pair(0x0A, 500));
        assert_eq!(inner[1], param(0x21, &[0x01, 0x01]));
        let mut out = Vec::new();
        msg.encode(&mut out).unwrap();
        assert_eq!(out, bytes);
    }

    /// FILL_PARAMETERS may appear in PUBLISH and SUBSCRIBE_TRACKS (Section
    /// 9.19.15), and not in FETCH.
    #[test]
    fn fill_parameters_scope() {
        assert!(parameter_in_scope(FILL_PARAMETERS, MessageType::Publish));
        assert!(parameter_in_scope(FILL_PARAMETERS, MessageType::SubscribeTracks));
        assert!(!parameter_in_scope(FILL_PARAMETERS, MessageType::Fetch));
    }

    /// Section 2.4.1: "If an endpoint receives a Track Name with a length of 0,
    /// it MUST close the session with a PROTOCOL_VIOLATION."
    #[test]
    fn an_empty_track_name_is_refused() {
        let bytes = frame(0x03, &[0x02, 0x01, 0x01, b'a', 0x00, 0x00]);
        assert_eq!(ControlMessage::decode(&mut &bytes[..]), Err(CodecError::EmptyTrackName));
        let msg = ControlMessage::Subscribe(Subscribe {
            request_id: VarInt::from_u64_moqt(2),
            track_namespace: TrackNamespace(vec![b"a".to_vec()]),
            track_name: Vec::new(),
            parameters: Vec::new(),
        });
        assert_eq!(msg.encode(&mut Vec::new()), Err(CodecError::EmptyTrackName));
    }

    /// Section 9.15, Figure 20: NAMESPACE ends with a parameter block, and no
    /// parameter definition names NAMESPACE.
    #[test]
    fn namespace_carries_a_parameter_block() {
        let bytes = frame(0x08, &[0x01, 0x01, b'a', 0x00]);
        let msg = ControlMessage::decode(&mut &bytes[..]).unwrap();
        assert_eq!(
            msg,
            ControlMessage::Namespace(Namespace {
                namespace_suffix: TrackNamespace(vec![b"a".to_vec()]),
                parameters: Vec::new(),
            })
        );
        let bytes = frame(0x08, &[0x01, 0x01, b'a', 0x01, 0x08, 0x05]);
        assert_eq!(
            ControlMessage::decode(&mut &bytes[..]),
            Err(CodecError::ParameterOutOfScope { key: 0x08, message_type: 0x08 })
        );
    }

    /// Section 9.4.2.1: a REDIRECT Error Detail is Length-prefixed and MUST be
    /// present under Error Code REDIRECT.
    #[test]
    fn redirect_travels_in_an_error_detail() {
        let bytes = [0x05, 0x0B, 0x34, 0x00, 0x00, 0x01, 0x06, 0x00, 0x01, 0x01, b'a', 0x01, b'b'];
        let msg = ControlMessage::decode(&mut &bytes[..]).unwrap();
        let ControlMessage::RequestError(err) = &msg else { panic!("{msg:?}") };
        let redirect = err.redirect().unwrap().unwrap();
        assert_eq!(redirect.track_name, b"b");
        let mut out = Vec::new();
        msg.encode(&mut out).unwrap();
        assert_eq!(out, bytes);

        assert_eq!(
            ControlMessage::decode(&mut &[0x05, 0x03, 0x34, 0x00, 0x00][..]),
            Err(CodecError::MissingErrorDetail { error_code: 0x34, detail_type: 0x01 })
        );
    }

    /// Section 9.4.2.2: "Multiple instances of this type are allowed."
    #[test]
    fn unsupported_property_details_repeat() {
        let bytes = [0x05, 0x0B, 0x33, 0x00, 0x00, 0x02, 0xC0, 0x40, 0x00, 0x00, 0xC0, 0x40, 0x02];
        let msg = ControlMessage::decode(&mut &bytes[..]).unwrap();
        let ControlMessage::RequestError(err) = &msg else { panic!("{msg:?}") };
        assert_eq!(err.unsupported_properties(), vec![0x4000, 0x4002]);
    }

    /// Section 9.3: Track Properties "are empty in PUBLISH_OK", and PUBLISH_OK
    /// carries EXPIRES alone.
    #[test]
    fn a_request_ok_is_held_to_the_request_it_answers() {
        let ok = RequestOk {
            parameters: vec![param(0x09, &[0x0a, 0x03])],
            track_properties: vec![varint_pair(0x30, 1)],
        };
        assert!(ok.check_answers(RequestOkKind::Fetch).is_ok());
        assert!(ok.check_answers(RequestOkKind::TrackStatus).is_ok());
        assert!(matches!(
            ok.check_answers(RequestOkKind::Publish),
            Err(CodecError::ParameterOutOfScope { key: 0x09, .. })
        ));
        let ok = RequestOk { parameters: Vec::new(), track_properties: vec![varint_pair(0x30, 1)] };
        assert_eq!(
            ok.check_answers(RequestOkKind::RequestUpdate),
            Err(CodecError::TrackPropertiesNotPermitted)
        );
    }

    /// Section 9.1.8: odd Option Type 0x09 carrying one varint behind a
    /// Length, at least 65535.
    #[test]
    fn max_control_message_size_is_one_varint_behind_a_length() {
        let bytes = [0xAF, 0x00, 0x05, 0x09, 0x03, 0xC0, 0xFF, 0xFF];
        let msg = ControlMessage::decode(&mut &bytes[..]).unwrap();
        let ControlMessage::Setup(setup) = &msg else { panic!("{msg:?}") };
        assert_eq!(setup.max_control_message_size(), Ok(65535));

        let short = Setup { options: vec![param(0x09, &encode_max_control_message_size(1000))] };
        assert_eq!(
            ControlMessage::Setup(short).encode(&mut Vec::new()),
            Err(CodecError::InvalidField)
        );

        let two = [0xAF, 0x00, 0x04, 0x09, 0x02, 0x01, 0x02];
        assert!(matches!(
            ControlMessage::decode(&mut &two[..]),
            Err(CodecError::KeyValueFormatting { key: 0x09, .. })
        ));
    }

    /// Section 10.4: "If an endpoint receives a value above 255, it MUST close
    /// the session with MALFORMED_KEY_VALUE."
    #[test]
    fn default_publisher_priority_above_255_is_refused() {
        let bytes = frame(0x07, &[0x00, 0x0E, 0x81, 0x00]);
        assert_eq!(
            ControlMessage::decode(&mut &bytes[..]),
            Err(CodecError::TrackPropertyValueOutOfRange { key: 0x0E, value: 256 })
        );
    }

    /// Section 12.2: "When more than one code applies, an endpoint uses
    /// DELTA_ENCODING_OVERFLOW or FIELD_LENGTH_EXCEEDED in preference to the
    /// other codes." An empty Track Name (PROTOCOL_VIOLATION) followed by a
    /// Parameter Type delta that overflows is refused for the overflow, on
    /// each message that carries both.
    #[test]
    fn an_overflow_after_an_empty_track_name_is_the_one_reported() {
        // Namespace ("a"), empty Track Name.
        let name = [0x01, 0x01, 0x61, 0x00];
        // SUBSCRIBER_PRIORITY (0x20) of 0x80, then a delta of 2^64-1.
        let mut params = vec![0x02, 0x20, 0x80];
        VarInt::from_u64_moqt(u64::MAX).encode_moqt::<Wire>(&mut params);
        for (ty, alias) in [(0x03u64, false), (0x1D, true), (0x0D, false), (0x16, false)] {
            let mut body = vec![0x00];
            body.extend_from_slice(&name);
            if alias {
                body.push(0x07);
            }
            body.extend_from_slice(&params);
            let mut bytes = Vec::new();
            VarInt::from_u64_moqt(ty).encode_moqt::<Wire>(&mut bytes);
            VarInt::from_usize(body.len()).encode_moqt::<Wire>(&mut bytes);
            bytes.extend_from_slice(&body);
            assert!(
                matches!(
                    ControlMessage::decode(&mut &bytes[..]),
                    Err(CodecError::KeyDeltaOverflow(0x20, u64::MAX))
                ),
                "message type {ty:#x}"
            );
        }
    }

    /// A SETUP's Alias references, scanned in wire order against the
    /// REGISTERs before them in the same SETUP.
    #[test]
    fn setup_alias_references_are_told_apart_by_registration() {
        let token = |bytes: &[u8]| param(AUTH_TOKEN_PARAMETER, bytes);
        let register = |alias: u8| token(&[0x01, alias, 0x00, b't']);
        let delete = |alias: u8| token(&[0x00, alias]);
        let use_alias = |alias: u8| token(&[0x02, alias]);
        let use_value = token(&[0x03, 0x00, b't']);
        let unregistered = |alias_type, alias| {
            Err(CodecError::UnregisteredTokenAliasInSetup { alias_type, alias })
        };
        let registered = |alias_type| Err(CodecError::TokenAliasInSetup { alias_type });

        assert_eq!(check_setup_token_aliases(&[register(1), use_value.clone()]), Ok(()));
        assert_eq!(check_setup_token_aliases(&[delete(0)]), unregistered(0, 0));
        assert_eq!(check_setup_token_aliases(&[use_alias(7)]), unregistered(2, 7));
        assert_eq!(check_setup_token_aliases(&[register(1), use_alias(2)]), unregistered(2, 2));
        // A reference ahead of its REGISTER is not registered yet.
        assert_eq!(check_setup_token_aliases(&[use_alias(1), register(1)]), unregistered(2, 1));
        assert_eq!(check_setup_token_aliases(&[register(1), use_alias(1)]), registered(2));
        assert_eq!(check_setup_token_aliases(&[register(1), delete(1)]), registered(0));
        // DELETE retires the Alias, so a later reference to it is unregistered.
        assert_eq!(
            check_setup_token_aliases(&[register(1), delete(1), use_alias(1)]),
            unregistered(2, 1)
        );
        // A later unregistered reference outranks an earlier registered one.
        assert_eq!(
            check_setup_token_aliases(&[register(1), use_alias(1), use_alias(3)]),
            unregistered(2, 3)
        );
    }
}

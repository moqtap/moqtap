//! Draft-17 control message encoding and decoding.
//!
//! Key differences from draft-16:
//! - Framing: Type (varint) + Length (16-bit fixed) + Payload.
//! - Unified SETUP (0x2F00) with delta-encoded KVP options (even/odd).
//! - Parameters: count-prefixed, delta-encoded types, type-specific value encoding.
//! - RequestOk/RequestError/PublishOk/PublishDone/FetchOk: no request_id.
//! - Request messages gain required_request_id_delta.
//! - New: PublishBlocked. FetchType gains AbsoluteJoining.
//! - SubscribeOk/Publish/FetchOk gain track_properties after parameters.
//! - Removed: ClientSetup, ServerSetup, MaxRequestId, RequestsBlocked, Unsubscribe,
//!   PublishNamespaceDone, PublishNamespaceCancel, FetchCancel.

use crate::auth_token::{AuthorizationToken, AUTH_TOKEN_PARAMETER};
use crate::error::MAX_FULL_TRACK_NAME_LENGTH;
pub use crate::error::{
    CodecError, MAX_GOAWAY_URI_LENGTH, MAX_MESSAGE_LENGTH, MAX_NAMESPACE_TUPLE_SIZE,
    MAX_REASON_PHRASE_LENGTH,
};
use crate::kvp::{KeyValuePair, KvpError, KvpValue, MAX_KVP_VALUE_LEN};
use crate::subscription_filter::{SubscriptionFilter, SUBSCRIPTION_FILTER_PARAMETER};
use crate::types::check_location_range;
use crate::types::*;
use crate::varint::{Moqt17 as Wire, VarInt};
use bytes::{Buf, BufMut};

// ============================================================
// Parameter encoding helpers for draft-17
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
}

fn param_encoding(key: u64) -> Option<ParamEncoding> {
    match key {
        // 0x02 = DELIVERY_TIMEOUT
        // 0x04 = RENDEZVOUS_TIMEOUT (draft-17 Section 9.3.4). Not
        //        MAX_CACHE_DURATION: that is Property Type 0x04 in the
        //        separate Properties registry (Table 12), a different
        //        namespace that happens to reuse the number.
        // 0x08 = EXPIRES, 0x32 = NEW_GROUP_REQUEST
        0x02 | 0x04 | 0x08 | 0x32 => Some(ParamEncoding::Varint),
        // 0x10 = FORWARD, 0x20 = SUBSCRIBER_PRIORITY, 0x22 = GROUP_ORDER
        0x10 | 0x20 | 0x22 => Some(ParamEncoding::Uint8),
        // 0x09 = LARGEST_OBJECT. Draft-17 Section 9.3.9: "The LARGEST_OBJECT
        //        parameter (Parameter Type 0x9) is a Location." A Location is
        //        two consecutive varints, with no length ahead of them.
        0x09 => Some(ParamEncoding::Location),
        // 0x03 = AUTHORIZATION_TOKEN, 0x21 = SUBSCRIPTION_FILTER
        0x03 | 0x21 => Some(ParamEncoding::LengthPrefixed),
        _ => None,
    }
}

/// The one parameter type draft-17 lets a message carry more than once.
///
/// Section 9.3.2: "The AUTHORIZATION TOKEN parameter MAY be repeated within a
/// message as long as the combination of Token Type and Token Value are unique
/// after resolving any aliases." Every other type is subject to the blanket rule
/// in Section 9.3.
const AUTHORIZATION_TOKEN: u64 = 0x03;

/// Whether `value` is inside the range draft-17 allows for a uint8-valued
/// parameter.
///
/// Two of the three uint8 parameters restrict their range and say the receiver
/// MUST close the session with PROTOCOL_VIOLATION on anything outside it:
/// GROUP_ORDER allows only Ascending (0x1) and Descending (0x2) (Section
/// 9.3.6), and FORWARD allows only 0 and 1 (Section 9.3.10).
/// SUBSCRIBER_PRIORITY (Section 9.3.5) uses the whole 0-255 range, so it has no
/// entry here.
///
/// Range-checking on decode is what makes the values usable: an application
/// that tests `group_order == 2` for descending would otherwise treat 7 as
/// neither ascending nor descending and carry on.
fn uint8_value_in_range(key: u64, value: u8) -> bool {
    match key {
        // FORWARD (0x10)
        0x10 => value <= 1,
        // GROUP_ORDER (0x22)
        0x22 => value == 1 || value == 2,
        _ => true,
    }
}

/// Add a delta to the previous delta-encoded key.
///
/// Draft-17 Section 1.4.3: "The previous Type value plus the Delta Type MUST NOT
/// be greater than 2^64 - 1. If a Delta Type is received that would be too
/// large, the Session MUST be closed with a PROTOCOL_VIOLATION." MoQT varints
/// span the whole 64-bit range, so a peer can drive the sum past the end: a
/// debug build panicked on the addition and a release build wrapped the key and
/// reported the parameter under a type its sender never wrote.
fn add_delta(prev_key: u64, delta: u64) -> Result<u64, CodecError> {
    prev_key.checked_add(delta).ok_or(CodecError::KeyDeltaOverflow(prev_key, delta))
}

/// Hold a namespace-plus-name pair to the Full Track Name cap.
///
/// Draft-17 Section 2.4.1: "The maximum total length of a Full Track Name is
/// 4,096 bytes. The length of a Full Track Name is computed as the sum of the
/// Track Namespace Field Length fields and the Track Name Length field... If an
/// endpoint receives a Track Namespace or a Full Track Name exceeding 4,096
/// bytes, it MUST close the session with a PROTOCOL_VIOLATION."
///
/// The namespace half of that sentence is enforced inside the namespace decoder,
/// which is the only place that sees a namespace with no name beside it. This is
/// the other half, and it has to live where the two are decoded together: a
/// namespace at 4,000 bytes and a name at 500 are each legal alone.
///
/// A control message can be 65,535 bytes, so without this a peer can hand the
/// application a Full Track Name sixteen times the permitted size — and two
/// relays that disagree about whether it was legal disagree about cache
/// identity.
fn check_full_track_name(namespace: &TrackNamespace, track_name: &[u8]) -> Result<(), CodecError> {
    let total = namespace.field_bytes_len().saturating_add(track_name.len());
    if total > MAX_FULL_TRACK_NAME_LENGTH {
        return Err(CodecError::TrackNameTooLong);
    }
    Ok(())
}

/// Hold a request message's Required Request ID Delta to the bound its own
/// Request ID sets.
///
/// Draft-17 Section 9.2: "The Required Request ID is computed as: Required
/// Request ID = Request ID - (2 x Required Request ID Delta)... An endpoint MUST
/// close the session with INVALID_REQUIRED_REQUEST_ID if it receives a delta
/// where 2 x Required Request ID Delta exceeds the Request ID."
///
/// Both operands travel in the same message, so this is the one Required Request
/// ID rule the codec can settle without any session state. Left unchecked, the
/// subtraction underflows and any consumer computing the dependency gets a
/// wrapped id rather than a session close. Draft-18 removed the field, so this
/// is draft-17 only.
fn check_required_request_id_delta(request_id: VarInt, delta: VarInt) -> Result<(), CodecError> {
    let id = request_id.into_inner();
    let scaled = delta.into_inner().checked_mul(2);
    match scaled {
        Some(scaled) if scaled <= id => Ok(()),
        _ => Err(CodecError::InvalidRequiredRequestIdDelta(id, delta.into_inner())),
    }
}

/// Hold every AUTHORIZATION TOKEN parameter to the Token structure it names.
///
/// Section 9.3.2: "If the Token structure cannot be decoded, the receiver
/// MUST close the Session with KEY_VALUE_FORMATTING_ERROR." That is the answer
/// Section 1.4.3 gives for any Type whose value does not match the
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
                AuthorizationToken::decode_moqt::<Wire>(key, value)?;
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
/// Section 5.1.2: "An endpoint that receives a filter type other than the above
/// MUST close the session with PROTOCOL_VIOLATION." Section 9.3.7: "The
/// SUBSCRIPTION_FILTER parameter (Parameter Type 0x21) uses length-prefixed
/// encoding... It is a Subscription Filter."
///
/// This draft dropped the sentence drafts 15 and 16 wrote about the length,
/// draft-16 Section 9.2.2.5 — "If the length of the Subscription Filter does
/// not match the parameter length, the publisher MUST close the session with
/// PROTOCOL_VIOLATION" — and leaves the general rule of Section 1.4.3, which
/// answers a value that is not the serialization its Type defines with
/// KEY_VALUE_FORMATTING_ERROR. Same malformation, different code, and the
/// session table is where the two part.
///
/// The End Group is a delta on this draft rather than a group written out, and
/// nothing here resolves it. Drafts 18 and 19 answer a sum that leaves the
/// 64-bit range with a close; this draft, which introduced the delta, states no
/// such sentence, so a filter whose end cannot be represented is carried and the
/// caller resolving it decides what to do.
///
/// The filter is decoded and discarded. What is kept is the refusal — the value
/// stays on the parameter as the bytes that arrived, so a caller reads it
/// through [`SubscriptionFilter::decode_moqt`] when it wants the filter rather
/// than the frame.
fn check_subscription_filters(parameters: &[KeyValuePair]) -> Result<(), CodecError> {
    for parameter in parameters {
        if parameter.key.into_inner() != SUBSCRIPTION_FILTER_PARAMETER {
            continue;
        }
        match &parameter.value {
            KvpValue::Bytes(value) => {
                SubscriptionFilter::decode_moqt::<Wire>(value)?;
            }
            // Unreachable from the decoder, which picks the shape from the type
            // and finds this one length-prefixed. A caller that built the pair
            // in memory can still get here, and it is the same rule.
            KvpValue::Varint(_) => {
                return Err(CodecError::SubscriptionFilterMalformed {
                    detail: "its value is a bare varint where the type defines a filter",
                });
            }
        }
    }
    Ok(())
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
        // parameter before it. Draft-17 Section 9.3: "Receivers SHOULD check
        // that there are no unexpected duplicate parameters and close the
        // session with PROTOCOL_VIOLATION if found." Downstream code that scans
        // the list for a key takes whichever copy it meets first, so two
        // implementations reading one frame can pick opposite values.
        if i > 0 && delta == 0 && abs_key != AUTHORIZATION_TOKEN {
            return Err(CodecError::DuplicateParameter(abs_key));
        }
        prev_key = abs_key;

        // Section 9.3: "All Message Parameters MUST be defined in the
        // negotiated version of MOQT or negotiated via Setup Options. An
        // endpoint that receives an unknown Message Parameter MUST close the
        // session with PROTOCOL_VIOLATION. Because the receiver has to
        // understand every Message Parameter, there is no need for a mechanism
        // to skip unknown parameters."
        //
        // The table this consults is the registry's, so a type it cannot name
        // is one this draft does not define. Reporting it as an ordinary
        // malformation, which is what it did before, left the rule enforced
        // against the frame and invisible to the session.
        let encoding =
            param_encoding(abs_key).ok_or(CodecError::UnknownMessageParameter(abs_key))?;

        let value = match encoding {
            ParamEncoding::Varint => {
                let v = VarInt::decode_moqt::<Wire>(buf)?;
                KvpValue::Varint(v)
            }
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
                let data = read_bytes(buf, len)?;
                KvpValue::Bytes(data)
            }
        };

        params.push(KeyValuePair { key: VarInt::from_u64_moqt(abs_key), value });
    }
    check_authorization_tokens(&params)?;
    check_subscription_filters(&params)?;
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

/// Encode a count-prefixed list of parameters with delta-encoded types.
///
/// Errors on every list [`decode_parameters`] would refuse, so the two
/// directions accept the same set of frames. Three things are refused, and each
/// of them is a frame this codec would otherwise emit and then decline to read
/// back:
///
/// * A list not in ascending order by type. The delta is a difference, so a
///   descending pair wraps the subtraction into a nine-byte delta the peer
///   resolves to an unrelated key.
/// * A repeated type, except AUTHORIZATION_TOKEN (Section 9.3.2).
/// * A uint8-valued parameter whose value does not fit one octet or lies
///   outside the range its definition allows. Truncating instead is the worse
///   outcome: GROUP_ORDER 258 goes out as the byte 0x02, a well-formed
///   Descending indistinguishable on the wire from one the caller meant.
/// * A value under a type that defines a structure which is not that structure:
///   a Token, and a filter. Each is a value the receiver must close the session
///   over, so writing one is not a way to send it — the sender's first sign of
///   trouble would be the session going.
fn encode_parameters(params: &[KeyValuePair], buf: &mut impl BufMut) -> Result<(), CodecError> {
    check_authorization_tokens(params)?;
    check_subscription_filters(params)?;
    VarInt::from_usize(params.len()).encode_moqt::<Wire>(buf);
    let mut prev_key: u64 = 0;

    for (i, p) in params.iter().enumerate() {
        let abs_key = p.key.into_inner();
        let delta = abs_key
            .checked_sub(prev_key)
            .ok_or(CodecError::ParametersOutOfOrder(prev_key, abs_key))?;
        if i > 0 && delta == 0 && abs_key != AUTHORIZATION_TOKEN {
            return Err(CodecError::DuplicateParameter(abs_key));
        }
        prev_key = abs_key;
        VarInt::from_u64_moqt(delta).encode_moqt::<Wire>(buf);

        // The same maximum the decoder below applies, and the same one this
        // draft's Setup Option encoder has always applied: "The maximum length
        // of a value is 2^16-1 bytes. If an endpoint receives a length larger
        // than the maximum, it MUST close the session with a PROTOCOL_VIOLATION."
        // A value past it is one the peer must end the session over, so writing
        // it is not a way to send it.
        //
        // Hoisted above the shape table rather than repeated inside it: a
        // Location is bytes as well, and one past the maximum is not a Location.
        if let KvpValue::Bytes(b) = &p.value {
            if b.len() > MAX_KVP_VALUE_LEN {
                return Err(KvpError::ValueTooLong(b.len()).into());
            }
        }

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
            (KvpValue::Bytes(b), Some(ParamEncoding::Location)) => {
                if !is_location_value(b) {
                    return Err(CodecError::InvalidField);
                }
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
            // Draft-17 Section 1.4.3: "The maximum length of a value is 2^16-1
            // bytes. If an endpoint receives a length larger than the maximum,
            // it MUST close the session with a PROTOCOL_VIOLATION." The
            // standalone `KeyValuePair::decode` already enforces this; stating
            // it here too means the two readers of the same wire shape answer
            // the same way, rather than this one leaning on the caller having
            // clipped the buffer to a control message first.
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
/// Section 11.6: Immutable Properties "contain a sequence of Key-Value-Pairs
/// (see Figure 2) which are also Track or Object Properties". The Type is odd,
/// so its value is length-prefixed bytes, and those bytes are another
/// delta-typed run starting from 0.
const IMMUTABLE_PROPERTIES: u64 = 0x0B;

/// Whether `value` is inside the range draft-17 allows for a Track Property
/// type that restricts one.
///
/// Two types do, and each answers anything outside its range with a session
/// close. DEFAULT_PUBLISHER_GROUP_ORDER (0x22), Section 11.4: "The allowed
/// values are Ascending (0x1) or Descending (0x2). If an endpoint receives a
/// value outside this range, it MUST close the session with
/// PROTOCOL_VIOLATION." DYNAMIC_GROUPS (0x30), Section 11.5: "The allowed
/// values are 0 or 1... If an endpoint receives a value larger than 1, it MUST
/// close the session with PROTOCOL_VIOLATION."
///
/// Both are Track Properties, so the list they arrive in is the one carried by
/// a control message rather than the properties on an object.
///
/// DEFAULT_PUBLISHER_PRIORITY (0x0E) is not here. Section 11.3 says
/// "Priorities above 255 are invalid" and stops, where the two above name a
/// consequence in the next clause. A range stated without one is not a close.
///
/// The numbers belong to the Property registry and not the Message Parameter
/// one. Type 0x22 is GROUP_ORDER as a parameter and
/// DEFAULT_PUBLISHER_GROUP_ORDER as a property, and the two happen to permit the
/// same pair of values while meaning different things — one subscriber's
/// preference against a property of the track. Reading either table for the
/// other's types would be right by accident here and wrong at the next entry.
fn track_property_value_in_range(key: u64, value: u64) -> bool {
    match key {
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
/// contents Section 11.6 defines as properties themselves. The draft asks for
/// this in as many words: "When looking for the value of a property, processors
/// MUST search both the mutable properties and the contents of Immutable
/// Extensions." A check applied only to the outer list is one a peer opts out
/// of by moving a pair inside the block, and the block is where an Original
/// Publisher puts what a relay must not rewrite — which is where a track's
/// group order and dynamic-group support belong.
///
/// Bytes under 0xB that do not parse as a Key-Value-Pair run are left alone
/// rather than refused. Section 11.6 says relays "MAY decode and view the
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
/// Section 9.4.1 assigns PATH, AUTHORIZATION TOKEN, MAX_AUTH_TOKEN_CACHE_SIZE, AUTHORITY and
/// MOQT_IMPLEMENTATION.
///
/// The list exists for one rule and one direction. Section 9.4: "Receivers
/// MUST allow duplicates of unknown Setup Options." A receiver may therefore
/// refuse a repeat only of a type it can name, and an option outside this list
/// is one an extension defined and this codec has no business closing a session
/// over. Nothing else reads it - unknown options are still decoded and carried,
/// as "Receivers MUST ignore unrecognized Setup Options" requires.
const KNOWN_SETUP_OPTIONS: &[u64] = &[0x01, 0x03, 0x04, 0x05, 0x07];

/// The one Setup Option whose definition allows more than one instance.
///
/// Section 9.4.1.4: "The AUTHORIZATION TOKEN Setup Option (Option Type 0x03)
/// is functionally equivalent to the AUTHORIZATION TOKEN message parameter...
/// The endpoint can specify one or more tokens in SETUP that the peer can use to
/// authorize MOQT session establishment." That is the "unless the option
/// definition explicitly allows multiple instances" carve-out, and it is the
/// only one on this draft.
const REPEATABLE_SETUP_OPTION: u64 = 0x03;

/// Decode the Setup Options of a SETUP message.
///
/// Section 9.4: "Senders MUST NOT repeat the same Option Type in a message
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
    Ok(options)
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
fn encode_setup_options(options: &[KeyValuePair], buf: &mut impl BufMut) -> Result<(), CodecError> {
    check_authorization_tokens(options)?;
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
    PublishDone = 0x0B,
    TrackStatus = 0x0D,
    NamespaceDone = 0x0E,
    PublishBlocked = 0x0F,
    GoAway = 0x10,
    SubscribeNamespace = 0x11,
    Fetch = 0x16,
    FetchOk = 0x18,
    Publish = 0x1D,
    PublishOk = 0x1E,
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
            0x0F => Some(MessageType::PublishBlocked),
            0x10 => Some(MessageType::GoAway),
            0x11 => Some(MessageType::SubscribeNamespace),
            0x16 => Some(MessageType::Fetch),
            0x18 => Some(MessageType::FetchOk),
            0x1D => Some(MessageType::Publish),
            0x1E => Some(MessageType::PublishOk),
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
            MessageType::PublishBlocked => "publish_blocked",
            MessageType::GoAway => "goaway",
            MessageType::SubscribeNamespace => "subscribe_namespace",
            MessageType::Fetch => "fetch",
            MessageType::FetchOk => "fetch_ok",
            MessageType::Publish => "publish",
            MessageType::PublishOk => "publish_ok",
            MessageType::Setup => "setup",
        }
    }
}

// ============================================================
// Session Lifecycle Messages
// ============================================================

/// Unified SETUP (0x2F00). Replaces ClientSetup/ServerSetup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setup {
    pub options: Vec<KeyValuePair>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoAway {
    pub new_session_uri: Vec<u8>,
    pub timeout: VarInt,
}

// ============================================================
// Consolidated Response Messages
// ============================================================

/// REQUEST_OK (0x07). No request_id in draft-17.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestOk {
    pub parameters: Vec<KeyValuePair>,
}

/// REQUEST_ERROR (0x05). No request_id in draft-17.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestError {
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
    pub required_request_id_delta: VarInt,
    pub track_namespace: TrackNamespace,
    pub track_name: Vec<u8>,
    pub parameters: Vec<KeyValuePair>,
}

/// SUBSCRIBE_OK (0x04). No request_id in draft-17. Gains track_properties.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeOk {
    pub track_alias: VarInt,
    pub parameters: Vec<KeyValuePair>,
    pub track_properties: Vec<KeyValuePair>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestUpdate {
    pub request_id: VarInt,
    pub required_request_id_delta: VarInt,
    pub parameters: Vec<KeyValuePair>,
}

// ============================================================
// Publish Messages
// ============================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publish {
    pub request_id: VarInt,
    pub required_request_id_delta: VarInt,
    pub track_namespace: TrackNamespace,
    pub track_name: Vec<u8>,
    pub track_alias: VarInt,
    pub parameters: Vec<KeyValuePair>,
    pub track_properties: Vec<KeyValuePair>,
}

/// PUBLISH_OK (0x1E). No request_id in draft-17.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishOk {
    pub parameters: Vec<KeyValuePair>,
}

/// PUBLISH_DONE (0x0B). No request_id in draft-17.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishDone {
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
    pub required_request_id_delta: VarInt,
    pub track_namespace: TrackNamespace,
    pub parameters: Vec<KeyValuePair>,
}

// ============================================================
// Namespace Messages
// ============================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Namespace {
    pub namespace_suffix: TrackNamespace,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceDone {
    pub namespace_suffix: TrackNamespace,
}

// ============================================================
// Subscribe Namespace Messages
// ============================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeNamespace {
    pub request_id: VarInt,
    pub required_request_id_delta: VarInt,
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
    pub required_request_id_delta: VarInt,
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
    pub required_request_id_delta: VarInt,
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

/// FETCH_OK (0x18). No request_id in draft-17. end_of_track is uint8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchOk {
    pub end_of_track: u8,
    pub end_group: VarInt,
    pub end_object: VarInt,
    pub parameters: Vec<KeyValuePair>,
    pub track_properties: Vec<KeyValuePair>,
}

// ============================================================
// Publish Blocked (new in draft-17)
// ============================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishBlocked {
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
    PublishOk(PublishOk),
    PublishDone(PublishDone),
    PublishNamespace(PublishNamespace),
    Namespace(Namespace),
    NamespaceDone(NamespaceDone),
    SubscribeNamespace(SubscribeNamespace),
    TrackStatus(TrackStatus),
    Fetch(Fetch),
    FetchOk(FetchOk),
    PublishBlocked(PublishBlocked),
}

/// Refuse a FETCH whose range ends before it starts.
///
/// Section 9.14.3: "Fetch specifies an inclusive range of Objects starting at
/// Start Location and ending at End Location. End Location MUST specify the
/// same or a larger Location than Start Location for Standalone and Absolute Joining Fetches." A Joining Fetch names
/// no explicit range - it is computed from the subscription it joins - so only
/// a standalone range is checked here.
///
/// SUBSCRIBE is not checked here, and needs no check: this draft's
/// AbsoluteRange filter carries an End Group Delta measured from the start
/// location rather than an absolute End Group, so an end before the start
/// has no encoding.
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
/// One draft-17 message carries a field that says which of the following fields
/// are on the wire: FETCH's Fetch Type. This codec holds the alternatives in an
/// enum of its own, [`FetchPayload`], so a value can say one thing in its
/// discriminator and another in its body, and the two sides of the codec
/// resolve that differently — the encoder writes whatever the body holds, and
/// the decoder reads whatever the discriminator announces.
///
/// The result is a message that does not survive its own round trip. A FETCH
/// whose type says Standalone and whose body is a joining pair encodes to a
/// joining request id and a joining start where a Track Namespace and a Track
/// Name belong, and comes back as a Standalone fetch of a track named after two
/// integers — or, more often, as an error, which at least is honest. Refusing
/// at the encoder keeps the two readings from ever diverging on the wire.
///
/// The two joining types share one body shape, so the check is between
/// Standalone and everything else rather than one arm per type.
fn check_discriminators(message: &ControlMessage) -> Result<(), CodecError> {
    if let ControlMessage::Fetch(m) = message {
        let body_is_standalone = matches!(m.fetch_payload, FetchPayload::Standalone { .. });
        if body_is_standalone != (m.fetch_type == FetchType::Standalone) {
            return Err(CodecError::InvalidField);
        }
    }
    Ok(())
}

/// Whether draft-17 lets Message Parameter `key` appear in `message`.
///
/// Section 9.3.1: "Each Message Parameter definition indicates the message
/// types in which it can appear. If it appears in some other type of message,
/// the receiving endpoint MUST close the connection with a PROTOCOL_VIOLATION."
/// One arm per entry in the Message Parameters registry (Section 14.3),
/// carrying the message types that entry's own subsection names.
///
/// Where a name is qualified, the qualifier describes one of the destinations
/// rather than adding another. LARGEST_OBJECT "MAY appear in SUBSCRIBE_OK,
/// PUBLISH or in REQUEST_OK (in response to REQUEST_UPDATE or TRACK_STATUS)"
/// names three message types, and drafts 18 and 19 write that same rule as
/// SUBSCRIBE_OK, PUBLISH, REQUEST_UPDATE_OK and TRACK_STATUS_OK once those
/// responses have names of their own.
///
/// FETCH_OK has no arm in the table below, and that is the draft's doing rather
/// than an omission here: Section 9.15 gives it a Parameters field and no
/// parameter definition names it, so every type this draft defines is "some
/// other type of message" there.
///
/// The table decides scope only. A type this draft does not define has no scope
/// to be outside of and is answered by [`CodecError::UnknownMessageParameter`],
/// which is why the final arm carries rather than refuses.
fn parameter_in_scope(key: u64, message: MessageType) -> bool {
    use MessageType as M;
    match key {
        // Section 9.3.3 DELIVERY TIMEOUT: "It MAY appear in a PUBLISH_OK,
        // SUBSCRIBE, or REQUEST_UPDATE message."
        0x02 => matches!(message, M::PublishOk | M::Subscribe | M::RequestUpdate),
        // Section 9.3.2 AUTHORIZATION TOKEN: "It MAY appear in a PUBLISH,
        // SUBSCRIBE, REQUEST_UPDATE, SUBSCRIBE_NAMESPACE, PUBLISH_NAMESPACE,
        // TRACK_STATUS or FETCH message."
        0x03 => matches!(
            message,
            M::Publish
                | M::Subscribe
                | M::RequestUpdate
                | M::SubscribeNamespace
                | M::PublishNamespace
                | M::TrackStatus
                | M::Fetch
        ),
        // Section 9.3.4 RENDEZVOUS TIMEOUT: it "MAY appear in a SUBSCRIBE
        // message".
        0x04 => matches!(message, M::Subscribe),
        // Section 9.3.8 EXPIRES: "It MAY appear in SUBSCRIBE_OK, PUBLISH,
        // PUBLISH_OK, or REQUEST_OK."
        0x08 => matches!(message, M::SubscribeOk | M::Publish | M::PublishOk | M::RequestOk),
        // Section 9.3.9 LARGEST OBJECT: "It MAY appear in SUBSCRIBE_OK, PUBLISH
        // or in REQUEST_OK (in response to REQUEST_UPDATE or TRACK_STATUS)."
        0x09 => matches!(message, M::SubscribeOk | M::Publish | M::RequestOk),
        // Section 9.3.10 FORWARD: "It MAY appear in SUBSCRIBE, REQUEST_UPDATE
        // (for a subscription), PUBLISH, PUBLISH_OK and SUBSCRIBE_NAMESPACE."
        0x10 => matches!(
            message,
            M::Subscribe | M::RequestUpdate | M::Publish | M::PublishOk | M::SubscribeNamespace
        ),
        // Section 9.3.5 SUBSCRIBER PRIORITY: "It MAY appear in a SUBSCRIBE,
        // FETCH, REQUEST_UPDATE (for a subscription or FETCH), or PUBLISH_OK
        // message."
        0x20 => matches!(message, M::Subscribe | M::Fetch | M::RequestUpdate | M::PublishOk),
        // Section 9.3.7 SUBSCRIPTION FILTER: "It MAY appear in a SUBSCRIBE,
        // PUBLISH_OK or REQUEST_UPDATE (for a subscription) message."
        0x21 => matches!(message, M::Subscribe | M::PublishOk | M::RequestUpdate),
        // Section 9.3.6 GROUP ORDER: "It MAY appear in a SUBSCRIBE, PUBLISH_OK,
        // or FETCH."
        0x22 => matches!(message, M::Subscribe | M::PublishOk | M::Fetch),
        // Section 9.3.11 NEW GROUP REQUEST: "It MAY appear in PUBLISH_OK,
        // SUBSCRIBE or REQUEST_UPDATE for a subscription."
        0x32 => matches!(message, M::PublishOk | M::Subscribe | M::RequestUpdate),
        _ => true,
    }
}

/// Refuse a message carrying a Message Parameter its own definition does not
/// place there.
///
/// Section 9.3.1 answers this with a close, which the drafts below do not.
/// Draft-16 Section 9.2.2, and drafts 07 through 15 under the older name
/// Version Specific Parameters, end the same sentence "it MUST be ignored" —
/// so this check belongs to drafts 17, 18 and 19 and to no draft before them.
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
        ControlMessage::PublishOk(m) => &m.parameters,
        ControlMessage::PublishNamespace(m) => &m.parameters,
        ControlMessage::SubscribeNamespace(m) => &m.parameters,
        ControlMessage::TrackStatus(m) => &m.parameters,
        ControlMessage::Fetch(m) => &m.parameters,
        ControlMessage::FetchOk(m) => &m.parameters,
        // No Message Parameters field. SETUP is named here rather than left to
        // a wildcard because the draft says why it can never have one: Section
        // 9.3.1 notes that "since Setup Options use a separate namespace, it is
        // impossible for Message Parameters to appear in Setup messages", and
        // this codec keeps the two namespaces in separate fields.
        ControlMessage::Setup(_)
        | ControlMessage::GoAway(_)
        | ControlMessage::RequestError(_)
        | ControlMessage::PublishDone(_)
        | ControlMessage::Namespace(_)
        | ControlMessage::NamespaceDone(_)
        | ControlMessage::PublishBlocked(_) => return Ok(()),
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
    pub fn encode(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        check_discriminators(self)?;
        check_ranges(self)?;
        check_parameter_scope(self)?;
        let mut payload = Vec::with_capacity(256);
        self.encode_payload(&mut payload)?;

        if payload.len() > MAX_MESSAGE_LENGTH {
            return Err(CodecError::MessageTooLong(payload.len()));
        }

        let msg_type = self.message_type();
        VarInt::from_usize(msg_type.id() as usize).encode_moqt::<Wire>(buf);
        // Draft-17: 16-bit length (big-endian)
        buf.put_u16(payload.len() as u16);
        buf.put_slice(&payload);
        Ok(())
    }

    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let type_id = VarInt::decode_moqt::<Wire>(buf)?.into_inner();
        let msg_type =
            MessageType::from_id(type_id).ok_or(CodecError::UnknownMessageType(type_id))?;
        // Draft-17: 16-bit length (big-endian)
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
        check_parameter_scope(&msg)?;
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
            }
            ControlMessage::RequestError(m) => {
                if m.reason_phrase.len() > MAX_REASON_PHRASE_LENGTH {
                    return Err(CodecError::ReasonPhraseTooLong);
                }
                m.error_code.encode_moqt::<Wire>(buf);
                m.retry_interval.encode_moqt::<Wire>(buf);
                VarInt::from_usize(m.reason_phrase.len()).encode_moqt::<Wire>(buf);
                buf.put_slice(&m.reason_phrase);
            }
            ControlMessage::Subscribe(m) => {
                check_required_request_id_delta(m.request_id, m.required_request_id_delta)?;
                m.track_namespace.validate_moqt()?;
                check_full_track_name(&m.track_namespace, &m.track_name)?;
                m.request_id.encode_moqt::<Wire>(buf);
                m.required_request_id_delta.encode_moqt::<Wire>(buf);
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
                check_required_request_id_delta(m.request_id, m.required_request_id_delta)?;
                m.request_id.encode_moqt::<Wire>(buf);
                m.required_request_id_delta.encode_moqt::<Wire>(buf);
                encode_parameters(&m.parameters, buf)?;
            }
            ControlMessage::Publish(m) => {
                check_required_request_id_delta(m.request_id, m.required_request_id_delta)?;
                m.track_namespace.validate_moqt()?;
                check_full_track_name(&m.track_namespace, &m.track_name)?;
                m.request_id.encode_moqt::<Wire>(buf);
                m.required_request_id_delta.encode_moqt::<Wire>(buf);
                m.track_namespace.encode_moqt::<Wire>(buf);
                VarInt::from_usize(m.track_name.len()).encode_moqt::<Wire>(buf);
                buf.put_slice(&m.track_name);
                m.track_alias.encode_moqt::<Wire>(buf);
                encode_parameters(&m.parameters, buf)?;
                encode_track_properties(&m.track_properties, buf)?;
            }
            ControlMessage::PublishOk(m) => {
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
                check_required_request_id_delta(m.request_id, m.required_request_id_delta)?;
                m.track_namespace.validate_moqt()?;
                m.request_id.encode_moqt::<Wire>(buf);
                m.required_request_id_delta.encode_moqt::<Wire>(buf);
                m.track_namespace.encode_moqt::<Wire>(buf);
                encode_parameters(&m.parameters, buf)?;
            }
            ControlMessage::Namespace(m) => {
                m.namespace_suffix.validate_moqt()?;
                m.namespace_suffix.encode_moqt::<Wire>(buf);
            }
            ControlMessage::NamespaceDone(m) => {
                m.namespace_suffix.validate_moqt()?;
                m.namespace_suffix.encode_moqt::<Wire>(buf);
            }
            ControlMessage::SubscribeNamespace(m) => {
                check_required_request_id_delta(m.request_id, m.required_request_id_delta)?;
                m.namespace_prefix.validate_moqt()?;
                m.request_id.encode_moqt::<Wire>(buf);
                m.required_request_id_delta.encode_moqt::<Wire>(buf);
                m.namespace_prefix.encode_moqt::<Wire>(buf);
                m.subscribe_options.encode_moqt::<Wire>(buf);
                encode_parameters(&m.parameters, buf)?;
            }
            ControlMessage::TrackStatus(m) => {
                check_required_request_id_delta(m.request_id, m.required_request_id_delta)?;
                m.track_namespace.validate_moqt()?;
                check_full_track_name(&m.track_namespace, &m.track_name)?;
                m.request_id.encode_moqt::<Wire>(buf);
                m.required_request_id_delta.encode_moqt::<Wire>(buf);
                m.track_namespace.encode_moqt::<Wire>(buf);
                VarInt::from_usize(m.track_name.len()).encode_moqt::<Wire>(buf);
                buf.put_slice(&m.track_name);
                encode_parameters(&m.parameters, buf)?;
            }
            ControlMessage::Fetch(m) => {
                check_required_request_id_delta(m.request_id, m.required_request_id_delta)?;
                m.request_id.encode_moqt::<Wire>(buf);
                m.required_request_id_delta.encode_moqt::<Wire>(buf);
                VarInt::from_usize(m.fetch_type as usize).encode_moqt::<Wire>(buf);
                match &m.fetch_payload {
                    FetchPayload::Standalone {
                        track_namespace,
                        track_name,
                        start_group,
                        start_object,
                        end_group,
                        end_object,
                    } => {
                        track_namespace.validate_moqt()?;
                        check_full_track_name(track_namespace, track_name)?;
                        track_namespace.encode_moqt::<Wire>(buf);
                        VarInt::from_usize(track_name.len()).encode_moqt::<Wire>(buf);
                        buf.put_slice(track_name);
                        start_group.encode_moqt::<Wire>(buf);
                        start_object.encode_moqt::<Wire>(buf);
                        end_group.encode_moqt::<Wire>(buf);
                        end_object.encode_moqt::<Wire>(buf);
                    }
                    FetchPayload::Joining { joining_request_id, joining_start } => {
                        joining_request_id.encode_moqt::<Wire>(buf);
                        joining_start.encode_moqt::<Wire>(buf);
                    }
                }
                encode_parameters(&m.parameters, buf)?;
            }
            ControlMessage::FetchOk(m) => {
                buf.put_u8(m.end_of_track);
                m.end_group.encode_moqt::<Wire>(buf);
                m.end_object.encode_moqt::<Wire>(buf);
                encode_parameters(&m.parameters, buf)?;
                encode_track_properties(&m.track_properties, buf)?;
            }
            ControlMessage::PublishBlocked(m) => {
                m.namespace_suffix.validate_moqt()?;
                check_full_track_name(&m.namespace_suffix, &m.track_name)?;
                m.namespace_suffix.encode_moqt::<Wire>(buf);
                VarInt::from_usize(m.track_name.len()).encode_moqt::<Wire>(buf);
                buf.put_slice(&m.track_name);
            }
        }
        Ok(())
    }

    fn decode_payload(msg_type: MessageType, buf: &mut impl Buf) -> Result<Self, CodecError> {
        match msg_type {
            MessageType::Setup => {
                let options = decode_setup_options(buf)?;
                Ok(ControlMessage::Setup(Setup { options }))
            }
            MessageType::GoAway => {
                let uri_len = VarInt::decode_moqt::<Wire>(buf)?.into_inner() as usize;
                // Draft-17 Section 9.5: "The maximum length of the New Session
                // URI is 8,192 bytes. If an endpoint receives a length
                // exceeding the maximum, it MUST close the session with a
                // PROTOCOL_VIOLATION." Checked here as well as on encode: a
                // client migrates to this URI, so an oversize one is handed
                // straight to connection setup, and the codec is the only layer
                // that was ever going to bound it.
                if uri_len > MAX_GOAWAY_URI_LENGTH {
                    return Err(CodecError::GoAwayUriTooLong);
                }
                let uri = read_bytes(buf, uri_len)?;
                let timeout = VarInt::decode_moqt::<Wire>(buf)?;
                Ok(ControlMessage::GoAway(GoAway { new_session_uri: uri, timeout }))
            }
            MessageType::RequestOk => {
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::RequestOk(RequestOk { parameters }))
            }
            MessageType::RequestError => {
                let error_code = VarInt::decode_moqt::<Wire>(buf)?;
                let retry_interval = VarInt::decode_moqt::<Wire>(buf)?;
                let reason_len = VarInt::decode_moqt::<Wire>(buf)?.into_inner() as usize;
                // Draft-17 Section 1.4.4: "The reason phrase length has a
                // maximum value of 1024 bytes. If an endpoint receives a length
                // exceeding the maximum, it MUST close the session with a
                // PROTOCOL_VIOLATION". A reason phrase is diagnostic text that
                // implementations log and surface, so an unbounded one is a
                // peer-controlled amplification into whatever consumes it.
                if reason_len > MAX_REASON_PHRASE_LENGTH {
                    return Err(CodecError::ReasonPhraseTooLong);
                }
                let reason_phrase = read_bytes(buf, reason_len)?;
                Ok(ControlMessage::RequestError(RequestError {
                    error_code,
                    retry_interval,
                    reason_phrase,
                }))
            }
            MessageType::Subscribe => {
                let request_id = VarInt::decode_moqt::<Wire>(buf)?;
                let required_request_id_delta = VarInt::decode_moqt::<Wire>(buf)?;
                let track_namespace = TrackNamespace::decode_moqt::<Wire>(buf)?;
                let tn_len = VarInt::decode_moqt::<Wire>(buf)?.into_inner() as usize;
                let track_name = read_bytes(buf, tn_len)?;
                check_required_request_id_delta(request_id, required_request_id_delta)?;
                check_full_track_name(&track_namespace, &track_name)?;
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::Subscribe(Subscribe {
                    request_id,
                    required_request_id_delta,
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
                let required_request_id_delta = VarInt::decode_moqt::<Wire>(buf)?;
                check_required_request_id_delta(request_id, required_request_id_delta)?;
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::RequestUpdate(RequestUpdate {
                    request_id,
                    required_request_id_delta,
                    parameters,
                }))
            }
            MessageType::Publish => {
                let request_id = VarInt::decode_moqt::<Wire>(buf)?;
                let required_request_id_delta = VarInt::decode_moqt::<Wire>(buf)?;
                let track_namespace = TrackNamespace::decode_moqt::<Wire>(buf)?;
                let tn_len = VarInt::decode_moqt::<Wire>(buf)?.into_inner() as usize;
                let track_name = read_bytes(buf, tn_len)?;
                let track_alias = VarInt::decode_moqt::<Wire>(buf)?;
                check_required_request_id_delta(request_id, required_request_id_delta)?;
                check_full_track_name(&track_namespace, &track_name)?;
                let parameters = decode_parameters(buf)?;
                let track_properties = decode_track_properties(buf)?;
                Ok(ControlMessage::Publish(Publish {
                    request_id,
                    required_request_id_delta,
                    track_namespace,
                    track_name,
                    track_alias,
                    parameters,
                    track_properties,
                }))
            }
            MessageType::PublishOk => {
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::PublishOk(PublishOk { parameters }))
            }
            MessageType::PublishDone => {
                let status_code = VarInt::decode_moqt::<Wire>(buf)?;
                let stream_count = VarInt::decode_moqt::<Wire>(buf)?;
                let reason_len = VarInt::decode_moqt::<Wire>(buf)?.into_inner() as usize;
                // Draft-17 Section 1.4.4, the same bound as REQUEST_ERROR above.
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
                let required_request_id_delta = VarInt::decode_moqt::<Wire>(buf)?;
                let track_namespace = TrackNamespace::decode_moqt::<Wire>(buf)?;
                check_required_request_id_delta(request_id, required_request_id_delta)?;
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::PublishNamespace(PublishNamespace {
                    request_id,
                    required_request_id_delta,
                    track_namespace,
                    parameters,
                }))
            }
            MessageType::Namespace => {
                let namespace_suffix = TrackNamespace::decode_allow_empty_moqt::<Wire>(buf)?;
                Ok(ControlMessage::Namespace(Namespace { namespace_suffix }))
            }
            MessageType::NamespaceDone => {
                let namespace_suffix = TrackNamespace::decode_allow_empty_moqt::<Wire>(buf)?;
                Ok(ControlMessage::NamespaceDone(NamespaceDone { namespace_suffix }))
            }
            MessageType::SubscribeNamespace => {
                let request_id = VarInt::decode_moqt::<Wire>(buf)?;
                let required_request_id_delta = VarInt::decode_moqt::<Wire>(buf)?;
                let namespace_prefix = TrackNamespace::decode_allow_empty_moqt::<Wire>(buf)?;
                let subscribe_options = VarInt::decode_moqt::<Wire>(buf)?;
                check_required_request_id_delta(request_id, required_request_id_delta)?;
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::SubscribeNamespace(SubscribeNamespace {
                    request_id,
                    required_request_id_delta,
                    namespace_prefix,
                    subscribe_options,
                    parameters,
                }))
            }
            MessageType::TrackStatus => {
                let request_id = VarInt::decode_moqt::<Wire>(buf)?;
                let required_request_id_delta = VarInt::decode_moqt::<Wire>(buf)?;
                let track_namespace = TrackNamespace::decode_moqt::<Wire>(buf)?;
                let tn_len = VarInt::decode_moqt::<Wire>(buf)?.into_inner() as usize;
                let track_name = read_bytes(buf, tn_len)?;
                check_required_request_id_delta(request_id, required_request_id_delta)?;
                check_full_track_name(&track_namespace, &track_name)?;
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::TrackStatus(TrackStatus {
                    request_id,
                    required_request_id_delta,
                    track_namespace,
                    track_name,
                    parameters,
                }))
            }
            MessageType::Fetch => {
                let request_id = VarInt::decode_moqt::<Wire>(buf)?;
                let required_request_id_delta = VarInt::decode_moqt::<Wire>(buf)?;
                let fetch_type_val = VarInt::decode_moqt::<Wire>(buf)?.into_inner();
                let fetch_type = FetchType::from_u64(fetch_type_val)
                    .ok_or(CodecError::InvalidFetchType(fetch_type_val))?;
                let fetch_payload = match fetch_type {
                    FetchType::Standalone => {
                        let track_namespace = TrackNamespace::decode_moqt::<Wire>(buf)?;
                        let tn_len = VarInt::decode_moqt::<Wire>(buf)?.into_inner() as usize;
                        let track_name = read_bytes(buf, tn_len)?;
                        let start_group = VarInt::decode_moqt::<Wire>(buf)?;
                        let start_object = VarInt::decode_moqt::<Wire>(buf)?;
                        let end_group = VarInt::decode_moqt::<Wire>(buf)?;
                        let end_object = VarInt::decode_moqt::<Wire>(buf)?;
                        check_full_track_name(&track_namespace, &track_name)?;
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
                        let joining_request_id = VarInt::decode_moqt::<Wire>(buf)?;
                        let joining_start = VarInt::decode_moqt::<Wire>(buf)?;
                        FetchPayload::Joining { joining_request_id, joining_start }
                    }
                };
                check_required_request_id_delta(request_id, required_request_id_delta)?;
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::Fetch(Fetch {
                    request_id,
                    required_request_id_delta,
                    fetch_type,
                    fetch_payload,
                    parameters,
                }))
            }
            MessageType::FetchOk => {
                if buf.remaining() < 1 {
                    return Err(CodecError::UnexpectedEnd);
                }
                let end_of_track = buf.get_u8();
                let end_group = VarInt::decode_moqt::<Wire>(buf)?;
                let end_object = VarInt::decode_moqt::<Wire>(buf)?;
                let parameters = decode_parameters(buf)?;
                let track_properties = decode_track_properties(buf)?;
                Ok(ControlMessage::FetchOk(FetchOk {
                    end_of_track,
                    end_group,
                    end_object,
                    parameters,
                    track_properties,
                }))
            }
            MessageType::PublishBlocked => {
                let namespace_suffix = TrackNamespace::decode_allow_empty_moqt::<Wire>(buf)?;
                let tn_len = VarInt::decode_moqt::<Wire>(buf)?.into_inner() as usize;
                let track_name = read_bytes(buf, tn_len)?;
                check_full_track_name(&namespace_suffix, &track_name)?;
                Ok(ControlMessage::PublishBlocked(PublishBlocked { namespace_suffix, track_name }))
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
            ControlMessage::PublishOk(_) => MessageType::PublishOk,
            ControlMessage::PublishDone(_) => MessageType::PublishDone,
            ControlMessage::PublishNamespace(_) => MessageType::PublishNamespace,
            ControlMessage::Namespace(_) => MessageType::Namespace,
            ControlMessage::NamespaceDone(_) => MessageType::NamespaceDone,
            ControlMessage::SubscribeNamespace(_) => MessageType::SubscribeNamespace,
            ControlMessage::TrackStatus(_) => MessageType::TrackStatus,
            ControlMessage::Fetch(_) => MessageType::Fetch,
            ControlMessage::FetchOk(_) => MessageType::FetchOk,
            ControlMessage::PublishBlocked(_) => MessageType::PublishBlocked,
        }
    }
}

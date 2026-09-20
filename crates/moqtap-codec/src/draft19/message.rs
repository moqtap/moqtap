//! Draft-19 control message encoding and decoding.
//!
//! Key differences from draft-18:
//! - `Request ID` field removed from GOAWAY entirely; the control-stream and
//!   request-stream forms are now identical.
//! - New Range Filter parameters (length-prefixed): SUBGROUP_FILTER (0x25),
//!   OBJECTID_FILTER (0x26), PRIORITY_FILTER (0x27), OBJECT_PROPERTY_FILTER
//!   (0x28) and TRACK_PROPERTY_FILTER (0x29).
//! - New Setup Options MAX_FILTER_RANGES (0x06) and MAX_REQUEST_UPDATES (0x08);
//!   both are even KVP types carrying a varint value.
//! - GROUP_ORDER (0x22) moves from PUBLISH_OK to SUBSCRIBE_TRACKS (the wire
//!   encoding of the parameter is unchanged).
//! - PUBLISH_BLOCKED renamed to PUBLISH_SKIPPED (still type 0x0F; wire
//!   identical).
//! - SUBSCRIPTION_FILTER renamed to LOCATION_FILTER (still parameter 0x21).
//! - REQUEST_ERROR adds CONFLICTING_FILTERS (0x35) and INVALID_FILTER (0x36);
//!   DUPLICATE_SUBSCRIPTION (0x19) is removed.
//! - The framing field after Message Length is named Message Body (draft-19
//!   Section 10, Figure 3); earlier drafts called it Message Payload. The
//!   change is editorial, so the bytes are unchanged, but this module uses the
//!   new name.

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
use crate::varint::{Moqt18 as Wire, VarInt};
use bytes::{Buf, BufMut};

// ============================================================
// Parameter encoding helpers for draft-19
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
    /// A Track Namespace as defined in draft-19 Section 2.4.1: a varint field
    /// count followed by that many length-prefixed fields.
    ///
    /// Not one of the four value encodings draft-19 Section 10.2 lists. A
    /// parameter definition is free to name an encoding from elsewhere in the
    /// document, and TRACK_NAMESPACE_PREFIX does exactly that; the field count
    /// is the only length the wire carries.
    TrackNamespaceValue,
}

fn param_encoding(key: u64) -> Option<ParamEncoding> {
    match key {
        // 0x02 = OBJECT_DELIVERY_TIMEOUT (DELIVERY_TIMEOUT on drafts 11-17)
        // 0x04 = RENDEZVOUS_TIMEOUT (draft-19 Section 10.2.6). Not
        //        MAX_CACHE_DURATION: that is Property Type 0x04 in the
        //        separate Properties registry (Section 15.8), a different
        //        namespace that happens to reuse the number.
        // 0x06 = SUBGROUP_DELIVERY_TIMEOUT (new in draft-18)
        // 0x08 = EXPIRES
        // 0x0A = FILL_TIMEOUT (new in draft-18, FETCH only)
        // 0x32 = NEW_GROUP_REQUEST
        0x02 | 0x04 | 0x06 | 0x08 | 0x0A | 0x32 => Some(ParamEncoding::Varint),
        // 0x10 = FORWARD, 0x20 = SUBSCRIBER_PRIORITY, 0x22 = GROUP_ORDER
        0x10 | 0x20 | 0x22 => Some(ParamEncoding::Uint8),
        // 0x09 = LARGEST_OBJECT. Draft-19 Section 10.2.16: "The LARGEST_OBJECT
        //        parameter (Parameter Type 0x9) is a Location." A Location is
        //        two consecutive varints (Section 10.2), with no length ahead
        //        of them.
        0x09 => Some(ParamEncoding::Location),
        // 0x34 = TRACK_NAMESPACE_PREFIX. Section 10.2.19: it "uses the Track
        //        Namespace encoding described in Section 2.4.1".
        0x34 => Some(ParamEncoding::TrackNamespaceValue),
        // 0x03 = AUTHORIZATION_TOKEN
        // 0x21 = LOCATION_FILTER (SUBSCRIPTION_FILTER on drafts 15-18)
        // 0x25 = SUBGROUP_FILTER, 0x26 = OBJECTID_FILTER, 0x27 = PRIORITY_FILTER,
        // 0x28 = OBJECT_PROPERTY_FILTER, 0x29 = TRACK_PROPERTY_FILTER
        //        (Range Filters, new in draft-19)
        0x03 | 0x21 | 0x25 | 0x26 | 0x27 | 0x28 | 0x29 => Some(ParamEncoding::LengthPrefixed),
        _ => None,
    }
}

/// Whether `value` is inside the range draft-19 allows for a uint8-valued
/// parameter.
///
/// Two of the three uint8 parameters restrict their range and say the receiver
/// MUST close the session with PROTOCOL_VIOLATION on anything outside it:
/// GROUP_ORDER allows only Ascending (0x1) and Descending (0x2) (Section
/// 10.2.8), and FORWARD allows only 0 and 1 (Section 10.2.17).
/// SUBSCRIBER_PRIORITY (Section 10.2.7) uses the whole 0-255 range, so it has
/// no entry here.
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

const AUTHORIZATION_TOKEN: u64 = 0x03;

/// Whether a message may carry `key` more than once.
///
/// Section 10.2 states the default: "Senders MUST NOT repeat the same Parameter
/// Type in a message unless the parameter definition explicitly allows multiple
/// instances of that type to be sent in a single message." Two definitions do.
///
/// * `AUTHORIZATION_TOKEN` (0x03), Section 10.2.2: "The AUTHORIZATION TOKEN
///   parameter MAY be repeated within a message as long as the combination of
///   Token Type and Token Value are unique after resolving any aliases."
/// * The five Range Filters (0x25 through 0x29), Section 5.1.3: "The Track
///   Property filter parameter MAY appear multiple times in a SUBSCRIBE_TRACKS
///   message or REQUEST_UPDATE for it. All other filter parameters MAY appear
///   multiple times in a FETCH, SUBSCRIBE, SUBSCRIBE_TRACKS, PUBLISH_OK, or
///   REQUEST_UPDATE (on a subscription, from the subscriber only) message."
///
/// # A zero `Type Delta` is "the same type again", not an error
///
/// The two rules interact, and **the draft does not say how**. Section 10.2 also
/// requires that "Parameters MUST be serialized in ascending order by Type", so
/// a second instance of a repeatable type produces a `Type Delta` of 0 — well
/// formed only if the decoder reads a zero delta as a repeat rather than as a
/// malformation. That reading is the one taken here; the alternative makes
/// Section 5.1.3's permission unusable, because there is no other encoding for
/// a second filter of the same type.
///
/// # Why the permission is not decoration
///
/// "All filter parameters with the same SetID value are combined using logical
/// 'AND' operations, then all the resulting sets are combined using logical
/// 'OR' operations." One filter parameter carries one SetID, so a subscriber
/// asking for two alternatives that each constrain the same field — Subgroup 1
/// to 3 at low priority, or Subgroup 10 to 12 at high — has to send SUBGROUP_
/// FILTER twice, once per set. Refusing the repeat does not narrow what a peer
/// can express; it collapses the set lattice to one filter per type and turns
/// conforming traffic into a session close.
///
/// What the filters may **not** do is repeat the same (Parameter Type, SetID,
/// Property Type) triple, and Section 5.1.3 answers that with a REQUEST_ERROR
/// carrying INVALID_FILTER rather than with a session close. A reply an endpoint
/// sends is not a frame a decoder refuses, so nothing here enforces it — see
/// [`crate::range_filter`] for the reader an endpoint uses to decide.
fn parameter_may_repeat(key: u64) -> bool {
    matches!(key, AUTHORIZATION_TOKEN | 0x25..=0x29)
}

/// Add a delta to the previous delta-encoded key.
///
/// Draft-19 Section 1.4.3: "The previous Type value plus the Delta Type MUST NOT
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
/// Draft-19 Section 2.4.1: "The maximum total length of a Full Track Name is
/// 4,096 bytes. The length of a Full Track Name is computed as the sum of the
/// Track Namespace Field Length fields and the Track Name Length field... If an
/// endpoint receives a Track Namespace or a Full Track Name exceeding 4,096
/// bytes, it MUST close the session with a PROTOCOL_VIOLATION."
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

/// Hold every AUTHORIZATION TOKEN parameter to the Token structure it names.
///
/// Section 10.2.2: "If the Token structure cannot be decoded, the receiver
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

/// Hold every LOCATION_FILTER parameter to the filter structure it names.
///
/// Section 5.1.2: "An endpoint that receives a filter type other than the above
/// MUST close the session with PROTOCOL_VIOLATION." Section 10.2.9 defines the
/// parameter, which this draft renamed from SUBSCRIPTION_FILTER to
/// LOCATION_FILTER when it added the Range Filters beside it. The number, 0x21,
/// and the structure are the ones draft-18 had.
///
/// Drafts 15 and 16 stated the length rule of this parameter directly, at
/// draft-16 Section 9.2.2.5 — "If the length of the Subscription Filter does
/// not match the parameter length, the publisher MUST close the session with
/// PROTOCOL_VIOLATION." Draft-17 dropped that sentence, and what answers the
/// same malformation here is the general rule of Section 1.4.3, which names
/// KEY_VALUE_FORMATTING_ERROR. Same malformation, different code, and the
/// session table is where the two part.
///
/// The End Group is a delta, and this draft states what happens when resolving
/// it leaves the number space: "the last Group ID to be delivered
/// will be the Group ID in Start Location plus the End Group Delta. If the
/// resulting Group ID would be greater than 2^64 - 1, the endpoint MUST close
/// the session with a PROTOCOL_VIOLATION." That is why the sum is taken here and
/// not left to the caller — draft-17, which introduced the delta and states no
/// such sentence, does not take it.
///
/// The filter is otherwise decoded and discarded. What is kept is the refusal —
/// the value stays on the parameter as the bytes that arrived, so a caller reads
/// it through [`SubscriptionFilter::decode_moqt`] when it wants the filter
/// rather than the frame.
fn check_subscription_filters(parameters: &[KeyValuePair]) -> Result<(), CodecError> {
    for parameter in parameters {
        if parameter.key.into_inner() != SUBSCRIPTION_FILTER_PARAMETER {
            continue;
        }
        match &parameter.value {
            KvpValue::Bytes(value) => {
                SubscriptionFilter::decode_moqt::<Wire>(value)?.last_group()?;
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
        // parameter before it. Draft-19 Section 10.2: "Receivers SHOULD check
        // that there are no unexpected duplicate parameters and close the
        // session with PROTOCOL_VIOLATION if found." Downstream code that scans
        // the list for a key takes whichever copy it meets first, so two
        // implementations reading one frame can pick opposite values.
        //
        // "Unexpected" is what `parameter_may_repeat` reads: a zero delta on a
        // type whose own definition permits repeats is the second instance,
        // which is the only encoding such an instance has.
        if i > 0 && delta == 0 && !parameter_may_repeat(abs_key) {
            return Err(CodecError::DuplicateParameter(abs_key));
        }
        prev_key = abs_key;

        // Section 10.2: "All Message Parameters MUST be defined in the
        // negotiated version of MOQT or negotiated via Setup Options. An
        // endpoint that receives an unknown Message Parameter MUST close the
        // session with PROTOCOL_VIOLATION. Because the receiver has to
        // understand every Message Parameter, there is no need for a mechanism
        // to skip unknown parameters." Because unknown parameters
        // cannot be skipped, the block is bounded by a parameter count rather
        // than a length.
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
            ParamEncoding::TrackNamespaceValue => {
                // A prefix of zero fields is legal: Section 2.4.1 puts a Track
                // Namespace at "between 0 and 32 Track Namespace Fields", and
                // an empty prefix matches every namespace.
                let ns = TrackNamespace::decode_allow_empty_moqt::<Wire>(buf)?;
                let mut encoded = Vec::new();
                ns.encode_moqt::<Wire>(&mut encoded);
                KvpValue::Bytes(encoded)
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
    check_subscription_filters(params)?;
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
            // Both values are already stored in their own wire form — two
            // varints for a Location, a field count and its fields for a Track
            // Namespace — so they go out as they are. Adding a length here is
            // the bug these arms exist to avoid.
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
            // Draft-19 Section 1.4.3: "The maximum length of a value is 2^16-1
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
/// Section 12.7: Immutable Properties are "a Track or Object Property that
/// contains a sequence of Key-Value-Pairs (see Figure 2) that are themselves
/// Track or Object Properties, respectively". The Type is odd, so its value is
/// length-prefixed bytes, and those bytes are another delta-typed run starting
/// from 0.
const IMMUTABLE_PROPERTIES: u64 = 0x0B;

/// Whether `value` is inside the range draft-19 allows for a Track Property
/// type that restricts one.
///
/// Two types do, and each answers anything outside its range with a session
/// close. DEFAULT_PUBLISHER_GROUP_ORDER (0x22), Section 12.5: "The allowed
/// values are Ascending (0x1) or Descending (0x2). If an endpoint receives a
/// value outside this range, it MUST close the session with
/// PROTOCOL_VIOLATION." DYNAMIC_GROUPS (0x30), Section 12.6: "The allowed
/// values are 0 or 1... If an endpoint receives a value larger than 1, it MUST
/// close the session with PROTOCOL_VIOLATION."
///
/// Both are Track Properties, so the list they arrive in is the one carried by
/// a control message rather than the properties on an object.
///
/// DEFAULT_PUBLISHER_PRIORITY (0x0E) is not here. Section 12.4 says
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
/// contents Section 12.7 defines as properties themselves. The draft asks for
/// this in as many words: "When looking for the value of a property, processors
/// MUST search both the mutable properties and the contents of Immutable
/// Properties." A check applied only to the outer list is one a peer opts out of
/// by moving a pair inside the block, and the block is where an Original
/// Publisher puts what a relay must not rewrite — which is where a track's group
/// order and dynamic-group support belong.
///
/// Bytes under 0xB that do not parse as a Key-Value-Pair run are left alone
/// rather than refused. Section 12.7 says relays "MAY decode and view the
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
/// Section 10.3.1 assigns PATH, AUTHORIZATION TOKEN, MAX_AUTH_TOKEN_CACHE_SIZE, AUTHORITY,
/// MAX_FILTER_RANGES, MOQT_IMPLEMENTATION and MAX_REQUEST_UPDATES.
///
/// The list exists for one rule and one direction. Section 10.3: "Receivers
/// MUST allow duplicates of unknown Setup Options." A receiver may therefore
/// refuse a repeat only of a type it can name, and an option outside this list
/// is one an extension defined and this codec has no business closing a session
/// over. Nothing else reads it - unknown options are still decoded and carried,
/// as "Receivers MUST ignore unrecognized Setup Options" requires.
const KNOWN_SETUP_OPTIONS: &[u64] = &[0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

/// The one Setup Option whose definition allows more than one instance.
///
/// Section 10.3.1.4: "The AUTHORIZATION TOKEN Setup Option (Option Type 0x03)
/// is functionally equivalent to the AUTHORIZATION TOKEN message parameter...
/// The endpoint can specify one or more tokens in SETUP that the peer can use to
/// authorize MOQT session establishment." That is the "unless the option
/// definition explicitly allows multiple instances" carve-out, and it is the
/// only one on this draft.
const REPEATABLE_SETUP_OPTION: u64 = 0x03;

/// Decode the Setup Options of a SETUP message.
///
/// Section 10.3: "Senders MUST NOT repeat the same Option Type in a message
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
    /// REQUEST_OK (0x07). PUBLISH_OK is now an alias of this type.
    RequestOk = 0x07,
    Namespace = 0x08,
    PublishDone = 0x0B,
    TrackStatus = 0x0D,
    NamespaceDone = 0x0E,
    PublishSkipped = 0x0F,
    GoAway = 0x10,
    Fetch = 0x16,
    FetchOk = 0x18,
    Publish = 0x1D,
    /// SUBSCRIBE_NAMESPACE (renumbered to 0x50 in draft-18).
    SubscribeNamespace = 0x50,
    /// SUBSCRIBE_TRACKS (new message in draft-18).
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
            0x18 => Some(MessageType::FetchOk),
            0x1D => Some(MessageType::Publish),
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
            MessageType::FetchOk => "fetch_ok",
            MessageType::Publish => "publish",
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

/// GOAWAY (0x10). Draft-19's GOAWAY has no Request ID field, so the
/// control-stream and request-stream forms are identical on the wire.
/// Draft-18 is the one draft that carries the field, and only when the
/// message is sent on the control stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoAway {
    pub new_session_uri: Vec<u8>,
    pub timeout: VarInt,
}

// ============================================================
// Consolidated Response Messages
// ============================================================

/// REQUEST_OK (0x07). Used as a generic OK response and as the alias for
/// PUBLISH_OK / REQUEST_UPDATE_OK / TRACK_STATUS_OK / SUBSCRIBE_NAMESPACE_OK
/// / PUBLISH_NAMESPACE_OK.
///
/// `track_properties` is only populated for TRACK_STATUS_OK; for every
/// other shape it MUST be empty (length implicit from the message length).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestOk {
    pub parameters: Vec<KeyValuePair>,
    pub track_properties: Vec<KeyValuePair>,
}

/// Optional Redirect structure carried in REQUEST_ERROR with code 0x34.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirect {
    pub connect_uri: Vec<u8>,
    pub track_namespace: TrackNamespace,
    pub track_name: Vec<u8>,
}

/// REQUEST_ERROR (0x05). Adds an optional Redirect structure when
/// `error_code` is REDIRECT (0x34).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestError {
    pub error_code: VarInt,
    pub retry_interval: VarInt,
    pub reason_phrase: Vec<u8>,
    pub redirect: Option<Redirect>,
}

/// REQUEST_ERROR error codes with dedicated meaning.
///
/// Note: DUPLICATE_SUBSCRIPTION (0x19) is removed in draft-19, as multiple
/// concurrent subscriptions per Track are now allowed.
pub mod request_error_codes {
    /// A Mandatory Track Property the receiver does not understand.
    pub const UNSUPPORTED_EXTENSION: u64 = 0x33;
    /// Response carries a [`super::Redirect`] structure.
    pub const REDIRECT: u64 = 0x34;
    /// New in draft-19: SUBSCRIBE_TRACKS filter parameters conflict among too
    /// many subscribers to aggregate the subscription upstream.
    pub const CONFLICTING_FILTERS: u64 = 0x35;
    /// New in draft-19: a Range Filter parameter is invalid or exceeds
    /// MAX_FILTER_RANGES.
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

/// PUBLISH_DONE (0x0B). Status codes 0x5/0x6 are swapped vs draft-17.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishDone {
    pub status_code: VarInt,
    pub stream_count: VarInt,
    pub reason_phrase: Vec<u8>,
}

/// Numeric values for the [`PublishDone::status_code`] field.
pub mod publish_done_codes {
    /// Draft-18: TOO_FAR_BEHIND is 0x05 (was 0x06 in draft-17).
    pub const TOO_FAR_BEHIND: u64 = 0x05;
    /// Draft-18: EXPIRED is 0x06 (was 0x05 in draft-17).
    pub const EXPIRED: u64 = 0x06;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Namespace {
    pub namespace_suffix: TrackNamespace,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceDone {
    pub namespace_suffix: TrackNamespace,
}

// ============================================================
// Subscribe Namespace / Tracks Messages
// ============================================================

/// SUBSCRIBE_NAMESPACE (0x50). Subscribes to NAMESPACE / NAMESPACE_DONE
/// advertisements for namespaces matching `namespace_prefix`. The
/// `subscribe_options` byte from draft-17 is removed; namespace subscriptions
/// only produce NAMESPACE / NAMESPACE_DONE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeNamespace {
    pub request_id: VarInt,
    pub namespace_prefix: TrackNamespace,
    pub parameters: Vec<KeyValuePair>,
}

/// SUBSCRIBE_TRACKS (0x51, new in draft-18). Subscribes to PUBLISH messages
/// for tracks whose namespace matches `namespace_prefix`. Carries the FORWARD
/// parameter (Section 10.2.17), which on drafts 15 through 17 may appear on
/// SUBSCRIBE_NAMESPACE instead.
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

/// FETCH_OK (0x18). `end_of_track` is uint8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchOk {
    pub end_of_track: u8,
    pub end_group: VarInt,
    pub end_object: VarInt,
    pub parameters: Vec<KeyValuePair>,
    pub track_properties: Vec<KeyValuePair>,
}

// ============================================================
// Publish Skipped
// ============================================================

/// PUBLISH_SKIPPED (0x0F). Drafts 17 and 18 name the same codepoint
/// PUBLISH_BLOCKED, with the same two fields.
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
    PublishDone(PublishDone),
    PublishNamespace(PublishNamespace),
    Namespace(Namespace),
    NamespaceDone(NamespaceDone),
    SubscribeNamespace(SubscribeNamespace),
    SubscribeTracks(SubscribeTracks),
    TrackStatus(TrackStatus),
    Fetch(Fetch),
    FetchOk(FetchOk),
    PublishSkipped(PublishSkipped),
}

/// Refuse a FETCH whose range ends before it starts.
///
/// Section 10.12.3: "Fetch specifies an inclusive range of Objects starting at
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
/// Two draft-19 messages carry a field that says which of the following fields
/// are on the wire: FETCH's Fetch Type, and REQUEST_ERROR's Error Code, whose
/// REDIRECT value (0x34) is what puts the Redirect structure on the wire. This
/// codec holds the alternatives in an enum and an `Option`, so a value can say
/// one thing in its discriminator and another in its body, and the two sides of
/// the codec resolve that differently — the encoder writes whatever the body
/// holds, and the decoder reads whatever the discriminator announces.
///
/// The result is a message that does not survive its own round trip:
///
/// - A FETCH whose type says Standalone and whose body is a joining pair
///   encodes to a joining request id and a joining start where a Track
///   Namespace and a Track Name belong, and comes back as a Standalone fetch of
///   a track named after two integers — or, more often, as an error, which at
///   least is honest. The two joining types share one body shape, so the check
///   is between Standalone and everything else rather than one arm per type.
/// - A REQUEST_ERROR with code REDIRECT and no Redirect body encodes to a
///   message that ends where the decoder expects a Connect URI length, so the
///   peer reads the redirect out of whatever follows or runs off the end. The
///   mirror case is quieter and no better: a Redirect body under any other
///   error code is written out and then skipped by a decoder that was never
///   told to look for it, so the sender believes it redirected a peer that
///   never saw a redirect.
///
/// Refusing at the encoder keeps the two readings from ever diverging on the
/// wire.
fn check_discriminators(message: &ControlMessage) -> Result<(), CodecError> {
    match message {
        ControlMessage::Fetch(m) => {
            let body_is_standalone = matches!(m.fetch_payload, FetchPayload::Standalone { .. });
            if body_is_standalone != (m.fetch_type == FetchType::Standalone) {
                return Err(CodecError::InvalidField);
            }
        }
        ControlMessage::RequestError(m) => {
            let code_is_redirect = m.error_code.into_inner() == request_error_codes::REDIRECT;
            if code_is_redirect != m.redirect.is_some() {
                return Err(CodecError::InvalidField);
            }
        }
        _ => {}
    }
    Ok(())
}

/// Whether draft-19 lets Message Parameter `key` appear in `message`.
///
/// Section 10.2.1: "Each Message Parameter definition indicates the message
/// types in which it can appear. If it appears in some other type of message,
/// the receiving endpoint MUST close the connection with a PROTOCOL_VIOLATION."
/// One arm per entry in the Message Parameters registry (Section 15.7),
/// carrying the message types that entry's own definition names.
///
/// Three things about this draft the arms below fold in:
///
/// * Six of the names are one wire type. Section 10.5: "This document uses the
///   shorthand PUBLISH_OK, REQUEST_UPDATE_OK, TRACK_STATUS_OK,
///   SUBSCRIBE_NAMESPACE_OK, and PUBLISH_NAMESPACE_OK to refer to a REQUEST_OK
///   sent in response to the corresponding request type", and the same section
///   sends a REQUEST_OK in answer to SUBSCRIBE_TRACKS as well. Which one a
///   given REQUEST_OK is depends on the request its Request ID answers, which
///   is session state and not in the frame, so each of those names widens the
///   same arm and a REQUEST_OK is held to their union.
/// * The five Range Filters state their scope in Section 5.1.3 rather than in
///   their own subsections: the Track Property filter "MAY appear multiple
///   times in a SUBSCRIBE_TRACKS message or REQUEST_UPDATE for it", and "all
///   other filter parameters MAY appear multiple times in a FETCH, SUBSCRIBE,
///   SUBSCRIBE_TRACKS, PUBLISH_OK, or REQUEST_UPDATE" message. A parameter
///   definition is free to state its scope elsewhere, and these do.
/// * SUBSCRIBE_TRACKS inherits SUBSCRIBE's whole set. Section 10.19.1: "Any
///   Parameter that can be specified on a Subscription (ie: in SUBSCRIBE) is
///   valid in SUBSCRIBE_TRACKS, unless otherwise specified." Draft-18 has no
///   such sentence, which is why its SUBSCRIBE_TRACKS admits two types and
///   this one admits fourteen.
///
/// FETCH_OK has no arm in the table below, and that is the draft's doing rather
/// than an omission here: Section 10.13 gives it a Parameters field and no
/// parameter definition names it, so every type this draft defines is "some
/// other type of message" there.
///
/// The table decides scope only. A type this draft does not define has no scope
/// to be outside of and is answered by [`CodecError::UnknownMessageParameter`],
/// which is why the final arm carries rather than refuses.
fn parameter_in_scope(key: u64, message: MessageType) -> bool {
    use MessageType as M;
    // Section 10.19.1 makes SUBSCRIBE_TRACKS a superset of SUBSCRIBE, so every
    // arm admitting one admits the other. The arms spell both out rather than
    // wrapping the call, so each still reads against its own sentence.
    match key {
        // Section 10.2.4 OBJECT_DELIVERY_TIMEOUT: "It MAY appear in a
        // PUBLISH_OK, SUBSCRIBE, or REQUEST_UPDATE message."
        0x02 => {
            matches!(message, M::RequestOk | M::Subscribe | M::RequestUpdate | M::SubscribeTracks)
        }
        // Section 10.2.2 AUTHORIZATION TOKEN: "It MAY appear in a PUBLISH,
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
        // Section 10.2.6 RENDEZVOUS TIMEOUT: it "MAY appear in a SUBSCRIBE
        // message".
        0x04 => matches!(message, M::Subscribe | M::SubscribeTracks),
        // Section 10.2.3 SUBGROUP_DELIVERY_TIMEOUT: "It MAY appear in a
        // PUBLISH_OK, SUBSCRIBE, or REQUEST_UPDATE message."
        0x06 => {
            matches!(message, M::RequestOk | M::Subscribe | M::RequestUpdate | M::SubscribeTracks)
        }
        // Section 10.2.15 EXPIRES: "It MAY appear in SUBSCRIBE_OK, PUBLISH,
        // PUBLISH_OK, SUBSCRIBE_NAMESPACE_OK, SUBSCRIBE_TRACKS_OK,
        // PUBLISH_NAMESPACE_OK, or REQUEST_UPDATE_OK." Five of those seven are
        // a REQUEST_OK.
        0x08 => matches!(message, M::SubscribeOk | M::Publish | M::RequestOk),
        // Section 10.2.16 LARGEST OBJECT: "It MAY appear in SUBSCRIBE_OK,
        // PUBLISH, REQUEST_UPDATE_OK, or TRACK_STATUS_OK."
        0x09 => matches!(message, M::SubscribeOk | M::Publish | M::RequestOk),
        // Section 10.2.5 FILL TIMEOUT: it "MAY appear in a FETCH message".
        0x0A => matches!(message, M::Fetch),
        // Section 10.2.17 FORWARD: "It MAY appear in SUBSCRIBE, REQUEST_UPDATE
        // (for a subscription), PUBLISH, PUBLISH_OK and SUBSCRIBE_TRACKS."
        0x10 => matches!(
            message,
            M::Subscribe | M::RequestUpdate | M::Publish | M::RequestOk | M::SubscribeTracks
        ),
        // Section 10.2.7 SUBSCRIBER PRIORITY: "It MAY appear in a SUBSCRIBE,
        // FETCH, REQUEST_UPDATE (for a subscription or FETCH), or PUBLISH_OK
        // message."
        0x20 => matches!(
            message,
            M::Subscribe | M::Fetch | M::RequestUpdate | M::RequestOk | M::SubscribeTracks
        ),
        // Section 10.2.9 LOCATION FILTER: "It MAY appear in a SUBSCRIBE,
        // PUBLISH_OK or REQUEST_UPDATE (for a subscription) message."
        0x21 => {
            matches!(message, M::Subscribe | M::RequestOk | M::RequestUpdate | M::SubscribeTracks)
        }
        // Section 10.2.8 GROUP ORDER: "It MAY appear in a SUBSCRIBE,
        // SUBSCRIBE_TRACKS, or FETCH."
        0x22 => matches!(message, M::Subscribe | M::SubscribeTracks | M::Fetch),
        // Section 5.1.3: "All other filter parameters MAY appear multiple times
        // in a FETCH, SUBSCRIBE, SUBSCRIBE_TRACKS, PUBLISH_OK, or
        // REQUEST_UPDATE (on a subscription, from the subscriber only)
        // message." SUBGROUP_FILTER (Section 10.2.10), OBJECTID_FILTER
        // (10.2.11), PRIORITY_FILTER (10.2.12) and OBJECT_PROPERTY_FILTER
        // (10.2.13) are those four.
        0x25..=0x28 => matches!(
            message,
            M::Fetch | M::Subscribe | M::SubscribeTracks | M::RequestOk | M::RequestUpdate
        ),
        // Section 5.1.3, of TRACK_PROPERTY_FILTER (Section 10.2.14) alone: it
        // "MAY appear multiple times in a SUBSCRIBE_TRACKS message or
        // REQUEST_UPDATE for it". It selects tracks rather than objects, which
        // is why it is the one filter a SUBSCRIBE may not carry.
        0x29 => matches!(message, M::SubscribeTracks | M::RequestUpdate),
        // Section 10.2.18 NEW GROUP REQUEST: "It MAY appear in PUBLISH_OK,
        // SUBSCRIBE or REQUEST_UPDATE for a subscription."
        0x32 => {
            matches!(message, M::RequestOk | M::Subscribe | M::RequestUpdate | M::SubscribeTracks)
        }
        // Section 10.2.19 TRACK_NAMESPACE_PREFIX: "It MAY appear in
        // REQUEST_UPDATE for a SUBSCRIBE_NAMESPACE or SUBSCRIBE_TRACKS
        // request." The two named there are the request being updated, not two
        // more places the parameter may be written.
        0x34 => matches!(message, M::RequestUpdate),
        _ => true,
    }
}

/// Refuse a message carrying a Message Parameter its own definition does not
/// place there.
///
/// Section 10.2.1 answers this with a close, which the drafts below do not.
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
        ControlMessage::PublishNamespace(m) => &m.parameters,
        ControlMessage::SubscribeNamespace(m) => &m.parameters,
        ControlMessage::SubscribeTracks(m) => &m.parameters,
        ControlMessage::TrackStatus(m) => &m.parameters,
        ControlMessage::Fetch(m) => &m.parameters,
        ControlMessage::FetchOk(m) => &m.parameters,
        // No Message Parameters field. SETUP is named here rather than left to
        // a wildcard because the draft says why it can never have one: Section
        // 10.2.1 notes that "since Setup Options use a separate namespace, it
        // is impossible for Message Parameters to appear in Setup messages",
        // and this codec keeps the two namespaces in separate fields.
        ControlMessage::Setup(_)
        | ControlMessage::GoAway(_)
        | ControlMessage::RequestError(_)
        | ControlMessage::PublishDone(_)
        | ControlMessage::Namespace(_)
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
    pub fn encode(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        check_discriminators(self)?;
        check_ranges(self)?;
        check_parameter_scope(self)?;
        let mut body = Vec::with_capacity(256);
        self.encode_body(&mut body)?;

        if body.len() > MAX_MESSAGE_LENGTH {
            return Err(CodecError::MessageTooLong(body.len()));
        }

        let msg_type = self.message_type();
        VarInt::from_usize(msg_type.id() as usize).encode_moqt::<Wire>(buf);
        // Draft-19: 16-bit length (big-endian)
        buf.put_u16(body.len() as u16);
        buf.put_slice(&body);
        Ok(())
    }

    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let type_id = VarInt::decode_moqt::<Wire>(buf)?.into_inner();
        let msg_type =
            MessageType::from_id(type_id).ok_or(CodecError::UnknownMessageType(type_id))?;
        // Draft-19: 16-bit length (big-endian)
        if buf.remaining() < 2 {
            return Err(CodecError::UnexpectedEnd);
        }
        let body_len = buf.get_u16() as usize;
        if buf.remaining() < body_len {
            return Err(CodecError::UnexpectedEnd);
        }
        let body_bytes = buf.copy_to_bytes(body_len);
        let mut body = &body_bytes[..];
        let msg = match Self::decode_body(msg_type, &mut body) {
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
                    declared: body_len,
                    detail: "its fields ran past the end",
                });
            }
            Err(e) => return Err(e),
        };
        check_ranges(&msg)?;
        check_parameter_scope(&msg)?;
        // Draft-19 Section 10: "If the length does not match the length of the
        // Message Body, the receiver MUST close the session with a
        // PROTOCOL_VIOLATION." A body parser that stops short leaves bytes
        // here; without this the surplus is discarded and a truncated or
        // mis-framed field looks like a well-formed message.
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
                if let Some(r) = &m.redirect {
                    r.track_namespace.validate_moqt()?;
                    check_full_track_name(&r.track_namespace, &r.track_name)?;
                    VarInt::from_usize(r.connect_uri.len()).encode_moqt::<Wire>(buf);
                    buf.put_slice(&r.connect_uri);
                    r.track_namespace.encode_moqt::<Wire>(buf);
                    VarInt::from_usize(r.track_name.len()).encode_moqt::<Wire>(buf);
                    buf.put_slice(&r.track_name);
                }
            }
            ControlMessage::Subscribe(m) => {
                m.track_namespace.validate_moqt()?;
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
                check_full_track_name(&m.track_namespace, &m.track_name)?;
                m.request_id.encode_moqt::<Wire>(buf);
                m.track_namespace.encode_moqt::<Wire>(buf);
                VarInt::from_usize(m.track_name.len()).encode_moqt::<Wire>(buf);
                buf.put_slice(&m.track_name);
                m.track_alias.encode_moqt::<Wire>(buf);
                encode_parameters(&m.parameters, buf)?;
                encode_track_properties(&m.track_properties, buf)?;
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
                check_full_track_name(&m.track_namespace, &m.track_name)?;
                m.request_id.encode_moqt::<Wire>(buf);
                m.track_namespace.encode_moqt::<Wire>(buf);
                VarInt::from_usize(m.track_name.len()).encode_moqt::<Wire>(buf);
                buf.put_slice(&m.track_name);
                encode_parameters(&m.parameters, buf)?;
            }
            ControlMessage::Fetch(m) => {
                m.request_id.encode_moqt::<Wire>(buf);
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
            ControlMessage::PublishSkipped(m) => {
                m.namespace_suffix.validate_moqt()?;
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
                // Draft-19 Section 10.4: an endpoint that receives a New
                // Session URI Length above the maximum MUST close the session
                // with a PROTOCOL_VIOLATION. Checked here as well as on encode
                // so an oversized URI never reaches the application.
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
                // Draft-19 Section 1.4.4: a received reason phrase length above
                // the maximum MUST close the session with a PROTOCOL_VIOLATION.
                if reason_len > MAX_REASON_PHRASE_LENGTH {
                    return Err(CodecError::ReasonPhraseTooLong);
                }
                let reason_phrase = read_bytes(buf, reason_len)?;
                let redirect = if error_code.into_inner() == request_error_codes::REDIRECT {
                    let uri_len = VarInt::decode_moqt::<Wire>(buf)?.into_inner() as usize;
                    let connect_uri = read_bytes(buf, uri_len)?;
                    let track_namespace = TrackNamespace::decode_allow_empty_moqt::<Wire>(buf)?;
                    let name_len = VarInt::decode_moqt::<Wire>(buf)?.into_inner() as usize;
                    let track_name = read_bytes(buf, name_len)?;
                    check_full_track_name(&track_namespace, &track_name)?;
                    Some(Redirect { connect_uri, track_namespace, track_name })
                } else {
                    None
                };
                Ok(ControlMessage::RequestError(RequestError {
                    error_code,
                    retry_interval,
                    reason_phrase,
                    redirect,
                }))
            }
            MessageType::Subscribe => {
                let request_id = VarInt::decode_moqt::<Wire>(buf)?;
                let track_namespace = TrackNamespace::decode_moqt::<Wire>(buf)?;
                let tn_len = VarInt::decode_moqt::<Wire>(buf)?.into_inner() as usize;
                let track_name = read_bytes(buf, tn_len)?;
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
                Ok(ControlMessage::Publish(Publish {
                    request_id,
                    track_namespace,
                    track_name,
                    track_alias,
                    parameters,
                    track_properties,
                }))
            }
            MessageType::PublishDone => {
                let status_code = VarInt::decode_moqt::<Wire>(buf)?;
                let stream_count = VarInt::decode_moqt::<Wire>(buf)?;
                let reason_len = VarInt::decode_moqt::<Wire>(buf)?.into_inner() as usize;
                // Draft-19 Section 1.4.4, same bound as REQUEST_ERROR above.
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
                Ok(ControlMessage::Namespace(Namespace { namespace_suffix }))
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
                Ok(ControlMessage::TrackStatus(TrackStatus {
                    request_id,
                    track_namespace,
                    track_name,
                    parameters,
                }))
            }
            MessageType::Fetch => {
                let request_id = VarInt::decode_moqt::<Wire>(buf)?;
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
                let parameters = decode_parameters(buf)?;
                Ok(ControlMessage::Fetch(Fetch {
                    request_id,
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
            MessageType::PublishSkipped => {
                let namespace_suffix = TrackNamespace::decode_allow_empty_moqt::<Wire>(buf)?;
                let tn_len = VarInt::decode_moqt::<Wire>(buf)?.into_inner() as usize;
                let track_name = read_bytes(buf, tn_len)?;
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
            ControlMessage::PublishDone(_) => MessageType::PublishDone,
            ControlMessage::PublishNamespace(_) => MessageType::PublishNamespace,
            ControlMessage::Namespace(_) => MessageType::Namespace,
            ControlMessage::NamespaceDone(_) => MessageType::NamespaceDone,
            ControlMessage::SubscribeNamespace(_) => MessageType::SubscribeNamespace,
            ControlMessage::SubscribeTracks(_) => MessageType::SubscribeTracks,
            ControlMessage::TrackStatus(_) => MessageType::TrackStatus,
            ControlMessage::Fetch(_) => MessageType::Fetch,
            ControlMessage::FetchOk(_) => MessageType::FetchOk,
            ControlMessage::PublishSkipped(_) => MessageType::PublishSkipped,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Frame `body` as a draft-19 control message of `type_id`, declaring
    /// `declared_len` rather than the body's real length. Used to build the
    /// mismatched frame the length rule is about.
    fn frame_with_declared_len(type_id: u64, declared_len: u16, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        VarInt::from_u64_moqt(type_id).encode_moqt::<Wire>(&mut out);
        out.put_u16(declared_len);
        out.put_slice(body);
        out
    }

    fn frame(type_id: u64, body: &[u8]) -> Vec<u8> {
        frame_with_declared_len(type_id, body.len() as u16, body)
    }

    /// A SUBSCRIBE body: request id 1, namespace ("a"), track name "b", and
    /// `params` already encoded.
    fn subscribe_body(params: &[u8]) -> Vec<u8> {
        let mut body = vec![0x01, 0x01, 0x01, b'a', 0x01, b'b'];
        body.extend_from_slice(params);
        body
    }

    /// Draft-19 Section 10: "If the length does not match the length of the
    /// Message Body, the receiver MUST close the session with a
    /// PROTOCOL_VIOLATION."
    ///
    /// Without the trailing-byte check in `decode` this SUBSCRIBE parses and
    /// the two surplus bytes vanish:
    ///
    /// ```text
    /// assertion `left == right` failed
    ///   left: Ok(Subscribe(Subscribe { request_id: VarInt(1), track_namespace:
    ///         TrackNamespace([[97]]), track_name: [98], parameters: [] }))
    ///  right: Err(InvalidField)
    /// ```
    #[test]
    fn a_message_body_shorter_than_the_declared_length_is_refused() {
        let body = subscribe_body(&[0x00]);
        let mut junked = body.clone();
        junked.extend_from_slice(&[0xff, 0xff]);
        let bytes = frame_with_declared_len(0x03, (body.len() + 2) as u16, &junked);

        let mut buf = &bytes[..];
        assert_eq!(
            ControlMessage::decode(&mut buf),
            Err(CodecError::ControlMessageLengthMismatch {
                declared: (body.len() + 2),
                detail: "its fields left bytes unread",
            })
        );

        // The same body with an honest length still decodes, so the guard
        // rejects the mismatch and not the message.
        let honest = frame(0x03, &body);
        let mut buf = &honest[..];
        assert!(ControlMessage::decode(&mut buf).is_ok());
    }

    /// Draft-19 Section 1.4.4: "The reason phrase length has a maximum value of
    /// 1024 bytes. If an endpoint receives a length exceeding the maximum, it
    /// MUST close the session with a PROTOCOL_VIOLATION".
    ///
    /// Without the decode-side bound the 2000-byte phrase is handed to the
    /// application:
    ///
    /// ```text
    /// assertion `left == right` failed
    ///   left: Ok(RequestError(RequestError { error_code: VarInt(1),
    ///         retry_interval: VarInt(0), reason_phrase: [120, 120, ...],
    ///         redirect: None }))
    ///  right: Err(ReasonPhraseTooLong)
    /// ```
    ///
    /// (The 2000 repeated bytes of the phrase are elided from that transcript.)
    #[test]
    fn an_over_long_reason_phrase_is_refused_on_decode() {
        for (type_id, prefix) in [(0x05u64, vec![0x01, 0x00]), (0x0B, vec![0x01, 0x00])] {
            let mut body = prefix;
            let over = MAX_REASON_PHRASE_LENGTH + 976;
            VarInt::from_usize(over).encode_moqt::<Wire>(&mut body);
            body.extend(std::iter::repeat_n(b'x', over));
            let bytes = frame(type_id, &body);

            let mut buf = &bytes[..];
            assert_eq!(
                ControlMessage::decode(&mut buf),
                Err(CodecError::ReasonPhraseTooLong),
                "message type 0x{type_id:x}"
            );
        }
    }

    /// Draft-19 Section 10.4: "The maximum length of the New Session URI is
    /// 8,192 bytes. If an endpoint receives a length exceeding the maximum, it
    /// MUST close the session with a PROTOCOL_VIOLATION."
    ///
    /// Without the decode-side bound the oversized URI reaches the application
    /// and a migrating endpoint follows it:
    ///
    /// ```text
    /// assertion `left == right` failed
    ///   left: Ok(GoAway(GoAway { new_session_uri: [117, 117, ...],
    ///         timeout: VarInt(0) }))
    ///  right: Err(GoAwayUriTooLong)
    /// ```
    ///
    /// (The 9000 repeated bytes of the URI are elided from that transcript.)
    #[test]
    fn an_over_long_goaway_uri_is_refused_on_decode() {
        let over = MAX_GOAWAY_URI_LENGTH + 808;
        let mut body = Vec::new();
        VarInt::from_usize(over).encode_moqt::<Wire>(&mut body);
        body.extend(std::iter::repeat_n(b'u', over));
        body.push(0x00); // timeout
        let bytes = frame(0x10, &body);

        let mut buf = &bytes[..];
        assert_eq!(ControlMessage::decode(&mut buf), Err(CodecError::GoAwayUriTooLong));
    }

    /// Draft-19 Section 10.2.8 (GROUP_ORDER): "The allowed values are Ascending
    /// (0x1) or Descending (0x2). If an endpoint receives a value outside this
    /// range, it MUST close the session with PROTOCOL_VIOLATION." Section
    /// 10.2.17 says the same of FORWARD with the values 0 and 1.
    ///
    /// Without `uint8_value_in_range` the out-of-range byte is handed up as an
    /// ordinary parameter:
    ///
    /// ```text
    /// assertion `left == right` failed
    ///   left: Ok(Subscribe(Subscribe { request_id: VarInt(1), track_namespace:
    ///         TrackNamespace([[97]]), track_name: [98], parameters:
    ///         [KeyValuePair { key: VarInt(34), value: Varint(VarInt(7)) }] }))
    ///  right: Err(InvalidField)
    /// ```
    #[test]
    fn a_uint8_parameter_outside_its_range_is_refused() {
        // key, rejected value, accepted value
        let cases = [(0x22u8, 7u8, 2u8), (0x10, 9, 1)];
        for (key, bad, good) in cases {
            let bytes = frame(0x03, &subscribe_body(&[0x01, key, bad]));
            let mut buf = &bytes[..];
            assert_eq!(
                ControlMessage::decode(&mut buf),
                Err(CodecError::ParameterValueOutOfRange { key: key as u64, value: bad as u64 }),
                "parameter 0x{key:x} value {bad}"
            );

            let bytes = frame(0x03, &subscribe_body(&[0x01, key, good]));
            let mut buf = &bytes[..];
            assert!(
                ControlMessage::decode(&mut buf).is_ok(),
                "parameter 0x{key:x} value {good} should still decode"
            );
        }
    }

    /// SUBSCRIBER_PRIORITY (0x20) is a uint8 with no restricted range, so it
    /// must keep accepting the whole 0-255 span. This is the negative half of
    /// the range check: a table that over-reached would fail here.
    #[test]
    fn subscriber_priority_still_accepts_the_whole_byte_range() {
        for value in [0u8, 1, 2, 128, 255] {
            let bytes = frame(0x03, &subscribe_body(&[0x01, 0x20, value]));
            let mut buf = &bytes[..];
            assert!(ControlMessage::decode(&mut buf).is_ok(), "priority {value}");
        }
    }

    fn param(key: u64, value: &[u8]) -> KeyValuePair {
        KeyValuePair { key: VarInt::from_u64_moqt(key), value: KvpValue::Bytes(value.to_vec()) }
    }

    /// Draft-19 Section 10.2.16: "The LARGEST_OBJECT parameter (Parameter Type
    /// 0x9) is a Location." Section 10.2 defines Location as "Two consecutive
    /// varints (Group, Object)" — the value carries no length of its own.
    ///
    /// The frame below is built from the draft rather than from this encoder:
    /// REQUEST_OK, four body bytes, one parameter, type delta `0x09`, then the
    /// two varints `0x0a` and `0x03` for Location (10, 3). A length-prefixed
    /// spelling would need a fifth byte.
    ///
    /// With `0x09` back in the Length-prefixed arm, the decoder reads the
    /// group varint `0x0a` as a value length of 10 and runs off the end of a
    /// four-byte body. Both this test and
    /// [`a_location_does_not_eat_the_block_that_follows_it`] fail with:
    ///
    /// ```text
    /// spec-correct frame must decode: UnexpectedEnd
    /// ```
    #[test]
    fn largest_object_is_two_bare_varints() {
        let body = [0x01, 0x09, 0x0a, 0x03];
        let bytes = frame(0x07, &body);

        let msg = ControlMessage::decode(&mut &bytes[..]).expect("spec-correct frame must decode");
        let ControlMessage::RequestOk(ok) = &msg else {
            panic!("expected REQUEST_OK, got {msg:?}")
        };
        assert_eq!(ok.parameters, vec![param(0x09, &[0x0a, 0x03])]);
        assert!(ok.track_properties.is_empty(), "the four body bytes are all parameter");

        let mut out = Vec::new();
        msg.encode(&mut out).expect("re-encode");
        assert_eq!(out, bytes, "the value must go back out as the two bare varints it came in as");
    }

    /// A Location value the encoder was handed but the decoder could not read
    /// back is refused on the way out, not written.
    ///
    /// LARGEST_OBJECT carries no length of its own — that is the whole point
    /// of the encoding — so `encode_parameters` writes its bytes verbatim. A
    /// value built in memory rather than decoded is under no obligation to be
    /// two varints, and without this check the codec answers `Ok(())` and puts
    /// a frame on the wire that `ControlMessage::decode` then refuses. One
    /// varint short and one varint long are the two ways to get it wrong.
    ///
    /// # What it catches
    ///
    /// Dropping the `is_location_value` guard from this draft's encode arm,
    /// run:
    ///
    /// ```text
    /// panicked at crates\moqtap-codec\src\draft19\message.rs:
    /// LARGEST_OBJECT of one varint must not encode: the decoder cannot read it back
    ///
    /// test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 108 filtered out
    /// ```
    ///
    /// The sibling draft kept its guard and kept passing, which is what shows
    /// the check is per-draft and not inherited from somewhere shared.
    #[test]
    fn a_location_value_that_is_not_two_varints_is_refused_on_encode() {
        for (label, value) in
            [("one varint", vec![0x0a]), ("three varints", vec![0x0a, 0x03, 0x05])]
        {
            let msg = ControlMessage::RequestOk(RequestOk {
                parameters: vec![param(0x09, &value)],
                track_properties: Vec::new(),
            });
            let mut out = Vec::new();
            assert!(
                msg.encode(&mut out).is_err(),
                "LARGEST_OBJECT of {label} must not encode: the decoder cannot read it back"
            );
        }

        // The well-formed value still goes out, so the check refuses the
        // malformed case and not the encoding itself.
        let msg = ControlMessage::RequestOk(RequestOk {
            parameters: vec![param(0x09, &[0x0a, 0x03])],
            track_properties: Vec::new(),
        });
        let mut out = Vec::new();
        msg.encode(&mut out).expect("a Location of exactly two varints must still encode");
        ControlMessage::decode(&mut &out[..]).expect("and must decode back");
    }

    /// The same Location read through a message that carries other fields
    /// after it, so a stray length byte cannot hide in a trailing block.
    ///
    /// SUBSCRIBE_OK is track alias `0x05`, then the parameters, then the track
    /// properties. With LARGEST_OBJECT (10, 3) and one property
    /// (OBJECT_DELIVERY_TIMEOUT, type `0x02`, 5000ms as the two-byte varint
    /// `0x93 0x88`), the body is `05 01 09 0a 03 02 93 88`.
    #[test]
    fn a_location_does_not_eat_the_block_that_follows_it() {
        let body = [0x05, 0x01, 0x09, 0x0a, 0x03, 0x02, 0x93, 0x88];
        let bytes = frame(0x04, &body);

        let msg = ControlMessage::decode(&mut &bytes[..]).expect("spec-correct frame must decode");
        let ControlMessage::SubscribeOk(ok) = &msg else {
            panic!("expected SUBSCRIBE_OK, got {msg:?}")
        };
        assert_eq!(ok.parameters, vec![param(0x09, &[0x0a, 0x03])]);
        assert_eq!(
            ok.track_properties,
            vec![KeyValuePair {
                key: VarInt::from_u64_moqt(0x02),
                value: KvpValue::Varint(VarInt::from_u64_moqt(5000)),
            }]
        );

        let mut out = Vec::new();
        msg.encode(&mut out).expect("re-encode");
        assert_eq!(out, bytes);
    }

    /// Draft-19 Section 10.2.19: the TRACK_NAMESPACE_PREFIX parameter
    /// (Parameter Type 0x34) "uses the Track Namespace encoding described in
    /// Section 2.4.1" — a varint field count followed by that many
    /// length-prefixed fields, and nothing in front of it. That encoding is not
    /// one of the four Section 10.2 lists, so it cannot be assumed to be
    /// Length-prefixed by default.
    ///
    /// The frame below is built from Section 2.4.1: REQUEST_UPDATE for request
    /// `7`, one parameter, type delta `0x34`, then the namespace ("live",
    /// "sports") as `02 04 "live" 06 "sports"`. Sixteen body bytes; a
    /// length-prefixed spelling would need a seventeenth for the outer length.
    ///
    /// With `0x34` back in the Length-prefixed arm the field count `0x02` is
    /// read as an outer length of two bytes, leaving eleven bytes of namespace
    /// unread. Draft-19's Section 10 body-length check turns that into a
    /// refusal rather than a truncated value:
    ///
    /// ```text
    /// spec-correct frame must decode: InvalidField
    /// ```
    ///
    /// That check is not a safety net here. Where the surplus lands inside the
    /// declared body — as in
    /// [`an_empty_track_namespace_prefix_is_one_zero_byte`], whose namespace is
    /// one byte long — the misread is silent, and that test fails instead with:
    ///
    /// ```text
    /// assertion `left == right` failed
    ///   left: [KeyValuePair { key: VarInt(52), value: Bytes([]) }]
    ///  right: [KeyValuePair { key: VarInt(52), value: Bytes([0]) }]
    /// ```
    #[test]
    fn track_namespace_prefix_is_a_bare_track_namespace() {
        let namespace: Vec<u8> = [&[0x02, 0x04][..], b"live", &[0x06][..], b"sports"].concat();
        assert_eq!(namespace.len(), 13);

        let body: Vec<u8> = [&[0x07, 0x01, 0x34][..], &namespace].concat();
        assert_eq!(body.len(), 16);
        let bytes = frame(0x02, &body);

        let msg = ControlMessage::decode(&mut &bytes[..]).expect("spec-correct frame must decode");
        let ControlMessage::RequestUpdate(update) = &msg else {
            panic!("expected REQUEST_UPDATE, got {msg:?}")
        };
        assert_eq!(update.request_id.into_inner(), 7);
        assert_eq!(update.parameters, vec![param(0x34, &namespace)]);

        let mut out = Vec::new();
        msg.encode(&mut out).expect("re-encode");
        assert_eq!(out, bytes, "no outer length may appear in front of the Track Namespace");
    }

    /// An empty prefix is a legal Track Namespace: Section 2.4.1 puts one at
    /// "between 0 and 32 Track Namespace Fields". On the wire that is the
    /// single byte `0x00`, and it must not be confused with a length-prefixed
    /// value of zero bytes.
    #[test]
    fn an_empty_track_namespace_prefix_is_one_zero_byte() {
        let body = [0x07, 0x01, 0x34, 0x00];
        let bytes = frame(0x02, &body);

        let msg = ControlMessage::decode(&mut &bytes[..]).expect("empty prefix must decode");
        let ControlMessage::RequestUpdate(update) = &msg else {
            panic!("expected REQUEST_UPDATE, got {msg:?}")
        };
        assert_eq!(update.parameters, vec![param(0x34, &[0x00])]);

        let mut out = Vec::new();
        msg.encode(&mut out).expect("re-encode");
        assert_eq!(out, bytes);
    }
}

#![cfg(feature = "draft16")]

//! Draft-16 rules the shipped vector corpus does not pin down.
//!
//! Each gate below observes a consequence — bytes on the wire, or the value a
//! decoder hands back — rather than reading a setting back out of the codec.
//! The failure text quoted in each docstring is the real output of running that
//! test with the rule removed, not a prediction.
//!
//! Two kinds of rule appear here, and the difference decides where each one is
//! enforced. A rule about bytes that cannot exist is applied in both
//! directions: an out-of-range stream Type, a descending parameter list, a
//! declared length that disagrees with its payload. A rule about a frame that
//! is well formed and merely non-conforming is applied to the writer alone, and
//! reported by a predicate on the way in — because a decoder that refused it
//! could not report the violation, and a codec that could not write it could
//! not reproduce a capture containing one. Extensions beside a non-Normal
//! Object Status are the second kind; drafts 17, 18 and 19 take the same
//! position, and `tests/draft19_object_properties_rule.rs` sets it out in full.

use bytes::Buf;
use moqtap_codec::draft16::data_stream::{
    DatagramHeader, SubgroupHeader, SubgroupObject, SubgroupObjectMeta, SubgroupObjectReader,
};
use moqtap_codec::draft16::message::*;
use moqtap_codec::draft16::types::ObjectStatus;
use moqtap_codec::error::CodecError;
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).unwrap()
}

/// A parameter with a varint value. Every type used below is even, so the value
/// is written bare and the pair is two fields on the wire.
/// A well-formed Token structure carrying `payload`.
///
/// The AUTHORIZATION TOKEN parameter's value is a Token, not opaque bytes: an
/// Alias Type followed by the fields that Alias Type promises. USE_VALUE (0x3)
/// is the shortest complete form - no Alias, a Token Type and the value - and
/// Token Type 0 is the one the drafts reserve for a meaning the two peers settle
/// out of band, so a fixture using it commits to nothing. Both integers are
/// below 0x40 and take one byte under either variable-length integer encoding,
/// which is what lets one helper serve every draft here.
///
/// Arbitrary bytes cannot stand in for a token. A value of this type that does
/// not decode as a Token is the case the drafts require a close over, so a
/// fixture built from arbitrary bytes would be testing the refusal rather than
/// the rule beside it.
fn token_value(payload: &[u8]) -> Vec<u8> {
    let mut value = vec![0x03, 0x00];
    value.extend_from_slice(payload);
    value
}

fn param(key: u64, value: u64) -> KeyValuePair {
    KeyValuePair { key: varint(key), value: KvpValue::Varint(varint(value)) }
}

/// A parameter with a length-prefixed value, for the odd types.
fn bytes_param(key: u64, value: &[u8]) -> KeyValuePair {
    KeyValuePair { key: varint(key), value: KvpValue::Bytes(value.to_vec()) }
}

fn encode(message: &ControlMessage) -> Result<Vec<u8>, CodecError> {
    let mut buf = Vec::new();
    message.encode(&mut buf)?;
    Ok(buf)
}

fn decode(bytes: &[u8]) -> Result<ControlMessage, CodecError> {
    ControlMessage::decode(&mut &bytes[..])
}

/// SUBSCRIBE_NAMESPACE is the carrier of choice for parameter gates: its only
/// other variable field is the prefix, so the parameter bytes sit at a known
/// place and a hand-written frame stays short.
fn subscribe_namespace(parameters: Vec<KeyValuePair>) -> ControlMessage {
    ControlMessage::SubscribeNamespace(SubscribeNamespace {
        request_id: varint(1),
        namespace_prefix: TrackNamespace(vec![b"ns".to_vec()]),
        subscribe_options: varint(0),
        parameters,
    })
}

fn publish_ok(parameters: Vec<KeyValuePair>) -> ControlMessage {
    ControlMessage::PublishOk(PublishOk { request_id: varint(3), parameters })
}

fn parameters_of(message: &ControlMessage) -> Vec<u64> {
    match message {
        ControlMessage::PublishOk(m) => &m.parameters,
        ControlMessage::SubscribeNamespace(m) => &m.parameters,
        ControlMessage::ClientSetup(m) => &m.parameters,
        ControlMessage::Fetch(m) => &m.parameters,
        ControlMessage::Publish(m) => &m.parameters,
        other => panic!("no parameter list on {other:?}"),
    }
    .iter()
    .map(|p| p.key.into_inner())
    .collect()
}

// ============================================================
// Key-Value-Pair Type delta encoding (Section 1.4.2)
// ============================================================

/// PUBLISH_OK carrying SUBSCRIBER_PRIORITY (0x20) then GROUP_ORDER (0x22),
/// delta-encoded. The second Type is written as the difference, 0x02.
///
/// This supersedes the committed vector
/// `transport/draft16/codec/messages/publish-ok.json` id `with-params`, whose
/// hex `1e000703022040402201` spells the second Type absolutely.
const PUBLISH_OK_TWO_PARAMETERS: &str = "1e000703022040400201";

/// The same two parameters written the way drafts 15 and earlier write them,
/// with both Types absolute. This is the committed vector's hex.
const PUBLISH_OK_TWO_PARAMETERS_ABSOLUTE: &str = "1e000703022040402201";

/// A second parameter's Type goes on the wire as a delta, not as itself.
///
/// Draft-16 Section 1.4.2: "Key-Value-Pairs encode a Type value as a delta from
/// the previous Type value, or from 0 if there is no previous Type value."
///
/// Writing absolute Types instead fails with:
///
/// ```text
/// assertion `left == right` failed: two parameters must be delta-encoded
///   left: "1e000703022040402201"
///  right: "1e000703022040400201"
/// ```
#[test]
fn a_second_parameter_type_is_written_as_a_delta_from_the_first() {
    let buf = encode(&publish_ok(vec![param(0x20, 64), param(0x22, 1)]))
        .expect("two ascending types are a legal list");
    assert_eq!(
        hex::encode(&buf),
        PUBLISH_OK_TWO_PARAMETERS,
        "two parameters must be delta-encoded",
    );
}

/// And a frame a conforming peer sent comes back as the Types that peer meant.
///
/// Reading absolute Types instead fails with:
///
/// ```text
/// assertion `left == right` failed: a delta of 0x02 after 0x20 is GROUP_ORDER
///   left: [32, 2]
///  right: [32, 34]
/// ```
#[test]
fn a_delta_encoded_frame_decodes_to_the_types_its_sender_meant() {
    let message = decode(&hex(PUBLISH_OK_TWO_PARAMETERS)).expect("a conforming frame");
    assert_eq!(
        parameters_of(&message),
        vec![0x20, 0x22],
        "a delta of 0x02 after 0x20 is GROUP_ORDER",
    );
}

/// The two encodings are distinguishable, which is what made the defect a wire
/// incompatibility rather than a cosmetic one.
///
/// The committed vector's bytes name Types 0x20 and 0x42 under this draft's
/// rules — 0x42 being a Type draft-16 assigns to nothing. A codec that reads
/// them as 0x20 and 0x22 is reading a draft-15 frame, and the two readings are
/// not merely different: one of them is a frame this draft requires a session to
/// close over. Section 9.2: "An endpoint that receives an unknown Message
/// Parameter MUST close the session with PROTOCOL_VIOLATION."
///
/// So a codec still reading absolute Types accepts these bytes and reports two
/// ordinary parameters, where a draft-16 codec ends the session. The failure is
/// visible from the far end of the connection, not just in a decoded struct.
///
/// Reading absolute Types instead fails with:
///
/// ```text
/// assertion `left == right` failed: 0x20 + 0x22 is 0x42, which this draft
/// defines nothing for
///   left: Ok(PublishOk(..))
///  right: Err(UnknownMessageParameter(66))
/// ```
#[test]
fn the_absolute_encoding_no_longer_names_the_types_it_used_to() {
    let refusal = decode(&hex(PUBLISH_OK_TWO_PARAMETERS_ABSOLUTE));
    assert!(
        matches!(refusal, Err(CodecError::UnknownMessageParameter(0x42))),
        "0x20 + 0x22 is 0x42, which this draft defines nothing for: {refusal:?}",
    );
}

/// The FETCH form of the same pair.
///
/// This supersedes the committed vector
/// `transport/draft16/codec/messages/fetch.json` id `with-params`, whose hex
/// `160018020101046c69766505766964656f00000a00022040802201` spells the second
/// Type absolutely. Only the one byte naming that Type differs, and it keeps
/// its width, so the declared payload length is unchanged.
const FETCH_TWO_PARAMETERS: &str = "160018020101046c69766505766964656f00000a00022040800201";

/// The second superseded vector, checked the same way.
#[test]
fn the_fetch_vector_with_two_parameters_is_delta_encoded_too() {
    let message = ControlMessage::Fetch(Fetch {
        request_id: varint(2),
        fetch_type: FetchType::Standalone,
        fetch_payload: FetchPayload::Standalone {
            track_namespace: TrackNamespace(vec![b"live".to_vec()]),
            track_name: b"video".to_vec(),
            start_group: varint(0),
            start_object: varint(0),
            end_group: varint(10),
            end_object: varint(0),
        },
        parameters: vec![param(0x20, 128), param(0x22, 1)],
    });
    let buf = encode(&message).expect("two ascending types are a legal list");
    assert_eq!(hex::encode(&buf), FETCH_TWO_PARAMETERS, "the FETCH vector is delta-encoded too");
    assert_eq!(decode(&buf).expect("reads back"), message);
}

/// Every message that carries parameters uses the same encoding, so a round
/// trip through this codec is stable on all of them.
#[test]
fn every_parameter_carrying_message_round_trips_two_types() {
    let namespace = TrackNamespace(vec![b"ns".to_vec()]);
    let two = || vec![param(0x20, 7), param(0x22, 1)];
    let messages = vec![
        ControlMessage::ClientSetup(ClientSetup {
            parameters: vec![param(0x02, 7), param(0x04, 1)],
        }),
        ControlMessage::RequestOk(RequestOk { request_id: varint(1), parameters: two() }),
        publish_ok(two()),
        subscribe_namespace(two()),
        ControlMessage::Subscribe(Subscribe {
            request_id: varint(1),
            track_namespace: namespace.clone(),
            track_name: b"t".to_vec(),
            parameters: two(),
        }),
        ControlMessage::TrackStatus(TrackStatus {
            request_id: varint(1),
            track_namespace: namespace.clone(),
            track_name: b"t".to_vec(),
            parameters: two(),
        }),
        ControlMessage::RequestUpdate(RequestUpdate {
            request_id: varint(1),
            existing_request_id: varint(1),
            parameters: two(),
        }),
        ControlMessage::PublishNamespace(PublishNamespace {
            request_id: varint(1),
            track_namespace: namespace.clone(),
            parameters: two(),
        }),
    ];
    for message in messages {
        let buf = encode(&message).unwrap_or_else(|e| panic!("{message:?} refused: {e:?}"));
        let back = decode(&buf).unwrap_or_else(|e| panic!("{message:?} did not read back: {e:?}"));
        assert_eq!(back, message, "what this codec wrote it must read");
    }
}

/// The Track Extensions run restarts the delta at 0 rather than continuing the
/// Parameters run before it.
///
/// Section 1.4.2 resets at "no previous Type value", and the two runs are
/// separate lists — the Parameters list is count-prefixed and the Track
/// Extensions run fills what is left of the payload. Continuing the count
/// across them writes the first extension's Type as a difference from the last
/// parameter's, which the peer resolves to something else entirely.
///
/// Seeding the extensions run with the last parameter's Type fails with:
///
/// ```text
/// ascending lists are legal: ParametersOutOfOrder(34, 2)
/// ```
///
/// and writing the run's Types absolutely fails with:
///
/// ```text
/// assertion `left == right` failed: the extensions run restarts the delta
///   left: [2, 5, 14, 9]
///  right: [2, 5, 12, 9]
/// ```
#[test]
fn a_track_extensions_run_restarts_the_delta() {
    let publish = ControlMessage::Publish(Publish {
        request_id: varint(1),
        track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
        track_name: b"t".to_vec(),
        track_alias: varint(1),
        parameters: vec![param(0x20, 7), param(0x22, 1)],
        track_extensions: vec![param(0x02, 5), param(0x0e, 9)],
    });
    let buf = encode(&publish).expect("ascending lists are legal");
    // The last four bytes are the extensions run: delta 0x02 then its value,
    // delta 0x0c then its value. A run continuing from the last parameter Type
    // could not spell the first of those at all, and an absolute run would
    // write 0x0e where the 0x0c is.
    assert_eq!(
        &buf[buf.len() - 4..],
        &[0x02, 0x05, 0x0c, 0x09],
        "the extensions run restarts the delta",
    );

    let back = decode(&buf).expect("what this codec wrote it must read");
    let ControlMessage::Publish(back) = back else { panic!("a PUBLISH decodes as one") };
    assert_eq!(
        back.track_extensions.iter().map(|e| e.key.into_inner()).collect::<Vec<_>>(),
        vec![0x02, 0x0e],
        "and the reader resolves the same Types",
    );
    assert_eq!(
        back.parameters.iter().map(|p| p.key.into_inner()).collect::<Vec<_>>(),
        vec![0x20, 0x22]
    );
}

/// A descending parameter list has no encoding and is refused before any byte
/// is written.
///
/// The delta is an unsigned difference. Encoding a descending pair anyway wraps
/// the subtraction and emits a nine-byte delta the peer resolves to an
/// unrelated Type.
///
/// Wrapping the subtraction into the varint range instead fails with:
///
/// ```text
/// a descending list has no delta encoding: Ok([30, 0, 14, 3, 2, 34, 1, 255,
/// 255, 255, 255, 255, 255, 255, 254, 64, 64])
/// ```
///
/// — a frame whose second parameter is announced by a nine-byte delta.
#[test]
fn a_descending_parameter_list_never_reaches_the_wire() {
    let result = encode(&publish_ok(vec![param(0x22, 1), param(0x20, 64)]));
    assert!(result.is_err(), "a descending list has no delta encoding: {result:?}");
}

/// A delta that would carry the running Type past what this draft can express
/// is refused rather than wrapped.
///
/// Section 1.4.2: "The previous Type value plus the Delta Type MUST NOT be
/// greater than 2^64 - 1. If a Delta Type is received that would be too large,
/// the Session MUST be closed with a PROTOCOL_VIOLATION."
///
/// The frame below is a PUBLISH_OK whose two parameters each carry the largest
/// delta a varint can spell. Resolving the second wraps a `u64` in a release
/// build and panics the addition in a debug one.
///
/// Wrapping the sum into the varint range instead fails with:
///
/// ```text
/// a delta past the end of the Type space is refused: Ok(PublishOk(PublishOk {
/// request_id: VarInt(1), parameters: [KeyValuePair { key:
/// VarInt(4611686018427387902), value: Varint(VarInt(0)) }, KeyValuePair { key:
/// VarInt(4611686018427387900), value: Varint(VarInt(0)) }] }))
/// ```
///
/// — the second parameter arriving under a Type *smaller* than the first, which
/// no ascending run can produce.
///
/// Of the two halves of the guard it is the varint range that fires on this
/// draft: replacing the checked add alone with a wrapping one still refuses the
/// frame, because a sum above the varint maximum has no draft-16 spelling. The
/// checked add covers the case the varint range cannot, a running sum that
/// wraps past 2^64 after enough pairs.
#[test]
fn a_delta_that_overruns_the_type_space_is_refused() {
    // request id 1, count = 2, then two deltas of 2^62 - 2 — the largest even value a varint
    // spells — each followed by the one-byte value an even Type takes. The
    // first resolves cleanly; the second carries the running Type to
    // 2^63 - 4, past anything this draft can express. Every field is present,
    // so a codec without the check decodes the frame rather than running out
    // of bytes.
    let mut payload = vec![0x01u8, 0x02];
    for _ in 0..2 {
        payload.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe]);
        payload.push(0x00);
    }
    let mut frame = vec![0x1eu8];
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(&payload);

    let result = decode(&frame);
    assert!(result.is_err(), "a delta past the end of the Type space is refused: {result:?}");
}

// ============================================================
// Subgroup and datagram Type validation (Sections 10.4.2, 10.3.1)
// ============================================================

/// Every subgroup header Type draft-16 Section 10.4.2 permits: the form
/// 0b00X1XXXX less the eight values whose SUBGROUP_ID_MODE is the reserved
/// 0b11.
fn valid_subgroup_types() -> Vec<u8> {
    (0x00u16..=0xff)
        .map(|t| t as u8)
        .filter(|t| t & 0xc0 == 0 && t & 0x10 != 0 && (t & 0x06) >> 1 != 0b11)
        .collect()
}

/// Every datagram Type draft-16 Section 10.3.1 permits: the form 0b00X0XXXX
/// less the eight values setting both STATUS and END_OF_GROUP.
fn valid_datagram_types() -> Vec<u8> {
    (0x00u16..=0xff)
        .map(|t| t as u8)
        .filter(|t| t & 0xd0 == 0 && !(t & 0x20 != 0 && t & 0x02 != 0))
        .collect()
}

/// Spare bytes appended to every hand-built header below, so a Type refusal is
/// never masked by the buffer running out.
const SLACK: &str = "8080808080808080";

/// A subgroup header whose fields match what `header_type` announces: alias 1,
/// group 0, an explicit Subgroup ID only when the mode asks for one, and a
/// priority byte unless DEFAULT_PRIORITY is set.
fn subgroup_header_bytes(header_type: u8) -> Vec<u8> {
    let mut s = format!("{header_type:02x}0100");
    if (header_type & 0x06) >> 1 == 2 {
        s.push_str("05");
    }
    if header_type & 0x20 == 0 {
        s.push_str("80");
    }
    s.push_str(SLACK);
    hex(&s)
}

/// A datagram whose fields match what `datagram_type` announces: alias 1, group
/// 2, an Object ID unless ZERO_OBJECT_ID is set, a priority byte unless
/// DEFAULT_PRIORITY is set, a one-byte extension block when EXTENSIONS is set,
/// and a Normal status when STATUS is set.
fn datagram_bytes(datagram_type: u8) -> Vec<u8> {
    let mut s = format!("{datagram_type:02x}0102");
    if datagram_type & 0x04 == 0 {
        s.push_str("03");
    }
    if datagram_type & 0x08 == 0 {
        s.push_str("80");
    }
    if datagram_type & 0x01 != 0 {
        s.push_str("01aa");
    }
    if datagram_type & 0x20 != 0 {
        s.push_str("00");
    }
    hex(&s)
}

/// A subgroup header Type wider than one byte no longer aliases onto a valid
/// one.
///
/// The Type was read as a full varint and narrowed to `u8`. The two-byte varint
/// `41 10` holds 0x110, which truncated to 0x10 — a valid header — so an
/// out-of-range Type was parsed as a stream rather than refused, and every byte
/// behind it was read under framing its sender never asked for.
///
/// Every Type Section 10.4.2 permits is below 0x40 and so is a one-byte varint,
/// which is what lets the Type be read as a single octet and checked.
///
/// Narrowing a decoded varint instead fails with:
///
/// ```text
/// a two-byte Type must not alias onto 0x10: 4110
/// ```
#[test]
fn a_subgroup_type_wider_than_one_byte_is_refused() {
    for spelling in ["4110", "80000110", "c000000000000110"] {
        let bytes = hex(&format!("{spelling}0100{SLACK}"));
        assert!(
            SubgroupHeader::decode(&mut &bytes[..]).is_err(),
            "a two-byte Type must not alias onto 0x10: {spelling}",
        );
    }
}

/// The eight reserved-mode subgroup Types are refused, and every other Type in
/// the form is accepted.
///
/// Section 10.4.2: "Type values with SUBGROUP_ID_MODE set to 0b11: 0x16, 0x17,
/// 0x1E, 0x1F, 0x36, 0x37, 0x3E, 0x3F. This mode is reserved for future use."
/// The mode is not merely unassigned — the other three modes each say whether a
/// Subgroup ID follows the Group ID, and 0b11 says nothing, so reading one
/// shifts every later field by the width of that varint.
///
/// Dropping the reserved-mode check fails with:
///
/// ```text
/// reserved SUBGROUP_ID_MODE 0b11: type 0x16
/// ```
///
/// Dropping the form check fails on the first out-of-form Type with:
///
/// ```text
/// outside the form 0b00X1XXXX: type 0x00
/// ```
#[test]
fn the_subgroup_types_the_draft_lists_as_invalid_are_refused() {
    let reserved = [0x16u8, 0x17, 0x1e, 0x1f, 0x36, 0x37, 0x3e, 0x3f];
    let valid = valid_subgroup_types();
    assert_eq!(valid.len(), 24, "24 of 256 byte values are valid subgroup Types");

    for t in 0x00u16..=0xff {
        let t = t as u8;
        let bytes = subgroup_header_bytes(t);
        let decoded = SubgroupHeader::decode(&mut &bytes[..]);
        if reserved.contains(&t) {
            assert!(decoded.is_err(), "reserved SUBGROUP_ID_MODE 0b11: type {t:#04x}");
        } else if valid.contains(&t) {
            assert!(decoded.is_ok(), "a Type in the form parses: type {t:#04x}");
        } else {
            assert!(decoded.is_err(), "outside the form 0b00X1XXXX: type {t:#04x}");
        }
    }
}

/// The checked subgroup encoder refuses exactly what the decoder refuses.
///
/// Without it the two halves disagree about which streams exist: a
/// reserved-mode header this codec wrote could not be read back by the same
/// codec.
///
/// Dropping the encode-side check fails with:
///
/// ```text
/// type 0x00 has no encoding: Ok(())
/// ```
#[test]
fn the_checked_subgroup_encoder_refuses_what_the_decoder_would() {
    for t in 0x00u16..=0xff {
        let t = t as u8;
        let header = SubgroupHeader {
            header_type: t,
            track_alias: varint(1),
            group_id: varint(0),
            subgroup_id: varint(0),
            // Matched to the Type byte's DEFAULT_PRIORITY bit, so this gate
            // holds on the Type alone. The gate below is the one that moves
            // them apart.
            publisher_priority: if t & 0x20 == 0 { Some(0x80) } else { None },
        };
        let mut buf = Vec::new();
        let written = header.encode_checked(&mut buf);
        if valid_subgroup_types().contains(&t) {
            assert!(written.is_ok(), "type {t:#04x} is one the draft permits: {written:?}");
        } else {
            assert!(written.is_err(), "type {t:#04x} has no encoding: {written:?}");
            assert!(buf.is_empty(), "a refused header leaves the buffer untouched");
        }
    }
}

/// The subgroup header's Priority byte is on the wire because the Type byte
/// says so, and `encode_checked` refuses a header whose two halves disagree.
///
/// Section 10.4.2: "The DEFAULT_PRIORITY bit (0x20) indicates when the Priority
/// field is present. When set to 1, the Priority field is omitted ... When set
/// to 0, the Priority field is present in the Subgroup header." One bit decides
/// it, and `decode` reads that bit — so an encoder driven by whether the Rust
/// `Option` happens to be `Some` writes a header its own decoder cannot read.
/// Both directions of the disagreement desync the stream rather than merely
/// losing a field: a stray byte is taken for the first Object's Object ID
/// Delta, and a missing one makes the reader take that Delta for the priority.
///
/// So this gate asks two things of the twenty-four Types the draft permits.
/// `encode` resolves the disagreement — the byte count follows the Type byte
/// whatever the `Option` holds, which is what keeps an infallible encoder from
/// emitting an unparseable stream — and `encode_checked` refuses it, because
/// the caller who set the wrong half is the only one who can fix it.
///
/// Driving `encode` off the `Option` fails with:
///
/// ```text
/// type 0x10 with None round-trips: Err(UnexpectedEnd)
/// ```
///
/// Dropping the `encode_checked` agreement check fails with:
///
/// ```text
/// type 0x10 with None is not what it says: Ok(())
/// ```
#[test]
fn a_subgroup_priority_byte_that_disagrees_with_its_type_is_refused() {
    for t in valid_subgroup_types() {
        // The half the Type byte does not ask for, in both directions.
        let wrong = if t & 0x20 == 0 { None } else { Some(0x80u8) };
        let header = SubgroupHeader {
            header_type: t,
            track_alias: varint(1),
            group_id: varint(0),
            subgroup_id: varint(0),
            publisher_priority: wrong,
        };

        let mut buf = Vec::new();
        header.encode(&mut buf);
        let mut rest = &buf[..];
        let back = SubgroupHeader::decode(&mut rest)
            .unwrap_or_else(|e| panic!("type {t:#04x} with {wrong:?} round-trips: Err({e:?})"));
        assert!(
            !rest.has_remaining(),
            "type {t:#04x} with {wrong:?} left {} stray byte(s) the peer reads as an Object ID Delta",
            rest.remaining()
        );
        assert_eq!(
            back.publisher_priority.is_some(),
            t & 0x20 == 0,
            "type {t:#04x}: the Priority field's presence follows the Type byte"
        );

        let mut buf = Vec::new();
        let written = header.encode_checked(&mut buf);
        assert!(written.is_err(), "type {t:#04x} with {wrong:?} is not what it says: {written:?}");
        assert!(buf.is_empty(), "a refused header leaves the buffer untouched");
    }
}

/// The datagram Types Section 10.3.1 lists as invalid are refused, and the 24
/// it permits are not.
///
/// The section forbids the eight values setting both STATUS (0x20) and
/// END_OF_GROUP (0x02) — "an object status message cannot signal end of group"
/// — and everything outside the form 0b00X0XXXX. That leaves 24 of 256, where
/// 232 were accepted before.
///
/// Dropping the validator fails with:
///
/// ```text
/// outside the form 0b00X0XXXX: type 0x10
/// ```
///
/// Dropping only the STATUS-plus-END_OF_GROUP half fails with:
///
/// ```text
/// STATUS and END_OF_GROUP together: type 0x22
/// ```
#[test]
fn the_datagram_types_the_draft_lists_as_invalid_are_refused() {
    let both_bits = [0x22u8, 0x23, 0x26, 0x27, 0x2a, 0x2b, 0x2e, 0x2f];
    let valid = valid_datagram_types();
    assert_eq!(valid.len(), 24, "24 of 256 byte values are valid datagram Types");

    for t in 0x00u16..=0xff {
        let t = t as u8;
        let bytes = datagram_bytes(t);
        let decoded = DatagramHeader::decode(&mut &bytes[..]);
        if both_bits.contains(&t) {
            assert!(decoded.is_err(), "STATUS and END_OF_GROUP together: type {t:#04x}");
        } else if valid.contains(&t) {
            assert!(decoded.is_ok(), "a Type in the form parses: type {t:#04x}: {decoded:?}");
        } else {
            assert!(decoded.is_err(), "outside the form 0b00X0XXXX: type {t:#04x}");
        }
    }
}

/// A datagram Type wider than one byte no longer aliases onto a valid one.
///
/// The same defect as on the subgroup header, and the same fix: every valid
/// datagram Type is below 0x40.
///
/// Narrowing a decoded varint instead fails with:
///
/// ```text
/// a wide Type must not alias onto 0x01: 4101
/// ```
#[test]
fn a_datagram_type_wider_than_one_byte_is_refused() {
    for spelling in ["4101", "4001", "80000001"] {
        let bytes = hex(&format!("{spelling}0102038001aa"));
        assert!(
            DatagramHeader::decode(&mut &bytes[..]).is_err(),
            "a wide Type must not alias onto 0x01: {spelling}",
        );
    }
}

// ============================================================
// Extensions against Object Status (Section 10.2.1.2)
// ============================================================

/// Build a one-object subgroup stream: header type 0x11 (extensions present,
/// mode 0b00, priority present), then one object.
fn subgroup_stream(extensions: &str, payload_length_and_tail: &str) -> Vec<u8> {
    let ext_len = extensions.len() / 2;
    hex(&format!("1101008000{ext_len:02x}{extensions}{payload_length_and_tail}"))
}

fn read_first_object(bytes: &[u8]) -> Result<SubgroupObject, CodecError> {
    let mut cursor = bytes;
    let header = SubgroupHeader::decode(&mut cursor)?;
    SubgroupObjectReader::new(&header).read_object(&mut cursor)
}

fn read_first_object_meta(bytes: &[u8]) -> Result<SubgroupObjectMeta, CodecError> {
    let mut cursor = bytes;
    let header = SubgroupHeader::decode(&mut cursor)?;
    SubgroupObjectReader::new(&header).read_object_meta(&mut cursor)
}

/// An Object whose status is not Normal may not carry extensions — and the
/// codec reports that rather than refusing to parse it.
///
/// Section 10.2.1.2: "Any Object with status Normal can have extension headers
/// (Section 2.5). If an endpoint receives extension headers on Objects with
/// status that is not Normal, it MUST close the session with a
/// PROTOCOL_VIOLATION".
///
/// Draft-16 is where the status set narrowed to Normal, End of Group and End of
/// Track, so the rule reaches two codes rather than the single Object Does Not
/// Exist that earlier drafts name — that status does not exist here at all.
///
/// The frame is well formed: the extension block sits between its length and
/// the status field and reads back byte for byte. So the rule is about what a
/// peer may send, not about what the bytes mean. A decoder that refused it
/// could not report the violation, and a writer that refused it could not
/// reproduce a capture containing one — including the committed
/// `transport/draft16/codec/data-streams/subgroup.json` vector
/// `subgroup-extensions-status-object`, hex `1101008000023c010003`, which is
/// exactly this frame. Drafts 17, 18 and 19 take the same position.
///
/// So both directions round-trip the bytes and `extensions_permitted` answers.
/// This test pins that split: the predicate must be able to say "no" while the
/// codec still carries the frame.
///
/// Making the predicate unconditional fails with:
///
/// ```text
/// an End of Group object with extensions is a violation to report
/// ```
///
/// and making the reader refuse the frame fails with:
///
/// ```text
/// the frame is well formed and must parse: InvalidField
/// ```
#[test]
fn extensions_on_a_non_normal_subgroup_object_parse_and_are_reported() {
    for (status, name) in [(0x03u8, "End of Group"), (0x04, "End of Track")] {
        let stream = subgroup_stream("3c01", &format!("00{status:02x}"));

        let object = read_first_object(&stream)
            .unwrap_or_else(|e| panic!("the frame is well formed and must parse: {e:?}"));
        assert_eq!(object.extension_headers, hex("3c01"), "and the block survives the trip");
        assert!(
            !object.extensions_permitted(),
            "an {name} object with extensions is a violation to report",
        );

        let meta = read_first_object_meta(&stream)
            .unwrap_or_else(|e| panic!("the meta reader parses it too: {e:?}"));
        assert!(
            !meta.extensions_permitted(),
            "and the meta reader reports it the same way on {name}",
        );
    }
}

/// The whole vector re-encodes byte for byte, which is the property a writer
/// that refused the frame would destroy.
///
/// Refusing it in `write_object` fails with:
///
/// ```text
/// a capture containing a violation must be reproducible: InvalidField
/// ```
#[test]
fn the_extensions_status_object_vector_round_trips_byte_for_byte() {
    let stream = hex("1101008000023c010003");
    let mut cursor: &[u8] = &stream;
    let header = SubgroupHeader::decode(&mut cursor).expect("type 0x11 is valid");
    let object = SubgroupObjectReader::new(&header)
        .read_object(&mut cursor)
        .expect("the frame is well formed");

    let mut buf = Vec::new();
    header.encode(&mut buf);
    SubgroupObjectReader::new(&header)
        .write_object(&object, &mut buf)
        .unwrap_or_else(|e| panic!("a capture containing a violation must be reproducible: {e:?}"));
    assert_eq!(hex::encode(&buf), "1101008000023c010003");
}

/// The subgroup writer carries the same frame, and the predicate still reports
/// it.
///
/// Deliberately not refused here, unlike the payload rule beside it: a status
/// next to a payload has no encoding at all, while extensions next to a status
/// encode fine. A writer that refused this could not reproduce a capture.
///
/// Making the writer refuse it fails with:
///
/// ```text
/// an End of Group object with extensions is writable: InvalidField
/// ```
#[test]
fn the_subgroup_writer_carries_a_non_normal_object_with_extensions() {
    let header = SubgroupHeader {
        header_type: 0x11,
        track_alias: varint(1),
        group_id: varint(0),
        subgroup_id: varint(0),
        publisher_priority: Some(0x80),
    };
    for (status, name) in
        [(ObjectStatus::EndOfGroup, "End of Group"), (ObjectStatus::EndOfTrack, "End of Track")]
    {
        let object = SubgroupObject {
            object_id: varint(0),
            extension_headers: hex("3c01"),
            payload_length: varint(0),
            object_status: Some(status),
            payload: Vec::new(),
        };
        assert!(
            !object.extensions_permitted(),
            "an {name} object with extensions is still a violation to report",
        );

        let mut buf = Vec::new();
        SubgroupObjectReader::new(&header)
            .write_object(&object, &mut buf)
            .unwrap_or_else(|e| panic!("an {name} object with extensions is writable: {e:?}"));
    }
}

/// A Normal object still carries its extensions, and so does one with a
/// payload. Without this the gates above would pass on a reader that refused
/// every extension block.
#[test]
fn extensions_on_a_normal_object_are_carried() {
    let with_status = subgroup_stream("3c01", "0000");
    let object = read_first_object(&with_status).expect("Normal permits extensions");
    assert_eq!(object.extension_headers, hex("3c01"));
    assert_eq!(object.object_status, Some(ObjectStatus::Normal));

    let with_payload = subgroup_stream("3c01", "04deadbeef");
    let object = read_first_object(&with_payload).expect("a payload object is Normal");
    assert_eq!(object.extension_headers, hex("3c01"));
    assert_eq!(object.payload, hex("deadbeef"));
}

/// A status datagram carrying extensions parses, reports, and cannot be
/// written by the checked encoder.
///
/// Section 10.2.1.2 reaches every carrier that can announce a status, and on
/// this draft a datagram is the other one. A plain datagram has no status field
/// and cannot break the rule.
///
/// The datagram is the carrier that has an `encode_checked`, so it is where the
/// two directions differ: reading one is how a tap reports the violation, while
/// writing one has no such excuse — a conforming peer answers with a
/// PROTOCOL_VIOLATION, so emitting it costs the session and not merely the
/// datagram.
///
/// Making the decoder refuse the frame fails with:
///
/// ```text
/// a well-formed datagram must parse: InvalidField
/// ```
///
/// Dropping the encode check fails with:
///
/// ```text
/// a status datagram with extensions has no encoding: Ok(())
/// ```
#[test]
fn extensions_on_a_status_datagram_parse_but_are_not_written() {
    // Type 0x21: STATUS bit and EXTENSIONS bit together.
    let bytes = hex("210102038002aabb03");
    let decoded = DatagramHeader::decode(&mut &bytes[..])
        .unwrap_or_else(|e| panic!("a well-formed datagram must parse: {e:?}"));
    assert_eq!(decoded.extension_headers, hex("aabb"), "and the block survives the trip");
    assert_eq!(decoded.object_status, Some(ObjectStatus::EndOfGroup));
    assert!(
        !decoded.extensions_permitted(),
        "a status datagram with extensions is a violation to report",
    );

    let mut buf = Vec::new();
    let written = decoded.encode_checked(&mut buf);
    assert!(written.is_err(), "a status datagram with extensions has no encoding: {written:?}");
    assert!(buf.is_empty(), "a refused datagram leaves the buffer untouched");
}

// ============================================================
// The datagram EXTENSIONS bit over an empty block (Section 10.3.1)
// ============================================================

/// A datagram announcing extensions must carry some, and the writer says so
/// before the bytes go out.
///
/// Section 10.3.1: "If an endpoint receives a datagram with the EXTENSIONS bit
/// set and an Extension Headers Length of 0, it MUST close the session with a
/// PROTOCOL_VIOLATION." The reader already refused such a datagram; the writer
/// spelled one happily, so this codec could emit a datagram it would then
/// decline to read.
///
/// Dropping the check fails with:
///
/// ```text
/// an empty block under a set EXTENSIONS bit has no encoding: Ok(())
/// ```
#[test]
fn a_datagram_announcing_extensions_over_an_empty_block_never_reaches_the_wire() {
    let header = DatagramHeader {
        datagram_type: 0x01,
        track_alias: varint(1),
        group_id: varint(2),
        object_id: varint(3),
        publisher_priority: Some(0x80),
        extension_headers: Vec::new(),
        object_status: None,
    };
    let mut buf = Vec::new();
    let written = header.encode_checked(&mut buf);
    assert!(
        written.is_err(),
        "an empty block under a set EXTENSIONS bit has no encoding: {written:?}"
    );
    assert!(buf.is_empty(), "a refused datagram leaves the buffer untouched");
}

/// And a datagram that carries extensions under the bit is written and reads
/// back. Without this the gate above would pass on an encoder that refused
/// every extension block.
#[test]
fn a_datagram_carrying_extensions_under_the_bit_round_trips() {
    let header = DatagramHeader {
        datagram_type: 0x01,
        track_alias: varint(1),
        group_id: varint(2),
        object_id: varint(3),
        publisher_priority: Some(0x80),
        extension_headers: hex("aabb"),
        object_status: None,
    };
    let mut buf = Vec::new();
    header.encode_checked(&mut buf).expect("a non-empty block is legal");
    let back = DatagramHeader::decode(&mut &buf[..]).expect("what this codec wrote it must read");
    assert_eq!(back.extension_headers, hex("aabb"));
}

/// The same shape is legal on a subgroup stream, and must stay legal.
///
/// This is the nuance the datagram rule does not carry over. Section 10.4.2:
/// "Objects with no extensions set Extension Headers Length to 0." The Type
/// byte is fixed for the whole stream, so an Object with no extensions has no
/// other way to say so — a zero-length block there is the encoding, not a
/// violation.
///
/// Applying the datagram rule to subgroups fails with:
///
/// ```text
/// a zero-length block is how a subgroup object says it has none:
/// Err(InvalidField)
/// ```
#[test]
fn a_subgroup_object_may_carry_a_zero_length_extension_block() {
    let stream = subgroup_stream("", "04deadbeef");
    let object = read_first_object(&stream);
    assert!(
        object.is_ok(),
        "a zero-length block is how a subgroup object says it has none: {object:?}",
    );
    assert!(object.unwrap().extension_headers.is_empty());

    let header = SubgroupHeader {
        header_type: 0x11,
        track_alias: varint(1),
        group_id: varint(0),
        subgroup_id: varint(0),
        publisher_priority: Some(0x80),
    };
    let object = SubgroupObject {
        object_id: varint(0),
        extension_headers: Vec::new(),
        payload_length: varint(4),
        object_status: None,
        payload: hex("deadbeef"),
    };
    let mut buf = Vec::new();
    SubgroupObjectReader::new(&header)
        .write_object(&object, &mut buf)
        .expect("and the writer spells it");
}

// ============================================================
// Discriminators (FETCH)
// ============================================================

fn fetch(fetch_type: FetchType, payload: FetchPayload) -> ControlMessage {
    ControlMessage::Fetch(Fetch {
        request_id: varint(2),
        fetch_type,
        fetch_payload: payload,
        parameters: Vec::new(),
    })
}

fn standalone_payload() -> FetchPayload {
    FetchPayload::Standalone {
        track_namespace: TrackNamespace(vec![b"live".to_vec()]),
        track_name: b"video".to_vec(),
        start_group: varint(0),
        start_object: varint(0),
        end_group: varint(10),
        end_object: varint(0),
    }
}

fn joining_payload() -> FetchPayload {
    FetchPayload::Joining { joining_request_id: varint(2), joining_start: varint(3) }
}

/// A FETCH whose Fetch Type disagrees with its body never reaches the wire.
///
/// The Fetch Type says which fields follow it. The encoder writes whatever the
/// body holds and the decoder reads whatever the type announces, so a message
/// that disagrees with itself does not survive its own round trip: a Standalone
/// type over a joining body puts a request id and a start where a namespace and
/// a name belong, and comes back as a fetch of a track named after two
/// integers.
///
/// Dropping the check fails with:
///
/// ```text
/// a Standalone type over a joining body has no encoding: Ok([22, 0, 5, 2, 1,
/// 2, 3, 0])
/// ```
///
/// and in the other direction with:
///
/// ```text
/// a joining type over a standalone body has no encoding: Ok([22, 0, 19, 2, 2,
/// 1, 4, 108, 105, 118, 101, 5, 118, 105, 100, 101, 111, 0, 0, 10, 0, 0])
/// ```
#[test]
fn a_fetch_whose_type_disagrees_with_its_body_never_reaches_the_wire() {
    let result = encode(&fetch(FetchType::Standalone, joining_payload()));
    assert!(result.is_err(), "a Standalone type over a joining body has no encoding: {result:?}");

    for joining in [FetchType::RelativeJoining, FetchType::AbsoluteJoining] {
        let result = encode(&fetch(joining, standalone_payload()));
        assert!(
            result.is_err(),
            "a joining type over a standalone body has no encoding: {result:?}",
        );
    }
}

/// A FETCH whose type and body agree is carried, in all three shapes. Without
/// this the gate above would pass on an encoder that refused every FETCH.
#[test]
fn a_fetch_whose_type_matches_its_body_is_carried() {
    let cases = [
        (FetchType::Standalone, standalone_payload()),
        (FetchType::RelativeJoining, joining_payload()),
        (FetchType::AbsoluteJoining, joining_payload()),
    ];
    for (fetch_type, payload) in cases {
        let message = fetch(fetch_type, payload);
        let buf = encode(&message).unwrap_or_else(|e| panic!("{fetch_type:?} refused: {e:?}"));
        assert_eq!(decode(&buf).expect("reads back"), message);
    }
}

// ============================================================
// SUBSCRIBE_NAMESPACE prefix field count (Section 9.25)
// ============================================================

/// A SUBSCRIBE_NAMESPACE may name a prefix of zero Track Namespace Fields.
///
/// Section 9.25: "Track Namespace Prefix: A Track Namespace structure as
/// described in Section 2.4.1 with between 0 and 32 Track Namespace Fields",
/// and its session-closing clause names only "greater than than 32 Track
/// Namespace Fields". The general rule in Section 2.4.1 closes the session on "0
/// or greater than 32", so the prefix is the one position where an empty
/// namespace is legal — it is the prefix that matches every namespace, which is
/// how a subscriber asks for all of them.
///
/// Holding the prefix to a one-field minimum on the encode side fails with:
///
/// ```text
/// a zero-field prefix is what asks for every namespace:
/// InvalidNamespaceTupleSize(0)
/// ```
///
/// and on the decode side with:
///
/// ```text
/// and the reader takes it back: InvalidNamespaceTupleSize(0)
/// ```
#[test]
fn a_subscribe_namespace_carries_a_zero_field_prefix() {
    let message = ControlMessage::SubscribeNamespace(SubscribeNamespace {
        request_id: varint(1),
        namespace_prefix: TrackNamespace(vec![]),
        subscribe_options: varint(0),
        parameters: Vec::new(),
    });
    let buf = encode(&message)
        .unwrap_or_else(|e| panic!("a zero-field prefix is what asks for every namespace: {e:?}"));
    let back = decode(&buf).unwrap_or_else(|e| panic!("and the reader takes it back: {e:?}"));
    assert_eq!(back, message);
}

/// A prefix holding a field of length zero is a different rule and stays
/// refused.
///
/// Section 2.4.1: "Each Track Namespace Field Value MUST contain at least one
/// byte. If an endpoint receives a Track Namespace Field with a Track Namespace
/// Field Length of 0, it MUST close the session with a PROTOCOL_VIOLATION."
/// Relaxing the field *count* to zero must not relax the field *length*.
///
/// Relaxing both together fails with:
///
/// ```text
/// a zero-length field has no encoding
/// ```
#[test]
fn a_zero_length_namespace_field_in_a_prefix_is_still_refused() {
    let message = ControlMessage::SubscribeNamespace(SubscribeNamespace {
        request_id: varint(1),
        namespace_prefix: TrackNamespace(vec![Vec::new()]),
        subscribe_options: varint(0),
        parameters: Vec::new(),
    });
    assert!(encode(&message).is_err(), "a zero-length field has no encoding");

    // request id 1, one field of length 0, options 0, no parameters.
    let frame = hex("1100050101000000");
    let decoded = decode(&frame);
    assert!(decoded.is_err(), "a zero-length field is a different rule: {decoded:?}");
}

// ============================================================
// FETCH_OK End Of Track (Section 9.17)
// ============================================================

/// FETCH_OK's End Of Track occupies exactly one byte.
///
/// Section 9.17 declares it `End Of Track (8)`. Read as a varint instead, the
/// value 0x40 and up consumes the bytes of the End Location behind it, and
/// every later field shifts.
///
/// The message below carries an End Of Track of 0xFF. As one octet that is the
/// byte 0xFF; as a varint it is the two bytes 0x40 0xFF, and 0xFF read back as
/// a varint announces an eight-byte integer that swallows the End Location
/// behind it. Values below 0x40 cannot tell the two encodings apart, and 0x40
/// itself round-trips by coincidence, so the gate needs a value above it.
///
/// Reading it as a varint fails with:
///
/// ```text
/// and read back as one: VarInt(UnexpectedEnd)
/// ```
///
/// and writing it as one fails with:
///
/// ```text
/// assertion `left == right` failed: End Of Track is written as one octet
///   left: 64
///  right: 255
/// ```
#[test]
fn fetch_ok_end_of_track_occupies_exactly_one_byte() {
    let message = ControlMessage::FetchOk(FetchOk {
        request_id: varint(1),
        end_of_track: 0xff,
        end_group: varint(5),
        end_object: varint(0),
        parameters: Vec::new(),
        track_extensions: Vec::new(),
    });
    let buf = encode(&message).expect("a FETCH_OK with any End Of Track byte");
    // type, two length bytes, request id, then the End Of Track octet.
    assert_eq!(buf[4], 0xff, "End Of Track is written as one octet");

    let back = decode(&buf).expect("and read back as one");
    let ControlMessage::FetchOk(back) = back else { panic!("a FETCH_OK decodes as one") };
    assert_eq!(back.end_of_track, 0xff, "End Of Track is one byte");
    assert_eq!(back.end_group.into_inner(), 5, "and the fields behind it do not shift");
}

// ============================================================
// Duplicate Parameter Types (Section 9.2)
// ============================================================

/// A type this codec cannot name. Draft-16 assigns nothing to 0x40 in either
/// parameter namespace.
const UNKNOWN_TYPE: u64 = 0x40;

/// The sender's rule names no exception for types the sender does not know.
///
/// Section 9.2: "Senders MUST NOT repeat the same parameter type in a message
/// unless the parameter definition explicitly allows multiple instances of that
/// type to be sent in a single message." A definition this codec has never seen
/// cannot have granted that permission, so a caller holding an unknown type
/// still may not send it twice.
///
/// This is the half that fails if someone makes the rule symmetric by narrowing
/// the encoder to match the decoder.
///
/// Narrowing the encoder to the receiver's rule fails with:
///
/// ```text
/// a sender may not repeat even an unknown type: Ok([17, 0, 12, 1, 1, 2, 110,
/// 115, 0, 2, 64, 64, 11, 0, 12])
/// ```
#[test]
fn a_sender_may_not_repeat_even_a_type_this_codec_cannot_name() {
    let result =
        encode(&subscribe_namespace(vec![param(UNKNOWN_TYPE, 11), param(UNKNOWN_TYPE, 12)]));
    assert!(result.is_err(), "a sender may not repeat even an unknown type: {result:?}");
}

/// The receiver's rule does have that exception, and it is a MUST.
///
/// Section 9.2: "Receivers MUST allow duplicates of unknown Setup Parameters."
/// Closing a session over a repeat of a type an extension defined is the one
/// thing the sentence forbids outright, where the duplicate check itself is
/// only a SHOULD.
///
/// This is the half that fails if someone makes the rule symmetric by widening
/// the decoder to match the encoder.
///
/// Widening the decoder to the sender's rule fails with:
///
/// ```text
/// a receiver must carry a repeat of a type it cannot name:
/// Err(DuplicateParameter(64))
/// ```
#[test]
fn a_receiver_carries_a_repeat_of_a_type_it_cannot_name() {
    // CLIENT_SETUP, two parameters, both type 0x40: a delta of 0x40 then a
    // delta of 0, each with a one-byte varint value.
    let frame = hex("2000060240400b000c");
    let decoded = decode(&frame);
    assert!(
        decoded.is_ok(),
        "a receiver must carry a repeat of a type it cannot name: {decoded:?}",
    );
    assert_eq!(parameters_of(&decoded.unwrap()), vec![UNKNOWN_TYPE, UNKNOWN_TYPE]);
}

/// A repeat of a type the draft does name is refused on receipt.
///
/// Section 9.2: "Receivers SHOULD check that there are no unexpected duplicate
/// parameters and close the session as a PROTOCOL_VIOLATION if found." Code
/// that scans a parameter list for a key takes whichever copy it meets first,
/// so one frame carrying two values for one type is read two ways by two
/// conforming implementations.
///
/// Dropping the receiver check fails with:
///
/// ```text
/// a repeated MAX_REQUEST_ID is not two parameters: Ok(ClientSetup(ClientSetup
/// { parameters: [KeyValuePair { key: VarInt(2), value: Varint(VarInt(11)) },
/// KeyValuePair { key: VarInt(2), value: Varint(VarInt(12)) }] }))
/// ```
#[test]
fn a_receiver_refuses_a_repeat_of_a_type_the_draft_names() {
    // CLIENT_SETUP, two parameters, both MAX_REQUEST_ID (0x02).
    let frame = hex("20000502020b000c");
    let decoded = decode(&frame);
    assert!(decoded.is_err(), "a repeated MAX_REQUEST_ID is not two parameters: {decoded:?}");

    // And a Message Parameter namespace type: PUBLISH_OK with GROUP_ORDER twice.
    let frame = hex("1e0006010222010001");
    let decoded = decode(&frame);
    assert!(decoded.is_err(), "a repeated GROUP_ORDER is not two parameters: {decoded:?}");
}

/// AUTHORIZATION TOKEN may repeat, in both directions.
///
/// Section 9.2.2.1: "The AUTHORIZATION TOKEN parameter MAY be repeated within a
/// message as long as the combination of Token Type and Token Value are unique
/// after resolving any aliases." Resolving aliases needs a session's token
/// cache, which a codec does not have, so both copies are carried and the
/// caller decides.
///
/// Removing the exemption fails with:
///
/// ```text
/// an AUTHORIZATION TOKEN may repeat: DuplicateParameter(3)
/// ```
#[test]
fn an_authorization_token_may_be_repeated() {
    let message = subscribe_namespace(vec![
        bytes_param(0x03, &token_value(b"first")),
        bytes_param(0x03, &token_value(b"second")),
    ]);
    let buf =
        encode(&message).unwrap_or_else(|e| panic!("an AUTHORIZATION TOKEN may repeat: {e:?}"));
    let back = decode(&buf).unwrap_or_else(|e| panic!("and reads back: {e:?}"));
    assert_eq!(back, message);
    assert_eq!(parameters_of(&back), vec![0x03, 0x03]);
}

/// The two namespaces are kept apart.
///
/// Section 9.2: "Setup Parameters use a namespace that is constant across all
/// MOQT versions. All other messages use a version-specific namespace. For
/// example, the integer '1' can refer to different parameters for Setup
/// messages and for all other message types."
///
/// PATH (0x01) is a Setup Parameter and nothing at all in the message
/// namespace, and this draft answers those two facts with two different
/// refusals. One frame's worth of bytes, read in either namespace, says which
/// registry the codec consulted:
///
/// - In a PUBLISH_OK, 0x01 is a Message Parameter type draft-16 does not define,
///   and Section 9.2 requires the session to close over it as unknown.
/// - In a CLIENT_SETUP, 0x01 is PATH, a type this draft does name, so the second
///   copy is refused as a repeat instead — "Senders MUST NOT repeat the same
///   parameter type in a message".
///
/// A codec holding one merged registry cannot produce both answers, and the
/// wrong one goes out on the wire as the reason the session ended.
///
/// This is also where the two namespaces stopped agreeing about unknown types at
/// all. Drafts 11 through 15 carry unknown parameters in both; draft-16 narrows
/// "Receivers MUST allow duplicates of unknown parameters" to "unknown Setup
/// Parameters" and adds the close in the same paragraph.
///
/// Merging the two registries fails with:
///
/// ```text
/// 0x01 is not a Message Parameter type this draft defines:
/// Err(DuplicateParameter(1))
/// ```
#[test]
fn the_setup_and_message_parameter_namespaces_are_kept_apart() {
    // PUBLISH_OK with type 0x01 twice: unknown in this namespace, refused as
    // unknown rather than as a repeat.
    let frame = hex("1e00080102010161000161");
    let decoded = decode(&frame);
    assert!(
        matches!(decoded, Err(CodecError::UnknownMessageParameter(1))),
        "0x01 is not a Message Parameter type this draft defines: {decoded:?}",
    );

    // The same repeat in a CLIENT_SETUP, where 0x01 is PATH and the repeat is
    // what the draft objects to.
    let frame = hex("20000702010161000161");
    let decoded = decode(&frame);
    assert!(
        matches!(decoded, Err(CodecError::DuplicateParameter(1))),
        "PATH is a Setup Parameter this draft names, so the repeat is the rule \
         it breaks: {decoded:?}",
    );
}

/// A list naming each type once is carried in both namespaces. Without this the
/// gates above would pass on a codec that refused every parameter list.
#[test]
fn a_list_that_names_each_type_once_is_carried() {
    let lists = vec![
        vec![],
        vec![param(0x20, 11)],
        vec![param(0x20, 11), param(0x22, 1)],
        vec![param(0x02, 5), bytes_param(0x03, &token_value(b"tok")), param(0x08, 9)],
    ];
    for parameters in lists {
        let message = subscribe_namespace(parameters.clone());
        let buf = encode(&message)
            .unwrap_or_else(|e| panic!("{} distinct types is a list: {e:?}", parameters.len()));
        assert_eq!(decode(&buf).expect("what this codec wrote it must read"), message);
    }
}

/// A whole stream still parses end to end after the type checks, so the gates
/// above are not passing because everything is refused.
#[test]
fn a_subgroup_stream_still_reads_its_objects() {
    let stream = hex("100100800004deadbeef0002cafe");
    let mut cursor: &[u8] = &stream;
    let header = SubgroupHeader::decode(&mut cursor).expect("type 0x10 is valid");
    let mut reader = SubgroupObjectReader::new(&header);
    let mut ids = Vec::new();
    while cursor.has_remaining() {
        ids.push(reader.read_object(&mut cursor).expect("objects parse").object_id.into_inner());
    }
    assert_eq!(ids, vec![0, 1]);
}

/// The two draft-16 renderer tables name exactly what draft-16 assigns, and
/// nothing a decoded message could not carry.
///
/// Draft-16 opened a second registry and moved three code points into it.
/// Section 13.2 Table 8 lists nine Message Parameters — 0x02, 0x03, 0x08, 0x09,
/// 0x10, 0x20, 0x21, 0x22, 0x32 — and Section 13.3 Table 9 lists the Extension
/// Headers, of which six are scoped Track: 0x02, 0x04, 0x0B, 0x0E, 0x22 and
/// 0x30. The numbers overlap and mean different things in each: 0x22 is
/// GROUP_ORDER as a Message Parameter and DEFAULT_PUBLISHER_GROUP_ORDER as an
/// Extension Header.
///
/// The Message Parameter renderer had three names too many, inherited from
/// draft-15 where those numbers really were Message Parameters. They were worse
/// than unused. Section 9.2 makes an unknown Message Parameter a session close
/// and `decode_parameters` applies it, so no decoded message can carry one of
/// the three — the names were reachable only for a parameter the same file had
/// already refused. The first half of this gate ties the two together: a type
/// the renderer names has to be a type a frame can actually arrive carrying.
///
/// The Track Extension renderer had three names too few — 0x0B, 0x22 and 0x30,
/// which is the whole of the Immutable Extensions block plus both extensions
/// draft-16 gives a value range to, and therefore both of the two this codec
/// closes the session over. The parameter a trace could not name was the one
/// most worth naming.
///
/// 0x3C and 0x3E are not asserted: Table 9 scopes them to Object, and this
/// renderer answers for a `track_extensions` field.
///
/// Dropping the trim fails with:
///
/// ```text
/// renderer names 0x4, decode_parameters refuses it
/// ```
///
/// Dropping the three added Track Extension names fails with:
///
/// ```text
/// draft-16 Table 9 scopes 0xb to Track, so the renderer names it
/// ```
#[test]
fn the_renderer_tables_are_the_two_registries_draft_16_assigns() {
    /// A value of the shape its Type defines.
    ///
    /// An even Type takes a bare varint and an odd one a length-prefixed
    /// value, and two odd Types are held to their contents as well: 0x03 is a
    /// Token and 0x21 a subscription filter, and a value that is not one is a
    /// session close before the renderer is ever reached. Everything else is
    /// opaque, so an empty value is the shape.
    fn value_for(key: u64) -> Vec<u8> {
        match key {
            // USE_VALUE (0x3) with Token Type 0 and no Token Value.
            0x03 => vec![0x03, 0x00],
            // LatestObject (0x2), which carries no further fields.
            0x21 => vec![0x02],
            // Every value range on an even Type admits 1.
            _ if key.is_multiple_of(2) => vec![0x01],
            _ => Vec::new(),
        }
    }

    fn kvp_value(key: u64) -> KvpValue {
        if key.is_multiple_of(2) {
            KvpValue::Varint(varint(1))
        } else {
            KvpValue::Bytes(value_for(key))
        }
    }

    /// Whether a SUBSCRIBE_OK carrying one parameter of this type decodes.
    fn a_frame_can_carry(key: u64) -> bool {
        let mut body = vec![0x01, 0x01, 0x01]; // Request ID, Track Alias, one parameter
                                               // The Type is a delta from zero, so it is the Type itself.
        VarInt::from_u64(key).unwrap().encode(&mut body);
        let value = value_for(key);
        if !key.is_multiple_of(2) {
            VarInt::from_usize(value.len()).encode(&mut body);
        }
        body.extend_from_slice(&value);

        let mut wire = vec![0x04];
        wire.extend_from_slice(&(body.len() as u16).to_be_bytes());
        wire.extend_from_slice(&body);
        ControlMessage::decode(&mut &wire[..]).is_ok()
    }

    /// The name this draft's renderer gives one parameter in `field`.
    fn name_of(field: &str, key: u64) -> Option<String> {
        let pair = KeyValuePair { key: varint(key), value: kvp_value(key) };
        let message = ControlMessage::SubscribeOk(SubscribeOk {
            request_id: varint(1),
            track_alias: varint(1),
            parameters: if field == "parameters" { vec![pair.clone()] } else { Vec::new() },
            track_extensions: if field == "track_extensions" { vec![pair] } else { Vec::new() },
        });
        let fields = moqtap_codec::draft16::fields::message_fields(&message);
        let Some(moqtap_codec::fields::FieldValue::Array(entries)) = fields.get(field) else {
            panic!("{field} renders as a list: {fields:?}");
        };
        let moqtap_codec::fields::FieldValue::Map(entry) = entries.first()? else {
            panic!("an entry renders as a map");
        };
        match entry.get("name") {
            Some(moqtap_codec::fields::FieldValue::Text(name)) => Some(name.clone()),
            _ => None,
        }
    }

    // Table 8, and no more. Every type the Message Parameter renderer names has
    // to be one a frame can arrive carrying, or the name is unreachable.
    for key in 0x00u64..0x40 {
        if name_of("parameters", key).is_some() {
            assert!(
                a_frame_can_carry(key),
                "renderer names {key:#x}, decode_parameters refuses it"
            );
        }
    }
    for key in [0x02u64, 0x03, 0x08, 0x09, 0x10, 0x20, 0x21, 0x22, 0x32] {
        assert!(
            name_of("parameters", key).is_some(),
            "draft-16 Table 8 assigns {key:#x}, so the renderer names it"
        );
    }

    // Table 9, Track scope. A separate table because the two registries reuse
    // numbers: 0x22 is named twice, above and below, and differently.
    for key in [0x02u64, 0x04, 0x0b, 0x0e, 0x22, 0x30] {
        assert!(
            name_of("track_extensions", key).is_some(),
            "draft-16 Table 9 scopes {key:#x} to Track, so the renderer names it"
        );
    }
    assert_eq!(
        name_of("track_extensions", 0x22).as_deref(),
        Some("default_publisher_group_order"),
        "0x22 is GROUP_ORDER among Message Parameters and this among Extension Headers"
    );
    assert_eq!(name_of("parameters", 0x22).as_deref(), Some("group_order"));
}

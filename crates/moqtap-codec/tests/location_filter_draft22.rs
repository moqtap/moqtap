#![cfg(feature = "draft22")]

//! Draft-22's LOCATION_FILTER, which is the one thing draft-22 changed on the
//! wire.
//!
//! Section 9.20.9 puts a `Location Filter Type` first in the value, and the
//! type names which `vi64` fields follow: none for 0x00 (no filter) and 0x05
//! (Next Object), then `StartGroup`, `StartObject`, `EndGroupDelta` and
//! `EndObject` in that order for 0x01 through 0x04. "Any other Location Filter
//! Type is a PROTOCOL_VIOLATION." Nothing on the wire states the value's
//! length, so the type is also the only thing that says where the next
//! parameter begins.
//!
//! # Why most of these tests are not small-valued
//!
//! With every field a one-byte `vi64`, draft-21's `Length` equals the field
//! count, and that is the draft-22 type naming the same fields: `21 01 03`,
//! `21 02 0a 03`, `21 03 0a 03 05` and `21 04 0a 03 05 07` decode to the same
//! filter under both drafts. A decoder that still read the byte as a length
//! passes every one of them. The tests that can tell the two apart are the
//! ones whose name says *discriminator*: Next Object, `{0, 0}`, a multi-byte
//! field, and a parameter after a filter that carries no fields.

use moqtap_codec::draft22::message::{
    decode_fill_parameters, decode_location_filter, location_filter_field_count,
    location_filter_types as T, parameter_in_scope, ControlMessage, MessageType, RequestOk,
    Subscribe, SubscribeTracks, FILL_PARAMETERS, LOCATION_FILTER,
};
use moqtap_codec::error::CodecError;
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;

fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).expect("fixture value fits a varint")
}

/// A SUBSCRIBE for `live`/`video`, request 1, whose parameter block is
/// `count` followed by `params` exactly as given.
fn subscribe_frame(count: u8, params: &[u8]) -> Vec<u8> {
    let mut body = vec![0x01, 0x01, 0x04];
    body.extend_from_slice(b"live");
    body.push(0x05);
    body.extend_from_slice(b"video");
    body.push(count);
    body.extend_from_slice(params);
    let mut frame = vec![0x03, 0x00, body.len() as u8];
    frame.extend_from_slice(&body);
    frame
}

fn decode(frame: &[u8]) -> Result<ControlMessage, CodecError> {
    ControlMessage::decode(&mut &frame[..])
}

fn encode(message: &ControlMessage) -> Result<Vec<u8>, CodecError> {
    let mut out = Vec::new();
    message.encode(&mut out)?;
    Ok(out)
}

fn subscribe_parameters(message: &ControlMessage) -> &[KeyValuePair] {
    match message {
        ControlMessage::Subscribe(s) => &s.parameters,
        other => panic!("expected SUBSCRIBE, got {other:?}"),
    }
}

/// The filter a decoded SUBSCRIBE carries, as `(type, fields)`.
fn filter_of(message: &ControlMessage) -> (u64, Vec<u64>) {
    let parameter = subscribe_parameters(message)
        .iter()
        .find(|p| p.key.into_inner() == LOCATION_FILTER)
        .expect("a LOCATION_FILTER parameter");
    match &parameter.value {
        KvpValue::Bytes(b) => decode_location_filter(b).expect("a stored filter reads back"),
        KvpValue::Varint(v) => panic!("LOCATION_FILTER stored as a bare varint {v:?}"),
    }
}

fn subscribe_with(parameters: Vec<KeyValuePair>) -> ControlMessage {
    ControlMessage::Subscribe(Subscribe {
        request_id: varint(1),
        track_namespace: TrackNamespace(vec![b"live".to_vec()]),
        track_name: b"video".to_vec(),
        parameters,
    })
}

fn filter_parameter(value: &[u8]) -> KeyValuePair {
    KeyValuePair { key: varint(LOCATION_FILTER), value: KvpValue::Bytes(value.to_vec()) }
}

/// Section 9.20.9's list, one row per type, and nothing past it.
#[test]
fn each_type_names_its_own_field_count() {
    let table = [
        (T::NONE, 0x00, 0),
        (T::RELATIVE_START, 0x01, 1),
        (T::ABSOLUTE_START, 0x02, 2),
        (T::ABSOLUTE_START_GROUP_END, 0x03, 3),
        (T::ABSOLUTE_RANGE, 0x04, 4),
        (T::NEXT_OBJECT, 0x05, 0),
    ];
    for (named, number, fields) in table {
        assert_eq!(named, number, "the constant for type {number:#04x}");
        assert_eq!(location_filter_field_count(number), Some(fields), "type {number:#04x}");
    }
    for unassigned in [0x06, 0x07, 0x40, 0x3fff, u64::MAX] {
        assert_eq!(location_filter_field_count(unassigned), None, "type {unassigned:#x}");
    }
}

/// Every type decodes to exactly its fields and re-encodes to the bytes it
/// came from.
#[test]
fn every_type_round_trips_through_a_subscribe() {
    let cases: [(&[u8], u64, &[u64]); 6] = [
        (&[0x21, 0x00], 0x00, &[]),
        (&[0x21, 0x01, 0x03], 0x01, &[3]),
        (&[0x21, 0x02, 0x0a, 0x03], 0x02, &[10, 3]),
        (&[0x21, 0x03, 0x0a, 0x03, 0x05], 0x03, &[10, 3, 5]),
        (&[0x21, 0x04, 0x0a, 0x03, 0x05, 0x07], 0x04, &[10, 3, 5, 7]),
        (&[0x21, 0x05], 0x05, &[]),
    ];
    for (params, filter_type, fields) in cases {
        let frame = subscribe_frame(1, params);
        let message = decode(&frame).unwrap_or_else(|e| panic!("type {filter_type}: {e:?}"));
        assert_eq!(filter_of(&message), (filter_type, fields.to_vec()), "type {filter_type}");
        assert_eq!(encode(&message).expect("re-encodes"), frame, "type {filter_type}");
    }
}

/// Discriminator: `21 02 00 00` is the absolute start `{0, 0}`, and Next Object
/// is `21 05`.
///
/// Draft-21 reads the first as the Next Object, because two zero fields were
/// how it spelled one. Draft-22 has a type for the Next Object, and Table 6
/// gives 0x02 as "absolute: {StartGroup, StartObject}" with no exception for
/// zero — so these are two different filters, the beginning of the track and
/// the object after Largest Object.
#[test]
fn discriminator_zero_zero_is_an_absolute_start_and_next_object_has_its_own_type() {
    let absolute = decode(&subscribe_frame(1, &[0x21, 0x02, 0x00, 0x00])).expect("decodes");
    assert_eq!(filter_of(&absolute), (T::ABSOLUTE_START, vec![0, 0]));

    let next_object = decode(&subscribe_frame(1, &[0x21, 0x05])).expect("decodes");
    assert_eq!(filter_of(&next_object), (T::NEXT_OBJECT, vec![]));

    assert_ne!(filter_of(&absolute), filter_of(&next_object));
}

/// Discriminator: a multi-byte field.
///
/// `21 02 80 0a 03` is an absolute start at `{10, 3}`: type 2, then a two-byte
/// `StartGroup` and a one-byte `StartObject`. A decoder reading the second
/// byte as draft-21's `Length` takes two bytes, finds the single field
/// `80 0a`, calls it a relative start and leaves the `03` to be misread as the
/// next parameter.
#[test]
fn discriminator_a_two_byte_field_is_one_field_not_two_bytes_of_length() {
    let frame = subscribe_frame(1, &[0x21, 0x02, 0x80, 0x0a, 0x03]);
    let message = decode(&frame).expect("decodes");
    assert_eq!(filter_of(&message), (T::ABSOLUTE_START, vec![10, 3]));

    let frame = subscribe_frame(1, &[0x21, 0x02, 0x83, 0xe8, 0x00]);
    let message = decode(&frame).expect("decodes");
    assert_eq!(filter_of(&message), (T::ABSOLUTE_START, vec![1000, 0]), "StartGroup 1000");
}

/// Discriminator: the fieldless types end where they begin, so the parameter
/// after them is read from the very next byte.
///
/// `21 05 01 02` is a Next Object filter and then GROUP_ORDER (type delta 1,
/// so 0x22) Descending. A decoder that read `05` as a length would swallow the
/// GROUP_ORDER and four bytes past the end of the message.
#[test]
fn discriminator_a_fieldless_type_is_followed_by_the_next_parameter() {
    for fieldless in [T::NEXT_OBJECT, T::NONE] {
        let frame = subscribe_frame(2, &[0x21, fieldless as u8, 0x01, 0x02]);
        let message = decode(&frame).unwrap_or_else(|e| panic!("type {fieldless}: {e:?}"));
        let parameters = subscribe_parameters(&message);
        assert_eq!(parameters.len(), 2, "type {fieldless}");
        assert_eq!(filter_of(&message), (fieldless, vec![]), "type {fieldless}");
        assert_eq!(parameters[1].key.into_inner(), 0x22, "type {fieldless}: GROUP_ORDER follows");
        assert_eq!(parameters[1].value, KvpValue::Varint(varint(2)), "type {fieldless}");
        assert_eq!(encode(&message).expect("re-encodes"), frame, "type {fieldless}");
    }
}

/// Discriminator: a type past 0x05 is a session close, and the value is never
/// read past the type.
#[test]
fn discriminator_an_unassigned_type_is_refused() {
    for (wire, filter_type) in
        [(vec![0x21, 0x06], 0x06), (vec![0x21, 0x40, 0x40], 0x40), (vec![0x21, 0xbf, 0xff], 0x3fff)]
    {
        assert_eq!(
            decode(&subscribe_frame(1, &wire)),
            Err(CodecError::InvalidFilterType(filter_type)),
            "type {filter_type:#x}"
        );
    }
}

/// A non-minimal type is still the type, and re-encodes minimally.
///
/// Section 8.1 permits a non-minimal `vi64` anywhere, the type included, so
/// `21 80 05` is a Next Object filter. The decoder stores the minimal form, so
/// the frame re-encodes as `21 05`: the vector is a non-canonical one rather
/// than one whose bytes survive a relay.
#[test]
fn a_non_minimal_type_decodes_and_re_encodes_minimally() {
    let frame = subscribe_frame(1, &[0x21, 0x80, 0x05]);
    let message = decode(&frame).expect("decodes");
    assert_eq!(filter_of(&message), (T::NEXT_OBJECT, vec![]));
    assert_eq!(encode(&message).expect("re-encodes"), subscribe_frame(1, &[0x21, 0x05]));
}

/// Fields that run past the message body are a malformed parameter, not a
/// short frame: the frame's own Length was honoured and the filter is what
/// does not fit inside it.
#[test]
fn fields_that_overrun_the_message_are_a_malformed_parameter() {
    for wire in [vec![0x21, 0x04, 0x0a, 0x03], vec![0x21, 0x01], vec![0x21]] {
        assert!(
            matches!(
                decode(&subscribe_frame(1, &wire)),
                Err(CodecError::SubscriptionFilterMalformed { .. })
            ),
            "{wire:02x?}"
        );
    }
}

/// Section 9.20.9: "If StartGroup + EndGroupDelta exceeds 2^64 - 1, the
/// endpoint MUST close the session with a PROTOCOL_VIOLATION." Only types 0x03
/// and 0x04 carry an `EndGroupDelta`, and both are held to it.
#[test]
fn an_end_group_past_the_number_space_is_refused_on_both_types_that_have_one() {
    let max = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    for (filter_type, tail) in [(0x03u8, vec![0x00, 0x01]), (0x04, vec![0x00, 0x01, 0x00])] {
        let mut wire = vec![0x21, filter_type];
        wire.extend_from_slice(&max);
        wire.extend_from_slice(&tail);
        assert_eq!(
            decode(&subscribe_frame(1, &wire)),
            Err(CodecError::FilterEndGroupOverflow { start_group: u64::MAX, delta: 1 }),
            "type {filter_type}"
        );
    }

    // The same StartGroup with a zero delta is the last group, and in range.
    let mut wire = vec![0x21, 0x03];
    wire.extend_from_slice(&max);
    wire.extend_from_slice(&[0x00, 0x00]);
    assert_eq!(
        filter_of(&decode(&subscribe_frame(1, &wire)).expect("in range")),
        (T::ABSOLUTE_START_GROUP_END, vec![u64::MAX, 0, 0])
    );
}

/// The encoder writes no length, so it refuses a value whose fields disagree
/// with its type: the receiver would read past the value into whatever came
/// next.
#[test]
fn the_encoder_refuses_a_value_that_is_not_its_own_type() {
    let malformed: [&[u8]; 4] = [
        // Type 2 with one field.
        &[0x02, 0x0a],
        // Type 5 with a field after it.
        &[0x05, 0x00],
        // Type 1 with two fields.
        &[0x01, 0x0a, 0x03],
        // Nothing at all.
        &[],
    ];
    for value in malformed {
        assert!(
            matches!(
                encode(&subscribe_with(vec![filter_parameter(value)])),
                Err(CodecError::SubscriptionFilterMalformed { .. })
            ),
            "{value:02x?}"
        );
    }

    assert_eq!(
        encode(&subscribe_with(vec![filter_parameter(&[0x06])])),
        Err(CodecError::InvalidFilterType(0x06))
    );
    assert!(matches!(
        encode(&subscribe_with(vec![KeyValuePair {
            key: varint(LOCATION_FILTER),
            value: KvpValue::Varint(varint(5)),
        }])),
        Err(CodecError::SubscriptionFilterMalformed { .. })
    ));
}

/// A filter inside FILL_PARAMETERS is the same type-led value, with no length
/// of its own: the outer FILL_PARAMETERS length bounds the nested block, and
/// nothing bounds the filter inside it but its type.
#[test]
fn a_filter_nested_in_fill_parameters_is_type_led_too() {
    // FILL_PARAMETERS (0x23), length 3: one nested parameter, type delta 0x21,
    // Next Object.
    let frame = subscribe_frame(1, &[0x23, 0x03, 0x01, 0x21, 0x05]);
    let message = decode(&frame).expect("decodes");
    let fill = &subscribe_parameters(&message)[0];
    assert_eq!(fill.key.into_inner(), FILL_PARAMETERS);
    let KvpValue::Bytes(nested) = &fill.value else { panic!("FILL_PARAMETERS is bytes") };
    let nested = decode_fill_parameters(nested).expect("the nested block reads");
    assert_eq!(nested.len(), 1);
    assert_eq!(nested[0].key.into_inner(), LOCATION_FILTER);
    assert_eq!(nested[0].value, KvpValue::Bytes(vec![0x05]));
    assert_eq!(encode(&message).expect("re-encodes"), frame);

    // An absolute start with a two-byte StartGroup. A FILL_PARAMETERS length
    // of 5 covers the count, the delta, the type and StartGroup and leaves
    // StartObject outside the block; 6 covers all of it.
    let frame = subscribe_frame(1, &[0x23, 0x05, 0x01, 0x21, 0x02, 0x80, 0x64, 0x00]);
    assert!(
        matches!(decode(&frame), Err(CodecError::SubscriptionFilterMalformed { .. })),
        "the nested filter's fields run past the FILL_PARAMETERS length"
    );
    let frame = subscribe_frame(1, &[0x23, 0x06, 0x01, 0x21, 0x02, 0x80, 0x64, 0x00]);
    let message = decode(&frame).expect("decodes");
    let KvpValue::Bytes(nested) = &subscribe_parameters(&message)[0].value else {
        panic!("FILL_PARAMETERS is bytes")
    };
    let nested = decode_fill_parameters(nested).expect("the nested block reads");
    let KvpValue::Bytes(filter) = &nested[0].value else { panic!("a filter is bytes") };
    assert_eq!(decode_location_filter(filter), Ok((T::ABSOLUTE_START, vec![100, 0])));

    // An unassigned type one level down is the same refusal.
    let frame = subscribe_frame(1, &[0x23, 0x03, 0x01, 0x21, 0x06]);
    assert_eq!(decode(&frame), Err(CodecError::InvalidFilterType(0x06)));
}

/// SUBSCRIBE_TRACKS carries a LOCATION_FILTER, which is Section 3.6.2's reading
/// and not Section 9.18's list; a REQUEST_OK carries none under either.
#[test]
fn a_subscribe_tracks_may_carry_a_filter_and_a_request_ok_may_not() {
    assert!(parameter_in_scope(LOCATION_FILTER, MessageType::SubscribeTracks));
    assert!(!parameter_in_scope(LOCATION_FILTER, MessageType::RequestOk));

    let tracks = ControlMessage::SubscribeTracks(SubscribeTracks {
        request_id: varint(1),
        namespace_prefix: TrackNamespace(vec![b"conference".to_vec()]),
        parameters: vec![filter_parameter(&[0x05])],
    });
    let wire = encode(&tracks).expect("SUBSCRIBE_TRACKS carries a filter");
    assert_eq!(decode(&wire), Ok(tracks));

    let ok = ControlMessage::RequestOk(RequestOk {
        parameters: vec![filter_parameter(&[0x05])],
        track_properties: vec![],
    });
    assert!(matches!(
        encode(&ok),
        Err(CodecError::ParameterOutOfScope { key: LOCATION_FILTER, .. })
    ));
}

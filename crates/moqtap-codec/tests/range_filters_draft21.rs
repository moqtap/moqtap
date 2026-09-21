//! Draft-21's Range Filters, and the two things about them that are easy to
//! get wrong in opposite directions.
//!
//! Section 3.3.2 — draft-19's Section 5.1.3, renumbered — gives five parameter
//! types, 0x25 through 0x29, one value shape, and three rules. The codepoints,
//! the field order and the delta arithmetic are all unchanged from draft-19;
//! what draft-21 did was replace the one-line shorthand with proper figures,
//! drop PUBLISH_OK from the list of messages the filters may appear in, and
//! permit 0x25 through 0x28 inside FILL_PARAMETERS. None of that moves a byte,
//! which is exactly why this file is a copy of the draft-19 one: a rule that
//! did not change is one a new draft still has to be held to. Every one of the three is answered with "MUST be rejected
//! with REQUEST_ERROR with error code INVALID_FILTER" — a reply, not a session
//! close, and not a refusal either.
//!
//! # The reading that is well formed and wrong
//!
//! "Start is delta encoded from the prior Range's End or from 0 for the first
//! Range, and End is delta encoded from the current Range's Start." Two
//! baselines named in one sentence, and the draft supplies its own worked
//! example of them. `the_drafts_own_worked_example_reads_back_as_the_ranges_it_names`
//! is that example: counting a Start from the prior Range's Start instead of its
//! End decodes the same four integers into two ranges that are wrong, in range,
//! and indistinguishable from correct output without the example beside them.
//!
//! # The refusal that must not happen
//!
//! `a_filter_this_module_cannot_read_does_not_refuse_the_frame` is the other
//! half. A delta that runs off the end of the space is something the endpoint
//! owes the subscriber a REQUEST_ERROR about, and a REQUEST_ERROR names the
//! Request ID of the request it answers — which the endpoint only has because
//! the frame decoded. Wiring the reader into `decode_parameters` would turn the
//! answer the draft requires into a frame the endpoint never saw.

#![cfg(feature = "draft21")]

use moqtap_codec::draft21::message::{ControlMessage, Subscribe};
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::range_filter::*;
use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::{Moqt18, VarInt};

fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).expect("fixture value fits a varint")
}

/// A Range Filter value: a SetID, an optional Property Type, then the integers
/// as they sit on the wire, already delta-encoded.
fn value(set_id: u8, property_type: Option<u64>, deltas: &[u64]) -> Vec<u8> {
    let mut out = vec![set_id];
    if let Some(property_type) = property_type {
        VarInt::from_u64_moqt(property_type).encode_moqt::<Moqt18>(&mut out);
    }
    for &delta in deltas {
        VarInt::from_u64_moqt(delta).encode_moqt::<Moqt18>(&mut out);
    }
    out
}

fn read(parameter_type: u64, bytes: &[u8]) -> Result<RangeFilter, RangeFilterError> {
    RangeFilter::decode_moqt::<Moqt18>(parameter_type, bytes)
}

/// The draft's own worked example, read back as the ranges it names.
///
/// Section 3.4: "For example, to express ranges 3-5 and 10-15: the first Start
/// is 3 (delta from 0), the first End is 2 (5 minus 3), the second Start is 5
/// (10 minus 5), and the second End is 5 (15 minus 10)."
///
/// # What it catches
///
/// The sentence names two different baselines in one line, and the plausible
/// misreading is to count a Start from the prior Range's *Start* rather than its
/// End. The same four integers then decode as 3-5 and 8-13. Both ranges are well
/// formed, both are plausible, and the second admits two values the subscriber
/// did not ask for while excluding two it did:
///
/// ```text
/// assertion `left == right` failed: a Start counts from the prior Range's End, not from its Start
///   left: [FilterRange { start: 3, end: Some(5) }, FilterRange { start: 8, end: Some(13) }]
///  right: [FilterRange { start: 3, end: Some(5) }, FilterRange { start: 10, end: Some(15) }]
/// ```
#[test]
fn the_drafts_own_worked_example_reads_back_as_the_ranges_it_names() {
    let filter = read(SUBGROUP_FILTER_PARAMETER, &value(0, None, &[3, 2, 5, 5]))
        .expect("the example is well formed");

    assert_eq!(
        filter.ranges,
        vec![FilterRange { start: 3, end: Some(5) }, FilterRange { start: 10, end: Some(15) },],
        "a Start counts from the prior Range's End, not from its Start",
    );

    // And the ranges answer what they were written to answer.
    for inside in [3, 4, 5, 10, 12, 15] {
        assert!(filter.passes(inside), "{inside} is inside 3-5 or 10-15");
    }
    for outside in [0, 2, 6, 9, 16] {
        assert!(!filter.passes(outside), "{outside} is in neither range");
    }
}

/// A final End left off means the range has no end.
///
/// "The final End in a sequence of Ranges can be omitted to indicate no end."
/// Three integers is one bounded range and one open one, and the open one has to
/// be the last: the omission is what tells a trailing Start from the next
/// Range's Start, so it works exactly once and at the end.
#[test]
fn a_final_end_left_off_leaves_the_range_open() {
    let filter = read(OBJECT_ID_FILTER_PARAMETER, &value(0, None, &[3, 2, 5]))
        .expect("an odd integer count is the open form");

    assert_eq!(
        filter.ranges,
        vec![FilterRange { start: 3, end: Some(5) }, FilterRange { start: 10, end: None }],
    );
    assert!(filter.passes(u64::MAX), "an open range has no upper bound");
    assert!(!filter.passes(9), "and still has a lower one");
}

/// The two property filters read a Property Type and the other three do not.
///
/// The prefix is one integer, and reading it for the wrong parameter type shifts
/// every Range in the value along by one — the first Start becomes the Property
/// Type, the first End becomes the first Start, and the filter that comes out is
/// a well-formed filter over the wrong numbers.
#[test]
fn only_the_two_property_filters_carry_a_property_type() {
    // The same integers under a header-field filter and under a property filter.
    let header_field = read(PRIORITY_FILTER_PARAMETER, &value(2, None, &[3, 2]))
        .expect("PRIORITY_FILTER carries no Property Type");
    assert_eq!(header_field.property_type, None);
    assert_eq!(header_field.set_id, 2);
    assert_eq!(header_field.ranges, vec![FilterRange { start: 3, end: Some(5) }]);

    let property = read(TRACK_PROPERTY_FILTER_PARAMETER, &value(2, Some(0x22), &[3, 2]))
        .expect("TRACK_PROPERTY_FILTER carries one");
    assert_eq!(property.property_type, Some(0x22));
    assert_eq!(property.set_id, 2);
    assert_eq!(property.ranges, vec![FilterRange { start: 3, end: Some(5) }]);

    // Reading the property filter's bytes as a header-field filter is the shift
    // this is about: the Property Type becomes the first Start.
    let misread = read(SUBGROUP_FILTER_PARAMETER, &value(2, Some(0x22), &[3, 2]))
        .expect("the bytes still parse, which is the hazard");
    assert_ne!(
        misread.ranges, property.ranges,
        "the same bytes under the wrong type must not silently agree",
    );
}

/// A delta past the end of the 64-bit space is reported rather than wrapped.
///
/// "Any delta encoding that results in a value that exceeds 2^64-1 MUST be
/// rejected with REQUEST_ERROR with error code INVALID_FILTER." Wrapping instead
/// is the dangerous failure: a Start of 2^64-1 plus a delta of 2 wraps to 1, and
/// a filter that reads as starting at 1 passes almost everything.
#[test]
fn a_delta_off_the_end_of_the_space_is_reported() {
    // First Start at the top of the space, then an End two past it.
    let bytes = value(0, None, &[u64::MAX, 2]);
    assert_eq!(
        read(SUBGROUP_FILTER_PARAMETER, &bytes),
        Err(RangeFilterError::DeltaOverflow { base: u64::MAX, delta: 2 }),
    );

    // And the same on a Start, counted from the previous End.
    let bytes = value(0, None, &[u64::MAX, 0, 1]);
    assert_eq!(
        read(SUBGROUP_FILTER_PARAMETER, &bytes),
        Err(RangeFilterError::DeltaOverflow { base: u64::MAX, delta: 1 }),
    );
}

/// A filter this module cannot read does not refuse the frame.
///
/// The rule this gates is a decision rather than a mechanism, which is why it is
/// asserted rather than assumed. Draft-21 answers a bad Range Filter with a
/// REQUEST_ERROR, and a REQUEST_ERROR names the Request ID of the request it
/// answers. An endpoint that refused the SUBSCRIBE at decode time would have
/// nothing to name and the subscriber would wait for a reply that no longer has
/// a subject.
///
/// # What it catches
///
/// Calling the reader from draft-21's `decode_parameters` — the shape the
/// LOCATION_FILTER check beside it has, because *that* rule is a session close.
/// The reader's error has no route into `CodecError`, so the ablation had to
/// invent one, which is itself the point: nothing in the crate can make this
/// mistake without adding a conversion that does not exist.
///
/// ```text
/// a Range Filter is carried whether or not it makes sense: InvalidField
/// ```
#[test]
fn a_filter_this_module_cannot_read_does_not_refuse_the_frame() {
    let message = ControlMessage::Subscribe(Subscribe {
        request_id: varint(1),
        track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
        track_name: b"t".to_vec(),
        parameters: vec![KeyValuePair {
            key: varint(SUBGROUP_FILTER_PARAMETER),
            // A delta that runs off the end of the space, which is one of the
            // three things Section 3.4 answers with a REQUEST_ERROR.
            value: KvpValue::Bytes(value(0, None, &[u64::MAX, 2])),
        }],
    });

    let mut wire = Vec::new();
    message.encode(&mut wire).expect("the encoder carries the value it is given");

    let decoded = ControlMessage::decode(&mut &wire[..])
        .expect("a Range Filter is carried whether or not it makes sense");

    // And the endpoint that now holds the request can find out why.
    let parameters = match &decoded {
        ControlMessage::Subscribe(m) => &m.parameters,
        other => panic!("the fixture is a SUBSCRIBE: {other:?}"),
    };
    assert_eq!(
        decode_all_moqt::<Moqt18>(parameters),
        Err(RangeFilterError::DeltaOverflow { base: u64::MAX, delta: 2 }),
        "the reason for the REQUEST_ERROR is available after the frame decodes",
    );
}

/// Every filter round-trips through the encoder byte for byte.
#[test]
fn a_filter_round_trips_through_the_encoder() {
    let cases = [
        (SUBGROUP_FILTER_PARAMETER, value(0, None, &[3, 2, 5, 5])),
        (OBJECT_ID_FILTER_PARAMETER, value(7, None, &[3, 2, 5])),
        (PRIORITY_FILTER_PARAMETER, value(255, None, &[0, 255])),
        (OBJECT_PROPERTY_FILTER_PARAMETER, value(1, Some(0x3C), &[10, 0])),
        (TRACK_PROPERTY_FILTER_PARAMETER, value(1, Some(0x22), &[1, 1])),
    ];
    for (parameter_type, bytes) in cases {
        let filter = read(parameter_type, &bytes).expect("the fixture is well formed");
        let mut out = Vec::new();
        filter.encode_moqt::<Moqt18>(&mut out).expect("what was read can be written");
        assert_eq!(out, bytes, "filter {parameter_type:#x} did not reproduce its own bytes");
    }
}

/// The encoder refuses what its own decoder would read back as something else.
#[test]
fn the_encoder_refuses_a_filter_it_would_not_read_back() {
    let open_in_the_middle = RangeFilter {
        parameter_type: SUBGROUP_FILTER_PARAMETER,
        set_id: 0,
        property_type: None,
        ranges: vec![FilterRange { start: 3, end: None }, FilterRange { start: 10, end: Some(15) }],
    };
    let mut out = Vec::new();
    assert_eq!(
        open_in_the_middle.encode_moqt::<Moqt18>(&mut out),
        Err(RangeFilterError::Malformed { detail: "only the final Range may be left open" }),
        "an open range in the middle pairs its successor's Start as its own End",
    );

    let backwards = RangeFilter {
        parameter_type: SUBGROUP_FILTER_PARAMETER,
        set_id: 0,
        property_type: None,
        ranges: vec![FilterRange { start: 10, end: Some(3) }],
    };
    let mut out = Vec::new();
    assert_eq!(
        backwards.encode_moqt::<Moqt18>(&mut out),
        Err(RangeFilterError::Malformed { detail: "a Range ends before it starts" }),
    );

    let property_type_on_a_header_filter = RangeFilter {
        parameter_type: SUBGROUP_FILTER_PARAMETER,
        set_id: 0,
        property_type: Some(0x22),
        ranges: Vec::new(),
    };
    let mut out = Vec::new();
    assert!(property_type_on_a_header_filter.encode_moqt::<Moqt18>(&mut out).is_err());
}

/// The Ranges are counted across every filter, not within one.
///
/// "which limits the total number of Ranges allowed in all Range Filter
/// parameters for a given subscription or fetch". A count kept per parameter
/// lets a peer spend the budget one parameter at a time and never exceed it.
#[test]
fn the_ranges_are_counted_across_every_filter() {
    let parameters = vec![
        KeyValuePair {
            key: varint(SUBGROUP_FILTER_PARAMETER),
            value: KvpValue::Bytes(value(0, None, &[3, 2, 5, 5])),
        },
        KeyValuePair {
            key: varint(OBJECT_ID_FILTER_PARAMETER),
            value: KvpValue::Bytes(value(0, None, &[1, 1, 1, 1, 1])),
        },
        // Not a Range Filter, and not counted.
        KeyValuePair { key: varint(0x10), value: KvpValue::Varint(varint(1)) },
    ];
    let filters = decode_all_moqt::<Moqt18>(&parameters).expect("both filters are well formed");
    assert_eq!(filters.len(), 2, "the FORWARD parameter is not a Range Filter");
    assert_eq!(total_ranges(&filters), 5, "two ranges in the first, three in the second");
}

/// A repeated key is found; a repeated type on its own is not one.
///
/// "The Track Property filter parameter MAY appear multiple times in a
/// SUBSCRIBE_TRACKS message" sits two paragraphs above the sentence that forbids
/// a repeat, so the parameter type alone cannot be the key. What repeats is the
/// combination with the SetID and, on the two property filters, the Property
/// Type.
#[test]
fn the_repeat_rule_is_about_the_whole_key_and_not_the_type() {
    let twice_with_different_properties = vec![
        RangeFilter {
            parameter_type: TRACK_PROPERTY_FILTER_PARAMETER,
            set_id: 0,
            property_type: Some(0x22),
            ranges: vec![FilterRange { start: 1, end: Some(2) }],
        },
        RangeFilter {
            parameter_type: TRACK_PROPERTY_FILTER_PARAMETER,
            set_id: 0,
            property_type: Some(0x30),
            ranges: vec![FilterRange { start: 0, end: Some(1) }],
        },
    ];
    assert_eq!(
        first_repeated_key(&twice_with_different_properties),
        None,
        "the same type twice is what the section permits",
    );

    let mut twice_with_the_same_key = twice_with_different_properties.clone();
    twice_with_the_same_key[1].property_type = Some(0x22);
    assert_eq!(
        first_repeated_key(&twice_with_the_same_key),
        Some((TRACK_PROPERTY_FILTER_PARAMETER, 0, Some(0x22))),
    );

    // The SetID is part of the key too, so the same type and property under two
    // sets is two filters and not a repeat.
    let mut twice_under_two_sets = twice_with_the_same_key.clone();
    twice_under_two_sets[1].set_id = 1;
    assert_eq!(first_repeated_key(&twice_under_two_sets), None);
}

/// A zero-length value is the removal form and not a malformation.
///
/// "In REQUEST_UPDATE, Length can be 0 to remove a filter parameter or non-zero
/// to replace that entire filter parameter including all sets and Property
/// Types."
#[test]
fn a_zero_length_value_is_the_removal_form() {
    let filter = read(TRACK_PROPERTY_FILTER_PARAMETER, &[]).expect("a removal is well formed");
    assert!(filter.ranges.is_empty());
    assert_eq!(filter.property_type, None, "a removal names no property to remove it from");
}

/// A priority range that names a value the field cannot hold is reported.
///
/// Section 9.20.13: "If a decoded value exceeds 255, the endpoint MUST reject
/// this with REQUEST_ERROR with error code INVALID_FILTER since Publisher
/// Priority is an 8-bit field."
///
/// The rule is about the decoded value and not the delta, which is what makes it
/// worth stating: 200 to 300 is written as the deltas 200 and 100, both of them
/// comfortably inside a byte.
#[test]
fn a_priority_range_above_the_field_is_reported() {
    assert_eq!(
        read(PRIORITY_FILTER_PARAMETER, &value(0, None, &[200, 100])),
        Err(RangeFilterError::PriorityAboveTheField(300)),
        "the End resolves to 300, which no Publisher Priority can be",
    );

    // The same numbers under a filter whose field is a full varint are ordinary.
    let subgroup = read(SUBGROUP_FILTER_PARAMETER, &value(0, None, &[200, 100]))
        .expect("a Subgroup ID is not an 8-bit field");
    assert_eq!(subgroup.ranges, vec![FilterRange { start: 200, end: Some(300) }]);

    // And the whole byte is still available.
    assert!(read(PRIORITY_FILTER_PARAMETER, &value(0, None, &[0, 255])).is_ok());
}

/// A property filter naming an odd Property Type is reported.
///
/// Sections 9.20.14 and 9.20.15: the Property Type "MUST be even, i.e. a single
/// integer value (see Figure 2), otherwise the endpoint MUST reject this with
/// REQUEST_ERROR with error code INVALID_FILTER".
///
/// The parity is the Key-Value-Pair convention: an even Type carries a bare
/// varint and an odd one carries bytes, so an odd Property Type names a property
/// whose value a range has nothing to compare against.
#[test]
fn a_property_filter_over_a_non_integer_property_is_reported() {
    for parameter_type in [OBJECT_PROPERTY_FILTER_PARAMETER, TRACK_PROPERTY_FILTER_PARAMETER] {
        assert_eq!(
            read(parameter_type, &value(0, Some(0x0B), &[1, 1])),
            Err(RangeFilterError::PropertyTypeIsNotAnInteger(0x0B)),
            "filter {parameter_type:#x} accepted an odd Property Type",
        );
        assert!(
            read(parameter_type, &value(0, Some(0x22), &[1, 1])).is_ok(),
            "filter {parameter_type:#x} refused an even one",
        );
    }
}

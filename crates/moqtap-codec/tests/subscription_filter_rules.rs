//! The subscription filter, and the rules that moved when it stopped being a
//! field.
//!
//! Every draft states the same sentence about the Filter Type and not the same
//! consequence. Drafts 07 through 13: "A filter type other than the above MUST
//! be treated as error" — no code, no close. Draft-14: "An endpoint that
//! receives a filter type other than the above MUST be close the session with
//! PROTOCOL_VIOLATION", missing word and all. Drafts 15 through 19 say the same
//! without the typo.
//!
//! # Where the value lives, which is the half that changed
//!
//! Through draft-14 the Filter Type is a field of SUBSCRIBE and its relatives,
//! and a decoder reads it because it has to know whether a Start Location and an
//! End Group follow. From draft-15 the whole group is one length-prefixed
//! parameter, and a codec that carries a parameter value as opaque bytes reads
//! none of it: the rule went from enforced to invisible without a word of either
//! draft changing.
//!
//! # And the End Group changed shape underneath it
//!
//! Drafts 15 and 16 write an End Group out in full. Drafts 17 and later write an
//! End Group Delta measured from the Start Location's Group, so the last group
//! in range is a sum rather than a field — and drafts 18 and 19 add "If the
//! resulting Group ID would be greater than 2^64 - 1, the endpoint MUST close
//! the session with a PROTOCOL_VIOLATION". Draft-17, which introduced the delta,
//! states no such sentence, and `draft17` below is what fails if the rule is
//! applied to the draft that does not have it.
//!
//! # The assigned set is not constant
//!
//! Drafts 07 and 08 assign 0x1 as Latest Group. Drafts 09 and 10 withdraw it and
//! list three types. Drafts 11 and later reinstate 0x1 as Next Group Start,
//! which begins one group later than the value it replaced. A decoder holding
//! all thirteen to the union would read a draft-09 SUBSCRIBE the draft requires
//! it to reject, and one holding them to the intersection would reject a
//! draft-11 SUBSCRIBE that is legal.
//!
//! # What is deliberately not here
//!
//! Drafts 15 and 16 say of AbsoluteRange that "End Group MUST specify the same
//! or a larger Group than specified in Start Location" and name no consequence
//! for receiving one that does not. A range that ends before it starts selects
//! nothing, but selecting nothing is not a close, and nothing in either draft
//! turns that MUST into one. `an_end_before_the_start_is_carried_where_no_draft
//! _answers_it` is what fails when a range check is added on the strength of the
//! word MUST alone.

#![cfg(all(
    feature = "draft08",
    feature = "draft09",
    feature = "draft11",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19"
))]

mod frames;

use moqtap_codec::error::CodecError;
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::subscription_filter::{
    FilterEnd, SubscriptionFilter, SUBSCRIPTION_FILTER_PARAMETER,
};
use moqtap_codec::types::{FilterType, Forward, GroupOrder, Location, TrackNamespace};
use moqtap_codec::varint::{Moqt17, Moqt18, MoqtProfile, VarInt};

fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).expect("fixture value fits a varint")
}

/// A filter value written with QUIC variable-length integers, as drafts 15 and
/// 16 write one.
fn quic_filter(values: &[u64]) -> Vec<u8> {
    let mut out = Vec::new();
    for value in values {
        varint(*value).encode(&mut out);
    }
    out
}

/// A filter value written with MoQT variable-length integers, as drafts 17 and
/// later write one. Unlike the QUIC form this reaches the whole 64-bit range,
/// which is what lets a fixture drive an End Group Delta past the end of it.
fn moqt_filter<P: MoqtProfile>(values: &[u64]) -> Vec<u8> {
    let mut out = Vec::new();
    for value in values {
        VarInt::from_u64_moqt(*value).encode_moqt::<P>(&mut out);
    }
    out
}

/// The same, decoded straight back with the reader drafts 18 and 19 use.
fn moqt18_filter(values: &[u64]) -> Result<SubscriptionFilter, CodecError> {
    SubscriptionFilter::decode_moqt::<Moqt18>(&moqt_filter::<Moqt18>(values))
}

/// The filter parameter, carrying `value` verbatim.
fn filter_parameter(value: Vec<u8>) -> KeyValuePair {
    KeyValuePair { key: varint(SUBSCRIPTION_FILTER_PARAMETER), value: KvpValue::Bytes(value) }
}

/// Largest Object (0x2), the shortest complete filter: one field and nothing
/// after it.
const LARGEST_OBJECT: u64 = 0x2;
/// AbsoluteStart (0x3), which puts a Start Location on the wire.
const ABSOLUTE_START: u64 = 0x3;
/// AbsoluteRange (0x4), which puts a Start Location and an End Group on it.
const ABSOLUTE_RANGE: u64 = 0x4;

// ── The structure, read directly ───────────────────────────

/// Each Filter Type carries exactly the fields it promises, in both spellings.
///
/// The two readers differ in the integer encoding and in what the last field
/// means, and in nothing else. Reading a draft-19 filter with the draft-15
/// reader is not a compile error and not a decode error either — the bytes
/// overlap for small values — so the difference has to be asserted rather than
/// assumed.
#[test]
fn a_filter_carries_the_fields_its_type_promises() {
    let largest = SubscriptionFilter::decode(&quic_filter(&[LARGEST_OBJECT])).expect("decodes");
    assert_eq!(largest.filter_type, FilterType::LargestObject);
    assert_eq!(largest.start_location, None, "an open-ended filter names no start");
    assert_eq!(largest.end_group, None, "an open-ended filter names no end");

    let start = SubscriptionFilter::decode(&quic_filter(&[ABSOLUTE_START, 4, 7])).expect("decodes");
    assert_eq!(start.start_location, Some(Location { group: varint(4), object: varint(7) }));
    assert_eq!(start.end_group, None, "AbsoluteStart is open ended");

    let range =
        SubscriptionFilter::decode(&quic_filter(&[ABSOLUTE_RANGE, 4, 7, 9])).expect("decodes");
    assert_eq!(range.end_group, Some(FilterEnd::Group(9)), "drafts 15 and 16 write it out");
    assert_eq!(range.last_group().expect("no addition to overflow"), Some(9));

    let delta = moqt18_filter(&[ABSOLUTE_RANGE, 4, 7, 9]).expect("decodes");
    assert_eq!(
        delta.end_group,
        Some(FilterEnd::GroupDelta(9)),
        "drafts 17 and later write a delta"
    );
    assert_eq!(
        delta.last_group().expect("4 plus 9 fits"),
        Some(13),
        "the same four bytes name group 9 on draft-16 and group 13 on draft-18"
    );
}

/// An End Group Delta of zero bounds the range to the group it starts in.
///
/// "If the specified End Group Delta is zero, the remainder of that Group passes
/// the filter." The value that means "one group" is the one that on drafts 15
/// and 16 would mean group zero, which is usually a range excluding its own
/// start.
#[test]
fn a_zero_delta_bounds_the_range_to_the_starting_group() {
    let filter = moqt18_filter(&[ABSOLUTE_RANGE, 12, 0, 0]).expect("decodes");
    assert_eq!(filter.last_group().expect("12 plus 0 fits"), Some(12));
}

/// A filter that ends before the fields its type promises is not a truncated
/// frame.
///
/// The parameter's declared length was satisfied and the frame is intact; what
/// ran out is the filter inside it. Reporting [`CodecError::UnexpectedEnd`]
/// would send the rule to a table arm that answers with no close, which is the
/// same failure the value ranges had before they were given a variant.
#[test]
fn a_filter_that_ends_early_is_a_malformed_filter_and_not_a_short_frame() {
    let got = SubscriptionFilter::decode(&quic_filter(&[ABSOLUTE_START, 4]));
    assert!(
        matches!(got, Err(CodecError::SubscriptionFilterMalformed { .. })),
        "an AbsoluteStart with half a Start Location must be a malformed filter, got {got:?}"
    );
    let empty = SubscriptionFilter::decode(&[]);
    assert!(
        matches!(empty, Err(CodecError::SubscriptionFilterMalformed { .. })),
        "an empty value carries no Filter Type at all, got {empty:?}"
    );
}

/// And neither is one the parameter outlives.
///
/// Bytes after the filter are the other half of the same sentence: "If the
/// length of the Subscription Filter does not match the parameter length". A
/// decoder that stops at the last field it wanted and ignores the rest accepts a
/// value the draft requires it to close over.
#[test]
fn bytes_after_the_filter_are_refused() {
    let got = SubscriptionFilter::decode(&quic_filter(&[LARGEST_OBJECT, 0]));
    assert!(
        matches!(got, Err(CodecError::SubscriptionFilterMalformed { .. })),
        "a trailing byte must be refused, got {got:?}"
    );
}

/// A Filter Type the drafts do not assign is its own refusal, not a
/// malformation.
///
/// The two are answered differently from draft-17 on — the Filter Type by
/// PROTOCOL_VIOLATION under Section 5.1.2 and the malformation by
/// KEY_VALUE_FORMATTING_ERROR under the general key-value rule — so a decoder
/// that reports both the same way closes the session with the wrong code half
/// the time.
#[test]
fn an_unassigned_filter_type_is_reported_as_a_filter_type() {
    for value in [0x00u64, 0x05, 0x63] {
        let got = SubscriptionFilter::decode(&quic_filter(&[value]));
        assert!(
            matches!(got, Err(CodecError::InvalidFilterType(v)) if v == value),
            "filter type {value} must be refused as a filter type, got {got:?}"
        );
    }
}

/// A range that ends before it starts is carried.
///
/// Drafts 15 and 16: "End Group MUST specify the same or a larger Group than
/// specified in Start Location." A MUST addressed to the sender, with no
/// sentence anywhere in either draft saying what a receiver does with one that
/// disobeys — unlike the Filter Type two bullets above it, which names
/// PROTOCOL_VIOLATION outright.
///
/// # What it catches, observed by making the change and running it
///
/// Adding `if end < start.group { return Err(...) }` to the decoder:
///
/// ```text
/// ---- an_end_before_the_start_is_carried_where_no_draft_answers_it stdout ----
///
/// thread 'an_end_before_the_start_is_carried_where_no_draft_answers_it' (76568) panicked at crates\moqtap-codec\tests\subscription_filter_rules.rs:238:5:
/// no draft states a consequence for a backwards range; refusing one closes sessions over a sentence that is not there: Err(SubscriptionFilterMalformed { detail: "its End Group is before its Start Location" })
/// ```
#[test]
fn an_end_before_the_start_is_carried_where_no_draft_answers_it() {
    let got = SubscriptionFilter::decode(&quic_filter(&[ABSOLUTE_RANGE, 9, 0, 4]));
    assert!(
        got.is_ok(),
        "no draft states a consequence for a backwards range; refusing one closes \
         sessions over a sentence that is not there: {got:?}"
    );
}

// ── The rule reaching a message ────────────────────────────

/// A SUBSCRIBE carrying `$parameters`, encoded, or the encoder's refusal.
///
/// Four of the five drafts with the filter parameter spell SUBSCRIBE this way;
/// draft-17 puts a Required Request ID Delta in front of the namespace and so
/// builds its own message where it needs one.
macro_rules! subscribe_result {
    ($draft:ident, $parameters:expr) => {{
        use moqtap_codec::$draft::message::*;
        let message = ControlMessage::Subscribe(Subscribe {
            request_id: varint(1),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            parameters: $parameters,
        });
        let mut out = Vec::new();
        message.encode(&mut out).map(|()| out)
    }};
}

macro_rules! subscribe_with {
    ($draft:ident, $parameters:expr) => {
        subscribe_result!($draft, $parameters).expect("the encoder writes a filter it can read")
    };
}

/// The frame this codec writes for a SUBSCRIBE carrying `$legal`, with the
/// filter rewritten to `$bad`.
///
/// The encoder will not write `$bad`: a value that is not the structure its Type
/// defines is one the receiver must close the session over, so writing it is not
/// a way to send it. That is the same rule these gates read from the receiver's
/// side, and it is gated from the sender's below. Everything ahead of the filter
/// is still the encoder's, and where the two filters are the same length so is
/// every length in the frame.
macro_rules! subscribe_carrying {
    ($draft:ident, $legal:expr, $bad:expr) => {
        frames::with_length_prefixed_value(
            &subscribe_with!($draft, vec![filter_parameter($legal.to_vec())]),
            $legal,
            $bad,
        )
    };
}

/// Drafts 15 and 16 refuse the filter parameter's own malformations.
///
/// The framing, the declared Length and the parameter block are all exactly
/// what this codec's encoder writes; the run of bytes inside the parameter is
/// rewritten afterwards, for the reason `subscribe_carrying` gives.
#[test]
fn drafts_15_and_16_read_the_filter_inside_the_parameter() {
    use moqtap_codec::draft15::message::ControlMessage as D15;
    use moqtap_codec::draft16::message::ControlMessage as D16;

    // Largest Object is the shortest complete filter, so it is what every frame
    // here is written around.
    let legal = quic_filter(&[LARGEST_OBJECT]);
    let unassigned = quic_filter(&[0x05]);
    let trailing = quic_filter(&[LARGEST_OBJECT, 0]);

    let frame = subscribe_carrying!(draft15, &legal, &unassigned);
    let got = D15::decode(&mut &frame[..]);
    assert!(
        matches!(got, Err(CodecError::InvalidFilterType(5))),
        "draft-15 must refuse an unassigned Filter Type inside the parameter, got {got:?}"
    );

    let frame = subscribe_carrying!(draft16, &legal, &unassigned);
    let got = D16::decode(&mut &frame[..]);
    assert!(
        matches!(got, Err(CodecError::InvalidFilterType(5))),
        "draft-16 must refuse an unassigned Filter Type inside the parameter, got {got:?}"
    );

    let frame = subscribe_carrying!(draft16, &legal, &trailing);
    let got = D16::decode(&mut &frame[..]);
    assert!(
        matches!(got, Err(CodecError::SubscriptionFilterMalformed { .. })),
        "draft-16 must refuse a filter shorter than its parameter, got {got:?}"
    );
}

/// An unassigned Filter Type is one the writer will not write either, on every
/// draft that carries the filter in a parameter.
///
/// The same sentence from the sender's side: "An endpoint that receives a filter
/// type other than the above MUST close the session with PROTOCOL_VIOLATION"
/// makes a filter this codec cannot read a message that ends the session, so
/// writing one is not a way to send it.
///
/// # What it catches
///
/// Dropping the `check_subscription_filters` call from a draft's parameter
/// encoder, which is where all five had it missing. The frame in the message is
/// the whole SUBSCRIBE the writer produced, ending in the parameter: type 0x21,
/// a value one byte long, and the byte 5:
///
/// ```text
/// draft-15 wrote an unassigned Filter Type: Ok([3, 0, 11, 1, 1, 2, 110, 115, 1, 116, 1, 33, 1, 5])
/// ```
#[test]
fn an_unassigned_filter_type_is_one_the_writer_will_not_write() {
    let quic = filter_parameter(quic_filter(&[0x05]));
    let moqt = filter_parameter(moqt_filter::<Moqt18>(&[0x05]));

    let draft17 = {
        use moqtap_codec::draft17::message::*;
        let message = ControlMessage::Subscribe(Subscribe {
            request_id: varint(1),
            required_request_id_delta: varint(0),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            parameters: vec![moqt.clone()],
        });
        let mut out = Vec::new();
        message.encode(&mut out).map(|()| out)
    };

    for (name, got) in [
        ("draft-15", subscribe_result!(draft15, vec![quic.clone()])),
        ("draft-16", subscribe_result!(draft16, vec![quic])),
        ("draft-17", draft17),
        ("draft-18", subscribe_result!(draft18, vec![moqt.clone()])),
        ("draft-19", subscribe_result!(draft19, vec![moqt])),
    ] {
        assert!(
            matches!(got, Err(CodecError::InvalidFilterType(5))),
            "{name} wrote an unassigned Filter Type: {got:?}"
        );
    }
}

/// Draft-17 carries an End Group Delta whose sum leaves the number space;
/// drafts 18 and 19 close over it.
///
/// This is the reversal in its sharpest form: one filter, byte for byte
/// identical apart from the varint profile, that a draft-17 endpoint must accept
/// and a draft-18 endpoint must close the session over. Draft-17 introduced the
/// delta and wrote no sentence about the sum; draft-18 added one.
///
/// # What it catches, observed by making the change and running it
///
/// Calling `last_group()` in draft-17's `check_subscription_filters`, which is
/// what applying the draft-18 rule to all three drafts looks like:
///
/// ```text
/// ---- the_overflow_rule_starts_at_draft_18 stdout ----
///
/// thread 'the_overflow_rule_starts_at_draft_18' (45272) panicked at crates\moqtap-codec\tests\subscription_filter_rules.rs:339:5:
/// draft-17 states no rule about the sum, so refusing one closes sessions a conforming peer may open: Err(FilterEndGroupOverflow { start_group: 18446744073709551615, delta: 1 })
/// ```
#[test]
fn the_overflow_rule_starts_at_draft_18() {
    use moqtap_codec::draft17::message::ControlMessage as D17;
    use moqtap_codec::draft18::message::ControlMessage as D18;
    use moqtap_codec::draft19::message::ControlMessage as D19;

    let over_17 = filter_parameter(moqt_filter::<Moqt17>(&[ABSOLUTE_RANGE, u64::MAX, 0, 1]));
    // The same filter with a delta of 0, which is the one drafts 18 and 19 will
    // write: the sum stays inside the range. The two deltas are varints of the
    // same length, so swapping them moves nothing else in the frame.
    let legal_18 = moqt_filter::<Moqt18>(&[ABSOLUTE_RANGE, u64::MAX, 0, 0]);
    let over_18 = moqt_filter::<Moqt18>(&[ABSOLUTE_RANGE, u64::MAX, 0, 1]);

    let frame = {
        use moqtap_codec::draft17::message::*;
        let message = ControlMessage::Subscribe(Subscribe {
            request_id: varint(1),
            required_request_id_delta: varint(0),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            parameters: vec![over_17],
        });
        let mut out = Vec::new();
        message.encode(&mut out).expect("the encoder writes the value it is given");
        out
    };
    let got = D17::decode(&mut &frame[..]);
    assert!(
        got.is_ok(),
        "draft-17 states no rule about the sum, so refusing one closes sessions a \
         conforming peer may open: {got:?}"
    );

    let frame = subscribe_carrying!(draft18, &legal_18, &over_18);
    let got = D18::decode(&mut &frame[..]);
    assert!(
        matches!(got, Err(CodecError::FilterEndGroupOverflow { delta: 1, .. })),
        "draft-18 must close over a sum that leaves the range, got {got:?}"
    );

    let frame = subscribe_carrying!(draft19, &legal_18, &over_18);
    let got = D19::decode(&mut &frame[..]);
    assert!(
        matches!(got, Err(CodecError::FilterEndGroupOverflow { delta: 1, .. })),
        "draft-19 must close over a sum that leaves the range, got {got:?}"
    );
}

/// The reversal reaches the writer as well: draft-17 writes the filter that
/// drafts 18 and 19 refuse to write.
///
/// The gate above is this pair read from the receiver's side. The rule about the
/// sum arrives in draft-18, so a draft-17 endpoint may send the filter and a
/// draft-18 endpoint may not — and a codec that applied one draft's rule to the
/// other would either refuse a message draft-17 permits or emit one draft-18
/// closes over.
///
/// # What it catches
///
/// Both halves, each observed by making the change and running it. Dropping the
/// `check_subscription_filters` call from draft-18's `encode_parameters`:
///
/// ```text
/// draft-18 wrote a sum that leaves the range: Ok([3, 0, 22, 1, 1, 2, 110, 115, 1, 116, 1, 33, 12, 4, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 1])
/// ```
///
/// And calling `last_group()` in draft-17's `check_subscription_filters`, which
/// is what applying draft-18's sentence to the draft that does not state it
/// looks like:
///
/// ```text
/// draft-17 states no rule about the sum, so refusing to write one refuses a message a conforming peer may send: Err(FilterEndGroupOverflow { start_group: 18446744073709551615, delta: 1 })
/// ```
#[test]
fn the_writer_follows_the_same_line_between_draft_17_and_draft_18() {
    let over_18 = filter_parameter(moqt_filter::<Moqt18>(&[ABSOLUTE_RANGE, u64::MAX, 0, 1]));

    let written = {
        use moqtap_codec::draft17::message::*;
        let message = ControlMessage::Subscribe(Subscribe {
            request_id: varint(1),
            required_request_id_delta: varint(0),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            parameters: vec![filter_parameter(moqt_filter::<Moqt17>(&[
                ABSOLUTE_RANGE,
                u64::MAX,
                0,
                1,
            ]))],
        });
        let mut out = Vec::new();
        message.encode(&mut out).map(|()| out)
    };
    assert!(
        written.is_ok(),
        "draft-17 states no rule about the sum, so refusing to write one refuses a \
         message a conforming peer may send: {written:?}"
    );

    for (name, got) in [
        ("draft-18", subscribe_result!(draft18, vec![over_18.clone()])),
        ("draft-19", subscribe_result!(draft19, vec![over_18])),
    ] {
        assert!(
            matches!(got, Err(CodecError::FilterEndGroupOverflow { delta: 1, .. })),
            "{name} wrote a sum that leaves the range: {got:?}"
        );
    }
}

/// A legal filter reaches the application on every draft that carries one.
///
/// The negative half of everything above. A check that refused more than the
/// drafts name would pass every test that asserts a refusal and fail this one.
#[test]
fn a_legal_filter_is_carried_on_every_draft_that_has_the_parameter() {
    let quic = filter_parameter(quic_filter(&[ABSOLUTE_RANGE, 4, 7, 9]));
    for (name, decoded) in [
        ("draft-15", {
            let frame = subscribe_with!(draft15, vec![quic.clone()]);
            moqtap_codec::draft15::message::ControlMessage::decode(&mut &frame[..]).is_ok()
        }),
        ("draft-16", {
            let frame = subscribe_with!(draft16, vec![quic.clone()]);
            moqtap_codec::draft16::message::ControlMessage::decode(&mut &frame[..]).is_ok()
        }),
        ("draft-18", {
            let frame = subscribe_with!(
                draft18,
                vec![filter_parameter(moqt_filter::<Moqt18>(&[ABSOLUTE_RANGE, 4, 7, 9]))]
            );
            moqtap_codec::draft18::message::ControlMessage::decode(&mut &frame[..]).is_ok()
        }),
        ("draft-19", {
            let frame = subscribe_with!(
                draft19,
                vec![filter_parameter(moqt_filter::<Moqt18>(&[ABSOLUTE_RANGE, 4, 7, 9]))]
            );
            moqtap_codec::draft19::message::ControlMessage::decode(&mut &frame[..]).is_ok()
        }),
    ] {
        assert!(decoded, "{name} must carry an AbsoluteRange filter its own draft describes");
    }
}

/// The filter check does not reach into a SETUP.
///
/// The two parameter namespaces are separate, and a setup 0x21 is not this
/// parameter. A check applied to both would refuse a SETUP over a type the setup
/// registry never assigned this meaning.
///
/// Both drafts that carry the filter as a parameter with the QUIC integer
/// encoding, and both sides of each. The encoder has to reach the setup-namespace
/// path, which leaves the version-specific value rules out; pointing a SETUP arm
/// at the message-namespace encoder fails here with:
///
/// ```text
/// a setup 0x21 is not the filter parameter: InvalidFilterType(5)
/// ```
#[test]
fn the_filter_rule_does_not_reach_into_a_setup() {
    let unassigned = filter_parameter(quic_filter(&[0x05]));

    let d15 = {
        use moqtap_codec::draft15::message::*;
        let message =
            ControlMessage::ClientSetup(ClientSetup { parameters: vec![unassigned.clone()] });
        let mut out = Vec::new();
        message.encode(&mut out).expect("a setup 0x21 is not the filter parameter");
        ControlMessage::decode(&mut &out[..]).is_ok()
    };
    assert!(d15, "draft-15: 0x21 in the setup namespace carries no filter");

    let d16 = {
        use moqtap_codec::draft16::message::*;
        let message = ControlMessage::ClientSetup(ClientSetup { parameters: vec![unassigned] });
        let mut out = Vec::new();
        message.encode(&mut out).expect("a setup 0x21 is not the filter parameter");
        ControlMessage::decode(&mut &out[..]).is_ok()
    };
    assert!(d16, "draft-16: 0x21 in the setup namespace carries no filter");
}

// ── The field form, and the set that moves under it ────────

/// Draft-14 refuses an unassigned Filter Type as a Filter Type.
///
/// The field form of the same rule, on the one draft that carries the field and
/// states the close. Its refusal has to be nameable for the session table to
/// answer it; reported as the shared malformed-field variant it was detected and
/// unroutable, which is the state every draft from 07 to 14 was in.
#[test]
fn draft_14_names_the_filter_type_it_refuses() {
    use moqtap_codec::draft14::message::*;

    let message = ControlMessage::Subscribe(Subscribe {
        request_id: varint(1),
        track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
        track_name: b"t".to_vec(),
        subscriber_priority: 128,
        group_order: GroupOrder::Ascending,
        forward: Forward::Forward,
        filter_type: FilterType::LargestObject,
        start_location: None,
        end_group: None,
        parameters: Vec::new(),
    });
    let mut out = Vec::new();
    message.encode(&mut out).expect("a Largest Object filter is legal on draft-14");

    // The Filter Type is the byte after subscriber priority, group order and
    // forward, which the encoder has just written as 0x02.
    let position = out.iter().rposition(|b| *b == 0x02).expect("the filter type is on the wire");
    out[position] = 0x07;

    let got = ControlMessage::decode(&mut &out[..]);
    assert!(
        matches!(got, Err(CodecError::InvalidFilterType(7))),
        "draft-14 must name the filter type it refuses, got {got:?}"
    );
}

/// Filter Type 0x1 is legal on draft-08, absent on draft-09, and legal again on
/// draft-11 meaning something else.
///
/// Drafts 07 and 08 call it Latest Group — "an open-ended subscription with
/// objects from the beginning of the current group". Drafts 09 and 10 list three
/// filters and do not assign 0x1 at all. Drafts 11 and later call it Next Group
/// Start, which begins one group later. Same number, three positions, and a
/// decoder built from any one of them is wrong on the other two.
#[test]
fn filter_type_one_leaves_and_comes_back_meaning_something_else() {
    // Draft-08 and draft-09 lay SUBSCRIBE out identically, so one frame written
    // by draft-08's encoder is a well-formed draft-09 SUBSCRIBE in every respect
    // but the one value the two drafts disagree about.
    let frame = {
        use moqtap_codec::draft08::message::*;
        let message = ControlMessage::Subscribe(Subscribe {
            subscribe_id: varint(1),
            track_alias: varint(2),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            filter_type: FilterType::NextGroupStart,
            start_location: None,
            end_group: None,
            parameters: Vec::new(),
        });
        let mut out = Vec::new();
        message.encode(&mut out).expect("Latest Group is legal on draft-08");
        out
    };

    let d08 = moqtap_codec::draft08::message::ControlMessage::decode(&mut &frame[..]);
    assert!(d08.is_ok(), "draft-08 assigns 0x1 as Latest Group: {d08:?}");

    let d09 = moqtap_codec::draft09::message::ControlMessage::decode(&mut &frame[..]);
    assert!(
        matches!(d09, Err(CodecError::InvalidFilterType(1))),
        "draft-09 lists three filter types and 0x1 is not one of them: {d09:?}"
    );
}

// ── Writing one, which is the other half of the same rule ──

/// A filter written into a parameter and read back out is the filter that went
/// in, in both spellings.
///
/// The writer exists because from draft-15 a caller asking for a range hands its
/// endpoint a parameter list rather than a Filter Type and a Start Location, so
/// the bytes inside the parameter are the caller's to assemble. Assembling them
/// by hand is what `subscribe_filter_range` in the client exists to stop one
/// layer up.
#[test]
fn a_filter_survives_the_parameter_it_is_written_into() {
    let quic = SubscriptionFilter {
        filter_type: FilterType::AbsoluteRange,
        start_location: Some(Location { group: varint(4), object: varint(7) }),
        end_group: Some(FilterEnd::Group(9)),
    };
    let parameters = vec![quic.parameter().expect("a complete AbsoluteRange is writable")];
    assert_eq!(
        SubscriptionFilter::from_parameters(&parameters).expect("the parameter is present"),
        Ok(quic)
    );

    let moqt = SubscriptionFilter {
        filter_type: FilterType::AbsoluteRange,
        start_location: Some(Location { group: varint(4), object: varint(7) }),
        end_group: Some(FilterEnd::GroupDelta(9)),
    };
    let parameters = vec![moqt.parameter_moqt::<Moqt18>().expect("writable")];
    assert_eq!(
        SubscriptionFilter::from_parameters_moqt::<Moqt18>(&parameters)
            .expect("the parameter is present"),
        Ok(moqt)
    );

    assert_eq!(
        SubscriptionFilter::from_parameters(&[]),
        None,
        "no filter parameter is an unfiltered subscription, not a malformed one"
    );
}

/// A filter whose fields disagree with its own Filter Type is not written.
///
/// The decoder derives presence from the Filter Type, so a surplus field is
/// written out and read back short and a missing one is written short and read
/// back out of whatever follows it. Both produce a frame this codec's own reader
/// refuses, which is the failure the client's `subscribe` had before it stopped
/// taking a Filter Type it could not serve.
#[test]
fn a_filter_that_contradicts_its_own_type_is_not_written() {
    let missing_start = SubscriptionFilter {
        filter_type: FilterType::AbsoluteStart,
        start_location: None,
        end_group: None,
    };
    assert!(
        matches!(missing_start.parameter(), Err(CodecError::SubscriptionFilterMalformed { .. })),
        "AbsoluteStart promises a Start Location"
    );

    let surplus_end = SubscriptionFilter {
        filter_type: FilterType::LargestObject,
        start_location: None,
        end_group: Some(FilterEnd::Group(9)),
    };
    assert!(
        matches!(surplus_end.parameter(), Err(CodecError::SubscriptionFilterMalformed { .. })),
        "Largest Object is open ended and promises no End Group"
    );

    let wrong_spelling = SubscriptionFilter {
        filter_type: FilterType::AbsoluteRange,
        start_location: Some(Location { group: varint(4), object: varint(7) }),
        end_group: Some(FilterEnd::GroupDelta(9)),
    };
    assert!(
        matches!(wrong_spelling.parameter(), Err(CodecError::SubscriptionFilterMalformed { .. })),
        "a delta cannot be written where drafts 15 and 16 write the group in full"
    );
}

/// A Start Location the QUIC integer encoding cannot spell is not written on the
/// drafts that use it.
///
/// That encoding stops at 2^62 - 1 and these fields are 64-bit. Written anyway,
/// the value goes out with the length bits folded into it and arrives as an
/// unrelated group — a subscription for something nobody asked for, on a frame
/// that parses cleanly. Drafts 17 and later reach the whole range, so the same
/// filter is writable there.
#[test]
fn a_start_the_quic_encoding_cannot_spell_is_refused_where_it_matters() {
    let huge = SubscriptionFilter {
        filter_type: FilterType::AbsoluteStart,
        start_location: Some(Location {
            group: VarInt::from_u64_moqt(u64::MAX),
            object: varint(0),
        }),
        end_group: None,
    };
    assert!(
        matches!(huge.parameter(), Err(CodecError::VarInt(_))),
        "drafts 15 and 16 cannot carry this group at all"
    );
    assert!(
        huge.parameter_moqt::<Moqt18>().is_ok(),
        "drafts 17 and later reach the whole 64-bit range"
    );
}

/// An integer inside the filter that is not a legal integer is reported as
/// itself, not as a filter that failed to match its type.
///
/// Draft-17 omits the seven-byte length and calls it an invalid code point,
/// answering it with PROTOCOL_VIOLATION; draft-18 restored the length and reads
/// the same bytes as an ordinary non-minimal encoding. Flattening every integer
/// failure into the filter's own rule would answer draft-17 with
/// KEY_VALUE_FORMATTING_ERROR — a rule it does state, for a case it states a
/// different one for — and would erase the difference between the two profiles
/// while it was at it.
#[test]
fn an_illegal_integer_inside_a_filter_keeps_its_own_name() {
    // Largest Object (0x2) written in the seven-byte form: six leading one bits,
    // a zero, then the value. Non-minimal, and legal on draft-18.
    let seven_byte = [0xFCu8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02];

    let on_18 = SubscriptionFilter::decode_moqt::<Moqt18>(&seven_byte);
    assert_eq!(
        on_18.as_ref().map(|f| f.filter_type).ok(),
        Some(FilterType::LargestObject),
        "draft-18 defines the seven-byte length and reads this: {on_18:?}"
    );

    let on_17 = SubscriptionFilter::decode_moqt::<Moqt17>(&seven_byte);
    assert!(
        matches!(on_17, Err(CodecError::VarInt(_))),
        "draft-17 calls this an invalid code point, which is not the filter's rule: {on_17:?}"
    );
}

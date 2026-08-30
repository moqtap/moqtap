#![cfg(feature = "draft13")]
//! Draft-13 control-message rules the shipped corpus does not pin down.
//!
//! Every rule here is about a value a peer may put on the wire and this codec
//! would never write itself, which is why a corpus generated from this codec
//! cannot reach any of them. The round trips all pass; what they prove is that
//! the codec agrees with itself.
//!
//! # TRACK_STATUS is the SUBSCRIBE message
//!
//! Section 8.20: "The TRACK_STATUS message format is identical to the SUBSCRIBE
//! message (Section 8.7)." Draft-13's changelog records the change outright, and
//! draft-14 keeps the same sentence, so this is not a rule that arrives later.
//! Two of SUBSCRIBE's fields are present only for some filters, and a message
//! that reads the filter but not the fields it announces stops mid-frame.
//!
//! # Three fields the draft draws as `(8)`
//!
//! Group Order, Forward and Content Exists are single bytes in every figure
//! that carries them; only Filter Type and Fetch Type are `(i)`. Reading a
//! single byte as a varint is invisible for every legal value — each is below
//! 64, where a one-byte varint and a bare byte are the same byte — so this is
//! not something a round trip can catch. It is what a peer may send that
//! separates the two readings, and there the varint reader swallows the
//! following byte and shifts every field after it while the declared Length
//! still adds up.
//!
//! # The same field, two different rules
//!
//! Group Order `0x0` means "the original publisher's Group Order SHOULD be
//! used". Sections 8.7, 8.16 and 8.20 permit it, because a request is where a
//! subscriber says it has no preference. Sections 8.8, 8.13, 8.14, 8.17 and
//! 8.21 forbid it — "Values of 0x0 and those larger than 0x2 are a protocol
//! error" — because a response reports the order the publisher settled on. One
//! reader for both halves is wrong whichever way it is written, so the gates
//! below drive the two directions separately.

use moqtap_codec::draft13::message::{
    Announce, ControlMessage, Fetch, FetchOk, FetchPayload, FetchType, Subscribe,
    SubscribeNamespace, SubscribeOk, TrackStatus,
};
use moqtap_codec::error::CodecError;
use moqtap_codec::types::{
    ContentExists, FilterType, Forward, GroupOrder, Location, TrackNamespace,
};
use moqtap_codec::varint::VarInt;

fn vi(v: u64) -> VarInt {
    VarInt::from_u64(v).expect("value fits a varint")
}

/// Draft-13 framing: a type byte, a 16-bit big-endian Length, the payload.
fn framed(type_id: u8, payload: &[u8]) -> Vec<u8> {
    let mut wire = vec![type_id];
    wire.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    wire.extend_from_slice(payload);
    wire
}

/// A one-field Track Namespace holding `l`, then a Track Name holding `v`.
const NAMESPACE_AND_NAME: &[u8] = &[0x01, 0x01, b'l', 0x01, b'v'];

/// The SUBSCRIBE payload, with the two single-byte fields and the Filter Type
/// written from raw bytes so a test can offer a value the struct cannot hold.
///
/// TRACK_STATUS has the same payload, which is the rule under test.
fn subscribe_payload(group_order: &[u8], forward: &[u8], filter_and_after: &[u8]) -> Vec<u8> {
    let mut p = vec![0x01];
    p.extend_from_slice(NAMESPACE_AND_NAME);
    p.push(128); // Subscriber Priority
    p.extend_from_slice(group_order);
    p.extend_from_slice(forward);
    p.extend_from_slice(filter_and_after);
    p.push(0x00); // Number of Parameters
    p
}

/// Filter Type 0x2, which puts no Start Location and no End Group on the wire.
const FILTER_LARGEST_OBJECT: &[u8] = &[0x02];

/// Filter Type 0x4 with Start {7, 3} and End Group 9.
const FILTER_ABSOLUTE_RANGE: &[u8] = &[0x04, 0x07, 0x03, 0x09];

fn subscribe_ok_payload(group_order: u8, content_exists: u8) -> Vec<u8> {
    vec![0x02, 0x01, 0x00, group_order, content_exists, 0x00]
}

fn fetch_ok_payload(group_order: u8) -> Vec<u8> {
    vec![0x01, group_order, 0x00, 0x05, 0x02, 0x00]
}

fn fetch_payload(group_order: u8) -> Vec<u8> {
    let mut p = vec![0x01, 128, group_order, 0x01];
    p.extend_from_slice(NAMESPACE_AND_NAME);
    p.extend_from_slice(&[0x00, 0x00, 0x05, 0x00, 0x00]);
    p
}

fn publish_payload(group_order: u8) -> Vec<u8> {
    let mut p = vec![0x01];
    p.extend_from_slice(NAMESPACE_AND_NAME);
    p.extend_from_slice(&[0x07, group_order, 0x00, 0x01, 0x00]);
    p
}

fn publish_ok_payload(group_order: u8) -> Vec<u8> {
    vec![0x01, 0x01, 128, group_order, 0x02, 0x00]
}

// ── TRACK_STATUS is the SUBSCRIBE message ──────────────────

/// A TRACK_STATUS body is a SUBSCRIBE body, filter-dependent fields included.
///
/// The gate reads one byte string under both type IDs and asks for the same
/// answer, because "identical to the SUBSCRIBE message" is a claim about the
/// bytes and nothing weaker. An AbsoluteRange filter is the case that
/// distinguishes them: it announces a Start Location and an End Group, and a
/// reader that stops at the Filter Type runs into the parameter count where a
/// Start Group belongs.
///
/// # What this catches, observed by making the change and running it
///
/// Dropping the Start Location and End Group from the TRACK_STATUS decode arm:
///
/// ```text
/// a TRACK_STATUS body is a SUBSCRIBE body, got Err(Kvp(UnexpectedEnd))
/// ```
#[test]
fn draft13_track_status_carries_the_fields_its_filter_announces() {
    let payload = subscribe_payload(&[0x00], &[0x01], FILTER_ABSOLUTE_RANGE);

    let as_track_status = ControlMessage::decode(&mut &framed(0x0D, &payload)[..]);
    let ControlMessage::TrackStatus(ts) = as_track_status.as_ref().unwrap_or_else(|e| {
        panic!("a TRACK_STATUS body is a SUBSCRIBE body, got {:?}", Err::<(), _>(e))
    }) else {
        panic!("expected a TRACK_STATUS, got {as_track_status:?}")
    };

    assert_eq!(ts.filter_type, FilterType::AbsoluteRange);
    assert_eq!(ts.start_group, Some(vi(7)));
    assert_eq!(ts.start_object, Some(vi(3)));
    assert_eq!(ts.end_group, Some(vi(9)));

    // The same bytes under the SUBSCRIBE type must land in the same places.
    let ControlMessage::Subscribe(sub) =
        ControlMessage::decode(&mut &framed(0x03, &payload)[..]).expect("a SUBSCRIBE decodes")
    else {
        panic!("expected a SUBSCRIBE")
    };
    assert_eq!(
        (sub.filter_type, sub.start_group, sub.start_object, sub.end_group),
        (ts.filter_type, ts.start_group, ts.start_object, ts.end_group)
    );

    // And the message survives its own encoder.
    let mut round = Vec::new();
    ControlMessage::TrackStatus(ts.clone()).encode(&mut round).expect("a TRACK_STATUS encodes");
    assert_eq!(round, framed(0x0D, &payload), "TRACK_STATUS must re-encode to the bytes it read");
}

/// TRACK_STATUS refuses a Filter Type the draft does not assign.
///
/// "A filter type other than the above MUST be treated as error." The SUBSCRIBE
/// arm already refused these; the TRACK_STATUS arm read the field and never
/// looked at it, so the same four values were an error on one type ID and a
/// stored integer on the other.
///
/// # What this catches, observed by making the change and running it
///
/// Reading the Filter Type as a bare varint without validating it:
///
/// ```text
/// TRACK_STATUS must refuse filter type 0, got Ok(TrackStatus(TrackStatus { request_id: VarInt(1), track_namespace: TrackNamespace([[108]]), track_name: [118], subscriber_priority: 128, group_order: Publisher, forward: Forward, filter_type: NextGroupStart, start_group: None, start_object: None, end_group: None, parameters: [] }))
/// ```
#[test]
fn draft13_track_status_refuses_an_unassigned_filter_type() {
    for filter in [0x00u8, 0x05, 0x63] {
        let payload = subscribe_payload(&[0x00], &[0x01], &[filter]);
        let got = ControlMessage::decode(&mut &framed(0x0D, &payload)[..]);
        assert!(
            matches!(got, Err(CodecError::InvalidFilterType(_))),
            "TRACK_STATUS must refuse filter type {filter}, got {got:?}"
        );
    }
}

// ── Fields the draft draws as `(8)` ────────────────────────

/// Group Order and Forward are one byte each, not a varint.
///
/// The wire here holds `40 01` where Group Order belongs — the two-byte varint
/// encoding of 1, which is a value a conforming peer is entitled to send and
/// which a varint reader accepts as Ascending. Read as the draft draws it, the
/// first byte is `0x40` = 64, which is larger than 0x2 and so a protocol error;
/// the point is that the two readings disagree about a byte string, not that
/// this particular one is legal.
///
/// # What this catches, observed by making the change and running it
///
/// Reading Group Order with `VarInt::decode` again:
///
/// ```text
/// Group Order is one byte: a two-byte varint must not pass, got Ok(Subscribe(Subscribe { request_id: VarInt(1), track_namespace: TrackNamespace([[108]]), track_name: [118], subscriber_priority: 128, group_order: Ascending, forward: Forward, filter_type: LargestObject, start_group: None, start_object: None, end_group: None, parameters: [] }))
/// ```
#[test]
fn draft13_reads_its_single_byte_fields_as_single_bytes() {
    let payload = subscribe_payload(&[0x40, 0x01], &[0x01], FILTER_LARGEST_OBJECT);
    let got = ControlMessage::decode(&mut &framed(0x03, &payload)[..]);
    assert!(
        matches!(got, Err(CodecError::InvalidField)),
        "Group Order is one byte: a two-byte varint must not pass, got {got:?}"
    );

    let payload = subscribe_payload(&[0x01], &[0x40, 0x01], FILTER_LARGEST_OBJECT);
    let got = ControlMessage::decode(&mut &framed(0x03, &payload)[..]);
    assert!(
        matches!(got, Err(CodecError::InvalidForward(0x40))),
        "Forward is one byte: a two-byte varint must not pass, got {got:?}"
    );

    // The single-byte reading of the same fields is what the corpus holds, so
    // the gate above observes the width and not the values.
    let payload = subscribe_payload(&[0x01], &[0x01], FILTER_LARGEST_OBJECT);
    ControlMessage::decode(&mut &framed(0x03, &payload)[..])
        .expect("one byte each is the shape the draft draws");
}

// ── Values the draft calls protocol errors ─────────────────

/// Group Order `0x0` is a request-only value.
///
/// This is the one rule in this file that cannot be written as a single check.
/// A request says "no preference" with `0x0` — "the original publisher's Group
/// Order SHOULD be used" — and a reply has to name the order it settled on.
/// Draft-13 carries "Values of 0x0 and those larger than 0x2 are a protocol
/// error" under SUBSCRIBE_OK, PUBLISH, PUBLISH_OK and FETCH_OK, and
/// TRACK_STATUS_OK inherits it by being "identical to the SUBSCRIBE_OK
/// message". A shared reader that accepts `0x0` everywhere lets a subscriber be
/// told nothing, and one that refuses it everywhere refuses the most common
/// SUBSCRIBE in the corpus.
///
/// # What this catches, observed by making the change and running it
///
/// Pointing the five response arms at the request reader:
///
/// ```text
/// SUBSCRIBE_OK must refuse Group Order 0, got Ok(SubscribeOk(SubscribeOk { request_id: VarInt(2), track_alias: VarInt(1), expires: VarInt(0), group_order: Publisher, content_exists: NoLargestLocation, largest_location: None, parameters: [] }))
/// ```
///
/// and pointing the request arms at the response reader:
///
/// ```text
/// SUBSCRIBE must accept Group Order 0, got Err(InvalidField)
/// ```
#[test]
fn draft13_group_order_zero_is_a_request_only_value() {
    let requests: [(&str, u8, Vec<u8>); 3] = [
        ("SUBSCRIBE", 0x03, subscribe_payload(&[0x00], &[0x01], FILTER_LARGEST_OBJECT)),
        ("TRACK_STATUS", 0x0D, subscribe_payload(&[0x00], &[0x01], FILTER_LARGEST_OBJECT)),
        ("FETCH", 0x16, fetch_payload(0x00)),
    ];
    for (name, type_id, payload) in requests {
        let got = ControlMessage::decode(&mut &framed(type_id, &payload)[..]);
        assert!(got.is_ok(), "{name} must accept Group Order 0, got {got:?}");
    }

    let responses: [(&str, u8, Vec<u8>); 5] = [
        ("SUBSCRIBE_OK", 0x04, subscribe_ok_payload(0x00, 0x00)),
        ("TRACK_STATUS_OK", 0x0E, subscribe_ok_payload(0x00, 0x00)),
        ("FETCH_OK", 0x18, fetch_ok_payload(0x00)),
        ("PUBLISH", 0x1D, publish_payload(0x00)),
        ("PUBLISH_OK", 0x1E, publish_ok_payload(0x00)),
    ];
    for (name, type_id, payload) in responses {
        let got = ControlMessage::decode(&mut &framed(type_id, &payload)[..]);
        assert!(
            matches!(got, Err(CodecError::InvalidField)),
            "{name} must refuse Group Order 0, got {got:?}"
        );
    }

    // Ascending is legal on both sides, so what the responses above observe is
    // the value and not the message.
    for (name, type_id, payload) in [
        ("SUBSCRIBE_OK", 0x04u8, subscribe_ok_payload(0x01, 0x00)),
        ("TRACK_STATUS_OK", 0x0E, subscribe_ok_payload(0x01, 0x00)),
        ("FETCH_OK", 0x18, fetch_ok_payload(0x01)),
        ("PUBLISH", 0x1D, publish_payload(0x01)),
        ("PUBLISH_OK", 0x1E, publish_ok_payload(0x01)),
    ] {
        let got = ControlMessage::decode(&mut &framed(type_id, &payload)[..]);
        assert!(got.is_ok(), "{name} must accept Group Order 1, got {got:?}");
    }
}

/// Group Order above 0x2, and Forward or Content Exists outside 0 and 1, are
/// refused.
///
/// All three sentences are unconditional — "Values larger than 0x2 are a
/// protocol error", "Any other value is a protocol error and MUST terminate the
/// session with a Protocol Violation" — and none of the three was checked.
///
/// # What this catches, observed by making the change and running it
///
/// Returning the raw byte from `read_forward` without matching on it:
///
/// ```text
/// Forward 7 must be refused, got Ok(Subscribe(Subscribe { request_id: VarInt(1), track_namespace: TrackNamespace([[108]]), track_name: [118], subscriber_priority: 128, group_order: Ascending, forward: Forward, filter_type: LargestObject, start_group: None, start_object: None, end_group: None, parameters: [] }))
/// ```
#[test]
fn draft13_refuses_values_the_draft_calls_protocol_errors() {
    let payload = subscribe_payload(&[0x05], &[0x01], FILTER_LARGEST_OBJECT);
    let got = ControlMessage::decode(&mut &framed(0x03, &payload)[..]);
    assert!(
        matches!(got, Err(CodecError::InvalidField)),
        "Group Order 5 must be refused, got {got:?}"
    );

    let payload = subscribe_payload(&[0x01], &[0x07], FILTER_LARGEST_OBJECT);
    let got = ControlMessage::decode(&mut &framed(0x03, &payload)[..]);
    assert!(
        matches!(got, Err(CodecError::InvalidForward(7))),
        "Forward 7 must be refused, got {got:?}"
    );

    let got = ControlMessage::decode(&mut &framed(0x04, &subscribe_ok_payload(0x01, 0x07))[..]);
    assert!(
        matches!(got, Err(CodecError::InvalidContentExists(7))),
        "Content Exists 7 must be refused, got {got:?}"
    );
}

// ── Encode and decode reading the same message ─────────────

/// The encoder refuses a message whose discriminator disagrees with its body.
///
/// Each of these encodes without complaint and comes back as something else, or
/// as an error, because the encoder follows the `Option` and the decoder follows
/// the field that says what is there. A SUBSCRIBE_OK announcing a location it
/// does not carry hands its own reader the parameter count where a Group ID
/// belongs.
///
/// The Group Order case is the same defect one layer along: the decoders now
/// refuse `0x0` on a response, so an encoder that writes one produces a frame
/// nothing can read, including itself.
///
/// # What this catches, observed by making the change and running it
///
/// Dropping the `check_discriminators` and `check_group_order` calls from the
/// head of `encode`:
///
/// ```text
/// a SUBSCRIBE_OK that announces a location it does not carry must be refused, got Ok(())
/// ```
#[test]
fn draft13_encode_refuses_a_message_that_contradicts_itself() {
    let namespace = TrackNamespace(vec![b"l".to_vec()]);

    let announced_but_absent = ControlMessage::SubscribeOk(SubscribeOk {
        request_id: vi(2),
        track_alias: vi(1),
        expires: vi(0),
        group_order: GroupOrder::Ascending,
        content_exists: ContentExists::HasLargestLocation,
        largest_location: None,
        parameters: vec![],
    });
    let got = announced_but_absent.encode(&mut Vec::new());
    assert!(
        matches!(got, Err(CodecError::InvalidField)),
        "a SUBSCRIBE_OK that announces a location it does not carry must be refused, got {got:?}"
    );

    let range_without_a_range = ControlMessage::Subscribe(Subscribe {
        request_id: vi(1),
        track_namespace: namespace.clone(),
        track_name: b"v".to_vec(),
        subscriber_priority: 128,
        group_order: GroupOrder::Publisher,
        forward: Forward::Forward,
        filter_type: FilterType::AbsoluteRange,
        start_group: None,
        start_object: None,
        end_group: None,
        parameters: vec![],
    });
    let got = range_without_a_range.encode(&mut Vec::new());
    assert!(
        matches!(got, Err(CodecError::InvalidField)),
        "an AbsoluteRange SUBSCRIBE with no range must be refused, got {got:?}"
    );

    // Half a Start Location is not a Start Location.
    let half_a_start = ControlMessage::TrackStatus(TrackStatus {
        request_id: vi(1),
        track_namespace: namespace.clone(),
        track_name: b"v".to_vec(),
        subscriber_priority: 128,
        group_order: GroupOrder::Publisher,
        forward: Forward::Forward,
        filter_type: FilterType::AbsoluteStart,
        start_group: Some(vi(7)),
        start_object: None,
        end_group: None,
        parameters: vec![],
    });
    let got = half_a_start.encode(&mut Vec::new());
    assert!(
        matches!(got, Err(CodecError::InvalidField)),
        "a TRACK_STATUS with half a Start Location must be refused, got {got:?}"
    );

    let standalone_carrying_a_join = ControlMessage::Fetch(Fetch {
        request_id: vi(1),
        subscriber_priority: 128,
        group_order: GroupOrder::Ascending,
        fetch_type: FetchType::Standalone,
        fetch_payload: FetchPayload::Joining { joining_request_id: vi(1), joining_start: vi(2) },
        parameters: vec![],
    });
    let got = standalone_carrying_a_join.encode(&mut Vec::new());
    assert!(
        matches!(got, Err(CodecError::InvalidField)),
        "a Standalone FETCH carrying a joining body must be refused, got {got:?}"
    );

    let deferring_response = ControlMessage::FetchOk(FetchOk {
        request_id: vi(1),
        group_order: GroupOrder::Publisher,
        end_of_track: 0,
        end_location: Location { group: vi(5), object: vi(2) },
        parameters: vec![],
    });
    let got = deferring_response.encode(&mut Vec::new());
    assert!(
        matches!(got, Err(CodecError::InvalidField)),
        "a FETCH_OK that defers the Group Order must be refused, got {got:?}"
    );

    // The same messages with their halves in agreement encode, so the gates
    // above observe the disagreement and not the message type.
    let agreeing = ControlMessage::SubscribeOk(SubscribeOk {
        request_id: vi(2),
        track_alias: vi(1),
        expires: vi(0),
        group_order: GroupOrder::Ascending,
        content_exists: ContentExists::HasLargestLocation,
        largest_location: Some(Location { group: vi(5), object: vi(10) }),
        parameters: vec![],
    });
    agreeing.encode(&mut Vec::new()).expect("a SUBSCRIBE_OK that agrees with itself encodes");
}

// ── The namespace tuple bound, on both sides ───────────────

/// A Track Namespace tuple holds between 1 and 32 fields, on the way out too.
///
/// Sections 2.4.1 and 8.28: "If an endpoint receives a Track Namespace tuple
/// with an N of 0 or more than 32, it MUST close the session with a Protocol
/// Violation." The reader enforced it and the writer did not, so this codec
/// emitted namespaces it would refuse to read back — the sentence is about a
/// receiver, and the peer is the receiver.
///
/// The rule is written once and applied at nine separate call sites, so the
/// gate drives all three field names a site can carry — the plain namespace, the
/// prefix, and the one nested inside a standalone FETCH. Removing the check from
/// any single site leaves the other eight standing, which is how eight of nine
/// would still look right.
///
/// # What this catches, observed by making the change and running it
///
/// Removing the validation from all nine namespace encode sites:
///
/// ```text
/// a 0-field Track Namespace in ANNOUNCE must be refused on encode, got Ok(())
/// ```
///
/// and removing it from the nested FETCH site alone, which is the one a gate
/// driving a single message would have missed:
///
/// ```text
/// a 0-field Track Namespace in FETCH must be refused on encode, got Ok(())
/// ```
#[test]
fn draft13_holds_a_namespace_to_its_bounds_in_both_directions() {
    fn announce(namespace: TrackNamespace) -> ControlMessage {
        ControlMessage::Announce(Announce {
            request_id: vi(1),
            track_namespace: namespace,
            parameters: vec![],
        })
    }
    fn subscribe_namespace(namespace: TrackNamespace) -> ControlMessage {
        ControlMessage::SubscribeNamespace(SubscribeNamespace {
            request_id: vi(1),
            track_namespace_prefix: namespace,
            parameters: vec![],
        })
    }
    fn standalone_fetch(namespace: TrackNamespace) -> ControlMessage {
        ControlMessage::Fetch(Fetch {
            request_id: vi(1),
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            fetch_type: FetchType::Standalone,
            fetch_payload: FetchPayload::Standalone {
                track_namespace: namespace,
                track_name: b"v".to_vec(),
                start_group: vi(0),
                start_object: vi(0),
                end_group: vi(5),
                end_object: vi(0),
            },
            parameters: vec![],
        })
    }

    /// A message named for the report, and the way to build one around a
    /// namespace.
    type Carrier = (&'static str, fn(TrackNamespace) -> ControlMessage);

    let carriers: [Carrier; 3] = [
        ("ANNOUNCE", announce),
        ("SUBSCRIBE_NAMESPACE", subscribe_namespace),
        ("FETCH", standalone_fetch),
    ];

    for (name, build) in carriers {
        for fields in [0usize, 33] {
            let got = build(TrackNamespace(vec![b"n".to_vec(); fields])).encode(&mut Vec::new());
            assert!(
                matches!(got, Err(CodecError::InvalidNamespaceTupleSize(n)) if n == fields),
                "a {fields}-field Track Namespace in {name} must be refused on encode, got {got:?}"
            );
        }

        // One field and thirty-two are both inside the bound, so the gate
        // observes the edges and not the presence of a namespace.
        for fields in [1usize, 32] {
            build(TrackNamespace(vec![b"n".to_vec(); fields]))
                .encode(&mut Vec::new())
                .unwrap_or_else(|e| panic!("a {fields}-field namespace in {name} encodes: {e:?}"));
        }
    }
}

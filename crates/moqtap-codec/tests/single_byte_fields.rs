//! The control-message fields the drafts draw as `(8)`, on drafts 11 through 16.
//!
//! Group Order, Forward, Content Exists and End Of Track are each drawn as a
//! single octet, and each was read and written as a variable-length integer.
//! Nothing about that is visible while both ends agree, because every legal
//! value of all four is below 64 — the range where a one-byte QUIC varint and a
//! bare octet are the same byte. The corpus was generated from those encoders,
//! so it agrees too.
//!
//! Where the two readings part company is on a value a peer may put on the wire
//! that this codec would never write. `0x40 0x01` is a lawful two-byte varint
//! holding 1. A varint reader takes it as Ascending and carries on one byte
//! late for the rest of the message; an octet reader takes `0x40` as the field
//! and refuses it. Every probe below is that byte string, spliced in where the
//! field is, with the frame's declared Length corrected so that the only thing
//! left wrong is the width.
//!
//! The field's offset is not hardcoded. Each probe encodes the same message
//! twice with two different values of the field and takes the one position at
//! which the two encodings differ, so a probe cannot drift out of position when
//! a neighbouring field changes shape.
//!
//! # What breaking each fix does, observed by making the change and running
//!
//! The output quoted in each docstring came from making that edit and running
//! the test; none of it is a prediction.

#![cfg(all(
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16"
))]

use moqtap_codec::error::CodecError;
use moqtap_codec::types::{
    ContentExists, FilterType, Forward, GroupOrder, Location, TrackNamespace,
};
use moqtap_codec::varint::VarInt;

fn vi(v: u64) -> VarInt {
    VarInt::from_u64(v).expect("value fits a QUIC varint")
}

fn loc(group: u64, object: u64) -> Location {
    Location { group: vi(group), object: vi(object) }
}

/// Split a control frame into its type field and its payload.
///
/// Drafts 11 through 16 all frame a control message as a type varint, a 16-bit
/// big-endian Length, and the payload.
fn split(frame: &[u8]) -> (&[u8], &[u8]) {
    let type_len = 1usize << (frame[0] >> 6);
    let payload_at = type_len + 2;
    (&frame[..type_len], &frame[payload_at..])
}

/// Put a payload back in a frame, with the declared Length corrected for it.
fn reframe(type_field: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = type_field.to_vec();
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// The one position at which two payloads of equal length differ.
///
/// Panics unless there is exactly one, which is what makes it safe to call the
/// result "the field": two encodings of the same message that differ only in
/// one field's value differ in exactly one place, unless the field is not the
/// width this file says it is.
fn sole_difference(a: &[u8], b: &[u8]) -> usize {
    assert_eq!(a.len(), b.len(), "two values of a one-byte field must encode to the same length");
    let mut found = None;
    for (i, (x, y)) in a.iter().zip(b.iter()).enumerate() {
        if x != y {
            assert!(found.is_none(), "expected one differing byte, found several");
            found = Some(i);
        }
    }
    found.expect("the two encodings must differ somewhere")
}

/// A frame in which the field at `pos` has been widened to a two-byte varint
/// holding the same value, with the declared Length corrected.
fn widened(frame: &[u8], pos: usize) -> Vec<u8> {
    let (type_field, payload) = split(frame);
    let value = payload[pos];
    assert!(value < 64, "only a value below 64 can be written both ways");
    let mut widened = payload[..pos].to_vec();
    widened.extend_from_slice(&[0x40, value]);
    widened.extend_from_slice(&payload[pos + 1..]);
    reframe(type_field, &widened)
}

/// Encode a message, or say which draft could not.
macro_rules! wire {
    ($draft:literal, $msg:expr) => {{
        let mut out = Vec::new();
        $msg.encode(&mut out).unwrap_or_else(|e| panic!("[{}] fixture must encode: {e}", $draft));
        out
    }};
}

/// The probe itself: two encodings, the byte they differ at, and the verdict on
/// the widened frame.
fn refuses_a_widened_field(
    draft: &str,
    field: &str,
    a: &[u8],
    b: &[u8],
    decode: fn(&[u8]) -> bool,
) {
    let (_, pa) = split(a);
    let (_, pb) = split(b);
    let pos = sole_difference(pa, pb);

    assert!(decode(a), "[{draft}] the unaltered fixture must decode");

    let probe = widened(a, pos);
    assert!(
        !decode(&probe),
        "[{draft}] {field} is one octet, so a two-byte varint in its place must be refused"
    );
}

/// Group Order is one octet on drafts 11 through 14.
///
/// Draft-15 moved the field into a parameter and dropped it from the message,
/// so the sweep stops at 14.
///
/// # What breaking the fix does, observed by making the change and running
///
/// Reading draft-12's FETCH_OK Group Order with `VarInt::decode` again:
///
/// ```text
/// [draft-12] Group Order is one octet, so a two-byte varint in its place must be refused
/// ```
#[test]
fn group_order_is_one_octet() {
    {
        use moqtap_codec::draft11::message::{ControlMessage, FetchOk};
        let m = |o| {
            ControlMessage::FetchOk(FetchOk {
                request_id: vi(1),
                group_order: o,
                end_of_track: 0,
                end_location: loc(5, 2),
                parameters: vec![],
            })
        };
        refuses_a_widened_field(
            "draft-11",
            "Group Order",
            &wire!("draft-11", m(GroupOrder::Ascending)),
            &wire!("draft-11", m(GroupOrder::Descending)),
            |b| ControlMessage::decode(&mut &b[..]).is_ok(),
        );
    }
    {
        use moqtap_codec::draft12::message::{ControlMessage, FetchOk};
        let m = |o| {
            ControlMessage::FetchOk(FetchOk {
                request_id: vi(1),
                group_order: o,
                end_of_track: 0,
                end_location: loc(5, 2),
                parameters: vec![],
            })
        };
        refuses_a_widened_field(
            "draft-12",
            "Group Order",
            &wire!("draft-12", m(GroupOrder::Ascending)),
            &wire!("draft-12", m(GroupOrder::Descending)),
            |b| ControlMessage::decode(&mut &b[..]).is_ok(),
        );
    }
    {
        use moqtap_codec::draft13::message::{ControlMessage, FetchOk};
        let m = |o| {
            ControlMessage::FetchOk(FetchOk {
                request_id: vi(1),
                group_order: o,
                end_of_track: 0,
                end_location: loc(5, 2),
                parameters: vec![],
            })
        };
        refuses_a_widened_field(
            "draft-13",
            "Group Order",
            &wire!("draft-13", m(GroupOrder::Ascending)),
            &wire!("draft-13", m(GroupOrder::Descending)),
            |b| ControlMessage::decode(&mut &b[..]).is_ok(),
        );
    }
    {
        use moqtap_codec::draft14::message::{ControlMessage, FetchOk};
        let m = |o| {
            ControlMessage::FetchOk(FetchOk {
                request_id: vi(1),
                group_order: o,
                end_of_track: 0,
                end_location: loc(5, 2),
                parameters: vec![],
            })
        };
        refuses_a_widened_field(
            "draft-14",
            "Group Order",
            &wire!("draft-14", m(GroupOrder::Ascending)),
            &wire!("draft-14", m(GroupOrder::Descending)),
            |b| ControlMessage::decode(&mut &b[..]).is_ok(),
        );
    }
}

/// End Of Track is one octet on drafts 11 through 16.
///
/// It stays a raw byte rather than an enum: these drafts describe 1 and 0 and
/// say nothing about any other value, where they do call an out-of-range Group
/// Order, Forward or Content Exists a protocol error. So the probe here is the
/// width and not the range — `0x40 0x01` is refused because `0x40` is not where
/// the next field starts, not because 64 is out of range.
///
/// # What breaking the fix does, observed by making the change and running
///
/// Reading draft-16's End Of Track with `VarInt::decode` again:
///
/// ```text
/// [draft-16] End Of Track is one octet, so a two-byte varint in its place must be refused
/// ```
#[test]
fn end_of_track_is_one_octet() {
    {
        use moqtap_codec::draft11::message::{ControlMessage, FetchOk};
        let m = |e| {
            ControlMessage::FetchOk(FetchOk {
                request_id: vi(1),
                group_order: GroupOrder::Ascending,
                end_of_track: e,
                end_location: loc(5, 2),
                parameters: vec![],
            })
        };
        refuses_a_widened_field(
            "draft-11",
            "End Of Track",
            &wire!("draft-11", m(0)),
            &wire!("draft-11", m(1)),
            |b| ControlMessage::decode(&mut &b[..]).is_ok(),
        );
    }
    {
        use moqtap_codec::draft12::message::{ControlMessage, FetchOk};
        let m = |e| {
            ControlMessage::FetchOk(FetchOk {
                request_id: vi(1),
                group_order: GroupOrder::Ascending,
                end_of_track: e,
                end_location: loc(5, 2),
                parameters: vec![],
            })
        };
        refuses_a_widened_field(
            "draft-12",
            "End Of Track",
            &wire!("draft-12", m(0)),
            &wire!("draft-12", m(1)),
            |b| ControlMessage::decode(&mut &b[..]).is_ok(),
        );
    }
    {
        use moqtap_codec::draft13::message::{ControlMessage, FetchOk};
        let m = |e| {
            ControlMessage::FetchOk(FetchOk {
                request_id: vi(1),
                group_order: GroupOrder::Ascending,
                end_of_track: e,
                end_location: loc(5, 2),
                parameters: vec![],
            })
        };
        refuses_a_widened_field(
            "draft-13",
            "End Of Track",
            &wire!("draft-13", m(0)),
            &wire!("draft-13", m(1)),
            |b| ControlMessage::decode(&mut &b[..]).is_ok(),
        );
    }
    {
        use moqtap_codec::draft15::message::{ControlMessage, FetchOk};
        let m = |e| {
            ControlMessage::FetchOk(FetchOk {
                request_id: vi(1),
                end_of_track: e,
                end_group: vi(5),
                end_object: vi(2),
                parameters: vec![],
            })
        };
        refuses_a_widened_field(
            "draft-15",
            "End Of Track",
            &wire!("draft-15", m(0)),
            &wire!("draft-15", m(1)),
            |b| ControlMessage::decode(&mut &b[..]).is_ok(),
        );
    }
    {
        use moqtap_codec::draft16::message::{ControlMessage, FetchOk};
        let m = |e| {
            ControlMessage::FetchOk(FetchOk {
                request_id: vi(1),
                end_of_track: e,
                end_group: vi(5),
                end_object: vi(2),
                parameters: vec![],
                track_extensions: vec![],
            })
        };
        refuses_a_widened_field(
            "draft-16",
            "End Of Track",
            &wire!("draft-16", m(0)),
            &wire!("draft-16", m(1)),
            |b| ControlMessage::decode(&mut &b[..]).is_ok(),
        );
    }
}

/// A Group Order of 0x0 is refused on every reply that forbids it, and accepted
/// on the requests that give it a meaning.
///
/// The sentence is "Values of 0x0 and those larger than 0x2 are a protocol
/// error", and counting where it appears is the whole of this rule. Drafts 07
/// through 11 state it on SUBSCRIBE_OK and FETCH_OK; drafts 12, 13 and 14 add
/// PUBLISH and PUBLISH_OK; drafts 13 and 14 pick up TRACK_STATUS_OK, whose
/// format "is identical to the SUBSCRIBE_OK message". Drafts 15 and later moved
/// Group Order into a parameter and the field is gone.
///
/// SUBSCRIBE and FETCH are the other half, and there 0x0 is how a subscriber
/// says it has no preference: "the original publisher's Group Order SHOULD be
/// used". Both halves are asserted, because a single reader is wrong in one
/// direction or the other — one that refuses 0x0 everywhere refuses the most
/// common SUBSCRIBE in the corpus, and one that accepts it everywhere lets a
/// reply tell the subscriber nothing.
///
/// # What breaking the fix does, observed by making the change and running
///
/// Pointing draft-11's SUBSCRIBE_OK arm at the ordinary reader:
///
/// ```text
/// [draft-11] a SUBSCRIBE_OK that defers to the publisher's order must be refused: Ok(())
/// ```
///
/// and pointing draft-12's SUBSCRIBE arm at the strict reader:
///
/// ```text
/// [draft-12] a SUBSCRIBE that defers to the publisher's order must be accepted
/// ```
#[test]
fn group_order_zero_is_refused_only_where_a_draft_says_so() {
    // draft-11 SUBSCRIBE_OK, the earliest shape this file reaches.
    {
        use moqtap_codec::draft11::message::{ControlMessage, SubscribeOk};
        let msg = ControlMessage::SubscribeOk(SubscribeOk {
            request_id: vi(2),
            expires: vi(0),
            group_order: GroupOrder::Publisher,
            content_exists: ContentExists::NoLargestLocation,
            largest_location: None,
            parameters: vec![],
        });
        let got = msg.encode(&mut Vec::new());
        assert!(
            matches!(got, Err(CodecError::InvalidField)),
            "[draft-11] a SUBSCRIBE_OK that defers to the publisher's order must be refused: {got:?}"
        );
    }

    // draft-11 FETCH_OK, the other message its draft names.
    {
        use moqtap_codec::draft11::message::{ControlMessage, FetchOk};
        let msg = ControlMessage::FetchOk(FetchOk {
            request_id: vi(1),
            group_order: GroupOrder::Publisher,
            end_of_track: 0,
            end_location: loc(5, 2),
            parameters: vec![],
        });
        let got = msg.encode(&mut Vec::new());
        assert!(
            matches!(got, Err(CodecError::InvalidField)),
            "[draft-11] a FETCH_OK that defers to the publisher's order must be refused: {got:?}"
        );
    }

    // draft-12 PUBLISH_OK, one of the two messages draft-12 added to the rule.
    {
        use moqtap_codec::draft12::message::{ControlMessage, PublishOk};
        let msg = ControlMessage::PublishOk(PublishOk {
            request_id: vi(1),
            forward: Forward::Forward,
            subscriber_priority: 128,
            group_order: GroupOrder::Publisher,
            filter_type: vi(FilterType::LargestObject as u64),
            start_group: None,
            start_object: None,
            end_group: None,
            parameters: vec![],
        });
        let got = msg.encode(&mut Vec::new());
        assert!(
            matches!(got, Err(CodecError::InvalidField)),
            "[draft-12] a PUBLISH_OK that defers to the publisher's order must be refused: {got:?}"
        );
    }

    // draft-14 TRACK_STATUS_OK, which inherits the rule by being "identical to
    // the SUBSCRIBE_OK message". It is the arm a reader of the figures alone
    // would miss, because its own section states no field list at all.
    {
        use moqtap_codec::draft14::message::{ControlMessage, TrackStatusOk};
        let msg = ControlMessage::TrackStatusOk(TrackStatusOk {
            request_id: vi(1),
            track_alias: vi(0),
            expires: vi(0),
            group_order: GroupOrder::Publisher,
            content_exists: ContentExists::NoLargestLocation,
            largest_location: None,
            parameters: vec![],
        });
        let got = msg.encode(&mut Vec::new());
        assert!(
            matches!(got, Err(CodecError::InvalidField)),
            "[draft-14] a TRACK_STATUS_OK that defers to the publisher's order must be refused: {got:?}"
        );
    }

    // And the requests, which give 0x0 a meaning and must keep taking it. This
    // is the half a blanket fix breaks, and it is the more common traffic.
    {
        use moqtap_codec::draft12::message::{ControlMessage, Subscribe};
        let msg = ControlMessage::Subscribe(Subscribe {
            request_id: vi(1),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            subscriber_priority: 128,
            group_order: GroupOrder::Publisher,
            forward: Forward::Forward,
            filter_type: vi(FilterType::LargestObject as u64),
            start_group: None,
            start_object: None,
            end_group: None,
            parameters: vec![],
        });
        let mut out = Vec::new();
        msg.encode(&mut out).expect("draft-12 SUBSCRIBE must be written");
        assert!(
            ControlMessage::decode(&mut &out[..]).is_ok(),
            "[draft-12] a SUBSCRIBE that defers to the publisher's order must be accepted"
        );
    }
    {
        use moqtap_codec::draft14::message::{ControlMessage, Fetch, FetchPayload, FetchType};
        let msg = ControlMessage::Fetch(Fetch {
            request_id: vi(1),
            subscriber_priority: 128,
            group_order: GroupOrder::Publisher,
            fetch_type: FetchType::Standalone,
            fetch_payload: FetchPayload::Standalone {
                track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
                track_name: b"t".to_vec(),
                start_group: vi(0),
                start_object: vi(0),
                end_group: vi(5),
                end_object: vi(2),
            },
            parameters: vec![],
        });
        let mut out = Vec::new();
        msg.encode(&mut out).expect("draft-14 FETCH must be written");
        assert!(
            ControlMessage::decode(&mut &out[..]).is_ok(),
            "[draft-14] a FETCH that defers to the publisher's order must be accepted"
        );
    }
}

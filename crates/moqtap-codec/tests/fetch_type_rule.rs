//! The Fetch Type, and the draft where its rule grew a consequence.
//!
//! The sentence beside the Filter Type one, moving the same way. Drafts 08
//! through 13: "A Fetch Type other than 0x1, 0x2 or 0x3 MUST be treated as an
//! error" — no code, no close, and 0x3 missing from the sentence on drafts 08,
//! 09 and 10, which assign only two types. Draft-14: "An endpoint that receives
//! a Fetch Type other than 0x1, 0x2 or 0x3 MUST be close the session with a
//! PROTOCOL_VIOLATION", carrying the same missing word as its Filter Type
//! sentence. Drafts 15 through 19 say it without the typo.
//!
//! Draft-07 states nothing because it has nothing to state it about: its FETCH
//! is the standalone form and carries no Fetch Type field at all.
//!
//! # Why the value cannot simply be ignored
//!
//! It decides which fields follow it. A Standalone fetch carries a Track
//! Namespace, a Track Name and a four-field range; a joining fetch carries a
//! Request ID and an offset. A reader that cannot name the type cannot find the
//! end of the message, which is why the later drafts answer an unassigned value
//! with a close rather than by skipping the field.
//!
//! # What is under test here, and what is not
//!
//! That the refusal names the Fetch Type rather than arriving as the shared
//! malformed-field variant, which every draft's session table sends to the
//! no-close arm. Whether the session then ends is a property of the wire, and
//! `draft15_fetch_type_closes_the_session` in the client is where that is seen.

#![cfg(all(feature = "draft13", feature = "draft15"))]

use moqtap_codec::error::CodecError;
use moqtap_codec::types::{GroupOrder, TrackNamespace};
use moqtap_codec::varint::VarInt;

fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).expect("fixture value fits a varint")
}

/// A Fetch Type no draft assigns. Above the assigned block rather than zero, so
/// a decoder that merely required a non-zero value would still accept it.
const UNASSIGNED: u8 = 0x07;

/// Overwrite one byte, having first checked it is the byte meant.
///
/// The Fetch Type sits at a fixed offset in a frame whose earlier fields are all
/// one byte wide at these values. Asserting what is there before replacing it is
/// what keeps a framing change from quietly moving this test onto some other
/// field, where it would go on passing for the wrong reason.
fn replace(frame: &mut [u8], offset: usize, expected: u8, with: u8) {
    assert_eq!(
        frame[offset], expected,
        "the Fetch Type should be at offset {offset}; the frame reads {frame:?}"
    );
    frame[offset] = with;
}

/// Draft-13 refuses the value and names it, and its session table leaves it
/// alone.
///
/// The naming is the whole change on this draft. Nothing about the outcome moves
/// — the message was refused before and is refused now — but a refusal reported
/// as the shared malformed-field variant cannot be told from a dozen unrelated
/// ones, so draft-14's table had nothing to route.
#[test]
fn draft13_names_the_fetch_type_it_refuses() {
    use moqtap_codec::draft13::message::*;

    let message = ControlMessage::Fetch(Fetch {
        request_id: varint(1),
        subscriber_priority: 128,
        group_order: GroupOrder::Ascending,
        fetch_type: FetchType::Standalone,
        fetch_payload: FetchPayload::Standalone {
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            start_group: varint(1),
            start_object: varint(0),
            end_group: varint(2),
            end_object: varint(0),
        },
        parameters: Vec::new(),
    });
    let mut frame = Vec::new();
    message.encode(&mut frame).expect("a standalone fetch is legal on draft-13");

    // Type (1 byte, 0x16), Length (2 bytes), Request ID (1), Subscriber
    // Priority (1), Group Order (1), then the Fetch Type.
    replace(&mut frame, 6, FetchType::Standalone as u8, UNASSIGNED);

    let got = ControlMessage::decode(&mut &frame[..]);
    assert!(
        matches!(got, Err(CodecError::InvalidFetchType(7))),
        "draft-13 must name the fetch type it refuses, got {got:?}"
    );
}

/// Draft-15 refuses the same value, under the same name, and its table answers
/// it with a close.
///
/// Drafts 14 through 19 all state the close; the codec-side half is identical on
/// every one of them, which is why one draft stands for the group here and the
/// per-draft routing is checked where it lives, in each table's own arm.
#[test]
fn draft15_names_the_fetch_type_it_refuses() {
    use moqtap_codec::draft15::message::*;

    let message = ControlMessage::Fetch(Fetch {
        request_id: varint(1),
        fetch_type: FetchType::Standalone,
        fetch_payload: FetchPayload::Standalone {
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            start_group: varint(1),
            start_object: varint(0),
            end_group: varint(2),
            end_object: varint(0),
        },
        parameters: Vec::new(),
    });
    let mut frame = Vec::new();
    message.encode(&mut frame).expect("a standalone fetch is legal on draft-15");

    // Draft-15 moved Subscriber Priority and Group Order into parameters, so the
    // Fetch Type follows the Request ID directly.
    replace(&mut frame, 4, FetchType::Standalone as u8, UNASSIGNED);

    let got = ControlMessage::decode(&mut &frame[..]);
    assert!(
        matches!(got, Err(CodecError::InvalidFetchType(7))),
        "draft-15 must name the fetch type it refuses, got {got:?}"
    );
}

/// Every assigned Fetch Type is still carried.
///
/// The negative half. A check that refused more than the drafts name would pass
/// both tests above and fail this one — and the two joining types are the ones
/// to watch, because drafts 08 through 10 assign only 0x1 and 0x2 and a reader
/// built from those would refuse the third here.
#[test]
fn every_assigned_fetch_type_is_carried() {
    use moqtap_codec::draft15::message::*;

    for fetch_type in
        [FetchType::Standalone, FetchType::RelativeJoining, FetchType::AbsoluteJoining]
    {
        let fetch_payload = match fetch_type {
            FetchType::Standalone => FetchPayload::Standalone {
                track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
                track_name: b"t".to_vec(),
                start_group: varint(1),
                start_object: varint(0),
                end_group: varint(2),
                end_object: varint(0),
            },
            _ => FetchPayload::Joining { joining_request_id: varint(0), joining_start: varint(3) },
        };
        let message = ControlMessage::Fetch(Fetch {
            request_id: varint(1),
            fetch_type,
            fetch_payload,
            parameters: Vec::new(),
        });
        let mut frame = Vec::new();
        message.encode(&mut frame).expect("every assigned type is writable");
        let back = ControlMessage::decode(&mut &frame[..]);
        assert_eq!(
            back.as_ref().ok(),
            Some(&message),
            "draft-15 assigns {fetch_type:?} and must carry it: {back:?}"
        );
    }
}

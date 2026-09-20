#![cfg(any(feature = "draft12", feature = "draft13", feature = "draft14"))]

//! A standalone FETCH names where its range ends, and the caller names it.
//!
//! All three drafts describe what a FETCH asks for the same way. Draft-12
//! Section 8.16, and draft-13 and draft-14 in the same words: "Fetch specifies
//! an inclusive range of Objects starting at Start Location and ending at End
//! Location."
//!
//! They do not word the end field the same way, and the difference is worth
//! having straight before reading the gates. Drafts 12 and 13 continue: "End
//! Location MUST specify the same or a larger Location than Start Location."
//! Draft-14 keeps that sentence and narrows it to the fetch types it can be
//! about — "... for Standalone and Absolute Joining Fetches" — and words the
//! field itself in its own terms, in Section 9.16.1: "End Location: The end
//! Location, plus 1. A Location.Object value of 0 means the entire group is
//! requested", where 12 and 13 write "plus 1 Object ID" and "An Object ID
//! value of 0". The wording moved and the number in the field did not, and on
//! all three the caller is the one who knows it.
//!
//! The end is the caller's for the same reason the start is. A fetch is a
//! request for a range, and one that cannot say where it stops is not a
//! smaller request but a different one.
//!
//! # Why the range is these three
//!
//! They are the drafts whose per-draft `Endpoint::fetch` takes the whole
//! request as arguments: the range, the Subscriber Priority and Group Order
//! FETCH draws as fields of its own, and a parameter list beside them. Drafts
//! 07 through 11 draw those two fields as well but take no parameter list, and
//! draft-15 deletes both fields and moves them into the parameters, so its
//! `fetch` takes neither. The gates below read the priority and the order off
//! the wire beside the range.
//!
//! The draft-neutral `AnyConnection::fetch` reaches every draft; the range it
//! writes through `FetchRange` is gated in
//! `a_fetch_range_means_one_thing_on_every_draft.rs`, on drafts 14 through 20.
//!
//! # What this file does not cover
//!
//! The `parameters` field, which the gates below pass empty because the range
//! is what they are about. It is the caller's on all three drafts and is gated
//! in `a_fetch_carries_the_parameters_it_was_given_on_the_earlier_drafts.rs`,
//! over this same range, with drafts 15 through 20 in the file beside it.
//!
//! # Ablations, measured
//!
//! Four cuts were made, one per field the caller names, run
//! against the two crates a change to `moqtap-client` can reach, and
//! reverted. Drafts 12 and 13 build a joining fetch beside the
//! standalone one and draft-14 does not, so the two cuts that fall on
//! a line both builders share land twice there and once here.

#![allow(clippy::items_after_test_module)]

use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;

/// The namespace every fetch here is for.
fn namespace() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec()])
}

fn v(n: u64) -> VarInt {
    VarInt::from_u64(n).unwrap()
}

/// One draft's gates. All three build the same FETCH from the same call.
macro_rules! fetch_range_gates {
    ($draft:ident, $feat:literal, $version:expr, $sec:literal) => {
        #[cfg(feature = $feat)]
        mod $draft {
            use moqtap_client::$draft::endpoint::Endpoint;
            use moqtap_client::$draft::session::request_id::Role;
            use moqtap_client::$draft::session::state::SessionState;
            use moqtap_codec::kvp::{KeyValuePair, KvpValue};
            use moqtap_codec::types::*;
            use moqtap_codec::$draft::message::*;

            /// A client with its session established and a budget to spend.
            fn active() -> Endpoint {
                let mut ep = Endpoint::new(Role::Client);
                ep.connect().expect("a client may open");
                let _ = ep.send_client_setup(vec![crate::v($version)], vec![]).expect("SETUP");
                ep.receive_server_setup(&ServerSetup {
                    selected_version: crate::v($version),
                    parameters: vec![KeyValuePair {
                        key: crate::v(0x02),
                        value: KvpValue::Varint(crate::v(100)),
                    }],
                })
                .expect("SERVER_SETUP");
                let _ = ep.send_max_request_id(crate::v(100)).expect("MAX_REQUEST_ID");
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "the gates need a running session"
                );
                ep
            }

            /// The range every gate here asks for, chosen so that no field
            /// holds a value the crate would have picked on its own.
            const START_GROUP: u64 = 3;
            const START_OBJECT: u64 = 4;
            const END_GROUP: u64 = 9;
            const END_OBJECT: u64 = 2;

            /// Build a fetch for that range and read it back off the wire.
            fn round_trip(ep: &mut Endpoint) -> Fetch {
                let (_, msg) = ep
                    .fetch(
                        crate::namespace(),
                        b"alpha".to_vec(),
                        200,
                        GroupOrder::Descending,
                        crate::v(START_GROUP),
                        crate::v(START_OBJECT),
                        crate::v(END_GROUP),
                        crate::v(END_OBJECT),
                        Vec::new(),
                    )
                    .expect("this endpoint may fetch a range");
                let mut buf = Vec::new();
                msg.encode(&mut buf).expect("the fetch encodes");
                let mut cursor = &buf[..];
                let ControlMessage::Fetch(back) =
                    ControlMessage::decode(&mut cursor).expect("the fetch decodes")
                else {
                    panic!("what was encoded was a FETCH");
                };
                back
            }

            /// The end of the range the caller asked for reaches the peer.
            ///
            /// This is the gate the range's end rests on: Section 8.16 on
            /// drafts 12 and 13, and Section 9.16.1 on draft-14, make both ends
            /// the caller's, and against the group 3, object 4 start this gate
            /// asks for, an end of group 0, object 0 names a range that stops
            /// before it starts.
            ///
            /// # What it catches
            ///
            /// Sending group 0, object 0 as the end of every range, whatever
            /// the caller asked for:
            ///
            /// ```text
            /// the fetch encodes: InvalidRange(3, 4, 0, 0)
            /// ```
            ///
            /// It reddens nine, every gate here on all three drafts. Two of them
            /// read the range only through the helper that builds it, so a fetch
            /// that cannot be built at all takes them with it; the two cuts below
            /// are what say each field is measured on its own.
            ///
            /// Sending group 0, object 0 as the *start* as well. The mirror of the
            /// first cut, and the one that says this gate reads both ends rather
            /// than one:
            ///
            /// ```text
            /// assertion `left == right` failed: Section 8.16 makes the start the
            /// caller's left: (0, 0) right: (3, 4)
            /// ```
            ///
            /// It reddens three, this gate on all three drafts and nothing else.
            #[test]
            fn the_end_of_the_range_reaches_the_peer() {
                let mut ep = active();
                let back = round_trip(&mut ep);
                let FetchPayload::Standalone {
                    start_group,
                    start_object,
                    end_group,
                    end_object,
                    ..
                } = back.fetch_payload
                else {
                    panic!("a standalone fetch carries a standalone payload");
                };
                assert_eq!(
                    (start_group.into_inner(), start_object.into_inner()),
                    (START_GROUP, START_OBJECT),
                    "Section {} makes the start the caller's",
                    $sec
                );
                assert_eq!(
                    (end_group.into_inner(), end_object.into_inner()),
                    (END_GROUP, END_OBJECT),
                    "Section {} makes the end the caller's too, not group 0",
                    $sec
                );
            }

            /// The priority and the delivery order reach the peer.
            ///
            /// Both are fields of the FETCH on these three drafts and of no
            /// later one, which is why the call takes them as arguments here
            /// and why the gate for them lives in this range alone.
            ///
            /// # What it catches
            ///
            /// Sending group 0, object 0 as the end of every range, whatever
            /// the caller asked for:
            ///
            /// ```text
            /// the fetch encodes: InvalidRange(3, 4, 0, 0)
            /// ```
            ///
            /// It reddens nine, every gate here on all three drafts. Two of them
            /// read the range only through the helper that builds it, so a fetch
            /// that cannot be built at all takes them with it; the two cuts below
            /// are what say each field is measured on its own.
            ///
            /// Filling in the subscriber priority rather than passing the caller's
            /// through:
            ///
            /// ```text
            /// assertion `left == right` failed: the subscriber priority is the
            /// caller's to choose left: 128 right: 200
            /// ```
            ///
            /// It reddens three, this gate on all three drafts and nothing else.
            ///
            /// Filling in the delivery order the same way:
            ///
            /// ```text
            /// assertion `left == right` failed: the delivery order is the caller's
            /// to choose left: Ascending right: Descending
            /// ```
            ///
            /// It reddens three, this gate on all three drafts and nothing else.
            #[test]
            fn the_priority_and_the_order_reach_the_peer() {
                let mut ep = active();
                let back = round_trip(&mut ep);
                assert_eq!(
                    back.subscriber_priority, 200,
                    "the subscriber priority is the caller's to choose"
                );
                assert_eq!(
                    back.group_order,
                    GroupOrder::Descending,
                    "the delivery order is the caller's to choose"
                );
            }

            /// A zero the caller chose reaches the peer as a zero.
            ///
            /// An end object of 0 is a meaningful value when the caller means
            /// it, and all three drafts read it the same way: drafts 12 and 13
            /// Section 8.16 say "An Object ID value of 0 means the entire group
            /// is requested", and draft-14 Section 9.16.1 says "A
            /// Location.Object value of 0 means the entire group is requested."
            /// So what this gate holds is that a default value is still
            /// reachable, and reaching it is the caller saying so rather than
            /// the crate deciding.
            ///
            /// # What it catches
            ///
            /// Sending group 0, object 0 as the end of every range, whatever
            /// the caller asked for:
            ///
            /// ```text
            /// assertion `left == right` failed: the group after the one asked for
            /// left: 0 right: 8 failures:
            /// draft12::a_whole_group_can_still_be_asked_for
            /// draft12::the_end_of_the_range_reaches_the_peer
            /// draft12::the_priority_and_the_order_reach_the_peer draft13::a_wh
            /// ```
            ///
            /// It reddens nine, every gate here on all three drafts. Two of them
            /// read the range only through the helper that builds it, so a fetch
            /// that cannot be built at all takes them with it; the two cuts below
            /// are what say each field is measured on its own.
            #[test]
            fn a_whole_group_can_still_be_asked_for() {
                let mut ep = active();
                let (_, msg) = ep
                    .fetch(
                        crate::namespace(),
                        b"alpha".to_vec(),
                        128,
                        GroupOrder::Ascending,
                        crate::v(7),
                        crate::v(0),
                        crate::v(8),
                        crate::v(0),
                        Vec::new(),
                    )
                    .expect("a fetch of one whole group");
                let ControlMessage::Fetch(built) = msg else {
                    panic!("what was built was a FETCH");
                };
                let FetchPayload::Standalone { end_group, end_object, .. } = built.fetch_payload
                else {
                    panic!("a standalone fetch carries a standalone payload");
                };
                assert_eq!(end_group.into_inner(), 8, "the group after the one asked for");
                assert_eq!(
                    end_object.into_inner(),
                    0,
                    "zero here is the whole group, and reaches the peer as zero"
                );
            }
        }
    };
}

fetch_range_gates!(draft12, "draft12", 0xff00_000c, "8.16");
fetch_range_gates!(draft13, "draft13", 0xff00_000d, "8.16");
fetch_range_gates!(draft14, "draft14", 0xff00_000e, "9.16");

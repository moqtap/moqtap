#![cfg(any(
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
))]

//! A subscriber that joins a subscription can name the group it wants, rather
//! than only how far back from the live edge to count.
//!
//! One Joining Start field carries both, and the Fetch Type says which the
//! publisher is to read it as. Draft-15 Section 9.16.2.1 gives the two
//! readings — "For a Relative Joining Fetch, the publisher sets the Start
//! Location to {Subscribe Largest Location.Group - Joining Start, 0}" against
//! "For an Absolute Joining Fetch, the publisher sets the Start Location to
//! {Joining Start, 0}" — and draft-17 Section 9.14.2 leaves the choice with
//! the caller: "The subscriber can set the Start Location to an absolute
//! Location or a Location relative to the Largest group."
//!
//! # Why it is a gap
//!
//! The relative reading needs a number the subscriber may not have. It counts
//! back from the subscription's largest group, so an application that knows
//! which group it wants — one named in a catalogue, one an earlier session
//! stopped at — has to convert it into an offset, and the value it would need
//! to do the arithmetic with is the publisher's. An endpoint with only the
//! relative call cannot ask the question the absolute form exists to ask.
//!
//! # Where the range comes from
//!
//! Fetch Type 0x3 is defined on every draft from 11 and the call to send one
//! was on drafts 11 through 14 and draft-19 alone. These five are the drafts
//! whose call takes a Joining Request ID and a Joining Start and nothing else;
//! draft-14's carries the Subscriber Priority and Group Order that draft-15
//! moved into the parameters, so its gate stays with the rest of its draft's
//! message shapes in `draft14_endpoint_tests.rs`.
//!
//! Draft-19 is in the range although it had the pair already. It is the draft
//! the other four were copied from, and a file that gated the four copies and
//! not the original would not notice the original breaking.
//!
//! # The wording moves twice inside these five drafts
//!
//! The section number does. The Joining Fetch Range Calculation is draft-15
//! Section 9.16.2.1 and draft-16 Section 9.16.2.1, draft-17 Section 9.14.2.1,
//! draft-18 Section 10.12.2.1 and draft-19 Section 10.12.2.1 — written out one
//! draft at a time because that is the form something here can check.
//! So does the sentence. Drafts 15 and 16 word the relative reading with
//! "{Subscribe Largest Location.Group - Joining Start, 0}"; draft-17 renames
//! the value it counts from and words it "{Joining Location.Group - Joining
//! Start, 0}", which drafts 18 and 19 keep. The absolute reading is the one
//! sentence that survives the range unchanged.
//!
//! # Ablations, measured
//!
//! Five cuts, run against the two crates a change to `moqtap-client` can
//! reach, and reverted. Two of them are the same mistake in opposite
//! directions — sending the relative type from the absolute call and the
//! absolute type from the relative one — because a gate that checked only one
//! would be passed by an endpoint that had stopped telling them apart. The
//! second of that pair reddens draft-19's own unit test as well, which is the
//! one draft where something already watched the difference.
//!
//! ## Two of the five reddened nothing, and that is the finding
//!
//! Both were the same cut in a connection helper: `absolute_joining_fetch`
//! left calling the endpoint's relative builder, so the helper compiles, opens
//! its stream, writes a FETCH, and asks for the wrong one. Made on draft-16,
//! which no test drives that helper on, nothing failed. Made on draft-17,
//! whose helper `uni_control_plane.rs` does drive, nothing failed either — the
//! peer there reads the message's leading type varint, and both Fetch Types
//! are the same message.
//!
//! So the helpers were covered for opening a stream and writing a FETCH, and
//! not for which FETCH — a gap in the tests rather than in the crate, and the
//! same on all five drafts.
//!
//! It is closed. The peer in `uni_control_plane.rs` decodes the request it is
//! handed and reports the whole of it, and drafts 15 and 16 have a connection
//! gate of their own in `a_request_helper_asks_for_what_it_was_told.rs`. Both
//! cuts above were made again afterwards and both fail now.

#![allow(clippy::items_after_test_module)]

use moqtap_codec::varint::VarInt;

fn v(n: u64) -> VarInt {
    VarInt::from_u64(n).unwrap()
}

/// One draft's gate.
macro_rules! absolute_joining_gates {
    ($draft:ident, $feat:literal, $setup:tt) => {
        #[cfg(feature = $feat)]
        mod $draft {
            use moqtap_client::$draft::endpoint::Endpoint;
            use moqtap_client::$draft::session::request_id::Role;
            use moqtap_client::$draft::session::state::SessionState;
            use moqtap_codec::kvp::{KeyValuePair, KvpValue};
            #[allow(unused_imports)]
            use moqtap_codec::types::*;
            use moqtap_codec::$draft::message::*;

            /// A client with its session established and a budget to spend.
            fn active() -> Endpoint {
                let mut ep = Endpoint::new(Role::Client);
                ep.connect().expect("a client may open");
                crate::setup_for!($setup, ep);
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "the gate needs a running session"
                );
                ep
            }

            /// The Fetch Type and Joining Start a message reaches the peer
            /// with, read back off the encoded bytes rather than off the
            /// struct that was handed to them.
            fn on_the_wire(msg: ControlMessage) -> (u64, u64) {
                let mut buf = Vec::new();
                msg.encode(&mut buf).expect("the fetch encodes");
                let mut cursor = &buf[..];
                let ControlMessage::Fetch(back) =
                    ControlMessage::decode(&mut cursor).expect("the fetch decodes")
                else {
                    panic!("what was encoded was a FETCH");
                };
                let FetchPayload::Joining { joining_start, .. } = back.fetch_payload else {
                    panic!("what was encoded was a Joining Fetch");
                };
                (back.fetch_type as u64, joining_start.into_inner())
            }

            /// The two Fetch Types are told apart, and the Joining Start
            /// reaches the peer as it was given for both.
            ///
            /// The relative half is not decoration: it is what keeps the gate
            /// from being passed by an endpoint that sends 0x3 for everything.
            ///
            /// # What it catches
            ///
            /// An endpoint with no way to send the absolute form, which is
            /// what four of these five drafts had. Taking the method away
            /// again reports at the connection helper before it reports here,
            /// because the helper is the first caller the compiler reaches:
            ///
            /// ```text
            /// error[E0599]: no method named `absolute_joining_fetch` found
            /// for struct `endpoint::Endpoint` in the current scope
            /// ```
            ///
            /// And, once there is one, either type sent in the other's place:
            ///
            /// ```text
            /// assertion `left == right` failed: an Absolute Joining Fetch
            /// reaches the peer as Fetch Type 0x3; 0x2 asks the publisher to
            /// count back from a group the caller never named
            ///   left: 2
            ///  right: 3
            /// ```
            ///
            /// Each of those two reddens this gate on the draft it was cut
            /// in, and the second reddens draft-19's own unit test beside it,
            /// which is the only other place the difference is watched.
            #[test]
            fn an_absolute_joining_fetch_names_the_group_it_starts_at() {
                let mut ep = active();
                let (relative_id, relative) = ep
                    .joining_fetch(crate::v(0), crate::v(2), Vec::new())
                    .expect("this endpoint may join a subscription");
                let (absolute_id, absolute) = ep
                    .absolute_joining_fetch(crate::v(0), crate::v(9), Vec::new())
                    .expect("this endpoint may join a subscription at a group it names");
                assert_ne!(
                    relative_id.into_inner(),
                    absolute_id.into_inner(),
                    "two fetches are two requests"
                );

                let (relative_type, relative_start) = on_the_wire(relative);
                let (absolute_type, absolute_start) = on_the_wire(absolute);

                assert_eq!(
                    absolute_type,
                    FetchType::AbsoluteJoining as u64,
                    "an Absolute Joining Fetch reaches the peer as Fetch Type 0x3; 0x2 asks \
                     the publisher to count back from a group the caller never named"
                );
                assert_eq!(
                    absolute_start, 9,
                    "and the group it names reaches the peer as it was given, because the \
                     publisher reads it as the group to start at"
                );
                assert_eq!(
                    relative_type,
                    FetchType::RelativeJoining as u64,
                    "the relative call still sends 0x2, which is the half of this gate that \
                     the absolute half cannot stand without"
                );
                assert_eq!(relative_start, 2, "and its offset is the caller's too");
            }

            /// A joining fetch of either type carries what the caller
            /// attached.
            ///
            /// `a_fetch_carries_the_parameters_it_was_given.rs` makes the
            /// claim for the request as a whole. Here it is the second call
            /// that is watched: the pair share one private builder, and a
            /// second one written later could quietly stop passing the list
            /// on.
            ///
            /// # What it catches
            ///
            /// The cut that empties the list, which is made in the shared
            /// builder and so reddens this gate and the file that owns the
            /// claim together:
            ///
            /// ```text
            /// assertion `left == right` failed: the parameter the caller
            /// attached must be on the request
            ///   left: 0
            ///  right: 1
            /// ```
            #[test]
            fn an_absolute_joining_fetch_carries_the_parameters_it_was_given() {
                let mut ep = active();
                let attached =
                    KeyValuePair { key: crate::v(0x20), value: KvpValue::Varint(crate::v(42)) };
                let (_, msg) = ep
                    .absolute_joining_fetch(crate::v(0), crate::v(9), vec![attached])
                    .expect("this endpoint may join a subscription with parameters");
                let ControlMessage::Fetch(built) = msg else {
                    panic!("what was built was a FETCH");
                };
                assert_eq!(
                    built.parameters.len(),
                    1,
                    "the parameter the caller attached must be on the request"
                );
            }
        }
    };
}

/// SETUP, in the two shapes these five drafts take.
#[macro_export]
macro_rules! setup_for {
    (alpn, $ep:expr) => {{
        let _ = $ep.send_client_setup(vec![]).expect("CLIENT_SETUP");
        $ep.receive_server_setup(&ServerSetup {
            parameters: vec![KeyValuePair {
                key: $crate::v(0x02),
                value: KvpValue::Varint($crate::v(100)),
            }],
        })
        .expect("SERVER_SETUP");
        let _ = $ep.send_max_request_id($crate::v(100)).expect("MAX_REQUEST_ID");
    }};
    (options, $ep:expr) => {{
        let _ = $ep.send_setup(vec![]).expect("SETUP");
        $ep.receive_setup(&Setup { options: vec![] }).expect("SETUP");
    }};
}

absolute_joining_gates!(draft15, "draft15", alpn);
absolute_joining_gates!(draft16, "draft16", alpn);
absolute_joining_gates!(draft17, "draft17", options);
absolute_joining_gates!(draft18, "draft18", options);
absolute_joining_gates!(draft19, "draft19", options);

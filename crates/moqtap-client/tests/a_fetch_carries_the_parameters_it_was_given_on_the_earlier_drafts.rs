#![cfg(any(feature = "draft12", feature = "draft13", feature = "draft14"))]

//! A FETCH carries the parameters the caller gave it, on the three drafts that
//! used to fill the field in for them.
//!
//! The same claim as `a_fetch_carries_the_parameters_it_was_given.rs` makes for
//! drafts 15 through 19, in the shape these three drafts draw a FETCH: with a
//! Subscriber Priority and a Group Order of their own, which draft-15 moves
//! into the parameters and this range does not.
//!
//! # Why it is a gap
//!
//! Each of these drafts registers AUTHORIZATION TOKEN, DELIVERY TIMEOUT and
//! MAX CACHE DURATION as message parameters. A fetch that cannot carry an
//! authorization token cannot fetch from a track that requires one, and the
//! field was being written by the crate rather than by the application.
//!
//! # Both kinds of FETCH
//!
//! A Joining Fetch is the same message under a different Fetch Type: one
//! Parameters field, the same three parameters registered for it, and nothing
//! about naming the range through a subscription rather than outright that
//! changes what may be attached. So the claim covers both, and the third gate
//! on each draft is the joining one.
//!
//! Drafts 12 and 13 took the argument on that call from the start. Draft-14
//! had no such call at all until the sender was written, which is why the gate
//! arrives on three drafts at once rather than on the one it was written for.
//! Drafts 15 through 19 had the call and filled the field in themselves for a
//! round longer; `a_fetch_carries_the_parameters_it_was_given.rs` gates them
//! now, in the shape those drafts give the call.
//!
//! # Ablations, measured
//!
//! Two cuts, run against the two crates a change to `moqtap-client` can reach,
//! and reverted. The second gate on each draft is the control: without it a
//! change that filled the field with something of its own would satisfy the
//! first.

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

/// A subscription for a joining fetch to attach itself to.
///
/// Draft-12 draws the Filter Type as a variable-length integer where the two
/// drafts above it take the typed value straight through, which is the only
/// thing that differs between the arms.
macro_rules! a_subscription_to_join {
    (varint_filter, $ep:expr) => {
        $ep.subscribe(
            crate::namespace(),
            b"alpha".to_vec(),
            128,
            GroupOrder::Ascending,
            crate::v(0x2),
            Vec::new(),
        )
    };
    (typed_filter, $ep:expr) => {
        $ep.subscribe(
            crate::namespace(),
            b"alpha".to_vec(),
            128,
            GroupOrder::Ascending,
            FilterType::LargestObject,
            Vec::new(),
        )
    };
}

/// A Relative Joining Fetch.
///
/// All three drafts have a call per kind, so the Fetch Type is not something
/// a caller passes and not something one of these gates can pass wrongly.
macro_rules! a_joining_fetch {
    ($ep:expr, $parent:expr, $params:expr) => {
        $ep.joining_fetch(128, GroupOrder::Ascending, $parent, crate::v(2), $params)
    };
}

/// One draft's gates.
macro_rules! fetch_parameter_gates {
    ($draft:ident, $feat:literal, $version:literal, $filter:tt) => {
        #[cfg(feature = $feat)]
        mod $draft {
            use moqtap_client::$draft::endpoint::Endpoint;
            use moqtap_client::$draft::session::request_id::Role;
            use moqtap_client::$draft::session::state::SessionState;
            use moqtap_codec::kvp::{KeyValuePair, KvpValue};
            #[allow(unused_imports)]
            use moqtap_codec::types::*;
            use moqtap_codec::$draft::message::*;

            /// A client with its session established.
            fn active() -> Endpoint {
                let mut ep = Endpoint::new(Role::Client);
                ep.connect().expect("a client may open");
                let _ =
                    ep.send_client_setup(vec![crate::v($version)], vec![]).expect("CLIENT_SETUP");
                ep.receive_server_setup(&ServerSetup {
                    selected_version: crate::v($version),
                    parameters: vec![KeyValuePair {
                        key: crate::v(0x02),
                        value: KvpValue::Varint(crate::v(100)),
                    }],
                })
                .expect("SERVER_SETUP");
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "the gate needs a running session"
                );
                ep
            }

            /// DELIVERY TIMEOUT, chosen so an empty list cannot be mistaken
            /// for it. An even key, so its value is a varint, and registered
            /// on all three drafts.
            fn parameter() -> KeyValuePair {
                KeyValuePair { key: crate::v(0x02), value: KvpValue::Varint(crate::v(3000)) }
            }

            /// The parameters a fetch is given reach the peer.
            ///
            /// # What it catches
            ///
            /// Sending an empty list whatever the caller passed, which is
            /// what all three drafts did and what there was no argument to
            /// change:
            ///
            /// ```text
            /// assertion `left == right` failed: the parameter the caller
            /// attached must reach the peer, and this call used to send an
            /// empty list whatever it was given left: 0 right: 1
            /// ```
            ///
            /// It reddens three, this gate on each draft in the range and
            /// nothing else in the client or the proxy.
            #[test]
            fn the_parameters_a_fetch_is_given_reach_the_peer() {
                let mut ep = active();
                let (_, msg) = ep
                    .fetch(
                        crate::namespace(),
                        b"alpha".to_vec(),
                        128,
                        GroupOrder::Ascending,
                        crate::v(0),
                        crate::v(0),
                        crate::v(1),
                        crate::v(0),
                        vec![parameter()],
                    )
                    .expect("this endpoint may fetch with parameters");
                let mut buf = Vec::new();
                msg.encode(&mut buf).expect("the fetch encodes");
                let mut cursor = &buf[..];
                let ControlMessage::Fetch(back) =
                    ControlMessage::decode(&mut cursor).expect("the fetch decodes")
                else {
                    panic!("what was encoded was a FETCH");
                };
                assert_eq!(
                    back.parameters.len(),
                    1,
                    "the parameter the caller attached must reach the peer, and this call \
                     used to send an empty list whatever it was given"
                );
                assert_eq!(
                    back.parameters[0].key.into_inner(),
                    0x02,
                    "and it must be the one the caller passed"
                );
            }

            /// A fetch with nothing attached still carries nothing.
            ///
            /// # What it catches
            ///
            /// Nothing the cut reaches, which is what a control is for. The cut
            /// sends an empty list whatever it is given, which is what this
            /// gate asserts, so it stays green under it.
            #[test]
            fn a_fetch_given_no_parameters_carries_none() {
                let mut ep = active();
                let (_, msg) = ep
                    .fetch(
                        crate::namespace(),
                        b"alpha".to_vec(),
                        128,
                        GroupOrder::Ascending,
                        crate::v(0),
                        crate::v(0),
                        crate::v(1),
                        crate::v(0),
                        Vec::new(),
                    )
                    .expect("this endpoint may fetch without parameters");
                let ControlMessage::Fetch(built) = msg else {
                    panic!("what was built was a FETCH");
                };
                assert!(
                    built.parameters.is_empty(),
                    "an empty list is still what an empty list means"
                );
            }

            /// The other kind of FETCH carries them too.
            ///
            /// A Joining Fetch is a FETCH: one message type, one Parameters
            /// field, and the same three registered parameters to put in it.
            /// Nothing about naming the range through a subscription rather
            /// than outright changes what may be attached to the request.
            ///
            /// # What it catches
            ///
            /// A joining fetch that sends an empty list whatever the caller
            /// passed, which is what draft-14's sender was written as before
            /// this gate:
            ///
            /// ```text
            /// assertion `left == right` failed: a Joining Fetch is a FETCH,
            /// and the parameter the caller attached must reach the peer
            ///   left: 0
            ///  right: 1
            /// ```
            ///
            /// It reddens one, this gate on draft-14, because the cut is a
            /// draft-14 sender.
            #[test]
            fn the_parameters_a_joining_fetch_is_given_reach_the_peer() {
                let mut ep = active();
                let (parent, _) = a_subscription_to_join!($filter, ep)
                    .expect("a subscription for the fetch to join");
                ep.receive_message(ControlMessage::SubscribeOk(SubscribeOk {
                    request_id: parent,
                    track_alias: crate::v(1),
                    expires: crate::v(0),
                    group_order: GroupOrder::Ascending,
                    content_exists: ContentExists::NoLargestLocation,
                    largest_location: None,
                    parameters: Vec::new(),
                }))
                .expect("the subscription is answered");

                let (_, msg) = a_joining_fetch!(ep, parent, vec![parameter()])
                    .expect("this endpoint may join a subscription with parameters");
                let mut buf = Vec::new();
                msg.encode(&mut buf).expect("the fetch encodes");
                let mut cursor = &buf[..];
                let ControlMessage::Fetch(back) =
                    ControlMessage::decode(&mut cursor).expect("the fetch decodes")
                else {
                    panic!("what was encoded was a FETCH");
                };
                assert_eq!(
                    back.parameters.len(),
                    1,
                    "a Joining Fetch is a FETCH, and the parameter the caller attached must \
                     reach the peer"
                );
                assert_eq!(
                    back.parameters[0].key.into_inner(),
                    0x02,
                    "and it must be the one the caller passed"
                );
            }
        }
    };
}

fetch_parameter_gates!(draft12, "draft12", 0xff00_000c, varint_filter);
fetch_parameter_gates!(draft13, "draft13", 0xff00_000d, typed_filter);
fetch_parameter_gates!(draft14, "draft14", 0xff00_000e, typed_filter);

#![cfg(any(feature = "draft12", feature = "draft13", feature = "draft14"))]

//! A namespace subscription carries the parameters the caller gave it, on the
//! three drafts that used to fill the field in for them.
//!
//! The last of the row's builders, after SUBSCRIBE, FETCH, the track-status
//! request and the announcement. It is also the one where the drafts name the
//! message themselves rather than leaving the reasoning to be assembled:
//!
//! Draft-12 Section 8.2.1.1: "The AUTHORIZATION TOKEN parameter (Parameter
//! Type 0x03) MAY appear in a CLIENT_SETUP, SERVER_SETUP, SUBSCRIBE,
//! SUBSCRIBE_ANNOUNCES, ANNOUNCE, TRACK_STATUS_REQUEST or FETCH message."
//!
//! Draft-13 Section 8.2.1.1: "The AUTHORIZATION TOKEN parameter (Parameter
//! Type 0x03) MAY appear in a CLIENT_SETUP, SERVER_SETUP, SUBSCRIBE,
//! SUBSCRIBE_NAMESPACE, ANNOUNCE, TRACK_STATUS or FETCH message."
//!
//! Draft-14 Section 9.2.1.1: "The AUTHORIZATION TOKEN parameter (Parameter
//! Type 0x03) MAY appear in a CLIENT_SETUP, SERVER_SETUP, PUBLISH, SUBSCRIBE,
//! SUBSCRIBE_UPDATE, SUBSCRIBE_NAMESPACE, PUBLISH_NAMESPACE, TRACK_STATUS or
//! FETCH message."
//!
//! Each of the three lists this very message by name, so an endpoint that
//! cannot attach a parameter to it cannot subscribe to a namespace on a peer
//! that requires a token - and none of the three could until the builder
//! took an argument to attach one with.
//!
//! # Two names for one request
//!
//! Draft-12 calls it SUBSCRIBE_ANNOUNCES. Draft-13 renamed the message
//! SUBSCRIBE_NAMESPACE and the builder with it, and draft-14 renamed the field
//! the prefix travels in as well. Nothing else about the parameter list moved.
//!
//! # What the gates observe
//!
//! The claim gate encodes what the builder returns and decodes it back, so it
//! reads what a peer would receive rather than what the endpoint stored. The
//! second gate on each draft is the control: an empty list still means an
//! empty list, which is what the cut below leaves behind, so the pair can only
//! both pass when the argument is actually carried.
//!
//! # Ablations, measured
//!
//! One cut, run against the two crates a change to `moqtap-client` can reach
//! and then reverted: the builder sends an empty list whatever it was given,
//! which all three drafts did before it forwarded them. It reddens three
//! tests of the 3,464 in those crates - the first gate on each draft here -
//! and leaves the other 165 test binaries green. The control on each draft
//! stays green under the cut, which is what a control is for.

#![allow(clippy::items_after_test_module)]

use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;

/// The prefix every subscription here is opened under.
fn prefix() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec()])
}

fn v(n: u64) -> VarInt {
    VarInt::from_u64(n).unwrap()
}

/// One draft's gates. `$ask` names the builder and `$built` the message it
/// makes, both of which the rename at draft-13 moves.
macro_rules! namespace_subscription_parameter_gates {
    ($draft:ident, $feat:literal, $version:literal, $ask:ident, $built:ident) => {
        #[cfg(feature = $feat)]
        mod $draft {
            use moqtap_client::$draft::endpoint::Endpoint;
            use moqtap_client::$draft::session::request_id::Role;
            use moqtap_client::$draft::session::state::SessionState;
            use moqtap_codec::kvp::{KeyValuePair, KvpValue};
            #[allow(unused_imports)]
            use moqtap_codec::types::*;
            use moqtap_codec::$draft::message::*;

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

            /// An even key, so a varint value. Which parameter it is does not
            /// matter to the claim - that the list the caller passes is the
            /// list that goes out - and an even key keeps the gate to one
            /// well-formed pair.
            fn parameter() -> KeyValuePair {
                KeyValuePair { key: crate::v(0x02), value: KvpValue::Varint(crate::v(3000)) }
            }

            /// The parameters the subscription is given reach the peer.
            ///
            /// # What it catches
            ///
            /// Sending an empty list whatever the caller passed, which is
            /// what all three drafts did:
            ///
            /// ```text
            /// assertion `left == right` failed: the parameter the caller
            /// attached must reach the peer, and this call used to send an
            /// empty list whatever it was given
            ///   left: 0
            ///  right: 1
            /// ```
            #[test]
            fn the_parameters_a_namespace_subscription_is_given_reach_the_peer() {
                let mut ep = active();
                let (_, msg) = ep
                    .$ask(crate::prefix(), vec![parameter()])
                    .expect("this endpoint may subscribe with parameters");
                let mut buf = Vec::new();
                msg.encode(&mut buf).expect("the request encodes");
                let mut cursor = &buf[..];
                let back = ControlMessage::decode(&mut cursor).expect("the request decodes");
                let ControlMessage::$built(ref r) = back else {
                    panic!("what was encoded was the namespace subscription: {back:?}");
                };
                let carried = r.parameters.clone();
                assert_eq!(
                    carried.len(),
                    1,
                    "the parameter the caller attached must reach the peer, and this call \
                     used to send an empty list whatever it was given"
                );
                assert_eq!(
                    carried[0].key.into_inner(),
                    0x02,
                    "and it must be the one the caller passed"
                );
            }

            /// A subscription with nothing attached still carries nothing.
            ///
            /// # What it catches
            ///
            /// Nothing the cut reaches, which is what a control is for: the cut
            /// sends an empty list whatever it is given, which is what this
            /// gate asserts.
            #[test]
            fn a_namespace_subscription_given_no_parameters_carries_none() {
                let mut ep = active();
                let (_, msg) = ep
                    .$ask(crate::prefix(), Vec::new())
                    .expect("this endpoint may subscribe without parameters");
                let ControlMessage::$built(ref r) = msg else {
                    panic!("what was built was the namespace subscription: {msg:?}");
                };
                let carried = r.parameters.clone();
                assert!(carried.is_empty(), "an empty list is still what an empty list means");
            }
        }
    };
}

namespace_subscription_parameter_gates!(
    draft12,
    "draft12",
    0xff00_000c,
    subscribe_announces,
    SubscribeAnnounces
);
namespace_subscription_parameter_gates!(
    draft13,
    "draft13",
    0xff00_000d,
    subscribe_namespace,
    SubscribeNamespace
);
namespace_subscription_parameter_gates!(
    draft14,
    "draft14",
    0xff00_000e,
    subscribe_namespace,
    SubscribeNamespace
);

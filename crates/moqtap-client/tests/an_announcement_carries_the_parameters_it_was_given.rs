#![cfg(any(feature = "draft12", feature = "draft13", feature = "draft14"))]

//! An announcement carries the parameters the caller gave it, on drafts 12, 13
//! and 14.
//!
//! The fourth of the row's builders, after SUBSCRIBE, FETCH and the
//! track-status request. The same claim and the same reason: each of these
//! drafts registers AUTHORIZATION TOKEN, DELIVERY TIMEOUT and MAX CACHE
//! DURATION, so an endpoint that cannot attach one cannot advertise a
//! namespace to a peer that requires it.
//!
//! # Two names for one request
//!
//! Drafts 12 and 13 call it ANNOUNCE. Draft-14 renamed the message
//! PUBLISH_NAMESPACE and the builder with it; nothing else about the field
//! changed.
//!
//! # Ablations, measured
//!
//! One cut, run against the two crates a change to `moqtap-client` can reach
//! and then reverted: the builder sends an empty list whatever it was given.
//! It reddens three tests of the 3,458 in those crates - the first gate on
//! each draft here -
//! and leaves the other 164 test binaries green. The second gate on each draft
//! is the control, and it stays green under the cut, which is the point of
//! it.

#![allow(clippy::items_after_test_module)]

use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;

/// The namespace every announcement here is for.
fn namespace() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec()])
}

fn v(n: u64) -> VarInt {
    VarInt::from_u64(n).unwrap()
}

/// One draft's gates. `$ask` names the builder and `$built` the message it
/// makes, both of which the rename at draft-14 moves.
macro_rules! announce_parameter_gates {
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

            /// DELIVERY TIMEOUT: an even key, so a varint value, and
            /// registered on all three drafts.
            fn parameter() -> KeyValuePair {
                KeyValuePair { key: crate::v(0x02), value: KvpValue::Varint(crate::v(3000)) }
            }

            /// The parameters the announcement is given reach the peer.
            ///
            /// # What it catches
            ///
            /// Sending an empty list whatever the caller passed:
            ///
            /// ```text
            /// assertion `left == right` failed: the parameter the caller
            /// attached must reach the peer, not the empty list a call that
            /// ignores its argument sends
            ///   left: 0
            ///  right: 1
            /// ```
            #[test]
            fn the_parameters_an_announcement_is_given_reach_the_peer() {
                let mut ep = active();
                let (_, msg) = ep
                    .$ask(crate::namespace(), vec![parameter()])
                    .expect("this endpoint may announce with parameters");
                let mut buf = Vec::new();
                msg.encode(&mut buf).expect("the announcement encodes");
                let mut cursor = &buf[..];
                let back = ControlMessage::decode(&mut cursor).expect("the announcement decodes");
                let ControlMessage::$built(ref r) = back else {
                    panic!("what was encoded was the announcement: {back:?}");
                };
                let carried = r.parameters.clone();
                assert_eq!(
                    carried.len(),
                    1,
                    "the parameter the caller attached must reach the peer, not the empty \
                     list a call that ignores its argument sends"
                );
                assert_eq!(
                    carried[0].key.into_inner(),
                    0x02,
                    "and it must be the one the caller passed"
                );
            }

            /// An announcement with nothing attached still carries nothing.
            ///
            /// # What it catches
            ///
            /// Nothing the cut reaches, which is what a control is for: the cut
            /// sends an empty list whatever it is given, which is what this
            /// gate asserts.
            #[test]
            fn an_announcement_given_no_parameters_carries_none() {
                let mut ep = active();
                let (_, msg) = ep
                    .$ask(crate::namespace(), Vec::new())
                    .expect("this endpoint may announce without parameters");
                let ControlMessage::$built(ref r) = msg else {
                    panic!("what was built was the announcement: {msg:?}");
                };
                let carried = r.parameters.clone();
                assert!(carried.is_empty(), "an empty list is still what an empty list means");
            }
        }
    };
}

announce_parameter_gates!(draft12, "draft12", 0xff00_000c, announce, Announce);
announce_parameter_gates!(draft13, "draft13", 0xff00_000d, announce, Announce);
announce_parameter_gates!(draft14, "draft14", 0xff00_000e, publish_namespace, PublishNamespace);

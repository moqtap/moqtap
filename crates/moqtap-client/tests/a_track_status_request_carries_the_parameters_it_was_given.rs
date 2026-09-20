#![cfg(any(feature = "draft12", feature = "draft13", feature = "draft14"))]

//! A TRACK_STATUS request carries the parameters the caller gave it, on
//! drafts 12, 13 and 14.
//!
//! The third of the row's builders, after SUBSCRIBE and FETCH. The same claim
//! and the same reason: each of these drafts registers AUTHORIZATION TOKEN,
//! DELIVERY TIMEOUT and MAX CACHE DURATION, so an application that cannot
//! attach one cannot ask the status of a track that requires it.
//!
//! # Two shapes, because the request has two names
//!
//! Draft-12 calls the request `track_status_request` and keeps `track_status`
//! for the answer, whose builder takes the caller's parameters. Drafts
//! 13 and 14 name the request `track_status` and word it like a SUBSCRIBE,
//! with a priority, a group order, a forward flag and a filter of its own.
//!
//! # Ablations, measured
//!
//! One cut, run against the two crates a change to `moqtap-client` can reach,
//! and reverted. The second gate on each draft is the control.

#![allow(clippy::items_after_test_module)]

use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;

/// The namespace every request here is for.
fn namespace() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec()])
}

fn v(n: u64) -> VarInt {
    VarInt::from_u64(n).unwrap()
}

/// One draft's gates. `$ask` names the builder and spells the arguments it
/// draws besides the track and the parameters.
macro_rules! track_status_parameter_gates {
    ($draft:ident, $feat:literal, $version:literal, $ask:ident, $built:ident,
     ($($extra:expr),*)) => {
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

            /// The parameters the request is given reach the peer.
            ///
            /// # What it catches
            ///
            /// Sending an empty list whatever the caller passed:
            ///
            /// ```text
            /// assertion `left == right` failed: the parameter the caller
            /// attached must reach the peer, not the empty list a call that
            /// ignores its argument sends left: 0 right: 1
            /// ```
            ///
            /// It reddens three, this gate on each draft in the range and
            /// nothing else in the client or the proxy.
            #[test]
            fn the_parameters_a_track_status_request_is_given_reach_the_peer() {
                let mut ep = active();
                let (_, msg) = ep
                    .$ask(crate::namespace(), b"alpha".to_vec(), $($extra,)* vec![parameter()])
                    .expect("this endpoint may ask with parameters");
                let mut buf = Vec::new();
                msg.encode(&mut buf).expect("the request encodes");
                let mut cursor = &buf[..];
                let back = ControlMessage::decode(&mut cursor).expect("the request decodes");
                let ControlMessage::$built(ref r) = back else {
                    panic!("what was encoded was the request: {back:?}");
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

            /// A request with nothing attached still carries nothing.
            ///
            /// # What it catches
            ///
            /// Nothing the cut reaches, which is what a control is for: the cut
            /// sends an empty list whatever it is given, which is what this
            /// gate asserts.
            #[test]
            fn a_track_status_request_given_no_parameters_carries_none() {
                let mut ep = active();
                let (_, msg) = ep
                    .$ask(crate::namespace(), b"alpha".to_vec(), $($extra,)* Vec::new())
                    .expect("this endpoint may ask without parameters");
                let ControlMessage::$built(ref r) = msg else {
                    panic!("what was built was the request: {msg:?}");
                };
                let carried = r.parameters.clone();
                assert!(carried.is_empty(), "an empty list is still what an empty list means");
            }
        }
    };
}

track_status_parameter_gates!(
    draft12,
    "draft12",
    0xff00_000c,
    track_status_request,
    TrackStatusRequest,
    ()
);
track_status_parameter_gates!(
    draft13,
    "draft13",
    0xff00_000d,
    track_status,
    TrackStatus,
    (128, GroupOrder::Ascending, Forward::Forward, FilterType::LargestObject)
);
track_status_parameter_gates!(
    draft14,
    "draft14",
    0xff00_000e,
    track_status,
    TrackStatus,
    (128, GroupOrder::Ascending, Forward::Forward, FilterType::LargestObject)
);

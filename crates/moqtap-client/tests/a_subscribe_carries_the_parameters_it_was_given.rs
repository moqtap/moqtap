#![cfg(any(feature = "draft12", feature = "draft13", feature = "draft14"))]

//! A SUBSCRIBE carries the parameters the caller gave it, on drafts 12, 13
//! and 14.
//!
//! # Why the range is these three
//!
//! `Endpoint::subscribe` takes the caller's parameter list on drafts 15 and up
//! already, so these three are where the claim has to be held.
//!
//! `Endpoint::subscribe_range` is the second builder carrying that list on
//! these three: it hands its `parameters` argument to the same
//! `subscribe_inner` `subscribe` does, so a gate on `subscribe` covers the
//! shape both write. It is a per-draft entry point drafts 07 through 14 have
//! and drafts 15 and up do not. The draft-neutral
//! `AnyConnection::subscribe_range` reaches every draft, but the list it passes
//! is never the caller's: drafts 07 through 11 take no parameter list at all,
//! the arms for 12, 13 and 14 pass an empty one, and from draft-15 it passes a
//! single parameter holding the filter it built. So it is not where this claim
//! lives either.
//!
//! # Why this is a gap and not a matter of taste
//!
//! Each of these three drafts registers AUTHORIZATION TOKEN, DELIVERY TIMEOUT
//! and MAX CACHE DURATION as message parameters. A subscriber that cannot put
//! an authorization token on a SUBSCRIBE cannot subscribe to a track that
//! requires one, and no rewording of the API makes that reachable — the field
//! has to be the application's to write and not the crate's.
//!
//! DELIVERY TIMEOUT is what these gates attach. It is an even key, so its
//! value is a varint, and it is registered on all three drafts, which makes it
//! the one choice that needs no per-draft spelling.
//!
//! # Ablations, measured
//!
//! One cut, run against the two crates a change to `moqtap-client` can reach,
//! and reverted. The second gate in each draft is the control: without it, a
//! change that filled the field with something of its own would satisfy the
//! first.

#![allow(clippy::items_after_test_module)]

use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;

/// The namespace every subscribe here is for.
fn namespace() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec()])
}

fn v(n: u64) -> VarInt {
    VarInt::from_u64(n).unwrap()
}

/// One draft's gates. `$filter` is the Filter Type in the shape that draft
/// draws it: a bare varint on draft-12, an enum on drafts 13 and 14.
macro_rules! subscribe_parameter_gates {
    ($draft:ident, $feat:literal, $version:literal, $filter:expr) => {
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

            /// DELIVERY TIMEOUT, chosen so that an empty list cannot be
            /// mistaken for it.
            fn parameter() -> KeyValuePair {
                KeyValuePair { key: crate::v(0x02), value: KvpValue::Varint(crate::v(3000)) }
            }

            /// The parameters a subscribe is given reach the peer.
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
            fn the_parameters_a_subscribe_is_given_reach_the_peer() {
                let mut ep = active();
                let (_, msg) = ep
                    .subscribe(
                        crate::namespace(),
                        b"alpha".to_vec(),
                        128,
                        GroupOrder::Ascending,
                        $filter,
                        vec![parameter()],
                    )
                    .expect("this endpoint may subscribe with parameters");
                let mut buf = Vec::new();
                msg.encode(&mut buf).expect("the subscribe encodes");
                let mut cursor = &buf[..];
                let ControlMessage::Subscribe(back) =
                    ControlMessage::decode(&mut cursor).expect("the subscribe decodes")
                else {
                    panic!("what was encoded was a SUBSCRIBE");
                };
                assert_eq!(
                    back.parameters.len(),
                    1,
                    "the parameter the caller attached must reach the peer, not the empty \
                     list a call that ignores its argument sends"
                );
                assert_eq!(
                    back.parameters[0].key.into_inner(),
                    0x02,
                    "and it must be the one the caller passed"
                );
            }

            /// A subscribe with nothing attached still carries nothing.
            ///
            /// # What it catches
            ///
            /// Nothing the cut reaches, which is what a control is for. The cut
            /// sends an empty list whatever it is given, which is what this
            /// gate asserts, so it stays green under it — and without it a
            /// change that filled the field with something of its own would
            /// satisfy the only other assertion here.
            #[test]
            fn a_subscribe_given_no_parameters_carries_none() {
                let mut ep = active();
                let (_, msg) = ep
                    .subscribe(
                        crate::namespace(),
                        b"alpha".to_vec(),
                        128,
                        GroupOrder::Ascending,
                        $filter,
                        Vec::new(),
                    )
                    .expect("this endpoint may subscribe without parameters");
                let ControlMessage::Subscribe(built) = msg else {
                    panic!("what was built was a SUBSCRIBE");
                };
                assert!(
                    built.parameters.is_empty(),
                    "an empty list is still what an empty list means"
                );
            }
        }
    };
}

subscribe_parameter_gates!(draft12, "draft12", 0xff00_000c, crate::v(0x2));
subscribe_parameter_gates!(draft13, "draft13", 0xff00_000d, FilterType::LargestObject);
subscribe_parameter_gates!(draft14, "draft14", 0xff00_000e, FilterType::LargestObject);

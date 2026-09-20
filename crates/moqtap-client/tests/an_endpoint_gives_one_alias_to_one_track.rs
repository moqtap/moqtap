#![cfg(any(
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
))]

//! An endpoint that chooses a Track Alias will not give it to a second track.
//!
//! Draft-19 Section 11.1, and draft-18 in the same words: "The same Track
//! Alias MUST NOT be used by a publisher to refer to two different Tracks
//! simultaneously in the same session." Draft-17 Sections 9.9 and 9.11 state
//! the same sentence once per message; drafts 12 through 16 state it without
//! "by a publisher" and without "in the same session".
//!
//! Every one of those sentences is two rules, and the second one is what
//! `duplicate_track_alias_closes_the_session.rs` measures: a subscriber that
//! *receives* a duplicate closes the session. This file is the first one,
//! which is addressed to the endpoint doing the choosing. On these eight
//! drafts that is `publish`, the only place this crate names an alias itself.
//!
//! # Why a refusal and not a close
//!
//! There is nothing to close over. The message is declined before it is built,
//! so the alias never reaches the peer, no Request ID is spent and the session
//! is exactly where it was. A close would be this endpoint punishing the peer
//! for something this endpoint was asked to do.
//!
//! # Why "in use" is wider here than in the receiving half
//!
//! The receiving half is qualified - "the same Track Alias as a different
//! track with an active subscription", "with an Established subscription" -
//! and this half is not. Once a PUBLISH carrying an alias has gone out, giving
//! that alias to a second track is what the sentence forbids, whether or not
//! the PUBLISH has been answered yet.
//!
//! # Why drafts 12, 13 and 14 are in the range
//!
//! All three state the sentence in the same words, and all three draw a Track
//! Alias field in the PUBLISH the endpoint sends. The caller names that alias
//! on the call, along with the delivery order, the largest location and the
//! parameters, and all three build the message with the same call — so the four
//! gates below are the same four gates on each of them. An endpoint that could
//! not say which alias it meant would give two tracks one alias by
//! construction, which is exactly what the sentence forbids.
//!
//! Drafts 07 through 11 are outside the range because there the alias is
//! chosen in SUBSCRIBE - that half is in
//! `a_track_alias_names_one_track_at_the_publisher.rs`.
//!
//! # Ablations, measured
//!
//! Four cuts were made, run and reverted, each recorded on the gate it belongs
//! to. None of them reddens anything in the receiving half's files, which is
//! what says the two halves of the sentence are two rules.

#![allow(clippy::items_after_test_module)]

use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;

/// The namespace both tracks live in, so that the track name is the only thing
/// telling them apart.
fn namespace() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec()])
}

fn v(n: u64) -> VarInt {
    VarInt::from_u64(n).unwrap()
}

/// A PUBLISH this endpoint sends, in the four shapes the call takes.
#[macro_export]
macro_rules! we_publish {
    (rich, $ep:expr, $alias:expr, $track:expr) => {
        $ep.publish(
            $crate::namespace(),
            $track.to_vec(),
            $crate::v($alias),
            GroupOrder::Ascending,
            None,
            Forward::Forward,
            Vec::new(),
        )
    };
    (params, $ep:expr, $alias:expr, $track:expr) => {
        $ep.publish($crate::namespace(), $track.to_vec(), $crate::v($alias), Vec::new())
    };
    (ext, $ep:expr, $alias:expr, $track:expr) => {
        $ep.publish($crate::namespace(), $track.to_vec(), $crate::v($alias), Vec::new(), Vec::new())
    };
}

/// The peer refusing an offer, which is the shortest way to end one.
#[macro_export]
macro_rules! peer_refuses {
    (publish_error, $ep:expr, $id:expr) => {
        $ep.receive_publish_error(&PublishError {
            request_id: $id,
            error_code: $crate::v(1),
            reason_phrase: b"no".to_vec(),
        })
    };
    (plain, $ep:expr, $id:expr) => {
        $ep.receive_request_error(&RequestError {
            request_id: $id,
            error_code: $crate::v(1),
            reason_phrase: b"no".to_vec(),
        })
    };
    (retry, $ep:expr, $id:expr) => {
        $ep.receive_request_error(&RequestError {
            request_id: $id,
            error_code: $crate::v(1),
            retry_interval: $crate::v(0),
            reason_phrase: b"no".to_vec(),
        })
    };
    (by_id, $ep:expr, $id:expr) => {
        $ep.receive_request_error(
            $id,
            &RequestError {
                error_code: $crate::v(1),
                retry_interval: $crate::v(0),
                reason_phrase: b"no".to_vec(),
            },
        )
    };
    (redirect, $ep:expr, $id:expr) => {
        $ep.receive_request_error(
            $id,
            &RequestError {
                error_code: $crate::v(1),
                retry_interval: $crate::v(0),
                reason_phrase: b"no".to_vec(),
                redirect: None,
            },
        )
    };
}

/// One draft's four gates.
macro_rules! sender_alias_gates {
    ($draft:ident, $feat:literal, $setup:tt, $pub:tt, $refuse:tt, $sec:literal) => {
        #[cfg(feature = $feat)]
        mod $draft {
            #[allow(unused_imports)]
            use moqtap_client::$draft::endpoint::{Endpoint, EndpointError};
            use moqtap_client::$draft::session::request_id::Role;
            use moqtap_client::$draft::session::state::SessionState;
            #[allow(unused_imports)]
            use moqtap_codec::kvp::{KeyValuePair, KvpValue};
            #[allow(unused_imports)]
            use moqtap_codec::types::*;
            #[allow(unused_imports)]
            use moqtap_codec::$draft::message::*;

            /// The alias both tracks are asked to answer to.
            const ALIAS: u64 = 7;

            const ALPHA: &[u8] = b"alpha";
            const BETA: &[u8] = b"beta";

            /// A client with its session established and a ceiling from the
            /// peer, without which no PUBLISH of this endpoint's is legal.
            fn active() -> Endpoint {
                let mut ep = Endpoint::new(Role::Client);
                ep.connect().expect("a client may open");
                crate::client_setup!($setup, ep);
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "the gates need a running session"
                );
                ep
            }

            /// The session is untouched: a message this endpoint declined to
            /// build never reached the peer.
            fn still_running(ep: &Endpoint) {
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "Section {} forbids the publisher from choosing the alias twice; \
                     declining to is not a reason to end the session",
                    $sec
                );
            }

            /// One alias for two tracks is refused before the message exists.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// Deleting the `alias_held_elsewhere` call from `publish`:
            ///
            /// ```text
            /// this endpoint gave one alias to two tracks: (VarInt(2), Publish(Publish { request_id: VarInt(2), track_namespace: TrackNamespace([[99, 111, 110, 102, 111, 114, 109, 97, 110, 99, 101]]), track_name: [98, 101, 116, 97], track_alias: VarInt(7), parameters: [] }))
            /// ```
            ///
            /// It reddens twenty tests: this gate and the identifier gate
            /// below on all eight drafts, and two more on drafts 12 and 13 in
            /// `a_publish_this_endpoint_makes_has_a_lifecycle.rs`, where the
            /// same check is what stops an offer taking an alias the peer's
            /// own offer is using and what frees one when a subscription ends.
            #[test]
            fn one_alias_for_two_tracks_is_refused() {
                let mut ep = active();
                crate::we_publish!($pub, ep, ALIAS, ALPHA).expect("the first offer");

                let err = crate::we_publish!($pub, ep, ALIAS, BETA)
                    .expect_err("this endpoint gave one alias to two tracks");
                assert!(
                    matches!(err, EndpointError::TrackAliasInUse { .. }),
                    "the refusal should name the alias that is spoken for, and named {err:?}"
                );
                assert_eq!(
                    err.session_error_code(),
                    None,
                    "a message this endpoint declined to build is not a session error"
                );
                still_running(&ep);
            }

            /// The same track under the same alias is not a conflict.
            ///
            /// # What it catches
            ///
            /// Comparing only the alias and not the track it names, which
            /// stops an endpoint offering a track it has already offered:
            ///
            /// ```text
            /// a second offer of the same track under the same alias was refused: TrackAliasInUse { alias: 7, held: 0 }
            /// ```
            #[test]
            fn the_same_track_under_the_same_alias_is_not_a_conflict() {
                let mut ep = active();
                crate::we_publish!($pub, ep, ALIAS, ALPHA).expect("the first offer");

                crate::we_publish!($pub, ep, ALIAS, ALPHA)
                    .expect("a second offer of the same track under the same alias was refused");
                still_running(&ep);
            }

            /// An alias is free again once the offer holding it ends.
            ///
            /// # What it catches
            ///
            /// Answering `binding_is_in_use` with `true`, which holds an alias
            /// for the rest of the session and refuses the next, conforming,
            /// use of it:
            ///
            /// ```text
            /// an alias whose offer had been refused was still held: TrackAliasInUse { alias: 7, held: 0 }
            /// ```
            #[test]
            fn an_alias_is_free_once_its_offer_ends() {
                let mut ep = active();
                let (id, _) = crate::we_publish!($pub, ep, ALIAS, ALPHA).expect("the first offer");
                crate::peer_refuses!($refuse, ep, id).expect("the peer's refusal");

                crate::we_publish!($pub, ep, ALIAS, BETA)
                    .expect("an alias whose offer had been refused was still held");
                still_running(&ep);
            }

            /// A refused PUBLISH spends no Request ID.
            ///
            /// # What it catches
            ///
            /// Judging the alias after allocating the Request ID:
            ///
            /// ```text
            /// assertion `left == right` failed: a refused PUBLISH spent a Request ID
            ///   left: 4
            ///  right: 2
            /// ```
            #[test]
            fn a_refused_publish_spends_no_request_id() {
                let mut ep = active();
                let (first, _) = crate::we_publish!($pub, ep, ALIAS, ALPHA).expect("the offer");
                crate::we_publish!($pub, ep, ALIAS, BETA).expect_err("one alias, two tracks");

                let (next, _) = crate::we_publish!($pub, ep, ALIAS + 1, BETA)
                    .expect("a second track under a second alias");
                assert_eq!(
                    next.into_inner(),
                    first.into_inner() + 2,
                    "a refused PUBLISH spent a Request ID"
                );
                still_running(&ep);
            }
        }
    };
}

/// SETUP, in the two shapes it takes across the six drafts.
#[macro_export]
macro_rules! client_setup {
    (v12, $ep:expr) => {{
        let _ = $ep.send_client_setup(vec![$crate::v(0xff00_000c)], vec![]).expect("CLIENT_SETUP");
        $ep.receive_server_setup(&ServerSetup {
            selected_version: $crate::v(0xff00_000c),
            parameters: vec![KeyValuePair {
                key: $crate::v(0x02),
                value: KvpValue::Varint($crate::v(100)),
            }],
        })
        .expect("SERVER_SETUP");
    }};
    (v13, $ep:expr) => {{
        let _ = $ep.send_client_setup(vec![$crate::v(0xff00_000d)], vec![]).expect("CLIENT_SETUP");
        $ep.receive_server_setup(&ServerSetup {
            selected_version: $crate::v(0xff00_000d),
            parameters: vec![KeyValuePair {
                key: $crate::v(0x02),
                value: KvpValue::Varint($crate::v(100)),
            }],
        })
        .expect("SERVER_SETUP");
    }};
    (v14, $ep:expr) => {{
        let _ = $ep.send_client_setup(vec![$crate::v(0xff00_000e)], vec![]).expect("CLIENT_SETUP");
        $ep.receive_server_setup(&ServerSetup {
            selected_version: $crate::v(0xff00_000e),
            parameters: vec![KeyValuePair {
                key: $crate::v(0x02),
                value: KvpValue::Varint($crate::v(100)),
            }],
        })
        .expect("SERVER_SETUP");
    }};
    (alpn, $ep:expr) => {{
        let _ = $ep.send_client_setup(vec![]).expect("CLIENT_SETUP");
        $ep.receive_server_setup(&ServerSetup {
            parameters: vec![KeyValuePair {
                key: $crate::v(0x02),
                value: KvpValue::Varint($crate::v(100)),
            }],
        })
        .expect("SERVER_SETUP");
    }};
    (options, $ep:expr) => {{
        let _ = $ep.send_setup(vec![]).expect("SETUP");
        $ep.receive_setup(&Setup { options: vec![] }).expect("SETUP");
    }};
}

sender_alias_gates!(draft12, "draft12", v12, rich, publish_error, "8.13");
sender_alias_gates!(draft13, "draft13", v13, rich, publish_error, "8.13");
sender_alias_gates!(draft14, "draft14", v14, rich, publish_error, "9.13");
sender_alias_gates!(draft15, "draft15", alpn, params, plain, "9.13");
sender_alias_gates!(draft16, "draft16", alpn, ext, retry, "9.13");
sender_alias_gates!(draft17, "draft17", options, ext, by_id, "9.11");
sender_alias_gates!(draft18, "draft18", options, ext, redirect, "11.1");
sender_alias_gates!(draft19, "draft19", options, ext, redirect, "11.1");

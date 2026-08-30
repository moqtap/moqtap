//! Two namespace subscriptions on one session may not overlap, and the
//! publisher is the end that says so.
//!
//! Drafts 07 through 11, Sections 6.13, 7.13, 7.13, 8.23 and 8.24: "A
//! subscriber cannot make overlapping namespace subscriptions on a single
//! session. Within a session, if a publisher receives a SUBSCRIBE_ANNOUNCES
//! with a Track Namespace Prefix that is a prefix of an earlier
//! SUBSCRIBE_ANNOUNCES or vice versa, it MUST respond with
//! SUBSCRIBE_ANNOUNCES_ERROR, with error code SUBSCRIBE_ANNOUNCES_OVERLAP" -
//! spelled `Namespace Prefix Overlap` from draft-11. Drafts 12, 13 and 14,
//! Sections 8.27, 8.28 and 9.28, change the relation to "a prefix of, suffix
//! of, or equal to an active SUBSCRIBE_ANNOUNCES", with the message renamed
//! SUBSCRIBE_NAMESPACE from draft-13 and the code spelled
//! `NAMESPACE_PREFIX_OVERLAP` at draft-14. Drafts 15, 16 and 17, Sections
//! 9.23, 9.25 and 9.20, and drafts 18 and 19 Section 10.18: "a Track Namespace
//! Prefix that shares a common prefix with an established namespace
//! subscription, it MUST respond with REQUEST_ERROR with error code
//! PREFIX_OVERLAP".
//!
//! # The relation, and why all three wordings are read the same way
//!
//! A namespace matches a namespace subscription when the subscription's prefix
//! is a prefix of it. Two prefixes therefore select overlapping sets of
//! namespaces exactly when one of them is a prefix of the other, equal
//! prefixes included. Neither of the other two wordings can be taken at its
//! word: "shares a common prefix with" would forbid every second namespace
//! subscription in a session, because any two prefixes share the empty one,
//! and "suffix of" decides nothing at all about which namespaces a prefix
//! matches. Both are read as the relation drafts 07 through 11 spell out.
//!
//! Two gates hold that reading in place. One subscribes to a pair that share
//! their first element and nothing else, which the literal reading of "shares
//! a common prefix" would refuse and this one accepts; the other subscribes to
//! a pair where one extends the other, which is the case every wording names.
//!
//! # The word that changes what is forbidden
//!
//! Not the relation - the adjective in front of the subscription being
//! compared against. Drafts 07 through 11 say "an earlier", which counts one
//! that has already been withdrawn; drafts 12 through 19 say "active" and then
//! "established", which do not. So the same second request is refused on five
//! drafts and accepted on eight, and only a gate that withdraws the first one
//! before making the second can see the difference. There is one on every
//! draft, and it asserts the opposite thing on either side of the split.
//!
//! # Where the refusal happens, and why draft-07 through draft-10 differ
//!
//! SUBSCRIBE_ANNOUNCES carries no Request ID on the first four drafts, so the
//! acceptance, the refusal and the withdrawal all name a Track Namespace
//! Prefix and nothing else. A second subscription under an overlapping prefix
//! could be written down there, but the answers to the two could not be told
//! apart, and for an equal prefix the second would displace the first
//! outright. So on those four the request is refused where it arrives and
//! nothing is recorded for it; from draft-11 on it is recorded like any other
//! request and the answer path refuses to accept it.
//!
//! The same four drafts name the code the refusal carries -
//! SUBSCRIBE_ANNOUNCES_OVERLAP - in prose, and define it in no registry, so
//! there is no number to check a refusal against. Every draft from 11 on
//! assigns one, and there the refusal is checked: `Namespace Prefix Overlap`
//! is 0x5 in the SUBSCRIBE_ANNOUNCES_ERROR and SUBSCRIBE_NAMESPACE_ERROR
//! registries, and `PREFIX_OVERLAP` is 0x30 in the REQUEST_ERROR registry.
//!
//! # The two directions are separate
//!
//! The rule is about what one endpoint has been asked, so the prefixes this
//! endpoint has subscribed to are not weighed against the peer's and the
//! peer's are not weighed against this endpoint's. Two gates per draft say so,
//! one in each direction. On drafts 11 through 19 the state machines for both
//! directions live in one map per request kind, so the record of what actually
//! arrived is what keeps them apart.
//!
//! # What was here before
//!
//! Nothing on any of the thirteen. Every draft states the rule and every one
//! makes it a MUST; no endpoint compared a prefix with anything.
//!
//! # The third statement, on drafts 18 and 19
//!
//! Those two say it once more for a REQUEST_UPDATE carrying the
//! TRACK_NAMESPACE_PREFIX parameter, which moves the prefix of a subscription
//! already accepted rather than judging one arriving. That half is gated in
//! `a_namespace_prefix_moves_with_its_update.rs`; nothing in this file reaches
//! it.
//!
//! # Ablations, measured
//!
//! Seventeen cuts, each made, run against the two crates a change to
//! `moqtap-client` can reach, recorded on the gate it reddens and reverted.
//! Four of them cut the relation itself and partition it cleanly: never
//! overlapping reddens eighty tests, equality alone sixty-seven, comparing the first
//! element alone thirteen and excluding equality thirteen. Two cut the guard rather
//! than the relation, one per half of the range: removing the refusal on
//! arrival reddens twenty on drafts 07 through 10, and removing it from the
//! answer forty-four on drafts 11 through 19. The rest sit on one gate each and are
//! recorded there.
//!
//! Every gate here carries at least one, and the loopback gate in
//! `draft16_namespace_stream_on_the_wire.rs` is reddened by three of them.

#![allow(clippy::items_after_test_module)]

use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;

fn v(n: u64) -> VarInt {
    VarInt::from_u64(n).expect("a fixture value fits a varint")
}

/// The prefix the first namespace subscription is opened under.
fn root() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec()])
}

/// A prefix that extends [`root`] by one element, so `root` is a prefix of it
/// and the two overlap.
fn under() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec(), b"alpha".to_vec()])
}

/// A second prefix beneath [`root`], which [`under`] neither prefixes nor is
/// prefixed by. The two share their first element and select disjoint sets of
/// namespaces.
fn sibling() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec(), b"beta".to_vec()])
}

/// A prefix sharing no element with any of the others.
fn elsewhere() -> TrackNamespace {
    TrackNamespace(vec![b"elsewhere".to_vec()])
}

// -- The shapes one rule takes across thirteen drafts ------------------

/// The request the peer sends. Drafts 07 through 10 name only the prefix,
/// draft-11 adds a Request ID, draft-13 renames the message, drafts 14 and 15
/// each rename the field the prefix travels in, draft-16 adds Subscribe
/// Options and puts the request on a stream, and draft-17 adds a Required
/// Request ID Delta that 18 and 19 take away again.
#[macro_export]
macro_rules! peers_request {
    (plain, $id:expr, $ns:expr) => {{
        let _ = $id;
        SubscribeAnnounces { track_namespace_prefix: $ns, parameters: vec![] }
    }};
    (ided, $id:expr, $ns:expr) => {
        SubscribeAnnounces {
            request_id: $crate::v($id),
            track_namespace_prefix: $ns,
            parameters: vec![],
        }
    };
    (renamed, $id:expr, $ns:expr) => {
        SubscribeNamespace {
            request_id: $crate::v($id),
            track_namespace_prefix: $ns,
            parameters: vec![],
        }
    };
    (d14, $id:expr, $ns:expr) => {
        SubscribeNamespace { request_id: $crate::v($id), track_namespace: $ns, parameters: vec![] }
    };
    (d15, $id:expr, $ns:expr) => {
        SubscribeNamespace { request_id: $crate::v($id), namespace_prefix: $ns, parameters: vec![] }
    };
    (d16, $id:expr, $ns:expr) => {
        ControlMessage::SubscribeNamespace(SubscribeNamespace {
            request_id: $crate::v($id),
            namespace_prefix: $ns,
            subscribe_options: $crate::v(0),
            parameters: vec![],
        })
    };
    (d17, $id:expr, $ns:expr) => {
        ControlMessage::SubscribeNamespace(SubscribeNamespace {
            request_id: $crate::v($id),
            required_request_id_delta: $crate::v(0),
            namespace_prefix: $ns,
            subscribe_options: $crate::v(0),
            parameters: vec![],
        })
    };
    (d18, $id:expr, $ns:expr) => {
        ControlMessage::SubscribeNamespace(SubscribeNamespace {
            request_id: $crate::v($id),
            namespace_prefix: $ns,
            parameters: vec![],
        })
    };
    (tracks, $id:expr, $ns:expr) => {
        ControlMessage::SubscribeTracks(SubscribeTracks {
            request_id: $crate::v($id),
            namespace_prefix: $ns,
            parameters: vec![],
        })
    };
}

/// Taking it in.
#[macro_export]
macro_rules! we_receive {
    (ns, $ep:expr, $req:expr) => {
        $ep.receive_subscribe_announces(&$req)
    };
    (renamed, $ep:expr, $req:expr) => {
        $ep.receive_subscribe_namespace(&$req)
    };
    (stream16, $ep:expr, $req:expr) => {
        $ep.receive_subscribe_namespace_on_stream(&$req).map(|_| ())
    };
    (stream, $ep:expr, $req:expr) => {
        $ep.receive_request_on_stream(&$req).map(|_| ())
    };
}

/// Accepting it, which names the request by prefix up to draft-10 and by
/// Request ID after it, and travels as REQUEST_OK from draft-15.
#[macro_export]
macro_rules! we_accept {
    (ns, $ep:expr, $id:expr, $ns:expr) => {{
        let _ = $id;
        $ep.send_subscribe_announces_ok($ns).map(|_| ())
    }};
    (id, $ep:expr, $id:expr, $ns:expr) => {
        $ep.send_subscribe_announces_ok($crate::v($id)).map(|_| ())
    };
    (renamed, $ep:expr, $id:expr, $ns:expr) => {
        $ep.send_subscribe_namespace_ok($crate::v($id)).map(|_| ())
    };
    (request, $ep:expr, $id:expr, $ns:expr) => {
        $ep.send_request_ok($crate::v($id), Vec::new()).map(|_| ())
    };
    (stream16, $ep:expr, $id:expr, $ns:expr) => {
        $ep.respond_on_namespace_stream($crate::v($id), None)
    };
    (stream17, $ep:expr, $id:expr, $ns:expr) => {
        $ep.send_response_on_stream(
            $crate::v($id),
            &ControlMessage::RequestOk(RequestOk { parameters: Vec::new() }),
        )
    };
    (stream18, $ep:expr, $id:expr, $ns:expr) => {
        $ep.send_response_on_stream(
            $crate::v($id),
            &ControlMessage::RequestOk(RequestOk {
                parameters: Vec::new(),
                track_properties: Vec::new(),
            }),
        )
    };
}

/// Refusing it under a chosen code.
#[macro_export]
macro_rules! we_refuse {
    (ns, $ep:expr, $id:expr, $ns:expr, $code:expr) => {{
        let _ = $id;
        $ep.send_subscribe_announces_error($ns, $crate::v($code), b"no".to_vec()).map(|_| ())
    }};
    (id, $ep:expr, $id:expr, $ns:expr, $code:expr) => {
        $ep.send_subscribe_announces_error($crate::v($id), $crate::v($code), b"no".to_vec())
            .map(|_| ())
    };
    (renamed, $ep:expr, $id:expr, $ns:expr, $code:expr) => {
        $ep.send_subscribe_namespace_error($crate::v($id), $crate::v($code), b"no".to_vec())
            .map(|_| ())
    };
    (request, $ep:expr, $id:expr, $ns:expr, $code:expr) => {
        $ep.send_request_error($crate::v($id), $crate::v($code), b"no".to_vec()).map(|_| ())
    };
    (stream16, $ep:expr, $id:expr, $ns:expr, $code:expr) => {
        $ep.respond_on_namespace_stream($crate::v($id), Some($crate::v($code)))
    };
    (stream17, $ep:expr, $id:expr, $ns:expr, $code:expr) => {
        $ep.send_response_on_stream(
            $crate::v($id),
            &ControlMessage::RequestError(RequestError {
                error_code: $crate::v($code),
                retry_interval: $crate::v(0),
                reason_phrase: b"no".to_vec(),
            }),
        )
    };
    (stream18, $ep:expr, $id:expr, $ns:expr, $code:expr) => {
        $ep.send_response_on_stream(
            $crate::v($id),
            &ControlMessage::RequestError(RequestError {
                error_code: $crate::v($code),
                retry_interval: $crate::v(0),
                reason_phrase: b"no".to_vec(),
                redirect: None,
            }),
        )
    };
}

/// Ending the peer's namespace subscription, which the peer withdraws by name
/// up to draft-14, by Request ID at draft-15, and by finishing its stream from
/// draft-16.
#[macro_export]
macro_rules! peer_withdraws {
    (by_ns, $ep:expr, $id:expr, $ns:expr) => {{
        let _ = $id;
        $ep.receive_unsubscribe_announces(&UnsubscribeAnnounces { track_namespace_prefix: $ns })
    }};
    (renamed_ns, $ep:expr, $id:expr, $ns:expr) => {{
        let _ = $id;
        $ep.receive_unsubscribe_namespace(&UnsubscribeNamespace { track_namespace_prefix: $ns })
    }};
    (by_id, $ep:expr, $id:expr, $ns:expr) => {
        $ep.receive_unsubscribe_namespace(&UnsubscribeNamespace { request_id: $crate::v($id) })
    };
    (cancel16, $ep:expr, $id:expr, $ns:expr) => {
        $ep.cancel_namespace_subscription($crate::v($id))
    };
    (cancel, $ep:expr, $id:expr, $ns:expr) => {
        $ep.cancel_request($crate::v($id))
    };
}

/// A namespace subscription this endpoint makes itself, whose argument list
/// grows twice across the range.
#[macro_export]
macro_rules! we_subscribe {
    (bare, $ep:expr, $ns:expr) => {
        $ep.subscribe_announces($ns).map(|_| ())
    };
    (allocating, $ep:expr, $ns:expr) => {
        $ep.subscribe_announces($ns).map(|_| ())
    };
    (allocating_params, $ep:expr, $ns:expr) => {
        $ep.subscribe_announces($ns, Vec::new()).map(|_| ())
    };
    (params, $ep:expr, $ns:expr) => {
        $ep.subscribe_namespace($ns, Vec::new()).map(|_| ())
    };
    (options, $ep:expr, $ns:expr) => {
        $ep.subscribe_namespace($ns, $crate::v(0), Vec::new()).map(|_| ())
    };
}

/// The setup parameters each draft requires. Draft-07 requires a ROLE of both
/// endpoints and is the only one of the thirteen that does.
#[macro_export]
macro_rules! setup_params {
    (role) => {
        vec![KeyValuePair { key: $crate::v(0x00), value: KvpValue::Varint($crate::v(3)) }]
    };
    (none) => {
        Vec::new()
    };
}

/// The same, plus the ceiling the peer must grant before this endpoint may
/// open a request of its own.
#[macro_export]
macro_rules! server_params {
    (role) => {
        vec![
            KeyValuePair { key: $crate::v(0x00), value: KvpValue::Varint($crate::v(3)) },
            KeyValuePair { key: $crate::v(0x02), value: KvpValue::Varint($crate::v(100)) },
        ]
    };
    (none) => {
        vec![KeyValuePair { key: $crate::v(0x02), value: KvpValue::Varint($crate::v(100)) }]
    };
}

/// The setup exchange, which carries a selected version up to draft-14, leaves
/// it to the ALPN at draft-15, and becomes one SETUP message at draft-17.
#[macro_export]
macro_rules! peers_setup {
    (versioned, $ep:expr, $version:expr, $params:tt) => {{
        let _ = $ep
            .send_client_setup(vec![$crate::v($version)], $crate::setup_params!($params))
            .expect("CLIENT_SETUP");
        $ep.receive_server_setup(&ServerSetup {
            selected_version: $crate::v($version),
            parameters: $crate::server_params!($params),
        })
        .expect("SERVER_SETUP");
    }};
    (alpn, $ep:expr, $version:expr, $params:tt) => {{
        let _ = $ep.send_client_setup($crate::setup_params!($params)).expect("CLIENT_SETUP");
        $ep.receive_server_setup(&ServerSetup { parameters: $crate::server_params!($params) })
            .expect("SERVER_SETUP");
    }};
    (d16, $ep:expr, $version:expr, $params:tt) => {{
        let _ = $ep.send_client_setup(Vec::new()).expect("CLIENT_SETUP");
        $ep.receive_server_setup(&ServerSetup { parameters: $crate::server_params!($params) })
            .expect("SERVER_SETUP");
    }};
    (one_message, $ep:expr, $version:expr, $params:tt) => {{
        $ep.send_setup(Vec::new()).expect("SETUP");
        $ep.receive_setup(&Setup { options: Vec::new() }).expect("the peer's SETUP");
    }};
}

// -- Drafts 07 through 10 ----------------------------------------------

/// One draft's gates, where the request carries no Request ID.
macro_rules! prefix_keyed_gates {
    ($draft:ident, $feat:literal, $version:expr, $grant:ident, $params:tt, $sec:literal) => {
        #[cfg(feature = $feat)]
        mod $draft {
            use moqtap_client::$draft::endpoint::Role;
            use moqtap_client::$draft::endpoint::{Endpoint, EndpointError};
            use moqtap_client::$draft::session::state::SessionState;
            use moqtap_codec::kvp::{KeyValuePair, KvpValue};
            use moqtap_codec::$draft::message::*;

            /// A client past setup, with a budget granted to the peer.
            fn active() -> Endpoint {
                let mut ep = Endpoint::new(Role::Client);
                ep.connect().expect("a client may open");
                crate::peers_setup!(versioned, ep, $version, $params);
                let _ = ep.$grant(crate::v(100)).expect("a budget for the peer");
                ep
            }

            /// The peer subscribes to `crate::root()` and this endpoint
            /// accepts, so one namespace subscription is open.
            fn opened() -> Endpoint {
                let mut ep = active();
                ep.receive_subscribe_announces(&crate::peers_request!(plain, 0, crate::root()))
                    .expect("the peer may subscribe to a namespace");
                ep.send_subscribe_announces_ok(crate::root()).expect("accept it");
                ep
            }

            /// The peer sends a second SUBSCRIBE_ANNOUNCES for `prefix`, which
            /// this endpoint must refuse where it arrives.
            fn second_is_refused(ep: &mut Endpoint, prefix: moqtap_codec::types::TrackNamespace) {
                let err = ep
                    .receive_subscribe_announces(&crate::peers_request!(plain, 0, prefix.clone()))
                    .expect_err("a namespace subscription overlapping an open one is refused");
                assert!(
                    matches!(err, EndpointError::PeerPrefixOverlap),
                    "the refusal should name the rule, and named {err}"
                );
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "Section {} answers this with a message, not with a close",
                    $sec
                );
            }

            /// A second one for `prefix` is taken in and can be answered.
            fn second_is_taken(ep: &mut Endpoint, prefix: moqtap_codec::types::TrackNamespace) {
                ep.receive_subscribe_announces(&crate::peers_request!(plain, 0, prefix.clone()))
                    .expect("a namespace subscription overlapping nothing is taken in");
                assert!(
                    ep.pending_subscribe_announces(&prefix).is_some(),
                    "it should be on record, waiting for an answer"
                );
                ep.send_subscribe_announces_ok(prefix).expect("and this endpoint may accept it");
            }

            /// Two equal prefixes overlap.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// Reading the relation as a proper prefix - one a prefix of the
            /// other and the two not equal - which is what "a prefix of" says
            /// if a prefix is taken to exclude the whole:
            ///
            /// ```text
            /// a namespace subscription overlapping an open one is refused: ()
            /// an overlapping namespace subscription may not be accepted: ()
            /// ```
            ///
            /// It reddens thirteen tests, this gate on every draft and
            /// nothing else: every other gate in this file compares prefixes
            /// of different lengths, so a relation that is merely too strict
            /// about equality leaves them alone. An equal prefix is the case
            /// the sentence names first, and on drafts 07 through 10 it is
            /// the case that cannot be written down beside the first at all.
            #[test]
            fn a_second_subscription_under_the_same_prefix_is_refused() {
                let mut ep = opened();
                second_is_refused(&mut ep, crate::root());
                // The first is untouched: only a namespace subscription this
                // endpoint accepted can be withdrawn, so this would fail if
                // the second had displaced it in a map keyed by prefix.
                ep.receive_unsubscribe_announces(&UnsubscribeAnnounces {
                    track_namespace_prefix: crate::root(),
                })
                .expect("the first namespace subscription is still the one on record");
            }

            /// A prefix that extends an open one overlaps it.
            ///
            /// # What it catches
            ///
            /// Reading the relation as equality, which is all drafts 12
            /// through 14 spell out in so many words and none of what the
            /// sentence means:
            ///
            /// ```text
            /// a namespace subscription overlapping an open one is refused: ()
            /// an overlapping namespace subscription may not be accepted: ()
            /// ```
            ///
            /// It reddens sixty-seven tests - everything the cut that drops
            /// the relation altogether reaches, less the thirteen equal-
            /// prefix gates above, which an equality still catches. The gate
            /// below this one is the same comparison the other way round, and
            /// this cut reaches both.
            #[test]
            fn a_subscription_under_an_open_prefix_is_refused() {
                let mut ep = opened();
                second_is_refused(&mut ep, crate::under());
                assert!(
                    ep.pending_subscribe_announces(&crate::under()).is_none(),
                    "nothing is recorded for a request this endpoint may not accept"
                );
            }

            /// An open prefix that extends the arriving one overlaps it too,
            /// which is the "or vice versa" half of the sentence.
            #[test]
            fn a_subscription_above_an_open_prefix_is_refused() {
                let mut ep = active();
                ep.receive_subscribe_announces(&crate::peers_request!(plain, 0, crate::under()))
                    .expect("the peer may subscribe to a namespace");
                ep.send_subscribe_announces_ok(crate::under()).expect("accept it");
                second_is_refused(&mut ep, crate::root());
            }

            /// Prefixes sharing no element do not overlap.
            ///
            /// # What it catches
            ///
            /// Reading "shares a common prefix with" at its word. Any two
            /// prefixes share the empty one, so the relation holds for every
            /// pair and no second namespace subscription in a session is ever
            /// legal:
            ///
            /// ```text
            /// a namespace subscription overlapping nothing is taken in: PeerPrefixOverlap
            /// and this endpoint may accept it: PeerPrefixOverlap { request: 3, established: 1 }
            /// ```
            ///
            /// It reddens twenty-six tests: this gate and the one below it,
            /// on every draft. The two that read the *other* direction's set
            /// stay green, and that is the shape of them - an always-true
            /// relation over an empty set still finds nothing, so those two
            /// are gates about which set is consulted rather than about the
            /// relation.
            #[test]
            fn a_subscription_under_an_unrelated_prefix_is_taken() {
                let mut ep = opened();
                second_is_taken(&mut ep, crate::elsewhere());
            }

            /// Prefixes sharing only their first element do not overlap, which
            /// is what keeps "shares a common prefix" from being read at its
            /// word.
            ///
            /// # What it catches
            ///
            /// The same loose reading applied to one element instead of none,
            /// which is what a prefix tree reaches for: compare the first
            /// element and stop.
            ///
            /// ```text
            /// a namespace subscription overlapping nothing is taken in: PeerPrefixOverlap
            /// and this endpoint may accept it: PeerPrefixOverlap { request: 3, established: 1 }
            /// ```
            ///
            /// It reddens thirteen tests, this gate on every draft. It is the
            /// sharpest of the relation cuts, because the pair it refuses
            /// share everything a loose reading looks at and select disjoint
            /// sets of namespaces.
            #[test]
            fn two_prefixes_beneath_one_namespace_are_both_taken() {
                let mut ep = active();
                ep.receive_subscribe_announces(&crate::peers_request!(plain, 0, crate::under()))
                    .expect("the peer may subscribe to a namespace");
                ep.send_subscribe_announces_ok(crate::under()).expect("accept it");
                second_is_taken(&mut ep, crate::sibling());
            }

            /// One still waiting for an answer counts.
            ///
            /// # What it catches
            ///
            /// Counting only the namespace subscriptions this endpoint has
            /// already accepted, on the ground that "active" and
            /// "established" say so:
            ///
            /// ```text
            /// a namespace subscription overlapping an open one is refused: ()
            /// an overlapping namespace subscription may not be accepted: ()
            /// ```
            ///
            /// It reddens thirteen tests, this gate on every draft. That
            /// reading is not available: this endpoint is the one about to
            /// establish the first request, and accepting both would leave
            /// the session holding exactly the pair the sentence exists to
            /// prevent.
            #[test]
            fn an_unanswered_subscription_still_counts() {
                let mut ep = active();
                ep.receive_subscribe_announces(&crate::peers_request!(plain, 0, crate::root()))
                    .expect("the peer may subscribe to a namespace");
                second_is_refused(&mut ep, crate::under());
            }

            /// One that has been withdrawn counts as well, because this draft
            /// weighs the arriving prefix against "an earlier" namespace
            /// subscription rather than a live one.
            ///
            /// # What it catches
            ///
            /// Dropping a namespace subscription that has ended from the set,
            /// which is what the eight drafts after these do and what these
            /// five do not:
            ///
            /// ```text
            /// a namespace subscription overlapping an open one is refused: ()
            /// an overlapping namespace subscription may not be accepted: ()
            /// ```
            ///
            /// It reddens five tests, this gate on drafts 07 through 11 - the
            /// five that weigh the arriving prefix against "an earlier"
            /// namespace subscription rather than a live one. It is one half
            /// of the split; the other half is the gate of the opposite name
            /// below, on the eight drafts after them.
            #[test]
            fn a_withdrawn_subscription_still_counts() {
                let mut ep = opened();
                ep.receive_unsubscribe_announces(&UnsubscribeAnnounces {
                    track_namespace_prefix: crate::root(),
                })
                .expect("the peer withdraws it");
                second_is_refused(&mut ep, crate::under());
            }

            /// A prefix this endpoint subscribed to does not stop the peer
            /// subscribing to it.
            ///
            /// # What it catches
            ///
            /// Weighing the arriving prefix against this endpoint's own
            /// namespace subscriptions as well as the peer's, which one map
            /// of state machines holding both directions invites:
            ///
            /// ```text
            /// a namespace subscription overlapping nothing is taken in: PeerPrefixOverlap
            /// and this endpoint may accept it: PeerPrefixOverlap { request: 1, established: 0 }
            /// ```
            ///
            /// It reddens eleven tests, this gate on drafts 07 through 17.
            /// Drafts 18 and 19 keep no set of this endpoint's own prefixes
            /// for that cut to read; there the same gate is reached by
            /// writing the arriving-request record on the outbound path too,
            /// which reddens three.
            #[test]
            fn a_prefix_of_this_endpoints_own_does_not_block_the_peers() {
                let mut ep = active();
                let _ = ep
                    .subscribe_announces(crate::root())
                    .expect("this endpoint may subscribe to a namespace");
                second_is_taken(&mut ep, crate::root());
            }

            /// The subscriber's half: this endpoint refuses to build a second
            /// request overlapping one of its own.
            ///
            /// # What it catches
            ///
            /// Building the request and leaving the publisher to refuse it:
            ///
            /// ```text
            /// a second request overlapping the first is not built: ()
            /// ```
            ///
            /// It reddens eleven tests, this gate on drafts 07 through 17.
            /// Drafts 18 and 19 drop the sentence addressed to the subscriber
            /// and have no gate here.
            #[test]
            fn this_endpoint_refuses_to_make_an_overlapping_request() {
                let mut ep = active();
                let _ = ep
                    .subscribe_announces(crate::root())
                    .expect("this endpoint may subscribe to a namespace");
                let err = ep
                    .subscribe_announces(crate::under())
                    .map(|_| ())
                    .expect_err("a second request overlapping the first is not built");
                assert!(
                    matches!(err, EndpointError::OwnPrefixOverlap),
                    "the refusal should name the rule, and named {err}"
                );
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "refusing to build a message ends nothing"
                );
            }

            /// A prefix the peer subscribed to does not stop this endpoint
            /// subscribing to it.
            ///
            /// # What it catches
            ///
            /// Weighing a request this endpoint is about to make against the
            /// peer's namespace subscriptions:
            ///
            /// ```text
            /// this endpoint may subscribe to a namespace the peer asked about: OwnPrefixOverlap
            /// this endpoint may subscribe to a namespace the peer asked about: OwnPrefixOverlap { established: 1 }
            /// ```
            ///
            /// It reddens fifteen tests. eleven are this gate on drafts 07
            /// through 17. The other four are the subscriber's-half gate on
            /// drafts 07 through 10, where the cut swaps one map for the
            /// other rather than adding to it, so this endpoint's own
            /// prefixes stop being read at all; on drafts 11 through 17 it
            /// adds the peer's set to its own and that gate stays green.
            #[test]
            fn the_peers_prefix_does_not_block_this_endpoints() {
                let mut ep = opened();
                let _ = ep
                    .subscribe_announces(crate::root())
                    .expect("this endpoint may subscribe to a namespace the peer asked about");
            }
        }
    };
}

prefix_keyed_gates!(draft07, "draft07", 0xff00_0007, send_max_subscribe_id, role, "6.13");
prefix_keyed_gates!(draft08, "draft08", 0xff00_0008, send_max_subscribe_id, none, "7.13");
prefix_keyed_gates!(draft09, "draft09", 0xff00_0009, send_max_subscribe_id, none, "7.13");
prefix_keyed_gates!(draft10, "draft10", 0xff00_000a, send_max_subscribe_id, none, "8.23");

// -- Drafts 11 through 19 ----------------------------------------------

/// Whether a namespace subscription that has ended still counts, which is the
/// one word that moves across the range.
#[macro_export]
macro_rules! ended_gate {
    (counts, $sec:literal) => {
        /// One that has been withdrawn counts as well, because this draft
        /// weighs the arriving prefix against "an earlier" namespace
        /// subscription rather than a live one.
        ///
        /// # What it catches
        ///
        /// The cut recorded on this gate in the group above, which reaches
        /// draft-11 here.
        #[test]
        fn a_withdrawn_subscription_still_counts() {
            let mut ep = opened();
            ended(&mut ep);
            second_overlapping_is_refused(&mut ep, SECOND, $crate::under());
        }
    };
    (ignored, $sec:literal) => {
        /// One that has ended stops counting, because this draft weighs the
        /// arriving prefix against an "active" or "established" one.
        ///
        /// # What it catches
        ///
        /// Keeping a namespace subscription that has ended in the set, which
        /// is what drafts 07 through 11 do:
        ///
        /// ```text
        /// and this endpoint may accept it: PeerPrefixOverlap { request: 3, established: 1 }
        /// ```
        ///
        /// It reddens eight tests, this gate on drafts 12 through 19, and
        /// nothing else: no other gate in this file ends a subscription
        /// before making the second request, which is what makes this pair
        /// the only one that can see the word the range turns on.
        #[test]
        fn a_withdrawn_subscription_stops_counting() {
            let mut ep = opened();
            ended(&mut ep);
            second_is_taken(&mut ep, SECOND, $crate::under());
        }
    };
}

/// The half of the sentence addressed to the subscriber, which drafts 18 and
/// 19 drop along with the framing sentence in front of it.
#[macro_export]
macro_rules! subscriber_gates {
    (dropped, $sub:tt) => {};
    (stated, $sub:tt) => {
        /// The subscriber's half: this endpoint refuses to build a second
        /// request overlapping one of its own.
        ///
        /// # What it catches
        ///
        /// The cut recorded on this gate in the group above, which reaches
        /// drafts 11 through 17 here.
        #[test]
        fn this_endpoint_refuses_to_make_an_overlapping_request() {
            let mut ep = active();
            $crate::we_subscribe!($sub, ep, $crate::root())
                .expect("this endpoint may subscribe to a namespace");
            let err = $crate::we_subscribe!($sub, ep, $crate::under())
                .expect_err("a second request overlapping the first is not built");
            assert!(
                matches!(err, EndpointError::OwnPrefixOverlap { .. }),
                "the refusal should name the rule, and named {err}"
            );
            still_running(&ep);
        }

        /// A prefix the peer subscribed to does not stop this endpoint
        /// subscribing to it.
        ///
        /// # What it catches
        ///
        /// The cut recorded on this gate in the group above, which reaches
        /// drafts 11 through 17 here.
        #[test]
        fn the_peers_prefix_does_not_block_this_endpoints() {
            let mut ep = opened();
            $crate::we_subscribe!($sub, ep, $crate::root())
                .expect("this endpoint may subscribe to a namespace the peer asked about");
        }
    };
}

/// SUBSCRIBE_TRACKS, which drafts 18 and 19 give an overlap space of its own.
#[macro_export]
macro_rules! tracks_gates {
    (none, $accept:tt) => {};
    (present, $accept:tt) => {
        /// Section 10.19: "Within a session, if a publisher receives a
        /// SUBSCRIBE_TRACKS with a Track Namespace Prefix that shares a common
        /// prefix with an established SUBSCRIBE_TRACKS, it MUST respond with
        /// REQUEST_ERROR with error code PREFIX_OVERLAP."
        ///
        /// # What it catches
        ///
        /// Judging a SUBSCRIBE_TRACKS against nothing at all:
        ///
        /// ```text
        /// an overlapping track subscription may not be accepted: ()
        /// ```
        ///
        /// It reddens two tests, this gate on each of the two drafts that
        /// carry the message.
        #[test]
        fn a_second_track_subscription_that_overlaps_is_refused() {
            let mut ep = active();
            $crate::we_receive!(stream, ep, $crate::peers_request!(tracks, FIRST, $crate::root()))
                .expect("the peer may subscribe to tracks");
            $crate::we_accept!($accept, ep, FIRST, $crate::root()).expect("accept it");
            $crate::we_receive!(
                stream,
                ep,
                $crate::peers_request!(tracks, SECOND, $crate::under())
            )
            .expect("the second request is taken in and judged");
            let err = $crate::we_accept!($accept, ep, SECOND, $crate::under())
                .expect_err("an overlapping track subscription may not be accepted");
            assert!(
                matches!(err, EndpointError::PeerPrefixOverlap { .. }),
                "the refusal should name the rule, and named {err}"
            );
            still_running(&ep);
        }

        /// Section 10.6.2: "SUBSCRIBE_NAMESPACE and SUBSCRIBE_TRACKS have
        /// independent overlap spaces, so a SUBSCRIBE_NAMESPACE and a
        /// SUBSCRIBE_TRACKS may share the same prefix."
        ///
        /// # What it catches
        ///
        /// Judging a SUBSCRIBE_TRACKS against the SUBSCRIBE_NAMESPACE the
        /// peer has open instead of against the SUBSCRIBE_TRACKS, which is
        /// the arrangement Section 10.6.2 says these drafts do not have:
        ///
        /// ```text
        /// and this endpoint may accept it: PeerPrefixOverlap { request: 2, established: 0 }
        /// ```
        ///
        /// It reddens six tests, and where they fall was not what the cut was
        /// expected to do. Two are this gate and two are the gate above it,
        /// because pointing the arm at the other helper does not merge the
        /// two spaces - it replaces one with the other, so a second
        /// overlapping SUBSCRIBE_TRACKS stops being refused as well. The
        /// remaining two are unit tests in `draft18::endpoint` that were
        /// already defending this: they open a SUBSCRIBE_NAMESPACE and a
        /// SUBSCRIBE_TRACKS under one prefix and fail with
        ///
        /// ```text
        /// called `Result::unwrap()` on an `Err` value: PeerPrefixOverlap { request: 3, established: 1 }
        /// ```
        #[test]
        fn a_track_subscription_and_a_namespace_subscription_may_share_a_prefix() {
            let mut ep = opened();
            $crate::we_receive!(stream, ep, $crate::peers_request!(tracks, SECOND, $crate::root()))
                .expect("the peer may subscribe to tracks under a prefix it watches");
            $crate::we_accept!($accept, ep, SECOND, $crate::root())
                .expect("and this endpoint may accept it");
        }
    };
}

/// One draft's gates, where the request carries a Request ID of its own.
macro_rules! id_keyed_gates {
    ($draft:ident, $feat:literal, $version:expr, $role:path, $who:ident, $grant:tt, $params:tt,
     $setup:tt, $request:tt, $recv:tt, $accept:tt, $refuse:tt, $withdraw:tt, $sub:tt,
     $first:literal, $second:literal, $ours:literal, $code:literal, $ended:tt,
     $subscriber:tt, $tracks:tt, $sec:literal) => {
        #[cfg(feature = $feat)]
        mod $draft {
            use moqtap_client::$draft::endpoint::{Endpoint, EndpointError};
            use moqtap_client::$draft::session::state::SessionState;
            use $role as Role;

            #[allow(unused_imports)]
            use moqtap_codec::kvp::{KeyValuePair, KvpValue};
            #[allow(unused_imports)]
            use moqtap_codec::types::TrackNamespace;
            #[allow(unused_imports)]
            use moqtap_codec::$draft::message::*;

            /// The Request ID the peer opens its first namespace subscription
            /// under, and the one it uses for a second request.
            const FIRST: u64 = $first;
            const SECOND: u64 = $second;

            /// An identifier of this endpoint's own, unread on the drafts that
            /// state no rule for the subscriber.
            #[allow(dead_code)]
            const OURS: u64 = $ours;

            /// The code the sentence names for this refusal.
            const OVERLAP: u64 = $code;

            /// An endpoint past setup, with a budget granted to the peer.
            fn active() -> Endpoint {
                let mut ep = Endpoint::new(Role::$who);
                ep.connect().expect("an endpoint may open");
                crate::peers_setup!($setup, ep, $version, $params);
                crate::grant!($grant, ep);
                ep
            }

            fn still_running(ep: &Endpoint) {
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "Section {} answers this with a message, not with a close",
                    $sec
                );
            }

            /// The peer subscribes to `crate::root()` and this endpoint
            /// accepts, so one namespace subscription is open.
            fn opened() -> Endpoint {
                let mut ep = active();
                crate::we_receive!(
                    $recv,
                    ep,
                    crate::peers_request!($request, FIRST, crate::root())
                )
                .expect("the peer may subscribe to a namespace");
                crate::we_accept!($accept, ep, FIRST, crate::root()).expect("accept it");
                ep
            }

            /// End the open namespace subscription.
            fn ended(ep: &mut Endpoint) {
                crate::peer_withdraws!($withdraw, ep, FIRST, crate::root())
                    .expect("a namespace subscription that was accepted can end");
            }

            /// A second request under `prefix` is taken in, judged as
            /// overlapping, and cannot be accepted.
            fn second_overlapping_is_refused(ep: &mut Endpoint, id: u64, prefix: TrackNamespace) {
                crate::we_receive!($recv, ep, crate::peers_request!($request, id, prefix.clone()))
                    .expect("the request is taken in, because it is the answer that is fixed");
                let err = crate::we_accept!($accept, ep, id, prefix.clone())
                    .expect_err("an overlapping namespace subscription may not be accepted");
                assert!(
                    matches!(err, EndpointError::PeerPrefixOverlap { .. }),
                    "the refusal should name the rule, and named {err}"
                );
                still_running(ep);
            }

            /// A second request under `prefix` is taken in and can be
            /// accepted.
            fn second_is_taken(ep: &mut Endpoint, id: u64, prefix: TrackNamespace) {
                crate::we_receive!($recv, ep, crate::peers_request!($request, id, prefix.clone()))
                    .expect("a namespace subscription overlapping nothing is taken in");
                crate::we_accept!($accept, ep, id, prefix)
                    .expect("and this endpoint may accept it");
            }

            /// Two equal prefixes overlap.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// Reading the relation as a proper prefix - one a prefix of the
            /// other and the two not equal - which is what "a prefix of" says
            /// if a prefix is taken to exclude the whole:
            ///
            /// ```text
            /// a namespace subscription overlapping an open one is refused: ()
            /// an overlapping namespace subscription may not be accepted: ()
            /// ```
            ///
            /// It reddens thirteen tests, this gate on every draft and
            /// nothing else: every other gate in this file compares prefixes
            /// of different lengths, so a relation that is merely too strict
            /// about equality leaves them alone. An equal prefix is the case
            /// the sentence names first, and on drafts 07 through 10 it is
            /// the case that cannot be written down beside the first at all.
            #[test]
            fn a_second_subscription_under_the_same_prefix_is_refused() {
                let mut ep = opened();
                second_overlapping_is_refused(&mut ep, SECOND, crate::root());
            }

            /// A prefix that extends an open one overlaps it.
            ///
            /// # What it catches
            ///
            /// Reading the relation as equality, which is all drafts 12
            /// through 14 spell out in so many words and none of what the
            /// sentence means:
            ///
            /// ```text
            /// a namespace subscription overlapping an open one is refused: ()
            /// an overlapping namespace subscription may not be accepted: ()
            /// ```
            ///
            /// It reddens sixty-seven tests - everything the cut that drops
            /// the relation altogether reaches, less the thirteen equal-
            /// prefix gates above, which an equality still catches. The gate
            /// below this one is the same comparison the other way round, and
            /// this cut reaches both.
            #[test]
            fn a_subscription_under_an_open_prefix_is_refused() {
                let mut ep = opened();
                second_overlapping_is_refused(&mut ep, SECOND, crate::under());
            }

            /// An open prefix that extends the arriving one overlaps it too,
            /// which is the "or vice versa" half of the sentence.
            #[test]
            fn a_subscription_above_an_open_prefix_is_refused() {
                let mut ep = active();
                crate::we_receive!(
                    $recv,
                    ep,
                    crate::peers_request!($request, FIRST, crate::under())
                )
                .expect("the peer may subscribe to a namespace");
                crate::we_accept!($accept, ep, FIRST, crate::under()).expect("accept it");
                second_overlapping_is_refused(&mut ep, SECOND, crate::root());
            }

            /// Prefixes sharing no element do not overlap.
            ///
            /// # What it catches
            ///
            /// Reading "shares a common prefix with" at its word. Any two
            /// prefixes share the empty one, so the relation holds for every
            /// pair and no second namespace subscription in a session is ever
            /// legal:
            ///
            /// ```text
            /// a namespace subscription overlapping nothing is taken in: PeerPrefixOverlap
            /// and this endpoint may accept it: PeerPrefixOverlap { request: 3, established: 1 }
            /// ```
            ///
            /// It reddens twenty-six tests: this gate and the one below it,
            /// on every draft. The two that read the *other* direction's set
            /// stay green, and that is the shape of them - an always-true
            /// relation over an empty set still finds nothing, so those two
            /// are gates about which set is consulted rather than about the
            /// relation.
            #[test]
            fn a_subscription_under_an_unrelated_prefix_is_taken() {
                let mut ep = opened();
                second_is_taken(&mut ep, SECOND, crate::elsewhere());
            }

            /// Prefixes sharing only their first element do not overlap, which
            /// is what keeps "shares a common prefix" from being read at its
            /// word.
            ///
            /// # What it catches
            ///
            /// The same loose reading applied to one element instead of none,
            /// which is what a prefix tree reaches for: compare the first
            /// element and stop.
            ///
            /// ```text
            /// a namespace subscription overlapping nothing is taken in: PeerPrefixOverlap
            /// and this endpoint may accept it: PeerPrefixOverlap { request: 3, established: 1 }
            /// ```
            ///
            /// It reddens thirteen tests, this gate on every draft. It is the
            /// sharpest of the relation cuts, because the pair it refuses
            /// share everything a loose reading looks at and select disjoint
            /// sets of namespaces.
            #[test]
            fn two_prefixes_beneath_one_namespace_are_both_taken() {
                let mut ep = active();
                crate::we_receive!(
                    $recv,
                    ep,
                    crate::peers_request!($request, FIRST, crate::under())
                )
                .expect("the peer may subscribe to a namespace");
                crate::we_accept!($accept, ep, FIRST, crate::under()).expect("accept it");
                second_is_taken(&mut ep, SECOND, crate::sibling());
            }

            /// One still waiting for an answer counts.
            ///
            /// # What it catches
            ///
            /// Counting only the namespace subscriptions this endpoint has
            /// already accepted, on the ground that "active" and
            /// "established" say so:
            ///
            /// ```text
            /// a namespace subscription overlapping an open one is refused: ()
            /// an overlapping namespace subscription may not be accepted: ()
            /// ```
            ///
            /// It reddens thirteen tests, this gate on every draft. That
            /// reading is not available: this endpoint is the one about to
            /// establish the first request, and accepting both would leave
            /// the session holding exactly the pair the sentence exists to
            /// prevent.
            #[test]
            fn an_unanswered_subscription_still_counts() {
                let mut ep = active();
                crate::we_receive!(
                    $recv,
                    ep,
                    crate::peers_request!($request, FIRST, crate::root())
                )
                .expect("the peer may subscribe to a namespace");
                second_overlapping_is_refused(&mut ep, SECOND, crate::under());
            }

            crate::ended_gate!($ended, $sec);

            /// The refusal goes out under the code the sentence names, and
            /// under no other.
            ///
            /// # What it catches
            ///
            /// Refusing an overlapping request like any other, without
            /// holding the refusal to the code the sentence names for it:
            ///
            /// ```text
            /// a refusal under some other code is not this refusal: ()
            /// ```
            ///
            /// It reddens nine tests, this gate on each draft that gives the
            /// code a number. Drafts 07 through 10 have no gate here at all:
            /// they name the code SUBSCRIBE_ANNOUNCES_OVERLAP in the prose of
            /// the rule and define it in no registry, so there is no number a
            /// refusal could be held to.
            #[test]
            fn the_refusal_carries_the_code_the_draft_names() {
                let mut ep = opened();
                crate::we_receive!(
                    $recv,
                    ep,
                    crate::peers_request!($request, SECOND, crate::under())
                )
                .expect("the second request is taken in and judged");
                let err = crate::we_refuse!($refuse, ep, SECOND, crate::under(), 0x0)
                    .expect_err("a refusal under some other code is not this refusal");
                assert!(
                    matches!(err, EndpointError::WrongOverlapRefusal { .. }),
                    "the refusal should name the code it wanted, and said {err}"
                );
                crate::we_refuse!($refuse, ep, SECOND, crate::under(), OVERLAP)
                    .expect("and under that code it goes out");
                still_running(&ep);
            }

            /// A prefix this endpoint subscribed to does not stop the peer
            /// subscribing to it.
            ///
            /// # What it catches
            ///
            /// Weighing the arriving prefix against this endpoint's own
            /// namespace subscriptions as well as the peer's, which one map
            /// of state machines holding both directions invites:
            ///
            /// ```text
            /// a namespace subscription overlapping nothing is taken in: PeerPrefixOverlap
            /// and this endpoint may accept it: PeerPrefixOverlap { request: 1, established: 0 }
            /// ```
            ///
            /// It reddens eleven tests, this gate on drafts 07 through 17.
            /// Drafts 18 and 19 keep no set of this endpoint's own prefixes
            /// for that cut to read; there the same gate is reached by
            /// writing the arriving-request record on the outbound path too,
            /// which reddens three.
            #[test]
            fn a_prefix_of_this_endpoints_own_does_not_block_the_peers() {
                let mut ep = active();
                crate::we_subscribe!($sub, ep, crate::root())
                    .expect("this endpoint may subscribe to a namespace");
                second_is_taken(&mut ep, FIRST, crate::root());
            }

            crate::subscriber_gates!($subscriber, $sub);
            crate::tracks_gates!($tracks, $accept);
        }
    };
}

/// The budget the peer needs before it may open a request, which draft-15
/// renames and draft-17 leaves to the setup.
#[macro_export]
macro_rules! grant {
    (subscribe_id, $ep:expr) => {
        let _ = $ep.send_max_subscribe_id($crate::v(100)).expect("a budget for the peer");
    };
    (request_id, $ep:expr) => {
        let _ = $ep.send_max_request_id($crate::v(100)).expect("a budget for the peer");
    };
    (in_setup, $ep:expr) => {};
}

id_keyed_gates!(
    draft11,
    "draft11",
    0xff00_000b,
    moqtap_client::draft11::session::request_id::Role,
    Client,
    request_id,
    none,
    versioned,
    ided,
    ns,
    id,
    id,
    by_ns,
    allocating,
    1,
    3,
    0,
    0x5,
    counts,
    stated,
    none,
    "8.24"
);
id_keyed_gates!(
    draft12,
    "draft12",
    0xff00_000c,
    moqtap_client::draft12::session::request_id::Role,
    Client,
    request_id,
    none,
    versioned,
    ided,
    ns,
    id,
    id,
    by_ns,
    allocating_params,
    1,
    3,
    0,
    0x5,
    ignored,
    stated,
    none,
    "8.27"
);
id_keyed_gates!(
    draft13,
    "draft13",
    0xff00_000d,
    moqtap_client::draft13::session::request_id::Role,
    Client,
    request_id,
    none,
    versioned,
    renamed,
    renamed,
    renamed,
    renamed,
    renamed_ns,
    params,
    1,
    3,
    0,
    0x5,
    ignored,
    stated,
    none,
    "8.28"
);
id_keyed_gates!(
    draft14,
    "draft14",
    0xff00_000e,
    moqtap_client::draft14::session::request_id::Role,
    Client,
    request_id,
    none,
    versioned,
    d14,
    renamed,
    renamed,
    renamed,
    renamed_ns,
    params,
    1,
    3,
    0,
    0x5,
    ignored,
    stated,
    none,
    "9.28"
);
id_keyed_gates!(
    draft15,
    "draft15",
    0xff00_000f,
    moqtap_client::draft15::session::request_id::Role,
    Client,
    request_id,
    none,
    alpn,
    d15,
    renamed,
    request,
    request,
    by_id,
    params,
    1,
    3,
    0,
    0x30,
    ignored,
    stated,
    none,
    "9.23"
);
id_keyed_gates!(
    draft16,
    "draft16",
    0xff00_0010,
    moqtap_client::draft16::session::request_id::Role,
    Server,
    request_id,
    none,
    d16,
    d16,
    stream16,
    stream16,
    stream16,
    cancel16,
    options,
    0,
    2,
    1,
    0x30,
    ignored,
    stated,
    none,
    "9.25"
);
id_keyed_gates!(
    draft17,
    "draft17",
    0xff00_0011,
    moqtap_client::draft17::session::request_id::Role,
    Server,
    in_setup,
    none,
    one_message,
    d17,
    stream,
    stream17,
    stream17,
    cancel,
    options,
    0,
    2,
    1,
    0x30,
    ignored,
    stated,
    none,
    "9.20"
);
id_keyed_gates!(
    draft18,
    "draft18",
    0xff00_0012,
    moqtap_client::draft18::session::request_id::Role,
    Server,
    in_setup,
    none,
    one_message,
    d18,
    stream,
    stream18,
    stream18,
    cancel,
    params,
    0,
    2,
    1,
    0x30,
    ignored,
    dropped,
    present,
    "10.18"
);
id_keyed_gates!(
    draft19,
    "draft19",
    0xff00_0013,
    moqtap_client::draft19::session::request_id::Role,
    Server,
    in_setup,
    none,
    one_message,
    d18,
    stream,
    stream18,
    stream18,
    cancel,
    params,
    0,
    2,
    1,
    0x30,
    ignored,
    dropped,
    present,
    "10.18"
);

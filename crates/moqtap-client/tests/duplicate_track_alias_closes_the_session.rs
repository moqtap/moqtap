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

//! One Track Alias may not name two tracks at once, on the eight drafts that
//! say so at the subscriber.
//!
//! Draft-19 Section 11.1, and draft-18 in the same words: "The same Track
//! Alias MUST NOT be used by a publisher to refer to two different Tracks
//! simultaneously in the same session. If a subscriber receives a PUBLISH or
//! SUBSCRIBE_OK that uses the same Track Alias as a different Track with an
//! Established subscription, it MUST close the session with error
//! DUPLICATE_TRACK_ALIAS." Drafts 12 through 17 state the same thing as two
//! sentences, one in the SUBSCRIBE_OK section and one in the PUBLISH section,
//! and drafts 12, 13 and 14 write "an active subscription" where 15 onward
//! write "an Established subscription".
//!
//! # Why the range stops at 12
//!
//! Drafts 07 through 11 have the rule and put it at the other endpoint. There
//! the Track Alias is a field of SUBSCRIBE, chosen by the subscriber, and it
//! is the publisher that must close: "If the Track Alias is already being used
//! for a different track, the publisher MUST close the session with a
//! Duplicate Track Alias error (Section 3.5)." Those five also state a second
//! half at the
//! subscriber, on the alias a SUBSCRIBE_ERROR may offer for a retry. Both are
//! in `a_track_alias_names_one_track_at_the_publisher.rs`, which needed a
//! publisher-side subscription lifecycle before it could have either: an alias
//! bound with nothing behind it is one nothing can release, and the peer's
//! next, conforming, use of it would be closed on.
//!
//! # What the comparison set is
//!
//! Every subscription this endpoint holds whose Track Alias it knows and whose
//! state machine still says the subscription is live. Nothing is kept beside
//! the state machines: an alias is free again the instant its subscription
//! ends, and no path that ends one has to remember to say so.
//!
//! A PUBLISH the peer sends is judged against that set and joins it, on all
//! eight drafts. Both halves of the sentence are therefore measured from both
//! ends: a PUBLISH may not take an alias a live subscription holds, and a
//! SUBSCRIBE_OK may not take one an accepted PUBLISH holds.
//!
//! # Why the error code is asserted and not just the refusal
//!
//! The sections name DUPLICATE_TRACK_ALIAS and name no other code. A gate that
//! observed only that the session ended would pass just as well against a
//! close carrying PROTOCOL_VIOLATION, and which rule was broken is the whole
//! of what the peer is being told. Every gate below reads the code the
//! transport would carry, and the loopback gates read it off the
//! CONNECTION_CLOSE - `duplicate_track_alias_on_the_wire.rs` for drafts 12
//! through 16, and `uni_control_plane.rs` for 17, 18 and 19, beside the peer
//! that already enforces their stream topology.
//!
//! # Ablations, measured
//!
//! Five cuts fall on one gate each and are recorded there. The two that fall
//! on the close table are recorded here, because they redden every gate in
//! this file and both loopback files at once - twenty-four tests - and no one
//! gate is where they belong.
//!
//! Deleting the `DuplicateTrackAlias` arm from each draft's
//! `EndpointError::session_error_code` leaves the endpoint refusing the
//! message and ending its own session with nothing to close the transport
//! with:
//!
//! ```text
//! assertion `left == right` failed: Sections 9.8 and 9.13 answer a PUBLISH with
//! DUPLICATE_TRACK_ALIAS and with no other code; the endpoint offered None
//!   left: None
//!  right: Some(DuplicateTrackAlias)
//! ```
//!
//! Answering that arm with `ProtocolViolation` instead:
//!
//! ```text
//! assertion `left == right` failed: Sections 8.8 and 8.13 answer a PUBLISH with
//! DUPLICATE_TRACK_ALIAS and with no other code; the endpoint offered
//! Some(ProtocolViolation)
//!   left: Some(ProtocolViolation)
//!  right: Some(DuplicateTrackAlias)
//! ```

#![allow(clippy::items_after_test_module)]

use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;

/// The namespace both tracks live in, so that the only thing telling them
/// apart is the name.
fn namespace() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec()])
}

fn v(n: u64) -> VarInt {
    VarInt::from_u64(n).unwrap()
}

/// SETUP, in each of the three shapes it takes across the eight drafts.
#[macro_export]
macro_rules! setup_for {
    (versioned, $ep:expr, $version:expr) => {{
        let _ = $ep.send_client_setup(vec![$crate::v($version)], vec![]).expect("CLIENT_SETUP");
        $ep.receive_server_setup(&ServerSetup {
            selected_version: $crate::v($version),
            parameters: vec![KeyValuePair {
                key: $crate::v(0x02),
                value: KvpValue::Varint($crate::v(100)),
            }],
        })
        .expect("SERVER_SETUP");
        // A peer may not open a request until this endpoint has granted it a
        // budget, and that budget starts at zero.
        let _ = $ep.send_max_request_id($crate::v(100)).expect("MAX_REQUEST_ID");
    }};
    (alpn, $ep:expr, $version:expr) => {{
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
    (options, $ep:expr, $version:expr) => {{
        $ep.send_setup(vec![]).expect("SETUP");
        $ep.receive_setup(&Setup { options: vec![] }).expect("the peer's SETUP");
    }};
}

/// `Endpoint::subscribe`, in the three shapes it takes across the eight
/// drafts, asking for whatever each calls a subscription to the largest object
/// of `name` and nothing more.
#[macro_export]
macro_rules! subscribe_to {
    (varint, $ep:expr, $name:expr) => {
        $ep.subscribe(
            $crate::namespace(),
            $name.to_vec(),
            128,
            GroupOrder::Ascending,
            $crate::v(0x2),
            Vec::new(),
        )
    };
    (filter, $ep:expr, $name:expr) => {
        $ep.subscribe(
            $crate::namespace(),
            $name.to_vec(),
            128,
            GroupOrder::Ascending,
            FilterType::LargestObject,
            Vec::new(),
        )
    };
    (params, $ep:expr, $name:expr) => {
        $ep.subscribe($crate::namespace(), $name.to_vec(), Vec::new())
    };
}

/// A SUBSCRIBE_OK naming `alias`, delivered for request `id`.
///
/// Drafts 17, 18 and 19 took the Request ID off the message and put the
/// correlation on the stream, which is why the id is an argument to the call
/// on those three and a field of the message on the other five.
#[macro_export]
macro_rules! answer_with {
    (rich, $ep:expr, $id:expr, $alias:expr) => {
        $ep.receive_subscribe_ok(&SubscribeOk {
            request_id: $id,
            track_alias: $crate::v($alias),
            expires: $crate::v(0),
            group_order: GroupOrder::Ascending,
            content_exists: ContentExists::NoLargestLocation,
            largest_location: None,
            parameters: Vec::new(),
        })
    };
    (plain, $ep:expr, $id:expr, $alias:expr) => {
        $ep.receive_subscribe_ok(&SubscribeOk {
            request_id: $id,
            track_alias: $crate::v($alias),
            parameters: Vec::new(),
        })
    };
    (ext, $ep:expr, $id:expr, $alias:expr) => {
        $ep.receive_subscribe_ok(&SubscribeOk {
            request_id: $id,
            track_alias: $crate::v($alias),
            parameters: Vec::new(),
            track_extensions: Vec::new(),
        })
    };
    (stream, $ep:expr, $id:expr, $alias:expr) => {
        $ep.receive_subscribe_ok(
            $id,
            &SubscribeOk {
                track_alias: $crate::v($alias),
                parameters: Vec::new(),
                track_properties: Vec::new(),
            },
        )
    };
}

/// A PUBLISH from the peer, offering `name` under `alias`.
#[macro_export]
macro_rules! publish_of {
    (rich, $id:expr, $alias:expr, $name:expr) => {
        Publish {
            request_id: $crate::v($id),
            track_namespace: $crate::namespace(),
            track_name: $name.to_vec(),
            track_alias: $crate::v($alias),
            group_order: GroupOrder::Ascending,
            content_exists: ContentExists::NoLargestLocation,
            largest_location: None,
            forward: Forward::Forward,
            parameters: Vec::new(),
        }
    };
    (plain, $id:expr, $alias:expr, $name:expr) => {
        Publish {
            request_id: $crate::v($id),
            track_namespace: $crate::namespace(),
            track_name: $name.to_vec(),
            track_alias: $crate::v($alias),
            parameters: Vec::new(),
        }
    };
    (ext, $id:expr, $alias:expr, $name:expr) => {
        Publish {
            request_id: $crate::v($id),
            track_namespace: $crate::namespace(),
            track_name: $name.to_vec(),
            track_alias: $crate::v($alias),
            parameters: Vec::new(),
            track_extensions: Vec::new(),
        }
    };
    (delta, $id:expr, $alias:expr, $name:expr) => {
        Publish {
            request_id: $crate::v($id),
            required_request_id_delta: $crate::v(0),
            track_namespace: $crate::namespace(),
            track_name: $name.to_vec(),
            track_alias: $crate::v($alias),
            parameters: Vec::new(),
            track_properties: Vec::new(),
        }
    };
    (properties, $id:expr, $alias:expr, $name:expr) => {
        Publish {
            request_id: $crate::v($id),
            track_namespace: $crate::namespace(),
            track_name: $name.to_vec(),
            track_alias: $crate::v($alias),
            parameters: Vec::new(),
            track_properties: Vec::new(),
        }
    };
}

/// Hand the endpoint a PUBLISH the way a message off the wire reaches it.
#[macro_export]
macro_rules! deliver_publish {
    (publish_fn, $ep:expr, $msg:expr) => {
        $ep.receive_publish(&$msg)
    };
    (on_stream, $ep:expr, $msg:expr) => {
        $ep.receive_request_on_stream(&ControlMessage::Publish($msg)).map(|_| ())
    };
}

/// Accept a PUBLISH the peer sent, which is what establishes the subscription
/// it opened and so what makes its Track Alias count against the next one.
///
/// Drafts 18 and 19 have no PUBLISH_OK message: draft-18 Section 10.5 makes
/// REQUEST_OK the answer to a PUBLISH and calls it PUBLISH_OK only as
/// shorthand.
#[macro_export]
macro_rules! accept_publish {
    (varint, $ep:expr, $id:expr) => {
        $ep.send_publish_ok(
            $id,
            Forward::Forward,
            128,
            GroupOrder::Ascending,
            $crate::v(0x2),
            None,
            None,
            None,
        )
        .map(|_| ())
    };
    (filter, $ep:expr, $id:expr) => {
        $ep.send_publish_ok(
            $id,
            Forward::Forward,
            128,
            GroupOrder::Ascending,
            FilterType::LargestObject,
            None,
            None,
            None,
        )
        .map(|_| ())
    };
    (location, $ep:expr, $id:expr) => {
        $ep.send_publish_ok(
            $id,
            Forward::Forward,
            128,
            GroupOrder::Ascending,
            FilterType::LargestObject,
            None,
            None,
        )
        .map(|_| ())
    };
    (params, $ep:expr, $id:expr) => {
        $ep.send_publish_ok($id, Vec::new()).map(|_| ())
    };
    (publish_ok_stream, $ep:expr, $id:expr) => {
        $ep.send_response_on_stream(
            $id,
            &ControlMessage::PublishOk(PublishOk { parameters: Vec::new() }),
        )
        .map(|_| ())
    };
    (request_ok_stream, $ep:expr, $id:expr) => {
        $ep.send_response_on_stream(
            $id,
            &ControlMessage::RequestOk(RequestOk {
                parameters: Vec::new(),
                track_properties: Vec::new(),
            }),
        )
        .map(|_| ())
    };
}

/// End a subscription the way each draft ends one.
#[macro_export]
macro_rules! end_subscription {
    (unsubscribe, $ep:expr, $id:expr) => {
        $ep.unsubscribe($id).map(|_| ())
    };
    (cancel, $ep:expr, $id:expr) => {
        $ep.cancel_request($id).map(|_| ())
    };
}

/// One draft's eight gates.
macro_rules! duplicate_track_alias_gates {
    ($draft:ident, $feat:literal, $version:expr, $setup:tt, $sub:tt, $ok:tt,
     $pubmsg:tt, $pubin:tt, $accept:tt, $end:tt, $ok_sec:literal,
     $pub_sec:literal) => {
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
            use moqtap_codec::varint::VarInt;
            use moqtap_codec::$draft::error_codes::SessionErrorCode;
            #[allow(unused_imports)]
            use moqtap_codec::$draft::message::*;

            /// The alias the peer reuses.
            const ALIAS: u64 = 7;

            /// A second alias, so that a gate about the alias can be told from
            /// one about there being two subscriptions.
            const OTHER_ALIAS: u64 = 8;

            const ALPHA: &[u8] = b"alpha";
            const BETA: &[u8] = b"beta";

            /// The peer's first Request ID: odd, because this endpoint is the
            /// client and the peer is the server.
            const PEERS_FIRST: u64 = 1;

            /// A client with its session established.
            fn active() -> Endpoint {
                let mut ep = Endpoint::new(Role::Client);
                ep.connect().expect("a client may open");
                crate::setup_for!($setup, ep, $version);
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "the gates need a running session to end"
                );
                ep
            }

            /// The peer's first Request ID, as a varint.
            fn peer_id() -> VarInt {
                VarInt::from_u64(PEERS_FIRST).expect("a small id is a varint")
            }

            /// Take the peer's offer of `name` under `alias` and accept it,
            /// which is what establishes the subscription it opened.
            fn offered(ep: &mut Endpoint, name: &'static [u8], alias: u64) {
                let offer = crate::publish_of!($pubmsg, PEERS_FIRST, alias, name);
                crate::deliver_publish!($pubin, ep, offer).expect("the peer's PUBLISH");
                crate::accept_publish!($accept, ep, peer_id())
                    .expect("this endpoint's answer to the offer");
            }

            /// Subscribe to `name` and have it answered with `alias`.
            fn established(ep: &mut Endpoint, name: &'static [u8], alias: u64) -> VarInt {
                let (id, _) = crate::subscribe_to!($sub, ep, name).expect("SUBSCRIBE");
                crate::answer_with!($ok, ep, id, alias).expect("SUBSCRIBE_OK");
                id
            }

            /// Assert the endpoint has ended its own session and named the
            /// code the sections name.
            fn refused(ep: &Endpoint, err: &EndpointError, what: &str) {
                assert_eq!(
                    err.session_error_code(),
                    Some(SessionErrorCode::DuplicateTrackAlias),
                    "Sections {} and {} answer {what} with DUPLICATE_TRACK_ALIAS and \
                     with no other code; the endpoint offered {:?}",
                    $ok_sec,
                    $pub_sec,
                    err.session_error_code()
                );
                assert_eq!(
                    ep.session_state(),
                    SessionState::Closed,
                    "a rule the draft answers with a session close has to end this \
                     endpoint's own session too, or nothing puts the close on the wire"
                );
            }

            /// A SUBSCRIBE_OK giving a second track an alias a live one
            /// already holds ends the session.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// Deleting the `conflicting_alias_for_subscribe_ok` call from
            /// `receive_subscribe_ok`:
            ///
            /// ```text
            /// the second SUBSCRIBE_OK reused a live track's alias and was accepted: ()
            /// ```
            ///
            /// It reddens sixteen tests: this gate on all eight drafts, and
            /// both loopback gates on all eight. A rule with a route to the
            /// wire has both.
            #[test]
            fn a_second_track_under_a_live_alias_closes_the_session() {
                let mut ep = active();
                let first = established(&mut ep, ALPHA, ALIAS);
                let (second, _) = crate::subscribe_to!($sub, ep, BETA).expect("SUBSCRIBE");
                assert_ne!(first, second, "two requests, or there is nothing to conflict");

                let err = crate::answer_with!($ok, ep, second, ALIAS).expect_err(
                    "the second SUBSCRIBE_OK reused a live track's alias and was accepted",
                );
                refused(&ep, &err, "a SUBSCRIBE_OK");
            }

            /// A second track under an alias of its own is accepted.
            ///
            /// The refusal is about the alias and not about there being two
            /// subscriptions, and this is the input that tells the two apart:
            /// everything else about it is the gate above.
            ///
            /// # What it catches
            ///
            /// Dropping the `binding.alias != Some(alias)` guard from
            /// `conflicting_track_alias`:
            ///
            /// ```text
            /// a second track under an alias of its own was refused: DuplicateTrackAlias { alias: 8, established: 0, offered: 2 }
            /// ```
            ///
            /// It reddens eleven tests. The other three are
            /// `two_requests_are_answered_on_their_own_streams` in
            /// `uni_control_plane.rs`, which subscribes to two tracks and is
            /// answered with two aliases - the shape a rule that ignored the
            /// alias would break for every subscriber that has more than one
            /// subscription open.
            #[test]
            fn a_second_track_under_its_own_alias_is_accepted() {
                let mut ep = active();
                established(&mut ep, ALPHA, ALIAS);
                let (second, _) = crate::subscribe_to!($sub, ep, BETA).expect("SUBSCRIBE");

                crate::answer_with!($ok, ep, second, OTHER_ALIAS)
                    .expect("a second track under an alias of its own was refused");
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "a conforming pair of subscriptions must leave the session running"
                );
            }

            /// The same track keeps the alias it already has.
            ///
            /// The sections forbid one alias naming "two different Tracks", so
            /// a second subscription to the same Full Track Name answered with
            /// the same alias breaks nothing here.
            ///
            /// Whether a subscriber may hold two subscriptions to one track at
            /// once is a different rule with a different range: drafts 07
            /// through 14 say "A subscriber MUST NOT make multiple active
            /// subscriptions for a track within a single session", and drafts
            /// 15 through 20 do not say it at all. Nothing in this crate
            /// enforces it either way, so the pair of subscriptions this gate
            /// builds is a state three of these eight drafts would call a
            /// violation - of that rule, and not of this one. What is being
            /// measured is that the alias check reads the Full Track Name and
            /// not merely the Request ID.
            ///
            /// # What it catches
            ///
            /// Dropping the `binding.namespace == *namespace && binding.name
            /// == name` guard from `conflicting_track_alias`:
            ///
            /// ```text
            /// the same track was refused its own alias: DuplicateTrackAlias { alias: 7, established: 0, offered: 2 }
            /// ```
            #[test]
            fn the_same_track_keeps_the_alias_it_has() {
                let mut ep = active();
                established(&mut ep, ALPHA, ALIAS);
                let (second, _) = crate::subscribe_to!($sub, ep, ALPHA).expect("SUBSCRIBE");

                crate::answer_with!($ok, ep, second, ALIAS)
                    .expect("the same track was refused its own alias");
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "one track under one alias twice breaks no rule"
                );
            }

            /// An alias is free again once the subscription holding it ends.
            ///
            /// This is the "simultaneously" in the sentence, and it is the
            /// reason the comparison set is read off the state machines rather
            /// than kept beside them.
            ///
            /// # What it catches
            ///
            /// Answering `binding_is_established` with `true` for every
            /// binding - which is what a set kept beside the state machines
            /// and never pruned would do:
            ///
            /// ```text
            /// an alias whose subscription had ended was still held: DuplicateTrackAlias { alias: 7, established: 0, offered: 2 }
            /// ```
            #[test]
            fn an_alias_is_free_once_its_subscription_ends() {
                let mut ep = active();
                let first = established(&mut ep, ALPHA, ALIAS);
                crate::end_subscription!($end, ep, first).expect("end the first subscription");

                let (second, _) = crate::subscribe_to!($sub, ep, BETA).expect("SUBSCRIBE");
                crate::answer_with!($ok, ep, second, ALIAS)
                    .expect("an alias whose subscription had ended was still held");
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "reusing the alias of a finished subscription breaks no rule"
                );
            }

            /// A PUBLISH offering a second track under a live alias ends the
            /// session, with the same code.
            ///
            /// The other half of the sentence, and a different message on a
            /// different path: a SUBSCRIBE_OK answers a request this endpoint
            /// made, a PUBLISH opens one the peer makes. One input cannot
            /// reach both.
            ///
            /// # What it catches
            ///
            /// Deleting the `conflicting_track_alias` call from the inbound
            /// PUBLISH path:
            ///
            /// ```text
            /// the PUBLISH reused a live track's alias and was accepted: ()
            /// ```
            ///
            /// The cut above leaves this gate green and this cut leaves that
            /// one green, on all eight drafts: one shared check, two callers,
            /// and neither of them covered by the other's gate.
            #[test]
            fn a_publish_under_a_live_alias_closes_the_session() {
                let mut ep = active();
                established(&mut ep, ALPHA, ALIAS);

                let offer = crate::publish_of!($pubmsg, PEERS_FIRST, ALIAS, BETA);
                let err = crate::deliver_publish!($pubin, ep, offer)
                    .expect_err("the PUBLISH reused a live track's alias and was accepted");
                refused(&ep, &err, "a PUBLISH");
            }

            /// An alias an accepted PUBLISH holds is not free for a
            /// SUBSCRIBE_OK to give to another track.
            ///
            /// The other direction of the gate above, and the one that needs
            /// the peer's offer to have been written down rather than only
            /// judged: a PUBLISH is one of the two sequences
            /// draft-19 Section 5.1 names as a source of a subscription, so
            /// what it establishes has to count against what comes next.
            ///
            /// # What it catches
            ///
            /// Recording nothing for an accepted PUBLISH - dropping the
            /// `track_bindings.insert` from the inbound PUBLISH path:
            ///
            /// ```text
            /// a SUBSCRIBE_OK took an alias an accepted PUBLISH holds: ()
            /// ```
            ///
            /// It reddens ten tests: this gate on drafts 12 through 16 and
            /// the loopback gate on the same five. Drafts 17, 18 and 19
            /// record the binding at a call site of their own and are left
            /// alone by that cut, which is why the five and the three each
            /// need their own.
            #[test]
            fn an_accepted_publish_holds_its_alias() {
                let mut ep = active();
                offered(&mut ep, ALPHA, ALIAS);

                let (second, _) = crate::subscribe_to!($sub, ep, BETA).expect("SUBSCRIBE");
                let err = crate::answer_with!($ok, ep, second, ALIAS)
                    .expect_err("a SUBSCRIBE_OK took an alias an accepted PUBLISH holds");
                refused(&ep, &err, "a SUBSCRIBE_OK");
            }

            /// The alias an accepted PUBLISH held is free once that
            /// subscription ends.
            ///
            /// The "simultaneously" again, on the other kind of binding. It
            /// is a gate of its own because the two kinds are two arms of
            /// `binding_is_established`, and a wrong answer in one of them is
            /// invisible from the other.
            ///
            /// # What it catches
            ///
            /// Counting a `BindingKind::Publish` binding as established while
            /// its subscription is over - reading `!= Publishing` where the
            /// state should be `== Active`:
            ///
            /// ```text
            /// the alias of a finished publish was still held: DuplicateTrackAlias { alias: 7, established: 1, offered: 0 }
            /// ```
            ///
            /// It reddens eight tests and no others: this gate, on all eight
            /// drafts. The cut above and this one are the two halves of the
            /// same comparison, and neither reddens the other's gate.
            #[test]
            fn an_alias_is_free_once_its_publish_ends() {
                let mut ep = active();
                offered(&mut ep, ALPHA, ALIAS);
                crate::end_subscription!($end, ep, peer_id()).expect("end the peer's offer");

                let (second, _) = crate::subscribe_to!($sub, ep, BETA).expect("SUBSCRIBE");
                crate::answer_with!($ok, ep, second, ALIAS)
                    .expect("the alias of a finished publish was still held");
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "reusing the alias of a finished subscription breaks no rule"
                );
            }

            /// A PUBLISH that has arrived and not been answered holds nothing.
            ///
            /// "Simultaneously" is about subscriptions that exist, and an
            /// offer this endpoint has not accepted is not one yet. This is
            /// the input that tells the recording apart from the acceptance:
            /// it differs from the gate above only in the answer not being
            /// sent.
            ///
            /// # What it catches
            ///
            /// Counting a `BindingKind::Publish` binding as established
            /// from the moment it arrives - reading `!= Done` where the
            /// state should be `== Active`:
            ///
            /// ```text
            /// an unanswered PUBLISH held an alias it had not been given: DuplicateTrackAlias { alias: 7, established: 1, offered: 0 }
            /// ```
            ///
            /// It reddens eight tests and no others: this gate, on all eight
            /// drafts.
            #[test]
            fn an_unanswered_publish_holds_no_alias() {
                let mut ep = active();
                let offer = crate::publish_of!($pubmsg, PEERS_FIRST, ALIAS, ALPHA);
                crate::deliver_publish!($pubin, ep, offer).expect("the peer's PUBLISH");

                let (second, _) = crate::subscribe_to!($sub, ep, BETA).expect("SUBSCRIBE");
                crate::answer_with!($ok, ep, second, ALIAS)
                    .expect("an unanswered PUBLISH held an alias it had not been given");
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "an offer that was never accepted establishes nothing"
                );
            }
        }
    };
}

duplicate_track_alias_gates!(
    draft12,
    "draft12",
    0xff00_000c,
    versioned,
    varint,
    rich,
    rich,
    publish_fn,
    varint,
    unsubscribe,
    "8.8",
    "8.13"
);
duplicate_track_alias_gates!(
    draft13,
    "draft13",
    0xff00_000d,
    versioned,
    filter,
    rich,
    rich,
    publish_fn,
    filter,
    unsubscribe,
    "8.8",
    "8.13"
);
duplicate_track_alias_gates!(
    draft14,
    "draft14",
    0xff00_000e,
    versioned,
    filter,
    rich,
    rich,
    publish_fn,
    location,
    unsubscribe,
    "9.8",
    "9.13"
);
duplicate_track_alias_gates!(
    draft15,
    "draft15",
    0,
    alpn,
    params,
    plain,
    plain,
    publish_fn,
    params,
    unsubscribe,
    "9.10",
    "9.13"
);
duplicate_track_alias_gates!(
    draft16,
    "draft16",
    0,
    alpn,
    params,
    ext,
    ext,
    publish_fn,
    params,
    unsubscribe,
    "9.10",
    "9.13"
);
duplicate_track_alias_gates!(
    draft17,
    "draft17",
    0,
    options,
    params,
    stream,
    delta,
    on_stream,
    publish_ok_stream,
    cancel,
    "9.9",
    "9.11"
);
duplicate_track_alias_gates!(
    draft18,
    "draft18",
    0,
    options,
    params,
    stream,
    properties,
    on_stream,
    request_ok_stream,
    cancel,
    "11.1",
    "11.1"
);
duplicate_track_alias_gates!(
    draft19,
    "draft19",
    0,
    options,
    params,
    stream,
    properties,
    on_stream,
    request_ok_stream,
    cancel,
    "11.1",
    "11.1"
);

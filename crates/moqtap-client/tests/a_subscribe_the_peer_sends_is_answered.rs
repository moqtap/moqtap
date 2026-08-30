#![cfg(any(
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
))]

//! A SUBSCRIBE the peer sends opens a subscription, and this endpoint carries
//! it from arrival to acceptance to the end of the flow.
//!
//! Drafts 12 and 13 Section 4.1, and drafts 14 through 16 Section 5.1: "A
//! publisher MUST send exactly one SUBSCRIBE_OK or SUBSCRIBE_ERROR in response
//! to a SUBSCRIBE." Drafts 15 and 16 name the refusal REQUEST_ERROR and say
//! the sentence with that word in it.
//!
//! What comes after the answer is the rest of the flow: the subscriber ends an
//! accepted subscription with UNSUBSCRIBE and the publisher ends it with
//! SUBSCRIBE_DONE, which drafts 14 and later call PUBLISH_DONE. This endpoint
//! is the publisher of a SUBSCRIBE that arrives, so it sends the answer,
//! receives the UNSUBSCRIBE and sends the message that ends the flow - every
//! message the other way round from a subscription it opened itself.
//!
//! # What was here before
//!
//! Nothing. An arriving SUBSCRIBE was checked for its Request ID and dropped,
//! and no UNSUBSCRIBE was processed at all, so a peer that subscribed to this
//! endpoint waited for an answer the crate had no record to build. These five
//! drafts are the ones that had a record for the peer's PUBLISH and none for
//! the peer's SUBSCRIBE.
//!
//! # Why the Track Alias is judged here and not on arrival
//!
//! From draft-12 the SUBSCRIBE does not carry one: the publisher chooses it
//! and sends it in the SUBSCRIBE_OK. So this endpoint is the end that must not
//! give one alias to two tracks, and the refusal happens where the alias is
//! chosen. That is the same rule
//! `an_endpoint_gives_one_alias_to_one_track.rs` gates at `publish`, reached
//! through a second call site, which is why it is gated again here.
//!
//! # Why none of this closes the session
//!
//! "MUST send exactly one" is addressed to the sender of the answer. This
//! endpoint's job is not to send the second one, so a second answer is refused
//! where it is asked for and the session goes on running. Every gate below
//! checks that.
//!
//! # Ablations, measured
//!
//! Ten cuts were made, run and reverted, each recorded on the gate it belongs
//! to. Several reach past this file, and the direction is always the same: a
//! subscription the peer opened that cannot be recorded, answered or ended is
//! one nothing downstream can act on, so the update files go with it. Nothing
//! here reaches the other way.

#![allow(clippy::items_after_test_module)]

use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;

/// The namespace the subscribed track lives in.
fn namespace() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec()])
}

fn v(n: u64) -> VarInt {
    VarInt::from_u64(n).unwrap()
}

/// A SUBSCRIBE from the peer, in the four shapes it takes across the five
/// drafts: draft-12 carries the filter as a raw varint, draft-13 as a named
/// type, draft-14 replaces the start group and object with a location, and
/// drafts 15 and 16 moved everything but the track into parameters.
#[macro_export]
macro_rules! peers_subscribe {
    (filter_varint, $id:expr, $track:expr) => {
        Subscribe {
            request_id: $crate::v($id),
            track_namespace: $crate::namespace(),
            track_name: $track.to_vec(),
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            forward: Forward::Forward,
            filter_type: $crate::v(0x2),
            start_group: None,
            start_object: None,
            end_group: None,
            parameters: Vec::new(),
        }
    };
    (filter_type, $id:expr, $track:expr) => {
        Subscribe {
            request_id: $crate::v($id),
            track_namespace: $crate::namespace(),
            track_name: $track.to_vec(),
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            forward: Forward::Forward,
            filter_type: FilterType::LargestObject,
            start_group: None,
            start_object: None,
            end_group: None,
            parameters: Vec::new(),
        }
    };
    (location, $id:expr, $track:expr) => {
        Subscribe {
            request_id: $crate::v($id),
            track_namespace: $crate::namespace(),
            track_name: $track.to_vec(),
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            forward: Forward::Forward,
            filter_type: FilterType::LargestObject,
            start_location: None,
            end_group: None,
            parameters: Vec::new(),
        }
    };
    (bare, $id:expr, $track:expr) => {
        Subscribe {
            request_id: $crate::v($id),
            track_namespace: $crate::namespace(),
            track_name: $track.to_vec(),
            parameters: Vec::new(),
        }
    };
}

/// The SUBSCRIBE_OK this endpoint builds, under the arguments each draft's
/// message needs.
#[macro_export]
macro_rules! we_accept {
    (expires, $ep:expr, $id:expr, $alias:expr) => {
        $ep.send_subscribe_ok(
            $crate::v($id),
            $crate::v($alias),
            $crate::v(0),
            GroupOrder::Ascending,
            Vec::new(),
        )
    };
    (params, $ep:expr, $id:expr, $alias:expr) => {
        $ep.send_subscribe_ok($crate::v($id), $crate::v($alias), Vec::new())
    };
    (ext, $ep:expr, $id:expr, $alias:expr) => {
        $ep.send_subscribe_ok($crate::v($id), $crate::v($alias), Vec::new(), Vec::new())
    };
}

/// The refusal, under the name and shape each draft gives it.
#[macro_export]
macro_rules! we_refuse {
    (subscribe_error, $ep:expr, $id:expr) => {
        $ep.send_subscribe_error($crate::v($id), $crate::v(1), b"no".to_vec())
    };
    (request_error, $ep:expr, $id:expr) => {
        $ep.send_request_error($crate::v($id), $crate::v(1), b"no".to_vec())
    };
    (retry, $ep:expr, $id:expr) => {
        $ep.send_request_error($crate::v($id), $crate::v(1), $crate::v(0), b"no".to_vec())
    };
}

/// The message the publisher ends the subscription with, which drafts 14 and
/// later renamed and drafts 15 and later gave an explicit stream count.
#[macro_export]
macro_rules! we_finish {
    (subscribe_done, $ep:expr, $id:expr) => {
        $ep.send_subscribe_done($crate::v($id), $crate::v(0), $crate::v(0), Vec::new())
    };
    (publish_done, $ep:expr, $id:expr) => {
        $ep.send_publish_done($crate::v($id), $crate::v(0), Vec::new())
    };
    (publish_done_count, $ep:expr, $id:expr) => {
        $ep.send_publish_done($crate::v($id), $crate::v(0), $crate::v(0), Vec::new())
    };
}

/// SETUP, in the two shapes it takes across the five drafts: the version is
/// negotiated in the message up to draft-14 and in the ALPN afterwards.
#[macro_export]
macro_rules! peers_setup {
    (versioned, $ep:expr, $ver:expr) => {{
        let _ = $ep.send_client_setup(vec![$crate::v($ver)], vec![]).expect("CLIENT_SETUP");
        $ep.receive_server_setup(&ServerSetup {
            selected_version: $crate::v($ver),
            parameters: vec![],
        })
        .expect("SERVER_SETUP");
    }};
    (alpn, $ep:expr, $ver:expr) => {{
        let _ = $ep.send_client_setup(vec![]).expect("CLIENT_SETUP");
        $ep.receive_server_setup(&ServerSetup { parameters: vec![] }).expect("SERVER_SETUP");
    }};
}

/// One draft's ten gates.
macro_rules! inbound_subscribe_gates {
    ($draft:ident, $feat:literal, $ver:expr, $setup:tt, $submsg:tt, $accept:tt, $refuse:tt,
     $finish:tt, $sec:literal) => {
        #[cfg(feature = $feat)]
        mod $draft {
            use moqtap_client::$draft::endpoint::{Endpoint, EndpointError};
            use moqtap_client::$draft::session::request_id::Role;
            use moqtap_client::$draft::session::state::SessionState;

            #[allow(unused_imports)]
            use moqtap_codec::kvp::{KeyValuePair, KvpValue};
            #[allow(unused_imports)]
            use moqtap_codec::types::*;
            use moqtap_codec::varint::VarInt;
            use moqtap_codec::$draft::message::*;

            /// The peer is the server here, so its Request IDs are the odd
            /// ones.
            const PEERS_FIRST: u64 = 1;

            /// A second one, for the gates that need two subscriptions.
            const PEERS_SECOND: u64 = 3;

            /// An identifier no SUBSCRIBE ever arrived under.
            const NEVER_USED: u64 = 9;

            /// The alias this endpoint gives the track it accepts.
            const ALIAS: u64 = 7;

            const ALPHA: &[u8] = b"alpha";
            const BETA: &[u8] = b"beta";

            fn peer_id() -> VarInt {
                VarInt::from_u64(PEERS_FIRST).expect("a small id is a varint")
            }

            /// A client with its session established and a budget granted to
            /// the peer, without which no SUBSCRIBE of the peer's is legal.
            fn active() -> Endpoint {
                let mut ep = Endpoint::new(Role::Client);
                ep.connect().expect("a client may open");
                crate::peers_setup!($setup, ep, $ver);
                let _ = ep.send_max_request_id($crate::v(100)).expect("a budget for the peer");
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "the gates need a running session"
                );
                ep
            }

            /// An endpoint holding the peer's unanswered SUBSCRIBE.
            fn subscribed() -> Endpoint {
                let mut ep = active();
                ep.receive_subscribe(&crate::peers_subscribe!($submsg, PEERS_FIRST, ALPHA))
                    .expect("the peer's SUBSCRIBE");
                ep
            }

            /// An endpoint that has accepted the peer's SUBSCRIBE.
            fn accepted() -> Endpoint {
                let mut ep = subscribed();
                crate::we_accept!($accept, ep, PEERS_FIRST, ALIAS)
                    .expect("accept the subscription");
                ep
            }

            /// The session is still running: none of these rules is one this
            /// endpoint answers by closing.
            fn still_running(ep: &Endpoint) {
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "Section {} addresses the sender of the answer, so declining to \
                     send a second one is not a reason to end the session",
                    $sec
                );
            }

            /// A SUBSCRIBE arriving the way the control stream delivers one
            /// reaches the flow that can answer it.
            ///
            /// The dispatch arm is the whole of what this measures. Without it
            /// a SUBSCRIBE is checked for its Request ID and then dropped,
            /// which is what these drafts did: the peer waits for an answer
            /// the endpoint has no record to build one from.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// Removing the `ControlMessage::Subscribe` arm from
            /// `receive_message`:
            ///
            /// ```text
            /// the SUBSCRIBE that arrived on the control stream could not be answered: UnknownRequest(1)
            /// ```
            ///
            /// It reddens thirty-three tests: this gate on all five drafts, every gate
            /// in `an_update_for_an_unknown_request_ends_the_session.rs`, which needs
            /// the peer's subscription to exist before it can be updated, and the
            /// draft-14 dispatch test.
            #[test]
            fn a_subscribe_off_the_control_stream_reaches_the_flow() {
                let mut ep = active();
                ep.receive_message(ControlMessage::Subscribe(crate::peers_subscribe!(
                    $submsg,
                    PEERS_FIRST,
                    ALPHA
                )))
                .expect("the peer's SUBSCRIBE");

                crate::we_accept!($accept, ep, PEERS_FIRST, ALIAS).expect(
                    "the SUBSCRIBE that arrived on the control stream could not be answered",
                );
                still_running(&ep);
            }

            /// An answer to a SUBSCRIBE that never arrived is refused.
            ///
            /// # What it catches
            ///
            /// Answering whichever subscription is outstanding instead of the
            /// one the answer names - looking the record up by iteration
            /// rather than by identifier:
            ///
            /// ```text
            /// a SUBSCRIBE_OK was built for a request that never arrived: SubscribeOk(SubscribeOk { request_id: VarInt(9), track_alias: VarInt(7), expires: VarInt(0), group_order: Ascending, content_exists: NoLargestLocation, largest_location: None, parameters: [] })
            /// ```
            ///
            /// Made by answering whichever inbound subscription is first in the map,
            /// in both of the acceptance's lookups. It reddens twenty-two tests across
            /// six drafts - draft-11's acceptance is written the same way and is cut
            /// by the same edit - because the gates that answer two subscriptions and
            /// the ones that judge an alias all need the right record.
            #[test]
            fn an_answer_to_a_subscribe_that_never_arrived_is_refused() {
                let mut ep = subscribed();
                let err = crate::we_accept!($accept, ep, NEVER_USED, ALIAS)
                    .expect_err("a SUBSCRIBE_OK was built for a request that never arrived");
                assert!(
                    matches!(err, EndpointError::UnknownRequest(NEVER_USED)),
                    "the refusal should name the id nothing arrived under, and named {err:?}"
                );
                still_running(&ep);
            }

            /// A second acceptance for one SUBSCRIBE is refused.
            ///
            /// # What it catches
            ///
            /// Building the answer without moving the record on, which is the
            /// shape a publisher with no lifecycle has: every answer looks
            /// like the first one.
            ///
            /// ```text
            /// a second answer was sent for one SUBSCRIBE: SubscribeOk(SubscribeOk { request_id: VarInt(1), track_alias: VarInt(7), expires: VarInt(0), group_order: Ascending, content_exists: NoLargestLocation, largest_location: None, parameters: [] })
            /// ```
            ///
            /// It reddens sixty tests. A subscription that never reaches Active is one
            /// nothing else in the flow can act on, so every gate past the answer goes
            /// with it, on all ten drafts that have this lifecycle.
            #[test]
            fn a_second_acceptance_is_refused() {
                let mut ep = accepted();
                crate::we_accept!($accept, ep, PEERS_FIRST, ALIAS)
                    .expect_err("a second answer was sent for one SUBSCRIBE");
                still_running(&ep);
            }

            /// A SUBSCRIBE already rejected cannot then be accepted.
            ///
            /// The other order, and a separate input because it leaves the
            /// record in a different state: "exactly one" is one answer of
            /// either kind, not one of each.
            ///
            /// # What it catches
            ///
            /// Letting the acceptance run from the state a rejection leaves:
            ///
            /// ```text
            /// a SUBSCRIBE was accepted after it had been rejected: SubscribeOk(SubscribeOk { request_id: VarInt(1), track_alias: VarInt(7), expires: VarInt(0), group_order: Ascending, content_exists: NoLargestLocation, largest_location: None, parameters: [] })
            /// ```
            ///
            /// The cut is the rejection's own, not the acceptance's: leaving the record
            /// where it was when the refusal went out reddens ten tests and only this
            /// gate. The acceptance has a cut of its own and it reddens this gate too,
            /// which is what two answers to one question look like.
            #[test]
            fn a_rejected_subscribe_cannot_then_be_accepted() {
                let mut ep = subscribed();
                crate::we_refuse!($refuse, ep, PEERS_FIRST).expect("reject the subscription");

                crate::we_accept!($accept, ep, PEERS_FIRST, ALIAS)
                    .expect_err("a SUBSCRIBE was accepted after it had been rejected");
                still_running(&ep);
            }

            /// A subscription that has not been accepted cannot be ended by
            /// the publisher.
            ///
            /// The message that ends a subscription ends one that is running;
            /// one still waiting for its answer is refused instead, which is a
            /// different message and a different state.
            ///
            /// # What it catches
            ///
            /// Discarding what the record says when the message is built, so
            /// that it ends a subscription from any state rather than from the
            /// one the subscription exists in:
            ///
            /// ```text
            /// a subscription this endpoint had not accepted was ended: SubscribeDone(SubscribeDone { request_id: VarInt(1), status_code: VarInt(0), stream_count: VarInt(0), reason_phrase: [] })
            /// ```
            ///
            /// Drafts 14 through 16 send PUBLISH_DONE for the same thing and report it
            /// under that name. It reddens forty tests: a subscription that cannot be
            /// ended is one whose alias is never freed and whose update can still be
            /// accepted, so the alias gate and both update files go with it.
            #[test]
            fn an_unanswered_subscribe_cannot_be_ended() {
                let mut ep = subscribed();
                let err = crate::we_finish!($finish, ep, PEERS_FIRST)
                    .expect_err("a subscription this endpoint had not accepted was ended");
                assert!(
                    matches!(err, EndpointError::Subscription(_)),
                    "the refusal should come from the subscription's own state, \
                     and came from {err:?}"
                );
                still_running(&ep);
            }

            /// The subscribing peer ends an accepted subscription with
            /// UNSUBSCRIBE, once.
            ///
            /// Delivered the way the control stream delivers one, because the
            /// dispatch arm for UNSUBSCRIBE is as new as the record it lands
            /// in and nothing else would reach it.
            ///
            /// # What it catches
            ///
            /// Removing the `ControlMessage::Unsubscribe` arm from
            /// `receive_message`, which leaves the message with nowhere to
            /// land and the subscription running for ever:
            ///
            /// ```text
            /// a subscription that was never ended accepted a second UNSUBSCRIBE: ()
            /// ```
            ///
            /// It reddens five tests and no others: this gate, on all five drafts.
            /// Nothing else here needs an UNSUBSCRIBE to arrive off the control
            /// stream.
            #[test]
            fn an_accepted_subscribe_is_ended_by_unsubscribe() {
                let mut ep = accepted();
                ep.receive_message(ControlMessage::Unsubscribe(Unsubscribe {
                    request_id: peer_id(),
                }))
                .expect("the peer's UNSUBSCRIBE");

                ep.receive_unsubscribe(&Unsubscribe { request_id: peer_id() }).expect_err(
                    "a subscription that was never ended accepted a second UNSUBSCRIBE",
                );
                still_running(&ep);
            }

            /// The publisher ends an accepted subscription, and nothing
            /// follows it.
            ///
            /// The other end of the same subscription, and the message that
            /// carries it is one this endpoint sends rather than receives -
            /// which is a different route into the same record.
            ///
            /// # What it catches
            ///
            /// Building the closing message without moving the record on:
            ///
            /// ```text
            /// a subscription this endpoint had already ended was unsubscribed: ()
            /// ```
            ///
            /// The subscriber's route into the same record is a different probe in a
            /// different method, and cutting either one leaves the other's gate green.
            #[test]
            fn an_accepted_subscribe_is_ended_by_the_publisher() {
                let mut ep = accepted();
                crate::we_finish!($finish, ep, PEERS_FIRST)
                    .expect("the publisher could not end the subscription it accepted");

                ep.receive_unsubscribe(&Unsubscribe { request_id: peer_id() })
                    .expect_err("a subscription this endpoint had already ended was unsubscribed");
                still_running(&ep);
            }

            /// Two subscriptions from the peer are answered independently.
            ///
            /// # What it catches
            ///
            /// Keeping one inbound record for the whole session rather than
            /// one per request, which passes every gate above - each of them
            /// has a single subscription outstanding:
            ///
            /// ```text
            /// the first subscription could not be accepted: UnknownRequest(1)
            /// ```
            ///
            /// Made by clearing the map before each insert, which is what one record
            /// for the whole session amounts to. It reddens twenty tests: this gate and
            /// the two alias gates below, on all ten drafts. The first subscription is
            /// the one that goes missing, so the failure names it rather than the
            /// second.
            #[test]
            fn two_subscriptions_from_the_peer_are_answered_apart() {
                let mut ep = subscribed();
                ep.receive_subscribe(&crate::peers_subscribe!($submsg, PEERS_SECOND, BETA))
                    .expect("the peer's second SUBSCRIBE");

                crate::we_accept!($accept, ep, PEERS_FIRST, ALIAS)
                    .expect("the first subscription could not be accepted");
                crate::we_accept!($accept, ep, PEERS_SECOND, ALIAS + 1)
                    .expect("the second subscription could not be accepted");
                still_running(&ep);
            }

            /// One alias for two of the peer's tracks is refused before the
            /// SUBSCRIBE_OK exists.
            ///
            /// The same rule `an_endpoint_gives_one_alias_to_one_track.rs`
            /// gates at `publish`, reached through the call site added here.
            /// A shared check needs one gate per caller: cutting it out
            /// of one leaves the other's gate green.
            ///
            /// # What it catches
            ///
            /// Deleting the `alias_held_elsewhere` call from
            /// `send_subscribe_ok`:
            ///
            /// ```text
            /// this endpoint gave one alias to two of the peer's tracks: SubscribeOk(SubscribeOk { request_id: VarInt(3), track_alias: VarInt(7), expires: VarInt(0), group_order: Ascending, content_exists: NoLargestLocation, largest_location: None, parameters: [] })
            /// ```
            ///
            /// It reddens five tests and only this gate. Nothing that judges an alias
            /// arriving is touched, and neither is `publish`, which is the same check
            /// at its other call site.
            #[test]
            fn one_alias_for_two_of_the_peers_tracks_is_refused() {
                let mut ep = subscribed();
                ep.receive_subscribe(&crate::peers_subscribe!($submsg, PEERS_SECOND, BETA))
                    .expect("the peer's second SUBSCRIBE");
                crate::we_accept!($accept, ep, PEERS_FIRST, ALIAS).expect("the first acceptance");

                let err = crate::we_accept!($accept, ep, PEERS_SECOND, ALIAS)
                    .expect_err("this endpoint gave one alias to two of the peer's tracks");
                assert!(
                    matches!(
                        err,
                        EndpointError::TrackAliasInUse { alias: ALIAS, held: PEERS_FIRST }
                    ),
                    "the refusal should name the alias and the request holding it, \
                     and named {err:?}"
                );
                still_running(&ep);
            }

            /// An alias whose subscription has ended is free again.
            ///
            /// The liveness the rule reads is the subscription's own state,
            /// not a second set kept beside it, so ending the subscription is
            /// all it takes to release the alias.
            ///
            /// # What it catches
            ///
            /// Reading a binding as live whatever state its subscription is
            /// in, which is what a set of aliases with nothing to prune it
            /// amounts to:
            ///
            /// ```text
            /// an alias whose subscription had ended was still held: TrackAliasInUse { alias: 7, held: 1 }
            /// ```
            ///
            /// Made by reading a binding as live whenever its record exists. It reddens
            /// five tests and only this gate: every other alias gate here has a live
            /// subscription behind the binding.
            #[test]
            fn an_alias_is_free_once_its_subscription_ends() {
                let mut ep = subscribed();
                ep.receive_subscribe(&crate::peers_subscribe!($submsg, PEERS_SECOND, BETA))
                    .expect("the peer's second SUBSCRIBE");
                crate::we_accept!($accept, ep, PEERS_FIRST, ALIAS).expect("the first acceptance");
                crate::we_finish!($finish, ep, PEERS_FIRST).expect("end the first subscription");

                crate::we_accept!($accept, ep, PEERS_SECOND, ALIAS)
                    .expect("an alias whose subscription had ended was still held");
                still_running(&ep);
            }
        }
    };
}

inbound_subscribe_gates!(
    draft12,
    "draft12",
    0xff00_000c,
    versioned,
    filter_varint,
    expires,
    subscribe_error,
    subscribe_done,
    "4.1"
);
inbound_subscribe_gates!(
    draft13,
    "draft13",
    0xff00_000d,
    versioned,
    filter_type,
    expires,
    subscribe_error,
    subscribe_done,
    "4.1"
);
inbound_subscribe_gates!(
    draft14,
    "draft14",
    0xff00_000e,
    versioned,
    location,
    expires,
    subscribe_error,
    publish_done,
    "5.1"
);
inbound_subscribe_gates!(
    draft15,
    "draft15",
    0,
    alpn,
    bare,
    params,
    request_error,
    publish_done_count,
    "5.1"
);
inbound_subscribe_gates!(draft16, "draft16", 0, alpn, bare, ext, retry, publish_done_count, "5.1");

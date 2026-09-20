#![cfg(any(
    feature = "draft07",
    feature = "draft08",
    feature = "draft09",
    feature = "draft10",
    feature = "draft11",
))]

//! A SUBSCRIBE the peer sends opens a subscription, and this endpoint carries
//! it from arrival to acceptance to the end of the flow.
//!
//! Draft-10 Section 4, with 11 in the same place: "A publisher MUST send
//! exactly one SUBSCRIBE_OK or SUBSCRIBE_ERROR in response to a SUBSCRIBE."
//! Drafts 08 and 09 state it in the same words in Section 4.3, and draft-07
//! Section 5.1 states it in different ones: "The entity receiving the
//! SUBSCRIBE MUST send only a single response to a given SUBSCRIBE of either
//! SUBSCRIBE_OK or SUBSCRIBE_ERROR."
//!
//! What comes after the answer is the rest of the flow: the subscriber ends an
//! accepted subscription with UNSUBSCRIBE and the publisher ends it with
//! SUBSCRIBE_DONE. This endpoint is the publisher of a SUBSCRIBE that arrives,
//! so it sends the answer, receives the UNSUBSCRIBE and sends the
//! SUBSCRIBE_DONE - every message the other way round from a subscription it
//! opened itself.
//!
//! # Why the range is these five
//!
//! They are the drafts where the subscriber chooses the Track Alias: the
//! SUBSCRIBE draws a Track Alias field of its own through draft-11 and
//! draft-12 deletes it. A Track Alias with no subscription behind it is one
//! nothing can ever release, which is why the alias rule in
//! `a_track_alias_names_one_track_at_the_publisher.rs` rests on this flow for
//! these five drafts.
//!
//! # Why none of this closes the session
//!
//! "MUST send exactly one" is addressed to the sender of the answer. This
//! endpoint's job is not to send the second one, so a second answer is refused
//! where it is asked for and the session goes on running. Every gate below
//! checks that, because a refusal that also tore down the session would be a
//! worse bug than the one it was fixing.
//!
//! # Ablations, measured
//!
//! Seven cuts were made, run and reverted, each recorded on the gate it
//! belongs to. Two of them reach past this file: taking the dispatch arm out
//! reddens the loopback gate as well, and answering without moving the record
//! on reddens `an_alias_is_free_once_its_subscription_ends` in the alias file,
//! which is the point of the ordering. An alias whose subscription can never
//! reach Active can never be freed either.

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

/// A SUBSCRIBE from the peer, in the three shapes it takes across the five
/// drafts: draft-07 carries an End Object beside the End Group, and draft-11
/// replaces the start location with a group and object of its own and adds
/// Forward.
#[macro_export]
macro_rules! subscribe_of {
    (end_object, $id:expr, $alias:expr, $track:expr) => {
        Subscribe {
            subscribe_id: $crate::v($id),
            track_alias: $crate::v($alias),
            track_namespace: $crate::namespace(),
            track_name: $track.to_vec(),
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            filter_type: FilterType::LargestObject,
            start_location: None,
            end_group: None,
            end_object: None,
            parameters: Vec::new(),
        }
    };
    (end_group, $id:expr, $alias:expr, $track:expr) => {
        Subscribe {
            subscribe_id: $crate::v($id),
            track_alias: $crate::v($alias),
            track_namespace: $crate::namespace(),
            track_name: $track.to_vec(),
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            filter_type: FilterType::LargestObject,
            start_location: None,
            end_group: None,
            parameters: Vec::new(),
        }
    };
    (forward, $id:expr, $alias:expr, $track:expr) => {
        Subscribe {
            request_id: $crate::v($id),
            track_alias: $crate::v($alias),
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
}

/// The UNSUBSCRIBE the subscribing peer sends, under the name each draft gives
/// the identifier.
#[macro_export]
macro_rules! unsubscribe_of {
    (subscribe_id, $id:expr) => {
        Unsubscribe { subscribe_id: $id }
    };
    (request_id, $id:expr) => {
        Unsubscribe { request_id: $id }
    };
}

/// The setup parameters each draft requires. Draft-07 requires a ROLE of both
/// endpoints and is the only one of the five that does.
#[macro_export]
macro_rules! setup_params {
    (role) => {
        vec![KeyValuePair { key: $crate::v(0x00), value: KvpValue::Varint($crate::v(3)) }]
    };
    (none) => {
        Vec::new()
    };
}

/// One draft's eight gates.
macro_rules! inbound_subscribe_gates {
    ($draft:ident, $feat:literal, $version:expr, $role:path, $unknown:ident, $submsg:tt,
     $unsub:tt, $grant:ident, $params:tt, $peers_first:literal, $never_used:literal,
     $sec:literal) => {
        #[cfg(feature = $feat)]
        mod $draft {
            use moqtap_client::$draft::endpoint::{Endpoint, EndpointError};
            use moqtap_client::$draft::session::state::SessionState;
            use $role as Role;

            #[allow(unused_imports)]
            use moqtap_codec::kvp::{KeyValuePair, KvpValue};
            #[allow(unused_imports)]
            use moqtap_codec::types::*;
            use moqtap_codec::varint::VarInt;
            use moqtap_codec::$draft::message::*;

            /// The peer's first identifier for a request of its own.
            const PEERS_FIRST: u64 = $peers_first;

            /// A second one, for the gates that need two subscriptions.
            const PEERS_SECOND: u64 = $peers_first + 2;

            /// An identifier no SUBSCRIBE ever arrived under.
            const NEVER_USED: u64 = $never_used;

            /// The alias the peer chooses for the track it subscribes to.
            const ALIAS: u64 = 7;

            const ALPHA: &[u8] = b"alpha";

            fn peer_id() -> VarInt {
                VarInt::from_u64(PEERS_FIRST).expect("a small id is a varint")
            }

            /// A client with its session established and a budget granted to
            /// the peer, without which no SUBSCRIBE of the peer's is legal.
            fn active() -> Endpoint {
                let mut ep = Endpoint::new(Role::Client);
                ep.connect().expect("a client may open");
                let _ = ep
                    .send_client_setup(vec![$crate::v($version)], $crate::setup_params!($params))
                    .expect("CLIENT_SETUP");
                ep.receive_server_setup(&ServerSetup {
                    selected_version: $crate::v($version),
                    parameters: $crate::setup_params!($params),
                })
                .expect("SERVER_SETUP");
                let _ = ep.$grant($crate::v(100)).expect("a budget for the peer");
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
                ep.receive_subscribe(&crate::subscribe_of!($submsg, PEERS_FIRST, ALIAS, ALPHA))
                    .expect("the peer's SUBSCRIBE");
                ep
            }

            /// An endpoint that has accepted the peer's SUBSCRIBE.
            fn accepted() -> Endpoint {
                let mut ep = subscribed();
                ep.send_subscribe_ok(peer_id(), $crate::v(0), GroupOrder::Ascending, Vec::new())
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
            /// a SUBSCRIBE is checked for its identifier and then dropped, and
            /// the peer waits for an answer the endpoint has no record to
            /// build one from.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// Removing the `ControlMessage::Subscribe` arm from
            /// `receive_message`:
            ///
            /// ```text
            /// the SUBSCRIBE that arrived on the control stream could not be answered: UnknownSubscribe(0)
            /// ```
            ///
            /// It reddens ten tests: this gate on all five drafts, and the
            /// loopback gate on the same five, where the SUBSCRIBE arrives off
            /// a real QUIC stream and this arm is the only thing that takes it
            /// anywhere.
            #[test]
            fn a_subscribe_off_the_control_stream_reaches_the_flow() {
                let mut ep = active();
                ep.receive_message(ControlMessage::Subscribe(crate::subscribe_of!(
                    $submsg,
                    PEERS_FIRST,
                    ALIAS,
                    ALPHA
                )))
                .expect("the peer's SUBSCRIBE");

                ep.send_subscribe_ok(peer_id(), $crate::v(0), GroupOrder::Ascending, Vec::new())
                    .expect(
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
            /// a SUBSCRIBE_OK was built for a request that never arrived: SubscribeOk(SubscribeOk { subscribe_id: VarInt(9), expires: VarInt(0), group_order: Ascending, content_exists: NoLargestLocation, largest_group_id: None, largest_object_id: None, parameters: [] })
            /// ```
            ///
            /// It reddens ten tests: this gate and the two-subscription gate
            /// below, on all five drafts. Every other gate here has exactly
            /// one subscription outstanding, so a lookup that ignores the
            /// identifier finds the right record by accident.
            #[test]
            fn an_answer_to_a_subscribe_that_never_arrived_is_refused() {
                let mut ep = subscribed();
                let err = ep
                    .send_subscribe_ok(
                        $crate::v(NEVER_USED),
                        $crate::v(0),
                        GroupOrder::Ascending,
                        Vec::new(),
                    )
                    .expect_err("a SUBSCRIBE_OK was built for a request that never arrived");
                assert!(
                    matches!(err, EndpointError::$unknown(NEVER_USED)),
                    "the refusal should name the id nothing arrived under, and named {err:?}"
                );
                still_running(&ep);
            }

            /// A second SUBSCRIBE_OK for one SUBSCRIBE is refused.
            ///
            /// # What it catches
            ///
            /// Building the answer without moving the record on, which is the
            /// shape a publisher with no lifecycle has: every answer looks
            /// like the first one.
            ///
            /// ```text
            /// a second SUBSCRIBE_OK was sent for one SUBSCRIBE: SubscribeOk(SubscribeOk { subscribe_id: VarInt(0), expires: VarInt(0), group_order: Ascending, content_exists: NoLargestLocation, largest_group_id: None, largest_object_id: None, parameters: [] })
            /// ```
            ///
            /// It reddens twenty-five tests: four of the gates here on all
            /// five drafts, and `an_alias_is_free_once_its_subscription_ends`
            /// in the alias file, where a subscription that never reached
            /// Active cannot be ended and so never frees its alias.
            #[test]
            fn a_second_acceptance_is_refused() {
                let mut ep = accepted();
                ep.send_subscribe_ok(peer_id(), $crate::v(0), GroupOrder::Ascending, Vec::new())
                    .expect_err("a second SUBSCRIBE_OK was sent for one SUBSCRIBE");
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
            /// a SUBSCRIBE was accepted after it had been rejected: SubscribeOk(SubscribeOk { subscribe_id: VarInt(0), expires: VarInt(0), group_order: Ascending, content_exists: NoLargestLocation, largest_group_id: None, largest_object_id: None, parameters: [] })
            /// ```
            ///
            /// The cut is the rejection's own, not the acceptance's: leaving
            /// the record where it was when the SUBSCRIBE_ERROR went out
            /// reddens five tests and only this gate. The acceptance has a cut
            /// of its own and it reddens this gate too, which is what two
            /// answers to one question look like.
            #[test]
            fn a_rejected_subscribe_cannot_then_be_accepted() {
                let mut ep = subscribed();
                ep.send_subscribe_error(peer_id(), $crate::v(1), b"no".to_vec(), $crate::v(ALIAS))
                    .expect("reject the subscription");

                ep.send_subscribe_ok(peer_id(), $crate::v(0), GroupOrder::Ascending, Vec::new())
                    .expect_err("a SUBSCRIBE was accepted after it had been rejected");
                still_running(&ep);
            }

            /// A subscription that has not been accepted cannot be ended with
            /// SUBSCRIBE_DONE.
            ///
            /// SUBSCRIBE_DONE ends a subscription that is running; one still
            /// waiting for its answer is refused with SUBSCRIBE_ERROR
            /// instead, which is a different message and a different state.
            ///
            /// # What it catches
            ///
            /// Discarding what the record says when the SUBSCRIBE_DONE is
            /// built, so that it ends a subscription from any state rather
            /// than from the one the subscription exists in:
            ///
            /// ```text
            /// a subscription this endpoint had not accepted was ended: SubscribeDone(SubscribeDone { subscribe_id: VarInt(0), status_code: VarInt(0), reason_phrase: [], content_exists: NoLargestLocation, final_group: None, final_object: None })
            /// ```
            ///
            /// It reddens ten tests: this gate and the publisher's-end gate
            /// below, on all five drafts.
            #[test]
            fn an_unanswered_subscribe_cannot_be_ended() {
                let mut ep = subscribed();
                let err = ep
                    .send_subscribe_done(peer_id(), $crate::v(0), Vec::new())
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
            /// It reddens five tests and no others: this gate, on all five
            /// drafts. Nothing else here needs an UNSUBSCRIBE to arrive off
            /// the control stream.
            #[test]
            fn an_accepted_subscribe_is_ended_by_unsubscribe() {
                let mut ep = accepted();
                ep.receive_message(ControlMessage::Unsubscribe(crate::unsubscribe_of!(
                    $unsub,
                    peer_id()
                )))
                .expect("the peer's UNSUBSCRIBE");

                ep.receive_unsubscribe(&crate::unsubscribe_of!($unsub, peer_id())).expect_err(
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
            /// Building the SUBSCRIBE_DONE without moving the record on:
            ///
            /// ```text
            /// a subscription this endpoint had already ended was unsubscribed: ()
            /// ```
            ///
            /// The subscriber's route into the same record is a different
            /// probe in a different method, and cutting either one leaves the
            /// other's gate green.
            #[test]
            fn an_accepted_subscribe_is_ended_by_the_publisher() {
                let mut ep = accepted();
                ep.send_subscribe_done(peer_id(), $crate::v(0), Vec::new())
                    .expect("the publisher could not end the subscription it accepted");

                ep.receive_unsubscribe(&crate::unsubscribe_of!($unsub, peer_id()))
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
            /// the first subscription could not be accepted: UnknownSubscribe(0)
            /// ```
            ///
            /// Made by clearing the map before each insert, which is what one
            /// record for the whole session amounts to. It reddens five tests
            /// and only this gate: the first subscription is the one that goes
            /// missing, so the failure names it rather than the second.
            #[test]
            fn two_subscriptions_from_the_peer_are_answered_apart() {
                let mut ep = subscribed();
                ep.receive_subscribe(&crate::subscribe_of!(
                    $submsg,
                    PEERS_SECOND,
                    ALIAS + 1,
                    b"beta"
                ))
                .expect("the peer's second SUBSCRIBE");

                ep.send_subscribe_ok(peer_id(), $crate::v(0), GroupOrder::Ascending, Vec::new())
                    .expect("the first subscription could not be accepted");
                ep.send_subscribe_ok(
                    $crate::v(PEERS_SECOND),
                    $crate::v(0),
                    GroupOrder::Ascending,
                    Vec::new(),
                )
                .expect("the second subscription could not be accepted");
                still_running(&ep);
            }
        }
    };
}

inbound_subscribe_gates!(
    draft07,
    "draft07",
    0xff00_0007,
    moqtap_client::draft07::endpoint::Role,
    UnknownSubscribe,
    end_object,
    subscribe_id,
    send_max_subscribe_id,
    role,
    0,
    9,
    "5.1"
);
inbound_subscribe_gates!(
    draft08,
    "draft08",
    0xff00_0008,
    moqtap_client::draft08::endpoint::Role,
    UnknownSubscribe,
    end_group,
    subscribe_id,
    send_max_subscribe_id,
    none,
    0,
    9,
    "4.3"
);
inbound_subscribe_gates!(
    draft09,
    "draft09",
    0xff00_0009,
    moqtap_client::draft09::endpoint::Role,
    UnknownSubscribe,
    end_group,
    subscribe_id,
    send_max_subscribe_id,
    none,
    0,
    9,
    "4.3"
);
inbound_subscribe_gates!(
    draft10,
    "draft10",
    0xff00_000a,
    moqtap_client::draft10::endpoint::Role,
    UnknownSubscribe,
    end_group,
    subscribe_id,
    send_max_subscribe_id,
    none,
    0,
    9,
    "4"
);
inbound_subscribe_gates!(
    draft11,
    "draft11",
    0xff00_000b,
    moqtap_client::draft11::session::request_id::Role,
    UnknownRequest,
    forward,
    request_id,
    send_max_request_id,
    none,
    1,
    9,
    "4"
);

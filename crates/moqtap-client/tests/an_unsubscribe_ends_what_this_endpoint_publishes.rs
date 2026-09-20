#![cfg(any(
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
))]

//! An UNSUBSCRIBE ends a subscription this endpoint publishes, whichever of
//! the two sequences opened it.
//!
//! Draft-12 Section 8.11, and draft-13 in the same words: "A subscriber issues
//! a UNSUBSCRIBE message to a publisher indicating it is no longer interested
//! in receiving media for the specified track and requesting that the
//! publisher stop sending Objects as soon as possible." Draft-14 Section 9.11,
//! and drafts 15 and 16 in Section 9.12: "A Subscriber issues an UNSUBSCRIBE
//! message to a Publisher indicating it is no longer interested in receiving
//! the specified Track, indicating that the Publisher stop sending Objects as
//! soon as possible."
//!
//! The message travels one way, from the subscriber to the publisher, so what
//! it can end is whatever this endpoint publishes. Draft-12 Section 4.1, and
//! draft-14 Section 5.1 in the same words, say there are two of those: "A
//! subscription can be initiated by either a publisher or a subscriber. ...
//! Once either of these sequences is successful, the subscription can be
//! updated by the subscriber using SUBSCRIBE_UPDATE, terminated by the
//! subscriber using UNSUBSCRIBE, or terminated by the publisher using
//! SUBSCRIBE_DONE." Draft-14 writes PUBLISH_DONE for that last one.
//!
//! Drafts 15 and 16 say it in one line each, and not the same line. Draft-15
//! Section 5.1: "The subscriber terminates a subscription using UNSUBSCRIBE,
//! the publisher terminates a subscription using PUBLISH_DONE." Draft-16 adds
//! the states it may be done from: "The subscriber terminates a subscription
//! in the Pending (Subscriber) or Established states using UNSUBSCRIBE, the
//! publisher terminates a subscription in the Pending (Publisher) or
//! Established states using PUBLISH_DONE." Those qualifiers are what drafts
//! 17, 18 and 19 keep when they drop the message, which is worth seeing here
//! rather than in the range below: the states outlived the message that named
//! them.
//!
//! # Which offers this endpoint publishes
//!
//! Only the ones it made itself. A PUBLISH the peer sent opens a subscription
//! this endpoint *subscribes* to, so an UNSUBSCRIBE naming one of those is the
//! publisher trying to end a subscription both sentences give the subscriber.
//! That identifier names something, and it still gets `UnknownRequest`,
//! because what it names is not a subscription this endpoint publishes.
//!
//! Drafts 12 and 13 keep the two directions in two records and the question
//! answers itself. Drafts 14, 15 and 16 keep both in one map keyed by Request
//! ID, and there the offer's own message is what tells them apart: one the
//! peer made was written down when it arrived and one of this endpoint's never
//! was.
//!
//! # Why drafts 17, 18 and 19 are not here
//!
//! They have no UNSUBSCRIBE. Section 5.1 on all three: "The subscriber
//! terminates a subscription in the Pending (Subscriber) or Established states
//! by sending STOP_SENDING." That is draft-16's sentence with the message
//! swapped and the states kept, so the subscriber ends it on the stream
//! instead: there is no message for this rule to arrive as and no handler for
//! one.
//!
//! # Ablations, measured
//!
//! Six cuts were made, run against the two crates a change to
//! `moqtap-client` can reach, and reverted. Each of the five drafts
//! carries the change in one of two shapes, so each claim is cut twice
//! rather than once: one shared check needs one ablation per caller.

#![allow(clippy::items_after_test_module)]

use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;

/// The namespace every track here lives in, so the name is the only thing
/// telling two tracks apart.
fn namespace() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec()])
}

fn v(n: u64) -> VarInt {
    VarInt::from_u64(n).unwrap()
}

/// SETUP, in the two shapes the five drafts take.
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
}

/// This endpoint's own PUBLISH, in the three shapes the call takes.
#[macro_export]
macro_rules! we_publish {
    (rich, $ep:expr, $track:expr, $alias:expr) => {
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
    (params, $ep:expr, $track:expr, $alias:expr) => {
        $ep.publish($crate::namespace(), $track.to_vec(), $crate::v($alias), Vec::new())
    };
    (ext, $ep:expr, $track:expr, $alias:expr) => {
        $ep.publish($crate::namespace(), $track.to_vec(), $crate::v($alias), Vec::new(), Vec::new())
    };
}

/// The peer accepting an offer of this endpoint's, in the four shapes
/// PUBLISH_OK takes.
#[macro_export]
macro_rules! peer_accepts {
    (varint, $ep:expr, $id:expr) => {
        $ep.receive_publish_ok(&PublishOk {
            request_id: $id,
            forward: Forward::Forward,
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            filter_type: $crate::v(0x2),
            start_group: None,
            start_object: None,
            end_group: None,
            parameters: Vec::new(),
        })
    };
    (filter, $ep:expr, $id:expr) => {
        $ep.receive_publish_ok(&PublishOk {
            request_id: $id,
            forward: Forward::Forward,
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            filter_type: FilterType::LargestObject,
            start_group: None,
            start_object: None,
            end_group: None,
            parameters: Vec::new(),
        })
    };
    (location, $ep:expr, $id:expr) => {
        $ep.receive_publish_ok(&PublishOk {
            request_id: $id,
            forward: Forward::Forward,
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            filter_type: FilterType::LargestObject,
            start_location: None,
            end_group: None,
            parameters: Vec::new(),
        })
    };
    (params, $ep:expr, $id:expr) => {
        $ep.receive_publish_ok(&PublishOk { request_id: $id, parameters: Vec::new() })
    };
}

/// A PUBLISH the peer sends, offering `$track` under `$alias`.
#[macro_export]
macro_rules! peer_publishes {
    (rich, $id:expr, $track:expr, $alias:expr) => {
        Publish {
            request_id: $crate::v($id),
            track_namespace: $crate::namespace(),
            track_name: $track.to_vec(),
            track_alias: $crate::v($alias),
            group_order: GroupOrder::Ascending,
            content_exists: ContentExists::NoLargestLocation,
            largest_location: None,
            forward: Forward::Forward,
            parameters: Vec::new(),
        }
    };
    (plain, $id:expr, $track:expr, $alias:expr) => {
        Publish {
            request_id: $crate::v($id),
            track_namespace: $crate::namespace(),
            track_name: $track.to_vec(),
            track_alias: $crate::v($alias),
            parameters: Vec::new(),
        }
    };
    (ext, $id:expr, $track:expr, $alias:expr) => {
        Publish {
            request_id: $crate::v($id),
            track_namespace: $crate::namespace(),
            track_name: $track.to_vec(),
            track_alias: $crate::v($alias),
            parameters: Vec::new(),
            track_extensions: Vec::new(),
        }
    };
}

/// This endpoint accepting the peer's offer, in the shapes PUBLISH_OK takes on
/// the sending side.
#[macro_export]
macro_rules! we_accept {
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
}

/// This endpoint, as publisher, ending a subscription. Drafts 12 and 13 call
/// the message SUBSCRIBE_DONE and 14, 15 and 16 call it PUBLISH_DONE.
#[macro_export]
macro_rules! we_end {
    (subscribe_done, $ep:expr, $id:expr) => {
        $ep.send_subscribe_done($id, $crate::v(0), $crate::v(0), Vec::new()).map(|_| ())
    };
    (publish_done_3, $ep:expr, $id:expr) => {
        $ep.send_publish_done($id, $crate::v(0), Vec::new()).map(|_| ())
    };
    (publish_done_4, $ep:expr, $id:expr) => {
        $ep.send_publish_done($id, $crate::v(0), $crate::v(0), Vec::new()).map(|_| ())
    };
}

/// One draft's gates.
macro_rules! unsubscribe_gates {
    ($draft:ident, $feat:literal, $version:expr, $setup:tt, $ours:tt, $ok:tt,
     $theirs:tt, $accept:tt, $end:tt, $sec:literal) => {
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
            #[allow(unused_imports)]
            use moqtap_codec::$draft::message::*;

            /// The first Request ID this endpoint spends: even, as the client.
            const OURS: u64 = 0;

            /// The peer's first: odd, for the same reason.
            const THEIRS: u64 = 1;

            /// An identifier this session opened nothing under.
            const NEVER_USED: u64 = 9;

            const ALIAS: u64 = 7;
            const ALPHA: &[u8] = b"alpha";
            const BETA: &[u8] = b"beta";

            fn ours() -> VarInt {
                VarInt::from_u64(OURS).expect("a small id is a varint")
            }

            fn theirs() -> VarInt {
                VarInt::from_u64(THEIRS).expect("a small id is a varint")
            }

            /// A client with its session established and a budget to spend.
            fn active() -> Endpoint {
                let mut ep = Endpoint::new(Role::Client);
                ep.connect().expect("a client may open");
                crate::setup_for!($setup, ep, $version);
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "the gates need a running session"
                );
                ep
            }

            /// An endpoint whose own offer of ALPHA the peer has accepted.
            fn publishing() -> Endpoint {
                let mut ep = active();
                let (id, _) = crate::we_publish!($ours, ep, ALPHA, ALIAS).expect("our offer");
                assert_eq!(id, ours(), "the offer spends this endpoint's first id");
                crate::peer_accepts!($ok, ep, ours()).expect("the peer accepts it");
                ep
            }

            /// The peer's UNSUBSCRIBE for the subscription opened under `id`.
            fn unsubscribe(ep: &mut Endpoint, id: VarInt) -> Result<(), EndpointError> {
                ep.receive_unsubscribe(&Unsubscribe { request_id: id })
            }

            /// The session is still running: nothing here is answered by
            /// ending it.
            fn still_running(ep: &Endpoint) {
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "Section {} gives the subscriber a message, not the endpoint a reason \
                     to close",
                    $sec
                );
            }

            /// The subscriber can end a subscription this endpoint offered.
            ///
            /// # What it catches
            ///
            /// Leaving `receive_unsubscribe` looking only at the subscriptions the
            /// peer opened with SUBSCRIBE. On 12 and 13 that is one branch:
            ///
            /// ```text
            /// the subscriber may end a subscription this endpoint publishes:
            /// UnknownRequest(0)
            /// ```
            ///
            /// It reddens twelve, on drafts 12 and 13: six of the gates here.
            ///
            /// The same claim on 14, 15 and 16, where the branch has to say whose
            /// offer it is before it can take one:
            ///
            /// ```text
            /// the subscriber may end a subscription this endpoint publishes:
            /// UnknownRequest(0)
            /// ```
            ///
            /// It reddens eighteen, on drafts 14 through 16: six of the gates here.
            #[test]
            fn an_unsubscribe_ends_a_subscription_this_endpoint_offered() {
                let mut ep = publishing();
                unsubscribe(&mut ep, ours())
                    .expect("the subscriber may end a subscription this endpoint publishes");
                still_running(&ep);
            }

            /// It ends once. A second UNSUBSCRIBE names a subscription that is
            /// already over.
            ///
            /// # What it catches
            ///
            /// Leaving `receive_unsubscribe` looking only at the subscriptions the
            /// peer opened with SUBSCRIBE. On 12 and 13 that is one branch:
            ///
            /// ```text
            /// the first UNSUBSCRIBE: UnknownRequest(0)
            /// ```
            ///
            /// It reddens twelve, on drafts 12 and 13: six of the gates here.
            ///
            /// The same claim on 14, 15 and 16, where the branch has to say whose
            /// offer it is before it can take one:
            ///
            /// ```text
            /// the first UNSUBSCRIBE: UnknownRequest(0)
            /// ```
            ///
            /// It reddens eighteen, on drafts 14 through 16: six of the gates here.
            ///
            /// Ending the subscription by assignment rather than by transition, so
            /// a state with no ending to give gives one anyway:
            ///
            /// ```text
            /// the subscription was already over, and instead: Ok(())
            /// ```
            ///
            /// It reddens four, on drafts 12 and 13: two of the gates here.
            ///
            /// The same on 14, 15 and 16, where the ending is an alias over the
            /// shared step and the cut swallows its refusal:
            ///
            /// ```text
            /// the subscription was already over, and instead: Ok(())
            /// ```
            ///
            /// It reddens six, on drafts 14 through 16: two of the gates here.
            #[test]
            fn a_subscription_is_ended_by_one_unsubscribe() {
                let mut ep = publishing();
                unsubscribe(&mut ep, ours()).expect("the first UNSUBSCRIBE");
                let again = unsubscribe(&mut ep, ours());
                assert!(
                    matches!(again, Err(EndpointError::PublishFlow(_))),
                    "the subscription was already over, and instead: {again:?}"
                );
                still_running(&ep);
            }

            /// The publisher cannot end what the subscriber has already ended.
            ///
            /// # What it catches
            ///
            /// Leaving `receive_unsubscribe` looking only at the subscriptions the
            /// peer opened with SUBSCRIBE. On 12 and 13 that is one branch:
            ///
            /// ```text
            /// the subscriber ends it: UnknownRequest(0)
            /// ```
            ///
            /// It reddens twelve, on drafts 12 and 13: six of the gates here.
            ///
            /// The same claim on 14, 15 and 16, where the branch has to say whose
            /// offer it is before it can take one:
            ///
            /// ```text
            /// the subscriber ends it: UnknownRequest(0)
            /// ```
            ///
            /// It reddens eighteen, on drafts 14 through 16: six of the gates here.
            #[test]
            fn an_ended_subscription_is_not_ended_again_by_its_publisher() {
                let mut ep = publishing();
                unsubscribe(&mut ep, ours()).expect("the subscriber ends it");
                let late = crate::we_end!($end, ep, ours());
                assert!(
                    matches!(late, Err(EndpointError::PublishFlow(_))),
                    "there is nothing left for the publisher to end, and instead: {late:?}"
                );
                still_running(&ep);
            }

            /// The Track Alias the subscription held is free once it ends.
            ///
            /// # What it catches
            ///
            /// Leaving `receive_unsubscribe` looking only at the subscriptions the
            /// peer opened with SUBSCRIBE. On 12 and 13 that is one branch:
            ///
            /// ```text
            /// the subscriber ends it: UnknownRequest(0)
            /// ```
            ///
            /// It reddens twelve, on drafts 12 and 13: six of the gates here.
            ///
            /// The same claim on 14, 15 and 16, where the branch has to say whose
            /// offer it is before it can take one:
            ///
            /// ```text
            /// the subscriber ends it: UnknownRequest(0)
            /// ```
            ///
            /// It reddens eighteen, on drafts 14 through 16: six of the gates here.
            #[test]
            fn the_alias_of_an_unsubscribed_offer_is_free() {
                let mut ep = publishing();
                let held = crate::we_publish!($ours, ep, BETA, ALIAS);
                assert!(
                    matches!(held, Err(EndpointError::TrackAliasInUse { .. })),
                    "a live subscription is holding the alias, and instead: {held:?}"
                );

                unsubscribe(&mut ep, ours()).expect("the subscriber ends it");
                let freed = crate::we_publish!($ours, ep, BETA, ALIAS);
                assert!(
                    freed.is_ok(),
                    "an ended subscription holds nothing simultaneously with anything, \
                     and instead: {freed:?}"
                );
                still_running(&ep);
            }

            /// An offer that has not been accepted yet is not a subscription
            /// for the subscriber to end.
            ///
            /// # What it catches
            ///
            /// Leaving `receive_unsubscribe` looking only at the subscriptions the
            /// peer opened with SUBSCRIBE. On 12 and 13 that is one branch:
            ///
            /// ```text
            /// the sentence names a subscription, and an unanswered offer is not
            /// one yet; instead: Err(UnknownRequest(0))
            /// ```
            ///
            /// It reddens twelve, on drafts 12 and 13: six of the gates here.
            ///
            /// The same claim on 14, 15 and 16, where the branch has to say whose
            /// offer it is before it can take one:
            ///
            /// ```text
            /// the sentence names a subscription, and an unanswered offer is not
            /// one yet; instead: Err(UnknownRequest(0))
            /// ```
            ///
            /// It reddens eighteen, on drafts 14 through 16: six of the gates here.
            ///
            /// Ending the subscription by assignment rather than by transition, so
            /// a state with no ending to give gives one anyway:
            ///
            /// ```text
            /// the sentence names a subscription, and an unanswered offer is not
            /// one yet; instead: Ok(()) failures:
            /// draft12::a_subscription_is_ended_by_one_unsubscribe
            /// draft12::an_unanswered_offer_cannot_be_unsubscribed
            /// draft13::a_subscription_is_
            /// ```
            ///
            /// It reddens four, on drafts 12 and 13: two of the gates here.
            ///
            /// The same on 14, 15 and 16, where the ending is an alias over the
            /// shared step and the cut swallows its refusal:
            ///
            /// ```text
            /// the sentence names a subscription, and an unanswered offer is not
            /// one yet; instead: Ok(())
            /// ```
            ///
            /// It reddens six, on drafts 14 through 16: two of the gates here.
            #[test]
            fn an_unanswered_offer_cannot_be_unsubscribed() {
                let mut ep = active();
                let (id, _) = crate::we_publish!($ours, ep, ALPHA, ALIAS).expect("our offer");
                let early = unsubscribe(&mut ep, id);
                assert!(
                    matches!(early, Err(EndpointError::PublishFlow(_))),
                    "the sentence names a subscription, and an unanswered offer is not one \
                     yet; instead: {early:?}"
                );
                still_running(&ep);
            }

            /// An UNSUBSCRIBE naming the peer's own offer names nothing this
            /// endpoint publishes.
            ///
            /// This endpoint is the subscriber of that one, so the peer
            /// sending UNSUBSCRIBE for it is the publisher using the
            /// subscriber's message. The identifier names a live subscription
            /// and is still refused, which is the whole of what this gate
            /// says.
            ///
            /// # What it catches
            ///
            /// Letting the branch reach the peer's own offers too, so the publisher
            /// can end a subscription with the subscriber's message:
            ///
            /// ```text
            /// an offer the peer made is not one this endpoint publishes, and
            /// instead: Ok(())
            /// ```
            ///
            /// It reddens two, this gate on drafts 12 and 13 and nothing else.
            ///
            /// Dropping the test that says whose offer it is, which on these three
            /// is the only thing separating the two directions held in one map:
            ///
            /// ```text
            /// an offer the peer made is not one this endpoint publishes, and
            /// instead: Ok(())
            /// ```
            ///
            /// It reddens three, this gate on drafts 14 through 16 and nothing
            /// else.
            #[test]
            fn an_unsubscribe_naming_the_peers_own_offer_is_refused() {
                let mut ep = active();
                ep.receive_publish(&crate::peer_publishes!($theirs, THEIRS, BETA, ALIAS + 1))
                    .expect("the peer's PUBLISH");
                crate::we_accept!($accept, ep, theirs()).expect("this endpoint accepts it");

                let crossed = unsubscribe(&mut ep, theirs());
                assert!(
                    matches!(crossed, Err(EndpointError::UnknownRequest(THEIRS))),
                    "an offer the peer made is not one this endpoint publishes, \
                     and instead: {crossed:?}"
                );
                still_running(&ep);
            }

            /// An UNSUBSCRIBE naming nothing at all is refused.
            /// # What it catches
            ///
            /// Nothing that the six cuts reach. Every one of them leaves
            /// it green, because an identifier that names nothing is refused
            /// by the lookup that was already here and none of them touches
            /// it. It is kept as the control for the gate above: both assert
            /// `UnknownRequest`, and without this one there would be no
            /// evidence that the endpoint can still produce that answer for an
            /// identifier naming nothing at all, rather than only for one
            /// naming an offer it declines to end.
            #[test]
            fn an_unsubscribe_naming_nothing_is_refused() {
                let mut ep = publishing();
                let stray = unsubscribe(&mut ep, crate::v(NEVER_USED));
                assert!(
                    matches!(stray, Err(EndpointError::UnknownRequest(NEVER_USED))),
                    "no subscription was opened under that identifier, and instead: {stray:?}"
                );
                still_running(&ep);
            }

            /// An UNSUBSCRIBE arriving the way the control stream delivers one
            /// reaches the flow that ends the subscription.
            ///
            /// # What it catches
            ///
            /// Leaving `receive_unsubscribe` looking only at the subscriptions the
            /// peer opened with SUBSCRIBE. On 12 and 13 that is one branch:
            ///
            /// ```text
            /// the peer's UNSUBSCRIBE: UnknownRequest(0)
            /// ```
            ///
            /// It reddens twelve, on drafts 12 and 13: six of the gates here.
            ///
            /// The same claim on 14, 15 and 16, where the branch has to say whose
            /// offer it is before it can take one:
            ///
            /// ```text
            /// the peer's UNSUBSCRIBE: UnknownRequest(0)
            /// ```
            ///
            /// It reddens eighteen, on drafts 14 through 16: six of the gates here.
            #[test]
            fn an_unsubscribe_off_the_control_stream_reaches_the_flow() {
                let mut ep = publishing();
                ep.receive_message(ControlMessage::Unsubscribe(Unsubscribe { request_id: ours() }))
                    .expect("the peer's UNSUBSCRIBE");

                let freed = crate::we_publish!($ours, ep, BETA, ALIAS);
                assert!(
                    freed.is_ok(),
                    "the UNSUBSCRIBE that arrived on the control stream ended nothing, \
                     and instead: {freed:?}"
                );
                still_running(&ep);
            }
        }
    };
}

unsubscribe_gates!(
    draft12,
    "draft12",
    0xff00_000c,
    versioned,
    rich,
    varint,
    rich,
    varint,
    subscribe_done,
    "8.11"
);
unsubscribe_gates!(
    draft13,
    "draft13",
    0xff00_000d,
    versioned,
    rich,
    filter,
    rich,
    filter,
    subscribe_done,
    "8.11"
);
unsubscribe_gates!(
    draft14,
    "draft14",
    0xff00_000e,
    versioned,
    rich,
    location,
    rich,
    location,
    publish_done_3,
    "9.11"
);
unsubscribe_gates!(
    draft15,
    "draft15",
    0,
    alpn,
    params,
    params,
    plain,
    params,
    publish_done_4,
    "9.12"
);
unsubscribe_gates!(draft16, "draft16", 0, alpn, ext, params, ext, params, publish_done_4, "9.12");

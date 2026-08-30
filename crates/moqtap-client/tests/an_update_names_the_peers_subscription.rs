#![cfg(any(
    feature = "draft07",
    feature = "draft08",
    feature = "draft09",
    feature = "draft10",
    feature = "draft11",
))]

//! A SUBSCRIBE_UPDATE that arrives is about a subscription the peer opened,
//! never about one this endpoint opened itself.
//!
//! Draft-11 Section 8.10, and drafts 07 through 10 in their own SUBSCRIBE_UPDATE
//! sections: "A subscriber issues a SUBSCRIBE_UPDATE to a publisher to request
//! a change to an existing subscription." The endpoint receiving one is the
//! publisher, so the subscription it names is one the peer opened - and the
//! record that holds those is not the record that holds this endpoint's own.
//!
//! # What was here before
//!
//! The update was looked for among the subscriptions this endpoint had opened,
//! on every draft. On these five that is worse than a miss: they have no
//! parity rule, both ends allocate identifiers from zero, and the peer's
//! subscribe 3 and this endpoint's subscribe 3 are two different
//! subscriptions. An update for the peer's found this endpoint's and moved it.
//!
//! # Why none of this closes the session
//!
//! These five say **SHOULD**: "A publisher SHOULD close the Session as a
//! 'Protocol Violation' if the SUBSCRIBE_UPDATE violates either rule or if the
//! subscriber specifies a Subscribe ID that has not existed within the
//! Session." Draft-11 says the same with Request ID in place of Subscribe ID.
//! A SHOULD is not a rule this crate may impose on its caller, so the update is
//! refused, the identifier is named, and the session goes on running. From
//! draft-12 the same sentence says MUST and the session ends;
//! `an_update_for_an_unknown_request_ends_the_session.rs` is that half.
//!
//! # Ablations, measured
//!
//! Four cuts were made, run and reverted, each recorded on the gate it belongs
//! to. Three of them are shared with the drafts 12 through 16 file, because the
//! probe, the record's lifetime and the outbound builder are one claim each
//! across all ten drafts; what is not shared is the answer, and the two cuts
//! that measure that live in the other file.

#![allow(clippy::items_after_test_module)]

use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;

/// The namespace both tracks live in.
fn namespace() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec()])
}

fn v(n: u64) -> VarInt {
    VarInt::from_u64(n).unwrap()
}

/// A SUBSCRIBE from the peer, in the three shapes it takes across the five
/// drafts.
#[macro_export]
macro_rules! peers_subscribe {
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

/// The SUBSCRIBE_UPDATE the subscribing peer sends: draft-07 carries an End
/// Object beside the End Group, and draft-11 adds Forward and renames the
/// identifier.
#[macro_export]
macro_rules! peers_update {
    (end_object, $id:expr) => {
        SubscribeUpdate {
            subscribe_id: $crate::v($id),
            start_group: $crate::v(0),
            start_object: $crate::v(0),
            end_group: $crate::v(0),
            end_object: $crate::v(0),
            subscriber_priority: 128,
            parameters: Vec::new(),
        }
    };
    (end_group, $id:expr) => {
        SubscribeUpdate {
            subscribe_id: $crate::v($id),
            start_group: $crate::v(0),
            start_object: $crate::v(0),
            end_group: $crate::v(0),
            subscriber_priority: 128,
            parameters: Vec::new(),
        }
    };
    (forward, $id:expr) => {
        SubscribeUpdate {
            request_id: $crate::v($id),
            start_group: $crate::v(0),
            start_object: $crate::v(0),
            end_group: $crate::v(0),
            subscriber_priority: 128,
            forward: Forward::Forward,
            parameters: Vec::new(),
        }
    };
}

/// The update this endpoint builds for a subscription of its own.
#[macro_export]
macro_rules! we_update {
    (end_object, $ep:expr, $id:expr) => {
        $ep.subscribe_update(
            $id,
            $crate::v(0),
            $crate::v(0),
            $crate::v(0),
            $crate::v(0),
            128,
            Vec::new(),
        )
    };
    (end_group, $ep:expr, $id:expr) => {
        $ep.subscribe_update($id, $crate::v(0), $crate::v(0), $crate::v(0), 128, Vec::new())
    };
    (forward, $ep:expr, $id:expr) => {
        $ep.subscribe_update(
            $id,
            $crate::v(0),
            $crate::v(0),
            $crate::v(0),
            128,
            Forward::Forward,
            Vec::new(),
        )
    };
}

/// The SUBSCRIBE_OK the peer answers this endpoint's own SUBSCRIBE with, which
/// is what puts the subscription in a state UNSUBSCRIBE may end.
#[macro_export]
macro_rules! peers_ok {
    (end_object, $id:expr) => {
        SubscribeOk {
            subscribe_id: $id,
            expires: $crate::v(0),
            group_order: GroupOrder::Ascending,
            content_exists: ContentExists::NoLargestLocation,
            largest_group_id: None,
            largest_object_id: None,
            parameters: Vec::new(),
        }
    };
    (end_group, $id:expr) => {
        SubscribeOk {
            subscribe_id: $id,
            expires: $crate::v(0),
            group_order: GroupOrder::Ascending,
            content_exists: ContentExists::NoLargestLocation,
            largest_group_id: None,
            largest_object_id: None,
            parameters: Vec::new(),
        }
    };
    (forward, $id:expr) => {
        SubscribeOk {
            request_id: $id,
            expires: $crate::v(0),
            group_order: GroupOrder::Ascending,
            content_exists: ContentExists::NoLargestLocation,
            largest_location: None,
            parameters: Vec::new(),
        }
    };
}

/// This endpoint's own SUBSCRIBE, whose filter is a named type up to draft-10
/// and a raw varint on draft-11.
#[macro_export]
macro_rules! we_subscribe {
    (named, $ep:expr, $alias:expr, $track:expr) => {
        $ep.subscribe(
            $crate::v($alias),
            $crate::namespace(),
            $track.to_vec(),
            128,
            GroupOrder::Ascending,
            FilterType::LargestObject,
        )
    };
    (varint, $ep:expr, $alias:expr, $track:expr) => {
        $ep.subscribe(
            $crate::v($alias),
            $crate::namespace(),
            $track.to_vec(),
            128,
            GroupOrder::Ascending,
            $crate::v(0x2),
        )
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

/// The same, plus the ceiling the peer must grant before this endpoint may
/// open a subscription of its own. Half these gates need one.
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

/// One draft's seven gates.
macro_rules! update_gates {
    ($draft:ident, $feat:literal, $version:expr, $role:path, $unknown:ident, $submsg:tt,
     $updmsg:tt, $oursub:tt, $grant:ident, $params:tt, $peers_first:literal, $sec:literal) => {
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

            /// An identifier no SUBSCRIBE ever arrived under.
            const NEVER_USED: u64 = 9;

            const ALIAS: u64 = 7;
            const OUR_ALIAS: u64 = 8;

            const ALPHA: &[u8] = b"alpha";
            const BETA: &[u8] = b"beta";

            fn peer_id() -> VarInt {
                VarInt::from_u64(PEERS_FIRST).expect("a small id is a varint")
            }

            /// A client with its session established and a budget granted to
            /// the peer.
            fn active() -> Endpoint {
                let mut ep = Endpoint::new(Role::Client);
                ep.connect().expect("a client may open");
                let _ = ep
                    .send_client_setup(vec![$crate::v($version)], $crate::setup_params!($params))
                    .expect("CLIENT_SETUP");
                ep.receive_server_setup(&ServerSetup {
                    selected_version: $crate::v($version),
                    parameters: $crate::server_params!($params),
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

            /// An endpoint publishing a track the peer subscribed to.
            fn publishing() -> Endpoint {
                let mut ep = active();
                ep.receive_subscribe(&crate::peers_subscribe!($submsg, PEERS_FIRST, ALIAS, ALPHA))
                    .expect("the peer's SUBSCRIBE");
                ep.send_subscribe_ok(peer_id(), $crate::v(0), GroupOrder::Ascending, Vec::new())
                    .expect("accept the subscription");
                ep
            }

            /// The session is still running. Every rule in this file is a
            /// SHOULD, and a SHOULD is not this crate's to impose.
            fn still_running(ep: &Endpoint) {
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "Section {} says a publisher SHOULD close over this, so the crate \
                     reports it and leaves the session to its caller",
                    $sec
                );
            }

            /// The peer updates the subscription it opened, and it is
            /// accepted.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// Looking the update up among the subscriptions this endpoint
            /// opened, which is what every draft used to do:
            ///
            /// ```text
            /// the peer's update of its own subscription: UpdateForUnknownSubscribe(0)
            /// ```
            ///
            /// It reddens forty-eight tests across both update files and the draft-14
            /// dispatch test: every gate that puts a legal update through the endpoint
            /// reads it out of that one probe.
            #[test]
            fn an_update_for_the_peers_subscription_is_accepted() {
                let mut ep = publishing();
                ep.receive_subscribe_update(&crate::peers_update!($updmsg, PEERS_FIRST))
                    .expect("the peer's update of its own subscription");
                still_running(&ep);
            }

            /// An update naming a subscription **this endpoint** opened is
            /// refused.
            ///
            /// The identifier is a live subscription's, and on these drafts it
            /// can be numerically the same as the peer's: neither end's
            /// sequence is set apart from the other's. What decides the answer
            /// is which record the identifier is looked for in.
            ///
            /// # What it catches
            ///
            /// The same cut as the gate above, from the other side: a lookup
            /// in this endpoint's own map accepts this and it must not.
            ///
            /// ```text
            /// an update moved a subscription this endpoint had opened: ()
            /// ```
            ///
            /// The same cut as the gate above, and this is the half of it only these
            /// five drafts can show: with no parity rule the identifier is a live
            /// subscription's either way, so the wrong probe does not miss - it
            /// succeeds on the wrong record.
            #[test]
            fn an_update_for_our_own_subscription_is_refused() {
                let mut ep = active();
                let (ours, _) = crate::we_subscribe!($oursub, ep, OUR_ALIAS, BETA)
                    .expect("this endpoint's own SUBSCRIBE");

                let err = ep
                    .receive_subscribe_update(&crate::peers_update!(
                        $updmsg,
                        ours.into_inner()
                    ))
                    .expect_err("an update moved a subscription this endpoint had opened");
                assert!(
                    matches!(err, EndpointError::$unknown(id) if id == ours.into_inner()),
                    "the refusal should name the identifier, and named {err:?}"
                );
                assert_eq!(
                    err.session_error_code(),
                    None,
                    "Section {} says SHOULD, so the refusal carries no close code",
                    $sec
                );
                still_running(&ep);
            }

            /// An update naming an identifier no subscription has ever had is
            /// refused.
            #[test]
            fn an_update_for_an_identifier_nothing_opened_is_refused() {
                let mut ep = publishing();
                let err = ep
                    .receive_subscribe_update(&crate::peers_update!($updmsg, NEVER_USED))
                    .expect_err("an update named an identifier nothing had opened");
                assert!(
                    matches!(err, EndpointError::$unknown(NEVER_USED)),
                    "the refusal should name the identifier, and named {err:?}"
                );
                assert_eq!(
                    err.session_error_code(),
                    None,
                    "Section {} says SHOULD, so the refusal carries no close code",
                    $sec
                );
                still_running(&ep);
            }

            /// An update that arrives before the answer does is accepted.
            ///
            /// The subscription exists from the moment the SUBSCRIBE arrives,
            /// and the draft puts no answer between the two: there is no
            /// control message in response to a SUBSCRIBE_UPDATE, so a
            /// subscriber may send one without waiting.
            #[test]
            fn an_update_before_the_answer_is_accepted() {
                let mut ep = active();
                ep.receive_subscribe(&crate::peers_subscribe!($submsg, PEERS_FIRST, ALIAS, ALPHA))
                    .expect("the peer's SUBSCRIBE");

                ep.receive_subscribe_update(&crate::peers_update!($updmsg, PEERS_FIRST))
                    .expect("an update of an unanswered subscription");
                still_running(&ep);
            }

            /// An update naming a subscription that has **ended** is refused
            /// by the flow, not by the identifier.
            ///
            /// The sentence is about an identifier that "has not existed
            /// within the Session", and an ended subscription existed. The
            /// record outlives the subscription for exactly that reason, so
            /// this refusal comes from the state machine and names the
            /// transition rather than the identifier.
            ///
            /// # What it catches
            ///
            /// Dropping the record when the subscription ends, which turns an
            /// identifier the session has had into one it never had:
            ///
            /// ```text
            /// an identifier the session has had should be refused by its flow, and was
            /// refused by UpdateForUnknownSubscribe(0)
            /// ```
            ///
            /// Made by removing the inbound record when the subscription ends. It
            /// reddens fifteen tests across both update files.
            #[test]
            fn an_update_for_an_ended_subscription_is_refused_by_the_flow() {
                let mut ep = publishing();
                ep.send_subscribe_done(peer_id(), $crate::v(0), Vec::new())
                    .expect("end the subscription");

                let err = ep
                    .receive_subscribe_update(&crate::peers_update!($updmsg, PEERS_FIRST))
                    .expect_err("an ended subscription was updated");
                assert!(
                    matches!(err, EndpointError::Subscription(_)),
                    "an identifier the session has had should be refused by its flow, \
                     and was refused by {err:?}"
                );
                still_running(&ep);
            }

            /// An update arriving the way the control stream delivers one
            /// reaches the peer's record.
            #[test]
            fn an_update_off_the_control_stream_reaches_the_peers_record() {
                let mut ep = publishing();
                ep.receive_message(ControlMessage::SubscribeUpdate(crate::peers_update!(
                    $updmsg,
                    PEERS_FIRST
                )))
                .expect("the peer's update off the control stream");
                still_running(&ep);
            }

            /// This endpoint can narrow a subscription of its own.
            ///
            /// The other half of the same sentence: the subscriber sends the
            /// update, and this endpoint is the subscriber for every
            /// subscription it opened. Earlier only draft-14 could
            /// build one.
            ///
            /// # What it catches
            ///
            /// Building the update without moving the subscription's own
            /// record, which is what a builder that ignores the flow looks
            /// like - it would go on building updates for a subscription that
            /// had ended:
            ///
            /// ```text
            /// a subscription this endpoint had ended was updated: SubscribeUpdate(SubscribeUpdate { subscribe_id: VarInt(0), start_group: VarInt(0), start_object: VarInt(0), end_group: VarInt(0), subscriber_priority: 128, parameters: [] })
            /// ```
            ///
            /// It reddens ten tests: this gate on all ten drafts that can build an
            /// update. Nothing that judges one arriving is touched.
            #[test]
            fn this_endpoint_can_update_a_subscription_of_its_own() {
                let mut ep = active();
                let (ours, _) = crate::we_subscribe!($oursub, ep, OUR_ALIAS, BETA)
                    .expect("this endpoint's own SUBSCRIBE");

                let msg = crate::we_update!($updmsg, ep, ours)
                    .expect("this endpoint could not narrow its own subscription");
                assert!(
                    matches!(msg, ControlMessage::SubscribeUpdate(_)),
                    "the builder should return a SUBSCRIBE_UPDATE, and returned {msg:?}"
                );

                ep.receive_subscribe_ok(&crate::peers_ok!($updmsg, ours))
                    .expect("the peer's answer to this endpoint's SUBSCRIBE");
                ep.unsubscribe(ours).expect("end this endpoint's own subscription");
                crate::we_update!($updmsg, ep, ours)
                    .expect_err("a subscription this endpoint had ended was updated");
                still_running(&ep);
            }
        }
    };
}

update_gates!(
    draft07,
    "draft07",
    0xff00_0007,
    moqtap_client::draft07::endpoint::Role,
    UpdateForUnknownSubscribe,
    end_object,
    end_object,
    named,
    send_max_subscribe_id,
    role,
    0,
    "6.5"
);
update_gates!(
    draft08,
    "draft08",
    0xff00_0008,
    moqtap_client::draft08::endpoint::Role,
    UpdateForUnknownSubscribe,
    end_group,
    end_group,
    named,
    send_max_subscribe_id,
    none,
    0,
    "7.5"
);
update_gates!(
    draft09,
    "draft09",
    0xff00_0009,
    moqtap_client::draft09::endpoint::Role,
    UpdateForUnknownSubscribe,
    end_group,
    end_group,
    named,
    send_max_subscribe_id,
    none,
    0,
    "7.5"
);
update_gates!(
    draft10,
    "draft10",
    0xff00_000a,
    moqtap_client::draft10::endpoint::Role,
    UpdateForUnknownSubscribe,
    end_group,
    end_group,
    named,
    send_max_subscribe_id,
    none,
    0,
    "8.9"
);
update_gates!(
    draft11,
    "draft11",
    0xff00_000b,
    moqtap_client::draft11::session::request_id::Role,
    UpdateForUnknownRequest,
    forward,
    forward,
    varint,
    send_max_request_id,
    none,
    1,
    "8.10"
);

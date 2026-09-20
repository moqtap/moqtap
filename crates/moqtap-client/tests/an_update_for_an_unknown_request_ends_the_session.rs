#![cfg(any(
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
))]

//! An update that arrives is about a subscription the peer opened, and one
//! naming an identifier this session has never carried ends the session.
//!
//! Draft-14 Section 9.10: "A publisher MUST terminate the session with a
//! PROTOCOL_VIOLATION if the SUBSCRIBE_UPDATE violates these rules or if the
//! subscriber specifies a request ID that has not existed within the Session."
//! Draft-12 Section 8.10 and draft-13 Section 8.10 state the same sentence
//! with the code written out as a name rather than as the constant.
//! Draft-15 Section 9.11 says it of the Subscription Request ID and draft-16
//! Section 9.11 of the Existing Request ID, both with the same code.
//!
//! Drafts 07 through 11 state the same sentence with **SHOULD**, so there the
//! update is refused and the session goes on running;
//! `an_update_names_the_peers_subscription.rs` is that half. Drafts 17 through
//! 19 dropped the field: the update rides its request's own stream, so there is
//! no identifier in it to be invalid.
//!
//! # What "has not existed" rules out
//!
//! Two things that are **not** violations, and each has a gate here. A
//! subscription that has ended existed, so an update naming one is refused by
//! the flow and the session survives - which is why the record of an inbound
//! SUBSCRIBE outlives the subscription it holds. And an identifier this
//! session carried for some other request existed too, whatever kind of
//! request it was, so that one is accepted and nothing moves.
//!
//! # Ablations, measured
//!
//! Five cuts were made, run and reverted, each recorded on the gate it belongs
//! to. Two of them are this half's alone: raising the error without failing the
//! session is what drafts 07 through 11 do and are right to do, and closing
//! over every identifier that is not the peer's subscription is the
//! over-reading the sentence rules out.

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

/// A SUBSCRIBE from the peer, in the four shapes it takes across the five
/// drafts.
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

/// The update the subscribing peer sends. Drafts 12 and 13 give it no
/// identifier of its own; drafts 14 and later do, and draft-16 renamed both
/// the message and the field.
#[macro_export]
macro_rules! peers_update {
    (reuses_id, $own:expr, $names:expr) => {
        SubscribeUpdate {
            request_id: $crate::v($names),
            start_group: $crate::v(0),
            start_object: $crate::v(0),
            end_group: $crate::v(0),
            subscriber_priority: 128,
            forward: Forward::Forward,
            parameters: Vec::new(),
        }
    };
    (own_id, $own:expr, $names:expr) => {
        SubscribeUpdate {
            request_id: $crate::v($own),
            subscription_request_id: $crate::v($names),
            start_location: Location { group: $crate::v(0), object: $crate::v(0) },
            end_group: $crate::v(0),
            subscriber_priority: 128,
            forward: Forward::Forward,
            parameters: Vec::new(),
        }
    };
    (params, $own:expr, $names:expr) => {
        SubscribeUpdate {
            request_id: $crate::v($own),
            subscription_request_id: $crate::v($names),
            parameters: Vec::new(),
        }
    };
    (renamed, $own:expr, $names:expr) => {
        RequestUpdate {
            request_id: $crate::v($own),
            existing_request_id: $crate::v($names),
            parameters: Vec::new(),
        }
    };
}

/// The update wrapped in the variant its draft's dispatch matches on.
#[macro_export]
macro_rules! peers_update_message {
    (renamed, $own:expr, $names:expr) => {
        ControlMessage::RequestUpdate($crate::peers_update!(renamed, $own, $names))
    };
    ($shape:tt, $own:expr, $names:expr) => {
        ControlMessage::SubscribeUpdate($crate::peers_update!($shape, $own, $names))
    };
}

/// The update handed to the method its draft names.
#[macro_export]
macro_rules! receive_update {
    (renamed, $ep:expr, $own:expr, $names:expr) => {
        $ep.receive_request_update(&$crate::peers_update!(renamed, $own, $names))
    };
    ($shape:tt, $ep:expr, $own:expr, $names:expr) => {
        $ep.receive_subscribe_update(&$crate::peers_update!($shape, $own, $names))
    };
}

/// Whether a built message is the update its draft calls for.
#[macro_export]
macro_rules! is_update {
    (renamed, $msg:expr) => {
        matches!($msg, ControlMessage::RequestUpdate(_))
    };
    ($shape:tt, $msg:expr) => {
        matches!($msg, ControlMessage::SubscribeUpdate(_))
    };
}

/// The update this endpoint builds for a subscription of its own.
#[macro_export]
macro_rules! we_update {
    (reuses_id, $ep:expr, $id:expr) => {
        $ep.subscribe_update(
            $id,
            $crate::v(0),
            $crate::v(0),
            $crate::v(0),
            128,
            Forward::Forward,
            Vec::new(),
        )
        .map(|msg| ((), msg))
    };
    (own_id, $ep:expr, $id:expr) => {
        $ep.subscribe_update(
            $id,
            Location { group: $crate::v(0), object: $crate::v(0) },
            $crate::v(0),
            128,
            Forward::Forward,
            Vec::new(),
        )
    };
    (params, $ep:expr, $id:expr) => {
        $ep.subscribe_update($id, Vec::new())
    };
    (renamed, $ep:expr, $id:expr) => {
        $ep.request_update($id, Vec::new())
    };
}

/// This endpoint's own SUBSCRIBE, whose arguments moved into parameters at
/// draft-15.
#[macro_export]
macro_rules! we_subscribe {
    (filter_varint, $ep:expr, $track:expr) => {
        $ep.subscribe(
            $crate::namespace(),
            $track.to_vec(),
            128,
            GroupOrder::Ascending,
            $crate::v(0x2),
            Vec::new(),
        )
    };
    (filter_type, $ep:expr, $track:expr) => {
        $ep.subscribe(
            $crate::namespace(),
            $track.to_vec(),
            128,
            GroupOrder::Ascending,
            FilterType::LargestObject,
            Vec::new(),
        )
    };
    (location, $ep:expr, $track:expr) => {
        $ep.subscribe(
            $crate::namespace(),
            $track.to_vec(),
            128,
            GroupOrder::Ascending,
            FilterType::LargestObject,
            Vec::new(),
        )
    };
    (bare, $ep:expr, $track:expr) => {
        $ep.subscribe($crate::namespace(), $track.to_vec(), Vec::new())
    };
}

/// The SUBSCRIBE_OK this endpoint builds for the peer.
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

/// The SUBSCRIBE_OK the peer answers this endpoint's own SUBSCRIBE with, which
/// is what puts the subscription in a state UNSUBSCRIBE may end.
#[macro_export]
macro_rules! peers_ok {
    (expires, $id:expr, $alias:expr) => {
        SubscribeOk {
            request_id: $id,
            track_alias: $crate::v($alias),
            expires: $crate::v(0),
            group_order: GroupOrder::Ascending,
            content_exists: ContentExists::NoLargestLocation,
            largest_location: None,
            parameters: Vec::new(),
        }
    };
    (params, $id:expr, $alias:expr) => {
        SubscribeOk { request_id: $id, track_alias: $crate::v($alias), parameters: Vec::new() }
    };
    (ext, $id:expr, $alias:expr) => {
        SubscribeOk {
            request_id: $id,
            track_alias: $crate::v($alias),
            parameters: Vec::new(),
            track_extensions: Vec::new(),
        }
    };
}

/// The message the publisher ends the subscription with.
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

/// SETUP, in the two shapes it takes across the five drafts.
#[macro_export]
macro_rules! peers_setup {
    (versioned, $ep:expr, $ver:expr) => {{
        let _ = $ep.send_client_setup(vec![$crate::v($ver)], vec![]).expect("CLIENT_SETUP");
        $ep.receive_server_setup(&ServerSetup {
            selected_version: $crate::v($ver),
            parameters: vec![KeyValuePair {
                key: $crate::v(0x02),
                value: KvpValue::Varint($crate::v(100)),
            }],
        })
        .expect("SERVER_SETUP");
    }};
    (alpn, $ep:expr, $ver:expr) => {{
        let _ = $ep.send_client_setup(vec![]).expect("CLIENT_SETUP");
        $ep.receive_server_setup(&ServerSetup {
            parameters: vec![KeyValuePair {
                key: $crate::v(0x02),
                value: KvpValue::Varint($crate::v(100)),
            }],
        })
        .expect("SERVER_SETUP");
    }};
}

/// One draft's seven gates.
macro_rules! update_gates {
    ($draft:ident, $feat:literal, $ver:expr, $setup:tt, $submsg:tt, $updmsg:tt, $accept:tt,
     $finish:tt, $sec:literal) => {
        #[cfg(feature = $feat)]
        mod $draft {
            use moqtap_client::$draft::endpoint::{Endpoint, EndpointError};
            use moqtap_client::$draft::session::request_id::Role;
            use moqtap_client::$draft::session::state::SessionState;
            use moqtap_codec::$draft::error_codes::SessionErrorCode;

            #[allow(unused_imports)]
            use moqtap_codec::kvp::{KeyValuePair, KvpValue};
            #[allow(unused_imports)]
            use moqtap_codec::types::*;
            use moqtap_codec::$draft::message::*;

            /// The peer is the server here, so its Request IDs are the odd
            /// ones.
            const PEERS_FIRST: u64 = 1;

            /// The identifier the update spends on the drafts that give it one
            /// of its own. Drafts 12 and 13 give it none, so there it goes
            /// unread.
            #[allow(dead_code)]
            const PEERS_UPDATE: u64 = 3;

            /// An identifier this session has never carried a request under.
            const NEVER_USED: u64 = 9;

            const ALIAS: u64 = 7;

            const ALPHA: &[u8] = b"alpha";
            const BETA: &[u8] = b"beta";

            /// A client with its session established, a budget granted to the
            /// peer and a ceiling granted by it.
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

            /// An endpoint publishing a track the peer subscribed to.
            fn publishing() -> Endpoint {
                let mut ep = active();
                // Through the dispatch, so that the Request ID the SUBSCRIBE
                // spends steps the peer's sequence: on the drafts where the
                // update carries an identifier of its own, the next one is
                // measured against it.
                ep.receive_message(ControlMessage::Subscribe(crate::peers_subscribe!(
                    $submsg,
                    PEERS_FIRST,
                    ALPHA
                )))
                .expect("the peer's SUBSCRIBE");
                crate::we_accept!($accept, ep, PEERS_FIRST, ALIAS)
                    .expect("accept the subscription");
                ep
            }

            /// The session is still running: the rule ends it only over an
            /// identifier the session has never carried.
            fn still_running(ep: &Endpoint) {
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "Section {} ends the session only over an identifier that has not \
                     existed within it",
                    $sec
                );
            }

            /// The peer updates the subscription it opened, and it is
            /// accepted.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// Looking the update up among the subscriptions this endpoint
            /// opened rather than among the peer's:
            ///
            /// ```text
            /// the peer's update of its own subscription: UpdateForUnknownRequest(1)
            /// ```
            ///
            /// It reddens forty-eight tests across both update files and the draft-14
            /// dispatch test. From draft-11 the parity rule makes the lookup a miss
            /// rather than a hit on the wrong record, so under the cut every
            /// conforming update is refused.
            #[test]
            fn an_update_for_the_peers_subscription_is_accepted() {
                let mut ep = publishing();
                ep.receive_message(crate::peers_update_message!(
                    $updmsg,
                    PEERS_UPDATE,
                    PEERS_FIRST
                ))
                .expect("the peer's update of its own subscription");
                still_running(&ep);
            }

            /// An update naming an identifier this session has never carried
            /// ends the session, carrying PROTOCOL_VIOLATION.
            ///
            /// # What it catches
            ///
            /// Answering it with a plain error, which is what drafts 07
            /// through 11 do - their sentence says SHOULD and this one says
            /// MUST:
            ///
            /// ```text
            /// assertion `left == right` failed: a MUST-terminate rule leaves the session closed
            ///   left: Active
            ///  right: Closed
            /// ```
            ///
            /// Made by raising the error without failing the session, which is exactly
            /// what drafts 07 through 11 do and are right to do: their sentence says
            /// SHOULD. It reddens five tests and only this gate.
            #[test]
            fn an_update_for_an_identifier_nothing_has_carried_ends_the_session() {
                let mut ep = publishing();
                let err = crate::receive_update!($updmsg, ep, PEERS_UPDATE, NEVER_USED)
                    .expect_err("an update named an identifier the session never carried");
                assert!(
                    matches!(err, EndpointError::UpdateForUnknownRequest(NEVER_USED)),
                    "the refusal should name the identifier, and named {err:?}"
                );
                assert_eq!(
                    err.session_error_code(),
                    Some(SessionErrorCode::ProtocolViolation),
                    "Section {} names PROTOCOL_VIOLATION for this and no other code",
                    $sec
                );
                assert_eq!(
                    ep.session_state(),
                    SessionState::Closed,
                    "a MUST-terminate rule leaves the session closed"
                );
            }

            /// An update that arrives before the answer does is accepted.
            ///
            /// The subscription exists from the moment the SUBSCRIBE arrives,
            /// and nothing in the draft makes the subscriber wait.
            #[test]
            fn an_update_before_the_answer_is_accepted() {
                let mut ep = active();
                ep.receive_subscribe(&crate::peers_subscribe!($submsg, PEERS_FIRST, ALPHA))
                    .expect("the peer's SUBSCRIBE");

                crate::receive_update!($updmsg, ep, PEERS_UPDATE, PEERS_FIRST)
                    .expect("an update of an unanswered subscription");
                still_running(&ep);
            }

            /// An update naming a subscription that has **ended** is refused
            /// by the flow, and the session survives.
            ///
            /// An ended subscription existed, so this is not the case the
            /// draft ends the session over. The record outlives the
            /// subscription for exactly that reason.
            ///
            /// # What it catches
            ///
            /// Dropping the record when the subscription ends, which turns an
            /// identifier the session has carried into one it never had and
            /// ends the session over conforming traffic:
            ///
            /// ```text
            /// an identifier the session has carried should be refused by its flow, and
            /// was refused by UpdateForUnknownRequest(1)
            /// ```
            ///
            /// Made by removing the inbound record when the subscription ends. It
            /// reddens fifteen tests across both update files, and here it does more
            /// than misreport: the session ends over traffic the sentence does not
            /// reach.
            #[test]
            fn an_update_for_an_ended_subscription_is_refused_by_the_flow() {
                let mut ep = publishing();
                crate::we_finish!($finish, ep, PEERS_FIRST).expect("end the subscription");

                let err = crate::receive_update!($updmsg, ep, PEERS_UPDATE, PEERS_FIRST)
                    .expect_err("an ended subscription was updated");
                assert!(
                    matches!(err, EndpointError::Subscription(_)),
                    "an identifier the session has carried should be refused by its \
                     flow, and was refused by {err:?}"
                );
                assert_eq!(
                    err.session_error_code(),
                    None,
                    "an identifier the session has carried is not what Section {} \
                     ends the session over",
                    $sec
                );
                still_running(&ep);
            }

            /// An identifier this session carried for a request of another
            /// kind is accepted, and nothing moves.
            ///
            /// A subscription this endpoint opened itself is such an
            /// identifier: the peer has no business updating it, but the
            /// sentence the close comes from is about an identifier that "has
            /// not existed within the Session", and this one has.
            ///
            /// # What it catches
            ///
            /// Closing over every identifier that is not the peer's
            /// subscription, which ends the session over traffic the sentence
            /// does not reach:
            ///
            /// ```text
            /// an identifier the session had carried was refused: UpdateForUnknownRequest(0)
            /// ```
            ///
            /// Made by closing over everything the inbound-subscribe map does not hold.
            /// It reddens five tests and only this gate: every other update here names
            /// either the peer's subscription or nothing at all.
            #[test]
            fn an_identifier_carried_by_another_request_is_accepted() {
                let mut ep = publishing();
                let (ours, _) =
                    crate::we_subscribe!($submsg, ep, BETA).expect("this endpoint's own SUBSCRIBE");

                crate::receive_update!($updmsg, ep, PEERS_UPDATE, ours.into_inner())
                    .expect("an identifier the session had carried was refused");
                still_running(&ep);
            }

            /// An update arriving the way the control stream delivers one
            /// reaches the peer's record.
            ///
            /// # What it catches
            ///
            /// The same as the first gate, through the dispatch arm rather
            /// than the handler.
            #[test]
            fn an_update_off_the_control_stream_reaches_the_peers_record() {
                let mut ep = publishing();
                crate::we_finish!($finish, ep, PEERS_FIRST).expect("end the subscription");

                ep.receive_message(crate::peers_update_message!(
                    $updmsg,
                    PEERS_UPDATE,
                    PEERS_FIRST
                ))
                .expect_err("an ended subscription was updated off the control stream");
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
            /// record, which would go on building updates for a subscription
            /// that had ended:
            ///
            /// ```text
            /// a subscription this endpoint had ended was updated: ((), SubscribeUpdate(SubscribeUpdate { request_id: VarInt(0), start_group: VarInt(0), start_object: VarInt(0), end_group: VarInt(0), subscriber_priority: 128, forward: Forward, parameters: [] }))
            /// ```
            ///
            /// It reddens ten tests: this gate on all ten drafts that can build an
            /// update. Nothing that judges one arriving is touched.
            #[test]
            fn this_endpoint_can_update_a_subscription_of_its_own() {
                let mut ep = active();
                let (ours, _) =
                    crate::we_subscribe!($submsg, ep, BETA).expect("this endpoint's own SUBSCRIBE");

                let (_, msg) = crate::we_update!($updmsg, ep, ours)
                    .expect("this endpoint could not narrow its own subscription");
                assert!(
                    crate::is_update!($updmsg, msg),
                    "the builder should return the update message, and returned {msg:?}"
                );

                ep.receive_subscribe_ok(&crate::peers_ok!($accept, ours, 20))
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
    draft12,
    "draft12",
    0xff00_000c,
    versioned,
    filter_varint,
    reuses_id,
    expires,
    subscribe_done,
    "8.10"
);
update_gates!(
    draft13,
    "draft13",
    0xff00_000d,
    versioned,
    filter_type,
    reuses_id,
    expires,
    subscribe_done,
    "8.10"
);
update_gates!(
    draft14,
    "draft14",
    0xff00_000e,
    versioned,
    location,
    own_id,
    expires,
    publish_done,
    "9.10"
);
update_gates!(draft15, "draft15", 0, alpn, bare, params, params, publish_done_count, "9.11");
update_gates!(draft16, "draft16", 0, alpn, bare, renamed, ext, publish_done_count, "9.11");

#![cfg(any(
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
))]

//! A track status creates no subscription, so nothing about a subscription can
//! name one.
//!
//! From draft-13 the request is a TRACK_STATUS with a SUBSCRIBE's shape, and
//! the sentence that says so says what it is not in the same breath. Draft-13
//! Section 8.20, draft-14 Section 9.20, drafts 15 and 16 Section 9.19,
//! draft-17 Section 9.16 and drafts 18 and 19 Section 10.14: the receiver
//! "treats it identically as if it had received a SUBSCRIBE message, except it
//! does not create downstream subscription state or send any Objects".
//!
//! What follows is spelled out at the end of the same paragraph. Drafts 13
//! through 15: "the subscriber cannot send SUBSCRIBE_UPDATE or UNSUBSCRIBE".
//! Draft-16 renames the first of the two: "the subscriber cannot send
//! REQUEST_UPDATE or UNSUBSCRIBE". Drafts 17 through 19 drop the second half,
//! because there is no UNSUBSCRIBE for a request that owns a stream: "the
//! subscriber cannot send REQUEST_UPDATE".
//!
//! # What was here before
//!
//! The opposite, in writing, on six of the seven drafts that state the rule.
//! Drafts 12 through 16 listed the track statuses this endpoint had asked for
//! among the requests whose identifier had already existed within the session,
//! which is the complement of the drafts' own "has not existed" test, and an
//! update naming one was accepted on that ground. Drafts 17 and 18 went further
//! and named `track_statuses` in the set of request kinds an update may modify,
//! beside the five the draft actually lists. Draft-19 alone left it out, and
//! its comment says why.
//!
//! Draft-12 is not in this file. Its TRACK_STATUS_REQUEST is a different
//! message with no such sentence attached, so an update naming one is answered
//! by the rule about identifiers that never existed and by nothing else.
//!
//! # Why none of this ends the session
//!
//! Only draft-19 names a close code for an update that may not be sent: "An
//! endpoint that receives a REQUEST_UPDATE other than in the two cases above
//! MUST close the session with a PROTOCOL_VIOLATION." No draft in this file
//! carries that sentence, so the message is refused where it is handled and the
//! session goes on running. The rule about an identifier the session never
//! carried is a different sentence and still closes, which the last gate on
//! each of the four control-stream drafts checks.
//!
//! # Ablations, measured
//!
//! Four cuts are recorded here, each run and reverted, each on the gate it
//! reddens. Two of them restore the earlier behaviour, on the
//! four control-stream drafts and on the two stream-era ones; the other two
//! are the guard cut in the withdrawal's handler and the guard widened past
//! the one request kind the sentence is about.
//!
//! One gate carries no cut. The rule about an identifier the session never
//! carried is a different sentence with a close code of its own, and nothing
//! changed here touches the path that raises it.

#![allow(clippy::items_after_test_module)]

use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;

/// Unread in a build that enables only drafts whose gates do not use it.
#[allow(dead_code)]
fn namespace() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec()])
}

/// Unread in a build that enables only drafts whose gates do not use it.
#[allow(dead_code)]
fn elsewhere() -> TrackNamespace {
    TrackNamespace(vec![b"elsewhere".to_vec()])
}

/// Unread in a build that enables only drafts whose gates do not use it.
#[allow(dead_code)]
fn name() -> Vec<u8> {
    b"video".to_vec()
}

/// Unread in a build that enables only drafts whose gates do not use it.
#[allow(dead_code)]
fn other_name() -> Vec<u8> {
    b"audio".to_vec()
}

fn v(n: u64) -> VarInt {
    VarInt::from_u64(n).unwrap()
}

/// The TRACK_STATUS the peer sends, in the three shapes it takes.
#[macro_export]
macro_rules! peers_request {
    (subscribe13, $id:expr, $ns:expr, $nm:expr) => {
        TrackStatus {
            request_id: $crate::v($id),
            track_namespace: $ns,
            track_name: $nm,
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            forward: Forward::Forward,
            filter_type: FilterType::LargestObject,
            start_group: None,
            start_object: None,
            end_group: None,
            parameters: vec![],
        }
    };
    (subscribe14, $id:expr, $ns:expr, $nm:expr) => {
        TrackStatus {
            request_id: $crate::v($id),
            track_namespace: $ns,
            track_name: $nm,
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            forward: Forward::Forward,
            filter_type: FilterType::LargestObject,
            start_location: None,
            end_group: None,
            parameters: vec![],
        }
    };
    (simple, $id:expr, $ns:expr, $nm:expr) => {
        TrackStatus {
            request_id: $crate::v($id),
            track_namespace: $ns,
            track_name: $nm,
            parameters: vec![],
        }
    };
}

/// The update the peer sends, naming the request it means to modify. Draft-13
/// puts the target in the message's only identifier; drafts 14 and 15 give the
/// update an identifier of its own and name the target beside it; draft-16
/// renames the message and the field with it.
#[macro_export]
macro_rules! peers_update {
    (d13, $target:expr) => {
        SubscribeUpdate {
            request_id: $crate::v($target),
            start_group: $crate::v(0),
            start_object: $crate::v(0),
            end_group: $crate::v(0),
            subscriber_priority: 128,
            forward: Forward::Forward,
            parameters: vec![],
        }
    };
    (d14, $target:expr) => {
        SubscribeUpdate {
            request_id: $crate::v(90),
            subscription_request_id: $crate::v($target),
            start_location: Location { group: $crate::v(0), object: $crate::v(0) },
            end_group: $crate::v(0),
            subscriber_priority: 128,
            forward: Forward::Forward,
            parameters: vec![],
        }
    };
    (d15, $target:expr) => {
        SubscribeUpdate {
            request_id: $crate::v(90),
            subscription_request_id: $crate::v($target),
            parameters: vec![],
        }
    };
    (d16, $target:expr) => {
        RequestUpdate {
            request_id: $crate::v(90),
            existing_request_id: $crate::v($target),
            parameters: vec![],
        }
    };
}

/// A track status this endpoint asks for.
#[macro_export]
macro_rules! our_own {
    (sub13, $ep:expr) => {
        $ep.track_status(
            $crate::elsewhere(),
            $crate::other_name(),
            128,
            GroupOrder::Ascending,
            Forward::Forward,
            FilterType::LargestObject,
            Vec::new(),
        )
    };
    (bare, $ep:expr) => {
        $ep.track_status($crate::elsewhere(), $crate::other_name())
    };
    (params, $ep:expr) => {
        $ep.track_status($crate::elsewhere(), $crate::other_name(), vec![])
    };
}

/// An advertisement this endpoint makes, which is one of the request kinds the
/// draft does allow an update to modify.
#[macro_export]
macro_rules! our_advert {
    (announce, $ep:expr) => {
        $ep.announce($crate::elsewhere(), vec![])
    };
    (bare, $ep:expr) => {
        $ep.publish_namespace($crate::elsewhere(), vec![])
    };
    (params, $ep:expr) => {
        $ep.publish_namespace($crate::elsewhere(), vec![])
    };
}

#[macro_export]
macro_rules! setup_params {
    (none) => {
        Vec::new()
    };
}

#[macro_export]
macro_rules! server_params {
    (none) => {
        vec![KeyValuePair { key: $crate::v(0x02), value: KvpValue::Varint($crate::v(100)) }]
    };
}

#[macro_export]
macro_rules! peers_setup {
    (versioned, $ep:expr, $version:expr) => {{
        let _ = $ep
            .send_client_setup(vec![$crate::v($version)], $crate::setup_params!(none))
            .expect("CLIENT_SETUP");
        $ep.receive_server_setup(&ServerSetup {
            selected_version: $crate::v($version),
            parameters: $crate::server_params!(none),
        })
        .expect("SERVER_SETUP");
    }};
    (alpn, $ep:expr, $version:expr) => {{
        let _ = $ep.send_client_setup($crate::setup_params!(none)).expect("CLIENT_SETUP");
        $ep.receive_server_setup(&ServerSetup { parameters: $crate::server_params!(none) })
            .expect("SERVER_SETUP");
    }};
}

/// The six gates for a draft whose update and withdrawal travel on the control
/// stream.
macro_rules! control_stream_gates {
    ($draft:ident, $feat:literal, $version:expr, $role:path, $params:tt, $setup:tt,
     $request:tt, $update:tt, $recv_update:ident, $ours:tt, $advert:tt,
     $peers_id:literal, $sec:literal) => {
        #[cfg(feature = $feat)]
        mod $draft {
            use moqtap_client::$draft::endpoint::{Endpoint, EndpointError};
            use moqtap_client::$draft::session::state::SessionState;
            use $role as Role;

            #[allow(unused_imports)]
            use moqtap_codec::kvp::{KeyValuePair, KvpValue};
            #[allow(unused_imports)]
            use moqtap_codec::types::*;
            #[allow(unused_imports)]
            use moqtap_codec::varint::VarInt;
            use moqtap_codec::$draft::message::*;

            /// The identifier the peer asks its track status under.
            const PEERS_ID: u64 = $peers_id;

            /// An identifier no request of either end has opened.
            const NEVER_USED: u64 = 41;

            fn active() -> Endpoint {
                let mut ep = Endpoint::new(Role::Client);
                ep.connect().expect("a client may open");
                crate::peers_setup!($setup, ep, $version);
                let _ = ep.send_max_request_id($crate::v(100)).expect("a budget for the peer");
                ep
            }

            /// An endpoint holding a track status the peer asked for.
            fn asked() -> Endpoint {
                let mut ep = active();
                ep.receive_track_status(&crate::peers_request!(
                    $request,
                    PEERS_ID,
                    crate::namespace(),
                    crate::name()
                ))
                .expect("the peer may ask");
                ep
            }

            /// An update naming a track status the peer asked for is refused.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// Section 8.20 says the subscriber cannot update a track status: ()
            /// ```
            ///
            /// Made by putting the track statuses back among the requests whose
            /// identifier has existed, which is where all four drafts had them. It
            /// reddens 8 tests, this gate and the one after it on each of the four.
            #[test]
            fn an_update_naming_a_track_status_the_peer_asked_for_is_refused() {
                let mut ep = asked();
                let err = ep.$recv_update(&crate::peers_update!($update, PEERS_ID)).expect_err(
                    concat!("Section ", $sec, " says the subscriber cannot update a track status"),
                );
                assert!(
                    matches!(err, EndpointError::NotASubscription(PEERS_ID)),
                    "the refusal should name the track status; got {err:?}"
                );
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "no draft here names a close code for an update that may not be sent"
                );
            }

            /// And one naming a track status this endpoint asked for is refused
            /// the same way: the sentence is about the request kind, not about
            /// which end opened it.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// a track status cannot be updated whichever end asked for it: ()
            /// ```
            ///
            /// The other half of the same cut: the sentence is about the request
            /// kind, so a guard that reads only the peer's record would let this
            /// one through.
            #[test]
            fn an_update_naming_this_endpoints_own_track_status_is_refused() {
                let mut ep = active();
                let (ours, _) = crate::our_own!($ours, ep).expect("this endpoint may ask");
                let err = ep
                    .$recv_update(&crate::peers_update!($update, ours.into_inner()))
                    .expect_err("a track status cannot be updated whichever end asked for it");
                assert!(
                    matches!(err, EndpointError::NotASubscription(_)),
                    "the refusal should name the track status; got {err:?}"
                );
                assert_eq!(ep.session_state(), SessionState::Active, "a refusal is not a close");
            }

            /// An UNSUBSCRIBE naming a track status is refused too, which is
            /// the other half of the same sentence.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// the refusal should say what the identifier names; got
            /// UnknownRequest(1)
            /// ```
            ///
            /// Made by cutting the guard in the withdrawal's own handler, which
            /// leaves the message refused for the wrong reason: the identifier does
            /// name a request this session is carrying. It reddens 4 tests, this
            /// gate on each of the four. One shared sentence, two handlers, so the
            /// update's cut does not reach here.
            #[test]
            fn an_unsubscribe_naming_a_track_status_is_refused() {
                let mut ep = asked();
                let err = ep
                    .receive_unsubscribe(&Unsubscribe { request_id: crate::v(PEERS_ID) })
                    .expect_err(concat!(
                        "Section ",
                        $sec,
                        " says the subscriber cannot unsubscribe a track status"
                    ));
                assert!(
                    matches!(err, EndpointError::NotASubscription(PEERS_ID)),
                    "the refusal should say what the identifier names; got {err:?}"
                );
                assert_eq!(ep.session_state(), SessionState::Active, "a refusal is not a close");
            }

            /// The refusal reaches no further than the one request kind: an
            /// update naming a request the draft does allow one for is still
            /// accepted.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// an advertisement is one of the kinds an update may modify:
            /// NotASubscription(0)
            /// ```
            ///
            /// Made by widening the guard to the advertisements as well. It reddens
            /// 6 tests, this gate on all six drafts, and it is the reason the guard
            /// names one request kind rather than everything that is not a
            /// subscription.
            #[test]
            fn an_update_naming_a_request_that_may_be_updated_is_still_accepted() {
                let mut ep = active();
                let (ours, _) =
                    crate::our_advert!($advert, ep).expect("this endpoint may advertise");
                ep.$recv_update(&crate::peers_update!($update, ours.into_inner()))
                    .expect("an advertisement is one of the kinds an update may modify");
                assert_eq!(ep.session_state(), SessionState::Active, "and it is not a close");
            }

            /// And the rule about an identifier the session never carried is a
            /// different sentence, which still ends the session.
            #[test]
            fn an_update_naming_an_identifier_never_carried_still_closes_the_session() {
                let mut ep = asked();
                let err = ep
                    .$recv_update(&crate::peers_update!($update, NEVER_USED))
                    .expect_err("nothing has ever been opened under that identifier");
                assert!(
                    matches!(err, EndpointError::UpdateForUnknownRequest(NEVER_USED)),
                    "the close should name the identifier that never existed; got {err:?}"
                );
                assert_eq!(
                    ep.session_state(),
                    SessionState::Closed,
                    "that sentence does name a close, and it is unchanged"
                );
            }

            /// An UNSUBSCRIBE naming an identifier nothing was opened under is
            /// still an unknown request rather than a track status.
            #[test]
            fn an_unsubscribe_naming_nothing_is_still_an_unknown_request() {
                let mut ep = asked();
                let err = ep
                    .receive_unsubscribe(&Unsubscribe { request_id: crate::v(NEVER_USED) })
                    .expect_err("nothing was opened under that identifier");
                assert!(
                    matches!(err, EndpointError::UnknownRequest(NEVER_USED)),
                    "an identifier naming nothing is not a track status; got {err:?}"
                );
                assert_eq!(ep.session_state(), SessionState::Active, "and it is not a close");
            }
        }
    };
}

/// The four gates for a draft whose update travels on the request's own stream.
macro_rules! stream_gates {
    ($draft:ident, $feat:literal, $update:tt, $sec:literal) => {
        #[cfg(feature = $feat)]
        mod $draft {
            use moqtap_client::$draft::endpoint::{Endpoint, EndpointError};
            use moqtap_client::$draft::session::request_id::Role;
            use moqtap_client::$draft::session::state::SessionState;

            #[allow(unused_imports)]
            use moqtap_codec::types::*;
            #[allow(unused_imports)]
            use moqtap_codec::varint::VarInt;
            use moqtap_codec::$draft::message::{self, ControlMessage, Setup};

            /// The identifier the peer asks its track status under.
            const PEERS_ID: u64 = 1;

            fn active() -> Endpoint {
                let mut ep = Endpoint::new(Role::Client);
                ep.connect().expect("a client may open");
                let _ = ep.send_setup(vec![]).expect("SETUP");
                ep.receive_setup(&Setup { options: vec![] }).expect("the peer's SETUP");
                ep
            }

            fn peers_track_status(id: u64) -> ControlMessage {
                ControlMessage::TrackStatus(crate::peers_stream_request!($update, id))
            }

            fn update() -> ControlMessage {
                ControlMessage::RequestUpdate(crate::peers_stream_update!($update))
            }

            /// An endpoint holding a track status the peer asked for on a
            /// stream of its own.
            fn asked() -> Endpoint {
                let mut ep = active();
                let _ = ep
                    .receive_request_on_stream(&peers_track_status(PEERS_ID))
                    .expect("the peer may ask");
                ep
            }

            /// An update arriving on the peer's track status stream is refused.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// Section 9.16 says the subscriber cannot send REQUEST_UPDATE for a
            /// track status: ()
            /// ```
            ///
            /// Made by putting the track statuses back among the request kinds an
            /// update may modify, which is where both drafts had them written out.
            /// It reddens 4 tests, this gate and the one after it on both.
            #[test]
            fn an_update_naming_a_track_status_the_peer_asked_for_is_refused() {
                let mut ep = asked();
                let err = ep
                    .receive_on_peer_request_stream(crate::v(PEERS_ID), update())
                    .expect_err(concat!(
                        "Section ",
                        $sec,
                        " says the subscriber cannot send REQUEST_UPDATE for a track status"
                    ));
                assert!(
                    matches!(err, EndpointError::NotASubscription(PEERS_ID)),
                    "the refusal should name the track status; got {err:?}"
                );
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "this draft names no close code for it"
                );
            }

            /// And one naming a track status this endpoint asked for is refused
            /// the same way.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// a track status cannot be updated whichever end asked for it: ()
            /// ```
            ///
            /// The other half of the same cut. One map holds both ends' requests
            /// here, so the guard cannot tell them apart and does not need to.
            #[test]
            fn an_update_naming_this_endpoints_own_track_status_is_refused() {
                let mut ep = active();
                let (ours, _) = ep
                    .track_status(
                        TrackNamespace(vec![b"elsewhere".to_vec()]),
                        b"audio".to_vec(),
                        vec![],
                    )
                    .expect("this endpoint may ask");
                let msg = match update() {
                    ControlMessage::RequestUpdate(m) => m,
                    other => panic!("built the wrong message: {other:?}"),
                };
                let err = ep
                    .receive_request_update(ours, &msg)
                    .expect_err("a track status cannot be updated whichever end asked for it");
                assert!(
                    matches!(err, EndpointError::NotASubscription(_)),
                    "the refusal should name the track status; got {err:?}"
                );
                assert_eq!(ep.session_state(), SessionState::Active, "a refusal is not a close");
            }

            /// The refusal reaches no further than the one request kind.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// an advertisement is one of the kinds an update may modify:
            /// NotASubscription(0)
            /// ```
            ///
            /// Made by widening the guard to the advertisements as well. It reddens
            /// 6 tests across the six drafts in this file.
            #[test]
            fn an_update_naming_a_request_that_may_be_updated_is_still_accepted() {
                let mut ep = active();
                let (ours, _) = ep
                    .publish_namespace(TrackNamespace(vec![b"elsewhere".to_vec()]), vec![])
                    .expect("this endpoint may advertise");
                let msg = match update() {
                    ControlMessage::RequestUpdate(m) => m,
                    other => panic!("built the wrong message: {other:?}"),
                };
                ep.receive_request_update(ours, &msg)
                    .expect("an advertisement is one of the kinds an update may modify");
                assert_eq!(ep.session_state(), SessionState::Active, "and it is not a close");
            }

            /// An update naming an identifier no request has opened is still an
            /// unknown request rather than a track status.
            #[test]
            fn an_update_naming_nothing_is_still_an_unknown_request() {
                let mut ep = asked();
                let msg = match update() {
                    ControlMessage::RequestUpdate(m) => m,
                    other => panic!("built the wrong message: {other:?}"),
                };
                let err = ep
                    .receive_request_update(crate::v(41), &msg)
                    .expect_err("nothing was opened under that identifier");
                assert!(
                    matches!(err, EndpointError::UnknownRequest(41)),
                    "an identifier naming nothing is not a track status; got {err:?}"
                );
                assert_eq!(ep.session_state(), SessionState::Active, "and it is not a close");
            }

            #[allow(unused_imports)]
            use message as _message;
        }
    };
}

/// The TRACK_STATUS and REQUEST_UPDATE shapes on the two stream-era drafts in
/// this file.
#[macro_export]
macro_rules! peers_stream_request {
    (d17, $id:expr) => {
        message::TrackStatus {
            request_id: $crate::v($id),
            required_request_id_delta: $crate::v(0),
            track_namespace: TrackNamespace(vec![b"conformance".to_vec()]),
            track_name: b"video".to_vec(),
            parameters: vec![],
        }
    };
    (d18, $id:expr) => {
        message::TrackStatus {
            request_id: $crate::v($id),
            track_namespace: TrackNamespace(vec![b"conformance".to_vec()]),
            track_name: b"video".to_vec(),
            parameters: vec![],
        }
    };
}

#[macro_export]
macro_rules! peers_stream_update {
    (d17) => {
        message::RequestUpdate {
            request_id: $crate::v(90),
            required_request_id_delta: $crate::v(0),
            parameters: vec![],
        }
    };
    (d18) => {
        message::RequestUpdate { request_id: $crate::v(90), parameters: vec![] }
    };
}

control_stream_gates!(
    draft13,
    "draft13",
    0xff00_000d,
    moqtap_client::draft13::session::request_id::Role,
    none,
    versioned,
    subscribe13,
    d13,
    receive_subscribe_update,
    sub13,
    announce,
    1,
    "8.20"
);
control_stream_gates!(
    draft14,
    "draft14",
    0xff00_000e,
    moqtap_client::draft14::session::request_id::Role,
    none,
    versioned,
    subscribe14,
    d14,
    receive_subscribe_update,
    sub13,
    bare,
    1,
    "9.20"
);
control_stream_gates!(
    draft15,
    "draft15",
    0xff00_000f,
    moqtap_client::draft15::session::request_id::Role,
    none,
    alpn,
    simple,
    d15,
    receive_subscribe_update,
    params,
    params,
    1,
    "9.19"
);
control_stream_gates!(
    draft16,
    "draft16",
    0xff00_0010,
    moqtap_client::draft16::session::request_id::Role,
    none,
    alpn,
    simple,
    d16,
    receive_request_update,
    params,
    params,
    1,
    "9.19"
);
stream_gates!(draft17, "draft17", d17, "9.16");
stream_gates!(draft18, "draft18", d18, "10.14");

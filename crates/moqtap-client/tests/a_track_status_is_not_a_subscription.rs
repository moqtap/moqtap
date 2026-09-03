#![cfg(any(
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20",
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
//! REQUEST_UPDATE or UNSUBSCRIBE". Drafts 17 through 20 drop the second half,
//! because there is no UNSUBSCRIBE for a request that owns a stream: "the
//! subscriber cannot send REQUEST_UPDATE".
//!
//! # What was here before
//!
//! The opposite, in writing, on six of the eight drafts that state the rule.
//! Drafts 12 through 16 listed the track statuses this endpoint had asked for
//! among the requests whose identifier had already existed within the session,
//! which is the complement of the drafts' own "has not existed" test, and an
//! update naming one was accepted on that ground. Drafts 17 and 18 went further
//! and named `track_statuses` in the set of request kinds an update may modify,
//! beside the five the draft actually lists. Drafts 19 and 20 left it out, and
//! draft-19's comment says why.
//!
//! Draft-12 is not in this file. Its TRACK_STATUS_REQUEST is a different
//! message with no such sentence attached, so an update naming one is answered
//! by the rule about identifiers that never existed and by nothing else.
//!
//! # Where the consequence changes
//!
//! Drafts 13 through 18 name no close code for an update that may not be sent,
//! so the message is refused where it is handled and the session goes on
//! running. Drafts 19 and 20 do name one: "An endpoint that receives a
//! REQUEST_UPDATE other than in the two cases above MUST close the session with
//! a PROTOCOL_VIOLATION." Same rule, opposite outcome, which is why those two
//! have a macro of their own rather than an argument on the one the four
//! before them share — three of the four assertions invert.
//!
//! The rule about an identifier the session never carried is a different
//! sentence and closes on every draft here, which the last gate on each of the
//! four control-stream drafts checks.
//!
//! ## What the range used to stop at 18
//!
//! It stopped there because that is where the outcome changes, and a gate
//! asserting a refusal would have failed on 19 and 20. The two drafts left out
//! on that ground were the two the rule is stated most explicitly for, and the
//! error they raise for it — `UnexpectedRequestUpdate` — turned out to be
//! raised in twelve places in each of their endpoints and observed by nothing
//! anywhere in the workspace. Not one test, in either crate.
//!
//! That is the shape worth naming. A range that stops where the behaviour
//! changes looks like scoping and reads like a decision, and it leaves exactly
//! the drafts whose behaviour is most particular with no gate at all. The
//! divergence was the reason to write more, not less.
//!
//! # Ablations, measured
//!
//! Four cuts are recorded on the six drafts that refuse, each run and reverted,
//! each on the gate it reddens. Two of them restore the earlier behaviour, on
//! the four control-stream drafts and on the two stream-era ones; the other two
//! are the guard cut in the withdrawal's handler and the guard widened past the
//! one request kind the sentence is about.
//!
//! One gate carries no cut. The rule about an identifier the session never
//! carried is a different sentence with a close code of its own, and nothing
//! changed here touches the path that raises it.
//!
//! The two closing drafts carry a cut of their own, recorded on the gate below.

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

/// The four gates for a draft that closes the session over this rather than
/// refusing the message.
///
/// Same rule, different consequence, so a separate macro rather than a
/// parameter on the one above: three of the four assertions invert. See the
/// module header for why drafts 19 and 20 part company with their four
/// predecessors here, and what that cost.
macro_rules! closing_gates {
    ($draft:ident, $feat:literal, $sec:literal) => {
        #[cfg(feature = $feat)]
        mod $draft {
            use moqtap_client::$draft::endpoint::{Endpoint, EndpointError};
            use moqtap_client::$draft::session::request_id::Role;
            use moqtap_client::$draft::session::state::SessionState;
            use moqtap_codec::$draft::error_codes::SessionErrorCode;
            #[allow(unused_imports)]
            use moqtap_codec::types::*;
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
                ControlMessage::TrackStatus(message::TrackStatus {
                    request_id: crate::v(id),
                    track_namespace: crate::namespace(),
                    track_name: crate::name(),
                    parameters: vec![],
                })
            }

            /// An update naming `id`.
            ///
            /// Built against the identifier under test rather than a constant,
            /// which the two drafts before these could get away with: from
            /// draft-19 the message's own Request ID is compared with the
            /// stream's, and a mismatch is the same violation by a different
            /// route. A fixed 90 here would close the session for the wrong
            /// reason and the gate would still pass.
            fn update(id: u64) -> message::RequestUpdate {
                message::RequestUpdate { request_id: crate::v(id), parameters: vec![] }
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

            /// An update on the peer's track status stream closes the session.
            ///
            /// Section 10.9 gives the six request kinds an update may name and
            /// then says: "An endpoint that receives a REQUEST_UPDATE other
            /// than in the two cases above MUST close the session with a
            /// PROTOCOL_VIOLATION." TRACK_STATUS is not among the six, and
            /// Section
            #[doc = $sec]
            /// says so directly — "the subscriber cannot send REQUEST_UPDATE".
            ///
            /// The close code is asserted, not just the close. A session that
            /// ended for some other reason would satisfy a state check on its
            /// own, and PROTOCOL_VIOLATION is the half of the sentence that
            /// reaches the peer.
            ///
            /// # Ablation, measured
            ///
            /// `track_statuses` put back into the updatable set, which is what
            /// drafts 17 and 18 shipped and what the four gates above them
            /// catch there:
            ///
            /// ```text
            /// thread 'draft19::an_update_naming_a_track_status_the_peer_asked_for_closes_the_session'
            /// panicked at crates\moqtap-client\tests\a_track_status_is_not_a_subscription.rs:913:1:
            /// a track status is not one of the six kinds an update may name: ()
            /// ```
            ///
            /// It reddens two — this gate on both closing drafts — out of 40.
            /// The other two gates below stay green under it, because both fail
            /// at the earlier check on *whose* request it is and never reach the
            /// check on which kind it is. That is the measurement behind the
            /// warning on the next one.
            #[test]
            fn an_update_naming_a_track_status_the_peer_asked_for_closes_the_session() {
                let mut ep = asked();
                let err = ep
                    .receive_on_peer_request_stream(
                        crate::v(PEERS_ID),
                        ControlMessage::RequestUpdate(update(PEERS_ID)),
                    )
                    .expect_err("a track status is not one of the six kinds an update may name");
                assert!(
                    matches!(err, EndpointError::UnexpectedRequestUpdate(PEERS_ID)),
                    "the violation should name the track status; got {err:?}"
                );
                assert_eq!(
                    ep.session_state(),
                    SessionState::Closed,
                    "this draft says the session MUST close, unlike its four predecessors"
                );
                assert_eq!(
                    err.session_error_code(),
                    Some(SessionErrorCode::ProtocolViolation),
                    "and it closes with the code the sentence names"
                );
            }

            /// One naming this endpoint's own track status closes it too.
            ///
            /// A different branch reaches the same error. The two cases in
            /// Section 10.9 are both about a request the *peer* made, or a
            /// subscription this endpoint established with PUBLISH; a request
            /// of this endpoint's own is in neither, so it never reaches the
            /// check on which kind it is.
            ///
            /// That makes this gate weaker than it looks on its own, and it is
            /// here for the pair: were the kind check the only thing refusing a
            /// track status, this would still pass.
            #[test]
            fn an_update_naming_this_endpoints_own_track_status_closes_the_session() {
                let mut ep = active();
                let (ours, _) = ep
                    .track_status(crate::elsewhere(), crate::other_name(), vec![])
                    .expect("this endpoint may ask");
                let err = ep
                    .receive_request_update(ours, &update(ours.into_inner()))
                    .expect_err("a track status cannot be updated whichever end asked for it");
                assert!(
                    matches!(err, EndpointError::UnexpectedRequestUpdate(_)),
                    "the violation should name the track status; got {err:?}"
                );
                assert_eq!(ep.session_state(), SessionState::Closed, "and the session closes");
            }

            /// The close reaches no further than the kinds the sentence excludes.
            ///
            /// The control, and it has to be built from the peer's side here.
            /// On drafts 13 through 18 this endpoint's own advertisement was
            /// the updatable case; from draft-19 it is not, because case one is
            /// the peer updating a request the peer made. So the accepted
            /// update names a PUBLISH_NAMESPACE that arrived on the peer's
            /// stream, which is inside the sentence rather than outside it.
            ///
            /// Without this gate an endpoint that closed on every REQUEST_UPDATE
            /// would pass both gates above.
            #[test]
            fn an_update_naming_a_request_the_peer_made_is_still_accepted() {
                let mut ep = active();
                let _ = ep
                    .receive_request_on_stream(&ControlMessage::PublishNamespace(
                        message::PublishNamespace {
                            request_id: crate::v(PEERS_ID),
                            track_namespace: crate::elsewhere(),
                            parameters: vec![],
                        },
                    ))
                    .expect("the peer may advertise");
                ep.receive_request_update(crate::v(PEERS_ID), &update(PEERS_ID))
                    .expect("an advertisement the peer made is one of the six kinds");
                assert_eq!(ep.session_state(), SessionState::Active, "and it is not a close");
            }

            /// An update whose own Request ID disagrees with its stream's is the
            /// same violation by the other route.
            ///
            /// Section 10.9 puts the update "on the same bidi stream as the
            /// request", so the two identifiers name one request when the peer
            /// is conforming. A disagreement is refused rather than resolved to
            /// either of the two, which is the branch the `update` helper above
            /// exists to stay out of.
            #[test]
            fn an_update_that_disagrees_with_its_own_stream_closes_the_session() {
                let mut ep = asked();
                let err = ep
                    .receive_request_update(crate::v(PEERS_ID), &update(PEERS_ID + 2))
                    .expect_err("the update names a stream that is not its request's");
                assert!(
                    matches!(err, EndpointError::UnexpectedRequestUpdate(id) if id == PEERS_ID + 2),
                    "the violation should name the identifier the message carried; got {err:?}"
                );
                assert_eq!(ep.session_state(), SessionState::Closed, "and the session closes");
            }
        }
    };
}

closing_gates!(draft19, "draft19", "10.14");
closing_gates!(draft20, "draft20", "10.15");

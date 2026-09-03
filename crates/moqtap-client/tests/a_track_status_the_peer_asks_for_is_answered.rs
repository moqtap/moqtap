#![cfg(any(
    feature = "draft07",
    feature = "draft08",
    feature = "draft09",
    feature = "draft10",
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
))]

//! A track status the peer asks for is recorded, and answered exactly once.
//!
//! Drafts 07 through 12 state the rule about the answer outright. Draft-07
//! Section 6.12, drafts 08 and 09 Section 7.12, draft-10 Section 8.16,
//! draft-11 Section 8.17 and draft-12 Section 8.20 all say: "A TRACK_STATUS
//! message MUST be sent in response to each TRACK_STATUS_REQUEST." One answer
//! is owed and one is allowed, and the request carries no identifier of its own
//! before draft-11, so the track it names is what the answer is matched to.
//!
//! Draft-13 renamed the request to TRACK_STATUS and said what it is rather than
//! what answers it. Section 8.20: the receiver "treats it identically as if it
//! had received a SUBSCRIBE message, except it does not create downstream
//! subscription state or send any Objects". Drafts 14 through 16 carry the same
//! sentence at Section 9.20 and Section 9.19. The answer moves twice inside
//! that range: TRACK_STATUS_OK and TRACK_STATUS_ERROR on 13 and 14, and
//! REQUEST_OK and REQUEST_ERROR from 15.
//!
//! # What was here before
//!
//! Nothing on any of the ten. A TRACK_STATUS_REQUEST or a TRACK_STATUS that
//! arrived had its Request ID counted against the peer's sequence from draft-11
//! on and was then dropped; drafts 07 through 10, whose request carries no
//! Request ID, dropped it outright. A peer that asked this crate about a track
//! waited for an answer the crate had no record to build.
//!
//! Drafts 17 through 20 already carry all of this, because a request there
//! arrives on a stream of its own and one map holds both ends' requests.
//!
//! # Why none of this ends the session
//!
//! "MUST be sent in response to each" is addressed to the end that answers, and
//! this endpoint's job is not to send a second one. No draft names a close code
//! for a second answer arriving, so a second answer is refused where it is
//! asked for and the session goes on running. Every gate below checks that.
//!
//! # Ablations, measured
//!
//! Nine cuts are recorded here, each run and reverted, each on the gate it
//! reddens. The first of them reaches every gate in all three files, and the
//! direction is always the same: a request that cannot be kept or cannot be
//! found is one nothing downstream can answer, so the other two files go with
//! it. Nothing here reaches the other way.
//!
//! Two gates carry no cut: one says a track status is absent from the
//! subscriptions the peer opened, and the record it would have to appear in
//! holds a message of another type entirely, so nothing short of a new
//! conversion could put it there. The other refuses a second answer, which the
//! cut on the first answer already reddens.

#![allow(clippy::items_after_test_module)]

use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;

/// The namespace the peer asks about.
fn namespace() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec()])
}

/// A second namespace, for the request this endpoint makes of its own and for
/// the one the peer never sent.
fn elsewhere() -> TrackNamespace {
    TrackNamespace(vec![b"elsewhere".to_vec()])
}

fn name() -> Vec<u8> {
    b"video".to_vec()
}

fn other_name() -> Vec<u8> {
    b"audio".to_vec()
}

fn v(n: u64) -> VarInt {
    VarInt::from_u64(n).unwrap()
}

/// The request the peer sends, in the four shapes it takes across the ten
/// drafts: 07 through 10 name only the track, 11 and 12 add a Request ID and
/// parameters, 13 and 14 carry the whole of a SUBSCRIBE, and 15 and 16 cut it
/// back to the track and its parameters.
#[macro_export]
macro_rules! peers_request {
    (plain, $id:expr, $ns:expr, $nm:expr) => {{
        let _ = $id;
        TrackStatusRequest { track_namespace: $ns, track_name: $nm }
    }};
    (ided, $id:expr, $ns:expr, $nm:expr) => {
        TrackStatusRequest {
            request_id: $crate::v($id),
            track_namespace: $ns,
            track_name: $nm,
            parameters: vec![],
        }
    };
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

/// The single answer drafts 07 through 12 allow, which names the track up to
/// draft-10 and the Request ID after it.
#[macro_export]
macro_rules! we_answer {
    (by_track, $ep:expr, $id:expr, $ns:expr, $nm:expr) => {{
        let _ = $id;
        $ep.send_track_status($ns, $nm, $crate::v(0), $crate::v(0), $crate::v(0))
    }};
    (by_id, $ep:expr, $id:expr, $ns:expr, $nm:expr) => {{
        let _ = ($ns, $nm);
        $ep.send_track_status(
            $crate::v($id),
            $crate::v(0),
            Location { group: $crate::v(0), object: $crate::v(0) },
            vec![],
        )
    }};
}

/// Accepting one on the drafts that have a pair of answers.
#[macro_export]
macro_rules! we_accept {
    (named, $ep:expr, $id:expr) => {
        $ep.send_track_status_ok($crate::v($id), $crate::v(0), GroupOrder::Ascending, vec![])
    };
    (request, $ep:expr, $id:expr) => {
        $ep.send_request_ok($crate::v($id), Vec::new())
    };
}

/// Refusing one. Draft-16's REQUEST_ERROR carries a retry interval the one
/// before it does not.
#[macro_export]
macro_rules! we_refuse {
    (named, $ep:expr, $id:expr) => {
        $ep.send_track_status_error($crate::v($id), $crate::v(0), b"no".to_vec())
    };
    (request, $ep:expr, $id:expr) => {
        $ep.send_request_error($crate::v($id), $crate::v(0), b"no".to_vec())
    };
    (retry, $ep:expr, $id:expr) => {
        $ep.send_request_error($crate::v($id), $crate::v(0), $crate::v(0), b"no".to_vec())
    };
}

/// The request the peer sent that is still waiting for an answer.
#[macro_export]
macro_rules! still_waiting {
    (by_track, $ep:expr, $id:expr, $ns:expr, $nm:expr) => {{
        let _ = $id;
        $ep.pending_track_status_request(&$ns, &$nm)
    }};
    (by_id_req, $ep:expr, $id:expr, $ns:expr, $nm:expr) => {{
        let _ = ($ns, $nm);
        $ep.pending_track_status_request($crate::v($id))
    }};
    (by_id, $ep:expr, $id:expr, $ns:expr, $nm:expr) => {{
        let _ = ($ns, $nm);
        $ep.pending_track_status($crate::v($id))
    }};
}

/// A track status this endpoint asks for, so that the peer's cannot be
/// confused with it.
#[macro_export]
macro_rules! our_own {
    (plain, $ep:expr) => {
        $ep.track_status_request($crate::elsewhere(), $crate::other_name())
    };
    (ided, $ep:expr) => {
        $ep.track_status_request($crate::elsewhere(), $crate::other_name())
    };
    (ided_params, $ep:expr) => {
        $ep.track_status_request($crate::elsewhere(), $crate::other_name(), Vec::new())
    };
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
    (params, $ep:expr) => {
        $ep.track_status($crate::elsewhere(), $crate::other_name(), vec![])
    };
}

/// What the acceptance says about a Track Alias. Drafts 13 and 14 carry one and
/// the draft fixes its value; drafts 15 and 16 carry none at all.
#[macro_export]
macro_rules! alias_reads {
    (zero, $msg:expr) => {
        match $msg {
            ControlMessage::TrackStatusOk(ref ok) => assert_eq!(
                ok.track_alias.into_inner(),
                0,
                "the acceptance sets Track Alias to 0 and this draft allows no other value"
            ),
            ref other => panic!("the acceptance should be a TRACK_STATUS_OK; got {other:?}"),
        }
    };
    (absent, $msg:expr) => {
        assert!(
            matches!($msg, ControlMessage::RequestOk(_)),
            "this draft's acceptance carries no Track Alias at all"
        )
    };
}

/// The setup parameters each draft requires. Draft-07 requires a ROLE of both
/// endpoints and is the only one of the ten that does.
#[macro_export]
macro_rules! setup_params {
    (role) => {
        vec![KeyValuePair { key: $crate::v(0x00), value: KvpValue::Varint($crate::v(3)) }]
    };
    (none) => {
        Vec::new()
    };
}

/// The same, plus the ceiling the peer must grant before this endpoint may open
/// a request of its own.
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

/// SERVER_SETUP, which carries a selected version up to draft-14 and leaves it
/// to the ALPN afterwards.
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
}

/// The eight gates for a draft whose request has exactly one answer.
macro_rules! single_answer_gates {
    ($draft:ident, $feat:literal, $version:expr, $role:path, $grant:ident, $params:tt,
     $setup:tt, $request:tt, $answer:tt, $pending:tt, $ours:tt, $unknown:ident,
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

            /// The identifier the peer asks under. On the drafts whose request
            /// carries none, nothing reads it.
            #[allow(dead_code)]
            const PEERS_ID: u64 = $peers_id;

            /// An identifier the peer asked nothing under. Unread on the drafts
            /// whose request carries no identifier at all.
            #[allow(dead_code)]
            const NEVER_USED: u64 = 7;

            /// A client with its session established and a budget granted to
            /// the peer, without which no request of the peer's is legal.
            fn active() -> Endpoint {
                let mut ep = Endpoint::new(Role::Client);
                ep.connect().expect("a client may open");
                crate::peers_setup!($setup, ep, $version, $params);
                let _ = ep.$grant($crate::v(100)).expect("a budget for the peer");
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "the gates need a running session"
                );
                ep
            }

            /// An endpoint holding the peer's unanswered request.
            fn asked() -> Endpoint {
                let mut ep = active();
                ep.receive_track_status_request(&crate::peers_request!(
                    $request,
                    PEERS_ID,
                    crate::namespace(),
                    crate::name()
                ))
                .expect("the peer may ask");
                ep
            }

            /// A track status the peer asks for is kept, rather than counted
            /// and dropped.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// the request the peer sent should be on record
            /// ```
            ///
            /// Made by dropping the record instead of inserting it, which is what
            /// all ten drafts did before. It reddens 87 tests across all three
            /// files: a request that is not kept is one no answer can find, and
            /// nothing that names it can be refused for the right reason either.
            #[test]
            fn a_track_status_the_peer_asks_for_is_recorded() {
                let ep = asked();
                assert!(
                    crate::still_waiting!(
                        $pending,
                        ep,
                        PEERS_ID,
                        crate::namespace(),
                        crate::name()
                    )
                    .is_some(),
                    "the request the peer sent should be on record"
                );
                assert_eq!(ep.pending_track_status_request_count(), 1, "one is waiting");
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "a request arriving is ordinary traffic"
                );
            }

            /// It is kept when it arrives the way it arrives on the wire, which
            /// is through the control stream's dispatcher.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// assertion `left == right` failed: the request should have
            /// reached the endpoint's record
            ///   left: 0
            ///  right: 1
            /// ```
            ///
            /// Made by cutting the dispatch arm, which sends the message back to
            /// the fall-through that accepts and ignores it - the state all ten
            /// drafts were in. It reddens 15 tests: this gate on all ten drafts,
            /// and the loopback gate on the five that have one.
            #[test]
            fn a_request_arriving_on_the_control_stream_is_recorded() {
                let mut ep = active();
                ep.receive_message(ControlMessage::TrackStatusRequest(crate::peers_request!(
                    $request,
                    PEERS_ID,
                    crate::namespace(),
                    crate::name()
                )))
                .expect("the peer may ask on the control stream");
                assert_eq!(
                    ep.pending_track_status_request_count(),
                    1,
                    "the request should have reached the endpoint's record"
                );
            }

            /// Answering it answers it, and it is no longer waiting.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// the request should be answered
            /// ```
            ///
            /// Made by building the answer without moving the flow, so the request
            /// stays where it was and could be answered again. It reddens 30 tests
            /// across two files.
            #[test]
            fn answering_a_track_status_answers_it() {
                let mut ep = asked();
                assert!(
                    crate::still_waiting!(
                        $pending,
                        ep,
                        PEERS_ID,
                        crate::namespace(),
                        crate::name()
                    )
                    .is_some(),
                    "it is waiting before the answer"
                );
                crate::we_answer!($answer, ep, PEERS_ID, crate::namespace(), crate::name())
                    .expect("answer the request");
                assert!(
                    crate::still_waiting!(
                        $pending,
                        ep,
                        PEERS_ID,
                        crate::namespace(),
                        crate::name()
                    )
                    .is_none(),
                    "the request should be answered"
                );
                assert_eq!(
                    ep.pending_track_status_request_count(),
                    0,
                    "nothing is waiting for an answer now"
                );
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "answering is ordinary traffic"
                );
            }

            /// One request takes one answer.
            #[test]
            fn a_track_status_is_answered_once() {
                let mut ep = asked();
                crate::we_answer!($answer, ep, PEERS_ID, crate::namespace(), crate::name())
                    .expect("answer the request");
                let err =
                    crate::we_answer!($answer, ep, PEERS_ID, crate::namespace(), crate::name())
                        .expect_err(concat!(
                            "Section ",
                            $sec,
                            " owes one TRACK_STATUS to each request and allows no second"
                        ));
                assert!(
                    matches!(err, EndpointError::TrackStatus(_) | EndpointError::$unknown { .. }),
                    "the second answer should be refused; got {err:?}"
                );
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "refusing to send a second answer is not a close"
                );
            }

            /// An answer to a request that never arrived has nothing to answer.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// nothing was asked about that: TrackStatus(TrackStatus {
            /// track_namespace: TrackNamespace(...), ... })
            /// ```
            ///
            /// Made by having the answer take the first record it finds rather than
            /// the one its key names, so a caller naming a track nobody asked about
            /// is handed someone else's request. It reddens 15 tests across two
            /// files.
            #[test]
            fn an_answer_to_a_request_that_never_arrived_is_refused() {
                let mut ep = asked();
                let err =
                    crate::we_answer!($answer, ep, NEVER_USED, crate::elsewhere(), crate::name())
                        .expect_err("nothing was asked about that");
                assert!(
                    matches!(err, EndpointError::$unknown { .. }),
                    "the miss should name the peer's record; got {err:?}"
                );
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "a caller's mistake is not a close"
                );
            }

            /// Two requests are answered independently, so answering one leaves
            /// the other waiting.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// assertion `left == right` failed: answering one should leave
            /// the other waiting
            ///   left: 2
            ///  right: 1
            /// ```
            ///
            /// Made by having the count ignore whether a request has been answered.
            /// It reddens 16 tests: the count is what says a request is outstanding,
            /// so a count that never falls says every request still is.
            #[test]
            fn answering_one_request_leaves_the_other_waiting() {
                let mut ep = asked();
                ep.receive_track_status_request(&crate::peers_request!(
                    $request,
                    PEERS_ID + 2,
                    crate::namespace(),
                    crate::other_name()
                ))
                .expect("the peer may ask about a second track");
                assert_eq!(ep.pending_track_status_request_count(), 2, "both are waiting");
                crate::we_answer!($answer, ep, PEERS_ID, crate::namespace(), crate::name())
                    .expect("answer the first");
                assert_eq!(
                    ep.pending_track_status_request_count(),
                    1,
                    "answering one should leave the other waiting"
                );
                assert!(
                    crate::still_waiting!(
                        $pending,
                        ep,
                        PEERS_ID + 2,
                        crate::namespace(),
                        crate::other_name()
                    )
                    .is_some(),
                    "the second request is the one still waiting"
                );
            }

            /// The peer's request does not join the ones this endpoint made.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// assertion `left == right` failed: the peer's request should not
            /// join the ones this endpoint made
            ///   left: 2
            ///  right: 1
            /// ```
            ///
            /// Made by recording the arriving request in this endpoint's own map as
            /// well as the peer's. It reddens 16 tests, this gate and the one after
            /// it on every draft that has both.
            #[test]
            fn the_peers_request_is_kept_apart_from_this_endpoints_own() {
                let mut ep = active();
                let _ = crate::our_own!($ours, ep).expect("this endpoint may ask too");
                assert_eq!(ep.active_track_status_count(), 1, "one of ours is outstanding");
                ep.receive_track_status_request(&crate::peers_request!(
                    $request,
                    PEERS_ID,
                    crate::namespace(),
                    crate::name()
                ))
                .expect("the peer may ask");
                assert_eq!(
                    ep.active_track_status_count(),
                    1,
                    "the peer's request should not join the ones this endpoint made"
                );
                assert_eq!(
                    ep.pending_track_status_request_count(),
                    1,
                    "it is on the peer's side of the record"
                );
            }

            /// And answering the peer's leaves this endpoint's own alone.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// assertion `left == right` failed: this endpoint's own request
            /// should still be outstanding
            ///   left: 2
            ///  right: 1
            /// ```
            ///
            /// The same cut, one moment later: this is the half of it that says the
            /// peer's request never becomes one of ours.
            #[test]
            fn answering_the_peers_request_leaves_this_endpoints_own_alone() {
                let mut ep = active();
                let _ = crate::our_own!($ours, ep).expect("this endpoint may ask too");
                ep.receive_track_status_request(&crate::peers_request!(
                    $request,
                    PEERS_ID,
                    crate::namespace(),
                    crate::name()
                ))
                .expect("the peer may ask");
                crate::we_answer!($answer, ep, PEERS_ID, crate::namespace(), crate::name())
                    .expect("answer the peer");
                assert_eq!(
                    ep.active_track_status_count(),
                    1,
                    "this endpoint's own request should still be outstanding"
                );
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "answering the peer is ordinary traffic"
                );
            }
        }
    };
}

/// The ten gates for a draft whose request has a pair of answers.
macro_rules! two_answer_gates {
    ($draft:ident, $feat:literal, $version:expr, $role:path, $grant:ident, $params:tt,
     $setup:tt, $request:tt, $accept:tt, $refuse:tt, $ours:tt, $alias:tt,
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

            /// The identifier the peer asks under.
            const PEERS_ID: u64 = $peers_id;

            /// An identifier the peer asked nothing under.
            const NEVER_USED: u64 = 7;

            fn active() -> Endpoint {
                let mut ep = Endpoint::new(Role::Client);
                ep.connect().expect("a client may open");
                crate::peers_setup!($setup, ep, $version, $params);
                let _ = ep.$grant($crate::v(100)).expect("a budget for the peer");
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "the gates need a running session"
                );
                ep
            }

            /// An endpoint holding the peer's unanswered request.
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

            /// A track status the peer asks for is kept, rather than counted
            /// and dropped.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// the request the peer sent should be on record
            /// ```
            ///
            /// Made by dropping the record instead of inserting it, which is what
            /// all ten drafts did before. It reddens 87 tests across all three
            /// files.
            #[test]
            fn a_track_status_the_peer_asks_for_is_recorded() {
                let ep = asked();
                assert!(
                    ep.pending_track_status(crate::v(PEERS_ID)).is_some(),
                    "the request the peer sent should be on record"
                );
                assert_eq!(ep.pending_track_status_count(), 1, "one is waiting");
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "a request arriving is ordinary traffic"
                );
            }

            /// It is kept when it arrives the way it arrives on the wire.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// assertion `left == right` failed: the request should have
            /// reached the endpoint's record
            ///   left: 0
            ///  right: 1
            /// ```
            ///
            /// Made by cutting the dispatch arm. It reddens 15 tests: this gate on
            /// all ten drafts and the loopback gate on the five that have one.
            #[test]
            fn a_request_arriving_on_the_control_stream_is_recorded() {
                let mut ep = active();
                ep.receive_message(ControlMessage::TrackStatus(crate::peers_request!(
                    $request,
                    PEERS_ID,
                    crate::namespace(),
                    crate::name()
                )))
                .expect("the peer may ask on the control stream");
                assert_eq!(
                    ep.pending_track_status_count(),
                    1,
                    "the request should have reached the endpoint's record"
                );
            }

            /// Accepting it answers it.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// the request should be answered
            /// ```
            ///
            /// Made by building the acceptance without moving the flow. It reddens
            /// 30 tests across two files: nothing downstream of an answer happens
            /// if the answer leaves no trace.
            #[test]
            fn accepting_a_track_status_answers_it() {
                let mut ep = asked();
                crate::we_accept!($accept, ep, PEERS_ID).expect("accept the request");
                assert!(
                    ep.pending_track_status(crate::v(PEERS_ID)).is_none(),
                    "the request should be answered"
                );
                assert_eq!(ep.pending_track_status_count(), 0, "nothing is waiting now");
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "answering is ordinary traffic"
                );
            }

            /// Refusing it answers it too.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// the refusal should answer it
            /// ```
            ///
            /// The same cut on the refusal. It reddens 8 tests: this gate and the
            /// one after it on each of the four drafts with a pair of answers.
            #[test]
            fn refusing_a_track_status_answers_it() {
                let mut ep = asked();
                crate::we_refuse!($refuse, ep, PEERS_ID).expect("refuse the request");
                assert!(
                    ep.pending_track_status(crate::v(PEERS_ID)).is_none(),
                    "the refusal should answer it"
                );
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "a refusal is a message, not a close"
                );
            }

            /// One request takes one acceptance.
            #[test]
            fn a_track_status_is_accepted_once() {
                let mut ep = asked();
                crate::we_accept!($accept, ep, PEERS_ID).expect("accept the request");
                let err = crate::we_accept!($accept, ep, PEERS_ID).expect_err(concat!(
                    "Section ",
                    $sec,
                    " gives a track status one answer, as it gives a SUBSCRIBE one"
                ));
                assert!(
                    matches!(err, EndpointError::TrackStatus(_)),
                    "the second acceptance should be refused by the flow; got {err:?}"
                );
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "refusing to send a second answer is not a close"
                );
            }

            /// And one already accepted cannot then be refused.
            #[test]
            fn a_track_status_accepted_cannot_then_be_refused() {
                let mut ep = asked();
                crate::we_accept!($accept, ep, PEERS_ID).expect("accept the request");
                let err = crate::we_refuse!($refuse, ep, PEERS_ID)
                    .expect_err("the request has already been answered");
                assert!(
                    matches!(err, EndpointError::TrackStatus(_)),
                    "the refusal after an acceptance should be refused; got {err:?}"
                );
            }

            /// An answer to a request that never arrived has nothing to answer.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// nothing was asked under that identifier: TrackStatusOk(
            /// TrackStatusOk { request_id: VarInt(7), track_alias: VarInt(0), ... })
            /// ```
            ///
            /// Made by having the answer take the first record it finds rather than
            /// the one its identifier names. It reddens 15 tests across two files.
            #[test]
            fn an_answer_to_a_request_that_never_arrived_is_refused() {
                let mut ep = asked();
                let err = crate::we_accept!($accept, ep, NEVER_USED)
                    .expect_err("nothing was asked under that identifier");
                assert!(
                    matches!(err, EndpointError::UnknownRequest(NEVER_USED)),
                    "the miss should name the identifier; got {err:?}"
                );
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "a caller's mistake is not a close"
                );
            }

            /// The request is treated as a SUBSCRIBE without becoming one: it
            /// creates no downstream subscription state.
            #[test]
            fn a_track_status_the_peer_asks_for_is_not_a_subscription() {
                let ep = asked();
                assert!(
                    ep.pending_subscribe(crate::v(PEERS_ID)).is_none(),
                    "a track status should not appear among the subscriptions the peer opened"
                );
                assert_eq!(
                    ep.pending_subscribe_count(),
                    0,
                    "no subscription state is created by a track status"
                );
            }

            /// The acceptance hands out no alias that could collide with one,
            /// so two of them in a session do not tread on each other.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// assertion `left == right` failed: the acceptance sets Track Alias
            /// to 0 and this draft allows no other value
            ///   left: 7
            ///  right: 0
            /// ```
            ///
            /// Made by putting a live-looking alias in the acceptance. It reddens 2
            /// tests, this gate on the two drafts whose answer carries an alias at
            /// all: the caller cannot choose the value, so the only way a wrong one
            /// reaches the wire is for this builder to write it.
            #[test]
            fn two_track_statuses_are_accepted_though_the_alias_is_the_same() {
                let mut ep = asked();
                ep.receive_track_status(&crate::peers_request!(
                    $request,
                    PEERS_ID + 2,
                    crate::elsewhere(),
                    crate::other_name()
                ))
                .expect("the peer may ask about a second track");
                let first = crate::we_accept!($accept, ep, PEERS_ID).expect("accept the first");
                crate::alias_reads!($alias, first);
                let second = crate::we_accept!($accept, ep, PEERS_ID + 2).expect(concat!(
                    "Section ",
                    $sec,
                    " does not let one track status refuse another over an alias"
                ));
                crate::alias_reads!($alias, second);
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "two answers to two requests are ordinary traffic"
                );
            }

            /// The peer's request does not join the ones this endpoint made.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// assertion `left == right` failed: the peer's request should not
            /// join the ones this endpoint made
            ///   left: 2
            ///  right: 1
            /// ```
            ///
            /// Made by recording the arriving request in this endpoint's own map as
            /// well as the peer's. It reddens 16 tests across the ten drafts.
            #[test]
            fn the_peers_request_is_kept_apart_from_this_endpoints_own() {
                let mut ep = active();
                let _ = crate::our_own!($ours, ep).expect("this endpoint may ask too");
                assert_eq!(ep.active_track_status_count(), 1, "one of ours is outstanding");
                ep.receive_track_status(&crate::peers_request!(
                    $request,
                    PEERS_ID,
                    crate::namespace(),
                    crate::name()
                ))
                .expect("the peer may ask");
                assert_eq!(
                    ep.active_track_status_count(),
                    1,
                    "the peer's request should not join the ones this endpoint made"
                );
                assert_eq!(
                    ep.pending_track_status_count(),
                    1,
                    "it is on the peer's side of the record"
                );
            }
        }
    };
}

/// A SUBSCRIBE the peer opens, so that a live track can hold Track Alias 0.
#[macro_export]
macro_rules! peers_subscribe {
    (d13, $id:expr) => {
        Subscribe {
            request_id: $crate::v($id),
            track_namespace: $crate::elsewhere(),
            track_name: $crate::other_name(),
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
    (d14, $id:expr) => {
        Subscribe {
            request_id: $crate::v($id),
            track_namespace: $crate::elsewhere(),
            track_name: $crate::other_name(),
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            forward: Forward::Forward,
            filter_type: FilterType::LargestObject,
            start_location: None,
            end_group: None,
            parameters: vec![],
        }
    };
}

/// The one gate for a draft whose acceptance carries a Track Alias the draft
/// pins to zero, and says outright that zero may already be taken.
macro_rules! alias_carve_out_gates {
    ($modname:ident, $draft:ident, $feat:literal, $version:expr, $role:path,
     $request:tt, $subscribe:tt, $sec:literal) => {
        #[cfg(feature = $feat)]
        mod $modname {
            use moqtap_client::$draft::endpoint::Endpoint;
            use moqtap_client::$draft::session::state::SessionState;
            use $role as Role;

            use moqtap_codec::kvp::{KeyValuePair, KvpValue};
            #[allow(unused_imports)]
            use moqtap_codec::types::*;
            #[allow(unused_imports)]
            use moqtap_codec::varint::VarInt;
            use moqtap_codec::$draft::message::*;

            const PEERS_ID: u64 = 1;

            /// The peer's subscription, which this endpoint accepts with Track
            /// Alias 0 so that a live track holds the value the answer to a
            /// track status is pinned to.
            const SUBSCRIPTION_ID: u64 = 3;

            fn active() -> Endpoint {
                let mut ep = Endpoint::new(Role::Client);
                ep.connect().expect("a client may open");
                crate::peers_setup!(versioned, ep, $version, none);
                let _ = ep.send_max_request_id($crate::v(100)).expect("a budget for the peer");
                ep
            }

            /// An endpoint on which Track Alias 0 is held by a live track.
            fn alias_zero_in_use() -> Endpoint {
                let mut ep = active();
                ep.receive_subscribe(&crate::peers_subscribe!($subscribe, SUBSCRIPTION_ID))
                    .expect("the peer may subscribe");
                ep.send_subscribe_ok(
                    crate::v(SUBSCRIPTION_ID),
                    crate::v(0),
                    crate::v(0),
                    GroupOrder::Ascending,
                    vec![],
                )
                .expect("accepting it binds Track Alias 0 to that track");
                ep
            }

            /// A track status is accepted even though a live track already
            /// holds the alias its answer carries.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// Section 8.21: it is not an error if Track Alias 0 is already in
            /// use: TrackAliasInUse { alias: 0, held: 3 }
            /// ```
            ///
            /// Made by having the acceptance consult the alias table a SUBSCRIBE_OK
            /// is judged against, and add its own alias to it. It reddens 2 tests,
            /// this gate on both drafts that carry an alias. The cut is what the
            /// sentence in Section 8.21 exists to forbid, and without a live track
            /// holding alias 0 it reddens nothing at all - which is why this gate
            /// opens with a subscription rather than with an empty session.
            #[test]
            fn a_track_status_is_accepted_though_a_live_track_holds_alias_zero() {
                let mut ep = alias_zero_in_use();
                ep.receive_track_status(&crate::peers_request!(
                    $request,
                    PEERS_ID,
                    crate::namespace(),
                    crate::name()
                ))
                .expect("the peer may ask");
                let msg = crate::we_accept!(named, ep, PEERS_ID).expect(concat!(
                    "Section ",
                    $sec,
                    ": it is not an error if Track Alias 0 is already in use"
                ));
                crate::alias_reads!(zero, msg);
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "and it is not a close either"
                );
            }
        }
    };
}

single_answer_gates!(
    draft07,
    "draft07",
    0xff00_0007,
    moqtap_client::draft07::endpoint::Role,
    send_max_subscribe_id,
    role,
    versioned,
    plain,
    by_track,
    by_track,
    plain,
    UnknownPeerTrackStatus,
    0,
    "6.12"
);
single_answer_gates!(
    draft08,
    "draft08",
    0xff00_0008,
    moqtap_client::draft08::endpoint::Role,
    send_max_subscribe_id,
    none,
    versioned,
    plain,
    by_track,
    by_track,
    plain,
    UnknownPeerTrackStatus,
    0,
    "7.12"
);
single_answer_gates!(
    draft09,
    "draft09",
    0xff00_0009,
    moqtap_client::draft09::endpoint::Role,
    send_max_subscribe_id,
    none,
    versioned,
    plain,
    by_track,
    by_track,
    plain,
    UnknownPeerTrackStatus,
    0,
    "7.12"
);
single_answer_gates!(
    draft10,
    "draft10",
    0xff00_000a,
    moqtap_client::draft10::endpoint::Role,
    send_max_subscribe_id,
    none,
    versioned,
    plain,
    by_track,
    by_track,
    plain,
    UnknownPeerTrackStatus,
    0,
    "8.16"
);
single_answer_gates!(
    draft11,
    "draft11",
    0xff00_000b,
    moqtap_client::draft11::session::request_id::Role,
    send_max_request_id,
    none,
    versioned,
    ided,
    by_id,
    by_id_req,
    ided,
    UnknownRequest,
    1,
    "8.17"
);
single_answer_gates!(
    draft12,
    "draft12",
    0xff00_000c,
    moqtap_client::draft12::session::request_id::Role,
    send_max_request_id,
    none,
    versioned,
    ided,
    by_id,
    by_id_req,
    ided_params,
    UnknownRequest,
    1,
    "8.20"
);
two_answer_gates!(
    draft13,
    "draft13",
    0xff00_000d,
    moqtap_client::draft13::session::request_id::Role,
    send_max_request_id,
    none,
    versioned,
    subscribe13,
    named,
    named,
    sub13,
    zero,
    1,
    "8.20"
);
two_answer_gates!(
    draft14,
    "draft14",
    0xff00_000e,
    moqtap_client::draft14::session::request_id::Role,
    send_max_request_id,
    none,
    versioned,
    subscribe14,
    named,
    named,
    sub13,
    zero,
    1,
    "9.20"
);
two_answer_gates!(
    draft15,
    "draft15",
    0xff00_000f,
    moqtap_client::draft15::session::request_id::Role,
    send_max_request_id,
    none,
    alpn,
    simple,
    request,
    request,
    params,
    absent,
    1,
    "9.19"
);
two_answer_gates!(
    draft16,
    "draft16",
    0xff00_0010,
    moqtap_client::draft16::session::request_id::Role,
    send_max_request_id,
    none,
    alpn,
    simple,
    request,
    retry,
    params,
    absent,
    1,
    "9.19"
);

alias_carve_out_gates!(
    draft13_alias,
    draft13,
    "draft13",
    0xff00_000d,
    moqtap_client::draft13::session::request_id::Role,
    subscribe13,
    d13,
    "8.21"
);
alias_carve_out_gates!(
    draft14_alias,
    draft14,
    "draft14",
    0xff00_000e,
    moqtap_client::draft14::session::request_id::Role,
    subscribe14,
    d14,
    "9.21"
);

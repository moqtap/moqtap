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

//! An announcement the peer makes is recorded, answered once, and ended when
//! the peer withdraws it.
//!
//! Draft-07 Section 5.2: "The entity receiving the ANNOUNCE MUST send only a
//! single response to a given ANNOUNCE of either ANNOUNCE_OK or
//! ANNOUNCE_ERROR." Drafts 08 and 09 Section 4.2 and drafts 10 through 13
//! Section 5.2 state it the other way round - "A subscriber MUST send exactly
//! one ANNOUNCE_OK or ANNOUNCE_ERROR in response to an ANNOUNCE" - and add what
//! the other end does about a second: "The publisher SHOULD close the session
//! with a protocol error if it receives more than one." Drafts 14 through 16
//! Section 6.2 are the same sentence with the message renamed, and from
//! draft-15 the answer is a REQUEST_OK or a REQUEST_ERROR.
//!
//! What comes after the answer is the rest of the flow. The publisher stops
//! serving a namespace it advertised by withdrawing the announcement, which is
//! UNANNOUNCE up to draft-13 and PUBLISH_NAMESPACE_DONE after it. This endpoint
//! is the subscriber of an announcement that arrives, so it sends the answer
//! and receives the withdrawal - both the other way round from an announcement
//! it makes itself.
//!
//! # What was here before
//!
//! Nothing on any of the ten. An arriving ANNOUNCE or PUBLISH_NAMESPACE had its
//! Request ID counted against the peer's sequence from draft-11 on, and was
//! then dropped; drafts 07 through 10, which have no Request ID on the message,
//! dropped it outright. A peer that announced to this crate waited for an
//! answer the crate had no record to build.
//!
//! The withdrawal was worse than absent on drafts 14 through 16, which did
//! dispatch it: it walked the announcements this endpoint had made, because
//! those were the only ones on record. Draft-14 advanced every one of them at
//! once and ignored what they said about it.
//!
//! Drafts 17 through 19 already carry all of this, because a request there
//! arrives on a stream of its own and one map holds both ends' announcements.
//!
//! # Why none of this ends the session
//!
//! "MUST send exactly one" is addressed to the sender of the answer, and this
//! endpoint's job is not to send the second one. The SHOULD beside it belongs
//! to the publisher, which this endpoint is not for an announcement that
//! arrives. So a second answer is refused where it is asked for and the session
//! goes on running, and every gate below checks that.
//!
//! # Ablations, measured
//!
//! Seven cuts are recorded here, each run and reverted, each on the gate it
//! reddens. Two of them reach a long way past this file and the direction is
//! always the same: an announcement that cannot be kept or cannot be found is
//! one nothing downstream can act on, so the cancellation file and the
//! loopback file go with it. Nothing here reaches the other way.

#![allow(clippy::items_after_test_module)]

use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;

/// The namespace the peer advertises.
fn namespace() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec()])
}

/// A namespace nothing was ever announced under.
/// Unread in a build that enables only drafts whose gates do not use it.
#[allow(dead_code)]
fn elsewhere() -> TrackNamespace {
    TrackNamespace(vec![b"elsewhere".to_vec()])
}

fn v(n: u64) -> VarInt {
    VarInt::from_u64(n).unwrap()
}

/// The advertisement the peer sends, in the three shapes it takes across the
/// ten drafts: draft-07 through draft-10 name only the namespace, draft-11 adds
/// a Request ID, and draft-14 renames the message.
#[macro_export]
macro_rules! peers_advert {
    (plain, $id:expr, $ns:expr) => {{
        let _ = $id;
        Announce { track_namespace: $ns, parameters: vec![] }
    }};
    (ided, $id:expr, $ns:expr) => {
        Announce { request_id: $crate::v($id), track_namespace: $ns, parameters: vec![] }
    };
    (renamed, $id:expr, $ns:expr) => {
        PublishNamespace { request_id: $crate::v($id), track_namespace: $ns, parameters: vec![] }
    };
}

/// Accepting it, which names the announcement by namespace up to draft-10 and
/// by Request ID after it, and folds into REQUEST_OK from draft-15.
#[macro_export]
macro_rules! we_accept {
    (ns, $ep:expr, $id:expr, $ns:expr) => {{
        let _ = $id;
        $ep.send_announce_ok($ns)
    }};
    (id, $ep:expr, $id:expr, $ns:expr) => {
        $ep.send_announce_ok($crate::v($id))
    };
    (renamed, $ep:expr, $id:expr, $ns:expr) => {
        $ep.send_publish_namespace_ok($crate::v($id))
    };
    (request, $ep:expr, $id:expr, $ns:expr) => {
        $ep.send_request_ok($crate::v($id), Vec::new())
    };
}

/// Refusing it. Draft-16's REQUEST_ERROR carries a retry interval the one
/// before it does not.
#[macro_export]
macro_rules! we_refuse {
    (ns, $ep:expr, $id:expr, $ns:expr) => {{
        let _ = $id;
        $ep.send_announce_error($ns, $crate::v(0), b"no".to_vec())
    }};
    (id, $ep:expr, $id:expr, $ns:expr) => {
        $ep.send_announce_error($crate::v($id), $crate::v(0), b"no".to_vec())
    };
    (renamed, $ep:expr, $id:expr, $ns:expr) => {
        $ep.send_publish_namespace_error($crate::v($id), $crate::v(0), b"no".to_vec())
    };
    (request, $ep:expr, $id:expr, $ns:expr) => {
        $ep.send_request_error($crate::v($id), $crate::v(0), b"no".to_vec())
    };
    (retry, $ep:expr, $id:expr, $ns:expr) => {
        $ep.send_request_error($crate::v($id), $crate::v(0), $crate::v(0), b"no".to_vec())
    };
}

/// The withdrawal the peer sends, which names a namespace on nine of the ten
/// drafts and a Request ID on draft-16.
#[macro_export]
macro_rules! peers_withdrawal {
    (by_ns, $id:expr, $ns:expr) => {{
        let _ = $id;
        Unannounce { track_namespace: $ns }
    }};
    (renamed_ns, $id:expr, $ns:expr) => {{
        let _ = $id;
        PublishNamespaceDone { track_namespace: $ns }
    }};
    (renamed_id, $id:expr, $ns:expr) => {
        PublishNamespaceDone { request_id: $crate::v($id) }
    };
}

/// The announcement the peer made that is still waiting for an answer.
#[macro_export]
macro_rules! still_waiting {
    (ns, $ep:expr, $id:expr, $ns:expr) => {{
        let _ = $id;
        $ep.pending_announce(&$ns)
    }};
    (id, $ep:expr, $id:expr, $ns:expr) => {
        $ep.pending_announce($crate::v($id))
    };
    (renamed, $ep:expr, $id:expr, $ns:expr) => {
        $ep.pending_publish_namespace($crate::v($id))
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

/// One draft's ten gates.
macro_rules! inbound_announce_gates {
    ($draft:ident, $feat:literal, $version:expr, $role:path, $grant:ident, $params:tt,
     $setup:tt, $advert:tt, $accept:tt, $refuse:tt, $withdrawal:tt, $pending:tt,
     $recv:ident, $count:ident, $variant:ident, $donevariant:ident,
     $unknown_answer:ident, $unknown_withdrawal:ident, $peers_id:literal, $sec:literal) => {
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

            /// The identifier the peer opens its announcement under. On the
            /// drafts whose ANNOUNCE carries none, nothing reads it.
            #[allow(dead_code)]
            const PEERS_ID: u64 = $peers_id;

            /// An identifier the peer announced nothing under. Unread on the
            /// drafts whose announcement carries no identifier at all.
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

            /// An endpoint holding the peer's unanswered announcement.
            fn announced() -> Endpoint {
                let mut ep = active();
                ep.$recv(&crate::peers_advert!($advert, PEERS_ID, crate::namespace()))
                    .expect("the peer may announce");
                ep
            }

            /// The same, with the announcement accepted.
            fn accepted() -> Endpoint {
                let mut ep = announced();
                crate::we_accept!($accept, ep, PEERS_ID, crate::namespace())
                    .expect("accept the announcement");
                ep
            }

            /// An announcement the peer makes is kept, rather than counted and
            /// dropped.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// the announcement the peer made should be on record
            /// ```
            ///
            /// Made by dropping the record instead of inserting it, which is
            /// what all ten drafts did before. It reddens 170 tests across all
            /// four files: an announcement that is not kept is one no answer,
            /// no withdrawal and no cancellation can find.
            #[test]
            fn an_announcement_the_peer_makes_is_recorded() {
                let ep = announced();
                assert!(
                    crate::still_waiting!($pending, ep, PEERS_ID, crate::namespace()).is_some(),
                    "the announcement the peer made should be on record"
                );
                assert_eq!(ep.$count(), 1, "one announcement is waiting for an answer");
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "an announcement arriving is ordinary traffic"
                );
            }

            /// It is kept when it arrives the way it arrives on the wire, which
            /// is through the control stream's dispatcher.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// the announcement should have reached the endpoint's record
            ///   left: 0
            ///  right: 1
            /// ```
            ///
            /// Made by cutting the dispatch arm, which sends the message back
            /// to the fall-through that accepts and ignores it - the state all
            /// ten drafts were in. It reddens 20 tests: this gate on all ten
            /// drafts, and both loopback gates on the five that have them.
            #[test]
            fn an_announcement_arriving_on_the_control_stream_is_recorded() {
                let mut ep = active();
                ep.receive_message(ControlMessage::$variant(crate::peers_advert!(
                    $advert,
                    PEERS_ID,
                    crate::namespace()
                )))
                .expect("the peer may announce on the control stream");
                assert_eq!(
                    ep.$count(),
                    1,
                    "the announcement should have reached the endpoint's record"
                );
            }

            /// Accepting it answers it, and it is no longer waiting.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// the announcement should be answered
            /// ```
            ///
            /// Made by building the acceptance without moving the flow, so the
            /// announcement stays where it was and could be answered again. It
            /// reddens 85 tests across all four files: nothing downstream of an
            /// acceptance happens if the acceptance leaves no trace.
            #[test]
            fn accepting_an_announcement_answers_it() {
                let mut ep = announced();
                assert!(
                    crate::still_waiting!($pending, ep, PEERS_ID, crate::namespace()).is_some(),
                    "it is waiting before the answer"
                );
                crate::we_accept!($accept, ep, PEERS_ID, crate::namespace())
                    .expect("accept the announcement");
                assert!(
                    crate::still_waiting!($pending, ep, PEERS_ID, crate::namespace()).is_none(),
                    "the announcement should be answered"
                );
                assert_eq!(ep.$count(), 0, "nothing is waiting for an answer now");
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "answering is ordinary traffic"
                );
            }

            /// Refusing it answers it too, and the other way is closed.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// the refusal should answer it
            /// ```
            ///
            /// Made by building the refusal without moving the flow. It reddens
            /// 25 tests across two files.
            #[test]
            fn refusing_an_announcement_answers_it() {
                let mut ep = announced();
                crate::we_refuse!($refuse, ep, PEERS_ID, crate::namespace())
                    .expect("refuse the announcement");
                assert!(
                    crate::still_waiting!($pending, ep, PEERS_ID, crate::namespace()).is_none(),
                    "the refusal should answer it"
                );
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "a refusal is a message, not a close"
                );
            }

            /// One announcement takes one acceptance.
            #[test]
            fn an_announcement_is_accepted_once() {
                let mut ep = accepted();
                let err = crate::we_accept!($accept, ep, PEERS_ID, crate::namespace()).expect_err(
                    concat!("Section ", $sec, " allows exactly one answer to an announcement"),
                );
                assert!(
                    matches!(err, EndpointError::Namespace(_)),
                    "the second acceptance should be refused by the flow; got {err:?}"
                );
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "refusing to send a second answer is not a close"
                );
            }

            /// And an announcement already accepted cannot then be refused: the
            /// sentence allows one answer, not one of each.
            #[test]
            fn an_announcement_accepted_cannot_then_be_refused() {
                let mut ep = accepted();
                let err = crate::we_refuse!($refuse, ep, PEERS_ID, crate::namespace()).expect_err(
                    concat!("Section ", $sec, " allows exactly one answer to an announcement"),
                );
                assert!(
                    matches!(err, EndpointError::Namespace(_)),
                    "the second answer should be refused by the flow; got {err:?}"
                );
                assert_eq!(ep.session_state(), SessionState::Active, "still a message");
            }

            /// An answer to an announcement that never arrived is refused, and
            /// the refusal says which record came up empty.
            ///
            /// The endpoint holds one announcement while this runs, and the
            /// answer names a different one. An empty record cannot tell a
            /// lookup that reads its key from one that ignores it: both come up
            /// with nothing.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// there is nothing to accept: AnnounceOk(AnnounceOk { track_namespace: ... })
            /// ```
            ///
            /// Made by answering whichever announcement the record happens to
            /// hold instead of the one named, at every place that reads it. It
            /// reddens 20 tests: this gate, and the two beside it that name an
            /// announcement the peer never made.
            #[test]
            fn an_answer_to_an_announcement_that_never_arrived_is_refused() {
                let mut ep = announced();
                let err = crate::we_accept!($accept, ep, NEVER_USED, crate::elsewhere())
                    .expect_err("there is nothing to accept");
                assert!(
                    matches!(err, EndpointError::$unknown_answer { .. }),
                    "the miss should name the peer's announcements; got {err:?}"
                );
                assert_eq!(ep.session_state(), SessionState::Active, "still a message");
            }

            /// The peer withdraws an announcement this endpoint accepted, and
            /// the record ends.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// a withdrawal ends the announcement once: ()
            /// ```
            ///
            /// Made by leaving the flow where it was when the withdrawal
            /// arrives, so the same announcement could be withdrawn for ever.
            /// It reddens 20 tests, two per draft.
            #[test]
            fn the_peer_withdraws_an_announcement_this_endpoint_accepted() {
                let mut ep = accepted();
                ep.receive_message(ControlMessage::$donevariant(crate::peers_withdrawal!(
                    $withdrawal,
                    PEERS_ID,
                    crate::namespace()
                )))
                .expect("the peer may withdraw what it announced");
                let err = ep
                    .receive_message(ControlMessage::$donevariant(crate::peers_withdrawal!(
                        $withdrawal,
                        PEERS_ID,
                        crate::namespace()
                    )))
                    .expect_err("a withdrawal ends the announcement once");
                assert!(
                    matches!(
                        err,
                        EndpointError::Namespace(_) | EndpointError::$unknown_withdrawal { .. }
                    ),
                    "the second withdrawal should find nothing live; got {err:?}"
                );
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "a withdrawal is ordinary traffic"
                );
            }

            /// A withdrawal of an announcement this endpoint never answered is
            /// refused: there is nothing to stop serving.
            #[test]
            fn a_withdrawal_of_an_announcement_never_answered_is_refused() {
                let mut ep = announced();
                let err = ep
                    .receive_message(ControlMessage::$donevariant(crate::peers_withdrawal!(
                        $withdrawal,
                        PEERS_ID,
                        crate::namespace()
                    )))
                    .expect_err("nothing was accepted, so nothing can be withdrawn");
                assert!(
                    matches!(err, EndpointError::Namespace(_)),
                    "the flow should refuse it; got {err:?}"
                );
                assert_eq!(ep.session_state(), SessionState::Active, "still a message");
            }

            /// A withdrawal naming nothing the peer ever announced is refused,
            /// and the refusal says which record came up empty.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// the peer announced nothing under that name: ()
            /// ```
            ///
            /// Made by cutting the withdrawal's dispatch arm, so it reaches the
            /// fall-through that accepts and ignores it - which is where
            /// UNANNOUNCE went on all ten drafts. It reddens 30 tests, three
            /// per draft.
            #[test]
            fn a_withdrawal_for_an_announcement_that_never_arrived_is_refused() {
                let mut ep = accepted();
                let err = ep
                    .receive_message(ControlMessage::$donevariant(crate::peers_withdrawal!(
                        $withdrawal,
                        NEVER_USED,
                        crate::elsewhere()
                    )))
                    .expect_err("the peer announced nothing under that name");
                assert!(
                    matches!(err, EndpointError::$unknown_withdrawal { .. }),
                    "the miss should name the peer's announcements; got {err:?}"
                );
                assert_eq!(ep.session_state(), SessionState::Active, "still a message");
            }
        }
    };
}

inbound_announce_gates!(
    draft07,
    "draft07",
    0xff00_0007,
    moqtap_client::draft07::endpoint::Role,
    send_max_subscribe_id,
    role,
    versioned,
    plain,
    ns,
    ns,
    by_ns,
    ns,
    receive_announce,
    pending_announce_count,
    Announce,
    Unannounce,
    UnknownPeerNamespace,
    UnknownPeerNamespace,
    0,
    "5.2"
);
inbound_announce_gates!(
    draft08,
    "draft08",
    0xff00_0008,
    moqtap_client::draft08::endpoint::Role,
    send_max_subscribe_id,
    none,
    versioned,
    plain,
    ns,
    ns,
    by_ns,
    ns,
    receive_announce,
    pending_announce_count,
    Announce,
    Unannounce,
    UnknownPeerNamespace,
    UnknownPeerNamespace,
    0,
    "4.2"
);
inbound_announce_gates!(
    draft09,
    "draft09",
    0xff00_0009,
    moqtap_client::draft09::endpoint::Role,
    send_max_subscribe_id,
    none,
    versioned,
    plain,
    ns,
    ns,
    by_ns,
    ns,
    receive_announce,
    pending_announce_count,
    Announce,
    Unannounce,
    UnknownPeerNamespace,
    UnknownPeerNamespace,
    0,
    "4.2"
);
inbound_announce_gates!(
    draft10,
    "draft10",
    0xff00_000a,
    moqtap_client::draft10::endpoint::Role,
    send_max_subscribe_id,
    none,
    versioned,
    plain,
    ns,
    ns,
    by_ns,
    ns,
    receive_announce,
    pending_announce_count,
    Announce,
    Unannounce,
    UnknownPeerNamespace,
    UnknownPeerNamespace,
    0,
    "5.2"
);
inbound_announce_gates!(
    draft11,
    "draft11",
    0xff00_000b,
    moqtap_client::draft11::session::request_id::Role,
    send_max_request_id,
    none,
    versioned,
    ided,
    id,
    id,
    by_ns,
    id,
    receive_announce,
    pending_announce_count,
    Announce,
    Unannounce,
    UnknownRequest,
    UnknownPeerNamespace,
    1,
    "5.2"
);
inbound_announce_gates!(
    draft12,
    "draft12",
    0xff00_000c,
    moqtap_client::draft12::session::request_id::Role,
    send_max_request_id,
    none,
    versioned,
    ided,
    id,
    id,
    by_ns,
    id,
    receive_announce,
    pending_announce_count,
    Announce,
    Unannounce,
    UnknownRequest,
    UnknownPeerNamespace,
    1,
    "5.2"
);
inbound_announce_gates!(
    draft13,
    "draft13",
    0xff00_000d,
    moqtap_client::draft13::session::request_id::Role,
    send_max_request_id,
    none,
    versioned,
    ided,
    id,
    id,
    by_ns,
    id,
    receive_announce,
    pending_announce_count,
    Announce,
    Unannounce,
    UnknownRequest,
    UnknownPeerNamespace,
    1,
    "5.2"
);
inbound_announce_gates!(
    draft14,
    "draft14",
    0xff00_000e,
    moqtap_client::draft14::session::request_id::Role,
    send_max_request_id,
    none,
    versioned,
    renamed,
    renamed,
    renamed,
    renamed_ns,
    renamed,
    receive_publish_namespace,
    pending_publish_namespace_count,
    PublishNamespace,
    PublishNamespaceDone,
    UnknownRequest,
    UnknownPeerNamespace,
    1,
    "6.2"
);
inbound_announce_gates!(
    draft15,
    "draft15",
    0xff00_000f,
    moqtap_client::draft15::session::request_id::Role,
    send_max_request_id,
    none,
    alpn,
    renamed,
    request,
    request,
    renamed_ns,
    renamed,
    receive_publish_namespace,
    pending_publish_namespace_count,
    PublishNamespace,
    PublishNamespaceDone,
    UnknownRequest,
    UnknownPeerNamespace,
    1,
    "6.2"
);
inbound_announce_gates!(
    draft16,
    "draft16",
    0xff00_0010,
    moqtap_client::draft16::session::request_id::Role,
    send_max_request_id,
    none,
    alpn,
    renamed,
    request,
    retry,
    renamed_id,
    renamed,
    receive_publish_namespace,
    pending_publish_namespace_count,
    PublishNamespace,
    PublishNamespaceDone,
    UnknownRequest,
    UnknownRequest,
    1,
    "6.2"
);

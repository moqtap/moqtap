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

//! A cancellation revokes an acceptance, so there has to be one to revoke.
//!
//! Draft-07 Section 5.2, drafts 08 and 09 Section 6.2, draft-10 Section 7.2,
//! drafts 11 through 13 Section 7.3, draft-14 Section 8.4 and drafts 15 and 16
//! Section 8.5 all state it in one sentence: a subscriber says it will no
//! longer subscribe to tracks in a namespace "it previously responded
//! ANNOUNCE_OK to" - PUBLISH_NAMESPACE_OK on draft-14, REQUEST_OK on the two
//! after it - by sending the cancellation.
//!
//! "Previously responded OK to" is a state, and it is the one an announcement
//! reaches by being accepted and no other way. An announcement still waiting
//! for an answer has not been responded to at all; one refused was responded to
//! the other way; one already withdrawn or cancelled is over. All three are
//! refused here rather than sent.
//!
//! # Whose announcement it is
//!
//! The peer's. This endpoint responds OK to announcements that arrive, so those
//! are the only ones it can revoke an acceptance of. Its own announcements are
//! cancelled by the peer, and that arrives the other way.
//!
//! That distinction is the reason this file exists at all. Drafts 07 through 13
//! could not send a cancellation, and drafts 14 through 16 sent one that named
//! an announcement this endpoint had made - reading the only map there was.
//! Draft-14's built the message with an empty namespace and a zero code
//! whatever it was asked for.
//!
//! # Why none of this ends the session
//!
//! The sentence describes what a subscriber does, not what either end does
//! about a wrong one. A cancellation with nothing to revoke is refused where it
//! is asked for, and every gate below checks the session is still running.
//!
//! # Ablations, measured
//!
//! Four cuts are recorded here, each run and reverted, each on the gate it
//! reddens. One of them reaches only five drafts, which is the five whose
//! cancellation names a namespace while the announcement that opened it carried
//! a Request ID: there and nowhere else can a namespace stand for an
//! announcement that has ended.

#![allow(clippy::items_after_test_module)]

use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;

/// The namespace the peer advertises, and the one this endpoint advertises in
/// the gate that holds both at once.
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

/// Revoking the acceptance, which names the announcement by namespace on nine
/// of the ten drafts and by Request ID on draft-16.
#[macro_export]
macro_rules! we_cancel {
    (by_ns, $ep:expr, $id:expr, $ns:expr) => {{
        let _ = $id;
        $ep.announce_cancel($ns, $crate::v(1), b"expired".to_vec())
    }};
    (renamed_ns, $ep:expr, $id:expr, $ns:expr) => {{
        let _ = $id;
        $ep.publish_namespace_cancel($ns, $crate::v(1), b"expired".to_vec())
    }};
    (renamed_id, $ep:expr, $id:expr, $ns:expr) => {
        $ep.publish_namespace_cancel($crate::v($id), $crate::v(1), b"expired".to_vec())
    };
}

/// What the built cancellation has to name, which is the same thing said two
/// ways: the namespace up to draft-15, the Request ID on draft-16.
#[macro_export]
macro_rules! cancel_names {
    (by_ns, $msg:expr, $id:expr, $ns:expr) => {
        match $msg {
            ControlMessage::AnnounceCancel(c) => {
                assert_eq!(c.track_namespace, $ns, "the cancellation should name the namespace");
                assert_eq!(c.reason_phrase, b"expired".to_vec(), "and carry the reason given");
            }
            other => panic!("expected an ANNOUNCE_CANCEL; got {other:?}"),
        }
    };
    (renamed_ns, $msg:expr, $id:expr, $ns:expr) => {
        match $msg {
            ControlMessage::PublishNamespaceCancel(c) => {
                assert_eq!(c.track_namespace, $ns, "the cancellation should name the namespace");
                assert_eq!(c.reason_phrase, b"expired".to_vec(), "and carry the reason given");
            }
            other => panic!("expected a PUBLISH_NAMESPACE_CANCEL; got {other:?}"),
        }
    };
    (renamed_id, $msg:expr, $id:expr, $ns:expr) => {
        match $msg {
            ControlMessage::PublishNamespaceCancel(c) => {
                assert_eq!(
                    c.request_id,
                    $crate::v($id),
                    "the cancellation should name the announcement"
                );
                assert_eq!(c.reason_phrase, b"expired".to_vec(), "and carry the reason given");
            }
            other => panic!("expected a PUBLISH_NAMESPACE_CANCEL; got {other:?}"),
        }
    };
}

/// How an announcement that has already ended reads back when it is named
/// again. Drafts 07 through 10 file the record under the namespace and
/// draft-16 under the Request ID, so the ended record is found and the flow
/// refuses the transition. Drafts 11 through 15 name a namespace where the
/// announcement carried a Request ID, and a namespace can only stand for a
/// live announcement: one that has ended is a namespace the peer has nothing
/// under, which is the other refusal and not a weaker one.
#[macro_export]
macro_rules! ended_reads_as {
    (flow, $err:expr) => {
        matches!($err, EndpointError::Namespace(_))
    };
    (missing, $err:expr) => {
        matches!($err, EndpointError::UnknownPeerNamespace)
    };
}

/// This endpoint withdrawing what it announced, for the gate that holds one
/// announcement of each.
#[macro_export]
macro_rules! we_withdraw {
    (by_ns, $ep:expr, $id:expr, $ns:expr) => {{
        let _ = $id;
        $ep.unannounce($ns)
    }};
    (renamed_ns, $ep:expr, $id:expr, $ns:expr) => {{
        let _ = $id;
        $ep.publish_namespace_done($ns)
    }};
    (renamed_id, $ep:expr, $id:expr, $ns:expr) => {
        $ep.publish_namespace_done($id)
    };
}

/// An announcement of this endpoint's own, for the gate that holds one of each.
#[macro_export]
macro_rules! we_announce {
    (bare, $ep:expr) => {{
        let _ = $ep.announce($crate::namespace()).expect("this endpoint may announce");
        $crate::v(0)
    }};
    (ided, $ep:expr) => {{
        let (id, _) = $ep.announce($crate::namespace()).expect("this endpoint may announce");
        id
    }};
    (ided_params, $ep:expr) => {{
        let (id, _) =
            $ep.announce($crate::namespace(), vec![]).expect("this endpoint may announce");
        id
    }};
    (renamed, $ep:expr) => {{
        let (id, _) = $ep
            .publish_namespace($crate::namespace(), Vec::new())
            .expect("this endpoint may announce");
        id
    }};
    (params, $ep:expr) => {{
        let (id, _) =
            $ep.publish_namespace($crate::namespace(), vec![]).expect("this endpoint may announce");
        id
    }};
}

/// The peer accepting an announcement this endpoint made, which only succeeds
/// while that announcement is still waiting for an answer.
#[macro_export]
macro_rules! peer_accepts_ours {
    (ns, $ep:expr, $id:expr) => {{
        let _ = $id;
        $ep.receive_announce_ok(&AnnounceOk { track_namespace: $crate::namespace() })
    }};
    (id, $ep:expr, $id:expr) => {
        $ep.receive_announce_ok(&AnnounceOk { request_id: $id })
    };
    (renamed, $ep:expr, $id:expr) => {
        $ep.receive_publish_namespace_ok(&PublishNamespaceOk { request_id: $id })
    };
    (request, $ep:expr, $id:expr) => {
        $ep.receive_request_ok(&RequestOk { request_id: $id, parameters: vec![] })
    };
}

#[macro_export]
macro_rules! setup_params {
    (role) => {
        vec![KeyValuePair { key: $crate::v(0x00), value: KvpValue::Varint($crate::v(3)) }]
    };
    (none) => {
        Vec::new()
    };
}

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

/// One draft's six gates.
macro_rules! cancellation_gates {
    ($draft:ident, $feat:literal, $version:expr, $role:path, $grant:ident, $params:tt,
     $setup:tt, $advert:tt, $accept:tt, $refuse:tt, $cancel:tt, $ours:tt, $theirok:tt,
     $recv:ident, $unknown:ident, $ended:tt, $withdraw:tt, $peers_id:literal,
     $sec:literal,
     $okname:literal) => {
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

            fn announced() -> Endpoint {
                let mut ep = active();
                ep.$recv(&crate::peers_advert!($advert, PEERS_ID, crate::namespace()))
                    .expect("the peer may announce");
                ep
            }

            fn accepted() -> Endpoint {
                let mut ep = announced();
                crate::we_accept!($accept, ep, PEERS_ID, crate::namespace())
                    .expect("accept the announcement");
                ep
            }

            /// An announcement this endpoint accepted can be cancelled, and the
            /// message names it.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// the cancellation should name the namespace
            ///   left: TrackNamespace([])
            ///  right: TrackNamespace([[99, 111, 110, ...]])
            /// ```
            ///
            /// Made by building the cancellation with an empty namespace, which
            /// is what draft-14's did for every announcement it was ever asked
            /// about. It reaches the nine drafts that name the announcement
            /// that way and reddens 13 tests: this gate on all nine, and the
            /// loopback gate on the four of them that have one, where an empty
            /// namespace does not reach the wire at all.
            #[test]
            fn an_announcement_this_endpoint_accepted_can_be_cancelled() {
                let mut ep = accepted();
                let msg = crate::we_cancel!($cancel, ep, PEERS_ID, crate::namespace())
                    .expect(concat!("Section ", $sec, " lets a subscriber revoke an acceptance"));
                crate::cancel_names!($cancel, msg, PEERS_ID, crate::namespace());
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "a cancellation is ordinary traffic"
                );
            }

            /// One still waiting for an answer cannot be: nothing has responded
            /// to it yet.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// nothing has responded to it, so there is no acceptance to revoke:
            /// AnnounceCancel(AnnounceCancel { track_namespace: ... })
            /// ```
            ///
            /// Made by building the cancellation without moving the flow, so
            /// there is no state for the rule to be about. It reddens 25 tests,
            /// all three of the gates that turn on which state the announcement
            /// is in.
            #[test]
            fn an_announcement_still_waiting_cannot_be_cancelled() {
                let mut ep = announced();
                let err = crate::we_cancel!($cancel, ep, PEERS_ID, crate::namespace())
                    .expect_err("nothing has responded to it, so there is no acceptance to revoke");
                assert!(
                    matches!(err, EndpointError::Namespace(_)),
                    concat!(
                        "Section ",
                        $sec,
                        " revokes a namespace this endpoint responded ",
                        $okname,
                        " to; got {:?}"
                    ),
                    err
                );
                assert_eq!(ep.session_state(), SessionState::Active, "still a message");
            }

            /// One this endpoint refused cannot be either: it responded, and it
            /// responded the other way.
            #[test]
            fn an_announcement_this_endpoint_refused_cannot_be_cancelled() {
                let mut ep = announced();
                crate::we_refuse!($refuse, ep, PEERS_ID, crate::namespace())
                    .expect("refuse the announcement");
                let err = crate::we_cancel!($cancel, ep, PEERS_ID, crate::namespace())
                    .expect_err("a refusal is not an acceptance");
                assert!(
                    crate::ended_reads_as!($ended, err),
                    "the refused announcement should not be cancellable; got {err:?}"
                );
                assert_eq!(ep.session_state(), SessionState::Active, "still a message");
            }

            /// An acceptance is revoked once.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// the second cancellation should find nothing live; got
            /// Namespace(InvalidTransition { from: "Done", ... })
            /// ```
            ///
            /// Made by letting the namespace scan return announcements that
            /// have ended, so a namespace that stands for nothing live stands
            /// for something dead instead. It reaches only the five drafts
            /// whose cancellation names a namespace while the announcement
            /// carried a Request ID, and reddens 10 tests there.
            #[test]
            fn an_acceptance_is_revoked_once() {
                let mut ep = accepted();
                crate::we_cancel!($cancel, ep, PEERS_ID, crate::namespace())
                    .expect("revoke the acceptance");
                let err = crate::we_cancel!($cancel, ep, PEERS_ID, crate::namespace())
                    .expect_err("there is nothing left to revoke");
                assert!(
                    crate::ended_reads_as!($ended, err),
                    "the second cancellation should find nothing live; got {err:?}"
                );
                assert_eq!(ep.session_state(), SessionState::Active, "still a message");
            }

            /// An announcement the peer never made cannot be cancelled, and the
            /// refusal says which record came up empty.
            #[test]
            fn an_announcement_the_peer_never_made_cannot_be_cancelled() {
                let mut ep = accepted();
                let err = crate::we_cancel!($cancel, ep, NEVER_USED, crate::elsewhere())
                    .expect_err("the peer announced nothing under that name");
                assert!(
                    matches!(err, EndpointError::$unknown { .. }),
                    "the miss should name the peer's announcements; got {err:?}"
                );
                assert_eq!(ep.session_state(), SessionState::Active, "still a message");
            }

            /// Cancelling the peer's announcement leaves this endpoint's own
            /// announcement of the same namespace alone.
            ///
            /// The two are different announcements that happen to name the same
            /// thing, and only one of them is this endpoint's to revoke an
            /// acceptance of. Withdrawing this endpoint's own afterwards is what
            /// proves it was untouched: a withdrawal only lands on an
            /// announcement the peer has accepted and nothing has ended.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// the publisher may still stop serving its own
            /// ```
            ///
            /// Made by ending this endpoint's own announcements alongside the
            /// peer's when a cancellation goes out. It reddens 10 tests, one per
            /// draft, and nothing else: every other gate holds one
            /// announcement, and this is the only one that holds two.
            #[test]
            fn cancelling_the_peers_announcement_leaves_this_endpoints_own_alone() {
                let mut ep = active();
                let ours = crate::we_announce!($ours, ep);
                crate::peer_accepts_ours!($theirok, ep, ours)
                    .expect("the peer may accept this endpoint's announcement");
                ep.$recv(&crate::peers_advert!($advert, PEERS_ID, crate::namespace()))
                    .expect("the peer may announce the same namespace");
                crate::we_accept!($accept, ep, PEERS_ID, crate::namespace())
                    .expect("accept the peer's announcement");
                crate::we_cancel!($cancel, ep, PEERS_ID, crate::namespace())
                    .expect("revoke the acceptance of the peer's");

                crate::we_withdraw!($withdraw, ep, ours, crate::namespace())
                    .expect("the publisher may still stop serving its own");
                assert_eq!(ep.session_state(), SessionState::Active, "still a message");
            }
        }
    };
}

cancellation_gates!(
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
    bare,
    ns,
    receive_announce,
    UnknownPeerNamespace,
    flow,
    by_ns,
    0,
    "5.2",
    "ANNOUNCE_OK"
);
cancellation_gates!(
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
    bare,
    ns,
    receive_announce,
    UnknownPeerNamespace,
    flow,
    by_ns,
    0,
    "6.2",
    "ANNOUNCE_OK"
);
cancellation_gates!(
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
    bare,
    ns,
    receive_announce,
    UnknownPeerNamespace,
    flow,
    by_ns,
    0,
    "6.2",
    "ANNOUNCE_OK"
);
cancellation_gates!(
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
    bare,
    ns,
    receive_announce,
    UnknownPeerNamespace,
    flow,
    by_ns,
    0,
    "7.2",
    "ANNOUNCE_OK"
);
cancellation_gates!(
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
    ided,
    id,
    receive_announce,
    UnknownPeerNamespace,
    missing,
    by_ns,
    1,
    "7.3",
    "ANNOUNCE_OK"
);
cancellation_gates!(
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
    ided_params,
    id,
    receive_announce,
    UnknownPeerNamespace,
    missing,
    by_ns,
    1,
    "7.3",
    "ANNOUNCE_OK"
);
cancellation_gates!(
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
    ided_params,
    id,
    receive_announce,
    UnknownPeerNamespace,
    missing,
    by_ns,
    1,
    "7.3",
    "ANNOUNCE_OK"
);
cancellation_gates!(
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
    renamed,
    receive_publish_namespace,
    UnknownPeerNamespace,
    missing,
    renamed_ns,
    1,
    "8.4",
    "PUBLISH_NAMESPACE_OK"
);
cancellation_gates!(
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
    params,
    request,
    receive_publish_namespace,
    UnknownPeerNamespace,
    missing,
    renamed_ns,
    1,
    "8.5",
    "REQUEST_OK"
);
cancellation_gates!(
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
    params,
    request,
    receive_publish_namespace,
    UnknownRequest,
    flow,
    renamed_id,
    1,
    "8.5",
    "REQUEST_OK"
);

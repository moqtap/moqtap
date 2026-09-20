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

//! An announcement this endpoint makes ends one of two ways, and the two do
//! not both happen.
//!
//! The publisher withdraws it - UNANNOUNCE up to draft-13,
//! PUBLISH_NAMESPACE_DONE after it - or the subscriber revokes its acceptance
//! with a cancellation. Drafts 08 and 09 Section 4.2, drafts 10 through 13
//! Section 5.2 and drafts 14 through 16 Section 6.2 say what happens when the
//! second one comes first: "After receiving an ANNOUNCE_CANCEL, the publisher
//! does not send UNANNOUNCE." Draft-07 states no such sentence, and the flow
//! refuses the withdrawal there for the same reason it does everywhere: an
//! announcement that has been cancelled has left the state a withdrawal is sent
//! from.
//!
//! # Whose announcement it is
//!
//! This endpoint's. Everything here is about an announcement it made and the
//! peer answered, which is the other direction from the file beside this one.
//! The two are held apart, and the last gate of each is the one that says so.
//!
//! # Why none of this ends the session
//!
//! "The publisher does not send UNANNOUNCE" describes what the publisher does,
//! and this endpoint is that publisher: the message is refused where it is
//! asked for and nothing goes out. Every gate below checks the session is still
//! running.
//!
//! # Ablations, measured
//!
//! Four cuts are recorded here, each run and reverted, each on the gate it
//! reddens. One gate needed two of them to be measured at all: cutting the
//! cancellation's dispatch arm does not redden the gate that says the
//! cancellation is accepted, because a message that reaches the fall-through
//! is accepted. What that cut reddens is the gate after it, which reads the
//! state the dispatch was supposed to move.

#![allow(clippy::items_after_test_module)]

use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;

/// The namespace this endpoint advertises, and the one the peer advertises in
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

/// An announcement of this endpoint's own, and the identifier it got.
#[macro_export]
macro_rules! we_announce {
    (bare, $ep:expr, $ns:expr) => {{
        let _ = $ep.announce($ns).expect("this endpoint may announce");
        $crate::v(0)
    }};
    (ided, $ep:expr, $ns:expr) => {{
        let (id, _) = $ep.announce($ns).expect("this endpoint may announce");
        id
    }};
    (ided_params, $ep:expr, $ns:expr) => {{
        let (id, _) = $ep.announce($ns, vec![]).expect("this endpoint may announce");
        id
    }};
    (renamed, $ep:expr, $ns:expr) => {{
        let (id, _) = $ep.publish_namespace($ns, vec![]).expect("this endpoint may announce");
        id
    }};
    (params, $ep:expr, $ns:expr) => {{
        let (id, _) = $ep.publish_namespace($ns, vec![]).expect("this endpoint may announce");
        id
    }};
}

/// The peer accepting an announcement this endpoint made.
#[macro_export]
macro_rules! peer_accepts_ours {
    (ns, $ep:expr, $id:expr, $ns:expr) => {{
        let _ = $id;
        $ep.receive_announce_ok(&AnnounceOk { track_namespace: $ns })
    }};
    (id, $ep:expr, $id:expr, $ns:expr) => {
        $ep.receive_announce_ok(&AnnounceOk { request_id: $id })
    };
    (renamed, $ep:expr, $id:expr, $ns:expr) => {
        $ep.receive_publish_namespace_ok(&PublishNamespaceOk { request_id: $id })
    };
    (request, $ep:expr, $id:expr, $ns:expr) => {
        $ep.receive_request_ok(&RequestOk { request_id: $id, parameters: vec![] })
    };
}

/// This endpoint withdrawing what it announced.
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

/// The cancellation the peer sends about an announcement this endpoint made.
#[macro_export]
macro_rules! peers_cancel {
    (by_ns, $id:expr, $ns:expr) => {{
        let _ = $id;
        AnnounceCancel {
            track_namespace: $ns,
            error_code: $crate::v(1),
            reason_phrase: b"expired".to_vec(),
        }
    }};
    (renamed_ns, $id:expr, $ns:expr) => {{
        let _ = $id;
        PublishNamespaceCancel {
            track_namespace: $ns,
            error_code: $crate::v(1),
            reason_phrase: b"expired".to_vec(),
        }
    }};
    (renamed_id, $id:expr, $ns:expr) => {
        PublishNamespaceCancel {
            request_id: $id,
            error_code: $crate::v(1),
            reason_phrase: b"expired".to_vec(),
        }
    };
}

/// The advertisement the peer makes, for the gate that holds one of each.
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

/// This endpoint accepting the peer's advertisement.
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

/// The peer withdrawing what it announced.
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

/// Why a withdrawal after a cancellation is refused, which nine of the ten
/// drafts say in one sentence and draft-07 does not say at all.
#[macro_export]
macro_rules! not_after_cancel {
    (uncited) => {
        "an announcement that has been cancelled has left the state a withdrawal is sent from"
    };
    ($sec:literal) => {
        concat!("Section ", $sec, " says the publisher does not withdraw after a cancellation")
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
macro_rules! outbound_announce_gates {
    ($draft:ident, $feat:literal, $version:expr, $role:path, $grant:ident, $params:tt,
     $setup:tt, $ours:tt, $theirok:tt, $withdraw:tt, $cancel:tt, $advert:tt, $accept:tt,
     $theirdone:tt, $recv:ident, $cancelvariant:ident, $donevariant:ident,
     $unknown:ident, $peers_id:literal, $rule:tt) => {
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

            /// The identifier the peer opens an announcement of its own under.
            /// On the drafts whose ANNOUNCE carries none, nothing reads it.
            #[allow(dead_code)]
            const PEERS_ID: u64 = $peers_id;

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

            /// An endpoint whose own announcement the peer has accepted.
            fn ours_accepted() -> (Endpoint, VarInt) {
                let mut ep = active();
                let ours = crate::we_announce!($ours, ep, crate::namespace());
                crate::peer_accepts_ours!($theirok, ep, ours, crate::namespace())
                    .expect("the peer may accept it");
                (ep, ours)
            }

            /// This endpoint withdraws what it announced.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// the publisher may stop serving what it announced: UnknownNamespace
            /// ```
            ///
            /// Made by looking the announcement up among the ones the peer made
            /// instead of this endpoint's own. It reddens 50 tests across two
            /// files, five gates on each of the ten drafts: every gate here
            /// that ends an announcement of this endpoint's, and the one in the
            /// file beside this that proves the peer's cancellation left it
            /// alone.
            #[test]
            fn this_endpoint_withdraws_the_announcement_it_made() {
                let (mut ep, ours) = ours_accepted();
                crate::we_withdraw!($withdraw, ep, ours, crate::namespace())
                    .expect("the publisher may stop serving what it announced");
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "a withdrawal is ordinary traffic"
                );
            }

            /// One the peer has not accepted cannot be withdrawn: there is
            /// nothing being served to stop serving.
            #[test]
            fn an_announcement_the_peer_has_not_accepted_cannot_be_withdrawn() {
                let mut ep = active();
                let ours = crate::we_announce!($ours, ep, crate::namespace());
                let err = crate::we_withdraw!($withdraw, ep, ours, crate::namespace())
                    .expect_err("the peer has not accepted it yet");
                assert!(
                    matches!(err, EndpointError::Namespace(_)),
                    "the flow should refuse it; got {err:?}"
                );
                assert_eq!(ep.session_state(), SessionState::Active, "still a message");
            }

            /// The peer revokes its acceptance of an announcement this endpoint
            /// made, and it arrives the way it arrives on the wire.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// the peer may revoke its acceptance: UnknownNamespace
            /// ```
            ///
            /// Made by reading the cancellation out of the announcements the
            /// **peer** made rather than this endpoint's own. It reddens 20
            /// tests, this gate and the one below it on all ten drafts.
            ///
            /// Cutting the dispatch arm instead does not redden this gate: a
            /// message that reaches the fall-through is accepted and ignored,
            /// which is what an assertion that it was accepted cannot tell from
            /// the real thing. That cut is recorded on the gate below, which
            /// reads the state the dispatch was supposed to move.
            #[test]
            fn the_peer_revokes_its_acceptance_of_this_endpoints_announcement() {
                let (mut ep, ours) = ours_accepted();
                ep.receive_message(ControlMessage::$cancelvariant(crate::peers_cancel!(
                    $cancel,
                    ours,
                    crate::namespace()
                )))
                .expect("the peer may revoke its acceptance");
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "a cancellation is ordinary traffic"
                );
            }

            /// And after that this endpoint does not withdraw it.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// an announcement that has been cancelled has left the state a
            /// withdrawal is sent from: Unannounce(Unannounce { ... })
            /// ```
            ///
            /// Made by cutting the cancellation's dispatch arm, so nothing
            /// moves when it arrives and the withdrawal after it goes out - the
            /// state drafts 14 through 16 were in, where the message reached no
            /// handler at all. It reddens 20 tests, this gate and the one below
            /// it on all ten drafts.
            #[test]
            fn after_a_cancellation_this_endpoint_does_not_withdraw() {
                let (mut ep, ours) = ours_accepted();
                ep.receive_message(ControlMessage::$cancelvariant(crate::peers_cancel!(
                    $cancel,
                    ours,
                    crate::namespace()
                )))
                .expect("the peer may revoke its acceptance");
                let err = crate::we_withdraw!($withdraw, ep, ours, crate::namespace())
                    .expect_err(crate::not_after_cancel!($rule));
                assert!(
                    matches!(err, EndpointError::Namespace(_)),
                    "the withdrawal should be refused; got {err:?}"
                );
                assert_eq!(ep.session_state(), SessionState::Active, "still a message");
            }

            /// A cancellation about an announcement this endpoint never made is
            /// refused, and the refusal says which record came up empty.
            #[test]
            fn a_cancellation_for_an_announcement_never_made_is_refused() {
                let (mut ep, _ours) = ours_accepted();
                let err = ep
                    .receive_message(ControlMessage::$cancelvariant(crate::peers_cancel!(
                        $cancel,
                        $crate::v(9),
                        crate::elsewhere()
                    )))
                    .expect_err("this endpoint announced nothing under that name");
                assert!(
                    matches!(err, EndpointError::$unknown { .. }),
                    "the miss should name this endpoint's own announcements; got {err:?}"
                );
                assert_eq!(ep.session_state(), SessionState::Active, "still a message");
            }

            /// The peer withdrawing its own announcement of the same namespace
            /// leaves this endpoint's alone.
            ///
            /// The two are different announcements that happen to name the same
            /// thing, and each end withdraws only its own. This endpoint's
            /// still being withdrawable afterwards is what proves it was not
            /// touched.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// the publisher may still stop serving its own
            /// ```
            ///
            /// Made by ending this endpoint's own announcements when the peer's
            /// withdrawal arrives, which is what draft-14 did to every one of
            /// them at once. It reddens 10 tests, one per draft, and nothing
            /// else: every other gate holds one announcement, and this is the
            /// only one here that holds two.
            #[test]
            fn the_peers_withdrawal_leaves_this_endpoints_own_alone() {
                let (mut ep, ours) = ours_accepted();
                ep.$recv(&crate::peers_advert!($advert, PEERS_ID, crate::namespace()))
                    .expect("the peer may announce the same namespace");
                crate::we_accept!($accept, ep, PEERS_ID, crate::namespace())
                    .expect("accept the peer's announcement");
                ep.receive_message(ControlMessage::$donevariant(crate::peers_withdrawal!(
                    $theirdone,
                    PEERS_ID,
                    crate::namespace()
                )))
                .expect("the peer may withdraw its own");

                crate::we_withdraw!($withdraw, ep, ours, crate::namespace())
                    .expect("the publisher may still stop serving its own");
                assert_eq!(ep.session_state(), SessionState::Active, "still a message");
            }
        }
    };
}

outbound_announce_gates!(
    draft07,
    "draft07",
    0xff00_0007,
    moqtap_client::draft07::endpoint::Role,
    send_max_subscribe_id,
    role,
    versioned,
    bare,
    ns,
    by_ns,
    by_ns,
    plain,
    ns,
    by_ns,
    receive_announce,
    AnnounceCancel,
    Unannounce,
    UnknownNamespace,
    0,
    uncited
);
outbound_announce_gates!(
    draft08,
    "draft08",
    0xff00_0008,
    moqtap_client::draft08::endpoint::Role,
    send_max_subscribe_id,
    none,
    versioned,
    bare,
    ns,
    by_ns,
    by_ns,
    plain,
    ns,
    by_ns,
    receive_announce,
    AnnounceCancel,
    Unannounce,
    UnknownNamespace,
    0,
    "4.2"
);
outbound_announce_gates!(
    draft09,
    "draft09",
    0xff00_0009,
    moqtap_client::draft09::endpoint::Role,
    send_max_subscribe_id,
    none,
    versioned,
    bare,
    ns,
    by_ns,
    by_ns,
    plain,
    ns,
    by_ns,
    receive_announce,
    AnnounceCancel,
    Unannounce,
    UnknownNamespace,
    0,
    "4.2"
);
outbound_announce_gates!(
    draft10,
    "draft10",
    0xff00_000a,
    moqtap_client::draft10::endpoint::Role,
    send_max_subscribe_id,
    none,
    versioned,
    bare,
    ns,
    by_ns,
    by_ns,
    plain,
    ns,
    by_ns,
    receive_announce,
    AnnounceCancel,
    Unannounce,
    UnknownNamespace,
    0,
    "5.2"
);
outbound_announce_gates!(
    draft11,
    "draft11",
    0xff00_000b,
    moqtap_client::draft11::session::request_id::Role,
    send_max_request_id,
    none,
    versioned,
    ided,
    id,
    by_ns,
    by_ns,
    ided,
    id,
    by_ns,
    receive_announce,
    AnnounceCancel,
    Unannounce,
    UnknownNamespace,
    1,
    "5.2"
);
outbound_announce_gates!(
    draft12,
    "draft12",
    0xff00_000c,
    moqtap_client::draft12::session::request_id::Role,
    send_max_request_id,
    none,
    versioned,
    ided_params,
    id,
    by_ns,
    by_ns,
    ided,
    id,
    by_ns,
    receive_announce,
    AnnounceCancel,
    Unannounce,
    UnknownNamespace,
    1,
    "5.2"
);
outbound_announce_gates!(
    draft13,
    "draft13",
    0xff00_000d,
    moqtap_client::draft13::session::request_id::Role,
    send_max_request_id,
    none,
    versioned,
    ided_params,
    id,
    by_ns,
    by_ns,
    ided,
    id,
    by_ns,
    receive_announce,
    AnnounceCancel,
    Unannounce,
    UnknownNamespace,
    1,
    "5.2"
);
outbound_announce_gates!(
    draft14,
    "draft14",
    0xff00_000e,
    moqtap_client::draft14::session::request_id::Role,
    send_max_request_id,
    none,
    versioned,
    renamed,
    renamed,
    renamed_ns,
    renamed_ns,
    renamed,
    renamed,
    renamed_ns,
    receive_publish_namespace,
    PublishNamespaceCancel,
    PublishNamespaceDone,
    UnknownNamespace,
    1,
    "6.2"
);
outbound_announce_gates!(
    draft15,
    "draft15",
    0xff00_000f,
    moqtap_client::draft15::session::request_id::Role,
    send_max_request_id,
    none,
    alpn,
    params,
    request,
    renamed_ns,
    renamed_ns,
    renamed,
    request,
    renamed_ns,
    receive_publish_namespace,
    PublishNamespaceCancel,
    PublishNamespaceDone,
    UnknownNamespace,
    1,
    "6.2"
);
outbound_announce_gates!(
    draft16,
    "draft16",
    0xff00_0010,
    moqtap_client::draft16::session::request_id::Role,
    send_max_request_id,
    none,
    alpn,
    params,
    request,
    renamed_id,
    renamed_id,
    renamed,
    request,
    renamed_id,
    receive_publish_namespace,
    PublishNamespaceCancel,
    PublishNamespaceDone,
    UnknownRequest,
    1,
    "6.2"
);

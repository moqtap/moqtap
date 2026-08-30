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
))]

//! A namespace subscription the peer makes is recorded, answered once, and
//! ended when the peer withdraws it.
//!
//! Draft-07 Section 6.13: "The publisher will respond with
//! SUBSCRIBE_ANNOUNCES_OK or SUBSCRIBE_ANNOUNCES_ERROR." Drafts 08 and 09
//! Section 4.1, drafts 10 through 13 Section 5.1 and drafts 14 and 15 Section
//! 6.1 make it a requirement and put a number on it: "A publisher MUST send
//! exactly one SUBSCRIBE_ANNOUNCES_OK or SUBSCRIBE_ANNOUNCES_ERROR in response
//! to a SUBSCRIBE_ANNOUNCES", with the message renamed SUBSCRIBE_NAMESPACE from
//! draft-13 and the answer folded into REQUEST_OK and REQUEST_ERROR at
//! draft-15.
//!
//! What comes after the answer is the rest of the flow. The subscriber stops
//! asking about a namespace by withdrawing the subscription, which names the
//! prefix up to draft-14 and the Request ID at draft-15. This endpoint is the
//! publisher of a request that arrives, so it sends the answer and receives the
//! withdrawal - both the other way round from a namespace subscription it makes
//! itself.
//!
//! # What was here before
//!
//! Nothing on any of the nine. An arriving SUBSCRIBE_ANNOUNCES or
//! SUBSCRIBE_NAMESPACE had its Request ID counted against the peer's sequence
//! from draft-11 on, and was then dropped; drafts 07 through 10, whose request
//! carries no Request ID, dropped it outright. The withdrawal was dispatched
//! nowhere on any of the nine. A peer that subscribed to a namespace here
//! waited for an answer the crate had no record to build.
//!
//! Draft-16 already carries all of this, because there the request arrives on a
//! bidirectional stream of its own, and drafts 17 through 19 keep it that way.
//!
//! # Why none of this ends the session
//!
//! "MUST send exactly one" is addressed to the sender of the answer, and this
//! endpoint's job is not to send the second one. The SHOULD beside it -
//! "The subscriber SHOULD close the session with a protocol error if it detects
//! receiving more than one" - belongs to the subscriber, which this endpoint is
//! not for a request that arrives. So a second answer is refused where it is
//! asked for and the session goes on running, and every gate below checks that.
//!
//! # What is deliberately not gated here
//!
//! Whether two namespace subscriptions overlap. Every draft from 07 through 17
//! says a subscriber cannot make overlapping ones and that the publisher MUST
//! refuse the second, and the relation it forbids is worded three different
//! ways across the range. Judging it needs this record and is a rule of its
//! own; nothing here decides it.
//!
//! # Ablations, measured
//!
//! Nine cuts are recorded here, each made, run and reverted, and each sitting on
//! the gate it reddens - from 1 failing test to 103. Three gates carry no cut:
//! the two that check a second answer is refused are measured by the cuts on the
//! gates above them, and the one naming a request that never arrived is refused
//! by an empty record whether or not the lookup reads its key, so only the cut
//! that makes the lookup ignore the key can move it.

#![allow(clippy::items_after_test_module)]

use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;

/// The prefix the peer subscribes to.
fn prefix() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec()])
}

/// A prefix nothing was ever subscribed to.
/// Unread in a build that enables only drafts whose gates do not use it.
#[allow(dead_code)]
fn elsewhere() -> TrackNamespace {
    TrackNamespace(vec![b"elsewhere".to_vec()])
}

fn v(n: u64) -> VarInt {
    VarInt::from_u64(n).unwrap()
}

/// The request the peer sends, in the four shapes it takes across the nine
/// drafts: drafts 07 through 10 name only the prefix, draft-11 adds a Request
/// ID, draft-13 renames the message, and drafts 14 and 15 each rename the field
/// the prefix travels in.
#[macro_export]
macro_rules! peers_request {
    (plain, $id:expr, $ns:expr) => {{
        let _ = $id;
        SubscribeAnnounces { track_namespace_prefix: $ns, parameters: vec![] }
    }};
    (ided, $id:expr, $ns:expr) => {
        SubscribeAnnounces {
            request_id: $crate::v($id),
            track_namespace_prefix: $ns,
            parameters: vec![],
        }
    };
    (renamed, $id:expr, $ns:expr) => {
        SubscribeNamespace {
            request_id: $crate::v($id),
            track_namespace_prefix: $ns,
            parameters: vec![],
        }
    };
    (d14, $id:expr, $ns:expr) => {
        SubscribeNamespace { request_id: $crate::v($id), track_namespace: $ns, parameters: vec![] }
    };
    (d15, $id:expr, $ns:expr) => {
        SubscribeNamespace { request_id: $crate::v($id), namespace_prefix: $ns, parameters: vec![] }
    };
}

/// Accepting it, which names the request by prefix up to draft-10 and by
/// Request ID after it, and folds into REQUEST_OK at draft-15.
#[macro_export]
macro_rules! we_accept {
    (ns, $ep:expr, $id:expr, $ns:expr) => {{
        let _ = $id;
        $ep.send_subscribe_announces_ok($ns)
    }};
    (id, $ep:expr, $id:expr, $ns:expr) => {
        $ep.send_subscribe_announces_ok($crate::v($id))
    };
    (renamed, $ep:expr, $id:expr, $ns:expr) => {
        $ep.send_subscribe_namespace_ok($crate::v($id))
    };
    (request, $ep:expr, $id:expr, $ns:expr) => {
        $ep.send_request_ok($crate::v($id), Vec::new())
    };
}

/// Refusing it.
#[macro_export]
macro_rules! we_refuse {
    (ns, $ep:expr, $id:expr, $ns:expr) => {{
        let _ = $id;
        $ep.send_subscribe_announces_error($ns, $crate::v(0), b"no".to_vec())
    }};
    (id, $ep:expr, $id:expr, $ns:expr) => {
        $ep.send_subscribe_announces_error($crate::v($id), $crate::v(0), b"no".to_vec())
    };
    (renamed, $ep:expr, $id:expr, $ns:expr) => {
        $ep.send_subscribe_namespace_error($crate::v($id), $crate::v(0), b"no".to_vec())
    };
    (request, $ep:expr, $id:expr, $ns:expr) => {
        $ep.send_request_error($crate::v($id), $crate::v(0), b"no".to_vec())
    };
}

/// The withdrawal the peer sends, which names a prefix on eight of the nine
/// drafts and a Request ID on draft-15.
#[macro_export]
macro_rules! peers_withdrawal {
    (by_ns, $id:expr, $ns:expr) => {{
        let _ = $id;
        UnsubscribeAnnounces { track_namespace_prefix: $ns }
    }};
    (renamed_ns, $id:expr, $ns:expr) => {{
        let _ = $id;
        UnsubscribeNamespace { track_namespace_prefix: $ns }
    }};
    (by_id, $id:expr, $ns:expr) => {
        UnsubscribeNamespace { request_id: $crate::v($id) }
    };
}

/// The prefix out of the request, which travels in a field each of the last two
/// drafts in the range renames.
#[macro_export]
macro_rules! reads_prefix {
    (pfx, $req:expr) => {
        $req.track_namespace_prefix.0.clone()
    };
    (ns, $req:expr) => {
        $req.track_namespace.0.clone()
    };
    (nspfx, $req:expr) => {
        $req.namespace_prefix.0.clone()
    };
}

/// The namespace subscription the peer made that is still waiting for an
/// answer.
#[macro_export]
macro_rules! still_waiting {
    (ns, $ep:expr, $id:expr, $ns:expr) => {{
        let _ = $id;
        $ep.pending_subscribe_announces(&$ns)
    }};
    (id, $ep:expr, $id:expr, $ns:expr) => {
        $ep.pending_subscribe_announces($crate::v($id))
    };
    (renamed, $ep:expr, $id:expr, $ns:expr) => {
        $ep.pending_subscribe_namespace($crate::v($id))
    };
}

/// The setup parameters each draft requires. Draft-07 requires a ROLE of both
/// endpoints and is the only one of the nine that does.
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

/// One draft's eleven gates.
macro_rules! inbound_namespace_gates {
    ($draft:ident, $feat:literal, $version:expr, $role:path, $grant:ident, $params:tt,
     $setup:tt, $request:tt, $accept:tt, $refuse:tt, $withdrawal:tt, $pending:tt,
     $recv:ident, $count:ident, $variant:ident, $unsubvariant:ident,
     $unknown_answer:ident, $unknown_withdrawal:ident, $peers_id:literal, $sec:literal,
     $ok_event:literal, $field:tt) => {
        #[cfg(feature = $feat)]
        mod $draft {
            use moqtap_client::$draft::endpoint::{Endpoint, EndpointError};
            use moqtap_client::$draft::namespace::NamespaceError;
            use moqtap_client::$draft::session::state::SessionState;
            use $role as Role;

            #[allow(unused_imports)]
            use moqtap_codec::kvp::{KeyValuePair, KvpValue};
            #[allow(unused_imports)]
            use moqtap_codec::types::*;
            #[allow(unused_imports)]
            use moqtap_codec::varint::VarInt;
            use moqtap_codec::$draft::message::*;

            /// The identifier the peer opens its request under. On the drafts
            /// whose request carries none, nothing reads it.
            #[allow(dead_code)]
            const PEERS_ID: u64 = $peers_id;

            /// An identifier the peer subscribed to nothing under. Unread on
            /// the drafts whose request carries no identifier at all.
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

            /// An endpoint holding the peer's unanswered namespace
            /// subscription.
            fn subscribed() -> Endpoint {
                let mut ep = active();
                ep.$recv(&crate::peers_request!($request, PEERS_ID, crate::prefix()))
                    .expect("the peer may subscribe to a namespace");
                ep
            }

            /// The same, with the request accepted.
            fn accepted() -> Endpoint {
                let mut ep = subscribed();
                crate::we_accept!($accept, ep, PEERS_ID, crate::prefix())
                    .expect("accept the namespace subscription");
                ep
            }

            /// A namespace subscription the peer makes is kept, rather than
            /// counted and dropped.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// the namespace subscription the peer made should be on record
            /// ```
            ///
            /// Made by dropping the record instead of inserting it, which is what
            /// all nine drafts did before. It reddens 103 tests: every gate in this
            /// file on all nine drafts except the one naming a request that never
            /// arrived, which an empty record refuses anyway, and all four loopback
            /// gates.
            #[test]
            fn a_namespace_subscription_the_peer_makes_is_recorded() {
                let ep = subscribed();
                assert!(
                    crate::still_waiting!($pending, ep, PEERS_ID, crate::prefix()).is_some(),
                    "the namespace subscription the peer made should be on record"
                );
                assert_eq!(ep.$count(), 1, "one request is waiting for an answer");
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "a namespace subscription arriving is ordinary traffic"
                );
            }

            /// The record holds the request and not only its state, which is
            /// what an answer is built from.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// assertion `left == right` failed: the prefix the peer named should be
            /// readable back
            ///   left: [[99, 111, 110, 102, 111, 114, 109, 97, 110, 99, 101]]
            ///  right: []
            /// ```
            ///
            /// Made by recording the request with its prefix emptied, which is what a
            /// record that keeps the state machine alone amounts to - the shape the
            /// peer's PUBLISH is still kept in on three drafts. It reddens 17 tests:
            /// this gate on all nine, and both withdrawal gates on drafts 11 through
            /// 14, where the request is keyed by Request ID and the withdrawal names
            /// the prefix, so the prefix is what finds the record.
            #[test]
            fn the_record_holds_the_prefix_the_peer_named() {
                let ep = subscribed();
                let req = crate::still_waiting!($pending, ep, PEERS_ID, crate::prefix())
                    .expect("the request is on record");
                assert_eq!(
                    crate::prefix().0,
                    crate::reads_prefix!($field, req),
                    "the prefix the peer named should be readable back"
                );
            }

            /// It is kept when it arrives the way it arrives on the wire, which
            /// is through the control stream's dispatcher.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// the request should have reached the endpoint's record
            ///   left: 0
            ///  right: 1
            /// ```
            ///
            /// Made by cutting the dispatch arm, which sends the message back to the
            /// fall-through that accepts and ignores it - the state all nine drafts
            /// were in. It reddens 13 tests: this gate on all nine, and all four
            /// loopback gates.
            #[test]
            fn a_namespace_subscription_arriving_on_the_control_stream_is_recorded() {
                let mut ep = active();
                ep.receive_message(ControlMessage::$variant(crate::peers_request!(
                    $request,
                    PEERS_ID,
                    crate::prefix()
                )))
                .expect("the peer may subscribe on the control stream");
                assert_eq!(ep.$count(), 1, "the request should have reached the endpoint's record");
            }

            /// Accepting it answers it, and it is no longer waiting.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// the request should be answered
            /// ```
            ///
            /// Made by building the acceptance without moving the flow, so the
            /// request stays where it was and could be answered again. It reddens 45
            /// tests, five per draft: nothing downstream of an acceptance happens if
            /// the acceptance leaves no trace.
            #[test]
            fn accepting_a_namespace_subscription_answers_it() {
                let mut ep = subscribed();
                assert!(
                    crate::still_waiting!($pending, ep, PEERS_ID, crate::prefix()).is_some(),
                    "it is waiting before the answer"
                );
                crate::we_accept!($accept, ep, PEERS_ID, crate::prefix())
                    .expect("accept the namespace subscription");
                assert!(
                    crate::still_waiting!($pending, ep, PEERS_ID, crate::prefix()).is_none(),
                    "the request should be answered"
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
            /// Made by building the refusal without moving the flow. It reddens 18
            /// tests, two per draft.
            #[test]
            fn refusing_a_namespace_subscription_answers_it() {
                let mut ep = subscribed();
                crate::we_refuse!($refuse, ep, PEERS_ID, crate::prefix())
                    .expect("refuse the namespace subscription");
                assert!(
                    crate::still_waiting!($pending, ep, PEERS_ID, crate::prefix()).is_none(),
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
            fn a_namespace_subscription_is_accepted_once() {
                let mut ep = accepted();
                let err = crate::we_accept!($accept, ep, PEERS_ID, crate::prefix()).expect_err(
                    concat!("Section ", $sec, " allows exactly one answer to a request"),
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

            /// And one already accepted cannot then be refused: the sentence
            /// allows one answer, not one of each.
            #[test]
            fn a_namespace_subscription_accepted_cannot_then_be_refused() {
                let mut ep = accepted();
                let err = crate::we_refuse!($refuse, ep, PEERS_ID, crate::prefix()).expect_err(
                    concat!("Section ", $sec, " allows exactly one answer to a request"),
                );
                assert!(
                    matches!(err, EndpointError::Namespace(_)),
                    "the second answer should be refused by the flow; got {err:?}"
                );
                assert_eq!(ep.session_state(), SessionState::Active, "still a message");
            }

            /// The refusal names the event this draft's own message carries.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// assertion `left == right` failed: the event should name this draft's
            /// message
            ///   left: "on_subscribe_announces_ok_sent"
            ///  right: "on_subscribe_namespace_ok_sent"
            /// ```
            ///
            /// Made by leaving draft-13's namespace flow named for SUBSCRIBE_ANNOUNCES,
            /// which is the message draft-12 carries and draft-13 renamed - the state
            /// the file was in, doc header included. It reddens 1 test, on draft-13
            /// alone, which is what a rename that reached only one draft should
            /// redden.
            #[test]
            fn the_refusal_names_the_message_this_draft_carries() {
                let mut ep = accepted();
                let err = crate::we_accept!($accept, ep, PEERS_ID, crate::prefix())
                    .expect_err("one answer only");
                let EndpointError::Namespace(NamespaceError::InvalidTransition {
                    ref event, ..
                }) = err
                else {
                    panic!("the flow should refuse it; got {err:?}");
                };
                assert_eq!(event, $ok_event, "the event should name this draft's message");
            }

            /// An answer to a request that never arrived is refused, and the
            /// refusal says which record came up empty.
            ///
            /// The endpoint holds one request while this runs, and the answer
            /// names a different one. An empty record cannot tell a lookup that
            /// reads its key from one that ignores it: both come up with
            /// nothing.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// there is nothing to accept: SubscribeAnnouncesOk(SubscribeAnnouncesOk {
            /// track_namespace_prefix: TrackNamespace([[101, 108, 115, 101, 119, 104,
            /// 101, 114, 101]]) })
            /// ```
            ///
            /// Made by answering whichever request the record happens to hold instead
            /// of the one named, at every place that reads it. It reddens 9 tests, one
            /// per draft.
            #[test]
            fn an_answer_to_a_namespace_subscription_that_never_arrived_is_refused() {
                let mut ep = subscribed();
                let err = crate::we_accept!($accept, ep, NEVER_USED, crate::elsewhere())
                    .expect_err("there is nothing to accept");
                assert!(
                    matches!(err, EndpointError::$unknown_answer { .. }),
                    "the miss should name the peer's namespace subscriptions; got {err:?}"
                );
                assert_eq!(ep.session_state(), SessionState::Active, "still a message");
            }

            /// The peer withdraws a namespace subscription this endpoint
            /// accepted, and the record ends.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// a withdrawal ends the namespace subscription once
            /// ```
            ///
            /// Made by leaving the flow where it was when the withdrawal arrives, so
            /// the same subscription could be withdrawn for ever. It reddens 18 tests,
            /// two per draft.
            #[test]
            fn the_peer_withdraws_a_namespace_subscription_this_endpoint_accepted() {
                let mut ep = accepted();
                ep.receive_message(ControlMessage::$unsubvariant(crate::peers_withdrawal!(
                    $withdrawal,
                    PEERS_ID,
                    crate::prefix()
                )))
                .expect("the peer may withdraw what it subscribed to");
                let err = ep
                    .receive_message(ControlMessage::$unsubvariant(crate::peers_withdrawal!(
                        $withdrawal,
                        PEERS_ID,
                        crate::prefix()
                    )))
                    .expect_err("a withdrawal ends the namespace subscription once");
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

            /// A withdrawal of a namespace subscription this endpoint never
            /// answered is refused: there is nothing to stop forwarding.
            #[test]
            fn a_withdrawal_of_a_namespace_subscription_never_answered_is_refused() {
                let mut ep = subscribed();
                let err = ep
                    .receive_message(ControlMessage::$unsubvariant(crate::peers_withdrawal!(
                        $withdrawal,
                        PEERS_ID,
                        crate::prefix()
                    )))
                    .expect_err("nothing was accepted, so nothing can be withdrawn");
                assert!(
                    matches!(err, EndpointError::Namespace(_)),
                    "the flow should refuse it; got {err:?}"
                );
                assert_eq!(ep.session_state(), SessionState::Active, "still a message");
            }

            /// A withdrawal naming nothing the peer ever subscribed to is
            /// refused, and the refusal says which record came up empty.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// the peer subscribed to nothing under that name
            /// ```
            ///
            /// Made by cutting the withdrawal's dispatch arm, so it reaches the
            /// fall-through that accepts and ignores it - which is where the message
            /// went on all nine drafts. It reddens 27 tests, three per draft.
            #[test]
            fn a_withdrawal_for_a_namespace_subscription_that_never_arrived_is_refused() {
                let mut ep = accepted();
                let err = ep
                    .receive_message(ControlMessage::$unsubvariant(crate::peers_withdrawal!(
                        $withdrawal,
                        NEVER_USED,
                        crate::elsewhere()
                    )))
                    .expect_err("the peer subscribed to nothing under that name");
                assert!(
                    matches!(err, EndpointError::$unknown_withdrawal { .. }),
                    "the miss should name the peer's namespace subscriptions; got {err:?}"
                );
                assert_eq!(ep.session_state(), SessionState::Active, "still a message");
            }
        }
    };
}

inbound_namespace_gates!(
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
    receive_subscribe_announces,
    pending_subscribe_announces_count,
    SubscribeAnnounces,
    UnsubscribeAnnounces,
    UnknownPeerNamespaceSubscription,
    UnknownPeerNamespaceSubscription,
    0,
    "6.13",
    "on_subscribe_announces_ok_sent",
    pfx
);
inbound_namespace_gates!(
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
    receive_subscribe_announces,
    pending_subscribe_announces_count,
    SubscribeAnnounces,
    UnsubscribeAnnounces,
    UnknownPeerNamespaceSubscription,
    UnknownPeerNamespaceSubscription,
    0,
    "4.1",
    "on_subscribe_announces_ok_sent",
    pfx
);
inbound_namespace_gates!(
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
    receive_subscribe_announces,
    pending_subscribe_announces_count,
    SubscribeAnnounces,
    UnsubscribeAnnounces,
    UnknownPeerNamespaceSubscription,
    UnknownPeerNamespaceSubscription,
    0,
    "4.1",
    "on_subscribe_announces_ok_sent",
    pfx
);
inbound_namespace_gates!(
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
    receive_subscribe_announces,
    pending_subscribe_announces_count,
    SubscribeAnnounces,
    UnsubscribeAnnounces,
    UnknownPeerNamespaceSubscription,
    UnknownPeerNamespaceSubscription,
    0,
    "5.1",
    "on_subscribe_announces_ok_sent",
    pfx
);
inbound_namespace_gates!(
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
    receive_subscribe_announces,
    pending_subscribe_announces_count,
    SubscribeAnnounces,
    UnsubscribeAnnounces,
    UnknownRequest,
    UnknownPeerNamespaceSubscription,
    1,
    "5.1",
    "on_subscribe_announces_ok_sent",
    pfx
);
inbound_namespace_gates!(
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
    receive_subscribe_announces,
    pending_subscribe_announces_count,
    SubscribeAnnounces,
    UnsubscribeAnnounces,
    UnknownRequest,
    UnknownPeerNamespaceSubscription,
    1,
    "5.1",
    "on_subscribe_announces_ok_sent",
    pfx
);
inbound_namespace_gates!(
    draft13,
    "draft13",
    0xff00_000d,
    moqtap_client::draft13::session::request_id::Role,
    send_max_request_id,
    none,
    versioned,
    renamed,
    renamed,
    renamed,
    renamed_ns,
    renamed,
    receive_subscribe_namespace,
    pending_subscribe_namespace_count,
    SubscribeNamespace,
    UnsubscribeNamespace,
    UnknownRequest,
    UnknownPeerNamespaceSubscription,
    1,
    "5.1",
    "on_subscribe_namespace_ok_sent",
    pfx
);
inbound_namespace_gates!(
    draft14,
    "draft14",
    0xff00_000e,
    moqtap_client::draft14::session::request_id::Role,
    send_max_request_id,
    none,
    versioned,
    d14,
    renamed,
    renamed,
    renamed_ns,
    renamed,
    receive_subscribe_namespace,
    pending_subscribe_namespace_count,
    SubscribeNamespace,
    UnsubscribeNamespace,
    UnknownRequest,
    UnknownPeerNamespaceSubscription,
    1,
    "6.1",
    "on_subscribe_namespace_ok_sent",
    ns
);
inbound_namespace_gates!(
    draft15,
    "draft15",
    0xff00_000f,
    moqtap_client::draft15::session::request_id::Role,
    send_max_request_id,
    none,
    alpn,
    d15,
    request,
    request,
    by_id,
    renamed,
    receive_subscribe_namespace,
    pending_subscribe_namespace_count,
    SubscribeNamespace,
    UnsubscribeNamespace,
    UnknownRequest,
    UnknownRequest,
    1,
    "6.1",
    "on_subscribe_namespace_ok_sent",
    nspfx
);

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

//! A FETCH the peer sends opens a fetch, and this endpoint carries it from
//! arrival to its answer to the end of the flow.
//!
//! Drafts 08 and 09 Section 4.3, drafts 10 and 11 Section 4, drafts 12 and 13
//! Section 4.1, draft 14 Section 5.1: a publisher "MUST send exactly one
//! FETCH_OK or FETCH_ERROR in response to a FETCH". Drafts 15 and 16 give the
//! sentence a section of its own, 5.2, and name the refusal REQUEST_ERROR.
//! Draft-07 states no such sentence, and the flow refuses a second answer
//! there for the same reason it does everywhere: a fetch that has been
//! answered has left the state the answer is sent from.
//!
//! What comes after the answer is the rest of the flow. The subscriber stops a
//! fetch it no longer wants with FETCH_CANCEL, and the publisher ends the data
//! stream that carries the objects. This endpoint is the publisher of a FETCH
//! that arrives, so it sends the answer, receives the cancel and finishes the
//! stream - every message the other way round from a fetch it makes itself.
//!
//! # Why the range stops at 16
//!
//! Drafts 17 through 20 already carry all of this, because a request there
//! arrives on a stream of its own — draft-17 Section 9.14 has the subscriber
//! send FETCH "as the first message on a new bidi stream" — and the same map
//! holds both ends' fetches.
//!
//! # Why none of this ends the session
//!
//! "MUST send exactly one" is addressed to the sender of the answer. This
//! endpoint's job is not to send the second one, so a second answer is refused
//! where it is asked for and the session goes on running. Every gate below
//! checks that.
//!
//! # Ablations, measured
//!
//! Eight cuts were made, run and reverted, each recorded on the gate it
//! belongs to. Two reach a long way past this file and the direction is
//! always the same: a fetch the peer opened that cannot be recorded or cannot
//! be found is one nothing downstream can act on, so both joining files go
//! with it. Nothing here reaches the other way.

#![allow(clippy::items_after_test_module)]

use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;

/// The namespace the fetched track lives in.
fn namespace() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec()])
}

fn v(n: u64) -> VarInt {
    VarInt::from_u64(n).unwrap()
}

/// A standalone FETCH from the peer, in the four shapes it takes across the
/// ten drafts: draft-07 has no Fetch Type and names the track inline, drafts
/// 08 through 10 add the type and make every other field optional, draft-11
/// moves them into a payload enum, and draft-15 drops the priority and order.
#[macro_export]
macro_rules! peers_fetch {
    (inline, $id:expr, $track:expr) => {
        Fetch {
            subscribe_id: $crate::v($id),
            track_namespace: $crate::namespace(),
            track_name: $track.to_vec(),
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            start_group: $crate::v(0),
            start_object: $crate::v(0),
            end_group: $crate::v(1),
            end_object: $crate::v(0),
            parameters: Vec::new(),
        }
    };
    (optional, $id:expr, $track:expr) => {
        Fetch {
            subscribe_id: $crate::v($id),
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            fetch_type: FetchType::Standalone,
            track_namespace: Some($crate::namespace()),
            track_name: Some($track.to_vec()),
            start_group: Some($crate::v(0)),
            start_object: Some($crate::v(0)),
            end_group: Some($crate::v(1)),
            end_object: Some($crate::v(0)),
            joining_subscribe_id: None,
            preceding_group_offset: None,
            parameters: Vec::new(),
        }
    };
    (payload, $id:expr, $track:expr) => {
        Fetch {
            request_id: $crate::v($id),
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            fetch_type: FetchType::Standalone,
            fetch_payload: FetchPayload::Standalone {
                track_namespace: $crate::namespace(),
                track_name: $track.to_vec(),
                start_group: $crate::v(0),
                start_object: $crate::v(0),
                end_group: $crate::v(1),
                end_object: $crate::v(0),
            },
            parameters: Vec::new(),
        }
    };
    (bare, $id:expr, $track:expr) => {
        Fetch {
            request_id: $crate::v($id),
            fetch_type: FetchType::Standalone,
            fetch_payload: FetchPayload::Standalone {
                track_namespace: $crate::namespace(),
                track_name: $track.to_vec(),
                start_group: $crate::v(0),
                start_object: $crate::v(0),
                end_group: $crate::v(1),
                end_object: $crate::v(0),
            },
            parameters: Vec::new(),
        }
    };
}

/// The FETCH_OK this endpoint builds, in the four shapes the answer takes:
/// draft-07 leaves the largest group and object optional, drafts 08 through 10
/// require them, draft-11 replaces the pair with a Location, and draft-15
/// splits it back into two fields and drops the group order.
#[macro_export]
macro_rules! we_accept {
    (optional_largest, $ep:expr, $id:expr) => {
        $ep.send_fetch_ok(
            $crate::v($id),
            GroupOrder::Ascending,
            0,
            Some($crate::v(1)),
            Some($crate::v(0)),
            Vec::new(),
        )
    };
    (largest, $ep:expr, $id:expr) => {
        $ep.send_fetch_ok(
            $crate::v($id),
            GroupOrder::Ascending,
            0,
            $crate::v(1),
            $crate::v(0),
            Vec::new(),
        )
    };
    (location, $ep:expr, $id:expr) => {
        $ep.send_fetch_ok(
            $crate::v($id),
            GroupOrder::Ascending,
            0,
            Location { group: $crate::v(1), object: $crate::v(0) },
            Vec::new(),
        )
    };
    (split, $ep:expr, $id:expr) => {
        $ep.send_fetch_ok($crate::v($id), 0, $crate::v(1), $crate::v(0), Vec::new())
    };
    (extensions, $ep:expr, $id:expr) => {
        $ep.send_fetch_ok($crate::v($id), 0, $crate::v(1), $crate::v(0), Vec::new(), Vec::new())
    };
}

/// The refusal this endpoint builds, which drafts 15 and 16 renamed and gave a
/// retry interval to.
#[macro_export]
macro_rules! we_refuse {
    (fetch_error, $ep:expr, $id:expr, $code:expr) => {
        $ep.send_fetch_error($crate::v($id), $crate::v($code), b"no".to_vec())
    };
    (request_error, $ep:expr, $id:expr, $code:expr) => {
        $ep.send_request_error($crate::v($id), $crate::v($code), b"no".to_vec())
    };
    (retry, $ep:expr, $id:expr, $code:expr) => {
        $ep.send_request_error($crate::v($id), $crate::v($code), $crate::v(0), b"no".to_vec())
    };
}

/// This endpoint's own FETCH. Draft-14 takes only the track and a start,
/// filling the rest in, and draft-15 dropped the priority and group order.
#[macro_export]
macro_rules! we_fetch {
    (full, $ep:expr, $track:expr) => {
        $ep.fetch(
            $crate::namespace(),
            $track.to_vec(),
            128,
            GroupOrder::Ascending,
            $crate::v(0),
            $crate::v(0),
            $crate::v(1),
            $crate::v(0),
        )
    };
    (full_params, $ep:expr, $track:expr) => {
        $ep.fetch(
            $crate::namespace(),
            $track.to_vec(),
            128,
            GroupOrder::Ascending,
            $crate::v(0),
            $crate::v(0),
            $crate::v(1),
            $crate::v(0),
            Vec::new(),
        )
    };
    (short, $ep:expr, $track:expr) => {
        $ep.fetch(
            $crate::namespace(),
            $track.to_vec(),
            128,
            GroupOrder::Ascending,
            $crate::v(0),
            $crate::v(0),
            $crate::v(0),
            $crate::v(0),
            Vec::new(),
        )
    };
    (bare, $ep:expr, $track:expr) => {
        $ep.fetch(
            $crate::namespace(),
            $track.to_vec(),
            $crate::v(0),
            $crate::v(0),
            $crate::v(1),
            $crate::v(0),
            Vec::new(),
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

/// The same, plus the ceiling the peer must grant before this endpoint may
/// open a fetch of its own.
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

/// Why a second answer is refused, which nine of the ten drafts say in one
/// sentence and draft-07 does not say at all.
#[macro_export]
macro_rules! one_answer {
    (uncited) => {
        "a fetch that has been answered has left the state an answer is sent from"
    };
    ($sec:literal) => {
        concat!("Section ", $sec, " says the publisher sends exactly one answer to a FETCH")
    };
}

/// One draft's ten gates.
macro_rules! inbound_fetch_gates {
    ($draft:ident, $feat:literal, $version:expr, $role:path, $unknown:ident, $grant:ident,
     $params:tt, $setup:tt, $fetchmsg:tt, $accept:tt, $refuse:tt, $ourfetch:tt,
     $peers_first:literal, $one:tt) => {
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

            /// The peer's first identifier for a request of its own.
            const PEERS_FIRST: u64 = $peers_first;

            /// A second one, for the gates that need two fetches at once.
            const PEERS_SECOND: u64 = $peers_first + 2;

            /// An identifier no FETCH ever arrived under.
            const NEVER_USED: u64 = 9;

            /// A refusal code every one of these drafts has.
            const INTERNAL_ERROR: u64 = 0x0;

            const ALPHA: &[u8] = b"alpha";
            const BETA: &[u8] = b"beta";

            /// A client with its session established and a budget granted to
            /// the peer, without which no FETCH of the peer's is legal.
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

            /// An endpoint holding the peer's unanswered FETCH.
            fn fetched() -> Endpoint {
                let mut ep = active();
                ep.receive_fetch(&crate::peers_fetch!($fetchmsg, PEERS_FIRST, ALPHA))
                    .expect("the peer's FETCH");
                ep
            }

            /// An endpoint that has accepted the peer's FETCH and is serving
            /// it.
            fn serving() -> Endpoint {
                let mut ep = fetched();
                crate::we_accept!($accept, ep, PEERS_FIRST).expect("accept the fetch");
                ep
            }

            /// The session is still running: none of these rules is one this
            /// endpoint answers by closing.
            fn still_running(ep: &Endpoint) {
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "refusing to build a message is not a reason to end the session"
                );
            }

            /// A FETCH arriving the way the control stream delivers one
            /// reaches the flow that can answer it.
            ///
            /// The dispatch arm is the whole of what this measures. Without it
            /// the FETCH is counted and dropped, and the peer waits for an
            /// answer the endpoint has no record to build one from.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// the FETCH that arrived on the control stream could not be answered: UnknownSubscribe(0)
            /// ```
            ///
            /// Made by removing the `ControlMessage::Fetch` arm from `receive_message`.
            /// It reddens twenty tests: this gate on all ten drafts, and both wire
            /// gates on the five that have them, where the FETCH arrives through the
            /// same dispatch.
            #[test]
            fn a_fetch_off_the_control_stream_reaches_the_flow() {
                let mut ep = active();
                ep.receive_message(ControlMessage::Fetch(crate::peers_fetch!(
                    $fetchmsg,
                    PEERS_FIRST,
                    ALPHA
                )))
                .expect("the control stream delivers a FETCH");
                crate::we_accept!($accept, ep, PEERS_FIRST)
                    .expect("the FETCH that arrived on the control stream could not be answered");
            }

            /// A FETCH is owed an answer from the moment it arrives until one
            /// is sent.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// assertion `left == right` failed: the answer settled it
            ///   left: 1
            ///  right: 0
            /// ```
            ///
            /// Made by leaving the record where it was when the FETCH_OK went out. It
            /// reddens fifty tests on the ten drafts: a fetch that never leaves the
            /// state it arrived in is one nothing later in the flow can act on.
            #[test]
            fn an_arriving_fetch_is_owed_an_answer() {
                let mut ep = active();
                assert_eq!(ep.pending_fetch_count(), 0, "no FETCH has arrived yet");
                ep.receive_fetch(&crate::peers_fetch!($fetchmsg, PEERS_FIRST, ALPHA))
                    .expect("the peer's FETCH");
                assert_eq!(ep.pending_fetch_count(), 1, "the peer's FETCH is owed an answer");
                assert!(
                    ep.pending_fetch($crate::v(PEERS_FIRST)).is_some(),
                    "the FETCH the answer is built from should be readable"
                );
                crate::we_accept!($accept, ep, PEERS_FIRST).expect("accept the fetch");
                assert_eq!(ep.pending_fetch_count(), 0, "the answer settled it");
                assert!(
                    ep.pending_fetch($crate::v(PEERS_FIRST)).is_none(),
                    "an answered FETCH is owed nothing"
                );
            }

            /// One FETCH gets one answer.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// a fetch that has been answered has left the state an answer is sent from: FetchOk(FetchOk { subscribe_id: VarInt(0), group_order: Ascending, end_of_track: 0, largest_group_id: Some(VarInt(1)), largest_object_id: Some(VarInt(0)), parameters: [] })
            /// ```
            ///
            /// The same cut. Nine of these drafts say a publisher sends exactly one
            /// answer to a FETCH and draft-07 says nothing at all, and the flow
            /// refuses the second one on all ten for the same reason.
            #[test]
            fn one_fetch_gets_one_answer() {
                let mut ep = serving();
                let err = crate::we_accept!($accept, ep, PEERS_FIRST)
                    .expect_err(crate::one_answer!($one));
                assert!(
                    matches!(err, EndpointError::Fetch(_)),
                    "the flow refuses the second answer; got {err:?}"
                );
                still_running(&ep);
            }

            /// A fetch that was refused cannot then be accepted.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// assertion `left == right` failed: the refusal settled it
            ///   left: 1
            ///  right: 0
            /// ```
            ///
            /// The refusal has a cut of its own, and it reddens ten tests and only
            /// this gate: nothing else here refuses a fetch.
            #[test]
            fn a_refused_fetch_cannot_then_be_accepted() {
                let mut ep = fetched();
                crate::we_refuse!($refuse, ep, PEERS_FIRST, INTERNAL_ERROR)
                    .expect("refuse the fetch");
                assert_eq!(ep.pending_fetch_count(), 0, "the refusal settled it");
                let err = crate::we_accept!($accept, ep, PEERS_FIRST)
                    .expect_err(crate::one_answer!($one));
                assert!(
                    matches!(err, EndpointError::Fetch(_)),
                    "the flow refuses the second answer; got {err:?}"
                );
                still_running(&ep);
            }

            /// An answer to a fetch that never arrived is refused.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// no FETCH arrived under that identifier: FetchOk(FetchOk { subscribe_id: VarInt(9), group_order: Ascending, end_of_track: 0, largest_group_id: Some(VarInt(1)), largest_object_id: Some(VarInt(0)), parameters: [] })
            /// ```
            ///
            /// Made by answering whichever inbound fetch is first in the map, at every
            /// call site that names an identifier. It reddens forty tests: this gate,
            /// the cancel's, the second half of the stream gate and the two-record gate,
            /// on all ten drafts.
            #[test]
            fn an_answer_to_a_fetch_that_never_arrived_is_refused() {
                let mut ep = fetched();
                let err = crate::we_accept!($accept, ep, NEVER_USED)
                    .expect_err("no FETCH arrived under that identifier");
                assert!(
                    matches!(err, EndpointError::$unknown(NEVER_USED)),
                    "the refusal should name the identifier; got {err:?}"
                );
                let err = crate::we_refuse!($refuse, ep, NEVER_USED, INTERNAL_ERROR)
                    .expect_err("no FETCH arrived under that identifier");
                assert!(
                    matches!(err, EndpointError::$unknown(NEVER_USED)),
                    "the refusal should name the identifier; got {err:?}"
                );
                still_running(&ep);
            }

            /// A FETCH_CANCEL ends a fetch this endpoint is serving.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// a fetch that has ended cannot end again: ()
            /// ```
            ///
            /// Made by removing the `ControlMessage::FetchCancel` arm from
            /// `receive_message`. It reddens ten tests and only this gate: nothing else
            /// here needs a cancel off the control stream.
            #[test]
            fn a_fetch_cancel_ends_a_fetch_this_endpoint_serves() {
                let mut ep = serving();
                ep.receive_message(ControlMessage::FetchCancel(crate::peers_cancel!(
                    $fetchmsg,
                    PEERS_FIRST
                )))
                .expect("the subscriber stops the fetch");
                let err = ep
                    .receive_fetch_cancel(&crate::peers_cancel!($fetchmsg, PEERS_FIRST))
                    .expect_err("a fetch that has ended cannot end again");
                assert!(
                    matches!(err, EndpointError::Fetch(_)),
                    "the flow refuses the second cancel; got {err:?}"
                );
                still_running(&ep);
            }

            /// A FETCH_CANCEL for a fetch that never arrived is refused.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// no FETCH arrived under that identifier: ()
            /// ```
            ///
            /// The same cut as the gate above, reached through the cancel rather than
            /// the answer. One claim with four call sites, so the cut replaces every
            /// match rather than exactly one.
            #[test]
            fn a_fetch_cancel_for_nothing_is_refused() {
                let mut ep = serving();
                let err = ep
                    .receive_fetch_cancel(&crate::peers_cancel!($fetchmsg, NEVER_USED))
                    .expect_err("no FETCH arrived under that identifier");
                assert!(
                    matches!(err, EndpointError::$unknown(NEVER_USED)),
                    "the refusal should name the identifier; got {err:?}"
                );
                still_running(&ep);
            }

            /// Two fetches of the peer's are two records, and answering one
            /// leaves the other owed its answer.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// assertion `left == right` failed: both are owed an answer
            ///   left: 1
            ///  right: 2
            /// ```
            ///
            /// Made by clearing the map before each insert, which is what one record
            /// for the whole session amounts to. It reddens ten tests and only this
            /// gate.
            #[test]
            fn two_fetches_of_the_peers_have_their_own_records() {
                let mut ep = active();
                ep.receive_fetch(&crate::peers_fetch!($fetchmsg, PEERS_FIRST, ALPHA))
                    .expect("the peer's first FETCH");
                ep.receive_fetch(&crate::peers_fetch!($fetchmsg, PEERS_SECOND, BETA))
                    .expect("the peer's second FETCH");
                assert_eq!(ep.pending_fetch_count(), 2, "both are owed an answer");
                crate::we_accept!($accept, ep, PEERS_FIRST).expect("answer the first");
                assert_eq!(ep.pending_fetch_count(), 1, "the second is still owed one");
                assert!(
                    ep.pending_fetch($crate::v(PEERS_SECOND)).is_some(),
                    "the second FETCH should still be readable"
                );
                crate::we_accept!($accept, ep, PEERS_SECOND).expect("answer the second");
                assert_eq!(ep.pending_fetch_count(), 0, "both are answered");
            }

            /// Finishing the data stream ends a fetch this endpoint served.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// a fetch that is over cannot be cancelled: ()
            /// ```
            ///
            /// Made by leaving the record where it was when this endpoint finished the
            /// objects. It reddens ten tests and only this gate; the cancel's own cut
            /// reddens this one too, which is what two ways of ending one fetch look
            /// like.
            #[test]
            fn finishing_the_data_stream_ends_a_served_fetch() {
                let mut ep = serving();
                ep.on_peer_fetch_stream_fin($crate::v(PEERS_FIRST))
                    .expect("this endpoint finished the objects");
                let err = ep
                    .receive_fetch_cancel(&crate::peers_cancel!($fetchmsg, PEERS_FIRST))
                    .expect_err("a fetch that is over cannot be cancelled");
                assert!(
                    matches!(err, EndpointError::Fetch(_)),
                    "the flow refuses the cancel; got {err:?}"
                );
                let err = ep
                    .on_peer_fetch_stream_fin($crate::v(NEVER_USED))
                    .expect_err("no FETCH arrived under that identifier");
                assert!(
                    matches!(err, EndpointError::$unknown(NEVER_USED)),
                    "the refusal should name the identifier; got {err:?}"
                );
                still_running(&ep);
            }

            /// A fetch this endpoint made is not one it answers.
            ///
            /// The two directions are two records. On the drafts with no
            /// parity rule they can share a number, and answering the wrong
            /// one would move a fetch this endpoint is waiting on.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// ```text
            /// a fetch this endpoint made is not one it answers: FetchOk(FetchOk { subscribe_id: VarInt(0), group_order: Ascending, end_of_track: 0, largest_group_id: VarInt(1), largest_object_id: VarInt(0), parameters: [] })
            /// ```
            ///
            /// Made by reading the answer out of `fetches`, where this endpoint's own
            /// fetches live. It reddens a hundred and forty-two tests, because a
            /// record read from the wrong map is missing from every gate that needs
            /// it, and only this one shows what the wrong map holds instead.
            #[test]
            fn a_fetch_this_endpoint_made_is_not_the_peers() {
                let mut ep = active();
                let (ours, _) = crate::we_fetch!($ourfetch, ep, ALPHA).expect("our own FETCH");
                assert_eq!(ep.pending_fetch_count(), 0, "a fetch we made is not one we answer");
                let err = crate::we_accept!($accept, ep, ours.into_inner())
                    .expect_err("a fetch this endpoint made is not one it answers");
                assert!(
                    matches!(err, EndpointError::$unknown(_)),
                    "the refusal should name the identifier; got {err:?}"
                );
                still_running(&ep);
            }
        }
    };
}

/// The FETCH_CANCEL the peer sends, whose identifier followed the FETCH's own.
#[macro_export]
macro_rules! peers_cancel {
    (inline, $id:expr) => {
        FetchCancel { subscribe_id: $crate::v($id) }
    };
    (optional, $id:expr) => {
        FetchCancel { subscribe_id: $crate::v($id) }
    };
    (payload, $id:expr) => {
        FetchCancel { request_id: $crate::v($id) }
    };
    (bare, $id:expr) => {
        FetchCancel { request_id: $crate::v($id) }
    };
}

inbound_fetch_gates!(
    draft07,
    "draft07",
    0xff00_0007,
    moqtap_client::draft07::endpoint::Role,
    UnknownSubscribe,
    send_max_subscribe_id,
    role,
    versioned,
    inline,
    optional_largest,
    fetch_error,
    full,
    0,
    uncited
);
inbound_fetch_gates!(
    draft08,
    "draft08",
    0xff00_0008,
    moqtap_client::draft08::endpoint::Role,
    UnknownSubscribe,
    send_max_subscribe_id,
    none,
    versioned,
    optional,
    largest,
    fetch_error,
    full,
    0,
    "4.3"
);
inbound_fetch_gates!(
    draft09,
    "draft09",
    0xff00_0009,
    moqtap_client::draft09::endpoint::Role,
    UnknownSubscribe,
    send_max_subscribe_id,
    none,
    versioned,
    optional,
    largest,
    fetch_error,
    full,
    0,
    "4.3"
);
inbound_fetch_gates!(
    draft10,
    "draft10",
    0xff00_000a,
    moqtap_client::draft10::endpoint::Role,
    UnknownSubscribe,
    send_max_subscribe_id,
    none,
    versioned,
    optional,
    largest,
    fetch_error,
    full,
    0,
    "4"
);
inbound_fetch_gates!(
    draft11,
    "draft11",
    0xff00_000b,
    moqtap_client::draft11::session::request_id::Role,
    UnknownRequest,
    send_max_request_id,
    none,
    versioned,
    payload,
    location,
    fetch_error,
    full,
    1,
    "4"
);
inbound_fetch_gates!(
    draft12,
    "draft12",
    0xff00_000c,
    moqtap_client::draft12::session::request_id::Role,
    UnknownRequest,
    send_max_request_id,
    none,
    versioned,
    payload,
    location,
    fetch_error,
    full_params,
    1,
    "4.1"
);
inbound_fetch_gates!(
    draft13,
    "draft13",
    0xff00_000d,
    moqtap_client::draft13::session::request_id::Role,
    UnknownRequest,
    send_max_request_id,
    none,
    versioned,
    payload,
    location,
    fetch_error,
    full_params,
    1,
    "4.1"
);
inbound_fetch_gates!(
    draft14,
    "draft14",
    0xff00_000e,
    moqtap_client::draft14::session::request_id::Role,
    UnknownRequest,
    send_max_request_id,
    none,
    versioned,
    payload,
    location,
    fetch_error,
    short,
    1,
    "5.1"
);
inbound_fetch_gates!(
    draft15,
    "draft15",
    0xff00_000f,
    moqtap_client::draft15::session::request_id::Role,
    UnknownRequest,
    send_max_request_id,
    none,
    alpn,
    bare,
    split,
    request_error,
    bare,
    1,
    "5.2"
);
inbound_fetch_gates!(
    draft16,
    "draft16",
    0xff00_0010,
    moqtap_client::draft16::session::request_id::Role,
    UnknownRequest,
    send_max_request_id,
    none,
    alpn,
    bare,
    extensions,
    retry,
    bare,
    1,
    "5.2"
);

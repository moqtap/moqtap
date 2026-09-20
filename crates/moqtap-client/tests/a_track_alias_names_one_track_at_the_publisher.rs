#![cfg(any(
    feature = "draft07",
    feature = "draft08",
    feature = "draft09",
    feature = "draft10",
    feature = "draft11",
))]

//! One Track Alias may not name two tracks at once, on the five drafts that
//! say so at the publisher.
//!
//! Draft-11 Section 8.7, and drafts 07 through 10 in the same words in their
//! own SUBSCRIBE sections: "Track Alias: A session specific identifier for the
//! track. ... If the Track Alias is already being used for a different track,
//! the publisher MUST close the session with a Duplicate Track Alias error."
//! The alias is a field of SUBSCRIBE here and the subscriber chooses it, so
//! the endpoint that must close is the one the SUBSCRIBE arrives at.
//!
//! The same five state a second half at the subscriber, on the alias a
//! SUBSCRIBE_ERROR may offer for a retry. Draft-11 Section 8.9, and 07 through
//! 10 in the same words: "When Error Code is 'Retry Track Alias', the
//! subscriber SHOULD re-issue the SUBSCRIBE with this Track Alias instead. If
//! this Track Alias is already in use, the subscriber MUST close the
//! connection with a Duplicate Track Alias error (Section 3.4)."
//!
//! And a third: this endpoint chooses aliases too, in the SUBSCRIBEs it sends.
//! Section 3.4 describes the code as "The endpoint attempted to use a Track
//! Alias that was already in use" - drafts 07, 08 and 09 in Section 3.5 - so a
//! SUBSCRIBE that gives an alias to a second track is one the peer must answer
//! by ending the session. It is refused before it is built instead, and that
//! refusal is not a close: the alias never reaches the peer.
//!
//! # Where the rule goes at draft-12
//!
//! It does not go away, it moves. From draft-12 the alias travels in
//! SUBSCRIBE_OK and PUBLISH, which the publisher chooses, and the subscriber
//! is the endpoint that must close. That half is in
//! `duplicate_track_alias_closes_the_session.rs`.
//!
//! # What the comparison set is
//!
//! Every subscription in the session whose Track Alias this endpoint knows and
//! whose state machine still says it is standing - the ones the peer opened
//! and the ones this endpoint opened alike, because a Track Alias is "a
//! session specific identifier" and there is one space of them per session.
//! Nothing is kept beside the state machines: an alias is free again the
//! instant its subscription ends, and no path that ends one has to remember to
//! say so.
//!
//! Standing here means Subscribing or Active, not Active alone. These drafts
//! say "already being used" with no qualifier on it, and the alias is in the
//! SUBSCRIBE itself, so it is in use from the moment that message is sent or
//! received. Drafts 12 onwards qualify it - "a different track with an active
//! subscription" - and there the alias arrives in the answer, so only an
//! answered request holds one.
//!
//! # Why the error code is asserted and not just the refusal
//!
//! The sections name Duplicate Track Alias and name no other code. A gate that
//! observed only that the session ended would pass just as well against a
//! close carrying Protocol Violation, and which rule was broken is the whole
//! of what the peer is being told. Every gate below reads the code the
//! transport would carry, and the loopback gate in
//! `duplicate_track_alias_at_the_publisher_on_the_wire.rs` reads it off the
//! CONNECTION_CLOSE.
//!
//! # Ablations, measured
//!
//! Nine cuts were made, run and reverted, each recorded on the gate it belongs
//! to. The three halves of the rule come apart under them: cutting what judges
//! an arriving SUBSCRIBE leaves both retry gates green, cutting the retry
//! judge leaves the arriving one green, and cutting the refusal this endpoint
//! makes of its own SUBSCRIBE leaves both.

#![allow(clippy::items_after_test_module)]

use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;

/// The namespace both tracks live in, so that the track name is the only thing
/// telling them apart.
fn namespace() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec()])
}

fn v(n: u64) -> VarInt {
    VarInt::from_u64(n).unwrap()
}

/// A SUBSCRIBE from the peer, in the three shapes it takes across the five
/// drafts.
#[macro_export]
macro_rules! peer_subscribe {
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

/// A SUBSCRIBE this endpoint sends. Draft-11 takes the Filter Type as a
/// varint, the four before it as a named type.
#[macro_export]
macro_rules! our_subscribe {
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

/// The UNSUBSCRIBE the subscribing peer sends.
#[macro_export]
macro_rules! peer_unsubscribes {
    (subscribe_id, $id:expr) => {
        Unsubscribe { subscribe_id: $id }
    };
    (request_id, $id:expr) => {
        Unsubscribe { request_id: $id }
    };
}

/// A SUBSCRIBE_ERROR the peer sends, offering `alias` under `code`.
#[macro_export]
macro_rules! peer_rejects {
    (subscribe_id, $id:expr, $code:expr, $alias:expr) => {
        SubscribeError {
            subscribe_id: $id,
            error_code: $crate::v($code),
            reason_phrase: b"no".to_vec(),
            track_alias: $crate::v($alias),
        }
    };
    (request_id, $id:expr, $code:expr, $alias:expr) => {
        SubscribeError {
            request_id: $id,
            error_code: $crate::v($code),
            reason_phrase: b"no".to_vec(),
            track_alias: $crate::v($alias),
        }
    };
}

/// The setup parameters both ends send. The ceiling is in both, because these
/// gates need the peer to be allowed to subscribe and this endpoint to be
/// allowed to subscribe back. Draft-07 also requires a ROLE of both endpoints,
/// and is the only one of the five that does.
#[macro_export]
macro_rules! alias_setup_params {
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

/// One draft's nine gates.
macro_rules! publisher_alias_gates {
    ($draft:ident, $feat:literal, $version:expr, $role:path, $submsg:tt, $oursub:tt,
     $unsub:tt, $idname:tt, $params:tt, $peers_first:literal, $step:literal,
     $retry:literal, $sub_sec:literal, $err_sec:literal) => {
        #[cfg(feature = $feat)]
        mod $draft {
            use moqtap_client::$draft::endpoint::{Endpoint, EndpointError};
            use moqtap_client::$draft::session::state::SessionState;
            use $role as Role;

            use moqtap_codec::kvp::{KeyValuePair, KvpValue};
            #[allow(unused_imports)]
            use moqtap_codec::types::*;
            use moqtap_codec::varint::VarInt;
            use moqtap_codec::$draft::error_codes::SessionErrorCode;
            use moqtap_codec::$draft::message::*;

            /// The peer's first identifier for a request of its own.
            const PEERS_FIRST: u64 = $peers_first;
            const PEERS_SECOND: u64 = $peers_first + 2;

            /// The alias both tracks are asked to answer to.
            const ALIAS: u64 = 7;

            /// The code this draft assigns to 'Retry Track Alias'.
            const RETRY_TRACK_ALIAS: u64 = $retry;

            /// A code that is not 'Retry Track Alias' on any of the five.
            const NOT_A_RETRY: u64 = 0x0;

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
                    .send_client_setup(
                        vec![$crate::v($version)],
                        $crate::alias_setup_params!($params),
                    )
                    .expect("CLIENT_SETUP");
                ep.receive_server_setup(&ServerSetup {
                    selected_version: $crate::v($version),
                    parameters: $crate::alias_setup_params!($params),
                })
                .expect("SERVER_SETUP");
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "the gates need a running session"
                );
                ep
            }

            /// Assert the endpoint has ended its own session and named the
            /// code the sections name.
            fn refused(ep: &Endpoint, err: &EndpointError, what: &str) {
                assert_eq!(
                    err.session_error_code(),
                    Some(SessionErrorCode::DuplicateTrackAlias),
                    "Sections {} and {} answer {what} with Duplicate Track Alias and \
                     with no other code; the endpoint offered {:?}",
                    $sub_sec,
                    $err_sec,
                    err.session_error_code()
                );
                assert_eq!(
                    ep.session_state(),
                    SessionState::Closed,
                    "a rule the draft answers with a session close has to end this \
                     endpoint's own session too, or nothing puts the close on the wire"
                );
            }

            /// The session is untouched: the rule this gate measures is one
            /// this endpoint answers by declining to act, not by closing.
            fn still_running(ep: &Endpoint) {
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "a message this endpoint declined to build never reached the peer, \
                     so there is nothing for either end to close over"
                );
            }

            /// A second track under an alias a live subscription holds ends the
            /// session.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// Deleting the `conflicting_track_alias` call from
            /// `receive_subscribe`:
            ///
            /// ```text
            /// the peer gave one alias to two tracks and was not refused: ()
            /// ```
            ///
            /// It reddens fifteen tests: this gate and the one below it that
            /// holds this endpoint's own alias against the peer, on all five
            /// drafts, and the loopback gate on the same five.
            #[test]
            fn a_second_track_under_a_live_alias_closes_the_session() {
                let mut ep = active();
                ep.receive_subscribe(&crate::peer_subscribe!($submsg, PEERS_FIRST, ALIAS, ALPHA))
                    .expect("the peer's first SUBSCRIBE");

                let err = ep
                    .receive_subscribe(&crate::peer_subscribe!($submsg, PEERS_SECOND, ALIAS, BETA))
                    .expect_err("the peer gave one alias to two tracks and was not refused");
                refused(&ep, &err, "one alias naming two tracks");
            }

            /// The same track under the same alias is not a conflict.
            ///
            /// The rule is about an alias naming two tracks, not about naming
            /// one track twice.
            ///
            /// # What it catches
            ///
            /// Comparing only the alias and not the track it names, which
            /// turns every re-subscription into a session close:
            ///
            /// ```text
            /// a second subscription to the same track under the same alias was refused: DuplicateTrackAlias { alias: 7, established_side: Peers, established: 0, offered_side: Peers, offered: 2 }
            /// ```
            #[test]
            fn the_same_track_under_the_same_alias_is_not_a_conflict() {
                let mut ep = active();
                ep.receive_subscribe(&crate::peer_subscribe!($submsg, PEERS_FIRST, ALIAS, ALPHA))
                    .expect("the peer's first SUBSCRIBE");

                ep.receive_subscribe(&crate::peer_subscribe!($submsg, PEERS_SECOND, ALIAS, ALPHA))
                    .expect(
                        "a second subscription to the same track under the same alias was refused",
                    );
                still_running(&ep);
            }

            /// An alias is free again once the subscription holding it ends.
            ///
            /// This is the half that could not be built before the publisher
            /// had a lifecycle for an inbound SUBSCRIBE: a binding nothing can
            /// retire refuses the peer's next, conforming, use of the alias.
            ///
            /// # What it catches
            ///
            /// Reading liveness off a set kept beside the state machines
            /// rather than off the state machines themselves - equivalently,
            /// answering `binding_is_live` with `true`:
            ///
            /// ```text
            /// an alias whose subscription had ended was still held: DuplicateTrackAlias { alias: 7, established_side: Peers, established: 0, offered_side: Peers, offered: 2 }
            /// ```
            #[test]
            fn an_alias_is_free_once_its_subscription_ends() {
                let mut ep = active();
                ep.receive_subscribe(&crate::peer_subscribe!($submsg, PEERS_FIRST, ALIAS, ALPHA))
                    .expect("the peer's first SUBSCRIBE");
                ep.send_subscribe_ok(peer_id(), $crate::v(0), GroupOrder::Ascending, Vec::new())
                    .expect("accept the subscription");
                ep.receive_unsubscribe(&crate::peer_unsubscribes!($unsub, peer_id()))
                    .expect("the peer's UNSUBSCRIBE");

                ep.receive_subscribe(&crate::peer_subscribe!($submsg, PEERS_SECOND, ALIAS, BETA))
                    .expect("an alias whose subscription had ended was still held");
                still_running(&ep);
            }

            /// An alias this endpoint chose for a track of its own is held
            /// against the peer's SUBSCRIBE.
            ///
            /// A Track Alias is "a session specific identifier", and both ends
            /// of a session draw from the one space. A gate built only on two
            /// SUBSCRIBEs from the peer would pass against a table that only
            /// ever recorded the peer's.
            ///
            /// # What it catches
            ///
            /// Not recording a binding for the SUBSCRIBEs this endpoint sends:
            ///
            /// ```text
            /// the peer took an alias this endpoint's own subscription held: ()
            /// ```
            ///
            /// It reddens twenty-five tests: five gates on all five drafts.
            /// Everything that reads an alias this endpoint chose reads it out
            /// of that one insert.
            #[test]
            fn an_alias_this_endpoint_chose_is_held_against_the_peer() {
                let mut ep = active();
                crate::our_subscribe!($oursub, ep, ALIAS, ALPHA)
                    .expect("this endpoint's SUBSCRIBE");

                let err = ep
                    .receive_subscribe(&crate::peer_subscribe!($submsg, PEERS_FIRST, ALIAS, BETA))
                    .expect_err("the peer took an alias this endpoint's own subscription held");
                refused(&ep, &err, "one alias naming two tracks");
            }

            /// A retry alias that is already in use ends the session.
            ///
            /// # What it catches
            ///
            /// Deleting the `conflicting_retry_alias` call from
            /// `receive_subscribe_error`:
            ///
            /// ```text
            /// the retry offered an alias another track was using and was not refused: ()
            /// ```
            ///
            /// It reddens ten tests: this gate on all five drafts and the
            /// loopback gate on the same five. Nothing that judges an arriving
            /// SUBSCRIBE is touched, which is what makes the two halves of the
            /// rule two rules.
            #[test]
            fn a_retry_alias_already_in_use_closes_the_session() {
                let mut ep = active();
                crate::our_subscribe!($oursub, ep, ALIAS, ALPHA).expect("the ALPHA subscription");
                let (beta, _) = crate::our_subscribe!($oursub, ep, ALIAS + 1, BETA)
                    .expect("the BETA subscription");

                let err = ep
                    .receive_subscribe_error(&crate::peer_rejects!(
                        $idname,
                        beta,
                        RETRY_TRACK_ALIAS,
                        ALIAS
                    ))
                    .expect_err(
                        "the retry offered an alias another track was using and was not refused",
                    );
                refused(&ep, &err, "a retry alias that is already in use");
            }

            /// A retry alias that is free is taken up, and the failed
            /// subscription ends the way any refused one does.
            ///
            /// This is the positive control the two refusing gates need. A
            /// judge that answered every retry with a conflict would pass both
            /// of them: one expects a refusal, and the other never reaches the
            /// judge because its code is not a retry.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// Answering an offer of a free alias as though it were taken -
            /// falling back to a conflict where the holder lookup finds none:
            ///
            /// ```text
            /// a free retry alias was refused: DuplicateTrackAlias { alias: 8, established_side: Ours, established: 0, offered_side: Ours, offered: 0 }
            /// ```
            ///
            /// It reddens five tests and only this gate, on all five drafts.
            #[test]
            fn a_free_retry_alias_is_taken_up() {
                let mut ep = active();
                let (alpha, _) =
                    crate::our_subscribe!($oursub, ep, ALIAS, ALPHA).expect("the subscription");

                ep.receive_subscribe_error(&crate::peer_rejects!(
                    $idname,
                    alpha,
                    RETRY_TRACK_ALIAS,
                    ALIAS + 1
                ))
                .expect("a free retry alias was refused");
                still_running(&ep);

                crate::our_subscribe!($oursub, ep, ALIAS + 1, ALPHA)
                    .expect("the retry the draft asks the subscriber to make");
            }

            /// The Track Alias field means nothing under any other code.
            ///
            /// # What it catches
            ///
            /// Judging the field whatever the code says, which closes the
            /// session over a number the peer never meant as an offer:
            ///
            /// ```text
            /// a Track Alias under a code that is not a retry was judged: DuplicateTrackAlias { alias: 7, established_side: Ours, established: 0, offered_side: Ours, offered: 1 }
            /// ```
            #[test]
            fn a_track_alias_under_another_code_is_ignored() {
                let mut ep = active();
                crate::our_subscribe!($oursub, ep, ALIAS, ALPHA).expect("the ALPHA subscription");
                let (beta, _) = crate::our_subscribe!($oursub, ep, ALIAS + 1, BETA)
                    .expect("the BETA subscription");

                ep.receive_subscribe_error(&crate::peer_rejects!(
                    $idname,
                    beta,
                    NOT_A_RETRY,
                    ALIAS
                ))
                .expect("a Track Alias under a code that is not a retry was judged");
                still_running(&ep);
            }

            /// This endpoint will not give one alias to two tracks, and says
            /// so instead of sending the message.
            ///
            /// # What it catches
            ///
            /// Deleting the `alias_holder` call from `subscribe_inner`:
            ///
            /// ```text
            /// this endpoint gave one alias to two tracks: (VarInt(1), Subscribe(Subscribe { subscribe_id: VarInt(1), track_alias: VarInt(7), track_namespace: TrackNamespace([[99, 111, 110, 102, 111, 114, 109, 97, 110, 99, 101]]), track_name: [98, 101, 116, 97], subscriber_priority: 128, group_order: Ascending, filter_type: LargestObject, start_location: None, end_group: None, end_object: None, parameters: [] }))
            /// ```
            ///
            /// It reddens ten tests: this gate and the one below it, on all
            /// five drafts. Nothing that judges a message arriving is touched.
            #[test]
            fn this_endpoint_will_not_give_one_alias_to_two_tracks() {
                let mut ep = active();
                crate::our_subscribe!($oursub, ep, ALIAS, ALPHA).expect("the ALPHA subscription");

                let err = crate::our_subscribe!($oursub, ep, ALIAS, BETA)
                    .expect_err("this endpoint gave one alias to two tracks");
                assert!(
                    matches!(err, EndpointError::TrackAliasInUse { .. }),
                    "the refusal should name the alias that is spoken for, and named {err:?}"
                );
                assert_eq!(
                    err.session_error_code(),
                    None,
                    "a message this endpoint declined to build is not a session error"
                );
                still_running(&ep);
            }

            /// A refused SUBSCRIBE spends no identifier.
            ///
            /// The refusal comes before the allocation, so the next
            /// subscription takes the identifier the refused one would have
            /// had. Draft-11 steps its Request IDs by two because they carry
            /// the allocating end's parity; the four before it step by one.
            ///
            /// # What it catches
            ///
            /// Judging the alias after allocating the identifier:
            ///
            /// ```text
            /// assertion `left == right` failed: a refused SUBSCRIBE spent an identifier
            ///   left: 2
            ///  right: 1
            /// ```
            ///
            /// It reddens five tests and only this gate: the refusal still
            /// happens, so the gate above stays green and only the identifier
            /// it spent shows.
            #[test]
            fn a_refused_subscribe_spends_no_identifier() {
                let mut ep = active();
                let (first, _) =
                    crate::our_subscribe!($oursub, ep, ALIAS, ALPHA).expect("the subscription");
                crate::our_subscribe!($oursub, ep, ALIAS, BETA).expect_err("one alias, two tracks");

                let (next, _) = crate::our_subscribe!($oursub, ep, ALIAS + 1, BETA)
                    .expect("a second track under a second alias");
                assert_eq!(
                    next.into_inner(),
                    first.into_inner() + $step,
                    "a refused SUBSCRIBE spent an identifier"
                );
                still_running(&ep);
            }

            /// The alias this endpoint offers a caller is the lowest one no
            /// live binding holds.
            ///
            /// `AnyConnection::subscribe` spans all fourteen drafts with one
            /// signature and no alias argument, because on these five it takes
            /// the value from here. That only works if the offer is one the
            /// endpoint would itself accept — the two gates above refuse a
            /// duplicate, and an offer that had to be refused would make the
            /// facade's SUBSCRIBE fail on its second call.
            ///
            /// # What it catches
            ///
            /// Offering one past the highest taken alias rather than the
            /// lowest free one. That is not wrong on its own, but it drifts
            /// upward forever in a long session and never reuses what a
            /// finished subscription gave back:
            ///
            /// ```text
            /// assertion `left == right` failed: a hole below the highest taken alias is still free
            ///   left: 10
            ///  right: 1
            /// ```
            #[test]
            fn the_offered_alias_is_the_lowest_one_no_live_binding_holds() {
                let mut ep = active();
                assert_eq!(
                    ep.next_free_track_alias().into_inner(),
                    0,
                    "a session holding no alias should offer the first one"
                );

                crate::our_subscribe!($oursub, ep, 0, ALPHA).expect("ALPHA under alias 0");
                assert_eq!(
                    ep.next_free_track_alias().into_inner(),
                    1,
                    "an alias this endpoint just used is not free"
                );

                crate::our_subscribe!($oursub, ep, 9, BETA).expect("BETA under alias 9");
                assert_eq!(
                    ep.next_free_track_alias().into_inner(),
                    1,
                    "a hole below the highest taken alias is still free"
                );
                still_running(&ep);
            }

            /// The offer is read off the same table the refusals are, so an
            /// alias the *peer* holds is not offered, and one whose
            /// subscription has ended is offered again.
            ///
            /// A Track Alias is "a session specific identifier" and there is
            /// one space of them per session, so an offer that consulted only
            /// this endpoint's own subscriptions would hand out an alias the
            /// peer is using — and the gate that refuses it would then fire on
            /// a value this endpoint had just recommended.
            ///
            /// # What it catches
            ///
            /// Reading the offer off anything but the live bindings:
            ///
            /// ```text
            /// assertion `left == right` failed: the peer's alias is held against this endpoint's own choice too
            ///   left: 0
            ///  right: 1
            /// ```
            #[test]
            fn an_offered_alias_comes_back_when_its_subscription_ends() {
                let mut ep = active();
                ep.receive_subscribe(&crate::peer_subscribe!($submsg, PEERS_FIRST, 0, ALPHA))
                    .expect("the peer's SUBSCRIBE under alias 0");
                ep.send_subscribe_ok(peer_id(), $crate::v(0), GroupOrder::Ascending, Vec::new())
                    .expect("accept the subscription");
                assert_eq!(
                    ep.next_free_track_alias().into_inner(),
                    1,
                    "the peer's alias is held against this endpoint's own choice too"
                );

                ep.receive_unsubscribe(&crate::peer_unsubscribes!($unsub, peer_id()))
                    .expect("the peer's UNSUBSCRIBE");
                assert_eq!(
                    ep.next_free_track_alias().into_inner(),
                    0,
                    "an alias whose subscription ended is free to offer again"
                );
                still_running(&ep);
            }
        }
    };
}

publisher_alias_gates!(
    draft07,
    "draft07",
    0xff00_0007,
    moqtap_client::draft07::endpoint::Role,
    end_object,
    named,
    subscribe_id,
    subscribe_id,
    role,
    0,
    1,
    0x2,
    "6.4",
    "6.16"
);
publisher_alias_gates!(
    draft08,
    "draft08",
    0xff00_0008,
    moqtap_client::draft08::endpoint::Role,
    end_group,
    named,
    subscribe_id,
    subscribe_id,
    none,
    0,
    1,
    0x6,
    "7.4",
    "7.16"
);
publisher_alias_gates!(
    draft09,
    "draft09",
    0xff00_0009,
    moqtap_client::draft09::endpoint::Role,
    end_group,
    named,
    subscribe_id,
    subscribe_id,
    none,
    0,
    1,
    0x6,
    "7.4",
    "7.16"
);
publisher_alias_gates!(
    draft10,
    "draft10",
    0xff00_000a,
    moqtap_client::draft10::endpoint::Role,
    end_group,
    named,
    subscribe_id,
    subscribe_id,
    none,
    0,
    1,
    0x6,
    "8.6",
    "8.8"
);
publisher_alias_gates!(
    draft11,
    "draft11",
    0xff00_000b,
    moqtap_client::draft11::session::request_id::Role,
    forward,
    varint,
    request_id,
    request_id,
    none,
    1,
    2,
    0x6,
    "8.7",
    "8.9"
);

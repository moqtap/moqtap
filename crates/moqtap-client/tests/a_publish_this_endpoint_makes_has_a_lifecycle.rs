#![cfg(any(feature = "draft12", feature = "draft13", feature = "draft14"))]

//! This endpoint can offer the peer a subscription with PUBLISH, and carries
//! the offer from the moment it is built to the end of the subscription it
//! opens.
//!
//! Draft-12 Section 4.1, and draft-13 in the same words, with draft-14 saying
//! it in Section 5.1: "A
//! subscription can be initiated by either a publisher or a subscriber. A
//! publisher initiates a subscription to a track by sending the PUBLISH
//! message. The subscriber either accepts or rejects the subscription using
//! PUBLISH_OK or PUBLISH_ERROR. A subscriber initiates a subscription to a
//! track by sending the SUBSCRIBE message." Both halves of the first sentence
//! are the point: an application that can take an offer but cannot make one has
//! only half of the sequence the drafts describe, and the publisher's half is
//! what this file holds.
//!
//! What follows the answer is the same sentence for both sequences: "Once
//! either of these sequences is successful, the subscription can be updated by
//! the subscriber using SUBSCRIBE_UPDATE, terminated by the subscriber using
//! UNSUBSCRIBE, or terminated by the publisher using SUBSCRIBE_DONE." This
//! endpoint is the publisher of an offer it made, so SUBSCRIBE_DONE is the end
//! of it and the gates below take it there.
//!
//! Drafts 12 and 13 number every section this file names identically, and
//! draft-14 numbers each of them one chapter higher: its Section 4.1 is 5.1
//! and its 8.13 is 9.13, with the same words under both. The bare numbers
//! below are 12 and 13's, and the gate bodies carry draft-14's own where a
//! message names one.
//!
//! # What the caller names and what this endpoint derives
//!
//! `publish` takes the same seven arguments on all three drafts: the namespace,
//! the name, the alias, the delivery order, the largest location, the
//! forwarding flag and the parameters. The four after the alias are the ones an
//! offer would otherwise decide on the application's behalf, and the largest
//! location is the one that shows why that matters — an application offering a
//! track that already has content has to be able to say so, or the subscriber
//! reads "no object has been published on this track" whatever the application
//! knows.
//!
//! # The alias, and where its rule is measured
//!
//! Draft-12 Section 8.13, and draft-13's section of the same number, state
//! two rules in one sentence: "The same Track Alias MUST NOT be used to refer
//! to two different Tracks simultaneously. If a subscriber
//! receives a PUBLISH that uses the same Track Alias as a different track with
//! an active subscription, it MUST close the session with error 'Duplicate
//! Track Alias'." The half addressed to the endpoint choosing the alias is in
//! `an_endpoint_gives_one_alias_to_one_track.rs`, which reaches these two
//! drafts because they can choose one; the half addressed to the endpoint
//! receiving it is in `duplicate_track_alias_closes_the_session.rs`.
//!
//! Three things are gated here and not there, because all three are about the
//! offer's own lifetime rather than about the sentence. An offer of this
//! endpoint's may not take an alias the peer's own offer is using, because the
//! table is the session's and not this endpoint's half of it. The alias comes
//! back when the subscription ends with SUBSCRIBE_DONE, which is the word
//! "simultaneously" on the ending this file owns. And an accepted offer of
//! this endpoint's is in the set an arriving PUBLISH is judged against, which
//! is the second of those two rules reading a record that only an offer of
//! this endpoint's own writes.
//!
//! # What the endpoint does not decide
//!
//! Section 8.13 makes ContentExists a flag for whether the field after it is
//! present at all: "1 if an object has been published on this track, 0 if not.
//! If 0, then the Largest Group ID and Largest Object ID fields will not be
//! present." It is therefore not a parameter of `publish` but derived from the
//! largest location, and the pair cannot be built disagreeing. The gate for it
//! encodes the offer and reads it back, because an offer whose flag disagreed
//! with its field would be refused by the encoder rather than reaching the
//! peer.
//!
//! # Why the session stays up
//!
//! Section 4.1 puts the close for a second answer at the end that receives it:
//! "A subscriber MUST send exactly one PUBLISH_OK or PUBLISH_ERROR in response
//! to a PUBLISH. The peer SHOULD close the session with a protocol error if it
//! receives more than one." The verb is SHOULD and the endpoint is a library,
//! so a second answer is reported to the caller and the session goes on
//! running. Every gate here checks that the session is still up, because a
//! refusal that also tore the session down would be the worse bug — except
//! the one gate whose subject is the other half of the alias sentence, which
//! is a session close and says so.
//!
//! # The two gates about the answer
//!
//! Both are about the *answer* rather than the offer, and all three drafts run
//! them. An identifier nothing was offered under is refused by
//! `receive_publish_ok` and by `receive_publish_error` alike, and so is an
//! answer naming an offer the *peer* made: `inbound_publishes` holds the peer's
//! offer and never this endpoint's, so that is the record telling the two
//! directions apart - consulted by both answers on draft-14, where one map
//! holds publishes in either direction, and kept apart from `publishes`
//! outright on drafts 12 and 13.

//! # Ablations, measured
//!
//! Twelve cuts were made, run against the two crates a change to
//! `moqtap-client` can reach, and reverted. Each gate records the ones
//! that redden it.
//!
//! Four of them are the four the read-back gate covers — the delivery order,
//! the parameters, the largest location, and the Content Exists flag derived
//! from that location — and each is cut on all three drafts at once, because
//! all three build the message with the same call. The rest were cut on
//! drafts 12 and 13 only, which is where the code they cut lives: draft-14
//! reaches those same claims through code of its own, and the reach sentences
//! say which drafts each cut was applied to rather than which drafts the claim
//! covers.
//!
//! Four of them reach past this file, into
//! `an_endpoint_gives_one_alias_to_one_track.rs`, and that is the honest
//! picture: the alias half of what an outbound PUBLISH does belongs there and
//! is measured there. One of the four, the offer never being weighed against
//! the aliases already spoken for, reaches every draft that can build an offer
//! rather than only these two.
//!
//! One gate here is shaped by what the cuts showed. A SUBSCRIBE_DONE is refused
//! with a publish-flow error from a refused offer and from one still waiting for
//! an answer alike, so a gate asking only that question cannot tell the two
//! states apart and stays green under the cut that throws the peer's refusal
//! away. `a_refused_offer_opened_no_subscription` asks for a second refusal and
//! a late acceptance as well, which the two states answer differently, and that
//! cut reddens it.

#![allow(clippy::items_after_test_module)]

use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;

/// The namespace both offered tracks live in.
fn namespace() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec()])
}

fn v(n: u64) -> VarInt {
    VarInt::from_u64(n).unwrap()
}

/// The peer's PUBLISH_OK, in the two shapes it takes across the three drafts.
#[macro_export]
macro_rules! publish_ok_of {
    (varint, $id:expr) => {
        PublishOk {
            request_id: $id,
            forward: Forward::Forward,
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            filter_type: $crate::v(0x2),
            start_group: None,
            start_object: None,
            end_group: None,
            parameters: Vec::new(),
        }
    };
    (filter, $id:expr) => {
        PublishOk {
            request_id: $id,
            forward: Forward::Forward,
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            filter_type: FilterType::LargestObject,
            start_group: None,
            start_object: None,
            end_group: None,
            parameters: Vec::new(),
        }
    };
    (location, $id:expr) => {
        PublishOk {
            request_id: $id,
            forward: Forward::Forward,
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            filter_type: FilterType::LargestObject,
            start_location: None,
            end_group: None,
            parameters: Vec::new(),
        }
    };
}

/// This endpoint, as publisher, ending the subscription it offered.
#[macro_export]
macro_rules! publisher_ends {
    (subscribe_done, $ep:expr, $id:expr) => {
        $ep.send_subscribe_done($id, $crate::v(0), $crate::v(0), Vec::new())
    };
    (publish_done, $ep:expr, $id:expr) => {
        $ep.send_publish_done($id, $crate::v(0), Vec::new())
    };
}

/// The two gates about the answer rather than the offer.
///
/// Every draft here passes `both`. The selector is what would keep a draft
/// that cannot run them a stated exclusion rather than a gate quietly
/// missing from a draft.
#[macro_export]
macro_rules! answer_gates {
    (neither) => {};
    (both) => {
        /// A Request ID nothing in this session was ever opened under.
        const NEVER_USED: u64 = 8;

        /// An answer naming no offer of this endpoint's is refused.
        ///
        /// # What it catches
        ///
        /// Taking the acceptance and dropping it — `receive_publish_ok`
        /// ignoring its argument and returning `Ok(())`, so nothing the
        /// subscription does afterwards has a state to be judged against:
        ///
        /// ```text
        /// an acceptance of an offer that was never made, and instead: Ok(())
        /// ```
        ///
        /// It reddens sixteen, on drafts 12 and 13: eight of the gates here.
        ///
        /// Taking the refusal and dropping it, the other half of the same pair
        /// of stubs:
        ///
        /// ```text
        /// a refusal of an offer that was never made, and instead: Ok(())
        /// ```
        ///
        /// It reddens eight, on drafts 12 and 13: three of the gates here and
        /// one in `an_endpoint_gives_one_alias_to_one_track.rs`:
        /// `an_alias_is_free_once_its_offer_ends`.
        ///
        /// Returning `Ok(())` from the refusal when the identifier names no
        /// offer, while the acceptance beside it answers `UnknownRequest`:
        ///
        /// ```text
        /// a refusal of an offer that was never made, and instead: Ok(())
        /// ```
        ///
        /// It reddens four: this gate on draft-14, and three in
        /// `endpoint_tests.rs`.
        #[test]
        fn an_answer_naming_no_offer_is_refused() {
            let mut ep = offered();
            let stray = ep.receive_publish_ok(&publish_ok(NEVER_USED));
            assert!(
                matches!(stray, Err(EndpointError::UnknownRequest(NEVER_USED))),
                "an acceptance of an offer that was never made, and instead: {stray:?}"
            );
            let refusal = ep.receive_publish_error(&publish_error(NEVER_USED));
            assert!(
                matches!(refusal, Err(EndpointError::UnknownRequest(NEVER_USED))),
                "a refusal of an offer that was never made, and instead: {refusal:?}"
            );
            still_running(&ep);
        }

        /// An answer naming the peer's own offer is not an answer to one of
        /// this endpoint's.
        ///
        /// The two directions are two records, and Section 8.1 keeps their
        /// identifiers apart. An acceptance arriving for a PUBLISH the
        /// *peer* sent is the peer answering itself, which is not a thing
        /// this endpoint has any record of.
        ///
        /// # What it catches
        ///
        /// Taking the acceptance and dropping it — `receive_publish_ok`
        /// ignoring its argument and returning `Ok(())`, so nothing the
        /// subscription does afterwards has a state to be judged against:
        ///
        /// ```text
        /// the peer's own offer was answered as though this endpoint had made
        /// it, and instead: Ok(())
        /// ```
        ///
        /// It reddens sixteen, on drafts 12 and 13: eight of the gates here.
        ///
        /// Falling back to the peer's own offers when the identifier names none
        /// of this endpoint's, which is the helpful-looking version of holding
        /// both directions in one record:
        ///
        /// ```text
        /// the peer's own offer was answered as though this endpoint had made
        /// it, and instead: Ok(())
        /// ```
        ///
        /// It reddens two, this gate on drafts 12 and 13 and nothing else.
        ///
        /// Dropping the test that says whose offer an identifier names, from
        /// the acceptance. Draft-14 keeps both directions in one map, so
        /// without it the peer's own offer is one this endpoint will answer:
        ///
        /// ```text
        /// the peer's own offer was answered as though this endpoint had made
        /// it, and instead: Ok(())
        /// ```
        ///
        /// It reddens one, this gate on draft-14 and nothing else. Drafts 12
        /// and 13 keep the two directions in two records, so there is no such
        /// test on them to cut.
        ///
        /// The same, from the refusal. It needs a cut of its own because it is
        /// a second call site of the same idea, and a gate that drives only the
        /// acceptance leaves this one unmeasured:
        ///
        /// ```text
        /// the peer's own offer was refused as though this endpoint had made
        /// it, and instead: Ok(())
        /// ```
        ///
        /// It reddens one, the same gate on draft-14, and only because that
        /// gate drives both answers: an acceptance-only gate leaves this cut
        /// green, which is why the assertion below is a pair.
        #[test]
        fn an_answer_to_the_peers_own_offer_is_not_an_answer_to_ours() {
            let mut ep = offered();
            ep.receive_publish(&peers_offer()).expect("the peer may offer a track too");
            let crossed = ep.receive_publish_ok(&publish_ok(PEERS_FIRST));
            assert!(
                matches!(crossed, Err(EndpointError::UnknownRequest(PEERS_FIRST))),
                "the peer's own offer was answered as though this endpoint had made it, \
                 and instead: {crossed:?}"
            );
            // Both answers, because both read the record and each needs its
            // own cut to be measured. The offer is still unanswered here, so a
            // refusal that reached it would succeed rather than be stopped by
            // the state machine on its way past.
            let refused = ep.receive_publish_error(&publish_error(PEERS_FIRST));
            assert!(
                matches!(refused, Err(EndpointError::UnknownRequest(PEERS_FIRST))),
                "the peer's own offer was refused as though this endpoint had made it, \
                 and instead: {refused:?}"
            );
            still_running(&ep);
        }
    };
}

/// One draft's gates. The two drafts state every rule this file reads in the
/// same section under the same words, and the PUBLISH they build is the same
/// message with the same fields, so one body serves both.
macro_rules! outbound_publish_gates {
    ($draft:ident, $feat:literal, $version:expr, $ok:tt, $end:tt, $answers:tt) => {
        #[cfg(feature = $feat)]
        mod $draft {
            use moqtap_client::$draft::endpoint::{Endpoint, EndpointError};
            use moqtap_client::$draft::session::request_id::Role;
            use moqtap_client::$draft::session::state::SessionState;
            use moqtap_codec::kvp::{KeyValuePair, KvpValue};
            use moqtap_codec::types::*;
            use moqtap_codec::varint::VarInt;
            use moqtap_codec::$draft::message::*;

            /// The first Request ID this endpoint may spend: even, because it
            /// is the client.
            const OURS_FIRST: u64 = 0;

            /// The second one, which is what "increments by 2" means here.
            const OURS_SECOND: u64 = 2;

            /// The peer's first, which is odd for the same reason.
            const PEERS_FIRST: u64 = 1;

            /// The alias the offers below spend.
            const ALIAS: u64 = 7;

            /// A client with its session established and a budget to spend.
            fn active() -> Endpoint {
                let mut ep = Endpoint::new(Role::Client);
                ep.connect().expect("a client may open");
                let _ = ep.send_client_setup(vec![crate::v($version)], vec![]).expect("SETUP");
                ep.receive_server_setup(&ServerSetup {
                    selected_version: crate::v($version),
                    parameters: vec![KeyValuePair {
                        key: crate::v(0x02),
                        value: KvpValue::Varint(crate::v(100)),
                    }],
                })
                .expect("SERVER_SETUP");
                let _ = ep.send_max_request_id(crate::v(100)).expect("MAX_REQUEST_ID");
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "the gates need a running session"
                );
                ep
            }

            /// Offer `name` under `alias`, with no largest location.
            fn offer(
                ep: &mut Endpoint,
                name: &[u8],
                alias: u64,
            ) -> Result<(VarInt, ControlMessage), EndpointError> {
                ep.publish(
                    crate::namespace(),
                    name.to_vec(),
                    crate::v(alias),
                    GroupOrder::Ascending,
                    None,
                    Forward::Forward,
                    Vec::new(),
                )
            }

            /// An endpoint with one unanswered offer of its own on record.
            fn offered() -> Endpoint {
                let mut ep = active();
                let (id, _) = offer(&mut ep, b"alpha", ALIAS).expect("this endpoint may offer");
                assert_eq!(id, crate::v(OURS_FIRST), "the offer spends this endpoint's first id");
                ep
            }

            /// An endpoint whose offer the peer accepted.
            fn accepted() -> Endpoint {
                let mut ep = offered();
                ep.receive_publish_ok(&publish_ok(OURS_FIRST)).expect("the peer accepts");
                ep
            }

            /// The peer's acceptance of the offer opened under `id`. Drafts
            /// 12 and 13 carry the start of the range as two fields and
            /// draft-14 carries it as one Location.
            fn publish_ok(id: u64) -> PublishOk {
                crate::publish_ok_of!($ok, crate::v(id))
            }

            /// The peer's refusal of the offer opened under `id`.
            fn publish_error(id: u64) -> PublishError {
                PublishError {
                    request_id: crate::v(id),
                    error_code: crate::v(1),
                    reason_phrase: b"no".to_vec(),
                }
            }

            /// A PUBLISH the peer sends, which holds `ALIAS` for `beta`.
            fn peers_offer() -> Publish {
                Publish {
                    request_id: crate::v(PEERS_FIRST),
                    track_namespace: crate::namespace(),
                    track_name: b"beta".to_vec(),
                    track_alias: crate::v(ALIAS),
                    group_order: GroupOrder::Ascending,
                    content_exists: ContentExists::NoLargestLocation,
                    largest_location: None,
                    forward: Forward::Forward,
                    parameters: Vec::new(),
                }
            }

            /// End the subscription opened under `id`, as its publisher.
            /// Drafts 12 and 13 call the message SUBSCRIBE_DONE and draft-14
            /// calls it PUBLISH_DONE.
            fn end(ep: &mut Endpoint, id: u64) -> Result<ControlMessage, EndpointError> {
                crate::publisher_ends!($end, ep, crate::v(id))
            }

            /// The session is still running: none of these rules is one this
            /// endpoint answers by closing.
            fn still_running(ep: &Endpoint) {
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "Section 4.1 puts the close at the peer that receives a second answer, \
                     not at the endpoint that declines to send one"
                );
            }

            /// This endpoint can build a PUBLISH, and it is the offer it was
            /// asked for.
            ///
            /// # What it catches
            ///
            /// Building the offer with a Track Alias of zero rather than the one
            /// the caller chose:
            ///
            /// ```text
            /// assertion `left == right` failed: the alias the offer spends left:
            /// VarInt(0) right: VarInt(7)
            /// ```
            ///
            /// It reddens two, this gate on drafts 12 and 13 and nothing else.
            #[test]
            fn this_endpoint_can_offer_a_track() {
                let mut ep = active();
                let (id, msg) = offer(&mut ep, b"alpha", ALIAS).expect("this endpoint may offer");
                assert_eq!(id, crate::v(OURS_FIRST), "the offer spends this endpoint's first id");
                let ControlMessage::Publish(offer) = msg else {
                    panic!("PUBLISH is what initiates a subscription from the publisher");
                };
                assert_eq!(
                    offer.request_id,
                    crate::v(OURS_FIRST),
                    "the id in the message is the \
                    one the caller was handed"
                );
                assert_eq!(offer.track_namespace, crate::namespace(), "the namespace offered");
                assert_eq!(offer.track_name, b"alpha".to_vec(), "the track offered");
                assert_eq!(offer.track_alias, crate::v(ALIAS), "the alias the offer spends");
                assert_eq!(
                    offer.forward,
                    Forward::Forward,
                    "the initial Forward State is the \
                    initiator's to set"
                );
                still_running(&ep);
            }

            /// A second offer takes the next identifier in this endpoint's own
            /// sequence.
            ///
            /// # What it catches
            ///
            /// Returning a fixed Request ID rather than allocating one, which
            /// leaves every offer of this endpoint's under the same identifier and
            /// the peer unable to tell two subscriptions apart:
            ///
            /// ```text
            /// assertion `left == right` failed: Section 8.1 steps this endpoint's
            /// ids by two, so the second offer is 2 left: VarInt(0) right:
            /// VarInt(2)
            /// ```
            ///
            /// It reddens four, on drafts 12 and 13: this gate and one in
            /// `an_endpoint_gives_one_alias_to_one_track.rs`:
            /// `a_refused_publish_spends_no_request_id`.
            #[test]
            fn a_second_offer_takes_the_next_identifier() {
                let mut ep = active();
                let (first, _) = offer(&mut ep, b"alpha", ALIAS).expect("the first offer");
                let (second, _) = offer(&mut ep, b"beta", ALIAS + 1).expect("the second offer");
                assert_eq!(first, crate::v(OURS_FIRST), "the first offer spends the first id");
                assert_eq!(
                    second,
                    crate::v(OURS_SECOND),
                    "Section 8.1 steps this endpoint's ids by two, so the second offer is 2"
                );
                still_running(&ep);
            }

            /// An acceptance establishes the subscription, and the publisher
            /// can then end it.
            ///
            /// # What it catches
            ///
            /// Taking the acceptance and dropping it — `receive_publish_ok`
            /// ignoring its argument and returning `Ok(())`, so nothing the
            /// subscription does afterwards has a state to be judged against:
            ///
            /// ```text
            /// Section 4.1 lets the publisher end it with SUBSCRIBE_DONE:
            /// PublishFlow(InvalidTransition { from: Publishing, event:
            /// "on_subscribe_done_sent" })
            /// ```
            ///
            /// It reddens sixteen, on drafts 12 and 13: eight of the gates here.
            ///
            /// Building the SUBSCRIBE_DONE without moving the record it ends, so
            /// the message goes out and the subscription stays live behind it:
            ///
            /// ```text
            /// Section 4.1 lets the publisher end it with SUBSCRIBE_DONE:
            /// UnknownRequest(0)
            /// ```
            ///
            /// It reddens eight, on drafts 12 and 13: four of the gates here.
            #[test]
            fn an_accepted_offer_is_a_subscription_this_endpoint_publishes() {
                let mut ep = offered();
                ep.receive_publish_ok(&publish_ok(OURS_FIRST)).expect("the peer accepts the offer");
                end(&mut ep, OURS_FIRST)
                    .expect("Section 4.1 lets the publisher end it with SUBSCRIBE_DONE");
                still_running(&ep);
            }

            /// A refusal ends the offer, and there is nothing left to end.
            ///
            /// # What it catches
            ///
            /// Taking the acceptance and dropping it — `receive_publish_ok`
            /// ignoring its argument and returning `Ok(())`, so nothing the
            /// subscription does afterwards has a state to be judged against:
            ///
            /// ```text
            /// a refused offer cannot then be accepted, and instead: Ok(())
            /// ```
            ///
            /// It reddens sixteen, on drafts 12 and 13: eight of the gates here.
            ///
            /// Taking the refusal and dropping it, the other half of the same pair
            /// of stubs:
            ///
            /// ```text
            /// a refused offer has had its one answer, and instead: Ok(())
            /// ```
            ///
            /// It reddens eight, on drafts 12 and 13: three of the gates here and
            /// one in `an_endpoint_gives_one_alias_to_one_track.rs`:
            /// `an_alias_is_free_once_its_offer_ends`.
            ///
            /// Building the SUBSCRIBE_DONE without moving the record it ends, so
            /// the message goes out and the subscription stays live behind it:
            ///
            /// ```text
            /// a refused offer opened no subscription for SUBSCRIBE_DONE to end,
            /// and instead: Err(UnknownRequest(0))
            /// ```
            ///
            /// It reddens eight, on drafts 12 and 13: four of the gates here.
            #[test]
            fn a_refused_offer_opened_no_subscription() {
                let mut ep = offered();
                ep.receive_publish_error(&publish_error(OURS_FIRST)).expect("the peer refuses");
                // The two assertions below are what tell a refused offer from
                // one still waiting for an answer. The SUBSCRIBE_DONE beneath
                // them is not: it is refused from either state and names the
                // same error doing it, so a gate that asks only that question
                // passes with the refusal thrown away.
                let again = ep.receive_publish_error(&publish_error(OURS_FIRST));
                assert!(
                    matches!(again, Err(EndpointError::PublishFlow(_))),
                    "a refused offer has had its one answer, and instead: {again:?}"
                );
                let late = ep.receive_publish_ok(&publish_ok(OURS_FIRST));
                assert!(
                    matches!(late, Err(EndpointError::PublishFlow(_))),
                    "a refused offer cannot then be accepted, and instead: {late:?}"
                );
                let refused = end(&mut ep, OURS_FIRST);
                assert!(
                    matches!(refused, Err(EndpointError::PublishFlow(_))),
                    "a refused offer opened no subscription for SUBSCRIBE_DONE to end, \
                     and instead: {refused:?}"
                );
                still_running(&ep);
            }

            /// An offer is answered once, whichever answer comes first.
            ///
            /// # What it catches
            ///
            /// Taking the acceptance and dropping it — `receive_publish_ok`
            /// ignoring its argument and returning `Ok(())`, so nothing the
            /// subscription does afterwards has a state to be judged against:
            ///
            /// ```text
            /// Section 4.1 says exactly one answer, and instead: Ok(())
            /// ```
            ///
            /// It reddens sixteen, on drafts 12 and 13: eight of the gates here.
            ///
            /// Taking the refusal and dropping it, the other half of the same pair
            /// of stubs:
            ///
            /// ```text
            /// the second answer is refused whichever of the two it is, and
            /// instead: Ok(())
            /// ```
            ///
            /// It reddens eight, on drafts 12 and 13: three of the gates here and
            /// one in `an_endpoint_gives_one_alias_to_one_track.rs`:
            /// `an_alias_is_free_once_its_offer_ends`.
            #[test]
            fn an_offer_is_answered_exactly_once() {
                let mut ep = offered();
                ep.receive_publish_ok(&publish_ok(OURS_FIRST)).expect("the first answer");
                let again = ep.receive_publish_ok(&publish_ok(OURS_FIRST));
                assert!(
                    matches!(again, Err(EndpointError::PublishFlow(_))),
                    "Section 4.1 says exactly one answer, and instead: {again:?}"
                );
                let other = ep.receive_publish_error(&publish_error(OURS_FIRST));
                assert!(
                    matches!(other, Err(EndpointError::PublishFlow(_))),
                    "the second answer is refused whichever of the two it is, and \
                     instead: {other:?}"
                );
                still_running(&ep);
            }

            /// An offer may not take an alias the peer's own offer is using.
            ///
            /// The table is the session's and not this endpoint's half of it:
            /// the peer would close the session over an alias it is already
            /// using itself.
            ///
            /// # What it catches
            ///
            /// Not weighing an offer against the aliases already spoken for, on all
            /// eight drafts that can build one:
            ///
            /// ```text
            /// the alias table is the session's, and instead: Ok((VarInt(0),
            /// Publish(Publish { request_id: VarInt(0), track_namespace:
            /// TrackNamespace([[99, 111, 110, 102, 111, 114, 109, 97, 110, 99,
            /// 101]]), track_name: [97, 108, 112, 104, 97], t
            /// ```
            ///
            /// It reddens twenty, on drafts 12 through 19: two of the gates here
            /// and two in `an_endpoint_gives_one_alias_to_one_track.rs`:
            /// `a_refused_publish_spends_no_request_id`,
            /// `one_alias_for_two_tracks_is_refused`.
            #[test]
            fn an_offer_may_not_take_an_alias_the_peer_is_using() {
                let mut ep = active();
                ep.receive_publish(&peers_offer()).expect("the peer's PUBLISH");
                let ours = offer(&mut ep, b"alpha", ALIAS);
                assert!(
                    matches!(
                        ours,
                        Err(EndpointError::TrackAliasInUse { alias: ALIAS, held: PEERS_FIRST })
                    ),
                    "the alias table is the session's, and instead: {ours:?}"
                );
                still_running(&ep);
            }

            /// A subscription this endpoint ended gives its alias back.
            ///
            /// # What it catches
            ///
            /// Taking the acceptance and dropping it — `receive_publish_ok`
            /// ignoring its argument and returning `Ok(())`, so nothing the
            /// subscription does afterwards has a state to be judged against:
            ///
            /// ```text
            /// the publisher ends it: PublishFlow(InvalidTransition { from:
            /// Publishing, event: "on_subscribe_done_sent" })
            /// ```
            ///
            /// It reddens sixteen, on drafts 12 and 13: eight of the gates here.
            ///
            /// Building the SUBSCRIBE_DONE without moving the record it ends, so
            /// the message goes out and the subscription stays live behind it:
            ///
            /// ```text
            /// the publisher ends it: UnknownRequest(0)
            /// ```
            ///
            /// It reddens eight, on drafts 12 and 13: four of the gates here.
            ///
            /// Leaving an offer of this endpoint's out of the set the next offer
            /// this endpoint builds is weighed against:
            ///
            /// ```text
            /// a live subscription is holding the alias, and instead:
            /// Ok((VarInt(2), Publish(Publish { request_id: VarInt(2),
            /// track_namespace: TrackNamespace([[99, 111, 110, 102, 111, 114, 109,
            /// 97, 110, 99, 101]]), track_name: [98, 101, 116, 97], track_al
            /// ```
            ///
            /// It reddens six, on drafts 12 and 13: this gate and two in
            /// `an_endpoint_gives_one_alias_to_one_track.rs`:
            /// `a_refused_publish_spends_no_request_id`,
            /// `one_alias_for_two_tracks_is_refused`.
            ///
            /// Not weighing an offer against the aliases already spoken for, on all
            /// eight drafts that can build one:
            ///
            /// ```text
            /// a live subscription is holding the alias, and instead:
            /// Ok((VarInt(2), Publish(Publish { request_id: VarInt(2),
            /// track_namespace: TrackNamespace([[99, 111, 110, 102, 111, 114, 109,
            /// 97, 110, 99, 101]]), track_name: [98, 101, 116, 97], track_al
            /// ```
            ///
            /// It reddens twenty, on drafts 12 through 19: two of the gates here
            /// and two in `an_endpoint_gives_one_alias_to_one_track.rs`:
            /// `a_refused_publish_spends_no_request_id`,
            /// `one_alias_for_two_tracks_is_refused`.
            ///
            /// Recording the offer's state and not the track its alias was bound
            /// to, so the alias is spent on the wire and free in the table:
            ///
            /// ```text
            /// a live subscription is holding the alias, and instead:
            /// Ok((VarInt(2), Publish(Publish { request_id: VarInt(2),
            /// track_namespace: TrackNamespace([[99, 111, 110, 102, 111, 114, 109,
            /// 97, 110, 99, 101]]), track_name: [98, 101, 116, 97], track_al
            /// ```
            ///
            /// It reddens eight, on drafts 12 and 13: two of the gates here and two
            /// in `an_endpoint_gives_one_alias_to_one_track.rs`:
            /// `a_refused_publish_spends_no_request_id`,
            /// `one_alias_for_two_tracks_is_refused`.
            #[test]
            fn an_ended_subscription_frees_its_alias() {
                let mut ep = accepted();
                let held = offer(&mut ep, b"beta", ALIAS);
                assert!(
                    matches!(held, Err(EndpointError::TrackAliasInUse { .. })),
                    "a live subscription is holding the alias, and instead: {held:?}"
                );
                end(&mut ep, OURS_FIRST).expect("the publisher ends it");
                let freed = offer(&mut ep, b"beta", ALIAS);
                assert!(
                    freed.is_ok(),
                    "an ended subscription holds nothing, and instead: {freed:?}"
                );
                still_running(&ep);
            }

            /// A subscription is ended once.
            ///
            /// # What it catches
            ///
            /// Taking the acceptance and dropping it — `receive_publish_ok`
            /// ignoring its argument and returning `Ok(())`, so nothing the
            /// subscription does afterwards has a state to be judged against:
            ///
            /// ```text
            /// the publisher ends it: PublishFlow(InvalidTransition { from:
            /// Publishing, event: "on_subscribe_done_sent" })
            /// ```
            ///
            /// It reddens sixteen, on drafts 12 and 13: eight of the gates here.
            ///
            /// Building the SUBSCRIBE_DONE without moving the record it ends, so
            /// the message goes out and the subscription stays live behind it:
            ///
            /// ```text
            /// the publisher ends it: UnknownRequest(0)
            /// ```
            ///
            /// It reddens eight, on drafts 12 and 13: four of the gates here.
            #[test]
            fn a_subscription_this_endpoint_publishes_is_ended_once() {
                let mut ep = accepted();
                end(&mut ep, OURS_FIRST).expect("the publisher ends it");
                let again = end(&mut ep, OURS_FIRST);
                assert!(
                    matches!(again, Err(EndpointError::PublishFlow(_))),
                    "there is nothing left to end, and instead: {again:?}"
                );
                still_running(&ep);
            }

            /// An accepted offer of this endpoint's is in the set an arriving
            /// PUBLISH is judged against.
            ///
            /// The second half of Section 8.13's sentence - "If a subscriber
            /// receives a PUBLISH that uses the same Track Alias as a
            /// different track with an active subscription, it MUST close the
            /// session with error 'Duplicate Track Alias'" - and the record it
            /// reads is the one this file's subject created. Before it, an
            /// arriving PUBLISH was weighed against the peer's own offers and
            /// this endpoint's subscriptions, and against nothing this
            /// endpoint had published.
            ///
            /// # What it catches
            ///
            /// Taking the acceptance and dropping it — `receive_publish_ok`
            /// ignoring its argument and returning `Ok(())`, so nothing the
            /// subscription does afterwards has a state to be judged against:
            ///
            /// ```text
            /// a PUBLISH took the alias a subscription this endpoint publishes
            /// holds, and instead: Ok(())
            /// ```
            ///
            /// It reddens sixteen, on drafts 12 and 13: eight of the gates here.
            ///
            /// Leaving an offer of this endpoint's out of the set an arriving
            /// message is weighed against:
            ///
            /// ```text
            /// a PUBLISH took the alias a subscription this endpoint publishes
            /// holds, and instead: Ok(())
            /// ```
            ///
            /// It reddens two, this gate on drafts 12 and 13 and nothing else.
            ///
            /// Recording the offer's state and not the track its alias was bound
            /// to, so the alias is spent on the wire and free in the table:
            ///
            /// ```text
            /// a PUBLISH took the alias a subscription this endpoint publishes
            /// holds, and instead: Ok(())
            /// ```
            ///
            /// It reddens eight, on drafts 12 and 13: two of the gates here and two
            /// in `an_endpoint_gives_one_alias_to_one_track.rs`:
            /// `a_refused_publish_spends_no_request_id`,
            /// `one_alias_for_two_tracks_is_refused`.
            #[test]
            fn an_accepted_offer_is_judged_against_an_arriving_publish() {
                let mut ep = accepted();
                let clash = ep.receive_publish(&peers_offer());
                assert!(
                    matches!(clash, Err(EndpointError::DuplicateTrackAlias { alias: ALIAS, .. })),
                    "a PUBLISH took the alias a subscription this endpoint publishes holds, \
                     and instead: {clash:?}"
                );
                assert_eq!(
                    ep.session_state(),
                    SessionState::Closed,
                    "this half of the sentence is a session close, and the only one in this file"
                );
            }

            crate::answer_gates!($answers);

            /// An offer needs a running session.
            ///
            /// # What it catches
            ///
            /// Building the offer without first asking whether there is a session
            /// to send it on:
            ///
            /// ```text
            /// there is no session to offer on, and instead:
            /// Err(RequestId(Blocked))
            /// ```
            ///
            /// It reddens two, this gate on drafts 12 and 13 and nothing else.
            #[test]
            fn an_offer_needs_a_running_session() {
                let mut ep = Endpoint::new(Role::Client);
                let early = offer(&mut ep, b"alpha", ALIAS);
                assert!(
                    matches!(early, Err(EndpointError::NotActive)),
                    "there is no session to offer on, and instead: {early:?}"
                );
                assert_eq!(
                    ep.session_state(),
                    SessionState::Connecting,
                    "a refusal to build a message is not a session event"
                );
            }

            /// Every field the caller chooses reaches the peer, and the
            /// largest location decides the flag in front of it.
            ///
            /// Section 8.13 makes those two one field and one optional field
            /// behind it, and the codec refuses a message whose flag and field
            /// disagree, so an offer that reaches the peer at all is one whose
            /// flag was derived correctly.
            ///
            /// The other two the caller chooses are read back for the same
            /// reason and in the same place. Each is set here to something the
            /// crate would not have chosen on its own — Descending where the
            /// default was Ascending, one parameter where the default was
            /// none — so a field filled in rather than passed through is
            /// visible rather than accidentally right.
            ///
            /// # What it catches
            ///
            /// Writing the Content Exists flag from a constant rather than from the
            /// field it governs:
            ///
            /// ```text
            /// an offer the encoder accepts is a coherent one: InvalidField
            /// ```
            ///
            /// It reddens three, this gate on drafts 12, 13 and 14 and nothing else.
            ///
            /// Filling in the delivery order instead of passing the caller's
            /// through:
            ///
            /// ```text
            /// assertion `left == right` failed: the delivery order is the caller's
            /// to choose left: Ascending right: Descending
            /// ```
            ///
            /// It reddens three, this gate on drafts 12, 13 and 14 and nothing else.
            ///
            /// Dropping the parameters the caller passed:
            ///
            /// ```text
            /// assertion `left == right` failed: the parameters the caller passed
            /// must reach the peer left: 0 right: 1
            /// ```
            ///
            /// It reddens three, this gate on drafts 12, 13 and 14 and nothing else.
            ///
            /// Dropping the largest location the caller passed. The flag was
            /// derived before the field went missing, so the two disagree and the
            /// encoder is what says so — which is why this gate reads the offer
            /// back off the wire rather than out of the struct:
            ///
            /// ```text
            /// an offer the encoder accepts is a coherent one: InvalidField
            /// ```
            ///
            /// It reddens three, this gate on drafts 12, 13 and 14 and nothing else.
            #[test]
            fn every_field_the_caller_chooses_reaches_the_peer() {
                let mut ep = active();
                let (_, empty) = offer(&mut ep, b"alpha", ALIAS).expect("an offer with no content");
                let (_, full) = ep
                    .publish(
                        crate::namespace(),
                        b"beta".to_vec(),
                        crate::v(ALIAS + 1),
                        GroupOrder::Descending,
                        Some(Location { group: crate::v(4), object: crate::v(9) }),
                        Forward::Forward,
                        vec![KeyValuePair {
                            key: crate::v(0x02),
                            value: KvpValue::Varint(crate::v(7)),
                        }],
                    )
                    .expect("an offer with content");

                for (msg, expected) in [(empty, None), (full, Some((4, 9)))] {
                    let mut buf = Vec::new();
                    msg.encode(&mut buf).expect("an offer the encoder accepts is a coherent one");
                    let mut cursor = &buf[..];
                    let ControlMessage::Publish(back) =
                        ControlMessage::decode(&mut cursor).expect("the offer decodes")
                    else {
                        panic!("what was encoded was a PUBLISH");
                    };
                    let seen = back
                        .largest_location
                        .map(|l| (l.group.into_inner(), l.object.into_inner()));
                    assert_eq!(seen, expected, "the largest location must survive the wire");
                    assert_eq!(
                        back.content_exists == ContentExists::HasLargestLocation,
                        expected.is_some(),
                        "the flag says whether the field is there, so it follows the field"
                    );
                    if expected.is_some() {
                        assert_eq!(
                            back.group_order,
                            GroupOrder::Descending,
                            "the delivery order is the caller's to choose"
                        );
                        assert_eq!(
                            back.parameters.len(),
                            1,
                            "the parameters the caller passed must reach the peer"
                        );
                    }
                }
                still_running(&ep);
            }
        }
    };
}

outbound_publish_gates!(draft12, "draft12", 0xff00_000c, varint, subscribe_done, both);
outbound_publish_gates!(draft13, "draft13", 0xff00_000d, filter, subscribe_done, both);
outbound_publish_gates!(draft14, "draft14", 0xff00_000e, location, publish_done, both);

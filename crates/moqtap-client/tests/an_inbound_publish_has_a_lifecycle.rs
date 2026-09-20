#![cfg(any(
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
))]

//! A PUBLISH the peer sends opens a subscription, and this endpoint carries it
//! from arrival to acceptance to the end of the flow.
//!
//! Draft-14 Section 5.1, with 15 and 16 in the same place, and
//! draft-12 Section 4.1 with 13 saying it in the same words: "A publisher
//! initiates a subscription to a track by sending the PUBLISH message. The
//! subscriber either accepts or rejects the subscription using PUBLISH_OK or
//! PUBLISH_ERROR." Drafts 15 and 16 write REQUEST_ERROR
//! where 12, 13 and 14 write PUBLISH_ERROR, which is the only difference the
//! rule has across the five.
//!
//! Two more sentences make it a lifecycle rather than a question and an
//! answer. "A subscriber MUST send exactly one PUBLISH_OK or PUBLISH_ERROR in
//! response to a PUBLISH. The peer SHOULD close the session with a protocol
//! error if it receives more than one." And, on 12, 13 and 14: "Once either of
//! these sequences is successful, the subscription can be updated by the
//! subscriber using SUBSCRIBE_UPDATE, terminated by the subscriber using
//! UNSUBSCRIBE, or terminated by the publisher using SUBSCRIBE_DONE" - drafts
//! 12 and 13 end it with SUBSCRIBE_DONE, 14 with PUBLISH_DONE, and 15 and 16
//! say the same thing as "The subscriber terminates a subscription ... using
//! UNSUBSCRIBE, the publisher terminates a subscription ... using
//! PUBLISH_DONE."
//!
//! # Why the range is these five, and what the read-back gates are for
//!
//! PUBLISH arrives at draft-12; draft-11 has no such message. Drafts 17
//! through 20 carry the whole flow already, on the request stream of their own
//! that they give it, so the range runs 12 through 16.
//!
//! A state machine says how far a request has got and a track binding says
//! which track it is about; neither says what was offered, and the offer is
//! what an answer is decided from. The peer states the offer once, in the
//! PUBLISH: on drafts 12, 13 and 14 that is a delivery order, a largest
//! location and a forwarding preference carried as fields of the message, and
//! on 15 and 16 it is the parameters, with the track extensions beside them on
//! 16. An application taking one of those offers with only the state to read
//! has nothing to read. The read-back gates below are on all five drafts:
//! on 12 and 13 the offer sits inside the same record the state machine lives
//! in, and on 14, 15 and 16 it is a record of its own.
//!
//! # Why none of this closes the session
//!
//! The "exactly one" sentence puts the close at the *other* end: "The peer
//! SHOULD close the session ... if it receives more than one." This endpoint's
//! job is not to send the second one, so a second answer is refused where it
//! is asked for and the session goes on running. Every gate below checks that,
//! because a refusal that also tore down the session would be a worse bug than
//! the one it was fixing.
//!
//! # Ablations, measured
//!
//! Six cuts were made and run, five of them recorded on the gate they belong
//! to. The sixth is recorded here because it is the one that spans files:
//! letting the acceptance build its PUBLISH_OK without moving the record on
//! reddens thirty-five tests. Four of the eleven gates here, on all five
//! drafts, and in the alias files the accepted offer's alias stops being held,
//! in process and over QUIC:
//!
//! ```text
//! a second PUBLISH_OK was sent for one PUBLISH: ()
//! ```
//!
//! Three of the gates it leaves green are worth naming, because they are what
//! the cut does not reach: the offer still arrives and is still looked up by
//! the id it names, and an offer stuck at "arrived" still cannot be
//! unsubscribed.

#![allow(clippy::items_after_test_module)]

use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;

/// The namespace the offered track lives in.
fn namespace() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec()])
}

fn v(n: u64) -> VarInt {
    VarInt::from_u64(n).unwrap()
}

/// SETUP, in the two shapes it takes across the five drafts.
#[macro_export]
macro_rules! setup_for {
    (versioned, $ep:expr, $version:expr) => {{
        let _ = $ep.send_client_setup(vec![$crate::v($version)], vec![]).expect("CLIENT_SETUP");
        $ep.receive_server_setup(&ServerSetup {
            selected_version: $crate::v($version),
            parameters: vec![KeyValuePair {
                key: $crate::v(0x02),
                value: KvpValue::Varint($crate::v(100)),
            }],
        })
        .expect("SERVER_SETUP");
        // A peer may not open a request until this endpoint has granted it a
        // budget, and that budget starts at zero.
        let _ = $ep.send_max_request_id($crate::v(100)).expect("MAX_REQUEST_ID");
    }};
    (alpn, $ep:expr, $version:expr) => {{
        let _ = $ep.send_client_setup(vec![]).expect("CLIENT_SETUP");
        $ep.receive_server_setup(&ServerSetup {
            parameters: vec![KeyValuePair {
                key: $crate::v(0x02),
                value: KvpValue::Varint($crate::v(100)),
            }],
        })
        .expect("SERVER_SETUP");
        let _ = $ep.send_max_request_id($crate::v(100)).expect("MAX_REQUEST_ID");
    }};
}

/// A PUBLISH from the peer, offering `TRACK` under `ALIAS`.
#[macro_export]
macro_rules! publish_of {
    (rich, $id:expr) => {
        Publish {
            request_id: $crate::v($id),
            track_namespace: $crate::namespace(),
            track_name: b"alpha".to_vec(),
            track_alias: $crate::v(7),
            group_order: GroupOrder::Ascending,
            content_exists: ContentExists::NoLargestLocation,
            largest_location: None,
            forward: Forward::Forward,
            parameters: Vec::new(),
        }
    };
    (plain, $id:expr) => {
        Publish {
            request_id: $crate::v($id),
            track_namespace: $crate::namespace(),
            track_name: b"alpha".to_vec(),
            track_alias: $crate::v(7),
            parameters: Vec::new(),
        }
    };
    (ext, $id:expr) => {
        Publish {
            request_id: $crate::v($id),
            track_namespace: $crate::namespace(),
            track_name: b"alpha".to_vec(),
            track_alias: $crate::v(7),
            parameters: Vec::new(),
            track_extensions: Vec::new(),
        }
    };
}

/// Accept the peer's offer, in the shapes the answer takes across the five.
#[macro_export]
macro_rules! accept_publish {
    (varint, $ep:expr, $id:expr) => {
        $ep.send_publish_ok(
            $id,
            Forward::Forward,
            128,
            GroupOrder::Ascending,
            $crate::v(0x2),
            None,
            None,
            None,
        )
        .map(|_| ())
    };
    (filter, $ep:expr, $id:expr) => {
        $ep.send_publish_ok(
            $id,
            Forward::Forward,
            128,
            GroupOrder::Ascending,
            FilterType::LargestObject,
            None,
            None,
            None,
        )
        .map(|_| ())
    };
    (location, $ep:expr, $id:expr) => {
        $ep.send_publish_ok(
            $id,
            Forward::Forward,
            128,
            GroupOrder::Ascending,
            FilterType::LargestObject,
            None,
            None,
        )
        .map(|_| ())
    };
    (params, $ep:expr, $id:expr) => {
        $ep.send_publish_ok($id, Vec::new()).map(|_| ())
    };
}

/// Reject the peer's offer. Drafts 15 and 16 answer with REQUEST_ERROR, and
/// draft-16's carries a retry interval the other four have no field for.
#[macro_export]
macro_rules! reject_publish {
    (plain, $ep:expr, $id:expr) => {
        $ep.send_publish_error($id, $crate::v(1), b"no".to_vec()).map(|_| ())
    };
    (retry, $ep:expr, $id:expr) => {
        $ep.send_publish_error($id, $crate::v(1), $crate::v(0), b"no".to_vec()).map(|_| ())
    };
}

/// The publisher ending the subscription it opened.
#[macro_export]
macro_rules! publisher_ends {
    (subscribe_done, $ep:expr, $id:expr) => {
        $ep.receive_subscribe_done(&SubscribeDone {
            request_id: $id,
            status_code: $crate::v(0),
            stream_count: $crate::v(0),
            reason_phrase: Vec::new(),
        })
    };
    (publish_done, $ep:expr, $id:expr) => {
        $ep.receive_publish_done(&PublishDone {
            request_id: $id,
            status_code: $crate::v(0),
            stream_count: $crate::v(0),
            reason_phrase: Vec::new(),
        })
    };
}

/// This endpoint's own PUBLISH, in the three shapes the outbound call takes.
///
/// Drafts 12, 13 and 14 carry the fields drafts 15 and 16 moved out of the
/// message: a delivery order, a largest location and a forwarding preference.
/// All three take them from the caller, so one arm serves them.
#[macro_export]
macro_rules! own_publish {
    (rich, $ep:expr) => {
        $ep.publish(
            $crate::namespace(),
            b"beta".to_vec(),
            $crate::v(9),
            GroupOrder::Ascending,
            None,
            Forward::Forward,
            Vec::new(),
        )
    };
    (params, $ep:expr) => {
        $ep.publish($crate::namespace(), b"beta".to_vec(), $crate::v(9), Vec::new())
    };
    (ext, $ep:expr) => {
        $ep.publish($crate::namespace(), b"beta".to_vec(), $crate::v(9), Vec::new(), Vec::new())
    };
}

/// The gate saying an offer of this endpoint's own is not one the peer made.
///
/// One map of state machines holds both directions on drafts 14, 15 and 16, so
/// the record that answers which offer the peer made has to be the one that
/// knows which direction the offer went. Drafts 12 and 13 hold the two
/// directions in two records and the separation is structural there, which is
/// why the cut recorded below does not reach them; the gate is still theirs to
/// pass, because a record that answered by identifier alone would be the
/// obvious way to write it.
#[macro_export]
macro_rules! own_offer_gate {
    (none, $ignored:tt) => {};
    (own, $call:tt) => {
        /// An offer this endpoint made itself is not one the peer made.
        ///
        /// # What it catches
        ///
        /// Recording this endpoint's own PUBLISH in the same place the peer's
        /// goes, which is what a map keyed by Request ID alone invites:
        ///
        /// ```text
        /// an offer this endpoint made was read back as the peer's, and named Some(VarInt(0))
        /// ```
        ///
        /// It reddens three tests, this gate on each of the three drafts. The
        /// state of both directions is in one map here and that is not the
        /// defect; what tells them apart is that only an arrival writes the
        /// message down.
        #[test]
        fn an_offer_of_this_endpoints_own_is_not_the_peers() {
            let mut ep = offered();
            let (own, _) = $crate::own_publish!($call, ep)
                .expect("this endpoint may offer a track of its own");
            let read = ep.pending_publish(own);
            assert!(
                read.is_none(),
                "an offer this endpoint made was read back as the peer's, and named {:?}",
                read.map(|p| p.request_id)
            );
            assert_eq!(
                ep.pending_publish_count(),
                1,
                "only the peer's offer is waiting for an answer from this endpoint"
            );
            still_running(&ep);
        }
    };
}

/// One draft's eleven gates: the ten defined here, plus the own-offer gate
/// this body invokes.
macro_rules! inbound_publish_gates {
    ($draft:ident, $feat:literal, $version:expr, $setup:tt, $pubmsg:tt, $accept:tt,
     $reject:tt, $ends:tt, $own:tt, $ownmsg:tt, $sec:literal) => {
        #[cfg(feature = $feat)]
        mod $draft {
            #[allow(unused_imports)]
            use moqtap_client::$draft::endpoint::{Endpoint, EndpointError};
            use moqtap_client::$draft::session::request_id::Role;
            use moqtap_client::$draft::session::state::SessionState;
            #[allow(unused_imports)]
            use moqtap_codec::kvp::{KeyValuePair, KvpValue};
            #[allow(unused_imports)]
            use moqtap_codec::types::*;
            use moqtap_codec::varint::VarInt;
            #[allow(unused_imports)]
            use moqtap_codec::$draft::message::*;

            /// The peer's first Request ID: odd, because this endpoint is the
            /// client and the peer is the server.
            const PEERS_FIRST: u64 = 1;

            /// A Request ID no PUBLISH ever arrived under.
            const NEVER_USED: u64 = 3;

            fn peer_id() -> VarInt {
                VarInt::from_u64(PEERS_FIRST).expect("a small id is a varint")
            }

            /// A client with its session established.
            fn active() -> Endpoint {
                let mut ep = Endpoint::new(Role::Client);
                ep.connect().expect("a client may open");
                crate::setup_for!($setup, ep, $version);
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "the gates need a running session"
                );
                ep
            }

            /// An endpoint holding the peer's unanswered offer.
            fn offered() -> Endpoint {
                let mut ep = active();
                ep.receive_publish(&crate::publish_of!($pubmsg, PEERS_FIRST))
                    .expect("the peer's PUBLISH");
                ep
            }

            /// An endpoint holding the peer's accepted offer.
            fn accepted() -> Endpoint {
                let mut ep = offered();
                crate::accept_publish!($accept, ep, peer_id()).expect("accept the offer");
                ep
            }

            /// The session is still running: none of these rules is one this
            /// endpoint answers by closing.
            fn still_running(ep: &Endpoint) {
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "Section {} puts the close at the peer that receives a second \
                     answer, not at the endpoint that declines to send one",
                    $sec
                );
            }

            /// A PUBLISH arriving the way the control stream delivers one
            /// reaches the flow that can answer it.
            ///
            /// The dispatch arm is the whole of what this measures. Without
            /// it a PUBLISH is checked for its Request ID and then dropped,
            /// and the peer waits for an answer the endpoint has no record to
            /// build one from.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// Removing the `ControlMessage::Publish` arm from
            /// `receive_message`:
            ///
            /// ```text
            /// the PUBLISH that arrived on the control stream could not be answered: UnknownRequest(1)
            /// ```
            ///
            /// It reddens fifteen tests: this gate on all five drafts, and
            /// both loopback gates on the same five, where the PUBLISH
            /// arrives off a real QUIC stream and this arm is the only thing
            /// that takes it anywhere.
            #[test]
            fn a_publish_off_the_control_stream_reaches_the_flow() {
                let mut ep = active();
                ep.receive_message(ControlMessage::Publish(crate::publish_of!(
                    $pubmsg,
                    PEERS_FIRST
                )))
                .expect("the peer's PUBLISH");

                crate::accept_publish!($accept, ep, peer_id())
                    .expect("the PUBLISH that arrived on the control stream could not be answered");
                still_running(&ep);
            }

            /// The offer the peer made is read back from the record.
            ///
            /// Every field asserted here is one an answer is decided from, and
            /// the alias is the one the endpoint has to hold against a second
            /// offer, so a record that kept only the identifier would pass the
            /// rest of this file and fail here.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// Moving the state machine on and dropping the message, which on
            /// drafts 14, 15 and 16 leaves nothing holding the offer:
            ///
            /// ```text
            /// the offer the peer made must be readable
            /// ```
            ///
            /// It reddens twelve tests, all on those three drafts: this gate,
            /// the one that says an offer of this endpoint's own is not the
            /// peer's, and both loopback gates in
            /// `duplicate_track_alias_on_the_wire.rs`, where the offer arrives
            /// off a real QUIC stream. Drafts 12 and 13 stay green, which is
            /// what already holding the record looks like from here.
            ///
            /// The two gates below it are the ones the cut cannot reach: both
            /// assert an absence, and with no record at all there is nothing
            /// to read back either way. They have cuts of their own.
            #[test]
            fn the_offer_the_peer_made_is_read_back() {
                let ep = offered();
                let offer = ep
                    .pending_publish(peer_id())
                    .expect("the offer the peer made must be readable");
                assert_eq!(
                    offer.track_namespace,
                    crate::namespace(),
                    "the record should name the namespace the peer offered"
                );
                assert_eq!(
                    offer.track_name,
                    b"alpha".to_vec(),
                    "the record should name the track the peer offered"
                );
                assert_eq!(
                    offer.track_alias,
                    crate::v(7),
                    "the record should carry the alias the offer spends"
                );
                assert_eq!(ep.pending_publish_count(), 1, "one offer is waiting for an answer");
                still_running(&ep);
            }

            /// An offer that has been answered is no longer waiting for one.
            ///
            /// The other half of what "pending" means, and the half that says
            /// the record is read against the state rather than against its
            /// own presence: the offer stays on record for as long as the
            /// subscription does.
            ///
            /// # What it catches
            ///
            /// Reading the record back without asking the state machine beside
            /// it whether an answer is still owed - `pending_publish` answering
            /// `self.inbound_publishes.get(&id)` and nothing more:
            ///
            /// ```text
            /// an answered offer is still waiting for an answer, and named Some(VarInt(1))
            /// ```
            ///
            /// It reddens three tests, this gate on each of the three drafts,
            /// and no others: every other gate here reads the record while it
            /// is still owed an answer, which is the state the cut does not
            /// change.
            #[test]
            fn an_answered_offer_is_no_longer_waiting() {
                let ep = accepted();
                let still = ep.pending_publish(peer_id());
                assert!(
                    still.is_none(),
                    "an answered offer is still waiting for an answer, and named {:?}",
                    still.map(|p| p.request_id)
                );
                assert_eq!(ep.pending_publish_count(), 0, "nothing is waiting for an answer");
                still_running(&ep);
            }

            /// An identifier no offer arrived under reads back nothing.
            ///
            /// # What it catches
            ///
            /// Finding the record by iteration instead of by the identifier
            /// the caller named, and judging what was found instead of what
            /// was asked for. Every other gate in this file has exactly one
            /// offer outstanding, so a lookup that ignores the id finds the
            /// right record by accident:
            ///
            /// ```text
            /// an offer was read back for an id nothing arrived under
            /// ```
            ///
            /// It reddens six tests: this gate and the one below it, on all
            /// three drafts that gained the record.
            ///
            /// Both halves have to be cut together. `pending_publish` looks the
            /// record up by id *and* asks the state machine, also by id,
            /// whether an answer is owed; replacing only the lookup leaves this
            /// gate green, because the state probe still refuses an identifier
            /// nothing arrived under. That was measured too: the one-sided cut
            /// failed two gates away instead of here.
            #[test]
            fn an_identifier_no_offer_arrived_under_reads_back_nothing() {
                let ep = offered();
                let none = ep.pending_publish(VarInt::from_u64(NEVER_USED).unwrap());
                assert!(none.is_none(), "an offer was read back for an id nothing arrived under");
            }

            crate::own_offer_gate!($own, $ownmsg);
            /// An answer to a PUBLISH that never arrived is refused.
            ///
            /// # What it catches
            ///
            /// Answering whichever offer is outstanding instead of the one
            /// the answer names - looking the record up by iteration rather
            /// than by id:
            ///
            /// ```text
            /// a PUBLISH_OK was built for a request that never arrived: ()
            /// ```
            ///
            /// It reddens five tests and no others: this gate, on all five
            /// drafts. Every other gate here has exactly one offer
            /// outstanding, so a lookup that ignores the id finds the right
            /// record by accident.
            #[test]
            fn an_answer_to_a_publish_that_never_arrived_is_refused() {
                let mut ep = offered();
                let err =
                    crate::accept_publish!($accept, ep, VarInt::from_u64(NEVER_USED).unwrap())
                        .expect_err("a PUBLISH_OK was built for a request that never arrived");
                assert!(
                    matches!(err, EndpointError::UnknownRequest(NEVER_USED)),
                    "the refusal should name the id nothing arrived under, and named {err:?}"
                );
                still_running(&ep);
            }

            /// A second PUBLISH_OK for one PUBLISH is refused.
            ///
            /// # What it catches
            ///
            /// Answering without moving the record on, so that the answer
            /// either drops the record or never makes one. That cut is the
            /// one recorded in this file's header, because it reaches
            /// thirty-five tests across three files and no single gate is
            /// where it belongs:
            ///
            /// ```text
            /// a second PUBLISH_OK was sent for one PUBLISH: ()
            /// ```
            #[test]
            fn a_second_acceptance_is_refused() {
                let mut ep = accepted();
                crate::accept_publish!($accept, ep, peer_id())
                    .expect_err("a second PUBLISH_OK was sent for one PUBLISH");
                still_running(&ep);
            }

            /// A PUBLISH already rejected cannot then be accepted.
            ///
            /// The other order, and a separate input because it leaves the
            /// record in a different state: "exactly one" is one answer of
            /// either kind, not one of each.
            ///
            /// # What it catches
            ///
            /// Letting the acceptance run from the state a rejection leaves:
            ///
            /// ```text
            /// a PUBLISH was accepted after it had been rejected: ()
            /// ```
            ///
            /// The cut is the rejection's own, not the acceptance's: leaving
            /// the record where it was when the PUBLISH_ERROR went out
            /// reddens five tests and only this gate. The acceptance has a
            /// cut of its own and it reddens this gate too, which is what
            /// two answers to one question look like.
            #[test]
            fn a_rejected_publish_cannot_then_be_accepted() {
                let mut ep = offered();
                crate::reject_publish!($reject, ep, peer_id()).expect("reject the offer");

                crate::accept_publish!($accept, ep, peer_id())
                    .expect_err("a PUBLISH was accepted after it had been rejected");
                still_running(&ep);
            }

            /// An offer that has not been accepted cannot be unsubscribed.
            ///
            /// The section gives the subscriber UNSUBSCRIBE for a
            /// subscription that is established; an offer still waiting for
            /// its answer is refused with the rejection message instead.
            ///
            /// # What it catches
            ///
            /// Discarding what the record says when the UNSUBSCRIBE is sent,
            /// so that it ends from any state rather than from the one the
            /// subscription exists in:
            ///
            /// ```text
            /// an offer this endpoint had not accepted was unsubscribed: Unsubscribe(Unsubscribe { request_id: VarInt(1) })
            /// ```
            ///
            /// It reddens fifteen tests: this gate and the two below it, on
            /// all five drafts.
            ///
            /// A second cut, taking the inbound-offer probe out of
            /// `unsubscribe` altogether, reddens this gate for a different
            /// reason - the refusal stops coming from the publish flow and
            /// starts coming from the request id not being found at all:
            ///
            /// ```text
            /// the refusal should come from the publish flow, and came from UnknownRequest(1)
            /// ```
            #[test]
            fn an_unanswered_publish_cannot_be_unsubscribed() {
                let mut ep = offered();
                let sent = ep
                    .unsubscribe(peer_id())
                    .expect_err("an offer this endpoint had not accepted was unsubscribed");
                assert!(
                    matches!(sent, EndpointError::PublishFlow(_)),
                    "the refusal should come from the publish flow, and came from {sent:?}"
                );
                still_running(&ep);
            }

            /// The subscriber ends an accepted offer with UNSUBSCRIBE, once.
            ///
            /// # What it catches
            ///
            /// Taking the inbound-offer probe out of `unsubscribe`, which
            /// leaves the message with nowhere to land:
            ///
            /// ```text
            /// UNSUBSCRIBE for an accepted offer: UnknownRequest(1)
            /// ```
            ///
            /// It reddens fifteen tests: this gate, the one above it and
            /// `an_alias_is_free_once_its_publish_ends` in the alias file,
            /// on all five drafts.
            #[test]
            fn an_accepted_publish_is_ended_by_unsubscribe() {
                let mut ep = accepted();
                ep.unsubscribe(peer_id()).expect("UNSUBSCRIBE for an accepted offer");

                ep.unsubscribe(peer_id()).expect_err("one subscription was unsubscribed twice");
                still_running(&ep);
            }

            /// The publisher ends an accepted offer, and nothing follows it.
            ///
            /// The other end of the same subscription, and the message that
            /// carries it is one this endpoint receives rather than sends -
            /// which is a different route into the same record.
            ///
            /// # What it catches
            ///
            /// Routing the publisher's end-of-subscription message only to
            /// subscriptions this endpoint asked for:
            ///
            /// ```text
            /// the publisher could not end the subscription it opened: UnknownRequest(1)
            /// ```
            ///
            /// It reddens five tests and no others: this gate, on all five
            /// drafts. The subscriber's own route into the same record is a
            /// different probe in a different method, and cutting either one
            /// leaves the other's gate green.
            #[test]
            fn an_accepted_publish_is_ended_by_the_publisher() {
                let mut ep = accepted();
                crate::publisher_ends!($ends, ep, peer_id())
                    .expect("the publisher could not end the subscription it opened");

                ep.unsubscribe(peer_id())
                    .expect_err("a subscription the publisher had ended was unsubscribed");
                still_running(&ep);
            }
        }
    };
}

inbound_publish_gates!(
    draft12,
    "draft12",
    0xff00_000c,
    versioned,
    rich,
    varint,
    plain,
    subscribe_done,
    own,
    rich,
    "4.1"
);
inbound_publish_gates!(
    draft13,
    "draft13",
    0xff00_000d,
    versioned,
    rich,
    filter,
    plain,
    subscribe_done,
    own,
    rich,
    "4.1"
);
inbound_publish_gates!(
    draft14,
    "draft14",
    0xff00_000e,
    versioned,
    rich,
    location,
    plain,
    publish_done,
    own,
    rich,
    "5.1"
);
inbound_publish_gates!(
    draft15,
    "draft15",
    0,
    alpn,
    plain,
    params,
    plain,
    publish_done,
    own,
    params,
    "5.1"
);
inbound_publish_gates!(
    draft16,
    "draft16",
    0,
    alpn,
    ext,
    params,
    retry,
    publish_done,
    own,
    ext,
    "5.1"
);

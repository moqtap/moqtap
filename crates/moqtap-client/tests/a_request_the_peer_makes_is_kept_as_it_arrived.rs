#![cfg(any(feature = "draft16", feature = "draft17", feature = "draft18", feature = "draft19",))]

//! What the peer asked for can be read back from the endpoint it asked.
//!
//! Section 5.1, in the same words on all four drafts: "A publisher initiates a
//! subscription to a track by sending the PUBLISH message. The subscriber
//! either accepts or rejects the subscription using PUBLISH_OK or
//! REQUEST_ERROR." Every request kind is that shape - one end asks, the other
//! decides - and what is being decided about is named in the request. An
//! endpoint that keeps only how far a request has got has kept the half that
//! cannot answer it.
//!
//! # Why draft-16 sits with the other three
//!
//! Drafts 17, 18 and 19 take every request kind through one entry point,
//! `receive_request_on_stream` - six kinds on draft-17 and seven on 18 and 19.
//! Draft-16 has an entry point of its own for exactly one kind, because Section
//! 3.3 there names only two uses of a bidirectional stream: the control stream
//! and SUBSCRIBE_NAMESPACE. That one message is also the only place a namespace
//! prefix appears, so an arm that moved a state machine and dropped the message
//! would leave the prefix with nowhere to be read from again.
//!
//! # Why one map holds both directions, and the messages do not
//!
//! A Request ID the peer allocated and one this endpoint allocated have
//! opposite least significant bits, so a per-kind map of state machines can
//! hold both ends' requests without confusing them. That is why these drafts
//! have one - but a state machine is not the request. The request itself is
//! recorded on arrival and only on arrival, which is what makes
//! "did the peer ask this" a question the endpoint can answer at all. The last
//! gate in each group is the one that says so.
//!
//! # Ablations, measured
//!
//! Recorded on the gates they redden.

use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;

fn v(n: u64) -> VarInt {
    VarInt::from_u64(n).expect("a fixture value fits a varint")
}

/// The namespace every request below is about.
#[allow(dead_code)]
fn ns() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec()])
}

/// A namespace prefix, which is the same tuple: a prefix of a namespace is a
/// namespace, and nothing here turns on the two being different.
#[allow(dead_code)]
fn prefix() -> TrackNamespace {
    TrackNamespace(vec![b"conformance".to_vec()])
}

/// A second prefix, for the request this endpoint makes itself.
#[allow(dead_code)]
fn other_prefix() -> TrackNamespace {
    TrackNamespace(vec![b"elsewhere".to_vec()])
}

#[allow(dead_code)]
fn track() -> Vec<u8> {
    b"alpha".to_vec()
}

// -- draft-16: the one request that has a stream of its own ------------

#[cfg(feature = "draft16")]
mod draft16 {
    use moqtap_client::draft16::endpoint::Endpoint;
    use moqtap_client::draft16::session::request_id::Role;
    use moqtap_client::draft16::session::state::SessionState;
    use moqtap_codec::draft16::message::{ControlMessage, ServerSetup, SubscribeNamespace};
    use moqtap_codec::kvp::{KeyValuePair, KvpValue};
    use moqtap_codec::varint::VarInt;

    /// The peer is the client here, so its Request IDs are the even ones.
    const PEERS_ID: u64 = 0;

    /// An identifier no request ever arrived under.
    const NEVER_USED: u64 = 4;

    fn v(n: u64) -> VarInt {
        crate::v(n)
    }

    /// A server past setup, with a budget granted to the peer.
    fn responder() -> Endpoint {
        let mut ep = Endpoint::new(Role::Server);
        ep.connect().expect("a server may open");
        let _ = ep.send_client_setup(vec![]).expect("its own SETUP");
        ep.receive_server_setup(&ServerSetup {
            parameters: vec![KeyValuePair { key: v(0x02), value: KvpValue::Varint(v(100)) }],
        })
        .expect("the peer's SETUP");
        let _ = ep.send_max_request_id(v(100)).expect("a budget for the peer");
        ep
    }

    fn peers_request(id: u64) -> ControlMessage {
        ControlMessage::SubscribeNamespace(SubscribeNamespace {
            request_id: v(id),
            namespace_prefix: crate::prefix(),
            subscribe_options: v(0),
            parameters: Vec::new(),
        })
    }

    /// An endpoint holding the peer's unanswered namespace subscription.
    fn asked() -> Endpoint {
        let mut ep = responder();
        ep.receive_subscribe_namespace_on_stream(&peers_request(PEERS_ID))
            .expect("the peer opens a namespace subscription stream");
        ep
    }

    fn still_running(ep: &Endpoint) {
        assert_eq!(
            ep.session_state(),
            SessionState::Active,
            "nothing here is a rule this endpoint answers by closing"
        );
    }

    /// The prefix the peer asked for is read back from the record.
    ///
    /// # What it catches, observed by making the change and running it
    ///
    /// Moving the state machine on and dropping the request:
    ///
    /// ```text
    /// the namespace subscription the peer opened must be readable
    /// ```
    ///
    /// It reddens three tests: this gate, the one that says a subscription of
    /// this endpoint's own is not the peer's, and
    /// `the_peers_subscription_is_answered_on_its_own_stream` in
    /// `draft16_namespace_stream_on_the_wire.rs`, where the request arrives off
    /// a real QUIC stream.
    #[test]
    fn the_prefix_the_peer_asked_for_is_read_back() {
        let ep = asked();
        let asked_for = ep
            .pending_subscribe_namespace(v(PEERS_ID))
            .expect("the namespace subscription the peer opened must be readable");
        assert_eq!(
            asked_for.namespace_prefix,
            crate::prefix(),
            "the record should name the prefix the peer asked for"
        );
        assert_eq!(
            ep.pending_subscribe_namespace_count(),
            1,
            "one namespace subscription is waiting for an answer"
        );
        still_running(&ep);
    }

    /// A namespace subscription that has been answered is no longer waiting.
    ///
    /// # What it catches
    ///
    /// Reading the record back without asking the state machine beside it
    /// whether an answer is still owed:
    ///
    /// ```text
    /// an answered request is still waiting for an answer, and named Some(VarInt(0))
    /// ```
    ///
    /// It reddens one test, this one.
    #[test]
    fn an_answered_namespace_subscription_is_no_longer_waiting() {
        let mut ep = asked();
        ep.respond_on_namespace_stream(v(PEERS_ID), None).expect("accept it");
        let still = ep.pending_subscribe_namespace(v(PEERS_ID));
        assert!(
            still.is_none(),
            "an answered request is still waiting for an answer, and named {:?}",
            still.map(|s| s.request_id)
        );
        assert_eq!(ep.pending_subscribe_namespace_count(), 0, "nothing is waiting for an answer");
        still_running(&ep);
    }

    /// An identifier nothing arrived under reads back nothing.
    ///
    /// # What it catches
    ///
    /// Finding the record by iteration instead of by the identifier the caller
    /// named, and judging what was found instead of what was asked for:
    ///
    /// ```text
    /// a request was read back for an id nothing arrived under
    /// ```
    ///
    /// It reddens two tests, this gate and the one below it. Both halves of
    /// the accessor have to be cut together: replacing only the lookup leaves
    /// this gate green, because the state probe is still keyed by the
    /// identifier and refuses one nothing arrived under.
    #[test]
    fn an_identifier_nothing_arrived_under_reads_back_nothing() {
        let ep = asked();
        let none = ep.pending_subscribe_namespace(v(NEVER_USED));
        assert!(none.is_none(), "a request was read back for an id nothing arrived under");
    }

    /// A namespace subscription this endpoint made is not one the peer made.
    ///
    /// # What it catches
    ///
    /// Writing the record on the outbound path as well as the inbound one,
    /// which one map keyed by Request ID alone invites:
    ///
    /// ```text
    /// a request this endpoint made was read back as the peer's, and named Some(VarInt(1))
    /// ```
    ///
    /// It reddens one test, this one.
    #[test]
    fn a_namespace_subscription_of_this_endpoints_own_is_not_the_peers() {
        let mut ep = asked();
        let (own, _) = ep
            .subscribe_namespace(crate::other_prefix(), v(0), vec![])
            .expect("this endpoint may subscribe to a namespace of its own");
        let read = ep.pending_subscribe_namespace(own);
        assert!(
            read.is_none(),
            "a request this endpoint made was read back as the peer's, and named {:?}",
            read.map(|s| s.request_id)
        );
        assert_eq!(
            ep.pending_subscribe_namespace_count(),
            1,
            "only the peer's request is waiting for an answer from this endpoint"
        );
        still_running(&ep);
    }
}

// -- drafts 17, 18 and 19: every request kind --------------------------

/// The peer's request, in the two shapes the request messages take: draft-17
/// gives every one of them a Required Request ID Delta, and drafts 18 and 19
/// dropped it again.
#[macro_export]
macro_rules! peers_request {
    (subscribe, d17, $id:expr) => {
        ControlMessage::Subscribe(Subscribe {
            request_id: $id,
            required_request_id_delta: $crate::v(0),
            track_namespace: $crate::ns(),
            track_name: $crate::track(),
            parameters: Vec::new(),
        })
    };
    (subscribe, plain, $id:expr) => {
        ControlMessage::Subscribe(Subscribe {
            request_id: $id,
            track_namespace: $crate::ns(),
            track_name: $crate::track(),
            parameters: Vec::new(),
        })
    };
    (publish, d17, $id:expr) => {
        ControlMessage::Publish(Publish {
            request_id: $id,
            required_request_id_delta: $crate::v(0),
            track_namespace: $crate::ns(),
            track_name: $crate::track(),
            track_alias: $crate::v(7),
            parameters: Vec::new(),
            track_properties: Vec::new(),
        })
    };
    (publish, plain, $id:expr) => {
        ControlMessage::Publish(Publish {
            request_id: $id,
            track_namespace: $crate::ns(),
            track_name: $crate::track(),
            track_alias: $crate::v(7),
            parameters: Vec::new(),
            track_properties: Vec::new(),
        })
    };
    (fetch, d17, $id:expr) => {
        ControlMessage::Fetch(Fetch {
            request_id: $id,
            required_request_id_delta: $crate::v(0),
            fetch_type: FetchType::Standalone,
            fetch_payload: $crate::standalone_payload!(),
            parameters: Vec::new(),
        })
    };
    (fetch, plain, $id:expr) => {
        ControlMessage::Fetch(Fetch {
            request_id: $id,
            fetch_type: FetchType::Standalone,
            fetch_payload: $crate::standalone_payload!(),
            parameters: Vec::new(),
        })
    };
    (publish_namespace, d17, $id:expr) => {
        ControlMessage::PublishNamespace(PublishNamespace {
            request_id: $id,
            required_request_id_delta: $crate::v(0),
            track_namespace: $crate::ns(),
            parameters: Vec::new(),
        })
    };
    (publish_namespace, plain, $id:expr) => {
        ControlMessage::PublishNamespace(PublishNamespace {
            request_id: $id,
            track_namespace: $crate::ns(),
            parameters: Vec::new(),
        })
    };
    (subscribe_namespace, d17, $id:expr) => {
        ControlMessage::SubscribeNamespace(SubscribeNamespace {
            request_id: $id,
            required_request_id_delta: $crate::v(0),
            namespace_prefix: $crate::prefix(),
            subscribe_options: $crate::v(0),
            parameters: Vec::new(),
        })
    };
    (subscribe_namespace, plain, $id:expr) => {
        ControlMessage::SubscribeNamespace(SubscribeNamespace {
            request_id: $id,
            namespace_prefix: $crate::prefix(),
            parameters: Vec::new(),
        })
    };
    (subscribe_tracks, plain, $id:expr) => {
        ControlMessage::SubscribeTracks(SubscribeTracks {
            request_id: $id,
            namespace_prefix: $crate::prefix(),
            parameters: Vec::new(),
        })
    };
    (track_status, d17, $id:expr) => {
        ControlMessage::TrackStatus(TrackStatus {
            request_id: $id,
            required_request_id_delta: $crate::v(0),
            track_namespace: $crate::ns(),
            track_name: $crate::track(),
            parameters: Vec::new(),
        })
    };
    (track_status, plain, $id:expr) => {
        ControlMessage::TrackStatus(TrackStatus {
            request_id: $id,
            track_namespace: $crate::ns(),
            track_name: $crate::track(),
            parameters: Vec::new(),
        })
    };
}

/// The one fetch payload used here, which is the same on all three drafts.
#[macro_export]
macro_rules! standalone_payload {
    () => {
        FetchPayload::Standalone {
            track_namespace: $crate::ns(),
            track_name: $crate::track(),
            start_group: $crate::v(0),
            start_object: $crate::v(0),
            end_group: $crate::v(1),
            end_object: $crate::v(0),
        }
    };
}

/// The seventh request kind, which draft-17 does not carry.
///
/// Section 10.19 of drafts 18 and 19 gives SUBSCRIBE_TRACKS a map of its own
/// beside SUBSCRIBE_NAMESPACE, so the read-back has to find the right one of
/// the two.
#[macro_export]
macro_rules! subscribe_tracks_gates {
    (none) => {};
    (present) => {
        /// The SUBSCRIBE_TRACKS the peer sent is read back from the record.
        #[test]
        fn a_track_subscription_the_peer_makes_is_read_back() {
            let (ep, id) = arrives($crate::peers_request!(subscribe_tracks, plain, v(10)));
            let asked_for = ep
                .pending_subscribe_tracks(id)
                .expect("the track subscription the peer opened must be readable");
            assert_eq!(
                asked_for.namespace_prefix,
                $crate::prefix(),
                "the record should name the prefix the peer asked for"
            );
            assert!(
                ep.pending_subscribe_namespace(id).is_none(),
                "a SUBSCRIBE_TRACKS is not a SUBSCRIBE_NAMESPACE, and these two share a prefix"
            );
            still_running(&ep);
        }
    };
}

/// One draft's gates: one per request kind, then the four that say what the
/// record is not.
macro_rules! peers_request_gates {
    ($draft:ident, $feat:literal, $shape:tt, $tracks:tt) => {
        #[cfg(feature = $feat)]
        mod $draft {
            use moqtap_client::$draft::endpoint::Endpoint;
            use moqtap_client::$draft::session::request_id::Role;
            use moqtap_client::$draft::session::state::SessionState;
            #[allow(unused_imports)]
            use moqtap_codec::types::*;
            use moqtap_codec::varint::VarInt;
            #[allow(unused_imports)]
            use moqtap_codec::$draft::message::*;

            /// An identifier no request ever arrived under.
            const NEVER_USED: u64 = 40;

            fn v(n: u64) -> VarInt {
                crate::v(n)
            }

            /// A server, so the peer's Request IDs are the even ones.
            fn responder() -> Endpoint {
                let mut ep = Endpoint::new(Role::Server);
                ep.connect().expect("a server may open");
                ep.send_setup(vec![]).expect("its own SETUP");
                ep.receive_setup(&Setup { options: vec![] }).expect("the peer's SETUP");
                ep
            }

            /// An endpoint holding one unanswered request from the peer.
            fn arrives(msg: ControlMessage) -> (Endpoint, VarInt) {
                let mut ep = responder();
                let id =
                    ep.receive_request_on_stream(&msg).expect("the peer opens a request stream");
                (ep, id)
            }

            fn still_running(ep: &Endpoint) {
                assert_eq!(
                    ep.session_state(),
                    SessionState::Active,
                    "nothing here is a rule this endpoint answers by closing"
                );
            }

            /// The SUBSCRIBE the peer sent is read back from the record.
            ///
            /// # What it catches, observed by making the change and running it
            ///
            /// Moving the state machine on and dropping the request:
            ///
            /// ```text
            /// the subscription the peer opened must be readable
            /// ```
            ///
            /// One cut reaches every read-back gate in this group, because one
            /// entry point takes every request kind: it reddens twenty-six
            /// tests, eight on draft-17 and nine each on 18 and 19. The
            /// exception is the gate that asserts an absence - with nothing
            /// recorded, an identifier nothing arrived under still reads back
            /// nothing - and that gate has a cut of its own.
            #[test]
            fn a_subscribe_the_peer_makes_is_read_back() {
                let (ep, id) = arrives(crate::peers_request!(subscribe, $shape, v(0)));
                let asked_for = ep
                    .pending_subscribe(id)
                    .expect("the subscription the peer opened must be readable");
                assert_eq!(
                    asked_for.track_name,
                    crate::track(),
                    "the record should name the track the peer subscribed to"
                );
                assert_eq!(
                    asked_for.track_namespace,
                    crate::ns(),
                    "the record should name the namespace the peer subscribed in"
                );
                assert_eq!(ep.pending_subscribe_count(), 1, "one SUBSCRIBE is waiting");
                still_running(&ep);
            }

            /// The PUBLISH the peer sent is read back from the record.
            #[test]
            fn a_publish_the_peer_makes_is_read_back() {
                let (ep, id) = arrives(crate::peers_request!(publish, $shape, v(2)));
                let offer =
                    ep.pending_publish(id).expect("the offer the peer made must be readable");
                assert_eq!(
                    offer.track_alias,
                    v(7),
                    "the record should carry the alias the offer spends"
                );
                assert_eq!(ep.pending_publish_count(), 1, "one offer is waiting");
                still_running(&ep);
            }

            /// The FETCH the peer sent is read back from the record.
            #[test]
            fn a_fetch_the_peer_makes_is_read_back() {
                let (ep, id) = arrives(crate::peers_request!(fetch, $shape, v(4)));
                let asked_for =
                    ep.pending_fetch(id).expect("the fetch the peer made must be readable");
                let FetchPayload::Standalone { ref track_name, .. } = asked_for.fetch_payload
                else {
                    panic!("the fixture is a standalone fetch");
                };
                assert_eq!(
                    *track_name,
                    crate::track(),
                    "the record should name the track the peer fetched"
                );
                assert_eq!(ep.pending_fetch_count(), 1, "one FETCH is waiting");
                still_running(&ep);
            }

            /// The PUBLISH_NAMESPACE the peer sent is read back from the record.
            #[test]
            fn an_announcement_the_peer_makes_is_read_back() {
                let (ep, id) = arrives(crate::peers_request!(publish_namespace, $shape, v(6)));
                let announced = ep
                    .pending_publish_namespace(id)
                    .expect("the announcement the peer made must be readable");
                assert_eq!(
                    announced.track_namespace,
                    crate::ns(),
                    "the record should name the namespace the peer announced"
                );
                assert_eq!(ep.pending_publish_namespace_count(), 1, "one announcement is waiting");
                still_running(&ep);
            }

            /// The SUBSCRIBE_NAMESPACE the peer sent is read back from the record.
            #[test]
            fn a_namespace_subscription_the_peer_makes_is_read_back() {
                let (ep, id) = arrives(crate::peers_request!(subscribe_namespace, $shape, v(8)));
                let asked_for = ep
                    .pending_subscribe_namespace(id)
                    .expect("the namespace subscription the peer opened must be readable");
                assert_eq!(
                    asked_for.namespace_prefix,
                    crate::prefix(),
                    "the record should name the prefix the peer asked for"
                );
                assert_eq!(
                    ep.pending_subscribe_namespace_count(),
                    1,
                    "one namespace subscription is waiting"
                );
                still_running(&ep);
            }

            crate::subscribe_tracks_gates!($tracks);

            /// The TRACK_STATUS the peer asked for is read back from the record.
            #[test]
            fn a_track_status_the_peer_asks_for_is_read_back() {
                let (ep, id) = arrives(crate::peers_request!(track_status, $shape, v(12)));
                let asked_for = ep
                    .pending_track_status(id)
                    .expect("the track status the peer asked for must be readable");
                assert_eq!(
                    asked_for.track_name,
                    crate::track(),
                    "the record should name the track the peer asked about"
                );
                assert_eq!(ep.pending_track_status_count(), 1, "one track status is waiting");
                still_running(&ep);
            }

            /// A request that has been answered is no longer waiting for one.
            ///
            /// The other half of what "pending" means. The record stays,
            /// because the subscription outlives its answer; what stops is the
            /// endpoint owing a reply.
            ///
            /// # What it catches
            ///
            /// Reading the record back without asking the state machine
            /// whether it is still owed an answer:
            ///
            /// ```text
            /// an answered request is still waiting for an answer, and named Some(VarInt(0))
            /// ```
            ///
            /// It reddens three tests, this gate on each of the three drafts.
            #[test]
            fn an_answered_request_is_no_longer_waiting() {
                let (mut ep, id) = arrives(crate::peers_request!(subscribe, $shape, v(0)));
                ep.send_response_on_stream(
                    id,
                    &ControlMessage::SubscribeOk(SubscribeOk {
                        track_alias: v(7),
                        parameters: Vec::new(),
                        track_properties: Vec::new(),
                    }),
                )
                .expect("accept the subscription");
                let still = ep.pending_subscribe(id);
                assert!(
                    still.is_none(),
                    "an answered request is still waiting for an answer, and named {:?}",
                    still.map(|s| s.request_id)
                );
                assert_eq!(ep.pending_subscribe_count(), 0, "nothing is waiting for an answer");
                still_running(&ep);
            }

            /// An identifier nothing arrived under reads back nothing.
            ///
            /// # What it catches
            ///
            /// Finding the record by iteration instead of by the identifier the
            /// caller named, and judging what was found instead of what was
            /// asked for. Every other gate in this group has exactly one
            /// request outstanding, so a lookup that ignores the id finds the
            /// right record by accident:
            ///
            /// ```text
            /// a request was read back for an id nothing arrived under
            /// ```
            ///
            /// It reddens six tests: this gate and the one above it, on all
            /// three drafts. Both halves have to be cut together - replacing
            /// only the lookup leaves this gate green, because the state probe
            /// is still keyed by the identifier and refuses one nothing
            /// arrived under. That was measured: the one-sided cut failed on
            /// the gate above instead of on this one.
            #[test]
            fn an_identifier_nothing_arrived_under_reads_back_nothing() {
                let (ep, _) = arrives(crate::peers_request!(subscribe, $shape, v(0)));
                let none = ep.pending_subscribe(v(NEVER_USED));
                assert!(none.is_none(), "a request was read back for an id nothing arrived under");
            }

            /// A request reads back only as the kind it arrived as.
            ///
            /// One map holds all of them, so the identifier alone does not say
            /// which kind of request it names.
            ///
            /// # What it catches
            ///
            /// A count that forgets which kind it counts -
            /// `pending_publish_count` answering `inbound_requests.len()`:
            ///
            /// ```text
            /// assertion `left == right` failed: no offer arrived left: 1 right: 0
            /// ```
            ///
            /// It reddens three tests, this gate on each of the three drafts.
            /// The typed half of this gate has no cut of its own and cannot
            /// have one: `pending_publish` returns `Option<&Publish>`, so an
            /// accessor that ignored the variant would not compile. What can
            /// go wrong is the count beside it, and that is what is measured
            /// here.
            #[test]
            fn a_request_reads_back_only_as_the_kind_it_arrived_as() {
                let (ep, id) = arrives(crate::peers_request!(subscribe, $shape, v(0)));
                let wrong = ep.pending_publish(id);
                assert!(
                    wrong.is_none(),
                    "a SUBSCRIBE was read back as an offer, and named {:?}",
                    wrong.map(|p| p.request_id)
                );
                assert_eq!(ep.pending_publish_count(), 0, "no offer arrived");
                assert!(
                    ep.pending_subscribe(id).is_some(),
                    "the request itself is still on record"
                );
            }

            /// A request this endpoint made is not one the peer made.
            ///
            /// The state of both ends' subscriptions is in one map, keyed by
            /// Request ID, so the record that answers "what did the peer ask"
            /// is the one that knows which direction the request went.
            ///
            /// # What it catches
            ///
            /// Writing the record on the outbound path as well - one line in
            /// `subscribe`, beside the state machine it already inserts:
            ///
            /// ```text
            /// a request this endpoint made was read back as the peer's, and named Some(VarInt(1))
            /// ```
            ///
            /// It reddens three tests, this gate on each of the three drafts.
            #[test]
            fn a_request_of_this_endpoints_own_is_not_the_peers() {
                let (mut ep, _) = arrives(crate::peers_request!(subscribe, $shape, v(0)));
                let (own, _) = ep
                    .subscribe(crate::ns(), b"beta".to_vec(), vec![])
                    .expect("this endpoint may subscribe to a track of its own");
                let read = ep.pending_subscribe(own);
                assert!(
                    read.is_none(),
                    "a request this endpoint made was read back as the peer's, and named {:?}",
                    read.map(|s| s.request_id)
                );
                assert_eq!(
                    ep.pending_subscribe_count(),
                    1,
                    "only the peer's request is waiting for an answer from this endpoint"
                );
                still_running(&ep);
            }
        }
    };
}

peers_request_gates!(draft17, "draft17", d17, none);
peers_request_gates!(draft18, "draft18", plain, present);
peers_request_gates!(draft19, "draft19", plain, present);

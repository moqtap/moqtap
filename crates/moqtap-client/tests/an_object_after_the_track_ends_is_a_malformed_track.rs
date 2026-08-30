#![cfg(any(
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16"
))]

//! A track that carries on after its own final Object is given up.
//!
//! Draft-12 Section 2.5 lists the condition among the ways a Track can be
//! malformed: "An Object is received on a Track whose Group and Object ID are
//! larger than the final Object in the Track. The final Object in a Track is
//! the Object with Status END_OF_TRACK or the last Object sent in a FETCH whose
//! response indicated End of Track." Draft-13 repeats it word for word, and so
//! do drafts 14 through 17; drafts 18 and 19 drop the two words "on a Track"
//! and change nothing else.
//!
//! The answer is the section's one answer for its whole list, and these five
//! drafts do not all give it in the same words. Drafts 12 and 13 say "it MUST
//! UNSUBSCRIBE from the Track and SHOULD deliver an error to the application";
//! drafts 14, 15 and 16 widen it to the other kind of request — "it MUST
//! UNSUBSCRIBE any subscription and FETCH_CANCEL any fetch for that Track from
//! that publisher". Every gate here holds a subscription and no fetch, so what
//! it measures is the half both wordings share.
//!
//! # Why this condition and not the one beside it
//!
//! `a_malformed_track_is_withdrawn_from.rs` fires the mixed-framing condition,
//! which is the only other one this crate detects, and it stops at draft-15
//! because draft-16 made the Forwarding Preference a property of an Object
//! rather than of a Track and left nothing for a record of the track's framing
//! to contradict. This condition is stated unchanged from draft-12 through
//! draft-19 and rests on nothing that moved, so it is the one that reaches the
//! drafts the other cannot.
//!
//! **Draft-16 is the draft that argument was written for**, and it is here
//! now. It states the answer in the same words as drafts 14 and 15 and had no
//! condition this crate could raise it with — a whole sentence of the
//! specification with nothing on the other side of it. This is that condition,
//! and the entire Malformed Track apparatus reaches draft-16 with it: the
//! record of which tracks were given up, the fetch-track table a FETCH_CANCEL
//! is found through, and the flows behind a lock apiece that let a data path
//! holding `&self` end a request.
//!
//! **The record it needs is not the same one on every draft, and that is the
//! reason for the order these were built in.** Drafts 12 and 13 already kept
//! where each track's objects had reached, for a rule of their own: an
//! end-of-track object behind what the track has carried ends the session
//! there. Drafts 14 and 15 state no such rule —
//! `a_track_may_end_where_it_has_already_been.rs` asserts the acceptance on the
//! seven drafts that permit it — so on them an end-of-track object is judged
//! against nothing and only settles where the track stopped. One record, two
//! entry points, and which one a draft calls is the whole of what it says about
//! the rule beside this one.
//!
//! # Larger is the drafts' own comparison
//!
//! Every draft carrying the condition carries a Location Structure section with
//! it, and all five spell one Location as below another the same way —
//! draft-12 Section 1.3.1, and draft-15 and draft-16 Section 1.4.1: "A.Group <
//! B.Group ||
//! (A.Group == B.Group && A.Object < B.Object)". That is not a detail: read
//! field by field instead, an Object in a *later* group whose Object ID happens
//! to be smaller would have neither number larger and would escape the rule.
//! `a_later_group_is_past_the_end_whatever_its_object_id` is that exact case,
//! and it is the gate that tells the two readings apart.
//!
//! # The two paths answer in different places, and that is the design
//!
//! A datagram is read through the connection, which is what an UNSUBSCRIBE
//! takes, so `recv_datagram` withdraws where it finds the fault. An object on a
//! subgroup stream is not: `accept_subgroup_stream` hands the caller a stream
//! holding no connection, so the reader that finds the fault cannot send
//! anything, and `withdraw_for_data_stream` is the separate call that does —
//! the Malformed Track twin of `close_for_data_stream`, which draws the same
//! line for the same reason. Two gates hold the two halves apart: one asserts
//! the withdrawal arrives with nothing else asked of the caller, the other
//! asserts it does *not* arrive until the caller asks.
//!
//! # Every gate carries the subscription through to its answer
//!
//! The rule is reached by resolving an Object's Track Alias to a track, and
//! from draft-12 the alias travels in the SUBSCRIBE_OK rather than in the
//! SUBSCRIBE. A gate that sent the objects without waiting for the answer would
//! have an alias that names nothing, the record would never be consulted, and
//! the gate would pass against a tree with the rule and against one without it.
//!
//! # Ablations, measured
//!
//! Eleven cuts, each applied to the working tree, run, and reverted with the
//! file compared byte for byte afterwards. They are spread over all five
//! drafts, because each carries the answer through a module of its own and a
//! cut that only ever landed on one of them would say nothing about the others.
//!
//! Reading larger field by field rather than as the Location comparison the
//! drafts define:
//!
//! ```text
//! an Object in a later group is past the track's final Object, and it was accepted
//! Section 2.5 makes an Object past the track's final Object a malformed track, and the datagram was accepted
//! Section 2.4.2 makes an Object past the track's final Object a malformed track, and the datagram was accepted
//! ```
//!
//! **Eight of the twelve gates, on all four drafts, and not the four the cut
//! was aimed at.** The later-group gates are the case it was written for; the
//! datagram gates go with them because that object sits at group 3, object 1
//! against a final Object at group 3, object 0, where the Group is *equal*
//! rather than larger and the field-by-field reading lets it through as well.
//! The Location comparison carries both shapes an Object can be past the end
//! in, and neither survives without it. The four left green are the acceptance
//! gates, which is the right four: a reading that refuses less cannot refuse
//! something it should not.
//!
//! Never writing the final Object down, which is the rule removed rather than
//! misread, takes the same eight.
//!
//! Dropping the withdrawal from draft-12's datagram path, so the condition is
//! reported and nothing is sent, and again from draft-14's:
//!
//! ```text
//! assertion `left == right` failed: an application that missed the error should still be able to learn why the subscription ended
//!   left: None
//!  right: Some(ObjectPastFinalObject)
//! ```
//!
//! The gate that goes red is the record rather than the wire, and that is worth
//! reading twice: the withdrawal and the record are made by the same call, so a
//! path that stops sending stops remembering too. The record is not an
//! independent witness that the UNSUBSCRIBE went out, which is why the gate
//! asserts the peer's view of the wire beside it.
//!
//! Letting draft-13's `withdraw_for_data_stream` answer without withdrawing:
//!
//! ```text
//! assertion `left == right` failed: Section 2.5 asks a subscriber that detects a Malformed Track to UNSUBSCRIBE from it
//!   left: []
//!  right: [0]
//! ```
//!
//! Taking the measurement off draft-15's stream objects altogether:
//!
//! ```text
//! an Object in a later group is past the track's final Object, and it was accepted
//! ```
//!
//! **One gate, and draft-15's datagram gate stays green** — which is the
//! clearest statement there is that the two paths are wired separately and that
//! neither stands in for the other.
//!
//! Firing on every object that arrives after the end rather than on the ones
//! past it:
//!
//! ```text
//! an Object below the track's final Object is not one the condition names: Endpoint(ObjectPastFinalObject { alias: 7, group: 3, object: 0, final_group: 4, final_object: 1 })
//! ```
//!
//! Four gates, one on each draft, and every one of them an acceptance gate.
//!
//! And giving draft-12's close table an arm for the condition, which is the
//! worst answer within reach and the one a Protocol Violation code three
//! sections away invites:
//!
//! ```text
//! Section 2.5 answers this with an UNSUBSCRIBE rather than a close, but close_for_data_stream closed it
//! ```
//!
//! Two gates, both of them draft-12's, with the other thirteen untouched —
//! which is what a per-draft close table should do, and the clearest single
//! argument for spreading the cuts over all five.
//!
//! # Three more, into draft-16, because it arrived with the apparatus
//!
//! The other four drafts already had somewhere to put this condition. Draft-16
//! had none of it — no record of a withdrawn track, no fetch-track table, no
//! flow behind a lock — so its three gates went green the first time they were
//! run against code written the same afternoon, which is exactly when a gate
//! deserves least trust.
//!
//! Taking the measurement off draft-16's stream objects:
//!
//! ```text
//! an Object in a later group is past the track's final Object, and it was accepted
//! ```
//!
//! **One gate, and the datagram gate stays green** — the same separation
//! draft-15's cut showed, on a draft where the two paths were wired from
//! scratch rather than copied into place.
//!
//! Reporting the condition on draft-16 and sending nothing:
//!
//! ```text
//! assertion `left == right` failed: an application that missed the error should still be able to learn why the subscription ended
//!   left: None
//!  right: Some(ObjectPastFinalObject)
//! assertion `left == right` failed: Section 2.4.2 asks a subscriber that detects a Malformed Track to UNSUBSCRIBE from it
//!   left: []
//!  right: [0]
//! ```
//!
//! Two gates, and between them both halves of the answer: the record an
//! application reads afterwards, and the message the peer sees.
//!
//! Handing draft-16's streams and datagrams no track to measure against, which
//! is what an unresolved Track Alias amounts to:
//!
//! ```text
//! an Object in a later group is past the track's final Object, and it was accepted
//! Section 2.4.2 makes an Object past the track's final Object a malformed track, and the datagram was accepted
//! ```
//!
//! Both paths at once, which is the point: they share the alias lookup and
//! nothing else, so this is the one cut that has to take both of them.
//!
//! The acceptance gate stays green under all three, which is right — none of
//! these makes the crate refuse something it should not.

mod common;

/// One draft's gates.
macro_rules! past_the_end_gates {
    ($draft:ident, $feat:literal, $version:ident, $cfg:tt, $setup:tt, $ok:tt, $sub:tt,
     $hdr:tt, $dgram:tt, $section:literal) => {
        #[cfg(feature = $feat)]
        mod $draft {
            use std::time::Duration;

            use moqtap_client::malformed_tracks::MalformedTrackCondition;
            use moqtap_client::$draft::connection::{
                ClientConfig, Connection, ConnectionError, TransportType,
            };
            use moqtap_client::$draft::endpoint::EndpointError;
            use moqtap_codec::dispatch::AnyControlMessage;
            use moqtap_codec::kvp::{KeyValuePair, KvpValue};
            #[allow(unused_imports)]
            use moqtap_codec::types::{ContentExists, GroupOrder, TrackNamespace};
            use moqtap_codec::varint::VarInt;
            use moqtap_codec::version::DraftVersion;
            use moqtap_codec::$draft::message::{ControlMessage, ServerSetup, SubscribeOk};
            use moqtap_codec::$draft::types::ObjectStatus;

            const PATIENCE: Duration = Duration::from_secs(10);

            /// Long enough that a message on its way would have arrived, short
            /// enough that a gate expecting none does not sit on it.
            const BRIEF: Duration = Duration::from_millis(400);

            const ALIAS: u64 = 7;
            const TRACK: &[u8] = b"one-track";

            /// The group the track ends in. Everything is measured against a
            /// final Object in this one.
            const GROUP: u64 = 3;

            fn v(n: u64) -> VarInt {
                VarInt::from_u64(n).unwrap()
            }

            fn namespace() -> TrackNamespace {
                TrackNamespace(vec![b"conformance".to_vec()])
            }

            /// A ceiling large enough that no refusal here can be the
            /// ceiling's.
            fn setup_parameters() -> Vec<KeyValuePair> {
                vec![KeyValuePair { key: v(0x02), value: KvpValue::Varint(v(100)) }]
            }

            fn client_config() -> ClientConfig {
                crate::past_config!($cfg, DraftVersion::$version, setup_parameters())
            }

            fn server_setup() -> ServerSetup {
                crate::past_server_setup!($setup, DraftVersion::$version, setup_parameters())
            }

            fn encode(msg: ControlMessage) -> Vec<u8> {
                let mut out = Vec::new();
                AnyControlMessage::$version(msg).encode(&mut out).expect("encode");
                out
            }

            fn subscribe_id(msg: &AnyControlMessage) -> VarInt {
                match msg {
                    AnyControlMessage::$version(ControlMessage::Subscribe(s)) => s.request_id,
                    other => panic!("expected a SUBSCRIBE from the client, got {other:?}"),
                }
            }

            /// SUBSCRIBE_OK carrying the alias, which is what binds it.
            fn subscribe_ok(id: VarInt) -> ControlMessage {
                ControlMessage::SubscribeOk(crate::past_subscribe_ok!($ok, id, v(ALIAS)))
            }

            /// One subgroup stream: a header carrying no extension block, and
            /// then its objects, each with an empty payload so nothing about
            /// one can be refused for a reason that is not this rule.
            fn stream_bytes(group: u64, objects: &[(u64, ObjectStatus)]) -> Vec<u8> {
                crate::past_stream_bytes!($hdr, $draft, $version, v(ALIAS), v(group), objects)
            }

            /// A datagram stating the end of the track.
            fn end_of_track_datagram(group: u64, object: u64) -> Vec<u8> {
                crate::past_status_datagram!($dgram, $draft, $version, v(ALIAS), v(group), v(object))
            }

            /// An ordinary datagram carrying an object of the same track.
            fn payload_datagram(group: u64, object: u64) -> Vec<u8> {
                crate::past_payload_datagram!(
                    $dgram, $draft, $version, v(ALIAS), v(group), v(object)
                )
            }

            /// What the peer sends once the track is bound.
            ///
            /// Every scenario keeps to **one** framing throughout. A track sent
            /// two ways is the other condition of the same list, and a gate
            /// that fired both would not say which one it was measuring.
            #[derive(Debug, Clone, Copy)]
            enum Traffic {
                /// Datagrams: the track ends, and then an object arrives in the
                /// same group with a larger Object ID.
                PastByObject,
                /// Subgroup streams: the track ends in one group, and then an
                /// object arrives in a later one — with a *smaller* Object ID
                /// than the final Object's, which is what makes it the case
                /// that tells the two readings of "larger" apart.
                PastByGroup,
                /// Subgroup streams: the track ends, and then an object arrives
                /// below where it ended, which the rule does not name.
                Below,
            }

            /// Write one subgroup stream: a header and then its objects.
            async fn send_stream(
                conn: &quinn::Connection,
                group: u64,
                objects: &[(u64, ObjectStatus)],
            ) {
                let mut data = conn.open_uni().await.expect("open the data stream");
                data.write_all(&stream_bytes(group, objects)).await.expect("write the stream");
                data.finish().expect("finish the data stream");
            }

            async fn send_traffic(conn: &quinn::Connection, traffic: Traffic) {
                match traffic {
                    Traffic::PastByObject => {
                        conn.send_datagram(end_of_track_datagram(GROUP, 0).into())
                            .expect("send the end-of-track datagram");
                        conn.send_datagram(payload_datagram(GROUP, 1).into())
                            .expect("send the datagram past the end");
                    }
                    Traffic::PastByGroup => {
                        send_stream(conn, GROUP, &[(0, ObjectStatus::EndOfTrack)]).await;
                        send_stream(conn, GROUP + 1, &[(0, ObjectStatus::Normal)]).await;
                    }
                    Traffic::Below => {
                        send_stream(
                            conn,
                            GROUP + 1,
                            &[(0, ObjectStatus::Normal), (1, ObjectStatus::EndOfTrack)],
                        )
                        .await;
                        send_stream(conn, GROUP, &[(0, ObjectStatus::Normal)]).await;
                    }
                }
            }

            /// Everything that arrives on the control stream until it goes
            /// quiet.
            ///
            /// A macro rather than a function because the framed stream's type
            /// lives in a private module of the shared harness, so it can be
            /// held but not named.
            macro_rules! drain_control {
                ($framed:expr) => {{
                    let mut seen: Vec<AnyControlMessage> = Vec::new();
                    while let Ok(read) =
                        tokio::time::timeout(BRIEF, $framed.read_control(false)).await
                    {
                        match read {
                            Ok((msg, _)) => seen.push(msg),
                            Err(_) => break,
                        }
                    }
                    seen
                }};
            }

            /// The Request IDs of the UNSUBSCRIBEs among what the peer read.
            fn unsubscribed(seen: &[AnyControlMessage]) -> Vec<u64> {
                seen.iter()
                    .filter_map(|msg| match msg {
                        AnyControlMessage::$version(ControlMessage::Unsubscribe(u)) => {
                            Some(u.request_id.into_inner())
                        }
                        _ => None,
                    })
                    .collect()
            }

            /// The session outlives the withdrawal, which is the half of the
            /// sentence easiest to get wrong in the direction that destroys
            /// one.
            async fn still_running(conn: &quinn::Connection) {
                assert!(
                    conn.close_reason().is_none(),
                    "a Malformed Track costs one track, and the session was closed: {:?}",
                    conn.close_reason()
                );
            }

            /// Serve one connection: complete the setup, answer the SUBSCRIBE
            /// with the alias, send the traffic, and report the Request ID it
            /// asked under together with whatever came back.
            async fn peer(
                server: quinn::Endpoint,
                traffic: Traffic,
            ) -> (u64, Vec<AnyControlMessage>) {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");
                let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
                let mut framed = crate::common::frame_uni_recv(recv, DraftVersion::$version);
                framed.read_control(false).await.expect("read CLIENT_SETUP");
                send.write_all(&encode(ControlMessage::ServerSetup(server_setup())))
                    .await
                    .expect("write SERVER_SETUP");

                let (request, _) = framed.read_control(false).await.expect("read SUBSCRIBE");
                let id = subscribe_id(&request);
                send.write_all(&encode(subscribe_ok(id))).await.expect("write SUBSCRIBE_OK");

                send_traffic(&conn, traffic).await;
                let seen = drain_control!(framed);
                still_running(&conn).await;
                (id.into_inner(), seen)
            }

            /// Connect, subscribe, and read the answer that carries the alias.
            async fn subscribed(addr: &str) -> Connection {
                let mut conn =
                    tokio::time::timeout(PATIENCE, Connection::connect(addr, client_config()))
                        .await
                        .expect("connect did not finish")
                        .expect("connect");
                crate::past_subscribe!($sub, conn, namespace(), TRACK)
                    .await
                    .expect("subscribe");
                tokio::time::timeout(PATIENCE, conn.recv_and_dispatch())
                    .await
                    .expect("the answer carrying the alias never arrived")
                    .expect("dispatch SUBSCRIBE_OK");
                conn
            }

            /// Accept one subgroup stream, check it is the group expected, and
            /// read the objects the peer put on it.
            ///
            /// Exactly `objects` of them and no more, rather than reading to
            /// the end: what a reader gets past the last object is the
            /// decoder's business and not this rule's, and a loop that stopped
            /// on it would be asserting something about end-of-stream
            /// spellings instead of about the objects.
            ///
            /// The group is asserted rather than assumed so that a delivery
            /// order this gate did not intend fails saying so, instead of
            /// measuring the rule against the wrong object.
            async fn read_stream(
                conn: &Connection,
                group: u64,
                objects: usize,
            ) -> Result<(), ConnectionError> {
                let (header, mut stream) =
                    tokio::time::timeout(PATIENCE, conn.accept_subgroup_stream())
                        .await
                        .expect("the peer's data stream never arrived")
                        .expect("read the subgroup header");
                assert_eq!(
                    header.group_id(),
                    group,
                    "the streams arrived in an order this gate does not measure"
                );
                for _ in 0..objects {
                    tokio::time::timeout(PATIENCE, stream.read_subgroup_object())
                        .await
                        .expect("the stream produced no object")?;
                }
                Ok(())
            }

            /// The report names the object and where the track had ended, so an
            /// application reading it can tell the two apart.
            fn assert_report(err: &ConnectionError, at: (u64, u64), end: (u64, u64)) {
                match err {
                    ConnectionError::Endpoint(EndpointError::ObjectPastFinalObject {
                        alias,
                        group,
                        object,
                        final_group,
                        final_object,
                    }) => {
                        assert_eq!(*alias, ALIAS, "the report names another track's alias");
                        assert_eq!((*group, *object), at, "the report names another object");
                        assert_eq!(
                            (*final_group, *final_object),
                            end,
                            "the report names another place for the track to have ended"
                        );
                    }
                    other => panic!("expected a past-the-end report, got {other:?}"),
                }
            }

            /// A datagram arriving after the track's final Object withdraws
            /// from the track, and the peer reads the UNSUBSCRIBE naming the
            /// very request it answered.
            ///
            /// Four things, none implied by the others: the client reports the
            /// object and the end it was measured against, the session is not
            /// ended over it, an application that missed the error can still
            /// learn why the subscription stopped, and the peer sees the
            /// UNSUBSCRIBE.
            #[tokio::test]
            async fn a_datagram_past_the_final_object_withdraws_from_the_track() {
                crate::common::init_crypto();
                let (endpoint, addr) =
                    crate::common::spawn_server(&[DraftVersion::$version.quic_alpn()]);
                let served = tokio::spawn(peer(endpoint, Traffic::PastByObject));

                let conn = subscribed(&addr.to_string()).await;
                tokio::time::timeout(PATIENCE, conn.recv_datagram())
                    .await
                    .expect("the end-of-track datagram never arrived")
                    .expect("the datagram that ends the track is not itself a fault");
                let err = tokio::time::timeout(PATIENCE, conn.recv_datagram())
                    .await
                    .expect("the second datagram never arrived")
                    .err()
                    .expect(concat!(
                        "Section ",
                        $section,
                        " makes an Object past the track's final Object a malformed track, and \
                         the datagram was accepted"
                    ));
                assert_report(&err, (GROUP, 1), (GROUP, 0));
                assert!(
                    !conn.close_for_data_stream(&err),
                    concat!(
                        "Section ",
                        $section,
                        " answers this with an UNSUBSCRIBE rather than a close, but \
                         close_for_data_stream closed it"
                    )
                );
                assert_eq!(
                    conn.endpoint().malformed_track(&namespace(), TRACK),
                    Some(MalformedTrackCondition::ObjectPastFinalObject),
                    "an application that missed the error should still be able to learn why \
                     the subscription ended"
                );

                let (asked, seen) = tokio::time::timeout(PATIENCE * 3, served)
                    .await
                    .expect("peer task hung")
                    .unwrap();
                assert_eq!(
                    unsubscribed(&seen),
                    vec![asked],
                    concat!(
                        "Section ",
                        $section,
                        " asks a subscriber that detects a Malformed Track to UNSUBSCRIBE \
                         from it"
                    )
                );
            }

            /// An object in a later group is past the end whatever its Object
            /// ID, and the withdrawal waits for the caller to ask.
            ///
            /// The object is at Object ID 0 and the final Object is at Object
            /// ID 0 in the group before it, so neither number is larger than
            /// the other's counterpart: only the Location comparison the drafts
            /// define puts it past the end. Read field by field, this gate goes
            /// green with the rule removed.
            ///
            /// It carries the second half of the design as well. The fault is
            /// found by a stream holding no connection, so nothing is sent
            /// until `withdraw_for_data_stream` is called — which the gate
            /// checks by looking at the wire before it calls it.
            #[tokio::test]
            async fn a_later_group_is_past_the_end_whatever_its_object_id() {
                crate::common::init_crypto();
                let (endpoint, addr) =
                    crate::common::spawn_server(&[DraftVersion::$version.quic_alpn()]);
                let served = tokio::spawn(peer(endpoint, Traffic::PastByGroup));

                let conn = subscribed(&addr.to_string()).await;
                read_stream(&conn, GROUP, 1)
                    .await
                    .expect("the object that ends the track is not itself a fault");
                let err = read_stream(&conn, GROUP + 1, 1).await.err().expect(
                    "an Object in a later group is past the track's final Object, and it was \
                     accepted",
                );
                assert_report(&err, (GROUP + 1, 0), (GROUP, 0));
                assert!(
                    !conn.close_for_data_stream(&err),
                    concat!(
                        "Section ",
                        $section,
                        " answers this with an UNSUBSCRIBE rather than a close, but \
                         close_for_data_stream closed it"
                    )
                );
                assert!(
                    conn.withdraw_for_data_stream(&err).await,
                    "the fault a stream found is the one withdraw_for_data_stream answers"
                );

                let (asked, seen) = tokio::time::timeout(PATIENCE * 3, served)
                    .await
                    .expect("peer task hung")
                    .unwrap();
                assert_eq!(
                    unsubscribed(&seen),
                    vec![asked],
                    concat!(
                        "Section ",
                        $section,
                        " asks a subscriber that detects a Malformed Track to UNSUBSCRIBE \
                         from it"
                    )
                );
            }

            /// An object below where the track ended is accepted, and nothing
            /// is withdrawn.
            ///
            /// Streams arrive in whatever order the network gives them, so an
            /// object from an earlier group turning up after the end is
            /// ordinary rather than a fault. Without this gate a rule that
            /// fired on every object after the end would look exactly as
            /// correct as one that fires on the objects the draft names.
            #[tokio::test]
            async fn an_object_below_the_end_is_not_past_it() {
                crate::common::init_crypto();
                let (endpoint, addr) =
                    crate::common::spawn_server(&[DraftVersion::$version.quic_alpn()]);
                let served = tokio::spawn(peer(endpoint, Traffic::Below));

                let conn = subscribed(&addr.to_string()).await;
                read_stream(&conn, GROUP + 1, 2)
                    .await
                    .expect("the object that ends the track is not itself a fault");
                read_stream(&conn, GROUP, 1).await.expect(
                    "an Object below the track's final Object is not one the condition names",
                );
                assert_eq!(
                    conn.endpoint().malformed_track(&namespace(), TRACK),
                    None,
                    "nothing about this track is malformed"
                );

                let (_asked, seen) = tokio::time::timeout(PATIENCE * 3, served)
                    .await
                    .expect("peer task hung")
                    .unwrap();
                assert_eq!(
                    unsubscribed(&seen),
                    Vec::<u64>::new(),
                    "a track that ended and then carried an earlier Object was withdrawn from"
                );
            }
        }
    };
}

/// `ClientConfig`, in the three shapes these four drafts give it.
#[macro_export]
macro_rules! past_config {
    (early, $version:expr, $params:expr) => {
        ClientConfig {
            additional_versions: Vec::new(),
            transport: TransportType::Quic,
            skip_cert_verification: true,
            ca_certs: Vec::new(),
            setup_parameters: $params,
        }
    };
    (both, $version:expr, $params:expr) => {
        ClientConfig {
            draft: $version,
            additional_versions: Vec::new(),
            transport: TransportType::Quic,
            skip_cert_verification: true,
            ca_certs: Vec::new(),
            setup_parameters: $params,
        }
    };
    (late, $version:expr, $params:expr) => {
        ClientConfig {
            draft: $version,
            transport: TransportType::Quic,
            skip_cert_verification: true,
            ca_certs: Vec::new(),
            setup_parameters: $params,
        }
    };
}

/// SERVER_SETUP, with and without the Selected Version draft-15 dropped.
#[macro_export]
macro_rules! past_server_setup {
    (versioned, $version:expr, $params:expr) => {
        ServerSetup { selected_version: $version.version_varint(), parameters: $params }
    };
    (plain, $version:expr, $params:expr) => {
        ServerSetup { parameters: $params }
    };
}

/// SUBSCRIBE_OK, which is where the Track Alias travels on all five.
#[macro_export]
macro_rules! past_subscribe_ok {
    (rich, $id:expr, $alias:expr) => {
        SubscribeOk {
            request_id: $id,
            track_alias: $alias,
            expires: VarInt::from_u64(0).unwrap(),
            group_order: GroupOrder::Ascending,
            content_exists: ContentExists::NoLargestLocation,
            largest_location: None,
            parameters: Vec::new(),
        }
    };
    (plain, $id:expr, $alias:expr) => {
        SubscribeOk { request_id: $id, track_alias: $alias, parameters: Vec::new() }
    };
    // Draft-16 adds Track Extensions after the parameters. Empty here: this
    // rule is about where a track ended, and an extension block says nothing
    // about that.
    (extensions, $id:expr, $alias:expr) => {
        SubscribeOk {
            request_id: $id,
            track_alias: $alias,
            parameters: Vec::new(),
            track_extensions: Vec::new(),
        }
    };
}

/// `Connection::subscribe`, in the three shapes these four drafts give it.
#[macro_export]
macro_rules! past_subscribe {
    (varint, $conn:expr, $ns:expr, $name:expr) => {
        $conn.subscribe(
            $ns,
            $name.to_vec(),
            128,
            moqtap_codec::types::GroupOrder::Ascending,
            VarInt::from_u64(0x2).unwrap(),
            Vec::new(),
        )
    };
    (filter, $conn:expr, $ns:expr, $name:expr) => {
        $conn.subscribe(
            $ns,
            $name.to_vec(),
            128,
            moqtap_codec::types::GroupOrder::Ascending,
            moqtap_codec::types::FilterType::LargestObject,
            Vec::new(),
        )
    };
    (params, $conn:expr, $ns:expr, $name:expr) => {
        $conn.subscribe($ns, $name.to_vec(), Vec::new())
    };
}

/// One subgroup stream's bytes: the header, then every object on it.
///
/// Three shapes rather than four, and the split is not where the header's is.
/// Drafts 12 and 13 write an object's Object ID as itself; drafts 14 and 15
/// delta-encode it against the object before, so their objects go through a
/// writer that carries the state rather than being encoded one at a time.
#[macro_export]
macro_rules! past_stream_bytes {
    (explicit, $draft:ident, $version:ident, $alias:expr, $group:expr, $objects:expr) => {{
        let header = moqtap_codec::$draft::data_stream::SubgroupHeader {
            stream_type: moqtap_codec::$draft::data_stream::StreamType::SubgroupExplicit,
            track_alias: $alias,
            group_id: $group,
            subgroup_id: VarInt::from_usize(0),
            publisher_priority: 128,
        };
        let mut buf = Vec::new();
        moqtap_codec::dispatch::AnySubgroupHeader::$version(header)
            .encode_stream_checked(&mut buf)
            .expect("encode the subgroup header");
        for (object, status) in $objects {
            moqtap_codec::$draft::data_stream::ObjectHeader {
                object_id: VarInt::from_u64(*object).unwrap(),
                extension_headers_length: VarInt::from_usize(0),
                extensions: Vec::new(),
                payload_length: VarInt::from_usize(0),
                object_status: *status,
            }
            .encode(&mut buf);
        }
        buf
    }};
    (flags, $draft:ident, $version:ident, $alias:expr, $group:expr, $objects:expr) => {{
        let header = moqtap_codec::$draft::data_stream::SubgroupHeader {
            stream_type: moqtap_codec::$draft::data_stream::SubgroupStreamType::from_flags(
                true, false, false, false,
            ),
            track_alias: $alias,
            group_id: $group,
            subgroup_id: Some(VarInt::from_usize(0)),
            publisher_priority: 128,
        };
        let mut writer = moqtap_codec::$draft::data_stream::SubgroupObjectReader::new(&header);
        let mut buf = Vec::new();
        moqtap_codec::dispatch::AnySubgroupHeader::$version(header)
            .encode_stream_checked(&mut buf)
            .expect("encode the subgroup header");
        for (object, status) in $objects {
            writer
                .write_object(
                    &moqtap_codec::$draft::data_stream::SubgroupObject {
                        object_id: VarInt::from_u64(*object).unwrap(),
                        extension_headers: Vec::new(),
                        status: Some(*status),
                        payload: Vec::new(),
                    },
                    &mut buf,
                )
                .expect("write the object");
        }
        buf
    }};
    (byte, $draft:ident, $version:ident, $alias:expr, $group:expr, $objects:expr) => {{
        let header = moqtap_codec::$draft::data_stream::SubgroupHeader {
            // The subgroup base (0x10) with the explicit Subgroup ID bit
            // (0x04): no extensions, no end-of-group, priority present.
            header_type: 0x14,
            track_alias: $alias,
            group_id: $group,
            subgroup_id: VarInt::from_usize(0),
            publisher_priority: Some(128),
        };
        let mut writer = moqtap_codec::$draft::data_stream::SubgroupObjectReader::new(&header);
        let mut buf = Vec::new();
        moqtap_codec::dispatch::AnySubgroupHeader::$version(header)
            .encode_stream_checked(&mut buf)
            .expect("encode the subgroup header");
        for (object, status) in $objects {
            writer
                .write_object(
                    &moqtap_codec::$draft::data_stream::SubgroupObject {
                        object_id: VarInt::from_u64(*object).unwrap(),
                        extension_headers: Vec::new(),
                        payload_length: VarInt::from_usize(0),
                        object_status: Some(*status),
                        payload: Vec::new(),
                    },
                    &mut buf,
                )
                .expect("write the object");
        }
        buf
    }};
}

/// A datagram stating the end of the track, in the three shapes these four
/// drafts give one.
#[macro_export]
macro_rules! past_status_datagram {
    (grouped, $draft:ident, $version:ident, $alias:expr, $group:expr, $object:expr) => {{
        let header = moqtap_codec::$draft::data_stream::Datagram::Status(
            moqtap_codec::$draft::data_stream::DatagramStatusHeader {
                track_alias: $alias,
                group_id: $group,
                object_id: $object,
                publisher_priority: 128,
                extension_headers_length: VarInt::from_usize(0),
                extensions: Vec::new(),
                object_status: ObjectStatus::EndOfTrack,
            },
        );
        let mut buf = Vec::new();
        moqtap_codec::dispatch::AnyDatagramHeader::$version(header)
            .encode(&mut buf)
            .expect("encode the datagram");
        buf
    }};
    (typed, $draft:ident, $version:ident, $alias:expr, $group:expr, $object:expr) => {{
        let header = moqtap_codec::$draft::data_stream::DatagramObject {
            datagram_type: moqtap_codec::$draft::data_stream::DatagramType::status(false),
            track_alias: $alias,
            group_id: $group,
            object_id: $object,
            publisher_priority: 128,
            extension_headers: Vec::new(),
            status: Some(ObjectStatus::EndOfTrack),
            payload: Vec::new(),
        };
        let mut buf = Vec::new();
        moqtap_codec::dispatch::AnyDatagramHeader::$version(header)
            .encode(&mut buf)
            .expect("encode the datagram");
        buf
    }};
    (byte, $draft:ident, $version:ident, $alias:expr, $group:expr, $object:expr) => {{
        let header = moqtap_codec::$draft::data_stream::DatagramHeader {
            // The status bit (0x20), the Object ID written, the priority
            // present, and no extensions.
            datagram_type: 0x20,
            track_alias: $alias,
            group_id: $group,
            object_id: $object,
            publisher_priority: Some(128),
            extension_headers: Vec::new(),
            object_status: Some(ObjectStatus::EndOfTrack),
        };
        let mut buf = Vec::new();
        moqtap_codec::dispatch::AnyDatagramHeader::$version(header)
            .encode(&mut buf)
            .expect("encode the datagram");
        buf
    }};
}

/// A conforming payload datagram, in the three shapes these four drafts give
/// one. Every one carries no extensions and an empty payload, so nothing about
/// it can be refused for a reason that is not this rule.
#[macro_export]
macro_rules! past_payload_datagram {
    (grouped, $draft:ident, $version:ident, $alias:expr, $group:expr, $object:expr) => {{
        let header = moqtap_codec::$draft::data_stream::Datagram::Payload(
            moqtap_codec::$draft::data_stream::DatagramHeader {
                track_alias: $alias,
                group_id: $group,
                object_id: $object,
                publisher_priority: 128,
                extension_headers_length: VarInt::from_usize(0),
                extensions: Vec::new(),
                end_of_group: false,
            },
        );
        let mut buf = Vec::new();
        moqtap_codec::dispatch::AnyDatagramHeader::$version(header)
            .encode(&mut buf)
            .expect("encode the datagram");
        buf
    }};
    (typed, $draft:ident, $version:ident, $alias:expr, $group:expr, $object:expr) => {{
        let header = moqtap_codec::$draft::data_stream::DatagramObject {
            datagram_type: moqtap_codec::$draft::data_stream::DatagramType::payload(
                true, false, false,
            ),
            track_alias: $alias,
            group_id: $group,
            object_id: $object,
            publisher_priority: 128,
            extension_headers: Vec::new(),
            status: None,
            payload: Vec::new(),
        };
        let mut buf = Vec::new();
        moqtap_codec::dispatch::AnyDatagramHeader::$version(header)
            .encode(&mut buf)
            .expect("encode the datagram");
        buf
    }};
    (byte, $draft:ident, $version:ident, $alias:expr, $group:expr, $object:expr) => {{
        let header = moqtap_codec::$draft::data_stream::DatagramHeader {
            // A payload datagram with the Object ID written, the priority
            // present, no extensions and no status.
            datagram_type: 0x00,
            track_alias: $alias,
            group_id: $group,
            object_id: $object,
            publisher_priority: Some(128),
            extension_headers: Vec::new(),
            object_status: None,
        };
        let mut buf = Vec::new();
        moqtap_codec::dispatch::AnyDatagramHeader::$version(header)
            .encode(&mut buf)
            .expect("encode the datagram");
        buf
    }};
}

past_the_end_gates!(
    draft12, "draft12", Draft12, early, versioned, rich, varint, explicit, grouped, "2.5"
);
past_the_end_gates!(
    draft13, "draft13", Draft13, early, versioned, rich, filter, explicit, grouped, "2.5"
);
past_the_end_gates!(
    draft14, "draft14", Draft14, both, versioned, rich, filter, flags, typed, "2.5"
);
past_the_end_gates!(draft15, "draft15", Draft15, late, plain, plain, params, byte, byte, "2.4.2");
past_the_end_gates!(
    draft16, "draft16", Draft16, late, plain, extensions, params, byte, byte, "2.4.2"
);

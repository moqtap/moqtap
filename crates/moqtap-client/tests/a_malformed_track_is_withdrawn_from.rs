#![cfg(any(feature = "draft12", feature = "draft13", feature = "draft14", feature = "draft15"))]

//! A track a receiver finds malformed is given up, on the four drafts whose
//! answer to one is a control message.
//!
//! Draft-12 Section 2.5 defines the fault and answers it in one place: "There
//! are multiple ways a publisher can transmit a Track that does not conform to
//! MoQT constraints. Such a Track is considered malformed", then eleven
//! example conditions, then "The above list of conditions is not considered
//! exhaustive", and then the answer to all of them — "When a subscriber
//! detects a Malformed Track, it MUST UNSUBSCRIBE from the Track and SHOULD
//! deliver an error to the application." Draft-13 repeats it word for word.
//!
//! Drafts 14 and 15 widen the same sentence to the other kind of request: "it
//! MUST UNSUBSCRIBE any subscription and FETCH_CANCEL any fetch for that Track
//! from that publisher, and SHOULD deliver an error to the application."
//!
//! # Which drafts are here, and why not the ones next to them
//!
//! Checked with `re.finditer` over the raw HTML of all thirteen drafts, the
//! section carries three answers and no draft carries two of them: drafts 12
//! and 13 have the UNSUBSCRIBE above; drafts 14, 15 and 16 add the
//! FETCH_CANCEL; and drafts 17, 18 and 19 replace the messages with a
//! cross-reference — "it MUST cancel any corresponding subscription or fetches
//! for that Track from that publisher" — where cancelling a request is a
//! transport operation on the request's own stream. Drafts 07 through 11 have
//! no Malformed Tracks section at all, and draft-11 is the one worth naming:
//! it asks for a track to be treated as Malformed in Section 7.1 and never
//! says anywhere what that costs.
//!
//! **Draft-16 states this file's sentence and is not in this file**, which is
//! the one place the range of the answer and the range of the gates come
//! apart. The condition every gate here fires is a track framed two ways, and
//! draft-16 withdrew the rule that makes that a fault: Section 10.2.1 there
//! replaced draft-15's "the Original Publisher determines the Forwarding
//! Preference for the entire Track" with "Object Forwarding Preference is a
//! property of an individual Object and can vary among Objects in the same
//! Track", and its own Malformed Tracks bullet lost its scope in the same
//! draft, becoming "An Object is received with a different Forwarding
//! Preference than previously observed" where draft-15 has "... than
//! previously observed from the same Track". So on draft-16 this crate keeps
//! no forwarding-preference record to contradict, and the answer there needs a
//! condition this crate can still detect. **A rule and its answer have
//! separate ranges, and the gates can only run where both hold.**
//!
//! **Draft-16's answer is gated now, and elsewhere.**
//! `an_object_after_the_track_ends_is_a_malformed_track.rs` fires the
//! final-Object condition, which is stated unchanged from draft-12 through
//! draft-19 and rests on nothing draft-16 moved. That file reaches draft-16
//! and this one still cannot, which is the same statement made twice: the
//! range of a gate is the range of its *condition*, and the answer these two
//! files share is wider than either.
//!
//! # Which condition these gates fire
//!
//! One of them — eleven on drafts 12 and 13, nine on 14 and 15, counted off
//! the list itself: "An Object is received with a different Forwarding
//! Preference than previously observed from the same Track." It is the
//! condition this crate detects, because the framing an object arrived in is
//! visible without keeping the objects — a subgroup stream's header settles a
//! track's preference and a datagram for the same track disagrees with it.
//!
//! The others are not gated here and are not silently assumed. Several are
//! about orderings within a subgroup or a fetch, and one of the two that leave
//! at draft-14 leaves because it stopped being expressible: an Object ID that
//! does not strictly increase within a subgroup, on a draft where subgroup
//! Object IDs became deltas. What matters for this file is that the answer is
//! stated once for the whole list, so a gate on one condition measures the
//! answer rather than the condition.
//!
//! # A track is given up and the session is not
//!
//! Every gate here asserts that too, because it is the half of the sentence
//! that is easiest to get wrong in the direction that destroys a session. The
//! drafts' close table sits three sections away with a Protocol Violation code
//! in it, and nothing in the Malformed Tracks section points at it.
//!
//! # Both ways a subscriber holds a track
//!
//! Section 4.1 — 5.1 from draft-14 — gives this endpoint a subscription two
//! ways round: one it asked for with SUBSCRIBE, and one the peer offered with
//! PUBLISH and it accepted. Both end with UNSUBSCRIBE, so both are withdrawn
//! and both are gated. A third way of naming a track is not a subscription of
//! this endpoint's at all — a peer subscribing to it makes it the publisher —
//! and a publisher has nothing to withdraw from.
//!
//! # The fetch half, and the record it took
//!
//! A fetch is the other way this endpoint receives a track, and on drafts 14
//! and 15 the sentence names it. Finding one took a record this crate did not
//! have: `fetch()` put the namespace and the name into the message and kept a
//! state machine under the Request ID and nothing else, so nothing here knew
//! which track a fetch was for. The endpoint now writes the track down as the
//! fetch is made, in a table of its own rather than in the alias table beside
//! it — a fetch never holds a Track Alias, because its objects arrive on a
//! stream that opens by naming the Request ID.
//!
//! **And one fetch names no track at all.** A Joining Fetch identifies itself
//! by the subscription it joins. Draft-14 Section 9.16.2 and
//! draft-15 Section 9.16.2 word it the same way, and have the publisher use
//! "properties of the associated Subscribe to determine the Track Namespace,
//! Track Name and End Location". So its track is the joined
//! subscription's, and the endpoint resolves it once, when the fetch is made.
//! The alternative — resolving it at the withdrawal, through the request it
//! joined — fails in exactly the case a Joining Fetch exists for: the fetch
//! outlives the subscription, so the lookup comes up empty precisely when
//! there is still a fetch to cancel. The last gate here is that gate.
//!
//! It ran on draft-15 alone to begin with, and the reason was a gap rather
//! than a difference between the drafts: draft-14 states the rule and this
//! crate had no way to send the message. It has one now, so the gate runs on
//! both. **A per-draft module that is missing a method looks exactly like a
//! draft that does not have the feature**, and what tells the two apart is
//! reading the draft rather than the module beside it.
//!
//! # What makes the answer happen once
//!
//! Not a memo. The requests the withdrawal ends are ended by it, and a request
//! that has ended has no second ending in it, so a publisher that goes on
//! mixing a track's framing is answered once however many objects it sends.
//! One gate sends the offending object twice to assert that.
//!
//! Which leaves the case where a memo and a state machine give different
//! answers, and it has a gate of its own: an application that subscribes to
//! the same track *again*. That request has never been withdrawn from, and a
//! publisher mixing the framing again has broken the sentence again, so the
//! second subscription is withdrawn from too. A record that recognised the
//! track and declined would leave it running.
//!
//! # Why a writer owes nothing
//!
//! "When a subscriber detects" is the whole of the reason. The same crate
//! detects the same condition on the two paths where it is about to *send* an
//! object, and answers it there by refusing to send: an endpoint writing an
//! object is that object's Original Publisher, which is who the mixing rule
//! binds, and a publisher has no subscription of its own to give up and no
//! fetch of its own to cancel. One gate settles a track on datagrams, is
//! refused the subgroup stream that would mix it, and asserts the peer's
//! control stream stayed empty.
//!
//! # Why every gate carries the subscription through to its answer
//!
//! The rule is reached by resolving an object's Track Alias to a track, and
//! from draft-12 the alias travels in the SUBSCRIBE_OK rather than in the
//! SUBSCRIBE. A gate that sent the two framings without waiting for the answer
//! would have an alias that names nothing, the condition would never fire, and
//! it would pass against a tree with the rule and against one without it.
//!
//! # Ablations, measured
//!
//! Twelve cuts, each applied to the working tree, run under the draft it
//! names, and reverted with the file compared byte for byte afterwards. They are
//! spread over all four drafts on purpose: each draft carries the sentence
//! through a module of its own, so a cut that only ever landed on one of them
//! would say nothing about the others.
//!
//! Dropping the withdrawal from draft-12's receiving path, so the condition is
//! reported and nothing is sent:
//!
//! ```text
//! assertion `left == right` failed: an application that missed the error should still be able to learn why the subscription ended
//!   left: None
//!  right: Some(MixedForwardingPreference)
//! assertion `left == right` failed: Section 2.5 asks for an UNSUBSCRIBE from the Track, not for one per offending Object
//!   left: []
//!  right: [0]
//! assertion `left == right` failed: a subscription the peer opened with PUBLISH ends with UNSUBSCRIBE too
//!   left: []
//!  right: [1]
//! the second answer never arrived: Elapsed(())
//! ```
//!
//! Four gates, and the last of them fails by waiting rather than by asserting.
//! Its peer reads one message after the traffic, expecting the withdrawal, and
//! gets the client's second SUBSCRIBE instead — so it answers nothing and the
//! client waits for an alias that is never bound. A gate whose peer is a state
//! machine fails where the conversation stops making sense, which is not
//! always where the claim is.
//!
//! Making the record refuse a second withdrawal for a track it recognises, in
//! draft-13's endpoint, which is the design this file settles:
//!
//! ```text
//! the withdrawal never arrived: Elapsed(())
//! ```
//!
//! One gate, and only one — every other gate withdraws from a track exactly
//! once, so a record that declines the second time is invisible to all of
//! them. That is the whole argument for that gate existing.
//!
//! Routing draft-12's `open_subgroup_stream` through the receiving path's
//! check, so an endpoint withdraws from a track it was writing:
//!
//! ```text
//! a publisher has no subscription of its own to give up: [Draft12(Unsubscribe(Unsubscribe { request_id: VarInt(0) }))]
//! ```
//!
//! Dropping the record entirely from draft-13's endpoint, keeping the
//! UNSUBSCRIBE:
//!
//! ```text
//! assertion `left == right` failed: an application that missed the error should still be able to learn why the subscription ended
//!   left: None
//!  right: Some(MixedForwardingPreference)
//! ```
//!
//! Giving draft-12's close table an arm for the condition, which is the worst
//! answer within reach and the one a Protocol Violation code three sections
//! away invites:
//!
//! ```text
//! Section 2.5 answers this with an UNSUBSCRIBE rather than a close, but close_for_data_stream closed it
//! ```
//!
//! And withdrawing on every object rather than on the offending one, in
//! draft-13's receiving path:
//!
//! ```text
//! assertion `left == right` failed: nothing about this track is malformed
//!   left: Some(MixedForwardingPreference)
//!  right: None
//! Section 2.5 makes a second framing for one track a malformed track, and the datagram was accepted
//! the second framing should be reported: (Draft13(Payload(DatagramHeader { track_alias: VarInt(7), ... })), b"")
//! ```
//!
//! Five gates, and four of them fail for a reason worth reading twice. The
//! subgroup stream is the track's *first* framing, so an endpoint that
//! withdraws on it has ended the subscription before the datagram arrives, and
//! the datagram then names an alias that resolves to nothing. Withdrawing too
//! eagerly does not only withdraw too much: it stops the rule from being
//! reachable at all. Only the acceptance gate reports what the cut did.
//!
//! ## And four for the half the fetch adds
//!
//! Leaving the fetches out of draft-14's scan, so the withdrawal searches the
//! alias table and nothing else:
//!
//! ```text
//! assertion `left == right` failed: Section 2.5 asks for a FETCH_CANCEL for any fetch for that Track, and the fetch was left running
//!   left: []
//!  right: [2]
//! ```
//!
//! Ending draft-14's fetch with the subscription's message instead of its own,
//! which is the mistake a shared scan invites and the one a shared `Vec` of
//! control messages cannot catch by typing:
//!
//! ```text
//! assertion `left == right` failed: Section 2.5 asks for an UNSUBSCRIBE for any subscription
//!   left: [0, 2]
//!  right: [0]
//! ```
//!
//! The gate that goes red there is the UNSUBSCRIBE half rather than the
//! FETCH_CANCEL half, and the list is what says why: the fetch's Request ID
//! turned up among the subscriptions. **A gate that only counted the messages
//! would have been happy**, which is why both halves name their Request IDs.
//!
//! Cancelling every live fetch rather than the malformed track's, in
//! draft-15's scan:
//!
//! ```text
//! Section 2.4.2 names the fetches for *that* Track, and a fetch for another one was cancelled: [Draft15(Unsubscribe(Unsubscribe { request_id: VarInt(0) })), Draft15(FetchCancel(FetchCancel { request_id: VarInt(2) }))]
//! ```
//!
//! And dropping the resolution through the join, so a Joining Fetch leaves no
//! track behind — the design this file settled and the one it could have got
//! wrong:
//!
//! ```text
//! assertion `left == right` failed: Section 2.4.2 names any fetch for that Track, and a Joining Fetch's track is the one it joined
//!   left: []
//!  right: [2]
//! ```
//!
//! One gate each, and that is the point of the four being four: the record,
//! the message it produces, the key it is read by, and the one fetch that has
//! no key of its own are four separate claims, and no cut takes down more than
//! the one it is about.
//!
//! ## And two more when the joining gate reached a second draft
//!
//! Dropping the resolution through the join out of draft-14's sender, which is
//! the draft-15 cut above made against a second module rather than the same
//! one twice:
//!
//! ```text
//! assertion `left == right` failed: Section 2.5 names any fetch for that Track, and a Joining Fetch's track is the one it joined
//!   left: []
//!  right: [2]
//! ```
//!
//! And letting draft-14's wrapper allocate the request without writing the
//! FETCH, which is the failure a new sender is likeliest to ship with:
//!
//! ```text
//! the peer's data stream never arrived: Elapsed(())
//! ```
//!
//! The same gate goes red both times and it fails at different points, which
//! is the reason it reads the FETCH off the wire before it sends any traffic:
//! with no FETCH to read, the peer never gets as far as the objects, and what
//! the gate reports is where the conversation stopped rather than what was
//! wrong with the answer.

mod common;

/// One draft's loopback gates.
macro_rules! withdrawal_gates {
    ($draft:ident, $feat:literal, $version:ident, $cfg:tt, $setup:tt, $sub:tt, $ok:tt,
     $accept:tt, $hdr:tt, $dgram:tt, $fetches:tt, $join:tt, $sig:tt, $section:literal) => {
        #[cfg(feature = $feat)]
        mod $draft {
            use std::time::Duration;

            use moqtap_client::forwarding_preference::ObjectForwardingPreference as Pref;
            use moqtap_client::malformed_tracks::MalformedTrackCondition;
            use moqtap_client::$draft::connection::{
                ClientConfig, Connection, ConnectionError, TransportType,
            };
            use moqtap_client::$draft::endpoint::EndpointError;
            use moqtap_codec::dispatch::{AnyControlMessage, AnyDatagramHeader, AnySubgroupHeader};
            use moqtap_codec::kvp::{KeyValuePair, KvpValue};
            use moqtap_codec::types::TrackNamespace;
            #[allow(unused_imports)]
            use moqtap_codec::types::{ContentExists, Forward, GroupOrder};
            use moqtap_codec::varint::VarInt;
            use moqtap_codec::version::DraftVersion;
            use moqtap_codec::$draft::message::{
                ControlMessage, Publish, ServerSetup, SubscribeOk,
            };

            const PATIENCE: Duration = Duration::from_secs(10);

            /// Long enough that a message on its way would have arrived, short
            /// enough that a gate expecting none does not sit on it.
            const BRIEF: Duration = Duration::from_millis(400);

            /// The alias the track is known by on the wire.
            const ALIAS: u64 = 7;

            const TRACK: &[u8] = b"one-track";

            const GROUP_ID: u64 = 3;
            const OBJECT_ID: u64 = 0;

            /// The peer's first Request ID: odd, because this endpoint is the
            /// client and the peer is the server.
            const PEERS_FIRST: u64 = 1;

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
                crate::withdrawal_config!($cfg, DraftVersion::$version, setup_parameters())
            }

            fn server_setup() -> ServerSetup {
                crate::withdrawal_server_setup!($setup, DraftVersion::$version, setup_parameters())
            }

            fn encode(msg: ControlMessage) -> Vec<u8> {
                let mut out = Vec::new();
                AnyControlMessage::$version(msg).encode(&mut out).expect("encode");
                out
            }

            /// The Request ID a SUBSCRIBE carried, or a panic naming what
            /// arrived instead.
            fn subscribe_id(msg: &AnyControlMessage) -> VarInt {
                match msg {
                    AnyControlMessage::$version(ControlMessage::Subscribe(s)) => s.request_id,
                    other => panic!("expected a SUBSCRIBE from the client, got {other:?}"),
                }
            }

            /// SUBSCRIBE_OK carrying the alias, which is what binds it.
            fn subscribe_ok(id: VarInt) -> ControlMessage {
                ControlMessage::SubscribeOk(crate::withdrawal_subscribe_ok!($ok, id, v(ALIAS)))
            }

            /// The peer's offer of the same track, which opens a subscription
            /// the other way round.
            fn publish() -> ControlMessage {
                ControlMessage::Publish(crate::withdrawal_publish!(
                    $ok,
                    v(PEERS_FIRST),
                    namespace(),
                    TRACK,
                    v(ALIAS)
                ))
            }

            /// A conforming subgroup header, which settles the track's framing.
            fn subgroup_stream_bytes(group: u64) -> Vec<u8> {
                let header = crate::withdrawal_subgroup_header!($hdr, $draft, v(ALIAS), v(group));
                let mut buf = Vec::new();
                AnySubgroupHeader::$version(header)
                    .encode_stream_checked(&mut buf)
                    .expect("encode the subgroup header");
                buf
            }

            /// A datagram for the same track — the second framing, and the
            /// whole of what the condition names.
            fn datagram_bytes(object: u64) -> Vec<u8> {
                let header =
                    crate::withdrawal_datagram!($dgram, $draft, v(ALIAS), v(GROUP_ID), v(object));
                let mut buf = Vec::new();
                AnyDatagramHeader::$version(header).encode(&mut buf).expect("encode the datagram");
                buf
            }

            /// What the peer sends once the track is bound.
            #[derive(Debug, Clone, Copy)]
            enum Traffic {
                /// A subgroup stream and then a datagram: two framings for one
                /// track.
                Mixed,
                /// The same, and one more datagram after the withdrawal.
                MixedTwice,
                /// Two subgroup streams — one framing throughout, and nothing
                /// to answer.
                OneFraming,
                /// Nothing. The client is the one that writes.
                Silent,
            }

            /// Send one framing, or two, or none.
            async fn send_traffic(conn: &quinn::Connection, traffic: Traffic) {
                match traffic {
                    Traffic::Silent => {}
                    Traffic::OneFraming => {
                        for group in [GROUP_ID, GROUP_ID + 1] {
                            let mut data = conn.open_uni().await.expect("open the data stream");
                            data.write_all(&subgroup_stream_bytes(group))
                                .await
                                .expect("write the subgroup header");
                            data.finish().expect("finish the data stream");
                        }
                    }
                    Traffic::Mixed | Traffic::MixedTwice => {
                        let mut data = conn.open_uni().await.expect("open the data stream");
                        data.write_all(&subgroup_stream_bytes(GROUP_ID))
                            .await
                            .expect("write the subgroup header");
                        data.finish().expect("finish the data stream");
                        conn.send_datagram(datagram_bytes(OBJECT_ID).into())
                            .expect("send the datagram");
                        if matches!(traffic, Traffic::MixedTwice) {
                            conn.send_datagram(datagram_bytes(OBJECT_ID + 1).into())
                                .expect("send the second datagram");
                        }
                    }
                }
            }

            /// Everything that arrives on the control stream until it goes
            /// quiet.
            ///
            /// A gate expecting one message and a gate expecting none read the
            /// same way, which is what makes the second kind worth having: it
            /// waits exactly as long for a message that is not coming as the
            /// first waits for one that is.
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

            /// Serve one connection to a client that subscribes: complete the
            /// setup, answer the SUBSCRIBE with the alias, send the traffic,
            /// and report the Request ID it asked under together with whatever
            /// came back on the control stream.
            async fn subscribing_peer(
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

            /// Serve one connection to a client that never subscribes: offer
            /// the track with PUBLISH, wait for the acceptance, and mix the
            /// framing.
            async fn publishing_peer(server: quinn::Endpoint) -> Vec<AnyControlMessage> {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");
                let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
                let mut framed = crate::common::frame_uni_recv(recv, DraftVersion::$version);
                framed.read_control(false).await.expect("read CLIENT_SETUP");
                send.write_all(&encode(ControlMessage::ServerSetup(server_setup())))
                    .await
                    .expect("write SERVER_SETUP");

                send.write_all(&encode(publish())).await.expect("write PUBLISH");
                framed.read_control(false).await.expect("read PUBLISH_OK");

                send_traffic(&conn, Traffic::Mixed).await;
                let seen = drain_control!(framed);
                still_running(&conn).await;
                seen
            }

            /// Serve one connection to a client that subscribes to the same
            /// track twice, mixing the framing under each subscription.
            async fn resubscribing_peer(server: quinn::Endpoint) -> (Vec<u64>, Vec<u64>) {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");
                let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
                let mut framed = crate::common::frame_uni_recv(recv, DraftVersion::$version);
                framed.read_control(false).await.expect("read CLIENT_SETUP");
                send.write_all(&encode(ControlMessage::ServerSetup(server_setup())))
                    .await
                    .expect("write SERVER_SETUP");

                let mut asked = Vec::new();
                let mut withdrew = Vec::new();
                for round in 0..2u8 {
                    let (request, _) = framed.read_control(false).await.expect("read SUBSCRIBE");
                    let id = subscribe_id(&request);
                    asked.push(id.into_inner());
                    send.write_all(&encode(subscribe_ok(id))).await.expect("write SUBSCRIBE_OK");
                    // The track's framing is settled for the whole session by
                    // the first stream, so the second round needs only the
                    // datagram that disagrees with it.
                    if round == 0 {
                        send_traffic(&conn, Traffic::Mixed).await;
                    } else {
                        conn.send_datagram(datagram_bytes(OBJECT_ID + 1).into())
                            .expect("send the datagram");
                    }
                    // Exactly one message, rather than everything until the
                    // stream goes quiet. The client's second SUBSCRIBE
                    // follows the first withdrawal closely enough that a
                    // drain would swallow it, and then the round below would
                    // wait for a request that had already arrived.
                    let (answer, _) = tokio::time::timeout(PATIENCE, framed.read_control(false))
                        .await
                        .expect("the withdrawal never arrived")
                        .expect("read the UNSUBSCRIBE");
                    withdrew.extend(unsubscribed(&[answer]));
                }
                still_running(&conn).await;
                (asked, withdrew)
            }

            /// The session outlived the withdrawal, which is the half of the
            /// sentence that is easiest to get wrong in the direction that
            /// destroys a session.
            async fn still_running(conn: &quinn::Connection) {
                if let Ok(reason) = tokio::time::timeout(BRIEF, conn.closed()).await {
                    panic!(
                        concat!(
                            "Section ",
                            $section,
                            " answers a Malformed Track by giving up the track, but the \
                             session ended: {:?}"
                        ),
                        reason
                    );
                }
            }

            /// The report the mixing produces, with both framings named.
            fn assert_report(err: &ConnectionError, framings: (Pref, Pref)) {
                match err {
                    ConnectionError::Endpoint(EndpointError::MixedForwardingPreference {
                        alias,
                        established,
                        offered,
                    }) => {
                        assert_eq!(*alias, ALIAS, "the report should name the alias it arrived on");
                        assert_eq!(
                            (*established, *offered),
                            framings,
                            "the report should name the framing the track settled on and the \
                             one that disagreed with it"
                        );
                    }
                    other => panic!("expected a mixed-framing report, got {other:?}"),
                }
            }

            /// Connect, subscribe, and read the answer that carries the alias.
            ///
            /// The Request ID comes back with the connection because a Joining
            /// Fetch is made by naming it, and the gate that makes one is the
            /// only reader of it.
            async fn subscribed(addr: &str) -> (Connection, VarInt) {
                let mut conn =
                    tokio::time::timeout(PATIENCE, Connection::connect(addr, client_config()))
                        .await
                        .expect("connect did not finish")
                        .expect("connect");
                let id = crate::withdrawal_subscribe!($sub, conn, namespace(), TRACK)
                    .await
                    .expect("subscribe");
                tokio::time::timeout(PATIENCE, conn.recv_and_dispatch())
                    .await
                    .expect("the answer carrying the alias never arrived")
                    .expect("dispatch SUBSCRIBE_OK");
                (conn, id)
            }

            /// Read the peer's subgroup stream, then its datagram, and give
            /// back what the datagram produced.
            async fn read_both_framings(
                conn: &Connection,
            ) -> Result<(AnyDatagramHeader, bytes::Bytes), ConnectionError> {
                let (header, _stream) =
                    tokio::time::timeout(PATIENCE, conn.accept_subgroup_stream())
                        .await
                        .expect("the peer's data stream never arrived")
                        .expect("read the subgroup header");
                assert_eq!(
                    header.track_alias(),
                    ALIAS,
                    "the header that came back is not the one the peer sent"
                );
                tokio::time::timeout(PATIENCE, conn.recv_datagram())
                    .await
                    .expect("the peer's datagram never arrived")
            }

            /// A track whose objects arrive framed two ways is unsubscribed
            /// from, and the peer reads the UNSUBSCRIBE naming the very
            /// request it answered.
            ///
            /// Three things, none implied by the others: the client reports
            /// the mixing with both framings named, the peer sees an
            /// UNSUBSCRIBE for the subscription it granted, and the session is
            /// still standing afterwards.
            #[tokio::test]
            async fn a_mixed_track_is_unsubscribed_from() {
                crate::common::init_crypto();
                let (endpoint, addr) =
                    crate::common::spawn_server(&[DraftVersion::$version.quic_alpn()]);
                let peer = tokio::spawn(subscribing_peer(endpoint, Traffic::Mixed));

                let (conn, _) = subscribed(&addr.to_string()).await;
                let arrival = read_both_framings(&conn).await;
                let err = arrival.as_ref().err().unwrap_or_else(|| {
                    panic!(concat!(
                        "Section ",
                        $section,
                        " makes a second framing for one track a malformed track, and the \
                         datagram was accepted"
                    ))
                });
                assert_report(err, (Pref::Subgroup, Pref::Datagram));
                assert!(
                    !conn.close_for_data_stream(err),
                    concat!(
                        "Section ",
                        $section,
                        " answers this with an UNSUBSCRIBE rather than a close, but \
                         close_for_data_stream closed it"
                    )
                );
                assert_eq!(
                    conn.endpoint().malformed_track(&namespace(), TRACK),
                    Some(MalformedTrackCondition::MixedForwardingPreference),
                    "an application that missed the error should still be able to learn why \
                     the subscription ended"
                );

                let (asked, seen) = tokio::time::timeout(PATIENCE * 3, peer)
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

            /// A publisher that goes on mixing the framing is answered once.
            ///
            /// The second datagram is not accepted quietly either: by then the
            /// subscription that gave the alias its meaning has ended, so the
            /// objects name a track this endpoint no longer holds. What the
            /// gate measures is the wire, where exactly one UNSUBSCRIBE has
            /// been sent for one track.
            #[tokio::test]
            async fn the_withdrawal_is_sent_once() {
                crate::common::init_crypto();
                let (endpoint, addr) =
                    crate::common::spawn_server(&[DraftVersion::$version.quic_alpn()]);
                let peer = tokio::spawn(subscribing_peer(endpoint, Traffic::MixedTwice));

                let (conn, _) = subscribed(&addr.to_string()).await;
                let err = read_both_framings(&conn).await;
                assert_report(
                    err.as_ref().expect_err("the second framing should be reported"),
                    (Pref::Subgroup, Pref::Datagram),
                );
                // Read the second one so the peer's traffic is drained before
                // the assertion, whatever this draft makes of it.
                let _ = tokio::time::timeout(BRIEF, conn.recv_datagram()).await;

                let (asked, seen) = tokio::time::timeout(PATIENCE * 3, peer)
                    .await
                    .expect("peer task hung")
                    .unwrap();
                assert_eq!(
                    unsubscribed(&seen),
                    vec![asked],
                    concat!(
                        "Section ",
                        $section,
                        " asks for an UNSUBSCRIBE from the Track, not for one per offending \
                         Object"
                    )
                );
            }

            /// A track the peer offered with PUBLISH is withdrawn the same way.
            ///
            /// A subscription that came either way round has the same ending,
            /// so the UNSUBSCRIBE names the peer's Request ID here and this
            /// endpoint never sent a SUBSCRIBE at all.
            #[tokio::test]
            async fn a_track_the_peer_published_is_unsubscribed_from() {
                crate::common::init_crypto();
                let (endpoint, addr) =
                    crate::common::spawn_server(&[DraftVersion::$version.quic_alpn()]);
                let peer = tokio::spawn(publishing_peer(endpoint));

                let mut conn = tokio::time::timeout(
                    PATIENCE,
                    Connection::connect(&addr.to_string(), client_config()),
                )
                .await
                .expect("connect did not finish")
                .expect("connect");
                tokio::time::timeout(PATIENCE, conn.recv_and_dispatch())
                    .await
                    .expect("the peer's offer never arrived")
                    .expect("dispatch PUBLISH");
                crate::withdrawal_accept_publish!($accept, conn, v(PEERS_FIRST))
                    .await
                    .expect("accept the peer's offer");

                let err = read_both_framings(&conn).await;
                assert_report(
                    err.as_ref().expect_err("the second framing should be reported"),
                    (Pref::Subgroup, Pref::Datagram),
                );

                let seen = tokio::time::timeout(PATIENCE * 3, peer)
                    .await
                    .expect("peer task hung")
                    .unwrap();
                assert_eq!(
                    unsubscribed(&seen),
                    vec![PEERS_FIRST],
                    "a subscription the peer opened with PUBLISH ends with UNSUBSCRIBE too"
                );
            }

            /// Subscribing to the same track again opens a request that has
            /// never been withdrawn from, and mixing the framing again
            /// withdraws from that one too.
            ///
            /// This is the gate that separates a record of malformed tracks
            /// from a record that refuses to act twice. The track is the same
            /// one, and the second UNSUBSCRIBE names the second Request ID.
            #[tokio::test]
            async fn a_second_subscription_to_the_same_track_is_withdrawn_from_too() {
                crate::common::init_crypto();
                let (endpoint, addr) =
                    crate::common::spawn_server(&[DraftVersion::$version.quic_alpn()]);
                let peer = tokio::spawn(resubscribing_peer(endpoint));

                let (conn, _) = subscribed(&addr.to_string()).await;
                let err = read_both_framings(&conn).await;
                assert_report(
                    err.as_ref().expect_err("the second framing should be reported"),
                    (Pref::Subgroup, Pref::Datagram),
                );

                let mut conn = conn;
                crate::withdrawal_subscribe!($sub, conn, namespace(), TRACK)
                    .await
                    .expect("subscribe again");
                tokio::time::timeout(PATIENCE, conn.recv_and_dispatch())
                    .await
                    .expect("the second answer never arrived")
                    .expect("dispatch the second SUBSCRIBE_OK");
                let second = tokio::time::timeout(PATIENCE, conn.recv_datagram())
                    .await
                    .expect("the second datagram never arrived");
                assert_report(
                    second.as_ref().err().expect("the framing is still the track's property"),
                    (Pref::Subgroup, Pref::Datagram),
                );

                let (asked, withdrew) = tokio::time::timeout(PATIENCE * 3, peer)
                    .await
                    .expect("peer task hung")
                    .unwrap();
                assert_eq!(
                    withdrew, asked,
                    concat!(
                        "Section ",
                        $section,
                        " is about a subscription rather than about a memory of a track: a \
                         second subscription to the same track is withdrawn from as well"
                    )
                );
            }

            /// A track framed one way throughout is never withdrawn from.
            ///
            /// Without this the file would pass against a client that
            /// unsubscribed from everything, which is the shape of failure a
            /// suite made only of violations cannot see.
            #[tokio::test]
            async fn one_framing_throughout_withdraws_nothing() {
                crate::common::init_crypto();
                let (endpoint, addr) =
                    crate::common::spawn_server(&[DraftVersion::$version.quic_alpn()]);
                let peer = tokio::spawn(subscribing_peer(endpoint, Traffic::OneFraming));

                let (conn, _) = subscribed(&addr.to_string()).await;
                for _ in 0..2 {
                    let (header, _stream) =
                        tokio::time::timeout(PATIENCE, conn.accept_subgroup_stream())
                            .await
                            .expect("the peer's data stream never arrived")
                            .expect("a track framed one way is not malformed");
                    assert_eq!(header.track_alias(), ALIAS, "the wrong track came back");
                }
                assert_eq!(
                    conn.endpoint().malformed_track(&namespace(), TRACK),
                    None,
                    "nothing about this track is malformed"
                );

                let (_asked, seen) = tokio::time::timeout(PATIENCE * 3, peer)
                    .await
                    .expect("peer task hung")
                    .unwrap();
                assert!(
                    unsubscribed(&seen).is_empty(),
                    "a conforming track was unsubscribed from: {seen:?}"
                );
            }

            /// An endpoint that detects the condition while *writing* refuses
            /// to write and withdraws from nothing.
            ///
            /// The answer belongs to a subscriber — "When a subscriber detects
            /// a Malformed Track" — and the rule the writer here breaks binds
            /// the Original Publisher. So the second framing is refused before
            /// anything is encoded, and the control stream stays empty.
            ///
            /// The framings are the other way round from every gate above,
            /// and that is what makes this one able to fail. Of the two paths
            /// that write an object, only the one that opens a stream is
            /// async, so only that one could send an UNSUBSCRIBE if it were
            /// wired like its receiving counterpart. The track is settled on
            /// datagrams so that the stream is the framing that disagrees.
            ///
            /// The subscription is what gives the alias a track to be resolved
            /// to; without it the record is never reached and the gate would
            /// pass over a rule it never asked about.
            #[tokio::test]
            async fn a_writer_owes_no_withdrawal() {
                crate::common::init_crypto();
                let (endpoint, addr) =
                    crate::common::spawn_server(&[DraftVersion::$version.quic_alpn()]);
                let peer = tokio::spawn(subscribing_peer(endpoint, Traffic::Silent));

                let (conn, _) = subscribed(&addr.to_string()).await;
                let datagram = AnyDatagramHeader::decode(
                    DraftVersion::$version,
                    &mut &datagram_bytes(OBJECT_ID)[..],
                )
                .expect("decode the datagram this endpoint is about to write");
                conn.send_datagram(&datagram, &[])
                    .expect("the track's first framing is not a mixture");

                let header = AnySubgroupHeader::decode_stream(
                    DraftVersion::$version,
                    &mut &subgroup_stream_bytes(GROUP_ID)[..],
                )
                .expect("decode the header this endpoint is about to write");
                let refused = tokio::time::timeout(PATIENCE, conn.open_subgroup_stream(&header))
                    .await
                    .expect("opening the stream hung");
                assert_report(
                    refused.as_ref().err().expect("a publisher may not mix a track's framing"),
                    (Pref::Datagram, Pref::Subgroup),
                );

                let (_asked, seen) = tokio::time::timeout(PATIENCE * 3, peer)
                    .await
                    .expect("peer task hung")
                    .unwrap();
                assert!(
                    unsubscribed(&seen).is_empty(),
                    "a publisher has no subscription of its own to give up: {seen:?}"
                );
            }

            withdrawal_fetch_gates!($fetches, $version, $sig, $section);
            withdrawal_joining_gate!($join, $version, $section);
        }
    };
}

/// The two gates the FETCH_CANCEL half needs, on the drafts whose sentence
/// has one.
///
/// Expanded inside the per-draft module above, so everything it reaches — the
/// peers, the traffic, the extractors — is already in scope. It defines the
/// helpers the joining gate below also uses, and is always expanded first.
macro_rules! withdrawal_fetch_gates {
    (no, $($rest:tt)*) => {};
    (yes, $version:ident, $sig:tt, $section:literal) => {
        /// A second track, asked for by fetch and never subscribed to.
        const OTHER_TRACK: &[u8] = b"another-track";

        /// The Request ID a FETCH carried, or a panic naming what arrived
        /// instead.
        fn fetch_id(msg: &AnyControlMessage) -> u64 {
            match msg {
                AnyControlMessage::$version(ControlMessage::Fetch(f)) => f.request_id.into_inner(),
                other => panic!("expected a FETCH from the client, got {other:?}"),
            }
        }

        /// The Request IDs of the FETCH_CANCELs among what the peer read.
        fn fetch_cancelled(seen: &[AnyControlMessage]) -> Vec<u64> {
            seen.iter()
                .filter_map(|msg| match msg {
                    AnyControlMessage::$version(ControlMessage::FetchCancel(c)) => {
                        Some(c.request_id.into_inner())
                    }
                    _ => None,
                })
                .collect()
        }

        /// Serve one connection to a client that subscribes and then fetches.
        ///
        /// The FETCH is read before the traffic goes out, so the sequence is
        /// the same every run and a gate can say which Request ID the fetch
        /// was made under rather than inferring it from the allocation order.
        async fn fetching_peer(server: quinn::Endpoint) -> (u64, u64, Vec<AnyControlMessage>) {
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

            let (fetch, _) = framed.read_control(false).await.expect("read FETCH");
            let fetched = fetch_id(&fetch);

            send_traffic(&conn, Traffic::Mixed).await;
            let seen = drain_control!(framed);
            still_running(&conn).await;
            (id.into_inner(), fetched, seen)
        }

        /// A fetch for the malformed track is cancelled, and the subscription
        /// is unsubscribed from in the same breath.
        ///
        /// The two halves of one sentence, and the gate asserts both: an
        /// endpoint that answered only the subscription would have read half
        /// of it. Neither request is answered by the peer — the fetch is still
        /// waiting for its FETCH_OK — because a fetch that has been asked for
        /// is a fetch that can be cancelled.
        #[tokio::test]
        async fn a_fetch_for_the_malformed_track_is_cancelled() {
            crate::common::init_crypto();
            let (endpoint, addr) =
                crate::common::spawn_server(&[DraftVersion::$version.quic_alpn()]);
            let peer = tokio::spawn(fetching_peer(endpoint));

            let (mut conn, _) = subscribed(&addr.to_string()).await;
            let mine = crate::withdrawal_fetch!($sig, conn, namespace(), TRACK)
                .await
                .expect("fetch the track this session is also subscribed to");

            let err = read_both_framings(&conn).await;
            assert_report(
                err.as_ref().expect_err("the second framing should be reported"),
                (Pref::Subgroup, Pref::Datagram),
            );

            let (asked, fetched, seen) =
                tokio::time::timeout(PATIENCE * 3, peer).await.expect("peer task hung").unwrap();
            assert_eq!(
                fetched,
                mine.into_inner(),
                "the peer read a FETCH under a different Request ID than the client made it \
                 under"
            );
            assert_eq!(
                unsubscribed(&seen),
                vec![asked],
                concat!("Section ", $section, " asks for an UNSUBSCRIBE for any subscription")
            );
            assert_eq!(
                fetch_cancelled(&seen),
                vec![fetched],
                concat!(
                    "Section ",
                    $section,
                    " asks for a FETCH_CANCEL for any fetch for that Track, and the fetch was \
                     left running"
                )
            );
        }

        /// A fetch for a different track is left alone.
        ///
        /// The record has to be keyed on the track or this file would pass
        /// against an endpoint that cancelled every fetch it had open the
        /// moment any track went bad. The subscription is still withdrawn
        /// from, so the gate cannot go green by nothing happening at all.
        #[tokio::test]
        async fn a_fetch_for_another_track_is_left_alone() {
            crate::common::init_crypto();
            let (endpoint, addr) =
                crate::common::spawn_server(&[DraftVersion::$version.quic_alpn()]);
            let peer = tokio::spawn(fetching_peer(endpoint));

            let (mut conn, _) = subscribed(&addr.to_string()).await;
            crate::withdrawal_fetch!($sig, conn, namespace(), OTHER_TRACK)
                .await
                .expect("fetch a track nothing is wrong with");

            let err = read_both_framings(&conn).await;
            assert_report(
                err.as_ref().expect_err("the second framing should be reported"),
                (Pref::Subgroup, Pref::Datagram),
            );

            let (asked, _fetched, seen) =
                tokio::time::timeout(PATIENCE * 3, peer).await.expect("peer task hung").unwrap();
            assert_eq!(
                unsubscribed(&seen),
                vec![asked],
                "the subscription to the malformed track is still withdrawn from"
            );
            assert!(
                fetch_cancelled(&seen).is_empty(),
                concat!(
                    "Section ",
                    $section,
                    " names the fetches for *that* Track, and a fetch for another one was \
                     cancelled: {:?}"
                ),
                seen
            );
        }
    };
}

/// The gate for a fetch that names no track of its own.
macro_rules! withdrawal_joining_gate {
    (no, $($rest:tt)*) => {};
    ($sig:tt, $version:ident, $section:literal) => {
        /// A Joining Fetch is cancelled through the subscription it joined.
        ///
        /// It carries no Track Namespace and no Track Name, so an endpoint
        /// that only wrote down what a FETCH said would have nothing to match
        /// the malformed track against and would leave it running. The
        /// subscription it joins is the malformed track's own, which is what
        /// makes the join the only route to the answer.
        #[tokio::test]
        async fn a_joining_fetch_is_cancelled_through_the_subscription_it_joins() {
            crate::common::init_crypto();
            let (endpoint, addr) =
                crate::common::spawn_server(&[DraftVersion::$version.quic_alpn()]);
            let peer = tokio::spawn(fetching_peer(endpoint));

            let (mut conn, subscription) = subscribed(&addr.to_string()).await;
            let mine = withdrawal_joining_fetch!($sig, conn, subscription)
                .await
                .expect("join the subscription this session already has");

            let err = read_both_framings(&conn).await;
            assert_report(
                err.as_ref().expect_err("the second framing should be reported"),
                (Pref::Subgroup, Pref::Datagram),
            );

            let (asked, fetched, seen) =
                tokio::time::timeout(PATIENCE * 3, peer).await.expect("peer task hung").unwrap();
            assert_eq!(
                fetched,
                mine.into_inner(),
                "the peer read a FETCH under a different Request ID than the client made it \
                 under"
            );
            assert_eq!(
                unsubscribed(&seen),
                vec![asked],
                "the subscription the fetch joined is withdrawn from as well"
            );
            assert_eq!(
                fetch_cancelled(&seen),
                vec![fetched],
                concat!(
                    "Section ",
                    $section,
                    " names any fetch for that Track, and a Joining Fetch's track is the one \
                     it joined"
                )
            );
        }
    };
}

/// The joining fetch itself, in the two shapes the drafts that can send one
/// give the call.
///
/// Draft-14's FETCH carries a Subscriber Priority and a Group Order of its own,
/// which draft-15 moved into the parameters, so the call above it takes neither
/// - the same split `withdrawal_fetch!` makes for a standalone one.
///
/// Reached only from the gate above, which drafts 12 and 13 do not build.
#[allow(unused_macros)]
macro_rules! withdrawal_joining_fetch {
    (ordered, $conn:expr, $parent:expr) => {
        $conn.joining_fetch(
            128,
            moqtap_codec::types::GroupOrder::Ascending,
            $parent,
            v(0),
            Vec::new(),
        )
    };
    (bare, $conn:expr, $parent:expr) => {
        $conn.joining_fetch($parent, v(0), Vec::new())
    };
}

/// `ClientConfig`, in the three shapes these four drafts give it.
#[macro_export]
macro_rules! withdrawal_config {
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
macro_rules! withdrawal_server_setup {
    (versioned, $version:expr, $params:expr) => {
        ServerSetup { selected_version: $version.version_varint(), parameters: $params }
    };
    (plain, $version:expr, $params:expr) => {
        ServerSetup { parameters: $params }
    };
}

/// SUBSCRIBE_OK, which is where the Track Alias travels on all four.
#[macro_export]
macro_rules! withdrawal_subscribe_ok {
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
}

/// PUBLISH, the peer's way of opening a subscription this endpoint receives.
#[macro_export]
macro_rules! withdrawal_publish {
    (rich, $id:expr, $ns:expr, $name:expr, $alias:expr) => {
        Publish {
            request_id: $id,
            track_namespace: $ns,
            track_name: $name.to_vec(),
            track_alias: $alias,
            group_order: GroupOrder::Ascending,
            content_exists: ContentExists::NoLargestLocation,
            largest_location: None,
            forward: Forward::Forward,
            parameters: Vec::new(),
        }
    };
    (plain, $id:expr, $ns:expr, $name:expr, $alias:expr) => {
        Publish {
            request_id: $id,
            track_namespace: $ns,
            track_name: $name.to_vec(),
            track_alias: $alias,
            parameters: Vec::new(),
        }
    };
}

/// A conforming subgroup header, in the three shapes these four drafts give it.
#[macro_export]
macro_rules! withdrawal_subgroup_header {
    (typed, $draft:ident, $alias:expr, $group:expr) => {
        moqtap_codec::$draft::data_stream::SubgroupHeader {
            stream_type: moqtap_codec::$draft::data_stream::StreamType::SubgroupExplicit,
            track_alias: $alias,
            group_id: $group,
            subgroup_id: VarInt::from_usize(0),
            publisher_priority: 128,
        }
    };
    (opt, $draft:ident, $alias:expr, $group:expr) => {
        moqtap_codec::$draft::data_stream::SubgroupHeader {
            stream_type: moqtap_codec::$draft::data_stream::SubgroupStreamType::from_flags(
                true, false, false, false,
            ),
            track_alias: $alias,
            group_id: $group,
            subgroup_id: Some(VarInt::from_usize(0)),
            publisher_priority: 128,
        }
    };
    (byte, $draft:ident, $alias:expr, $group:expr) => {
        moqtap_codec::$draft::data_stream::SubgroupHeader {
            // The subgroup base (0x10) with the explicit Subgroup ID bit
            // (0x04): no extensions, no end-of-group, priority present.
            header_type: 0x14,
            track_alias: $alias,
            group_id: $group,
            subgroup_id: VarInt::from_usize(0),
            publisher_priority: Some(128),
        }
    };
}

/// A conforming payload datagram, in the three shapes these four drafts give
/// it. Every one carries no extensions and an empty payload, so nothing about
/// it can be refused for a reason that is not this rule.
#[macro_export]
macro_rules! withdrawal_datagram {
    (grouped, $draft:ident, $alias:expr, $group:expr, $object:expr) => {
        moqtap_codec::$draft::data_stream::Datagram::Payload(
            moqtap_codec::$draft::data_stream::DatagramHeader {
                track_alias: $alias,
                group_id: $group,
                object_id: $object,
                publisher_priority: 128,
                extension_headers_length: VarInt::from_usize(0),
                extensions: Vec::new(),
                end_of_group: false,
            },
        )
    };
    (typed, $draft:ident, $alias:expr, $group:expr, $object:expr) => {
        moqtap_codec::$draft::data_stream::DatagramObject {
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
        }
    };
    (byte, $draft:ident, $alias:expr, $group:expr, $object:expr) => {
        moqtap_codec::$draft::data_stream::DatagramHeader {
            // A payload datagram with the Object ID written, the priority
            // present, no extensions and no status.
            datagram_type: 0x00,
            track_alias: $alias,
            group_id: $group,
            object_id: $object,
            publisher_priority: Some(128),
            extension_headers: Vec::new(),
            object_status: None,
        }
    };
}

/// `Connection::subscribe`, in the three shapes these four drafts give it.
/// Draft-12 names the filter with a varint, draft-13 and draft-14 give it a
/// type, and draft-15 takes neither.
#[macro_export]
macro_rules! withdrawal_subscribe {
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

/// `Connection::fetch`, on the two drafts that have one to cancel here.
/// Draft-14 carries a priority and a group order in the request; draft-15
/// moved both out of it.
#[macro_export]
macro_rules! withdrawal_fetch {
    (ordered, $conn:expr, $ns:expr, $name:expr) => {
        $conn.fetch(
            $ns,
            $name.to_vec(),
            128,
            moqtap_codec::types::GroupOrder::Ascending,
            VarInt::from_u64(0).unwrap(),
            VarInt::from_u64(0).unwrap(),
            VarInt::from_u64(1).unwrap(),
            VarInt::from_u64(0).unwrap(),
            Vec::new(),
        )
    };
    (bare, $conn:expr, $ns:expr, $name:expr) => {
        $conn.fetch(
            $ns,
            $name.to_vec(),
            VarInt::from_u64(0).unwrap(),
            VarInt::from_u64(0).unwrap(),
            VarInt::from_u64(1).unwrap(),
            VarInt::from_u64(0).unwrap(),
            Vec::new(),
        )
    };
}

/// PUBLISH_OK, which differs between the four in what the answer restates.
#[macro_export]
macro_rules! withdrawal_accept_publish {
    (varint, $conn:expr, $id:expr) => {
        $conn.publish_ok(
            $id,
            moqtap_codec::types::Forward::Forward,
            128,
            moqtap_codec::types::GroupOrder::Ascending,
            VarInt::from_u64(0x2).unwrap(),
            None,
            None,
            None,
        )
    };
    (filter, $conn:expr, $id:expr) => {
        $conn.publish_ok(
            $id,
            moqtap_codec::types::Forward::Forward,
            128,
            moqtap_codec::types::GroupOrder::Ascending,
            moqtap_codec::types::FilterType::LargestObject,
            None,
            None,
            None,
        )
    };
    (located, $conn:expr, $id:expr) => {
        $conn.publish_ok(
            $id,
            moqtap_codec::types::Forward::Forward,
            128,
            moqtap_codec::types::GroupOrder::Ascending,
            moqtap_codec::types::FilterType::LargestObject,
            None,
            None,
        )
    };
    (params, $conn:expr, $id:expr) => {
        $conn.publish_ok($id, Vec::new())
    };
}

withdrawal_gates!(
    draft12, "draft12", Draft12, early, versioned, varint, rich, varint, typed, grouped, no, no,
    bare, "2.5"
);
withdrawal_gates!(
    draft13, "draft13", Draft13, early, versioned, filter, rich, filter, typed, grouped, no, no,
    bare, "2.5"
);
withdrawal_gates!(
    draft14, "draft14", Draft14, both, versioned, filter, rich, located, opt, typed, yes, ordered,
    ordered, "2.5"
);
withdrawal_gates!(
    draft15, "draft15", Draft15, late, plain, params, plain, params, byte, byte, yes, bare, bare,
    "2.4.2"
);

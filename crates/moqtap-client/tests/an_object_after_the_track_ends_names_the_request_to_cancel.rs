#![cfg(any(
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20",
    feature = "draft21"
))]

//! A track that carries on after its own final Object is given up, on the
//! three drafts whose answer is a reset rather than a message.
//!
//! Draft-17 Section 2.4.2 lists the condition: "An Object is received on a
//! Track whose Group and Object ID are larger than the final Object in the
//! Track. The final Object in a Track is the Object with Status END_OF_TRACK or
//! the last Object sent in a FETCH whose response indicated End of Track."
//! Drafts 18 and 19 drop the two words "on a Track" and change nothing else.
//!
//! The answer is the section's one answer for its whole list, and on these
//! three it is not a message: "it MUST cancel any corresponding subscription or
//! fetches for that Track from that publisher". Cancelling a request is the
//! transport operation Section 3.3.1 describes on draft-17, 3.3.2 on draft-18
//! and 3.3.3 on draft-19 — reset the directions of the request's own stream
//! that are still open.
//!
//! # Why these gates read a list of ids where the earlier ones read the wire
//!
//! Because the stream to reset is not this crate's to touch. Every request on
//! these drafts lives at the front of a bidirectional stream of its own, and
//! `Connection::recv_on_request_stream` hands that stream back to the caller as
//! a `RequestStream`. `Connection::requests_to_cancel` therefore does the half
//! a connection can — note the track, and work out which requests receive it —
//! and the caller passes each id to `Connection::cancel_request_stream`, which
//! resets the stream *and* moves the endpoint's record.
//!
//! On drafts 12 through 16 the answer is a control message, which the
//! connection owns, so `withdraw_for_data_stream` there does the whole thing
//! and `an_object_after_the_track_ends_is_a_malformed_track.rs` asserts the
//! peer's view of the wire. **This is the one place in this crate where the two
//! halves of an answer are split across the API boundary**, and the draft is
//! what splits them.
//!
//! What a reset looks like at the peer is not re-asserted here.
//! `a_cancellation_revokes_an_acceptance.rs` and `a_cancelled_request_is_recorded.rs`
//! already gate `cancel_request_stream` end to end on these drafts; what is new
//! is which requests it should be called for, and that is what these gates
//! measure.
//!
//! # Larger is the drafts' own comparison
//!
//! All three carry a Location Structure section — Section 1.4.2 on each —
//! putting one Location below another when "A.Group < B.Group || (A.Group ==
//! B.Group && A.Object < B.Object)". Read field by field instead, an Object in
//! a *later* group whose Object ID happens to be smaller would have neither
//! number larger and would escape the rule.
//! `a_later_group_is_past_the_end_whatever_its_object_id` is that exact case.
//!
//! # What keeps the answer to one, and why it had to be re-decided here
//!
//! On the drafts that answer with a message, the endpoint ends the requests it
//! withdraws, so a request that has ended has no second ending in it. Nothing
//! here ends anything: the flows are read and not moved. What closes the loop
//! is the caller's `cancel_request_stream` — it ends the request, the binding
//! stops being in use, and the alias resolves to no track, so a later object
//! past the end names nothing.
//! `a_cancelled_request_leaves_no_track_to_name` is that claim, and it is the
//! gate that says the request ending is still the mechanism and only the side
//! performing it changed.
//!
//! # Every gate carries the subscription through to its answer
//!
//! The rule is reached by resolving an Object's Track Alias to a track, and the
//! alias travels in the SUBSCRIBE_OK. A gate that sent the objects without
//! reading the answer off the request stream would have an alias that names
//! nothing, the record would never be consulted, and the gate would pass
//! against a tree with the rule and against one without it. The request stream
//! is also **held** for the whole of each gate: dropping it resets it, which on
//! these drafts cancels the subscription and frees the alias.
//!
//! # Ablations, measured
//!
//! Four cuts, each applied to the working tree, run, and reverted with every
//! touched file compared byte for byte afterwards. They are spread over all
//! three drafts, because each carries the rule through modules of its own and a
//! cut that only ever landed on one of them would say nothing about the others
//! — and **no cut reddened a draft it was not aimed at**, which is the
//! evidence for that being true rather than assumed.
//!
//! Taking the measurement off draft-18's stream objects:
//!
//! ```text
//! an Object in a later group is past the track's final Object: ()
//! ```
//!
//! One gate, and draft-18's datagram gates stay green.
//!
//! Taking it off draft-17's datagrams:
//!
//! ```text
//! an object past the track's final Object is a malformed track: (Draft17(DatagramHeader { datagram_type: 0, track_alias: VarInt(7), group_id: VarInt(5), object_id: VarInt(3), publisher_priority: Some(128), properties: [], object_status: None }), b"")
//! ```
//!
//! Two gates, both of them draft-17's datagram ones, with the stream gate
//! untouched. The two paths are wired separately and neither stands in for the
//! other — the same separation the drafts that answer with a message show, on
//! drafts where neither path can answer at all.
//!
//! Making every binding on draft-19 read as still in use, so a cancelled
//! request is still found:
//!
//! ```text
//! the request ending is what keeps the answer to one, and on this draft the caller is the side that ends it
//! ```
//!
//! **One gate, and it is the one that matters here.** Nothing in this crate
//! ends a request on these drafts, so if the caller's cancellation did not take
//! the binding out of use there would be no mechanism at all keeping the answer
//! to one — the same object would be named again for ever.
//!
//! Making draft-18 answer that it receives no track through any request:
//!
//! ```text
//! assertion `left == right` failed: Section 2.4.2 asks for the subscription carrying this track to be cancelled, and Section 3.3.2 makes that a reset of its own stream — so the request has to be named
//!   left: []
//!  right: [VarInt(0)]
//! ```
//!
//! Three gates, which is right: detection is unaffected and every gate that
//! reads the *list* goes red. The acceptance gate stays green under all four,
//! because none of these makes the crate refuse something it should not.
//!
//! The field-by-field reading of *larger* is not cut here. It lives in the
//! shared `track_locations`, so a cut there reddens drafts 12 through 20 at
//! once; it is recorded where it was measured, in
//! `an_object_after_the_track_ends_is_a_malformed_track.rs`.

mod common;

use std::time::Duration;

/// How long a test waits on the client or the peer before calling it hung.
const PATIENCE: Duration = Duration::from_secs(10);

/// Long enough that a close on its way would have arrived, short enough that a
/// gate expecting none does not sit on it.
const BRIEF: Duration = Duration::from_millis(400);

/// The alias the track is known by on the wire.
const ALIAS: u64 = 7;

const TRACK: &[u8] = b"one-track";

/// The group and object the track ends at. Everything else is measured against
/// this pair.
const END_GROUP: u64 = 5;
const END_OBJECT: u64 = 2;

/// What the peer puts on the wire once the subscription is bound.
#[derive(Debug, Clone, Copy)]
enum Traffic {
    /// End the track, then send an object in the same group with a larger
    /// Object ID. Datagrams, so the connection reads them itself.
    PastByObject,
    /// End the track on one subgroup stream, then open another for a *later*
    /// group carrying object 0 — smaller by one field and larger by the
    /// comparison the drafts define.
    PastByGroup,
    /// End the track, then send an object below the end, which is not the
    /// condition.
    BelowTheEnd,
}

/// A quinn receive stream with a buffer in front of it.
///
/// It decodes with `moqtap-codec` and never calls the framing helpers in
/// `moqtap-client`: a peer assembled out of the code under test could not
/// disagree with it.
struct PeerStream {
    recv: quinn::RecvStream,
    buf: Vec<u8>,
}

impl PeerStream {
    fn new(recv: quinn::RecvStream) -> Self {
        Self { recv, buf: Vec::new() }
    }

    async fn fill(&mut self) -> bool {
        let mut tmp = [0u8; 2048];
        match self.recv.read(&mut tmp).await {
            Ok(Some(n)) => {
                self.buf.extend_from_slice(&tmp[..n]);
                true
            }
            _ => false,
        }
    }

    /// Decode one whole control message, type field included.
    ///
    /// On these drafts a control stream's leading varint *is* its first
    /// message's type field, so this reads the SETUP off the front of the
    /// stream with nothing skipped — and the SUBSCRIBE off the front of a
    /// request stream the same way.
    async fn read_control(
        &mut self,
        draft: moqtap_codec::version::DraftVersion,
    ) -> Option<moqtap_codec::dispatch::AnyControlMessage> {
        use moqtap_codec::dispatch::AnyControlMessage;
        use moqtap_codec::error::CodecError;
        use moqtap_codec::varint::VarIntError;

        loop {
            let mut cursor = &self.buf[..];
            match AnyControlMessage::decode(draft, &mut cursor) {
                Ok(msg) => {
                    let consumed = self.buf.len() - cursor.len();
                    self.buf.drain(..consumed);
                    return Some(msg);
                }
                Err(CodecError::UnexpectedEnd | CodecError::VarInt(VarIntError::UnexpectedEnd)) => {
                    if !self.fill().await {
                        return None;
                    }
                }
                Err(_) => return None,
            }
        }
    }
}

/// One draft's gates.
macro_rules! cancel_gates {
    ($draft:ident, $feat:literal, $version:ident, $cancel_sec:literal) => {
        #[cfg(feature = $feat)]
        mod $draft {
            use moqtap_client::malformed_tracks::MalformedTrackCondition;
            use moqtap_client::$draft::connection::{
                ClientConfig, Connection, ConnectionError, RequestStream, TransportType,
                REQUEST_CANCELLED,
            };
            use moqtap_client::$draft::endpoint::EndpointError;
            use moqtap_client::$draft::session::state::SessionState;
            use moqtap_codec::dispatch::{AnyControlMessage, AnyDatagramHeader, AnySubgroupHeader};
            use moqtap_codec::types::TrackNamespace;
            use moqtap_codec::varint::VarInt;
            use moqtap_codec::version::DraftVersion;
            use moqtap_codec::$draft::message::{ControlMessage, Setup, SubscribeOk};
            use moqtap_codec::$draft::types::ObjectStatus;

            use crate::{
                PeerStream, Traffic, ALIAS, BRIEF, END_GROUP, END_OBJECT, PATIENCE, TRACK,
            };

            fn v(n: u64) -> VarInt {
                VarInt::from_u64(n).unwrap()
            }

            fn namespace() -> TrackNamespace {
                TrackNamespace(vec![b"conformance".to_vec()])
            }

            fn client_config() -> ClientConfig {
                ClientConfig {
                    draft: DraftVersion::$version,
                    transport: TransportType::Quic,
                    skip_cert_verification: true,
                    ca_certs: Vec::new(),
                    setup_parameters: Vec::new(),
                }
            }

            fn setup_bytes() -> Vec<u8> {
                let mut out = Vec::new();
                AnyControlMessage::$version(ControlMessage::Setup(Setup { options: Vec::new() }))
                    .encode(&mut out)
                    .expect("encode SETUP");
                out
            }

            /// The answer that binds the alias. A response on these drafts
            /// carries no Request ID — the stream it comes back on is the
            /// correlation — so this is the whole of it.
            fn subscribe_ok_bytes() -> Vec<u8> {
                let ok = SubscribeOk {
                    track_alias: v(ALIAS),
                    parameters: Vec::new(),
                    track_properties: Vec::new(),
                };
                let mut out = Vec::new();
                AnyControlMessage::$version(ControlMessage::SubscribeOk(ok))
                    .encode(&mut out)
                    .expect("encode SUBSCRIBE_OK");
                out
            }

            /// One subgroup stream for `group`, carrying one object.
            fn subgroup_stream_bytes(
                group: u64,
                object: u64,
                status: Option<ObjectStatus>,
            ) -> Vec<u8> {
                let header = moqtap_codec::$draft::data_stream::SubgroupHeader {
                    // The subgroup base (0x10) with the explicit Subgroup ID
                    // bit (0x04): nothing per-object, no end-of-group,
                    // priority present.
                    header_type: 0x14,
                    track_alias: v(ALIAS),
                    group_id: v(group),
                    subgroup_id: v(0),
                    publisher_priority: Some(128),
                };
                let mut buf = Vec::new();
                AnySubgroupHeader::$version(header.clone())
                    .encode_stream_checked(&mut buf)
                    .expect("encode the subgroup header");
                let mut writer =
                    moqtap_codec::$draft::data_stream::SubgroupObjectReader::new(&header);
                writer
                    .write_object(
                        &moqtap_codec::$draft::data_stream::SubgroupObject {
                            object_id: v(object),
                            extension_headers: Vec::new(),
                            payload_length: VarInt::from_usize(0),
                            object_status: status,
                            payload: Vec::new(),
                        },
                        &mut buf,
                    )
                    .expect("encode the object");
                buf
            }

            /// The same object, carried by a datagram.
            fn datagram_bytes(group: u64, object: u64, status: Option<ObjectStatus>) -> Vec<u8> {
                let header = moqtap_codec::$draft::data_stream::DatagramHeader {
                    // A payload datagram with the Object ID written, the
                    // priority present and nothing per-object; the status bit
                    // (0x20) is what puts a status code on the wire in place of
                    // a payload.
                    datagram_type: if status.is_some() { 0x20 } else { 0x00 },
                    track_alias: v(ALIAS),
                    group_id: v(group),
                    object_id: v(object),
                    publisher_priority: Some(128),
                    properties: Vec::new(),
                    object_status: status,
                };
                let mut buf = Vec::new();
                AnyDatagramHeader::$version(header).encode(&mut buf).expect("encode the datagram");
                buf
            }

            /// Serve one connection: the setup exchange, the SUBSCRIBE_OK that
            /// binds the alias, and then the traffic.
            ///
            /// Every stream the peer opened or accepted is held until this
            /// returns. Dropping a quinn send stream resets it, and on these
            /// drafts a request stream's reset is how a request is withdrawn —
            /// so letting the SUBSCRIBE's stream fall out of scope early would
            /// cancel the subscription and leave the objects naming a track
            /// that no longer resolves.
            async fn serve(server: quinn::Endpoint, traffic: Traffic) {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");

                let mut control = PeerStream::new(conn.accept_uni().await.expect("accept_uni"));
                control
                    .read_control(DraftVersion::$version)
                    .await
                    .expect("read the client's SETUP");

                let mut our_control =
                    conn.open_uni().await.expect("open the peer's control stream");
                our_control.write_all(&setup_bytes()).await.expect("write the peer's SETUP");

                let (mut answer, request) = conn.accept_bi().await.expect("accept_bi");
                let mut request = PeerStream::new(request);
                match request.read_control(DraftVersion::$version).await {
                    Some(AnyControlMessage::$version(ControlMessage::Subscribe(_))) => {}
                    other => panic!("expected a SUBSCRIBE from the client, got {other:?}"),
                }
                answer.write_all(&subscribe_ok_bytes()).await.expect("write SUBSCRIBE_OK");

                match traffic {
                    Traffic::PastByObject | Traffic::BelowTheEnd => {
                        let after = if matches!(traffic, Traffic::PastByObject) {
                            END_OBJECT + 1
                        } else {
                            END_OBJECT - 1
                        };
                        conn.send_datagram(
                            datagram_bytes(END_GROUP, END_OBJECT, Some(ObjectStatus::EndOfTrack))
                                .into(),
                        )
                        .expect("send the end-of-track datagram");
                        conn.send_datagram(datagram_bytes(END_GROUP, after, None).into())
                            .expect("send the object after it");
                    }
                    Traffic::PastByGroup => {
                        let mut ending =
                            conn.open_uni().await.expect("open the ending subgroup stream");
                        ending
                            .write_all(&subgroup_stream_bytes(
                                END_GROUP,
                                END_OBJECT,
                                Some(ObjectStatus::EndOfTrack),
                            ))
                            .await
                            .expect("write the ending stream");
                        ending.finish().expect("finish the ending stream");
                        let mut later =
                            conn.open_uni().await.expect("open the later subgroup stream");
                        later
                            .write_all(&subgroup_stream_bytes(END_GROUP + 1, 0, None))
                            .await
                            .expect("write the later stream");
                        later.finish().expect("finish the later stream");
                        // Held until the connection ends, so a finished stream
                        // is not also a dropped one.
                        std::future::pending::<()>().await;
                    }
                }
                // Nothing is closed from this side: every gate here asserts
                // that the session survives the condition.
                std::future::pending::<()>().await;
            }

            /// A connected client whose SUBSCRIBE has been answered, the
            /// request stream it went out on, and the task serving it.
            async fn subscribed(
                traffic: Traffic,
            ) -> (Connection, RequestStream, tokio::task::JoinHandle<()>) {
                crate::common::init_crypto();
                let (endpoint, addr) =
                    crate::common::spawn_server(&[DraftVersion::$version.quic_alpn()]);
                let peer = tokio::spawn(serve(endpoint, traffic));

                let mut conn = tokio::time::timeout(
                    PATIENCE,
                    Connection::connect(&addr.to_string(), client_config()),
                )
                .await
                .expect("connect did not finish")
                .expect("connect");

                let mut request = tokio::time::timeout(
                    PATIENCE,
                    conn.subscribe(namespace(), TRACK.to_vec(), Vec::new()),
                )
                .await
                .expect("subscribe did not finish")
                .expect("subscribe");

                let answer =
                    tokio::time::timeout(PATIENCE, conn.recv_on_request_stream(&mut request))
                        .await
                        .expect("the answer carrying the alias never arrived")
                        .expect("read SUBSCRIBE_OK");
                match answer {
                    ControlMessage::SubscribeOk(ok) => assert_eq!(
                        ok.track_alias.into_inner(),
                        ALIAS,
                        "the alias the objects name is the one this answer bound"
                    ),
                    other => panic!("expected a SUBSCRIBE_OK, got {other:?}"),
                }
                (conn, request, peer)
            }

            /// The report names the object and where the track had ended, so an
            /// application reading it can tell the two apart.
            fn assert_report(err: &ConnectionError, at: (u64, u64)) {
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
                            (END_GROUP, END_OBJECT),
                            "the report names another place for the track to have ended"
                        );
                    }
                    other => panic!("expected a past-the-end report, got {other:?}"),
                }
            }

            /// Read one subgroup stream and its single object.
            async fn read_stream(conn: &Connection) -> Result<(), ConnectionError> {
                let (_header, mut stream) =
                    tokio::time::timeout(PATIENCE, conn.accept_subgroup_stream())
                        .await
                        .expect("the peer's data stream never arrived")
                        .expect("read the subgroup header");
                tokio::time::timeout(PATIENCE, stream.read_subgroup_object())
                    .await
                    .expect("the stream produced no object")?;
                Ok(())
            }

            /// A datagram past the track's final Object is reported, names the
            /// request to cancel, and does not end the session.
            ///
            /// Four things, none implied by the others: the client reports the
            /// object and the end it was measured against, the request whose
            /// stream the caller must reset is named, an application that
            /// missed the error can still learn why, and the session survives.
            #[tokio::test]
            async fn a_datagram_past_the_final_object_names_the_request_to_cancel() {
                let (conn, request, _peer) = subscribed(Traffic::PastByObject).await;

                tokio::time::timeout(PATIENCE, conn.recv_datagram())
                    .await
                    .expect("the end-of-track datagram never arrived")
                    .expect("the object ending the track is accepted");

                let err = tokio::time::timeout(PATIENCE, conn.recv_datagram())
                    .await
                    .expect("the object after the end never arrived")
                    .expect_err("an object past the track's final Object is a malformed track");
                assert_report(&err, (END_GROUP, END_OBJECT + 1));

                assert_eq!(
                    conn.requests_to_cancel(&err),
                    vec![request.request_id()],
                    "Section 2.4.2 asks for the subscription carrying this track to be \
                     cancelled, and Section {} makes that a reset of its own stream — so \
                     the request has to be named",
                    $cancel_sec,
                );
                assert_eq!(
                    conn.endpoint().malformed_track(&namespace(), TRACK),
                    Some(MalformedTrackCondition::ObjectPastFinalObject),
                    "an application that missed the error should still be able to learn \
                     why the subscription ended",
                );
                // Read for as long as a close would have taken to arrive,
                // then ask the session what it thinks it is. The endpoint is
                // what closes a session over a violation, so a session that is
                // still Active is one this crate did not end.
                tokio::time::sleep(BRIEF).await;
                assert_eq!(
                    conn.endpoint().session_state(),
                    SessionState::Active,
                    "a malformed track gives up one track, not the session",
                );
            }

            /// An Object in a later group is past the end whatever its own
            /// Object ID is.
            ///
            /// The gate that tells the drafts' Location comparison apart from a
            /// field-by-field reading: object 0 of group 6 is smaller in one
            /// field and larger by the comparison Section 1.4.2 defines.
            #[tokio::test]
            async fn a_later_group_is_past_the_end_whatever_its_object_id() {
                let (conn, request, _peer) = subscribed(Traffic::PastByGroup).await;

                read_stream(&conn).await.expect("the stream ending the track is accepted");
                let err = read_stream(&conn)
                    .await
                    .expect_err("an Object in a later group is past the track's final Object");
                assert_report(&err, (END_GROUP + 1, 0));

                assert_eq!(
                    conn.requests_to_cancel(&err),
                    vec![request.request_id()],
                    "an object on a stream reaches the same answer as one in a datagram",
                );
            }

            /// An Object below the track's final Object is not the condition.
            #[tokio::test]
            async fn an_object_below_the_end_is_not_past_it() {
                let (conn, _request, _peer) = subscribed(Traffic::BelowTheEnd).await;

                tokio::time::timeout(PATIENCE, conn.recv_datagram())
                    .await
                    .expect("the end-of-track datagram never arrived")
                    .expect("the object ending the track is accepted");
                tokio::time::timeout(PATIENCE, conn.recv_datagram())
                    .await
                    .expect("the object below the end never arrived")
                    .expect(
                        "an Object below the track's final Object is not one the condition names",
                    );

                assert_eq!(
                    conn.endpoint().malformed_track(&namespace(), TRACK),
                    None,
                    "nothing was given up, so nothing should be recorded as given up",
                );
            }

            /// Cancelling the request that was named leaves no track to name.
            ///
            /// This is what keeps the answer to one on these drafts, and it is
            /// not the record. The endpoint reads the flows and never moves
            /// them, so the loop is closed by the caller's
            /// `cancel_request_stream`: the request ends, the binding stops
            /// being in use, and the alias resolves to no track at all.
            ///
            /// The same error is put a second time deliberately — the question
            /// is whether the *endpoint* still has anything to name, not
            /// whether a second object would be judged.
            #[tokio::test]
            async fn a_cancelled_request_leaves_no_track_to_name() {
                let (mut conn, mut request, _peer) = subscribed(Traffic::PastByObject).await;

                tokio::time::timeout(PATIENCE, conn.recv_datagram())
                    .await
                    .expect("the end-of-track datagram never arrived")
                    .expect("the object ending the track is accepted");
                let err = tokio::time::timeout(PATIENCE, conn.recv_datagram())
                    .await
                    .expect("the object after the end never arrived")
                    .expect_err("an object past the track's final Object is a malformed track");
                assert_eq!(
                    conn.requests_to_cancel(&err).len(),
                    1,
                    "the request is named while it is live",
                );

                conn.cancel_request_stream(&mut request, REQUEST_CANCELLED)
                    .expect("cancel the request the answer named");

                assert!(
                    conn.requests_to_cancel(&err).is_empty(),
                    "the request ending is what keeps the answer to one, and on this draft \
                     the caller is the side that ends it",
                );
            }
        }
    };
}

cancel_gates!(draft17, "draft17", Draft17, "3.3.1");
cancel_gates!(draft18, "draft18", Draft18, "3.3.2");
cancel_gates!(draft19, "draft19", Draft19, "3.3.3");
cancel_gates!(draft20, "draft20", Draft20, "3.3.3");
cancel_gates!(draft21, "draft21", Draft21, "6.4.2.3");

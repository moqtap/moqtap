#![cfg(any(feature = "draft17", feature = "draft18", feature = "draft19"))]

//! One track's objects arrive on a subgroup stream and then in a datagram, over
//! QUIC, at the three drafts that let them.
//!
//! Draft-17 Section 10.2.1 — Section 11.2.1 on drafts 18 and 19 — states the
//! property this is about: "Object Forwarding Preference is a property of an
//! individual Object and can vary among Objects in the same Track. In a
//! subscription, an Object MUST be sent according to its Object Forwarding
//! Preference." The preference is the Object's, so a track whose objects are
//! framed both ways is conforming, and both halves of this file assert an
//! acceptance: nothing is reported when the second framing is read, and nothing
//! is refused when one is written.
//!
//! # A gate for a rule that is not here
//!
//! Nine drafts, 07 through 15, state the opposite — "Every Track has a single
//! 'Object Forwarding Preference' and the Original Publisher MUST NOT mix
//! different forwarding preferences within a single track" — and
//! `a_track_keeps_one_forwarding_preference.rs` enforces it on every one of
//! them. What makes the three drafts here worth a test rather than a note is
//! what draft-16 did to the Malformed Tracks list at the same time as it
//! replaced that sentence.
//!
//! Draft-15 Section 2.4.2 lists "An Object is received with a different
//! Forwarding Preference than previously observed from the same Track" among
//! the conditions that make a track malformed. Draft-17 Section 2.4.2 lists "An
//! Object is received with a different Forwarding Preference than previously
//! observed." Four words are gone and the bullet is otherwise untouched, so read
//! on its own it still reads as a rule about a track — and the answer that list
//! gives is a real one: "When a subscriber detects a Malformed Track, it MUST
//! cancel any corresponding subscription or fetches for that Track from that
//! publisher". Reading the bullet and not the sentence above would carry a
//! rule these drafts do not have, against traffic they permit. This
//! file is what makes that a failing test rather than a plausible commit.
//!
//! # Why the alias is bound when nothing records it
//!
//! Both gates take the subscription all the way to its answer, which is the
//! only thing that binds the Track Alias the objects carry, even though on
//! these drafts nothing is written down about the track afterwards. The reason
//! is what the gate would be worth otherwise. The rule, where it exists, is
//! reached by resolving an object's alias to the track a live subscription gave
//! it to; an alias no binding names resolves to nothing and settles nothing. So
//! a gate that sent the two framings without ever binding the alias would go on
//! passing after somebody added the rule to these drafts, and a test that cannot
//! fail is not a gate. The ablation below is what says this one can.
//!
//! # Why this is not in the file next door
//!
//! The rule's own file covers drafts 07 through 16 and asserts draft-16's
//! acceptance in exactly the terms used here. Drafts 17, 18 and 19 answer to a
//! different topology: control travels on a pair of unidirectional streams and
//! every request opens a bidirectional stream of its own, so its peer — which
//! reads SETUP and the SUBSCRIBE off one bidirectional stream — cannot serve
//! them. The assertion is shared and the peer cannot be, which is the split.
//!
//! # Why the peer here enforces nothing
//!
//! `uni_control_plane.rs` holds the client to that topology from both
//! directions, and repeating it here would test the same thing twice. This peer
//! is shaped by the topology rather than enforcing it: the client puts its SETUP
//! on a unidirectional stream and its SUBSCRIBE at the front of a bidirectional
//! one, so a peer that read either anywhere else would read nothing at all and
//! every test here would time out.
//!
//! # Ablation, measured
//!
//! The cut is the commit this file exists to stop: draft-17 given the
//! track-scoped forwarding-preference record drafts 07 through 15 carry, wired
//! into the two readers and the two writers exactly as they wire it. Applied to
//! the working tree, run, and reverted with the file compared byte for byte
//! afterwards; `scratchpad/r82_ablate.py` runs it.
//!
//! Reading the second framing:
//!
//! ```text
//! Section 10.2.1 makes the forwarding preference a property of the Object, so a datagram for a track whose objects have used subgroup streams is legal here: Endpoint(MixedForwardingPreference { alias: 7, established: Subgroup, offered: Datagram })
//! ```
//!
//! Writing it:
//!
//! ```text
//! Section 10.2.1 makes the forwarding preference a property of the Object, so a publisher may send one track's objects both ways: Endpoint(MixedForwardingPreference { alias: 7, established: Subgroup, offered: Datagram })
//! ```
//!
//! Both reports name alias 7, which is the alias the SUBSCRIBE_OK bound. That is
//! the other half of the ablation: a rule reached by resolving an alias to a
//! track can only report one it resolved, so a gate that had skipped the answer
//! would have stayed green under the same cut.

mod common;

use std::time::Duration;

use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::error::CodecError;
use moqtap_codec::varint::VarIntError;
use moqtap_codec::version::DraftVersion;

/// How long a test waits on the client or the peer before calling it hung.
const PATIENCE: Duration = Duration::from_secs(10);

/// Long enough that a close on its way would have arrived, short enough that a
/// gate expecting none does not sit on it.
const BRIEF: Duration = Duration::from_millis(400);

/// The alias the peer gives the track in its SUBSCRIBE_OK, and the one both
/// framings carry.
const ALIAS: u64 = 7;

/// The track both gates subscribe to. One track, framed two ways, is the whole
/// of what these drafts permit and the nine before them forbid.
const TRACK: &[u8] = b"one-track";

const GROUP_ID: u64 = 3;
const OBJECT_ID: u64 = 0;

/// Subgroup header type: the subgroup form (0x10) with subgroup-ID mode 2, an
/// explicit ID (0x04). No properties, no end-of-group, priority present — the
/// plainest subgroup stream these drafts carry, so nothing about it can be
/// refused for a reason that is not this rule.
const SUBGROUP_HEADER_TYPE: u8 = 0x14;

/// Datagram type: a payload datagram with the Object ID written, the priority
/// present, no properties and no status. The plainest datagram, for the same
/// reason.
const DATAGRAM_TYPE: u8 = 0x00;

/// A quinn receive stream with a buffer in front of it.
///
/// The peer decodes with `moqtap-codec` and never calls the framing helpers in
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

    /// Pull more bytes in. `false` once the stream has ended or failed.
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
    /// On these three drafts a control stream's leading varint *is* its first
    /// message's type field, so this reads the SETUP off the front of the stream
    /// with nothing skipped — and the SUBSCRIBE off the front of a request
    /// stream the same way.
    async fn read_control(&mut self, draft: DraftVersion) -> Option<AnyControlMessage> {
        loop {
            let mut cursor = &self.buf[..];
            match AnyControlMessage::decode(draft, &mut cursor) {
                Ok(msg) => {
                    let consumed = self.buf.len() - cursor.len();
                    self.buf.drain(..consumed);
                    return Some(msg);
                }
                // Two errors mean "not enough bytes yet", and which one it is
                // depends on where the message ran out. A body that stops short
                // is `UnexpectedEnd`; a message whose leading type varint has
                // not arrived fails inside the varint decoder before there is a
                // message to be short, which is what every read before the first
                // one gives.
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

/// One draft's pair of gates. `$draft` is the draft's module in both crates,
/// `$version` its [`DraftVersion`] and [`AnyControlMessage`] variant, and
/// `$section` the section carrying the sentence both gates are about — 10.2.1
/// on draft-17, renumbered to 11.2.1 when draft-18 added a section above it.
macro_rules! object_forwarding_preference_gate {
    ($draft:ident, $feat:literal, $version:ident, $section:literal) => {
        #[cfg(feature = $feat)]
        mod $draft {
            use moqtap_client::$draft::connection::{ClientConfig, Connection, TransportType};
            use moqtap_codec::dispatch::{AnyControlMessage, AnyDatagramHeader, AnySubgroupHeader};
            use moqtap_codec::types::TrackNamespace;
            use moqtap_codec::varint::VarInt;
            use moqtap_codec::version::DraftVersion;
            use moqtap_codec::$draft::data_stream::{DatagramHeader, SubgroupHeader};
            use moqtap_codec::$draft::message::{ControlMessage, Setup, SubscribeOk};

            use crate::{
                PeerStream, ALIAS, BRIEF, DATAGRAM_TYPE, GROUP_ID, OBJECT_ID, PATIENCE,
                SUBGROUP_HEADER_TYPE, TRACK,
            };

            fn v(n: u64) -> VarInt {
                VarInt::from_u64_moqt(n)
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

            /// The peer's SETUP. Its message type is also its stream's type, so
            /// these bytes go on a fresh unidirectional stream with no header in
            /// front of them.
            fn setup_bytes() -> Vec<u8> {
                let mut out = Vec::new();
                AnyControlMessage::$version(ControlMessage::Setup(Setup { options: Vec::new() }))
                    .encode(&mut out)
                    .expect("encode SETUP");
                out
            }

            /// The answer that binds the alias. On these drafts a response
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

            fn subgroup_header() -> SubgroupHeader {
                SubgroupHeader {
                    header_type: SUBGROUP_HEADER_TYPE,
                    track_alias: v(ALIAS),
                    group_id: v(GROUP_ID),
                    subgroup_id: v(0),
                    publisher_priority: Some(128),
                }
            }

            fn datagram_header() -> DatagramHeader {
                DatagramHeader {
                    datagram_type: DATAGRAM_TYPE,
                    track_alias: v(ALIAS),
                    group_id: v(GROUP_ID),
                    object_id: v(OBJECT_ID),
                    publisher_priority: Some(128),
                    properties: Vec::new(),
                    object_status: None,
                }
            }

            /// The track's first framing, written through the codec's own
            /// writer because it is conforming and there is nothing to
            /// hand-build.
            fn subgroup_stream_bytes() -> Vec<u8> {
                let mut out = Vec::new();
                subgroup_header().encode(&mut out);
                out
            }

            /// The second framing for that same track, which is the whole of
            /// what the nine earlier drafts forbid.
            fn datagram_bytes() -> Vec<u8> {
                let mut out = Vec::new();
                datagram_header().encode(&mut out);
                out
            }

            /// Serve one connection: complete the setup exchange, answer the
            /// client's SUBSCRIBE with the Track Alias, send that track's
            /// objects both ways when asked to, and then require the session to
            /// still be standing.
            ///
            /// Every stream the peer opened or accepted is held until this
            /// returns. Dropping a quinn send stream resets it, and on these
            /// drafts a request stream's reset is how a request is withdrawn —
            /// so letting the SUBSCRIBE's stream fall out of scope early would
            /// cancel the subscription, free the alias, and leave the objects
            /// naming a track that no longer resolves.
            async fn serve(server: quinn::Endpoint, send_objects: bool) {
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

                if send_objects {
                    let mut data = conn.open_uni().await.expect("open the data stream");
                    data.write_all(&subgroup_stream_bytes())
                        .await
                        .expect("write the subgroup header");
                    data.finish().expect("finish the data stream");

                    conn.send_datagram(datagram_bytes().into()).expect("send the datagram");
                }

                if let Ok(reason) = tokio::time::timeout(BRIEF, conn.closed()).await {
                    panic!(
                        concat!(
                            "Section ",
                            $section,
                            " makes the forwarding preference the Object's, so nothing here \
                             ends a session; it ended with {:?}"
                        ),
                        reason
                    );
                }
            }

            /// A connected client whose SUBSCRIBE has been answered, and the
            /// task serving it.
            ///
            /// The answer is read off the request stream it went out on, which
            /// is what carries it into the endpoint and binds the alias. Its
            /// Track Alias is asserted here rather than taken on trust: a peer
            /// that answered with a different one would leave every later
            /// assertion about a track this client never heard of.
            async fn subscribed(send_objects: bool) -> (Connection, tokio::task::JoinHandle<()>) {
                crate::common::init_crypto();
                let (endpoint, addr) =
                    crate::common::spawn_server(&[DraftVersion::$version.quic_alpn()]);
                let peer = tokio::spawn(serve(endpoint, send_objects));

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
                (conn, peer)
            }

            /// A track's objects arrive framed two ways and both are accepted.
            ///
            /// Three things are asserted and none implies the others. The
            /// subgroup header comes back naming the track, so the gate cannot
            /// pass because the peer's stream never arrived. The datagram comes
            /// back naming the same track and the object the peer sent, so it
            /// cannot pass on a client that accepted *something*. And the peer
            /// sees no close, which is the only part of this that is about the
            /// wire.
            #[tokio::test]
            async fn a_second_framing_for_one_track_is_accepted() {
                let (conn, peer) = subscribed(true).await;

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

                let (datagram, _payload) = tokio::time::timeout(PATIENCE, conn.recv_datagram())
                    .await
                    .expect("the peer's datagram never arrived")
                    .expect(concat!(
                        "Section ",
                        $section,
                        " makes the forwarding preference a property of the Object, so a \
                         datagram for a track whose objects have used subgroup streams is \
                         legal here"
                    ));
                let meta = datagram.meta();
                assert_eq!(
                    (meta.track_alias, meta.group_id, meta.object_id),
                    (ALIAS, GROUP_ID, OBJECT_ID),
                    "the datagram that came back is not the one the peer sent"
                );

                tokio::time::timeout(PATIENCE * 3, peer)
                    .await
                    .expect("peer task hung")
                    .expect("peer task panicked");
            }

            /// The other end of the same sentence: this endpoint will write one
            /// track's objects two ways as well.
            ///
            /// The nine drafts that state the rule name the Original Publisher,
            /// so their writers refuse the second framing. These three do not,
            /// and an endpoint subscribed to a track and publishing that track's
            /// objects — which is a relay, the topology the drafts are written
            /// around — may frame each Object as it likes.
            #[tokio::test]
            async fn one_track_may_be_written_two_ways() {
                let (conn, peer) = subscribed(false).await;

                let header = AnySubgroupHeader::$version(subgroup_header());
                tokio::time::timeout(PATIENCE, conn.open_subgroup_stream(&header))
                    .await
                    .expect("opening the subgroup stream did not finish")
                    .expect("the track's first framing");

                let datagram = AnyDatagramHeader::$version(datagram_header());
                conn.send_datagram(&datagram, b"").expect(concat!(
                    "Section ",
                    $section,
                    " makes the forwarding preference a property of the Object, so a \
                     publisher may send one track's objects both ways"
                ));

                tokio::time::timeout(PATIENCE * 3, peer)
                    .await
                    .expect("peer task hung")
                    .expect("peer task panicked");
            }
        }
    };
}

object_forwarding_preference_gate!(draft17, "draft17", Draft17, "10.2.1");
object_forwarding_preference_gate!(draft18, "draft18", Draft18, "11.2.1");
object_forwarding_preference_gate!(draft19, "draft19", Draft19, "11.2.1");

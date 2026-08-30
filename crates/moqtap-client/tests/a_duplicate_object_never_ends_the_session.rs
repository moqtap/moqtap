#![cfg(any(
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19"
))]

//! A duplicate Object that contradicts the one before it never ends the
//! session, on any of the nine drafts that have a rule about it.
//!
//! Draft-19 Section 9.1 states the rule: "An endpoint that receives a duplicate
//! Object with a different Forwarding Preference, Subgroup ID, Priority or
//! Payload MUST treat the track as Malformed." It arrives in draft-11 and is
//! carried by every draft after it, in three wordings that differ only in what
//! they do with the Object Status clause. Drafts 11 through 14 write it "An
//! endpoint that receives a duplicate Object with an invalid Object Status
//! change, or a Forwarding Preference, Subgroup ID, Priority or Payload that
//! differ from a previous version MUST treat the track as Malformed";
//! draft-15 rewrites the tail as "or with a different Forwarding Preference,
//! Subgroup ID, Priority or Payload"; draft-16 drops the status clause and
//! leaves the four fields alone. The four fields never change, and this file is
//! about two of them.
//!
//! # What "treat the track as Malformed" costs a session, which is nothing
//!
//! The four drafts that answer it agree on one thing and disagree on the rest,
//! and none of the answers is a close. Drafts 12 and 13 say, at Section 2.5,
//! "When a subscriber detects a Malformed Track, it MUST UNSUBSCRIBE from the
//! Track and SHOULD deliver an error to the application." Drafts 14 through 16
//! widen it to fetches — draft-15 Section 2.4.2: "it MUST UNSUBSCRIBE any
//! subscription and FETCH_CANCEL any fetch for that Track from that publisher,
//! and SHOULD deliver an error to the application." Drafts 17 through 19 point
//! at the transport instead — draft-19 Section 2.4.2: "it MUST cancel any
//! corresponding subscription or fetches for that Track from that publisher
//! (see Section 3.3.3), and SHOULD deliver an error to the application."
//!
//! Three answers, one track withdrawn, and the session left standing in all
//! three. So whatever this crate eventually does about a Malformed Track, the
//! gates here are the floor underneath it: a duplicate that contradicts its
//! predecessor is a reason to stop asking for a track, never a reason to end
//! the connection carrying it.
//!
//! # Draft-11 names a consequence it never defines
//!
//! Draft-11 is where "MUST treat the track as Malformed" first appears, and the
//! phrase "Malformed Track" does not occur anywhere in that draft — there is no
//! Section 2.5 to point at, no condition list, and no answer. The Malformed
//! Tracks section arrives in draft-12, one draft behind the sentence that needs
//! it.
//!
//! That makes draft-11 the likeliest place to reach for the wrong answer, and
//! the wrong answer is a close: an endpoint told a track is malformed, with
//! nothing in the draft saying what that costs, has a Protocol Violation code
//! sitting right there in Section 3.4's table. The gates say it does not
//! qualify. **A draft that names a fault without naming its consequence has
//! not thereby permitted the worst one.**
//!
//! # Two fields, and two sentences reaching the same fact
//!
//! Payload and Priority are the two of the four that a single subscription can
//! contradict itself on without tripping a different rule. Forwarding
//! Preference is a rule of its own on these drafts and is gated next door in
//! `a_track_keeps_one_forwarding_preference.rs`, and a duplicate with a
//! different Subgroup ID is not reachable without also changing the stream it
//! arrived on.
//!
//! Priority is reached twice over on the last four drafts. Besides the
//! duplicate-Object sentence, the Malformed Tracks list itself carries "In a
//! FETCH response, an Object with a particular Subgroup ID is received, but its
//! Publisher Priority is different from that of the previous Object with the
//! same Subgroup ID" on drafts 16 and 17 — and drafts 18 and 19 delete the
//! first four words, so on those two the list condition covers a subscription's
//! objects as well as a fetch's. The gate is the same either way; the number of
//! sentences it answers is not.
//!
//! # Holding everything else equal
//!
//! Each gate changes exactly one field between the two copies of one Object,
//! because every other field in that sentence is a separate condition and a
//! session ended for one of those would look like a pass.
//!
//! * Both copies name the same Track Alias, Group ID and Object ID. That is
//!   what makes the second one a *duplicate* rather than a second object.
//! * Both copies name the same Subgroup ID, so the two streams are two
//!   transport streams carrying one subgroup. Both are finished after their one
//!   object, so the subgroup's final Object is the same in each — the condition
//!   about a subgroup arriving over multiple streams "with different final
//!   Objects" needs them to differ, and here they cannot.
//! * Both copies use one framing. A track that put its first copy on a subgroup
//!   stream and its second on a datagram would be refused for mixing forwarding
//!   preferences on the seven drafts here that hold a track to one, which is
//!   the rule next door and not this one.
//! * The payload gate holds the Publisher Priority equal, and the priority gate
//!   holds the payload equal. Each gate would otherwise answer for both.
//!
//! # Two topologies, one assertion
//!
//! Drafts 11 through 16 put SETUP and every request on a single bidirectional
//! stream; drafts 17, 18 and 19 put control on a pair of unidirectional streams
//! and open a bidirectional stream per request. The three gates are written
//! once, in `dup_common!`, and both peers call it. The split a rule with two
//! peers forces is between the peer and the assertion, not between files.
//!
//! # Why the alias is bound before any of it
//!
//! Every gate completes a SUBSCRIBE and reads its answer before the first
//! object goes out, so the Track Alias the objects name resolves to a track
//! this client is subscribed to. An endpoint that kept a record of the objects
//! it has seen would key that record on a resolved track, so a gate that sent
//! the objects without subscribing would stay green against an endpoint that
//! had the rule and merely could not reach its own record — which is a gate
//! that cannot fail.
//!
//! # Recorded failures
//!
//! Each was produced by giving the client the rule this file says it does not
//! have — a per-track record of every Object seen, and a session closed with
//! Protocol Violation when a later copy disagrees with it — and running the
//! gates. The cut goes into draft-11, draft-15 and draft-18: one draft that has
//! the sentence and no definition of Malformed, one that answers it with an
//! UNSUBSCRIBE, and one that answers it by resetting a stream. Three drafts
//! because a rule with two peers has to be cut into a draft each peer serves,
//! and the third topology is the one draft-11 alone reaches.
//!
//! All nine went red. Draft-11, whose gates name the section the sentence sits
//! in there:
//!
//! ```text
//! Section 7.1 asks for a track to be treated as Malformed, which is not a
//! reason to refuse the object that showed it: Endpoint(DuplicateObjectDiffers
//! { alias: 7, group: 5, object: 2, field: Payload })
//!
//! Section 7.1 asks for a track to be treated as Malformed, which is not a
//! reason to refuse the object that showed it: Endpoint(DuplicateObjectDiffers
//! { alias: 7, group: 5, object: 2, field: Priority })
//!
//! Section 7.1 asks for a track to be treated as Malformed, which is not a
//! reason to refuse the object that showed it: Endpoint(DuplicateObjectDiffers
//! { alias: 7, group: 5, object: 2, field: Payload })
//! ```
//!
//! Draft-15 and draft-18 reported the same three against Section 8.1 and
//! Section 9.1. Every one of the nine names alias 7, which is the other half of
//! the argument above: a record reached by resolving an alias can only report
//! one it resolved, so a gate that had skipped the SUBSCRIBE's answer would
//! have stayed green under the same cut.
//!
//! The middle report is the one worth reading twice. The Priority the two
//! copies disagree on is not in either object — it is in the two stream headers
//! that framed them, which is why the cut had to carry the priority from
//! `accept_subgroup_stream` into the stream before any object could be judged
//! against it. A rule about an Object is not always a rule about an object
//! header.

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

/// The one Object every gate sends twice.
///
/// Both are above zero so that nothing about the location can be mistaken for a
/// default the client filled in.
const GROUP: u64 = 5;
const OBJECT: u64 = 2;

/// The subgroup both copies belong to. One ID, because two would make the
/// second copy an object in a different subgroup rather than the same Object
/// again.
const SUBGROUP: u64 = 0;

/// The Publisher Priority both copies carry, except in the gate that is about
/// the priority.
const PRIORITY: u8 = 128;
const OTHER_PRIORITY: u8 = 129;

/// The two payloads. Different lengths as well as different bytes, so a client
/// that compared only one of the two would still have to disagree.
const FIRST: &[u8] = b"first";
const SECOND: &[u8] = b"second-and-longer";

/// Which of the four fields the second copy of the Object contradicts, and on
/// which framing.
#[derive(Debug, Clone, Copy)]
enum Twice {
    /// Both copies on subgroup streams, differing only in payload.
    Payload,
    /// Both copies on subgroup streams, differing only in the Publisher
    /// Priority their stream headers named.
    Priority,
    /// Both copies on datagrams, differing only in payload.
    OnDatagrams,
}

impl Twice {
    /// The payload each copy carries.
    fn payloads(self) -> (&'static [u8], &'static [u8]) {
        match self {
            // The priority gate holds the payload equal, or it would be
            // answering for the payload gate as well.
            Twice::Priority => (FIRST, FIRST),
            Twice::Payload | Twice::OnDatagrams => (FIRST, SECOND),
        }
    }

    /// The Publisher Priority each copy's stream header names.
    fn priorities(self) -> (u8, u8) {
        match self {
            Twice::Priority => (PRIORITY, OTHER_PRIORITY),
            Twice::Payload | Twice::OnDatagrams => (PRIORITY, PRIORITY),
        }
    }

    fn on_datagrams(self) -> bool {
        matches!(self, Twice::OnDatagrams)
    }
}

/// A quinn receive stream with a buffer in front of it, for the peer that
/// serves the drafts whose control plane is unidirectional.
///
/// It decodes with `moqtap-codec` and never calls the framing helpers in
/// `moqtap-client`: a peer assembled out of the code under test could not
/// disagree with it.
#[cfg(any(feature = "draft17", feature = "draft18", feature = "draft19"))]
struct PeerStream {
    recv: quinn::RecvStream,
    buf: Vec<u8>,
}

#[cfg(any(feature = "draft17", feature = "draft18", feature = "draft19"))]
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
    /// On those three drafts a control stream's leading varint *is* its first
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
                // Two errors mean "not enough bytes yet", and which one it is
                // depends on where the message ran out. A body that stops short
                // is `UnexpectedEnd`; a message whose leading type varint has
                // not arrived fails inside the varint decoder before there is a
                // message to be short, which is what every read before the
                // first one gives.
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

/// Everything that does not depend on the topology: the traffic, the wait that
/// says no session ended, the reads that say both copies arrived, and the three
/// gates.
///
/// `$obj` names how this draft hands a decoded subgroup object back, `$dgram`
/// how it hands back a datagram's payload, and `$section` the section carrying
/// the duplicate-Object sentence.
#[macro_export]
macro_rules! dup_common {
    ($obj:tt, $dgram:tt, $section:literal) => {
        /// Put the Object on the wire twice.
        ///
        /// The first stream is written and finished before the second is
        /// opened, so the two arrive in the order the client reads them in and
        /// the second copy is unambiguously the later one.
        async fn send_it_twice(conn: &quinn::Connection, twice: Twice) {
            let (first_payload, second_payload) = twice.payloads();
            let (first_priority, second_priority) = twice.priorities();

            if twice.on_datagrams() {
                conn.send_datagram(datagram_bytes(first_payload).into())
                    .expect("send the first copy");
                conn.send_datagram(datagram_bytes(second_payload).into())
                    .expect("send the second copy");
            } else {
                let mut first = conn.open_uni().await.expect("open the first data stream");
                first
                    .write_all(&subgroup_stream_bytes(first_priority, first_payload))
                    .await
                    .expect("write the first copy");
                first.finish().expect("finish the first data stream");

                let mut second = conn.open_uni().await.expect("open the second data stream");
                second
                    .write_all(&subgroup_stream_bytes(second_priority, second_payload))
                    .await
                    .expect("write the second copy");
                second.finish().expect("finish the second data stream");
            }
        }

        /// The peer's half of every gate: the session is still standing when
        /// both copies have been read.
        async fn expect_no_close(conn: &quinn::Connection) {
            if let Ok(reason) = tokio::time::timeout(BRIEF, conn.closed()).await {
                panic!(
                    concat!(
                        "Section ",
                        $section,
                        " asks for a track to be treated as Malformed, which no draft answers \
                         by ending the session; it ended with {:?}"
                    ),
                    reason
                );
            }
        }

        /// Drive one gate: connect, subscribe, and read both copies of the
        /// Object.
        ///
        /// The second read is the assertion. It is `expect` rather than a
        /// discarded result because an endpoint that answered this rule with a
        /// close would refuse there, and it names the payload it got back so
        /// that a gate cannot pass on a client that accepted *something*.
        async fn read_it_twice(twice: Twice) -> (Connection, tokio::task::JoinHandle<()>) {
            let (conn, peer) = connected(twice).await;
            let (first_payload, second_payload) = twice.payloads();

            if twice.on_datagrams() {
                for (nth, expected) in [("first", first_payload), ("second", second_payload)] {
                    let (header, payload) = tokio::time::timeout(PATIENCE, conn.recv_datagram())
                        .await
                        .unwrap_or_else(|_| panic!("the peer's {nth} datagram never arrived"))
                        .expect(concat!(
                            "Section ",
                            $section,
                            " asks for a track to be treated as Malformed, which is not a \
                             reason to refuse the object that showed it"
                        ));
                    let meta = header.meta();
                    assert_eq!(
                        (meta.track_alias, meta.group_id, meta.object_id),
                        (ALIAS, GROUP, OBJECT),
                        "both datagrams carry the same Object, which is what makes the second a \
                         duplicate"
                    );
                    assert_eq!(
                        &$crate::dup_datagram_payload!($dgram, header, payload)[..],
                        expected,
                        "the {nth} datagram came back with a payload the peer did not send"
                    );
                }
            } else {
                for (nth, expected) in [("first", first_payload), ("second", second_payload)] {
                    let (header, mut stream) =
                        tokio::time::timeout(PATIENCE, conn.accept_subgroup_stream())
                            .await
                            .unwrap_or_else(|_| {
                                panic!("the peer's {nth} data stream never arrived")
                            })
                            .unwrap_or_else(|e| panic!("read the {nth} subgroup header: {e:?}"));
                    assert_eq!(
                        (header.track_alias(), header.group_id()),
                        (ALIAS, GROUP),
                        "both streams carry the same Object, which is what makes the second a \
                         duplicate"
                    );
                    let object = tokio::time::timeout(PATIENCE, stream.read_subgroup_object())
                        .await
                        .unwrap_or_else(|_| panic!("the {nth} copy never arrived"))
                        .expect(concat!(
                            "Section ",
                            $section,
                            " asks for a track to be treated as Malformed, which is not a \
                             reason to refuse the object that showed it"
                        ));
                    assert_eq!(
                        $crate::dup_read_back!($obj, object),
                        (OBJECT, expected.to_vec()),
                        "the {nth} object came back as something the peer did not send"
                    );
                }
            }

            (conn, peer)
        }

        async fn finish(peer: tokio::task::JoinHandle<()>) {
            tokio::time::timeout(PATIENCE * 3, peer)
                .await
                .expect("peer task hung")
                .expect("peer task panicked");
        }

        /// The same Object twice, the second copy carrying a different payload.
        ///
        /// The Payload half of the four fields, and the one a receiver can only
        /// notice by having kept the first copy's bytes.
        #[tokio::test]
        async fn a_duplicate_object_whose_payload_differs_is_accepted() {
            let (_conn, peer) = read_it_twice(Twice::Payload).await;
            finish(peer).await;
        }

        /// The same Object twice, the second copy arriving under a different
        /// Publisher Priority.
        ///
        /// The Priority half, which is spelled in the stream header rather than
        /// in the object — so a client that kept only what an object header
        /// carries would have nothing to compare.
        #[tokio::test]
        async fn a_duplicate_object_whose_priority_differs_is_accepted() {
            let (_conn, peer) = read_it_twice(Twice::Priority).await;
            finish(peer).await;
        }

        /// The payload contradiction again, on the other data path.
        ///
        /// Both copies are datagrams: a track that used one framing for each
        /// would be refused for mixing them on most of these drafts, which is a
        /// different rule.
        #[tokio::test]
        async fn a_duplicate_carried_by_datagrams_is_accepted_the_same_way() {
            let (_conn, peer) = read_it_twice(Twice::OnDatagrams).await;
            finish(peer).await;
        }
    };
}

/// One draft's gates, where SETUP and every request travel on one bidirectional
/// stream.
///
/// `$draft` is the draft's module in both crates, `$version` its `DraftVersion`
/// and dispatch variant, and `$section` the section carrying the
/// duplicate-Object sentence. The rest name the shapes that differ across the
/// six: `$cfg` and `$setup` for the session, `$sub`, `$bind`, `$ok` and
/// `$idfield` for the subscription that binds the alias, and `$hdr`, `$write`,
/// `$obj` and `$dgram` for the ways an object is spelled and read back.
macro_rules! bidirectional_duplicate_gates {
    ($draft:ident, $feat:literal, $version:ident, $cfg:tt, $setup:tt, $sub:tt, $bind:tt, $ok:tt,
     $idfield:tt, $hdr:tt, $write:tt, $obj:tt, $dgram:tt, $section:literal) => {
        #[cfg(feature = $feat)]
        mod $draft {
            use moqtap_client::$draft::connection::{ClientConfig, Connection, TransportType};
            use moqtap_codec::dispatch::{AnyControlMessage, AnyDatagramHeader, AnySubgroupHeader};
            use moqtap_codec::kvp::{KeyValuePair, KvpValue};
            use moqtap_codec::types::TrackNamespace;
            use moqtap_codec::varint::VarInt;
            use moqtap_codec::version::DraftVersion;
            #[allow(unused_imports)]
            use moqtap_codec::$draft::message::{ControlMessage, ServerSetup, SubscribeOk};

            use crate::{Twice, ALIAS, BRIEF, GROUP, OBJECT, PATIENCE, PRIORITY, SUBGROUP, TRACK};

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
                crate::dup_config_for!($cfg, DraftVersion::$version, setup_parameters())
            }

            fn server_setup() -> ServerSetup {
                crate::dup_server_setup_for!($setup, DraftVersion::$version, setup_parameters())
            }

            fn encode(msg: ControlMessage) -> Vec<u8> {
                let mut out = Vec::new();
                AnyControlMessage::$version(msg).encode(&mut out).expect("encode");
                out
            }

            /// The Request ID the client's SUBSCRIBE carried, or a panic naming
            /// what arrived instead.
            fn request_id_of(msg: &AnyControlMessage) -> VarInt {
                match msg {
                    AnyControlMessage::$version(ControlMessage::Subscribe(s)) => {
                        crate::dup_request_id_of!($idfield, s)
                    }
                    other => panic!("expected a SUBSCRIBE from the client, got {other:?}"),
                }
            }

            /// One subgroup stream carrying one copy of the Object.
            ///
            /// The object goes through whatever writer this draft gives it, so
            /// the delta encoding the later ones apply to an Object ID is the
            /// codec's and not this test's idea of it.
            fn subgroup_stream_bytes(priority: u8, payload: &[u8]) -> Vec<u8> {
                let header = crate::dup_subgroup_header_for!(
                    $hdr,
                    $draft,
                    v(ALIAS),
                    v(GROUP),
                    v(SUBGROUP),
                    priority
                );
                let mut buf = Vec::new();
                AnySubgroupHeader::$version(header.clone())
                    .encode_stream_checked(&mut buf)
                    .expect("encode the subgroup header");
                crate::dup_write_object!($write, $draft, header, buf, v(OBJECT), payload);
                buf
            }

            /// The same copy, carried by a datagram.
            fn datagram_bytes(payload: &[u8]) -> Vec<u8> {
                let header = crate::dup_datagram_for!(
                    $dgram,
                    $draft,
                    v(ALIAS),
                    v(GROUP),
                    v(OBJECT),
                    payload
                );
                let mut buf = Vec::new();
                AnyDatagramHeader::$version(header).encode(&mut buf).expect("encode the datagram");
                crate::dup_datagram_tail!($dgram, buf, payload);
                buf
            }

            /// Serve one connection: complete the setup exchange, bind the
            /// Track Alias, and send the Object twice.
            async fn serve(server: quinn::Endpoint, twice: Twice) {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");

                let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
                let mut framed = crate::common::frame_uni_recv(recv, DraftVersion::$version);
                framed.read_control(false).await.expect("read CLIENT_SETUP");
                send.write_all(&encode(ControlMessage::ServerSetup(server_setup())))
                    .await
                    .expect("write SERVER_SETUP");

                let (request, _) = framed.read_control(false).await.expect("read SUBSCRIBE");
                crate::dup_answer_subscribe!($bind, $ok, send, request_id_of(&request));

                send_it_twice(&conn, twice).await;
                expect_no_close(&conn).await;
            }

            /// A connected client whose SUBSCRIBE has been answered, and the
            /// task serving it.
            async fn connected(twice: Twice) -> (Connection, tokio::task::JoinHandle<()>) {
                crate::common::init_crypto();
                let (endpoint, addr) =
                    crate::common::spawn_server(&[DraftVersion::$version.quic_alpn()]);
                let peer = tokio::spawn(serve(endpoint, twice));

                #[allow(unused_mut)]
                let mut conn = tokio::time::timeout(
                    PATIENCE,
                    Connection::connect(&addr.to_string(), client_config()),
                )
                .await
                .expect("connect did not finish")
                .expect("connect");

                crate::dup_subscribe_for!($sub, conn, namespace(), TRACK, v(ALIAS))
                    .await
                    .expect("subscribe");
                crate::dup_await_binding!($bind, conn);
                (conn, peer)
            }

            crate::dup_common!($obj, $dgram, $section);
        }
    };
}

/// One draft's gates, where control travels on a pair of unidirectional streams
/// and every request opens a bidirectional stream of its own.
///
/// These three share every shape a gate needs, so the only thing that varies is
/// the draft itself and the section its duplicate-Object sentence sits in.
macro_rules! unidirectional_duplicate_gates {
    ($draft:ident, $feat:literal, $version:ident, $section:literal) => {
        #[cfg(feature = $feat)]
        mod $draft {
            use moqtap_client::$draft::connection::{ClientConfig, Connection, TransportType};
            use moqtap_codec::dispatch::{AnyControlMessage, AnyDatagramHeader, AnySubgroupHeader};
            use moqtap_codec::types::TrackNamespace;
            use moqtap_codec::varint::VarInt;
            use moqtap_codec::version::DraftVersion;
            use moqtap_codec::$draft::message::{ControlMessage, Setup, SubscribeOk};

            use crate::{
                PeerStream, Twice, ALIAS, BRIEF, GROUP, OBJECT, PATIENCE, PRIORITY, SUBGROUP, TRACK,
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

            /// One subgroup stream carrying one copy of the Object.
            fn subgroup_stream_bytes(priority: u8, payload: &[u8]) -> Vec<u8> {
                let header = crate::dup_subgroup_header_for!(
                    byte,
                    $draft,
                    v(ALIAS),
                    v(GROUP),
                    v(SUBGROUP),
                    priority
                );
                let mut buf = Vec::new();
                AnySubgroupHeader::$version(header.clone())
                    .encode_stream_checked(&mut buf)
                    .expect("encode the subgroup header");
                crate::dup_write_object!(measured, $draft, header, buf, v(OBJECT), payload);
                buf
            }

            /// The same copy, carried by a datagram.
            fn datagram_bytes(payload: &[u8]) -> Vec<u8> {
                let header =
                    crate::dup_datagram_for!(prop, $draft, v(ALIAS), v(GROUP), v(OBJECT), payload);
                let mut buf = Vec::new();
                AnyDatagramHeader::$version(header).encode(&mut buf).expect("encode the datagram");
                crate::dup_datagram_tail!(prop, buf, payload);
                buf
            }

            /// Serve one connection: complete the setup exchange, answer the
            /// client's SUBSCRIBE with the Track Alias, and send the Object
            /// twice.
            ///
            /// Every stream the peer opened or accepted is held until this
            /// returns. Dropping a quinn send stream resets it, and on these
            /// drafts a request stream's reset is how a request is withdrawn —
            /// so letting the SUBSCRIBE's stream fall out of scope early would
            /// cancel the subscription, free the alias, and leave the objects
            /// naming a track that no longer resolves.
            async fn serve(server: quinn::Endpoint, twice: Twice) {
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

                send_it_twice(&conn, twice).await;
                expect_no_close(&conn).await;
            }

            /// A connected client whose SUBSCRIBE has been answered, and the
            /// task serving it.
            ///
            /// The answer is read off the request stream it went out on, which
            /// is what carries it into the endpoint and binds the alias. Its
            /// Track Alias is asserted here rather than taken on trust: a peer
            /// that answered with a different one would leave every later
            /// assertion about a track this client never heard of.
            async fn connected(twice: Twice) -> (Connection, tokio::task::JoinHandle<()>) {
                crate::common::init_crypto();
                let (endpoint, addr) =
                    crate::common::spawn_server(&[DraftVersion::$version.quic_alpn()]);
                let peer = tokio::spawn(serve(endpoint, twice));

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

            crate::dup_common!(flat, prop, $section);
        }
    };
}

/// `ClientConfig`, in the three shapes it takes across the six drafts whose
/// control plane is bidirectional.
#[macro_export]
macro_rules! dup_config_for {
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

/// SERVER_SETUP, with and without the Selected Version drafts 15 and 16
/// dropped.
#[macro_export]
macro_rules! dup_server_setup_for {
    (versioned, $version:expr, $params:expr) => {
        ServerSetup { selected_version: $version.version_varint(), parameters: $params }
    };
    (plain, $version:expr, $params:expr) => {
        ServerSetup { parameters: $params }
    };
}

/// What a SUBSCRIBE calls the identifier it carries.
#[macro_export]
macro_rules! dup_request_id_of {
    (request_id, $s:expr) => {
        $s.request_id
    };
}

/// `Connection::subscribe`, in the four shapes it takes across those six.
///
/// Draft-11 carries the Track Alias in the SUBSCRIBE itself; the rest wait for
/// it in the answer, and take `$alias` only to be ignored.
#[macro_export]
macro_rules! dup_subscribe_for {
    (alias_varint, $conn:expr, $ns:expr, $name:expr, $alias:expr) => {
        $conn.subscribe(
            $alias,
            $ns,
            $name.to_vec(),
            PRIORITY,
            moqtap_codec::types::GroupOrder::Ascending,
            VarInt::from_u64(0x2).unwrap(),
        )
    };
    (varint, $conn:expr, $ns:expr, $name:expr, $alias:expr) => {{
        let _ = $alias;
        $conn.subscribe(
            $ns,
            $name.to_vec(),
            PRIORITY,
            moqtap_codec::types::GroupOrder::Ascending,
            VarInt::from_u64(0x2).unwrap(),
            Vec::new(),
        )
    }};
    (filter, $conn:expr, $ns:expr, $name:expr, $alias:expr) => {{
        let _ = $alias;
        $conn.subscribe(
            $ns,
            $name.to_vec(),
            PRIORITY,
            moqtap_codec::types::GroupOrder::Ascending,
            moqtap_codec::types::FilterType::LargestObject,
            Vec::new(),
        )
    }};
    (params, $conn:expr, $ns:expr, $name:expr, $alias:expr) => {{
        let _ = $alias;
        $conn.subscribe($ns, $name.to_vec(), Vec::new())
    }};
}

/// SUBSCRIBE_OK, in the three shapes those five drafts give the answer that
/// carries the alias.
#[macro_export]
macro_rules! dup_subscribe_ok_for {
    (rich, $id:expr, $alias:expr) => {
        SubscribeOk {
            request_id: $id,
            track_alias: $alias,
            expires: VarInt::from_u64(0).unwrap(),
            group_order: moqtap_codec::types::GroupOrder::Ascending,
            content_exists: moqtap_codec::types::ContentExists::NoLargestLocation,
            largest_location: None,
            parameters: Vec::new(),
        }
    };
    (plain, $id:expr, $alias:expr) => {
        SubscribeOk { request_id: $id, track_alias: $alias, parameters: Vec::new() }
    };
    (ext, $id:expr, $alias:expr) => {
        SubscribeOk {
            request_id: $id,
            track_alias: $alias,
            parameters: Vec::new(),
            track_extensions: Vec::new(),
        }
    };
}

/// The peer's half of binding the alias.
///
/// Draft-11 bound it in the SUBSCRIBE the client already sent, so its peer has
/// nothing left to answer with.
#[macro_export]
macro_rules! dup_answer_subscribe {
    (in_subscribe, $ok:tt, $send:expr, $id:expr) => {{
        let _ = $id;
    }};
    (in_answer, $ok:tt, $send:expr, $id:expr) => {{
        let reply = $crate::dup_subscribe_ok_for!($ok, $id, v(ALIAS));
        $send
            .write_all(&encode(ControlMessage::SubscribeOk(reply)))
            .await
            .expect("write SUBSCRIBE_OK");
    }};
}

/// The client's half of the same.
#[macro_export]
macro_rules! dup_await_binding {
    (in_subscribe, $conn:expr) => {{}};
    (in_answer, $conn:expr) => {{
        tokio::time::timeout(PATIENCE, $conn.recv_and_dispatch())
            .await
            .expect("the answer carrying the alias never arrived")
            .expect("dispatch SUBSCRIBE_OK");
    }};
}

/// A conforming subgroup header, in the three shapes it takes across the nine.
///
/// Every one names an explicit Subgroup ID and carries neither extensions nor
/// properties, which is the plainest stream each draft can carry. The
/// Publisher Priority is the field one gate varies, so it is a parameter rather
/// than a constant.
#[macro_export]
macro_rules! dup_subgroup_header_for {
    (typed, $draft:ident, $alias:expr, $group:expr, $subgroup:expr, $priority:expr) => {
        moqtap_codec::$draft::data_stream::SubgroupHeader {
            stream_type: moqtap_codec::$draft::data_stream::StreamType::SubgroupExplicit,
            track_alias: $alias,
            group_id: $group,
            subgroup_id: $subgroup,
            publisher_priority: $priority,
        }
    };
    (opt, $draft:ident, $alias:expr, $group:expr, $subgroup:expr, $priority:expr) => {
        moqtap_codec::$draft::data_stream::SubgroupHeader {
            stream_type: moqtap_codec::$draft::data_stream::SubgroupStreamType::from_flags(
                true, false, false, false,
            ),
            track_alias: $alias,
            group_id: $group,
            subgroup_id: Some($subgroup),
            publisher_priority: $priority,
        }
    };
    (byte, $draft:ident, $alias:expr, $group:expr, $subgroup:expr, $priority:expr) => {
        moqtap_codec::$draft::data_stream::SubgroupHeader {
            // The subgroup base (0x10) with the explicit Subgroup ID bit
            // (0x04): nothing per-object, no end-of-group, priority present.
            header_type: 0x14,
            track_alias: $alias,
            group_id: $group,
            subgroup_id: $subgroup,
            publisher_priority: Some($priority),
        }
    };
}

/// One object onto the stream `$header` opened, in the three shapes it takes.
///
/// Two of them go through the codec's own `SubgroupObjectReader`, so the delta
/// encoding those drafts give an Object ID is the codec's and not this test's
/// idea of it. Drafts 11 through 13 have no such reader and need none: their
/// Object IDs are absolute, so the object is a header and a payload written
/// straight out.
#[macro_export]
macro_rules! dup_write_object {
    (nested, $draft:ident, $header:expr, $buf:expr, $object:expr, $payload:expr) => {{
        let _ = &$header;
        moqtap_codec::$draft::data_stream::ObjectHeader {
            object_id: $object,
            extension_headers_length: VarInt::from_usize(0),
            extensions: Vec::new(),
            payload_length: VarInt::from_usize($payload.len()),
            // The status field is not optional on these drafts, and Normal is
            // what an object carrying a payload has.
            object_status: moqtap_codec::$draft::types::ObjectStatus::Normal,
        }
        .encode_checked(&mut $buf)
        .expect("encode the object header");
        $buf.extend_from_slice($payload);
    }};
    (staged, $draft:ident, $header:expr, $buf:expr, $object:expr, $payload:expr) => {{
        let mut writer = moqtap_codec::$draft::data_stream::SubgroupObjectReader::new(&$header);
        writer
            .write_object(
                &moqtap_codec::$draft::data_stream::SubgroupObject {
                    object_id: $object,
                    extension_headers: Vec::new(),
                    status: None,
                    payload: $payload.to_vec(),
                },
                &mut $buf,
            )
            .expect("encode the object");
    }};
    (measured, $draft:ident, $header:expr, $buf:expr, $object:expr, $payload:expr) => {{
        let mut writer = moqtap_codec::$draft::data_stream::SubgroupObjectReader::new(&$header);
        writer
            .write_object(
                &moqtap_codec::$draft::data_stream::SubgroupObject {
                    object_id: $object,
                    extension_headers: Vec::new(),
                    payload_length: VarInt::from_usize($payload.len()),
                    object_status: None,
                    payload: $payload.to_vec(),
                },
                &mut $buf,
            )
            .expect("encode the object");
    }};
}

/// The Object ID and payload of an object the client decoded, in the two shapes
/// the nine hand back.
///
/// Drafts 11 through 13 return the header beside the payload; the rest flatten
/// the two.
#[macro_export]
macro_rules! dup_read_back {
    (nested, $object:expr) => {
        ($object.header.object_id.into_inner(), $object.payload.clone())
    };
    (flat, $object:expr) => {
        ($object.object_id.into_inner(), $object.payload.clone())
    };
}

/// A datagram carrying one copy of the Object, in the five shapes it takes.
#[macro_export]
macro_rules! dup_datagram_for {
    (measured, $draft:ident, $alias:expr, $group:expr, $object:expr, $payload:expr) => {{
        let _ = $payload;
        moqtap_codec::$draft::data_stream::Datagram::Payload(
            moqtap_codec::$draft::data_stream::DatagramHeader {
                track_alias: $alias,
                group_id: $group,
                object_id: $object,
                publisher_priority: PRIORITY,
                extension_headers_length: VarInt::from_usize(0),
                extensions: Vec::new(),
            },
        )
    }};
    (grouped, $draft:ident, $alias:expr, $group:expr, $object:expr, $payload:expr) => {{
        let _ = $payload;
        moqtap_codec::$draft::data_stream::Datagram::Payload(
            moqtap_codec::$draft::data_stream::DatagramHeader {
                track_alias: $alias,
                group_id: $group,
                object_id: $object,
                publisher_priority: PRIORITY,
                extension_headers_length: VarInt::from_usize(0),
                extensions: Vec::new(),
                end_of_group: false,
            },
        )
    }};
    (typed, $draft:ident, $alias:expr, $group:expr, $object:expr, $payload:expr) => {
        moqtap_codec::$draft::data_stream::DatagramObject {
            datagram_type: moqtap_codec::$draft::data_stream::DatagramType::payload(
                true, false, false,
            ),
            track_alias: $alias,
            group_id: $group,
            object_id: $object,
            publisher_priority: PRIORITY,
            extension_headers: Vec::new(),
            status: None,
            payload: $payload.to_vec(),
        }
    };
    (byte, $draft:ident, $alias:expr, $group:expr, $object:expr, $payload:expr) => {{
        let _ = $payload;
        moqtap_codec::$draft::data_stream::DatagramHeader {
            // A payload datagram with the Object ID written, the priority
            // present and no extensions.
            datagram_type: 0x00,
            track_alias: $alias,
            group_id: $group,
            object_id: $object,
            publisher_priority: Some(PRIORITY),
            extension_headers: Vec::new(),
            object_status: None,
        }
    }};
    (prop, $draft:ident, $alias:expr, $group:expr, $object:expr, $payload:expr) => {{
        let _ = $payload;
        moqtap_codec::$draft::data_stream::DatagramHeader {
            // The same byte, against a draft that calls the per-object block
            // properties rather than extension headers.
            datagram_type: 0x00,
            track_alias: $alias,
            group_id: $group,
            object_id: $object,
            publisher_priority: Some(PRIORITY),
            properties: Vec::new(),
            object_status: None,
        }
    }};
}

/// Whether the payload still has to be written after the header.
///
/// Draft-14 alone models a datagram as a whole object and carries the payload
/// inside it; every other draft here leaves the payload as the rest of the
/// packet.
#[macro_export]
macro_rules! dup_datagram_tail {
    (typed, $buf:expr, $payload:expr) => {{
        let _ = (&$buf, $payload);
    }};
    ($other:tt, $buf:expr, $payload:expr) => {
        $buf.extend_from_slice($payload)
    };
}

/// The payload of a datagram the client decoded, from whichever half of the
/// pair holds it.
#[macro_export]
macro_rules! dup_datagram_payload {
    (typed, $header:expr, $payload:expr) => {{
        // Draft-14's decoder reads the payload into the object, so the bytes
        // beside it are empty by construction rather than by accident.
        assert!($payload.is_empty(), "draft-14 carries the payload inside the datagram object");
        match &$header {
            moqtap_codec::dispatch::AnyDatagramHeader::Draft14(object) => object.payload.clone(),
            // How many variants this enum has depends on which drafts the build
            // enabled, so the arm below is dead in a draft-14-only build and
            // load-bearing in every other one.
            #[allow(unreachable_patterns)]
            other => panic!("expected a draft-14 datagram, got {other:?}"),
        }
    }};
    ($other:tt, $header:expr, $payload:expr) => {{
        let _ = &$header;
        $payload.to_vec()
    }};
}

bidirectional_duplicate_gates!(
    draft11,
    "draft11",
    Draft11,
    early,
    versioned,
    alias_varint,
    in_subscribe,
    rich,
    request_id,
    typed,
    nested,
    nested,
    measured,
    "7.1"
);
bidirectional_duplicate_gates!(
    draft12, "draft12", Draft12, early, versioned, varint, in_answer, rich, request_id, typed,
    nested, nested, grouped, "7.1"
);
bidirectional_duplicate_gates!(
    draft13, "draft13", Draft13, early, versioned, filter, in_answer, rich, request_id, typed,
    nested, nested, grouped, "7.1"
);
bidirectional_duplicate_gates!(
    draft14, "draft14", Draft14, both, versioned, filter, in_answer, rich, request_id, opt, staged,
    flat, typed, "8.1"
);
bidirectional_duplicate_gates!(
    draft15, "draft15", Draft15, late, plain, params, in_answer, plain, request_id, byte, measured,
    flat, byte, "8.1"
);
bidirectional_duplicate_gates!(
    draft16, "draft16", Draft16, late, plain, params, in_answer, ext, request_id, byte, measured,
    flat, byte, "8.1"
);

unidirectional_duplicate_gates!(draft17, "draft17", Draft17, "8.1");
unidirectional_duplicate_gates!(draft18, "draft18", Draft18, "9.1");
unidirectional_duplicate_gates!(draft19, "draft19", Draft19, "9.1");

#![cfg(any(
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20",
    feature = "draft21",
    feature = "draft22",
    feature = "draft23"
))]

//! A received datagram is read whole, and a Prior gap fault on a datagram, a
//! subgroup stream or a fetch stream is answered the way its draft's Malformed
//! Tracks section answers a subscriber, without closing the session. So is a
//! property block that does not parse, on drafts 14-23: draft-14 Section 11.2
//! and draft-23 Section 10.7, "A Key-Value-Pair cannot be parsed." Drafts
//! 12-13 list no such condition, so nothing is withdrawn there. The datagram
//! faults a draft answers with a close do close it.
//!
//! draft-11 Section 10.1, draft-12 Section 10.1 and draft-13 Section 10.1: "A
//! track with a Group that contains more than one Object with different values
//! for Prior Group ID Gap or has a Prior Group ID Gap larger than the Group ID
//! is considered malformed." Draft-11 has no Malformed Tracks section, so
//! nothing is withdrawn there.
//!
//! draft-12 Section 2.5 and draft-13 Section 2.5: "When a subscriber detects a
//! Malformed Track, it MUST UNSUBSCRIBE from the Track and SHOULD deliver an
//! error to the application."
//!
//! draft-14 Section 2.5, draft-15 Section 2.4.2 and draft-16 Section 2.4.2:
//! "When a subscriber detects a Malformed Track, it MUST UNSUBSCRIBE any
//! subscription and FETCH_CANCEL any fetch for that Track from that publisher,
//! and SHOULD deliver an error to the application."
//!
//! draft-17 Section 2.4.2, draft-18 Section 2.4.2, draft-19 Section 2.4.2,
//! draft-20 Section 2.4.2, draft-21 Section 12.1, draft-22 Section 12.1 and
//! draft-23 Section 12.1: "When a subscriber detects a Malformed Track, it MUST
//! cancel any corresponding subscription or fetches for that Track from that
//! publisher". Cancelling is a reset of the request's own stream, which the
//! caller holds, so these gates read the ids `requests_to_cancel` names.
//!
//! A group gap fault is one Object in Group 1 with a Prior Group ID Gap of 2,
//! and an object gap fault Object 0 with a Prior Object ID Gap of 2: each gap
//! is "larger than" the ID it is measured from.

mod common;

use std::time::Duration;

use moqtap_codec::varint::VarInt;

const PATIENCE: Duration = Duration::from_secs(10);

/// Long enough that a message on its way would have arrived.
const BRIEF: Duration = Duration::from_millis(400);

const ALIAS: u64 = 7;
#[allow(dead_code)]
const TRACK: &[u8] = b"one-track";
const GROUP: u64 = 1;
const GAP: u64 = 2;

/// Type 0x01, Track Alias 7, Group 1, Object 0, Publisher Priority 128, an
/// Extension Headers Length of 0, and one payload byte. Type 0x01 announces an
/// extension block, an Object ID and a Publisher Priority on drafts 11 to 16.
#[allow(dead_code)]
const EMPTY_EXTENSIONS: &[u8] = &[0x01, 0x07, 0x01, 0x00, 0x80, 0x00, 0xAA];

fn v(n: u64) -> VarInt {
    VarInt::from_u64(n).unwrap()
}

/// One gap of `GAP`, as an extension or property block.
fn gap_block(gap_type: u64) -> Vec<u8> {
    let mut block = Vec::new();
    v(gap_type).encode(&mut block);
    v(GAP).encode(&mut block);
    block
}

/// A status datagram of `status_type` with no extension block, Object Status
/// End of Group (0x03), and one byte after it.
#[allow(dead_code)]
fn payload_after_status(status_type: u8) -> Vec<u8> {
    vec![status_type, 0x07, 0x01, 0x00, 0x80, 0x03, 0xAA]
}

/// Draft-11: a gap datagram is refused and the session stays open. There is
/// no Malformed Tracks section to withdraw by, so no subscription is needed.
#[cfg(feature = "draft11")]
mod draft11 {
    use super::{
        gap_block, payload_after_status, v, ALIAS, BRIEF, EMPTY_EXTENSIONS, GROUP, PATIENCE,
    };
    use moqtap_client::draft11::connection::{
        ClientConfig, Connection, ConnectionError, TransportType,
    };
    use moqtap_codec::dispatch::{AnyControlMessage, AnyDatagramHeader};
    use moqtap_codec::draft11::data_stream::{Datagram, DatagramHeader, PRIOR_GROUP_ID_GAP};
    use moqtap_codec::draft11::message::{ControlMessage, ServerSetup};
    use moqtap_codec::error::CodecError;
    use moqtap_codec::kvp::{KeyValuePair, KvpValue};
    use moqtap_codec::version::DraftVersion;

    fn setup_parameters() -> Vec<KeyValuePair> {
        vec![KeyValuePair { key: v(0x02), value: KvpValue::Varint(v(100)) }]
    }

    fn gap_datagram() -> Vec<u8> {
        let extensions = gap_block(PRIOR_GROUP_ID_GAP);
        let datagram = Datagram::Payload(DatagramHeader {
            track_alias: v(ALIAS),
            group_id: v(GROUP),
            object_id: v(0),
            publisher_priority: 128,
            extension_headers_length: v(extensions.len() as u64),
            extensions,
        });
        let mut buf = Vec::new();
        AnyDatagramHeader::Draft11(datagram).encode(&mut buf).expect("encode the datagram");
        buf
    }

    /// Send `datagram` and report whether the session was closed.
    async fn peer(server: quinn::Endpoint, datagram: Vec<u8>) -> bool {
        let conn = server.accept().await.expect("accept").await.expect("tls handshake");
        let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
        let mut framed = crate::common::frame_uni_recv(recv, DraftVersion::Draft11);
        framed.read_control(false).await.expect("read CLIENT_SETUP");
        let setup = ServerSetup {
            selected_version: DraftVersion::Draft11.version_varint(),
            parameters: setup_parameters(),
        };
        let mut out = Vec::new();
        AnyControlMessage::Draft11(ControlMessage::ServerSetup(setup))
            .encode(&mut out)
            .expect("encode SERVER_SETUP");
        send.write_all(&out).await.expect("write SERVER_SETUP");
        conn.send_datagram(datagram.into()).expect("send the datagram");
        while let Ok(Ok(_)) = tokio::time::timeout(BRIEF, framed.read_control(false)).await {}
        conn.close_reason().is_some()
    }

    async fn received(
        datagram: Vec<u8>,
    ) -> (Connection, ConnectionError, tokio::task::JoinHandle<bool>) {
        crate::common::init_crypto();
        let (endpoint, addr) = crate::common::spawn_server(&[DraftVersion::Draft11.quic_alpn()]);
        let served = tokio::spawn(peer(endpoint, datagram));
        let config = ClientConfig {
            additional_versions: Vec::new(),
            transport: TransportType::Quic,
            skip_cert_verification: true,
            ca_certs: Vec::new(),
            setup_parameters: setup_parameters(),
        };
        let conn = tokio::time::timeout(PATIENCE, Connection::connect(&addr.to_string(), config))
            .await
            .expect("connect did not finish")
            .expect("connect");
        let err = tokio::time::timeout(PATIENCE, conn.recv_datagram())
            .await
            .expect("the datagram never arrived")
            .expect_err("the datagram was accepted");
        (conn, err, served)
    }

    #[tokio::test]
    async fn a_gap_datagram_is_refused_and_the_session_stays_open() {
        let (conn, err, served) = received(gap_datagram()).await;
        assert!(
            matches!(err, ConnectionError::Codec(CodecError::MalformedTrack { .. })),
            "expected a Malformed Track, got {err:?}"
        );
        assert!(!conn.close_for_data_stream(&err), "the error closed the session");
        assert!(!tokio::time::timeout(PATIENCE * 3, served).await.expect("peer hung").unwrap());
    }

    #[tokio::test]
    async fn a_payload_after_a_status_is_refused_and_the_session_stays_open() {
        let (conn, err, served) = received(payload_after_status(0x02)).await;
        assert!(
            matches!(err, ConnectionError::Codec(CodecError::PayloadNotPermitted { .. })),
            "expected a payload refusal, got {err:?}"
        );
        assert!(!conn.close_for_data_stream(&err), "the error closed the session");
        assert!(!tokio::time::timeout(PATIENCE * 3, served).await.expect("peer hung").unwrap());
    }

    /// Types 0x01 and 0x03 both close the session (draft-11 Section 9.2,
    /// draft-11 Section 9.3).
    #[tokio::test]
    async fn an_empty_extension_block_closes_the_session() {
        for datagram_type in [0x01, 0x03] {
            let mut datagram = EMPTY_EXTENSIONS.to_vec();
            datagram[0] = datagram_type;
            if datagram_type == 0x03 {
                // A status in place of the payload byte: End of Group.
                datagram[6] = 0x03;
            }
            let (conn, err, served) = received(datagram).await;
            assert!(
                matches!(err, ConnectionError::EmptyDatagramExtensions { object_id: 0 }),
                "Type {datagram_type:#04x}: expected an empty extension block, got {err:?}"
            );
            assert!(conn.close_for_data_stream(&err), "the session was not closed");
            assert!(tokio::time::timeout(PATIENCE * 3, served).await.expect("peer hung").unwrap());
        }
    }
}

/// What the peer of a draft 12-16 gate read after its traffic went out.
#[allow(dead_code)]
#[derive(Debug)]
struct Seen {
    /// The SUBSCRIBE's Request ID.
    subscribed: u64,
    /// The FETCH's Request ID, where the client made one.
    fetched: Option<u64>,
    unsubscribed: Vec<u64>,
    fetch_cancelled: Vec<u64>,
    closed: bool,
}

/// Drafts 12-16, whose answer is a control message the connection sends.
macro_rules! message_gates {
    ($draft:ident, $feat:literal, $version:ident, $cfg:tt, $setup:tt, $ok:tt, $sub:tt,
     $dgram:tt, $stream:tt, $condition:ident, $status_type:tt, $late:tt,
     ($fetch:tt $fetch_bytes:tt $fetch_read:tt)) => {
        #[cfg(feature = $feat)]
        mod $draft {
            #[allow(unused_imports)]
            use super::{
                gap_block, payload_after_status, v, Seen, ALIAS, BRIEF, EMPTY_EXTENSIONS, GROUP,
                PATIENCE, TRACK,
            };
            use moqtap_client::malformed_tracks::MalformedTrackCondition;
            use moqtap_client::$draft::connection::{
                ClientConfig, Connection, ConnectionError, TransportType,
            };
            use moqtap_codec::dispatch::{AnyControlMessage, AnyDatagramHeader, AnySubgroupHeader};
            use moqtap_codec::error::CodecError;
            use moqtap_codec::kvp::{KeyValuePair, KvpValue};
            #[allow(unused_imports)]
            use moqtap_codec::types::{ContentExists, GroupOrder, TrackNamespace};
            use moqtap_codec::varint::VarInt;
            use moqtap_codec::version::DraftVersion;
            use moqtap_codec::$draft::data_stream::PRIOR_GROUP_ID_GAP;
            use moqtap_codec::$draft::message::{ControlMessage, ServerSetup, SubscribeOk};

            #[derive(Debug, Clone)]
            enum Traffic {
                Datagram(Vec<u8>),
                #[allow(dead_code)]
                Stream,
                Fetch,
            }

            fn namespace() -> TrackNamespace {
                TrackNamespace(vec![b"conformance".to_vec()])
            }

            fn setup_parameters() -> Vec<KeyValuePair> {
                vec![KeyValuePair { key: v(0x02), value: KvpValue::Varint(v(100)) }]
            }

            fn encode(msg: ControlMessage) -> Vec<u8> {
                let mut out = Vec::new();
                AnyControlMessage::$version(msg).encode(&mut out).expect("encode");
                out
            }

            fn gap_datagram(gap_type: u64) -> Vec<u8> {
                datagram_with(gap_block(gap_type))
            }

            fn datagram_with(extensions: Vec<u8>) -> Vec<u8> {
                let header = crate::gap_datagram!($dgram, $draft, extensions);
                let mut buf = Vec::new();
                AnyDatagramHeader::$version(header).encode(&mut buf).expect("encode the datagram");
                buf
            }

            /// Answer the SUBSCRIBE with the alias, read a FETCH when the
            /// client makes one, send the traffic, and report what came back.
            async fn peer(server: quinn::Endpoint, traffic: Traffic, fetching: bool) -> Seen {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");
                let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
                let mut framed = crate::common::frame_uni_recv(recv, DraftVersion::$version);
                framed.read_control(false).await.expect("read CLIENT_SETUP");
                let setup: ServerSetup =
                    crate::gap_server_setup!($setup, DraftVersion::$version, setup_parameters());
                send.write_all(&encode(ControlMessage::ServerSetup(setup)))
                    .await
                    .expect("write SERVER_SETUP");
                let (request, _) = framed.read_control(false).await.expect("read SUBSCRIBE");
                let id = match request {
                    AnyControlMessage::$version(ControlMessage::Subscribe(s)) => s.request_id,
                    other => panic!("expected a SUBSCRIBE, got {other:?}"),
                };
                let ok: SubscribeOk = crate::gap_subscribe_ok!($ok, id, v(ALIAS));
                send.write_all(&encode(ControlMessage::SubscribeOk(ok)))
                    .await
                    .expect("write SUBSCRIBE_OK");
                let mut fetched = None;
                if fetching {
                    match framed.read_control(false).await.expect("read FETCH") {
                        (AnyControlMessage::$version(ControlMessage::Fetch(f)), _) => {
                            fetched = Some(f.request_id.into_inner())
                        }
                        other => panic!("expected a FETCH, got {other:?}"),
                    }
                }

                match traffic {
                    Traffic::Datagram(bytes) => {
                        conn.send_datagram(bytes.into()).expect("send the datagram")
                    }
                    Traffic::Stream => {
                        let extensions = gap_block(PRIOR_GROUP_ID_GAP);
                        let bytes: Vec<u8> =
                            crate::gap_stream!($stream, $draft, $version, extensions);
                        let mut data = conn.open_uni().await.expect("open the data stream");
                        data.write_all(&bytes).await.expect("write the stream");
                        data.finish().expect("finish the data stream");
                    }
                    Traffic::Fetch => {
                        let request = fetched.expect("a fetch stream answers a FETCH");
                        let bytes = crate::fetch_stream_bytes(stringify!($fetch_bytes), request);
                        let mut data = conn.open_uni().await.expect("open the fetch stream");
                        data.write_all(&bytes).await.expect("write the fetch stream");
                        data.finish().expect("finish the fetch stream");
                    }
                }

                let mut seen = Seen {
                    subscribed: id.into_inner(),
                    fetched,
                    unsubscribed: Vec::new(),
                    fetch_cancelled: Vec::new(),
                    closed: false,
                };
                while let Ok(read) = tokio::time::timeout(BRIEF, framed.read_control(false)).await {
                    match read {
                        Ok((AnyControlMessage::$version(ControlMessage::Unsubscribe(u)), _)) => {
                            seen.unsubscribed.push(u.request_id.into_inner())
                        }
                        Ok((AnyControlMessage::$version(message), _)) => {
                            crate::gap_fetch_cancel!($late, message, seen)
                        }
                        // Another draft's message, in a build with several.
                        #[allow(unreachable_patterns)]
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
                seen.closed = conn.close_reason().is_some();
                seen
            }

            async fn subscribed(
                traffic: Traffic,
                fetching: bool,
            ) -> (Connection, tokio::task::JoinHandle<Seen>) {
                crate::common::init_crypto();
                let (endpoint, addr) =
                    crate::common::spawn_server(&[DraftVersion::$version.quic_alpn()]);
                let served = tokio::spawn(peer(endpoint, traffic, fetching));
                let config: ClientConfig =
                    crate::gap_config!($cfg, DraftVersion::$version, setup_parameters());
                let mut conn =
                    tokio::time::timeout(PATIENCE, Connection::connect(&addr.to_string(), config))
                        .await
                        .expect("connect did not finish")
                        .expect("connect");
                crate::gap_subscribe!($sub, conn, namespace(), TRACK).await.expect("subscribe");
                tokio::time::timeout(PATIENCE, conn.recv_and_dispatch())
                    .await
                    .expect("SUBSCRIBE_OK never arrived")
                    .expect("dispatch SUBSCRIBE_OK");
                (conn, served)
            }

            async fn refused(datagram: Vec<u8>) -> (Connection, ConnectionError, Seen) {
                let (conn, served) = subscribed(Traffic::Datagram(datagram), false).await;
                let err = tokio::time::timeout(PATIENCE, conn.recv_datagram())
                    .await
                    .expect("the datagram never arrived")
                    .expect_err("the datagram was accepted");
                let closed = conn.close_for_data_stream(&err);
                let seen =
                    tokio::time::timeout(PATIENCE * 3, served).await.expect("peer hung").unwrap();
                assert_eq!(closed, seen.closed, "the peer saw a different session state");
                (conn, err, seen)
            }

            fn assert_malformed_track(err: &ConnectionError) {
                assert!(
                    matches!(err, ConnectionError::Codec(CodecError::MalformedTrack { .. })),
                    "expected a Malformed Track, got {err:?}"
                );
            }

            #[tokio::test]
            async fn a_gap_datagram_withdraws_from_the_track() {
                let (conn, err, seen) = refused(gap_datagram(PRIOR_GROUP_ID_GAP)).await;
                assert_malformed_track(&err);
                assert!(!seen.closed, "the error closed the session");
                assert_eq!(
                    conn.endpoint().malformed_track(&namespace(), TRACK),
                    Some(MalformedTrackCondition::$condition)
                );
                assert_eq!(seen.unsubscribed, vec![seen.subscribed], "not unsubscribed from");
            }

            crate::gap_payload_gate!($status_type);

            #[tokio::test]
            async fn an_empty_extension_block_closes_the_session() {
                let (_conn, err, seen) = refused(EMPTY_EXTENSIONS.to_vec()).await;
                assert!(
                    matches!(err, ConnectionError::EmptyDatagramExtensions { object_id: 0 }),
                    "expected an empty extension block, got {err:?}"
                );
                assert!(seen.closed, "the session was not closed");
            }

            crate::gap_late_gates!($draft $late);
            crate::gap_stream_gate!($stream);

            /// Two fetch Objects in Group 5 with Prior Group ID Gap 2 and 3,
            /// on one fetch stream. draft-12 Section 10.1 and
            /// draft-13 Section 10.1: "A track with a Group that contains more
            /// than one Object with different values for Prior Group ID Gap
            /// ... is considered malformed"; draft-14 Section 11.1,
            /// draft-15 Section 11.1 and draft-16 Section 11.3: "A Group
            /// contains more than one Object with different values for Prior
            /// Group ID Gap".
            #[tokio::test]
            async fn a_gap_fetch_stream_withdraws_from_the_track() {
                let (mut conn, served) = subscribed(Traffic::Fetch, true).await;
                let mine = crate::gap_fetch!($fetch, conn, namespace(), TRACK)
                    .await
                    .expect("fetch the track this session is also subscribed to");
                let (header, mut stream) =
                    tokio::time::timeout(PATIENCE, conn.accept_fetch_stream())
                        .await
                        .expect("the fetch stream never arrived")
                        .expect("read the fetch header");
                assert_eq!(header.request_id(), mine.into_inner());
                let err = crate::gap_read_fetch!($fetch_read, $draft, stream);
                assert_malformed_track(&err);
                assert!(!conn.close_for_data_stream(&err), "the error closed the session");
                assert!(!conn.withdraw_for_data_stream(&err).await, "the error names no track");
                assert!(conn.withdraw_for_fetch_stream(&header, &err).await);
                assert_eq!(
                    conn.endpoint().malformed_track(&namespace(), TRACK),
                    Some(MalformedTrackCondition::$condition)
                );
                let seen =
                    tokio::time::timeout(PATIENCE * 3, served).await.expect("peer hung").unwrap();
                assert_eq!(seen.unsubscribed, vec![seen.subscribed], "not unsubscribed from");
                crate::gap_fetch_cancelled!($late, seen, mine);
            }
        }
    };
}

/// The fetch stream for Request ID `request`: two Objects in Group 5, Object
/// IDs 0 and 1, carrying Prior Group ID Gap 2 and 3. `ext40` is the draft-12
/// and draft-13 layout with Extension Header Type 0x40, `ext3c` draft-14's
/// with Type 0x3C, and `flags` the Serialization Flags layout of drafts 15-23:
/// 0x3C states the Group ID, Object ID, Priority and the block, 0x20 the block
/// alone, the rest taken from the Object before.
#[cfg(any(
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20",
    feature = "draft21",
    feature = "draft22",
    feature = "draft23"
))]
fn fetch_stream_bytes(layout: &str, request: u64) -> Vec<u8> {
    assert!(request < 64, "a one-byte Request ID on every draft");
    let objects = match layout {
        "ext40" => "0500008003 404002 01aa".to_string() + "0500018003 404003 01bb",
        "ext3c" => "0500008002 3c02 01aa".to_string() + "0500018002 3c03 01bb",
        "flags" => "3c05008002 3c02 01aa".to_string() + "2002 3c03 01bb",
        other => panic!("no fetch layout {other}"),
    };
    let digits: Vec<u8> = objects.bytes().filter(|b| *b != b' ').collect();
    let mut bytes = vec![0x05, request as u8];
    bytes.extend(digits.chunks(2).map(|pair| {
        u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).expect("fetch stream hex")
    }));
    bytes
}

/// Read until the stream refuses an Object, the way each draft's reader can.
#[macro_export]
macro_rules! gap_read_fetch {
    (checked, $draft:ident, $stream:expr) => {{
        $stream.read_fetch_object().await.expect("the first Object was refused");
        $stream.read_fetch_object().await.expect_err("the second Object was accepted")
    }};
    // Draft-16's stream hands back each header unresolved, and the codec's
    // `resolve` applies the gap conditions.
    (resolved, $draft:ident, $stream:expr) => {{
        let mut reader = moqtap_codec::$draft::data_stream::FetchObjectReader::new();
        let (first, _) = $stream.read_fetch_object().await.expect("read a fetch Object");
        reader.resolve(&first).expect("the first Object was refused");
        let (second, _) = $stream.read_fetch_object().await.expect("read a fetch Object");
        ConnectionError::Codec(reader.resolve(&second).expect_err("the second Object was accepted"))
    }};
}

/// The FETCH_CANCEL half of the answer, on drafts 14-16.
#[macro_export]
macro_rules! gap_fetch_cancelled {
    (early, $seen:expr, $mine:expr) => {
        assert!($seen.fetch_cancelled.is_empty())
    };
    ((late $fetch:tt $ext_status:tt), $seen:expr, $mine:expr) => {
        assert_eq!($seen.fetch_cancelled, vec![$mine.into_inner()], "the fetch was not cancelled")
    };
}

/// A payload after a status, which the codec refuses on drafts 12-16.
#[macro_export]
macro_rules! gap_payload_gate {
    (none) => {};
    ($status_type:literal) => {
        #[tokio::test]
        async fn a_payload_after_a_status_is_refused_and_the_session_stays_open() {
            let (_conn, err, seen) = refused(payload_after_status($status_type)).await;
            assert!(
                matches!(err, ConnectionError::Codec(CodecError::PayloadNotPermitted { .. })),
                "expected a payload refusal, got {err:?}"
            );
            assert!(!seen.closed, "the error closed the session");
        }
    };
}

/// Drafts 14-16 only: the Prior Object ID Gap, the FETCH_CANCEL half of the
/// answer, and, on 15-16, extension headers on a status.
#[macro_export]
macro_rules! gap_late_gates {
    // draft-12 Section 2.5 and draft-13 Section 2.5 list no condition for an
    // extension block that does not parse, so it is refused and nothing is
    // withdrawn.
    ($draft:ident early) => {
        #[tokio::test]
        async fn an_extension_block_that_does_not_parse_is_refused_and_nothing_withdrawn() {
            let (conn, err, seen) = refused(datagram_with(vec![0x3D, 0x05, 0x01])).await;
            assert!(
                matches!(err, ConnectionError::Codec(CodecError::MalformedObjectProperties { .. })),
                "expected a block that does not parse, got {err:?}"
            );
            assert!(!seen.closed, "the error closed the session");
            assert_eq!(conn.endpoint().malformed_track(&namespace(), TRACK), None);
            assert!(seen.unsubscribed.is_empty(), "unsubscribed over a silent condition");
        }
    };
    ($draft:ident (late $fetch:tt $ext_status:tt)) => {
        #[tokio::test]
        async fn an_object_gap_datagram_withdraws_from_the_track() {
            use moqtap_codec::$draft::data_stream::PRIOR_OBJECT_ID_GAP;
            let (conn, err, seen) = refused(gap_datagram(PRIOR_OBJECT_ID_GAP)).await;
            assert_malformed_track(&err);
            assert!(!seen.closed, "the error closed the session");
            assert_eq!(
                conn.endpoint().malformed_track(&namespace(), TRACK),
                Some(MalformedTrackCondition::PriorGap)
            );
            assert_eq!(seen.unsubscribed, vec![seen.subscribed], "not unsubscribed from");
        }

        #[tokio::test]
        async fn a_gap_datagram_also_cancels_a_fetch_for_the_track() {
            let traffic = Traffic::Datagram(gap_datagram(PRIOR_GROUP_ID_GAP));
            let (mut conn, served) = subscribed(traffic, true).await;
            let mine = $crate::gap_fetch!($fetch, conn, namespace(), TRACK)
                .await
                .expect("fetch the track this session is also subscribed to");
            let err = tokio::time::timeout(PATIENCE, conn.recv_datagram())
                .await
                .expect("the datagram never arrived")
                .expect_err("a Prior Group ID Gap larger than the Group ID was accepted");
            assert_malformed_track(&err);
            assert!(!conn.close_for_data_stream(&err), "the error closed the session");
            let seen =
                tokio::time::timeout(PATIENCE * 3, served).await.expect("peer hung").unwrap();
            assert_eq!(seen.fetched, Some(mine.into_inner()));
            assert_eq!(seen.unsubscribed, vec![seen.subscribed], "not unsubscribed from");
            assert_eq!(
                seen.fetch_cancelled,
                vec![mine.into_inner()],
                "the fetch was not cancelled"
            );
        }

        /// An extension block whose one odd-typed header claims five bytes
        /// and has one: "A Key-Value-Pair cannot be parsed".
        #[tokio::test]
        async fn an_extension_block_that_does_not_parse_withdraws_from_the_track() {
            let (conn, err, seen) = refused(datagram_with(vec![0x3D, 0x05, 0x01])).await;
            assert!(
                matches!(err, ConnectionError::Codec(CodecError::MalformedObjectProperties { .. })),
                "expected a block that does not parse, got {err:?}"
            );
            assert!(!seen.closed, "the error closed the session");
            assert_eq!(
                conn.endpoint().malformed_track(&namespace(), TRACK),
                Some(MalformedTrackCondition::MalformedPropertyBlock)
            );
            assert_eq!(seen.unsubscribed, vec![seen.subscribed], "not unsubscribed from");
        }

        $crate::gap_status_extensions_gate!($ext_status);
    };
}

/// Drafts 15-16: extension headers on a status that is not Normal.
#[macro_export]
macro_rules! gap_status_extensions_gate {
    (no) => {};
    (yes) => {
        /// Type 0x21 (STATUS and EXTENSIONS), an Extension Headers Length of 2
        /// holding one even-typed header of value 0, and End of Group.
        #[tokio::test]
        async fn extensions_on_a_status_datagram_close_the_session() {
            let datagram = vec![0x21, 0x07, 0x01, 0x00, 0x80, 0x02, 0x02, 0x00, 0x03];
            let (_conn, err, seen) = refused(datagram).await;
            assert!(
                matches!(err, ConnectionError::ExtensionsOnNonNormalStatus { .. }),
                "expected extension headers on a non-Normal status, got {err:?}"
            );
            assert!(seen.closed, "the session was not closed");
        }
    };
}

/// Record a FETCH_CANCEL, on the drafts that have one.
#[macro_export]
macro_rules! gap_fetch_cancel {
    (early, $message:expr, $seen:expr) => {{
        let _ = $message;
    }};
    ((late $fetch:tt $ext_status:tt), $message:expr, $seen:expr) => {
        if let ControlMessage::FetchCancel(c) = $message {
            $seen.fetch_cancelled.push(c.request_id.into_inner())
        }
    };
}

#[macro_export]
macro_rules! gap_fetch {
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
    (params, $conn:expr, $ns:expr, $name:expr) => {
        $conn.fetch($ns, $name.to_vec(), Vec::new())
    };
}

/// The subgroup stream gate, for drafts 14-16; drafts 12-13 have theirs in
/// `a_prior_group_id_gap_fault_is_a_malformed_track.rs`.
#[macro_export]
macro_rules! gap_stream_gate {
    (none) => {};
    ($stream:tt) => {
        #[tokio::test]
        async fn a_gap_subgroup_stream_withdraws_from_the_track() {
            let (conn, served) = subscribed(Traffic::Stream, false).await;
            let (header, mut stream) =
                tokio::time::timeout(PATIENCE, conn.accept_subgroup_stream())
                    .await
                    .expect("the data stream never arrived")
                    .expect("read the subgroup header");
            let err = tokio::time::timeout(PATIENCE, stream.read_subgroup_object())
                .await
                .expect("the stream produced no object")
                .expect_err("a Prior Group ID Gap larger than the Group ID was accepted");
            assert_malformed_track(&err);
            assert!(!conn.close_for_data_stream(&err), "the error closed the session");
            assert!(!conn.withdraw_for_data_stream(&err).await, "the error names no track");
            assert!(conn.withdraw_for_subgroup_stream(&header, &err).await);
            assert_eq!(
                conn.endpoint().malformed_track(&namespace(), TRACK),
                Some(MalformedTrackCondition::PriorGap)
            );
            let seen =
                tokio::time::timeout(PATIENCE * 3, served).await.expect("peer hung").unwrap();
            assert_eq!(seen.unsubscribed, vec![seen.subscribed], "not unsubscribed from");
        }
    };
}

#[macro_export]
macro_rules! gap_config {
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

#[macro_export]
macro_rules! gap_server_setup {
    (versioned, $version:expr, $params:expr) => {
        ServerSetup { selected_version: $version.version_varint(), parameters: $params }
    };
    (plain, $version:expr, $params:expr) => {
        ServerSetup { parameters: $params }
    };
}

#[macro_export]
macro_rules! gap_subscribe_ok {
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
    (extensions, $id:expr, $alias:expr) => {
        SubscribeOk {
            request_id: $id,
            track_alias: $alias,
            parameters: Vec::new(),
            track_extensions: Vec::new(),
        }
    };
}

#[macro_export]
macro_rules! gap_subscribe {
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

/// One payload datagram in `GROUP` carrying `$ext` as its extension block.
#[macro_export]
macro_rules! gap_datagram {
    (grouped, $draft:ident, $ext:expr) => {{
        let extensions = $ext;
        moqtap_codec::$draft::data_stream::Datagram::Payload(
            moqtap_codec::$draft::data_stream::DatagramHeader {
                track_alias: v(ALIAS),
                group_id: v(GROUP),
                object_id: v(0),
                publisher_priority: 128,
                extension_headers_length: v(extensions.len() as u64),
                extensions,
                end_of_group: false,
            },
        )
    }};
    (typed, $draft:ident, $ext:expr) => {
        moqtap_codec::$draft::data_stream::DatagramObject {
            datagram_type: moqtap_codec::$draft::data_stream::DatagramType::payload(
                true, true, false,
            ),
            track_alias: v(ALIAS),
            group_id: v(GROUP),
            object_id: v(0),
            publisher_priority: 128,
            extension_headers: $ext,
            status: None,
            payload: Vec::new(),
        }
    };
    (byte, $draft:ident, $ext:expr) => {
        moqtap_codec::$draft::data_stream::DatagramHeader {
            // The EXTENSIONS bit (0x01), the Object ID written, the priority
            // present, and no status.
            datagram_type: 0x01,
            track_alias: v(ALIAS),
            group_id: v(GROUP),
            object_id: v(0),
            publisher_priority: Some(128),
            extension_headers: $ext,
            object_status: None,
        }
    };
}

/// One subgroup stream in `GROUP` whose one Object carries `$ext`.
#[macro_export]
macro_rules! gap_stream {
    (flags, $draft:ident, $version:ident, $ext:expr) => {{
        let header = moqtap_codec::$draft::data_stream::SubgroupHeader {
            stream_type: moqtap_codec::$draft::data_stream::SubgroupStreamType::from_flags(
                true, false, true, false,
            ),
            track_alias: v(ALIAS),
            group_id: v(GROUP),
            subgroup_id: Some(VarInt::from_usize(0)),
            publisher_priority: 128,
        };
        let mut writer = moqtap_codec::$draft::data_stream::SubgroupObjectReader::new(&header);
        let mut buf = Vec::new();
        AnySubgroupHeader::$version(header)
            .encode_stream_checked(&mut buf)
            .expect("encode the subgroup header");
        writer
            .write_object(
                &moqtap_codec::$draft::data_stream::SubgroupObject {
                    object_id: VarInt::from_usize(0),
                    extension_headers: $ext,
                    status: None,
                    payload: vec![1],
                },
                &mut buf,
            )
            .expect("write the object");
        buf
    }};
    (byte, $draft:ident, $version:ident, $ext:expr) => {{
        let header = moqtap_codec::$draft::data_stream::SubgroupHeader {
            // The subgroup base (0x10) with the explicit Subgroup ID bit
            // (0x04) and the EXTENSIONS bit (0x01).
            header_type: 0x15,
            track_alias: v(ALIAS),
            group_id: v(GROUP),
            subgroup_id: VarInt::from_usize(0),
            publisher_priority: Some(128),
        };
        let mut writer = moqtap_codec::$draft::data_stream::SubgroupObjectReader::new(&header);
        let mut buf = Vec::new();
        AnySubgroupHeader::$version(header)
            .encode_stream_checked(&mut buf)
            .expect("encode the subgroup header");
        writer
            .write_object(
                &moqtap_codec::$draft::data_stream::SubgroupObject {
                    object_id: VarInt::from_usize(0),
                    extension_headers: $ext,
                    payload_length: VarInt::from_usize(1),
                    object_status: None,
                    payload: vec![1],
                },
                &mut buf,
            )
            .expect("write the object");
        buf
    }};
    (none, $draft:ident, $version:ident, $ext:expr) => {{
        let _ = $ext;
        let _ = AnySubgroupHeader::$version;
        Vec::new()
    }};
}

message_gates!(
    draft12,
    "draft12",
    Draft12,
    early,
    versioned,
    rich,
    varint,
    grouped,
    none,
    PriorGroupIdGap,
    0x04,
    early,
    (ordered ext40 checked)
);
message_gates!(
    draft13,
    "draft13",
    Draft13,
    early,
    versioned,
    rich,
    filter,
    grouped,
    none,
    PriorGroupIdGap,
    0x04,
    early,
    (ordered ext40 checked)
);
message_gates!(
    draft14,
    "draft14",
    Draft14,
    both,
    versioned,
    rich,
    filter,
    typed,
    flags,
    PriorGap,
    0x20,
    (late ordered no),
    (ordered ext3c checked)
);
message_gates!(
    draft15,
    "draft15",
    Draft15,
    late,
    plain,
    plain,
    params,
    byte,
    byte,
    PriorGap,
    0x20,
    (late bare yes),
    (bare flags checked)
);
message_gates!(
    draft16,
    "draft16",
    Draft16,
    late,
    plain,
    extensions,
    params,
    byte,
    byte,
    PriorGap,
    0x20,
    (late bare yes),
    (bare flags resolved)
);

#[cfg(any(
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20",
    feature = "draft21",
    feature = "draft22",
    feature = "draft23"
))]
/// A quinn receive stream with a buffer in front of it, decoding with
/// `moqtap-codec` only.
struct PeerStream {
    recv: quinn::RecvStream,
    buf: Vec<u8>,
}

#[cfg(any(
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20",
    feature = "draft21",
    feature = "draft22",
    feature = "draft23"
))]
impl PeerStream {
    fn new(recv: quinn::RecvStream) -> Self {
        Self { recv, buf: Vec::new() }
    }

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
                    let mut tmp = [0u8; 2048];
                    match self.recv.read(&mut tmp).await {
                        Ok(Some(n)) => self.buf.extend_from_slice(&tmp[..n]),
                        _ => return None,
                    }
                }
                Err(_) => return None,
            }
        }
    }
}

/// Drafts 17-23, whose answer is a reset of the request's own stream.
macro_rules! cancel_gates {
    ($draft:ident, $feat:literal, $version:ident, $fetch:tt, $empty:tt, $begin:tt) => {
        #[cfg(feature = $feat)]
        mod $draft {
            use super::{gap_block, v, PeerStream, ALIAS, BRIEF, GROUP, PATIENCE, TRACK};
            use moqtap_client::malformed_tracks::MalformedTrackCondition;
            use moqtap_client::$draft::connection::{
                ClientConfig, Connection, ConnectionError, RequestStream, TransportType,
            };
            use moqtap_client::$draft::session::state::SessionState;
            use moqtap_codec::dispatch::{AnyControlMessage, AnySubgroupHeader};
            use moqtap_codec::error::CodecError;
            use moqtap_codec::types::TrackNamespace;
            use moqtap_codec::varint::VarInt;
            use moqtap_codec::version::DraftVersion;
            use moqtap_codec::$draft::data_stream::{
                DatagramHeader, SubgroupHeader, SubgroupObject, SubgroupObjectReader,
                PRIOR_GROUP_ID_GAP, PRIOR_OBJECT_ID_GAP,
            };
            use moqtap_codec::$draft::message::{ControlMessage, Setup, SubscribeOk};
            use moqtap_codec::$draft::types::ObjectStatus;

            #[derive(Debug, Clone, Copy)]
            enum Traffic {
                GapDatagram,
                ObjectGapDatagram,
                GapStream,
                PropertiesOnAStatus,
                EmptyProperties,
                UnparsableProperties,
                /// A fetch stream for the Request ID the test hands over.
                Fetch,
            }

            fn namespace() -> TrackNamespace {
                TrackNamespace(vec![b"conformance".to_vec()])
            }

            fn datagram(
                datagram_type: u8,
                properties: Vec<u8>,
                status: Option<ObjectStatus>,
            ) -> Vec<u8> {
                let header = DatagramHeader {
                    // The PROPERTIES bit (0x01), with the STATUS bit (0x20)
                    // when there is a status.
                    datagram_type,
                    track_alias: v(ALIAS),
                    group_id: v(GROUP),
                    object_id: v(0),
                    publisher_priority: Some(128),
                    properties,
                    object_status: status,
                };
                // The unchecked encoder, which writes what the peer under test
                // does.
                let mut buf = Vec::new();
                header.encode(&mut buf);
                buf
            }

            fn stream_bytes() -> Vec<u8> {
                let header = SubgroupHeader {
                    // The subgroup base (0x10) with the explicit Subgroup ID
                    // bit (0x04) and the PROPERTIES bit (0x01).
                    header_type: 0x15,
                    track_alias: v(ALIAS),
                    group_id: v(GROUP),
                    subgroup_id: v(0),
                    publisher_priority: Some(128),
                };
                let mut buf = Vec::new();
                AnySubgroupHeader::$version(header.clone())
                    .encode_stream_checked(&mut buf)
                    .expect("encode the subgroup header");
                SubgroupObjectReader::new(&header)
                    .write_object(
                        &SubgroupObject {
                            object_id: v(0),
                            extension_headers: gap_block(PRIOR_GROUP_ID_GAP),
                            payload_length: VarInt::from_usize(1),
                            object_status: None,
                            payload: vec![1],
                        },
                        &mut buf,
                    )
                    .expect("encode the object");
                buf
            }

            async fn serve(
                server: quinn::Endpoint,
                traffic: Traffic,
                fetch: tokio::sync::oneshot::Receiver<u64>,
            ) {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");
                let mut control = PeerStream::new(conn.accept_uni().await.expect("accept_uni"));
                control.read_control(DraftVersion::$version).await.expect("read SETUP");
                let mut setup = Vec::new();
                AnyControlMessage::$version(ControlMessage::Setup(Setup { options: Vec::new() }))
                    .encode(&mut setup)
                    .expect("encode SETUP");
                let mut our_control = conn.open_uni().await.expect("open the control stream");
                our_control.write_all(&setup).await.expect("write SETUP");

                let (mut answer, request) = conn.accept_bi().await.expect("accept_bi");
                let mut request = PeerStream::new(request);
                match request.read_control(DraftVersion::$version).await {
                    Some(AnyControlMessage::$version(ControlMessage::Subscribe(_))) => {}
                    other => panic!("expected a SUBSCRIBE, got {other:?}"),
                }
                let ok = SubscribeOk {
                    track_alias: v(ALIAS),
                    parameters: Vec::new(),
                    track_properties: Vec::new(),
                };
                let mut out = Vec::new();
                AnyControlMessage::$version(ControlMessage::SubscribeOk(ok))
                    .encode(&mut out)
                    .expect("encode SUBSCRIBE_OK");
                answer.write_all(&out).await.expect("write SUBSCRIBE_OK");

                // Held until the connection ends: a dropped stream is reset.
                let mut _held = None;
                let sent = match traffic {
                    Traffic::GapDatagram => datagram(0x01, gap_block(PRIOR_GROUP_ID_GAP), None),
                    Traffic::ObjectGapDatagram => {
                        datagram(0x01, gap_block(PRIOR_OBJECT_ID_GAP), None)
                    }
                    Traffic::PropertiesOnAStatus => datagram(
                        0x21,
                        gap_block(PRIOR_GROUP_ID_GAP),
                        Some(ObjectStatus::EndOfTrack),
                    ),
                    Traffic::EmptyProperties => datagram(0x01, Vec::new(), None),
                    Traffic::UnparsableProperties => datagram(0x01, vec![0x3D, 0x05, 0x01], None),
                    Traffic::Fetch => {
                        let request = fetch.await.expect("the test names its FETCH");
                        let bytes = crate::fetch_stream_bytes("flags", request);
                        let mut data = conn.open_uni().await.expect("open the fetch stream");
                        data.write_all(&bytes).await.expect("write the fetch stream");
                        data.finish().expect("finish the fetch stream");
                        _held = Some(data);
                        Vec::new()
                    }
                    Traffic::GapStream => {
                        let mut data = conn.open_uni().await.expect("open the data stream");
                        data.write_all(&stream_bytes()).await.expect("write the stream");
                        data.finish().expect("finish the data stream");
                        _held = Some(data);
                        Vec::new()
                    }
                };
                if !sent.is_empty() {
                    conn.send_datagram(sent.into()).expect("send the datagram");
                }
                std::future::pending::<()>().await;
            }

            async fn subscribed(
                traffic: Traffic,
            ) -> (Connection, RequestStream, tokio::task::JoinHandle<()>) {
                let (conn, request, peer, _) = subscribed_with(traffic).await;
                (conn, request, peer)
            }

            async fn subscribed_with(
                traffic: Traffic,
            ) -> (
                Connection,
                RequestStream,
                tokio::task::JoinHandle<()>,
                tokio::sync::oneshot::Sender<u64>,
            ) {
                crate::common::init_crypto();
                let (endpoint, addr) =
                    crate::common::spawn_server(&[DraftVersion::$version.quic_alpn()]);
                let (name_fetch, fetch) = tokio::sync::oneshot::channel();
                let peer = tokio::spawn(serve(endpoint, traffic, fetch));
                let config = ClientConfig {
                    draft: DraftVersion::$version,
                    transport: TransportType::Quic,
                    skip_cert_verification: true,
                    ca_certs: Vec::new(),
                    setup_parameters: Vec::new(),
                };
                let mut conn =
                    tokio::time::timeout(PATIENCE, Connection::connect(&addr.to_string(), config))
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
                        .expect("SUBSCRIBE_OK never arrived")
                        .expect("read SUBSCRIBE_OK");
                assert!(matches!(answer, ControlMessage::SubscribeOk(_)), "got {answer:?}");
                (conn, request, peer, name_fetch)
            }

            async fn still_active(conn: &Connection) {
                tokio::time::sleep(BRIEF).await;
                assert_eq!(conn.endpoint().session_state(), SessionState::Active);
            }

            fn assert_gap_datagram(err: &ConnectionError) {
                match err {
                    ConnectionError::MalformedTrackDatagram {
                        track_alias,
                        error: CodecError::MalformedTrack { .. },
                    } => assert_eq!(*track_alias, ALIAS),
                    other => panic!("expected a Malformed Track datagram, got {other:?}"),
                }
            }

            async fn refused(conn: &Connection) -> ConnectionError {
                tokio::time::timeout(PATIENCE, conn.recv_datagram())
                    .await
                    .expect("the datagram never arrived")
                    .expect_err("the datagram was accepted")
            }

            #[tokio::test]
            async fn a_gap_datagram_names_the_request_to_cancel() {
                let (conn, request, _peer) = subscribed(Traffic::GapDatagram).await;
                let err = refused(&conn).await;
                assert_gap_datagram(&err);
                assert!(!conn.close_for_data_stream(&err), "the error closed the session");
                assert_eq!(conn.requests_to_cancel(&err), vec![request.request_id()]);
                assert_eq!(
                    conn.endpoint().malformed_track(&namespace(), TRACK),
                    Some(MalformedTrackCondition::PriorGap)
                );
                still_active(&conn).await;
            }

            #[tokio::test]
            async fn an_object_gap_datagram_names_the_request_to_cancel() {
                let (conn, request, _peer) = subscribed(Traffic::ObjectGapDatagram).await;
                let err = refused(&conn).await;
                assert_gap_datagram(&err);
                assert!(!conn.close_for_data_stream(&err), "the error closed the session");
                assert_eq!(conn.requests_to_cancel(&err), vec![request.request_id()]);
                still_active(&conn).await;
            }

            /// "cancel any corresponding subscription or fetches": the fetch
            /// for the same track is named beside the subscription.
            #[tokio::test]
            async fn a_gap_datagram_names_a_fetch_for_the_track_as_well() {
                let (mut conn, request, _peer) = subscribed(Traffic::GapDatagram).await;
                let fetch = tokio::time::timeout(
                    PATIENCE,
                    crate::gap_fetch!($fetch, conn, namespace(), TRACK),
                )
                .await
                .expect("fetch did not finish")
                .expect("fetch the track this session is also subscribed to");
                let err = refused(&conn).await;
                assert_gap_datagram(&err);
                let mut expected = vec![request.request_id(), fetch.request_id()];
                expected.sort_unstable_by_key(|id| id.into_inner());
                assert_eq!(conn.requests_to_cancel(&err), expected);
                still_active(&conn).await;
            }

            #[tokio::test]
            async fn a_gap_subgroup_stream_names_the_request_to_cancel() {
                let (conn, request, _peer) = subscribed(Traffic::GapStream).await;
                let (header, mut stream) =
                    tokio::time::timeout(PATIENCE, conn.accept_subgroup_stream())
                        .await
                        .expect("the data stream never arrived")
                        .expect("read the subgroup header");
                let err = tokio::time::timeout(PATIENCE, stream.read_subgroup_object())
                    .await
                    .expect("the stream produced no object")
                    .expect_err("a Prior Group ID Gap larger than the Group ID was accepted");
                assert!(
                    matches!(err, ConnectionError::Codec(CodecError::MalformedTrack { .. })),
                    "expected a Malformed Track, got {err:?}"
                );
                assert!(!conn.close_for_data_stream(&err), "the error closed the session");
                assert!(conn.requests_to_cancel(&err).is_empty(), "the error names no track");
                assert_eq!(
                    conn.requests_to_cancel_for_subgroup_stream(&header, &err),
                    vec![request.request_id()]
                );
                assert_eq!(
                    conn.endpoint().malformed_track(&namespace(), TRACK),
                    Some(MalformedTrackCondition::PriorGap)
                );
                still_active(&conn).await;
            }

            /// A property block whose one odd-typed property claims five bytes
            /// and has one: "A Key-Value-Pair cannot be parsed".
            #[tokio::test]
            async fn a_property_block_that_does_not_parse_names_the_request_to_cancel() {
                let (conn, request, _peer) = subscribed(Traffic::UnparsableProperties).await;
                let err = refused(&conn).await;
                match &err {
                    ConnectionError::MalformedTrackDatagram {
                        track_alias,
                        error: CodecError::MalformedObjectProperties { .. },
                    } => assert_eq!(*track_alias, ALIAS),
                    other => panic!("expected a Malformed Track datagram, got {other:?}"),
                }
                assert!(!conn.close_for_data_stream(&err), "the error closed the session");
                assert_eq!(conn.requests_to_cancel(&err), vec![request.request_id()]);
                assert_eq!(
                    conn.endpoint().malformed_track(&namespace(), TRACK),
                    Some(MalformedTrackCondition::MalformedPropertyBlock)
                );
                still_active(&conn).await;
            }

            /// Two fetch Objects in Group 5 with Prior Group ID Gap 2 and 3: "A
            /// Group contains more than one Object with different values for
            /// Prior Group ID Gap", on one fetch stream. The FETCH and the
            /// SUBSCRIBE are both for the track, so both are named.
            #[tokio::test]
            async fn a_gap_fetch_stream_names_the_requests_to_cancel() {
                let (mut conn, request, _peer, name_fetch) = subscribed_with(Traffic::Fetch).await;
                let fetch = tokio::time::timeout(
                    PATIENCE,
                    crate::gap_fetch!($fetch, conn, namespace(), TRACK),
                )
                .await
                .expect("fetch did not finish")
                .expect("fetch the track this session is also subscribed to");
                name_fetch.send(fetch.request_id().into_inner()).expect("the peer is waiting");
                let (header, mut stream) =
                    tokio::time::timeout(PATIENCE, conn.accept_fetch_stream())
                        .await
                        .expect("the fetch stream never arrived")
                        .expect("read the fetch header");
                crate::gap_begin_fetch!($begin, $draft, stream);
                tokio::time::timeout(PATIENCE, stream.read_fetch_object())
                    .await
                    .expect("the first Object never arrived")
                    .expect("the first Object was refused");
                let err = tokio::time::timeout(PATIENCE, stream.read_fetch_object())
                    .await
                    .expect("the second Object never arrived")
                    .expect_err("the second Object was accepted");
                assert!(
                    matches!(err, ConnectionError::Codec(CodecError::MalformedTrack { .. })),
                    "expected a Malformed Track, got {err:?}"
                );
                assert!(!conn.close_for_data_stream(&err), "the error closed the session");
                assert!(conn.requests_to_cancel(&err).is_empty(), "the error names no track");
                let mut expected = vec![request.request_id(), fetch.request_id()];
                expected.sort_unstable_by_key(|id| id.into_inner());
                assert_eq!(conn.requests_to_cancel_for_fetch_stream(&header, &err), expected);
                assert_eq!(
                    conn.endpoint().malformed_track(&namespace(), TRACK),
                    Some(MalformedTrackCondition::PriorGap)
                );
                still_active(&conn).await;
            }

            /// "If an Object Datagram includes both the STATUS bit and
            /// PROPERTIES bit, and the Object Status is not Normal (0x0), the
            /// endpoint MUST close the session", on every draft here.
            #[tokio::test]
            async fn properties_on_a_status_datagram_close_the_session() {
                let (conn, _request, _peer) = subscribed(Traffic::PropertiesOnAStatus).await;
                let err = refused(&conn).await;
                assert!(
                    matches!(err, ConnectionError::PropertiesOnNonNormalStatus { .. }),
                    "expected properties on a non-Normal status, got {err:?}"
                );
                assert!(conn.close_for_data_stream(&err), "the session was not closed");
            }

            /// "If an endpoint receives a datagram with the PROPERTIES bit set
            /// and an Properties Length of 0, it MUST close the session", on
            /// every draft here.
            #[tokio::test]
            async fn an_empty_property_block_closes_the_session() {
                let (conn, _request, _peer) = subscribed(Traffic::EmptyProperties).await;
                let err = refused(&conn).await;
                crate::gap_empty_properties!($empty, err);
                assert!(conn.close_for_data_stream(&err), "the session was not closed");
            }
        }
    };
}

/// Drafts 18-23 take the Group Order before the first fetch Object.
#[macro_export]
macro_rules! gap_begin_fetch {
    (none, $draft:ident, $stream:expr) => {};
    (begin, $draft:ident, $stream:expr) => {
        $stream.begin_fetch_objects(moqtap_codec::$draft::data_stream::GroupOrder::Ascending)
    };
}

#[macro_export]
macro_rules! gap_empty_properties {
    (named, $err:expr) => {
        assert!(
            matches!($err, ConnectionError::EmptyDatagramProperties { object_id: 0 }),
            "expected an empty property block, got {:?}",
            $err
        )
    };
    (malformed, $err:expr) => {
        assert!(
            matches!($err, ConnectionError::Codec(CodecError::MalformedObject { .. })),
            "expected a malformed Object, got {:?}",
            $err
        )
    };
}

cancel_gates!(draft17, "draft17", Draft17, bare, named, none);
cancel_gates!(draft18, "draft18", Draft18, bare, named, begin);
cancel_gates!(draft19, "draft19", Draft19, bare, named, begin);
cancel_gates!(draft20, "draft20", Draft20, params, named, begin);
cancel_gates!(draft21, "draft21", Draft21, params, named, begin);
cancel_gates!(draft22, "draft22", Draft22, params, named, begin);
cancel_gates!(draft23, "draft23", Draft23, params, malformed, begin);

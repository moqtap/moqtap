#![cfg(any(feature = "draft11", feature = "draft12", feature = "draft13"))]

//! Drafts 11-13: a subgroup stream whose Prior Group ID Gap values make its
//! track malformed is refused, and the session stays open.
//!
//! draft-11 Section 10.1, draft-12 Section 10.1 and draft-13 Section 10.1: "A
//! track with a Group that contains more than one Object with different values
//! for Prior Group ID Gap or has a Prior Group ID Gap larger than the Group ID
//! is considered malformed."
//!
//! draft-12 Section 2.5 and draft-13 Section 2.5: "When a subscriber detects a
//! Malformed Track, it MUST UNSUBSCRIBE from the Track and SHOULD deliver an
//! error to the application." Draft-11 has no such section.

mod common;

use moqtap_codec::varint::VarInt;

fn v(n: u64) -> VarInt {
    VarInt::from_u64(n).unwrap()
}

/// One Prior Group ID Gap extension header (type 0x40).
#[allow(dead_code)]
fn gap_block(gap: u64) -> Vec<u8> {
    let mut block = Vec::new();
    v(0x40).encode(&mut block);
    v(gap).encode(&mut block);
    block
}

/// The reader gates, one module per draft.
macro_rules! gap_reader_gates {
    ($mod_name:ident, $feat:literal, $draft:ident, $version:ident) => {
        #[cfg(feature = $feat)]
        mod $mod_name {
            use super::{common, gap_block, v};
            use moqtap_client::transport::RecvStream;
            use moqtap_client::$draft::connection::{
                Connection, ConnectionError, FramedRecvStream,
            };
            use moqtap_codec::dispatch::AnySubgroupHeader;
            use moqtap_codec::error::CodecError;
            use moqtap_codec::version::DraftVersion;
            use moqtap_codec::$draft::data_stream::{ObjectHeader, StreamType, SubgroupHeader};
            use moqtap_codec::$draft::types::ObjectStatus;

            /// A stream of `group` on track `alias` whose type carries an
            /// extension block, then one Object per entry of `gaps`, each with
            /// that Prior Group ID Gap.
            pub fn stream_bytes(alias: u64, group: u64, gaps: &[u64]) -> Vec<u8> {
                let mut buf = Vec::new();
                AnySubgroupHeader::$version(SubgroupHeader {
                    stream_type: StreamType::SubgroupExplicitExt,
                    track_alias: v(alias),
                    group_id: v(group),
                    subgroup_id: v(0),
                    publisher_priority: 128,
                })
                .encode_stream_checked(&mut buf)
                .expect("encode the subgroup header");
                for (id, &gap) in gaps.iter().enumerate() {
                    let extensions = gap_block(gap);
                    ObjectHeader {
                        object_id: v(id as u64),
                        extension_headers_length: v(extensions.len() as u64),
                        extensions,
                        payload_length: v(1),
                        object_status: ObjectStatus::Normal,
                    }
                    .encode_with_extensions(true, &mut buf);
                    buf.push(0xAA);
                }
                buf
            }

            /// Send `bytes` on one stream and read `objects` Objects from it.
            async fn read(bytes: Vec<u8>, objects: usize) -> Vec<Result<(), ConnectionError>> {
                common::init_crypto();
                let alpn = DraftVersion::$version.quic_alpn();
                let (server, addr) = common::spawn_server(&[alpn]);
                let reader = tokio::spawn(async move {
                    let conn = server.accept().await.expect("accept").await.expect("handshake");
                    let recv = conn.accept_uni().await.expect("accept_uni");
                    let mut framed = FramedRecvStream::new(RecvStream::Quic(recv));
                    framed.read_subgroup_header().await.expect("read the subgroup header");
                    let mut results = Vec::new();
                    for _ in 0..objects {
                        results.push(framed.read_subgroup_object().await.map(|_| ()));
                    }
                    results
                });
                let client = common::client_endpoint(&[alpn]);
                let conn =
                    client.connect(addr, "localhost").expect("connect").await.expect("handshake");
                let mut send = conn.open_uni().await.expect("open_uni");
                send.write_all(&bytes).await.expect("write the stream");
                send.finish().expect("finish");
                reader.await.expect("reader task")
            }

            fn assert_malformed_track(result: &Result<(), ConnectionError>) {
                match result {
                    Err(ConnectionError::Codec(err @ CodecError::MalformedTrack { .. })) => {
                        assert_eq!(
                            Connection::codec_session_error_code(err),
                            None,
                            "a Malformed Track costs the track, not the session"
                        );
                    }
                    other => panic!("expected CodecError::MalformedTrack, got {other:?}"),
                }
            }

            #[tokio::test]
            async fn a_gap_larger_than_the_group_id_is_refused() {
                let results = read(stream_bytes(1, 1, &[2]), 1).await;
                assert_malformed_track(&results[0]);
            }

            #[tokio::test]
            async fn objects_with_different_gaps_are_refused() {
                let results = read(stream_bytes(1, 5, &[2, 3]), 2).await;
                results[0].as_ref().expect("the first Object's gap is within its Group ID");
                assert_malformed_track(&results[1]);
            }

            #[tokio::test]
            async fn objects_with_the_same_gap_are_accepted() {
                for result in read(stream_bytes(1, 5, &[2, 2]), 2).await {
                    result.expect("one gap value within the Group ID is conforming");
                }
            }
        }
    };
}

gap_reader_gates!(draft11, "draft11", draft11, Draft11);
gap_reader_gates!(draft12, "draft12", draft12, Draft12);
gap_reader_gates!(draft13, "draft13", draft13, Draft13);

/// The withdrawal gate for drafts 12-13, where draft-12 Section 2.5 and
/// draft-13 Section 2.5 require the UNSUBSCRIBE.
macro_rules! gap_withdrawal_gate {
    ($mod_name:ident, $reader:ident, $feat:literal, $draft:ident, $version:ident, $sub:tt) => {
        #[cfg(feature = $feat)]
        mod $mod_name {
            use std::time::Duration;

            use super::v;
            use moqtap_client::malformed_tracks::MalformedTrackCondition;
            use moqtap_client::$draft::connection::{ClientConfig, Connection, TransportType};
            use moqtap_codec::dispatch::AnyControlMessage;
            use moqtap_codec::kvp::{KeyValuePair, KvpValue};
            use moqtap_codec::types::{ContentExists, GroupOrder, TrackNamespace};
            use moqtap_codec::version::DraftVersion;
            use moqtap_codec::$draft::message::{ControlMessage, ServerSetup, SubscribeOk};

            const PATIENCE: Duration = Duration::from_secs(10);
            const BRIEF: Duration = Duration::from_millis(400);
            const ALIAS: u64 = 7;
            const TRACK: &[u8] = b"one-track";

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

            /// Answer the SUBSCRIBE with the alias, send a stream whose Object
            /// carries a gap larger than its Group ID, and return the SUBSCRIBE's
            /// Request ID and the UNSUBSCRIBEs read afterwards.
            async fn peer(server: quinn::Endpoint) -> (u64, Vec<u64>) {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");
                let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
                let mut framed = crate::common::frame_uni_recv(recv, DraftVersion::$version);
                framed.read_control(false).await.expect("read CLIENT_SETUP");
                let setup = ServerSetup {
                    selected_version: DraftVersion::$version.version_varint(),
                    parameters: setup_parameters(),
                };
                send.write_all(&encode(ControlMessage::ServerSetup(setup)))
                    .await
                    .expect("write SERVER_SETUP");
                let (request, _) = framed.read_control(false).await.expect("read SUBSCRIBE");
                let id = match request {
                    AnyControlMessage::$version(ControlMessage::Subscribe(s)) => s.request_id,
                    other => panic!("expected a SUBSCRIBE, got {other:?}"),
                };
                let ok = SubscribeOk {
                    request_id: id,
                    track_alias: v(ALIAS),
                    expires: v(0),
                    group_order: GroupOrder::Ascending,
                    content_exists: ContentExists::NoLargestLocation,
                    largest_location: None,
                    parameters: Vec::new(),
                };
                send.write_all(&encode(ControlMessage::SubscribeOk(ok)))
                    .await
                    .expect("write SUBSCRIBE_OK");

                let mut data = conn.open_uni().await.expect("open the data stream");
                data.write_all(&crate::$reader::stream_bytes(ALIAS, 1, &[2]))
                    .await
                    .expect("write the stream");
                data.finish().expect("finish the data stream");

                let mut unsubscribed = Vec::new();
                while let Ok(read) =
                    tokio::time::timeout(BRIEF, framed.read_control(false)).await
                {
                    match read {
                        Ok((AnyControlMessage::$version(ControlMessage::Unsubscribe(u)), _)) => {
                            unsubscribed.push(u.request_id.into_inner())
                        }
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
                assert!(conn.close_reason().is_none(), "the session was closed");
                (id.into_inner(), unsubscribed)
            }

            #[tokio::test]
            async fn a_gap_fault_withdraws_from_the_track() {
                crate::common::init_crypto();
                let (endpoint, addr) =
                    crate::common::spawn_server(&[DraftVersion::$version.quic_alpn()]);
                let served = tokio::spawn(peer(endpoint));

                let config = ClientConfig {
                    additional_versions: Vec::new(),
                    transport: TransportType::Quic,
                    skip_cert_verification: true,
                    ca_certs: Vec::new(),
                    setup_parameters: setup_parameters(),
                };
                let mut conn =
                    tokio::time::timeout(PATIENCE, Connection::connect(&addr.to_string(), config))
                        .await
                        .expect("connect did not finish")
                        .expect("connect");
                gap_withdrawal_gate!(@subscribe $sub, conn).await.expect("subscribe");
                tokio::time::timeout(PATIENCE, conn.recv_and_dispatch())
                    .await
                    .expect("SUBSCRIBE_OK never arrived")
                    .expect("dispatch SUBSCRIBE_OK");

                let (header, mut stream) =
                    tokio::time::timeout(PATIENCE, conn.accept_subgroup_stream())
                        .await
                        .expect("the data stream never arrived")
                        .expect("read the subgroup header");
                let err = tokio::time::timeout(PATIENCE, stream.read_subgroup_object())
                    .await
                    .expect("the stream produced no object")
                    .err()
                    .expect("a gap larger than the Group ID was accepted");
                assert!(!conn.close_for_data_stream(&err), "the error closed the session");
                assert!(conn.withdraw_for_subgroup_stream(&header, &err).await);
                assert_eq!(
                    conn.endpoint().malformed_track(&namespace(), TRACK),
                    Some(MalformedTrackCondition::PriorGroupIdGap)
                );

                let (asked, unsubscribed) =
                    tokio::time::timeout(PATIENCE * 3, served).await.expect("peer hung").unwrap();
                assert_eq!(unsubscribed, vec![asked], "the track was not unsubscribed from");
            }
        }
    };
    (@subscribe varint, $conn:expr) => {
        $conn.subscribe(namespace(), TRACK.to_vec(), 128, GroupOrder::Ascending, v(0x2), Vec::new())
    };
    (@subscribe filter, $conn:expr) => {
        $conn.subscribe(
            namespace(),
            TRACK.to_vec(),
            128,
            GroupOrder::Ascending,
            moqtap_codec::types::FilterType::LargestObject,
            Vec::new(),
        )
    };
}

gap_withdrawal_gate!(draft12_withdrawal, draft12, "draft12", draft12, Draft12, varint);
gap_withdrawal_gate!(draft13_withdrawal, draft13, "draft13", draft13, Draft13, filter);

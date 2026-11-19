//! A stream `AnyConnection::accept_data_stream` returned goes back only to the
//! connection that accepted it, and the streams set aside come back in the
//! order they arrived, on every enabled draft.
//!
//! The peer opens FETCH_HEADER streams, each naming its own Request ID. Two are
//! set aside in the reverse of their arrival and come back from `accept_fetch`
//! in arrival order. A second connection of the same draft, and one of another
//! draft, refuse a stream the first accepted. On the drafts whose peer can open
//! a data stream before its control stream, a fetch stream and then a stream of
//! another type, both opened before the control stream, come back from
//! `accept_data_stream` in arrival order.

mod common;
#[macro_use]
mod data_stream_peer;

use std::time::Duration;

use moqtap_client::dispatch::{
    AnyClientConfig, AnyConnection, AnyConnectionError, AnyIncomingDataStream, AnyIncomingHeader,
    AnyTransportType, ErrorCause,
};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::types::GroupOrder;
use moqtap_codec::version::DraftVersion;

/// How long any one step may take before the test fails.
const PATIENCE: Duration = Duration::from_secs(10);

/// Open one finished stream per Request ID, each carrying only a FETCH_HEADER
/// for it: the same two bytes on every draft.
async fn open_fetch_streams(conn: &quinn::Connection, requests: &[u8]) {
    for &request in requests {
        let mut stream = conn.open_uni().await.expect("open a fetch stream");
        stream.write_all(&[0x05, request]).await.expect("write a FETCH_HEADER");
        stream.finish().expect("finish the fetch stream");
    }
}

async fn accept(conn: &AnyConnection) -> AnyIncomingDataStream {
    tokio::time::timeout(PATIENCE, conn.accept_data_stream())
        .await
        .expect("accept_data_stream waited")
        .expect("accept_data_stream")
}

/// The Request ID the stream's FETCH_HEADER names.
async fn fetch_request(stream: &mut AnyIncomingDataStream) -> u64 {
    match tokio::time::timeout(PATIENCE, stream.read_header()).await {
        Ok(Ok(AnyIncomingHeader::Fetch(header))) => header.request_id(),
        other => panic!("expected a FETCH_HEADER, got {other:?}"),
    }
}

async fn accepted_fetch(conn: &AnyConnection) -> u64 {
    let (header, _) = tokio::time::timeout(PATIENCE, conn.accept_fetch(GroupOrder::Ascending))
        .await
        .expect("accept_fetch waited")
        .expect("accept_fetch");
    header.request_id()
}

fn refused<T>(what: &str, result: Result<T, AnyConnectionError>) {
    match result {
        Ok(_) => panic!("{what}: accepted"),
        Err(e) => assert_eq!(e.cause(), &ErrorCause::Facade, "{what}: {e}"),
    }
}

/// Three streams from `from`, each handed to `to` one way and refused.
async fn every_hand_off_is_refused(from: &AnyConnection, to: &AnyConnection) {
    let stream = accept(from).await;
    refused("adopt_subgroup", to.adopt_subgroup(stream).await);
    let stream = accept(from).await;
    refused("adopt_fetch", to.adopt_fetch(stream, GroupOrder::Ascending).await);
    let stream = accept(from).await;
    refused("set_aside_fetch", to.set_aside_fetch(stream));
}

macro_rules! own_connection_gate {
    ($module:ident, $feat:literal, $version:ident, $handshake:tt, $params:tt) => {
        #[cfg(feature = $feat)]
        mod $module {
            use super::*;

            pub(super) const DRAFT: DraftVersion = DraftVersion::$version;

            draft_setup_parameters!($params);

            fn client_config() -> AnyClientConfig {
                AnyClientConfig::new(DRAFT, AnyTransportType::Quic)
                    .with_skip_cert_verification(true)
                    .with_setup_parameters(setup_parameters())
            }

            /// A connection to a peer that opens a fetch stream for each of
            /// `requests` once setup is done, and the peer's task.
            pub(super) async fn connected(
                requests: &'static [u8],
            ) -> (AnyConnection, tokio::task::JoinHandle<()>) {
                common::init_crypto();
                let (server, addr) = common::spawn_server(&[DRAFT.quic_alpn()]);
                let peer = tokio::spawn(async move {
                    let conn =
                        server.accept().await.expect("accept").await.expect("tls handshake");
                    let _control = peer_setup!($handshake, conn, $version, $module);
                    open_fetch_streams(&conn, requests).await;
                    conn.closed().await;
                });
                let conn = tokio::time::timeout(
                    PATIENCE,
                    AnyConnection::connect(&addr.to_string(), client_config()),
                )
                .await
                .expect("connect did not finish")
                .expect("connect");
                (conn, peer)
            }

            pub(super) async fn closed(conn: AnyConnection, peer: tokio::task::JoinHandle<()>) {
                conn.close(0, b"gate complete");
                tokio::time::timeout(PATIENCE * 2, peer)
                    .await
                    .expect("the peer hung")
                    .expect("the peer task");
            }

            #[tokio::test]
            async fn set_aside_streams_come_back_in_arrival_order() {
                let (conn, peer) = connected(&[1, 2]).await;
                let mut first = accept(&conn).await;
                let mut second = accept(&conn).await;
                assert_eq!(fetch_request(&mut first).await, 1);
                assert_eq!(fetch_request(&mut second).await, 2);
                conn.set_aside_fetch(second).expect("set the second stream aside");
                conn.set_aside_fetch(first).expect("set the first stream aside");
                assert_eq!(accepted_fetch(&conn).await, 1, "the first to arrive comes first");
                assert_eq!(accepted_fetch(&conn).await, 2);
                closed(conn, peer).await;
            }

            #[tokio::test]
            async fn another_connection_of_the_draft_refuses_the_stream() {
                let (first, first_peer) = connected(&[1, 2, 3, 4]).await;
                let (second, second_peer) = connected(&[]).await;
                every_hand_off_is_refused(&first, &second).await;
                let stream = accept(&first).await;
                let (header, _) = tokio::time::timeout(
                    PATIENCE,
                    first.adopt_fetch(stream, GroupOrder::Ascending),
                )
                .await
                .expect("adopt_fetch waited")
                .expect("the connection that accepted the stream takes it in");
                assert_eq!(header.request_id(), 4);
                closed(first, first_peer).await;
                closed(second, second_peer).await;
            }

            on_uni_drafts!($handshake, {
                #[tokio::test]
                async fn streams_met_before_the_control_stream_come_back_in_arrival_order() {
                    common::init_crypto();
                    let (server, addr) = common::spawn_server(&[DRAFT.quic_alpn()]);
                    let peer = tokio::spawn(async move {
                        let conn =
                            server.accept().await.expect("accept").await.expect("tls handshake");
                        let _control = peer_setup!(uni, conn, $version, $module, before: {
                            open_fetch_streams(&conn, &[1]).await;
                            // A stream of another type, ended after the type.
                            let mut other = conn.open_uni().await.expect("open a stream");
                            other.write_all(&[0x10]).await.expect("write its type");
                            other.finish().expect("finish it");
                        });
                        conn.closed().await;
                    });
                    let conn = tokio::time::timeout(
                        PATIENCE,
                        AnyConnection::connect(&addr.to_string(), client_config()),
                    )
                    .await
                    .expect("connect did not finish")
                    .expect("connect");

                    let mut fetch = accept(&conn).await;
                    assert_eq!(fetch_request(&mut fetch).await, 1, "the fetch stream came first");
                    let other = accept(&conn).await;
                    assert!(other.stream_id() > fetch.stream_id(), "the other stream came second");
                    closed(conn, peer).await;
                }
            });
        }
    };
}

own_connection_gate!(draft07, "draft07", Draft07, versioned, with_role);
own_connection_gate!(draft08, "draft08", Draft08, versioned, none);
own_connection_gate!(draft09, "draft09", Draft09, versioned, none);
own_connection_gate!(draft10, "draft10", Draft10, versioned, none);
own_connection_gate!(draft11, "draft11", Draft11, versioned, none);
own_connection_gate!(draft12, "draft12", Draft12, versioned, none);
own_connection_gate!(draft13, "draft13", Draft13, versioned, none);
own_connection_gate!(draft14, "draft14", Draft14, versioned, none);
own_connection_gate!(draft15, "draft15", Draft15, plain, none);
own_connection_gate!(draft16, "draft16", Draft16, plain, none);
own_connection_gate!(draft17, "draft17", Draft17, uni, none);
own_connection_gate!(draft18, "draft18", Draft18, uni, none);
own_connection_gate!(draft19, "draft19", Draft19, uni, none);
own_connection_gate!(draft20, "draft20", Draft20, uni, none);
own_connection_gate!(draft21, "draft21", Draft21, uni, none);
own_connection_gate!(draft22, "draft22", Draft22, uni, none);
own_connection_gate!(draft23, "draft23", Draft23, uni, none);

/// `AnyConnection` refuses a stream of another draft before that draft's
/// connection sees it.
#[cfg(all(feature = "draft14", feature = "draft23"))]
#[tokio::test]
async fn a_connection_of_another_draft_refuses_the_stream() {
    let (draft23, draft23_peer) = draft23::connected(&[1, 2, 3]).await;
    let (draft14, draft14_peer) = draft14::connected(&[]).await;
    assert_eq!(draft14.draft(), draft14::DRAFT);
    every_hand_off_is_refused(&draft23, &draft14).await;
    draft14::closed(draft14, draft14_peer).await;
    draft23::closed(draft23, draft23_peer).await;
}

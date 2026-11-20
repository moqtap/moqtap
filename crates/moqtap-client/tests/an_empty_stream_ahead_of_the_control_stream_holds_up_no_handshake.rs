//! On the drafts whose control plane is a pair of unidirectional streams, a
//! data stream the peer opens before its control stream and leaves empty holds
//! up neither `connect` nor the streams after it.
//!
//! Before its control stream the peer opens a stream it writes nothing on, then
//! a whole FETCH_HEADER stream for Request ID 1. Only once the client has
//! connected does it write a FETCH_HEADER for Request ID 2 on the first stream.
//! Both streams come back in arrival order, from `accept_data_stream` and from
//! `accept_fetch`.

#![cfg(any(
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20",
    feature = "draft21",
    feature = "draft22",
    feature = "draft23"
))]

mod common;
#[macro_use]
mod data_stream_peer;

use std::time::Duration;

use moqtap_client::dispatch::{
    AnyClientConfig, AnyConnection, AnyIncomingDataStream, AnyIncomingHeader, AnyTransportType,
};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::types::GroupOrder;
use moqtap_codec::version::DraftVersion;

/// How long any one step may take before the test fails.
const PATIENCE: Duration = Duration::from_secs(10);

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

macro_rules! empty_stream_gate {
    ($module:ident, $feat:literal, $version:ident) => {
        #[cfg(feature = $feat)]
        mod $module {
            use super::*;

            const DRAFT: DraftVersion = DraftVersion::$version;

            draft_setup_parameters!(none);

            fn client_config() -> AnyClientConfig {
                AnyClientConfig::new(DRAFT, AnyTransportType::Quic)
                    .with_skip_cert_verification(true)
                    .with_setup_parameters(setup_parameters())
            }

            /// Open the empty stream and the fetch stream, then the control
            /// stream. The empty stream gets its FETCH_HEADER when `release`
            /// fires.
            async fn serve(server: quinn::Endpoint, release: tokio::sync::oneshot::Receiver<()>) {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");
                let mut empty;
                let _control = peer_setup!(uni, conn, $version, $module, before: {
                    // Nothing is written yet: the client learns of this stream
                    // from the higher-numbered ones opened after it.
                    empty = conn.open_uni().await.expect("open the empty stream");
                    let mut fetch = conn.open_uni().await.expect("open the fetch stream");
                    fetch.write_all(&[0x05, 0x01]).await.expect("write a FETCH_HEADER");
                    fetch.finish().expect("finish the fetch stream");
                });
                release.await.expect("the client releases the empty stream");
                empty.write_all(&[0x05, 0x02]).await.expect("write the late FETCH_HEADER");
                empty.finish().expect("finish the late stream");
                conn.closed().await;
            }

            async fn connected() -> (
                AnyConnection,
                tokio::sync::oneshot::Sender<()>,
                tokio::task::JoinHandle<()>,
            ) {
                common::init_crypto();
                let (endpoint, addr) = common::spawn_server(&[DRAFT.quic_alpn()]);
                let (release, released) = tokio::sync::oneshot::channel();
                let peer = tokio::spawn(serve(endpoint, released));
                let conn = tokio::time::timeout(
                    PATIENCE,
                    AnyConnection::connect(&addr.to_string(), client_config()),
                )
                .await
                .expect("connect waited on the empty stream")
                .expect("connect");
                (conn, release, peer)
            }

            async fn closed(conn: AnyConnection, peer: tokio::task::JoinHandle<()>) {
                conn.close(0, b"gate complete");
                tokio::time::timeout(PATIENCE * 2, peer)
                    .await
                    .expect("the peer hung")
                    .expect("the peer task");
            }

            #[tokio::test]
            async fn accept_data_stream_returns_both_in_arrival_order() {
                let (conn, release, peer) = connected().await;
                let mut late = accept(&conn).await;
                let mut whole = accept(&conn).await;
                assert!(late.stream_id() < whole.stream_id(), "the empty stream came first");
                assert_eq!(fetch_request(&mut whole).await, 1);
                release.send(()).expect("release the empty stream");
                assert_eq!(fetch_request(&mut late).await, 2);
                closed(conn, peer).await;
            }

            #[tokio::test]
            async fn accept_fetch_returns_both_in_arrival_order() {
                let (conn, release, peer) = connected().await;
                release.send(()).expect("release the empty stream");
                assert_eq!(accepted_fetch(&conn).await, 2, "the empty stream came first");
                assert_eq!(accepted_fetch(&conn).await, 1);
                closed(conn, peer).await;
            }
        }
    };
}

empty_stream_gate!(draft17, "draft17", Draft17);
empty_stream_gate!(draft18, "draft18", Draft18);
empty_stream_gate!(draft19, "draft19", Draft19);
empty_stream_gate!(draft20, "draft20", Draft20);
empty_stream_gate!(draft21, "draft21", Draft21);
empty_stream_gate!(draft22, "draft22", Draft22);
empty_stream_gate!(draft23, "draft23", Draft23);

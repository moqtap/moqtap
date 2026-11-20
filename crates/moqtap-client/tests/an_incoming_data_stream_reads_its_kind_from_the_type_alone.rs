//! `AnyIncomingDataStream::read_kind` tells a fetch stream from a subgroup
//! stream by the stream type alone, on every enabled draft, and leaves the
//! stream for `read_header` and the adopts.
//!
//! The peer opens five streams: a whole subgroup, a whole FETCH_HEADER stream,
//! a fetch stream that carries only its type and is reset once the client has
//! read the kind, a stream reset before a byte is written, and an empty stream.

mod common;
#[macro_use]
mod data_stream_peer;

use std::time::Duration;

use moqtap_client::dispatch::{
    AnyClientConfig, AnyConnection, AnyConnectionError, AnyDataStreamKind, AnyIncomingDataStream,
    AnyIncomingHeader, AnyTransportType, ErrorCause, SubgroupStart,
};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::types::GroupOrder;
use moqtap_codec::version::DraftVersion;

/// How long any one step may take before the test fails.
const PATIENCE: Duration = Duration::from_secs(10);

const ALIAS: u64 = 7;
const GROUP: u64 = 3;
const SUBGROUP: u64 = 5;
const PRIORITY: u8 = 200;
const PAYLOAD: &[u8] = b"kind first";

/// FETCH_HEADER for Request ID 4: the same two bytes on every draft.
const FETCH_HEADER: [u8; 2] = [0x05, 0x04];
const FETCH_REQUEST: u64 = 4;

/// The code the peer resets streams with.
const RESET_CODE: u32 = 0x9;

async fn accept(conn: &AnyConnection) -> AnyIncomingDataStream {
    tokio::time::timeout(PATIENCE, conn.accept_data_stream())
        .await
        .expect("accept_data_stream waited")
        .expect("accept_data_stream")
}

async fn kind(what: &str, stream: &mut AnyIncomingDataStream) -> AnyDataStreamKind {
    tokio::time::timeout(PATIENCE, stream.read_kind())
        .await
        .unwrap_or_else(|_| panic!("{what}: read_kind waited"))
        .unwrap_or_else(|e| panic!("{what}: read_kind: {e}"))
}

/// Wait for `step`, and check that it failed with `cause`.
async fn fails_with<T>(
    what: &str,
    step: impl std::future::Future<Output = Result<T, AnyConnectionError>>,
    cause: ErrorCause,
) {
    match tokio::time::timeout(PATIENCE, step).await {
        Err(_) => panic!("{what}: waited"),
        Ok(Ok(_)) => panic!("{what}: succeeded"),
        Ok(Err(e)) => assert_eq!(e.cause(), &cause, "{what}: {e}"),
    }
}

fn reset() -> ErrorCause {
    ErrorCause::StreamReset(u64::from(RESET_CODE))
}

macro_rules! kind_gate {
    ($module:ident, $feat:literal, $version:ident, $handshake:tt, $params:tt) => {
        #[cfg(feature = $feat)]
        mod $module {
            use super::*;

            const DRAFT: DraftVersion = DraftVersion::$version;

            draft_setup_parameters!($params);

            fn client_config() -> AnyClientConfig {
                AnyClientConfig::new(DRAFT, AnyTransportType::Quic)
                    .with_skip_cert_verification(true)
                    .with_setup_parameters(setup_parameters())
            }

            /// Echo the client's subgroup stream, then open the fetch streams,
            /// the reset stream and the empty one. The type-only fetch stream is
            /// reset when `release` fires.
            async fn serve(server: quinn::Endpoint, release: tokio::sync::oneshot::Receiver<()>) {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");
                let _control = peer_setup!($handshake, conn, $version, $module);

                let mut recv =
                    conn.accept_uni().await.expect("accept the client's subgroup stream");
                let bytes =
                    recv.read_to_end(64 * 1024).await.expect("read the subgroup stream whole");

                let mut subgroup = conn.open_uni().await.expect("open the subgroup stream");
                subgroup.write_all(&bytes).await.expect("write the subgroup stream");
                subgroup.finish().expect("finish the subgroup stream");
                let mut fetch = conn.open_uni().await.expect("open the fetch stream");
                fetch.write_all(&FETCH_HEADER).await.expect("write the fetch header");
                fetch.finish().expect("finish the fetch stream");
                let mut cut = conn.open_uni().await.expect("open the type-only fetch stream");
                cut.write_all(&FETCH_HEADER[..1]).await.expect("write the fetch stream type");
                let mut early = conn.open_uni().await.expect("open the stream to reset");
                early.reset(quinn::VarInt::from_u32(RESET_CODE)).expect("reset the stream");
                let mut empty = conn.open_uni().await.expect("open the empty stream");
                empty.finish().expect("finish the empty stream");

                release.await.expect("the client releases the type-only fetch stream");
                cut.reset(quinn::VarInt::from_u32(RESET_CODE))
                    .expect("reset the type-only fetch stream");

                conn.closed().await;
            }

            #[tokio::test]
            async fn the_kind_comes_from_the_stream_type_alone() {
                common::init_crypto();
                let (endpoint, addr) = common::spawn_server(&[DRAFT.quic_alpn()]);
                let (release, released) = tokio::sync::oneshot::channel();
                let peer = tokio::spawn(serve(endpoint, released));

                let conn = tokio::time::timeout(
                    PATIENCE,
                    AnyConnection::connect(&addr.to_string(), client_config()),
                )
                .await
                .expect("connect did not finish")
                .expect("connect");

                let mut writer = tokio::time::timeout(
                    PATIENCE,
                    conn.open_subgroup(ALIAS, GROUP, SUBGROUP, PRIORITY, SubgroupStart::First),
                )
                .await
                .expect("opening the subgroup did not finish")
                .expect("open a subgroup stream");
                writer.write_object(0, PAYLOAD).await.expect("write the object");
                writer.finish().await.expect("finish the subgroup");

                let mut subgroup = accept(&conn).await;
                assert_eq!(kind("subgroup", &mut subgroup).await, AnyDataStreamKind::Subgroup);
                assert_eq!(
                    kind("subgroup, again", &mut subgroup).await,
                    AnyDataStreamKind::Subgroup
                );
                match tokio::time::timeout(PATIENCE, subgroup.read_header()).await {
                    Ok(Ok(AnyIncomingHeader::Subgroup(header))) => {
                        assert_eq!(header.group_id(), GROUP)
                    }
                    other => panic!("the subgroup stream's header: {other:?}"),
                }
                let (_, mut reader) = tokio::time::timeout(PATIENCE, conn.adopt_subgroup(subgroup))
                    .await
                    .expect("adopting the subgroup stream waited")
                    .expect("adopt the subgroup stream");
                let object = tokio::time::timeout(PATIENCE, reader.read_object())
                    .await
                    .expect("the subgroup stream's object waited")
                    .expect("read the subgroup stream's object");
                assert_eq!(object.payload, PAYLOAD);

                let mut fetch = accept(&conn).await;
                assert_eq!(kind("fetch", &mut fetch).await, AnyDataStreamKind::Fetch);
                match tokio::time::timeout(PATIENCE, fetch.read_header()).await {
                    Ok(Ok(AnyIncomingHeader::Fetch(header))) => {
                        assert_eq!(header.request_id(), FETCH_REQUEST)
                    }
                    other => panic!("the fetch stream's header: {other:?}"),
                }
                let (header, _) =
                    tokio::time::timeout(PATIENCE, conn.adopt_fetch(fetch, GroupOrder::Ascending))
                        .await
                        .expect("adopting the fetch stream waited")
                        .expect("adopt the fetch stream");
                assert_eq!(header.request_id(), FETCH_REQUEST);

                let mut cut = accept(&conn).await;
                assert_eq!(kind("type-only fetch", &mut cut).await, AnyDataStreamKind::Fetch);
                release.send(()).expect("release the type-only fetch stream");
                fails_with("read_header after the reset", cut.read_header(), reset()).await;
                assert_eq!(
                    kind("type-only fetch, after the reset", &mut cut).await,
                    AnyDataStreamKind::Fetch
                );

                let mut early = accept(&conn).await;
                fails_with("read_kind on a reset stream", early.read_kind(), reset()).await;
                let mut empty = accept(&conn).await;
                fails_with(
                    "read_kind on an empty stream",
                    empty.read_kind(),
                    ErrorCause::StreamEnded,
                )
                .await;

                conn.close(0, b"gate complete");
                tokio::time::timeout(PATIENCE * 2, peer)
                    .await
                    .expect("the peer hung")
                    .expect("the peer task");
            }
        }
    };
}

kind_gate!(draft07, "draft07", Draft07, versioned, with_role);
kind_gate!(draft08, "draft08", Draft08, versioned, none);
kind_gate!(draft09, "draft09", Draft09, versioned, none);
kind_gate!(draft10, "draft10", Draft10, versioned, none);
kind_gate!(draft11, "draft11", Draft11, versioned, none);
kind_gate!(draft12, "draft12", Draft12, versioned, none);
kind_gate!(draft13, "draft13", Draft13, versioned, none);
kind_gate!(draft14, "draft14", Draft14, versioned, none);
kind_gate!(draft15, "draft15", Draft15, plain, none);
kind_gate!(draft16, "draft16", Draft16, plain, none);
kind_gate!(draft17, "draft17", Draft17, uni, none);
kind_gate!(draft18, "draft18", Draft18, uni, none);
kind_gate!(draft19, "draft19", Draft19, uni, none);
kind_gate!(draft20, "draft20", Draft20, uni, none);
kind_gate!(draft21, "draft21", Draft21, uni, none);
kind_gate!(draft22, "draft22", Draft22, uni, none);
kind_gate!(draft23, "draft23", Draft23, uni, none);

//! A data stream that ends before its header has arrived reports how it ended,
//! through `AnyIncomingDataStream::read_header` and through the accepts that
//! read the header themselves, on every enabled draft: a reset as the peer's
//! reset, and a FIN as an early end.
//!
//! The peer resets three streams before writing a byte to them, then ends one
//! after the first byte of a FETCH_HEADER and one with nothing on it. On the
//! drafts whose peer can open a data stream before its control stream, two
//! streams reset before the control stream are reported the same way.

mod common;
#[macro_use]
mod data_stream_peer;

use std::time::Duration;

use moqtap_client::dispatch::{
    AnyClientConfig, AnyConnection, AnyConnectionError, AnyTransportType, ErrorCause,
};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::types::GroupOrder;
use moqtap_codec::version::DraftVersion;

/// How long any one step may take before the test fails.
const PATIENCE: Duration = Duration::from_secs(10);

/// The code the peer resets every stream with.
const RESET_CODE: u32 = 0x9;

/// Open a stream and reset it before writing a byte to it.
async fn open_and_reset(conn: &quinn::Connection) {
    let mut stream = conn.open_uni().await.expect("open a stream to reset");
    stream.reset(quinn::VarInt::from_u32(RESET_CODE)).expect("reset the stream");
}

/// Open a stream, write `bytes` and end it.
async fn open_and_finish(conn: &quinn::Connection, bytes: &[u8]) {
    let mut stream = conn.open_uni().await.expect("open a stream to end early");
    stream.write_all(bytes).await.expect("write the stream's bytes");
    stream.finish().expect("finish the stream");
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

macro_rules! ended_gate {
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

            async fn connect(addr: std::net::SocketAddr) -> AnyConnection {
                tokio::time::timeout(
                    PATIENCE,
                    AnyConnection::connect(&addr.to_string(), client_config()),
                )
                .await
                .expect("connect did not finish")
                .expect("connect")
            }

            async fn accept(conn: &AnyConnection) -> moqtap_client::dispatch::AnyIncomingDataStream {
                tokio::time::timeout(PATIENCE, conn.accept_data_stream())
                    .await
                    .expect("accept_data_stream waited")
                    .expect("accept_data_stream")
            }

            async fn serve(server: quinn::Endpoint) {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");
                let _control = peer_setup!($handshake, conn, $version, $module);
                for _ in 0..3 {
                    open_and_reset(&conn).await;
                }
                open_and_finish(&conn, &[0x05]).await;
                open_and_finish(&conn, &[]).await;
                conn.closed().await;
            }

            #[tokio::test]
            async fn a_stream_that_ends_before_its_header_reports_how() {
                common::init_crypto();
                let (endpoint, addr) = common::spawn_server(&[DRAFT.quic_alpn()]);
                let peer = tokio::spawn(serve(endpoint));
                let conn = connect(addr).await;

                let mut stream = accept(&conn).await;
                fails_with("read_header on a reset stream", stream.read_header(), reset()).await;
                fails_with("read_header again", stream.read_header(), reset()).await;
                fails_with("accept_subgroup on a reset stream", conn.accept_subgroup(), reset())
                    .await;
                fails_with(
                    "accept_fetch on a reset stream",
                    conn.accept_fetch(GroupOrder::Ascending),
                    reset(),
                )
                .await;

                let mut cut = accept(&conn).await;
                fails_with("a FETCH_HEADER cut short", cut.read_header(), ErrorCause::StreamEnded)
                    .await;
                let mut empty = accept(&conn).await;
                fails_with("an empty stream", empty.read_header(), ErrorCause::StreamEnded).await;

                conn.close(0, b"gate complete");
                tokio::time::timeout(PATIENCE * 2, peer)
                    .await
                    .expect("the peer hung")
                    .expect("the peer task");
            }

            on_uni_drafts!($handshake, {
                async fn serve_resets_first(server: quinn::Endpoint) {
                    let conn =
                        server.accept().await.expect("accept").await.expect("tls handshake");
                    let _control = peer_setup!(uni, conn, $version, $module, before: {
                        open_and_reset(&conn).await;
                        open_and_reset(&conn).await;
                    });
                    conn.closed().await;
                }

                #[tokio::test]
                async fn a_stream_reset_before_the_control_stream_reports_the_reset() {
                    common::init_crypto();
                    let (endpoint, addr) = common::spawn_server(&[DRAFT.quic_alpn()]);
                    let peer = tokio::spawn(serve_resets_first(endpoint));
                    let conn = connect(addr).await;

                    fails_with("accept_subgroup", conn.accept_subgroup(), reset()).await;
                    let mut stream = accept(&conn).await;
                    fails_with("read_header", stream.read_header(), reset()).await;

                    conn.close(0, b"gate complete");
                    tokio::time::timeout(PATIENCE * 2, peer)
                        .await
                        .expect("the peer hung")
                        .expect("the peer task");
                }
            });
        }
    };
}

ended_gate!(draft07, "draft07", Draft07, versioned, with_role);
ended_gate!(draft08, "draft08", Draft08, versioned, none);
ended_gate!(draft09, "draft09", Draft09, versioned, none);
ended_gate!(draft10, "draft10", Draft10, versioned, none);
ended_gate!(draft11, "draft11", Draft11, versioned, none);
ended_gate!(draft12, "draft12", Draft12, versioned, none);
ended_gate!(draft13, "draft13", Draft13, versioned, none);
ended_gate!(draft14, "draft14", Draft14, versioned, none);
ended_gate!(draft15, "draft15", Draft15, plain, none);
ended_gate!(draft16, "draft16", Draft16, plain, none);
ended_gate!(draft17, "draft17", Draft17, uni, none);
ended_gate!(draft18, "draft18", Draft18, uni, none);
ended_gate!(draft19, "draft19", Draft19, uni, none);
ended_gate!(draft20, "draft20", Draft20, uni, none);
ended_gate!(draft21, "draft21", Draft21, uni, none);
ended_gate!(draft22, "draft22", Draft22, uni, none);
ended_gate!(draft23, "draft23", Draft23, uni, none);

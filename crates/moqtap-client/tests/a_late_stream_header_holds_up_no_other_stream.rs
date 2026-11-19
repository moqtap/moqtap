//! `AnyConnection::accept_data_stream` hands a stream over before its header
//! has arrived, so a stream whose header is late holds up no stream after it,
//! on every enabled draft.
//!
//! The peer opens three streams: a subgroup whose first byte alone is sent, a
//! whole copy of the same subgroup, and a FETCH_HEADER stream. The second and
//! third are read and taken in while the first waits, and the first is read
//! once the peer is told to send the rest.

mod common;
#[macro_use]
mod data_stream_peer;

use std::time::Duration;

use moqtap_client::dispatch::{
    AnyClientConfig, AnyConnection, AnyIncomingHeader, AnyTransportType, SubgroupStart,
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
const PAYLOAD: &[u8] = b"held up by nothing";

/// FETCH_HEADER for Request ID 4: the same two bytes on every draft.
const FETCH_HEADER: [u8; 2] = [0x05, 0x04];
const FETCH_REQUEST: u64 = 4;

macro_rules! late_header_gate {
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

            /// Echo the client's subgroup stream twice, the first copy cut
            /// after one byte until `release` fires, then open a fetch stream.
            async fn serve(server: quinn::Endpoint, release: tokio::sync::oneshot::Receiver<()>) {
                let conn = server.accept().await.expect("accept").await.expect("tls handshake");
                let _control = peer_setup!($handshake, conn, $version, $module);

                let mut recv =
                    conn.accept_uni().await.expect("accept the client's subgroup stream");
                let bytes =
                    recv.read_to_end(64 * 1024).await.expect("read the subgroup stream whole");

                let mut late = conn.open_uni().await.expect("open the late stream");
                late.write_all(&bytes[..1]).await.expect("write the late stream's first byte");
                let mut prompt = conn.open_uni().await.expect("open the prompt stream");
                prompt.write_all(&bytes).await.expect("write the prompt stream");
                prompt.finish().expect("finish the prompt stream");
                let mut fetch = conn.open_uni().await.expect("open the fetch stream");
                fetch.write_all(&FETCH_HEADER).await.expect("write the fetch header");
                fetch.finish().expect("finish the fetch stream");

                release.await.expect("the client releases the late stream");
                late.write_all(&bytes[1..]).await.expect("write the rest of the late stream");
                late.finish().expect("finish the late stream");

                conn.closed().await;
            }

            #[tokio::test]
            async fn a_late_header_holds_up_no_later_stream() {
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

                let mut accepted = Vec::new();
                for which in ["late", "prompt", "fetch"] {
                    accepted.push(
                        tokio::time::timeout(PATIENCE, conn.accept_data_stream())
                            .await
                            .unwrap_or_else(|_| panic!("accepting the {which} stream waited"))
                            .unwrap_or_else(|e| panic!("accept the {which} stream: {e}")),
                    );
                }
                let mut fetch = accepted.pop().expect("fetch stream");
                let mut prompt = accepted.pop().expect("prompt stream");
                let mut late = accepted.pop().expect("late stream");
                assert_eq!(late.draft(), DRAFT);
                assert!(late.stream_id() < prompt.stream_id(), "the late stream is the lower");

                let late_read = tokio::spawn(async move {
                    let header = late.read_header().await;
                    (header, late)
                });

                match tokio::time::timeout(PATIENCE, prompt.read_header()).await {
                    Ok(Ok(AnyIncomingHeader::Subgroup(header))) => {
                        assert_eq!(header.group_id(), GROUP)
                    }
                    other => panic!("the prompt stream's header: {other:?}"),
                }
                match tokio::time::timeout(PATIENCE, prompt.read_header()).await {
                    Ok(Ok(AnyIncomingHeader::Subgroup(header))) => {
                        assert_eq!(
                            header.group_id(),
                            GROUP,
                            "a second read returns the same header"
                        )
                    }
                    other => panic!("the prompt stream's header, read again: {other:?}"),
                }
                let (_, mut reader) = tokio::time::timeout(PATIENCE, conn.adopt_subgroup(prompt))
                    .await
                    .expect("adopting the prompt stream waited")
                    .expect("adopt the prompt stream");
                let object = tokio::time::timeout(PATIENCE, reader.read_object())
                    .await
                    .expect("the prompt stream's object waited")
                    .expect("read the prompt stream's object");
                assert_eq!(object.payload, PAYLOAD);

                match tokio::time::timeout(PATIENCE, fetch.read_header()).await {
                    Ok(Ok(AnyIncomingHeader::Fetch(header))) => {
                        assert_eq!(header.request_id(), FETCH_REQUEST)
                    }
                    other => panic!("the fetch stream's header: {other:?}"),
                }
                conn.set_aside_fetch(fetch).expect("set the fetch stream aside");
                let (header, _) =
                    tokio::time::timeout(PATIENCE, conn.accept_fetch(GroupOrder::Ascending))
                        .await
                        .expect("the set-aside fetch stream waited")
                        .expect("accept the set-aside fetch stream");
                assert_eq!(header.request_id(), FETCH_REQUEST);

                assert!(!late_read.is_finished(), "the late stream's header has not been sent");
                release.send(()).expect("release the late stream");
                let (header, late) = tokio::time::timeout(PATIENCE, late_read)
                    .await
                    .expect("the late stream's header never arrived")
                    .expect("the late stream's task");
                assert!(
                    matches!(header, Ok(AnyIncomingHeader::Subgroup(_))),
                    "the late stream's header: {header:?}"
                );
                let (_, mut reader) =
                    conn.adopt_subgroup(late).await.expect("adopt the late stream");
                let object = tokio::time::timeout(PATIENCE, reader.read_object())
                    .await
                    .expect("the late stream's object waited")
                    .expect("read the late stream's object");
                assert_eq!(object.payload, PAYLOAD);

                conn.close(0, b"gate complete");
                tokio::time::timeout(PATIENCE * 2, peer)
                    .await
                    .expect("the peer hung")
                    .expect("the peer task");
            }
        }
    };
}

late_header_gate!(draft07, "draft07", Draft07, versioned, with_role);
late_header_gate!(draft08, "draft08", Draft08, versioned, none);
late_header_gate!(draft09, "draft09", Draft09, versioned, none);
late_header_gate!(draft10, "draft10", Draft10, versioned, none);
late_header_gate!(draft11, "draft11", Draft11, versioned, none);
late_header_gate!(draft12, "draft12", Draft12, versioned, none);
late_header_gate!(draft13, "draft13", Draft13, versioned, none);
late_header_gate!(draft14, "draft14", Draft14, versioned, none);
late_header_gate!(draft15, "draft15", Draft15, plain, none);
late_header_gate!(draft16, "draft16", Draft16, plain, none);
late_header_gate!(draft17, "draft17", Draft17, uni, none);
late_header_gate!(draft18, "draft18", Draft18, uni, none);
late_header_gate!(draft19, "draft19", Draft19, uni, none);
late_header_gate!(draft20, "draft20", Draft20, uni, none);
late_header_gate!(draft21, "draft21", Draft21, uni, none);
late_header_gate!(draft22, "draft22", Draft22, uni, none);
late_header_gate!(draft23, "draft23", Draft23, uni, none);

//! End-to-end forwarding smoke test.
//!
//! Drives a client ↔ proxy ↔ upstream topology with a `NoOpHook` and
//! asserts that a CLIENT_SETUP / SERVER_SETUP handshake round-trip plus a
//! follow-up SUBSCRIBE message reach the upstream unmodified.
//!
//! This is the baseline check that the proxy's pass-through control path
//! (`wants_control_mutation = false`) does not alter or drop bytes.

mod common;

use std::sync::Arc;

use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::draft14::message::{ClientSetup, ControlMessage, ServerSetup, Subscribe};
use moqtap_codec::types::{FilterType, Forward, GroupOrder, TrackNamespace};
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

use moqtap_proxy::event::SessionId;
use moqtap_proxy::hook::NoOpHook;
use moqtap_proxy::observer::NoOpProxyObserver;
use moqtap_proxy::session::{ProxySession, ProxySessionConfig, UpstreamTransportType};

use tokio_util::sync::CancellationToken;

const DRAFT14_VERSION: u64 = 0xff000000 + 14;

fn sample_subscribe() -> ControlMessage {
    ControlMessage::Subscribe(Subscribe {
        request_id: VarInt::from_u64(1).unwrap(),
        track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
        track_name: b"video".to_vec(),
        subscriber_priority: 128,
        group_order: GroupOrder::Ascending,
        forward: Forward::Forward,
        filter_type: FilterType::NextGroupStart,
        start_location: None,
        end_group: None,
        parameters: Vec::new(),
    })
}

#[tokio::test]
async fn passthrough_forwards_setup_and_subscribe_unchanged() {
    common::init_crypto();

    let (upstream_ep, upstream_addr) = common::spawn_quic_server(&[b"moq-00"]);
    let expected_subscribe = sample_subscribe();
    let expected_subscribe_clone = expected_subscribe.clone();
    let (sub_tx, sub_rx) = tokio::sync::oneshot::channel::<AnyControlMessage>();

    let upstream_task = tokio::spawn(async move {
        let incoming = upstream_ep.accept().await.expect("upstream accept");
        let conn = incoming.await.expect("upstream tls");
        let (send, recv) = conn.accept_bi().await.expect("upstream accept_bi");
        let (mut framed_send, mut framed_recv) =
            common::frame_bi(send, recv, DraftVersion::Draft14);

        let (msg, _) = framed_recv.read_control(false).await.expect("read CLIENT_SETUP");
        let selected = match msg {
            AnyControlMessage::Draft14(ControlMessage::ClientSetup(cs)) => cs.supported_versions[0],
            other => panic!("expected CLIENT_SETUP, got {other:?}"),
        };

        let server_setup = AnyControlMessage::Draft14(ControlMessage::ServerSetup(ServerSetup {
            selected_version: selected,
            parameters: vec![],
        }));
        framed_send.write_control(&server_setup).await.expect("write SERVER_SETUP");

        let (msg, _) = framed_recv.read_control(false).await.expect("read SUBSCRIBE");
        let _ = sub_tx.send(msg);

        // Keep the connection alive until the client closes.
        let _ = conn.closed().await;
    });

    let (proxy_front_ep, proxy_addr) = common::spawn_quic_server(&[b"moq-00"]);

    let cancel = CancellationToken::new();
    let proxy_cancel = cancel.clone();
    let proxy_task = tokio::spawn(async move {
        let incoming = proxy_front_ep.accept().await.expect("proxy accept");
        let client_conn = incoming.await.expect("proxy tls");

        let session = ProxySession::new(
            SessionId(1),
            ProxySessionConfig {
                draft: DraftVersion::Draft14,
                upstream_transport: UpstreamTransportType::Quic,
                upstream_addr: upstream_addr.to_string(),
                skip_upstream_cert_verify: true,
                upstream_ca_certs: Vec::new(),
                upstream_connect_timeout_secs: 5,
            },
            b"moq-00".to_vec(),
            Arc::new(NoOpProxyObserver),
            Arc::new(NoOpHook),
            proxy_cancel,
        );
        let _ = session.run(client_conn).await;
    });

    let client_ep = common::client_endpoint(&[b"moq-00"]);
    let client_conn = client_ep
        .connect(proxy_addr, "localhost")
        .expect("client connect")
        .await
        .expect("client handshake");

    let (send, recv) = client_conn.open_bi().await.expect("open_bi");
    let (mut framed_send, mut framed_recv) = common::frame_bi(send, recv, DraftVersion::Draft14);

    let client_setup = AnyControlMessage::Draft14(ControlMessage::ClientSetup(ClientSetup {
        supported_versions: vec![VarInt::from_u64(DRAFT14_VERSION).unwrap()],
        parameters: vec![],
    }));
    framed_send.write_control(&client_setup).await.expect("write CLIENT_SETUP");

    let (server_setup_msg, _) = framed_recv.read_control(false).await.expect("read SERVER_SETUP");
    match server_setup_msg {
        AnyControlMessage::Draft14(ControlMessage::ServerSetup(ss)) => {
            assert_eq!(ss.selected_version.into_inner(), DRAFT14_VERSION);
        }
        other => panic!("expected SERVER_SETUP, got {other:?}"),
    }

    let subscribe_any = AnyControlMessage::Draft14(expected_subscribe);
    framed_send.write_control(&subscribe_any).await.expect("write SUBSCRIBE");

    // Both ends use the same codec, so struct equality implies byte equality.
    let got = tokio::time::timeout(std::time::Duration::from_secs(5), sub_rx)
        .await
        .expect("upstream received SUBSCRIBE within timeout")
        .expect("oneshot");

    match got {
        AnyControlMessage::Draft14(inner) => {
            assert_eq!(inner, expected_subscribe_clone);
        }
        other => panic!("expected SUBSCRIBE on upstream, got {other:?}"),
    }

    client_conn.close(0u32.into(), b"done");
    cancel.cancel();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), proxy_task).await;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), upstream_task).await;
}

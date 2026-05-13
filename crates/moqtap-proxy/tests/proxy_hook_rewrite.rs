//! Hook-driven control-message rewrite test.
//!
//! Topology matches `proxy_forward.rs` but with a `RewritingHook` that
//! turns any SUBSCRIBE targeting namespace `foo` into a SUBSCRIBE targeting
//! namespace `bar`. The assertion is twofold:
//!
//! 1. The hook observes the original (pre-rewrite) message — variant
//!    dispatch and decode are correct.
//! 2. The upstream receives the rewritten bytes, decoded as a SUBSCRIBE
//!    with namespace `bar`.
//!
//! Non-matching frames (CLIENT_SETUP, SERVER_SETUP) must flow through
//! unchanged even though `wants_control_mutation = true` forces the
//! parse-then-forward path.

mod common;

use std::sync::{Arc, Mutex};

use moqtap_codec::dispatch::{AnyControlMessage, AnyDatagramHeader};
use moqtap_codec::draft14::message::{ClientSetup, ControlMessage, ServerSetup, Subscribe};
use moqtap_codec::types::{FilterType, Forward, GroupOrder, TrackNamespace};
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

use moqtap_proxy::event::{ProxySide, SessionId};
use moqtap_proxy::hook::ProxyHook;
use moqtap_proxy::observer::NoOpProxyObserver;
use moqtap_proxy::session::{ProxySession, ProxySessionConfig, UpstreamTransportType};

use tokio_util::sync::CancellationToken;

const DRAFT14_VERSION: u64 = 0xff000000 + 14;

/// Hook that rewrites SUBSCRIBE's track namespace from a configured
/// `from` tuple to a configured `to` tuple. Records every decoded control
/// message it sees so the test can verify the hook's view of the flow.
struct RewritingHook {
    from: Vec<Vec<u8>>,
    to: Vec<Vec<u8>>,
    seen: Arc<Mutex<Vec<AnyControlMessage>>>,
}

impl RewritingHook {
    fn new(
        from: Vec<Vec<u8>>,
        to: Vec<Vec<u8>>,
    ) -> (Arc<Self>, Arc<Mutex<Vec<AnyControlMessage>>>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let hook = Arc::new(Self { from, to, seen: Arc::clone(&seen) });
        (hook, seen)
    }
}

impl ProxyHook for RewritingHook {
    fn wants_control_mutation(&self) -> bool {
        true
    }

    fn on_control_message(
        &self,
        _session_id: SessionId,
        _side: ProxySide,
        message: &AnyControlMessage,
        _raw_bytes: &[u8],
    ) -> Option<Vec<u8>> {
        self.seen.lock().unwrap().push(message.clone());

        let AnyControlMessage::Draft14(ControlMessage::Subscribe(sub)) = message else {
            return None;
        };
        if sub.track_namespace.0 != self.from {
            return None;
        }

        let mut rewritten = sub.clone();
        rewritten.track_namespace = TrackNamespace(self.to.clone());
        let mut buf = Vec::new();
        AnyControlMessage::Draft14(ControlMessage::Subscribe(rewritten))
            .encode(&mut buf)
            .expect("re-encode subscribe");
        Some(buf)
    }

    fn on_datagram(
        &self,
        _session_id: SessionId,
        _side: ProxySide,
        _header: &AnyDatagramHeader,
        _raw_bytes: &[u8],
    ) -> Option<Vec<u8>> {
        None
    }
}

fn subscribe_with_ns(ns: Vec<Vec<u8>>) -> ControlMessage {
    ControlMessage::Subscribe(Subscribe {
        request_id: VarInt::from_u64(42).unwrap(),
        track_namespace: TrackNamespace(ns),
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
async fn subscribe_namespace_foo_is_rewritten_to_bar() {
    common::init_crypto();

    let (upstream_ep, upstream_addr) = common::spawn_quic_server(&[b"moq-00"]);
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

        // The SUBSCRIBE the hook should have rewritten.
        let (msg, _) = framed_recv.read_control(false).await.expect("read SUBSCRIBE");
        let _ = sub_tx.send(msg);

        let _ = conn.closed().await;
    });

    let (proxy_front_ep, proxy_addr) = common::spawn_quic_server(&[b"moq-00"]);
    let (hook, hook_seen) = RewritingHook::new(vec![b"foo".to_vec()], vec![b"bar".to_vec()]);

    let cancel = CancellationToken::new();
    let proxy_cancel = cancel.clone();
    let hook_for_session: Arc<dyn ProxyHook> = hook.clone();
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
            hook_for_session,
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
    assert!(matches!(server_setup_msg, AnyControlMessage::Draft14(ControlMessage::ServerSetup(_))));

    let foo_subscribe = AnyControlMessage::Draft14(subscribe_with_ns(vec![b"foo".to_vec()]));
    framed_send.write_control(&foo_subscribe).await.expect("write SUBSCRIBE(foo)");

    let got = tokio::time::timeout(std::time::Duration::from_secs(5), sub_rx)
        .await
        .expect("upstream SUBSCRIBE within timeout")
        .expect("oneshot");

    match got {
        AnyControlMessage::Draft14(ControlMessage::Subscribe(s)) => {
            assert_eq!(
                s.track_namespace.0,
                vec![b"bar".to_vec()],
                "namespace should have been rewritten to bar",
            );
            assert_eq!(s.request_id.into_inner(), 42);
            assert_eq!(s.track_name, b"video");
        }
        other => panic!("expected SUBSCRIBE, got {other:?}"),
    }

    let seen = hook_seen.lock().unwrap().clone();
    assert!(
        seen.iter()
            .any(|m| matches!(m, AnyControlMessage::Draft14(ControlMessage::ClientSetup(_)))),
        "hook should have observed CLIENT_SETUP: {seen:?}",
    );
    assert!(
        seen.iter().any(|m| {
            matches!(
                m,
                AnyControlMessage::Draft14(ControlMessage::Subscribe(s))
                    if s.track_namespace.0 == vec![b"foo".to_vec()]
            )
        }),
        "hook should have observed SUBSCRIBE(foo): {seen:?}",
    );

    client_conn.close(0u32.into(), b"done");
    cancel.cancel();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), proxy_task).await;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), upstream_task).await;
}

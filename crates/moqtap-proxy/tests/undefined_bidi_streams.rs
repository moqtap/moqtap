//! Drafts 07-15 define one bidirectional stream, the control stream. Any other
//! bidirectional stream, from either peer, is forwarded unread so the far peer
//! answers it as its draft says.

#![cfg(feature = "draft14")]

mod common;

use std::sync::Arc;
use std::time::Duration;

use moqtap_proxy::hook::NoOpHook;
use moqtap_proxy::observer::NoOpProxyObserver;

const PATIENCE: Duration = Duration::from_secs(10);

async fn read_exact(recv: &mut quinn::RecvStream, n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    tokio::time::timeout(PATIENCE, recv.read_exact(&mut buf))
        .await
        .expect("the bytes arrive in time")
        .expect("the stream carries them");
    buf
}

#[tokio::test]
async fn bidi_streams_beside_the_control_stream_are_forwarded_both_ways() {
    common::init_crypto();
    let relay = common::FakeRelay::bind(b"moq-00");
    let proxy = common::spawn_proxy(relay.addr, Arc::new(NoOpProxyObserver), Arc::new(NoOpHook));
    let (_client_ep, client) = common::connect_client(proxy.addr, b"moq-00").await;

    // The control stream; held open, since a FIN on it ends the session.
    let (mut control, _control_recv) = client.open_bi().await.expect("control stream");
    control.write_all(b"\x40\x40").await.expect("a first byte on the control stream");
    let (_relay_control, _relay_control_recv) = relay.accept_bi().await;

    // A second stream from the client reaches the relay, and its answer comes back.
    let (mut send, mut recv) = client.open_bi().await.expect("a second bidi stream");
    send.write_all(b"from client").await.expect("written");
    let (mut relay_send, mut relay_recv) =
        tokio::time::timeout(PATIENCE, relay.accept_bi()).await.expect("reaches the relay");
    assert_eq!(read_exact(&mut relay_recv, 11).await, b"from client");
    relay_send.write_all(b"answer").await.expect("written");
    assert_eq!(read_exact(&mut recv, 6).await, b"answer");

    // A stream the relay opens reaches the client.
    let relay_conn = relay.connection().await;
    let (mut send, _recv) = relay_conn.open_bi().await.expect("a relay bidi stream");
    send.write_all(b"from relay").await.expect("written");
    let (_client_send, mut client_recv) = tokio::time::timeout(PATIENCE, client.accept_bi())
        .await
        .expect("reaches the client")
        .expect("accepted");
    assert_eq!(read_exact(&mut client_recv, 10).await, b"from relay");

    proxy.shutdown().await;
}

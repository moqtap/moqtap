//! `stream_id` is the QUIC stream ID (RFC 9000 Section 2.1), not quinn's per-type index.

mod common;

use moqtap_client::transport::{RecvStream, SendStream};

#[tokio::test]
async fn a_stream_id_is_the_quic_stream_id() {
    common::init_crypto();
    let alpn: &[&[u8]] = &[b"moqtap-test"];
    let (server, addr) = common::spawn_server(alpn);
    let client = common::client_endpoint(alpn);

    let accepting = tokio::spawn(async move {
        let conn = server.accept().await.expect("accept").await.expect("handshake");
        let mut ids = Vec::new();
        for _ in 0..2 {
            let (_send, recv) = conn.accept_bi().await.expect("accept_bi");
            ids.push(RecvStream::Quic(recv).stream_id());
        }
        let recv = conn.accept_uni().await.expect("accept_uni");
        ids.push(RecvStream::Quic(recv).stream_id());
        ids
    });

    let conn = client.connect(addr, "localhost").expect("connect").await.expect("handshake");
    let mut sent = Vec::new();
    let mut keep = Vec::new();
    for _ in 0..2 {
        let (mut send, recv) = conn.open_bi().await.expect("open_bi");
        // A stream reaches the peer only once something is written on it.
        send.write_all(&[0]).await.expect("write");
        sent.push(SendStream::Quic(send));
        keep.push(recv);
    }
    let mut uni = conn.open_uni().await.expect("open_uni");
    uni.write_all(&[0]).await.expect("write");
    sent.push(SendStream::Quic(uni));

    let opened: Vec<u64> = sent.iter().map(SendStream::stream_id).collect();
    // Client-initiated bidirectional streams are 0 mod 4, unidirectional 2 mod 4.
    assert_eq!(opened, vec![0, 4, 2]);
    assert_eq!(accepting.await.expect("server task"), opened);
}

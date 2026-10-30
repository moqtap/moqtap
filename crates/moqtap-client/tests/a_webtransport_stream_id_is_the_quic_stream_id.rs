//! Over WebTransport, `stream_id` is the QUIC stream ID too, the same at both
//! ends, and it outlives `finish`.

#![cfg(feature = "webtransport")]

mod common;

use std::net::SocketAddr;

use moqtap_client::transport::webtransport::WebTransportTransport;
use moqtap_client::transport::{RecvStream, SendStream};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};

#[tokio::test]
async fn a_webtransport_stream_id_is_the_quic_stream_id() {
    common::init_crypto();
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("keypair");
    let cert = CertificateParams::new(vec!["localhost".into()])
        .expect("params")
        .self_signed(&key_pair)
        .expect("self-sign");
    let identity = wtransport::Identity::new(
        wtransport::tls::CertificateChain::single(
            wtransport::tls::Certificate::from_der(cert.der().to_vec()).expect("DER"),
        ),
        wtransport::tls::PrivateKey::from_der_pkcs8(key_pair.serialize_der()),
    );
    let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server = wtransport::Endpoint::server(
        wtransport::ServerConfig::builder().with_bind_address(bind).with_identity(identity).build(),
    )
    .expect("server");
    let addr = server.local_addr().expect("local_addr");

    let accepting = tokio::spawn(async move {
        let request = server.accept().await.await.expect("session request");
        let conn = WebTransportTransport::new(request.accept().await.expect("accept"));
        let mut ids = Vec::new();
        let mut keep = Vec::new();
        for _ in 0..2 {
            let (send, recv) = conn.accept_bi().await.expect("accept_bi");
            ids.push((send.stream_id(), recv.stream_id()));
            keep.push(send);
        }
        let recv = conn.accept_uni().await.expect("accept_uni");
        ids.push((recv.stream_id(), recv.stream_id()));
        (ids, conn, keep)
    });

    let client = wtransport::Endpoint::client(
        wtransport::ClientConfig::builder().with_bind_default().with_no_cert_validation().build(),
    )
    .expect("client");
    let conn = WebTransportTransport::new(
        client.connect(format!("https://{addr}/")).await.expect("connect"),
    );
    let mut opened: Vec<(SendStream, RecvStream)> = Vec::new();
    for _ in 0..2 {
        let (mut send, recv) = conn.open_bi().await.expect("open_bi");
        // A stream reaches the peer only once something is written on it.
        send.write_all(&[0]).await.expect("write");
        opened.push((send, recv));
    }
    let mut uni = conn.open_uni().await.expect("open_uni");
    uni.write_all(&[0]).await.expect("write");
    uni.finish().expect("finish");

    let mut ids: Vec<(u64, u64)> =
        opened.iter().map(|(s, r)| (s.stream_id(), r.stream_id())).collect();
    ids.push((uni.stream_id(), uni.stream_id()));

    // Client-initiated bidirectional streams are 0 mod 4, unidirectional 2
    // mod 4; stream 0 carries the session's CONNECT, so none of these is 0.
    let kinds: Vec<u64> = ids.iter().map(|(s, _)| s % 4).collect();
    assert_eq!(kinds, vec![0, 0, 2]);
    assert!(ids.iter().all(|&(s, r)| s == r && s != 0), "{ids:?}");
    assert_ne!(ids[0].0, ids[1].0);
    assert_eq!(accepting.await.expect("server task").0, ids);
}

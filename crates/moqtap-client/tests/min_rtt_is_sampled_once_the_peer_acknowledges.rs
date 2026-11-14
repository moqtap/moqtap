//! `min_rtt` on a loopback connection, over QUIC and over WebTransport.

mod common;

use std::time::Duration;

use moqtap_client::transport::{dial_quic, QuicDialOptions, Transport};

const PATIENCE: Duration = Duration::from_secs(10);

/// quinn's initial RTT, which it reports as the minimum before any sample.
const INITIAL_RTT: Duration = Duration::from_millis(333);

const ALPN: &[u8] = b"moqtap-min-rtt";

/// Waits for the first sample, which an ACK can deliver after the handshake.
async fn first_sample(transport: &Transport) -> Duration {
    tokio::time::timeout(PATIENCE, async {
        loop {
            if let Some(rtt) = transport.min_rtt() {
                return rtt;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the peer acknowledges a packet within the timeout")
}

#[tokio::test]
async fn a_quic_connection_reports_a_sampled_min_rtt() {
    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[ALPN]);
    let server = tokio::spawn(async move {
        let conn = endpoint.accept().await.expect("accept").await.expect("handshake");
        conn.closed().await;
    });

    let options = QuicDialOptions::new(vec![ALPN.to_vec()]).insecure(true);
    let (transport, _) = tokio::time::timeout(PATIENCE, dial_quic(&addr.to_string(), &options))
        .await
        .expect("the dial completes within the timeout")
        .expect("dial");

    let rtt = first_sample(&transport).await;
    assert!(rtt < INITIAL_RTT, "a loopback sample is below quinn's initial RTT, got {rtt:?}");

    transport.close(0, b"");
    let _ = tokio::time::timeout(PATIENCE, server).await;
}

#[cfg(feature = "webtransport")]
#[tokio::test]
async fn a_webtransport_connection_reports_a_sampled_min_rtt() {
    use std::net::SocketAddr;

    use moqtap_client::transport::webtransport::WebTransportTransport;
    use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};

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
        let conn = request.accept().await.expect("accept");
        conn.closed().await;
    });

    let client = wtransport::Endpoint::client(
        wtransport::ClientConfig::builder().with_bind_default().with_no_cert_validation().build(),
    )
    .expect("client");
    let session = tokio::time::timeout(PATIENCE, client.connect(format!("https://{addr}/")))
        .await
        .expect("the session opens within the timeout")
        .expect("connect");
    let transport = Transport::WebTransport(WebTransportTransport::new(session));

    let rtt = first_sample(&transport).await;
    assert!(rtt < INITIAL_RTT, "a loopback sample is below quinn's initial RTT, got {rtt:?}");

    transport.close(0, b"");
    let _ = tokio::time::timeout(PATIENCE, accepting).await;
}

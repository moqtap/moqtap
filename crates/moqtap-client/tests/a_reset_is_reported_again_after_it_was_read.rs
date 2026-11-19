//! Once a read has returned a peer's reset, `FramedRecvStream::received_reset`
//! answers with the same code, and so does every later read, on every enabled
//! draft that has `received_reset`, over QUIC and over WebTransport.

#![cfg(any(
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20",
    feature = "draft21",
    feature = "draft22",
    feature = "draft23"
))]

mod common;

use std::time::Duration;

use moqtap_client::transport::{RecvStream, TransportError};
use moqtap_codec::version::DraftVersion;

/// How long any one step may take before the test fails.
const PATIENCE: Duration = Duration::from_secs(10);

/// The code the peer resets the stream with.
const RESET_CODE: u32 = 0x9;

/// A unidirectional stream the peer opened and reset before writing a byte.
async fn reset_stream() -> (quinn::RecvStream, quinn::Connection, quinn::Connection) {
    common::init_crypto();
    let alpn: &[&[u8]] = &[b"moqtap-test"];
    let (server, addr) = common::spawn_server(alpn);
    let client = common::client_endpoint(alpn);
    let (client_conn, server_conn) = tokio::join!(
        async { client.connect(addr, "localhost").expect("connect").await.expect("handshake") },
        async { server.accept().await.expect("accept").await.expect("handshake") },
    );
    let mut send = client_conn.open_uni().await.expect("open a stream");
    send.reset(quinn::VarInt::from_u32(RESET_CODE)).expect("reset the stream");
    let recv = tokio::time::timeout(PATIENCE, server_conn.accept_uni())
        .await
        .expect("accept_uni waited")
        .expect("accept_uni");
    (recv, client_conn, server_conn)
}

macro_rules! reset_gate {
    ($module:ident, $feat:literal, $version:ident) => {
        #[cfg(feature = $feat)]
        mod $module {
            use super::*;
            use moqtap_client::$module::connection::{ConnectionError, FramedRecvStream};

            fn is_reset<T: std::fmt::Debug>(what: &str, result: Result<T, ConnectionError>) {
                match result {
                    Err(ConnectionError::Transport(TransportError::StreamReset(code))) => {
                        assert_eq!(code, u64::from(RESET_CODE), "{what}")
                    }
                    other => panic!("{what}: {other:?}"),
                }
            }

            #[tokio::test]
            async fn received_reset_answers_after_a_read_returned_the_reset() {
                let (recv, _client, _server) = reset_stream().await;
                let mut framed =
                    FramedRecvStream::new(RecvStream::Quic(recv), DraftVersion::$version);

                let read = tokio::time::timeout(PATIENCE, framed.read_subgroup_header())
                    .await
                    .expect("the first read waited");
                is_reset("the first read", read);

                let code = tokio::time::timeout(PATIENCE, framed.received_reset())
                    .await
                    .expect("received_reset waited")
                    .expect("received_reset");
                assert_eq!(code, Some(u64::from(RESET_CODE)));

                let read = tokio::time::timeout(PATIENCE, framed.read_subgroup_header())
                    .await
                    .expect("the second read waited");
                is_reset("the second read", read);
            }
        }
    };
}

reset_gate!(draft16, "draft16", Draft16);
reset_gate!(draft17, "draft17", Draft17);
reset_gate!(draft18, "draft18", Draft18);
reset_gate!(draft19, "draft19", Draft19);
reset_gate!(draft20, "draft20", Draft20);
reset_gate!(draft21, "draft21", Draft21);
reset_gate!(draft22, "draft22", Draft22);
reset_gate!(draft23, "draft23", Draft23);

/// Over WebTransport, which has no reset-only observable, `received_reset`
/// learns of the reset from the read that returned it.
#[cfg(all(feature = "webtransport", feature = "draft23"))]
mod webtransport {
    use std::net::SocketAddr;

    use moqtap_client::draft23::connection::FramedRecvStream;
    use moqtap_client::transport::webtransport::WebTransportTransport;
    use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};

    use super::*;

    #[tokio::test]
    async fn received_reset_answers_after_a_read_returned_the_reset() {
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
            wtransport::ServerConfig::builder()
                .with_bind_address(bind)
                .with_identity(identity)
                .build(),
        )
        .expect("server");
        let addr = server.local_addr().expect("local_addr");
        let (accepted, reset_now) = tokio::sync::oneshot::channel();

        let reading = tokio::spawn(async move {
            let request = server.accept().await.await.expect("session request");
            let conn = WebTransportTransport::new(request.accept().await.expect("accept"));
            let recv = conn.accept_uni().await.expect("accept_uni");
            accepted.send(()).expect("signal the writer");
            let mut framed = FramedRecvStream::new(recv, DraftVersion::Draft23);
            let first = framed.read_fetch_stream_header().await.map(|_| ());
            let code = framed.received_reset().await.expect("received_reset");
            let second = framed.read_fetch_stream_header().await.map(|_| ());
            (format!("{first:?}"), code, format!("{second:?}"), conn)
        });

        let client = wtransport::Endpoint::client(
            wtransport::ClientConfig::builder()
                .with_bind_default()
                .with_no_cert_validation()
                .build(),
        )
        .expect("client");
        let conn = WebTransportTransport::new(
            client.connect(format!("https://{addr}/")).await.expect("connect"),
        );
        let mut send = conn.open_uni().await.expect("open_uni");
        // A stream reaches the peer only once something is written on it. One
        // byte of a FETCH_HEADER leaves the header incomplete.
        send.write_all(&[0x05]).await.expect("write");
        tokio::time::timeout(PATIENCE, reset_now)
            .await
            .expect("the peer did not accept the stream")
            .expect("the reader task");
        send.reset(u64::from(RESET_CODE)).expect("reset the stream");

        let (first, code, second, _conn) = tokio::time::timeout(PATIENCE, reading)
            .await
            .expect("the reader hung")
            .expect("reader");
        let reset = format!("Err(Transport(StreamReset({RESET_CODE})))");
        assert_eq!(first, reset);
        assert_eq!(code, Some(u64::from(RESET_CODE)));
        assert_eq!(second, reset);
    }
}

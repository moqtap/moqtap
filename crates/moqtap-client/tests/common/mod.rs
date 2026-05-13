//! Shared loopback test harness.
//!
//! Spins up a real `quinn::Endpoint` on `127.0.0.1` with a self-signed
//! cert. Tests drive `moqtap_client::draft14::Connection::connect()` at
//! this endpoint and the server side reads/writes MoQT frames using the
//! public `FramedSendStream` / `FramedRecvStream` wrappers so that the
//! wire is exercised end-to-end — but with no external relay required.
//!
//! This is not interop: the other end is our own codec. What's verified
//! is I/O plumbing, framing, and observer-event emission on real quinn
//! streams.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use moqtap_client::draft14::connection::{FramedRecvStream, FramedSendStream};
use moqtap_client::transport::{RecvStream, SendStream};
use moqtap_codec::version::DraftVersion;
use quinn::{Endpoint, ServerConfig};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// Install the ring crypto provider if nothing is installed yet.
/// Idempotent — safe to call from every test.
pub fn init_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Build a quinn server endpoint bound to a random port on `127.0.0.1`
/// with a self-signed cert for `localhost`. Returns the endpoint and
/// its bound address — pass `addr.to_string()` to `Connection::connect`.
pub fn spawn_server(alpn: &[&[u8]]) -> (Endpoint, SocketAddr) {
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("keypair");
    let params = CertificateParams::new(vec!["localhost".into()]).expect("params");
    let cert = params.self_signed(&key_pair).expect("self-sign");

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("server cert");
    server_crypto.alpn_protocols = alpn.iter().map(|s| s.to_vec()).collect();
    let server_crypto =
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).expect("quic crypto");

    let server_config = ServerConfig::with_crypto(Arc::new(server_crypto));
    let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let endpoint = Endpoint::server(server_config, bind).expect("bind server");
    let addr = endpoint.local_addr().expect("local_addr");
    (endpoint, addr)
}

/// Wrap the server side of a bi stream into moqtap framed streams for
/// the given draft.
pub fn frame_bi(
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    draft: DraftVersion,
) -> (FramedSendStream, FramedRecvStream) {
    (
        FramedSendStream::new(SendStream::Quic(send), draft),
        FramedRecvStream::new(RecvStream::Quic(recv), draft),
    )
}

/// Wrap a server-side uni recv stream.
pub fn frame_uni_recv(recv: quinn::RecvStream, draft: DraftVersion) -> FramedRecvStream {
    FramedRecvStream::new(RecvStream::Quic(recv), draft)
}

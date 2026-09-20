//! The peer's certificate chain, from the handshake to the caller, unaltered.
//!
//! # Why this needs a test at all
//!
//! `Transport::peer_certificates` is three lines and one of them is a
//! downcast. quinn is generic over its crypto backend, so
//! `quinn::Connection::peer_identity` can only return `Option<Box<dyn Any>>`;
//! the rustls backend puts a `Vec<rustls::pki_types::CertificateDer>` in that
//! box, and reading it back means naming that type by hand. Nothing checks the
//! guess. A quinn release that boxed something else — a newtype, a different
//! lifetime, a `Vec<Vec<u8>>` — would compile exactly as it does today and
//! return `None` from the downcast, and the whole feature would become "this
//! relay presented no certificate" on every connection in the fleet.
//!
//! That is the failure this file exists to make loud, and it is why the
//! assertion is byte equality against a certificate the test itself generated
//! rather than "the chain is non-empty". A non-emptiness check would pass on
//! any `Vec` of anything; only the server's own DER coming back proves the box
//! was opened correctly.
//!
//! # Why the server is built here instead of using `common::spawn_server`
//!
//! The shared harness generates a certificate and keeps it — it returns an
//! endpoint and an address, not the DER. This test needs the DER to compare
//! against, so it builds an equivalent server locally. That is fifteen lines
//! duplicated in exchange for leaving a harness used by a hundred other files
//! alone.
//!
//! # Ablation, measured
//!
//! Changing the downcast target in `transport::quic::peer_certificates` to
//! `Vec<Vec<u8>>` — the shape a plausible upstream change would produce, and
//! one that still compiles and still passes clippy:
//!
//! ```text
//! the_chain_a_relay_presented_is_what_the_caller_reads
//!   the server was configured with exactly one certificate, so the chain
//!   length is a fact about the peer and not about this client
//!     left: 0
//!
//! a_chain_is_returned_whole_and_leaf_first
//!   the chain must arrive whole and leaf first: a caller counting
//!   certificates to spot a missing intermediate is reading this length
//!     left: []
//! ```
//!
//! Both fail as an empty chain, which is exactly the shape of the silent
//! break: no error anywhere, every relay in the fleet suddenly presenting
//! nothing. `transport/quic.rs` was restored byte for byte afterwards.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use moqtap_client::transport::{dial_quic, QuicDialOptions};
use quinn::{Endpoint, ServerConfig};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

const PATIENCE: Duration = Duration::from_secs(10);
const ALPN: &[u8] = b"moqt-16";

/// A loopback QUIC server that presents `chain` and nothing else.
///
/// `chain` is returned to the caller so the test can compare against the exact
/// bytes the server was configured with, which is the only comparison that
/// says anything about the downcast.
fn server_presenting(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> (Endpoint, SocketAddr) {
    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .expect("the generated certificate and key are a matched pair");
    crypto.alpn_protocols = vec![ALPN.to_vec()];

    let quic_crypto =
        quinn::crypto::rustls::QuicServerConfig::try_from(crypto).expect("quic server crypto");
    let bind: SocketAddr = "127.0.0.1:0".parse().expect("loopback address");
    let endpoint =
        Endpoint::server(ServerConfig::with_crypto(Arc::new(quic_crypto)), bind).expect("bind");
    let addr = endpoint.local_addr().expect("local_addr");
    (endpoint, addr)
}

/// One self-signed leaf for `localhost`, as DER plus its key.
fn self_signed_leaf() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("keypair");
    let params = CertificateParams::new(vec!["localhost".into()]).expect("params");
    let cert = params.self_signed(&key_pair).expect("self-sign");
    (
        CertificateDer::from(cert.der().to_vec()),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der())),
    )
}

fn options() -> QuicDialOptions {
    // Verification off: the point of the test is what the peer *sent*, and a
    // self-signed loopback certificate would never survive the public roots.
    // A probe reads exactly this way — the chain from a connection that was
    // established precisely because nothing judged it.
    QuicDialOptions::new(vec![ALPN.to_vec()]).insecure(true)
}

/// The bytes the server was configured with are the bytes the caller gets.
#[tokio::test]
async fn the_chain_a_relay_presented_is_what_the_caller_reads() {
    common::init_crypto();
    let (leaf, key) = self_signed_leaf();
    let expected = leaf.as_ref().to_vec();
    let (endpoint, addr) = server_presenting(vec![leaf], key);

    let server = tokio::spawn(async move {
        let _ = endpoint.accept().await.expect("accept").await;
    });

    let (transport, _) = tokio::time::timeout(PATIENCE, dial_quic(&addr.to_string(), &options()))
        .await
        .expect("the dial completes within the timeout")
        .expect("the dial succeeds against a loopback server");

    let chain = transport.peer_certificates();
    assert_eq!(
        chain.len(),
        1,
        "the server was configured with exactly one certificate, so the chain length is a fact \
         about the peer and not about this client"
    );
    assert_eq!(
        chain.first().map(Vec::as_slice),
        Some(expected.as_slice()),
        "a completed handshake against a certificate-presenting server must yield that server's \
         own DER, unaltered — anything else means the downcast in \
         transport::quic::peer_certificates stopped matching what quinn boxes"
    );

    transport.close(0, b"done");
    let _ = tokio::time::timeout(PATIENCE, server).await;
}

/// Every certificate the server sent arrives, in the order it sent them.
///
/// The length is not incidental detail — it is the finding. A relay that
/// serves a leaf with no intermediate presents a chain of one, which a client
/// validating against a fixed root set rejects while a browser holding a
/// cached intermediate connects to it without complaint. A caller can only
/// tell that apart from a genuinely untrusted certificate by counting what
/// arrived, so a `peer_certificates` that returned the leaf alone would erase
/// the distinction while looking entirely correct.
#[tokio::test]
async fn a_chain_is_returned_whole_and_leaf_first() {
    common::init_crypto();

    // Two self-signed certificates stacked as a chain. Not a real issuance
    // relationship — rustls does not check one here, and what is under test is
    // whether both survive the crossing, in order.
    let (leaf, key) = self_signed_leaf();
    let (second, _) = self_signed_leaf();
    let expected: Vec<Vec<u8>> = vec![leaf.as_ref().to_vec(), second.as_ref().to_vec()];
    assert_ne!(
        expected[0], expected[1],
        "two generated certificates must differ, or the \
        ordering assertion below proves nothing"
    );

    let (endpoint, addr) = server_presenting(vec![leaf, second], key);

    let server = tokio::spawn(async move {
        let _ = endpoint.accept().await.expect("accept").await;
    });

    let (transport, _) = tokio::time::timeout(PATIENCE, dial_quic(&addr.to_string(), &options()))
        .await
        .expect("the dial completes within the timeout")
        .expect("dial");

    assert_eq!(
        transport.peer_certificates(),
        expected,
        "the chain must arrive whole and leaf first: a caller counting certificates to spot a \
         missing intermediate is reading this length"
    );

    transport.close(0, b"done");
    let _ = tokio::time::timeout(PATIENCE, server).await;
}

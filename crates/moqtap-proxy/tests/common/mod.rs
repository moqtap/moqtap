//! Shared harness for proxy integration tests.
//!
//! Topology:
//!
//! ```text
//!   client (raw quinn + moqtap-client framed streams)
//!     ↓ QUIC, ALPN moq-00, self-signed cert
//!   proxy front-end endpoint (bound in the test)
//!     ↓ ProxySession::run() handed the accepted connection
//!   fake upstream (raw quinn + moqtap-client framed streams)
//! ```
//!
//! `ProxySession` is used directly rather than going through the full
//! `TransparentProxy` accept loop so tests can pick their own ephemeral
//! ports for both the proxy's front-end listener and the upstream —
//! avoiding the "how do I learn which port the proxy bound?" problem.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use moqtap_client::draft14::connection::{FramedRecvStream, FramedSendStream};
use moqtap_client::transport::{RecvStream, SendStream};
use moqtap_codec::version::DraftVersion;
use quinn::{ClientConfig, Endpoint, ServerConfig};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// Idempotent install of the ring crypto provider.
pub fn init_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// A QUIC server endpoint bound to an ephemeral port on 127.0.0.1 with a
/// fresh self-signed cert for `localhost`.
pub fn spawn_quic_server(alpn: &[&[u8]]) -> (Endpoint, SocketAddr) {
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("keypair");
    let params = CertificateParams::new(vec!["localhost".into()]).expect("cert params");
    let cert = params.self_signed(&key_pair).expect("self-sign");
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("server cert");
    server_crypto.alpn_protocols = alpn.iter().map(|s| s.to_vec()).collect();

    let quic_crypto =
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).expect("quic crypto");
    let server_config = ServerConfig::with_crypto(Arc::new(quic_crypto));
    let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let endpoint = Endpoint::server(server_config, bind).expect("bind server");
    let addr = endpoint.local_addr().expect("local_addr");
    (endpoint, addr)
}

/// Build a QUIC client endpoint that skips certificate verification and
/// advertises the given ALPN list.
pub fn client_endpoint(alpn: &[&[u8]]) -> Endpoint {
    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerify))
        .with_no_client_auth();
    client_crypto.alpn_protocols = alpn.iter().map(|s| s.to_vec()).collect();

    let quic_crypto =
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).expect("quic crypto");
    let client_config = ClientConfig::new(Arc::new(quic_crypto));

    let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut ep = Endpoint::client(bind).expect("client endpoint");
    ep.set_default_client_config(client_config);
    ep
}

/// Wrap server-side quinn bi streams in moqtap framed helpers for the
/// given draft.
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

/// Rustls verifier that accepts every server cert. Tests only.
#[derive(Debug)]
struct SkipVerify;

impl rustls::client::danger::ServerCertVerifier for SkipVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dcs: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dcs: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

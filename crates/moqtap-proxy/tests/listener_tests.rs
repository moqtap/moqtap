#![cfg(feature = "cert-gen")]

use moqtap_proxy::cert::generate_self_signed;
use moqtap_proxy::listener::*;

fn test_listener_config() -> ListenerConfig {
    let cert = generate_self_signed(&["localhost"], 14).unwrap();
    ListenerConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        cert_chain: vec![cert.cert_der],
        key_der: cert.key_der,
        alpn: vec![b"moq-00".to_vec()],
    }
}

#[tokio::test]
async fn listener_bind_and_local_addr() {
    let config = test_listener_config();
    let listener = Listener::bind(config).unwrap();

    let addr = listener.local_addr().unwrap();
    assert_eq!(addr.ip(), "127.0.0.1".parse::<std::net::IpAddr>().unwrap());
    assert_ne!(addr.port(), 0, "should have been assigned a real port");
}

#[tokio::test]
async fn listener_close_does_not_panic() {
    let config = test_listener_config();
    let listener = Listener::bind(config).unwrap();
    listener.close();
}

#[test]
fn listener_bind_invalid_cert_fails() {
    let config = ListenerConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        cert_chain: vec![rustls::pki_types::CertificateDer::from(vec![0u8; 10])],
        key_der: rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(vec![0u8; 10]),
        ),
        alpn: vec![b"moq-00".to_vec()],
    };
    let result = Listener::bind(config);
    assert!(result.is_err());
}

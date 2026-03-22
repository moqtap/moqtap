#![cfg(feature = "cert-gen")]

use moqtap_proxy::cert::*;

#[test]
fn generate_self_signed_creates_cert() {
    let cert = generate_self_signed(&["localhost"], 14).unwrap();

    // DER should be non-empty
    assert!(!cert.cert_der.is_empty());

    // Hash should be 32 bytes (SHA-256)
    assert_eq!(cert.cert_hash.len(), 32);
    // Hash should not be all zeros
    assert!(cert.cert_hash.iter().any(|&b| b != 0));
}

#[test]
fn generate_self_signed_multiple_sans() {
    let cert = generate_self_signed(&["localhost", "127.0.0.1", "proxy.local"], 30).unwrap();
    assert!(!cert.cert_der.is_empty());
}

#[test]
fn generate_self_signed_different_certs_have_different_hashes() {
    let cert1 = generate_self_signed(&["localhost"], 14).unwrap();
    let cert2 = generate_self_signed(&["localhost"], 14).unwrap();
    // Different key pairs → different hashes (with overwhelming probability)
    assert_ne!(cert1.cert_hash, cert2.cert_hash);
}

#[test]
fn generated_cert_key_is_pkcs8() {
    let cert = generate_self_signed(&["localhost"], 14).unwrap();
    // Verify the key is a PKCS#8 variant
    assert!(matches!(cert.key_der, rustls::pki_types::PrivateKeyDer::Pkcs8(_)));
}

/// Verify the generated cert+key can be used to build a rustls ServerConfig.
#[test]
fn generated_cert_usable_in_rustls() {
    let cert = generate_self_signed(&["localhost"], 14).unwrap();

    let result = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert_der], cert.key_der);

    assert!(result.is_ok(), "rustls should accept the generated cert+key");
}

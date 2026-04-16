#![cfg(feature = "cert-gen")]

use moqtap_proxy::cert::*;
use time::OffsetDateTime;

#[test]
fn cert_pair_generates_two_valid_certs() {
    let pair = CertPair::generate(&["localhost"]).unwrap();

    // Both DERs should be non-empty
    assert!(!pair.current.cert_der.is_empty());
    assert!(!pair.next.cert_der.is_empty());

    // Both hashes should be 32 bytes and non-zero
    for hash in &pair.cert_hashes() {
        assert_eq!(hash.len(), 32);
        assert!(hash.iter().any(|&b| b != 0));
    }
}

#[test]
fn cert_pair_has_different_hashes() {
    let pair = CertPair::generate(&["localhost"]).unwrap();
    let [h1, h2] = pair.cert_hashes();
    assert_ne!(h1, h2);
}

#[test]
fn cert_pair_validity_under_14_days() {
    let pair = CertPair::generate(&["localhost"]).unwrap();

    let fourteen_days = time::Duration::days(14);
    let current_validity = pair.current.not_after - pair.current.not_before;
    let next_validity = pair.next.not_after - pair.next.not_before;

    assert!(current_validity < fourteen_days, "current cert must be valid for <14 days");
    assert!(next_validity < fourteen_days, "next cert must be valid for <14 days");
}

#[test]
fn cert_pair_next_starts_before_current_expires() {
    let pair = CertPair::generate(&["localhost"]).unwrap();

    // next.not_before should be 1 hour before current.not_after
    let expected_next_start = pair.current.not_after - time::Duration::hours(1);
    let diff = (pair.next.not_before - expected_next_start).abs();
    assert!(diff < time::Duration::seconds(2), "next cert should start 1h before current expires");

    // next starts before current ends (overlap exists)
    assert!(pair.next.not_before < pair.current.not_after);
    // next ends after current ends (provides continuity)
    assert!(pair.next.not_after > pair.current.not_after);
}

#[test]
fn cert_pair_generate_at_deterministic_timing() {
    let now = OffsetDateTime::now_utc();
    let pair = CertPair::generate_at(&["localhost"], now).unwrap();

    assert_eq!(pair.current.not_before, now);

    let expected_validity = time::Duration::new(13 * 86_400 + 23 * 3_600 + 59 * 60 + 59, 0);
    let current_validity = pair.current.not_after - pair.current.not_before;
    assert_eq!(current_validity, expected_validity);

    let next_validity = pair.next.not_after - pair.next.not_before;
    assert_eq!(next_validity, expected_validity);
}

#[test]
fn cert_pair_multiple_sans() {
    let pair = CertPair::generate(&["localhost", "127.0.0.1", "proxy.local"]).unwrap();
    assert!(!pair.current.cert_der.is_empty());
    assert!(!pair.next.cert_der.is_empty());
}

#[test]
fn generated_cert_key_is_pkcs8() {
    let pair = CertPair::generate(&["localhost"]).unwrap();
    assert!(matches!(pair.current.key_der, rustls::pki_types::PrivateKeyDer::Pkcs8(_)));
    assert!(matches!(pair.next.key_der, rustls::pki_types::PrivateKeyDer::Pkcs8(_)));
}

#[test]
fn generated_certs_usable_in_rustls() {
    let pair = CertPair::generate(&["localhost"]).unwrap();

    for cert in [&pair.current, &pair.next] {
        let result = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.cert_der.clone()], cert.key_der.clone_key());

        assert!(result.is_ok(), "rustls should accept the generated cert+key");
    }
}

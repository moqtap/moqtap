//! Self-signed certificate generation for proxy TLS interception.
//!
//! This module is behind the `cert-gen` feature flag. It uses `rcgen` to
//! generate ECDSA P-256 self-signed certificates suitable for use with
//! QUIC and WebTransport.

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::error::ProxyError;

/// A generated self-signed certificate with its private key and hash.
#[derive(Debug)]
pub struct GeneratedCert {
    /// The DER-encoded certificate.
    pub cert_der: CertificateDer<'static>,
    /// The DER-encoded private key (PKCS#8 DER).
    pub key_der: PrivateKeyDer<'static>,
    /// SHA-256 hash of the DER certificate (for WebTransport pinning).
    pub cert_hash: [u8; 32],
}

/// Generate a self-signed certificate for the given subject alternative
/// names with the specified validity period.
///
/// Uses ECDSA P-256 for key generation. The certificate's validity
/// defaults to starting now and lasting `validity_days` days.
///
/// # Arguments
///
/// * `subject_alt_names` — DNS names and/or IP addresses for the cert.
/// * `validity_days` — How many days the certificate should be valid.
pub fn generate_self_signed(
    subject_alt_names: &[&str],
    validity_days: u32,
) -> Result<GeneratedCert, ProxyError> {
    use rcgen::{CertificateParams, KeyPair};

    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| ProxyError::CertGen(e.to_string()))?;

    let mut params =
        CertificateParams::new(subject_alt_names.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .map_err(|e| ProxyError::CertGen(e.to_string()))?;

    // rcgen's CertificateParams has not_before/not_after fields that
    // default to now → now+1year. We use rcgen's time re-export.
    let now = rcgen::date_time_ymd(2025, 1, 1);
    let end = rcgen::date_time_ymd(
        2025 + (validity_days / 365) as i32,
        1 + ((validity_days % 365) / 30) as u8,
        1,
    );
    params.not_before = now;
    params.not_after = end;

    let cert = params.self_signed(&key_pair).map_err(|e| ProxyError::CertGen(e.to_string()))?;

    let cert_der_bytes = cert.der().to_vec();

    // Compute SHA-256 hash
    let digest = ring::digest::digest(&ring::digest::SHA256, &cert_der_bytes);
    let mut cert_hash = [0u8; 32];
    cert_hash.copy_from_slice(digest.as_ref());

    let cert_der = CertificateDer::from(cert_der_bytes);
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    Ok(GeneratedCert { cert_der, key_der, cert_hash })
}

//! WebTransport-compliant self-signed certificate generation.
//!
//! This module is behind the `cert-gen` feature flag. It uses `rcgen` to
//! generate ECDSA P-256 self-signed certificates that comply with the
//! WebTransport specification:
//!
//! - **Algorithm**: ECDSA P-256 (required by WebTransport)
//! - **Validity**: strictly less than 14 days (13 days, 23 hours, 59 minutes,
//!   59 seconds)
//!
//! Certificates are always generated in pairs ([`CertPair`]) for seamless
//! rotation: the **next** cert's `not_before` overlaps with the **current**
//! cert's `not_after` by 1 hour, so clients can be given both hashes upfront.

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use time::OffsetDateTime;

use crate::error::ProxyError;

/// Maximum WebTransport-compliant validity: 13d 23h 59m 59s.
const CERT_VALIDITY: time::Duration =
    time::Duration::new(13 * 86_400 + 23 * 3_600 + 59 * 60 + 59, 0);

/// Overlap between current and next certificate: 1 hour.
const ROTATION_OVERLAP: time::Duration = time::Duration::new(3_600, 0);

/// A self-signed ECDSA P-256 certificate with its private key and SHA-256 hash.
#[derive(Debug)]
pub struct GeneratedCert {
    /// The DER-encoded certificate.
    pub cert_der: CertificateDer<'static>,
    /// The DER-encoded private key (PKCS#8).
    pub key_der: PrivateKeyDer<'static>,
    /// SHA-256 hash of the DER certificate (for WebTransport pinning).
    pub cert_hash: [u8; 32],
    /// When this certificate becomes valid (UTC).
    pub not_before: OffsetDateTime,
    /// When this certificate expires (UTC).
    pub not_after: OffsetDateTime,
}

impl GeneratedCert {
    /// Reconstruct a `GeneratedCert` from raw DER bytes (for loading from disk).
    pub fn from_der(
        cert_bytes: Vec<u8>,
        key_bytes: Vec<u8>,
        cert_hash: [u8; 32],
        not_before: OffsetDateTime,
        not_after: OffsetDateTime,
    ) -> Self {
        Self {
            cert_der: CertificateDer::from(cert_bytes),
            key_der: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_bytes)),
            cert_hash,
            not_before,
            not_after,
        }
    }
}

/// A pair of overlapping certificates for seamless WebTransport rotation.
///
/// Both certificates are WebTransport-compliant (ECDSA P-256, <14 day validity).
/// The `next` certificate's validity begins 1 hour before the `current`
/// certificate expires, providing a smooth handover window.
///
/// # Example
///
/// ```no_run
/// use moqtap_proxy::cert::{CertPair, format_hash_hex};
///
/// let pair = CertPair::generate(&["localhost"]).unwrap();
///
/// // Use current cert for TLS
/// let _tls_cert = &pair.current.cert_der;
/// let _tls_key = &pair.current.key_der;
///
/// // Advertise both hashes to WebTransport clients
/// for hash in &pair.cert_hashes() {
///     println!("  {}", format_hash_hex(hash));
/// }
/// ```
#[derive(Debug)]
pub struct CertPair {
    /// The certificate to use now.
    pub current: GeneratedCert,
    /// The next certificate, valid starting 1 hour before `current` expires.
    pub next: GeneratedCert,
}

impl CertPair {
    /// Generate a new certificate pair starting now.
    ///
    /// Shorthand for [`CertPair::generate_at`] with `now = OffsetDateTime::now_utc()`.
    pub fn generate(subject_alt_names: &[&str]) -> Result<Self, ProxyError> {
        Self::generate_at(subject_alt_names, OffsetDateTime::now_utc())
    }

    /// Generate a new certificate pair with a specific start time.
    ///
    /// - `current`: valid from `now` for 13d 23h 59m 59s
    /// - `next`: valid from `current.not_after − 1h` for 13d 23h 59m 59s
    pub fn generate_at(
        subject_alt_names: &[&str],
        now: OffsetDateTime,
    ) -> Result<Self, ProxyError> {
        let current = generate_single(subject_alt_names, now)?;
        let next_start = current.not_after - ROTATION_OVERLAP;
        let next = generate_single(subject_alt_names, next_start)?;
        Ok(Self { current, next })
    }

    /// SHA-256 hashes of both certificates, for `serverCertificateHashes`.
    ///
    /// Returns `[current_hash, next_hash]`.
    pub fn cert_hashes(&self) -> [[u8; 32]; 2] {
        [self.current.cert_hash, self.next.cert_hash]
    }
}

/// Generate a single ECDSA P-256 self-signed certificate.
fn generate_single(
    subject_alt_names: &[&str],
    not_before: OffsetDateTime,
) -> Result<GeneratedCert, ProxyError> {
    use rcgen::{CertificateParams, KeyPair};

    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| ProxyError::CertGen(e.to_string()))?;

    let mut params =
        CertificateParams::new(subject_alt_names.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .map_err(|e| ProxyError::CertGen(e.to_string()))?;

    let not_after = not_before + CERT_VALIDITY;
    params.not_before = not_before;
    params.not_after = not_after;

    let cert = params.self_signed(&key_pair).map_err(|e| ProxyError::CertGen(e.to_string()))?;

    let cert_der_bytes = cert.der().to_vec();

    let digest = ring::digest::digest(&ring::digest::SHA256, &cert_der_bytes);
    let mut cert_hash = [0u8; 32];
    cert_hash.copy_from_slice(digest.as_ref());

    let cert_der = CertificateDer::from(cert_der_bytes);
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    Ok(GeneratedCert { cert_der, key_der, cert_hash, not_before, not_after })
}

/// Format a SHA-256 hash as colon-separated hex pairs (e.g., `ab:cd:ef:...`).
pub fn format_hash_hex(hash: &[u8; 32]) -> String {
    hash.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

/// Compute the SHA-256 hash of a DER-encoded certificate.
pub fn compute_cert_hash(cert_der: &[u8]) -> [u8; 32] {
    let digest = ring::digest::digest(&ring::digest::SHA256, cert_der);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(digest.as_ref());
    hash
}

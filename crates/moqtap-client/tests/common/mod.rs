//! Shared loopback test harness.
//!
//! Spins up a real `quinn::Endpoint` on `127.0.0.1` with a self-signed
//! cert. Tests drive a per-draft `Connection::connect()` at this endpoint
//! and the server side reads/writes MoQT frames using the public
//! `FramedSendStream` / `FramedRecvStream` wrappers so that the wire is
//! exercised end-to-end — but with no external relay required.
//!
//! This is not interop: the other end is our own codec. What's verified
//! is I/O plumbing, framing, and observer-event emission on real quinn
//! streams.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use moqtap_client::transport::{RecvStream, SendStream};
use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;
use quinn::{Endpoint, ServerConfig};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

// -- which draft's framed streams the harness uses ---------------------------
//
// The harness frames the *server* side of the loopback, and the draft it has
// to frame is whichever one the test at the other end is exercising — so
// every helper below takes a `DraftVersion` at the call site, and the pair of
// types behind them has to be able to accept one.
//
// Drafts 14 and later can. `FramedSendStream::new` takes the draft and the
// stream dispatches on it, so any one of those pairs frames every draft in the
// build. Drafts 07 to 13 predate that argument: each of their pairs names its
// own draft in the call to the dispatcher, so it frames that draft and no
// other. They are not interchangeable, which is why this is a cascade rather
// than an alias.
//
// The pick is the lowest enabled draft at or above 14, and a fixed pair only
// when the build enables none of them. Lowest rather than highest so that the
// all-drafts build — the default, and what everybody runs — keeps the draft-14
// types it used before there was a choice to make.

#[cfg(any(
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20"
))]
mod framing {
    //! One pair, carrying the draft at run time, frames all fourteen.

    use moqtap_client::transport::{RecvStream, SendStream};
    use moqtap_codec::version::DraftVersion;

    #[cfg(feature = "draft14")]
    pub use moqtap_client::draft14::connection::{FramedRecvStream, FramedSendStream};
    #[cfg(all(feature = "draft15", not(feature = "draft14")))]
    pub use moqtap_client::draft15::connection::{FramedRecvStream, FramedSendStream};
    #[cfg(all(feature = "draft16", not(any(feature = "draft14", feature = "draft15"))))]
    pub use moqtap_client::draft16::connection::{FramedRecvStream, FramedSendStream};
    #[cfg(all(
        feature = "draft17",
        not(any(feature = "draft14", feature = "draft15", feature = "draft16"))
    ))]
    pub use moqtap_client::draft17::connection::{FramedRecvStream, FramedSendStream};
    #[cfg(all(
        feature = "draft18",
        not(any(
            feature = "draft14",
            feature = "draft15",
            feature = "draft16",
            feature = "draft17"
        ))
    ))]
    pub use moqtap_client::draft18::connection::{FramedRecvStream, FramedSendStream};
    #[cfg(all(
        feature = "draft19",
        not(any(
            feature = "draft14",
            feature = "draft15",
            feature = "draft16",
            feature = "draft17",
            feature = "draft18"
        ))
    ))]
    pub use moqtap_client::draft19::connection::{FramedRecvStream, FramedSendStream};
    #[cfg(all(
        feature = "draft20",
        not(any(
            feature = "draft14",
            feature = "draft15",
            feature = "draft16",
            feature = "draft17",
            feature = "draft18",
            feature = "draft19"
        ))
    ))]
    pub use moqtap_client::draft20::connection::{FramedRecvStream, FramedSendStream};

    pub fn send(inner: SendStream, draft: DraftVersion) -> FramedSendStream {
        FramedSendStream::new(inner, draft)
    }

    pub fn recv(inner: RecvStream, draft: DraftVersion) -> FramedRecvStream {
        FramedRecvStream::new(inner, draft)
    }
}

#[cfg(not(any(
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20"
)))]
mod framing {
    //! A pair wired to one draft, for a build that enables no later one.

    use moqtap_client::transport::{RecvStream, SendStream};
    use moqtap_codec::version::DraftVersion;

    /// Bring in one draft's pair and record which draft it frames. Both items
    /// under one `cfg`, so the two can never disagree.
    macro_rules! fixed_pair {
        ($draft:ident, $version:ident) => {
            pub use moqtap_client::$draft::connection::{FramedRecvStream, FramedSendStream};
            const HARNESS_DRAFT: DraftVersion = DraftVersion::$version;
        };
    }

    #[cfg(feature = "draft07")]
    fixed_pair!(draft07, Draft07);
    #[cfg(all(feature = "draft08", not(feature = "draft07")))]
    fixed_pair!(draft08, Draft08);
    #[cfg(all(feature = "draft09", not(any(feature = "draft07", feature = "draft08"))))]
    fixed_pair!(draft09, Draft09);
    #[cfg(all(
        feature = "draft10",
        not(any(feature = "draft07", feature = "draft08", feature = "draft09"))
    ))]
    fixed_pair!(draft10, Draft10);
    #[cfg(all(
        feature = "draft11",
        not(any(
            feature = "draft07",
            feature = "draft08",
            feature = "draft09",
            feature = "draft10"
        ))
    ))]
    fixed_pair!(draft11, Draft11);
    #[cfg(all(
        feature = "draft12",
        not(any(
            feature = "draft07",
            feature = "draft08",
            feature = "draft09",
            feature = "draft10",
            feature = "draft11"
        ))
    ))]
    fixed_pair!(draft12, Draft12);
    #[cfg(all(
        feature = "draft13",
        not(any(
            feature = "draft07",
            feature = "draft08",
            feature = "draft09",
            feature = "draft10",
            feature = "draft11",
            feature = "draft12"
        ))
    ))]
    fixed_pair!(draft13, Draft13);

    /// The draft asked for has to be the one this pair frames. A build that
    /// enables several of drafts 07 to 13 and none later gets the lowest of
    /// them here, and would otherwise frame the others' tests as that draft —
    /// which is a wrong answer rather than an error, since the frames differ
    /// only in places a given test may not reach.
    fn check(draft: DraftVersion) {
        assert_eq!(
            draft, HARNESS_DRAFT,
            "the harness frames {HARNESS_DRAFT:?} in this build and was asked for {draft:?}"
        );
    }

    pub fn send(inner: SendStream, draft: DraftVersion) -> FramedSendStream {
        check(draft);
        FramedSendStream::new(inner)
    }

    pub fn recv(inner: RecvStream, draft: DraftVersion) -> FramedRecvStream {
        check(draft);
        FramedRecvStream::new(inner)
    }
}

// -- rendering a request, for the gates that assert on one -------------------

/// Render a request: its name, the type number the draft assigns it, and the
/// fields inside it a caller chooses.
///
/// **Both ends of an assertion about a request go through here**, and the
/// difference between them is where the values come from. A peer fills the
/// fields in from the message it decoded off the wire; a test fills them in
/// from what it asked the helper for. One format, two claims, and they agree
/// only if the helper wrote the request it was told to.
///
/// Here rather than in one test file because three files make that assertion
/// about different drafts — the request-stream drafts, the two that carry every
/// request on a control stream, and the eight below those, whose requests are
/// the same eight messages in six different shapes — and a failure should read
/// the same way in all of them.
pub fn render(name: &str, message_type: u64, fields: &[(&str, String)]) -> String {
    let mut out = format!("{name} {message_type:#04x}");
    for (field, value) in fields {
        out.push(' ');
        out.push_str(field);
        out.push('=');
        out.push_str(value);
    }
    out
}

/// A track name, for [`render`]. Lossy, because a name that is not UTF-8 still
/// has to appear in a failure message.
pub fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A namespace, for [`render`]: its tuple fields joined with slashes, so a
/// request naming one field of the right namespace does not render the same as
/// one naming all of it.
pub fn namespace_text(ns: &TrackNamespace) -> String {
    ns.0.iter().map(|field| String::from_utf8_lossy(field)).collect::<Vec<_>>().join("/")
}

// -- a frame this codec wrote, with one value rewritten ----------------------
//
// Several gates here hand a peer a frame whose one wrong value is the rule
// under test. The frame used to come straight from the encoder with the wrong
// value passed in, and that stopped working for a reason worth stating: the
// encoder refuses every value the decoder refuses. A value that is not what its
// Type defines is one the receiver must close the session over, so writing it
// is not a way to send it, and a gate that watches a peer close over one cannot
// ask this codec to produce it.
//
// So the frame is written around a value the encoder will write, and the value
// alone is rewritten. Everything else is still the encoder's: the message type,
// every field ahead of the parameters, the parameter count, the parameter type,
// and -- where the two values are the same length -- every length in the frame
// as well. Where the lengths differ, exactly two move, the value's own and the
// message's declared Length, and both are recomputed here.
//
// Every draft from 11 to 20 frames a control message the same way: a type as a
// varint, a 16-bit big-endian Length, then the body.

/// The bytes this codec writes for `value` as a varint.
fn varint_bytes(value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    VarInt::from_u64(value).expect("fixture value fits a varint").encode(&mut out);
    out
}

/// A length-prefixed value, as an odd-typed parameter carries it.
fn length_prefixed(value: &[u8]) -> Vec<u8> {
    assert!(
        value.len() < 64,
        "a length under 64 is one byte in every varint profile these drafts use, \
         which is what lets this run alongside the encoder's own; {} is not",
        value.len(),
    );
    let mut out = varint_bytes(value.len() as u64);
    out.extend_from_slice(value);
    out
}

/// `frame` with its trailing length-prefixed parameter value replaced by `bad`.
pub fn with_length_prefixed_value(frame: &[u8], good: &[u8], bad: &[u8]) -> Vec<u8> {
    replace_tail(frame, &length_prefixed(good), &length_prefixed(bad))
}

/// `frame` with its trailing bare varint parameter value replaced by `bad`.
pub fn with_varint_value(frame: &[u8], good: u64, bad: u64) -> Vec<u8> {
    replace_tail(frame, &varint_bytes(good), &varint_bytes(bad))
}

/// The number of bytes in a varint that begins with `first`. The two most
/// significant bits carry the length, which every profile spells the same way.
fn varint_len(first: u8) -> usize {
    1usize << (first >> 6)
}

fn replace_tail(frame: &[u8], good: &[u8], bad: &[u8]) -> Vec<u8> {
    let body = varint_len(frame[0]) + 2;
    let declared = u16::from_be_bytes([frame[body - 2], frame[body - 1]]) as usize;
    assert_eq!(
        declared,
        frame.len() - body,
        "the frame handed here is not one this codec wrote: it declares {declared} bytes \
         of body and carries {}",
        frame.len() - body,
    );
    assert!(
        frame.ends_with(good),
        "the value to rewrite must be the last thing in the frame; {good:?} is not the \
         tail of {frame:?}",
    );

    let mut out = frame[..frame.len() - good.len()].to_vec();
    out.extend_from_slice(bad);
    let length = u16::try_from(out.len() - body).expect("the rewritten body fits the Length field");
    out[body - 2..body].copy_from_slice(&length.to_be_bytes());
    out
}

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
) -> (framing::FramedSendStream, framing::FramedRecvStream) {
    (framing::send(SendStream::Quic(send), draft), framing::recv(RecvStream::Quic(recv), draft))
}

/// Wrap a server-side uni recv stream.
pub fn frame_uni_recv(recv: quinn::RecvStream, draft: DraftVersion) -> framing::FramedRecvStream {
    framing::recv(RecvStream::Quic(recv), draft)
}

/// Build a quinn client endpoint that skips certificate verification and
/// advertises the given ALPN list.
///
/// Tests that drive `Connection::connect` don't need this — it exists for
/// tests that want raw quinn streams on both ends of a loopback.
pub fn client_endpoint(alpn: &[&[u8]]) -> Endpoint {
    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerify))
        .with_no_client_auth();
    client_crypto.alpn_protocols = alpn.iter().map(|s| s.to_vec()).collect();

    let client_crypto =
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).expect("quic crypto");
    let client_config = quinn::ClientConfig::new(Arc::new(client_crypto));

    let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut endpoint = Endpoint::client(bind).expect("client endpoint");
    endpoint.set_default_client_config(client_config);
    endpoint
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

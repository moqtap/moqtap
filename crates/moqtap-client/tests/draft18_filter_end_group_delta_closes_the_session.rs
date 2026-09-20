#![cfg(feature = "draft18")]
//! Draft-18 Section 5.1.2: "Otherwise, the last Group ID to be delivered will be
//! the Group ID in Start Location plus the End Group Delta. If the resulting
//! Group ID would be greater than 2^64 - 1, the endpoint MUST close the session
//! with a PROTOCOL_VIOLATION."
//!
//! # Why this rule exists at all, and why it starts here
//!
//! Drafts 15 and 16 write an AbsoluteRange filter's End Group out in full: a
//! field, with nothing to compute and nothing to overflow. Draft-17 replaced it
//! with a delta measured from the Start Location's Group, which turned the last
//! group in range into a sum — and stated nothing about what happens when the
//! sum leaves the number space. Draft-18 added the sentence above; draft-19
//! keeps it.
//!
//! So the same four values are a legal draft-17 filter and a session close on
//! draft-18, and the codec takes the addition on the two drafts that state the
//! rule and leaves it to the caller on the one that does not. The draft-17 half
//! of that is asserted in the codec's own `subscription_filter_rules`; this is
//! the half that has to be seen on the wire, because a refusal that never
//! reaches the session is indistinguishable from one that does at any layer
//! below this one.
//!
//! # Why the value is built rather than encoded through a helper
//!
//! The overflow needs a Start Location group of 2^64 - 1, which the QUIC integer
//! encoding cannot spell at all — it stops at 2^62 - 1. Only the MoQT encoding
//! draft-17 introduced reaches the whole range, which is the same change that
//! made this rule necessary.

mod common;

use std::time::Duration;

use moqtap_client::draft18::connection::{ClientConfig, Connection, TransportType};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::draft18::message::{ControlMessage, Setup, Subscribe};
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::subscription_filter::SUBSCRIPTION_FILTER_PARAMETER;
use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::{Moqt18, VarInt};
use moqtap_codec::version::DraftVersion;

/// Session termination code PROTOCOL_VIOLATION, draft-18 Section 15.10.1.
const PROTOCOL_VIOLATION: u64 = 0x3;

const PATIENCE: Duration = Duration::from_secs(10);

/// AbsoluteRange (0x4), the one Filter Type that puts an End Group on the wire.
const ABSOLUTE_RANGE: u64 = 0x4;

fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).expect("fixture value fits a varint")
}

/// A one-field Track Namespace, the smallest every one of these drafts accepts.
fn ns() -> TrackNamespace {
    TrackNamespace(vec![b"live".to_vec()])
}
fn client_config() -> ClientConfig {
    ClientConfig {
        draft: DraftVersion::Draft18,
        transport: TransportType::Quic,
        skip_cert_verification: true,
        ca_certs: Vec::new(),
        setup_parameters: Vec::new(),
    }
}

fn encode_setup() -> Vec<u8> {
    let mut buf = Vec::new();
    AnyControlMessage::Draft18(ControlMessage::Setup(Setup { options: Vec::new() }))
        .encode(&mut buf)
        .expect("encode SETUP");
    buf
}

/// An AbsoluteRange filter starting at the last representable group and asking
/// for one more.
///
/// The smallest delta that overflows, against the largest start that does not.
/// Both halves matter: a delta of zero at the same start is legal and means the
/// remainder of that group, so the fixture is one step away from a frame the
/// draft requires an endpoint to accept.
fn a_filter_whose_end_leaves_the_range() -> Vec<u8> {
    filter_value(1)
}

/// The same filter with an End Group Delta of 0, whose sum is the Start
/// Location's group and so stays inside the range.
///
/// What the frame is written around: the encoder refuses to write the filter
/// above, because a sum past the end of the number space is one the receiver
/// must close the session over. The two deltas are varints of the same length,
/// so replacing one with the other moves nothing else in the frame.
fn a_filter_whose_end_is_the_group_it_starts_at() -> Vec<u8> {
    filter_value(0)
}

fn filter_value(delta: u64) -> Vec<u8> {
    let mut value = Vec::new();
    for field in [ABSOLUTE_RANGE, u64::MAX, 0, delta] {
        VarInt::from_u64_moqt(field).encode_moqt::<Moqt18>(&mut value);
    }
    value
}

fn filter_parameter(value: Vec<u8>) -> KeyValuePair {
    KeyValuePair { key: varint(SUBSCRIPTION_FILTER_PARAMETER), value: KvpValue::Bytes(value) }
}

/// A SUBSCRIBE carrying that filter, framed by this codec's own encoder.
///
/// A SUBSCRIBE and not a response: Section 10.2.9 lets this parameter appear in
/// "a SUBSCRIBE, PUBLISH_OK or REQUEST_UPDATE (for a subscription) message", and
/// a frame carrying it anywhere else is one the receiver must close the session
/// over for that reason instead, which would answer a different rule than the
/// one under test.
fn subscribe_with_an_unrepresentable_end() -> Vec<u8> {
    let message = ControlMessage::Subscribe(Subscribe {
        request_id: varint(1),
        track_namespace: ns(),
        track_name: b"video".to_vec(),
        parameters: vec![filter_parameter(a_filter_whose_end_is_the_group_it_starts_at())],
    });
    let mut out = Vec::new();
    message.encode(&mut out).expect("the encoder writes a filter it can read back");
    common::with_length_prefixed_value(
        &out,
        &a_filter_whose_end_is_the_group_it_starts_at(),
        &a_filter_whose_end_leaves_the_range(),
    )
}

/// An End Group Delta that carries the range past the end of the number space
/// closes the QUIC connection with PROTOCOL_VIOLATION.
///
/// # What it catches, observed by making the change and running it
///
/// Dropping the `last_group()` call from draft-18's `check_subscription_filters`
/// — the state every draft was in, where the filter decoded and the sum was
/// never taken:
///
/// ```text
/// ---- an_end_group_delta_past_the_range_closes_the_quic_connection stdout ----
///
/// thread 'an_end_group_delta_past_the_range_closes_the_quic_connection' (105508) panicked at crates\moqtap-client\tests\draft18_filter_end_group_delta_closes_the_session.rs:
/// an unrepresentable end must be refused: Subscribe(Subscribe { request_id: VarInt(1), track_namespace: TrackNamespace([[108, 105, 118, 101]]), track_name: [118, 105, 100, 101, 111], parameters: [KeyValuePair { key: VarInt(33), value: Bytes([4, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 1]) }] })
/// ```
///
/// Sending `CodecError::FilterEndGroupOverflow` to the no-close arm of
/// draft-18's `codec_session_error_code`, which is where draft-17 correctly
/// leaves it:
///
/// ```text
/// thread 'an_end_group_delta_past_the_range_closes_the_quic_connection' (70128) panicked at crates\moqtap-client\tests\draft18_filter_end_group_delta_closes_the_session.rs:
/// the client refused the frame but never closed the connection: Elapsed(())
/// ```
#[tokio::test]
async fn an_end_group_delta_past_the_range_closes_the_quic_connection() {
    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft18.quic_alpn()]);

    let peer = tokio::spawn(async move {
        let conn = endpoint.accept().await.expect("accept").await.expect("tls handshake");

        let mut client_control = conn.accept_uni().await.expect("accept_uni");
        let mut seen = Vec::new();
        let mut chunk = [0u8; 1024];
        while seen.len() < 3 {
            match client_control.read(&mut chunk).await.expect("read SETUP") {
                Some(n) => seen.extend_from_slice(&chunk[..n]),
                None => break,
            }
        }
        assert!(!seen.is_empty(), "the client sent no SETUP");

        let mut our_control = conn.open_uni().await.expect("open_uni");
        our_control.write_all(&encode_setup()).await.expect("write SETUP");
        our_control
            .write_all(&subscribe_with_an_unrepresentable_end())
            .await
            .expect("write the offending SUBSCRIBE");

        let reason = tokio::time::timeout(PATIENCE, conn.closed())
            .await
            .expect("the client refused the frame but never closed the connection");

        match reason {
            quinn::ConnectionError::ApplicationClosed(frame) => {
                let code = u64::from(frame.error_code);
                assert_eq!(
                    code, PROTOCOL_VIOLATION,
                    "Section 5.1.2 answers a sum that leaves the range with \
                     PROTOCOL_VIOLATION; the close carried {code}"
                );
                let text = String::from_utf8_lossy(&frame.reason).to_string();
                assert!(
                    text.contains("64-bit range"),
                    "the close reason should name the rule that was broken; got {text:?}"
                );
            }
            other => panic!("expected an application close, got {other:?}"),
        }
    });

    let mut conn =
        Connection::connect(&addr.to_string(), client_config()).await.expect("client connect");

    let err = conn.recv_control().await.expect_err("an unrepresentable end must be refused");
    let text = err.to_string();
    assert!(text.contains("64-bit range"), "the error should name the rule; got {text:?}");

    tokio::time::timeout(PATIENCE * 3, peer)
        .await
        .expect("peer task hung")
        .expect("peer task panicked");
}

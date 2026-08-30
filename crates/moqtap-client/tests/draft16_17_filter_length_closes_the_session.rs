#![cfg(all(feature = "draft16", feature = "draft17"))]
//! One malformed filter, two session codes.
//!
//! Draft-16 Section 9.2.2.5: "It is a length-prefixed Subscription Filter (see
//! Section 5.1.2). If the length of the Subscription Filter does not match the
//! parameter length, the publisher MUST close the session with
//! PROTOCOL_VIOLATION."
//!
//! Draft-17 dropped that sentence. What answers the same bytes there is the
//! general key-value rule both drafts carry: "If a receiver understands a Type,
//! and the following Value or Length/Value does not match the serialization
//! defined by that Type, the receiver MUST close the session with error code
//! KEY_VALUE_FORMATTING_ERROR."
//!
//! # Why both halves are here
//!
//! Because the two are one code path. The filter is decoded by one function, and
//! the only thing that separates PROTOCOL_VIOLATION from
//! KEY_VALUE_FORMATTING_ERROR is which draft's session table the refusal reaches
//! — a difference no codec test can see, since the frame is refused either way.
//! An implementation that answered the general rule on all five drafts would
//! pass every test but this one's draft-16 half, and one that carried draft-16's
//! specific sentence forward would pass everything but its draft-17 half.
//!
//! # Why the value is a filter with a byte after it
//!
//! Largest Object is a one-field filter: a Filter Type and nothing else. A
//! second byte inside the same parameter is therefore a parameter longer than
//! the filter it declares, which is the malformation both sentences describe,
//! and it leaves the Filter Type itself legal so that nothing here is answered
//! by the Filter Type rule instead.

mod common;

use std::time::Duration;

use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::subscription_filter::SUBSCRIPTION_FILTER_PARAMETER;
use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

/// Session termination code PROTOCOL_VIOLATION, on both drafts.
const PROTOCOL_VIOLATION: u64 = 0x3;
/// Session termination code KEY_VALUE_FORMATTING_ERROR, on both drafts.
const KEY_VALUE_FORMATTING_ERROR: u64 = 0x6;

const PATIENCE: Duration = Duration::from_secs(10);

fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).expect("fixture value fits a varint")
}

/// A one-field Track Namespace, the smallest either draft accepts.
fn ns() -> TrackNamespace {
    TrackNamespace(vec![b"live".to_vec()])
}

/// Largest Object (0x2), the shortest complete filter: one field and nothing
/// after it.
///
/// What both frames are written around, because the encoder refuses to write
/// the one below — a filter this codec could not read back is a message that
/// ends the session, so writing it is not a way to send it.
const LARGEST_OBJECT: &[u8] = &[0x02];

/// Largest Object, then a byte the filter does not account for.
///
/// The same two bytes on both drafts: 0x02 is one octet under the QUIC integer
/// encoding draft-16 uses and under the MoQT one draft-17 uses, so the fixture
/// is byte-identical and only the reading of it differs.
const A_FILTER_SHORTER_THAN_ITS_PARAMETER: &[u8] = &[0x02, 0x00];

/// The filter parameter, carrying `value` verbatim.
fn filter_parameter(value: &[u8]) -> KeyValuePair {
    KeyValuePair {
        key: varint(SUBSCRIPTION_FILTER_PARAMETER),
        value: KvpValue::Bytes(value.to_vec()),
    }
}

/// The malformation ends a draft-16 session with PROTOCOL_VIOLATION.
///
/// # What it catches, observed by making the change and running it
///
/// Sending `CodecError::SubscriptionFilterMalformed` to draft-16's
/// `KeyValueFormatting` arm instead — which is what applying the general rule to
/// every draft that has it looks like, and what draft-17 correctly does:
///
/// ```text
/// ---- draft16_answers_the_malformation_with_protocol_violation stdout ----
///
/// thread 'draft16_answers_the_malformation_with_protocol_violation' (96584) panicked at crates\moqtap-client\tests\draft16_17_filter_length_closes_the_session.rs:136:17:
/// assertion `left == right` failed: Section 9.2.2.5 answers this parameter's own malformation with PROTOCOL_VIOLATION; the close carried 6, and KEY_VALUE_FORMATTING_ERROR (6) here would mean the general rule was applied where the specific one governs
///   left: 6
///  right: 3
/// ```
#[tokio::test]
async fn draft16_answers_the_malformation_with_protocol_violation() {
    use moqtap_client::draft16::connection::{ClientConfig, Connection, TransportType};
    use moqtap_codec::draft16::message::{ControlMessage, ServerSetup, Subscribe};

    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft16.quic_alpn()]);

    let offending = {
        // A SUBSCRIBE and not a response. Both drafts let this parameter appear in
        // "a SUBSCRIBE, PUBLISH_OK or REQUEST_UPDATE (for a subscription) message"
        // and nowhere else, and draft-17 answers a parameter outside its scope with
        // a session close of its own — which would settle a different rule than the
        // one under test.
        let message = ControlMessage::Subscribe(Subscribe {
            request_id: varint(1),
            track_namespace: ns(),
            track_name: b"video".to_vec(),
            parameters: vec![filter_parameter(LARGEST_OBJECT)],
        });
        let mut out = Vec::new();
        message.encode(&mut out).expect("the encoder writes a filter it can read back");
        common::with_length_prefixed_value(
            &out,
            LARGEST_OBJECT,
            A_FILTER_SHORTER_THAN_ITS_PARAMETER,
        )
    };

    let peer = tokio::spawn(async move {
        let conn = endpoint.accept().await.expect("accept").await.expect("tls handshake");

        let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
        let mut framed_recv = common::frame_uni_recv(recv, DraftVersion::Draft16);
        framed_recv.read_control(false).await.expect("read CLIENT_SETUP");

        let mut setup = Vec::new();
        AnyControlMessage::Draft16(ControlMessage::ServerSetup(ServerSetup {
            parameters: Vec::new(),
        }))
        .encode(&mut setup)
        .expect("encode SERVER_SETUP");
        send.write_all(&setup).await.expect("write SERVER_SETUP");
        send.write_all(&offending).await.expect("write the offending SUBSCRIBE");

        let reason = tokio::time::timeout(PATIENCE, conn.closed())
            .await
            .expect("the client refused the frame but never closed the connection");

        match reason {
            quinn::ConnectionError::ApplicationClosed(frame) => {
                let code = u64::from(frame.error_code);
                assert_eq!(
                    code, PROTOCOL_VIOLATION,
                    "Section 9.2.2.5 answers this parameter's own malformation with \
                     PROTOCOL_VIOLATION; the close carried {code}, and \
                     KEY_VALUE_FORMATTING_ERROR ({KEY_VALUE_FORMATTING_ERROR}) here would \
                     mean the general rule was applied where the specific one governs"
                );
            }
            other => panic!("expected an application close, got {other:?}"),
        }
    });

    let mut conn = Connection::connect(
        &addr.to_string(),
        ClientConfig {
            draft: DraftVersion::Draft16,
            transport: TransportType::Quic,
            skip_cert_verification: true,
            ca_certs: Vec::new(),
            setup_parameters: Vec::new(),
        },
    )
    .await
    .expect("client connect");

    let err =
        conn.recv_control().await.expect_err("a filter shorter than its parameter is refused");
    let text = err.to_string();
    assert!(text.contains("filter"), "the error should name the rule; got {text:?}");

    tokio::time::timeout(PATIENCE * 3, peer)
        .await
        .expect("peer task hung")
        .expect("peer task panicked");
}

/// The same malformation ends a draft-17 session with
/// KEY_VALUE_FORMATTING_ERROR.
///
/// # What it catches, observed by making the change and running it
///
/// Answering draft-17 with PROTOCOL_VIOLATION, which is what carrying draft-16's
/// sentence forward past the draft that deleted it looks like:
///
/// ```text
/// ---- draft17_answers_the_malformation_with_a_key_value_formatting_error stdout ----
///
/// thread 'draft17_answers_the_malformation_with_a_key_value_formatting_error' (105332) panicked at crates\moqtap-client\tests\draft16_17_filter_length_closes_the_session.rs:243:17:
/// assertion `left == right` failed: this draft states no sentence of its own about the filter's length, so the general key-value rule answers it; the close carried 3, and PROTOCOL_VIOLATION (3) here would mean draft-16's deleted sentence was carried forward
///   left: 3
///  right: 6
/// ```
#[tokio::test]
async fn draft17_answers_the_malformation_with_a_key_value_formatting_error() {
    use moqtap_client::draft17::connection::{ClientConfig, Connection, TransportType};
    use moqtap_codec::draft17::message::{ControlMessage, Setup, Subscribe};

    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft17.quic_alpn()]);

    let offending = {
        // A SUBSCRIBE and not a response. Both drafts let this parameter appear in
        // "a SUBSCRIBE, PUBLISH_OK or REQUEST_UPDATE (for a subscription) message"
        // and nowhere else, and draft-17 answers a parameter outside its scope with
        // a session close of its own — which would settle a different rule than the
        // one under test.
        let message = ControlMessage::Subscribe(Subscribe {
            request_id: varint(1),
            required_request_id_delta: varint(0),
            track_namespace: ns(),
            track_name: b"video".to_vec(),
            parameters: vec![filter_parameter(LARGEST_OBJECT)],
        });
        let mut out = Vec::new();
        message.encode(&mut out).expect("the encoder writes a filter it can read back");
        common::with_length_prefixed_value(
            &out,
            LARGEST_OBJECT,
            A_FILTER_SHORTER_THAN_ITS_PARAMETER,
        )
    };

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
        let mut setup = Vec::new();
        AnyControlMessage::Draft17(ControlMessage::Setup(Setup { options: Vec::new() }))
            .encode(&mut setup)
            .expect("encode SETUP");
        our_control.write_all(&setup).await.expect("write SETUP");
        our_control.write_all(&offending).await.expect("write the offending SUBSCRIBE");

        let reason = tokio::time::timeout(PATIENCE, conn.closed())
            .await
            .expect("the client refused the frame but never closed the connection");

        match reason {
            quinn::ConnectionError::ApplicationClosed(frame) => {
                let code = u64::from(frame.error_code);
                assert_eq!(
                    code, KEY_VALUE_FORMATTING_ERROR,
                    "this draft states no sentence of its own about the filter's length, \
                     so the general key-value rule answers it; the close carried {code}, \
                     and PROTOCOL_VIOLATION ({PROTOCOL_VIOLATION}) here would mean \
                     draft-16's deleted sentence was carried forward"
                );
            }
            other => panic!("expected an application close, got {other:?}"),
        }
    });

    let mut conn = Connection::connect(
        &addr.to_string(),
        ClientConfig {
            draft: DraftVersion::Draft17,
            transport: TransportType::Quic,
            skip_cert_verification: true,
            ca_certs: Vec::new(),
            setup_parameters: Vec::new(),
        },
    )
    .await
    .expect("client connect");

    let err =
        conn.recv_control().await.expect_err("a filter shorter than its parameter is refused");
    let text = err.to_string();
    assert!(text.contains("filter"), "the error should name the rule; got {text:?}");

    tokio::time::timeout(PATIENCE * 3, peer)
        .await
        .expect("peer task hung")
        .expect("peer task panicked");
}

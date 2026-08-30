#![cfg(feature = "draft07")]
//! Draft-07 answers a parameter whose value disagrees with its type by closing
//! the session, with a code no draft above 10 has.
//!
//! # Why draft-07 was the last draft without the machinery
//!
//! `close_for_codec` and its mapping table arrived with draft-17 and worked
//! downwards a group at a time. Until this file existed, draft-07's decoder
//! refused the frame, `recv_control` handed the caller an `Err`, and the peer —
//! the endpoint that broke the rule — saw a session that was still open and went
//! on sending. That gap is invisible from inside the process, because the
//! decoder returns `Err` either way. Only something holding the other end of a
//! real connection can tell the difference.
//!
//! # Why draft-07's table is not draft-08's
//!
//! The two drafts sit next to each other and answer different lists. Draft-08
//! states five decoder-reachable rules; draft-07 states three, and only two of
//! them are shared:
//!
//!   - The Track Namespace tuple size is the parting of the ways. Draft-07
//!     Section 2.4.1 states the range and nothing else — "an ordered N-tuple of
//!     bytes where N can be between 1 and 32" — where draft-08 Section 2.4.1
//!     goes on to say "If an endpoint
//!     receives a Track Namespace tuple with an N of 0 or more than 32, it MUST
//!     close the session with a Protocol Violation." On this draft a tuple of 40
//!     fields is malformed and the session survives it.
//!   - The end-of-track Object ID rule has no subject here: draft-07 assigns no
//!     Object Status 0x5 for it to be about. Draft-07 is therefore the one draft
//!     with no decoder-reachable data-stream close at all, and the only one whose
//!     connection has no `close_for_data_stream`.
//!
//! # Why this rule and not the other two
//!
//! Of the three, two answer with Protocol Violation — a duplicate parameter and
//! an unknown control message type. This one does not:
//!
//! Section 6.1: "If a receiver understands a parameter type, and the parameter
//! length implied by that type does not match the Parameter Length field, the
//! receiver MUST terminate the session with error code 'Parameter Length
//! Mismatch'."
//!
//! That is code `0x5`, named by the sentence itself, and it exists only on
//! drafts 07 through 10 — drafts 11 and later drop the sentence along with the
//! Parameter framing it describes. A table written by analogy with any draft
//! above 10 would close this session with `0x3` and satisfy any test that only
//! asked whether a close happened. The gate is the code.
//!
//! # Why the frame is built by hand
//!
//! The encoder refuses to write one, and that is the point: the two directions
//! apply the same rule, so only a hand-made frame can reach the decode side.

mod common;

use std::time::Duration;

use moqtap_client::draft07::connection::{ClientConfig, Connection, TransportType};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::draft07::message::{ControlMessage, ServerSetup};
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

/// Session termination code `Parameter Length Mismatch`, draft-07 Section 3.5.
const PARAMETER_LENGTH_MISMATCH: u64 = 0x5;

/// Session termination code `Protocol Violation`, which the draft's other two
/// decoder-reachable rules use and this one does not. Named so the assertion can
/// say which wrong answer it saw.
const PROTOCOL_VIOLATION: u64 = 0x3;

const PATIENCE: Duration = Duration::from_secs(10);

/// DELIVERY TIMEOUT, one of the two version-specific parameters draft-07
/// describes as carrying a single integer. Section 6.1.1.2 gives it as "the
/// duration in milliseconds", so its value is one varint and nothing else.
const DELIVERY_TIMEOUT: u64 = 0x03;

fn client_config() -> ClientConfig {
    ClientConfig {
        additional_versions: Vec::new(),
        transport: TransportType::Quic,
        skip_cert_verification: true,
        ca_certs: Vec::new(),
        // Required of the client as well: this draft holds its own CLIENT_SETUP
        // to the same sentence before it goes out.
        setup_parameters: vec![role()],
    }
}

/// The ROLE setup parameter, which only this draft has and which it requires of
/// both endpoints. Section 6.2.2.1: "Both endpoints MUST send a ROLE parameter
/// with one of the three values specified above. Both endpoints MUST close the
/// session if the ROLE parameter is missing or is not one of the three
/// above-specified values."
///
/// Without it the client refuses the SERVER_SETUP and the session never reaches
/// the frame this test is about. Every draft above 07 dropped the parameter, so
/// no other gate in this suite needs one.
fn role() -> KeyValuePair {
    let mut value = Vec::new();
    VarInt::from_usize(3).encode(&mut value); // PubSub
    KeyValuePair { key: VarInt::from_usize(0x00), value: KvpValue::Bytes(value) }
}

fn server_setup() -> AnyControlMessage {
    AnyControlMessage::Draft07(ControlMessage::ServerSetup(ServerSetup {
        selected_version: DraftVersion::Draft07.version_varint(),
        parameters: vec![role()],
    }))
}

/// ANNOUNCE (0x06) carrying a DELIVERY TIMEOUT whose value is three zero bytes.
///
/// Draft-07 frames a control message as a varint Type, a varint Length, then the
/// payload: here a Track Namespace of one field, and one parameter.
///
/// Three zero bytes are a valid *byte string* of length 3 and an invalid varint
/// of length 3 — the first byte decodes as the varint 0 and two bytes are left
/// over. That is exactly the disagreement the sentence describes: the length the
/// type implies is one byte, the Parameter Length field says three.
fn announce_with_a_mismatched_parameter() -> Vec<u8> {
    let mut body = Vec::new();
    VarInt::from_usize(1).encode(&mut body); // Track Namespace: one field
    VarInt::from_usize(3).encode(&mut body); // that field's length
    body.extend_from_slice(b"abc"); // and its value
    VarInt::from_usize(1).encode(&mut body); // one parameter
    VarInt::from_u64(DELIVERY_TIMEOUT).unwrap().encode(&mut body);
    VarInt::from_usize(3).encode(&mut body); // Parameter Length: three bytes
    body.extend_from_slice(&[0x00, 0x00, 0x00]); // which are not one varint

    let mut out = Vec::new();
    VarInt::from_usize(0x06).encode(&mut out);
    VarInt::from_usize(body.len()).encode(&mut out);
    out.extend_from_slice(&body);
    out
}

/// A parameter whose length disagrees with its type closes the QUIC connection
/// with `Parameter Length Mismatch`, not with Protocol Violation.
///
/// # What it catches, observed by making the change and running it
///
/// Removing `close_for_codec` from draft-07's `recv_control` — the state this
/// draft was in until now, and the state every draft below 15 was in one round
/// ago:
///
/// ```text
/// ---- a_mismatched_parameter_length_closes_the_quic_connection stdout ----
///
/// thread 'a_mismatched_parameter_length_closes_the_quic_connection' (58952) panicked at crates\moqtap-client\tests\draft07_parameter_length_mismatch_closes_the_session.rs:192:14:
/// the client refused the frame but never closed the connection: Elapsed(())
/// ```
///
/// Answering this rule with Protocol Violation instead — folding
/// `ParameterLengthMismatch` into the arm the draft's other two rules share,
/// which is what a table copied from any draft above 10 would do:
///
/// ```text
/// ---- a_mismatched_parameter_length_closes_the_quic_connection stdout ----
///
/// thread 'a_mismatched_parameter_length_closes_the_quic_connection' (49976) panicked at crates\moqtap-client\tests\draft07_parameter_length_mismatch_closes_the_session.rs:197:17:
/// assertion `left == right` failed: Section 6.1 names the code for this rule; the close carried Protocol Violation (0x3) instead
///   left: 3
///  right: 5
/// ```
#[tokio::test]
async fn a_mismatched_parameter_length_closes_the_quic_connection() {
    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft07.quic_alpn()]);

    let peer = tokio::spawn(async move {
        let conn = endpoint.accept().await.expect("accept").await.expect("tls handshake");

        // Draft-07 carries control on a bidirectional stream the client opens.
        // The send half stays raw quinn: the offending frame has to go out
        // exactly as written, and every framing helper here would refuse it.
        let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
        let mut framed_recv = common::frame_uni_recv(recv, DraftVersion::Draft07);
        framed_recv.read_control(false).await.expect("read CLIENT_SETUP");

        let mut setup = Vec::new();
        server_setup().encode(&mut setup).expect("encode SERVER_SETUP");
        send.write_all(&setup).await.expect("write SERVER_SETUP");

        send.write_all(&announce_with_a_mismatched_parameter())
            .await
            .expect("write the offending ANNOUNCE");

        let reason = tokio::time::timeout(PATIENCE, conn.closed())
            .await
            .expect("the client refused the frame but never closed the connection");

        match reason {
            quinn::ConnectionError::ApplicationClosed(frame) => {
                let code = u64::from(frame.error_code);
                assert_eq!(
                    code,
                    PARAMETER_LENGTH_MISMATCH,
                    "Section 6.1 names the code for this rule; the close carried {}",
                    if code == PROTOCOL_VIOLATION {
                        "Protocol Violation (0x3) instead".to_string()
                    } else {
                        format!("{code} instead")
                    }
                );
                let text = String::from_utf8_lossy(&frame.reason).to_string();
                assert!(
                    text.contains("parameter"),
                    "the close reason should name the rule that was broken; got {text:?}"
                );
            }
            other => panic!("expected an application close, got {other:?}"),
        }
    });

    let mut conn =
        Connection::connect(&addr.to_string(), client_config()).await.expect("client connect");

    let err = conn
        .recv_control()
        .await
        .expect_err("a parameter whose length disagrees with its type must be refused");
    let text = err.to_string();
    assert!(text.contains("parameter"), "the error should name the rule; got {text:?}");

    tokio::time::timeout(PATIENCE * 3, peer)
        .await
        .expect("peer task hung")
        .expect("peer task panicked");
}

#![cfg(feature = "draft08")]
//! Draft-08 answers a parameter whose value disagrees with its type by closing
//! the session — and not with the code every other rule in this draft uses.
//!
//! # Why this draft needed the machinery at all
//!
//! `close_for_codec` and its mapping table arrived with draft-17, and drafts 15
//! and 16 gained one later. Everything below that had none: the decoder refused
//! the frame, `recv_control` handed the caller an `Err`, and the peer — the
//! endpoint that broke the rule — saw a session that was still open and went on
//! sending. That gap is invisible from inside the process, because the decoder
//! returns `Err` either way. Only something holding the other end of a real
//! connection can tell the difference.
//!
//! # Why this rule and not one of the other four
//!
//! Draft-08 states five rules its decoder can reach, and four of them answer
//! with Protocol Violation: the Track Namespace tuple size, a duplicate
//! parameter, an unknown control message type, and an end-of-track Object ID
//! that is not zero. This one does not:
//!
//! Section 7.1: "If a receiver understands a parameter type, and the parameter
//! length implied by that type does not match the Parameter Length field, the
//! receiver MUST terminate the session with error code 'Parameter Length
//! Mismatch'."
//!
//! That is code `0x5`, named by the sentence itself. A mapping table written by
//! analogy with drafts 15 through 19 — where every entry is Protocol Violation —
//! would close this session with `0x3` and satisfy any test that only asked
//! whether a close happened. The gate is the code.
//!
//! # Why the frame is built by hand
//!
//! The encoder refuses to write one, and that is the point: the two directions
//! apply the same rule, so only a hand-made frame can reach the decode side.

mod common;

use std::time::Duration;

use moqtap_client::draft08::connection::{ClientConfig, Connection, TransportType};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::draft08::message::{ControlMessage, ServerSetup};
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

/// Session termination code `Parameter Length Mismatch`, draft-08 Section 3.5.
const PARAMETER_LENGTH_MISMATCH: u64 = 0x5;

/// Session termination code `Protocol Violation`, the code four of this draft's
/// five decoder-reachable rules use and this one does not. Named so the
/// assertion can say which wrong answer it saw.
const PROTOCOL_VIOLATION: u64 = 0x3;

const PATIENCE: Duration = Duration::from_secs(10);

/// DELIVERY TIMEOUT, one of the two version-specific parameters draft-08
/// describes as carrying a single integer. Section 7.1.1.2 gives it as "the
/// duration in milliseconds", so its value is one varint and nothing else.
const DELIVERY_TIMEOUT: u64 = 0x03;

fn client_config() -> ClientConfig {
    ClientConfig {
        additional_versions: Vec::new(),
        transport: TransportType::Quic,
        skip_cert_verification: true,
        ca_certs: Vec::new(),
        setup_parameters: Vec::new(),
    }
}

fn server_setup() -> AnyControlMessage {
    AnyControlMessage::Draft08(ControlMessage::ServerSetup(ServerSetup {
        selected_version: DraftVersion::Draft08.version_varint(),
        parameters: Vec::new(),
    }))
}

/// ANNOUNCE (0x06) carrying a DELIVERY TIMEOUT whose value is three zero bytes.
///
/// Draft-08 frames a control message as a varint Type, a varint Length, then the
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
/// Answering this rule with Protocol Violation in draft-08's
/// `codec_session_error_code` — folding `ParameterLengthMismatch` into the arm
/// the draft's other four rules share, which is what a table copied from a later
/// draft would do:
///
/// ```text
/// ---- a_mismatched_parameter_length_closes_the_quic_connection stdout ----
///
/// thread 'a_mismatched_parameter_length_closes_the_quic_connection' (60640) panicked at crates\moqtap-client\tests\draft08_parameter_length_mismatch_closes_the_session.rs:151:17:
/// assertion `left == right` failed: Section 7.1 names the code for this rule; the close carried Protocol Violation (0x3) instead
///   left: 3
///  right: 5
/// ```
#[tokio::test]
async fn a_mismatched_parameter_length_closes_the_quic_connection() {
    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft08.quic_alpn()]);

    let peer = tokio::spawn(async move {
        let conn = endpoint.accept().await.expect("accept").await.expect("tls handshake");

        // Draft-08 carries control on a bidirectional stream the client opens.
        // The send half stays raw quinn: the offending frame has to go out
        // exactly as written, and every framing helper here would refuse it.
        let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
        let mut framed_recv = common::frame_uni_recv(recv, DraftVersion::Draft08);
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
                    "Section 7.1 names the code for this rule; the close carried {}",
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

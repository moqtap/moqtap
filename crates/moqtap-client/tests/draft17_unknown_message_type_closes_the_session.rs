#![cfg(feature = "draft17")]
//! Draft-17 Section 9: "An endpoint that receives an unknown message type MUST
//! close the session."
//!
//! # Why this rule needed a gate five drafts late
//!
//! All fourteen drafts carry that sentence, in those words. Drafts 08 through 14
//! answered it; drafts 15 through 19 did not, and none of the five said so. An
//! exclusion that is written down can be checked against the draft. This one was
//! never written down — the rule was simply absent from five tables, each of
//! which reads, in its own doc comment, as though every sentence in its draft had
//! been accounted for. That is the failure mode a "**Not** X" line exists to
//! prevent, and it is why the sweep that found this one enumerated what the
//! tables answer as well as what they refuse.
//!
//! # Why draft-17 carries it
//!
//! Draft-10 gates the same rule on the other side of two changes at once. There,
//! control is a bidirectional stream the client opens and a message is framed as
//! a varint Type and a varint Length; here control is a pair of unidirectional
//! streams and the Length is 16 bits big-endian. A gate on one says nothing about
//! the other.
//!
//! Draft-17 is also the only draft whose table holds two different codes. The
//! Required Request ID Delta bound of Section 9.2 answers with
//! INVALID_REQUIRED_REQUEST_ID; everything else answers with PROTOCOL_VIOLATION,
//! and this sentence names no code at all. Asserting the code is what separates
//! the rule reaching the table from the rule reaching the right arm of it.
//!
//! # Why the frame is built by hand
//!
//! `ControlMessage` has no variant for a type it does not know, so the encoder
//! cannot produce one. The frame is three bytes and a length, written directly.

mod common;

use std::time::Duration;

use moqtap_client::draft17::connection::{ClientConfig, Connection, TransportType};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::draft17::message::{ControlMessage, Setup};
use moqtap_codec::varint::{Moqt17, VarInt};
use moqtap_codec::version::DraftVersion;

/// Session termination code PROTOCOL_VIOLATION, draft-17 Section 14.5.1.
const PROTOCOL_VIOLATION: u64 = 0x3;

/// Session termination code INVALID_REQUIRED_REQUEST_ID, the other code in
/// draft-17's table. Named so the assertion can say which wrong answer it saw.
const INVALID_REQUIRED_REQUEST_ID: u64 = 0x7;

const PATIENCE: Duration = Duration::from_secs(10);

/// A control message type draft-17 does not assign.
///
/// Deliberately a hole *inside* the assigned block rather than a number past the
/// end of it: 0x0B is PUBLISH_DONE and 0x0D is TRACK_STATUS, so a decoder that
/// merely range-checked the type would accept this one. Only a decoder that
/// looks the number up in the registry refuses it.
const UNASSIGNED_TYPE: u64 = 0x0C;

fn client_config() -> ClientConfig {
    ClientConfig {
        draft: DraftVersion::Draft17,
        transport: TransportType::Quic,
        skip_cert_verification: true,
        ca_certs: Vec::new(),
        setup_parameters: Vec::new(),
    }
}

fn encode_setup() -> Vec<u8> {
    let mut buf = Vec::new();
    AnyControlMessage::Draft17(ControlMessage::Setup(Setup { options: Vec::new() }))
        .encode(&mut buf)
        .expect("encode SETUP");
    buf
}

/// A well-formed frame of an unassigned type: varint Type, 16-bit big-endian
/// Length, then that many bytes.
///
/// The body is a plausible payload rather than nothing, so the decoder cannot
/// refuse this for running out of bytes and pass the test for the wrong reason.
fn frame_of_an_unassigned_type() -> Vec<u8> {
    let body = [0x00u8, 0x01, 0x02, 0x03];

    let mut out = Vec::new();
    VarInt::from_u64_moqt(UNASSIGNED_TYPE).encode_moqt::<Moqt17>(&mut out);
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// A control message of an unassigned type closes the QUIC connection with
/// PROTOCOL_VIOLATION.
///
/// # What it catches, observed by making the change and running it
///
/// Removing `CodecError::UnknownMessageType(_)` from draft-17's
/// `codec_session_error_code` — the state the table was in for as long as it has
/// existed, and the state drafts 15, 16, 18 and 19 were in alongside it:
///
/// ```text
/// ---- an_unassigned_control_message_type_closes_the_quic_connection stdout ----
///
/// thread 'an_unassigned_control_message_type_closes_the_quic_connection' (3252) panicked at crates\moqtap-client\tests\draft17_unknown_message_type_closes_the_session.rs:144:14:
/// the client refused the frame but never closed the connection: Elapsed(())
/// ```
///
/// The client still returns `Err(UnknownMessageType)` in that state. The peer
/// never hears about it and can repeat the frame indefinitely.
#[tokio::test]
async fn an_unassigned_control_message_type_closes_the_quic_connection() {
    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft17.quic_alpn()]);

    let peer = tokio::spawn(async move {
        let conn = endpoint.accept().await.expect("accept").await.expect("tls handshake");

        // Draft-17 carries control on a pair of unidirectional streams, not on
        // one bidirectional stream: the client opens its own and the server
        // opens the other.
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
            .write_all(&frame_of_an_unassigned_type())
            .await
            .expect("write the offending frame");

        let reason = tokio::time::timeout(PATIENCE, conn.closed())
            .await
            .expect("the client refused the frame but never closed the connection");

        match reason {
            quinn::ConnectionError::ApplicationClosed(frame) => {
                let code = u64::from(frame.error_code);
                assert_eq!(
                    code,
                    PROTOCOL_VIOLATION,
                    "Section 9 names no code for this rule, so it takes the one every \
                     other unnamed rule takes; the close carried {}",
                    if code == INVALID_REQUIRED_REQUEST_ID {
                        "INVALID_REQUIRED_REQUEST_ID (0x7), the other code in this \
                         draft's table, instead"
                            .to_string()
                    } else {
                        format!("{code} instead")
                    }
                );
                let text = String::from_utf8_lossy(&frame.reason).to_string();
                assert!(
                    text.contains("message type"),
                    "the close reason should name the rule that was broken; got {text:?}"
                );
            }
            other => panic!("expected an application close, got {other:?}"),
        }
    });

    let mut conn =
        Connection::connect(&addr.to_string(), client_config()).await.expect("client connect");

    let err = conn.recv_control().await.expect_err("an unassigned message type must be refused");
    let text = err.to_string();
    assert!(text.contains("message type"), "the error should name the rule; got {text:?}");

    tokio::time::timeout(PATIENCE * 3, peer)
        .await
        .expect("peer task hung")
        .expect("peer task panicked");
}

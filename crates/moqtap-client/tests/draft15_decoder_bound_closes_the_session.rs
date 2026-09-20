#![cfg(feature = "draft15")]
//! When draft-15 says a decoder bound MUST close the session, the client closes
//! it on the wire — not just in its own state machine.
//!
//! # Why this draft needs the machinery at all
//!
//! Draft-15 states most of the same decoder bounds as the later drafts, so it
//! needs a `close_for_codec` and a mapping table of its own. Without them a
//! refusal stops at the frame, and the peer, which is the one that broke the
//! rule, sees a session that is still open and goes on sending.
//! That gap is invisible from inside the process: the decoder returns `Err`
//! either way, and only something holding the other end of a real connection can
//! tell the difference.
//!
//! # Why the table is shorter here than on draft-16
//!
//! Because the draft is. Draft-16 answers two rules draft-15 does not state at
//! all — a zero-length Track Namespace Field, and the delta-encoded parameter
//! type overflow, which arrives with delta encoding itself at draft-16.
//! Answering a bound the draft does not state would close sessions over traffic
//! a conforming peer may send.
//!
//! # The violation used
//!
//! A REQUEST_ERROR carrying a 2,000-byte Reason Phrase. Draft-15 Section 1.4.3:
//! "The reason phrase length has a maximum value of 1024 bytes. If an endpoint
//! receives a length exceeding the maximum, it MUST close the session with a
//! PROTOCOL_VIOLATION". The frame is built by hand because the encoder refuses
//! to write one — which is the point: the two directions agree, and only a
//! hand-made frame can reach the decode-side check.

mod common;

use std::time::Duration;

use moqtap_client::draft15::connection::{ClientConfig, Connection, TransportType};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::draft15::message::{ControlMessage, ServerSetup};
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

/// Session termination code PROTOCOL_VIOLATION, draft-15 Section 13.3.1.
const PROTOCOL_VIOLATION: u64 = 0x3;

const PATIENCE: Duration = Duration::from_secs(10);

/// Over the 1,024-byte maximum and well clear of it, so a fencepost error in
/// either direction cannot make this test pass for the wrong reason.
const REASON_PHRASE_LEN: usize = 2_000;

fn server_setup() -> AnyControlMessage {
    AnyControlMessage::Draft15(ControlMessage::ServerSetup(ServerSetup { parameters: Vec::new() }))
}

fn client_config() -> ClientConfig {
    ClientConfig {
        draft: DraftVersion::Draft15,
        transport: TransportType::Quic,
        skip_cert_verification: true,
        ca_certs: Vec::new(),
        setup_parameters: Vec::new(),
    }
}

/// REQUEST_ERROR (0x05) with a Reason Phrase of `len` bytes.
///
/// Draft-15 frames a control message as a varint Type, a 16-bit big-endian
/// Length, and then the payload — Request ID, Error Code, Reason Phrase Length
/// and the phrase itself.
fn oversized_request_error(len: usize) -> Vec<u8> {
    let mut body = Vec::new();
    VarInt::from_usize(1).encode(&mut body); // Request ID
    VarInt::from_usize(0).encode(&mut body); // Error Code
    VarInt::from_usize(len).encode(&mut body); // Reason Phrase Length
    body.extend(std::iter::repeat_n(b'x', len));

    let mut out = Vec::new();
    VarInt::from_usize(0x05).encode(&mut out);
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// An oversized Reason Phrase closes the QUIC connection with
/// PROTOCOL_VIOLATION.
///
/// # What it catches, observed by making the change and running it
///
/// Replacing `recv_control`'s body with `recv.read_control(capture_raw).await?`,
/// so the refusal never reaches `close_for_codec`:
///
/// ```text
/// ---- an_oversized_reason_phrase_closes_the_quic_connection stdout ----
///
/// thread 'an_oversized_reason_phrase_closes_the_quic_connection' panicked at crates\moqtap-client\tests\draft15_decoder_bound_closes_the_session.rs:
/// the client refused the frame but never closed the connection: Elapsed(())
/// ```
///
/// The client still returns `Err(ReasonPhraseTooLong)` in that state; the peer
/// just never hears about it and can repeat the frame indefinitely.
#[tokio::test]
async fn an_oversized_reason_phrase_closes_the_quic_connection() {
    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft15.quic_alpn()]);

    let peer = tokio::spawn(async move {
        let conn = endpoint.accept().await.expect("accept").await.expect("tls handshake");

        // Draft-15 carries control on a bidirectional stream the client opens.
        // The send half stays raw quinn: the offending frame has to go out
        // exactly as written, and every framing helper in this workspace would
        // refuse to build it.
        let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
        let mut framed_recv = common::frame_uni_recv(recv, DraftVersion::Draft15);
        framed_recv.read_control(false).await.expect("read CLIENT_SETUP");

        let mut setup = Vec::new();
        server_setup().encode(&mut setup).expect("encode SERVER_SETUP");
        send.write_all(&setup).await.expect("write SERVER_SETUP");

        send.write_all(&oversized_request_error(REASON_PHRASE_LEN))
            .await
            .expect("write the oversized REQUEST_ERROR");

        let reason = tokio::time::timeout(PATIENCE, conn.closed())
            .await
            .expect("the client refused the frame but never closed the connection");

        match reason {
            quinn::ConnectionError::ApplicationClosed(frame) => {
                assert_eq!(
                    u64::from(frame.error_code),
                    PROTOCOL_VIOLATION,
                    "Section 1.4.3 answers an oversized Reason Phrase with \
                     PROTOCOL_VIOLATION; the close carried {} instead",
                    u64::from(frame.error_code)
                );
                let text = String::from_utf8_lossy(&frame.reason).to_string();
                assert!(
                    text.contains("reason phrase"),
                    "the close reason should name the bound that was broken; got {text:?}"
                );
            }
            other => panic!("expected an application close, got {other:?}"),
        }
    });

    let mut conn =
        Connection::connect(&addr.to_string(), client_config()).await.expect("client connect");

    let err = conn.recv_control().await.expect_err("a 2,000-byte Reason Phrase must be refused");
    let text = err.to_string();
    assert!(text.contains("reason phrase"), "the error should name the bound; got {text:?}");

    tokio::time::timeout(PATIENCE * 3, peer)
        .await
        .expect("peer task hung")
        .expect("peer task panicked");
}

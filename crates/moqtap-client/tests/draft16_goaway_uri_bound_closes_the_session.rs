#![cfg(feature = "draft16")]
//! Draft-16 Section 9.4: "The maxmimum length of the New Session URI is 8,192
//! bytes. If an endpoint receives a length exceeding the maximum, it MUST close
//! the session with a PROTOCOL_VIOLATION."
//!
//! # Why this rule has a gate and its six siblings do not
//!
//! Because this is the one draft-16's table got wrong. When the table was
//! written, a survey reported that drafts 15 and 16 stated no maximum for the
//! field and that draft-17 introduced one, so the entry was left out
//! deliberately and the reasoning was written down in three places. The survey
//! was wrong: the sentence above is in every draft from 11 to 20, and only 07
//! through 10 are without it. Drafts 15 and 16 refused the frame and left the
//! session open over a rule they state as plainly as their neighbours.
//!
//! The mistake was a search pattern narrow enough to miss the wording rather
//! than a reading of the draft, which is the failure a bare hit count invites —
//! the same shape as answering a bound a draft does not state, in the other
//! direction. Excluding a rule needs the same evidence as including one, and
//! this gate is the evidence for including it.
//!
//! # Why the frame carries a length and no URI
//!
//! The decoder checks the declared length before reading any bytes, which is
//! what the sentence asks of it: an endpoint that read 8,193 bytes to discover
//! it should not have would have allocated them first. So the frame is a length
//! and nothing else, and the gate reaches the rule without a nine-kilobyte
//! write.
//!
//! The encoder refuses to produce one either way, which is the point: the two
//! directions apply the same bound, so only a hand-made frame can reach the
//! decode side.

mod common;

use std::time::Duration;

use moqtap_client::draft16::connection::{ClientConfig, Connection, TransportType};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::draft16::message::{ControlMessage, ServerSetup};
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

/// Session termination code PROTOCOL_VIOLATION, draft-16 Section 13.4.1.
const PROTOCOL_VIOLATION: u64 = 0x3;

const PATIENCE: Duration = Duration::from_secs(10);

/// Over the 8,192-byte maximum and well clear of it, so a fencepost error in
/// either direction cannot make this test pass for the wrong reason.
const DECLARED_URI_LEN: usize = 9_000;

fn client_config() -> ClientConfig {
    ClientConfig {
        draft: DraftVersion::Draft16,
        transport: TransportType::Quic,
        skip_cert_verification: true,
        ca_certs: Vec::new(),
        setup_parameters: Vec::new(),
    }
}

fn server_setup() -> AnyControlMessage {
    AnyControlMessage::Draft16(ControlMessage::ServerSetup(ServerSetup { parameters: Vec::new() }))
}

/// GOAWAY (0x10) declaring a New Session URI longer than the maximum.
///
/// Draft-16 frames a control message as a varint Type, a 16-bit big-endian
/// Length, then the payload — for GOAWAY, the New Session URI Length and the URI
/// itself.
fn goaway_with_an_oversized_uri() -> Vec<u8> {
    let mut body = Vec::new();
    VarInt::from_usize(DECLARED_URI_LEN).encode(&mut body);

    let mut out = Vec::new();
    VarInt::from_usize(0x10).encode(&mut out);
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// An oversized New Session URI length closes the QUIC connection with
/// PROTOCOL_VIOLATION.
///
/// # What it catches, observed by making the change and running it
///
/// Dropping `CodecError::GoAwayUriTooLong` from draft-16's
/// `codec_session_error_code` — that is, the state the table was in when it was
/// first written, on the strength of a survey that said this draft states no
/// such maximum:
///
/// ```text
/// ---- an_oversized_new_session_uri_closes_the_quic_connection stdout ----
///
/// thread 'an_oversized_new_session_uri_closes_the_quic_connection' (20816) panicked at crates\moqtap-client\tests\draft16_goaway_uri_bound_closes_the_session.rs:122:14:
/// the client refused the frame but never closed the connection: Elapsed(())
/// ```
#[tokio::test]
async fn an_oversized_new_session_uri_closes_the_quic_connection() {
    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft16.quic_alpn()]);

    let peer = tokio::spawn(async move {
        let conn = endpoint.accept().await.expect("accept").await.expect("tls handshake");

        // Draft-16 carries control on a bidirectional stream the client opens.
        // The send half stays raw quinn: the offending frame has to go out
        // exactly as written, and every framing helper here would refuse it.
        let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
        let mut framed_recv = common::frame_uni_recv(recv, DraftVersion::Draft16);
        framed_recv.read_control(false).await.expect("read CLIENT_SETUP");

        let mut setup = Vec::new();
        server_setup().encode(&mut setup).expect("encode SERVER_SETUP");
        send.write_all(&setup).await.expect("write SERVER_SETUP");

        send.write_all(&goaway_with_an_oversized_uri()).await.expect("write the offending GOAWAY");

        let reason = tokio::time::timeout(PATIENCE, conn.closed())
            .await
            .expect("the client refused the frame but never closed the connection");

        match reason {
            quinn::ConnectionError::ApplicationClosed(frame) => {
                assert_eq!(
                    u64::from(frame.error_code),
                    PROTOCOL_VIOLATION,
                    "Section 8.4 answers an oversized New Session URI with \
                     PROTOCOL_VIOLATION; the close carried {} instead",
                    u64::from(frame.error_code)
                );
                let text = String::from_utf8_lossy(&frame.reason).to_string();
                assert!(
                    text.contains("URI"),
                    "the close reason should name the bound that was broken; got {text:?}"
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
        .expect_err("a New Session URI length past the maximum must be refused");
    let text = err.to_string();
    assert!(text.contains("URI"), "the error should name the bound; got {text:?}");

    tokio::time::timeout(PATIENCE * 3, peer)
        .await
        .expect("peer task hung")
        .expect("peer task panicked");
}

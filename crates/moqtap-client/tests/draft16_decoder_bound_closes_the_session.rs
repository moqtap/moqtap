#![cfg(feature = "draft16")]
//! Draft-16's close table is draft-15's plus two rules, and this gates one of
//! the two.
//!
//! `close_for_codec` and its mapping table arrived with draft-17; drafts 15 and
//! 16 state most of the same bounds and had neither, so every one of them
//! stopped at refusing the frame while the peer went on sending.
//! The companion file `draft15_decoder_bound_closes_the_session.rs` gates a rule
//! both drafts share. This one deliberately does not: it uses a rule draft-15
//! does not state at all, so a table copied wholesale from draft-15 to draft-16
//! fails here.
//!
//! # The violation used
//!
//! A PUBLISH_NAMESPACE whose Track Namespace carries one field of length zero.
//! Draft-16 Section 2.4.1: "Each Track Namespace Field Value MUST contain at
//! least one byte. If an endpoint receives a Track Namespace Field with a Track
//! Namespace Field Length of 0, it MUST close the session with a
//! PROTOCOL_VIOLATION." Draft-15 has no such sentence — its namespace fields may
//! be empty — which is why `CodecError::EmptyNamespaceField` appears in
//! draft-16's table and not in draft-15's.
//!
//! The frame is built by hand because the encoder refuses to write one, which is
//! the point: the two directions agree, and only a hand-made frame can reach the
//! decode-side check.

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

fn server_setup() -> AnyControlMessage {
    AnyControlMessage::Draft16(ControlMessage::ServerSetup(ServerSetup { parameters: Vec::new() }))
}

fn client_config() -> ClientConfig {
    ClientConfig {
        draft: DraftVersion::Draft16,
        transport: TransportType::Quic,
        skip_cert_verification: true,
        ca_certs: Vec::new(),
        setup_parameters: Vec::new(),
    }
}

/// PUBLISH_NAMESPACE (0x06) whose namespace is a single zero-length field.
///
/// Draft-16 frames a control message as a varint Type, a 16-bit big-endian
/// Length, then the payload: Request ID, the Track Namespace as a field count
/// followed by that many length-prefixed fields, and the parameter count.
fn namespace_with_an_empty_field() -> Vec<u8> {
    let mut body = Vec::new();
    VarInt::from_usize(1).encode(&mut body); // Request ID
    VarInt::from_usize(1).encode(&mut body); // Number of Track Namespace Fields
    VarInt::from_usize(0).encode(&mut body); // the field's length — the violation
    VarInt::from_usize(0).encode(&mut body); // parameter count

    let mut out = Vec::new();
    VarInt::from_usize(0x06).encode(&mut out);
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// A zero-length Track Namespace Field closes the QUIC connection with
/// PROTOCOL_VIOLATION.
///
/// # What it catches, observed by making the change and running it
///
/// Dropping `CodecError::EmptyNamespaceField` from draft-16's
/// `codec_session_error_code` — that is, giving draft-16 the table draft-15
/// needs, which is the mistake a copy between the two would make:
///
/// ```text
/// ---- an_empty_track_namespace_field_closes_the_quic_connection stdout ----
///
/// thread 'an_empty_track_namespace_field_closes_the_quic_connection' panicked at crates\moqtap-client\tests\draft16_decoder_bound_closes_the_session.rs:
/// the client refused the frame but never closed the connection: Elapsed(())
/// ```
#[tokio::test]
async fn an_empty_track_namespace_field_closes_the_quic_connection() {
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

        send.write_all(&namespace_with_an_empty_field())
            .await
            .expect("write the offending PUBLISH_NAMESPACE");

        let reason = tokio::time::timeout(PATIENCE, conn.closed())
            .await
            .expect("the client refused the frame but never closed the connection");

        match reason {
            quinn::ConnectionError::ApplicationClosed(frame) => {
                assert_eq!(
                    u64::from(frame.error_code),
                    PROTOCOL_VIOLATION,
                    "Section 2.4.1 answers a zero-length Track Namespace Field with \
                     PROTOCOL_VIOLATION; the close carried {} instead",
                    u64::from(frame.error_code)
                );
                let text = String::from_utf8_lossy(&frame.reason).to_string();
                assert!(
                    text.contains("track namespace field"),
                    "the close reason should name the rule that was broken; got {text:?}"
                );
            }
            other => panic!("expected an application close, got {other:?}"),
        }
    });

    let mut conn =
        Connection::connect(&addr.to_string(), client_config()).await.expect("client connect");

    let err =
        conn.recv_control().await.expect_err("a zero-length Track Namespace Field must be refused");
    let text = err.to_string();
    assert!(text.contains("track namespace field"), "the error should name the rule; got {text:?}");

    tokio::time::timeout(PATIENCE * 3, peer)
        .await
        .expect("peer task hung")
        .expect("peer task panicked");
}

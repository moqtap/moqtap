#![cfg(feature = "draft10")]
//! Draft-10 Section 8: "An endpoint that receives an unknown message type MUST
//! close the session."
//!
//! # Why this rule is worth a gate of its own
//!
//! It is the one rule in this draft's close table whose sentence names no error
//! code. The other four quote one — "with a Protocol Violation", "with error
//! code 'Parameter Length Mismatch'" — and this one stops at "MUST close the
//! session". The table therefore has to *choose*, and the choice is the registry's
//! general code for an action "disallowed by the specification". A reader of the
//! table cannot tell a deliberate choice from an accident, so the choice is
//! pinned here.
//!
//! # Why an unassigned type inside the assigned block
//!
//! `0x0F` is the gap between UNSUBSCRIBE_ANNOUNCES-era assignments and GOAWAY at
//! `0x10`. A type far outside the range would also be unknown, and would also be
//! caught by a decoder that merely stopped at the first unassigned value it
//! reached; a hole inside the block is only caught by one that checks membership.
//!
//! # Why the frame is built by hand
//!
//! There is no other way. An unknown type has no encoder, by construction.

mod common;

use std::time::Duration;

use moqtap_client::draft10::connection::{ClientConfig, Connection, TransportType};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::draft10::message::{ControlMessage, ServerSetup};
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

/// Session termination code `Protocol Violation`, draft-10 Section 3.4.
const PROTOCOL_VIOLATION: u64 = 0x3;

const PATIENCE: Duration = Duration::from_secs(10);

/// A control message type draft-10 assigns to nothing. It sits between the
/// namespace-subscription types below it and GOAWAY at `0x10`.
const UNASSIGNED_TYPE: u64 = 0x0F;

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
    AnyControlMessage::Draft10(ControlMessage::ServerSetup(ServerSetup {
        selected_version: DraftVersion::Draft10.version_varint(),
        parameters: Vec::new(),
    }))
}

/// A well-framed control message of an unassigned type.
///
/// Draft-10 frames a control message as a varint Type and a varint Length, so a
/// receiver can skip a message it does not understand — which is exactly what
/// this draft says not to do. The payload is empty: the frame is refused for its
/// type, and giving it contents would leave open whether the contents were what
/// did it.
fn message_of_an_unassigned_type() -> Vec<u8> {
    let mut out = Vec::new();
    VarInt::from_u64(UNASSIGNED_TYPE).unwrap().encode(&mut out);
    VarInt::from_usize(0).encode(&mut out);
    out
}

/// An unassigned control message type closes the QUIC connection with Protocol
/// Violation.
///
/// # What it catches, observed by making the change and running it
///
/// Dropping `CodecError::UnknownMessageType` from draft-10's
/// `codec_session_error_code` — the state the draft was in before it had a table
/// at all, where the decoder refused the frame and the peer never heard:
///
/// ```text
/// ---- an_unassigned_message_type_closes_the_quic_connection stdout ----
///
/// thread 'an_unassigned_message_type_closes_the_quic_connection' (28572) panicked at crates\moqtap-client\tests\draft10_unknown_message_type_closes_the_session.rs:
/// the client refused the frame but never closed the connection: Elapsed(())
/// ```
#[tokio::test]
async fn an_unassigned_message_type_closes_the_quic_connection() {
    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft10.quic_alpn()]);

    let peer = tokio::spawn(async move {
        let conn = endpoint.accept().await.expect("accept").await.expect("tls handshake");

        // Draft-10 carries control on a bidirectional stream the client opens.
        // The send half stays raw quinn: the offending frame has to go out
        // exactly as written, and every framing helper here would refuse it.
        let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
        let mut framed_recv = common::frame_uni_recv(recv, DraftVersion::Draft10);
        framed_recv.read_control(false).await.expect("read CLIENT_SETUP");

        let mut setup = Vec::new();
        server_setup().encode(&mut setup).expect("encode SERVER_SETUP");
        send.write_all(&setup).await.expect("write SERVER_SETUP");

        send.write_all(&message_of_an_unassigned_type())
            .await
            .expect("write the unassigned-type message");

        let reason = tokio::time::timeout(PATIENCE, conn.closed())
            .await
            .expect("the client refused the frame but never closed the connection");

        match reason {
            quinn::ConnectionError::ApplicationClosed(frame) => {
                assert_eq!(
                    u64::from(frame.error_code),
                    PROTOCOL_VIOLATION,
                    "an unknown message type is an action the draft disallows; the close \
                     carried {} instead",
                    u64::from(frame.error_code)
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

    let err =
        conn.recv_control().await.expect_err("an unassigned control message type must be refused");
    let text = err.to_string();
    assert!(text.contains("message type"), "the error should name the rule; got {text:?}");

    tokio::time::timeout(PATIENCE * 3, peer)
        .await
        .expect("peer task hung")
        .expect("peer task panicked");
}

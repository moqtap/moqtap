#![cfg(feature = "draft14")]
//! Draft-14 Section 9.8: "Content Exists: 1 if an object has been published on
//! this track, 0 if not. If 0, then the Largest Group ID and Largest Object ID
//! fields will not be present. Any other value is a protocol error and MUST
//! terminate the session with a PROTOCOL_VIOLATION".
//!
//! Every draft from 07 to 14 carries the field and that sentence, word for word.
//! Draft-15 removed the field, replacing it with the presence or absence of a
//! LARGEST_OBJECT parameter, so the rule has no subject from there on.
//!
//! # Why this gate exists on draft-14 and not on draft-07
//!
//! Draft-07 was the only draft answering the rule. Its table mapped the codec's
//! `InvalidContentExists` variant to Protocol Violation and its doc comment gave
//! the reason, which was that no draft above 07 has the field at all. That is
//! not so — the
//! field and the sentence run to draft-14 — and the other seven drafts both
//! produced a different error variant and left it unrouted, so they refused the
//! frame and kept the session open over a rule they state as plainly as
//! draft-07 does.
//!
//! Draft-14 is the far end of that range and the draft where the field appears
//! in the most messages, which makes it the one most likely to drift again.
//!
//! # Why the field and not the value's meaning
//!
//! Content Exists decides whether two more fields follow it. A value that is
//! neither 0 nor 1 leaves a reader with no way to know where the message ends,
//! so this is not a rule about a preference being out of range — it is a frame
//! whose remaining length is undefined. That is why the drafts answer it with a
//! close rather than by ignoring the field.

mod common;

use std::time::Duration;

use moqtap_client::draft14::connection::{ClientConfig, Connection, TransportType};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::draft14::message::{ControlMessage, ServerSetup};
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

/// Session termination code PROTOCOL_VIOLATION, draft-14 Section 3.4.
const PROTOCOL_VIOLATION: u64 = 0x3;

/// A Content Exists value the draft assigns no meaning to, clear of both legal
/// values so a fencepost error cannot make this pass for the wrong reason.
const NEITHER_ZERO_NOR_ONE: u8 = 7;

const PATIENCE: Duration = Duration::from_secs(10);

fn client_config() -> ClientConfig {
    ClientConfig {
        draft: DraftVersion::Draft14,
        additional_versions: Vec::new(),
        transport: TransportType::Quic,
        skip_cert_verification: true,
        ca_certs: Vec::new(),
        setup_parameters: Vec::new(),
    }
}

fn server_setup() -> AnyControlMessage {
    AnyControlMessage::Draft14(ControlMessage::ServerSetup(ServerSetup {
        selected_version: DraftVersion::Draft14.version_varint(),
        parameters: Vec::new(),
    }))
}

/// A SUBSCRIBE_OK whose Content Exists byte is neither zero nor one.
///
/// Hand-built rather than encoded, because the codec's `ContentExists` is an
/// enum of exactly the two legal values and no encoder here can write a third.
/// Draft-14 frames a control message as a varint Type, a 16-bit big-endian
/// Length, then the payload: Request ID, Track Alias, Expires, Group Order,
/// Content Exists, and the parameter count.
fn subscribe_ok_with_an_unassigned_content_exists() -> Vec<u8> {
    let body = [
        0x00,                 // Request ID
        0x04,                 // Track Alias
        0x00,                 // Expires
        0x01,                 // Group Order: Ascending
        NEITHER_ZERO_NOR_ONE, // Content Exists
        0x00,                 // Number of Parameters
    ];

    let mut out = Vec::new();
    VarInt::from_u64(0x04).expect("message type fits a varint").encode(&mut out);
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// A Content Exists that is neither zero nor one closes the QUIC connection with
/// PROTOCOL_VIOLATION.
///
/// # What it catches, observed by making the change and running it
///
/// Sending `CodecError::InvalidContentExists` to the `None` arm of draft-14's
/// `codec_session_error_code` — the state every draft from 08 to 14 was in. The
/// decoder still refuses the frame, so the client-side half of this test passes
/// unchanged; only the wire shows the difference:
///
/// ```text
/// ---- an_unassigned_content_exists_closes_the_quic_connection stdout ----
///
/// thread 'an_unassigned_content_exists_closes_the_quic_connection' (36548) panicked at crates\moqtap-client\tests\draft14_content_exists_closes_the_session.rs:134:14:
/// the client refused the frame but never closed the connection: Elapsed(())
/// ```
///
/// That is the whole reason this gate is on the wire and not in the codec: a
/// decoder test cannot tell a routed rule from an unrouted one.
#[tokio::test]
async fn an_unassigned_content_exists_closes_the_quic_connection() {
    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft14.quic_alpn()]);

    let peer = tokio::spawn(async move {
        let conn = endpoint.accept().await.expect("accept").await.expect("tls handshake");

        let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
        let mut framed_recv = common::frame_uni_recv(recv, DraftVersion::Draft14);
        framed_recv.read_control(false).await.expect("read CLIENT_SETUP");

        let mut setup = Vec::new();
        server_setup().encode(&mut setup).expect("encode SERVER_SETUP");
        send.write_all(&setup).await.expect("write SERVER_SETUP");

        send.write_all(&subscribe_ok_with_an_unassigned_content_exists())
            .await
            .expect("write the offending SUBSCRIBE_OK");

        let reason = tokio::time::timeout(PATIENCE, conn.closed())
            .await
            .expect("the client refused the frame but never closed the connection");

        match reason {
            quinn::ConnectionError::ApplicationClosed(frame) => {
                assert_eq!(
                    u64::from(frame.error_code),
                    PROTOCOL_VIOLATION,
                    "Section 9.8 answers a Content Exists that is neither zero nor one \
                     with PROTOCOL_VIOLATION; the close carried {} instead",
                    u64::from(frame.error_code)
                );
                let text = String::from_utf8_lossy(&frame.reason).to_string();
                assert!(
                    text.contains("content exists"),
                    "the close reason should name the field; got {text:?}"
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
        .expect_err("a Content Exists that is neither zero nor one must be refused");
    let text = err.to_string();
    assert!(text.contains("content exists"), "the error should name the field; got {text:?}");

    tokio::time::timeout(PATIENCE * 3, peer)
        .await
        .expect("peer task hung")
        .expect("peer task panicked");
}

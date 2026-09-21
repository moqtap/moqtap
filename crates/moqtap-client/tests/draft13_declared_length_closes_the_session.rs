#![cfg(feature = "draft13")]
//! Draft-13 Section 8: "Control messages have a length to make parsing easier,
//! but no control messages are intended to be ignored. The length is set to the
//! number of bytes in Message Payload, which is defined by each message type. If
//! the length does not match the length of the Message Payload, the receiver
//! MUST close the session with Protocol Violation."
//!
//! # Why the rule needs a variant of its own
//!
//! Every draft's `ControlMessage::decode` has the check. Answered with
//! `CodecError::InvalidField` it reaches no further than the frame: a dozen
//! unrelated malformations answer with that variant too, so no mapping table can
//! route it to a close without closing sessions the drafts say nothing about. A
//! rule that lands there is enforced against the frame and invisible to the
//! session, which is the half-fix any rule reaches on that variant, and why this
//! one answers `CodecError::ControlMessageLengthMismatch` instead.
//!
//! # Why the short direction and not the long one
//!
//! "Does not match" has two sides and they arrive as different failures. A
//! Length larger than the fields leaves bytes unread; the codec has gated that
//! on all the drafts. A Length *smaller* than the fields makes
//! them run past the end of a buffer that cannot grow. Reported as
//! `UnexpectedEnd` it would be invisible to every close table, which excludes
//! the variant on purpose: everywhere else it means the message is still
//! arriving and a reader loops on it rather than closing.
//!
//! Inside a buffer already bounded by the declared Length there is nothing left
//! to arrive. The frame is entirely present and it is the number describing it
//! that is wrong. This gate is the one that says so on the wire.
//!
//! # Why draft-13
//!
//! Drafts 11 and 14 hold the two ends of their group, so without a gate here
//! drafts 12 and 13 are covered only by whatever they share with them — which
//! is exactly how four identical-looking tables drift apart unnoticed.

mod common;

use std::time::Duration;

use moqtap_client::draft13::connection::{ClientConfig, Connection, TransportType};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::draft13::message::{ControlMessage, ServerSetup};
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

/// Session termination code Protocol Violation, draft-13 Section 3.5.
const PROTOCOL_VIOLATION: u64 = 0x3;

const PATIENCE: Duration = Duration::from_secs(10);

/// The URI the GOAWAY carries. Long enough that the Length being short by two
/// cannot be mistaken for a boundary effect on a one-byte field.
const URI: &[u8] = b"moqt://example/next";

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
    AnyControlMessage::Draft13(ControlMessage::ServerSetup(ServerSetup {
        selected_version: DraftVersion::Draft13.version_varint(),
        parameters: Vec::new(),
    }))
}

/// GOAWAY (0x10) whose declared Length is two bytes short of its own fields.
///
/// Draft-13 frames a control message as a varint Type, a 16-bit big-endian
/// Length, then the payload — for GOAWAY, the New Session URI Length and the URI
/// itself. Every byte of that payload is written; only the number in front of it
/// is wrong, so the frame is complete and the disagreement is purely between the
/// Length and the fields.
///
/// The decoder hands its payload parser two bytes fewer than the URI needs, and
/// the parser runs out with the rest of the frame sitting unread behind it.
fn goaway_with_a_short_declared_length() -> Vec<u8> {
    let mut body = Vec::new();
    VarInt::from_usize(URI.len()).encode(&mut body);
    body.extend_from_slice(URI);

    let declared = (body.len() - 2) as u16;

    let mut out = Vec::new();
    VarInt::from_usize(0x10).encode(&mut out);
    out.extend_from_slice(&declared.to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// A control message whose Length disagrees with its fields closes the QUIC
/// connection with Protocol Violation.
///
/// # What it catches, observed by making the change and running it
///
/// Letting draft-13's `ControlMessage::decode` pass the payload parser's
/// `UnexpectedEnd` out unchanged instead of answering with
/// `ControlMessageLengthMismatch`, which is the shape in which a table cannot
/// answer it:
///
/// ```text
/// ---- a_short_declared_length_closes_the_quic_connection stdout ----
///
/// thread 'a_short_declared_length_closes_the_quic_connection' (61172) panicked at crates\moqtap-client\tests\draft13_declared_length_closes_the_session.rs:
/// the error should name the rule; got "codec error: insufficient bytes"
/// ```
///
/// That is the whole difficulty in one line. The frame was complete, the client
/// had every byte of it, and the answer it gave was the one that means "keep
/// waiting".
#[tokio::test]
async fn a_short_declared_length_closes_the_quic_connection() {
    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft13.quic_alpn()]);

    let peer = tokio::spawn(async move {
        let conn = endpoint.accept().await.expect("accept").await.expect("tls handshake");

        // Draft-13 carries control on a bidirectional stream the client opens.
        // The send half stays raw quinn: the offending frame has to go out
        // exactly as written, and every framing helper here would refuse it.
        let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
        let mut framed_recv = common::frame_uni_recv(recv, DraftVersion::Draft13);
        framed_recv.read_control(false).await.expect("read CLIENT_SETUP");

        let mut setup = Vec::new();
        server_setup().encode(&mut setup).expect("encode SERVER_SETUP");
        send.write_all(&setup).await.expect("write SERVER_SETUP");

        send.write_all(&goaway_with_a_short_declared_length())
            .await
            .expect("write the offending GOAWAY");

        let reason = tokio::time::timeout(PATIENCE, conn.closed())
            .await
            .expect("the client refused the frame but never closed the connection");

        match reason {
            quinn::ConnectionError::ApplicationClosed(frame) => {
                assert_eq!(
                    u64::from(frame.error_code),
                    PROTOCOL_VIOLATION,
                    "Section 8 answers a Length that disagrees with the fields with \
                     Protocol Violation; the close carried {} instead",
                    u64::from(frame.error_code)
                );
                let text = String::from_utf8_lossy(&frame.reason).to_string();
                assert!(
                    text.contains("declares"),
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
        .expect_err("a Length that disagrees with the fields must be refused");
    let text = err.to_string();
    assert!(text.contains("declares"), "the error should name the rule; got {text:?}");

    tokio::time::timeout(PATIENCE * 3, peer)
        .await
        .expect("peer task hung")
        .expect("peer task panicked");
}

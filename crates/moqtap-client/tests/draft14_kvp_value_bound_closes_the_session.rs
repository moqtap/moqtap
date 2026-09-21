#![cfg(feature = "draft14")]
//! Draft-14 Section 1.4.2, on the Key-Value-Pair Length field: "The maximum
//! length of a value is 2^16-1 bytes. If an endpoint receives a length larger
//! than the maximum, it MUST close the session with a Protocol Violation."
//!
//! # Why this draft needs the machinery at all
//!
//! Draft-14 states most of the same decoder bounds as the later drafts, so it
//! needs a `close_for_codec` and a mapping table of its own. Without them a
//! refusal stops at the frame, and the peer, which is the one that broke the
//! rule, sees a session that is still open and goes on
//! sending. That gap is invisible from inside the process: the decoder returns
//! `Err` either way, and only something holding the other end of a real
//! connection can tell the difference.
//!
//! # Why this rule and not one of the other seven
//!
//! It is the only one in draft-14's table that is raised by shared code rather
//! than by this draft's own message module. `KeyValuePair::decode` is one
//! function serving nine drafts, and it reports the bound as
//! `CodecError::Kvp(KvpError::ValueTooLong)` — a nested variant, where every
//! other entry in the table is a plain one. A table that matched
//! `CodecError::Kvp(_)` would also close the session over a malformed pair the
//! draft says nothing about; a table that forgot to nest would not compile.
//! Neither mistake is possible to make with the other seven rules, so this is
//! where the gate belongs.
//!
//! The other seven are shared verbatim with drafts 11, 12 and 13 — the finditer
//! sweep across all the drafts found the same eight sentences in all four —
//! so a gate on any one of them would say the same thing four times.
//!
//! # Why the frame is built by hand
//!
//! The encoder refuses to write one. This draft's parameter encoder writes
//! through `KeyValuePair::encode_list_checked`, which applies the same bound,
//! because a value past the maximum is one the receiver is required to close the
//! session over, so writing it is not a way to send it. Only a hand-made frame
//! reaches the decode side.
//!
//! The declared length is what the rule is about, and the decoder checks it
//! before reading any bytes — so the frame carries the declared length and no
//! value at all, which is also the only way to express a 65,536-byte value
//! inside a control message whose own length field is sixteen bits.

mod common;

use std::time::Duration;

use moqtap_client::draft14::connection::{ClientConfig, Connection, TransportType};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::draft14::message::{ControlMessage, ServerSetup};
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

/// Session termination code `Protocol Violation`, draft-14 Section 3.4.
const PROTOCOL_VIOLATION: u64 = 0x3;

const PATIENCE: Duration = Duration::from_secs(10);

/// One byte past the 2^16-1 maximum. Exactly one past, so the gate observes the
/// boundary the draft draws and not some number far outside it.
const OVERSIZED_VALUE_LEN: usize = 65_536;

/// A parameter type with an odd number, which is what makes its value
/// length-prefixed rather than a bare varint. An even type carries a varint and
/// has no Length field for this rule to bind.
const ODD_PARAMETER_TYPE: u64 = 0x01;

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

/// PUBLISH_NAMESPACE (0x06) carrying one parameter whose declared value length
/// is over the maximum.
///
/// Draft-14 frames a control message as a varint Type, a 16-bit big-endian
/// Length, then the payload: Request ID, the Track Namespace as a field count
/// followed by that many length-prefixed fields, then the parameters as a count
/// followed by that many Key-Value-Pairs.
fn publish_namespace_with_an_oversized_parameter() -> Vec<u8> {
    let mut body = Vec::new();
    VarInt::from_usize(1).encode(&mut body); // Request ID
    VarInt::from_usize(1).encode(&mut body); // one Track Namespace field
    VarInt::from_usize(3).encode(&mut body); // its length
    body.extend_from_slice(b"abc"); // and its value
    VarInt::from_usize(1).encode(&mut body); // one parameter
    VarInt::from_u64(ODD_PARAMETER_TYPE).unwrap().encode(&mut body);
    VarInt::from_usize(OVERSIZED_VALUE_LEN).encode(&mut body); // the violation

    let mut out = Vec::new();
    VarInt::from_usize(0x06).encode(&mut out);
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// A parameter value declared past the maximum closes the QUIC connection with
/// Protocol Violation.
///
/// # What it catches, observed by making the change and running it
///
/// Replacing `recv_control`'s body with `recv.read_control(capture_raw).await?`,
/// so the refusal never reaches `close_for_codec`:
///
/// ```text
/// ---- an_oversized_parameter_value_closes_the_quic_connection stdout ----
///
/// thread 'an_oversized_parameter_value_closes_the_quic_connection' (16764) panicked at crates\moqtap-client\tests\draft14_kvp_value_bound_closes_the_session.rs:
/// the client refused the frame but never closed the connection: Elapsed(())
/// ```
///
/// The client still returns `Err(Kvp(ValueTooLong(65536)))` in that state; the
/// peer just never hears about it and can repeat the frame indefinitely.
#[tokio::test]
async fn an_oversized_parameter_value_closes_the_quic_connection() {
    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft14.quic_alpn()]);

    let peer = tokio::spawn(async move {
        let conn = endpoint.accept().await.expect("accept").await.expect("tls handshake");

        // Draft-14 carries control on a bidirectional stream the client opens.
        // The send half stays raw quinn: the offending frame has to go out
        // exactly as written, and every framing helper here would refuse it.
        let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
        let mut framed_recv = common::frame_uni_recv(recv, DraftVersion::Draft14);
        framed_recv.read_control(false).await.expect("read CLIENT_SETUP");

        let mut setup = Vec::new();
        server_setup().encode(&mut setup).expect("encode SERVER_SETUP");
        send.write_all(&setup).await.expect("write SERVER_SETUP");

        send.write_all(&publish_namespace_with_an_oversized_parameter())
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
                    "Section 1.4.2 answers an oversized value with a Protocol Violation; \
                     the close carried {} instead",
                    u64::from(frame.error_code)
                );
                let text = String::from_utf8_lossy(&frame.reason).to_string();
                assert!(
                    text.contains(&OVERSIZED_VALUE_LEN.to_string()),
                    "the close reason should carry the length that broke the bound; got {text:?}"
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
        .expect_err("a parameter value declared past the maximum must be refused");
    let text = err.to_string();
    assert!(
        text.contains(&OVERSIZED_VALUE_LEN.to_string()),
        "the error should carry the length that broke the bound; got {text:?}"
    );

    tokio::time::timeout(PATIENCE * 3, peer)
        .await
        .expect("peer task hung")
        .expect("peer task panicked");
}

#![cfg(feature = "draft12")]
//! Draft-12 Section 8.2.1.1: "If the Token structure cannot be decoded, the
//! receiver MUST close the Session with Key-Value Formatting error."
//!
//! The AUTHORIZATION TOKEN parameter's value is not opaque bytes. It is a Token:
//! an Alias Type, then whichever of a Token Alias, a Token Type and a Token
//! Value that Alias Type promises. Section 8.2.1.1 calls the Alias Type "an
//! integer defining both the serialization and the processing behavior of the
//! receiver", so a receiver that does not recognise it cannot tell where the
//! token ends, let alone what it authorizes.
//!
//! Section 1.3.2 states the general form of the same rule about every Type:
//! "If a receiver understands a Type, and the following Value or Length/Value
//! does not match the serialization defined by that Type, the receiver MUST
//! terminate the session with error code 'Key-Value Formatting Error'." Every
//! draft from 11 to 19 carries that sentence, and every one of them numbers the
//! code 0x6.
//!
//! # Why this is the one rule in the table with its own code
//!
//! Every other rule draft-12 answers with a close answers with Protocol
//! Violation. This one names a different number, which means a mapping table
//! that routes it correctly and a table that routes it to the general code are
//! distinguishable only on the wire — the codec refuses the frame either way,
//! and the peer is the only party that sees which number arrived. That is what
//! this test observes.
//!
//! # Why draft-12
//!
//! It is where the Token sentence enters: draft-11 defines the structure and
//! leaves it to the general rule, and draft-12 gives it a sentence of its own
//! and keeps it through draft-19. It is also the draft in this group without a
//! rule gate of its own — drafts 11 and 13 hold the two ends of a family of four
//! tables that look identical, which is exactly how they drift apart unnoticed.

mod common;

use std::time::Duration;

use moqtap_client::draft12::connection::{ClientConfig, Connection, TransportType};
use moqtap_codec::draft12::message::{ControlMessage, ServerSetup, SubscribeOk};
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::types::{ContentExists, GroupOrder};
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

/// Session termination code Key-Value Formatting Error, draft-12 Section 3.4.
///
/// Not Protocol Violation (0x3), which is what every other rule this draft
/// answers with a close carries.
const KEY_VALUE_FORMATTING_ERROR: u64 = 0x6;

/// AUTHORIZATION TOKEN, draft-12 Section 8.2.1.1 Parameter Type 0x03.
///
/// Draft-11 numbers the same parameter 0x01, where this draft's setup namespace
/// puts PATH. The number is per draft and per namespace, and the close has to
/// name the one the frame actually carried.
const AUTHORIZATION_TOKEN: u64 = 0x03;

const PATIENCE: Duration = Duration::from_secs(10);

fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).expect("fixture value fits a varint")
}

fn client_config() -> ClientConfig {
    ClientConfig {
        additional_versions: Vec::new(),
        transport: TransportType::Quic,
        skip_cert_verification: true,
        ca_certs: Vec::new(),
        setup_parameters: Vec::new(),
    }
}

fn server_setup() -> ControlMessage {
    ControlMessage::ServerSetup(ServerSetup {
        selected_version: DraftVersion::Draft12.version_varint(),
        parameters: Vec::new(),
    })
}

/// A SUBSCRIBE_OK carrying an AUTHORIZATION TOKEN whose Alias Type is 0x04.
///
/// The draft assigns four: DELETE (0x0), REGISTER (0x1), USE_ALIAS (0x2) and
/// USE_VALUE (0x3). 0x04 is one past the end, and because the Alias Type is what
/// says which fields follow, a reader meeting it has no way to know whether the
/// two bytes after it are an Alias, a Type, or a value.
///
/// The frame is built by this codec's own encoder, so the message framing, the
/// declared Length, the parameter count, the key and the value length are all
/// exactly what it writes. The only thing wrong with the frame is the two bytes
/// inside the token, which is what makes this a test of the rule rather than of
/// the framing around it.
///
/// The token goes in afterwards, and the reason is this rule read from the
/// other side: the encoder refuses to write a Token it could not read back, so
/// the message is built around the shortest well-formed one — USE_ALIAS and an
/// alias — and its two bytes are replaced. The two tokens are the same length,
/// so not even the value's own length moves.
fn subscribe_ok_with_an_unassigned_alias_type() -> Vec<u8> {
    const WELL_FORMED: &[u8] = &[0x02, 0x07];
    const UNASSIGNED_ALIAS_TYPE: &[u8] = &[0x04, 0x01];

    let message = ControlMessage::SubscribeOk(SubscribeOk {
        request_id: varint(0),
        track_alias: varint(4),
        expires: varint(0),
        group_order: GroupOrder::Ascending,
        content_exists: ContentExists::NoLargestLocation,
        largest_location: None,
        parameters: vec![KeyValuePair {
            key: varint(AUTHORIZATION_TOKEN),
            value: KvpValue::Bytes(WELL_FORMED.to_vec()),
        }],
    });

    let mut out = Vec::new();
    message.encode(&mut out).expect("the encoder writes a token it can read back");
    common::with_length_prefixed_value(&out, WELL_FORMED, UNASSIGNED_ALIAS_TYPE)
}

/// A token that cannot be decoded closes the QUIC connection, and with the code
/// this rule names rather than the one every other rule names.
///
/// # What it catches, observed by making the change and running it
///
/// Mapping the variant to Protocol Violation in draft-12's
/// `codec_session_error_code`, which is where twelve of the thirteen rules in
/// that table go and so the arm a copy of a neighbouring draft's table produces:
///
/// ```text
/// ---- a_malformed_authorization_token_closes_the_quic_connection stdout ----
///
/// thread 'a_malformed_authorization_token_closes_the_quic_connection' (65840) panicked at crates\moqtap-client\tests\draft12_malformed_auth_token_closes_the_session.rs:165:17:
/// assertion `left == right` failed: Section 8.2.1.1 answers a Token that cannot be decoded with Key-Value Formatting Error; the close carried 3 instead
/// ```
///
/// Removing the check from the codec instead leaves the session open entirely:
///
/// ```text
/// ---- a_malformed_authorization_token_closes_the_quic_connection stdout ----
///
/// thread 'a_malformed_authorization_token_closes_the_quic_connection' (58284) panicked at crates\moqtap-client\tests\draft12_malformed_auth_token_closes_the_session.rs:186:35:
/// a Token that cannot be decoded must be refused: SubscribeOk(SubscribeOk { request_id: VarInt(0), track_alias: VarInt(4), expires: VarInt(0), group_order: Ascending, content_exists: NoLargestLocation, largest_location: None, parameters: [KeyValuePair { key: VarInt(3), value: Bytes([4, 1]) }] })
/// ```
#[tokio::test]
async fn a_malformed_authorization_token_closes_the_quic_connection() {
    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft12.quic_alpn()]);

    let peer = tokio::spawn(async move {
        let conn = endpoint.accept().await.expect("accept").await.expect("tls handshake");

        // Draft-12 carries control on a bidirectional stream the client opens.
        let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
        let mut framed_recv = common::frame_uni_recv(recv, DraftVersion::Draft12);
        framed_recv.read_control(false).await.expect("read CLIENT_SETUP");

        let mut setup = Vec::new();
        server_setup().encode(&mut setup).expect("encode SERVER_SETUP");
        send.write_all(&setup).await.expect("write SERVER_SETUP");

        send.write_all(&subscribe_ok_with_an_unassigned_alias_type())
            .await
            .expect("write the offending SUBSCRIBE_OK");

        let reason = tokio::time::timeout(PATIENCE, conn.closed())
            .await
            .expect("the client refused the frame but never closed the connection");

        match reason {
            quinn::ConnectionError::ApplicationClosed(frame) => {
                assert_eq!(
                    u64::from(frame.error_code),
                    KEY_VALUE_FORMATTING_ERROR,
                    "Section 8.2.1.1 answers a Token that cannot be decoded with \
                     Key-Value Formatting Error; the close carried {} instead",
                    u64::from(frame.error_code)
                );
                let text = String::from_utf8_lossy(&frame.reason).to_string();
                assert!(
                    text.contains("serialization"),
                    "the close reason should name the rule that was broken; got {text:?}"
                );
            }
            other => panic!("expected an application close, got {other:?}"),
        }
    });

    let mut conn =
        Connection::connect(&addr.to_string(), client_config()).await.expect("client connect");

    let err =
        conn.recv_control().await.expect_err("a Token that cannot be decoded must be refused");
    let text = err.to_string();
    assert!(text.contains("serialization"), "the error should name the rule; got {text:?}");

    tokio::time::timeout(PATIENCE * 3, peer)
        .await
        .expect("peer task hung")
        .expect("peer task panicked");
}

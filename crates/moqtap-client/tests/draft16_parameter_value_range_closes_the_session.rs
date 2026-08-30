#![cfg(feature = "draft16")]
//! Draft-16 Section 9.2.2.4: "The allowed values are Ascending (0x1) or
//! Descending (0x2). If an endpoint receives a value outside this range, it MUST
//! close the session with PROTOCOL_VIOLATION."
//!
//! # Why the close is the thing under test and the refusal is not
//!
//! Draft-16 did not check the value at all, and drafts 17, 18 and 19 checked it
//! and reported `CodecError::InvalidField` — the variant a dozen unrelated
//! malformations share, and the one every draft's table sends to `None`. So the
//! decoder refused the frame and the peer, which is the party that broke the
//! rule, kept an open session and went on sending. A codec test cannot tell
//! those two states apart: the frame is refused either way. Only the wire shows
//! whether the session ended, which is what this observes.
//!
//! # Why Group Order rather than Forward
//!
//! Because it is the value the rule reversed on. Drafts 07 through 14 carry
//! Group Order as a message field and permit 0x0 in a request — "A value of 0x0
//! indicates the original publisher's Group Order SHOULD be used" — so a
//! subscriber with no preference says so by sending zero. From draft-15 the
//! field becomes a parameter, the parameter admits only 0x1 and 0x2, and a
//! subscriber with no preference omits it instead. The byte that means "no
//! preference" on draft-14 ends the session here, and an implementation that
//! carried the field's asymmetry into the parameter would send this frame
//! believing it legal.

mod common;

use std::time::Duration;

use moqtap_client::draft16::connection::{ClientConfig, Connection, TransportType};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::draft16::message::{ControlMessage, ServerSetup, SubscribeOk};
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

/// Session termination code PROTOCOL_VIOLATION, draft-16 Section 13.4.1.
const PROTOCOL_VIOLATION: u64 = 0x3;

/// GROUP_ORDER, draft-16 Section 9.2.2.4, Parameter Type 0x22.
const GROUP_ORDER: u64 = 0x22;

const PATIENCE: Duration = Duration::from_secs(10);

fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).expect("fixture value fits a varint")
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

fn server_setup() -> AnyControlMessage {
    AnyControlMessage::Draft16(ControlMessage::ServerSetup(ServerSetup { parameters: Vec::new() }))
}

/// A SUBSCRIBE_OK carrying GROUP_ORDER with the value 0x0.
///
/// Built by this codec's own encoder, so the framing, the declared Length, the
/// parameter count and the delta-encoded type are all exactly what it writes.
/// The only thing the draft objects to is the one value, which is what makes
/// this a test of the rule and not of the framing around it.
///
/// The value goes in afterwards, and the reason is this rule read from the other
/// side: the encoder refuses to write a value outside the range its type allows,
/// because that is a message the receiver must close the session over. So the
/// message is built around Ascending and the byte is replaced by 0x0. Both are
/// one-byte varints, so nothing else in the frame moves.
fn subscribe_ok_with_group_order_zero() -> Vec<u8> {
    const ASCENDING: u64 = 0x1;
    const PUBLISHERS_CHOICE: u64 = 0x0;

    let message = ControlMessage::SubscribeOk(SubscribeOk {
        request_id: varint(0),
        track_alias: varint(4),
        parameters: vec![KeyValuePair {
            key: varint(GROUP_ORDER),
            value: KvpValue::Varint(varint(ASCENDING)),
        }],
        track_extensions: Vec::new(),
    });
    let mut out = Vec::new();
    message.encode(&mut out).expect("the encoder writes a value inside the range");
    common::with_varint_value(&out, ASCENDING, PUBLISHERS_CHOICE)
}

/// A Group Order outside the range closes the QUIC connection with
/// PROTOCOL_VIOLATION.
///
/// # What it catches, observed by making the change and running it
///
/// Removing `check_parameter_value_ranges` from draft-16's
/// `decode_parameters_in` — the state the codec was in, where nothing read the
/// value at all and the parameter reached the application as ordinary traffic:
///
/// ```text
/// ---- a_group_order_outside_its_range_closes_the_quic_connection stdout ----
///
/// thread 'a_group_order_outside_its_range_closes_the_quic_connection' (74772) panicked at crates\moqtap-client\tests\draft16_parameter_value_range_closes_the_session.rs:158:35:
/// a Group Order outside its range must be refused: SubscribeOk(SubscribeOk { request_id: VarInt(0), track_alias: VarInt(4), parameters: [KeyValuePair { key: VarInt(34), value: Varint(VarInt(0)) }], track_extensions: [] })
/// ```
///
/// Sending `CodecError::ParameterValueOutOfRange` to the `None` arm of
/// draft-16's `codec_session_error_code` instead — which is where drafts 17, 18
/// and 19 effectively had it, reporting the same rule as `InvalidField` — leaves
/// the decoder refusing the frame and the session open:
///
/// ```text
/// thread 'a_group_order_outside_its_range_closes_the_quic_connection' (89880) panicked at crates\moqtap-client\tests\draft16_parameter_value_range_closes_the_session.rs:133:14:
/// the client refused the frame but never closed the connection: Elapsed(())
/// ```
#[tokio::test]
async fn a_group_order_outside_its_range_closes_the_quic_connection() {
    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft16.quic_alpn()]);

    let peer = tokio::spawn(async move {
        let conn = endpoint.accept().await.expect("accept").await.expect("tls handshake");

        let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
        let mut framed_recv = common::frame_uni_recv(recv, DraftVersion::Draft16);
        framed_recv.read_control(false).await.expect("read CLIENT_SETUP");

        let mut setup = Vec::new();
        server_setup().encode(&mut setup).expect("encode SERVER_SETUP");
        send.write_all(&setup).await.expect("write SERVER_SETUP");

        send.write_all(&subscribe_ok_with_group_order_zero())
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
                    "Section 9.2.2.4 answers a Group Order outside its range with \
                     PROTOCOL_VIOLATION; the close carried {} instead",
                    u64::from(frame.error_code)
                );
                let text = String::from_utf8_lossy(&frame.reason).to_string();
                assert!(
                    text.contains("range"),
                    "the close reason should name the rule that was broken; got {text:?}"
                );
            }
            other => panic!("expected an application close, got {other:?}"),
        }
    });

    let mut conn =
        Connection::connect(&addr.to_string(), client_config()).await.expect("client connect");

    let err =
        conn.recv_control().await.expect_err("a Group Order outside its range must be refused");
    let text = err.to_string();
    assert!(text.contains("range"), "the error should name the rule; got {text:?}");

    tokio::time::timeout(PATIENCE * 3, peer)
        .await
        .expect("peer task hung")
        .expect("peer task panicked");
}

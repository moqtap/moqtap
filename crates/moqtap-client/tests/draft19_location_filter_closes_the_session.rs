#![cfg(feature = "draft19")]
//! Draft-19 Section 5.1.2: "An endpoint that receives a filter type other than
//! the above MUST close the session with PROTOCOL_VIOLATION."
//!
//! # Why the rule went quiet without the sentence changing
//!
//! Through draft-14 the Filter Type is a field of SUBSCRIBE, and a decoder reads
//! it whether or not it means to enforce anything: the value decides how many
//! fields follow. Draft-15 moved the Filter Type, the Start Location and the End
//! Group into one length-prefixed parameter, and draft-19 renamed that parameter
//! from SUBSCRIPTION_FILTER to LOCATION_FILTER without touching either its number
//! or its contents. A codec that carries a parameter value as opaque bytes reads
//! none of it, so the rule was enforced on the eight drafts where the value is a
//! field and unread on the five where it is a parameter — and nothing about the
//! drafts said so.
//!
//! # Why the close and not the refusal is under test
//!
//! Because a codec test cannot tell them apart. A frame carrying an unassigned
//! Filter Type is refused whether the refusal reaches the session or not, and the
//! peer that broke the rule only learns about it if the connection ends. The
//! value the eight earlier drafts refuse reported the shared malformed-field
//! variant, which every draft's table sends to the no-close arm, so all thirteen
//! drafts refused the frame and none of them closed.

mod common;

use std::time::Duration;

use moqtap_client::draft19::connection::{ClientConfig, Connection, TransportType};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::draft19::message::{ControlMessage, Setup, Subscribe};
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::subscription_filter::SUBSCRIPTION_FILTER_PARAMETER;
use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

/// Session termination code PROTOCOL_VIOLATION, draft-19 Section 15.11.1.
const PROTOCOL_VIOLATION: u64 = 0x3;
/// The other code this parameter can end a session with, when the value is not a
/// filter at all. Named so the assertion can say which wrong answer it saw.
const KEY_VALUE_FORMATTING_ERROR: u64 = 0x6;

const PATIENCE: Duration = Duration::from_secs(10);

/// A Filter Type this draft does not assign.
///
/// Deliberately above the assigned block rather than zero: 0x0 would also be
/// caught by a decoder that merely required a non-zero value, and this one is
/// only refused by a decoder that holds the field to the four types Section
/// 5.1.2 lists.
const UNASSIGNED_FILTER_TYPE: u8 = 0x07;

fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).expect("fixture value fits a varint")
}

/// A one-field Track Namespace, the smallest every one of these drafts accepts.
fn ns() -> TrackNamespace {
    TrackNamespace(vec![b"live".to_vec()])
}
fn client_config() -> ClientConfig {
    ClientConfig {
        draft: DraftVersion::Draft19,
        transport: TransportType::Quic,
        skip_cert_verification: true,
        ca_certs: Vec::new(),
        setup_parameters: Vec::new(),
    }
}

fn encode_setup() -> Vec<u8> {
    let mut buf = Vec::new();
    AnyControlMessage::Draft19(ControlMessage::Setup(Setup { options: Vec::new() }))
        .encode(&mut buf)
        .expect("encode SETUP");
    buf
}

/// A SUBSCRIBE carrying a LOCATION_FILTER whose Filter Type is unassigned.
///
/// Built by this codec's own encoder, so the framing, the declared Length, the
/// parameter count and the delta-encoded type are exactly what it writes. The
/// parameter's value is a complete, self-consistent filter — one field, and the
/// parameter length matches it — so nothing here is answered by the length rule
/// instead. The only thing the draft objects to is the number.
///
/// A SUBSCRIBE and not a response: Section 10.2.9 lets this parameter appear in
/// "a SUBSCRIBE, PUBLISH_OK or REQUEST_UPDATE (for a subscription) message", and
/// a frame carrying it anywhere else is one the receiver must close the session
/// over for that reason instead, which would answer a different rule than the
/// one under test.
///
/// The number goes in afterwards, and the reason is this rule read from the
/// other side: the encoder refuses to write a filter it could not read back. So
/// the message is written around Largest Object, which is the shortest filter
/// this draft assigns, and its one byte is replaced. Both filters are one byte,
/// so not even the value's own length moves.
fn subscribe_with_an_unassigned_filter_type() -> Vec<u8> {
    /// Largest Object, one field and nothing after it.
    const LARGEST_OBJECT: &[u8] = &[0x02];

    let message = ControlMessage::Subscribe(Subscribe {
        request_id: varint(1),
        track_namespace: ns(),
        track_name: b"video".to_vec(),
        parameters: vec![KeyValuePair {
            key: varint(SUBSCRIPTION_FILTER_PARAMETER),
            value: KvpValue::Bytes(LARGEST_OBJECT.to_vec()),
        }],
    });
    let mut out = Vec::new();
    message.encode(&mut out).expect("the encoder writes a filter it can read back");
    common::with_length_prefixed_value(&out, LARGEST_OBJECT, &[UNASSIGNED_FILTER_TYPE])
}

/// An unassigned Filter Type inside the parameter closes the QUIC connection
/// with PROTOCOL_VIOLATION.
///
/// # What it catches, observed by making the change and running it
///
/// Removing `check_subscription_filters` from draft-19's `decode_parameters` —
/// the state the codec was in, where nothing read the value and the filter
/// reached the application as ordinary parameter bytes:
///
/// ```text
/// ---- an_unassigned_filter_type_closes_the_quic_connection stdout ----
///
/// thread 'an_unassigned_filter_type_closes_the_quic_connection' (92560) panicked at crates\moqtap-client\tests\draft19_location_filter_closes_the_session.rs:
/// an unassigned Filter Type must be refused: Subscribe(Subscribe { request_id: VarInt(1), track_namespace: TrackNamespace([[108, 105, 118, 101]]), track_name: [118, 105, 100, 101, 111], parameters: [KeyValuePair { key: VarInt(33), value: Bytes([7]) }] })
/// ```
///
/// Sending `CodecError::InvalidFilterType` to the no-close arm of draft-19's
/// `codec_session_error_code` instead — which is where the eight drafts that
/// carry the Filter Type as a field effectively had it, reporting the rule under
/// a variant every table ignores:
///
/// ```text
/// thread 'an_unassigned_filter_type_closes_the_quic_connection' (101768) panicked at crates\moqtap-client\tests\draft19_location_filter_closes_the_session.rs:
/// the client refused the frame but never closed the connection: Elapsed(())
/// ```
#[tokio::test]
async fn an_unassigned_filter_type_closes_the_quic_connection() {
    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft19.quic_alpn()]);

    let peer = tokio::spawn(async move {
        let conn = endpoint.accept().await.expect("accept").await.expect("tls handshake");

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
            .write_all(&subscribe_with_an_unassigned_filter_type())
            .await
            .expect("write the offending SUBSCRIBE");

        let reason = tokio::time::timeout(PATIENCE, conn.closed())
            .await
            .expect("the client refused the frame but never closed the connection");

        match reason {
            quinn::ConnectionError::ApplicationClosed(frame) => {
                let code = u64::from(frame.error_code);
                assert_eq!(
                    code, PROTOCOL_VIOLATION,
                    "Section 5.1.2 answers an unassigned Filter Type with \
                     PROTOCOL_VIOLATION; the close carried {code}, and \
                     KEY_VALUE_FORMATTING_ERROR ({KEY_VALUE_FORMATTING_ERROR}) here would \
                     mean the value was reported as a malformed parameter rather than as a \
                     Filter Type"
                );
                let text = String::from_utf8_lossy(&frame.reason).to_string();
                assert!(
                    text.contains("filter type"),
                    "the close reason should name the rule that was broken; got {text:?}"
                );
            }
            other => panic!("expected an application close, got {other:?}"),
        }
    });

    let mut conn =
        Connection::connect(&addr.to_string(), client_config()).await.expect("client connect");

    let err = conn.recv_control().await.expect_err("an unassigned Filter Type must be refused");
    let text = err.to_string();
    assert!(text.contains("filter type"), "the error should name the rule; got {text:?}");

    tokio::time::timeout(PATIENCE * 3, peer)
        .await
        .expect("peer task hung")
        .expect("peer task panicked");
}

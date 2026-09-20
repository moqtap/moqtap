#![cfg(feature = "draft19")]
//! Draft-19 Section 11.4.2: "The Object ID Delta + 1 is added to the previous
//! Object ID in the Subgroup stream if there was one... If the resulting Object
//! ID would be greater than 2^64 - 1, the endpoint MUST close the session with a
//! PROTOCOL_VIOLATION."
//!
//! # Why this rule needed a second path
//!
//! Every other "MUST close the session" rule the client answers arrives on the
//! control stream, where `recv_control` owns both the stream and the connection
//! and can close for itself. This one cannot: it is raised while reading a
//! *subgroup* stream, and `accept_subgroup_stream` hands the caller a
//! `FramedRecvStream` that holds no connection at all. The codec reported the
//! wrap under its own error variant and the connection's mapping table could
//! recognise it, and the session still stayed open, because nothing joined the
//! two. `Connection::close_for_data_stream` is that join, and this test is the
//! only place the whole path is exercised end to end.
//!
//! # Why the peer is raw quinn
//!
//! The offending stream cannot be produced by `SubgroupObjectReader::write_object`,
//! which takes an absolute Object ID and computes the delta itself — no absolute
//! ID it accepts produces a wrapping delta. So the second object is appended by
//! hand, one varint at a time, while the header and the first object come from
//! the codec's own writer. The peer never calls anything in `moqtap-client`, so
//! it cannot agree with the reader under test by construction.

mod common;

use std::time::Duration;

use moqtap_client::draft19::connection::{
    ClientConfig, Connection, ConnectionError, TransportType,
};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::draft19::data_stream::{SubgroupHeader, SubgroupObject, SubgroupObjectReader};
use moqtap_codec::draft19::message::{ControlMessage, Setup};
use moqtap_codec::error::CodecError;
use moqtap_codec::varint::{Moqt18, VarInt};
use moqtap_codec::version::DraftVersion;

/// Session termination code PROTOCOL_VIOLATION, draft-19 Section 15.11.1.
const PROTOCOL_VIOLATION: u64 = 0x3;

const PATIENCE: Duration = Duration::from_secs(10);

/// Subgroup header type: the base subgroup bit (0x10) plus subgroup-ID mode 4
/// for an explicit ID. The PROPERTIES bit is deliberately clear — an object on
/// this stream is a delta, a payload length and a payload, which is the
/// shortest framing that can carry the wrap.
const HEADER_TYPE: u8 = 0x14;

const TRACK_ALIAS: u64 = 42;
const GROUP_ID: u64 = 7;

/// Payload of the conforming object that precedes the wrap. Its arrival is how
/// the test says the stream was read normally right up to the violation.
const FIRST_PAYLOAD: &[u8] = b"in-step";

fn encode_setup() -> Vec<u8> {
    let mut buf = Vec::new();
    AnyControlMessage::Draft19(ControlMessage::Setup(Setup { options: Vec::new() }))
        .encode(&mut buf)
        .expect("encode SETUP");
    buf
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

fn varint(v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    VarInt::from_u64_moqt(v).encode_moqt::<Moqt18>(&mut out);
    out
}

/// A subgroup stream whose second object states an Object ID Delta of
/// 2^64 - 1.
///
/// The first object resolves to Object ID 0, so the second asks for
/// `0 + (2^64 - 1) + 1`, which is exactly one past the largest Object ID the
/// draft allows. Putting the wrap on the *second* object matters: on the first
/// there is no previous Object ID, the delta is the absolute ID, and the same
/// bytes would be refused for being an unrepresentable ID rather than for
/// wrapping.
fn subgroup_stream_bytes() -> Vec<u8> {
    let header = SubgroupHeader {
        header_type: HEADER_TYPE,
        track_alias: VarInt::from_u64_moqt(TRACK_ALIAS),
        group_id: VarInt::from_u64_moqt(GROUP_ID),
        subgroup_id: VarInt::from_u64_moqt(1),
        publisher_priority: Some(128),
    };
    let mut buf = Vec::new();
    header.encode(&mut buf);

    let mut writer = SubgroupObjectReader::new(&header);
    writer
        .write_object(
            &SubgroupObject {
                object_id: VarInt::from_u64_moqt(0),
                extension_headers: Vec::new(),
                payload_length: VarInt::from_u64_moqt(FIRST_PAYLOAD.len() as u64),
                object_status: None,
                payload: FIRST_PAYLOAD.to_vec(),
            },
            &mut buf,
        )
        .expect("encode the conforming object");

    // By hand: the codec's writer cannot be asked for a delta that wraps.
    buf.extend_from_slice(&varint(u64::MAX));
    buf.extend_from_slice(&varint(1));
    buf.push(0xBB);
    buf
}

/// A wrapping Object ID delta on a subgroup stream closes the QUIC connection
/// with PROTOCOL_VIOLATION.
///
/// Three things are asserted and none implies the others. The wrap is reported
/// under its own error variant, so a caller can tell it from the dozen
/// unrelated malformations `InvalidField` covers. `close_for_data_stream`
/// recognises it as fatal and says so. And the *peer* — the endpoint that broke
/// the rule — receives the close, which is the only part of the rule that is
/// about the wire.
///
/// # What it catches, observed by making the change and running it
///
/// Removing `CodecError::ObjectIdOverflow` from draft-19's
/// `codec_session_error_code`, which is the state this rule was in before: the
/// codec reported the wrap, the client refused the object, and the session
/// stayed open.
///
/// ```text
/// ---- a_wrapped_object_id_delta_closes_the_quic_connection stdout ----
///
/// thread 'a_wrapped_object_id_delta_closes_the_quic_connection' panicked at crates\moqtap-client\tests\draft19_object_id_wrap_closes_the_session.rs:
/// the wrap is a rule draft-19 answers with a close, but close_for_data_stream declined to close
/// ```
#[tokio::test]
async fn a_wrapped_object_id_delta_closes_the_quic_connection() {
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

        // Held open for the rest of the session: dropping a quinn send stream
        // sends a FIN, and a control stream must not end while the session is
        // alive.
        let mut our_control = conn.open_uni().await.expect("open_uni");
        our_control.write_all(&encode_setup()).await.expect("write SETUP");

        let mut data = conn.open_uni().await.expect("open data stream");
        data.write_all(&subgroup_stream_bytes()).await.expect("write the subgroup stream");
        data.finish().expect("finish the data stream");

        let reason = tokio::time::timeout(PATIENCE, conn.closed())
            .await
            .expect("the client refused the object but never closed the connection");

        match reason {
            quinn::ConnectionError::ApplicationClosed(frame) => {
                assert_eq!(
                    u64::from(frame.error_code),
                    PROTOCOL_VIOLATION,
                    "Section 11.4.2 answers a wrapped Object ID with PROTOCOL_VIOLATION; \
                     the close carried {} instead",
                    u64::from(frame.error_code)
                );
                let text = String::from_utf8_lossy(&frame.reason).to_string();
                assert!(
                    text.contains("object id"),
                    "the close reason should name the rule that was broken; got {text:?}"
                );
            }
            other => panic!("expected an application close, got {other:?}"),
        }
    });

    let conn =
        Connection::connect(&addr.to_string(), client_config()).await.expect("client connect");

    let (header, mut stream) = tokio::time::timeout(PATIENCE, conn.accept_subgroup_stream())
        .await
        .expect("the peer's data stream never arrived")
        .expect("read the subgroup header");
    assert_eq!(
        header.track_alias(),
        TRACK_ALIAS,
        "the header that came back is not the one the peer sent"
    );

    let first = tokio::time::timeout(PATIENCE, stream.read_subgroup_object())
        .await
        .expect("the first object never arrived")
        .expect("the conforming object must read");
    assert_eq!(first.payload, FIRST_PAYLOAD, "the stream was misread before the violation");

    let err = tokio::time::timeout(PATIENCE, stream.read_subgroup_object())
        .await
        .expect("the second object never arrived")
        .expect_err("a wrapping Object ID delta must be refused");
    assert!(
        matches!(err, ConnectionError::Codec(CodecError::ObjectIdOverflow(0, u64::MAX))),
        "the wrap must be reported under its own variant, not as a generic \
         malformation a session cannot act on; got {err:?}"
    );

    assert!(
        conn.close_for_data_stream(&err),
        "the wrap is a rule draft-19 answers with a close, but close_for_data_stream \
         declined to close"
    );

    tokio::time::timeout(PATIENCE * 3, peer)
        .await
        .expect("peer task hung")
        .expect("peer task panicked");
}

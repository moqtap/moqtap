#![cfg(feature = "draft16")]
//! Draft-16 Section 10.2.1.2: "Any Object with status Normal can have extension
//! headers (Section 2.5). If an endpoint receives extension headers on Objects
//! with status that is not Normal, it MUST close the session with a
//! PROTOCOL_VIOLATION."
//!
//! # Why this draft has a gate of its own
//!
//! Six drafts state this rule, in two vocabularies — 15 and 16 say "extension
//! headers", 17 through 20 say "properties" — and the client carries six
//! separate copies of the check, one per draft module. Copies drift. The rule
//! was raised on draft-19 alone until recently, which is exactly how that drift
//! looks from inside the process: every layer agrees, and nothing notices that
//! four of the five never ask the question.
//!
//! Draft-16 sits between the two shapes the other gates cover. It shares
//! draft-15's vocabulary and its bidirectional control stream, and it shares
//! draft-17's mapping table from a decode failure to a close code — so
//! `close_for_data_stream` here has two arms to get right where draft-15's has
//! one. Neither neighbouring gate would notice if this draft's arm went missing.
//!
//! The peer is raw quinn plus `moqtap-codec`'s own writer, so it never calls the
//! framing helpers under test and cannot agree with them by construction. The
//! codec writes the offending object rather than refusing it, deliberately: the
//! frame is well formed and merely non-conforming, so a codec that could not
//! produce one could not reproduce a capture containing one.

mod common;

use std::time::Duration;

use moqtap_client::draft16::connection::{
    ClientConfig, Connection, ConnectionError, TransportType,
};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::draft16::data_stream::{SubgroupHeader, SubgroupObject, SubgroupObjectReader};
use moqtap_codec::draft16::message::{ControlMessage, ServerSetup};
use moqtap_codec::draft16::types::ObjectStatus;
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

/// Session termination code PROTOCOL_VIOLATION, draft-16 Section 13.4.1.
const PROTOCOL_VIOLATION: u64 = 0x3;

const PATIENCE: Duration = Duration::from_secs(10);

/// Subgroup header type: the base subgroup bit (0x10) plus the extensions bit
/// (0x01). Without the extensions bit the objects on this stream carry no
/// extension block at all and the rule cannot be reached — an object with no
/// extension headers is conforming at every status.
const HEADER_WITH_EXTENSIONS: u8 = 0x11;

const TRACK_ALIAS: u64 = 42;
const GROUP_ID: u64 = 7;

/// The extension block the offending object carries. Opaque to both ends — the
/// reader copies these bytes verbatim — so its only job is to be non-empty and
/// to have a length the assertion can name.
const EXTENSIONS: &[u8] = b"\x01\x02\x03\x04";

const OFFENDING_OBJECT_ID: u64 = 0;
/// Strictly greater than [`OFFENDING_OBJECT_ID`]: object IDs on a subgroup
/// stream are delta-encoded and a delta only runs forward.
const NEXT_OBJECT_ID: u64 = 1;
/// Payload on the object behind the offending one. Its arrival is how the test
/// says the refusal cost the stream nothing.
const NEXT_PAYLOAD: &[u8] = b"still-in-step";

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

/// A subgroup stream carrying the violation and then a conforming object.
///
/// Both are written through `SubgroupObjectReader`, so the delta encoding is the
/// codec's own and not this test's idea of it.
fn subgroup_stream_bytes() -> Vec<u8> {
    let header = SubgroupHeader {
        header_type: HEADER_WITH_EXTENSIONS,
        track_alias: VarInt::from_u64(TRACK_ALIAS).unwrap(),
        group_id: VarInt::from_u64(GROUP_ID).unwrap(),
        subgroup_id: VarInt::from_usize(0),
        publisher_priority: Some(128),
    };
    let mut buf = Vec::new();
    header.encode(&mut buf);

    let mut writer = SubgroupObjectReader::new(&header);
    // Extension headers on End of Group: the combination Section 10.2.1.2
    // forbids. The status is spelled out because the payload is empty; an
    // object carrying bytes would have no status field and would be Normal.
    writer
        .write_object(
            &SubgroupObject {
                object_id: VarInt::from_u64(OFFENDING_OBJECT_ID).unwrap(),
                extension_headers: EXTENSIONS.to_vec(),
                payload_length: VarInt::from_usize(0),
                object_status: Some(ObjectStatus::EndOfGroup),
                payload: Vec::new(),
            },
            &mut buf,
        )
        .expect("the codec writes a non-conforming object rather than refusing it");
    writer
        .write_object(
            &SubgroupObject {
                object_id: VarInt::from_u64(NEXT_OBJECT_ID).unwrap(),
                extension_headers: Vec::new(),
                payload_length: VarInt::from_usize(NEXT_PAYLOAD.len()),
                object_status: None,
                payload: NEXT_PAYLOAD.to_vec(),
            },
            &mut buf,
        )
        .expect("encode the object that follows");
    buf
}

/// Extension headers on a non-Normal status are refused, the stream stays in
/// step, and the caller can turn the refusal into the close the draft requires.
///
/// Three things are asserted and none implies the others. The refusal names the
/// object, its extension length and the status they arrived on, so a log says
/// which object in a subgroup broke the rule. The *next* object still decodes,
/// which is what says the refusal did not desynchronise the delta encoding. And
/// the peer receives a CONNECTION_CLOSE carrying PROTOCOL_VIOLATION, which is
/// the only part of the rule that is about the wire.
///
/// # What it catches, observed by making the change and running it
///
/// Dropping the `ExtensionsOnNonNormalStatus` arm from draft-16's
/// `close_for_data_stream`, so it answers only the codec failures its mapping
/// table names — the state drafts 17 and 18 were in after the Object ID wrap
/// gave them that method:
///
/// ```text
/// ---- extension_headers_on_a_non_normal_status_are_refused_and_close stdout ----
///
/// thread 'extension_headers_on_a_non_normal_status_are_refused_and_close' (42668) panicked at crates\moqtap-client\tests\draft16_extensions_on_non_normal_status.rs:240:5:
/// Section 10.2.1.2 answers this with a close, but close_for_data_stream declined
/// ```
#[tokio::test]
async fn extension_headers_on_a_non_normal_status_are_refused_and_close() {
    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft16.quic_alpn()]);

    let peer = tokio::spawn(async move {
        let conn = endpoint.accept().await.expect("accept").await.expect("tls handshake");

        // Draft-16 carries control on a bidirectional stream the client opens,
        // not on the pair of unidirectional streams drafts 17 and later use.
        let (send, recv) = conn.accept_bi().await.expect("accept_bi");
        let (mut framed_send, mut framed_recv) =
            common::frame_bi(send, recv, DraftVersion::Draft16);
        framed_recv.read_control(false).await.expect("read CLIENT_SETUP");
        framed_send.write_control(&server_setup()).await.expect("write SERVER_SETUP");

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
                    "Section 10.2.1.2 answers extension headers on a non-Normal status \
                     with PROTOCOL_VIOLATION; the close carried {} instead",
                    u64::from(frame.error_code)
                );
                let text = String::from_utf8_lossy(&frame.reason).to_string();
                assert!(
                    text.contains("extension headers"),
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

    let err = tokio::time::timeout(PATIENCE, stream.read_subgroup_object())
        .await
        .expect("the first object never arrived")
        .expect_err("extension headers on End of Group must be refused");
    match &err {
        ConnectionError::ExtensionsOnNonNormalStatus { object_id, extensions_len, status } => {
            assert_eq!(*object_id, OFFENDING_OBJECT_ID, "the refusal names the wrong object");
            assert_eq!(
                *extensions_len,
                EXTENSIONS.len(),
                "the refusal should say how many bytes of extension headers arrived"
            );
            assert_eq!(
                *status,
                ObjectStatus::EndOfGroup,
                "the refusal should name the status the extension headers arrived on"
            );
        }
        other => panic!("expected an extensions-on-non-Normal refusal, got {other:?}"),
    }

    let next = tokio::time::timeout(PATIENCE, stream.read_subgroup_object())
        .await
        .expect("the object behind the refused one never arrived")
        .expect("the object behind the refused one should still decode");
    assert_eq!(
        next.object_id.into_inner(),
        NEXT_OBJECT_ID,
        "the delta encoding lost its place across the refusal"
    );
    assert_eq!(next.payload, NEXT_PAYLOAD, "the object behind the refused one came back wrong");

    assert!(
        conn.close_for_data_stream(&err),
        "Section 10.2.1.2 answers this with a close, but close_for_data_stream declined"
    );

    tokio::time::timeout(PATIENCE * 3, peer)
        .await
        .expect("peer task hung")
        .expect("peer task panicked");
}

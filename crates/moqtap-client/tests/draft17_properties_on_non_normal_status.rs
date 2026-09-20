#![cfg(feature = "draft17")]
//! Draft-17 Section 10.2.1.2: "Any Object with status Normal can have
//! properties (Section 2.5). If an endpoint receives properties on an Object
//! with status that is not Normal, it MUST close the session with a
//! PROTOCOL_VIOLATION."
//!
//! # Why this draft has a gate of its own
//!
//! Six drafts state this rule and the client carries six separate copies of
//! the check, one per draft module. Copies drift, and the drift is invisible
//! from inside a single draft: every layer there agrees with itself. Draft-17 is
//! where the vocabulary changes — 15 and 16 call the block extension headers,
//! 17 through 20 call it properties — so it is the first draft on the later side
//! of a rename that touched the variant name, the error text and the section
//! number all at once. A gate on draft-19 alone would not notice draft-17
//! keeping the extension-headers spelling, or losing the check entirely.
//!
//! The peer is raw quinn plus `moqtap-codec`'s own writer, so it never calls the
//! framing helpers under test and cannot agree with them by construction. The
//! codec writes the offending object rather than refusing it, deliberately: the
//! frame is well formed and merely non-conforming, so a codec that could not
//! produce one could not reproduce a capture containing one.

mod common;

use std::time::Duration;

use moqtap_client::draft17::connection::{
    ClientConfig, Connection, ConnectionError, TransportType,
};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::draft17::data_stream::{SubgroupHeader, SubgroupObject, SubgroupObjectReader};
use moqtap_codec::draft17::message::{ControlMessage, Setup};
use moqtap_codec::draft17::types::ObjectStatus;
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

/// Session termination code PROTOCOL_VIOLATION, draft-17 Section 14.5.1.
const PROTOCOL_VIOLATION: u64 = 0x3;

const PATIENCE: Duration = Duration::from_secs(10);

/// Subgroup header type: the base subgroup bit (0x10), subgroup-ID mode 2 for
/// an explicit ID (0x04), and the properties bit (0x01).
///
/// The properties bit is what puts a properties block on every object of this
/// stream. Without it the objects carry none and the rule cannot be reached at
/// all — an object with no properties is conforming at every status.
const HEADER_WITH_PROPERTIES: u8 = 0x15;

const TRACK_ALIAS: u64 = 42;
const GROUP_ID: u64 = 7;

/// The properties block the offending object carries. Opaque to both ends — the
/// reader copies these bytes verbatim — so its only job is to be non-empty and
/// to have a length the assertion can name.
const PROPERTIES: &[u8] = b"\x01\x02\x03\x04";

const OFFENDING_OBJECT_ID: u64 = 0;
/// Strictly greater than [`OFFENDING_OBJECT_ID`]: object IDs on a subgroup
/// stream are delta-encoded and a delta only runs forward.
const NEXT_OBJECT_ID: u64 = 1;
/// Payload on the object behind the offending one. Its arrival is how the test
/// says the refusal cost the stream nothing.
const NEXT_PAYLOAD: &[u8] = b"still-in-step";

fn client_config() -> ClientConfig {
    ClientConfig {
        draft: DraftVersion::Draft17,
        transport: TransportType::Quic,
        skip_cert_verification: true,
        ca_certs: Vec::new(),
        setup_parameters: Vec::new(),
    }
}

fn encode_setup() -> Vec<u8> {
    let mut buf = Vec::new();
    AnyControlMessage::Draft17(ControlMessage::Setup(Setup { options: Vec::new() }))
        .encode(&mut buf)
        .expect("encode SETUP");
    buf
}

/// A subgroup stream carrying the violation and then a conforming object.
///
/// Both are written through `SubgroupObjectReader`, so the delta encoding is the
/// codec's own and not this test's idea of it.
fn subgroup_stream_bytes() -> Vec<u8> {
    let header = SubgroupHeader {
        header_type: HEADER_WITH_PROPERTIES,
        track_alias: VarInt::from_u64_moqt(TRACK_ALIAS),
        group_id: VarInt::from_u64_moqt(GROUP_ID),
        subgroup_id: VarInt::from_u64_moqt(1),
        publisher_priority: Some(128),
    };
    let mut buf = Vec::new();
    header.encode(&mut buf);

    let mut writer = SubgroupObjectReader::new(&header);
    // Properties on End of Group: the combination Section 10.2.1.2 forbids. The
    // status is spelled out because the payload is empty; an object carrying
    // bytes would have no status field and would be Normal.
    writer
        .write_object(
            &SubgroupObject {
                object_id: VarInt::from_u64_moqt(OFFENDING_OBJECT_ID),
                extension_headers: PROPERTIES.to_vec(),
                payload_length: VarInt::from_u64_moqt(0),
                object_status: Some(ObjectStatus::EndOfGroup),
                payload: Vec::new(),
            },
            &mut buf,
        )
        .expect("the codec writes a non-conforming object rather than refusing it");
    writer
        .write_object(
            &SubgroupObject {
                object_id: VarInt::from_u64_moqt(NEXT_OBJECT_ID),
                extension_headers: Vec::new(),
                payload_length: VarInt::from_u64_moqt(NEXT_PAYLOAD.len() as u64),
                object_status: None,
                payload: NEXT_PAYLOAD.to_vec(),
            },
            &mut buf,
        )
        .expect("encode the object that follows");
    buf
}

/// Properties on a non-Normal status are refused, the stream stays in step, and
/// the caller can turn the refusal into the close the draft requires.
///
/// Three things are asserted and none implies the others. The refusal names the
/// object, its properties length and the status they arrived on, so a log says
/// which object in a subgroup broke the rule. The *next* object still decodes,
/// which is what says the refusal did not desynchronise the delta encoding. And
/// the peer receives a CONNECTION_CLOSE carrying PROTOCOL_VIOLATION, which is
/// the only part of the rule that is about the wire.
///
/// # What it catches, observed by making the change and running it
///
/// Deleting the `properties_permitted` check from draft-17's
/// `FramedRecvStream::read_subgroup_object`, so the object is handed to the
/// caller like any other:
///
/// ```text
/// ---- properties_on_a_non_normal_status_are_refused_and_close stdout ----
///
/// thread 'properties_on_a_non_normal_status_are_refused_and_close' (27452) panicked at crates\moqtap-client\tests\draft17_properties_on_non_normal_status.rs:
/// properties on End of Group must be refused: SubgroupObject { object_id: VarInt(0), extension_headers: [1, 2, 3, 4], payload_length: VarInt(0), object_status: Some(EndOfGroup), payload: [] }
/// ```
#[tokio::test]
async fn properties_on_a_non_normal_status_are_refused_and_close() {
    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft17.quic_alpn()]);

    let peer = tokio::spawn(async move {
        let conn = endpoint.accept().await.expect("accept").await.expect("tls handshake");

        // Draft-17 carries control on a pair of unidirectional streams, not on
        // the bidirectional stream drafts 16 and below use. Read the client's
        // SETUP off its half; one read is enough for a message this small, but
        // loop so a split write cannot flake.
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

        // The peer's own control stream, held open for the rest of the session:
        // dropping a quinn send stream sends a FIN, and a control stream must
        // not end while the session is alive.
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
                    "Section 10.2.1.2 answers properties on a non-Normal status with \
                     PROTOCOL_VIOLATION; the close carried {} instead",
                    u64::from(frame.error_code)
                );
                let text = String::from_utf8_lossy(&frame.reason).to_string();
                assert!(
                    text.contains("properties"),
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
        .expect_err("properties on End of Group must be refused");
    match &err {
        ConnectionError::PropertiesOnNonNormalStatus { object_id, properties_len, status } => {
            assert_eq!(*object_id, OFFENDING_OBJECT_ID, "the refusal names the wrong object");
            assert_eq!(
                *properties_len,
                PROPERTIES.len(),
                "the refusal should say how many bytes of properties arrived"
            );
            assert_eq!(
                *status,
                ObjectStatus::EndOfGroup,
                "the refusal should name the status the properties arrived on"
            );
        }
        other => panic!("expected a properties-on-non-Normal refusal, got {other:?}"),
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

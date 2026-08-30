#![cfg(feature = "draft19")]
//! Draft-19 Section 11.2.1.2: "Any Object with status Normal can have
//! properties (Section 2.5). If an endpoint receives properties on an Object
//! with status that is not Normal, it MUST close the session with a
//! PROTOCOL_VIOLATION."
//!
//! # Why a loopback test and not a unit test
//!
//! The rule is about *receiving*, and every layer that could hold an opinion
//! about it already agrees in isolation. `SubgroupObject::properties_permitted`
//! answers the question from a struct, and the codec has its own tests for that.
//! What none of them exercise is the path a real object takes: bytes off a QUIC
//! stream, through the framed reader's buffering and its delta-decoded object
//! IDs, into the check. The client is the only layer holding both the decoded
//! object and the stream it came from, so it is the only one that can refuse it,
//! and the refusal is worth nothing if the object never reaches it.
//!
//! The peer here is raw quinn plus `moqtap-codec`'s own writer. It never calls
//! the framing helpers in `moqtap-client`, so it cannot agree with the reader
//! under test by construction.
//!
//! # Why the codec writes the offending object rather than refusing it
//!
//! `SubgroupObjectReader::write_object` emits properties beside a non-Normal
//! status without complaint, and that is deliberate: the frame is well formed
//! and merely non-conforming, so a codec that could not produce one could not
//! reproduce a capture containing one. That is what lets this peer build the
//! object out of the same codec the client decodes with.

mod common;

use std::time::Duration;

use moqtap_client::draft19::connection::{
    ClientConfig, Connection, ConnectionError, TransportType,
};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::draft19::data_stream::{SubgroupHeader, SubgroupObject, SubgroupObjectReader};
use moqtap_codec::draft19::message::{ControlMessage, Setup};
use moqtap_codec::draft19::types::ObjectStatus;
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

const PATIENCE: Duration = Duration::from_secs(10);

/// Subgroup header type byte: the base subgroup bit (0x10), subgroup-ID mode 2
/// for an explicit ID (0x04), and the PROPERTIES bit (0x01).
///
/// The PROPERTIES bit is what puts a properties block on every object of this
/// stream. Without it the objects carry none and the rule under test cannot be
/// reached at all — an object with no properties is conforming at any status.
const HEADER_WITH_PROPERTIES: u8 = 0x15;

/// Track alias and group ID on the peer's data stream. Arbitrary; they only
/// have to come back out of the client unchanged so the header can be
/// recognised as the one that went in.
const TRACK_ALIAS: u64 = 42;
/// See [`TRACK_ALIAS`].
const GROUP_ID: u64 = 7;

/// The properties block the offending object carries. Opaque to both ends —
/// the reader copies these bytes verbatim — so its only job is to be non-empty
/// and to have a length the assertion can name.
const PROPERTIES: &[u8] = b"\x01\x02\x03\x04";

/// The Object ID of the offending object, and of the conforming one that
/// follows it.
const OFFENDING_OBJECT_ID: u64 = 0;
/// See [`OFFENDING_OBJECT_ID`]. Strictly greater, since object IDs on a
/// subgroup stream are delta-encoded and a delta only runs forward.
const NEXT_OBJECT_ID: u64 = 1;

/// The payload on that following object. Its arrival is how the test says the
/// reader stayed in step with the wire.
const NEXT_PAYLOAD: &[u8] = b"still-in-step";

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

/// A subgroup stream carrying two objects: one with properties on an End of
/// Group status, and one ordinary payload object after it.
///
/// Both are written through `SubgroupObjectReader`, so the delta encoding of
/// the object IDs is the codec's own and not this test's idea of it.
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
    // Properties on End of Group: the combination Section 11.2.1.2 forbids.
    // The status is spelled out because the payload is empty; an object that
    // carried bytes would have no status field at all and would be Normal.
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
    // A conforming object behind it. Empty properties are permitted at every
    // status, and this one is Normal anyway.
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

/// An object carrying properties on a non-Normal status is refused, and the
/// object behind it still reads.
///
/// Two things are asserted and neither implies the other.
///
/// The refusal names the object: its ID, how many bytes of properties it
/// carried and the status they arrived on. An implementation that returned a
/// bare "malformed object" would satisfy a test that only checked for `Err`,
/// and would leave whoever reads the log unable to say which object in a
/// subgroup broke the rule.
///
/// The *next* object still decodes. Draft-19's subgroup objects are
/// delta-encoded, so a reader that refused the object before consuming it, or
/// consumed the wrong number of bytes doing so, leaves every following object
/// on the stream unreadable or silently misnumbered. Reading `NEXT_PAYLOAD`
/// back at [`NEXT_OBJECT_ID`] is what says the refusal cost the stream nothing.
///
/// # What it catches
///
/// Deleting the `properties_permitted` check from draft-19's
/// `FramedRecvStream::read_subgroup_object`, so the object is handed to the
/// caller like any other:
///
/// ```text
/// ---- an_object_with_properties_on_a_non_normal_status_is_refused stdout ----
///
/// thread 'an_object_with_properties_on_a_non_normal_status_is_refused' (66196) panicked at crates\moqtap-client\tests\draft19_properties_on_non_normal_status.rs:227:10:
/// properties on End of Group must be refused: SubgroupObject { object_id: VarInt(0), extension_headers: [1, 2, 3, 4], payload_length: VarInt(0), object_status: Some(EndOfGroup), payload: [] }
/// ```
#[tokio::test]
async fn an_object_with_properties_on_a_non_normal_status_is_refused() {
    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft19.quic_alpn()]);

    let peer = tokio::spawn(async move {
        let conn = endpoint.accept().await.expect("accept").await.expect("tls handshake");

        // Read the client's SETUP off its unidirectional control stream. One
        // read is enough for a message this small, but loop so a split write
        // cannot flake.
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

        // The data stream, opened after the setup exchange so it arrives as an
        // ordinary unidirectional stream rather than one `connect` has to defer.
        let mut data = conn.open_uni().await.expect("open data stream");
        data.write_all(&subgroup_stream_bytes()).await.expect("write the subgroup stream");
        data.finish().expect("finish the data stream");

        // Held until the client is done reading.
        let _ = conn.closed().await;
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
    match err {
        ConnectionError::PropertiesOnNonNormalStatus { object_id, properties_len, status } => {
            assert_eq!(object_id, OFFENDING_OBJECT_ID, "the refusal names the wrong object");
            assert_eq!(
                properties_len,
                PROPERTIES.len(),
                "the refusal should say how many bytes of properties arrived"
            );
            assert_eq!(
                status,
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

    conn.close(0, b"done");
    let _ = tokio::time::timeout(PATIENCE, peer).await;
}

/// Session termination code PROTOCOL_VIOLATION, draft-19 Section 15.11.1.
const PROTOCOL_VIOLATION: u64 = 0x3;

/// The refusal above closes the QUIC connection when the caller asks it to.
///
/// The test above proves the client *detects* the violation. That is not the
/// rule: Section 11.2.1.2 says "it MUST close the session with a
/// PROTOCOL_VIOLATION", which is a statement about the wire, and until now
/// nothing in this crate could carry it there. The violation is raised on a
/// data stream, and `accept_subgroup_stream` hands the caller a
/// `FramedRecvStream` holding no connection, so the reader that finds the
/// violation is not the object that can act on it.
///
/// `close_for_data_stream` is where the caller joins the two, and this asserts
/// on what the *peer* — the endpoint that broke the rule — receives.
///
/// # What it catches, observed by making the change and running it
///
/// Dropping the `PropertiesOnNonNormalStatus` arm from
/// `close_for_data_stream`, leaving it matching only `ConnectionError::Codec`
/// as it did when it was added for the Object ID wrap:
///
/// ```text
/// ---- the_refusal_closes_the_quic_connection stdout ----
///
/// thread 'the_refusal_closes_the_quic_connection' panicked at crates\moqtap-client\tests\draft19_properties_on_non_normal_status.rs:350:5:
/// Section 11.2.1.2 answers this with a close, but close_for_data_stream declined
/// ```
#[tokio::test]
async fn the_refusal_closes_the_quic_connection() {
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
                    "Section 11.2.1.2 answers properties on a non-Normal status with \
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

    let (_header, mut stream) = tokio::time::timeout(PATIENCE, conn.accept_subgroup_stream())
        .await
        .expect("the peer's data stream never arrived")
        .expect("read the subgroup header");

    let err = tokio::time::timeout(PATIENCE, stream.read_subgroup_object())
        .await
        .expect("the first object never arrived")
        .expect_err("properties on End of Group must be refused");

    assert!(
        conn.close_for_data_stream(&err),
        "Section 11.2.1.2 answers this with a close, but close_for_data_stream declined"
    );

    tokio::time::timeout(PATIENCE * 3, peer)
        .await
        .expect("peer task hung")
        .expect("peer task panicked");
}

#![cfg(feature = "draft11")]
//! Draft-11 Section 9.1.1.2: "Any Object may have extension headers except
//! those with Object Status 'Object Does Not Exist'. If an endpoint receives a
//! non-existent Object containing extension headers it MUST close the session
//! with a Protocol Violation."
//!
//! Drafts 11 through 14 state this narrow form and no other draft states it.
//! Draft-15 replaced it with the general one — extensions only beside Normal —
//! which is a different rule with a different subject.
//!
//! # Two defects meet on this stream
//!
//! The codec reported the violation as `CodecError::InvalidField`, which a dozen
//! unrelated malformations share. A caller could see that something was wrong
//! and could not tell *what*, so the rule could not be routed to a close without
//! closing sessions the draft says nothing about. It has its own variant now.
//!
//! And the client could not reach the rule on a subgroup stream at all.
//! Whether an object carries an extension block is a property of the stream's
//! Type; `read_subgroup_object` did not remember the Type and always decoded as
//! though there were none. On a stream whose Type announces extensions that is
//! not a conservative default — the Extension Headers Length is read as the
//! Object Payload Length, and every object on the stream comes back wrong rather
//! than being refused. Fixing the variant alone would have left this rule
//! unreachable here.
//!
//! Neither defect is visible from the other end. A codec test decodes the object
//! directly and never touches the framed reader; a framing test reads a stream
//! whose Type announces no extensions and never reaches the check.
//!
//! # Why the object is built by hand
//!
//! The codec applies the rule in both directions, so its writer refuses to
//! produce the object. Only hand-written bytes reach the decode-side check.
//!
//! # Why the stream does not stay in step afterwards
//!
//! It cannot, and that is the draft's answer rather than a shortfall: the
//! refusal comes from the decoder, before the object's bytes are consumed, and
//! the session is required to end. There is no "next object" to read. The gates
//! that assert a stream stays in step are the ones on drafts 15 and later, where
//! the reader accepts the object and this crate refuses it afterwards.

mod common;

use std::time::Duration;

use moqtap_client::draft11::connection::{
    ClientConfig, Connection, ConnectionError, TransportType,
};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::draft11::data_stream::{StreamType, SubgroupHeader};
use moqtap_codec::draft11::message::{ControlMessage, ServerSetup};
use moqtap_codec::error::CodecError;
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

/// Session termination code `Protocol Violation`, draft-11 Section 3.4.
const PROTOCOL_VIOLATION: u64 = 0x3;

const PATIENCE: Duration = Duration::from_secs(10);

/// Object Status 0x1, Object Does Not Exist. The rule names this status and no
/// other, so an object carrying End of Group beside the same extension block
/// stays lawful on this draft.
const OBJECT_DOES_NOT_EXIST: u64 = 0x1;

/// The extension block the offending object carries. Opaque to both ends, so
/// its only job is to be non-empty and to have a length the assertion can name.
const EXTENSIONS: &[u8] = b"\x01\x02\x03\x04";

const TRACK_ALIAS: u64 = 42;
const GROUP_ID: u64 = 7;
const OBJECT_ID: u64 = 0;

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
    AnyControlMessage::Draft11(ControlMessage::ServerSetup(ServerSetup {
        selected_version: DraftVersion::Draft11.version_varint(),
        parameters: Vec::new(),
    }))
}

/// A subgroup stream whose Type announces extensions, carrying one object that
/// pairs an extension block with Object Does Not Exist.
///
/// The stream header goes through the codec's own writer — it is conforming and
/// there is no reason to hand-build it. Choosing `SubgroupExplicitExt` is the
/// point of the test: on a Type without the extensions bit the objects carry no
/// block at all and the rule has nothing to bind.
///
/// The object is laid out as Object ID, Extension Headers Length, those headers,
/// Object Payload Length, and — only because that length is zero — the Object
/// Status.
fn subgroup_stream_bytes() -> Vec<u8> {
    let header = SubgroupHeader {
        stream_type: StreamType::SubgroupExplicitExt,
        track_alias: VarInt::from_u64(TRACK_ALIAS).unwrap(),
        group_id: VarInt::from_u64(GROUP_ID).unwrap(),
        subgroup_id: VarInt::from_usize(0),
        publisher_priority: 128,
    };
    let mut buf = Vec::new();
    header.encode_stream(&mut buf);

    VarInt::from_u64(OBJECT_ID).unwrap().encode(&mut buf);
    VarInt::from_usize(EXTENSIONS.len()).encode(&mut buf);
    buf.extend_from_slice(EXTENSIONS);
    VarInt::from_usize(0).encode(&mut buf); // empty payload, so a status follows
    VarInt::from_u64(OBJECT_DOES_NOT_EXIST).unwrap().encode(&mut buf);
    buf
}

/// A non-existent object carrying extension headers is refused by name, and the
/// caller can turn the refusal into the close the draft requires.
///
/// Two things are asserted and neither implies the other. The refusal is
/// `ExtensionsOnNonExistentObject` and names the length of the block that
/// arrived — an `InvalidField` would satisfy a test that only checked for `Err`
/// and would leave the caller unable to act. And the peer receives a
/// CONNECTION_CLOSE carrying Protocol Violation, which is the only part of the
/// rule that is about the wire.
///
/// # What it catches, observed by making the change and running it
///
/// Reverting `read_subgroup_object` to `ObjectHeader::decode`, which is
/// `decode_with_extensions(false, ..)` — the shape it had before it remembered
/// the stream Type. The four extension bytes are then read as the payload
/// length and what follows, and the object that comes back is not the one on the
/// wire:
///
/// ```text
/// ---- a_non_existent_object_with_extensions_is_refused_and_closes stdout ----
///
/// thread 'a_non_existent_object_with_extensions_is_refused_and_closes' (43812) panicked at crates\moqtap-client\tests\draft11_extensions_on_a_non_existent_object.rs:211:10:
/// a non-existent object carrying extension headers must be refused: SubgroupObject { header: ObjectHeader { object_id: VarInt(0), extension_headers_length: VarInt(0), extensions: [], payload_length: VarInt(4), object_status: Normal }, payload: [1, 2, 3, 4] }
/// ```
///
/// Note what came back rather than that something did: the four extension bytes
/// as a payload, on an object reported Normal. Nothing is refused, and nothing
/// downstream has any way to know.
///
/// And with that fix kept but the codec still reporting the rule as
/// `CodecError::InvalidField`:
///
/// ```text
/// ---- a_non_existent_object_with_extensions_is_refused_and_closes stdout ----
///
/// thread 'a_non_existent_object_with_extensions_is_refused_and_closes' (24272) panicked at crates\moqtap-client\tests\draft11_extensions_on_a_non_existent_object.rs:220:18:
/// expected an extensions-on-a-non-existent-object refusal, got Codec(InvalidField)
/// ```
#[tokio::test]
async fn a_non_existent_object_with_extensions_is_refused_and_closes() {
    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft11.quic_alpn()]);

    let peer = tokio::spawn(async move {
        let conn = endpoint.accept().await.expect("accept").await.expect("tls handshake");

        // Draft-11 carries control on a bidirectional stream the client opens.
        let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
        let mut framed_recv = common::frame_uni_recv(recv, DraftVersion::Draft11);
        framed_recv.read_control(false).await.expect("read CLIENT_SETUP");

        let mut setup = Vec::new();
        server_setup().encode(&mut setup).expect("encode SERVER_SETUP");
        send.write_all(&setup).await.expect("write SERVER_SETUP");

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
                    "Section 9.1.1.2 answers this with a Protocol Violation; the close \
                     carried {} instead",
                    u64::from(frame.error_code)
                );
                let text = String::from_utf8_lossy(&frame.reason).to_string();
                assert!(
                    text.contains("does not exist"),
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
        .expect("the object never arrived")
        .expect_err("a non-existent object carrying extension headers must be refused");
    match &err {
        ConnectionError::Codec(CodecError::ExtensionsOnNonExistentObject(len)) => {
            assert_eq!(
                *len,
                EXTENSIONS.len(),
                "the refusal should say how many bytes of extension headers arrived"
            );
        }
        other => panic!("expected an extensions-on-a-non-existent-object refusal, got {other:?}"),
    }

    assert!(
        conn.close_for_data_stream(&err),
        "Section 9.1.1.2 answers this with a close, but close_for_data_stream declined"
    );

    tokio::time::timeout(PATIENCE * 3, peer)
        .await
        .expect("peer task hung")
        .expect("peer task panicked");
}

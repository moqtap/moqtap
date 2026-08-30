#![cfg(feature = "draft09")]
//! Draft-09 Section 8.1.1.1, on Object Status 0x5: "An object with this status
//! that has a Group ID less than or equal to any other Group ID, or an Object ID
//! other than zero, is a protocol error, and the receiver MUST terminate the
//! session."
//!
//! # Why a data-stream gate and not another control-stream one
//!
//! Every other rule drafts 08 through 10 answer with a close arrives on the
//! control stream, where `recv_control` can close for itself. This one arrives
//! on a subgroup or fetch stream, and a data stream cannot: `accept_subgroup_stream`
//! hands the caller a `FramedRecvStream` holding no connection, so the reader
//! that finds the violation is not the object that can act on it. The two paths
//! share a mapping table but reach it through different code, and a table wired
//! only to `recv_control` leaves this rule detected and never carried to the
//! wire. That is precisely the state drafts 18 and 19 were in for the Object ID
//! wrap: the mapping entry was there and inert.
//!
//! Only the Object ID half of the sentence is gated here. The Group ID half
//! compares against the largest group produced on the track, which no reader of
//! a single object header can know.
//!
//! # Why the object is built by hand
//!
//! The codec applies this rule on both sides, so its writer refuses to produce
//! the object. Only hand-written bytes reach the decode-side check — and a codec
//! that could produce one on demand would be a codec that could emit a frame it
//! is required to close a session over.

mod common;

use std::time::Duration;

use moqtap_client::draft09::connection::{
    ClientConfig, Connection, ConnectionError, TransportType,
};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::draft09::data_stream::SubgroupHeader;
use moqtap_codec::draft09::message::{ControlMessage, ServerSetup};
use moqtap_codec::error::CodecError;
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

/// Session termination code `Protocol Violation`, draft-09 Section 3.5. The
/// sentence calls the condition "a protocol error" and requires the session to
/// end; this is the code the registry gives that.
const PROTOCOL_VIOLATION: u64 = 0x3;

const PATIENCE: Duration = Duration::from_secs(10);

/// Object Status 0x5, End of Track, draft-09 Section 8.1.1.1.
const END_OF_TRACK: u64 = 0x5;

/// The Object ID the offending object carries. Anything but zero breaks the
/// rule; a value well clear of zero means an off-by-one in either direction
/// cannot make this pass for the wrong reason.
const OFFENDING_OBJECT_ID: u64 = 7;

const TRACK_ALIAS: u64 = 42;
const GROUP_ID: u64 = 3;

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
    AnyControlMessage::Draft09(ControlMessage::ServerSetup(ServerSetup {
        selected_version: DraftVersion::Draft09.version_varint(),
        parameters: Vec::new(),
    }))
}

/// A subgroup stream whose first object claims End of Track at a non-zero
/// Object ID.
///
/// The stream header goes through the codec's own writer — it is conforming and
/// there is no reason to hand-build it. The object does not: draft-09 lays one
/// out as Object ID, an extension-headers length, those headers, a payload
/// length, and — only when that length is zero — the Object Status.
fn subgroup_stream_bytes() -> Vec<u8> {
    let header = SubgroupHeader {
        track_alias: VarInt::from_u64(TRACK_ALIAS).unwrap(),
        group_id: VarInt::from_u64(GROUP_ID).unwrap(),
        subgroup_id: VarInt::from_usize(0),
        publisher_priority: 128,
    };
    let mut buf = Vec::new();
    header.encode_stream(&mut buf);

    VarInt::from_u64(OFFENDING_OBJECT_ID).unwrap().encode(&mut buf);
    VarInt::from_usize(0).encode(&mut buf); // no extension headers
    VarInt::from_usize(0).encode(&mut buf); // empty payload, so a status follows
    VarInt::from_u64(END_OF_TRACK).unwrap().encode(&mut buf);
    buf
}

/// An end-of-track object at a non-zero Object ID is refused, and the caller can
/// turn the refusal into the close the draft requires.
///
/// Two things are asserted and neither implies the other. The refusal names the
/// Object ID it saw, so a log says which object on the stream broke the rule
/// rather than that some object did. And the peer receives a CONNECTION_CLOSE —
/// the only part of "the receiver MUST terminate the session" that is about the
/// wire, and the part this draft had no way to reach.
///
/// # What it catches, observed by making the change and running it
///
/// Deleting `close_for_data_stream` from draft-09's connection, leaving
/// `close_for_codec` — which only `recv_control` reaches — as the sole route to
/// a close:
///
/// ```text
/// error[E0599]: no method named `close_for_data_stream` found for struct `moqtap_client::draft09::connection::Connection` in the current scope
///    --> crates\moqtap-client\tests\draft09_end_of_track_object_id_closes_the_session.rs:202:14
///     |
/// 202 |         conn.close_for_data_stream(&err),
///     |              ^^^^^^^^^^^^^^^^^^^^^
/// ```
///
/// With the method kept but its `Codec` arm dropped, so it compiles and declines:
///
/// ```text
/// ---- an_end_of_track_object_at_a_non_zero_id_closes_the_connection stdout ----
///
/// thread 'an_end_of_track_object_at_a_non_zero_id_closes_the_connection' (51516) panicked at crates\moqtap-client\tests\draft09_end_of_track_object_id_closes_the_session.rs:201:5:
/// Section 8.1.1.1 answers this with a close, but close_for_data_stream declined
/// ```
#[tokio::test]
async fn an_end_of_track_object_at_a_non_zero_id_closes_the_connection() {
    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft09.quic_alpn()]);

    let peer = tokio::spawn(async move {
        let conn = endpoint.accept().await.expect("accept").await.expect("tls handshake");

        // Draft-09 carries control on a bidirectional stream the client opens.
        let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
        let mut framed_recv = common::frame_uni_recv(recv, DraftVersion::Draft09);
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
                    "Section 8.1.1.1 calls this a protocol error; the close carried {} instead",
                    u64::from(frame.error_code)
                );
                let text = String::from_utf8_lossy(&frame.reason).to_string();
                assert!(
                    text.contains("end of track"),
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
        .expect_err("an end-of-track object at a non-zero Object ID must be refused");
    match &err {
        ConnectionError::Codec(CodecError::EndOfTrackObjectId(id)) => {
            assert_eq!(
                *id, OFFENDING_OBJECT_ID,
                "the refusal should name the Object ID it saw, not merely that one was wrong"
            );
        }
        other => panic!("expected an end-of-track refusal, got {other:?}"),
    }

    assert!(
        conn.close_for_data_stream(&err),
        "Section 8.1.1.1 answers this with a close, but close_for_data_stream declined"
    );

    tokio::time::timeout(PATIENCE * 3, peer)
        .await
        .expect("peer task hung")
        .expect("peer task panicked");
}

#![cfg(feature = "draft07")]
//! Draft-07 Section 7: "An endpoint that receives an unknown stream type MUST
//! close the session."
//!
//! # Why the rule needs a variant of its own
//!
//! Answered with `CodecError::InvalidField`, which a dozen unrelated
//! malformations share, it would reach no mapping table that could route it
//! without closing sessions the draft says nothing about. A rule that cannot be
//! expressed looks exactly like a rule that does not exist, which is why this
//! one answers `CodecError::UnknownStreamType` instead.
//!
//! Every draft from 07 to 20 states the rule, in one of two phrasings. This one
//! names streams alone because draft-07 numbers its datagrams in the very same
//! table; drafts 08 through 16 split the table in two and say "an unknown stream
//! or datagram type"; drafts 17 through 20 give each table a sentence of its
//! own. The stream-only sentence is in five drafts and the combined one in
//! nine, so a search for either phrasing alone misses the rest.
//!
//! # Why a data-stream gate and not another control-stream one
//!
//! The rest of draft-07's rules arrive on the control stream, where
//! `recv_control` closes for itself. This one is the first varint on a
//! unidirectional stream, and `accept_subgroup_stream` hands the caller a
//! `FramedRecvStream` holding no connection — so the reader that finds the
//! violation is not the object that can act on it. `close_for_data_stream` is
//! the join between the two.
//!
//! # Why the type is 0x02
//!
//! Draft-07's Table 5 assigns three values — 0x01 OBJECT_DATAGRAM, 0x04
//! STREAM_HEADER_SUBGROUP and 0x05 FETCH_HEADER — in one number space shared by
//! streams and datagrams. 0x02 is a hole among assigned neighbours rather than a
//! number past the end of everything, so a reader that merely range-checked
//! would take it. 0x01 would not do: this draft assigns it, and a stream
//! carrying it is refused under a different rule that does not end the
//! session.

mod common;

use std::time::Duration;

use moqtap_client::draft07::connection::{
    ClientConfig, Connection, ConnectionError, TransportType,
};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::draft07::message::{ControlMessage, ServerSetup};
use moqtap_codec::error::CodecError;
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

/// Session termination code `Protocol Violation`, draft-07 Section 3.5. Section
/// 7 names no code, so the rule takes the one this draft's other unnamed rules
/// take.
const PROTOCOL_VIOLATION: u64 = 0x3;

const PATIENCE: Duration = Duration::from_secs(10);

/// A stream type draft-07 does not assign.
const UNASSIGNED_STREAM_TYPE: u64 = 0x02;

/// The ROLE setup parameter, which only this draft has and which it requires of
/// both endpoints, in both directions, before a session is usable.
fn role() -> KeyValuePair {
    let mut value = Vec::new();
    VarInt::from_usize(3).encode(&mut value); // PubSub
    KeyValuePair { key: VarInt::from_usize(0x00), value: KvpValue::Bytes(value) }
}

fn client_config() -> ClientConfig {
    ClientConfig {
        additional_versions: Vec::new(),
        transport: TransportType::Quic,
        skip_cert_verification: true,
        ca_certs: Vec::new(),
        setup_parameters: vec![role()],
    }
}

fn server_setup() -> AnyControlMessage {
    AnyControlMessage::Draft07(ControlMessage::ServerSetup(ServerSetup {
        selected_version: DraftVersion::Draft07.version_varint(),
        parameters: vec![role()],
    }))
}

/// A unidirectional stream announcing an unassigned type, with plausible header
/// bytes behind it.
///
/// The bytes are there so a reader that accepted the type would get somewhere:
/// a stream carrying nothing but the type would be refused for running out of
/// input, and would pass this test without the rule ever being reached.
fn stream_with_an_unassigned_type() -> Vec<u8> {
    let mut buf = Vec::new();
    VarInt::from_u64(UNASSIGNED_STREAM_TYPE).expect("fits a varint").encode(&mut buf);
    buf.extend_from_slice(&[0x2a, 0x03, 0x00, 0x80]);
    buf
}

/// A stream announcing a type this draft does not assign is refused, and the
/// caller can turn the refusal into the close the draft requires.
///
/// Two things are asserted and neither implies the other. The refusal names the
/// type it saw, so a log says which value arrived rather than that some value
/// was wrong. And the peer receives a CONNECTION_CLOSE, which is the part of
/// "MUST close the session" that is about the wire and the part only something
/// holding the other end can observe.
///
/// # What it catches, observed by making each change and running it
///
/// Making the decoder answer `CodecError::InvalidField` instead of the rule's
/// own variant. It compiles, and
/// `close_for_data_stream` declines, because `InvalidField` is not a rule:
///
/// ```text
/// ---- an_unassigned_stream_type_closes_the_connection stdout ----
///
/// thread 'an_unassigned_stream_type_closes_the_connection' (24648) panicked at crates\moqtap-client\tests\draft07_unknown_stream_type_closes_the_session.rs:
/// expected an unknown-stream-type refusal, got Codec(InvalidField)
/// ```
///
/// Deleting `close_for_data_stream` from draft-07's connection, leaving
/// `close_for_codec` — which only `recv_control` reaches — as the sole route to
/// a close:
///
/// ```text
/// ---- an_unassigned_stream_type_closes_the_connection stdout ----
///
/// thread 'an_unassigned_stream_type_closes_the_connection' (30040) panicked at crates\moqtap-client\tests\draft07_unknown_stream_type_closes_the_session.rs:
/// Section 7 answers this with a close, but close_for_data_stream declined
/// ```
#[tokio::test]
async fn an_unassigned_stream_type_closes_the_connection() {
    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft07.quic_alpn()]);

    let peer = tokio::spawn(async move {
        let conn = endpoint.accept().await.expect("accept").await.expect("tls handshake");

        // Draft-07 carries control on a bidirectional stream the client opens.
        let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
        let mut framed_recv = common::frame_uni_recv(recv, DraftVersion::Draft07);
        framed_recv.read_control(false).await.expect("read CLIENT_SETUP");

        let mut setup = Vec::new();
        server_setup().encode(&mut setup).expect("encode SERVER_SETUP");
        send.write_all(&setup).await.expect("write SERVER_SETUP");

        let mut data = conn.open_uni().await.expect("open data stream");
        data.write_all(&stream_with_an_unassigned_type()).await.expect("write the data stream");
        data.finish().expect("finish the data stream");

        let reason = tokio::time::timeout(PATIENCE, conn.closed())
            .await
            .expect("the client refused the stream but never closed the connection");

        match reason {
            quinn::ConnectionError::ApplicationClosed(frame) => {
                assert_eq!(
                    u64::from(frame.error_code),
                    PROTOCOL_VIOLATION,
                    "Section 7 requires the session to end; the close carried {} instead",
                    u64::from(frame.error_code)
                );
                let text = String::from_utf8_lossy(&frame.reason).to_string();
                assert!(
                    text.contains("stream type"),
                    "the close reason should name the rule that was broken; got {text:?}"
                );
            }
            other => panic!("expected an application close, got {other:?}"),
        }
    });

    let conn =
        Connection::connect(&addr.to_string(), client_config()).await.expect("client connect");

    // `FramedRecvStream` is not `Debug`, so the success side cannot be unwrapped
    // into a panic message. Matching says the same thing and names what arrived.
    let err = match tokio::time::timeout(PATIENCE, conn.accept_subgroup_stream())
        .await
        .expect("the peer's data stream never arrived")
    {
        Ok((header, _)) => {
            panic!("a stream announcing an unassigned type must be refused, got header {header:?}")
        }
        Err(e) => e,
    };
    match &err {
        ConnectionError::Codec(CodecError::UnknownStreamType(raw)) => {
            assert_eq!(
                *raw, UNASSIGNED_STREAM_TYPE,
                "the refusal should name the type it saw, not merely that one was wrong"
            );
        }
        other => panic!("expected an unknown-stream-type refusal, got {other:?}"),
    }

    assert!(
        conn.close_for_data_stream(&err),
        "Section 7 answers this with a close, but close_for_data_stream declined"
    );

    tokio::time::timeout(PATIENCE * 3, peer)
        .await
        .expect("peer task hung")
        .expect("peer task panicked");
}

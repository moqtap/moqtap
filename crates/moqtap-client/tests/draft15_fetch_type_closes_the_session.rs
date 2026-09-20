#![cfg(feature = "draft15")]
//! Draft-15 Section 9.16: "An endpoint that receives a Fetch Type other than
//! 0x1, 0x2 or 0x3 MUST close the session with a PROTOCOL_VIOLATION."
//!
//! # Why a draft-14 sentence needed a gate five drafts later
//!
//! Drafts 11, 12 and 13 write the same rule as "A Fetch Type other than 0x1,
//! 0x2 or 0x3 MUST be treated as an error", which names no code and no
//! consequence — and those three are where it starts, because the Fetch Type is
//! draft-11's own addition and drafts 07 through 10 have no such field to hold
//! a wrong value. Draft-14 is where it became a close, in a rendering that
//! reads "MUST be close the session with a PROTOCOL_VIOLATION", and drafts 15
//! through 19 keep the rule with the stray word gone. Every one of the nine
//! drafts that has the field detected the value and reported
//! `CodecError::InvalidField` — the variant a dozen unrelated malformations
//! share and every table sends to the no-close arm — so the six drafts that
//! require the session to end behaved exactly like the three that do not.
//!
//! # Why the message is a FETCH sent at a subscriber
//!
//! A FETCH travels from subscriber to publisher, so a well-behaved server never
//! sends one here. That is the point: a session table exists for the peer that
//! is not well behaved, and the rule is stated of an endpoint receiving the
//! value rather than of the role it arrives in. What is under test is the
//! decoder and the table, not who may legitimately send a FETCH.
//!
//! # Why one byte of an otherwise legal frame
//!
//! The frame is written by this codec's own encoder as a standalone FETCH, and
//! exactly one byte is replaced afterwards. Everything else — the framing, the
//! declared Length, the range, the parameter count — is what the codec itself
//! writes, so nothing but the Fetch Type can be what the draft objects to.

mod common;

use std::time::Duration;

use moqtap_client::draft15::connection::{ClientConfig, Connection, TransportType};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::draft15::message::{ControlMessage, Fetch, FetchPayload, FetchType, ServerSetup};
use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

/// Session termination code PROTOCOL_VIOLATION, draft-15 Section 13.3.1.
const PROTOCOL_VIOLATION: u64 = 0x3;

const PATIENCE: Duration = Duration::from_secs(10);

/// A Fetch Type no draft assigns. Above the assigned block rather than zero, so
/// a decoder that merely required a non-zero value would still accept it.
const UNASSIGNED_FETCH_TYPE: u8 = 0x07;

fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).expect("fixture value fits a varint")
}

fn client_config() -> ClientConfig {
    ClientConfig {
        draft: DraftVersion::Draft15,
        transport: TransportType::Quic,
        skip_cert_verification: true,
        ca_certs: Vec::new(),
        setup_parameters: Vec::new(),
    }
}

/// A standalone FETCH with its Fetch Type replaced.
///
/// Type (1 byte, 0x16), Length (2 bytes) and Request ID (1 byte) precede it, and
/// the value that is there beforehand is asserted so that a framing change
/// cannot move this onto some other field and leave it passing.
fn fetch_with_an_unassigned_type() -> Vec<u8> {
    let message = ControlMessage::Fetch(Fetch {
        request_id: varint(1),
        fetch_type: FetchType::Standalone,
        fetch_payload: FetchPayload::Standalone {
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            start_group: varint(1),
            start_object: varint(0),
            end_group: varint(2),
            end_object: varint(0),
        },
        parameters: Vec::new(),
    });
    let mut frame = Vec::new();
    message.encode(&mut frame).expect("a standalone fetch is legal on draft-15");
    assert_eq!(
        frame[4],
        FetchType::Standalone as u8,
        "the Fetch Type should be the fifth byte; the frame reads {frame:?}"
    );
    frame[4] = UNASSIGNED_FETCH_TYPE;
    frame
}

/// An unassigned Fetch Type closes the QUIC connection with PROTOCOL_VIOLATION.
///
/// # What it catches, observed by making the change and running it
///
/// Sending `CodecError::InvalidFetchType` to the no-close arm of draft-15's
/// `codec_session_error_code` — where the rule effectively was, reported under
/// the shared malformed-field variant, on all twelve drafts that have the field:
///
/// ```text
/// ---- an_unassigned_fetch_type_closes_the_quic_connection stdout ----
///
/// thread 'an_unassigned_fetch_type_closes_the_quic_connection' (43892) panicked at crates\moqtap-client\tests\draft15_fetch_type_closes_the_session.rs:
/// the client refused the frame but never closed the connection: Elapsed(())
/// ```
#[tokio::test]
async fn an_unassigned_fetch_type_closes_the_quic_connection() {
    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft15.quic_alpn()]);

    let offending = fetch_with_an_unassigned_type();

    let peer = tokio::spawn(async move {
        let conn = endpoint.accept().await.expect("accept").await.expect("tls handshake");

        let (mut send, recv) = conn.accept_bi().await.expect("accept_bi");
        let mut framed_recv = common::frame_uni_recv(recv, DraftVersion::Draft15);
        framed_recv.read_control(false).await.expect("read CLIENT_SETUP");

        let mut setup = Vec::new();
        AnyControlMessage::Draft15(ControlMessage::ServerSetup(ServerSetup {
            parameters: Vec::new(),
        }))
        .encode(&mut setup)
        .expect("encode SERVER_SETUP");
        send.write_all(&setup).await.expect("write SERVER_SETUP");
        send.write_all(&offending).await.expect("write the offending FETCH");

        let reason = tokio::time::timeout(PATIENCE, conn.closed())
            .await
            .expect("the client refused the frame but never closed the connection");

        match reason {
            quinn::ConnectionError::ApplicationClosed(frame) => {
                let code = u64::from(frame.error_code);
                assert_eq!(
                    code, PROTOCOL_VIOLATION,
                    "Section 9.16 answers an unassigned Fetch Type with \
                     PROTOCOL_VIOLATION; the close carried {code}"
                );
                let text = String::from_utf8_lossy(&frame.reason).to_string();
                assert!(
                    text.contains("fetch type"),
                    "the close reason should name the rule that was broken; got {text:?}"
                );
            }
            other => panic!("expected an application close, got {other:?}"),
        }
    });

    let mut conn =
        Connection::connect(&addr.to_string(), client_config()).await.expect("client connect");

    let err = conn.recv_control().await.expect_err("an unassigned Fetch Type must be refused");
    let text = err.to_string();
    assert!(text.contains("fetch type"), "the error should name the rule; got {text:?}");

    tokio::time::timeout(PATIENCE * 3, peer)
        .await
        .expect("peer task hung")
        .expect("peer task panicked");
}

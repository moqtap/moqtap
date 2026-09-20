#![cfg(feature = "draft19")]
//! When draft-19 says a violation MUST close the session, the client closes it
//! on the wire — not just in its own state machine.
//!
//! # Why a loopback test and not a unit test
//!
//! The endpoint holds all the parts on its own. `EndpointError::session_error_code`
//! returns `Some(ProtocolViolation)` for exactly the errors the draft answers
//! with a close, and the endpoint moves its own session state to Closed as it
//! raises one. A unit test that asserts "this is fatal" is satisfied by those
//! two facts alone, and stays green against a connection layer that drops the
//! error on the floor and leaves the QUIC connection open.
//!
//! That gap is invisible from inside the process. The local endpoint refuses to
//! start new requests either way; what differs is what the *peer* sees, and the
//! peer is the one that broke the rule. "MUST close the session with a
//! PROTOCOL_VIOLATION" is a statement about the wire, so only something holding
//! the other end of a real connection can check it. This test is that peer: it
//! completes a draft-19 setup exchange over real QUIC, commits the violation,
//! and then asserts on the CONNECTION_CLOSE it receives.
//!
//! # The violation used
//!
//! REQUEST_UPDATE on the control stream. Draft-19 Section 10.9 states the rule
//! as two permitted cases and closes over everything else: "The sender of a
//! request (SUBSCRIBE, PUBLISH, FETCH, PUBLISH_NAMESPACE, SUBSCRIBE_NAMESPACE,
//! SUBSCRIBE_TRACKS) can later send a REQUEST_UPDATE on the same bidi stream as
//! the request to modify it. A subscriber can also send REQUEST_UPDATE to
//! modify parameters of a subscription established with PUBLISH." and "An
//! endpoint that receives a REQUEST_UPDATE other than in the two cases above
//! MUST close the session with a PROTOCOL_VIOLATION." One on the control stream
//! is in neither case, and it is reachable with a single message and no prior
//! request state.
//!
//! A misplaced NAMESPACE would not do. Table 5's Stream column says where each
//! message is sent and attaches no consequence to a peer that sends one
//! elsewhere, so closing over that would be this crate's model of the protocol
//! rather than draft-19's. What this test is *for* — that a close the draft does
//! require reaches the wire and is not merely recorded in this endpoint's own
//! state — needs a rule the draft states in a sentence that can be quoted, and
//! Section 10.9 is one.

mod common;

use std::time::Duration;

use moqtap_client::draft19::connection::{ClientConfig, Connection, TransportType};
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::draft19::message::{ControlMessage, RequestUpdate, Setup};
use moqtap_codec::version::DraftVersion;

/// Session termination code PROTOCOL_VIOLATION, draft-19 Section 15.11.1.
const PROTOCOL_VIOLATION: u64 = 0x3;

const PATIENCE: Duration = Duration::from_secs(10);

fn encode(msg: ControlMessage) -> Vec<u8> {
    let mut buf = Vec::new();
    AnyControlMessage::Draft19(msg).encode(&mut buf).expect("encode");
    buf
}

/// A REQUEST_UPDATE arriving on the control stream closes the QUIC connection
/// with PROTOCOL_VIOLATION.
///
/// # What it catches
///
/// Propagating the endpoint's error out of `recv_and_dispatch` with `?`
/// instead of routing it through `close_if_session_fatal` fails this test with:
///
/// ```text
/// ---- a_control_stream_violation_closes_the_quic_connection stdout ----
/// thread '...' panicked at crates\moqtap-client\tests\draft19_session_close_on_the_wire.rs:
/// the client reported the violation but never closed the connection: Elapsed(())
/// ```
///
/// The client still returns the error and still refuses new requests; the peer
/// just never hears about it.
#[tokio::test]
async fn a_control_stream_violation_closes_the_quic_connection() {
    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft19.quic_alpn()]);

    let peer = tokio::spawn(async move {
        let conn = endpoint.accept().await.expect("accept").await.expect("tls handshake");

        // Read the client's SETUP off its unidirectional control stream.
        let mut client_control = conn.accept_uni().await.expect("accept_uni");
        let mut seen = Vec::new();
        let mut chunk = [0u8; 1024];
        // SETUP is the first message on the stream; one read is enough for a
        // message this small, but loop so a split write cannot flake.
        while seen.len() < 3 {
            match client_control.read(&mut chunk).await.expect("read SETUP") {
                Some(n) => seen.extend_from_slice(&chunk[..n]),
                None => break,
            }
        }
        assert!(!seen.is_empty(), "the client sent no SETUP");

        // Answer with our own SETUP, then commit the violation on the same
        // stream: a REQUEST_UPDATE, which Section 10.9 permits only on the
        // request's own bidi stream and closes the session over anywhere else.
        let mut our_control = conn.open_uni().await.expect("open_uni");
        our_control
            .write_all(&encode(ControlMessage::Setup(Setup { options: Vec::new() })))
            .await
            .expect("write SETUP");
        our_control
            .write_all(&encode(ControlMessage::RequestUpdate(RequestUpdate {
                request_id: moqtap_codec::varint::VarInt::from_usize(0),
                parameters: Vec::new(),
            })))
            .await
            .expect("write REQUEST_UPDATE");

        // The close is the observable. Waiting on it is the whole test.
        let reason = tokio::time::timeout(PATIENCE, conn.closed())
            .await
            .expect("the client reported the violation but never closed the connection");

        match reason {
            quinn::ConnectionError::ApplicationClosed(frame) => {
                assert_eq!(
                    u64::from(frame.error_code),
                    PROTOCOL_VIOLATION,
                    "draft-19 answers a message on the wrong stream with PROTOCOL_VIOLATION; \
                     the close carried {} instead",
                    u64::from(frame.error_code)
                );
                // The reason phrase should name what happened rather than
                // repeating the code, so an operator reading a packet capture
                // can tell which rule was broken.
                let text = String::from_utf8_lossy(&frame.reason).to_string();
                assert!(
                    text.contains("REQUEST_UPDATE"),
                    "the close reason should name the offending message; got {text:?}"
                );
            }
            other => panic!("expected an application close, got {other:?}"),
        }
    });

    let config = ClientConfig {
        draft: DraftVersion::Draft19,
        transport: TransportType::Quic,
        skip_cert_verification: true,
        ca_certs: Vec::new(),
        setup_parameters: Vec::new(),
    };
    let mut conn = Connection::connect(&addr.to_string(), config).await.expect("client connect");

    // Reading the REQUEST_UPDATE is what raises the violation. The error is
    // expected; the close it triggers is what the peer above asserts on.
    let err = conn
        .recv_and_dispatch()
        .await
        .expect_err("a REQUEST_UPDATE on the control stream must be refused");
    let text = err.to_string();
    assert!(
        text.contains("REQUEST_UPDATE"),
        "the error should name the offending message; got {text:?}"
    );

    // Longer than the peer's own wait, so that when the close never arrives it
    // is the peer's specific message that fails the test and not this one.
    tokio::time::timeout(PATIENCE * 3, peer)
        .await
        .expect("peer task hung")
        .expect("peer task panicked");
}

/// A control message the *decoder* refuses closes the QUIC connection too.
///
/// The test above proves the path from an `EndpointError` the draft calls fatal
/// to a CONNECTION_CLOSE. This one proves the other half: the bounds the decoder
/// enforces are stated in the draft with the same "MUST close the session"
/// consequence, and a decoder that stops at refusing the frame leaves the peer
/// free to go on sending.
///
/// The violation used is a GOAWAY declaring a New Session URI of 9,000 bytes.
/// Draft-19 Section 10.4: "The maximum length of the New Session URI is 8,192
/// bytes. If an endpoint receives a length exceeding the maximum, it MUST close
/// the session with a PROTOCOL_VIOLATION." The frame is built by hand because
/// the encoder refuses to write one — which is the point: the two directions
/// agree, and only a hand-made frame can reach the decode-side check.
///
/// # What it catches
///
/// Replacing `recv_control`'s body with `recv.read_control(capture_raw).await?`,
/// so the refusal never reaches `close_for_codec`, fails this test with:
///
/// ```text
/// ---- a_decoder_bound_violation_closes_the_quic_connection stdout ----
///
/// thread 'a_decoder_bound_violation_closes_the_quic_connection' (57204) panicked at crates\moqtap-client\tests\draft19_session_close_on_the_wire.rs:
/// the client refused the frame but never closed the connection: Elapsed(())
/// ```
///
/// The client still returns `Err(GoAwayUriTooLong)` in that state; the peer just
/// never hears about it and can repeat the frame indefinitely.
#[tokio::test]
async fn a_decoder_bound_violation_closes_the_quic_connection() {
    use moqtap_codec::varint::{Moqt18, VarInt};

    common::init_crypto();
    let (endpoint, addr) = common::spawn_server(&[DraftVersion::Draft19.quic_alpn()]);

    /// GOAWAY (0x10) with a New Session URI of `uri_len` bytes and a zero
    /// timeout, framed as draft-19 Section 10 Figure 3 describes.
    fn oversized_goaway(uri_len: usize) -> Vec<u8> {
        let mut body = Vec::new();
        VarInt::from_u64_moqt(uri_len as u64).encode_moqt::<Moqt18>(&mut body);
        body.extend(std::iter::repeat_n(b'x', uri_len));
        body.push(0x00);

        let mut out = Vec::new();
        VarInt::from_u64_moqt(0x10).encode_moqt::<Moqt18>(&mut out);
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

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
        our_control
            .write_all(&encode(ControlMessage::Setup(Setup { options: Vec::new() })))
            .await
            .expect("write SETUP");
        our_control.write_all(&oversized_goaway(9_000)).await.expect("write GOAWAY");

        let reason = tokio::time::timeout(PATIENCE, conn.closed())
            .await
            .expect("the client refused the frame but never closed the connection");

        match reason {
            quinn::ConnectionError::ApplicationClosed(frame) => {
                assert_eq!(
                    u64::from(frame.error_code),
                    PROTOCOL_VIOLATION,
                    "Section 10.4 answers an oversized New Session URI with \
                     PROTOCOL_VIOLATION; the close carried {} instead",
                    u64::from(frame.error_code)
                );
                let text = String::from_utf8_lossy(&frame.reason).to_string();
                assert!(
                    text.contains("GOAWAY"),
                    "the close reason should name the bound that was broken; got {text:?}"
                );
            }
            other => panic!("expected an application close, got {other:?}"),
        }
    });

    let config = ClientConfig {
        draft: DraftVersion::Draft19,
        transport: TransportType::Quic,
        skip_cert_verification: true,
        ca_certs: Vec::new(),
        setup_parameters: Vec::new(),
    };
    let mut conn = Connection::connect(&addr.to_string(), config).await.expect("client connect");

    let err =
        conn.recv_and_dispatch().await.expect_err("a 9,000-byte New Session URI must be refused");
    let text = err.to_string();
    assert!(text.contains("GOAWAY"), "the error should name the bound; got {text:?}");

    tokio::time::timeout(PATIENCE * 3, peer)
        .await
        .expect("peer task hung")
        .expect("peer task panicked");
}

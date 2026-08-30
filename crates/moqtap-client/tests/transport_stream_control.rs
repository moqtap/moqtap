//! Abnormal stream teardown through the transport wrapper.
//!
//! Drives `SendStream::reset`, `RecvStream::stop` and
//! `SendStream::set_priority` over a real quinn loopback and asserts the
//! peer's application error code survives the round trip as a typed
//! [`TransportError`] rather than being flattened into a message or
//! replaced by a default.
//!
//! The distinction these tests protect is reset-vs-FIN: a stream that was
//! abandoned must never look like one that ended cleanly.

mod common;

use std::time::Duration;

use moqtap_client::transport::{RecvStream, SendStream, TransportError};

const RESET_CODE: u64 = 0x10;
const STOP_CODE: u64 = 0x05;

/// Establish a loopback connection and return `(server_conn, client_conn)`.
async fn loopback() -> (quinn::Connection, quinn::Connection) {
    common::init_crypto();

    let (server_ep, server_addr) = common::spawn_server(&[b"test"]);
    let accept = tokio::spawn(async move {
        let incoming = server_ep.accept().await.expect("accept");
        incoming.await.expect("server handshake")
    });

    let client_ep = common::client_endpoint(&[b"test"]);
    let client_conn = client_ep
        .connect(server_addr, "localhost")
        .expect("connect")
        .await
        .expect("client handshake");

    let server_conn = accept.await.expect("accept task");
    (server_conn, client_conn)
}

// ============================================================
// SendStream::reset
// ============================================================

#[tokio::test]
async fn reset_surfaces_peer_code_as_stream_reset() {
    let (server_conn, client_conn) = loopback().await;

    let mut send = SendStream::Quic(server_conn.open_uni().await.expect("open_uni"));
    send.write_all(b"partial subgroup").await.expect("write");
    send.reset(RESET_CODE).expect("reset");

    let mut recv = RecvStream::Quic(client_conn.accept_uni().await.expect("accept_uni"));
    let mut buf = [0u8; 1024];

    // The reset may arrive after the already-written bytes, so read until
    // the stream errors rather than assuming the first read fails.
    let err = loop {
        match recv.read(&mut buf).await {
            Ok(Some(_)) => continue,
            Ok(None) => panic!("expected a reset, got a clean FIN"),
            Err(e) => break e,
        }
    };

    match err {
        TransportError::StreamReset(code) => assert_eq!(code, RESET_CODE),
        other => panic!("expected StreamReset({RESET_CODE}), got {other:?}"),
    }
}

#[tokio::test]
async fn finish_still_reads_as_clean_end_of_stream() {
    let (server_conn, client_conn) = loopback().await;

    let mut send = SendStream::Quic(server_conn.open_uni().await.expect("open_uni"));
    send.write_all(b"whole subgroup").await.expect("write");
    send.finish().expect("finish");

    let mut recv = RecvStream::Quic(client_conn.accept_uni().await.expect("accept_uni"));
    let mut buf = [0u8; 1024];
    let mut total = 0usize;

    loop {
        match recv.read(&mut buf).await {
            Ok(Some(n)) => total += n,
            Ok(None) => break,
            Err(e) => panic!("expected a clean FIN, got {e:?}"),
        }
    }

    assert_eq!(total, b"whole subgroup".len());
}

// ============================================================
// RecvStream::stop
// ============================================================

#[tokio::test]
async fn stop_surfaces_peer_code_as_stopped() {
    let (server_conn, client_conn) = loopback().await;

    let mut send = SendStream::Quic(server_conn.open_uni().await.expect("open_uni"));
    send.write_all(b"unwanted").await.expect("write");

    let mut recv = RecvStream::Quic(client_conn.accept_uni().await.expect("accept_uni"));
    let mut buf = [0u8; 1024];
    recv.read(&mut buf).await.expect("read");
    recv.stop(STOP_CODE).expect("stop");

    // STOP_SENDING is noticed on the next write, which may take a round
    // trip to arrive — keep writing until the stream fails.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let err = loop {
        assert!(tokio::time::Instant::now() < deadline, "writes never failed after STOP_SENDING");
        match send.write_all(b"more").await {
            Ok(()) => tokio::time::sleep(Duration::from_millis(10)).await,
            Err(e) => break e,
        }
    };

    match err {
        TransportError::Stopped(code) => assert_eq!(code, STOP_CODE),
        other => panic!("expected Stopped({STOP_CODE}), got {other:?}"),
    }
}

// ============================================================
// SendStream::set_priority
// ============================================================

/// Read the priority back out of quinn. Asserting only that
/// `set_priority` returned `Ok(())` would pass against a body of
/// `Ok(())` that never reaches the transport at all.
fn priority_of(send: &SendStream) -> i32 {
    match send {
        SendStream::Quic(s) => s.priority().expect("priority on a live stream"),
        #[cfg(feature = "webtransport")]
        _ => panic!("these tests only drive the QUIC arm"),
    }
}

#[tokio::test]
async fn set_priority_succeeds_on_a_live_stream() {
    let (server_conn, _client_conn) = loopback().await;

    let send = SendStream::Quic(server_conn.open_uni().await.expect("open_uni"));
    assert_eq!(priority_of(&send), 0, "every stream starts at priority 0");

    send.set_priority(7).expect("set_priority on a live stream");
    assert_eq!(priority_of(&send), 7, "the value must reach the transport, not just return Ok");
}

#[tokio::test]
async fn set_priority_applies_to_a_stream_with_pending_data() {
    let (server_conn, _client_conn) = loopback().await;

    // The realistic call order: the shaper reprioritises a subgroup that
    // already has bytes buffered.
    let mut send = SendStream::Quic(server_conn.open_uni().await.expect("open_uni"));
    send.write_all(b"buffered").await.expect("write");

    send.set_priority(-1).expect("lower priority");
    assert_eq!(priority_of(&send), -1, "negative priorities must survive the wrapper");

    send.set_priority(3).expect("raise priority");
    assert_eq!(priority_of(&send), 3, "the last write wins");
}

// ============================================================
// Error-code range
// ============================================================

/// The exact variant matters: `propagate_reset` in moqtap-proxy discards
/// the result with `let _ =`, so the only way a caller can tell "I passed
/// a bad code" from "the stream was already gone" is the variant. Pin it.
#[tokio::test]
async fn reset_rejects_a_code_outside_the_varint_range() {
    let (server_conn, _client_conn) = loopback().await;

    let mut send = SendStream::Quic(server_conn.open_uni().await.expect("open_uni"));
    match send.reset(u64::MAX) {
        Err(TransportError::Write(msg)) => {
            assert!(msg.contains("varint"), "the message should name the cause, got {msg:?}");
        }
        other => panic!("expected Write(..varint..) for an unencodable code, got {other:?}"),
    }

    // The rejected call must not have torn the stream down.
    send.write_all(b"still usable").await.expect("stream must survive a rejected code");
    send.finish().expect("finish");
}

#[tokio::test]
async fn stop_rejects_a_code_outside_the_varint_range() {
    let (server_conn, client_conn) = loopback().await;

    let mut send = SendStream::Quic(server_conn.open_uni().await.expect("open_uni"));
    send.write_all(b"payload").await.expect("write");

    let mut recv = RecvStream::Quic(client_conn.accept_uni().await.expect("accept_uni"));
    match recv.stop(u64::MAX) {
        Err(TransportError::Write(msg)) => {
            assert!(msg.contains("varint"), "the message should name the cause, got {msg:?}");
        }
        other => panic!("expected Write(..varint..) for an unencodable code, got {other:?}"),
    }

    // Validation happens before the stream is touched, so it stays
    // readable — the WebTransport arm relies on the same ordering to
    // avoid consuming its inner stream on a rejected code.
    let mut buf = [0u8; 64];
    let n = recv.read(&mut buf).await.expect("stream must survive a rejected code");
    assert_eq!(n, Some(b"payload".len()));
}

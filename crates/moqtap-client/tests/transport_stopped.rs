//! `SendStream::stopped()` over a real quinn loopback.
//!
//! The gap these tests close: `write_all` only reports `STOP_SENDING`
//! when there is something to write, so an idle forwarder never learns
//! that its peer walked away. `stopped()` is the watcher for that case,
//! and its value depends entirely on *which* of the four outcomes it
//! reports and *when* — so each test pins one of them:
//!
//! - the peer's code survives as a typed [`TransportError::Stopped`],
//!   with no write in flight,
//! - a finished-and-acked stream is `Ok(())`, never an error,
//! - a live stream keeps the future pending, so a `select!` branch built
//!   on it does not fire spuriously.
//!
//! All three drive the QUIC arm. The WebTransport arm reaches the same
//! quinn future through `WtSendStream::quic_stream`, and is untested
//! here because nothing in this crate stands up a live WebTransport
//! session. That arm is therefore unproven here: nothing below fails if
//! the WebTransport path stops reaching the quinn future.

mod common;

use std::time::Duration;

use moqtap_client::transport::{RecvStream, SendStream, TransportError};

const STOP_CODE: u64 = 0x2a;

/// How long a resolution is allowed to take before the test calls it a
/// hang. Generous on purpose: these are lower bounds on liveness, and a
/// loaded machine may only make the wait longer, never shorter.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// The window `stopped()` must stay pending for on a live stream. Load
/// can only delay a spurious resolution, so a longer window would make
/// the test slower without making it stricter.
const PENDING_WINDOW: Duration = Duration::from_millis(500);

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
// The peer stopped us
// ============================================================

/// The whole point of the method: an *idle* sender learns the peer's
/// `STOP_SENDING` code. The test writes exactly one chunk to make the
/// stream visible to the peer and then never writes again — so nothing
/// but `stopped()` can produce the code, and a `write_all`-only
/// implementation reports nothing at all.
///
/// The future is handed to `tokio::spawn`, which also pins the
/// `Send + 'static` half of the signature: a watcher that borrowed
/// `send` could not be spawned, and would not fit in the `select!` this
/// exists for.
#[tokio::test]
async fn stopped_reports_the_peer_code() {
    let (server_conn, client_conn) = loopback().await;

    let mut send = SendStream::Quic(server_conn.open_uni().await.expect("open_uni"));
    send.write_all(b"first chunk").await.expect("write");

    // Started before the peer stops, and never written to again.
    let watcher = tokio::spawn(send.stopped());

    let mut recv = RecvStream::Quic(client_conn.accept_uni().await.expect("accept_uni"));
    let mut buf = [0u8; 1024];
    recv.read(&mut buf).await.expect("read");
    recv.stop(STOP_CODE).expect("stop");

    let outcome = tokio::time::timeout(RESOLVE_TIMEOUT, watcher)
        .await
        .expect("stopped() must resolve once the peer sends STOP_SENDING")
        .expect("watcher task");

    match outcome {
        Err(TransportError::Stopped(code)) => assert_eq!(code, STOP_CODE),
        other => panic!("expected Err(Stopped({STOP_CODE})), got {other:?}"),
    }

    drop(client_conn);
}

// ============================================================
// We finished and the peer acked
// ============================================================

/// A clean end must not look like a failure. `Ok(None)` from quinn is
/// "the send state is gone", which is the *normal* end of a forwarded
/// stream — mapping it to an error would make every completed stream
/// report a teardown reason it does not have.
#[tokio::test]
async fn stopped_on_a_finished_stream_is_ok() {
    let (server_conn, client_conn) = loopback().await;

    let mut send = SendStream::Quic(server_conn.open_uni().await.expect("open_uni"));
    send.write_all(b"whole subgroup").await.expect("write");
    send.finish().expect("finish");

    // Read to the FIN so the peer acknowledges every byte; without this
    // quinn keeps the send state and the future stays pending.
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

    let outcome = tokio::time::timeout(RESOLVE_TIMEOUT, send.stopped())
        .await
        .expect("stopped() must resolve once the peer has acked a finished stream");

    assert!(
        outcome.is_ok(),
        "a finished, fully acked stream is not an error condition, got {outcome:?}"
    );

    drop(client_conn);
}

// ============================================================
// Nothing happened
// ============================================================

/// A watcher that resolves on a healthy stream is worse than no watcher:
/// as a `select!` branch it would tear down every live forwarding loop
/// the moment it was armed. The stream here is open, written to, read
/// from, and neither finished nor stopped — so the only correct
/// behaviour is to stay pending.
///
/// `recv` is deliberately kept alive to the end of the test: dropping a
/// `RecvStream` sends `STOP_SENDING` with a hard-coded 0, which would
/// resolve the watcher and turn this into a green test of the wrong
/// thing.
#[tokio::test]
async fn stopped_stays_pending_on_a_live_stream() {
    let (server_conn, client_conn) = loopback().await;

    let mut send = SendStream::Quic(server_conn.open_uni().await.expect("open_uni"));
    send.write_all(b"still flowing").await.expect("write");

    let mut recv = RecvStream::Quic(client_conn.accept_uni().await.expect("accept_uni"));
    let mut buf = [0u8; 1024];
    recv.read(&mut buf).await.expect("read");

    let elapsed = tokio::time::timeout(PENDING_WINDOW, send.stopped()).await;

    assert!(
        elapsed.is_err(),
        "stopped() resolved on a stream that was never stopped, finished or lost: {elapsed:?}"
    );

    // Keep both halves and the connection alive past the assertion.
    drop((recv, send, client_conn));
}

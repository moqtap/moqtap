//! End-to-end abnormal stream teardown through the proxy.
//!
//! Same client ↔ proxy ↔ upstream topology as `proxy_forward`, but the
//! streams end badly instead of cleanly. What's asserted is that the
//! proxy relays the *shape* of the teardown, not just the bytes:
//!
//! - an upstream `RESET_STREAM` reaches the client as a `RESET_STREAM`
//!   carrying the same application error code — not as a FIN;
//! - a client `STOP_SENDING` reaches the upstream with the client's code
//!   — not the 0 that dropping a `RecvStream` would send;
//! - a clean FIN still arrives as a clean FIN;
//! - the same holds on the control stream, on *both* the pass-through
//!   and the parse-then-forward (`Interest::CONTROL`) paths, which are
//!   separate functions with separate propagation call sites.
//!
//! The reset case is a regression test for a real fidelity bug: quinn's
//! `SendStream::drop` calls `finish()`, so a forwarder that simply
//! returns on a read error silently converts an abandoned stream into a
//! complete one and a player sees a truncated group as whole.
//!
//! # "Data, then a reset" is an order here, not a wait
//!
//! A reset that overtook the bytes would leave the *reset* assertions green
//! and only the byte count wrong, and a sleep between the write and the
//! reset — 100 ms on the data stream, 150 ms on the control stream — cannot
//! make that ordering true; on a loaded box it only makes it likely.
//!
//! So the side that reads says when it holds the bytes, over a
//! `oneshot`, and the side that resets waits for that. The data case reads
//! `PARTIAL_GROUP` with `read_exact` before releasing the upstream; the
//! control case has the upstream read the forwarded CLIENT_SETUP before
//! releasing the client. Nothing is timed, and the byte counts the
//! assertions read back are the same ones.
//!
//! *Ablation:* return from `propagate_reset` before its
//! `if let Some(code) = mirrored` arm resets the destination. All three
//! reset tests here go red — the two control ones with
//! `left: Fin, right: Reset(33)` after 13 bytes, which is the whole
//! CLIENT_SETUP, so the ordering held while the propagation was broken.
//! `upstream_fin_still_reaches_the_client_as_a_fin` and both
//! `STOP_SENDING` tests stay green.
//!
//! Draft-14 throughout: `common::spawn_proxy` configures the session for
//! draft-14 and the control-stream cases feed it a draft-14 CLIENT_SETUP,
//! which the `Interest::CONTROL` case genuinely parses. The file compiles
//! and runs exactly when that draft does.

#![cfg(feature = "draft14")]

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{drain, Ending};

use moqtap_proxy::action::{Action, Interest};
use moqtap_proxy::event::{ProxyEvent, ProxySide};
use moqtap_proxy::hook::{FrameCtx, NoOpHook, ProxyHook};
use moqtap_proxy::observer::ProxyObserver;

use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::draft14::message::{ClientSetup, ControlMessage};
use moqtap_codec::varint::VarInt;

const RESET_CODE: u64 = 0x10;
const STOP_CODE: u64 = 0x05;
const CONTROL_RESET_CODE: u64 = 0x21;
const TIMEOUT: Duration = Duration::from_secs(10);

/// Leading `0x04` is the subgroup stream-type varint; the rest stands in
/// for the start of a group the publisher never finishes.
const PARTIAL_GROUP: &[u8] = &[0x04, 0x01, 0x02, 0x03];

/// How often a wait for something the forwarding tasks report looks again.
const RE_READ: Duration = Duration::from_millis(5);

/// Wait until the observer has recorded a stream reset, then return them.
///
/// Events are emitted from the forwarding tasks, so reading the record the
/// instant the *peer* saw its stream end is reading a record that may not
/// have been written yet. Returning whatever is there at the deadline
/// rather than panicking is what lets the caller's own assertion report the
/// shortfall: "expected a StreamReset event for the relay side, got []" is
/// a better failure than a timeout, and it is the same failure.
async fn recorded_resets(observer: &TeardownObserver) -> Vec<(ProxySide, u64)> {
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    loop {
        let resets = observer.resets();
        if !resets.is_empty() || tokio::time::Instant::now() >= deadline {
            return resets;
        }
        tokio::time::sleep(RE_READ).await;
    }
}

/// Observer that records every stream-teardown event.
#[derive(Default)]
struct TeardownObserver {
    resets: Mutex<Vec<(ProxySide, u64)>>,
    closes: Mutex<Vec<ProxySide>>,
    parse_errors: Mutex<Vec<String>>,
}

impl ProxyObserver for TeardownObserver {
    fn on_event(&self, event: &ProxyEvent) {
        match event {
            ProxyEvent::StreamReset { side, code, .. } => {
                self.resets.lock().unwrap().push((*side, *code));
            }
            ProxyEvent::StreamClosed { side, .. } => {
                self.closes.lock().unwrap().push(*side);
            }
            ProxyEvent::ParseError { error, .. } => {
                self.parse_errors.lock().unwrap().push(error.clone());
            }
            _ => {}
        }
    }
}

impl TeardownObserver {
    fn resets(&self) -> Vec<(ProxySide, u64)> {
        self.resets.lock().unwrap().clone()
    }

    fn closes(&self) -> Vec<ProxySide> {
        self.closes.lock().unwrap().clone()
    }

    fn parse_errors(&self) -> Vec<String> {
        self.parse_errors.lock().unwrap().clone()
    }
}

/// A hook that changes nothing but asks for the parse-then-forward
/// control path, so the `pipe_control_mutating` propagation sites are
/// exercised as well as `pipe_control_passthrough`'s.
///
/// It asks through [`Interest::CONTROL`], which is what `session.rs`'s
/// `control_mutation` gate reads, and that gate is the whole of the
/// routing decision between the two control pipes.
///
/// It counts the control messages it is shown, because that is the only
/// thing that distinguishes the two paths from outside: `on_control_message`
/// fires **only** under `control_mutation`, so a zero count means the
/// session took `pipe_control_passthrough` and this test was silently a
/// duplicate of the one above it.
#[derive(Default)]
struct MutatingPassthroughHook {
    seen: Mutex<usize>,
}

impl MutatingPassthroughHook {
    fn seen(&self) -> usize {
        *self.seen.lock().unwrap()
    }
}

impl ProxyHook for MutatingPassthroughHook {
    fn interest(&self) -> Interest {
        Interest::CONTROL
    }

    fn on_control_message(
        &self,
        _cx: &FrameCtx<'_>,
        _msg: &AnyControlMessage,
        _raw: &[u8],
    ) -> Action {
        *self.seen.lock().unwrap() += 1;
        Action::Pass
    }
}

#[tokio::test]
async fn upstream_reset_reaches_the_client_as_a_reset_with_the_same_code() {
    common::init_crypto();

    // The client says when it holds the bytes; until then the upstream does
    // not reset. "Data, then a reset" is the whole claim of this test, and
    // this is what makes it an order rather than a bet on how long a
    // forward takes.
    let (held_tx, held_rx) = tokio::sync::oneshot::channel::<()>();

    let (upstream_ep, upstream_addr) = common::spawn_quic_server(&[b"moq-00"]);
    let upstream_task = tokio::spawn(async move {
        let incoming = upstream_ep.accept().await.expect("upstream accept");
        let conn = incoming.await.expect("upstream tls");

        // Open a subgroup stream, write a partial group, then abandon it.
        let mut send = conn.open_uni().await.expect("upstream open_uni");
        send.write_all(PARTIAL_GROUP).await.expect("upstream write");
        let _ = held_rx.await;
        send.reset(quinn::VarInt::from_u64(RESET_CODE).unwrap()).expect("upstream reset");

        let _ = conn.closed().await;
    });

    let observer = Arc::new(TeardownObserver::default());
    let proxy = common::spawn_proxy(
        upstream_addr,
        Arc::clone(&observer) as Arc<dyn ProxyObserver>,
        Arc::new(NoOpHook),
    );

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, b"moq-00").await;

    let mut recv = tokio::time::timeout(TIMEOUT, client_conn.accept_uni())
        .await
        .expect("client saw the forwarded uni stream")
        .expect("accept_uni");

    // Everything the upstream wrote before it was told it could reset. The
    // read has to come back before the reset is asked for, so it is spelled
    // as its own read rather than left inside `drain`.
    let mut held = vec![0u8; PARTIAL_GROUP.len()];
    tokio::time::timeout(TIMEOUT, recv.read_exact(&mut held))
        .await
        .expect("the forwarded bytes arrived")
        .expect("the bytes written before the reset must reach the client");
    let _ = held_tx.send(());

    let (rest, ending) =
        tokio::time::timeout(TIMEOUT, drain(&mut recv)).await.expect("stream terminated");
    let bytes = held.len() + rest;

    match ending {
        Ending::Reset(code) => {
            assert_eq!(code, RESET_CODE, "the peer's error code must survive the proxy")
        }
        Ending::Fin => panic!(
            "expected RESET_STREAM({RESET_CODE}) but the client saw a clean FIN after {bytes} \
             bytes — the proxy laundered the reset into a FIN"
        ),
    }

    // Fidelity is "everything received, *then* the reset" — a proxy that
    // forwarded nothing and only mirrored the reset would satisfy the
    // assertion above on its own.
    assert_eq!(
        held, PARTIAL_GROUP,
        "the bytes written before the reset must still reach the client, unaltered"
    );
    assert_eq!(bytes, PARTIAL_GROUP.len(), "and nothing else must arrive after them");

    let resets = observer.resets();
    assert!(
        resets.contains(&(ProxySide::RelayToProxy, RESET_CODE)),
        "expected a StreamReset event for the relay side, got {resets:?}"
    );
    assert!(
        observer.closes().is_empty(),
        "a reset must not also be reported as StreamClosed, got {:?}",
        observer.closes()
    );
    // `PARTIAL_GROUP` is deliberately not a decodable subgroup header, so
    // the inline parser legitimately complains about it. What must *not*
    // appear is the pipe wrapper re-reporting the teardown itself:
    // `ParseError` means the codec failed and the bytes were forwarded
    // anyway, which is the opposite of what a reset is.
    let pipe_errors: Vec<_> =
        observer.parse_errors().into_iter().filter(|e| e.contains("uni stream pipe")).collect();
    assert!(
        pipe_errors.is_empty(),
        "a forwarded reset is already reported as StreamReset; it must not also be a ParseError, \
         got {pipe_errors:?}"
    );

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), upstream_task).await;
}

#[tokio::test]
async fn upstream_fin_still_reaches_the_client_as_a_fin() {
    common::init_crypto();

    let payload: Vec<u8> = vec![0x04, 0xAA, 0xBB, 0xCC, 0xDD];
    let expected_len = payload.len();

    let (upstream_ep, upstream_addr) = common::spawn_quic_server(&[b"moq-00"]);
    let upstream_task = tokio::spawn(async move {
        let incoming = upstream_ep.accept().await.expect("upstream accept");
        let conn = incoming.await.expect("upstream tls");

        let mut send = conn.open_uni().await.expect("upstream open_uni");
        send.write_all(&payload).await.expect("upstream write");
        send.finish().expect("upstream finish");

        let _ = conn.closed().await;
    });

    let observer = Arc::new(TeardownObserver::default());
    let proxy = common::spawn_proxy(
        upstream_addr,
        Arc::clone(&observer) as Arc<dyn ProxyObserver>,
        Arc::new(NoOpHook),
    );

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, b"moq-00").await;

    let mut recv = tokio::time::timeout(TIMEOUT, client_conn.accept_uni())
        .await
        .expect("client saw the forwarded uni stream")
        .expect("accept_uni");

    let (bytes, ending) =
        tokio::time::timeout(TIMEOUT, drain(&mut recv)).await.expect("stream terminated");

    match ending {
        Ending::Fin => assert_eq!(bytes, expected_len, "all bytes should arrive before the FIN"),
        Ending::Reset(code) => panic!("expected a clean FIN, got RESET_STREAM({code})"),
    }

    assert!(
        observer.resets().is_empty(),
        "a clean FIN must not be reported as a stream reset, got {:?}",
        observer.resets()
    );
    assert!(
        observer.closes().contains(&ProxySide::RelayToProxy),
        "a clean FIN must be reported as StreamClosed, got {:?}",
        observer.closes()
    );

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), upstream_task).await;
}

// ============================================================
// Control stream
//
// `pipe_control_passthrough` and `pipe_control_mutating` are separate
// functions with their own propagation call sites. Both are driven here;
// covering only `pipe_data` would let either one silently regress.
// ============================================================

/// Wire bytes of a draft-14 CLIENT_SETUP, so the proxy has a real
/// control message to forward before the stream is abandoned.
fn client_setup_bytes() -> Vec<u8> {
    let msg = AnyControlMessage::Draft14(ControlMessage::ClientSetup(ClientSetup {
        supported_versions: vec![VarInt::from_u64(0xff000000 + 14).unwrap()],
        parameters: Vec::new(),
    }));
    let mut buf = Vec::new();
    msg.encode(&mut buf).expect("encode CLIENT_SETUP");
    buf
}

/// Drive one control-stream reset through the proxy with the given hook,
/// returning what the upstream saw and what the observer recorded.
async fn control_reset_case(hook: Arc<dyn ProxyHook>) -> ((usize, Ending), Vec<(ProxySide, u64)>) {
    common::init_crypto();

    let (ending_tx, ending_rx) = tokio::sync::oneshot::channel::<(usize, Ending)>();
    // The upstream says when it holds the forwarded CLIENT_SETUP; until
    // then the client does not abandon the control stream. Same ordering
    // the data case needs, from the other end.
    let (held_tx, held_rx) = tokio::sync::oneshot::channel::<()>();
    let setup_len = client_setup_bytes().len();

    let (upstream_ep, upstream_addr) = common::spawn_quic_server(&[b"moq-00"]);
    let upstream_task = tokio::spawn(async move {
        let incoming = upstream_ep.accept().await.expect("upstream accept");
        let conn = incoming.await.expect("upstream tls");
        let (_send, mut recv) = conn.accept_bi().await.expect("upstream accept_bi");

        let mut held = vec![0u8; setup_len];
        let held = recv.read_exact(&mut held).await.map(|()| held.len()).unwrap_or(0);
        // Sent whether or not the read succeeded: a client left waiting
        // here would hang the run, and the ending reported below is what
        // says which of the two happened.
        let _ = held_tx.send(());

        let (rest, ending) = drain(&mut recv).await;
        let _ = ending_tx.send((held + rest, ending));
        let _ = conn.closed().await;
    });

    let observer = Arc::new(TeardownObserver::default());
    let proxy =
        common::spawn_proxy(upstream_addr, Arc::clone(&observer) as Arc<dyn ProxyObserver>, hook);

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, b"moq-00").await;

    let (mut client_send, _client_recv) = client_conn.open_bi().await.expect("client open_bi");
    client_send.write_all(&client_setup_bytes()).await.expect("client write CLIENT_SETUP");

    // The upstream has the forwarded setup, so what it sees next is the
    // reset and nothing else: "message, then reset".
    let _ = held_rx.await;
    client_send
        .reset(quinn::VarInt::from_u64(CONTROL_RESET_CODE).unwrap())
        .expect("client reset control stream");

    let observed = tokio::time::timeout(TIMEOUT, ending_rx)
        .await
        .expect("upstream control stream terminated")
        .expect("oneshot");

    let resets = recorded_resets(&observer).await;

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), upstream_task).await;

    (observed, resets)
}

#[tokio::test]
async fn client_control_reset_reaches_the_upstream_on_the_passthrough_path() {
    let ((bytes, ending), resets) = control_reset_case(Arc::new(NoOpHook)).await;

    assert_eq!(
        ending,
        Ending::Reset(CONTROL_RESET_CODE),
        "the upstream must see RESET_STREAM({CONTROL_RESET_CODE}) on the control stream, not a \
         FIN — after {bytes} bytes"
    );
    assert_eq!(
        bytes,
        client_setup_bytes().len(),
        "the CLIENT_SETUP must still reach the upstream ahead of the reset"
    );
    assert!(
        resets.contains(&(ProxySide::ClientToProxy, CONTROL_RESET_CODE)),
        "expected a StreamReset event for the client side, got {resets:?}"
    );
}

#[tokio::test]
async fn client_control_reset_reaches_the_upstream_on_the_mutating_path() {
    // Byte delivery is not asserted here: the parse-then-forward path
    // withholds bytes until a whole frame is parsed, which is its own
    // contract (covered by proxy_hook_rewrite). What matters is that the
    // reset propagates from this path too.
    let hook = Arc::new(MutatingPassthroughHook::default());
    let ((_, ending), resets) = control_reset_case(Arc::clone(&hook) as Arc<dyn ProxyHook>).await;

    assert_eq!(
        ending,
        Ending::Reset(CONTROL_RESET_CODE),
        "pipe_control_mutating must propagate the reset just like the pass-through path"
    );
    assert!(
        resets.contains(&(ProxySide::ClientToProxy, CONTROL_RESET_CODE)),
        "expected a StreamReset event for the client side, got {resets:?}"
    );
    // Without this the test above it would satisfy every assertion in this
    // one: both paths propagate the reset, so "the reset arrived" cannot
    // by itself say which function ran. `on_control_message` fires only
    // under `control_mutation`, so a non-zero count is the routing proof.
    assert!(
        hook.seen() >= 1,
        "the hook must have been consulted, or this ran on the pass-through path and is a \
         duplicate of client_control_reset_reaches_the_upstream_on_the_passthrough_path"
    );
}

#[tokio::test]
async fn client_stop_sending_reaches_the_upstream_with_the_same_code() {
    common::init_crypto();

    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<u64>();

    let (upstream_ep, upstream_addr) = common::spawn_quic_server(&[b"moq-00"]);
    let upstream_task = tokio::spawn(async move {
        let incoming = upstream_ep.accept().await.expect("upstream accept");
        let conn = incoming.await.expect("upstream tls");

        let mut send = conn.open_uni().await.expect("upstream open_uni");
        send.write_all(&[0x04, 0x01]).await.expect("upstream write");

        // Keep producing until the proxy mirrors the client's
        // STOP_SENDING back onto this stream.
        let deadline = tokio::time::Instant::now() + TIMEOUT;
        loop {
            if tokio::time::Instant::now() >= deadline {
                panic!("upstream was never stopped");
            }
            match send.write_all(&[0u8; 256]).await {
                Ok(()) => tokio::time::sleep(Duration::from_millis(20)).await,
                Err(quinn::WriteError::Stopped(code)) => {
                    let _ = stop_tx.send(code.into_inner());
                    break;
                }
                Err(e) => panic!("unexpected upstream write error: {e:?}"),
            }
        }

        let _ = conn.closed().await;
    });

    let observer = Arc::new(TeardownObserver::default());
    let proxy = common::spawn_proxy(
        upstream_addr,
        Arc::clone(&observer) as Arc<dyn ProxyObserver>,
        Arc::new(NoOpHook),
    );

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, b"moq-00").await;

    let mut recv = tokio::time::timeout(TIMEOUT, client_conn.accept_uni())
        .await
        .expect("client saw the forwarded uni stream")
        .expect("accept_uni");

    let mut buf = [0u8; 1024];
    tokio::time::timeout(TIMEOUT, recv.read(&mut buf)).await.expect("first read").expect("read");
    recv.stop(quinn::VarInt::from_u64(STOP_CODE).unwrap()).expect("client stop");

    let observed = tokio::time::timeout(TIMEOUT, stop_rx)
        .await
        .expect("upstream observed a STOP_SENDING")
        .expect("oneshot");

    assert_eq!(
        observed, STOP_CODE,
        "the client's STOP_SENDING code must survive the proxy — 0 means it was defaulted by \
         RecvStream::drop instead of forwarded"
    );

    // The STOP_SENDING was observed on the stream the proxy writes to,
    // i.e. the proxy→client egress side — not the relay ingress side the
    // forwarder was handed. Without this the side mapping could be the
    // identity function and nothing would notice.
    let resets = observer.resets();
    assert!(
        resets.contains(&(ProxySide::ProxyToClient, STOP_CODE)),
        "expected StreamReset {{ side: ProxyToClient, code: {STOP_CODE} }}, got {resets:?}"
    );

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), upstream_task).await;
}

/// How long the idle upstream waits to be stopped before giving up.
///
/// Deliberately not [`TIMEOUT`]: on the passing path the stop arrives in
/// milliseconds, and the only run that waits this long is a broken one.
const IDLE_STOP_WINDOW: Duration = Duration::from_millis(400);

/// An upstream that writes nothing after its first chunk must still learn
/// that the client stopped the stream.
///
/// This is the same claim as
/// [`client_stop_sending_reaches_the_upstream_with_the_same_code`] minus its
/// workaround. That test keeps the upstream writing in a 20 ms loop, and the
/// loop is not incidental — it is what lets that test pass even without the
/// `stop.watch()` branch, because without the watcher a `STOP_SENDING` is
/// noticed *only* when the next write to the destination fails, so a
/// publisher between groups, or one that has finished a subgroup and is
/// waiting for the next, is never stopped at all. Removing the loop is the
/// whole test: the upstream here writes four bytes and then does nothing but
/// wait to be told.
///
/// It runs on the **framed** pipe — an observer is attached, so
/// `objects_enabled` is true. `interest_none.rs`'s
/// `an_interest_none_session_still_mirrors_a_stop` covers the pass-through
/// pipe, which is a separate function with its own watcher.
///
/// *Ablation (run, and it fails):* delete the `stop.watch()` branch from
/// `pipe_data_framed`'s `select!`. The upstream then sees nothing —
/// `observed` is `None` — because nothing ever writes to the destination
/// again and there is no other trigger.
#[tokio::test]
async fn stop_sending_reaches_an_idle_upstream() {
    common::init_crypto();

    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<Option<u64>>();

    let (upstream_ep, upstream_addr) = common::spawn_quic_server(&[b"moq-00"]);
    let upstream_task = tokio::spawn(async move {
        let incoming = upstream_ep.accept().await.expect("upstream accept");
        let conn = incoming.await.expect("upstream tls");

        let mut send = conn.open_uni().await.expect("upstream open_uni");
        send.write_all(PARTIAL_GROUP).await.expect("upstream write");

        // …and then nothing at all. No second write, no FIN, no reset.
        let observed = match tokio::time::timeout(IDLE_STOP_WINDOW, send.stopped()).await {
            Ok(Ok(Some(code))) => Some(code.into_inner()),
            _ => None,
        };
        let _ = stop_tx.send(observed);
        let _ = conn.closed().await;
    });

    let observer = Arc::new(TeardownObserver::default());
    let proxy = common::spawn_proxy(
        upstream_addr,
        Arc::clone(&observer) as Arc<dyn ProxyObserver>,
        Arc::new(NoOpHook),
    );

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, b"moq-00").await;

    let mut recv = tokio::time::timeout(TIMEOUT, client_conn.accept_uni())
        .await
        .expect("client saw the forwarded uni stream")
        .expect("accept_uni");

    // Read the prefix first, so the stop is "the client changed its mind
    // about a stream it was already receiving" rather than one that raced
    // the stream open.
    let mut buf = [0u8; 1024];
    let first = tokio::time::timeout(TIMEOUT, recv.read(&mut buf))
        .await
        .expect("first read")
        .expect("read")
        .expect("not an immediate FIN");
    assert_eq!(first, PARTIAL_GROUP.len(), "the partial group must arrive before the stop");

    recv.stop(quinn::VarInt::from_u64(STOP_CODE).unwrap()).expect("client stop");

    let observed = tokio::time::timeout(TIMEOUT, stop_rx)
        .await
        .expect("the upstream task finished")
        .expect("oneshot");

    assert_eq!(
        observed,
        Some(STOP_CODE),
        "an idle upstream must still be stopped with the client's code. `None` means it was \
         never stopped at all: nothing wrote to the destination, so nothing \
         noticed the STOP_SENDING"
    );

    // The in-process half of the same claim. The wire assertion above could
    // in principle be satisfied by a `RecvStream::drop`, which stops with a
    // hard-coded 0; this pins the side mapping and the code together.
    let resets = observer.resets();
    assert!(
        resets.contains(&(ProxySide::ProxyToClient, STOP_CODE)),
        "expected StreamReset {{ side: ProxyToClient, code: {STOP_CODE} }}, got {resets:?}"
    );

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), upstream_task).await;
}

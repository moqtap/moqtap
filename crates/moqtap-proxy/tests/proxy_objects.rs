//! End-to-end object framing through a live proxy session.
//!
//! Proves the two framing promises together: a subgroup stream
//! arrives at the far end byte-identical, *and* one
//! [`ProxyEvent::Object`] fires per object — on every draft, including
//! 14-19, where the proxy previously emitted nothing at all.

//! `DRAFTS` is cfg-built, so the sweep is the compiled set. A build with
//! no draft at all has no subgroup codec to build a stream with, and
//! nothing here is answerable, so the file is gated out of that row.

#![cfg(any(
    feature = "draft07",
    feature = "draft08",
    feature = "draft09",
    feature = "draft10",
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19"
))]

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use moqtap_codec::dispatch::{AnySubgroupHeader, AnySubgroupObject, AnySubgroupObjectWriter};
use moqtap_codec::version::DraftVersion;

use moqtap_proxy::action::{Action, Interest};
use moqtap_proxy::event::ProxyEvent;
use moqtap_proxy::framer::ObjectMeta;
use moqtap_proxy::hook::{NoOpHook, ObjectCtx, ProxyHook};
use moqtap_proxy::observer::ProxyObserver;

const DRAFTS: &[DraftVersion] = &[
    #[cfg(feature = "draft07")]
    DraftVersion::Draft07,
    #[cfg(feature = "draft08")]
    DraftVersion::Draft08,
    #[cfg(feature = "draft09")]
    DraftVersion::Draft09,
    #[cfg(feature = "draft10")]
    DraftVersion::Draft10,
    #[cfg(feature = "draft11")]
    DraftVersion::Draft11,
    #[cfg(feature = "draft12")]
    DraftVersion::Draft12,
    #[cfg(feature = "draft13")]
    DraftVersion::Draft13,
    #[cfg(feature = "draft14")]
    DraftVersion::Draft14,
    #[cfg(feature = "draft15")]
    DraftVersion::Draft15,
    #[cfg(feature = "draft16")]
    DraftVersion::Draft16,
    #[cfg(feature = "draft17")]
    DraftVersion::Draft17,
    #[cfg(feature = "draft18")]
    DraftVersion::Draft18,
    #[cfg(feature = "draft19")]
    DraftVersion::Draft19,
];

/// Collects object events. `wants_events()` is left at its `true` default
/// — with `NoOpProxyObserver` the session takes the byte-pump path and
/// this test would prove nothing.
#[derive(Default)]
struct ObjectCollector {
    objects: Mutex<Vec<ObjectMeta>>,
    errors: Mutex<Vec<String>>,
}

impl ProxyObserver for ObjectCollector {
    fn on_event(&self, event: &ProxyEvent) {
        match event {
            ProxyEvent::Object { meta, .. } => {
                self.objects.lock().expect("objects lock").push(*meta)
            }
            ProxyEvent::ParseError { error, .. } => {
                self.errors.lock().expect("errors lock").push(error.clone())
            }
            _ => {}
        }
    }
}

/// The newest draft this build compiled — the draft the two single-stream
/// tests below run on.
///
/// Neither claim is about a particular draft: one says the byte pump
/// forwards untouched, the other that a stream cut mid-object still has
/// its tail flushed. But the draft has to be one this build compiled — a
/// session configured for a draft with no codec behind it is refused by
/// `ProxyError::DraftNotCompiled` before it dials, which surfaces as an
/// upstream connection that never arrives rather than as anything about
/// framing.
///
/// The newest rather than the first, so that a build with every draft runs
/// them on draft-19, which is what they named before this was derived, and
/// which is the half of the range where the proxy used to report nothing
/// at all. `DRAFTS` is cfg-built and the file-level gate guarantees at
/// least one entry.
fn a_compiled_draft() -> DraftVersion {
    DRAFTS[DRAFTS.len() - 1]
}

fn subgroup_stream_type(draft: DraftVersion) -> u8 {
    match draft {
        DraftVersion::Draft07
        | DraftVersion::Draft08
        | DraftVersion::Draft09
        | DraftVersion::Draft10 => 0x04,
        DraftVersion::Draft11 => 0x0C,
        _ => 0x14,
    }
}

/// A subgroup stream carrying three objects: track alias 1, group 0,
/// subgroup 0, publisher priority 128.
fn build_stream(draft: DraftVersion) -> Vec<u8> {
    let head = vec![subgroup_stream_type(draft), 0x01, 0x00, 0x00, 0x80];
    let mut cursor = &head[..];
    let header = AnySubgroupHeader::decode_stream(draft, &mut cursor)
        .unwrap_or_else(|e| panic!("[{draft}] header decode: {e}"));
    let mut writer =
        AnySubgroupObjectWriter::new(&header).unwrap_or_else(|e| panic!("[{draft}] writer: {e}"));

    let mut out = head;
    for (id, payload) in
        [(0u64, b"deadbeef".to_vec()), (1, b"cafe".to_vec()), (2, vec![0xAB; 5000])]
    {
        let obj = AnySubgroupObject {
            object_id: id,
            extension_headers: Vec::new(),
            extension_count: None,
            status: None,
            payload,
        };
        writer.write_object(&obj, &mut out).unwrap_or_else(|e| panic!("[{draft}] write: {e}"));
    }
    out
}

/// A hook that declares no interest and would panic if the object site
/// were ever consulted.
///
/// The gate under test in
/// [`byte_pump_path_forwards_unchanged_without_an_observer`] is
/// structural: `Interest::NONE` plus a non-event observer must keep the
/// session on `pipe_data_passthrough`, where there is no framer and no
/// hook call. A hook that merely counted calls could not distinguish "not
/// called" from "called and ignored"; panicking can.
struct NeverAskMeHook;

impl ProxyHook for NeverAskMeHook {
    fn interest(&self) -> Interest {
        Interest::NONE
    }

    fn on_object(&self, cx: &ObjectCtx<'_>, _raw: &[u8]) -> Action {
        panic!(
            "on_object fired on an Interest::NONE hook (object {} on stream {})",
            cx.meta.object_id, cx.stream_id
        );
    }
}

/// Wait until the upstream has collected `want` bytes, or give up.
///
/// Returns whatever arrived either way, so the caller's `assert_eq!`
/// reports the shortfall rather than a bare timeout.
async fn wait_for_bytes(got: &Mutex<Vec<u8>>, want: usize) -> Vec<u8> {
    let poll = async {
        loop {
            {
                let seen = got.lock().expect("got lock");
                if seen.len() >= want {
                    return seen.clone();
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    match tokio::time::timeout(Duration::from_secs(10), poll).await {
        Ok(seen) => seen,
        Err(_) => got.lock().expect("got lock").clone(),
    }
}

#[tokio::test]
async fn subgroup_stream_is_framed_and_forwarded_unchanged() {
    common::init_crypto();

    for &draft in DRAFTS {
        let stream = build_stream(draft);

        let (upstream_ep, upstream_addr) = common::spawn_quic_server(&[b"moq-00"]);
        let (got_tx, got_rx) = tokio::sync::oneshot::channel::<Vec<u8>>();

        let upstream_task = tokio::spawn(async move {
            let incoming = upstream_ep.accept().await.expect("upstream accept");
            let conn = incoming.await.expect("upstream tls");
            let mut recv = conn.accept_uni().await.expect("upstream accept_uni");
            let bytes = recv.read_to_end(1024 * 1024).await.expect("upstream read_to_end");
            let _ = got_tx.send(bytes);
            let _ = conn.closed().await;
        });

        let observer = Arc::new(ObjectCollector::default());
        let proxy = common::spawn_proxy_with(
            common::session_config(draft, upstream_addr),
            b"moq-00",
            Arc::clone(&observer) as Arc<dyn ProxyObserver>,
            Arc::new(NoOpHook),
        );

        let (_client_ep, client_conn) = common::connect_client(proxy.addr, b"moq-00").await;

        let mut send = client_conn.open_uni().await.expect("open_uni");
        // Write in small pieces so the framer is exercised across chunk
        // boundaries rather than handed the whole stream at once.
        for piece in stream.chunks(64) {
            send.write_all(piece).await.expect("write");
        }
        send.finish().expect("finish");

        let got = tokio::time::timeout(Duration::from_secs(10), got_rx)
            .await
            .unwrap_or_else(|_| panic!("[{draft}] upstream did not receive the stream"))
            .expect("oneshot");

        assert_eq!(got, stream, "[{draft}] forwarded stream must be byte-identical");

        let objects = observer.objects.lock().expect("objects lock").clone();
        let errors = observer.errors.lock().expect("errors lock").clone();
        assert!(errors.is_empty(), "[{draft}] unexpected parse errors: {errors:?}");
        assert_eq!(
            objects.iter().map(|m| m.object_id).collect::<Vec<_>>(),
            vec![0, 1, 2],
            "[{draft}] one Object event per object, in order"
        );
        assert_eq!(objects[0].draft, draft, "[{draft}] reported draft");
        assert_eq!(objects[0].track_alias, Some(1), "[{draft}] track alias");
        assert_eq!(objects[2].payload_len, 5000, "[{draft}] payload length");

        client_conn.close(0u32.into(), b"done");
        proxy.shutdown().await;
        let _ = tokio::time::timeout(Duration::from_secs(2), upstream_task).await;
    }
}

#[tokio::test]
async fn a_stream_that_fins_mid_object_still_forwards_its_tail() {
    common::init_crypto();

    let draft = a_compiled_draft();
    let stream = build_stream(draft);
    // Cut the last object in half: a publisher whose subgroup is cut short
    // FINs mid-object, and everything the framer still holds then depends
    // on `pipe_data_framed` calling `ObjectFramer::finish()` before
    // finishing the destination stream.
    let truncated = stream[..stream.len() - 32].to_vec();

    let (upstream_ep, upstream_addr) = common::spawn_quic_server(&[b"moq-00"]);
    let (got_tx, got_rx) = tokio::sync::oneshot::channel::<Vec<u8>>();

    let upstream_task = tokio::spawn(async move {
        let incoming = upstream_ep.accept().await.expect("upstream accept");
        let conn = incoming.await.expect("upstream tls");
        let mut recv = conn.accept_uni().await.expect("upstream accept_uni");
        let bytes = recv.read_to_end(1024 * 1024).await.expect("upstream read_to_end");
        let _ = got_tx.send(bytes);
        let _ = conn.closed().await;
    });

    let observer = Arc::new(ObjectCollector::default());
    let proxy = common::spawn_proxy_with(
        common::session_config(draft, upstream_addr),
        b"moq-00",
        Arc::clone(&observer) as Arc<dyn ProxyObserver>,
        Arc::new(NoOpHook),
    );

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, b"moq-00").await;

    let mut send = client_conn.open_uni().await.expect("open_uni");
    for piece in truncated.chunks(64) {
        send.write_all(piece).await.expect("write");
    }
    send.finish().expect("finish");

    let got = tokio::time::timeout(Duration::from_secs(10), got_rx)
        .await
        .expect("upstream received the stream")
        .expect("oneshot");
    assert_eq!(got, truncated, "the truncated final object must still reach the upstream");

    let objects = observer.objects.lock().expect("objects lock").clone();
    assert_eq!(
        objects.iter().map(|m| m.object_id).collect::<Vec<_>>(),
        vec![0, 1],
        "only the objects that arrived whole are reported"
    );

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), upstream_task).await;
}

/// The byte pump forwards unchanged, and nothing on the framed path runs.
///
/// Driven twice by
/// [`byte_pump_path_forwards_unchanged_without_an_observer`]: once with a
/// `NoOpHook`, and once with a hook that declares `Interest::NONE` and
/// panics from `on_object`. The second case is the one this file could
/// not express before Hook v2 — it could only turn the *observer* off,
/// which proves nothing about the hook gate — and it is the end-to-end
/// companion to the `objects_enabled` / `object_hook` split: framing is
/// enabled by observation, while hook authority is enabled only by declared
/// object interest.
async fn byte_pump_case(hook: Arc<dyn ProxyHook>) {
    let draft = a_compiled_draft();
    let stream = build_stream(draft);
    // Stop ten bytes short of the end so the last object is incomplete.
    // The byte pump forwards it anyway — it has no idea where objects
    // begin — while the framed path would hold those ~5000 bytes until
    // FIN. That difference is the only honest way a test can tell which
    // branch of `pipe_data` ran: with `wants_events() == false` the
    // session suppresses every event, so no observer can see the
    // difference and the forwarded bytes are identical either way.
    let head = stream[..stream.len() - 10].to_vec();

    let (upstream_ep, upstream_addr) = common::spawn_quic_server(&[b"moq-00"]);
    let got = Arc::new(Mutex::new(Vec::new()));

    let upstream_got = Arc::clone(&got);
    let upstream_task = tokio::spawn(async move {
        let incoming = upstream_ep.accept().await.expect("upstream accept");
        let conn = incoming.await.expect("upstream tls");
        let mut recv = conn.accept_uni().await.expect("upstream accept_uni");
        let mut buf = [0u8; 4096];
        while let Some(n) = recv.read(&mut buf).await.expect("upstream read") {
            upstream_got.lock().expect("got lock").extend_from_slice(&buf[..n]);
        }
        let _ = conn.closed().await;
    });

    let proxy = common::spawn_proxy_with(
        common::session_config(draft, upstream_addr),
        b"moq-00",
        Arc::new(moqtap_proxy::observer::NoOpProxyObserver),
        hook,
    );

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, b"moq-00").await;

    let mut send = client_conn.open_uni().await.expect("open_uni");
    send.write_all(&head).await.expect("write");

    let forwarded = wait_for_bytes(&got, head.len()).await;
    assert_eq!(
        forwarded, head,
        "the byte pump forwards every byte as it arrives; holding an \
         incomplete object back means the framing path ran"
    );

    send.write_all(&stream[stream.len() - 10..]).await.expect("write tail");
    send.finish().expect("finish");

    let forwarded = wait_for_bytes(&got, stream.len()).await;
    assert_eq!(forwarded, stream, "the byte-pump path forwards the stream unchanged");

    // The falsifiable half: a session on the byte pump touches no slow
    // path at all, so every counter is still at its default. Byte
    // equality alone cannot say this — the framed path is byte-identical
    // to the pump on purpose.
    assert_eq!(
        proxy.counters(),
        moqtap_proxy::instrument::Counters::default(),
        "an Interest::NONE session with a non-event observer must touch no slow path"
    );

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), upstream_task).await;
}

#[tokio::test]
async fn byte_pump_path_forwards_unchanged_without_an_observer() {
    common::init_crypto();

    // Case 1, as it always was: a no-op hook and a non-event observer.
    byte_pump_case(Arc::new(NoOpHook)).await;

    // Case 2: a hook that is *present* and declares `Interest::NONE`. Its
    // `on_object` panics, so "the hook was never consulted" is asserted by
    // the run surviving rather than by an absence nobody checked.
    byte_pump_case(Arc::new(NeverAskMeHook)).await;
}

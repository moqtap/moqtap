//! The two stream-decision sites, end to end.
//!
//! [`StreamAction::Reject`] is honoured at two places with two *different*
//! observable effects, and both are honest:
//!
//! * at [`Site::StreamOpen`] the decision is taken between `accept_uni()`
//!   and `open_uni()`, so no peer stream is ever created — proved with
//!   `common::assert_no_uni_stream_for`, which is a negative claim and
//!   therefore needs a window rather than a poll;
//! * at [`Site::StreamHeader`] the peer stream already exists (the accept
//!   loop opened it before the first byte was read), so it is reset with
//!   the code having carried **zero** payload bytes.
//!
//! # Why `Interest::STREAMS` alone is the interesting declaration
//!
//! A `STREAMS`-only hook that did not structurally imply
//! `OBJECTS` would be sent down `pipe_data_passthrough`, where there is no
//! framer, therefore no stream header, therefore no `on_stream_header`
//! call — a **silent no-op**, not a refusal. The implication is asserted at
//! compile time by the `const _` below and at run time by
//! [`streams_alone_frames_the_stream_and_fires_the_header_hook`] and
//! [`a_track_targeted_reject_only_rejects_that_track`], both of which
//! attach a **non-event** observer on purpose: with `wants_events() ==
//! true` the session frames the stream for the observer's sake and
//! `objects_enabled` is true whatever `STREAMS` contains, so the ablation
//! would not bite.

mod common;

// Three draft-specific groups live here and are gated separately: the
// four stream-rejection tests drive a draft-14 subgroup stream, and the
// two control-plane-topology tests are a draft-19 / draft-16 pair whose
// whole point is that the two drafts disagree. Everything a group needs —
// its fixtures, its hook, its imports — carries that group's gate, so a
// single-draft row keeps whichever group it compiled and drops the rest.
//
// The named drafts here are representatives, not a range, and this is the
// one file in the workspace where that is deliberate. `draft19` stands for
// every draft whose control plane is a pair of unidirectional streams and
// `draft16` for every draft whose control plane is one bidirectional
// stream; `session::control_plane_is_unidirectional` is where the line
// actually sits, it answers `true` for 17 through 20 and `false` for 07
// through 16, and it matches exhaustively so a new draft cannot join
// either side by default. Adding draft-20 alongside draft-19 would compile
// and pass and assert a fourth copy of one side of a two-sided contrast.
// A sweep that widens per-draft enumerations should skip this block.
#[cfg(any(feature = "draft14", feature = "draft16", feature = "draft19"))]
use std::sync::{Arc, Mutex};
#[cfg(feature = "draft14")]
use std::time::Duration;

#[cfg(any(feature = "draft16", feature = "draft19"))]
use moqtap_codec::dispatch::AnyControlMessage;
#[cfg(feature = "draft14")]
use moqtap_codec::dispatch::{AnySubgroupHeader, AnySubgroupObject, AnySubgroupObjectWriter};
#[cfg(any(feature = "draft14", feature = "draft16", feature = "draft19"))]
use moqtap_codec::version::DraftVersion;

use moqtap_proxy::action::Interest;
#[cfg(any(feature = "draft14", feature = "draft16", feature = "draft19"))]
use moqtap_proxy::action::StreamAction;
#[cfg(feature = "draft14")]
use moqtap_proxy::capability::{ActionKind, Site};
#[cfg(any(feature = "draft14", feature = "draft16", feature = "draft19"))]
use moqtap_proxy::event::DataStreamHeaderKind;
#[cfg(feature = "draft14")]
use moqtap_proxy::event::Effect;
#[cfg(any(feature = "draft16", feature = "draft19"))]
use moqtap_proxy::event::ImpairmentKind;
#[cfg(any(feature = "draft14", feature = "draft16", feature = "draft19"))]
use moqtap_proxy::hook::{ProxyHook, StreamCtx};
#[cfg(feature = "draft14")]
use moqtap_proxy::observer::NoOpProxyObserver;
#[cfg(any(feature = "draft14", feature = "draft16", feature = "draft19"))]
use moqtap_proxy::observer::ProxyObserver;

#[cfg(feature = "draft14")]
use common::Ending;
#[cfg(any(feature = "draft14", feature = "draft16", feature = "draft19"))]
use common::{FakeRelay, RecordingObserver};

/// The compile-time companion to the two runtime tests below.
///
/// `Interest::STREAMS` is `(1 << 3) | (1 << 1)`, so it contains
/// `Interest::OBJECTS` *by construction*. A revision that wrote it as a
/// plain `1 << 3` would put every `STREAMS`-only hook on the byte pump,
/// where `on_stream_header` can never fire. `src/action.rs` carries the
/// same assertion; this copy is here because that is the assertion the two
/// runtime tests below are the end-to-end half of, and a reader of this
/// file should not have to go and find it.
const _: () = assert!(Interest::STREAMS.contains(Interest::OBJECTS));

/// Rejection code used at `Site::StreamOpen`.
#[cfg(feature = "draft14")]
const OPEN_REJECT_CODE: u64 = 0x2A;
/// Rejection code used at `Site::StreamHeader`.
#[cfg(feature = "draft14")]
const HEADER_REJECT_CODE: u64 = 0x11;

/// The track alias the track-targeted hook rejects.
#[cfg(feature = "draft14")]
const BANNED_ALIAS: u64 = 2;
/// The track alias it lets through.
#[cfg(feature = "draft14")]
const ALLOWED_ALIAS: u64 = 1;

// ── fixtures ───────────────────────────────────────────────────────────

/// A draft-14 subgroup stream header, hand-written.
///
/// `0x14` is the explicit-subgroup-ID stream type; then track alias, group
/// ID, subgroup ID and publisher priority, each one byte at these values.
/// Written out rather than encoded through the codec so that "the hook was
/// shown track alias N" is a claim about **these bytes** and not about a
/// value that went out through the same code that read it back.
#[cfg(feature = "draft14")]
fn subgroup_head(track_alias: u64) -> Vec<u8> {
    assert!(track_alias < 64, "single-byte varint only");
    vec![0x14, track_alias as u8, 0x00, 0x00, 0x80]
}

/// A whole draft-14 subgroup stream: the hand-written header plus three
/// objects.
///
/// The objects go through `AnySubgroupObjectWriter` because drafts 14-20
/// delta-encode Object IDs and a hand-rolled object body would be
/// asserting the codec's arithmetic rather than the proxy's routing. No
/// assertion in this file reads object *content*: the stream is either
/// forwarded whole, or it is not forwarded at all.
#[cfg(feature = "draft14")]
fn subgroup_stream(track_alias: u64) -> Vec<u8> {
    let head = subgroup_head(track_alias);
    let mut cursor = &head[..];
    let header = AnySubgroupHeader::decode_stream(DraftVersion::Draft14, &mut cursor)
        .expect("hand-written subgroup header must decode");
    assert_eq!(header.track_alias(), track_alias, "the byte at index 1 is the track alias");
    let mut writer = AnySubgroupObjectWriter::new(&header).expect("subgroup object writer");

    let mut out = head;
    for (object_id, payload) in [(0u64, vec![0xD0; 16]), (1, vec![0xD1; 8]), (2, vec![0xD2; 64])] {
        let obj = AnySubgroupObject {
            object_id,
            extension_headers: Vec::new(),
            extension_count: None,
            status: None,
            payload,
        };
        writer.write_object(&obj, &mut out).expect("write object");
    }
    out
}

/// Rejects at `Site::StreamOpen`, and panics if anything downstream of the
/// open decision is ever reached.
///
/// A counting hook could not tell "not called" from "called and ignored";
/// panicking can. Nothing on a rejected stream may be framed, so
/// `on_stream_header` firing is a defect, not a nuance.
#[derive(Default)]
#[cfg(feature = "draft14")]
struct RejectAtOpen {
    opens: Mutex<Vec<u64>>,
}

#[cfg(feature = "draft14")]
impl ProxyHook for RejectAtOpen {
    fn interest(&self) -> Interest {
        Interest::STREAMS
    }

    fn on_stream_open(&self, cx: &StreamCtx<'_>) -> StreamAction {
        self.opens.lock().expect("opens").push(cx.stream_id);
        assert!(!cx.is_control_stream, "uni data streams are never the control stream");
        StreamAction::Reject { code: OPEN_REJECT_CODE }
    }

    fn on_stream_header(
        &self,
        _cx: &StreamCtx<'_>,
        _header: &DataStreamHeaderKind,
    ) -> StreamAction {
        panic!("on_stream_header fired for a stream rejected at Site::StreamOpen");
    }
}

/// Opens at `Site::StreamOpen`, rejects at `Site::StreamHeader`.
#[derive(Default)]
#[cfg(feature = "draft14")]
struct RejectAtHeader {
    headers: Mutex<Vec<u64>>,
}

#[cfg(feature = "draft14")]
impl ProxyHook for RejectAtHeader {
    fn interest(&self) -> Interest {
        Interest::STREAMS
    }

    fn on_stream_header(&self, _cx: &StreamCtx<'_>, header: &DataStreamHeaderKind) -> StreamAction {
        let alias = match header {
            DataStreamHeaderKind::Subgroup(h) => h.track_alias(),
            DataStreamHeaderKind::Fetch(_) => panic!("expected a subgroup stream"),
        };
        self.headers.lock().expect("headers").push(alias);
        StreamAction::Reject { code: HEADER_REJECT_CODE }
    }
}

/// Rejects exactly one track, by alias, at the header site.
///
/// This is the decision `StreamCtx` at `Site::StreamOpen` deliberately
/// cannot make: the peer stream is opened before the first byte is read,
/// so no track alias is known there. Declared with `Interest::STREAMS`
/// **alone**.
#[derive(Default)]
#[cfg(feature = "draft14")]
struct RejectOneTrack {
    seen: Mutex<Vec<u64>>,
}

#[cfg(feature = "draft14")]
impl ProxyHook for RejectOneTrack {
    fn interest(&self) -> Interest {
        Interest::STREAMS
    }

    fn on_stream_header(&self, _cx: &StreamCtx<'_>, header: &DataStreamHeaderKind) -> StreamAction {
        let alias = match header {
            DataStreamHeaderKind::Subgroup(h) => h.track_alias(),
            DataStreamHeaderKind::Fetch(_) => panic!("expected a subgroup stream"),
        };
        self.seen.lock().expect("seen").push(alias);
        if alias == BANNED_ALIAS {
            StreamAction::Reject { code: HEADER_REJECT_CODE }
        } else {
            StreamAction::Open
        }
    }
}

/// Records every `on_stream_header` call and forwards everything.
#[derive(Default)]
#[cfg(feature = "draft14")]
struct WatchHeaders {
    seen: Mutex<Vec<HeaderFields>>,
}

/// The three subgroup-header fields `WatchHeaders` reads back, as the
/// uniform `AnySubgroupHeader` accessors report them.
#[cfg(feature = "draft14")]
type HeaderFields = (u64, Option<u64>, Option<u8>);

#[cfg(feature = "draft14")]
impl ProxyHook for WatchHeaders {
    fn interest(&self) -> Interest {
        Interest::STREAMS
    }

    fn on_stream_header(&self, _cx: &StreamCtx<'_>, header: &DataStreamHeaderKind) -> StreamAction {
        if let DataStreamHeaderKind::Subgroup(h) = header {
            self.seen.lock().expect("seen").push((
                h.track_alias(),
                h.subgroup_id(),
                h.publisher_priority(),
            ));
        }
        StreamAction::Open
    }
}

/// Records every control message the proxy shows it.
///
/// Used by the topology pair below: on draft-19 the SETUP arrives on a
/// *unidirectional* stream and on draft-16 on the one client-initiated
/// bidirectional stream, and this log must hold that message in both
/// cases. The two drafts put the control plane in different places, so the
/// pair is what says the site follows it rather than following a stream
/// shape.
#[derive(Default)]
#[cfg(any(feature = "draft16", feature = "draft19"))]
struct WatchControl {
    seen: Mutex<Vec<AnyControlMessage>>,
    headers: Mutex<usize>,
}

#[cfg(any(feature = "draft16", feature = "draft19"))]
impl ProxyHook for WatchControl {
    fn interest(&self) -> Interest {
        Interest::CONTROL | Interest::STREAMS
    }

    fn on_control_message(
        &self,
        _cx: &moqtap_proxy::hook::FrameCtx<'_>,
        msg: &AnyControlMessage,
        _raw: &[u8],
    ) -> moqtap_proxy::action::Action {
        self.seen.lock().expect("seen").push(msg.clone());
        moqtap_proxy::action::Action::Pass
    }

    fn on_stream_header(
        &self,
        _cx: &StreamCtx<'_>,
        _header: &DataStreamHeaderKind,
    ) -> StreamAction {
        *self.headers.lock().expect("headers") += 1;
        StreamAction::Open
    }
}

/// Every impairment the session reported.
///
/// A session that identifies its control plane correctly, forwards one
/// message on it and closes has nothing to report, on either draft. Read as
/// a whole rather than filtered to one kind: filtering names in advance what
/// a wrong topology would be expected to complain about, and the honest
/// claim is that it complains about nothing.
#[cfg(any(feature = "draft16", feature = "draft19"))]
fn impairments(observer: &RecordingObserver) -> Vec<ImpairmentKind> {
    observer.impairments()
}

// ── Site::StreamOpen ───────────────────────────────────────────────────

/// A reject at the open site creates no peer stream at all, and the source
/// is stopped with the code.
#[tokio::test]
#[cfg(feature = "draft14")]
async fn reject_at_stream_open_never_opens_a_peer_stream() {
    common::init_crypto();

    let relay = Arc::new(FakeRelay::bind(b"moq-00"));
    let observer = Arc::new(RecordingObserver::new());
    let hook = Arc::new(RejectAtOpen::default());
    let proxy = common::spawn_proxy(
        relay.addr,
        Arc::clone(&observer) as Arc<dyn ProxyObserver>,
        Arc::clone(&hook) as Arc<dyn ProxyHook>,
    );

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, b"moq-00").await;
    let relay_conn = tokio::time::timeout(common::TIMEOUT, relay.connection())
        .await
        .expect("the proxy connected upstream");

    let stream = subgroup_stream(ALLOWED_ALIAS);
    let mut send = client_conn.open_uni().await.expect("open_uni");
    send.write_all(&stream).await.expect("write");

    // The source half of the claim: the client's stream is stopped, with
    // the hook's own code rather than quinn's drop-time 0.
    let stopped = tokio::time::timeout(common::TIMEOUT, send.stopped())
        .await
        .expect("the client's stream was stopped")
        .expect("stopped");
    assert_eq!(
        stopped.map(|c| c.into_inner()),
        Some(OPEN_REJECT_CODE),
        "the source must observe STOP_SENDING carrying the rejection code"
    );

    // The destination half: nothing was ever opened towards the relay.
    // Negative claim, so it takes a window.
    common::assert_no_uni_stream_for(&relay_conn, Duration::from_millis(500)).await;

    assert_eq!(hook.opens.lock().expect("opens").len(), 1, "on_stream_open fired once");
    let applied = observer.applied();
    assert_eq!(
        applied,
        vec![(
            Site::StreamOpen,
            ActionKind::Reject,
            Effect::StreamRejected { code: OPEN_REJECT_CODE }
        )],
        "exactly one ActionApplied, at the open site: {:?}",
        observer.events()
    );
    assert!(observer.refused().is_empty(), "nothing was refused: {:?}", observer.refused());
    assert_eq!(
        proxy.counters().framers_created,
        0,
        "a stream rejected before open is never framed"
    );

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

// ── Site::StreamHeader ─────────────────────────────────────────────────

/// A reject at the header site forwards no header byte: the peer stream
/// exists, and is reset having carried nothing.
#[tokio::test]
#[cfg(feature = "draft14")]
async fn reject_at_the_stream_header_forwards_no_header_bytes() {
    common::init_crypto();

    let relay = Arc::new(FakeRelay::bind(b"moq-00"));
    let observer = Arc::new(RecordingObserver::new());
    let hook = Arc::new(RejectAtHeader::default());
    let proxy = common::spawn_proxy(
        relay.addr,
        Arc::clone(&observer) as Arc<dyn ProxyObserver>,
        Arc::clone(&hook) as Arc<dyn ProxyHook>,
    );

    let relay_for_task = Arc::clone(&relay);
    let upstream = tokio::spawn(async move {
        let mut recv = relay_for_task.accept_uni().await;
        common::drain(&mut recv).await
    });

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, b"moq-00").await;
    let stream = subgroup_stream(ALLOWED_ALIAS);
    let mut send = client_conn.open_uni().await.expect("open_uni");
    send.write_all(&stream).await.expect("write");

    let (bytes, ending) = tokio::time::timeout(common::TIMEOUT, upstream)
        .await
        .expect("the upstream stream terminated")
        .expect("join");

    assert_eq!(
        ending,
        Ending::Reset(HEADER_REJECT_CODE),
        "the peer stream is reset with the hook's code"
    );
    assert_eq!(bytes, 0, "not one header byte may be forwarded before the reset");

    let stopped = tokio::time::timeout(common::TIMEOUT, send.stopped())
        .await
        .expect("the client's stream was stopped")
        .expect("stopped");
    assert_eq!(
        stopped.map(|c| c.into_inner()),
        Some(HEADER_REJECT_CODE),
        "the source is stopped with the same code"
    );

    assert_eq!(
        hook.headers.lock().expect("headers").as_slice(),
        &[ALLOWED_ALIAS],
        "on_stream_header saw the stream's real track alias"
    );
    // `StreamAction::Open` at the open site is itself an applied action,
    // so the expected trace is two entries: the open the hook allowed,
    // then the reject it took once it could see the track.
    assert_eq!(
        observer.applied(),
        vec![
            (Site::StreamOpen, ActionKind::Open, Effect::ForwardedVerbatim),
            (
                Site::StreamHeader,
                ActionKind::Reject,
                Effect::StreamRejected { code: HEADER_REJECT_CODE }
            )
        ],
        "the open is allowed and the header is rejected, in that order: {:?}",
        observer.events()
    );

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

/// Two streams, one rejected by track alias — declared with
/// `Interest::STREAMS` **alone** and observed with a **non-event**
/// observer.
///
/// Both of those are load-bearing. Without the structural
/// `STREAMS ⊇ OBJECTS` implication the session takes
/// `pipe_data_passthrough`, where there is no framer and therefore no
/// header decision, and *both* streams would be forwarded whole — the
/// rejection would become a silent no-op rather than a refusal. Attaching a
/// recording observer would
/// hide that, because `objects_enabled` keeps an `observer_enabled ||`
/// term, so every assertion here is made on the wire instead.
#[tokio::test]
#[cfg(feature = "draft14")]
async fn a_track_targeted_reject_only_rejects_that_track() {
    common::init_crypto();

    let relay = Arc::new(FakeRelay::bind(b"moq-00"));
    let hook = Arc::new(RejectOneTrack::default());
    let proxy = common::spawn_proxy(
        relay.addr,
        Arc::new(NoOpProxyObserver),
        Arc::clone(&hook) as Arc<dyn ProxyHook>,
    );

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, b"moq-00").await;

    // Stream 1: the allowed track. Written and drained to completion
    // before stream 2 is opened, so the accept order at the proxy — and
    // therefore the order the relay sees the two forwarded streams in — is
    // not a race.
    let allowed = subgroup_stream(ALLOWED_ALIAS);
    let relay_for_task = Arc::clone(&relay);
    let first = tokio::spawn(async move {
        let mut recv = relay_for_task.accept_uni().await;
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        let ending = loop {
            match recv.read(&mut buf).await {
                Ok(Some(n)) => got.extend_from_slice(&buf[..n]),
                Ok(None) => break Ending::Fin,
                Err(quinn::ReadError::Reset(code)) => break Ending::Reset(code.into_inner()),
                Err(e) => panic!("unexpected read error: {e:?}"),
            }
        };
        (got, ending)
    });

    let mut send_a = client_conn.open_uni().await.expect("open_uni A");
    send_a.write_all(&allowed).await.expect("write A");
    send_a.finish().expect("finish A");

    let (got, ending) = tokio::time::timeout(common::TIMEOUT, first)
        .await
        .expect("the allowed track reached the relay")
        .expect("join");
    assert_eq!(ending, Ending::Fin, "the allowed track ends cleanly");
    assert_eq!(got, allowed, "the allowed track is forwarded byte-identically");

    // Stream 2: the banned track.
    let banned = subgroup_stream(BANNED_ALIAS);
    let relay_for_task = Arc::clone(&relay);
    let second = tokio::spawn(async move {
        let mut recv = relay_for_task.accept_uni().await;
        common::drain(&mut recv).await
    });

    let mut send_b = client_conn.open_uni().await.expect("open_uni B");
    send_b.write_all(&banned).await.expect("write B");

    let (bytes, ending) = tokio::time::timeout(common::TIMEOUT, second)
        .await
        .expect("the banned track's stream terminated")
        .expect("join");
    assert_eq!(ending, Ending::Reset(HEADER_REJECT_CODE), "the banned track is reset");
    assert_eq!(bytes, 0, "the banned track forwards nothing");

    assert_eq!(
        hook.seen.lock().expect("seen").as_slice(),
        &[ALLOWED_ALIAS, BANNED_ALIAS],
        "on_stream_header fired once per stream, in order — a STREAMS-only hook that took the \
         byte-pump path would have seen nothing at all"
    );

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

/// `Interest::STREAMS` alone frames the stream and fires the header hook.
///
/// The positive half of the `STREAMS ⊇ OBJECTS` claim: the rejection test
/// above shows a header decision is honoured, and this one shows the hook is
/// consulted at all. A non-event observer is used so that `objects_enabled`
/// can only be true because `STREAMS` contains `OBJECTS`.
#[tokio::test]
#[cfg(feature = "draft14")]
async fn streams_alone_frames_the_stream_and_fires_the_header_hook() {
    common::init_crypto();

    let relay = Arc::new(FakeRelay::bind(b"moq-00"));
    let hook = Arc::new(WatchHeaders::default());
    let proxy = common::spawn_proxy(
        relay.addr,
        Arc::new(NoOpProxyObserver),
        Arc::clone(&hook) as Arc<dyn ProxyHook>,
    );

    let relay_for_task = Arc::clone(&relay);
    let uni = tokio::spawn(async move { relay_for_task.timed_uni().await });

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, b"moq-00").await;
    let stream = subgroup_stream(ALLOWED_ALIAS);
    let mut send = client_conn.open_uni().await.expect("open_uni");
    for piece in stream.chunks(37) {
        send.write_all(piece).await.expect("write");
    }
    send.finish().expect("finish");

    let rx = tokio::time::timeout(common::TIMEOUT, uni)
        .await
        .expect("the relay saw the stream")
        .expect("join");
    let got = rx.wait_for_bytes(stream.len()).await;
    assert_eq!(got, stream, "a STREAMS-only session still forwards byte-identically");
    assert_eq!(rx.wait_for_ending().await, Ending::Fin, "and ends cleanly");

    assert_eq!(
        hook.seen.lock().expect("seen").as_slice(),
        // `0x14` is the explicit-subgroup-ID stream type, so the subgroup
        // ID really is present and really is 0 — not the `None` the
        // implicit modes report.
        &[(ALLOWED_ALIAS, Some(0u64), Some(0x80u8))],
        "on_stream_header must fire exactly once, with the header's own fields"
    );

    // The falsifiable companion: framing happened. A `STREAMS = 1 << 3`
    // build takes `pipe_data_passthrough`, where no framer is ever built.
    assert_eq!(
        proxy.counters().framers_created,
        1,
        "Interest::STREAMS must frame the stream: exactly one ObjectFramer"
    );

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

// ── drafts 17-20: the control plane is the unidirectional pair ─────────

/// A draft-19 unified SETUP driven down a **unidirectional** stream is
/// shown to `on_control_message`, the session reports nothing, and the
/// bytes are forwarded intact.
///
/// Drafts 17, 18, 19 and 20 carry the control plane on a pair of unidirectional
/// streams — each peer opens one and begins it with SETUP — and carry
/// requests on bidirectional streams. `session.rs` reads the stream type
/// varint (0x2F00, which is SETUP's own message type, so nothing is
/// stripped) to tell one from the other, and pipes the pair through the
/// control path. A hook that asked for `Interest::CONTROL` therefore sees
/// SETUP here, exactly as it does on the drafts that put control on a
/// bidirectional stream.
///
/// While the engine took the first bidirectional stream to be the control
/// stream on every draft, this row asserted the opposite — an empty log and
/// one `ControlStreamMisidentified` per session — and that impairment kind
/// no longer exists.
#[tokio::test]
#[cfg(feature = "draft19")]
async fn a_draft19_setup_on_a_uni_stream_is_shown_to_the_control_hook() {
    common::init_crypto();

    let draft = DraftVersion::Draft19;
    let setup = {
        use moqtap_codec::draft19::message::{ControlMessage, Setup};
        let mut buf = Vec::new();
        AnyControlMessage::Draft19(ControlMessage::Setup(Setup { options: Vec::new() }))
            .encode(&mut buf)
            .expect("encode draft-19 SETUP");
        // 0x2F00 as a two-byte MoQT varint (draft-17 Section 1.4.1) is
        // `0x80 | 0x2F, 0x00`. Under RFC 9000's two-bit prefix it would be
        // `0x6F 0x00`, which no draft-19 peer can read.
        assert_eq!(&buf[..2], &[0xAF, 0x00], "the unified SETUP's type is 0x2F00");
        buf
    };

    let relay = Arc::new(FakeRelay::bind(b"moqt-19"));
    let observer = Arc::new(RecordingObserver::new());
    let hook = Arc::new(WatchControl::default());
    let proxy = common::spawn_proxy_with(
        common::session_config(draft, relay.addr),
        b"moqt-19",
        Arc::clone(&observer) as Arc<dyn ProxyObserver>,
        Arc::clone(&hook) as Arc<dyn ProxyHook>,
    );

    let relay_for_task = Arc::clone(&relay);
    let uni = tokio::spawn(async move { relay_for_task.timed_uni().await });

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, b"moqt-19").await;
    let mut send = client_conn.open_uni().await.expect("open_uni");
    send.write_all(&setup).await.expect("write SETUP");
    send.finish().expect("finish");

    let rx = tokio::time::timeout(common::TIMEOUT, uni)
        .await
        .expect("the relay saw the stream")
        .expect("join");
    let got = rx.wait_for_bytes(setup.len()).await;
    assert_eq!(
        got, setup,
        "a control message the proxy cannot recognise on this topology must still be forwarded \
         byte-for-byte"
    );

    let seen = hook.seen.lock().expect("seen").clone();
    assert_eq!(seen.len(), 1, "on_control_message fired exactly once: {seen:?}");
    assert!(
        matches!(
            &seen[0],
            AnyControlMessage::Draft19(moqtap_codec::draft19::message::ControlMessage::Setup(_))
        ),
        "the hook was shown the SETUP that arrived on the unidirectional control stream: {seen:?}"
    );
    assert_eq!(
        impairments(&observer),
        Vec::new(),
        "a session that identifies its control plane reports nothing",
    );

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

/// The paired draft-16 run: the control plane really is the first
/// bidirectional stream there, `on_control_message` sees CLIENT_SETUP, and
/// the session reports nothing.
///
/// Without this half the row above would be satisfied by a proxy that piped
/// *every* unidirectional stream through the control path — which would
/// hand every subgroup header to the control decoder — rather than by one
/// that identifies the control plane per draft.
#[tokio::test]
#[cfg(feature = "draft16")]
async fn a_draft16_client_setup_is_shown_to_the_control_hook_with_no_impairment() {
    common::init_crypto();

    let draft = DraftVersion::Draft16;
    let client_setup = {
        use moqtap_codec::draft16::message::{ClientSetup, ControlMessage};
        let mut buf = Vec::new();
        AnyControlMessage::Draft16(ControlMessage::ClientSetup(ClientSetup {
            parameters: Vec::new(),
        }))
        .encode(&mut buf)
        .expect("encode draft-16 CLIENT_SETUP");
        assert_eq!(buf[0], 0x20, "CLIENT_SETUP's type is 0x20 on draft-16");
        buf
    };

    let relay = Arc::new(FakeRelay::bind(b"moqt-16"));
    let observer = Arc::new(RecordingObserver::new());
    let hook = Arc::new(WatchControl::default());
    let proxy = common::spawn_proxy_with(
        common::session_config(draft, relay.addr),
        b"moqt-16",
        Arc::clone(&observer) as Arc<dyn ProxyObserver>,
        Arc::clone(&hook) as Arc<dyn ProxyHook>,
    );

    let relay_for_task = Arc::clone(&relay);
    let upstream = tokio::spawn(async move {
        let (_send, mut recv) = relay_for_task.accept_bi().await;
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        while got.len() < 3 {
            match recv.read(&mut buf).await {
                Ok(Some(n)) => got.extend_from_slice(&buf[..n]),
                Ok(None) => break,
                Err(e) => panic!("relay control read: {e:?}"),
            }
        }
        got
    });

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, b"moqt-16").await;
    let (mut send, _recv) = client_conn.open_bi().await.expect("open_bi");
    send.write_all(&client_setup).await.expect("write CLIENT_SETUP");

    let got = tokio::time::timeout(common::TIMEOUT, upstream)
        .await
        .expect("the relay saw the control stream")
        .expect("join");
    assert_eq!(got, client_setup, "the control frame reaches the relay unchanged");

    let seen = hook.seen.lock().expect("seen").clone();
    assert_eq!(seen.len(), 1, "on_control_message fired exactly once: {seen:?}");
    assert!(
        matches!(
            &seen[0],
            AnyControlMessage::Draft16(
                moqtap_codec::draft16::message::ControlMessage::ClientSetup(_)
            )
        ),
        "the hook was shown the CLIENT_SETUP: {seen:?}"
    );
    assert_eq!(
        impairments(&observer),
        Vec::new(),
        "draft-16 puts control on the first bidirectional stream, which is where this run \
         wrote it, so there is nothing to report",
    );

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

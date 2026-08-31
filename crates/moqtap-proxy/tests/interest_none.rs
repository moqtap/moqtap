//! `Interest::NONE` keeps the zero-parse byte pump bit-for-bit.
//!
//! # Why this file asserts on counters and not on bytes
//!
//! The framing guarantee is that the *framed* path is byte-identical to the
//! byte pump: every byte written to the destination comes out of
//! [`ObjectFramer::poll`](moqtap_proxy::framer::ObjectFramer::poll), and
//! the framer only decides where the boundaries are. That guarantee is
//! exactly what makes the fast-path claim unprovable by bytes — a test
//! that compares forwarded bytes passes just as green when
//! `Interest::NONE` has been routed through the framer, the control
//! parser and the datagram decoder.
//!
//! So the proof rests on [`Counters`], which are incremented **only**
//! inside code the fast path never reaches. An `Interest::NONE` session
//! that moved a subgroup stream, a fetch stream, four datagrams and a
//! SETUP/SUBSCRIBE exchange and still reports `Counters::default()` did
//! not merely produce the right bytes; it never entered the machinery
//! that could have produced the wrong ones.
//!
//! Counters are **session-scoped**, read through
//! `SpawnedProxy::counters()`, so a sibling test in this binary running on
//! another thread cannot spoil the assertion and no `#[ignore]` pressure
//! ever builds up.
//!
//! # The three claims, and the ablation that falsifies each
//!
//! | Test | Claim | Ablation that must turn it red |
//! |---|---|---|
//! | [`interest_none_touches_no_slow_path`] | no framer, no parser, no decoder, no release thread | `session.rs`: `objects_enabled = true` unconditionally |
//! | [`interest_none_allocates_no_control_parser`] | `control_parsers_created == 0` | `session.rs`: drop `ctx.control_parse &&` from `pipe_control_passthrough`'s parser construction |
//! | [`an_observer_does_not_turn_on_the_object_hook`] | framing gate ≠ hook gate | `session.rs`: gate `on_object` on `objects_enabled` instead of `object_hook` |
//!
//! The first ablation is the argument for counters existing at all: it
//! must turn *this* file red while the byte-equality tests stay green,
//! and the contrast is the proof. Measured, on the tree this file landed
//! on: under `objects_enabled = true`, `framer_tests` (16),
//! `object_framing_acceptance` (7), `proxy_forward` (1), `proxy_hook_rewrite`
//! (1), `proxy_reset` (5) and `common_harness` (4) all stayed green and
//! only `interest_none_touches_no_slow_path` went red on its counters.
//!
//! One test in `proxy_objects.rs` goes red too, and it is the exception
//! that states the rule: `byte_pump_path_forwards_unchanged_without_an_observer`
//! deliberately FINs nothing and stops ten bytes short of the end, so the
//! byte pump forwards a half-object the framed path would still be
//! holding. It is a *path detector* built out of the one input on which
//! the two paths are not byte-identical, not a byte-equality test — and
//! constructing that input is precisely the contortion these counters
//! exist to make unnecessary.
//!
//! # `moqt-19` is load-bearing
//!
//! `session.rs`'s `draft_is_fixed` is derived from the client ALPN, and
//! the control parser is built only when the draft is fixed. A session
//! whose ALPN does not resolve — `moq-00`, which
//! [`common::spawn_proxy`] defaults to — builds no parser *even in the
//! ablated build*, so `control_parsers_created == 0` would hold for the
//! wrong reason and the ablation would come back green.
//! [`the_pinned_alpn_resolves_to_a_draft`] pins that precondition
//! directly rather than leaving it to a comment.
//!
//! # The fixtures come from a local encoder
//!
//! Every byte this file puts on the wire is assembled here, from the
//! draft's documented layout, sharing no code with the framer, the
//! control parser or the datagram decoder under test. The fixtures are
//! then shown to be real draft-19 wire bytes by
//! [`the_fixtures_are_real_draft19_wire_bytes`] — otherwise "an
//! `Interest::NONE` session parsed nothing" would be trivially true of a
//! session handed noise.

//! `ALPN` is `moqt-19` and `DRAFT` is draft-19 — the ALPN is load-bearing
//! for `interest_none_allocates_no_control_parser`, so the draft cannot be
//! swapped for whichever one a row happens to compile. The file is gated
//! on draft-19 instead.

#![cfg(feature = "draft19")]

mod common;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::Bytes;

use moqtap_codec::dispatch::{AnyControlMessage, AnyDatagramHeader};
use moqtap_codec::draft19::message::ControlMessage as Draft19Message;
use moqtap_codec::version::DraftVersion;

use moqtap_proxy::action::{Action, Interest, StreamAction, StreamEnd};
use moqtap_proxy::event::DataStreamHeaderKind;
use moqtap_proxy::hook::{FrameCtx, NoOpHook, ObjectCtx, ProxyHook, StreamCtx};
use moqtap_proxy::instrument::{release_timer_started, Counters};
use moqtap_proxy::observer::{NoOpProxyObserver, ProxyObserver};
use moqtap_proxy::parser::control::{ControlStreamParser, ParseResult, ParsedFrame, ParsedItem};

use common::{FakeRelay, RecordingObserver, SpawnedProxy};

/// The ALPN every session in this file negotiates.
///
/// Pinned rather than defaulted: see the module docs. `moq-00` would make
/// `interest_none_allocates_no_control_parser` unfalsifiable.
const ALPN: &[u8] = b"moqt-19";

/// The draft `ALPN` resolves to.
const DRAFT: DraftVersion = DraftVersion::Draft19;

/// Cap for `read_to_end` on a forwarded stream. Every fixture here is a
/// few kilobytes.
const READ_CAP: usize = 1024 * 1024;

// ============================================================
// An encoder independent of everything under test
// ============================================================

/// QUIC variable-length integer, RFC 9000 §16.
fn put_varint(out: &mut Vec<u8>, value: u64) {
    // Every fixture in this file is draft-19, which uses MoQT's
    // variable-length integer (Section 1.4.1): the length is the number of
    // leading 1 bits in the first byte, and one byte carries 0-127.
    let width = (1..=8usize).find(|w| value < 1u64 << (7 * w)).unwrap_or(9);
    if width == 9 {
        out.push(0xFF);
        out.extend_from_slice(&value.to_be_bytes());
        return;
    }
    let prefix = (((1u16 << (width - 1)) - 1) << (9 - width)) as u8;
    let combined = ((prefix as u64) << (8 * (width - 1))) | value;
    for i in (0..width).rev() {
        out.push((combined >> (8 * i)) as u8);
    }
}

/// Draft-19 subgroup stream type with an explicit Subgroup ID and no
/// extension block.
const SUBGROUP_STREAM_TYPE: u8 = 0x14;

/// A draft-19 subgroup stream: track alias 1, group 0, subgroup 0,
/// publisher priority 128, then one object per `(object_id, payload)`.
///
/// Draft-19 delta-encodes Object IDs after the first, and carries no
/// extension block for stream type `0x14`, so an object is
/// `varint(id delta) varint(payload length) payload`.
fn subgroup_stream(objects: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut out = vec![SUBGROUP_STREAM_TYPE, 0x01, 0x00, 0x00, 0x80];
    let mut prev: Option<u64> = None;
    for (object_id, payload) in objects {
        let id_field = match prev {
            Some(previous) => object_id - previous - 1,
            None => *object_id,
        };
        put_varint(&mut out, id_field);
        put_varint(&mut out, payload.len() as u64);
        out.extend_from_slice(payload);
        prev = Some(*object_id);
    }
    out
}

/// The subgroup stream every session in this file carries: four objects,
/// one of them large enough to span several reads.
fn the_subgroup_stream() -> Vec<u8> {
    subgroup_stream(&[
        (0, b"deadbeef".to_vec()),
        (1, b"cafe".to_vec()),
        (2, vec![0xAB; 5000]),
        (3, b"tail".to_vec()),
    ])
}

/// The Object IDs [`the_subgroup_stream`] encodes.
const SUBGROUP_OBJECT_IDS: &[u64] = &[0, 1, 2, 3];

/// A draft-19 fetch stream: type `0x05`, request ID 9, then objects laid
/// out the way drafts 07-14 do.
///
/// Drafts 15-19 have no fetch object codec, so nothing in the proxy can
/// interpret these bytes on this draft — which is the point. Under
/// `Interest::NONE` they must arrive intact without anything even trying.
fn the_fetch_stream() -> Vec<u8> {
    let mut out = vec![0x05, 0x09];
    for (group_id, object_id) in [(7u64, 0u64), (7, 1), (8, 0)] {
        put_varint(&mut out, group_id);
        put_varint(&mut out, 0); // subgroup
        put_varint(&mut out, object_id);
        out.push(128); // publisher priority
        put_varint(&mut out, 0); // extension block length
        put_varint(&mut out, 4); // payload length
        out.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    }
    out
}

/// One draft-19 object datagram, type `0x00`: explicit Object ID,
/// explicit publisher priority, no properties, no status.
fn datagram(track_alias: u64, group_id: u64, object_id: u64, payload: &[u8]) -> Bytes {
    let mut out = vec![0x00];
    put_varint(&mut out, track_alias);
    put_varint(&mut out, group_id);
    put_varint(&mut out, object_id);
    out.push(128);
    out.extend_from_slice(payload);
    Bytes::from(out)
}

/// Four datagrams, each distinguishable from the others: they vary track
/// alias, group ID, object ID and payload, so a path that dropped one,
/// duplicated one or reordered them cannot pass by accident.
fn the_datagrams() -> Vec<Bytes> {
    vec![
        datagram(1, 0, 0, b"one"),
        datagram(1, 0, 1, b"two"),
        datagram(1, 1, 0, b"three"),
        datagram(2, 9, 4, b"four"),
    ]
}

/// A draft-19 control message: type varint, 16-bit big-endian length,
/// payload. Draft-11 onwards use `Length(16)` rather than a varint.
fn control_message(msg_type: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    put_varint(&mut out, msg_type);
    out.extend_from_slice(&(u16::try_from(payload.len()).expect("fixture fits u16")).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// SETUP, which draft-19 uses for both the client's and the server's half
/// of the handshake (draft-14's CLIENT_SETUP / SERVER_SETUP pair became
/// one message type at draft-17).
const SETUP_TYPE: u64 = 0x2F00;
/// SUBSCRIBE.
const SUBSCRIBE_TYPE: u64 = 0x03;

/// A SETUP carrying delta-encoded Setup Options.
///
/// Only even keys are accepted: draft-19's KVP convention gives even keys
/// a bare varint value and odd keys a length-prefixed one, and this
/// encoder writes the varint form.
fn setup(options: &[(u64, u64)]) -> Vec<u8> {
    let mut payload = Vec::new();
    let mut prev_key = 0u64;
    for (key, value) in options {
        assert!(key.is_multiple_of(2), "odd Setup Option keys take a length-prefixed value");
        put_varint(&mut payload, key - prev_key);
        prev_key = *key;
        put_varint(&mut payload, *value);
    }
    control_message(SETUP_TYPE, &payload)
}

/// A SUBSCRIBE with no parameters.
fn subscribe(request_id: u64, namespace: &[&[u8]], track_name: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    put_varint(&mut payload, request_id);
    put_varint(&mut payload, namespace.len() as u64);
    for element in namespace {
        put_varint(&mut payload, element.len() as u64);
        payload.extend_from_slice(element);
    }
    put_varint(&mut payload, track_name.len() as u64);
    payload.extend_from_slice(track_name);
    put_varint(&mut payload, 0); // parameter count
    control_message(SUBSCRIBE_TYPE, &payload)
}

/// What the client sends on the control stream: SETUP, then SUBSCRIBE.
fn client_control_bytes() -> Vec<u8> {
    let mut out = setup(&[(0x02, 5), (0x04, 3600)]);
    out.extend_from_slice(&subscribe(1, &[b"live"], b"video"));
    out
}

/// What the relay answers with, so the exchange is bidirectional and both
/// `pipe_control` directions are entered rather than only one.
fn relay_control_bytes() -> Vec<u8> {
    setup(&[(0x02, 5)])
}

// ============================================================
// Hooks
// ============================================================

/// A hook that declares [`Interest::NONE`] and treats *any* call as the
/// defect it is.
///
/// Stronger than a counting hook, which cannot distinguish "not called"
/// from "called and ignored", and stronger than a hook that guards only
/// `on_object`: all six methods trip, so a gate that leaks at the stream,
/// control or datagram site is caught by the same fixture.
///
/// The flag is set *before* the panic so the failure is diagnosable even
/// though the panic unwinds inside a spawned forwarding task, where a
/// dropped `JoinHandle` swallows it.
struct SilentHook {
    fired: Arc<AtomicBool>,
}

impl SilentHook {
    fn new() -> (Arc<Self>, Arc<AtomicBool>) {
        let fired = Arc::new(AtomicBool::new(false));
        (Arc::new(Self { fired: Arc::clone(&fired) }), fired)
    }

    fn trip(&self, method: &str) -> ! {
        self.fired.store(true, Ordering::SeqCst);
        panic!("{method} fired on a hook whose interest() is Interest::NONE");
    }
}

impl ProxyHook for SilentHook {
    fn interest(&self) -> Interest {
        Interest::NONE
    }

    fn on_control_message(
        &self,
        _cx: &FrameCtx<'_>,
        _msg: &AnyControlMessage,
        _raw: &[u8],
    ) -> Action {
        self.trip("on_control_message")
    }

    fn on_stream_open(&self, _cx: &StreamCtx<'_>) -> StreamAction {
        self.trip("on_stream_open")
    }

    fn on_stream_header(
        &self,
        _cx: &StreamCtx<'_>,
        _header: &DataStreamHeaderKind,
    ) -> StreamAction {
        self.trip("on_stream_header")
    }

    fn on_object(&self, _cx: &ObjectCtx<'_>, _raw: &[u8]) -> Action {
        self.trip("on_object")
    }

    fn on_datagram(
        &self,
        _cx: &FrameCtx<'_>,
        _header: Option<&AnyDatagramHeader>,
        _raw: &[u8],
    ) -> Action {
        self.trip("on_datagram")
    }

    fn on_stream_end(&self, _cx: &StreamCtx<'_>, _end: StreamEnd) -> Action {
        self.trip("on_stream_end")
    }
}

/// A hook that declares [`Interest::OBJECTS`] and counts what it is asked.
///
/// The control half of [`an_observer_does_not_turn_on_the_object_hook`]:
/// a gate that is permanently dead would satisfy the first half by
/// accident, and only a session of the same shape whose hook *is* called
/// rules that out.
struct CountingHook {
    calls: Arc<AtomicUsize>,
}

impl CountingHook {
    fn new() -> (Arc<Self>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        (Arc::new(Self { calls: Arc::clone(&calls) }), calls)
    }
}

impl ProxyHook for CountingHook {
    fn interest(&self) -> Interest {
        Interest::OBJECTS
    }

    fn on_object(&self, _cx: &ObjectCtx<'_>, _raw: &[u8]) -> Action {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Action::Pass
    }
}

// ============================================================
// Plumbing
// ============================================================

/// Bring up a relay and a proxy session on `ALPN`, and connect a client to
/// it.
///
/// Returns the relay's accepted connection too: the proxy's upstream
/// connect is awaited by the session before it spawns any forwarding
/// task, so a test that never accepts on the relay hits
/// `upstream_connect_timeout_secs` instead of running.
async fn bring_up(
    observer: Arc<dyn ProxyObserver>,
    hook: Arc<dyn ProxyHook>,
) -> (FakeRelay, SpawnedProxy, quinn::Endpoint, quinn::Connection, quinn::Connection) {
    common::init_crypto();
    let relay = FakeRelay::bind(ALPN);
    let proxy =
        common::spawn_proxy_with(common::session_config(DRAFT, relay.addr), ALPN, observer, hook);
    let (client_ep, client_conn) = common::connect_client(proxy.addr, ALPN).await;
    let relay_conn = relay.connection().await;
    (relay, proxy, client_ep, client_conn, relay_conn)
}

/// Read exactly `want` bytes, or say so rather than hanging.
async fn read_exact(recv: &mut quinn::RecvStream, want: usize) -> Vec<u8> {
    let mut buf = vec![0u8; want];
    tokio::time::timeout(common::TIMEOUT, recv.read_exact(&mut buf))
        .await
        .expect("the far end received the control bytes within the timeout")
        .expect("read_exact");
    buf
}

/// Send one uni stream and read it back off the relay, whole.
async fn round_trip_uni(
    client_conn: &quinn::Connection,
    relay: &FakeRelay,
    stream: &[u8],
) -> Vec<u8> {
    let mut send = client_conn.open_uni().await.expect("open_uni");
    // Small writes so the forwarding path is exercised across chunk
    // boundaries rather than handed the whole stream in one read.
    for piece in stream.chunks(64) {
        send.write_all(piece).await.expect("write");
    }
    send.finish().expect("finish");

    let mut recv = relay.accept_uni().await;
    tokio::time::timeout(common::TIMEOUT, recv.read_to_end(READ_CAP))
        .await
        .expect("the relay received the whole stream within the timeout")
        .expect("read_to_end")
}

/// Collect `n` datagrams off `conn`, sorted so the comparison does not
/// assume an ordering QUIC does not promise for datagrams.
async fn collect_datagrams(conn: &quinn::Connection, n: usize) -> Vec<Bytes> {
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let datagram = tokio::time::timeout(common::TIMEOUT, conn.read_datagram())
            .await
            .unwrap_or_else(|_| panic!("datagram {i} of {n} did not arrive"))
            .expect("read_datagram");
        out.push(datagram);
    }
    out.sort();
    out
}

// ============================================================
// 1. The fixtures are real wire bytes
// ============================================================

/// Nothing below can mean anything if the "traffic" is noise: "an
/// `Interest::NONE` session parsed nothing" is trivially true of a session
/// handed bytes nobody could parse. The fixtures are built by this file's
/// own encoder and decoded here by the codec, so the two agree by
/// measurement rather than by construction.
/// The decoded frame behind one parsed item.
///
/// This file's fixtures are hand-built draft-19 wire bytes whose whole
/// purpose is to decode, so a `Refused` is the failure rather than a case:
/// the panic names the Message Type the decoder would not read.
fn frame(item: &ParsedItem) -> &ParsedFrame {
    match item {
        ParsedItem::Frame(f) => f,
        ParsedItem::Refused(r) => {
            panic!("the codec refused a fixture frame; Message Type {:#x}", r.type_id)
        }
    }
}

#[test]
fn the_fixtures_are_real_draft19_wire_bytes() {
    let mut parser = ControlStreamParser::new(DRAFT);
    match parser.feed(&client_control_bytes()) {
        ParseResult::Framed(frames) => {
            assert_eq!(frames.len(), 2, "the client's control bytes are two whole messages");
            assert!(
                matches!(
                    frame(&frames[0]).message,
                    AnyControlMessage::Draft19(Draft19Message::Setup(_))
                ),
                "the first control message is a SETUP, got {:?}",
                frame(&frames[0]).message
            );
            assert!(
                matches!(
                    frame(&frames[1]).message,
                    AnyControlMessage::Draft19(Draft19Message::Subscribe(_))
                ),
                "the second control message is a SUBSCRIBE, got {:?}",
                frame(&frames[1]).message
            );
        }
        ParseResult::NeedMore => panic!("the client's control fixture is not two whole messages"),
    }

    let mut parser = ControlStreamParser::new(DRAFT);
    match parser.feed(&relay_control_bytes()) {
        ParseResult::Framed(frames) => {
            assert_eq!(frames.len(), 1, "the relay's control bytes are one whole message");
            assert!(
                matches!(
                    frame(&frames[0]).message,
                    AnyControlMessage::Draft19(Draft19Message::Setup(_))
                ),
                "the relay answers with a SETUP, got {:?}",
                frame(&frames[0]).message
            );
        }
        ParseResult::NeedMore => panic!("the relay's control fixture is not a whole message"),
    }

    for (i, raw) in the_datagrams().iter().enumerate() {
        let mut cursor = &raw[..];
        let header = AnyDatagramHeader::decode(DRAFT, &mut cursor)
            .unwrap_or_else(|e| panic!("datagram {i} is not a draft-19 datagram: {e}"));
        assert!(
            matches!(header, AnyDatagramHeader::Draft19(_)),
            "datagram {i} decoded as the wrong draft: {header:?}"
        );
    }

    // The subgroup fixture's own validity is measured end to end by
    // `an_observer_does_not_turn_on_the_object_hook`, which asserts the
    // proxy frames exactly `SUBGROUP_OBJECT_IDS` out of it.
    assert_eq!(the_subgroup_stream()[0], SUBGROUP_STREAM_TYPE);
}

/// The ALPN precondition, pinned rather than assumed.
///
/// `session.rs`'s `draft_is_fixed` is `DraftVersion::from_alpn(..).is_some()`
/// and the control parser is built only when the draft is fixed. If this
/// ALPN ever stopped resolving,
/// [`interest_none_allocates_no_control_parser`] would keep passing while
/// measuring nothing at all — its ablation would build no parser either.
#[test]
fn the_pinned_alpn_resolves_to_a_draft() {
    assert_eq!(
        DraftVersion::from_alpn(ALPN),
        Some(DRAFT),
        "interest_none_allocates_no_control_parser is unfalsifiable unless this ALPN resolves"
    );
}

// ============================================================
// 2. Interest::NONE touches no slow path
// ============================================================

/// One `Interest::NONE` session carrying every kind of traffic the proxy
/// forwards, asserting that all of it arrived and that no counter moved.
///
/// `hook` is driven twice by [`interest_none_touches_no_slow_path`]: once
/// as a plain [`NoOpHook`], once as a [`SilentHook`] that is *present* and
/// declares no interest — the case `proxy_objects.rs` could not express
/// before Hook v2, because it could only turn the observer off.
async fn no_slow_path_case(hook: Arc<dyn ProxyHook>) {
    let (relay, proxy, _client_ep, client_conn, relay_conn) =
        bring_up(Arc::new(NoOpProxyObserver), hook).await;

    // ── the control exchange, both directions ──────────────────────
    let client_control = client_control_bytes();
    let (mut client_send, mut client_recv) = client_conn.open_bi().await.expect("open_bi");
    client_send.write_all(&client_control).await.expect("write control");

    let (mut relay_send, mut relay_recv) = relay.accept_bi().await;
    let seen = read_exact(&mut relay_recv, client_control.len()).await;
    assert_eq!(seen, client_control, "the relay must receive the SETUP/SUBSCRIBE byte for byte");

    let relay_control = relay_control_bytes();
    relay_send.write_all(&relay_control).await.expect("write relay control");
    let seen = read_exact(&mut client_recv, relay_control.len()).await;
    assert_eq!(seen, relay_control, "the client must receive the relay's SETUP byte for byte");

    // ── a subgroup stream and a fetch stream ───────────────────────
    let subgroup = the_subgroup_stream();
    let seen = round_trip_uni(&client_conn, &relay, &subgroup).await;
    assert_eq!(seen, subgroup, "the subgroup stream must arrive byte-identical");

    let fetch = the_fetch_stream();
    let seen = round_trip_uni(&client_conn, &relay, &fetch).await;
    assert_eq!(seen, fetch, "the fetch stream must arrive byte-identical");

    // ── four datagrams ─────────────────────────────────────────────
    let mut sent = the_datagrams();
    for datagram in &sent {
        client_conn.send_datagram(datagram.clone()).expect("send_datagram");
    }
    let received = collect_datagrams(&relay_conn, sent.len()).await;
    sent.sort();
    assert_eq!(received, sent, "every datagram must arrive byte-identical");

    // ── the falsifiable half ───────────────────────────────────────
    let counters = proxy.counters();
    assert_eq!(
        counters,
        Counters::default(),
        "an Interest::NONE session with a non-event observer must touch no slow path; \
         real traffic moved through it, so a non-zero field names the path that ran"
    );

    // The release thread is process-wide, so `false` is the spoilable
    // direction — but nothing in this binary ever issues a `Delay` or a
    // `Hold`, and `arm_at` is the sole trigger, so no sibling test can
    // start it under us.
    assert!(!release_timer_started(), "an Interest::NONE session must start no release thread");

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

/// The headline claim of this file: a session that moved a subgroup stream,
/// a fetch stream, four datagrams and a SETUP/SUBSCRIBE exchange under
/// `Interest::NONE` delivered every byte and left every counter at zero.
///
/// *Ablation:* in `session.rs`, make `objects_enabled` unconditionally
/// `true`. This test must fail on `framers_created` / `framer_header_polls`
/// / `framer_object_polls` while every byte-equality assertion in the
/// suite — including the ones in this very test — still passes.
#[tokio::test]
async fn interest_none_touches_no_slow_path() {
    // Case 1: no hook worth the name, and a non-event observer.
    no_slow_path_case(Arc::new(NoOpHook)).await;

    // Case 2: a hook that is present and declares `Interest::NONE`. Every
    // one of its six methods panics, so "the hook was never consulted" is
    // asserted by the run surviving rather than by an absence nobody
    // checked.
    let (hook, fired) = SilentHook::new();
    no_slow_path_case(hook).await;
    assert!(
        !fired.load(Ordering::SeqCst),
        "no ProxyHook method may fire on a hook whose interest() is Interest::NONE"
    );
}

/// The eager `ControlStreamParser` allocation, which `Interest::NONE` must
/// not make.
///
/// Split out from [`interest_none_touches_no_slow_path`] because it is the
/// one claim with a precondition: it is only falsifiable when the client
/// ALPN resolves to a draft (see [`the_pinned_alpn_resolves_to_a_draft`]).
/// The control exchange runs in both directions so both `pipe_control`
/// tasks have entered their loops by the time the counter is read — a
/// parser is built at function entry, before any byte is examined, so a
/// direction that never started would hide the allocation.
///
/// *Ablation:* in `session.rs`, drop the `ctx.control_parse &&` term from
/// `pipe_control_passthrough`'s parser construction, restoring the
/// `draft_is_fixed`-only form. This test must fail.
#[tokio::test]
async fn interest_none_allocates_no_control_parser() {
    let (relay, proxy, _client_ep, client_conn, _relay_conn) =
        bring_up(Arc::new(NoOpProxyObserver), Arc::new(NoOpHook)).await;

    let client_control = client_control_bytes();
    let (mut client_send, mut client_recv) = client_conn.open_bi().await.expect("open_bi");
    client_send.write_all(&client_control).await.expect("write control");

    let (mut relay_send, mut relay_recv) = relay.accept_bi().await;
    let seen = read_exact(&mut relay_recv, client_control.len()).await;
    assert_eq!(seen, client_control);

    let relay_control = relay_control_bytes();
    relay_send.write_all(&relay_control).await.expect("write relay control");
    let seen = read_exact(&mut client_recv, relay_control.len()).await;
    assert_eq!(seen, relay_control);

    assert_eq!(
        proxy.counters().control_parsers_created,
        0,
        "a real SETUP/SUBSCRIBE exchange crossed both control directions and no \
         ControlStreamParser may have been built for it"
    );

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

// ============================================================
// 3. The framing gate is not the hook gate
// ============================================================

/// The `objects_enabled` / `object_hook` split, end to end: framing is
/// enabled by observation, but hook authority is enabled only by declared
/// object interest.
///
/// An observer attached to an `Interest::NONE` hook is today's default
/// deployment. `objects_enabled` must be true — `ProxyEvent::Object` is a
/// framing guarantee that fires for an observer alone — while the hook is
/// never asked and never has a returned `Action` honoured. Collapse the
/// two variables and a hook that declared no object interest silently
/// acquires the power to drop, delay and rewrite production traffic.
///
/// The first half proves the hook stays silent *while the stream is really
/// framed* (`framer_object_polls > 0` and one `ProxyEvent::Object` per
/// object); the second proves the gate is not simply dead, by running the
/// same session shape with `Interest::OBJECTS` and watching the hook fire
/// once per object.
///
/// *Ablation:* in `session.rs`'s `pipe_data_framed`, gate the `on_object`
/// call on `ctx.objects_enabled` instead of `ctx.object_hook`. The first
/// half must fail.
#[tokio::test]
async fn an_observer_does_not_turn_on_the_object_hook() {
    let stream = the_subgroup_stream();

    // ── half one: observer on, Interest::NONE, on_object must not fire ──
    let observer = Arc::new(RecordingObserver::new());
    let (hook, fired) = SilentHook::new();
    let (relay, proxy, _client_ep, client_conn, _relay_conn) =
        bring_up(Arc::clone(&observer) as Arc<dyn ProxyObserver>, hook).await;

    let mut send = client_conn.open_uni().await.expect("open_uni");
    for piece in stream.chunks(64) {
        send.write_all(piece).await.expect("write");
    }
    send.finish().expect("finish");

    let mut recv = relay.accept_uni().await;
    let seen = tokio::time::timeout(common::TIMEOUT, recv.read_to_end(READ_CAP)).await;

    // Asserted before the bytes: a hook that fired panics inside a spawned
    // forwarding task, which resets the peer stream, and "the relay saw a
    // reset" is a much worse diagnosis than "the hook fired".
    assert!(
        !fired.load(Ordering::SeqCst),
        "attaching an observer must not start calling a hook that declared Interest::NONE"
    );

    let seen =
        seen.expect("the relay received the stream within the timeout").expect("read_to_end");
    assert_eq!(seen, stream, "the framed stream must still arrive byte-identical");

    let counters = proxy.counters();
    assert!(
        counters.framer_object_polls > 0,
        "the stream must really have been framed, or the hook staying silent proves nothing \
         (counters: {counters:?})"
    );
    assert_eq!(
        observer.objects().iter().map(|m| m.object_id).collect::<Vec<_>>(),
        SUBGROUP_OBJECT_IDS.to_vec(),
        "one ProxyEvent::Object per object, in order — the observer's half of the split"
    );

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;

    // ── half two: the same shape with Interest::OBJECTS ────────────
    let observer = Arc::new(RecordingObserver::new());
    let (hook, calls) = CountingHook::new();
    let (relay, proxy, _client_ep, client_conn, _relay_conn) =
        bring_up(Arc::clone(&observer) as Arc<dyn ProxyObserver>, hook).await;

    let seen = round_trip_uni(&client_conn, &relay, &stream).await;
    assert_eq!(seen, stream, "Action::Pass must forward the stream byte-identically");

    assert_eq!(
        calls.load(Ordering::SeqCst),
        SUBGROUP_OBJECT_IDS.len(),
        "a hook that declares Interest::OBJECTS is asked once per object — without this the \
         first half would pass against a permanently dead gate"
    );
    assert_eq!(
        observer.objects().iter().map(|m| m.object_id).collect::<Vec<_>>(),
        SUBGROUP_OBJECT_IDS.to_vec(),
        "the observer still sees every object when the hook is armed"
    );

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

// ============================================================
// 4. Mirroring a client STOP_SENDING on the byte pump
// ============================================================

/// The application error code the client stops with. Not `0`, which is
/// what `RecvStream::drop` would send, so "mirrored" and "defaulted" can
/// never be confused.
const STOP_CODE: u64 = 0x05;

/// How long the idle relay waits to be stopped. On the passing path this
/// resolves in milliseconds; only a broken run waits it out.
const IDLE_STOP_WINDOW: std::time::Duration = std::time::Duration::from_millis(400);

/// The byte pump mirrors a client `STOP_SENDING` onto an idle relay — and
/// is still the byte pump.
///
/// `pipe_data_framed` and `pipe_data_passthrough` are separate functions
/// with separate `select!` loops, so `proxy_reset.rs`'s
/// `stop_sending_reaches_an_idle_upstream` says nothing about this one; a
/// watcher wired into the framed pipe alone would leave every
/// `Interest::NONE` deployment — the default one — unable to mirror a stop,
/// so the relay keeps producing a stream nobody is reading.
///
/// The two halves are asserted in one body on purpose. The watcher is the
/// one heap allocation the byte pump makes (see `pipe_data_passthrough`'s
/// rustdoc), and a "fix" that restored stop mirroring by routing this
/// session through the framer would satisfy the first half while destroying
/// the property the whole file exists to protect. `Counters::default()` is
/// what says it did not.
///
/// The relay writes a *prefix* of the subgroup stream and then goes silent:
/// no second write, no FIN, no reset. That silence is the test.
///
/// *Ablation (run, and it fails):* delete the `stop.watch()` branch from
/// `pipe_data_passthrough`'s `select!`. `observed` is then `None` — nothing
/// writes to the destination again, so nothing notices the `STOP_SENDING`.
#[tokio::test]
async fn an_interest_none_session_still_mirrors_a_stop() {
    let (hook, fired) = SilentHook::new();
    let (relay, proxy, _client_ep, client_conn, _relay_conn) =
        bring_up(Arc::new(NoOpProxyObserver), hook).await;

    let stream = the_subgroup_stream();
    let prefix = &stream[..stream.len() / 2];

    let mut relay_send = relay.open_uni().await;
    relay_send.write_all(prefix).await.expect("relay write");

    let mut recv = tokio::time::timeout(common::TIMEOUT, client_conn.accept_uni())
        .await
        .expect("the client saw the forwarded stream")
        .expect("accept_uni");

    // Read something first, so the stop lands on a stream the client was
    // already receiving rather than one it never accepted.
    let mut buf = [0u8; 4096];
    let first = tokio::time::timeout(common::TIMEOUT, recv.read(&mut buf))
        .await
        .expect("first read")
        .expect("read")
        .expect("not an immediate FIN");
    assert!(first > 0, "the prefix must arrive before the stop");

    recv.stop(quinn::VarInt::from_u64(STOP_CODE).unwrap()).expect("client stop");

    let observed = match tokio::time::timeout(IDLE_STOP_WINDOW, relay_send.stopped()).await {
        Ok(Ok(Some(code))) => Some(code.into_inner()),
        _ => None,
    };
    assert_eq!(
        observed,
        Some(STOP_CODE),
        "an Interest::NONE session must mirror the client's STOP_SENDING onto an idle relay. \
         `None` means the relay was never stopped and keeps producing a stream \
         nobody is reading"
    );

    assert!(
        !fired.load(Ordering::SeqCst),
        "mirroring a stop must not consult a hook that declared Interest::NONE"
    );

    // The falsifiable half: the session that just did all that is still the
    // byte pump. A watcher on the framed pipe only, plus an `objects_enabled`
    // widened to reach it, would pass everything above and fail here.
    assert_eq!(
        proxy.counters(),
        Counters::default(),
        "mirroring a stop must not enter the framer, the control parser or the datagram \
         decoder; a non-zero field names the path that ran"
    );
    assert!(!release_timer_started(), "mirroring a stop must start no release thread");

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

//! The shape of the hook API itself: dyn-compatibility, and the 0.3.x
//! adapter.
//!
//! # Why this file exists at all
//!
//! An earlier `tests/hook_tests.rs` was deleted: its five tests all called
//! a hook directly and asserted on its own return value, so every one of
//! them passes against a proxy that never calls the hook at all. Two
//! things went down with it and are rebuilt here, differently:
//!
//! * **Constraint 5** — `ProxyHook` has no `async fn`, no `async-trait`
//!   dependency and is object safe. [`the_hook_trait_is_dyn_compatible`]
//!   is the *only* guard on it in the whole suite. It is deliberately a
//!   compile-and-dispatch test rather than an end-to-end one: an `async
//!   fn` in the trait makes `Arc<dyn ProxyHook>` fail to build, so the
//!   assertion is that this file compiles, and dispatching every one of
//!   the seven methods through the `dyn` reference is what stops a
//!   defaulted method from being "covered" by never being called.
//! * **The 0.3.x adapter** — [`LegacyHook`]'s three preserved behaviours.
//!   Those are asserted on **forwarded bytes**, through a live session,
//!   never on what the adapter returned.
//!
//! # The discard is protected twice, and the two tests are not redundant
//!
//! A `LegacyProxyHook` that never asked for control mutation must not
//! start rewriting control traffic. Two independent things stop it:
//!
//! 1. [`LegacyHook::interest`] withholds [`Interest::CONTROL`], so the
//!    session takes `pipe_control_passthrough` and the hook is never
//!    consulted at all —
//!    [`legacy_hook_without_control_mutation_is_never_shown_the_control_stream`].
//! 2. [`LegacyHook::on_control_message`] discards a `Some(..)` from a hook
//!    whose `wants_control_mutation()` is false —
//!    [`legacy_hook_discards_a_control_replacement_when_mutation_was_not_requested`].
//!
//! Neither test can falsify the other's guard, which is exactly why both
//! are here; see this file's ablation notes on each.

mod common;

// Everything down to the last test is fed draft-14 fixtures — a draft-14
// SUBGROUP header, a draft-14 datagram, a draft-14 CLIENT_SETUP — so the
// hook fixtures, their impls and the five tests that drive them are gated
// on `draft14` and vanish together on a row that did not compile it.
// `the_context_types_stay_constructible_from_another_crate` names no
// draft, so it, and the handful of imports it needs, stay on all fourteen
// rows.
#[cfg(feature = "draft14")]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(feature = "draft14")]
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[cfg(feature = "draft14")]
use bytes::Bytes;

use moqtap_codec::dispatch::AnySubgroupObject;
#[cfg(feature = "draft14")]
use moqtap_codec::dispatch::{AnyControlMessage, AnyDatagramHeader, AnySubgroupHeader};
#[cfg(feature = "draft14")]
use moqtap_codec::draft14::data_stream::{
    DatagramObject, DatagramType, SubgroupHeader, SubgroupStreamType,
};
#[cfg(feature = "draft14")]
use moqtap_codec::draft14::message::{ClientSetup, ControlMessage, GoAway};
#[cfg(feature = "draft14")]
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

#[cfg(feature = "draft14")]
use moqtap_proxy::action::{Action, DropMode, Interest, StreamAction, StreamEnd};
use moqtap_proxy::capability::Capabilities;
#[cfg(feature = "draft14")]
use moqtap_proxy::event::DataStreamHeaderKind;
use moqtap_proxy::event::{ProxySide, SessionId};
use moqtap_proxy::framer::ObjectMeta;
use moqtap_proxy::hook::ObjectCtx;
#[cfg(feature = "draft14")]
use moqtap_proxy::hook::{FrameCtx, LegacyHook, ProxyHook, StreamCtx};
// `LegacyProxyHook` is `#[deprecated]` by design — 0.4.0 tells implementors
// to move to `ProxyHook` — and this file's whole job is to prove the
// deprecated shape still works. The allow is on the import alone, so a
// *new* deprecation anywhere else in the file is still a warning, and
// `clippy --all-targets -- -D warnings` still has teeth here.
#[allow(deprecated)]
#[cfg(feature = "draft14")]
use moqtap_proxy::hook::LegacyProxyHook;
#[cfg(feature = "draft14")]
use moqtap_proxy::observer::NoOpProxyObserver;
use moqtap_proxy::parser::data::DataStreamType;
#[cfg(feature = "draft14")]
use moqtap_proxy::shape::StreamKey;

#[cfg(feature = "draft14")]
use common::FakeRelay;

#[cfg(feature = "draft14")]
const DRAFT14_VERSION: u64 = 0xff000000 + 14;

// ── dyn-compatibility ──────────────────────────────────────────────────

/// Which method a `dyn` dispatch landed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(feature = "draft14")]
enum Called {
    Interest,
    Control,
    StreamOpen,
    StreamHeader,
    Object,
    Datagram,
    StreamEnd,
}

/// A hook that answers every method with a value nothing else returns, so
/// that "the call reached this impl" is provable rather than assumed.
///
/// The defaults on `ProxyHook` are `Action::Pass` / `StreamAction::Open` /
/// `Interest::NONE`; every answer below differs from its default, so a
/// dispatch that silently fell back to the default would be caught by the
/// value as well as by the log.
#[derive(Default)]
#[cfg(feature = "draft14")]
struct EveryMethodHook {
    calls: Mutex<Vec<Called>>,
}

#[cfg(feature = "draft14")]
impl EveryMethodHook {
    fn note(&self, what: Called) {
        self.calls.lock().expect("calls").push(what);
    }
}

#[cfg(feature = "draft14")]
impl ProxyHook for EveryMethodHook {
    fn interest(&self) -> Interest {
        self.note(Called::Interest);
        Interest::CONTROL | Interest::DATAGRAMS
    }

    fn on_control_message(
        &self,
        _cx: &FrameCtx<'_>,
        _msg: &AnyControlMessage,
        _raw: &[u8],
    ) -> Action {
        self.note(Called::Control);
        Action::Replace(Bytes::from_static(b"control"))
    }

    fn on_stream_open(&self, _cx: &StreamCtx<'_>) -> StreamAction {
        self.note(Called::StreamOpen);
        StreamAction::Reject { code: 1 }
    }

    fn on_stream_header(
        &self,
        _cx: &StreamCtx<'_>,
        _header: &DataStreamHeaderKind,
    ) -> StreamAction {
        self.note(Called::StreamHeader);
        StreamAction::Reject { code: 2 }
    }

    fn on_object(&self, _cx: &ObjectCtx<'_>, _raw: &[u8]) -> Action {
        self.note(Called::Object);
        Action::ReplacePayload(Bytes::from_static(b"payload"))
    }

    fn on_datagram(
        &self,
        _cx: &FrameCtx<'_>,
        _header: Option<&AnyDatagramHeader>,
        _raw: &[u8],
    ) -> Action {
        self.note(Called::Datagram);
        Action::Drop(DropMode::Elide)
    }

    fn on_stream_end(&self, _cx: &StreamCtx<'_>, _end: StreamEnd) -> Action {
        self.note(Called::StreamEnd);
        Action::ResetStream { code: 3 }
    }
}

/// A draft-14 subgroup header, for the `on_stream_header` dispatch.
#[cfg(feature = "draft14")]
fn subgroup_header() -> DataStreamHeaderKind {
    DataStreamHeaderKind::Subgroup(AnySubgroupHeader::Draft14(SubgroupHeader {
        stream_type: SubgroupStreamType::from_u8(0x14).expect("stream type 0x14"),
        track_alias: VarInt::from_u64(1).expect("varint"),
        group_id: VarInt::from_u64(0).expect("varint"),
        subgroup_id: Some(VarInt::from_u64(0).expect("varint")),
        publisher_priority: 128,
    }))
}

/// A draft-14 datagram header, for the `on_datagram` dispatch.
#[cfg(feature = "draft14")]
fn datagram_header() -> AnyDatagramHeader {
    AnyDatagramHeader::Draft14(DatagramObject {
        datagram_type: DatagramType::from_u8(0x00).expect("datagram type 0x00"),
        track_alias: VarInt::from_u64(1).expect("varint"),
        group_id: VarInt::from_u64(0).expect("varint"),
        object_id: VarInt::from_u64(0).expect("varint"),
        publisher_priority: 128,
        extension_headers: Vec::new(),
        status: None,
        payload: Vec::new(),
    })
}

/// An `ObjectMeta`, for the `on_object` dispatch.
fn object_meta() -> ObjectMeta {
    ObjectMeta {
        draft: DraftVersion::Draft14,
        stream_kind: DataStreamType::Subgroup,
        track_alias: Some(1),
        group_id: 0,
        subgroup_id: Some(0),
        object_id: 0,
        publisher_priority: Some(128),
        index_in_stream: 0,
        payload_len: 7,
        status: None,
        end_of_range: None,
    }
}

/// Every `ProxyHook` method dispatches through `Arc<dyn ProxyHook>`.
///
/// This is the whole of the dyn-compatibility coverage. Three separate things are
/// asserted, and only the first two are visible as assertions:
///
/// * **It compiles.** `Arc<dyn ProxyHook>` does not exist for a trait with
///   an `async fn` in it, or one made `async` through `#[async_trait]`
///   (which rewrites the return type to a `Pin<Box<dyn Future + 'life0>>`
///   borrowing `&self` and is object safe only by accident of that crate's
///   own machinery — and is not a dependency of this workspace).
/// * **Every method is reachable through the vtable**, including the three
///   whose real call sites are behind an `Interest` gate. A trait method
///   that stopped being dispatchable would fail here rather than in a
///   case nobody ran.
/// * **The values come back**, so a dispatch that fell through to the
///   default body is distinguishable from one that reached the impl.
///
/// It also depends on `FrameCtx::new` / `StreamCtx::new` / `ObjectCtx::new`
/// existing: all three context types are `#[non_exhaustive]`, so a
/// separate crate — which `tests/` is — cannot build one with a struct
/// literal (E0639). Finding F12; the constructors are `pub`, not
/// `#[doc(hidden)]`, because unit-testing your own hook is a supported use.
#[test]
#[cfg(feature = "draft14")]
fn the_hook_trait_is_dyn_compatible() {
    let hook = Arc::new(EveryMethodHook::default());
    // The load-bearing coercion. Everything after it is dispatch through
    // a vtable, not through a concrete type.
    let dynamic: Arc<dyn ProxyHook> = Arc::clone(&hook) as Arc<dyn ProxyHook>;
    let by_ref: &dyn ProxyHook = dynamic.as_ref();

    let caps = Capabilities::for_draft(DraftVersion::Draft14);
    let now = Instant::now();

    // 1. interest()
    assert_eq!(
        by_ref.interest(),
        Interest::CONTROL | Interest::DATAGRAMS,
        "interest() must dispatch to the impl, not to the Interest::NONE default"
    );

    // 2. on_control_message()
    let frame_cx = FrameCtx::new(
        SessionId(1),
        ProxySide::ClientToProxy,
        DraftVersion::Draft14,
        Some(4),
        now,
        &caps,
    );
    let msg = AnyControlMessage::Draft14(ControlMessage::GoAway(GoAway {
        new_session_uri: b"https://example.invalid".to_vec(),
    }));
    match by_ref.on_control_message(&frame_cx, &msg, b"raw-control") {
        Action::Replace(b) => assert_eq!(&b[..], b"control"),
        other => panic!("on_control_message returned {other:?}"),
    }

    // 3. on_stream_open()
    let key = StreamKey { side: ProxySide::ClientToProxy, id: 9 };
    let stream_cx = StreamCtx::new(
        SessionId(1),
        ProxySide::ClientToProxy,
        4,
        DraftVersion::Draft14,
        false,
        &caps,
        key,
    );
    assert_eq!(by_ref.on_stream_open(&stream_cx), StreamAction::Reject { code: 1 });
    // `key()` is the read path for the identity `SerializeAfter` names, and
    // it is deliberately *not* `stream_id` — 9 against a transport id of 4.
    assert_eq!(stream_cx.key(), key);
    assert_ne!(
        stream_cx.key().id,
        stream_cx.stream_id,
        "the session-local key must not be the transport stream id"
    );

    // 4. on_stream_header()
    assert_eq!(
        by_ref.on_stream_header(&stream_cx, &subgroup_header()),
        StreamAction::Reject { code: 2 }
    );

    // 5. on_object()
    let meta = object_meta();
    let object_cx = ObjectCtx::new(SessionId(1), ProxySide::ClientToProxy, 4, &meta, now, &caps);
    match by_ref.on_object(&object_cx, b"framing+payload") {
        Action::ReplacePayload(b) => assert_eq!(&b[..], b"payload"),
        other => panic!("on_object returned {other:?}"),
    }

    // 6. on_datagram() — both the decoded and the undecodable shape, since
    //    `Option<&AnyDatagramHeader>` is part of the signature under test.
    let header = datagram_header();
    let datagram_cx = FrameCtx::new(
        SessionId(1),
        ProxySide::RelayToProxy,
        DraftVersion::Draft14,
        None,
        now,
        &caps,
    );
    assert!(matches!(
        by_ref.on_datagram(&datagram_cx, Some(&header), b"raw-datagram"),
        Action::Drop(DropMode::Elide)
    ));
    assert!(matches!(
        by_ref.on_datagram(&datagram_cx, None, b"undecodable"),
        Action::Drop(DropMode::Elide)
    ));

    // 7. on_stream_end()
    match by_ref.on_stream_end(&stream_cx, StreamEnd::Reset { code: 9 }) {
        Action::ResetStream { code } => assert_eq!(code, 3),
        other => panic!("on_stream_end returned {other:?}"),
    }

    assert_eq!(
        hook.calls.lock().expect("calls").as_slice(),
        &[
            Called::Interest,
            Called::Control,
            Called::StreamOpen,
            Called::StreamHeader,
            Called::Object,
            Called::Datagram,
            Called::Datagram,
            Called::StreamEnd,
        ],
        "all seven methods must be reachable through the dyn reference"
    );

    // A second coercion, of the crate's own no-op hook: `impl ProxyHook for
    // NoOpHook {}` — every method defaulted — must be object safe too, or
    // `spawn_proxy`'s `Arc<dyn ProxyHook>` parameter would be unusable
    // with the type the crate ships for it.
    let noop: Arc<dyn ProxyHook> = Arc::new(moqtap_proxy::hook::NoOpHook);
    assert_eq!(noop.interest(), Interest::NONE);
}

// ── the 0.3.x adapter ──────────────────────────────────────────────────

/// A `LegacyProxyHook` that answers `wants_control_mutation()` `true` the
/// **first** time and `false` afterwards.
///
/// Contrived on purpose, and the contrivance is the point.
/// [`LegacyHook`] reads the flag in two different places for two different
/// reasons: once from `interest()`, which the session samples exactly once
/// at start-up, and once per control frame from `on_control_message()`,
/// where it gates the *replacement* rather than the call. A hook that
/// answers `false` to both is stopped by the interest gate before the
/// second one is ever reached, so the second guard — the one whose removal
/// silently inverts an observe-only hook into a rewriting one — cannot be
/// falsified by any fixture that answers consistently.
///
/// `ProxyHook::interest`'s own rustdoc says a hook that returns a
/// different value later is not re-consulted; this fixture is that
/// sentence made executable.
#[derive(Default)]
#[cfg(feature = "draft14")]
struct FlipFlopLegacyHook {
    asked: AtomicUsize,
    control_calls: AtomicUsize,
}

#[allow(deprecated)]
#[cfg(feature = "draft14")]
impl LegacyProxyHook for FlipFlopLegacyHook {
    fn wants_control_mutation(&self) -> bool {
        // Call 0 is `LegacyHook::interest()`, sampled once at session
        // start. Every later call is the per-frame guard.
        self.asked.fetch_add(1, Ordering::SeqCst) == 0
    }

    fn on_control_message(
        &self,
        _session_id: SessionId,
        _side: ProxySide,
        _message: &AnyControlMessage,
        _raw_bytes: &[u8],
    ) -> Option<Vec<u8>> {
        self.control_calls.fetch_add(1, Ordering::SeqCst);
        Some(b"evil-replacement-bytes".to_vec())
    }
}

/// A `LegacyProxyHook` that never asks for control mutation and rewrites
/// datagrams.
#[derive(Default)]
#[cfg(feature = "draft14")]
struct ObserveOnlyLegacyHook {
    control_calls: AtomicUsize,
    datagram_calls: AtomicUsize,
    rewrite: Option<Vec<u8>>,
}

#[allow(deprecated)]
#[cfg(feature = "draft14")]
impl LegacyProxyHook for ObserveOnlyLegacyHook {
    fn wants_control_mutation(&self) -> bool {
        false
    }

    fn on_control_message(
        &self,
        _session_id: SessionId,
        _side: ProxySide,
        _message: &AnyControlMessage,
        _raw_bytes: &[u8],
    ) -> Option<Vec<u8>> {
        self.control_calls.fetch_add(1, Ordering::SeqCst);
        Some(b"evil-replacement-bytes".to_vec())
    }

    fn on_datagram(
        &self,
        _session_id: SessionId,
        _side: ProxySide,
        _header: &AnyDatagramHeader,
        _raw_bytes: &[u8],
    ) -> Option<Vec<u8>> {
        self.datagram_calls.fetch_add(1, Ordering::SeqCst);
        self.rewrite.clone()
    }
}

/// A draft-14 CLIENT_SETUP offering draft-14, on the wire.
///
/// Encoded through the codec on purpose: `pipe_control_mutating` on
/// `moq-00` will not start its parser until `detect_draft_from_setup`
/// recognises a real SETUP, so a hand-rolled approximation would leave the
/// control stream stalled in detection and the test would pass by
/// forwarding nothing.
#[cfg(feature = "draft14")]
fn client_setup_bytes() -> Vec<u8> {
    let mut buf = Vec::new();
    AnyControlMessage::Draft14(ControlMessage::ClientSetup(ClientSetup {
        supported_versions: vec![VarInt::from_u64(DRAFT14_VERSION).expect("varint")],
        parameters: Vec::new(),
    }))
    .encode(&mut buf)
    .expect("encode CLIENT_SETUP");
    buf
}

/// A draft-14 payload-bearing datagram: type `0x00`, track alias 1, group
/// 7, object 3, priority 128, then the payload.
#[cfg(feature = "draft14")]
fn datagram_bytes(payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x00, 0x01, 0x07, 0x03, 0x80];
    out.extend_from_slice(payload);
    out
}

/// Read from the relay's control stream until at least `want` bytes have
/// arrived, then report them.
#[cfg(feature = "draft14")]
async fn relay_control_bytes(relay: Arc<FakeRelay>, want: usize) -> Vec<u8> {
    let (_send, mut recv) = relay.accept_bi().await;
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    while got.len() < want {
        match recv.read(&mut buf).await {
            Ok(Some(n)) => got.extend_from_slice(&buf[..n]),
            Ok(None) => break,
            Err(e) => panic!("relay control read: {e:?}"),
        }
    }
    got
}

/// A legacy `Some(bytes)` from a hook that did not ask for control
/// mutation stays discarded — the inversion `LegacyHook`'s rustdoc warns
/// about.
///
/// *Ablation:* drop the `if self.0.wants_control_mutation()` guard from
/// `LegacyHook::on_control_message`, so the arm reads
/// `Some(bytes) => Action::Replace(Bytes::from(bytes))`. `evil-replacement-bytes`
/// then reaches the relay and this test goes red.
///
/// The fixture's flip-flop is what makes that ablation reachable at all;
/// see [`FlipFlopLegacyHook`].
#[tokio::test]
#[allow(deprecated)]
#[cfg(feature = "draft14")]
async fn legacy_hook_discards_a_control_replacement_when_mutation_was_not_requested() {
    common::init_crypto();

    let legacy = Arc::new(FlipFlopLegacyHook::default());
    let hook: Arc<dyn ProxyHook> = Arc::new(LegacyHook(Arc::clone(&legacy) as Arc<_>));

    let relay = Arc::new(FakeRelay::bind(b"moq-00"));
    let proxy = common::spawn_proxy(relay.addr, Arc::new(NoOpProxyObserver), hook);

    let setup = client_setup_bytes();
    let relay_for_task = Arc::clone(&relay);
    let want = setup.len();
    let upstream = tokio::spawn(async move { relay_control_bytes(relay_for_task, want).await });

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, b"moq-00").await;
    let (mut send, _recv) = client_conn.open_bi().await.expect("open_bi");
    send.write_all(&setup).await.expect("write CLIENT_SETUP");

    let got = tokio::time::timeout(common::TIMEOUT, upstream)
        .await
        .expect("the relay saw the control stream")
        .expect("join");

    assert_eq!(
        got, setup,
        "the ORIGINAL control bytes must reach the upstream; a Some(..) from a hook that did not \
         ask for control mutation is discarded"
    );
    assert_ne!(
        &got[..],
        b"evil-replacement-bytes",
        "the legacy replacement must not have been spliced in"
    );

    // The fixture's own premises, so a run in which nothing happened
    // cannot masquerade as a pass.
    assert!(
        legacy.control_calls.load(Ordering::SeqCst) >= 1,
        "the legacy hook's on_control_message must actually have been consulted"
    );
    assert!(
        legacy.asked.load(Ordering::SeqCst) >= 2,
        "wants_control_mutation must have been asked once for interest() and once per frame; \
         got {}",
        legacy.asked.load(Ordering::SeqCst)
    );

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

/// A legacy hook that never asks for control mutation is never shown the
/// control stream at all — the *first* of the two guards.
///
/// *Ablation:* make `LegacyHook::interest()` return
/// `Interest::DATAGRAMS | Interest::CONTROL` unconditionally. The
/// `control_calls` assertion then goes red, while the byte assertion keeps
/// passing — which is precisely why the count is asserted and not only the
/// bytes.
#[tokio::test]
#[allow(deprecated)]
#[cfg(feature = "draft14")]
async fn legacy_hook_without_control_mutation_is_never_shown_the_control_stream() {
    common::init_crypto();

    let legacy = Arc::new(ObserveOnlyLegacyHook::default());
    let adapter = LegacyHook(Arc::clone(&legacy) as Arc<_>);
    assert!(
        !adapter.interest().contains(Interest::CONTROL),
        "a legacy hook that answers false must not be given Interest::CONTROL"
    );

    let hook: Arc<dyn ProxyHook> = Arc::new(adapter);
    let relay = Arc::new(FakeRelay::bind(b"moq-00"));
    let proxy = common::spawn_proxy(relay.addr, Arc::new(NoOpProxyObserver), hook);

    let setup = client_setup_bytes();
    let relay_for_task = Arc::clone(&relay);
    let want = setup.len();
    let upstream = tokio::spawn(async move { relay_control_bytes(relay_for_task, want).await });

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, b"moq-00").await;
    let (mut send, _recv) = client_conn.open_bi().await.expect("open_bi");
    send.write_all(&setup).await.expect("write CLIENT_SETUP");

    let got = tokio::time::timeout(common::TIMEOUT, upstream)
        .await
        .expect("the relay saw the control stream")
        .expect("join");
    assert_eq!(got, setup, "the control frame reaches the relay unchanged");
    assert_eq!(
        legacy.control_calls.load(Ordering::SeqCst),
        0,
        "without Interest::CONTROL the session takes pipe_control_passthrough and the hook is \
         never consulted"
    );

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

/// Datagram rewriting survives the migration: `LegacyHook::interest()`
/// yields `DATAGRAMS` unconditionally, and the rewrite reaches the wire.
///
/// `DATAGRAMS` is unconditional because in 0.3.x the datagram hook *was*
/// the datagram hook — there was no flag to ask for it — so gating it on
/// `wants_control_mutation()` would stop datagram rewriting for every
/// existing implementation.
///
/// *Ablation:* return `Interest::NONE` from `LegacyHook::interest()` when
/// `wants_control_mutation()` is false. The relay then receives the
/// original datagram and this test goes red.
#[tokio::test]
#[allow(deprecated)]
#[cfg(feature = "draft14")]
async fn legacy_hook_keeps_datagram_rewriting() {
    common::init_crypto();

    let original = datagram_bytes(b"original-payload");
    let rewritten = datagram_bytes(b"REWRITTEN-PYLOAD");
    assert_eq!(original.len(), rewritten.len(), "same length keeps the fixture honest about size");

    let legacy =
        Arc::new(ObserveOnlyLegacyHook { rewrite: Some(rewritten.clone()), ..Default::default() });
    let adapter = LegacyHook(Arc::clone(&legacy) as Arc<_>);
    assert!(
        adapter.interest().contains(Interest::DATAGRAMS),
        "the adapter must keep DATAGRAMS whatever wants_control_mutation() says"
    );

    let hook: Arc<dyn ProxyHook> = Arc::new(adapter);
    let relay = Arc::new(FakeRelay::bind(b"moq-00"));
    let proxy = common::spawn_proxy(relay.addr, Arc::new(NoOpProxyObserver), hook);

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, b"moq-00").await;
    let relay_conn = tokio::time::timeout(common::TIMEOUT, relay.connection())
        .await
        .expect("the proxy connected upstream");

    client_conn.send_datagram(Bytes::from(original.clone())).expect("client send_datagram");

    let got = tokio::time::timeout(common::TIMEOUT, relay_conn.read_datagram())
        .await
        .expect("the relay received a datagram")
        .expect("read_datagram");

    assert_eq!(
        &got[..],
        &rewritten[..],
        "the legacy hook's Some(bytes) must reach the wire as the whole datagram"
    );
    assert_eq!(
        legacy.datagram_calls.load(Ordering::SeqCst),
        1,
        "the legacy datagram hook fired exactly once"
    );

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

/// A legacy hook is not called for a datagram whose header did not decode,
/// because 0.3.x never called it there.
///
/// The third preserved behaviour in [`LegacyHook`]'s rustdoc, and the one
/// that separates the *adapter's* semantics from Hook v2's — a native
/// `ProxyHook` **is** shown an undecodable datagram
/// (`tests/actions_datagrams.rs`), which is what makes `Action::Drop` on
/// malformed traffic expressible at all.
///
/// *Ablation:* delete the `let Some(header) = header else { return
/// Action::Pass }` early return in `LegacyHook::on_datagram`. The call
/// count goes to 1 and this test goes red.
#[tokio::test]
#[allow(deprecated)]
#[cfg(feature = "draft14")]
async fn legacy_hook_is_not_called_for_an_undecodable_datagram() {
    common::init_crypto();

    // One byte of a would-be 8-byte varint: no draft can decode a header
    // out of it.
    let undecodable = vec![0xC0u8];

    let legacy = Arc::new(ObserveOnlyLegacyHook {
        rewrite: Some(b"never-used".to_vec()),
        ..Default::default()
    });
    let hook: Arc<dyn ProxyHook> = Arc::new(LegacyHook(Arc::clone(&legacy) as Arc<_>));

    let relay = Arc::new(FakeRelay::bind(b"moq-00"));
    let proxy = common::spawn_proxy(relay.addr, Arc::new(NoOpProxyObserver), hook);

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, b"moq-00").await;
    let relay_conn = tokio::time::timeout(common::TIMEOUT, relay.connection())
        .await
        .expect("the proxy connected upstream");

    client_conn.send_datagram(Bytes::from(undecodable.clone())).expect("client send_datagram");

    let got = tokio::time::timeout(common::TIMEOUT, relay_conn.read_datagram())
        .await
        .expect("the relay received a datagram")
        .expect("read_datagram");

    assert_eq!(&got[..], &undecodable[..], "the undecodable datagram is forwarded unchanged");
    assert_eq!(
        legacy.datagram_calls.load(Ordering::SeqCst),
        0,
        "0.3.x sat inside `if let Ok(header) = ..` and was never reached; the adapter preserves \
         that"
    );

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

/// A guard against the fixture above rotting: an `AnySubgroupObject` is
/// still what a subgroup stream carries, and `ObjectMeta` is still
/// literal-constructible from another crate.
///
/// Both are load-bearing for `the_hook_trait_is_dyn_compatible`: if
/// `ObjectMeta` gained `#[non_exhaustive]`, that test would stop
/// compiling and the only guard on dyn compatibility would go with it.
#[test]
fn the_context_types_stay_constructible_from_another_crate() {
    let meta = object_meta();
    assert_eq!(meta.payload_len, 7);
    let caps = Capabilities::for_draft(DraftVersion::Draft19);
    let cx =
        ObjectCtx::new(SessionId(7), ProxySide::RelayToProxy, 11, &meta, Instant::now(), &caps);
    assert_eq!(cx.stream_id, 11);
    assert_eq!(cx.meta.object_id, 0);

    let _ = AnySubgroupObject {
        object_id: 0,
        extension_headers: Vec::new(),
        extension_count: None,
        status: None,
        payload: Vec::new(),
    };
}

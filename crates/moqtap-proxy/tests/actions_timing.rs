//! `Delay`, `Hold`, ordering, and cancellation while held.
//!
//! Every test here drives a **real** proxy session over real QUIC, because
//! the property under test is a property of the read loop's `select!`, not
//! of `PendingQueue` arithmetic — that half lives in `egress.rs`'s own
//! `#[cfg(test)] mod tests`, which is where a private module is testable
//! from.
//!
//! # Why no `start_paused = true`
//!
//! Two independent reasons, and either alone is enough:
//!
//! * Virtual time does not advance while real QUIC I/O is pending, so a
//!   paused-time test deadlocks rather than running fast.
//! * The release wheel is on a **real** clock — it is not tokio's timer and
//!   `tokio::time::pause` cannot move it — so a paused-time test would wait
//!   out the real deadline anyway.
//!
//! # How the timing assertions are written
//!
//! Two kinds of claim live in this file, and only one of them belongs in
//! `cargo test --workspace`.
//!
//! **Correctness** — never early, never reordered, never lost, never
//! stalled. A busy box can only make a release *later*, so none of these
//! can be invalidated by load, and all of them are asserted hard:
//!
//! 1. **Lower bounds.** "Object *i* did not reach the relay before it was
//!    written plus `d`" has no scheduler exposure at all
//!    ([`a_five_millisecond_delay_is_never_released_early`],
//!    [`a_delayed_object_never_arrives_early`],
//!    [`a_delay_behind_a_hold_keeps_its_own_deadline`]).
//! 2. **Byte equality and counters.** Ordering under `Delay` and `Hold` is
//!    asserted as "the destination stream is byte-equal to the source"
//!    ([`ordering_is_preserved_under_delay`]) and completeness as "the
//!    release branch counted every unit"
//!    (`release_errors.count == COUNT`), neither of which contains a
//!    duration.
//! 3. **Paired instants from the same process** — a hook-call instant
//!    against a byte-arrival instant ([`delay_is_not_backpressure`]), or
//!    "the two objects arrived less than half a `DELAY` apart"
//!    ([`delay_is_a_deadline_not_a_spacing`]). These compare two
//!    *orderings*, not two rates, so load moves both.
//!
//! **Accuracy** — *how* late. That is a measurement of the machine at
//! least as much as of the code, and it is `#[ignore]`d here and in
//! `release_timer.rs`; see
//! [`calibration_a_five_millisecond_delay_is_measured_as_five_milliseconds`]
//! for the whole argument and the numbers behind it.
//!
//! ## Paired comparison does not rescue an accuracy pair
//!
//! It is tempting to rank paired comparisons **first**, on the reasoning
//! that "scheduler noise is additive and lands on both arms, so it cancels
//! in the difference". For an accuracy pair that is wrong, and it is
//! falsified by measurement rather than argued away:
//! under 16 busy-loop processes the wheel arm does *not* keep its ~0.5 ms
//! lateness while the tokio arm keeps its ~11 ms tick. Both arms degrade
//! to the same tens of milliseconds and the separation collapses. Measured
//! wheel/control pairs across seven loaded failures: 12.58/12.03,
//! 10.49/11.12, 12.58/12.87, 12.58/11.94, 12.58/12.09, 12.58/11.45 and
//! 12.58/13.26 ms — the wheel *slower* in four of the seven, against a
//! 3 ms margin. The noise is not additive; it is a ceiling both arms hit.
//!
//! Pairing still works for the claims in group 3 above, because those pairs
//! are two events in a fixed order rather than two rates.
//!
//! Where an upper bound is unavoidable it is written with a wide margin
//! and a comment saying *widen this, do not delete it*. The surviving ones
//! are all of that shape: 1.5 s of slack over a 300-400 ms delay
//! ([`a_delayed_object_never_arrives_early`],
//! [`a_delay_behind_a_hold_keeps_its_own_deadline`]), a 1 s resume window
//! against a 2 s or 30 s `max_hold` ceiling, and a 1 s teardown window.
//! Each is separated from the defect it rejects by at least a factor of
//! two, which is why none of them moved under the load that broke the
//! accuracy pair.
//!
//! # What "teardown" is observable as, and what it is not
//!
//! `forward_uni_streams` spawns each stream's pipe with a detached
//! `tokio::spawn` (`session.rs:1506`), and `run_with_transport` returns as
//! soon as the **first** of its five top-level tasks finishes. So the time
//! from `cancel()` to `ProxySession::run` returning says nothing about
//! whether a pipe loop noticed the cancellation: it is short whatever the
//! pipe does, and a test that measured it would pass against every
//! implementation. `cancelling_while_an_object_is_held_tears_down_promptly`
//! therefore asserts on what the *pipe task* does — the held unit is
//! delivered, or reported as `Impairment { QueuedBytesAtTeardown }`, within
//! the window — the "never silently gone" guarantee, and the thing an
//! inline drain loop fails.
//!
//! # Three tests here each pin a measured defect
//!
//! They are the regression tests for three concrete failure modes. Each
//! rustdoc records the measurement that caught its defect and the ablation
//! that puts the failure back.
//!
//! * `releasing_a_gate_resumes_the_stream` and
//!   `releasing_a_gate_resumes_the_stream_and_its_fin` — a `Hold` on one
//!   object stalls every later object on that stream, and the stream's FIN,
//!   until `max_hold` (30 s by default) **even after the gate is
//!   released**, unless readiness is kept separate from ordering in
//!   `egress.rs`: `PendingQueue::push` does not rewrite a successor's
//!   deadline.
//! * `a_delay_behind_a_hold_keeps_its_own_deadline` — that same rewrite
//!   would overwrite a queued `Delay`'s own `arrived_at + by` deadline with
//!   the hold's ceiling.
//! * `a_held_object_is_never_silently_lost_at_teardown` — on a multi-thread
//!   runtime, cancelling a session while an object is held loses that
//!   object with no event at all, 8 runs out of 8, unless every teardown
//!   path reports `PendingQueue::unconfirmed_bytes` rather than
//!   `queued_bytes`: bytes handed to a transport the session is closing are
//!   not delivered bytes.
//!
//! None of them is `#[ignore]`d, because an ignored test is a defect that
//! has stopped being visible. That rule holds for every claim about *what* the
//! session does. The single `#[ignore]` in this file is on a claim about
//! *how accurately* it does it, where there is no defect to hide — the
//! capability is gated by the lower bounds and counters above — and where
//! the thing being measured is genuinely not measurable on a loaded box by
//! any method. Its rustdoc makes that case in full; do not read it as
//! licence for a second one.
//!
//! # Which draft this file speaks, and why it is derived rather than named
//!
//! Every test here needs *a* framed subgroup stream; none of them cares
//! which draft framed it. The property under test is the read loop's
//! `select!` and the release wheel behind it, and neither reads a draft.
//!
//! So [`DRAFT`] is the newest draft **this build compiled**, and the
//! fixture's five header bytes are derived from it by
//! [`subgroup_header_bytes`]. A hardcoded `DraftVersion::Draft19` was
//! wrong in two directions at once and both were measured:
//!
//! * with no draft compiled, `AnySubgroupHeader` is uninhabited, so
//!   `decode_stream` can never return `Ok` and every line after it is
//!   `unreachable_code` — `cargo check --no-default-features` exited 101
//!   under `-D warnings`;
//! * with *one* draft compiled that was not 19, the constant still asked
//!   for draft-19 bytes and `decode_stream` returned
//!   `UnsupportedDraft("draft Draft19 not enabled via feature flag")` —
//!   0 passed / 13 failed on each of draft07, draft13, draft14 and
//!   draft18, and 13/13 only on draft19.
//!
//! The second is why deriving beats gating: `#![cfg(feature = "draft19")]`
//! would have made the twelve other rows *green by absence*, and this
//! file's subject — a wheel, a deque and a `select!` — is exercised on
//! every one of them. A per-row **run** is what catches it; a compile-only
//! gate cannot see a fixture that decodes to the wrong draft.
//!
//! A build with **no** draft compiled has no framer to drive at all, so
//! the whole file is gated out below rather than left to fail at
//! `decode_stream`.

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
    feature = "draft19",
    feature = "draft20",
    feature = "draft21"
))]

mod common;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;

// Only the draft-14-pinned control-pipe test at the end of this file needs
// these two; a
// single-draft build without draft14 compiles that leg away.
#[cfg(feature = "draft14")]
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::dispatch::{AnySubgroupHeader, AnySubgroupObject, AnySubgroupObjectWriter};
use moqtap_codec::version::DraftVersion;

use moqtap_proxy::action::{Action, EgressConfig, Gate, Interest};
use moqtap_proxy::capability::{ActionKind, Refusal, Site};
use moqtap_proxy::event::{Effect, ImpairmentKind};
#[cfg(feature = "draft14")]
use moqtap_proxy::hook::FrameCtx;
use moqtap_proxy::hook::{ObjectCtx, ProxyHook};
use moqtap_proxy::instrument::Counters;
use moqtap_proxy::observer::ProxyObserver;
use moqtap_proxy::shape::{
    BucketConfig, ClassRule, Discipline, Expiry, Matcher, QueueConfig, ShapeProfile,
};

use common::{Ending, FakeRelay, RecordingObserver, SpawnedProxy, TimedReceiver};

/// Every draft this build compiled, oldest first.
///
/// Each element carries its own `#[cfg]`, so the array is the enabled set
/// and not a hardcoded list — the same shape `action_matrix.rs` and
/// `actions_objects.rs` use for their sweep axes. The file-level gate above
/// guarantees it is non-empty, which is what makes [`DRAFT`]'s index a
/// compile-time fact rather than a panic.
const COMPILED_DRAFTS: &[DraftVersion] = &[
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
    #[cfg(feature = "draft20")]
    DraftVersion::Draft20,
    #[cfg(feature = "draft21")]
    DraftVersion::Draft21,
];

/// The draft every fixture in this file is built for: the **newest** one
/// this build compiled.
///
/// Newest rather than oldest so the default all-drafts build keeps running
/// what it always ran (draft-20, the hardest half of the framer: drafts
/// 14-20 delta-encode object IDs). Nothing here elides, so no ID is
/// rewritten and byte equality is the ordering assertion on every draft.
const DRAFT: DraftVersion = COMPILED_DRAFTS[COMPILED_DRAFTS.len() - 1];

/// `spawn_proxy_with` needs the ALPN the front-end endpoint advertises.
/// `moq-00` leaves `draft_is_fixed` false, which only affects the control
/// parser — no test in this file opens a control stream.
const ALPN: &[u8] = b"moq-00";

// ── the source stream ──────────────────────────────────────────────────

/// The stream-type field [`DRAFT`] opens a subgroup stream with, for a
/// header carrying an **explicit** Subgroup ID.
///
/// Drafts 07-10 define a single subgroup type, `0x04`, ahead of the header
/// body. Draft-11 numbered the types from `0x08` and put the explicit-ID
/// one at `0x0C`; drafts 12+ moved it to `0x14` and folded it into the
/// header's own first byte. The low bit selects an extension/property
/// block on drafts 11+ and is left clear here: no test in this file writes
/// one.
///
/// This is the same table `actions_objects.rs`'s independent encoder
/// carries, restated rather than shared — the two files are separate test
/// binaries, and an encoder written to check the proxy's bytes must not
/// live anywhere the proxy could end up linking it, or the check becomes
/// the proxy compared against itself.
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

/// A subgroup stream header for `draft`: track alias 1, group 0, subgroup
/// 0, publisher priority `0x80`.
///
/// Five bytes on every draft 07-21 — the type field, three one-byte
/// varints and the priority octet — which is why [`Rig`]'s promise that
/// every test here starts with the same five header bytes holds whatever
/// this build compiled.
fn subgroup_header_bytes(draft: DraftVersion) -> Vec<u8> {
    vec![subgroup_stream_type(draft), 0x01, 0x00, 0x00, 0x80]
}

/// A [`DRAFT`] subgroup stream: the header, and `count` objects each
/// carrying `payload_len` bytes, returned separately so a test can write
/// them with a real gap between them.
fn subgroup_stream(count: u64, payload_len: usize) -> (Vec<u8>, Vec<Vec<u8>>) {
    let head = subgroup_header_bytes(DRAFT);
    let mut cursor = &head[..];
    let header =
        AnySubgroupHeader::decode_stream(DRAFT, &mut cursor).expect("subgroup header decode");
    let mut writer = AnySubgroupObjectWriter::new(&header).expect("subgroup object writer");

    let mut objects = Vec::new();
    for object_id in 0..count {
        let fill = u8::try_from(0xA0 + object_id % 0x40).expect("fill byte");
        let obj = AnySubgroupObject {
            object_id,
            extension_headers: Vec::new(),
            extension_count: None,
            status: None,
            payload: vec![fill; payload_len],
        };
        let mut buf = Vec::new();
        writer.write_object(&obj, &mut buf).expect("write object");
        objects.push(buf);
    }
    (head, objects)
}

/// Header plus every object, as one byte vector — what the destination must
/// reproduce.
fn whole(head: &[u8], objects: &[Vec<u8>]) -> Vec<u8> {
    head.iter().copied().chain(objects.iter().flatten().copied()).collect()
}

// ── the hook ───────────────────────────────────────────────────────────

/// A hook that returns a scripted [`Action`] per object ID and stamps the
/// instant of every call.
///
/// The stamp is what [`delay_is_not_backpressure`] reads: it is taken in
/// the proxy's read loop, in this process, so it is directly comparable
/// with a [`TimedReceiver`]'s arrival instants.
struct ScriptedHook {
    plan: Box<dyn Fn(u64) -> Action + Send + Sync>,
    calls: Mutex<Vec<(u64, Instant)>>,
}

impl ScriptedHook {
    fn new(plan: impl Fn(u64) -> Action + Send + Sync + 'static) -> Arc<Self> {
        Arc::new(Self { plan: Box::new(plan), calls: Mutex::new(Vec::new()) })
    }

    /// Every `on_object` call so far, as `(object_id, instant)`.
    fn calls(&self) -> Vec<(u64, Instant)> {
        self.calls.lock().expect("hook calls").clone()
    }
}

impl ProxyHook for ScriptedHook {
    /// `OBJECTS` and nothing else: the object site is the only one this
    /// file decides at, and `STREAMS` would additionally arm
    /// `on_stream_open` / `on_stream_header` / `on_stream_end`.
    fn interest(&self) -> Interest {
        Interest::OBJECTS
    }

    fn on_object(&self, cx: &ObjectCtx<'_>, _raw: &[u8]) -> Action {
        self.calls.lock().expect("hook calls").push((cx.meta.object_id, Instant::now()));
        (self.plan)(cx.meta.object_id)
    }
}

// ── the rig ────────────────────────────────────────────────────────────

/// One client → proxy → relay session with the stream header already
/// forwarded, so the pipe loop is live and the relay-side receiver exists.
///
/// The header is written by [`Self::start`] on purpose: a QUIC uni stream
/// does not exist for the peer until a frame arrives on it, so the relay's
/// `accept_uni` cannot resolve before the client writes something, and
/// every test here starts with the same five header bytes.
struct Rig {
    proxy: SpawnedProxy,
    observer: Arc<RecordingObserver>,
    hook: Arc<ScriptedHook>,
    /// The endpoint must outlive the connection.
    _client_ep: quinn::Endpoint,
    client_conn: quinn::Connection,
    send: quinn::SendStream,
    /// Bound to a field, not a temporary: dropping a [`TimedReceiver`]
    /// aborts its reader task.
    rx: TimedReceiver,
    /// The relay, kept alive for the session's lifetime.
    _relay: Arc<FakeRelay>,
}

impl Rig {
    async fn start(hook: Arc<ScriptedHook>, egress: Option<EgressConfig>, head: &[u8]) -> Self {
        Self::start_with(hook, egress, None, head).await
    }

    /// The same rig with a shaping profile installed.
    ///
    /// Split out rather than folded into [`Self::start`]'s signature because
    /// exactly one test in this file shapes anything: the clamp report has
    /// two producers — a hook's `Delay`, and a token bucket that will not
    /// release the head — and they are only comparable when both run against
    /// the same fixture.
    async fn start_shaped(
        hook: Arc<ScriptedHook>,
        egress: EgressConfig,
        shape: ShapeProfile,
        head: &[u8],
    ) -> Self {
        Self::start_with(hook, Some(egress), Some(shape), head).await
    }

    async fn start_with(
        hook: Arc<ScriptedHook>,
        egress: Option<EgressConfig>,
        shape: Option<ShapeProfile>,
        head: &[u8],
    ) -> Self {
        common::init_crypto();

        let relay = Arc::new(FakeRelay::bind(ALPN));
        let observer = Arc::new(RecordingObserver::new());

        let mut config = common::session_config(DRAFT, relay.addr);
        if let Some(egress) = egress {
            // Field assignment, not a struct literal: `EgressConfig` and
            // `ProxySessionConfig` are both `#[non_exhaustive]`, which
            // forbids literal construction from this crate.
            config.egress = egress;
        }
        config.shape = shape;

        let proxy = common::spawn_proxy_with(
            config,
            ALPN,
            Arc::clone(&observer) as Arc<dyn ProxyObserver>,
            Arc::clone(&hook) as Arc<dyn ProxyHook>,
        );

        let relay_for_task = Arc::clone(&relay);
        let accepting = tokio::spawn(async move { relay_for_task.timed_uni().await });

        let (client_ep, client_conn) = common::connect_client(proxy.addr, ALPN).await;
        let mut send = client_conn.open_uni().await.expect("open_uni");
        send.write_all(head).await.expect("write header");

        let rx = tokio::time::timeout(common::TIMEOUT, accepting)
            .await
            .expect("the relay saw the forwarded stream")
            .expect("join");

        // The header is on the wire before any assertion runs, so a later
        // `assert_no_bytes_for` measures the objects and not the handshake.
        let seen = rx.wait_for_bytes(head.len()).await;
        assert_eq!(seen, head, "the stream header must reach the relay unchanged");

        Self { proxy, observer, hook, _client_ep: client_ep, client_conn, send, rx, _relay: relay }
    }

    fn counters(&self) -> Counters {
        self.proxy.counters()
    }

    /// Poll `probe` against the recorded events until it holds, or give up.
    async fn wait_for_event(&self, what: &str, probe: impl Fn(&RecordingObserver) -> bool) {
        let poll = async {
            loop {
                if probe(&self.observer) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        };
        if tokio::time::timeout(common::TIMEOUT, poll).await.is_err() {
            panic!("timed out waiting for {what}; events were {:?}", self.observer.events());
        }
    }

    /// Wait until the hook has been shown `n` objects.
    ///
    /// The feedback edge [`delay_is_not_backpressure`] needs: it makes the
    /// client's write of object *i+1* depend on the proxy having read object
    /// *i*, so a stalled read loop shows up as elapsed time instead of
    /// disappearing into the receive buffer.
    async fn wait_for_hook_calls(&self, n: usize) {
        let poll = async {
            loop {
                if self.hook.calls().len() >= n {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        };
        if tokio::time::timeout(common::TIMEOUT, poll).await.is_err() {
            panic!(
                "timed out waiting for the hook to be shown {n} object(s); it saw {:?}",
                self.hook.calls().iter().map(|(id, _)| *id).collect::<Vec<_>>(),
            );
        }
    }

    async fn shutdown(self) {
        self.client_conn.close(0u32.into(), b"done");
        self.proxy.shutdown().await;
    }
}

// ── ordering ───────────────────────────────────────────────────────────

/// Object 0 delayed, objects 1..N not, and the destination byte stream is
/// still byte-equal to the source.
///
/// Objects are concatenated on one stream, so **byte equality is the
/// ordering assertion** — stronger than comparing arrival instants and
/// cheaper. It is also the only form that can fail: the plan's original
/// wording ("ordering preserved under `Delay`") cannot, because each
/// `pipe_data_framed` owns its `SendStream` exclusively and nothing else
/// writes to it.
///
/// *Ablation (run, and it fails):* let a zero-delay unit overtake a queued
/// one — in `exec.rs`'s `Action::Delay` arm, write the unit inline
/// (`Plan::WriteNow`) instead of pushing it whenever its release time has
/// already passed. Objects 1..N then reach the relay ahead of object 0 and
/// the mid-flight assertion below goes red inside 150 ms.
///
/// Note that removing the monotonic clamp in `PendingQueue::push` is *not*
/// an ablation for this test and never was: `pop_next_due` only ever looks
/// at the queue's front, so wire order survives an unclamped push. What the
/// clamp buys is that the release time the queue *reports* is the one it
/// will honour, which is a different claim.
#[tokio::test]
async fn ordering_is_preserved_under_delay() {
    const COUNT: u64 = 8;
    const HEAD_DELAY: Duration = Duration::from_millis(300);

    let (head, objects) = subgroup_stream(COUNT, 8);
    let stream = whole(&head, &objects);

    let hook = ScriptedHook::new(|id| {
        if id == 0 {
            Action::Pass.delayed(HEAD_DELAY)
        } else {
            // Zero delay: these must wait behind object 0 anyway.
            Action::Pass.delayed(Duration::ZERO)
        }
    });
    let mut rig = Rig::start(Arc::clone(&hook), None, &head).await;

    let wrote_at = Instant::now();
    rig.send.write_all(&objects.concat()).await.expect("write objects");

    // Mid-flight: while object 0 waits, nothing behind it may be on the
    // wire. This is where the ablation dies, and it dies fast.
    tokio::time::sleep(HEAD_DELAY / 2).await;
    assert_eq!(
        rig.rx.len(),
        head.len(),
        "objects queued behind a delayed object 0 reached the relay before it did: {} byte(s) \
         past the header after {:?}",
        rig.rx.len() - head.len(),
        HEAD_DELAY / 2,
    );

    let got = rig.rx.wait_for_bytes(stream.len()).await;
    assert_eq!(got, stream, "the destination stream must be byte-equal to the source");
    assert!(
        wrote_at.elapsed() >= HEAD_DELAY,
        "the whole stream arrived in {:?}, before object 0's {HEAD_DELAY:?} delay",
        wrote_at.elapsed(),
    );

    let ids: Vec<u64> =
        rig.rx.into_objects(DRAFT).iter().map(|(_, meta, _)| meta.object_id).collect();
    assert_eq!(ids, (0..COUNT).collect::<Vec<_>>(), "objects re-frame in source order");

    rig.send.finish().expect("finish");
    rig.shutdown().await;
}

// ── the delay is real ──────────────────────────────────────────────────

/// Run one stream through a session whose hook delays every object by
/// `delay` (or passes, when `None`), and report how long after the write
/// each object reached the relay.
async fn arrival_offsets(delay: Option<Duration>, count: u64) -> Vec<Duration> {
    let (head, objects) = subgroup_stream(count, 8);
    let stream = whole(&head, &objects);

    let hook = ScriptedHook::new(move |_| match delay {
        Some(by) => Action::Pass.delayed(by),
        None => Action::Pass,
    });
    let mut rig = Rig::start(hook, None, &head).await;

    let wrote_at = Instant::now();
    rig.send.write_all(&objects.concat()).await.expect("write objects");

    let got = rig.rx.wait_for_bytes(stream.len()).await;
    assert_eq!(got, stream, "the whole stream must arrive for the timings to mean anything");

    let offsets = rig
        .rx
        .into_objects(DRAFT)
        .iter()
        .map(|(at, _, _)| at.saturating_duration_since(wrote_at))
        .collect::<Vec<_>>();
    assert_eq!(offsets.len(), usize::try_from(count).expect("count"));

    rig.send.finish().expect("finish");
    rig.shutdown().await;
    offsets
}

/// No object — not just the first — arrives before its delay has elapsed,
/// and a no-delay control run of the same shape on the same box arrives
/// well inside it.
///
/// The control run is what makes this falsifiable. "Every object arrived at
/// least 300 ms after the write" is trivially satisfied on a loaded CI box
/// by a session that honours no delay at all; the pair is not.
///
/// The lower bound has **no** scheduler exposure — a busy machine can only
/// release later — so it is asserted tightly. The upper bound is the
/// scheduler-exposed half and is deliberately loose; if it ever goes red on
/// a runner, widen it, do not delete it.
///
/// *Ablation (run, and it fails):* in `exec.rs`'s `Action::Delay` arm,
/// ignore `by` and use `unit.arrived_at` as the release time. Every object
/// then lands in the control band and the delayed run's lower bound fails.
#[tokio::test]
async fn a_delayed_object_never_arrives_early() {
    const DELAY: Duration = Duration::from_millis(300);
    const COUNT: u64 = 4;
    /// Loose on purpose: the only scheduler-exposed assertion in this test.
    const SLACK: Duration = Duration::from_millis(1500);

    let control = arrival_offsets(None, COUNT).await;
    for (i, offset) in control.iter().enumerate() {
        assert!(
            *offset < DELAY,
            "control run: object {i} took {offset:?}, which is not distinguishable from a \
             {DELAY:?} delay — the paired comparison this test rests on is meaningless",
        );
    }

    let delayed = arrival_offsets(Some(DELAY), COUNT).await;
    for (i, offset) in delayed.iter().enumerate() {
        assert!(
            *offset >= DELAY,
            "object {i} arrived {offset:?} after the write, inside its {DELAY:?} delay",
        );
        assert!(
            *offset < DELAY + SLACK,
            "object {i} arrived {offset:?} after the write, far past its {DELAY:?} delay; \
             widen SLACK rather than deleting this assertion",
        );
    }
}

/// Nearest-rank percentile of `samples`, which it sorts in place.
///
/// The same definition `release_timer.rs`'s own tests use, so the two
/// files' medians mean the same thing.
fn percentile(samples: &mut [Duration], q: usize) -> Duration {
    assert!(!samples.is_empty(), "no samples");
    samples.sort_unstable();
    let rank = (samples.len() * q).div_ceil(100);
    samples[rank.saturating_sub(1).min(samples.len() - 1)]
}

/// Forty independent 5 ms delays, and not one of them reaches the relay
/// before the 5 ms is up.
///
/// **This is the gated half of the small-delay claim.** The accuracy
/// half — *how close to* 5 ms — is
/// [`calibration_a_five_millisecond_delay_is_measured_as_five_milliseconds`]
/// below, and it is `#[ignore]`d; this one runs on every
/// `cargo test --workspace` and cannot be reddened by a busy box, because
/// every assertion in it is a lower bound, a byte comparison or a count.
///
/// The objects are written one at a time with a gap wider than the delay,
/// so each is queued on an empty queue, armed on the wheel and released by
/// its own wake: forty *independent* samples, not one wake counted forty
/// times. `wrote_at[i]` is taken **before** the `write_all`, so it is
/// strictly earlier than the proxy's own `arrived_at` for that object —
/// which makes `arrival - wrote_at[i] >= DELAY` a strictly weaker claim
/// than the guarantee itself (`release >= arrived_at + by`), and therefore
/// one that no amount of load can falsify.
///
/// Two assertions, and both are needed:
///
/// * `release_errors.count == COUNT` — every object went out through the
///   **release branch**. An implementation that dropped `Delay` on the
///   floor, or one that let the FIN drain flush the queue, reports a
///   different count. This is the structural half: all forty units left
///   through the one path that honours a deadline.
/// * the per-object lower bound — each unit waited for its own deadline.
///
/// It is honest about one limit: on a box so loaded that an *undelayed*
/// object needs more than 5 ms to cross loopback, the lower bound is
/// satisfied vacuously and the test passes without discriminating. That is
/// the acceptable direction — it can go quiet, it cannot go falsely red —
/// and [`a_delayed_object_never_arrives_early`] holds the same claim at
/// 300 ms with a paired control that a loaded box cannot fake.
///
/// *Ablation (run, and it fails):* in `exec.rs`'s `Action::Delay` arm,
/// ignore `by` and use `unit.arrived_at` as the release time. Object 0
/// reaches the relay well inside the 5 ms it asked for — measured 1.49 ms
/// on an idle box, and 2.14-2.55 ms in **5 of 5** runs under 16 busy-loop
/// processes, so the ablation is caught under exactly the load that made
/// the accuracy form of this test unusable. Re-run once the loop staged on
/// arrivals rather than on a settle: `object 0 reached the relay 1.7013ms
/// after it was written, inside the 5ms deadline it asked for`.
#[tokio::test]
async fn a_five_millisecond_delay_is_never_released_early() {
    const COUNT: u64 = 40;
    const DELAY: Duration = Duration::from_millis(5);

    let (head, objects) = subgroup_stream(COUNT, 8);
    let stream = whole(&head, &objects);

    let hook = ScriptedHook::new(|_| Action::Pass.delayed(DELAY));
    let mut rig = Rig::start(hook, None, &head).await;

    let mut wrote_at: Vec<Instant> = Vec::with_capacity(objects.len());
    let mut through = head.len();
    for (i, object) in objects.iter().enumerate() {
        // Before the write, so it is earlier than the proxy's `arrived_at`
        // and the bound below can only be conservative.
        wrote_at.push(Instant::now());
        rig.send.write_all(object).await.expect("write object");
        through += object.len();

        // Object *i* is on the relay before *i+1* is written, so each
        // release is its own wake rather than one batch release of
        // whatever happened to be queued when the wheel next fired. That
        // was a flat 12 ms — wider than `DELAY`, and wide enough on an
        // idle box — but a release slower than the settle turned the run
        // into exactly the batch case the settle was there to avoid, and
        // said nothing. Waiting for the arrival says it happened.
        let seen = rig.rx.wait_for_bytes(through).await;
        assert_eq!(
            seen.len(),
            through,
            "object {i} never reached the relay: {} of {through} byte(s) after it was written",
            seen.len(),
        );
    }

    let got = rig.rx.wait_for_bytes(stream.len()).await;
    assert_eq!(got, stream, "the delayed stream must still arrive intact");

    // Read *before* the source FINs. The FIN drain honours release times
    // but takes no samples, so a unit flushed by it is not a
    // release and `count` would be short of `COUNT`.
    let errors = rig.counters().release_errors;
    assert_eq!(
        errors.count, COUNT,
        "every object must have been released by the release branch, not flushed by a drain",
    );

    let arrivals = rig.rx.into_objects(DRAFT);
    assert_eq!(arrivals.len(), usize::try_from(COUNT).expect("count"), "one arrival per object");
    for (i, (at, meta, _)) in arrivals.iter().enumerate() {
        assert_eq!(meta.object_id, i as u64, "objects re-frame in source order");
        let waited = at.saturating_duration_since(wrote_at[i]);
        assert!(
            waited >= DELAY,
            "object {i} reached the relay {waited:?} after it was written, inside the {DELAY:?} \
             deadline it asked for. A Delay is a lower bound on the release: load may make it \
             later, nothing may make it earlier",
        );
    }

    rig.send.finish().expect("finish");
    rig.shutdown().await;
}

/// **Calibration measurement, not a gate. Requires a quiet machine.**
/// Ignored by default; run with
/// `cargo test -p moqtap-proxy --test actions_timing -- --ignored calibration`.
///
/// Forty independent 5 ms delays, measured against forty
/// `tokio::time::sleep(5 ms)` calls taken in the same run, on the same
/// runtime, under the same load.
///
/// # Why this is opt-in, and why "widen the margin" is not the answer
///
/// The claim here is *accuracy*: that the session's release lateness is
/// small in a way `tokio::time::sleep` is not. Under CPU saturation that
/// claim is not measurable **by any method**, which is a stronger statement
/// than "the bound was too tight", and it is the reason this is `#[ignore]`d
/// rather than loosened.
///
/// The history is worth having in one place, because two formulations have
/// now failed:
///
/// * **Absolute bound.** Shipped as "the session's p50 release lateness is
///   under 3 ms": green 12 runs of 12 alone, red 1 run in 8 inside a full
///   `cargo test --workspace` (p50 8388 µs, p95 29 360, max 38 512).
///   Widening does not fix it — at 8.4 ms the wheel is already inside the
///   ~10 ms a `tokio::time::sleep` implementation lands at on Windows, so a
///   10 ms bound is passed by the very implementation this exists to reject
///   and the ablation below stops failing.
/// * **Paired difference**, i.e. what is written below. The reasoning was
///   that scheduler noise is additive and lands on both arms, so it cancels.
///   **Measured, that is false.** Under 16 busy-loop processes on 16 logical
///   cores the wheel does not hold its ~0.5 ms while tokio keeps its tick;
///   both arms hit the same ceiling. Seven loaded failures, wheel/control:
///   12.58/12.03, 10.49/11.12, 12.58/12.87, 12.58/11.94, 12.58/12.09,
///   12.58/11.45, 12.58/13.26 ms — the wheel slower in four of seven — so
///   the separation was 0 ns against a 3 ms margin. **7 red in 8 loaded
///   runs, 0 red in 5 idle runs**; re-measured while re-homing it, **5 red
///   in 5** loaded runs of this target alone.
///
/// There is no third formulation. A quantity that reads 0.5 ms idle and
/// 12 ms saturated is reporting the box, and `cargo test --workspace` runs
/// on three shared CI runners alongside 76 other targets.
///
/// # This is not concealment
///
/// * The **capability** is still gated, by
///   [`a_five_millisecond_delay_is_never_released_early`] (forty 5 ms
///   deadlines, each honoured as a lower bound, all forty counted by the
///   release branch) and by `release_timer.rs`'s never-early,
///   never-lost and preemption tests. An implementation that regressed to
///   `tokio::time::sleep` is rejected by `release_timer.rs`'s test 2 with
///   no timing budget at all: measured 1975 ms late under its ablation.
/// * The full form of this measurement — schedule 10 000 releases at 1 ms,
///   5 ms, 200 µs spacing and assert p95 release error under a per-platform
///   budget, the test that catches a CI runner with a pathological
///   scheduler — belongs in a dedicated calibration job. The release error
///   is reported in `Counters::release_errors` so a caller can prove its
///   timing was honoured rather than assume it. That reporting is what this
///   test reads, and it is what such a job would read too.
///
/// # Reference numbers, measured on a quiet box
///
/// Windows 11, i9-11900K, 16 logical cores, debug profile, this target
/// alone, five runs, `MARGIN` 3 ms:
///
/// | | wheel p50 (bucket upper bound) | tokio p50 | separation |
/// |---|---|---|---|
/// | idle | 459-524 µs | 10.27-10.56 ms | 9.7-10.1 ms |
/// | under the ablation below | 10.486 ms | 10.522 ms | 36 µs |
/// | 16 busy-loop processes | 10.49-12.58 ms | 11.45-13.26 ms | 0-2.6 ms |
///
/// The wheel's p50 is a bucket **upper** bound (two significant bits per
/// octave) while the control's is exact, so the comparison is biased
/// against the wheel by up to 25% — conservative in the direction that
/// matters.
///
/// # How the two arms are sampled, which is load-bearing
///
/// The objects are written one at a time with a gap wider than the delay, so
/// each is queued on an empty queue, armed on the wheel, and released by its
/// own wake: forty *independent* samples, not one wake counted forty times.
/// Forty units sharing one release instant give a p50 that is a single
/// wake's luck.
///
/// The control sample is taken *after* the settle, not next to the write: a
/// `sleep(DELAY)` armed alongside the unit's own deadline is woken by the
/// wheel's own token cancellation — the wheel unparks the runtime at
/// +5.2 ms, tokio then finds its 5 ms timer expired, and the control arm
/// inherits the wheel's accuracy instead of measuring tokio's. In the settle
/// window there is no armed deadline and no forwarded byte outstanding, so
/// tokio parks on its own timer, which is what a tokio-timed release would
/// have done.
///
/// Both p50s, never p95: a median cannot be moved by a single unlucky wake.
///
/// *Ablation (run, and it fails):* make `release_timer::arm_at` spawn a
/// `tokio::time::sleep` task that cancels the deadline token instead of
/// arming the wheel. Both arms then measure the same ~15.6 ms Windows tick,
/// the difference collapses to about zero (36 µs, measured), and `MARGIN`
/// fails.
///
/// **This is the accuracy measurement taken at session level**, as against
/// the wheel-level one in `release_timer.rs`, and it is still worth having
/// — which is why it was re-homed rather than deleted. Run it when the
/// question is "is this box still fast enough to release on time", not to
/// decide whether a commit is good.
#[tokio::test]
#[ignore = "calibration measurement: asserts timing accuracy, which is not \
            measurable on a loaded box — run with --ignored on a quiet machine"]
async fn calibration_a_five_millisecond_delay_is_measured_as_five_milliseconds() {
    const COUNT: u64 = 40;
    const DELAY: Duration = Duration::from_millis(5);
    /// Wider than `DELAY`, so object *i* is released before *i+1* arrives
    /// and each release is its own wake — and so the control sample below
    /// is taken with nothing else armed.
    ///
    /// A duration here and not an arrival wait, unlike
    /// [`a_five_millisecond_delay_is_never_released_early`], because this
    /// window is part of the instrument: the control arm measures tokio's
    /// timer in a fixed quiet, and a quiet whose length depends on how
    /// fast the wheel was is not the same measurement twice. What the
    /// window buys is asserted rather than assumed — see the loop.
    const SETTLE: Duration = Duration::from_millis(12);
    /// How much better than `tokio::time::sleep` the wheel has to be for
    /// this to count as a difference rather than as luck.
    ///
    /// Windows quantises every interruptible wait to the ~15.6 ms system
    /// tick, so on a **quiet** box the two arms separate by about 10 ms
    /// there: measured wheel p50 459-524 µs end to end against control p50
    /// 10.27-10.56 ms, i.e. 9.7-10.1 ms of separation, and 3 ms is a third
    /// of it. Under the ablation in this test's rustdoc the same two
    /// numbers were 10.486 ms and 10.522 ms — 36 µs.
    ///
    /// **Do not tune this to make a loaded run green.** The separation does
    /// move between an idle box and a loaded one: under 16 busy-loop
    /// processes the wheel arm degrades to the control's own level and the
    /// separation reaches 0 ns, which is why this whole test is
    /// `#[ignore]`d rather than margined.
    /// There is no value here that is both meaningful and load-proof:
    /// anything above ~10 ms is passed by the `tokio::time::sleep`
    /// implementation this exists to reject, and anything below it is
    /// failed by a busy box.
    ///
    /// A tickless platform's tokio timer is ~1 ms coarse, so the same claim
    /// is true there with a smaller separation and the margin follows it.
    const MARGIN: Duration =
        if cfg!(windows) { Duration::from_millis(3) } else { Duration::from_micros(400) };

    let (head, objects) = subgroup_stream(COUNT, 8);
    let stream = whole(&head, &objects);

    let hook = ScriptedHook::new(|_| Action::Pass.delayed(DELAY));
    let mut rig = Rig::start(hook, None, &head).await;

    let mut control: Vec<Duration> = Vec::with_capacity(objects.len());
    let mut through = head.len();
    for (i, object) in objects.iter().enumerate() {
        rig.send.write_all(object).await.expect("write object");
        through += object.len();
        // Object *i* is armed at +5 ms and released inside this window.
        tokio::time::sleep(SETTLE).await;
        // And it is checked, because the control sample is only a control
        // if the wheel is idle when it is taken. A release that overran
        // the settle would leave a wake armed inside the sample and change
        // nothing else about the run, so the reading would be wrong and
        // green.
        assert_eq!(
            rig.rx.len(),
            through,
            "object {i} had not reached the relay {SETTLE:?} after it was written ({} of \
             {through} byte(s)), so the control sample below would be taken with a release \
             still armed. Check the machine was quiet before reading anything into a number \
             from this run",
            rig.rx.len(),
        );

        // The control arm, in the quiet that follows: nothing is armed on
        // the wheel and nothing is in flight, so this measures tokio's
        // timer and not the wheel's wake.
        let asked_at = Instant::now();
        tokio::time::sleep(DELAY).await;
        control.push(asked_at.elapsed().saturating_sub(DELAY));
    }

    let got = rig.rx.wait_for_bytes(stream.len()).await;
    assert_eq!(got, stream, "the delayed stream must still arrive intact");

    // Read *before* the source FINs. The FIN drain honours release times
    // but takes no samples, so a unit flushed by it is not a
    // release and `count` would be short of `COUNT`.
    let errors = rig.counters().release_errors;
    assert_eq!(
        errors.count, COUNT,
        "every object must have been released by the release branch, not flushed by a drain",
    );
    assert_eq!(
        control.len() as u64,
        COUNT,
        "one control sample per object, or the two medians are not paired",
    );

    let wheel_p50 = Duration::from_nanos(errors.p50_ns);
    let tokio_p50 = percentile(&mut control, 50);
    assert!(
        wheel_p50 + MARGIN <= tokio_p50,
        "the session released {} deferred units at a median lateness of {:?} (p95 {} µs, max \
         {} µs), against a median {:?} for the {} tokio::time::sleep({DELAY:?}) calls \
         interleaved with them on this runtime. The wheel has to beat the timer it was written \
         to replace by at least {MARGIN:?}; {:?} is not a difference. This is a calibration \
         measurement: **first check the machine was quiet**, because under CPU saturation both \
         arms degrade together and this separation collapses to zero without anything having \
         regressed. On a quiet box, a red run here means the release path regressed — widen the \
         gap between the mechanisms, do not widen MARGIN",
        errors.count,
        wheel_p50,
        errors.p95_ns / 1_000,
        errors.max_ns / 1_000,
        tokio_p50,
        control.len(),
        tokio_p50.saturating_sub(wheel_p50),
    );

    rig.send.finish().expect("finish");
    rig.shutdown().await;
}

/// A delay shifts latency; it does not stop the read loop.
///
/// The hook stamps every `on_object` call, and the assertion is that the
/// **last** object's hook call happened before the **first** object's bytes
/// reached the relay. Both instants are taken in this process, so this is a
/// paired comparison with no wall-clock bound in it at all.
///
/// This is the test that proves the deque works and an inline
/// `sleep`-in-the-read-arm design does not.
///
/// # The write loop is a feedback loop, and it has to be
///
/// The obvious shape — write the five objects with a fixed gap and compare
/// instants afterwards — **does not fail under its own ablation**, and this
/// was measured, not reasoned about. Under backpressure the client's later
/// objects simply sit in the proxy's QUIC receive buffer, so when the read
/// branch is finally re-enabled *one* read returns all four at once and all
/// four hook calls land within microseconds of object 0's write. The margin
/// between "the last hook call" and "object 0's bytes reached the relay"
/// collapses to the cost of a `write_all` plus a loopback packet, and the
/// test passes on a coin flip.
///
/// So object *i+1* is not written until the hook has been shown object *i*.
/// A read loop that keeps reading gets all five within a few milliseconds; a
/// read loop that stalls behind its queue cannot ask for object *i+1* until
/// object *i* has gone out, and the loop below then takes `COUNT × DELAY`
/// rather than `COUNT` round trips.
///
/// *Ablation (run, and it fails):* in `pipe_data_framed`, make the read
/// branch's precondition `pending.accepts_more() && pending.is_empty()`.
/// The last hook call lands at roughly `COUNT × DELAY` — measured 1.2 s
/// against object 0's arrival at 0.3 s.
#[tokio::test]
async fn delay_is_not_backpressure() {
    const COUNT: u64 = 5;
    const DELAY: Duration = Duration::from_millis(300);

    let (head, objects) = subgroup_stream(COUNT, 8);
    let stream = whole(&head, &objects);

    let hook = ScriptedHook::new(|_| Action::Pass.delayed(DELAY));
    let mut rig = Rig::start(Arc::clone(&hook), None, &head).await;

    for (i, object) in objects.iter().enumerate() {
        rig.send.write_all(object).await.expect("write object");
        rig.wait_for_hook_calls(i + 1).await;
    }

    let got = rig.rx.wait_for_bytes(stream.len()).await;
    assert_eq!(got, stream, "the delayed stream must still arrive intact");

    let calls = rig.hook.calls();
    assert_eq!(
        calls.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
        (0..COUNT).collect::<Vec<_>>(),
        "the hook must be shown every object, in order",
    );
    let last_call = calls.last().expect("one call per object").1;

    let arrivals = rig.rx.into_objects(DRAFT);
    let first_arrival = arrivals.first().expect("object 0 arrived").0;

    assert!(
        last_call < first_arrival,
        "object {} was shown to the hook {:?} *after* object 0's bytes reached the relay; the \
         read loop stalled behind the queue instead of shifting latency",
        COUNT - 1,
        last_call.saturating_duration_since(first_arrival),
    );

    rig.send.finish().expect("finish");
    rig.shutdown().await;
}

/// Two objects arriving together, each `Delay(100 ms)`, are released
/// together — at about +100 ms, not at +100 ms and +200 ms.
///
/// `Delay` is a **deadline** (`arrived_at + by`), not a spacing. The
/// primary assertion is the paired one — how far apart the two arrived —
/// because that is what a spacing implementation gets wrong and it needs no
/// wall-clock bound.
///
/// *Ablation (run, and it fails):* in `egress::defer_by`, return
/// `tail_release_at + by` instead of `arrived_at + by` (equivalently: in
/// `PendingQueue::push`, clamp to `tail + by`). The two objects then land
/// 100 ms apart and `BAND` fails.
#[tokio::test]
async fn delay_is_a_deadline_not_a_spacing() {
    const DELAY: Duration = Duration::from_millis(100);
    /// Half the delay: a spacing implementation misses by a full `DELAY`,
    /// so this discriminates with 50 ms to spare in both directions.
    const BAND: Duration = Duration::from_millis(50);

    let (head, objects) = subgroup_stream(2, 8);
    let stream = whole(&head, &objects);

    let hook = ScriptedHook::new(|_| Action::Pass.delayed(DELAY));
    let mut rig = Rig::start(hook, None, &head).await;

    let wrote_at = Instant::now();
    // One write, so both objects arrive in one chunk and share an
    // `arrived_at` — the case where a deadline and a spacing differ.
    rig.send.write_all(&objects.concat()).await.expect("write objects");

    let got = rig.rx.wait_for_bytes(stream.len()).await;
    assert_eq!(got, stream, "both objects must arrive");

    let arrivals = rig.rx.into_objects(DRAFT);
    let first = arrivals[0].0;
    let second = arrivals[1].0;
    let apart = second.saturating_duration_since(first);

    assert!(
        apart < BAND,
        "the two objects arrived {apart:?} apart; each asked for {DELAY:?} from its own \
         arrival, so a deadline releases them together and a spacing releases them {DELAY:?} \
         apart",
    );
    assert!(
        first.saturating_duration_since(wrote_at) >= DELAY,
        "object 0 arrived before its {DELAY:?} deadline",
    );

    rig.send.finish().expect("finish");
    rig.shutdown().await;
}

// ── hold, release, clamp ───────────────────────────────────────────────

/// Low enough that a `max_hold` stall is two seconds rather than thirty,
/// and far enough from `RESUME_WINDOW` to be unambiguous.
const HOLD_CEILING: Duration = Duration::from_secs(2);
/// A released gate is due *now*; anything near [`HOLD_CEILING`] is the bug.
const RESUME_WINDOW: Duration = Duration::from_secs(1);
/// How long the negative half of a hold assertion watches for.
const QUIET: Duration = Duration::from_millis(200);

/// Build the `EgressConfig` the two hold tests share.
fn egress_with_ceiling() -> EgressConfig {
    // Field assignment, not a struct literal: `EgressConfig` is
    // `#[non_exhaustive]`, which forbids literal construction here.
    let mut egress = EgressConfig::default();
    egress.max_hold = HOLD_CEILING;
    egress
}

/// A `Hold` stops the unit it is returned for; releasing the gate makes it
/// due **immediately**, not at `max_hold`.
///
/// `pop_next_due` treats a released gate as due regardless of
/// `release_at`. Without that clause the `select!`'s release arm wakes on the
/// gate, finds nothing due, and spins hot until the `max_hold` ceiling — so
/// the observable is elapsed time, not a wake counter.
///
/// Exactly one object, so the only thing this can fail on is the gate
/// clause. [`releasing_a_gate_resumes_the_stream`] is the same shape with
/// traffic queued behind the hold, and it does not pass; keeping the two
/// apart is what makes that failure diagnostic rather than ambiguous.
///
/// *Ablation (run, and it fails):* in `egress::Pending::is_due`, drop the
/// `|| gate released` clause and consider only `release_at`. The object
/// then arrives at the 2 s ceiling and `RESUME_WINDOW` fails.
#[tokio::test]
async fn a_released_gate_makes_the_held_unit_due_at_once() {
    let (head, objects) = subgroup_stream(1, 8);
    let stream = whole(&head, &objects);

    let gate = Gate::new();
    let hook_gate = gate.clone();
    let hook = ScriptedHook::new(move |_| Action::Pass.held(hook_gate.clone()));
    let mut rig = Rig::start(hook, Some(egress_with_ceiling()), &head).await;

    rig.send.write_all(&objects.concat()).await.expect("write object");

    // The negative claim needs a window, not a poll: nothing past the
    // header may be on the wire while the gate is shut.
    common::assert_no_bytes_for(&rig.rx, QUIET).await;
    assert_eq!(rig.rx.len(), head.len(), "only the header has been forwarded");

    let released_at = Instant::now();
    gate.release();

    let got = rig.rx.wait_for_bytes(stream.len()).await;
    let resumed_in = released_at.elapsed();
    assert_eq!(got, stream, "releasing the gate must forward the held object");
    assert!(
        resumed_in < RESUME_WINDOW,
        "the held object went out {resumed_in:?} after the gate was released; a released gate \
         is due at once, and anything near max_hold ({HOLD_CEILING:?}) means the release arm \
         woke, found nothing due, and spun",
    );

    rig.send.finish().expect("finish");
    rig.shutdown().await;
}

/// Nothing arrives while the gate is shut; releasing it delivers the whole
/// stream — every object queued behind the hold, and the FIN — byte-equal
/// to the source.
///
/// # What this pinned, and what fixed it
///
/// Measured on 2026-08-05, four objects, object 0 held and objects 1-3
/// `Pass`, `max_hold` 2 s, the gate released 200 ms in: the whole stream
/// arrived **1.84 s** after the release — that is, at object 0's `max_hold`
/// ceiling. With the shipped default `max_hold` of 30 s it would have been
/// 30 s. Releasing the gate resumed the *held object* and nothing else.
///
/// The cause was the interaction of two rules, each fine on its own:
///
/// * `Action::Hold` gives its unit `due_at = arrived_at + max_hold` — the
///   ceiling, not an expected release (`egress::hold_ceiling`).
/// * `PendingQueue::push` clamped every later unit's *release time* to
///   `max(release_at, now, tail_release_at)`.
///
/// So objects 1-3 were stamped with the *ceiling* of a unit that would not
/// wait for it, and they carry no gate, so `Pending::is_due` had nothing to
/// make them due early. The gate clause fixed the head and only the head.
///
/// What keeps it green: `push` does not clamp a unit's own deadline at all.
/// Ordering is the deque's job — `pop_next_due` only ever looks at the
/// front — and the clamp is what `Pending::expected_at` computes, which is
/// reported as `Effect::Queued { release_at }` and gates nothing.
///
/// It was not visible from `egress.rs`'s own tests:
/// `a_released_gate_makes_a_unit_due_before_its_ceiling` puts exactly one
/// unit in the queue, so it never pushes anything behind a gated tail. It is
/// the gap between that unit test and this integration test, which is why
/// this test asserts on the whole stream and not just the held object;
/// `egress::tests::releasing_a_gate_frees_the_whole_run_queued_behind_it`
/// now closes it at queue level too.
///
/// *Ablation (run, and it fails):* in `PendingQueue::push`, clamp
/// `unit.due_at` the way `unit.expected_at` is clamped. The stream resumes
/// at the 2 s ceiling instead of at the release, and `RESUME_WINDOW` fails.
///
/// Companion: [`a_released_gate_makes_the_held_unit_due_at_once`] is this
/// test with the queue behind the hold removed, and it passed throughout —
/// which is what localised the defect to the successors.
#[tokio::test]
async fn releasing_a_gate_resumes_the_stream() {
    let (head, objects) = subgroup_stream(4, 8);
    let stream = whole(&head, &objects);

    let gate = Gate::new();
    let hook_gate = gate.clone();
    let hook = ScriptedHook::new(move |id| {
        if id == 0 {
            Action::Pass.held(hook_gate.clone())
        } else {
            Action::Pass
        }
    });
    let mut rig = Rig::start(hook, Some(egress_with_ceiling()), &head).await;

    rig.send.write_all(&objects.concat()).await.expect("write objects");

    common::assert_no_bytes_for(&rig.rx, QUIET).await;
    assert_eq!(rig.rx.len(), head.len(), "only the header has been forwarded");

    let released_at = Instant::now();
    gate.release();

    let got = rig.rx.wait_for_bytes(stream.len()).await;
    let resumed_in = released_at.elapsed();
    assert_eq!(got, stream, "releasing the gate must resume the whole stream, in order");
    assert!(
        resumed_in < RESUME_WINDOW,
        "the stream resumed {resumed_in:?} after the gate was released, which is the \
         max_hold ceiling ({HOLD_CEILING:?}) and not the release: units queued behind a hold \
         inherit the hold's ceiling through the monotonic clamp and carry no gate of their \
         own, so nothing makes them due when the gate opens. See this test's rustdoc.",
    );

    rig.send.finish().expect("finish");
    rig.shutdown().await;
}

/// The same, at the **shipped** `max_hold` of 30 s, with the source FINed
/// before the release — because the FIN is queued behind the hold too.
///
/// This is the reproduction as it was measured, and it is a strictly harder
/// shape than [`releasing_a_gate_resumes_the_stream`] in two ways that both
/// matter:
///
/// * `EgressConfig::default()` — no lowered ceiling, so a successor that
///   inherits the hold's deadline waits **30 s** and `wait_for_bytes` gives
///   up at its 10 s `TIMEOUT` with a short buffer, rather than eventually
///   arriving;
/// * the client FINs before the gate opens, so the mover is the FIN drain
///   (`egress::drain_honouring_release_times`) rather than the pipe loop's
///   release branch, and `Ending::Fin` is the assertion that the drain ran
///   to completion instead of returning after the held unit.
///
/// Measured before the fix, 5 runs of 5, five objects of 8 bytes each with
/// object 1 held: five seconds after the release the relay had **25 of 55
/// bytes** — the header and object 0 at 44 µs, object 1 at 158 ms, then
/// nothing. Objects 2, 3, 4 and the FIN were stranded until `max_hold`.
///
/// *Ablation (run, and it fails):* in `PendingQueue::push`, clamp
/// `unit.due_at` the way `unit.expected_at` is clamped.
#[tokio::test]
async fn releasing_a_gate_resumes_the_stream_and_its_fin() {
    const COUNT: u64 = 5;
    /// The held object's index. Not 0: object 0 goes out inline from the
    /// read arm, so its arrival proves the pipe is live and the bytes that
    /// follow are the queue's doing.
    const HELD: u64 = 1;

    let (head, objects) = subgroup_stream(COUNT, 8);
    let stream = whole(&head, &objects);
    let through_object_0 = head.len() + objects[0].len();

    let gate = Gate::new();
    let hook_gate = gate.clone();
    let hook = ScriptedHook::new(move |id| {
        if id == HELD {
            Action::Pass.held(hook_gate.clone())
        } else {
            Action::Pass
        }
    });
    // `None` is the shipped `EgressConfig::default()`: `max_hold` 30 s.
    let mut rig = Rig::start(hook, None, &head).await;

    rig.send.write_all(&objects.concat()).await.expect("write objects");
    rig.send.finish().expect("finish");

    let seen = rig.rx.wait_for_bytes(through_object_0).await;
    assert_eq!(
        seen.len(),
        through_object_0,
        "object 0 is not held and must reach the relay whatever the queue does",
    );
    common::assert_no_bytes_for(&rig.rx, QUIET).await;
    assert_eq!(rig.rx.len(), through_object_0, "nothing behind the hold may be on the wire");

    let released_at = Instant::now();
    gate.release();

    let got = rig.rx.wait_for_bytes(stream.len()).await;
    assert_eq!(
        got, stream,
        "releasing the gate must resume every object behind the hold, in order",
    );
    let ending = rig.rx.wait_for_ending().await;
    assert_eq!(
        ending,
        Ending::Fin,
        "the FIN waits for the queue to drain, so a stranded queue strands the FIN too",
    );
    let resumed_in = released_at.elapsed();
    assert!(
        resumed_in < RESUME_WINDOW,
        "the stream and its FIN took {resumed_in:?} after the release; with the shipped \
         30 s max_hold anything near a second means the units behind the hold were stamped \
         with its ceiling",
    );

    rig.shutdown().await;
}

/// A `Delay` queued behind a `Hold` keeps its **own** deadline.
///
/// `Action::Delay`'s rustdoc calls its argument "a deadline, not a spacing":
/// the guarantee is `arrived_at + by` and nothing else. A `Hold` in front of
/// it may make it *later* — ordering — but may not redefine what it is
/// waiting for.
///
/// Measured before the fix, `max_hold` 20 s, object 1 held and object 2
/// `Pass.delayed(50 ms)` with the gate released at 200 ms: object 2 was
/// stamped with the hold's ceiling and never became due — 25 of 35 bytes
/// three seconds after the release.
///
/// The assertions are a matched pair around object 2's arrival, and both
/// are needed:
///
/// * **not before** `wrote_at + DELAY` — a lower bound, so it has no
///   scheduler exposure at all, and it is what an implementation that
///   dropped the delay to resume-on-gate would fail;
/// * **not after** `wrote_at + DELAY + SLACK` — the defect this test is
///   named for, which lands at the 5 s ceiling.
///
/// `CEILING` is deliberately far outside `DELAY + SLACK` so the two cannot
/// be confused on a loaded runner.
///
/// *Ablation (run, and it fails):* in `PendingQueue::push`, clamp
/// `unit.due_at` the way `unit.expected_at` is clamped. Object 2 arrives at
/// the 5 s ceiling and the upper bound fails.
#[tokio::test]
async fn a_delay_behind_a_hold_keeps_its_own_deadline() {
    /// Far enough out that inheriting it is unmistakable.
    const CEILING: Duration = Duration::from_secs(5);
    const DELAY: Duration = Duration::from_millis(400);
    /// The gate opens well inside `DELAY`, so object 2's own deadline —
    /// and not the release — is what has to hold it back.
    const RELEASE_AFTER: Duration = Duration::from_millis(100);
    /// The scheduler-exposed half. Widen it if a runner needs it; do not
    /// delete it, and keep it far below `CEILING - DELAY`.
    const SLACK: Duration = Duration::from_millis(1500);

    let (head, objects) = subgroup_stream(3, 8);
    let stream = whole(&head, &objects);
    let through_object_0 = head.len() + objects[0].len();
    let through_object_1 = through_object_0 + objects[1].len();

    let gate = Gate::new();
    let hook_gate = gate.clone();
    let hook = ScriptedHook::new(move |id| match id {
        0 => Action::Pass,
        1 => Action::Pass.held(hook_gate.clone()),
        _ => Action::Pass.delayed(DELAY),
    });

    let mut egress = EgressConfig::default();
    egress.max_hold = CEILING;
    let mut rig = Rig::start(hook, Some(egress), &head).await;

    let wrote_at = Instant::now();
    rig.send.write_all(&objects.concat()).await.expect("write objects");

    let seen = rig.rx.wait_for_bytes(through_object_0).await;
    assert_eq!(seen.len(), through_object_0, "object 0 is neither held nor delayed");

    tokio::time::sleep(RELEASE_AFTER).await;
    assert_eq!(rig.rx.len(), through_object_0, "objects 1 and 2 are both still waiting");
    gate.release();

    // Object 1 carries the gate, so it is due at once.
    let seen = rig.rx.wait_for_bytes(through_object_1).await;
    assert_eq!(seen.len(), through_object_1, "a released gate frees the object that carries it");

    let got = rig.rx.wait_for_bytes(stream.len()).await;
    assert_eq!(got, stream, "the whole stream must arrive, in order");

    let arrivals = rig.rx.into_objects(DRAFT);
    assert_eq!(arrivals.len(), 3, "three objects re-frame out of the destination stream");
    let object_2 = arrivals[2].0.saturating_duration_since(wrote_at);
    assert!(
        object_2 >= DELAY,
        "object 2 arrived {object_2:?} after the write, inside its own {DELAY:?} deadline; \
         a released gate must not release a delay that is still waiting",
    );
    assert!(
        object_2 < DELAY + SLACK,
        "object 2 arrived {object_2:?} after the write: its own {DELAY:?} deadline was \
         overwritten with the hold's {CEILING:?} ceiling. Delay is a deadline, and a Hold in \
         front of it does not get to redefine it",
    );

    rig.send.finish().expect("finish");
    rig.shutdown().await;
}

/// A delay longer than `max_hold` is clamped, executed at the ceiling, and
/// reported once.
///
/// *Ablation (run, and it fails):* in `egress::Deferral::was_clamped`,
/// return `false`. The object still goes out at the ceiling — so a test
/// that only timed it would pass — and no `HoldClamped` is emitted.
#[tokio::test]
async fn a_delay_beyond_max_hold_is_clamped_and_reported() {
    const MAX_HOLD: Duration = Duration::from_millis(60);
    const ASKED: Duration = Duration::from_secs(5);

    let (head, objects) = subgroup_stream(1, 8);
    let stream = whole(&head, &objects);

    let hook = ScriptedHook::new(|_| Action::Pass.delayed(ASKED));

    let mut egress = EgressConfig::default();
    egress.max_hold = MAX_HOLD;
    let mut rig = Rig::start(hook, Some(egress), &head).await;

    let wrote_at = Instant::now();
    rig.send.write_all(&objects.concat()).await.expect("write object");

    let got = rig.rx.wait_for_bytes(stream.len()).await;
    assert_eq!(got, stream, "a clamped delay still forwards the object");
    assert!(
        wrote_at.elapsed() < ASKED / 2,
        "the object took {:?}: the {ASKED:?} request was not clamped to {MAX_HOLD:?}",
        wrote_at.elapsed(),
    );
    assert!(
        wrote_at.elapsed() >= MAX_HOLD,
        "the object arrived in {:?}, before the {MAX_HOLD:?} ceiling it was clamped to",
        wrote_at.elapsed(),
    );

    assert_eq!(
        rig.observer.impairments(),
        vec![ImpairmentKind::HoldClamped { requested: Some(ASKED), applied: MAX_HOLD }],
        "a clamp is reported once per clamped unit, with both durations",
    );

    rig.send.finish().expect("finish");
    rig.shutdown().await;
}

/// A bucket that grants **nothing, ever**, so the only thing that can
/// release a unit is the clamp.
///
/// `rate_bps: Some(0)` with `burst_bytes: 0` makes the bucket answer "never"
/// for every unit: there is no accrual, no refill instant, and therefore no
/// duration for the clamp report to quote. `Some(0)` is emphatically not
/// `None` — `None` means unlimited and paces nothing.
fn never_grants(max_hold: Duration) -> ShapeProfile {
    let mut bucket = BucketConfig::default();
    bucket.name = "still".to_string();
    bucket.rate_bps = Some(0);
    bucket.burst_bytes = 0;

    let mut class = ClassRule::default();
    class.name = "everything".to_string();
    class.bucket = "still".to_string();
    // All-`None`, which claims every unit. Spelled out because "this rule
    // matches everything" is load-bearing here, not an omission.
    class.matcher = Matcher::default();
    class.weight = 1;

    let mut queue = QueueConfig::default();
    queue.max_hold = Some(max_hold);
    queue.on_expiry = Expiry::Deliver;

    ShapeProfile::try_new(vec![bucket], vec![class], queue, Discipline::Fifo)
        .expect("one class over the bucket it names")
}

/// **A clamp says what it cut short, and says nothing when there was
/// nothing to say.** The two producers of `HoldClamped`, in one test, on the
/// event surface a run report is written from.
///
/// # Why both legs, and why they must be one test
///
/// * A hook's `Delay { by }` names a figure, so its report carries
///   `Some(by)` — and the leg pins the exact duration, not merely that one
///   is present.
/// * A token bucket at rate zero names **no** refill instant. Nothing but
///   the clamp will ever release its head, and there is no duration to
///   quote, so its report carries `None`.
///
/// Either leg alone is satisfied by a constant. "Always `Some(x)`" passes
/// the first, "always `None`" passes the second, and the pair passes
/// neither — which is the whole property, because the field's job is to
/// **distinguish** a bounded request from an unbounded one.
///
/// # What it replaces
///
/// The unbounded case was reported as `Duration::MAX`, i.e. as
/// `18446744073709551615.999999999s` in an event log. The assertion an
/// author writes against a clamp is that it *reduced* the request —
/// `requested > applied` — and that inequality holds for the sentinel and
/// for a real thirty-second request alike, so it certified nothing while
/// looking like the strongest available claim. `applied` is asserted on
/// both legs for the same reason it always was: a clamp that reports no
/// ceiling is not a clamp.
///
/// # Ablations, both run
///
/// **(a) Restore the sentinel** — `requested: Some(Duration::MAX)` in
/// `egress::PendingQueue::expire_head`'s `Expiry::Deliver` arm. The delayed
/// leg is untouched; the shaped leg reddens with
/// `left: [HoldClamped { requested: Some(18446744073709551615.999999999s), applied: 60ms }]`.
///
/// **(b) Report the shaped clamp's ceiling as its request** —
/// `requested: Some(self.shape_hold)`. The stream still arrives and the
/// clamp is still reported, so nothing else in the file moves; this leg
/// reddens with `requested: Some(60ms)`, which is the fabrication the
/// absent field exists to refuse.
#[tokio::test]
async fn hold_clamped_reports_no_request_for_an_unbounded_wait() {
    const MAX_HOLD: Duration = Duration::from_millis(60);
    const ASKED: Duration = Duration::from_secs(30);

    let (head, objects) = subgroup_stream(1, 8);
    let stream = whole(&head, &objects);

    let mut egress = EgressConfig::default();
    egress.max_hold = MAX_HOLD;

    // Leg 1 — a hook that names 30 s against a 60 ms ceiling.
    let delayed = {
        let hook = ScriptedHook::new(|_| Action::Pass.delayed(ASKED));
        let mut rig = Rig::start(hook, Some(egress), &head).await;
        rig.send.write_all(&objects.concat()).await.expect("write object");
        assert_eq!(
            rig.rx.wait_for_bytes(stream.len()).await,
            stream,
            "a clamped delay still forwards the object"
        );
        let reported = rig.observer.impairments();
        rig.send.finish().expect("finish");
        rig.shutdown().await;
        reported
    };

    // Leg 2 — the same ceiling, no hook action at all, and a bucket that
    // will not release the head on any timescale.
    let shaped = {
        let hook = ScriptedHook::new(|_| Action::Pass);
        let mut rig = Rig::start_shaped(hook, egress, never_grants(MAX_HOLD), &head).await;
        rig.send.write_all(&objects.concat()).await.expect("write object");
        assert_eq!(
            rig.rx.wait_for_bytes(stream.len()).await,
            stream,
            "Expiry::Deliver is late, never lossy: the clamp delivers the object"
        );
        let reported = rig.observer.impairments();
        rig.send.finish().expect("finish");
        rig.shutdown().await;
        reported
    };

    assert_eq!(
        delayed,
        vec![ImpairmentKind::HoldClamped { requested: Some(ASKED), applied: MAX_HOLD }],
        "a hook that asked for {ASKED:?} is reported as having asked for it"
    );
    assert_eq!(
        shaped,
        vec![ImpairmentKind::HoldClamped { requested: None, applied: MAX_HOLD }],
        "a bucket at rate zero names no refill instant, so the clamp cut short \
         an unbounded wait and there is no duration to report"
    );
}

// ── composition ────────────────────────────────────────────────────────

/// `Delay` and `Hold` wrap a *content* action. Wrapping a terminal, a
/// session close or another modifier is refused **before the unit reaches
/// the deque** — which is why `egress_items_queued` is asserted as well as
/// the refusal.
///
/// Four cases, one session each, because counters are session-scoped.
///
/// *Ablation (run, and it fails):* in `exec.rs`'s `Action::Delay` arm, push
/// a `Pending::bytes(raw, deferral.release_at)` before calling
/// `check_composition`. Every refusal is still reported — so the event
/// assertions still pass — and `egress_items_queued` moves to 1, which is
/// the assertion that catches it.
#[tokio::test]
async fn a_delay_wrapping_a_terminal_is_refused_before_it_is_queued() {
    const WRAPPED_TERMINAL: &str = "Delay or Hold wrapping Truncate or ResetStream";
    const WRAPPED_CLOSE: &str = "Delay or Hold wrapping CloseSession";
    const NESTED_MODIFIER: &str = "Delay or Hold wrapping another Delay or Hold";

    let cases: Vec<(&str, Action, ActionKind, &str)> = vec![
        (
            "Delay { then: ResetStream }",
            Action::ResetStream { code: 0x2 }.delayed(Duration::from_millis(50)),
            ActionKind::ResetStream,
            WRAPPED_TERMINAL,
        ),
        (
            "Delay { then: Truncate }",
            Action::Truncate { bytes: 4, code: 0x2 }.delayed(Duration::from_millis(50)),
            ActionKind::Truncate,
            WRAPPED_TERMINAL,
        ),
        (
            "Delay { then: CloseSession }",
            Action::CloseSession { code: 3, reason: Bytes::from_static(b"nope") }
                .delayed(Duration::from_millis(50)),
            ActionKind::CloseSession,
            WRAPPED_CLOSE,
        ),
        (
            "Delay { then: Delay }",
            Action::Pass.delayed(Duration::from_millis(10)).delayed(Duration::from_millis(50)),
            ActionKind::Delay,
            NESTED_MODIFIER,
        ),
    ];

    for (name, action, expected_kind, expected_detail) in cases {
        let (head, objects) = subgroup_stream(3, 8);
        let stream = whole(&head, &objects);

        let action = Mutex::new(Some(action));
        let hook = ScriptedHook::new(move |id| {
            if id == 1 {
                // Taken once: only object 1 carries the bad composition, so
                // exactly one refusal is expected.
                action.lock().expect("case action").take().expect("object 1 is decided once")
            } else {
                Action::Pass
            }
        });
        let mut rig = Rig::start(hook, None, &head).await;

        rig.send.write_all(&objects.concat()).await.expect("write objects");

        let got = rig.rx.wait_for_bytes(stream.len()).await;

        // Asserted **first**, deliberately: this is the one claim nothing
        // else in this test can make — a refusal reported
        // after the push looks identical in the event log, and its only
        // fingerprint is a counter that moved.
        let counters = rig.counters();
        assert_eq!(
            counters.egress_items_queued, 0,
            "[{name}] the composition is validated before the unit reaches the deque",
        );
        assert_eq!(counters.actions_refused, 1, "[{name}] one refusal, counted per attempt");

        assert_eq!(got, stream, "[{name}] a refused action forwards the unit unchanged");
        assert_eq!(
            rig.observer.refused(),
            vec![(
                Site::Object,
                expected_kind,
                Refusal::WrongComposition { detail: expected_detail },
            )],
            "[{name}] exactly one WrongComposition refusal, naming the wrapped action",
        );
        assert!(
            rig.observer.applied().iter().all(|(_, kind, _)| *kind == ActionKind::Pass),
            "[{name}] nothing but the two Pass objects was applied: {:?}",
            rig.observer.applied(),
        );

        rig.send.finish().expect("finish");
        rig.shutdown().await;
    }
}

// ── cancellation while held ────────────────────────────────────────────

/// What the pipe task did with a unit it was holding when the session was
/// cancelled: delivered it, or reported it stranded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeldOutcome {
    Delivered,
    Stranded,
}

/// Wait for the held unit to be accounted for, one way or the other.
///
/// The guarantee is that the held object is either delivered or reported as
/// `Impairment { QueuedBytesAtTeardown }` — never silently gone. The
/// disjunction is not slack: on cancellation the pipe races
/// `run_with_transport`'s `client.close()` / `relay.close()`, and the two
/// outcomes are exactly the two sides of that race. A drain that never
/// resolves produces **neither**, which is what the ablations below do.
async fn held_unit_settled(
    rx: &TimedReceiver,
    observer: &RecordingObserver,
    want_bytes: usize,
    within: Duration,
) -> HeldOutcome {
    let deadline = Instant::now() + within;
    loop {
        if rx.len() >= want_bytes {
            return HeldOutcome::Delivered;
        }
        if observer
            .impairments()
            .iter()
            .any(|k| matches!(k, ImpairmentKind::QueuedBytesAtTeardown { .. }))
        {
            return HeldOutcome::Stranded;
        }
        if Instant::now() >= deadline {
            panic!(
                "{within:?} after cancellation the held unit was neither delivered ({} of {} \
                 bytes) nor reported as QueuedBytesAtTeardown; impairments were {:?}",
                rx.len(),
                want_bytes,
                observer.impairments(),
            );
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// A `Hold` on a gate nobody releases must never pin a stream past
/// cancellation — in three orderings, each pinned so it exercises the drain
/// it is meant to.
///
/// Leaving it unpinned whether the source FINs before the cancel lets a run
/// enter the FIN drain or skip it, so the test can go green with the hazard
/// still live. Each case below waits for a *recorded event* before
/// cancelling, so the ordering is not a sleep.
///
/// Three cases, because the three reach cancellation through different
/// code: case 1 through the pipe loop's own cancel arm, cases 2 and 3
/// through `egress::drain_honouring_release_times` — nominally two drains,
/// the FIN drain and the terminal drain, but one shared function in the
/// implementation. Cases 2 and 3 therefore share an ablation: there is no
/// separate terminal-drain body left to revert on its own. Both call sites
/// are still exercised, which is what keeping them as separate cases buys.
///
/// *Ablations (both run, and each fails only its own cases):*
/// (a) delete the `_ = ctx.cancel.cancelled()` arm from `pipe_data_framed`'s
///     `select!`. `wait_release` still resolves on cancel, so the loop wakes,
///     finds the held head not due, and spins — case 1 fails, cases 2 and 3
///     still pass;
/// (b) rewrite `egress::drain_honouring_release_times` as a plain
///     `while let Some(release) = pending.head_release()` loop over
///     `wait_release` + `pop_next_due`, with no `biased` cancel arm — cases 2
///     and 3 fail, case 1 still passes.
///
/// Both ablations are *hot spins*: `wait_release` resolves immediately once
/// the session is cancelled, `pop_next_due` finds the held head not due, and
/// the loop goes round without ever yielding. On this runtime that starves
/// the test's own timers too, so the failure takes the 30 s `max_hold`
/// ceiling to surface and ablation (b) against case 3 reports through
/// `wait_for_ending`'s internal expect rather than through this file's
/// message. Both still fail, for the right reason; the delay is noted so the
/// next person does not read a 30 s ablation run as a hang.
///
/// # Why the default runtime and not `flavor = "multi_thread"`
///
/// Because on a multi-thread runtime case 1 does not pass, and the reason is
/// a **separate defect**, not this one — see
/// [`a_held_object_is_never_silently_lost_at_teardown`], which pins it. Left
/// here it would conflate "the drain noticed the cancel" (this test) with
/// "the bytes survived the teardown race" (that one), and neither diagnosis
/// would be readable.
#[tokio::test]
async fn cancelling_while_an_object_is_held_tears_down_promptly() {
    /// Teardown has to be observable inside a second, and it is measured
    /// against the pipe task rather than against `ProxySession::run` — see
    /// this file's module doc for why the latter cannot fail.
    const WINDOW: Duration = Duration::from_secs(1);

    cancel_with_the_source_open(WINDOW).await;
    cancel_after_the_source_fins(WINDOW).await;
    cancel_with_a_terminal_behind_the_hold(WINDOW).await;
}

/// Case 1: the source is still open, so the pipe loop's own cancel arm is
/// what has to notice.
async fn cancel_with_the_source_open(window: Duration) {
    let (head, objects) = subgroup_stream(1, 32);
    let stream = whole(&head, &objects);

    let gate = Gate::new();
    let hook_gate = gate.clone();
    let hook = ScriptedHook::new(move |_| Action::Pass.held(hook_gate.clone()));
    let mut rig = Rig::start(hook, None, &head).await;

    rig.send.write_all(&objects.concat()).await.expect("write object");

    // Deterministic ordering: the unit is on the queue before we cancel.
    rig.wait_for_event("the held object to be queued", |obs| {
        obs.applied().iter().any(|(site, kind, effect)| {
            *site == Site::Object
                && *kind == ActionKind::Hold
                && matches!(effect, Effect::Queued { .. })
        })
    })
    .await;
    assert_eq!(rig.rx.len(), head.len(), "case 1: the held object must not be on the wire yet");

    rig.proxy.cancel.cancel();
    let outcome = held_unit_settled(&rig.rx, &rig.observer, stream.len(), window).await;
    if outcome == HeldOutcome::Delivered {
        assert_eq!(rig.rx.bytes(), stream, "case 1: a late delivery is still the source bytes");
    }

    // The gate was never released, and must not have been what freed it.
    assert!(!gate.is_released(), "case 1: nothing may release the gate but the test");
    rig.shutdown().await;
}

/// Case 2: the source FINs **first**, so the FIN drain is entered and is
/// waiting on a gate nobody will release; only then is the session
/// cancelled.
///
/// The ordering is pinned without a sleep: object 0 carries a plain 150 ms
/// `Delay` and object 1 the `Hold`. The client FINs immediately after
/// writing, so object 0 can only reach the relay from inside the FIN
/// drain — its arrival is therefore proof that the drain is running and is
/// now blocked on object 1's gate.
async fn cancel_after_the_source_fins(window: Duration) {
    const LEAD_DELAY: Duration = Duration::from_millis(150);

    let (head, objects) = subgroup_stream(2, 32);
    let stream = whole(&head, &objects);
    let through_object_0 = head.len() + objects[0].len();

    let gate = Gate::new();
    let hook_gate = gate.clone();
    let hook = ScriptedHook::new(move |id| {
        if id == 0 {
            Action::Pass.delayed(LEAD_DELAY)
        } else {
            Action::Pass.held(hook_gate.clone())
        }
    });
    let mut rig = Rig::start(hook, None, &head).await;

    rig.send.write_all(&objects.concat()).await.expect("write objects");
    rig.send.finish().expect("finish");

    let seen = rig.rx.wait_for_bytes(through_object_0).await;
    assert_eq!(
        seen.len(),
        through_object_0,
        "case 2: object 0 must come out of the FIN drain before the cancel, or the case \
         degenerates into case 1",
    );
    assert_eq!(rig.rx.len(), through_object_0, "case 2: object 1 is held, not forwarded");

    rig.proxy.cancel.cancel();
    let outcome = held_unit_settled(&rig.rx, &rig.observer, stream.len(), window).await;
    if outcome == HeldOutcome::Delivered {
        assert_eq!(rig.rx.bytes(), stream, "case 2: a late delivery is still the source bytes");
    }

    assert!(!gate.is_released(), "case 2: nothing may release the gate but the test");
    rig.shutdown().await;
}

/// Case 3: a positional terminal is queued **behind** the held object, so
/// the drain that has to notice cancellation is the one `Plan::Terminal`
/// runs before it resets the destination.
///
/// Object 0 is held; object 1 returns `Truncate`, which is pushed behind it
/// and reported as `Effect::Truncated` at the decision — that event is the
/// ordering probe, and it fires before the drain blocks.
///
/// **The observable here is the `RESET_STREAM`, not the bytes**, and that is
/// forced rather than chosen. The cancel-fallback drain writes the held
/// object and the truncated prefix and *then* calls `reset()`, which
/// discards whatever of them quinn had not yet put on the wire — measured:
/// zero bytes past the header reach the relay, every time. `Action::Truncate`
/// says exactly this ("the peer observes **at most** `bytes` further bytes,
/// and may observe none"), and the truncate tests in `actions_objects.rs`
/// assert an upper bound and a prefix for the same
/// reason. So the drain having run is proved by the reset arriving with the
/// action's code; asserting on delivered bytes here would be asserting on
/// something QUIC does not promise.
async fn cancel_with_a_terminal_behind_the_hold(window: Duration) {
    const TRUNCATE_AT: usize = 4;
    const RESET_CODE: u64 = 0x2;

    let (head, objects) = subgroup_stream(2, 32);

    let gate = Gate::new();
    let hook_gate = gate.clone();
    let hook = ScriptedHook::new(move |id| {
        if id == 0 {
            Action::Pass.held(hook_gate.clone())
        } else {
            Action::Truncate { bytes: TRUNCATE_AT, code: RESET_CODE }
        }
    });
    let mut rig = Rig::start(hook, None, &head).await;

    rig.send.write_all(&objects.concat()).await.expect("write objects");

    rig.wait_for_event("the terminal to be queued behind the hold", |obs| {
        obs.applied().iter().any(|(site, kind, effect)| {
            *site == Site::Object
                && *kind == ActionKind::Truncate
                && matches!(effect, Effect::Truncated { code: RESET_CODE, .. })
        })
    })
    .await;
    assert_eq!(rig.rx.len(), head.len(), "case 3: nothing behind the hold may be on the wire");

    let cancelled_at = Instant::now();
    rig.proxy.cancel.cancel();

    let ending =
        tokio::time::timeout(window, rig.rx.wait_for_ending()).await.unwrap_or_else(|_| {
            panic!(
                "case 3: {window:?} after cancellation the terminal queued behind the hold had \
                 not fired — the drain that runs before a `Plan::Terminal` reset never noticed \
                 the cancel. Impairments were {:?}",
                rig.observer.impairments(),
            )
        });
    assert_eq!(
        ending,
        Ending::Reset(RESET_CODE),
        "case 3: the queued terminal must fire with the code the action stated",
    );
    assert!(
        cancelled_at.elapsed() < window,
        "case 3: the terminal fired {:?} after the cancel",
        cancelled_at.elapsed(),
    );
    assert!(
        rig.rx.len() <= head.len() + objects[0].len() + TRUNCATE_AT,
        "case 3: never more than the held object plus the truncated prefix",
    );

    assert!(!gate.is_released(), "case 3: nothing may release the gate but the test");
    rig.shutdown().await;
}

/// A held object is either delivered or reported as
/// `Impairment { QueuedBytesAtTeardown }` — never silently gone.
///
/// # What this pinned, on a multi-thread runtime, and what fixed it
///
/// Measured on 2026-08-05, `flavor = "multi_thread"`, **8 runs out of 8**:
/// one 256 KiB object held on a gate nobody releases, the source still open,
/// the session cancelled. One second later the relay had received the stream
/// header and nothing else — 5 of 262 154 bytes — and the observer had
/// recorded **no impairment at all**. The relay's read then failed with
/// `ConnectionLost(ApplicationClosed(… b"proxy session ended"))`: the
/// session's own `relay.close()` had already torn the connection down.
///
/// With a 32-byte object the same case failed 12 runs out of 14 — a
/// race, not a certainty. The object size below is what turns the race into
/// a fact, and the reasoning is in its doc comment. It is deliberately
/// separate from [`cancelling_while_an_object_is_held_tears_down_promptly`]
/// so that one stays a clean measurement of a different property.
///
/// [`cancelling_while_an_object_is_held_tears_down_promptly`] is the same
/// case on tokio's default current-thread runtime and passed every time,
/// which is exactly why this was filed separately: the difference is
/// scheduling, and the runtime this failed on is the one a real deployment
/// uses (`#[tokio::main]` is multi-thread by default).
///
/// The race itself is known and remains open: a cancelled session still
/// races `client.close()` / `relay.close()` on tasks nobody awaits. What is
/// supposed to make that race harmless — and what was **not** true — is that
/// anything still queued is reported as
/// `Impairment { QueuedBytesAtTeardown }`. It was not, on either of the two
/// paths that can win this race:
///
/// * the pipe loop's cancel arm calls `drain_ignoring_release_times` and then
///   reported only `pending.queued_bytes()`. A `write_all` that succeeded
///   into a connection that is about to close leaves **nothing** queued, so
///   there was nothing to report and the bytes were gone silently. This is
///   the path that won here: instrumented, the cancel arm saw
///   `queued=262149` on entry and `stranded=0` after the drain;
/// * `propagate_reset` — reached when the read arm's `ConnectionLost` wins
///   over the cancel arm — drained best-effort with `let _ = …` and never
///   emitted `QueuedBytesAtTeardown` at all.
///
/// So the guarantee was not "delivered or reported"; it was "delivered, or
/// reported, or lost, depending on which task the scheduler ran first". Both
/// paths are closed the same way: `PendingQueue` now counts what a teardown
/// drain *hands to the transport* as unconfirmed, every teardown site
/// reports `unconfirmed_bytes()` instead of `queued_bytes()`, and
/// `propagate_reset` reports at all. The event already documented itself
/// this way — "flushed best-effort; `bytes` may not have reached the peer".
///
/// *Ablation (run, and it fails):* make
/// `egress::PendingQueue::unconfirmed_bytes` return `self.queued_bytes`.
/// The 256 KiB object is handed to a dying quinn connection, nothing is left
/// queued, no impairment is emitted, and this goes red exactly as it did on
/// 2026-08-05.
#[tokio::test(flavor = "multi_thread")]
async fn a_held_object_is_never_silently_lost_at_teardown() {
    const WINDOW: Duration = Duration::from_secs(1);
    /// 256 KiB, and the size is load-bearing in both directions. Small
    /// enough to stay well inside the framer's 4 MiB buffering cap and the
    /// queue's 1 MiB budget, so the object is a real held unit and not a
    /// `Passthrough`; large enough that quinn cannot possibly have put it on
    /// the wire in the microseconds between the drain's `write_all` and
    /// `relay.close()`. With a 32-byte object the same defect shows up as a
    /// coin flip (12 failures in 14 runs), which is a bad way to report a
    /// bug; with this one the loss is what the transport must do.
    const PAYLOAD: usize = 256 * 1024;

    let (head, objects) = subgroup_stream(1, PAYLOAD);
    let stream = whole(&head, &objects);

    let gate = Gate::new();
    let hook_gate = gate.clone();
    let hook = ScriptedHook::new(move |_| Action::Pass.held(hook_gate.clone()));
    let mut rig = Rig::start(hook, None, &head).await;

    rig.send.write_all(&objects.concat()).await.expect("write object");

    rig.wait_for_event("the held object to be queued", |obs| {
        obs.applied().iter().any(|(site, kind, effect)| {
            *site == Site::Object
                && *kind == ActionKind::Hold
                && matches!(effect, Effect::Queued { .. })
        })
    })
    .await;
    assert_eq!(rig.rx.len(), head.len(), "the held object must not be on the wire yet");

    rig.proxy.cancel.cancel();
    let outcome = held_unit_settled(&rig.rx, &rig.observer, stream.len(), WINDOW).await;
    if outcome == HeldOutcome::Delivered {
        assert_eq!(rig.rx.bytes(), stream, "a late delivery is still the source bytes");
    }

    assert!(!gate.is_released(), "nothing may release the gate but the test");
    rig.shutdown().await;
}

// ── the deferred-release stop, both sites ──────────────────────────────
//
// `session.rs` has nine write sites that can surface a destination peer's
// `STOP_SENDING`. Seven are inline `send.write_all` calls and every one of
// them routes its error through `propagate_stop`. The other two are the
// `release_due_units(..)` calls in the two `select!` release branches —
// the control pipe's and the data pipe's — and they used a bare `?`.
//
// That is not a cosmetic asymmetry. The release branch is the *only* write
// a `Delay`/`Hold` stream ever makes: the whole point of deferring is that
// nothing goes out inline. So on exactly the streams this file exists to
// test, a peer's stop reason was replaced by the hard-coded `0` that
// quinn's `RecvStream::drop` sends.
//
// # Why these fixtures block the write, and why they must
//
// The stream-level stop watcher (`StopWatcher`) races the read and the
// release as a fourth `select!` branch, so a stop that arrives while the
// loop is *parked* is mirrored by the watcher and this path never runs.
// The two are not redundant, and the difference is what these fixtures are
// built around: once `select!` has picked the release branch, its arm body
// runs to completion with **no branch polling at all**, so a stop that
// lands while `release_due_units` is inside `write_all` can surface here
// and nowhere else.
//
// Reaching that state is what `stream_receive_window` is for. quinn's
// default gives the destination peer a 1.25 MB per-stream window, so a peer
// that never reads still absorbs every fixture in this file and no proxy
// write is ever in flight long enough to be stopped. Pinning the window
// small makes "the proxy is parked inside `write_all`" a property of the
// fixture rather than a race, which is what lets each leg's ablation be
// attributed to one source line.
//
// # And each leg waits for the park rather than timing it
//
// The window makes the park inevitable; it does not say when it starts.
// Spending a fixed `50 ms + 200 ms` there and calling the proxy
// "demonstrably parked" would be a claim about the run that the run was
// never asked. It matters more here than in most places: a stop that lands
// before the release branch has entered its write is mirrored by
// `StopWatcher` instead, and a leg that drifted into that ordering would
// stay green under its own ablation while gating the other site.
//
// So each leg waits for something it can see, and the two are
// different because the two fixtures park differently:
//
// * **data** — one object is larger than the whole window, so the first
//   released write cannot complete. Its destination is the client, which
//   accepted the stream on the header alone (headers are not deferred), so
//   one more STREAM frame than the accept saw means the release branch is
//   inside a `write_all` it cannot leave.
// * **control** — the frames are ~20 bytes each and complete in their
//   hundreds, so what fills the window is the count. The proxy's own
//   `release_errors.count` reaches a window's worth of them and the next
//   write is the one that parks, with thousands of bytes still queued
//   behind it.
//
// Both legs' ablations were re-run against the waits, and each still fails
// only its own leg with `left: Some(0), right: Some(7)`. Neither wait
// changed under them, which is the point: they observe the write, and the
// ablation is about what happens to its error.

/// The code the destination peer stops with. Not `0` — that is what
/// `RecvStream::drop` sends, and telling the two apart is the whole test.
const DELAY_STOP_CODE: u64 = 0x07;

/// How long each unit is deferred before the release branch runs.
const STOP_LEG_DELAY: Duration = Duration::from_millis(50);

/// How often each leg looks again while waiting for the write to park.
const STOP_LEG_POLL: Duration = Duration::from_millis(2);

/// Wait until the destination has been sent bytes it has no room for.
///
/// `frame_rx.stream` counts the STREAM frames a connection has received
/// whether or not the application ever reads them, and the caller takes
/// its own baseline by calling this: nothing else writes to these
/// destinations, so one more frame is the release branch's write.
///
/// Panics rather than returning on the deadline. A leg that reached its
/// stop without a parked write is not a leg that fails a little later —
/// it is a leg testing the stop watcher, and saying so here is more use
/// than `Some(0)` two assertions further down.
async fn wait_for_a_parked_write(conn: &quinn::Connection) {
    let baseline = conn.stats().frame_rx.stream;
    let deadline = tokio::time::Instant::now() + common::TIMEOUT;
    while conn.stats().frame_rx.stream == baseline {
        assert!(
            tokio::time::Instant::now() < deadline,
            "no released bytes reached the destination within {:?}: the release branch never \
             wrote, so the stop this leg is about to send would land on a parked read instead",
            common::TIMEOUT,
        );
        tokio::time::sleep(STOP_LEG_POLL).await;
    }
}

/// How long the source waits to learn it was stopped. On the passing path
/// this resolves at once; only a broken run waits it out.
const STOP_LEG_WINDOW: Duration = Duration::from_millis(400);

/// The destination's per-stream receive window. Small enough that the
/// first released unit fills it; see the section comment above.
const STOP_LEG_RECV_WINDOW: u32 = 4096;

/// What one leg observed: the code the *source* was stopped with, and
/// every impairment the session reported.
struct StopLegOutcome {
    observed: Option<u64>,
    impairments: Vec<ImpairmentKind>,
}

/// One assertion body for both legs, so a site cannot drift.
fn assert_stop_during_a_delay_is_mirrored(leg: &str, out: &StopLegOutcome) {
    assert_eq!(
        out.observed,
        Some(DELAY_STOP_CODE),
        "{leg}: the destination's STOP_SENDING code must reach the source. `Some(0)` is the \
         defect — a bare `?` on the release branch returns without mirroring and quinn's \
         RecvStream::drop stops the source with a hard-coded 0. `None` means it was never \
         stopped at all. Impairments: {:?}",
        out.impairments
    );

    let stranded = out
        .impairments
        .iter()
        .filter(|k| matches!(k, ImpairmentKind::QueuedBytesAtTeardown { .. }))
        .count();
    assert!(
        stranded > 0,
        "{leg}: the units still queued behind the one that failed must be reported as stranded, \
         or a deferred stream loses bytes silently. Impairments: {:?}",
        out.impairments
    );
}

/// **The data pipe's release branch (`pipe_data_framed`).**
///
/// Relay → client. Every object is deferred, so the release branch is the
/// only thing that ever writes; the client accepts the forwarded stream and
/// then never reads it, so the first released object fills its 4 KiB window
/// and the write parks. The stop lands 200 ms into that park.
///
/// *Ablation (run, and it fails):* in `pipe_data_framed`, replace the
/// `match released { .. }` block with the original
/// `if release_due_units(..).await? == Flow::StreamOver { return Ok(()); }`.
/// The relay then observes `Some(0)` instead of `Some(7)`.
#[tokio::test]
async fn a_stop_during_a_delay_is_mirrored_on_the_data_path() {
    common::init_crypto();

    let observer = Arc::new(RecordingObserver::new());
    let relay = Arc::new(FakeRelay::bind(ALPN));
    let hook = ScriptedHook::new(|_| Action::Pass.delayed(STOP_LEG_DELAY));

    let proxy = common::spawn_proxy_with(
        common::session_config(DRAFT, relay.addr),
        ALPN,
        Arc::clone(&observer) as Arc<dyn ProxyObserver>,
        hook,
    );
    let (_client_ep, client_conn) =
        common::connect_client_windowed(proxy.addr, ALPN, Some(STOP_LEG_RECV_WINDOW)).await;

    // Six 4 KiB objects: the first fills the client's window on its own,
    // and the other five stay queued so `propagate_stop` has residue to
    // report.
    let (head, objects) = subgroup_stream(6, 4096);
    let mut source = relay.open_uni().await;
    source.write_all(&whole(&head, &objects)).await.expect("relay write");

    // Accepted and then never read: the window stays full.
    let mut recv = tokio::time::timeout(common::TIMEOUT, client_conn.accept_uni())
        .await
        .expect("the client saw the forwarded stream")
        .expect("accept_uni");

    // Object 0 is 4 KiB against a 4 KiB window that the header has already
    // eaten into, so the write that puts one byte here can place none of
    // the rest: when this returns the release branch is parked inside it.
    wait_for_a_parked_write(&client_conn).await;
    recv.stop(quinn::VarInt::from_u64(DELAY_STOP_CODE).unwrap()).expect("client stop");

    let observed = match tokio::time::timeout(STOP_LEG_WINDOW, source.stopped()).await {
        Ok(Ok(Some(code))) => Some(code.into_inner()),
        _ => None,
    };
    let out = StopLegOutcome { observed, impairments: observer.impairments() };

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;

    assert_stop_during_a_delay_is_mirrored("data leg", &out);
}

// ── the control pipe's release branch ──────────────────────────────────
//
// Pinned to **draft-14**, unlike everything else in this file, and the pin
// is a fact about the fixture rather than about the code under test.
// `pipe_control_mutating`'s release branch is draft-independent — it writes
// whatever the hook deferred — but *reaching* it needs control frames the
// proxy's parser will actually decode, and a CLIENT_SETUP is a different
// message on each cohort: type `0x40` with a varint length on drafts 07-10,
// `0x20` with a `u16` length on 11-14, versions replaced by parameters on
// 15-16, and a unified `SETUP` at `0x2F00` with delta-encoded KVP options
// on 17-20. A "portable" encoder here would be four encoders and three
// guesses.
//
// Draft-14 also keeps `moq-00` — this file's ALPN — meaningful: it leaves
// `draft_is_fixed` false, so the pipe additionally has to close its
// draft-detection window from these bytes before it forwards any of them,
// which is the same path `proxy_reset.rs`'s control tests exercise.

/// Encode a QUIC variable-length integer.
///
/// Local, like every other fixture in this file: a control fixture built
/// with the codec that parses it cannot see a shared misunderstanding of
/// the wire format.
#[cfg(feature = "draft14")]
fn put_varint(out: &mut Vec<u8>, value: u64) {
    match value {
        0..=63 => out.push(value as u8),
        64..=16_383 => out.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes()),
        16_384..=1_073_741_823 => {
            out.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes());
        }
        _ => out.extend_from_slice(&(value | 0xC000_0000_0000_0000).to_be_bytes()),
    }
}

/// One draft-14 CLIENT_SETUP — type `0x20`, `u16` length, one supported
/// version and no parameters.
#[cfg(feature = "draft14")]
fn client_setup_d14() -> Vec<u8> {
    let mut payload = Vec::new();
    put_varint(&mut payload, 1);
    put_varint(&mut payload, DraftVersion::Draft14.version_varint().into_inner());
    put_varint(&mut payload, 0);

    let mut out = Vec::new();
    put_varint(&mut out, 0x20);
    out.extend_from_slice(&u16::try_from(payload.len()).expect("setup fits u16").to_be_bytes());
    out.extend_from_slice(&payload);
    out
}

/// A hook that defers every control frame, so the control pipe's release
/// branch is the only thing that ever writes towards the relay.
#[cfg(feature = "draft14")]
struct DelayingControlHook;

#[cfg(feature = "draft14")]
impl ProxyHook for DelayingControlHook {
    fn interest(&self) -> Interest {
        Interest::CONTROL
    }

    fn on_control_message(
        &self,
        _cx: &FrameCtx<'_>,
        _msg: &AnyControlMessage,
        _raw: &[u8],
    ) -> Action {
        Action::Pass.delayed(STOP_LEG_DELAY)
    }
}

/// **The control pipe's release branch (`pipe_control_mutating`).**
///
/// The higher-blast-radius half. An idle control stream is MoQT's steady
/// state, so a control stream whose frames are deferred is precisely the
/// case with no inline write to fall back on, and `a_stop_on_an_idle_...`
/// in `actions_teardown.rs` gates the *watcher* rather than this site.
///
/// Client → relay, because the draft-detection window `moq-00` opens can
/// only be closed by a CLIENT_SETUP and those only travel that way. The
/// relay accepts the control stream and never reads it, so the first
/// released frames fill its 4 KiB window and the write parks.
///
/// *Ablation (run, and it fails):* in `pipe_control_mutating`, replace the
/// `match released { .. }` block with the original
/// `if release_due_units(..).await? == Flow::StreamOver { return Ok(()); }`.
/// The client then observes `Some(0)` instead of `Some(7)`.
#[cfg(feature = "draft14")]
#[tokio::test]
async fn a_stop_during_a_delay_is_mirrored_on_the_control_path() {
    const ALPN_D14: &[u8] = b"moq-00";

    common::init_crypto();

    let observer = Arc::new(RecordingObserver::new());
    let relay = Arc::new(FakeRelay::bind_windowed(ALPN_D14, STOP_LEG_RECV_WINDOW));

    let proxy = common::spawn_proxy_with(
        common::session_config(DraftVersion::Draft14, relay.addr),
        ALPN_D14,
        Arc::clone(&observer) as Arc<dyn ProxyObserver>,
        Arc::new(DelayingControlHook),
    );
    let (_client_ep, client_conn) =
        common::connect_client_windowed(proxy.addr, ALPN_D14, None).await;

    // Enough CLIENT_SETUPs to overrun the relay's window several times
    // over, sized from the window rather than guessed so the fixture still
    // overruns it if either number changes.
    let one = client_setup_d14();
    let copies = 4 * STOP_LEG_RECV_WINDOW as usize / one.len() + 1;
    let mut frames = Vec::with_capacity(copies * one.len());
    for _ in 0..copies {
        frames.extend_from_slice(&one);
    }
    assert!(
        frames.len() > 3 * STOP_LEG_RECV_WINDOW as usize,
        "the control fixture must be able to overrun the destination window"
    );

    let (mut source, _client_recv) = client_conn.open_bi().await.expect("client open_bi");
    source.write_all(&frames).await.expect("client write");

    // Accepted and then never read. `_relay_send` is held for the case's
    // lifetime: dropping a quinn `SendStream` FINs it, which is a teardown
    // the proxy would forward and this test would then be measuring.
    let (_relay_send, mut relay_recv) = tokio::time::timeout(common::TIMEOUT, relay.accept_bi())
        .await
        .expect("the relay saw the forwarded control stream");

    // A window's worth of frames have been released, so the relay has no
    // room for another and the release branch is parked in the write of
    // the next one — with the rest of `frames`, three windows of it,
    // still queued behind. Counting releases rather than watching the
    // relay's frames because these complete: the relay's own accept above
    // is already the first release arriving.
    let window_worth = (STOP_LEG_RECV_WINDOW as usize).div_ceil(one.len()) as u64;
    let deadline = tokio::time::Instant::now() + common::TIMEOUT;
    while proxy.counters().release_errors.count < window_worth {
        assert!(
            tokio::time::Instant::now() < deadline,
            "only {} of the {window_worth} frame(s) that fill the relay's window were \
             released within {:?}, so the write below is not parked yet",
            proxy.counters().release_errors.count,
            common::TIMEOUT,
        );
        tokio::time::sleep(STOP_LEG_POLL).await;
    }
    relay_recv.stop(quinn::VarInt::from_u64(DELAY_STOP_CODE).unwrap()).expect("relay stop");

    let observed = match tokio::time::timeout(STOP_LEG_WINDOW, source.stopped()).await {
        Ok(Ok(Some(code))) => Some(code.into_inner()),
        _ => None,
    };
    let out = StopLegOutcome { observed, impairments: observer.impairments() };

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;

    assert_stop_during_a_delay_is_mirrored("control leg", &out);
}

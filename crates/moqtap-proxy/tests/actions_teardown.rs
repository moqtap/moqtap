//! Stream and session teardown: `Action::ResetStream`,
//! `Action::CloseSession`, the reset synthesized from a non-reset read
//! failure, and the two propagation directions nothing else covers.
//!
//! # What each group here is for
//!
//! **A non-reset read failure must not become a FIN.** `propagate_reset`
//! used to mirror only `TransportError::StreamReset`; every other read
//! failure dropped the destination `SendStream`, and quinn's `Drop` calls
//! `finish()`. The player then reads a truncated group to EOF and commits it
//! as complete. `a_non_reset_read_failure_resets_a_data_stream` proves the
//! peer now sees a reset, on **both** data pipes — `pipe_data_passthrough`
//! (`Interest::NONE`) and `pipe_data_framed` (`Interest::STREAMS`) are
//! separate functions with separate `propagate_reset` call sites.
//! `a_non_reset_read_failure_on_the_control_stream_does_not_synthesize_a_reset`
//! proves the control stream is exempt: MoQT treats a reset control stream as
//! a session-level error, so the destination still FINs and the truncation is
//! reported as `Impairment { ControlStreamTruncated }`.
//!
//! **The two untested propagation directions.** `proxy_reset.rs` covers
//! `pipe_data` relay→client and both *client-initiated* control paths.
//! Missing were `pipe_data` client→relay and control relay→client. Both are
//! here, driven through one `propagation_case` parameterized over
//! [`Leg`] — same code, different `side` argument, which is exactly where
//! the risk lies: reset propagation is written once per direction, so one
//! direction can be correct while its mirror image was never wired up.
//!
//! **The reset-fidelity guarantees, restated in this file.** `a_clean_fin_stays_a_fin`
//! and `a_mirrored_reset_keeps_the_peer_code_after_data_already_written` are
//! not duplicates of `proxy_reset.rs` for their own sake — they are the
//! *negative controls* for the synthesized-reset ablation. Stub the new
//! `propagate_reset` arms and the synthesized-reset tests must go red while
//! those two stay green; a change
//! that reddened all four would mean the tests were measuring "a reset
//! happened" rather than "a reset happened *for this reason*".
//!
//! # Why the data-stream test asserts code `0x0` and not `0x3`
//!
//! `session.rs::synthesized_reset_code` maps `TransportError::ConnectionLost`
//! and `Connection(_)` to `0x3` (SESSION_CLOSED) and everything else to `0x0`
//! (INTERNAL_ERROR). A relay that dies mid-subgroup *should* therefore be
//! `0x3` — but `moqtap-client/src/transport/quic.rs`'s
//! `From<quinn::ReadError>` has exactly one typed arm, `Reset(code)`, and
//! collapses `ReadError::ConnectionLost(_)` into
//! `TransportError::Read(String)`. Nothing in the workspace constructs
//! `TransportError::ConnectionLost` from a real read, so the `0x3` arm is
//! unreachable end to end and the observed code is `0x0`. The substance —
//! *reset rather than FIN* — holds either way, and this file asserts the
//! code that is actually produced rather than the one the mapping suggests.
//!
//! # Ablations, each measured
//!
//! Every test below has a named source change that reddens it, run and
//! recorded rather than reasoned about. Restore each one after running it.
//!
//! | Ablation | Reddens | Stays green |
//! |---|---|---|
//! | `propagate_reset`: drop the `synthesized_reset_code` reset+report | both `a_non_reset_read_failure_resets_*` | `a_clean_fin_stays_a_fin`, `a_mirrored_reset_*`, all four propagation legs |
//! | `propagate_reset`: drop `if st.is_control_stream` | both `..._control_stream_does_not_synthesize_a_reset` (they see `Reset(0)`) | the data-stream tests |
//! | `propagate_reset`: drop `if let Some(code) = mirrored` | all four propagation legs **and** `a_mirrored_reset_*` | `a_clean_fin_stays_a_fin` |
//! | `run_stream_end`: `Target::StreamEnd { is_control_stream: false }` | `reset_stream_at_the_control_streams_end_is_refused` | `reset_stream_reaches_the_peer_with_the_requested_code` |
//! | `exec::execute`: drop `check_error_code` on `ResetStream` | `an_out_of_range_reset_code_is_refused_before_anything_is_sent` | the rest |
//! | `pipe_data_framed` FIN branch: `Plan::Terminal => {}` | `reset_stream_reaches_the_peer_with_the_requested_code` | `a_clean_fin_stays_a_fin` |
//! | `run_with_transport`: hard-code `client.close(0, b"proxy session ended")` | `close_session_carries_the_requested_code_and_reason` | the rest |
//! | `SessionCloser::request`: always return `true` | `a_second_close_session_is_refused` | the rest |
//!
//! The `Plan::Terminal => {}` ablation must be applied to the **framed** FIN
//! branch: `pipe_data_passthrough` carries a byte-identical block, and
//! ablating that one instead leaves every test here green, because
//! `Interest::STREAMS` never takes the pass-through pipe. That near-miss is
//! recorded because it is the shape of a test that measures nothing.
//!
//! Every test here runs on [`DRAFT`] — draft-14 — and the file's
//! CLIENT_SETUP fixture is a draft-14 message, so the whole file is gated
//! on that draft rather than compiled into rows whose codec cannot build
//! the fixture.

#![cfg(feature = "draft14")]

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;

use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::draft14::message::{ClientSetup, ControlMessage};
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

use moqtap_proxy::action::{Action, Interest, StreamEnd};
use moqtap_proxy::capability::{ActionKind, Refusal, Site};
use moqtap_proxy::event::{Effect, ImpairmentKind, ProxySide};
use moqtap_proxy::hook::{FrameCtx, NoOpHook, ProxyHook, StreamCtx};
use moqtap_proxy::observer::ProxyObserver;

use common::{Ending, FakeRelay, RecordingObserver, SpawnedProxy};

/// The draft every test here runs on, and the ALPN that carries it.
///
/// Drafts 07-14 share `moq-00`, which `DraftVersion::from_alpn` does not
/// resolve, so `draft_is_fixed` is false and the session parses as whatever
/// the config says — [`DRAFT`]. Load-bearing for one assertion: draft-14
/// *does* define a stream-reset code vocabulary, which is why every
/// `Effect::StreamReset` below is expected with `code_defined: true`. On
/// drafts 07-10 the same tests would want `false`.
const DRAFT: DraftVersion = DraftVersion::Draft14;

/// The client ALPN the front-end endpoint advertises. See [`DRAFT`].
const ALPN: &[u8] = b"moq-00";

/// Whether [`DRAFT`] defines stream-reset codes, as reported in
/// `Effect::StreamReset { code_defined }` / `Effect::Truncated`.
const CODE_DEFINED: bool = true;

/// Leading `0x04` is the subgroup stream-type varint; the rest stands in for
/// the start of a group whose publisher never finishes it.
const PARTIAL_GROUP: &[u8] = &[0x04, 0x01, 0x02, 0x03];

/// The code `synthesized_reset_code` produces for a read failure that is not
/// a peer `RESET_STREAM`. `0x0` INTERNAL_ERROR — see the module docs for why
/// it is not `0x3`.
const SYNTHESIZED_CODE: u64 = 0x0;

/// A peer-chosen `RESET_STREAM` code, distinct from every code the proxy
/// might synthesize, so "mirrored" and "synthesized" can never be confused.
const PEER_RESET_CODE: u64 = 0x1F;

/// The code a hook asks for at `Site::StreamEnd`.
const HOOK_RESET_CODE: u64 = 0x2;

/// Above the QUIC varint ceiling (2^62 - 1), so it must be refused.
const OUT_OF_RANGE_CODE: u64 = u64::MAX;

/// How many streams `a_second_close_session_is_refused` ends at once.
///
/// Two: one close to win, one to be refused. Nothing here is a lever on a
/// probability, because [`CountingCloseHook`] holds each decision until
/// both exist. The number was 24 for as long as it was, because 24 was how
/// many trials it took for a race to come out the right way often enough —
/// see the test's own docs for what that cost and what it measured at.
const CLOSING_STREAMS: u8 = 2;

/// How long [`CountingCloseHook`] waits at each of its two gates.
///
/// Bounded, so a run where the second stream end never arrives fails on an
/// assertion naming what was missing rather than hanging. What it bounds is
/// normally microseconds: every FIN is already written and in flight before
/// the first call reaches the gate.
const BARRIER_TIMEOUT: Duration = Duration::from_secs(5);

// ── hooks ──────────────────────────────────────────────────────────────

/// What a [`StreamEndHook`] returns, given the stream and how it ended.
type StreamEndDecision = dyn Fn(&StreamCtx<'_>, StreamEnd) -> Action + Send + Sync;

/// Returns one fixed [`Action`] from `on_stream_end`, and records the
/// [`StreamEnd`] reasons it was shown.
///
/// `interest()` is [`Interest::STREAMS`], which is what arms `on_stream_end`
/// at all — and, because `STREAMS` contains `OBJECTS` structurally, also
/// what puts data streams on `pipe_data_framed`.
struct StreamEndHook {
    action: Box<StreamEndDecision>,
    seen: Mutex<Vec<(bool, StreamEnd)>>,
}

impl StreamEndHook {
    fn new(action: impl Fn(&StreamCtx<'_>, StreamEnd) -> Action + Send + Sync + 'static) -> Self {
        Self { action: Box::new(action), seen: Mutex::new(Vec::new()) }
    }

    /// A hook that returns `action` at every stream end, control or data.
    fn always(action: Action) -> Self {
        Self::new(move |_, _| action.clone())
    }

    /// Every `(is_control_stream, end)` the hook was shown.
    fn seen(&self) -> Vec<(bool, StreamEnd)> {
        self.seen.lock().expect("seen").clone()
    }
}

impl ProxyHook for StreamEndHook {
    fn interest(&self) -> Interest {
        Interest::STREAMS
    }

    fn on_stream_end(&self, cx: &StreamCtx<'_>, end: StreamEnd) -> Action {
        self.seen.lock().expect("seen").push((cx.is_control_stream, end));
        (self.action)(cx, end)
    }
}

/// Asks for [`Interest::CONTROL`], so the session routes the control stream
/// through `pipe_control_mutating` rather than `pipe_control_passthrough`.
///
/// The count is the only externally visible difference between the two
/// paths: `on_control_message` fires **only** under `control_mutation`, so a
/// zero count means the session silently took the pass-through pipe and the
/// test was a duplicate of its sibling.
#[derive(Default)]
struct ControlMutatingHook {
    seen: Mutex<usize>,
}

impl ControlMutatingHook {
    fn seen(&self) -> usize {
        *self.seen.lock().expect("seen")
    }
}

impl ProxyHook for ControlMutatingHook {
    fn interest(&self) -> Interest {
        Interest::CONTROL
    }

    fn on_control_message(
        &self,
        _cx: &FrameCtx<'_>,
        _msg: &AnyControlMessage,
        _raw: &[u8],
    ) -> Action {
        *self.seen.lock().expect("seen") += 1;
        Action::Pass
    }
}

/// Returns [`Action::CloseSession`] with a different code each time it is
/// called, so "the first close wins" is falsifiable: with one fixed code the
/// test could not tell first-wins from last-wins.
///
/// # Two gates, because two different things would otherwise be luck
///
/// **A later decision has to exist.** `SessionCloser::request` cancels the
/// session token synchronously, inside `exec::execute`, so the moment the
/// first close is recorded every other pipe is racing its own
/// `cancel.cancelled()` branch — and a pipe that takes it never calls a
/// hook again. So the *first* call blocks until `expected` calls have
/// arrived. Every one of them is then already past its `select!` and inside
/// a hook, where no cancellation can reach it.
///
/// **The order they reach the executor has to be known.** Two calls
/// released together are two tasks racing to `SessionCloser::request`, and
/// whichever won would be the code the peer saw — which is last-wins and
/// first-wins made indistinguishable, the exact thing the differing codes
/// are here to tell apart. So every *later* call blocks until the first
/// one's close has been applied, read off the observer the session reports
/// to.
///
/// Both gates are bounded by [`BARRIER_TIMEOUT`]. This is the shape
/// `action_matrix.rs` uses for its own racing-close probe, for the first of
/// these two reasons.
struct CountingCloseHook {
    codes: Vec<u32>,
    reasons: Vec<Bytes>,
    calls: Mutex<usize>,
    /// How many data-stream ends the first call waits for.
    expected: usize,
    /// Where a later call reads "the first close has been applied".
    observer: Arc<RecordingObserver>,
}

impl CountingCloseHook {
    fn new(
        pairs: &[(u32, &'static [u8])],
        expected: usize,
        observer: Arc<RecordingObserver>,
    ) -> Self {
        Self {
            codes: pairs.iter().map(|(c, _)| *c).collect(),
            reasons: pairs.iter().map(|(_, r)| Bytes::from_static(r)).collect(),
            calls: Mutex::new(0),
            expected,
            observer,
        }
    }

    fn calls(&self) -> usize {
        *self.calls.lock().expect("calls")
    }

    /// Whether a `CloseSession` has been reported as applied.
    fn a_close_was_applied(&self) -> bool {
        self.observer.applied().iter().any(|(_, action, _)| *action == ActionKind::CloseSession)
    }
}

impl ProxyHook for CountingCloseHook {
    fn interest(&self) -> Interest {
        Interest::STREAMS
    }

    fn on_stream_end(&self, cx: &StreamCtx<'_>, _end: StreamEnd) -> Action {
        // The control stream's end is not one of the decisions being
        // counted. It arrives at teardown, after the session is already
        // closing, so letting it take a gate slot would leave a data
        // stream's end waiting for a call that had already happened.
        if cx.is_control_stream {
            return Action::Pass;
        }
        let i = {
            let mut calls = self.calls.lock().expect("calls");
            let i = *calls;
            *calls += 1;
            i
        };
        if i == 0 {
            wait_blocking(|| self.calls() >= self.expected);
        } else {
            wait_blocking(|| self.a_close_was_applied());
        }
        let at = i.min(self.codes.len() - 1);
        Action::CloseSession { code: self.codes[at], reason: self.reasons[at].clone() }
    }
}

/// Spin until `f` holds, or give up after [`BARRIER_TIMEOUT`].
///
/// `std::thread::sleep`, not `tokio::time::sleep`: a hook is a synchronous
/// call from a forwarding task, so there is no `.await` to reach for. That
/// is what makes the one test using it need more than one worker thread —
/// the thread this parks is a thread the task it is waiting for cannot run
/// on.
fn wait_blocking(f: impl Fn() -> bool) {
    let deadline = std::time::Instant::now() + BARRIER_TIMEOUT;
    while !f() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(2));
    }
}

// ── shared plumbing ────────────────────────────────────────────────────

/// Wire bytes of a draft-14 CLIENT_SETUP, so the control stream carries a
/// real message before it is torn down.
fn client_setup_bytes() -> Vec<u8> {
    let msg = AnyControlMessage::Draft14(ControlMessage::ClientSetup(ClientSetup {
        supported_versions: vec![VarInt::from_u64(0xff00_0000 + 14).unwrap()],
        parameters: Vec::new(),
    }));
    let mut buf = Vec::new();
    msg.encode(&mut buf).expect("encode CLIENT_SETUP");
    buf
}

/// Read a uni stream to its end, reporting a connection-level close as its
/// own outcome rather than panicking.
///
/// [`common::drain`] panics on any read error that is not `Reset`, which is
/// right for a test whose stream ends before the session does. The
/// synthesized-reset tests deliberately kill a connection mid-stream, so
/// `ConnectionLost` is a *reachable* outcome there and has to be reportable:
/// a CONNECTION_CLOSE overtaking the RESET_STREAM is a different failure from
/// the proxy sending a FIN, and a panic would flatten the two.
async fn drain_reporting_loss(recv: &mut quinn::RecvStream) -> (usize, Result<Ending, String>) {
    let mut buf = [0u8; 4096];
    let mut total = 0usize;
    loop {
        match recv.read(&mut buf).await {
            Ok(Some(n)) => total += n,
            Ok(None) => return (total, Ok(Ending::Fin)),
            Err(quinn::ReadError::Reset(code)) => {
                return (total, Ok(Ending::Reset(code.into_inner())))
            }
            Err(e) => return (total, Err(format!("{e:?}"))),
        }
    }
}

/// Wait until `f` holds on the observer's record, or `TIMEOUT` elapses.
///
/// Events are emitted from the forwarding tasks, so a test that reads them
/// straight after observing a stream ending can lose a race it does not care
/// about. This waits for the claim instead of sleeping a guessed interval.
async fn wait_for_event<F: Fn(&RecordingObserver) -> bool>(obs: &RecordingObserver, f: F) {
    let poll = async {
        loop {
            if f(obs) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    };
    let _ = tokio::time::timeout(common::TIMEOUT, poll).await;
}

/// Every `Effect::StreamReset` reported at `Site::StreamEnd`.
fn stream_end_resets(obs: &RecordingObserver) -> Vec<(u64, bool)> {
    obs.applied()
        .into_iter()
        .filter_map(|(site, action, effect)| match (site, action, effect) {
            (
                Site::StreamEnd,
                ActionKind::ResetStream,
                Effect::StreamReset { code, code_defined },
            ) => Some((code, code_defined)),
            _ => None,
        })
        .collect()
}

/// Every `ImpairmentKind::ControlStreamTruncated`.
fn control_truncations(obs: &RecordingObserver) -> Vec<String> {
    obs.impairments()
        .into_iter()
        .filter_map(|k| match k {
            ImpairmentKind::ControlStreamTruncated { error } => Some(error),
            _ => None,
        })
        .collect()
}

/// Spawn a [`DRAFT`] session on [`ALPN`] in front of `relay`, with `hook`
/// attached.
///
/// Spelled through `spawn_proxy_with` rather than `spawn_proxy` so [`DRAFT`]
/// is the single place the draft is stated — `spawn_proxy`'s own default
/// happens to match today, and a test file whose stated draft and actual
/// draft can drift apart is a test file whose `code_defined` assertions mean
/// nothing.
fn spawn(
    relay: &FakeRelay,
    observer: &Arc<RecordingObserver>,
    hook: Arc<dyn ProxyHook>,
) -> SpawnedProxy {
    common::spawn_proxy_with(
        common::session_config(DRAFT, relay.addr),
        ALPN,
        Arc::clone(observer) as Arc<dyn ProxyObserver>,
        hook,
    )
}

// ── A non-reset read failure resets the destination ────────────────────

/// Which data pipe the session takes. Both call `propagate_reset`, from
/// separate call sites in separate functions, so a fix applied to one and
/// not the other would leave half of the traffic still turning a truncated
/// stream into a FIN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pipe {
    /// `Interest::NONE` — `pipe_data_passthrough`, the byte pump.
    Passthrough,
    /// `Interest::STREAMS` — `pipe_data_framed`, which also runs
    /// `on_stream_end` before the reset is synthesized.
    Framed,
}

/// The relay dies mid-subgroup; the client must see a `RESET_STREAM`, not a
/// FIN that would let a player commit a truncated group as complete.
///
/// *Ablation:* delete the `synthesized_reset_code`
/// arm at the end of `propagate_reset` (return instead of resetting) and both
/// cases report `Ending::Fin`, while `a_clean_fin_stays_a_fin` and
/// `a_mirrored_reset_keeps_the_peer_code_after_data_already_written` stay
/// green.
async fn non_reset_read_failure_case(pipe: Pipe) {
    common::init_crypto();

    let relay = Arc::new(FakeRelay::bind(ALPN));
    let observer = Arc::new(RecordingObserver::new());
    let hook: Arc<dyn ProxyHook> = match pipe {
        Pipe::Passthrough => Arc::new(NoOpHook),
        Pipe::Framed => Arc::new(StreamEndHook::always(Action::Pass)),
    };
    let proxy = spawn(&relay, &observer, hook);

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, ALPN).await;

    // Relay opens a subgroup stream and writes a partial group.
    let mut relay_send = relay.open_uni().await;
    relay_send.write_all(PARTIAL_GROUP).await.expect("relay write");

    let mut recv = tokio::time::timeout(common::TIMEOUT, client_conn.accept_uni())
        .await
        .expect("client saw the forwarded uni stream")
        .expect("accept_uni");

    // Read the prefix before killing the relay, so what follows is a read
    // failure *mid-stream* rather than one that races the stream open.
    let mut buf = [0u8; 4096];
    let first = tokio::time::timeout(common::TIMEOUT, recv.read(&mut buf))
        .await
        .expect("the partial group arrived")
        .expect("read")
        .expect("the partial group is not an immediate FIN");
    assert_eq!(first, PARTIAL_GROUP.len(), "the bytes written before the failure must arrive");

    // The relay dies: connection-level loss, not a RESET_STREAM. This is the
    // failure class this test is about — every read on the relay leg now
    // fails with something `propagate_reset` used to ignore.
    relay.close(0x9, b"relay died");

    let (rest, ending) = tokio::time::timeout(common::TIMEOUT, drain_reporting_loss(&mut recv))
        .await
        .expect("the client stream terminated");

    let ending = ending.unwrap_or_else(|e| {
        panic!(
            "{pipe:?}: the client stream ended with a connection-level error ({e}) instead of a \
             stream ending — the proxy's session close overtook the reset"
        )
    });
    match ending {
        Ending::Reset(code) => assert_eq!(
            code, SYNTHESIZED_CODE,
            "{pipe:?}: the synthesized reset must carry the code session.rs chose"
        ),
        Ending::Fin => panic!(
            "{pipe:?}: the client saw a clean FIN after {} bytes. The relay died mid-subgroup and \
             a FIN tells the player the group is complete",
            PARTIAL_GROUP.len() + rest
        ),
    }

    wait_for_event(&observer, |o| !stream_end_resets(o).is_empty()).await;
    assert_eq!(
        stream_end_resets(&observer),
        vec![(SYNTHESIZED_CODE, CODE_DEFINED)],
        "{pipe:?}: exactly one ActionApplied {{ StreamEnd, ResetStream, StreamReset }}; draft-14 \
         defines a stream-reset code vocabulary, so code_defined is true. Saw: {:?}",
        observer.applied()
    );
    assert!(
        control_truncations(&observer).is_empty(),
        "{pipe:?}: a data stream must not report ControlStreamTruncated"
    );

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

#[tokio::test]
async fn a_non_reset_read_failure_resets_a_data_stream() {
    non_reset_read_failure_case(Pipe::Passthrough).await;
}

#[tokio::test]
async fn a_non_reset_read_failure_resets_a_framed_data_stream() {
    non_reset_read_failure_case(Pipe::Framed).await;
}

/// The control stream is exempt: a non-reset read failure there must leave a
/// FIN and one `Impairment { ControlStreamTruncated }`, because MoQT treats a
/// reset control stream as a session-level error on every draft.
///
/// Run on both control pipes — `pipe_control_passthrough` and
/// `pipe_control_mutating` are separate functions with their own
/// `propagate_reset` call sites.
async fn control_truncation_case(mutating: bool) {
    common::init_crypto();

    let relay = Arc::new(FakeRelay::bind(ALPN));
    let observer = Arc::new(RecordingObserver::new());
    let control_hook = Arc::new(ControlMutatingHook::default());
    let hook: Arc<dyn ProxyHook> =
        if mutating { Arc::clone(&control_hook) as Arc<dyn ProxyHook> } else { Arc::new(NoOpHook) };
    let proxy = spawn(&relay, &observer, hook);

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, ALPN).await;
    let (mut client_send, _client_recv) = client_conn.open_bi().await.expect("client open_bi");
    client_send.write_all(&client_setup_bytes()).await.expect("client write CLIENT_SETUP");

    // The relay's half of the control stream, which is what must still FIN.
    let (_relay_send, mut relay_recv) = relay.accept_bi().await;
    let setup_len = client_setup_bytes().len();
    let mut buf = [0u8; 4096];
    let n = tokio::time::timeout(common::TIMEOUT, relay_recv.read(&mut buf))
        .await
        .expect("the CLIENT_SETUP reached the relay")
        .expect("read")
        .expect("not an immediate FIN");
    assert_eq!(n, setup_len, "the CLIENT_SETUP must reach the relay before the client dies");

    // Kill the client connection: the proxy's client→relay control read now
    // fails with a connection-level error, not a RESET_STREAM.
    client_conn.close(0x7u32.into(), b"client died");

    let (rest, ending) =
        tokio::time::timeout(common::TIMEOUT, drain_reporting_loss(&mut relay_recv))
            .await
            .expect("the relay's control stream terminated");

    let label = if mutating { "pipe_control_mutating" } else { "pipe_control_passthrough" };
    let ending = ending.unwrap_or_else(|e| {
        panic!("{label}: the relay's control stream ended with a connection error ({e})")
    });
    assert_eq!(
        ending,
        Ending::Fin,
        "{label}: a synthesized RESET_STREAM on a control stream is a session-level protocol \
         violation on every draft — the destination must still FIN (after {rest} further bytes)"
    );

    wait_for_event(&observer, |o| !control_truncations(o).is_empty()).await;
    let truncations = control_truncations(&observer);
    assert_eq!(
        truncations.len(),
        1,
        "{label}: exactly one ControlStreamTruncated for the failing direction, got {truncations:?}"
    );
    assert!(
        stream_end_resets(&observer).is_empty(),
        "{label}: no reset may be synthesized on a control stream, got {:?}",
        stream_end_resets(&observer)
    );

    if mutating {
        assert!(
            control_hook.seen() >= 1,
            "{label}: on_control_message never fired, so this ran on the pass-through pipe and is \
             a duplicate of its sibling"
        );
    }

    proxy.shutdown().await;
}

#[tokio::test]
async fn a_non_reset_read_failure_on_the_control_stream_does_not_synthesize_a_reset() {
    control_truncation_case(false).await;
}

#[tokio::test]
async fn a_non_reset_read_failure_on_the_mutating_control_stream_does_not_synthesize_a_reset() {
    control_truncation_case(true).await;
}

// ── Propagation, parameterized over direction ──────────────────────────

/// Which forwarding leg a propagation case drives.
///
/// `proxy_reset.rs` covers `DataRelayToClient` and both control legs
/// *initiated by the client*. `DataClientToRelay` and `ControlRelayToClient`
/// are the two that nothing else exercises — same code, different `side`
/// argument, and that symmetry is exactly what makes the omission easy to
/// miss by reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Leg {
    /// `pipe_data`, client → relay. Covered here and nowhere else.
    DataClientToRelay,
    /// `pipe_data`, relay → client. Already covered by `proxy_reset.rs`.
    DataRelayToClient,
    /// `pipe_control`, client → relay. Already covered by `proxy_reset.rs`.
    ControlClientToRelay,
    /// `pipe_control`, relay → client. Covered here and nowhere else.
    ControlRelayToClient,
}

impl Leg {
    /// The `ProxySide` a `StreamReset` event for this leg must carry: the
    /// ingress side the failing read happened on.
    fn ingress(self) -> ProxySide {
        match self {
            Leg::DataClientToRelay | Leg::ControlClientToRelay => ProxySide::ClientToProxy,
            Leg::DataRelayToClient | Leg::ControlRelayToClient => ProxySide::RelayToProxy,
        }
    }

    fn is_control(self) -> bool {
        matches!(self, Leg::ControlClientToRelay | Leg::ControlRelayToClient)
    }
}

/// Drive one leg: write `PARTIAL_GROUP` (or a CLIENT_SETUP on control) into
/// the source end, let it be forwarded, then `RESET_STREAM` the source.
/// Reports what the destination peer saw.
async fn propagation_case(
    leg: Leg,
    hook: Arc<dyn ProxyHook>,
) -> (usize, Ending, Vec<(ProxySide, u64)>) {
    common::init_crypto();

    let relay = Arc::new(FakeRelay::bind(ALPN));
    let observer = Arc::new(RecordingObserver::new());
    let proxy = spawn(&relay, &observer, hook);

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, ALPN).await;

    let payload: Vec<u8> =
        if leg.is_control() { client_setup_bytes() } else { PARTIAL_GROUP.to_vec() };

    // The halves this leg does not drive, held for as long as the case runs.
    // Dropping a `quinn::SendStream` FINs it and dropping a `RecvStream`
    // stops it, either of which is a teardown the proxy would forward and
    // this test would then be measuring instead of the one it asked for.
    let mut idle_send: Option<quinn::SendStream> = None;
    let mut idle_recv: Option<quinn::RecvStream> = None;

    // Open the source stream and the destination stream for this leg, and
    // write the payload *before* accepting the destination: opening a QUIC
    // stream puts nothing on the wire, so the far end cannot accept a stream
    // that has never carried a byte.
    let (mut source, mut dest): (quinn::SendStream, quinn::RecvStream) = match leg {
        Leg::DataClientToRelay => {
            let mut send = client_conn.open_uni().await.expect("client open_uni");
            send.write_all(&payload).await.expect("client write");
            (send, relay.accept_uni().await)
        }
        Leg::DataRelayToClient => {
            let mut send = relay.open_uni().await;
            send.write_all(&payload).await.expect("relay write");
            (send, client_conn.accept_uni().await.expect("client accept_uni"))
        }
        Leg::ControlClientToRelay => {
            let (mut send, recv) = client_conn.open_bi().await.expect("client open_bi");
            send.write_all(&payload).await.expect("client write");
            idle_recv = Some(recv);
            let (relay_send, relay_recv) = relay.accept_bi().await;
            idle_send = Some(relay_send);
            (send, relay_recv)
        }
        Leg::ControlRelayToClient => {
            // The control stream is opened client→proxy→relay first — the
            // proxy only opens its half towards the relay once the client
            // has one — so the relay has no send half to write on until a
            // priming frame has crossed. That frame goes the other way and
            // is never counted below; `dest` only ever sees relay→client.
            let (mut client_send, client_recv) =
                client_conn.open_bi().await.expect("client open_bi");
            client_send.write_all(&client_setup_bytes()).await.expect("client prime");
            idle_send = Some(client_send);
            let (mut relay_send, relay_recv) = relay.accept_bi().await;
            idle_recv = Some(relay_recv);
            relay_send.write_all(&payload).await.expect("relay write");
            (relay_send, client_recv)
        }
    };

    // Read the payload out of the destination before resetting, so the
    // assertion below is "data, *then* a reset" — a proxy that forwarded
    // nothing and only mirrored the reset would otherwise pass.
    let mut buf = [0u8; 4096];
    let delivered = tokio::time::timeout(common::TIMEOUT, dest.read(&mut buf))
        .await
        .expect("the payload reached the destination")
        .expect("read")
        .expect("not an immediate FIN");

    source.reset(quinn::VarInt::from_u64(PEER_RESET_CODE).unwrap()).expect("source reset");

    let (rest, ending) =
        tokio::time::timeout(common::TIMEOUT, common::drain(&mut dest)).await.expect("terminated");

    wait_for_event(&observer, |o| !o.resets().is_empty()).await;
    let resets = observer.resets();

    drop(idle_send);
    drop(idle_recv);
    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;

    (delivered + rest, ending, resets)
}

/// One assertion body for all four legs, so a direction cannot drift.
async fn assert_leg_propagates(leg: Leg, hook: Arc<dyn ProxyHook>, expect_bytes: usize) {
    let (bytes, ending, resets) = propagation_case(leg, hook).await;

    assert_eq!(
        ending,
        Ending::Reset(PEER_RESET_CODE),
        "{leg:?}: the peer's RESET_STREAM code must survive the proxy, not become a FIN"
    );
    assert_eq!(
        bytes, expect_bytes,
        "{leg:?}: the bytes written before the reset must still arrive"
    );
    assert!(
        resets.contains(&(leg.ingress(), PEER_RESET_CODE)),
        "{leg:?}: expected StreamReset {{ side: {:?}, code: {PEER_RESET_CODE} }}, got {resets:?}",
        leg.ingress()
    );
}

/// The first direction no other test covers: `pipe_data` client → relay.
#[tokio::test]
async fn a_client_data_reset_reaches_the_relay_with_the_same_code() {
    assert_leg_propagates(Leg::DataClientToRelay, Arc::new(NoOpHook), PARTIAL_GROUP.len()).await;
}

/// The direction `proxy_reset.rs` already covers, restated here so the four cases
/// share one assertion body and a regression in either is caught the same
/// way.
#[tokio::test]
async fn a_relay_data_reset_reaches_the_client_with_the_same_code() {
    assert_leg_propagates(Leg::DataRelayToClient, Arc::new(NoOpHook), PARTIAL_GROUP.len()).await;
}

/// The second direction no other test covers: `pipe_control` relay → client.
#[tokio::test]
async fn a_relay_control_reset_reaches_the_client_with_the_same_code() {
    assert_leg_propagates(
        Leg::ControlRelayToClient,
        Arc::new(NoOpHook),
        client_setup_bytes().len(),
    )
    .await;
}

/// The control leg `proxy_reset.rs` covers, on the pass-through pipe.
#[tokio::test]
async fn a_client_control_reset_reaches_the_relay_with_the_same_code() {
    assert_leg_propagates(
        Leg::ControlClientToRelay,
        Arc::new(NoOpHook),
        client_setup_bytes().len(),
    )
    .await;
}

// ── Reset-fidelity guarantees, as the synthesized reset's negative controls ──

/// A clean FIN stays a clean FIN, with every byte ahead of it.
///
/// The negative control for the synthesized-reset ablation: stubbing the
/// synthesized reset must redden the tests above and leave this one green.
/// `Fin` is the *default*
/// outcome of dropping a `SendStream`, so this test on its own proves
/// nothing — it is the contrast that carries the information.
#[tokio::test]
async fn a_clean_fin_stays_a_fin() {
    common::init_crypto();

    let payload: Vec<u8> = vec![0x04, 0xAA, 0xBB, 0xCC, 0xDD];
    let relay = Arc::new(FakeRelay::bind(ALPN));
    let observer = Arc::new(RecordingObserver::new());
    let proxy = spawn(&relay, &observer, Arc::new(NoOpHook));

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, ALPN).await;

    let mut relay_send = relay.open_uni().await;
    relay_send.write_all(&payload).await.expect("relay write");
    relay_send.finish().expect("relay finish");

    let mut recv = tokio::time::timeout(common::TIMEOUT, client_conn.accept_uni())
        .await
        .expect("client saw the forwarded uni stream")
        .expect("accept_uni");
    let (bytes, ending) =
        tokio::time::timeout(common::TIMEOUT, common::drain(&mut recv)).await.expect("terminated");

    assert_eq!(ending, Ending::Fin, "a clean FIN must not become a reset");
    assert_eq!(bytes, payload.len(), "every byte must arrive ahead of the FIN");
    assert!(observer.resets().is_empty(), "a FIN is not a reset: {:?}", observer.resets());
    assert!(
        stream_end_resets(&observer).is_empty(),
        "nothing was synthesized: {:?}",
        stream_end_resets(&observer)
    );
    assert!(
        observer.closes().contains(&ProxySide::RelayToProxy),
        "a clean FIN is reported as StreamClosed, got {:?}",
        observer.closes()
    );

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

/// A mirrored reset carries the *peer's* code and arrives after the data
/// already written — the reset-fidelity guarantee, which the synthesized
/// reset sits downstream of and must not disturb.
#[tokio::test]
async fn a_mirrored_reset_keeps_the_peer_code_after_data_already_written() {
    common::init_crypto();

    let relay = Arc::new(FakeRelay::bind(ALPN));
    let observer = Arc::new(RecordingObserver::new());
    let proxy = spawn(&relay, &observer, Arc::new(NoOpHook));

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, ALPN).await;

    let mut relay_send = relay.open_uni().await;
    relay_send.write_all(PARTIAL_GROUP).await.expect("relay write");

    let mut recv = tokio::time::timeout(common::TIMEOUT, client_conn.accept_uni())
        .await
        .expect("client saw the forwarded uni stream")
        .expect("accept_uni");
    let mut buf = [0u8; 4096];
    let delivered = tokio::time::timeout(common::TIMEOUT, recv.read(&mut buf))
        .await
        .expect("the partial group arrived")
        .expect("read")
        .expect("not an immediate FIN");

    relay_send.reset(quinn::VarInt::from_u64(PEER_RESET_CODE).unwrap()).expect("relay reset");

    let (rest, ending) =
        tokio::time::timeout(common::TIMEOUT, common::drain(&mut recv)).await.expect("terminated");

    assert_eq!(
        ending,
        Ending::Reset(PEER_RESET_CODE),
        "the peer's code must survive, not be replaced by a synthesized one \
         ({SYNTHESIZED_CODE})"
    );
    assert_eq!(delivered + rest, PARTIAL_GROUP.len(), "data first, then the reset");
    assert!(
        stream_end_resets(&observer).is_empty(),
        "a mirrored reset is not an ActionApplied — it is the peer's decision, reported as \
         StreamReset: {:?}",
        stream_end_resets(&observer)
    );

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

// ── Action::ResetStream, end to end ────────────────────────────────────

/// A hook returning `ResetStream` at a **data** stream's end turns the clean
/// FIN into a reset carrying the code it asked for.
///
/// *Ablation:* make `Plan::Terminal` fall through to `send.finish()` in
/// `pipe_data_framed`'s FIN branch; the client sees `Ending::Fin` and this
/// fails while `a_clean_fin_stays_a_fin` still passes.
#[tokio::test]
async fn reset_stream_reaches_the_peer_with_the_requested_code() {
    common::init_crypto();

    let payload: Vec<u8> = vec![0x04, 0x01, 0x00, 0x00, 0x02, 0xAA, 0xBB];
    let relay = Arc::new(FakeRelay::bind(ALPN));
    let observer = Arc::new(RecordingObserver::new());
    let hook = Arc::new(StreamEndHook::new(|cx, _end| {
        if cx.is_control_stream {
            Action::Pass
        } else {
            Action::ResetStream { code: HOOK_RESET_CODE }
        }
    }));
    let proxy = spawn(&relay, &observer, Arc::clone(&hook) as Arc<dyn ProxyHook>);

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, ALPN).await;

    let mut relay_send = relay.open_uni().await;
    relay_send.write_all(&payload).await.expect("relay write");
    relay_send.finish().expect("relay finish");

    let mut recv = tokio::time::timeout(common::TIMEOUT, client_conn.accept_uni())
        .await
        .expect("client saw the forwarded uni stream")
        .expect("accept_uni");
    let (bytes, ending) =
        tokio::time::timeout(common::TIMEOUT, common::drain(&mut recv)).await.expect("terminated");

    assert_eq!(
        ending,
        Ending::Reset(HOOK_RESET_CODE),
        "the source FINed; the hook asked for a reset at Site::StreamEnd and it must be the \
         ending the peer sees"
    );
    assert!(bytes <= payload.len(), "a reset can only lose bytes, never invent them");

    wait_for_event(&observer, |o| !stream_end_resets(o).is_empty()).await;
    assert_eq!(
        stream_end_resets(&observer),
        vec![(HOOK_RESET_CODE, CODE_DEFINED)],
        "exactly one ActionApplied {{ StreamEnd, ResetStream }} carrying the requested code; \
         draft-14 defines a reset-code vocabulary so code_defined is true. Saw: {:?}",
        observer.applied()
    );
    assert!(
        observer.refused().is_empty(),
        "ResetStream is legal at a data stream's end: {:?}",
        observer.refused()
    );
    assert!(
        hook.seen().iter().any(|(is_control, end)| !is_control && *end == StreamEnd::Fin),
        "the hook must have been shown the data stream's FIN, got {:?}",
        hook.seen()
    );

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

/// An error code above the QUIC varint ceiling is refused **before anything
/// is sent**: the stream still ends with a FIN carrying every byte.
///
/// *Ablation:* drop the `check_error_code` call from the `ResetStream` arm of
/// `exec::execute`; `send.reset` then fails or truncates and this goes red.
#[tokio::test]
async fn an_out_of_range_reset_code_is_refused_before_anything_is_sent() {
    common::init_crypto();

    let payload: Vec<u8> = vec![0x04, 0x01, 0x00, 0x00, 0x03, 0xAA, 0xBB, 0xCC];
    let relay = Arc::new(FakeRelay::bind(ALPN));
    let observer = Arc::new(RecordingObserver::new());
    let hook = Arc::new(StreamEndHook::new(|cx, _end| {
        if cx.is_control_stream {
            Action::Pass
        } else {
            Action::ResetStream { code: OUT_OF_RANGE_CODE }
        }
    }));
    let proxy = spawn(&relay, &observer, hook);

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, ALPN).await;

    let mut relay_send = relay.open_uni().await;
    relay_send.write_all(&payload).await.expect("relay write");
    relay_send.finish().expect("relay finish");

    let mut recv = tokio::time::timeout(common::TIMEOUT, client_conn.accept_uni())
        .await
        .expect("client saw the forwarded uni stream")
        .expect("accept_uni");
    let (bytes, ending) =
        tokio::time::timeout(common::TIMEOUT, common::drain(&mut recv)).await.expect("terminated");

    assert_eq!(ending, Ending::Fin, "a refused reset must leave the FIN alone");
    assert_eq!(bytes, payload.len(), "a refusal costs no bytes");

    wait_for_event(&observer, |o| !o.refused().is_empty()).await;
    assert_eq!(
        observer.refused(),
        vec![(
            Site::StreamEnd,
            ActionKind::ResetStream,
            Refusal::ErrorCodeOutOfRange { code: OUT_OF_RANGE_CODE }
        )],
        "exactly one ErrorCodeOutOfRange refusal, naming the code that was asked for"
    );
    assert!(
        stream_end_resets(&observer).is_empty(),
        "a refused reset must not also be reported as applied: {:?}",
        observer.applied()
    );

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

/// `ResetStream` at the **control** stream's end is refused, and the control
/// stream still FINs. `ResetStream` at a stream's end is honoured on data
/// streams and refused on the control stream — the same action, two answers
/// depending on which stream it targets.
///
/// Paired with `reset_stream_reaches_the_peer_with_the_requested_code`, which
/// must *succeed* on a data stream. Either test alone is compatible with the
/// two cases never having been distinguished at all.
///
/// *Ablation:* drop `is_control_stream` from `exec::Target::StreamEnd`; the
/// control case synthesizes a reset and this goes red.
#[tokio::test]
async fn reset_stream_at_the_control_streams_end_is_refused() {
    common::init_crypto();

    let relay = Arc::new(FakeRelay::bind(ALPN));
    let observer = Arc::new(RecordingObserver::new());
    let hook = Arc::new(StreamEndHook::always(Action::ResetStream { code: HOOK_RESET_CODE }));
    let proxy = spawn(&relay, &observer, Arc::clone(&hook) as Arc<dyn ProxyHook>);

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, ALPN).await;
    let (mut client_send, _client_recv) = client_conn.open_bi().await.expect("client open_bi");
    client_send.write_all(&client_setup_bytes()).await.expect("client write CLIENT_SETUP");

    let (_relay_send, mut relay_recv) = relay.accept_bi().await;
    let mut buf = [0u8; 4096];
    let delivered = tokio::time::timeout(common::TIMEOUT, relay_recv.read(&mut buf))
        .await
        .expect("the CLIENT_SETUP reached the relay")
        .expect("read")
        .expect("not an immediate FIN");

    // A clean FIN on the client's half of the control stream: `on_stream_end`
    // fires with `is_control_stream == true`.
    client_send.finish().expect("client finish");

    let (rest, ending) =
        tokio::time::timeout(common::TIMEOUT, common::drain(&mut relay_recv)).await.expect("end");

    assert_eq!(
        ending,
        Ending::Fin,
        "a reset on a control stream is a session-level protocol violation on every draft — the \
         refused action must leave the FIN in place"
    );
    assert_eq!(
        delivered + rest,
        client_setup_bytes().len(),
        "the frame must still have passed through"
    );

    wait_for_event(&observer, |o| !o.refused().is_empty()).await;
    assert_eq!(
        observer.refused(),
        vec![(Site::StreamEnd, ActionKind::ResetStream, Refusal::ControlStreamResetIllegal)],
        "exactly one ControlStreamResetIllegal refusal"
    );
    assert!(
        stream_end_resets(&observer).is_empty(),
        "nothing may be applied: {:?}",
        observer.applied()
    );
    assert!(
        hook.seen().iter().any(|(is_control, _)| *is_control),
        "on_stream_end must fire on the control stream too, got {:?}",
        hook.seen()
    );

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

// ── Action::CloseSession, end to end ───────────────────────────────────

/// The close carries the hook's code and reason to the client, not the
/// proxy's hard-coded pair.
///
/// *Ablation:* restore `client.close(0, b"proxy session ended")` in
/// `run_with_transport`; this fails on both the code and the reason. A test
/// asserting only "the session ended" would pass against that hard-coding,
/// which is why both fields are asserted.
#[tokio::test]
async fn close_session_carries_the_requested_code_and_reason() {
    common::init_crypto();

    const CLOSE_CODE: u32 = 0x2;
    const CLOSE_REASON: &[u8] = b"scenario asked for this";

    let relay = Arc::new(FakeRelay::bind(ALPN));
    let observer = Arc::new(RecordingObserver::new());
    let hook = Arc::new(StreamEndHook::always(Action::CloseSession {
        code: CLOSE_CODE,
        reason: Bytes::from_static(CLOSE_REASON),
    }));
    let proxy = spawn(&relay, &observer, Arc::clone(&hook) as Arc<dyn ProxyHook>);

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, ALPN).await;

    // One data stream that ends cleanly is enough to reach `on_stream_end`.
    let mut relay_send = relay.open_uni().await;
    relay_send.write_all(&[0x04, 0x01, 0x00, 0x00, 0x01, 0xAA]).await.expect("relay write");
    relay_send.finish().expect("relay finish");

    let reason = tokio::time::timeout(common::TIMEOUT, client_conn.closed())
        .await
        .expect("the proxy closed the client connection");

    match reason {
        quinn::ConnectionError::ApplicationClosed(app) => {
            assert_eq!(
                app.error_code,
                quinn::VarInt::from_u32(CLOSE_CODE),
                "the close must carry the code the hook asked for, not the proxy's default"
            );
            assert_eq!(
                app.reason.as_ref(),
                CLOSE_REASON,
                "the close must carry the reason the hook asked for"
            );
        }
        other => panic!("expected an application close from the proxy, got {other:?}"),
    }

    assert!(
        observer.applied().iter().any(|(site, action, effect)| *site == Site::StreamEnd
            && *action == ActionKind::CloseSession
            && *effect == Effect::SessionClosing { code: CLOSE_CODE }),
        "expected ActionApplied {{ StreamEnd, CloseSession, SessionClosing }}, got {:?}",
        observer.applied()
    );

    proxy.shutdown().await;
}

/// Two `CloseSession` decisions on one session: the **first** wins, the
/// second is refused with [`Refusal::SessionAlreadyClosing`], and the peer
/// observes the first code.
///
/// The hook returns a *different* code on its second call, which is what
/// makes first-wins falsifiable: with one fixed code the test could not tell
/// it from last-wins.
///
/// # This used to assert "at least one refusal", and that was the bug
///
/// Both decisions are stream ends, and the first one cancels the session as
/// it is recorded, so the second was reaching a hook only if its pipe won a
/// `tokio::select!` coin flip against a `cancel.cancelled()` branch that had
/// just gone ready. The test bought trials with streams — 24 of them — and
/// then asserted only what a race can promise: at least one refusal, and
/// `hook.calls() >= 2`.
///
/// It was not enough. Measured on 2026-08-26, 20 runs on an idle box with
/// the 300 ms sleep that separated the writes from the FINs: **2 to 11
/// decisions out of 24 streams**, median 6 — not the ~12 an independent
/// coin flip per stream would give, because the trials are not the streams.
/// They are the FINs already delivered when the first close lands, and that
/// is a packet-batching detail no test can see or set. Twenty more runs
/// with the sleep removed, so that fewer of them have arrived: 1 to 3
/// decisions, and **8 runs in 20 failed outright**, each after waiting the
/// full 10 s for a second decision that was never coming.
///
/// So the fix is not a longer wait or more streams. [`CountingCloseHook`]
/// holds the first decision inside the hook until the second has arrived,
/// and holds the second until the first has been applied — after which
/// **exactly two** decisions, **exactly one** applied close and **exactly
/// one** refusal are all assertable, and every one of them is asserted.
///
/// *Ablation:* let `SessionCloser::request` return `true` on a second call
/// instead of `false` — `assertion left == right failed: exactly one
/// SessionClosing, carrying the first code, out of 2 decisions; left:
/// [(StreamEnd, CloseSession, SessionClosing { code: 1 }), (StreamEnd,
/// CloseSession, SessionClosing { code: 3 })]`. The `OnceLock` still keeps
/// the first pair, so the peer still sees `FIRST_CODE` and the peer
/// assertion stays green: what the applied-effect count is for is exactly
/// this, a second close reported as applied when nothing was applied.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_close_session_is_refused() {
    common::init_crypto();

    const FIRST_CODE: u32 = 0x1;
    const SECOND_CODE: u32 = 0x3;

    let relay = Arc::new(FakeRelay::bind(ALPN));
    let observer = Arc::new(RecordingObserver::new());
    let hook = Arc::new(CountingCloseHook::new(
        &[(FIRST_CODE, b"first"), (SECOND_CODE, b"second")],
        usize::from(CLOSING_STREAMS),
        Arc::clone(&observer),
    ));
    let proxy = spawn(&relay, &observer, Arc::clone(&hook) as Arc<dyn ProxyHook>);

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, ALPN).await;

    // Open every stream and write to it first, so the proxy has accepted all
    // of them and spawned a forwarding task for each before any of them
    // ends. Then FIN them together. Whether the two FINs are delivered in
    // one batch or a hundred milliseconds apart no longer decides anything:
    // the first stream end waits inside the hook for the second, and until
    // it returns nothing has been closed and nothing has been cancelled.
    let mut sends = Vec::new();
    for id in 0u8..CLOSING_STREAMS {
        let mut relay_send = relay.open_uni().await;
        relay_send
            .write_all(&[0x04, 0x01, 0x00, 0x00, 0x01, 0xA0 + id])
            .await
            .expect("relay write");
        sends.push(relay_send);
    }
    for relay_send in &mut sends {
        relay_send.finish().expect("relay finish");
    }

    let reason = tokio::time::timeout(common::TIMEOUT, client_conn.closed())
        .await
        .expect("the proxy closed the client connection");

    match reason {
        quinn::ConnectionError::ApplicationClosed(app) => assert_eq!(
            app.error_code,
            quinn::VarInt::from_u32(FIRST_CODE),
            "the first close request must win; seeing {SECOND_CODE} means the second overwrote it"
        ),
        other => panic!("expected an application close from the proxy, got {other:?}"),
    }

    // The second decision is taken while the connection is already closing,
    // so how it went may be reported after the peer has seen the close.
    // Waited for as "both decisions have been disposed of", not as "a
    // refusal happened": a run where the second one is *applied* is the
    // failure this test exists to catch, and it should reach its assertion
    // at once rather than after the full timeout.
    wait_for_event(&observer, |o| {
        let applied = o.applied().iter().filter(|(_, a, _)| *a == ActionKind::CloseSession).count();
        let refused = o.refused().iter().filter(|(_, a, _)| *a == ActionKind::CloseSession).count();
        applied + refused >= usize::from(CLOSING_STREAMS)
    })
    .await;

    assert_eq!(
        hook.calls(),
        usize::from(CLOSING_STREAMS),
        "every stream end must reach the hook: the first waits there for the rest, so a smaller \
         count means a stream never ended rather than a decision being lost to the cancel"
    );

    let closings: Vec<_> = observer
        .applied()
        .into_iter()
        .filter(|(site, action, _)| *site == Site::StreamEnd && *action == ActionKind::CloseSession)
        .collect();
    assert_eq!(
        closings,
        vec![(
            Site::StreamEnd,
            ActionKind::CloseSession,
            Effect::SessionClosing { code: FIRST_CODE }
        )],
        "exactly one SessionClosing, carrying the first code, out of {} decisions",
        hook.calls()
    );

    let refusals: Vec<_> = observer
        .refused()
        .into_iter()
        .filter(|(_, action, _)| *action == ActionKind::CloseSession)
        .collect();
    assert_eq!(
        refusals,
        vec![(Site::StreamEnd, ActionKind::CloseSession, Refusal::SessionAlreadyClosing)],
        "the one decision after the first must be refused as SessionAlreadyClosing"
    );

    proxy.shutdown().await;
}

/// [`ALPN`] must not resolve to a draft, or the whole file is testing a
/// different session shape than its comments claim.
///
/// Not a restatement of [`DRAFT`]: it reads `DraftVersion::from_alpn`, which
/// is a different fact. `moq-00` failing to resolve is what leaves
/// `draft_is_fixed` false, which is what makes the session parse as the
/// *configured* draft. Add `moq-00` to `from_alpn` and this goes red — which
/// is the point, because at that moment the control pipes would start
/// building their parsers eagerly and no other test here would notice.
#[test]
fn the_alpn_this_file_uses_leaves_the_draft_to_the_config() {
    assert_eq!(
        DraftVersion::from_alpn(ALPN),
        None,
        "{} must stay unresolvable, or ProxySession::draft_is_fixed flips and the session no \
         longer parses as DRAFT ({DRAFT})",
        String::from_utf8_lossy(ALPN)
    );
}

// ── STOP_SENDING on the control stream: an idle stream that gets stopped ──

/// The code the relay stops the forwarded control stream with. Distinct
/// from every other code in this file, and never `0` — `0` is what
/// dropping a `RecvStream` sends, which is the defect, not the fix.
const CONTROL_STOP_CODE: u64 = 0x2B;

/// How long the idle client waits to learn it was stopped. On the passing
/// path this resolves in milliseconds; only a broken run waits it out.
const IDLE_CONTROL_STOP_WINDOW: Duration = Duration::from_millis(400);

/// A `STOP_SENDING` on a control stream nobody is writing to must still
/// reach the far side.
///
/// An idle control stream is MoQT's *normal* steady state: SETUP and a
/// SUBSCRIBE cross, and then the stream can carry nothing for the rest of
/// the session. That makes it the worst case for the old trigger, which
/// noticed a `STOP_SENDING` only when the next write to the destination
/// failed — on a control stream there may never be a next write, so the
/// source was never stopped at all.
///
/// It is also the worst case for the *fix*, which is why the control stream
/// gets its own test rather than riding on the data-stream one: a watcher
/// that fired on anything other than the peer's own decision would tear down
/// a healthy session on every idle control stream in production. The two negative assertions below are that claim —
/// nothing here may be reported as a truncation, and nothing may synthesize
/// a reset on a control stream, which MoQT treats as a session-level error
/// on every draft.
///
/// Run over both control pipes. `pipe_control_passthrough` and
/// `pipe_control_mutating` are separate functions with separate `select!`
/// loops, and `Interest::CONTROL` is what chooses between them, so a
/// watcher wired into one says nothing about the other.
///
/// *Ablation (run, and it fails):* delete the `stop.watch()` branch from
/// the relevant pipe's `select!`. The client observes `None` — it is never
/// stopped, because nothing writes towards the relay again.
async fn idle_control_stop_case(mutating: bool) {
    common::init_crypto();

    let relay = Arc::new(FakeRelay::bind(ALPN));
    let observer = Arc::new(RecordingObserver::new());
    let counting = Arc::new(ControlMutatingHook::default());
    let hook: Arc<dyn ProxyHook> =
        if mutating { Arc::clone(&counting) as Arc<dyn ProxyHook> } else { Arc::new(NoOpHook) };
    let proxy = spawn(&relay, &observer, hook);

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, ALPN).await;

    // One CLIENT_SETUP crosses, and then the client says nothing more —
    // which is a MoQT session in its steady state, not a broken one.
    let setup = client_setup_bytes();
    let (mut client_send, mut client_recv) = client_conn.open_bi().await.expect("client open_bi");
    client_send.write_all(&setup).await.expect("client write");

    let (_relay_send, mut relay_recv) = relay.accept_bi().await;
    let mut buf = [0u8; 4096];
    let seen = tokio::time::timeout(common::TIMEOUT, relay_recv.read(&mut buf))
        .await
        .expect("the relay received the SETUP")
        .expect("read")
        .expect("not an immediate FIN");
    assert_eq!(seen, setup.len(), "{mutating}: the SETUP must arrive before the stop");

    // The relay changes its mind about a stream it is no longer being
    // written to.
    relay_recv
        .stop(quinn::VarInt::from_u64(CONTROL_STOP_CODE).expect("stop code"))
        .expect("relay stop");

    let observed = match tokio::time::timeout(IDLE_CONTROL_STOP_WINDOW, client_send.stopped()).await
    {
        Ok(Ok(Some(code))) => Some(code.into_inner()),
        _ => None,
    };
    assert_eq!(
        observed,
        Some(CONTROL_STOP_CODE),
        "mutating={mutating}: the relay's STOP_SENDING must reach the client with the relay's \
         code. `None` means the client was never stopped, so the STOP_SENDING was lost on an \
         idle control stream. `Some(0)` means a dropped RecvStream defaulted it"
    );

    // The safety half. `propagate_stop` stops the *source*; it must not
    // reset the destination, and a control stream that ends this way is not
    // a truncation to report.
    wait_for_event(&observer, |o| !o.resets().is_empty()).await;
    let resets = observer.resets();
    assert!(
        resets.contains(&(ProxySide::ProxyToRelay, CONTROL_STOP_CODE)),
        "mutating={mutating}: expected StreamReset {{ side: ProxyToRelay, code: \
         {CONTROL_STOP_CODE} }}, got {resets:?}"
    );
    assert!(
        stream_end_resets(&observer).is_empty(),
        "mutating={mutating}: no reset may be synthesized on a control stream; got {:?}",
        stream_end_resets(&observer)
    );
    assert!(
        control_truncations(&observer).is_empty(),
        "mutating={mutating}: a mirrored stop is not a control-stream truncation; got {:?}",
        control_truncations(&observer)
    );

    // …and the other direction of the same control stream must not come
    // back to the client as a `RESET_STREAM`. A connection-level ending is
    // allowed — the session really is over — but a reset is the
    // session-level protocol violation this pipe is exempt from.
    let (_bytes, ending) =
        tokio::time::timeout(common::TIMEOUT, drain_reporting_loss(&mut client_recv))
            .await
            .expect("the client's control half terminated");
    assert!(
        !matches!(ending, Ok(Ending::Reset(_))),
        "mutating={mutating}: the control stream must not be reset, got {ending:?}"
    );

    if mutating {
        // Without this the case is a silent duplicate of the pass-through
        // one: `on_control_message` fires only under `control_mutation`.
        assert!(
            counting.seen() >= 1,
            "the hook must have been consulted, or this ran on the pass-through pipe"
        );
    }

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

#[tokio::test]
async fn a_stop_on_an_idle_control_stream_is_mirrored() {
    idle_control_stop_case(false).await;
    idle_control_stop_case(true).await;
}

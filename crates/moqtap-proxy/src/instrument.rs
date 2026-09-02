//! Slow-path counters, so `Interest::NONE` is a falsifiable claim.
//!
//! The framed path is byte-identical to the byte pump, which
//! means no assertion on forwarded bytes can distinguish `Interest::NONE`
//! from `Interest::OBJECTS`. These counters can: they are incremented only
//! *inside* code the fast path never reaches, so they are free on the fast
//! path, need no feature gate, and the binary under test is the binary that
//! ships.
//!
//! **Counters are scoped to a session, not to the process.** Making them
//! process-wide with no reset is not merely flaky —
//! `tests/actions_objects.rs::a_matching_rule_on_a_draft19_fetch_stream_reports_a_bypass`
//! asserts `objects_elided == 0` while sharing a binary with five tests
//! whose whole purpose is to elide, and `cargo test` runs a binary's test
//! functions on a thread pool. That assertion is near-certain to fail, and
//! a counter suite that goes red for scheduling reasons gets weakened or
//! `#[ignore]`d within a week — at which point the `Interest::NONE` proof
//! is back to being an assertion.
//!
//! There is deliberately **no process-global `snapshot()`**. Counters are
//! read through `ProxySession::counters()`, which returns the [`Counters`]
//! of one session's [`Recorder`]. (Named in plain text rather than as an
//! intra-doc link, so this module's documentation builds under
//! `RUSTDOCFLAGS="-D warnings"` whether or not that method is in scope
//! here.)
//!
//! The one thing that does stay process-global is the release thread's
//! existence and backend ([`release_timer_started`],
//! [`release_timer_backend`]) — a process-wide *resource*, not a counter,
//! whose value is monotonic (`false → true`, `None → Some`).

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::time::Duration;

// ── the snapshot types ─────────────────────────────────────────────────

/// A snapshot of one session's slow-path counters.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Counters {
    /// `ObjectFramer` instances created.
    pub framers_created: u64,
    /// `ObjectFramer::poll_header` calls.
    pub framer_header_polls: u64,
    /// `ObjectFramer::poll_object` calls.
    pub framer_object_polls: u64,
    /// `ControlStreamParser` constructions.
    pub control_parsers_created: u64,
    /// `AnyDatagramHeader::decode` call sites entered.
    pub datagram_headers_decoded: u64,
    /// Units pushed onto a per-stream pending queue.
    pub egress_items_queued: u64,
    /// Objects removed by `DropMode::Elide`.
    pub objects_elided: u64,
    /// Elide fix-ups written: one leading Object ID varint on a subgroup
    /// stream, one re-encoded framing on a fetch stream. Counted only where
    /// the bytes actually moved — a survivor that already said the right
    /// thing is forwarded untouched and counted nowhere.
    pub object_ids_rewritten: u64,
    /// Units deferred by [`Action::Delay`](crate::action::Action::Delay),
    /// counted once each at the decision.
    ///
    /// **Units, not objects**, and the name is the whole statement of the
    /// difference: a delay is honoured at the control site as well as the
    /// object site, so a deferred SUBSCRIBE is one of these. The field below
    /// is named for objects because a truncation is refused on a control
    /// stream and can only ever land on one.
    ///
    /// Counted where the decision was taken rather than where the unit came
    /// back out, so one still sitting in a queue when the session ends is
    /// already here. [`Self::release_errors`] is the other half — what was
    /// released, and how late.
    ///
    /// Not [`Self::egress_items_queued`], which counts every push, stream
    /// headers and elided ordering slots included; that figure is larger
    /// than this one on any session that forwards at all.
    pub units_delayed: u64,
    /// Objects cut short by
    /// [`Action::Truncate`](crate::action::Action::Truncate), counted once
    /// each.
    ///
    /// Applied truncations only. An attempt refused for an out-of-range
    /// error code, or made at a site that carries no truncation, moves
    /// [`Self::actions_refused`] and never this.
    pub objects_truncated: u64,
    /// Actions refused, counted per attempt.
    pub actions_refused: u64,
    /// Streams the framer stopped parsing.
    pub streams_not_shapeable: u64,
    /// Objects streamed through without being addressable. The running
    /// total behind `ImpairmentKind::ObjectNotAddressable`, which is
    /// emitted only once per stream.
    pub objects_not_addressable: u64,
    /// Control frames the decoder refused, which the proxy forwarded
    /// without being able to read. The running total behind
    /// `ImpairmentKind::ControlFrameNotDecodable`, which is emitted only
    /// once per control stream direction.
    ///
    /// Zero on a session with no observer and no control interest, which
    /// builds no parser and reads no frame — the same byte-pump case
    /// `control_parsers_created` reports.
    pub control_frames_not_decodable: u64,
    /// Accumulated `actual_release - release_at`, in nanoseconds.
    /// The raw sum, kept for callers that want it;
    /// [`Self::release_errors`] is the useful form.
    pub release_error_ns: u64,
    /// Distribution of the above: p50, p95 and max lateness.
    pub release_errors: ReleaseErrors,
}

/// Observed lateness of deferred releases, in one session.
///
/// Measured **end to end** — from the unit's `release_at` to the instant
/// its bytes were handed to the destination stream — so it includes the
/// wheel, the runtime wake and the engine, which is what a caller
/// actually cares about. A sample taken inside the release thread would
/// have reported 0.55 ms while the object went out at 0.9 ms.
///
/// Values are bucketed with two significant bits per octave, so each
/// quantile is the upper bound of its bucket and is accurate to within
/// 25%; `max_ns` is exact.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReleaseErrors {
    /// Deferred units released. Units written inline (never queued) and
    /// units flushed by a drain that ignores release times are excluded,
    /// so this is the number of units that actually waited.
    pub count: u64,
    /// Median lateness, nanoseconds (bucket upper bound).
    pub p50_ns: u64,
    /// 95th-percentile lateness, nanoseconds (bucket upper bound).
    pub p95_ns: u64,
    /// Worst lateness, nanoseconds. Exact.
    pub max_ns: u64,
}

// ── the histogram ──────────────────────────────────────────────────────

/// Histogram slots. `[AtomicU32; 128]` is 512 bytes per session.
const HIST_BUCKETS: usize = 128;

/// Which bucket `ns` falls in: two significant bits per octave.
///
/// Buckets 0-3 are the exact values 0-3; from there each octave is split
/// into four, so a bucket is at most 25% wider than its lower bound.
/// Bucket 127 covers everything from 2^32 ns (4.29 s) upward — lateness
/// past that saturates, and [`ReleaseErrors::max_ns`] stays exact.
const fn bucket_of(ns: u64) -> usize {
    if ns < 4 {
        return ns as usize;
    }
    // `ns >= 4`, so `leading_zeros() <= 61` and `oct >= 2`.
    let oct = (63 - ns.leading_zeros()) as usize;
    let sub = ((ns >> (oct - 2)) & 0b11) as usize;
    let idx = (oct - 1) * 4 + sub;
    if idx >= HIST_BUCKETS {
        HIST_BUCKETS - 1
    } else {
        idx
    }
}

/// The largest lateness that lands in bucket `idx`, in nanoseconds.
///
/// Reported as the quantile value, which is why quantiles are upper
/// bounds rather than estimates: a reported `p95_ns` is a number the run
/// provably did not exceed 95% of the time.
const fn bucket_upper_ns(idx: usize) -> u64 {
    if idx < 4 {
        return idx as u64;
    }
    let oct = idx / 4 + 1;
    let sub = (idx % 4) as u64;
    // lower = (4 + sub) << (oct - 2), width = 1 << (oct - 2).
    ((5 + sub) << (oct - 2)) - 1
}

/// The upper bound of the first bucket whose cumulative count reaches
/// `pct`% of `total`. `0` when nothing was sampled.
fn quantile(hist: &[u64; HIST_BUCKETS], total: u64, pct: u64) -> u64 {
    if total == 0 {
        return 0;
    }
    let target = total.saturating_mul(pct).div_ceil(100).max(1);
    let mut cum: u64 = 0;
    for (idx, &count) in hist.iter().enumerate() {
        cum = cum.saturating_add(count);
        if cum >= target {
            return bucket_upper_ns(idx);
        }
    }
    bucket_upper_ns(HIST_BUCKETS - 1)
}

// ── the recorder ───────────────────────────────────────────────────────

/// Session-scoped counter storage.
///
/// One per `ProxySession`, shared by that session's forwarding tasks
/// through `Arc` (`ForwardCtx` is `#[derive(Clone)]` and cloned per task,
/// `session.rs:191-229`), so concurrently running sessions in one test
/// binary cannot see each other's increments. That is what makes
/// `objects_elided == 0` assertable at all.
///
/// Storage is atomics plus a `[AtomicU32; 128]` histogram — 512 bytes per
/// session. A release sample costs four relaxed atomic operations (sum,
/// count, max, one bucket) on a path that already did a `write_all`;
/// every other counter costs one.
pub struct Recorder {
    framers_created: AtomicU64,
    framer_header_polls: AtomicU64,
    framer_object_polls: AtomicU64,
    control_parsers_created: AtomicU64,
    datagram_headers_decoded: AtomicU64,
    egress_items_queued: AtomicU64,
    objects_elided: AtomicU64,
    object_ids_rewritten: AtomicU64,
    units_delayed: AtomicU64,
    objects_truncated: AtomicU64,
    actions_refused: AtomicU64,
    streams_not_shapeable: AtomicU64,
    objects_not_addressable: AtomicU64,
    control_frames_not_decodable: AtomicU64,
    release_error_ns: AtomicU64,
    release_count: AtomicU64,
    release_max_ns: AtomicU64,
    release_hist: [AtomicU32; HIST_BUCKETS],
    coarse_timer_reported: AtomicBool,
}

impl Default for Recorder {
    fn default() -> Self {
        Self {
            framers_created: AtomicU64::new(0),
            framer_header_polls: AtomicU64::new(0),
            framer_object_polls: AtomicU64::new(0),
            control_parsers_created: AtomicU64::new(0),
            datagram_headers_decoded: AtomicU64::new(0),
            egress_items_queued: AtomicU64::new(0),
            objects_elided: AtomicU64::new(0),
            object_ids_rewritten: AtomicU64::new(0),
            units_delayed: AtomicU64::new(0),
            objects_truncated: AtomicU64::new(0),
            actions_refused: AtomicU64::new(0),
            streams_not_shapeable: AtomicU64::new(0),
            objects_not_addressable: AtomicU64::new(0),
            control_frames_not_decodable: AtomicU64::new(0),
            release_error_ns: AtomicU64::new(0),
            release_count: AtomicU64::new(0),
            release_max_ns: AtomicU64::new(0),
            release_hist: std::array::from_fn(|_| AtomicU32::new(0)),
            coarse_timer_reported: AtomicBool::new(false),
        }
    }
}

impl std::fmt::Debug for Recorder {
    /// Prints the snapshot, not 128 histogram slots.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Recorder").field(&self.snapshot()).finish()
    }
}

/// One relaxed `+= 1` on a `u64` counter.
macro_rules! bump {
    ($doc:expr, $name:ident, $field:ident) => {
        #[doc = $doc]
        pub(crate) fn $name(&self) {
            self.$field.fetch_add(1, Ordering::Relaxed);
        }
    };
}

impl Recorder {
    /// A recorder with every counter at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot every counter for this session.
    pub fn snapshot(&self) -> Counters {
        let mut hist = [0u64; HIST_BUCKETS];
        let mut hist_total: u64 = 0;
        for (slot, out) in self.release_hist.iter().zip(hist.iter_mut()) {
            *out = u64::from(slot.load(Ordering::Relaxed));
            hist_total = hist_total.saturating_add(*out);
        }
        Counters {
            framers_created: self.framers_created.load(Ordering::Relaxed),
            framer_header_polls: self.framer_header_polls.load(Ordering::Relaxed),
            framer_object_polls: self.framer_object_polls.load(Ordering::Relaxed),
            control_parsers_created: self.control_parsers_created.load(Ordering::Relaxed),
            datagram_headers_decoded: self.datagram_headers_decoded.load(Ordering::Relaxed),
            egress_items_queued: self.egress_items_queued.load(Ordering::Relaxed),
            objects_elided: self.objects_elided.load(Ordering::Relaxed),
            object_ids_rewritten: self.object_ids_rewritten.load(Ordering::Relaxed),
            units_delayed: self.units_delayed.load(Ordering::Relaxed),
            objects_truncated: self.objects_truncated.load(Ordering::Relaxed),
            actions_refused: self.actions_refused.load(Ordering::Relaxed),
            streams_not_shapeable: self.streams_not_shapeable.load(Ordering::Relaxed),
            objects_not_addressable: self.objects_not_addressable.load(Ordering::Relaxed),
            control_frames_not_decodable: self.control_frames_not_decodable.load(Ordering::Relaxed),
            release_error_ns: self.release_error_ns.load(Ordering::Relaxed),
            release_errors: ReleaseErrors {
                count: self.release_count.load(Ordering::Relaxed),
                p50_ns: quantile(&hist, hist_total, 50),
                p95_ns: quantile(&hist, hist_total, 95),
                max_ns: self.release_max_ns.load(Ordering::Relaxed),
            },
        }
    }

    /// Record one deferred release's lateness.
    ///
    /// Call sites: the release arm of the egress `select!`, once per unit
    /// `pop_due` yields, with `now.saturating_duration_since(release_at)`.
    /// Units written inline and units flushed by a drain that ignores
    /// release times are **not** samples — recording them would dilute
    /// the distribution with zeros and report teardown as a timing
    /// failure.
    pub(crate) fn record_release(&self, late: Duration) {
        let ns = u64::try_from(late.as_nanos()).unwrap_or(u64::MAX);
        self.release_error_ns.fetch_add(ns, Ordering::Relaxed);
        self.release_count.fetch_add(1, Ordering::Relaxed);
        self.release_max_ns.fetch_max(ns, Ordering::Relaxed);
        self.release_hist[bucket_of(ns)].fetch_add(1, Ordering::Relaxed);
    }

    /// `true` the first time it is called, `false` after — a `swap(true)`
    /// on an `AtomicBool`, so "once per session" holds across the
    /// session's five concurrent forwarding tasks without a lock.
    pub(crate) fn claim_coarse_timer_report(&self) -> bool {
        !self.coarse_timer_reported.swap(true, Ordering::Relaxed)
    }

    bump!(
        "One `ObjectFramer` was constructed. `framer.rs`, both constructors.",
        note_framer_created,
        framers_created
    );
    bump!("`ObjectFramer::poll_header` was entered.", note_framer_header_poll, framer_header_polls);
    bump!("`ObjectFramer::poll_object` was entered.", note_framer_object_poll, framer_object_polls);
    bump!(
        "A `ControlStreamParser` was constructed. `session.rs`, behind `control_parse`.",
        note_control_parser_created,
        control_parsers_created
    );
    bump!(
        "An `AnyDatagramHeader::decode` call site was entered.",
        note_datagram_header_decoded,
        datagram_headers_decoded
    );
    bump!(
        "One unit was pushed onto a per-stream pending queue. `egress.rs`.",
        note_egress_item_queued,
        egress_items_queued
    );
    bump!("One object was removed by `DropMode::Elide`.", note_object_elided, objects_elided);
    bump!(
        "One elide fix-up was written: a leading Object ID varint on a          subgroup stream, a re-encoded framing on a fetch stream.",
        note_object_id_rewritten,
        object_ids_rewritten
    );
    bump!(
        "One unit was deferred by `Action::Delay`. Counted at the decision, \
         so a unit still queued when the session ends is already in it.",
        note_unit_delayed,
        units_delayed
    );
    bump!(
        "One object was cut short by `Action::Truncate`. Applied \
         truncations only — a refused attempt is `actions_refused`.",
        note_object_truncated,
        objects_truncated
    );
    bump!(
        "One action attempt was refused. Counted per attempt, not per stream.",
        note_action_refused,
        actions_refused
    );
    bump!(
        "The framer stopped parsing one stream — one latched bypass.",
        note_stream_not_shapeable,
        streams_not_shapeable
    );
    bump!(
        "One object was streamed through without being addressable. The \
         running total behind `ImpairmentKind::ObjectNotAddressable`, which \
         is emitted once per stream — so this counter and that event count \
         different things on purpose.",
        note_object_not_addressable,
        objects_not_addressable
    );

    /// `n` control frames were stepped over because the decoder refused
    /// them. `session.rs`, after any feed that raised the parser's running
    /// count.
    ///
    /// Takes a count where every neighbour takes none. `ControlStreamParser`
    /// reports a cumulative figure rather than an edge, and one feed can
    /// refuse several frames, so the caller passes the difference: three
    /// refusals in one chunk are three here and one
    /// `ImpairmentKind::ControlFrameNotDecodable`. A `+= 1` per call would
    /// have made the counter agree with the event and disagree with the
    /// traffic, which is the wrong one of the two to match.
    pub(crate) fn note_control_frames_not_decodable(&self, n: u64) {
        self.control_frames_not_decodable.fetch_add(n, Ordering::Relaxed);
    }
}

// ── the release thread, which is process-wide on purpose ───────────────

/// Which primitive the process-wide release thread waits on.
///
/// Descriptive, not a knob: the wheel picks the best available backend and
/// records what it got. `MOQTAP_RELEASE_TIMER` overrides it only to
/// diagnose a host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TimerBackend {
    /// One dedicated OS thread sleeping in `SLICE`-bounded
    /// `std::thread::sleep` steps and parking on an untimed `Condvar`
    /// when no deadline is armed. The backend on **every** platform, and
    /// sub-millisecond on all of them: measured p50 lateness
    /// 0.11-0.17 ms, p95 0.52-0.57 ms on Windows 11.
    SleepSlice,
    /// `std::sync::Condvar::wait_timeout`, reachable only by setting
    /// `MOQTAP_RELEASE_TIMER=condvar`. Precise on Unix, where it is
    /// backed by a `CLOCK_MONOTONIC` hrtimer; on Windows it is bounded
    /// below by the ~15.6 ms system tick (measured p50 lateness
    /// 12.26 ms for a 3 ms deadline) and is the forced-diagnosis backend
    /// rather than a fallback.
    Condvar,
}

impl TimerBackend {
    /// Whether this backend can resolve delays below the ~15.6 ms Windows
    /// system tick.
    ///
    /// `SleepSlice => true` on every platform. `Condvar => cfg!(unix)` —
    /// platform-dependent, because it is the good primitive on Unix and
    /// the degraded one on Windows, and the type says so rather than the
    /// reader having to know.
    pub const fn is_high_resolution(self) -> bool {
        match self {
            Self::SleepSlice => true,
            Self::Condvar => cfg!(unix),
        }
    }

    /// A stable, lowercase, machine-readable name for reports:
    /// `"sleep-slice"` / `"condvar"`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SleepSlice => "sleep-slice",
            Self::Condvar => "condvar",
        }
    }
}

/// No release thread has been constructed.
const BACKEND_NONE: u8 = 0;
/// [`TimerBackend::SleepSlice`].
const BACKEND_SLEEP_SLICE: u8 = 1;
/// [`TimerBackend::Condvar`].
const BACKEND_CONDVAR: u8 = 2;

/// The process-wide release thread's backend, or [`BACKEND_NONE`].
///
/// Monotonic: written exactly once, by the construction of the
/// process-wide wheel, and never cleared. That monotonicity is what makes
/// [`release_timer_started`] sound to assert on from a test that shares a
/// binary with other tests — in the `true` direction. The tests that assert
/// `false` are isolated into a test binary of their own, because
/// `false → true` is the direction that *can* be spoiled.
static RELEASE_TIMER_BACKEND: AtomicU8 = AtomicU8::new(BACKEND_NONE);

/// Whether the process-wide release thread exists.
///
/// `false` until some session issues a `Delay` with a future release time
/// or a `Hold`. This is the falsifiable form of "an `Interest::NONE`
/// session starts no threads": assert it, do not assume it.
pub fn release_timer_started() -> bool {
    RELEASE_TIMER_BACKEND.load(Ordering::Acquire) != BACKEND_NONE
}

/// Which backend the process-wide release thread resolved to, or `None`
/// if it has not started.
pub fn release_timer_backend() -> Option<TimerBackend> {
    match RELEASE_TIMER_BACKEND.load(Ordering::Acquire) {
        BACKEND_SLEEP_SLICE => Some(TimerBackend::SleepSlice),
        BACKEND_CONDVAR => Some(TimerBackend::Condvar),
        _ => None,
    }
}

/// Publish the fact that the **process-wide** release thread now exists.
///
/// `release_timer.rs` is the only caller, and must call it from inside
/// `shared()`'s one-time initialiser — after `ReleaseTimer::new()` has
/// resolved a backend, and *not* from `ReleaseTimer::new()` itself, which
/// also runs for the owned wheels this module's tests and any per-socket
/// owner construct. Publishing from `new()` would make
/// [`release_timer_started`] report a process-wide thread that does not
/// exist.
///
/// The state lives here rather than in `release_timer.rs` so that
/// `instrument.rs` compiles standing alone, depending on nothing else in
/// the crate, and so there is exactly one source of truth for a value two
/// modules expose. `release_timer::started()` / `release_timer::backend()`
/// read it back through the two public functions above.
///
/// First writer wins; later calls are ignored, which keeps the value
/// monotonic even if a future caller gets the "once" wrong.
///
/// This function is `pub(crate)` and has no `#[allow(dead_code)]` on
/// purpose: if `release_timer.rs` never calls it, `-D warnings` fails the
/// build rather than leaving `release_timer_started()` silently stuck at
/// `false` — which is the direction that would make the tests asserting
/// that no release thread was started pass for the wrong reason.
pub(crate) fn note_release_timer_started(backend: TimerBackend) {
    let code = match backend {
        TimerBackend::SleepSlice => BACKEND_SLEEP_SLICE,
        TimerBackend::Condvar => BACKEND_CONDVAR,
    };
    let _ = RELEASE_TIMER_BACKEND.compare_exchange(
        BACKEND_NONE,
        code,
        Ordering::Release,
        Ordering::Relaxed,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn a_fresh_recorder_snapshots_as_default() {
        assert_eq!(Recorder::new().snapshot(), Counters::default());
    }

    #[test]
    fn every_counter_moves_independently() {
        let r = Recorder::new();
        r.note_framer_created();
        r.note_framer_header_poll();
        r.note_framer_header_poll();
        r.note_framer_object_poll();
        r.note_control_parser_created();
        r.note_datagram_header_decoded();
        r.note_egress_item_queued();
        r.note_object_elided();
        r.note_object_id_rewritten();
        r.note_action_refused();
        r.note_stream_not_shapeable();
        r.note_object_not_addressable();
        r.note_control_frames_not_decodable(1);

        let c = r.snapshot();
        assert_eq!(c.framers_created, 1);
        assert_eq!(c.framer_header_polls, 2);
        assert_eq!(c.framer_object_polls, 1);
        assert_eq!(c.control_parsers_created, 1);
        assert_eq!(c.datagram_headers_decoded, 1);
        assert_eq!(c.egress_items_queued, 1);
        assert_eq!(c.objects_elided, 1);
        assert_eq!(c.object_ids_rewritten, 1);
        assert_eq!(c.actions_refused, 1);
        assert_eq!(c.streams_not_shapeable, 1);
        assert_eq!(c.objects_not_addressable, 1);
        assert_eq!(c.control_frames_not_decodable, 1);
        // Nothing was released, so the release fields stay at their
        // defaults — a counter suite whose fields bled into each other
        // would make every counter assertion meaningless.
        assert_eq!(c.release_error_ns, 0);
        assert_eq!(c.release_errors, ReleaseErrors::default());
    }

    /// Two sessions, one process, no interference — the property that lets
    /// a test assert `objects_elided == 0` while sharing a binary with
    /// tests whose whole purpose is to elide.
    #[test]
    fn two_recorders_do_not_see_each_others_increments() {
        let a = Arc::new(Recorder::new());
        let b = Arc::new(Recorder::new());
        for _ in 0..5 {
            a.note_object_elided();
        }
        assert_eq!(a.snapshot().objects_elided, 5);
        assert_eq!(b.snapshot().objects_elided, 0);
    }

    /// The `Arc` clone a `ForwardCtx` hands to each forwarding task must
    /// reach the same counters, or the session's totals are per-task.
    #[test]
    fn arc_clones_share_one_recorder() {
        let a = Arc::new(Recorder::new());
        let b = Arc::clone(&a);
        std::thread::scope(|s| {
            for _ in 0..4 {
                let r = Arc::clone(&b);
                s.spawn(move || {
                    for _ in 0..250 {
                        r.note_framer_object_poll();
                    }
                });
            }
        });
        assert_eq!(a.snapshot().framer_object_polls, 1000);
    }

    #[test]
    fn the_coarse_timer_report_is_claimed_exactly_once() {
        let r = Arc::new(Recorder::new());
        let claims: usize = std::thread::scope(|s| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    let r = Arc::clone(&r);
                    s.spawn(move || usize::from(r.claim_coarse_timer_report()))
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).sum()
        });
        assert_eq!(claims, 1);
        assert!(!r.claim_coarse_timer_report());
    }

    #[test]
    fn buckets_are_monotonic_and_bounded_by_their_upper_bound() {
        let mut previous = 0usize;
        // Every power of two and its neighbours, plus the exact small
        // values: a swapped shift or an off-by-one in `bucket_of` shows
        // up as a non-monotonic index rather than as a wrong quantile
        // nobody can trace.
        let mut probes: Vec<u64> = (0..16).collect();
        for shift in 2..63u32 {
            let base = 1u64 << shift;
            probes.extend([base - 1, base, base + 1, base + base / 2]);
        }
        probes.sort_unstable();
        for ns in probes {
            let idx = bucket_of(ns);
            assert!(idx >= previous, "bucket_of({ns}) went backwards");
            assert!(idx < HIST_BUCKETS);
            previous = idx;
            if idx < HIST_BUCKETS - 1 {
                assert!(ns <= bucket_upper_ns(idx), "{ns} exceeds the upper bound of bucket {idx}");
            }
        }
    }

    #[test]
    fn a_bucket_is_never_more_than_25_percent_wide() {
        for idx in 4..HIST_BUCKETS {
            let upper = bucket_upper_ns(idx);
            let lower = bucket_upper_ns(idx - 1) + 1;
            assert!(lower <= upper, "bucket {idx} is empty or inverted");
            assert!(
                (upper - lower + 1) * 4 <= upper + 1,
                "bucket {idx} ({lower}..={upper}) is wider than 25%"
            );
        }
    }

    #[test]
    fn quantiles_bound_the_samples_they_summarise() {
        let r = Recorder::new();
        // 100 samples: 1 µs ×95, 40 ms ×5. p50 is a microsecond-ish
        // bucket, p95 is still one, max is exact.
        for _ in 0..95 {
            r.record_release(Duration::from_micros(1));
        }
        for _ in 0..5 {
            r.record_release(Duration::from_millis(40));
        }
        let c = r.snapshot();
        assert_eq!(c.release_errors.count, 100);
        assert_eq!(c.release_errors.max_ns, 40_000_000);
        assert_eq!(c.release_error_ns, 95 * 1_000 + 5 * 40_000_000);
        assert!(c.release_errors.p50_ns >= 1_000);
        assert!(c.release_errors.p50_ns < 1_250, "p50 too coarse");
        assert!(c.release_errors.p95_ns >= 1_000);
        assert!(c.release_errors.p95_ns < 40_000_000, "p95 must not be dragged up by the 5% tail");
    }

    #[test]
    fn a_single_sample_is_its_own_p50_and_p95() {
        let r = Recorder::new();
        r.record_release(Duration::from_micros(300));
        let e = r.snapshot().release_errors;
        assert_eq!(e.count, 1);
        assert_eq!(e.max_ns, 300_000);
        assert!(e.p50_ns >= 300_000 && e.p50_ns < 375_000);
        assert_eq!(e.p50_ns, e.p95_ns);
    }

    #[test]
    fn a_zero_lateness_release_is_still_a_release() {
        let r = Recorder::new();
        r.record_release(Duration::ZERO);
        let e = r.snapshot().release_errors;
        assert_eq!(e.count, 1);
        assert_eq!(e.max_ns, 0);
        assert_eq!(e.p50_ns, 0);
    }

    #[test]
    fn an_absurd_lateness_saturates_the_last_bucket_but_not_the_max() {
        let r = Recorder::new();
        r.record_release(Duration::from_secs(3600));
        let e = r.snapshot().release_errors;
        assert_eq!(e.max_ns, 3_600_000_000_000);
        assert_eq!(e.p50_ns, bucket_upper_ns(HIST_BUCKETS - 1));
    }

    #[test]
    fn the_backend_names_and_resolutions_are_pinned() {
        assert_eq!(TimerBackend::SleepSlice.as_str(), "sleep-slice");
        assert_eq!(TimerBackend::Condvar.as_str(), "condvar");
        assert!(TimerBackend::SleepSlice.is_high_resolution());
        assert_eq!(TimerBackend::Condvar.is_high_resolution(), cfg!(unix));
    }

    /// The codes `note_release_timer_started` stores must decode back to
    /// the backend that was stored, and `BACKEND_NONE` must decode to
    /// `None`. Asserted without touching the static: setting it would
    /// make this test binary's `release_timer_started()` `true` for every
    /// other test in it — the hazard that keeps the tests asserting `false`
    /// in a binary of their own.
    #[test]
    fn the_backend_encoding_round_trips() {
        for (code, backend) in [
            (BACKEND_SLEEP_SLICE, TimerBackend::SleepSlice),
            (BACKEND_CONDVAR, TimerBackend::Condvar),
        ] {
            let decoded = match code {
                BACKEND_SLEEP_SLICE => Some(TimerBackend::SleepSlice),
                BACKEND_CONDVAR => Some(TimerBackend::Condvar),
                _ => None,
            };
            assert_eq!(decoded, Some(backend));
            assert_ne!(code, BACKEND_NONE);
        }
    }
}

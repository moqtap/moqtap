//! The per-stream deferred-write deque — the engine behind `Delay` and
//! `Hold`.
//!
//! A [`PendingQueue`] is a **local variable** in the pipe function that already
//! owns both halves of the stream. No task, no channel, no `Semaphore`: the
//! reader keeps `&mut send`, so a mirrored peer reset still leaves the
//! destination *after* the bytes already written, which is what
//! `proxy_reset.rs::upstream_reset_reaches_the_client_as_a_reset_with_the_same_code`
//! (*data, **then** reset*) asserts. A writer-task design reverses that
//! ordering and cannot be made to pass it.
//!
//! The queue is empty and non-allocating unless a timing action is used —
//! `VecDeque::new` does not allocate — so a session that only passes,
//! replaces or drops never touches this module's hot path and never links
//! [`crate::release_timer`] into any executed code.
//!
//! # The shape the pipe loop takes
//!
//! ```ignore
//! let can_read     = pending.accepts_more();   // byte + unit budget, a bool
//! let head_release = pending.head_release();   // Option<Release>, owned clone
//!
//! tokio::select! {
//!     // `can_read` chooses *inside* observe_source: true polls
//!     // `recv.read`, false polls `recv.received_reset()`, which consumes
//!     // no bytes. The source is never unobserved — see `observe_source`.
//!     source = observe_source(&mut recv, &mut buf, can_read, watch) => { /* enqueue-or-write-now */ }
//!     _ = egress::wait_release(head_release.clone(), &ctx.cancel), if head_release.is_some() => {
//!         let now = Instant::now();
//!         while let Some(unit) = pending.pop_next_due(now) {
//!             pending.record_release(&unit, now);
//!             egress::write_unit(unit, &mut send).await?;
//!         }
//!     }
//!     _ = ctx.cancel.cancelled() => { /* framer.finish() flush, then drain, then return */ }
//! }
//! ```
//!
//! Both branch *expressions* are free of any borrow of `pending`: one is a
//! `bool`, the other an owned [`Release`] (one `Arc` clone plus one token
//! clone). That is a **rule, not a compile error** — a branch future holding
//! `&mut pending` whose winning body then calls `pending.pop_next_due()`
//! does in fact compile, because `select!` drops the branch-future tuple
//! before the handler runs. Keeping the expressions borrow-free is what lets
//! [`wait_release`] be a free function shared by the release branch and by
//! [`drain_honouring_release_times`], and lets a later edit add a fourth
//! branch without re-arranging the other three.
//!
//! **Why [`tokio_util::sync::CancellationToken`] and not a `Notify` or a
//! waker registration**: it is level-triggered. The `select!` may create and
//! drop a fresh `cancelled()` future on every iteration with no lost-wakeup
//! window and no re-registration, whereas a `Notify`-based wheel would need
//! a global-mutex round trip per read chunk to re-register.
//! `if head_release.is_some()` matters for the same reason from the other
//! side: tokio does not evaluate a branch's async expression when its
//! precondition is false, so an empty queue costs one `Option::is_some()`.
//!
//! # Cancellation
//!
//! Every wait in this module is a `select!` **branch**, never an arm body:
//! an arm body is not preemptible, so an inline sleep there starves the
//! cancel branch and a `Hold` on a gate nobody releases would pin session
//! teardown for up to [`EgressConfig::max_hold`] (30 s by default). That
//! applies to the two release-honouring drains as much as to the pipe loop,
//! which is why [`drain_honouring_release_times`] is written as a `biased`
//! race against cancellation with
//! [`PendingQueue::drain_ignoring_release_times`] as its fallback.
//!
//! # Ordering is the queue's; readiness is the unit's
//!
//! The two are **separate properties**, and conflating them is what the
//! first shape of this module got wrong.
//!
//! * *Ordering* belongs to the deque. [`PendingQueue::pop_next_due`] only
//!   ever looks at the **front**, so nothing can be written before
//!   everything ahead of it has been. That invariant needs no arithmetic
//!   at all, and it is absolute: anything else silently corrupts MoQT
//!   stream semantics.
//! * *Readiness* belongs to the unit. A [`Pending`] is due when
//!   [`Pending::due_at`] has passed **or** its own `Hold` gate is open —
//!   see [`Pending::is_due`]. Nothing that happens to a unit ahead of it
//!   may rewrite that.
//!
//! So [`PendingQueue::push`] does **not** clamp `due_at` against the tail.
//! An earlier shape did, and it turned a `Hold`'s
//! [`EgressConfig::max_hold`] ceiling into a *deadline conferred on every
//! successor*: releasing the gate woke only the unit carrying it, and
//! objects queued behind — including the stream's FIN, which waits for the
//! queue to drain — sat until `max_hold` (30 s by default). Worse, a
//! `Delay`'s own deadline was overwritten by the ceiling of a `Hold` in
//! front of it, so the deadline `Action::Delay` documents ("`arrived_at +
//! by`, a deadline, not a spacing") was not the one the engine honoured.
//!
//! What the clamp *was* for is still wanted, and it survives as a separate
//! field: [`Pending::expected_at`] is `max(due_at, tail.expected_at, now)`,
//! the queue's estimate of when the unit will actually reach the wire given
//! everything ahead of it. It is what [`Push::release_at`] reports as
//! `Effect::Queued { release_at }` and what [`PendingQueue::record_release`]
//! measures lateness against, so a unit queued behind a 300 ms delay is not
//! logged as a 300 ms timer error. It never gates anything.
//!
//! # Bound
//!
//! [`PendingQueue::accepts_more`] is `false` once the queue holds
//! [`EgressConfig::max_pending_bytes`] (1 MiB default) **or**
//! [`MAX_PENDING_UNITS`] units. The pipe loop stops calling `recv.read` on
//! `false`, so the queue cannot grow past that plus one in-flight read
//! chunk. **It does not stop observing the source**: it swaps the read for
//! `RecvStream::received_reset`, which consumes nothing, so the bound here
//! is unchanged and a peer's `RESET_STREAM` is still seen at once. The
//! unit cap is not redundant with the byte cap: an elided unit
//! holds an ordering slot and carries zero bytes, so a hook that elides
//! every object behind a never-released `Hold` would otherwise grow the
//! deque without bound at zero bytes. Crossing either cap is reported once
//! per stream — see [`Push::entered_backpressure`].

use std::collections::VecDeque;
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use moqtap_client::transport::{SendStream, TransportError};

use crate::action::{EgressConfig, Gate};
use crate::error::ProxyError;
use crate::instrument::Recorder;
use crate::release_timer::{self, Deadline};
use crate::shape::{Acquire, Class, Expiry, QueueDepth, Scheduler, ShapeRecorder};
use crate::types::ProxySide;

/// Hard cap on queued units, independent of the byte budget.
///
/// A [`Pending`] is on the order of 64 bytes, so this is roughly the same
/// order of bookkeeping as the default 1 MiB byte budget, and it is far
/// more objects than any realistic hold window. It exists because
/// [`Item::Elided`] units carry zero bytes: without it, eliding every
/// object behind a never-released `Hold` grows the deque without bound
/// while `queued_bytes()` stays at zero.
pub(crate) const MAX_PENDING_UNITS: usize = 8192;

/// What writing to a destination can fail with.
///
/// Deliberately narrower than [`ProxyError`]: this module hands bytes to a
/// transport and abandons streams, and those are the only two ways it can
/// fail. Naming them separately is what lets a sink be implemented without
/// naming a crate-wide error enum whose listener, TLS, certificate, qlog and
/// draft-admission cases a write can never produce — and the recording sink
/// below is the second implementor, so "without naming it" is not
/// hypothetical.
///
/// Nothing a caller sees changes: the conversion below is applied by `?` at
/// every boundary this module is called across, and it produces the same
/// [`ProxyError`] the failure produced before.
///
/// One case, and the enum is still the right shape. Every failure reaching
/// here today comes back from the transport, which is a fact about the two
/// operations rather than about the one production implementor — so a second
/// case would be a second *kind of failure*, not a second sink, and would want
/// a name of its own. The recording sink below models a refused write as a
/// refused write for the same reason: a test sink inventing a failure the
/// transport cannot produce would be testing a path nothing takes.
#[derive(Debug, thiserror::Error)]
pub(crate) enum EgressError {
    /// The transport refused a write or a reset.
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),
}

impl From<EgressError> for ProxyError {
    fn from(error: EgressError) -> Self {
        let EgressError::Transport(source) = error;
        ProxyError::Transport(source)
    }
}

// ── The destination ─────────────────────────────────────────────────

/// The write half this module drives.
///
/// A trait rather than a bare `&mut SendStream` for exactly one reason:
/// the ordering, clamping, terminal and cancellation behaviour below is
/// then testable in-process against a recording sink, with no QUIC
/// handshake and no timing. The only production implementor is
/// [`SendStream`].
///
/// `write_all` returns `impl Future + Send` rather than being an
/// `async fn`: the forwarding tasks are spawned onto a multi-threaded
/// runtime, so every future this module builds has to be `Send`, and an
/// `async fn` in a trait carries no such bound.
pub(crate) trait EgressSink {
    /// Hand `buf` to the transport.
    fn write_all(&mut self, buf: &[u8]) -> impl Future<Output = Result<(), EgressError>> + Send;
    /// Abandon the stream with `code`, discarding anything still in the
    /// local send buffer.
    fn reset(&mut self, code: u64) -> Result<(), EgressError>;
}

impl EgressSink for SendStream {
    // `async fn` here still satisfies the trait's `impl Future + Send`:
    // the compiler checks the Send-ness of the generated future against
    // the bound, which is the whole reason the bound is on the trait.
    // Inherent methods win method resolution, so the call below is the
    // transport's own `write_all`, not this trait's.
    async fn write_all(&mut self, buf: &[u8]) -> Result<(), EgressError> {
        SendStream::write_all(self, buf).await.map_err(EgressError::from)
    }

    fn reset(&mut self, code: u64) -> Result<(), EgressError> {
        SendStream::reset(self, code).map_err(EgressError::from)
    }
}

// ── Release handles ─────────────────────────────────────────────────

/// What the head of a queue is waiting for. Owned, cheap to clone.
///
/// Cloning is one `Arc` clone plus one or two token clones. Nothing here
/// borrows the queue, which is what keeps [`wait_release`] a free function
/// usable from both the pipe loop's release branch and the drains.
#[derive(Clone, Debug)]
pub(crate) struct Release {
    /// The wheel's handle for `release_at`. Registration happened once, in
    /// [`PendingQueue::arm_head`]; awaiting this registers nothing.
    deadline: Deadline,
    /// A `Hold`'s gate, when the head carries one.
    gate: Option<Gate>,
}

// Read only by this module's own tests today — `session.rs` awaits a
// `Release` through `wait_release` and never inspects it, and `exec.rs`
// never sees one. Kept because it is part of this type's deliberate read
// surface and because the fast-path test asserts on the deadline's token
// directly; the allow is on the one item rather than on the file, so
// anything that becomes dead later is still a build failure.
#[allow(dead_code)]
impl Release {
    /// The wheel handle, for callers that want to observe it directly.
    pub(crate) fn deadline(&self) -> &Deadline {
        &self.deadline
    }
}

/// Resolve when the head unit may be written, or when the session is torn
/// down — whichever comes first.
///
/// Races three level-triggered tokens: the wheel's deadline, the unit's
/// `Hold` gate (a released gate makes a unit due early — see
/// [`Pending::is_due`]) and session cancellation. It **registers nothing**:
/// every one of the three is a `CancellationToken`, so creating and
/// dropping the futures on each `select!` iteration is free of lost-wakeup
/// races.
///
/// `None` parks until cancellation. Callers guard the branch with
/// `if head_release.is_some()`, so that path is a safety net rather than a
/// normal outcome: it must not resolve immediately, or a caller that forgot
/// the guard would spin the loop hot on an empty queue.
pub(crate) async fn wait_release(release: Option<Release>, cancel: &CancellationToken) {
    let Some(release) = release else {
        cancel.cancelled().await;
        return;
    };
    match release.gate {
        Some(gate) => {
            tokio::select! {
                () = release.deadline.token().cancelled() => {}
                () = gate.wait() => {}
                () = cancel.cancelled() => {}
            }
        }
        None => {
            tokio::select! {
                () = release.deadline.token().cancelled() => {}
                () = cancel.cancelled() => {}
            }
        }
    }
}

// ── Queued units ────────────────────────────────────────────────────

/// A positional stream ending.
///
/// Enqueued *behind* the current queue contents, so everything decided
/// before it is written first. Nothing may be queued behind one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Terminal {
    /// Write `prefix`, then `RESET_STREAM` with `code` —
    /// [`crate::action::Action::Truncate`].
    ///
    /// The peer observes **at most** `prefix.len()` further bytes and may
    /// observe none: quinn clears the receive assembler when the reset is
    /// processed, and `reset()` discards the local send buffer too.
    Truncate {
        /// The prefix of the unit to write before resetting.
        prefix: Bytes,
        /// The application error code for the reset.
        code: u64,
    },
    /// `RESET_STREAM` with `code` and nothing further —
    /// [`crate::action::Action::ResetStream`].
    Reset {
        /// The application error code for the reset.
        code: u64,
    },
}

impl Terminal {
    /// Bytes this terminal still owes the wire.
    fn len(&self) -> usize {
        match self {
            Terminal::Truncate { prefix, .. } => prefix.len(),
            Terminal::Reset { .. } => 0,
        }
    }
}

/// What a queued unit does when it is written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Item {
    /// Write these bytes. Already whatever the action made of them —
    /// verbatim for `Pass`, spliced for `ReplacePayload`, substituted for
    /// `Replace`.
    Write(Bytes),
    /// Write nothing.
    ///
    /// An elided unit still takes a slot when the queue is non-empty: it
    /// was decided at a point in the stream, and dropping it out of band
    /// would let a later unit be written before an earlier one is.
    Elided,
    /// End the stream. See [`Terminal`].
    Terminal(Terminal),
}

/// What the shaper attached to one queued unit, on a shaped stream.
///
/// `None` on every unit of every unshaped stream, which is what makes "a
/// session with no `ShapeProfile` adds nothing to this path" a fact the type
/// carries rather than a claim a reviewer checks.
#[derive(Clone, Copy, Debug)]
struct ShapeTag {
    /// The row this unit's bytes are charged to, and the bucket it draws
    /// from. Resolved per unit at admission — never per stream, because
    /// `object_id` and `every_nth` are legal class selectors and a
    /// stream-sticky class would evaluate them on object 0 alone.
    class: Class,
    /// The instant this unit goes out **anyway**: `arrived_at` plus the
    /// profile's `max_hold`, or the engine's when the profile inherits it.
    ///
    /// Under the default `Expiry::Deliver` that is a clamp, not a drop — so
    /// a starved class is late, never silently lossy, and "delivers zero
    /// bytes" is always a statement about a sampling window.
    expires_at: Instant,
    /// Whether this unit has already been counted against
    /// `starved_behind_other_class`. Once per unit, not once per wake.
    starved_noted: bool,
}

/// One unit of traffic waiting for its release time.
#[derive(Clone, Debug)]
pub(crate) struct Pending {
    /// The earliest instant **this** unit may be written, and the only instant
    /// that gates it. Set once, by whoever built the unit, and never rewritten
    /// by the queue — see the module doc's *Ordering is the queue's; readiness
    /// is the unit's*.
    due_at: Instant,
    /// When the queue *expects* to write it, given everything ahead of it:
    /// `max(due_at, tail.expected_at, now)` at push time.
    ///
    /// Reporting and lateness only. It gates nothing, and it is
    /// deliberately an over-estimate for a unit queued behind a `Hold`,
    /// whose gate may open long before its [`EgressConfig::max_hold`]
    /// ceiling.
    expected_at: Instant,
    /// A `Hold`'s gate. Releasing it makes the unit due before `due_at`,
    /// which for a held unit is the [`EgressConfig::max_hold`] ceiling.
    gate: Option<Gate>,
    /// What writing it does.
    item: Item,
    /// The shaper's tag, on a shaped stream only. Attached by
    /// [`PendingQueue::push`] from the class the pipe loop most recently
    /// resolved, so `exec`'s pushes carry it without `exec` naming a class.
    shape: Option<ShapeTag>,
}

impl Pending {
    /// Bytes to write no earlier than `due_at`.
    pub(crate) fn bytes(raw: Bytes, due_at: Instant) -> Self {
        Self { due_at, expected_at: due_at, gate: None, item: Item::Write(raw), shape: None }
    }

    /// An ordering placeholder that writes nothing.
    pub(crate) fn elided(due_at: Instant) -> Self {
        Self { due_at, expected_at: due_at, gate: None, item: Item::Elided, shape: None }
    }

    /// A positional terminal, due as soon as the queue ahead of it drains.
    pub(crate) fn terminal(terminal: Terminal) -> Self {
        let now = Instant::now();
        Self {
            due_at: now,
            expected_at: now,
            gate: None,
            item: Item::Terminal(terminal),
            shape: None,
        }
    }

    /// Attach a `Hold`'s gate. `due_at` stays the `max_hold` ceiling.
    #[must_use]
    pub(crate) fn with_gate(mut self, gate: Gate) -> Self {
        self.gate = Some(gate);
        self
    }

    // The observers below are read by this module's tests and by nothing
    // else: the queue answers `due_at` through `head_release()`, and a
    // terminal announces itself through `Written::Terminated` rather than
    // being asked. They stay as the deliberate read surface of a unit,
    // with the allow scoped to them rather than to the file.
    /// When this unit becomes due on its own account.
    #[allow(dead_code)]
    pub(crate) fn due_at(&self) -> Instant {
        self.due_at
    }

    /// When the queue expected to write it. Never a gate; see the field.
    #[allow(dead_code)]
    pub(crate) fn expected_at(&self) -> Instant {
        self.expected_at
    }

    /// What it does. Terminals end the stream.
    #[allow(dead_code)]
    pub(crate) fn item(&self) -> &Item {
        &self.item
    }

    /// Whether this unit ends the stream.
    #[allow(dead_code)]
    pub(crate) fn is_terminal(&self) -> bool {
        matches!(self.item, Item::Terminal(_))
    }

    /// Bytes this unit is holding on the queue's behalf.
    pub(crate) fn len(&self) -> usize {
        match &self.item {
            Item::Write(raw) => raw.len(),
            Item::Elided => 0,
            Item::Terminal(t) => t.len(),
        }
    }

    /// Whether this unit may be written at `now`, **on its own account**.
    ///
    /// Readiness only: whether anything is still queued ahead of it is the
    /// deque's business, and [`PendingQueue::pop_next_due`] answers that by
    /// looking at the front and nowhere else.
    ///
    /// A **released gate makes it due**, regardless of `due_at`. Without
    /// that clause, releasing a `Hold` early wakes the release branch to
    /// find nothing due and the loop spins hot until
    /// [`EgressConfig::max_hold`] — one of the two ways this loop can spin
    /// hot, and the one that is invisible from the call site.
    ///
    /// `expected_at` is deliberately **not** consulted: it is the queue's
    /// estimate, and for a unit behind a `Hold` it is that hold's ceiling.
    /// Gating on it is what stranded whole streams behind a released gate.
    fn is_due(&self, now: Instant) -> bool {
        self.due_at <= now || self.gate.as_ref().is_some_and(Gate::is_released)
    }
}

/// What handing one unit to the transport did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Written {
    /// This many bytes were handed to the transport.
    Bytes(usize),
    /// Nothing was written — an elided unit holding its ordering slot.
    Nothing,
    /// A terminal fired. The destination is reset; nothing further may be
    /// written to it.
    Terminated {
        /// Bytes written ahead of the reset, on this unit.
        forwarded: usize,
        /// The code the stream was reset with.
        code: u64,
    },
}

/// Write one popped unit.
///
/// A failing prefix write on a [`Terminal::Truncate`] is propagated rather
/// than swallowed: the caller mirrors it with `propagate_stop`, and the
/// reset it would have sent is moot once the peer has stopped us. A failing
/// `reset` is *not* propagated — it means the stream was already finished
/// or reset, so there is nothing left to report and nothing left to do.
pub(crate) async fn write_unit<S: EgressSink>(
    unit: Pending,
    send: &mut S,
) -> Result<Written, EgressError> {
    match unit.item {
        Item::Write(raw) => {
            send.write_all(&raw).await?;
            Ok(Written::Bytes(raw.len()))
        }
        Item::Elided => Ok(Written::Nothing),
        Item::Terminal(Terminal::Truncate { prefix, code }) => {
            if !prefix.is_empty() {
                send.write_all(&prefix).await?;
            }
            let _ = send.reset(code);
            Ok(Written::Terminated { forwarded: prefix.len(), code })
        }
        Item::Terminal(Terminal::Reset { code }) => {
            let _ = send.reset(code);
            Ok(Written::Terminated { forwarded: 0, code })
        }
    }
}

// ── Delay and hold arithmetic ───────────────────────────────────────

/// A resolved release deadline, and whether [`EgressConfig::max_hold`] cut
/// it short.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Deferral {
    /// The deadline to put on the [`Pending`], before the queue's own
    /// monotonic clamp.
    pub(crate) release_at: Instant,
    /// What was asked for.
    pub(crate) requested: Duration,
    /// What was applied.
    pub(crate) applied: Duration,
}

impl Deferral {
    /// Whether `max_hold` cut the request short — emit
    /// `Impairment { HoldClamped { requested, applied } }`, once per
    /// clamped unit.
    pub(crate) fn was_clamped(&self) -> bool {
        self.applied < self.requested
    }
}

/// Resolve `Delay { by }` against [`EgressConfig::max_hold`].
///
/// A **deadline**, not a spacing: `arrived_at + by`. Two units arriving
/// together with the same `by` are released together, not staggered.
pub(crate) fn defer_by(arrived_at: Instant, by: Duration, config: &EgressConfig) -> Deferral {
    let applied = by.min(config.max_hold);
    Deferral { release_at: arrived_at + applied, requested: by, applied }
}

/// The ceiling on an [`crate::action::Action::Hold`]: a gate nobody
/// releases is still written at `arrived_at + max_hold`, so a hook cannot
/// pin a stream open forever.
pub(crate) fn hold_ceiling(arrived_at: Instant, config: &EgressConfig) -> Instant {
    arrived_at + config.max_hold
}

// ── The queue ───────────────────────────────────────────────────────

/// What [`PendingQueue::push`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Push {
    /// [`Pending::expected_at`] — the queue's estimate of when this unit
    /// reaches the wire, which is the value to report as
    /// `Effect::Queued { release_at }`. It accounts for everything already
    /// queued, so it may be later than the action asked for, and for a unit
    /// behind a `Hold` it is that hold's `max_hold` ceiling: an upper
    /// bound, since a gate may open at any time before it.
    ///
    /// **Not** the unit's own deadline. That is [`Pending::due_at`], it is
    /// the only thing that gates the unit, and `push` never rewrites it.
    pub(crate) release_at: Instant,
    /// `true` exactly once per stream: on the push after which
    /// [`PendingQueue::accepts_more`] first turns `false`. Emit
    /// `Impairment { EgressQueueFull { stream_id } }` on it, and only on
    /// it — a queue that drains and fills again does not report twice.
    pub(crate) entered_backpressure: bool,
}

/// How a drain ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DrainOutcome {
    /// Every queued unit was written.
    Complete,
    /// Cancellation won mid-drain. The remainder was flushed ignoring
    /// release times; [`PendingQueue::unconfirmed_bytes`] afterwards is
    /// what that fallback either could not write **or** wrote into a
    /// transport that is being closed out from under it, and is what
    /// `Impairment { QueuedBytesAtTeardown }` carries.
    CancelledMidDrain,
    /// A queued terminal fired. The destination is reset and nothing
    /// further may be written to it.
    Terminated {
        /// Bytes written on the terminal unit itself, ahead of the reset.
        forwarded: usize,
        /// The code the stream was reset with.
        code: u64,
    },
    /// A write failed. The failing unit and everything behind it are still
    /// queued. Only the best-effort drain returns this; the
    /// release-honouring drain propagates the error instead.
    WriteFailed,
    /// The teardown flush declined to write anything, because the session's
    /// [`EgressGauge`] is discarding: a requested close ran out of drain
    /// time, so what is left is reported rather than handed to a connection
    /// that is about to be closed. The queue is untouched, so
    /// [`PendingQueue::unconfirmed_bytes`] is exactly what was abandoned.
    Discarded,
}

/// How many bytes one session's egress queues are holding, right now.
///
/// One gauge per session, shared by every [`PendingQueue`] the session
/// builds. It exists for a single caller — a requested close, which has to
/// know when there is nothing left to flush so it can stop waiting early
/// — and it answers that question in the one unit that is worth waiting on.
///
/// # Why a byte gauge rather than a stream count
///
/// A session's live streams are already enumerated by
/// [`StreamRegistry`](crate::control::StreamRegistry), and waiting for that
/// to empty was the obvious alternative. It is the wrong signal twice over:
/// a stream with an empty queue keeps its registration until its source
/// FINs, so the wait would run to the deadline on a session that had
/// nothing to flush at all; and a stream that ends while its queue is full
/// drops its registration with the bytes still unwritten, so the wait would
/// finish claiming a drain that lost data.
///
/// # Two-valued, and the second value is the whole bound
///
/// [`Self::wait_idle`] is the wait. [`Self::begin_discarding`] is what
/// happens when the wait runs out: it puts every queue in the session into
/// a mode where [`PendingQueue::drain_ignoring_release_times`] writes
/// nothing at all.
///
/// That looks backwards next to the rest of this module, whose teardown rule is
/// *delivered late beats lost silently*. The difference is that an ordinary
/// teardown is not a deadline anybody set — the flush is the best remaining
/// chance those bytes have. A close that has already been given its drain
/// window and spent it is a deadline somebody set, and flushing past it makes
/// the outcome *unreportable*: a `write_all` into quinn returns `Ok` as soon as
/// the bytes are buffered and `Connection::close` discards that buffer, so the
/// bytes are neither confirmably delivered nor confirmably lost, and no count
/// of them adds up. Declining to write keeps the arithmetic exact — what the
/// peer received plus what
/// [`ImpairmentKind::QueuedBytesAtTeardown`](crate::event::ImpairmentKind::QueuedBytesAtTeardown)
/// names equals what was queued when the close was requested — which is the
/// property a gate can actually be written against.
#[derive(Debug)]
pub(crate) struct EgressGauge {
    /// Bytes queued across every live [`PendingQueue`] of this session.
    queued: AtomicUsize,
    /// Pulsed whenever `queued` reaches zero.
    idle: Notify,
    /// Whether teardown flushes are declined — see the type's own doc.
    discarding: AtomicBool,
}

impl EgressGauge {
    /// A gauge reading zero, flushing normally.
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            queued: AtomicUsize::new(0),
            idle: Notify::new(),
            discarding: AtomicBool::new(false),
        })
    }

    /// Bytes queued across the session at this instant.
    pub(crate) fn queued(&self) -> usize {
        self.queued.load(Ordering::Acquire)
    }

    /// Whether teardown flushes are being declined.
    pub(crate) fn is_discarding(&self) -> bool {
        self.discarding.load(Ordering::Acquire)
    }

    /// Decline every later teardown flush on this session.
    ///
    /// One-way: nothing turns it off again, because the only caller is a
    /// close whose drain window has expired and a session in that state is
    /// on its way down.
    pub(crate) fn begin_discarding(&self) {
        self.discarding.store(true, Ordering::Release);
    }

    /// Charge `bytes` to the session total.
    fn add(&self, bytes: usize) {
        if bytes > 0 {
            self.queued.fetch_add(bytes, Ordering::AcqRel);
        }
    }

    /// Credit `bytes` back, waking a waiter when the session reaches zero.
    fn sub(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        // `saturating` in effect: a queue never credits back more than it
        // charged, but an underflow here would wrap to a total that never
        // reaches zero and would turn every later close into a full-length
        // wait, so the arithmetic is written not to be able to.
        let before = self
            .queued
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| Some(n.saturating_sub(bytes)))
            .unwrap_or(0);
        if before.saturating_sub(bytes) == 0 {
            self.idle.notify_waiters();
        }
    }

    /// Wait for the session's queues to empty, for at most `timeout`.
    ///
    /// Answers the bytes still queued when it returns: `0` when everything
    /// drained, and the residue when the deadline won. That residue is the
    /// figure a caller acts on — it is what will be abandoned — and it is
    /// deliberately a byte count and not "did it time out", because the
    /// two differ: a queue that empties on the last poll before the
    /// deadline drained, and one that reports zero after the deadline
    /// drained too.
    ///
    /// The registration is armed **before** the count is re-read, so a
    /// queue that empties between the two is not a lost wakeup that costs
    /// the caller its whole timeout.
    pub(crate) async fn wait_idle(&self, timeout: Duration) -> usize {
        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);
        loop {
            if self.queued() == 0 {
                return 0;
            }
            let notified = self.idle.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.queued() == 0 {
                return 0;
            }
            tokio::select! {
                () = &mut notified => {}
                () = &mut deadline => return self.queued(),
            }
        }
    }
}

/// A per-stream FIFO of units waiting for their release times.
///
/// Live as a local variable in `pipe_data_framed` / `pipe_control_mutating`
/// for the lifetime of one stream direction.
#[derive(Debug)]
pub(crate) struct PendingQueue {
    q: VecDeque<Pending>,
    /// The wheel handle for `q.front()`. Invariant:
    /// `head_deadline.is_some() == !q.is_empty()`.
    head_deadline: Option<Deadline>,
    queued_bytes: usize,
    /// Bytes a teardown drain handed to the transport, which nothing can
    /// confirm ever left it. See [`Self::unconfirmed_bytes`].
    flushed_unconfirmed: usize,
    /// The session-wide byte gauge this queue reports into, or `None` for a
    /// queue built outside a session — every `#[cfg(test)]` queue in this
    /// module, which has no session to report to.
    ///
    /// Mirrored rather than derived: nothing can walk a session's queues,
    /// because each one is a local variable in the pipe function that owns
    /// its stream. Every write to `queued_bytes` goes through
    /// [`Self::charge`] or [`Self::credit`] so the mirror cannot drift from
    /// the value it mirrors.
    gauge: Option<Arc<EgressGauge>>,
    config: EgressConfig,
    counters: Arc<Recorder>,
    /// Report-once latch for [`Push::entered_backpressure`].
    backpressure_reported: bool,
    /// The shaping profile's per-stream depth, when this stream's session
    /// has one **and** its overflow policy is `Block`.
    ///
    /// `None` on every unshaped stream and under every non-blocking
    /// overflow: `DropTail` needs the read branch to stay enabled or
    /// nothing arrives to be dropped, and `ResetStream` is decided on the
    /// arriving unit. See [`Self::accepts_more`].
    shape_depth: Option<QueueDepth>,
    /// The session's shaper, on a shaped **data** stream and nowhere else.
    /// `None` on every unshaped stream and on both control pipes, which is what
    /// makes *the control pipes are never shaped* structural: a control queue
    /// has no scheduler to ask, so no control frame can reach a bucket even by
    /// accident.
    shaper: Option<Arc<Scheduler>>,
    /// Where a shaped release records what it did. Carried beside the
    /// scheduler rather than reached through it because the recorder is
    /// always constructed and the scheduler is not.
    shape_stats: Option<Arc<ShapeRecorder>>,
    /// The side this stream's traffic **arrived** on, for the per-leg and
    /// per-direction figures the recorder keeps.
    ///
    /// `Option`, and deliberately not a defaulted side: one recorder serves
    /// both legs of a session, so a queue that guessed would charge real
    /// bytes to the wrong side and the figure would still look plausible.
    /// `Some` exactly when `shape_stats` is — the same builder sets both —
    /// so every reader below takes them together.
    ///
    /// A side rather than a direction because the recorder needs the leg
    /// too, and this queue is the only thing that knows which stream it is
    /// serving. It stays the *arrival* side even for the release figures the
    /// proxy charges to the leg a unit leaves by: the turn-around belongs to
    /// the recorder, which is one place, rather than to every queue, which
    /// is one per stream.
    shape_side: Option<ProxySide>,
    /// `max_hold` for this stream's shaped units: the profile's, or the
    /// engine's when the profile inherits it.
    shape_hold: Duration,
    /// The class the pipe loop resolved for the unit it is currently
    /// handling. Read — not taken — by [`Self::push`], so every push made
    /// while one framed unit is being executed carries the same class, and
    /// the next unit overwrites it.
    unit_class: Class,
    /// The gate the head is parked on because a [`Discipline`] is holding
    /// its class back. Merged into [`Self::head_release`] so `wait_release`
    /// races it exactly as it races a `Hold`'s gate.
    ///
    /// [`Discipline`]: crate::shape::Discipline
    shape_gate: Option<Gate>,
    /// Whether the shaper is currently holding the head back.
    ///
    /// It decides which gate [`Self::head_release`] reports, and that is a
    /// **spin guard**, not bookkeeping. A `Hold` whose gate has been released
    /// makes its unit due (`Pending::is_due`) and the gate stays released
    /// forever; if the queue kept reporting it while the shaper was refusing
    /// the same unit, `wait_release` would resolve on every `select!`
    /// iteration and the pipe loop would spin hot until the bucket refilled.
    /// Measured before this field existed: a barrier-held object on a 0-bps
    /// class pinned a core for the whole five-second clamp and starved the
    /// test's own task alongside it.
    ///
    /// Once a unit is due, the only things that may wake its stream are the
    /// deadline the scheduler armed and the gate a discipline handed back.
    shape_parked: bool,
    /// The class this queue has declared demand for with the scheduler.
    /// Exactly one declaration is outstanding at a time, and [`Drop`] is what
    /// guarantees it is withdrawn.
    shape_demand: Option<Class>,
    /// Edge latch for `tokens_exhausted_episodes` — armed when a release is
    /// refused for want of tokens, re-armed when one is granted.
    tokens_dry: bool,
    /// The index the next `starved_behind_other_class` sweep starts from, so
    /// each queued unit is examined once over the queue's whole life rather
    /// than once per wake.
    starved_from: usize,
    /// What the last [`Self::pop_next_due`] wants reported, for a caller that
    /// has an `exec::Reporter` and an event sink. Taken, never accumulated:
    /// at most one unit is released per call.
    shape_report: Option<ShapeReport>,
}

/// What a shaped release wants the pipe loop to report.
///
/// The queue owns the decision and the caller owns the reporting: `egress`
/// has no `Reporter`, no `ProxyObserver` and no session id, and giving it
/// one would put the whole event surface behind a type whose job is a deque.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ShapeReport {
    /// A unit went out at its `max_hold` clamp rather than when its bucket
    /// would have allowed it. Report `Impairment{HoldClamped}`, whose
    /// cardinality is already *once per clamped unit*.
    Clamped {
        /// What the bucket asked for, or `None` when it named no instant at
        /// all — a zero rate, or a unit larger than `burst_bytes`, where the
        /// wait is genuinely unbounded.
        ///
        /// `None` rather than a sentinel duration: a finite figure here
        /// would be a fabrication, and the largest representable one renders
        /// as an eighteen-quintillion-second request that reads as an
        /// encoding fault rather than as "unbounded".
        requested: Option<Duration>,
        /// What was applied: the clamp.
        applied: Duration,
    },
    /// A unit outlived its clamp under `Expiry::ResetStream`, and the queue
    /// has replaced everything with the reset. Report exactly one
    /// `Shaped{Expired}`.
    Expired,
    /// The head could not be granted because its class's `burst_bytes` is
    /// smaller than the head itself, so that class's configured rate can
    /// never pace anything. Report `Impairment{ShapeBurstBelowUnit}`.
    ///
    /// The queue produces this on **every** refusal of such a unit and does
    /// not deduplicate: the burst is a property of the session's profile,
    /// not of this stream, so the report-once state belongs to the scheduler
    /// and the caller claims it there through
    /// `Scheduler::claim_burst_report`. A per-queue latch would report once
    /// per stream for a fault that is the same fault on every stream.
    ///
    /// Carries the class rather than its name so this type stays `Copy`;
    /// resolving a name here would allocate on a release path for an event
    /// that is emitted once.
    BurstBelowUnit {
        /// The class whose rate is not being applied.
        class: Class,
        /// Its bucket cap, as configured.
        burst_bytes: u64,
        /// The wire size of the unit the cap could not cover.
        unit_bytes: u64,
    },
}

impl PendingQueue {
    /// An empty queue. Allocates nothing until the first [`Self::push`].
    pub(crate) fn new(config: EgressConfig, counters: Arc<Recorder>) -> Self {
        Self {
            q: VecDeque::new(),
            head_deadline: None,
            queued_bytes: 0,
            flushed_unconfirmed: 0,
            gauge: None,
            shape_hold: config.max_hold,
            config,
            counters,
            backpressure_reported: false,
            shape_depth: None,
            shaper: None,
            shape_stats: None,
            shape_side: None,
            unit_class: Class::Unshapeable,
            shape_gate: None,
            shape_parked: false,
            shape_demand: None,
            tokens_dry: false,
            starved_from: 1,
            shape_report: None,
        }
    }

    /// Report this queue's depth into its session's [`EgressGauge`].
    ///
    /// A builder for the same reason [`Self::with_shape_depth`] is: the
    /// tests in this module build queues that belong to no session, and a
    /// required parameter would make each of them invent one.
    /// Installed by every pipe function, on every stream, shaped or not —
    /// unlike a scheduler, which only the framed data pipe installs. A gauge
    /// that only some queues reported into would answer *the session has
    /// nothing left to flush* while a control stream still held a deferred
    /// SUBSCRIBE_OK.
    pub(crate) fn with_gauge(mut self, gauge: Arc<EgressGauge>) -> Self {
        // A fresh queue is empty, so there is nothing to charge here. If
        // that ever stops being true this has to charge `queued_bytes`.
        debug_assert_eq!(self.queued_bytes, 0, "a queue takes its gauge before it takes bytes");
        self.gauge = Some(gauge);
        self
    }

    /// Add `bytes` to this queue's depth and to its session's gauge.
    fn charge(&mut self, bytes: usize) {
        self.queued_bytes = self.queued_bytes.saturating_add(bytes);
        if let Some(gauge) = &self.gauge {
            gauge.add(bytes);
        }
    }

    /// Take `bytes` off this queue's depth and off its session's gauge.
    fn credit(&mut self, bytes: usize) {
        let bytes = bytes.min(self.queued_bytes);
        self.queued_bytes -= bytes;
        if let Some(gauge) = &self.gauge {
            gauge.sub(bytes);
        }
    }

    /// Whether this queue's session has stopped flushing at teardown.
    ///
    /// `false` for a queue with no gauge, which is every queue built
    /// outside a session: nothing can have asked such a queue to stop.
    fn discarding(&self) -> bool {
        self.gauge.as_ref().is_some_and(|g| g.is_discarding())
    }

    /// Carry a shaping profile's per-stream depth into [`Self::accepts_more`].
    ///
    /// A builder rather than a fourth parameter on [`Self::new`], because
    /// every caller but one passes `None` and the shape of the exception is
    /// the point: exactly one construction site — the framed data pipe —
    /// has a profile to install, and the ~25 unit tests below construct
    /// queues that never had one.
    ///
    /// **Installed only under `Overflow::Block`**, which the caller
    /// decides; this type deliberately does not name `Overflow`. What it
    /// does is enforce a depth, and a depth that reaches it is one the
    /// session has already decided should stop reads.
    ///
    /// Plumbed *into* `accepts_more` rather than checked beside it because
    /// the once-per-stream backpressure latch is computed inside
    /// [`Self::push`] from `accepts_more()`: a stream full by
    /// `QueueConfig::depth_objects` but under
    /// [`EgressConfig::max_pending_bytes`] would otherwise never trip it,
    /// and `Impairment{EgressQueueFull}` would have no producer on a shaped
    /// stream at all.
    pub(crate) fn with_shape_depth(mut self, depth: Option<QueueDepth>) -> Self {
        self.shape_depth = depth;
        self
    }

    /// Install the session's shaper, making this a **paced** queue.
    /// A builder for the same reason [`Self::with_shape_depth`] is: exactly one
    /// construction site — the framed data pipe — has a shaper, and the ~25
    /// unit tests below build queues that never had one. Both control pipes and
    /// `pipe_data_passthrough` call [`Self::new`] and stop there, which is what
    /// makes *the control pipes are never shaped* a property of the type graph
    /// rather than of a review.
    ///
    /// What it changes, and only this: [`Self::pop_next_due`] asks
    /// `Scheduler::acquire` before it yields a shaped unit, and [`Self::push`]
    /// tags what it queues. Everything else — ordering, `due_at`, `Hold`
    /// gates, the two drains, `head_release`'s signature — is untouched.
    ///
    /// `side` travels with the recorder rather than beside it because the
    /// recorder is session-scoped and this queue is not: one `ShapeRecorder`
    /// is shared by the forwarding tasks of both legs, and the figures it
    /// keeps are per leg and per direction. Naming it here — at the one site
    /// that has both a profile and a stream — is what makes a downlink stall
    /// unattributable to the uplink.
    ///
    /// It is the side this stream's traffic **arrives** on, which is the
    /// only side a forwarding task is ever handed. What a release figure
    /// does with it — charge the leg the unit leaves by — is the recorder's
    /// business, not this queue's.
    pub(crate) fn with_shaper(
        mut self,
        shaper: Option<Arc<Scheduler>>,
        stats: Arc<ShapeRecorder>,
        side: ProxySide,
    ) -> Self {
        if let Some(shaper) = shaper {
            self.shape_hold = shaper.max_hold().unwrap_or(self.config.max_hold);
            self.shaper = Some(shaper);
            self.shape_stats = Some(stats);
            self.shape_side = Some(side);
        }
        self
    }

    /// Whether this queue paces what it holds.
    ///
    /// Read by `exec::Engine::queue_is_busy`, which is what routes a shaped
    /// stream's units *through* the queue instead of writing them inline: a
    /// unit written straight to the transport never reaches
    /// [`Self::pop_next_due`], so on a shaped stream the fast path is exactly
    /// the path that cannot be paced.
    pub(crate) fn is_shaped(&self) -> bool {
        self.shaper.is_some()
    }

    /// Name the class of the unit the pipe loop is about to queue.
    ///
    /// Set once per framed unit, immediately after classification, and read
    /// by every [`Self::push`] until the next unit overwrites it. That is why
    /// `exec` can queue a `Delay`'d object without ever naming a class: the
    /// tag is the loop's, the push is `exec`'s, and neither has to know about
    /// the other.
    ///
    /// A no-op on an unshaped queue, where nothing reads it.
    pub(crate) fn tag_unit(&mut self, class: Class) {
        self.unit_class = class;
    }

    /// Whatever the last [`Self::pop_next_due`] wants the caller to report.
    pub(crate) fn take_shape_report(&mut self) -> Option<ShapeReport> {
        self.shape_report.take()
    }

    /// Whether anything is waiting.
    pub(crate) fn is_empty(&self) -> bool {
        self.q.is_empty()
    }

    /// How many units are waiting.
    ///
    /// Read by this module's tests and by `exec.rs`'s, which assert
    /// `DeferredEffects::len() == PendingQueue::len()`, and on the data
    /// path by shaping admission, which needs the object count the
    /// arriving unit would be the `n + 1`-th of. The pipe loops themselves
    /// ask [`Self::accepts_more`] and [`Self::is_empty`].
    pub(crate) fn len(&self) -> usize {
        self.q.len()
    }

    /// Bytes the queue is holding, right now, still unwritten.
    ///
    /// Not the teardown report — see [`Self::unconfirmed_bytes`]. This is
    /// the live figure the byte budget and the tests are written against.
    pub(crate) fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }

    /// Bytes this queue cannot vouch for: everything a teardown drain
    /// handed to the transport, **plus** everything still queued.
    ///
    /// What `Impairment { QueuedBytesAtTeardown }` carries, and the reason
    /// it is not simply [`Self::queued_bytes`]. A cancelled session's pipe
    /// task races `run_with_transport`'s `client.close()` / `relay.close()`:
    /// [`Self::drain_ignoring_release_times`] can hand a 256 KiB
    /// object to quinn, have `write_all` return `Ok` because quinn buffered
    /// it, and have the connection torn down before a byte of it is on the
    /// wire. Reporting only the residue reports **zero** there, and the
    /// object is gone with no event at all — the one failure class this
    /// engine forbids outright: traffic is never silently gone.
    ///
    /// So a teardown flush counts as *unconfirmed*, not as delivered. The
    /// event says exactly this already: "they were flushed best-effort;
    /// `bytes` may not have reached the peer". A peer that did receive them
    /// gets a spurious impairment, which is the right side to err on: an
    /// over-report is a diagnosable nuisance, a silent loss is not.
    ///
    /// Zero on every path that is not a teardown, so a stream that drains
    /// at its release times reports nothing.
    pub(crate) fn unconfirmed_bytes(&self) -> usize {
        self.flushed_unconfirmed.saturating_add(self.queued_bytes)
    }

    /// The engine knobs this queue was built with.
    pub(crate) fn config(&self) -> &EgressConfig {
        &self.config
    }

    /// Whether the source may still be **read from**.
    ///
    /// `false` once the queue holds [`EgressConfig::max_pending_bytes`] or
    /// [`MAX_PENDING_UNITS`] units — the point at which `Delay` stops being
    /// a latency shift and becomes backpressure — **or** once it reaches a
    /// shaping profile's own depth, when one was installed by
    /// [`Self::with_shape_depth`]. A `bool`, deliberately: it is hoisted
    /// out of the `select!` and holds no borrow.
    ///
    /// **Read from, not observed.** This gates `recv.read`, which is the
    /// only call that consumes bytes and therefore the only one that grants
    /// the peer flow-control credit. It does *not* gate whether the pipe
    /// loop watches its source: `false` swaps the read for
    /// `RecvStream::received_reset`, so a peer's `RESET_STREAM` is mirrored
    /// at once however full this queue is. Gating the observation on this
    /// was the defect — a dry bucket under `Overflow::Block` held the read
    /// shut for `max_hold` (30 s by default) and the reset went unseen for
    /// the whole of it.
    ///
    /// Both terms are **per stream**, and both imply a non-empty deque, so
    /// `head_release()` stays `Some` and the release branch stays live. A
    /// shared cross-class budget must never reach this function: an empty
    /// own queue with a shared budget exhausted disables the read branch
    /// *and* the release branch, and the stream deadlocks until session
    /// teardown.
    pub(crate) fn accepts_more(&self) -> bool {
        let within_engine_budget =
            self.queued_bytes < self.config.max_pending_bytes && self.q.len() < MAX_PENDING_UNITS;
        let within_shape_depth = match self.shape_depth {
            Some(depth) => self.queued_bytes < depth.bytes && self.q.len() < depth.objects,
            None => true,
        };
        within_engine_budget && within_shape_depth
    }

    /// What the head is waiting for, as an owned clone — see [`Release`].
    ///
    /// **`&self`, and it debits nothing.** It reports the deadline the
    /// scheduler last computed and the gate it last parked on; the decision
    /// itself belongs to [`Self::pop_next_due`], which is `&mut self` and
    /// runs exactly once per released unit. This function is called once
    /// per `select!` iteration from a hoisted local, so a debit here would
    /// be charged per read-wake rather than per byte written.
    ///
    /// **The FIN drain *is* on `pop_next_due`'s path**, and this sentence
    /// used to deny it. [`drain_honouring_release_times`] —
    /// the read arm's `None` branch — loops `pop_next_due`, debits the
    /// bucket, and applies the clamp and the expiry, which is why it takes
    /// an `on_shape` callback and reports them. The control pipes really
    /// are exempt, but by *construction* rather than by call graph: they
    /// install no [`Scheduler`] at all, so
    /// `shaping_grants_head` short-circuits on `shaper: None` and no
    /// control frame can reach a bucket even by accident. The only drain
    /// that is genuinely off the seam is
    /// [`Self::drain_ignoring_release_times`], which pops the front
    /// directly and consults nothing.
    pub(crate) fn head_release(&self) -> Option<Release> {
        let head = self.q.front()?;
        debug_assert!(
            self.head_deadline.is_some(),
            "a non-empty queue always has an armed head deadline",
        );
        Some(Release {
            deadline: self.head_deadline.clone()?,
            // Exactly one of the two, never both, and the choice is the spin
            // guard `shape_parked` documents: while the shaper is holding a
            // unit the shaper's gate is the only one that can usefully wake
            // it, because the unit's own `Hold` gate has already fired and
            // would resolve `wait_release` on every iteration forever.
            gate: if self.shape_parked { self.shape_gate.clone() } else { head.gate.clone() },
        })
    }

    /// When the queue expects to have written the last unit in it, or
    /// `None` if it is empty.
    ///
    /// `None` rather than `Instant::now()`: the estimate exists only to say
    /// what a unit waits behind, and on an empty queue there is nothing
    /// ahead. Folding `now` in there would quietly shift every unit's
    /// reported release time forward to its push instant.
    fn tail_expected_at(&self) -> Option<Instant> {
        self.q.back().map(|u| u.expected_at)
    }

    /// Register the head with the release wheel.
    ///
    /// Armed at the head's **`due_at`**, never its `expected_at`: the head
    /// has nothing ahead of it, so its own deadline is when it may go, and
    /// arming on the estimate would re-introduce the successor stall the
    /// module doc describes (a unit clamped behind a `Hold` would sleep to
    /// that hold's ceiling even after it became the head).
    ///
    /// The **only** caller of [`release_timer::arm_at`] besides
    /// [`Self::push`]'s use of it through here. `arm_at` starts nothing when
    /// the head is already due, so a queue of undelayed units never
    /// constructs the wheel.
    fn arm_head(&mut self) {
        self.head_deadline = self.q.front().map(|u| release_timer::arm_at(u.due_at));
    }

    /// Re-arm the head at an instant the *scheduler* named, rather than at
    /// the head's own `due_at`.
    /// The head is due on its own account — that is how it reached the shaper —
    /// so re-arming at `due_at` would give an already-fired deadline and spin
    /// the release branch hot until the bucket refilled. This is what makes
    /// `head_release()` *the deadline the scheduler last computed*: it reads
    /// back exactly what was armed here.
    fn arm_head_at(&mut self, at: Instant) {
        self.head_deadline = Some(release_timer::arm_at(at));
    }

    /// Queue a unit behind everything already waiting.
    ///
    /// **`due_at` is not touched.** The unit keeps the deadline it was
    /// built with, because that deadline is its own: a `Delay`'s
    /// `arrived_at + by`, a `Hold`'s `max_hold` ceiling, or `now` for a
    /// unit queued purely for ordering. Wire order is held by the deque —
    /// [`Self::pop_next_due`] only ever considers the *front* — so nothing
    /// has to be added to a successor's deadline to keep it behind its
    /// predecessor, and adding something is exactly what stranded a stream
    /// behind a released `Hold` (module doc).
    /// What *is* computed here is [`Pending::expected_at`], the queue's
    /// estimate of when this unit will reach the wire: `max(due_at,
    /// tail.expected_at, now)` on a non-empty queue, and `due_at` on an empty
    /// one. It is what [`Push::release_at`] returns, so `Effect::Queued {
    /// release_at }` still says *no earlier than everything ahead of you*, and
    /// it is what [`Self::record_release`] measures lateness against, so a
    /// `Pass` queued behind a 300 ms `Delay` is not logged as a 300 ms release
    /// error.
    ///
    /// A unit that is due now on an *empty* queue should not be pushed at
    /// all — the pipe loop writes it inline in the read arm, which is
    /// today's code and today's cost.
    pub(crate) fn push(&mut self, mut unit: Pending) -> Push {
        if let Some(tail) = self.tail_expected_at() {
            unit.expected_at = unit.due_at.max(tail).max(Instant::now());
        }
        // Tagged here, not at the call site, so that every producer of a
        // queued unit — this file's own terminals, `exec`'s `Delay`/`Hold`
        // pushes, and the pipe loop's own header and passthrough bytes — is
        // charged to the class the loop resolved, without any of them naming
        // one. The clock read is behind the shaping test, so an unshaped push
        // costs exactly what it did before.
        if self.shaper.is_some() {
            unit.shape = Some(ShapeTag {
                class: self.unit_class,
                expires_at: Instant::now() + self.shape_hold,
                starved_noted: false,
            });
            self.note_unshapeable_seen(&unit);
        }
        let release_at = unit.expected_at;
        let becomes_head = self.q.is_empty();
        self.charge(unit.len());
        self.q.push_back(unit);
        self.counters.note_egress_item_queued();
        if becomes_head {
            self.arm_head();
        }
        self.sync_shape_demand();
        let entered_backpressure = !self.accepts_more() && !self.backpressure_reported;
        if entered_backpressure {
            self.backpressure_reported = true;
        }
        Push { release_at, entered_backpressure }
    }

    /// Pop the head if it is due at `now`, re-arming the new head.
    ///
    /// **The front and only the front.** That single fact is the whole
    /// ordering guarantee: a unit whose own deadline passed long ago is
    /// still not popped while anything is queued in front of it.
    ///
    /// Call it in a `while let` loop: `pop_next_due` yields one unit at a
    /// time and allocates nothing, where a `Vec`-returning `pop_due` would
    /// allocate on every release wake. Looping matters as much as it reads:
    /// one wake on a `Hold`'s gate has to drain the held unit *and* every
    /// unit behind it that is due on its own account, or releasing a gate
    /// resumes one object and strands the rest.
    ///
    /// # The release seam
    ///
    /// On a shaped queue — and only there — a unit that is due on its own
    /// account is then put to `Scheduler::acquire`, which debits its class's
    /// token bucket and applies the [`Discipline`]. This function is where
    /// that happens because it is `&mut self`, it is the sole ordering
    /// authority, and it is called **exactly once per released unit**;
    /// `head_release` is none of those things.
    ///
    /// A refusal is not an error and costs nothing: the head deadline is
    /// re-armed at whatever the scheduler named (clamped by the unit's own
    /// `max_hold`), the gate a discipline handed back is stored for
    /// `head_release`, and `None` is returned exactly as a not-yet-due head
    /// returns it. The caller's loop is unchanged.
    ///
    /// [`Discipline`]: crate::shape::Discipline
    pub(crate) fn pop_next_due(&mut self, now: Instant) -> Option<Pending> {
        if !self.q.front().is_some_and(|u| u.is_due(now)) {
            return None;
        }
        // A fresh decision every call: a gate stored by a previous refusal
        // says nothing about this one, and leaving it set would let
        // `head_release` hand out a gate nobody will release.
        self.shape_gate = None;
        self.shape_parked = false;
        if !self.shaping_grants_head(now) {
            return None;
        }
        let unit = self.q.pop_front()?;
        self.credit(unit.len());
        self.starved_from = self.starved_from.saturating_sub(1).max(1);
        self.note_delivered(&unit);
        self.arm_head();
        self.sync_shape_demand();
        Some(unit)
    }

    /// Whether the shaper lets the head go at `now`, arming whatever it must
    /// wait for when it does not.
    ///
    /// `true` on every unshaped queue and for every unit the shaper does not
    /// own — a terminal, an elided ordering slot, a header — so the only
    /// thing a bucket can ever hold back is bytes.
    fn shaping_grants_head(&mut self, now: Instant) -> bool {
        let Some(shaper) = self.shaper.clone() else {
            return true;
        };
        let Some(head) = self.q.front() else {
            return true;
        };
        let Some(tag) = head.shape else {
            return true;
        };
        // Terminals bypass the pacer. A queued reset or truncate is the end
        // of the stream, not media: gating it would make teardown ordering
        // depend on a token bucket, which is exactly what turns the
        // data-then-reset tests into coin flips.
        if matches!(head.item, Item::Terminal(_)) {
            return true;
        }
        let bytes = head.len() as u64;

        // The clamp comes first, and it is what makes starvation late rather
        // than lossy: a unit that has outlived `max_hold` is decided by
        // `Expiry`, never by a bucket that has already refused it.
        if now >= tag.expires_at {
            return self.expire_head(shaper.on_expiry());
        }

        match shaper.acquire(tag.class, bytes, now) {
            Acquire::Now => {
                self.tokens_dry = false;
                true
            }
            Acquire::Later(at) => {
                self.note_tokens_dry(tag.class);
                self.park_head(at.min(tag.expires_at), tag, None);
                false
            }
            // No refill instant exists, so the clamp *is* the deadline. Arming
            // a fabricated far-future instant instead would arm a timer that
            // never fires, and the stream would look identical to one that
            // had simply hung.
            Acquire::Never => {
                self.note_tokens_dry(tag.class);
                self.park_head(tag.expires_at, tag, None);
                false
            }
            // The clamp is the deadline here too — nothing about *time* makes
            // a unit larger than the whole bucket fit — but this refusal is a
            // mis-sized burst rather than a rate doing its job, and the two
            // are otherwise identical from outside: same clamp, same counter,
            // same `HoldClamped`. The report is the only thing that separates
            // them, so it is set here and deduplicated by the scheduler.
            Acquire::LargerThanBurst { burst_bytes, unit_bytes } => {
                self.note_tokens_dry(tag.class);
                self.shape_report =
                    Some(ShapeReport::BurstBelowUnit { class: tag.class, burst_bytes, unit_bytes });
                self.park_head(tag.expires_at, tag, None);
                false
            }
            Acquire::Starved(gate) => {
                self.park_head(tag.expires_at, tag, Some(gate));
                false
            }
        }
    }

    /// Charge one **episode** of this class's own bucket being dry, on the
    /// edge only.
    ///
    /// Shared by the three refusals that are the bucket's rather than a
    /// discipline's, so the edge latch cannot be re-armed on one of them and
    /// forgotten on another. Re-armed by a grant, in `shaping_grants_head`.
    fn note_tokens_dry(&mut self, class: Class) {
        if self.tokens_dry {
            return;
        }
        self.tokens_dry = true;
        if let Some(stats) = &self.shape_stats {
            stats.note_tokens_exhausted(class);
        }
    }

    /// Park the head until `at` — or until `gate` opens, when a discipline is
    /// what is holding it — and charge everything queued behind a unit of
    /// another class.
    fn park_head(&mut self, at: Instant, tag: ShapeTag, gate: Option<Gate>) {
        let by_discipline = gate.is_some();
        self.shape_gate = gate;
        self.shape_parked = true;
        self.arm_head_at(at);
        self.sync_shape_demand();
        if by_discipline {
            // The head itself waited on **another class**, not on its own
            // bucket. Same counter as a same-stream head of another class,
            // because to a scenario author they are one question — *was I held
            // up by my rate, or by somebody else?* — and the answer is the same
            // in both. What it is emphatically not is
            // `tokens_exhausted_episodes`: the bucket was never asked.
            self.note_head_starved();
        }
        self.note_starved_behind(tag.class);
    }

    /// Charge the head once against `starved_behind_other_class`.
    fn note_head_starved(&mut self) {
        let Some(stats) = self.shape_stats.clone() else { return };
        let Some(tag) = self.q.front_mut().and_then(|u| u.shape.as_mut()) else { return };
        if tag.starved_noted {
            return;
        }
        tag.starved_noted = true;
        stats.note_starved(tag.class);
    }

    /// Charge `starved_behind_other_class` for every queued unit that is
    /// waiting behind a unit of a *different* class.
    ///
    /// Once per unit over the queue's whole life, not once per wake: the
    /// sweep resumes from where the last one stopped and the cursor follows
    /// the front as units are popped, so the total work is linear in units
    /// queued rather than quadratic in wakes.
    ///
    /// Deliberately separate from `tokens_exhausted_episodes`. Head-gating
    /// makes configured shaping and head-of-line blocking look identical from
    /// outside, and this is the number that tells them apart.
    fn note_starved_behind(&mut self, head_class: Class) {
        let Some(stats) = self.shape_stats.clone() else { return };
        let len = self.q.len();
        for index in self.starved_from.max(1)..len {
            let Some(unit) = self.q.get_mut(index) else { continue };
            let Some(tag) = unit.shape.as_mut() else { continue };
            if tag.starved_noted || tag.class == head_class {
                continue;
            }
            tag.starved_noted = true;
            stats.note_starved(tag.class);
        }
        self.starved_from = len.max(1);
    }

    /// The head outlived its clamp. Deliver it, or abandon the stream.
    ///
    /// Returns whether the caller may pop the head. Under
    /// [`Expiry::Deliver`] it may — that is the whole of "clamps and
    /// delivers", and it is why `objects_expired` is zero by default.
    fn expire_head(&mut self, expiry: Expiry) -> bool {
        match expiry {
            Expiry::Deliver => {
                // What the bucket *would* have asked for is gone by now — the
                // deadline it named is in the past, or it named none — so the
                // report states the clamp that was applied and leaves the
                // request absent rather than inventing a figure for it.
                self.shape_report =
                    Some(ShapeReport::Clamped { requested: None, applied: self.shape_hold });
                true
            }
            Expiry::ResetStream { code } => {
                if let (Some(stats), Some(side)) = (&self.shape_stats, self.shape_side) {
                    stats.note_expired(side);
                    stats.note_stream_reset_by_shaping(side);
                }
                self.shape_report = Some(ShapeReport::Expired);
                // Everything queued is replaced by the reset: the stream is
                // being given up on, and writing part of it first would leave
                // the peer a prefix it cannot distinguish from a truncation.
                self.clear();
                self.q.push_back(Pending::terminal(Terminal::Reset { code }));
                self.arm_head();
                true
            }
        }
    }

    /// Account for a queued unit **no rule could see**: the left-hand side of
    /// the conservation identity, for bytes the classifier never met.
    /// A stream header, an oversized object's passthrough chunk and a bypassed
    /// stream's tail carry no `ObjectMeta`, so `note_object_seen` is never
    /// reached for them and `bytes_shaped` would not count them. They are still
    /// bytes the shaper handled — it queued them, it ordered them, and it wrote
    /// them — so leaving them out would make `bytes_shaped` mean "bytes a rule
    /// saw" while
    /// [`ShapeStats::bytes_shaped`](crate::shape::ShapeStats::bytes_shaped)
    /// promises *every byte it accounted for*, and the `unshapeable` row would
    /// have nothing to be the other half of.
    ///
    /// **Here and not at the call site**, which is what makes the identity
    /// structural: `push` is the one place an unshapeable unit enters, this
    /// reads the same `unit.len()` [`Self::note_delivered`] will charge when
    /// it leaves, and both are gated on the same `ShapeTag`. `session.rs`
    /// cannot get it wrong because `session.rs` is not asked — the object
    /// arm and the unshown arm share one `exec` entry point, and only the
    /// tag tells them apart.
    ///
    /// Zero-length units — an elided ordering slot, a queued reset — add
    /// nothing on either side.
    fn note_unshapeable_seen(&self, unit: &Pending) {
        if self.unit_class != Class::Unshapeable {
            return;
        }
        let (Some(stats), Some(side)) = (&self.shape_stats, self.shape_side) else {
            return;
        };
        let bytes = unit.len();
        if bytes > 0 {
            stats.note_unshapeable_seen(side, bytes as u64);
        }
    }

    /// Charge one released unit to its class.
    ///
    /// [`Class::Unshapeable`] is charged like any other row, and only
    /// because [`Self::note_unshapeable_seen`] now counts the same bytes
    /// into `bytes_shaped` on the way in: both terms move together or
    /// neither does, and this is the unit in which they moved.
    /// The consequence worth stating: unshapeable bytes are **not paced**.
    /// `shaping_grants_head` never asks a bucket about them — they carry no
    /// class a bucket is configured for — so an object too large for the framer
    /// to buffer bypasses every rate, and a class rate can be exceeded by
    /// exactly one oversized object. That is what "unshapeable" means; the row
    /// named for it is where the figure is reported, and it is deliberately a
    /// *separate* row from `default_class` so that *no rule claimed this unit*
    /// and "no rule could have" stay two answers.
    ///
    /// The row alone does not say *whose* rate went, which is the question an
    /// author with a 500 kbps video cap and a large initial segment is
    /// actually asking, so the pipe loop pairs it with
    /// `Impairment{ShapeUnpacedObject}` naming the class the stream's
    /// classified units are charged to.
    fn note_delivered(&self, unit: &Pending) {
        let (Some(stats), Some(side), Some(tag)) = (&self.shape_stats, self.shape_side, unit.shape)
        else {
            return;
        };
        let bytes = unit.len();
        if bytes > 0 {
            stats.note_delivered(side, tag.class, bytes as u64);
        }
    }

    /// Tell the scheduler which class this queue is holding an unreleased
    /// head of, if any.
    ///
    /// **Demand, not depth.** One declaration per queue, replaced whenever
    /// the head's class changes and withdrawn when the queue empties — which
    /// includes [`Self::clear`], the teardown drain, and [`Drop`]. A
    /// declaration that outlived its stream would starve a lower-priority
    /// class for the rest of the session, and the failure would look like a
    /// hang rather than like a leak.
    fn sync_shape_demand(&mut self) {
        let Some(shaper) = &self.shaper else { return };
        let want = self.q.front().and_then(|u| u.shape).map(|t| t.class);
        if want == self.shape_demand {
            return;
        }
        if let Some(old) = self.shape_demand.take() {
            shaper.withdraw_demand(old);
        }
        if let Some(new) = want {
            shaper.declare_demand(new);
            self.shape_demand = Some(new);
        }
    }

    /// Sample one deferred release's lateness onto the session counters.
    ///
    /// Call it **only** from the release branch, once per unit
    /// `pop_next_due` yields, before writing. Units written inline in the
    /// read arm are not releases and would dilute the distribution with
    /// zeros; drains ignore release times by design and recording their
    /// lateness would report teardown as a timing failure. Neither
    /// drain in this file calls it.
    /// Measured against [`Pending::expected_at`], not [`Pending::due_at`]: the
    /// question is *did the engine release when it said it would*, and what it
    /// said was `Effect::Queued { release_at }`. Sampling `due_at` instead
    /// would log the queueing delay of every unit behind a `Delay` as a timer
    /// error.
    ///
    /// `saturating_duration_since` because a unit released early — a
    /// `Hold`'s gate opening long before its ceiling, which is the normal
    /// case — is a zero, not a negative.
    pub(crate) fn record_release(&self, unit: &Pending, now: Instant) {
        self.counters.record_release(now.saturating_duration_since(unit.expected_at));
    }

    /// Forget everything queued. Used after a terminal fires — the
    /// destination is reset, so nothing behind it can be written.
    ///
    /// Dropping the [`Release`]s abandons their wheel slots, which the
    /// wheel prunes at their own instants or at a sweep, without waking
    /// anything.
    pub(crate) fn clear(&mut self) {
        self.q.clear();
        self.credit(self.queued_bytes);
        self.head_deadline = None;
        self.starved_from = 1;
        // The shaping gate goes with the units it was holding, and the
        // demand goes with the head that declared it: a queue that is being
        // emptied has nothing to send, and leaving the declaration standing
        // would starve a lower class for the rest of the session.
        self.shape_gate = None;
        self.shape_parked = false;
        self.sync_shape_demand();
    }

    /// Write everything queued **now**, in order, ignoring release times.
    ///
    /// The teardown path: delivered late beats lost silently. Best effort
    /// by construction — a write failure stops the drain and leaves the
    /// failing unit and everything behind it queued, so
    /// [`Self::queued_bytes`] reports exactly what did not reach the
    /// transport.
    ///
    /// Every byte it *does* hand over is added to
    /// [`Self::unconfirmed_bytes`], because a `write_all` that returns `Ok`
    /// into a connection another task is about to `close()` is not a
    /// delivery. That is the whole of the teardown-race loss: read
    /// [`Self::unconfirmed_bytes`] after this, never [`Self::queued_bytes`],
    /// on any path that runs because the session is going down.
    ///
    /// **Consults no bucket.** This is the teardown drain, and teardown
    /// bypasses the pacer entirely: it pops the front directly
    /// rather than through [`Self::pop_next_due`], so a token bucket can
    /// never gate a mirrored reset. That is what keeps the eleven
    /// data-then-teardown ordering tests independent of any configured rate.
    ///
    /// **And therefore reports no shaping, deliberately.** Every other
    /// release path takes a [`ShapeReport`] out of the queue and hands it to
    /// a reporter, because a clamp or an expiry that nothing says happened is
    /// indistinguishable from a profile that did nothing. This one is the
    /// exception, and it is an exception because it *applies* no shaping:
    /// [`Self::pop_next_due`] is the only producer of a `ShapeReport` and
    /// this function never calls it, so there is nothing to drain rather
    /// than something dropped. The slot is empty on entry as well — both
    /// callers that can reach it through a shaped queue
    /// ([`drain_honouring_release_times`]'s cancel arm and
    /// `release_due_units`) drain the report before the pop that produced it
    /// is written.
    ///
    /// **Known residue, stated rather than fixed:** popping the front
    /// directly also skips the `shape_parked` / `shape_gate` bookkeeping
    /// [`Self::pop_next_due`] maintains, so after this drain a
    /// [`Self::head_release`] would describe a park belonging to a unit that
    /// is gone. Nothing reads it — every caller returns immediately, the
    /// queue is empty or cleared, and `head_release` answers `None` on an
    /// empty deque — so there is no failure scenario here to fix. It is
    /// written down because "unreachable today" is a property of the
    /// callers, not of this function.
    pub(crate) async fn drain_ignoring_release_times<S: EgressSink>(
        &mut self,
        send: &mut S,
    ) -> DrainOutcome {
        // A close that was given a drain window and spent it has already
        // decided these bytes are not going out. Writing them anyway would move
        // them from *queued, and reported as abandoned* into *handed to a
        // connection that is closing*, which is the one state nothing
        // downstream can count: see [`EgressGauge`].
        if self.discarding() {
            return DrainOutcome::Discarded;
        }
        while let Some(unit) = self.q.front().cloned() {
            match write_unit(unit, send).await {
                Ok(Written::Terminated { forwarded, code }) => {
                    // Everything behind a terminal is discarded by design,
                    // not lost: the destination is reset. Only the prefix
                    // this unit actually handed over is unconfirmed.
                    self.flushed_unconfirmed = self.flushed_unconfirmed.saturating_add(forwarded);
                    self.clear();
                    return DrainOutcome::Terminated { forwarded, code };
                }
                Ok(written) => {
                    if let Written::Bytes(n) = written {
                        self.flushed_unconfirmed = self.flushed_unconfirmed.saturating_add(n);
                    }
                    let unit = self.q.pop_front().expect("front was just observed");
                    self.credit(unit.len());
                    self.starved_from = self.starved_from.saturating_sub(1).max(1);
                    // Charged to its class like any other release: a flush that
                    // `write_all` accepted is the only definition of *released
                    // to the destination stream* this side of the transport,
                    // and what it could not vouch for is separately reported as
                    // `QueuedBytesAtTeardown`.
                    self.note_delivered(&unit);
                    self.arm_head();
                    self.sync_shape_demand();
                }
                Err(_) => return DrainOutcome::WriteFailed,
            }
        }
        DrainOutcome::Complete
    }
}

/// Withdraw whatever demand this queue still holds.
///
/// `Drop` rather than a call on each teardown path, and for the same reason
/// `StreamGuard` is: a forwarding task can end in at least five different
/// ways, any hand-written list of them is only as complete as its reader,
/// and `Drop` additionally covers a `?` return, a panicking task, and
/// `JoinSet::shutdown` dropping the future wholesale. A leaked declaration
/// is not a loud failure — it is a *different* stream stalling to
/// `max_hold`, on a class the reader was not looking at.
impl Drop for PendingQueue {
    fn drop(&mut self) {
        if let (Some(shaper), Some(class)) = (&self.shaper, self.shape_demand.take()) {
            shaper.withdraw_demand(class);
        }
        // The session gauge counts bytes that are still *somewhere*, and a
        // queue going away takes its remainder with it. Without this a
        // stream torn down with a full queue would leave the session's
        // total permanently above zero, and every later close would spend
        // its whole drain window waiting for a queue that no longer exists.
        self.credit(self.queued_bytes);
    }
}

/// Write everything queued **at its release time**, racing cancellation.
///
/// The shape both release-honouring drains take — the FIN drain in the read
/// arm's `None` branch and the one a terminal runs before it resets. Both
/// sit inside `select!` arm bodies, which are not preemptible, so writing
/// either as a plain `while let` loop would let a `Hold` on a gate nobody
/// releases pin session teardown for up to [`EgressConfig::max_hold`] —
/// precisely the failure the deque was chosen over a writer task to avoid.
///
/// The inner `select!` is `biased` so cancellation wins deterministically
/// when both are ready. Unbiased, a cancelled session could keep picking
/// the release branch, find nothing due, and spin.
///
/// Release lateness is **not** sampled here: this drain honours release
/// times only until cancellation, and recording a teardown flush as a
/// timing sample would report teardown as a timing failure.
///
/// # Shaping **is** reported here
///
/// `on_shape` is called once per [`ShapeReport`] the drain's own
/// [`PendingQueue::pop_next_due`] produces, and it exists because this loop
/// is a full release seam and not a teardown flush: on a shaped queue every
/// pop below debits a token bucket and every clamp or expiry is decided
/// here. The FIN path — header, a few objects, FIN, the ordinary MoQT
/// subgroup shape — reaches the wire through *this* function and not
/// through `release_due_units`, so a drain that swallowed its reports would
/// apply the whole profile to the normal case and say nothing about it.
/// That is the silent no-op this signature exists to prevent, and the reason
/// the parameter is not optional: a caller cannot forget what it has to name.
///
/// Passing a no-op closure is correct only where no report can exist —
/// every `#[cfg(test)]` caller in this module builds an unshaped queue, and
/// an unshaped queue's `pop_next_due` never reaches a scheduler.
pub(crate) async fn drain_honouring_release_times<S, F>(
    pending: &mut PendingQueue,
    send: &mut S,
    cancel: &CancellationToken,
    mut on_shape: F,
) -> Result<DrainOutcome, EgressError>
where
    S: EgressSink,
    F: FnMut(ShapeReport),
{
    while let Some(release) = pending.head_release() {
        tokio::select! {
            biased;
            () = cancel.cancelled() => {
                return Ok(match pending.drain_ignoring_release_times(send).await {
                    DrainOutcome::Terminated { forwarded, code } => {
                        DrainOutcome::Terminated { forwarded, code }
                    }
                    _ => DrainOutcome::CancelledMidDrain,
                });
            }
            () = wait_release(Some(release), cancel) => {
                let now = Instant::now();
                while let Some(unit) = pending.pop_next_due(now) {
                    // Before the write, exactly as `release_due_units` does:
                    // a terminal write returns out of this loop, and an
                    // expiry's report belongs to the very unit whose write
                    // takes that return.
                    if let Some(report) = pending.take_shape_report() {
                        on_shape(report);
                    }
                    if let Written::Terminated { forwarded, code } = write_unit(unit, send).await? {
                        pending.clear();
                        return Ok(DrainOutcome::Terminated { forwarded, code });
                    }
                }
                // A refusal reports too. The clamp is decided inside
                // `shaping_grants_head`, which runs whether or not the head
                // is yielded, so reading the report only after a successful
                // pop would lose the one case that matters.
                if let Some(report) = pending.take_shape_report() {
                    on_shape(report);
                }
            }
        }
    }
    Ok(DrainOutcome::Complete)
}

// ── Session close ───────────────────────────────────────────────────

/// The default `(code, reason)` `run_with_transport` closes with when no
/// hook asked for anything else — today's hard-coded pair.
const DEFAULT_CLOSE: (u32, &[u8]) = (0, b"proxy session ended");

/// Where [`crate::action::Action::CloseSession`] lands.
///
/// A `OnceLock<(u32, Bytes)>` plus the session's `CancellationToken`, and
/// deliberately **no `Transport` handles**: the transports own the tasks
/// that own the hooks that reach this, so holding them here would close a
/// reference cycle. The close itself happens where it already happens, in
/// `run_with_transport`, which reads [`Self::close_args`] instead of
/// hard-coding `(0, b"proxy session ended")`.
///
/// `CloseSession` is honoured at **every** site that returns an `Action`,
/// including `Site::StreamEnd` on both data and control streams: a close is
/// session-scoped, so no site can be the wrong one for it.
#[derive(Clone, Debug)]
pub(crate) struct SessionCloser {
    inner: Arc<CloserInner>,
}

#[derive(Debug)]
struct CloserInner {
    request: OnceLock<(u32, Bytes, CloseOrigin)>,
    cancel: CancellationToken,
}

/// Who asked for a session close.
///
/// Carried alongside the code and the reason because
/// [`ProxyEvent::SessionEnded`](crate::event::ProxyEvent::SessionEnded)
/// names the cause in prose, and the two callers are not interchangeable to
/// anyone reading that: a hook's `Action::CloseSession` is the scenario
/// under test deciding something, while
/// [`ProxyControl::close_session`](crate::control::ProxyControl::close_session)
/// is the operator outside it pulling the plug. The recorded pair alone
/// cannot tell them apart — both arrive as a `u32` and some bytes — and
/// before this every control-plane close was reported to observers as a
/// hook's, which is a sentence about the run that was simply untrue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CloseOrigin {
    /// A hook returned [`crate::action::Action::CloseSession`].
    Hook,
    /// [`ProxyControl::close_session`](crate::control::ProxyControl::close_session).
    ControlPlane,
}

impl SessionCloser {
    /// A closer bound to the session's cancellation token.
    pub(crate) fn new(cancel: CancellationToken) -> Self {
        Self { inner: Arc::new(CloserInner { request: OnceLock::new(), cancel }) }
    }

    /// Record a close request and cancel the session.
    ///
    /// The first request wins and returns `true`. A later one changes
    /// nothing and returns `false` — refuse it with
    /// [`Refusal::SessionAlreadyClosing`](crate::capability::Refusal::SessionAlreadyClosing)
    /// rather than letting the second reason overwrite the first.
    pub(crate) fn request(&self, code: u32, reason: Bytes) -> bool {
        let won = self.inner.request.set((code, reason, CloseOrigin::Hook)).is_ok();
        // Cancel unconditionally: a losing request still arrived after a
        // winning one, so the session is already on its way down and this
        // is idempotent.
        self.inner.cancel.cancel();
        won
    }

    /// Record a close request **without** cancelling the session.
    ///
    /// The first request wins and returns `true`, exactly as
    /// [`Self::request`] does; the only difference is that the session
    /// keeps running afterwards.
    ///
    /// That difference is the whole reason this exists. A control-plane
    /// close has two steps — fix the code and reason, then give the egress
    /// queues a bounded window to flush — and [`Self::request`] cannot
    /// express the first without the second, because it cancels as it
    /// records. A caller that used it would end the session before the
    /// drain it just asked for had begun, and the drain window would be
    /// unobservable.
    ///
    /// Nothing else changes: `run_with_transport` still reads
    /// [`Self::close_args`] at teardown, so a session recorded this way
    /// closes with the recorded pair whenever it does close — whether that
    /// is the caller cancelling after its drain, or the peer going away
    /// first.
    pub(crate) fn record(&self, code: u32, reason: Bytes) -> bool {
        self.inner.request.set((code, reason, CloseOrigin::ControlPlane)).is_ok()
    }

    /// Whether a close has been requested.
    ///
    /// `session.rs` reads [`Self::requested`] instead, because it wants the
    /// code and the reason as well; this stays as the cheap yes-or-no
    /// predicate for callers that need nothing more.
    #[allow(dead_code)]
    pub(crate) fn is_closing(&self) -> bool {
        self.inner.request.get().is_some()
    }

    /// What was requested and by whom, if anything.
    ///
    /// The origin rides along rather than being a second accessor because
    /// the two are set together, under one `OnceLock`, and a caller that
    /// read them in two calls would be writing a race it does not have.
    pub(crate) fn requested(&self) -> Option<(u32, Bytes, CloseOrigin)> {
        self.inner.request.get().cloned()
    }

    /// The `(code, reason)` to hand `Transport::close`, falling back to the
    /// pair the proxy has always used.
    /// The origin is deliberately dropped here: it is a fact about this
    /// process, and what goes on the wire is what the peer was told. A
    /// `CONNECTION_CLOSE` carrying *the control plane asked* would be this
    /// proxy leaking its own topology into somebody else's session.
    pub(crate) fn close_args(&self) -> (u32, Bytes) {
        self.inner
            .request
            .get()
            .map(|(code, reason, _)| (*code, reason.clone()))
            .unwrap_or_else(|| (DEFAULT_CLOSE.0, Bytes::from_static(DEFAULT_CLOSE.1)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An [`EgressSink`] that records instead of sending.
    #[derive(Debug, Default)]
    struct RecordingSink {
        writes: Vec<Bytes>,
        reset_code: Option<u64>,
        /// Fail every write once this many have succeeded.
        fail_after: Option<usize>,
    }

    impl RecordingSink {
        fn written(&self) -> Bytes {
            let mut out = Vec::new();
            for w in &self.writes {
                out.extend_from_slice(w);
            }
            Bytes::from(out)
        }
    }

    impl EgressSink for RecordingSink {
        fn write_all(
            &mut self,
            buf: &[u8],
        ) -> impl Future<Output = Result<(), EgressError>> + Send {
            let out = if self.fail_after.is_some_and(|n| self.writes.len() >= n) {
                Err(EgressError::Transport(TransportError::Write(
                    "recording sink is full".to_owned(),
                )))
            } else {
                self.writes.push(Bytes::copy_from_slice(buf));
                Ok(())
            };
            async move { out }
        }

        fn reset(&mut self, code: u64) -> Result<(), EgressError> {
            self.reset_code = Some(code);
            Ok(())
        }
    }

    /// The `on_shape` every drain in this module passes.
    ///
    /// Sound only because every queue built here is **unshaped** — `queue()`
    /// and `queue_with()` call `PendingQueue::new` and never
    /// `with_shaper`, and `pop_next_due` reaches no scheduler without one —
    /// so no `ShapeReport` can exist to swallow. A `unreachable!` rather than
    /// an empty body, so a later edit that installs a shaper here finds out
    /// instead of inheriting that silent no-op a second time.
    fn no_shape_reports(report: ShapeReport) {
        unreachable!("an unshaped queue produces no shaping report, got {report:?}");
    }

    fn queue() -> (PendingQueue, Arc<Recorder>) {
        let counters = Arc::new(Recorder::new());
        (PendingQueue::new(EgressConfig::default(), Arc::clone(&counters)), counters)
    }

    fn queue_with(config: EgressConfig) -> (PendingQueue, Arc<Recorder>) {
        let counters = Arc::new(Recorder::new());
        (PendingQueue::new(config, Arc::clone(&counters)), counters)
    }

    // ── shaped queues ───────────────────────────────────────────────
    //
    // Every queue above is unshaped, which is deliberate: the ~25 tests in
    // this module encode invariants that must hold whether or not a profile
    // is configured, and a shaper installed on all of them would stop being
    // separable from them. The handful below install one.

    use crate::shape::{
        BucketConfig, ClassRule, DirectionStats, Discipline, Expiry, Matcher, Overflow,
        QueueConfig, ShapeProfile, ShapeRecorder,
    };

    /// One named bucket. Struct literals rather than field assignment:
    /// `#[non_exhaustive]` does not apply inside the defining crate, and
    /// `..Default::default()` is what clippy's `field_reassign_with_default`
    /// asks for.
    fn test_bucket(rate: Option<u64>, burst: u64) -> BucketConfig {
        BucketConfig {
            name: "b".to_string(),
            rate_bps: rate,
            burst_bytes: burst,
            ..BucketConfig::default()
        }
    }

    /// One class over bucket `b`, claiming every unit.
    fn test_class(name: &str, priority: u8) -> ClassRule {
        ClassRule {
            name: name.to_string(),
            bucket: "b".to_string(),
            matcher: Matcher::default(),
            priority,
            weight: 1,
        }
    }

    /// A one-class profile over one bucket, with everything a shaped queue
    /// reads spelled out.
    fn profile(rate: Option<u64>, burst: u64, max_hold: Duration, expiry: Expiry) -> ShapeProfile {
        let queue = QueueConfig {
            max_hold: Some(max_hold),
            overflow: Overflow::Block,
            on_expiry: expiry,
            ..QueueConfig::default()
        };
        ShapeProfile::try_new(
            vec![test_bucket(rate, burst)],
            vec![test_class("only", 0)],
            queue,
            Discipline::Fifo,
        )
        .expect("the fixture names its own bucket")
    }

    /// A queue paced by `profile`, plus the recorder it writes to.
    ///
    /// One leg, because one leg is all these tests are about; the leg the
    /// totals actually land on is
    /// [`two_legs_sharing_one_recorder_charge_their_own_side`].
    fn shaped(profile: ShapeProfile) -> (PendingQueue, Arc<ShapeRecorder>, Arc<Scheduler>) {
        let counters = Arc::new(Recorder::new());
        let stats = Arc::new(ShapeRecorder::for_profile(Some(&profile)));
        let shaper = Arc::new(Scheduler::new(profile));
        let mut q = PendingQueue::new(EgressConfig::default(), counters).with_shaper(
            Some(Arc::clone(&shaper)),
            Arc::clone(&stats),
            ProxySide::ClientToProxy,
        );
        q.tag_unit(Class::Rule(0));
        (q, stats, shaper)
    }

    fn payload(n: usize) -> Bytes {
        Bytes::from(vec![0xAB; n])
    }

    /// The seam. A shaped head that is due on its own account is still held
    /// back by its bucket, and the deadline `head_release` then reports is
    /// the one the **scheduler** computed — not the head's own `due_at`,
    /// which is already in the past.
    ///
    /// That last clause is the whole reason `arm_head_at` exists: re-arming
    /// at `due_at` would hand back an already-fired deadline and spin the
    /// release branch hot until the bucket refilled.
    ///
    /// *Ablation:* delete the `shaping_grants_head` call from
    /// `pop_next_due` — the first `is_none` assertion reddens with the unit
    /// popped, which is a configured rate that paces nothing.
    #[test]
    fn a_shaped_head_waits_for_its_bucket_and_reports_the_scheduler_s_deadline() {
        // 1000 bytes/s, 1000-byte burst: the first 1000-byte unit fits and
        // the second needs a full second.
        let (mut q, _stats, _s) =
            shaped(profile(Some(1_000), 1_000, Duration::from_secs(60), Expiry::Deliver));
        let now = Instant::now();
        q.push(Pending::bytes(payload(1_000), now));
        q.push(Pending::bytes(payload(1_000), now));

        assert!(q.pop_next_due(now).is_some(), "the burst covers the first unit");
        assert!(
            q.pop_next_due(now).is_none(),
            "the burst is spent, so the second unit waits on a refill"
        );
        // The head is due on its own account — it was pushed at `now` — so a
        // deadline that had not been re-armed would already have fired.
        let release = q.head_release().expect("a non-empty queue always has one");
        assert!(
            !release.deadline().token().is_cancelled(),
            "the head must be armed at the refill instant, not at its own past due_at"
        );
        assert!(
            q.pop_next_due(now + Duration::from_secs(1)).is_some(),
            "a second's refill covers it"
        );
        assert!(q.is_empty());
    }

    /// The spin guard, and it is a **measured** defect rather than a
    /// hypothetical one.
    ///
    /// A `Hold` whose gate has been released makes its unit due, and the gate
    /// stays released forever. If the queue kept reporting that gate while
    /// the shaper was refusing the same unit, `wait_release` would resolve on
    /// every `select!` iteration and the pipe loop would spin hot for the
    /// whole of `max_hold`. Measured before `shape_parked` existed: a
    /// barrier-held object on a 0-bps class pinned a core for five seconds
    /// and starved the test's own task alongside it, so
    /// `a_zero_rate_class_starves_and_the_other_flows` failed with the video
    /// stream *delivered at its clamp* rather than held.
    ///
    /// *Ablation:* restore `head.gate.clone().or_else(|| shape_gate)` in
    /// `head_release` — the `is_released` assertion reddens, and the
    /// integration gate above it goes from 30 ms to 5 s.
    #[test]
    fn a_shaper_holding_a_gated_unit_does_not_report_the_gate_that_freed_it() {
        let (mut q, _stats, _s) =
            shaped(profile(Some(0), 0, Duration::from_secs(60), Expiry::Deliver));
        let now = Instant::now();
        let gate = Gate::new();
        // A `Hold`'s shape: due at the ceiling, released early by its gate.
        q.push(Pending::bytes(payload(16), now + Duration::from_secs(30)).with_gate(gate.clone()));

        assert!(q.pop_next_due(now).is_none(), "an unreleased gate leaves it not due");
        assert!(
            q.head_release().expect("queued").gate.is_some_and(|g| !g.is_released()),
            "before the shaper has an opinion, the unit's own gate is what it waits on"
        );

        gate.release();
        assert!(q.pop_next_due(now).is_none(), "released and due, but the bucket refuses");
        let release = q.head_release().expect("still queued");
        assert!(
            !release.gate.is_some_and(|g| g.is_released()),
            "a released Hold gate must not be re-reported while the shaper holds the unit: \
             wait_release would resolve on every iteration and spin the pipe loop"
        );
    }

    /// An **unshaped** queue is untouched by any of this: no scheduler, no
    /// tag, no clock read beyond what it already did.
    ///
    /// The control for every test above it. Without this row a bug that
    /// paced everything unconditionally would still leave the shaped tests
    /// green.
    #[test]
    fn an_unshaped_queue_pops_a_due_head_with_no_shaper_at_all() {
        let (mut q, _c) = queue();
        assert!(!q.is_shaped());
        let now = Instant::now();
        q.push(Pending::bytes(payload(1_000_000), now));
        assert!(q.pop_next_due(now).is_some(), "an unshaped queue has nothing to ask");
    }

    /// A queued terminal bypasses the pacer, on a bucket that grants nothing
    /// at all.
    ///
    /// This is the teardown-bypasses-the-pacer rule at the one place it is
    /// not obvious: a `Truncate` or a hook's `ResetStream` is a *queued*
    /// unit, so it reaches `pop_next_due` like any other. Gating it would
    /// make the eleven data-then-teardown ordering tests depend on a token
    /// bucket.
    ///
    /// # Why the `Truncate` arm is the one that matters
    ///
    /// Found by the ablation, not by reading. A bare `Terminal::Reset`
    /// carries **zero bytes**, and a zero-byte charge is granted by any
    /// bucket — `tokens >= 0` holds even at rate zero — so a `Reset`-only
    /// fixture passes with the guard deleted and proves nothing. A
    /// `Truncate` owes its prefix to the wire, and that prefix is exactly
    /// what a dry bucket would sit on. Both are asserted, in that order, so
    /// the row says which of the two the guard is for.
    /// *Ablation, recorded:* remove the `Item::Terminal` early return from
    /// `shaping_grants_head`. The `Reset` still pops; the `Truncate` is held to
    /// `max_hold` and its `expect` reddens with *a truncate owes its prefix to
    /// the wire, not to a bucket*.
    #[test]
    fn a_terminal_is_never_gated_by_a_bucket() {
        let (mut q, _stats, _s) =
            shaped(profile(Some(0), 0, Duration::from_secs(60), Expiry::Deliver));

        q.push(Pending::terminal(Terminal::Reset { code: 7 }));
        // `Pending::terminal` stamps its own `due_at` from the clock, so the
        // pop instant has to be taken after the push or the unit is simply
        // not due yet and this would pass without asking the shaper anything.
        let unit = q.pop_next_due(Instant::now()).expect("a reset consults no bucket");
        assert!(unit.is_terminal());

        q.push(Pending::terminal(Terminal::Truncate { prefix: payload(64), code: 9 }));
        let unit = q
            .pop_next_due(Instant::now())
            .expect("a truncate owes its prefix to the wire, not to a bucket");
        assert_eq!(unit.len(), 64, "and the prefix goes with it");
    }

    /// Under the default `Expiry::Deliver` a class that can never be
    /// granted from tokens **still delivers**, at `max_hold`, and says so.
    ///
    /// The two halves are one test because the report is what keeps the
    /// clamp from being a silent lateness, and the delivery is what keeps a
    /// starved class from being a silent loss.
    ///
    /// *Ablation:* make the `Expiry::Deliver` arm return `false` — the unit
    /// is never yielded, the `is_some` assertion reddens, and in a session
    /// that is a 0-bps class that hangs its stream instead of running late.
    ///
    /// The report is asserted as a **whole variant**, `requested` included,
    /// and not as `matches!(.., Clamped { applied, .. })`: a zero-rate
    /// bucket names no refill instant, so the request this clamp cut short
    /// is unbounded and the only honest value for it is absent. Written as
    /// a wildcard it passed against a `Duration::MAX` sentinel, which is
    /// what the field used to hold and what
    /// `an_unbounded_shaping_wait_reports_no_request_at_all` exists for.
    #[test]
    fn a_zero_rate_class_still_delivers_at_the_clamp_and_reports_it() {
        const HOLD: Duration = Duration::from_millis(80);
        let (mut q, stats, _s) = shaped(profile(Some(0), 0, HOLD, Expiry::Deliver));
        let now = Instant::now();
        q.push(Pending::bytes(payload(16), now));

        assert!(q.pop_next_due(now).is_none(), "a zero-rate bucket grants nothing");
        assert_eq!(
            stats.snapshot().classes[0].tokens_exhausted_episodes,
            1,
            "and says its own bucket was dry, once per episode"
        );
        assert_eq!(q.take_shape_report(), None, "nothing is clamped before the clamp");

        let unit = q
            .pop_next_due(now + HOLD + Duration::from_millis(1))
            .expect("Expiry::Deliver clamps and delivers");
        assert_eq!(unit.len(), 16);
        assert_eq!(
            q.take_shape_report(),
            Some(ShapeReport::Clamped { requested: None, applied: HOLD }),
            "a clamped release reports the clamp it applied, and reports the \
             request it cut short as absent because a zero-rate bucket named none"
        );
        assert_eq!(stats.snapshot().classes[0].bytes_delivered, 16);
        assert_eq!(stats.snapshot().objects_expired, 0, "Deliver never expires an object");
    }

    /// A shaping clamp reports **no request at all**, on both of the two
    /// ways a bucket can decline to name a refill instant.
    /// The two legs are the two refusals that name no instant: a rate of zero,
    /// and a unit larger than the burst the bucket can ever hold. Both are
    /// released by the clamp and by nothing else, and neither has a duration to
    /// quote — the wait was unbounded. Leg (b) additionally has a **positive**
    /// rate, so it rules out *the report is absent because the class is
    /// switched off*.
    ///
    /// Asserted as a whole-variant equality, which is the point: the field
    /// used to carry `Duration::MAX` here, and every inequality an author
    /// would naturally write against it — `requested > applied` — is
    /// satisfied by that sentinel exactly as it is by a real request.
    /// The **pre-clamp** report is asserted per leg for the same reason, and it
    /// is where the two legs stop looking alike: a zero-rate class is silent
    /// until its clamp fires, and a class whose burst cannot cover one of its
    /// own units says so at the first refusal. That asymmetry is the only thing
    /// separating *this rate is being applied and it is low* from *this rate is
    /// not being applied at all*, since both produce this same `Clamped`
    /// afterwards.
    ///
    /// *Ablation, run:* restore the sentinel in `expire_head`'s
    /// `Expiry::Deliver` arm, `requested: Some(Duration::MAX)`. Both legs
    /// redden with
    /// `left: Some(Clamped { requested: Some(18446744073709551615.999999999s), applied: 80ms })`
    /// against `right: Some(Clamped { requested: None, applied: 80ms })`.
    #[test]
    fn an_unbounded_shaping_wait_reports_no_request_at_all() {
        const HOLD: Duration = Duration::from_millis(80);
        /// Bigger than the burst leg (b) configures, so the bucket can never
        /// hold enough for it however long it accrues.
        const OVERSIZED: usize = 4_096;

        let legs = [
            ("a zero rate", profile(Some(0), 0, HOLD, Expiry::Deliver), 16, None),
            (
                "a unit above burst_bytes",
                profile(Some(64_000), 64, HOLD, Expiry::Deliver),
                OVERSIZED,
                Some(ShapeReport::BurstBelowUnit {
                    class: Class::Rule(0),
                    burst_bytes: 64,
                    unit_bytes: OVERSIZED as u64,
                }),
            ),
        ];

        for (label, profile, bytes, pre_clamp) in legs {
            let (mut q, _stats, _s) = shaped(profile);
            let now = Instant::now();
            q.push(Pending::bytes(payload(bytes), now));

            assert!(q.pop_next_due(now).is_none(), "{label}: nothing may be granted up front");
            assert_eq!(
                q.take_shape_report(),
                pre_clamp,
                "{label}: nothing is *clamped* before the clamp, and only the \
                 mis-sized burst says anything at all before it"
            );

            let unit = q
                .pop_next_due(now + HOLD + Duration::from_millis(1))
                .unwrap_or_else(|| panic!("{label}: Expiry::Deliver clamps and delivers"));
            assert_eq!(unit.len(), bytes, "{label}: the whole unit goes out");
            assert_eq!(
                q.take_shape_report(),
                Some(ShapeReport::Clamped { requested: None, applied: HOLD }),
                "{label}: the bucket named no instant, so there is no request to \
                 quote and the report must say so rather than name a sentinel"
            );
        }
    }

    /// `Expiry::ResetStream` abandons the whole destination stream: the
    /// queue is replaced by the reset, the object is counted as expired and
    /// the stream as reset by shaping.
    ///
    /// Everything queued goes with it, and that is deliberate — writing part
    /// of a stream the shaper has given up on leaves the peer a prefix it
    /// cannot tell from a truncation.
    /// *Ablation:* drop the `note_expired` call — the `objects_expired`
    /// assertion reddens while the reset still happens, which is exactly the
    /// *it worked but nothing says so* failure the counter exists for.
    #[test]
    fn expiry_reset_stream_replaces_the_queue_with_its_reset() {
        const HOLD: Duration = Duration::from_millis(50);
        let (mut q, stats, _s) =
            shaped(profile(Some(0), 0, HOLD, Expiry::ResetStream { code: 0x2A }));
        let now = Instant::now();
        q.push(Pending::bytes(payload(16), now));
        q.push(Pending::bytes(payload(16), now));

        let unit = q
            .pop_next_due(now + HOLD + Duration::from_millis(1))
            .expect("an expired head under ResetStream yields the reset");
        assert_eq!(unit.item(), &Item::Terminal(Terminal::Reset { code: 0x2A }));
        assert_eq!(q.take_shape_report(), Some(ShapeReport::Expired));
        assert!(q.is_empty(), "everything behind it went with the stream");

        let snap = stats.snapshot();
        assert_eq!(snap.objects_expired, 1);
        assert_eq!(snap.streams_reset_by_shaping, 1);
    }

    /// Two queues, one recorder, one leg each: what a queue charges lands on
    /// the leg it was built for.
    ///
    /// This is the seam between the split totals and the thing that knows
    /// which side a stream is on. The recorder is session-scoped and shared
    /// by every forwarding task, so it cannot work the direction out for
    /// itself; the queue is per stream direction and can. A recorder that
    /// could split but that nothing ever told which leg to charge would
    /// report one side doing all the work and the other doing none, which
    /// is indistinguishable from a session that really was one-way.
    ///
    /// The two legs are deliberately asymmetric in **opposite** senses —
    /// the uplink carries fewer bytes and takes the expiry, the downlink
    /// carries six times the bytes and expires nothing — so swapping the
    /// rows fails on every field rather than cancelling out.
    ///
    /// `objects_seen` is zero on both legs, and it is asserted rather than
    /// elided: it is charged where a unit is classified, which is the pipe
    /// loop's job and not this queue's, so a queue that started moving it
    /// would be counting the same object twice.
    ///
    /// *Ablation, recorded:* pass `ProxySide::ClientToProxy` for both queues — the
    /// uplink compare reddens with `left: DirectionStats { objects_seen: 0,
    /// bytes_shaped: 112, objects_expired: 1, streams_reset_by_shaping: 1,
    /// streams_with_mixed_classes: 0 }` against `right: DirectionStats { ..,
    /// bytes_shaped: 16, .. }`. Note what *does not* move: the aggregate is
    /// still 112 and the expiry is still counted once, so a one-legged
    /// recorder passes every figure a reader would have had before the
    /// split.
    #[test]
    fn two_legs_sharing_one_recorder_charge_their_own_side() {
        const HOLD: Duration = Duration::from_millis(50);
        // A bucket that grants nothing, so nothing leaves except through
        // the clamp, and the clamp is what the expiry arm decides.
        let p = profile(Some(0), 0, HOLD, Expiry::ResetStream { code: 0x2A });
        let counters = Arc::new(Recorder::new());
        let stats = Arc::new(ShapeRecorder::for_profile(Some(&p)));
        let shaper = Arc::new(Scheduler::new(p));

        let mut up = PendingQueue::new(EgressConfig::default(), Arc::clone(&counters)).with_shaper(
            Some(Arc::clone(&shaper)),
            Arc::clone(&stats),
            ProxySide::ClientToProxy,
        );
        let mut down = PendingQueue::new(EgressConfig::default(), counters).with_shaper(
            Some(shaper),
            Arc::clone(&stats),
            ProxySide::RelayToProxy,
        );

        let now = Instant::now();
        // Untagged, so these are the units no rule could see — the ones
        // charged to `bytes_shaped` as they are queued. Different sizes on
        // the two legs, so a leg that counted pushes rather than bytes is
        // separable from one that adds.
        up.push(Pending::bytes(payload(16), now));
        down.push(Pending::bytes(payload(48), now));
        down.push(Pending::bytes(payload(48), now));

        // The uplink head outlives its clamp and the stream is abandoned.
        assert!(
            up.pop_next_due(now + HOLD + Duration::from_millis(1)).is_some(),
            "an expired head under ResetStream yields the reset"
        );
        // The downlink's head is inside its clamp and goes out normally —
        // unshapeable bytes charge no bucket — so nothing on that leg
        // expires and nothing on it is reset.
        assert!(down.pop_next_due(now).is_some(), "the downlink head is not past its clamp");

        let snap = stats.snapshot();
        assert_eq!(
            snap.uplink,
            DirectionStats {
                objects_seen: 0,
                bytes_shaped: 16,
                objects_expired: 1,
                streams_reset_by_shaping: 1,
                streams_with_mixed_classes: 0,
            },
            "the uplink queue's bytes and its expiry are the uplink's"
        );
        assert_eq!(
            snap.downlink,
            DirectionStats {
                objects_seen: 0,
                bytes_shaped: 96,
                objects_expired: 0,
                streams_reset_by_shaping: 0,
                streams_with_mixed_classes: 0,
            },
            "the downlink queued more and gave nothing up: a stall on one leg \
             must not be reported on the other"
        );
        assert_eq!(snap.bytes_shaped, 112, "the aggregate is the two legs and nothing else");
        assert_eq!(snap.objects_expired, 1);
        assert_eq!(snap.streams_reset_by_shaping, 1);
    }

    /// A unit queued behind a unit of a **different** class is counted once,
    /// against its own class, and never against `tokens_exhausted_episodes`
    /// — which belongs to the class whose bucket was actually dry.
    ///
    /// Two causes of waiting, two counters. Conflating them is what makes
    /// head-of-line blocking read as configured shaping.
    ///
    /// *Ablation:* charge `note_starved` to the *head's* class instead of
    /// the waiting unit's — the two assertions swap and both redden.
    #[test]
    fn a_unit_behind_another_class_is_counted_once_and_separately() {
        // Two classes, one bucket that grants nothing, so the head parks.
        let queue =
            QueueConfig { max_hold: Some(Duration::from_secs(60)), ..QueueConfig::default() };
        let p = ShapeProfile::try_new(
            vec![test_bucket(Some(0), 0)],
            vec![test_class("head", 0), test_class("behind", 0)],
            queue,
            Discipline::Fifo,
        )
        .expect("two uniquely named classes over one bucket");

        let counters = Arc::new(Recorder::new());
        let stats = Arc::new(ShapeRecorder::for_profile(Some(&p)));
        let mut q = PendingQueue::new(EgressConfig::default(), counters).with_shaper(
            Some(Arc::new(Scheduler::new(p))),
            Arc::clone(&stats),
            ProxySide::ClientToProxy,
        );

        let now = Instant::now();
        q.tag_unit(Class::Rule(0));
        q.push(Pending::bytes(payload(16), now));
        q.tag_unit(Class::Rule(1));
        q.push(Pending::bytes(payload(16), now));
        q.push(Pending::bytes(payload(16), now));

        // Three refusals; the sweep must still charge each waiting unit once.
        for _ in 0..3 {
            assert!(q.pop_next_due(now).is_none());
        }
        let snap = stats.snapshot();
        assert_eq!(
            snap.classes[1].starved_behind_other_class, 2,
            "both units behind the other class's head are counted, once each"
        );
        assert_eq!(
            snap.classes[0].starved_behind_other_class, 0,
            "the head is not waiting behind anybody"
        );
        assert_eq!(
            snap.classes[0].tokens_exhausted_episodes, 1,
            "the dry bucket is the head's own, and it is one episode"
        );
    }

    /// The demand a queue declares is withdrawn when it is dropped.
    ///
    /// Not a nicety: a declaration that outlives its stream starves every
    /// lower-priority class for the rest of the session, and the symptom is
    /// a *different* stream stalling to `max_hold`.
    ///
    /// *Ablation:* delete the `Drop` impl — the final `is_none` assertion
    /// reddens with `Starved(..)`, on a stream that no longer exists.
    #[test]
    fn dropping_a_queue_withdraws_the_demand_it_declared() {
        let queue =
            QueueConfig { max_hold: Some(Duration::from_secs(60)), ..QueueConfig::default() };
        let p = ShapeProfile::try_new(
            vec![test_bucket(None, 0)],
            vec![test_class("hi", 9), test_class("lo", 0)],
            queue,
            Discipline::StrictPriority,
        )
        .expect("two uniquely named classes over one bucket");

        let counters = Arc::new(Recorder::new());
        let stats = Arc::new(ShapeRecorder::for_profile(Some(&p)));
        let shaper = Arc::new(Scheduler::new(p));

        let now = Instant::now();
        {
            let mut hi = PendingQueue::new(EgressConfig::default(), Arc::clone(&counters))
                .with_shaper(
                    Some(Arc::clone(&shaper)),
                    Arc::clone(&stats),
                    ProxySide::ClientToProxy,
                );
            hi.tag_unit(Class::Rule(0));
            // Due a minute out, so it stays queued and keeps declaring.
            hi.push(Pending::bytes(payload(16), now + Duration::from_secs(60)));
            assert!(
                matches!(shaper.acquire(Class::Rule(1), 16, now), Acquire::Starved(_)),
                "the high class is holding the bucket while its queue is alive"
            );
        }
        assert!(
            matches!(shaper.acquire(Class::Rule(1), 16, now), Acquire::Now),
            "the high class's stream is gone, so nothing is holding the low one back"
        );
    }

    #[test]
    fn an_empty_queue_waits_for_nothing_and_accepts_more() {
        let (q, _c) = queue();
        assert!(q.is_empty());
        assert_eq!(q.len(), 0);
        assert_eq!(q.queued_bytes(), 0);
        assert!(q.accepts_more());
        assert!(q.head_release().is_none());
    }

    #[test]
    fn a_later_unit_cannot_overtake_an_earlier_one() {
        let (mut q, _c) = queue();
        let now = Instant::now();
        let head =
            q.push(Pending::bytes(Bytes::from_static(b"0"), now + Duration::from_millis(300)));
        // A `Pass` — no delay at all — pushed behind it.
        let behind = q.push(Pending::bytes(Bytes::from_static(b"1"), now));
        assert_eq!(
            behind.release_at, head.release_at,
            "the reported release is the queue's estimate, and it accounts for the head",
        );
        // And a third with a smaller delay than the head's.
        let third =
            q.push(Pending::bytes(Bytes::from_static(b"2"), now + Duration::from_millis(10)));
        assert_eq!(third.release_at, head.release_at);
        assert_eq!(q.len(), 3);
        assert_eq!(q.queued_bytes(), 3);
    }

    /// The estimate is reporting; `due_at` is readiness. Conflating the two
    /// is what stranded whole streams behind a released `Hold`.
    ///
    /// *Ablation (run, and it fails):* in [`PendingQueue::push`], clamp
    /// `unit.due_at` the way `unit.expected_at` is clamped. Units 1 and 2
    /// then report the head's 300 ms deadline as their own.
    #[test]
    fn the_queues_estimate_never_rewrites_a_units_own_deadline() {
        let (mut q, _c) = queue();
        let now = Instant::now();
        q.push(Pending::bytes(Bytes::from_static(b"0"), now + Duration::from_millis(300)));
        q.push(Pending::bytes(Bytes::from_static(b"1"), now));
        q.push(Pending::bytes(Bytes::from_static(b"2"), now + Duration::from_millis(10)));

        // Popped at a time past everything, so the deque hands all three
        // back and each can be asked what it was actually built with.
        let far = now + Duration::from_secs(1);
        let units: Vec<Pending> = std::iter::from_fn(|| q.pop_next_due(far)).collect();
        assert_eq!(units.len(), 3);
        assert_eq!(units[0].due_at(), now + Duration::from_millis(300));
        assert_eq!(units[1].due_at(), now, "a `Pass` behind a delay keeps its own `now`");
        assert_eq!(units[2].due_at(), now + Duration::from_millis(10));
        // The estimate is the clamped one, on every unit.
        for unit in &units {
            assert_eq!(unit.expected_at(), units[0].due_at());
        }
    }

    #[test]
    fn pushing_bumps_the_egress_counter_once_per_unit() {
        let (mut q, counters) = queue();
        let now = Instant::now();
        for _ in 0..4 {
            q.push(Pending::bytes(Bytes::from_static(b"x"), now));
        }
        assert_eq!(counters.snapshot().egress_items_queued, 4);
    }

    #[test]
    fn a_unit_that_is_due_pops_and_one_that_is_not_does_not() {
        let (mut q, _c) = queue();
        let now = Instant::now();
        q.push(Pending::bytes(Bytes::from_static(b"soon"), now));
        q.push(Pending::bytes(Bytes::from_static(b"later"), now + Duration::from_secs(60)));
        let first = q.pop_next_due(now).expect("head is due");
        assert_eq!(first.len(), 4);
        assert!(q.pop_next_due(now).is_none(), "the tail is a minute out");
        assert_eq!(q.queued_bytes(), 5);
        assert!(q.head_release().is_some());
    }

    #[test]
    fn a_released_gate_makes_a_unit_due_before_its_ceiling() {
        let (mut q, _c) = queue();
        let now = Instant::now();
        let gate = Gate::new();
        // The `max_hold` ceiling: 30 s out.
        q.push(
            Pending::bytes(Bytes::from_static(b"held"), hold_ceiling(now, q.config()))
                .with_gate(gate.clone()),
        );
        assert!(q.pop_next_due(Instant::now()).is_none());
        gate.release();
        let unit = q
            .pop_next_due(Instant::now())
            .expect("a released gate is due, or the release arm spins until max_hold");
        assert_eq!(unit.len(), 4);
    }

    /// Releasing a gate frees the held unit **and the run behind it**.
    ///
    /// The head carries the gate; the three units behind it carry none, so
    /// the only thing that can make them due is their own deadline. They
    /// have one — `now` — and it is theirs, which is the whole point. When
    /// the queue stamped them with the hold's `max_hold` ceiling instead,
    /// one gate release wrote one object and stranded every object behind
    /// it, plus the stream's FIN, for 30 s.
    ///
    /// *Ablation (run, and it fails):* in [`PendingQueue::push`], write
    /// `unit.due_at = unit.due_at.max(tail).max(Instant::now())` alongside
    /// the `expected_at` line. Only the head pops, and `drained` is
    /// `[4]`.
    #[test]
    fn releasing_a_gate_frees_the_whole_run_queued_behind_it() {
        let (mut q, _c) = queue();
        let now = Instant::now();
        let gate = Gate::new();
        q.push(
            Pending::bytes(Bytes::from_static(b"held"), hold_ceiling(now, q.config()))
                .with_gate(gate.clone()),
        );
        // Three plain `Pass` units, decided after the hold, so they are
        // pushed for ordering and nothing else.
        for tail in [&b"1"[..], b"2", b"3"] {
            q.push(Pending::bytes(Bytes::copy_from_slice(tail), Instant::now()));
        }
        assert_eq!(q.len(), 4);
        assert!(q.pop_next_due(Instant::now()).is_none(), "the head holds the whole run");

        gate.release();
        let at = Instant::now();
        let drained: Vec<usize> =
            std::iter::from_fn(|| q.pop_next_due(at)).map(|u| u.len()).collect();
        assert_eq!(
            drained,
            vec![4, 1, 1, 1],
            "one wake on the gate must free the head *and* everything behind it, in order",
        );
        assert!(q.is_empty(), "nothing may be left for the max_hold ceiling to release");
        assert_eq!(q.queued_bytes(), 0);
    }

    /// A `Delay` queued behind a `Hold` keeps its **own** deadline.
    /// `Action::Delay` documents `arrived_at + by` — *a deadline, not a
    /// spacing* — and a `Hold` in front of it is not allowed to redefine that
    /// as the hold's ceiling. The unit is not due at the gate release, because
    /// its own 50 ms have not passed; it *is* due 50 ms later, rather than at
    /// the 20 s ceiling.
    ///
    /// *Ablation (run, and it fails):* in [`PendingQueue::push`], clamp
    /// `unit.due_at` as well as `unit.expected_at`. The second pop at
    /// `+60 ms` returns `None` and the unit waits out `max_hold`.
    #[test]
    fn a_delay_queued_behind_a_hold_keeps_its_own_deadline() {
        const CEILING: Duration = Duration::from_secs(20);
        const BY: Duration = Duration::from_millis(50);

        let config = EgressConfig { max_hold: CEILING, ..EgressConfig::default() };
        let (mut q, _c) = queue_with(config);
        let now = Instant::now();
        let gate = Gate::new();
        q.push(
            Pending::bytes(Bytes::from_static(b"held"), hold_ceiling(now, q.config()))
                .with_gate(gate.clone()),
        );
        let queued = q.push(Pending::bytes(Bytes::from_static(b"late"), now + BY));
        assert!(
            queued.release_at >= now + CEILING,
            "the *estimate* stays conservative — the queue cannot know when a gate opens",
        );

        gate.release();
        let head = q.pop_next_due(now + Duration::from_millis(10)).expect("a released gate is due");
        assert_eq!(head.len(), 4);
        assert!(
            q.pop_next_due(now + Duration::from_millis(10)).is_none(),
            "the delayed unit's own deadline still governs it: 10 ms is inside its {BY:?}",
        );
        let second = q
            .pop_next_due(now + BY + Duration::from_millis(10))
            .expect("arrived_at + by has passed, and that is the whole of the deadline");
        assert_eq!(second.len(), 4);
        assert_eq!(second.due_at(), now + BY, "its deadline was never rewritten");
    }

    #[test]
    fn the_byte_budget_stops_the_read_branch_and_reports_once() {
        // A struct literal is legal here and not in `tests/`: this file is
        // inside the defining crate, where `#[non_exhaustive]` does not
        // apply.
        let config = EgressConfig { max_pending_bytes: 8, ..EgressConfig::default() };
        let (mut q, _c) = queue_with(config);
        let now = Instant::now();
        let first = q.push(Pending::bytes(Bytes::from_static(b"1234"), now));
        assert!(!first.entered_backpressure);
        assert!(q.accepts_more());
        let second = q.push(Pending::bytes(Bytes::from_static(b"5678"), now));
        assert!(second.entered_backpressure, "the transition into backpressure is reported");
        assert!(!q.accepts_more());
        let third = q.push(Pending::bytes(Bytes::from_static(b"9"), now));
        assert!(!third.entered_backpressure, "once per stream, not once per push");
    }

    #[test]
    fn the_unit_cap_bounds_a_queue_of_zero_byte_units() {
        let (mut q, _c) = queue();
        let now = Instant::now();
        let mut reports = 0;
        for _ in 0..=MAX_PENDING_UNITS {
            if q.push(Pending::elided(now)).entered_backpressure {
                reports += 1;
            }
        }
        assert_eq!(q.queued_bytes(), 0, "elided units carry no bytes at all");
        assert!(!q.accepts_more(), "the byte budget alone would never stop this");
        assert_eq!(reports, 1);
    }

    #[tokio::test]
    async fn an_elided_unit_writes_nothing_but_keeps_its_slot() {
        let (mut q, _c) = queue();
        let now = Instant::now();
        q.push(Pending::bytes(Bytes::from_static(b"a"), now));
        q.push(Pending::elided(now));
        q.push(Pending::bytes(Bytes::from_static(b"c"), now));
        let mut sink = RecordingSink::default();
        assert_eq!(q.drain_ignoring_release_times(&mut sink).await, DrainOutcome::Complete);
        assert_eq!(sink.written(), Bytes::from_static(b"ac"));
        assert_eq!(sink.writes.len(), 2);
    }

    #[tokio::test]
    async fn a_truncate_terminal_writes_its_prefix_then_resets() {
        let (mut q, _c) = queue();
        let now = Instant::now();
        q.push(Pending::bytes(Bytes::from_static(b"ahead"), now));
        q.push(Pending::terminal(Terminal::Truncate {
            prefix: Bytes::from_static(b"pre"),
            code: 0x2,
        }));
        q.push(Pending::bytes(Bytes::from_static(b"never"), now));
        let mut sink = RecordingSink::default();
        let outcome = q.drain_ignoring_release_times(&mut sink).await;
        assert_eq!(outcome, DrainOutcome::Terminated { forwarded: 3, code: 0x2 });
        assert_eq!(sink.written(), Bytes::from_static(b"aheadpre"));
        assert_eq!(sink.reset_code, Some(0x2));
        assert!(q.is_empty(), "nothing behind a terminal is written");
        assert_eq!(q.queued_bytes(), 0);
    }

    #[tokio::test]
    async fn a_reset_terminal_writes_nothing() {
        let mut sink = RecordingSink::default();
        let written = write_unit(Pending::terminal(Terminal::Reset { code: 7 }), &mut sink)
            .await
            .expect("reset never fails the write");
        assert_eq!(written, Written::Terminated { forwarded: 0, code: 7 });
        assert!(sink.writes.is_empty());
        assert_eq!(sink.reset_code, Some(7));
    }

    #[tokio::test]
    async fn a_failed_drain_leaves_what_it_could_not_write_queued() {
        let (mut q, _c) = queue();
        let now = Instant::now();
        q.push(Pending::bytes(Bytes::from_static(b"aa"), now));
        q.push(Pending::bytes(Bytes::from_static(b"bbb"), now));
        q.push(Pending::bytes(Bytes::from_static(b"cccc"), now));
        let mut sink = RecordingSink { fail_after: Some(1), ..RecordingSink::default() };
        assert_eq!(q.drain_ignoring_release_times(&mut sink).await, DrainOutcome::WriteFailed);
        assert_eq!(sink.written(), Bytes::from_static(b"aa"));
        assert_eq!(q.len(), 2);
        // This is what `Impairment { QueuedBytesAtTeardown { bytes } }` carries.
        assert_eq!(q.queued_bytes(), 7);
    }

    #[tokio::test]
    async fn the_honouring_drain_writes_in_order_at_release_time() {
        let (mut q, counters) = queue();
        let now = Instant::now();
        q.push(Pending::bytes(Bytes::from_static(b"0"), now + Duration::from_millis(30)));
        q.push(Pending::bytes(Bytes::from_static(b"1"), now));
        q.push(Pending::bytes(Bytes::from_static(b"2"), now));
        let cancel = CancellationToken::new();
        let mut sink = RecordingSink::default();
        let started = Instant::now();
        let outcome = drain_honouring_release_times(&mut q, &mut sink, &cancel, no_shape_reports)
            .await
            .expect("no write failed");
        assert_eq!(outcome, DrainOutcome::Complete);
        assert!(started.elapsed() >= Duration::from_millis(30), "release times were honoured");
        assert_eq!(sink.written(), Bytes::from_static(b"012"));
        assert_eq!(counters.snapshot().release_errors.count, 0, "drains are never release samples");
        assert_eq!(
            q.unconfirmed_bytes(),
            0,
            "a drain that ran to completion at its release times is not a teardown and owes \
             no `QueuedBytesAtTeardown`",
        );
    }

    /// A teardown flush reports what it handed to a dying transport.
    ///
    /// The teardown-race loss, at queue level. `drain_ignoring_release_times`
    /// writes the held unit and `write_all` returns `Ok` — quinn buffered it —
    /// so **nothing is left queued**, and a report built on
    /// [`PendingQueue::queued_bytes`] says zero for exactly the case where
    /// `run_with_transport`'s `close()` then discards the buffer and the
    /// object never reaches the peer. `a_held_object_is_never_silently_lost_at_teardown`
    /// is the same claim over real QUIC; this is the mechanism, with no
    /// scheduler in it.
    ///
    /// *Ablation (run, and it fails):* make
    /// [`PendingQueue::unconfirmed_bytes`] return `self.queued_bytes`. It
    /// reports 0 and the last assertion goes red — which is precisely the
    /// silent loss, spelled out.
    #[tokio::test]
    async fn a_teardown_flush_reports_what_it_handed_to_a_dying_transport() {
        let (mut q, _c) = queue();
        // A hold nobody will release, so only the cancel fallback can move
        // it.
        q.push(
            Pending::bytes(Bytes::from_static(b"gone"), hold_ceiling(Instant::now(), q.config()))
                .with_gate(Gate::new()),
        );
        let cancel = CancellationToken::new();
        cancel.cancel();
        let mut sink = RecordingSink::default();

        let outcome = drain_honouring_release_times(&mut q, &mut sink, &cancel, no_shape_reports)
            .await
            .expect("the fallback drain swallows write failures");
        assert_eq!(outcome, DrainOutcome::CancelledMidDrain);
        assert_eq!(sink.written(), Bytes::from_static(b"gone"), "delivered late beats lost");
        assert_eq!(q.queued_bytes(), 0, "the fallback handed everything to the transport");
        assert_eq!(
            q.unconfirmed_bytes(),
            4,
            "…and handing bytes to a transport the session is closing is not delivering \
             them: this is what `QueuedBytesAtTeardown` has to carry, or the object is \
             gone with no event at all",
        );
    }

    #[tokio::test]
    async fn a_teardown_flush_that_could_not_write_reports_both_halves() {
        let (mut q, _c) = queue();
        let now = Instant::now();
        q.push(Pending::bytes(Bytes::from_static(b"aa"), now));
        q.push(Pending::bytes(Bytes::from_static(b"bbb"), now));
        q.push(Pending::bytes(Bytes::from_static(b"cccc"), now));
        let mut sink = RecordingSink { fail_after: Some(1), ..RecordingSink::default() };
        assert_eq!(q.drain_ignoring_release_times(&mut sink).await, DrainOutcome::WriteFailed);
        assert_eq!(q.queued_bytes(), 7, "what never reached the transport");
        assert_eq!(q.unconfirmed_bytes(), 9, "…plus the two bytes that did, and may be lost");
    }

    #[tokio::test]
    async fn cancelling_a_drain_that_is_waiting_on_a_gate_falls_back_at_once() {
        let (mut q, _c) = queue();
        let now = Instant::now();
        // A hold nobody will ever release, at the 30 s ceiling.
        q.push(
            Pending::bytes(Bytes::from_static(b"held"), hold_ceiling(now, q.config()))
                .with_gate(Gate::new()),
        );
        let cancel = CancellationToken::new();
        let waker = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            waker.cancel();
        });
        let mut sink = RecordingSink::default();
        let started = Instant::now();
        let outcome = drain_honouring_release_times(&mut q, &mut sink, &cancel, no_shape_reports)
            .await
            .expect("no write failed");
        assert_eq!(outcome, DrainOutcome::CancelledMidDrain);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "teardown must not wait out max_hold; took {:?}",
            started.elapsed(),
        );
        assert_eq!(
            sink.written(),
            Bytes::from_static(b"held"),
            "delivered late beats lost silently"
        );
        assert_eq!(q.queued_bytes(), 0);
    }

    #[tokio::test]
    async fn an_already_cancelled_drain_does_not_spin() {
        let (mut q, _c) = queue();
        q.push(Pending::bytes(Bytes::from_static(b"x"), Instant::now() + Duration::from_secs(60)));
        let cancel = CancellationToken::new();
        cancel.cancel();
        let mut sink = RecordingSink::default();
        let started = Instant::now();
        let outcome = drain_honouring_release_times(&mut q, &mut sink, &cancel, no_shape_reports)
            .await
            .unwrap();
        assert_eq!(outcome, DrainOutcome::CancelledMidDrain);
        assert!(started.elapsed() < Duration::from_secs(1), "the biased arm must win");
        assert_eq!(sink.written(), Bytes::from_static(b"x"));
    }

    #[tokio::test]
    async fn wait_release_resolves_on_the_gate_the_deadline_or_the_cancel() {
        let (mut q, _c) = queue();
        let far = Instant::now() + Duration::from_secs(60);

        // 1. The gate.
        let gate = Gate::new();
        q.push(Pending::bytes(Bytes::from_static(b"g"), far).with_gate(gate.clone()));
        gate.release();
        let cancel = CancellationToken::new();
        wait_release(q.head_release(), &cancel).await;

        // 2. The deadline.
        let (mut q, _c) = queue();
        q.push(Pending::bytes(
            Bytes::from_static(b"d"),
            Instant::now() + Duration::from_millis(20),
        ));
        let started = Instant::now();
        wait_release(q.head_release(), &cancel).await;
        assert!(started.elapsed() >= Duration::from_millis(20));

        // 3. The session cancel.
        let (mut q, _c) = queue();
        q.push(Pending::bytes(Bytes::from_static(b"c"), far));
        cancel.cancel();
        wait_release(q.head_release(), &cancel).await;

        // 4. `None` parks until cancellation rather than resolving at once.
        wait_release(None, &cancel).await;
    }

    #[tokio::test]
    async fn the_pipe_loop_shape_from_the_contract_compiles_and_keeps_order() {
        // The pipe loop's `select!`, with the read half standing in for
        // `recv.read` and a recording sink for `send`. What it proves is
        // the shape: both branch expressions are borrow-free, the read
        // guard and the release branch coexist, and a delayed head holds
        // everything behind it.
        let (mut pending, counters) = queue();
        let cancel = CancellationToken::new();
        let mut sink = RecordingSink::default();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(8);

        tokio::spawn(async move {
            for chunk in [&b"0"[..], b"1", b"2", b"3"] {
                tx.send(Bytes::from_static(chunk)).await.expect("receiver lives");
            }
            // Stay open past the head's release time, or the source FINs
            // first and the FIN drain — not the release branch — is what
            // writes everything.
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let mut first = true;
        loop {
            let can_read = pending.accepts_more();
            let head_release = pending.head_release();

            tokio::select! {
                chunk = rx.recv(), if can_read => {
                    match chunk {
                        Some(raw) => {
                            // Object 0 is delayed; 1.. are not, and must
                            // still not overtake it.
                            let release_at = if std::mem::take(&mut first) {
                                Instant::now() + Duration::from_millis(40)
                            } else {
                                Instant::now()
                            };
                            if pending.is_empty() && release_at <= Instant::now() {
                                // Today's fast path: written inline in the read arm.
                                write_unit(Pending::bytes(raw, release_at), &mut sink)
                                    .await
                                    .expect("recording sink");
                            } else {
                                pending.push(Pending::bytes(raw, release_at));
                            }
                        }
                        None => {
                            let outcome =
                                drain_honouring_release_times(&mut pending, &mut sink, &cancel, no_shape_reports)
                                    .await
                                    .expect("recording sink");
                            assert_eq!(outcome, DrainOutcome::Complete);
                            break;
                        }
                    }
                }
                () = wait_release(head_release.clone(), &cancel), if head_release.is_some() => {
                    let now = Instant::now();
                    while let Some(unit) = pending.pop_next_due(now) {
                        pending.record_release(&unit, now);
                        write_unit(unit, &mut sink).await.expect("recording sink");
                    }
                }
                () = cancel.cancelled() => unreachable!("nothing cancels this test"),
            }
        }

        assert_eq!(
            sink.written(),
            Bytes::from_static(b"0123"),
            "byte equality is the ordering assertion"
        );
        let snap = counters.snapshot();
        assert_eq!(snap.egress_items_queued, 4, "every unit went through the deque");
        assert_eq!(
            snap.release_errors.count, 4,
            "all four share the head's clamped release time, so one wake pops all four \
             — and only the release branch samples",
        );
    }

    #[test]
    fn defer_by_is_a_deadline_and_clamps_to_max_hold() {
        let config =
            EgressConfig { max_hold: Duration::from_millis(100), ..EgressConfig::default() };
        let now = Instant::now();

        let short = defer_by(now, Duration::from_millis(10), &config);
        assert_eq!(short.release_at, now + Duration::from_millis(10));
        assert!(!short.was_clamped());

        let long = defer_by(now, Duration::from_secs(5), &config);
        assert_eq!(long.release_at, now + Duration::from_millis(100));
        assert!(long.was_clamped());
        assert_eq!(long.requested, Duration::from_secs(5));
        assert_eq!(long.applied, Duration::from_millis(100));

        // Two units arriving together with the same `by` release together,
        // not at +by and +2by.
        let a = defer_by(now, Duration::from_millis(10), &config);
        let b = defer_by(now, Duration::from_millis(10), &config);
        assert_eq!(a.release_at, b.release_at);

        assert_eq!(hold_ceiling(now, &config), now + Duration::from_millis(100));
    }

    #[test]
    fn the_first_close_request_wins() {
        let cancel = CancellationToken::new();
        let closer = SessionCloser::new(cancel.clone());
        assert!(!closer.is_closing());
        assert_eq!(
            closer.close_args(),
            (0, Bytes::from_static(b"proxy session ended")),
            "the default is what run_with_transport has always sent",
        );

        assert!(closer.request(3, Bytes::from_static(b"protocol violation")));
        assert!(cancel.is_cancelled());
        assert!(closer.is_closing());
        assert!(!closer.request(1, Bytes::from_static(b"too late")));
        assert_eq!(closer.close_args(), (3, Bytes::from_static(b"protocol violation")));
        assert_eq!(
            closer.requested(),
            Some((3, Bytes::from_static(b"protocol violation"), CloseOrigin::Hook)),
            "a close that arrived through `request` is a hook's, and the session's own \
             `SessionEnded` reason says so in those words",
        );
    }

    #[test]
    fn an_undelayed_head_arms_a_deadline_that_never_touches_the_wheel() {
        // `arm_at` on an already-passed instant returns an
        // already-cancelled `Deadline` without constructing the wheel, so
        // a session that never delays never links it into executed code.
        //
        // Asserted on the deadline's own token rather than on
        // `release_timer::started()`: that is process-global state, and
        // another test in this binary may legitimately have started the
        // wheel on another thread between the two reads.
        let (mut q, _c) = queue();
        q.push(Pending::bytes(Bytes::from_static(b"now"), Instant::now()));
        let release = q.head_release().expect("one unit queued");
        assert!(
            release.deadline().token().is_cancelled(),
            "an already-due head must not be registered with the wheel",
        );

        let (mut q, _c) = queue();
        q.push(Pending::bytes(
            Bytes::from_static(b"later"),
            Instant::now() + Duration::from_secs(60),
        ));
        let release = q.head_release().expect("one unit queued");
        assert!(!release.deadline().token().is_cancelled(), "a future head is registered");
        assert!(release_timer::started(), "…and registering is what starts the wheel");
    }

    // ── The session-wide byte gauge ─────────────────────────────────

    /// A queue reporting into a gauge, plus the gauge.
    fn gauged() -> (PendingQueue, Arc<EgressGauge>) {
        let gauge = EgressGauge::new();
        let q = PendingQueue::new(EgressConfig::default(), Arc::new(Recorder::new()))
            .with_gauge(Arc::clone(&gauge));
        (q, gauge)
    }

    /// The gauge is the sum of what the queues hold, on every route bytes
    /// take out of one.
    ///
    /// It has to be exact in both directions or the one caller that reads
    /// it — a requested close deciding whether it may stop waiting —
    /// either stops early on bytes that are still queued, or waits out its
    /// whole window on bytes that left long ago.
    ///
    /// *Ablation, recorded:* drop the `self.credit(self.queued_bytes)` from
    /// `PendingQueue`'s `Drop`. The final assertion goes red with
    ///
    /// ```text
    /// assertion `left == right` failed: a queue that goes away takes its
    /// remainder with it, or every later close waits out its whole window
    ///   left: 4
    ///  right: 0
    /// ```
    ///
    /// — a session total permanently above zero, on a stream that no longer
    /// exists.
    #[tokio::test]
    async fn the_gauge_follows_every_route_bytes_leave_a_queue_by() {
        let (mut q, gauge) = gauged();
        let now = Instant::now();
        assert_eq!(gauge.queued(), 0);

        q.push(Pending::bytes(Bytes::from_static(b"aaa"), now));
        q.push(Pending::bytes(Bytes::from_static(b"bb"), now));
        assert_eq!(gauge.queued(), 5, "two pushes, five bytes");

        // Route one: released at its release time.
        q.pop_next_due(now).expect("both are due");
        assert_eq!(gauge.queued(), 2);

        // Route two: flushed by the teardown drain.
        let mut sink = RecordingSink::default();
        assert_eq!(q.drain_ignoring_release_times(&mut sink).await, DrainOutcome::Complete);
        assert_eq!(gauge.queued(), 0);

        // Route three: cleared wholesale, as a terminal or a shaping reset
        // does.
        q.push(Pending::bytes(Bytes::from_static(b"cccc"), now));
        assert_eq!(gauge.queued(), 4);
        q.clear();
        assert_eq!(gauge.queued(), 0);

        // Route four: the stream ends holding bytes.
        q.push(Pending::bytes(Bytes::from_static(b"dddd"), now));
        assert_eq!(gauge.queued(), 4);
        drop(q);
        assert_eq!(
            gauge.queued(),
            0,
            "a queue that goes away takes its remainder with it, or every later close waits out \
             its whole window"
        );
    }

    /// The wait ends when the queues empty, and answers zero.
    #[tokio::test]
    async fn the_drain_wait_ends_the_moment_the_queues_empty() {
        let (mut q, gauge) = gauged();
        let now = Instant::now();
        q.push(Pending::bytes(Bytes::from_static(b"payload"), now));

        // A generous window, so finishing quickly can only be the queue
        // emptying and not the deadline.
        let waiting = tokio::spawn({
            let gauge = Arc::clone(&gauge);
            async move { gauge.wait_idle(Duration::from_secs(30)).await }
        });

        tokio::task::yield_now().await;
        let mut sink = RecordingSink::default();
        assert_eq!(q.drain_ignoring_release_times(&mut sink).await, DrainOutcome::Complete);

        let stranded = tokio::time::timeout(Duration::from_secs(5), waiting)
            .await
            .expect("the wait must end on the queue emptying, not on its own deadline")
            .expect("the waiting task must not panic");
        assert_eq!(stranded, 0, "nothing was left, so nothing is abandoned");
    }

    /// The wait ends at its deadline holding the exact residue, and an
    /// expired window makes the teardown flush write nothing.
    ///
    /// The second half is what keeps the arithmetic closed. A flush at that
    /// point hands bytes to a connection that is about to discard its
    /// buffer, so they are neither confirmably delivered nor confirmably
    /// lost; declining to write leaves `unconfirmed_bytes` equal to what
    /// was abandoned, exactly.
    #[tokio::test]
    async fn an_expired_window_reports_the_residue_and_writes_nothing() {
        let (mut q, gauge) = gauged();
        let now = Instant::now();
        q.push(Pending::bytes(Bytes::from_static(b"held"), now + Duration::from_secs(60)));

        let stranded = gauge.wait_idle(Duration::from_millis(20)).await;
        assert_eq!(stranded, 4, "the window closed on four bytes that had not been released");

        gauge.begin_discarding();
        let mut sink = RecordingSink::default();
        assert_eq!(
            q.drain_ignoring_release_times(&mut sink).await,
            DrainOutcome::Discarded,
            "past the deadline the flush declines rather than best-efforts"
        );
        assert!(sink.writes.is_empty(), "nothing reached the transport");
        assert_eq!(
            q.unconfirmed_bytes(),
            4,
            "so the reported figure is what was abandoned, with nothing handed anywhere"
        );
        assert_eq!(
            q.queued_bytes(),
            q.unconfirmed_bytes(),
            "and the two agree, which is the point"
        );
    }

    /// A close recorded on the closer does **not** end the session.
    ///
    /// `request` cancels as it records, which is right for a hook: the hook
    /// asked for the session to end. A control-plane close has to fix the
    /// pair first and let the session keep running through its drain
    /// window, and it would have no window at all if recording cancelled.
    ///
    /// It also checks who the close is *reported as*.
    /// `run_with_transport` turns the recorded triple into the prose on
    /// [`ProxyEvent::SessionEnded`](crate::event::ProxyEvent::SessionEnded),
    /// and both callers reach the same `OnceLock`, so without an origin
    /// beside the pair every operator-initiated close was reported to
    /// observers as a hook's decision.
    ///
    /// *Ablation, recorded:* have `record` store `CloseOrigin::Hook` — the
    /// state the type was in before this field existed, where the two
    /// callers are indistinguishable once they have written. This test goes
    /// red with the real message
    ///
    /// ```text
    /// assertion `left == right` failed
    ///   left: Some((7, b"asked", Hook))
    ///  right: Some((7, b"asked", ControlPlane))
    /// ```
    #[test]
    fn recording_a_close_leaves_the_session_running() {
        let cancel = CancellationToken::new();
        let closer = SessionCloser::new(cancel.clone());

        assert!(closer.record(7, Bytes::from_static(b"asked")));
        assert!(!cancel.is_cancelled(), "the drain window has not even started yet");
        assert_eq!(closer.close_args(), (7, Bytes::from_static(b"asked")));

        // First writer wins here exactly as it does through `request`, so a
        // hook and a control plane racing cannot end up with a code from
        // one and a reason from the other.
        assert!(!closer.record(9, Bytes::from_static(b"second")));
        assert!(!closer.request(9, Bytes::from_static(b"second")));
        assert_eq!(closer.close_args(), (7, Bytes::from_static(b"asked")));
        assert!(cancel.is_cancelled(), "…and `request` still cancels, losing or not");

        // The losing `request` above is a hook's, and it lost. The origin
        // has to lose with it: a session whose close was recorded by the
        // control plane and then re-asked for by a hook must not report the
        // hook's name against the control plane's code and reason, which is
        // the mislabel this field exists to stop.
        assert_eq!(
            closer.requested(),
            Some((7, Bytes::from_static(b"asked"), CloseOrigin::ControlPlane)),
        );
    }
}

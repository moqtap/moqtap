//! The session-scoped shaper: classification, admission and release.
//!
//! [`Scheduler`] is the one object a shaped session's forwarding tasks
//! share. It owns the validated [`ShapeProfile`], the report-once state
//! that keeps a run from repeating itself, and the token buckets, and it
//! answers three questions per unit:
//!
//! 1. **Which class is this?** — [`Scheduler::classify`], the
//!    [`Matcher`](super::Matcher)
//!    over [`ObjectMeta`] plus the fall to [`Class::Default`], plus the
//!    `ShapeRuleUnmatchable` report that keeps that fall from being silent.
//! 2. **Does it fit?** — [`Scheduler::admit`], the per-stream queue depth
//!    and the [`Overflow`] policy.
//! 3. **May it go now?** — [`Scheduler::acquire`], the token bucket and the
//!    [`Discipline`] that arbitrates between classes
//!    sharing one.
//!
//! The first two are **pure functions of their arguments and the profile**:
//! neither reads a clock, touches a queue or writes a counter. The third
//! owns state — that is what a bucket *is* — but it still takes `now` as a
//! parameter and reads no clock, which is why the arithmetic under it stays
//! provable from a table. The statistics are the caller's to record, and the
//! reports are handed to a callback, so everything below is testable with no
//! QUIC, no runtime and no session.
//!
//! # Release is per class; the stream performs it
//!
//! [`Scheduler::acquire`] is the whole of the release decision, and it is
//! reachable from exactly one place: `PendingQueue::pop_next_due`, which is
//! `&mut self`, is the sole ordering authority, and is called exactly once
//! per released unit. It is deliberately **not** reachable from
//! `PendingQueue::head_release`, which is `&self`, fires once per `select!`
//! iteration rather than once per unit, and is also called by the two
//! teardown drains and by the control pipes.
//!
//! **The control pipes are never shaped.** `pipe_control_passthrough` and
//! `pipe_control_mutating` install no [`Scheduler`] on their queues at all,
//! so no control frame can reach a bucket even by accident. Pacing
//! SUBSCRIBE and ANNOUNCE behind a video bucket would stall MoQT's steady
//! state and make an idle control stream look like a dead session.
//!
//! # Why starvation is a gate and not a poll
//!
//! A class that a discipline refuses has no deadline to arm — nothing about
//! *time* will make it eligible, only the blocking class draining will. So
//! [`Acquire::Starved`] hands back a [`Gate`], created under the same lock
//! that reads the demand it is waiting on, and the withdrawal of that demand
//! releases it. Level-triggered, so a withdrawal that races the park is
//! observed rather than lost; a fresh gate per park, so a release cannot be
//! mistaken for the next one. Polling instead would either spin a starved
//! stream hot or add a latency nobody configured.
//!
//! # Why admission is per stream and release is per class
//!
//! Queue depth, [`Overflow`] and the framer's elide fix-up all live where
//! `note_elided` is legal: at admission, on the *arriving* unit, before the
//! framer's positional cursor has moved past it. Dropping an
//! already-queued unit at release time would not leave a gap in absolute
//! object IDs on drafts 14-20 — it would leave every successor decoding a
//! *wrong* ID. That single fact is why [`Overflow::DropTail`] exists and
//! `DropHead` does not.

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::action::Gate;
use crate::types::{ObjectMeta, ProxySide};

use moqtap_codec::dispatch::AnyDatagramMeta;

use moqtap_codec::version::DraftVersion;

use super::bucket::{charge, BucketState, Grant};
use super::matcher::MatcherField;
use super::{Discipline, Expiry, Overflow, ShapeProfile};

/// Which row of [`ShapeStats`](super::ShapeStats) a unit is charged to.
///
/// `Copy`, and an index rather than a name: the storage is a pre-sized
/// `Vec<ClassCounters>` in configured order, so charging a unit is one
/// relaxed `fetch_add` at a known offset and never a map lookup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Class {
    /// The rule at this index in [`ShapeProfile::classes`].
    Rule(usize),
    /// No rule claimed the unit.
    ///
    /// This is the falsifiable signal that a rule did not fire: an author
    /// who expected a class to claim everything and reads
    /// `ShapeStats::default_class.objects_delivered > 0` knows their rule
    /// did not fire, and the `ShapeRuleUnmatchable` impairment says why.
    ///
    /// **`objects_delivered`, not `objects_dropped`** — `objects_dropped`
    /// has a producer only under [`Overflow::DropTail`], so under the
    /// default [`Overflow::Block`] it is permanently zero and an author
    /// told to read it would read a zero and conclude their rule had fired.
    /// `objects_delivered` has a producer under every overflow policy.
    /// (The drop row is still the right one to read in a
    /// `DropTail` fixture, which is why
    /// `a_datagram_rule_says_so_instead_of_matching_nothing` asserts it.)
    Default,
    /// There was nothing to classify: a subgroup stream header, an oversized
    /// object the framer could only pass through, a bypassed stream's bytes.
    /// Such a unit still takes an **ordering slot** — it is bytes on a wire
    /// that has other bytes queued in front of it — but it charges no bucket,
    /// because no rule can name what no `ObjectMeta` describes. Distinct from
    /// [`Self::Default`], which is a unit the rules *did* see and none of them
    /// claimed: conflating them would let *my rule matched nothing* and *there
    /// was nothing for a rule to match* report as one number.
    Unshapeable,
}

/// What admission decided about one **arriving** unit.
///
/// There is no `Block` variant, and its absence is the design: `Block` is
/// not a decision taken about a unit that arrived, it is the read branch
/// never being polled, so no unit arrives to decide about. That is what
/// makes [`Self::DropTail`] observable at all — see
/// [`Scheduler::blocking_depth`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Admission {
    /// Forward it, exactly as an unshaped session would.
    Admit,
    /// Discard it. The caller must run it through the framer's elide path
    /// so absolute object IDs on drafts 14-20 stay correct, and must admit
    /// it anyway if an elide guard refuses.
    DropTail,
    /// Abandon the destination stream with `code`.
    ResetStream {
        /// The application error code to reset with.
        code: u64,
    },
}

/// What release decided about one **queued** unit.
///
/// The four "not now" answers are four different waits, and collapsing them
/// is how a shaper stalls or misreports: a bucket that will refill names an
/// instant, a bucket that will never refill names nothing at all, a bucket
/// too small to hold one unit names nothing *and* is a misconfiguration, and
/// a discipline that is holding the class back names an event.
#[derive(Clone, Debug)]
pub(crate) enum Acquire {
    /// Write it. The tokens have already been debited.
    Now,
    /// Not yet — the bucket holds enough at this instant and not before.
    ///
    /// *Earliest*, not exact: another stream sharing the bucket may drain it
    /// again first, in which case the next [`Scheduler::acquire`] answers
    /// `Later` again with a new instant.
    Later(Instant),
    /// Not yet, and no instant exists: the rate is `Some(0)`, so the bucket
    /// never refills. The caller supplies its own deadline — the unit's
    /// `max_hold` clamp — because arming a fabricated far-future instant
    /// would arm a timer that never fires and nothing downstream could tell
    /// it from a real deadline.
    Never,
    /// Not yet, and not ever: this class's `burst_bytes` is smaller than the
    /// unit at the head of its queue, so its configured rate can never pace
    /// anything and every unit leaves at the clamp instead.
    ///
    /// **Handled exactly as [`Self::Never`] is** — the clamp is the deadline
    /// in both cases — and kept apart from it for one reason: this one is a
    /// misconfiguration and `Never` is a configuration. Without the split
    /// the two produce the same clamp, the same `tokens_exhausted_episodes`
    /// and the same `HoldClamped`, so an author who wrote a rate and left
    /// the burst too small reads a throughput unrelated to their number with
    /// no signal that anything is wrong. The caller pairs this with
    /// [`Scheduler::claim_burst_report`] and reports it once per class.
    LargerThanBurst {
        /// The class's bucket cap.
        burst_bytes: u64,
        /// The unit it could not cover.
        unit_bytes: u64,
    },
    /// Not yet, and the reason is not the bucket: another class sharing it
    /// is ahead under the configured [`Discipline`]. Wait on this gate; it
    /// is released when the blocking demand withdraws.
    ///
    /// Charged to `starved_behind_other_class` and **never** to
    /// `tokens_exhausted_episodes` — two causes, two counters.
    Starved(Gate),
}

/// The per-stream queue depth, in both units at once.
///
/// Both limits, always: a queue of small objects reaches neither the byte
/// depth nor `EgressConfig::max_pending_bytes`, and a queue of large ones
/// reaches the byte depth long before the object count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct QueueDepth {
    /// Bytes one stream's queue may hold.
    pub(crate) bytes: usize,
    /// Objects one stream's queue may hold.
    pub(crate) objects: usize,
}

/// One session's shaper.
///
/// Held behind an `Arc` on `ForwardCtx` and cloned into every forwarding
/// task, exactly as the two recorders are — and, unlike them,
/// **`None` when the session has no profile**. There is nothing for an
/// unshaped session to share, and an `Option` on the context is what makes
/// "a session with `shape: None` adds nothing to this path" a compile-time
/// fact rather than a runtime hope.
pub(crate) struct Scheduler {
    profile: ShapeProfile,
    /// One report-once mask per class, indexed the same way
    /// [`Class::Rule`] is. Bit `MatcherField::bit` is set the first time
    /// that `(class, field)` pair is reported.
    /// Relaxed atomics rather than a `Mutex`: the only operation is *set this
    /// bit, tell me whether it was already set*, the only consequence of losing
    /// a race is one duplicate event on a path that fires at most `classes × 4`
    /// times per session, and taking a lock per non-matching rule per unit
    /// would put a contended mutex on the data path of every shaped session.
    unmatchable: Vec<AtomicU8>,
    /// One report-once flag per class for *this class's burst cannot cover one
    /// of its own units*, indexed the same way [`Class::Rule`] is.
    ///
    /// A separate mask from [`Self::unmatchable`] rather than a fifth bit in
    /// it, because the two are answers to different questions and share no
    /// key: that one is per `(class, field)` and is set from classification,
    /// this one is per class and is set from release. Sharing the storage
    /// would make the *first* release refusal silence a later unmatchable
    /// field report on the same class, which is a diagnostic losing to an
    /// unrelated one.
    /// A relaxed `swap` for the same reason the other mask is relaxed: the only
    /// operation is *claim this, tell me whether it was already claimed*, the
    /// only cost of losing the race is one duplicate event, and the path fires
    /// at most once per class per session.
    burst_reported: Vec<AtomicBool>,
    /// Which bucket each class charges, resolved once at construction.
    ///
    /// `ShapeProfile::try_new` has already rejected a class naming a bucket
    /// that is not configured, so this is a total map and the lookup on the
    /// data path is an index rather than a string compare.
    class_bucket: Vec<usize>,
    /// Everything release mutates, behind one lock.
    ///
    /// A `Mutex` and not a set of atomics, and the reason is the gate: a
    /// class parks on a gate created from the *same* read of the demand that
    /// decided to park it, and the withdrawal that releases it happens under
    /// the same lock. Split across atomics there is a window in which a
    /// withdrawal wakes nobody and the park that follows waits for a wake
    /// that has already happened. The lock is taken once per released unit,
    /// not once per byte, on a path that is already doing a `write_all`.
    state: Mutex<SchedState>,
    /// Whether this scheduler paces at all.
    ///
    /// Shared with every other scheduler built from the same proxy, which is
    /// what makes turning pacing off a single act rather than a walk over
    /// the sessions. A scheduler built with no switch of its own owns one
    /// that is set and never cleared, so pacing is never switched off under
    /// a session driven without a proxy.
    ///
    /// Read in [`Self::acquire`] and nowhere else. Everything a shaper does
    /// *besides* pacing — classification, the per-stream queue depth, the
    /// statistics — keeps running while it is clear, so the profile is still
    /// there to resume with and the rows a caller was reading keep moving.
    enabled: Arc<AtomicBool>,
}

/// The scheduler's mutable half.
struct SchedState {
    /// One per [`ShapeProfile::buckets`] entry, in configured order.
    buckets: Vec<BucketState>,
    /// How many stream queues currently hold an unreleased head of this
    /// class. The **demand** a discipline arbitrates over.
    ///
    /// Maintained by `PendingQueue`, which declares its head's class and
    /// withdraws on every path that can retire one — including `clear`,
    /// the teardown drain and `Drop`. A leaked declaration would starve a
    /// lower class for the rest of the session, which is why the withdrawal
    /// is a `Drop` obligation and not a list of call sites.
    demand: Vec<u64>,
    /// Releases remaining in this round, per class, under
    /// [`Discipline::WeightedRoundRobin`]. Refilled to
    /// [`ClassRule::weight`](super::ClassRule::weight) when every class with
    /// demand in a bucket has spent its own.
    credits: Vec<u32>,
    /// The gate each starved class is parked on, or `None` when it is not
    /// parked. Taken and released by whoever makes the class eligible.
    parked: Vec<Option<Gate>>,
}

impl Scheduler {
    /// Build the shaper for `profile`, with every bucket full as of `now`.
    ///
    /// Full rather than empty: an empty burst would put a
    /// `burst_bytes / rate_bps` delay in front of the first object of every
    /// session and read as a broken proxy.
    pub(crate) fn new(profile: ShapeProfile) -> Self {
        Self::at(profile, Instant::now())
    }

    /// [`Self::new`], sharing `enabled` with every other scheduler this proxy
    /// builds.
    ///
    /// The switch is handed in rather than owned because turning pacing off
    /// has to be one act for the whole proxy: a session builds its own
    /// scheduler, and a per-scheduler flag would have to be found and
    /// cleared once per session, which is a walk over a set that changes
    /// while it is being walked.
    pub(crate) fn with_switch(profile: ShapeProfile, enabled: Arc<AtomicBool>) -> Self {
        Self::build(profile, Instant::now(), enabled)
    }

    /// [`Self::new`] with the clock supplied, so the unit tests below fabricate
    /// their own timeline exactly as [`charge`] lets them.
    pub(crate) fn at(profile: ShapeProfile, now: Instant) -> Self {
        Self::build(profile, now, Arc::new(AtomicBool::new(true)))
    }

    /// The one constructor. Both public ones differ only in where the clock
    /// and the switch come from.
    fn build(profile: ShapeProfile, now: Instant, enabled: Arc<AtomicBool>) -> Self {
        let unmatchable = profile.classes().iter().map(|_| AtomicU8::new(0)).collect();
        let burst_reported = profile.classes().iter().map(|_| AtomicBool::new(false)).collect();
        let class_bucket = profile
            .classes()
            .iter()
            .map(|c| {
                profile
                    .buckets()
                    .iter()
                    .position(|b| b.name == c.bucket)
                    // `try_new` rejects `UnknownBucket`, so this is
                    // unreachable; charging bucket 0 rather than panicking on
                    // a forwarding task is the same total-function discipline
                    // `ShapeRecorder::row` takes.
                    .unwrap_or(0)
            })
            .collect();
        let state = SchedState {
            buckets: profile
                .buckets()
                .iter()
                .map(|b| BucketState::new(b.burst_bytes, now))
                .collect(),
            demand: vec![0; profile.classes().len()],
            credits: profile.classes().iter().map(|c| u32::from(c.weight)).collect(),
            parked: profile.classes().iter().map(|_| None).collect(),
        };
        Self {
            profile,
            unmatchable,
            burst_reported,
            class_bucket,
            state: Mutex::new(state),
            enabled,
        }
    }

    /// The name to label a report with, for a class index.
    pub(crate) fn class_name(&self, index: usize) -> String {
        self.profile.classes()[index].name.clone()
    }

    /// The deadline a queued unit is clamped to, or `None` to inherit
    /// [`EgressConfig::max_hold`](crate::action::EgressConfig::max_hold).
    /// Under the default [`Expiry::Deliver`] this is the instant a starved unit
    /// goes out **anyway**, which is why every starvation fixture is required
    /// to pin it: *a 0-bps class delivers zero bytes* is a statement about a
    /// sampling window, and the window only means something against a ceiling
    /// the fixture wrote down.
    pub(crate) fn max_hold(&self) -> Option<Duration> {
        self.profile.queue().max_hold
    }

    /// What happens to a unit that outlives its clamp.
    pub(crate) fn on_expiry(&self) -> Expiry {
        self.profile.queue().on_expiry
    }

    /// The depth `PendingQueue::accepts_more` must carry, or `None` when
    /// this profile does not stop reading.
    ///
    /// **`Some` only under [`Overflow::Block`]**. Under `DropTail` the
    /// read branch has to stay enabled, or nothing ever arrives to be
    /// dropped and `objects_dropped` could only ever be zero; under
    /// `ResetStream` the arriving unit is what triggers the reset. So the
    /// depth is installed on the queue for exactly one policy, and the
    /// other two evaluate it per unit through [`Self::admit`].
    ///
    /// Installing it *in* `accepts_more` rather than beside it is what
    /// gives `Impairment{EgressQueueFull}` a producer here at all: the
    /// once-per-transition latch is computed inside `PendingQueue::push`
    /// from `accepts_more()`, so a stream full by `depth_objects` but under
    /// `EgressConfig::max_pending_bytes` would otherwise never trip it.
    pub(crate) fn blocking_depth(&self) -> Option<QueueDepth> {
        let queue = self.profile.queue();
        match queue.overflow {
            Overflow::Block => {
                Some(QueueDepth { bytes: queue.depth_bytes, objects: queue.depth_objects })
            }
            Overflow::DropTail | Overflow::ResetStream { .. } => None,
        }
    }

    /// Classify one unit, reporting each unmatchable `(class, field)` once
    /// per session.
    ///
    /// Rules are tried in configured order and the **first** match wins, so
    /// a profile's order is a priority order for classification. A unit no
    /// rule claims is [`Class::Default`].
    ///
    /// `report` is called with the class index and the key that could not
    /// be carried, at most once per pair for the session's whole life. It
    /// is a callback rather than a return value because the common answer
    /// is "nothing to report" and building a collection to say so would
    /// allocate on the data path.
    ///
    /// `unit_index` is the per-**stream** count of hook-visible units,
    /// which is what `Matcher::every_nth` is defined against — never
    /// `ObjectMeta::index_in_stream`, which counts oversized objects the
    /// hook never sees and would silently shift the pattern.
    ///
    /// # The diagnostic sweep does not stop at the winner
    /// The *classification* short-circuits — first match wins, and the loop
    /// below stops asking `matches` once it has an answer. The unmatchability
    /// check does **not**, and the asymmetry is what stops a dead rule going
    /// unreported: *which class is this unit* is about one unit, but *can this
    /// rule ever fire* is a question about the profile, and a rule's answer to
    /// it does not depend on whether some earlier rule happened to claim this
    /// particular unit.
    ///
    /// Returning at the winner made it depend on exactly that. A catch-all
    /// placed first — which is the value `ClassRule::default()` hands you,
    /// since `Matcher::default()` claims everything — matched every unit and
    /// so no later rule was ever examined, silencing every diagnostic behind
    /// it for the session's whole life. Measured: same profile, same
    /// traffic, class order reversed, 1 report against 0.
    ///
    /// The winner itself is skipped, and that is not the same thing: a rule
    /// that *matched* cannot have been defeated by an absent key, so
    /// reporting it would be a false positive on a working rule.
    ///
    /// The cost is one `Matcher::unmatchable_fields` per rule per unit —
    /// three `is_some` tests over a fixed-size array, no allocation, and the
    /// relaxed `fetch_or` is reached only when a field is genuinely absent.
    /// A profile whose keys are all carried never touches an atomic.
    pub(crate) fn classify(
        &self,
        side: ProxySide,
        meta: &ObjectMeta,
        unit_index: u64,
        mut report: impl FnMut(usize, MatcherField),
    ) -> Class {
        let mut claimed: Option<Class> = None;
        for (index, rule) in self.profile.classes().iter().enumerate() {
            if claimed.is_none() && rule.matcher.matches(side, meta, unit_index) {
                claimed = Some(Class::Rule(index));
                continue;
            }
            for field in rule.matcher.unmatchable_fields(meta).into_iter().flatten() {
                self.report_once(index, field, &mut report);
            }
        }
        claimed.unwrap_or(Class::Default)
    }

    /// [`Self::classify`] for a datagram.
    ///
    /// The same two-part sweep — first match wins, every rule that did not
    /// match is asked whether it *could* have — over
    /// [`Matcher::matches_datagram`] and
    /// [`Matcher::unmatchable_fields_datagram`] instead of their framed
    /// siblings. The report-once mask is the one `classify` uses, so a
    /// session carrying both never reports a `(class, field)` pair twice and
    /// whichever carrier arrives first is the one that says it.
    ///
    /// `unit_index` counts hook-visible datagrams per forwarding direction;
    /// see [`Matcher::matches_datagram`] for why that is the only scope a
    /// datagram has.
    ///
    /// The draft is taken as an argument rather than read off the unit
    /// because an [`AnyDatagramMeta`] does not carry one — it is the resolved
    /// identity, not the header — where an [`ObjectMeta`] does.
    pub(crate) fn classify_datagram(
        &self,
        side: ProxySide,
        draft: DraftVersion,
        meta: &AnyDatagramMeta,
        unit_index: u64,
        mut report: impl FnMut(usize, MatcherField),
    ) -> Class {
        let mut claimed: Option<Class> = None;
        for (index, rule) in self.profile.classes().iter().enumerate() {
            if claimed.is_none() && rule.matcher.matches_datagram(side, meta, unit_index) {
                claimed = Some(Class::Rule(index));
                continue;
            }
            for field in rule.matcher.unmatchable_fields_datagram(draft, meta).into_iter().flatten()
            {
                self.report_once(index, field, &mut report);
            }
        }
        claimed.unwrap_or(Class::Default)
    }

    /// Set `(index, field)`'s bit and call `report` only if this is the
    /// first time anyone has.
    ///
    /// One relaxed `fetch_or`; see [`Self::unmatchable`] for why the losing
    /// side of a race costs one duplicate event rather than a lock.
    fn report_once(
        &self,
        index: usize,
        field: MatcherField,
        report: &mut impl FnMut(usize, MatcherField),
    ) {
        let Some(mask) = self.unmatchable.get(index) else { return };
        if mask.fetch_or(field.bit(), Ordering::Relaxed) & field.bit() == 0 {
            report(index, field);
        }
    }

    /// Whether a unit of `bytes` fits behind `queued_objects` units holding
    /// `queued_bytes`, and what to do if it does not.
    ///
    /// The byte test counts the arriving unit (`queued_bytes + bytes >
    /// depth_bytes`) and the object test does not (`queued_objects >=
    /// depth_objects`), because they answer different questions: the byte
    /// depth is a budget the queue may not exceed, and the object depth is
    /// a count of slots, all of which are taken.
    ///
    /// [`Overflow::Block`] answers [`Admission::Admit`] here and always
    /// will: under `Block` a full queue is one the read branch is not
    /// polling, so a unit reaching this function proves there was room for
    /// it. Deciding to drop it here as well would double-count the same
    /// limit and silently make `Block` destructive.
    pub(crate) fn admit(
        &self,
        bytes: usize,
        queued_bytes: usize,
        queued_objects: usize,
    ) -> Admission {
        let queue = self.profile.queue();
        let fits = queued_objects < queue.depth_objects
            && queued_bytes.saturating_add(bytes) <= queue.depth_bytes;
        if fits {
            return Admission::Admit;
        }
        match queue.overflow {
            Overflow::Block => Admission::Admit,
            Overflow::DropTail => Admission::DropTail,
            Overflow::ResetStream { code } => Admission::ResetStream { code },
        }
    }

    // ── release ─────────────────────────────────────────────────────

    /// Ask whether a queued unit of `class` holding `bytes` may go at `now`,
    /// debiting its bucket when the answer is yes.
    ///
    /// **The release seam.** Called from `PendingQueue::pop_next_due` and
    /// from nowhere else, exactly once per released unit.
    /// [`Class::Default`] and [`Class::Unshapeable`] answer [`Acquire::Now`]
    /// unconditionally and touch no lock: neither names a bucket, so there is
    /// nothing to charge and nothing to arbitrate. That is not a shortcut — it
    /// is what *no rule claimed this* means. A profile that wants a catch-all
    /// charges one by writing a class with an all-`None`
    /// [`Matcher`](super::Matcher).
    ///
    /// The discipline is consulted **before** the bucket, and the order is
    /// load-bearing: charging first would let a class the discipline is
    /// holding back spend tokens the class ahead of it is entitled to, and
    /// the debit is not refundable.
    ///
    /// # While pacing is switched off
    ///
    /// Every unit is granted here, before the bucket is read and before the
    /// discipline is consulted, so nothing is debited and no class is parked
    /// while the switch is clear.
    ///
    /// **It is read when a queue asks, and a queue asks when its head's park
    /// expires.** This function is the whole of the release decision, and a
    /// queue that has been refused here parks its head on the deadline the
    /// refusal named. Switching pacing off does not reach into that park; it
    /// changes the answer the *next* call gives. So the delay between the
    /// switch and a stream resuming is the park that was already running,
    /// and which park that is depends on why the head was refused:
    ///
    /// * refused by a bucket that will refill — the refill instant, which is
    ///   one unit's worth of the configured rate;
    /// * refused by a bucket that never refills, or one whose burst cannot
    ///   cover a unit — no instant exists, so the park is the queue's
    ///   `max_hold` clamp, which on a stopped class is the whole of it;
    /// * held back by the discipline — the class ahead withdrawing its
    ///   demand, which is now immediate, because that class is granted here
    ///   too.
    ///
    /// The middle case is the one to know: switching pacing off does **not**
    /// promptly release a class configured at zero. Nothing here can, and
    /// nothing else in this crate can either — the park is a timer a queue
    /// armed, the queues are per stream, and no session-wide wake reaches
    /// them.
    ///
    /// Nothing leaves a bucket half-charged whichever way the switch moves:
    /// the debit happens on the same call as the grant or not at all.
    pub(crate) fn acquire(&self, class: Class, bytes: u64, now: Instant) -> Acquire {
        if !self.enabled.load(Ordering::Relaxed) {
            return Acquire::Now;
        }
        let Class::Rule(index) = class else {
            return Acquire::Now;
        };
        let Some(&bucket) = self.class_bucket.get(index) else {
            return Acquire::Now;
        };
        let mut state = self.state.lock().expect("shape scheduler");

        if let Some(gate) = self.discipline_holds(&mut state, index, bucket) {
            return Acquire::Starved(gate);
        }

        let config = &self.profile.buckets()[bucket];
        match charge(&mut state.buckets[bucket], config.rate_bps, config.burst_bytes, bytes, now) {
            Grant::Now => {
                if self.profile.discipline() == Discipline::WeightedRoundRobin {
                    let credit = &mut state.credits[index];
                    *credit = credit.saturating_sub(1);
                }
                Acquire::Now
            }
            Grant::Later(at) => Acquire::Later(at),
            Grant::Never => Acquire::Never,
            Grant::LargerThanBurst { burst_bytes, unit_bytes } => {
                Acquire::LargerThanBurst { burst_bytes, unit_bytes }
            }
        }
    }

    /// Claim the once-per-session right to report that `class`'s burst is
    /// smaller than one of its own units, and say what to call the class.
    ///
    /// `Some(name)` for the first caller and `None` for every one after, so
    /// a class whose every unit is refused for the whole session reports
    /// once rather than once per release attempt. The name comes back with
    /// the claim because the caller needs both and asking twice would let a
    /// caller claim one class and label another.
    ///
    /// **Once per session per class, not once per stream.** A burst that
    /// cannot cover an object is a property of the profile, so every stream
    /// carrying that class reproduces it and a per-stream report would say
    /// the same thing as many times as the session has streams. The rows
    /// that keep counting are the class's own `tokens_exhausted_episodes`
    /// and the `HoldClamped` report on each clamped unit.
    ///
    /// Answers `None` for the two rows that name no bucket: neither
    /// [`Class::Default`] nor [`Class::Unshapeable`] reaches [`charge`] at
    /// all, so neither can have produced the refusal this reports.
    pub(crate) fn claim_burst_report(&self, class: Class) -> Option<String> {
        let Class::Rule(index) = class else { return None };
        let claimed = self.burst_reported.get(index)?.swap(true, Ordering::Relaxed);
        if claimed {
            return None;
        }
        Some(self.class_name(index))
    }

    /// Whether the discipline is holding `index` back, and the gate to wait
    /// on if it is.
    ///
    /// Scoped to the classes that **share `bucket`**: a discipline arbitrates
    /// between classes competing for one bucket, and two classes with their
    /// own buckets are not competing for anything.
    fn discipline_holds(
        &self,
        state: &mut SchedState,
        index: usize,
        bucket: usize,
    ) -> Option<Gate> {
        let discipline = self.profile.discipline();
        // Whoever asked first: the bucket alone decides, and it decides by
        // arriving at `charge` first. Answered before anything is collected,
        // so the default discipline allocates nothing per unit.
        if discipline == Discipline::Fifo {
            return None;
        }

        let classes = self.profile.classes();
        // The classes this one is actually competing with: same bucket, not
        // itself, and holding something to send.
        let rivals: Vec<usize> = (0..classes.len())
            .filter(|&j| j != index && self.class_bucket[j] == bucket && state.demand[j] > 0)
            .collect();

        match discipline {
            Discipline::Fifo => return None,
            Discipline::StrictPriority => {
                let mine = classes[index].priority;
                if !rivals.iter().any(|&j| classes[j].priority > mine) {
                    return None;
                }
            }
            Discipline::WeightedRoundRobin => {
                if state.credits[index] > 0 {
                    return None;
                }
                if rivals.iter().any(|&j| state.credits[j] > 0) {
                    // Somebody else still owes this round: wait for them.
                    // Deliberately *not* a refill — refilling here would let
                    // a class that spent its share take a second one while a
                    // rival still had credit, and the ratio would collapse to
                    // whoever polls most often.
                } else {
                    // Every class with demand has spent its share, so the
                    // round is over. Refill and wake the ones parked on it.
                    for (j, rule) in classes.iter().enumerate() {
                        if self.class_bucket[j] == bucket {
                            state.credits[j] = u32::from(rule.weight);
                        }
                    }
                    self.wake_bucket(state, bucket);
                    return None;
                }
            }
        }

        // Parked. One gate per park, created under the lock that just read
        // the demand it waits on, so a withdrawal cannot slip between the
        // decision and the wait.
        Some(state.parked[index].get_or_insert_with(Gate::new).clone())
    }

    /// Release every class parked on `bucket`.
    ///
    /// Over-waking is safe and deliberate: a woken class re-asks and parks
    /// again on a *fresh* gate if it is still held back, which costs one
    /// loop iteration. Under-waking is a stall until `max_hold`, so the
    /// asymmetry decides the direction to err in.
    fn wake_bucket(&self, state: &mut SchedState, bucket: usize) {
        for j in 0..state.parked.len() {
            if self.class_bucket[j] == bucket {
                if let Some(gate) = state.parked[j].take() {
                    gate.release();
                }
            }
        }
    }

    /// Record that one stream queue now holds an unreleased head of `class`.
    ///
    /// Demand, not depth: one per *queue*, whatever it holds behind that
    /// head. A discipline arbitrates between classes that have something to
    /// send, and a class with ten streams waiting is not ten times more
    /// entitled than a class with one.
    pub(crate) fn declare_demand(&self, class: Class) {
        let Class::Rule(index) = class else { return };
        let mut state = self.state.lock().expect("shape scheduler");
        if let Some(slot) = state.demand.get_mut(index) {
            *slot += 1;
        }
    }

    /// Undo one [`Self::declare_demand`], waking whatever it was holding back.
    /// Called from every path that can retire a head — a grant, a `clear`, the
    /// teardown drain, and `PendingQueue`'s `Drop`. The wake is unconditional
    /// rather than *only when the count reached zero*, because the classes it
    /// wakes re-ask and park again for free, while a missed wake is a
    /// `max_hold` stall on a stream that has nothing wrong with it.
    pub(crate) fn withdraw_demand(&self, class: Class) {
        let Class::Rule(index) = class else { return };
        let Some(&bucket) = self.class_bucket.get(index) else { return };
        let mut state = self.state.lock().expect("shape scheduler");
        if let Some(slot) = state.demand.get_mut(index) {
            *slot = slot.saturating_sub(1);
        }
        self.wake_bucket(&mut state, bucket);
    }
}

impl std::fmt::Debug for Scheduler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Scheduler").field("profile", &self.profile).finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shape::{
        BucketConfig, ClassRule, Discipline, MatchKind, Matcher, QueueConfig, RangeSet,
    };
    use crate::types::DataStreamType;
    use moqtap_codec::version::DraftVersion;
    use std::cell::RefCell;

    fn meta() -> ObjectMeta {
        ObjectMeta {
            draft: DraftVersion::Draft19,
            stream_kind: DataStreamType::Subgroup,
            track_alias: Some(7),
            group_id: 3,
            subgroup_id: Some(4),
            object_id: 11,
            publisher_priority: Some(128),
            index_in_stream: 0,
            payload_len: 16,
            status: None,
            end_of_range: None,
        }
    }

    /// A datagram carrying every key one can carry, so a test can knock a
    /// single one out and attribute the result.
    fn datagram_meta() -> AnyDatagramMeta {
        AnyDatagramMeta {
            track_alias: 7,
            group_id: 3,
            object_id: 11,
            publisher_priority: Some(128),
            status: None,
        }
    }

    fn class(name: &str, matcher: Matcher) -> ClassRule {
        ClassRule {
            name: name.to_string(),
            bucket: "b".to_string(),
            matcher,
            weight: 1,
            ..ClassRule::default()
        }
    }

    fn scheduler(classes: Vec<ClassRule>, queue: QueueConfig) -> Scheduler {
        let bucket = BucketConfig { name: "b".to_string(), ..BucketConfig::default() };
        Scheduler::new(
            ShapeProfile::try_new(vec![bucket], classes, queue, Discipline::Fifo)
                .expect("the fixture names its own bucket"),
        )
    }

    /// Collect every `(class index, field)` a classification reported.
    fn reports<'a>(
        s: &'a Scheduler,
        meta: &'a ObjectMeta,
    ) -> impl FnMut(u64) -> Vec<(usize, MatcherField)> + 'a {
        move |unit_index| {
            let seen = RefCell::new(Vec::new());
            s.classify(ProxySide::ClientToProxy, meta, unit_index, |i, f| {
                seen.borrow_mut().push((i, f));
            });
            seen.into_inner()
        }
    }

    /// The first rule that claims a unit wins, and a unit no rule claims
    /// falls to the default row rather than to the first rule.
    ///
    /// *Ablation:* return `Class::Rule(0)` instead of `Class::Default` —
    /// the `Default` assertion reddens with `left: Rule(0)`.
    #[test]
    fn the_first_matching_rule_wins_and_the_rest_fall_to_default() {
        let s = scheduler(
            vec![
                class(
                    "high",
                    Matcher { object_id: Some(RangeSet::new([0..=5])), ..Matcher::default() },
                ),
                class(
                    "mid",
                    Matcher { object_id: Some(RangeSet::new([0..=20])), ..Matcher::default() },
                ),
            ],
            QueueConfig::default(),
        );

        let low = ObjectMeta { object_id: 3, ..meta() };
        assert_eq!(
            s.classify(ProxySide::ClientToProxy, &low, 0, |_, _| {}),
            Class::Rule(0),
            "both rules claim object 3; configured order decides"
        );
        assert_eq!(s.classify(ProxySide::ClientToProxy, &meta(), 0, |_, _| {}), Class::Rule(1));
        let out = ObjectMeta { object_id: 99, ..meta() };
        assert_eq!(s.classify(ProxySide::ClientToProxy, &out, 0, |_, _| {}), Class::Default);
    }

    /// A rule keyed on a field the wire did not carry falls to default
    /// **and** reports, once per session per `(class, field)`.
    ///
    /// The three separate assertions are the three cases that must not be
    /// conflated: absent-and-keyed reports, present-but-wrong does not, and
    /// a second unit of the same shape does not report again.
    ///
    /// *Ablation:* drop the `fetch_or` guard and report unconditionally —
    /// the "once" assertion reddens with two entries for the same pair.
    #[test]
    fn an_absent_key_reports_once_per_class_and_field() {
        let s = scheduler(
            vec![class(
                "video",
                Matcher { subgroup_id: Some(RangeSet::single(4)), ..Matcher::default() },
            )],
            QueueConfig::default(),
        );

        let absent = ObjectMeta { subgroup_id: None, ..meta() };
        let mut classify = reports(&s, &absent);
        assert_eq!(
            classify(0),
            vec![(0, MatcherField::SubgroupId)],
            "the wire carried no subgroup ID, so this rule can never fire: say so"
        );
        assert_eq!(classify(1), vec![], "once per session per (class, field), not per unit");
    }

    /// A key that is *present but out of range* is a rule working, not a
    /// rule that cannot work — so nothing is reported.
    ///
    /// Without this the report would fire on every ordinary non-match and
    /// mean nothing.
    #[test]
    fn a_present_but_unmatched_key_reports_nothing() {
        let s = scheduler(
            vec![class(
                "video",
                Matcher { subgroup_id: Some(RangeSet::single(4)), ..Matcher::default() },
            )],
            QueueConfig::default(),
        );
        let other = ObjectMeta { subgroup_id: Some(9), ..meta() };
        assert_eq!(reports(&s, &other)(0), vec![]);
    }

    /// A rule aimed at datagrams claims a datagram, walks past a framed
    /// object, and reports nothing about either.
    ///
    /// Three assertions because the middle one is what the first would
    /// otherwise be satisfied by: a `stream_kind` key that had stopped being
    /// read would claim both, and a rule that claimed neither would fall to
    /// default on both. The third is what a live `Datagram` rule turns the
    /// silence into: not a rule that can never fire, but one that is live
    /// and simply did not claim *this* unit.
    ///
    /// *Ablation (measured):* have `MatchKind::is_matchable_on` answer
    /// `false` for `Datagram`. The first run of it left this test **green**
    /// and reddened two others, which is what put the fresh scheduler below
    /// in: an assertion above it had already consumed the report.
    ///
    /// ```text
    /// ---- shape::scheduler::tests::a_datagram_rule_claims_a_datagram stdout ----
    /// assertion `left == right` failed: a Datagram rule is live now, so a
    /// framed object walking past it is an ordinary non-match and not a
    /// diagnostic
    ///   left: [(0, StreamKind)]
    ///  right: []
    /// ```
    #[test]
    fn a_datagram_rule_claims_a_datagram() {
        let s = scheduler(
            vec![class(
                "dgram",
                Matcher { stream_kind: Some(MatchKind::Datagram), ..Matcher::default() },
            )],
            QueueConfig::default(),
        );
        let dgram = datagram_meta();
        assert_eq!(
            s.classify_datagram(
                ProxySide::ClientToProxy,
                DraftVersion::Draft19,
                &dgram,
                0,
                |_, _| {}
            ),
            Class::Rule(0),
            "a class aimed at datagrams must claim one"
        );

        let m = meta();
        assert_eq!(
            s.classify(ProxySide::ClientToProxy, &m, 0, |_, _| {}),
            Class::Default,
            "...and must not claim a framed object, or `stream_kind` is not a key"
        );

        // A **fresh** scheduler for the report, and this is load-bearing:
        // the report-once mask is set by whichever call reaches it first,
        // including one whose reporter discards what it is handed. Asking
        // the scheduler above would read a mask the assertion before it had
        // already consumed, and the assertion would pass for every possible
        // implementation. Measured — the ablation below left it green.
        let fresh = scheduler(
            vec![class(
                "dgram",
                Matcher { stream_kind: Some(MatchKind::Datagram), ..Matcher::default() },
            )],
            QueueConfig::default(),
        );
        assert_eq!(
            reports(&fresh, &m)(0),
            vec![],
            "a Datagram rule is live now, so a framed object walking past it is \
             an ordinary non-match and not a diagnostic"
        );
    }

    /// **A rule behind the winner is still checked**, so a rule that can
    /// never fire is not silenced by whichever rule happened to win.
    ///
    /// `classify` returned at the first match, so every rule after it —
    /// including its unmatchability check — was skipped. A catch-all placed
    /// first is the value `ClassRule::default()` hands you, and it silenced
    /// every diagnostic behind it for the session's whole life.
    ///
    /// The two legs are the **same two rules in the two orders**, which is
    /// what makes this attributable to the short-circuit and to nothing
    /// else: same profile, same unit, same report-once state, one
    /// difference. The classification is asserted on both legs too, because
    /// a "fix" that reported the shadowed rule by also *letting it win*
    /// would break first-match-wins, and the second assertion is what
    /// forbids it.
    ///
    /// *Ablation, recorded:* restore the `return Class::Rule(index)` in
    /// place of `claimed = Some(..); continue;` —
    ///
    /// ```text
    /// assertion `left == right` failed: a rule behind the winner can still be
    /// one that can never fire, and the winner claiming this unit is not a
    /// statement about it
    ///   left: []
    ///  right: [(1, TrackAlias)]
    /// ```
    #[test]
    fn a_rule_shadowed_by_a_catch_all_is_still_checked() {
        let catch_all = || class("everything", Matcher::default());
        // A rule keyed on the Track Alias, against a fetch unit, which
        // carries a Request ID where a subgroup unit carries an alias — so
        // the key is one the unit could not have had rather than one whose
        // value was wrong.
        let by_alias = || {
            class(
                "aliased",
                Matcher { track_alias: Some(RangeSet::single(7)), ..Matcher::default() },
            )
        };
        let m = ObjectMeta { stream_kind: DataStreamType::Fetch, track_alias: None, ..meta() };

        let shadowed = scheduler(vec![catch_all(), by_alias()], QueueConfig::default());
        assert_eq!(
            reports(&shadowed, &m)(0),
            vec![(1, MatcherField::TrackAlias)],
            "a rule behind the winner can still be one that can never fire, and \
             the winner claiming this unit is not a statement about it"
        );
        assert_eq!(
            shadowed.classify(ProxySide::ClientToProxy, &m, 0, |_, _| {}),
            Class::Rule(0),
            "...and reporting it must not promote it: the first match still wins"
        );

        // The control leg: the same two rules in the other order, which
        // must also report, and exactly once.
        let ordered = scheduler(vec![by_alias(), catch_all()], QueueConfig::default());
        assert_eq!(reports(&ordered, &m)(0), vec![(0, MatcherField::TrackAlias)]);
        assert_eq!(reports(&ordered, &m)(1), vec![], "still once per session per pair");
    }

    /// The winner is **not** reported, however unmatchable its keys look.
    ///
    /// The guard against sweeping every rule unconditionally instead,
    /// which would fire `ShapeRuleUnmatchable` on the very class that is
    /// doing the work and make the report noise.
    ///
    /// Nearly every key makes this vacuous — an absent key never matches,
    /// so a rule keyed on one cannot be the winner. `stream_kind` is the
    /// exception and therefore the fixture: `kind_matches(Fetch, Fetch)` is
    /// `true` while `Fetch::is_matchable_on(Draft19)` is `false`, so a
    /// draft-19 fetch `ObjectMeta` is a unit that a Fetch rule both claims
    /// and is "unmatchable" for. The framer never builds one — drafts 15-19
    /// have no fetch object codec, so every fetch stream is bypassed at its
    /// header — which is exactly why it has to be built here: it is the only
    /// input that can tell the `continue` from a `return`.
    ///
    /// *Ablation, recorded:* drop the `continue` so the winner falls into
    /// the sweep — `left: [(0, StreamKind)] / right: []`.
    #[test]
    fn the_winning_rule_is_never_reported_as_unmatchable() {
        let s = scheduler(
            vec![class(
                "fetch",
                Matcher { stream_kind: Some(MatchKind::Fetch), ..Matcher::default() },
            )],
            QueueConfig::default(),
        );
        let claimed = ObjectMeta {
            draft: DraftVersion::Draft19,
            stream_kind: DataStreamType::Fetch,
            ..meta()
        };
        // The reporting assertion goes **first**, and deliberately: the mask
        // is once-per-session, so a classification run with a no-op reporter
        // would spend the budget and leave the ablation invisible. Measured
        // — with the assertions the other way round the `continue` ablation
        // ran green.
        assert_eq!(
            reports(&s, &claimed)(0),
            vec![],
            "a rule that claimed the unit is a rule that fired; reporting it as \
             unable to fire would be a false positive on a working class"
        );
        assert_eq!(
            s.classify(ProxySide::ClientToProxy, &claimed, 0, |_, _| {}),
            Class::Rule(0),
            "the fixture is only meaningful if the rule really does win"
        );

        // The contrast in the same body, so the assertion above is not
        // passing because this scheduler never reports: a rule against a
        // unit it does *not* claim, keyed on something that unit could not
        // have carried, reports at once. The key rather than the kind,
        // because naming a kind is not something a rule can be dead for —
        // see `Matcher::unmatchable_fields`.
        let s = scheduler(
            vec![class(
                "aliased",
                Matcher { track_alias: Some(RangeSet::single(7)), ..Matcher::default() },
            )],
            QueueConfig::default(),
        );
        let unaliased = ObjectMeta { track_alias: None, ..claimed };
        assert_eq!(reports(&s, &unaliased)(0), vec![(0, MatcherField::TrackAlias)]);
    }

    /// The depth reaches `PendingQueue` under `Block` and nowhere else.
    ///
    /// *Ablation:* return the depth for every overflow — `DropTail`'s
    /// `None` assertion reddens, which is the read branch being switched
    /// off under the one policy that needs it on.
    #[test]
    fn only_block_installs_a_blocking_depth() {
        let depths = QueueConfig { depth_objects: 4, depth_bytes: 99, ..QueueConfig::default() };
        let with = |overflow| QueueConfig { overflow, ..depths.clone() };

        let blocking = scheduler(vec![class("c", Matcher::default())], with(Overflow::Block));
        assert_eq!(blocking.blocking_depth(), Some(QueueDepth { bytes: 99, objects: 4 }));

        for overflow in [Overflow::DropTail, Overflow::ResetStream { code: 7 }] {
            assert_eq!(
                scheduler(vec![class("c", Matcher::default())], with(overflow)).blocking_depth(),
                None,
                "{overflow:?} must leave the read branch enabled"
            );
        }
    }

    /// Both depth limits, and the policy each one selects.
    /// *Ablation:* make the object test `>` instead of `>=` — the *the fourth
    /// slot is taken* row admits a fifth unit and reddens.
    #[test]
    fn admission_applies_both_depths_and_then_the_policy() {
        let depths = QueueConfig { depth_objects: 4, depth_bytes: 100, ..QueueConfig::default() };
        let with = |overflow| QueueConfig { overflow, ..depths.clone() };
        let s = scheduler(vec![class("c", Matcher::default())], with(Overflow::DropTail));

        assert_eq!(s.admit(10, 0, 0), Admission::Admit, "an empty queue takes anything that fits");
        assert_eq!(s.admit(10, 90, 3), Admission::Admit, "exactly at the byte depth still fits");
        assert_eq!(s.admit(11, 90, 3), Admission::DropTail, "one byte over the byte depth");
        assert_eq!(s.admit(1, 0, 4), Admission::DropTail, "all four object slots are taken");
        assert_eq!(s.admit(1, 0, 3), Admission::Admit, "the fourth slot is free");

        let s = scheduler(
            vec![class("c", Matcher::default())],
            with(Overflow::ResetStream { code: 0x2A }),
        );
        assert_eq!(s.admit(1, 0, 4), Admission::ResetStream { code: 0x2A });

        // `Block` never decides here: a unit that reached admission under
        // `Block` proves the queue had room, because the read branch is
        // what enforces the limit.
        let s = scheduler(vec![class("c", Matcher::default())], with(Overflow::Block));
        assert_eq!(s.admit(1, 0, 4), Admission::Admit);
    }

    // ── release ─────────────────────────────────────────────────────

    /// A shaper over one bucket shared by every class, with the discipline
    /// and the per-class `(priority, weight)` given.
    fn shared_bucket(
        rate: Option<u64>,
        burst: u64,
        discipline: Discipline,
        classes: &[(&str, u8, u16)],
        now: Instant,
    ) -> Scheduler {
        let bucket = BucketConfig {
            name: "b".to_string(),
            rate_bps: rate,
            burst_bytes: burst,
            ..BucketConfig::default()
        };
        let rules = classes
            .iter()
            .map(|(name, priority, weight)| ClassRule {
                name: (*name).to_string(),
                bucket: "b".to_string(),
                matcher: Matcher::default(),
                priority: *priority,
                weight: *weight,
            })
            .collect();
        Scheduler::at(
            ShapeProfile::try_new(vec![bucket], rules, QueueConfig::default(), discipline)
                .expect("the fixture names its own bucket"),
            now,
        )
    }

    fn granted(a: &Acquire) -> bool {
        matches!(a, Acquire::Now)
    }

    /// Neither of the two rows that name no bucket can be charged one, and
    /// neither is arbitrated: an unclassified unit is not a class competing
    /// for anything.
    ///
    /// *Ablation:* charge `Class::Default` to bucket 0 — the zero-rate arm
    /// answers `Never` and the assertion reddens, which is a unit no rule
    /// claimed being paced by a bucket no rule pointed it at.
    #[test]
    fn the_unclassified_rows_are_never_charged_a_bucket() {
        let base = Instant::now();
        // A bucket that grants nothing at all, so a charge is unmissable.
        let s = shared_bucket(Some(0), 0, Discipline::Fifo, &[("only", 0, 1)], base);
        for class in [Class::Default, Class::Unshapeable] {
            assert!(
                granted(&s.acquire(class, 4096, base)),
                "{class:?} names no bucket, so there is nothing to charge it against"
            );
        }
        // ...and the class that *does* name the bucket is refused, so the
        // assertion above is not passing because the bucket grants freely.
        assert!(matches!(s.acquire(Class::Rule(0), 1, base), Acquire::Never));
    }

    /// The bound `charge` proves, reached through `acquire`: a rate-limited
    /// class is granted, then refused with the instant its own refill lands.
    #[test]
    fn a_rate_limited_class_is_refused_with_its_refill_instant() {
        let base = Instant::now();
        // 1000 bytes/s, 1000-byte burst: the first 1000-byte unit fits, the
        // second needs a full second.
        let s = shared_bucket(Some(1_000), 1_000, Discipline::Fifo, &[("v", 0, 1)], base);
        assert!(granted(&s.acquire(Class::Rule(0), 1_000, base)));
        match s.acquire(Class::Rule(0), 1_000, base) {
            Acquire::Later(at) => assert_eq!(at, base + Duration::from_secs(1)),
            other => panic!("expected a refill instant, got {other:?}"),
        }
        assert!(granted(&s.acquire(Class::Rule(0), 1_000, base + Duration::from_secs(1))));
    }

    /// **A burst too small for one unit is its own answer, claimable once**
    /// — not the answer a stopped class gives and not the answer a merely
    /// slow class gives.
    /// All three postures are driven in one body against the same unit size,
    /// because the whole claim is that they are distinguishable and a single
    /// posture cannot show that. Before the split, the first and the second
    /// were the same value and the run reported the same clamp for both, so *1
    /// MB/s delivering at the hold clamp* looked exactly like *this class was
    /// configured to stop*.
    ///
    /// *Ablation, recorded:* fold the two refusals back together in `charge`
    /// (`if rate == 0 || need > cap { Grant::Never }`) — the first
    /// assertion panics with
    /// `a rate that was asked for and a burst that cannot cover one object is a
    /// misconfiguration, not a rate limit: Never`.
    #[test]
    fn a_burst_below_one_unit_is_separable_from_a_stopped_or_a_slow_class() {
        let base = Instant::now();
        const UNIT: u64 = 1_000;

        // The defect: a real rate, a burst that cannot hold one object.
        let mis_sized = shared_bucket(Some(1_000_000), 100, Discipline::Fifo, &[("v", 0, 1)], base);
        match mis_sized.acquire(Class::Rule(0), UNIT, base) {
            Acquire::LargerThanBurst { burst_bytes, unit_bytes } => {
                assert_eq!((burst_bytes, unit_bytes), (100, UNIT), "both figures, as configured");
            }
            other => panic!(
                "a rate that was asked for and a burst that cannot cover one object \
                 is a misconfiguration, not a rate limit: {other:?}"
            ),
        }
        assert_eq!(
            mis_sized.claim_burst_report(Class::Rule(0)).as_deref(),
            Some("v"),
            "the report names the class whose rate is not being applied"
        );
        assert_eq!(
            mis_sized.claim_burst_report(Class::Rule(0)),
            None,
            "once per session per class: the refusal repeats on every unit and the \
             report must not"
        );
        assert_eq!(
            mis_sized.claim_burst_report(Class::Default),
            None,
            "the rows that name no bucket never reached a bucket to be refused by"
        );

        // A class configured to stop. Same unit, same clamp downstream, and
        // deliberately a different answer: nothing is wrong with it.
        let stopped = shared_bucket(Some(0), 0, Discipline::Fifo, &[("v", 0, 1)], base);
        assert!(
            matches!(stopped.acquire(Class::Rule(0), UNIT, base), Acquire::Never),
            "a zero rate is a class doing what it was asked, whatever the burst is"
        );

        // A class that is merely slow: the burst covers a unit, so the
        // bucket refuses with the instant it will hold one again.
        let slow = shared_bucket(Some(1_000), UNIT, Discipline::Fifo, &[("v", 0, 1)], base);
        assert!(granted(&slow.acquire(Class::Rule(0), UNIT, base)));
        match slow.acquire(Class::Rule(0), UNIT, base) {
            Acquire::Later(at) => assert_eq!(at, base + Duration::from_secs(1)),
            other => panic!("a burst that holds a unit names a refill instant: {other:?}"),
        }
    }

    /// Strict priority's mechanism, without QUIC: on one shared non-zero
    /// bucket, the
    /// lower-priority class is refused **while the higher one has demand**
    /// and released the moment that demand withdraws.
    ///
    /// The two halves are one test because neither means anything alone: a
    /// park that is never released is a stall, and a release that never
    /// parked is `Fifo` wearing a different name.
    ///
    /// *Ablation:* drop the `wake_bucket` call from `withdraw_demand` — the
    /// gate assertion reddens, and in the session that is a low class stalled
    /// to `max_hold` after the high class has finished.
    #[test]
    fn strict_priority_parks_the_low_class_until_the_high_one_withdraws() {
        let base = Instant::now();
        let s = shared_bucket(
            Some(1_000_000),
            1_000_000,
            Discipline::StrictPriority,
            &[("audio", 9, 1), ("video", 1, 1)],
            base,
        );

        // Nobody is holding anything: the bucket alone decides, and it grants.
        assert!(granted(&s.acquire(Class::Rule(1), 10, base)));

        s.declare_demand(Class::Rule(0));
        let gate = match s.acquire(Class::Rule(1), 10, base) {
            Acquire::Starved(gate) => gate,
            other => panic!("audio has demand and outranks video; got {other:?}"),
        };
        assert!(!gate.is_released(), "the blocking class is still holding it");
        // The high class is not held back by the low one's demand.
        s.declare_demand(Class::Rule(1));
        assert!(granted(&s.acquire(Class::Rule(0), 10, base)));

        s.withdraw_demand(Class::Rule(0));
        assert!(
            gate.is_released(),
            "the gate a starved class parked on opens when its blocker drains"
        );
        assert!(granted(&s.acquire(Class::Rule(1), 10, base)));
    }

    /// Weighted round robin's mechanism, without QUIC: two classes with
    /// demand on one bucket
    /// under `WeightedRoundRobin` are granted in their **weight ratio**,
    /// because the ratio is a count and not a rate.
    ///
    /// The bucket is deliberately unlimited, so nothing but the discipline
    /// can shape the counts, and each class asks the way a stream's release
    /// branch does — `while let Some(unit) = pop_next_due(..)`, i.e. until it
    /// is refused. Asking exactly once per turn instead would cap a class at
    /// one grant per turn whatever its weight, and the harness rather than
    /// the discipline would be setting the ratio. (Measured: that shape gave
    /// `[40, 14]` for weights 3:1.)
    ///
    /// The ratio is asserted as a **band**, not an equality, and the reason
    /// is arithmetic rather than caution: a round hands out `weight` grants
    /// per class, so the totals are exact only when sampled on a round
    /// boundary and the last partial round moves them by at most `weight`.
    /// The band still separates 3:1 from 1:1 by a factor of three.
    ///
    /// *Ablation:* give both classes weight 1 — the counts come out equal and
    /// the `>= 2x` assertion reddens.
    #[test]
    fn weighted_round_robin_grants_in_the_weight_ratio() {
        let base = Instant::now();
        let s = shared_bucket(
            None,
            0,
            Discipline::WeightedRoundRobin,
            &[("a", 0, 3), ("b", 0, 1)],
            base,
        );
        s.declare_demand(Class::Rule(0));
        s.declare_demand(Class::Rule(1));

        let mut counts = [0u32; 2];
        for _ in 0..20 {
            for (index, count) in counts.iter_mut().enumerate() {
                while granted(&s.acquire(Class::Rule(index), 1, base)) {
                    *count += 1;
                }
            }
        }
        assert!(counts[1] > 0, "the low-weight class must still be scheduled, not starved");
        assert!(
            counts[0] >= 2 * counts[1],
            "weights 3:1 must give the heavy class at least twice the count: {counts:?}"
        );
        assert!(counts[0] <= 4 * counts[1], "weights 3:1 are a share, not a monopoly: {counts:?}");
    }

    /// A class with no rival holding demand takes the whole bucket under
    /// `WeightedRoundRobin`, rather than stalling once its own credits run
    /// out. A round is over when everyone *who wants it* has had their share.
    ///
    /// *Ablation:* refill only when `credits[index] == 0` for every class
    /// including those with no demand — this loop stops after three grants
    /// and reddens.
    #[test]
    fn weighted_round_robin_does_not_wait_for_a_class_with_nothing_to_send() {
        let base = Instant::now();
        let s = shared_bucket(
            None,
            0,
            Discipline::WeightedRoundRobin,
            &[("a", 0, 3), ("b", 0, 1)],
            base,
        );
        s.declare_demand(Class::Rule(0));
        for i in 0..20 {
            assert!(granted(&s.acquire(Class::Rule(0), 1, base)), "grant {i} was refused");
        }
    }

    /// `Fifo` arbitrates nothing: demand from another class changes no
    /// answer, and the bucket is the only thing that can refuse.
    ///
    /// This is the control for the two discipline tests above — without it
    /// they could both be passing because `acquire` refuses whenever *any*
    /// other class has demand.
    #[test]
    fn fifo_never_parks_a_class() {
        let base = Instant::now();
        let s = shared_bucket(None, 0, Discipline::Fifo, &[("a", 9, 1), ("b", 0, 1)], base);
        s.declare_demand(Class::Rule(0));
        for _ in 0..10 {
            assert!(granted(&s.acquire(Class::Rule(1), 1_000, base)));
        }
    }

    /// A withdrawal that outnumbers its declarations does not wrap the count
    /// into a permanent block.
    ///
    /// The queue withdraws from `clear`, from the teardown drain and from
    /// `Drop`, and those can overlap; a `u64` going through zero would make
    /// a class look like it had four billion streams waiting and starve
    /// everything under it for the rest of the session.
    #[test]
    fn withdrawing_more_than_was_declared_saturates_at_zero() {
        let base = Instant::now();
        let s =
            shared_bucket(None, 0, Discipline::StrictPriority, &[("hi", 9, 1), ("lo", 0, 1)], base);
        s.declare_demand(Class::Rule(0));
        s.withdraw_demand(Class::Rule(0));
        s.withdraw_demand(Class::Rule(0));
        s.withdraw_demand(Class::Rule(0));
        assert!(granted(&s.acquire(Class::Rule(1), 1, base)));
    }
}

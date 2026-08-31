//! Egress shaping — the configuration a scenario author writes, and the
//! pure primitives the scheduler is built from.
//!
//! A [`ShapeProfile`] describes what one session's *media* egress is
//! allowed to do: named token buckets, class rules that aim a [`Matcher`]
//! at a bucket, one bounded-queue policy, and a [`Discipline`] that
//! arbitrates between classes competing for the same bucket. Control
//! streams are never shaped — pacing SUBSCRIBE and ANNOUNCE behind a video
//! bucket would stall MoQT's normal steady state and make an idle control
//! stream look like a dead session.
//!
//! # Why this module is `pub`
//!
//! Unlike the engine internals (`egress`, `exec`, `release_timer`), a
//! scenario author *constructs* these types, so they are public and every
//! item below carries a rustdoc comment.
//!
//! # The two constructor shapes, and why they differ
//!
//! [`ShapeProfile`] has **private fields and a fallible constructor**. A
//! mis-typed bucket name would otherwise be a silently inert class —
//! configuration that looks applied and does nothing, which is exactly the
//! failure this module exists to make impossible. [`ShapeProfile::try_new`]
//! rejects it, so an invalid profile cannot reach a session and there is no
//! runtime *your config was rejected* path to miss.
//!
//! The four config structs it is built from — [`BucketConfig`],
//! [`ClassRule`], [`Matcher`] and [`QueueConfig`] — are the opposite:
//! all-public fields and `#[non_exhaustive]` **with** a [`Default`],
//! exactly as [`EgressConfig`](crate::action::EgressConfig) is. The pairing
//! is load-bearing rather than stylistic: `#[non_exhaustive]` on its own
//! makes a struct unconstructible outside this crate, because
//! struct-expression *and* functional-update syntax are both illegal there
//! — the entire public configuration surface would be unreachable from an
//! integration-test crate and from every scenario author's code.
//!
//! Note precisely what the `Default` buys, because it is one step less than
//! it looks: `..Default::default()` is **also** `E0639` outside this crate,
//! so an outside caller writes `let mut m = Matcher::default();` followed by
//! per-field assignment — which is what `tests/actions_shaping.rs` does at
//! every construction site. What the `Default` provides is a *value* to
//! start from, not a syntax. Inside this crate both forms compile, which is
//! why the unit tests below use the shorter one; a sentence claiming the
//! functional-update form works for a scenario author was measured false
//! (11 × `E0639` out of tree, on all four structs).
//!
//! # State of the module
//!
//! The types, [`Matcher::matches`], [`ShapeProfile::try_new`]'s validation
//! and the pure token bucket ([`charge`]) landed first, with their own unit
//! tests, so the scheduler that consumes them lands against arithmetic that
//! is already gated.
//!
//! A configured [`ShapeProfile`] arms framing on its own
//! (`ProxySessionConfig::shape`), [`ShapeStats`] is recorded and readable
//! through
//! [`ProxySession::shape_stats`](crate::session::ProxySession::shape_stats),
//! **admission** runs — per-unit classification through [`Matcher`], the
//! per-stream queue depth and all three [`Overflow`] policies — and so does
//! **release**: every shaped unit is queued rather than written inline, its
//! class's token bucket is debited at `PendingQueue::pop_next_due`, the
//! configured [`Discipline`] arbitrates between classes sharing a bucket,
//! and [`Expiry`] decides what becomes of a unit that outlives `max_hold`.
//!
//! The same figures are kept a second time for a whole proxy. [`ProxyStats`]
//! — [`LegStats`], [`SessionStats`] and the class rows — is read through
//! [`ProxyControl::stats`](crate::control::ProxyControl::stats) and covers
//! every session the proxy has accepted, including the ones that have already
//! ended, so it is cumulative where `ProxySession::shape_stats` is one
//! session's own. It is charged by the same writers, forwarded from inside
//! each one, so no figure can reach a session's rows and miss the proxy's.
//! The one shape difference is worth knowing before reading a cell: a
//! session's totals carry a direction only, while a proxy's carry a leg *and*
//! a direction, because a proxy holds two connections and a byte crosses
//! both. [`LegStats`] states which cell each measurement lands in.
//!
//! Two things are deliberately outside that: **control streams**, which
//! install no scheduler at all, and **teardown**, which drains ignoring
//! release times so a bucket can never gate a mirrored reset.
//!
//! **An object too large for the framer to buffer is outside it as well, and
//! says so.** Such an object has no `ObjectMeta`, so no rule can name it, so no
//! bucket charges it and it is granted unconditionally — one object can
//! therefore cross a class's rate whole. Measured: a 4 MiB object crossed in
//! 800 ms against a class whose bucket was configured at zero bytes per second.
//! The bytes are accounted on [`ShapeStats::unshapeable`] and the session
//! reports `Impairment{ShapeUnpacedObject}`, once per stream, naming the class
//! the stream's other units are charged to — because *my 500 kbps cap was
//! breached by one large segment* is otherwise a hole in the accounting with
//! nothing to attribute it to.
//!
//! **Datagrams are policed rather than paced**, which is a different
//! operation and not a lesser one. `forward_datagrams` classifies each
//! datagram through [`Matcher::matches_datagram`], asks its class's bucket
//! for the bytes, and **discards** what the bucket refuses instead of
//! queuing it. Nothing on that path delays anything, and nothing should: a
//! FIFO would impose a delivery order the protocol does not have, and a
//! datagram has neither a successor written against it nor a stream whose
//! object IDs would move behind a hole — which is exactly what makes
//! dropping the arriving unit sound here and unsound for a queued stream
//! unit.
//!
//! What follows from that shape, and is worth knowing before reading a
//! figure: [`QueueConfig`] is **not consulted** for a datagram. Neither
//! depth binds it and no [`Overflow`] policy decides it, because it is never
//! queued — the bucket is the whole of the decision. A profile that shapes
//! subgroup streams and polices datagrams reads its queue policy for the
//! first and not for the second.
//!
//! **This is settled rather than pending, and the sharp edge is worth stating
//! outright:** the bucket can answer *not now, but at this instant* — the
//! same answer that defers a stream unit — and on the datagram path that
//! answer is discarded like every other refusal. A datagram over a live rate
//! is dropped where it arrived, not held until the instant its own bucket
//! named.
//!
//! **If what is wanted is smoothing, reach for `quinn-netem`.** It delays,
//! jitters and reorders at the socket, under the whole connection, which is
//! the scope a link-level queue has: a bottleneck queues by link, not by
//! track, and a router does not know which track a datagram belongs to.
//! Class-aware policing is a real box — an operator rate-limiter drops over
//! rate — while class-aware smoothing is a scheduler *inside* a router, which
//! is not a condition a player is ever placed in. So netem's not being
//! class-aware is the right scope for it rather than a gap in it, and the
//! division is: **a rate on one track is a class over a bucket, and belongs
//! here; a congested path is netem.**
//!
//! The framed sites keep their `Delay` and `Hold` because a stream **has** a
//! delivery order — holding object N and then N+1 preserves a guarantee the
//! protocol makes, where holding two datagrams would manufacture one.
//!
//! There is no seam a datagram never reaches. There was one — a report a
//! `Fetch`-aimed class made on drafts 18 and 19, where the framer bypassed
//! every fetch stream before any `ObjectMeta` existed — and it went when
//! those streams became readable. Every unmatchable rule now reports from a
//! unit that arrived, through `Scheduler::classify` or its datagram sibling.
//!
//! # What is still owed
//!
//! [`BucketConfig::ceil_bps`] is accepted and never borrowed against: a
//! profile setting it above `rate_bps` measures a flat `rate_bps`.
//!
//! Nothing else, and there used to be more: five reported fields here
//! snapshotted as a constant zero. Two of them counted what a **hook** does,
//! which needs no profile at all while every figure on this page is gated on
//! one, and they are
//! [`Counters::units_delayed`](crate::instrument::Counters::units_delayed)
//! and
//! [`Counters::objects_truncated`](crate::instrument::Counters::objects_truncated)
//! now. The other three were `Duration` totals; [`ClassStats`] says why this
//! page carries no duration at all.
//!
//! Separately, and not the same kind of zero: of the five figures a
//! [`DirectionStats`] carries, only `objects_seen` and `bytes_shaped` are
//! measured at both crossings, so the three event figures read zero in a
//! **departure** cell of [`ProxyStats::per_leg`]. [`LegStats`] says which
//! cell is which.

mod bucket;
mod matcher;
mod scheduler;
mod stats;

pub use bucket::{charge, BucketConfig, BucketState, Grant};
pub use matcher::{MatchKind, Matcher, MatcherField, RangeSet};
pub use stats::{ClassStats, DirectionStats, LegStats, ProxyStats, SessionStats, ShapeStats};

pub(crate) use scheduler::{Acquire, Admission, Class, QueueDepth, Scheduler};
pub(crate) use stats::{ProxyRecorder, ShapeRecorder};

use std::collections::HashSet;
use std::time::Duration;

use crate::types::ProxySide;

/// A complete egress shaping configuration for one session.
///
/// Constructed only through [`ShapeProfile::try_new`], which validates the
/// combination — an invalid profile cannot reach a session, so there is no
/// runtime *your config was rejected* path to miss.
///
/// Not `#[non_exhaustive]`: the fields are private, so the attribute would
/// add nothing a caller could observe.
///
/// # Reading one from a file
///
/// Under the non-default `serde` feature this type serializes and
/// deserializes, and the two directions are **not symmetric**. Serializing is
/// a derive over the private fields, which is safe because writing a profile
/// out cannot make an invalid one. Deserializing goes
/// `#[serde(try_from = "ShapeProfileSpec")]`, through a public-field mirror
/// whose `TryFrom` calls [`ShapeProfile::try_new`].
///
/// The detour is the whole point. A derived `Deserialize` would reach these
/// private fields directly and bypass every one of the seven validations below
/// — including [`ShapeError::UnknownBucket`], where a file naming a bucket
/// that does not exist would parse, arm, report shaping and shape nothing.
/// Routing through the mirror means there is no deserialization path that
/// skips the constructor, and no consumer has to remember to convert.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "ShapeProfileSpec"))]
pub struct ShapeProfile {
    buckets: Vec<BucketConfig>,
    classes: Vec<ClassRule>,
    queue: QueueConfig,
    discipline: Discipline,
}

impl ShapeProfile {
    /// Validate a profile and build it, or say exactly what is wrong.
    ///
    /// The seven rejections, in the order they are checked:
    ///
    /// 1. [`ShapeError::EmptyQueue`] — a queue that can hold nothing.
    /// 2. [`ShapeError::NoClasses`] — a profile with no class rules at all,
    ///    which is a shaping profile that shapes nothing.
    /// 3. [`ShapeError::DuplicateClassName`] — class names index the
    ///    statistics, so duplicates make them unattributable.
    /// 4. [`ShapeError::UnknownBucket`] — a class naming a bucket that is
    ///    not in `buckets`; the silently-inert class this constructor
    ///    exists to prevent.
    /// 5. [`ShapeError::EgressSideInMatcher`] — a matcher keyed on an
    ///    egress side, which no hook site ever sees.
    /// 6. [`ShapeError::ZeroWeight`] — a zero weight under
    ///    [`Discipline::WeightedRoundRobin`], which is a class that can
    ///    never be scheduled.
    /// 7. [`ShapeError::InertMatcher`] — a matcher key naming an *empty set
    ///    of values*, which is a class that can never claim a unit.
    ///
    /// The second is checked **outside** the loop below, and that is the
    /// point of it: every other class rule is checked *inside* a
    /// `for class in &classes`, and a loop over nothing runs no checks at
    /// all. A profile with no classes was therefore the one shape that could
    /// pass every rule here by not being subject to any of them.
    ///
    /// Duplicate *bucket* names are not an error: two identical entries
    /// resolve to the same bucket and the first one wins, which is what a
    /// caller who wrote the name twice meant. Only class names index
    /// anything.
    ///
    /// # What this constructor cannot see, and why the line is there
    ///
    /// Every check above is a property of the **configuration alone**. What
    /// it deliberately does not attempt is anything that depends on the
    /// draft or on the traffic, and there are two such faults; both are
    /// reported during the run instead, because a rejection here has to be
    /// right for *every* session the profile could be used in.
    ///
    /// A key the wire does not carry on this draft is
    /// `Impairment{ShapeRuleUnmatchable}` — `try_new` has no draft. And a
    /// [`BucketConfig::burst_bytes`] smaller than the objects a class
    /// actually sees is
    /// `Impairment{ShapeBurstBelowUnit}` — `try_new` has the burst but not
    /// the object sizes, and the sizes are what decide. The second is worth
    /// the attention because its silent form is so plausible: a burst below
    /// one object makes every unit leave at its `max_hold` clamp, at a
    /// throughput with no relation to the rate that was configured, and
    /// before the report existed the only signal was the one an ordinary
    /// rate-limited class produces.
    pub fn try_new(
        buckets: Vec<BucketConfig>,
        classes: Vec<ClassRule>,
        queue: QueueConfig,
        discipline: Discipline,
    ) -> Result<Self, ShapeError> {
        if queue.depth_bytes == 0 || queue.depth_objects == 0 {
            return Err(ShapeError::EmptyQueue);
        }
        // Before the loop, because the loop is what every other rule lives
        // in and an empty list is the one input it cannot judge.
        if classes.is_empty() {
            return Err(ShapeError::NoClasses);
        }

        let mut seen: HashSet<&str> = HashSet::with_capacity(classes.len());
        for class in &classes {
            if !seen.insert(class.name.as_str()) {
                return Err(ShapeError::DuplicateClassName { name: class.name.clone() });
            }
            if !buckets.iter().any(|b| b.name == class.bucket) {
                return Err(ShapeError::UnknownBucket {
                    class: class.name.clone(),
                    bucket: class.bucket.clone(),
                });
            }
            if matches!(
                class.matcher.side,
                Some(ProxySide::ProxyToClient) | Some(ProxySide::ProxyToRelay)
            ) {
                return Err(ShapeError::EgressSideInMatcher { class: class.name.clone() });
            }
            if discipline == Discipline::WeightedRoundRobin && class.weight == 0 {
                return Err(ShapeError::ZeroWeight { class: class.name.clone() });
            }
            if let Some(key) = class.matcher.inert_key() {
                return Err(ShapeError::InertMatcher { class: class.name.clone(), key });
            }
        }

        Ok(Self { buckets, classes, queue, discipline })
    }

    /// The configured buckets, in the order they were given.
    pub fn buckets(&self) -> &[BucketConfig] {
        &self.buckets
    }

    /// The configured class rules, in the order they were given — which is
    /// also the order the statistics snapshot reports them in, and the
    /// order [`Discipline::Fifo`] tie-breaks on.
    pub fn classes(&self) -> &[ClassRule] {
        &self.classes
    }

    /// The per-stream queue policy.
    pub fn queue(&self) -> &QueueConfig {
        &self.queue
    }

    /// How classes competing for one bucket are arbitrated.
    pub fn discipline(&self) -> Discipline {
        self.discipline
    }
}

/// Why a [`ShapeProfile`] could not be built.
///
/// `#[non_exhaustive]` and no `Default`: nobody constructs an error, and a
/// later release adding a further reason must not be a breaking change.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ShapeError {
    /// Two classes share a name. Class names index the stats, so they must
    /// be unique or the stats are unattributable.
    #[error("duplicate class name: {name}")]
    DuplicateClassName {
        /// The name that appeared more than once.
        name: String,
    },
    /// A class names a bucket that is not in `buckets`.
    #[error("class {class} names unknown bucket {bucket}")]
    UnknownBucket {
        /// The class holding the dangling reference.
        class: String,
        /// The bucket name that matches no [`BucketConfig`].
        bucket: String,
    },
    /// A matcher's `side` is an egress label. Hook sites only ever see
    /// `ClientToProxy` / `RelayToProxy`, so such a rule matches nothing —
    /// rejected here rather than left to look like a working rule that
    /// never fires.
    #[error("class {class} matches on an egress side, which no hook site sees")]
    EgressSideInMatcher {
        /// The class whose matcher named an egress side.
        class: String,
    },
    /// [`Discipline::WeightedRoundRobin`] with a zero weight: a class that
    /// can never be scheduled.
    #[error("class {class} has weight 0 under WeightedRoundRobin")]
    ZeroWeight {
        /// The class whose weight is zero.
        class: String,
    },
    /// [`QueueConfig::depth_objects`] or [`QueueConfig::depth_bytes`] is
    /// zero, so the queue could admit nothing.
    #[error("queue depth is zero in bytes or in objects")]
    EmptyQueue,
    /// The profile declares no class rules, so it is a shaping profile that
    /// shapes nothing.
    ///
    /// Every unit such a profile sees falls to `Class::Default`, which is
    /// unpaced: no bucket claims it, no discipline arbitrates it and the
    /// queue releases it as soon as it reaches the head. A session
    /// configured with one therefore frames every object — because a profile
    /// arms framing on its own — pays for the classification and the queue,
    /// reports itself as shaping, and delivers at line rate. Nothing in
    /// [`crate::shape::ShapeStats`] distinguishes it from a profile whose
    /// classes never matched.
    ///
    /// # It also used to reach further than the session that carried it
    ///
    /// A proxy sizes its class rows once, from the first shaped session it
    /// accepts, because a class is an index into the class list of the
    /// scheduler that produced it and rows that could be resized underneath
    /// a running session would relabel every figure in them. A classless
    /// profile arriving first would have installed **no rows at all**, and
    /// every classed session accepted afterwards — for the life of the proxy
    /// — would have found rows it did not match and charged the default one:
    /// every number right, every label gone, unrecoverable without a
    /// restart. That is guarded a second time where the sizing happens, but
    /// the guard is a repair at the far end of the pipe; this is the profile
    /// never existing.
    ///
    /// A caller who wants the queue policy and no pacing writes one class
    /// claiming everything, over a bucket with no rate — an explicitly
    /// unshaped class, which has a name and a row of its own and says in the
    /// configuration what a missing class list only implied.
    #[error(
        "a shaping profile with no classes shapes nothing: every unit falls to the unpaced \
         default class. Declare a class over a rate-less bucket if that is what was meant"
    )]
    NoClasses,
    /// A [`Matcher`] key names an **empty set of values**, so the class can
    /// never claim a unit — on any draft, from any traffic.
    ///
    /// The three shapes this catches, all of which were accepted before:
    /// a [`RangeSet`] built from an inverted range (`RangeSet::new` drops
    /// `start > end`, leaving an empty set whose `contains` is always
    /// `false`), an empty [`Matcher::priority`] range such as `200..=100`,
    /// and [`Matcher::every_nth`] with `n == 0`.
    ///
    /// Distinct from
    /// [`ImpairmentKind::ShapeRuleUnmatchable`](crate::event::ImpairmentKind::ShapeRuleUnmatchable),
    /// and the distinction is *when the answer exists*: a rule keyed on a
    /// field this draft does not carry can only be judged against a running
    /// session, so it is reported; an empty value set is a property of the
    /// configuration by itself, so it is rejected before a session starts.
    /// Rejecting is strictly the better answer where it is available —
    /// there is no run to read the report from.
    #[error("class {class} keys on {key}, which names no value at all")]
    InertMatcher {
        /// The class whose matcher can never claim anything.
        class: String,
        /// The key that names the empty set, spelled as the
        /// [`Matcher`] field is: one of `track_alias`, `group_id`,
        /// `subgroup_id`, `object_id`, `priority`, `every_nth`.
        key: &'static str,
    },
}

/// A matcher plus what to do with what it matches.
///
/// `#[non_exhaustive]` *with* a [`Default`] — see the module doc for why
/// the pairing is required rather than stylistic. The default is an
/// unnamed class that claims every unit and names no bucket, so it is
/// always edited before use; note that a defaulted `weight` of zero is
/// rejected under [`Discipline::WeightedRoundRobin`].
///
/// In the written form `name` and `bucket` are required and the other three
/// default, because the two that are required are the two whose defaults are
/// wrong rather than merely empty: an unnamed class collides with the next
/// unnamed class as [`ShapeError::DuplicateClassName`], and a class naming no
/// bucket at all is [`ShapeError::UnknownBucket`] against the empty string.
/// Both are refusals about a key the author never wrote.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
#[non_exhaustive]
pub struct ClassRule {
    /// The class name. Unique across the profile, and the label under
    /// which this class's statistics are reported.
    pub name: String,
    /// Which units this class claims.
    #[cfg_attr(feature = "serde", serde(default))]
    pub matcher: Matcher,
    /// The [`BucketConfig::name`] this class charges against. Several
    /// classes may share one bucket, which is what makes [`Discipline`]
    /// mean anything.
    pub bucket: String,
    /// [`Discipline::StrictPriority`] orders classes by this; higher wins.
    ///
    /// Distinct from MoQT's `publisher_priority`, which
    /// [`Matcher::priority`] keys on: this one is the scheduler's, and it
    /// is always present.
    #[cfg_attr(feature = "serde", serde(default))]
    pub priority: u8,
    /// [`Discipline::WeightedRoundRobin`] shares a bucket by this. Zero is
    /// rejected under that discipline and ignored under the other two.
    #[cfg_attr(feature = "serde", serde(default))]
    pub weight: u16,
}

/// The per-stream queue policy: how deep, how long, and what happens at
/// each limit.
///
/// `#[non_exhaustive]` *with* a [`Default`] — see the module doc.
///
/// The `Default` is **hand-written, not derived**: a derived one would
/// give `depth_bytes == 0` and `depth_objects == 0`, which
/// [`ShapeProfile::try_new`] rejects as [`ShapeError::EmptyQueue`] — so
/// `QueueConfig::default()` would be a value that cannot be used, and the
/// `..Default::default()` idiom this type is built for would fail on every
/// profile that did not restate both depths.
///
/// That hand-written `Default` is also what the written form defaults every
/// key to, so a scenario file may omit `queue` entirely or name only the one
/// knob it cares about. It is the one config in this module where the derived
/// default would be the unusable value and the written default is therefore
/// worth having.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(default, deny_unknown_fields))]
#[non_exhaustive]
pub struct QueueConfig {
    /// Bytes one stream's queue may hold. Defaults to 1 MiB, matching
    /// [`EgressConfig::max_pending_bytes`](crate::action::EgressConfig::max_pending_bytes).
    pub depth_bytes: usize,
    /// Objects one stream's queue may hold. Defaults to 256 — a limit the
    /// byte depth does not imply, since a queue of small objects reaches
    /// neither.
    pub depth_objects: usize,
    /// Deadline for a queued object, per class. `None` inherits
    /// [`EgressConfig::max_hold`](crate::action::EgressConfig::max_hold),
    /// which is 30 s.
    ///
    /// Pin this explicitly in any fixture that relies on a class *not*
    /// delivering: under the default [`Expiry::Deliver`] a starved class
    /// still delivers at `max_hold`, so an unnamed 30 s is a margin the
    /// test inherited rather than chose.
    pub max_hold: Option<Duration>,
    /// What happens when the queue is full.
    pub overflow: Overflow,
    /// What happens when a queued object outlives `max_hold`.
    pub on_expiry: Expiry,
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            depth_bytes: 1024 * 1024,
            depth_objects: 256,
            max_hold: None,
            overflow: Overflow::default(),
            on_expiry: Expiry::default(),
        }
    }
}

/// What happens when a per-stream queue is full.
///
/// `#[non_exhaustive]`, with `Block` as the [`Default`]: the only
/// non-destructive answer is the one a caller gets without asking.
///
/// There is deliberately no `DropHead`. Dropping an *already queued* unit
/// happens after the framer's positional cursor has moved past it, so the
/// elide fix-up can no longer be armed — and on drafts 14-19 object IDs are
/// delta-encoded, so the result is not a gap but every successor decoding
/// with a wrong absolute ID. [`Overflow::DropTail`] is sound for exactly
/// the reason `DropHead` is not: it discards the *arriving* unit, at
/// admission time, where the fix-up is still legal.
///
/// Written as `"block"`, `"drop-tail"` or `{"reset-stream": {"code": 1}}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case", deny_unknown_fields))]
#[non_exhaustive]
pub enum Overflow {
    /// Stop reading the source. Non-destructive. **Default.**
    ///
    /// Per stream, and it does not reliably stall the *peer*: the
    /// transport's own receive window absorbs megabytes first.
    #[default]
    Block,
    /// Discard the *arriving* unit. Renumbers via the framer's own elide
    /// fix-up, so absolute object IDs stay correct on drafts 14-19.
    ///
    /// When an elide guard refuses the fix-up the unit is admitted anyway —
    /// the queue overshoots by one — and the refusal is reported. A shaper
    /// may not corrupt a stream to honour a depth limit.
    DropTail,
    /// Abandon the destination stream.
    ResetStream {
        /// The application error code to reset with.
        code: u64,
    },
}

/// What happens when a queued object outlives `max_hold`.
///
/// `#[non_exhaustive]`, with `Deliver` as the [`Default`] — which is
/// exactly today's behaviour, so nothing changes for a session that does
/// not ask for shaping.
///
/// There is deliberately **no** `Drop` variant. An expiry is decided at
/// release time, long after the framer's positional cursor has advanced
/// past the object, so the elide fix-up cannot be armed; on drafts 14-19
/// that corrupts every successor's absolute ID. A variant that is
/// constructible and always refused is worse than an absent one.
///
/// The cost of the pick, stated so nobody rediscovers it: *the relay gave up on
/// stale media* is expressible only at *stream* granularity, and
/// `objects_expired` is therefore zero by default, with a producer only on the
/// [`Expiry::ResetStream`] arm.
///
/// Written as `"deliver"` or `{"reset-stream": {"code": 1}}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case", deny_unknown_fields))]
#[non_exhaustive]
pub enum Expiry {
    /// Clamp the deadline and deliver anyway. Today's behaviour, and the
    /// reason a starved class still delivers at `max_hold`. **Default.**
    #[default]
    Deliver,
    /// Give up on the stream: drain what is due, then reset.
    ResetStream {
        /// The application error code to reset with.
        code: u64,
    },
}

/// How classes competing for the same bucket are arbitrated.
///
/// `#[non_exhaustive]`, with `Fifo` as the [`Default`]. The discipline only
/// decides *between* classes; within one destination stream the queue stays
/// a single FIFO whatever this says, because object IDs are delta-encoded
/// on the wire and reordering them corrupts the chain.
///
/// Written as `"fifo"`, `"strict-priority"` or `*weighted-round-robin*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[non_exhaustive]
pub enum Discipline {
    /// Whoever asked first. **Default.**
    #[default]
    Fifo,
    /// Highest [`ClassRule::priority`] first, and only then the rest.
    StrictPriority,
    /// Share by [`ClassRule::weight`]. A zero weight is rejected by
    /// [`ShapeProfile::try_new`] under this discipline.
    WeightedRoundRobin,
}

/// Identifies one forwarded stream within a session.
///
/// A **session-local monotonic id**, minted from one counter per session at
/// the moment the session accepts the stream, plus the side it arrived on.
/// Unique for the session's lifetime and never reused.
///
/// Deliberately **not** a media key: `subgroup_id` is absent on eight
/// drafts and `track_alias` on every fetch stream, so a media-keyed
/// serialize would silently miss.
///
/// Deliberately **not** the transport stream id either. On the WebTransport
/// arm `SendStream::stream_id()` is the constant `0`
/// (`moqtap-client/src/transport/mod.rs:133-137`), and the proxy really
/// does accept WebTransport clients — so a transport-keyed `StreamKey`
/// collapses every WT stream onto one entry per side. A serialize would
/// then attach a stream to an arbitrary sibling, or to itself, which is a
/// self-deadlock that degrades to a `max_hold` stall, and every per-stream
/// report becomes unattributable.
///
/// The transport id is still worth reporting where it means something, so
/// it stays a separate field on the events that carry both.
/// `Hash` is hand-written because [`ProxySide`] does not derive it and
/// lives in a module this type may not edit. It hashes the side's
/// discriminant, so it agrees with the derived [`PartialEq`] exactly:
/// equal keys hash equal, which is the whole obligation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamKey {
    /// The direction the stream was accepted on.
    pub side: ProxySide,
    /// Session-local monotonic id. Never reused within a session, and not
    /// comparable across sessions.
    pub id: u64,
}

impl std::hash::Hash for StreamKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::mem::discriminant(&self.side).hash(state);
        self.id.hash(state);
    }
}

/// The written form of a [`ShapeProfile`].
///
/// # Why the mirror exists
///
/// [`ShapeProfile`]'s four fields are private, and that is the whole of its
/// safety: [`ShapeProfile::try_new`] is the only way to build one, and it
/// refuses seven configurations that would otherwise arm and do nothing —
/// chief among them a class naming a bucket that is not in `buckets`, which
/// reports shaping and shapes nothing, and a profile with no classes at all,
/// which matches nothing there is to match.
///
/// A derived `Deserialize` on `ShapeProfile` would reach those private fields
/// directly and bypass all seven. So `ShapeProfile` deserializes
/// `#[serde(try_from = "ShapeProfileSpec")]` instead: serde builds *this*
/// type, whose fields are public and whose only job is to be built, and the
/// [`TryFrom`] impl runs `try_new`. Every deserialization path therefore
/// validates, and no consumer has to remember to convert — which matters
/// because the consumer is usually a field on some caller's own
/// configuration type, reached by someone who never names this one at all.
///
/// The reverse direction, [`From<&ShapeProfile>`](ShapeProfileSpec), exists so
/// a caller can take a profile apart, edit it and rebuild it through the same
/// validation.
///
/// `#[non_exhaustive]` **with** a [`Default`], as the shaping configs are: the
/// attribute makes struct-expression and functional-update syntax illegal
/// outside this crate, so the `Default` is what leaves a construction path
/// open — `let mut spec = ShapeProfileSpec::default();` and then per-field
/// assignment.
#[cfg(feature = "serde")]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ShapeProfileSpec {
    /// The token buckets, by name. A class names one of these.
    pub buckets: Vec<BucketConfig>,
    /// The class rules, in the order they are matched — which is also the
    /// order the statistics report them in.
    pub classes: Vec<ClassRule>,
    /// The per-stream queue policy. Defaults to
    /// [`QueueConfig::default`], which is a usable policy rather than a
    /// placeholder.
    #[serde(default)]
    pub queue: QueueConfig,
    /// How classes sharing a bucket are arbitrated. Defaults to
    /// [`Discipline::Fifo`].
    #[serde(default)]
    pub discipline: Discipline,
}

#[cfg(feature = "serde")]
impl TryFrom<ShapeProfileSpec> for ShapeProfile {
    type Error = ShapeError;

    fn try_from(spec: ShapeProfileSpec) -> Result<Self, Self::Error> {
        ShapeProfile::try_new(spec.buckets, spec.classes, spec.queue, spec.discipline)
    }
}

#[cfg(feature = "serde")]
impl From<&ShapeProfile> for ShapeProfileSpec {
    fn from(profile: &ShapeProfile) -> Self {
        Self {
            buckets: profile.buckets().to_vec(),
            classes: profile.classes().to_vec(),
            queue: profile.queue().clone(),
            discipline: profile.discipline(),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn bucket(name: &str) -> BucketConfig {
        BucketConfig {
            name: name.to_string(),
            rate_bps: Some(64_000),
            burst_bytes: 16_000,
            ..BucketConfig::default()
        }
    }

    fn class(name: &str) -> ClassRule {
        ClassRule {
            name: name.to_string(),
            bucket: "b".to_string(),
            weight: 1,
            ..ClassRule::default()
        }
    }

    /// A profile that `try_new` accepts, so every rejection below is
    /// attributable to the one field its row edits.
    fn valid() -> (Vec<BucketConfig>, Vec<ClassRule>, QueueConfig, Discipline) {
        (
            vec![bucket("b")],
            vec![class("audio"), class("video")],
            QueueConfig::default(),
            Discipline::Fifo,
        )
    }

    #[test]
    fn a_valid_profile_round_trips_through_its_accessors() {
        let (buckets, classes, queue, discipline) = valid();
        let p = ShapeProfile::try_new(buckets, classes, queue.clone(), discipline)
            .expect("the control profile must be valid or every rejection below is unattributable");
        assert_eq!(p.buckets().len(), 1);
        assert_eq!(
            p.classes().iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
            ["audio", "video"]
        );
        assert_eq!(p.queue(), &queue);
        assert_eq!(p.discipline(), Discipline::Fifo);
    }

    /// The named single case for the egress-side rejection.
    ///
    /// Kept beside the table below rather than folded into it: this is the
    /// one rejection that is about the *proxy's* topology rather than about
    /// the profile's internal consistency, and it is the rejection a
    /// scenario author is most likely to trip.
    #[test]
    fn try_new_rejects_an_egress_side() {
        for side in [ProxySide::ProxyToClient, ProxySide::ProxyToRelay] {
            let (buckets, mut classes, queue, discipline) = valid();
            classes[1].matcher.side = Some(side);
            assert_eq!(
                ShapeProfile::try_new(buckets, classes, queue, discipline),
                Err(ShapeError::EgressSideInMatcher { class: "video".to_string() }),
                "{side:?} is an egress label and no hook site ever sees it"
            );
        }

        // The two ingress sides are accepted, so the rejection is about the
        // direction and not about the field being set at all.
        for side in [ProxySide::ClientToProxy, ProxySide::RelayToProxy] {
            let (buckets, mut classes, queue, discipline) = valid();
            classes[1].matcher.side = Some(side);
            assert!(ShapeProfile::try_new(buckets, classes, queue, discipline).is_ok());
        }
    }

    /// One row per `ShapeError` variant. Seven variants, seven rows, and
    /// the count is asserted so an eighth variant cannot be added without a
    /// row.
    #[test]
    fn try_new_rejects_every_invalid_profile() {
        type Edit =
            fn(&mut Vec<BucketConfig>, &mut Vec<ClassRule>, &mut QueueConfig, &mut Discipline);

        let rows: [(&str, Edit, ShapeError); 7] = [
            (
                "two classes share a name",
                |_b, c, _q, _d| c[1].name = "audio".to_string(),
                ShapeError::DuplicateClassName { name: "audio".to_string() },
            ),
            (
                "a class names a bucket that is not configured",
                |_b, c, _q, _d| c[1].bucket = "nope".to_string(),
                ShapeError::UnknownBucket {
                    class: "video".to_string(),
                    bucket: "nope".to_string(),
                },
            ),
            (
                "a matcher names an egress side",
                |_b, c, _q, _d| c[1].matcher.side = Some(ProxySide::ProxyToClient),
                ShapeError::EgressSideInMatcher { class: "video".to_string() },
            ),
            (
                "weighted round robin with a zero weight",
                |_b, c, _q, d| {
                    *d = Discipline::WeightedRoundRobin;
                    c[1].weight = 0;
                },
                ShapeError::ZeroWeight { class: "video".to_string() },
            ),
            (
                "a queue that can hold nothing",
                |_b, _c, q, _d| q.depth_objects = 0,
                ShapeError::EmptyQueue,
            ),
            (
                "a matcher key that names no value at all",
                |_b, c, _q, _d| c[1].matcher.every_nth = Some((0, 0)),
                ShapeError::InertMatcher { class: "video".to_string(), key: "every_nth" },
            ),
            (
                "a profile with no class rules at all",
                |_b, c, _q, _d| c.clear(),
                ShapeError::NoClasses,
            ),
        ];

        for (label, edit, want) in rows {
            let (mut buckets, mut classes, mut queue, mut discipline) = valid();
            edit(&mut buckets, &mut classes, &mut queue, &mut discipline);
            assert_eq!(
                ShapeProfile::try_new(buckets, classes, queue, discipline),
                Err(want),
                "{label}"
            );
        }

        // The byte half of `EmptyQueue`, which the row above cannot also
        // cover without testing two fields in one assertion.
        let (buckets, classes, mut queue, discipline) = valid();
        queue.depth_bytes = 0;
        assert_eq!(
            ShapeProfile::try_new(buckets, classes, queue, discipline),
            Err(ShapeError::EmptyQueue)
        );

        // A zero weight is only an error under WeightedRoundRobin, so the
        // fourth row is about the pairing and not about the weight.
        let (buckets, mut classes, queue, discipline) = valid();
        classes[1].weight = 0;
        assert!(ShapeProfile::try_new(buckets, classes, queue, discipline).is_ok());
    }

    /// **`try_new` rejects every class that can never claim anything** —
    /// one of the silent no-ops this constructor exists to make loud.
    /// The constructor's own reason for existing is that *a mis-typed bucket
    /// name would not be a silently inert class — configuration that looks
    /// applied and does nothing*, and it checked five things, none of which was
    /// the matcher's own arithmetic. All three rows below were accepted as
    /// valid profiles and delivered zero bytes in silence; the detector
    /// (`RangeSet::is_empty`) was already written and already public.
    ///
    /// Each row is paired with the **same key holding a real value**, in
    /// the same body, so a rejection cannot be passing because `try_new`
    /// rejects any profile that sets that key at all — which would be a far
    /// worse defect than the one being fixed.
    ///
    /// *Ablation, recorded:* delete the `inert_key` check from `try_new` —
    /// all three rejections redden here, the inert-matcher row of
    /// `try_new_rejects_every_invalid_profile` reddens with it,
    /// and each `left` is the accepted profile printed in full, which is the
    /// point: the thing that ships is a `ShapeProfile` that looks entirely
    /// ordinary and holds `track_alias: Some(RangeSet { ranges: [] })`.
    ///
    /// ```text
    /// assertion `left == right` failed: an inverted track_alias range is an empty
    /// set, so this class can never claim a unit
    ///   left: Ok(ShapeProfile { .. track_alias: Some(RangeSet { ranges: [] }) .. })
    ///  right: Err(InertMatcher { class: "video", key: "track_alias" })
    /// ```
    #[test]
    fn try_new_rejects_a_class_that_can_never_claim_a_unit() {
        // Bound through locals: a literal `9..=1` is a clippy error at the
        // call site (`reversed_empty_ranges`), and a configuration built at
        // runtime is exactly where these come from.
        let (lo, hi) = (9u64, 1u64);
        let (top, bottom) = (200u8, 100u8);

        let build = |edit: &dyn Fn(&mut Matcher)| {
            let (buckets, mut classes, queue, discipline) = valid();
            edit(&mut classes[1].matcher);
            ShapeProfile::try_new(buckets, classes, queue, discipline)
        };
        let inert =
            |key: &'static str| Err(ShapeError::InertMatcher { class: "video".to_string(), key });

        assert_eq!(
            build(&|m| m.track_alias = Some(RangeSet::new([lo..=hi]))),
            inert("track_alias"),
            "an inverted track_alias range is an empty set, so this class can \
             never claim a unit"
        );
        assert_eq!(
            build(&|m| m.priority = Some(top..=bottom)),
            inert("priority"),
            "an empty priority range contains no value, so no header can satisfy it"
        );
        assert_eq!(
            build(&|m| m.every_nth = Some((0, 0))),
            inert("every_nth"),
            "`n == 0` names no units, which `Matcher::matches` answers false for \
             unconditionally"
        );

        // The positive controls: the same three keys holding real values
        // are ordinary working rules.
        assert!(build(&|m| m.track_alias = Some(RangeSet::new([hi..=lo]))).is_ok());
        assert!(build(&|m| m.priority = Some(bottom..=top)).is_ok());
        assert!(build(&|m| m.every_nth = Some((2, 0))).is_ok());

        // And the empty range really is what `RangeSet` stores, so the
        // rejection is about emptiness and not about the literal.
        assert!(RangeSet::new([lo..=hi]).is_empty());
    }

    /// Duplicate *bucket* names are deliberately not an error, unlike
    /// duplicate class names. Pinned so the asymmetry is a decision rather
    /// than an oversight.
    #[test]
    fn duplicate_bucket_names_are_not_an_error() {
        let (_, classes, queue, discipline) = valid();
        assert!(ShapeProfile::try_new(vec![bucket("b"), bucket("b")], classes, queue, discipline)
            .is_ok());
    }

    /// The defaults the `..Default::default()` idiom hands a caller are
    /// usable as they stand — a derived `QueueConfig::default()` would be
    /// `EmptyQueue` and every profile that did not restate both depths
    /// would be rejected.
    #[test]
    fn the_default_queue_config_is_a_profile_that_builds() {
        let (buckets, classes, _, discipline) = valid();
        assert!(ShapeProfile::try_new(buckets, classes, QueueConfig::default(), discipline).is_ok());

        let q = QueueConfig::default();
        assert_ne!(q.depth_bytes, 0);
        assert_ne!(q.depth_objects, 0);
        assert_eq!(q.max_hold, None);
        assert_eq!(q.overflow, Overflow::Block);
        assert_eq!(q.on_expiry, Expiry::Deliver);
        assert_eq!(Discipline::default(), Discipline::Fifo);
    }

    /// `StreamKey` is session-local and side-scoped: the same id on the two
    /// sides is two keys, or a registry entry would be shared by the two
    /// halves of a forwarded pair.
    #[test]
    fn a_stream_key_is_scoped_by_side_as_well_as_id() {
        let a = StreamKey { side: ProxySide::ClientToProxy, id: 1 };
        let b = StreamKey { side: ProxySide::RelayToProxy, id: 1 };
        assert_ne!(a, b);
        assert_eq!(a, StreamKey { side: ProxySide::ClientToProxy, id: 1 });

        let mut set = HashSet::new();
        assert!(set.insert(a));
        assert!(set.insert(b));
        assert!(!set.insert(a));
    }

    /// A profile with one bucket and one class, valid by construction.
    ///
    /// Built with functional-update syntax, which compiles here and would not
    /// outside this crate: `#[non_exhaustive]` makes both the struct literal
    /// and `..Default::default()` illegal there, so a caller assigns per field
    /// on a `::default()` binding instead.
    #[cfg(feature = "serde")]
    fn profile() -> ShapeProfile {
        let bucket = BucketConfig {
            name: "video".to_owned(),
            rate_bps: Some(500_000),
            burst_bytes: 65_536,
            ..Default::default()
        };

        let class = ClassRule {
            name: "video".to_owned(),
            bucket: "video".to_owned(),
            matcher: Matcher {
                side: Some(crate::types::ProxySide::ClientToProxy),
                track_alias: Some(crate::shape::RangeSet::new([1..=3, 9..=9])),
                ..Default::default()
            },
            ..Default::default()
        };

        ShapeProfile::try_new(
            vec![bucket],
            vec![class],
            QueueConfig::default(),
            Discipline::StrictPriority,
        )
        .expect("a profile with one class naming its own bucket is valid")
    }

    /// A `ShapeProfile` serializes into the shape `ShapeProfileSpec` reads
    /// back, and the two derives are on different types — one on the private
    /// fields, one on the mirror — so nothing but this test holds their field
    /// names together. A rename on either side lands here as a parse failure.
    #[cfg(feature = "serde")]
    #[test]
    fn shape_profile_round_trips_through_json() {
        let before = profile();
        let json = serde_json::to_string(&before).expect("a profile serializes");
        let after: ShapeProfile = serde_json::from_str(&json).expect("and reads back");
        assert_eq!(before, after, "round trip through {json}");
    }

    /// A `RangeSet` is written as a plain list of ranges and read back through
    /// `RangeSet::new`, which sorts and coalesces — so a file listing
    /// overlapping ranges in any order produces the same set as one listing
    /// them merged, and `contains` cannot be reading an unsorted vector.
    #[cfg(feature = "serde")]
    #[test]
    fn range_sets_coalesce_when_they_are_read() {
        let json = r#"[{"start":4,"end":6},{"start":1,"end":3}]"#;
        let set: crate::shape::RangeSet = serde_json::from_str(json).expect("ranges parse");
        assert_eq!(set.ranges(), &[1..=6], "adjacent ranges are one range after a read");
    }
}

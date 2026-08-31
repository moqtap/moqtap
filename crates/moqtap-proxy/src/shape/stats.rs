//! Per-class shaping statistics: the atomic storage and its snapshot.
//!
//! The split mirrors [`instrument`](crate::instrument) exactly — a
//! [`ShapeRecorder`] of atomics that the forwarding tasks write, and a
//! plain-value [`ShapeStats`] that a reader takes. It is a **sibling** of
//! `Counters`, not an extension of it: `interest_none.rs` compares
//! `Counters` whole against `Counters::default()` and `actions_*.rs`
//! compare it by value, so a field added there would have to be threaded
//! through every one of those assertions, and `Counters` would lose `Copy`
//! for a `Vec` that is empty on all but shaped sessions.
//!
//! # Why a pre-sized `Vec`, indexed by position
//!
//! The class list is fixed for a session's lifetime — live reconfigure is
//! expected to build a new recorder rather than mutate this one. So the
//! rows are allocated once at session construction, in
//! [`ShapeProfile::classes`] order, and every increment on
//! the data path is one relaxed `fetch_add` at a known index. No lock, no
//! name lookup, no hot-path allocation — the cost model `instrument.rs`
//! already established.
//!
//! Snapshot order is therefore the configured order, deterministically, and
//! a class that never saw a unit is present with a zero row rather than
//! absent. A reader asking "what did `video` do?" gets an answer whether or
//! not `video` did anything, which is the difference between a starved
//! class and a mis-typed one.
//!
//! # What has a producer today
//!
//! Two session totals — `objects_seen` and `bytes_shaped` — are written at the
//! one place a shaped session's framed unit becomes visible, and they exist
//! here so that *an unshaped session shaped nothing* is falsifiable rather than
//! vacuous: something has to move when the path *is* entered, or an all-zero
//! snapshot cannot tell "not armed" from *armed and did nothing*.
//! `bytes_shaped` additionally counts what **no rule could see** — a stream
//! header, an oversized object's passthrough chunk, a bypassed stream's tail —
//! because the `unshapeable` row is a term of the conservation identity and a
//! term with nothing on the other side of the equals sign is not a term.
//! `objects_seen` does not: it is the *classifier's* count, and a header is not
//! an object.
//!
//! Admission adds the three rows a policy can move without a clock:
//! `objects_dropped` / `bytes_dropped` (`Overflow::DropTail`),
//! `blocked_episodes` (`Overflow::Block`) and `streams_reset_by_shaping`
//! (`Overflow::ResetStream`). Every one of them is charged to the class the
//! classifier resolved, so a per-class figure is an answer about a *rule*
//! and not about a stream.
//!
//! Release adds the rest: `bytes_delivered` / `objects_delivered` on every
//! granted unit, `tokens_exhausted_episodes` when a class's own bucket is
//! dry, `starved_behind_other_class` when a *different* class's unit was in
//! the way, `objects_expired` on the `Expiry::ResetStream` arm, and
//! `streams_with_mixed_classes` once per stream that carried two classes.
//!
//! # Session totals carry a direction
//!
//! Every session total is stored twice, once per leg: **uplink** is the
//! client's traffic on its way to the relay, **downlink** is the relay's on
//! its way to the client. One recorder serves every forwarding task of a
//! session, so without the split an author shaping both legs reads a single
//! figure and cannot tell an uplink stall from a downlink one — a
//! bidirectional run reports downlink starvation as though the uplink class
//! had caused it.
//!
//! The flat totals stay, and they are **derived**: `bytes_shaped` is
//! `uplink.bytes_shaped + downlink.bytes_shaped`, summed in
//! [`ShapeRecorder::snapshot`] rather than accumulated in a third atomic.
//! The data path therefore costs exactly what it did — one relaxed
//! `fetch_add` into the arriving leg's row — and the aggregate cannot drift
//! from its parts, which is not a property any pair of independently
//! written counters has. What that leaves falsifiable is the *attribution*:
//! charging every byte to one leg keeps the sum right and both legs wrong,
//! which is what the tests below and `egress.rs`'s two-leg test aim at.
//!
//! Per-class rows are deliberately **not** split. An author who wants a
//! class figure per leg writes two classes and keys each matcher on
//! [`Matcher::side`](super::Matcher::side); the totals are the ones no
//! configuration could separate, which is why they are the ones that carry
//! the direction themselves.
//!
//! # The proxy-wide aggregate, and why it is not a sum over live sessions
//!
//! [`ProxyRecorder`] is the second recorder in this module: one per
//! [`TransparentProxy`](crate::proxy::TransparentProxy), held by its control
//! plane, and charged by the *same* writers that charge the session
//! recorder — every `note_*` below forwards, so no call site in `session.rs`
//! or `egress.rs` knows it exists and no figure can be charged to one
//! recorder and missed by the other.
//!
//! Summing the sessions a control plane lists instead would be wrong three
//! ways, and only the first is fixable. The registry holds no recorder at
//! all, so there is nothing to sum. The registration is released by a
//! `Drop`, so a total taken over it would go *down* when a client
//! disconnected — a statistic that falls under normal operation cannot be
//! alerted on. And the list is a snapshot of a proxy that keeps moving, so a
//! sum walked across it is a consistent read of nothing. A recorder that
//! outlives every session has none of those problems: a session whose whole
//! future is dropped mid-flight still contributed at the instant each unit
//! was charged.
//!
//! # Where a proxy-level byte is charged: the measurement point
//!
//! [`ProxyStats::per_leg`] is a 2×2 — two legs, two directions — and the
//! two axes are orthogonal, which is exactly what makes the shape worth
//! having and exactly what makes it easy to fill in wrongly. A proxy holds
//! two connections; a byte crosses **both**, read on one leg and written on
//! the other. So the cell is chosen by where the measurement is taken, not
//! by a label copied off the arriving side:
//!
//! * `per_leg[Client].uplink` — bytes read from the client.
//! * `per_leg[Upstream].uplink` — bytes written to the relay.
//! * `per_leg[Upstream].downlink` — bytes read from the relay.
//! * `per_leg[Client].downlink` — bytes written to the client.
//!
//! The alternative — deriving a leg from the side a counting site holds — looks
//! equivalent and carries no information at all. Every hook site is handed
//! `ClientToProxy` or `RelayToProxy` and nothing else
//! ([`ShapeProfile::try_new`] refuses a rule keyed on an egress side), and over
//! those two values leg and direction are the *same* partition: the client row
//! would be a verbatim copy of the uplink row, the upstream row of the downlink
//! row, and two of the four cells would be identically zero. Four numbers
//! carrying two numbers' worth of information, with a reader who took
//! `per_leg[Upstream]` for *what this proxy sent upstream* getting the figure
//! for what it received from the client.
//!
//! Charging by measurement point makes the difference between the two
//! uplink cells the shaper's own retention — bytes it read from the client
//! and did not write to the relay — which is a number that can be non-zero
//! and therefore a number that can be asserted.
//!
//! Only the flow of units is measured twice. The three event figures on a
//! [`DirectionStats`] — expiries, streams a policy gave up on, streams that
//! carried two classes — are decisions taken over traffic that *arrived*,
//! so they are charged to the arrival cell and the departure cell reports
//! zero for them. That is stated on [`LegStats`] rather than left for a
//! reader to infer from a zero.
//!
//! [`ProxyStats::sessions`] is the flat rollup, and it sums the two
//! **arrival** cells — the two places a byte enters this proxy, where each
//! byte is counted exactly once. Summing all four would count every byte
//! twice, once read and once written.
//!
//! **Every figure on this page has a producer.** Worth stating, because it
//! was not always true: five fields here snapshotted as a constant zero for
//! a long time, each documenting its own emptiness, and what settled them
//! was not writing five producers but noticing that none of the five
//! belonged here.
//!
//! Everything on this page is gated on a configured [`ShapeProfile`] — a
//! proxy running without one reports `ProxyStats::default()` however many
//! gigabytes it forwards. Two of the five counted what a **hook** does,
//! which needs no profile at all, so in this type they could only ever have
//! been a partial count that read zero for every unprofiled session that
//! delayed or truncated a thousand objects. They are
//! [`Counters::units_delayed`](crate::instrument::Counters::units_delayed)
//! and
//! [`Counters::objects_truncated`](crate::instrument::Counters::objects_truncated)
//! now, beside
//! [`Counters::objects_elided`](crate::instrument::Counters::objects_elided),
//! which had already settled where a hook's decision is counted.
//!
//! The other three were `Duration` totals, and a sum of wall-clock time that
//! the machine's scheduler moves as much as this code does is reportable and
//! never assertable. The timing dimension is measured instead by
//! [`Counters::release_errors`](crate::instrument::Counters::release_errors),
//! which reports a distribution — p50, p95 and an exact maximum — rather
//! than a total nobody can calibrate.
//!
//! With release and the unshapeable row wired, the conservation identity
//! `Σ classes(delivered + dropped) + default + unshapeable == bytes_shaped`
//! holds for a stream that ran to completion. Both sides come from the same
//! measurement — `raw.len()` for a framed object, `Pending::len()` for a
//! unit no rule saw — taken at the see-point and charged again, unchanged,
//! at release, so it is an identity over one number and not an agreement
//! between two.
//!
//! Two things break it, both named rather than papered over. A
//! `STOP_SENDING`-driven teardown, where `propagate_stop` clears the queue
//! rather than draining it — those bytes are neither delivered nor dropped,
//! and `Impairment{QueuedBytesAtTeardown}` is what accounts for them. And a
//! hook action that changes a unit's size after it was seen: `Replace`,
//! `ReplacePayload` and `Truncate` are all charged in full on the left and
//! by what they actually wrote on the right. Both are properties of the
//! *scenario*, not of the recorder, which is why the fixture that asserts
//! the identity takes no hook action and runs its streams to completion
//! before it reads.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use super::scheduler::Class;
use super::ShapeProfile;
use crate::types::{Leg, ProxySide};

// ── which leg ──────────────────────────────────────────────────────────

/// Which leg of the proxy a shaped unit is travelling on.
///
/// Two variants rather than [`ProxySide`]'s four. A unit is charged on the
/// side it *arrived* on, and the two egress sides never reach a shaping
/// decision at all — [`ShapeProfile::try_new`] rejects a rule keyed on one
/// — but both halves of a leg answer the same question anyway, so the
/// conversion below is total and no call site has an impossible arm to
/// invent a value for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Direction {
    /// Client → relay: what the client publishes and asks for.
    Uplink,
    /// Relay → client: what the client is subscribed to.
    Downlink,
}

impl Direction {
    /// This leg's row in [`ShapeRecorder`]'s session totals.
    ///
    /// An index rather than a `match` at each writer: the totals are an
    /// array precisely so that charging one is the same single
    /// `fetch_add` at a known offset the class rows already are.
    fn index(self) -> usize {
        match self {
            Direction::Uplink => 0,
            Direction::Downlink => 1,
        }
    }
}

impl From<ProxySide> for Direction {
    fn from(side: ProxySide) -> Self {
        match side {
            ProxySide::ClientToProxy | ProxySide::ProxyToRelay => Direction::Uplink,
            ProxySide::RelayToProxy | ProxySide::ProxyToClient => Direction::Downlink,
        }
    }
}

/// The connection a side's traffic is travelling over, and the way it is
/// going — the pair [`ProxyStats::per_leg`] is indexed by.
///
/// A [`ProxySide`] is exactly this pair: `transport.rs` says so in prose,
/// that `ClientToProxy` and `ProxyToClient` are the two directions of the
/// client leg and `ProxyToRelay` and `RelayToProxy` the two of the upstream
/// leg, and this is that sentence written as a total function. Written out
/// arm by arm rather than composed from [`Direction::from`] and a second
/// mapping, because the four arms are the definition and a reader checking
/// the attribution should not have to compose two functions to see it.
fn split(side: ProxySide) -> (Leg, Direction) {
    match side {
        ProxySide::ClientToProxy => (Leg::Client, Direction::Uplink),
        ProxySide::ProxyToRelay => (Leg::Upstream, Direction::Uplink),
        ProxySide::RelayToProxy => (Leg::Upstream, Direction::Downlink),
        ProxySide::ProxyToClient => (Leg::Client, Direction::Downlink),
    }
}

/// The leg a unit read on `leg` leaves this proxy by.
///
/// A proxy holds two connections and forwards between them, so the leg a
/// unit is written on is always the other one. The *direction* is unchanged
/// — traffic the client published is uplink on both legs — which is why
/// this takes a leg rather than a side: naming the departure cell needs the
/// leg flipped and nothing else.
fn opposite(leg: Leg) -> Leg {
    match leg {
        Leg::Client => Leg::Upstream,
        Leg::Upstream => Leg::Client,
    }
}

/// This leg's row in [`ProxyStats::per_leg`].
///
/// An index rather than a `match` at each writer, for the reason
/// [`Direction::index`] gives: charging a cell stays one relaxed
/// `fetch_add` at a known offset.
fn leg_index(leg: Leg) -> usize {
    match leg {
        Leg::Client => 0,
        Leg::Upstream => 1,
    }
}

// ── the snapshot types ─────────────────────────────────────────────────

/// Shaping statistics for one session.
///
/// Zero-valued on any session with no [`ShapeProfile`], which is what makes
/// *this session shaped nothing* a falsifiable claim rather than a promise.
/// Reported separately from `Counters` so that crate's whole-struct `==
/// Counters::default()` assertions keep meaning what they mean.
///
/// Read through
/// [`ProxySession::shape_stats`](crate::session::ProxySession::shape_stats).
///
/// The session totals appear twice: flat, summed over the whole session,
/// and again under [`Self::uplink`] and [`Self::downlink`] for one leg
/// each. The flat figure is the sum of the two by construction, so the two
/// forms can never disagree — pick the leg when the question is which side
/// stalled, and the aggregate when it is whether the profile ran at all.
///
/// **Every field here is written.** Two were not until recently — the
/// `Duration` totals on [`ClassStats`], which were calibration figures and
/// are gone; that type says why there is no duration among these at all. A
/// zero row is still reported, never omitted — a class that saw nothing is
/// present and empty, which is the difference between a starved class and a
/// mis-typed one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShapeStats {
    /// One entry per configured class, in [`ShapeProfile::classes`] order.
    pub classes: Vec<ClassStats>,
    /// Units that matched no rule.
    pub default_class: ClassStats,
    /// Units with no object metadata at all: subgroup and fetch stream
    /// headers, oversized passthrough objects, bypassed streams — every
    /// fetch stream on drafts 15-19, which have no fetch object codec.
    /// A **separate** row from [`Self::default_class`], and the distinction is
    /// the point: the default row is *the rules saw this unit and none claimed
    /// it*, this row is *no rule could have seen it*. Merging them would make a
    /// mis-aimed matcher indistinguishable from a stream the framer cannot
    /// address.
    ///
    /// These bytes are **not paced**: they charge no bucket, so a class
    /// rate can be exceeded by exactly one oversized object.
    pub unshapeable: ClassStats,
    /// Hook-visible units the classifier saw.
    ///
    /// Objects only. A stream header is counted in [`Self::bytes_shaped`]
    /// and in [`Self::unshapeable`], and not here.
    pub objects_seen: u64,
    /// Bytes the shaper accounted for — every byte it saw, whether a bucket
    /// granted it, a policy dropped it, or it was unshapeable.
    /// Deliberately **not** *bytes that passed through a bucket*: the
    /// `unshapeable` row never touches a bucket, and the conservation identity
    /// this total exists for — `Σ classes(delivered + dropped) + default +
    /// unshapeable == bytes_shaped` — has to hold across that row too, or bytes
    /// the shaper declined to shape would vanish from the accounting.
    pub bytes_shaped: u64,
    /// Objects whose `max_hold` elapsed under [`Expiry::ResetStream`].
    /// Zero under the default [`Expiry::Deliver`], which has no producer.
    ///
    /// [`Expiry::ResetStream`]: super::Expiry::ResetStream
    /// [`Expiry::Deliver`]: super::Expiry::Deliver
    pub objects_expired: u64,
    /// Destination streams abandoned by an overflow or expiry policy.
    pub streams_reset_by_shaping: u64,
    /// Streams on which two units resolved to different classes.
    ///
    /// Head-gating means such a stream's throughput is decided by whichever
    /// class is at the head, so without this count configured shaping and
    /// head-of-line blocking are indistinguishable from outside.
    pub streams_with_mixed_classes: u64,
    /// The same totals for the client's traffic on its way to the relay.
    ///
    /// Every flat total above is this plus [`Self::downlink`], term by
    /// term. Read a leg when the question is *which side stalled*; read the
    /// aggregate when it is *did the profile do anything at all*. A session
    /// shaping only one leg reports the other as all zeros, which is an
    /// answer rather than an absence.
    pub uplink: DirectionStats,
    /// The same totals for the relay's traffic on its way to the client.
    pub downlink: DirectionStats,
}

/// Five totals over the traffic travelling **one way**.
///
/// Reported in two different containers, and reading a figure here means
/// knowing which one it came out of. As [`ShapeStats::uplink`] and
/// [`ShapeStats::downlink`] it is one half of a session's own totals, and
/// the split is by direction alone — a session recorder has no leg axis. As
/// one cell of [`ProxyStats::per_leg`] it is one *crossing*: a connection
/// and a direction together, so the same unit appears in two cells, once
/// where it was read and once where it was written. [`LegStats`] names the
/// four.
///
/// The distinction is not decoration for the three event figures below.
/// Every one of them is charged where the traffic **arrived**, so in a
/// departure cell all three read zero, and in an arrival cell they describe
/// destination streams that physically live on the *other* connection —
/// they name which of the two flows the shaper acted on, not which socket
/// the abandoned stream was on. That is deliberate, and stated on each
/// field, because putting them on the departure cell would separate them
/// from the `bytes_shaped` that explains them.
///
/// Nothing here is per class: an author who wants a class figure per
/// direction writes two classes and keys each matcher on
/// [`Matcher::side`](super::Matcher::side), and these are the totals no
/// configuration could have separated.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DirectionStats {
    /// Hook-visible units the classifier saw. Objects only, for the reason
    /// [`ShapeStats::objects_seen`] gives — including in a departure cell,
    /// where a released stream header is bytes and still not an object.
    pub objects_seen: u64,
    /// Bytes the shaper accounted for — every byte it saw, whether a bucket
    /// granted it, a policy dropped it, or it was unshapeable.
    ///
    /// The one figure besides `objects_seen` that is measured at both
    /// crossings, which is what makes the difference between the two cells
    /// of one direction in [`ProxyStats::per_leg`] the shaper's own
    /// retention.
    pub bytes_shaped: u64,
    /// Objects whose `max_hold` elapsed under
    /// [`Expiry::ResetStream`](super::Expiry::ResetStream).
    ///
    /// Charged to the cell the traffic arrived on. **Zero in a departure
    /// cell of [`ProxyStats::per_leg`]** — an expired object was read and
    /// never written, so the leg it would have left by never carried it.
    pub objects_expired: u64,
    /// Destination streams abandoned by an overflow or expiry policy,
    /// counted against the flow whose traffic they were carrying.
    ///
    /// Charged to the cell the traffic arrived on, which is **not** the
    /// connection the abandoned stream is on: a stream carrying what the
    /// client published is written towards the relay, and this figure
    /// appears in the client leg's uplink cell beside the `bytes_shaped`
    /// that explains it. **Zero in a departure cell.**
    pub streams_reset_by_shaping: u64,
    /// Streams on which two units resolved to different classes.
    ///
    /// Charged to the cell the traffic arrived on, on the same terms as
    /// [`Self::streams_reset_by_shaping`], and **zero in a departure
    /// cell**. Note that the event beside it,
    /// [`ProxyEvent::Impairment`](crate::event::ProxyEvent::Impairment)
    /// carrying
    /// [`ImpairmentKind::ClassChangedMidStream`](crate::event::ImpairmentKind::ClassChangedMidStream),
    /// answers the **other** leg for the same occurrence: an event names the
    /// connection whose write is affected, and a cell here names the flow
    /// the figure belongs to. Correlating the two means expecting them to
    /// disagree by exactly one leg.
    pub streams_with_mixed_classes: u64,
}

/// Per-class shaping statistics, one entry in [`ShapeStats`].
///
/// Every figure is a count, and there is deliberately no duration among
/// them. Two once were — a blocked total and a hold total — and both would
/// have been sums of wall-clock time, movable by the machine's scheduler as
/// much as by this code, so a gate could only ever have reported them. One
/// of the two would have misdescribed itself as well:
/// [`Overflow::Block`](super::Overflow::Block) stops *this crate* calling
/// `read()` on the source stream and does **not** stall the peer, because
/// the transport's own receive window absorbs megabytes before a publisher
/// notices anything — so a blocked time measured here would have been how
/// long this queue refused to read, never how long the publisher was held
/// up, and a test reading it as publisher backpressure would have been
/// measuring the wrong thing under a name that invited it. Real backpressure
/// needs a small
/// [`TransportProfile::stream_receive_window`](crate::transport::TransportProfile::stream_receive_window),
/// which is a transport setting and not a shaping one.
///
/// What survives is the load-independent companion a gate can read:
/// [`Self::blocked_episodes`] and [`Self::tokens_exhausted_episodes`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClassStats {
    /// The [`ClassRule::name`](super::ClassRule::name) this row reports, or
    /// an empty string for the default and unshapeable rows.
    pub name: String,
    /// Bytes released to the destination stream.
    pub bytes_delivered: u64,
    /// Bytes discarded by a policy.
    pub bytes_dropped: u64,
    /// Objects released to the destination stream.
    pub objects_delivered: u64,
    /// Objects discarded by a policy.
    pub objects_dropped: u64,
    /// **Edge-triggered**: distinct starvation episodes, not dequeue
    /// attempts. Level counting would report the runner's read batching
    /// rather than the shaper.
    pub tokens_exhausted_episodes: u64,
    /// Edge-triggered, same reason: distinct episodes of the read side
    /// being stalled by [`Overflow::Block`](super::Overflow::Block).
    pub blocked_episodes: u64,
    /// Units that waited behind a *different* class's unit on the same
    /// stream. Separates configured shaping from head-of-line blocking;
    /// conflating it with `tokens_exhausted_episodes` would hide which of
    /// the two a scenario actually produced.
    pub starved_behind_other_class: u64,
}

// ── the proxy-wide snapshot ────────────────────────────────────────────

/// Shaping statistics for a whole proxy: every session it has accepted,
/// including the ones that have already ended.
///
/// Read through [`ProxyControl::stats`](crate::control::ProxyControl::stats)
/// and cleared through
/// [`ProxyControl::reset_stats`](crate::control::ProxyControl::reset_stats).
/// The figures are **cumulative and monotone** between resets, which is the
/// property that separates this from
/// [`ProxyControl::sessions`](crate::control::ProxyControl::sessions): that
/// list is what is live now and shrinks when a client disconnects, and a
/// total summed from it would shrink with it. Nothing here is ever removed,
/// so a session that ended, errored, or had its whole future dropped
/// mid-flight has already contributed everything it moved.
///
/// # Everything here is gated on a configured [`ShapeProfile`]
///
/// The writers are the shaping path's, so a proxy running with no profile
/// reports `ProxyStats::default()` no matter how many gigabytes it forwards.
/// An all-zero snapshot means **no profile**, not *no traffic*, and the two
/// are not distinguishable from this type alone — ask
/// [`ProxyControl::sessions`](crate::control::ProxyControl::sessions) or an
/// observer's event stream which of the two it is.
///
/// # A session driven directly is not in here
///
/// A [`ProxySession`](crate::session::ProxySession) constructed by a caller
/// rather than accepted by a proxy belongs to no control plane, so it has
/// nowhere to report and keeps only its own
/// [`ShapeStats`]. That is the same rule
/// [`ProxyControl::sessions`](crate::control::ProxyControl::sessions)
/// follows, and for the same reason: a proxy must not claim traffic it never
/// accepted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProxyStats {
    /// One row per connection this proxy holds: index `0` is
    /// [`Leg::Client`], index `1` is [`Leg::Upstream`]. Reach a row by name
    /// with [`ProxyStats::leg`] rather than by literal index.
    ///
    /// A byte crosses **both** legs — read on one, written on the other —
    /// so a figure here is charged where it was measured and the two legs
    /// are not two views of one number. See [`LegStats`] for the cell by
    /// cell statement.
    pub per_leg: [LegStats; 2],
    /// The flat rollup over every session, **derived** at snapshot time
    /// from [`Self::per_leg`] and the class rows rather than accumulated
    /// into counters of its own.
    ///
    /// Derived for the reason a session's own snapshot sums its two legs:
    /// two independently written counters can disagree, and the disagreement
    /// surfaces as an identity that fails for no reason a reader could act
    /// on. A sum taken at read time cannot drift from its parts, which also
    /// means the rollup identity is a property of this type's shape and not
    /// something a test could ever falsify.
    pub sessions: SessionStats,
    /// One entry per class, in [`ShapeProfile::classes`] order.
    ///
    /// Sized **once**, from the first session this proxy accepts that has a
    /// class to install — a session with no profile, and a session whose
    /// profile declares no classes, both leave the rows alone — and never
    /// resized: a `Class::Rule(index)` is an index into the class
    /// list its own scheduler was built from, so a row set that changed
    /// shape under a running session would relabel every figure in it. A
    /// session whose class list does not match, which is what a live
    /// [`ProxyControl::set_shape`](crate::control::ProxyControl::set_shape)
    /// with a different set of classes produces, charges
    /// [`Self::default_class`] instead of a row that would be named for
    /// somebody else's rule.
    pub classes: Vec<ClassStats>,
    /// Units that matched no rule — and units of a session whose class list
    /// this proxy's rows were not sized for, for the reason
    /// [`Self::classes`] gives.
    pub default_class: ClassStats,
    /// Units no rule could have seen: stream headers, oversized passthrough
    /// objects, bypassed streams. A separate row from [`Self::default_class`]
    /// for the reason [`ShapeStats::unshapeable`] gives.
    pub unshapeable: ClassStats,
}

impl ProxyStats {
    /// One leg's row, by name.
    ///
    /// [`Self::per_leg`] is an array so the data path can charge a cell at a
    /// known offset; a reader should not have to remember which offset that
    /// is, and an index literal at a call site is exactly the kind of
    /// mistake that reads plausibly forever.
    pub fn leg(&self, leg: Leg) -> &LegStats {
        &self.per_leg[leg_index(leg)]
    }
}

/// One connection's shaping statistics, split by which way the traffic was
/// going — one entry of [`ProxyStats::per_leg`].
///
/// Two rows and not one. A leg carries traffic both ways, and a leg that
/// reported a single row would answer *how much crossed this connection* while
/// refusing "in which direction" — which is the question an author diagnosing a
/// one-sided stall is actually asking, and the one no configuration could
/// separate afterwards.
///
/// # Which cell a figure lands in
///
/// A proxy reads on one leg and writes on the other, so the same unit is
/// measured twice, once at each crossing:
///
/// * `per_leg[Client].uplink` — read from the client.
/// * `per_leg[Upstream].uplink` — written to the relay.
/// * `per_leg[Upstream].downlink` — read from the relay.
/// * `per_leg[Client].downlink` — written to the client.
///
/// The difference between the two cells of one direction is what the shaper
/// kept back: bytes it read and did not write, whether a policy dropped
/// them, a hook elided them, or a stream was given up on before they went
/// out.
///
/// # Three fields of a departure cell have no producer
///
/// Only the flow of units is measured at both crossings. Of the five
/// figures a [`DirectionStats`] carries, [`DirectionStats::objects_seen`]
/// and [`DirectionStats::bytes_shaped`] are charged at both;
/// [`DirectionStats::objects_expired`],
/// [`DirectionStats::streams_reset_by_shaping`] and
/// [`DirectionStats::streams_with_mixed_classes`] are decisions taken over
/// traffic that **arrived**, so they are charged to the arrival cell only
/// and a departure cell reports zero for all three. Stated here because a
/// zero that means "no producer" and a zero that means "it did not happen"
/// are not the same answer.
///
/// `objects_seen` stays the classifier's count on both cells: a stream
/// header is not an object on the way in, and it is still not one on the
/// way out.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LegStats {
    /// This leg's two directions: index `0` is uplink — the client's traffic
    /// on its way to the relay — and index `1` is downlink. Reach them by
    /// name with [`LegStats::uplink`] and [`LegStats::downlink`].
    pub directions: [DirectionStats; 2],
}

impl LegStats {
    /// The client's traffic on its way to the relay, on this leg.
    pub fn uplink(&self) -> &DirectionStats {
        &self.directions[Direction::Uplink.index()]
    }

    /// The relay's traffic on its way to the client, on this leg.
    pub fn downlink(&self) -> &DirectionStats {
        &self.directions[Direction::Downlink.index()]
    }
}

/// What every session this proxy has run did, added up — the flat form of
/// [`ProxyStats`].
///
/// Every field is **derived** at snapshot time, from [`ProxyStats::per_leg`]
/// or from the class rows, so it cannot drift from the figures beside it.
/// The two arrival cells are what the totals below are summed from — the two
/// points a byte enters this proxy, where each byte is counted exactly once.
/// Summing all four cells would count every byte twice, once where it was
/// read and once where it was written.
///
/// # Every field here has a producer, and the three that did not are gone
///
/// Every figure is derived at snapshot time from the per-leg cells and the
/// class rows, and those are written only by the shaping path. So a figure
/// counting something a **hook** does — which needs no
/// [`ShapeProfile`](super::ShapeProfile), while everything here is gated on
/// one — could not have been a complete count in this type however it was
/// wired, and two of the three were exactly that. [`Self::objects_dropped`]
/// below already said where that kind of figure lives: an object a hook
/// elided is counted on [`Counters`](crate::instrument::Counters), and a
/// unit a hook delayed and an object it truncated are counted beside it
/// there now. The third was a `Duration` total; see [`ClassStats`] for why
/// no statistic on this page is one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionStats {
    /// Hook-visible units the classifier saw, over every session. Objects
    /// only, for the reason [`ShapeStats::objects_seen`] gives.
    pub objects_seen: u64,
    /// Objects discarded by a policy, summed over every class row.
    ///
    /// Today that means [`Overflow::DropTail`](super::Overflow::DropTail)
    /// and nothing else: an object a hook elided is the hook's decision
    /// rather than the shaper's and is counted by
    /// [`Counters::objects_elided`](crate::instrument::Counters::objects_elided)
    /// on the session that ran the hook.
    pub objects_dropped: u64,
    /// Objects whose `max_hold` elapsed under
    /// [`Expiry::ResetStream`](super::Expiry::ResetStream). Zero under the
    /// default [`Expiry::Deliver`](super::Expiry::Deliver), which has no
    /// producer — correctly, because that arm delivers the object instead.
    pub objects_expired: u64,
    /// Destination streams abandoned by an overflow or expiry policy.
    ///
    /// Shaping only. A stream reset by a hook, by a peer, or by a mirrored
    /// teardown is not counted here — those are not decisions this profile
    /// took, and folding them in would make a configured
    /// [`Overflow::ResetStream`](super::Overflow::ResetStream) impossible to
    /// distinguish from a client that went away.
    pub streams_reset: u64,
    /// Bytes the shaper accounted for — every byte it saw, whether a bucket
    /// granted it, a policy dropped it, or it was unshapeable.
    pub bytes_shaped: u64,
}

// ── the storage ────────────────────────────────────────────────────────

/// One class's atomic counters — the storage behind one [`ClassStats`].
///
/// `name` is immutable for the recorder's lifetime, so it is a plain
/// `String` rather than anything shared: the class list cannot change
/// under a running session.
pub(crate) struct ClassCounters {
    name: String,
    bytes_delivered: AtomicU64,
    bytes_dropped: AtomicU64,
    objects_delivered: AtomicU64,
    objects_dropped: AtomicU64,
    tokens_exhausted_episodes: AtomicU64,
    blocked_episodes: AtomicU64,
    starved_behind_other_class: AtomicU64,
}

impl ClassCounters {
    /// An all-zero row labelled `name`.
    fn named(name: String) -> Self {
        Self {
            name,
            bytes_delivered: AtomicU64::new(0),
            bytes_dropped: AtomicU64::new(0),
            objects_delivered: AtomicU64::new(0),
            objects_dropped: AtomicU64::new(0),
            tokens_exhausted_episodes: AtomicU64::new(0),
            blocked_episodes: AtomicU64::new(0),
            starved_behind_other_class: AtomicU64::new(0),
        }
    }

    /// Read this row.
    fn snapshot(&self) -> ClassStats {
        ClassStats {
            name: self.name.clone(),
            bytes_delivered: self.bytes_delivered.load(Ordering::Relaxed),
            bytes_dropped: self.bytes_dropped.load(Ordering::Relaxed),
            objects_delivered: self.objects_delivered.load(Ordering::Relaxed),
            objects_dropped: self.objects_dropped.load(Ordering::Relaxed),
            tokens_exhausted_episodes: self.tokens_exhausted_episodes.load(Ordering::Relaxed),
            blocked_episodes: self.blocked_episodes.load(Ordering::Relaxed),
            starved_behind_other_class: self.starved_behind_other_class.load(Ordering::Relaxed),
        }
    }

    /// Zero every counter, keeping the row's name.
    ///
    /// Only [`ProxyRecorder`] resets: a session's figures are the session's
    /// for its whole life. Seven relaxed stores, and deliberately not one
    /// atomic swap of the whole row — there is no such primitive, and a
    /// reset that raced traffic would land between two `fetch_add`s whatever
    /// it was written with. What that costs is a snapshot straddling a reset
    /// that reports a row part-cleared, which is why the reset is a caller's
    /// verb and not something this crate does on its own.
    fn reset(&self) {
        self.bytes_delivered.store(0, Ordering::Relaxed);
        self.bytes_dropped.store(0, Ordering::Relaxed);
        self.objects_delivered.store(0, Ordering::Relaxed);
        self.objects_dropped.store(0, Ordering::Relaxed);
        self.tokens_exhausted_episodes.store(0, Ordering::Relaxed);
        self.blocked_episodes.store(0, Ordering::Relaxed);
        self.starved_behind_other_class.store(0, Ordering::Relaxed);
    }
}

/// One leg's session totals — the storage behind one [`DirectionStats`].
struct DirectionCounters {
    objects_seen: AtomicU64,
    bytes_shaped: AtomicU64,
    objects_expired: AtomicU64,
    streams_reset_by_shaping: AtomicU64,
    streams_with_mixed_classes: AtomicU64,
}

impl DirectionCounters {
    /// An all-zero leg.
    fn new() -> Self {
        Self {
            objects_seen: AtomicU64::new(0),
            bytes_shaped: AtomicU64::new(0),
            objects_expired: AtomicU64::new(0),
            streams_reset_by_shaping: AtomicU64::new(0),
            streams_with_mixed_classes: AtomicU64::new(0),
        }
    }

    /// Read this leg.
    fn snapshot(&self) -> DirectionStats {
        DirectionStats {
            objects_seen: self.objects_seen.load(Ordering::Relaxed),
            bytes_shaped: self.bytes_shaped.load(Ordering::Relaxed),
            objects_expired: self.objects_expired.load(Ordering::Relaxed),
            streams_reset_by_shaping: self.streams_reset_by_shaping.load(Ordering::Relaxed),
            streams_with_mixed_classes: self.streams_with_mixed_classes.load(Ordering::Relaxed),
        }
    }

    /// Zero every counter. [`ClassCounters::reset`] states the terms.
    fn reset(&self) {
        self.objects_seen.store(0, Ordering::Relaxed);
        self.bytes_shaped.store(0, Ordering::Relaxed);
        self.objects_expired.store(0, Ordering::Relaxed);
        self.streams_reset_by_shaping.store(0, Ordering::Relaxed);
        self.streams_with_mixed_classes.store(0, Ordering::Relaxed);
    }
}

// ── the proxy-wide storage ─────────────────────────────────────────────

/// Proxy-scoped shaping-counter storage — the storage behind [`ProxyStats`].
///
/// One per [`TransparentProxy`](crate::proxy::TransparentProxy), owned by
/// its control plane and handed to each session's [`ShapeRecorder`] as that
/// session is attached, so it lives for as long as the proxy does and no
/// session's ending takes anything out of it.
///
/// Every counter here is charged by the same call that charges the session
/// recorder — [`ShapeRecorder`]'s `note_*` methods forward — which is what
/// makes the two recorders unable to disagree. The data path pays one extra
/// relaxed `fetch_add` per figure and one `Option` test, on a path that has
/// already done a `write_all`.
pub(crate) struct ProxyRecorder {
    /// The four cells of [`ProxyStats::per_leg`]: `legs[leg][direction]`,
    /// indexed by [`leg_index`] then [`Direction::index`].
    legs: [[DirectionCounters; 2]; 2],
    /// The class rows, installed by the first session to attach with a class
    /// to install — see [`Self::adopt_classes`] for the two kinds of session
    /// that have none and must not win this.
    ///
    /// A [`OnceLock`] and not a `Mutex`, because the list must be **fixed**:
    /// a `Class::Rule(index)` is an index into the class list of the
    /// scheduler that produced it, so rows that could be resized under a
    /// running session would silently relabel every figure in them. First
    /// writer wins; a later session whose class list differs charges
    /// [`Self::default_class`], which [`Self::row`] does and
    /// [`ProxyStats::classes`] states.
    ///
    /// Empty until the first shaped session, so a proxy that has accepted
    /// nothing, or only unshaped sessions, reports no class rows rather than
    /// rows invented from a profile nothing ran under.
    classes: OnceLock<Vec<ClassCounters>>,
    default_class: ClassCounters,
    unshapeable: ClassCounters,
}

impl ProxyRecorder {
    /// A recorder with four all-zero cells and no class rows yet.
    pub(crate) fn new() -> Self {
        Self {
            legs: [
                [DirectionCounters::new(), DirectionCounters::new()],
                [DirectionCounters::new(), DirectionCounters::new()],
            ],
            classes: OnceLock::new(),
            // Unnamed by contract, exactly as `ShapeRecorder::for_profile`
            // leaves them: an empty `name` is what distinguishes these two
            // rows from a class somebody wrote.
            default_class: ClassCounters::named(String::new()),
            unshapeable: ClassCounters::named(String::new()),
        }
    }

    /// Size the class rows from `names` if nothing has yet, and answer
    /// whether the installed rows are `names` — which is whether a session
    /// running that class list may charge them by index.
    ///
    /// The comparison is over names **and order**, the same pair
    /// `same_classes` compares in `session.rs` and for the same reason: that
    /// pair is what makes a `Class::Rule(index)` mean the same thing to the
    /// scheduler that produced it and to the row it is charged to. The same
    /// names in a different order would charge every class to another one's
    /// row without a single count going missing.
    ///
    /// # An empty list never sizes anything
    ///
    /// A list with no rows in it names no row, so letting it win the
    /// `OnceLock` would install an empty row set that nothing can ever match
    /// again: every classed session accepted for the rest of the proxy's life
    /// would find rows it did not match and charge [`Self::default_class`],
    /// with [`ProxyStats::classes`] empty forever. Every figure right, every
    /// label gone — which is precisely the relabelling this whole sizing rule
    /// exists to prevent, and it would arrive silently and be unrecoverable
    /// without restarting the proxy.
    ///
    /// The way an empty list used to get here was a [`ShapeProfile`] with no
    /// classes, which the constructor accepted because it validated each
    /// class it was *given* and had nothing to say about being given none.
    /// [`ShapeProfile::try_new`] now refuses that outright as
    /// [`ShapeError::NoClasses`](super::ShapeError::NoClasses), so no
    /// profile can carry an empty list to this call and the branch below is
    /// no longer reachable from any public path.
    ///
    /// It stays because of what it costs against what it prevents: two lines
    /// and a comparison that is already being made, against a proxy-wide,
    /// silent, restart-only failure. Answering `false` costs a caller nothing
    /// in any case — a session with no `Class::Rule` to charge is unaffected
    /// by the flag, and `Class::Default` and `Class::Unshapeable` are
    /// unaffected by it always.
    fn adopt_classes(&self, names: &[String]) -> bool {
        if names.is_empty() {
            return false;
        }
        let rows =
            self.classes.get_or_init(|| names.iter().cloned().map(ClassCounters::named).collect());
        rows.len() == names.len() && rows.iter().zip(names).all(|(row, name)| &row.name == name)
    }

    /// The class rows, or an empty slice before any shaped session attached.
    fn classes(&self) -> &[ClassCounters] {
        self.classes.get().map_or(&[], Vec::as_slice)
    }

    /// The cell a unit **read** on `side` is charged to.
    fn arrival(&self, side: ProxySide) -> &DirectionCounters {
        let (leg, direction) = split(side);
        &self.legs[leg_index(leg)][direction.index()]
    }

    /// The cell a unit read on `side` is charged to when it is **written**:
    /// the other leg, the same direction.
    fn departure(&self, side: ProxySide) -> &DirectionCounters {
        let (leg, direction) = split(side);
        &self.legs[leg_index(opposite(leg))][direction.index()]
    }

    /// The row one class's units are charged to.
    ///
    /// `sized` is whether the charging session's class list is the one these
    /// rows were sized from. When it is not, a `Class::Rule` index names a
    /// row belonging to a different rule, so the unit goes to the default
    /// row instead — the same answer [`ShapeRecorder::row`] gives an
    /// impossible index, and for the stronger of the two reasons: here the
    /// index is not impossible, it is *plausible and wrong*.
    ///
    /// [`Class::Unshapeable`] is unaffected either way. That row is not
    /// named for a rule, so no reconfiguration can make it mean something
    /// else.
    fn row(&self, class: Class, sized: bool) -> &ClassCounters {
        match class {
            Class::Unshapeable => &self.unshapeable,
            Class::Rule(index) if sized => self.classes().get(index).unwrap_or(&self.default_class),
            _ => &self.default_class,
        }
    }

    /// Read every counter.
    ///
    /// Allocates: one `Vec` and one `String` per class row. A reader's call —
    /// the control plane's — never the data path's.
    ///
    /// [`ProxyStats::sessions`] is **computed here**, from the two arrival
    /// cells and the class rows, which is why no writer maintains it.
    pub(crate) fn snapshot(&self) -> ProxyStats {
        let per_leg = [self.leg_stats(Leg::Client), self.leg_stats(Leg::Upstream)];
        let classes: Vec<ClassStats> = self.classes().iter().map(ClassCounters::snapshot).collect();
        let default_class = self.default_class.snapshot();
        let unshapeable = self.unshapeable.snapshot();

        // The two cells traffic *enters* by. Every other cell reports what
        // left, and a byte that entered and left would be counted twice.
        let from_client = per_leg[leg_index(Leg::Client)].uplink();
        let from_relay = per_leg[leg_index(Leg::Upstream)].downlink();
        let objects_dropped = classes
            .iter()
            .chain([&default_class, &unshapeable])
            .fold(0u64, |sum, row| sum.saturating_add(row.objects_dropped));

        let sessions = SessionStats {
            objects_seen: from_client.objects_seen.saturating_add(from_relay.objects_seen),
            objects_dropped,
            objects_expired: from_client.objects_expired.saturating_add(from_relay.objects_expired),
            streams_reset: from_client
                .streams_reset_by_shaping
                .saturating_add(from_relay.streams_reset_by_shaping),
            bytes_shaped: from_client.bytes_shaped.saturating_add(from_relay.bytes_shaped),
        };

        ProxyStats { per_leg, sessions, classes, default_class, unshapeable }
    }

    /// One leg's two cells.
    fn leg_stats(&self, leg: Leg) -> LegStats {
        let rows = &self.legs[leg_index(leg)];
        LegStats { directions: [rows[0].snapshot(), rows[1].snapshot()] }
    }

    /// Zero every counter this proxy holds, keeping the class rows and their
    /// names.
    ///
    /// The rows survive because they are what a `Class::Rule(index)` means:
    /// dropping them would let the next session install a different class
    /// list and charge figures under it, which is precisely the relabelling
    /// [`Self::adopt_classes`] exists to prevent. A reset moves the counters
    /// to zero, not the schema.
    pub(crate) fn reset(&self) {
        for leg in &self.legs {
            for cell in leg {
                cell.reset();
            }
        }
        for row in self.classes() {
            row.reset();
        }
        self.default_class.reset();
        self.unshapeable.reset();
    }
}

impl std::fmt::Debug for ProxyRecorder {
    /// Prints the snapshot, not the atomics.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ProxyRecorder").field(&self.snapshot()).finish()
    }
}

/// Session-scoped shaping-counter storage.
///
/// One per `ProxySession`, held behind an `Arc` and cloned into every
/// forwarding task exactly as `Recorder` is, so two sessions running
/// side by side in one test binary cannot see each other's increments.
///
/// **Always constructed**, including for a session with no profile, on the
/// same reasoning `StreamRegistry` is. An unshaped session's
/// recorder has an empty class list and no writer, so it snapshots as
/// `ShapeStats::default()`; making construction conditional would replace
/// one always-zero allocation with an `Option` on the hot context and prove
/// nothing extra.
pub(crate) struct ShapeRecorder {
    classes: Vec<ClassCounters>,
    default_class: ClassCounters,
    unshapeable: ClassCounters,
    /// The session totals, one row per leg, indexed by [`Direction`].
    ///
    /// One recorder serves every forwarding task of a session, so a single
    /// row would answer "how much was shaped" and refuse to answer "on
    /// which side" — the question an author shaping both legs is actually
    /// asking. Two rows and an index cost the writers nothing: charging a
    /// total is still one relaxed `fetch_add` at a known offset.
    totals: [DirectionCounters; 2],
    /// This session's proxy's counters, or `None` when it has no proxy.
    ///
    /// Forwarded to by every writer below rather than reached by a separate
    /// call at each site. One call charges both recorders or neither, so
    /// there is no way to add a producer to a session figure and forget the
    /// proxy figure beside it — which is the failure a second set of call
    /// sites would make inevitable and silent.
    ///
    /// `None` is not a degraded mode. A session constructed directly belongs
    /// to no proxy, so there is no aggregate for it to be part of, and it
    /// keeps reporting its own [`ShapeStats`] exactly as it always did.
    proxy: Option<Arc<ProxyRecorder>>,
    /// Whether this session's class list is the one the proxy's rows were
    /// sized from, which decides whether a `Class::Rule(index)` may address
    /// them. Resolved once at attach; see [`ProxyRecorder::row`].
    proxy_sized: bool,
}

impl ShapeRecorder {
    /// Pre-size the rows for `profile`'s classes, in configured order.
    ///
    /// `None` gives a recorder with no class rows — the unshaped session's
    /// shape, whose snapshot is `ShapeStats::default()`.
    ///
    /// The recorder this builds reports to no proxy. That is the right
    /// answer for a session driven directly, and
    /// [`Self::attached`] is what the accept loop
    /// uses instead.
    pub(crate) fn for_profile(profile: Option<&ShapeProfile>) -> Self {
        let classes = profile
            .map(|p| p.classes().iter().map(|c| ClassCounters::named(c.name.clone())).collect())
            .unwrap_or_default();
        Self {
            classes,
            // The default and unshapeable rows are unnamed by contract:
            // an empty `name` is what distinguishes them from a class the
            // user wrote, and a user-written class name is unique by
            // `ShapeError::DuplicateClassName`, so there is no collision.
            default_class: ClassCounters::named(String::new()),
            unshapeable: ClassCounters::named(String::new()),
            totals: [DirectionCounters::new(), DirectionCounters::new()],
            proxy: None,
            proxy_sized: false,
        }
    }

    /// The same recorder, additionally reporting into `proxy`.
    ///
    /// Built at the one moment a session is attached to a control plane —
    /// after it is constructed and before it runs — so the recorder that
    /// forwards is the recorder every forwarding task will clone, and no
    /// figure is charged before the forwarding target is in place.
    ///
    /// An unshaped session does **not** size the proxy's class rows. It has
    /// no classes to install, and installing its empty list would mean the
    /// first shaped session to arrive afterwards found rows it did not match
    /// and charged the default row forever. Nothing is lost by skipping it:
    /// an unshaped session's writers are all behind a configured profile, so
    /// it charges nothing at all.
    ///
    /// A **shaped** session cannot be in the same position any more:
    /// [`ShapeProfile::try_new`] refuses a profile with no classes, so
    /// `Some(profile)` always carries at least one class name to install.
    /// [`ProxyRecorder::adopt_classes`] keeps its own guard against an empty
    /// list all the same, and says there why.
    pub(crate) fn attached(profile: Option<&ShapeProfile>, proxy: Arc<ProxyRecorder>) -> Self {
        let mut recorder = Self::for_profile(profile);
        recorder.proxy_sized = match profile {
            Some(profile) => {
                let names: Vec<String> = profile.classes().iter().map(|c| c.name.clone()).collect();
                proxy.adopt_classes(&names)
            }
            None => false,
        };
        recorder.proxy = Some(proxy);
        recorder
    }

    /// This session's proxy row for `class`, when it has a proxy.
    fn proxy_row(&self, class: Class) -> Option<&ClassCounters> {
        self.proxy.as_ref().map(|proxy| proxy.row(class, self.proxy_sized))
    }

    /// Snapshot every counter for this session.
    ///
    /// Allocates: one `Vec` and one `String` per class row. Called by a
    /// reader (a test, or a control plane), never on the data path.
    ///
    /// The flat session totals are **computed here** from the two legs,
    /// which is why no writer maintains them. Two independently written
    /// counters can disagree, and the disagreement would surface as a
    /// conservation identity that fails for no reason a reader could act
    /// on; a sum taken at read time cannot.
    pub(crate) fn snapshot(&self) -> ShapeStats {
        let uplink = self.leg(Direction::Uplink).snapshot();
        let downlink = self.leg(Direction::Downlink).snapshot();
        ShapeStats {
            classes: self.classes.iter().map(ClassCounters::snapshot).collect(),
            default_class: self.default_class.snapshot(),
            unshapeable: self.unshapeable.snapshot(),
            objects_seen: uplink.objects_seen.saturating_add(downlink.objects_seen),
            bytes_shaped: uplink.bytes_shaped.saturating_add(downlink.bytes_shaped),
            objects_expired: uplink.objects_expired.saturating_add(downlink.objects_expired),
            streams_reset_by_shaping: uplink
                .streams_reset_by_shaping
                .saturating_add(downlink.streams_reset_by_shaping),
            streams_with_mixed_classes: uplink
                .streams_with_mixed_classes
                .saturating_add(downlink.streams_with_mixed_classes),
            uplink,
            downlink,
        }
    }

    /// One framed unit entered the shaping path, carrying `bytes` on the
    /// wire.
    ///
    /// Two relaxed `fetch_add`s, called from the object arm of
    /// `pipe_data_framed` **behind `ForwardCtx::shaping_enabled`** — so a
    /// session with no profile never reaches it, and `interest_none.rs`
    /// stays at an all-zero `Counters` and an all-zero `ShapeStats`
    /// together.
    ///
    /// This is the *seen* count, not a delivery count: it is taken where
    /// the unit becomes visible to the shaper, before any classification or
    /// bucket exists to say what became of it. `bytes_shaped` is therefore
    /// the left-hand side of the conservation identity from the start, and
    /// the units that add the per-class rows are adding the right-hand
    /// side rather than re-defining this one.
    /// `side` is the side the unit **arrived** on, which the caller already
    /// holds as the side it reports every other event for. Charging it here
    /// rather than deriving it later is what keeps *the downlink stalled*
    /// separable from "the uplink did", and it is a side rather than a
    /// [`Direction`] because the proxy-wide rows need the leg as well — a
    /// caller that passed a direction would have thrown away exactly the half
    /// of the answer [`ProxyStats::per_leg`] exists for.
    pub(crate) fn note_object_seen(&self, side: ProxySide, bytes: u64) {
        let leg = self.leg(Direction::from(side));
        leg.objects_seen.fetch_add(1, Ordering::Relaxed);
        leg.bytes_shaped.fetch_add(bytes, Ordering::Relaxed);
        if let Some(proxy) = &self.proxy {
            let cell = proxy.arrival(side);
            cell.objects_seen.fetch_add(1, Ordering::Relaxed);
            cell.bytes_shaped.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    /// `bytes` no rule could see entered the shaping path.
    /// The sibling of [`Self::note_object_seen`] for a unit with no
    /// `ObjectMeta` — a stream header, an oversized object's passthrough chunk,
    /// a bypassed stream's tail. One relaxed `fetch_add`, and deliberately
    /// **not** two: `objects_seen` counts what the *classifier* saw, and a
    /// header is not an object. Bumping it here would make the count that every
    /// fixture anchors on (*wait until all twelve objects have been
    /// classified*) depend on how many stream headers happened to arrive first.
    ///
    /// `bytes_shaped` does move, because it is the left-hand side of the
    /// conservation identity and the `unshapeable` row is one of that
    /// identity's right-hand terms. The row itself is charged on release,
    /// from the same `unit.len()`.
    pub(crate) fn note_unshapeable_seen(&self, side: ProxySide, bytes: u64) {
        self.leg(Direction::from(side)).bytes_shaped.fetch_add(bytes, Ordering::Relaxed);
        if let Some(proxy) = &self.proxy {
            proxy.arrival(side).bytes_shaped.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    /// One unit of `bytes` was discarded by [`Overflow::DropTail`], charged
    /// to the class that claimed it.
    ///
    /// No side, because nothing this moves is per leg: a drop is a fact
    /// about a *rule*, and the leg it happened on is already in the
    /// difference between the two cells of that direction — the bytes were
    /// charged where they arrived and are never charged where they would
    /// have left.
    ///
    /// [`Overflow::DropTail`]: super::Overflow::DropTail
    pub(crate) fn note_dropped(&self, class: Class, bytes: u64) {
        for row in [Some(self.row(class)), self.proxy_row(class)].into_iter().flatten() {
            row.objects_dropped.fetch_add(1, Ordering::Relaxed);
            row.bytes_dropped.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    /// One **episode** of the read side being stalled by
    /// [`Overflow::Block`] began.
    ///
    /// Edge-triggered by the caller, which owns the per-stream latch: level
    /// counting here would report the runner's read batching rather than
    /// the shaper. Charged to the class of the last unit classified on the
    /// stream — the one whose admission filled the queue — because a stall
    /// is a property of a stream and a stream has no single class.
    ///
    /// [`Overflow::Block`]: super::Overflow::Block
    pub(crate) fn note_blocked(&self, class: Class) {
        for row in [Some(self.row(class)), self.proxy_row(class)].into_iter().flatten() {
            row.blocked_episodes.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// A destination stream carrying traffic that arrived on `side` was
    /// abandoned by a shaping policy.
    ///
    /// Charged to the **arrival** cell, like every other decision figure,
    /// and not to the leg the abandoned stream is physically on. What a
    /// reader wants from it is which of the two flows the profile gave up
    /// on, and the flow is named by where its traffic came from; splitting
    /// this one figure the other way would put it in a different cell from
    /// the `bytes_shaped` that explains it.
    pub(crate) fn note_stream_reset_by_shaping(&self, side: ProxySide) {
        self.leg(Direction::from(side)).streams_reset_by_shaping.fetch_add(1, Ordering::Relaxed);
        if let Some(proxy) = &self.proxy {
            proxy.arrival(side).streams_reset_by_shaping.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// One unit of `bytes` was released to the destination stream.
    ///
    /// The right-hand term the conservation identity was missing: with this
    /// producer in place, `Σ classes(delivered + dropped) + default +
    /// unshapeable == bytes_shaped` holds for a stream that ran to
    /// completion. It is charged from the same `raw.len()` `note_object_seen`
    /// took, so the identity is over one measurement rather than two.
    /// A teardown flush counts here too. `write_all` returning is the only
    /// definition of *released to the destination stream* this side of the
    /// transport, and the bytes it could not vouch for are separately reported
    /// as `QueuedBytesAtTeardown` — an over-report there is a diagnosable
    /// nuisance, a byte missing from both is a hole in the identity.
    ///
    /// `side` is still the side the unit **arrived** on — every caller holds
    /// that one and only that one — and it is the proxy-wide rows that turn
    /// it around: a release is the second and last time a unit is measured,
    /// on the leg it is leaving by, so [`ProxyRecorder::departure`] is what
    /// this charges. The session's own rows are untouched by that, because
    /// they have no leg axis to be wrong about.
    ///
    /// The proxy's departure cell counts an object only for a unit that
    /// carried one. [`Class::Unshapeable`] is the tag every unit no rule
    /// could see is pushed with — a stream header, an oversized passthrough
    /// chunk — and `objects_seen` is the *classifier's* count on both cells
    /// or it is not one figure at all: a header is not an object on the way
    /// in and it is not one on the way out.
    pub(crate) fn note_delivered(&self, side: ProxySide, class: Class, bytes: u64) {
        for row in [Some(self.row(class)), self.proxy_row(class)].into_iter().flatten() {
            row.objects_delivered.fetch_add(1, Ordering::Relaxed);
            row.bytes_delivered.fetch_add(bytes, Ordering::Relaxed);
        }
        if let Some(proxy) = &self.proxy {
            let cell = proxy.departure(side);
            cell.bytes_shaped.fetch_add(bytes, Ordering::Relaxed);
            if class != Class::Unshapeable {
                cell.objects_seen.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// One **episode** of a class's own bucket being dry began.
    /// Edge-triggered by the caller, which owns the per-stream latch, for the
    /// same reason [`Self::note_blocked`] is: a level count would report how
    /// often the release branch woke rather than how often the shaper ran out.
    /// Deliberately **not** bumped when a [`Discipline`](super::Discipline) is
    /// what held the unit back — that is [`Self::note_starved`], and conflating
    /// the two would make *my bucket is too small* and *another class is ahead
    /// of me* one unactionable number.
    pub(crate) fn note_tokens_exhausted(&self, class: Class) {
        for row in [Some(self.row(class)), self.proxy_row(class)].into_iter().flatten() {
            row.tokens_exhausted_episodes.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// One unit waited behind a unit of a *different* class.
    ///
    /// Per unit, once — the queue marks a unit as it charges it. Both causes
    /// of head-of-line waiting land here: a discipline holding this class
    /// back behind a rival, and a same-stream head of another class that the
    /// single per-stream FIFO cannot be reordered around.
    pub(crate) fn note_starved(&self, class: Class) {
        for row in [Some(self.row(class)), self.proxy_row(class)].into_iter().flatten() {
            row.starved_behind_other_class.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// One queued object outlived its clamp under
    /// [`Expiry::ResetStream`](super::Expiry::ResetStream).
    ///
    /// Zero under the default [`Expiry::Deliver`](super::Expiry::Deliver),
    /// which delivers the object instead of expiring it — that arm has no
    /// producer here and deliberately so.
    ///
    /// Charged to `side`'s **arrival** cell: the object was read and never
    /// written, so the leg it would have left by never carried it.
    pub(crate) fn note_expired(&self, side: ProxySide) {
        self.leg(Direction::from(side)).objects_expired.fetch_add(1, Ordering::Relaxed);
        if let Some(proxy) = &self.proxy {
            proxy.arrival(side).objects_expired.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// One stream carried units of two different classes.
    ///
    /// Once per stream, latched by the caller. Head-gating means such a
    /// stream's throughput is decided by whichever class is at its head, so
    /// without this count a scenario author cannot tell configured shaping
    /// from head-of-line blocking.
    pub(crate) fn note_mixed_class_stream(&self, side: ProxySide) {
        self.leg(Direction::from(side)).streams_with_mixed_classes.fetch_add(1, Ordering::Relaxed);
        if let Some(proxy) = &self.proxy {
            proxy.arrival(side).streams_with_mixed_classes.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The row one class's units are charged to.
    ///
    /// A [`Class::Rule`] index out of range cannot happen — the indices
    /// come from the same profile the rows were pre-sized from — but this
    /// is on a forwarding task, where a total function beats a panicking
    /// one: an impossible index charges the default row rather than killing
    /// the stream.
    fn row(&self, class: Class) -> &ClassCounters {
        match class {
            Class::Rule(index) => self.classes.get(index).unwrap_or(&self.default_class),
            Class::Default => &self.default_class,
            Class::Unshapeable => &self.unshapeable,
        }
    }

    /// The session totals one leg's units are charged to.
    fn leg(&self, direction: Direction) -> &DirectionCounters {
        &self.totals[direction.index()]
    }
}

impl std::fmt::Debug for ShapeRecorder {
    /// Prints the snapshot, not the atomics.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ShapeRecorder").field(&self.snapshot()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shape::{BucketConfig, ClassRule, Discipline, Matcher, QueueConfig};

    /// A valid profile whose classes are `names`, in that order. Struct
    /// literals rather than field assignment: `#[non_exhaustive]` does not
    /// apply inside the defining crate, and `..Default::default()` is what
    /// clippy's `field_reassign_with_default` asks for.
    fn profile(names: &[&str]) -> ShapeProfile {
        let bucket = BucketConfig { name: "b".to_string(), ..BucketConfig::default() };
        let classes = names
            .iter()
            .map(|n| ClassRule {
                name: (*n).to_string(),
                bucket: "b".to_string(),
                matcher: Matcher::default(),
                ..ClassRule::default()
            })
            .collect();
        ShapeProfile::try_new(vec![bucket], classes, QueueConfig::default(), Discipline::Fifo)
            .expect("the fixture names its own bucket and its classes are unique")
    }

    /// No profile means no rows and an all-default snapshot — the claim
    /// `interest_none.rs` rests on, checked without a session.
    /// *Ablation, recorded:* give the `None` arm of `for_profile` one row
    /// (`unwrap_or_else(|| vec![ClassCounters::named(String::new())])`). Every
    /// counter is still zero and the compare still reddens, on `classes:
    /// [ClassStats { .. }]` against `classes: []` — which is the point: a
    /// `ShapeStats` that is *all zeros but shaped* is not `default()`, and the
    /// integration gate compares the whole struct.
    #[test]
    fn an_unshaped_recorder_snapshots_as_default() {
        let rec = ShapeRecorder::for_profile(None);
        assert_eq!(rec.snapshot(), ShapeStats::default());
    }

    /// Rows are pre-sized and ordered by the configured class order, not by
    /// name and not by first use — a class that never saw a unit is present
    /// with a zero row.
    ///
    /// Order is not decoration: it is what lets the data path address a row
    /// by index instead of by name, which is the whole reason the storage
    /// is a `Vec` and not a map. The two class names are deliberately in
    /// non-alphabetical order, so a snapshot that sorted would redden here
    /// too.
    ///
    /// *Ablation, recorded:* `.rev()` the class iteration in `for_profile`
    /// — `left: ["audio", "video"]`, `right: ["video", "audio"]`.
    #[test]
    fn rows_are_pre_sized_in_configured_order() {
        let rec = ShapeRecorder::for_profile(Some(&profile(&["video", "audio"])));
        let stats = rec.snapshot();
        assert_eq!(
            stats.classes.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
            vec!["video", "audio"],
            "snapshot order is the configured order, so a reader can index it"
        );
        assert!(
            stats
                .classes
                .iter()
                .all(|c| *c == ClassStats { name: c.name.clone(), ..ClassStats::default() }),
            "a class that saw nothing reports a zero row rather than being absent"
        );
    }

    /// The see-point producer moves exactly two totals and leaves every
    /// class row alone.
    ///
    /// Two calls with different byte counts, so a `bytes_shaped` that
    /// counted calls rather than bytes, or that overwrote rather than
    /// accumulated, is separable from one that adds: only addition gives
    /// `2` and `42` together.
    ///
    /// The three zero assertions are the boundary the release side moves.
    /// Attribution is charged when a unit is *released*, from the same
    /// measurement taken here, so a class row moving at the see-point would
    /// mean the same byte counted twice on the right-hand side of the
    /// conservation identity.
    ///
    /// *Ablation, recorded:* have `note_object_seen` also bump
    /// `default_class.objects_delivered` —
    /// `left: ClassStats { .., objects_delivered: 2, .. }` against
    /// `right: ClassStats { .., objects_delivered: 0, .. }`.
    #[test]
    fn note_object_seen_moves_the_session_totals_only() {
        let rec = ShapeRecorder::for_profile(Some(&profile(&["video"])));
        rec.note_object_seen(ProxySide::ClientToProxy, 40);
        rec.note_object_seen(ProxySide::ClientToProxy, 2);
        let stats = rec.snapshot();
        assert_eq!(stats.objects_seen, 2);
        assert_eq!(stats.bytes_shaped, 42);
        assert_eq!(stats.classes[0].bytes_delivered, 0, "release is what attributes bytes");
        assert_eq!(stats.default_class, ClassStats::default());
        assert_eq!(stats.unshapeable, ClassStats::default());
    }

    /// One recorder, both legs busy: every session total lands on the side
    /// it was charged from, and the flat total is the two sides added.
    ///
    /// This is the shape of a session shaping in both directions, which is
    /// the case a single set of totals cannot report: the recorder is
    /// shared by every forwarding task, so before the split "5 objects
    /// seen" was compatible with 5/0, 0/5 and anything between, and an
    /// author diagnosing a stall could not tell which leg had it.
    ///
    /// Both legs are compared **whole** rather than field by field, so a
    /// figure leaking into a neighbouring total on the correct leg reddens
    /// too. Every quantity differs between the legs — 2 objects against 3,
    /// 49 bytes against 605, one reset against three — so swapping the two
    /// rows fails on all of them rather than on none.
    ///
    /// The sums are stated because they are the guarantee a reader relies on
    /// when mixing the two forms; they hold by construction of `snapshot`,
    /// which sums the legs rather than keeping a third counter. What the
    /// per-leg equalities above them falsify is the attribution, and that
    /// is the part no arithmetic guarantees.
    ///
    /// *Ablation, recorded:* swap the two legs in `snapshot`, so each row is
    /// reported under the other's name. Every sum below still passes —
    /// addition does not care which order it is given — and the uplink
    /// compare reddens with `left: DirectionStats { objects_seen: 3,
    /// bytes_shaped: 605, objects_expired: 2, streams_reset_by_shaping: 3,
    /// streams_with_mixed_classes: 0 }` against `right: DirectionStats {
    /// objects_seen: 2, bytes_shaped: 49, objects_expired: 0,
    /// streams_reset_by_shaping: 1, streams_with_mixed_classes: 1 }`. That
    /// is the whole case for the per-leg equalities: they are the part the
    /// arithmetic cannot check.
    ///
    /// *Ablation, recorded:* collapse the split instead — have
    /// `ShapeRecorder::leg` ignore its argument and always answer
    /// `&self.totals[0]`. The uplink compare reddens with `left:
    /// DirectionStats { objects_seen: 5, bytes_shaped: 654, objects_expired:
    /// 2, streams_reset_by_shaping: 4, streams_with_mixed_classes: 1 }`, and
    /// `note_object_seen_moves_the_session_totals_only` goes with it on
    /// `left: 4 right: 2` — the aggregate counts the one surviving row
    /// twice.
    #[test]
    fn a_bidirectional_run_charges_each_leg_and_the_legs_sum_to_the_aggregate() {
        let rec = ShapeRecorder::for_profile(Some(&profile(&["video", "audio"])));

        // Uplink: two objects, a stream header no rule could see, one
        // mixed-class stream and one stream the policy gave up on.
        rec.note_object_seen(ProxySide::ClientToProxy, 40);
        rec.note_object_seen(ProxySide::ClientToProxy, 2);
        rec.note_unshapeable_seen(ProxySide::ClientToProxy, 7);
        rec.note_mixed_class_stream(ProxySide::ClientToProxy);
        rec.note_stream_reset_by_shaping(ProxySide::ClientToProxy);

        // Downlink: more of everything, and two expiries the uplink has
        // none of.
        rec.note_object_seen(ProxySide::RelayToProxy, 100);
        rec.note_object_seen(ProxySide::RelayToProxy, 200);
        rec.note_object_seen(ProxySide::RelayToProxy, 300);
        rec.note_unshapeable_seen(ProxySide::RelayToProxy, 5);
        rec.note_expired(ProxySide::RelayToProxy);
        rec.note_expired(ProxySide::RelayToProxy);
        rec.note_stream_reset_by_shaping(ProxySide::RelayToProxy);
        rec.note_stream_reset_by_shaping(ProxySide::RelayToProxy);
        rec.note_stream_reset_by_shaping(ProxySide::RelayToProxy);

        let stats = rec.snapshot();
        assert_eq!(
            stats.uplink,
            DirectionStats {
                objects_seen: 2,
                bytes_shaped: 49,
                objects_expired: 0,
                streams_reset_by_shaping: 1,
                streams_with_mixed_classes: 1,
            },
            "the uplink reports what the uplink was charged, and nothing else"
        );
        assert_eq!(
            stats.downlink,
            DirectionStats {
                objects_seen: 3,
                bytes_shaped: 605,
                objects_expired: 2,
                streams_reset_by_shaping: 3,
                streams_with_mixed_classes: 0,
            },
            "the downlink's two expiries are its own: a starved downlink must \
             not read as a starved uplink"
        );

        assert_eq!(stats.uplink.objects_seen + stats.downlink.objects_seen, stats.objects_seen);
        assert_eq!(stats.uplink.bytes_shaped + stats.downlink.bytes_shaped, stats.bytes_shaped);
        assert_eq!(
            stats.uplink.objects_expired + stats.downlink.objects_expired,
            stats.objects_expired
        );
        assert_eq!(
            stats.uplink.streams_reset_by_shaping + stats.downlink.streams_reset_by_shaping,
            stats.streams_reset_by_shaping
        );
        assert_eq!(
            stats.uplink.streams_with_mixed_classes + stats.downlink.streams_with_mixed_classes,
            stats.streams_with_mixed_classes
        );

        // Splitting the totals must not have started attributing anything:
        // the class rows are release's, and nothing here released a unit.
        assert!(
            stats
                .classes
                .iter()
                .all(|c| *c == ClassStats { name: c.name.clone(), ..ClassStats::default() }),
            "no class row moved, on either leg"
        );
        assert_eq!(stats.default_class, ClassStats::default());
        assert_eq!(stats.unshapeable, ClassStats::default());
    }

    /// Every ingress side maps to the leg its traffic is on, and each
    /// egress side maps to the same leg as the ingress side it pairs with.
    ///
    /// The mapping is total because the recorder has no fifth row to put a
    /// surprise on: a `ProxySide` that fell through would have to invent a
    /// leg, and an invented leg is a byte silently attributed to the wrong
    /// side of the session.
    #[test]
    fn every_side_maps_to_the_leg_its_traffic_travels_on() {
        assert_eq!(Direction::from(ProxySide::ClientToProxy), Direction::Uplink);
        assert_eq!(Direction::from(ProxySide::ProxyToRelay), Direction::Uplink);
        assert_eq!(Direction::from(ProxySide::RelayToProxy), Direction::Downlink);
        assert_eq!(Direction::from(ProxySide::ProxyToClient), Direction::Downlink);
    }

    /// Every side names one connection and one way along it, and the four
    /// pairs are all different.
    ///
    /// The pair is what [`ProxyStats::per_leg`] is indexed by, so a mapping
    /// that sent two sides to the same cell would merge two flows with
    /// nothing going red anywhere else — the aggregate would still be right.
    /// Written as four equalities against the four pairs rather than as a
    /// round trip, because the claim is *which* pair, not that some pair
    /// exists.
    #[test]
    fn every_side_names_one_cell_of_the_two_by_two() {
        assert_eq!(split(ProxySide::ClientToProxy), (Leg::Client, Direction::Uplink));
        assert_eq!(split(ProxySide::ProxyToRelay), (Leg::Upstream, Direction::Uplink));
        assert_eq!(split(ProxySide::RelayToProxy), (Leg::Upstream, Direction::Downlink));
        assert_eq!(split(ProxySide::ProxyToClient), (Leg::Client, Direction::Downlink));

        // Four sides, four cells, no collisions: the property the four lines
        // above are for, stated so a fifth arm added later cannot quietly
        // land on a cell that is already taken.
        let mut cells: Vec<_> = [
            ProxySide::ClientToProxy,
            ProxySide::ProxyToRelay,
            ProxySide::RelayToProxy,
            ProxySide::ProxyToClient,
        ]
        .into_iter()
        .map(|side| {
            let (leg, direction) = split(side);
            (leg_index(leg), direction.index())
        })
        .collect();
        cells.sort_unstable();
        cells.dedup();
        assert_eq!(cells.len(), 4, "two sides charge the same cell");
    }

    /// A proxy recorder and one session reporting into it, on the class list
    /// `names`.
    fn attached(names: &[&str]) -> (Arc<ProxyRecorder>, ShapeRecorder) {
        let proxy = Arc::new(ProxyRecorder::new());
        let recorder = ShapeRecorder::attached(Some(&profile(names)), Arc::clone(&proxy));
        (proxy, recorder)
    }

    /// A bidirectional run over the class `video`, in which all four
    /// crossings carry a different number of bytes and a different number of
    /// objects.
    ///
    /// Uplink: two objects (40 and 2) and a 7-byte stream header arrive from
    /// the client; one 40-byte object is dropped by policy, so a 30-byte
    /// object and the header go out to the relay. Downlink: four objects
    /// (100, 200, 300, 400) and a 5-byte header arrive from the relay, one
    /// expires and takes its stream with it, and three objects and the
    /// header go out to the client.
    ///
    /// Every figure differs from every other, in both directions and on both
    /// legs, so no swap of two cells and no collapse of either axis can
    /// cancel out.
    fn bidirectional_run(rec: &ShapeRecorder) {
        let video = Class::Rule(0);

        // Read from the client.
        rec.note_object_seen(ProxySide::ClientToProxy, 40);
        rec.note_object_seen(ProxySide::ClientToProxy, 2);
        rec.note_unshapeable_seen(ProxySide::ClientToProxy, 7);
        rec.note_mixed_class_stream(ProxySide::ClientToProxy);
        rec.note_dropped(video, 12);
        // Written to the relay. Still the arrival side: turning it around is
        // the recorder's job.
        rec.note_delivered(ProxySide::ClientToProxy, video, 30);
        rec.note_delivered(ProxySide::ClientToProxy, Class::Unshapeable, 7);

        // Read from the relay.
        rec.note_object_seen(ProxySide::RelayToProxy, 100);
        rec.note_object_seen(ProxySide::RelayToProxy, 200);
        rec.note_object_seen(ProxySide::RelayToProxy, 300);
        rec.note_object_seen(ProxySide::RelayToProxy, 400);
        rec.note_unshapeable_seen(ProxySide::RelayToProxy, 5);
        rec.note_expired(ProxySide::RelayToProxy);
        rec.note_stream_reset_by_shaping(ProxySide::RelayToProxy);
        rec.note_dropped(video, 400);
        // Written to the client.
        rec.note_delivered(ProxySide::RelayToProxy, video, 100);
        rec.note_delivered(ProxySide::RelayToProxy, video, 200);
        rec.note_delivered(ProxySide::RelayToProxy, video, 300);
        rec.note_delivered(ProxySide::RelayToProxy, Class::Unshapeable, 5);
    }

    /// The four crossings of a proxy land in four different cells, and each
    /// cell reports its own crossing.
    ///
    /// This is the attribution claim, and it is the one no arithmetic
    /// checks. A proxy holds two connections and a byte crosses both — read
    /// on one leg, written on the other — so leg and direction are
    /// genuinely two axes and the surface has four cells to fill. Two
    /// mistakes fill them wrongly while leaving every total intact, and
    /// either one hides the other: charging every unit to the direction the
    /// first arm happened to name, and deriving the leg from the arriving
    /// side so that both legs report the same row. Comparing all four rows
    /// **whole** is what separates them; comparing one, or comparing a sum,
    /// separates neither.
    ///
    /// The two upstream figures are what the shape exists for. The uplink
    /// pair, 49 bytes in against 37 out, is the shaper's own retention on
    /// that direction — bytes it read from the client and did not write to
    /// the relay — and it is a number that can only be non-zero because the
    /// two cells are measured at two different crossings.
    ///
    /// The three event figures move on the arrival cell only, and the zeros
    /// for them on the two departure cells are asserted rather than elided:
    /// an expiry is a decision over traffic that came in and never went out,
    /// so a departure cell that reported one would be claiming a crossing
    /// that did not happen.
    ///
    /// *Ablation, recorded:* collapse the leg axis — have `leg_index`
    /// answer `0` for both legs, so every figure lands on the client row.
    /// The first compare reddens with `left: DirectionStats { objects_seen:
    /// 3, bytes_shaped: 86, objects_expired: 0, streams_reset_by_shaping: 0,
    /// streams_with_mixed_classes: 1 }` against `right: DirectionStats {
    /// objects_seen: 2, bytes_shaped: 49, objects_expired: 0,
    /// streams_reset_by_shaping: 0, streams_with_mixed_classes: 1 }` — what
    /// was written to the relay piled on top of what was read from the
    /// client.
    ///
    /// *Ablation, recorded:* derive the leg from the arriving side instead —
    /// name `Leg::Client` in both upstream arms of `split`, which is what
    /// that derivation amounts to over the two sides a hook site can hold.
    /// The upstream downlink compare reddens with `left: DirectionStats {
    /// objects_seen: 3, bytes_shaped: 605, objects_expired: 0,
    /// streams_reset_by_shaping: 0, streams_with_mixed_classes: 0 }` against
    /// `right: DirectionStats { objects_seen: 4, bytes_shaped: 1005,
    /// objects_expired: 1, streams_reset_by_shaping: 1,
    /// streams_with_mixed_classes: 0 }` — the two downlink cells swapped,
    /// so what this proxy read from the relay is reported as what it sent to
    /// the client. Every total still adds up, and every sum still passes.
    ///
    /// *Ablation, recorded:* collapse the direction axis instead — name
    /// `Direction::Uplink` in both downlink arms of `split`. The first
    /// compare reddens with `left: DirectionStats { objects_seen: 5,
    /// bytes_shaped: 654, objects_expired: 0, streams_reset_by_shaping: 0,
    /// streams_with_mixed_classes: 1 }` against `right: DirectionStats {
    /// objects_seen: 2, bytes_shaped: 49, objects_expired: 0,
    /// streams_reset_by_shaping: 0, streams_with_mixed_classes: 1 }` — both
    /// directions piled into row 0.
    ///
    /// *Ablation, recorded:* keep both axes and drop the turn-around — have
    /// `ProxyRecorder::departure` answer `self.arrival(side)`. The first
    /// compare reddens with `left: DirectionStats { objects_seen: 3,
    /// bytes_shaped: 86, objects_expired: 0, streams_reset_by_shaping: 0,
    /// streams_with_mixed_classes: 1 }` against the same right-hand side as
    /// the leg collapse above — the two mutations are different mistakes
    /// with one observable, because a proxy that cannot tell its legs apart
    /// and a proxy that never turns a release around both file a write where
    /// the read went.
    #[test]
    fn each_crossing_charges_its_own_cell_of_the_two_by_two() {
        let (proxy, rec) = attached(&["video"]);
        bidirectional_run(&rec);
        let stats = proxy.snapshot();

        assert_eq!(
            *stats.leg(Leg::Client).uplink(),
            DirectionStats {
                objects_seen: 2,
                bytes_shaped: 49,
                objects_expired: 0,
                streams_reset_by_shaping: 0,
                streams_with_mixed_classes: 1,
            },
            "what this proxy read from the client"
        );
        assert_eq!(
            *stats.leg(Leg::Upstream).uplink(),
            DirectionStats {
                objects_seen: 1,
                bytes_shaped: 37,
                objects_expired: 0,
                streams_reset_by_shaping: 0,
                streams_with_mixed_classes: 0,
            },
            "what it wrote to the relay — 12 bytes short of what it read, \
             because a policy dropped an object"
        );
        assert_eq!(
            *stats.leg(Leg::Upstream).downlink(),
            DirectionStats {
                objects_seen: 4,
                bytes_shaped: 1005,
                objects_expired: 1,
                streams_reset_by_shaping: 1,
                streams_with_mixed_classes: 0,
            },
            "what it read from the relay"
        );
        assert_eq!(
            *stats.leg(Leg::Client).downlink(),
            DirectionStats {
                objects_seen: 3,
                bytes_shaped: 605,
                objects_expired: 0,
                streams_reset_by_shaping: 0,
                streams_with_mixed_classes: 0,
            },
            "what it wrote to the client"
        );
    }

    /// A stream header crosses both legs as bytes and as no object at all.
    ///
    /// `objects_seen` is the classifier's count, and the classifier runs
    /// where traffic arrives — so on the way in a header is charged to
    /// `bytes_shaped` and not to `objects_seen`. The departure cell has to
    /// hold the same line or the field means two different things in two
    /// cells of the same array, and the difference between the two would
    /// read as objects this proxy invented.
    ///
    /// *Ablation, recorded:* drop the `class != Class::Unshapeable` guard in
    /// `note_delivered`, so every released unit counts as an object. The
    /// compare reddens with `left: 2` against `right: 1` — the header
    /// counted as an object on the way out and not on the way in.
    #[test]
    fn a_released_header_is_bytes_on_the_departure_cell_and_not_an_object() {
        let (proxy, rec) = attached(&["video"]);
        rec.note_unshapeable_seen(ProxySide::ClientToProxy, 7);
        rec.note_object_seen(ProxySide::ClientToProxy, 40);
        rec.note_delivered(ProxySide::ClientToProxy, Class::Unshapeable, 7);
        rec.note_delivered(ProxySide::ClientToProxy, Class::Rule(0), 40);

        let stats = proxy.snapshot();
        let out = stats.leg(Leg::Upstream).uplink();
        assert_eq!(out.bytes_shaped, 47, "both units crossed, and both are bytes");
        assert_eq!(out.objects_seen, 1, "a header is not an object on the way out either");
        assert_eq!(
            stats.unshapeable.objects_delivered, 1,
            "the unshapeable row still counts the unit it released"
        );
    }

    /// The flat rollup counts a byte where it **entered**, once.
    ///
    /// Derived rather than accumulated, so it cannot drift from the cells
    /// beside it — but *which* cells it is derived from is a real choice and
    /// the wrong one is invisible. A byte crosses two legs, so the obvious
    /// summation, all four cells, reports every byte twice and looks
    /// entirely plausible: it is monotone, it is proportional to the
    /// traffic, and it is about double.
    ///
    /// The compare is over the **whole struct** rather than the fields this
    /// test has an opinion about, so a field added to [`SessionStats`] later
    /// and derived from the wrong cells cannot slip past it.
    ///
    /// *Ablation, re-run:* sum all four cells in `ProxyRecorder::snapshot`
    /// instead of the two arrival cells. The compare reddens with `left:
    /// SessionStats { objects_seen: 10, objects_dropped: 2, objects_expired:
    /// 1, streams_reset: 1, bytes_shaped: 1696 }` against `right:
    /// SessionStats { objects_seen: 6, .., bytes_shaped: 1054 }` — every byte
    /// counted twice, and nothing else out of place.
    #[test]
    fn the_flat_rollup_counts_a_byte_where_it_entered() {
        let (proxy, rec) = attached(&["video"]);
        bidirectional_run(&rec);

        assert_eq!(
            proxy.snapshot().sessions,
            SessionStats {
                objects_seen: 6,
                objects_dropped: 2,
                objects_expired: 1,
                streams_reset: 1,
                bytes_shaped: 1054,
            },
            "49 + 1005 bytes in, not 49 + 37 + 1005 + 605 crossings"
        );
    }

    /// A session reports both to itself and to its proxy, and the two agree
    /// about everything they both hold.
    ///
    /// The reason the forwarding lives inside the recorder rather than at a
    /// second set of call sites: one call charges both or neither, so a
    /// producer cannot be added to a session figure and forgotten beside it.
    /// The comparison is over the figures the two types share — the flat
    /// session totals and the class rows — because those are the ones a
    /// reader would put side by side and expect to match.
    ///
    /// *Ablation, recorded:* drop the proxy forward from
    /// `note_object_seen`. The compare reddens with `left: 0` against
    /// `right: 6` — the session still reports six objects and the proxy
    /// reports none of them.
    #[test]
    fn one_session_charges_its_own_rows_and_its_proxys_together() {
        let (proxy, rec) = attached(&["video"]);
        bidirectional_run(&rec);

        let session = rec.snapshot();
        let aggregate = proxy.snapshot();
        assert_eq!(aggregate.sessions.objects_seen, session.objects_seen);
        assert_eq!(aggregate.sessions.bytes_shaped, session.bytes_shaped);
        assert_eq!(aggregate.sessions.objects_expired, session.objects_expired);
        assert_eq!(aggregate.sessions.streams_reset, session.streams_reset_by_shaping);
        assert_eq!(aggregate.classes, session.classes);
        assert_eq!(aggregate.unshapeable, session.unshapeable);
    }

    /// A session with no proxy charges no proxy.
    ///
    /// `ShapeRecorder::for_profile` is what a session constructed directly
    /// gets, and such a session belongs to no proxy: it never went through
    /// an accept loop, so no [`ProxyStats`] should claim its traffic. The
    /// proxy recorder here is built and driven past — the run below charges
    /// a recorder that was never attached to it — and it must still snapshot
    /// as default.
    #[test]
    fn a_session_with_no_proxy_leaves_the_aggregate_alone() {
        let proxy = Arc::new(ProxyRecorder::new());
        let rec = ShapeRecorder::for_profile(Some(&profile(&["video"])));
        bidirectional_run(&rec);

        assert_ne!(rec.snapshot(), ShapeStats::default(), "the session recorded its own run");
        assert_eq!(proxy.snapshot(), ProxyStats::default());
    }

    /// Class rows are sized by the first shaped session, and a later session
    /// on a different class list charges the default row rather than a row
    /// named for somebody else's rule.
    ///
    /// A `Class::Rule(index)` is an index into the class list of the
    /// scheduler that produced it. A live `set_shape` that installs a
    /// different list reaches sessions accepted afterwards, so the second
    /// session here is that session — and if it charged by index anyway,
    /// every figure it produced would be reported under the first profile's
    /// names, monotone and plausible and wrong. The default row is where a
    /// unit whose row cannot be named belongs, which is the answer
    /// `ShapeRecorder::row` already gives an index it cannot place.
    ///
    /// *Ablation, recorded:* have `ProxyRecorder::row` ignore `sized`. The
    /// compare reddens with `left: 500` against `right: 100` — the second
    /// session's bytes filed under `video`, a class it never had.
    #[test]
    fn a_session_on_another_class_list_charges_the_default_row() {
        let proxy = Arc::new(ProxyRecorder::new());
        let first = ShapeRecorder::attached(Some(&profile(&["video"])), Arc::clone(&proxy));
        let second = ShapeRecorder::attached(Some(&profile(&["screen"])), Arc::clone(&proxy));

        first.note_delivered(ProxySide::ClientToProxy, Class::Rule(0), 100);
        second.note_delivered(ProxySide::ClientToProxy, Class::Rule(0), 400);

        let stats = proxy.snapshot();
        assert_eq!(
            stats.classes.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
            vec!["video"],
            "the rows are the first shaped session's, and are never resized"
        );
        assert_eq!(stats.classes[0].bytes_delivered, 100, "only the matching session's bytes");
        assert_eq!(stats.default_class.bytes_delivered, 400, "the mismatched session's go here");
    }

    /// An unshaped session does not size the proxy's class rows.
    ///
    /// It has no classes to install, and installing its empty list would
    /// leave every shaped session that arrived afterwards mismatched
    /// forever — charging the default row for the life of the proxy because
    /// the first connection happened to be one nobody configured shaping
    /// for. Nothing is lost by skipping it: an unshaped session's writers
    /// are all behind a configured profile, so it charges nothing at all.
    ///
    /// *Ablation, recorded:* let the `None` arm of `ShapeRecorder::attached`
    /// adopt an empty class list too. The compare reddens with `left: []`
    /// against `right: ["video"]` — the proxy sized itself from a session
    /// that had no classes, and the shaped session behind it has no row.
    #[test]
    fn an_unshaped_session_does_not_size_the_proxys_class_rows() {
        let proxy = Arc::new(ProxyRecorder::new());
        let _unshaped = ShapeRecorder::attached(None, Arc::clone(&proxy));
        let shaped = ShapeRecorder::attached(Some(&profile(&["video"])), Arc::clone(&proxy));

        shaped.note_delivered(ProxySide::ClientToProxy, Class::Rule(0), 64);

        let stats = proxy.snapshot();
        assert_eq!(
            stats.classes.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
            vec!["video"]
        );
        assert_eq!(stats.classes[0].bytes_delivered, 64);
    }

    /// An empty class list does not size the proxy's rows either.
    ///
    /// The sibling of the test above, and the case that one does not cover.
    /// The guard beside it keys on there being no profile; this one is about
    /// a list that is present and holds nothing.
    ///
    /// **It reaches [`ProxyRecorder::adopt_classes`] directly, and that is
    /// the point of this version of the row.** The way an empty list used to
    /// arrive was a `ShapeProfile` with no classes, which
    /// [`ShapeProfile::try_new`] accepted because it validated each class it
    /// was handed and had nothing to say about being handed none. That
    /// constructor now refuses one as `ShapeError::NoClasses`, so there is no
    /// profile left that could bring an empty list here and no public path
    /// that reaches this branch. The guard stays anyway, and so does this
    /// row: what it prevents is proxy-wide, silent and unrecoverable without
    /// a restart, and the check is a comparison that was being made in any
    /// case.
    ///
    /// An empty row set matches no later class list, so the proxy's rows
    /// would stay empty and every classed session accepted for the rest of
    /// its life would charge the default row — every figure right, every
    /// label gone, with nothing anywhere reporting it.
    ///
    /// The 100 bytes are asserted on the row rather than on the total,
    /// because a total is exactly what survives the bug: the bytes are never
    /// lost, only misfiled.
    ///
    /// *Ablation, run:* drop the `names.is_empty()` guard from
    /// `ProxyRecorder::adopt_classes`, which is the state this file shipped
    /// in. The first assertion reddens with
    ///
    /// ```text
    /// thread 'shape::stats::tests::an_empty_class_list_does_not_size_the_proxys_class_rows'
    /// (63164) panicked at crates\moqtap-proxy\src\shape\stats.rs:2053:9:
    /// a list with no rows in it names no row, so there is nothing for it to
    /// charge and nothing is lost by declining it
    /// ```
    ///
    /// The three assertions under it are not reached, so that is the whole of
    /// what the mutation was seen to produce; the misfiling they describe is
    /// what the empty row set leaves behind once the sizing has been lost.
    /// The bug this pins was found by probe rather than by review — a throwaway
    /// test printed `classes=[] default_bytes=100` against the shipped code.
    #[test]
    fn an_empty_class_list_does_not_size_the_proxys_class_rows() {
        let proxy = Arc::new(ProxyRecorder::new());
        assert!(
            !proxy.adopt_classes(&[]),
            "a list with no rows in it names no row, so there is nothing for it to charge and \
             nothing is lost by declining it"
        );
        let classed = ShapeRecorder::attached(Some(&profile(&["video"])), Arc::clone(&proxy));

        classed.note_delivered(ProxySide::ClientToProxy, Class::Rule(0), 100);

        let stats = proxy.snapshot();
        assert_eq!(
            stats.classes.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
            vec!["video"],
            "the classed session's rows are the proxy's rows: a list with nothing in it must not \
             install itself"
        );
        assert_eq!(stats.classes[0].bytes_delivered, 100, "and its bytes are charged by name");
        assert_eq!(
            stats.default_class.bytes_delivered, 0,
            "not to a row named for nobody, which is where they land once an empty list has won \
             the sizing"
        );
    }

    /// A reset zeroes every counter and keeps the class rows, and traffic
    /// after it accumulates from zero.
    ///
    /// The rows survive because they are what a `Class::Rule(index)` means:
    /// a reset that dropped them would let the next session install a
    /// different class list, which is the relabelling the sizing rule exists
    /// to prevent. So the observable is a class row that is present, still
    /// named, and empty.
    ///
    /// *Ablation, recorded:* have `ProxyRecorder::reset` skip the class rows
    /// — reset the four cells and stop. The compare reddens with `left:
    /// 630` against `right: 0`: the legs read as a proxy that has done
    /// nothing while the class rows still hold the whole run.
    #[test]
    fn a_reset_zeroes_the_counters_and_keeps_the_rows() {
        let (proxy, rec) = attached(&["video"]);
        bidirectional_run(&rec);
        assert_ne!(proxy.snapshot(), ProxyStats::default(), "there was something to clear");

        proxy.reset();
        let cleared = proxy.snapshot();
        assert_eq!(cleared.classes[0].bytes_delivered, 0);
        assert_eq!(cleared.classes[0].name, "video", "the row is still the row it was");
        assert_eq!(
            cleared,
            ProxyStats {
                classes: vec![ClassStats { name: "video".to_string(), ..ClassStats::default() }],
                ..ProxyStats::default()
            },
            "nothing but the row's name survives a reset"
        );

        rec.note_object_seen(ProxySide::ClientToProxy, 11);
        assert_eq!(proxy.snapshot().sessions.bytes_shaped, 11, "counting resumes from zero");
    }
}

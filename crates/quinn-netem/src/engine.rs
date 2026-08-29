//! The engine — clock-free, socket-free.
//!
//! [`Impairer::decide`] is the whole of this crate's decision surface. It takes
//! a sequence number, an on-wire byte count and a tick, and returns a
//! [`Decision`]. It reads no clock, touches no socket, allocates nothing, and
//! holds no hash map — the last because two hash maps in one process already
//! iterate in different orders, which would make a run depend on process-local
//! randomness.
//!
//! # The order the models are consulted, and why it is fixed
//!
//! 1. **Timeline** — the active profile is whichever step's tick has passed.
//! 2. **Blackout** — inside a window, drop. **No draw.**
//! 3. **MTU black hole** — over the limit, drop. **No draw.**
//! 4. **Loss** — Bernoulli, Gilbert-Elliott, an index list, or every n-th.
//! 5. **Rate** — the bounded byte queue first, then the token bucket.
//! 6. **Delay** — one sample, added to whatever tick the bucket allowed.
//! 7. **Reorder** — a candidate that hits reverts to `now`, skipping the queue.
//! 8. **Duplication** — an extra copy at the same release tick.
//! 9. **Corruption** — one bit at a drawn offset.
//!
//! Steps 2, 3 and 4 are terminal: a dropped datagram consumes nothing from the
//! later models' generators, so each model's stream is a function of the
//! datagrams that actually reached it rather than of the whole arrival pattern.
//! That is the network emulator's shape, and it is what makes a burst-loss
//! chain's state track the traffic it was configured against.
//!
//! The order is part of the decision-log format: reordering it changes every
//! recorded run.
//!
//! # One generator per model, per direction
//!
//! Each model draws from its own [`Pcg32`], seeded from the profile's seed and
//! the model's frozen stream id. Enabling duplication must not shift the loss
//! decisions — that is what lets switching one model off produce a decision-log
//! diff naming exactly one model. A shared generator makes every such diff a
//! whole-log rewrite that names nothing.
//!
//! # Everything is an integer
//!
//! Ticks are `u64` nanoseconds, probabilities are integer numerators over 2^32,
//! delays come out of committed integer tables, and the token bucket is scaled
//! integer arithmetic. One last-bit difference in a jitter sample is enough to
//! make two runs of a seed disagree, and std documents its transcendental
//! functions as permitted to differ between platforms and compiler versions.

use crate::dist::CorrState;
use crate::model::{sample_delay, LossModel, Prob, Window};
use crate::profile::{DirectionProfile, ProfileError};
use crate::queue::{charge, offer, Admission, BucketState, QueueState, RateGrant};
use crate::rng::{
    Pcg32, STREAM_DOWNLINK_CORRUPT, STREAM_DOWNLINK_DELAY, STREAM_DOWNLINK_DUP,
    STREAM_DOWNLINK_LOSS, STREAM_DOWNLINK_RATE_QUEUE, STREAM_DOWNLINK_REORDER,
    STREAM_UPLINK_CORRUPT, STREAM_UPLINK_DELAY, STREAM_UPLINK_DUP, STREAM_UPLINK_LOSS,
    STREAM_UPLINK_RATE_QUEUE, STREAM_UPLINK_REORDER,
};
use crate::stats::StatsSnapshot;
use crate::{Direction, Tick};

/// The largest link-layer overhead a datagram of a given on-wire size can be
/// carrying: 40 bytes of IPv6 header plus 8 of UDP.
///
/// The engine is told the **on-wire** size and deliberately not the peer's
/// address family — an address in the decision path would put an ephemeral port
/// and a platform-dependent address rendering into a log that has to be
/// byte-identical across machines. So when the corruption model needs a payload
/// offset, it bounds the draw by `wire_bytes - 48`: the smallest payload an
/// on-wire size of that many bytes can possibly correspond to, over any address
/// family.
///
/// The cost is that the last 20 bytes of a payload sent to an IPv4 peer are
/// never selected. The alternative — bounding by `wire_bytes - 28`, which is the
/// right answer for IPv4 — names a byte past the end of the payload for one
/// datagram in sixty over IPv6, and the layer that applies the flip would then
/// have to either clamp the offset (so the log names a byte that was not the one
/// flipped) or skip the flip (so an impairment is configured, counted, logged
/// and never delivered). Under-selecting is a bias; over-selecting is a lie.
const MAX_HEADER_WIRE_BYTES: u32 = 48;

/// The impairment engine for ONE direction.
///
/// Reads no clock, touches no socket, allocates nothing on the hot path, and
/// contains no hash map. [`Impairer::decide`] is a pure function of the profile,
/// the seed, its arguments and this struct's own integer state — which is what
/// lets the determinism gate be a plain `#[test]` with no async runtime, no QUIC
/// and no network.
#[derive(Debug, Clone)]
pub struct Impairer {
    /// The profile as armed, including its timeline. The step in force is
    /// selected from `now` on every decision rather than latched, so a caller
    /// whose ticks go backwards sees the step that tick belongs to.
    profile: DirectionProfile,
    /// Which half of the link this is, and therefore which six stream ids.
    direction: Direction,
    /// The six generators plus the model state that rides with them.
    streams: Streams,
    /// The token bucket, when a rate model is armed.
    bucket: BucketState,
    /// The bounded byte queue in front of the bucket.
    queue: QueueState,
    /// This engine's own counters.
    counters: Counters,
}

/// One generator per model, plus the two pieces of state that belong with a
/// generator rather than with the profile.
///
/// Grouped into their own struct so that [`Impairer::decide`] can borrow them
/// mutably while holding a shared borrow of the profile, and so that
/// [`Impairer::reseed`] is one assignment rather than eight.
#[derive(Debug, Clone)]
struct Streams {
    /// Loss stream. Bernoulli draws once per datagram, Gilbert-Elliott twice,
    /// and the two deterministic loss models draw nothing at all.
    loss: Pcg32,
    /// Delay stream. One draw per stochastic sample; a fixed delay draws
    /// nothing, so arming one cannot shift a later sample.
    delay: Pcg32,
    /// Reorder stream. Drawn only for a datagram the gap counter selects, which
    /// is the emulator's behaviour and keeps the stream a function of the
    /// candidate sequence rather than of every datagram.
    reorder: Pcg32,
    /// Duplication stream.
    dup: Pcg32,
    /// Corruption stream. One draw for the hit, two more for the site.
    corrupt: Pcg32,
    /// Rate/queue stream.
    ///
    /// **Seeded and never drawn from**, because the rate model is exact
    /// arithmetic with no randomness in it. It exists because the twelve stream
    /// ids are part of the decision-log format: dropping this one would move
    /// every uplink id down by one and invalidate every log ever recorded. It
    /// is also what a future stochastic queue discipline would draw from
    /// without renumbering anything.
    ///
    /// The `allow` is the point rather than an oversight: this field is seeded
    /// and never read on the decision path, and `the_rate_model_consumes_no_randomness`
    /// asserts exactly that by comparing it against a freshly seeded generator
    /// after a run that overflows the queue and empties the bucket. Deleting it
    /// to silence the lint would renumber the uplink block.
    #[allow(dead_code)]
    rate_queue: Pcg32,
    /// The delay model's correlation state. Advances on every stochastic
    /// sample, including at `rho = 0`, so raising `rho` at a timeline step
    /// starts from the sample that preceded it rather than from a stale word.
    delay_corr: CorrState,
    /// The burst-loss chain's current state. Survives a re-seed: it is a
    /// property of the traffic the chain has seen, not of the generator.
    gilbert: GilbertState,
}

/// The burst-loss chain's two states.
///
/// A two-variant enum rather than a `bool`, because `false` reads as "not bad"
/// at half the call sites and "not good" at the other half.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum GilbertState {
    /// The low-loss state. A chain starts here, which is what makes the mean
    /// gap before the first burst `1/p` rather than an artefact of arming.
    #[default]
    Good,
    /// The high-loss state.
    Bad,
}

/// This engine's counters, as plain integers.
///
/// Not atomics: an [`Impairer`] decides one direction and is not shared. The
/// atomic counters the socket layer needs are a different type with a different
/// job, and folding the two together would put an atomic increment on a path
/// that is otherwise pure integer arithmetic.
#[derive(Debug, Clone, Copy, Default)]
struct Counters {
    /// Datagrams decided about.
    seen: u64,
    /// Released at `now` with no model holding them.
    passed: u64,
    /// Released later than `now`.
    delayed: u64,
    /// Released at `now` having skipped an armed delay model.
    reordered: u64,
    /// Datagrams given an extra copy.
    duplicated: u64,
    /// Datagrams with a bit flipped.
    corrupted: u64,
    /// Dropped by a loss model.
    dropped_loss: u64,
    /// Dropped inside a blackout window.
    dropped_blackout: u64,
    /// Dropped for exceeding the MTU black hole.
    dropped_mtu: u64,
    /// Tail-dropped at the bounded byte queue.
    dropped_queue_full: u64,
    /// On-wire bytes offered.
    wire_bytes_in: u64,
    /// On-wire bytes released, duplicates included.
    wire_bytes_out: u64,
    /// High-water mark of the queue backlog.
    backlog_max: u64,
}

impl Impairer {
    /// Arm one direction. The profile is validated first: a profile this crate
    /// cannot honour is refused here, never accepted and then quietly ignored.
    ///
    /// `direction` selects the six generator stream ids, so two engines built
    /// from one seed — one per direction — draw independent sequences.
    pub fn new(
        profile: DirectionProfile,
        seed: u64,
        direction: Direction,
    ) -> Result<Self, ProfileError> {
        profile.validate()?;
        let mut profile = profile;
        normalise_patterns(&mut profile);
        Ok(Impairer {
            streams: Streams::seeded(seed, direction),
            profile,
            direction,
            bucket: BucketState::default(),
            queue: QueueState::default(),
            counters: Counters::default(),
        })
    }

    /// Decide what happens to one datagram.
    ///
    /// `seq` is this direction's own monotone datagram counter from 0.
    /// `wire_bytes` is the ON-WIRE size — payload plus IP and UDP headers —
    /// because a rate limit is a claim about what a link carries and a link
    /// carries headers. `now` is nanoseconds since the profile was armed.
    ///
    /// A `now` that goes backwards is clamped rather than rejected: the bucket
    /// and the queue refill and drain nothing across an inverted pair, so an
    /// out-of-order caller under-grants and over-reports its backlog instead of
    /// manufacturing tokens or emptying a queue that is full.
    ///
    /// # Panics
    ///
    /// If the token bucket reports that it can *never* grant this datagram. That
    /// answer means one of two things, and neither is a question about disposing
    /// of a datagram: the configured rate is zero, or the datagram is larger than
    /// the whole bucket depth. Both are refused when a profile is validated, so
    /// reaching it here means validation let through a profile it should not
    /// have. Reporting it as a queue overflow instead would say "the link was
    /// congested" about a queue that has never held a byte — which is exactly
    /// the mis-attribution the separate drop causes exist to prevent — and a
    /// debug-only assertion would be silent in the build that matters.
    pub fn decide(&mut self, seq: u64, wire_bytes: u32, now: Tick) -> Decision {
        // Destructured rather than accessed through `self`, so the shared borrow
        // of the profile and the mutable borrows of the generators, the bucket
        // and the queue are disjoint.
        let Impairer { profile, streams, bucket, queue, counters, .. } = self;
        let active = active_profile(profile, now);

        counters.seen += 1;
        counters.wire_bytes_in += u64::from(wire_bytes);

        // 2. Blackout. No draw, so the models below see only the datagrams that
        //    survived the window and their streams are undisturbed by it.
        if active.blackouts.iter().any(|w| window_contains(w, now)) {
            return counters.finish(wire_bytes, dropped(DropCause::Blackout, now, queue));
        }

        // 3. MTU black hole. Strictly greater: a datagram of exactly the limit
        //    passes. No draw.
        if let Some(mtu) = active.mtu_blackhole {
            if wire_bytes > u32::from(mtu) {
                return counters.finish(wire_bytes, dropped(DropCause::Mtu, now, queue));
            }
        }

        // 4. Loss.
        if let Some(loss) = &active.loss {
            if loss_selects(loss, seq, &mut streams.loss, &mut streams.gilbert) {
                return counters.finish(wire_bytes, dropped(DropCause::Loss, now, queue));
            }
        }

        // 5. Rate: the bounded byte queue, then the token bucket. The queue is
        //    the only thing that may report an overflow, and the bucket is the
        //    only thing that may name a later release tick.
        let mut release = now;
        if let Some(rate) = active.rate {
            // The rate model is configured in BITS per second while the bucket,
            // the queue and every byte count in this crate are in on-wire
            // BYTES. Rounded up, so that a rate below eight bits per second —
            // absurd, but expressible — cannot become a byte rate of zero, at
            // which the bucket never refills and every datagram would reach the
            // panic this function documents.
            let bytes_per_second = rate.bps.div_ceil(8);

            // The rule is one comparison — the backlog plus this datagram
            // against the threshold — and both refusals below satisfy it.
            //
            // `TailDropped` is congestion: the queue is genuinely holding bytes
            // and this datagram would take it past its threshold. `NeverFits`
            // is a datagram larger than the whole threshold, which is a
            // configuration that refuses the first datagram of an idle link.
            // The two are reported here under one cause, and that is a known
            // rough edge rather than a considered equivalence: a queue
            // threshold below one datagram drops everything with a recorded
            // backlog of zero, which is the mis-attribution this crate is
            // otherwise careful to avoid. It is left as a drop rather than a
            // panic because a profile that reaches it is one the validator
            // accepted, and crashing a datagram path on an accepted profile is
            // worse than reporting the drop under a slightly wrong name.
            match offer(queue, bytes_per_second, rate.queue_bytes, wire_bytes, now) {
                Admission::Queued => {}
                Admission::TailDropped | Admission::NeverFits => {
                    return counters
                        .finish(wire_bytes, dropped(DropCause::RateQueueFull, now, queue))
                }
            }

            match charge(bucket, bytes_per_second, rate.burst_bytes, wire_bytes, now) {
                RateGrant::Now => {}
                RateGrant::Later(at) => release = at,
                RateGrant::Never => panic!(
                    "the token bucket can never grant a {wire_bytes}-byte datagram at \
                     {} bits per second with a {}-byte burst; that is a refusal the profile \
                     validator owed the caller, not a datagram to dispose of",
                    rate.bps, rate.burst_bytes
                ),
            }
        }

        // 6. Delay. A sample may legitimately be negative — half of a symmetric
        //    distribution is — so the release tick is clamped, not the sample.
        let delayed_by_model = active.delay.is_some();
        if let Some(model) = &active.delay {
            let ns = sample_delay(&mut streams.delay, &mut streams.delay_corr, model);
            release = if ns >= 0 {
                release.saturating_add_ns(ns.unsigned_abs())
            } else {
                Tick(release.0.saturating_sub(ns.unsigned_abs()))
            };
        }
        if release < now {
            release = now;
        }

        let mut verdict = if release > now { Verdict::Delay } else { Verdict::Pass };

        // 7. Reorder. Counter semantics, not displacement: every `gap`-th
        //    datagram is a candidate, and a candidate that hits is released at
        //    `now` instead of at the tick the delay model chose — so it jumps
        //    ahead of everything already parked. Nothing is swapped with
        //    anything, which is why the model needs a delay to exist and is
        //    refused without one.
        if delayed_by_model {
            if let Some(model) = active.reorder {
                let gap = u64::from(model.gap);
                if gap != 0 && seq % gap == gap - 1 && model.p.hits(streams.reorder.next_u32()) {
                    release = now;
                    // `Reorder`, not `Pass`, although both release at `now`.
                    // Collapsing them would make the model invisible in the log
                    // — the whole of its effect is that this datagram did not
                    // wait, and a `Pass` says it was never asked to.
                    verdict = Verdict::Reorder;
                }
            }
        }

        // 8. Duplication: one extra copy, released at the same tick as the
        //    original, which is what a link-layer retransmission looks like from
        //    above.
        let mut duplicate = None;
        if let Some(model) = active.dup {
            if model.p.hits(streams.dup.next_u32()) {
                duplicate = Some(release);
                counters.duplicated += 1;
                counters.wire_bytes_out += u64::from(wire_bytes);
            }
        }

        // 9. Corruption: one draw for the hit, then two for the site.
        let mut corrupt = None;
        if let Some(model) = active.corrupt {
            if model.p.hits(streams.corrupt.next_u32()) {
                let bound = wire_bytes.saturating_sub(MAX_HEADER_WIRE_BYTES);
                if bound > 0 {
                    let byte_offset = streams.corrupt.next_bounded(bound);
                    let bit = streams.corrupt.next_bounded(8) as u8;
                    corrupt = Some(CorruptSite { byte_offset, bit });
                    counters.corrupted += 1;
                }
                // A datagram too small to name an offset in is left alone and
                // costs the stream no further draws. The site would otherwise
                // have to be a byte this engine cannot prove exists.
            }
        }

        counters.finish(
            wire_bytes,
            Decision {
                verdict,
                cause: DropCause::NotDropped,
                release,
                duplicate,
                corrupt,
                queue_backlog_bytes: queue.backlog_bytes(),
            },
        )
    }

    /// Re-seed every generator of this direction and reset the delay
    /// correlation state.
    ///
    /// What deliberately survives: the token bucket, the byte queue, the
    /// burst-loss chain's state and every counter. Re-seeding changes which
    /// random stream the models read; it is not a re-arm, and silently emptying
    /// a queue or resetting a statistic would make it one.
    pub fn reseed(&mut self, seed: u64) {
        let gilbert = self.streams.gilbert;
        self.streams = Streams::seeded(seed, self.direction);
        self.streams.gilbert = gilbert;
    }

    /// A snapshot of this engine's own counters.
    ///
    /// The four release-path fields — [`StatsSnapshot::release_batches`],
    /// [`StatsSnapshot::released_from_queue`], [`StatsSnapshot::release_batch_max`]
    /// and [`StatsSnapshot::release_error_ns`] — are **always 0 here**. This
    /// engine decides; it has no release path and no clock to compare a
    /// scheduled tick against, so any number it reported for them would be
    /// invented. They are populated by the layer that actually hands datagrams
    /// to a socket.
    pub fn stats(&self) -> StatsSnapshot {
        let c = &self.counters;
        StatsSnapshot {
            datagrams_seen: c.seen,
            datagrams_passed: c.passed,
            datagrams_delayed: c.delayed,
            datagrams_reordered: c.reordered,
            datagrams_duplicated: c.duplicated,
            datagrams_corrupted: c.corrupted,
            dropped_loss: c.dropped_loss,
            dropped_blackout: c.dropped_blackout,
            dropped_mtu: c.dropped_mtu,
            dropped_queue_full: c.dropped_queue_full,
            wire_bytes_in: c.wire_bytes_in,
            wire_bytes_out: c.wire_bytes_out,
            queue_backlog_bytes: self.queue.backlog_bytes(),
            queue_backlog_bytes_max: c.backlog_max,
            release_batches: 0,
            released_from_queue: 0,
            release_batch_max: 0,
            release_error_ns: 0,
        }
    }
}

impl Streams {
    /// All six generators of one direction, from one seed.
    fn seeded(seed: u64, direction: Direction) -> Streams {
        let ids = stream_ids(direction);
        Streams {
            loss: Pcg32::seeded(seed, ids[0]),
            delay: Pcg32::seeded(seed, ids[1]),
            reorder: Pcg32::seeded(seed, ids[2]),
            dup: Pcg32::seeded(seed, ids[3]),
            corrupt: Pcg32::seeded(seed, ids[4]),
            rate_queue: Pcg32::seeded(seed, ids[5]),
            delay_corr: CorrState::default(),
            gilbert: GilbertState::default(),
        }
    }
}

impl Counters {
    /// Fold one finished decision into the counters and hand it back.
    ///
    /// Every decision passes through here, which is what makes the conservation
    /// identity — passed plus delayed plus reordered plus the four drop causes
    /// equals seen — a property of the control flow rather than of a reviewer
    /// having remembered to increment something on each of eleven branches.
    fn finish(&mut self, wire_bytes: u32, decision: Decision) -> Decision {
        match decision.verdict {
            Verdict::Pass => self.passed += 1,
            Verdict::Delay => self.delayed += 1,
            Verdict::Reorder => self.reordered += 1,
            Verdict::Drop => match decision.cause {
                DropCause::Loss => self.dropped_loss += 1,
                DropCause::Blackout => self.dropped_blackout += 1,
                DropCause::Mtu => self.dropped_mtu += 1,
                DropCause::RateQueueFull => self.dropped_queue_full += 1,
                DropCause::NotDropped => unreachable!("a Drop verdict always carries a cause"),
            },
        }
        if decision.verdict != Verdict::Drop {
            self.wire_bytes_out += u64::from(wire_bytes);
        }
        self.backlog_max = self.backlog_max.max(decision.queue_backlog_bytes);
        decision
    }
}

/// The profile in force at `now`: the last timeline step whose tick has passed,
/// or the profile as armed when none has.
///
/// Computed from `now` on every decision rather than latched in a field, so the
/// answer is a pure function of the tick. A latched index would make a caller
/// whose ticks go backwards see a step that tick does not belong to, and would
/// make the engine's output depend on the order calls arrived in as well as on
/// their arguments.
///
/// `at_ns` is strictly increasing — the validator refuses anything else — so the
/// partition point is the number of steps that have landed.
fn active_profile(profile: &DirectionProfile, now: Tick) -> &DirectionProfile {
    let landed = profile.timeline.partition_point(|step| step.at_ns <= now.0);
    match landed {
        0 => profile,
        n => &profile.timeline[n - 1].profile,
    }
}

/// Half-open: `at <= now && now < at + for_`.
///
/// Half-open so that two back-to-back windows neither overlap by one nanosecond
/// nor leave a gap of one, and so that the length of a window is exactly
/// `for_ns` however it is placed.
/// Written as a subtraction guarded by the lower bound rather than as
/// `now < at + for_`, so a window that runs to the top of the tick range
/// compares correctly instead of wrapping to a window that contains nothing.
fn window_contains(window: &Window, now: Tick) -> bool {
    now.0 >= window.at_ns && now.0 - window.at_ns < window.for_ns
}

/// Whether the loss model selects this datagram, advancing whatever generator
/// state the model owns.
///
/// The two deterministic models draw **nothing**. That is not an optimisation:
/// an index list that spent a word per datagram would make the loss stream's
/// position depend on how many datagrams had gone by, so switching from a
/// pattern to a probability would shift every later model's decisions as well as
/// its own.
fn loss_selects(model: &LossModel, seq: u64, rng: &mut Pcg32, chain: &mut GilbertState) -> bool {
    match model {
        LossModel::Bernoulli { p } => p.hits(rng.next_u32()),
        LossModel::GilbertElliott { p, r, h, one_minus_k } => {
            gilbert_step(chain, *p, *r, *h, *one_minus_k, rng.next_u32(), rng.next_u32())
        }
        // Sorted and deduplicated when the engine was built, so this is a
        // binary search and not a scan over a list that could hold every index
        // of a long run.
        LossModel::Pattern { indices } => indices.binary_search(&seq).is_ok(),
        // The n-th, 2n-th, … datagram. Stated as `seq % n == n - 1` rather than
        // `== 0` because "every 10th" has two readings and the other one drops
        // datagram 0, which is the first datagram of the run.
        LossModel::EveryNth { n } => *n != 0 && seq % n == n - 1,
    }
}

/// One step of the burst-loss chain: transition on the first draw, decide on the
/// second, and decide with the **departing** state's parameter.
///
/// Two draws per datagram, always, and the order matters: the datagram that
/// triggers the move into the bad state is still judged by the good state's loss
/// probability. That is a real property of the chain and not an off-by-one — it
/// is why a burst's first lost datagram is the one *after* the transition, and
/// it is what makes the mean burst length exactly `1/r` instead of `1/r + 1`.
///
/// # Both loss probabilities are compared the same way
///
/// The kernel emulator this chain is modelled on stores the bad state's
/// parameter as a complement and tests it with a greater-than, which is an
/// asymmetry worth knowing about and not worth reproducing. A greater-than
/// against a threshold in `[0, 2^32]` cannot express certainty: `draw > t` is
/// false for every draw once `t` reaches the top of the range, so the degenerate
/// configuration "the bad state loses everything" would keep a hole of one
/// datagram in 4.3 billion — and the row of the burst-loss gate that asserts
/// *every* datagram is lost would fail about once in 21 000 runs, for a reason
/// no one reading the failure would guess. Both parameters are held as the loss
/// probability they are and compared the one way every probability in this crate
/// is compared.
fn gilbert_step(
    chain: &mut GilbertState,
    p: Prob,
    r: Prob,
    h: Prob,
    one_minus_k: Prob,
    transition_draw: u32,
    decision_draw: u32,
) -> bool {
    match *chain {
        GilbertState::Good => {
            if p.hits(transition_draw) {
                *chain = GilbertState::Bad;
            }
            one_minus_k.hits(decision_draw)
        }
        GilbertState::Bad => {
            if r.hits(transition_draw) {
                *chain = GilbertState::Good;
            }
            h.hits(decision_draw)
        }
    }
}

/// A dropped datagram's decision.
///
/// `release` carries `now` rather than a zero or a sentinel: the datagram is not
/// released at all, the verdict says so, and inventing a tick it was never at
/// would put a number in the log that a reader could mistake for a schedule.
///
/// The backlog is read out of the queue's recorded state, not re-drained. A
/// datagram dropped before the queue was consulted did not change it, and a read
/// that advanced the queue's clock would make the recorded backlog depend on how
/// many datagrams had been dropped ahead of it.
fn dropped(cause: DropCause, now: Tick, queue: &QueueState) -> Decision {
    Decision {
        verdict: Verdict::Drop,
        cause,
        release: now,
        duplicate: None,
        corrupt: None,
        queue_backlog_bytes: queue.backlog_bytes(),
    }
}

/// Sort and deduplicate every index list in the profile, including the timeline
/// steps', so membership is a binary search.
///
/// A caller's list is a set, and both an unsorted list and a repeated index mean
/// exactly what the sorted deduplicated one does. Doing it once here rather than
/// on every datagram is what keeps the decision path free of scans whose cost
/// grows with the length of a configuration.
fn normalise_patterns(profile: &mut DirectionProfile) {
    fn normalise(direction: &mut DirectionProfile) {
        if let Some(LossModel::Pattern { indices }) = &mut direction.loss {
            indices.sort_unstable();
            indices.dedup();
        }
    }
    normalise(profile);
    for step in &mut profile.timeline {
        normalise(&mut step.profile);
    }
}

/// This direction's six stream ids, in model order.
///
/// The uplink id of a model is its downlink id plus eight, with a deliberate gap
/// at six and seven: it leaves room for two more downlink models before the
/// uplink block would have to move, and moving the uplink block would change the
/// decision-log format.
const fn stream_ids(direction: Direction) -> [u64; 6] {
    match direction {
        Direction::Downlink => [
            STREAM_DOWNLINK_LOSS,
            STREAM_DOWNLINK_DELAY,
            STREAM_DOWNLINK_REORDER,
            STREAM_DOWNLINK_DUP,
            STREAM_DOWNLINK_CORRUPT,
            STREAM_DOWNLINK_RATE_QUEUE,
        ],
        Direction::Uplink => [
            STREAM_UPLINK_LOSS,
            STREAM_UPLINK_DELAY,
            STREAM_UPLINK_REORDER,
            STREAM_UPLINK_DUP,
            STREAM_UPLINK_CORRUPT,
            STREAM_UPLINK_RATE_QUEUE,
        ],
    }
}

/// What the engine decided about one datagram.
///
/// **Not `#[non_exhaustive]`**: that attribute on a *struct* forbids
/// struct-literal construction from outside the defining crate, functional-update
/// syntax included, and this crate's behavioural gates live in a separate test
/// crate. No gate could then build an expected `Decision` to compare against,
/// which is what `PartialEq` is derived here *for*.
///
/// **`Default` is derived, and it is not decoration**: a gate writes
/// `Decision { verdict: Verdict::Drop, cause: DropCause::Loss, ..Default::default() }`
/// instead of restating six fields per expectation.
///
/// **The hazard is named rather than hidden.** `Decision::default()` is a pass at
/// `Tick(0)` holding nothing — *nothing happened*, which is the exact shape a
/// silently-broken impairer produces. It is safe here for two reasons and only
/// these two. No production path constructs a `Decision` by `Default`:
/// [`Impairer::decide`] returns one by value on every branch. And a fixture
/// blessed from a defaulting engine is what a coverage precondition over the
/// verdicts reddens on, before any behaviour is compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Decision {
    /// What happened to the datagram.
    pub verdict: Verdict,
    /// Why it was dropped. [`DropCause::NotDropped`] whenever `verdict` is not
    /// [`Verdict::Drop`].
    ///
    /// A field rather than a payload on the `Drop` variant, because a fieldless
    /// enum renders to the decision log as one integer and a payload-carrying
    /// variant does not. It is public for the reason the struct is not
    /// `#[non_exhaustive]`: an expected `Decision` has to be constructible from
    /// the test crate. Read it through [`Decision::cause`], which is the shape
    /// the rest of the crate uses.
    pub cause: DropCause,
    /// Release tick. Equals `now` for [`Verdict::Pass`] and [`Verdict::Reorder`],
    /// and for a [`Verdict::Drop`], which is released at no tick at all.
    pub release: Tick,
    /// The extra copy's release tick, when the dup model fired.
    pub duplicate: Option<Tick>,
    /// Where the bit-flip goes, when the corrupt model fired.
    pub corrupt: Option<CorruptSite>,
    /// On-wire bytes the queue holds after this decision, this datagram included
    /// while it is still in there.
    ///
    /// Makes queueing delay observable rather than inferred: a datagram held by
    /// a full-ish queue and a datagram held by the delay model both come back
    /// with a release tick in the future, and this is the field that says which
    /// of the two it was.
    pub queue_backlog_bytes: u64,
}

impl Decision {
    /// [`DropCause::NotDropped`] unless the verdict is [`Verdict::Drop`].
    pub fn cause(&self) -> DropCause {
        match self.verdict {
            Verdict::Drop => self.cause,
            _ => DropCause::NotDropped,
        }
    }
}

/// What happened to a datagram. Discriminants are part of the decision-log
/// format; do not reorder.
///
/// **Not `#[non_exhaustive]`, and the reason is this type's own first line**: the
/// discriminants are declared part of the format, so a new variant is a format
/// change and a re-blessing of every fixture regardless. The attribute would
/// therefore buy no compatibility it did not already have, while costing every
/// external gate an exhaustive match — including the coverage precondition that
/// asserts a gate fixture contains a decision of *every* verdict, which is what
/// stops an all-pass fixture being blessed.
///
/// `Pass` is the derived default because [`Decision`] needs one and `Pass` is
/// already discriminant 0, so the derived default and the zero value of the log
/// format agree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum Verdict {
    /// Released at `now`; no model held it.
    #[default]
    Pass = 0,
    /// Released at a tick later than `now`.
    Delay = 1,
    /// A delay model is armed and this datagram skipped it, so it is released at
    /// `now` and jumps ahead of everything already waiting.
    ///
    /// Distinguishable from [`Verdict::Pass`] in the log although both release
    /// at `now` — that distinction is the entire visible effect of the reorder
    /// model.
    Reorder = 2,
    /// Not released at all.
    Drop = 3,
}

/// Why a datagram was dropped.
///
/// **Not `#[non_exhaustive]`, for [`Verdict`]'s reason** — the discriminants are
/// part of the log format, and the coverage precondition over a gate fixture
/// matches every cause exhaustively.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum DropCause {
    /// The datagram was not dropped.
    #[default]
    NotDropped = 0,
    /// A [`crate::model::LossModel`] selected it.
    Loss = 1,
    /// It arrived inside a blackout [`crate::model::Window`].
    Blackout = 2,
    /// Its on-wire size exceeded `mtu_blackhole`.
    Mtu = 3,
    /// The bounded byte queue was at its `queue_bytes` threshold.
    ///
    /// A **different** cause from [`DropCause::Loss`], and keeping the two apart
    /// is the whole reason to have a rate model rather than another probability:
    /// "the link was congested" and "these datagrams were unlucky" call for
    /// different fixes, and a single drop counter cannot tell them apart.
    RateQueueFull = 4,
}

/// Where the corrupt model's single bit-flip goes.
///
/// Both integers come from this crate's own generator and both are recorded, so
/// a corrupted datagram is reproducible and the rejection it causes can be
/// pointed at a specific bit of a specific packet. The kernel emulator this
/// crate follows elsewhere draws them from the system's cryptographic generator
/// instead, which makes its corruption irreproducible even under its own seed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CorruptSite {
    /// Offset into the datagram payload.
    pub byte_offset: u32,
    /// Which bit of that byte, `[0, 7]`.
    pub bit: u8,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A probability of exactly one, and one of exactly zero.
    const ALWAYS: Prob = Prob::from_ppb(1_000_000_000);
    const NEVER: Prob = Prob::from_ppb(0);

    /// The chain's transition is `draw < threshold` and nothing else, asserted
    /// as the boundary rather than as a frequency over samples.
    ///
    /// The claim underneath "the transition probability is `r`" is an integer
    /// identity: exactly `t` of the 2^32 possible draw values move the chain,
    /// where `t` is the probability's numerator over 2^32. Counting them by
    /// sampling would need billions of draws to distinguish `t` from `t ± 1`;
    /// asserting the boundary distinguishes them with two calls, because
    /// `{ d : d < t }` has exactly `t` members by arithmetic.
    ///
    /// The numerator is recomputed here from the same rounding rule the
    /// probability constructor uses, so the expected boundary is derived rather
    /// than copied out of the implementation.
    ///
    /// The second half is the part a boundary test alone would miss: the
    /// datagram that triggers a transition is judged by the state it is
    /// *leaving*. Drive the chain out of the good state with a certain
    /// transition and a good state that loses nothing, and the triggering
    /// datagram must survive even though the chain is now in a state that loses
    /// everything.
    ///
    /// Judging by the arriving state instead leaves the external burst-loss
    /// suite green at every seed: those configurations are degenerate enough
    /// that a burst simply starts and ends one datagram earlier, which is a
    /// burst of the same length in the same place. This test is the only thing
    /// that can see the difference, which is why it sits beside the private
    /// function rather than in a behavioural gate that cannot distinguish it.
    #[test]
    fn the_burst_chain_transitions_on_an_exact_threshold() {
        // 25%, written the way a caller writes it, with the numerator derived
        // here by the same arithmetic rather than transcribed.
        let ppb: u64 = 250_000_000;
        let r = Prob::from_ppb(ppb as u32);
        let t = u32::try_from(((ppb << 32) + 500_000_000) / 1_000_000_000).expect("below 2^32");
        assert_eq!(t, 1_073_741_824, "the numerator of 25% over 2^32");

        // Bad -> Good happens for exactly the draws below `t`.
        for (draw, moves) in [(0u32, true), (t - 1, true), (t, false), (u32::MAX, false)] {
            let mut chain = GilbertState::Bad;
            gilbert_step(&mut chain, NEVER, r, NEVER, NEVER, draw, 0);
            assert_eq!(
                chain == GilbertState::Good,
                moves,
                "draw {draw} must {} move the chain",
                if moves { "" } else { "not" }
            );
        }

        // Good -> Bad, the same identity on the other parameter.
        for (draw, moves) in [(0u32, true), (t - 1, true), (t, false), (u32::MAX, false)] {
            let mut chain = GilbertState::Good;
            gilbert_step(&mut chain, r, NEVER, NEVER, NEVER, draw, 0);
            assert_eq!(chain == GilbertState::Bad, moves, "draw {draw}");
        }

        // The departing state decides. A certain transition out of a good state
        // that loses nothing, into a bad state that loses everything: the
        // triggering datagram survives.
        let mut chain = GilbertState::Good;
        let lost = gilbert_step(&mut chain, ALWAYS, NEVER, ALWAYS, NEVER, 0, 0);
        assert_eq!(chain, GilbertState::Bad, "the transition happened");
        assert!(!lost, "the datagram that triggers the transition is judged by the state it left");

        // And the next one, which departs the bad state, is lost.
        assert!(gilbert_step(&mut chain, ALWAYS, NEVER, ALWAYS, NEVER, 0, u32::MAX));
    }

    /// Certainty in either state loses every datagram, including on the single
    /// largest draw.
    ///
    /// That draw is the whole point. A probability held as a 32-bit numerator and
    /// compared with a strict less-than cannot represent certainty — its largest
    /// value leaves a hole of one datagram in 4.3 billion — and this is the row
    /// that closes it. Sampling would never find it.
    #[test]
    fn certainty_in_either_state_loses_the_largest_draw() {
        let mut good = GilbertState::Good;
        assert!(gilbert_step(&mut good, NEVER, NEVER, NEVER, ALWAYS, u32::MAX, u32::MAX));

        let mut bad = GilbertState::Bad;
        assert!(gilbert_step(&mut bad, NEVER, NEVER, ALWAYS, NEVER, u32::MAX, u32::MAX));

        // And the zero probability misses the smallest draw, so the two ends are
        // both pinned and `hits` cannot be a non-zero check.
        let mut good = GilbertState::Good;
        assert!(!gilbert_step(&mut good, NEVER, NEVER, NEVER, NEVER, 0, 0));
    }

    /// The window is half-open at four named points, and a window placed at tick
    /// zero still has a first instant.
    ///
    /// Written against the predicate directly as well as through `decide`
    /// elsewhere, because this is the boundary arithmetic and an off-by-one here
    /// shortens or lengthens every blackout in the crate by one nanosecond.
    #[test]
    fn a_blackout_window_is_half_open() {
        let w = Window { at_ns: 1_000, for_ns: 500 };
        assert!(!window_contains(&w, Tick(999)), "one before the start");
        assert!(window_contains(&w, Tick(1_000)), "the start itself");
        assert!(window_contains(&w, Tick(1_499)), "the last instant inside");
        assert!(!window_contains(&w, Tick(1_500)), "the end itself is outside");

        // A window at the origin, where an implementation that subtracted before
        // comparing would underflow.
        let z = Window { at_ns: 0, for_ns: 1 };
        assert!(window_contains(&z, Tick(0)));
        assert!(!window_contains(&z, Tick(1)));

        // And a window that runs to the top of the range does not wrap.
        let big = Window { at_ns: u64::MAX - 1, for_ns: 1 };
        assert!(window_contains(&big, Tick(u64::MAX - 1)));
        assert!(!window_contains(&big, Tick(u64::MAX)));
    }

    /// Shaping a thousand datagrams draws nothing from the rate/queue stream.
    ///
    /// The token bucket and the bounded byte queue are exact integer arithmetic
    /// with no randomness in them, so their generator must be exactly where it
    /// was seeded after a run that filled a queue and emptied a bucket. The
    /// stream is nevertheless allocated and seeded, because the twelve stream
    /// ids are part of the decision-log format: leaving this one out would move
    /// every uplink id down by one.
    ///
    /// Asserted as generator-state equality rather than as "the decisions look
    /// right", because consuming a word here would be invisible in the output
    /// of *this* run and would shift every stream a later model was given if
    /// the streams were ever merged.
    #[test]
    fn the_rate_model_consumes_no_randomness() {
        use crate::model::RateModel;
        use crate::rng::STREAM_DOWNLINK_RATE_QUEUE;

        let profile = DirectionProfile {
            // 1 000 000 bytes per second, a burst of one full datagram, and a
            // queue that is only a few datagrams deep — so the bucket answers
            // `Later` and the queue tail-drops, which is every branch of the
            // rate step.
            rate: Some(RateModel { bps: 8_000_000, burst_bytes: 1_500, queue_bytes: 5_000 }),
            ..DirectionProfile::default()
        };
        let mut engine = Impairer::new(profile, 99, Direction::Downlink).expect("a valid profile");
        for seq in 0..1_000u64 {
            engine.decide(seq, 1_400, Tick(seq * 500_000));
        }

        let snapshot = engine.stats();
        assert!(snapshot.dropped_queue_full > 0, "the queue must actually overflow here");
        assert!(snapshot.datagrams_delayed > 0, "the bucket must actually hold datagrams back");
        assert_eq!(
            engine.streams.rate_queue,
            Pcg32::seeded(99, STREAM_DOWNLINK_RATE_QUEUE),
            "the rate model drew from its stream"
        );
    }

    /// The six stream ids of the two directions are disjoint, and the uplink
    /// block is the downlink block plus eight.
    ///
    /// Asserted against what the engine's own selector returns rather than
    /// against a list written into a test, so a test of the ids cannot drift
    /// from the ids the engine actually draws on.
    #[test]
    fn the_two_directions_select_disjoint_stream_blocks() {
        let down = stream_ids(Direction::Downlink);
        let up = stream_ids(Direction::Uplink);
        assert_eq!(down, [0, 1, 2, 3, 4, 5]);
        assert_eq!(up, [8, 9, 10, 11, 12, 13]);
        for i in 0..6 {
            assert_eq!(up[i], down[i] + 8, "model {i}");
        }
    }
}

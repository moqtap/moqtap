//! The token bucket and the bounded byte queue.
//!
//! Two pieces of arithmetic sit between a datagram and the wire, and they
//! answer different questions. [`charge`] is the **token bucket**: given a
//! sustained rate and a burst depth, it says whether this datagram may go now
//! or names the tick at which it could. [`offer`] is the **bounded byte
//! queue** in front of it: it says whether there is room for the datagram at
//! all, and tail-drops it when the link's backlog is already at its
//! configured threshold.
//!
//! # Both are pure with respect to the clock
//!
//! `now` is a [`Tick`] parameter and nothing here reads a clock, allocates, or
//! holds interior mutability. That is what makes the rate claim provable
//! arithmetic rather than a measurement: a test fabricates its own ticks, so
//! the bound is an exact integer assertion over ten thousand steps rather than
//! a number machine load can move.
//!
//! # Units
//!
//! `rate_bps` is **bytes** per second, paired with `burst_bytes`,
//! `threshold_bytes` and the `bytes` argument — all on-wire byte counts, the
//! same quantity the rest of the crate counts. A bit rate is `rate_bps * 8`;
//! feeding one in here puts a silent factor of eight between the configuration
//! and every statistic reported against it.
//!
//! # Why the arithmetic is scaled
//!
//! Tokens and backlog are held in nano-bytes (`u128`) and both refill and drain
//! are computed from elapsed nanoseconds. An unscaled byte counter rounds every
//! sub-byte step to zero, so a bucket paced faster than a byte per nanosecond
//! drifts low and a queue drained in small steps never empties. `u128` removes
//! the overflow question rather than documenting a ceiling nobody would check.
//!
//! # The distinction this module exists to keep
//!
//! A datagram is refused here for one of two unrelated reasons, and collapsing
//! them makes "the link was congested" indistinguishable from "the settings
//! were impossible".
//!
//! * **Congestion.** The queue is holding bytes and this datagram would take it
//!   past its threshold: [`Admission::TailDropped`], with a non-zero recorded
//!   backlog. Only this may be reported as queue overflow.
//! * **A configuration that can never be satisfied.** A zero rate, or a burst
//!   or threshold smaller than one datagram. Each refuses the first datagram of
//!   an idle link, on an empty queue. [`RateGrant::Never`] and
//!   [`Admission::NeverFits`] are separate variants so a `match` arm cannot
//!   fold them into the congestion answer.
//!
//! `rate_bps: 100_000_000` with `burst_bytes: 1000` is a plausible hand-written
//! profile that can never cover a 1400-byte datagram, since the bucket never
//! holds more than its burst. Routed to a queue-overflow cause it would drop
//! all traffic and report every drop as overflow with a backlog of zero.

use crate::Tick;

/// Nano-bytes per byte, and equally nanoseconds per second.
///
/// The two are the same constant because a bucket accumulating `rate` bytes
/// per second accumulates exactly `rate` nano-bytes per nanosecond, which is
/// what lets both refill and drain be a single multiplication with no
/// division and no rounding.
const NANO: u128 = 1_000_000_000;

/// What the byte bucket says about one datagram.
///
/// `Later(Tick)` carries a [`Tick`], not an `Instant`: this crate reads no
/// clock, and a grant naming a real instant would drag one in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateGrant {
    /// Send it now. The tokens have already been debited.
    Now,
    /// Not now. The bucket holds enough at this tick and not before, so this
    /// is the deadline to arm.
    ///
    /// The tick is *earliest*, not *exact*: nothing stops another datagram
    /// draining the bucket again before this one comes round, in which case
    /// the next [`charge`] answers `Later` with a new deadline. Re-charging
    /// costs nothing — a `Later` answer debits no tokens — so re-offering a
    /// datagram after its deadline is correct rather than double-billing.
    Later(Tick),
    /// The bucket can never grant it, however long the caller waits: either
    /// the rate is zero, so the bucket never refills, or the datagram is
    /// larger than `burst_bytes`, so the bucket cannot hold enough for it
    /// even when completely idle.
    ///
    /// This is a statement about the configuration, not about the link: there
    /// is no deadline to compute and no queue to blame. A profile that can
    /// produce it is refused when it is built, so a validated profile never
    /// reaches this variant — it exists because [`charge`] is also driven
    /// directly, with parameters no validator has seen.
    ///
    /// A fabricated far-future tick would arm a release deadline that never
    /// fires, and nothing downstream could tell it from a real one.
    Never,
}

/// Bucket state. Plain integers; no clock, no interior mutability.
///
/// # Why the state is a deficit rather than a token count
///
/// The derived [`Default`] is part of what callers may rely on, and the zero value
/// of a token count is an **empty** bucket. An empty bucket puts a
/// `burst_bytes / rate_bps` delay in front of the very first datagram of
/// every session, which reads as a broken link rather than as a shaped one —
/// so the correct starting state is a **full** bucket, and a derived
/// `Default` cannot produce one from a field that counts tokens held.
///
/// What is stored instead is the *deficit*: nano-bytes spent out of the
/// burst and not yet earned back. Tokens held are `burst_bytes * NANO`
/// minus the deficit, refilling reduces the deficit and debiting raises it,
/// and the zero value is exactly a full bucket at `Tick(0)` — the tick that
/// means "armed". The burst is a parameter of [`charge`] rather than a field,
/// so the cap is always the caller's current configuration and a reconfigured
/// bucket cannot go on holding tokens against a depth it no longer has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BucketState {
    /// Nano-bytes spent out of the burst and not yet refilled. Held tokens
    /// are the burst minus this, floored at zero.
    deficit: u128,
    /// The tick the deficit was last brought up to date at.
    last: Tick,
}

impl BucketState {
    /// Whole bytes currently held, as of the last [`charge`].
    ///
    /// Does not refill: this is a read of recorded state and not a clock
    /// reading, so it stays usable from a test that fabricates its own ticks.
    /// `burst_bytes` is a parameter for the reason the type's own
    /// documentation gives — the cap lives with the caller's configuration,
    /// not in the state.
    pub fn available_bytes(&self, burst_bytes: u64) -> u64 {
        let cap = u128::from(burst_bytes) * NANO;
        u64::try_from(cap.saturating_sub(self.deficit) / NANO).unwrap_or(u64::MAX)
    }
}

/// Charge `bytes` against the bucket at `now`.
///
/// **Pure with respect to the clock** — `now` is a parameter and no clock is
/// read. The state is refilled to `now` before the decision and debited only
/// on [`RateGrant::Now`]; a `Later` or `Never` answer costs nothing.
///
/// The bound this function upholds, exactly: over any interval, the bytes it
/// grants never exceed `rate_bps * elapsed + burst_bytes`. That is provable
/// arithmetic rather than a measurement, and it is what
/// `the_bucket_never_grants_above_rate_plus_burst` proves over 10 001
/// fabricated ticks.
///
/// # What it is not
///
/// It is a bound on grants, not on bytes leaving a socket. Anything upstream
/// that clamps how long a datagram may be held will release datagrams this
/// function never granted, so a caller meaning to observe this bound must
/// keep such a clamp from binding inside its sampling window.
///
/// `now` is expected to be monotone: an earlier `now` refills nothing and does
/// not rewind the bucket's clock, so an out-of-order caller under-grants rather
/// than manufacturing tokens. A `burst_bytes` that shrank under a reconfigure
/// needs no separate clamp, since tokens are the burst minus the deficit.
///
/// A wait longer than a `u64` nanosecond count saturates to `Tick(u64::MAX)`
/// rather than degrading to [`RateGrant::Never`] — a saturated tick is a real
/// tick a release path can hold, where `Never` is a claim about the
/// configuration that a caller should treat as a validation bug.
pub fn charge(
    state: &mut BucketState,
    rate_bps: u64,
    burst_bytes: u64,
    bytes: u32,
    now: Tick,
) -> RateGrant {
    // `Tick::since` saturates, so a backwards `now` refills nothing; leaving
    // `last` alone is what stops the next forward call re-crediting the gap.
    let elapsed = now.since(state.last);
    if elapsed > 0 {
        state.deficit = state.deficit.saturating_sub(u128::from(elapsed) * u128::from(rate_bps));
        state.last = now;
    }

    let cap = u128::from(burst_bytes) * NANO;
    let need = u128::from(bytes) * NANO;
    let held = cap.saturating_sub(state.deficit);

    if held >= need {
        // `held >= need` is `cap - deficit >= need`, so this addition is
        // bounded by `cap` and cannot overflow.
        state.deficit += need;
        return RateGrant::Now;
    }

    // The bucket can hold at most `cap`, so anything above it is unreachable
    // however long the caller waits — as is anything at all once the rate is
    // zero. Neither says anything about the queue.
    if rate_bps == 0 || need > cap {
        return RateGrant::Never;
    }

    let shortfall = need - held;
    let wait_ns = u64::try_from(shortfall.div_ceil(u128::from(rate_bps))).unwrap_or(u64::MAX);
    RateGrant::Later(state.last.saturating_add_ns(wait_ns))
}

/// What the bounded byte queue says about one datagram.
///
/// The two refusals are separate variants on purpose; see the module
/// documentation for what is lost when they are folded together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// Queued. The backlog now includes this datagram.
    Queued,
    /// **Congestion.** The queue was already holding bytes and this datagram
    /// would take it past `threshold_bytes`, so it is dropped at the tail.
    ///
    /// The backlog is non-zero whenever this is returned, and that is a
    /// property of the arithmetic rather than of the test data: [`offer`]
    /// answers [`Admission::NeverFits`] first for any datagram that could not
    /// fit an empty queue, so reaching this variant requires the datagram to
    /// be no larger than the threshold, which in turn requires the backlog to
    /// be strictly positive for the sum to exceed it.
    TailDropped,
    /// **Not congestion.** This datagram alone exceeds `threshold_bytes`, so
    /// no amount of draining would ever make room for it — including on a
    /// queue that has never held a byte.
    ///
    /// A threshold of zero lands every datagram here, which is why a zero
    /// threshold is refused when the profile is built: left alone it drops
    /// 100% of traffic, and reporting that as overflow would describe an
    /// empty queue as a saturated one. A profile that means "drop everything"
    /// says so with a loss model.
    NeverFits,
}

/// Bounded byte queue state. Plain integers; no clock, no allocation.
///
/// The derived [`Default`] is an **empty** queue at `Tick(0)`, which is the
/// correct starting state and needs no deficit trick: an idle link holds
/// nothing.
///
/// # Why there is no per-datagram storage
///
/// The queue is modelled as occupancy in bytes that leaks at `rate_bps`, not
/// as a list of held datagrams. Occupancy is the quantity a congestion
/// profile is about — how deep the standing backlog is, and therefore how
/// much delay it adds — and holding it as one integer keeps [`offer`]
/// allocation-free and its trace exactly reproducible. A list would carry
/// per-datagram release ticks that nothing here reads and would put an
/// unbounded allocation on the path of every datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QueueState {
    /// Occupancy in nano-bytes.
    backlog: u128,
    /// The tick the backlog was last drained to.
    last: Tick,
}

impl QueueState {
    /// On-wire bytes currently queued, as of the last [`offer`].
    ///
    /// Does not drain — a read of recorded state, not a clock reading.
    ///
    /// Rounded **up**: a datagram that is half-drained is still occupying the
    /// queue, and rounding down would let a queue holding a fraction of a
    /// byte report zero. That matters at exactly one place and it is the
    /// place that counts — a tail drop must never be reported alongside a
    /// backlog of zero, and rounding up makes "the backlog is non-zero"
    /// identical to "the queue holds something" instead of nearly identical.
    pub fn backlog_bytes(&self) -> u64 {
        u64::try_from(self.backlog.div_ceil(NANO)).unwrap_or(u64::MAX)
    }
}

/// Offer `bytes` to the bounded queue at `now`.
///
/// **Pure with respect to the clock**, exactly as [`charge`] is. The queue is
/// drained to `now` before the decision and grows only on
/// [`Admission::Queued`].
///
/// The queue drains at `rate_bps` — the same rate the bucket downstream of it
/// is charged against, because the bucket is the only thing the queue feeds:
/// bytes leave at the speed the link is configured to carry them. The burst is
/// deliberately **not** part of the drain. A burst is depth the bucket already
/// holds, not extra link capacity, and crediting it here as well would let the
/// queue report room the link does not have.
///
/// `now` going backwards drains nothing and does not rewind the queue's own
/// clock, so an out-of-order caller reports a deeper backlog than the truth
/// rather than a shallower one.
///
/// # Order of the two checks
///
/// `bytes > threshold_bytes` is tested **before** the backlog comparison, and
/// that ordering is the whole of [`Admission::TailDropped`]'s non-zero-backlog
/// guarantee. Reversed, a datagram larger than the threshold would be reported
/// as a tail drop on an empty queue — congestion attributed to a link that was
/// idle, which is the one report this module exists to make impossible.
pub fn offer(
    state: &mut QueueState,
    rate_bps: u64,
    threshold_bytes: u64,
    bytes: u32,
    now: Tick,
) -> Admission {
    let elapsed = now.since(state.last);
    if elapsed > 0 {
        state.backlog = state.backlog.saturating_sub(u128::from(elapsed) * u128::from(rate_bps));
        state.last = now;
    }

    let cap = u128::from(threshold_bytes) * NANO;
    let need = u128::from(bytes) * NANO;

    if need > cap {
        return Admission::NeverFits;
    }
    if state.backlog + need > cap {
        return Admission::TailDropped;
    }
    state.backlog += need;
    Admission::Queued
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One second in nanoseconds, so the fabricated tick sequences read as
    /// the durations they are.
    const SECOND: u64 = 1_000_000_000;

    /// The exact rate bound, over fabricated ticks.
    ///
    /// Four assertions, and each one is load-bearing:
    ///
    /// 1. `granted <= rate * dt + burst` — the claim.
    /// 2. `granted >= rate * dt` — so it cannot pass by granting nothing. A
    ///    bucket that always answered `Later` would satisfy (1) perfectly.
    /// 3. `ceiling - granted < UNIT` — so (1) is a tight bound and not a
    ///    decade of slack. Here the residue is zero: the numbers are chosen
    ///    so `burst + rate * dt` divides by `UNIT`.
    /// 4. The exact grant count, which no inequality can be satisfied by
    ///    accident.
    ///
    /// Demand is twice the rate, so the bucket and not the offered load is
    /// what limits the total. At or below the rate the bucket never binds and
    /// every one of these assertions would hold however wrong the arithmetic
    /// was.
    ///
    /// Note what this test does **not** catch, so its weight is not
    /// overestimated. Demand here is twice the rate, so the bucket is drained
    /// on every step and never accumulates towards the burst — which means the
    /// refill cap never binds, and removing it leaves all four assertions
    /// green. The cap is pinned by
    /// `a_datagram_larger_than_the_burst_is_never_grantable` instead, and the
    /// per-step behaviour by `the_grant_sequence_for_a_known_rate_and_burst_is_exact`.
    /// An aggregate bound is a weak instrument on its own; that is why it is
    /// not the only test here.
    #[test]
    fn the_bucket_never_grants_above_rate_plus_burst() {
        const RATE: u64 = 1_000_000; // bytes/s
        const BURST: u64 = 10_000; // bytes
        const STEPS: u64 = 10_000;
        const STEP_NS: u64 = 100_000; // 100 bytes of refill per step
        const UNIT: u32 = 200; // twice the rate

        let mut state = BucketState::default();
        let mut granted: u128 = 0;
        let mut grants = 0u64;

        // `0..=STEPS`: the first charge happens at `Tick(0)`, before any
        // refill, so the full bucket is never clamped away and the ceiling
        // below is reached exactly rather than approached.
        for i in 0..=STEPS {
            let now = Tick(i * STEP_NS);
            match charge(&mut state, RATE, BURST, UNIT, now) {
                RateGrant::Now => {
                    granted += u128::from(UNIT);
                    grants += 1;
                }
                RateGrant::Later(at) => assert!(at > now, "a Later deadline must be in the future"),
                RateGrant::Never => panic!("a {UNIT}-byte datagram fits in a {BURST}-byte burst"),
            }
        }

        let elapsed_ns = u128::from(STEPS * STEP_NS);
        let ceiling = u128::from(RATE) * elapsed_ns / NANO + u128::from(BURST);

        assert!(
            granted <= ceiling,
            "granted {granted} bytes over {elapsed_ns} ns; \
             ceiling is rate*dt + burst = {ceiling}"
        );
        assert!(
            granted >= u128::from(RATE) * elapsed_ns / NANO,
            "granted {granted} bytes, below the sustained rate"
        );
        assert!(
            ceiling - granted < u128::from(UNIT),
            "bound is not tight: ceiling {ceiling} vs granted {granted}"
        );
        assert_eq!(grants, 5050, "grant count is deterministic: (burst + rate*dt) / unit");
    }

    /// The whole grant sequence for one known rate and burst, `Later`
    /// deadlines included.
    ///
    /// The arithmetic, worked by hand and reproduced here so the expected
    /// vector is not a number this implementation once printed. Rate is 1000
    /// bytes/s and the burst is 1000 bytes, so each 100 ms step refills
    /// exactly 100 bytes; a fresh bucket starts full; offers are 400 bytes.
    ///
    /// ```text
    /// step  held before  need  answer                held after
    ///  0     1000         400  Now                    600
    ///  1      700         400  Now                    300
    ///  2      400         400  Now                      0
    ///  3      100         400  short 300 -> +300 ms   100   deadline 600 ms
    ///  4      200         400  short 200 -> +200 ms   200   deadline 600 ms
    ///  5      300         400  short 100 -> +100 ms   300   deadline 600 ms
    ///  6      400         400  Now                      0
    ///  7      100         400  short 300 -> +300 ms   100   deadline 1000 ms
    ///  8      200         400  short 200 -> +200 ms   200   deadline 1000 ms
    ///  9      300         400  short 100 -> +100 ms   300   deadline 1000 ms
    /// 10      400         400  Now                      0
    /// ```
    ///
    /// Three separate stubs die here that the aggregate bound above survives.
    /// An implementation that answers `Now` unconditionally reddens at step 3;
    /// one that answers `Later(now)` — arming a deadline at the tick it was
    /// asked, which busy-loops rather than shaping — reddens at step 3 with
    /// `Later(Tick(300000000))`; and one that recomputes the deadline from the
    /// shortfall but forgets that the bucket kept refilling while the datagram
    /// waited reddens at step 4, because the three deadlines at steps 3, 4 and
    /// 5 must all name the *same* tick.
    #[test]
    fn the_grant_sequence_for_a_known_rate_and_burst_is_exact() {
        const RATE: u64 = 1_000;
        const BURST: u64 = 1_000;
        const UNIT: u32 = 400;
        const STEP_NS: u64 = SECOND / 10;

        let deadline_at_600ms = RateGrant::Later(Tick(600_000_000));
        let deadline_at_1s = RateGrant::Later(Tick(SECOND));
        let want = [
            RateGrant::Now,
            RateGrant::Now,
            RateGrant::Now,
            deadline_at_600ms,
            deadline_at_600ms,
            deadline_at_600ms,
            RateGrant::Now,
            deadline_at_1s,
            deadline_at_1s,
            deadline_at_1s,
            RateGrant::Now,
        ];

        let mut state = BucketState::default();
        for (step, expected) in want.iter().enumerate() {
            let now = Tick(step as u64 * STEP_NS);
            let got = charge(&mut state, RATE, BURST, UNIT, now);
            assert_eq!(got, *expected, "step {step}");
        }

        // Four grants of 400 bytes over one second. Offered load was 4000
        // bytes/s against a 1000 bytes/s bucket, so this is the bucket
        // binding and not the offer pattern running out.
        assert_eq!(state.available_bytes(BURST), 0, "the last grant emptied the bucket");
    }

    /// A `Later` deadline is the earliest tick the datagram fits, and waiting
    /// exactly that long makes it fit.
    ///
    /// The inequality half is what stops an implementation from padding the
    /// deadline: a bucket that answered one millisecond late every time would
    /// still be under the rate bound and would still look correct in an
    /// aggregate test.
    #[test]
    fn a_later_deadline_is_the_earliest_tick_the_datagram_fits() {
        const RATE: u64 = 1_000;
        const BURST: u64 = 10_000;

        // Spend the whole burst, so the bucket is empty at `Tick(0)`.
        let mut state = BucketState::default();
        assert_eq!(charge(&mut state, RATE, BURST, 10_000, Tick(0)), RateGrant::Now);
        assert_eq!(state.available_bytes(BURST), 0);

        // 500 bytes at 1000 bytes/s is exactly 500 ms.
        let at = match charge(&mut state, RATE, BURST, 500, Tick(0)) {
            RateGrant::Later(at) => at,
            other => panic!("expected Later, got {other:?}"),
        };
        assert_eq!(at, Tick(500_000_000));

        // One nanosecond early is still not enough; the deadline itself is.
        assert!(matches!(
            charge(&mut state, RATE, BURST, 500, Tick(at.0 - 1)),
            RateGrant::Later(_)
        ));
        assert_eq!(charge(&mut state, RATE, BURST, 500, at), RateGrant::Now);
        assert_eq!(state.available_bytes(BURST), 0);
    }

    /// With a zero rate the burst is the entire budget: exactly
    /// `floor(burst / size)` datagrams are granted and the next is `Never`,
    /// forever.
    ///
    /// An exact count, not a rate — a rate assertion over a bucket that never
    /// refills is satisfied by any implementation that eventually stops.
    ///
    /// A zero rate is refused when a profile is built, for the reason this
    /// test then demonstrates: it is 100% loss, and 100% loss belongs to a
    /// loss model where it is legible. `charge` is driven directly here
    /// precisely because that is the only way to reach the parameters at all;
    /// a reader who tries to build this profile through validation will
    /// correctly be refused.
    #[test]
    fn the_bucket_honours_burst_and_then_grants_nothing() {
        const BURST: u64 = 10_000;
        const SIZE: u32 = 1_400;

        let mut state = BucketState::default();
        let mut grants = 0u64;
        for i in 0..1_000u64 {
            match charge(&mut state, 0, BURST, SIZE, Tick(i * SECOND)) {
                RateGrant::Now => grants += 1,
                RateGrant::Never => break,
                RateGrant::Later(at) => {
                    panic!("a bucket that never refills named a deadline at {at:?}")
                }
            }
        }

        assert_eq!(grants, 7, "floor(10000 / 1400)");
        assert_eq!(state.available_bytes(BURST), 200, "10000 - 7 * 1400");

        // A century of waiting does not change it: there is no refill to wait
        // for, which is exactly why the answer is not a deadline.
        let a_century = Tick(100 * 365 * 24 * 60 * 60 * SECOND);
        assert_eq!(charge(&mut state, 0, BURST, SIZE, a_century), RateGrant::Never);
    }

    /// A datagram larger than the burst is `Never`, not a deadline that would
    /// come round again and again with the bucket capped below it.
    ///
    /// This is the second of the two configurations that produce `Never`, and
    /// the one that looks most like a working profile: the rate is generous,
    /// the burst is merely too shallow, and every datagram is refused.
    #[test]
    fn a_datagram_larger_than_the_burst_is_never_grantable() {
        let mut state = BucketState::default();
        assert_eq!(charge(&mut state, 1_000, 100, 101, Tick(0)), RateGrant::Never);

        let a_year = Tick(365 * 24 * 60 * 60 * SECOND);
        assert_eq!(charge(&mut state, 1_000, 100, 101, a_year), RateGrant::Never);

        // And the bucket is still capped at the burst, not accumulating a
        // year's worth of tokens against a depth it cannot hold.
        assert_eq!(state.available_bytes(100), 100);
    }

    /// A `now` that goes backwards under-grants. It never manufactures
    /// tokens and never rewinds the bucket's own clock, so the gap it skipped
    /// is not re-credited by the next forward call.
    #[test]
    fn a_backwards_now_does_not_manufacture_tokens() {
        const RATE: u64 = 1_000;
        const BURST: u64 = 10_000;

        let mut state = BucketState::default();
        assert_eq!(charge(&mut state, RATE, BURST, 10_000, Tick(0)), RateGrant::Now);
        assert_eq!(charge(&mut state, RATE, BURST, 1_000, Tick(SECOND)), RateGrant::Now);

        // Rewind a full second. No refill, and the state's clock stays at
        // 1 s — so the deadline is measured from 1 s, one millisecond out.
        assert_eq!(
            charge(&mut state, RATE, BURST, 1, Tick(0)),
            RateGrant::Later(Tick(SECOND + 1_000_000)),
        );
        // The skipped second is not re-credited: the next forward call earns
        // exactly the 1000 bytes of one more second and no more.
        assert_eq!(charge(&mut state, RATE, BURST, 1_000, Tick(2 * SECOND)), RateGrant::Now);
        assert_eq!(state.available_bytes(BURST), 0);
    }

    /// The exact backlog trace of a queue under above-rate ingress, the exact
    /// index of the first tail drop, and the backlog at that index.
    ///
    /// The arithmetic, worked by hand. The link is 1 000 000 bytes/s and
    /// offers arrive every 500 µs, so 500 bytes drain between offers while
    /// 1400 arrive — ingress is 2.8x the rate. The threshold is 5000 bytes.
    /// Each row is drain, then the admission test `backlog + 1400 > 5000`,
    /// then the resulting backlog:
    ///
    /// ```text
    ///  i  drained to  1400 fits?      backlog after
    ///  0      0        0+1400 ok         1400
    ///  1    900        900+1400 ok       2300
    ///  2   1800        ...ok             3200
    ///  3   2700        ...ok             4100
    ///  4   3600        3600+1400 = 5000, not > 5000, ok   5000
    ///  5   4500        4500+1400 = 5900 > 5000  DROP      4500
    ///  6   4000        5400 > 5000  DROP                  4000
    ///  7   3500        4900 ok                            4900
    ///  8   4400        5800 > 5000  DROP                  4400
    ///  9   3900        5300 > 5000  DROP                  3900
    /// 10   3400        4800 ok                            4800
    /// 11   4300        5700 > 5000  DROP                  4300
    /// 12   3800        5200 > 5000  DROP                  3800
    /// 13   3300        4700 ok                            4700
    /// 14   4200        5600 > 5000  DROP                  4200
    /// ```
    ///
    /// The trace is the assertion rather than a bound on it: `offer` is
    /// clock-free, so the sequence is a pure function of the fabricated ticks
    /// and there is no rate measurement and no tolerance anywhere here.
    ///
    /// The non-zero backlog at the first drop is what separates a genuine tail
    /// drop from a configuration that could never have worked; the trace and
    /// the drop index would both still look plausible without it. The closing
    /// identity — admitted minus drained is what remains queued — fails
    /// immediately if drops are counted as admitted or the drain runs at the
    /// wrong rate.
    #[test]
    fn the_queue_traces_an_exact_backlog_and_tail_drops_at_a_named_index() {
        const RATE: u64 = 1_000_000; // bytes/s
        const THRESHOLD: u64 = 5_000; // bytes
        const SIZE: u32 = 1_400; // bytes
        const STEP_NS: u64 = 500_000; // 500 bytes of drain per step

        let want_backlog = [
            1400, 2300, 3200, 4100, 5000, 4500, 4000, 4900, 4400, 3900, 4800, 4300, 3800, 4700,
            4200,
        ];

        let mut state = QueueState::default();
        let mut got_backlog = Vec::new();
        let mut first_drop = None;
        let mut queued = 0u64;

        for i in 0..want_backlog.len() {
            let now = Tick(i as u64 * STEP_NS);
            match offer(&mut state, RATE, THRESHOLD, SIZE, now) {
                Admission::Queued => queued += 1,
                Admission::TailDropped => {
                    if first_drop.is_none() {
                        first_drop = Some(i);
                        assert!(
                            state.backlog_bytes() > 0,
                            "a tail drop at index {i} reported an empty queue, \
                             which is a configuration that never fits and not congestion"
                        );
                    }
                }
                Admission::NeverFits => {
                    panic!("a {SIZE}-byte datagram fits in a {THRESHOLD}-byte queue")
                }
            }
            got_backlog.push(state.backlog_bytes());
        }

        assert_eq!(got_backlog, want_backlog, "backlog trace");
        assert_eq!(first_drop, Some(5), "index of the first tail drop");
        assert_eq!(got_backlog[5], 4500, "backlog at the first tail drop");
        assert_eq!(queued, 8, "8 of 15 admitted");

        // Conservation: admitted - drained = what is still queued. The drain
        // runs from tick 0 to the last offer's tick, 14 steps of 500 bytes.
        let admitted = queued * u64::from(SIZE);
        let drained = 14 * (STEP_NS * RATE / SECOND);
        assert_eq!(admitted - drained, state.backlog_bytes(), "admitted 11200 - drained 7000");
    }

    /// The distinction, stated as an invariant over a driven sequence rather
    /// than as one example.
    ///
    /// Leg one drives an above-rate ingress hard enough to tail-drop
    /// repeatedly and asserts that **every** tail drop carries a non-zero
    /// backlog. Leg two takes the two configurations that can never work — a
    /// zero threshold and a threshold below one datagram — and asserts they
    /// answer `NeverFits` on an empty queue, at tick zero and again after a
    /// year of draining. Leg three does the same for the bucket's two
    /// unsatisfiable configurations and then asserts that a *workable* one
    /// never produces `Never` at all, so the variant is not simply
    /// unreachable.
    ///
    /// The non-vacuity assertions matter as much as the invariants: an
    /// implementation that never tail-drops satisfies "every tail drop has a
    /// non-zero backlog" perfectly.
    #[test]
    fn a_tail_drop_means_congestion_and_never_fits_does_not() {
        const RATE: u64 = 1_000_000;
        const THRESHOLD: u64 = 5_000;
        const SIZE: u32 = 1_400;
        const STEP_NS: u64 = 500_000;

        let mut state = QueueState::default();
        let mut drops = 0u64;
        for i in 0..200u64 {
            let a = offer(&mut state, RATE, THRESHOLD, SIZE, Tick(i * STEP_NS));
            if a == Admission::TailDropped {
                drops += 1;
                assert!(
                    state.backlog_bytes() > 0,
                    "a tail drop was reported on an empty queue at index {i}"
                );
            }
            assert_ne!(a, Admission::NeverFits, "index {i}: this datagram does fit the threshold");
        }
        assert!(drops > 0, "the ingress must actually overflow, or the invariant is vacuous");

        // A zero threshold, and a threshold below one datagram. Both refuse
        // the first datagram of an idle link; neither is congestion.
        for threshold in [0, 1, u64::from(SIZE) - 1] {
            let mut empty = QueueState::default();
            assert_eq!(
                offer(&mut empty, RATE, threshold, SIZE, Tick(0)),
                Admission::NeverFits,
                "threshold {threshold}"
            );
            assert_eq!(empty.backlog_bytes(), 0, "threshold {threshold}: nothing was ever queued");

            let a_year = Tick(365 * 24 * 60 * 60 * SECOND);
            assert_eq!(
                offer(&mut empty, RATE, threshold, SIZE, a_year),
                Admission::NeverFits,
                "threshold {threshold}: draining does not create room that the threshold forbids"
            );
        }

        // The bucket's twin pair, and then a bucket that can work.
        let mut bucket = BucketState::default();
        assert_eq!(
            charge(&mut bucket, 0, 10_000, SIZE, Tick(0)),
            RateGrant::Now,
            "burst covers it"
        );
        assert_eq!(
            charge(&mut bucket, 0, 10_000, 9_000, Tick(SECOND)),
            RateGrant::Never,
            "zero rate: the burst is spent and never refills"
        );
        assert_eq!(
            charge(&mut BucketState::default(), 100_000_000, 1_000, SIZE, Tick(0)),
            RateGrant::Never,
            "a 1000-byte burst can never cover a 1400-byte datagram, however fast the rate"
        );

        let mut workable = BucketState::default();
        for i in 0..1_000u64 {
            let g = charge(&mut workable, RATE, 10_000, SIZE, Tick(i * STEP_NS));
            assert_ne!(g, RateGrant::Never, "index {i}: this configuration is satisfiable");
        }
    }

    /// A backwards `now` drains nothing and does not rewind the queue's
    /// clock, so it over-reports the backlog rather than under-reporting it.
    ///
    /// The direction is the point. Under-reporting would let a saturated
    /// queue admit datagrams it has no room for, which is a tail drop that
    /// silently does not happen.
    #[test]
    fn a_backwards_now_does_not_drain_the_queue() {
        const RATE: u64 = 1_000_000;

        let mut state = QueueState::default();
        assert_eq!(offer(&mut state, RATE, 5_000, 1_400, Tick(SECOND)), Admission::Queued);
        assert_eq!(state.backlog_bytes(), 1_400);

        // A second earlier: no drain, and the clock stays at 1 s.
        assert_eq!(offer(&mut state, RATE, 5_000, 1_400, Tick(0)), Admission::Queued);
        assert_eq!(state.backlog_bytes(), 2_800, "the skipped second drained nothing");

        // And the skipped second is not re-credited on the next forward call:
        // 500 µs of drain is 500 bytes, not 1 000 500.
        assert_eq!(
            offer(&mut state, RATE, 5_000, 1_400, Tick(SECOND + 500_000)),
            Admission::Queued
        );
        assert_eq!(state.backlog_bytes(), 2_800 - 500 + 1_400);
    }

    /// A fresh bucket is **full** and a fresh queue is **empty**, both at
    /// `Tick(0)`.
    ///
    /// Not a triviality about `Default`. A bucket that started empty would
    /// hold the first datagram of every session for `burst / rate`, which
    /// reads as a broken link rather than a shaped one, and the whole reason
    /// this state is stored as a deficit is that the derived `Default` of a
    /// token count would do exactly that. The assertion is therefore on the
    /// behaviour — the first datagram goes at tick zero — and not on a field.
    #[test]
    fn a_fresh_bucket_is_full_and_a_fresh_queue_is_empty() {
        const BURST: u64 = 4_096;

        assert_eq!(BucketState::default().available_bytes(BURST), BURST);
        assert_eq!(QueueState::default().backlog_bytes(), 0);

        // The first datagram of a session goes immediately, at any rate.
        let mut state = BucketState::default();
        assert_eq!(charge(&mut state, 1, BURST, 4_096, Tick(0)), RateGrant::Now);

        // An empty bucket, by contrast, would need 4096 seconds at 1 byte/s
        // — which is what the deficit representation exists to avoid, and
        // what this deadline shows the cost of.
        assert_eq!(
            charge(&mut state, 1, BURST, 4_096, Tick(0)),
            RateGrant::Later(Tick(4_096 * SECOND))
        );
    }
}

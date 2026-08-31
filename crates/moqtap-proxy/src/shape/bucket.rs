//! The token bucket — configuration, state, and the one pure function
//! that decides whether a unit may go now.
//!
//! [`charge`] takes `now` as a parameter and reads no clock, following
//! `release_timer::plan(now, next, slice)`. That is the whole reason the
//! exact rate claim is provable: the arithmetic is a function of
//! fabricated `Instant`s, so `the_bucket_never_grants_above_rate_plus_burst`
//! is a +-0 % assertion over ten thousand steps rather than a measurement
//! that machine load can move.
//!
//! # Units
//!
//! `rate_bps` is **bytes per second**, paired with `burst_bytes` and with
//! the `bytes` argument to [`charge`]. Everything the scheduler counts is a
//! byte count, and mixing a bit rate into a byte accounting would put a
//! factor of eight between the configuration and every statistic that
//! reports against it. A bit rate is `rate_bps * 8`.
//!
//! # Why the arithmetic is scaled
//!
//! Tokens are held in *nano-bytes* (`u128`), one byte being a thousand
//! million nano-bytes, and refills are computed from elapsed nanoseconds.
//! An unscaled byte counter would round every sub-byte refill to zero and
//! a bucket paced faster than one byte per nanosecond would drift low
//! without any test noticing; `u128` removes the overflow question
//! entirely rather than documenting a ceiling nobody would check.

use std::time::{Duration, Instant};

/// Nano-bytes per byte, and equally nanoseconds per second — the two are
/// the same constant because a bucket accumulating `rate` bytes per second
/// accumulates exactly `rate` nano-bytes per nanosecond.
const NANO: u128 = 1_000_000_000;

/// A named token bucket. One per class, or shared by several.
///
/// `#[non_exhaustive]` *with* a [`Default`], exactly as
/// [`EgressConfig`](crate::action::EgressConfig) is. Without the `Default`
/// an integration-test crate could not construct one at all, because
/// struct-expression and functional-update syntax are both illegal outside
/// the defining crate — and note that `..BucketConfig::default()` is one of
/// the two illegal forms (`E0639`), so an outside caller assigns per field
/// on a `::default()` binding. See the module doc on
/// [`shape`](crate::shape) for the full statement. The default is an
/// unnamed, unlimited bucket.
///
/// # The written form requires `name` and `burst_bytes`
///
/// The two rate fields default to absent, which means unlimited and is a
/// sensible thing to leave out. The other two are required, and
/// `burst_bytes` is the interesting one: its Rust default is `0`, a depth
/// that can cover no object at all, and a bucket that inherits it delivers
/// every unit at its `max_hold` clamp at a throughput bearing no relation to
/// the rate beside it. That failure is quiet — the run looks rate-limited,
/// because it is, just not by the number in the file — so the written form
/// makes the author state the depth rather than inherit the one value that
/// cannot work. See [`BucketConfig::burst_bytes`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
#[non_exhaustive]
pub struct BucketConfig {
    /// The name a [`ClassRule`](super::ClassRule) refers to. Must be unique
    /// across the profile's buckets, and a class naming a bucket that is
    /// not present is rejected by
    /// [`ShapeProfile::try_new`](super::ShapeProfile::try_new).
    pub name: String,
    /// Sustained rate in **bytes per second**.
    ///
    /// `None` means unlimited — an explicitly unshaped class, which is not
    /// the same as no class: it still has a name, its own statistics, and
    /// its own place in the discipline. [`charge`] answers
    /// [`Grant::Now`] for every unit, whatever its size, and touches no
    /// state.
    ///
    /// `Some(0)` is **legal and distinct**: the bucket never refills, so
    /// after the initial `burst_bytes` are spent no unit is ever grantable
    /// from tokens. [`charge`] answers [`Grant::Never`] rather than a
    /// refill instant, because there is no refill instant to compute and
    /// arming a release timer at an unreachable one would arm a timer that
    /// never fires. The caller supplies the deadline instead — the unit's
    /// `max_hold` clamp — so under the default
    /// [`Expiry::Deliver`](super::Expiry) a 0-bps class **does** deliver,
    /// at `max_hold`, clamped, reporting `Impairment{HoldClamped}`.
    /// A zero rate is checked **before** the burst, so a deliberately stopped
    /// class answers [`Grant::Never`] and never [`Grant::LargerThanBurst`]. The
    /// distinction is the whole value of the second variant: *I asked for no
    /// traffic* is a configuration working, and *I asked for a rate and my
    /// burst cannot cover one object* is a configuration that silently is not.
    /// The consequence is binding on every fixture: **a 0-bps class delivers
    /// zero bytes* is a statement about a sampling window, not a property.* A
    /// test that relies on starvation must pin
    /// [`QueueConfig::max_hold`](super::QueueConfig::max_hold) explicitly so
    /// the margin between the assertion and the delivery is visible in the
    /// fixture rather than inherited from a default the test never names.
    #[cfg_attr(feature = "serde", serde(default))]
    pub rate_bps: Option<u64>,
    /// Bytes the bucket may accumulate while idle, and therefore the
    /// largest unit it can ever grant from tokens: a unit larger than
    /// `burst_bytes` can never be covered, however long the caller waits.
    ///
    /// **Set this to at least one object.** The default is `0`, which
    /// cannot cover anything, and the failure it produces is quiet: with no
    /// unit ever grantable, every object leaves at its `max_hold` clamp
    /// instead of at `rate_bps`, so the measured throughput is
    /// `depth / max_hold` and bears no relation to the rate that was
    /// written down. Measured, at `rate_bps: Some(1_000_000)` with
    /// `burst_bytes: 100` and 1000-byte objects: delivery landed on the
    /// clamp exactly, at a rate the configuration never names.
    ///
    /// [`charge`] answers [`Grant::LargerThanBurst`] for that case rather
    /// than folding it into [`Grant::Never`], so the caller can report it as
    /// the misconfiguration it is instead of as the ordinary rate limiting
    /// it is indistinguishable from. It cannot be rejected when the profile
    /// is built: [`ShapeProfile::try_new`](super::ShapeProfile::try_new) has
    /// the burst but not the object sizes, and the sizes are what decide.
    pub burst_bytes: u64,
    /// Optional ceiling for borrowing above `rate_bps`.
    ///
    /// **Reserved.** The scheduler accepts this field and never borrows, with no
    /// diagnostic — the frozen `ShapeError` has no variant it could land
    /// in. A profile setting `ceil_bps` above `rate_bps` measures a flat
    /// `rate_bps`; this sentence is the whole of the warning.
    #[cfg_attr(feature = "serde", serde(default))]
    pub ceil_bps: Option<u64>,
}

/// The mutable half of a token bucket: what it holds and when it was last
/// refilled.
///
/// Session-scoped and shared by every stream of a class, so it is the
/// scheduler's state and not a stream's. Kept separate from
/// [`BucketConfig`] so the configuration stays comparable and cloneable
/// while the state stays exactly one owner's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BucketState {
    /// Held tokens in nano-bytes. Never exceeds `burst_bytes * NANO` and
    /// never goes negative — the type forbids it, and so does the rate
    /// bound the bucket exists to hold.
    tokens: u128,
    /// The instant `tokens` was last brought up to date.
    last: Instant,
}

impl BucketState {
    /// A bucket that starts full at `burst_bytes`, as of `now`.
    ///
    /// Starting full is what makes the first unit of a session go
    /// immediately; starting empty would put a `burst_bytes / rate_bps`
    /// delay in front of every stream and read as a broken proxy.
    pub fn new(burst_bytes: u64, now: Instant) -> Self {
        Self { tokens: u128::from(burst_bytes) * NANO, last: now }
    }

    /// Whole bytes currently held, as of the last [`charge`].
    ///
    /// Does not refill: this is a read of recorded state, not a clock
    /// reading, so it stays usable from a test that fabricates its own
    /// instants.
    pub fn available_bytes(&self) -> u64 {
        u64::try_from(self.tokens / NANO).unwrap_or(u64::MAX)
    }
}

/// What [`charge`] decided about one unit.
///
/// `#[non_exhaustive]` with no `Default`: there is no safe default answer.
/// Defaulting to `Now` would silently unshape a bucket; defaulting to
/// `Never` would silently stall one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Grant {
    /// The unit may go now. The tokens have already been debited.
    Now,
    /// Not now. The bucket holds enough at this instant and not before, so
    /// this is the deadline to arm.
    ///
    /// The instant is *earliest*, not *exact*: another stream sharing the
    /// bucket may drain it again before this one wakes, in which case the
    /// next [`charge`] answers `Later` again with a new deadline.
    Later(Instant),
    /// Not now, and no refill instant exists, because the rate is `Some(0)`
    /// and the bucket therefore never refills.
    ///
    /// The caller must supply its own deadline, which is the unit's
    /// `max_hold` clamp. Returning a fabricated far-future instant instead
    /// was rejected: it would arm a release timer that never fires, and
    /// nothing downstream could tell that deadline from a real one.
    Never,
    /// Not now, and not ever from tokens: the unit is larger than the whole
    /// bucket, so no amount of refilling reaches it.
    ///
    /// **A separate answer from [`Self::Never`], and the separation is the
    /// point.** Both leave the caller to fall back on the `max_hold` clamp,
    /// so the two are identical in what they *do*; they are opposite in what
    /// they mean. `Never` is a rate of zero doing exactly what it was asked
    /// to. This is a rate that was asked for and cannot be delivered, because
    /// the bucket cannot hold one object's worth of tokens — every unit
    /// leaves at the clamp and the configured rate never binds at all. Folded
    /// into one variant, the second is invisible: it produces the same clamp,
    /// the same `tokens_exhausted_episodes` and the same `HoldClamped` report
    /// a working rate limit produces.
    ///
    /// Reachable only with a non-zero rate — a zero rate is answered first —
    /// so a caller reporting this is always reporting a burst that is too
    /// small and never a class that was configured to stop.
    LargerThanBurst {
        /// The bucket's cap, which is [`BucketConfig::burst_bytes`].
        burst_bytes: u64,
        /// The unit that did not fit, so the report can quote both numbers
        /// rather than leaving the reader to find one of them.
        unit_bytes: u64,
    },
}

/// Charge `bytes` against a bucket and say whether the unit may go.
///
/// **Pure with respect to the clock** — `now` is a parameter and no clock
/// is read, following `release_timer::plan`. `state` is refilled to `now`
/// before the decision and debited only on [`Grant::Now`]; every refusal
/// costs nothing, so re-charging the same unit after its deadline is correct
/// rather than double-billing.
///
/// The bound **this function** upholds, exactly: over any interval, the
/// bytes it grants never exceed `rate_bps * elapsed + burst_bytes`. That is
/// what makes the rate claim provable arithmetic rather than a measurement,
/// and `the_bucket_never_grants_above_rate_plus_burst` proves it over
/// 10 001 fabricated steps.
///
/// # It is not the bound the *shaper* upholds
///
/// Stated here because the difference is a factor of thousands and a reader
/// of this line will otherwise assume the wrong one. `PendingQueue`'s
/// release seam checks the unit's `max_hold` clamp **before** it calls
/// `acquire`, and under the default [`Expiry::Deliver`](super::Expiry) a
/// clamped unit goes out without a bucket being consulted at all — that is
/// what "a 0-bps class still delivers, at `max_hold`" means. So the
/// end-to-end ceiling is
///
/// ```text
/// min(rate_bps * elapsed + burst_bytes,   <- this function
///     depth / max_hold * elapsed)         <- the clamp, per stream
/// ```
///
/// Measured, with `rate_bps: Some(0)`, `depth_bytes: 4096` and `max_hold:
/// 300 ms`: a bucket configured at **0 bytes/s** sustained ~25 kB/s. The
/// clamp is the deliberate non-destructive default — a starved unit is
/// delivered late rather than dropped — and not a defect, but a fixture that
/// means to observe *this* function's bound has to pin
/// `max_hold` far enough out that the clamp cannot bind inside its sampling
/// window — which is why every starvation fixture is required to name it.
///
/// `now` is expected to be monotonic. A `now` earlier than the last one
/// refills nothing and does not rewind the bucket's clock, so an
/// out-of-order caller under-grants rather than manufacturing tokens.
pub fn charge(
    state: &mut BucketState,
    rate_bps: Option<u64>,
    burst_bytes: u64,
    bytes: u64,
    now: Instant,
) -> Grant {
    // Unlimited: no accounting at all, so an unshaped class costs nothing
    // per unit and arms no deadline. `None` is emphatically not `Some(0)`.
    let Some(rate) = rate_bps else {
        return Grant::Now;
    };

    let cap = u128::from(burst_bytes) * NANO;
    if now > state.last {
        let elapsed = (now - state.last).as_nanos();
        state.tokens = (state.tokens + elapsed * u128::from(rate)).min(cap);
        state.last = now;
    } else {
        // Still clamp: `burst_bytes` may have shrunk under a reconfigure.
        state.tokens = state.tokens.min(cap);
    }

    let need = u128::from(bytes) * NANO;
    if state.tokens >= need {
        state.tokens -= need;
        return Grant::Now;
    }

    // Two unreachable answers, deliberately not one. A zero rate is asked
    // for first, so a class configured to stop is never reported as a class
    // whose burst is mis-sized; what is left is a rate the caller does want
    // and a bucket that cannot hold one unit of it, which is the case that
    // has no other symptom.
    if rate == 0 {
        return Grant::Never;
    }
    if need > cap {
        return Grant::LargerThanBurst { burst_bytes, unit_bytes: bytes };
    }

    let deficit = need - state.tokens;
    let wait_nanos = deficit.div_ceil(u128::from(rate));
    let wait = u64::try_from(wait_nanos).map(Duration::from_nanos);
    match wait.ok().and_then(|d| state.last.checked_add(d)) {
        Some(at) => Grant::Later(at),
        // A wait that does not fit in a `Duration`, or an `Instant` past
        // the platform's representable range, is not a deadline anyone can
        // arm. Say so rather than saturate into a lie.
        None => Grant::Never,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact rate bound, over fabricated instants.
    ///
    /// Demand is twice the rate, so the bucket — not the offered load — is
    /// what limits the total. With demand at or below the rate the bucket
    /// never binds and the assertion would hold however wrong the
    /// arithmetic was.
    #[test]
    fn the_bucket_never_grants_above_rate_plus_burst() {
        const RATE: u64 = 1_000_000; // bytes/s
        const BURST: u64 = 10_000; // bytes
        const STEPS: u64 = 10_000;
        const STEP: Duration = Duration::from_micros(100); // 100 bytes of refill
        const UNIT: u64 = 200; // 2x the rate

        let base = Instant::now();
        let mut state = BucketState::new(BURST, base);
        let mut granted: u128 = 0;
        let mut grants = 0u64;

        // `0..=STEPS`: the first charge happens at `base`, before any
        // refill, so the full bucket is never clamped away and the ceiling
        // below is reached exactly rather than approached.
        for i in 0..=STEPS {
            let now = base + STEP * u32::try_from(i).expect("step index fits u32");
            match charge(&mut state, Some(RATE), BURST, UNIT, now) {
                Grant::Now => {
                    granted += u128::from(UNIT);
                    grants += 1;
                }
                Grant::Later(at) => assert!(at > now, "a Later deadline must be in the future"),
                other => panic!("a {UNIT}-byte unit fits in a {BURST}-byte burst: {other:?}"),
            }
        }

        let elapsed_nanos = (STEP * u32::try_from(STEPS).expect("step count fits u32")).as_nanos();
        let ceiling = u128::from(RATE) * elapsed_nanos / NANO + u128::from(BURST);

        // The claim.
        assert!(
            granted <= ceiling,
            "granted {granted} bytes over {elapsed_nanos} ns; ceiling is rate*dt + burst = {ceiling}"
        );
        // ...and it is not passing by granting nothing: a bucket that is
        // offered twice its rate must still deliver its rate.
        assert!(
            granted >= u128::from(RATE) * elapsed_nanos / NANO,
            "granted {granted} bytes, below the sustained rate"
        );
        // The residue is strictly less than one unit, so `ceiling` is a
        // tight bound and not a decade of slack. Here it is zero: the
        // numbers are chosen so `(burst + rate*dt)` divides by `UNIT`.
        assert!(ceiling - granted < u128::from(UNIT), "bound is not tight: {ceiling} vs {granted}");
        assert_eq!(grants, 5050, "grant count is deterministic: (burst + rate*dt) / unit");
    }

    /// An unlimited bucket always grants, and arms no deadline.
    #[test]
    fn an_unlimited_bucket_always_grants() {
        let base = Instant::now();
        let mut state = BucketState::new(0, base);

        // No time passes at all, and the burst is zero: only `None` meaning
        // *unlimited* rather than *zero* can carry this.
        for i in 0..1_000u64 {
            let g = charge(&mut state, None, 0, u64::MAX, base);
            assert_eq!(g, Grant::Now, "unlimited bucket refused unit {i}");
        }

        // Contrast, in the same test, so "always grants" is not vacuous:
        // `Some(0)` with the same burst never grants and never names an
        // instant to wait for.
        let mut zero = BucketState::new(0, base);
        assert_eq!(charge(&mut zero, Some(0), 0, 1, base), Grant::Never);
        assert_eq!(
            charge(&mut zero, Some(0), 0, 1, base + Duration::from_secs(3600)),
            Grant::Never,
            "a zero-rate bucket does not refill, however long it waits"
        );
    }

    /// The `Later` deadline is the earliest instant the unit fits, and
    /// waiting exactly that long makes it fit.
    #[test]
    fn a_later_deadline_is_when_the_unit_fits() {
        let base = Instant::now();
        // 1000 bytes/s, empty burst: 500 bytes needs exactly 500 ms.
        let mut state = BucketState::new(0, base);
        let at = match charge(&mut state, Some(1_000), 10_000, 500, base) {
            Grant::Later(at) => at,
            other => panic!("expected Later, got {other:?}"),
        };
        assert_eq!(at, base + Duration::from_millis(500));

        // One nanosecond early is still not enough; the deadline itself is.
        assert!(matches!(
            charge(&mut state, Some(1_000), 10_000, 500, at - Duration::from_nanos(1)),
            Grant::Later(_)
        ));
        assert_eq!(charge(&mut state, Some(1_000), 10_000, 500, at), Grant::Now);
        assert_eq!(state.available_bytes(), 0);
    }

    /// A unit larger than the burst is refused with **its own answer** —
    /// not a deadline that would come round again and again with the bucket
    /// capped below it, and not the answer a zero-rate bucket gives.
    ///
    /// The two refusals are driven in one body against the same unit size,
    /// because the claim is a difference and a difference needs both sides.
    /// A rate of zero is a class that was asked to stop; a rate of 1000 with
    /// a burst of 100 is a class that was asked for 1000 bytes a second and
    /// will never see one byte of it, and only the second is worth a report.
    ///
    /// *Ablation:* restore the single `if rate == 0 || need > cap { Never }`
    /// — the first assertion reddens with
    /// `left: Never / right: LargerThanBurst { burst_bytes: 100, unit_bytes: 101 }`,
    /// which is precisely the collapse that made a mis-sized burst
    /// unreportable.
    #[test]
    fn a_unit_larger_than_the_burst_is_refused_as_a_burst_problem() {
        let base = Instant::now();
        let mut state = BucketState::new(100, base);
        let too_big = Grant::LargerThanBurst { burst_bytes: 100, unit_bytes: 101 };
        assert_eq!(charge(&mut state, Some(1_000), 100, 101, base), too_big);
        // A century of refill does not change it: the cap, not the wait, is
        // what refuses.
        let much_later = base + Duration::from_secs(60 * 60 * 24 * 365);
        assert_eq!(charge(&mut state, Some(1_000), 100, 101, much_later), too_big);
        // And the bucket is still capped at the burst, not accumulating.
        assert_eq!(state.available_bytes(), 100);

        // The other side of the difference: the same over-sized unit against
        // a bucket whose rate is zero is `Never`, because a class configured
        // to stop is doing what it was told and there is nothing to report.
        let mut stopped = BucketState::new(100, base);
        assert_eq!(charge(&mut stopped, Some(0), 100, 101, base), Grant::Never);

        // ...and one that *does* fit is granted, so neither refusal above is
        // the bucket refusing everything.
        assert_eq!(charge(&mut state, Some(1_000), 100, 100, much_later), Grant::Now);
    }

    /// A `now` that goes backwards under-grants; it never manufactures
    /// tokens and never rewinds the bucket's own clock.
    #[test]
    fn a_backwards_now_does_not_manufacture_tokens() {
        let base = Instant::now();
        let mut state = BucketState::new(0, base);
        let later = base + Duration::from_secs(1);
        assert_eq!(charge(&mut state, Some(1_000), 10_000, 1_000, later), Grant::Now);

        // Rewind a second: no refill, and the state's clock stays at
        // `later`, so the deadline is measured from `later` and the next
        // forward call does not re-credit the gap.
        assert_eq!(
            charge(&mut state, Some(1_000), 10_000, 1, base),
            Grant::Later(later + Duration::from_millis(1)),
        );
        assert_eq!(
            charge(&mut state, Some(1_000), 10_000, 1_000, later + Duration::from_secs(1)),
            Grant::Now,
        );
    }
}

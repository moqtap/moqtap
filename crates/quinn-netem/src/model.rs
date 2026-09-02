//! The six models, `Prob`, `Window`, and the delay sampler.
//!
//! A model here is pure configuration plus the arithmetic that turns a
//! generator draw into a decision. Nothing in this module owns a generator,
//! reads a clock or allocates on the hot path; the engine hands each sampler
//! the stream it is entitled to draw from and nothing else.

use crate::dist::{crandom, tabledist, CorrState, NORMAL, PARETO, PARETONORMAL};
use crate::profile::ProfileError;
use crate::rng::Pcg32;

/// One part per billion as a numerator: the value [`Prob::from_ppb`] treats as
/// certainty and saturates at.
const PPB_ONE: u32 = 1_000_000_000;

/// A probability as an integer numerator over 2^32, in the INCLUSIVE range
/// `[0, 2^32]` — so p = 0 and p = 1 are both exactly representable.
///
/// netem holds these as a `u32` compared with a strict `<`. The largest value
/// that representation can express is `(2^32 - 1) / 2^32`, which leaves a hole
/// of 2^-32 per datagram: "drop everything" is not expressible there, only
/// approachable, and a long enough run eventually delivers a datagram that was
/// configured to be dropped. Widening the numerator to `u64` costs one cast on
/// the hot path and turns the degenerate all-lost row from a probabilistic
/// claim into an exact one — [`Prob::hits`] is `false` for every draw at p = 0
/// and `true` for every draw at p = 1, `u32::MAX` included.
///
/// # The written form
///
/// Under the `serde` feature a probability is written and read as `ProbPpb` —
/// one integer, parts per billion — and never as the numerator above. That
/// scale belongs to the comparison [`Prob::hits`] performs; putting it into a
/// file format would publish 2^32 as a number a caller has to know,
/// and would accept values above it that no constructor can produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(into = "ProbPpb", try_from = "ProbPpb"))]
pub struct Prob(u64);

impl Prob {
    /// Canonical, integer. `ppb > 1_000_000_000` saturates at certainty.
    ///
    /// Rounds to nearest rather than truncating. Truncation is a systematic
    /// downward bias: every configured probability would come out fractionally
    /// smaller than it was written, which is the wrong direction for a crate
    /// whose standing rule is that a configured impairment gets delivered.
    /// Rounding costs one addition and keeps both endpoints exact —
    /// `from_ppb(0)` is 0 and `from_ppb(1_000_000_000)` is 2^32 with no
    /// remainder.
    pub const fn from_ppb(ppb: u32) -> Prob {
        // `Ord::min` is not callable from a `const fn`, hence the `if`.
        let ppb = if ppb > PPB_ONE { PPB_ONE } else { ppb };
        // Widest intermediate is `1_000_000_000 << 32` plus half a billion,
        // about 4.29e18 — comfortably inside `u64::MAX`, about 1.84e19.
        Prob((((ppb as u64) << 32) + (PPB_ONE as u64) / 2) / (PPB_ONE as u64))
    }

    /// Convenience constructor for callers that already hold a float. Uses
    /// only multiplication and truncation, which IEEE-754 specifies exactly
    /// and which are therefore identical on every platform — unlike the
    /// transcendental functions this crate refuses to call.
    ///
    /// The scale factor is written as a **cast** of `1u64 << 32` rather than
    /// as the literal `4294967296.0`, so that the two clamp bounds below are
    /// the only float literals in the whole crate. The cast is exact.
    ///
    /// # NaN is refused, not silently zeroed
    ///
    /// `clamp` propagates NaN, and the truncating cast turns NaN into 0. That
    /// is p = 0, which is *drop nothing*. A caller who arrived at a
    /// probability through `hits / total` with `total == 0` would get an
    /// impairment that is configured, accepted, and then silently never
    /// delivered — out of the one function in this crate that truncates a
    /// caller-supplied float. So this constructor is fallible, and the failure
    /// is [`ProfileError::ProbabilityNotANumber`].
    ///
    /// Out-of-range finite values still clamp rather than erroring, because
    /// `p = 1.5` has an unambiguous intent — certainty — and NaN has none.
    pub fn from_f64(p: f64) -> Result<Prob, ProfileError> {
        if p.is_nan() {
            return Err(ProfileError::ProbabilityNotANumber);
        }
        Ok(Prob(((p.clamp(0.0, 1.0)) * ((1u64 << 32) as f64)) as u64))
    }

    /// Whether a generator draw falls inside this probability.
    ///
    /// `(draw as u64) < self.0` — the whole comparison, stated once, so that
    /// no model can spell it with a `<=` of its own and quietly shift every
    /// fixture this crate has ever recorded.
    pub const fn hits(self, draw: u32) -> bool {
        (draw as u64) < self.0
    }
}

/// A [`Prob`] as it is written in a configuration file: one integer, parts per
/// billion, in the inclusive range `[0, 1_000_000_000]`.
///
/// [`Prob`] cannot be written as itself. Its numerator is private and scaled
/// over 2^32, so a derived representation would put that scale into the file
/// format and would accept numerators above it — values with no constructor,
/// reached without the saturation and the rounding that [`Prob::from_ppb`]
/// performs. This type is the whole of the written representation, and
/// `from_ppb` is the only way back out of it.
///
/// # Why the keys say `ppb`
///
/// Every field that holds one is written with the unit in the key — `p-ppb`
/// rather than `p` — for the reason every other number in this crate carries
/// its unit in its name. Without it, `p: 1` reads as certainty to anyone who
/// has ever written a probability as a fraction, and means one part in a
/// billion: an impairment configured, armed, reported as applied, and firing
/// on approximately nothing. No range check can catch that one, because both
/// readings are in range; only the name can.
///
/// # The round trip
///
/// Exact for every value this type can hold: `from_ppb` maps the billion
/// inputs onto distinct numerators, and the conversion back rounds to the
/// nearest, so no `ppb` written down comes back as a different one. It is
/// **not** exact the other way for a [`Prob`] built by [`Prob::from_f64`],
/// which can land between two `ppb` grid points; such a probability is written
/// out as the nearest one.
#[cfg(feature = "serde")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct ProbPpb(
    /// Parts per billion. `1_000_000_000` is certainty.
    pub u32,
);

/// A written probability above certainty, refused rather than saturated.
///
/// [`Prob::from_ppb`] saturates, and is right to: a caller who arrived at a
/// probability by arithmetic can overshoot by a rounding step and mean nothing
/// by it. A number in a configuration file was typed, and a typed
/// `2_000_000_000` has no second reading — it is a unit the author expected to
/// be percent, or a fraction, or a digit too many. Saturating it would arm
/// certainty out of something nobody wrote, so the deserializer refuses it and
/// names the value it refused.
#[cfg(feature = "serde")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbPpbOutOfRange {
    /// The value that was written.
    pub ppb: u32,
}

/// Lower case and no trailing period, matching [`crate::profile::ProfileError`]
/// and the other error types in this workspace, so that a wrapped message reads
/// as one sentence.
#[cfg(feature = "serde")]
impl std::fmt::Display for ProbPpbOutOfRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { ppb } = self;
        write!(f, "probability {ppb} ppb is above {PPB_ONE}, which is certainty")
    }
}

#[cfg(feature = "serde")]
impl std::error::Error for ProbPpbOutOfRange {}

/// Rounds to nearest, for [`Prob::from_ppb`]'s reason: truncating here would
/// bias every written probability downward, so a profile saved and reloaded
/// would impair fractionally less each time it made the trip.
#[cfg(feature = "serde")]
impl From<Prob> for ProbPpb {
    fn from(p: Prob) -> ProbPpb {
        // Widest intermediate is `2^32 * 1_000_000_000` plus a half, about
        // 4.29e18 — comfortably inside `u64::MAX`, about 1.84e19.
        ProbPpb((((p.0 * PPB_ONE as u64) + (1u64 << 31)) >> 32) as u32)
    }
}

/// The only deserialization path into a [`Prob`], and it goes through
/// [`Prob::from_ppb`] rather than around it.
#[cfg(feature = "serde")]
impl TryFrom<ProbPpb> for Prob {
    type Error = ProbPpbOutOfRange;

    fn try_from(written: ProbPpb) -> Result<Prob, ProbPpbOutOfRange> {
        if written.0 > PPB_ONE {
            return Err(ProbPpbOutOfRange { ppb: written.0 });
        }
        Ok(Prob::from_ppb(written.0))
    }
}

/// How datagrams are selected for loss.
///
/// `#[non_exhaustive]` is deliberate and costs nothing here. This is an *input*
/// enum: callers and tests **construct** its variants rather than matching them
/// exhaustively, and `#[non_exhaustive]` on an enum still permits construction
/// from outside the defining crate. So the attribute buys room for a seventh
/// loss model without making a single existing caller add a wildcard arm.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(rename_all = "kebab-case", rename_all_fields = "kebab-case", deny_unknown_fields)
)]
#[non_exhaustive]
pub enum LossModel {
    /// Independent per-datagram draw at probability `p`.
    Bernoulli {
        /// Drop probability.
        #[cfg_attr(feature = "serde", serde(rename = "p-ppb"))]
        p: Prob,
    },
    /// netem's four-parameter Gilbert-Elliott burst-loss chain.
    ///
    /// Consumes **two** draws per datagram — one to step the chain, one to
    /// decide — and decides with the **departing** state's parameter: the Good
    /// state compares `<` against `one_minus_k`, the Bad state compares `>`
    /// against `h`. The asymmetry between those two operators is netem's, and
    /// it is kept rather than tidied up: the entire reason to implement this
    /// chain instead of a nicer one is so that a profile written against `tc`
    /// produces the same burst structure here.
    GilbertElliott {
        /// Good -> Bad transition probability.
        #[cfg_attr(feature = "serde", serde(rename = "p-ppb"))]
        p: Prob,
        /// Bad -> Good transition probability.
        #[cfg_attr(feature = "serde", serde(rename = "r-ppb"))]
        r: Prob,
        /// Loss probability in the Bad state, netem's `1-h` sense.
        #[cfg_attr(feature = "serde", serde(rename = "h-ppb"))]
        h: Prob,
        /// Loss probability in the Good state, netem's `1-k`.
        #[cfg_attr(feature = "serde", serde(rename = "one-minus-k-ppb"))]
        one_minus_k: Prob,
    },
    /// Exact indices in the direction's own `seq` space. Sorted and
    /// deduplicated by `validate`. Consumes NO draws.
    Pattern {
        /// The `seq` values to drop.
        indices: Vec<u64>,
    },
    /// `seq % n == n - 1`. Consumes NO draws. `n == 0` is a construction
    /// error, not a silent no-op.
    EveryNth {
        /// Period. `0` is [`ProfileError::EveryNthZero`].
        n: u64,
    },
}

/// How long a datagram is held.
///
/// `#[non_exhaustive]` for the reason given on [`LossModel`]: it is constructed
/// from outside, never matched exhaustively.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(rename_all = "kebab-case", rename_all_fields = "kebab-case", deny_unknown_fields)
)]
#[non_exhaustive]
pub enum DelayModel {
    /// Constant delay. Consumes no draws.
    Fixed {
        /// The delay, nanoseconds.
        mean_ns: u64,
    },
    /// netem's uniform arm: `((rnd % (2*sigma)) + mu) - sigma`.
    Uniform {
        /// Mean delay, nanoseconds.
        mean_ns: u64,
        /// Half-width of the uniform interval, nanoseconds.
        jitter_ns: u64,
        /// Correlation, `[0, 255]`; 0 is uncorrelated.
        rho: u8,
    },
    /// [`crate::dist::NORMAL`] through `tabledist`.
    Normal {
        /// Mean delay, nanoseconds.
        mean_ns: u64,
        /// Standard deviation, nanoseconds.
        sigma_ns: u64,
        /// Correlation, `[0, 255]`; 0 is uncorrelated.
        rho: u8,
    },
    /// [`crate::dist::PARETO`] through `tabledist`.
    Pareto {
        /// Mean delay, nanoseconds.
        mean_ns: u64,
        /// Scale, nanoseconds.
        sigma_ns: u64,
        /// Correlation, `[0, 255]`; 0 is uncorrelated.
        rho: u8,
    },
    /// [`crate::dist::PARETONORMAL`] through `tabledist`.
    ParetoNormal {
        /// Mean delay, nanoseconds.
        mean_ns: u64,
        /// Scale, nanoseconds.
        sigma_ns: u64,
        /// Correlation, `[0, 255]`; 0 is uncorrelated.
        rho: u8,
    },
}

/// Reordering, with netem's COUNTER semantics rather than displacement.
///
/// With `gap: n`, every n-th datagram is a reorder *candidate*; a candidate
/// that also passes `p` is released at `now` instead of `now + delay`, so it
/// jumps ahead of everything already parked in the delay queue. Nothing is
/// swapped with anything — the reordering is a side effect of one datagram
/// skipping the queue, which is why the model needs a queue to exist.
///
/// # Two ways this is refused rather than ignored
///
/// A `ReorderModel` on a direction whose `delay` is `None` is a construction
/// error ([`ProfileError::ReorderWithoutDelay`]). With no delay there is no
/// queue to jump, so the model cannot change any outcome. netem has the
/// identical dependency and says nothing when you hit it, which is how an
/// afternoon disappears into wondering why a reorder percentage did nothing.
///
/// `gap == 0` is also a construction error
/// ([`ProfileError::ReorderGapZero`]), and specifically it does **not** mean
/// "reordering off". `ReorderModel { gap: 0, p: <certainty> }` reads like the
/// strongest reorder setting available and fires on nothing. A direction that
/// wants no reordering sets `reorder: None`; that is what the `Option` is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case", deny_unknown_fields))]
pub struct ReorderModel {
    /// Every `gap`-th datagram is a reorder candidate. `0` is refused.
    pub gap: u32,
    /// Probability a candidate actually reorders.
    #[cfg_attr(feature = "serde", serde(rename = "p-ppb"))]
    pub p: Prob,
}

/// One extra copy of a datagram, released at the same tick as the original.
///
/// netem compares `>=` here where reorder compares `<`. The operators are
/// netem's and are kept, for the reason the Gilbert-Elliott asymmetry is kept:
/// a profile ported from `tc` has to produce the same stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case", deny_unknown_fields))]
pub struct DupModel {
    /// Duplication probability.
    #[cfg_attr(feature = "serde", serde(rename = "p-ppb"))]
    pub p: Prob,
}

/// One bit flipped at a drawn offset.
///
/// This diverges from netem deliberately. netem draws the corruption offset
/// and the bit from the kernel CSPRNG, so netem's corruption is not
/// reproducible even when the rest of the qdisc is seeded — the same seed
/// gives a different bit. Here both integers come from this crate's own
/// generator and both are written into the decision log, so a corrupted
/// datagram can be reproduced exactly and the rejection it causes can be
/// pointed at a specific bit of a specific packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case", deny_unknown_fields))]
pub struct CorruptModel {
    /// Corruption probability.
    #[cfg_attr(feature = "serde", serde(rename = "p-ppb"))]
    pub p: Prob,
}

/// A token bucket with a bounded byte queue in front of it.
///
/// Each of the three fields has a degenerate value that would make the model
/// drop 100% of traffic while blaming the queue, and all three are refused at
/// construction rather than mis-reported at run time. They are refused
/// together because they are one failure wearing three hats: a bucket
/// configuration that cannot be honoured, reported as something it is not. A
/// profile that means "drop everything" says so with a [`LossModel`], where
/// the drop is attributed honestly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case", deny_unknown_fields))]
pub struct RateModel {
    /// Sustained rate, in bits per second. `0` is
    /// [`ProfileError::RateWithZeroBps`]: at zero the bucket never accumulates
    /// a token, so every datagram is ungrantable forever and the profile drops
    /// everything while reporting a full queue that is in fact empty.
    pub bps: u64,
    /// Bucket depth in ON-WIRE bytes. A depth below one on-wire datagram is
    /// [`ProfileError::RateBurstBelowDatagram`], because the bucket can then
    /// never hold enough tokens for a single full-size packet no matter how
    /// long it waits: a 1000-byte burst against 1400-byte datagrams drops all
    /// of them at any rate, and blames an empty queue for it.
    pub burst_bytes: u64,
    /// Tail-drop threshold, in ON-WIRE bytes. A datagram arriving when the
    /// queue already holds this many bytes is dropped — and it is dropped with
    /// a *different* recorded cause from a loss-model drop
    /// ([`crate::engine::DropCause`]). Keeping those two causes apart is the
    /// whole reason to have a rate model rather than another probability, so
    /// this is the only path that may report a full queue: an ungrantable
    /// datagram is a configuration error, not a disposal question.
    ///
    /// `0` is [`ProfileError::RateWithZeroQueue`]: a zero threshold makes the
    /// arrival test true for every datagram, so the queue-full cause is
    /// reported for 100% of traffic with a recorded backlog of zero bytes —
    /// the same mis-attribution, reached through this field instead of through
    /// the bucket.
    pub queue_bytes: u64,
}

/// Half-open `[at_ns, at_ns + for_ns)`, in ticks since arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case", deny_unknown_fields))]
pub struct Window {
    /// Start tick, nanoseconds since arm.
    pub at_ns: u64,
    /// Length, nanoseconds. `0` is [`ProfileError::BlackoutZeroLength`].
    pub for_ns: u64,
}

/// One delay sample, in nanoseconds, from a model.
///
/// The only place the three pieces of the delay path are put together — the
/// generator supplies a raw word, [`crandom`] folds it into the correlation
/// state, and [`tabledist`] turns the result into nanoseconds through the
/// model's table. It is public API for that reason: a test re-composing those
/// three itself would pass against any implementation that composed them the
/// same wrong way.
///
/// # What each model costs the stream
///
/// [`DelayModel::Fixed`] draws nothing and does not touch `corr`; spending a
/// word on it would shift every later sample of the stream, so arming a fixed
/// delay would change the jitter of a model that is not fixed. Every other
/// variant consumes exactly one word, whatever `rho` is.
///
/// # `rho` is applied even when it is zero
///
/// At `rho == 0` [`crandom`]'s arithmetic is `(draw * 256 + last * 0) / 256`,
/// which is `draw` exactly, so calling it unconditionally leaves the
/// uncorrelated stream unaffected while still advancing the correlation state —
/// so a timeline step raising `rho` from zero starts from the preceding sample
/// rather than a stale word. An `if rho != 0` shortcut would make the two paths
/// differ in state, not just in value.
///
/// # Bounds
///
/// `mean_ns` and `sigma_ns` are `u64` and the sample is an `i64`, since a
/// distribution is signed around its mean; a mean past `i64::MAX` nanoseconds
/// saturates rather than wrapping into a negative delay. The sample itself may
/// legitimately be negative — half of a symmetric distribution is — and the
/// caller decides what that means by clamping the release tick, not the sample.
pub fn sample_delay(rng: &mut Pcg32, corr: &mut CorrState, model: &DelayModel) -> i64 {
    match *model {
        DelayModel::Fixed { mean_ns } => saturating_ns(mean_ns),
        DelayModel::Uniform { mean_ns, jitter_ns, rho } => {
            let rnd = crandom(corr, rho, rng.next_u32());
            tabledist(saturating_ns(mean_ns), saturating_ns(jitter_ns), rnd, None)
        }
        DelayModel::Normal { mean_ns, sigma_ns, rho } => {
            let rnd = crandom(corr, rho, rng.next_u32());
            tabledist(saturating_ns(mean_ns), saturating_ns(sigma_ns), rnd, Some(NORMAL))
        }
        DelayModel::Pareto { mean_ns, sigma_ns, rho } => {
            let rnd = crandom(corr, rho, rng.next_u32());
            tabledist(saturating_ns(mean_ns), saturating_ns(sigma_ns), rnd, Some(PARETO))
        }
        DelayModel::ParetoNormal { mean_ns, sigma_ns, rho } => {
            let rnd = crandom(corr, rho, rng.next_u32());
            tabledist(saturating_ns(mean_ns), saturating_ns(sigma_ns), rnd, Some(PARETONORMAL))
        }
    }
}

/// `u64` nanoseconds as `i64`, clamping at the top instead of wrapping.
///
/// `mean_ns as i64` on a value above `i64::MAX` yields a *negative* delay: an
/// absurd configuration would then release datagrams before they arrived,
/// silently, which is a worse answer than "292 years, capped".
const fn saturating_ns(ns: u64) -> i64 {
    if ns > i64::MAX as u64 {
        i64::MAX
    } else {
        ns as i64
    }
}

/// Gates for [`Prob`].
///
/// Separate from the sampler's module for the reason stated there: one
/// `mod tests` per file is a merge hazard when two people are writing the same
/// file, and these tests share no fixture with those.
///
/// The fallible constructor is gated from `tests/`, not from here. Its name
/// and its parameter type both spell the float type, and this crate's
/// no-runtime-float audit is an exact allow-list of the lines under `src/`
/// that may do so — three of them, none of which is a test. Keeping the
/// constructor's gate in the integration suite keeps that audit exact, and
/// costs nothing: the constructor is public.
#[cfg(test)]
mod probability_tests {
    use super::*;

    /// The endpoints of the probability range are exact, and they are checked
    /// at the *worst* draw rather than at a convenient one.
    ///
    /// `u32::MAX` is the row that matters. It is the single draw a 32-bit
    /// numerator with a strict `<` cannot cover, and it is the whole of the
    /// 2^-32 per-datagram hole: with a `u32` representation a profile
    /// configured to drop everything delivers roughly one datagram in 4.3
    /// billion, and no test sampling fewer than that would ever see it. The
    /// two `draw = 0` rows are not enough on their own, and are here only so
    /// the endpoint claim is stated at both ends.
    #[test]
    fn probability_zero_and_one_are_exactly_representable() {
        let never = Prob::from_ppb(0);
        assert!(!never.hits(0), "p = 0 must not hit the smallest draw");
        assert!(!never.hits(u32::MAX), "p = 0 must not hit the largest draw");

        let always = Prob::from_ppb(PPB_ONE);
        assert!(always.hits(0), "p = 1 must hit the smallest draw");
        assert!(always.hits(u32::MAX), "p = 1 must hit the largest draw");
    }

    /// `from_ppb` is exact at a half, saturates above a billion, and never
    /// decreases.
    ///
    /// The half is asserted as the two draws either side of 2^31 rather than
    /// as a frequency over samples, because the boundary is a far stronger
    /// claim: it pins the numerator to `2_147_483_648` and to nothing else. An
    /// implementation that truncated instead of rounding, or that scaled by
    /// `u32::MAX` instead of by 2^32, lands on a different boundary — and the
    /// difference would otherwise surface as a drop rate wrong in the ninth
    /// decimal place, which no run would ever notice.
    #[test]
    fn probability_from_ppb_is_exact_at_a_half_and_saturates() {
        let half = Prob::from_ppb(PPB_ONE / 2);
        assert!(half.hits(2_147_483_647), "the draw below the midpoint hits");
        assert!(!half.hits(2_147_483_648), "the midpoint itself does not");

        assert_eq!(Prob::from_ppb(u32::MAX), Prob::from_ppb(PPB_ONE), "above a billion saturates");
        assert_eq!(Prob::from_ppb(PPB_ONE + 1), Prob::from_ppb(PPB_ONE));

        let mut previous = Prob::from_ppb(0);
        for ppb in (0..=PPB_ONE).step_by((PPB_ONE / 64) as usize) {
            let current = Prob::from_ppb(ppb);
            assert!(current >= previous, "from_ppb must not decrease; broke at {ppb} ppb");
            previous = current;
        }
    }

    /// A probability strictly between the endpoints hits a draw below it and
    /// misses a draw above it, at four widely separated points.
    ///
    /// Without this, `hits` returning `self.0 != 0` would satisfy both tests
    /// above: it is `false` at p = 0 and `true` at p = 1 for every draw. The
    /// four rows here are what make `hits` a comparison rather than a
    /// non-zero check.
    #[test]
    fn a_partial_probability_separates_the_draws_either_side_of_it() {
        for ppb in [1_000, 1_000_000, 250_000_000, 999_999_999_u32] {
            let p = Prob::from_ppb(ppb);
            let boundary = u32::try_from(p.0).expect("a partial probability fits in 32 bits");
            assert!(p.hits(boundary - 1), "{ppb} ppb must hit the draw below its boundary");
            assert!(!p.hits(boundary), "{ppb} ppb must not hit its own boundary");
        }
    }

    /// Every value the written form can express survives a trip out and back,
    /// and a value above certainty is refused rather than saturated.
    ///
    /// The round trip is asserted across the whole range rather than at a few
    /// convenient points, because the two conversions round in opposite
    /// directions and the question is whether their errors can ever add up to
    /// a whole step. `from_ppb`'s numerator moves by about 4.29 per part per
    /// billion, so each rounding is worth at most about 0.117 of a `ppb` — but
    /// that is an argument, and this is the check.
    ///
    /// The endpoint rows are the ones that would go first: certainty is the
    /// only input `from_ppb` saturates at, and it is one step below the first
    /// value `TryFrom` refuses.
    ///
    /// This does not exercise a data format. Doing that needs a serializer,
    /// a serializer is a dev-dependency, and a dev-dependency is compiled by
    /// every `cargo test` here — including the featureless one whose whole
    /// point is that it has none.
    #[cfg(feature = "serde")]
    #[test]
    fn a_written_probability_round_trips_and_refuses_a_value_above_certainty() {
        let round_trip = |ppb: u32| ProbPpb::from(Prob::from_ppb(ppb)).0;
        for ppb in [0, 1, 2, 1_000, 999_999, 500_000_000, 999_999_998, 999_999_999, PPB_ONE] {
            assert_eq!(round_trip(ppb), ppb, "{ppb} ppb did not survive the round trip");
        }
        for ppb in (0..=PPB_ONE).step_by((PPB_ONE / 4096) as usize) {
            assert_eq!(round_trip(ppb), ppb, "{ppb} ppb did not survive the round trip");
        }

        assert_eq!(
            Prob::try_from(ProbPpb(PPB_ONE)),
            Ok(Prob::from_ppb(PPB_ONE)),
            "certainty is in"
        );
        assert_eq!(
            Prob::try_from(ProbPpb(PPB_ONE + 1)),
            Err(ProbPpbOutOfRange { ppb: PPB_ONE + 1 }),
            "one past certainty is refused, and the refusal names the value"
        );
        assert_eq!(
            ProbPpbOutOfRange { ppb: 2_000_000_000 }.to_string(),
            "probability 2000000000 ppb is above 1000000000, which is certainty"
        );
    }
}

/// Gates for [`sample_delay`].
///
/// Named `sampler_tests` rather than `tests` because the models above it are
/// tested in their own module; one `mod tests` per file is a merge hazard when
/// two people are writing the same file, and nothing else here needs the name.
#[cfg(test)]
mod sampler_tests {
    use super::*;
    use crate::consts::RELEASE_FLOOR_NS;
    use crate::rng::STREAM_DOWNLINK_DELAY;

    /// A 20 ms mean with 5 ms of jitter: the uniform arm's interval is
    /// `[15 ms, 25 ms)`, which is wide enough that a wrong `% (2 * sigma)`
    /// shows up in the first sample rather than in the thousandth.
    const MEAN_NS: u64 = 20_000_000;
    const JITTER_NS: u64 = 5_000_000;
    const SEED: u64 = 42;

    fn uniform(rho: u8) -> DelayModel {
        DelayModel::Uniform { mean_ns: MEAN_NS, jitter_ns: JITTER_NS, rho }
    }

    fn sample_n(n: usize, rho: u8) -> Vec<i64> {
        let mut rng = Pcg32::seeded(SEED, STREAM_DOWNLINK_DELAY);
        let mut corr = CorrState::default();
        let model = uniform(rho);
        (0..n).map(|_| sample_delay(&mut rng, &mut corr, &model)).collect()
    }

    /// The uncorrelated vector, pinned as exact nanoseconds.
    ///
    /// The uniform arm is chosen for the pinned vector because its arithmetic
    /// is fully specified as integers — `((rnd % (2 * sigma)) + mu) - sigma` —
    /// so every expected value below is derivable by hand from a generator
    /// word, and the generator words are themselves anchored to a published
    /// reference vector. The table-driven arms cannot be pinned that way
    /// without quoting 4096 committed integers into this file, and pinning them
    /// by running this implementation and recording what came out would assert
    /// only that the code does what the code does.
    ///
    /// The arithmetic for sample 0: the delay stream's first word is
    /// 1 307 692 281; `1307692281 % 10000000 = 7692281`; `+ 20000000 -
    /// 5000000 = 22692281`.
    ///
    /// The last assertion is the one that makes this a test of the composition
    /// rather than of eight numbers: the sampler must consume **exactly one**
    /// generator word per sample, so a generator advanced 1000 times by hand
    /// must end in the identical state. An implementation that drew twice — one
    /// word for the table index and another for a sign, say — would produce a
    /// vector that is wrong from sample 1 onward *and* leave the stream
    /// desynchronised for every model that follows it.
    #[test]
    fn the_delay_sampler_returns_the_pinned_uncorrelated_vector() {
        let got = sample_n(1000, 0);
        let want = [22692281, 15602322, 16967504, 16771729, 17238836, 20024040, 21118430, 23801432];
        for (i, w) in want.iter().enumerate() {
            assert_eq!(got[i], *w, "sample {i}");
        }

        // The interval is half-open at the top: `rnd % 10_000_000` is at most
        // 9 999 999, so 25 ms is never reached and 15 ms is.
        assert!(got.iter().all(|&x| (15_000_000..25_000_000).contains(&x)), "outside the interval");

        let mut reference = Pcg32::seeded(SEED, STREAM_DOWNLINK_DELAY);
        for _ in 0..1000 {
            reference.next_u32();
        }
        let mut used = Pcg32::seeded(SEED, STREAM_DOWNLINK_DELAY);
        let mut corr = CorrState::default();
        for _ in 0..1000 {
            sample_delay(&mut used, &mut corr, &uniform(0));
        }
        assert_eq!(used, reference, "exactly one generator word per sample");
    }

    /// The same seed at `rho = 200` must produce a different vector, and the
    /// first five values are checked against arithmetic worked out by hand
    /// beside them.
    ///
    /// Correlation has no external reference implementation to be compared
    /// against — this crate is bit-compatible with netem for the table
    /// arithmetic and explicitly not for correlation — so the only thing that
    /// can hold it is its own stated integer formula,
    /// `next = (draw * (256 - rho) + last * rho) / 256`, applied here with
    /// `256 - 200 = 56` and a `last` that starts at zero:
    ///
    /// | i | draw | last before | next = (draw·56 + last·200)/256 | sample |
    /// |---|------|-------------|---------------------------------|--------|
    /// | 0 | 1307692281 | 0 | 286057686 | 21057686 |
    /// | 1 | 3850602322 | 286057686 | 1065801825 | 20801825 |
    /// | 2 | 1491967504 | 1065801825 | 1159025567 | 24025567 |
    /// | 3 | 4091771729 | 1159025567 | 1800563789 | 15563789 |
    /// | 4 | 3882238836 | 1800563789 | 2255930205 | 20930205 |
    ///
    /// where each sample is `next % 10_000_000 + 15_000_000`. Note row 3:
    /// `next` is 1 800 563 789 where the raw draw was 4 091 771 729 — the
    /// correlated value is pulled most of the way back toward the previous one,
    /// which is what `rho = 200/256` means and what the sample of 15.56 ms
    /// against an uncorrelated 16.77 ms shows.
    #[test]
    fn the_delay_sampler_correlates_at_a_non_zero_rho() {
        let correlated = sample_n(1000, 200);
        let want = [21057686, 20801825, 24025567, 15563789, 20930205];
        for (i, w) in want.iter().enumerate() {
            assert_eq!(correlated[i], *w, "sample {i}");
        }

        let uncorrelated = sample_n(1000, 0);
        let first_diff = uncorrelated.iter().zip(correlated.iter()).position(|(a, b)| a != b);
        assert_eq!(first_diff, Some(0), "correlation must change the very first sample");

        // Stronger than "they differ somewhere": over 1000 samples the two
        // sequences agree nowhere. A partial implementation that applied
        // `crandom` on some path but not all of them would leave collisions
        // here even though index 0 differed.
        let agreements = uncorrelated.iter().zip(correlated.iter()).filter(|(a, b)| a == b).count();
        assert_eq!(agreements, 0, "no sample may survive correlation unchanged");

        // Correlation must not cost an extra word either.
        let mut reference = Pcg32::seeded(SEED, STREAM_DOWNLINK_DELAY);
        for _ in 0..1000 {
            reference.next_u32();
        }
        let mut used = Pcg32::seeded(SEED, STREAM_DOWNLINK_DELAY);
        let mut corr = CorrState::default();
        for _ in 0..1000 {
            sample_delay(&mut used, &mut corr, &uniform(200));
        }
        assert_eq!(used, reference, "exactly one generator word per correlated sample");
    }

    /// A fixed delay draws nothing and disturbs nothing.
    ///
    /// Asserted as state equality on both the generator and the correlation
    /// state, not as "the value is the mean" — the value is trivially the mean
    /// in any implementation, while the whole point is that arming a fixed
    /// delay must not shift the stream that a *later* model, or a later
    /// timeline step with a real distribution, draws from.
    #[test]
    fn a_fixed_delay_consumes_nothing() {
        let mut rng = Pcg32::seeded(SEED, STREAM_DOWNLINK_DELAY);
        let mut corr = CorrState::default();
        let untouched_rng = rng.clone();
        let untouched_corr = corr;

        let model = DelayModel::Fixed { mean_ns: 12_345_678 };
        for _ in 0..16 {
            assert_eq!(sample_delay(&mut rng, &mut corr, &model), 12_345_678);
        }
        assert_eq!(rng, untouched_rng, "the generator must not advance");
        assert_eq!(corr, untouched_corr, "the correlation state must not advance");

        // A nonsensical mean clamps instead of wrapping negative. `u64::MAX as
        // i64` is -1: a delay model that releases one nanosecond in the past.
        let mut rng = Pcg32::seeded(SEED, STREAM_DOWNLINK_DELAY);
        let mut corr = CorrState::default();
        let huge = DelayModel::Fixed { mean_ns: u64::MAX };
        assert_eq!(sample_delay(&mut rng, &mut corr, &huge), i64::MAX);
    }

    /// CALIBRATION — measures the platform, asserts nothing about it.
    ///
    /// The sampler is exact to the nanosecond; the machine that has to deliver
    /// the sample is not. This reports what a sub-floor delay costs on the host
    /// it runs on, and is `#[ignore]`d because the answer is a property of the
    /// box, its scheduler and its load — an assertion on it would redden
    /// whenever someone else's CI runner is busy.
    ///
    /// The one thing it does assert is deterministic and not a timing claim:
    /// that the requested delays really are below the reported floor, so the
    /// measurement is measuring what its name says.
    ///
    /// Run it with
    /// `cargo test -p quinn-netem --lib -- --ignored --nocapture`.
    #[test]
    #[ignore = "calibration: measures the host's timer floor, asserts nothing about it"]
    fn calibration_a_sub_floor_delay_is_below_what_the_platform_delivers() {
        use std::time::{Duration, Instant};

        const ROUNDS: usize = 200;
        let model = DelayModel::Uniform { mean_ns: 200_000, jitter_ns: 50_000, rho: 0 };
        let mut rng = Pcg32::seeded(SEED, STREAM_DOWNLINK_DELAY);
        let mut corr = CorrState::default();

        let mut requested = Vec::with_capacity(ROUNDS);
        let mut slept = Vec::with_capacity(ROUNDS);
        for _ in 0..ROUNDS {
            let ns = sample_delay(&mut rng, &mut corr, &model);
            assert!(ns > 0, "the calibration model must not sample a negative delay");
            assert!(
                (ns as u64) < RELEASE_FLOOR_NS,
                "the calibration model must request less than the reported floor"
            );
            let start = Instant::now();
            std::thread::sleep(Duration::from_nanos(ns as u64));
            slept.push(start.elapsed().as_nanos() as u64);
            requested.push(ns as u64);
        }
        requested.sort_unstable();
        slept.sort_unstable();
        println!(
            "requested p50 {} ns, slept p50 {} ns, slept min {} ns, reported floor {} ns",
            requested[ROUNDS / 2],
            slept[ROUNDS / 2],
            slept[0],
            RELEASE_FLOOR_NS
        );
    }
}

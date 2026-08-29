//! The generator, and the twelve frozen PRNG stream ids.
//!
//! **Stream separation is frozen.** Each `(`[`crate::Direction`]`, model)` pair
//! draws from its own [`Pcg32`], seeded `Pcg32::seeded(profile.seed, stream_id)`.
//! Enabling the duplication model must not shift the loss decisions, because
//! that is what makes an **ablation** readable: disable one model and the diff
//! in the decision log names exactly one model. A single shared stream makes
//! every ablation a whole-log rewrite and makes the fixture useless as a
//! diagnostic.
/// PCG32 XSH-RR 64/32, transcribed from `pcg_basic.c`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pcg32 {
    state: u64,
    inc: u64,
}

impl Pcg32 {
    /// `pcg32_srandom_r(&rng, initstate, initseq)`, including both priming
    /// steps.
    ///
    /// The priming is not decoration. Without it the all-zero seed leaves
    /// `state = 0, inc = 1`, and the first two outputs are `0x00000000` —
    /// a generator that emits zero twice and looks armed.
    /// `rng_zero_seed_does_not_emit_zero` pins that.
    pub fn seeded(initstate: u64, initseq: u64) -> Self {
        let mut rng = Pcg32 { state: 0, inc: (initseq << 1) | 1 };
        rng.next_u32();
        rng.state = rng.state.wrapping_add(initstate);
        rng.next_u32();
        rng
    }

    /// One 32-bit output, advancing the state.
    pub fn next_u32(&mut self) -> u32 {
        let old = self.state;
        self.state = old.wrapping_mul(MULTIPLIER).wrapping_add(self.inc);
        let xorshifted = (((old >> 18) ^ old) >> 27) as u32;
        let rot = (old >> 59) as u32;
        xorshifted.rotate_right(rot)
    }

    /// `pcg32_boundedrand_r`: threshold `(-bound) % bound`, reject-below, then
    /// `r % bound`. Consumes one or more outputs. `bound == 0` panics.
    ///
    /// The rejection loop is what removes modulo bias. Note how rarely it
    /// fires for a small bound: at `bound = 6` the threshold is `4`, so a
    /// draw is rejected with probability `4 / 2^32` and a naive
    /// `next_u32() % bound` is indistinguishable over any test-sized sample.
    /// That is why `rng_bounded_rejects_below_the_threshold` uses a bound
    /// near `u32::MAX / 2`: at dice-sized bounds the two implementations are
    /// indistinguishable, so a test there would pass against the very bug it
    /// exists to forbid.
    pub fn next_bounded(&mut self, bound: u32) -> u32 {
        assert!(bound != 0, "next_bounded(0) has no value to return");
        let threshold = bound.wrapping_neg() % bound;
        loop {
            let r = self.next_u32();
            if r >= threshold {
                return r % bound;
            }
        }
    }
}

/// The LCG multiplier from `pcg_basic.c`. Part of the frozen value stream:
/// changing it changes every decision this crate has ever recorded.
const MULTIPLIER: u64 = 6_364_136_223_846_793_005;

// ── PRNG stream ids — part of the decision-log format ───────────────────
//
// `Pcg32::seeded(initstate, initseq)` takes `u64`, so these are `u64`.
//
// Downlink ids are 0..=5; the uplink id of a model is its downlink id + 8.
// The gap at 6..=7 is deliberate and is part of the freeze: it leaves room
// for two more downlink models before the uplink block would have to move,
// and moving the uplink block is a decision-log FORMAT change.

/// Downlink loss stream.
pub const STREAM_DOWNLINK_LOSS: u64 = 0;
/// Downlink delay stream.
pub const STREAM_DOWNLINK_DELAY: u64 = 1;
/// Downlink reorder stream.
pub const STREAM_DOWNLINK_REORDER: u64 = 2;
/// Downlink duplication stream.
pub const STREAM_DOWNLINK_DUP: u64 = 3;
/// Downlink corruption stream.
pub const STREAM_DOWNLINK_CORRUPT: u64 = 4;
/// Downlink rate/queue stream.
pub const STREAM_DOWNLINK_RATE_QUEUE: u64 = 5;
/// Uplink loss stream — downlink + 8.
pub const STREAM_UPLINK_LOSS: u64 = 8;
/// Uplink delay stream — downlink + 8.
pub const STREAM_UPLINK_DELAY: u64 = 9;
/// Uplink reorder stream — downlink + 8.
pub const STREAM_UPLINK_REORDER: u64 = 10;
/// Uplink duplication stream — downlink + 8.
pub const STREAM_UPLINK_DUP: u64 = 11;
/// Uplink corruption stream — downlink + 8.
pub const STREAM_UPLINK_CORRUPT: u64 = 12;
/// Uplink rate/queue stream — downlink + 8.
pub const STREAM_UPLINK_RATE_QUEUE: u64 = 13;

/// All twelve stream ids, downlink block then uplink block, in model order.
///
/// A constant rather than a hand-written list in the test, so that a test
/// asserting the ids cannot drift from the ids the engine actually draws on.
pub const ALL_STREAM_IDS: [u64; 12] = [
    STREAM_DOWNLINK_LOSS,
    STREAM_DOWNLINK_DELAY,
    STREAM_DOWNLINK_REORDER,
    STREAM_DOWNLINK_DUP,
    STREAM_DOWNLINK_CORRUPT,
    STREAM_DOWNLINK_RATE_QUEUE,
    STREAM_UPLINK_LOSS,
    STREAM_UPLINK_DELAY,
    STREAM_UPLINK_REORDER,
    STREAM_UPLINK_DUP,
    STREAM_UPLINK_CORRUPT,
    STREAM_UPLINK_RATE_QUEUE,
];

#[cfg(test)]
mod tests {
    use super::*;

    /// The only vector here with an outside publisher: round 1 of the
    /// `pcg_basic` demo from pcg-random.org. Every other expected value in
    /// this module is anchored to it, because a value this crate produced and
    /// then asserted on would test nothing but its own consistency.
    #[test]
    fn rng_matches_the_published_reference_vector() {
        let mut rng = Pcg32::seeded(42, 54);
        let got: Vec<u32> = (0..8).map(|_| rng.next_u32()).collect();
        let want = [
            0xa15c_02b7,
            0x7b47_f409,
            0xba1d_3330,
            0x83d2_f293,
            0xbfa4_784b,
            0xcbed_606e,
            0xbfc6_a3ad,
            0x812f_ff6d_u32,
        ];
        for (i, (g, w)) in got.iter().zip(want.iter()).enumerate() {
            assert_eq!(g, w, "word {i}");
        }
    }

    /// A bound of six would make this test worthless. The rejection
    /// threshold is `(-bound) % bound`, so at `bound = 6` it is `4` and a
    /// draw is discarded with probability `4 / 2^32`: over any test-sized
    /// sample the rejection loop never runs, and a naive `next_u32() % bound`
    /// produces byte-identical output. Measured over 40 draws at each of
    /// bounds 3, 5, 6, 7, 10 and 100 — correct and naive agreed everywhere
    /// and the loop fired zero times.
    ///
    /// So the bound is one where rejection actually happens: at
    /// `3_000_000_000` the threshold is `1_294_967_296`, discarding 30.2% of
    /// draws, and the two implementations desynchronise at index 10.
    /// Asserting the divergence index is what makes this a test of the
    /// rejection loop rather than of a table of numbers.
    ///
    /// The expected values come from a separate implementation written from
    /// the algorithm description, never from this one; it reproduces the
    /// published vector above, which is what makes it trustworthy here.
    #[test]
    fn rng_bounded_rejects_below_the_threshold() {
        const BOUND: u32 = 3_000_000_000;
        assert_eq!(BOUND.wrapping_neg() % BOUND, 1_294_967_296, "threshold");

        let mut rng = Pcg32::seeded(42, 54);
        let got: Vec<u32> = (0..12).map(|_| rng.next_bounded(BOUND)).collect();
        let want = [
            2_707_161_783,
            2_068_313_097,
            122_475_824,
            2_211_639_955,
            215_226_955,
            421_331_566,
            217_466_285,
            2_167_406_445,
            860_803_674,
            1_181_216_144,
            984_091_174,
            2_721_289_578_u32,
        ];
        for (i, (g, w)) in got.iter().zip(want.iter()).enumerate() {
            assert_eq!(g, w, "draw {i}");
        }

        // The naive stream agrees for ten draws and then does not. Asserting
        // the divergence INDEX is what makes this a test of the rejection
        // loop rather than of the value table.
        let mut naive = Pcg32::seeded(42, 54);
        let naive_seq: Vec<u32> = (0..12).map(|_| naive.next_u32() % BOUND).collect();
        let first_diff = got.iter().zip(naive_seq.iter()).position(|(a, b)| a != b);
        assert_eq!(first_diff, Some(10), "naive `% bound` must desynchronise at 10");
    }

    /// The first output of the all-zero seed must be non-zero *and* must be
    /// this specific word. The inequality on its own is satisfied by any
    /// non-zero constant, which is exactly what a broken `seeded` that
    /// skipped priming would eventually be patched into.
    #[test]
    fn rng_zero_seed_does_not_emit_zero() {
        let mut rng = Pcg32::seeded(0, 0);
        let first = rng.next_u32();
        assert_ne!(first, 0, "the degenerate all-zero seed must not emit zero");
        assert_eq!(first, 0xe4c1_4788, "first output");
        assert_eq!(rng.next_u32(), 0x379c_6516, "second output");
    }

    /// A model drawing from the wrong stream changes the decision-log
    /// format, so the ids are pinned here as well as at their declaration.
    #[test]
    fn the_twelve_stream_ids_are_frozen() {
        assert_eq!(ALL_STREAM_IDS, [0, 1, 2, 3, 4, 5, 8, 9, 10, 11, 12, 13]);
        for (i, id) in ALL_STREAM_IDS.iter().enumerate().take(6) {
            assert_eq!(ALL_STREAM_IDS[i + 6], id + 8, "uplink is downlink + 8");
        }
    }

    /// Distinct streams from one seed must not be the same sequence. Every
    /// ablation's readability rests on it: if two models shared a stream,
    /// disabling one would rewrite the other's decisions too, and the diff
    /// would name nothing.
    #[test]
    fn distinct_streams_from_one_seed_differ() {
        let mut a = Pcg32::seeded(7, STREAM_DOWNLINK_LOSS);
        let mut b = Pcg32::seeded(7, STREAM_DOWNLINK_DELAY);
        let sa: Vec<u32> = (0..16).map(|_| a.next_u32()).collect();
        let sb: Vec<u32> = (0..16).map(|_| b.next_u32()).collect();
        assert_ne!(sa, sb, "loss and delay must not share a stream");
    }
}

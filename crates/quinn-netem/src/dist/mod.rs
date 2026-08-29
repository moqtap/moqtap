//! Delay distributions: committed integer tables, and integer lookup.
//!
//! # Why there is not a float in here
//!
//! Sampling a delay from a normal or pareto distribution wants `erf`, `exp` and
//! a cube root, all of which std permits to differ across platforms, compiler
//! versions, and even between two calls in one process. One last-bit difference
//! in a jitter sample makes two runs of a seed disagree.
//!
//! So the floating-point work happens once, offline, in
//! `examples/gen_tables.rs`, and what is committed is its output: three arrays
//! of `i16` in `tables.rs`. At run time this module does an array index, a
//! multiply, an add and a divide, all in `i64`. The generator is an example
//! rather than a module because no float may appear under `src/`, and an
//! example is not compiled into the library.
//!
//! The tables are computed from the published definitions of the distributions
//! rather than copied, so they can be re-derived and diffed on demand.
//! `calibration_regenerate_the_distribution_tables_and_diff` does that, and is
//! `#[ignore]`d to keep the generator's floating point off the everyday path.
//!
//! # The representation
//!
//! Each table is 4096 scaled quantiles of a zero-centred distribution, at a
//! fixed point scale of 8192 — so an entry of 8192 means one standard
//! deviation, and an entry of `-30482` (the smallest entry of the normal
//! table) means −3.72σ. Table length and scale are the same ones the Linux
//! kernel's traffic-control network emulator uses, which is what makes a delay
//! profile written for that emulator mean the same thing here.
//!
//! [`tabledist`] is that emulator's sampling step, in integers: index the
//! table with the draw, scale by σ with the multiply split across the fixed
//! point so nothing overflows, round half away from zero, add μ.
//! [`crandom`] is the correlation filter, stated in this crate's own terms —
//! the sampling step is a claim of bit-for-bit agreement with the kernel, the
//! correlation filter deliberately is not.

mod tables;

#[cfg(test)]
mod sha256;

/// Fixed-point scale of a table entry: an entry of `TABLE_SCALE` is one
/// standard deviation.
pub const TABLE_SCALE: i64 = 8192;

/// Entries in a distribution table. A draw is reduced modulo this, so it must
/// stay a power of two for the reduction to be free of modulo bias.
pub const TABLE_LEN: usize = 4096;

/// A scaled inverse-CDF table: 4096 quantiles of a zero-centred distribution,
/// each multiplied by [`TABLE_SCALE`] and rounded to an `i16`.
///
/// Entries are non-decreasing, which is what makes indexing the table with a
/// uniform draw sample the distribution the table came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DistTable(
    /// The entries, smallest first.
    pub &'static [i16; TABLE_LEN],
);

/// The normal distribution: the scaled inverse of
/// `Φ(x) = 0.5 + 0.5·erf(x/√2)`, truncated at ±3.72σ, which is where 4096
/// equal-probability cells put the outermost one.
///
/// Exactly antisymmetric — `NORMAL[i] == -NORMAL[4095 - i]` for every `i` —
/// so a jitter model built on it adds no mean offset of its own. Its entries
/// sum to exactly zero, and a "centred" table whose entries did not would be a
/// delay model that silently shifts the mean while claiming only to spread it.
pub const NORMAL: DistTable = DistTable(&tables::NORMAL_TABLE);

/// The pareto distribution, shape `a = 3`.
///
/// Long-tailed and **not** symmetric: its median entry is `-2622` and its
/// entries sum to `-1_109_860`, because the distribution is centred on zero
/// *mean* and then its top ~1% is clipped at the `i16` ceiling. Neither of
/// those is a defect; a symmetric long-tailed distribution would not be a
/// pareto.
pub const PARETO: DistTable = DistTable(&tables::PARETO_TABLE);

/// `(normal + 3·pareto)/4`, entry by entry — a mostly-normal body with a
/// pareto tail, which is the shape real network jitter tends to have.
///
/// Computed from the two committed integer tables rather than from floating
/// point, so `paretonormal_is_the_integer_blend_of_the_other_two` can assert
/// the blend as an exact identity across all three arrays instead of trusting
/// three independent piles of numbers to agree.
pub const PARETONORMAL: DistTable = DistTable(&tables::PARETONORMAL_TABLE);

/// One delay sample: `mu_ns` displaced by `sigma_ns` worth of `dist`, selected
/// by the uniform draw `rnd`. Integer arithmetic throughout.
///
/// `dist` of `None` is the uniform arm — `rnd` folded into `[μ−σ, μ+σ)` — and
/// is not merely a degenerate table. It is the shape a caller gets by asking
/// for jitter without naming a distribution, and it is one modulo rather than
/// a table lookup.
///
/// With a table, the σ multiply is split across the fixed point:
/// `(σ mod 8192)·t` is rounded half away from zero at the 8192 scale, and
/// `(σ div 8192)·t` is added at full scale. Splitting it is what keeps a
/// multi-second σ from overflowing while a σ of a few hundred nanoseconds
/// still rounds correctly rather than truncating to zero.
///
/// The half-away rounding — the `±4096` before the divide — is not cosmetic,
/// and the way it fails is worth knowing. Without it every sample truncates
/// **toward zero**, which shortens the sample rather than shifting it: over one
/// sweep of the normal table at σ = 1000 ns, 2084 of the 4096 samples come back
/// one nanosecond nearer μ and the total spread falls from 3 268 122 ns to
/// 3 266 038 ns. The *mean* is untouched, because truncation toward zero is an
/// odd function and the table is antisymmetric — so a test that only checked
/// the mean, or only the sum, would see nothing at all. The jitter would simply
/// be quietly narrower than the profile asked for.
///
/// A `sigma_ns` of zero returns `mu_ns`. That case is reached by a profile
/// that asks for a fixed delay with no jitter, and it is handled here rather
/// than left to the caller because both arms divide by σ.
pub fn tabledist(mu_ns: i64, sigma_ns: i64, rnd: u32, dist: Option<DistTable>) -> i64 {
    debug_assert!(sigma_ns >= 0, "sigma is a spread, so it is never negative");
    if sigma_ns <= 0 {
        return mu_ns;
    }

    let Some(table) = dist else {
        // Identical to the kernel's `u32` form of this expression for every
        // σ below 2^31 ns (2.1 s); above that the kernel's would wrap and
        // this widens instead, which is the sane extension rather than a
        // reproduction of an overflow.
        let span = sigma_ns.saturating_mul(2);
        return (i64::from(rnd) % span).saturating_add(mu_ns).saturating_sub(sigma_ns);
    };

    let t = i64::from(table.0[(rnd % (TABLE_LEN as u32)) as usize]);
    let mut x = (sigma_ns % TABLE_SCALE) * t;
    x += if x >= 0 { TABLE_SCALE / 2 } else { -(TABLE_SCALE / 2) };
    (x / TABLE_SCALE)
        .saturating_add((sigma_ns / TABLE_SCALE).saturating_mul(t))
        .saturating_add(mu_ns)
}

/// The state of one correlation filter: the previous filtered draw.
///
/// One of these per correlated model per direction. `Default` starts it at
/// zero, which is the same starting point every run gets — a filter seeded
/// from anything else would make the first few samples of a run depend on
/// history the fixture does not record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CorrState {
    last: u32,
}

/// One correlated draw: `next = (draw·(256 − rho) + last·rho) / 256`,
/// computed in `u64` and truncated back to `u32`, with `next` becoming the new
/// `last`.
///
/// `rho` is `0..=255`. At `rho = 0` this is the identity and the caller gets
/// the raw draw; at `rho = 255` the state moves by 1/256 of the gap per draw,
/// so consecutive samples are nearly the same and the delay wanders instead of
/// jumping. The result always lies between `last` and `draw` inclusive, which
/// is the invariant an overflowing or sign-confused implementation breaks.
///
/// This is a first-order filter over the *draw*, so it correlates the uniform
/// input to [`tabledist`] rather than its output; that is what makes the
/// correlation independent of which distribution is selected. It is written
/// here from that description, and this crate makes no claim that it agrees
/// bit-for-bit with any other implementation of correlation — unlike
/// [`tabledist`], where agreement is the point.
pub fn crandom(state: &mut CorrState, rho: u8, draw: u32) -> u32 {
    let rho = u64::from(rho);
    let blended = (u64::from(draw) * (256 - rho) + u64::from(state.last) * rho) / 256;
    // The dividend is below 2^40 and the quotient below 2^32, so the narrowing
    // is exact rather than a wrap.
    let next = blended as u32;
    state.last = next;
    next
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three tables, so a property can be asserted about each by name.
    const ALL: [(&str, DistTable); 3] =
        [("normal", NORMAL), ("pareto", PARETO), ("paretonormal", PARETONORMAL)];

    /// The bytes the committed digest covers: every entry of all three
    /// tables, in declaration order, little-endian.
    fn payload() -> Vec<u8> {
        let mut out = Vec::with_capacity(3 * TABLE_LEN * 2);
        for (_, table) in ALL {
            for v in table.0 {
                out.extend_from_slice(&v.to_le_bytes());
            }
        }
        out
    }

    /// The digest written into `tables.rs`'s header comment.
    ///
    /// Read out of the source text rather than out of a constant, so there is
    /// one copy of the number and the comment is the thing under test. A pin
    /// that lives in a constant next to a comment claiming the same value
    /// drifts silently the first time somebody updates one of them.
    fn committed_digest() -> String {
        const MARKER: &str = "// payload sha256 = ";
        include_str!("tables.rs")
            .lines()
            .find_map(|l| l.strip_prefix(MARKER))
            .expect("tables.rs carries a `payload sha256` header line")
            .trim()
            .to_string()
    }

    /// Anchors the digest routine to somebody else's arithmetic.
    ///
    /// The same `sha256` is used to stamp the pin into `tables.rs` and to
    /// check it here, so on its own the pin proves only that the routine
    /// agrees with itself: a digest that returned its input length, or the
    /// state with two words swapped, would be perfectly self-consistent and
    /// would hold nothing. These three are the published FIPS 180-4 vectors,
    /// produced by nothing in this repository.
    #[test]
    fn sha256_matches_the_published_vectors() {
        let cases: [(&[u8], &str); 3] = [
            (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
        ];
        for (input, want) in cases {
            assert_eq!(sha256::hex(&sha256::sha256(input)), want, "input {input:?}");
        }
    }

    /// The committed integers are the ones the generator produced.
    ///
    /// This is the only check that pins all 12288 entries to specific values.
    /// The property tests below constrain shape — monotone, centred, blended —
    /// and a table can keep every bit of that shape while a hand edit moves one
    /// entry by a millisecond's worth of jitter.
    ///
    /// What it does *not* catch is a wrong generator: regenerate the file and
    /// the header comment is restamped to match whatever came out. That is
    /// what the shape tests below are for, and it is why the blend is asserted
    /// as an identity rather than trusted to the pin.
    #[test]
    fn distribution_tables_match_their_committed_hash() {
        assert_eq!(payload().len(), 3 * TABLE_LEN * 2, "payload size");
        assert_eq!(sha256::hex(&sha256::sha256(&payload())), committed_digest());
    }

    /// Shape, in integers only: monotone everywhere, and for the normal table
    /// exactly antisymmetric and exactly centred.
    ///
    /// An all-zero table would make every delay sample come back as μ — a
    /// jitter model configured and not delivered — and it is **monotone, is
    /// exactly antisymmetric, has a zero median and sums to exactly zero**.
    /// Every well-orderedness and centring clause here passes against it. So
    /// those clauses on their own would be worth nothing, and what carries
    /// this test is the pinned entries and the σ-band counts: measured, the
    /// first assertion an all-zero table reddens is the central pair.
    ///
    /// The 1σ/2σ/3σ counts are the independent anchor. 68.27%, 95.45% and
    /// 99.73% of a normal distribution lie inside one, two and three standard
    /// deviations, which for 4096 entries is 2796.30, 3909.63 and 4084.94;
    /// the table gives 2796, 3910 and 4084. Those three proportions come from
    /// the distribution and not from this repository, and no monotone
    /// antisymmetric table that is not a normal inverse-CDF reproduces them.
    #[test]
    fn distribution_tables_are_monotone_and_symmetric() {
        for (name, table) in ALL {
            for i in 1..TABLE_LEN {
                assert!(
                    table.0[i - 1] <= table.0[i],
                    "{name} is not monotone at {i}: entry {} follows entry {}",
                    table.0[i],
                    table.0[i - 1],
                );
            }
        }

        let normal = NORMAL.0;
        for i in 0..TABLE_LEN {
            assert_eq!(normal[i], -normal[TABLE_LEN - 1 - i], "normal is antisymmetric at {i}");
        }
        // A table built by rounding a quantile function is only obliged to be
        // centred to within one scaled unit per entry, so `|Σ| ≤ TABLE_LEN` is
        // the bound that has to hold for any construction. This one does
        // better by mirroring its own upper half, and the exact zero is
        // asserted too — if the construction ever changes, the loose bound is
        // the one that still has to survive.
        let sum: i64 = normal.iter().map(|v| i64::from(*v)).sum();
        assert!(sum.unsigned_abs() as usize <= TABLE_LEN, "normal sum is within the table length");
        assert_eq!(sum, 0, "normal entries sum to exactly zero");

        // The median of an even-length sorted table is the mean of its two
        // central entries; it is asserted as their sum so the arithmetic stays
        // in integers. The entry *at* index `TABLE_LEN/2` is `+2` and cannot be
        // `0`: 4096 equal-probability cells put the first cell above the median
        // at the 0.50012 quantile, which is 2.5 scaled units out. A table whose
        // central entry were zero would have to be either non-antisymmetric or
        // coarser than this one, and both cost more than they buy.
        let central = i64::from(normal[TABLE_LEN / 2 - 1]) + i64::from(normal[TABLE_LEN / 2]);
        assert!(central.abs() <= 2, "the median is within a scaled unit of zero");
        assert_eq!(central, 0, "the median is exactly zero");
        assert_eq!(
            (normal[TABLE_LEN / 2 - 1], normal[TABLE_LEN / 2]),
            (-2, 2),
            "the two central entries"
        );

        let inside = |k: i16| normal.iter().filter(|v| v.abs() <= k).count();
        assert_eq!(inside(8192), 2796, "normal entries inside 1 sigma");
        assert_eq!(inside(16384), 3910, "normal entries inside 2 sigma");
        assert_eq!(inside(24576), 4084, "normal entries inside 3 sigma");

        assert_eq!((normal[0], normal[TABLE_LEN - 1]), (-30482, 30482), "normal extremes");
        assert_eq!(
            normal.iter().collect::<std::collections::BTreeSet<_>>().len(),
            TABLE_LEN,
            "every normal entry is distinct, so no run of the table is flat"
        );

        // The long-tailed tables are centred on zero *mean*, not on zero
        // median, and their top entries sit on the `i16` ceiling — so the two
        // clauses above are properties of the normal table alone, and are
        // pinned here as the values they actually take rather than quietly
        // not asserted.
        let pareto_sum: i64 = PARETO.0.iter().map(|v| i64::from(*v)).sum();
        let blend_sum: i64 = PARETONORMAL.0.iter().map(|v| i64::from(*v)).sum();
        assert_eq!((PARETO.0[TABLE_LEN / 2], pareto_sum), (-2622, -1_109_860), "pareto centre");
        assert_eq!(
            (PARETONORMAL.0[TABLE_LEN / 2], blend_sum),
            (-1966, -831_923),
            "paretonormal centre"
        );
        assert_eq!((PARETO.0[0], PARETO.0[TABLE_LEN - 1]), (-5461, 32767), "pareto extremes");
        assert_eq!(
            PARETO.0.iter().filter(|v| **v == i16::MAX).count(),
            44,
            "pareto entries clipped at the ceiling"
        );
    }

    /// The blend is exact, entry by entry, in integers.
    ///
    /// Three arrays of four thousand numbers cannot be checked by eye, and a
    /// generator that emitted the paretonormal table from an independent
    /// floating-point pass could disagree with its own inputs by a unit here
    /// and there with nobody noticing. Deriving it from the two committed
    /// tables makes the relationship an identity that either holds everywhere
    /// or fails loudly.
    #[test]
    fn paretonormal_is_the_integer_blend_of_the_other_two() {
        for i in 0..TABLE_LEN {
            let want = (i32::from(NORMAL.0[i]) + 3 * i32::from(PARETO.0[i])) / 4;
            let want = want.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16;
            assert_eq!(PARETONORMAL.0[i], want, "paretonormal at {i}");
        }
    }

    /// The uniform arm is a bijection onto `[μ−σ, μ+σ)`, three sweeps deep.
    ///
    /// "Every sample is inside the window" is satisfied by a function that
    /// returns `μ − σ` forever, so the test asserts the histogram instead:
    /// three sweeps of the draw must hit every one of the `2σ` values exactly
    /// three times. Sweeping past one period is what makes an off-by-one in
    /// the modulus visible — over a single sweep of `0..2σ` a modulus of
    /// `2σ + 1` produces exactly the same 128 values in exactly the same
    /// order, so a one-period test agrees with it completely.
    ///
    /// The sum is the second half of the same statement, and it pins the
    /// half-unit downward bias the arm has by construction: the window is
    /// closed at the bottom and open at the top, so its mean is `μ − ½` rather
    /// than `μ`. Rounding that away would be a nicer number and a different
    /// distribution.
    #[test]
    fn tabledist_without_a_table_is_uniform_over_the_window() {
        const MU: i64 = 160;
        const SIGMA: i64 = 64;
        let span = 2 * SIGMA;

        assert_eq!(tabledist(MU, SIGMA, 0, None), MU - SIGMA, "bottom of the window");
        assert_eq!(
            tabledist(MU, SIGMA, (span - 1) as u32, None),
            MU + SIGMA - 1,
            "top of the window"
        );

        let mut sum = 0i64;
        let mut hits = vec![0u32; span as usize];
        for rnd in 0..(3 * span) as u32 {
            let v = tabledist(MU, SIGMA, rnd, None);
            assert!(
                (MU - SIGMA..MU + SIGMA).contains(&v),
                "sample {v} left the window at rnd {rnd}"
            );
            hits[(v - (MU - SIGMA)) as usize] += 1;
            sum += v;
        }
        assert!(hits.iter().all(|h| *h == 3), "every value is hit exactly three times: {hits:?}");
        assert_eq!(sum, 3 * (span * MU - SIGMA), "sum over three sweeps");
    }

    /// The table arm scales, rounds half away from zero, and adds μ.
    ///
    /// Three independent statements, because each catches a different way of
    /// getting it wrong:
    ///
    /// At `σ = TABLE_SCALE` the fixed-point split degenerates — `σ mod 8192`
    /// is zero and `σ div 8192` is one — so the sample must come back as the
    /// table entry itself. That is an exact equality against a number the
    /// function did not compute, and it catches a scale that is off by a
    /// factor of 8192 in either direction.
    ///
    /// At `σ = 1000` the split is the other degenerate case, and the sample
    /// must equal the table entry scaled by 1000/8192 and rounded half away
    /// from zero — restated in the test as an integer expression that shares
    /// no code with the implementation.
    ///
    /// Summing over a full sweep of the table is the conservation identity:
    /// the normal table sums to zero, so the samples must sum to exactly
    /// `4096·μ` whatever σ is. A wrong table index, a σ that leaks into the
    /// offset, or a lost `+ mu` all break it. What it does **not** catch is a
    /// missing rounding term — truncation toward zero is an odd function, and
    /// against an antisymmetric table an odd error cancels perfectly in the
    /// sum. That is precisely why the per-draw equality above exists as well.
    #[test]
    fn tabledist_scales_and_rounds_the_table_entry() {
        const MU: i64 = 1000;

        for rnd in 0..TABLE_LEN as u32 {
            let t = i64::from(NORMAL.0[rnd as usize]);
            assert_eq!(
                tabledist(MU, TABLE_SCALE, rnd, Some(NORMAL)) - MU,
                t,
                "at sigma == TABLE_SCALE the sample is the entry, rnd {rnd}"
            );

            let scaled = 1000 * t;
            let want = if scaled >= 0 {
                (scaled + TABLE_SCALE / 2) / TABLE_SCALE
            } else {
                -((-scaled + TABLE_SCALE / 2) / TABLE_SCALE)
            };
            assert_eq!(
                tabledist(0, 1000, rnd, Some(NORMAL)),
                want,
                "half-away rounding at sigma 1000, rnd {rnd}"
            );
        }

        for sigma in [1, 1000, TABLE_SCALE, 20_000_000] {
            let sum: i64 =
                (0..TABLE_LEN as u32).map(|r| tabledist(MU, sigma, r, Some(NORMAL))).sum();
            assert_eq!(sum, TABLE_LEN as i64 * MU, "sum at sigma {sigma}");
        }

        // The draw wraps the table rather than reaching past its end.
        assert_eq!(
            tabledist(0, TABLE_SCALE, u32::MAX, Some(NORMAL)),
            i64::from(NORMAL.0[TABLE_LEN - 1]),
            "the draw is reduced modulo the table length"
        );
    }

    /// A σ of zero is a fixed delay, on both arms, and must not divide.
    ///
    /// Both arms divide by σ — the uniform arm by `2σ`, the table arm by the
    /// scale after multiplying by it — so this is the case that turns a
    /// perfectly reasonable profile ("delay 30 ms, no jitter") into a panic in
    /// the send path. Asserting the returned value rather than merely "it did
    /// not panic" also rejects the other easy wrong answer, zero.
    #[test]
    fn tabledist_with_zero_sigma_is_the_fixed_delay() {
        for rnd in [0u32, 1, 4095, 4096, u32::MAX] {
            assert_eq!(tabledist(30_000_000, 0, rnd, None), 30_000_000);
            assert_eq!(tabledist(30_000_000, 0, rnd, Some(PARETONORMAL)), 30_000_000);
        }
    }

    /// The correlation filter: identity at `rho = 0`, the plain mean at
    /// `rho = 128`, and never outside the pair it is blending.
    ///
    /// `rho = 128` is the one setting where the filter has a closed form
    /// somebody else can write down — `(draw + last)/2` — so it is checked
    /// against that rather than against a table of numbers this crate
    /// produced. The betweenness invariant is checked at the extremes of the
    /// input range, where a `u32` multiply that was not widened first wraps:
    /// `u32::MAX · 256` overflows a `u32` by eight bits, and the wrapped
    /// result lands *outside* `[last, draw]`, which is what the invariant sees.
    #[test]
    fn crandom_blends_between_the_pair_and_is_the_mean_at_half() {
        let mut s = CorrState::default();
        for draw in [0u32, 1, 7, u32::MAX / 3, u32::MAX] {
            assert_eq!(crandom(&mut s, 0, draw), draw, "rho 0 is the identity");
        }

        let mut s = CorrState::default();
        let mut last = 0u64;
        for draw in [900u32, 3, u32::MAX, 12, u32::MAX - 1, 0] {
            let want = ((u64::from(draw) + last) / 2) as u32;
            assert_eq!(crandom(&mut s, 128, draw), want, "rho 128 is the mean of the pair");
            last = u64::from(want);
        }

        for rho in [0u8, 1, 100, 128, 200, 255] {
            let mut s = CorrState::default();
            let mut last = 0u32;
            for draw in [u32::MAX, 0, u32::MAX, 17, u32::MAX / 2, 0, 1] {
                let next = crandom(&mut s, rho, draw);
                let (lo, hi) = (last.min(draw), last.max(draw));
                assert!(
                    (lo..=hi).contains(&next),
                    "blend of {draw} into {last} at rho {rho} left the pair: {next}"
                );
                last = next;
            }
        }

        // The state is what carries correlation between calls, so a filter
        // that computed the blend correctly and forgot to store it would pass
        // every assertion above with rho pinned at 0 or 128 by accident.
        let mut s = CorrState::default();
        crandom(&mut s, 255, u32::MAX);
        assert_eq!(s, CorrState { last: 16_777_215 }, "the blend becomes the new state");
    }

    /// Re-derives the tables from the generator and diffs them against the
    /// committed file.
    ///
    /// `#[ignore]`d on purpose. The generator is the one place in this crate
    /// that evaluates `erf`, `exp` and a cube root, and those are exactly the
    /// operations the committed tables exist to keep off the everyday test
    /// path; running it on every `cargo test` would put the platform's libm
    /// back in the loop for no gain. Run it when the generator changes:
    ///
    /// ```text
    /// cargo test -p quinn-netem --lib -- --ignored
    /// ```
    ///
    /// The diff is exact, with no tolerance. A last-bit difference in the
    /// platform's `exp` can in principle move an emitted integer, but only for
    /// a value sitting within about 1e-16 of a rounding boundary, which over
    /// the generator's ~400 000 evaluations is a one-in-1e11 event. If this
    /// ever does differ by a unit, that is worth reading rather than
    /// absorbing into a tolerance.
    ///
    /// The nested build gets its own target directory: `cargo test` holds a
    /// lock on the one it was invoked with, and a nested cargo would sit on
    /// that lock until the test harness timed out.
    #[test]
    #[ignore = "runs the floating-point generator; the whole point of the tables is to keep it off the test path"]
    fn calibration_regenerate_the_distribution_tables_and_diff() {
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
        let target = std::env::temp_dir().join("quinn-netem-gen-tables");
        let out = std::process::Command::new(cargo)
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .args(["run", "-q", "-p", "quinn-netem", "--example", "gen_tables"])
            .arg("--target-dir")
            .arg(&target)
            .output()
            .expect("the generator runs");
        assert!(out.status.success(), "generator failed: {}", String::from_utf8_lossy(&out.stderr));

        // Line endings are normalised on both sides: the committed file is
        // checked out with whatever endings the platform's git is configured
        // for, and the generator always writes LF. A CRLF-only diff would be
        // a false alarm about the numbers.
        let regenerated = String::from_utf8(out.stdout).expect("the generator emits UTF-8");
        let regenerated = regenerated.replace("\r\n", "\n");
        let committed = include_str!("tables.rs").replace("\r\n", "\n");

        let first_diff =
            regenerated.lines().zip(committed.lines()).enumerate().find(|(_, (a, b))| a != b);
        assert_eq!(first_diff, None, "regenerated tables differ from the committed ones");
        assert_eq!(regenerated.lines().count(), committed.lines().count(), "line count");
    }
}

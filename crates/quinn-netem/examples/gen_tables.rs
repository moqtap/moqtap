//! Emits `src/dist/tables.rs` — the three committed integer distribution
//! tables.
//!
//! ```text
//! cargo run -p quinn-netem --example gen_tables -- crates/quinn-netem/src/dist/tables.rs
//! ```
//!
//! With no argument the file is written to stdout instead, which is how the
//! calibration test consumes it. The argument form exists because the shell
//! redirect form truncates the destination *before* cargo builds the library
//! that contains it, so `> …/tables.rs` fails to compile and then leaves an
//! empty file behind. Writing the file from inside the program happens after
//! the build and cannot destroy its own input.
//!
//! # Why this program exists at all
//!
//! The delay models need an inverse cumulative distribution function, which
//! needs `erf`, `exp` and a cube root — all of which std permits to differ
//! across platforms, compiler versions, and even between two calls in one
//! process. One last-bit difference in a jitter sample makes two runs of a seed
//! disagree.
//!
//! So the floating-point work happens once, here, offline, and what ships is
//! its output: three arrays of `i16`. This is an example rather than a module
//! because nothing in `src/` may contain a float. It is committed rather than
//! discarded so the tables can be re-derived and diffed on demand;
//! `calibration_regenerate_the_distribution_tables_and_diff` runs it and
//! compares its output to the committed file byte for byte.
//!
//! # The three distributions
//!
//! All three are scaled by `TABLE_SCALE` = 8192, so an entry of 8192 means one
//! standard deviation. All three have 4096 entries, indexed by a uniform draw.
//!
//! **Normal.** The table is the scaled inverse of
//! `Φ(x) = 0.5 + 0.5·erf(x/√2)`. Rather than invert `Φ` — which would need an
//! inverse-error-function approximation and a second source of rounding — the
//! program walks `x` across `[−10, 10.05)` in steps of `0.00005` and drops each
//! `x` into the bin `round(16384·Φ(x))`. Because `Φ` never moves by a whole bin
//! in one step (its steepest rise is `16384·φ(0)·0.00005 ≈ 0.327` bins) no bin
//! is skipped, and the last `x` written into bin `k` is the largest grid point
//! whose probability still rounds into `k`. The true quantile boundary lies
//! somewhere between that point and the next one, so half a step is added back;
//! without it every entry carries a fixed −0.41 bias in scaled units and the
//! table stops being antisymmetric. The 16384 bins are then folded four to one
//! by averaging, which is where the 4096 entries come from and which cuts the
//! quantisation error of the fold by two.
//!
//! Only the upper half is computed. The lower half is the negated mirror of it,
//! so the table is **exactly** antisymmetric and its entries sum to exactly
//! zero. Computing both halves from floating-point sums would leave a residue
//! of a few hundred scaled units, purely from summation order, and that residue
//! would be indistinguishable from a real centring error in a table nobody can
//! check by eye.
//!
//! **Pareto**, shape `a = 3`. Entry `j` of the 16384 pre-fold values comes from
//! `u = (65536 − 4j)/65536`, then `u^(−1/3) − 1.5`, then a scale of
//! `(4/3)·8192`. The `−1.5` is not decoration: `∫₀¹ u^(−1/3) du = 3/2`, so
//! subtracting it centres the distribution on zero mean before the tail is
//! clipped. Values are clipped into `i16` **before** the fold, matching the
//! order the paretonormal blend below assumes.
//!
//! **Paretonormal**, `(normal + 3·pareto)/4`. Computed from the two committed
//! integer tables, not from floating point, so it is reproducible by integer
//! arithmetic alone and the library can assert the blend as an exact identity
//! across the three arrays.
//!
//! # Reproducibility of this program
//!
//! Byte-identical output across platforms is expected but not guaranteed, for
//! the reason the tables exist: `exp` and `cbrt` may differ in the last bit.
//! That changes an emitted integer only when a value sits within about 1e-16 of
//! a rounding boundary, which across the ~400 000 evaluations here has a
//! probability on the order of 1e-11. A regeneration that does differ is worth
//! investigating, which is why the calibration diffs exactly rather than to a
//! tolerance.

use std::fmt::Write as _;

#[path = "../src/dist/sha256.rs"]
mod sha256;

/// Entries in a committed table. Mirrors the library's `TABLE_LEN`.
const TABLE_LEN: usize = 4096;

/// Sub-bins computed before the four-to-one fold.
const BINS: usize = TABLE_LEN * 4;

/// Scale factor. Mirrors the library's `TABLE_SCALE`: an entry of 8192 is one
/// standard deviation.
const TABLE_SCALE: f64 = 8192.0;

/// Grid step for the normal scan.
const X_STEP: f64 = 0.00005;

/// Grid index of `x = 0`, so that `x` is computed as `(m − X_ZERO)·X_STEP` and
/// the grid is an exact mirror of itself. Accumulating `x += X_STEP` instead
/// would drift, and computing `−10.0 + m·X_STEP` would make `x` and `−x`
/// differ in the last bit.
const X_ZERO: i64 = 200_000;

/// One past the last grid index: `x` runs over `[−10, 10.05)`.
const X_STEPS: i64 = 401_000;

fn main() {
    let normal = normal_table();
    let pareto = pareto_table();
    let paretonormal = paretonormal_table(&normal, &pareto);

    let payload = payload_bytes(&normal, &pareto, &paretonormal);
    let digest = sha256::hex(&sha256::sha256(&payload));
    let text = render(&normal, &pareto, &paretonormal, &digest);

    match std::env::args().nth(1) {
        Some(path) => std::fs::write(&path, text.as_bytes()).expect("write the table file"),
        None => print!("{text}"),
    }
}

// ── the distributions ───────────────────────────────────────────────────────

/// `0.5 + 0.5·erf(x/√2)`.
fn phi(x: f64) -> f64 {
    0.5 + 0.5 * erf(x / std::f64::consts::SQRT_2)
}

/// The error function, from the all-positive-terms series
/// `erf(x) = (2x/√π)·e^(−x²)·Σ (2x²)^n / (1·3·5···(2n+1))`.
///
/// The alternating Maclaurin series for `erf` is shorter to write and wrong to
/// use: at `x ≈ 3` its largest term is about `e^9`, so it cancels away four
/// significant digits before it converges. This form has no cancellation at
/// all — every term is positive — at the cost of a large intermediate sum that
/// the `e^(−x²)` factor cancels. Beyond `|x| = 8` the result is one to within
/// 1e-29 and is returned as such.
fn erf(x: f64) -> f64 {
    let a = x.abs();
    if a >= 8.0 {
        return if x < 0.0 { -1.0 } else { 1.0 };
    }
    let z = a * a;
    let mut term = 1.0_f64;
    let mut sum = 1.0_f64;
    let mut n = 0.0_f64;
    // The terms grow while `2z/(2n+1) > 1` and then fall geometrically; the
    // bound is a guard against a non-terminating loop, never a truncation in
    // practice (the worst case here, `x = −10`, converges in about 110 terms).
    while n < 1000.0 {
        n += 1.0;
        term *= 2.0 * z / (2.0 * n + 1.0);
        sum += term;
        if term <= 1e-18 * sum {
            break;
        }
    }
    let r = 2.0 * a / std::f64::consts::PI.sqrt() * (-z).exp() * sum;
    if x < 0.0 {
        -r
    } else {
        r
    }
}

/// The normal table: upper half scanned, lower half mirrored.
fn normal_table() -> Vec<i16> {
    // `bin[k]` ends up holding the largest grid point whose probability rounds
    // into bin `k`. Only bins `BINS/2 ..` are used; the rest are mirrored.
    let mut bin = vec![f64::NAN; BINS];
    let mut filled = vec![false; BINS];
    for m in 0..X_STEPS {
        let x = ((m - X_ZERO) as f64) * X_STEP;
        let k = ((BINS as f64) * phi(x)).round();
        if k >= 0.0 && k < BINS as f64 {
            let k = k as usize;
            bin[k] = x;
            filled[k] = true;
        }
    }
    // A skipped bin would silently become a NaN entry, so refuse rather than
    // emit one. The scan cannot skip a bin at this step size, and this is what
    // says so out loud if the step size is ever changed.
    for (k, f) in filled.iter().enumerate().skip(BINS / 2) {
        assert!(*f, "bin {k} received no grid point");
    }

    let half = TABLE_LEN / 2;
    let mut table = vec![0i16; TABLE_LEN];
    for i in half..TABLE_LEN {
        // Half a step is added back because the bin's true upper quantile
        // boundary lies between the last grid point inside it and the first
        // one outside it.
        let mut acc = 0.0_f64;
        for b in &bin[4 * i..4 * i + 4] {
            acc += b + X_STEP / 2.0;
        }
        let v = clamp_i16(round_half_away(TABLE_SCALE * acc / 4.0));
        table[i] = v;
        table[TABLE_LEN - 1 - i] = -v;
    }
    table
}

/// The pareto table, shape `a = 3`, clipped into `i16` before the fold.
fn pareto_table() -> Vec<i16> {
    let scale = (4.0 / 3.0) * TABLE_SCALE;
    let sub: Vec<i64> = (0..BINS)
        .map(|j| {
            let u = ((65536 - 4 * j) as f64) / 65536.0;
            let d = (1.0 / u.cbrt() - 1.5) * scale;
            i64::from(clamp_i16(round_half_away(d)))
        })
        .collect();
    (0..TABLE_LEN)
        .map(|i| {
            let acc: i64 = sub[4 * i..4 * i + 4].iter().sum();
            clamp_i16(round_half_away((acc as f64) / 4.0))
        })
        .collect()
}

/// `(normal + 3·pareto)/4`, in integers, from the two committed tables.
fn paretonormal_table(normal: &[i16], pareto: &[i16]) -> Vec<i16> {
    normal
        .iter()
        .zip(pareto.iter())
        .map(|(n, p)| {
            let blended = (i32::from(*n) + 3 * i32::from(*p)) / 4;
            clamp_i16(i64::from(blended))
        })
        .collect()
}

/// Round half away from zero. Chosen over round-half-to-even because it is an
/// odd function of its argument, which is what keeps the mirrored half of the
/// normal table an exact negation of the scanned half.
fn round_half_away(v: f64) -> i64 {
    if v >= 0.0 {
        (v + 0.5).floor() as i64
    } else {
        (v - 0.5).ceil() as i64
    }
}

/// Clip into `i16`. The normal table never reaches the rails; the pareto tail
/// does, at about the top one percent of entries.
fn clamp_i16(v: i64) -> i16 {
    v.clamp(i64::from(i16::MIN), i64::from(i16::MAX)) as i16
}

// ── emission ────────────────────────────────────────────────────────────────

/// The bytes the committed digest covers: every entry of all three tables, in
/// declaration order, little-endian.
fn payload_bytes(normal: &[i16], pareto: &[i16], paretonormal: &[i16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 * TABLE_LEN * 2);
    for table in [normal, pareto, paretonormal] {
        for v in table {
            out.extend_from_slice(&v.to_le_bytes());
        }
    }
    out
}

/// The whole of `tables.rs`, as text. One integer per line, LF endings, no
/// alignment and no column packing — a fixed shape so that regenerating an
/// unchanged table produces a byte-identical file and a diff means a changed
/// number.
fn render(normal: &[i16], pareto: &[i16], paretonormal: &[i16], digest: &str) -> String {
    let mut out = String::with_capacity(3 * TABLE_LEN * 8 + 4096);
    out.push_str(&format!(
        "// @generated by `cargo run -p quinn-netem --example gen_tables`. Do not edit.\n\
         // \n\
         // Three inverse-CDF tables, scaled by TABLE_SCALE, generated once offline so\n\
         // that nothing at run time has to evaluate a transcendental function. See\n\
         // `examples/gen_tables.rs` for how each one is derived and why.\n\
         // \n\
         // payload sha256 = {digest}\n\
         // \n\
         // The digest covers every entry of all three tables below, in declaration\n\
         // order, two bytes each, little-endian: 24576 bytes. It lives in a comment\n\
         // and not in a constant so that there is exactly one copy of it: the test\n\
         // that recomputes it reads this line out of the source text, so the comment\n\
         // is load-bearing and cannot rot into decoration.\n\
         \n\
         use super::TABLE_LEN;\n"
    ));
    emit(
        &mut out,
        "NORMAL_TABLE",
        "Scaled inverse of `Φ(x) = 0.5 + 0.5·erf(x/√2)`. Exactly antisymmetric.",
        normal,
    );
    emit(
        &mut out,
        "PARETO_TABLE",
        "Pareto, shape `a = 3`, centred on zero mean before the tail is clipped.",
        pareto,
    );
    emit(
        &mut out,
        "PARETONORMAL_TABLE",
        "`(NORMAL_TABLE + 3·PARETO_TABLE)/4`, entry by entry, in integers.",
        paretonormal,
    );
    out
}

/// One `pub(crate) const` array, one entry per line.
fn emit(out: &mut String, name: &str, doc: &str, table: &[i16]) {
    let _ = write!(
        out,
        "\n/// {doc}\n#[rustfmt::skip]\npub(crate) const {name}: [i16; TABLE_LEN] = [\n"
    );
    for v in table {
        let _ = writeln!(out, "    {v},");
    }
    out.push_str("];\n");
}

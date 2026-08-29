//! The engine's behavioural gates: the model order, each model's arithmetic,
//! and the stream separation the readability of every ablation rests on.
//!
//! This file is an integration test, i.e. a separate crate, and that is
//! deliberate: `Decision`, `Verdict` and `DropCause` are constructible and
//! exhaustively matchable from outside, so an expected `Decision` written as a
//! struct literal is a stronger statement than a handful of field assertions
//! and fails with both values printed.
//!
//! # Where the expected numbers come from
//!
//! Nothing here was blessed by running the implementation and writing down what
//! came out, which would assert only that the code does what the code does.
//! Every pinned count, index set and corruption site comes from a second,
//! independent transcription of the generator and of this crate's integer model
//! arithmetic, anchored first to the generator's published reference vector
//! (`seeded(42, 54)` → `0xa15c02b7 0x7b47f409 0xba1d3330 …`) and to the pinned
//! first word of the all-zero seed (`0xe4c14788`).
//!
//! Where a value is derivable by hand — a backlog trace, a release tick, a
//! window boundary — the arithmetic is written out in the test's own
//! documentation, so re-blessing it means disagreeing with a table.
//!
//! # One-sided where the quantity is statistical, exact everywhere else
//!
//! Every model is a pure function of the seed, the sequence number and the
//! tick, so there is no noise source for a tolerance band to absorb and a band
//! would be strictly weaker than an equality. The one genuinely statistical
//! claim — that the burst-length tail matches its closed form — is asserted
//! one-sided at a fixed seed, with the slack derived from the distribution the
//! count actually has.

use quinn_netem::{
    CorruptModel, CorruptSite, Decision, DelayModel, Direction, DirectionProfile, DropCause,
    DupModel, Impairer, LossModel, Prob, RateModel, ReorderModel, Tick, TimelineStep, Verdict,
    Window, ALL_STREAM_IDS,
};

/// A millisecond, in nanoseconds, so the ticks below read as the durations they
/// are.
const MS: u64 = 1_000_000;

/// A full-size datagram to an IPv4 peer: 1200 bytes of payload plus 20 bytes of
/// IP header and 8 of UDP.
const WIRE: u32 = 1228;

/// The probability an implementation cannot round to something else: exactly
/// one, and exactly zero.
const ALWAYS: Prob = Prob::from_ppb(1_000_000_000);
const NEVER: Prob = Prob::from_ppb(0);

/// A direction that impairs nothing, as the base for a one-model profile.
///
/// Every test below arms exactly the models it is about and leaves the rest
/// `None`, which is what makes a failure name a model instead of a module.
fn blank() -> DirectionProfile {
    DirectionProfile::default()
}

/// An engine over one model, seeded, downlink.
fn engine(profile: DirectionProfile, seed: u64) -> Impairer {
    Impairer::new(profile, seed, Direction::Downlink).expect("the test profile must validate")
}

/// The sequence numbers a run dropped, and why.
fn drops(engine: &mut Impairer, n: u64, tick_of: impl Fn(u64) -> Tick) -> Vec<(u64, DropCause)> {
    (0..n)
        .filter_map(|seq| {
            let d = engine.decide(seq, WIRE, tick_of(seq));
            (d.verdict == Verdict::Drop).then(|| (seq, d.cause()))
        })
        .collect()
}

// ── loss ────────────────────────────────────────────────────────────────

/// 100 000 datagrams at a five-percent Bernoulli loss, seed 7: **exactly 4988
/// dropped**.
///
/// An equality, not a convergence measurement, and the difference matters. The
/// decision is a pure function of the generator stream and the datagram index —
/// there is no noise source for a band to absorb — so "the loss rate converges"
/// is strictly weaker than the count, and a test named for convergence would
/// pass against an implementation that was wrong by a hundred datagrams.
///
/// The probability is written as parts per billion and the threshold it becomes
/// is asserted alongside the count, because the count is only meaningful under a
/// stated threshold: 0.05 lands on the numerator 214 748 365 over 2^32, which is
/// 0.05000000004656613, and a constructor that truncated instead of rounding
/// would land one below it and shift the count.
///
/// **4988, and specifically not 5035.** 5035 is the count this same seed and
/// threshold produce when the generator is seeded with 54 as its stream
/// selector. 54 is the stream selector of the generator's own published demo
/// vector — a demo constant, not a stream id — and the loss model draws from the
/// downlink loss stream, which is 0. Measuring 5035 means the engine seeded from
/// the wrong stream, and the two numbers are close enough that only an equality
/// tells them apart: both are well inside any band a convergence test would use.
#[test]
fn loss_rate_over_100k_packets_is_exactly_the_pinned_count() {
    // The threshold the count is pinned under, derived here rather than
    // transcribed: `round(0.05 * 2^32)`.
    let threshold = ((50_000_000u64 << 32) + 500_000_000) / 1_000_000_000;
    assert_eq!(threshold, 214_748_365, "0.05 as a numerator over 2^32");
    let p = Prob::from_ppb(50_000_000);
    // The boundary either side of the threshold, so the count below is a
    // statement about that number and not about a nearby one.
    assert!(p.hits(214_748_364), "the draw below the threshold is a loss");
    assert!(!p.hits(214_748_365), "the threshold itself is not");

    let mut e = engine(DirectionProfile { loss: Some(LossModel::Bernoulli { p }), ..blank() }, 7);
    let dropped = drops(&mut e, 100_000, |_| Tick(0));

    assert_eq!(dropped.len(), 4988, "seed 7, p = 0.05, 100 000 datagrams");
    assert!(dropped.iter().all(|(_, c)| *c == DropCause::Loss), "every drop is a loss drop");

    // The counters agree with the decisions, so a run cannot report one number
    // and return another.
    let s = e.stats();
    assert_eq!(s.dropped_loss, 4988);
    assert_eq!(s.datagrams_seen, 100_000);
    assert_eq!(s.datagrams_passed, 100_000 - 4988);
}

/// Twelve seeds, the same probability and the same length: twelve counts, each
/// exact and each inside the six-sigma band.
///
/// The exact counts are the gate. The band is asserted as well because it is
/// what says the counts *mean* five percent: over 100 000 datagrams at p = 0.05
/// the mean is 5000.000 and the standard deviation 68.920244, so six sigma is
/// 413.5215 and the integer band is [4587, 5413] — ±8.27% relative. The measured
/// extremes are 4922 and 5063, which are 1.13 and 0.91 sigma out.
///
/// A companion to the single-seed equality, never a replacement for it: a band
/// this wide is satisfied by an implementation that is systematically wrong by a
/// few hundred datagrams. It earns its place by surviving a legitimate change to
/// the mapping from a generator word to a probability, which the equality would
/// not — so the two together say "this exact stream" and "and it is really five
/// percent".
///
/// The seeds are chosen rather than sampled, so nothing here can flake.
///
/// This is also why the band must not be computed at a small probability. At
/// p = 0.001 the same arithmetic gives [41, 159], a band of ±60%: no defect
/// could escape it and the test would assert nothing at all.
#[test]
fn loss_counts_for_twelve_seeds_lie_in_the_binomial_band() {
    const BAND: std::ops::RangeInclusive<usize> = 4587..=5413;
    let want = [5045, 5027, 4971, 5045, 4922, 5020, 4988, 4997, 4944, 5018, 5063, 4929];

    let p = Prob::from_ppb(50_000_000);
    for (i, expected) in want.iter().enumerate() {
        let seed = i as u64 + 1;
        let mut e =
            engine(DirectionProfile { loss: Some(LossModel::Bernoulli { p }), ..blank() }, seed);
        let count = drops(&mut e, 100_000, |_| Tick(0)).len();
        assert_eq!(count, *expected, "seed {seed}");
        assert!(
            BAND.contains(&count),
            "seed {seed}: {count} is outside the six-sigma band {BAND:?}"
        );
    }

    // Twelve identical counts would satisfy both assertions above if the
    // expected vector were also twelve identical numbers, so the vector's own
    // spread is asserted: the seeds must actually be doing something.
    let spread = want.iter().max().expect("non-empty") - want.iter().min().expect("non-empty");
    assert_eq!(spread, 141, "4922 to 5063");
}

/// The four degenerate rows of the burst-loss chain, exact at every seed.
///
/// Each row is a configuration whose outcome is forced by arithmetic rather than
/// by chance, which is what lets them be asserted as equalities across four
/// unrelated seeds:
///
/// * `p = 0` and a good state that loses nothing — the chain never leaves the
///   good state, so **nothing is lost**.
/// * `r = 1` — the chain leaves the bad state on the very next datagram, so
///   **every burst has length exactly 1**.
/// * `r = 0` with a bad state that loses everything — the chain never leaves the
///   bad state, so the loss set is a **suffix**: once it starts, it never stops.
/// * both states losing everything — **every datagram is lost**.
///
/// The last row is exact for every seed only because a probability here is a
/// 64-bit numerator over 2^32 rather than a 32-bit one. With 32 bits and a
/// strict comparison, certainty is not representable — the largest expressible
/// value leaves a hole of one datagram in 4.3 billion — and this row would fail
/// about once in 21 000 runs of 200 000 datagrams, for a reason nobody reading
/// the failure would guess.
#[test]
fn gilbert_elliott_degenerate_rows_are_exact_for_every_seed() {
    const N: u64 = 200_000;
    const SEEDS: [u64; 4] = [1, 2, 999, 0xdead_beef];
    let some = Prob::from_ppb(20_000_000);

    for seed in SEEDS {
        // Row 1: a chain that never leaves a good state that loses nothing.
        let mut e = engine(ge(NEVER, Prob::from_ppb(500_000_000), ALWAYS, NEVER), seed);
        assert_eq!(drops(&mut e, N, |_| Tick(0)).len(), 0, "seed {seed}: p = 0 must lose nothing");

        // Row 2: leaving the bad state is certain, so no burst can reach 2.
        let mut e = engine(ge(Prob::from_ppb(50_000_000), ALWAYS, ALWAYS, NEVER), seed);
        let lost = seqs(&drops(&mut e, N, |_| Tick(0)));
        assert!(
            !lost.is_empty(),
            "seed {seed}: the r = 1 row must lose something, or it is vacuous"
        );
        for burst in bursts(&lost) {
            assert_eq!(
                burst.len(),
                1,
                "seed {seed}: burst at {} has length {}",
                burst[0],
                burst.len()
            );
        }

        // Row 3: entering the bad state is one-way, so the loss set is a suffix.
        let mut e = engine(ge(some, NEVER, ALWAYS, NEVER), seed);
        let lost = seqs(&drops(&mut e, N, |_| Tick(0)));
        assert!(!lost.is_empty(), "seed {seed}: the suffix row must reach the bad state");
        let first = lost[0];
        assert_eq!(
            lost,
            (first..N).collect::<Vec<_>>(),
            "seed {seed}: the loss set is not a suffix"
        );

        // Row 4: both states lose everything.
        let mut e = engine(ge(some, Prob::from_ppb(500_000_000), ALWAYS, ALWAYS), seed);
        let lost = seqs(&drops(&mut e, N, |_| Tick(0)));
        assert_eq!(lost.len() as u64, N, "seed {seed}: every datagram must be lost");
    }
}

/// The burst-length tail against its closed form, at a fixed seed.
///
/// For the simple two-state chain — a good state that loses nothing, a bad state
/// that loses everything — a burst continues past its n-th datagram exactly when
/// the chain fails to leave the bad state, so `P(len >= n) = (1 - r)^(n-1)` and
/// the mean burst length is `1/r`. At `r = 0.25` that is `P(len >= 2) = 0.75`
/// and a mean of 4.
///
/// Measured over a million datagrams at `p = 0.05`, seed 7: 41 638 bursts, of
/// which 31 194 reach length 2 — a ratio of 0.749171 against a closed form of
/// 0.75 — and 166 722 losses, a mean burst of 4.0041 against 4.
///
/// **The slack is derived from the distribution this count actually has, not
/// from the loss count's.** The number of losses in a burst-loss run is *not*
/// binomially distributed: its variance inflates by `(1 + rho) / (1 - rho)` with
/// `rho = 1 - p - r`, which is a factor of 1.5 here and as much as 7.25 at
/// slower chains — so a "six sigma" band computed binomially on the *loss count*
/// can be a 0.83 sigma band in practice and fail about 41% of the time. The
/// quantity asserted here is a different one: conditioned on the number of
/// bursts, each burst independently continues with probability `1 - r`, so the
/// count of bursts reaching length 2 is exactly binomial in the number of bursts
/// and its standard deviation is `sqrt(41638 * 0.75 * 0.25)` = 88.4. Six of
/// those is 530 bursts, which is the one-sided allowance below. The observed
/// shortfall is 34.5 bursts, 0.39 sigma.
///
/// The exact counts are asserted too. The run is deterministic, so they are
/// available and are a far stronger statement than the bound; the bound is what
/// says the counts mean what the closed form says they should. Swapping the two
/// states' loss probabilities moves the burst count by one in forty thousand,
/// which an equality catches and a tolerance band does not.
#[test]
fn gilbert_elliott_burst_tail_matches_the_closed_form() {
    const N: u64 = 1_000_000;
    let r = Prob::from_ppb(250_000_000);
    let mut e = engine(ge(Prob::from_ppb(50_000_000), r, ALWAYS, NEVER), 7);
    let lost = seqs(&drops(&mut e, N, |_| Tick(0)));
    let runs = bursts(&lost);

    let total = runs.len();
    let at_least_2 = runs.iter().filter(|b| b.len() >= 2).count();
    assert_eq!(total, 41_638, "bursts");
    assert_eq!(at_least_2, 31_194, "bursts reaching length 2");
    assert_eq!(lost.len(), 166_722, "datagrams lost");

    // P(len >= 2) >= (1 - r) - delta, in integers: `4 * at_least_2` against
    // `3 * total`, with six standard deviations of one-sided allowance.
    const SIX_SIGMA_BURSTS: usize = 530;
    assert!(
        4 * at_least_2 + 4 * SIX_SIGMA_BURSTS >= 3 * total,
        "P(len >= 2) is {at_least_2}/{total}, more than six sigma below the closed-form 3/4"
    );

    // The mean burst length against 1/r = 4, to one decimal place, in integers.
    assert!(lost.len() * 10 >= total * 39 && lost.len() * 10 <= total * 41, "mean burst length");
}

/// Two deterministic loss models, asserted as set equalities rather than counts.
///
/// A count is satisfied by dropping the wrong datagrams; the complement is what
/// makes it a statement about *which*.
///
/// The last third of the test is about what a drop costs the models downstream
/// of it. A loss drop is terminal, so the duplication model sees ninety
/// datagrams rather than a hundred and its j-th draw goes to the j-th survivor —
/// which is asserted here as an exact index mapping, because it is the property
/// that makes every ablation in this file readable and because the obvious
/// wrong version of it ("the same sequence numbers duplicate either way") would
/// be asserting that a dropped datagram consumes a draw.
///
/// The `EveryNth` reading is the one that needs stating: `n = 10` drops the
/// tenth, twentieth, … datagram, i.e. sequence numbers 9, 19, 29. The other
/// reading — sequence numbers 0, 10, 20 — drops the very first datagram of the
/// run, and a test written against it passes vacuously against either
/// implementation unless the expected set is written out.
#[test]
fn pattern_mode_drops_exactly_the_listed_indices() {
    // An index list, deliberately written out of order and with a repeat, since
    // a caller's list is a set and both spellings mean the same set.
    let listed = vec![42u64, 3, 17, 42];
    let mut e = engine(
        DirectionProfile { loss: Some(LossModel::Pattern { indices: listed }), ..blank() },
        1,
    );
    let dropped = seqs(&drops(&mut e, 100, |_| Tick(0)));
    assert_eq!(dropped, vec![3, 17, 42], "the listed indices");
    let delivered: Vec<u64> = (0..100).filter(|s| !dropped.contains(s)).collect();
    assert_eq!(delivered.len(), 97, "the complement is everything else");

    let mut e =
        engine(DirectionProfile { loss: Some(LossModel::EveryNth { n: 10 }), ..blank() }, 1);
    let dropped = seqs(&drops(&mut e, 100, |_| Tick(0)));
    assert_eq!(dropped, (0..10).map(|k| k * 10 + 9).collect::<Vec<u64>>(), "every tenth datagram");
    assert!(!dropped.contains(&0), "the first datagram of the run is not the tenth");

    // A loss drop is terminal, so the duplication model downstream of it sees
    // only the survivors — and the j-th survivor gets the j-th duplication
    // draw, exactly as if the dropped datagrams had never been offered. That is
    // the property the whole suite's ablations rest on, and it is the one an
    // implementation that spent a draw on a dropped datagram would break.
    //
    // Note what is *not* claimed: that the duplication hits land on the same
    // sequence numbers with and without a loss model. They do not, and they
    // must not. Ninety datagrams reach the duplication model instead of a
    // hundred, so its hits move with the survivor list; asserting otherwise
    // would be asserting that a dropped datagram consumes a draw.
    let dup = DupModel { p: Prob::from_ppb(100_000_000) };
    let mut alone = engine(DirectionProfile { dup: Some(dup), ..blank() }, 42);
    let mut beside = engine(
        DirectionProfile { loss: Some(LossModel::EveryNth { n: 10 }), dup: Some(dup), ..blank() },
        42,
    );
    let alone: Vec<u64> =
        (0..100).filter(|s| alone.decide(*s, WIRE, Tick(0)).duplicate.is_some()).collect();
    let beside: Vec<u64> = (0..100)
        .filter(|s| {
            let d = beside.decide(*s, WIRE, Tick(0));
            d.verdict != Verdict::Drop && d.duplicate.is_some()
        })
        .collect();
    let survivors: Vec<u64> = (0..100).filter(|s| s % 10 != 9).collect();
    assert!(!alone.is_empty(), "the duplication model must fire, or the comparison is vacuous");
    assert_eq!(alone, vec![16, 31, 32, 50, 76], "duplication hits with no loss model");
    assert_eq!(
        beside,
        alone.iter().map(|j| survivors[*j as usize]).collect::<Vec<u64>>(),
        "the j-th datagram to reach the duplication model must see the j-th draw"
    );
}

// ── rate and queue ──────────────────────────────────────────────────────

/// The exact backlog trace of a queue under above-rate ingress, the exact
/// sequence number of the first overflow, and the backlog at that moment.
///
/// The link carries 1 000 000 bytes per second — 8 000 000 bits, which is how
/// the model is configured — and a 1400-byte datagram arrives every 500
/// microseconds, so 500 bytes drain between arrivals while 1400 arrive. Ingress
/// is 2.8 times the link. The threshold is 5000 bytes. Each row is drain, then
/// the admission test `backlog + 1400 > 5000`, then the resulting backlog:
///
/// ```text
///  seq  drained to  1400 fits?                          backlog after
///   0       0       0 + 1400 ok                             1400
///   1     900       900 + 1400 ok                            2300
///   2    1800       ok                                       3200
///   3    2700       ok                                       4100
///   4    3600       3600 + 1400 = 5000, not > 5000, ok       5000
///   5    4500       5900 > 5000  DROP                        4500
///   6    4000       5400 > 5000  DROP                        4000
///   7    3500       4900 ok                                  4900
///   8    4400       5800 > 5000  DROP                        4400
///   9    3900       5300 > 5000  DROP                        3900
///  10    3400       4800 ok                                  4800
///  11    4300       5700 > 5000  DROP                        4300
///  12    3800       5200 > 5000  DROP                        3800
///  13    3300       4700 ok                                  4700
///  14    4200       5600 > 5000  DROP                        4200
/// ```
///
/// The trace is the assertion rather than a bound on it: the engine is
/// clock-free, so the sequence is a pure function of the fabricated ticks.
///
/// The non-zero backlog at the first overflow separates a genuine tail drop
/// from a configuration that could never have worked. A bucket that cannot
/// cover one datagram refuses the first datagram of an idle link, and reporting
/// that as queue overflow describes a link at its threshold on a queue that has
/// never held a byte.
#[test]
fn the_queue_traces_an_exact_backlog_and_tail_drops_at_a_named_index() {
    const STEP_NS: u64 = 500_000;
    const SIZE: u32 = 1_400;
    let want = [
        1400u64, 2300, 3200, 4100, 5000, 4500, 4000, 4900, 4400, 3900, 4800, 4300, 3800, 4700, 4200,
    ];

    let mut e = engine(
        DirectionProfile {
            rate: Some(RateModel { bps: 8_000_000, burst_bytes: 65_536, queue_bytes: 5_000 }),
            ..blank()
        },
        1,
    );

    let mut trace = Vec::new();
    let mut first_overflow = None;
    let mut admitted = 0u64;
    for seq in 0..want.len() as u64 {
        let d = e.decide(seq, SIZE, Tick(seq * STEP_NS));
        match d.cause() {
            DropCause::NotDropped => admitted += 1,
            DropCause::RateQueueFull => {
                if first_overflow.is_none() {
                    first_overflow = Some(seq);
                    assert!(
                        d.queue_backlog_bytes > 0,
                        "an overflow at sequence {seq} reported an empty queue, which is a \
                         configuration that never fits and not congestion"
                    );
                }
            }
            other => panic!("sequence {seq}: unexpected drop cause {other:?}"),
        }
        trace.push(d.queue_backlog_bytes);
    }

    assert_eq!(trace, want, "backlog trace");
    assert_eq!(first_overflow, Some(5), "sequence of the first overflow");
    assert_eq!(trace[5], 4500, "backlog at the first overflow");
    assert_eq!(admitted, 8, "8 of 15 admitted");

    // Conservation: everything admitted, minus everything the link drained over
    // the window, is what is still in the queue. The drain runs from the first
    // arrival to the last, fourteen steps of 500 bytes. An implementation that
    // counted a dropped datagram as admitted, or that drained at the wrong rate,
    // fails this immediately.
    let drained = 14 * (STEP_NS * 1_000_000 / 1_000_000_000);
    assert_eq!(admitted * u64::from(SIZE) - drained, trace[14], "admitted 11200 - drained 7000");

    // And the bucket never refused anything here, so every drop above is the
    // queue's and the trace is a statement about the queue alone.
    assert_eq!(e.stats().dropped_queue_full, 7);
    assert_eq!(e.stats().datagrams_seen, 15);
}

/// Delay caused by queueing and delay caused by the delay model are the same
/// number of nanoseconds and are still distinguishable in the decision.
///
/// Both runs release sequence 1 at tick 1 500 000 having seen it at tick
/// 500 000 — one millisecond of delay either way, with the same verdict. The
/// only thing that tells them apart is the recorded backlog: 2500 bytes standing
/// in the queue in the first run, nothing at all in the second.
///
/// The arithmetic of the first run, by hand. The link is 1 000 000 bytes per
/// second with a burst of 1500 bytes, and 1500-byte datagrams arrive 500
/// microseconds apart. Sequence 0 finds a full bucket and goes at once, leaving
/// it empty. Sequence 1 arrives 500 microseconds later, by which time 500 bytes
/// have been earned back; it is 1000 bytes short, which at 1 000 000 bytes per
/// second is exactly 1 000 000 nanoseconds of waiting. The queue meanwhile holds
/// 1500 bytes from sequence 0, drains 500, and takes 1500 more: 2500.
///
/// Without this distinction the two runs are indistinguishable in the log, and
/// "this connection is slow" cannot be attributed to a full link rather than to
/// a configured latency — which is the entire reason to have a rate model rather
/// than a second delay model.
#[test]
fn queue_delay_and_model_delay_are_distinguishable_in_the_decision() {
    const SIZE: u32 = 1_500;

    let mut queued = engine(
        DirectionProfile {
            rate: Some(RateModel { bps: 8_000_000, burst_bytes: 1_500, queue_bytes: 5_000 }),
            ..blank()
        },
        1,
    );
    queued.decide(0, SIZE, Tick(0));
    let from_queue = queued.decide(1, SIZE, Tick(500_000));

    let mut held =
        engine(DirectionProfile { delay: Some(DelayModel::Fixed { mean_ns: MS }), ..blank() }, 1);
    held.decide(0, SIZE, Tick(0));
    let from_delay = held.decide(1, SIZE, Tick(500_000));

    // The same delay, to the nanosecond, and the same verdict.
    assert_eq!(from_queue.release, Tick(1_500_000), "one millisecond of queueing");
    assert_eq!(from_delay.release, from_queue.release, "the two runs delay by the same amount");
    assert_eq!(from_queue.verdict, Verdict::Delay);
    assert_eq!(from_delay.verdict, Verdict::Delay);

    // And the reason is legible.
    assert_eq!(from_queue.queue_backlog_bytes, 2_500, "1500 queued, 500 drained, 1500 more");
    assert_eq!(from_delay.queue_backlog_bytes, 0, "a delay model queues nothing");
    assert_ne!(
        from_queue, from_delay,
        "queueing and a fixed delay must not produce the same decision"
    );
}

// ── reorder, blackout, MTU ──────────────────────────────────────────────

/// A reorder gap of 3 at certainty: every third datagram skips the delay queue,
/// and the release order of the first twelve is a fixed permutation.
///
/// The model has counter semantics, not displacement. With `gap: n`, every n-th
/// datagram is a *candidate*, and a candidate that hits is released at `now`
/// instead of at the tick the delay model chose — so it jumps ahead of
/// everything already parked. Nothing is swapped with anything, which is why the
/// model needs a delay model to exist at all and is refused without one.
///
/// **No duration is asserted.** The claim is an ordering — the sequence numbers
/// sorted by release tick — which is why it is independent of the machine it
/// runs on. All twelve datagrams arrive at tick zero, so the delayed ones share
/// a release tick and the tie is broken by sequence number.
///
/// A test named "the reorder gap is exact" written against the displacement
/// reading passes vacuously against either implementation, because under that
/// reading there is nothing to observe unless two datagrams are compared.
/// Writing the permutation out is what closes the ambiguity.
#[test]
fn reorder_gap_produces_exactly_this_order() {
    let mut e = engine(
        DirectionProfile {
            delay: Some(DelayModel::Fixed { mean_ns: 10 * MS }),
            reorder: Some(ReorderModel { gap: 3, p: ALWAYS }),
            ..blank()
        },
        1,
    );

    let mut decided: Vec<(u64, Decision)> =
        (0..12).map(|seq| (seq, e.decide(seq, WIRE, Tick(0)))).collect();

    // Every third datagram skipped the queue; every other one waited.
    for (seq, d) in &decided {
        let expected = if seq % 3 == 2 { Verdict::Reorder } else { Verdict::Delay };
        assert_eq!(d.verdict, expected, "sequence {seq}");
        let expected_release = if seq % 3 == 2 { Tick(0) } else { Tick(10 * MS) };
        assert_eq!(d.release, expected_release, "sequence {seq}");
    }

    decided.sort_by_key(|(seq, d)| (d.release, *seq));
    let order: Vec<u64> = decided.iter().map(|(seq, _)| *seq).collect();
    assert_eq!(order, vec![2, 5, 8, 11, 0, 1, 3, 4, 6, 7, 9, 10], "release order");

    // A reordered datagram is not a passed one, although both leave at `now`.
    let s = e.stats();
    assert_eq!(s.datagrams_reordered, 4);
    assert_eq!(s.datagrams_passed, 0, "nothing here passed untouched");
    assert_eq!(s.datagrams_delayed, 8);
}

/// A blackout window is half-open, asserted at the four ticks that decide it.
///
/// A window of `[at, at + for_)` is the only definition under which two
/// back-to-back windows neither overlap by a nanosecond nor leave a gap of one,
/// and under which the length of a window is exactly `for_` however it is
/// placed. The four points are: one tick before the start, the start itself, the
/// last tick inside, and the end tick — which is outside.
#[test]
fn blackout_boundaries_are_half_open() {
    const AT: u64 = 100 * MS;
    const FOR: u64 = 20 * MS;

    let mut e = engine(
        DirectionProfile { blackouts: vec![Window { at_ns: AT, for_ns: FOR }], ..blank() },
        1,
    );

    let mut at = |seq: u64, now: u64| -> Decision { e.decide(seq, WIRE, Tick(now)) };
    assert_eq!(at(0, AT - 1).verdict, Verdict::Pass, "one tick before the start");
    assert_eq!(at(1, AT).verdict, Verdict::Drop, "the start itself is inside");
    assert_eq!(at(2, AT + FOR - 1).verdict, Verdict::Drop, "the last tick inside");
    assert_eq!(at(3, AT + FOR).verdict, Verdict::Pass, "the end tick is outside the window");

    // The drops are attributed to the window and not to something else.
    assert_eq!(e.stats().dropped_blackout, 2);
    assert_eq!(e.stats().datagrams_passed, 2);

    // Overlapping windows are legal and are not merged: membership is "inside
    // any of them", so a datagram inside two windows is dropped once.
    let mut overlapping = engine(
        DirectionProfile {
            blackouts: vec![
                Window { at_ns: AT, for_ns: FOR },
                Window { at_ns: AT + 10 * MS, for_ns: FOR },
            ],
            ..blank()
        },
        1,
    );
    assert_eq!(overlapping.decide(0, WIRE, Tick(AT + 15 * MS)).verdict, Verdict::Drop);
    assert_eq!(overlapping.decide(1, WIRE, Tick(AT + 25 * MS)).verdict, Verdict::Drop);
    assert_eq!(overlapping.decide(2, WIRE, Tick(AT + 30 * MS)).verdict, Verdict::Pass);
    assert_eq!(overlapping.stats().dropped_blackout, 2, "a datagram inside two windows drops once");
}

/// A blacked-out datagram consumes nothing from the loss stream, so the loss
/// model's decisions are a function of the datagrams that reached it and of
/// nothing else.
///
/// This is the property every other ablation in this suite depends on for its
/// readability. Without it, switching one model off rewrites the whole log and
/// the diff names nothing.
///
/// **The comparison is by position in the loss model's own input sequence, not
/// by sequence number, and that is the only form of the claim that is true.** A
/// blackout is terminal: the hundred datagrams inside the window never reach the
/// loss model at all, so the loss stream is a hundred draws behind the
/// unblacked-out run from the window onward. What must hold — and what does — is
/// that the k-th datagram *to reach the loss model* gets the k-th draw in both
/// runs. Asserting instead that the two runs agree at equal sequence numbers
/// past the window would be asserting that a blackout *does* consume a draw,
/// which is the defect.
///
/// The precondition is not decoration. Without it this test passes against an
/// engine that has no blackout model at all: both runs are then identical and
/// every comparison below is trivially true. So the blacked-out run must
/// contain exactly one hundred blackout drops, at exactly the sequence numbers
/// inside the window, asserted before anything is compared.
#[test]
fn blackout_consumes_no_draw() {
    const N: u64 = 1_000;
    const SEED: u64 = 11;
    let p = Prob::from_ppb(50_000_000);
    let window = Window { at_ns: 100 * MS, for_ns: 100 * MS };
    // One datagram per millisecond, so the window covers sequence 100 to 199.
    let tick = |seq: u64| Tick(seq * MS);

    let mut plain =
        engine(DirectionProfile { loss: Some(LossModel::Bernoulli { p }), ..blank() }, SEED);
    let mut blacked = engine(
        DirectionProfile {
            loss: Some(LossModel::Bernoulli { p }),
            blackouts: vec![window],
            ..blank()
        },
        SEED,
    );

    let plain_run: Vec<Decision> = (0..N).map(|s| plain.decide(s, WIRE, tick(s))).collect();
    let blacked_run: Vec<Decision> = (0..N).map(|s| blacked.decide(s, WIRE, tick(s))).collect();

    // Precondition: the window really blacked out exactly the datagrams inside
    // it, and nothing else.
    let inside: Vec<u64> =
        (0..N).filter(|s| blacked_run[*s as usize].cause() == DropCause::Blackout).collect();
    assert_eq!(inside.len(), 100, "the window must actually black something out");
    assert_eq!(inside, (100..200).collect::<Vec<u64>>(), "and exactly the datagrams inside it");
    assert_eq!(blacked.stats().dropped_blackout, 100);

    // Before the window the two runs are identical decision for decision.
    assert_eq!(plain_run[..100], blacked_run[..100], "the runs must agree before the window");

    // From the window onward they agree by position in the loss model's input
    // sequence, which is the claim: the blackout spent no draws. Compared as the
    // positions that were lost rather than as two vectors of 900 booleans, so a
    // failure prints a readable list instead of a wall of `false`.
    let reached: Vec<&Decision> =
        blacked_run.iter().filter(|d| d.cause() != DropCause::Blackout).collect();
    assert_eq!(reached.len(), 900, "900 datagrams reached the loss model");
    let blacked_positions: Vec<usize> =
        (0..900).filter(|k| reached[*k].cause() == DropCause::Loss).collect();
    let plain_positions: Vec<usize> =
        (0..900).filter(|k| plain_run[*k].cause() == DropCause::Loss).collect();
    assert_eq!(
        blacked_positions, plain_positions,
        "the k-th datagram to reach the loss model must see the k-th draw"
    );

    // Non-vacuity on the comparison itself: the loss model must have fired, or
    // two empty lists would prove nothing.
    assert_eq!(blacked_positions.len(), 41, "losses among the first 900 draws");
}

/// A datagram larger than the declared path MTU is black-holed, and one of
/// exactly the limit is not.
///
/// The comparison is against the **on-wire** size — payload plus headers — and
/// not against the payload, because that is the same quantity the rate model
/// charges and the queue holds. Two models sizing one packet differently would
/// be two limits wearing one name. It consumes no draw, so a run with an MTU
/// black hole and a loss model has the same loss decisions as one without,
/// datagram for datagram, among the datagrams that reached the loss model.
#[test]
fn the_mtu_black_hole_drops_strictly_larger_datagrams() {
    const LIMIT: u16 = 1_252;
    let mut e = engine(DirectionProfile { mtu_blackhole: Some(LIMIT), ..blank() }, 1);

    assert_eq!(e.decide(0, 1_251, Tick(0)).verdict, Verdict::Pass, "one byte under");
    assert_eq!(
        e.decide(1, 1_252, Tick(0)).verdict,
        Verdict::Pass,
        "a datagram of exactly the limit passes"
    );
    assert_eq!(e.decide(2, 1_253, Tick(0)).cause(), DropCause::Mtu, "one byte over");
    assert_eq!(e.stats().dropped_mtu, 1);
}

// ── duplication and corruption ──────────────────────────────────────────

/// Duplication and corruption fire at pinned sequence numbers, and corruption at
/// pinned sites.
///
/// This is the test the kernel emulator this crate follows elsewhere cannot
/// have: it draws its corruption offset and bit from the system's cryptographic
/// generator, so its corruption is not reproducible even under its own seed.
/// Here both integers come from the crate's own generator and both are recorded,
/// so a corrupted datagram can be reproduced exactly and the rejection it causes
/// can be pointed at one bit of one packet.
///
/// Both models are armed in the same run and each still fires exactly where it
/// fires alone, which is the separate-stream property stated as a consequence
/// rather than as a principle.
///
/// The offset is drawn against `wire_bytes - 48`: the engine is told the on-wire
/// size and deliberately not the peer's address family, so the only offset it
/// can name that is certainly inside the payload is one bounded by the smallest
/// payload that on-wire size could correspond to. At 1228 on-wire bytes that
/// bound is 1180, and every site below is inside it.
#[test]
fn duplicate_and_corrupt_fire_at_the_pinned_indices() {
    let p = Prob::from_ppb(100_000_000);
    let mut e = engine(
        DirectionProfile {
            dup: Some(DupModel { p }),
            corrupt: Some(CorruptModel { p }),
            ..blank()
        },
        42,
    );

    let mut duplicated = Vec::new();
    let mut corrupted = Vec::new();
    for seq in 0..64u64 {
        let d = e.decide(seq, WIRE, Tick(0));
        if let Some(at) = d.duplicate {
            assert_eq!(at, d.release, "the copy is released with the original");
            duplicated.push(seq);
        }
        if let Some(site) = d.corrupt {
            assert!(site.byte_offset < WIRE - 48, "the site must be inside the payload");
            assert!(site.bit < 8, "a bit index is [0, 7]");
            corrupted.push((seq, site.byte_offset, site.bit));
        }
    }

    assert_eq!(duplicated, vec![16, 31, 32, 50], "duplicated sequence numbers");
    assert_eq!(
        corrupted,
        vec![
            (0, 691, 0),
            (9, 1067, 4),
            (12, 49, 7),
            (18, 223, 2),
            (49, 391, 4),
            (55, 196, 1),
            (57, 507, 0),
            (59, 924, 7),
        ],
        "corruption sites"
    );

    let s = e.stats();
    assert_eq!(s.datagrams_duplicated, 4);
    assert_eq!(s.datagrams_corrupted, 8);
    // A duplicate is a second datagram on the wire, so the bytes out exceed the
    // bytes in by exactly the duplicated bytes.
    assert_eq!(s.wire_bytes_out, s.wire_bytes_in + 4 * u64::from(WIRE));

    // The same two models, each alone, fire at exactly the same places.
    let mut only_dup = engine(DirectionProfile { dup: Some(DupModel { p }), ..blank() }, 42);
    let alone: Vec<u64> =
        (0..64).filter(|s| only_dup.decide(*s, WIRE, Tick(0)).duplicate.is_some()).collect();
    assert_eq!(alone, duplicated, "arming corruption must not move the duplication stream");
}

/// A datagram too small to name a payload offset in is left alone rather than
/// given a site the engine cannot prove exists.
///
/// The engine knows the on-wire size and not the address family. An on-wire size
/// of 48 bytes or less could be a datagram with no payload at all, so there is no
/// offset it can name that is certainly inside one. The alternative is to name an
/// offset anyway and leave the layer that applies the flip to clamp it — which
/// puts a number in the log that is not the byte that was flipped — or to skip
/// it there, which is an impairment configured, counted, logged and never
/// delivered.
///
/// Non-vacuity is the second half: the same model at the same seed does fire on
/// full-size datagrams, so "no corruption site" here is a statement about the
/// size and not about the model being off.
#[test]
fn a_datagram_with_no_provable_payload_is_not_given_a_corruption_site() {
    let p = ALWAYS;
    let mut tiny = engine(DirectionProfile { corrupt: Some(CorruptModel { p }), ..blank() }, 42);
    for seq in 0..32u64 {
        assert_eq!(tiny.decide(seq, 48, Tick(0)).corrupt, None, "sequence {seq}");
    }
    assert_eq!(tiny.stats().datagrams_corrupted, 0);

    // One byte more on the wire is one byte of payload the engine can prove is
    // there, and the model fires on all of them.
    let mut just_enough =
        engine(DirectionProfile { corrupt: Some(CorruptModel { p }), ..blank() }, 42);
    for seq in 0..32u64 {
        assert_eq!(
            just_enough.decide(seq, 49, Tick(0)).corrupt,
            Some(CorruptSite { byte_offset: 0, bit: bit_of(seq) }),
            "sequence {seq}"
        );
    }
    assert_eq!(just_enough.stats().datagrams_corrupted, 32);
}

// ── the timeline ────────────────────────────────────────────────────────

/// A timeline step takes effect at its tick and not one nanosecond before.
///
/// The step swaps a loss model that drops nothing for one that drops everything,
/// so the boundary is visible in a single datagram either side of it: the last
/// datagram at 499 999 999 nanoseconds passes and the first at 500 000 000
/// drops. Both consume a draw, so the two are decided by the same model
/// machinery and differ only in which profile was in force.
#[test]
fn timeline_steps_take_effect_at_the_tick_and_not_before() {
    const AT: u64 = 500 * MS;
    let mut e = engine(
        DirectionProfile {
            loss: Some(LossModel::Bernoulli { p: NEVER }),
            timeline: vec![TimelineStep {
                at_ns: AT,
                profile: Box::new(DirectionProfile {
                    loss: Some(LossModel::Bernoulli { p: ALWAYS }),
                    ..blank()
                }),
            }],
            ..blank()
        },
        1,
    );

    assert_eq!(e.decide(0, WIRE, Tick(0)).verdict, Verdict::Pass, "the start of the run");
    assert_eq!(
        e.decide(1, WIRE, Tick(AT - 1)).verdict,
        Verdict::Pass,
        "the last datagram before the step"
    );
    assert_eq!(
        e.decide(2, WIRE, Tick(AT)).verdict,
        Verdict::Drop,
        "the first datagram at the step's tick"
    );
    assert_eq!(e.decide(3, WIRE, Tick(AT + 1)).cause(), DropCause::Loss, "and after it");

    // The swap does not reset the sequence counter and does not re-seed: the
    // counters run straight through it.
    assert_eq!(e.stats().datagrams_seen, 4);
}

/// A timeline step replaces the whole profile, delay and rate included — not
/// just the loss model.
///
/// Two boundaries, each asserted as an exact release tick immediately before and
/// immediately after. The link carries 1 000 000 bytes per second with a burst of
/// one 1500-byte datagram, and one datagram arrives every 2 milliseconds, so at
/// the base rate the bucket earns 2000 bytes between arrivals and is always full.
///
/// **The delay boundary at 500 ms** swaps a fixed 1 ms delay for a fixed 50 ms
/// one. The bucket is full on both sides of it, so the release tick is the
/// arrival plus the delay and nothing else:
///
/// ```text
///   arrival        delay   release
///   498 000 000     1 ms    499 000 000
///   500 000 000    50 ms    550 000 000
/// ```
///
/// **The rate boundary at 1000 ms** halves the link to 500 000 bytes per second.
/// Now 2 milliseconds earns only 1000 bytes against a 1500-byte datagram, so the
/// bucket starts holding datagrams back:
///
/// ```text
///   arrival         held   need   short   wait      release
///    998 000 000    1500   1500      0      0     1 048 000 000
///   1000 000 000    1000   1500    500    1 ms    1 051 000 000
/// ```
///
/// where the last row's 50 ms of model delay is added to a release the bucket
/// pushed out to 1 001 000 000.
///
/// Separate from the step test above because that one swaps the loss model and
/// nothing else: an implementation replacing only the `loss` field passes it
/// completely while leaving delay and rate at whatever they were armed with.
#[test]
fn a_timeline_step_swaps_the_delay_and_rate_models_too() {
    const SIZE: u32 = 1_500;
    const STEP_NS: u64 = 2 * MS;
    let fast = RateModel { bps: 8_000_000, burst_bytes: 1_500, queue_bytes: 1 << 20 };
    let slow = RateModel { bps: 4_000_000, burst_bytes: 1_500, queue_bytes: 1 << 20 };

    let mut e = engine(
        DirectionProfile {
            rate: Some(fast),
            delay: Some(DelayModel::Fixed { mean_ns: MS }),
            timeline: vec![
                TimelineStep {
                    at_ns: 500 * MS,
                    profile: Box::new(DirectionProfile {
                        rate: Some(fast),
                        delay: Some(DelayModel::Fixed { mean_ns: 50 * MS }),
                        ..blank()
                    }),
                },
                TimelineStep {
                    at_ns: 1_000 * MS,
                    profile: Box::new(DirectionProfile {
                        rate: Some(slow),
                        delay: Some(DelayModel::Fixed { mean_ns: 50 * MS }),
                        ..blank()
                    }),
                },
            ],
            ..blank()
        },
        1,
    );

    let mut release = std::collections::BTreeMap::new();
    for k in 0..=500u64 {
        let d = e.decide(k, SIZE, Tick(k * STEP_NS));
        release.insert(k, d.release);
    }

    assert_eq!(release[&249], Tick(499 * MS), "before the delay step");
    assert_eq!(release[&250], Tick(550 * MS), "after the delay step");
    assert_eq!(release[&499], Tick(1_048 * MS), "before the rate step");
    assert_eq!(release[&500], Tick(1_051 * MS), "after the rate step");
}

// ── stream separation ───────────────────────────────────────────────────

/// The two directions draw from independent streams, and the difference shows at
/// a named index.
///
/// One seed, one profile, one driven sequence: the downlink and the uplink must
/// not produce the same decisions. Their loss draws first disagree at sequence
/// 5, where the uplink drops and the downlink does not, and over the first
/// hundred datagrams the two drop sets are disjoint.
///
/// A "the sequences differ somewhere" assertion would be satisfied by two
/// streams that diverge after a thousand datagrams; naming the index is what
/// makes this a statement about the seeding.
#[test]
fn the_two_directions_draw_from_independent_streams() {
    let p = Prob::from_ppb(50_000_000);
    let profile = DirectionProfile { loss: Some(LossModel::Bernoulli { p }), ..blank() };
    let mut down = Impairer::new(profile.clone(), 42, Direction::Downlink).expect("valid");
    let mut up = Impairer::new(profile, 42, Direction::Uplink).expect("valid");

    let d: Vec<Decision> = (0..100).map(|s| down.decide(s, WIRE, Tick(0))).collect();
    let u: Vec<Decision> = (0..100).map(|s| up.decide(s, WIRE, Tick(0))).collect();

    let first = d.iter().zip(u.iter()).position(|(a, b)| a != b);
    assert_eq!(first, Some(5), "the first index where the directions differ");
    assert_eq!(u[5].cause(), DropCause::Loss, "the uplink drops sequence 5");
    assert_eq!(d[5].verdict, Verdict::Pass, "the downlink does not");

    let down_drops: Vec<usize> = (0..100).filter(|i| d[*i].verdict == Verdict::Drop).collect();
    let up_drops: Vec<usize> = (0..100).filter(|i| u[*i].verdict == Verdict::Drop).collect();
    assert_eq!(down_drops, vec![9, 23, 38, 55, 68, 85], "downlink drops");
    assert_eq!(up_drops, vec![5, 15, 24, 62, 78, 92], "uplink drops");
    assert!(
        down_drops.iter().all(|s| !up_drops.contains(s)),
        "the two directions must not drop the same datagrams from one seed"
    );
}

/// The twelve stream ids are the declared constants, and arming one model does
/// not move another model's decisions.
///
/// Two claims, and the second is the one that matters. The whole reason each
/// model has its own generator is that switching a model off must produce a diff
/// that names exactly that model — every ablation recorded in this file depends
/// on it, and until it is asserted it is a convention rather than a property.
///
/// Arming duplication alongside loss must leave the loss decisions **identical,
/// datagram for datagram**, because duplication draws from its own stream and
/// changes nothing about which datagrams reach the loss model.
///
/// The precondition on both models firing is not decoration: two runs in which
/// neither model ever fires agree perfectly.
#[test]
fn the_stream_ids_are_the_declared_constants_and_models_do_not_shift_each_other() {
    assert_eq!(ALL_STREAM_IDS, [0, 1, 2, 3, 4, 5, 8, 9, 10, 11, 12, 13]);
    for i in 0..6 {
        assert_eq!(
            ALL_STREAM_IDS[i + 6],
            ALL_STREAM_IDS[i] + 8,
            "model {i}: uplink is downlink + 8"
        );
    }

    let p = Prob::from_ppb(50_000_000);
    let dup = DupModel { p: Prob::from_ppb(100_000_000) };

    let mut loss_only =
        engine(DirectionProfile { loss: Some(LossModel::Bernoulli { p }), ..blank() }, 42);
    let mut both = engine(
        DirectionProfile { loss: Some(LossModel::Bernoulli { p }), dup: Some(dup), ..blank() },
        42,
    );

    let alone = seqs(&drops(&mut loss_only, 1_000, |_| Tick(0)));
    let beside = seqs(&drops(&mut both, 1_000, |_| Tick(0)));

    assert!(!alone.is_empty(), "the loss model must fire, or the comparison is vacuous");
    assert!(both.stats().datagrams_duplicated > 0, "and so must the duplication model");
    assert_eq!(beside, alone, "arming duplication must not move the loss decisions");
}

// ── helpers ─────────────────────────────────────────────────────────────

/// A direction whose only model is a burst-loss chain with the four given
/// parameters.
fn ge(p: Prob, r: Prob, h: Prob, one_minus_k: Prob) -> DirectionProfile {
    DirectionProfile { loss: Some(LossModel::GilbertElliott { p, r, h, one_minus_k }), ..blank() }
}

/// The sequence numbers out of a drop list.
fn seqs(drops: &[(u64, DropCause)]) -> Vec<u64> {
    drops.iter().map(|(seq, _)| *seq).collect()
}

/// Runs of consecutive sequence numbers — the bursts of a burst-loss run.
fn bursts(lost: &[u64]) -> Vec<Vec<u64>> {
    let mut out: Vec<Vec<u64>> = Vec::new();
    for &seq in lost {
        match out.last_mut() {
            Some(run) if run[run.len() - 1] + 1 == seq => run.push(seq),
            _ => out.push(vec![seq]),
        }
    }
    out
}

/// The bit the corruption stream picks for the `seq`-th datagram of a run in
/// which every datagram is corrupted at offset 0.
///
/// Recomputed here from the generator rather than written out as a table of
/// thirty-two numbers, so the assertion that uses it stays a statement about the
/// draw order — offset first, then bit — and not about a list.
fn bit_of(seq: u64) -> u8 {
    use quinn_netem::{Pcg32, STREAM_DOWNLINK_CORRUPT};
    let mut rng = Pcg32::seeded(42, STREAM_DOWNLINK_CORRUPT);
    let mut bit = 0;
    for _ in 0..=seq {
        rng.next_u32(); // the hit draw
        rng.next_bounded(1); // the offset, from a payload of exactly one byte
        bit = rng.next_bounded(8) as u8;
    }
    bit
}

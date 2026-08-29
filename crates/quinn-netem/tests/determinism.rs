//! The reproducibility gate: one hand-computed fixture, and the checks that
//! keep it a gate instead of a decoration.
//!
//! # What this file claims, and what it deliberately does not
//!
//! Running the engine ten times in one process and finding the ten logs equal
//! is not evidence that the engine is reproducible. `decide` is a pure function
//! of the profile, the seed, its arguments and the engine's own integer state,
//! so ten runs over one input agree by construction — and agree just as
//! perfectly for an engine that decides nothing. The ten runs catch one thing:
//! state that varies between runs inside a single process, of which the
//! standard hash map is the one that turns up. Two `HashMap`s built in one
//! process already iterate in different orders, so anything folded out of one
//! by iteration would make run 3 disagree with run 0.
//!
//! The claim with weight is the second: run 0 equals a committed fixture
//! written from arithmetic, by hand, before the comparison was ever run.
//! `tests/fixtures/pattern_mode_gate.log` carries that arithmetic in its own
//! header, together with the statement that re-deriving it by running the
//! implementation is forbidden — a fixture blessed from the code under test
//! certifies whatever that code does, including deciding nothing.
//!
//! A test matrix also cannot compare across machines, since each runner only
//! sees itself, so a fixture all of them assert against is what makes
//! "identical everywhere" checkable at all.
//!
//! # Why the fixture is shaped the way it is
//!
//! Every probability in the gate profile is exactly 0 or 1 and every loss
//! decision is an index rule, so no verdict, release tick or backlog depends on
//! the value of a generator draw: all are integer arithmetic a person can redo
//! from the header's rules. The two exceptions are the corruption site's byte
//! offset and bit, which are generator output by definition and are what pin
//! the fixture to the generator. Their expected values come from a second
//! transcription of the generator, anchored to its published demo vector.
//!
//! # Everything here is asserted through a `Result`
//!
//! Comparisons go through `diff_fixture`, never through the
//! `assert_matches_fixture` wrapper: a helper whose only outcomes are "panic"
//! and `()` cannot be told apart from an empty body by any call site.

use std::collections::BTreeSet;

use quinn_netem::{
    CorruptModel, DecisionLog, DelayModel, Direction, DirectionProfile, DropCause, DupModel,
    Impairer, LossModel, Prob, RateModel, ReorderModel, Tick, TimelineStep, Verdict, Window,
    RECORD_HEADER,
};

/// A millisecond in nanoseconds, so the ticks below read as the durations they
/// are.
const MS: u64 = 1_000_000;

/// The seed the fixture was computed under. It reaches exactly two columns of
/// the fixture — the corruption offset and bit — because every other decision in
/// the gate profile is deterministic in `seq` and `now`.
const SEED: u64 = 7;

/// One record per datagram, drops included, so a record index and a `seq` are
/// the same number. That is what lets an ablation name a *line* and a reader
/// find the datagram it belongs to without counting.
const RECORDS: u64 = 100;

/// A 1200-byte payload to an IPv4 peer: plus 20 bytes of IP header and 8 of UDP.
const WIRE: u32 = 1228;

/// Strictly larger than the MTU black hole, so it is dropped before it can reach
/// the queue.
const JUMBO: u32 = 1500;

/// Exactly the MTU black hole. The comparison is strictly-greater, so this size
/// passes — a boundary an implementation that wrote `>=` would fail here and
/// nowhere else.
const AT_THE_LIMIT: u32 = 1400;

/// The MTU black hole, in on-wire bytes.
const MTU: u16 = 1400;

/// Certainty. A probability of exactly one hits on every draw including
/// `u32::MAX`, so the reorder, duplication and corruption models still consume
/// their draw and still answer the same way on every platform.
const ALWAYS: Prob = Prob::from_ppb(1_000_000_000);

/// The hand-computed gate fixture. Its header is the derivation.
const GATE_FIXTURE: &str = include_str!("fixtures/pattern_mode_gate.log");

/// The datagram sizes the fixture was computed over.
///
/// Three of the four oversized datagrams are there to be dropped by the MTU
/// black hole; the fourth, at `seq` 23, is inside the blackout window and is
/// dropped by *that* instead, which is how the fixture pins the order the two
/// models are consulted in.
fn wire_of(seq: u64) -> u32 {
    match seq {
        5 | 23 | 37 | 88 => JUMBO,
        40 => AT_THE_LIMIT,
        _ => WIRE,
    }
}

/// The one rate model, shared by all three phases so that the queue and the
/// bucket carry straight across a timeline step.
fn rate() -> RateModel {
    RateModel { bps: 8_000_000, burst_bytes: 1_500, queue_bytes: 2_000 }
}

/// Ticks `[0, 50ms)`: a named list of dropped indices, an exact blackout window,
/// an MTU threshold and the rate model. No delay, so this phase is where the
/// fixture's `Pass` verdicts come from.
fn phase_a() -> DirectionProfile {
    DirectionProfile {
        rate: Some(rate()),
        mtu_blackhole: Some(MTU),
        loss: Some(LossModel::Pattern { indices: vec![3, 7, 11, 22, 29, 44] }),
        blackouts: vec![Window { at_ns: 20 * MS, for_ns: 5 * MS }],
        ..DirectionProfile::default()
    }
}

/// Ticks `[50ms, 80ms)`: the every-n-th rule instead of the index list, a fixed
/// delay, and the two models whose effect is visible in a single column each.
fn phase_b() -> DirectionProfile {
    DirectionProfile {
        rate: Some(rate()),
        mtu_blackhole: Some(MTU),
        loss: Some(LossModel::EveryNth { n: 5 }),
        delay: Some(DelayModel::Fixed { mean_ns: 2 * MS }),
        reorder: Some(ReorderModel { gap: 4, p: ALWAYS }),
        dup: Some(DupModel { p: ALWAYS }),
        ..DirectionProfile::default()
    }
}

/// Ticks `[80ms, ..)`: phase B plus corruption, which is the only model in the
/// fixture whose recorded numbers are generator output rather than arithmetic.
fn phase_c() -> DirectionProfile {
    DirectionProfile { corrupt: Some(CorruptModel { p: ALWAYS }), ..phase_b() }
}

/// The whole gate profile: phase A as armed, with two timeline steps.
fn gate_profile() -> DirectionProfile {
    DirectionProfile {
        timeline: vec![
            TimelineStep { at_ns: 50 * MS, profile: Box::new(phase_b()) },
            TimelineStep { at_ns: 80 * MS, profile: Box::new(phase_c()) },
        ],
        ..phase_a()
    }
}

/// The gate profile with one edit applied to **every** phase.
///
/// Applied to the timeline steps as well as to the armed profile, because a
/// model disarmed in only one phase is still armed in the others and the
/// resulting diff would name the phase boundary rather than the model.
fn ablate(mut edit: impl FnMut(&mut DirectionProfile)) -> DirectionProfile {
    let mut profile = gate_profile();
    edit(&mut profile);
    for step in &mut profile.timeline {
        edit(&mut step.profile);
    }
    profile
}

/// Drive one engine over the fixture's synthetic sequence and record every
/// decision.
///
/// One datagram per millisecond, `seq` counting from 0, sizes from
/// [`wire_of`] — no clock, no socket, no async runtime anywhere in it.
fn drive(profile: DirectionProfile, seed: u64) -> DecisionLog {
    let mut engine =
        Impairer::new(profile, seed, Direction::Downlink).expect("the gate profile must validate");
    let mut log = DecisionLog::default();
    for seq in 0..RECORDS {
        let now = Tick(seq * MS);
        let wire = wire_of(seq);
        let decision = engine.decide(seq, wire, now);
        log.push(Direction::Downlink, seq, wire, now, &decision);
    }
    log
}

/// The fixture's record lines: `#` comments and blank lines dropped, trailing
/// carriage returns stripped.
///
/// The same filter the comparison applies, restated here because the tests below
/// read the fixture as a *file* — to check what it says about itself, and to
/// check its coverage before any behaviour is compared.
fn fixture_records(fixture: &str) -> Vec<&str> {
    fixture
        .split('\n')
        .map(|line| line.trim_end_matches('\r'))
        .filter(|line| {
            let head = line.trim_start();
            !head.is_empty() && !head.starts_with('#')
        })
        .collect()
}

/// One field of one rendered record, by column index.
fn field(record: &str, column: usize) -> u64 {
    record
        .split(' ')
        .nth(column)
        .unwrap_or_else(|| panic!("record has no column {column}: {record}"))
        .parse()
        .unwrap_or_else(|e| panic!("column {column} of {record} is not an integer: {e}"))
}

/// The log-format code of a verdict.
///
/// Written as a `match` with **no wildcard arm** on purpose. A fifth verdict
/// would fail to compile here rather than silently escaping the coverage check
/// below, which is the strongest form that check can take and the reason the
/// type is exhaustively matchable from outside the crate that defines it.
fn verdict_code(v: Verdict) -> u64 {
    match v {
        Verdict::Pass => 0,
        Verdict::Delay => 1,
        Verdict::Reorder => 2,
        Verdict::Drop => 3,
    }
}

/// The log-format code of a drop cause. Wildcard-free for [`verdict_code`]'s
/// reason.
fn cause_code(c: DropCause) -> u64 {
    match c {
        DropCause::NotDropped => 0,
        DropCause::Loss => 1,
        DropCause::Blackout => 2,
        DropCause::Mtu => 3,
        DropCause::RateQueueFull => 4,
    }
}

/// Every verdict the format defines.
const EVERY_VERDICT: [Verdict; 4] =
    [Verdict::Pass, Verdict::Delay, Verdict::Reorder, Verdict::Drop];

/// Every drop cause the format defines.
const EVERY_CAUSE: [DropCause; 5] = [
    DropCause::NotDropped,
    DropCause::Loss,
    DropCause::Blackout,
    DropCause::Mtu,
    DropCause::RateQueueFull,
];

/// Ten runs in one process agree, and run 0 equals the hand-computed fixture.
///
/// **The two halves are not the same claim and the first is much the weaker.**
/// Ten fresh engines over one input are equal by construction for any pure
/// function — the assertion is maximally green against an engine that decides
/// nothing — so it is kept and labelled for the single bug class it does catch:
/// state that differs between runs *inside one process*. The standard hash map
/// is the practical instance. Ten separate process launches would not catch it,
/// because the hash key that makes two maps iterate differently is incremented
/// per map construction within a process; ten launches would each see one map.
///
/// The second half is the one with weight. `fixtures/pattern_mode_gate.log` was
/// written from the arithmetic printed in its own header, before this comparison
/// was ever run, and the comparison is asserted through `diff_fixture`'s
/// `Result` rather than through the panicking wrapper, so an implementation of
/// the comparison that does nothing is a compile error at this call site rather
/// than a green test.
///
/// Written the other way, by **key lookup**, the same map is order-independent
/// and therefore perfectly deterministic: `5 passed; 0 failed`, ten runs
/// identical and the fixture comparison green. That distinction is the whole
/// content of the experiment. An implementer who ran only the keyed version,
/// saw green, and applied the usual rule — an ablation that cannot redden means
/// the test measures nothing — would delete a check that works.
#[test]
fn the_same_seed_and_pattern_mode_yield_an_identical_decision_log() {
    // 1. Ten runs in one process. A CHECK FOR STATE THAT VARIES BETWEEN RUNS —
    //    not a reproducibility proof. See this test's documentation.
    let runs: Vec<DecisionLog> = (0..10).map(|_| drive(gate_profile(), SEED)).collect();
    for (i, run) in runs.iter().enumerate().skip(1) {
        let first_difference =
            run.records().iter().zip(runs[0].records()).position(|(a, b)| a != b);
        assert_eq!(first_difference, None, "run {i} differs from run 0");
        assert_eq!(run.records().len(), runs[0].records().len(), "run {i} has a different length");
    }

    // A lower bound, because ten empty logs are also pairwise equal.
    assert_eq!(runs[0].records().len(), RECORDS as usize, "records driven");

    // 2. Run 0 against the hand-computed fixture, through the Result.
    runs[0].diff_fixture(GATE_FIXTURE).expect("the gate fixture");
}

/// The fixture contains a decision of every verdict and every drop cause.
///
/// A coverage precondition, in its own test so that its failure names the right
/// thing: *the fixture is not exercising the engine*, which is a different
/// complaint from *the engine disagrees with the fixture*.
///
/// It is asserted against the **file**, parsed as text, and only then against
/// the engine's own log. That ordering matters. An all-pass fixture is exactly
/// what a defaulting engine produces, and this way it is refused before any
/// behaviour is compared — the check does not depend on the engine being right,
/// or even on it running.
#[test]
fn the_gate_fixture_covers_every_verdict_and_every_drop_cause() {
    let records = fixture_records(GATE_FIXTURE);
    assert_eq!(records.len(), RECORDS as usize, "records in the fixture file");

    let verdicts: BTreeSet<u64> = records.iter().map(|r| field(r, 2)).collect();
    let missing: Vec<Verdict> =
        EVERY_VERDICT.into_iter().filter(|v| !verdicts.contains(&verdict_code(*v))).collect();
    assert!(
        missing.is_empty(),
        "the fixture must contain a decision of every verdict; missing {missing:?}"
    );
    assert_eq!(verdicts.len(), EVERY_VERDICT.len(), "and no verdict outside the format");

    let causes: BTreeSet<u64> = records.iter().map(|r| field(r, 3)).collect();
    let missing: Vec<DropCause> =
        EVERY_CAUSE.into_iter().filter(|c| !causes.contains(&cause_code(*c))).collect();
    assert!(
        missing.is_empty(),
        "the fixture must contain a drop of every cause; missing {missing:?}"
    );
    assert_eq!(causes.len(), EVERY_CAUSE.len(), "and no cause outside the format");

    // The same coverage read back out of the engine's own records, so the
    // accessor the rest of the crate reports through is exercised too.
    let log = drive(gate_profile(), SEED);
    let from_engine: BTreeSet<u64> = log.records().iter().map(|r| u64::from(r.verdict)).collect();
    assert_eq!(from_engine, verdicts, "the engine's verdicts and the fixture's");
}

/// Removing the loss model moves the fixture, at a named record.
///
/// The differential that stops the whole criterion being decoration. A fixture
/// can be byte-identical to what an engine produces and still measure nothing
/// about that engine: if switching a whole model off leaves the log unchanged,
/// the log is not a function of the models and the comparison is a comparison of
/// two constants.
///
/// Record 3 is the first datagram the named index list drops, and with the loss
/// model disarmed it becomes an ordinary release — a different verdict, a
/// different cause and a different backlog on that line, because the datagram
/// now reaches the queue.
///
/// Both directions are asserted here rather than only the interesting one: with
/// the loss model restored the same comparison returns `Ok`. A one-sided version
/// would pass against a fixture that never matches anything.
#[test]
fn removing_the_loss_model_changes_the_fixture_at_a_named_line() {
    drive(gate_profile(), SEED).diff_fixture(GATE_FIXTURE).expect("armed, the fixture matches");

    let without_loss = drive(ablate(|p| p.loss = None), SEED);
    let mismatch = without_loss
        .diff_fixture(GATE_FIXTURE)
        .expect_err("disarming the loss model must move the log");

    assert_eq!(mismatch.line, 3, "the first index the named list drops");
    assert_eq!(
        mismatch.expected, "3 0 3 1 1228 3000000 3000000 18446744073709551615 4294967295 0 1684",
        "the fixture's record 3"
    );
    assert_ne!(mismatch.actual, mismatch.expected, "and the engine no longer produces it");
}

/// Every model the gate profile arms moves the fixture, each at its own record.
///
/// The generalisation of the loss differential to the whole profile, and the
/// reason it exists: a fixture that is sensitive to one model and blind to the
/// other seven gates one model. Each row disarms exactly one model in every
/// phase and names the record the log must first differ at — a record chosen
/// from the arithmetic (the first datagram that model is the *first* to decide
/// about), not from whatever the comparison happened to report.
///
/// A row that returns `Ok` is the failure this test is for, and it is reported
/// as what it is: the fixture does not measure that model.
///
/// The delay row disarms the reorder model with it. A reorder model without a
/// delay model to skip is refused at construction — there is nothing to jump
/// ahead of — so "delay alone" is not a profile this crate will build.
///
/// Each row is an ablation, and the shape that makes the set of them meaningful
/// is that the named records are not all the same number: if every row could be
/// satisfied at record 0, the test would be asserting that the fixture is
/// sensitive to *something*, once, and calling it eight results.
#[test]
fn every_model_the_gate_profile_arms_moves_the_fixture_at_a_named_line() {
    let fixture = fixture_records(GATE_FIXTURE);

    let cases: Vec<(&str, DirectionProfile, usize)> = vec![
        // The backlog column is non-zero from the very first datagram.
        ("rate", ablate(|p| p.rate = None), 0),
        // The first oversized datagram, which now reaches the queue instead.
        ("mtu_blackhole", ablate(|p| p.mtu_blackhole = None), 5),
        // The first index in the named list.
        ("loss", ablate(|p| p.loss = None), 3),
        // The first millisecond inside the window.
        ("blackout", ablate(|p| p.blackouts.clear()), 20),
        // The first datagram of the phase that arms the delay.
        (
            "delay",
            ablate(|p| {
                p.delay = None;
                p.reorder = None;
            }),
            50,
        ),
        // The first datagram the gap counter selects after that.
        ("reorder", ablate(|p| p.reorder = None), 51),
        // The duplicate column is filled from the first datagram of phase B.
        ("dup", ablate(|p| p.dup = None), 50),
        // The first datagram of the phase that arms corruption.
        ("corrupt", ablate(|p| p.corrupt = None), 80),
    ];

    for (model, profile, line) in cases {
        let log = drive(profile, SEED);
        match log.diff_fixture(GATE_FIXTURE) {
            Ok(()) => panic!(
                "disarming the {model} model left the gate fixture byte-identical: \
                 the fixture does not measure it, and every claim made through it \
                 about that model is decoration"
            ),
            Err(mismatch) => {
                assert_eq!(mismatch.line, line, "disarming {model} must first move record {line}");
                assert_eq!(mismatch.expected, fixture[line], "the fixture's record {line}");
            }
        }
    }
}

/// The fixture states the profile it was computed from, and forbids its own
/// re-blessing.
///
/// This is the check that makes the prohibition mechanical instead of
/// aspirational. Every number the gate profile is built from is read back out of
/// the profile at run time and looked for in the fixture's comment block, so
/// changing the profile without redoing the arithmetic in the header is a red
/// test — and the most likely way to "fix" a red gate, regenerating the file
/// from the engine, deletes the header and reddens here rather than passing.
///
/// The size band is asserted for the same reason. A fixture of a hundred records
/// can be checked by hand; ten thousand cannot, and a fixture nobody can check
/// by hand is one nobody did.
#[test]
fn the_gate_fixture_states_the_profile_it_was_computed_from() {
    let records = fixture_records(GATE_FIXTURE);
    assert!(
        (50..=200).contains(&records.len()),
        "a gate fixture is 50 to 200 records, so a person can check it; this one has {}",
        records.len()
    );

    let first = GATE_FIXTURE.split('\n').next().unwrap_or("").trim_end_matches('\r');
    assert_eq!(first, RECORD_HEADER, "the fixture's first line names the columns below it");

    // The comment block, with runs of whitespace collapsed, so the checks below
    // are about the numbers and not about the header's layout.
    let commentary: String = GATE_FIXTURE
        .split('\n')
        .map(|line| line.trim_end_matches('\r'))
        .filter(|line| line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    assert!(
        commentary.contains("FORBIDDEN"),
        "the fixture must say, in the fixture, that deriving it by running the \
         implementation is forbidden — a rule kept only in a sibling document is \
         a rule the next person to re-bless this file will not read"
    );

    let profile = gate_profile();
    let rate = profile.rate.expect("the gate profile arms a rate model");
    let mtu = profile.mtu_blackhole.expect("the gate profile arms an MTU black hole");
    let window = profile.blackouts[0];
    let indices = match &profile.loss {
        Some(LossModel::Pattern { indices }) => indices.clone(),
        other => panic!("the gate profile's first phase drops a named index list, not {other:?}"),
    };

    // The later phases' models are unwrapped rather than matched with an `if
    // let`. A conditional here would let a change of shape — a different loss
    // model, a stochastic delay — skip its own requirement silently, which is
    // the failure this whole test is written against, one level up.
    let later = phase_b();
    let n = match &later.loss {
        Some(LossModel::EveryNth { n }) => *n,
        other => panic!("the later phases drop every n-th datagram, not {other:?}"),
    };
    let mean_ns = match later.delay {
        Some(DelayModel::Fixed { mean_ns }) => mean_ns,
        other => panic!("the later phases add a fixed delay, not {other:?}"),
    };
    let reorder = later.reorder.expect("the later phases arm a reorder model");

    let required = vec![
        format!("seed {SEED}"),
        format!("{RECORDS} datagrams, seq 0..{}", RECORDS - 1),
        format!("bps {}", rate.bps),
        format!("burst_bytes {}", rate.burst_bytes),
        format!("queue_bytes {}", rate.queue_bytes),
        format!("mtu_blackhole {mtu}"),
        format!("indices {indices:?}"),
        format!("at_ns {}ms, for_ns {}ms", window.at_ns / MS, window.for_ns / MS),
        format!("EveryNth n = {n}"),
        format!("Fixed {}ms", mean_ns / MS),
        format!("gap {}, p = 1", reorder.gap),
    ];

    for needle in required {
        assert!(
            commentary.contains(&needle),
            "the fixture must state the profile it was computed from; missing {needle:?}"
        );
    }
}

//! The counters account for every datagram, and they say so from outside.
//!
//! This file is an integration test, i.e. a **separate crate**, and that is the
//! point rather than an accident. `StatsSnapshot` is a read-only output whose
//! whole job is to be asserted on, so it has to be constructible by struct
//! literal — `..Default::default()` included — from a crate that does not define
//! it. Marking it `#[non_exhaustive]` would forbid exactly that:
//!
//! ```text
//! error[E0639]: cannot create non-exhaustive struct using struct expression
//! ```
//!
//! and every expected snapshot below would have to be replaced by a handful of
//! field comparisons that print one number when they fail instead of the whole
//! struct. These tests are what that decision is for; they are here so that
//! reversing it is a compile error rather than a judgement call.
//!
//! # Why a conservation identity needs a non-zero precondition
//!
//! `passed + delayed + reordered + the four drop causes == datagrams_seen` is a
//! real invariant, and on its own it is a gate on nothing. An engine that
//! returns "pass" for every datagram satisfies it — `passed == seen`, all four
//! drop counters are `0`, and the identity holds exactly. So does an engine
//! whose counters are all `0`, and so does one that was never called.
//!
//! So the identity is asserted together with a precondition that every
//! bucket it sums over is non-zero, over a profile with every model armed. The
//! identity says the counters lose nothing; the precondition says there was
//! something to lose. Neither claim is worth much without the other.
//!
//! # Where the expected numbers come from
//!
//! The small exact snapshot below is hand-derived from the model's own rule and
//! written out in the test, so re-blessing it means disagreeing with three lines
//! of arithmetic rather than re-running the code under test. The large run
//! asserts identities and one-sided bounds only — nothing there is a transcribed
//! output, because a number this crate printed and this crate then asserts is a
//! test of nothing but its own consistency.

use quinn_netem::{
    model::{CorruptModel, DelayModel, DupModel, LossModel, Prob, RateModel, ReorderModel, Window},
    Decision, Direction, DirectionProfile, Impairer, Stats, StatsSnapshot, Tick, TimelineStep,
    Verdict,
};

/// Datagrams driven through the fully-armed profile.
const N: u64 = 20_000;

/// One datagram every 250 µs, so the whole run is five seconds of ticks and the
/// blackout windows and the timeline step below can be placed in it by hand.
const SPACING_NS: u64 = 250_000;

/// The on-wire size of a normal datagram, and of the oversized one that the MTU
/// black hole is there to drop.
const NORMAL_BYTES: u32 = 1_200;
/// Every 89th datagram is this size, which is above `mtu_blackhole`.
const OVERSIZED_BYTES: u32 = 1_500;

/// The on-wire size of datagram `seq`.
///
/// `%` rather than `is_multiple_of`, which is stable only from 1.87 and would
/// raise this crate's floor by two releases for one line of a test.
fn wire_bytes_of(seq: u64) -> u32 {
    if seq % 89 == 0 {
        OVERSIZED_BYTES
    } else {
        NORMAL_BYTES
    }
}

/// A percentage as a probability.
fn percent(p: u32) -> Prob {
    Prob::from_ppb(p * 10_000_000)
}

/// Every model armed at once, in two phases.
///
/// Phase one, from tick 0, has no delay model, so a datagram the token bucket
/// grants immediately is released at `now` and counts as passed. Phase two, from
/// two seconds in, adds a delay model and the reorder model that needs one —
/// reordering works by letting a datagram skip the delay queue, so with no delay
/// there is no queue to skip and the model is refused rather than silently
/// inert.
///
/// The two phases are what make every bucket of the conservation identity
/// non-zero in a single run: without phase one there are no passes, and without
/// phase two there are no delays and no reorders.
///
/// The rate is set below the offered load on purpose. Datagrams arrive at
/// 1 200 bytes every 250 µs, which is 4.8 MB/s, against a 3 MB/s bucket — so the
/// bounded queue in front of it fills and tail-drops, which is the only path
/// that reports a full queue.
fn every_model_armed() -> DirectionProfile {
    let common = || DirectionProfile {
        loss: Some(LossModel::Bernoulli { p: percent(4) }),
        rate: Some(RateModel { bps: 24_000_000, burst_bytes: 6_000, queue_bytes: 30_000 }),
        dup: Some(DupModel { p: percent(8) }),
        corrupt: Some(CorruptModel { p: percent(8) }),
        mtu_blackhole: Some(1_400),
        ..DirectionProfile::default()
    };

    let phase_two = DirectionProfile {
        delay: Some(DelayModel::Normal { mean_ns: 3_000_000, sigma_ns: 1_000_000, rho: 0 }),
        reorder: Some(ReorderModel { gap: 7, p: percent(30) }),
        // A blackout inside phase two's own window, because a timeline step
        // replaces the profile wholesale and does not inherit the windows of the
        // profile it replaced.
        blackouts: vec![Window { at_ns: 3_500_000_000, for_ns: 150_000_000 }],
        ..common()
    };

    DirectionProfile {
        blackouts: vec![Window { at_ns: 1_000_000_000, for_ns: 200_000_000 }],
        timeline: vec![TimelineStep { at_ns: 2_000_000_000, profile: Box::new(phase_two) }],
        ..common()
    }
}

/// **The conservation gate.**
///
/// Three claims, and each is weak without the other two.
///
/// 1. `datagrams_seen == N`. The engine cannot under-count what it was handed.
/// 2. Every bucket the identity sums over is non-zero. This is the precondition
///    that stops the identity passing by absence, and it is the reason the
///    profile arms all six models plus the MTU black hole plus a blackout.
/// 3. The identity itself, plus the byte accounting: the seven buckets sum to
///    `datagrams_seen`, and `wire_bytes_out` is exactly the bytes of the
///    datagrams that were not dropped plus the bytes of the extra copies.
///
/// The byte claim is asserted twice, once as the bound the crate documents
/// (`wire_bytes_out <= wire_bytes_in + duplicated_bytes`) and once as the exact
/// equality, recomputed here from the returned decisions. The bound alone is
/// satisfied by an engine that emits nothing at all.
///
/// The counters are also cross-checked against a second, independent
/// implementation of the same bookkeeping: the engine keeps plain integers
/// because it decides one direction and is not shared, while `Stats` keeps
/// atomics for a socket that is. Feeding one decision stream to both and
/// requiring the two snapshots to be identical is double-entry bookkeeping — a
/// counter that is wrong in only one of them shows up as a whole-struct
/// mismatch that prints both sides.
///
/// The four release-path fields stay `0` here, and that is not an omission. This
/// engine decides; it has no release path and no clock to compare a scheduled
/// tick against, so any number it reported for them would be invented. They are
/// populated by the layer that hands datagrams to a socket, and gated there.
#[test]
fn stats_conserve() {
    let mut engine =
        Impairer::new(every_model_armed(), 0x5eed_1234, Direction::Downlink).expect("valid");
    let atomics = Stats::default();

    // Recomputed here rather than read out of the counters, so the byte identity
    // below is a comparison between two derivations and not a restatement.
    let mut expected_out: u64 = 0;
    let mut duplicated_bytes: u64 = 0;

    for seq in 0..N {
        let wire = wire_bytes_of(seq);
        let d: Decision = engine.decide(seq, wire, Tick(seq * SPACING_NS));
        atomics.record(Direction::Downlink, wire, &d);

        if d.verdict != Verdict::Drop {
            expected_out += u64::from(wire);
            if d.duplicate.is_some() {
                expected_out += u64::from(wire);
                duplicated_bytes += u64::from(wire);
            }
        }
    }

    let got = engine.stats();

    // 1. Nothing was lost on the way in.
    assert_eq!(got.datagrams_seen, N, "the engine must count every datagram it was handed");

    // 2. The precondition. Every one of these is a bucket the identity sums
    //    over, or an impairment whose absence would make the run trivial, and
    //    every one of them is what stops "the counters conserve" being a
    //    statement about zero.
    assert!(got.datagrams_passed > 0, "no datagram was released untouched");
    assert!(got.datagrams_delayed > 0, "no datagram was held");
    assert!(got.datagrams_reordered > 0, "no datagram skipped the delay queue");
    assert!(got.datagrams_duplicated > 0, "no datagram was copied");
    assert!(got.datagrams_corrupted > 0, "no datagram had a bit flipped");
    assert!(got.dropped_loss > 0, "the loss model dropped nothing");
    assert!(got.dropped_blackout > 0, "no datagram fell inside a blackout window");
    assert!(got.dropped_mtu > 0, "the MTU black hole dropped nothing");
    assert!(got.dropped_queue_full > 0, "the bounded queue never overflowed");

    // 3a. The identity.
    let accounted = got.datagrams_passed
        + got.datagrams_delayed
        + got.datagrams_reordered
        + got.dropped_loss
        + got.dropped_blackout
        + got.dropped_mtu
        + got.dropped_queue_full;
    assert_eq!(accounted, got.datagrams_seen, "every datagram lands in exactly one bucket");

    // 3b. The bytes, as the documented bound and as the exact equality.
    assert!(
        got.wire_bytes_out <= got.wire_bytes_in + duplicated_bytes,
        "left the link with more bytes than arrived plus the copies: {} > {} + {}",
        got.wire_bytes_out,
        got.wire_bytes_in,
        duplicated_bytes
    );
    assert_eq!(got.wire_bytes_out, expected_out, "the released bytes are the ones recomputed here");
    assert_eq!(
        got.wire_bytes_in,
        (0..N).map(|s| u64::from(wire_bytes_of(s))).sum::<u64>(),
        "the offered bytes are the ones driven"
    );

    // The release path is somebody else's; this engine has none.
    assert_eq!(got.release_batches, 0);
    assert_eq!(got.released_from_queue, 0);
    assert_eq!(got.release_batch_max, 0);
    assert_eq!(got.release_error_ns, 0);

    // Double entry: the atomics and the engine's plain integers must agree.
    assert_eq!(atomics.snapshot(), got, "the two counter sets must not disagree");

    // The queue's arrival test refuses a datagram that would take the backlog
    // past the threshold, so the high-water mark can reach the threshold and
    // never exceed it. Asserted as an inequality rather than as the peak this
    // run happened to reach, because the peak depends on the draw sequence and
    // the bound does not.
    assert!(
        got.queue_backlog_bytes_max <= 30_000,
        "backlog peaked at {} against a 30 000-byte threshold",
        got.queue_backlog_bytes_max
    );
}

/// A whole expected snapshot, built by struct literal with functional update
/// from a crate that does not define the type.
///
/// Two things at once. It is the compile-time statement that `StatsSnapshot` can
/// be constructed this way from outside — the file header says why that matters
/// — and it is an exact equality over every field at once, which no combination
/// of `>` assertions is.
///
/// The expected values are derived, not transcribed. The profile drops every
/// third datagram and arms nothing else, and "every third" means
/// `seq % 3 == 2` — the reading that drops datagram 2 rather than datagram 0,
/// because datagram 0 is the first of the run and dropping it would make "every
/// third" and "the first" the same thing. Over `seq` in `0..10` that selects
/// `{2, 5, 8}`, so three are dropped and seven released; nothing delays them, so
/// all seven pass. Ten datagrams of 1 200 on-wire bytes are offered, and the
/// seven that survived are what left.
#[test]
fn the_whole_snapshot_is_an_exact_value_a_foreign_crate_can_write_down() {
    let profile = DirectionProfile {
        loss: Some(LossModel::EveryNth { n: 3 }),
        ..DirectionProfile::default()
    };
    let mut engine = Impairer::new(profile, 1, Direction::Downlink).expect("valid");
    for seq in 0..10 {
        engine.decide(seq, NORMAL_BYTES, Tick(seq * SPACING_NS));
    }

    assert_eq!(
        engine.stats(),
        StatsSnapshot {
            datagrams_seen: 10,
            datagrams_passed: 7,
            dropped_loss: 3,
            wire_bytes_in: 12_000,
            wire_bytes_out: 8_400,
            ..StatsSnapshot::default()
        }
    );
}

/// The identity is true of an engine that impairs nothing, which is why the test
/// above does not stop at it.
///
/// This is the trap written down as a test rather than as a comment. A profile
/// with no models armed passes every datagram, and the conservation identity
/// holds exactly — so anything that asserts only the identity is green against
/// an engine that does nothing at all. Reading this test beside `stats_conserve`
/// is what shows that the preconditions there are carrying the weight.
#[test]
fn conservation_alone_is_satisfied_by_an_engine_that_impairs_nothing() {
    let mut engine =
        Impairer::new(DirectionProfile::default(), 1, Direction::Downlink).expect("valid");
    for seq in 0..1_000 {
        engine.decide(seq, NORMAL_BYTES, Tick(seq * SPACING_NS));
    }

    let got = engine.stats();
    let accounted = got.datagrams_passed
        + got.datagrams_delayed
        + got.datagrams_reordered
        + got.dropped_loss
        + got.dropped_blackout
        + got.dropped_mtu
        + got.dropped_queue_full;
    assert_eq!(accounted, got.datagrams_seen, "the identity holds");
    assert!(got.wire_bytes_out <= got.wire_bytes_in, "and so does the byte bound");

    // And yet nothing happened. Every bucket `stats_conserve` requires to be
    // non-zero is zero here.
    assert_eq!(got.datagrams_delayed, 0);
    assert_eq!(got.datagrams_reordered, 0);
    assert_eq!(got.datagrams_duplicated, 0);
    assert_eq!(got.datagrams_corrupted, 0);
    assert_eq!(
        got.dropped_loss + got.dropped_blackout + got.dropped_mtu + got.dropped_queue_full,
        0
    );
}

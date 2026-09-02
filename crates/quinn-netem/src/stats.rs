//! Live counters, and the plain-integer snapshot they are read through.
//!
//! Two types because there are two jobs. [`Stats`] is a set of atomic words
//! folded into on the datagram path, so reading it takes no lock and cannot
//! stall a send. [`StatsSnapshot`] is a `Copy` struct of plain integers, so a
//! caller can build an expected value by struct literal and compare it.
//!
//! # The conservation identity, and why `datagrams_seen` is counted separately
//!
//! Every decision lands in exactly one of seven buckets — passed, delayed,
//! reordered, and the four drop causes — which sum to `datagrams_seen`. That
//! identity says the counters account for every datagram the engine was handed
//! rather than for the ones somebody remembered to increment.
//!
//! Deriving `datagrams_seen` as the sum of the seven would make the identity
//! arithmetic instead of evidence: it would hold for an engine that counts
//! nothing and for one that never ran. Counted independently it is a statement
//! that can be false. For the same reason the test asserting it also asserts a
//! non-zero lower bound on every bucket — all-zero counters satisfy the
//! identity trivially.
//!
//! # A snapshot taken under load is not a consistent cut
//!
//! The counters are independent atomic words read one at a time with no lock,
//! so a snapshot taken while another thread is inside [`Stats::record`] can
//! catch a datagram counted as seen and not yet classified. The identity is
//! exact once the path is quiescent, which is the state every assertion on it
//! is made in. Making it exact under concurrent load needs a lock on the
//! datagram path, and a send that waits behind a statistics reader is a worse
//! trade than a snapshot that is a few datagrams stale.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering::Relaxed};

use crate::engine::{Decision, DropCause, Verdict};
use crate::{Direction, Tick};

/// Live counters. Atomics, so [`crate::control::ImpairHandle::stats`] never
/// blocks the datagram path.
///
/// One set of counters for the whole link. The per-direction split the engines
/// already keep is a different question from "what did this socket carry", and
/// the direction a datagram travelled in is recorded in the decision log, where
/// it can be grouped by after the fact. The one place direction is kept apart
/// here is the queue backlog, because that is a *gauge* rather than a running
/// total: two directions storing into one cell would overwrite each other and
/// the reported backlog would be whichever direction sent last.
#[derive(Debug, Default)]
pub struct Stats {
    /// Datagrams decided about. Counted here and never derived from the sum of
    /// the buckets below, which is what lets the two disagree.
    seen: AtomicU64,
    /// Released at `now` with no model holding them.
    passed: AtomicU64,
    /// Released later than `now`.
    delayed: AtomicU64,
    /// Released at `now` having skipped an armed delay model.
    reordered: AtomicU64,
    /// Datagrams given an extra copy.
    duplicated: AtomicU64,
    /// Datagrams with a bit flipped.
    corrupted: AtomicU64,
    /// Dropped by a loss model.
    dropped_loss: AtomicU64,
    /// Dropped inside a blackout window.
    dropped_blackout: AtomicU64,
    /// Dropped for exceeding the MTU black hole.
    dropped_mtu: AtomicU64,
    /// Tail-dropped at the bounded byte queue.
    dropped_queue_full: AtomicU64,
    /// On-wire bytes offered.
    wire_bytes_in: AtomicU64,
    /// On-wire bytes released, duplicates included.
    wire_bytes_out: AtomicU64,
    /// The two directions' current backlogs, indexed by the direction's
    /// discriminant. A gauge, not a total: each decision overwrites its own
    /// direction's cell and leaves the other alone.
    backlog: [AtomicU64; 2],
    /// High-water mark of the two backlogs *added together*, which is the
    /// number that says how much memory the shim held at once.
    backlog_max: AtomicU64,
    /// Wake-ups of the release path that released at least one datagram.
    release_batches: AtomicU64,
    /// Datagrams the release path released.
    released_from_queue: AtomicU64,
    /// Largest number of datagrams one wake-up released.
    release_batch_max: AtomicU32,
    /// Accumulated lateness of the release path, nanoseconds.
    release_error_ns: AtomicU64,
}

impl Stats {
    /// Read every counter into a plain-integer struct.
    ///
    /// A public method because a type with none is unreachable. These counters
    /// are otherwise readable only through the live control handle, which only
    /// the socket decorator produces — and the socket decorator is behind an
    /// optional dependency that the tests asserting on these numbers
    /// deliberately do not pull in.
    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            datagrams_seen: self.seen.load(Relaxed),
            datagrams_passed: self.passed.load(Relaxed),
            datagrams_delayed: self.delayed.load(Relaxed),
            datagrams_reordered: self.reordered.load(Relaxed),
            datagrams_duplicated: self.duplicated.load(Relaxed),
            datagrams_corrupted: self.corrupted.load(Relaxed),
            dropped_loss: self.dropped_loss.load(Relaxed),
            dropped_blackout: self.dropped_blackout.load(Relaxed),
            dropped_mtu: self.dropped_mtu.load(Relaxed),
            dropped_queue_full: self.dropped_queue_full.load(Relaxed),
            wire_bytes_in: self.wire_bytes_in.load(Relaxed),
            wire_bytes_out: self.wire_bytes_out.load(Relaxed),
            queue_backlog_bytes: self.backlog_total(),
            queue_backlog_bytes_max: self.backlog_max.load(Relaxed),
            release_batches: self.release_batches.load(Relaxed),
            released_from_queue: self.released_from_queue.load(Relaxed),
            release_batch_max: self.release_batch_max.load(Relaxed),
            release_error_ns: self.release_error_ns.load(Relaxed),
        }
    }

    /// Fold one decision into the counters. `wire_bytes` is the ON-WIRE size.
    /// This is the only mutator of the decision counters; it takes `&self`
    /// because the fields are atomics.
    ///
    /// Every decision passes through the one `match` below and increments
    /// exactly one bucket, which is what makes the conservation identity a
    /// property of the control flow rather than of a reviewer having remembered
    /// to increment something on each of seven branches.
    ///
    /// `dir` selects which direction's backlog gauge this decision overwrites.
    /// Nothing else is kept per direction: a running total is a statement about
    /// the link, and the decision log already carries every record's direction.
    ///
    /// The duplicate and the corruption are counted only on a decision that was
    /// not dropped — a dropped datagram is released at no tick, so a copy of it
    /// and a bit-flip in it are both things that did not happen, and counting
    /// them would put bytes into `wire_bytes_out` that never left.
    ///
    /// # Panics
    ///
    /// If a decision says the datagram was dropped and names no cause. It
    /// belongs in no bucket, so counting it would leave the conservation
    /// identity short by one with nothing to say which datagram it lost. The
    /// engine never produces one, so reaching this means a hand-built decision.
    pub fn record(&self, dir: Direction, wire_bytes: u32, d: &Decision) {
        let bytes = u64::from(wire_bytes);
        self.seen.fetch_add(1, Relaxed);
        self.wire_bytes_in.fetch_add(bytes, Relaxed);

        let bucket = match d.verdict {
            Verdict::Pass => &self.passed,
            Verdict::Delay => &self.delayed,
            Verdict::Reorder => &self.reordered,
            Verdict::Drop => match d.cause {
                DropCause::Loss => &self.dropped_loss,
                DropCause::Blackout => &self.dropped_blackout,
                DropCause::Mtu => &self.dropped_mtu,
                DropCause::RateQueueFull => &self.dropped_queue_full,
                DropCause::NotDropped => panic!(
                    "a dropped {wire_bytes}-byte datagram arrived at the counters with no \
                     cause; it belongs in no bucket and counting it would leave the \
                     conservation identity short by one"
                ),
            },
        };
        bucket.fetch_add(1, Relaxed);

        if d.verdict != Verdict::Drop {
            self.wire_bytes_out.fetch_add(bytes, Relaxed);
            if d.duplicate.is_some() {
                self.duplicated.fetch_add(1, Relaxed);
                self.wire_bytes_out.fetch_add(bytes, Relaxed);
            }
            if d.corrupt.is_some() {
                self.corrupted.fetch_add(1, Relaxed);
            }
        }

        self.backlog[dir as usize].store(d.queue_backlog_bytes, Relaxed);
        self.backlog_max.fetch_max(self.backlog_total(), Relaxed);
    }

    /// Fold one **release-path** observation in.
    ///
    /// Separate from [`Stats::record`] because only the layer that hands
    /// datagrams to a socket has a release path: `batch` is the number of
    /// datagrams this wake-up released, `scheduled` and `observed` are the
    /// decided and the actual release ticks.
    ///
    /// A wake-up that released nothing is not a batch and is not counted. The
    /// four release fields exist to make the mean clump
    /// `released_from_queue / release_batches` readable, and counting empty
    /// wake-ups in the denominator would drive that number towards zero in
    /// proportion to how often the release path was polled — which is a
    /// property of the polling, not of the pacing.
    ///
    /// The lateness accumulated into [`StatsSnapshot::release_error_ns`] is
    /// `observed.since(scheduled)`, which saturates at zero, so an **early**
    /// release contributes 0 rather than about 1.8e19. Early releases are
    /// normal here rather than exceptional: the release path commits to a whole
    /// slice of work per wake-up, and a datagram that a reorder model pulls
    /// forward is deliberately released before the tick the delay model chose.
    pub fn record_release(&self, batch: u32, scheduled: Tick, observed: Tick) {
        if batch == 0 {
            return;
        }
        self.release_batches.fetch_add(1, Relaxed);
        self.released_from_queue.fetch_add(u64::from(batch), Relaxed);
        self.release_batch_max.fetch_max(batch, Relaxed);
        self.release_error_ns.fetch_add(observed.since(scheduled), Relaxed);
    }

    /// Both directions' backlogs added together, saturating.
    ///
    /// Two loads rather than one cell, so that the two directions cannot
    /// overwrite each other's gauge. The pair is not read atomically, so under
    /// concurrent traffic the total can mix one direction's new value with the
    /// other's previous one — a backlog is a gauge and was already only true
    /// for the instant it was taken.
    fn backlog_total(&self) -> u64 {
        self.backlog[0].load(Relaxed).saturating_add(self.backlog[1].load(Relaxed))
    }
}

/// Plain integers — no `Duration`, no float — so a caller can assert on it
/// and a report can print it.
///
/// **Deliberately not `#[non_exhaustive]`.** That attribute on a *struct*
/// forbids struct-literal construction from outside the defining crate,
/// functional-update syntax included, and the tests that assert on this type
/// live in this crate's integration-test directory, which is a separate crate:
///
/// ```text
/// error[E0639]: cannot create non-exhaustive struct using struct expression
/// ```
///
/// So an expected snapshot could not be built at all, `..Default::default()`
/// included. This is a read-only output whose documented purpose is to be
/// asserted on; new fields are additive and the derives already pin the shape.
///
/// # The four release fields are load-bearing, not decoration
///
/// The release path wakes on a timer coarser than the spacing a fast link asks
/// for, so it releases datagrams in clumps and the average rate — not the
/// micro-burst shape — is what stays exact.
/// [`StatsSnapshot::released_from_queue`] divided by
/// [`StatsSnapshot::release_batches`] is the mean clump, so a caller can see
/// that quantisation instead of assuming a smooth pacing that is not happening.
///
/// They are asserted by a plain gate rather than an ignored calibration: all
/// four could stay `0` forever with every other assertion in the crate still
/// green, since they are not part of the conservation identity. The gate
/// asserts load-independent integer relations and no duration, so it is not a
/// timing measurement and does not flake on a loaded machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StatsSnapshot {
    /// Datagrams the engine decided about.
    pub datagrams_seen: u64,
    /// Released at `now` with no model holding them.
    pub datagrams_passed: u64,
    /// Released later than `now`.
    pub datagrams_delayed: u64,
    /// Released at `now` having SKIPPED an armed delay model.
    pub datagrams_reordered: u64,
    /// Datagrams the dup model gave an extra copy.
    pub datagrams_duplicated: u64,
    /// Datagrams the corrupt model flipped a bit in.
    pub datagrams_corrupted: u64,
    /// Dropped by a [`crate::model::LossModel`].
    pub dropped_loss: u64,
    /// Dropped inside a blackout [`crate::model::Window`].
    pub dropped_blackout: u64,
    /// Dropped for exceeding `mtu_blackhole`.
    pub dropped_mtu: u64,
    /// Tail-dropped at the bounded byte queue's `queue_bytes` threshold.
    pub dropped_queue_full: u64,
    /// ON-WIRE bytes offered.
    pub wire_bytes_in: u64,
    /// ON-WIRE bytes released, duplicates included.
    pub wire_bytes_out: u64,
    /// ON-WIRE bytes currently queued.
    pub queue_backlog_bytes: u64,
    /// High-water mark of [`StatsSnapshot::queue_backlog_bytes`].
    pub queue_backlog_bytes_max: u64,

    /// Wake-ups of the release path that released at least one datagram.
    pub release_batches: u64,
    /// Datagrams the release path released, i.e. not passed straight through.
    /// `released_from_queue / release_batches` is the mean clump — the number a
    /// caller reads to see the release path's quantisation instead of
    /// assuming smooth pacing that is not happening.
    pub released_from_queue: u64,
    /// Largest number of datagrams one wake-up released.
    pub release_batch_max: u32,
    /// Accumulated lateness of the release path, nanoseconds — **saturating, so
    /// an early release contributes 0 rather than about 1.8e19**.
    pub release_error_ns: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::CorruptSite;

    /// A decision that was not dropped, at a named backlog.
    fn passed(backlog: u64) -> Decision {
        Decision { queue_backlog_bytes: backlog, ..Decision::default() }
    }

    /// A decision that was dropped for `cause`.
    fn dropped(cause: DropCause) -> Decision {
        Decision { verdict: Verdict::Drop, cause, ..Decision::default() }
    }

    /// One decision of every verdict and every drop cause, folded in, lands in
    /// seven distinct buckets that sum to the number of decisions.
    ///
    /// Written as an exact expected snapshot rather than as seven separate
    /// field assertions, because the failure that matters is two verdicts
    /// sharing a bucket, and that shows up as one number too high beside
    /// another too low. Comparing the whole struct prints both.
    #[test]
    fn every_verdict_and_every_cause_lands_in_its_own_bucket() {
        let stats = Stats::default();
        let decisions = [
            Decision { verdict: Verdict::Pass, ..Decision::default() },
            Decision { verdict: Verdict::Delay, ..Decision::default() },
            Decision { verdict: Verdict::Reorder, ..Decision::default() },
            dropped(DropCause::Loss),
            dropped(DropCause::Blackout),
            dropped(DropCause::Mtu),
            dropped(DropCause::RateQueueFull),
        ];
        for d in &decisions {
            stats.record(Direction::Downlink, 100, d);
        }

        let got = stats.snapshot();
        assert_eq!(
            got,
            StatsSnapshot {
                datagrams_seen: 7,
                datagrams_passed: 1,
                datagrams_delayed: 1,
                datagrams_reordered: 1,
                dropped_loss: 1,
                dropped_blackout: 1,
                dropped_mtu: 1,
                dropped_queue_full: 1,
                // Seven decisions of 100 bytes offered; the three that were not
                // dropped are the only ones that left.
                wire_bytes_in: 700,
                wire_bytes_out: 300,
                ..StatsSnapshot::default()
            }
        );

        let buckets = got.datagrams_passed
            + got.datagrams_delayed
            + got.datagrams_reordered
            + got.dropped_loss
            + got.dropped_blackout
            + got.dropped_mtu
            + got.dropped_queue_full;
        assert_eq!(buckets, got.datagrams_seen, "the seven buckets account for every decision");
    }

    /// A duplicate is one extra datagram on the wire and one extra count; a
    /// corruption is neither.
    ///
    /// The pair is asserted together because the tempting mistake is symmetry —
    /// treating the two models alike since both are "an impairment applied to a
    /// datagram that was not dropped". A duplicate puts a second copy of the
    /// payload on the link and a bit-flip does not, so only one of them moves
    /// the byte count.
    #[test]
    fn a_duplicate_adds_bytes_and_a_corruption_does_not() {
        let stats = Stats::default();
        let site = CorruptSite { byte_offset: 7, bit: 3 };

        // Plain, duplicated, corrupted, and both at once.
        stats.record(Direction::Downlink, 800, &Decision::default());
        stats.record(
            Direction::Downlink,
            800,
            &Decision { duplicate: Some(Tick(5)), ..Decision::default() },
        );
        stats.record(
            Direction::Downlink,
            800,
            &Decision { corrupt: Some(site), ..Decision::default() },
        );
        stats.record(
            Direction::Downlink,
            800,
            &Decision { duplicate: Some(Tick(5)), corrupt: Some(site), ..Decision::default() },
        );

        let got = stats.snapshot();
        assert_eq!(got.datagrams_duplicated, 2);
        assert_eq!(got.datagrams_corrupted, 2);
        assert_eq!(got.wire_bytes_in, 3_200, "four 800-byte datagrams offered");
        assert_eq!(got.wire_bytes_out, 4_800, "four released plus two extra copies");
    }

    /// A dropped datagram's duplicate and corruption fields are not counted,
    /// and its bytes never reach `wire_bytes_out`.
    ///
    /// The engine never builds such a decision — the models that set those
    /// fields run only after the terminal drops — so this pins the counters
    /// against the day something else assembles one, which is precisely when a
    /// silently inflated byte count would be hardest to trace.
    #[test]
    fn a_dropped_datagram_contributes_no_bytes_and_no_impairments() {
        let stats = Stats::default();
        stats.record(
            Direction::Downlink,
            1_200,
            &Decision {
                verdict: Verdict::Drop,
                cause: DropCause::Loss,
                duplicate: Some(Tick(1)),
                corrupt: Some(CorruptSite { byte_offset: 0, bit: 0 }),
                ..Decision::default()
            },
        );

        let got = stats.snapshot();
        assert_eq!(got.wire_bytes_in, 1_200);
        assert_eq!(got.wire_bytes_out, 0, "a dropped datagram left no bytes on the wire");
        assert_eq!(got.datagrams_duplicated, 0);
        assert_eq!(got.datagrams_corrupted, 0);
        assert_eq!(got.dropped_loss, 1);
    }

    /// The two directions keep separate backlog gauges and the reported backlog
    /// is their sum, while the high-water mark tracks the sum over time.
    ///
    /// One shared cell would make this test read `1_000` at the end instead of
    /// `1_700`: the uplink's last decision would have overwritten the
    /// downlink's standing backlog, and a caller reading the field would be
    /// told the shim was holding a third less memory than it was.
    #[test]
    fn the_two_directions_keep_separate_backlog_gauges() {
        let stats = Stats::default();
        stats.record(Direction::Downlink, 100, &passed(2_000));
        stats.record(Direction::Uplink, 100, &passed(700));
        assert_eq!(stats.snapshot().queue_backlog_bytes, 2_700);
        assert_eq!(stats.snapshot().queue_backlog_bytes_max, 2_700);

        // The downlink drains; the uplink's gauge is untouched by it.
        stats.record(Direction::Downlink, 100, &passed(1_000));
        let got = stats.snapshot();
        assert_eq!(got.queue_backlog_bytes, 1_700, "1 000 downlink plus 700 uplink");
        assert_eq!(got.queue_backlog_bytes_max, 2_700, "the peak does not follow the drain down");
    }

    /// `record_release` counts batches, datagrams and the largest clump, and
    /// ignores a wake-up that released nothing.
    ///
    /// The empty wake-up is the interesting row. `released_from_queue /
    /// release_batches` is read as the mean clump, so counting wake-ups that
    /// released nothing would make that number a measurement of how often the
    /// release path was polled rather than of how it paced.
    #[test]
    fn release_batches_count_wake_ups_that_released_something() {
        let stats = Stats::default();
        stats.record_release(2, Tick(1_000), Tick(1_000));
        stats.record_release(0, Tick(2_000), Tick(9_999));
        stats.record_release(7, Tick(3_000), Tick(3_000));
        stats.record_release(3, Tick(4_000), Tick(4_000));

        let got = stats.snapshot();
        assert_eq!(got.release_batches, 3, "the empty wake-up is not a batch");
        assert_eq!(got.released_from_queue, 12);
        assert_eq!(got.release_batch_max, 7);
        assert_eq!(got.release_error_ns, 0, "every release was on time");

        // And the relation the gate reads: no batch can be larger than the
        // largest batch, so this bound holds however the clumps fell.
        assert!(got.release_batches * u64::from(got.release_batch_max) >= got.released_from_queue);
    }

    /// Lateness accumulates; an early release contributes zero rather than a
    /// wrapped `u64`.
    ///
    /// The early release is not a hypothetical. The release path commits to a
    /// whole slice of work per wake-up, so it habitually releases a datagram
    /// before the tick that datagram was scheduled for, and a reorder decision
    /// pulls one forward on purpose. A plain subtraction here panics in a debug
    /// build and reports about 1.8e19 nanoseconds — 584 years of lateness — in
    /// a release one.
    #[test]
    fn an_early_release_contributes_no_lateness() {
        let stats = Stats::default();
        stats.record_release(1, Tick(1_000), Tick(1_250));
        stats.record_release(1, Tick(5_000), Tick(4_000));
        stats.record_release(1, Tick(9_000), Tick(9_050));
        assert_eq!(stats.snapshot().release_error_ns, 300, "250 late, 0 early, 50 late");
    }

    /// A drop with no cause is refused loudly rather than counted nowhere.
    ///
    /// Silently skipping it would break the conservation identity by exactly
    /// one datagram, with nothing anywhere to say which one — the identity's
    /// value is that it holds or names a bug, and a counter that quietly
    /// declines to count is how it stops doing either.
    #[test]
    #[should_panic(expected = "belongs in no bucket")]
    fn a_drop_with_no_cause_is_refused() {
        let stats = Stats::default();
        stats.record(
            Direction::Downlink,
            100,
            &Decision {
                verdict: Verdict::Drop,
                cause: DropCause::NotDropped,
                ..Decision::default()
            },
        );
    }
}

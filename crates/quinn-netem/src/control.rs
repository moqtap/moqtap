//! The live control surface: arm, disarm, reseed, read.
//!
//! [`ImpairHandle`] is the only way to change what a running socket is doing.
//! It is a cheap clone of one piece of shared state — two engines, a set of
//! counters, a decision log and a flag — so a scenario and a spawned task can
//! hold one each and both talk about the same link.
//!
//! # What arming resets, and what it deliberately does not
//!
//! Arming builds two fresh engines, zeroes both directions' datagram counters
//! and sets the tick origin to the moment of the call, so tick 0 means "armed".
//! It does not clear the statistics: a scenario that arms twice would otherwise
//! lose the first phase's totals with nothing to say they had been discarded.
//!
//! # A refused profile changes nothing
//!
//! The whole profile is validated and both engines are built before anything is
//! swapped in, so a profile refused for a mistake in its uplink half leaves the
//! previous one running rather than half-replacing it — which would leave a
//! caller impairing traffic with one direction from each profile.
//!
//! # Recording is off by default
//!
//! A hundred-thousand-record log is a hundred thousand allocations on a path
//! that otherwise allocates nothing, so nothing is recorded until it is asked
//! for. The log-capture path has its own gate for that reason: a
//! `record_decisions` that did nothing would leave an empty log behind, which
//! is exactly what the default already produces.

use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use crate::consts::DEFAULT_QUEUE_BYTES;
use crate::engine::{Decision, Impairer};
use crate::log::DecisionLog;
use crate::profile::{ImpairProfile, PeerFilter, ProfileError};
use crate::stats::{Stats, StatsSnapshot};
use crate::{Direction, Tick};

/// Live control. Cloneable, `Send + Sync`.
///
/// Cloning shares the state rather than copying it: two handles to one socket
/// arm the same engines and read the same counters. That is what lets a
/// scenario keep a handle while the socket it decorates is owned by a runtime
/// it cannot reach into.
#[derive(Debug, Clone)]
pub struct ImpairHandle {
    /// Shared with every clone of this handle and with the socket that made it.
    shared: Arc<Shared>,
}

/// Everything a handle and the socket it controls both need.
///
/// The armed engines sit behind a mutex and the counters do not. That split is
/// the whole performance argument for this design: reading statistics is the
/// frequent, latency-sensitive-for-nobody operation and it takes no lock at
/// all, while deciding about a datagram needs the engines' mutable state and
/// takes a short one.
#[derive(Debug, Default)]
struct Shared {
    /// `None` while disarmed, which is the state a socket starts in.
    armed: Mutex<Option<Armed>>,
    /// Atomic counters, readable without touching the mutex above.
    stats: Stats,
    /// Whether decisions are being recorded. Off until asked for.
    recording: AtomicBool,
    /// The recorded decisions, empty unless `recording` is set.
    log: Mutex<DecisionLog>,
}

/// The state that exists only while a profile is armed.
#[derive(Debug)]
struct Armed {
    /// Proxy to client.
    downlink: Impairer,
    /// Client to proxy.
    uplink: Impairer,
    /// Each direction's own monotone datagram counter, indexed by the
    /// direction's discriminant. Zeroed by arming, because a sequence number is
    /// what a loss pattern and a reorder gap are expressed in — carrying one
    /// over from a previous profile would silently offset both.
    seq: [u64; 2],
    /// The instant tick 0 refers to.
    origin: Instant,
    /// Which peers the socket applies this profile to. Kept here rather than in
    /// an engine on purpose: an ephemeral port differs on every run and a
    /// dual-stack listener renders the same peer differently on different
    /// platforms, so a peer address must not reach a decision log that is meant
    /// to be byte-identical across machines.
    peers: PeerFilter,
    /// Each direction's bound on held bytes, indexed by the direction's
    /// discriminant. Taken from the rate model's tail-drop threshold when there
    /// is one, so the shim and the engine agree about how deep the queue is,
    /// and from the crate's default otherwise. There is no "unbounded" option:
    /// a shim that accepts a datagram it has not sent and never bounds what it
    /// is holding is a memory leak that presents as a latency bug.
    queue_bytes: [u64; 2],
}

impl ImpairHandle {
    /// Arm with a validated profile. Resets both directions' `seq` to 0 and the
    /// tick origin to the arm instant, so `Tick(0)` means "armed".
    ///
    /// The profile is validated and both engines are built before either is
    /// installed, so a refusal leaves whatever was armed before still running.
    pub fn arm(&self, profile: ImpairProfile) -> Result<(), ProfileError> {
        // Validates both directions and the peer filter. Doing it here as well
        // as inside each engine is what makes the uplink's mistakes visible
        // before the downlink's engine has been built, so nothing is half-built
        // when the error is returned.
        profile.validate()?;

        let ImpairProfile { downlink, uplink, peers, seed } = profile;
        let queue_bytes = [queue_bound(&downlink), queue_bound(&uplink)];
        let downlink = Impairer::new(downlink, seed, Direction::Downlink)?;
        let uplink = Impairer::new(uplink, seed, Direction::Uplink)?;

        *lock(&self.shared.armed) = Some(Armed {
            downlink,
            uplink,
            seq: [0, 0],
            origin: Instant::now(),
            peers,
            queue_bytes,
        });
        Ok(())
    }

    /// Every datagram passes untouched and `max_transmit_segments()` reverts to
    /// the inner socket's value.
    ///
    /// The counters and any recorded decisions survive: disarming stops the
    /// impairment, it does not discard the evidence of what the impairment did.
    pub fn disarm(&self) {
        *lock(&self.shared.armed) = None;
    }

    /// Whether a profile is currently armed.
    pub fn is_armed(&self) -> bool {
        lock(&self.shared.armed).is_some()
    }

    /// Re-seed every stream of both directions.
    ///
    /// Which random sequence the models read changes; nothing else does. The
    /// token buckets, the byte queues, the burst-loss chains, the datagram
    /// counters and every statistic are left alone, because this is a re-seed
    /// and not a re-arm — silently emptying a queue here would make a call that
    /// says "draw different numbers" also mean "forget what you were holding".
    ///
    /// A no-op while disarmed. Arming installs the profile's own seed, so a
    /// seed set before arming could not survive the call that would use it, and
    /// storing one that the next `arm` then overwrites would be a setting that
    /// silently does nothing.
    pub fn reseed(&self, seed: u64) {
        if let Some(armed) = lock(&self.shared.armed).as_mut() {
            armed.downlink.reseed(seed);
            armed.uplink.reseed(seed);
        }
    }

    /// A snapshot of both directions' counters.
    ///
    /// Takes no lock, so it can be called from anywhere at any rate without
    /// slowing a send down. The cost is that a snapshot taken while datagrams
    /// are in flight is not a consistent cut of the counters.
    pub fn stats(&self) -> StatsSnapshot {
        self.shared.stats.snapshot()
    }

    /// OFF by default: a 100k-record log is 100k allocations a production shim
    /// must not make.
    ///
    /// Turning recording off does not discard what has already been recorded;
    /// [`ImpairHandle::take_log`] is what empties the log.
    pub fn record_decisions(&self, on: bool) {
        self.shared.recording.store(on, Relaxed);
    }

    /// Take the recorded log, leaving an empty one behind.
    ///
    /// Taking rather than borrowing, so a scenario that captures a phase, reads
    /// it, and captures another does not have to remember to subtract the first
    /// phase from the second.
    pub fn take_log(&self) -> DecisionLog {
        std::mem::take(&mut *lock(&self.shared.log))
    }
}

/// The seam the socket decorator drives this state through.
///
/// Every item here is crate-private and its only caller is the socket module,
/// which is compiled only when the optional QUIC dependency is enabled. A build
/// without it therefore has no caller for any of them, and the dead-code lint is
/// right to say so — the `allow` is the point rather than an oversight. Deleting
/// them to silence it would leave the socket unable to reach the engines at all,
/// since the state they reach into is private to this module.
///
/// The seam is deliberately narrow. In particular the per-datagram entry point
/// below does the counting and the recording itself instead of handing the
/// engines out, so there is exactly one place a decision can be folded into the
/// counters and exactly one place it can be appended to the log. That is what
/// makes "every decision is counted once" a property of this file rather than of
/// every call site remembering to do both.
#[allow(dead_code)]
impl ImpairHandle {
    /// A handle with nothing armed, which is the state a socket starts in.
    pub(crate) fn detached() -> Self {
        ImpairHandle { shared: Arc::new(Shared::default()) }
    }

    /// Nanoseconds since the profile was armed, or `None` while disarmed.
    ///
    /// Read once per send and reused for every datagram of a batch, so that a
    /// segmented transmit is decided about at one instant rather than smeared
    /// across the time it took to walk the segments.
    ///
    /// Saturating: the conversion clamps rather than wrapping, and the clamp is
    /// 584 years after arming.
    pub(crate) fn tick(&self) -> Option<Tick> {
        let armed = lock(&self.shared.armed);
        let elapsed = armed.as_ref()?.origin.elapsed().as_nanos();
        Some(Tick(u64::try_from(elapsed).unwrap_or(u64::MAX)))
    }

    /// Decide about one datagram, fold the decision into the counters, and
    /// append it to the log when recording is on. `None` while disarmed.
    ///
    /// The direction's sequence number is allocated inside the same critical
    /// section as the decision, so two threads sending at once cannot hand the
    /// same sequence number to the engine twice — which would make a loss
    /// pattern drop the wrong datagram and a reorder gap fire twice in a row.
    ///
    /// The counters and the log are updated after the engine's lock is
    /// released, because neither needs it and holding a lock across an
    /// allocation on the send path is how a shim starts adding latency of its
    /// own.
    pub(crate) fn decide(&self, dir: Direction, wire_bytes: u32, now: Tick) -> Option<Decision> {
        let decision;
        let seq;
        {
            let mut armed = lock(&self.shared.armed);
            let armed = armed.as_mut()?;
            let i = dir as usize;
            seq = armed.seq[i];
            armed.seq[i] += 1;
            let engine = match dir {
                Direction::Downlink => &mut armed.downlink,
                Direction::Uplink => &mut armed.uplink,
            };
            decision = engine.decide(seq, wire_bytes, now);
        }

        self.shared.stats.record(dir, wire_bytes, &decision);
        if self.shared.recording.load(Relaxed) {
            lock(&self.shared.log).push(dir, seq, wire_bytes, now, &decision);
        }
        Some(decision)
    }

    /// Whether the armed profile applies to this peer. `false` while disarmed,
    /// which is the same answer as "do not impair this datagram".
    pub(crate) fn applies_to(&self, peer: std::net::SocketAddr) -> bool {
        match lock(&self.shared.armed).as_ref() {
            None => false,
            Some(armed) => match &armed.peers {
                PeerFilter::All => true,
                PeerFilter::Only(addrs) => addrs.contains(&peer),
            },
        }
    }

    /// How many bytes of held datagrams this direction may accumulate before
    /// the shim must drop. Falls back to the crate default while disarmed, so a
    /// caller reading it never has to special-case an unbounded queue.
    pub(crate) fn queue_bytes(&self, dir: Direction) -> u64 {
        match lock(&self.shared.armed).as_ref() {
            None => DEFAULT_QUEUE_BYTES,
            Some(armed) => armed.queue_bytes[dir as usize],
        }
    }

    /// Fold one release-path wake-up into the counters.
    pub(crate) fn record_release(&self, batch: u32, scheduled: Tick, observed: Tick) {
        self.shared.stats.record_release(batch, scheduled, observed);
    }
}

/// One direction's bound on held bytes.
///
/// The rate model's tail-drop threshold when there is one, so that the shim's
/// queue and the engine's queue are the same size and a datagram cannot be
/// accepted by one and refused by the other.
fn queue_bound(profile: &crate::profile::DirectionProfile) -> u64 {
    match profile.rate {
        Some(rate) => rate.queue_bytes,
        None => DEFAULT_QUEUE_BYTES,
    }
}

/// Lock, recovering from a previous panic rather than propagating it.
///
/// A mutex here is poisoned only if a thread panicked while holding it, and the
/// state behind these two is a set of engines and a list of records — neither
/// can be left half-written by a panic in a way that makes it unsafe to read.
/// Propagating the poison instead would turn one panicked send into a socket
/// where every later `is_armed` also panics, which converts a single lost
/// datagram into a dead connection.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DupModel, LossModel, Prob, RateModel, ReorderModel};
    use crate::profile::DirectionProfile;

    /// A profile that drops every third datagram of both directions.
    ///
    /// Deterministic on purpose: a loss model expressed in sequence numbers is
    /// what makes "arming restarts the numbering" an assertion about named
    /// indices rather than about a count that a shifted run also satisfies.
    fn every_third() -> ImpairProfile {
        let third = || DirectionProfile {
            loss: Some(LossModel::EveryNth { n: 3 }),
            ..DirectionProfile::default()
        };
        ImpairProfile { downlink: third(), uplink: third(), seed: 7, ..ImpairProfile::default() }
    }

    /// The sequence numbers of the datagrams the engine dropped, over a run of
    /// `n` from wherever this direction's counter currently stands.
    ///
    /// The indices rather than a count, because a count is the weaker claim: it
    /// is satisfied by a run that is out of phase but the same length, and the
    /// phase is what a sequence-number-driven loss model is.
    fn dropped_indices(handle: &ImpairHandle, dir: Direction, n: u64) -> Vec<u64> {
        (0..n)
            .filter(|_| {
                handle.decide(dir, 1_200, Tick(0)).expect("armed").verdict
                    == crate::engine::Verdict::Drop
            })
            .collect()
    }

    /// The documented `Send + Sync` bound, asserted by the compiler.
    ///
    /// Nothing else in the crate would notice a field losing it — the handle is
    /// stored, cloned and read from one thread everywhere it is currently used,
    /// so the first report would come from a downstream crate trying to move
    /// one into a spawned task.
    #[test]
    fn the_handle_is_send_and_sync_and_clones_share_one_state() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ImpairHandle>();

        let a = ImpairHandle::detached();
        let b = a.clone();
        assert!(!a.is_armed());
        a.arm(every_third()).expect("a valid profile");
        assert!(b.is_armed(), "a clone sees the arm");
        b.disarm();
        assert!(!a.is_armed(), "and the original sees the disarm");
    }

    /// A profile refused for a mistake in its uplink half leaves the downlink's
    /// previously armed profile running.
    ///
    /// The failure this forbids is a partial swap: validate the downlink,
    /// install it, then fail on the uplink and return an error a caller logs
    /// and moves on from — after which the link is impaired by half of one
    /// profile and half of another, and nothing anywhere says so.
    ///
    /// Asserted through the decisions rather than through `is_armed`, because a
    /// partial swap leaves a profile armed either way. What distinguishes them
    /// is *which* profile: the drops must still fall on the third datagram.
    #[test]
    fn a_refused_profile_leaves_the_previous_one_armed() {
        let handle = ImpairHandle::detached();
        handle.arm(every_third()).expect("a valid profile");

        // A reorder model with no delay model on the same direction is inert by
        // construction, so it is refused rather than accepted and ignored.
        let bad = ImpairProfile {
            uplink: DirectionProfile {
                reorder: Some(ReorderModel { gap: 4, p: Prob::from_ppb(500_000_000) }),
                ..DirectionProfile::default()
            },
            ..ImpairProfile::default()
        };
        assert_eq!(handle.arm(bad), Err(ProfileError::ReorderWithoutDelay));

        assert_eq!(dropped_indices(&handle, Direction::Downlink, 15), vec![2, 5, 8, 11, 14]);
        assert_eq!(handle.stats().dropped_loss, 5);
    }

    /// Arming zeroes both directions' sequence numbers, and the sequence number
    /// is what a deterministic loss model is expressed in.
    ///
    /// Asserted as the exact set of dropped indices rather than as a count. A
    /// count is satisfied by a sequence number that carried over and happened to
    /// stay in phase — every third of fifteen is five drops whether the counter
    /// restarted at 0 or at 3 — and the phase is the whole claim.
    #[test]
    fn arming_restarts_each_direction_at_sequence_zero() {
        let handle = ImpairHandle::detached();
        handle.arm(every_third()).expect("a valid profile");

        // Burn four datagrams on each direction, then re-arm.
        for _ in 0..4 {
            handle.decide(Direction::Downlink, 1_200, Tick(0));
            handle.decide(Direction::Uplink, 1_200, Tick(0));
        }
        handle.arm(every_third()).expect("a valid profile");

        for dir in [Direction::Downlink, Direction::Uplink] {
            assert_eq!(
                dropped_indices(&handle, dir, 15),
                vec![2, 5, 8, 11, 14],
                "{dir:?} restarts in phase"
            );
        }
    }

    /// Disarming stops the impairment and keeps the counters.
    ///
    /// The second half is the one worth pinning: a scenario reads the counters
    /// *after* it has stopped the impairment, so a `disarm` that cleared them
    /// would leave every such scenario reading zeros and concluding that
    /// nothing happened.
    #[test]
    fn disarming_stops_deciding_and_keeps_the_counters() {
        let handle = ImpairHandle::detached();
        handle.arm(every_third()).expect("a valid profile");
        for _ in 0..9 {
            handle.decide(Direction::Downlink, 1_200, Tick(0));
        }
        let before = handle.stats();
        assert_eq!(before.datagrams_seen, 9);
        assert_eq!(before.dropped_loss, 3);

        handle.disarm();
        assert!(handle.decide(Direction::Downlink, 1_200, Tick(0)).is_none());
        assert_eq!(handle.stats(), before, "disarming decided nothing and discarded nothing");
    }

    /// Re-seeding changes the next draw at a named index, and leaves the
    /// counters and the datagram numbering alone.
    ///
    /// # Why this needs two handles rather than two runs of one
    ///
    /// The obvious shape — run a handle, re-seed it, run it again, and check
    /// that the two runs differ — tests nothing. A generator advances as it is
    /// drawn from, so the second run of one handle differs from the first
    /// **whether or not the re-seed did anything**; measured, a `reseed` whose
    /// body is `let _ = seed;` still produces a first difference, at index 0.
    ///
    /// So two handles are armed identically and given identical histories, and
    /// only one of them is re-seeded. Everything else about them is the same, so
    /// the first index at which their continuations differ is attributable to
    /// the re-seed and to nothing else — and a `reseed` that does nothing makes
    /// the two continuations byte-identical, which is `None`.
    #[test]
    fn reseeding_changes_the_next_draw_at_a_named_index() {
        // A duplication model at one in two, so a changed stream shows up
        // within a handful of datagrams.
        let coin = || ImpairProfile {
            downlink: DirectionProfile {
                dup: Some(DupModel { p: Prob::from_ppb(500_000_000) }),
                ..DirectionProfile::default()
            },
            seed: 11,
            ..ImpairProfile::default()
        };
        let run = |handle: &ImpairHandle, n: usize| -> Vec<bool> {
            (0..n)
                .map(|_| {
                    handle
                        .decide(Direction::Downlink, 1_200, Tick(0))
                        .expect("armed")
                        .duplicate
                        .is_some()
                })
                .collect()
        };

        let untouched = ImpairHandle::detached();
        let reseeded = ImpairHandle::detached();
        untouched.arm(coin()).expect("a valid profile");
        reseeded.arm(coin()).expect("a valid profile");
        assert_eq!(run(&untouched, 24), run(&reseeded, 24), "identical seeds, identical history");

        reseeded.reseed(12);

        let first_diff =
            run(&untouched, 24).iter().zip(run(&reseeded, 24).iter()).position(|(a, b)| a != b);
        assert_eq!(first_diff, Some(0), "the re-seeded stream must diverge here");
        assert_eq!(
            reseeded.stats().datagrams_seen,
            48,
            "a re-seed is not a re-arm: the datagram count carries on"
        );
    }

    /// Re-seeding while disarmed is a no-op rather than a stored setting.
    ///
    /// A stored seed would be overwritten by the next `arm`, which installs the
    /// profile's own — so it would be a call that appears to configure
    /// something and cannot.
    #[test]
    fn reseeding_while_disarmed_changes_nothing() {
        let handle = ImpairHandle::detached();
        handle.reseed(999);
        assert!(!handle.is_armed());
        assert_eq!(handle.stats(), StatsSnapshot::default());
    }

    /// The peer filter answers from the armed profile, and answers `false`
    /// while disarmed.
    #[test]
    fn the_peer_filter_answers_from_the_armed_profile() {
        let one: std::net::SocketAddr = "127.0.0.1:4433".parse().expect("a literal address");
        let other: std::net::SocketAddr = "127.0.0.1:4434".parse().expect("a literal address");

        let handle = ImpairHandle::detached();
        assert!(!handle.applies_to(one), "a disarmed socket impairs nobody");

        handle.arm(every_third()).expect("a valid profile");
        assert!(handle.applies_to(one), "the default filter is every peer");

        handle
            .arm(ImpairProfile { peers: PeerFilter::Only(vec![one]), ..every_third() })
            .expect("a valid profile");
        assert!(handle.applies_to(one));
        assert!(!handle.applies_to(other));
    }

    /// The held-byte bound comes from the rate model when there is one and from
    /// the crate default otherwise, per direction.
    ///
    /// The two directions are asserted separately because the tempting
    /// implementation reads one direction's rate model and uses it for both,
    /// which silently gives an unshaped uplink the downlink's much smaller
    /// queue.
    #[test]
    fn the_queue_bound_follows_each_directions_rate_model() {
        let handle = ImpairHandle::detached();
        assert_eq!(handle.queue_bytes(Direction::Downlink), DEFAULT_QUEUE_BYTES);

        handle
            .arm(ImpairProfile {
                downlink: DirectionProfile {
                    rate: Some(RateModel {
                        bps: 8_000_000,
                        burst_bytes: 3_000,
                        queue_bytes: 24_000,
                    }),
                    ..DirectionProfile::default()
                },
                ..ImpairProfile::default()
            })
            .expect("a valid profile");

        assert_eq!(handle.queue_bytes(Direction::Downlink), 24_000);
        assert_eq!(
            handle.queue_bytes(Direction::Uplink),
            DEFAULT_QUEUE_BYTES,
            "the unshaped direction keeps the default bound"
        );
    }

    /// The tick origin is the arm instant, so a disarmed handle has no tick at
    /// all and an armed one starts near zero.
    ///
    /// No duration is asserted beyond an upper bound generous enough that only
    /// a wrong origin — a fixed epoch, or the process start — could exceed it.
    #[test]
    fn the_tick_origin_is_the_arm_instant() {
        let handle = ImpairHandle::detached();
        assert_eq!(handle.tick(), None, "a disarmed handle has no origin");

        handle.arm(every_third()).expect("a valid profile");
        let tick = handle.tick().expect("armed");
        assert!(tick.0 < 1_000_000_000, "arming was the origin, not some earlier epoch: {tick:?}");
    }

    /// Recording is off by default, and the default log is empty.
    ///
    /// Only the off half is asserted here, which is a weaker claim than it
    /// looks: an empty log is what a `record_decisions` that does nothing also
    /// produces. The claim that gives it teeth — recording on yields exactly
    /// one record per datagram — needs the log's own append and render, which
    /// are not implemented yet.
    #[test]
    fn recording_is_off_by_default() {
        let handle = ImpairHandle::detached();
        handle.arm(every_third()).expect("a valid profile");
        for _ in 0..8 {
            handle.decide(Direction::Downlink, 1_200, Tick(0));
        }
        assert_eq!(handle.take_log(), DecisionLog::default());
        assert_eq!(handle.stats().datagrams_seen, 8, "the datagrams were decided about");
    }
}

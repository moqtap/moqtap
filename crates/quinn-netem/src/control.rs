//! The live control surface: arm, disarm, reseed, read.
//!
//! [`ImpairHandle`] is the only way to change what a running socket is doing.
//! It is a cheap clone of one piece of shared state, so a caller and a spawned
//! task can hold one each and both talk about the same socket.
//!
//! # One link per peer
//!
//! Each peer address gets its own link: two engines, its own datagram
//! numbering, its own tick origin and its own counters. The socket's armed
//! profile applies to every peer the filter admits, each on its own link, so
//! peers never share a rate budget or a queue and one peer's traffic never
//! moves another peer's random draws. A peer can be given a profile of its own
//! with [`ImpairHandle::arm_peer`], or left untouched with
//! [`ImpairHandle::disarm_peer`].
//!
//! A peer's link is built when its first datagram is seen and dropped after it
//! has been idle for [`ImpairHandle::set_peer_idle_timeout`]. A profile given
//! with `arm_peer` or `disarm_peer` is dropped with it, or after the same idle
//! time when the peer never sends.
//!
//! # Determinism per peer
//!
//! A peer inheriting the socket profile is seeded with
//! [`peer_seed`]`(seed, ordinal)`, where `ordinal` counts the inheriting links
//! this handle has built, from 0. The first peer therefore runs exactly the
//! profile's own seed, and a peer's decisions depend only on the profile, the
//! seed, its ordinal and its own datagrams. The address never reaches an engine
//! or a log. A peer armed with [`ImpairHandle::arm_peer`] uses that profile's
//! seed as written.
//!
//! # What arming resets
//!
//! Arming rebuilds every inheriting peer's link: fresh engines, numbering from
//! 0, tick 0 at the moment of the call. The statistics are not cleared.
//!
//! # A refused profile changes nothing
//!
//! The whole profile is validated before anything is swapped in.
//!
//! # Recording is off by default
//!
//! Turn it on with [`ImpairHandle::record_decisions`]; each peer's records are
//! kept apart and taken with [`ImpairHandle::take_log`].

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::consts::{DEFAULT_PEER_IDLE_TIMEOUT, DEFAULT_QUEUE_BYTES};
use crate::engine::{Decision, Impairer};
use crate::log::DecisionLog;
use crate::profile::{DirectionProfile, ImpairProfile, PeerFilter, ProfileError};
use crate::stats::{Stats, StatsSnapshot};
use crate::{Direction, Tick};

/// Live control. Cloneable, `Send + Sync`; clones share one state.
#[derive(Debug, Clone)]
pub struct ImpairHandle {
    shared: Arc<Shared>,
}

#[derive(Debug, Default)]
struct Shared {
    core: Mutex<Core>,
    /// Every peer's decisions, folded together. Read without a lock.
    stats: Stats,
    recording: AtomicBool,
}

#[derive(Debug)]
struct Core {
    /// The socket-wide profile, validated. `None` while disarmed.
    profile: Option<ImpairProfile>,
    /// Per-peer profiles that replace the socket-wide one, with when the peer
    /// was last seen.
    overrides: HashMap<SocketAddr, (Override, Instant)>,
    /// Peers with a live link.
    peers: HashMap<SocketAddr, Peer>,
    /// Kept apart from `peers` so a disarm or an idle drop keeps the records.
    logs: HashMap<SocketAddr, DecisionLog>,
    next_ordinal: u64,
    idle_timeout: Duration,
    last_sweep: Option<Instant>,
    /// Every peer's backlog added together, per direction, for the aggregate
    /// gauge.
    backlog: [u64; 2],
}

impl Default for Core {
    fn default() -> Self {
        Core {
            profile: None,
            overrides: HashMap::new(),
            peers: HashMap::new(),
            logs: HashMap::new(),
            next_ordinal: 0,
            idle_timeout: DEFAULT_PEER_IDLE_TIMEOUT,
            last_sweep: None,
            backlog: [0, 0],
        }
    }
}

#[derive(Debug, Clone)]
enum Override {
    Armed(Box<ImpairProfile>),
    Disarmed,
}

#[derive(Debug)]
struct Peer {
    /// `None` for a link built from an override.
    ordinal: Option<u64>,
    link: Link,
    last_seen: Instant,
    stats: Stats,
    /// This peer's share of `Core::backlog`.
    backlog: [u64; 2],
}

#[derive(Debug)]
struct Link {
    downlink: Impairer,
    uplink: Impairer,
    /// Per-direction datagram numbering, indexed by the direction's
    /// discriminant.
    seq: [u64; 2],
    origin: Instant,
    queue_bytes: [u64; 2],
    /// Whether this link was built from an override rather than inherited.
    own: bool,
}

impl Link {
    fn build(profile: &ImpairProfile, seed: u64, own: bool) -> Result<Link, ProfileError> {
        let downlink = Impairer::new(profile.downlink.clone(), seed, Direction::Downlink)?;
        let uplink = Impairer::new(profile.uplink.clone(), seed, Direction::Uplink)?;
        Ok(Link {
            downlink,
            uplink,
            seq: [0, 0],
            origin: Instant::now(),
            queue_bytes: [queue_bound(&profile.downlink), queue_bound(&profile.uplink)],
            own,
        })
    }
}

/// The seed a peer inheriting the socket profile runs with: `seed` itself for
/// the first inheriting peer (`ordinal` 0), and a fixed integer mix of the two
/// after it.
pub fn peer_seed(seed: u64, ordinal: u64) -> u64 {
    if ordinal == 0 {
        return seed;
    }
    // splitmix64's finaliser.
    let mut z = ordinal.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    seed ^ z ^ (z >> 31)
}

impl Core {
    /// The profile and seed this peer runs with, or `None` when it is left
    /// untouched.
    fn profile_for(&self, peer: SocketAddr, ordinal: u64) -> Option<(&ImpairProfile, u64, bool)> {
        match self.overrides.get(&peer).map(|(o, _)| o) {
            Some(Override::Armed(p)) => Some((p, p.seed, true)),
            Some(Override::Disarmed) => None,
            None => {
                let p = self.profile.as_ref()?;
                let admitted = match &p.peers {
                    PeerFilter::All => true,
                    PeerFilter::Only(addrs) => addrs.contains(&peer),
                };
                admitted.then(|| (p, peer_seed(p.seed, ordinal), false))
            }
        }
    }

    fn remove_peer(&mut self, peer: SocketAddr) {
        if let Some(p) = self.peers.remove(&peer) {
            for i in 0..2 {
                self.backlog[i] = self.backlog[i].saturating_sub(p.backlog[i]);
            }
        }
    }

    /// The peer's link, built if it has none. `None` when the peer is left
    /// untouched.
    fn link(&mut self, peer: SocketAddr, now: Instant) -> Option<&mut Peer> {
        self.sweep(now);
        if let Some((_, seen)) = self.overrides.get_mut(&peer) {
            *seen = now;
        }
        if !self.peers.contains_key(&peer) {
            let (profile, seed, own) = self.profile_for(peer, self.next_ordinal)?;
            // Validated when it was stored, so this cannot fail.
            let link = Link::build(profile, seed, own).ok()?;
            let ordinal = (!own).then_some(self.next_ordinal);
            if !own {
                self.next_ordinal += 1;
            }
            self.peers.insert(
                peer,
                Peer { ordinal, link, last_seen: now, stats: Stats::default(), backlog: [0, 0] },
            );
        }
        let p = self.peers.get_mut(&peer)?;
        p.last_seen = now;
        Some(p)
    }

    /// Drop links and per-peer profiles idle for longer than the timeout, at
    /// most a few times per timeout.
    fn sweep(&mut self, now: Instant) {
        let every = self.idle_timeout / 4;
        if self.last_sweep.is_some_and(|at| now.saturating_duration_since(at) < every) {
            return;
        }
        self.last_sweep = Some(now);
        let timeout = self.idle_timeout;
        let idle: Vec<SocketAddr> = self
            .peers
            .iter()
            .filter(|(_, p)| now.saturating_duration_since(p.last_seen) >= timeout)
            .map(|(a, _)| *a)
            .collect();
        for a in idle {
            self.remove_peer(a);
        }
        self.overrides.retain(|_, (_, seen)| now.saturating_duration_since(*seen) < timeout);
    }
}

impl ImpairHandle {
    /// Arm the socket with a validated profile. Every peer the filter admits
    /// gets its own link running it, from sequence 0 and tick 0.
    ///
    /// A refusal leaves whatever was armed before still running. Peers armed or
    /// disarmed individually keep their own setting.
    pub fn arm(&self, profile: ImpairProfile) -> Result<(), ProfileError> {
        profile.validate()?;
        let mut core = lock(&self.shared.core);
        let mut rebuilt = Vec::new();
        for (addr, peer) in &core.peers {
            if peer.link.own {
                continue;
            }
            let admitted = match &profile.peers {
                PeerFilter::All => true,
                PeerFilter::Only(addrs) => addrs.contains(addr),
            };
            let link = if admitted {
                let ordinal = peer.ordinal.unwrap_or_default();
                Some(Link::build(&profile, peer_seed(profile.seed, ordinal), false)?)
            } else {
                None
            };
            rebuilt.push((*addr, link));
        }
        for (addr, link) in rebuilt {
            match link {
                Some(link) => {
                    if let Some(p) = core.peers.get_mut(&addr) {
                        p.link = link;
                    }
                }
                None => core.remove_peer(addr),
            }
        }
        core.profile = Some(profile);
        Ok(())
    }

    /// Stop impairing every peer that inherits the socket profile. Peers armed
    /// with [`ImpairHandle::arm_peer`] keep their profile.
    ///
    /// The counters and the recorded decisions survive.
    pub fn disarm(&self) {
        let mut core = lock(&self.shared.core);
        core.profile = None;
        let inherited: Vec<SocketAddr> =
            core.peers.iter().filter(|(_, p)| !p.link.own).map(|(a, _)| *a).collect();
        for a in inherited {
            core.remove_peer(a);
        }
    }

    /// Whether the socket-wide profile is armed.
    pub fn is_armed(&self) -> bool {
        lock(&self.shared.core).profile.is_some()
    }

    /// Give one peer its own profile, replacing the socket-wide one for it.
    /// The peer's link restarts at sequence 0 and tick 0, seeded with the
    /// profile's own seed. The profile's peer filter is not consulted.
    ///
    /// Dropped once the peer has been idle for the peer idle timeout.
    pub fn arm_peer(&self, peer: SocketAddr, profile: ImpairProfile) -> Result<(), ProfileError> {
        profile.validate()?;
        let link = Link::build(&profile, profile.seed, true)?;
        let now = Instant::now();
        let mut core = lock(&self.shared.core);
        core.overrides.insert(peer, (Override::Armed(Box::new(profile)), now));
        match core.peers.get_mut(&peer) {
            Some(p) => {
                p.link = link;
                p.last_seen = now;
            }
            None => {
                core.peers.insert(
                    peer,
                    Peer {
                        ordinal: None,
                        link,
                        last_seen: now,
                        stats: Stats::default(),
                        backlog: [0, 0],
                    },
                );
            }
        }
        Ok(())
    }

    /// Leave one peer untouched, whatever the socket-wide profile says.
    ///
    /// Dropped once the peer has been idle for the peer idle timeout.
    pub fn disarm_peer(&self, peer: SocketAddr) {
        let mut core = lock(&self.shared.core);
        core.overrides.insert(peer, (Override::Disarmed, Instant::now()));
        core.remove_peer(peer);
    }

    /// Return one peer to the socket-wide profile and forget its link. Its
    /// next datagram builds a fresh one.
    pub fn clear_peer(&self, peer: SocketAddr) {
        let mut core = lock(&self.shared.core);
        core.overrides.remove(&peer);
        core.remove_peer(peer);
    }

    /// How long a peer may send and receive nothing before its link is
    /// dropped. Default [`DEFAULT_PEER_IDLE_TIMEOUT`].
    pub fn set_peer_idle_timeout(&self, timeout: Duration) {
        lock(&self.shared.core).idle_timeout = timeout;
    }

    /// The peers with a live link right now.
    pub fn peers(&self) -> Vec<SocketAddr> {
        lock(&self.shared.core).peers.keys().copied().collect()
    }

    /// Re-seed every peer that inherits the socket profile, and the profile
    /// itself so later peers use the new seed. Queues, buckets, numbering and
    /// statistics are left alone. A no-op while disarmed.
    pub fn reseed(&self, seed: u64) {
        let mut core = lock(&self.shared.core);
        let Some(profile) = core.profile.as_mut() else {
            return;
        };
        profile.seed = seed;
        for peer in core.peers.values_mut().filter(|p| !p.link.own) {
            let s = peer_seed(seed, peer.ordinal.unwrap_or_default());
            peer.link.downlink.reseed(s);
            peer.link.uplink.reseed(s);
        }
    }

    /// Every peer's counters, folded together. Takes no lock.
    ///
    /// A snapshot taken while datagrams are in flight is not a consistent cut.
    pub fn stats(&self) -> StatsSnapshot {
        self.shared.stats.snapshot()
    }

    /// One peer's decision counters, while it has a live link. The release
    /// counters are kept only socket-wide and read zero here.
    pub fn peer_stats(&self, peer: SocketAddr) -> Option<StatsSnapshot> {
        lock(&self.shared.core).peers.get(&peer).map(|p| p.stats.snapshot())
    }

    /// Record every decision. Off by default.
    pub fn record_decisions(&self, on: bool) {
        self.shared.recording.store(on, Relaxed);
    }

    /// Take one peer's recorded decisions, leaving an empty log behind.
    pub fn take_log(&self, peer: SocketAddr) -> DecisionLog {
        lock(&self.shared.core).logs.remove(&peer).unwrap_or_default()
    }

    /// Take every peer's recorded decisions, ordered by address.
    pub fn take_logs(&self) -> Vec<(SocketAddr, DecisionLog)> {
        let mut logs: Vec<_> =
            std::mem::take(&mut lock(&self.shared.core).logs).into_iter().collect();
        logs.sort_by_key(|(a, _)| *a);
        logs
    }
}

/// The seam the socket decorator drives this state through.
#[allow(dead_code)]
impl ImpairHandle {
    /// A handle with nothing armed.
    pub(crate) fn detached() -> Self {
        ImpairHandle { shared: Arc::new(Shared::default()) }
    }

    /// Whether any peer can be impaired: the socket is armed or some peer has
    /// a profile of its own.
    pub(crate) fn is_impairing(&self) -> bool {
        let core = lock(&self.shared.core);
        core.profile.is_some()
            || core.overrides.values().any(|(o, _)| matches!(o, Override::Armed(_)))
    }

    /// The peer's tick, building its link if it has none. `None` means the
    /// peer is left untouched.
    pub(crate) fn begin(&self, peer: SocketAddr) -> Option<Tick> {
        let now = Instant::now();
        let mut core = lock(&self.shared.core);
        let p = core.link(peer, now)?;
        let elapsed = now.saturating_duration_since(p.link.origin).as_nanos();
        Some(Tick(u64::try_from(elapsed).unwrap_or(u64::MAX)))
    }

    /// Decide about one datagram of this peer, count it and record it. `None`
    /// when the peer is left untouched.
    pub(crate) fn decide(
        &self,
        peer: SocketAddr,
        dir: Direction,
        wire_bytes: u32,
        now: Tick,
    ) -> Option<Decision> {
        let recording = self.shared.recording.load(Relaxed);
        let mut core = lock(&self.shared.core);
        let p = core.link(peer, Instant::now())?;
        let i = dir as usize;
        let seq = p.link.seq[i];
        p.link.seq[i] += 1;
        let engine = match dir {
            Direction::Downlink => &mut p.link.downlink,
            Direction::Uplink => &mut p.link.uplink,
        };
        let decision = engine.decide(seq, wire_bytes, now);
        p.stats.record(dir, wire_bytes, &decision);
        let before = std::mem::replace(&mut p.backlog[i], decision.queue_backlog_bytes);
        core.backlog[i] =
            core.backlog[i].saturating_sub(before).saturating_add(decision.queue_backlog_bytes);
        let total = Decision { queue_backlog_bytes: core.backlog[i], ..decision };
        if recording {
            core.logs.entry(peer).or_default().push(dir, seq, wire_bytes, now, &decision);
        }
        drop(core);
        self.shared.stats.record(dir, wire_bytes, &total);
        Some(decision)
    }

    /// The bound on held bytes for this peer and direction.
    pub(crate) fn queue_bytes(&self, peer: SocketAddr, dir: Direction) -> u64 {
        match lock(&self.shared.core).peers.get(&peer) {
            Some(p) => p.link.queue_bytes[dir as usize],
            None => DEFAULT_QUEUE_BYTES,
        }
    }

    /// Fold one release-path wake-up into the counters.
    pub(crate) fn record_release(&self, batch: u32, scheduled: Tick, observed: Tick) {
        self.shared.stats.record_release(batch, scheduled, observed);
    }

    /// Count a received datagram discarded because its peer's held queue was
    /// full.
    pub(crate) fn record_ingress_overflow(&self, peer: SocketAddr) {
        self.shared.stats.record_ingress_overflow();
        if let Some(p) = lock(&self.shared.core).peers.get(&peer) {
            p.stats.record_ingress_overflow();
        }
    }
}

/// One direction's bound on held bytes: the rate model's queue when there is
/// one, so the shim and the engine agree on its depth.
fn queue_bound(profile: &DirectionProfile) -> u64 {
    match profile.rate {
        Some(rate) => rate.queue_bytes,
        None => DEFAULT_QUEUE_BYTES,
    }
}

/// Lock, recovering from a previous panic: nothing behind these locks can be
/// left unsafe to read, and a poisoned lock would kill the socket.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Verdict;
    use crate::model::{DelayModel, DupModel, LossModel, Prob, RateModel, ReorderModel};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    /// Drops every third datagram of both directions.
    fn every_third() -> ImpairProfile {
        let third = || DirectionProfile {
            loss: Some(LossModel::EveryNth { n: 3 }),
            ..DirectionProfile::default()
        };
        ImpairProfile { downlink: third(), uplink: third(), seed: 7, ..ImpairProfile::default() }
    }

    fn dropped_indices(
        handle: &ImpairHandle,
        peer: SocketAddr,
        dir: Direction,
        n: u64,
    ) -> Vec<u64> {
        (0..n)
            .filter(|_| {
                handle.decide(peer, dir, 1_200, Tick(0)).expect("armed").verdict == Verdict::Drop
            })
            .collect()
    }

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

    #[test]
    fn a_refused_profile_leaves_the_previous_one_armed() {
        let handle = ImpairHandle::detached();
        handle.arm(every_third()).expect("a valid profile");
        let p = addr(1);
        handle.begin(p).expect("armed");

        let bad = ImpairProfile {
            uplink: DirectionProfile {
                reorder: Some(ReorderModel { gap: 4, p: Prob::from_ppb(500_000_000) }),
                ..DirectionProfile::default()
            },
            ..ImpairProfile::default()
        };
        assert_eq!(handle.arm(bad), Err(ProfileError::ReorderWithoutDelay));

        assert_eq!(dropped_indices(&handle, p, Direction::Downlink, 15), vec![2, 5, 8, 11, 14]);
        assert_eq!(handle.stats().dropped_loss, 5);
    }

    #[test]
    fn arming_restarts_each_peer_at_sequence_zero() {
        let handle = ImpairHandle::detached();
        handle.arm(every_third()).expect("a valid profile");
        let p = addr(1);
        for _ in 0..4 {
            handle.decide(p, Direction::Downlink, 1_200, Tick(0));
            handle.decide(p, Direction::Uplink, 1_200, Tick(0));
        }
        handle.arm(every_third()).expect("a valid profile");

        for dir in [Direction::Downlink, Direction::Uplink] {
            assert_eq!(dropped_indices(&handle, p, dir, 15), vec![2, 5, 8, 11, 14], "{dir:?}");
        }
    }

    #[test]
    fn disarming_stops_deciding_and_keeps_the_counters() {
        let handle = ImpairHandle::detached();
        handle.arm(every_third()).expect("a valid profile");
        let p = addr(1);
        for _ in 0..9 {
            handle.decide(p, Direction::Downlink, 1_200, Tick(0));
        }
        let before = handle.stats();
        assert_eq!(before.datagrams_seen, 9);
        assert_eq!(before.dropped_loss, 3);

        handle.disarm();
        assert!(handle.decide(p, Direction::Downlink, 1_200, Tick(0)).is_none());
        assert!(handle.begin(p).is_none());
        assert_eq!(handle.stats(), before);
    }

    /// Two handles with identical histories, one re-seeded: the first index at
    /// which they differ is attributable to the re-seed alone.
    #[test]
    fn reseeding_changes_the_next_draw_at_a_named_index() {
        let coin = || ImpairProfile {
            downlink: DirectionProfile {
                dup: Some(DupModel { p: Prob::from_ppb(500_000_000) }),
                ..DirectionProfile::default()
            },
            seed: 11,
            ..ImpairProfile::default()
        };
        let p = addr(1);
        let run = |handle: &ImpairHandle, n: usize| -> Vec<bool> {
            (0..n)
                .map(|_| {
                    handle
                        .decide(p, Direction::Downlink, 1_200, Tick(0))
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
        assert_eq!(run(&untouched, 24), run(&reseeded, 24));

        reseeded.reseed(12);

        let first_diff =
            run(&untouched, 24).iter().zip(run(&reseeded, 24).iter()).position(|(a, b)| a != b);
        assert_eq!(first_diff, Some(0));
        assert_eq!(reseeded.stats().datagrams_seen, 48, "a re-seed is not a re-arm");
    }

    #[test]
    fn reseeding_while_disarmed_changes_nothing() {
        let handle = ImpairHandle::detached();
        handle.reseed(999);
        assert!(!handle.is_armed());
        assert_eq!(handle.stats(), StatsSnapshot::default());
    }

    #[test]
    fn the_peer_filter_answers_from_the_armed_profile() {
        let one = addr(4433);
        let other = addr(4434);

        let handle = ImpairHandle::detached();
        assert!(handle.begin(one).is_none(), "a disarmed socket impairs nobody");

        handle.arm(every_third()).expect("a valid profile");
        assert!(handle.begin(one).is_some(), "the default filter is every peer");

        handle
            .arm(ImpairProfile { peers: PeerFilter::Only(vec![one]), ..every_third() })
            .expect("a valid profile");
        assert!(handle.begin(one).is_some());
        assert!(handle.begin(other).is_none());
    }

    #[test]
    fn the_queue_bound_follows_each_directions_rate_model() {
        let handle = ImpairHandle::detached();
        let p = addr(1);
        assert_eq!(handle.queue_bytes(p, Direction::Downlink), DEFAULT_QUEUE_BYTES);

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
        handle.begin(p).expect("armed");

        assert_eq!(handle.queue_bytes(p, Direction::Downlink), 24_000);
        assert_eq!(handle.queue_bytes(p, Direction::Uplink), DEFAULT_QUEUE_BYTES);
    }

    #[test]
    fn the_tick_origin_is_when_the_peers_link_was_built() {
        let handle = ImpairHandle::detached();
        let p = addr(1);
        assert_eq!(handle.begin(p), None);

        handle.arm(every_third()).expect("a valid profile");
        let tick = handle.begin(p).expect("armed");
        assert!(tick.0 < 1_000_000_000, "{tick:?}");
    }

    #[test]
    fn recording_is_off_by_default_and_kept_per_peer() {
        let handle = ImpairHandle::detached();
        handle.arm(every_third()).expect("a valid profile");
        let (a, b) = (addr(1), addr(2));
        for _ in 0..8 {
            handle.decide(a, Direction::Downlink, 1_200, Tick(0));
        }
        assert_eq!(handle.take_log(a), DecisionLog::default());

        handle.record_decisions(true);
        for _ in 0..3 {
            handle.decide(a, Direction::Downlink, 1_200, Tick(0));
        }
        handle.decide(b, Direction::Downlink, 1_200, Tick(0));
        handle.disarm();
        assert_eq!(handle.take_log(a).records().len(), 3, "a disarm keeps the records");
        assert_eq!(handle.take_log(b).records().len(), 1);
        assert!(handle.take_log(a).records().is_empty(), "taking empties it");
    }

    /// The first peer runs the profile's own seed; the second runs a
    /// different, reproducible one.
    #[test]
    fn each_peer_draws_from_its_own_stream() {
        let coin = ImpairProfile {
            downlink: DirectionProfile {
                loss: Some(LossModel::Bernoulli { p: Prob::from_ppb(500_000_000) }),
                ..DirectionProfile::default()
            },
            seed: 5,
            ..ImpairProfile::default()
        };
        let draws = |handle: &ImpairHandle, p: SocketAddr| -> Vec<bool> {
            (0..64)
                .map(|_| {
                    handle.decide(p, Direction::Downlink, 1_200, Tick(0)).expect("armed").verdict
                        == Verdict::Drop
                })
                .collect()
        };
        let solo = |seed: u64| -> Vec<bool> {
            let mut e =
                Impairer::new(coin.downlink.clone(), seed, Direction::Downlink).expect("valid");
            (0..64).map(|seq| e.decide(seq, 1_200, Tick(0)).verdict == Verdict::Drop).collect()
        };

        let handle = ImpairHandle::detached();
        handle.arm(coin.clone()).expect("a valid profile");
        let (a, b) = (addr(1), addr(2));
        handle.begin(a);
        handle.begin(b);
        let (da, db) = (draws(&handle, a), draws(&handle, b));
        assert_eq!(da, solo(5), "the first peer is the profile's own run");
        assert_eq!(db, solo(peer_seed(5, 1)), "the second is reproducible from its ordinal");
        assert_ne!(da, db);
    }

    /// A peer's own profile leaves every other peer's link as it was.
    #[test]
    fn a_peer_profile_leaves_the_other_peers_alone() {
        let handle = ImpairHandle::detached();
        handle.arm(every_third()).expect("a valid profile");
        let (a, b) = (addr(1), addr(2));
        for _ in 0..4 {
            handle.decide(a, Direction::Downlink, 1_200, Tick(0));
            handle.decide(b, Direction::Downlink, 1_200, Tick(0));
        }

        let slow = ImpairProfile {
            downlink: DirectionProfile {
                delay: Some(DelayModel::Fixed { mean_ns: 50_000_000 }),
                ..DirectionProfile::default()
            },
            seed: 1,
            ..ImpairProfile::default()
        };
        handle.arm_peer(a, slow).expect("a valid profile");

        let d = handle.decide(a, Direction::Downlink, 1_200, Tick(0)).expect("armed");
        assert_eq!(d.release, Tick(50_000_000), "the override is in force");
        // b continues its own numbering: datagrams 4.. of every-third drop at 5, 8.
        assert_eq!(dropped_indices(&handle, b, Direction::Downlink, 6), vec![1, 4]);

        handle.disarm_peer(a);
        assert!(handle.begin(a).is_none());
        assert!(handle.begin(b).is_some());
        handle.disarm();
        handle.clear_peer(a);
        assert!(handle.begin(a).is_none(), "cleared and the socket is disarmed");
    }

    #[test]
    fn an_armed_peer_is_impaired_on_a_disarmed_socket() {
        let handle = ImpairHandle::detached();
        let a = addr(1);
        assert!(!handle.is_impairing());
        handle.arm_peer(a, every_third()).expect("a valid profile");
        assert!(handle.is_impairing());
        assert!(!handle.is_armed());
        assert!(handle.begin(a).is_some());
        assert!(handle.begin(addr(2)).is_none());
    }

    #[test]
    fn an_idle_link_is_dropped_and_rebuilt() {
        let handle = ImpairHandle::detached();
        handle.arm(every_third()).expect("a valid profile");
        handle.set_peer_idle_timeout(Duration::from_millis(20));
        let (a, b) = (addr(1), addr(2));
        for _ in 0..2 {
            handle.decide(a, Direction::Downlink, 1_200, Tick(0));
        }
        std::thread::sleep(Duration::from_millis(40));
        handle.begin(b);
        assert_eq!(handle.peers(), vec![b], "the idle peer's link is gone");
        assert_eq!(
            dropped_indices(&handle, a, Direction::Downlink, 3),
            vec![2],
            "and restarts at 0"
        );
    }

    #[test]
    fn an_idle_peers_own_profile_is_dropped_with_its_link() {
        let handle = ImpairHandle::detached();
        handle.arm(every_third()).expect("a valid profile");
        handle.set_peer_idle_timeout(Duration::from_millis(20));
        let (armed, disarmed, other) = (addr(1), addr(2), addr(3));
        let slow = ImpairProfile {
            downlink: DirectionProfile {
                delay: Some(DelayModel::Fixed { mean_ns: 50_000_000 }),
                ..DirectionProfile::default()
            },
            ..ImpairProfile::default()
        };
        handle.arm_peer(armed, slow).expect("a valid profile");
        handle.disarm_peer(disarmed);
        assert!(handle.begin(disarmed).is_none());

        std::thread::sleep(Duration::from_millis(40));
        handle.begin(other);

        for p in [armed, disarmed] {
            assert_eq!(
                dropped_indices(&handle, p, Direction::Downlink, 3),
                vec![2],
                "{p} inherits the socket profile"
            );
        }
    }

    #[test]
    fn a_peer_seen_within_the_timeout_keeps_its_own_profile() {
        let handle = ImpairHandle::detached();
        handle.arm(every_third()).expect("a valid profile");
        handle.set_peer_idle_timeout(Duration::from_millis(60));
        let p = addr(1);
        handle.disarm_peer(p);
        for _ in 0..4 {
            std::thread::sleep(Duration::from_millis(20));
            assert!(handle.begin(p).is_none(), "still left untouched");
        }
    }

    #[test]
    fn a_peer_given_its_own_profile_takes_no_ordinal() {
        let coin = ImpairProfile {
            downlink: DirectionProfile {
                loss: Some(LossModel::Bernoulli { p: Prob::from_ppb(500_000_000) }),
                ..DirectionProfile::default()
            },
            seed: 5,
            ..ImpairProfile::default()
        };
        let handle = ImpairHandle::detached();
        handle.arm(coin.clone()).expect("a valid profile");
        handle.arm_peer(addr(9), every_third()).expect("a valid profile");
        let p = addr(1);
        let got: Vec<bool> = (0..64)
            .map(|_| {
                handle.decide(p, Direction::Downlink, 1_200, Tick(0)).expect("armed").verdict
                    == Verdict::Drop
            })
            .collect();
        let mut e = Impairer::new(coin.downlink, 5, Direction::Downlink).expect("valid");
        let solo: Vec<bool> =
            (0..64).map(|seq| e.decide(seq, 1_200, Tick(0)).verdict == Verdict::Drop).collect();
        assert_eq!(got, solo, "the first inheriting peer runs the profile's own seed");
    }

    #[test]
    fn the_aggregate_backlog_adds_every_peers() {
        let shaped = ImpairProfile {
            downlink: DirectionProfile {
                rate: Some(RateModel { bps: 8_000, burst_bytes: 1_500, queue_bytes: 100_000 }),
                ..DirectionProfile::default()
            },
            ..ImpairProfile::default()
        };
        let handle = ImpairHandle::detached();
        handle.arm(shaped).expect("a valid profile");
        let (a, b) = (addr(1), addr(2));
        for _ in 0..3 {
            handle.decide(a, Direction::Downlink, 1_200, Tick(0));
            handle.decide(b, Direction::Downlink, 1_200, Tick(0));
        }
        let pa = handle.peer_stats(a).expect("live").queue_backlog_bytes;
        let pb = handle.peer_stats(b).expect("live").queue_backlog_bytes;
        assert!(pa > 0);
        assert_eq!(pa, pb, "same profile, same traffic, separate queues");
        assert_eq!(handle.stats().queue_backlog_bytes, pa + pb);
    }
}

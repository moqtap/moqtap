//! Profiles, the timeline, the named presets, and the validation that refuses
//! a profile this crate cannot honour.
//!
//! A profile is refused at construction or it is honoured; there is no third
//! state in which an impairment is accepted, counted, logged and then quietly
//! not delivered. Every construction path runs [`ImpairProfile::validate`]
//! before anything is armed, and [`ProfileError`] names two families:
//!
//! **Bucket configurations that cannot be honoured.** A rate model with
//! `bps: 0`, `queue_bytes: 0`, or a `burst_bytes` below one on-wire datagram
//! drops every datagram through the queue-full path, reporting a full queue
//! whose recorded backlog is zero. Keeping "dropped by the loss model" and
//! "dropped because the queue was full" distinct is the only reason to have a
//! rate model rather than another probability. A profile that means "drop
//! everything" says so with a [`crate::model::LossModel`].
//!
//! **Impairments that are configured and can never fire.** A zero-length
//! blackout window, a reorder gap of zero, an `EveryNth` period of zero, a peer
//! filter that lists no peers. Each reads at the call site like the impairment
//! being switched on, each fires on nothing, and none produces any diagnostic
//! at run time — the run comes back clean and is believed.

use crate::model::{
    CorruptModel, DelayModel, DupModel, LossModel, Prob, RateModel, ReorderModel, Window,
};

/// The largest on-wire datagram a direction is assumed to carry when it does
/// not say otherwise, in bytes.
///
/// A standard 1500-byte Ethernet MTU is the on-wire size, headers included, of
/// the largest datagram a normal path will carry — 1472 bytes of payload to a
/// v4 peer, 1452 to a v6 one. It is used for exactly one purpose: deciding
/// whether a token bucket is deep enough to ever grant a full-size packet.
///
/// A direction that sets `mtu_blackhole` has already declared the largest
/// datagram it will forward, and that number is used instead. That is not a
/// refinement for its own sake — using the fixed 1500 for a direction whose
/// `mtu_blackhole` is 1200 would refuse a bucket of 1300, which that direction
/// can honour perfectly well, and refusing a deliverable configuration is the
/// mirror image of the mistake this module exists to prevent.
const ASSUMED_PATH_WIRE_BYTES: u64 = 1500;

/// Everything one direction's engine is configured with.
///
/// The default is a direction with no impairment at all: every model `None`,
/// no blackouts, no timeline. That is deliberate, because it makes
/// `DirectionProfile { loss: Some(..), ..Default::default() }` the natural way
/// to write a one-model profile, and a one-model profile is what an ablation
/// needs.
///
/// The same reasoning is why the written form defaults every field: a file
/// naming only `loss` is a one-model profile, and having to spell out eight
/// `null`s to write one would make the useful case the awkward one. Every key
/// that is *not* one of these nine is refused rather than skipped — see the
/// crate documentation for why a silently ignored key is the worst outcome
/// available here.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case", default, deny_unknown_fields))]
pub struct DirectionProfile {
    /// Token bucket plus a bounded byte queue.
    pub rate: Option<RateModel>,
    /// How long a datagram is held.
    pub delay: Option<DelayModel>,
    /// How datagrams are selected for loss.
    pub loss: Option<LossModel>,
    /// Reordering. Requires `delay`, and says so at construction time rather
    /// than doing nothing at run time.
    pub reorder: Option<ReorderModel>,
    /// Duplication.
    pub dup: Option<DupModel>,
    /// Single-bit corruption.
    pub corrupt: Option<CorruptModel>,
    /// Drop any datagram whose ON-WIRE size exceeds this. On-wire, not
    /// payload, so that this threshold and the rate model's byte accounting
    /// can never disagree about the same packet.
    pub mtu_blackhole: Option<u16>,
    /// Drop everything inside each half-open window. Windows may overlap and
    /// are not merged.
    pub blackouts: Vec<Window>,
    /// Steps that replace this profile wholesale at a tick boundary. `at_ns`
    /// must be strictly increasing, and the first step must be past 0.
    pub timeline: Vec<TimelineStep>,
}

/// One wholesale profile replacement at a tick boundary.
///
/// Both fields are required in the written form. A step whose `at-ns` was
/// omitted would land at tick 0 and be refused by validation, which is the
/// right answer arrived at by the wrong route: the reader would be told the
/// timeline starts too early rather than that a key is missing.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case", deny_unknown_fields))]
pub struct TimelineStep {
    /// When the step takes effect, nanoseconds since arm.
    ///
    /// Must be greater than 0 for the first step: a step at tick 0 replaces
    /// the profile before a single datagram has been decided by it, so the
    /// profile the caller wrote is never the profile that ran, and nothing
    /// says so.
    pub at_ns: u64,
    /// The profile that replaces the current one. May not carry a timeline of
    /// its own — see [`ProfileError::NestedTimeline`].
    pub profile: Box<DirectionProfile>,
}

/// Both directions, the peer filter and the seed.
///
/// # Reading one from a file
///
/// Under the `serde` feature this is the type a configuration deserializes
/// into, and the reason the derive lives in this crate rather than in the one
/// that wants it: the orphan rule permits `impl serde::Deserialize for
/// ImpairProfile` nowhere else.
///
/// Deserializing does **not** validate. Serde builds the value; the standing
/// rule that a profile is refused or honoured is enforced by
/// [`ImpairProfile::validate`], which every construction path runs and which a
/// caller reading a file must run too — [`crate::control::ImpairHandle::arm`]
/// is the entry point that already does.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case", default, deny_unknown_fields))]
pub struct ImpairProfile {
    /// Proxy -> client.
    pub downlink: DirectionProfile,
    /// Client -> proxy.
    pub uplink: DirectionProfile,
    /// Which peers the socket layer applies the profile to.
    pub peers: PeerFilter,
    /// The one number every generator stream is seeded from. Two profiles that
    /// differ only here produce two different decision logs; everything else
    /// about a run is a pure function of this number and the models.
    pub seed: u64,
}

/// Which peers the SOCKET layer applies the profile to.
///
/// This never reaches the engine and never appears in the decision log, and
/// that is a decision rather than an oversight: an ephemeral port differs on
/// every run, and a dual-stack listener renders the same v4 peer as
/// `::ffff:a.b.c.d` on Linux and not at all on Windows. Either would make a
/// log that is supposed to be byte-identical across runs and platforms into
/// one that is not.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum PeerFilter {
    /// Every peer.
    #[default]
    All,
    /// Only these peers, by exact equality against the address the socket
    /// layer is handed for the datagram.
    ///
    /// An empty list is [`ProfileError::PeerFilterMatchesNothing`], and a list
    /// containing an address no peer can present — port 0, or the unspecified
    /// address — is [`ProfileError::PeerFilterEntryCannotMatch`]. An address
    /// that is well formed but simply absent from a given run is not
    /// detectable here and is accepted; the second of those two errors says
    /// what that leaves open.
    Only(Vec<std::net::SocketAddr>),
}

/// Why a profile was refused.
///
/// **Not `#[non_exhaustive]`, deliberately.** The exhaustiveness test for this
/// enum lives in `tests/`, which is a separate crate, and `#[non_exhaustive]`
/// forces a `_` arm into an exhaustive match made from outside the defining
/// crate. Once that arm exists, adding a fourteenth variant compiles green and
/// the test stops being an exhaustiveness check — which is the only thing it
/// is. The attribute would buy the freedom to add a variant without a
/// construction path, and a validation error nothing can trigger is
/// decoration.
///
/// **Thirteen variants**, and every one of them is reachable from a profile a
/// person could plausibly write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileError {
    /// A [`ReorderModel`] on a direction whose `delay` is `None`. Reordering
    /// works by letting one datagram skip the delay queue; with no delay there
    /// is no queue and the model cannot change an outcome. netem has the same
    /// dependency and reports nothing when it is unmet.
    ReorderWithoutDelay,
    /// `ReorderModel { gap: 0, .. }` — configured, and can never fire. It does
    /// not mean "reordering off"; `reorder: None` means that.
    ReorderGapZero,
    /// `LossModel::EveryNth { n: 0 }` — configured, and can never fire.
    EveryNthZero,
    /// Timeline steps whose `at_ns` is not strictly increasing. Two steps at
    /// the same tick have no defined winner, and a step that goes backwards
    /// can never be reached.
    TimelineNotIncreasing,
    /// A first timeline step at tick 0, which would replace the profile before
    /// it decided a single datagram.
    TimelineStepAtZero,
    /// A timeline step's profile carrying a timeline of its own. There is one
    /// schedule per direction, evaluated against the tick; a nested schedule
    /// has no defined origin — it is neither relative to arm nor to the step —
    /// so it is refused rather than given an arbitrary one.
    NestedTimeline,
    /// `Window { for_ns: 0, .. }` — an empty interval contains no instant, so
    /// the blackout is configured and can never fire.
    BlackoutZeroLength,
    /// `RateModel { queue_bytes: 0, .. }`.
    ///
    /// The queue's arrival test is `backlog + wire_bytes > queue_bytes`. At
    /// zero that is `0 + n > 0`, true for every datagram — so the profile
    /// drops 100% of traffic and reports every drop as a full queue whose
    /// recorded backlog is zero bytes. A profile that means "drop everything"
    /// says so with a [`crate::model::LossModel`].
    RateWithZeroQueue,
    /// `RateModel { bps: 0, .. }`. At a zero rate the bucket never accumulates
    /// a token, so no datagram is ever grantable — 100% loss, again reported
    /// as queue overflow on an empty queue.
    RateWithZeroBps,
    /// `RateModel` whose `burst_bytes` is below one on-wire datagram, carrying
    /// both numbers so the message can name them.
    ///
    /// The bucket can never grant a packet larger than its own depth, however
    /// long it waits. `RateModel { bps: 100_000_000, burst_bytes: 1000, .. }`
    /// is a plausible hand-written profile and it drops **every** 1400-byte
    /// datagram, blaming an empty queue. Refused at construction rather than
    /// mis-attributed on every packet at run time.
    RateBurstBelowDatagram {
        /// The configured bucket depth.
        burst_bytes: u64,
        /// The largest on-wire datagram this direction can forward, which is
        /// the smallest depth that can grant everything it will be asked to.
        min_wire_bytes: u64,
    },
    /// `PeerFilter::Only(v)` with an empty `v`, which can match no peer.
    ///
    /// The filter never reaches the engine and never reaches the decision log,
    /// so "0 datagrams matched the filter" is otherwise indistinguishable from
    /// "the profile did nothing" — there is no counter anywhere that would
    /// tell the two apart.
    PeerFilterMatchesNothing,
    /// `PeerFilter::Only(v)` listing an address no peer can ever present,
    /// carrying that address so the message can name it.
    ///
    /// Matching is exact equality against the address `recv_from` reported for
    /// the datagram, so an entry that is not a form `recv_from` can produce is
    /// dead weight in the list: configured, indistinguishable from a working
    /// entry when the profile is printed back, and matched by nothing. Two
    /// forms are refused, and they are the only two decidable without a peer
    /// in hand:
    ///
    /// * **Port 0.** It is the "assign me one" sentinel a socket binds with,
    ///   never a port a socket sends *from* — the assignment happens before
    ///   the first datagram leaves — and the wire reserves it besides.
    /// * **The unspecified address**, `0.0.0.0` or `::`. It is the wildcard a
    ///   listener binds to, meaning "every local interface"; it is not a place
    ///   a datagram comes from, and a peer that did present it could not be
    ///   replied to.
    ///
    /// # What this does not check
    ///
    /// Whether a peer at that address will ever appear. At construction time
    /// there is no peer, no socket and no run to compare against, so
    /// `203.0.113.9:4433` is accepted here and is still accepted when the only
    /// peer that ever connects is `203.0.113.8:4433` — the mistyped octet, the
    /// stale port from yesterday's run, the address of the wrong interface.
    /// This variant refuses the forms that are wrong on their face, and
    /// nothing more; a filter that names plausible addresses and matches none
    /// of them is a gap this crate does not close.
    PeerFilterEntryCannotMatch {
        /// The listed address that no peer can present.
        addr: std::net::SocketAddr,
    },
    /// A probability constructed from a float that was NaN. See
    /// [`crate::model::Prob::from_f64`]: the truncation that constructor
    /// performs turns NaN into 0, which is *drop nothing*.
    ProbabilityNotANumber,
}

/// Written by hand because this crate has no dependency it does not have to
/// have: the ones it has are optional and off by default, and none of them is
/// the usual derive macro. And it has to exist, because
/// [`ProfileError`] is the error type of four public `Result`-returning entry
/// points plus [`crate::model::Prob::from_f64`]. Without `Display` and
/// `std::error::Error`, no caller can `?` it into an application error and
/// nothing downstream can wrap it.
///
/// The strings are stable API. A test asserts the rendered text of every
/// variant rather than its discriminant, which is what makes "a validation
/// error nobody can trigger is decoration" a thing a test can check: a variant
/// with no construction path has no rendered string to compare against.
///
/// Lower case and no trailing period, matching the other error types in this
/// workspace, so that a wrapped message reads as one sentence.
impl std::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReorderWithoutDelay => {
                write!(f, "reorder model requires a delay model on the same direction")
            }
            Self::ReorderGapZero => {
                write!(f, "reorder gap is 0, which can never fire; use reorder: None")
            }
            Self::EveryNthZero => write!(f, "EveryNth n is 0, which can never fire"),
            Self::TimelineNotIncreasing => {
                write!(f, "timeline steps must have strictly increasing at_ns")
            }
            Self::TimelineStepAtZero => {
                write!(f, "the first timeline step must be at a tick greater than 0")
            }
            Self::NestedTimeline => {
                write!(f, "a timeline step's profile may not carry its own timeline")
            }
            Self::BlackoutZeroLength => {
                write!(f, "blackout window has for_ns 0, which can never fire")
            }
            Self::RateWithZeroQueue => write!(
                f,
                "rate model has queue_bytes 0, which tail-drops every datagram on an empty queue"
            ),
            Self::RateWithZeroBps => write!(
                f,
                "rate model has bps 0; a profile that drops everything says so with a loss model"
            ),
            Self::RateBurstBelowDatagram { burst_bytes, min_wire_bytes } => write!(
                f,
                "rate model burst_bytes {burst_bytes} is below one on-wire datagram of \
                 {min_wire_bytes} bytes"
            ),
            Self::PeerFilterMatchesNothing => {
                write!(f, "peer filter Only(..) is empty and can match no peer")
            }
            Self::PeerFilterEntryCannotMatch { addr } => write!(
                f,
                "peer filter entry {addr} can never match: a peer presents neither an \
                 unspecified address nor port 0"
            ),
            Self::ProbabilityNotANumber => {
                write!(f, "probability is NaN; Prob::from_f64 clamps out-of-range but refuses NaN")
            }
        }
    }
}

impl std::error::Error for ProfileError {}

impl DirectionProfile {
    /// Every construction path runs this. A profile that cannot be honoured is
    /// refused, never accepted-and-ignored.
    ///
    /// # Order
    ///
    /// Field-declaration order — rate, then loss, then reorder, then the
    /// blackout windows, then the timeline — and the first failure is
    /// returned. A profile with two mistakes reports the earlier field, and
    /// fixing it reveals the second; the order is fixed so that behaviour is
    /// repeatable rather than dependent on which check happened to be written
    /// first.
    ///
    /// Within the reorder pair, the missing-delay check comes before the
    /// zero-gap check, because a reorder model on a direction with no delay is
    /// inert regardless of its gap, so that is the more useful thing to be
    /// told.
    ///
    /// # The timeline is validated all the way down
    ///
    /// Each step's profile is checked with the same rules as the outer one.
    /// A profile whose step 3 carries a zero-`bps` rate model is refused now,
    /// at arm time, rather than at whatever wall-clock moment step 3 lands —
    /// which for a long timeline could be minutes into a run that has already
    /// produced output.
    ///
    /// The recursion is one level deep and cannot be more, because a step's
    /// profile carrying its own timeline is itself refused.
    pub fn validate(&self) -> Result<(), ProfileError> {
        self.validate_models()?;

        let mut previous: Option<u64> = None;
        for step in &self.timeline {
            match previous {
                None if step.at_ns == 0 => return Err(ProfileError::TimelineStepAtZero),
                Some(prev) if step.at_ns <= prev => {
                    return Err(ProfileError::TimelineNotIncreasing)
                }
                _ => {}
            }
            previous = Some(step.at_ns);

            if !step.profile.timeline.is_empty() {
                return Err(ProfileError::NestedTimeline);
            }
            step.profile.validate_models()?;
        }
        Ok(())
    }

    /// Everything in [`DirectionProfile::validate`] except the timeline
    /// itself, so that the same rules can be applied to a step's profile
    /// without recursing into a timeline that is not allowed to exist.
    fn validate_models(&self) -> Result<(), ProfileError> {
        if let Some(rate) = self.rate {
            if rate.bps == 0 {
                return Err(ProfileError::RateWithZeroBps);
            }
            if rate.queue_bytes == 0 {
                return Err(ProfileError::RateWithZeroQueue);
            }
            let min_wire_bytes = self.largest_on_wire_datagram();
            if rate.burst_bytes < min_wire_bytes {
                return Err(ProfileError::RateBurstBelowDatagram {
                    burst_bytes: rate.burst_bytes,
                    min_wire_bytes,
                });
            }
        }

        if matches!(self.loss, Some(LossModel::EveryNth { n: 0 })) {
            return Err(ProfileError::EveryNthZero);
        }

        if let Some(reorder) = self.reorder {
            if self.delay.is_none() {
                return Err(ProfileError::ReorderWithoutDelay);
            }
            if reorder.gap == 0 {
                return Err(ProfileError::ReorderGapZero);
            }
        }

        if self.blackouts.iter().any(|w| w.for_ns == 0) {
            return Err(ProfileError::BlackoutZeroLength);
        }

        Ok(())
    }

    /// The largest on-wire datagram this direction can ever forward, and
    /// therefore the shallowest token bucket that can grant everything the
    /// direction will be asked to send.
    ///
    /// A `mtu_blackhole` of N drops anything strictly larger than N, so N is
    /// exactly the answer when one is set.
    fn largest_on_wire_datagram(&self) -> u64 {
        match self.mtu_blackhole {
            Some(mtu) => u64::from(mtu),
            None => ASSUMED_PATH_WIRE_BYTES,
        }
    }
}

impl ImpairProfile {
    /// Validates both directions **and** the peer filter.
    ///
    /// Separate from [`DirectionProfile::validate`] because [`PeerFilter`] is
    /// not a direction field, and would otherwise be validated by nothing at
    /// all — which is how an empty filter reaches a run and silently impairs
    /// no traffic.
    ///
    /// # The filter is checked entry by entry, not just for emptiness
    ///
    /// A list with one unmatchable entry among good ones is refused, exactly
    /// as a direction with one zero-length blackout window among real ones is.
    /// The reasoning is the same in both places: the neighbouring good entries
    /// do not make the dead one visible, nothing at run time reports "entry 2
    /// matched nothing" — the filter never reaches the engine or the decision
    /// log — and a profile printed back names the dead entry in the same
    /// breath as the live ones. Refusing at construction is the only moment
    /// anything can say so.
    ///
    /// The counter-argument, that refusing a filter which would still have
    /// impaired its other peers rejects a deliverable configuration, is real
    /// and is answered by what the entry can be: a `0` port or a wildcard
    /// address in a peer list is not a narrower intention, it is a mistake
    /// with no other reading.
    pub fn validate(&self) -> Result<(), ProfileError> {
        self.downlink.validate()?;
        self.uplink.validate()?;
        match &self.peers {
            PeerFilter::All => Ok(()),
            PeerFilter::Only(addrs) if addrs.is_empty() => {
                Err(ProfileError::PeerFilterMatchesNothing)
            }
            PeerFilter::Only(addrs) => match addrs.iter().find(|a| no_peer_can_present(a)) {
                Some(addr) => Err(ProfileError::PeerFilterEntryCannotMatch { addr: *addr }),
                None => Ok(()),
            },
        }
    }
}

/// Whether this address is one no peer can ever present, and so one that a
/// peer filter listing it can never match.
///
/// Both tests are about the *form* of the address rather than about who is on
/// the network: they hold before a socket is bound, which is what makes them
/// answerable at construction time when the alternative — comparing against
/// the peers a run actually sees — is not. See
/// [`ProfileError::PeerFilterEntryCannotMatch`] for why each of the two can
/// never appear on the receiving side, and for the much larger class of
/// wrong-but-well-formed addresses this deliberately does not catch.
fn no_peer_can_present(addr: &std::net::SocketAddr) -> bool {
    addr.port() == 0 || addr.ip().is_unspecified()
}

/// A named scenario.
///
/// **Not `#[non_exhaustive]`**, for [`ProfileError`]'s reason applied one type
/// over: the tests that hold the presets stable enumerate *every* variant, and
/// from an external test crate `#[non_exhaustive]` would force a `_` arm into
/// that enumeration. An eighth preset would then ship exercised by nothing,
/// with no failing test to say so. This is a closed vocabulary of named
/// scenarios, not an extension point.
///
/// A closed vocabulary is exactly what a configuration file wants to name, so
/// the written form is the variant's own name in kebab-case — `lossy-edge`,
/// `datacentre-clean`. An unknown name is an error, and serde's message lists
/// the seven that exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum Preset {
    /// Mobile LTE: tens of milliseconds of correlated jitter, a modest uplink,
    /// and enough loss to make a retransmission strategy matter.
    Lte,
    /// Consumer Wi-Fi: short delays with a heavy tail from contention and MAC
    /// retries, and the occasional duplicate those retries produce.
    Wifi,
    /// Geostationary satellite: a quarter-second each way, a constrained
    /// uplink, and a reduced path MTU.
    Satellite,
    /// A lossy access edge: bursty loss from a Gilbert-Elliott chain, wide
    /// uniform jitter, reordering and the occasional corrupted bit.
    LossyEdge,
    /// A clean datacentre path — the control. No loss, no jitter, no reorder,
    /// no duplication, no corruption: only a fixed sub-millisecond delay and a
    /// gigabit bucket, so that a run against it isolates whatever the code
    /// under test does on its own.
    DatacentreClean,
    /// A 3G cellular link: around a fifth of a second each way with a long
    /// tail from radio-layer retransmission, a couple of megabits of capacity,
    /// and about one percent loss.
    ThreeG,
    /// A bufferbloated access link: a short hop in front of a queue deep
    /// enough to hold seconds of traffic at the rate that drains it, so the
    /// delay a bulk sender sees is the backlog it built rather than anything
    /// the delay model imposed.
    Bufferbloat,
}

/// Every preset, in declaration order.
///
/// The tests that hold the presets stable iterate **this** rather than a
/// hand-written list of their own, so a preset that arrives without whatever
/// those tests demand of it — validity on both directions, a seed and a pair
/// of directions no other preset already has, the right side of the
/// control/impaired split — is a failing test instead of a silent omission.
/// A list written out inside a test would go on describing the presets that
/// existed the day it was written.
///
/// # What a const array cannot do is check itself for exhaustiveness
///
/// A variant added to [`Preset`] forces a new arm in [`preset`], because that
/// `match` has no `_`. Nothing forces the variant in *here*: omit it and the
/// crate compiles, and every preset test passes having examined the seven that
/// are listed. The length assertion in the pairwise-distinctness test is the
/// second place the count is written down, so widening this array without
/// going to that test reddens it — enough to keep the array and the tests
/// moving together, not enough to notice a variant that reached neither.
pub const ALL_PRESETS: [Preset; 7] = [
    Preset::Lte,
    Preset::Wifi,
    Preset::Satellite,
    Preset::LossyEdge,
    Preset::DatacentreClean,
    Preset::ThreeG,
    Preset::Bufferbloat,
];

/// Presets are DATA, not behaviour.
///
/// The numbers are plausible rather than measured: they are the shape of each
/// network, not a recording of a particular one. What a caller can rely on is
/// that they do not move — a preset cited by name in a report has to mean the
/// same thing the next time somebody runs it, so a "harmless" retune of a rate
/// or a jitter is a deliberate change that is written down, not a tidy-up.
///
/// What *enforces* that is weaker than the paragraph above sounds, and saying
/// so here is the point of this one. The tests iterate [`ALL_PRESETS`] and
/// check validity, pairwise distinctness in both models and seed, and the
/// control/impaired split; a retune that leaves a preset valid and distinct
/// passes them all. There is deliberately no committed decision log per preset
/// to diff against: a fixture generated by running the code under test agrees
/// with that code by construction, including with a code path that decided
/// nothing at all.
pub fn preset(p: Preset) -> ImpairProfile {
    match p {
        Preset::Lte => lte(),
        Preset::Wifi => wifi(),
        Preset::Satellite => satellite(),
        Preset::LossyEdge => lossy_edge(),
        Preset::DatacentreClean => datacentre_clean(),
        Preset::ThreeG => three_g(),
        Preset::Bufferbloat => bufferbloat(),
    }
}

// ── preset data ─────────────────────────────────────────────────────────
//
// Units, so the numbers below read as the quantities they are: `bps` is bits
// per second, every byte count is ON-WIRE bytes, every duration is
// nanoseconds.
//
// Each preset carries a distinct seed. The value is arbitrary — the generator
// primes its state, so a small seed is not a weak one — but the distinctness
// is not: two presets sharing a seed would draw identical word sequences, and
// a run that compared them would be comparing two models against one stream.

/// One kibibyte, in bytes.
const KIB: u64 = 1024;
/// One mebibyte, in bytes.
const MIB: u64 = 1024 * 1024;
/// One millisecond, in nanoseconds.
const MS: u64 = 1_000_000;
/// One megabit per second, in bits per second.
const MBPS: u64 = 1_000_000;

/// A probability written as hundredths of a percent, which is the finest
/// granularity any preset below needs. `pct_hundredths(50)` is 0.5%.
const fn pct_hundredths(v: u32) -> Prob {
    Prob::from_ppb(v * 100_000)
}

fn lte() -> ImpairProfile {
    ImpairProfile {
        downlink: DirectionProfile {
            rate: Some(RateModel { bps: 40 * MBPS, burst_bytes: 64 * KIB, queue_bytes: 512 * KIB }),
            delay: Some(DelayModel::Normal { mean_ns: 45 * MS, sigma_ns: 12 * MS, rho: 64 }),
            loss: Some(LossModel::Bernoulli { p: pct_hundredths(50) }),
            reorder: Some(ReorderModel { gap: 64, p: pct_hundredths(200) }),
            ..DirectionProfile::default()
        },
        uplink: DirectionProfile {
            rate: Some(RateModel { bps: 12 * MBPS, burst_bytes: 32 * KIB, queue_bytes: 256 * KIB }),
            delay: Some(DelayModel::Normal { mean_ns: 50 * MS, sigma_ns: 18 * MS, rho: 64 }),
            loss: Some(LossModel::Bernoulli { p: pct_hundredths(80) }),
            reorder: Some(ReorderModel { gap: 64, p: pct_hundredths(200) }),
            ..DirectionProfile::default()
        },
        peers: PeerFilter::All,
        seed: 1,
    }
}

fn wifi() -> ImpairProfile {
    ImpairProfile {
        downlink: DirectionProfile {
            rate: Some(RateModel {
                bps: 90 * MBPS,
                burst_bytes: 128 * KIB,
                queue_bytes: 512 * KIB,
            }),
            delay: Some(DelayModel::Pareto { mean_ns: 6 * MS, sigma_ns: 3 * MS, rho: 32 }),
            loss: Some(LossModel::Bernoulli { p: pct_hundredths(20) }),
            reorder: Some(ReorderModel { gap: 128, p: pct_hundredths(100) }),
            dup: Some(DupModel { p: pct_hundredths(10) }),
            ..DirectionProfile::default()
        },
        uplink: DirectionProfile {
            rate: Some(RateModel { bps: 45 * MBPS, burst_bytes: 64 * KIB, queue_bytes: 256 * KIB }),
            delay: Some(DelayModel::Pareto { mean_ns: 7 * MS, sigma_ns: 4 * MS, rho: 32 }),
            loss: Some(LossModel::Bernoulli { p: pct_hundredths(20) }),
            reorder: Some(ReorderModel { gap: 128, p: pct_hundredths(100) }),
            dup: Some(DupModel { p: pct_hundredths(10) }),
            ..DirectionProfile::default()
        },
        peers: PeerFilter::All,
        seed: 2,
    }
}

fn satellite() -> ImpairProfile {
    ImpairProfile {
        downlink: DirectionProfile {
            rate: Some(RateModel { bps: 25 * MBPS, burst_bytes: 256 * KIB, queue_bytes: 2 * MIB }),
            // Fixed, not jittered: a geostationary hop's delay is dominated by
            // the speed of light over a fixed distance, and the variance a
            // real link shows comes from queueing, which the bucket below
            // already produces.
            delay: Some(DelayModel::Fixed { mean_ns: 280 * MS }),
            loss: Some(LossModel::Bernoulli { p: pct_hundredths(10) }),
            mtu_blackhole: Some(1400),
            ..DirectionProfile::default()
        },
        uplink: DirectionProfile {
            rate: Some(RateModel { bps: 3 * MBPS, burst_bytes: 64 * KIB, queue_bytes: 512 * KIB }),
            delay: Some(DelayModel::Fixed { mean_ns: 290 * MS }),
            loss: Some(LossModel::Bernoulli { p: pct_hundredths(10) }),
            mtu_blackhole: Some(1400),
            ..DirectionProfile::default()
        },
        peers: PeerFilter::All,
        seed: 3,
    }
}

fn lossy_edge() -> ImpairProfile {
    // Bursty rather than independent loss: `p` is the chance of entering the
    // bad state, `r` of leaving it, and the two per-state loss probabilities
    // are what make a burst a burst. An independent Bernoulli at the same mean
    // rate exercises a congestion controller quite differently, which is the
    // reason this preset exists alongside the others.
    let burst_loss = LossModel::GilbertElliott {
        p: pct_hundredths(200),
        r: pct_hundredths(4000),
        h: pct_hundredths(6000),
        one_minus_k: pct_hundredths(20),
    };
    ImpairProfile {
        downlink: DirectionProfile {
            rate: Some(RateModel { bps: 10 * MBPS, burst_bytes: 32 * KIB, queue_bytes: 128 * KIB }),
            delay: Some(DelayModel::Uniform { mean_ns: 35 * MS, jitter_ns: 20 * MS, rho: 0 }),
            loss: Some(burst_loss.clone()),
            reorder: Some(ReorderModel { gap: 32, p: pct_hundredths(500) }),
            corrupt: Some(CorruptModel { p: pct_hundredths(5) }),
            ..DirectionProfile::default()
        },
        uplink: DirectionProfile {
            rate: Some(RateModel { bps: 5 * MBPS, burst_bytes: 16 * KIB, queue_bytes: 64 * KIB }),
            delay: Some(DelayModel::Uniform { mean_ns: 40 * MS, jitter_ns: 25 * MS, rho: 0 }),
            loss: Some(burst_loss),
            reorder: Some(ReorderModel { gap: 32, p: pct_hundredths(500) }),
            corrupt: Some(CorruptModel { p: pct_hundredths(5) }),
            ..DirectionProfile::default()
        },
        peers: PeerFilter::All,
        seed: 4,
    }
}

fn datacentre_clean() -> ImpairProfile {
    // The control. Every stochastic model is off, so this preset's decision
    // log is a pure function of the arrival pattern — which is what makes it
    // usable as the "did anything change at all" baseline that the other six
    // are read against. It is not `DirectionProfile::default()`, because a
    // profile that impairs nothing at all would not exercise the release path
    // and would therefore not be a comparable run.
    let one_way = DirectionProfile {
        rate: Some(RateModel { bps: 1000 * MBPS, burst_bytes: MIB, queue_bytes: 4 * MIB }),
        delay: Some(DelayModel::Fixed { mean_ns: 250_000 }),
        ..DirectionProfile::default()
    };
    ImpairProfile { downlink: one_way.clone(), uplink: one_way, peers: PeerFilter::All, seed: 5 }
}

fn three_g() -> ImpairProfile {
    // The delay here is dominated by the radio scheduler and by the link
    // layer's own retransmissions rather than by distance, which gives a bulk
    // of roughly two hundred milliseconds with a long tail sitting on top of
    // it. That shape is what `ParetoNormal` renders and what neither a normal
    // nor a pareto arm produces on its own, and the tail is the reason to
    // reach for this preset at all: a sender tuned against this link's mean
    // and one tuned against its worst decile behave nothing alike.
    //
    // The correlation is high because consecutive datagrams on a cellular link
    // are scheduled by the same base station in the same radio conditions —
    // successive delays are not independent draws, and a profile that made
    // them independent would smooth away the very stretches this preset is
    // for.
    ImpairProfile {
        downlink: DirectionProfile {
            rate: Some(RateModel { bps: 3 * MBPS, burst_bytes: 32 * KIB, queue_bytes: 256 * KIB }),
            delay: Some(DelayModel::ParetoNormal { mean_ns: 180 * MS, sigma_ns: 60 * MS, rho: 96 }),
            loss: Some(LossModel::Bernoulli { p: pct_hundredths(100) }),
            reorder: Some(ReorderModel { gap: 32, p: pct_hundredths(300) }),
            ..DirectionProfile::default()
        },
        uplink: DirectionProfile {
            rate: Some(RateModel { bps: MBPS, burst_bytes: 16 * KIB, queue_bytes: 128 * KIB }),
            delay: Some(DelayModel::ParetoNormal { mean_ns: 220 * MS, sigma_ns: 90 * MS, rho: 96 }),
            loss: Some(LossModel::Bernoulli { p: pct_hundredths(150) }),
            reorder: Some(ReorderModel { gap: 32, p: pct_hundredths(300) }),
            ..DirectionProfile::default()
        },
        peers: PeerFilter::All,
        seed: 6,
    }
}

fn bufferbloat() -> ImpairProfile {
    // The delay of this preset is not in its delay model, and that is the
    // whole preset. What the delay model carries is the access hop alone, a
    // few milliseconds; everything above that is backlog the sender itself
    // created in a queue far deeper than the rate draining it — 4 MiB against
    // 20 Mbit/s is about 1.6 seconds of standing queue once a bulk sender
    // fills it, and the uplink's 2 MiB against 5 Mbit/s is about 3.3.
    //
    // Writing those seconds into the delay model instead would impose them on
    // an idle link too, and an idle link with seconds of delay is a satellite
    // hop, not a bufferbloated one. The distinction is the point: here the
    // delay appears only under load, disappears when the sender backs off, and
    // is therefore something a congestion controller can act on.
    //
    // The small Bernoulli loss is not what makes this link slow. It is the
    // residual loss a consumer access link carries whatever its queue is
    // doing, kept because a link whose only drops are tail drops would let a
    // receiver treat every loss as a queue signal — which is true here and is
    // not true of the network being imitated.
    ImpairProfile {
        downlink: DirectionProfile {
            rate: Some(RateModel { bps: 20 * MBPS, burst_bytes: 64 * KIB, queue_bytes: 4 * MIB }),
            delay: Some(DelayModel::Fixed { mean_ns: 8 * MS }),
            loss: Some(LossModel::Bernoulli { p: pct_hundredths(5) }),
            ..DirectionProfile::default()
        },
        uplink: DirectionProfile {
            rate: Some(RateModel { bps: 5 * MBPS, burst_bytes: 32 * KIB, queue_bytes: 2 * MIB }),
            delay: Some(DelayModel::Fixed { mean_ns: 10 * MS }),
            loss: Some(LossModel::Bernoulli { p: pct_hundredths(5) }),
            ..DirectionProfile::default()
        },
        peers: PeerFilter::All,
        seed: 7,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A direction with every model armed and every value sane.
    ///
    /// Used as the starting point for the refusal tests, so that each of them
    /// changes exactly one field. A refusal test built from
    /// `DirectionProfile::default()` would leave the other eight fields at
    /// `None` and would still pass against a `validate` that ignored them.
    fn healthy() -> DirectionProfile {
        DirectionProfile {
            rate: Some(RateModel { bps: 10 * MBPS, burst_bytes: 64 * KIB, queue_bytes: 256 * KIB }),
            delay: Some(DelayModel::Fixed { mean_ns: 10 * MS }),
            loss: Some(LossModel::EveryNth { n: 7 }),
            reorder: Some(ReorderModel { gap: 4, p: pct_hundredths(500) }),
            dup: Some(DupModel { p: pct_hundredths(100) }),
            corrupt: Some(CorruptModel { p: pct_hundredths(10) }),
            mtu_blackhole: Some(1400),
            blackouts: vec![Window { at_ns: 100 * MS, for_ns: 20 * MS }],
            timeline: vec![],
        }
    }

    /// The precondition every refusal test below depends on: a fully populated
    /// profile is accepted.
    ///
    /// Without it, `fn validate(&self) -> Result<(), ProfileError> { Err(..) }`
    /// would satisfy every other test in this module.
    #[test]
    fn a_fully_populated_healthy_profile_is_accepted() {
        assert_eq!(healthy().validate(), Ok(()));

        let both = ImpairProfile {
            downlink: healthy(),
            uplink: healthy(),
            peers: PeerFilter::All,
            seed: 77,
        };
        assert_eq!(both.validate(), Ok(()));
    }

    /// Each single-field mistake is refused, and the *rest* of the profile is
    /// left healthy so that the refusal can only have come from the field
    /// under test.
    ///
    /// The table form is not cosmetic: it is what makes "one mutation, one
    /// error" checkable at a glance, and it is why a `validate` that returned
    /// the same error for everything cannot pass — the expected errors are all
    /// different.
    #[test]
    fn one_bad_field_at_a_time_is_refused_with_that_field_s_error() {
        let cases: Vec<(&str, DirectionProfile, ProfileError)> = vec![
            (
                "rate with no bits per second",
                DirectionProfile {
                    rate: Some(RateModel { bps: 0, burst_bytes: 64 * KIB, queue_bytes: 256 * KIB }),
                    ..healthy()
                },
                ProfileError::RateWithZeroBps,
            ),
            (
                "rate with no queue",
                DirectionProfile {
                    rate: Some(RateModel { bps: 10 * MBPS, burst_bytes: 64 * KIB, queue_bytes: 0 }),
                    ..healthy()
                },
                ProfileError::RateWithZeroQueue,
            ),
            (
                "bucket shallower than one datagram",
                DirectionProfile {
                    rate: Some(RateModel { bps: 100 * MBPS, burst_bytes: 1000, queue_bytes: MIB }),
                    ..healthy()
                },
                ProfileError::RateBurstBelowDatagram { burst_bytes: 1000, min_wire_bytes: 1400 },
            ),
            (
                "every zeroth datagram",
                DirectionProfile { loss: Some(LossModel::EveryNth { n: 0 }), ..healthy() },
                ProfileError::EveryNthZero,
            ),
            (
                "reorder with no delay to jump",
                DirectionProfile { delay: None, ..healthy() },
                ProfileError::ReorderWithoutDelay,
            ),
            (
                "reorder every zeroth datagram",
                DirectionProfile {
                    reorder: Some(ReorderModel { gap: 0, p: pct_hundredths(500) }),
                    ..healthy()
                },
                ProfileError::ReorderGapZero,
            ),
            (
                "a blackout of no duration",
                DirectionProfile {
                    blackouts: vec![
                        Window { at_ns: 10 * MS, for_ns: 5 * MS },
                        Window { at_ns: 50 * MS, for_ns: 0 },
                    ],
                    ..healthy()
                },
                ProfileError::BlackoutZeroLength,
            ),
            (
                "a timeline that starts before the profile ran",
                DirectionProfile {
                    timeline: vec![TimelineStep {
                        at_ns: 0,
                        profile: Box::new(DirectionProfile::default()),
                    }],
                    ..healthy()
                },
                ProfileError::TimelineStepAtZero,
            ),
            (
                "a timeline that stands still",
                DirectionProfile {
                    timeline: vec![
                        TimelineStep {
                            at_ns: 100 * MS,
                            profile: Box::new(DirectionProfile::default()),
                        },
                        TimelineStep {
                            at_ns: 100 * MS,
                            profile: Box::new(DirectionProfile::default()),
                        },
                    ],
                    ..healthy()
                },
                ProfileError::TimelineNotIncreasing,
            ),
            (
                "a timeline inside a timeline",
                DirectionProfile {
                    timeline: vec![TimelineStep {
                        at_ns: 100 * MS,
                        profile: Box::new(DirectionProfile {
                            timeline: vec![TimelineStep {
                                at_ns: 200 * MS,
                                profile: Box::new(DirectionProfile::default()),
                            }],
                            ..DirectionProfile::default()
                        }),
                    }],
                    ..healthy()
                },
                ProfileError::NestedTimeline,
            ),
        ];

        for (name, profile, want) in cases {
            assert_eq!(profile.validate(), Err(want), "{name}");
        }
    }

    /// A timeline step's profile is validated with the same rules as the outer
    /// one, and the failure is reported now rather than when the step lands.
    ///
    /// This is the test a `validate` that only walked the outer fields would
    /// fail, and it is the only one — every other timeline case here is about
    /// the step *schedule*, which such an implementation would still get
    /// right. Left untested, a zero-`bps` rate model buried in step 3 would
    /// arm cleanly and then, minutes into a run that had already produced
    /// output, start dropping 100% of traffic and blaming an empty queue.
    #[test]
    fn a_broken_profile_inside_a_timeline_step_is_refused_at_arm_time() {
        let outer = DirectionProfile {
            timeline: vec![
                TimelineStep {
                    at_ns: 100 * MS,
                    profile: Box::new(DirectionProfile {
                        loss: Some(LossModel::Bernoulli { p: pct_hundredths(100) }),
                        ..DirectionProfile::default()
                    }),
                },
                TimelineStep {
                    at_ns: 200 * MS,
                    profile: Box::new(DirectionProfile {
                        rate: Some(RateModel {
                            bps: 0,
                            burst_bytes: 64 * KIB,
                            queue_bytes: 256 * KIB,
                        }),
                        ..DirectionProfile::default()
                    }),
                },
            ],
            ..healthy()
        };

        assert_eq!(outer.validate(), Err(ProfileError::RateWithZeroBps));

        // …and the same timeline with that one step repaired is accepted, so
        // the refusal above is attributable to the step and not to the
        // presence of a timeline.
        let mut repaired = outer.clone();
        repaired.timeline[1].profile.rate =
            Some(RateModel { bps: 10 * MBPS, burst_bytes: 64 * KIB, queue_bytes: 256 * KIB });
        assert_eq!(repaired.validate(), Ok(()));
    }

    /// The bucket-depth floor follows the direction's own declared maximum
    /// datagram, and is 1500 bytes when it declares none.
    ///
    /// The middle row is the reason this is not a bare constant. A direction
    /// that black-holes anything over 1200 bytes can honour a 1300-byte
    /// bucket completely — it will never be asked for more — and refusing it
    /// against a fixed 1500 would reject a configuration that works. Refusing
    /// a deliverable profile and accepting an undeliverable one are the same
    /// mistake pointed in opposite directions.
    #[test]
    fn the_bucket_depth_floor_follows_the_direction_s_own_mtu() {
        let with_burst = |burst_bytes: u64, mtu: Option<u16>| DirectionProfile {
            rate: Some(RateModel { bps: 10 * MBPS, burst_bytes, queue_bytes: MIB }),
            mtu_blackhole: mtu,
            ..DirectionProfile::default()
        };

        assert_eq!(
            with_burst(1400, None).validate(),
            Err(ProfileError::RateBurstBelowDatagram { burst_bytes: 1400, min_wire_bytes: 1500 }),
            "with no declared maximum, one full Ethernet datagram is the floor"
        );
        assert_eq!(with_burst(1500, None).validate(), Ok(()), "exactly the floor is enough");
        assert_eq!(
            with_burst(1300, Some(1200)).validate(),
            Ok(()),
            "a direction that forwards nothing over 1200 bytes can honour a 1300-byte bucket"
        );
        assert_eq!(
            with_burst(1000, Some(1200)).validate(),
            Err(ProfileError::RateBurstBelowDatagram { burst_bytes: 1000, min_wire_bytes: 1200 }),
            "and cannot honour a 1000-byte one"
        );
    }

    /// An empty peer filter is refused; a filter naming a peer is accepted.
    ///
    /// The positive half matters as much as the negative one: without it,
    /// refusing every `Only(..)` would pass.
    #[test]
    fn a_peer_filter_that_can_match_no_peer_is_refused() {
        let empty = ImpairProfile { peers: PeerFilter::Only(vec![]), ..ImpairProfile::default() };
        assert_eq!(empty.validate(), Err(ProfileError::PeerFilterMatchesNothing));

        let named = ImpairProfile {
            peers: PeerFilter::Only(vec!["127.0.0.1:4433".parse().expect("a literal address")]),
            ..ImpairProfile::default()
        };
        assert_eq!(named.validate(), Ok(()));

        assert_eq!(ImpairProfile::default().validate(), Ok(()), "the default filter is All");
    }

    /// A non-empty filter listing an address no peer can present is refused,
    /// and the refusal names that address.
    ///
    /// The empty filter was already refused; this is the next case along, and
    /// it is a different failure rather than a variation of the same one. An
    /// empty list looks empty. `PeerFilter::Only(vec!["0.0.0.0:0"])` looks
    /// populated — it prints back as a configured filter, it survives every
    /// other check in this file, and the run it produces is clean because
    /// nothing was impaired, not because nothing went wrong.
    ///
    /// The last two rows are the boundary and matter as much as the first
    /// three: `127.0.0.1:0` is refused for its port while its address is
    /// perfectly ordinary, and `203.0.113.9:4433` is *accepted* even though no
    /// peer in this process will ever present it. That asymmetry is the honest
    /// extent of the check, and asserting it here stops the check from being
    /// read as one that knows which peers exist.
    #[test]
    fn a_peer_filter_entry_no_peer_can_present_is_refused_and_named() {
        let filtered = |addrs: &[&str]| ImpairProfile {
            peers: PeerFilter::Only(
                addrs.iter().map(|a| a.parse().expect("a literal address")).collect(),
            ),
            ..ImpairProfile::default()
        };
        let addr = |a: &str| -> std::net::SocketAddr { a.parse().expect("a literal address") };

        assert_eq!(
            filtered(&["0.0.0.0:4433"]).validate(),
            Err(ProfileError::PeerFilterEntryCannotMatch { addr: addr("0.0.0.0:4433") }),
            "an unspecified address is a bind wildcard, never a peer"
        );
        assert_eq!(
            filtered(&["[::]:4433"]).validate(),
            Err(ProfileError::PeerFilterEntryCannotMatch { addr: addr("[::]:4433") }),
            "and so is its v6 spelling"
        );
        assert_eq!(
            filtered(&["127.0.0.1:4433", "192.0.2.7:0"]).validate(),
            Err(ProfileError::PeerFilterEntryCannotMatch { addr: addr("192.0.2.7:0") }),
            "one dead entry among live ones is still an entry that matches nothing"
        );
        assert_eq!(
            filtered(&["127.0.0.1:0"]).validate(),
            Err(ProfileError::PeerFilterEntryCannotMatch { addr: addr("127.0.0.1:0") }),
            "port 0 is the sentinel a socket binds with, not one it sends from"
        );
        assert_eq!(
            filtered(&["203.0.113.9:4433", "[2001:db8::1]:443"]).validate(),
            Ok(()),
            "addresses no peer here will present are still accepted: the check is \
             about form, and no run has happened yet"
        );
    }

    /// Every preset validates, on both directions.
    ///
    /// A preset is the one profile a user is most likely to arm without
    /// reading, so a preset that its own crate would refuse is the worst
    /// possible place for a bucket-depth mistake to be sitting.
    #[test]
    fn every_preset_validates() {
        for p in ALL_PRESETS {
            assert_eq!(preset(p).validate(), Ok(()), "{p:?}");
        }
    }

    /// The presets are seven different networks, not one network seven times.
    ///
    /// This is the test that a `fn preset(_) -> ImpairProfile` returning a
    /// single profile — or `ImpairProfile::default()` — cannot pass, and it is
    /// the only one here that can catch that: "every preset validates" is
    /// satisfied by returning the same valid profile seven times, and so is any
    /// fixture comparison written after the fact against whatever it returned.
    ///
    /// The length assertion is the second half of the job and the reason it is
    /// a literal rather than `ALL_PRESETS.len()`, which would agree with the
    /// array whatever the array said. `ALL_PRESETS` is a const array and has no
    /// exhaustiveness check of its own, so the count has to be written down
    /// somewhere a change to the array does not silently follow.
    #[test]
    fn the_presets_are_pairwise_distinct_in_both_models_and_seed() {
        let all: Vec<ImpairProfile> = ALL_PRESETS.iter().map(|p| preset(*p)).collect();
        assert_eq!(all.len(), 7);

        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate().skip(i + 1) {
                assert_ne!(a, b, "presets {i} and {j} are the same profile");
                assert_ne!(
                    a.seed, b.seed,
                    "presets {i} and {j} share a seed, so they would draw one stream"
                );
                assert_ne!(
                    (&a.downlink, &a.uplink),
                    (&b.downlink, &b.uplink),
                    "presets {i} and {j} differ only in seed, which makes one of them redundant"
                );
            }
        }
    }

    /// The control preset is a control: no loss, no jitter, no reorder, no
    /// duplication, no corruption. Every other preset impairs something.
    ///
    /// Stated as an assertion rather than left to the doc comment because "the
    /// control" is a claim a reader will rely on when they attribute a result
    /// to the code under test, and a later retune that gave it 0.1% loss would
    /// invalidate every such attribution without touching a line of it.
    #[test]
    fn the_datacentre_preset_is_the_only_one_that_impairs_nothing_stochastic() {
        for p in ALL_PRESETS {
            let profile = preset(p);
            let stochastic = [&profile.downlink, &profile.uplink].into_iter().any(|d| {
                d.loss.is_some() || d.reorder.is_some() || d.dup.is_some() || d.corrupt.is_some()
            });
            assert_eq!(
                stochastic,
                p != Preset::DatacentreClean,
                "{p:?} is on the wrong side of the control/impaired split"
            );
        }

        // The control still shapes and still delays, or a run against it would
        // not exercise the same code path as the other six.
        let control = preset(Preset::DatacentreClean);
        assert!(control.downlink.rate.is_some() && control.downlink.delay.is_some());
        assert!(control.uplink.rate.is_some() && control.uplink.delay.is_some());
    }
}

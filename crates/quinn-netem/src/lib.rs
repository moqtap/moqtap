#![deny(missing_docs)]

//! Deterministic UDP datagram impairment for QUIC.
//!
//! This crate decides what happens to a datagram — pass it, delay it, reorder
//! it, duplicate it, corrupt one bit of it, or drop it — and decides the same
//! thing every time from the same seed, on every platform. An impairment run is
//! a fixture, not a weather report.
//!
//! # The two halves
//!
//! [`engine::Impairer::decide`] is a pure function of `(profile, seed, seq,
//! wire_bytes, now)` and the engine's own integer state. It reads no clock,
//! touches no socket and holds no `HashMap`, and compiles with zero
//! dependencies, which is what lets the determinism gate be a plain `#[test]`.
//!
//! `socket::ImpairedUdpSocket` is a thin `quinn::AsyncUdpSocket` decorator over
//! the engine, behind the non-default `quinn-socket` feature. Nothing else in
//! the crate depends on quinn.
//!
//! # How determinism is bought
//!
//! - **No runtime float.** The delay distributions are netem's own integer
//!   inverse-CDF tables ([`dist`]); `ln`/`exp`/`powf`/`cos` are documented by
//!   std as permitted to differ across platforms, so they appear nowhere. The
//!   only `f64` is [`model::Prob::from_f64`], whose multiplication and
//!   truncation are exact in IEEE-754 everywhere.
//! - **No clock.** Time is a caller-supplied [`Tick`].
//! - **Separate PRNG streams.** Each `(`[`Direction`]`, model)` pair draws from
//!   its own [`rng::Pcg32`], so disabling one model does not shift another's.
//! - **An integer decision log.** [`log::DecisionLog`] renders integers and
//!   enum discriminants only.
//!
//! # Nothing is silently ignored
//!
//! A profile that cannot be honoured is refused at construction rather than
//! accepted and ignored: see [`profile::ProfileError`]. An impairment that is
//! configured, counted, logged and then not delivered is the failure mode this
//! design is written against.
//!
//! # Writing a profile in a file
//!
//! Behind the non-default `serde` feature, every type reachable from
//! [`ImpairProfile`] and [`Preset`] derives `Serialize` and `Deserialize`.
//! An unknown key is refused rather than skipped, and probabilities are integer
//! parts per billion in a key that says so — `p-ppb`, not `p`, because `p: 1`
//! reads as certainty and would mean one part in a billion.
//!
//! Deserializing does not validate: a profile read from a file is refused or
//! honoured by [`ImpairProfile::validate`] exactly as one written in Rust is.
//!
//! # Modules
//!
//! - [`rng`] — `Pcg32` and the twelve frozen stream ids
//! - [`dist`] — the committed integer tables, `tabledist`, `crandom`
//! - [`model`] — `Prob`, the six models, `Window`, `sample_delay`
//! - [`wire`] — `wire_bytes`, the on-wire size of a datagram
//! - [`profile`] — profiles, timeline, presets, validation
//! - [`engine`] — `Impairer::decide` and the `Decision` it returns
//! - [`log`] — `Record`, `DecisionLog`, fixture comparison
//! - [`queue`] — the token bucket and the bounded byte queue
//! - [`stats`] — `Stats` (atomics) and `StatsSnapshot` (plain integers)
//! - [`control`] — `ImpairHandle`, the live control surface
//! - [`consts`] — the release floor, the release slice, log-format constants
//! - `socket` — `ImpairedUdpSocket`, feature `quinn-socket`

pub mod consts;
pub mod control;
pub mod dist;
pub mod engine;
pub mod log;
pub mod model;
pub mod profile;
pub mod queue;
pub mod rng;
#[cfg(feature = "quinn-socket")]
pub mod socket;
pub mod stats;
pub mod wire;

pub use crate::consts::{
    DEFAULT_QUEUE_BYTES, RECORD_FIELDS, RECORD_HEADER, RELEASE_FLOOR_NS, RELEASE_SLICE_NS,
};
pub use crate::control::ImpairHandle;
pub use crate::dist::{
    crandom, tabledist, CorrState, DistTable, NORMAL, PARETO, PARETONORMAL, TABLE_LEN, TABLE_SCALE,
};
pub use crate::engine::{CorruptSite, Decision, DropCause, Impairer, Verdict};
pub use crate::log::{DecisionLog, FixtureMismatch, Record};
pub use crate::model::{
    sample_delay, CorruptModel, DelayModel, DupModel, LossModel, Prob, RateModel, ReorderModel,
    Window,
};
/// The written form of a probability and its one refusal.
#[cfg(feature = "serde")]
pub use crate::model::{ProbPpb, ProbPpbOutOfRange};
pub use crate::profile::{
    preset, DirectionProfile, ImpairProfile, PeerFilter, Preset, ProfileError, TimelineStep,
    ALL_PRESETS,
};
pub use crate::queue::{charge, BucketState, RateGrant};
pub use crate::rng::{
    Pcg32, ALL_STREAM_IDS, STREAM_DOWNLINK_CORRUPT, STREAM_DOWNLINK_DELAY, STREAM_DOWNLINK_DUP,
    STREAM_DOWNLINK_LOSS, STREAM_DOWNLINK_RATE_QUEUE, STREAM_DOWNLINK_REORDER,
    STREAM_UPLINK_CORRUPT, STREAM_UPLINK_DELAY, STREAM_UPLINK_DUP, STREAM_UPLINK_LOSS,
    STREAM_UPLINK_RATE_QUEUE, STREAM_UPLINK_REORDER,
};
pub use crate::stats::{Stats, StatsSnapshot};
pub use crate::wire::wire_bytes;

/// Nanoseconds since the profile was armed. Integer, monotone, never a clock.
///
/// Supplied by the caller — by `socket::ImpairedUdpSocket` from a real
/// `Instant`, by a test from a `for` loop. Taking the instant as a parameter
/// rather than reading it is what makes the reproducibility claim testable: a
/// function calling `Instant::now()` internally could only be checked
/// statistically, where this one can be replayed and byte-compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Tick(
    /// Nanoseconds since arm. `Tick(0)` means "armed".
    pub u64,
);

impl Tick {
    /// Saturating: a delay past `u64::MAX` ns clamps rather than releasing in
    /// the past.
    pub const fn saturating_add_ns(self, ns: u64) -> Tick {
        Tick(self.0.saturating_add(ns))
    }

    /// Saturating, matching [`Tick::saturating_add_ns`]: `earlier > self`
    /// yields `0`, never a panic and never a wrap.
    ///
    /// An inverted pair is routine, not academic. Three paths produce one: a
    /// caller whose `now` goes backwards, the reorder model sending a datagram
    /// out ahead of one already parked, and the release loop letting a batch go
    /// in clumps. A plain subtraction would wrap to roughly 1.8e19 in release
    /// and surface as a nineteen-digit
    /// [`StatsSnapshot::release_error_ns`] in someone's report.
    pub const fn since(self, earlier: Tick) -> u64 {
        self.0.saturating_sub(earlier.0)
    }
}

/// Which way a datagram is travelling.
///
/// The discriminants are written into every decision-log record, so reordering
/// the variants would silently reinterpret every fixture ever recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Direction {
    /// Proxy -> client.
    Downlink = 0,
    /// Client -> proxy.
    Uplink = 1,
}

#[cfg(test)]
mod tests {
    use super::Tick;

    /// `Tick::since` clamps an inverted pair to 0, which an early release —
    /// the routine result of a release loop waking on a fixed quantum — needs.
    #[test]
    fn tick_since_saturates_on_an_inverted_pair() {
        assert_eq!(Tick(5).since(Tick(9)), 0);
        assert_eq!(Tick(0).since(Tick(u64::MAX)), 0);
        assert_eq!(Tick(9).since(Tick(5)), 4);
    }

    /// `Tick::saturating_add_ns` clamps rather than wrapping into the past,
    /// which would be a delay model releasing early.
    #[test]
    fn tick_saturating_add_ns_clamps_at_the_top() {
        assert_eq!(Tick(u64::MAX).saturating_add_ns(1), Tick(u64::MAX));
        assert_eq!(Tick(10).saturating_add_ns(0), Tick(10));
        assert_eq!(Tick(10).saturating_add_ns(5), Tick(15));
    }
}

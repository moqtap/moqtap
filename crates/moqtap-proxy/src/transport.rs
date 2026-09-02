//! QUIC transport parameters as a value a caller can write down.
//!
//! A [`TransportProfile`] is a typed, serializable, per-leg description of
//! the QUIC knobs a run wants: congestion controller, windows, loss-detection
//! thresholds, MTU, keep-alive. Eighteen optional fields and nothing else —
//! a field left `None` is a field this profile has no opinion about, and
//! [`TransportProfile::apply_to`] leaves such a field exactly as it found it.
//!
//! # Beside `quinn::TransportConfig`, not on top of it
//!
//! Both legs already accept a raw `quinn::TransportConfig`, and they still do.
//! A profile is applied *over* whatever the caller built, rather than replacing
//! it, and the reason that is the only workable shape is a missing trait:
//! `quinn::TransportConfig` has three impls — the inherent one, `Default` and
//! `Debug` — no `Clone`, and no public getter for any field. A wrapper that
//! owned the configuration could therefore neither copy the caller's config nor
//! read it back, so it could only ever hand back a fresh default with the
//! caller's settings discarded. Sitting beside the type and mutating it in
//! place is the one arrangement in which *everything this profile does not name
//! is untouched* is a fact rather than a claim. See
//! [`TransportProfile::apply_to`] for the full statement, including the trap it
//! leaves for a maintainer.
//!
//! # What is deliberately not a field
//!
//! There is no `enable_segmentation_offload`. Segmentation offload is turned
//! off while a socket-level impairment is armed, because GSO hands the kernel
//! one buffer to cut into many datagrams: the socket decorator then sees one
//! send where the wire carries several, and loss, delay and rate accounting
//! all count the wrong unit. A profile able to switch offload back on would
//! let a configuration file undo that from a distance — in a file that says
//! nothing about impairment — and the only symptom would be impairment
//! figures that quietly disagree with what crossed the wire. The knob is
//! absent, so there is nothing to undo it with.
//!
//! **That is the whole of the list, and it has to stay whole to be worth
//! consulting.** A quinn knob that is neither a field above nor named here
//! has not been ruled on at all, and a reader who comes here to find out
//! why it is missing takes the silence for a decision — the one thing it
//! cannot be. Carrying the knob and writing a paragraph here are the two
//! ways to leave this section true; there is no third.
//!
//! # Installing one on a leg
//!
//! A profile is a value until a connection installs it. [`Leg`] names which
//! of the proxy's two connections is being talked about, and
//! [`TransportInstaller`] is the step that turns the profile into the
//! `quinn::TransportConfig` that leg hands to quinn — [`DefaultInstaller`]
//! when the caller supplies none. Both legs refuse to carry a raw
//! `quinn::TransportConfig` *and* a profile at once, for the reason spelled
//! out on [`crate::error::ProxyError::TransportConfigAndProfile`]: the
//! merge that would appear to combine them cannot exist.
//!
//! Under the `qlog` feature a leg carries a third thing, a `qlog::QlogSpec`
//! saying where its QUIC-level capture goes — plain code font because none
//! of it exists in a build without the feature. A spec composes with a
//! profile, which is applied to the same config the sink is attached to, and
//! it composes with an installer too: [`TransportInstaller::build`] hands
//! back an **owned** `quinn::TransportConfig`, so the sink is attached to
//! the caller's own base afterwards and the three settings stack rather than
//! one of them winning silently. A spec is still refused beside a raw
//! config, for a reason of the same shape as the one above: a sink is
//! installed by mutating a `quinn::TransportConfig`, and a raw config
//! arrives behind an `Arc` that cannot be mutated. `resolve` below is where
//! all of it is decided, once per leg and before any endpoint exists.
//!
//! # Validating
//!
//! [`TransportProfile::validate`] answers before any connection exists, and
//! every rule it enforces is a case where quinn would otherwise accept a
//! value and not honour it. That is the whole reason the type has a
//! validator rather than just a set of setters: a transport parameter that
//! is configured, reported as applied, and silently replaced by something
//! else is indistinguishable from one that worked, and a run built on it is
//! believed.

use std::sync::Arc;
use std::time::Duration;

use quinn::congestion;
use quinn::{AckFrequencyConfig, IdleTimeout, MtuDiscoveryConfig, VarInt};

use crate::error::ProxyError;

/// QUIC's guaranteed-deliverable UDP payload size, in bytes, and the floor
/// that `quinn::TransportConfig::initial_mtu` and `min_mtu` silently raise
/// any smaller value to.
///
/// Defined here rather than imported because quinn keeps its `INITIAL_MTU`
/// private. The number is fixed by QUIC itself — the handshake establishes
/// that the path carries an unfragmented 1200-byte datagram body, so nothing
/// below it is a meaningful path MTU and quinn refuses to hold one.
const QUIC_INITIAL_MTU: u16 = 1200;

/// A per-leg description of QUIC transport parameters.
///
/// Every field is optional and every `None` means *leave this alone*. There
/// is no field whose `None` is a value: a profile that sets three knobs is a
/// profile about three knobs, and the other thirteen belong to whoever built
/// the `quinn::TransportConfig` it is applied to.
///
/// `#[non_exhaustive]` **with** a [`Default`], as the shaping configs are:
/// the attribute lets a later release add a seventeenth knob without a
/// break, and outside this crate it makes both struct-expression and
/// `..Default::default()` syntax illegal, so the `Default` is what leaves a
/// construction path open at all. The documented way to build one is
/// therefore `TransportProfile::default()` followed by field assignment,
/// which is what the example does — it is the only path the attribute
/// leaves, so it is the one worth proving.
///
/// ```
/// use std::time::Duration;
///
/// use moqtap_proxy::transport::{Congestion, MtuDiscovery, TransportProfile};
///
/// let mut profile = TransportProfile::default();
/// profile.congestion = Some(Congestion::Bbr);
/// profile.initial_rtt = Some(Duration::from_millis(40));
/// profile.receive_window = Some(8 * 1024 * 1024);
/// profile.initial_mtu = Some(1350);
/// profile.mtu_discovery = Some(MtuDiscovery::Off);
///
/// profile.validate()?;
/// let config = profile.into_config()?;
/// # let _ = config;
/// # Ok::<(), moqtap_proxy::transport::TransportProfileError>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(default, deny_unknown_fields))]
#[non_exhaustive]
pub struct TransportProfile {
    /// Which congestion controller to install.
    ///
    /// Each variant installs that controller's own default configuration.
    /// The controllers behave very differently on a lossy path — BBR keeps
    /// sending through loss that collapses a Cubic sender — so a run
    /// comparing two of them wants this named explicitly rather than
    /// inherited from whatever quinn's default happens to be that release.
    pub congestion: Option<Congestion>,
    /// The RTT to assume before a measurement exists.
    ///
    /// It decides the first retransmission timeout, so on a long path a
    /// default that is far too low spends the opening exchange
    /// retransmitting packets that were merely in flight.
    pub initial_rtt: Option<Duration>,
    /// Connection-wide flow-control window, in bytes.
    ///
    /// The cap on unacknowledged data across all streams. Too small for the
    /// bandwidth-delay product and the sender stalls on flow control at a
    /// throughput that has nothing to do with the congestion controller
    /// under test.
    pub receive_window: Option<u64>,
    /// Per-stream flow-control window, in bytes.
    ///
    /// Held below [`TransportProfile::receive_window`] so that one slow
    /// reader cannot monopolise the connection's receive buffers.
    pub stream_receive_window: Option<u64>,
    /// Cap on unacknowledged outgoing data, in bytes.
    ///
    /// The send-side counterpart of [`TransportProfile::receive_window`],
    /// and the one window quinn takes as a plain `u64` rather than a QUIC
    /// varint, so no range check applies to it.
    pub send_window: Option<u64>,
    /// How many unidirectional streams the peer may have open at once.
    ///
    /// MoQT carries media on unidirectional streams, so this is the ceiling
    /// on concurrent subgroups; a value below what a subscription needs
    /// shows up as senders blocked waiting for a stream credit rather than
    /// as anything resembling congestion.
    pub max_concurrent_uni_streams: Option<u64>,
    /// How many bidirectional streams the peer may have open at once.
    ///
    /// **What this starves depends on the draft, and a profile is
    /// installed on a leg before any version has been negotiated**, so it
    /// cannot depend on which. Three answers over the range, each taken
    /// from that draft's own Section 3.3:
    ///
    /// * Drafts 07 through 15 specify a single use of bidirectional
    ///   streams, the control stream (draft-15 Section 3.3). A cap of zero
    ///   there does not impair a session, it prevents one.
    /// * Draft-16 specifies two, the control stream and
    ///   SUBSCRIBE_NAMESPACE (draft-16 Section 3.3). It is the one draft
    ///   on which a cap can starve something and leave the session
    ///   running.
    /// * Drafts 17 through 19 moved the control plane onto a pair of
    ///   unidirectional streams and give bidirectional streams to
    ///   requests alone — six message types on draft-17, seven on drafts
    ///   18 and 19 (draft-17 Section 3.3). A cap there is the request-side
    ///   counterpart of
    ///   [`TransportProfile::max_concurrent_uni_streams`] on the media
    ///   side, and it is the case this knob is carried for.
    ///
    /// So a value written without knowing which draft the run will
    /// negotiate is a foot-gun rather than a setting, and that is a reason
    /// to say so here rather than a reason to leave the field out.
    pub max_concurrent_bidi_streams: Option<u64>,
    /// How long a connection may sit idle before it is closed.
    ///
    /// The effective timeout is the smaller of this and the peer's own, so
    /// setting it here only ever shortens the wait.
    pub max_idle_timeout: Option<Duration>,
    /// How often to send a packet purely to keep the connection alive.
    ///
    /// Must be strictly below [`TransportProfile::max_idle_timeout`] when
    /// both are set — see
    /// [`TransportProfileError::KeepAliveNotBelowIdle`].
    pub keep_alive_interval: Option<Duration>,
    /// How many packets may be acknowledged after a packet before it is
    /// declared lost.
    ///
    /// The reordering tolerance of loss detection. Lowering it makes a
    /// reordering path look like a lossy one, which is occasionally the
    /// point and is otherwise a way to misread a run.
    pub packet_threshold: Option<u32>,
    /// Loss-detection time threshold, as a multiple of the round-trip
    /// estimate.
    ///
    /// Must be finite and greater than `1.0`: it is a multiplier on the
    /// RTT, so a value at or below one declares packets lost before an
    /// acknowledgement could have arrived.
    pub time_threshold: Option<f32>,
    /// How many consecutive probe timeouts amount to persistent
    /// congestion.
    ///
    /// quinn multiplies the probe timeout by this to get the window it
    /// looks for entirely-lost packets in, and a path judged persistently
    /// congested has its congestion window collapsed to the minimum.
    /// Lowering it makes a sender give up on a bad path sooner.
    ///
    /// **Nothing in this crate demonstrates its effect.** Persistent
    /// congestion is entered on a *duration* of losses, and no test here
    /// asserts a duration, so a gate for this field could assert only that
    /// a setter accepted the value. It ships under that stated limit,
    /// which is a different thing from a knob accepted and ignored — the
    /// same footing as [`TransportProfile::ack_frequency`].
    pub persistent_congestion_threshold: Option<u32>,
    /// Acknowledgement frequency to request of the peer.
    ///
    /// `None` leaves quinn's default, which is not to negotiate the
    /// extension at all. `Some` asks for it, with the knobs in
    /// [`AckFrequency`].
    pub ack_frequency: Option<AckFrequency>,
    /// The packet size to start with, in bytes.
    ///
    /// Must be at least 1200 — see
    /// [`TransportProfileError::MtuBelowFloor`].
    pub initial_mtu: Option<u16>,
    /// The packet size never to go below, in bytes, after black-hole
    /// detection has lowered the discovered MTU.
    ///
    /// Must be at least 1200, and no larger than
    /// [`TransportProfile::initial_mtu`].
    pub min_mtu: Option<u16>,
    /// Whether to search for a larger path MTU, and how far.
    ///
    /// quinn's default is to search, so `None` here means *keep searching*
    /// and [`MtuDiscovery::Off`] is the only way to stop it. The two are
    /// deliberately distinguishable.
    pub mtu_discovery: Option<MtuDiscovery>,
    /// Whether to share send capacity fairly between streams rather than
    /// draining them in priority order.
    ///
    /// It changes which subgroup arrives first when several are ready at
    /// once, which is visible in delivery order and not in any counter.
    pub send_fairness: Option<bool>,
    /// How much room to give incoming QUIC datagrams, in bytes.
    ///
    /// [`DatagramBuffer::Disabled`] refuses datagrams outright, which is a
    /// different thing from leaving the field unset — see
    /// [`DatagramBuffer`] for why that distinction has a type rather than a
    /// nested `Option`.
    pub datagram_receive_buffer: Option<DatagramBuffer>,
}

impl TransportProfile {
    /// Everything wrong with this profile, before any connection exists.
    ///
    /// Returns the **first** failure, checked in field-declaration order, as
    /// the other validators in this workspace do: a profile with two
    /// mistakes reports the earlier field, and fixing it reveals the second.
    /// The order is fixed so the answer is repeatable rather than dependent
    /// on which check happened to be written first.
    ///
    /// Two deliberate departures from strict declaration order, both because
    /// the more useful thing to be told comes first:
    ///
    /// * [`TransportProfileError::KeepAliveNotBelowIdle`] is checked at
    ///   `keep_alive_interval`, the later of the two fields it compares, so
    ///   that the earlier field has already had its own range check.
    /// * Both MTU floors are checked before
    ///   [`TransportProfileError::MtuInverted`]. A value below the floor is
    ///   a single-field fault with a single-field fix, and once both values
    ///   are legal the inversion may not exist any more.
    ///
    /// # What is not checked, and why
    ///
    /// The idle timeout has no error variant of its own. `IdleTimeout`
    /// converts from a `Duration` through `as_millis` against the same
    /// varint ceiling as the windows, which puts the limit around 146
    /// million years — no configuration file reaches it, and an error a
    /// reader can never meet is worse than no error at all. The conversion
    /// is nevertheless fallible in Rust, because `Duration::from_secs(u64::MAX)`
    /// exists, so it is folded into
    /// [`TransportProfileError::VarIntRange`] under the field name
    /// `max_idle_timeout`. That keeps the path free of a panic without
    /// adding a rule to the list an author has to read.
    pub fn validate(&self) -> Result<(), TransportProfileError> {
        // `congestion` and `initial_rtt` have no invalid values: every
        // controller is installable and every `Duration` is an assumable
        // round trip.
        if let Some(bytes) = self.receive_window {
            varint("receive_window", bytes)?;
        }
        if let Some(bytes) = self.stream_receive_window {
            varint("stream_receive_window", bytes)?;
        }
        // `send_window` takes a plain `u64`, so it has no varint ceiling.
        if let Some(count) = self.max_concurrent_uni_streams {
            varint("max_concurrent_uni_streams", count)?;
        }
        if let Some(count) = self.max_concurrent_bidi_streams {
            varint("max_concurrent_bidi_streams", count)?;
        }
        if let Some(idle) = self.max_idle_timeout {
            idle_timeout(idle)?;
        }
        if let (Some(keep_alive), Some(idle)) = (self.keep_alive_interval, self.max_idle_timeout) {
            // A keep-alive at or above the idle timeout cannot prevent the
            // timeout it exists to prevent: the connection is already gone
            // when the packet that would have saved it is due.
            if keep_alive >= idle {
                return Err(TransportProfileError::KeepAliveNotBelowIdle { keep_alive, idle });
            }
        }
        // `packet_threshold` and `persistent_congestion_threshold` are plain
        // counts with no ceiling to exceed, and quinn honours every `u32`
        // either is given. Zero included: it makes an extremely eager loss
        // detector rather than an ignored setting, which is the distinction
        // that decides whether a rule belongs here.
        if let Some(threshold) = self.time_threshold {
            // It is a multiplier on the round-trip estimate, so anything at
            // or below 1.0 declares a packet lost before an acknowledgement
            // for it could have arrived, and a non-finite value is not a
            // multiplier at all.
            if !threshold.is_finite() || threshold <= 1.0 {
                return Err(TransportProfileError::TimeThreshold(threshold));
            }
        }
        if let Some(ack) = &self.ack_frequency {
            ack.validate()?;
        }
        if let Some(mtu) = self.initial_mtu {
            mtu_floor("initial_mtu", mtu)?;
        }
        if let Some(mtu) = self.min_mtu {
            mtu_floor("min_mtu", mtu)?;
        }
        if let (Some(min), Some(initial)) = (self.min_mtu, self.initial_mtu) {
            // `min_mtu` is the floor discovery may fall back to and
            // `initial_mtu` is where it starts; a floor above the start is
            // a range with nothing in it.
            if min > initial {
                return Err(TransportProfileError::MtuInverted { min, initial });
            }
        }
        // `mtu_discovery`, `send_fairness` and `datagram_receive_buffer`
        // have no invalid values: every variant and every bool is a
        // configuration quinn honours as written.
        Ok(())
    }

    /// Write this profile's fields into `tc`, leaving every field it does not
    /// set untouched.
    ///
    /// # Why this takes `&mut` and returns nothing
    /// `quinn::TransportConfig` has exactly three impls — the inherent setters,
    /// `Default` and `Debug`. There is no `Clone`, and every field is private
    /// with no getter. So there is no way to write `fn apply(&self, base:
    /// &TransportConfig) -> TransportConfig`: the function cannot copy `base`
    /// and cannot read a single value out of it, so the only thing it could
    /// return is a fresh default with the caller's configuration silently
    /// thrown away. Mutating in place is the one shape in which *leaves the
    /// rest untouched* is true rather than merely claimed.
    ///
    /// The trap this leaves for whoever maintains it: `base.clone()`
    /// **compiles**. `&TransportConfig` is `Clone` even though
    /// `TransportConfig` is not, so the call clones the reference and the
    /// mistake only surfaces at the return, as "`TransportConfig` does not
    /// implement `Clone`, so `&TransportConfig` was cloned instead". Anyone
    /// who reaches for the by-value signature will meet that message and
    /// should read it as the reason this signature is what it is.
    ///
    /// # All or nothing
    ///
    /// The first statement is `self.validate()?`, and that is the whole of
    /// how this method is kept from installing something `validate` would
    /// have rejected — there is no second list of rules to drift out of step
    /// with the first, and no field-by-field reading to do to check it. It
    /// also means `tc` is either fully written or not written at all: a
    /// profile that fails returns before the first setter runs, so a caller
    /// who ignores the error is not left with a half-applied config.
    ///
    /// The conversions below re-run the fallible steps with `?` rather than
    /// unwrapping them. They cannot fail after `validate` has passed, but
    /// expressing that as a panic would make a future divergence between the
    /// two lists into a crash instead of an error.
    pub fn apply_to(&self, tc: &mut quinn::TransportConfig) -> Result<(), TransportProfileError> {
        self.validate()?;

        if let Some(controller) = self.congestion {
            tc.congestion_controller_factory(controller.factory());
        }
        if let Some(rtt) = self.initial_rtt {
            tc.initial_rtt(rtt);
        }
        if let Some(bytes) = self.receive_window {
            tc.receive_window(varint("receive_window", bytes)?);
        }
        if let Some(bytes) = self.stream_receive_window {
            tc.stream_receive_window(varint("stream_receive_window", bytes)?);
        }
        if let Some(bytes) = self.send_window {
            tc.send_window(bytes);
        }
        if let Some(count) = self.max_concurrent_uni_streams {
            tc.max_concurrent_uni_streams(varint("max_concurrent_uni_streams", count)?);
        }
        if let Some(count) = self.max_concurrent_bidi_streams {
            tc.max_concurrent_bidi_streams(varint("max_concurrent_bidi_streams", count)?);
        }
        if let Some(idle) = self.max_idle_timeout {
            tc.max_idle_timeout(Some(IdleTimeout::from(idle_timeout(idle)?)));
        }
        if let Some(interval) = self.keep_alive_interval {
            tc.keep_alive_interval(Some(interval));
        }
        if let Some(threshold) = self.packet_threshold {
            tc.packet_threshold(threshold);
        }
        if let Some(threshold) = self.time_threshold {
            tc.time_threshold(threshold);
        }
        if let Some(threshold) = self.persistent_congestion_threshold {
            tc.persistent_congestion_threshold(threshold);
        }
        if let Some(ack) = &self.ack_frequency {
            tc.ack_frequency_config(Some(ack.to_config()?));
        }
        if let Some(mtu) = self.initial_mtu {
            tc.initial_mtu(mtu);
        }
        if let Some(mtu) = self.min_mtu {
            tc.min_mtu(mtu);
        }
        if let Some(discovery) = self.mtu_discovery {
            tc.mtu_discovery_config(discovery.to_config());
        }
        if let Some(fair) = self.send_fairness {
            tc.send_fairness(fair);
        }
        if let Some(buffer) = self.datagram_receive_buffer {
            tc.datagram_receive_buffer_size(buffer.to_size());
        }

        Ok(())
    }

    /// A fresh config carrying only this profile.
    ///
    /// Equivalent to [`TransportProfile::apply_to`] over a
    /// `quinn::TransportConfig::default()`, and defined that way rather than
    /// duplicated, so the two can only ever accept and refuse the same
    /// profiles. Use it for a leg with no configuration of its own; use
    /// `apply_to` for a leg that already has one.
    pub fn into_config(&self) -> Result<quinn::TransportConfig, TransportProfileError> {
        let mut tc = quinn::TransportConfig::default();
        self.apply_to(&mut tc)?;
        Ok(tc)
    }
}

/// The congestion controller to install.
///
/// Deliberately **not** `#[non_exhaustive]`. `tests/transport_exhaustive.rs`
/// compiles as its own crate and matches this enum with no `_` arm, which is
/// legal only while the attribute is absent; the attribute would force the
/// wildcard in, and after that a fourth controller compiles green out there
/// with nobody told it is unhandled. What the test can check is that every
/// variant named here is matchable, constructible and installable by a
/// downstream consumer, so adding one is a visible break rather than a
/// silent widening. What no test can check is the other direction: whether
/// quinn has grown a controller this list has never heard of. That stays a
/// reading of quinn's `congestion` module whenever the dependency moves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Congestion {
    /// CUBIC, quinn's default: loss-based, and the controller most of the
    /// internet is running.
    Cubic,
    /// BBR: rate-based, and the interesting one against an impaired path,
    /// because it keeps sending through loss that collapses a loss-based
    /// sender.
    Bbr,
    /// NewReno: the textbook loss-based controller, useful as a slow,
    /// predictable baseline.
    NewReno,
}

impl Congestion {
    /// The factory quinn wants, boxed as the trait object its setter takes.
    ///
    /// Each variant carries that controller's own default configuration.
    /// Exposing the individual controller knobs would be a second
    /// configuration surface with its own validation, and none of it is
    /// serializable.
    fn factory(self) -> Arc<dyn congestion::ControllerFactory + Send + Sync + 'static> {
        match self {
            Self::Cubic => Arc::new(congestion::CubicConfig::default()),
            Self::Bbr => Arc::new(congestion::BbrConfig::default()),
            Self::NewReno => Arc::new(congestion::NewRenoConfig::default()),
        }
    }
}

/// Acknowledgement frequency to request of the peer.
///
/// A serializable mirror of quinn's `AckFrequencyConfig`, which has private
/// fields, no getters and no serde support, so it cannot itself appear in a
/// profile. The three fields are the three knobs that type exposes, and the
/// [`Default`] is **hand-written to equal quinn's own defaults** rather than
/// derived: a derived one would give an ack-eliciting threshold of zero,
/// which asks the peer to acknowledge every single packet, and a reordering
/// threshold of zero, which asks it never to acknowledge reordering
/// promptly. Neither is a sensible starting point, and both would arrive
/// silently in any file that named one field and left the others out.
///
/// With this `Default`, `Some(AckFrequency::default())` means exactly what
/// `Some(AckFrequencyConfig::default())` means in quinn: negotiate the
/// extension, with its recommended values.
///
/// `#[non_exhaustive]`, so outside this crate one is built as
/// `AckFrequency::default()` followed by field assignment — the attribute
/// makes both the struct expression and `..Default::default()` illegal
/// there. Kept rather than dropped because it and the `Default` above are
/// one mechanism: this type mirrors an upstream config that gains a knob
/// from time to time, and the attribute guarantees that every construction
/// still reachable starts from the hand-written `Default`. A fourth field
/// added in a later release therefore arrives carrying quinn's recommended
/// value in code that was written before it existed, instead of the zero a
/// struct expression would have left there — and zero, for both thresholds
/// here, is a request the peer will honour and nobody meant to make.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(default, deny_unknown_fields))]
#[non_exhaustive]
pub struct AckFrequency {
    /// How many ack-eliciting packets the peer may receive before it must
    /// send an acknowledgement.
    ///
    /// Zero asks it to acknowledge every one. Defaults to 1, which is
    /// quinn's own default and acknowledges every other packet.
    pub ack_eliciting_threshold: u64,
    /// The longest the peer may wait before acknowledging, when the
    /// threshold above has not been reached.
    ///
    /// `None` leaves the peer's own advertised `max_ack_delay` in place,
    /// which is quinn's default and is why `None` is not ambiguous here.
    pub max_ack_delay: Option<Duration>,
    /// How far out of order a packet may arrive before the peer must
    /// acknowledge immediately.
    ///
    /// Zero asks it never to. Defaults to 2, which is quinn's own default
    /// and one below the default packet threshold, as quinn recommends.
    pub reordering_threshold: u64,
}

impl Default for AckFrequency {
    fn default() -> Self {
        Self { ack_eliciting_threshold: 1, max_ack_delay: None, reordering_threshold: 2 }
    }
}

impl AckFrequency {
    /// The two varint-valued thresholds, checked against the QUIC varint
    /// ceiling before they can fail at connect time.
    ///
    /// Field names are reported dotted — `ack_frequency.reordering_threshold`
    /// — because `reordering_threshold` on its own would not tell a reader
    /// which part of the file to look at.
    fn validate(&self) -> Result<(), TransportProfileError> {
        varint("ack_frequency.ack_eliciting_threshold", self.ack_eliciting_threshold)?;
        varint("ack_frequency.reordering_threshold", self.reordering_threshold)?;
        Ok(())
    }

    /// Build quinn's config from this mirror.
    fn to_config(&self) -> Result<AckFrequencyConfig, TransportProfileError> {
        let mut config = AckFrequencyConfig::default();
        config.ack_eliciting_threshold(varint(
            "ack_frequency.ack_eliciting_threshold",
            self.ack_eliciting_threshold,
        )?);
        config.max_ack_delay(self.max_ack_delay);
        config.reordering_threshold(varint(
            "ack_frequency.reordering_threshold",
            self.reordering_threshold,
        )?);
        Ok(config)
    }
}

/// Whether to search for a larger path MTU, and how far.
///
/// quinn's default is to search, so an unset
/// [`TransportProfile::mtu_discovery`] means discovery stays **on**.
/// [`MtuDiscovery::Off`] is the only way to say otherwise, and it has to be
/// expressible separately from unset: turning discovery off is a real choice
/// for a run that wants the packet size it configured to be the packet size
/// it gets, rather than the start of a binary search.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum MtuDiscovery {
    /// Do not search. The packet size stays where `initial_mtu` put it.
    Off,
    /// Search, but no higher than this many bytes.
    ///
    /// Everything else about the search — interval, minimum change,
    /// black-hole cooldown — stays at quinn's defaults.
    UpTo(u16),
}

impl MtuDiscovery {
    /// The value quinn's `mtu_discovery_config` setter takes, where `None`
    /// genuinely disables discovery rather than meaning "unchanged".
    fn to_config(self) -> Option<MtuDiscoveryConfig> {
        match self {
            Self::Off => None,
            Self::UpTo(bytes) => {
                let mut config = MtuDiscoveryConfig::default();
                config.upper_bound(bytes);
                Some(config)
            }
        }
    }
}

/// How much room to give incoming QUIC datagrams.
///
/// This exists instead of `Option<Option<usize>>`, and the nested option is not
/// a matter of taste. Written down, the outer `None` and the inner `None` are
/// the same three characters: `{`datagram_receive_buffer`: null}` in a
/// hand-written file deserializes to the **outer** `None`, so an author who
/// wrote it to disable datagram reception silently gets "change nothing", and
/// their datagrams keep arriving. `deny_unknown_fields` cannot catch it — the
/// key is well known and the value is well typed. Naming the two answers makes
/// them impossible to confuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum DatagramBuffer {
    /// Refuse incoming datagrams entirely.
    Disabled,
    /// Accept incoming datagrams, buffering up to this many bytes.
    Bytes(usize),
}

impl DatagramBuffer {
    /// The value quinn's `datagram_receive_buffer_size` setter takes, where
    /// `None` disables datagram reception.
    fn to_size(self) -> Option<usize> {
        match self {
            Self::Disabled => None,
            Self::Bytes(bytes) => Some(bytes),
        }
    }
}

/// Why a [`TransportProfile`] cannot be honoured.
///
/// No `Eq`: [`TransportProfileError::TimeThreshold`] carries an `f32`, and
/// the one value that most wants reporting — `NaN` — is not equal to
/// itself. `PartialEq` is what an `f32` admits, and it is enough for a test
/// to compare a returned error against an expected one.
///
/// Deliberately **not** `#[non_exhaustive]`: `tests/transport_exhaustive.rs`
/// builds one profile per variant, calls [`TransportProfile::validate`], and
/// matches what comes back with no `_` arm — a match a crate outside this
/// one can only write while the attribute is absent. A sixth variant fails
/// that build until a profile someone could actually write is shown to reach
/// it, which is the check worth having: not that the variant exists, but
/// that it is a refusal an author can trip over and therefore fix. The
/// attribute would replace all of that with a wildcard arm that silently
/// accepts anything.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum TransportProfileError {
    /// A value above `2^62 - 1`, which is the largest number QUIC's variable
    /// length integer encoding can carry.
    ///
    /// Caught here rather than at connect time, where quinn returns it
    /// without naming a field and the leg carries on with a default the
    /// author never asked for.
    #[error("{field} = {value} exceeds the QUIC varint range")]
    VarIntRange {
        /// The profile field holding the oversized value, spelled as the
        /// field is, and dotted for a field inside [`AckFrequency`].
        field: &'static str,
        /// The value that does not fit.
        value: u64,
    },
    /// A keep-alive interval at or above the idle timeout.
    ///
    /// Such a keep-alive cannot prevent the timeout it exists to prevent:
    /// the connection has already been closed by the time the packet that
    /// would have saved it is due.
    #[error("keep_alive_interval {keep_alive:?} must be below max_idle_timeout {idle:?}")]
    KeepAliveNotBelowIdle {
        /// The configured keep-alive interval.
        keep_alive: Duration,
        /// The idle timeout it fails to stay below.
        idle: Duration,
    },
    /// A minimum MTU above the initial MTU.
    ///
    /// The minimum is the floor MTU discovery may fall back to and the
    /// initial is where it starts, so a floor above the start describes a
    /// range with nothing in it.
    #[error("min_mtu {min} is above initial_mtu {initial}")]
    MtuInverted {
        /// The configured minimum MTU.
        min: u16,
        /// The initial MTU it exceeds.
        initial: u16,
    },
    /// An MTU below the 1200 bytes QUIC guarantees.
    ///
    /// quinn's `initial_mtu` and `min_mtu` setters both raise a smaller
    /// value to 1200 without a word, so a profile modelling a constrained
    /// path at 900 bytes validates, applies, reports applied, and runs at
    /// 1200. Refused here, naming the field, because a configured value that
    /// is quietly replaced is the failure this crate exists to make
    /// impossible.
    #[error("{field} = {value} is below QUIC's {floor}-byte floor; quinn would silently raise it")]
    MtuBelowFloor {
        /// Which of `initial_mtu` or `min_mtu` holds the value.
        field: &'static str,
        /// The value that would have been raised.
        value: u16,
        /// The floor it is below, which is always 1200.
        floor: u16,
    },
    /// A loss-detection time threshold that is not a usable multiplier.
    ///
    /// It multiplies the round-trip estimate, so at or below `1.0` it
    /// declares a packet lost before an acknowledgement for it could have
    /// arrived, and a non-finite value is not a multiplier at all.
    #[error("time_threshold {0} must be finite and greater than 1.0")]
    TimeThreshold(f32),
}

/// Convert to a QUIC varint, naming the field if it does not fit.
///
/// The single place the `u64`-to-`VarInt` conversion happens, so
/// [`TransportProfile::validate`] and [`TransportProfile::apply_to`] cannot
/// disagree about which values are acceptable.
fn varint(field: &'static str, value: u64) -> Result<VarInt, TransportProfileError> {
    VarInt::from_u64(value).map_err(|_| TransportProfileError::VarIntRange { field, value })
}

/// Convert an idle timeout to the varint of milliseconds quinn stores.
///
/// The saturation matters only for the error message: a `Duration` whose
/// millisecond count does not fit a `u64` is already unimaginably past the
/// varint ceiling, and reporting `u64::MAX` says so as well as the true
/// figure would while keeping the error's `value` field a `u64`.
fn idle_timeout(idle: Duration) -> Result<VarInt, TransportProfileError> {
    let millis = u64::try_from(idle.as_millis()).unwrap_or(u64::MAX);
    varint("max_idle_timeout", millis)
}

/// Refuse an MTU quinn would silently raise.
///
/// Shared by both MTU fields so the floor is written once; the field name is
/// passed in because the error has to say which one.
fn mtu_floor(field: &'static str, value: u16) -> Result<(), TransportProfileError> {
    if value < QUIC_INITIAL_MTU {
        return Err(TransportProfileError::MtuBelowFloor { field, value, floor: QUIC_INITIAL_MTU });
    }
    Ok(())
}

pub use crate::types::Leg;

// ── Installing a profile on a leg ───────────────────────────────────────

/// Builds the `quinn::TransportConfig` a leg installs.
///
/// A leg with a [`TransportProfile`] and no installer of its own uses
/// [`DefaultInstaller`], so supplying one replaces exactly one step and
/// nothing else: the leg still installs whatever comes back, still installs
/// it before its endpoint exists, and still refuses a leg that names a raw
/// `quinn::TransportConfig` as well as a profile.
///
/// # What this is for: a base configuration *and* a profile
///
/// A leg takes a raw config or a profile, never both — see
/// [`ProxyError::TransportConfigAndProfile`], which is where the reason is
/// written out. The short form is that
/// `quinn::TransportConfig` can be neither cloned nor read back, so no code
/// here can accept a caller's config and return a modified copy of it.
///
/// An installer is how a caller has both anyway, and it works because it
/// **builds** the base rather than being handed one: `build` constructs its
/// own `quinn::TransportConfig`, applies the profile over it with
/// [`TransportProfile::apply_to`], and returns the result. Nothing is
/// copied, so nothing is silently dropped, and the caller's own settings
/// survive because the caller is the one making them.
///
/// `Send + Sync + 'static` because one installer serves every connection a
/// leg carries, for as long as the proxy runs, from whichever task accepts
/// them.
pub trait TransportInstaller: Send + Sync + 'static {
    /// Turn `profile` into the config this leg will install.
    ///
    /// An error refuses the connection instead of falling back to a
    /// default. A leg that connected anyway would be running with
    /// parameters nobody chose while reporting success, which is the one
    /// outcome every rule in this module exists to prevent.
    ///
    /// # Owned, not `Arc`
    ///
    /// The return type is a plain `quinn::TransportConfig` and the reason is
    /// what the caller may still need to do to it. A QUIC-level capture sink
    /// is installed by **mutating** a `quinn::TransportConfig`, and an `Arc`
    /// that may already be shared cannot be mutated — `Arc::get_mut` hands
    /// back nothing the moment a second handle exists. An installer that
    /// returned one would therefore be unusable on any leg that also asked
    /// for a capture, and the only way to keep such a leg working would be
    /// to skip the installer: a caller who supplied one would find it never
    /// called, with nothing saying so. Handing back the value means the leg
    /// can attach whatever else it owes to it and every setting survives.
    ///
    /// The leg wraps the result in an `Arc` itself, once, after it has
    /// finished with it. An implementation that has an `Arc` already should
    /// build a fresh config rather than trying to unwrap one — that is the
    /// same rebuild-per-leg this trait exists for.
    fn build(
        &self,
        profile: &TransportProfile,
    ) -> Result<quinn::TransportConfig, TransportProfileError>;
}

/// The installer a leg uses when it was given none.
///
/// [`TransportProfile::into_config`] and deliberately nothing more. Every
/// field the profile does not name is therefore
/// `quinn::TransportConfig::default()`'s — quinn's own choice rather than
/// one this crate invented and would have to keep in step with a
/// dependency upgrade.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultInstaller;

impl TransportInstaller for DefaultInstaller {
    fn build(
        &self,
        profile: &TransportProfile,
    ) -> Result<quinn::TransportConfig, TransportProfileError> {
        profile.into_config()
    }
}

/// What a leg installs, from the fields a caller may have set and the
/// installer it may have supplied.
///
/// `None` back means the leg installs nothing and quinn's defaults apply,
/// which is the case that has to stay bit-identical to the behaviour from
/// before profiles existed.
///
/// Called once per leg, **before** the endpoint is built, so every refusal
/// below costs a caller no socket, no handshake and no connection to tear
/// down — and none of them can be mistaken for a network fault, which is
/// what the same error arriving mid-connection would look like.
///
/// An installer with no profile beside it is not consulted: `build` takes a
/// profile and there is none to give it. That is the one inert combination
/// here, and it is called out on both `installer` fields rather than left
/// for a caller to discover from a run where nothing happened.
///
/// # A spec changes what three of those cases install
///
/// Under the `qlog` feature a leg may also carry a `qlog::QlogSpec` — named
/// in plain code font here, as the variants below are, because none of it
/// exists in a build without the feature and a link from this
/// always-compiled item would not resolve. A sink can only be installed by
/// mutating a `quinn::TransportConfig` this function still holds by value,
/// and that single fact decides all four combinations:
///
/// * **Raw config alone** — installed as it was given, exactly as before.
/// * **Raw config and a spec** — `ProxyError::TransportConfigAndQlog`,
///   because the config arrives behind an `Arc` that can be neither cloned
///   nor mutated. The variant carries the whole reason.
/// * **Profile and a spec** — the leg's [`TransportInstaller`] builds the
///   config, exactly as it does for a profile with no spec beside it, and
///   the sink is attached to what it returned. The three compose because
///   `build` hands back an owned `quinn::TransportConfig` rather than an
///   `Arc`: the base is the caller's, the profile is applied over it by the
///   installer, and the sink goes on last. A leg with no installer of its
///   own gets [`DefaultInstaller`]'s base, which is
///   `quinn::TransportConfig::default()`.
/// * **Spec alone** — still a fresh `quinn::TransportConfig` with the sink
///   on it, and the leg installs it. This is the case worth being careful
///   about: a leg that named only a spec used to install nothing, and
///   installing nothing here would leave the commonest way of asking for a
///   capture producing no capture and no error.
///
/// A spec with no writer never reaches an endpoint: `attach_to` validates
/// before it builds, so `QlogError::NoWriter` is answered here, and by the
/// time a connection exists the sink is one quinn actually returned rather
/// than the silent `None` it answers a writer-less configuration with.
pub(crate) fn resolve(
    leg: Leg,
    raw: Option<Arc<quinn::TransportConfig>>,
    profile: Option<&TransportProfile>,
    installer: Option<&Arc<dyn TransportInstaller>>,
    #[cfg(feature = "qlog")] qlog: Option<crate::qlog::QlogSpec>,
) -> Result<Option<Arc<quinn::TransportConfig>>, ProxyError> {
    match (raw, profile) {
        // Checked first, and before the spec is looked at, so a leg that
        // named all three hears about this pair. It is the older rule and
        // the one whose fix — apply the profile to your own config — also
        // resolves the other, so reporting it first sends the caller
        // somewhere useful either way.
        (Some(_), Some(_)) => Err(ProxyError::TransportConfigAndProfile { leg }),
        (Some(config), None) => {
            #[cfg(feature = "qlog")]
            if qlog.is_some() {
                return Err(ProxyError::TransportConfigAndQlog { leg });
            }
            Ok(Some(config))
        }
        (None, Some(profile)) => {
            // One build, whether or not a capture was asked for. The
            // installer is the leg's single source of a base config, so a
            // spec cannot quietly move the leg onto a different one.
            #[cfg_attr(not(feature = "qlog"), allow(unused_mut))]
            let mut config = match installer {
                Some(installer) => installer.build(profile),
                None => DefaultInstaller.build(profile),
            }
            .map_err(|source| ProxyError::TransportProfile { leg, source })?;
            #[cfg(feature = "qlog")]
            if let Some(spec) = qlog {
                spec.attach_to(&mut config).map_err(|source| ProxyError::Qlog { leg, source })?;
            }
            Ok(Some(Arc::new(config)))
        }
        (None, None) => {
            #[cfg(feature = "qlog")]
            if let Some(spec) = qlog {
                // The one arm that installs a config out of nothing. A leg
                // asking only for a capture is the commonest way to ask for
                // one at all, and answering it with `None` would leave the
                // sink attached to a config nobody installed — a file
                // holding a preamble and never an event.
                let mut config = quinn::TransportConfig::default();
                spec.attach_to(&mut config).map_err(|source| ProxyError::Qlog { leg, source })?;
                return Ok(Some(Arc::new(config)));
            }
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A profile with every field set and every value sane.
    ///
    /// Used as the starting point for the refusal tests, so each of them
    /// changes exactly one field. A refusal test built from
    /// `TransportProfile::default()` would leave the other seventeen fields at
    /// `None` and would still pass against a `validate` that ignored them.
    fn healthy() -> TransportProfile {
        // Every field named, with no `..Default::default()`: adding a
        // nineteenth knob should break this fixture, because a fixture that
        // silently leaves the new field at `None` stops being the
        // fully-populated control it is used as.
        TransportProfile {
            congestion: Some(Congestion::Bbr),
            initial_rtt: Some(Duration::from_millis(40)),
            receive_window: Some(8 * 1024 * 1024),
            stream_receive_window: Some(1024 * 1024),
            send_window: Some(8 * 1024 * 1024),
            max_concurrent_uni_streams: Some(256),
            max_concurrent_bidi_streams: Some(16),
            max_idle_timeout: Some(Duration::from_secs(30)),
            keep_alive_interval: Some(Duration::from_secs(5)),
            packet_threshold: Some(3),
            time_threshold: Some(1.125),
            persistent_congestion_threshold: Some(3),
            ack_frequency: Some(AckFrequency::default()),
            initial_mtu: Some(1350),
            min_mtu: Some(1200),
            mtu_discovery: Some(MtuDiscovery::UpTo(1452)),
            send_fairness: Some(true),
            datagram_receive_buffer: Some(DatagramBuffer::Bytes(64 * 1024)),
        }
    }

    /// The largest value QUIC's varint encoding carries, and the first one
    /// above it.
    const VARINT_MAX: u64 = (1 << 62) - 1;

    #[test]
    fn a_profile_that_sets_nothing_validates() {
        assert_eq!(
            TransportProfile::default().validate(),
            Ok(()),
            "an all-`None` profile has no opinion to be wrong about"
        );
    }

    #[test]
    fn a_fully_populated_healthy_profile_is_accepted() {
        assert_eq!(
            healthy().validate(),
            Ok(()),
            "the control profile must be valid or every refusal below is unattributable"
        );
    }

    #[test]
    fn a_value_above_the_varint_ceiling_is_refused_and_names_its_field() {
        // One row per field that goes through a varint setter. Five fields,
        // five rows, and the expected errors differ in the field name, so a
        // `validate` that reported one fixed name cannot pass.
        type Edit = fn(&mut TransportProfile);

        let rows: [(&str, Edit, &str); 5] = [
            ("connection window", |p| p.receive_window = Some(VARINT_MAX + 1), "receive_window"),
            (
                "stream window",
                |p| p.stream_receive_window = Some(VARINT_MAX + 1),
                "stream_receive_window",
            ),
            (
                "uni stream count",
                |p| p.max_concurrent_uni_streams = Some(VARINT_MAX + 1),
                "max_concurrent_uni_streams",
            ),
            (
                "bidi stream count",
                |p| p.max_concurrent_bidi_streams = Some(VARINT_MAX + 1),
                "max_concurrent_bidi_streams",
            ),
            (
                "ack-eliciting threshold",
                |p| {
                    p.ack_frequency = Some(AckFrequency {
                        ack_eliciting_threshold: VARINT_MAX + 1,
                        ..Default::default()
                    });
                },
                "ack_frequency.ack_eliciting_threshold",
            ),
        ];

        for (label, edit, field) in rows {
            let mut profile = healthy();
            edit(&mut profile);
            assert_eq!(
                profile.validate(),
                Err(TransportProfileError::VarIntRange { field, value: VARINT_MAX + 1 }),
                "{label}"
            );
        }

        // The positive control for the whole table: the ceiling itself fits,
        // so none of the rows above is passing because the fixture was
        // already invalid.
        let mut profile = healthy();
        profile.receive_window = Some(VARINT_MAX);
        profile.stream_receive_window = Some(VARINT_MAX);
        profile.max_concurrent_uni_streams = Some(VARINT_MAX);
        profile.max_concurrent_bidi_streams = Some(VARINT_MAX);
        assert_eq!(profile.validate(), Ok(()), "exactly the ceiling is accepted");
    }

    #[test]
    fn the_reordering_threshold_is_checked_under_its_own_dotted_name() {
        let mut profile = healthy();
        profile.ack_frequency =
            Some(AckFrequency { reordering_threshold: VARINT_MAX + 1, ..Default::default() });
        assert_eq!(
            profile.validate(),
            Err(TransportProfileError::VarIntRange {
                field: "ack_frequency.reordering_threshold",
                value: VARINT_MAX + 1,
            }),
            "`reordering_threshold` alone would not say which part of the file to look at"
        );
    }

    #[test]
    fn a_keep_alive_at_the_idle_timeout_is_refused() {
        let mut profile = healthy();
        profile.max_idle_timeout = Some(Duration::from_secs(10));
        profile.keep_alive_interval = Some(Duration::from_secs(10));
        assert_eq!(
            profile.validate(),
            Err(TransportProfileError::KeepAliveNotBelowIdle {
                keep_alive: Duration::from_secs(10),
                idle: Duration::from_secs(10),
            }),
            "a keep-alive due exactly when the connection is already closed saves nothing"
        );

        profile.keep_alive_interval = Some(Duration::from_millis(9_999));
        assert_eq!(profile.validate(), Ok(()), "one millisecond below is enough");
    }

    #[test]
    fn a_keep_alive_without_an_idle_timeout_is_not_compared_to_anything() {
        let mut profile = healthy();
        profile.max_idle_timeout = None;
        profile.keep_alive_interval = Some(Duration::from_secs(3600));
        assert_eq!(
            profile.validate(),
            Ok(()),
            "with no idle timeout in the profile there is no timeout this could fail to prevent"
        );
    }

    #[test]
    fn a_min_mtu_above_the_initial_mtu_is_refused() {
        let mut profile = healthy();
        profile.initial_mtu = Some(1300);
        profile.min_mtu = Some(1400);
        assert_eq!(
            profile.validate(),
            Err(TransportProfileError::MtuInverted { min: 1400, initial: 1300 }),
            "a discovery floor above the starting size is an empty range"
        );

        profile.min_mtu = Some(1300);
        assert_eq!(profile.validate(), Ok(()), "equal is a range of one, which is usable");
    }

    #[test]
    fn an_mtu_below_the_quic_floor_is_refused_rather_than_silently_raised() {
        let mut profile = healthy();
        profile.initial_mtu = Some(900);
        assert_eq!(
            profile.validate(),
            Err(TransportProfileError::MtuBelowFloor {
                field: "initial_mtu",
                value: 900,
                floor: 1200
            }),
            "quinn would raise 900 to 1200 without a word, so a run at 900 never happens"
        );

        let mut profile = healthy();
        profile.min_mtu = Some(1199);
        assert_eq!(
            profile.validate(),
            Err(TransportProfileError::MtuBelowFloor {
                field: "min_mtu",
                value: 1199,
                floor: 1200
            }),
            "one byte below the floor is still below the floor"
        );

        let mut profile = healthy();
        profile.initial_mtu = Some(1200);
        profile.min_mtu = Some(1200);
        assert_eq!(profile.validate(), Ok(()), "exactly the floor is accepted");
    }

    #[test]
    fn the_mtu_floor_is_reported_before_the_inversion() {
        let mut profile = healthy();
        profile.initial_mtu = Some(900);
        profile.min_mtu = Some(1000);
        assert_eq!(
            profile.validate(),
            Err(TransportProfileError::MtuBelowFloor {
                field: "initial_mtu",
                value: 900,
                floor: 1200
            }),
            "the single-field fault comes first; the inversion may not survive fixing it"
        );
    }

    #[test]
    fn a_time_threshold_that_is_not_a_usable_multiplier_is_refused() {
        let mut profile = healthy();
        profile.time_threshold = Some(1.0);
        assert_eq!(
            profile.validate(),
            Err(TransportProfileError::TimeThreshold(1.0)),
            "a multiplier of exactly one declares loss the instant an ack becomes possible"
        );

        profile.time_threshold = Some(f32::NAN);
        // Compared with `matches!` rather than `assert_eq!`: `NaN != NaN`,
        // so the error carrying it is not equal to itself either. This is
        // the reason the error type has no `Eq`.
        assert!(
            matches!(profile.validate(), Err(TransportProfileError::TimeThreshold(t)) if t.is_nan()),
            "a non-finite multiplier is not a multiplier"
        );

        profile.time_threshold = Some(1.000_001);
        assert_eq!(profile.validate(), Ok(()), "anything above one is a usable multiplier");
    }

    #[test]
    fn every_field_applies_to_a_config_without_panicking() {
        let profile = healthy();
        let mut tc = quinn::TransportConfig::default();
        assert_eq!(
            profile.apply_to(&mut tc),
            Ok(()),
            "every field in the control profile has a setter that accepts it"
        );
    }

    #[test]
    fn the_other_variants_of_the_wrapper_enums_also_apply() {
        // `healthy` picks one variant of each two-variant enum; this covers
        // the other, so no arm of `to_config` or `to_size` is unexercised.
        let mut profile = healthy();
        profile.mtu_discovery = Some(MtuDiscovery::Off);
        profile.datagram_receive_buffer = Some(DatagramBuffer::Disabled);
        profile.congestion = Some(Congestion::NewReno);
        let mut tc = quinn::TransportConfig::default();
        assert_eq!(profile.apply_to(&mut tc), Ok(()), "discovery off and datagrams disabled apply");

        profile.congestion = Some(Congestion::Cubic);
        let mut tc = quinn::TransportConfig::default();
        assert_eq!(profile.apply_to(&mut tc), Ok(()), "cubic applies");
    }

    #[test]
    fn into_config_and_apply_to_agree_on_acceptance_and_on_the_error() {
        // Nothing here reads a field back out of the `TransportConfig`. Its
        // hand-written `Debug` would make that possible, and it would assert
        // only that the setter stored what it was given — not that quinn
        // honoured it, which is the part that matters and the part no test
        // in this module can see. The assertions are on the profile and on
        // the error.
        let profile = TransportProfile::default();
        let mut tc = quinn::TransportConfig::default();
        assert_eq!(
            profile.apply_to(&mut tc).is_ok(),
            profile.into_config().is_ok(),
            "a default profile is accepted by both or by neither"
        );

        let mut profile = healthy();
        profile.initial_mtu = Some(800);
        let mut tc = quinn::TransportConfig::default();
        assert_eq!(
            profile.apply_to(&mut tc),
            profile.into_config().map(|_| ()),
            "a refused profile is refused identically by both"
        );
        assert_eq!(
            profile.into_config().map(|_| ()),
            Err(TransportProfileError::MtuBelowFloor {
                field: "initial_mtu",
                value: 800,
                floor: 1200
            }),
            "and the error is the one `validate` gives"
        );
    }

    /// An installer that records every profile it was asked to build.
    /// The only observable a test has: `quinn::TransportConfig` cannot be read
    /// back, so *the leg installed what came out of here* is proved by the leg
    /// reaching this at all, with the profile the caller set, and then coming
    /// up.
    #[derive(Default)]
    struct RecordingInstaller {
        seen: std::sync::Mutex<Vec<TransportProfile>>,
    }

    impl TransportInstaller for RecordingInstaller {
        fn build(
            &self,
            profile: &TransportProfile,
        ) -> Result<quinn::TransportConfig, TransportProfileError> {
            self.seen.lock().expect("no test holds this across a panic").push(profile.clone());
            profile.into_config()
        }
    }

    /// [`resolve`] for a leg that asked for no capture.
    ///
    /// The spec argument exists only under the `qlog` feature, so every row
    /// that has nothing to do with capturing goes through this and reads the
    /// same in both builds. The alternative — a `#[cfg]` on the fifth
    /// argument of each call — puts a conditional in eight places to say
    /// "and no capture" eight times.
    fn resolve_uncaptured(
        leg: Leg,
        raw: Option<Arc<quinn::TransportConfig>>,
        profile: Option<&TransportProfile>,
        installer: Option<&Arc<dyn TransportInstaller>>,
    ) -> Result<Option<Arc<quinn::TransportConfig>>, ProxyError> {
        resolve(
            leg,
            raw,
            profile,
            installer,
            #[cfg(feature = "qlog")]
            None,
        )
    }

    #[test]
    fn a_leg_naming_neither_installs_nothing() {
        assert!(
            resolve_uncaptured(Leg::Client, None, None, None)
                .expect("nothing named is nothing to refuse")
                .is_none(),
            "a leg with no opinion has to stay exactly as it was before profiles existed"
        );
    }

    #[test]
    fn a_raw_config_is_installed_as_it_was_given() {
        let raw = Arc::new(quinn::TransportConfig::default());
        let resolved = resolve_uncaptured(Leg::Client, Some(Arc::clone(&raw)), None, None)
            .expect("a raw config alone is not a contradiction")
            .expect("and it is what the leg installs");
        assert!(
            Arc::ptr_eq(&raw, &resolved),
            "the caller's own config must reach the leg, not a copy of it — there is no copy"
        );
    }

    #[test]
    fn a_profile_alone_is_built_by_the_default_installer() {
        // Written as a struct expression with `..Default::default()`,
        // which is legal here and illegal downstream: the `default()` then
        // field-assignment form the type documents is what
        // `field_reassign_with_default` fires on inside this crate.
        let profile = TransportProfile { initial_mtu: Some(1350), ..Default::default() };
        assert!(
            resolve_uncaptured(Leg::Upstream, None, Some(&profile), None)
                .expect("a valid profile builds")
                .is_some(),
            "a leg carrying only a profile installs the config built from it"
        );
    }

    #[test]
    fn a_supplied_installer_is_what_builds_the_profile() {
        let installer = Arc::new(RecordingInstaller::default());
        let dynamic: Arc<dyn TransportInstaller> = installer.clone();
        let profile = TransportProfile { congestion: Some(Congestion::Bbr), ..Default::default() };

        assert!(resolve_uncaptured(Leg::Client, None, Some(&profile), Some(&dynamic))
            .expect("the installer accepted the profile")
            .is_some());
        let seen = installer.seen.lock().expect("uncontended");
        assert_eq!(seen.len(), 1, "the installer is consulted exactly once per leg");
        assert_eq!(
            seen[0], profile,
            "the leg must hand the caller's own profile to the caller's own installer"
        );
    }

    #[test]
    fn a_leg_naming_both_a_config_and_a_profile_is_refused_with_its_own_leg() {
        // One row per leg. The `leg` in the error is the whole point of the
        // field — a proxy holds two of these and *which one did I get wrong* is
        // the only question the caller has.
        for leg in [Leg::Client, Leg::Upstream] {
            let raw = Arc::new(quinn::TransportConfig::default());
            let err = resolve_uncaptured(leg, Some(raw), Some(&TransportProfile::default()), None)
                .expect_err("naming both is a contradiction, not a merge");
            assert!(
                matches!(err, ProxyError::TransportConfigAndProfile { leg: reported } if reported == leg),
                "{leg:?} must be refused as {leg:?}, got {err}"
            );
            assert!(
                err.to_string().contains("apply_to"),
                "the message has to name the supported way to have both, or the first reader \
                 takes this for a regression: {err}"
            );
        }
    }

    #[test]
    fn a_profile_the_installer_refuses_refuses_the_leg_and_names_it() {
        // quinn would raise 900 to 1200 without a word, which is the whole
        // reason the profile refuses it first.
        let profile = TransportProfile { initial_mtu: Some(900), ..Default::default() };

        let err = resolve_uncaptured(Leg::Upstream, None, Some(&profile), None)
            .expect_err("an unhonourable profile must not become a connection");
        assert!(
            matches!(
                err,
                ProxyError::TransportProfile {
                    leg: Leg::Upstream,
                    source: TransportProfileError::MtuBelowFloor { field: "initial_mtu", .. },
                }
            ),
            "the refusal carries both the leg and the reason: {err}"
        );
    }

    // ── and what a capture changes about all four ──────────────────────

    /// A writer that keeps everything, readable while the sink is alive.
    ///
    /// Unbuffered on purpose: every assertion below is about whether a sink
    /// was built at all, and a buffered writer would hold the preamble until
    /// something dropped it.
    #[cfg(feature = "qlog")]
    #[derive(Clone)]
    struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);

    #[cfg(feature = "qlog")]
    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("no test holds this across a panic").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A spec writing into `sink`, and the sink itself.
    #[cfg(feature = "qlog")]
    fn spec_over_a_sink() -> (crate::qlog::QlogSpec, Arc<std::sync::Mutex<Vec<u8>>>) {
        let sink = Arc::new(std::sync::Mutex::new(Vec::new()));
        let spec = crate::qlog::QlogSpec {
            writer: Some(Box::new(Captured(Arc::clone(&sink)))),
            title: Some("a leg".to_string()),
            description: None,
        };
        (spec, sink)
    }

    /// How many bytes the capture holds. Non-zero means a sink was built,
    /// because the preamble is written as it is built and nothing else in
    /// these tests connects.
    #[cfg(feature = "qlog")]
    fn written(sink: &Arc<std::sync::Mutex<Vec<u8>>>) -> usize {
        sink.lock().expect("uncontended").len()
    }

    /// A leg carrying only a spec still installs a config.
    ///
    /// The case most likely to be silently wrong, and the reason is that
    /// `None` back from `resolve` used to be the right answer for a leg that
    /// named neither of the other two fields. A leg that installed nothing
    /// here would leave the sink attached to a `quinn::TransportConfig` that
    /// went nowhere — and that produces a file which exists, parses, names a
    /// qlog version and holds no event, which is the one failure a caller
    /// watching their disk cannot see.
    #[cfg(feature = "qlog")]
    #[test]
    fn a_spec_alone_installs_a_config_for_the_sink_to_go_on() {
        let (spec, sink) = spec_over_a_sink();
        let resolved = resolve(Leg::Client, None, None, None, Some(spec))
            .expect("a spec with a writer is not a contradiction")
            .expect("a leg asking only for a capture still installs the config carrying it");
        assert!(
            written(&sink) > 0,
            "the preamble is written when the sink is built, so an empty writer means the spec \
             never became one"
        );
        drop(resolved);
    }

    /// A profile and a spec reach one config, and the installer is what
    /// built it.
    ///
    /// The installer is the leg's only source of a base config, so a spec
    /// beside a profile must not move the leg onto a different one. The
    /// recording installer is what makes that checkable rather than
    /// asserted: it counts every profile it is asked to build, and here it
    /// must be asked for exactly the profile the caller set. The sink is
    /// attached to what it returned, which is possible at all because
    /// `build` hands back an owned config rather than an `Arc`.
    #[cfg(feature = "qlog")]
    #[test]
    fn a_profile_and_a_spec_are_applied_to_one_config_built_by_the_installer() {
        let installer = Arc::new(RecordingInstaller::default());
        let dynamic: Arc<dyn TransportInstaller> = installer.clone();
        let profile = TransportProfile { initial_mtu: Some(1350), ..Default::default() };

        let (spec, sink) = spec_over_a_sink();
        assert!(
            resolve(Leg::Upstream, None, Some(&profile), Some(&dynamic), Some(spec))
                .expect("a profile and a spec are not a contradiction")
                .is_some(),
            "a leg carrying both installs the one config they were both written into"
        );
        assert!(written(&sink) > 0, "and the sink is on that config");
        let seen = installer.seen.lock().expect("uncontended");
        assert_eq!(
            seen.as_slice(),
            &[profile],
            "a spec must not bypass the caller's installer: a leg that built its own config here \
             would run on a base nobody supplied and report success"
        );
    }

    /// A leg naming a raw config and a spec is refused, as its own thing,
    /// with its own leg — and no capture is begun on the way out.
    #[cfg(feature = "qlog")]
    #[test]
    fn a_leg_naming_both_a_config_and_a_spec_is_refused_with_its_own_leg() {
        // One row per leg, as for the config-and-profile pair: a proxy holds
        // two of these and *which one did I get wrong* is the only question the
        // caller has.
        for leg in [Leg::Client, Leg::Upstream] {
            let (spec, sink) = spec_over_a_sink();
            let raw = Arc::new(quinn::TransportConfig::default());
            let err = resolve(leg, Some(raw), None, None, Some(spec))
                .expect_err("a config the sink cannot be installed on is not a leg with a capture");
            assert!(
                matches!(err, ProxyError::TransportConfigAndQlog { leg: reported } if reported == leg),
                "{leg:?} must be refused as {leg:?}, and as the config-and-spec pair rather than \
                 the config-and-profile one — the two have different fixes: {err}"
            );
            assert_eq!(
                written(&sink),
                0,
                "and nothing may be written on the way to refusing: a preamble here is a file the \
                 caller will read as the start of a capture that never happened"
            );
        }
    }

    /// The older pair is reported first when a leg names all three.
    ///
    /// Not a preference between the two refusals so much as a fixed answer:
    /// a leg with two faults reports one of them, and which one has to be
    /// the same every time or the fix a caller is told to make depends on
    /// the order of the checks. The config-and-profile pair is the one
    /// whose fix — apply the profile to your own config — also resolves the
    /// other, so it is the useful half to be sent to.
    #[cfg(feature = "qlog")]
    #[test]
    fn a_leg_naming_all_three_hears_about_the_config_and_the_profile() {
        let (spec, sink) = spec_over_a_sink();
        let raw = Arc::new(quinn::TransportConfig::default());
        let err =
            resolve(Leg::Client, Some(raw), Some(&TransportProfile::default()), None, Some(spec))
                .expect_err("three fields that cannot be combined are still a refusal");
        assert!(
            matches!(err, ProxyError::TransportConfigAndProfile { leg: Leg::Client }),
            "the answer has to be fixed rather than whichever check ran first: {err}"
        );
        assert_eq!(written(&sink), 0, "and no capture is begun for a leg that is refused");
    }

    /// A spec that names no writer refuses the leg, and says so as itself.
    ///
    /// quinn's own answer to a missing writer is no sink and no error, so a
    /// leg that let it through would connect, run, report success, and leave
    /// the caller's file untouched. The refusal has to carry the leg — a
    /// proxy has two — and the `NoWriter` reason, which is what tells a
    /// caller their spec is unfinished rather than their disk unwritable.
    #[cfg(feature = "qlog")]
    #[test]
    fn a_spec_with_no_writer_refuses_the_leg_that_carries_it() {
        let blind = crate::qlog::QlogSpec {
            writer: None,
            title: Some("a leg".to_string()),
            description: None,
        };
        let err = resolve(Leg::Upstream, None, None, None, Some(blind))
            .expect_err("a spec with nowhere to write is a mistake, not a request for no capture");
        assert!(
            matches!(
                err,
                ProxyError::Qlog { leg: Leg::Upstream, source: crate::qlog::QlogError::NoWriter }
            ),
            "the refusal carries both the leg and the reason: {err}"
        );
    }

    #[test]
    fn the_ack_frequency_default_is_quinns_own_and_not_a_derived_one() {
        let ack = AckFrequency::default();
        assert_eq!(
            (ack.ack_eliciting_threshold, ack.reordering_threshold),
            (1, 2),
            "a derived default would ask the peer to ack every packet and never ack reordering"
        );
        assert_eq!(ack.max_ack_delay, None, "`None` leaves the peer's advertised delay in place");
    }
}

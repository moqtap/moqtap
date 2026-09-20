//! A datagram larger than the burst, on a profile nothing is wrong with.
//!
//! `Impairer::decide` aborted here until 0.1.3, on the premise that
//! `validate_models` refuses every configuration that could reach the token
//! bucket's `RateGrant::Never`. Three facts falsify it:
//!
//! * `validate_models` refuses `burst_bytes` below **one on-wire datagram**,
//!   and "one on-wire datagram" is the direction's `mtu_blackhole` where one is
//!   set and `ASSUMED_PATH_WIRE_BYTES` (1500) where none is.
//! * A UDP datagram carries up to 65507 bytes of payload, so 65535 on the wire
//!   over IPv4.
//! * `LossyEdge`, `ThreeG`, `Lte` uplink and `Bufferbloat` carry a
//!   `burst_bytes` between those two numbers with a `queue_bytes` above them —
//!   the window in which the queue admits a datagram the bucket then refuses.
//!
//! The shim decides about every datagram arriving at the port, so this was
//! reachable before the QUIC handshake, from anywhere.

use quinn_netem::{
    preset, DirectionProfile, DropCause, Impairer, Preset, RateModel, Tick, Verdict,
};

/// The largest datagram an IPv4 UDP sender can put on the wire: 65507 bytes of
/// payload, 20 of IP header and 8 of UDP.
const MAX_UDP_WIRE: u32 = 65535;

/// A full-size datagram, for the "and the link still works" half.
const NORMAL_WIRE: u32 = 1228;

/// The four presets whose uplink sits in the vulnerable window, with the
/// numbers that put them there.
///
/// Read out of `profile::preset` rather than restated, so a preset retuned to
/// a larger burst removes itself from this list instead of leaving a test
/// asserting against a window it is no longer in.
fn vulnerable_uplinks() -> Vec<(Preset, RateModel)> {
    [Preset::LossyEdge, Preset::ThreeG, Preset::Lte, Preset::Bufferbloat]
        .into_iter()
        .filter_map(|p| {
            let rate = preset(p).uplink.rate?;
            let wire = u64::from(MAX_UDP_WIRE);
            (rate.burst_bytes < wire && wire <= rate.queue_bytes).then_some((p, rate))
        })
        .collect()
}

/// An oversized datagram is dropped, on a profile that validates.
///
/// Both halves are the finding. The profile validating is what says this was
/// never an operator error, and the datagram being the maximum a UDP sender can
/// send is what says no protocol had to be spoken to reach it.
///
/// *Ablation:* restore
/// `RateGrant::Never => panic!(..)` in `engine.rs::decide` and this does not
/// fail — it takes the test binary down:
///
/// ```text
/// thread 'a_datagram_larger_than_the_burst_is_dropped_and_not_aborted_on' panicked at
/// crates\quinn-netem\src\engine.rs:
/// the token bucket can never grant a 65535-byte datagram at 5000000 bits per
/// second with a 16384-byte burst; that is a refusal the profile validator owed
/// the caller, not a datagram to dispose of
/// ```
///
/// That is `LossyEdge`'s uplink, the first of the four this loop reaches.
#[test]
fn a_datagram_larger_than_the_burst_is_dropped_and_not_aborted_on() {
    let vulnerable = vulnerable_uplinks();
    assert!(
        !vulnerable.is_empty(),
        "at least one built-in preset must sit in the burst < datagram <= queue window, \
         or this test is asserting about nothing"
    );

    for (name, rate) in vulnerable {
        let mut engine = Impairer::new(preset(name).uplink, 1, quinn_netem::Direction::Uplink)
            .expect("a built-in preset validates; that is the point of this test");

        let decision = engine.decide(0, MAX_UDP_WIRE, Tick(0));
        assert_eq!(
            decision.verdict,
            Verdict::Drop,
            "{name:?} uplink (burst {}, queue {}) must dispose of a {MAX_UDP_WIRE}-byte \
             datagram, not abort on it",
            rate.burst_bytes,
            rate.queue_bytes
        );
        assert_eq!(
            decision.cause(),
            DropCause::RateQueueFull,
            "{name:?} uplink: the rate model refused it, so the rate model's cause"
        );
    }
}

/// The datagram the bucket refused does not leave its bytes in the queue.
///
/// The queue is consulted before the bucket, so an over-burst datagram has
/// already been counted into the backlog by the time it is refused. Leaving it
/// there would report a standing backlog for a datagram that is not going to
/// leave, and would tail-drop the datagrams behind it against occupancy that
/// does not exist — a rate model punishing a link for traffic it never carried.
///
/// The second decision is at the same tick as the first, so nothing has drained
/// and the backlog is exactly what the first decision left behind.
///
/// *Ablation:* drop the `queue.withdraw(wire_bytes)` call and this fails on the
/// refused datagram's own backlog — the bytes of a datagram that is not going
/// to leave, recorded as occupancy:
///
/// ```text
/// assertion `left == right` failed: nothing was queued before it and it is not queued either
///   left: 65535
///  right: 0
/// ```
#[test]
fn a_refused_datagram_leaves_nothing_in_the_queue() {
    let profile = preset(Preset::LossyEdge).uplink;
    let rate = profile.rate.expect("lossy_edge shapes its uplink");
    let mut engine = Impairer::new(profile, 1, quinn_netem::Direction::Uplink)
        .expect("a built-in preset validates");

    let refused = engine.decide(0, MAX_UDP_WIRE, Tick(0));
    assert_eq!(refused.verdict, Verdict::Drop, "the oversized one goes");
    assert_eq!(
        refused.queue_backlog_bytes, 0,
        "nothing was queued before it and it is not queued either"
    );

    // A datagram the link can carry, at the same tick: the backlog it reports
    // is its own and nothing else's.
    let carried = engine.decide(1, NORMAL_WIRE, Tick(0));
    assert_ne!(carried.verdict, Verdict::Drop, "a normal datagram still passes");
    assert_eq!(
        carried.queue_backlog_bytes,
        u64::from(NORMAL_WIRE),
        "the queue holds this datagram and not the {} bytes it refused; burst {}, queue {}",
        MAX_UDP_WIRE,
        rate.burst_bytes,
        rate.queue_bytes
    );
}

/// A datagram larger than the *queue* is still refused by the queue, unchanged.
///
/// The two refusals meet here and must not have been folded into one: this one
/// never reaches the bucket, and the fix above must not have moved the
/// boundary between them.
#[test]
fn a_datagram_larger_than_the_queue_is_still_the_queues_refusal() {
    let profile = DirectionProfile {
        rate: Some(RateModel { bps: 10_000_000, burst_bytes: 4096, queue_bytes: 8192 }),
        ..DirectionProfile::default()
    };
    let mut engine = Impairer::new(profile, 1, quinn_netem::Direction::Downlink)
        .expect("burst 4096 is above the assumed 1500-byte path");

    let decision = engine.decide(0, 16_384, Tick(0));
    assert_eq!(decision.verdict, Verdict::Drop);
    assert_eq!(decision.cause(), DropCause::RateQueueFull);
    assert_eq!(decision.queue_backlog_bytes, 0, "it never entered the queue");
}

//! Every `ProfileError` variant, reached through a real construction path and
//! compared against its rendered message.
//!
//! This file is an integration test, i.e. a **separate crate**, and that is
//! load-bearing rather than incidental. The exhaustive `match` below is the
//! whole gate: a fourteenth variant added without a construction path fails to
//! compile here, which is the strongest form this check can take. From inside
//! the defining crate the same `match` would still compile after
//! `#[non_exhaustive]` were added to the enum, because that attribute is only
//! visible to other crates — so an in-crate version of this file would go on
//! passing while quietly ceasing to check anything.
//!
//! Two rules the file is built around:
//!
//! **Reachability, not construction.** Nothing here writes a `ProfileError`
//! literal and then asserts it renders. Every value comes out of
//! `validate` or out of the probability constructor, given a profile a person
//! could plausibly have written. A validation error that no input can produce
//! is decoration, and a test that constructs the error itself cannot tell the
//! two apart.
//!
//! **Rendered text, not discriminants.** The messages are what a user sees
//! when the error is wrapped and printed, so they are the part worth freezing.
//! Comparing discriminants would let all thirteen render as "invalid profile"
//! and stay green.

use quinn_netem::{
    DelayModel, DirectionProfile, ImpairProfile, LossModel, PeerFilter, Prob, ProfileError,
    RateModel, ReorderModel, TimelineStep, Window,
};

/// A rate model that nothing below objects to, so a mutation of one field is
/// the only reason a rate case can fail.
fn healthy_rate() -> RateModel {
    RateModel { bps: 10_000_000, burst_bytes: 64 * 1024, queue_bytes: 256 * 1024 }
}

/// A direction profile with no impairment at all.
fn blank() -> DirectionProfile {
    DirectionProfile::default()
}

/// The error a direction profile is refused with. Panics if it is accepted,
/// because "this profile is legal after all" is a distinct failure from "the
/// wrong error came back" and the two should not be reported as one.
fn refusal(profile: DirectionProfile) -> ProfileError {
    match profile.validate() {
        Err(e) => e,
        Ok(()) => panic!("expected a refusal, got Ok: {profile:?}"),
    }
}

/// Every variant, each obtained from an input rather than written down.
///
/// The order matches the enum's declaration order, purely so a reader can put
/// the two side by side.
fn every_error_reached_from_an_input() -> Vec<ProfileError> {
    vec![
        // A reorder model with nothing to reorder against.
        refusal(DirectionProfile {
            reorder: Some(ReorderModel { gap: 8, p: Prob::from_ppb(500_000_000) }),
            ..blank()
        }),
        // A reorder model that reorders every zeroth datagram — with a delay
        // present, so this cannot be the missing-delay case above.
        refusal(DirectionProfile {
            delay: Some(DelayModel::Fixed { mean_ns: 1_000_000 }),
            reorder: Some(ReorderModel { gap: 0, p: Prob::from_ppb(500_000_000) }),
            ..blank()
        }),
        // Loss on every zeroth datagram.
        refusal(DirectionProfile { loss: Some(LossModel::EveryNth { n: 0 }), ..blank() }),
        // Two timeline steps at the same tick.
        refusal(DirectionProfile {
            timeline: vec![
                TimelineStep { at_ns: 5_000_000, profile: Box::new(blank()) },
                TimelineStep { at_ns: 5_000_000, profile: Box::new(blank()) },
            ],
            ..blank()
        }),
        // A first timeline step that lands before the profile has decided
        // anything.
        refusal(DirectionProfile {
            timeline: vec![TimelineStep { at_ns: 0, profile: Box::new(blank()) }],
            ..blank()
        }),
        // A timeline inside a timeline.
        refusal(DirectionProfile {
            timeline: vec![TimelineStep {
                at_ns: 5_000_000,
                profile: Box::new(DirectionProfile {
                    timeline: vec![TimelineStep { at_ns: 9_000_000, profile: Box::new(blank()) }],
                    ..blank()
                }),
            }],
            ..blank()
        }),
        // A blackout that covers no instant.
        refusal(DirectionProfile {
            blackouts: vec![Window { at_ns: 1_000_000, for_ns: 0 }],
            ..blank()
        }),
        // A queue that is full before anything arrives.
        refusal(DirectionProfile {
            rate: Some(RateModel { queue_bytes: 0, ..healthy_rate() }),
            ..blank()
        }),
        // A bucket that never earns a token.
        refusal(DirectionProfile { rate: Some(RateModel { bps: 0, ..healthy_rate() }), ..blank() }),
        // A bucket too shallow to ever hold one datagram: the plausible
        // hand-written mistake, 100 Mbps with a 1000-byte burst.
        refusal(DirectionProfile {
            rate: Some(RateModel { bps: 100_000_000, burst_bytes: 1000, queue_bytes: 1_000_000 }),
            ..blank()
        }),
        // A peer filter naming no peers. This one is on the whole profile,
        // because the filter is not a direction field.
        ImpairProfile { peers: PeerFilter::Only(vec![]), ..ImpairProfile::default() }
            .validate()
            .expect_err("an empty peer filter must be refused"),
        // A peer filter that names a peer, in a form no peer can present: the
        // port left at the value a socket binds with.
        ImpairProfile {
            peers: PeerFilter::Only(vec!["198.51.100.4:0".parse().expect("a literal address")]),
            ..ImpairProfile::default()
        }
        .validate()
        .expect_err("a filter entry on port 0 must be refused"),
        // A probability that is not a number. The only variant not reachable
        // through `validate`, because it is the one mistake that is caught
        // before a profile can be assembled at all.
        Prob::from_f64(f64::NAN).expect_err("NaN must be refused"),
    ]
}

/// Every variant is reachable from an input, and renders its frozen message.
///
/// The `match` is exhaustive with no `_` arm. That is not style: it is what
/// makes a fourteenth variant a compile error in this file rather than a
/// silently untested addition. The discriminant check above it is what makes
/// "thirteen values" mean "thirteen *different* variants" — thirteen
/// `RateBurstBelowDatagram`s with different field values would otherwise
/// satisfy a count and a distinctness check on the values alone.
///
/// ```text
/// error[E0004]: non-exhaustive patterns:
///   `ProfileError::FourteenthVariantWithNoTrigger` not covered
///    --> crates\quinn-netem\tests\profile_errors.rs:176:34
/// ```
///
/// Then, with a `_ => continue` arm added to the same match and the
/// fourteenth variant left in place, `test result: ok. 5 passed; 0 failed`.
/// That second leg is the one worth recording: it is exactly what this file
/// would do if the enum were marked non-exhaustive, since that attribute
/// forces the wildcard on any match written outside the defining crate.
#[test]
fn every_profile_error_is_reachable_and_renders_its_message() {
    let reached = every_error_reached_from_an_input();
    assert_eq!(reached.len(), 13, "thirteen variants, thirteen construction paths");

    for (i, a) in reached.iter().enumerate() {
        for (j, b) in reached.iter().enumerate().skip(i + 1) {
            assert_ne!(
                std::mem::discriminant(a),
                std::mem::discriminant(b),
                "cases {i} and {j} reached the same variant, so one variant is untested"
            );
        }
    }

    for error in &reached {
        let want: String = match *error {
            ProfileError::ReorderWithoutDelay => {
                "reorder model requires a delay model on the same direction".into()
            }
            ProfileError::ReorderGapZero => {
                "reorder gap is 0, which can never fire; use reorder: None".into()
            }
            ProfileError::EveryNthZero => "EveryNth n is 0, which can never fire".into(),
            ProfileError::TimelineNotIncreasing => {
                "timeline steps must have strictly increasing at_ns".into()
            }
            ProfileError::TimelineStepAtZero => {
                "the first timeline step must be at a tick greater than 0".into()
            }
            ProfileError::NestedTimeline => {
                "a timeline step's profile may not carry its own timeline".into()
            }
            ProfileError::BlackoutZeroLength => {
                "blackout window has for_ns 0, which can never fire".into()
            }
            ProfileError::RateWithZeroQueue => {
                "rate model has queue_bytes 0, which tail-drops every datagram on an empty queue"
                    .into()
            }
            ProfileError::RateWithZeroBps => {
                "rate model has bps 0; a profile that drops everything says so with a loss model"
                    .into()
            }
            ProfileError::RateBurstBelowDatagram { burst_bytes, min_wire_bytes } => format!(
                "rate model burst_bytes {burst_bytes} is below one on-wire datagram of \
                 {min_wire_bytes} bytes"
            ),
            ProfileError::PeerFilterMatchesNothing => {
                "peer filter Only(..) is empty and can match no peer".into()
            }
            ProfileError::PeerFilterEntryCannotMatch { addr } => format!(
                "peer filter entry {addr} can never match: a peer presents neither an \
                 unspecified address nor port 0"
            ),
            ProfileError::ProbabilityNotANumber => {
                "probability is NaN; Prob::from_f64 clamps out-of-range but refuses NaN".into()
            }
        };
        assert_eq!(error.to_string(), want, "{error:?}");
    }
}

/// The two numbers in the parameterised message are the ones the caller
/// actually wrote, not placeholders.
///
/// Asserted separately because the exhaustive match above renders the expected
/// text *from the error's own fields*, so it would agree with itself if
/// `validate` reported `burst_bytes: 0, min_wire_bytes: 0`. A message that
/// names the wrong two numbers is worse than one that names none: it sends the
/// reader to look at a field they did not set.
#[test]
fn the_burst_message_names_the_configured_depth_and_the_datagram_it_cannot_hold() {
    let too_shallow = DirectionProfile {
        rate: Some(RateModel { bps: 100_000_000, burst_bytes: 1000, queue_bytes: 1_000_000 }),
        ..blank()
    };

    assert_eq!(
        too_shallow.validate().expect_err("a 1000-byte bucket cannot hold a datagram").to_string(),
        "rate model burst_bytes 1000 is below one on-wire datagram of 1500 bytes"
    );
}

/// The address in the peer-filter message is the entry that cannot match, not
/// the first entry in the list.
///
/// Asserted separately for the reason the burst message is: the exhaustive
/// match above builds its expected text out of the error's own `addr`, so it
/// would agree with itself if `validate` reported whichever address it saw
/// first. A filter of three entries with the dead one in the middle is the
/// case that tells those two implementations apart, and it is also the case a
/// reader is in when they need the message — a one-entry filter needs no
/// message to find the mistake.
#[test]
fn the_peer_filter_message_names_the_entry_that_cannot_match() {
    let parse = |a: &str| -> std::net::SocketAddr { a.parse().expect("a literal address") };
    let profile = ImpairProfile {
        peers: PeerFilter::Only(vec![
            parse("127.0.0.1:4433"),
            parse("192.0.2.7:0"),
            parse("198.51.100.4:4433"),
        ]),
        ..ImpairProfile::default()
    };

    assert_eq!(
        profile.validate().expect_err("port 0 cannot be a peer").to_string(),
        "peer filter entry 192.0.2.7:0 can never match: a peer presents neither an \
         unspecified address nor port 0"
    );
}

/// `ProfileError` is a `std::error::Error`, so `?` lifts it into a boxed
/// application error without a wrapper type.
///
/// This is a compile-time claim more than a runtime one, and it is the reason
/// the trait impl exists at all: this crate has no dependencies, so there is
/// no derive macro available and the impl is hand-written. An impl that was
/// dropped would not fail any assertion — it would fail to build this
/// function, which is exactly the signal wanted.
#[test]
fn a_profile_error_lifts_into_a_boxed_application_error() {
    fn arm(profile: &ImpairProfile) -> Result<(), Box<dyn std::error::Error>> {
        profile.validate()?;
        Ok(())
    }

    let bad = ImpairProfile { peers: PeerFilter::Only(vec![]), ..ImpairProfile::default() };
    let boxed = arm(&bad).expect_err("an empty peer filter must be refused");
    assert_eq!(boxed.to_string(), "peer filter Only(..) is empty and can match no peer");

    assert!(arm(&ImpairProfile::default()).is_ok());
}

/// The out-of-range half of the probability constructor: finite values clamp,
/// and only NaN is refused.
///
/// Clamping and refusing are deliberately different answers. `p = 1.5` has one
/// possible meaning — certainty — so refusing it would be pedantry. NaN has no
/// meaning at all, and the truncating cast in the constructor turns it into
/// p = 0, i.e. *drop nothing*: an impairment that is configured, accepted, and
/// then silently never delivered.
#[test]
fn the_probability_constructor_refuses_nan_and_clamps_out_of_range() {
    assert_eq!(Prob::from_f64(f64::NAN), Err(ProfileError::ProbabilityNotANumber));

    let above = Prob::from_f64(1.5).expect("1.5 clamps to certainty");
    assert!(above.hits(0) && above.hits(u32::MAX), "clamped to p = 1");
    assert_eq!(above, Prob::from_ppb(1_000_000_000));

    let below = Prob::from_f64(-0.5).expect("-0.5 clamps to impossibility");
    assert!(!below.hits(0) && !below.hits(u32::MAX), "clamped to p = 0");
    assert_eq!(below, Prob::from_ppb(0));

    // Infinities are finite-valued after the clamp and must not be refused —
    // they are the one out-of-range input a caller reaches by dividing, and
    // their intent is as unambiguous as 1.5's.
    assert_eq!(Prob::from_f64(f64::INFINITY), Ok(Prob::from_ppb(1_000_000_000)));
    assert_eq!(Prob::from_f64(f64::NEG_INFINITY), Ok(Prob::from_ppb(0)));
}

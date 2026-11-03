//! The device's monotonic clock against ingest's, from the four-timestamp
//! exchange of each request: `t1` device send and `t4` device receive on the
//! monotonic clock, `t2` ingest receive and `t3` ingest send, whole ms.
//!
//! ```text
//! offset = ((t2 - t1) + (t3 - t4)) / 2
//! delay  = (t4 - t1) - (t3 - t2)
//! ```
//!
//! Wall time maps nothing. It is read beside the monotonic clock only to
//! catch a break: a suspend, or a step of either clock.

use std::time::Instant;

use crate::wire::ClockSample;

/// The assumed drift between the device and ingest clocks, as a fraction:
/// 100 ppm.
pub const DRIFT: f64 = 100e-6;

/// A change of wall minus monotonic time past this, beyond what [`DRIFT`]
/// allows, is a clock break, µs.
pub(crate) const B_BREAK_US: i64 = 20_000;

/// Ingest's whole-ms timestamps: a round trip can read up to this much
/// under the truth, µs.
const T23_QUANTUM_US: i64 = 1000;

/// An exchange's sample, or `None` when it cannot be true.
pub(crate) fn exchange(
    t1_us: i64,
    t2_ms: i64,
    t3_ms: i64,
    t4_us: i64,
    pop: Option<String>,
) -> Option<ClockSample> {
    let (t2, t3) = (t2_ms.checked_mul(1000)?, t3_ms.checked_mul(1000)?);
    let rtt = (t4_us - t1_us).checked_sub(t3.checked_sub(t2)?)?;
    if t4_us < t1_us || t3 < t2 || rtt < -T23_QUANTUM_US {
        return None;
    }
    let o_us = ((t2 - t1_us).checked_add(t3 - t4_us)?).div_euclid(2);
    Some(ClockSample {
        o_us,
        r_us: rtt.max(0) as u64,
        at_us: t1_us + (t4_us - t1_us) / 2,
        pop: pop.filter(|p| valid_pop(p)),
    })
}

/// A PoP as the reader takes it: `[A-Za-z0-9-]{1,16}`.
fn valid_pop(p: &str) -> bool {
    (1..=16).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Wall minus monotonic time at the last check.
#[derive(Debug, Default)]
pub(crate) struct BreakCheck {
    anchor: Option<(i64, i64)>,
}

impl BreakCheck {
    /// True when wall minus monotonic time moved past [`B_BREAK_US`] plus
    /// [`DRIFT`] times the time since the last check.
    pub(crate) fn check(&mut self, wall_us: i64, mono_us: i64) -> bool {
        let skew = wall_us - mono_us;
        let broke = self.anchor.is_some_and(|(anchor, at)| {
            let allowed = B_BREAK_US as f64 + DRIFT * (mono_us - at).abs() as f64;
            (skew - anchor).abs() as f64 > allowed
        });
        self.anchor = Some((skew, mono_us));
        broke
    }
}

/// The smallest non-zero step of the monotonic clock, µs, at least 1.
pub(crate) fn resolution_us() -> u64 {
    let mut best = u128::MAX;
    for _ in 0..8 {
        let a = Instant::now();
        let mut b = Instant::now();
        let mut spins = 0;
        while b == a && spins < 1_000_000 {
            b = Instant::now();
            spins += 1;
        }
        let step = b.duration_since(a).as_nanos();
        if step > 0 {
            best = best.min(step);
        }
    }
    if best == u128::MAX {
        return 1;
    }
    (best.div_ceil(1000) as u64).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offset_and_round_trip_from_four_timestamps() {
        // Ingest 5 s ahead of mono, 20 ms each way, 2 ms at ingest.
        let s = exchange(1_000_000, 6_020, 6_022, 1_042_000, Some("FRA".into())).unwrap();
        assert_eq!(
            s,
            ClockSample {
                o_us: 5_000_000,
                r_us: 40_000,
                at_us: 1_021_000,
                pop: Some("FRA".into())
            }
        );
    }

    #[test]
    fn a_round_trip_under_a_millisecond_reads_as_zero() {
        // 300 µs over loopback, but t2 and t3 fall on either side of a ms.
        let s = exchange(10_000_000, 20_000, 20_001, 10_000_300, None).unwrap();
        assert_eq!(s.r_us, 0);
        assert!(exchange(10_000_000, 20_000, 20_003, 10_000_300, None).is_none());
        assert!(exchange(10, 1, 0, 20, None).is_none(), "t3 before t2");
    }

    #[test]
    fn a_pop_that_does_not_read_is_dropped() {
        let s = exchange(0, 0, 0, 10, Some("FRA 1".into())).unwrap();
        assert_eq!(s.pop, None);
    }

    #[test]
    fn a_step_of_wall_time_is_a_break_and_drift_is_not() {
        let mut b = BreakCheck::default();
        assert!(!b.check(1_000_000_000, 0));
        // 60 s later, the wall clock 3 ms ahead: within 20 ms + 6 ms.
        assert!(!b.check(1_060_003_000, 60_000_000));
        // A 2 s step.
        assert!(b.check(1_062_003_000, 60_000_100));
        // Monotonic time stopped for a suspend of a minute.
        assert!(b.check(1_122_003_000, 60_000_200));
    }

    #[test]
    fn resolution_is_at_least_a_microsecond() {
        assert!(resolution_us() >= 1);
    }
}

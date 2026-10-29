//! The device clock against ingest's, from the four-timestamp exchange each
//! upload makes: `t1` device send, `t2` ingest receive, `t3` ingest send,
//! `t4` device receive.
//!
//! ```text
//! offset = ((t2 - t1) + (t3 - t4)) / 2
//! delay  = (t4 - t1) - (t3 - t2)
//! ```

use std::collections::VecDeque;

use crate::wire::Clock;

/// The assumed drift between the device and ingest clocks, as a fraction:
/// 100 ppm.
pub const DRIFT: f64 = 100e-6;

/// How long a sample stays a candidate, in ms.
pub(crate) const WINDOW_MS: f64 = 10.0 * 60.0 * 1000.0;

#[derive(Clone, Copy, Debug)]
struct Sample {
    offset_ms: f64,
    rtt_ms: f64,
    mono_ms: f64,
}

/// The samples of the last ten minutes. A body carries the one with the
/// smallest bound `rtt / 2 + DRIFT * age`.
#[derive(Debug, Default)]
pub(crate) struct ClockWindow {
    samples: VecDeque<Sample>,
    /// Device wall minus monotonic time when last checked, and the
    /// monotonic time of that check, ms.
    anchor: Option<(f64, f64)>,
}

impl ClockWindow {
    /// Fold one exchange in. `wall_ms` and `mono_ms` are read together, at `t4`.
    /// A sample that cannot be true (non-finite, or a negative round trip) is
    /// ignored.
    pub(crate) fn sample(&mut self, t1: f64, t2: f64, t3: f64, t4: f64, mono_ms: f64) {
        if ![t1, t2, t3, t4, mono_ms].iter().all(|v| v.is_finite()) {
            return;
        }
        self.check_step(t4, mono_ms);
        let rtt_ms = (t4 - t1) - (t3 - t2);
        if rtt_ms.is_nan() || rtt_ms < 0.0 {
            return;
        }
        let offset_ms = ((t2 - t1) + (t3 - t4)) / 2.0;
        self.samples.push_back(Sample { offset_ms, rtt_ms, mono_ms });
        self.expire(mono_ms);
    }

    /// The clock for a body sealed now, or `None` with no usable sample.
    pub(crate) fn best(&mut self, wall_ms: f64, mono_ms: f64) -> Option<Clock> {
        self.check_step(wall_ms, mono_ms);
        self.expire(mono_ms);
        let bound = |s: &Sample| s.rtt_ms / 2.0 + DRIFT * (mono_ms - s.mono_ms).max(0.0);
        let best = self.samples.iter().min_by(|a, b| bound(a).total_cmp(&bound(b)))?;
        Some(Clock {
            o: round3(best.offset_ms),
            r: round3(best.rtt_ms),
            n: self.samples.len() as u64,
            a: round3((mono_ms - best.mono_ms).max(0.0) / 1000.0),
        })
    }

    /// A wall-clock step makes every sample wrong: the window empties. A
    /// step is wall minus monotonic time moving by more than the best round
    /// trip plus `DRIFT` times the time since the last check, the rate the
    /// two clocks may drift apart.
    fn check_step(&mut self, wall_ms: f64, mono_ms: f64) {
        let skew = wall_ms - mono_ms;
        if let Some((anchor, at)) = self.anchor {
            let best_rtt = self.samples.iter().map(|s| s.rtt_ms).fold(f64::INFINITY, f64::min);
            if (skew - anchor).abs() > best_rtt + DRIFT * (mono_ms - at).abs() {
                self.samples.clear();
            }
        }
        self.anchor = Some((skew, mono_ms));
    }

    fn expire(&mut self, mono_ms: f64) {
        while self.samples.front().is_some_and(|s| mono_ms - s.mono_ms > WINDOW_MS) {
            self.samples.pop_front();
        }
    }
}

fn round3(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offset_and_round_trip_from_four_timestamps() {
        let mut w = ClockWindow::default();
        // Device 5 s behind ingest, 20 ms each way, 2 ms at ingest.
        w.sample(1_000.0, 6_020.0, 6_022.0, 1_042.0, 1_042.0);
        let c = w.best(1_042.0, 1_042.0).unwrap();
        assert_eq!(c, Clock { o: 5_000.0, r: 40.0, n: 1, a: 0.0 });
    }

    #[test]
    fn keeps_the_smallest_bound_not_the_smallest_round_trip() {
        let mut w = ClockWindow::default();
        // 10 ms round trip, then one of 30 ms nine minutes later.
        w.sample(0.0, 5.0, 5.0, 10.0, 10.0);
        let later = 10.0 + 9.0 * 60_000.0;
        w.sample(later - 30.0, later - 10.0, later - 10.0, later, later);
        // Bounds: 5 + 54 ms against 15 ms: the newer one wins.
        let c = w.best(later, later).unwrap();
        assert_eq!((c.r, c.n, c.a), (30.0, 2, 0.0));
        // Right after the first, the first wins.
        let mut w = ClockWindow::default();
        w.sample(0.0, 5.0, 5.0, 10.0, 10.0);
        w.sample(10.0, 25.0, 25.0, 40.0, 40.0);
        assert_eq!(w.best(40.0, 40.0).unwrap().r, 10.0);
    }

    #[test]
    fn samples_older_than_ten_minutes_expire() {
        let mut w = ClockWindow::default();
        w.sample(0.0, 5.0, 5.0, 10.0, 10.0);
        assert!(w.best(10.0 + WINDOW_MS + 1.0, 10.0 + WINDOW_MS + 1.0).is_none());
    }

    #[test]
    fn a_wall_clock_step_empties_the_window() {
        let mut w = ClockWindow::default();
        w.sample(0.0, 5.0, 5.0, 10.0, 10.0);
        // Wall jumps 2 s ahead of monotonic time.
        assert!(w.best(2_020.0, 20.0).is_none());
    }

    #[test]
    fn drift_within_the_drift_bound_is_not_a_step() {
        let mut w = ClockWindow::default();
        // A 2 ms round trip, then a minute in which the wall clock gains
        // 1.2 ms (20 ppm) on monotonic time: under 2 ms + 6 ms.
        w.sample(0.0, 1.0, 1.0, 2.0, 2.0);
        let later = 2.0 + 60_000.0;
        assert_eq!(w.best(later + 1.2, later).map(|c| c.n), Some(1));
        // 9 ms in the next minute is past 2 ms + 6 ms.
        assert!(w.best(later + 60_000.0 + 10.2, later + 60_000.0).is_none());
    }

    #[test]
    fn a_negative_round_trip_is_ignored() {
        let mut w = ClockWindow::default();
        w.sample(0.0, 50.0, 60.0, 5.0, 5.0);
        assert!(w.best(5.0, 5.0).is_none());
    }
}

//! Group sampling: a track with exponent `k` reports only groups whose id is
//! `0 mod 2^k`. Each track's `k` follows its own group rate against
//! [`TARGET_GROUPS_PER_SEC`]. The browser monitor measures the rate the same
//! way and rounds `k` up where this monitor rounds it down, so every group a
//! viewer reports is one the producer reports too.

/// The group rate per track that sampling aims at.
pub const TARGET_GROUPS_PER_SEC: u32 = 10;

/// The window a track's group rate is measured over, in seconds.
pub const RATE_WINDOW_SECS: u32 = 10;

/// The largest exponent a body may declare.
pub(crate) const MAX_K: u8 = 20;

/// The exponents `0..=MAX_K`.
pub(crate) const LEVELS: usize = MAX_K as usize + 1;

/// Groups in a window at the target rate.
const TARGET: f64 = (TARGET_GROUPS_PER_SEC * RATE_WINDOW_SECS) as f64;

/// How far over the target the next exponent must keep before `k` is
/// raised, so a track whose rate sits at a boundary does not change `k`
/// every second.
const RAISE_MARGIN: f64 = 1.125;

/// The window's seconds and the current one.
const SLOTS: usize = RATE_WINDOW_SECS as usize + 1;

/// Whether `group` is in the sample for exponent `k`.
pub(crate) fn in_sample(group: u64, k: u8) -> bool {
    group & ((1u64 << k) - 1) == 0
}

/// The largest exponent whose sample holds `group`.
pub(crate) fn level(group: u64) -> usize {
    (group.trailing_zeros() as usize).min(MAX_K as usize)
}

/// The groups a track started in each second of the window, by the largest
/// exponent that keeps them.
#[derive(Debug)]
pub(crate) struct Rate {
    /// One bucket per second, at `second mod SLOTS`.
    slots: [[u16; LEVELS]; SLOTS],
    /// The window's buckets summed.
    window: [u32; LEVELS],
    /// The current second.
    head: Option<i64>,
}

impl Rate {
    pub(crate) fn new() -> Self {
        Rate { slots: [[0; LEVELS]; SLOTS], window: [0; LEVELS], head: None }
    }

    /// Move to the second holding `mono_ms`. True when the window changed.
    pub(crate) fn advance(&mut self, mono_ms: f64) -> bool {
        let s = (mono_ms / 1000.0).floor() as i64;
        let h = match self.head {
            Some(h) if s > h => h,
            Some(_) => return false,
            None => {
                self.head = Some(s);
                return false;
            }
        };
        self.head = Some(s);
        if s - h > i64::from(RATE_WINDOW_SECS) {
            *self = Rate { head: Some(s), ..Rate::new() };
            return true;
        }
        for x in h + 1..=s {
            let done = slot(x - 1);
            let out = slot(x);
            for l in 0..LEVELS {
                self.window[l] += u32::from(self.slots[done][l]);
                self.window[l] -= u32::from(self.slots[out][l]);
            }
            self.slots[out] = [0; LEVELS];
        }
        true
    }

    /// Count a group started in the current second.
    pub(crate) fn add(&mut self, group: u64) {
        if let Some(h) = self.head {
            let n = &mut self.slots[slot(h)][level(group)];
            *n = n.saturating_add(1);
        }
    }

    /// Groups in the window that exponent `k` keeps.
    pub(crate) fn kept(&self, k: u8) -> u32 {
        self.window[usize::from(k)..].iter().sum()
    }

    /// The largest exponent keeping more than `n` groups of the window, or 0.
    fn largest_above(&self, n: f64) -> u8 {
        let mut sum = 0;
        for k in (0..LEVELS).rev() {
            sum += self.window[k];
            if f64::from(sum) > n {
                return k as u8;
            }
        }
        0
    }

    /// The viewer's rule: the smallest exponent keeping at most the target.
    #[cfg(test)]
    pub(crate) fn viewer_k(&self) -> u8 {
        (0..=MAX_K).find(|&k| f64::from(self.kept(k)) <= TARGET).unwrap_or(MAX_K)
    }
}

fn slot(second: i64) -> usize {
    second.rem_euclid(SLOTS as i64) as usize
}

/// The producer's exponent after the window moved, from `k`: the largest
/// exponent that keeps more than the target, lowered at once and raised only
/// past [`RAISE_MARGIN`].
pub(crate) fn producer_k(rate: &Rate, k: u8) -> u8 {
    if k > 0 && f64::from(rate.kept(k)) <= TARGET {
        return rate.largest_above(TARGET);
    }
    rate.largest_above(TARGET * RAISE_MARGIN).max(k)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `secs` seconds of `rate` groups a second, ids stepping by `step`; the
    /// window as it stands at the end, and the producer's `k` along the way.
    fn steady(rate: u64, step: u64, secs: u64) -> (Rate, u8) {
        let mut r = Rate::new();
        let mut k = 0;
        for i in 0..rate * secs {
            if r.advance(i as f64 * 1000.0 / rate as f64) {
                k = producer_k(&r, k);
            }
            r.add(i * step);
        }
        (r, k)
    }

    #[test]
    fn sample_is_group_mod_two_to_the_k() {
        assert!(in_sample(0, 3) && in_sample(8, 3) && in_sample(16, 3));
        assert!(!in_sample(9, 3));
        assert!((0..100).all(|g| in_sample(g, 0)));
        assert!(in_sample(1 << 40, 20) && !in_sample((1 << 20) + 1, 20));
        assert_eq!((level(0), level(1), level(12), level(1 << 40)), (20, 0, 2, 20));
    }

    #[test]
    fn the_window_holds_the_ten_whole_seconds_before_the_current_one() {
        let (r, _) = steady(30, 1, 20);
        assert_eq!(r.kept(0), 300);
        assert_eq!(r.kept(1), 150);
        // Nothing for longer than the window empties it.
        let mut r = r;
        assert!(r.advance(40_000.0));
        assert_eq!(r.kept(0), 0);
        // A second with no group still moves the window.
        let mut r = Rate::new();
        for s in 0..5 {
            r.advance(s as f64 * 1000.0);
            r.add(1);
        }
        r.advance(15_000.0);
        assert_eq!(r.kept(0), 0);
        r.advance(4_000.0);
        assert_eq!(r.kept(0), 0, "time going back changes nothing");
    }

    #[test]
    fn the_producer_rounds_down_and_the_viewer_up() {
        // (rate, id step, producer k, viewer k)
        for (rate, step, kp, kv) in [
            (5, 1, 0, 0),
            (10, 1, 0, 0),
            (15, 1, 0, 1),
            (30, 1, 1, 2),
            (40, 1, 1, 2),
            (50, 1, 2, 3),
            (1000, 1, 6, 7),
            (30, 2, 2, 3),
            (40, 4, 3, 4),
        ] {
            let (r, k) = steady(rate, step, 30);
            assert_eq!((k, r.viewer_k()), (kp, kv), "{rate}/s, ids step {step}");
        }
    }

    #[test]
    fn the_producer_lowers_at_once_and_raises_past_the_margin() {
        let window = |n: u64| {
            let mut r = Rate::new();
            r.advance(0.0);
            (0..n).for_each(|g| r.add(g));
            r.advance(1_000.0);
            r
        };
        // k = 1 would keep 110: past the target, not past the margin.
        let r = window(220);
        assert_eq!((producer_k(&r, 0), producer_k(&r, 1)), (0, 1));
        // 113 is past the margin.
        assert_eq!(producer_k(&window(226), 0), 1);
        // 90 at k = 1 is within the target: lowered.
        assert_eq!(producer_k(&window(180), 1), 0);
        assert_eq!(producer_k(&window(180), 3), 0);
    }
}

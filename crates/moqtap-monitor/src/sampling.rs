//! Group sampling by hash level: a (track, group) has level
//! `min(20, clz64(splitmix64(track_key ^ group)))` and is in the sample at
//! exponent `k` when its level is at least `k`, so the samples nest and any
//! id pattern is sampled evenly. Each body takes one `k` per track, from the
//! track's group rate within the body.

/// The group rate per track that sampling aims at.
pub const TARGET_GROUPS_PER_SEC: u32 = 10;

/// The largest exponent a body may declare.
pub(crate) const MAX_K: u8 = 20;

/// The exponents `0..=MAX_K`.
pub(crate) const LEVELS: usize = MAX_K as usize + 1;

/// How far over the target the next exponent must keep before `k` is
/// raised, so a track whose rate sits at a boundary does not change `k`
/// every body.
const RAISE_MARGIN: f64 = 1.125;

fn splitmix64(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// The largest exponent whose sample holds `group` of the track `tk`.
pub(crate) fn level(tk: u64, group: u64) -> u8 {
    (splitmix64(tk ^ group).leading_zeros() as u8).min(MAX_K)
}

/// A track's distinct groups in one body, by level, over `span_us`: the time
/// from its first group's first handoff to its last group's.
pub(crate) struct BodyGroups<'a> {
    pub by_level: &'a [u32; LEVELS],
    pub span_us: i64,
}

impl BodyGroups<'_> {
    /// Groups a second that exponent `k` keeps; `None` with no span to
    /// measure a rate over.
    fn kept(&self, k: u8) -> Option<f64> {
        if self.span_us <= 0 {
            return None;
        }
        let n: u32 = self.by_level[usize::from(k)..].iter().sum();
        Some(f64::from(n) / (self.span_us as f64 / 1e6))
    }

    /// The largest exponent keeping more than `rate` groups a second, or 0.
    fn largest_above(&self, rate: f64) -> u8 {
        (1..=MAX_K).rev().find(|&k| self.kept(k).is_some_and(|r| r > rate)).unwrap_or(0)
    }
}

/// The track's exponent for this body, from the previous body's `prev`:
/// the largest exponent that keeps more than the target, lowered at once
/// and raised only past [`RAISE_MARGIN`]. A body with a single group time
/// has no rate and keeps every group.
pub(crate) fn body_k(groups: &BodyGroups<'_>, prev: u8) -> u8 {
    let target = f64::from(TARGET_GROUPS_PER_SEC);
    if groups.span_us <= 0 {
        return 0;
    }
    if prev > 0 && groups.kept(prev).is_some_and(|r| r <= target) {
        return groups.largest_above(target);
    }
    groups.largest_above(target * RAISE_MARGIN).max(prev)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One body of `secs` seconds at `rate` groups a second, ids from
    /// `first` stepping by `step`.
    fn body(tk: u64, rate: u64, step: u64, secs: u64) -> ([u32; LEVELS], i64) {
        let mut by_level = [0u32; LEVELS];
        let n = rate * secs;
        for i in 0..n {
            by_level[usize::from(level(tk, 1000 + i * step))] += 1;
        }
        (by_level, ((n - 1) * 1_000_000 / rate) as i64)
    }

    #[test]
    fn levels_nest_and_are_capped() {
        assert!((0..10_000u64).all(|g| level(7, g) <= MAX_K));
        // About half of all groups are at level 1 or more, a quarter at 2.
        let n = (0..100_000u64).filter(|&g| level(0x6ea5_e279_e5a8_b218, g) >= 2).count();
        assert!((23_000..27_000).contains(&n), "{n}");
    }

    #[test]
    fn stepped_ids_are_sampled_evenly() {
        // Ids that are all multiples of 1000 keep about 1/2^k of the groups.
        let n = (0..40_000u64).filter(|&i| level(42, i * 1000) >= 3).count();
        assert!((4_500..5_500).contains(&n), "{n}");
    }

    #[test]
    fn k_follows_the_body_s_group_rate() {
        for (rate, want) in [(4, 0), (10, 0), (15, 0), (30, 1), (100, 3), (1000, 6)] {
            let (by_level, span_us) = body(99, rate, 1, 15);
            let k = body_k(&BodyGroups { by_level: &by_level, span_us }, 0);
            assert_eq!(k, want, "{rate}/s");
        }
    }

    #[test]
    fn k_lowers_at_once_and_raises_past_the_margin() {
        let mut by_level = [0u32; LEVELS];
        // 11 groups a second kept at k = 1: past the target, not the margin.
        by_level[1] = 11;
        let g = BodyGroups { by_level: &by_level, span_us: 1_000_000 };
        assert_eq!((body_k(&g, 0), body_k(&g, 1)), (0, 1));
        by_level[1] = 12;
        assert_eq!(body_k(&BodyGroups { by_level: &by_level, span_us: 1_000_000 }, 0), 1);
        by_level[1] = 9;
        assert_eq!(body_k(&BodyGroups { by_level: &by_level, span_us: 1_000_000 }, 1), 0);
        assert_eq!(body_k(&BodyGroups { by_level: &by_level, span_us: 0 }, 3), 0);
    }
}

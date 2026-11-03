//! The log histogram's bucket rule: key 0 holds a gap under 1 ms, key
//! `k >= 1` covers `[1.05^(k-1), 1.05^k)` ms. The edges are exact: edge `j`
//! is the least whole µs `a` with `a * 20^j >= 1000 * 21^j`.

use std::sync::OnceLock;

/// Gaps past the last edge share its key.
const LIMIT_US: u64 = 1 << 53;

/// The bucket key of a gap in µs.
pub(crate) fn key_of(gap_us: i64) -> u32 {
    if gap_us < 1000 {
        return 0;
    }
    let e = edges();
    let a = gap_us as u64;
    // The number of edges at or below `a`.
    e.partition_point(|&edge| edge <= a) as u32
}

fn edges() -> &'static [u64] {
    static EDGES: OnceLock<Vec<u64>> = OnceLock::new();
    EDGES.get_or_init(|| {
        let mut out = Vec::new();
        let mut num = Big::from(1000);
        let mut den = Big::from(1);
        let mut approx = 1000.0f64;
        loop {
            // Start from the float, then settle on the exact least `a`.
            let mut a = approx.ceil() as u64;
            while a > 0 && den.mul(a - 1).ge(&num) {
                a -= 1;
            }
            while !den.mul(a).ge(&num) {
                a += 1;
            }
            if a > LIMIT_US {
                return out;
            }
            out.push(a);
            num = num.mul(21);
            den = den.mul(20);
            approx *= 1.05;
        }
    })
}

/// A non-negative integer as little-endian base-2^32 limbs.
#[derive(Clone)]
struct Big(Vec<u32>);

impl Big {
    fn from(v: u64) -> Big {
        Big(vec![v as u32, (v >> 32) as u32])
    }

    fn mul(&self, m: u64) -> Big {
        let (lo, hi) = (m & 0xffff_ffff, m >> 32);
        let part = |f: u64, shift: usize| {
            let mut out = vec![0u32; shift];
            let mut carry = 0u64;
            for &l in &self.0 {
                let v = u64::from(l) * f + carry;
                out.push(v as u32);
                carry = v >> 32;
            }
            out.push(carry as u32);
            out
        };
        let (a, b) = (part(lo, 0), part(hi, 1));
        let mut out = vec![0u32; a.len().max(b.len()) + 1];
        let mut carry = 0u64;
        for (i, slot) in out.iter_mut().enumerate() {
            let v = u64::from(*a.get(i).unwrap_or(&0)) + u64::from(*b.get(i).unwrap_or(&0)) + carry;
            *slot = v as u32;
            carry = v >> 32;
        }
        Big(out)
    }

    fn ge(&self, other: &Big) -> bool {
        let n = self.0.len().max(other.0.len());
        for i in (0..n).rev() {
            let (a, b) = (*self.0.get(i).unwrap_or(&0), *other.0.get(i).unwrap_or(&0));
            if a != b {
                return a > b;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edges_match_the_latency_histogram() {
        let e = edges();
        assert_eq!(
            &e[..12],
            [1000, 1050, 1103, 1158, 1216, 1277, 1341, 1408, 1478, 1552, 1629, 1711]
        );
        assert_eq!(e[72], 33_546);
        assert!(*e.last().unwrap() <= LIMIT_US);
    }

    #[test]
    fn keys_follow_the_edges() {
        assert_eq!(key_of(-5), 0);
        assert_eq!(key_of(999), 0);
        assert_eq!(key_of(1000), 1);
        assert_eq!(key_of(1049), 1);
        assert_eq!(key_of(1050), 2);
        assert_eq!(key_of(33_333), 72);
        assert_eq!(key_of(i64::MAX), edges().len() as u32);
    }
}

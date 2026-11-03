//! The relay cap. Ingest refuses, whole, a source body that would bring its
//! source past [`MAX_RELAYS_PER_MONTH`] relay origins in a UTC month of
//! ingest's clock. The monitor counts the origins of its own bodies against
//! that month, which it learns from ingest's receive time, and sends no
//! record for an origin past the cap.

use std::collections::HashSet;

use crate::clock::DRIFT;

/// Distinct relay origins a source may report in one UTC month.
pub const MAX_RELAYS_PER_MONTH: usize = 64;

#[derive(Debug, Default)]
pub(crate) struct RelayLedger {
    /// Ingest's month, as months since 1970-01, once an accepted body said.
    month: Option<i64>,
    /// Origins of the bodies ingest may count in `month`.
    origins: HashSet<String>,
    /// Origins of bodies given up without an answer: ingest may have them.
    unanswered: HashSet<String>,
    /// Ingest's latest receive time, and the monotonic time it was answered.
    heard: Option<(f64, f64)>,
}

impl RelayLedger {
    /// The connections, of `(ordinal, origin)` in ordinal order, whose
    /// origin is past the cap, the oldest connection first in line.
    pub(crate) fn denied(&self, conns: &[(u64, &str)]) -> HashSet<u64> {
        let room = MAX_RELAYS_PER_MONTH.saturating_sub(self.origins.len());
        let mut added: HashSet<&str> = HashSet::new();
        let mut denied = HashSet::new();
        for &(id, origin) in conns {
            if self.origins.contains(origin) || added.contains(origin) {
                continue;
            }
            if added.len() < room {
                added.insert(origin);
            } else {
                denied.insert(id);
            }
        }
        denied
    }

    /// A body was sealed with `origins`.
    pub(crate) fn sealed(&mut self, origins: &[String]) {
        self.origins.extend(origins.iter().cloned());
    }

    /// A body was given up after it may have reached ingest.
    pub(crate) fn given_up(&mut self, origins: &[String]) {
        self.unanswered.extend(origins.iter().cloned());
    }

    /// Ingest accepted a body with `origins` at `recv_ms`, answered at
    /// monotonic `mono_ms`. In a later month the count restarts from what
    /// ingest may count in it: this body, the bodies still queued, and those
    /// given up unanswered.
    pub(crate) fn accepted<'a>(
        &mut self,
        recv_ms: Option<f64>,
        mono_ms: f64,
        origins: &'a [String],
        queued: impl Iterator<Item = &'a [String]>,
    ) {
        let Some((recv_ms, month)) = recv_ms.and_then(|r| Some((r, utc_month(r)?))) else {
            return;
        };
        if self.heard.is_none_or(|(r, _)| recv_ms >= r) {
            self.heard = Some((recv_ms, mono_ms));
        }
        self.restart(month, origins.iter().chain(queued.flatten()));
    }

    /// Restarts the count when ingest's clock must have passed into a later
    /// month by monotonic `mono_ms`, with no body answered since: an origin
    /// held back would otherwise wait for a body only counted origins send.
    pub(crate) fn advance<'a>(&mut self, mono_ms: f64, queued: impl Iterator<Item = &'a [String]>) {
        let Some((recv_ms, at)) = self.heard else { return };
        let earliest = recv_ms + (mono_ms - at).max(0.0) * (1.0 - DRIFT);
        if let Some(month) = utc_month(earliest) {
            self.restart(month, queued.flatten());
        }
    }

    fn restart<'a>(&mut self, month: i64, still: impl Iterator<Item = &'a String>) {
        match self.month {
            None => self.month = Some(month),
            Some(m) if month > m => {
                self.month = Some(month);
                let mut next: HashSet<String> = std::mem::take(&mut self.unanswered);
                next.extend(still.cloned());
                self.origins = next;
            }
            Some(_) => {}
        }
    }
}

/// Months since 1970-01 of the UTC date at `ms`.
fn utc_month(ms: f64) -> Option<i64> {
    if !ms.is_finite() || ms.abs() > 8.64e15 {
        return None;
    }
    let days = (ms / 86_400_000.0).floor() as i64;
    // Civil date from days since 1970-01-01 (proleptic Gregorian).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    Some((year - 1970) * 12 + month - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conns(origins: std::ops::Range<u64>) -> Vec<(u64, String)> {
        origins.map(|i| (i, format!("https://r{i}.example"))).collect()
    }

    fn denied(ledger: &RelayLedger, c: &[(u64, String)]) -> HashSet<u64> {
        let refs: Vec<(u64, &str)> = c.iter().map(|(i, o)| (*i, o.as_str())).collect();
        ledger.denied(&refs)
    }

    fn allowed(ledger: &RelayLedger, c: &[(u64, String)]) -> Vec<String> {
        let d = denied(ledger, c);
        let mut out: Vec<String> =
            c.iter().filter(|(i, _)| !d.contains(i)).map(|(_, o)| o.clone()).collect();
        out.dedup();
        out
    }

    #[test]
    fn months_are_utc_calendar_months() {
        let ms = |s: i64| s as f64 * 1000.0;
        assert_eq!(utc_month(0.0), Some(0));
        assert_eq!(utc_month(-1.0), Some(-1));
        // 2026-10-31T23:59:59.999Z and 2026-11-01T00:00:00Z.
        assert_eq!(utc_month(ms(1_793_491_200) - 1.0), Some(56 * 12 + 9));
        assert_eq!(utc_month(ms(1_793_491_200)), Some(56 * 12 + 10));
        // 2024-02-29T12:00:00Z, and 2024-03-01T00:00:00Z.
        assert_eq!(utc_month(ms(1_709_208_000)), Some(54 * 12 + 1));
        assert_eq!(utc_month(ms(1_709_251_200)), Some(54 * 12 + 2));
        // 2000-12-31T23:59:59Z.
        assert_eq!(utc_month(ms(978_307_199)), Some(30 * 12 + 11));
        assert_eq!(utc_month(f64::NAN), None);
    }

    #[test]
    fn origins_past_the_cap_send_nothing_and_are_counted() {
        let mut ledger = RelayLedger::default();
        let c = conns(0..70);
        let d = denied(&ledger, &c);
        assert_eq!(d.len(), 6);
        assert!(d.iter().all(|&i| i >= 64));
        ledger.sealed(&allowed(&ledger, &c));
        assert_eq!(ledger.origins.len(), MAX_RELAYS_PER_MONTH);

        // Counted origins keep reporting; a new one does not.
        assert_eq!(denied(&ledger, &conns(60..66)).len(), 2);
    }

    #[test]
    fn connections_to_one_origin_share_its_place() {
        let ledger = RelayLedger {
            origins: (0..63).map(|i| format!("o{i}")).collect(),
            ..Default::default()
        };
        let c = vec![
            (1, "https://a.example".to_string()),
            (2, "https://a.example".to_string()),
            (3, "https://b.example".to_string()),
        ];
        assert_eq!(denied(&ledger, &c), HashSet::from([3]));
        assert_eq!(allowed(&ledger, &c), ["https://a.example"]);
    }

    #[test]
    fn a_later_month_restarts_from_what_ingest_may_count_in_it() {
        let oct = 1_792_000_000_000.0; // 2026-10-14
        let nov = 1_793_491_200_000.0; // 2026-11-01
        let mut ledger = RelayLedger::default();
        let full: Vec<String> = (0..64).map(|i| format!("o{i}")).collect();
        ledger.sealed(&full);
        ledger.given_up(&["o1".to_string()]);
        ledger.accepted(Some(oct), 0.0, &["o0".into()], std::iter::empty());
        assert_eq!(ledger.origins.len(), 64, "the first answer only sets the month");
        ledger.accepted(Some(oct - 1.0), 0.0, &["o0".into()], std::iter::empty());
        assert_eq!(ledger.origins.len(), 64);
        ledger.accepted(None, 0.0, &["o0".into()], std::iter::empty());
        assert_eq!(ledger.origins.len(), 64);

        let queued = [vec!["o2".to_string(), "o3".to_string()]];
        ledger.accepted(Some(nov), 0.0, &["o0".into()], queued.iter().map(|q| q.as_slice()));
        let mut now: Vec<_> = ledger.origins.iter().cloned().collect();
        now.sort();
        assert_eq!(now, ["o0", "o1", "o2", "o3"]);
        assert!(ledger.unanswered.is_empty());

        // The same month again changes nothing.
        ledger.accepted(Some(nov + 1.0), 0.0, &["o9".into()], std::iter::empty());
        assert_eq!(ledger.origins.len(), 4);
    }

    #[test]
    fn ingest_clock_past_the_month_restarts_with_no_body_answered() {
        let day = 86_400_000.0;
        let oct31 = 1_793_491_200_000.0 - day; // 2026-10-31T00:00Z
        let mut ledger = RelayLedger::default();
        let full: Vec<String> = (0..64).map(|i| format!("o{i}")).collect();
        ledger.sealed(&full);
        ledger.accepted(Some(oct31), 1_000.0, &["o0".into()], std::iter::empty());

        // A day by the monotonic clock is not a day by ingest's once drift is
        // allowed for, so the month holds.
        ledger.advance(1_000.0 + day, std::iter::empty());
        assert_eq!(ledger.origins.len(), 64);
        assert_eq!(denied(&ledger, &conns(100..101)).len(), 1);

        let queued = [vec!["o5".to_string()]];
        ledger.advance(1_000.0 + day * 1.001, queued.iter().map(|q| q.as_slice()));
        assert_eq!(ledger.origins.iter().collect::<Vec<_>>(), ["o5"]);
        assert!(denied(&ledger, &conns(100..101)).is_empty());

        // With no answer yet, nothing moves.
        let mut fresh = RelayLedger::default();
        fresh.sealed(&full);
        fresh.advance(f64::MAX, std::iter::empty());
        assert_eq!(fresh.origins.len(), 64);
    }
}

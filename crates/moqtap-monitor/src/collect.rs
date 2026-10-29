//! What the producer reports, held until the next seal: open groups per relay
//! connection and track, closed group rows, object rows and events.
//!
//! Every collection is bounded. Past a bound, input is refused (`rejected`)
//! or a row is not kept (`dropped`); nothing grows without limit.

use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, HashMap};
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use crate::sampling::{in_sample, producer_k, Rate};
use crate::wire::{EventKind, MAX_MOQT_ID, MAX_SAFE_INTEGER};

/// Relay connections open at once.
pub(crate) const MAX_CONNECTIONS: usize = 256;
/// Tracks one connection may report.
pub(crate) const MAX_TRACKS_PER_CONNECTION: usize = 1024;
/// Groups of one track receiving objects at once.
const MAX_OPEN_GROUPS: usize = 4;
/// Group ids below a track's newest that are remembered, so a late object is
/// not reported as a new group. An object of an older group is not reported.
const RECENT_GROUPS: u64 = 64;
/// Closed group rows waiting for a seal.
pub(crate) const MAX_PENDING_GROUPS: usize = 100_000;
/// Object rows waiting for a seal.
pub(crate) const MAX_PENDING_OBJECTS: usize = 200_000;
/// Events waiting for a seal.
const MAX_PENDING_EVENTS: usize = 10_000;
/// Rows that make the monitor try an early seal against the byte seal.
pub(crate) const EARLY_PACK_ROWS: usize = 4096;
/// MoQT's limit on namespace fields.
const MAX_NAMESPACE_FIELDS: usize = 32;
/// MoQT's limit on a full track name, namespace and name together, in bytes.
const MAX_FULL_NAME_BYTES: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct TrackName {
    pub ns: Vec<String>,
    pub name: String,
}

#[derive(Clone, Debug)]
pub(crate) struct PendingGroup {
    pub conn: u64,
    pub track: Arc<TrackName>,
    pub k: u8,
    pub g: u64,
    pub fo: u64,
    pub first_us: i64,
    pub last_us: i64,
    pub objects: u64,
    pub bytes: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct PendingObject {
    pub conn: u64,
    pub track: Arc<TrackName>,
    pub k: u8,
    pub g: u64,
    pub o: u64,
    pub bytes: u64,
    pub at_us: i64,
}

#[derive(Clone, Debug)]
pub(crate) struct PendingEvent {
    pub conn: u64,
    pub ts: u64,
    pub track: Option<(Arc<TrackName>, u8)>,
    pub e: EventKind,
    pub code: Option<u64>,
}

/// A connection as its `relay` record states it.
#[derive(Clone, Debug)]
pub(crate) struct RelayInfo {
    pub origin: String,
    pub draft: Option<u64>,
    pub open_ts: u64,
    pub close_ts: Option<u64>,
    pub close_code: Option<u64>,
}

#[derive(Debug)]
struct OpenGroup {
    g: u64,
    fo: u64,
    k: u8,
    first_us: i64,
    last_us: i64,
    objects: u64,
    bytes: u64,
    last_ms: f64,
}

#[derive(Debug)]
struct Pair {
    track: Arc<TrackName>,
    k: u8,
    open: Vec<OpenGroup>,
    /// The newest group id started.
    high: Option<u64>,
    /// Bit `i` is group `high - i`: started at all, and reported.
    started: u64,
    reported: u64,
    rate: Rate,
}

/// What is known of a group that is not open.
enum History {
    New,
    /// Started before: reported, or sampled out.
    Started {
        reported: bool,
    },
    /// `RECENT_GROUPS` or more below the newest.
    Old,
}

impl Pair {
    fn new(track: Arc<TrackName>) -> Self {
        Pair {
            track,
            k: 0,
            open: Vec::new(),
            high: None,
            started: 0,
            reported: 0,
            rate: Rate::new(),
        }
    }

    fn history(&self, g: u64) -> History {
        let Some(high) = self.high.filter(|&h| g <= h) else { return History::New };
        let d = high - g;
        if d >= RECENT_GROUPS {
            History::Old
        } else if self.started >> d & 1 == 1 {
            History::Started { reported: self.reported >> d & 1 == 1 }
        } else {
            History::New
        }
    }

    /// Record that group `g`, new by [`Pair::history`], started.
    fn note(&mut self, g: u64, reported: bool) {
        let bit = u64::from(reported);
        match self.high {
            Some(h) if g <= h => {
                self.started |= 1 << (h - g);
                self.reported |= bit << (h - g);
            }
            _ => {
                let shift = self.high.map_or(RECENT_GROUPS, |h| g - h);
                if shift >= RECENT_GROUPS {
                    self.started = 1;
                    self.reported = bit;
                } else {
                    self.started = self.started << shift | 1;
                    self.reported = self.reported << shift | bit;
                }
                self.high = Some(g);
            }
        }
    }
}

#[derive(Debug)]
struct Conn {
    info: RelayInfo,
    closed: bool,
    pairs: Vec<Pair>,
    index: HashMap<u64, Vec<usize>>,
}

/// The rows taken for a seal.
#[derive(Debug, Default)]
pub(crate) struct Taken {
    pub groups: Vec<PendingGroup>,
    pub objects: Vec<PendingObject>,
    pub events: Vec<PendingEvent>,
    pub relays: HashMap<u64, RelayInfo>,
}

impl Taken {
    pub(crate) fn is_empty(&self) -> bool {
        self.groups.is_empty() && self.objects.is_empty() && self.events.is_empty()
    }
}

/// Why a call was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refused {
    Input,
    Closed,
}

#[derive(Debug)]
pub(crate) struct Collector {
    per_object: bool,
    conns: BTreeMap<u64, Conn>,
    next_conn: u64,
    groups: Vec<PendingGroup>,
    objects: Vec<PendingObject>,
    events: Vec<PendingEvent>,
    pub dropped: u64,
    pub over_relay_cap: u64,
    pub rejected: u64,
    rows_since_pack: usize,
    pub stopped: bool,
}

/// What a report asks of the sealer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Wake {
    No,
    Seal,
}

impl Collector {
    pub(crate) fn new(per_object: bool) -> Self {
        Collector {
            per_object,
            conns: BTreeMap::new(),
            next_conn: 0,
            groups: Vec::new(),
            objects: Vec::new(),
            events: Vec::new(),
            dropped: 0,
            over_relay_cap: 0,
            rejected: 0,
            rows_since_pack: 0,
            stopped: false,
        }
    }

    pub(crate) fn open_connections(&self) -> usize {
        self.conns.values().filter(|c| !c.closed).count()
    }

    pub(crate) fn open(&mut self, origin: String, open_ts: u64) -> Option<u64> {
        if self.stopped || self.open_connections() >= MAX_CONNECTIONS {
            return None;
        }
        let id = self.next_conn;
        self.next_conn += 1;
        self.conns.insert(
            id,
            Conn {
                info: RelayInfo { origin, draft: None, open_ts, close_ts: None, close_code: None },
                closed: false,
                pairs: Vec::new(),
                index: HashMap::new(),
            },
        );
        Some(id)
    }

    pub(crate) fn set_draft(&mut self, conn: u64, draft: u64) -> Result<(), Refused> {
        if draft > MAX_SAFE_INTEGER as u64 {
            return self.refuse(Refused::Input).map(drop);
        }
        match self.conns.get_mut(&conn) {
            Some(c) if !c.closed => {
                c.info.draft = Some(draft);
                Ok(())
            }
            _ => self.refuse(Refused::Closed).map(drop),
        }
    }

    /// Close a connection. A close code past 2^53 - 1 is refused, and the
    /// connection closes without one.
    pub(crate) fn close(&mut self, conn: u64, ts: u64, code: Option<u64>) -> Result<(), Refused> {
        let Some(c) = self.conns.get_mut(&conn) else { return Ok(()) };
        if c.closed {
            return Ok(());
        }
        let valid = code.is_none_or(|v| v <= MAX_SAFE_INTEGER as u64);
        c.closed = true;
        c.info.close_ts = Some(ts);
        c.info.close_code = code.filter(|_| valid);
        let mut closed = Vec::new();
        for p in &mut c.pairs {
            close_all(conn, p, &mut closed);
        }
        self.push_groups(closed);
        if valid {
            Ok(())
        } else {
            self.refuse(Refused::Input).map(drop)
        }
    }

    /// One object the producer's MoQ library accepted.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn object_sent<S: AsRef<str>>(
        &mut self,
        conn: u64,
        ns: &[S],
        name: &str,
        g: u64,
        o: u64,
        size: u64,
        at_us: i64,
        mono_ms: f64,
    ) -> Result<Wake, Refused> {
        if self.stopped {
            return self.refuse(Refused::Closed);
        }
        if !(0..=MAX_SAFE_INTEGER).contains(&at_us)
            || g > MAX_MOQT_ID
            || o > MAX_MOQT_ID
            || size > MAX_SAFE_INTEGER as u64
        {
            return self.refuse(Refused::Input);
        }
        let per_object = self.per_object;
        let Some(c) = self.conns.get_mut(&conn) else { return self.refuse(Refused::Closed) };
        if c.closed {
            return self.refuse(Refused::Closed);
        }
        let Some(pi) = c.pair(ns, name) else { return self.refuse(Refused::Input) };

        let mut closed = Vec::new();
        let mut object_row = None;
        let mut late = false;
        let p = &mut c.pairs[pi];
        if let Some(open) = p.open.iter_mut().find(|x| x.g == g) {
            open.last_us = open.last_us.max(at_us);
            open.objects += 1;
            open.bytes = (open.bytes + size).min(MAX_SAFE_INTEGER as u64);
            open.last_ms = mono_ms;
            if per_object {
                object_row = Some(open.k);
            }
        } else {
            match p.history(g) {
                History::Started { reported } => late = reported,
                History::Old => late = true,
                History::New => {
                    if p.rate.advance(mono_ms) {
                        let k = producer_k(&p.rate, p.k);
                        if k != p.k {
                            set_k(conn, p, k, &mut closed);
                        }
                    }
                    p.rate.add(g);
                    let keep = in_sample(g, p.k);
                    p.note(g, keep);
                    if keep {
                        p.open.push(OpenGroup {
                            g,
                            fo: o,
                            k: p.k,
                            first_us: at_us,
                            last_us: at_us,
                            objects: 1,
                            bytes: size,
                            last_ms: mono_ms,
                        });
                        if p.open.len() > MAX_OPEN_GROUPS {
                            let oldest = p.open.remove(0);
                            closed.push(row(conn, &p.track, oldest));
                        }
                        if per_object {
                            object_row = Some(p.k);
                        }
                    }
                }
            }
        }
        if late {
            self.dropped += 1;
        }
        if let Some(k) = object_row {
            let track = Arc::clone(&self.conns[&conn].pairs[pi].track);
            if self.objects.len() >= MAX_PENDING_OBJECTS {
                self.dropped += 1;
            } else {
                self.objects.push(PendingObject { conn, track, k, g, o, bytes: size, at_us });
                self.rows_since_pack += 1;
            }
        }
        self.push_groups(closed);
        Ok(self.wake())
    }

    /// A `pev` event. A `publish_done` also closes the track's open groups.
    pub(crate) fn event<S: AsRef<str>>(
        &mut self,
        conn: u64,
        track: Option<(&[S], &str)>,
        e: EventKind,
        code: Option<u64>,
        ts: u64,
    ) -> Result<Wake, Refused> {
        if self.stopped {
            return self.refuse(Refused::Closed);
        }
        if code.is_some_and(|v| v > MAX_SAFE_INTEGER as u64) {
            return self.refuse(Refused::Input);
        }
        let Some(c) = self.conns.get_mut(&conn) else { return self.refuse(Refused::Closed) };
        if c.closed {
            return self.refuse(Refused::Closed);
        }
        let mut closed = Vec::new();
        let track = match track {
            None => None,
            Some((ns, name)) => {
                let Some(pi) = c.pair(ns, name) else { return self.refuse(Refused::Input) };
                let p = &mut c.pairs[pi];
                if e == EventKind::PublishDone {
                    close_all(conn, p, &mut closed);
                }
                Some((Arc::clone(&p.track), p.k))
            }
        };
        if self.events.len() >= MAX_PENDING_EVENTS {
            self.dropped += 1;
        } else {
            self.events.push(PendingEvent { conn, ts, track, e, code });
        }
        self.push_groups(closed);
        Ok(self.wake())
    }

    /// Close the groups that are done and take every row for a seal. A
    /// track's newest group stays open unless it has been idle for `idle_ms`
    /// or `all` is set.
    pub(crate) fn take(&mut self, mono_ms: f64, idle_ms: f64, all: bool) -> Taken {
        let mut closed = Vec::new();
        for (&id, c) in &mut self.conns {
            for p in &mut c.pairs {
                p.open.sort_by(|a, b| a.first_us.cmp(&b.first_us).then(a.g.cmp(&b.g)));
                let keep_last =
                    !all && p.open.last().is_some_and(|x| mono_ms - x.last_ms < idle_ms);
                let keep = usize::from(keep_last);
                let n = p.open.len().saturating_sub(keep);
                for g in p.open.drain(..n) {
                    closed.push(row(id, &p.track, g));
                }
            }
        }
        self.push_groups(closed);
        self.rows_since_pack = 0;
        self.take_rows()
    }

    /// Take the rows for an early seal, leaving open groups as they are.
    pub(crate) fn take_early(&mut self) -> Taken {
        self.rows_since_pack = 0;
        self.take_rows()
    }

    /// Put back rows an early seal did not use, ahead of newer ones.
    pub(crate) fn restore(&mut self, t: Taken) {
        let Taken { mut groups, mut objects, mut events, .. } = t;
        groups.append(&mut self.groups);
        objects.append(&mut self.objects);
        events.append(&mut self.events);
        self.groups = groups;
        self.objects = objects;
        self.events = events;
    }

    /// Forget closed connections nothing pending refers to.
    pub(crate) fn prune(&mut self) {
        let groups = &self.groups;
        let objects = &self.objects;
        let events = &self.events;
        self.conns.retain(|id, c| {
            !c.closed
                || groups.iter().any(|r| r.conn == *id)
                || objects.iter().any(|r| r.conn == *id)
                || events.iter().any(|r| r.conn == *id)
        });
    }

    /// Drop everything and refuse further input: the key or path was refused.
    pub(crate) fn stop(&mut self) {
        self.stopped = true;
        self.conns.clear();
        self.groups = Vec::new();
        self.objects = Vec::new();
        self.events = Vec::new();
    }

    fn take_rows(&mut self) -> Taken {
        let groups = std::mem::take(&mut self.groups);
        let objects = std::mem::take(&mut self.objects);
        let events = std::mem::take(&mut self.events);
        let mut relays = HashMap::new();
        let ids = groups.iter().map(|r| r.conn).chain(objects.iter().map(|r| r.conn));
        for id in ids.chain(events.iter().map(|r| r.conn)) {
            if let Some(c) = self.conns.get(&id) {
                relays.entry(id).or_insert_with(|| c.info.clone());
            }
        }
        Taken { groups, objects, events, relays }
    }

    fn push_groups(&mut self, rows: Vec<PendingGroup>) {
        for r in rows {
            if self.groups.len() >= MAX_PENDING_GROUPS {
                self.dropped += 1;
            } else {
                self.groups.push(r);
                self.rows_since_pack += 1;
            }
        }
    }

    fn wake(&self) -> Wake {
        if self.rows_since_pack >= EARLY_PACK_ROWS {
            Wake::Seal
        } else {
            Wake::No
        }
    }

    fn refuse(&mut self, why: Refused) -> Result<Wake, Refused> {
        self.rejected += 1;
        Err(why)
    }
}

impl Conn {
    fn pair<S: AsRef<str>>(&mut self, ns: &[S], name: &str) -> Option<usize> {
        let mut h = DefaultHasher::new();
        ns.len().hash(&mut h);
        for f in ns {
            f.as_ref().hash(&mut h);
        }
        name.hash(&mut h);
        let hash = h.finish();
        if let Some(found) = self.index.get(&hash).and_then(|ix| {
            ix.iter().copied().find(|&i| {
                let t = &self.pairs[i].track;
                t.name == name
                    && t.ns.len() == ns.len()
                    && t.ns.iter().zip(ns).all(|(a, b)| a == b.as_ref())
            })
        }) {
            return Some(found);
        }
        if self.pairs.len() >= MAX_TRACKS_PER_CONNECTION || ns.len() > MAX_NAMESPACE_FIELDS {
            return None;
        }
        let bytes = name.len() + ns.iter().map(|f| f.as_ref().len()).sum::<usize>();
        if bytes > MAX_FULL_NAME_BYTES {
            return None;
        }
        let track = TrackName {
            ns: ns.iter().map(|f| f.as_ref().to_string()).collect(),
            name: name.to_string(),
        };
        self.pairs.push(Pair::new(Arc::new(track)));
        let i = self.pairs.len() - 1;
        self.index.entry(hash).or_default().push(i);
        Some(i)
    }
}

/// A new exponent applies to groups that start after it. Open groups were
/// sampled under the old one, so they close now and report under it.
fn set_k(conn: u64, p: &mut Pair, k: u8, closed: &mut Vec<PendingGroup>) {
    close_all(conn, p, closed);
    p.k = k;
}

fn close_all(conn: u64, p: &mut Pair, closed: &mut Vec<PendingGroup>) {
    for g in p.open.drain(..) {
        closed.push(row(conn, &p.track, g));
    }
}

fn row(conn: u64, track: &Arc<TrackName>, g: OpenGroup) -> PendingGroup {
    PendingGroup {
        conn,
        track: Arc::clone(track),
        k: g.k,
        g: g.g,
        fo: g.fo,
        first_us: g.first_us,
        last_us: g.last_us,
        objects: g.objects,
        bytes: g.bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sampling::{MAX_K, TARGET_GROUPS_PER_SEC};

    const NS: [&str; 2] = ["live", "ch"];

    fn collector() -> (Collector, u64) {
        let mut c = Collector::new(false);
        let id = c.open("https://relay.example".into(), 0).unwrap();
        (c, id)
    }

    #[test]
    fn a_group_reports_first_object_span_count_and_bytes() {
        let (mut c, id) = collector();
        c.object_sent(id, &NS, "v", 7, 3, 100, 1_000, 0.0).unwrap();
        c.object_sent(id, &NS, "v", 7, 4, 50, 1_500, 1.0).unwrap();
        c.object_sent(id, &NS, "v", 7, 5, 25, 1_200, 2.0).unwrap();
        let t = c.take(3.0, 60_000.0, true);
        assert_eq!(t.groups.len(), 1);
        let g = &t.groups[0];
        assert_eq!(
            (g.g, g.fo, g.first_us, g.last_us, g.objects, g.bytes),
            (7, 3, 1_000, 1_500, 3, 175)
        );
        assert_eq!(t.relays[&id].origin, "https://relay.example");
    }

    #[test]
    fn the_newest_group_stays_open_across_a_seal() {
        let (mut c, id) = collector();
        c.object_sent(id, &NS, "v", 1, 0, 1, 0, 0.0).unwrap();
        c.object_sent(id, &NS, "v", 2, 0, 1, 10, 1.0).unwrap();
        let t = c.take(2.0, 60_000.0, false);
        assert_eq!(t.groups.iter().map(|g| g.g).collect::<Vec<_>>(), vec![1]);
        c.object_sent(id, &NS, "v", 2, 1, 1, 20, 3.0).unwrap();
        let t = c.take(4.0, 60_000.0, true);
        assert_eq!((t.groups[0].g, t.groups[0].objects), (2, 2));
    }

    #[test]
    fn an_idle_group_closes_at_a_seal() {
        let (mut c, id) = collector();
        c.object_sent(id, &NS, "v", 1, 0, 1, 0, 0.0).unwrap();
        assert_eq!(c.take(70_000.0, 60_000.0, false).groups.len(), 1);
    }

    #[test]
    fn a_late_object_of_a_reported_group_is_dropped_not_reported_again() {
        let (mut c, id) = collector();
        c.object_sent(id, &NS, "v", 1, 0, 1, 0, 0.0).unwrap();
        c.take(1.0, 60_000.0, true);
        c.object_sent(id, &NS, "v", 1, 1, 1, 5, 2.0).unwrap();
        assert!(c.take(3.0, 60_000.0, true).groups.is_empty());
        assert_eq!(c.dropped, 1);
    }

    #[test]
    fn a_late_object_of_an_old_group_never_makes_a_second_row() {
        let (mut c, id) = collector();
        for g in 0..70u64 {
            c.object_sent(id, &NS, "v", g, 0, 1, g as i64, g as f64).unwrap();
        }
        // Group 0 is now 69 below the newest, group 60 nine below.
        c.object_sent(id, &NS, "v", 0, 1, 1, 100, 70.0).unwrap();
        c.object_sent(id, &NS, "v", 60, 1, 1, 100, 70.0).unwrap();
        let t = c.take(71.0, 60_000.0, true);
        let mut gs: Vec<u64> = t.groups.iter().map(|r| r.g).collect();
        gs.sort_unstable();
        assert_eq!(gs, (0..70).collect::<Vec<_>>());
        assert_eq!(c.dropped, 2);
        // Nor in a later body.
        c.object_sent(id, &NS, "v", 3, 1, 1, 200, 80.0).unwrap();
        c.object_sent(id, &NS, "v", 69, 1, 1, 200, 80.0).unwrap();
        assert!(c.take(81.0, 60_000.0, true).groups.is_empty());
        assert_eq!(c.dropped, 4);
    }

    #[test]
    fn a_group_that_starts_out_of_order_is_reported_once() {
        let (mut c, id) = collector();
        for (g, o) in [(0, 0), (2, 0), (1, 0), (1, 1), (2, 1)] {
            c.object_sent(id, &NS, "v", g, o, 1, 0, 0.0).unwrap();
        }
        let t = c.take(1.0, 60_000.0, true);
        let mut rows: Vec<_> = t.groups.iter().map(|r| (r.g, r.objects)).collect();
        rows.sort_unstable();
        assert_eq!(rows, [(0, 1), (1, 2), (2, 2)]);
        assert_eq!(c.dropped, 0);
    }

    #[test]
    fn codes_and_drafts_past_2_53_are_refused() {
        let (mut c, id) = collector();
        let big = MAX_SAFE_INTEGER as u64 + 1;
        c.object_sent(id, &NS, "v", 0, 0, 1, 0, 0.0).unwrap();
        let none: Option<(&[&str], &str)> = None;
        assert_eq!(c.event(id, none, EventKind::RequestError, Some(big), 1), Err(Refused::Input));
        assert_eq!(c.set_draft(id, big), Err(Refused::Input));
        c.set_draft(id, 16).unwrap();
        assert_eq!(c.close(id, 2, Some(big)), Err(Refused::Input));
        let t = c.take(3.0, 60_000.0, true);
        assert!(t.events.is_empty());
        let r = &t.relays[&id];
        assert_eq!((r.draft, r.close_ts, r.close_code), (Some(16), Some(2), None));
        assert_eq!(c.rejected, 3);
    }

    #[test]
    fn bad_input_is_refused_and_counted() {
        let (mut c, id) = collector();
        assert_eq!(c.object_sent(id, &NS, "v", MAX_MOQT_ID + 1, 0, 1, 0, 0.0), Err(Refused::Input));
        assert_eq!(c.object_sent(id, &NS, "v", 0, 0, u64::MAX, 0, 0.0), Err(Refused::Input));
        assert_eq!(c.object_sent(id, &NS, "v", 0, 0, 1, -1, 0.0), Err(Refused::Input));
        let long = "x".repeat(MAX_FULL_NAME_BYTES + 1);
        assert_eq!(c.object_sent(id, &NS, &long, 0, 0, 1, 0, 0.0), Err(Refused::Input));
        let many = vec!["f"; MAX_NAMESPACE_FIELDS + 1];
        assert_eq!(c.object_sent(id, &many, "v", 0, 0, 1, 0, 0.0), Err(Refused::Input));
        assert_eq!(c.object_sent(id + 1, &NS, "v", 0, 0, 1, 0, 0.0), Err(Refused::Closed));
        assert_eq!(c.rejected, 6);
    }

    #[test]
    fn a_closed_connection_refuses_objects_and_closes_its_groups() {
        let (mut c, id) = collector();
        c.object_sent(id, &NS, "v", 1, 0, 1, 0, 0.0).unwrap();
        c.close(id, 5, Some(0)).unwrap();
        assert_eq!(c.object_sent(id, &NS, "v", 2, 0, 1, 0, 0.0), Err(Refused::Closed));
        let t = c.take(1.0, 60_000.0, false);
        assert_eq!(t.groups.len(), 1);
        assert_eq!((t.relays[&id].close_ts, t.relays[&id].close_code), (Some(5), Some(0)));
        c.prune();
        assert_eq!(c.conns.len(), 0);
    }

    #[test]
    fn early_seal_is_asked_for_past_the_row_threshold() {
        let mut c = Collector::new(true);
        let id = c.open("https://r".into(), 0).unwrap();
        let mut wake = Wake::No;
        for o in 0..EARLY_PACK_ROWS as u64 {
            wake = c.object_sent(id, &NS, "v", 0, o, 1, 0, 0.0).unwrap();
        }
        assert_eq!(wake, Wake::Seal);
        let t = c.take_early();
        assert_eq!(t.objects.len(), EARLY_PACK_ROWS);
        c.restore(t);
        assert_eq!(c.take(1.0, 60_000.0, true).objects.len(), EARLY_PACK_ROWS);
    }

    #[test]
    fn publish_done_closes_the_track() {
        let (mut c, id) = collector();
        c.object_sent(id, &NS, "v", 1, 0, 1, 0, 0.0).unwrap();
        c.event(id, Some((&NS[..], "v")), EventKind::PublishDone, Some(0), 3).unwrap();
        let t = c.take(1.0, 60_000.0, false);
        assert_eq!((t.groups.len(), t.events.len()), (1, 1));
    }

    #[test]
    fn connections_are_bounded() {
        let mut c = Collector::new(false);
        for _ in 0..MAX_CONNECTIONS {
            assert!(c.open("https://r".into(), 0).is_some());
        }
        assert!(c.open("https://r".into(), 0).is_none());
    }

    /// Group ids stepping by `step` and their send times, ms, for phases of
    /// `(groups a second, seconds)`.
    fn schedule(step: u64, phases: &[(u64, u64)]) -> Vec<(u64, f64)> {
        let (mut out, mut t0, mut g) = (Vec::new(), 0.0, 0);
        for &(rate, secs) in phases {
            for i in 0..rate * secs {
                out.push((g, t0 + i as f64 * 1000.0 / rate as f64));
                g += step;
            }
            t0 += secs as f64 * 1000.0;
        }
        out
    }

    /// The groups the producer keeps, and its `k` as each group started.
    fn producer(groups: &[(u64, f64)]) -> (Vec<u64>, Vec<u8>) {
        let (mut c, id) = collector();
        let (mut kept, mut ks) = (Vec::new(), Vec::new());
        let mut next_seal = 60_000.0;
        for &(g, ms) in groups {
            if ms >= next_seal {
                kept.extend(c.take(ms, 60_000.0, false).groups.iter().map(|r| r.g));
                next_seal += 60_000.0;
            }
            c.object_sent(id, &NS, "a", g, 0, 1, (ms * 1000.0) as i64, ms).unwrap();
            ks.push(c.conns[&id].pairs[0].k);
        }
        kept.extend(c.take(f64::MAX, 0.0, true).groups.iter().map(|r| r.g));
        (kept, ks)
    }

    /// The browser monitor's rule (`monitor-browser` `GroupArrivals`), on
    /// its own clock: `offset_ms` later than the producer's, and 10 s
    /// intervals. Each interval's `k` is the highest the rate rule reached in
    /// it, raised further until the interval holds at most the target. The
    /// groups it keeps, and the interval `k` of each group.
    fn viewer(groups: &[(u64, f64)], offset_ms: f64) -> (Vec<u64>, Vec<u8>) {
        const INTERVAL_MS: f64 = 10_000.0;
        let per_interval = TARGET_GROUPS_PER_SEC as usize * 10;
        let mut rate = Rate::new();
        let (mut kept, mut ks) = (Vec::new(), Vec::new());
        let (mut interval, mut k, mut rule, mut held) = (None, 0u8, 0u8, Vec::<u64>::new());
        let close = |k: u8, held: &mut Vec<u64>, kept: &mut Vec<u64>, ks: &mut Vec<u8>| {
            kept.extend(held.iter().filter(|&&g| in_sample(g, k)));
            ks.extend(std::iter::repeat_n(k, held.len()));
            held.clear();
        };
        for &(g, ms) in groups {
            let at = ms + offset_ms;
            let i = (at / INTERVAL_MS).floor() as i64;
            if interval != Some(i) {
                close(k, &mut held, &mut kept, &mut ks);
                interval = Some(i);
                k = 0;
            }
            if rate.advance(at) {
                rule = rate.viewer_k();
            }
            k = k.max(rule);
            rate.add(g);
            held.push(g);
            while k < MAX_K && held.iter().filter(|&&g| in_sample(g, k)).count() > per_interval {
                k += 1;
            }
        }
        close(k, &mut held, &mut kept, &mut ks);
        (kept, ks)
    }

    fn check(step: u64, phases: &[(u64, u64)]) {
        let groups = schedule(step, phases);
        let (pk, pks) = producer(&groups);
        assert!(pk.len() < groups.len() || phases.iter().all(|p| p.0 <= 12), "{phases:?}");
        let pk: std::collections::HashSet<u64> = pk.into_iter().collect();
        for offset in [50.0, 7_371.7, 9_999.0] {
            let (vk, vks) = viewer(&groups, offset);
            for (i, (p, v)) in pks.iter().zip(&vks).enumerate() {
                assert!(
                    p <= v,
                    "{phases:?} offset {offset}: group {} producer k {p} > viewer k {v}",
                    groups[i].0
                );
            }
            assert!(!vk.is_empty(), "{phases:?}");
            let missing: Vec<_> = vk.iter().filter(|g| !pk.contains(g)).collect();
            assert!(missing.is_empty(), "{phases:?} offset {offset}: viewer-only {missing:?}");
        }
    }

    #[test]
    fn a_steady_track_keeps_k_at_most_the_viewers() {
        for rate in [5, 12, 30, 40, 50, 300] {
            check(1, &[(rate, 120)]);
        }
        check(2, &[(30, 120)]);
    }

    #[test]
    fn a_step_in_the_rate_keeps_k_at_most_the_viewers() {
        check(1, &[(10, 60), (80, 60), (10, 60)]);
        check(1, &[(80, 60), (5, 60)]);
        check(1, &[(40, 60), (160, 60), (20, 60)]);
        check(2, &[(20, 60), (100, 60), (15, 60)]);
    }

    #[test]
    fn a_steady_track_settles_on_one_k() {
        let groups = schedule(1, &[(50, 60)]);
        let (_, ks) = producer(&groups);
        // Raised once the window holds enough, then never changed.
        let tail: std::collections::BTreeSet<_> = ks[ks.len() - 2_000..].iter().collect();
        assert_eq!(tail.into_iter().collect::<Vec<_>>(), [&2]);
    }
}

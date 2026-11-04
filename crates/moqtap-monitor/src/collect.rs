//! What the producer reports, held until the next seal: per interval, an
//! open run per flow `(connection, track, group, subgroup)`, the runs that
//! ended, marks, events, pacing and group facts.
//!
//! An interval is cut (sealed) at the timer, at a clock break, and before it
//! would outgrow one body: the byte seal, the flow cap, or a body's
//! connection or track cap. Nothing is dropped for being late or old; the
//! few bounds that refuse input are named below.

#![allow(
    clippy::mutable_key_type,
    reason = "a track hashes and compares by its name bytes, not by its atomics"
)]

use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use crate::hist::key_of;
use crate::wire::track_list_gz_len;
use crate::wire::{
    leb_len, zigzag_len, EventKind, MarkKind, Track, DT_QUANTUM_US, MAX_BODY_CONNS,
    MAX_BODY_TRACKS, MAX_CONN_ORDINAL, MAX_FULL_NAME_BYTES, MAX_NAMESPACE_FIELDS, MAX_SAFE_INTEGER,
    MAX_VARINT_ID, SEAL_BYTES,
};

/// Relay connections open at once.
pub(crate) const MAX_CONNECTIONS: usize = 256;
/// Distinct tracks one connection may report over its life.
pub(crate) const MAX_TRACKS_PER_CONNECTION: usize = 1024;
/// Open runs in one interval; past it the interval is sealed early.
pub(crate) const MAX_FLOWS: usize = 4096;
/// Events and marks one interval holds; past it they are dropped and counted.
const MAX_FACTS: usize = 10_000;
/// Room kept under the byte seal for what the estimate does not see.
const SEAL_SLACK: usize = 2048;
/// A track's `span` in a body.
const SPAN_BYTES: usize = 34;

pub(crate) type TrackRef = Arc<Track>;

/// A flow: the unit a run belongs to.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Flow {
    pub c: u64,
    pub track: TrackRef,
    pub g: u64,
    pub sub: Option<u64>,
}

#[derive(Clone, Debug)]
pub(crate) struct Run {
    /// Creation order within the interval, shared with [`Clear`]s.
    pub order: u64,
    pub flow: Flow,
    pub ids: Vec<u64>,
    pub times: Vec<i64>,
    /// Each object's end, device mono µs.
    pub ends: Vec<i64>,
    /// Each object's payload bytes.
    pub sizes: Vec<u64>,
    pub b: u64,
    pub gs: bool,
    pub fo: bool,
    pub eog: bool,
}

/// A point after which a flow's next run continues nothing.
#[derive(Clone, Debug)]
pub(crate) enum Clear {
    Track(u64, TrackRef),
    Conn(u64),
}

#[derive(Clone, Debug)]
pub(crate) struct Mark {
    pub c: u64,
    pub track: TrackRef,
    pub kind: MarkKind,
    pub g: u64,
    pub o: u64,
    pub n: u64,
    pub t: i64,
}

#[derive(Clone, Debug)]
pub(crate) struct Event {
    pub c: u64,
    pub track: Option<TrackRef>,
    pub e: EventKind,
    pub code: Option<u64>,
    pub at_us: i64,
}

#[derive(Clone, Debug)]
pub(crate) struct ConnInfo {
    pub origin: String,
    pub draft: Option<u64>,
}

/// A track's distinct groups in one interval.
#[derive(Clone, Debug, Default)]
pub(crate) struct TrackGroups {
    pub groups: HashSet<u64>,
    /// First and last handoff.
    pub span: Option<(i64, i64)>,
}

/// Gaps by bucket key: before a `starts_group` object, and before the others.
#[derive(Clone, Debug, Default)]
pub(crate) struct Pace {
    pub first: BTreeMap<u32, u64>,
    pub later: BTreeMap<u32, u64>,
}

/// One sealed interval, ready to pack.
#[derive(Debug)]
pub(crate) struct Interval {
    pub from_us: i64,
    pub through_us: i64,
    pub epoch: u64,
    pub seal_ms: u64,
    pub is_final: bool,
    pub runs: Vec<Run>,
    pub clears: Vec<(u64, Clear)>,
    pub marks: Vec<Mark>,
    pub events: Vec<Event>,
    pub pace: HashMap<(u64, TrackRef), Pace>,
    pub gdec: HashMap<(u64, TrackRef), u64>,
    pub groups: HashMap<TrackRef, TrackGroups>,
    /// The connections the interval references.
    pub conns: BTreeMap<u64, ConnInfo>,
    /// The tracks the body lists, in order.
    pub tracks: Vec<TrackRef>,
    pub dropped_records: u64,
}

/// The interval being collected.
#[derive(Debug)]
struct Open {
    from_us: i64,
    epoch: u64,
    order: u64,
    open: HashMap<Flow, Run>,
    runs: Vec<Run>,
    clears: Vec<(u64, Clear)>,
    marks: Vec<Mark>,
    events: Vec<Event>,
    pace: HashMap<(u64, TrackRef), Pace>,
    gdec: HashMap<(u64, TrackRef), u64>,
    groups: HashMap<TrackRef, TrackGroups>,
    conns: BTreeMap<u64, ConnInfo>,
    tracks: Vec<TrackRef>,
    listed: HashSet<TrackRef>,
    dropped_records: u64,
    /// The body's gzipped size, estimated: the tracks listed at the start
    /// as measured, everything added since at its uncompressed size.
    bytes: usize,
    /// The track list's part of `bytes`.
    list_bytes: usize,
    /// The tracks `list_bytes` counts with their names.
    named: Vec<TrackRef>,
}

impl Open {
    fn new(from_us: i64, epoch: u64, active: Vec<TrackRef>, list_gz: usize) -> Self {
        let named = active.iter().filter(|t| t.names_needed()).cloned().collect();
        let mut o = Open {
            from_us,
            epoch,
            order: 0,
            open: HashMap::new(),
            runs: Vec::new(),
            clears: Vec::new(),
            marks: Vec::new(),
            events: Vec::new(),
            pace: HashMap::new(),
            gdec: HashMap::new(),
            groups: HashMap::new(),
            conns: BTreeMap::new(),
            tracks: Vec::new(),
            listed: HashSet::new(),
            dropped_records: 0,
            bytes: 600 + list_gz,
            list_bytes: list_gz,
            named,
        };
        for t in active {
            if o.listed.insert(Arc::clone(&t)) {
                o.tracks.push(t);
            }
        }
        o
    }

    fn list(&mut self, t: &TrackRef) {
        if self.listed.insert(Arc::clone(t)) {
            let mut cost = 40;
            if t.names_needed() {
                let names: usize = t.ns.iter().map(|f| f.len() * 4 / 3 + 6).sum();
                cost += 16 + names + t.name.len() * 4 / 3;
                self.named.push(Arc::clone(t));
            }
            self.bytes += cost;
            self.list_bytes += cost;
            self.tracks.push(Arc::clone(t));
        }
    }

    /// Measure the track list again once a body carrying names the estimate
    /// counts has been accepted: the body will list those tracks by key.
    fn remeasure_names(&mut self) {
        if self.named.iter().all(|t| t.names_needed()) {
            return;
        }
        let gz = track_list_gz_len(&self.tracks);
        self.bytes = self.bytes - self.list_bytes + gz;
        self.list_bytes = gz;
        self.named.retain(|t| t.names_needed());
    }

    fn has_facts(&self) -> bool {
        !(self.open.is_empty()
            && self.runs.is_empty()
            && self.marks.is_empty()
            && self.events.is_empty())
    }

    fn next_order(&mut self) -> u64 {
        self.order += 1;
        self.order
    }

    fn end_runs(&mut self, keep: impl Fn(&Flow) -> bool) {
        let ended: Vec<Flow> = self.open.keys().filter(|f| !keep(f)).cloned().collect();
        for f in ended {
            if let Some(r) = self.open.remove(&f) {
                self.runs.push(r);
            }
        }
    }

    fn seal(mut self, through_us: i64, seal_ms: u64, is_final: bool) -> Interval {
        self.end_runs(|_| false);
        self.runs.sort_by_key(|r| r.order);
        Interval {
            from_us: self.from_us,
            through_us: through_us.max(self.from_us),
            epoch: self.epoch,
            seal_ms,
            is_final,
            runs: self.runs,
            clears: self.clears,
            marks: self.marks,
            events: self.events,
            pace: self.pace,
            gdec: self.gdec,
            groups: self.groups,
            conns: self.conns,
            tracks: self.tracks,
            dropped_records: self.dropped_records,
        }
    }
}

#[derive(Debug, Default)]
struct Pair {
    last_at: Option<i64>,
    last_group: Option<u64>,
}

#[derive(Debug)]
struct Conn {
    info: ConnInfo,
    active: HashSet<TrackRef>,
    pairs: HashMap<TrackRef, Pair>,
}

/// Why a call was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refused {
    Input,
    Closed,
}

/// What a report asks of the sealer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Wake {
    No,
    Seal,
}

/// One object as the integrator reported it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Handoff {
    pub g: u64,
    pub sub: Option<u64>,
    pub o: u64,
    pub size: u64,
    pub starts_group: bool,
    pub opens_subgroup: bool,
    pub ends_group: bool,
}

#[derive(Debug)]
pub(crate) struct Collector {
    conns: BTreeMap<u64, Conn>,
    next_conn: u64,
    /// Tracks by a hash of their name parts.
    names: HashMap<u64, Vec<TrackRef>>,
    /// Connections each track is active on.
    active: HashMap<TrackRef, usize>,
    cur: Open,
    /// Sealed intervals waiting for the sealer.
    pub cuts: VecDeque<Interval>,
    pub epoch: u64,
    /// The seal interval in force, ms.
    pub seal_ms: u64,
    pub rejected: u64,
    pub stopped: bool,
    /// A clock break was seen: a clock exchange is due.
    pub probe_due: bool,
    breaks: crate::clock::BreakCheck,
    /// Mono µs of the latest call.
    last_mono: i64,
    /// The last measured track list, whether each entry was measured with
    /// its names, and its gzipped size.
    list_gz: (Vec<TrackRef>, Vec<bool>, usize),
}

impl Collector {
    pub(crate) fn new(seal_ms: u64) -> Self {
        Collector {
            conns: BTreeMap::new(),
            next_conn: 0,
            names: HashMap::new(),
            active: HashMap::new(),
            cur: Open::new(0, 0, Vec::new(), 0),
            list_gz: (Vec::new(), Vec::new(), 0),
            cuts: VecDeque::new(),
            epoch: 0,
            seal_ms,
            rejected: 0,
            stopped: false,
            probe_due: false,
            breaks: crate::clock::BreakCheck::default(),
            last_mono: 0,
        }
    }

    fn refuse<T>(&mut self, r: Refused) -> Result<T, Refused> {
        self.rejected += 1;
        Err(r)
    }

    /// Check the clocks at a captured time. A break seals what came before
    /// under the old epoch and starts the next.
    pub(crate) fn observe(&mut self, mono_us: i64, wall_us: Option<i64>) -> Wake {
        self.last_mono = self.last_mono.max(mono_us);
        let Some(wall) = wall_us else { return Wake::No };
        if !self.breaks.check(wall, mono_us) {
            return Wake::No;
        }
        self.cut(mono_us, false);
        self.epoch += 1;
        self.cur.epoch = self.epoch;
        self.probe_due = true;
        Wake::Seal
    }

    /// Seal the open interval at `through_us`. An interval with no facts and
    /// no listed track is not sealed, unless `is_final`.
    pub(crate) fn cut(&mut self, through_us: i64, is_final: bool) -> bool {
        if !is_final && !self.cur.has_facts() && self.cur.tracks.is_empty() {
            return false;
        }
        self.cut_due_or_final(through_us, is_final)
    }

    /// Seal the open interval at `through_us`, empty or not: the seal its
    /// last body said was due.
    pub(crate) fn cut_due(&mut self, through_us: i64) {
        self.cut_due_or_final(through_us, false);
    }

    fn cut_due_or_final(&mut self, through_us: i64, is_final: bool) -> bool {
        let active: Vec<TrackRef> = self.active_tracks();
        let named: Vec<bool> = active.iter().map(|t| t.names_needed()).collect();
        let same = named == self.list_gz.1
            && active.iter().zip(&self.list_gz.0).all(|(a, b)| Arc::ptr_eq(a, b));
        if !same {
            let gz = track_list_gz_len(&active);
            self.list_gz = (active.clone(), named, gz);
        }
        let next = Open::new(through_us.max(self.cur.from_us), self.epoch, active, self.list_gz.2);
        let done = std::mem::replace(&mut self.cur, next);
        self.cuts.push_back(done.seal(through_us, self.seal_ms, is_final));
        self.prune();
        true
    }

    fn active_tracks(&self) -> Vec<TrackRef> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for c in self.conns.values() {
            for t in &c.active {
                if seen.insert(Arc::clone(t)) {
                    out.push(Arc::clone(t));
                }
            }
        }
        out.sort_by(|a, b| (&a.ns, &a.name).cmp(&(&b.ns, &b.name)));
        out
    }

    /// Forget names nothing refers to any more.
    fn prune(&mut self) {
        self.names.retain(|_, v| {
            v.retain(|t| Arc::strong_count(t) > 1);
            !v.is_empty()
        });
    }

    /// Mono µs the open interval starts at.
    pub(crate) fn open_from_us(&self) -> i64 {
        self.cur.from_us
    }

    pub(crate) fn open(&mut self, origin: String, mono_us: i64) -> Option<(u64, Wake)> {
        if self.stopped || self.conns.len() >= MAX_CONNECTIONS || self.next_conn > MAX_CONN_ORDINAL
        {
            return None;
        }
        let c = self.next_conn;
        self.next_conn += 1;
        let info = ConnInfo { origin, draft: None };
        self.conns.insert(c, Conn { info, active: HashSet::new(), pairs: HashMap::new() });
        let wake = self.room(c, None, 90);
        self.push_event(Event {
            c,
            track: None,
            e: EventKind::ConnOpen,
            code: None,
            at_us: mono_us,
        });
        Some((c, wake))
    }

    /// Set a connection's draft. The open interval is sealed first when it
    /// holds runs or marks on the connection, which were checked against
    /// the draft known when they were reported.
    pub(crate) fn set_draft(&mut self, c: u64, draft: u64) -> Result<Wake, Refused> {
        if !(1..=65_535).contains(&draft) {
            return self.refuse(Refused::Input);
        }
        let Some(conn) = self.conns.get_mut(&c) else { return self.refuse(Refused::Closed) };
        if conn.info.draft == Some(draft) {
            return Ok(Wake::No);
        }
        conn.info.draft = Some(draft);
        let cur = &self.cur;
        let checked = cur.marks.iter().any(|m| m.c == c)
            || cur.runs.iter().any(|r| r.flow.c == c)
            || cur.open.keys().any(|f| f.c == c);
        let wake = if checked && self.cut(self.last_mono, false) { Wake::Seal } else { Wake::No };
        if let Some(i) = self.cur.conns.get_mut(&c) {
            i.draft = Some(draft);
        }
        Ok(wake)
    }

    fn draft(&self, c: u64) -> Option<u64> {
        self.conns.get(&c).and_then(|x| x.info.draft)
    }

    /// Ids past 2^62 - 1 exist only from draft 17.
    fn id_ok(&self, c: u64, id: u64) -> bool {
        id <= MAX_VARINT_ID || self.draft(c).is_none_or(|d| d > 16)
    }

    /// The interned track for these name parts, or `None` past MoQT's limits.
    fn track<N: AsRef<[u8]>>(&mut self, ns: &[N], name: &[u8]) -> Option<TrackRef> {
        let bytes = name.len() + ns.iter().map(|f| f.as_ref().len()).sum::<usize>();
        if ns.len() > MAX_NAMESPACE_FIELDS || bytes > MAX_FULL_NAME_BYTES {
            return None;
        }
        let mut h = DefaultHasher::new();
        ns.len().hash(&mut h);
        for f in ns {
            f.as_ref().hash(&mut h);
        }
        name.hash(&mut h);
        let key = h.finish();
        let same = |t: &TrackRef| {
            t.name == name
                && t.ns.len() == ns.len()
                && t.ns.iter().zip(ns).all(|(a, b)| a.as_slice() == b.as_ref())
        };
        let bucket = self.names.entry(key).or_default();
        if let Some(t) = bucket.iter().find(|t| same(t)) {
            return Some(Arc::clone(t));
        }
        let t =
            Arc::new(Track::new(ns.iter().map(|f| f.as_ref().to_vec()).collect(), name.to_vec()));
        bucket.push(Arc::clone(&t));
        Some(t)
    }

    /// Make room in the interval for a fact on `c` and `track` costing
    /// `bytes`, sealing it first when the fact would not fit one body.
    fn room(&mut self, c: u64, track: Option<&TrackRef>, bytes: usize) -> Wake {
        let new_conn = !self.cur.conns.contains_key(&c);
        let new_track = track.is_some_and(|t| !self.cur.listed.contains(t));
        if self.cur.has_facts() && self.cur.bytes + bytes + SEAL_SLACK > SEAL_BYTES {
            self.cur.remeasure_names();
        }
        let full = (new_conn && self.cur.conns.len() >= MAX_BODY_CONNS)
            || (new_track && self.cur.tracks.len() >= MAX_BODY_TRACKS)
            || (self.cur.has_facts() && self.cur.bytes + bytes + SEAL_SLACK > SEAL_BYTES);
        let wake = if full && self.cut(self.last_mono, false) { Wake::Seal } else { Wake::No };
        if let Some(info) = self.conns.get(&c).map(|x| x.info.clone()) {
            if !self.cur.conns.contains_key(&c) {
                self.cur.bytes += 60 + info.origin.len();
                self.cur.conns.insert(c, info);
            }
        }
        if let Some(t) = track {
            self.cur.list(t);
        }
        self.cur.bytes += bytes;
        wake
    }

    /// One object the producer's MoQ library accepted.
    pub(crate) fn object_sent<N: AsRef<[u8]>>(
        &mut self,
        c: u64,
        ns: &[N],
        name: &[u8],
        h: Handoff,
        at_us: i64,
        end_us: i64,
    ) -> Result<Wake, Refused> {
        if self.stopped {
            return self.refuse(Refused::Closed);
        }
        if !self.conns.contains_key(&c) {
            return self.refuse(Refused::Closed);
        }
        let ids_ok =
            self.id_ok(c, h.g) && self.id_ok(c, h.o) && h.sub.is_none_or(|s| self.id_ok(c, s));
        if !ids_ok || h.size > MAX_SAFE_INTEGER || end_us < at_us {
            return self.refuse(Refused::Input);
        }
        let Some(track) = self.track(ns, name) else { return self.refuse(Refused::Input) };
        {
            let conn = &self.conns[&c];
            let new_pair = !conn.pairs.contains_key(&track);
            let new_active = !self.active.contains_key(&track);
            if (new_pair && conn.pairs.len() >= MAX_TRACKS_PER_CONNECTION)
                || (new_active && self.active.len() >= MAX_BODY_TRACKS)
            {
                return self.refuse(Refused::Input);
            }
        }
        let flow = Flow { c, track: Arc::clone(&track), g: h.g, sub: h.sub };
        let cost = self.run_cost(&flow, &h, at_us, end_us);
        let mut wake = self.room(c, Some(&track), cost);
        if self.cur.open.len() >= MAX_FLOWS && !self.cur.open.contains_key(&flow) {
            if self.cut(self.last_mono, false) {
                wake = Wake::Seal;
            }
            self.room(c, Some(&track), cost);
        }

        let conn = self.conns.get_mut(&c).expect("checked above");
        if conn.active.insert(Arc::clone(&track)) {
            *self.active.entry(Arc::clone(&track)).or_default() += 1;
        }
        let pair = conn.pairs.entry(Arc::clone(&track)).or_default();
        let gap = pair.last_at.map(|last| at_us.saturating_sub(last));
        pair.last_at = Some(at_us);
        let fell = pair.last_group.is_some_and(|last| h.g < last);
        pair.last_group = Some(h.g);

        let cur = &mut self.cur;
        if let Some(gap) = gap {
            let pace = cur.pace.entry((c, Arc::clone(&track))).or_default();
            let hist = if h.starts_group { &mut pace.first } else { &mut pace.later };
            let n = hist.entry(key_of(gap)).or_insert(0);
            if *n == 0 {
                cur.bytes += 4;
            }
            *n += 1;
        }
        if fell {
            let n = cur.gdec.entry((c, Arc::clone(&track))).or_insert(0);
            if *n == 0 {
                cur.bytes += 12;
            }
            *n += 1;
        }
        if !cur.groups.contains_key(&track) {
            cur.bytes += SPAN_BYTES;
        }
        let groups = cur.groups.entry(Arc::clone(&track)).or_default();
        if groups.groups.insert(h.g) {
            cur.bytes += 2;
        }
        groups.span = Some(match groups.span {
            None => (at_us, at_us),
            Some((lo, hi)) => (lo.min(at_us), hi.max(at_us)),
        });

        let breaks = match cur.open.get(&flow) {
            None => false,
            Some(run) => {
                let last = *run.ids.last().expect("a run has an object");
                let q = (end_us - run.times[0]).div_euclid(DT_QUANTUM_US);
                h.o <= last
                    || h.starts_group
                    || h.opens_subgroup
                    || i32::try_from(q).is_err()
                    || run.b + h.size > MAX_SAFE_INTEGER
            }
        };
        if breaks {
            if let Some(run) = cur.open.remove(&flow) {
                cur.runs.push(run);
            }
        }
        match cur.open.get_mut(&flow) {
            Some(run) => {
                run.ids.push(h.o);
                run.times.push(at_us);
                run.ends.push(end_us);
                run.sizes.push(h.size);
                run.b += h.size;
            }
            None => {
                let order = cur.next_order();
                cur.open.insert(
                    flow.clone(),
                    Run {
                        order,
                        flow: flow.clone(),
                        ids: vec![h.o],
                        times: vec![at_us],
                        ends: vec![end_us],
                        sizes: vec![h.size],
                        b: h.size,
                        gs: h.starts_group,
                        fo: h.opens_subgroup,
                        eog: false,
                    },
                );
            }
        }
        if h.ends_group {
            if let Some(mut run) = cur.open.remove(&flow) {
                run.eog = true;
                cur.runs.push(run);
            }
        }
        Ok(wake)
    }

    /// What one more object adds to the body, about.
    fn run_cost(&self, flow: &Flow, h: &Handoff, at_us: i64, end_us: i64) -> usize {
        match self.cur.open.get(flow) {
            Some(run) if h.o > *run.ids.last().unwrap_or(&0) => {
                let t0 = run.times[0];
                let q = (at_us - t0).div_euclid(DT_QUANTUM_US);
                let prev = (run.times.last().unwrap_or(&at_us) - t0).div_euclid(DT_QUANTUM_US);
                let gap = h.o - run.ids.last().unwrap_or(&0);
                zigzag_len(q - prev)
                    + zigzag_len((end_us - t0).div_euclid(DT_QUANTUM_US) - q)
                    + leb_len(h.size)
                    + if gap == 1 { 0 } else { leb_len(gap) + 1 }
            }
            _ => {
                3 + leb_len(flow.c)
                    + leb_len(h.g)
                    + h.sub.map_or(0, leb_len)
                    + leb_len(h.o)
                    + 9
                    + zigzag_len((end_us - at_us).div_euclid(DT_QUANTUM_US))
                    + leb_len(h.size)
            }
        }
    }

    /// A status the producer sent, as a mark.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn mark<N: AsRef<[u8]>>(
        &mut self,
        c: u64,
        ns: &[N],
        name: &[u8],
        kind: MarkKind,
        g: u64,
        o: u64,
        n: u64,
        t: i64,
    ) -> Result<Wake, Refused> {
        if self.stopped || !self.conns.contains_key(&c) {
            return self.refuse(Refused::Closed);
        }
        let in_draft = match self.draft(c) {
            Some(d) if (7..=23).contains(&d) => {
                let (lo, hi) = kind.drafts();
                (lo..=hi).contains(&d)
            }
            _ => true,
        };
        if !in_draft || !self.id_ok(c, g) || !self.id_ok(c, o) {
            return self.refuse(Refused::Input);
        }
        let Some(track) = self.track(ns, name) else { return self.refuse(Refused::Input) };
        if !self.cur.listed.contains(&track)
            && !self.active.contains_key(&track)
            && self.active.len() >= MAX_BODY_TRACKS
        {
            return self.refuse(Refused::Input);
        }
        let wake = self.room(c, Some(&track), 12 + leb_len(g) + leb_len(o));
        if self.cur.marks.len() >= MAX_FACTS {
            self.cur.dropped_records += 1;
        } else {
            self.cur.marks.push(Mark { c, track, kind, g, o, n, t });
        }
        Ok(wake)
    }

    /// A `pev` event. `publish_done` ends the track on the connection.
    pub(crate) fn event<N: AsRef<[u8]>>(
        &mut self,
        c: u64,
        track: Option<(&[N], &[u8])>,
        e: EventKind,
        code: Option<u64>,
        at_us: i64,
    ) -> Result<Wake, Refused> {
        if self.stopped || !self.conns.contains_key(&c) {
            return self.refuse(Refused::Closed);
        }
        if code.is_some_and(|v| v > MAX_SAFE_INTEGER) {
            return self.refuse(Refused::Input);
        }
        let track = match track {
            None => None,
            Some((ns, name)) => match self.track(ns, name) {
                Some(t) => Some(t),
                None => return self.refuse(Refused::Input),
            },
        };
        if let Some(t) = &track {
            if !self.cur.listed.contains(t)
                && !self.active.contains_key(t)
                && self.active.len() >= MAX_BODY_TRACKS
            {
                return self.refuse(Refused::Input);
            }
        }
        let wake = self.room(c, track.as_ref(), 90);
        if let Some(t) = &track {
            if matches!(e, EventKind::PublishDone | EventKind::StreamReset) {
                self.clear(Clear::Track(c, Arc::clone(t)));
            }
            if e == EventKind::PublishDone {
                self.deactivate(c, t);
            }
        }
        self.push_event(Event { c, track, e, code, at_us });
        Ok(wake)
    }

    fn push_event(&mut self, ev: Event) {
        if self.cur.events.len() >= MAX_FACTS {
            self.cur.dropped_records += 1;
        } else {
            self.cur.events.push(ev);
        }
    }

    fn clear(&mut self, clear: Clear) {
        let order = self.cur.next_order();
        match &clear {
            Clear::Track(c, t) => self.cur.end_runs(|f| !(f.c == *c && &f.track == t)),
            Clear::Conn(c) => self.cur.end_runs(|f| f.c != *c),
        }
        self.cur.clears.push((order, clear));
    }

    fn deactivate(&mut self, c: u64, t: &TrackRef) {
        let Some(conn) = self.conns.get_mut(&c) else { return };
        if conn.active.remove(t) {
            if let Some(n) = self.active.get_mut(t) {
                *n -= 1;
                if *n == 0 {
                    self.active.remove(t);
                }
            }
        }
    }

    /// Close a connection, with its close code. A code past 2^53 - 1 is
    /// refused, and the connection closes without one.
    pub(crate) fn close(&mut self, c: u64, code: Option<u64>, at_us: i64) -> Result<Wake, Refused> {
        if !self.conns.contains_key(&c) {
            return Ok(Wake::No);
        }
        let valid = code.is_none_or(|v| v <= MAX_SAFE_INTEGER);
        let wake = self.room(c, None, 90);
        self.clear(Clear::Conn(c));
        let tracks: Vec<TrackRef> = self.conns[&c].active.iter().cloned().collect();
        for t in &tracks {
            self.deactivate(c, t);
        }
        self.conns.remove(&c);
        let code = code.filter(|_| valid);
        self.push_event(Event { c, track: None, e: EventKind::ConnClose, code, at_us });
        if valid {
            Ok(wake)
        } else {
            self.refuse(Refused::Input)
        }
    }
}

#[cfg(test)]
mod tests;

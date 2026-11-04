//! A sealed interval to a body: the track's sample level per body, run
//! continuation across bodies, record sequence numbers, and the tail
//! counters. Everything here runs on the sealer, one interval at a time, in
//! seal order.

#![allow(
    clippy::mutable_key_type,
    reason = "a track hashes and compares by its name bytes, not by its atomics"
)]

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::Arc;

use crate::collect::{Clear, Flow, Interval, Pace, TrackRef, MAX_FLOWS};
use crate::sampling::{body_k, level, BodyGroups, LEVELS};
use crate::wire::{
    preamble_json, record_frames, AppOffset, Batch, ConnRec, Hist, MarkIn, PaceIn, PevIn, Record,
    RunIn, Seal, Tail, TrackRec, MAX_RECORD_ENTRIES,
};
use crate::Timing;

/// A body sealed but not yet sent: its batch record gets its clock when it
/// is first sent, and from then on its bytes are fixed.
#[derive(Clone, Debug)]
pub(crate) struct Sealed {
    pub seq: u64,
    pub epoch: u64,
    pub base_us: i64,
    pub app: Option<AppOffset>,
    pub batch: Batch,
    /// `batch.tracks`' tracks, in order.
    pub tracks: Vec<TrackRef>,
    /// The fact records' frames.
    pub records: Vec<u8>,
    pub preamble: String,
    /// Mono µs its next seal is due; none in a final body.
    pub next_us: Option<i64>,
    /// Its size before compression.
    pub raw_len: usize,
}

impl Sealed {
    /// Fix which tracks carry their names, at the body's first send: those
    /// no accepted body has carried yet.
    pub(crate) fn name_tracks(&mut self) {
        for (rec, t) in self.batch.tracks.iter_mut().zip(&self.tracks) {
            rec.named = t.names_needed();
        }
    }

    /// The body left the buffer, accepted by ingest or given up.
    pub(crate) fn answered(&self, accepted: bool) {
        for (rec, t) in self.batch.tracks.iter().zip(&self.tracks) {
            t.answered(rec.named, accepted);
        }
    }
}

/// What every body of the instance shares.
#[derive(Clone, Debug)]
pub(crate) struct Head {
    pub source: String,
    pub instance_id: String,
    /// Mono µs and wall ms at the instance's start.
    pub start: (i64, i64),
    pub monitor_name: &'static str,
    pub monitor_version: &'static str,
}

/// Flows whose last run was emitted, for `cont`, bounded by the flow cap.
#[derive(Debug, Default)]
struct Emitted {
    stamp: HashMap<Flow, u64>,
    order: VecDeque<(Flow, u64)>,
    next: u64,
}

impl Emitted {
    fn contains(&self, f: &Flow) -> bool {
        self.stamp.contains_key(f)
    }

    fn insert(&mut self, f: Flow) {
        self.next += 1;
        self.stamp.insert(f.clone(), self.next);
        self.order.push_back((f, self.next));
        while self.stamp.len() > MAX_FLOWS {
            let Some((old, s)) = self.order.pop_front() else { break };
            if self.stamp.get(&old) == Some(&s) {
                self.stamp.remove(&old);
            }
        }
        if self.order.len() > 2 * MAX_FLOWS {
            let stamp = &self.stamp;
            self.order.retain(|(f, s)| stamp.get(f) == Some(s));
        }
    }

    fn remove(&mut self, f: &Flow) {
        self.stamp.remove(f);
    }

    fn clear(&mut self, c: &Clear) {
        match c {
            Clear::Track(conn, t) => self.stamp.retain(|f, _| !(f.c == *conn && &f.track == t)),
            Clear::Conn(conn) => self.stamp.retain(|f, _| f.c != *conn),
        }
    }
}

#[derive(Debug)]
pub(crate) struct Packer {
    head: Head,
    next_seq: u64,
    next_rseq: u64,
    /// The integrator's sampling target, groups/s; `None`: every group.
    target: Option<u32>,
    prev_k: HashMap<TrackRef, u8>,
    /// The tracks the previous body listed.
    prev_listed: HashSet<TrackRef>,
    emitted: Emitted,
    totals: BTreeMap<u64, (u64, u64)>,
    pre_drop_records: u64,
    pre_drop_objects: u64,
}

impl Packer {
    pub(crate) fn new(head: Head, target: Option<u32>) -> Self {
        Packer {
            head,
            next_seq: 0,
            next_rseq: 0,
            target,
            prev_k: HashMap::new(),
            prev_listed: HashSet::new(),
            emitted: Emitted::default(),
            totals: BTreeMap::new(),
            pre_drop_records: 0,
            pre_drop_objects: 0,
        }
    }

    /// Records dropped before encoding, so far.
    pub(crate) fn dropped(&self) -> u64 {
        self.pre_drop_records
    }

    /// Pack `iv`, its runs at `timing`, its next seal due one `iv.seal_ms` on.
    #[cfg(test)]
    pub(crate) fn pack(&mut self, iv: Interval, app: Option<AppOffset>, timing: Timing) -> Sealed {
        let next = iv.seal_ms;
        self.pack_due(iv, app, timing, next)
    }

    /// Pack `iv`, its runs at `timing`, its next seal due `next_ms` after it.
    pub(crate) fn pack_due(
        &mut self,
        iv: Interval,
        app: Option<AppOffset>,
        timing: Timing,
        next_ms: u64,
    ) -> Sealed {
        let Interval {
            from_us,
            through_us,
            epoch,
            seal_ms,
            is_final,
            runs,
            mut clears,
            marks,
            events,
            pace,
            gdec,
            groups,
            conns,
            tracks,
            dropped_records,
        } = iv;
        self.pre_drop_records += dropped_records;
        let ti: HashMap<&TrackRef, usize> =
            tracks.iter().enumerate().map(|(i, t)| (t, i)).collect();

        // One sample level per track for the body, when a target is set.
        let mut track_recs = Vec::with_capacity(tracks.len());
        let mut excluded: HashMap<&TrackRef, HashSet<u64>> = HashMap::new();
        for t in &tracks {
            let tg = groups.get(t);
            let (k, xg) = match (self.target, tg) {
                (Some(target), Some(tg)) => {
                    let mut by_level = [0u32; LEVELS];
                    for &g in &tg.groups {
                        by_level[usize::from(level(t.tk, g))] += 1;
                    }
                    let from = if self.prev_listed.contains(t) {
                        from_us
                    } else {
                        tg.span.map_or(through_us, |(lo, _)| lo)
                    };
                    let prev = self.prev_k.get(t).copied().unwrap_or(0);
                    let span_us = through_us - from;
                    let k = body_k(&BodyGroups { by_level: &by_level, span_us }, prev, target);
                    self.prev_k.insert(Arc::clone(t), k);
                    let mut xg: Vec<u64> =
                        tg.groups.iter().copied().filter(|&g| level(t.tk, g) < k).collect();
                    xg.sort_unstable();
                    excluded.insert(t, xg.iter().copied().collect());
                    (k, xg)
                }
                _ => (0, Vec::new()),
            };
            track_recs.push(TrackRec {
                ns: t.ns.clone(),
                name: t.name.clone(),
                tk: t.tk,
                named: true,
                k,
                span: tg.and_then(|g| g.span),
                xg,
            });
        }
        self.prev_k.retain(|t, _| ti.contains_key(t));
        self.prev_listed = tracks.iter().cloned().collect();

        let mut records = Vec::new();
        for e in events {
            records.push(Record::Pev(PevIn {
                c: e.c,
                ti: e.track.as_ref().map(|t| ti[t]),
                e: e.e,
                code: e.code,
                at_us: e.at_us,
            }));
        }

        let mut run_ins = Vec::new();
        clears.sort_by_key(|(o, _)| *o);
        let mut clears = clears.into_iter().peekable();
        for run in runs {
            while let Some((_, c)) = clears.next_if(|(o, _)| *o < run.order) {
                self.emitted.clear(&c);
            }
            let f = &run.flow;
            if excluded.get(&f.track).is_some_and(|x| x.contains(&f.g)) {
                continue;
            }
            let cont = self.emitted.contains(f);
            if run.eog {
                self.emitted.remove(f);
            } else {
                self.emitted.insert(f.clone());
            }
            let total = self.totals.entry(f.c).or_default();
            total.0 += run.ids.len() as u64;
            total.1 += run.b;
            run_ins.push(RunIn {
                cont,
                fo: run.fo,
                eog: run.eog,
                gs: run.gs,
                c: f.c,
                ti: ti[&f.track],
                g: f.g,
                sub: f.sub,
                ids: run.ids,
                times: run.times,
                ends: run.ends,
                sizes: run.sizes,
                b: run.b,
            });
        }
        for (_, c) in clears {
            self.emitted.clear(&c);
        }
        for chunk in chunks(run_ins) {
            records.push(Record::Runs(chunk));
        }

        let mut mark_ins = Vec::new();
        for m in marks {
            mark_ins.push(MarkIn {
                kind: m.kind,
                c: m.c,
                ti: ti[&m.track],
                g: m.g,
                o: m.o,
                n: m.n,
                t: m.t,
            });
        }
        for chunk in chunks(mark_ins) {
            records.push(Record::Marks(chunk));
        }

        let mut paces: Vec<PaceIn> =
            pace.into_iter().map(|((c, t), p)| pace_in(c, ti[&t], p)).collect();
        paces.sort_by_key(|p| (p.c, p.ti));
        for chunk in chunks(paces) {
            records.push(Record::Paces(chunk));
        }
        if is_final {
            records.push(Record::End("shutdown"));
        }

        let mut gdec: Vec<(u64, usize, u64)> =
            gdec.into_iter().map(|((c, t), n)| (c, ti[&t], n)).collect();
        gdec.sort_unstable();

        let conns: Vec<ConnRec> = conns
            .into_iter()
            .map(|(c, i)| ConnRec { c, draft: i.draft, relay: i.origin })
            .collect();

        let first_rseq = self.next_rseq;
        let n = records.len() as u64;
        self.next_rseq += n;
        let em: Vec<(u64, u64)> = if n > 0 { vec![(first_rseq, n)] } else { Vec::new() };
        let seq = self.next_seq;
        self.next_seq += 1;
        let tail = Tail {
            last_rseq: self.next_rseq.checked_sub(1),
            pre_drop_records: self.pre_drop_records,
            pre_drop_objects: self.pre_drop_objects,
            conn: conns
                .iter()
                .map(|c| {
                    let (o, b) = self.totals.get(&c.c).copied().unwrap_or_default();
                    (c.c, o, b)
                })
                .collect(),
        };
        let batch = Batch {
            source: self.head.source.clone(),
            instance_id: self.head.instance_id.clone(),
            seq,
            is_final,
            monitor_name: self.head.monitor_name,
            monitor_version: self.head.monitor_version,
            tail,
            conns,
            tracks: track_recs,
            gdec,
            start: (seq == 0).then_some(self.head.start),
            smp: self.target,
            timing,
        };
        let next_us = (!is_final).then(|| {
            through_us
                .saturating_add(i64::try_from(next_ms.saturating_mul(1000)).unwrap_or(i64::MAX))
        });
        let seal = Seal { seq, from_us, through_us, ms: seal_ms, next_us };
        let preamble = preamble_json(&self.head.instance_id, &em, &seal);
        let records = record_frames(&records, from_us, first_rseq, timing);
        let probe = crate::wire::Clk { base_us: from_us, epoch, res_us: 1, sample: None, app };
        let raw_len = preamble.len() + crate::wire::frames(&batch, &probe, &records).len() + 200;
        Sealed {
            seq,
            epoch,
            base_us: from_us,
            app,
            batch,
            tracks,
            records,
            preamble,
            next_us,
            raw_len,
        }
    }
}

fn pace_in(c: u64, ti: usize, p: Pace) -> PaceIn {
    let hist = |m: BTreeMap<u32, u64>| -> Hist { m.into_iter().collect() };
    PaceIn { c, ti, first: hist(p.first), later: hist(p.later) }
}

fn chunks<T>(mut v: Vec<T>) -> Vec<Vec<T>> {
    let mut out = Vec::new();
    while v.len() > MAX_RECORD_ENTRIES {
        let rest = v.split_off(MAX_RECORD_ENTRIES);
        out.push(std::mem::replace(&mut v, rest));
    }
    if !v.is_empty() {
        out.push(v);
    }
    out
}

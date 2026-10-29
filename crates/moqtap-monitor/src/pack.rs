//! Rows to bodies. Every body declares each relay and track its records
//! name, holds one `k` per track, stays within the reader's caps, and is
//! sealed before its gzipped frames pass 32 KiB.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::collect::{PendingEvent, PendingGroup, PendingObject, RelayInfo, Taken, TrackName};
use crate::relay_cap::origins_of;
use crate::wire::{
    encode_body, encode_frames, gzip, idempotency_key, BodySpec, Clock, DataRec, GrpRow, Head,
    IdForm, ObjRow, PevRec, RelayRec, TrackRec, EDGE_CAP_BYTES, MAX_BODY_GROUP_ROWS,
    MAX_BODY_RELAYS, MAX_BODY_TRACKS, MAX_COLUMN_ROWS, MAX_RELAY_C, MAX_SAFE_INTEGER, MAX_TRACK_ID,
    PREAMBLE_BYTES, SEAL_BYTES,
};

/// Gzip never grows frames by more than this, so smaller frames need no trial.
const GZIP_SLACK: usize = 256;

/// The batch fields every body of one seal shares.
#[derive(Clone, Debug)]
pub(crate) struct HeadFields {
    pub source: String,
    pub instance_id: String,
    pub ts: u64,
    pub wall: u64,
    pub lost: Vec<u64>,
    pub dropped: u64,
    pub clock: Option<Clock>,
    pub monitor_name: &'static str,
    pub monitor_version: &'static str,
}

#[derive(Clone, Debug)]
pub(crate) struct Sealed {
    pub seq: u64,
    pub idempotency_key: String,
    pub body: Vec<u8>,
    /// The relay origins the body names.
    pub origins: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    /// Seal only bodies that are full; hand back the rest.
    Early,
    /// Seal everything taken.
    All,
    /// Seal everything, the last body `final` with an `end` record.
    Final,
}

#[derive(Debug, Default)]
pub(crate) struct Packed {
    pub bodies: Vec<Sealed>,
    /// Rows of the body an early seal left open.
    pub leftover: Option<Taken>,
    /// Rows no body could carry.
    pub dropped: u64,
}

/// A row's connection, and its track with the track's `k`.
type Ref = (u64, Option<(Arc<TrackName>, u8)>);

#[derive(Clone, Debug)]
enum Unit {
    Grp(Vec<PendingGroup>),
    Obj(Vec<PendingObject>),
    Pev(Vec<PendingEvent>),
}

impl Unit {
    fn len(&self) -> usize {
        match self {
            Unit::Grp(r) => r.len(),
            Unit::Obj(r) => r.len(),
            Unit::Pev(r) => r.len(),
        }
    }

    fn split(self) -> (Unit, Unit) {
        fn half<T>(mut v: Vec<T>) -> (Vec<T>, Vec<T>) {
            let b = v.split_off(v.len() / 2);
            (v, b)
        }
        match self {
            Unit::Grp(r) => {
                let (a, b) = half(r);
                (Unit::Grp(a), Unit::Grp(b))
            }
            Unit::Obj(r) => {
                let (a, b) = half(r);
                (Unit::Obj(a), Unit::Obj(b))
            }
            Unit::Pev(r) => {
                let (a, b) = half(r);
                (Unit::Pev(a), Unit::Pev(b))
            }
        }
    }

    /// The (connection, track, k) each row names.
    fn refs(&self) -> Vec<Ref> {
        match self {
            Unit::Grp(r) => r.iter().map(|x| (x.conn, Some((Arc::clone(&x.track), x.k)))).collect(),
            Unit::Obj(r) => r.iter().map(|x| (x.conn, Some((Arc::clone(&x.track), x.k)))).collect(),
            Unit::Pev(r) => r.iter().map(|x| (x.conn, x.track.clone())).collect(),
        }
    }
}

/// The declarations of one body: relays by connection, tracks by name with
/// their one `k`.
#[derive(Clone, Debug, Default)]
struct Dict {
    relays: Vec<u64>,
    tracks: Vec<(Arc<TrackName>, u8)>,
    by_name: HashMap<Arc<TrackName>, u8>,
    group_rows: usize,
}

impl Dict {
    /// Add what `refs` need; false when that would break a cap or give a
    /// track a second `k`. On false nothing changed.
    fn admit(&mut self, refs: &[Ref], group_rows: usize) -> bool {
        let mut next = self.clone();
        for (conn, track) in refs {
            if !next.relays.contains(conn) {
                next.relays.push(*conn);
            }
            if let Some((name, k)) = track {
                match next.by_name.get(name) {
                    Some(have) if have != k => return false,
                    Some(_) => {}
                    None => {
                        next.by_name.insert(Arc::clone(name), *k);
                        next.tracks.push((Arc::clone(name), *k));
                    }
                }
            }
        }
        next.group_rows += group_rows;
        let fits = next.relays.len() <= MAX_BODY_RELAYS.min(MAX_RELAY_C + 1)
            && next.tracks.len() <= MAX_BODY_TRACKS.min(MAX_TRACK_ID)
            && next.group_rows <= MAX_BODY_GROUP_ROWS;
        if fits {
            *self = next;
        }
        fits
    }
}

/// Seal `taken` into bodies, numbering them from `next_seq`.
pub(crate) fn pack(taken: Taken, head: &HeadFields, next_seq: &mut u64, mode: Mode) -> Packed {
    let relays = taken.relays.clone();
    let mut out = Packed::default();
    let units = units(taken, &mut out.dropped);
    let mut bodies: Vec<Vec<Unit>> = Vec::new();
    let mut current: Vec<Unit> = Vec::new();
    let mut dict = Dict::default();
    let mut queue: std::collections::VecDeque<Unit> = units.into();

    while let Some(unit) = queue.pop_front() {
        let mut trial = dict.clone();
        if !trial.admit(&unit.refs(), group_rows(&unit)) {
            if current.is_empty() {
                // Every unit is built to fit an empty body; were one not to,
                // its rows are dropped rather than sent unreadable.
                out.dropped += unit.len() as u64;
                continue;
            }
            bodies.push(std::mem::take(&mut current));
            dict = Dict::default();
            queue.push_front(unit);
            continue;
        }
        current.push(unit);
        let seq = *next_seq + bodies.len() as u64;
        let gz = sealed_len(&current, &relays, &trial, head, seq, mode);
        if gz <= SEAL_BYTES {
            dict = trial;
            continue;
        }
        let Some(unit) = current.pop() else { continue };
        if !current.is_empty() {
            bodies.push(std::mem::take(&mut current));
            dict = Dict::default();
            queue.push_front(unit);
            continue;
        }
        // Alone and past the seal: sent if the edge takes it, else halved.
        if gz + PREAMBLE_BYTES <= EDGE_CAP_BYTES {
            bodies.push(vec![unit]);
            dict = Dict::default();
            continue;
        }
        if unit.len() <= 1 {
            out.dropped += unit.len() as u64;
            continue;
        }
        let (a, b) = unit.split();
        queue.push_front(b);
        queue.push_front(a);
    }

    match mode {
        Mode::Early => {
            if !current.is_empty() {
                out.leftover = Some(untake(current, relays.clone()));
            }
        }
        Mode::All => {
            if !current.is_empty() {
                bodies.push(current);
            }
        }
        Mode::Final => {
            if !current.is_empty() || bodies.is_empty() {
                bodies.push(current);
            }
        }
    }

    let n = bodies.len();
    for (i, units) in bodies.into_iter().enumerate() {
        let mut dict = Dict::default();
        for u in &units {
            dict.admit(&u.refs(), group_rows(u));
        }
        let is_final = mode == Mode::Final && i + 1 == n;
        let seq = *next_seq;
        *next_seq += 1;
        let frames = encode(&units, &relays, &dict, head, seq, is_final);
        let gz = gzip(&frames);
        debug_assert!(units.len() == 1 || gz.len() <= SEAL_BYTES, "sealed past 32 KiB");
        out.bodies.push(Sealed {
            seq,
            idempotency_key: idempotency_key(&head.source, &head.instance_id, seq),
            body: encode_body(&gz),
            origins: origins_of(dict.relays.iter(), &relays),
        });
    }
    out
}

/// Chunk the rows into records, each of which fits an empty body by itself.
/// A second row for one (connection, track, group) is dropped and counted.
fn units(t: Taken, dropped: &mut u64) -> Vec<Unit> {
    let Taken { mut groups, mut objects, events, .. } = t;
    let mut seen = HashSet::new();
    let before = groups.len();
    groups.retain(|r| seen.insert((r.conn, Arc::clone(&r.track), r.g)));
    *dropped += (before - groups.len()) as u64;
    groups.sort_by(|a, b| {
        (a.conn, &a.track, a.k, a.first_us, a.g).cmp(&(b.conn, &b.track, b.k, b.first_us, b.g))
    });
    objects.sort_by(|a, b| (a.conn, &a.track, a.k).cmp(&(b.conn, &b.track, b.k)));
    let mut out = Vec::new();
    chunk(events, |r| (r.conn, r.track.clone()), &mut out, Unit::Pev);
    chunk(groups, |r| (r.conn, Some((Arc::clone(&r.track), r.k))), &mut out, Unit::Grp);
    chunk(objects, |r| (r.conn, Some((Arc::clone(&r.track), r.k))), &mut out, Unit::Obj);
    out
}

fn chunk<T>(
    rows: Vec<T>,
    refs: impl Fn(&T) -> Ref,
    out: &mut Vec<Unit>,
    wrap: impl Fn(Vec<T>) -> Unit,
) {
    let mut cur = Vec::new();
    let mut dict = Dict::default();
    for r in rows {
        if cur.len() == MAX_COLUMN_ROWS || !dict.admit(&[refs(&r)], 0) {
            out.push(wrap(std::mem::take(&mut cur)));
            dict = Dict::default();
            dict.admit(&[refs(&r)], 0);
        }
        cur.push(r);
    }
    if !cur.is_empty() {
        out.push(wrap(cur));
    }
}

fn untake(units: Vec<Unit>, relays: HashMap<u64, RelayInfo>) -> Taken {
    let mut t = Taken { relays, ..Taken::default() };
    for u in units {
        match u {
            Unit::Grp(r) => t.groups.extend(r),
            Unit::Obj(r) => t.objects.extend(r),
            Unit::Pev(r) => t.events.extend(r),
        }
    }
    t
}

fn group_rows(u: &Unit) -> usize {
    if let Unit::Grp(r) = u {
        r.len()
    } else {
        0
    }
}

/// The gzipped frame length of a body holding `units`, sent as `seq`. In a
/// final seal any body may turn out to be the last, so both forms are measured.
fn sealed_len(
    units: &[Unit],
    relays: &HashMap<u64, RelayInfo>,
    dict: &Dict,
    head: &HeadFields,
    seq: u64,
    mode: Mode,
) -> usize {
    let forms: &[bool] = if mode == Mode::Final { &[false, true] } else { &[false] };
    let len = |is_final: bool| {
        let frames = encode(units, relays, dict, head, seq, is_final);
        if frames.len() + GZIP_SLACK <= SEAL_BYTES {
            frames.len()
        } else {
            gzip(&frames).len()
        }
    };
    forms.iter().map(|&f| len(f)).max().unwrap_or(0)
}

/// The frame stream of one body.
fn encode(
    units: &[Unit],
    relays: &HashMap<u64, RelayInfo>,
    dict: &Dict,
    head: &HeadFields,
    seq: u64,
    is_final: bool,
) -> Vec<u8> {
    let c_of = |conn: u64| dict.relays.iter().position(|&x| x == conn).unwrap_or(0);
    let tr_of = |name: &Arc<TrackName>| {
        dict.tracks.iter().position(|(n, _)| n == name).map_or(1, |i| i + 1)
    };
    let relay_recs: Vec<RelayRec<'_>> = dict
        .relays
        .iter()
        .enumerate()
        .map(|(c, id)| match relays.get(id) {
            Some(r) => RelayRec {
                c,
                relay: &r.origin,
                draft: r.draft,
                open_ts: Some(r.open_ts),
                close_ts: r.close_ts,
                close_code: r.close_code,
            },
            None => RelayRec {
                c,
                relay: "",
                draft: None,
                open_ts: None,
                close_ts: None,
                close_code: None,
            },
        })
        .collect();
    let track_recs: Vec<TrackRec<'_>> = dict
        .tracks
        .iter()
        .enumerate()
        .map(|(i, (n, k))| TrackRec { id: i + 1, ns: &n.ns, name: &n.name, k: *k })
        .collect();

    let mut data = Vec::new();
    let mut events = Vec::new();
    let mut per_object = false;
    for u in units.iter().filter(|u| matches!(u, Unit::Grp(_))) {
        if let Unit::Grp(rows) = u {
            let rows = rows
                .iter()
                .map(|r| GrpRow {
                    c: c_of(r.conn),
                    tr: tr_of(&r.track),
                    g: r.g,
                    fo: r.fo,
                    send_us: r.first_us,
                    span_us: (r.last_us - r.first_us).clamp(0, MAX_SAFE_INTEGER),
                    objects: r.objects,
                    bytes: r.bytes,
                })
                .collect();
            data.push(DataRec::Grp(rows, IdForm::Auto));
        }
    }
    for u in units {
        match u {
            Unit::Obj(rows) => {
                per_object = true;
                let rows = rows
                    .iter()
                    .map(|r| ObjRow {
                        c: c_of(r.conn),
                        tr: tr_of(&r.track),
                        g: r.g,
                        o: r.o,
                        bytes: r.bytes,
                        send_us: r.at_us,
                    })
                    .collect();
                data.push(DataRec::Obj(rows, IdForm::Auto));
            }
            Unit::Pev(rows) => events.extend(rows.iter().map(|r| PevRec {
                ts: r.ts,
                c: c_of(r.conn),
                tr: r.track.as_ref().map(|(n, _)| tr_of(n)),
                e: r.e,
                code: r.code,
            })),
            Unit::Grp(_) => {}
        }
    }
    let spec = BodySpec {
        head: Head {
            ts: head.ts,
            wall: head.wall,
            per_object,
            source: &head.source,
            instance_id: &head.instance_id,
            seq,
            is_final,
            lost: &head.lost,
            dropped: head.dropped,
            clock: head.clock,
            monitor_name: head.monitor_name,
            monitor_version: head.monitor_version,
        },
        relays: relay_recs,
        tracks: track_recs,
        data,
        events,
        end: is_final.then_some("shutdown"),
    };
    encode_frames(&spec)
}

#[cfg(test)]
mod tests {
    use std::io::Read as _;

    use super::*;
    use crate::wire::EventKind;

    fn head() -> HeadFields {
        HeadFields {
            source: "enc".into(),
            instance_id: "0".repeat(32),
            ts: 1,
            wall: 2,
            lost: vec![],
            dropped: 0,
            clock: None,
            monitor_name: "m",
            monitor_version: "0",
        }
    }

    fn records(body: &[u8]) -> Vec<serde_json::Value> {
        assert_eq!(&body[..6], b"MQTC\x01\x01");
        let mut frames = Vec::new();
        flate2::read::GzDecoder::new(&body[PREAMBLE_BYTES..]).read_to_end(&mut frames).unwrap();
        let mut out = Vec::new();
        let mut i = 0;
        while i < frames.len() {
            let len = u32::from_be_bytes(frames[i..i + 4].try_into().unwrap()) as usize;
            out.push(serde_json::from_slice(&frames[i + 4..i + 4 + len]).unwrap());
            i += 4 + len;
        }
        out
    }

    fn gz_len(body: &[u8]) -> usize {
        body.len() - PREAMBLE_BYTES
    }

    fn track(name: &str) -> Arc<TrackName> {
        Arc::new(TrackName { ns: vec!["live".into()], name: name.into() })
    }

    fn relays(n: u64) -> HashMap<u64, RelayInfo> {
        (0..n)
            .map(|i| {
                let info = RelayInfo {
                    origin: format!("https://r{i}.example"),
                    draft: None,
                    open_ts: 0,
                    close_ts: None,
                    close_code: None,
                };
                (i, info)
            })
            .collect()
    }

    fn group(conn: u64, track: &Arc<TrackName>, k: u8, g: u64) -> PendingGroup {
        PendingGroup {
            conn,
            track: Arc::clone(track),
            k,
            g,
            fo: 0,
            first_us: 1_761_696_000_000_000 + g as i64 * 33_367,
            last_us: 1_761_696_000_000_000 + g as i64 * 33_367 + 20_000,
            objects: 1 + g % 7,
            bytes: 1_000 + (g * 7_919) % 50_000,
        }
    }

    fn grp_rows(recs: &[serde_json::Value]) -> usize {
        recs.iter()
            .filter(|r| r["t"] == "grp")
            .map(|r| r["cols"]["c"].as_array().unwrap().len())
            .sum()
    }

    /// Each record's relays and tracks are declared earlier in its body.
    fn declared_before_use(recs: &[serde_json::Value]) {
        let mut cs = std::collections::HashSet::new();
        let mut ids = std::collections::HashSet::new();
        for r in &recs[1..] {
            match r["t"].as_str().unwrap() {
                "relay" => assert!(cs.insert(r["c"].as_u64().unwrap())),
                "track" => assert!(ids.insert(r["id"].as_u64().unwrap())),
                "grp" | "obj" => {
                    for c in r["cols"]["c"].as_array().unwrap() {
                        assert!(cs.contains(&c.as_u64().unwrap()));
                    }
                    for t in r["cols"]["tr"].as_array().unwrap() {
                        assert!(ids.contains(&t.as_u64().unwrap()));
                    }
                }
                _ => {}
            }
        }
    }

    #[test]
    fn many_groups_seal_into_bodies_under_32_kib() {
        let a = track("audio");
        let groups: Vec<_> = (0..2u64)
            .flat_map(|c| (0..20_000).map(move |g| (c, g)))
            .map(|(c, g)| group(c, &a, 0, g))
            .collect();
        let taken = Taken { groups, relays: relays(2), ..Taken::default() };
        let mut seq = 5;
        let p = pack(taken, &head(), &mut seq, Mode::All);
        assert!(p.bodies.len() > 2, "{}", p.bodies.len());
        assert_eq!(p.dropped, 0);
        let mut rows = 0;
        for (i, b) in p.bodies.iter().enumerate() {
            assert_eq!(b.seq, 5 + i as u64);
            assert!(gz_len(&b.body) <= SEAL_BYTES, "body {i}: {}", gz_len(&b.body));
            let recs = records(&b.body);
            assert_eq!(recs[0]["seq"], b.seq);
            assert_eq!(recs[0]["idempotencyKey"], b.idempotency_key.as_str());
            assert_eq!(recs[0]["final"], false);
            declared_before_use(&recs);
            for r in recs.iter().filter(|r| r["t"] == "grp") {
                assert!(r["cols"]["c"].as_array().unwrap().len() <= MAX_COLUMN_ROWS);
            }
            rows += grp_rows(&recs);
        }
        assert_eq!(rows, 40_000);
        assert_eq!(seq, 5 + p.bodies.len() as u64);
    }

    #[test]
    fn a_track_never_carries_two_k_in_one_body() {
        let v = track("video");
        let groups =
            vec![group(0, &v, 0, 1), group(0, &v, 0, 3), group(0, &v, 1, 4), group(0, &v, 1, 6)];
        let taken = Taken { groups, relays: relays(1), ..Taken::default() };
        let p = pack(taken, &head(), &mut 0, Mode::All);
        assert_eq!(p.bodies.len(), 2);
        for b in &p.bodies {
            let recs = records(&b.body);
            assert_eq!(recs.iter().filter(|r| r["t"] == "track").count(), 1);
        }
    }

    #[test]
    fn past_32_relays_a_second_body_starts() {
        let v = track("video");
        let groups = (0..40u64).map(|c| group(c, &v, 0, 1)).collect();
        let taken = Taken { groups, relays: relays(40), ..Taken::default() };
        let p = pack(taken, &head(), &mut 0, Mode::All);
        assert_eq!(p.bodies.len(), 2);
        for b in &p.bodies {
            let recs = records(&b.body);
            assert!(recs.iter().filter(|r| r["t"] == "relay").count() <= MAX_BODY_RELAYS);
            declared_before_use(&recs);
        }
    }

    #[test]
    fn only_referenced_relays_and_tracks_are_declared() {
        let v = track("video");
        let taken =
            Taken { groups: vec![group(3, &v, 0, 1)], relays: relays(5), ..Taken::default() };
        let recs = records(&pack(taken, &head(), &mut 0, Mode::All).bodies[0].body);
        let relays: Vec<_> = recs.iter().filter(|r| r["t"] == "relay").collect();
        assert_eq!(relays.len(), 1);
        assert_eq!(relays[0]["relay"], "https://r3.example");
        assert_eq!(relays[0]["c"], 0);
    }

    #[test]
    fn a_final_seal_with_nothing_still_ends_the_instance() {
        let p = pack(Taken::default(), &head(), &mut 9, Mode::Final);
        assert_eq!(p.bodies.len(), 1);
        let recs = records(&p.bodies[0].body);
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0]["final"], true);
        assert_eq!(recs[1]["t"], "end");
        assert_eq!(recs[1]["reason"], "shutdown");
        assert!(pack(Taken::default(), &head(), &mut 9, Mode::All).bodies.is_empty());
    }

    #[test]
    fn an_early_seal_hands_back_the_body_it_did_not_fill() {
        let a = track("audio");
        let groups: Vec<_> = (0..20_000).map(|g| group(0, &a, 0, g)).collect();
        let taken = Taken { groups, relays: relays(1), ..Taken::default() };
        let p = pack(taken, &head(), &mut 0, Mode::Early);
        let left = p.leftover.expect("leftover");
        assert!(!left.groups.is_empty());
        let sent: usize = p.bodies.iter().map(|b| grp_rows(&records(&b.body))).sum();
        assert_eq!(sent + left.groups.len(), 20_000);
        assert!(left.relays.contains_key(&0));
    }

    #[test]
    fn objects_mark_the_body_headers_and_sizes() {
        let v = track("video");
        let objects = (0..10)
            .map(|o| PendingObject {
                conn: 0,
                track: Arc::clone(&v),
                k: 0,
                g: 1,
                o,
                bytes: 10,
                at_us: o as i64,
            })
            .collect();
        let events = vec![PendingEvent {
            conn: 0,
            ts: 5,
            track: None,
            e: EventKind::RequestError,
            code: Some(4),
        }];
        let taken = Taken { objects, events, relays: relays(1), ..Taken::default() };
        let recs = records(&pack(taken, &head(), &mut 0, Mode::All).bodies[0].body);
        assert_eq!(recs[0]["lvl"], "headers+sizes");
        let kinds: Vec<_> = recs.iter().map(|r| r["t"].as_str().unwrap().to_string()).collect();
        assert_eq!(kinds, ["source-batch", "relay", "track", "obj", "pev"]);
        assert_eq!(recs[4]["code"], 4);
        assert!(recs[4].get("tr").is_none());
    }
}

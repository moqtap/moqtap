//! The upload body: an 8-byte header, an uncompressed preamble frame
//! `{v, i, em, seal}`, then length-prefixed frames, gzipped as one unit: the
//! batch record, and fact records each carrying `rseq`. A `run`, `mark` or
//! `pace` record is a small JSON descriptor followed by one raw frame of
//! LEB128 columns.
//!
//! The JSON is written by hand so that a body is byte-for-byte what ingest's
//! reference writer produces for the same input: keys in a fixed order, every
//! number an integer.

use std::fmt::Write as _;
use std::hash::{Hash, Hasher};
use std::io::Write as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use flate2::write::GzEncoder;
use flate2::Compression;
use ring::digest;

use crate::Timing;

/// Tracks one body may declare.
pub(crate) const MAX_BODY_TRACKS: usize = 256;
/// Connections one body may declare.
pub(crate) const MAX_BODY_CONNS: usize = 32;
/// Entries one `run`, `mark` or `pace` record may hold.
pub(crate) const MAX_RECORD_ENTRIES: usize = 65_536;
/// The highest connection ordinal.
pub(crate) const MAX_CONN_ORDINAL: u64 = u32::MAX as u64;
/// The byte seal: a body is sealed before its gzipped frames pass this.
pub(crate) const SEAL_BYTES: usize = 32 * 1024;
/// MoQT's limit on namespace fields.
pub(crate) const MAX_NAMESPACE_FIELDS: usize = 32;
/// MoQT's limit on a full track name, namespace and name together, in bytes.
pub(crate) const MAX_FULL_NAME_BYTES: usize = 4096;
/// The largest id a QUIC varint carries: the limit up to draft 16.
pub(crate) const MAX_VARINT_ID: u64 = (1 << 62) - 1;
/// The largest integer a JSON number carries exactly.
pub(crate) const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;
/// Time quantum of `dt` and `de`, µs.
pub(crate) const DT_QUANTUM_US: i64 = 100;

const BODY_MAGIC: [u8; 4] = *b"MQTC";
const BODY_VERSION: u8 = 2;
const FLAG_GZIP: u8 = 0x01;
const HEADER_BYTES: usize = 8;
const FRAME_RAW: u32 = 0x8000_0000;

const FL_CONT: u8 = 0x01;
const FL_XID: u8 = 0x02;
const FL_FO: u8 = 0x04;
const FL_FO_KNOWN: u8 = 0x08;
const FL_EOG: u8 = 0x10;
/// `end` = 3, not applicable: a source run has no stream end.
const FL_END_NA: u8 = 3 << 5;
const FL_GS: u8 = 0x80;

/// A full track name, by its bytes, with its `track_key`.
#[derive(Debug)]
pub(crate) struct Track {
    pub ns: Vec<Vec<u8>>,
    pub name: Vec<u8>,
    pub tk: u64,
    /// Ingest accepted a body carrying the names.
    accepted: AtomicBool,
}

impl PartialEq for Track {
    fn eq(&self, other: &Self) -> bool {
        self.ns == other.ns && self.name == other.name
    }
}

impl Eq for Track {}

impl Hash for Track {
    fn hash<H: Hasher>(&self, h: &mut H) {
        self.ns.hash(h);
        self.name.hash(h);
    }
}

impl Track {
    pub(crate) fn new(ns: Vec<Vec<u8>>, name: Vec<u8>) -> Self {
        let tk = track_key(&ns, &name);
        Track { ns, name, tk, accepted: AtomicBool::new(false) }
    }

    /// Whether a body first sent now carries the names.
    pub(crate) fn names_needed(&self) -> bool {
        !self.accepted.load(Ordering::Relaxed)
    }

    /// A body listing the track left the buffer: accepted, or given up.
    pub(crate) fn answered(&self, carried_names: bool, accepted: bool) {
        if accepted && carried_names {
            self.accepted.store(true, Ordering::Relaxed);
        }
    }
}

/// `u32be(field count)`, then for each namespace field and the name,
/// `u32be(len) ‖ bytes`.
pub(crate) fn canonical_track_bytes(ns: &[Vec<u8>], name: &[u8]) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(8 + ns.iter().map(|f| 4 + f.len()).sum::<usize>() + name.len());
    out.extend_from_slice(&(ns.len() as u32).to_be_bytes());
    for part in ns.iter().map(Vec::as_slice).chain(std::iter::once(name)) {
        out.extend_from_slice(&(part.len() as u32).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

/// The backend's `track_hash`: the first 8 bytes, big-endian, of SHA-256
/// over the canonical full track name.
pub(crate) fn track_key(ns: &[Vec<u8>], name: &[u8]) -> u64 {
    let d = digest::digest(&digest::SHA256, &canonical_track_bytes(ns, name));
    let mut b = [0u8; 8];
    b.copy_from_slice(&d.as_ref()[..8]);
    u64::from_be_bytes(b)
}

/// Unsigned LEB128 columns; `z` and `t` are zigzag forms.
#[derive(Debug, Default)]
pub(crate) struct Leb(pub Vec<u8>);

impl Leb {
    pub(crate) fn byte(&mut self, b: u8) {
        self.0.push(b);
    }

    pub(crate) fn u(&mut self, mut v: u64) {
        while v >= 0x80 {
            self.0.push((v as u8 & 0x7f) | 0x80);
            v >>= 7;
        }
        self.0.push(v as u8);
    }

    /// The wrapping difference `to - from`, as a signed zigzag.
    pub(crate) fn z(&mut self, to: u64, from: u64) {
        self.t(to.wrapping_sub(from) as i64);
    }

    pub(crate) fn t(&mut self, v: i64) {
        self.u(((v << 1) ^ (v >> 63)) as u64);
    }
}

/// Bytes `u` takes for `v`.
pub(crate) fn leb_len(v: u64) -> usize {
    (64 - v.max(1).leading_zeros() as usize).div_ceil(7)
}

/// Bytes `t` takes for `v`.
pub(crate) fn zigzag_len(v: i64) -> usize {
    leb_len(((v << 1) ^ (v >> 63)) as u64)
}

/// Standard padded base64.
pub(crate) fn base64(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for c in bytes.chunks(3) {
        let n = u32::from(c[0]) << 16
            | u32::from(*c.get(1).unwrap_or(&0)) << 8
            | u32::from(*c.get(2).unwrap_or(&0));
        out.push(A[(n >> 18) as usize & 63] as char);
        out.push(A[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 { A[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if c.len() > 2 { A[n as usize & 63] as char } else { '=' });
    }
    out
}

/// `xg`: the groups, sorted and distinct, as base64 of `u(g0)` then
/// `u(g_i - g_{i-1} - 1)`.
pub(crate) fn xg_field(groups: &[u64]) -> String {
    let mut sorted = groups.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut w = Leb::default();
    for (i, g) in sorted.iter().enumerate() {
        w.u(if i == 0 { *g } else { g - sorted[i - 1] - 1 });
    }
    base64(&w.0)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EventKind {
    StreamReset,
    RequestError,
    PublishDone,
    ConnOpen,
    ConnClose,
}

impl EventKind {
    fn as_str(self) -> &'static str {
        match self {
            EventKind::StreamReset => "stream_reset",
            EventKind::RequestError => "request_error",
            EventKind::PublishDone => "publish_done",
            EventKind::ConnOpen => "conn_open",
            EventKind::ConnClose => "conn_close",
        }
    }
}

/// Mark kinds a source writes, by their wire index.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum MarkKind {
    Eog = 0,
    Eot = 1,
    Eotg = 2,
    Eosg = 3,
    Dne = 4,
    Pgg = 8,
    Pog = 9,
}

impl MarkKind {
    /// The drafts the kind exists in.
    pub(crate) fn drafts(self) -> (u64, u64) {
        match self {
            MarkKind::Eog => (7, 23),
            MarkKind::Eot => (8, 23),
            MarkKind::Eotg => (7, 10),
            MarkKind::Eosg => (7, 7),
            MarkKind::Dne => (7, 15),
            MarkKind::Pgg => (11, 23),
            MarkKind::Pog => (14, 23),
        }
    }

    fn has_n(self) -> bool {
        matches!(self, MarkKind::Pgg | MarkKind::Pog)
    }
}

/// One run: ids and times as captured, times in device mono µs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RunIn {
    pub cont: bool,
    pub fo: bool,
    pub eog: bool,
    pub gs: bool,
    pub c: u64,
    pub ti: usize,
    pub g: u64,
    /// `None` for a datagram.
    pub sub: Option<u64>,
    pub ids: Vec<u64>,
    pub times: Vec<i64>,
    /// Each object's end, device mono µs.
    pub ends: Vec<i64>,
    /// Each object's payload bytes, summing to `b`.
    pub sizes: Vec<u64>,
    pub b: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MarkIn {
    pub kind: MarkKind,
    pub c: u64,
    pub ti: usize,
    pub g: u64,
    pub o: u64,
    /// The gap of `pgg`/`pog`.
    pub n: u64,
    pub t: i64,
}

/// A sparse histogram, keys strictly ascending, counts positive.
pub(crate) type Hist = Vec<(u32, u64)>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PaceIn {
    pub c: u64,
    pub ti: usize,
    pub first: Hist,
    pub later: Hist,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PevIn {
    pub c: u64,
    pub ti: Option<usize>,
    pub e: EventKind,
    pub code: Option<u64>,
    pub at_us: i64,
}

/// A fact record, in body order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Record {
    Pev(PevIn),
    Runs(Vec<RunIn>),
    Marks(Vec<MarkIn>),
    Paces(Vec<PaceIn>),
    End(&'static str),
}

/// An exchange sample: `server - mono` offset, round trip, mono time, PoP.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ClockSample {
    pub o_us: i64,
    pub r_us: u64,
    pub at_us: i64,
    pub pop: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Clk {
    pub base_us: i64,
    pub epoch: u64,
    pub res_us: u64,
    pub sample: Option<ClockSample>,
    pub app: Option<AppOffset>,
}

/// An integrator's UTC clock read: `utc - mono` offset and its bound, and
/// the mono time it was read, µs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AppOffset {
    pub o_us: i64,
    pub e_us: u64,
    pub at_us: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Tail {
    pub last_rseq: Option<u64>,
    pub pre_drop_records: u64,
    pub pre_drop_objects: u64,
    /// Cumulative objects and bytes per connection ordinal.
    pub conn: Vec<(u64, u64, u64)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ConnRec {
    pub c: u64,
    pub draft: Option<u64>,
    pub relay: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TrackRec {
    pub ns: Vec<Vec<u8>>,
    pub name: Vec<u8>,
    pub tk: u64,
    /// `ns` and `name` are written; otherwise `tk` alone.
    pub named: bool,
    pub k: u8,
    pub span: Option<(i64, i64)>,
    pub xg: Vec<u64>,
}

/// The `source-batch` record, but for `clk`, which is attached when the body
/// is first sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Batch {
    pub source: String,
    pub instance_id: String,
    pub seq: u64,
    pub is_final: bool,
    pub monitor_name: &'static str,
    pub monitor_version: &'static str,
    pub tail: Tail,
    pub conns: Vec<ConnRec>,
    /// Ids are positions.
    pub tracks: Vec<TrackRec>,
    /// `(c, ti, n)`.
    pub gdec: Vec<(u64, usize, u64)>,
    /// The instance's start: mono µs and wall ms.
    pub start: Option<(i64, i64)>,
    /// The integrator's sampling target, groups/s.
    pub smp: Option<u32>,
    /// [`Timing::Group`]: the runs carry no `dt`.
    pub timing: Timing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Seal {
    pub seq: u64,
    pub from_us: i64,
    pub through_us: i64,
    pub ms: u64,
}

/// `sha256("source:" + source + ":" + instanceId + ":" + seq)`, lowercase hex.
pub(crate) fn idempotency_key(source: &str, instance_id: &str, seq: u64) -> String {
    let d =
        digest::digest(&digest::SHA256, format!("source:{source}:{instance_id}:{seq}").as_bytes());
    hex(d.as_ref())
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn push_frame(out: &mut Vec<u8>, payload: &[u8], raw: bool) {
    let len = payload.len() as u32 | if raw { FRAME_RAW } else { 0 };
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
}

/// The preamble frame's JSON. `em` ranges ascend with a gap between them.
pub(crate) fn preamble_json(instance_id: &str, em: &[(u64, u64)], seal: &Seal) -> String {
    let mut j = Obj::new();
    j.int("v", 2);
    j.str("i", instance_id);
    let ranges: Vec<String> = em.iter().map(|(f, n)| format!("[{f},{n}]")).collect();
    j.raw("em", &format!("[{}]", ranges.join(",")));
    let mut s = Obj::new();
    s.int("seq", seal.seq.into());
    s.int("from_us", seal.from_us.into());
    s.int("through_us", seal.through_us.into());
    s.int("ms", seal.ms.into());
    j.raw("seal", &s.finish());
    j.finish()
}

/// The frames of the fact records, each numbered from `first_rseq`.
pub(crate) fn record_frames(
    records: &[Record],
    base_us: i64,
    first_rseq: u64,
    timing: Timing,
) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, r) in records.iter().enumerate() {
        let rseq = first_rseq + i as u64;
        match r {
            Record::Pev(e) => push_frame(&mut out, pev_json(e, rseq).as_bytes(), false),
            Record::Runs(runs) => {
                push_frame(&mut out, descriptor("run", 2, runs.len(), rseq).as_bytes(), false);
                push_frame(&mut out, &encode_runs(base_us, runs, timing), true);
            }
            Record::Marks(marks) => {
                push_frame(&mut out, descriptor("mark", 1, marks.len(), rseq).as_bytes(), false);
                push_frame(&mut out, &encode_marks(base_us, marks), true);
            }
            Record::Paces(paces) => {
                push_frame(&mut out, descriptor("pace", 1, paces.len(), rseq).as_bytes(), false);
                push_frame(&mut out, &encode_paces(paces), true);
            }
            Record::End(reason) => {
                let mut j = Obj::new();
                j.str("t", "end");
                j.str("reason", reason);
                j.int("rseq", rseq.into());
                push_frame(&mut out, j.finish().as_bytes(), false);
            }
        }
    }
    out
}

/// The frames after the preamble: the batch record, then the records'.
pub(crate) fn frames(batch: &Batch, clk: &Clk, records: &[u8]) -> Vec<u8> {
    let json = batch_json(batch, clk);
    let mut out = Vec::with_capacity(4 + json.len() + records.len());
    push_frame(&mut out, json.as_bytes(), false);
    out.extend_from_slice(records);
    out
}

/// A whole body: header, preamble frame, then the frames, gzipped when asked.
pub(crate) fn body(preamble: &str, frames: &[u8], gzipped: bool) -> Vec<u8> {
    let payload = if gzipped { gzip(frames) } else { frames.to_vec() };
    let mut out = Vec::with_capacity(HEADER_BYTES + 4 + preamble.len() + payload.len());
    out.extend_from_slice(&BODY_MAGIC);
    out.extend_from_slice(&[BODY_VERSION, if gzipped { FLAG_GZIP } else { 0 }, 0, 0]);
    push_frame(&mut out, preamble.as_bytes(), false);
    out.extend_from_slice(&payload);
    out
}

pub(crate) fn gzip(frames: &[u8]) -> Vec<u8> {
    let mut gz = GzEncoder::new(Vec::with_capacity(frames.len() / 2 + 64), Compression::default());
    let _ = gz.write_all(frames);
    gz.finish().unwrap_or_default()
}

fn descriptor(t: &str, v: i64, n: usize, rseq: u64) -> String {
    let mut j = Obj::new();
    j.str("t", t);
    j.int("v", v.into());
    j.int("n", n as i128);
    j.int("rseq", rseq.into());
    j.finish()
}

fn pev_json(e: &PevIn, rseq: u64) -> String {
    let mut j = Obj::new();
    j.str("t", "pev");
    j.int("v", 2);
    j.int("c", e.c.into());
    if let Some(ti) = e.ti {
        j.int("ti", ti as i128);
    }
    j.str("e", e.e.as_str());
    if let Some(code) = e.code {
        j.int("code", code.into());
    }
    j.int("at_us", e.at_us.into());
    j.int("rseq", rseq.into());
    j.finish()
}

fn batch_json(b: &Batch, clk: &Clk) -> String {
    let mut j = Obj::new();
    j.str("t", "source-batch");
    j.int("v", 2);
    j.str("source", &b.source);
    j.str("instanceId", &b.instance_id);
    j.int("seq", b.seq.into());
    j.str("idempotencyKey", &idempotency_key(&b.source, &b.instance_id, b.seq));
    j.bool("final", b.is_final);
    let mut m = Obj::new();
    m.str("name", b.monitor_name);
    m.str("version", b.monitor_version);
    j.raw("monitor", &m.finish());
    j.raw("clk", &clk_json(clk));
    j.raw("tail", &tail_json(&b.tail));
    let conns: Vec<String> = b.conns.iter().map(conn_json).collect();
    j.raw("conn", &format!("[{}]", conns.join(",")));
    let tracks: Vec<String> = b.tracks.iter().enumerate().map(|(i, t)| track_json(i, t)).collect();
    j.raw("trk", &format!("[{}]", tracks.join(",")));
    if !b.gdec.is_empty() {
        let rows: Vec<String> = b.gdec.iter().map(|(c, ti, n)| format!("[{c},{ti},{n}]")).collect();
        j.raw("gdec", &format!("[{}]", rows.join(",")));
    }
    if let Some((mono_us, wall_ms)) = b.start {
        let mut s = Obj::new();
        s.int("mono_us", mono_us.into());
        s.int("wall_ms", wall_ms.into());
        j.raw("start", &s.finish());
    }
    if let Some(t) = b.smp {
        j.raw("smp", &format!("{{\"t\":{t}}}"));
    }
    if b.timing == Timing::Group {
        j.str("timing", "group");
    }
    j.finish()
}

fn clk_json(c: &Clk) -> String {
    let mut j = Obj::new();
    j.int("base_us", c.base_us.into());
    j.int("epoch", c.epoch.into());
    j.int("res_us", c.res_us.into());
    if let Some(s) = &c.sample {
        j.int("o_us", s.o_us.into());
        j.int("r_us", s.r_us.into());
        j.int("at_us", s.at_us.into());
        if let Some(pop) = &s.pop {
            j.str("pop", pop);
        }
    }
    if let Some(app) = c.app {
        let mut a = Obj::new();
        a.int("o_us", app.o_us.into());
        a.int("e_us", app.e_us.into());
        a.int("at_us", app.at_us.into());
        j.raw("app", &a.finish());
    }
    j.finish()
}

fn tail_json(t: &Tail) -> String {
    let mut j = Obj::new();
    if let Some(r) = t.last_rseq {
        j.int("last_rseq", r.into());
    }
    let mut d = Obj::new();
    d.int("records", t.pre_drop_records.into());
    d.int("objects", t.pre_drop_objects.into());
    j.raw("pre_drop", &d.finish());
    let rows: Vec<String> = t.conn.iter().map(|(c, o, b)| format!("[{c},{o},{b}]")).collect();
    j.raw("conn", &format!("[{}]", rows.join(",")));
    j.finish()
}

fn conn_json(c: &ConnRec) -> String {
    let mut j = Obj::new();
    j.int("c", c.c.into());
    if let Some(d) = c.draft {
        j.int("draft", d.into());
    }
    j.str("relay", &c.relay);
    j.finish()
}

/// The gzipped size of a `trk` list of `tracks`, without spans or excluded
/// groups, with names until a body carrying them is accepted.
pub(crate) fn track_list_gz_len(tracks: &[Arc<Track>]) -> usize {
    if tracks.is_empty() {
        return 0;
    }
    let list: Vec<String> = tracks
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let rec = TrackRec {
                ns: t.ns.clone(),
                name: t.name.clone(),
                tk: t.tk,
                named: t.names_needed(),
                k: 0,
                span: None,
                xg: Vec::new(),
            };
            track_json(i, &rec)
        })
        .collect();
    gzip(list.join(",").as_bytes()).len()
}

fn track_json(id: usize, t: &TrackRec) -> String {
    let mut j = Obj::new();
    j.int("id", id as i128);
    if t.named {
        let ns: Vec<String> = t.ns.iter().map(|f| json_string(&base64(f))).collect();
        j.raw("ns", &format!("[{}]", ns.join(",")));
        j.str("name", &base64(&t.name));
    }
    j.str("tk", &format!("{:016x}", t.tk));
    j.int("k", t.k.into());
    if let Some((lo, hi)) = t.span {
        j.raw("span", &format!("[{lo},{hi}]"));
    }
    if !t.xg.is_empty() {
        j.str("xg", &xg_field(&t.xg));
    }
    j.finish()
}

/// The `run` columns: `fl c ti g sk [sub] o0 n [oid…] t0 [dt…] (de… os… | b)`:
/// each object's start, end and size at [`Timing::Object`], the run's first
/// start and its bytes at [`Timing::Group`].
pub(crate) fn encode_runs(base_us: i64, runs: &[RunIn], timing: Timing) -> Vec<u8> {
    let mut w = Leb::default();
    let mut last_g: Vec<(usize, u64)> = Vec::new();
    let mut last_t0 = base_us;
    for r in runs {
        let n = r.ids.len();
        let xid = r.ids.windows(2).any(|p| p[0].checked_add(1) != Some(p[1]));
        w.byte(
            flag(r.cont, FL_CONT)
                | flag(xid, FL_XID)
                | flag(r.fo, FL_FO)
                | FL_FO_KNOWN
                | flag(r.eog, FL_EOG)
                | FL_END_NA
                | flag(r.gs, FL_GS),
        );
        w.u(r.c);
        w.u(r.ti as u64);
        let prev = match last_g.iter_mut().find(|(ti, _)| *ti == r.ti) {
            Some(slot) => std::mem::replace(&mut slot.1, r.g),
            None => {
                last_g.push((r.ti, r.g));
                0
            }
        };
        w.z(r.g, prev);
        match r.sub {
            None => w.u(0),
            Some(s) => {
                w.u(1);
                w.u(s);
            }
        }
        w.u(r.ids[0]);
        w.u(n as u64);
        if xid {
            for p in r.ids.windows(2) {
                match r.sub {
                    None => w.z(p[1], p[0]),
                    Some(_) => w.u(p[1] - p[0] - 1),
                }
            }
        }
        let t0 = r.times[0];
        w.t(t0 - last_t0);
        last_t0 = t0;
        if timing == Timing::Object {
            let q = |t: i64| (t - t0).div_euclid(DT_QUANTUM_US);
            for p in r.times.windows(2) {
                w.t(q(p[1]) - q(p[0]));
            }
            for (&t, &e) in r.times.iter().zip(&r.ends) {
                w.t(q(e) - q(t));
            }
            for &s in &r.sizes {
                w.u(s);
            }
        } else {
            w.u(r.b);
        }
    }
    w.0
}

fn flag(on: bool, bit: u8) -> u8 {
    if on {
        bit
    } else {
        0
    }
}

/// The `mark` columns: `kind c ti g o [n] t`.
pub(crate) fn encode_marks(base_us: i64, marks: &[MarkIn]) -> Vec<u8> {
    let mut w = Leb::default();
    let mut last_t = base_us;
    for m in marks {
        w.u(m.kind as u64);
        w.u(m.c);
        w.u(m.ti as u64);
        w.u(m.g);
        w.u(m.o);
        if m.kind.has_n() {
            w.u(m.n);
        }
        w.t(m.t - last_t);
        last_t = m.t;
    }
    w.0
}

/// The `pace` columns: `c ti first later`, each histogram
/// `u(pairs) [u(key delta) u(count)]…`.
pub(crate) fn encode_paces(paces: &[PaceIn]) -> Vec<u8> {
    let mut w = Leb::default();
    for p in paces {
        w.u(p.c);
        w.u(p.ti as u64);
        for h in [&p.first, &p.later] {
            w.u(h.len() as u64);
            let mut last = None;
            for &(key, count) in h {
                w.u(u64::from(key - last.unwrap_or(0)));
                w.u(count);
                last = Some(key);
            }
        }
    }
    w.0
}

/// A JSON object, keys in the order written.
struct Obj(String);

impl Obj {
    fn new() -> Self {
        Obj(String::from("{"))
    }

    fn key(&mut self, k: &str) {
        if self.0.len() > 1 {
            self.0.push(',');
        }
        self.0.push_str(&json_string(k));
        self.0.push(':');
    }

    fn str(&mut self, k: &str, v: &str) {
        self.key(k);
        self.0.push_str(&json_string(v));
    }

    fn int(&mut self, k: &str, v: i128) {
        self.key(k);
        let _ = write!(self.0, "{v}");
    }

    fn bool(&mut self, k: &str, v: bool) {
        self.key(k);
        self.0.push_str(if v { "true" } else { "false" });
    }

    fn raw(&mut self, k: &str, json: &str) {
        self.key(k);
        self.0.push_str(json);
    }

    fn finish(mut self) -> String {
        self.0.push('}');
        self.0
    }
}

/// A string as `JSON.stringify` writes it.
fn json_string(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| String::from("\"\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leb_and_zigzag_are_minimal() {
        let enc = |f: &dyn Fn(&mut Leb)| {
            let mut w = Leb::default();
            f(&mut w);
            w.0
        };
        assert_eq!(enc(&|w| w.u(0)), [0]);
        assert_eq!(enc(&|w| w.u(127)), [127]);
        assert_eq!(enc(&|w| w.u(128)), [0x80, 1]);
        assert_eq!(enc(&|w| w.u(u64::MAX)).len(), 10);
        assert_eq!(enc(&|w| w.t(-1)), [1]);
        assert_eq!(enc(&|w| w.t(1)), [2]);
        assert_eq!(enc(&|w| w.z(0, u64::MAX)), [2], "a wrapping +1");
        assert_eq!(enc(&|w| w.z(u64::MAX, 0)), [1], "a wrapping -1");
        for v in [0u64, 1, 127, 128, 16_383, 16_384, u64::MAX] {
            assert_eq!(leb_len(v), enc(&|w| w.u(v)).len(), "{v}");
        }
        for v in [0i64, -1, 63, -64, 64, i64::MIN, i64::MAX] {
            assert_eq!(zigzag_len(v), enc(&|w| w.t(v)).len(), "{v}");
        }
    }

    #[test]
    fn base64_is_standard_and_padded() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(&[0xff, 0xfe, 0x00, 0x80]), "//4AgA==");
    }

    #[test]
    fn strings_escape_as_json_stringify_does() {
        assert_eq!(json_string("a\"b\\c\n\u{1}é/"), "\"a\\\"b\\\\c\\n\\u0001é/\"");
    }

    #[test]
    fn idempotency_key_is_sha256_of_the_triple() {
        assert_eq!(
            idempotency_key("enc-fra-1", "5f0c2a9e7b1d4e3fa6c8b0d2e4f6a8c1", 0),
            "998ec06a866c2ca9ec2eefc4e0fdf3ae739d146543a23665b5909ee5eafc2209"
        );
    }
}

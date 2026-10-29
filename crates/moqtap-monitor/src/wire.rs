//! The upload body: an 8-byte preamble, then length-prefixed JSON frames,
//! gzipped as one unit.
//!
//! The JSON is written by hand so that a body is byte-for-byte what the
//! ingest's reference writer produces for the same input: keys in a fixed
//! order, and numbers in ECMAScript's `Number.prototype.toString` form.

use std::fmt::Write as _;
use std::io::Write as _;

use flate2::write::GzEncoder;
use flate2::Compression;
use ring::digest;

/// Rows one `grp` or `obj` record may hold.
pub(crate) const MAX_COLUMN_ROWS: usize = 512;
/// Tracks one body may declare.
pub(crate) const MAX_BODY_TRACKS: usize = 256;
/// Relays one body may declare.
pub(crate) const MAX_BODY_RELAYS: usize = 32;
/// `grp` rows one body may hold.
pub(crate) const MAX_BODY_GROUP_ROWS: usize = 50_000;
/// The byte seal: a body is sealed before its gzipped frames pass this.
pub(crate) const SEAL_BYTES: usize = 32 * 1024;
/// The ingest edge refuses a body larger than this, preamble included.
pub(crate) const EDGE_CAP_BYTES: usize = 96 * 1024;
/// Highest body-local relay number.
pub(crate) const MAX_RELAY_C: usize = 255;
/// Highest body-local track id.
pub(crate) const MAX_TRACK_ID: usize = 65_535;
/// Seqs one body may list as lost.
pub(crate) const MAX_LOST_SEQS: usize = 256;
/// The largest MoQT group or object id: a QUIC varint.
pub(crate) const MAX_MOQT_ID: u64 = (1 << 62) - 1;
/// The largest integer a JSON number carries exactly.
pub(crate) const MAX_SAFE_INTEGER: i64 = (1 << 53) - 1;

const BODY_MAGIC: [u8; 4] = *b"MQTC";
const BODY_VERSION: u8 = 1;
const FLAG_GZIP: u8 = 0x01;
pub(crate) const PREAMBLE_BYTES: usize = 8;

/// How integer column elements are written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IdForm {
    /// A JSON number while exactly representable, else a decimal string.
    Auto,
    /// Always a decimal string.
    #[cfg_attr(not(test), allow(dead_code))]
    String,
}

/// The device's clock against the server's, as a body was sealed.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Clock {
    /// Offset `server - device`, ms.
    pub o: f64,
    /// Round trip of the sample `o` came from, ms.
    pub r: f64,
    /// Samples in the window.
    pub n: u64,
    /// That sample's age when the body was sealed, s.
    pub a: f64,
}

/// The fields of a `source-batch` record.
#[derive(Clone, Debug)]
pub(crate) struct Head<'a> {
    pub ts: u64,
    pub wall: u64,
    pub per_object: bool,
    pub source: &'a str,
    pub instance_id: &'a str,
    pub seq: u64,
    pub is_final: bool,
    pub lost: &'a [u64],
    pub dropped: u64,
    pub clock: Option<Clock>,
    pub monitor_name: &'a str,
    pub monitor_version: &'a str,
}

#[derive(Clone, Debug)]
pub(crate) struct RelayRec<'a> {
    pub c: usize,
    pub relay: &'a str,
    pub draft: Option<u64>,
    pub open_ts: Option<u64>,
    pub close_ts: Option<u64>,
    pub close_code: Option<u64>,
}

#[derive(Clone, Debug)]
pub(crate) struct TrackRec<'a> {
    pub id: usize,
    pub ns: &'a [String],
    pub name: &'a str,
    pub k: u8,
}

/// One `grp` row. Times are device wall µs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GrpRow {
    pub c: usize,
    pub tr: usize,
    pub g: u64,
    pub fo: u64,
    pub send_us: i64,
    pub span_us: i64,
    pub objects: u64,
    pub bytes: u64,
}

/// One `obj` row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ObjRow {
    pub c: usize,
    pub tr: usize,
    pub g: u64,
    pub o: u64,
    pub bytes: u64,
    pub send_us: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EventKind {
    StreamReset,
    RequestError,
    PublishDone,
}

impl EventKind {
    fn as_str(self) -> &'static str {
        match self {
            EventKind::StreamReset => "stream_reset",
            EventKind::RequestError => "request_error",
            EventKind::PublishDone => "publish_done",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PevRec {
    pub ts: u64,
    pub c: usize,
    pub tr: Option<usize>,
    pub e: EventKind,
    pub code: Option<u64>,
}

/// A columnar record, in body order.
#[derive(Clone, Debug)]
pub(crate) enum DataRec {
    Grp(Vec<GrpRow>, IdForm),
    Obj(Vec<ObjRow>, IdForm),
}

/// Everything one body holds.
#[derive(Clone, Debug)]
pub(crate) struct BodySpec<'a> {
    pub head: Head<'a>,
    pub relays: Vec<RelayRec<'a>>,
    pub tracks: Vec<TrackRec<'a>>,
    pub data: Vec<DataRec>,
    pub events: Vec<PevRec>,
    pub end: Option<&'a str>,
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

/// The frame stream of a body: what gets gzipped behind the preamble.
pub(crate) fn encode_frames(spec: &BodySpec<'_>) -> Vec<u8> {
    let mut frames = Vec::new();
    let mut push = |json: String| {
        let len = u32::try_from(json.len()).unwrap_or(u32::MAX) & 0x7fff_ffff;
        frames.extend_from_slice(&len.to_be_bytes());
        frames.extend_from_slice(json.as_bytes());
    };
    push(batch_json(&spec.head));
    for r in &spec.relays {
        push(relay_json(r));
    }
    for t in &spec.tracks {
        push(track_json(t));
    }
    for d in &spec.data {
        match d {
            DataRec::Grp(rows, form) => push(grp_json(rows, *form)),
            DataRec::Obj(rows, form) => push(obj_json(rows, *form)),
        }
    }
    for e in &spec.events {
        push(pev_json(e));
    }
    if let Some(reason) = spec.end {
        let mut o = Obj::new();
        o.str("t", "end");
        o.str("reason", reason);
        push(o.finish());
    }
    frames
}

pub(crate) fn gzip(frames: &[u8]) -> Vec<u8> {
    let mut enc = GzEncoder::new(Vec::with_capacity(frames.len() / 3), Compression::default());
    // Writing into a Vec cannot fail.
    let _ = enc.write_all(frames);
    enc.finish().unwrap_or_default()
}

/// A whole body: the preamble, then the gzipped frames.
pub(crate) fn encode_body(gzipped: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(PREAMBLE_BYTES + gzipped.len());
    out.extend_from_slice(&BODY_MAGIC);
    out.extend_from_slice(&[BODY_VERSION, FLAG_GZIP, 0, 0]);
    out.extend_from_slice(gzipped);
    out
}

fn batch_json(h: &Head<'_>) -> String {
    let mut o = Obj::new();
    o.str("t", "source-batch");
    o.int("v", 1);
    o.int("ts", h.ts as i128);
    o.int("wall", h.wall as i128);
    o.str("lvl", if h.per_object { "headers+sizes" } else { "baseline" });
    o.str("source", h.source);
    o.str("instanceId", h.instance_id);
    o.int("seq", h.seq as i128);
    o.str("idempotencyKey", &idempotency_key(h.source, h.instance_id, h.seq));
    o.bool("final", h.is_final);
    let mut lost = String::from("[");
    for (i, s) in h.lost.iter().enumerate() {
        if i > 0 {
            lost.push(',');
        }
        let _ = write!(lost, "{s}");
    }
    lost.push(']');
    o.raw("lost", &lost);
    o.int("dropped", h.dropped as i128);
    if let Some(c) = h.clock {
        let mut clock = Obj::new();
        clock.num("o", c.o);
        clock.num("r", c.r);
        clock.int("n", c.n as i128);
        clock.num("a", c.a);
        o.raw("clock", &clock.finish());
    }
    let mut m = Obj::new();
    m.str("name", h.monitor_name);
    m.str("version", h.monitor_version);
    o.raw("monitor", &m.finish());
    o.finish()
}

fn relay_json(r: &RelayRec<'_>) -> String {
    let mut o = Obj::new();
    o.str("t", "relay");
    o.int("c", r.c as i128);
    o.str("relay", r.relay);
    for (k, v) in [
        ("draft", r.draft),
        ("openTs", r.open_ts),
        ("closeTs", r.close_ts),
        ("closeCode", r.close_code),
    ] {
        if let Some(v) = v {
            o.int(k, v as i128);
        }
    }
    o.finish()
}

fn track_json(t: &TrackRec<'_>) -> String {
    let mut o = Obj::new();
    o.str("t", "track");
    o.int("id", t.id as i128);
    let mut ns = String::from("[");
    for (i, f) in t.ns.iter().enumerate() {
        if i > 0 {
            ns.push(',');
        }
        push_str(&mut ns, f);
    }
    ns.push(']');
    o.raw("ns", &ns);
    o.str("name", t.name);
    o.int("k", t.k as i128);
    o.finish()
}

fn pev_json(e: &PevRec) -> String {
    let mut o = Obj::new();
    o.str("t", "pev");
    o.int("ts", e.ts as i128);
    o.int("c", e.c as i128);
    if let Some(tr) = e.tr {
        o.int("tr", tr as i128);
    }
    o.str("e", e.e.as_str());
    if let Some(code) = e.code {
        o.int("code", code as i128);
    }
    o.finish()
}

/// `g` is absolute on a (c, tr) pair's first row, then a delta from that
/// pair's previous row; `t0` is a delta from the previous row, the first from
/// `base`; `fo` is omitted when every value is 0.
fn grp_json(rows: &[GrpRow], form: IdForm) -> String {
    let base = rows.first().map_or(0, |r| r.send_us);
    let mut cols: [Col; 8] = Default::default();
    let mut last = Vec::<((usize, usize), u64)>::new();
    let mut prev_send = base;
    for r in rows {
        let prev = pair_last(&mut last, (r.c, r.tr), r.g);
        cols[0].int(r.c as i128);
        cols[1].int(r.tr as i128);
        cols[2].id(prev.map_or(r.g as i128, |p| r.g as i128 - p as i128), form);
        cols[3].id(r.fo as i128, form);
        cols[4].int(r.send_us as i128 - prev_send as i128);
        prev_send = r.send_us;
        cols[5].int(r.span_us as i128);
        cols[6].int(r.objects as i128);
        cols[7].int(r.bytes as i128);
    }
    let with_fo = rows.iter().any(|r| r.fo != 0);
    let names = ["c", "tr", "g", "fo", "t0", "d", "n", "b"];
    let mut c = Obj::new();
    for (name, col) in names.iter().zip(cols) {
        if *name == "fo" && !with_fo {
            continue;
        }
        c.raw(name, &col.finish());
    }
    let mut o = Obj::new();
    o.str("t", "grp");
    o.int("v", 1);
    o.int("base", base as i128);
    o.raw("cols", &c.finish());
    o.finish()
}

/// `g` as in `grp`; `o` is absolute on a pair's first row and whenever its
/// group changes, else a delta from the pair's previous object; `at` as `t0`.
fn obj_json(rows: &[ObjRow], form: IdForm) -> String {
    let base = rows.first().map_or(0, |r| r.send_us);
    let mut cols: [Col; 6] = Default::default();
    let mut last = Vec::<((usize, usize), (u64, u64))>::new();
    let mut prev_send = base;
    for r in rows {
        let key = (r.c, r.tr);
        let prev = match last.iter_mut().find(|(k, _)| *k == key) {
            Some((_, v)) => Some(std::mem::replace(v, (r.g, r.o))),
            None => {
                last.push((key, (r.g, r.o)));
                None
            }
        };
        cols[0].int(r.c as i128);
        cols[1].int(r.tr as i128);
        cols[2].id(prev.map_or(r.g as i128, |(g, _)| r.g as i128 - g as i128), form);
        let o = match prev {
            Some((g, o)) if g == r.g => r.o as i128 - o as i128,
            _ => r.o as i128,
        };
        cols[3].id(o, form);
        cols[4].int(r.bytes as i128);
        cols[5].int(r.send_us as i128 - prev_send as i128);
        prev_send = r.send_us;
    }
    let mut c = Obj::new();
    for (name, col) in ["c", "tr", "g", "o", "s", "at"].iter().zip(cols) {
        c.raw(name, &col.finish());
    }
    let mut o = Obj::new();
    o.str("t", "obj");
    o.int("v", 1);
    o.int("base", base as i128);
    o.raw("cols", &c.finish());
    o.finish()
}

fn pair_last(last: &mut Vec<((usize, usize), u64)>, key: (usize, usize), g: u64) -> Option<u64> {
    match last.iter_mut().find(|(k, _)| *k == key) {
        Some((_, v)) => Some(std::mem::replace(v, g)),
        None => {
            last.push((key, g));
            None
        }
    }
}

#[derive(Default)]
struct Col(String);

impl Col {
    fn sep(&mut self) {
        self.0.push(if self.0.is_empty() { '[' } else { ',' });
    }
    fn int(&mut self, v: i128) {
        self.sep();
        let _ = write!(self.0, "{v}");
    }
    fn id(&mut self, v: i128, form: IdForm) {
        self.sep();
        let safe = (-(MAX_SAFE_INTEGER as i128)..=MAX_SAFE_INTEGER as i128).contains(&v);
        if form == IdForm::Auto && safe {
            let _ = write!(self.0, "{v}");
        } else {
            let _ = write!(self.0, "\"{v}\"");
        }
    }
    fn finish(mut self) -> String {
        if self.0.is_empty() {
            self.0.push('[');
        }
        self.0.push(']');
        self.0
    }
}

struct Obj(String);

impl Obj {
    fn new() -> Self {
        Obj(String::from("{"))
    }
    fn key(&mut self, k: &str) {
        if self.0.len() > 1 {
            self.0.push(',');
        }
        push_str(&mut self.0, k);
        self.0.push(':');
    }
    fn str(&mut self, k: &str, v: &str) {
        self.key(k);
        push_str(&mut self.0, v);
    }
    fn int(&mut self, k: &str, v: i128) {
        self.key(k);
        let _ = write!(self.0, "{v}");
    }
    fn num(&mut self, k: &str, v: f64) {
        self.key(k);
        self.0.push_str(&js_number(v));
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

/// A JSON string as `JSON.stringify` writes it.
fn push_str(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// A finite number as ECMAScript prints it. Rust's `Display` already gives the
/// shortest round-trip digits; ECMAScript differs only in switching to
/// exponent form outside `[1e-6, 1e21)` and in printing `-0` as `0`.
pub(crate) fn js_number(v: f64) -> String {
    if !v.is_finite() {
        return "null".to_string();
    }
    if v == 0.0 {
        return "0".to_string();
    }
    let a = v.abs();
    if (1e-6..1e21).contains(&a) {
        return format!("{v}");
    }
    let s = format!("{v:e}");
    match s.split_once('e') {
        Some((m, e)) if !e.starts_with('-') => format!("{m}e+{e}"),
        _ => s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_print_as_ecmascript_does() {
        for (v, js) in [
            (18.0, "18"),
            (-41.5, "-41.5"),
            (-0.0, "0"),
            (0.1 + 0.2, "0.30000000000000004"),
            (1e21, "1e+21"),
            (1.5e-7, "1.5e-7"),
            (123456789012.345, "123456789012.345"),
            (0.000001, "0.000001"),
        ] {
            assert_eq!(js_number(v), js, "{v}");
        }
    }

    #[test]
    fn strings_escape_as_json_stringify_does() {
        let mut s = String::new();
        push_str(&mut s, "a\"b\\c\n\u{1}\u{7f}é\u{2028}");
        assert_eq!(s, "\"a\\\"b\\\\c\\n\\u0001\u{7f}é\u{2028}\"");
    }

    #[test]
    fn ids_past_two_to_the_53_become_strings() {
        let mut c = Col::default();
        c.id(MAX_SAFE_INTEGER as i128, IdForm::Auto);
        c.id(MAX_SAFE_INTEGER as i128 + 1, IdForm::Auto);
        c.id(-(MAX_SAFE_INTEGER as i128) - 1, IdForm::Auto);
        c.id(3, IdForm::String);
        assert_eq!(
            c.finish(),
            "[9007199254740991,\"9007199254740992\",\"-9007199254740992\",\"3\"]"
        );
    }

    #[test]
    fn idempotency_key_is_sha256_of_the_triple() {
        // sha256("source:s:i:0")
        let k = idempotency_key("s", "i", 0);
        assert_eq!(k.len(), 64);
        assert_eq!(k, hex(digest::digest(&digest::SHA256, b"source:s:i:0").as_ref()));
    }
}

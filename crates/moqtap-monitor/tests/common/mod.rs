//! A strict reader for uploaded v2 bodies, mirroring the rules ingest
//! applies, and a mock ingest server that records every request.

#![allow(dead_code)]

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Read as _;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use serde_json::Value;

const SAFE: u64 = (1 << 53) - 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conn {
    pub c: u64,
    pub draft: Option<u64>,
    pub relay: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trk {
    pub id: u64,
    /// `ns` and `name` were sent; otherwise both are empty and `tk` alone
    /// names the track.
    pub named: bool,
    pub ns: Vec<Vec<u8>>,
    pub name: Vec<u8>,
    pub tk: u64,
    pub k: u64,
    pub span: Option<(i64, i64)>,
    pub xg: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Run {
    pub cont: bool,
    pub fo: bool,
    pub eog: bool,
    pub gs: bool,
    pub c: u64,
    pub ti: u64,
    pub g: u64,
    pub sub: Option<u64>,
    pub ids: Vec<u64>,
    pub t0: i64,
    /// Offsets from `t0`, in 100 µs.
    pub q: Vec<i64>,
    /// Each object's end from its start, in 100 µs; none at group timing.
    pub de: Vec<i64>,
    /// Each object's payload bytes; none at group timing.
    pub os: Vec<u64>,
    pub b: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mark {
    pub kind: u64,
    pub c: u64,
    pub ti: u64,
    pub g: u64,
    pub o: u64,
    pub n: Option<u64>,
    pub t: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pace {
    pub c: u64,
    pub ti: u64,
    pub first: Vec<(u64, u64)>,
    pub later: Vec<(u64, u64)>,
}

#[derive(Debug, Clone)]
pub struct Body {
    pub preamble: Value,
    pub batch: Value,
    pub gz_bytes: usize,
    pub conns: Vec<Conn>,
    pub tracks: Vec<Trk>,
    pub runs: Vec<Run>,
    pub marks: Vec<Mark>,
    pub paces: Vec<Pace>,
    pub events: Vec<Value>,
    pub end: Option<String>,
    pub rseqs: Vec<u64>,
}

impl Body {
    pub fn seq(&self) -> u64 {
        self.batch["seq"].as_u64().unwrap()
    }

    pub fn track(&self, ti: u64) -> &Trk {
        self.tracks.iter().find(|t| t.id == ti).expect("declared")
    }

    pub fn relay(&self, c: u64) -> &str {
        &self.conns.iter().find(|x| x.c == c).expect("declared").relay
    }
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, bytes).as_ref().to_vec()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn track_key(ns: &[Vec<u8>], name: &[u8]) -> u64 {
    let mut c = (ns.len() as u32).to_be_bytes().to_vec();
    for p in ns.iter().map(Vec::as_slice).chain([name]) {
        c.extend_from_slice(&(p.len() as u32).to_be_bytes());
        c.extend_from_slice(p);
    }
    u64::from_be_bytes(sha256(&c)[..8].try_into().unwrap())
}

type R<T> = Result<T, String>;

macro_rules! fail {
    ($($t:tt)*) => { return Err(format!($($t)*)) };
}

fn obj(v: &Value) -> R<&serde_json::Map<String, Value>> {
    v.as_object().ok_or_else(|| format!("not an object: {v}"))
}

fn count(v: &Value, what: &str) -> R<u64> {
    match v.as_u64() {
        Some(n) if n <= SAFE => Ok(n),
        _ => Err(format!("{what} is not a count: {v}")),
    }
}

fn int(v: &Value, what: &str) -> R<i64> {
    match v.as_i64() {
        Some(n) if n.unsigned_abs() <= SAFE => Ok(n),
        _ => Err(format!("{what} is not a safe integer: {v}")),
    }
}

fn base64(s: &Value) -> R<Vec<u8>> {
    const A: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let s = s.as_str().ok_or("base64 is not a string")?;
    if s.len() % 4 != 0 {
        fail!("base64 length");
    }
    let mut out = Vec::new();
    for chunk in s.as_bytes().chunks(4) {
        let mut n = 0u32;
        let mut pad = 0;
        for &c in chunk {
            n <<= 6;
            if c == b'=' {
                pad += 1;
            } else if pad > 0 {
                fail!("base64 padding");
            } else {
                n |= A.find(c as char).ok_or("base64 alphabet")? as u32;
            }
        }
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        out.extend_from_slice(&bytes[..3 - pad]);
    }
    let canon: String = {
        let mut t = String::new();
        for c in out.chunks(3) {
            let n = u32::from(c[0]) << 16
                | u32::from(*c.get(1).unwrap_or(&0)) << 8
                | u32::from(*c.get(2).unwrap_or(&0));
            for i in 0..4 {
                t.push(if i > c.len() {
                    '='
                } else {
                    A.as_bytes()[(n >> (18 - 6 * i)) as usize & 63] as char
                });
            }
        }
        t
    };
    if canon != s {
        fail!("base64 is not canonical");
    }
    Ok(out)
}

struct Leb<'a> {
    b: &'a [u8],
    at: usize,
}

impl Leb<'_> {
    fn done(&self) -> bool {
        self.at >= self.b.len()
    }

    fn byte(&mut self) -> R<u8> {
        let v = *self.b.get(self.at).ok_or("truncated column")?;
        self.at += 1;
        Ok(v)
    }

    fn u64(&mut self) -> R<u64> {
        let mut v = 0u64;
        for i in 0..10 {
            let b = self.byte()?;
            if i == 9 && b > 1 {
                fail!("LEB128 past a u64");
            }
            v |= u64::from(b & 0x7f) << (7 * i);
            if b & 0x80 == 0 {
                if b == 0 && i > 0 {
                    fail!("non-minimal LEB128");
                }
                return Ok(v);
            }
        }
        fail!("LEB128 too long")
    }

    fn u(&mut self) -> R<u64> {
        let v = self.u64()?;
        if v > SAFE {
            fail!("LEB128 past a safe integer");
        }
        Ok(v)
    }

    fn t(&mut self) -> R<i64> {
        let z = self.u64()?;
        let v = ((z >> 1) as i64) ^ -((z & 1) as i64);
        if v.unsigned_abs() > SAFE {
            fail!("t past a safe integer");
        }
        Ok(v)
    }

    fn z(&mut self, from: u64) -> R<u64> {
        let z = self.u64()?;
        let d = ((z >> 1) as i64) ^ -((z & 1) as i64);
        Ok(from.wrapping_add(d as u64))
    }
}

/// The drafts each mark kind exists in, by wire index.
fn mark_drafts(kind: u64) -> Option<(u64, u64)> {
    Some(match kind {
        0 => (7, 23),
        1 => (8, 23),
        2 => (7, 10),
        3 => (7, 7),
        4 => (7, 15),
        5 | 6 => (16, 23),
        7 => (20, 23),
        8 => (11, 23),
        9 => (14, 23),
        10 => (7, 23),
        11 => (23, 23),
        _ => return None,
    })
}

fn is_range(kind: u64) -> bool {
    matches!(kind, 5..=7 | 11)
}

fn frames(b: &[u8]) -> R<Vec<(bool, Vec<u8>)>> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < b.len() {
        if b.len() - at < 4 {
            fail!("truncated frame header");
        }
        let p = u32::from_be_bytes(b[at..at + 4].try_into().unwrap());
        let len = (p & 0x7fff_ffff) as usize;
        at += 4;
        if b.len() - at < len {
            fail!("truncated frame");
        }
        out.push((p & 0x8000_0000 != 0, b[at..at + len].to_vec()));
        at += len;
    }
    Ok(out)
}

/// Read a whole body as ingest does; `Err` with the reason it would refuse.
pub fn try_read_body(body: &[u8], source: &str) -> R<Body> {
    if body.len() < 12 || &body[..4] != b"MQTC" || body[4] != 2 {
        fail!("not a v2 body");
    }
    let p = u32::from_be_bytes(body[8..12].try_into().unwrap());
    if p & 0x8000_0000 != 0 {
        fail!("raw preamble");
    }
    let plen = p as usize;
    let pre_bytes = body.get(12..12 + plen).ok_or("truncated preamble")?;
    let preamble: Value = serde_json::from_slice(pre_bytes).map_err(|_| "preamble JSON")?;
    let instance = preamble["i"].as_str().ok_or("preamble i")?.to_string();
    let valid_claim = (1..=128).contains(&instance.len())
        && instance.bytes().all(|b| b.is_ascii_alphanumeric() || b".:_-".contains(&b));
    if preamble["v"] != 2 || !valid_claim {
        fail!("bad preamble");
    }
    let mut em = Vec::new();
    let mut next = 0;
    for r in preamble["em"].as_array().ok_or("em")? {
        let (first, n) = (count(&r[0], "em")?, count(&r[1], "em")?);
        if r.as_array().map(Vec::len) != Some(2)
            || n < 1
            || first < next
            || (!em.is_empty() && first == next)
        {
            fail!("bad preamble: em");
        }
        em.push((first, n));
        next = first + n;
    }
    let seal = obj(&preamble["seal"])?;
    let seq = count(&seal["seq"], "seal.seq")?;
    if int(&seal["through_us"], "through")? < int(&seal["from_us"], "from")?
        || count(&seal["ms"], "ms")? < 1
    {
        fail!("bad preamble: seal");
    }

    let rest = &body[12 + plen..];
    let gz_bytes = rest.len();
    let raw = if body[5] & 1 == 1 {
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(rest).read_to_end(&mut out).map_err(|_| "gzip")?;
        out
    } else {
        rest.to_vec()
    };
    let mut items: Vec<(Value, Vec<Vec<u8>>)> = Vec::new();
    for (is_raw, payload) in frames(&raw)? {
        if is_raw {
            if items.len() < 2 {
                fail!("a raw frame with no record before it");
            }
            items.last_mut().unwrap().1.push(payload);
            continue;
        }
        let v: Value = serde_json::from_slice(&payload).map_err(|_| "record JSON")?;
        obj(&v)?;
        items.push((v, Vec::new()));
    }
    let (batch, _) = items.first().cloned().ok_or("no batch record")?;
    if batch["t"] != "source-batch" {
        fail!("wrong path or no batch record: {}", batch["t"]);
    }
    if batch["v"] != 2 || batch["source"] != source {
        fail!("source mismatch");
    }
    if batch["instanceId"] != instance.as_str() {
        fail!("bad instance id");
    }
    if count(&batch["seq"], "seq")? != seq {
        fail!("seal mismatch");
    }
    let key = hex(&sha256(format!("source:{source}:{instance}:{seq}").as_bytes()));
    if batch["idempotencyKey"] != key.as_str() {
        fail!("bad idempotency key");
    }
    if !batch["final"].is_boolean() || !batch["monitor"]["name"].is_string() {
        fail!("batch fields");
    }
    let clk = obj(&batch["clk"])?;
    int(&clk["base_us"], "base_us")?;
    count(&clk["epoch"], "epoch")?;
    if count(&clk["res_us"], "res_us")? < 1 {
        fail!("res_us");
    }
    let has = ["o_us", "r_us", "at_us"].iter().filter(|f| clk.contains_key(**f)).count();
    if has != 0 && has != 3 {
        fail!("clk sample");
    }
    if has == 3 {
        int(&clk["o_us"], "o_us")?;
        count(&clk["r_us"], "r_us")?;
        int(&clk["at_us"], "at_us")?;
    }
    if let Some(app) = clk.get("app") {
        int(&app["o_us"], "app.o_us")?;
        count(&app["e_us"], "app.e_us")?;
        int(&app["at_us"], "app.at_us")?;
        if obj(app)?.len() != 3 {
            fail!("clk.app");
        }
    }
    if let Some(pop) = clk.get("pop") {
        let p = pop.as_str().ok_or("pop")?;
        if has != 3
            || !(1..=16).contains(&p.len())
            || !p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            fail!("clk.pop");
        }
    }
    let base_us = clk["base_us"].as_i64().unwrap();
    let tail = obj(&batch["tail"])?;
    let last_rseq = tail.get("last_rseq").map(|v| count(v, "last_rseq")).transpose()?;
    count(&tail["pre_drop"]["records"], "pre_drop")?;
    count(&tail["pre_drop"]["objects"], "pre_drop")?;
    for e in tail["conn"].as_array().ok_or("tail.conn")? {
        for i in 0..3 {
            count(&e[i], "tail.conn")?;
        }
    }

    let mut conns = Vec::new();
    let list = batch["conn"].as_array().ok_or("conn")?;
    if list.len() > 32 {
        fail!("too many relays");
    }
    for e in list {
        let c = count(&e["c"], "conn.c")?;
        if c > u64::from(u32::MAX) || conns.iter().any(|x: &Conn| x.c == c) {
            fail!("conn.c");
        }
        let draft = e.get("draft").map(|d| count(d, "draft")).transpose()?;
        if draft.is_some_and(|d| !(1..=65_535).contains(&d)) {
            fail!("conn.draft");
        }
        let relay = e["relay"].as_str().ok_or("relay")?.to_string();
        if !relay.contains("://") {
            fail!("conn.relay");
        }
        conns.push(Conn { c, draft, relay });
    }
    let target = match batch.get("smp") {
        None => None,
        Some(smp) => match count(&smp["t"], "smp.t")? {
            t @ 1..=1_000_000 if obj(smp)?.len() == 1 => Some(t),
            _ => fail!("smp"),
        },
    };
    let mut tracks = Vec::new();
    let list = batch["trk"].as_array().ok_or("trk")?;
    if list.len() > 256 {
        fail!("too many tracks");
    }
    for e in list {
        let id = count(&e["id"], "trk.id")?;
        if id > 65_535 || tracks.iter().any(|t: &Trk| t.id == id) {
            fail!("trk.id");
        }
        let named = match (e.get("ns"), e.get("name")) {
            (Some(_), Some(_)) => true,
            (None, None) => false,
            _ => fail!("half a track name"),
        };
        let (ns, name) = if named {
            (
                e["ns"].as_array().ok_or("ns")?.iter().map(base64).collect::<R<Vec<_>>>()?,
                base64(&e["name"])?,
            )
        } else {
            (Vec::new(), Vec::new())
        };
        if ns.len() > 32 || name.len() + ns.iter().map(Vec::len).sum::<usize>() > 4096 {
            fail!("track name");
        }
        let tk_s = e["tk"].as_str().ok_or("tk")?;
        if tk_s.len() != 16
            || !tk_s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            fail!("tk");
        }
        let tk = u64::from_str_radix(tk_s, 16).unwrap();
        if named && tk != track_key(&ns, &name) {
            fail!("tk does not match the name");
        }
        let k = count(&e["k"], "k")?;
        if k > 20 || (k > 0 && target.is_none()) {
            fail!("k");
        }
        let span = match e.get("span") {
            None => None,
            Some(s) => {
                let (lo, hi) = (int(&s[0], "span")?, int(&s[1], "span")?);
                if lo > hi {
                    fail!("span");
                }
                Some((lo, hi))
            }
        };
        let mut xg = Vec::new();
        if let Some(x) = e.get("xg") {
            if k == 0 {
                fail!("xg at k 0");
            }
            let bytes = base64(x)?;
            if bytes.is_empty() {
                fail!("xg");
            }
            let mut rd = Leb { b: &bytes, at: 0 };
            let mut g = rd.u64()?;
            xg.push(g);
            while !rd.done() {
                g = g.checked_add(rd.u64()?).and_then(|v| v.checked_add(1)).ok_or("xg past u64")?;
                xg.push(g);
            }
        }
        tracks.push(Trk { id, named, ns, name, tk, k, span, xg });
    }
    let has_conn = |c: u64| conns.iter().any(|x| x.c == c);
    let has_track = |t: u64| tracks.iter().any(|x| x.id == t);
    if let Some(g) = batch.get("gdec") {
        for e in g.as_array().ok_or("gdec")? {
            let (c, ti, n) = (count(&e[0], "gdec")?, count(&e[1], "gdec")?, count(&e[2], "gdec")?);
            if !has_conn(c) || !has_track(ti) || n < 1 {
                fail!("gdec");
            }
        }
    }
    if let Some(s) = batch.get("start") {
        int(&s["mono_us"], "start")?;
        int(&s["wall_ms"], "start")?;
    }
    let group = match batch.get("timing").map(Value::as_str) {
        None | Some(Some("object")) => false,
        Some(Some("group")) => true,
        _ => fail!("timing"),
    };

    let mut out = Body {
        preamble: preamble.clone(),
        batch: batch.clone(),
        gz_bytes,
        conns: conns.clone(),
        tracks: tracks.clone(),
        runs: Vec::new(),
        marks: Vec::new(),
        paces: Vec::new(),
        events: Vec::new(),
        end: None,
        rseqs: Vec::new(),
    };
    let draft_of = |c: u64| conns.iter().find(|x| x.c == c).and_then(|x| x.draft);
    for (r, raw) in &items[1..] {
        let t = r["t"].as_str().ok_or("record t")?;
        if t == "batch" || t == "source-batch" {
            fail!("a second batch");
        }
        out.rseqs.push(count(&r["rseq"], "rseq")?);
        match t {
            "run" | "mark" | "pace" => {
                let want_v = if t == "run" { 2 } else { 1 };
                if r["v"] != want_v {
                    fail!("{t}: v");
                }
                let n = count(&r["n"], "n")?;
                if !(1..=65_536).contains(&n) || raw.len() != 1 {
                    fail!("{t}: n or raw frames");
                }
                let mut rd = Leb { b: &raw[0], at: 0 };
                let (mut runs, mut marks) = (Vec::new(), Vec::new());
                for _ in 0..n {
                    match t {
                        "run" => runs.push(read_run(&mut rd, base_us, &runs, group)?),
                        "mark" => marks.push(read_mark(&mut rd, base_us, marks.last())?),
                        _ => out.paces.push(read_pace(&mut rd)?),
                    }
                }
                out.runs.extend(runs);
                out.marks.extend(marks);
                if !rd.done() {
                    fail!("{t}: bytes after its entries");
                }
            }
            "pev" => {
                if r["v"] != 2 || !raw.is_empty() || !has_conn(count(&r["c"], "c")?) {
                    fail!("pev");
                }
                if let Some(ti) = r.get("ti") {
                    if !has_track(count(ti, "ti")?) {
                        fail!("pev ti");
                    }
                }
                let events =
                    ["stream_reset", "request_error", "publish_done", "conn_open", "conn_close"];
                if !events.contains(&r["e"].as_str().unwrap_or("")) {
                    fail!("pev e");
                }
                if let Some(code) = r.get("code") {
                    count(code, "code")?;
                }
                int(&r["at_us"], "at_us")?;
                out.events.push(r.clone());
            }
            "end" => {
                if batch["final"] != true {
                    fail!("end in a body that is not final");
                }
                out.end = Some(r["reason"].as_str().unwrap_or("").to_string());
            }
            "ident" | "stream-end" | "bw" | "conn-open" | "conn-close" => {
                fail!("a viewer record: {t}")
            }
            _ => {}
        }
    }
    for run in &out.runs {
        if !has_conn(run.c) || !has_track(run.ti) {
            fail!("run names an undeclared connection or track");
        }
    }
    for m in &out.marks {
        if !has_conn(m.c) || !has_track(m.ti) {
            fail!("mark names an undeclared connection or track");
        }
        if let Some(d) = draft_of(m.c).filter(|d| (7..=23).contains(d)) {
            let (lo, hi) = mark_drafts(m.kind).ok_or("mark kind")?;
            if d < lo || d > hi {
                fail!("mark {} on draft {d}", m.kind);
            }
        }
    }
    for p in &out.paces {
        if !has_conn(p.c) || !has_track(p.ti) {
            fail!("pace names an undeclared connection or track");
        }
    }
    let mut sorted = out.rseqs.clone();
    sorted.sort_unstable();
    let want: Vec<u64> = em.iter().flat_map(|(f, n)| *f..f + n).collect();
    if sorted != want {
        fail!("rseq mismatch");
    }
    if let Some(top) = sorted.last() {
        if last_rseq.is_none_or(|l| l < *top) {
            fail!("rseq mismatch: tail.last_rseq");
        }
    }
    Ok(out)
}

/// At group timing, `q` holds only the first object's 0, and `de` and `os` are empty.
fn read_run(rd: &mut Leb<'_>, base_us: i64, prev: &[Run], group: bool) -> R<Run> {
    let fl = rd.byte()?;
    let (cont, xid, fo, fo_known, eog, end, gs) = (
        fl & 1 != 0,
        fl & 2 != 0,
        fl & 4 != 0,
        fl & 8 != 0,
        fl & 0x10 != 0,
        (fl >> 5) & 3,
        fl & 0x80 != 0,
    );
    if !fo_known || end != 3 {
        fail!("a source run has fo_known and no stream end");
    }
    let c = rd.u()?;
    let ti = rd.u()?;
    let last_g = prev.iter().rev().find(|r| r.ti == ti).map_or(0, |r| r.g);
    let g = rd.z(last_g)?;
    let sub = match rd.u()? {
        0 => None,
        1 => Some(rd.u64()?),
        sk => fail!("sk {sk}"),
    };
    let o0 = rd.u64()?;
    let n = rd.u()? as usize;
    if n < 1 {
        fail!("n {n}");
    }
    let mut ids = vec![o0];
    if xid {
        let mut gap = false;
        for i in 1..n {
            let p = ids[i - 1];
            let next = match sub {
                None => rd.z(p)?,
                Some(_) => {
                    p.checked_add(rd.u64()?).and_then(|v| v.checked_add(1)).ok_or("past u64")?
                }
            };
            gap |= p.checked_add(1) != Some(next);
            ids.push(next);
        }
        if !gap {
            fail!("xid on consecutive ids");
        }
    } else {
        for i in 1..n as u64 {
            ids.push(o0.checked_add(i).ok_or("object id past u64")?);
        }
    }
    let last_t0 = prev.last().map_or(base_us, |r| r.t0);
    let t0 = last_t0 + rd.t()?;
    let mut q = vec![0i64];
    for _ in 1..if group { 1 } else { n } {
        let d = rd.t()?;
        let next = q.last().unwrap() + d;
        if i32::try_from(next).is_err() {
            fail!("offset past Int32");
        }
        q.push(next);
    }
    let (mut de, mut os, mut b) = (Vec::new(), Vec::new(), 0u64);
    if group {
        b = rd.u()?;
    } else {
        for &qi in &q {
            let d = rd.t()?;
            if i32::try_from(qi + d).is_err() {
                fail!("end past Int32");
            }
            de.push(d);
        }
        for _ in 0..n {
            let s = rd.u()?;
            b = b.checked_add(s).ok_or("bytes past u64")?;
            os.push(s);
        }
    }
    Ok(Run { cont, fo, eog, gs, c, ti, g, sub, ids, t0, q, de, os, b })
}

fn read_mark(rd: &mut Leb<'_>, base_us: i64, prev: Option<&Mark>) -> R<Mark> {
    let kind = rd.u()?;
    mark_drafts(kind).ok_or("mark kind")?;
    let c = rd.u()?;
    let ti = rd.u()?;
    let g = rd.u64()?;
    let o = rd.u64()?;
    if is_range(kind) {
        rd.u64()?;
        rd.u64()?;
    }
    let n = if is_range(kind) || (8..=10).contains(&kind) { Some(rd.u64()?) } else { None };
    let t = prev.map_or(base_us, |m| m.t) + rd.t()?;
    Ok(Mark { kind, c, ti, g, o, n, t })
}

fn read_pace(rd: &mut Leb<'_>) -> R<Pace> {
    let c = rd.u()?;
    let ti = rd.u()?;
    let mut hist = || -> R<Vec<(u64, u64)>> {
        let pairs = rd.u()?;
        let mut out: Vec<(u64, u64)> = Vec::new();
        for i in 0..pairs {
            let d = rd.u()?;
            if i > 0 && d < 1 {
                fail!("hist keys must ascend");
            }
            let key = out.last().map_or(d, |(k, _)| k + d);
            let n = rd.u()?;
            if n < 1 {
                fail!("a zero count");
            }
            out.push((key, n));
        }
        Ok(out)
    };
    let first = hist()?;
    let later = hist()?;
    Ok(Pace { c, ti, first, later })
}

pub fn read_body(body: &[u8], source: &str) -> Body {
    try_read_body(body, source).unwrap_or_else(|e| panic!("refused: {e}"))
}

#[derive(Debug, Clone)]
pub struct Captured {
    pub method: String,
    pub uri: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Captured {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    pub fn is_upload(&self) -> bool {
        self.uri.starts_with("/v1/source")
    }
}

/// A scripted reply to an upload: status, extra headers, body.
#[derive(Debug, Clone)]
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Reply {
    pub fn status(status: u16) -> Self {
        Reply { status, headers: vec![], body: "{\"ok\":true}".into() }
    }
}

#[derive(Default)]
struct MockState {
    captured: Vec<Captured>,
    script: VecDeque<Reply>,
    clock_offset_ms: f64,
    pop: Option<String>,
    /// Never answer the next upload.
    hold: bool,
    /// The clock exchange's reply body, with a 200; none: an empty 204.
    clock_body: Option<String>,
}

#[derive(Clone)]
pub struct Mock {
    pub addr: SocketAddr,
    state: Arc<Mutex<MockState>>,
}

impl Mock {
    pub async fn start() -> Mock {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let state =
            Arc::new(Mutex::new(MockState { pop: Some("FRA".into()), ..Default::default() }));
        let s = Arc::clone(&state);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { return };
                let s = Arc::clone(&s);
                tokio::spawn(async move {
                    let svc = service_fn(move |req| handle(req, Arc::clone(&s)));
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
        Mock { addr, state }
    }

    pub fn endpoint(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Replies for the next uploads; `/v1/clock` is always answered 204.
    pub fn script(&self, replies: impl IntoIterator<Item = Reply>) {
        self.state.lock().unwrap().script.extend(replies);
    }

    /// Take the next upload and never answer it.
    pub fn hold_next(&self) {
        self.state.lock().unwrap().hold = true;
    }

    pub fn set_clock_body(&self, body: &str) {
        self.state.lock().unwrap().clock_body = Some(body.to_string());
    }

    pub fn set_clock_offset_ms(&self, ms: f64) {
        self.state.lock().unwrap().clock_offset_ms = ms;
    }

    pub fn captured(&self) -> Vec<Captured> {
        self.state.lock().unwrap().captured.clone()
    }

    pub fn uploads(&self) -> Vec<Captured> {
        self.captured().into_iter().filter(Captured::is_upload).collect()
    }

    pub fn clocks(&self) -> Vec<Captured> {
        self.captured().into_iter().filter(|c| c.uri == "/v1/clock").collect()
    }

    /// Wait until `n` uploads arrived, or `within` passed.
    pub async fn wait_for(&self, n: usize, within: Duration) -> Vec<Captured> {
        let end = tokio::time::Instant::now() + within;
        loop {
            let c = self.uploads();
            if c.len() >= n || tokio::time::Instant::now() > end {
                return c;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

fn now_ms() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("clock").as_secs_f64()
        * 1000.0
}

async fn handle(
    req: Request<hyper::body::Incoming>,
    state: Arc<Mutex<MockState>>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let (offset, pop) = {
        let s = state.lock().unwrap();
        (s.clock_offset_ms, s.pop.clone())
    };
    let recv = now_ms() + offset;
    let method = req.method().to_string();
    let uri = req.uri().to_string();
    let headers = req
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let body = req.into_body().collect().await.map(|b| b.to_bytes().to_vec()).unwrap_or_default();
    let clock = uri == "/v1/clock";
    let reply = {
        let mut s = state.lock().unwrap();
        s.captured.push(Captured { method, uri, headers, body });
        if !clock && std::mem::take(&mut s.hold) {
            None
        } else if clock {
            Some(match &s.clock_body {
                Some(body) => Reply { status: 200, headers: vec![], body: body.clone() },
                None => Reply { status: 204, headers: vec![], body: String::new() },
            })
        } else {
            Some(s.script.pop_front().unwrap_or(Reply::status(202)))
        }
    };
    let Some(reply) = reply else { return std::future::pending().await };
    let mut resp = Response::builder()
        .status(reply.status)
        .header("x-moqtap-recv-ms", format!("{}", recv.floor()))
        .header("x-moqtap-send-ms", format!("{}", (now_ms() + offset).floor()));
    if let Some(p) = pop {
        resp = resp.header("x-moqtap-pop", p);
    }
    for (k, v) in reply.headers {
        resp = resp.header(k, v);
    }
    Ok(resp.body(Full::new(Bytes::from(reply.body))).expect("response"))
}

/// Track names by `tk`, from the bodies that carried them.
pub fn names(bodies: &[Body]) -> HashMap<u64, (Vec<Vec<u8>>, Vec<u8>)> {
    let mut out = HashMap::new();
    for t in bodies.iter().flat_map(|b| &b.tracks).filter(|t| t.named) {
        out.insert(t.tk, (t.ns.clone(), t.name.clone()));
    }
    out
}

/// Every connection's runs across bodies, as `(relay, track name, group, ids)`.
pub fn published(bodies: &[Body]) -> Vec<(String, Vec<u8>, u64, Vec<u64>)> {
    let names = names(bodies);
    let mut out = Vec::new();
    for b in bodies {
        for r in &b.runs {
            let name = names.get(&b.track(r.ti).tk).expect("a body carried the names").1.clone();
            out.push((b.relay(r.c).to_string(), name, r.g, r.ids.clone()));
        }
    }
    out
}

pub fn unique<T: std::hash::Hash + Eq + Clone>(v: &[T]) -> HashSet<T> {
    v.iter().cloned().collect()
}

pub fn by_c(conns: &[Conn]) -> HashMap<u64, String> {
    conns.iter().map(|c| (c.c, c.relay.clone())).collect()
}

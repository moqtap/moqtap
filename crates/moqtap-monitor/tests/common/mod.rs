//! A strict reader for uploaded bodies, mirroring the rules ingest applies,
//! and a mock ingest server that records every request.

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

#[derive(Debug, Clone)]
pub struct Relay {
    pub c: u64,
    pub relay: String,
    pub open_ts: Option<u64>,
    pub close_ts: Option<u64>,
    pub close_code: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct Track {
    pub id: u64,
    pub ns: Vec<String>,
    pub name: String,
    pub k: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub relay: String,
    pub track: String,
    pub k: u32,
    pub g: u64,
    pub fo: u64,
    pub send_us: i64,
    pub span_us: i64,
    pub n: u64,
    pub b: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Object {
    pub relay: String,
    pub track: String,
    pub g: u64,
    pub o: u64,
    pub s: u64,
    pub at_us: i64,
}

#[derive(Debug, Clone)]
pub struct Body {
    pub batch: Value,
    pub gz_frames: usize,
    pub relays: Vec<Relay>,
    pub tracks: Vec<Track>,
    pub groups: Vec<Group>,
    pub objects: Vec<Object>,
    pub events: Vec<Value>,
    pub end: Option<String>,
}

fn sha256_hex(s: &str) -> String {
    let d = ring::digest::digest(&ring::digest::SHA256, s.as_bytes());
    d.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

fn int(v: &Value) -> i128 {
    match v {
        Value::Number(n) => {
            let i = n.as_i64().expect("integer element");
            assert!(i.unsigned_abs() < (1 << 53), "unsafe integer {i}");
            i128::from(i)
        }
        Value::String(s) => s.parse().expect("decimal string"),
        other => panic!("not an integer element: {other}"),
    }
}

/// An optional field that must be a count: a safe non-negative integer.
fn count(r: &Value, name: &str) -> Option<u64> {
    let v = r.get(name)?;
    let n = v.as_u64().unwrap_or_else(|| panic!("{name} is not a count: {v}"));
    assert!(n < (1 << 53), "{name} past 2^53 - 1: {n}");
    Some(n)
}

fn col(cols: &Value, name: &str, len: usize) -> Vec<i128> {
    let a = cols[name].as_array().unwrap_or_else(|| panic!("column {name}"));
    assert_eq!(a.len(), len, "column {name} length");
    a.iter().map(int).collect()
}

/// Read a whole body as ingest does, panicking on anything it would refuse.
pub fn read_body(body: &[u8], source: &str) -> Body {
    assert_eq!(&body[..4], b"MQTC", "magic");
    assert_eq!(body[4], 1, "version");
    assert!(body.len() <= 96 * 1024, "past the edge cap");
    let gz = &body[8..];
    let frames = if body[5] & 1 == 1 {
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(gz).read_to_end(&mut out).expect("gzip");
        out
    } else {
        gz.to_vec()
    };
    let mut records = Vec::new();
    let mut i = 0;
    while i < frames.len() {
        let prefix = u32::from_be_bytes(frames[i..i + 4].try_into().expect("prefix"));
        assert_eq!(prefix & 0x8000_0000, 0, "raw frame");
        let len = prefix as usize;
        let rec: Value = serde_json::from_slice(&frames[i + 4..i + 4 + len]).expect("JSON record");
        records.push(rec);
        i += 4 + len;
    }
    assert_eq!(i, frames.len(), "truncated frame");

    let batch = records[0].clone();
    assert_eq!(batch["t"], "source-batch");
    assert_eq!(batch["v"], 1);
    assert_eq!(batch["source"], source);
    let instance = batch["instanceId"].as_str().expect("instanceId");
    assert!(
        instance.len() == 32
            && instance.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    let seq = batch["seq"].as_u64().expect("seq");
    assert_eq!(batch["idempotencyKey"], sha256_hex(&format!("source:{source}:{instance}:{seq}")));
    assert!(batch["lost"].as_array().expect("lost").len() <= 256);
    assert!(batch["dropped"].is_u64());
    assert!(batch["final"].is_boolean());
    assert_eq!(batch["monitor"]["name"], "moqtap-monitor");
    let lvl = batch["lvl"].as_str().expect("lvl");
    assert!(lvl == "baseline" || lvl == "headers+sizes");

    let mut relays: HashMap<u64, Relay> = HashMap::new();
    let mut tracks: HashMap<u64, Track> = HashMap::new();
    let mut names = HashMap::<(Vec<String>, String), u32>::new();
    let mut out = Body {
        batch: batch.clone(),
        gz_frames: gz.len(),
        relays: vec![],
        tracks: vec![],
        groups: vec![],
        objects: vec![],
        events: vec![],
        end: None,
    };
    let mut seen = HashSet::new();
    for r in &records[1..] {
        assert!(out.end.is_none(), "record after end");
        match r["t"].as_str().expect("t") {
            "relay" => {
                let c = r["c"].as_u64().expect("c");
                assert!(c <= 255);
                let relay = Relay {
                    c,
                    relay: r["relay"].as_str().expect("relay").to_string(),
                    open_ts: r["openTs"].as_u64(),
                    close_ts: r["closeTs"].as_u64(),
                    close_code: count(r, "closeCode"),
                };
                count(r, "draft");
                assert!(relays.insert(c, relay.clone()).is_none(), "c twice");
                assert!(relays.len() <= 32, "too many relays");
                out.relays.push(relay);
            }
            "track" => {
                let id = r["id"].as_u64().expect("id");
                assert!(id <= 65_535);
                let ns: Vec<String> = r["ns"]
                    .as_array()
                    .expect("ns")
                    .iter()
                    .map(|f| f.as_str().expect("ns field").to_string())
                    .collect();
                let name = r["name"].as_str().expect("name").to_string();
                let k = r["k"].as_u64().expect("k") as u32;
                assert!(k <= 20);
                let prior = names.insert((ns.clone(), name.clone()), k);
                assert!(prior.is_none() || prior == Some(k), "a track with two k in one body");
                let t = Track { id, ns, name, k };
                assert!(tracks.insert(id, t.clone()).is_none(), "id twice");
                assert!(tracks.len() <= 256, "too many tracks");
                out.tracks.push(t);
            }
            "grp" => {
                assert_eq!(r["v"], 1);
                let cols = &r["cols"];
                let len = cols["c"].as_array().expect("c").len();
                assert!((1..=512).contains(&len), "rows in one record");
                let (c, tr, g, t0, d, n, b) = (
                    col(cols, "c", len),
                    col(cols, "tr", len),
                    col(cols, "g", len),
                    col(cols, "t0", len),
                    col(cols, "d", len),
                    col(cols, "n", len),
                    col(cols, "b", len),
                );
                let fo = if cols.get("fo").is_some() { col(cols, "fo", len) } else { vec![0; len] };
                let mut last = HashMap::new();
                let mut send = int(&r["base"]);
                for i in 0..len {
                    let relay = &relays[&(c[i] as u64)];
                    let track = &tracks[&(tr[i] as u64)];
                    let key = (c[i], tr[i]);
                    let group = last.get(&key).map_or(g[i], |p| p + g[i]);
                    last.insert(key, group);
                    assert!((0..(1i128 << 62)).contains(&group));
                    send += t0[i];
                    assert!(d[i] >= 0 && n[i] >= 1 && b[i] >= 0);
                    assert_eq!(group % (1i128 << track.k), 0, "bad sample");
                    assert!(seen.insert((c[i], tr[i], group)), "group twice in one body");
                    out.groups.push(Group {
                        relay: relay.relay.clone(),
                        track: track.name.clone(),
                        k: track.k,
                        g: group as u64,
                        fo: fo[i] as u64,
                        send_us: send as i64,
                        span_us: d[i] as i64,
                        n: n[i] as u64,
                        b: b[i] as u64,
                    });
                }
                assert!(out.groups.len() <= 50_000);
            }
            "obj" => {
                assert_eq!(lvl, "headers+sizes", "obj in a baseline body");
                let cols = &r["cols"];
                let len = cols["c"].as_array().expect("c").len();
                assert!((1..=512).contains(&len));
                let (c, tr, g, o, s, at) = (
                    col(cols, "c", len),
                    col(cols, "tr", len),
                    col(cols, "g", len),
                    col(cols, "o", len),
                    col(cols, "s", len),
                    col(cols, "at", len),
                );
                let mut last: HashMap<(i128, i128), (i128, i128)> = HashMap::new();
                let mut send = int(&r["base"]);
                for i in 0..len {
                    let relay = &relays[&(c[i] as u64)];
                    let track = &tracks[&(tr[i] as u64)];
                    let key = (c[i], tr[i]);
                    let prev = last.get(&key).copied();
                    let group = prev.map_or(g[i], |(pg, _)| pg + g[i]);
                    let object = match prev {
                        Some((pg, po)) if pg == group => po + o[i],
                        _ => o[i],
                    };
                    last.insert(key, (group, object));
                    send += at[i];
                    out.objects.push(Object {
                        relay: relay.relay.clone(),
                        track: track.name.clone(),
                        g: group as u64,
                        o: object as u64,
                        s: s[i] as u64,
                        at_us: send as i64,
                    });
                }
            }
            "pev" => {
                assert!(relays.contains_key(&r["c"].as_u64().expect("c")));
                if let Some(tr) = r.get("tr") {
                    assert!(tracks.contains_key(&tr.as_u64().expect("tr")));
                }
                count(r, "code");
                out.events.push(r.clone());
            }
            "end" => {
                assert_eq!(batch["final"], true, "end in a body that is not final");
                out.end = Some(r["reason"].as_str().expect("reason").to_string());
            }
            other => panic!("unexpected record {other}"),
        }
    }
    out
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
}

/// A scripted reply: status, extra headers.
#[derive(Debug, Clone)]
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
}

impl Reply {
    pub fn status(status: u16) -> Self {
        Reply { status, headers: vec![] }
    }
}

#[derive(Default)]
struct MockState {
    captured: Vec<Captured>,
    script: VecDeque<Reply>,
    clock_offset_ms: f64,
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
        let state = Arc::new(Mutex::new(MockState::default()));
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

    pub fn script(&self, replies: impl IntoIterator<Item = Reply>) {
        self.state.lock().unwrap().script.extend(replies);
    }

    pub fn set_clock_offset_ms(&self, ms: f64) {
        self.state.lock().unwrap().clock_offset_ms = ms;
    }

    pub fn captured(&self) -> Vec<Captured> {
        self.state.lock().unwrap().captured.clone()
    }

    pub async fn wait_for(&self, n: usize, within: Duration) -> Vec<Captured> {
        let end = tokio::time::Instant::now() + within;
        loop {
            let c = self.captured();
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
    let offset = state.lock().unwrap().clock_offset_ms;
    let recv = now_ms() + offset;
    let method = req.method().to_string();
    let uri = req.uri().to_string();
    let headers = req
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let body = req.into_body().collect().await.map(|b| b.to_bytes().to_vec()).unwrap_or_default();
    let reply = {
        let mut s = state.lock().unwrap();
        s.captured.push(Captured { method, uri, headers, body });
        s.script.pop_front().unwrap_or(Reply::status(202))
    };
    let mut resp = Response::builder()
        .status(reply.status)
        .header("x-moqtap-recv-ms", format!("{}", recv.round()))
        .header("x-moqtap-send-ms", format!("{}", (now_ms() + offset).round()));
    for (k, v) in reply.headers {
        resp = resp.header(k, v);
    }
    Ok(resp.body(Full::new(Bytes::from_static(b"{\"ok\":true}"))).expect("response"))
}

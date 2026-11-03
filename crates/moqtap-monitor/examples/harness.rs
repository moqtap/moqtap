//! The upload kit's harness: drives the monitor on a manual clock from JSON
//! Lines commands on stdin, one reply per line on stdout. Test-only; the
//! protocol is the kit's `PROTOCOL.md`.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use moqtap_monitor::{
    Connection, Delivery, Error, Gap, Monitor, MonitorBuilder, Proxy, Rejected, Sent, State, Stats,
    Status, TestClock,
};
use serde_json::{json, Map, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const PROTOCOL: u64 = 1;

/// A failed command: the reply's `error` code.
struct Fail(&'static str);

type Reply = Result<Map<String, Value>, Fail>;

fn bad() -> Fail {
    Fail("bad_command")
}

#[derive(Default)]
struct Harness {
    clock: Option<TestClock>,
    monitor: Option<Monitor>,
    conns: HashMap<String, Connection>,
    next_conn: u64,
    last: Option<Stats>,
}

#[tokio::main]
async fn main() {
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut out = tokio::io::stdout();
    let mut h = Harness::default();
    while let Ok(Some(line)) = lines.next_line().await {
        if line.trim().is_empty() {
            continue;
        }
        let (id, reply) = match serde_json::from_str::<Value>(&line) {
            Ok(Value::Object(cmd)) => {
                let id = cmd.get("id").cloned().unwrap_or(Value::Null);
                (id, h.run(&cmd).await)
            }
            _ => (Value::Null, Err(bad())),
        };
        let mut o = Map::new();
        o.insert("id".into(), id);
        match reply {
            Ok(fields) => {
                o.insert("ok".into(), Value::Bool(true));
                o.extend(fields);
            }
            Err(Fail(code)) => {
                o.insert("error".into(), Value::String(code.into()));
            }
        }
        let mut text = Value::Object(o).to_string();
        text.push('\n');
        if out.write_all(text.as_bytes()).await.is_err() || out.flush().await.is_err() {
            return;
        }
    }
}

impl Harness {
    async fn run(&mut self, cmd: &Map<String, Value>) -> Reply {
        let op = cmd.get("op").and_then(Value::as_str).ok_or_else(bad)?;
        match op {
            "hello" => Ok(fields(json!({
                "protocol": PROTOCOL,
                "monitor": {"name": env!("CARGO_PKG_NAME"), "version": env!("CARGO_PKG_VERSION")},
            }))),
            "start" => self.start(cmd),
            "connection" => {
                let relay = text(cmd, "relay")?;
                let c = self.monitor()?.connection(relay).map_err(error_code)?;
                self.next_conn += 1;
                let handle = self.next_conn.to_string();
                self.conns.insert(handle.clone(), c);
                Ok(fields(json!({ "conn": handle })))
            }
            "set_draft" => {
                let draft = uint(cmd, "draft")?;
                self.conn(cmd)?.set_draft(draft).map_err(rejected)?;
                Ok(Map::new())
            }
            "object_sent" => {
                let at = self.at(cmd)?;
                let sent = Sent {
                    group: uint(cmd, "group")?,
                    delivery: match opt_uint(cmd, "sub")? {
                        Some(s) => Delivery::Subgroup(s),
                        None => Delivery::Datagram,
                    },
                    object: uint(cmd, "object")?,
                    size: uint(cmd, "size")?,
                    starts_group: flag(cmd, "starts_group")?,
                    opens_subgroup: flag(cmd, "opens_subgroup")?,
                    ends_group: flag(cmd, "ends_group")?,
                };
                let (ns, track) = names(cmd)?;
                self.conn(cmd)?.object_sent(ns.as_slice(), &track, sent, at).map_err(rejected)?;
                Ok(Map::new())
            }
            "status_sent" => {
                let at = self.at(cmd)?;
                let status = match text(cmd, "status")? {
                    "eog" => Status::EndOfGroup,
                    "eot" => Status::EndOfTrack,
                    "eotg" => Status::EndOfTrackAndGroup,
                    "eosg" => Status::EndOfSubgroup,
                    "dne" => Status::DoesNotExist,
                    _ => return Err(bad()),
                };
                let (g, o) = (uint(cmd, "group")?, uint(cmd, "object")?);
                let (ns, track) = names(cmd)?;
                self.conn(cmd)?
                    .status_sent(ns.as_slice(), &track, g, o, status, at)
                    .map_err(rejected)?;
                Ok(Map::new())
            }
            "gap_sent" => {
                let n = uint(cmd, "n")?;
                let gap = match text(cmd, "gap")? {
                    "prior_groups" => Gap::PriorGroups(n),
                    "prior_objects" => Gap::PriorObjects(n),
                    _ => return Err(bad()),
                };
                let (g, o) = (uint(cmd, "group")?, uint(cmd, "object")?);
                let (ns, track) = names(cmd)?;
                self.conn(cmd)?.gap_sent(ns.as_slice(), &track, g, o, gap).map_err(rejected)?;
                Ok(Map::new())
            }
            "stream_reset" | "publish_done" => {
                let code = uint(cmd, "code")?;
                let (ns, track) = names(cmd)?;
                let c = self.conn(cmd)?;
                let r = if op == "stream_reset" {
                    c.stream_reset(ns.as_slice(), &track, code)
                } else {
                    c.publish_done(ns.as_slice(), &track, code)
                };
                r.map_err(rejected)?;
                Ok(Map::new())
            }
            "request_error" => {
                let code = uint(cmd, "code")?;
                let r = if cmd.contains_key("track") {
                    let (ns, track) = names(cmd)?;
                    self.conn(cmd)?.track_request_error(ns.as_slice(), &track, code)
                } else {
                    self.conn(cmd)?.request_error(code)
                };
                r.map_err(rejected)?;
                Ok(Map::new())
            }
            "close" => {
                let code = opt_uint(cmd, "code")?;
                let handle = text(cmd, "conn")?;
                let c = self.conns.remove(handle).ok_or(Fail("unknown_conn"))?;
                c.close(code).map_err(rejected)?;
                Ok(Map::new())
            }
            "advance" => {
                let ms = uint(cmd, "ms")?;
                let clock = self.clock.as_ref().ok_or(Fail("not_started"))?;
                clock.advance(Duration::from_millis(ms)).await;
                Ok(Map::new())
            }
            "step_wall" => {
                let ms = int(cmd, "ms")?;
                let clock = self.clock.as_ref().ok_or(Fail("not_started"))?;
                clock.step_wall(ms.checked_mul(1000).ok_or_else(bad)?);
                Ok(Map::new())
            }
            "stats" => match (&self.monitor, &self.last) {
                (Some(m), _) => Ok(stats_json(&m.stats())),
                (None, Some(s)) => Ok(stats_json(s)),
                (None, None) => Err(Fail("not_started")),
            },
            "shutdown" => {
                let ms = uint(cmd, "timeout_ms")?;
                let clock = self.clock.clone().ok_or(Fail("not_started"))?;
                let m = self.monitor.take().ok_or(Fail("stopped"))?;
                let s = shutdown(m, &clock, Duration::from_millis(ms)).await;
                let reply = stats_json(&s);
                self.last = Some(s);
                Ok(reply)
            }
            _ => Err(Fail("unknown_op")),
        }
    }

    fn start(&mut self, cmd: &Map<String, Value>) -> Reply {
        if self.clock.is_some() {
            return Err(Fail("already_started"));
        }
        if cmd.get("spool_dir").is_some_and(|v| !v.is_null()) {
            return Err(Fail("unsupported"));
        }
        let clock = TestClock::new(int(cmd, "wall_us")?);
        let mut b: MonitorBuilder =
            Monitor::builder(text(cmd, "source")?, text(cmd, "key")?).test_clock(&clock);
        if let Some(e) = opt_text(cmd, "endpoint")? {
            b = b.endpoint(e);
        }
        if let Some(ms) = opt_uint(cmd, "interval_ms")? {
            b = b.seal_interval(Duration::from_millis(ms));
        }
        if let Some(n) = opt_uint(cmd, "buffer_bytes")? {
            b = b.buffer_bytes(usize::try_from(n).map_err(|_| bad())?);
        }
        match opt_text(cmd, "proxy")? {
            None | Some("env") => {}
            Some("direct") => b = b.proxy(Proxy::Direct),
            Some(url) => b = b.proxy(Proxy::Url(url.to_string())),
        }
        if let Some(roots) = cmd.get("roots").filter(|v| !v.is_null()) {
            let roots = roots.as_array().ok_or_else(bad)?;
            let der = roots
                .iter()
                .map(|r| r.as_str().and_then(base64).ok_or_else(bad))
                .collect::<Result<Vec<_>, _>>()?;
            b = b.test_roots(der);
        }
        let m = b.start().map_err(error_code)?;
        let reply = fields(json!({ "instance_id": m.instance_id() }));
        self.clock = Some(clock);
        self.monitor = Some(m);
        Ok(reply)
    }

    fn monitor(&self) -> Result<&Monitor, Fail> {
        match (&self.monitor, &self.clock) {
            (Some(m), _) => Ok(m),
            (None, Some(_)) => Err(Fail("stopped")),
            (None, None) => Err(Fail("not_started")),
        }
    }

    fn conn(&self, cmd: &Map<String, Value>) -> Result<&Connection, Fail> {
        self.conns.get(text(cmd, "conn")?).ok_or(Fail("unknown_conn"))
    }

    /// `at_us` on the manual monotonic clock, which reads 0 at `start`.
    fn at(&self, cmd: &Map<String, Value>) -> Result<Option<Instant>, Fail> {
        let Some(us) = opt_int(cmd, "at_us")? else { return Ok(None) };
        let clock = self.clock.as_ref().ok_or(Fail("not_started"))?;
        Ok(Some(clock.instant_at(us)))
    }
}

/// While the shutdown runs, both clocks move at real speed, so its timeout
/// lapses after at most that much real time.
async fn shutdown(m: Monitor, clock: &TestClock, timeout: Duration) -> Stats {
    let fut = m.shutdown(timeout);
    tokio::pin!(fut);
    let mut last = Instant::now();
    loop {
        tokio::select! {
            s = &mut fut => return s,
            _ = tokio::time::sleep(Duration::from_millis(10)) => {
                let now = Instant::now();
                clock.advance(now - last).await;
                last = now;
            }
        }
    }
}

fn fields(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(m) => m,
        _ => Map::new(),
    }
}

fn stats_json(s: &Stats) -> Map<String, Value> {
    let mut m = fields(json!({
        "bodies_sent": s.bodies_sent.to_string(),
        "bodies_queued": s.bodies_queued.to_string(),
        "bytes_queued": s.bytes_queued.to_string(),
        "bodies_lost": s.bodies_lost.to_string(),
        "dropped": s.dropped.to_string(),
        "over_relay_cap": s.over_relay_cap.to_string(),
        "rejected": s.rejected.to_string(),
    }));
    let state = match s.state {
        State::Running => "running",
        State::Refused { status } => {
            m.insert("status".into(), Value::String(status.to_string()));
            "refused"
        }
        State::ShutDown => "shut_down",
        _ => "unknown",
    };
    m.insert("state".into(), Value::String(state.into()));
    m
}

fn error_code(e: Error) -> Fail {
    Fail(match e {
        Error::InvalidSource => "invalid_source",
        Error::BrowserKey => "browser_key",
        Error::InvalidKey => "invalid_key",
        Error::InvalidEndpoint => "invalid_endpoint",
        Error::InvalidProxy => "invalid_proxy",
        Error::InvalidSealInterval => "invalid_seal_interval",
        Error::InvalidRelayUrl => "invalid_relay_url",
        Error::TooManyConnections => "too_many_connections",
        Error::Stopped => "stopped",
        _ => "setup",
    })
}

fn rejected(r: Rejected) -> Fail {
    Fail(match r {
        Rejected::InvalidInput => "invalid_input",
        Rejected::Closed => "closed",
        _ => "invalid_input",
    })
}

fn text<'a>(cmd: &'a Map<String, Value>, k: &str) -> Result<&'a str, Fail> {
    opt_text(cmd, k)?.ok_or_else(bad)
}

fn opt_text<'a>(cmd: &'a Map<String, Value>, k: &str) -> Result<Option<&'a str>, Fail> {
    match cmd.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(bad()),
    }
}

/// Integers cross as decimal strings.
fn uint(cmd: &Map<String, Value>, k: &str) -> Result<u64, Fail> {
    opt_uint(cmd, k)?.ok_or_else(bad)
}

fn opt_uint(cmd: &Map<String, Value>, k: &str) -> Result<Option<u64>, Fail> {
    opt_text(cmd, k)?.map(|s| decimal(s).and_then(|s| s.parse().ok()).ok_or_else(bad)).transpose()
}

fn int(cmd: &Map<String, Value>, k: &str) -> Result<i64, Fail> {
    opt_int(cmd, k)?.ok_or_else(bad)
}

fn opt_int(cmd: &Map<String, Value>, k: &str) -> Result<Option<i64>, Fail> {
    opt_text(cmd, k)?
        .map(|s| {
            let digits = s.strip_prefix('-').unwrap_or(s);
            decimal(digits).and_then(|_| s.parse().ok()).ok_or_else(bad)
        })
        .transpose()
}

/// Plain decimal digits, no sign, no leading zero but for 0 itself.
fn decimal(s: &str) -> Option<&str> {
    let ok =
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && (s == "0" || !s.starts_with('0'));
    ok.then_some(s)
}

fn flag(cmd: &Map<String, Value>, k: &str) -> Result<bool, Fail> {
    match cmd.get(k) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(bad()),
    }
}

/// `ns` and `track` as base64 of their raw bytes.
fn names(cmd: &Map<String, Value>) -> Result<(Vec<Vec<u8>>, Vec<u8>), Fail> {
    let ns = cmd.get("ns").and_then(Value::as_array).ok_or_else(bad)?;
    let ns = ns
        .iter()
        .map(|f| f.as_str().and_then(base64).ok_or_else(bad))
        .collect::<Result<Vec<_>, _>>()?;
    let track = base64(text(cmd, "track")?).ok_or_else(bad)?;
    Ok((ns, track))
}

/// Standard base64 with padding.
fn base64(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    };
    let b = s.as_bytes();
    if !b.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 4 * 3);
    for (i, chunk) in b.chunks(4).enumerate() {
        let last = i + 1 == b.len() / 4;
        let pad = chunk.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut n = 0u32;
        for &c in &chunk[..4 - pad] {
            n = n << 6 | val(c)?;
        }
        n <<= 6 * pad as u32;
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        out.extend_from_slice(&bytes[..3 - pad]);
    }
    Some(out)
}

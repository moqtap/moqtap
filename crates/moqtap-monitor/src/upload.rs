//! The two background tasks: the sealer turns intervals into bodies at the
//! seal interval (sooner when the collector cuts one), and the sender posts
//! them in order, one at a time, keeping each until ingest accepts it.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE, RETRY_AFTER, USER_AGENT};
use hyper::{Request, StatusCode};
use tokio::sync::Notify;

use crate::clock::exchange;
use crate::collect::Collector;
use crate::egress::HttpClient;
use crate::pack::{Head, Packer, Sealed};
use crate::time::Clock;
use crate::wire::{body, frames, AppOffset, Clk, ClockSample};
use crate::{State, Timing};

/// The seal interval unless the builder names another.
pub(crate) const DEFAULT_SEAL: Duration = Duration::from_secs(15);
/// The shortest seal interval, configured or asked for by ingest.
pub(crate) const MIN_SEAL: Duration = Duration::from_secs(5);
/// The shortest seal interval ingest may ask for.
const MIN_DIRECTED_SEAL: Duration = Duration::from_secs(1);
/// The longest seal interval.
pub(crate) const MAX_SEAL: Duration = Duration::from_secs(60);
/// Sealed bodies kept until ingest accepts them, in bytes.
pub(crate) const DEFAULT_BUFFER_BYTES: usize = 16 * 1024 * 1024;

/// Clock epochs whose latest sample is kept for bodies still unsent.
const KEPT_EPOCHS: usize = 4;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
/// Retries back off from one retry unit (1 s) to 60, and a refused body is
/// sent again every 60.
const MAX_BACKOFF_UNITS: u32 = 60;
const REFUSED_RETRY_UNITS: u32 = 60;

const RECV_HEADER: &str = "x-moqtap-recv-ms";
const SEND_HEADER: &str = "x-moqtap-send-ms";
const POP_HEADER: &str = "x-moqtap-pop";
const IDEMPOTENCY_HEADER: &str = "idempotency-key";
const USER_AGENT_VALUE: &str = concat!("moqtap-monitor/", env!("CARGO_PKG_VERSION"));

pub(crate) const MONITOR_NAME: &str = "moqtap-monitor";
pub(crate) const MONITOR_VERSION: &str = env!("CARGO_PKG_VERSION");

/// An integrator's UTC clock: now in UTC µs, and its error bound in µs.
pub(crate) type AppClock = Arc<dyn Fn() -> Option<(i64, u64)> + Send + Sync>;

pub(crate) struct Config {
    pub source: String,
    pub instance_id: String,
    pub key: HeaderValue,
    /// `scheme://host[:port]`, no trailing slash.
    pub endpoint: String,
    pub interval: Duration,
    /// 0: a body that is not accepted at once is given up.
    pub buffer_bytes: usize,
    pub retry_unit: Duration,
    pub app_clock: Option<AppClock>,
    /// The integrator's sampling target, groups/s.
    pub sample_target: Option<u32>,
    /// The integrator's timing, the most a body is sealed at.
    pub timing: Timing,
    pub res_us: u64,
    pub start_wall_ms: i64,
}

#[derive(Debug)]
pub(crate) struct Entry {
    pub sealed: Sealed,
    /// The bytes sent, fixed at the first send.
    pub frozen: Option<Arc<Vec<u8>>>,
}

impl Entry {
    fn size(&self) -> usize {
        self.frozen.as_ref().map_or(self.sealed.raw_len, |b| b.len())
    }
}

#[derive(Debug)]
pub(crate) struct Outbox {
    pub queue: VecDeque<Entry>,
    pub bytes: usize,
    /// The body being posted.
    pub in_flight: Option<u64>,
    pub sent: u64,
    pub lost: u64,
    pub dropped: u64,
    pub state: State,
    /// The latest exchange of each recent clock epoch.
    pub samples: BTreeMap<u64, ClockSample>,
    /// Ingest's seal interval, ms, and when it lapses.
    pub directive: Option<(u64, Instant)>,
    /// The timing ingest last stated.
    pub timing: Option<Timing>,
}

impl Default for Outbox {
    fn default() -> Self {
        Outbox {
            queue: VecDeque::new(),
            bytes: 0,
            in_flight: None,
            sent: 0,
            lost: 0,
            dropped: 0,
            state: State::Running,
            samples: BTreeMap::new(),
            directive: None,
            timing: None,
        }
    }
}

impl Outbox {
    /// Give up the oldest bodies not in flight while the buffer is past `cap`.
    fn enforce(&mut self, cap: usize) {
        while self.bytes > cap && self.queue.len() > 1 {
            let i = usize::from(self.queue.front().map(|e| e.sealed.seq) == self.in_flight);
            if i >= self.queue.len() {
                break;
            }
            if let Some(gone) = self.queue.remove(i) {
                self.give_up(gone);
            }
        }
    }

    fn give_up(&mut self, gone: Entry) {
        gone.sealed.answered(false);
        self.bytes = self.bytes.saturating_sub(gone.size());
        self.lost += 1;
    }

    fn take(&mut self, seq: u64) -> Option<Entry> {
        let i = self.queue.iter().position(|e| e.sealed.seq == seq)?;
        let e = self.queue.remove(i)?;
        self.bytes = self.bytes.saturating_sub(e.size());
        Some(e)
    }
}

pub(crate) struct Shared {
    pub cfg: Config,
    pub clock: Clock,
    pub start: Instant,
    pub collector: Mutex<Collector>,
    pub outbox: Mutex<Outbox>,
    pub seal_now: Notify,
    pub send_now: Notify,
    /// Wakes the sender from a wait: a clock exchange is due, or shutdown.
    pub kick: Notify,
    pub directive_changed: Notify,
    pub shutting_down: AtomicBool,
    pub sealer_done: AtomicBool,
    pub shutdown: Notify,
}

impl Shared {
    /// Monotonic µs since the monitor started.
    pub(crate) fn mono_us(&self) -> i64 {
        self.mono_of(self.clock.now())
    }

    pub(crate) fn mono_of(&self, at: Instant) -> i64 {
        match at.checked_duration_since(self.start) {
            Some(d) => i64::try_from(d.as_micros()).unwrap_or(i64::MAX),
            None => -i64::try_from((self.start - at).as_micros()).unwrap_or(i64::MAX),
        }
    }

    pub(crate) fn collector(&self) -> MutexGuard<'_, Collector> {
        self.collector.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn outbox(&self) -> MutexGuard<'_, Outbox> {
        self.outbox.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn wall_us(&self) -> Option<i64> {
        self.clock.wall_us()
    }

    /// Wake the sealer to pack what the collector has cut.
    pub(crate) fn wake_sealer(&self) {
        self.clock.seal_asked();
        self.seal_now.notify_one();
    }

    /// The seal interval in force: the configured one, shortened while an
    /// ingest directive holds.
    fn interval(&self) -> Duration {
        let own = self.cfg.interval;
        match self.outbox().directive {
            Some((ms, until)) if self.clock.now() < until => {
                own.min(Duration::from_millis(ms).max(MIN_DIRECTED_SEAL))
            }
            _ => own,
        }
    }
}

pub(crate) async fn sealer(shared: Arc<Shared>) {
    let mut packer = Packer::new(
        Head {
            source: shared.cfg.source.clone(),
            instance_id: shared.cfg.instance_id.clone(),
            start: (0, shared.cfg.start_wall_ms),
            monitor_name: MONITOR_NAME,
            monitor_version: MONITOR_VERSION,
        },
        shared.cfg.sample_target,
    );
    let mut timer_from = shared.clock.now();
    let mut seen = shared.clock.seal_requests();
    // When the last body said the next seal is due: a later, longer
    // directive never moves it past that.
    let mut promised: Option<Instant> = None;
    loop {
        let interval = shared.interval();
        let from = {
            let mut c = shared.collector();
            c.seal_ms = interval.as_millis() as u64;
            c.open_from_us()
        };
        let opened = shared.start + Duration::from_micros(from.max(0) as u64);
        let due = opened.max(timer_from) + interval;
        let deadline = promised.map_or(due, |p| due.min(p));
        shared.clock.sealer_parked(deadline, seen);
        let is_final = tokio::select! {
            _ = shared.clock.sleep_until(deadline) => {
                timer_from = shared.clock.now();
                let mono = shared.mono_us();
                let mut c = shared.collector();
                c.observe(mono, shared.wall_us());
                // A due seal makes a body even with nothing in it, so the
                // time the last body stated holds.
                c.cut_due(mono);
                false
            }
            _ = shared.seal_now.notified() => false,
            _ = shared.directive_changed.notified() => false,
            _ = shared.shutdown.notified() => true,
        };
        seen = shared.clock.seal_requests();
        let is_final = is_final || shared.shutting_down.load(Ordering::SeqCst);
        if is_final {
            let mono = shared.mono_us();
            let mut c = shared.collector();
            c.observe(mono, shared.wall_us());
            c.cut(mono, true);
            c.stopped = true;
        }
        if let Some(next) = drain(&shared, &mut packer) {
            promised = Some(next);
        }
        if is_final {
            break;
        }
    }
    shared.sealer_done.store(true, Ordering::SeqCst);
    shared.clock.sealer_done();
    shared.send_now.notify_one();
}

/// Pack every interval the collector has sealed. Returns when the last
/// body packed says the next seal is due.
fn drain(shared: &Shared, packer: &mut Packer) -> Option<Instant> {
    let mut promised = None;
    loop {
        let (iv, probe) = {
            let mut c = shared.collector();
            (c.cuts.pop_front(), c.probe_due)
        };
        if probe {
            shared.kick.notify_one();
        }
        let Some(iv) = iv else { return promised };
        let own = shared.cfg.timing;
        let timing = shared.outbox().timing.map_or(own, |t| t.min(own));
        let app = shared.cfg.app_clock.as_ref().and_then(|f| {
            let (utc_us, e_us) = f()?;
            let at_us = shared.mono_us();
            Some(AppOffset { o_us: utc_us.checked_sub(at_us)?, e_us, at_us })
        });
        let next_ms = shared.interval().as_millis() as u64;
        let sealed = packer.pack_due(iv, app, timing, next_ms);
        promised = sealed.next_us.map(|us| shared.start + Duration::from_micros(us.max(0) as u64));
        let mut o = shared.outbox();
        o.dropped = packer.dropped();
        o.bytes += sealed.raw_len;
        o.queue.push_back(Entry { sealed, frozen: None });
        if shared.cfg.buffer_bytes > 0 {
            o.enforce(shared.cfg.buffer_bytes);
        }
        drop(o);
        shared.send_now.notify_one();
    }
}

enum Outcome {
    Accepted,
    Retry(Option<Duration>),
    Refused(u16),
    GiveUp,
}

pub(crate) async fn sender(shared: Arc<Shared>, client: HttpClient) {
    let unit = shared.cfg.retry_unit;
    let mut attempt = 0u32;
    let mut probed_epoch = None;
    probe(&shared, &client).await;
    loop {
        if std::mem::take(&mut shared.collector().probe_due) {
            probe(&shared, &client).await;
        }
        let head = shared.outbox().queue.front().map(|e| (e.sealed.seq, e.sealed.epoch));
        let Some((seq, epoch)) = head else {
            if shared.sealer_done.load(Ordering::SeqCst) {
                break;
            }
            tokio::select! {
                _ = shared.send_now.notified() => {}
                _ = shared.kick.notified() => {}
            }
            continue;
        };
        let current = shared.collector().epoch;
        let sampled = shared.outbox().samples.contains_key(&epoch);
        if !sampled && epoch == current && probed_epoch != Some(epoch) {
            probed_epoch = Some(epoch);
            probe(&shared, &client).await;
        }
        let Some(bytes) = freeze(&shared, seq) else { continue };
        shared.outbox().in_flight = Some(seq);
        let outcome = post(&shared, &client, seq, bytes).await;
        let keep = shared.cfg.buffer_bytes > 0;
        let wait = {
            let mut o = shared.outbox();
            o.in_flight = None;
            match outcome {
                Outcome::Accepted => {
                    attempt = 0;
                    if let Some(e) = o.take(seq) {
                        e.sealed.answered(true);
                        o.sent += 1;
                        o.state = State::Running;
                    }
                    None
                }
                Outcome::GiveUp => {
                    attempt = 0;
                    if let Some(e) = o.take(seq) {
                        o.give_up(e);
                    }
                    None
                }
                Outcome::Refused(status) => {
                    o.state = State::Refused { status };
                    if keep {
                        Some(unit * REFUSED_RETRY_UNITS)
                    } else {
                        if let Some(e) = o.take(seq) {
                            o.give_up(e);
                        }
                        None
                    }
                }
                Outcome::Retry(after) => {
                    if keep {
                        let cap = unit * MAX_BACKOFF_UNITS;
                        let wait = after.map_or_else(|| backoff(unit, attempt), |a| a.min(cap));
                        attempt = attempt.saturating_add(1);
                        Some(wait)
                    } else {
                        if let Some(e) = o.take(seq) {
                            o.give_up(e);
                        }
                        None
                    }
                }
            }
        };
        if let Some(wait) = wait {
            tokio::select! {
                _ = shared.clock.sleep(wait) => {}
                _ = shared.kick.notified() => {}
            }
        }
    }
}

/// The head body's bytes: built at its first send, with the latest clock
/// sample of its epoch and names only for tracks no accepted body carried,
/// and the same on every send after.
fn freeze(shared: &Shared, seq: u64) -> Option<Arc<Vec<u8>>> {
    let (mut sealed, sample) = {
        let o = shared.outbox();
        let e = o.queue.front().filter(|e| e.sealed.seq == seq)?;
        if let Some(b) = &e.frozen {
            return Some(Arc::clone(b));
        }
        let sample = o.samples.get(&e.sealed.epoch).cloned();
        (e.sealed.clone(), sample)
    };
    sealed.name_tracks();
    let clk = Clk {
        base_us: sealed.base_us,
        epoch: sealed.epoch,
        res_us: shared.cfg.res_us,
        sample,
        app: sealed.app,
    };
    let bytes =
        Arc::new(body(&sealed.preamble, &frames(&sealed.batch, &clk, &sealed.records), true));
    let mut o = shared.outbox();
    let o = &mut *o;
    let e = o.queue.iter_mut().find(|e| e.sealed.seq == seq)?;
    if e.frozen.is_none() {
        o.bytes = o.bytes.saturating_sub(e.sealed.raw_len) + bytes.len();
        e.frozen = Some(Arc::clone(&bytes));
        e.sealed.batch.tracks = sealed.batch.tracks;
    }
    e.frozen.clone()
}

/// Full jitter: uniform up to one unit doubled per attempt, capped at 60.
fn backoff(unit: Duration, attempt: u32) -> Duration {
    let full = unit.saturating_mul(1u32 << attempt.min(16)).min(unit * MAX_BACKOFF_UNITS);
    let mut b = [0u8; 4];
    let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b);
    full.mul_f64(f64::from(u32::from_le_bytes(b)) / f64::from(u32::MAX))
}

/// A clock exchange with no body, for a sample before the next body is sent.
async fn probe(shared: &Shared, client: &HttpClient) {
    let cfg = &shared.cfg;
    let req = Request::post(format!("{}/v1/clock", cfg.endpoint))
        .header(AUTHORIZATION, cfg.key.clone())
        .header(USER_AGENT, USER_AGENT_VALUE)
        .body(Full::new(Bytes::new()));
    let Ok(req) = req else { return };
    if let Some((status, _, reply)) = exchange_with(shared, client, req).await {
        if status.is_success() {
            take_timing(shared, &reply);
        }
    }
}

/// Keep the `timing` a reply states, `object` or `group`.
fn take_timing(shared: &Shared, reply: &[u8]) {
    if let Some(t) = timing(reply) {
        shared.outbox().timing = Some(t);
    }
}

fn timing(reply: &[u8]) -> Option<Timing> {
    let v: serde_json::Value = serde_json::from_slice(reply).ok()?;
    match v.get("timing")?.as_str()? {
        "object" => Some(Timing::Object),
        "group" => Some(Timing::Group),
        _ => None,
    }
}

/// Send `req`, take the reply's clock sample, and return the status,
/// headers and body.
async fn exchange_with(
    shared: &Shared,
    client: &HttpClient,
    req: Request<Full<Bytes>>,
) -> Option<(StatusCode, hyper::HeaderMap, Bytes)> {
    let epoch = shared.collector().epoch;
    let t1 = shared.mono_us();
    let resp = match shared.clock.timeout(REQUEST_TIMEOUT, client.request(req)).await {
        Some(Ok(resp)) => resp,
        _ => return None,
    };
    let t4 = shared.mono_us();
    let wall = shared.wall_us();
    let status = resp.status();
    let headers = resp.headers().clone();
    let int = |name: &str| -> Option<i64> { headers.get(name)?.to_str().ok()?.trim().parse().ok() };
    let pop = headers.get(POP_HEADER).and_then(|v| v.to_str().ok()).map(str::to_string);
    let sample = match (int(RECV_HEADER), int(SEND_HEADER)) {
        (Some(t2), Some(t3)) => exchange(t1, t2, t3, t4, pop),
        _ => None,
    };
    let broke = {
        let mut c = shared.collector();
        let wake = c.observe(t4, wall);
        wake == crate::collect::Wake::Seal || c.epoch != epoch
    };
    if broke {
        shared.wake_sealer();
    } else if let Some(s) = sample {
        let mut o = shared.outbox();
        o.samples.insert(epoch, s);
        while o.samples.len() > KEPT_EPOCHS {
            o.samples.pop_first();
        }
    }
    let body = shared
        .clock
        .timeout(REQUEST_TIMEOUT, Limited::new(resp.into_body(), MAX_RESPONSE_BYTES).collect())
        .await
        .and_then(Result::ok)
        .map(|b| b.to_bytes())
        .unwrap_or_default();
    Some((status, headers, body))
}

async fn post(shared: &Shared, client: &HttpClient, seq: u64, bytes: Arc<Vec<u8>>) -> Outcome {
    let cfg = &shared.cfg;
    let key = crate::wire::idempotency_key(&cfg.source, &cfg.instance_id, seq);
    let req = Request::post(format!("{}/v1/source?i={}", cfg.endpoint, cfg.instance_id))
        .header(AUTHORIZATION, cfg.key.clone())
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(IDEMPOTENCY_HEADER, key)
        .header(USER_AGENT, USER_AGENT_VALUE)
        .body(Full::new(Bytes::from((*bytes).clone())));
    let Ok(req) = req else { return Outcome::GiveUp };
    let Some((status, headers, reply)) = exchange_with(shared, client, req).await else {
        return Outcome::Retry(None);
    };
    let retry_after = headers
        .get(RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(|s| cfg.retry_unit.saturating_mul(u32::try_from(s).unwrap_or(u32::MAX)));
    let outcome = classify(status, retry_after);
    if let Outcome::Accepted = outcome {
        take_timing(shared, &reply);
        if let Some((ms, ttl)) = directive(&reply) {
            let until = shared.clock.now() + Duration::from_millis(ttl);
            shared.outbox().directive = Some((ms, until));
            shared.clock.seal_asked();
            shared.directive_changed.notify_one();
        }
    }
    outcome
}

/// `{seal_ms, ttl_ms}` from an accepted reply, both positive integers.
fn directive(reply: &[u8]) -> Option<(u64, u64)> {
    let v: serde_json::Value = serde_json::from_slice(reply).ok()?;
    let ms = v.get("seal_ms")?.as_u64().filter(|&n| n > 0)?;
    let ttl = v.get("ttl_ms")?.as_u64().filter(|&n| n > 0)?;
    Some((ms, ttl))
}

/// 2xx accepts the body. 401, 403 and 404 refuse the key or the path: the
/// body is kept and sent again later. 408, 425, 429 and every status that is
/// not a 4xx are retried. Any other 4xx means ingest will never take the
/// body.
fn classify(status: StatusCode, retry_after: Option<Duration>) -> Outcome {
    match status.as_u16() {
        200..=299 => Outcome::Accepted,
        401 | 403 | 404 => Outcome::Refused(status.as_u16()),
        408 | 425 | 429 => Outcome::Retry(retry_after),
        400..=499 => Outcome::GiveUp,
        _ => Outcome::Retry(retry_after),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_codes_follow_the_ingest_contract() {
        let kind = |s: u16| match classify(StatusCode::from_u16(s).unwrap(), None) {
            Outcome::Accepted => "ok",
            Outcome::Retry(_) => "retry",
            Outcome::Refused(_) => "refused",
            Outcome::GiveUp => "give up",
        };
        for (s, want) in [
            (202, "ok"),
            (401, "refused"),
            (403, "refused"),
            (404, "refused"),
            (400, "give up"),
            (405, "give up"),
            (413, "give up"),
            (422, "give up"),
            (408, "retry"),
            (425, "retry"),
            (429, "retry"),
            (500, "retry"),
            (503, "retry"),
        ] {
            assert_eq!(kind(s), want, "{s}");
        }
    }

    #[test]
    fn backoff_has_full_jitter_up_to_a_cap() {
        let unit = Duration::from_secs(1);
        for a in 0..20 {
            let full = unit.saturating_mul(1 << a.min(16)).min(unit * 60);
            assert!(backoff(unit, a) <= full, "{a}");
        }
        assert!(backoff(unit, 30) <= Duration::from_secs(60));
    }

    #[test]
    fn a_directive_needs_both_fields() {
        assert_eq!(
            directive(br#"{"ok":true,"seal_ms":5000,"ttl_ms":60000}"#),
            Some((5000, 60_000))
        );
        assert_eq!(directive(br#"{"ok":true}"#), None);
        assert_eq!(directive(br#"{"seal_ms":5000}"#), None);
        assert_eq!(directive(br#"{"seal_ms":0,"ttl_ms":1}"#), None);
        assert_eq!(directive(b"not json"), None);
    }

    #[test]
    fn a_reply_states_object_or_group_timing() {
        assert_eq!(timing(br#"{"ok":true,"timing":"group"}"#), Some(Timing::Group));
        assert_eq!(
            timing(br#"{"ok":true,"timing":"object","seal_ms":5000}"#),
            Some(Timing::Object)
        );
        assert_eq!(timing(br#"{"ok":true}"#), None);
        assert_eq!(timing(br#"{"timing":"frame"}"#), None);
        assert_eq!(timing(b""), None);
    }
}

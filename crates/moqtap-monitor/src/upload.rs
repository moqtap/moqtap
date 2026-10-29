//! The two background tasks: the sealer turns rows into bodies every
//! interval (sooner near the byte seal), and the sender posts them in order,
//! one at a time, retrying with backoff.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE, RETRY_AFTER, USER_AGENT};
use hyper::{Request, StatusCode};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tokio::sync::Notify;

use crate::clock::ClockWindow;
use crate::collect::Collector;
use crate::pack::{pack, HeadFields, Mode, Sealed};
use crate::relay_cap::RelayLedger;
use crate::wire::MAX_LOST_SEQS;
use crate::State;

/// Sealed bodies kept while ingest cannot be reached. Past it the oldest is
/// given up and listed as lost.
pub(crate) const MAX_QUEUED_BODIES: usize = 64;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const FIRST_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(300);
const MAX_RETRY_AFTER: Duration = Duration::from_secs(3600);
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

const RECV_HEADER: &str = "x-moqtap-recv-ms";
const SEND_HEADER: &str = "x-moqtap-send-ms";
const IDEMPOTENCY_HEADER: &str = "idempotency-key";

pub(crate) const MONITOR_NAME: &str = "moqtap-monitor";
pub(crate) const MONITOR_VERSION: &str = env!("CARGO_PKG_VERSION");

pub(crate) struct Config {
    pub source: String,
    pub instance_id: String,
    pub key: HeaderValue,
    /// `scheme://host[:port]`, no trailing slash.
    pub endpoint: String,
    pub interval: Duration,
}

#[derive(Debug, Default)]
pub(crate) struct Outbox {
    pub queue: VecDeque<Arc<Sealed>>,
    pub lost: VecDeque<u64>,
    pub lost_total: u64,
    pub sent: u64,
    pub clock: ClockWindow,
    pub state: Option<State>,
    pub relays: RelayLedger,
}

pub(crate) struct Shared {
    pub cfg: Config,
    pub start: Instant,
    pub collector: Mutex<Collector>,
    pub outbox: Mutex<Outbox>,
    pub seal_now: Notify,
    pub send_now: Notify,
    pub shutting_down: AtomicBool,
    pub sealer_done: AtomicBool,
    pub shutdown: Notify,
}

impl Shared {
    pub(crate) fn mono_ms(&self) -> f64 {
        self.start.elapsed().as_secs_f64() * 1000.0
    }

    pub(crate) fn collector(&self) -> MutexGuard<'_, Collector> {
        self.collector.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn outbox(&self) -> MutexGuard<'_, Outbox> {
        self.outbox.lock().unwrap_or_else(|e| e.into_inner())
    }
}

pub(crate) fn wall_ms() -> Option<f64> {
    SystemTime::now().duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs_f64() * 1000.0)
}

pub(crate) async fn sealer(shared: Arc<Shared>) {
    let mut next_seq = 0u64;
    let mut next = tokio::time::Instant::now() + shared.cfg.interval;
    loop {
        let mode = tokio::select! {
            _ = tokio::time::sleep_until(next) => {
                next = tokio::time::Instant::now() + shared.cfg.interval;
                Mode::All
            }
            _ = shared.seal_now.notified() => Mode::Early,
            _ = shared.shutdown.notified() => Mode::Final,
        };
        let mode = if shared.shutting_down.load(Ordering::SeqCst) { Mode::Final } else { mode };
        seal(&shared, mode, &mut next_seq).await;
        if mode == Mode::Final || shared.collector().stopped {
            break;
        }
    }
    shared.sealer_done.store(true, Ordering::SeqCst);
    shared.send_now.notify_one();
}

async fn seal(shared: &Shared, mode: Mode, next_seq: &mut u64) {
    // Read together, before any lock: the clock window compares the two.
    let mono = shared.mono_ms();
    let wall = wall_ms().unwrap_or(0.0);
    let idle_ms = shared.cfg.interval.as_secs_f64() * 1000.0;
    let clock = shared.outbox().clock.best(wall, mono);
    let mut taken = {
        let mut c = shared.collector();
        if c.stopped {
            return;
        }
        let taken = match mode {
            Mode::Early => c.take_early(),
            Mode::All => c.take(mono, idle_ms, false),
            Mode::Final => c.take(mono, 0.0, true),
        };
        if taken.is_empty() && mode != Mode::Final {
            c.prune();
            return;
        }
        taken
    };
    let capped = {
        let mut o = shared.outbox();
        let o = &mut *o;
        o.relays.advance(mono, o.queue.iter().map(|b| b.origins.as_slice()));
        o.relays.cap(&mut taken)
    };
    let dropped = {
        let mut c = shared.collector();
        c.dropped += capped;
        c.over_relay_cap += capped;
        c.dropped
    };
    let head = {
        let o = shared.outbox();
        HeadFields {
            source: shared.cfg.source.clone(),
            instance_id: shared.cfg.instance_id.clone(),
            ts: mono as u64,
            wall: wall as u64,
            lost: o.lost.iter().copied().collect(),
            dropped,
            clock,
            monitor_name: MONITOR_NAME,
            monitor_version: MONITOR_VERSION,
        }
    };
    // Packing gzips each trial body, so it runs off the runtime's threads.
    let mut seq = *next_seq;
    let packed = match tokio::task::spawn_blocking(move || {
        let packed = pack(taken, &head, &mut seq, mode);
        (packed, seq)
    })
    .await
    {
        Ok((packed, seq)) => {
            *next_seq = seq;
            packed
        }
        Err(_) => return,
    };
    {
        let mut c = shared.collector();
        c.dropped += packed.dropped;
        if let Some(rest) = packed.leftover {
            c.restore(rest);
        }
        c.prune();
    }
    if packed.bodies.is_empty() {
        return;
    }
    {
        let mut o = shared.outbox();
        for b in packed.bodies {
            o.relays.sealed(&b.origins);
            o.queue.push_back(Arc::new(b));
        }
        while o.queue.len() > MAX_QUEUED_BODIES {
            if let Some(gone) = o.queue.pop_front() {
                o.relays.given_up(&gone.origins);
                o.note_lost(gone.seq);
            }
        }
    }
    shared.send_now.notify_one();
}

impl Outbox {
    fn note_lost(&mut self, seq: u64) {
        self.lost_total += 1;
        self.lost.push_back(seq);
        while self.lost.len() > MAX_LOST_SEQS {
            self.lost.pop_front();
        }
    }

    fn remove(&mut self, seq: u64) -> bool {
        match self.queue.iter().position(|b| b.seq == seq) {
            Some(i) => {
                self.queue.remove(i);
                true
            }
            None => false,
        }
    }
}

type HttpClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

pub(crate) fn client() -> Result<HttpClient, rustls::Error> {
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_provider_and_webpki_roots(rustls::crypto::ring::default_provider())?
        .https_or_http()
        .enable_http1()
        .build();
    Ok(Client::builder(TokioExecutor::new()).build(https))
}

enum Outcome {
    /// With ingest's receive time, when it stated one.
    Accepted(Option<f64>),
    Retry(Option<Duration>),
    Refused,
    Stop(u16),
}

pub(crate) async fn sender(shared: Arc<Shared>, client: HttpClient) {
    let mut attempt = 0u32;
    loop {
        let next = shared.outbox().queue.front().cloned();
        let Some(body) = next else {
            if shared.sealer_done.load(Ordering::SeqCst) {
                break;
            }
            shared.send_now.notified().await;
            continue;
        };
        match post(&shared, &client, &body).await {
            Outcome::Accepted(recv_ms) => {
                attempt = 0;
                let mut o = shared.outbox();
                if o.remove(body.seq) {
                    o.sent += 1;
                }
                let o = &mut *o;
                let queued = o.queue.iter().map(|b| b.origins.as_slice());
                o.relays.accepted(recv_ms, shared.mono_ms(), &body.origins, queued);
            }
            Outcome::Refused => {
                attempt = 0;
                let mut o = shared.outbox();
                if o.remove(body.seq) {
                    o.note_lost(body.seq);
                }
            }
            Outcome::Stop(status) => {
                shared.collector().stop();
                let mut o = shared.outbox();
                o.queue.clear();
                o.state = Some(State::Stopped { status });
                drop(o);
                shared.shutdown.notify_one();
                break;
            }
            Outcome::Retry(after) => {
                let wait = after.unwrap_or_else(|| backoff(attempt));
                attempt = attempt.saturating_add(1);
                tokio::time::sleep(wait).await;
            }
        }
    }
}

/// Exponential from one second to five minutes, each wait drawn from its
/// upper half so that many monitors do not retry in step.
fn backoff(attempt: u32) -> Duration {
    let full = FIRST_BACKOFF.saturating_mul(1u32 << attempt.min(16)).min(MAX_BACKOFF);
    let mut b = [0u8; 2];
    let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b);
    let frac = 0.5 + f64::from(u16::from_le_bytes(b)) / f64::from(u16::MAX) / 2.0;
    full.mul_f64(frac)
}

async fn post(shared: &Shared, client: &HttpClient, body: &Sealed) -> Outcome {
    let cfg = &shared.cfg;
    let uri = format!("{}/v1/source?i={}", cfg.endpoint, cfg.instance_id);
    let req = Request::post(uri)
        .header(AUTHORIZATION, cfg.key.clone())
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(IDEMPOTENCY_HEADER, &body.idempotency_key)
        .header(USER_AGENT, concat!("moqtap-monitor/", env!("CARGO_PKG_VERSION")))
        .body(Full::new(Bytes::from(body.body.clone())));
    let Ok(req) = req else { return Outcome::Refused };

    let t1 = wall_ms();
    let resp = match tokio::time::timeout(REQUEST_TIMEOUT, client.request(req)).await {
        Ok(Ok(resp)) => resp,
        _ => return Outcome::Retry(None),
    };
    let t4 = wall_ms();
    let mono = shared.mono_ms();
    let status = resp.status();
    let headers = resp.headers();
    let num = |name: &str| -> Option<f64> {
        headers.get(name)?.to_str().ok()?.trim().parse::<f64>().ok().filter(|v| v.is_finite())
    };
    let recv_ms = num(RECV_HEADER);
    if let (Some(t1), Some(t2), Some(t3), Some(t4)) = (t1, recv_ms, num(SEND_HEADER), t4) {
        shared.outbox().clock.sample(t1, t2, t3, t4, mono);
    }
    let retry_after = headers
        .get(RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(|s| Duration::from_secs(s).min(MAX_RETRY_AFTER));
    let _ = tokio::time::timeout(
        REQUEST_TIMEOUT,
        Limited::new(resp.into_body(), MAX_RESPONSE_BYTES).collect(),
    )
    .await;

    match classify(status, retry_after) {
        Outcome::Accepted(_) => Outcome::Accepted(recv_ms),
        other => other,
    }
}

/// The ingest contract: every 4xx but 408, 425 and 429 is final for the
/// body; 401, 403 and 404 are final for the key or the path, so nothing more
/// is sent.
fn classify(status: StatusCode, retry_after: Option<Duration>) -> Outcome {
    match status.as_u16() {
        200..=299 => Outcome::Accepted(None),
        401 | 403 | 404 => Outcome::Stop(status.as_u16()),
        408 | 425 | 429 => Outcome::Retry(retry_after),
        400..=499 => Outcome::Refused,
        _ => Outcome::Retry(retry_after),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_codes_follow_the_ingest_contract() {
        let kind = |s: u16| match classify(StatusCode::from_u16(s).unwrap(), None) {
            Outcome::Accepted(_) => "ok",
            Outcome::Retry(_) => "retry",
            Outcome::Refused => "refused",
            Outcome::Stop(_) => "stop",
        };
        for (s, want) in [
            (202, "ok"),
            (401, "stop"),
            (403, "stop"),
            (404, "stop"),
            (400, "refused"),
            (413, "refused"),
            (405, "refused"),
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
    fn backoff_doubles_to_a_cap() {
        for a in 0..20 {
            let full = FIRST_BACKOFF.saturating_mul(1 << a.min(16)).min(MAX_BACKOFF);
            let d = backoff(a);
            assert!(d >= full / 2 && d <= full, "{a}: {d:?}");
        }
    }
}

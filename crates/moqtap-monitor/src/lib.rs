//! Producer monitor for moqtap Insight.
//!
//! A MoQT publisher reports each object after its MoQ library has accepted
//! it; the monitor uploads the reports to moqtap Insight in the background. One [`Monitor`] per process and source;
//! one [`Connection`] per relay connection.
//!
//! ```no_run
//! # async fn run() -> Result<(), moqtap_monitor::Error> {
//! use std::time::Duration;
//! use moqtap_monitor::Monitor;
//!
//! let monitor = Monitor::builder("encoder-fra-1", std::env::var("MOQTAP_SOURCE_KEY").unwrap())
//!     .start()?;
//! let relay = monitor.connection("https://relay.example.net/moq")?;
//!
//! // After the MoQ library accepted object 0 of group 42:
//! let _ = relay.object_sent(&["live", "channel-7"], "video", 42, 0, 18_000, None);
//!
//! let _ = relay.close(None);
//! monitor.shutdown(Duration::from_secs(5)).await;
//! # Ok(())
//! # }
//! ```
//!
//! The monitor needs a Tokio runtime: [`MonitorBuilder::start`] spawns its
//! tasks on the current one. Reporting never blocks on the network and never
//! panics on bad input; refused input is counted in [`Stats::rejected`].

#![deny(missing_docs)]

mod clock;
mod collect;
#[cfg(test)]
mod golden_tests;
mod pack;
mod relay;
mod relay_cap;
mod sampling;
mod upload;
mod wire;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hyper::header::HeaderValue;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

pub use clock::DRIFT;
pub use relay_cap::MAX_RELAYS_PER_MONTH;
pub use sampling::{RATE_WINDOW_SECS, TARGET_GROUPS_PER_SEC};

use collect::{Collector, Refused, Wake};
use upload::{Config, Outbox, Shared};
use wire::EventKind;

/// The ingest endpoint used unless [`MonitorBuilder::endpoint`] names another.
pub const DEFAULT_ENDPOINT: &str = "https://moqgest.com";

/// How often a body is sealed and uploaded.
pub const UPLOAD_INTERVAL: Duration = Duration::from_secs(60);

const KEY_PREFIX: &str = "mqt_sk_";
const BROWSER_KEY_PREFIX: &str = "mqt_pk_";
const MAX_KEY_BYTES: usize = 512;

/// What the monitor reports per relay connection and track.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Detail {
    /// One row per group: its first object, send time, span, object count and bytes.
    #[default]
    Group,
    /// Every object as well. Accepted only on plans that include it.
    Object,
}

/// Why the monitor could not start or a connection could not be opened.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The source slug is not `[a-z0-9][a-z0-9._-]{0,63}`.
    #[error("source must match [a-z0-9][a-z0-9._-]{{0,63}}")]
    InvalidSource,
    /// The key is a browser key (`mqt_pk_`); servers use a source key (`mqt_sk_`).
    #[error("this is a browser ingest key (mqt_pk_); a source needs a source key (mqt_sk_)")]
    BrowserKey,
    /// The key is not a source key.
    #[error("the key is not a source key (mqt_sk_)")]
    InvalidKey,
    /// The endpoint is not an `https` origin, or an `http` one on a loopback host.
    #[error("the endpoint must be an https origin, or http on a loopback host")]
    InvalidEndpoint,
    /// The relay URL is not an `https`, `http` or `moqt` URL.
    #[error("not a relay URL")]
    InvalidRelayUrl,
    /// Too many relay connections are open.
    #[error("too many relay connections are open")]
    TooManyConnections,
    /// The monitor has stopped: shut down, or refused by ingest.
    #[error("the monitor has stopped")]
    Stopped,
    /// There is no Tokio runtime to run on.
    #[error("no Tokio runtime is running")]
    NoRuntime,
    /// The system random source or TLS setup failed.
    #[error("setup failed: {0}")]
    Setup(String),
}

/// Why a report was not taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Rejected {
    /// An id past 2^62 - 1, a size, code or draft past 2^53 - 1, a time
    /// before 1970 or past 2255, a track name past MoQT's limits, or too
    /// many tracks.
    #[error("invalid report")]
    InvalidInput,
    /// The connection is closed, or the monitor has stopped.
    #[error("the connection is closed")]
    Closed,
}

/// Where the monitor stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum State {
    /// Collecting and uploading.
    Running,
    /// Ingest refused the key or the path (401, 403 or 404). Nothing more is
    /// collected or sent.
    Stopped {
        /// The HTTP status ingest answered with.
        status: u16,
    },
    /// [`Monitor::shutdown`] ran.
    ShutDown,
}

/// Counters, for logs and health checks.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct Stats {
    /// Where the monitor stands.
    pub state: State,
    /// Bodies ingest accepted.
    pub bodies_sent: u64,
    /// Bodies sealed and waiting to be sent.
    pub bodies_queued: usize,
    /// Bodies given up: refused by ingest, or past the queue bound.
    pub bodies_lost: u64,
    /// Rows not kept: past a memory bound, a late object of a group already
    /// reported, an object of a group 64 or more below its track's newest,
    /// or a relay past the cap ([`Stats::over_relay_cap`]).
    pub dropped: u64,
    /// Of [`Stats::dropped`], rows and events not sent because their relay
    /// would have taken the source past [`MAX_RELAYS_PER_MONTH`] origins this
    /// month.
    pub over_relay_cap: u64,
    /// Reports refused as invalid or for a closed connection.
    pub rejected: u64,
}

/// Configures and starts a [`Monitor`].
pub struct MonitorBuilder {
    source: String,
    key: String,
    endpoint: String,
    detail: Detail,
    interval: Duration,
}

impl std::fmt::Debug for MonitorBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MonitorBuilder")
            .field("source", &self.source)
            .field("key", &"<redacted>")
            .field("endpoint", &self.endpoint)
            .field("detail", &self.detail)
            .finish()
    }
}

impl MonitorBuilder {
    /// The ingest origin. Defaults to [`DEFAULT_ENDPOINT`].
    pub fn endpoint(mut self, origin: impl Into<String>) -> Self {
        self.endpoint = origin.into();
        self
    }

    /// Per group (the default) or per object.
    pub fn detail(mut self, detail: Detail) -> Self {
        self.detail = detail;
        self
    }

    #[doc(hidden)]
    pub fn seal_interval(mut self, interval: Duration) -> Self {
        self.interval = interval.max(Duration::from_millis(10));
        self
    }

    /// Validate the configuration and start the background tasks on the
    /// current Tokio runtime.
    pub fn start(self) -> Result<Monitor, Error> {
        if !valid_slug(&self.source) {
            return Err(Error::InvalidSource);
        }
        if self.key.starts_with(BROWSER_KEY_PREFIX) {
            return Err(Error::BrowserKey);
        }
        let key_ok = self.key.starts_with(KEY_PREFIX)
            && self.key.len() <= MAX_KEY_BYTES
            && self.key.bytes().all(|b| b.is_ascii_graphic());
        if !key_ok {
            return Err(Error::InvalidKey);
        }
        let mut key = HeaderValue::from_str(&format!("Bearer {}", self.key))
            .map_err(|_| Error::InvalidKey)?;
        key.set_sensitive(true);
        let endpoint = endpoint_origin(&self.endpoint).ok_or(Error::InvalidEndpoint)?;
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| Error::NoRuntime)?;
        let client = upload::client().map_err(|e| Error::Setup(e.to_string()))?;
        let mut id = [0u8; 16];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut id)
            .map_err(|_| Error::Setup("system random source".into()))?;

        let collector = Collector::new(self.detail == Detail::Object);
        let shared = Arc::new(Shared {
            cfg: Config {
                source: self.source,
                instance_id: wire::hex(&id),
                key,
                endpoint,
                interval: self.interval,
            },
            start: Instant::now(),
            collector: Mutex::new(collector),
            outbox: Mutex::new(Outbox::default()),
            seal_now: Notify::new(),
            send_now: Notify::new(),
            shutting_down: AtomicBool::new(false),
            sealer_done: AtomicBool::new(false),
            shutdown: Notify::new(),
        });
        let sealer = runtime.spawn(upload::sealer(Arc::clone(&shared)));
        let sender = runtime.spawn(upload::sender(Arc::clone(&shared), client));
        Ok(Monitor { shared, sealer: Some(sealer), sender: Some(sender) })
    }
}

/// One source's monitor. Dropping it without [`Monitor::shutdown`] still
/// seals a final body, sent while the runtime keeps running.
pub struct Monitor {
    shared: Arc<Shared>,
    sealer: Option<JoinHandle<()>>,
    sender: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for Monitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Monitor")
            .field("source", &self.shared.cfg.source)
            .field("instance_id", &self.shared.cfg.instance_id)
            .finish_non_exhaustive()
    }
}

impl Monitor {
    /// Start configuring a monitor for `source` (the source's slug, as set in
    /// the portal) with its secret `mqt_sk_` key. The key is sent only in the
    /// `Authorization` header and is never logged.
    pub fn builder(source: impl Into<String>, key: impl Into<String>) -> MonitorBuilder {
        MonitorBuilder {
            source: source.into(),
            key: key.into(),
            endpoint: DEFAULT_ENDPOINT.to_string(),
            detail: Detail::Group,
            interval: UPLOAD_INTERVAL,
        }
    }

    /// A new relay connection. Only the URL's origin is kept: the path,
    /// query and userinfo never leave the process.
    pub fn connection(&self, relay_url: &str) -> Result<Connection, Error> {
        let origin = relay::relay_origin(relay_url).ok_or(Error::InvalidRelayUrl)?;
        if self.shared.shutting_down.load(Ordering::SeqCst) {
            return Err(Error::Stopped);
        }
        let ts = self.shared.mono_ms();
        let mut c = self.shared.collector();
        if c.stopped {
            return Err(Error::Stopped);
        }
        let id = c.open(origin, ts as u64).ok_or(Error::TooManyConnections)?;
        Ok(Connection { shared: Arc::clone(&self.shared), id, closed: false })
    }

    /// This process's instance id: 32 lowercase hex characters, new each start.
    pub fn instance_id(&self) -> &str {
        &self.shared.cfg.instance_id
    }

    /// The monitor's counters.
    pub fn stats(&self) -> Stats {
        stats(&self.shared)
    }

    /// Seal a final body, then send what is queued, waiting at most
    /// `timeout`. Whatever is still unsent then is given up.
    pub async fn shutdown(mut self, timeout: Duration) -> Stats {
        self.signal_shutdown();
        let deadline = tokio::time::Instant::now() + timeout;
        for task in [self.sealer.take(), self.sender.take()].into_iter().flatten() {
            let abort = task.abort_handle();
            if tokio::time::timeout_at(deadline, task).await.is_err() {
                abort.abort();
            }
        }
        let mut s = stats(&self.shared);
        if s.state == State::Running {
            s.state = State::ShutDown;
            self.shared.outbox().state = Some(State::ShutDown);
        }
        s
    }

    fn signal_shutdown(&self) {
        self.shared.shutting_down.store(true, Ordering::SeqCst);
        self.shared.shutdown.notify_one();
    }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        if self.sealer.is_some() {
            self.signal_shutdown();
        }
    }
}

fn stats(shared: &Shared) -> Stats {
    let (dropped, over_relay_cap, rejected) = {
        let c = shared.collector();
        (c.dropped, c.over_relay_cap, c.rejected)
    };
    let o = shared.outbox();
    Stats {
        state: o.state.unwrap_or(State::Running),
        bodies_sent: o.sent,
        bodies_queued: o.queue.len(),
        bodies_lost: o.lost_total,
        dropped,
        over_relay_cap,
        rejected,
    }
}

/// One relay connection of the source. Closed when dropped.
pub struct Connection {
    shared: Arc<Shared>,
    id: u64,
    closed: bool,
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection").field("id", &self.id).finish_non_exhaustive()
    }
}

impl Connection {
    /// The MoQT draft the connection negotiated, when known.
    pub fn set_draft(&self, draft: u64) -> Result<(), Rejected> {
        let r = self.shared.collector().set_draft(self.id, draft);
        r.map_err(rejected)
    }

    /// Report one object, after the producer's MoQ library accepted it.
    /// `size` is the payload in bytes; `at` is when it was handed over,
    /// now when `None`.
    pub fn object_sent<S: AsRef<str>>(
        &self,
        namespace: &[S],
        track: &str,
        group: u64,
        object: u64,
        size: u64,
        at: Option<SystemTime>,
    ) -> Result<(), Rejected> {
        let at = at.unwrap_or_else(SystemTime::now);
        let at_us = match at.duration_since(UNIX_EPOCH) {
            Ok(d) => i64::try_from(d.as_micros()).unwrap_or(i64::MAX),
            Err(_) => -1,
        };
        let mono = self.shared.mono_ms();
        let r = self
            .shared
            .collector()
            .object_sent(self.id, namespace, track, group, object, size, at_us, mono);
        self.after(r)
    }

    /// A data stream of `track` was reset with `code`.
    pub fn stream_reset<S: AsRef<str>>(
        &self,
        namespace: &[S],
        track: &str,
        code: u64,
    ) -> Result<(), Rejected> {
        self.event(Some((namespace, track)), EventKind::StreamReset, code)
    }

    /// A request on the connection failed with `code`.
    pub fn request_error(&self, code: u64) -> Result<(), Rejected> {
        self.event::<&str>(None, EventKind::RequestError, code)
    }

    /// A request for `track` failed with `code`.
    pub fn track_request_error<S: AsRef<str>>(
        &self,
        namespace: &[S],
        track: &str,
        code: u64,
    ) -> Result<(), Rejected> {
        self.event(Some((namespace, track)), EventKind::RequestError, code)
    }

    /// Publishing `track` ended with status `code`. Its open groups close.
    pub fn publish_done<S: AsRef<str>>(
        &self,
        namespace: &[S],
        track: &str,
        code: u64,
    ) -> Result<(), Rejected> {
        self.event(Some((namespace, track)), EventKind::PublishDone, code)
    }

    /// Close the connection, with the session's close code when known. A
    /// code past 2^53 - 1 is refused; the connection closes without it.
    pub fn close(mut self, code: Option<u64>) -> Result<(), Rejected> {
        self.close_inner(code)
    }

    fn event<S: AsRef<str>>(
        &self,
        track: Option<(&[S], &str)>,
        e: EventKind,
        code: u64,
    ) -> Result<(), Rejected> {
        let ts = self.shared.mono_ms() as u64;
        let r = self.shared.collector().event(self.id, track, e, Some(code), ts);
        self.after(r)
    }

    fn after(&self, r: Result<Wake, Refused>) -> Result<(), Rejected> {
        match r {
            Ok(Wake::Seal) => {
                self.shared.seal_now.notify_one();
                Ok(())
            }
            Ok(Wake::No) => Ok(()),
            Err(e) => Err(rejected(e)),
        }
    }

    fn close_inner(&mut self, code: Option<u64>) -> Result<(), Rejected> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let ts = self.shared.mono_ms() as u64;
        let r = self.shared.collector().close(self.id, ts, code);
        r.map_err(rejected)
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        let _ = self.close_inner(None);
    }
}

fn rejected(r: Refused) -> Rejected {
    match r {
        Refused::Input => Rejected::InvalidInput,
        Refused::Closed => Rejected::Closed,
    }
}

fn valid_slug(s: &str) -> bool {
    let b = s.as_bytes();
    let tail =
        |c: &u8| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-');
    !b.is_empty()
        && b.len() <= 64
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b[1..].iter().all(tail)
}

/// `scheme://host[:port]` of an `https` origin, or of an `http` one on a
/// loopback host; `None` for anything else, a path included.
fn endpoint_origin(s: &str) -> Option<String> {
    let u = url::Url::parse(s).ok()?;
    if !u.username().is_empty() || u.password().is_some() || u.query().is_some() {
        return None;
    }
    if u.fragment().is_some() || !matches!(u.path(), "" | "/") {
        return None;
    }
    let host = u.host()?;
    let loopback = match &host {
        url::Host::Domain(d) => *d == "localhost",
        url::Host::Ipv4(a) => a.is_loopback(),
        url::Host::Ipv6(a) => a.is_loopback(),
    };
    match u.scheme() {
        "https" => {}
        "http" if loopback => {}
        _ => return None,
    }
    let port = u.port().map(|p| format!(":{p}")).unwrap_or_default();
    let host = match host {
        url::Host::Ipv6(a) => format!("[{a}]"),
        h => h.to_string(),
    };
    Some(format!("{}://{host}{port}", u.scheme()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs() {
        for ok in ["enc-fra-1", "a", "0.x_y-z", &"a".repeat(64)] {
            assert!(valid_slug(ok), "{ok}");
        }
        for bad in ["", "-a", "A", "a b", "é", &"a".repeat(65), ".a"] {
            assert!(!valid_slug(bad), "{bad}");
        }
    }

    #[test]
    fn endpoints() {
        assert_eq!(endpoint_origin("https://moqgest.com").as_deref(), Some("https://moqgest.com"));
        assert_eq!(endpoint_origin("https://moqgest.com/").as_deref(), Some("https://moqgest.com"));
        assert_eq!(
            endpoint_origin("http://127.0.0.1:8787").as_deref(),
            Some("http://127.0.0.1:8787")
        );
        assert_eq!(endpoint_origin("http://[::1]:1").as_deref(), Some("http://[::1]:1"));
        assert_eq!(endpoint_origin("http://localhost:1").as_deref(), Some("http://localhost:1"));
        for bad in [
            "http://moqgest.com",
            "https://moqgest.com/v1",
            "https://moqgest.com?k=x",
            "https://u:p@moqgest.com",
            "ftp://moqgest.com",
            "moqgest.com",
        ] {
            assert_eq!(endpoint_origin(bad), None, "{bad}");
        }
    }

    #[tokio::test]
    async fn keys_are_checked_before_anything_starts() {
        let start = |k: &str| Monitor::builder("enc", k).start().map(|_| ());
        assert!(matches!(start("mqt_pk_abc"), Err(Error::BrowserKey)));
        assert!(matches!(start("sk_abc"), Err(Error::InvalidKey)));
        assert!(matches!(start("mqt_sk_a b"), Err(Error::InvalidKey)));
        assert!(matches!(Monitor::builder("Enc", "mqt_sk_x").start(), Err(Error::InvalidSource)));
        let e = Monitor::builder("enc", "mqt_sk_x").endpoint("http://example.com").start();
        assert!(matches!(e, Err(Error::InvalidEndpoint)));
    }

    #[test]
    fn no_runtime_is_an_error() {
        assert!(matches!(Monitor::builder("enc", "mqt_sk_x").start(), Err(Error::NoRuntime)));
    }

    #[test]
    fn debug_never_prints_the_key() {
        let b = Monitor::builder("enc", "mqt_sk_secretvalue");
        assert!(!format!("{b:?}").contains("secretvalue"));
    }
}

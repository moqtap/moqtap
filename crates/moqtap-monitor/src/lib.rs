//! Producer monitor for moqtap Insight.
//!
//! A MoQT publisher reports each object as it hands it to its MoQ library;
//! the monitor uploads the reports to moqtap Insight in the background. One
//! [`Monitor`] per process and source; one [`Connection`] per relay
//! connection.
//!
//! ```no_run
//! # async fn run() -> Result<(), moqtap_monitor::Error> {
//! use std::time::Duration;
//! use moqtap_monitor::{Delivery, Monitor, Sent};
//!
//! let monitor = Monitor::builder("encoder-fra-1", std::env::var("MOQTAP_SOURCE_KEY").unwrap())
//!     .start()?;
//! let relay = monitor.connection("https://relay.example.net/moq")?;
//!
//! // As the MoQ library takes the first object of group 42:
//! let sent = Sent {
//!     group: 42,
//!     delivery: Delivery::Subgroup(0),
//!     object: 0,
//!     size: 18_000,
//!     starts_group: true,
//!     opens_subgroup: true,
//!     ends_group: false,
//! };
//! let _ = relay.object_sent(&["live", "channel-7"], "video", sent, None);
//!
//! let _ = relay.close(None);
//! // Required before the process exits: it seals and sends what is left.
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
mod egress;
#[cfg(test)]
mod golden_tests;
mod hist;
mod pack;
mod relay;
mod relay_cap;
mod sampling;
mod time;
mod upload;
mod wire;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hyper::header::HeaderValue;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

pub use clock::DRIFT;
pub use egress::Proxy;
pub use relay_cap::MAX_RELAYS_PER_MONTH;
pub use sampling::MAX_SAMPLE_TARGET;
#[doc(hidden)]
pub use time::TestClock;

use collect::{Collector, Handoff, Refused, Wake};
use time::Clock;
use upload::{AppClock, Config, Outbox, Shared};
use wire::{EventKind, MarkKind};

/// The ingest endpoint used unless [`MonitorBuilder::endpoint`] names another.
pub const DEFAULT_ENDPOINT: &str = "https://moqgest.com";

/// How often a body is sealed and uploaded, unless
/// [`MonitorBuilder::seal_interval`] says otherwise.
pub const DEFAULT_SEAL_INTERVAL: Duration = upload::DEFAULT_SEAL;
/// The shortest seal interval.
pub const MIN_SEAL_INTERVAL: Duration = upload::MIN_SEAL;
/// The longest seal interval.
pub const MAX_SEAL_INTERVAL: Duration = upload::MAX_SEAL;
/// The bytes of sealed bodies kept until ingest accepts them, unless
/// [`MonitorBuilder::buffer_bytes`] says otherwise.
pub const DEFAULT_BUFFER_BYTES: usize = upload::DEFAULT_BUFFER_BYTES;

const KEY_PREFIX: &str = "mqt_sk_";
const BROWSER_KEY_PREFIX: &str = "mqt_pk_";
const MAX_KEY_BYTES: usize = 512;

/// How an object is delivered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Delivery {
    /// On a subgroup stream, with its subgroup id.
    Subgroup(u64),
    /// As a datagram.
    Datagram,
}

/// One object as it is handed to the MoQ library.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Sent {
    /// The group id.
    pub group: u64,
    /// The subgroup, or a datagram.
    pub delivery: Delivery,
    /// The object id.
    pub object: u64,
    /// The payload in bytes. A zero-length object is reported with 0.
    pub size: u64,
    /// The first object the application publishes in this group.
    pub starts_group: bool,
    /// The first object in its subgroup.
    pub opens_subgroup: bool,
    /// The last object of the group.
    pub ends_group: bool,
}

/// An object status the producer sent in place of an object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Status {
    /// End of Group (drafts 07 to 23).
    EndOfGroup,
    /// End of Track (drafts 08 to 23).
    EndOfTrack,
    /// End of Track and Group (drafts 07 to 10).
    EndOfTrackAndGroup,
    /// End of Subgroup (draft 07).
    EndOfSubgroup,
    /// Object Does Not Exist (drafts 07 to 15).
    DoesNotExist,
}

/// A gap the producer declared on an object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Gap {
    /// Prior Group ID Gap: this many groups before the object's group do
    /// not exist (drafts 11 to 23).
    PriorGroups(u64),
    /// Prior Object ID Gap: this many objects before the object do not
    /// exist (drafts 14 to 23).
    PriorObjects(u64),
}

/// Why the monitor could not start or a connection could not be opened.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The source slug is not `[a-z0-9][a-z0-9._-]{0,63}`.
    #[error("source must match [a-z0-9][a-z0-9._-]{{0,63}}")]
    InvalidSource,
    /// The key is a browser key (`mqt_pk_`); servers use a source key (`mqt_sk_`).
    #[error(
        "this is a browser ingest key (mqt_pk_), for @moqtap/monitor-browser; a source needs a source key (mqt_sk_)"
    )]
    BrowserKey,
    /// The key is not a source key.
    #[error("the key is not a source key (mqt_sk_)")]
    InvalidKey,
    /// The endpoint is not an `https` origin, or an `http` one on a loopback host.
    #[error("the endpoint must be an https origin, or http on a loopback host")]
    InvalidEndpoint,
    /// The proxy, given or from `HTTPS_PROXY`, is not an `http` or `https` URL.
    #[error("the proxy must be an http or https URL")]
    InvalidProxy,
    /// The seal interval is outside [`MIN_SEAL_INTERVAL`] to [`MAX_SEAL_INTERVAL`].
    #[error("the seal interval must be 5 to 60 seconds")]
    InvalidSealInterval,
    /// The sampling target is outside 1 to [`MAX_SAMPLE_TARGET`] groups a second.
    #[error("the sampling target must be 1 to 1000000 groups a second")]
    InvalidSampleTarget,
    /// The relay URL is not an `https`, `http` or `moqt` URL.
    #[error("not a relay URL")]
    InvalidRelayUrl,
    /// Too many relay connections are open.
    #[error("too many relay connections are open")]
    TooManyConnections,
    /// The monitor has shut down.
    #[error("the monitor has shut down")]
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
    /// An id past 2^62 - 1 on a connection whose draft is 16 or earlier, a
    /// size or code past 2^53 - 1, a status or gap the connection's draft
    /// does not have, a draft outside 1 to 65535, a track name past MoQT's
    /// limits, or too many tracks.
    #[error("invalid report")]
    InvalidInput,
    /// The connection is closed, or the monitor has shut down.
    #[error("the connection is closed")]
    Closed,
}

/// Where the monitor stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum State {
    /// Collecting and uploading.
    Running,
    /// Ingest refused the key or the path (401, 403 or 404). The monitor
    /// keeps collecting and keeps the data, and sends the oldest body again
    /// every minute until it is accepted.
    Refused {
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
    /// Bytes of the bodies waiting.
    pub bytes_queued: usize,
    /// Bodies given up: past the buffer, refused for good by ingest, or not
    /// accepted at once with buffering off.
    pub bodies_lost: u64,
    /// Reports not sent: past a memory bound, or for a relay past the cap
    /// ([`Stats::over_relay_cap`]).
    pub dropped: u64,
    /// Of [`Stats::dropped`], reports not sent because their relay would
    /// have taken the source past [`MAX_RELAYS_PER_MONTH`] origins this month.
    pub over_relay_cap: u64,
    /// Reports refused as invalid or for a closed connection.
    pub rejected: u64,
}

/// Configures and starts a [`Monitor`].
pub struct MonitorBuilder {
    source: String,
    key: String,
    endpoint: String,
    proxy: Proxy,
    interval: Duration,
    interval_checked: bool,
    buffer_bytes: usize,
    retry_unit: Duration,
    app_clock: Option<AppClock>,
    sample_target: Option<u32>,
    clock: Option<TestClock>,
    roots: Option<Vec<Vec<u8>>>,
}

impl std::fmt::Debug for MonitorBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MonitorBuilder")
            .field("source", &self.source)
            .field("key", &"<redacted>")
            .field("endpoint", &self.endpoint)
            .field("proxy", &self.proxy)
            .field("seal_interval", &self.interval)
            .field("buffer_bytes", &self.buffer_bytes)
            .field("sample_target", &self.sample_target)
            .finish_non_exhaustive()
    }
}

impl MonitorBuilder {
    /// The ingest origin. Defaults to [`DEFAULT_ENDPOINT`].
    pub fn endpoint(mut self, origin: impl Into<String>) -> Self {
        self.endpoint = origin.into();
        self
    }

    /// How uploads reach the endpoint. Defaults to [`Proxy::FromEnv`]. Through
    /// a proxy, they go in an HTTP `CONNECT` tunnel, so the key is sent only
    /// inside it.
    pub fn proxy(mut self, proxy: Proxy) -> Self {
        self.proxy = proxy;
        self
    }

    /// How often a body is sealed and uploaded: 5 to 60 seconds, 15 by
    /// default. Ingest can ask for a shorter interval for a while, for
    /// example while someone watches a session this source feeds; it never
    /// makes it longer.
    pub fn seal_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self.interval_checked = true;
        self
    }

    /// The bytes of sealed bodies kept while ingest cannot be reached or
    /// refuses them. Defaults to [`DEFAULT_BUFFER_BYTES`]; past it, the
    /// oldest body is given up. 0 turns buffering off: a body that is not
    /// accepted at once is given up.
    pub fn buffer_bytes(mut self, bytes: usize) -> Self {
        self.buffer_bytes = bytes;
        self
    }

    /// An application clock synchronised to UTC, such as PTP: `clock`
    /// returns the time now as UTC µs since 1970 and its error bound in µs,
    /// or `None` when it has none. Used only when the viewer's times have an
    /// application clock too.
    pub fn app_clock(
        mut self,
        clock: impl Fn() -> Option<(i64, u64)> + Send + Sync + 'static,
    ) -> Self {
        self.app_clock = Some(Arc::new(clock));
        self
    }

    /// Report a sample of whole groups on fast tracks, aiming at more than
    /// `groups_per_sec` groups a second per track: 1 to
    /// [`MAX_SAMPLE_TARGET`]. Each upload states the groups it leaves out,
    /// and viewers' objects of those groups read as sampled. Without it,
    /// every group is reported.
    pub fn sample_target(mut self, groups_per_sec: u32) -> Self {
        self.sample_target = Some(groups_per_sec);
        self
    }

    #[doc(hidden)]
    pub fn test_timing(mut self, seal: Duration, retry_unit: Duration) -> Self {
        self.interval = seal.max(Duration::from_millis(10));
        self.interval_checked = false;
        self.retry_unit = retry_unit;
        self
    }

    /// Run on `clock` instead of the system's clocks and timers.
    #[doc(hidden)]
    pub fn test_clock(mut self, clock: &TestClock) -> Self {
        self.clock = Some(clock.clone());
        self
    }

    /// Trust only these root certificates (DER) for the endpoint and an
    /// `https` proxy, instead of the platform's verifier.
    #[doc(hidden)]
    pub fn test_roots(mut self, der: Vec<Vec<u8>>) -> Self {
        self.roots = Some(der);
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
        if self.interval_checked
            && !(MIN_SEAL_INTERVAL..=MAX_SEAL_INTERVAL).contains(&self.interval)
        {
            return Err(Error::InvalidSealInterval);
        }
        if self.sample_target.is_some_and(|t| !(1..=MAX_SAMPLE_TARGET).contains(&t)) {
            return Err(Error::InvalidSampleTarget);
        }
        let mut key = HeaderValue::from_str(&format!("Bearer {}", self.key))
            .map_err(|_| Error::InvalidKey)?;
        key.set_sensitive(true);
        let endpoint = endpoint_origin(&self.endpoint).ok_or(Error::InvalidEndpoint)?;
        let proxy = egress::route(&endpoint, &self.proxy, |name| std::env::var(name).ok())?;
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| Error::NoRuntime)?;
        let client = egress::client(proxy, self.roots.as_deref())
            .map_err(|e| Error::Setup(e.to_string()))?;
        let mut id = [0u8; 16];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut id)
            .map_err(|_| Error::Setup("system random source".into()))?;

        let clock = self.clock.map_or(Clock::System, Clock::Manual);
        let res_us = clock.resolution_us();
        let start = clock.now();
        let wall = clock.wall_us();
        let mut collector = Collector::new(self.interval.as_millis() as u64);
        collector.observe(0, wall);
        let shared = Arc::new(Shared {
            cfg: Config {
                source: self.source,
                instance_id: wire::hex(&id),
                key,
                endpoint,
                interval: self.interval,
                buffer_bytes: self.buffer_bytes,
                retry_unit: self.retry_unit,
                app_clock: self.app_clock,
                sample_target: self.sample_target,
                res_us,
                start_wall_ms: wall.unwrap_or(0).div_euclid(1000),
            },
            clock,
            start,
            collector: Mutex::new(collector),
            outbox: Mutex::new(Outbox::default()),
            seal_now: Notify::new(),
            send_now: Notify::new(),
            kick: Notify::new(),
            directive_changed: Notify::new(),
            shutting_down: AtomicBool::new(false),
            sealer_done: AtomicBool::new(false),
            shutdown: Notify::new(),
        });
        shared.clock.sealer_started();
        let sealer = runtime.spawn(upload::sealer(Arc::clone(&shared)));
        let sender = runtime.spawn(upload::sender(Arc::clone(&shared), client));
        Ok(Monitor { shared, sealer: Some(sealer), sender: Some(sender) })
    }
}

/// One source's monitor.
///
/// Call [`Monitor::shutdown`] before the process exits: it seals the final
/// body and sends what is buffered. Dropping the monitor only asks the
/// background tasks to finish, without waiting; whatever they have not sent
/// when the runtime stops is lost.
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
            proxy: Proxy::FromEnv,
            interval: DEFAULT_SEAL_INTERVAL,
            interval_checked: true,
            buffer_bytes: DEFAULT_BUFFER_BYTES,
            retry_unit: Duration::from_secs(1),
            app_clock: None,
            sample_target: None,
            clock: None,
            roots: None,
        }
    }

    /// A new relay connection. Only the URL's origin is kept: the path,
    /// query and userinfo never leave the process. A reconnect is a new
    /// connection.
    pub fn connection(&self, relay_url: &str) -> Result<Connection, Error> {
        let origin = relay::relay_origin(relay_url).ok_or(Error::InvalidRelayUrl)?;
        if self.shared.shutting_down.load(Ordering::SeqCst) {
            return Err(Error::Stopped);
        }
        let mono = self.shared.mono_us();
        let wall = self.shared.wall_us();
        let mut c = self.shared.collector();
        if c.stopped {
            return Err(Error::Stopped);
        }
        let first = c.observe(mono, wall);
        let (id, wake) = c.open(origin, mono).ok_or(Error::TooManyConnections)?;
        drop(c);
        if first == Wake::Seal || wake == Wake::Seal {
            self.shared.wake_sealer();
        }
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

    /// Seal the final body, then send everything buffered, waiting at most
    /// `timeout`. Call it before the process exits: whatever is unsent when
    /// the timeout passes is lost.
    pub async fn shutdown(mut self, timeout: Duration) -> Stats {
        self.signal_shutdown();
        let deadline = self.shared.clock.now() + timeout;
        for task in [self.sealer.take(), self.sender.take()].into_iter().flatten() {
            let abort = task.abort_handle();
            if self.shared.clock.until(deadline, task).await.is_none() {
                abort.abort();
            }
        }
        self.shared.outbox().state = State::ShutDown;
        stats(&self.shared)
    }

    fn signal_shutdown(&self) {
        self.shared.shutting_down.store(true, Ordering::SeqCst);
        self.shared.shutdown.notify_one();
        self.shared.kick.notify_one();
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
    let rejected = shared.collector().rejected;
    let o = shared.outbox();
    Stats {
        state: o.state,
        bodies_sent: o.sent,
        bodies_queued: o.queue.len(),
        bytes_queued: o.bytes,
        bodies_lost: o.lost,
        dropped: o.dropped,
        over_relay_cap: o.over_relay_cap,
        rejected,
    }
}

/// One relay connection of the source. Closed when dropped.
///
/// Track names are byte strings: the namespace fields and the track name
/// exactly as the MoQ library sends them, which must be what viewers
/// subscribe to. `&str` names work as they are.
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
    /// The MoQT draft the connection negotiated, when known. It decides
    /// which ids, statuses and gaps the connection takes.
    pub fn set_draft(&self, draft: u64) -> Result<(), Rejected> {
        self.call(None, |c, _| c.set_draft(self.id, draft))
    }

    /// Report one object, once per connection, as it is handed to the MoQ
    /// library; each call is one publication, even with the same ids. `at`
    /// is the handoff time, now when `None`.
    pub fn object_sent<N: AsRef<[u8]>>(
        &self,
        namespace: &[N],
        track: impl AsRef<[u8]>,
        sent: Sent,
        at: Option<Instant>,
    ) -> Result<(), Rejected> {
        let h = Handoff {
            g: sent.group,
            sub: match sent.delivery {
                Delivery::Subgroup(s) => Some(s),
                Delivery::Datagram => None,
            },
            o: sent.object,
            size: sent.size,
            starts_group: sent.starts_group,
            opens_subgroup: sent.opens_subgroup,
            ends_group: sent.ends_group,
        };
        self.call(at, |c, at_us| c.object_sent(self.id, namespace, track.as_ref(), h, at_us))
    }

    /// Report an object status sent in place of object `object` of `group`.
    /// A status the connection's draft does not have is refused.
    pub fn status_sent<N: AsRef<[u8]>>(
        &self,
        namespace: &[N],
        track: impl AsRef<[u8]>,
        group: u64,
        object: u64,
        status: Status,
        at: Option<Instant>,
    ) -> Result<(), Rejected> {
        let kind = match status {
            Status::EndOfGroup => MarkKind::Eog,
            Status::EndOfTrack => MarkKind::Eot,
            Status::EndOfTrackAndGroup => MarkKind::Eotg,
            Status::EndOfSubgroup => MarkKind::Eosg,
            Status::DoesNotExist => MarkKind::Dne,
        };
        self.call(at, |c, t| c.mark(self.id, namespace, track.as_ref(), kind, group, object, 0, t))
    }

    /// Report a gap declared on object `object` of `group`. A gap the
    /// connection's draft does not have is refused.
    pub fn gap_sent<N: AsRef<[u8]>>(
        &self,
        namespace: &[N],
        track: impl AsRef<[u8]>,
        group: u64,
        object: u64,
        gap: Gap,
    ) -> Result<(), Rejected> {
        let (kind, n) = match gap {
            Gap::PriorGroups(n) => (MarkKind::Pgg, n),
            Gap::PriorObjects(n) => (MarkKind::Pog, n),
        };
        self.call(None, |c, t| {
            c.mark(self.id, namespace, track.as_ref(), kind, group, object, n, t)
        })
    }

    /// A data stream of `track` was reset with `code`.
    pub fn stream_reset<N: AsRef<[u8]>>(
        &self,
        namespace: &[N],
        track: impl AsRef<[u8]>,
        code: u64,
    ) -> Result<(), Rejected> {
        self.event(Some((namespace, track.as_ref())), EventKind::StreamReset, code)
    }

    /// A request on the connection failed with `code`.
    pub fn request_error(&self, code: u64) -> Result<(), Rejected> {
        self.event::<&[u8]>(None, EventKind::RequestError, code)
    }

    /// A request for `track` failed with `code`.
    pub fn track_request_error<N: AsRef<[u8]>>(
        &self,
        namespace: &[N],
        track: impl AsRef<[u8]>,
        code: u64,
    ) -> Result<(), Rejected> {
        self.event(Some((namespace, track.as_ref())), EventKind::RequestError, code)
    }

    /// Publishing `track` on this connection ended with status `code`.
    pub fn publish_done<N: AsRef<[u8]>>(
        &self,
        namespace: &[N],
        track: impl AsRef<[u8]>,
        code: u64,
    ) -> Result<(), Rejected> {
        self.event(Some((namespace, track.as_ref())), EventKind::PublishDone, code)
    }

    /// Close the connection, with the session's close code when known. A
    /// code past 2^53 - 1 is refused; the connection closes without it.
    pub fn close(mut self, code: Option<u64>) -> Result<(), Rejected> {
        self.close_inner(code)
    }

    fn event<N: AsRef<[u8]>>(
        &self,
        track: Option<(&[N], &[u8])>,
        e: EventKind,
        code: u64,
    ) -> Result<(), Rejected> {
        self.call(None, |c, t| c.event(self.id, track, e, Some(code), t))
    }

    /// Run `f` on the collector with the call's time, after the clock check.
    fn call(
        &self,
        at: Option<Instant>,
        f: impl FnOnce(&mut Collector, i64) -> Result<Wake, Refused>,
    ) -> Result<(), Rejected> {
        let mono = self.shared.mono_us();
        let at_us = at.map_or(mono, |a| self.shared.mono_of(a));
        let wall = self.shared.wall_us();
        let (first, r) = {
            let mut c = self.shared.collector();
            let first = c.observe(mono, wall);
            (first, f(&mut c, at_us))
        };
        if first == Wake::Seal || r == Ok(Wake::Seal) {
            self.shared.wake_sealer();
        }
        r.map(drop).map_err(rejected)
    }

    fn close_inner(&mut self, code: Option<u64>) -> Result<(), Rejected> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let id = self.id;
        self.call(None, |c, t| c.close(id, code, t))
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
    async fn the_configuration_is_checked_before_anything_starts() {
        let start = |k: &str| Monitor::builder("enc", k).start().map(|_| ());
        assert!(matches!(start("mqt_pk_abc"), Err(Error::BrowserKey)));
        assert!(Error::BrowserKey.to_string().contains("@moqtap/monitor-browser"));
        assert!(matches!(start("sk_abc"), Err(Error::InvalidKey)));
        assert!(matches!(start("mqt_sk_a b"), Err(Error::InvalidKey)));
        assert!(matches!(Monitor::builder("Enc", "mqt_sk_x").start(), Err(Error::InvalidSource)));
        let e = Monitor::builder("enc", "mqt_sk_x").endpoint("http://example.com").start();
        assert!(matches!(e, Err(Error::InvalidEndpoint)));
        for bad in [Duration::from_secs(4), Duration::from_secs(61)] {
            let e = Monitor::builder("enc", "mqt_sk_x").seal_interval(bad).start();
            assert!(matches!(e, Err(Error::InvalidSealInterval)), "{bad:?}");
        }
        for bad in [0, MAX_SAMPLE_TARGET + 1] {
            let e = Monitor::builder("enc", "mqt_sk_x").sample_target(bad).start();
            assert!(matches!(e, Err(Error::InvalidSampleTarget)), "{bad}");
        }
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

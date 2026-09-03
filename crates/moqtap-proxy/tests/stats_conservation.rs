//! Two claims about the shaping statistics, driven by real traffic through
//! a real proxy: that every byte the shaper saw is charged to exactly one
//! row, and that the four cells of the per-leg matrix hold what they say
//! they hold.
//!
//! The two are separate claims and neither implies the other. Conservation
//! is arithmetic over the class rows and is blind to which connection a byte
//! crossed — a proxy that charged every byte to one leg satisfies it
//! perfectly. Attribution is about *where* a figure landed and says nothing
//! about whether the totals add up — a proxy that mislaid a third of its
//! bytes can still put the two thirds it kept in the right cells. So the
//! file gates them separately, with fixtures built for different things: the
//! conservation fixture loads every term of the sum and does not care what
//! the numbers are, and the attribution fixture makes all four cells carry
//! different numbers and does not care whether they add up.
//!
//! # Conservation is an equality, never a bound
//!
//! `Σ classes(bytes_delivered + bytes_dropped) + default_class + unshapeable
//! == bytes_shaped`. Written as an equality because the two ways it can break
//! point in opposite directions and each has a bound that hides it. A row that
//! stops being charged leaves the summed rows *short* of `bytes_shaped`, which
//! `charged <= bytes_shaped` admits. A byte counted twice in the rows, or a
//! term that stops entering `bytes_shaped`, leaves them *over*, which
//! `charged >= bytes_shaped` admits. The second ablation recorded on
//! [`bytes_are_conserved_on_one_session`] is measurably of the second kind —
//! the rows came out fifteen bytes above `bytes_shaped` — so a gate written
//! with a lower bound would have reported it green.
//!
//! ## The two exceptions are excluded by construction, not tolerated
//!
//! The identity has two documented holes, and a fixture that merely widened
//! the assertion to accommodate them would be gating nothing. Both are
//! properties of the *run*, so both are removed by building a run
//! that cannot produce them:
//!
//! * **A `STOP_SENDING`-driven teardown clears its queue rather than
//!   draining it**, leaving bytes that are neither delivered nor dropped.
//!   Nothing here sends `STOP_SENDING`: every destination stream is read to
//!   its FIN by a live reader that is not dropped until after the figures
//!   have been taken, and the fixture asserts each of them ended
//!   `Ending::Fin`. A `RecvStream` dropped early is the way a test sends one
//!   of these by accident, which is why the readers are held.
//! * **A hook action that changes a unit's size** is charged in full on the
//!   left and by what it actually wrote on the right. The conservation
//!   fixture's hook returns exactly two actions — `Action::Hold { then:
//!   Pass }` on the head of each stream and `Action::Pass` on everything
//!   else. Neither touches a byte. `Replace`, `ReplacePayload`, `Truncate`
//!   and `Drop` are not merely unused: the hook has no arm that can return
//!   one.
//!
//! What the fixture *does* keep is `Overflow::DropTail`, because a discarded
//! byte is a term of the identity rather than an exception to it: it moves
//! from `bytes_delivered` to `bytes_dropped` and the sum is unchanged. A
//! conservation gate whose `bytes_dropped` term is identically zero is
//! four-fifths of a gate.
//!
//! # What "across the seam" means
//!
//! A proxy holds two connections and a byte crosses both — read on one leg,
//! written on the other. [`ProxyStats::per_leg`] is measured at the crossing,
//! so the bytes a session *saw* are spread over two cells: what arrived from
//! the client and what arrived from the relay. The class rows carry no leg at
//! all. So the proxy-wide form of the identity has to sum both legs' arrival
//! cells to get the figure the rows are compared against, and that is what
//! [`the_identity_closes_when_the_rows_are_added_across_the_seam`] does. It is
//! not the same assertion as the session's: the two recorders are charged by
//! the same calls but stored separately, and only the proxy's has a leg axis
//! to be wrong about.
//!
//! The two arrival cells and not all four. A byte that entered and left has
//! been measured at both crossings, so a `bytes_shaped` summed over the whole
//! matrix would be about twice what the rows account for — which is a mistake
//! that reads perfectly plausibly, since "add up every cell" is what a matrix
//! invites.
//!
//! # The flat rollup is deliberately not asserted anywhere in this file
//!
//! [`ProxyStats::sessions`] is **derived** at snapshot time from the same
//! cells and the same rows every assertion below reads. Asserting that it
//! equals the sum of its parts would be asserting `a + b == a + b`: there is
//! no implementation of `ProxyRecorder::snapshot` that computes the sum and
//! then disagrees with it, so no mutation could redden such a row and it
//! would be a green line that measures nothing. If a later change gives
//! `SessionStats` storage of its own, that stops being true and the
//! assertion becomes worth writing — until then, do not add one.
//!
//! # Nothing here is a timing claim
//!
//! Every wait is [`wait_until`] on a monotone quantity a correct
//! implementation always reaches, or `TimedReceiver::wait_for_ending`. Load
//! makes them slower and never wrong; their timeouts are failure ceilings so
//! a broken build names the claim it was waiting on instead of hanging.
//!
//! The one number that could in principle be raced is
//! [`CONSERVE_MAX_HOLD`]: the conservation fixture keeps its queues full by
//! holding each stream's head on a [`Gate`] the test owns, and a queue whose
//! hold expired before the test released it would drain early and drop
//! nothing. The hold is five seconds and the anchor it has to outlast is
//! "twenty-six objects have been classified", which is milliseconds of
//! loopback work — three orders of magnitude of margin, one-sided, since load
//! can only make the anchor later and never the hold shorter. Widen it if it
//! ever fails; do not delete it and do not replace the anchor with a sleep.
//!
//! # Setup failures are not gate failures
//!
//! Binding a socket, generating a certificate and completing a handshake can
//! fail for reasons that have nothing to do with a counter. Every one of
//! those is an `expect` whose message begins with `fixture:`; every assertion
//! about a statistic names what the proxy did.

#![cfg(any(
    feature = "draft07",
    feature = "draft08",
    feature = "draft09",
    feature = "draft10",
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20"
))]

mod common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use moqtap_codec::dispatch::{AnySubgroupHeader, AnySubgroupObject, AnySubgroupObjectWriter};
use moqtap_codec::version::DraftVersion;

use moqtap_proxy::action::{Action, DropMode, Gate, Interest};
use moqtap_proxy::control::ProxyControl;
use moqtap_proxy::event::ProxySide;
use moqtap_proxy::hook::{ObjectCtx, ProxyHook};
use moqtap_proxy::listener::ListenerConfig;
use moqtap_proxy::observer::{NoOpProxyObserver, ProxyObserver};
use moqtap_proxy::proxy::{ProxyConfig, TransparentProxy};
use moqtap_proxy::session::ProxySessionConfig;
use moqtap_proxy::shape::{
    BucketConfig, ClassRule, ClassStats, DirectionStats, Discipline, LegStats, Matcher, Overflow,
    ProxyStats, QueueConfig, RangeSet, ShapeProfile, ShapeStats,
};
use moqtap_proxy::transport::Leg;

use common::{Ending, FakeRelay, SpawnedProxy, TimedReceiver};

/// Every draft this build compiled, oldest first. Each element carries its
/// own `#[cfg]`, so the array is the enabled set; the file-level gate above
/// guarantees it is non-empty, which makes [`DRAFT`]'s index a compile-time
/// fact rather than a panic.
const COMPILED_DRAFTS: &[DraftVersion] = &[
    #[cfg(feature = "draft07")]
    DraftVersion::Draft07,
    #[cfg(feature = "draft08")]
    DraftVersion::Draft08,
    #[cfg(feature = "draft09")]
    DraftVersion::Draft09,
    #[cfg(feature = "draft10")]
    DraftVersion::Draft10,
    #[cfg(feature = "draft11")]
    DraftVersion::Draft11,
    #[cfg(feature = "draft12")]
    DraftVersion::Draft12,
    #[cfg(feature = "draft13")]
    DraftVersion::Draft13,
    #[cfg(feature = "draft14")]
    DraftVersion::Draft14,
    #[cfg(feature = "draft15")]
    DraftVersion::Draft15,
    #[cfg(feature = "draft16")]
    DraftVersion::Draft16,
    #[cfg(feature = "draft17")]
    DraftVersion::Draft17,
    #[cfg(feature = "draft18")]
    DraftVersion::Draft18,
    #[cfg(feature = "draft19")]
    DraftVersion::Draft19,
    #[cfg(feature = "draft20")]
    DraftVersion::Draft20,
];

/// The draft every fixture here is built for: the **newest** one this build
/// compiled.
///
/// Derived rather than named, for the reason `actions_shaping.rs` states: a
/// hardcoded draft makes every single-draft build red, because the fixture's
/// header bytes decode against the draft the session was configured with.
const DRAFT: DraftVersion = COMPILED_DRAFTS[COMPILED_DRAFTS.len() - 1];

/// The ALPN the clients and the fake relays speak.
///
/// `moq-00` leaves `draft_is_fixed` false, which only affects the control
/// parser — nothing in this file opens a control stream.
const ALPN: &[u8] = b"moq-00";

/// How long an anchored poll waits before declaring the run broken.
const PATIENCE: Duration = Duration::from_secs(10);

// ── media, encoded independently of the proxy ──────────────────────────

/// The stream-type field [`DRAFT`] opens a subgroup stream with, for a
/// header carrying an **explicit** Subgroup ID.
///
/// Restated rather than taken from the crate under test — this is a separate
/// test binary, and a shared encoder would leave these gates comparing the
/// proxy against its own output.
fn subgroup_stream_type(draft: DraftVersion) -> u8 {
    match draft {
        DraftVersion::Draft07
        | DraftVersion::Draft08
        | DraftVersion::Draft09
        | DraftVersion::Draft10 => 0x04,
        DraftVersion::Draft11 => 0x0C,
        _ => 0x14,
    }
}

/// A subgroup stream header on `track_alias`: group 0, subgroup 0, publisher
/// priority `0x80`. Five bytes on every draft 07-20.
fn subgroup_header_bytes(track_alias: u64) -> Vec<u8> {
    assert!(track_alias < 64, "fixture: single-byte varint only");
    vec![subgroup_stream_type(DRAFT), track_alias as u8, 0x00, 0x00, 0x80]
}

/// The subgroup stream header's length, on every draft 07-20.
fn header_len() -> usize {
    subgroup_header_bytes(0).len()
}

/// A whole [`DRAFT`] subgroup stream on `track_alias`: the header and `count`
/// objects of `payload_len` bytes each.
///
/// One writer and one pass, because Object IDs are delta-encoded on drafts
/// 14-20 and encoding the objects independently would encode each delta
/// against nothing.
fn subgroup_stream(track_alias: u64, count: u64, payload_len: usize) -> Vec<u8> {
    let head = subgroup_header_bytes(track_alias);
    let mut cursor = &head[..];
    let header = AnySubgroupHeader::decode_stream(DRAFT, &mut cursor)
        .expect("fixture: the subgroup header must decode or nothing below is media");
    let mut writer =
        AnySubgroupObjectWriter::new(&header).expect("fixture: subgroup object writer");

    let mut out = head;
    for object_id in 0..count {
        let fill = u8::try_from(0xA0 + object_id % 0x40).expect("fixture: fill byte");
        let obj = AnySubgroupObject {
            object_id,
            extension_headers: Vec::new(),
            extension_count: None,
            status: None,
            payload: vec![fill; payload_len],
        };
        writer.write_object(&obj, &mut out).expect("fixture: write object");
    }
    out
}

/// The wire size of one object in a stream [`subgroup_stream`] built.
///
/// Measured rather than computed from the payload length, because the wire
/// size carries an object id, an extension count and a payload length as
/// well. The divisibility check is what makes "one object is `n` bytes" a
/// fact about this stream rather than an assumption: a run in which the
/// objects were *not* all the same size would make every count below a count
/// of something else, and it would do so silently.
fn object_size(stream: &[u8], count: u64) -> usize {
    let body = stream.len() - header_len();
    assert_eq!(
        body % count as usize,
        0,
        "fixture: {count} objects do not divide {body} body bytes evenly, so no single object \
         size describes this stream"
    );
    body / count as usize
}

// ── anchors ────────────────────────────────────────────────────────────

/// Poll `ready` until it answers `true`, or fail naming what was awaited.
///
/// A *liveness* anchor, never a deadline: every caller below waits for a
/// monotone quantity a correct implementation always reaches, so load makes
/// this slower and never wrong. The timeout is a failure ceiling — it exists
/// so a broken build reports the claim it was waiting on rather than hanging.
async fn wait_until(mut ready: impl FnMut() -> bool, what: &str) {
    let deadline = Instant::now() + PATIENCE;
    loop {
        if ready() {
            return;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

// ── the two topologies ─────────────────────────────────────────────────

/// A proxy config bound to an ephemeral port and pointed at `upstream`.
///
/// Port 0 deliberately: the port is chosen inside `run()` and read back
/// through [`ProxyControl::local_addr`], which is what the client connects
/// to.
fn proxy_config(session: ProxySessionConfig) -> ProxyConfig {
    let (cert_chain, key_der) = common::self_signed_localhost();
    ProxyConfig {
        listener: ListenerConfig {
            bind_addr: "127.0.0.1:0".parse().expect("fixture: a literal address"),
            cert_chain,
            key_der,
            transport_config: None,
            transport_profile: None,
            installer: None,
            #[cfg(feature = "qlog")]
            qlog: None,
        },
        session,
    }
}

/// A session config for [`DRAFT`] carrying `profile`, with `max_hold` pinned.
///
/// Both `max_hold` knobs are assigned rather than inherited. The 30 s default
/// would make every margin in this file a margin the file never wrote down,
/// and `EgressConfig`'s is the one a held unit races.
fn shaped_session(
    upstream: SocketAddr,
    profile: ShapeProfile,
    max_hold: Duration,
) -> ProxySessionConfig {
    let mut config = common::session_config(DRAFT, upstream);
    // Field assignment, not a struct literal: `EgressConfig` is
    // `#[non_exhaustive]`, which forbids literal construction from a test
    // crate.
    config.egress.max_hold = max_hold;
    config.shape = Some(profile);
    config
}

/// One `ProxySession`, driven directly — the topology that can report a
/// session's own [`ShapeStats`].
///
/// A directly-driven session belongs to no control plane, so it has no
/// [`ProxyStats`] at all. That is the point of having both topologies here:
/// this one is the only way to read the per-session recorder, and
/// [`ProxyRun`] is the only way to read the proxy-wide one.
struct SessionRun {
    proxy: SpawnedProxy,
    client: quinn::Connection,
    _client_ep: quinn::Endpoint,
    relay: Arc<FakeRelay>,
}

impl SessionRun {
    /// Stand the topology up with `profile` configured and `hook` attached.
    async fn start(profile: ShapeProfile, hook: Arc<dyn ProxyHook>, max_hold: Duration) -> Self {
        common::init_crypto();
        let relay = Arc::new(FakeRelay::bind(ALPN));
        let proxy = common::spawn_proxy_with(
            shaped_session(relay.addr, profile, max_hold),
            ALPN,
            Arc::new(NoOpProxyObserver) as Arc<dyn ProxyObserver>,
            hook,
        );
        let (client_ep, client) =
            tokio::time::timeout(PATIENCE, common::connect_client(proxy.addr, ALPN))
                .await
                .expect("fixture: the client handshake completed");
        tokio::time::timeout(PATIENCE, relay.connection())
            .await
            .expect("fixture: the proxy dialled the relay");
        Self { proxy, client, _client_ep: client_ep, relay }
    }

    fn shape(&self) -> ShapeStats {
        self.proxy.shape_stats()
    }

    async fn finish(self) {
        self.client.close(0u32.into(), b"done");
        self.proxy.shutdown().await;
    }
}

/// A whole [`TransparentProxy`] with one client connected — the topology that
/// can report [`ProxyStats`].
///
/// The accept loop is what attaches a session to a control plane, and the
/// control plane is what owns the proxy-wide recorder. A session built by
/// `ProxySession::new` and run directly, as [`SessionRun`] does, reports into
/// nothing proxy-wide, so this fixture cannot be replaced by that one.
struct ProxyRun {
    proxy: Arc<TransparentProxy>,
    control: ProxyControl,
    client: quinn::Connection,
    /// Held, not used: a `quinn::Endpoint` dropped out from under its
    /// connection takes the connection with it.
    _client_ep: quinn::Endpoint,
    /// Held beyond its use, because dropping it stops the endpoint accepting.
    relay: Arc<FakeRelay>,
    loop_task: tokio::task::JoinHandle<()>,
}

impl ProxyRun {
    /// Stand the topology up with `profile` configured and `hook` attached.
    async fn start(profile: ShapeProfile, hook: Arc<dyn ProxyHook>, max_hold: Duration) -> Self {
        common::init_crypto();
        let relay = Arc::new(FakeRelay::bind(ALPN));

        let proxy = Arc::new(TransparentProxy::with_hook(
            proxy_config(shaped_session(relay.addr, profile, max_hold)),
            Arc::new(NoOpProxyObserver) as Arc<dyn ProxyObserver>,
            hook,
        ));
        let control = proxy.control();
        let running = Arc::clone(&proxy);
        let loop_task = tokio::spawn(async move {
            let _ = running.run().await;
        });

        let mut addr = None;
        wait_until(
            || {
                addr = control.local_addr().ok();
                addr.is_some()
            },
            "fixture: the proxy to bind",
        )
        .await;
        let addr = addr.expect("fixture: the bound address");

        let (client_ep, client) =
            tokio::time::timeout(PATIENCE, common::connect_client(addr, ALPN))
                .await
                .expect("fixture: the client handshake completed");
        tokio::time::timeout(PATIENCE, relay.connection())
            .await
            .expect("fixture: the proxy dialled the relay");

        Self { proxy, control, client, _client_ep: client_ep, relay, loop_task }
    }

    fn stats(&self) -> ProxyStats {
        self.control.stats()
    }

    async fn finish(self) {
        self.client.close(0u32.into(), b"done");
        self.proxy.cancel_token().cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), self.loop_task).await;
        drop(self.relay);
    }
}

// ── gate one: conservation ─────────────────────────────────────────────

/// The bucket every conservation class charges against.
const CONSERVE_BUCKET: &str = "media";
/// The class claiming the client's shaped stream.
const CONSERVE_UP_CLASS: &str = "up";
/// The class claiming the relay's stream.
const CONSERVE_DOWN_CLASS: &str = "down";
/// Track alias of the client's stream that a rule claims.
const CONSERVE_UP_ALIAS: u64 = 11;
/// Track alias of the relay's stream, which the other rule claims.
const CONSERVE_DOWN_ALIAS: u64 = 12;
/// Track alias of the client's second stream, which no rule names — the
/// `default_class` term.
const CONSERVE_LOOSE_ALIAS: u64 = 13;

/// Objects the three conservation streams offer.
///
/// Three different counts so a term that leaked into a neighbouring row
/// changes an object total rather than cancelling out.
const CONSERVE_UP_OBJECTS: u64 = 12;
/// Objects on the unclaimed stream.
const CONSERVE_LOOSE_OBJECTS: u64 = 8;
/// Objects on the relay's stream.
const CONSERVE_DOWN_OBJECTS: u64 = 6;

/// Every object the conservation fixture offers, over all three streams.
const CONSERVE_OBJECTS: u64 = CONSERVE_UP_OBJECTS + CONSERVE_LOOSE_OBJECTS + CONSERVE_DOWN_OBJECTS;

/// Streams the conservation fixture opens, which is also the number of stream
/// headers that land in the `unshapeable` row.
const CONSERVE_STREAMS: u64 = 3;

/// Objects one conservation queue may hold.
const CONSERVE_DEPTH: usize = 4;

/// The payload every conservation object carries.
///
/// **Above the pipe's 8 KiB read buffer, and that is arithmetic rather than
/// taste.** `pipe_data_framed` drains the framer of everything one read
/// delivered before it consults admission again, so a queue overshoots its
/// depth by however many whole objects one read can carry. At a wire size
/// above the buffer that overshoot is zero and the number of objects the
/// queue admits is the depth exactly. Below it, admission and read batching
/// become indistinguishable and the drop count stops being a property of the
/// profile.
///
/// `ADMIT_PAYLOAD` in `actions_shaping.rs` carries the full derivation; this
/// is the same number for the same reason. Widen it, do not shrink it.
const CONSERVE_PAYLOAD: usize = 9000;

/// How long a held head may wait before the queue delivers it anyway.
///
/// Five seconds against an anchor — twenty-six objects classified over
/// loopback — that takes milliseconds. One-sided: load makes the anchor
/// later, never the hold shorter. Widen it if it ever fails; do not delete
/// it.
const CONSERVE_MAX_HOLD: Duration = Duration::from_secs(5);

/// Holds the **first** object of every stream on one [`Gate`] the test owns,
/// and passes everything else.
///
/// This is how the fixture shuts every drain at once without touching the
/// engine: the head unit gates everything behind it, so each queue fills at
/// line rate and admission is the only thing that decides what happens to the
/// rest. Nothing here is a timing claim — the gate is released by the test,
/// not by a clock.
///
/// Keyed on `(side, stream_id)` and not on `stream_id` alone. The two legs
/// mint unidirectional stream ids from the same sequence, so a client stream
/// and a relay stream routinely carry the same id, and a hook that kept only
/// the id would hold one leg's head and let the other's through — which would
/// leave the downlink queue draining as fast as it filled and the `down`
/// class with nothing dropped.
///
/// The two actions it can return are `Action::Hold { then: Pass }` and
/// `Action::Pass`, and there is no third arm. That is what excludes a
/// size-changing action from this fixture by construction rather than by
/// convention.
struct HeadHoldingHook {
    gate: Gate,
    held: Mutex<Vec<(ProxySide, u64)>>,
}

impl HeadHoldingHook {
    fn new() -> Arc<Self> {
        Arc::new(Self { gate: Gate::new(), held: Mutex::new(Vec::new()) })
    }

    /// Let every held head go.
    fn release(&self) {
        self.gate.release();
    }
}

impl ProxyHook for HeadHoldingHook {
    fn interest(&self) -> Interest {
        Interest::OBJECTS
    }

    fn on_object(&self, cx: &ObjectCtx<'_>, _raw: &[u8]) -> Action {
        let mut held = self.held.lock().expect("held");
        let key = (cx.side, cx.stream_id);
        if held.contains(&key) {
            Action::Pass
        } else {
            held.push(key);
            Action::Hold { gate: self.gate.clone(), then: Box::new(Action::Pass) }
        }
    }
}

/// Two classes keyed on track alias over one unlimited bucket, with a queue
/// that discards its tail.
///
/// `rate_bps: None` on purpose: this fixture is about *accounting*, and a
/// rate-limited bucket would make the drop count a function of a clock. The
/// depth limit is the only thing that decides what is discarded, and the
/// holding hook is what makes the depth limit bite.
fn conservation_profile() -> ShapeProfile {
    let mut bucket = BucketConfig::default();
    bucket.name = CONSERVE_BUCKET.to_string();
    bucket.rate_bps = None;

    let mut queue = QueueConfig::default();
    queue.depth_objects = CONSERVE_DEPTH;
    queue.max_hold = Some(CONSERVE_MAX_HOLD);
    queue.overflow = Overflow::DropTail;

    ShapeProfile::try_new(
        vec![bucket],
        vec![
            alias_class(CONSERVE_UP_CLASS, CONSERVE_UP_ALIAS),
            alias_class(CONSERVE_DOWN_CLASS, CONSERVE_DOWN_ALIAS),
        ],
        queue,
        Discipline::Fifo,
    )
    .expect("fixture: two uniquely-named classes over one configured bucket")
}

/// A class rule claiming one track alias, charged to [`CONSERVE_BUCKET`].
fn alias_class(name: &str, alias: u64) -> ClassRule {
    let mut class = ClassRule::default();
    class.name = name.to_string();
    class.bucket = CONSERVE_BUCKET.to_string();
    // Field assignment over `..Default::default()`: `Matcher` is
    // `#[non_exhaustive]`, which forbids struct-expression construction from
    // this crate.
    let mut matcher = Matcher::default();
    matcher.track_alias = Some(RangeSet::single(alias));
    class.matcher = matcher;
    class
}

/// The five figures the conservation identity is written over, read from
/// whichever recorder the caller is gating.
///
/// One type for both recorders because the identity is one claim. What
/// differs between them is only where `bytes_shaped` comes from — a session
/// keeps one flat total, a proxy keeps a cell per leg per direction — and
/// [`Self::from_proxy`] is where that difference is written down.
struct Rows {
    classes: Vec<ClassStats>,
    default_class: ClassStats,
    unshapeable: ClassStats,
    /// Every byte the shaper accounted for.
    bytes_shaped: u64,
    /// Hook-visible units the classifier saw. Objects only: a stream header
    /// is in `bytes_shaped` and in `unshapeable`, and is not an object.
    objects_seen: u64,
}

impl Rows {
    /// One session's own recorder.
    fn from_session(stats: &ShapeStats) -> Self {
        Self {
            classes: stats.classes.clone(),
            default_class: stats.default_class.clone(),
            unshapeable: stats.unshapeable.clone(),
            bytes_shaped: stats.bytes_shaped,
            objects_seen: stats.objects_seen,
        }
    }

    /// The proxy-wide recorder, **summed across both legs**.
    ///
    /// The two *arrival* cells: what this proxy read from the client and what
    /// it read from the relay. Those are the two points a byte enters, where
    /// each byte is counted exactly once, and they are the figure the class
    /// rows — which carry no leg — have to be compared against.
    ///
    /// Not all four cells. A byte that entered and left has been measured at
    /// both crossings, so a total summed over the whole matrix would be about
    /// twice what the rows account for. Not [`ProxyStats::sessions`] either,
    /// and that is the file docstring's point rather than an oversight: that
    /// field is derived from these same cells at snapshot time, so reading it
    /// here would make the identity depend on a sum this file also wanted to
    /// check.
    fn from_proxy(stats: &ProxyStats) -> Self {
        let from_client = stats.leg(Leg::Client).uplink();
        let from_relay = stats.leg(Leg::Upstream).downlink();
        Self {
            classes: stats.classes.clone(),
            default_class: stats.default_class.clone(),
            unshapeable: stats.unshapeable.clone(),
            bytes_shaped: from_client.bytes_shaped + from_relay.bytes_shaped,
            objects_seen: from_client.objects_seen + from_relay.objects_seen,
        }
    }

    /// One side of the identity: every byte the rows account for.
    fn charged(&self) -> u64 {
        self.classes
            .iter()
            .chain([&self.default_class, &self.unshapeable])
            .map(|row| row.bytes_delivered + row.bytes_dropped)
            .sum()
    }

    /// The row a class name was configured for.
    fn named(&self, name: &str) -> &ClassStats {
        self.classes
            .iter()
            .find(|row| row.name == name)
            .unwrap_or_else(|| panic!("no row named {name}: {:?}", self.classes))
    }
}

/// Offer the conservation fixture's traffic and hand back the rows once every
/// stream has run to completion.
///
/// Three streams, two of them from the client and one from the relay, so the
/// figures the identity is taken over span both legs. Each source is finished
/// the moment it has been written: a stream that never FINs leaves its queue
/// unresolved, and "ran to completion" is the precondition the identity is
/// stated under.
///
/// `rows` is read repeatedly rather than once, because it is both the anchor
/// and the answer — the caller supplies whichever recorder it is gating.
async fn offer_the_conservation_traffic(
    client: &quinn::Connection,
    relay: &Arc<FakeRelay>,
    hook: &Arc<HeadHoldingHook>,
    rows: impl Fn() -> Rows,
) -> Rows {
    let up = subgroup_stream(CONSERVE_UP_ALIAS, CONSERVE_UP_OBJECTS, CONSERVE_PAYLOAD);
    let loose = subgroup_stream(CONSERVE_LOOSE_ALIAS, CONSERVE_LOOSE_OBJECTS, CONSERVE_PAYLOAD);
    let down = subgroup_stream(CONSERVE_DOWN_ALIAS, CONSERVE_DOWN_OBJECTS, CONSERVE_PAYLOAD);

    for stream in [&up, &loose] {
        let mut send = client.open_uni().await.expect("fixture: the client opened a stream");
        send.write_all(stream).await.expect("fixture: the client wrote its stream");
        send.finish().expect("fixture: the client finished its stream");
    }
    let mut down_send = relay.open_uni().await;
    down_send.write_all(&down).await.expect("fixture: the relay wrote its stream");
    down_send.finish().expect("fixture: the relay finished its stream");

    // Every destination is read by a live reader that outlives the figures
    // below. A `RecvStream` dropped early sends `STOP_SENDING`, and a
    // `STOP_SENDING` is one of the two cases the identity does not cover — so
    // holding these is what excludes that case rather than tolerating it.
    let up_rx = tokio::time::timeout(PATIENCE, relay.timed_uni_n(2))
        .await
        .expect("fixture: the proxy opened a destination stream for each client stream");
    let down_recv = tokio::time::timeout(PATIENCE, client.accept_uni())
        .await
        .expect("fixture: the proxy opened a destination stream towards the client")
        .expect("fixture: the client accepted it");
    let down_rx = TimedReceiver::spawn(down_recv);

    // The queues must be full *before* the gate opens, or nothing overflows
    // and the `bytes_dropped` term of the identity is identically zero.
    // Anchored on classification, which is strictly earlier than release.
    wait_until(|| rows().objects_seen == CONSERVE_OBJECTS, "every offered object to be classified")
        .await;

    hook.release();

    // The anchor is the **wire**, and deliberately not any figure the
    // identity is stated over. A counter read as an anchor for a claim about
    // that same counter turns every defect into a timeout: the run reports
    // that it waited rather than what it found, which is the least useful
    // failure a gate can produce. A destination stream that has FINed has had
    // every unit it will ever carry released, and `note_delivered` runs
    // before `write_all`, so the figures lead the wire and cannot still be
    // moving here.
    //
    // The ending is also half the exclusion this fixture rests on: a clean
    // FIN is not a `STOP_SENDING`, and a `STOP_SENDING` is the one teardown
    // that clears a queue instead of draining it.
    for rx in &up_rx {
        assert_eq!(
            rx.wait_for_ending().await,
            Ending::Fin,
            "a destination stream ended cleanly, so nothing here was torn down by a \
             STOP_SENDING — which is the one case that clears a queue instead of draining it"
        );
    }
    assert_eq!(
        down_rx.wait_for_ending().await,
        Ending::Fin,
        "and so did the one going the other way"
    );

    rows()
}

/// Assert the conservation identity over `rows`, term by term and then whole.
///
/// The ordering is deliberate. Every term is checked non-zero *before* the
/// sum is taken, so a failure names the term that went missing rather than
/// reporting a mismatched total and leaving the reader to find it — and,
/// more importantly, so an identity with a term that is identically zero
/// cannot pass as an identity. Four-fifths of a conservation law is not a
/// conservation law.
fn assert_every_byte_is_charged_to_exactly_one_row(rows: &Rows, whose: &str) {
    let up = rows.named(CONSERVE_UP_CLASS);
    let down = rows.named(CONSERVE_DOWN_CLASS);

    assert!(
        up.bytes_delivered > 0 && up.bytes_dropped > 0,
        "{whose}: the claimed uplink class holds both an admitted prefix and an overflow, or the \
         identity has a term that cannot move: {up:?}"
    );
    assert!(
        down.bytes_delivered > 0 && down.bytes_dropped > 0,
        "{whose}: and so does the claimed downlink class, which is what makes this identity span \
         both legs: {down:?}"
    );
    assert!(
        rows.default_class.bytes_delivered > 0,
        "{whose}: an alias no rule names lands in the default row: {:?}",
        rows.default_class
    );
    assert_eq!(
        rows.unshapeable.bytes_delivered,
        CONSERVE_STREAMS * header_len() as u64,
        "{whose}: the unshapeable row holds exactly the three subgroup stream headers — no rule \
         could have claimed one, and a byte no rule could claim is still a byte the shaper \
         handled: {:?}",
        rows.unshapeable
    );

    assert_eq!(
        up.objects_delivered + up.objects_dropped,
        CONSERVE_UP_OBJECTS,
        "{whose}: every offered object of the claimed uplink stream is either delivered or \
         dropped, never both and never neither: {up:?}"
    );
    assert_eq!(
        down.objects_delivered + down.objects_dropped,
        CONSERVE_DOWN_OBJECTS,
        "{whose}: and every object of the relay's stream: {down:?}"
    );
    assert_eq!(
        rows.default_class.objects_delivered + rows.default_class.objects_dropped,
        CONSERVE_LOOSE_OBJECTS,
        "{whose}: and every object of the unclaimed stream: {:?}",
        rows.default_class
    );

    assert_eq!(
        rows.charged(),
        rows.bytes_shaped,
        "{whose}: every byte the shaper saw is charged to exactly one row — classes {:?}, default \
         {:?}, unshapeable {:?}",
        rows.classes,
        rows.default_class,
        rows.unshapeable
    );
}

/// **Every byte one session's shaper saw is charged to exactly one row.**
///
/// `Σ classes(delivered + dropped) + default + unshapeable == bytes_shaped`,
/// on a fixture that loads every term at once and in both directions: the
/// admitted prefix and the discarded tail of a claimed uplink stream, the
/// same pair on a claimed stream coming the other way, a stream on an alias
/// no rule names, and three stream headers no rule could have seen.
///
/// The two documented exceptions are excluded by construction and the file
/// docstring says how. In short: every destination stream is asserted to have
/// ended `Ending::Fin`, so no queue was cleared by a `STOP_SENDING`; and the
/// hook has exactly two arms, `Hold { then: Pass }` and `Pass`, so there is no
/// action available to it that could change a unit's size.
///
/// This row reads the **session's** recorder.
/// [`the_identity_closes_when_the_rows_are_added_across_the_seam`] reads the
/// proxy's, which is a different store written by the same calls, and it has
/// to sum two legs to arrive at the same `bytes_shaped`.
///
/// *Ablation (a), recorded: charge the unshapeable units to `default_class`
/// instead.* In `src/shape/stats.rs`, both `ShapeRecorder::row` and
/// `ProxyRecorder::row` answer `&self.default_class` for
/// `Class::Unshapeable`. **The equality still held** — the bytes moved from
/// one term of the sum to another and the total is unchanged — which is
/// exactly why the terms are asserted separately, and it is the whole
/// argument for doing so. What reddened is the term:
///
/// ```text
/// assertion `left == right` failed: the session's own recorder: the
/// unshapeable row holds exactly the three subgroup stream headers — no rule
/// could have claimed one, and a byte no rule could claim is still a byte the
/// shaper handled: ClassStats { name: "", bytes_delivered: 0, bytes_dropped: 0,
/// objects_delivered: 0, objects_dropped: 0, tokens_exhausted_episodes: 0,
/// blocked_episodes: 0, starved_behind_other_class: 0 }
///   left: 0
///  right: 15
/// ```
///
/// [`the_identity_closes_when_the_rows_are_added_across_the_seam`] failed on
/// the same term with the same figures and its own prefix;
/// [`each_crossing_is_charged_to_its_own_cell_of_the_two_by_two`] stayed
/// green, which is right — moving a byte between two class rows changes no
/// cell of the per-leg matrix.
///
/// *Ablation (b), recorded: drop the unshapeable term from the other side of
/// the equals sign.* Empty the body of `ShapeRecorder::note_unshapeable_seen`,
/// so the `unshapeable` row is still charged when the unit is released but its
/// bytes never enter `bytes_shaped`. **This is the one a bound would have
/// hidden.** Every term assertion above still passed — the row still reports
/// its fifteen bytes — and the missing term makes the sum *larger* than
/// `bytes_shaped`, so `charged >= bytes_shaped` is still true and so is
/// `charged > 0`. Only the equality is not:
///
/// ```text
/// assertion `left == right` failed: the session's own recorder: every byte the
/// shaper saw is charged to exactly one row — classes [ClassStats { name: "up",
/// bytes_delivered: 36012, bytes_dropped: 72024, objects_delivered: 4,
/// objects_dropped: 8, .. }, ClassStats { name: "down", bytes_delivered: 36012,
/// bytes_dropped: 18006, objects_delivered: 4, objects_dropped: 2, .. }],
/// default ClassStats { name: "", bytes_delivered: 36012, bytes_dropped: 36012,
/// objects_delivered: 4, objects_dropped: 4, .. }, unshapeable ClassStats {
/// name: "", bytes_delivered: 15, bytes_dropped: 0, objects_delivered: 3,
/// objects_dropped: 0, .. }
///   left: 234093
///  right: 234078
/// ```
///
/// The fifteen-byte gap is the whole of it: three five-byte subgroup stream
/// headers, each a unit no rule could have claimed. The seam row failed with
/// the same two numbers, and
/// [`each_crossing_is_charged_to_its_own_cell_of_the_two_by_two`] went with
/// them on `bytes_shaped: 1020` against `1025` in the client's uplink cell —
/// the same five missing header bytes, seen at the crossing rather than in
/// the total.
#[tokio::test]
async fn bytes_are_conserved_on_one_session() {
    let hook = HeadHoldingHook::new();
    let run = SessionRun::start(
        conservation_profile(),
        Arc::clone(&hook) as Arc<dyn ProxyHook>,
        CONSERVE_MAX_HOLD,
    )
    .await;

    let rows = offer_the_conservation_traffic(&run.client, &run.relay, &hook, || {
        Rows::from_session(&run.shape())
    })
    .await;

    assert_every_byte_is_charged_to_exactly_one_row(&rows, "the session's own recorder");

    run.finish().await;
}

/// **The same identity closes when the rows are added across the seam.**
///
/// The proxy-wide recorder keeps its `bytes_shaped` in a two-by-two — a cell
/// per leg per direction — and its class rows in one flat set with no leg on
/// them. So the identity here is stated against a `bytes_shaped` that has to
/// be **summed over both legs** before there is anything to compare the rows
/// against: what this proxy read from the client, plus what it read from the
/// relay.
///
/// That is a different assertion from the session's and not a restatement of
/// it. The two recorders are charged by the same `note_*` calls but stored
/// separately, and only this one has a leg axis, so only this one can put a
/// byte in the wrong cell and still add up. What this row would catch that
/// the session row cannot is a byte charged to an arrival cell and released
/// against nothing, or a class row charged twice while one cell was skipped.
///
/// The two arrival cells and not the whole matrix: the departure cells hold
/// the *same* bytes measured at the other crossing, so summing all four would
/// count every delivered byte twice and leave a total about double what the
/// rows account for. And not `ProxyStats::sessions`, which is derived from
/// these same two cells — see the file docstring.
///
/// *Ablations, run:* both of the mutations recorded on
/// [`bytes_are_conserved_on_one_session`] reddened this row too, which is
/// what makes them mutations of the recorder rather than of one of its
/// readers. Under (a) — the unshapeable units charged to `default_class` —
/// this row failed on the same term with the same `left: 0 / right: 15`,
/// under the prefix "the proxy's recorder, summed across both legs". Under
/// (b) — the unshapeable bytes never entering `bytes_shaped` — it failed on
/// the equality with `left: 234093 / right: 234078`.
///
/// A third mutation reddened it and belongs here rather than with the gate it
/// was aimed at, because what it shows is that the figure the rows are
/// compared against really is summed over both legs. *Recorded: `leg_index`
/// answers `0` for `Leg::Upstream` as well as for `Leg::Client`*, which folds
/// every departure measurement back into the two arrival cells this row adds
/// up:
///
/// ```text
/// assertion `left == right` failed: the proxy's recorder, summed across both
/// legs: every byte the shaper saw is charged to exactly one row — ...
///   left: 234093
///  right: 342144
/// ```
///
/// The rows are untouched at 234093 and the total they are compared against
/// has grown by exactly 108051 — the four rows' `bytes_delivered`, counted a
/// second time where they left. That is the shape of the mistake this row's
/// `Rows::from_proxy` is written to avoid, arrived at from the other
/// direction:
/// [`bytes_are_conserved_on_one_session`] stayed green throughout, because a
/// session's recorder has no leg axis to collapse.
#[tokio::test]
async fn the_identity_closes_when_the_rows_are_added_across_the_seam() {
    let hook = HeadHoldingHook::new();
    let run = ProxyRun::start(
        conservation_profile(),
        Arc::clone(&hook) as Arc<dyn ProxyHook>,
        CONSERVE_MAX_HOLD,
    )
    .await;

    let rows = offer_the_conservation_traffic(&run.client, &run.relay, &hook, || {
        Rows::from_proxy(&run.stats())
    })
    .await;

    assert_every_byte_is_charged_to_exactly_one_row(
        &rows,
        "the proxy's recorder, summed across both legs",
    );

    run.finish().await;
}

// ── gate two: attribution ──────────────────────────────────────────────

/// The bucket the attribution fixture's one class charges against.
const ATTRIBUTE_BUCKET: &str = "everything";
/// Its one class, which claims every unit on both legs.
const ATTRIBUTE_CLASS: &str = "all";

/// Track alias of the client's stream.
const ATTRIBUTE_UP_ALIAS: u64 = 21;
/// Track alias of the relay's stream.
const ATTRIBUTE_DOWN_ALIAS: u64 = 22;

/// Objects the client offers.
const ATTRIBUTE_UP_OBJECTS: u64 = 10;
/// Objects the relay offers — a different count, so the two directions cannot
/// be confused for one another by their object totals either.
const ATTRIBUTE_DOWN_OBJECTS: u64 = 8;

/// The payload the client's objects carry.
const ATTRIBUTE_UP_PAYLOAD: usize = 100;
/// The payload the relay's objects carry — deliberately far from the
/// client's, so the two directions differ by hundreds of bytes per object and
/// no rounding could bring two cells together.
const ATTRIBUTE_DOWN_PAYLOAD: usize = 300;

/// How long the attribution fixture's queue may hold a unit.
///
/// Nothing in this fixture is held: the hook elides or passes, and the bucket
/// is unlimited. The knob is pinned anyway so no fixture here inherits the
/// 30 s default and the ceiling every wait is separated from is a number this
/// file wrote.
const ATTRIBUTE_MAX_HOLD: Duration = Duration::from_secs(2);

/// Objects the attribution queue may hold — far above anything this fixture
/// offers, because it is not an admission gate and a discard here would be
/// the fixture measuring itself.
const ATTRIBUTE_DEPTH: usize = 64;

/// Elides the **last** object of every stream and passes the rest.
///
/// The retention this creates is what makes the arrival and departure cells
/// of one direction differ, which is the whole point: with everything
/// delivered, `per_leg[Client].uplink` and `per_leg[Upstream].uplink` are the
/// same numbers and a mapping that swapped them would be invisible.
///
/// The **last** object, and that is not arbitrary. Drafts 14-20 delta-encode
/// Object IDs, so eliding an object obliges the framer to rewrite the *next*
/// one — and a rewritten object is a different number of bytes on the wire
/// from the one the fixture encoded. Eliding the tail leaves no next object,
/// so every surviving object is byte-identical to what the fixture wrote and
/// the expected cell values below are arithmetic on one measured object size
/// rather than an estimate.
struct TailElidingHook {
    up_objects: u64,
    down_objects: u64,
}

impl ProxyHook for TailElidingHook {
    fn interest(&self) -> Interest {
        Interest::OBJECTS
    }

    fn on_object(&self, cx: &ObjectCtx<'_>, _raw: &[u8]) -> Action {
        let offered = match cx.side {
            ProxySide::ClientToProxy => self.up_objects,
            _ => self.down_objects,
        };
        if cx.meta.index_in_stream + 1 == offered {
            Action::Drop(DropMode::Elide)
        } else {
            Action::Pass
        }
    }
}

/// One class claiming everything, over one unlimited bucket, with a queue
/// deep enough never to discard.
///
/// One class rather than two keyed on side: the class rows carry no leg and
/// are not what this gate reads, so splitting them would add a knob the
/// assertions never look at. What the fixture needs from the profile is only
/// that the shaping path is armed on both legs, which
/// `Matcher::default()` gives.
fn attribution_profile() -> ShapeProfile {
    let mut bucket = BucketConfig::default();
    bucket.name = ATTRIBUTE_BUCKET.to_string();
    bucket.rate_bps = None;

    let mut class = ClassRule::default();
    class.name = ATTRIBUTE_CLASS.to_string();
    class.bucket = ATTRIBUTE_BUCKET.to_string();
    class.matcher = Matcher::default();

    let mut queue = QueueConfig::default();
    queue.depth_objects = ATTRIBUTE_DEPTH;
    queue.max_hold = Some(ATTRIBUTE_MAX_HOLD);

    ShapeProfile::try_new(vec![bucket], vec![class], queue, Discipline::Fifo)
        .expect("fixture: one class over its own configured bucket")
}

/// **Each of the four cells reports what crossed at its own measurement
/// point.**
///
/// One run, four different byte counts, compared as whole rows:
///
/// | cell | what it is | why it differs from the others |
/// |---|---|---|
/// | `per_leg[Client].uplink` | read from the client | ten objects and a header |
/// | `per_leg[Upstream].uplink` | written to the relay | nine — the tenth was elided |
/// | `per_leg[Upstream].downlink` | read from the relay | eight objects, three times the payload |
/// | `per_leg[Client].downlink` | written to the client | seven, at that payload |
///
/// Every one of those four numbers is different from the other three, and so
/// is every object count. That is what a fixture owes an attribution claim:
/// with a run in which nothing was retained, the two cells of a direction
/// carry identical numbers and a mapping that swapped them is green forever;
/// with a run in one direction only, half the matrix is zero and a mapping
/// that collapsed the other axis is green too.
///
/// # Whole rows, not fields
///
/// The comparison is against a whole [`LegStats`], which is exactly its two
/// [`DirectionStats`], which are exactly their five fields. Field-by-field
/// assertions would leave a figure that leaked into a neighbouring counter on
/// the correct cell unasserted, and would silently stop covering any field
/// added later — the three event figures here are all expected zero, and a
/// zero nobody compares is indistinguishable from a field nobody wrote.
///
/// # What is not asserted, and why
///
/// Not [`ProxyStats::sessions`]. It is derived from these same cells at
/// snapshot time, so asserting it equals their sum is `a + b == a + b` — no
/// mutation can redden it. The file docstring states the condition under
/// which that stops being true.
///
/// *Ablation (a), recorded: charge every unit to the uplink direction
/// regardless of the side it arrived on.* In `src/shape/stats.rs`, `split`
/// answers `Direction::Uplink` in all four arms. The legs are still told
/// apart and every byte is still counted somewhere — the two downlink cells
/// are simply empty and their traffic has been folded into the uplink cell
/// beside them:
///
/// ```text
/// assertion `left == right` failed: the client leg: what this proxy read from
/// the client, and what it wrote back to the client
///   left: LegStats { directions: [DirectionStats { objects_seen: 17,
///     bytes_shaped: 3151, objects_expired: 0, streams_reset_by_shaping: 0,
///     streams_with_mixed_classes: 0 }, DirectionStats { objects_seen: 0,
///     bytes_shaped: 0, objects_expired: 0, streams_reset_by_shaping: 0,
///     streams_with_mixed_classes: 0 }] }
///  right: LegStats { directions: [DirectionStats { objects_seen: 10,
///     bytes_shaped: 1025, objects_expired: 0, streams_reset_by_shaping: 0,
///     streams_with_mixed_classes: 0 }, DirectionStats { objects_seen: 7,
///     bytes_shaped: 2126, objects_expired: 0, streams_reset_by_shaping: 0,
///     streams_with_mixed_classes: 0 }] }
/// ```
///
/// `1025 + 2126 == 3151` and `10 + 7 == 17`: the client leg's own two flows,
/// added together and reported as though both had gone the same way.
/// [`bytes_are_conserved_on_one_session`] stayed green under it — a direction
/// that vanished is not a byte that vanished — and
/// [`the_identity_closes_when_the_rows_are_added_across_the_seam`] timed out
/// on its "every offered object to be classified" anchor, which is honest
/// rather than incidental: that anchor counts the two arrival cells, and this
/// mutation empties one of them.
///
/// *Ablation (b), recorded: collapse the leg-to-direction mapping so both
/// legs report row 0.* In `src/shape/stats.rs`, `leg_index` answers `0` for
/// `Leg::Upstream` as well as for `Leg::Client`. This is the other axis, and
/// neither mutation is the other: here the *directions* are still told apart
/// perfectly and it is the upstream leg that has vanished into the client's:
///
/// ```text
/// assertion `left == right` failed: the client leg: what this proxy read from
/// the client, and what it wrote back to the client
///   left: LegStats { directions: [DirectionStats { objects_seen: 19,
///     bytes_shaped: 1948, objects_expired: 0, streams_reset_by_shaping: 0,
///     streams_with_mixed_classes: 0 }, DirectionStats { objects_seen: 15,
///     bytes_shaped: 4555, objects_expired: 0, streams_reset_by_shaping: 0,
///     streams_with_mixed_classes: 0 }] }
///  right: LegStats { directions: [DirectionStats { objects_seen: 10,
///     bytes_shaped: 1025, objects_expired: 0, streams_reset_by_shaping: 0,
///     streams_with_mixed_classes: 0 }, DirectionStats { objects_seen: 7,
///     bytes_shaped: 2126, objects_expired: 0, streams_reset_by_shaping: 0,
///     streams_with_mixed_classes: 0 }] }
/// ```
///
/// `1025 + 923 == 1948` and `2429 + 2126 == 4555`: the uplink pair summed
/// into one uplink cell and the downlink pair into one downlink cell, with
/// the client leg reporting the whole proxy and the upstream leg reporting
/// nothing. Compare the numbers with ablation (a)'s — the two mutations put
/// the same traffic in different places, so neither could stand in for the
/// other.
#[tokio::test]
async fn each_crossing_is_charged_to_its_own_cell_of_the_two_by_two() {
    let hook = Arc::new(TailElidingHook {
        up_objects: ATTRIBUTE_UP_OBJECTS,
        down_objects: ATTRIBUTE_DOWN_OBJECTS,
    });
    let run =
        ProxyRun::start(attribution_profile(), hook as Arc<dyn ProxyHook>, ATTRIBUTE_MAX_HOLD)
            .await;

    let up = subgroup_stream(ATTRIBUTE_UP_ALIAS, ATTRIBUTE_UP_OBJECTS, ATTRIBUTE_UP_PAYLOAD);
    let down =
        subgroup_stream(ATTRIBUTE_DOWN_ALIAS, ATTRIBUTE_DOWN_OBJECTS, ATTRIBUTE_DOWN_PAYLOAD);
    let up_object = object_size(&up, ATTRIBUTE_UP_OBJECTS) as u64;
    let down_object = object_size(&down, ATTRIBUTE_DOWN_OBJECTS) as u64;
    let head = header_len() as u64;

    let mut up_send = run.client.open_uni().await.expect("fixture: the client opened a stream");
    up_send.write_all(&up).await.expect("fixture: the client wrote its stream");
    up_send.finish().expect("fixture: the client finished its stream");

    let mut down_send = run.relay.open_uni().await;
    down_send.write_all(&down).await.expect("fixture: the relay wrote its stream");
    down_send.finish().expect("fixture: the relay finished its stream");

    let up_rx = tokio::time::timeout(PATIENCE, run.relay.timed_uni())
        .await
        .expect("fixture: the proxy opened a destination stream towards the relay");
    let down_recv = tokio::time::timeout(PATIENCE, run.client.accept_uni())
        .await
        .expect("fixture: the proxy opened a destination stream towards the client")
        .expect("fixture: the client accepted it");
    let down_rx = TimedReceiver::spawn(down_recv);

    // The wire is the anchor, and it is a strictly later event than the
    // counters it anchors: `note_delivered` runs before `write_all`, so a
    // stream that has ended has already been counted. Byte-equality with the
    // source prefix is asserted as well as the ending, because "it ended" and
    // "it ended having carried exactly the objects that were not elided" are
    // different claims and the second is what makes the expected cell values
    // below arithmetic rather than a guess.
    let up_kept = head as usize + (ATTRIBUTE_UP_OBJECTS - 1) as usize * up_object as usize;
    let down_kept = head as usize + (ATTRIBUTE_DOWN_OBJECTS - 1) as usize * down_object as usize;
    assert_eq!(
        up_rx.wait_for_bytes(up_kept).await,
        up[..up_kept],
        "the relay received the client's stream with its last object elided and nothing else \
         changed"
    );
    assert_eq!(up_rx.wait_for_ending().await, Ending::Fin, "and it ended cleanly");
    assert_eq!(
        down_rx.wait_for_bytes(down_kept).await,
        down[..down_kept],
        "and the client received the relay's stream on the same terms"
    );
    assert_eq!(down_rx.wait_for_ending().await, Ending::Fin, "and that one ended cleanly too");

    let stats = run.stats();

    // Four cells, four different byte counts. Stated as the fixture's own
    // premise: if two of them ever coincided, a mapping that swapped the pair
    // would pass every assertion below.
    let want_client_up = DirectionStats {
        objects_seen: ATTRIBUTE_UP_OBJECTS,
        bytes_shaped: head + ATTRIBUTE_UP_OBJECTS * up_object,
        objects_expired: 0,
        streams_reset_by_shaping: 0,
        streams_with_mixed_classes: 0,
    };
    let want_upstream_up = DirectionStats {
        objects_seen: ATTRIBUTE_UP_OBJECTS - 1,
        bytes_shaped: head + (ATTRIBUTE_UP_OBJECTS - 1) * up_object,
        objects_expired: 0,
        streams_reset_by_shaping: 0,
        streams_with_mixed_classes: 0,
    };
    let want_upstream_down = DirectionStats {
        objects_seen: ATTRIBUTE_DOWN_OBJECTS,
        bytes_shaped: head + ATTRIBUTE_DOWN_OBJECTS * down_object,
        objects_expired: 0,
        streams_reset_by_shaping: 0,
        streams_with_mixed_classes: 0,
    };
    let want_client_down = DirectionStats {
        objects_seen: ATTRIBUTE_DOWN_OBJECTS - 1,
        bytes_shaped: head + (ATTRIBUTE_DOWN_OBJECTS - 1) * down_object,
        objects_expired: 0,
        streams_reset_by_shaping: 0,
        streams_with_mixed_classes: 0,
    };

    let mut distinct = vec![
        want_client_up.bytes_shaped,
        want_upstream_up.bytes_shaped,
        want_upstream_down.bytes_shaped,
        want_client_down.bytes_shaped,
    ];
    let offered = distinct.len();
    distinct.sort_unstable();
    distinct.dedup();
    assert_eq!(
        distinct.len(),
        offered,
        "the fixture's premise: the four cells must carry four different byte counts, or a \
         mapping that swapped two of them would pass"
    );

    assert_eq!(
        *stats.leg(Leg::Client),
        LegStats { directions: [want_client_up, want_client_down] },
        "the client leg: what this proxy read from the client, and what it wrote back to the \
         client"
    );
    assert_eq!(
        *stats.leg(Leg::Upstream),
        LegStats { directions: [want_upstream_up, want_upstream_down] },
        "the upstream leg: what this proxy wrote to the relay, and what it read from the relay — \
         the same two flows measured at their other crossing"
    );

    run.finish().await;
}

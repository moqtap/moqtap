//! `StreamAction::OpenAfter` at both stream sites, observed at the far peer.
//!
//! Two rows, one value. A hook returns `StreamAction::OpenAfter` at
//! `Site::StreamOpen` in the first and at `Site::StreamHeader` in the
//! second, and the crate answers differently at each — which is exactly what
//! `capability::classify` publishes: `Support::Yes` at the open site,
//! `Support::No(Refusal::WrongSite { .. })` at the header site. What this
//! file adds is the far-side consequence of each answer, because a published
//! verdict that nothing observes is a claim about the table rather than about
//! the proxy.
//!
//! * [`open_after_at_the_open_site_delivers_the_deferred_stream_last`] — the
//!   deferral reaches the wire. The peer receives a *later* stream's header
//!   before the deferred stream's first byte.
//! * [`open_after_at_the_header_site_is_refused_by_name_and_defers_nothing`]
//!   — the same value at the header site is refused, named, and inert: the
//!   stream is forwarded whole while a 60-second delay is nominally pending.
//!
//! # Ordering, not duration
//!
//! The first row's assertion compares two arrival instants recorded at the
//! relay — the instant the trigger stream's header finished arriving, and
//! the instant the dependent stream's first byte arrived — and asserts only
//! that one is before the other. No threshold, no window, no wall-clock
//! bound: a loaded runner moves both instants together and the ordering
//! survives. `actions_shaping.rs::open_after_delays_the_peer_stream` already
//! pins the same capability the other way, with a negative window on the
//! relay's connection; this row is the ordering half, and it is the one that
//! stays meaningful when the machine is busy.
//!
//! Both directions of the ordering are forced by a *causal* wait rather than
//! by the size of the delay. The client opens the dependent stream and does
//! not open the trigger stream until the hook has been shown the dependent
//! one, which the test observes by polling the hook's own call count. So the
//! trigger stream does not exist at the client until the proxy has already
//! taken the deferred-open decision, and the only thing that can put the
//! trigger's header in front of the dependent's first byte is the deferral
//! itself.
//!
//! # Which draft this file speaks
//!
//! Derived rather than named, for the reason `actions_shaping.rs` gives at
//! length: the fixture's header bytes decode against the draft the session
//! was configured with, so a hardcoded draft turns every single-draft build
//! that is not that draft red. Nothing here reads a draft — a subgroup
//! stream is a subgroup stream — so the newest compiled one is used and the
//! fixture is derived from it.

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
    feature = "draft20",
    feature = "draft21"
))]

mod common;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use moqtap_codec::dispatch::{AnySubgroupHeader, AnySubgroupObject, AnySubgroupObjectWriter};
use moqtap_codec::version::DraftVersion;

use moqtap_proxy::action::{Interest, StreamAction};
use moqtap_proxy::capability::{ActionKind, Refusal, Site};
use moqtap_proxy::event::{DataStreamHeaderKind, Effect};
use moqtap_proxy::framer::{FramerConfig, FramerOut, ObjectFramer};
use moqtap_proxy::hook::{ProxyHook, StreamCtx};
use moqtap_proxy::observer::ProxyObserver;
use moqtap_proxy::parser::data::DataStreamType;

use common::{Ending, FakeRelay, RecordingObserver, SpawnedProxy, TimedReceiver};

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
    #[cfg(feature = "draft21")]
    DraftVersion::Draft21,
];

/// The draft every fixture here is built for: the **newest** one this build
/// compiled.
const DRAFT: DraftVersion = COMPILED_DRAFTS[COMPILED_DRAFTS.len() - 1];

/// The ALPN the front-end endpoint advertises. No test here opens a control
/// stream, so the only thing it settles is that the session's draft stays
/// open to refinement — which nothing below depends on either way.
const ALPN: &[u8] = b"moq-00";

/// Track alias of the stream whose open decision is deferred.
const DEPENDENT_ALIAS: u64 = 2;
/// Track alias of the stream opened afterwards and never deferred.
const TRIGGER_ALIAS: u64 = 1;

/// The delay the open site is driven with.
///
/// A lower bound on the ordering margin, not an asserted duration: nothing
/// below compares it to anything. It is a whole second so that the ordering
/// it produces survives a runner that is busy, and it is the entire cost of
/// this file's first row.
const OPEN_AFTER: Duration = Duration::from_secs(1);

/// The delay the header site is driven with.
///
/// Six times the harness's `TIMEOUT`, on purpose: if the header site ever
/// started honouring `OpenAfter` instead of refusing it, no byte of the
/// stream could arrive inside any wait the second row makes, so the row
/// fails by shortfall rather than by passing slowly.
const REFUSED_AFTER: Duration = Duration::from_secs(60);

// ── fixtures ───────────────────────────────────────────────────────────

/// The stream-type field [`DRAFT`] opens a subgroup stream with, for a
/// header carrying an **explicit** Subgroup ID.
///
/// The same table `actions_shaping.rs`, `actions_timing.rs` and
/// `actions_objects.rs` carry, restated rather than shared: these are
/// separate test binaries, and the encoder is deliberately kept out of any
/// crate the proxy itself uses — a shared encoder would leave this file
/// comparing the proxy against its own output.
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

/// A subgroup stream header for `draft` carrying `track_alias`: group 0,
/// subgroup 0, publisher priority `0x80`. Five bytes on every draft 07-21.
fn subgroup_header_bytes(draft: DraftVersion, track_alias: u64) -> Vec<u8> {
    assert!(track_alias < 64, "single-byte varint only");
    vec![subgroup_stream_type(draft), track_alias as u8, 0x00, 0x00, 0x80]
}

/// A whole [`DRAFT`] subgroup stream on `track_alias`: the header and
/// `count` objects of `payload_len` bytes each, returned as one vector.
fn subgroup_stream(track_alias: u64, count: u64, payload_len: usize) -> Vec<u8> {
    let head = subgroup_header_bytes(DRAFT, track_alias);
    let mut cursor = &head[..];
    let header =
        AnySubgroupHeader::decode_stream(DRAFT, &mut cursor).expect("subgroup header decode");
    let mut writer = AnySubgroupObjectWriter::new(&header).expect("subgroup object writer");

    let mut out = head;
    for object_id in 0..count {
        let fill = u8::try_from(0xA0 + object_id % 0x40).expect("fill byte");
        let obj = AnySubgroupObject {
            object_id,
            extension_headers: Vec::new(),
            extension_count: None,
            status: None,
            payload: vec![fill; payload_len],
        };
        writer.write_object(&obj, &mut out).expect("write object");
    }
    out
}

// ── the hook ───────────────────────────────────────────────────────────

/// Returns a scripted [`StreamAction`] at each stream site.
///
/// The two sites are scripted on different keys, and the difference is the
/// crate's own: `on_stream_open` is track-blind — no byte of the stream has
/// been read when it fires — so the open script can only be a function of
/// *which* stream this is, counted in the order the hook was shown them.
/// `on_stream_header` is handed the decoded header, so its script keys on
/// the Track Alias and needs no ordering assumption at all.
struct DeferScript {
    #[allow(clippy::type_complexity)]
    at_open: Box<dyn Fn(usize) -> StreamAction + Send + Sync>,
    #[allow(clippy::type_complexity)]
    at_header: Box<dyn Fn(Option<u64>) -> StreamAction + Send + Sync>,
    opens: Mutex<usize>,
    headers: Mutex<usize>,
}

impl DeferScript {
    fn new(
        at_open: impl Fn(usize) -> StreamAction + Send + Sync + 'static,
        at_header: impl Fn(Option<u64>) -> StreamAction + Send + Sync + 'static,
    ) -> Arc<Self> {
        Arc::new(Self {
            at_open: Box::new(at_open),
            at_header: Box::new(at_header),
            opens: Mutex::new(0),
            headers: Mutex::new(0),
        })
    }

    /// How many streams the open site has been shown.
    fn opens(&self) -> usize {
        *self.opens.lock().expect("opens")
    }

    /// How many headers the header site has been shown.
    fn headers(&self) -> usize {
        *self.headers.lock().expect("headers")
    }
}

impl ProxyHook for DeferScript {
    fn interest(&self) -> Interest {
        Interest::STREAMS
    }

    fn on_stream_open(&self, _cx: &StreamCtx<'_>) -> StreamAction {
        let mut n = self.opens.lock().expect("opens");
        let at = *n;
        *n += 1;
        (self.at_open)(at)
    }

    fn on_stream_header(&self, _cx: &StreamCtx<'_>, header: &DataStreamHeaderKind) -> StreamAction {
        *self.headers.lock().expect("headers") += 1;
        let alias = match header {
            DataStreamHeaderKind::Subgroup(h) => Some(h.track_alias()),
            DataStreamHeaderKind::Fetch(_) => None,
        };
        (self.at_header)(alias)
    }
}

/// Spawn a proxy in front of `relay` and hand back the pieces both rows
/// drive: the proxy, a live client connection, and the client endpoint,
/// which must outlive it.
async fn rig(
    relay: &Arc<FakeRelay>,
    observer: Arc<dyn ProxyObserver>,
    hook: Arc<dyn ProxyHook>,
) -> (SpawnedProxy, quinn::Endpoint, quinn::Connection) {
    let proxy =
        common::spawn_proxy_with(common::session_config(DRAFT, relay.addr), ALPN, observer, hook);
    let (client_ep, client_conn) = common::connect_client(proxy.addr, ALPN).await;
    let _ = tokio::time::timeout(common::TIMEOUT, relay.connection())
        .await
        .expect("the proxy connected upstream");
    (proxy, client_ep, client_conn)
}

// ── observing the far side ─────────────────────────────────────────────

/// Wait until the hook's open site has been shown `n` streams.
///
/// The causal wait this file's ordering rests on: it is what lets the client
/// hold a stream back until the proxy has taken the *previous* stream's open
/// decision, so neither row depends on two client streams racing each other
/// through the proxy's accept loop.
async fn wait_for_opens(hook: &DeferScript, n: usize) {
    let poll = async {
        while hook.opens() < n {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    };
    tokio::time::timeout(common::TIMEOUT, poll).await.unwrap_or_else(|_| {
        panic!(
            "the open site was shown {} stream(s) in {:?}, not {n}",
            hook.opens(),
            common::TIMEOUT,
        )
    });
}

/// Wait until the hook's header site has been shown `n` headers.
async fn wait_for_headers(hook: &DeferScript, n: usize) {
    let poll = async {
        while hook.headers() < n {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    };
    tokio::time::timeout(common::TIMEOUT, poll).await.unwrap_or_else(|_| {
        panic!(
            "the header site was shown {} header(s) in {:?}, not {n}",
            hook.headers(),
            common::TIMEOUT,
        )
    });
}

/// The instant the read that completed this stream's subgroup header
/// returned, or `None` if no whole header has arrived.
///
/// Not the instant the first byte arrived: a header split across two reads
/// is not "the header has arrived" until the second one, and the claim this
/// file makes is about a whole header reaching the peer.
fn header_arrived_at(rx: &TimedReceiver, draft: DraftVersion) -> Option<Instant> {
    let mut framer = ObjectFramer::new(DataStreamType::Subgroup, draft, FramerConfig::default());
    for (at, chunk) in rx.chunks() {
        framer.feed(&chunk);
        loop {
            match framer.poll() {
                FramerOut::Header { .. } => return Some(at),
                FramerOut::NeedMore => break,
                _ => {}
            }
        }
    }
    None
}

/// The instant this stream's first byte arrived, or `None` if none has.
fn first_byte_arrived_at(rx: &TimedReceiver) -> Option<Instant> {
    rx.chunks().first().map(|(at, _)| *at)
}

// ── the open site: the deferral reaches the far peer ───────────────────

/// A stream whose open decision was deferred reaches the peer *after* a
/// stream that was opened later and not deferred.
///
/// This is the ordering half of `OpenAfter`. The client opens the dependent
/// stream first and writes all of it, waits until the proxy's open site has
/// been shown that stream, and only then opens the trigger stream. Every
/// byte of both streams is therefore already at the proxy in the order
/// dependent-then-trigger, and the relay's two receivers are read
/// concurrently. If nothing deferred the dependent stream's open, its bytes
/// would reach the relay before the trigger stream existed at all.
///
/// The assertion compares two recorded instants for order and nothing else,
/// so there is no window to widen and no threshold to tune.
///
/// *Ablation, run:* open the dependent stream immediately — in
/// `session.rs`'s unidirectional accept loop, replace the two-arm `match
/// open_after` with an unconditional `Some(dest.open_uni().await?)`, which
/// is the accept loop as it stands minus the deferral. Recorded:
///
/// ```text
/// thread 'open_after_at_the_open_site_delivers_the_deferred_stream_last'
/// (53576) panicked at crates\moqtap-proxy\tests\open_after_ordering.rs:
/// the deferred stream's first byte reached the relay 594µs BEFORE the
/// trigger stream's header, so the peer stream was opened at once: OpenAfter
/// was admitted at the open site and changed nothing on the wire
/// ```
///
/// The two margins are worth reading together. Passing, the trigger's
/// header leads by about the delay the hook asked for — the dependent
/// stream is not even open yet. Ablated, the dependent stream leads by
/// 594µs: one scheduling step, which is exactly the head start the client
/// gave it by writing it first. The order flips because of what the proxy
/// did, not because of how long anything took.
#[tokio::test]
async fn open_after_at_the_open_site_delivers_the_deferred_stream_last() {
    common::init_crypto();

    let relay = Arc::new(FakeRelay::bind(ALPN));
    let observer = Arc::new(RecordingObserver::new());
    let hook = DeferScript::new(
        |n| if n == 0 { StreamAction::OpenAfter(OPEN_AFTER) } else { StreamAction::Open },
        |_| StreamAction::Open,
    );
    let (proxy, _client_ep, client_conn) = rig(
        &relay,
        Arc::clone(&observer) as Arc<dyn ProxyObserver>,
        Arc::clone(&hook) as Arc<dyn ProxyHook>,
    )
    .await;

    let dependent = subgroup_stream(DEPENDENT_ALIAS, 2, 16);
    let trigger = subgroup_stream(TRIGGER_ALIAS, 2, 16);

    let mut dep_send = client_conn.open_uni().await.expect("open the dependent stream");
    dep_send.write_all(&dependent).await.expect("write the dependent stream");
    dep_send.finish().expect("finish the dependent stream");

    // The whole ordering rests on this: the trigger stream does not exist
    // until the proxy has taken the dependent stream's open decision.
    wait_for_opens(&hook, 1).await;

    let mut trig_send = client_conn.open_uni().await.expect("open the trigger stream");
    trig_send.write_all(&trigger).await.expect("write the trigger stream");
    trig_send.finish().expect("finish the trigger stream");

    let streams = relay.timed_uni_by_alias(&[TRIGGER_ALIAS, DEPENDENT_ALIAS], DRAFT).await;
    let (trig_rx, dep_rx) = (&streams[0], &streams[1]);

    let trigger_header_at = header_arrived_at(trig_rx, DRAFT)
        .expect("the trigger stream's header arrived at the relay");
    let dependent_first_at =
        first_byte_arrived_at(dep_rx).expect("the dependent stream's first byte arrived");

    assert!(
        trigger_header_at < dependent_first_at,
        "the deferred stream's first byte reached the relay {:?} BEFORE the trigger stream's \
         header, so the peer stream was opened at once: OpenAfter was admitted at the open site \
         and changed nothing on the wire",
        trigger_header_at.saturating_duration_since(dependent_first_at),
    );

    assert_eq!(
        dep_rx.wait_for_bytes(dependent.len()).await,
        dependent,
        "a deferred open forwards the whole stream, byte-equal"
    );
    assert_eq!(dep_rx.wait_for_ending().await, Ending::Fin, "and ends it cleanly");
    assert_eq!(
        trig_rx.wait_for_bytes(trigger.len()).await,
        trigger,
        "the stream that was not deferred is untouched too"
    );

    assert_eq!(
        observer
            .applied()
            .into_iter()
            .filter(|(site, ..)| *site == Site::StreamOpen)
            .collect::<Vec<_>>(),
        vec![
            (Site::StreamOpen, ActionKind::OpenAfter, Effect::ForwardedVerbatim),
            (Site::StreamOpen, ActionKind::Open, Effect::ForwardedVerbatim),
        ],
        "the open site applied the deferral to the first stream and nothing to the second: {:?}",
        observer.events()
    );
    assert!(observer.refused().is_empty(), "nothing was refused: {:?}", observer.refused());

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

// ── the header site: refused by name, and inert ────────────────────────

/// `OpenAfter` at the header site is refused by name, and the stream it was
/// returned for is forwarded whole while the delay is nominally pending.
///
/// The peer stream is opened in the accept loop, before the first source
/// byte is read, so by the time the header site runs there is no opening
/// left to defer — `capability::classify` publishes
/// `No(WrongSite { site: StreamHeader, action: OpenAfter })` and the engine
/// refuses it. The two things worth observing are that the refusal is
/// *emitted* rather than the action being dropped on the floor, and that
/// refusing costs the stream nothing.
///
/// [`REFUSED_AFTER`] is six times the harness's `TIMEOUT`, so a header site
/// that started honouring the deferral could not deliver a byte inside any
/// wait below: the row would fail on the byte compare, not pass slowly.
///
/// *Ablation, run:* admit it at the header site — in
/// `capability::classify_stream_decision`, return `Support::Yes` for
/// `ActionKind::OpenAfter` at every site instead of only at
/// `Site::StreamOpen`. The engine then plans a deferral the header site has
/// no way to perform. Recorded:
///
/// ```text
/// thread 'open_after_at_the_header_site_is_refused_by_name_and_defers_nothing'
/// (14280) panicked at crates\moqtap-proxy\tests\open_after_ordering.rs:
/// assertion `left == right` failed: the header site refused OpenAfter by
/// name, exactly once
///   left: []
///  right: [(StreamHeader, OpenAfter, WrongSite { site: StreamHeader, action: OpenAfter })]
/// ```
///
/// That is the outcome this row exists to forbid, and the ablated run shows
/// the whole of it: the two byte assertions above the refusal *passed* under
/// the mutation. So with the refusal removed the action is accepted, no
/// refusal is reported, and the 60-second delay it asked for is performed by
/// nobody — the stream is forwarded exactly as if the hook had returned
/// `Open`. An accepted action that does nothing is worse than a refused one,
/// because only the refusal reaches the caller.
#[tokio::test]
async fn open_after_at_the_header_site_is_refused_by_name_and_defers_nothing() {
    common::init_crypto();

    let relay = Arc::new(FakeRelay::bind(ALPN));
    let observer = Arc::new(RecordingObserver::new());
    let hook = DeferScript::new(
        |_| StreamAction::Open,
        |alias| {
            if alias == Some(DEPENDENT_ALIAS) {
                StreamAction::OpenAfter(REFUSED_AFTER)
            } else {
                StreamAction::Open
            }
        },
    );
    let (proxy, _client_ep, client_conn) = rig(
        &relay,
        Arc::clone(&observer) as Arc<dyn ProxyObserver>,
        Arc::clone(&hook) as Arc<dyn ProxyHook>,
    )
    .await;

    let dependent = subgroup_stream(DEPENDENT_ALIAS, 2, 16);

    let mut dep_send = client_conn.open_uni().await.expect("open the stream");
    dep_send.write_all(&dependent).await.expect("write the stream");
    dep_send.finish().expect("finish the stream");

    // The header site has run, so the decision has been taken and refused
    // by the time anything below is asserted.
    wait_for_headers(&hook, 1).await;

    let streams = relay.timed_uni_by_alias(&[DEPENDENT_ALIAS], DRAFT).await;
    let rx = &streams[0];

    assert_eq!(
        rx.wait_for_bytes(dependent.len()).await,
        dependent,
        "a refused stream decision costs the stream nothing: every byte is forwarded"
    );
    assert_eq!(rx.wait_for_ending().await, Ending::Fin, "and the stream still ends cleanly");

    assert_eq!(
        observer.refused(),
        vec![(
            Site::StreamHeader,
            ActionKind::OpenAfter,
            Refusal::WrongSite { site: Site::StreamHeader, action: ActionKind::OpenAfter },
        )],
        "the header site refused OpenAfter by name, exactly once"
    );
    assert!(
        !observer
            .applied()
            .iter()
            .any(|(site, kind, _)| *site == Site::StreamHeader && *kind == ActionKind::OpenAfter),
        "a refused action must not also be reported as applied: {:?}",
        observer.applied()
    );

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

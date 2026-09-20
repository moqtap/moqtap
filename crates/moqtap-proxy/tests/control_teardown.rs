//! Ending a session on request: what the peers are told, and what happens
//! to the bytes that were still queued when the request landed.
//!
//! Five claims, and each is observed as a consequence at a peer rather than
//! read back from anything the proxy stores:
//!
//! * the close code and reason reach **both** peers, exactly as written;
//! * a drain that has time delivers what was queued;
//! * a drain window of zero is a bound, not a licence to wait, and what it
//!   abandons is named;
//! * delivered plus stranded equals what was queued, as an equality;
//! * a second close aimed at a session that is already draining is refused,
//!   and the pair the first one fixed is what both peers are given.
//!
//! # How a byte is made to sit in an egress queue
//!
//! Every gate but the first uses one hook that answers
//! `Action::Pass.delayed(..)` for every object on a subgroup stream. The
//! stream's header carries no `ObjectMeta`, so no rule and no hook claims
//! it: it is written inline and arrives at once, which is what lets the
//! object assertions below be about the objects. Everything after it goes
//! into that stream's pending queue and stays there until its release time,
//! so the fixture chooses — to the millisecond — what is still queued when
//! the close is requested.
//!
//! The client's send half is deliberately **kept open** in every gate. A
//! dropped `quinn::SendStream` implicitly finishes the stream, and a source
//! that FINs sends the pipe down its end-of-stream drain, which honours
//! release times without any window at all — so a fixture that let the
//! source go would be measuring that path and not this one.
//!
//! # The margins, and which way load can push them
//!
//! Each gate separates a hold from a window by at least a factor of three,
//! and the separation is one-sided in every case:
//!
//! * [`a_drain_with_time_delivers_what_was_queued`] holds for 2 s inside a
//!   6 s window. A slow machine delays the release, and the window still
//!   covers it.
//! * [`a_zero_drain_window_closes_at_once_and_names_what_it_abandoned`]
//!   holds for 6 s and requires the close within 2 s. A slow machine makes
//!   the close later, never the hold shorter; the gap is three-fold against
//!   a close that normally takes single-digit milliseconds.
//! * [`delivered_plus_stranded_equals_what_was_queued`] releases its first
//!   object 500 ms in and the rest at 8 s, inside a 2 s window. Load moves
//!   the close later, which moves the window later with it — the first
//!   object stays inside and the rest stay outside either way.
//! * [`a_second_close_inside_the_drain_window_is_refused_and_the_first_pair_stands`]
//!   holds for 8 s inside a 6 s window and requires the session to still be
//!   open 2 s in. A slow machine makes the drain start later and end later,
//!   so the instant being observed moves with it.
//!
//! Widen a margin if one ever fails; do not delete it, and do not replace a
//! poll with a sleep.
//!
//! # Setup failures are not gate failures
//!
//! Binding a socket, generating a certificate and completing a handshake
//! can all fail for reasons that have nothing to do with a close. Every one
//! of those is an `expect` whose message begins with `fixture:`, and every
//! assertion about a close is an `assert` naming what the proxy did. A run
//! that could not stand the proxy up says so in those words rather than
//! reporting a claim about teardown.

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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use moqtap_codec::dispatch::{AnySubgroupHeader, AnySubgroupObject, AnySubgroupObjectWriter};
use moqtap_codec::version::DraftVersion;

use moqtap_proxy::action::{Action, Interest};
use moqtap_proxy::control::{ControlError, ProxyControl};
use moqtap_proxy::event::{ImpairmentKind, SessionId};
use moqtap_proxy::hook::{NoOpHook, ObjectCtx, ProxyHook};
use moqtap_proxy::listener::ListenerConfig;
use moqtap_proxy::proxy::{ProxyConfig, TransparentProxy};
use moqtap_proxy::session::ProxySessionConfig;

use common::{FakeRelay, RecordingObserver};

/// Every draft this build compiled, oldest first, so the media fixture has
/// a draft to encode for whichever single-draft build it is running under.
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

/// The draft every media fixture here is built for: the newest one
/// compiled.
const DRAFT: DraftVersion = COMPILED_DRAFTS[COMPILED_DRAFTS.len() - 1];

/// The ALPN the clients and the fake relays speak.
const ALPN: &[u8] = b"moq-00";

/// The session termination code every gate here asks for.
///
/// Not `0`. The proxy's own default pair is `(0, b"proxy session ended")`,
/// and a fixture that asked for either half of it could not tell a close
/// that carried the request from one that fell back.
const CLOSE_CODE: u32 = 42;

/// The reason phrase every gate here asks for, for the same reason the code
/// is not zero.
const CLOSE_REASON: &[u8] = b"the control plane asked";

/// How long an anchored poll waits before declaring the run broken.
const PATIENCE: Duration = Duration::from_secs(10);

/// How long a close that was given no drain window may take to reach a
/// peer.
///
/// A close with an empty queue and a zero window is a handful of task
/// wake-ups — single-digit milliseconds — so this is three orders of
/// magnitude of headroom, and it sits a factor of three below the hold the
/// gate that uses it leaves outstanding.
const PROMPT: Duration = Duration::from_secs(2);

// ── the far end, and the reader that survives a closing connection ─────

/// A background reader that records what arrived on one stream and treats
/// the connection going away as an ending rather than a fault.
///
/// `common::TimedReceiver` would be the natural choice and cannot be used
/// here: it panics on any read error that is not a `RESET_STREAM`, and
/// every gate in this file ends with the session closing while the
/// destination stream is still open, which surfaces as
/// `ReadError::ConnectionLost`. That panic would land in a detached task,
/// print, and fail nothing — noise in exchange for no signal.
struct Tap {
    seen: Arc<Mutex<Vec<u8>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Tap {
    /// Start reading `recv` in the background.
    fn spawn(mut recv: quinn::RecvStream) -> Self {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let task = tokio::spawn(async move {
            let mut buf = [0u8; 8192];
            loop {
                match recv.read(&mut buf).await {
                    Ok(Some(n)) => sink.lock().expect("tap").extend_from_slice(&buf[..n]),
                    // A FIN, a reset, or the connection closing under it.
                    // All three end this reader and none of them is a
                    // fault: what matters is how much had arrived first,
                    // and that is already recorded.
                    _ => return,
                }
            }
        });
        Self { seen, task }
    }

    /// How many bytes have arrived so far.
    fn len(&self) -> usize {
        self.seen.lock().expect("tap").len()
    }

    /// Wait until at least `want` bytes have arrived, or [`PATIENCE`]
    /// elapses, and report what actually arrived either way.
    ///
    /// Returning the count rather than panicking is what lets the caller's
    /// own `assert_eq!` report the shortfall, so a gate that reddens says
    /// how many bytes were missing instead of only that it waited.
    async fn wait_for(&self, want: usize) -> usize {
        let deadline = Instant::now() + PATIENCE;
        while self.len() < want && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        self.len()
    }
}

impl Drop for Tap {
    fn drop(&mut self) {
        self.task.abort();
    }
}

// ── the hook that puts bytes in a queue ────────────────────────────────

/// Holds every object it is shown in its stream's egress queue.
///
/// The first object of the session gets `first` and every later one gets
/// `rest`, which is what lets one fixture arrange for part of a queue to be
/// released inside a drain window and the remainder to be still waiting
/// when that window expires. A gate that wants one uniform hold passes the
/// same duration twice.
///
/// The count is per hook, not per stream, and that is enough here: every
/// gate offers exactly one stream.
struct HoldingHook {
    first: Duration,
    rest: Duration,
    seen: AtomicUsize,
}

impl HoldingHook {
    fn new(first: Duration, rest: Duration) -> Arc<Self> {
        Arc::new(Self { first, rest, seen: AtomicUsize::new(0) })
    }
}

impl ProxyHook for HoldingHook {
    fn interest(&self) -> Interest {
        Interest::OBJECTS
    }

    fn on_object(&self, _cx: &ObjectCtx<'_>, _raw: &[u8]) -> Action {
        let index = self.seen.fetch_add(1, Ordering::SeqCst);
        Action::Pass.delayed(if index == 0 { self.first } else { self.rest })
    }
}

// ── media, encoded independently of the proxy ──────────────────────────

/// The stream type byte for a [`DRAFT`] subgroup header carrying an
/// explicit Subgroup ID.
///
/// Restated rather than taken from the crate under test, so these gates
/// compare the proxy against a fixture and not against its own output.
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

/// A subgroup stream header on `track_alias`: group 0, subgroup 0,
/// publisher priority `0x80`. Five bytes on every draft 07-20.
fn subgroup_header(track_alias: u64) -> Vec<u8> {
    assert!(track_alias < 64, "fixture: single-byte varint only");
    vec![subgroup_stream_type(DRAFT), track_alias as u8, 0x00, 0x00, 0x80]
}

/// A subgroup stream split into its header and one buffer per object.
///
/// Split rather than returned whole because every count in this file is
/// per object: the header is written inline by the proxy and the objects
/// are what the hook holds, so a gate has to be able to name the two
/// separately. One writer and one pass, because Object IDs are
/// delta-encoded on drafts 14-20 and encoding the objects independently
/// would encode each delta against nothing.
fn subgroup_pieces(track_alias: u64, count: u64, payload_len: usize) -> (Vec<u8>, Vec<Vec<u8>>) {
    let head = subgroup_header(track_alias);
    let mut cursor = &head[..];
    let header = AnySubgroupHeader::decode_stream(DRAFT, &mut cursor)
        .expect("fixture: the subgroup header must decode or nothing below is media");
    let mut writer =
        AnySubgroupObjectWriter::new(&header).expect("fixture: subgroup object writer");

    let mut objects = Vec::with_capacity(count as usize);
    for object_id in 0..count {
        let fill = u8::try_from(0xA0 + object_id % 0x40).expect("fixture: fill byte");
        let obj = AnySubgroupObject {
            object_id,
            extension_headers: Vec::new(),
            extension_count: None,
            status: None,
            payload: vec![fill; payload_len],
        };
        let mut buf = Vec::new();
        writer.write_object(&obj, &mut buf).expect("fixture: write object");
        objects.push(buf);
    }
    (head, objects)
}

/// The stream every gate but the first offers: six objects of 64 payload
/// bytes each, all whole.
///
/// Whole matters. The conservation gate's equality is over bytes that the
/// proxy either wrote to the relay or named as abandoned, and a source cut
/// in the middle of an object would leave a partial frame in the framer
/// that belongs to neither total.
fn the_stream() -> (Vec<u8>, Vec<Vec<u8>>) {
    subgroup_pieces(1, 6, 64)
}

// ── the proxy under test ───────────────────────────────────────────────

/// A proxy config bound to an ephemeral port and pointed at `upstream`.
///
/// Port 0 deliberately: the port is chosen inside `run()` and read back
/// through [`ProxyControl::local_addr`], which is what every gate connects
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

/// Poll `probe` until it answers, or give up loudly.
async fn wait_for<T>(what: &str, mut probe: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + PATIENCE;
    loop {
        if let Some(answer) = probe() {
            return answer;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// What a peer observed when its connection went away, as `(code, reason)`.
///
/// Anything that is not an application close is a panic naming what was
/// seen instead: an idle timeout, a transport error or a local close all
/// mean the requested pair never reached this peer, and reporting them as
/// a mismatched code would be reporting the wrong failure.
async fn close_seen_by(conn: &quinn::Connection, who: &str, patience: Duration) -> (u64, Vec<u8>) {
    let ended = tokio::time::timeout(patience, conn.closed()).await.unwrap_or_else(|_| {
        panic!(
            "the {who} peer's connection was still open {patience:?} after the close was requested"
        )
    });
    match ended {
        quinn::ConnectionError::ApplicationClosed(close) => {
            (close.error_code.into_inner(), close.reason.to_vec())
        }
        other => panic!(
            "the {who} peer saw {other:?} rather than an application close carrying a code and a \
             reason"
        ),
    }
}

/// A running proxy with one client connected, its relay leg dialled and its
/// session registered — everything a close needs to be observable at both
/// ends.
struct Run {
    proxy: Arc<TransparentProxy>,
    control: ProxyControl,
    /// Where `QueuedBytesAtTeardown` is read from.
    observer: Arc<RecordingObserver>,
    /// The one session this proxy is running, as the census names it.
    session: SessionId,
    /// The client peer, which observes one half of every close.
    client: quinn::Connection,
    /// The relay peer, which observes the other half.
    relay_conn: quinn::Connection,
    /// The relay itself, for accepting the destination stream — and held
    /// beyond that, because dropping it stops the endpoint accepting.
    relay: Arc<FakeRelay>,
    /// Held, not used: a `quinn::Endpoint` dropped out from under its
    /// connection takes the connection with it, and every gate here is
    /// waiting to see how that connection *ends*.
    client_ep: quinn::Endpoint,
    loop_task: tokio::task::JoinHandle<()>,
}

impl Run {
    /// Stand the whole topology up with `hook` attached and `drain` as the
    /// session's drain window.
    async fn start(hook: Arc<dyn ProxyHook>, drain: Duration) -> Self {
        common::init_crypto();
        let relay = Arc::new(FakeRelay::bind(ALPN));

        let mut session = common::session_config(DRAFT, relay.addr);
        // The one knob a requested close reads. Assigned rather than named
        // in a literal because `EgressConfig` is `#[non_exhaustive]`.
        session.egress.drain_timeout = drain;

        let observer = Arc::new(RecordingObserver::new());
        let proxy = Arc::new(TransparentProxy::with_hook(
            proxy_config(session),
            Arc::clone(&observer) as Arc<_>,
            hook,
        ));

        let control = proxy.control();
        let running = Arc::clone(&proxy);
        let loop_task = tokio::spawn(async move {
            let _ = running.run().await;
        });
        let addr: SocketAddr =
            wait_for("fixture: the proxy to bind", || control.local_addr().ok()).await;

        let (client_ep, client) =
            tokio::time::timeout(PATIENCE, common::connect_client(addr, ALPN))
                .await
                .expect("fixture: the client handshake completed");

        let relay_conn = tokio::time::timeout(PATIENCE, relay.connection())
            .await
            .expect("fixture: the proxy dialled the relay");

        // Registration happens at the top of the session's run function, so
        // an id is listed here well before anything is forwarded.
        let session =
            wait_for("the session to be listed", || control.sessions().first().copied()).await;

        Self { proxy, control, observer, session, client, relay_conn, relay, client_ep, loop_task }
    }

    /// Open a source stream, write its header and every object, and hand
    /// back the send half — kept by the caller so the source never FINs —
    /// with a reader on the destination stream the relay accepted.
    async fn offer(&self, head: &[u8], objects: &[Vec<u8>]) -> (quinn::SendStream, Tap) {
        let mut send = self.client.open_uni().await.expect("fixture: open_uni");
        send.write_all(head).await.expect("fixture: write the stream header");
        for object in objects {
            send.write_all(object).await.expect("fixture: write an object");
        }

        let recv = tokio::time::timeout(PATIENCE, self.relay.accept_uni())
            .await
            .expect("fixture: the proxy opened a destination stream for it");
        let rx = Tap::spawn(recv);

        // The header carries no `ObjectMeta`, so no hook is consulted for
        // it and it is written inline: waiting for it here is what makes
        // every count below a count of *object* bytes.
        assert_eq!(
            rx.wait_for(head.len()).await,
            head.len(),
            "the stream header is forwarded inline and nothing the hook is holding has been \
             released yet"
        );
        (send, rx)
    }

    /// Ask this proxy to end its one session, with the pair every gate
    /// asserts on.
    fn close(&self) {
        self.control
            .close_session(self.session, CLOSE_CODE, CLOSE_REASON)
            .expect("a session listed a moment ago takes a close");
    }

    /// Every byte the session named as abandoned at teardown, summed.
    fn stranded(&self) -> usize {
        self.observer
            .impairments()
            .iter()
            .filter_map(|kind| match kind {
                ImpairmentKind::QueuedBytesAtTeardown { bytes, .. } => Some(*bytes),
                _ => None,
            })
            .sum()
    }

    /// Wait until the session has reported whatever it abandoned.
    ///
    /// The impairment is emitted by the pipe's own cancellation arm, which
    /// runs before the connections are closed — so it is already recorded
    /// by the time a peer observes the close. Polled anyway rather than
    /// read once, because "already recorded" is an ordering argument about
    /// another task and a poll costs nothing when the answer is there.
    async fn stranded_once_reported(&self) -> usize {
        wait_for("the session to report what it abandoned", || {
            let bytes = self.stranded();
            (bytes > 0).then_some(bytes)
        })
        .await
    }

    /// Stop the accept loop and let everything go, in that order.
    ///
    /// The two held-open halves are dropped explicitly and last, after the
    /// loop has returned, so a reader is not left wondering whether they
    /// were dropped early enough to matter.
    async fn finish(self) {
        self.proxy.cancel_token().cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), self.loop_task).await;
        drop(self.client_ep);
        drop(self.relay);
    }
}

// ── gate one: the close reaches both peers ─────────────────────────────

/// A requested close carries its code and its reason to the client **and**
/// to the relay, byte for byte.
///
/// Both legs, from one call, because a session has two peers and a close
/// that reached only the one the caller happened to be watching would look
/// perfectly correct from there. The relay's half is the one a caller
/// depends on without ever seeing: a relay left to discover the session had
/// ended by timing out keeps its subscription state alive for its whole
/// idle timeout.
///
/// The pair is asserted exactly, and neither half of it is the proxy's own
/// default `(0, b"proxy session ended")` — a fixture that asked for the
/// default could not tell a close that carried the request from one that
/// fell back to it.
///
/// *Ablation, recorded, and it takes two — one per half of the claim.*
///
/// Replace `let (close_code, close_reason) = closer.close_args();` in
/// `run_with_transport` with the proxy's hard-coded default pair, so a
/// requested close is recorded and then ignored. This row fails with
///
/// ```text
/// assertion `left == right` failed: the client leg closes with the code and
/// reason the call named, not the proxy's own default
///   left: (0, [112, 114, 111, 120, 121, 32, 115, 101, 115, 115, 105, 111, 110, 32, 101, 110, 100, 101, 100])
///  right: (42, [116, 104, 101, 32, 99, 111, 110, 116, 114, 111, 108, 32, 112, 108, 97, 110, 101, 32, 97, 115, 107, 101, 100])
/// ```
///
/// Delete the `relay.close(close_code, &close_reason);` line instead, so
/// only the client leg is closed explicitly. The relay leg then ends when
/// the proxy's last handle on it is dropped, which quinn reports as an
/// implicit close — code 0, empty reason — and this row fails with
///
/// ```text
/// assertion `left == right` failed: the relay leg closes with the same pair:
/// a requested close ends both legs, not the one the caller happens to be
/// watching
///   left: (0, [])
///  right: (42, [116, 104, 101, 32, 99, 111, 110, 116, 114, 111, 108, 32, 112, 108, 97, 110, 101, 32, 97, 115, 107, 101, 100])
/// ```
#[tokio::test]
async fn a_requested_close_carries_its_code_and_reason_to_both_peers() {
    let run = Run::start(Arc::new(NoOpHook), Duration::from_millis(100)).await;

    run.close();

    let want = (u64::from(CLOSE_CODE), CLOSE_REASON.to_vec());
    assert_eq!(
        close_seen_by(&run.client, "client", PATIENCE).await,
        want,
        "the client leg closes with the code and reason the call named, not the proxy's own default"
    );
    assert_eq!(
        close_seen_by(&run.relay_conn, "relay", PATIENCE).await,
        want,
        "the relay leg closes with the same pair: a requested close ends both legs, not the one \
         the caller happens to be watching"
    );

    run.finish().await;
}

// ── gate two: a drain that has time delivers ───────────────────────────

/// The hold every object in the drain-delivers gate is given.
const DELIVERED_HOLD: Duration = Duration::from_secs(2);

/// The window that gate gives the queues, three times the hold.
const GENEROUS_DRAIN: Duration = Duration::from_secs(6);

/// With bytes queued and a window that covers their release, the peer
/// receives all of them before the close.
///
/// The whole stream is held for [`DELIVERED_HOLD`] and the close is
/// requested while every object is still waiting — which the fixture
/// checks, so a run in which the hold had already expired cannot pass by
/// having nothing to drain. The window is [`GENEROUS_DRAIN`], three times
/// the hold, and the claim is that the six objects arrive at the relay
/// anyway.
///
/// This is the half of `close_session` that is easy to get wrong in the
/// direction that looks right: a close that cancelled immediately would
/// still close both legs with the right code, and every assertion about the
/// close itself would pass while the queued objects vanished.
///
/// *Ablation, recorded:* pass `Duration::ZERO` instead of `drain` at
/// `close_after_draining`'s call site in `serve_session_commands`, so a
/// requested close gives the queues no window whatever the session was
/// configured with. This row fails with
///
/// ```text
/// assertion `left == right` failed: a drain window three times the hold
/// delivers every object that was queued when the close was requested
///   left: 5
///  right: 401
/// ```
///
/// — five bytes being the stream header, which is written inline and is
/// never in the queue at all, and 396 the six objects that were.
#[tokio::test]
async fn a_drain_with_time_delivers_what_was_queued() {
    let run = Run::start(HoldingHook::new(DELIVERED_HOLD, DELIVERED_HOLD), GENEROUS_DRAIN).await;
    let (head, objects) = the_stream();
    let queued: usize = objects.iter().map(Vec::len).sum();

    let (_source, rx) = run.offer(&head, &objects).await;
    assert_eq!(
        rx.len(),
        head.len(),
        "the fixture's premise: every object is still queued when the close is requested, so \
         nothing below can be arriving because the hold had already expired"
    );

    run.close();

    assert_eq!(
        rx.wait_for(head.len() + queued).await,
        head.len() + queued,
        "a drain window three times the hold delivers every object that was queued when the close \
         was requested"
    );
    // The close is observed *before* the impairments are read, and the
    // order is load-bearing: a stream reports what it abandoned from its
    // own cancellation arm, which runs before either leg is closed, so a
    // count taken while the session was still up could read zero for a
    // session that was about to name something.
    assert_eq!(
        close_seen_by(&run.client, "client", PATIENCE).await,
        (u64::from(CLOSE_CODE), CLOSE_REASON.to_vec()),
        "and the close still carries what was asked for: a drain changes what reached the peer, \
         never what the close says"
    );
    assert_eq!(
        run.stranded(),
        0,
        "a drain that emptied the queues abandons nothing, so no stream is named as having lost \
         bytes"
    );

    run.finish().await;
}

// ── gate three: the drain is bounded ───────────────────────────────────

/// The hold the bounded-drain gate leaves outstanding, three times
/// [`PROMPT`].
const ABANDONED_HOLD: Duration = Duration::from_secs(6);

/// A drain window of zero closes at once and names every byte it abandoned.
///
/// Zero is a bound, not a licence to wait — a reading of "no timeout" as
/// "no deadline" is the single most plausible way for this knob to be
/// wrong, and it is invisible from a session that had nothing queued. So
/// the fixture leaves six objects held for [`ABANDONED_HOLD`] and asserts
/// three things: the close reaches the client within [`PROMPT`], a third of
/// that hold; not one object byte reaches the relay; and the whole of what
/// was queued is named in
/// `ImpairmentKind::QueuedBytesAtTeardown`.
///
/// The third is what separates this from data loss. The bytes are
/// abandoned rather than flushed, deliberately — a flush into a connection
/// about to send `CONNECTION_CLOSE` is neither confirmably delivered nor
/// confirmably lost — and the count is the proxy saying exactly what went.
///
/// *Ablation, recorded:* make `close_after_draining` read a zero window as
/// unbounded, `wait_idle(if drain.is_zero() { Duration::from_secs(60) }
/// else { drain })`. This row fails with
///
/// ```text
/// a drain window of zero is a bound, not a licence to wait: the close had
/// not reached the client 2s after it was requested, with a 6s hold still
/// outstanding
/// ```
#[tokio::test]
async fn a_zero_drain_window_closes_at_once_and_names_what_it_abandoned() {
    let run = Run::start(HoldingHook::new(ABANDONED_HOLD, ABANDONED_HOLD), Duration::ZERO).await;
    let (head, objects) = the_stream();
    let queued: usize = objects.iter().map(Vec::len).sum();

    let (_source, rx) = run.offer(&head, &objects).await;
    run.close();

    let ended = tokio::time::timeout(PROMPT, run.client.closed()).await.unwrap_or_else(|_| {
        panic!(
            "a drain window of zero is a bound, not a licence to wait: the close had not reached \
             the client {PROMPT:?} after it was requested, with a {ABANDONED_HOLD:?} hold still \
             outstanding"
        )
    });
    match ended {
        quinn::ConnectionError::ApplicationClosed(close) => assert_eq!(
            (close.error_code.into_inner(), close.reason.to_vec()),
            (u64::from(CLOSE_CODE), CLOSE_REASON.to_vec()),
            "a window that gave the queues nothing still closes with what was asked for"
        ),
        other => panic!("the client saw {other:?} rather than the requested application close"),
    }

    assert_eq!(
        rx.len(),
        head.len(),
        "with no window at all the held objects are abandoned, so the relay has the inline header \
         and not one object byte"
    );
    assert_eq!(
        run.stranded_once_reported().await,
        queued,
        "and every abandoned byte is named, so what did not make it is reported rather than lost \
         quietly"
    );

    run.finish().await;
}

// ── gate four: conservation ────────────────────────────────────────────

/// When the conservation gate's first object is released.
///
/// Two bounds at once, which is why it is neither shorter nor longer. It
/// has to be comfortably inside [`SPLIT_DRAIN`], so that object reaches the
/// relay; and it has to outlast the fixture's own setup — a bind, a
/// handshake, an upstream dial and a header round-trip, together a few tens
/// of milliseconds — so the object is still queued when the close is
/// requested rather than having gone out before it.
const RELEASED_HOLD: Duration = Duration::from_millis(500);

/// When its remaining objects would be released — far enough beyond
/// [`SPLIT_DRAIN`] that no amount of load brings them inside it.
const STRANDED_HOLD: Duration = Duration::from_secs(8);

/// The window that separates the two.
const SPLIT_DRAIN: Duration = Duration::from_secs(2);

/// Delivered plus stranded equals what was queued at the close, as an
/// equality, with both terms non-zero.
///
/// The two gates above each prove one column of this: a window that covers
/// everything strands nothing, and a window that covers nothing delivers
/// nothing. Either alone satisfies the arithmetic trivially. This row makes
/// the drain expire *part way through* the queue — the first object is
/// released 500 ms in, the rest are not due for eight seconds, and the
/// window is two — so both terms are non-zero and the equality has
/// something to say.
///
/// It is deliberately count-based and nothing else. Which object arrived,
/// in what order, and how the bytes were distributed across reads are all
/// beside the point: the claim is that no byte the client wrote is
/// unaccounted for, and a byte is accounted for by being either at the
/// relay or named in an impairment. Nothing here reads a queue depth back
/// from the proxy.
///
/// The stream is written whole — every object complete, the source never
/// finished — so there is no partial frame belonging to neither total. The
/// source is kept open on purpose: a FIN would send the pipe down its
/// end-of-stream drain, which honours release times with no window at all
/// and would deliver the eight-second objects regardless of the close.
///
/// *Ablation, recorded, and what it shows is the point of stating this
/// separately:* forcing the window to `Duration::ZERO` at
/// `close_after_draining`'s call site — the mutation the delivery gate
/// records — reddens this row's **premise** rather than its equality, with
///
/// ```text
/// assertion `left == right` failed: the object whose release fell inside
/// the window reached the relay
///   left: 0
///  right: 66
/// ```
///
/// The equality itself still held under that mutation, because a proxy that
/// drains nothing strands everything and the arithmetic closes at
/// `0 + 396 == 396`. That is the identity behaving as an identity should:
/// it survives a proxy that drains too little and one that drains too much,
/// and fails only for a proxy that loses bytes without saying so. The
/// assertions after the close are ordered so the split reports before the
/// equality — a run in which nothing was released at all is a fixture that
/// stopped splitting the queue, and reading that as a conservation failure
/// would send the next reader to the wrong place.
#[tokio::test]
async fn delivered_plus_stranded_equals_what_was_queued() {
    let run = Run::start(HoldingHook::new(RELEASED_HOLD, STRANDED_HOLD), SPLIT_DRAIN).await;
    let (head, objects) = the_stream();
    let queued: usize = objects.iter().map(Vec::len).sum();
    let first = objects[0].len();

    let (_source, rx) = run.offer(&head, &objects).await;
    assert_eq!(
        rx.len(),
        head.len(),
        "the fixture's premise: nothing has been released yet when the close is requested"
    );

    run.close();

    // Both counts are read after the close has been observed at the peer,
    // which is strictly after the window expired, the remainder was
    // abandoned and the report was made — so neither total can still be
    // moving underneath the arithmetic below.
    assert_eq!(
        close_seen_by(&run.client, "client", PATIENCE).await,
        (u64::from(CLOSE_CODE), CLOSE_REASON.to_vec()),
        "a drain that expired part way through still closes with what was asked for"
    );
    let stranded = run.stranded_once_reported().await;
    let delivered = rx.len().saturating_sub(head.len());

    assert_eq!(
        delivered, first,
        "the object whose release fell inside the window reached the relay"
    );
    assert!(
        stranded > 0 && delivered > 0,
        "the window has to expire part way through the queue or the equality below is trivial: \
         delivered {delivered}, stranded {stranded}"
    );
    assert_eq!(
        delivered + stranded,
        queued,
        "every byte the client offered is either at the relay or named as abandoned: no byte is \
         both, and none is neither"
    );

    run.finish().await;
}

// ── gate five: one close per session ───────────────────────────────────

/// The code a second call asks for, which must reach neither peer.
const SECOND_CODE: u32 = 99;

/// Its reason, chosen to share no byte with [`CLOSE_REASON`] so a peer that
/// somehow saw a mixture could not be read as having seen either.
const SECOND_REASON: &[u8] = b"a later caller";

/// A second close, aimed at a session that is still inside the first one's
/// drain window, is refused — and the pair the first call fixed is what both
/// peers are given.
///
/// A close is recorded once. The code and the reason are written into the
/// session's closer the instant the request is accepted, and nothing revises
/// them, so a second call's pair is going nowhere however the proxy answers
/// it. The only two answers available are therefore "refused" and "accepted
/// and silently dropped", and this row is here because the second is the
/// easier one to end up with by accident: the request channel has room, the
/// send succeeds, and every visible sign says the call worked.
///
/// # The window is genuinely open, and that is asserted rather than assumed
///
/// The refusal would look identical if the session had already finished
/// draining and cancelled — [`ControlError::SessionEnded`] covers both — so
/// the row would pass for the wrong reason on a proxy that closed
/// immediately. Two things stop that. The stream is left holding six objects
/// due in [`STRANDED_HOLD`], so the drain cannot end early by running out of
/// work; and after the refusal the client's connection is required to still
/// be **open** for [`PROMPT`], which is only true of a session that is
/// sitting in a drain it has not spent.
///
/// The margins are one-sided as everywhere else here: the window is
/// [`GENEROUS_DRAIN`], three times [`PROMPT`], and the hold outlasts the
/// window, so load can only make the session slower to close and never
/// quicker.
///
/// *Ablation, recorded:* delete the `if !handle.closer.record(..)` guard from
/// `ProxyControl::close_session` in `src/control.rs`, leaving the losing
/// record ignored and the request handed over as it was before. The second
/// call is then taken, its `SessionCommand::Close` is queued behind a session
/// task that never comes back for it, and this row fails with
///
/// ```text
/// thread 'a_second_close_inside_the_drain_window_is_refused_and_the_first_pair_stands'
/// panicked at crates\moqtap-proxy\tests\control_teardown.rs:
/// a session already draining under one close does not take a second: ()
/// ```
///
/// The `()` is the `Ok(())` the mutated call handed back — a close accepted,
/// reported as applied, and reaching neither peer, which is what the guard
/// exists to prevent. The four gates above stayed green in that same run
/// (`4 passed; 1 failed`), so nothing else in this file sees the case.
#[tokio::test]
async fn a_second_close_inside_the_drain_window_is_refused_and_the_first_pair_stands() {
    let run = Run::start(HoldingHook::new(STRANDED_HOLD, STRANDED_HOLD), GENEROUS_DRAIN).await;
    let (head, objects) = the_stream();

    let (_source, rx) = run.offer(&head, &objects).await;
    assert_eq!(
        rx.len(),
        head.len(),
        "the fixture's premise: every object is still queued, so the drain the first close starts \
         cannot end early for want of anything to flush"
    );

    run.close();

    let refusal = run
        .control
        .close_session(run.session, SECOND_CODE, SECOND_REASON)
        .expect_err("a session already draining under one close does not take a second");
    assert_eq!(
        refusal,
        ControlError::SessionEnded(run.session),
        "a session that is already ending is named as such, so a caller learns its pair was not \
         taken instead of being told the request succeeded"
    );

    assert!(
        tokio::time::timeout(PROMPT, run.client.closed()).await.is_err(),
        "the session is still inside the drain the first close gave it — so the refusal above is \
         'one close already owns this session' and not 'this session had already gone'"
    );

    let want = (u64::from(CLOSE_CODE), CLOSE_REASON.to_vec());
    assert_eq!(
        close_seen_by(&run.client, "client", PATIENCE).await,
        want,
        "the client is closed with the pair the first call fixed, not the second call's"
    );
    assert_eq!(
        close_seen_by(&run.relay_conn, "relay", PATIENCE).await,
        want,
        "and so is the relay: a refused close changes nothing on either leg"
    );

    run.finish().await;
}

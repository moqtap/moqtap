//! A small per-stream receive window is what makes shaping backpressure
//! reach the source.
//!
//! `Overflow::Block` stops the proxy reading its source stream the moment
//! the egress queue is full. That is a real stall of the *proxy*, and it is
//! gated elsewhere by counting what the shaper saw. It is **not**, on its
//! own, a stall of the *publisher*: between the two sits QUIC flow control,
//! and quinn's default per-stream receive window is 1.25 MB. Everything the
//! source writes up to that limit is accepted by the receiver's transport
//! and buffered where no application can see it.
//!
//! Measured with the fixtures below, front-end listener left on quinn's
//! defaults and a two-object egress queue held shut by a dry token bucket:
//! the source pushed **about 1.25 MB** before its first write pended, and
//! the whole run reported
//! `objects_seen: 2` and a *single* blocked episode. The shaper had stopped
//! reading after two objects and the transport absorbed a megabyte of the
//! consequence. A test written that way measures the receive window,
//! not the shaper.
//!
//! With the same session behind a 64 KiB window the source stalls at
//! **82 370 bytes**, and the shaper's own two numbers are unchanged. That
//! pair — fifteen times the difference at the publisher, no difference at
//! all at the proxy — is what this file gates.
//!
//! # This is a configuration fact, not a missing feature
//!
//! Nothing in the proxy needs to change. `ListenerConfig::transport_config`
//! and `ProxySessionConfig::upstream_transport_config` already carry an
//! `Arc<quinn::TransportConfig>` into the front-end bind and the upstream
//! connect respectively, and `stream_receive_window` lives on that type. A
//! caller that wants the publisher to feel the shaper sets a small window
//! on the leg that *receives* from it — the listener — and gets
//! backpressure end to end. This file is the evidence that the knob does
//! that, and the size of the difference it makes.
//!
//! # What is not possible, and why the window has to be small from the start
//!
//! Two things a reader will reach for first, and neither exists:
//!
//! **There is no per-stream window API.** `stream_receive_window` is a
//! field of `quinn::TransportConfig`, which is fixed at endpoint bind or at
//! connect and applies to *every* stream of every connection made through
//! it. There is no `RecvStream` knob and no per-stream override, so a
//! caller cannot shrink the window of the one stream it is shaping and
//! leave the rest alone. A fixture that wants a narrow window narrows the
//! whole leg.
//!
//! **Shrinking a window afterwards does not take credit back.** The only
//! runtime knob is `quinn::Connection::set_receive_window`, and it is
//! connection-level rather than per-stream. Worse for this purpose, a
//! shrink is *booked as a debt*: the receiver records the difference and
//! works it off by withholding future grants, because credit already
//! advertised in `MAX_STREAM_DATA` / `MAX_DATA` cannot be retracted — the
//! peer is entitled to spend it and the wire format has no way to say
//! otherwise. So a test that connects on the defaults, waits for the shaper
//! to block and *then* shrinks finds the source still holding its original
//! 1.25 MB allowance, and measures nothing.
//!
//! Hence the shape of both fixtures below: the window is chosen before
//! `Listener::bind`, and the bind/accept/connect sequence is spelled out
//! here rather than borrowed from the shared harness, whose proxy spawner
//! binds its front end on quinn's defaults.
//!
//! # Which claims here a loaded machine can move
//!
//! None of them, and that is a property of how each is phrased rather than
//! of the numbers. Every assertion in this file is one of:
//!
//! * **A liveness anchor.** "This `write_all` completes" — of a length the
//!   configured window is guaranteed to cover. A slow box makes it slower
//!   and never wrong; the timeout on it is a failure ceiling, there so a
//!   broken build reports the claim it was waiting on instead of hanging.
//! * **A negative claim over a window.** "This `write_all` does *not*
//!   complete in [`STALL_WINDOW`]." Load can only make a negative claim
//!   more true: a slower box moves fewer bytes, not more.
//! * **A count.** `objects_seen`, `blocked_episodes`. No duration in either.
//!
//! There is deliberately no assertion of the form "the source pushed
//! exactly N bytes before stalling" against a *measured* N, because that
//! would need a stall detector, and a stall detector is a clock reading in
//! the one direction load can push. It would also be asserting a number
//! that is not a property of the transport: the source stalls a little
//! *short* of the window, by however much of the final write did not fit,
//! so the stall point is a function of the writer's chunk size. Measured
//! directly against a receiver that never reads, with quinn on its
//! defaults: 1 KiB chunks pend after 1 249 281 bytes, 719 short of the
//! 1 250 000-byte window. Quoting a stall point without the chunk size
//! that produced it — and this file quoted 1 250 000 as "the default
//! window to the byte" for a while — states a fixture detail as a
//! transport constant. The equality this file does make —
//! [`a_configured_window_is_exactly_the_credit_a_source_gets`] — is
//! assembled out of the two safe forms instead: the window's worth of bytes
//! goes in, and the next byte does not.
//!
//! # Wall time
//!
//! Both rows spend real time only where they are *supposed* to see nothing
//! happen: one [`STALL_WINDOW`] each. The whole binary is 1.07 s for both
//! rows run one at a time, which includes the megabyte the control arm
//! pushes (20 ms of it) and the two half-second negative windows.
//!
//! No row here is `#[ignore]`d, and that is an audit result rather than an
//! omission: there is no timing *accuracy* claim in the file to be
//! calibration. Every duration below is either a failure ceiling or a
//! window a negative claim is made over.

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
use std::sync::Arc;
use std::time::Duration;

use moqtap_codec::dispatch::{AnySubgroupHeader, AnySubgroupObject, AnySubgroupObjectWriter};
use moqtap_codec::version::DraftVersion;

use moqtap_proxy::event::SessionId;
use moqtap_proxy::hook::{NoOpHook, ProxyHook};
use moqtap_proxy::listener::{AcceptedConn, Listener, ListenerConfig};
use moqtap_proxy::observer::{NoOpProxyObserver, ProxyObserver};
use moqtap_proxy::session::ProxySession;
use moqtap_proxy::shape::{
    BucketConfig, ClassRule, ClassStats, Discipline, Matcher, Overflow, QueueConfig, ShapeProfile,
    ShapeStats,
};

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use common::FakeRelay;

// ── the draft these fixtures speak ─────────────────────────────────────

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

/// The draft the fixture stream is built for: the **newest** one this build
/// compiled.
///
/// Derived rather than named, because the session decodes the fixture's
/// header bytes against the draft it was configured with — a hardcoded
/// draft reddens every single-draft build whose draft is not that one, and
/// nothing here reads a draft anyway. A subgroup stream is a subgroup
/// stream.
const DRAFT: DraftVersion = COMPILED_DRAFTS[COMPILED_DRAFTS.len() - 1];

/// The ALPN both fixtures speak. `moq-00` leaves `draft_is_fixed` false,
/// which only affects the control parser — nothing here opens one.
const ALPN: &[u8] = b"moq-00";

/// Track alias of the one stream either fixture publishes.
const TRACK_ALIAS: u64 = 1;

// ── the windows, and the separation between them ───────────────────────

/// The per-stream receive window a caller that wants felt backpressure
/// configures, in bytes.
///
/// 64 KiB, and the two properties that matter are that it is a round number
/// a reader can check against the assertions below, and that it is
/// **nineteen times smaller** than quinn's 1 250 000-byte default. Both
/// rows are separated by that ratio; shrink it and the rows stop being able
/// to tell a configured window from an unconfigured one.
const SMALL_WINDOW: u32 = 64 * 1024;

/// The push length the *default*-window arms use as their liveness anchor.
///
/// 1 MiB: strictly below quinn's 1 250 000-byte default per-stream window,
/// so "this completed" is a claim about the window rather than about the
/// fixture running out of bytes to offer. The margin is the ~19 % between
/// the two, and it is not load-sensitive — flow-control credit is granted
/// by the transport parameters at handshake, so a slow box delays the write
/// and cannot shrink the allowance.
const WIDE_PUSH: usize = 1024 * 1024;

/// How much a source may get past [`SMALL_WINDOW`] before the narrow-window
/// row calls the fixture broken.
///
/// The source's total allowance is its initial window plus whatever the
/// proxy has already consumed off the wire, because QUIC re-advertises
/// `MAX_STREAM_DATA` as the application reads. The proxy reads in 8 KiB
/// chunks and stops the instant the egress queue holds [`QUEUE_DEPTH`]
/// objects, and an object here is deliberately larger than that read buffer
/// (see [`OBJECT_PAYLOAD`]), so what it can consume first is capped by the
/// depth rather than by any clock. Measured: the source stalls at **82 370
/// bytes**, i.e. 16 834 past its window — the five-byte stream header, two
/// whole objects and the partial read that filled the queue.
///
/// 64 KiB is 3.9x that measurement, and the quantity being bounded is
/// derived from a count, so load can only push it down.
///
/// Widen this, do not delete it: it is the upper half of a bracket, and the
/// bracket is what turns "the source stalled somewhere" into "the source
/// stalled at the window".
const DRAIN_CEILING: usize = 64 * 1024;

/// How long a write that must *not* complete is given to prove it.
///
/// A negative claim needs a window, not a poll. Load can only make this
/// claim more true, so the only thing the number costs is wall time —
/// which is why it is half a second rather than the harness's ten.
const STALL_WINDOW: Duration = Duration::from_millis(500);

/// How long a wait that *must* end is given before it reports what it was
/// waiting for. A failure ceiling, never spent by a correct build.
const LIVENESS: Duration = Duration::from_secs(10);

// ── the shaped session that stops reading ──────────────────────────────

/// Objects the egress queue may hold. Two, which is the smallest depth that
/// still distinguishes "queued and stalled" from "never started".
const QUEUE_DEPTH: usize = 2;

/// The payload each fixture object carries.
///
/// 8192 rather than something smaller, and the reason is arithmetic rather
/// than taste: the forwarding pipe reads into an 8 KiB buffer, so an object
/// whose *wire* size is at or above that buffer cannot be completed twice by
/// one read. That is what makes "the shaper saw at most `QUEUE_DEPTH`
/// objects" an exact bound instead of one with an unstated overshoot in it,
/// and it is what keeps [`DRAIN_CEILING`] a small multiple of the depth
/// rather than of the whole stream.
///
/// Widen the payload, do not shrink it: below 8192 the two rows silently
/// stop measuring the thing they name.
const OBJECT_PAYLOAD: usize = 8192;

/// Objects the fixture stream carries. Enough that [`WIDE_PUSH`] bytes of
/// it exist to be offered, with room to spare.
const OFFERED_OBJECTS: u64 = 160;

/// The bucket the shaping profile charges against.
const BUCKET: &str = "media";
/// The one class its rule claims everything into.
const CLASS: &str = "all";

/// The queue deadline both fixtures pin.
///
/// A queued object that outlives `max_hold` is delivered anyway, which
/// reopens the drain and therefore reopens the read — so `max_hold` is the
/// one clock that could unblock a source these rows need to stay blocked.
/// Both rows together take 1.07 s, so thirty seconds is a separation of
/// more than 25x, and it is written down rather than inherited so the
/// margin is a number this file chose rather than one it was handed.
const MAX_HOLD: Duration = Duration::from_secs(30);

/// A profile whose single catch-all class is charged to a bucket that never
/// grants, over a queue of [`QUEUE_DEPTH`] objects under `Overflow::Block`.
///
/// `rate_bps: Some(0)` with a zero burst is legal and is not the same as
/// `None` (unlimited): the bucket never refills and is spent before the
/// first unit, so nothing is ever grantable and nothing the test does
/// reopens the drain. That is the state these rows need — the proxy's read
/// branch shut and staying shut — and it is reached from configuration
/// alone, with no hook and no observer.
fn dry_bucket_profile() -> ShapeProfile {
    // Field assignment rather than struct literals: these config types are
    // `#[non_exhaustive]`, which forbids both struct-expression and
    // functional-update syntax from outside the crate.
    let mut bucket = BucketConfig::default();
    bucket.name = BUCKET.to_string();
    bucket.rate_bps = Some(0);
    bucket.burst_bytes = 0;

    let mut class = ClassRule::default();
    class.name = CLASS.to_string();
    class.bucket = BUCKET.to_string();
    // `Matcher::default()` is all-`None`, which claims every unit. Spelled
    // out because "this class matches everything" is load-bearing here, not
    // an omission.
    class.matcher = Matcher::default();

    let mut queue = QueueConfig::default();
    queue.depth_objects = QUEUE_DEPTH;
    queue.max_hold = Some(MAX_HOLD);
    queue.overflow = Overflow::Block;

    ShapeProfile::try_new(vec![bucket], vec![class], queue, Discipline::Fifo)
        .expect("one catch-all class over the one bucket it names")
}

// ── the fixture stream ─────────────────────────────────────────────────

/// The stream-type field [`DRAFT`] opens a subgroup stream with, for a
/// header carrying an explicit Subgroup ID.
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

/// A subgroup stream header for `draft` on [`TRACK_ALIAS`]: group 0,
/// subgroup 0, publisher priority `0x80`. Five bytes on every draft 07-20.
fn subgroup_header_bytes(draft: DraftVersion) -> Vec<u8> {
    vec![subgroup_stream_type(draft), TRACK_ALIAS as u8, 0x00, 0x00, 0x80]
}

/// The whole fixture stream: a [`DRAFT`] subgroup header followed by
/// [`OFFERED_OBJECTS`] objects of [`OBJECT_PAYLOAD`] bytes each.
///
/// Encoded once by one writer rather than assembled per object, because
/// object IDs are delta-encoded on the wire from draft 14 on and a stream
/// restarted partway through would encode a delta against nothing.
fn fixture_stream() -> Vec<u8> {
    let head = subgroup_header_bytes(DRAFT);
    let mut cursor = &head[..];
    let header =
        AnySubgroupHeader::decode_stream(DRAFT, &mut cursor).expect("subgroup header decode");
    let mut writer = AnySubgroupObjectWriter::new(&header).expect("subgroup object writer");

    let mut out = head;
    for object_id in 0..OFFERED_OBJECTS {
        let fill = u8::try_from(0xA0 + object_id % 0x40).expect("fill byte");
        let obj = AnySubgroupObject {
            object_id,
            extension_headers: Vec::new(),
            extension_count: None,
            status: None,
            payload: vec![fill; OBJECT_PAYLOAD],
        };
        writer.write_object(&obj, &mut out).expect("write object");
    }
    assert!(
        out.len() > WIDE_PUSH,
        "the fixture must be able to offer more than the default window absorbs, or the \
         control arm below proves only that the fixture ran out: {} bytes",
        out.len()
    );
    out
}

// ── a proxy whose front-end window this file chose ─────────────────────

/// A running shaped session, plus its address and a live handle on its
/// statistics.
///
/// The `ProxySession` is built *before* the accept task is spawned and held
/// behind an `Arc`, which is what makes its counters readable from the test
/// thread while it is still running — every claim below is about what the
/// session had done *by* some instant, so waiting for teardown would answer
/// a different question.
struct WindowedProxy {
    addr: SocketAddr,
    cancel: CancellationToken,
    task: JoinHandle<()>,
    session: Arc<ProxySession>,
}

impl WindowedProxy {
    fn shape_stats(&self) -> ShapeStats {
        self.session.shape_stats()
    }

    /// This run's one configured class row.
    ///
    /// Named rather than indexed, so a session that never received the
    /// profile reports *that* instead of an index-out-of-bounds from
    /// somewhere else in the body.
    fn class(&self) -> ClassStats {
        self.shape_stats().classes.first().cloned().expect(
            "a shaped session reports one row per configured class; an empty list means \
             the profile never reached the session, and every claim below it is about a \
             byte pump",
        )
    }

    async fn shutdown(self) {
        self.cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), self.task).await;
    }
}

/// A listener configuration whose only departure from the default is the
/// per-stream receive window it advertises to clients.
///
/// `None` leaves quinn's defaults, which is the control.
fn listener_config(stream_receive_window: Option<u32>) -> ListenerConfig {
    let (cert_chain, key_der) = common::self_signed_localhost();
    let transport_config = stream_receive_window.map(|window| {
        let mut transport = quinn::TransportConfig::default();
        transport.stream_receive_window(quinn::VarInt::from_u32(window));
        Arc::new(transport)
    });
    ListenerConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        cert_chain,
        key_der,
        transport_config,
        transport_profile: None,
        installer: None,
        #[cfg(feature = "qlog")]
        qlog: None,
    }
}

/// Bind a listener with `stream_receive_window`, and run one shaped session
/// behind it against `upstream`.
///
/// The bind/accept sequence is written out rather than taken from the
/// shared harness for exactly one reason: the harness's spawner binds its
/// front end through a helper that has no window parameter, and the window
/// has to be set before the bind — see this file's header for why it cannot
/// be set afterwards.
fn spawn_windowed_proxy(stream_receive_window: Option<u32>, upstream: SocketAddr) -> WindowedProxy {
    let listener = Listener::bind(listener_config(stream_receive_window)).expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let mut config = common::session_config(DRAFT, upstream);
    config.shape = Some(dry_bucket_profile());

    let cancel = CancellationToken::new();
    let session = Arc::new(ProxySession::new(
        SessionId(1),
        config,
        ALPN.to_vec(),
        Arc::new(NoOpProxyObserver) as Arc<dyn ProxyObserver>,
        Arc::new(NoOpHook) as Arc<dyn ProxyHook>,
        cancel.clone(),
    ));

    let run_session = Arc::clone(&session);
    let task = tokio::spawn(async move {
        let conn = match listener.accept().await.expect("accept") {
            AcceptedConn::Quic { conn, .. } => conn,
            #[cfg(feature = "webtransport")]
            _ => panic!("expected a raw-QUIC client"),
        };
        let _ = run_session.run(conn).await;
    });

    WindowedProxy { addr, cancel, task, session }
}

/// Poll `ready` until it answers `true`, or fail naming what was awaited.
///
/// A liveness anchor, never a deadline: both callers wait on a monotone
/// counter a correct implementation always reaches, so load makes this
/// slower and never wrong.
async fn wait_until(mut ready: impl FnMut() -> bool, what: &str) {
    let poll = async {
        loop {
            if ready() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    };
    if tokio::time::timeout(LIVENESS, poll).await.is_err() {
        panic!("timed out waiting for {what}");
    }
}

// ── the equality: a window is exactly the credit it grants ─────────────

/// A receiver that accepts a stream and then never reads a byte of it,
/// bound with `stream_receive_window`.
///
/// Held together: the endpoint, the connection and the accepted
/// `RecvStream` all live inside the spawned task and are never dropped
/// while it runs. That is deliberate — dropping a `RecvStream` sends
/// `STOP_SENDING`, which would end the source's write with an error instead
/// of parking it, and the whole point of the fixture is a write that parks.
fn stalled_receiver(stream_receive_window: Option<u32>) -> (SocketAddr, JoinHandle<()>) {
    common::init_crypto();
    let (endpoint, addr) = common::spawn_quic_server_windowed(&[ALPN], stream_receive_window);
    let task = tokio::spawn(async move {
        let conn = endpoint
            .accept()
            .await
            .expect("the receiver accepted a connection")
            .await
            .expect("the receiver completed its handshake");
        let recv = conn.accept_uni().await.expect("the receiver accepted the source's stream");
        std::future::pending::<()>().await;
        drop((recv, conn, endpoint));
    });
    (addr, task)
}

/// A configured `stream_receive_window` is **exactly** the number of bytes
/// a source can push into a receiver that never reads.
///
/// This is the equality the rest of the file rests on, and it is stated at
/// the transport alone — no proxy, no MoQT framing, just bytes — because
/// the claim is about QUIC flow control and mixing a shaper into it would
/// make the number a property of two things.
///
/// # Why an equality is assembled out of two one-sided claims
///
/// "The source pushed exactly 65 536 bytes" cannot be measured without a
/// stall detector, and a stall detector reads a clock in the one direction
/// load can push: a starved runtime looks like an exhausted window and
/// under-reports. So the equality is written as its two halves, each safe
/// for its own reason:
///
/// * the window's worth of bytes **completes** — a liveness anchor, which
///   load can only delay;
/// * the byte after it **does not complete** inside [`STALL_WINDOW`] — a
///   negative claim over a window, which load can only make more true.
///
/// Together they say the credit is neither less than nor more than the
/// configured value, which is what an equality says.
///
/// # What a stub cannot do here
///
/// An implementation that ignored `stream_receive_window` would let the
/// 65 537th byte through on the default 1.25 MB allowance and redden the
/// second half. One that clamped harder than asked would fail the first.
/// The control arm rules out the remaining possibility — that the receiver
/// is simply slow, or the fixture simply short — by pushing sixteen times
/// as much through the *same* code with one field changed.
///
/// *Ablation, recorded:* pass `None` for the small arm's window, i.e. drop
/// the `TransportConfig` and keep everything else. The default allowance
/// covers the extra byte, the write returns, and the negative half reddens:
///
/// ```text
/// assertion failed: a receiver that never reads grants exactly its configured window
/// and not one byte more: 65537 bytes went in under a 65536-byte window
/// ```
#[tokio::test]
async fn a_configured_window_is_exactly_the_credit_a_source_gets() {
    let window = SMALL_WINDOW as usize;
    let (addr, receiver) = stalled_receiver(Some(SMALL_WINDOW));
    let (_client_ep, conn) = common::connect_client(addr, ALPN).await;
    let mut send = conn.open_uni().await.expect("open_uni");
    let data = vec![0x5A; window + 1];

    // Lower half. Flow-control credit for the whole window is granted by
    // the transport parameters at handshake, so this completes on every
    // machine; the ceiling is here to name the claim, not to time it.
    tokio::time::timeout(LIVENESS, send.write_all(&data[..window]))
        .await
        .expect("a source may push its whole window into a receiver that never reads")
        .expect("the source's write failed rather than completing");

    // Upper half. `write` and not `write_all`: cancelling `write` is safe —
    // a poll that returns pending has consumed nothing — whereas `write_all`
    // documents that a prefix may have been written when it is dropped, and
    // a cancelled prefix would leave the byte count this claim rests on
    // unknowable.
    assert!(
        tokio::time::timeout(STALL_WINDOW, send.write(&data[window..])).await.is_err(),
        "a receiver that never reads grants exactly its configured window and not one \
         byte more: {} bytes went in under a {window}-byte window",
        window + 1
    );

    conn.close(0u32.into(), b"done");
    receiver.abort();

    // The control, one field changed: quinn's default window absorbs
    // sixteen times as much before the source feels anything at all.
    let (wide_addr, wide_receiver) = stalled_receiver(None);
    let (_wide_ep, wide_conn) = common::connect_client(wide_addr, ALPN).await;
    let mut wide_send = wide_conn.open_uni().await.expect("open_uni");
    let wide_data = vec![0x5A; WIDE_PUSH];
    tokio::time::timeout(LIVENESS, wide_send.write_all(&wide_data))
        .await
        .expect(
            "quinn's default per-stream window absorbs a megabyte from a receiver that \
             never reads — without this, the row above proves only that the receiver was \
             slow",
        )
        .expect("the source's write failed rather than completing");

    wide_conn.close(0u32.into(), b"done");
    wide_receiver.abort();
}

// ── the demonstration: the shaper's stall reaches the publisher ────────

/// A shaped session whose egress queue is shut makes the **publisher**
/// stall — but only if the leg that receives from it was bound with a small
/// per-stream receive window.
///
/// Both arms run the same proxy, the same dry-bucket profile, the same
/// two-object queue and the same fixture stream. The only difference is the
/// `stream_receive_window` on `ListenerConfig::transport_config`, and the
/// two counter assertions in each arm are what make that comparison mean
/// something: the shaper behaves *identically* in both — it blocks, and it
/// sees at most `QUEUE_DEPTH` objects — while the source's experience
/// differs by more than an order of magnitude. So what the window changes is
/// not whether the proxy stalls but whether anyone upstream can tell.
///
/// # The narrow arm is a bracket, not a bound
///
/// A single upper bound would be satisfied by a fixture that never got
/// started — a source that pushed nothing has certainly pushed less than
/// 128 KiB. So the arm asserts both sides:
///
/// * [`SMALL_WINDOW`] bytes **go in**, because the initial credit is
///   granted unconditionally at handshake; and
/// * `SMALL_WINDOW + DRAIN_CEILING` bytes **do not**, because the only
///   credit beyond the initial window is what the proxy consumed before its
///   read branch shut, and that is capped by the queue depth.
///
/// Neither side is load-sensitive: the first is a liveness anchor and the
/// second is a negative claim over a window. See [`DRAIN_CEILING`] for the
/// measurement — 82 370 bytes, against a ceiling of 131 072.
///
/// # Ablations, all three recorded
///
/// **(a) Drop the window.** Pass `None` for the narrow arm too, changing
/// nothing else — the shipped default posture, and the run the header's
/// figures came from. The source pushes straight past the ceiling and the
/// negative half reddens, which is the headline claim doing its job:
///
/// ```text
/// with a 65536-byte listener window the shaper's stall must reach the source:
/// 131072 bytes went in before it felt anything
/// ```
///
/// The remaining two remove the *shaper* rather than the window. Neither
/// reaches the headline assertion, and that is the point of the guards
/// standing above it: without them, "the source stalled" would be a
/// sentence about a fixture with nobody draining its relay leg, and it
/// would read exactly the same.
///
/// **(b) Drop the shaping profile.** Leave `config.shape` at `None`, keep
/// the small window. There is then no shaper to stop any read, so whatever
/// the source eventually feels comes from somewhere this file is not
/// testing. The class row is empty and says so:
///
/// ```text
/// a shaped session reports one row per configured class; an empty list means the
/// profile never reached the session, and every claim below it is about a byte pump
/// ```
///
/// **(c) Swap `Overflow::Block` for `Overflow::DropTail`.** The queue then
/// discards rather than stalling, so the read branch never shuts and
/// `blocked_episodes` stays zero by design. The control arm's liveness
/// anchor is what reports it, at its ceiling:
///
/// ```text
/// timed out waiting for the wide arm's read branch to shut
/// ```
#[tokio::test]
async fn a_small_listener_window_makes_the_shapers_stall_reach_the_source() {
    common::init_crypto();
    let stream = fixture_stream();

    // ── control: quinn's defaults on the front end ──
    let wide_relay = Arc::new(FakeRelay::bind(ALPN));
    let wide = spawn_windowed_proxy(None, wide_relay.addr);
    let (_wide_ep, wide_client) = common::connect_client(wide.addr, ALPN).await;
    let _wide_relay_conn = tokio::time::timeout(LIVENESS, wide_relay.connection())
        .await
        .expect("the proxy connected upstream");
    let mut wide_send = wide_client.open_uni().await.expect("open_uni");

    tokio::time::timeout(LIVENESS, wide_send.write_all(&stream[..WIDE_PUSH]))
        .await
        .expect(
            "on quinn's default window a megabyte goes into a two-object queue before the \
             source feels anything — if this ever stops being true the comparison below \
             has nothing to compare against",
        )
        .expect("the source's write failed rather than completing");

    wait_until(|| wide.class().blocked_episodes > 0, "the wide arm's read branch to shut").await;
    assert!(
        wide.shape_stats().objects_seen <= QUEUE_DEPTH as u64,
        "the shaper stopped reading after its queue filled, exactly as in the narrow arm: \
         it saw {} objects against a depth of {QUEUE_DEPTH}",
        wide.shape_stats().objects_seen
    );

    wide_client.close(0u32.into(), b"done");
    wide.shutdown().await;

    // ── the same session, one field changed ──
    let relay = Arc::new(FakeRelay::bind(ALPN));
    let proxy = spawn_windowed_proxy(Some(SMALL_WINDOW), relay.addr);
    let (_client_ep, client) = common::connect_client(proxy.addr, ALPN).await;
    let _relay_conn = tokio::time::timeout(LIVENESS, relay.connection())
        .await
        .expect("the proxy connected upstream");
    let mut send = client.open_uni().await.expect("open_uni");

    let window = SMALL_WINDOW as usize;
    tokio::time::timeout(LIVENESS, send.write_all(&stream[..window]))
        .await
        .expect("the source may always push its initial window, whatever the shaper does")
        .expect("the source's write failed rather than completing");

    // The shaper really is blocked before the negative claim is made, so
    // "the source stalled" is about the block and not about a race with the
    // stream still being set up.
    wait_until(|| proxy.class().blocked_episodes > 0, "the read branch to shut").await;

    let ceiling = window + DRAIN_CEILING;
    assert!(
        tokio::time::timeout(STALL_WINDOW, send.write_all(&stream[window..ceiling])).await.is_err(),
        "with a {window}-byte listener window the shaper's stall must reach the source: \
         {ceiling} bytes went in before it felt anything"
    );

    let class = proxy.class();
    assert!(
        class.blocked_episodes > 0,
        "the fixture must actually be blocked, or the source's stall is a claim about \
         the transport and not about the shaper: {class:?}"
    );
    assert_eq!(
        class.objects_dropped, 0,
        "Block is non-destructive: it stops reading, it never discards — a stalled \
         source that also lost objects would be a different mechanism: {class:?}"
    );
    assert!(
        proxy.shape_stats().objects_seen <= QUEUE_DEPTH as u64,
        "the shaper saw at most the {QUEUE_DEPTH} objects its queue has room for, which \
         is the same figure the control arm reports: only the source's view differed, \
         and it saw {}",
        proxy.shape_stats().objects_seen
    );

    client.close(0u32.into(), b"done");
    proxy.shutdown().await;
}

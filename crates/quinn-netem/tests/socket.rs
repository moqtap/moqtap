//! The socket suite: forwarding, and whether a decision reaches the wire.
//!
//! # Why half of this file counts the inner socket's calls
//!
//! Everything else in this crate tests what the engine decides. Nothing there —
//! not the conservation identity, not the decision log, not the fixture
//! comparison — can tell a decorator that applies its decisions from one that
//! computes them, counts them, logs them and then forwards the datagram
//! unchanged. That second decorator is committed under `fixtures/silentshim/`.
//!
//! So the eight gate bodies listed in `WIRE_GATES` never read `dropped_*` as
//! proof. `dropped_loss` counts a decision; `CountingInner::sends` counts a
//! datagram that crossed the adapter. Every one of those gates is an integer
//! equality, a byte-string equality, an ordering or a popcount measured on the
//! far side of the decorator, and
//! `the_wire_gates_are_red_against_a_send_anyway_shim` runs each against the
//! fixture and requires it to panic.
//!
//! # What is deliberately not asserted
//!
//! No duration. The release path's timing is a property of the machine, so a
//! gate asserting a release latency would be asserting something about a CI
//! runner. Where a test has to wait for the release thread it waits on a count
//! with a generous one-sided timeout, and asserts the count.

#![cfg(feature = "quinn-socket")]

use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};

use quinn_netem::model::{
    CorruptModel, DelayModel, DupModel, LossModel, Prob, RateModel, ReorderModel, Window,
};
use quinn_netem::profile::{DirectionProfile, ImpairProfile};
use quinn_netem::socket::ImpairedUdpSocket;
use quinn_netem::{wire_bytes, ImpairHandle};

#[path = "fixtures/silentshim/mod.rs"]
mod silentshim;

// ── the fake inner socket ────────────────────────────────────────────────

/// An `AsyncUdpSocket` that records every send and serves scripted receives.
///
/// This is the far side of the adapter, and it is the only thing in this file
/// that can prove an impairment happened. It records the payload of every
/// datagram it is handed, in order, together with the destination and the
/// segment size the transmit claimed.
#[derive(Debug)]
struct CountingInner {
    /// Every datagram handed to this socket, in the order it arrived.
    sent: Mutex<Vec<Sent>>,
    /// Datagrams still to be served from `poll_recv`.
    incoming: Mutex<Vec<Incoming>>,
    /// How many datagrams `poll_recv` has served.
    served: AtomicUsize,
    /// What `max_transmit_segments` reports.
    transmit_segments: usize,
    /// What `max_receive_segments` reports.
    receive_segments: usize,
    /// What `may_fragment` reports.
    fragment: bool,
}

/// One datagram that crossed the adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Sent {
    /// The bytes as the inner socket saw them.
    payload: Vec<u8>,
    /// Where they were going.
    destination: SocketAddr,
    /// What the transmit claimed about segmentation.
    segment_size: Option<usize>,
}

/// One datagram the fake will serve from `poll_recv`.
#[derive(Debug, Clone)]
struct Incoming {
    /// The buffer contents, which may hold several datagrams packed together.
    payload: Vec<u8>,
    /// The peer it came from.
    addr: SocketAddr,
    /// The size of one datagram inside `payload`.
    stride: usize,
}

impl Default for CountingInner {
    fn default() -> Self {
        // Values no trait default could produce by accident: the trait's
        // defaults are 1 / 1 / true, so a decorator that inherits them is
        // distinguishable from one that forwards these.
        CountingInner {
            sent: Mutex::new(Vec::new()),
            incoming: Mutex::new(Vec::new()),
            served: AtomicUsize::new(0),
            transmit_segments: 8,
            receive_segments: 6,
            fragment: false,
        }
    }
}

impl CountingInner {
    /// How many datagrams crossed the adapter.
    fn sends(&self) -> usize {
        lock(&self.sent).len()
    }

    /// How many payload bytes crossed the adapter.
    fn total_bytes(&self) -> usize {
        lock(&self.sent).iter().map(|s| s.payload.len()).sum()
    }

    /// Every datagram that crossed the adapter, in order.
    fn sent(&self) -> Vec<Sent> {
        lock(&self.sent).clone()
    }

    /// The payloads that crossed the adapter, in order.
    fn payloads(&self) -> Vec<Vec<u8>> {
        lock(&self.sent).iter().map(|s| s.payload.clone()).collect()
    }

    /// Script one buffer for `poll_recv` to serve.
    fn push_incoming(&self, payload: Vec<u8>, addr: SocketAddr, stride: usize) {
        lock(&self.incoming).push(Incoming { payload, addr, stride });
    }

    /// How many buffers `poll_recv` has served.
    fn served(&self) -> usize {
        self.served.load(Relaxed)
    }
}

impl AsyncUdpSocket for CountingInner {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(AlwaysWritable)
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        lock(&self.sent).push(Sent {
            payload: transmit.contents.to_vec(),
            destination: transmit.destination,
            segment_size: transmit.segment_size,
        });
        Ok(())
    }

    fn poll_recv(
        &self,
        _cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut queue = lock(&self.incoming);
        if queue.is_empty() || bufs.is_empty() || meta.is_empty() {
            return Poll::Pending;
        }
        let next = queue.remove(0);
        drop(queue);
        bufs[0][..next.payload.len()].copy_from_slice(&next.payload);
        meta[0] = RecvMeta {
            addr: next.addr,
            len: next.payload.len(),
            stride: next.stride,
            ecn: None,
            dst_ip: None,
        };
        self.served.fetch_add(1, Relaxed);
        Poll::Ready(Ok(1))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(peer())
    }

    fn max_transmit_segments(&self) -> usize {
        self.transmit_segments
    }

    fn max_receive_segments(&self) -> usize {
        self.receive_segments
    }

    fn may_fragment(&self) -> bool {
        self.fragment
    }
}

/// A poller that is always writable.
#[derive(Debug)]
struct AlwaysWritable;

impl UdpPoller for AlwaysWritable {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Lock, ignoring poison: a panicking assertion must not turn every later
/// helper call into a second, less informative panic.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

// ── driving the decorator ────────────────────────────────────────────────

/// How a decorator is built over an inner socket.
///
/// A function pointer rather than a hardcoded constructor, so that one gate
/// body runs against the real decorator and against the send-anyway fixture.
type Wrap = fn(Arc<dyn AsyncUdpSocket>) -> (Arc<dyn AsyncUdpSocket>, ImpairHandle);

/// The decorator under test.
fn real(inner: Arc<dyn AsyncUdpSocket>) -> (Arc<dyn AsyncUdpSocket>, ImpairHandle) {
    let (socket, handle) = ImpairedUdpSocket::wrap(inner);
    (socket, handle)
}

/// The peer every datagram in this file goes to.
///
/// IPv4, so the on-wire size is the payload plus 28 and every expected number
/// below can be written out by hand.
fn peer() -> SocketAddr {
    "127.0.0.1:4433".parse().expect("a literal address")
}

/// Send one payload through the decorator.
fn send(socket: &Arc<dyn AsyncUdpSocket>, payload: &[u8]) -> io::Result<()> {
    socket.try_send(&Transmit {
        destination: peer(),
        ecn: None,
        contents: payload,
        segment_size: None,
        src_ip: None,
    })
}

/// A payload of `len` bytes whose every byte identifies `seq`.
///
/// Distinct per sequence number, so a survivor set can be compared as byte
/// strings rather than as a count — a count is satisfied by dropping the wrong
/// half.
fn payload(seq: u64, len: usize) -> Vec<u8> {
    let tag = u8::try_from(seq % 251).expect("modulus keeps this in range");
    (0..len).map(|i| tag.wrapping_add(u8::try_from(i % 97).expect("modulus"))).collect()
}

/// A profile with nothing armed on either direction.
fn bare() -> ImpairProfile {
    ImpairProfile { seed: 424_242, ..ImpairProfile::default() }
}

/// A profile with `downlink` armed and the uplink left alone.
fn down(downlink: DirectionProfile) -> ImpairProfile {
    ImpairProfile { downlink, ..bare() }
}

/// Certainty, as the integer probability the models take.
const ALWAYS: Prob = Prob::from_ppb(1_000_000_000);

/// Wait until `pred` holds, up to `limit`.
///
/// One-sided: the timeout only decides how long the test is willing to wait
/// before making its assertion anyway, so a slow machine makes this slower and
/// never makes it pass. The assertion that follows is what decides the test.
fn settle(limit: Duration, mut pred: impl FnMut() -> bool) {
    let start = Instant::now();
    while start.elapsed() < limit {
        if pred() {
            return;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// Poll the decorator once with a waker that does nothing.
///
/// Nothing here awaits, so a real waker would have nothing to wake; the tests
/// that need the release path poll again in a loop instead.
fn poll_once(
    socket: &Arc<dyn AsyncUdpSocket>,
    bufs: &mut [IoSliceMut<'_>],
    meta: &mut [RecvMeta],
) -> Poll<io::Result<usize>> {
    let mut cx = Context::from_waker(Waker::noop());
    socket.poll_recv(&mut cx, bufs, meta)
}

/// `n` receive buffers of `size` bytes.
fn buffers(n: usize, size: usize) -> Vec<Vec<u8>> {
    (0..n).map(|_| vec![0u8; size]).collect()
}

// ── forwarding gates ─────────────────────────────────────────────────────

/// A disarmed decorator reports the inner socket's three capabilities.
///
/// Asserted as an equality against the inner socket **read at test time**, not
/// against literals. The three numbers a real socket reports differ by platform
/// — the development box reports 512 / 64 / false and a CI runner will not —
/// so literals here would redden on other machines for a reason that has
/// nothing to do with the decorator. The equality is also the stronger claim:
/// it holds everywhere and still catches the trait defaults, because 1 / 1 /
/// true is not what any real socket reports.
///
/// The third of the three is the one that costs something when it is wrong.
/// quinn reads it as `allow_mtud = !socket.may_fragment()`, so a decorator that
/// inherits the default `true` turns path-MTU discovery off for every endpoint
/// built over it, with no compile error, no warning and no counter that moves.
#[test]
fn a_disarmed_socket_forwards_every_capability() {
    let inner = Arc::new(CountingInner::default());
    let (socket, handle) = real(inner.clone());
    assert!(!handle.is_armed());

    assert_eq!(socket.max_transmit_segments(), inner.max_transmit_segments());
    assert_eq!(socket.max_receive_segments(), inner.max_receive_segments());
    assert_eq!(socket.may_fragment(), inner.may_fragment());
}

/// An armed decorator reports one transmit segment, and reverts on disarm.
///
/// Both legs, because one constant satisfies each leg alone: returning the
/// inner value always passes the disarmed leg, returning 1 always passes the
/// armed one. The armed leg is what stops quinn building a segmented transmit
/// at all, so that each datagram arrives at the decorator as its own transmit
/// and can be decided about on its own.
#[test]
fn an_armed_socket_reports_one_transmit_segment() {
    let inner = Arc::new(CountingInner::default());
    let (socket, handle) = real(inner.clone());

    handle.arm(bare()).expect("a valid profile");
    assert_eq!(socket.max_transmit_segments(), 1, "armed");

    handle.disarm();
    assert_eq!(socket.max_transmit_segments(), inner.max_transmit_segments(), "disarmed");
}

/// A segmented transmit is split into its datagrams, each its own transmit.
///
/// 2500 bytes at a segment size of 1200 is 1200 / 1200 / 100 — quinn's own
/// arithmetic — and each piece carries `segment_size: None`, because a datagram
/// this decorator emits is one datagram whatever the transmit it came out of
/// claimed. The count is asserted first, so "split into nothing" is not a pass.
#[test]
fn a_gso_transmit_is_split_into_its_datagrams() {
    let inner = Arc::new(CountingInner::default());
    let (socket, handle) = real(inner.clone());
    handle.arm(bare()).expect("a valid profile");

    let contents = payload(0, 2500);
    socket
        .try_send(&Transmit {
            destination: peer(),
            ecn: None,
            contents: &contents,
            segment_size: Some(1200),
            src_ip: None,
        })
        .expect("the fake inner socket always accepts");

    let sent = inner.sent();
    assert_eq!(sent.len(), 3, "one transmit per datagram");
    assert_eq!(
        sent.iter().map(|s| s.payload.len()).collect::<Vec<_>>(),
        vec![1200, 1200, 100],
        "a possibly-shorter last datagram"
    );
    for (i, s) in sent.iter().enumerate() {
        assert_eq!(s.segment_size, None, "piece {i} must not claim segmentation");
    }
    let rejoined: Vec<u8> = sent.iter().flat_map(|s| s.payload.clone()).collect();
    assert_eq!(rejoined, contents, "the split must lose no byte and reorder none");
}

/// Every `RecvMeta` the decorator emits describes one datagram.
///
/// A buffer of 2500 bytes at a stride of 1200 holds three datagrams. Each one
/// comes back with `stride == len`, and `stride` is never zero while `len` is
/// non-zero: quinn's endpoint driver advances its read cursor by `stride`, so a
/// zero there is not a malformed packet, it is an infinite loop in the driver.
///
/// The count is asserted **first**, and that is not a formality. A
/// universally-quantified claim over an empty set is true, so a `poll_recv`
/// that returned `Ready(Ok(0))` — or `Pending` forever — satisfied the stride
/// assertion without emitting anything at all.
#[test]
fn a_gro_meta_is_split_and_never_emits_stride_zero() {
    let inner = Arc::new(CountingInner::default());
    inner.push_incoming(payload(0, 2500), peer(), 1200);
    let (socket, handle) = real(inner.clone());
    handle.arm(bare()).expect("a valid profile");

    // The first buffer has to hold the whole packed batch the inner socket
    // hands over; the rest only ever hold one datagram each.
    let mut store = buffers(4, 4096);
    let mut bufs: Vec<IoSliceMut> = store.iter_mut().map(|b| IoSliceMut::new(b)).collect();
    let mut meta = vec![RecvMeta::default(); 4];

    let n = match poll_once(&socket, &mut bufs, &mut meta) {
        Poll::Ready(Ok(n)) => n,
        other => panic!("expected datagrams, got {other:?}"),
    };
    assert_eq!(n, 3, "the buffer held three datagrams");
    for (i, m) in meta.iter().take(n).enumerate() {
        assert_ne!(m.len, 0, "datagram {i} must not be empty");
        assert_eq!(m.stride, m.len, "datagram {i} must describe exactly itself");
    }
    assert_eq!(
        meta.iter().take(n).map(|m| m.len).collect::<Vec<_>>(),
        vec![1200, 1200, 100],
        "the split lengths"
    );
}

/// A held datagram is delivered from the decorator's own queue while the inner
/// socket has nothing to give.
///
/// The inner socket serves exactly one buffer and is `Pending` from then on. A
/// delay model holds that datagram back, so the poll that finally delivers it
/// gets it from the decorator and from nowhere else. Asserted as **exactly
/// one** delivery with its payload byte-compared, so a decorator that
/// manufactured a datagram or delivered the same one twice fails as loudly as
/// one that delivered nothing.
#[test]
fn a_held_datagram_is_delivered_without_the_inner_socket() {
    let inner = Arc::new(CountingInner::default());
    let sent_up = payload(9, 300);
    inner.push_incoming(sent_up.clone(), peer(), 300);

    let (socket, handle) = real(inner.clone());
    handle
        .arm(ImpairProfile {
            uplink: DirectionProfile {
                delay: Some(DelayModel::Fixed { mean_ns: 60_000_000 }),
                ..DirectionProfile::default()
            },
            ..bare()
        })
        .expect("a valid profile");

    let mut store = buffers(2, 2048);
    let mut bufs: Vec<IoSliceMut> = store.iter_mut().map(|b| IoSliceMut::new(b)).collect();
    let mut meta = vec![RecvMeta::default(); 2];

    // The first poll takes the datagram off the inner socket and holds it.
    assert!(matches!(poll_once(&socket, &mut bufs, &mut meta), Poll::Pending));
    assert_eq!(inner.served(), 1, "the inner socket gave up its only datagram");

    let mut delivered = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline && delivered.is_empty() {
        if let Poll::Ready(Ok(n)) = poll_once(&socket, &mut bufs, &mut meta) {
            for i in 0..n {
                delivered.push(bufs[i][..meta[i].len].to_vec());
            }
        }
        std::thread::sleep(Duration::from_millis(2));
    }

    assert_eq!(delivered.len(), 1, "delivered {} datagrams", delivered.len());
    assert_eq!(delivered[0], sent_up, "byte for byte, from the decorator's queue");
    assert_eq!(inner.served(), 1, "and the inner socket produced nothing more");
}

/// The release path reports its own batching.
///
/// Four load-independent integer identities, no duration among them. They exist
/// because the release path releases in clumps — the sleep primitive has a
/// floor of roughly half a millisecond on the development platform, so pacing
/// finer than that arrives as several datagrams at once — and a test that
/// cannot see the clumping will assume smooth pacing that is not happening.
///
/// The identities are what makes those four counters unfakeable by silence: an
/// implementation that leaves all four at zero fails three of the four here, on
/// every run, rather than only under an `#[ignore]`d calibration nobody runs.
#[test]
fn the_release_path_reports_its_own_batching() {
    const N: u64 = 24;

    let inner = Arc::new(CountingInner::default());
    let (socket, handle) = real(inner.clone());
    handle
        .arm(down(DirectionProfile {
            delay: Some(DelayModel::Fixed { mean_ns: 30_000_000 }),
            ..DirectionProfile::default()
        }))
        .expect("a valid profile");

    for seq in 0..N {
        send(&socket, &payload(seq, 200)).expect("held, so accepted");
    }
    assert_eq!(inner.sends(), 0, "a delay model holds every one of them");

    settle(Duration::from_secs(5), || inner.sends() == N as usize);
    let s = handle.stats();

    assert_eq!(inner.sends(), N as usize, "every held datagram was released");
    assert_eq!(s.released_from_queue, N, "and every release was counted");
    assert!(s.release_batches >= 1, "at least one wake-up released something");
    assert!(s.release_batch_max >= 1, "and its batch was not empty");
    assert!(
        s.release_batches * u64::from(s.release_batch_max) >= s.released_from_queue,
        "no wake-up can release more than the largest batch: {} batches of at most {} \
         cannot cover {}",
        s.release_batches,
        s.release_batch_max,
        s.released_from_queue
    );
}

/// Dropping an armed socket that is holding datagrams returns promptly.
///
/// The bound is 250 ms against a release slice of 500 µs — a 500× margin, which
/// is what makes it a one-sided gate rather than a timing measurement. What it
/// forbids is a teardown that waits for the queue: the datagrams here are
/// parked five seconds out, so a `Drop` that drained before stopping would take
/// twenty times the bound.
#[test]
fn dropping_an_armed_socket_with_parked_datagrams_returns_promptly() {
    let inner = Arc::new(CountingInner::default());
    let (socket, handle) = real(inner.clone());
    handle
        .arm(down(DirectionProfile {
            delay: Some(DelayModel::Fixed { mean_ns: 5_000_000_000 }),
            ..DirectionProfile::default()
        }))
        .expect("a valid profile");

    for seq in 0..8 {
        send(&socket, &payload(seq, 200)).expect("held, so accepted");
    }
    assert_eq!(inner.sends(), 0, "all eight are parked");

    // Give the release thread time to park on the five-second deadline, so what
    // is measured below is a teardown against a sleeping thread. Without this
    // the thread is often still starting up and observes the stop flag on its
    // very first look, which makes the drop fast for a reason that has nothing
    // to do with the teardown being correct — and a gate that passes because of
    // a race is a gate that would keep passing after the teardown broke.
    std::thread::sleep(Duration::from_millis(50));

    let start = Instant::now();
    drop(socket);
    let took = start.elapsed();
    assert!(took < Duration::from_millis(250), "drop took {took:?}, bound is 250ms");
}

/// A transmit that arrives when the queue is full is refused **before** it is
/// decided about, and the refusal is recoverable.
///
/// This is the one thing `try_send` returns `WouldBlock` for, and the ordering
/// is the entire point. quinn's answer to `WouldBlock` is to retry the **whole**
/// transmit once `poll_writable` resolves. So a decorator that decided first and
/// refused afterwards would decide about that datagram twice: two sequence
/// numbers consumed by one datagram, two increments of `datagrams_seen`, two
/// chances at the loss model, and a conservation identity short by one with
/// nothing to say which datagram it lost. Refusing first costs nothing and makes
/// the retry free.
///
/// The three claims are: the queue fills and the next transmit is refused; the
/// refused datagram left no trace in the counters; and once the release thread
/// has drained the queue the same socket accepts again — because a decorator
/// that refused forever would be a decorator that stopped the connection.
///
/// The rate model here is fast enough that the engine's own byte queue is empty
/// at every decision, so the bound that binds is the decorator's own.
#[test]
fn a_full_queue_is_refused_before_the_datagram_is_counted() {
    let inner = Arc::new(CountingInner::default());
    let (socket, handle) = real(inner.clone());
    handle
        .arm(down(DirectionProfile {
            rate: Some(RateModel { bps: 8_000_000_000, burst_bytes: 100_000, queue_bytes: 3_000 }),
            delay: Some(DelayModel::Fixed { mean_ns: 300_000_000 }),
            ..DirectionProfile::default()
        }))
        .expect("a valid profile");

    // 1228 on-wire bytes each, against a 3000-byte bound.
    for seq in 0..3 {
        send(&socket, &payload(seq, 1200)).expect("under the bound");
    }
    assert_eq!(inner.sends(), 0, "all three are parked");
    assert_eq!(handle.stats().datagrams_seen, 3);

    let refused = send(&socket, &payload(3, 1200)).expect_err("over the bound");
    assert_eq!(refused.kind(), io::ErrorKind::WouldBlock, "the retryable refusal");
    assert_eq!(
        handle.stats().datagrams_seen,
        3,
        "the refused datagram must not have been decided about"
    );

    // And the write poller says so, which is what makes the refusal recoverable
    // instead of a spin: quinn parks on it rather than retrying immediately.
    let mut cx = Context::from_waker(Waker::noop());
    let mut poller = Arc::clone(&socket).create_io_poller();
    assert!(poller.as_mut().poll_writable(&mut cx).is_pending(), "full means not writable");

    settle(Duration::from_secs(5), || inner.sends() == 3);
    assert_eq!(inner.sends(), 3, "the release path drained the queue");
    assert!(poller.as_mut().poll_writable(&mut cx).is_ready(), "and writable again");
    send(&socket, &payload(4, 1200)).expect("accepted once there is room");
    assert_eq!(handle.stats().datagrams_seen, 4, "and that one was decided about");
}

/// `bind` binds the socket first and reports the missing runtime second.
///
/// There is no tokio runtime in this test binary, and there cannot be: the
/// engine half of this crate compiles with no dependencies at all, so the suite
/// pulls in no async runtime to drive one. What is checkable here is the order
/// of the two failures, and the order is what says the constructor is real.
///
/// A bindable address gets as far as quinn's runtime lookup and reports that.
/// An address that is on no interface fails at the operating system first and
/// reports something else entirely — which a constructor that only ever returned
/// the runtime error could not do. `192.0.2.0/24` is the documentation-only
/// range reserved by RFC 5737; no host has it configured, which is what makes
/// the second leg deterministic rather than a guess about the machine.
#[test]
fn bind_reports_the_operating_system_before_the_missing_runtime() {
    let bindable: SocketAddr = "127.0.0.1:0".parse().expect("a literal address");
    let unbindable: SocketAddr = "192.0.2.1:0".parse().expect("a literal address");

    let no_runtime =
        ImpairedUdpSocket::bind(bindable).expect_err("no async runtime in this test binary");
    assert_eq!(no_runtime.to_string(), "no async runtime found");

    let os = ImpairedUdpSocket::bind(unbindable).expect_err("no host owns a TEST-NET-1 address");
    assert_ne!(
        os.to_string(),
        "no async runtime found",
        "binding must be attempted before the runtime is looked up, and it must be the \
         operating system that answers: {os}"
    );
}

// ── the wire gates ───────────────────────────────────────────────────────

/// The conservation identity, measured **across the adapter**.
///
/// ```text
/// inner_sends + dropped_loss + dropped_blackout + dropped_mtu + dropped_queue_full
///     == datagrams_seen
/// ```
///
/// This is the only assertion in the crate that spans the seam, and that is the
/// whole of its value. Each side alone is satisfiable by a lie: the counters by
/// an engine that decides and discards, the inner count by a decorator that
/// forwards everything. Their sum is not — forward everything and the left side
/// exceeds the right by exactly the number of drops that were reported and not
/// performed.
///
/// Every bucket is also asserted non-zero. All-zero counters satisfy the
/// identity trivially, so a decorator that impaired nothing would pass a
/// conservation check on its own.
///
/// The four causes are driven in four phases with four profiles, because a
/// blackout is terminal and would otherwise be the only cause that ever fired.
/// Arming again resets the sequence numbers and deliberately does not reset the
/// counters, which is what lets the identity be asserted once over the whole
/// run.
fn gate_conservation_across_the_adapter(wrap: Wrap) {
    let inner = Arc::new(CountingInner::default());
    let (socket, handle) = wrap(inner.clone());

    // Phase 1 — a blackout window wide enough that five sends cannot leave it.
    handle
        .arm(down(DirectionProfile {
            blackouts: vec![Window { at_ns: 0, for_ns: 60_000_000 }],
            ..DirectionProfile::default()
        }))
        .expect("a valid profile");
    for seq in 0..5 {
        send(&socket, &payload(seq, 200)).expect("dropped, so accepted");
    }

    // Phase 2 — every datagram larger than the black hole.
    handle
        .arm(down(DirectionProfile { mtu_blackhole: Some(1000), ..DirectionProfile::default() }))
        .expect("a valid profile");
    for seq in 0..5 {
        send(&socket, &payload(seq, 1200)).expect("dropped, so accepted");
    }

    // Phase 3 — every second datagram lost, by sequence number.
    handle
        .arm(down(DirectionProfile {
            loss: Some(LossModel::EveryNth { n: 2 }),
            ..DirectionProfile::default()
        }))
        .expect("a valid profile");
    for seq in 0..6 {
        send(&socket, &payload(seq, 200)).expect("accepted either way");
    }

    // Phase 4 — a byte queue two datagrams deep that drains at 1 kB/s, so the
    // first datagram is admitted and the next four are tail-dropped.
    handle
        .arm(down(DirectionProfile {
            rate: Some(RateModel { bps: 8_000, burst_bytes: 2_000, queue_bytes: 2_000 }),
            ..DirectionProfile::default()
        }))
        .expect("a valid profile");
    for seq in 0..5 {
        send(&socket, &payload(seq, 1200)).expect("accepted either way");
    }

    settle(Duration::from_secs(2), || inner.sends() >= 4);
    let s = handle.stats();

    assert_eq!(s.datagrams_seen, 21, "the drive itself");
    assert_eq!(s.dropped_blackout, 5, "phase 1");
    assert_eq!(s.dropped_mtu, 5, "phase 2");
    assert_eq!(s.dropped_loss, 3, "phase 3");
    assert_eq!(s.dropped_queue_full, 4, "phase 4");
    assert_eq!(s.datagrams_duplicated, 0, "no duplication in this profile");

    let drops = s.dropped_loss + s.dropped_blackout + s.dropped_mtu + s.dropped_queue_full;
    assert_eq!(
        inner.sends() as u64 + drops,
        s.datagrams_seen,
        "{} datagrams crossed the adapter and {drops} were reported dropped, out of {} seen",
        inner.sends(),
        s.datagrams_seen
    );
}

/// The dup-armed form of the identity: a duplicate adds to the far side without
/// adding to `datagrams_seen`.
fn gate_duplication_adds_one_crossing_each(wrap: Wrap) {
    const N: u64 = 12;

    let inner = Arc::new(CountingInner::default());
    let (socket, handle) = wrap(inner.clone());
    handle
        .arm(down(DirectionProfile {
            dup: Some(DupModel { p: ALWAYS }),
            ..DirectionProfile::default()
        }))
        .expect("a valid profile");
    for seq in 0..N {
        send(&socket, &payload(seq, 200)).expect("accepted");
    }

    let s = handle.stats();
    assert_eq!(s.datagrams_seen, N);
    assert_eq!(s.datagrams_duplicated, N, "certainty means every one of them");
    let drops = s.dropped_loss + s.dropped_blackout + s.dropped_mtu + s.dropped_queue_full;
    assert_eq!(drops, 0, "nothing in this profile drops");
    assert_eq!(
        inner.sends() as u64,
        s.datagrams_seen - drops + s.datagrams_duplicated,
        "each datagram crossed the adapter twice"
    );
}

/// A dropped decision never reaches the inner socket.
///
/// Two claims. Total loss over sixteen transmits must put **zero bytes** on the
/// inner socket — zero, not fewer, because "fewer" is satisfied by dropping one
/// datagram in sixteen and reporting sixteen. Then a deterministic loss model
/// must leave exactly the complement of the dropped sequence numbers, compared
/// as a set of byte strings: a count alone is satisfied by a decorator that
/// dropped the right number of the wrong datagrams.
fn gate_a_drop_reaches_nothing(wrap: Wrap) {
    const N: u64 = 16;

    // (i) Total loss.
    let inner = Arc::new(CountingInner::default());
    let (socket, handle) = wrap(inner.clone());
    handle
        .arm(down(DirectionProfile {
            loss: Some(LossModel::Bernoulli { p: ALWAYS }),
            ..DirectionProfile::default()
        }))
        .expect("a valid profile");
    for seq in 0..N {
        send(&socket, &payload(seq, 400)).expect("dropped, so accepted");
    }
    assert_eq!(inner.sends(), 0, "total loss must put nothing on the wire");
    assert_eq!(inner.total_bytes(), 0, "and no bytes either");
    assert_eq!(handle.stats().dropped_loss, N, "while reporting every one of them");
    drop(socket);

    // (ii) Every second datagram, by sequence number.
    let inner = Arc::new(CountingInner::default());
    let (socket, handle) = wrap(inner.clone());
    handle
        .arm(down(DirectionProfile {
            loss: Some(LossModel::EveryNth { n: 2 }),
            ..DirectionProfile::default()
        }))
        .expect("a valid profile");
    for seq in 0..N {
        send(&socket, &payload(seq, 400)).expect("accepted either way");
    }

    let survivors = inner.payloads();
    let expected: Vec<Vec<u8>> =
        (0..N).filter(|seq| seq % 2 == 0).map(|s| payload(s, 400)).collect();
    assert_eq!(survivors.len(), (N / 2) as usize, "half of them");
    assert_eq!(survivors, expected, "and specifically the even-numbered half");
}

/// A corrupt decision flips exactly the bit the record names.
///
/// The popcount is the point. An unapplied bit-flip changes nothing anyone can
/// see — no count moves, no byte count moves, no other test in this crate can
/// tell — which makes corruption the single most silently-skippable model here
/// and is why its gate is the tightest one in the file. For each datagram the
/// payload that crossed the adapter is XORed against the payload that went in:
/// exactly one bit must differ, and it must be the bit the decision log names.
fn gate_corruption_flips_the_recorded_bit(wrap: Wrap) {
    const N: u64 = 8;
    const LEN: usize = 300;

    let inner = Arc::new(CountingInner::default());
    let (socket, handle) = wrap(inner.clone());
    handle.record_decisions(true);
    handle
        .arm(down(DirectionProfile {
            corrupt: Some(CorruptModel { p: ALWAYS }),
            ..DirectionProfile::default()
        }))
        .expect("a valid profile");

    for seq in 0..N {
        send(&socket, &payload(seq, LEN)).expect("accepted");
    }

    let log = handle.take_log();
    let records = log.records();
    assert_eq!(records.len(), N as usize, "one record per datagram");
    assert_eq!(inner.sends(), N as usize, "corruption does not drop");

    let crossed = inner.payloads();
    let mut sites = 0;
    for (i, record) in records.iter().enumerate() {
        assert_ne!(record.corrupt_offset, u32::MAX, "record {i} names no corruption site");
        sites += 1;

        let input = payload(record.seq, LEN);
        let output = &crossed[i];
        assert_eq!(output.len(), input.len(), "datagram {i} changed length");

        let differing: Vec<(usize, u32)> = input
            .iter()
            .zip(output.iter())
            .enumerate()
            .map(|(at, (a, b))| (at, u32::from(a ^ b)))
            .filter(|(_, x)| *x != 0)
            .collect();
        let popcount: u32 = differing.iter().map(|(_, x)| x.count_ones()).sum();
        assert_eq!(
            popcount, 1,
            "datagram {i}: expected exactly one differing bit, found {popcount}"
        );

        let (at, mask) = differing[0];
        let bit = mask.trailing_zeros() as u8;
        assert_eq!(
            (at as u32, bit),
            (record.corrupt_offset, record.corrupt_bit),
            "datagram {i}: the flipped bit must be the one the record names"
        );
    }
    assert_eq!(sites, N as usize, "every datagram carried a corruption site");
}

/// A duplicated decision emits exactly two identical datagrams.
///
/// Exactly two, not at least two: a decorator that emitted three would be
/// duplicating something the profile did not ask it to.
///
/// Corruption is armed alongside the duplication, and that is what gives the
/// byte-equality something to catch. A duplicate is a copy of the packet, not a
/// second packet — so the copy has to carry the *same* bit-flip, which means the
/// outgoing bytes are built once and sent twice. A decorator that instead
/// decided a second time for the copy would draw from the corruption generator
/// again, land on a different site, and put two subtly different datagrams on
/// the wire while every count stayed correct. With no corruption armed the two
/// implementations are indistinguishable and this assertion would be decoration.
fn gate_duplication_emits_two_identical(wrap: Wrap) {
    let inner = Arc::new(CountingInner::default());
    let (socket, handle) = wrap(inner.clone());
    handle
        .arm(down(DirectionProfile {
            dup: Some(DupModel { p: ALWAYS }),
            corrupt: Some(CorruptModel { p: ALWAYS }),
            ..DirectionProfile::default()
        }))
        .expect("a valid profile");

    let one = payload(0, 512);
    send(&socket, &one).expect("accepted");

    settle(Duration::from_secs(2), || inner.sends() >= 2);
    let sent = inner.sent();
    assert_eq!(sent.len(), 2, "one datagram in, two out");
    assert_eq!(sent[0].destination, sent[1].destination, "to the same peer");
    assert_eq!(sent[0].payload, sent[1].payload, "the copy is byte-identical to the original");

    let differing: u32 =
        one.iter().zip(sent[0].payload.iter()).map(|(a, b)| u32::from(a ^ b).count_ones()).sum();
    assert_eq!(differing, 1, "and both carry the one bit-flip the decision named");
}

/// The order datagrams cross the adapter is the order the records predict.
///
/// With a delay model armed and reordering at every second datagram, a
/// reordered datagram is released at the tick it arrived and jumps ahead of
/// everything already parked. The claim is an ordering and nothing else: the
/// sequence numbers the inner socket saw, in order, equal the sequence numbers
/// of the records sorted by `(release_ns, seq)`. No duration appears in it,
/// which is what makes it load-independent.
fn gate_send_order_matches_the_records(wrap: Wrap) {
    const N: u64 = 12;
    const LEN: usize = 256;

    let inner = Arc::new(CountingInner::default());
    let (socket, handle) = wrap(inner.clone());
    handle.record_decisions(true);
    handle
        .arm(down(DirectionProfile {
            delay: Some(DelayModel::Fixed { mean_ns: 400_000_000 }),
            reorder: Some(ReorderModel { gap: 2, p: ALWAYS }),
            ..DirectionProfile::default()
        }))
        .expect("a valid profile");

    for seq in 0..N {
        send(&socket, &payload(seq, LEN)).expect("held or forwarded, both accepted");
    }
    settle(Duration::from_secs(5), || inner.sends() == N as usize);

    let log = handle.take_log();
    let mut predicted: Vec<(u64, u64)> =
        log.records().iter().map(|r| (r.release_ns, r.seq)).collect();
    predicted.sort_unstable();
    let predicted: Vec<u64> = predicted.into_iter().map(|(_, seq)| seq).collect();

    // Every payload identifies its sequence number, so the order at the far
    // side of the adapter can be read back as sequence numbers.
    let by_payload: Vec<u64> = inner
        .payloads()
        .iter()
        .map(|p| {
            (0..N).find(|seq| payload(*seq, LEN) == *p).expect("every payload identifies its seq")
        })
        .collect();

    assert_eq!(by_payload.len(), N as usize, "every datagram must have crossed");
    assert_eq!(by_payload, predicted, "the wire order must be the order the records predict");
}

/// A blackout puts nothing on the wire, and the first datagram after it does.
///
/// The second claim is the non-vacuity precondition, and it is not a formality:
/// "zero sends inside the window" is satisfied perfectly by a decorator that
/// never sends anything at all. The window is a hundred and fifty milliseconds
/// wide against five sends that take microseconds, and the datagram after it is
/// driven a quarter of a second past the arm — both margins are one-sided, so a
/// slow machine cannot turn a pass into a failure or the other way round.
fn gate_blackout_sends_nothing(wrap: Wrap) {
    let inner = Arc::new(CountingInner::default());
    let (socket, handle) = wrap(inner.clone());
    handle
        .arm(down(DirectionProfile {
            blackouts: vec![Window { at_ns: 0, for_ns: 150_000_000 }],
            ..DirectionProfile::default()
        }))
        .expect("a valid profile");

    for seq in 0..5 {
        send(&socket, &payload(seq, 200)).expect("dropped, so accepted");
    }
    assert_eq!(inner.sends(), 0, "nothing leaves inside the window");
    assert_eq!(handle.stats().dropped_blackout, 5, "and all five were reported");

    std::thread::sleep(Duration::from_millis(250));
    send(&socket, &payload(99, 200)).expect("accepted");
    settle(Duration::from_secs(2), || inner.sends() >= 1);
    assert_eq!(inner.sends(), 1, "and the first datagram after it does leave");
    assert_eq!(inner.payloads()[0], payload(99, 200), "that one, byte for byte");
}

/// An over-sized datagram produces zero inner sends, and one of exactly the
/// threshold produces one.
///
/// The comparison is strictly greater, so a datagram whose on-wire size is
/// exactly the threshold passes. Both halves are asserted at the socket, which
/// is where the size actually decides anything: an on-wire size is the payload
/// plus twenty-eight bytes of IPv4 and UDP header, so a 1200-byte payload to
/// this peer is 1228 on the wire and a 1201-byte one is 1229.
fn gate_over_mtu_sends_nothing(wrap: Wrap) {
    const THRESHOLD: u16 = 1228;
    assert_eq!(wire_bytes(1200, peer()), u32::from(THRESHOLD), "the on-wire arithmetic");

    let inner = Arc::new(CountingInner::default());
    let (socket, handle) = wrap(inner.clone());
    handle
        .arm(down(DirectionProfile {
            mtu_blackhole: Some(THRESHOLD),
            ..DirectionProfile::default()
        }))
        .expect("a valid profile");

    send(&socket, &payload(0, 1201)).expect("dropped, so accepted");
    assert_eq!(inner.sends(), 0, "one byte over the threshold must not leave");

    send(&socket, &payload(1, 1200)).expect("accepted");
    settle(Duration::from_secs(2), || inner.sends() >= 1);
    assert_eq!(inner.sends(), 1, "exactly at the threshold must leave");
    assert_eq!(inner.payloads()[0], payload(1, 1200), "and it is the right one");
    assert_eq!(handle.stats().dropped_mtu, 1, "with one drop reported");
}

/// One wire gate: a name for the failure message, and the body to run.
type Gate = (&'static str, fn(Wrap));

/// Every wire gate, and the decorator each runs against.
///
/// A table rather than seven duplicated calls, because
/// `the_wire_gates_are_red_against_a_send_anyway_shim` walks the same list: a
/// gate added here is automatically also required to fail against the fixture,
/// where one added as a loose `#[test]` would not be.
const WIRE_GATES: &[Gate] = &[
    ("conservation across the adapter", gate_conservation_across_the_adapter),
    ("duplication adds one crossing each", gate_duplication_adds_one_crossing_each),
    ("a drop reaches nothing", gate_a_drop_reaches_nothing),
    ("a corruption flips exactly one bit", gate_corruption_flips_the_recorded_bit),
    ("a duplicate emits two identical datagrams", gate_duplication_emits_two_identical),
    ("the send order matches the records", gate_send_order_matches_the_records),
    ("a blackout sends nothing", gate_blackout_sends_nothing),
    ("over the black hole sends nothing", gate_over_mtu_sends_nothing),
];

#[test]
fn the_adapter_conserves_every_datagram_it_was_given() {
    gate_conservation_across_the_adapter(real);
}

#[test]
fn duplication_adds_exactly_one_crossing_each() {
    gate_duplication_adds_one_crossing_each(real);
}

#[test]
fn a_dropped_decision_never_reaches_the_inner_socket() {
    gate_a_drop_reaches_nothing(real);
}

#[test]
fn a_corrupt_decision_flips_exactly_the_recorded_bit() {
    gate_corruption_flips_the_recorded_bit(real);
}

#[test]
fn a_duplicated_decision_emits_two_identical_datagrams() {
    gate_duplication_emits_two_identical(real);
}

#[test]
fn the_inner_send_order_equals_the_order_the_records_predict() {
    gate_send_order_matches_the_records(real);
}

#[test]
fn a_blackout_puts_nothing_on_the_wire() {
    gate_blackout_sends_nothing(real);
}

#[test]
fn an_over_mtu_datagram_produces_zero_inner_sends() {
    gate_over_mtu_sends_nothing(real);
}

/// **This test is GREEN and the suite underneath it is RED.** Get the polarity
/// right before changing anything here.
///
/// Every wire gate above is run against the committed send-anyway fixture — a
/// decorator that computes every decision, moves every counter, writes every
/// log record and then forwards the datagram anyway — and each one is required
/// to **panic**. If they all pass against it, the gates are decoration: they
/// would be green against precisely the failure they exist to detect, which is
/// the failure that was measured delivering 41 of 52 datagrams reported as
/// dropped.
///
/// So do not "fix" `fixtures/silentshim/`. Making it forward conditionally
/// makes the suite go green against it and reddens **this** test. That
/// inversion is correct and it is the reason the fixture is committed instead
/// of described.
///
/// Neither this test nor the shim it runs is behind a feature. Both were, and
/// no ordinary build compiled either: `--workspace` turns `quinn-socket` on by
/// unification and turned nothing else on, so the eight gates below ran without
/// the one check that says they gate anything.
#[test]
fn the_wire_gates_are_red_against_a_send_anyway_shim() {
    // The gate bodies are expected to panic, and their backtraces are noise
    // here. The hook is restored before anything is asserted.
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let outcomes: Vec<(&str, bool)> = WIRE_GATES
        .iter()
        .map(|(name, body)| {
            let failed =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(silentshim::wrap)))
                    .is_err();
            (*name, failed)
        })
        .collect();
    std::panic::set_hook(previous);

    for (name, failed) in outcomes {
        assert!(failed, "{name} passed against the send-anyway shim, so it gates nothing");
    }
}

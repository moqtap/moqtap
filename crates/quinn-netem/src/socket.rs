//! The `quinn::AsyncUdpSocket` decorator. Feature `quinn-socket`.
//!
//! This is the layer where a decision becomes an effect. Everything below it
//! decides; only this file drops a datagram, holds one back, copies one, or
//! flips a bit in one. The tests that matter here therefore count what arrived
//! at the *inner* socket rather than what the counters say: a decorator that
//! computes every decision, increments every counter and then forwards the
//! datagram anyway satisfies every assertion made about decisions while
//! delivering all of the traffic it reports as lost.
//!
//! # Which direction is which
//!
//! One decorator sits at one endpoint and names its own halves: the datagrams
//! it sends are the downlink, the ones it receives are the uplink. Installed on
//! a proxy's client-facing socket those read the usual way round.
//!
//! # What `try_send` promises, and what it does not
//!
//! `try_send` runs on quinn's connection driver and must never block, so a
//! datagram the profile says to release later is copied into this socket's own
//! queue and `Ok(())` is returned while it is still in memory here. quinn's
//! pacing and release-error accounting therefore measure this shim's
//! acceptance, not the wire. The alternative is worse: quinn retries the whole
//! transmit after `poll_writable` resolves, so returning `WouldBlock` for held
//! datagrams would need bookkeeping whose bugs duplicate traffic.
//!
//! `WouldBlock` is returned for one thing only — a transmit arriving when the
//! queue is at its bound — and refused before any decision is taken, so the
//! retry re-decides nothing and no sequence number is consumed.
//!
//! # The release path arrives in clumps, by design
//!
//! Held datagrams go out on this socket's own thread, waiting on a condition
//! variable until the earliest deadline. That primitive has a floor — see
//! [`crate::consts::RELEASE_FLOOR_NS`] — so per-datagram pacing finer than the
//! floor does not exist. At 100 Mbps with 1200-byte datagrams the ideal spacing
//! is 96 µs, so one wake-up releases about six datagrams instead of six
//! wake-ups releasing one each. The average rate stays exact; the micro-burst
//! shape a congestion controller sees does not match the profile.
//!
//! The clumping is reported rather than hidden: every wake-up folds its batch
//! size into `release_batches`, `released_from_queue` and `release_batch_max`,
//! and its lateness into `release_error_ns`.
//!
//! # Teardown detaches when it would otherwise join itself
//!
//! The release thread wakes the task blocked in `poll_recv`, and a waker can
//! hold the last reference to the socket owning the wheel — so `Drop` can run
//! on the release thread, where joining would deadlock. `Drop` compares thread
//! ids and detaches when they match. The stop flag is set and the condition
//! variable notified before that branch, so a detached thread still exits.

use std::collections::VecDeque;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use quinn::udp::{EcnCodepoint, RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};

use crate::consts::RELEASE_SLICE_NS;
use crate::control::ImpairHandle;
use crate::engine::Verdict;
use crate::wire::wire_bytes;
use crate::{Direction, Tick};

/// How long one wake-up of the release thread commits to.
///
/// The thread never sleeps longer than this while it is holding anything, which
/// is what bounds the retry interval for a datagram the inner socket refused
/// and the re-wake interval for a receive buffer too small for the head of the
/// queue. Both of those are progress guarantees rather than pacing decisions —
/// the pacing comes from each datagram's own deadline.
const SLICE: Duration = Duration::from_nanos(RELEASE_SLICE_NS);

/// An `AsyncUdpSocket` decorator. Behind the non-default `quinn-socket`
/// feature; nothing else in the crate depends on quinn.
///
/// Starts disarmed, and a disarmed decorator is transparent: sends are handed
/// to the inner socket byte for byte with their segmentation intact, receives
/// are handed back untouched, no buffer is copied and no thread is spawned.
#[derive(Debug)]
pub struct ImpairedUdpSocket {
    /// Everything the release thread also needs. The thread holds an
    /// `Arc<Shared>` and never an `Arc<ImpairedUdpSocket>`, so the socket stays
    /// droppable while its thread is running.
    shared: Arc<Shared>,
    /// The release thread, spawned the first time a datagram is held.
    ///
    /// Lazy rather than eager because a decorator that is never armed — the
    /// state every one of them starts in, and the state a socket installed
    /// "just in case" stays in — would otherwise cost an OS thread for nothing.
    releaser: Mutex<Option<JoinHandle<()>>>,
}

/// The state the socket and its release thread share.
#[derive(Debug)]
struct Shared {
    /// The socket being decorated.
    inner: Arc<dyn AsyncUdpSocket>,
    /// The engines, the counters and the decision log.
    handle: ImpairHandle,
    /// The held datagrams and the parked wakers.
    state: Mutex<State>,
    /// Signalled when a deadline is added, when a waker is parked, and when the
    /// socket is dropped.
    wake: Condvar,
}

/// Held datagrams and parked wakers.
///
/// One mutex for both directions. They are touched once per held datagram and
/// once per wake-up, never per byte, and splitting them would buy nothing but
/// a second lock ordering to get wrong.
#[derive(Debug, Default)]
struct State {
    /// Set by `Drop`. The release thread returns at its next look.
    stopping: bool,
    /// Datagrams waiting to be handed to the inner socket, earliest first.
    egress: VecDeque<Held>,
    /// Datagrams waiting to be handed up to quinn, earliest first.
    ingress: VecDeque<Held>,
    /// On-wire bytes in `egress`.
    egress_bytes: u64,
    /// On-wire bytes in `ingress`.
    ingress_bytes: u64,
    /// The task blocked in `poll_recv`, if any.
    recv_waker: Option<Waker>,
    /// Tasks blocked in `poll_writable` because the egress queue is full.
    write_wakers: Vec<Waker>,
    /// When the release thread last woke `recv_waker` for a due datagram.
    ///
    /// Rate-limits that wake to once per slice. Without it, a receive buffer
    /// too small for the head of the queue is an unbounded hot loop: the
    /// datagram stays due, the thread wakes the task, the task makes no
    /// progress and re-parks, and the pair spins a core between them. With it,
    /// the same situation retries at slice granularity and makes progress as
    /// soon as quinn offers a buffer that fits.
    last_recv_wake: Option<Instant>,
}

/// One datagram this socket is holding.
#[derive(Debug)]
struct Held {
    /// When it may go out. A real instant, not a tick, so that datagrams held
    /// across a `disarm` still leave: after a disarm there is no tick origin to
    /// convert against, and a queue that can only be drained while armed is a
    /// queue that strands whatever was in it.
    deadline: Instant,
    /// The tick the decision named. Kept only so the release path can report
    /// its own lateness.
    scheduled: Tick,
    /// Destination on the way out, source on the way in.
    peer: SocketAddr,
    /// Congestion notification bits, carried through unchanged.
    ecn: Option<EcnCodepoint>,
    /// `src_ip` on the way out, `dst_ip` on the way in.
    ip: Option<IpAddr>,
    /// The datagram, corruption already applied.
    payload: Vec<u8>,
    /// On-wire size, which is what the queue bound is expressed in.
    wire_bytes: u32,
}

impl ImpairedUdpSocket {
    /// Wrap an inner abstract socket. Starts DISARMED.
    pub fn wrap(inner: Arc<dyn AsyncUdpSocket>) -> (Arc<Self>, ImpairHandle) {
        let handle = ImpairHandle::detached();
        let shared = Arc::new(Shared {
            inner,
            handle: handle.clone(),
            state: Mutex::new(State::default()),
            wake: Condvar::new(),
        });
        (Arc::new(ImpairedUdpSocket { shared, releaser: Mutex::new(None) }), handle)
    }

    /// Bind a real socket and wrap it.
    ///
    /// Must be called from inside a tokio runtime context: the inner socket is
    /// built by quinn's own runtime adapter, which is how it gets its
    /// readiness notifications, and that adapter is only reachable there. The
    /// error when it is not is `no async runtime found`.
    ///
    /// # An IPv6 bind here is not dual-stack
    ///
    /// `quinn::Endpoint::client` asks for a dual-stack socket when the bind
    /// address is IPv6, so that a client bound to `[::]:0` can still reach an
    /// IPv4 peer. Doing the same needs the `IPV6_V6ONLY` socket option, which
    /// the standard library does not expose and which this crate cannot reach
    /// without taking a dependency it deliberately does not have. So the
    /// option is left at the platform default — and the platform defaults
    /// disagree: a wildcard IPv6 bind is dual-stack on a stock Linux and
    /// IPv6-only on Windows.
    ///
    /// This is stated rather than papered over because the failure is silent:
    /// nothing errors, the endpoint comes up, and IPv4 peers simply never
    /// answer. A caller that needs dual-stack builds the socket itself, hands
    /// it to `quinn::Runtime::wrap_udp_socket`, and passes the result to
    /// [`ImpairedUdpSocket::wrap`], which is what that constructor is for.
    pub fn bind(addr: SocketAddr) -> io::Result<(Arc<Self>, ImpairHandle)> {
        let socket = std::net::UdpSocket::bind(addr)?;
        let runtime =
            quinn::default_runtime().ok_or_else(|| io::Error::other("no async runtime found"))?;
        Ok(Self::wrap(runtime.wrap_udp_socket(socket)?))
    }

    /// Hand one datagram to the inner socket, as its own transmit.
    ///
    /// `segment_size` is always `None`: a datagram this shim emits is one
    /// datagram, whatever the transmit it came out of claimed.
    fn forward(
        &self,
        payload: &[u8],
        peer: SocketAddr,
        ecn: Option<EcnCodepoint>,
        ip: Option<IpAddr>,
    ) -> io::Result<()> {
        self.shared.inner.try_send(&Transmit {
            destination: peer,
            ecn,
            contents: payload,
            segment_size: None,
            src_ip: ip,
        })
    }

    /// Decide about one datagram of an outgoing transmit and act on the answer.
    fn send_one(
        &self,
        payload: &[u8],
        peer: SocketAddr,
        ecn: Option<EcnCodepoint>,
        ip: Option<IpAddr>,
        now: Tick,
    ) -> io::Result<()> {
        let wire = wire_bytes(payload.len(), peer);
        let Some(d) = self.shared.handle.decide(Direction::Downlink, wire, now) else {
            // Disarmed between reading the tick and here. Forwarding is the
            // disarmed behaviour and the datagram was never counted.
            return self.forward(payload, peer, ecn, ip);
        };
        if d.verdict == Verdict::Drop {
            return Ok(());
        }

        // Built once and reused for the copy, so the duplicate is byte-identical
        // to the original. Re-deciding for the copy would draw from the
        // generators again — a second, different corruption site — and netem's
        // duplicate is a copy of the packet, not a second packet.
        let outgoing = match d.corrupt {
            None => payload.to_vec(),
            Some(site) => {
                let mut v = payload.to_vec();
                // The engine bounds the offset by the smallest payload an
                // on-wire size of this many bytes can correspond to over any
                // address family, so it is inside this payload. An index panic
                // here would mean the log named a byte that was not flipped,
                // which is the one outcome worth crashing over.
                v[site.byte_offset as usize] ^= 1u8 << site.bit;
                v
            }
        };

        let releases = match d.duplicate {
            None => vec![d.release],
            Some(copy_at) => vec![d.release, copy_at],
        };
        for release in releases {
            if release > now {
                self.hold_egress(&outgoing, peer, ecn, ip, release, now, wire);
                continue;
            }
            match self.forward(&outgoing, peer, ecn, ip) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // The datagram has already been decided about and counted,
                    // so returning `WouldBlock` now would have quinn resend it
                    // and this shim decide about it a second time. Holding it
                    // instead keeps every counter matched to exactly one
                    // datagram; the release thread retries it a slice later.
                    self.hold_egress(&outgoing, peer, ecn, ip, now, now, wire);
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Copy a datagram into the egress queue and make sure something will drain
    /// it.
    #[allow(clippy::too_many_arguments)]
    fn hold_egress(
        &self,
        payload: &[u8],
        peer: SocketAddr,
        ecn: Option<EcnCodepoint>,
        ip: Option<IpAddr>,
        release: Tick,
        now: Tick,
        wire: u32,
    ) {
        let held = Held {
            deadline: Instant::now() + Duration::from_nanos(release.since(now)),
            scheduled: release,
            peer,
            ecn,
            ip,
            payload: payload.to_vec(),
            wire_bytes: wire,
        };
        {
            let mut st = lock(&self.shared.state);
            st.egress_bytes += u64::from(wire);
            insert_by_deadline(&mut st.egress, held);
        }
        self.start_releaser();
        self.shared.wake.notify_all();
    }

    /// Copy datagrams into the ingress queue, ahead of whatever is already
    /// there.
    ///
    /// `front` is what makes it correct to call this with datagrams that came
    /// out of one `RecvMeta` and did not fit the buffers quinn supplied: they
    /// arrived before everything still queued, so they go back in front of it.
    fn hold_ingress_front(&self, datagrams: Vec<Held>) {
        if datagrams.is_empty() {
            return;
        }
        {
            let mut st = lock(&self.shared.state);
            for held in datagrams.into_iter().rev() {
                st.ingress_bytes += u64::from(held.wire_bytes);
                st.ingress.push_front(held);
            }
        }
        self.start_releaser();
        self.shared.wake.notify_all();
    }

    /// Copy datagrams into the ingress queue in deadline order.
    fn hold_ingress(&self, datagrams: Vec<Held>) {
        if datagrams.is_empty() {
            return;
        }
        {
            let mut st = lock(&self.shared.state);
            for held in datagrams {
                st.ingress_bytes += u64::from(held.wire_bytes);
                insert_by_deadline(&mut st.ingress, held);
            }
        }
        self.start_releaser();
        self.shared.wake.notify_all();
    }

    /// Spawn the release thread if it is not running yet.
    fn start_releaser(&self) {
        let mut slot = lock(&self.releaser);
        if slot.is_some() {
            return;
        }
        let shared = Arc::clone(&self.shared);
        *slot = std::thread::Builder::new()
            .name("quinn-netem-release".to_owned())
            .spawn(move || release_loop(&shared))
            .ok();
    }

    /// Move every due ingress datagram that fits into `bufs`, and report the
    /// batch.
    ///
    /// Stops at the first datagram that is not due yet or does not fit, so the
    /// queue stays in order. Returns how many buffers were filled.
    fn drain_ingress(&self, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> usize {
        let capacity = bufs.len().min(meta.len());
        if capacity == 0 {
            return 0;
        }
        let now = Instant::now();
        let mut taken: Vec<Held> = Vec::new();
        {
            let mut st = lock(&self.shared.state);
            while taken.len() < capacity {
                let fits = match st.ingress.front() {
                    Some(h) => h.deadline <= now && h.payload.len() <= bufs[taken.len()].len(),
                    None => false,
                };
                if !fits {
                    break;
                }
                let h = st.ingress.pop_front().expect("front was just inspected");
                st.ingress_bytes = st.ingress_bytes.saturating_sub(u64::from(h.wire_bytes));
                taken.push(h);
            }
            if !taken.is_empty() {
                st.last_recv_wake = None;
            }
        }
        if taken.is_empty() {
            return 0;
        }

        let earliest = taken.iter().map(|h| h.deadline).min().expect("non-empty");
        let scheduled = taken.iter().map(|h| h.scheduled).min().expect("non-empty");
        for (i, h) in taken.iter().enumerate() {
            bufs[i][..h.payload.len()].copy_from_slice(&h.payload);
            meta[i] = RecvMeta {
                addr: h.peer,
                len: h.payload.len(),
                // Never zero while `len` is non-zero: quinn's endpoint driver
                // advances its read cursor by `stride`, so a zero there is an
                // infinite loop in the driver rather than a malformed packet.
                // One datagram per meta, so the two are equal by construction.
                stride: h.payload.len(),
                ecn: h.ecn,
                dst_ip: h.ip,
            };
        }
        let n = taken.len();
        self.report_release(n, scheduled, earliest);
        n
    }

    /// Fold one wake-up's batch into the release counters.
    fn report_release(&self, batch: usize, scheduled: Tick, deadline: Instant) {
        let late = Instant::now().saturating_duration_since(deadline);
        let observed =
            scheduled.saturating_add_ns(u64::try_from(late.as_nanos()).unwrap_or(u64::MAX));
        let batch = u32::try_from(batch).unwrap_or(u32::MAX);
        self.shared.handle.record_release(batch, scheduled, observed);
    }

    /// Decide about everything one `poll_recv` of the inner socket produced.
    ///
    /// Returns the datagrams to hand up now, in arrival order, and separately
    /// the ones a delay model held back.
    fn decide_received(
        &self,
        bufs: &[IoSliceMut<'_>],
        meta: &[RecvMeta],
        n: usize,
        now: Tick,
    ) -> (Vec<Held>, Vec<Held>) {
        let mut ready = Vec::new();
        let mut held = Vec::new();
        for i in 0..n {
            let m = meta[i];
            let filled = &bufs[i][..m.len.min(bufs[i].len())];
            // A `RecvMeta` describes one datagram when `stride == len`, and
            // several packed back to back when it is smaller. A zero stride is
            // not a valid description of a non-empty buffer, so it is read as
            // "one datagram" rather than propagated.
            let stride =
                if m.stride == 0 || m.stride > filled.len() { filled.len() } else { m.stride };
            let datagrams: Vec<&[u8]> =
                if stride == 0 { vec![&filled[..0]] } else { filled.chunks(stride).collect() };

            for dg in datagrams {
                if !self.shared.handle.applies_to(m.addr) {
                    ready.push(received(dg.to_vec(), &m, now, wire_bytes(dg.len(), m.addr)));
                    continue;
                }
                let wire = wire_bytes(dg.len(), m.addr);
                let Some(d) = self.shared.handle.decide(Direction::Uplink, wire, now) else {
                    ready.push(received(dg.to_vec(), &m, now, wire));
                    continue;
                };
                if d.verdict == Verdict::Drop {
                    continue;
                }
                let payload = match d.corrupt {
                    None => dg.to_vec(),
                    Some(site) => {
                        let mut v = dg.to_vec();
                        v[site.byte_offset as usize] ^= 1u8 << site.bit;
                        v
                    }
                };
                let releases = match d.duplicate {
                    None => vec![d.release],
                    Some(copy_at) => vec![d.release, copy_at],
                };
                for release in releases {
                    let mut one = received(payload.clone(), &m, release, wire);
                    if release > now {
                        one.deadline = Instant::now() + Duration::from_nanos(release.since(now));
                        held.push(one);
                    } else {
                        ready.push(one);
                    }
                }
            }
        }
        (ready, held)
    }

    /// Park the polling task so the release thread can wake it.
    fn park_recv(&self, cx: &Context<'_>) {
        let mut st = lock(&self.shared.state);
        st.recv_waker = Some(cx.waker().clone());
    }

    /// On-wire bytes this direction is allowed to be holding.
    fn bound(&self, dir: Direction) -> u64 {
        self.shared.handle.queue_bytes(dir)
    }
}

/// One received datagram, as a queue entry due immediately.
fn received(payload: Vec<u8>, m: &RecvMeta, scheduled: Tick, wire: u32) -> Held {
    Held {
        deadline: Instant::now(),
        scheduled,
        peer: m.addr,
        ecn: m.ecn,
        ip: m.dst_ip,
        payload,
        wire_bytes: wire,
    }
}

impl AsyncUdpSocket for ImpairedUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        let inner = Arc::clone(&self.shared.inner).create_io_poller();
        Box::pin(ImpairedPoller { shared: Arc::clone(&self.shared), inner })
    }

    // The transmit type here is `quinn::udp::Transmit`, which carries the bytes.
    // `quinn::Transmit` is a different type with a `size` field and no
    // `contents`, and a decorator written against it compiles nowhere near this
    // trait.
    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let peer = transmit.destination;
        let Some(now) = self.shared.handle.tick() else {
            return self.shared.inner.try_send(transmit);
        };
        if !self.shared.handle.applies_to(peer) {
            return self.shared.inner.try_send(transmit);
        }

        // Refused before anything is decided or counted, so quinn's retry of
        // the whole transmit costs a sequence number and a set of counter
        // increments for a datagram that was never accepted.
        let queued = lock(&self.shared.state).egress_bytes;
        if queued > 0 && queued >= self.bound(Direction::Downlink) {
            return Err(io::ErrorKind::WouldBlock.into());
        }

        // While armed `max_transmit_segments` reports 1, so quinn does not
        // build segmented transmits — but it re-reads that value once per
        // `drive_transmit` rather than per datagram, so a profile armed in the
        // middle of one still sees a segmented transmit arrive. Splitting it is
        // what makes each datagram of it decidable on its own.
        match transmit.segment_size {
            Some(n) if n > 0 && n < transmit.contents.len() => {
                for chunk in transmit.contents.chunks(n) {
                    self.send_one(chunk, peer, transmit.ecn, transmit.src_ip, now)?;
                }
            }
            _ => self.send_one(transmit.contents, peer, transmit.ecn, transmit.src_ip, now)?,
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            // Anything this socket is holding goes up before anything new is
            // read, which is what keeps a held datagram ahead of the datagrams
            // that arrived after it.
            let delivered = self.drain_ingress(bufs, meta);
            if delivered > 0 {
                return Poll::Ready(Ok(delivered));
            }

            let Some(now) = self.shared.handle.tick() else {
                let held = lock(&self.shared.state).ingress.is_empty();
                if held {
                    return self.shared.inner.poll_recv(cx, bufs, meta);
                }
                // Disarmed with datagrams still held: they are drained above and
                // the thread that owns their deadlines wakes this task.
                self.park_recv(cx);
                return Poll::Pending;
            };

            // At the bound the inner socket is deliberately left unread. The
            // datagrams stay in the kernel's receive buffer and the kernel drops
            // them if it must, which is what a congested link does — and which
            // is honest in a way that accepting them and dropping them here
            // would not be, because a drop this shim performs is a drop it must
            // account for.
            let queued = lock(&self.shared.state).ingress_bytes;
            if queued > 0 && queued >= self.bound(Direction::Uplink) {
                self.park_recv(cx);
                return Poll::Pending;
            }

            let n = match self.shared.inner.poll_recv(cx, bufs, meta) {
                Poll::Ready(Ok(n)) => n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    // The inner socket registered `cx`; this registers it a
                    // second time so a release deadline can wake the same task.
                    self.park_recv(cx);
                    return Poll::Pending;
                }
            };
            if n == 0 {
                return Poll::Ready(Ok(0));
            }

            let (ready, held) = self.decide_received(bufs, meta, n, now);
            self.hold_ingress(held);
            if ready.is_empty() {
                // Every datagram of this batch was dropped or held back. There
                // is nothing to hand up and no progress to report, so the inner
                // socket is polled again rather than returning a count of zero.
                continue;
            }

            // Whatever does not fit the buffers quinn supplied goes to the front
            // of the queue, due immediately, and comes up on the next poll.
            let capacity = bufs.len().min(meta.len());
            let mut out = 0;
            let mut overflow = Vec::new();
            for h in ready {
                if out < capacity && h.payload.len() <= bufs[out].len() {
                    bufs[out][..h.payload.len()].copy_from_slice(&h.payload);
                    meta[out] = RecvMeta {
                        addr: h.peer,
                        len: h.payload.len(),
                        stride: h.payload.len(),
                        ecn: h.ecn,
                        dst_ip: h.ip,
                    };
                    out += 1;
                } else {
                    overflow.push(h);
                }
            }
            self.hold_ingress_front(overflow);
            if out == 0 {
                continue;
            }
            return Poll::Ready(Ok(out));
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.shared.inner.local_addr()
    }

    /// `1` while armed, so quinn never builds a segmented transmit and every
    /// datagram arrives here as its own transmit; the inner socket's value
    /// otherwise.
    ///
    /// Not the trait default, which is also `1` — that coincidence is why this
    /// override has to be tested on both legs. A decorator that inherits the
    /// default is correct while armed and silently caps a disarmed socket's
    /// throughput at one datagram per syscall.
    fn max_transmit_segments(&self) -> usize {
        if self.shared.handle.is_armed() {
            1
        } else {
            self.shared.inner.max_transmit_segments()
        }
    }

    /// Always the inner socket's value: it sizes the receive buffers quinn
    /// allocates, and this shim splits whatever it is given rather than
    /// constraining what may arrive.
    fn max_receive_segments(&self) -> usize {
        self.shared.inner.max_receive_segments()
    }

    /// Always the inner socket's value.
    ///
    /// The trait default is `true`, and quinn reads this as
    /// `let allow_mtud = !socket.may_fragment();`. So a decorator that inherits
    /// the default turns path-MTU discovery off for every endpoint built over
    /// it, with no compile error, no warning, and no counter that moves.
    fn may_fragment(&self) -> bool {
        self.shared.inner.may_fragment()
    }
}

impl Drop for ImpairedUdpSocket {
    fn drop(&mut self) {
        {
            let mut st = lock(&self.shared.state);
            st.stopping = true;
        }
        self.shared.wake.notify_all();
        let Some(handle) = lock(&self.releaser).take() else {
            return;
        };
        // Joining the release thread from the release thread is an unbounded
        // deadlock, not a slow path: the thread is inside this call and can
        // never return to observe the stop flag. It is reachable because the
        // thread wakes the task blocked in `poll_recv`, and that waker can hold
        // the last reference to this socket. Detaching converts the hang into a
        // bounded leak — the flag is set and the notification already sent
        // above, so the detached thread exits within one slice on its own.
        if handle.thread().id() != std::thread::current().id() {
            let _ = handle.join();
        }
    }
}

/// A `UdpPoller` over the inner socket's, with the shim's own queue in front.
#[derive(Debug)]
struct ImpairedPoller {
    /// The queue whose fullness this poller reports on.
    shared: Arc<Shared>,
    /// The inner socket's poller.
    ///
    /// `Pin<Box<dyn UdpPoller>>` is `Unpin`, so forwarding needs neither
    /// `unsafe` nor a pin projection.
    inner: Pin<Box<dyn UdpPoller>>,
}

impl UdpPoller for ImpairedPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        {
            let mut st = lock(&this.shared.state);
            let bound = this.shared.handle.queue_bytes(Direction::Downlink);
            if st.egress_bytes > 0 && st.egress_bytes >= bound {
                st.write_wakers.push(cx.waker().clone());
                return Poll::Pending;
            }
        }
        this.inner.as_mut().poll_writable(cx)
    }
}

/// Insert keeping the queue ordered by deadline, and stable within one
/// deadline.
///
/// Stability is what makes the order the socket emits predictable from the
/// decisions alone: entries are appended in sequence-number order, so the
/// result is the decisions sorted by release tick and then by sequence number.
/// An unstable insert would put two datagrams released at the same tick in
/// whichever order the sort felt like, and the ordering assertion at the socket
/// would then be asserting a property of the sort.
fn insert_by_deadline(queue: &mut VecDeque<Held>, held: Held) {
    let at = queue.iter().position(|q| q.deadline > held.deadline).unwrap_or(queue.len());
    queue.insert(at, held);
}

/// The release thread's body.
///
/// Owns nothing but `Shared`, so the socket it serves stays droppable, and
/// touches the inner socket only outside the state lock.
fn release_loop(shared: &Arc<Shared>) {
    loop {
        let Some(mut st) = wait_for_work(shared) else {
            return;
        };

        let now = Instant::now();
        let mut due: Vec<Held> = Vec::new();
        while st.egress.front().is_some_and(|h| h.deadline <= now) {
            let h = st.egress.pop_front().expect("front was just inspected");
            st.egress_bytes = st.egress_bytes.saturating_sub(u64::from(h.wire_bytes));
            due.push(h);
        }

        // A due ingress datagram is not moved here — only the task inside
        // `poll_recv` has buffers to put one in. It is woken, at most once per
        // slice, and it does the moving.
        let wake_recv = st.ingress.front().is_some_and(|h| h.deadline <= now)
            && st.last_recv_wake.is_none_or(|w| now.duration_since(w) >= SLICE);
        let recv_waker = if wake_recv {
            st.last_recv_wake = Some(now);
            st.recv_waker.take()
        } else {
            None
        };
        let write_wakers = if st.egress_bytes < shared.handle.queue_bytes(Direction::Downlink) {
            std::mem::take(&mut st.write_wakers)
        } else {
            Vec::new()
        };
        drop(st);

        // Outside the lock: `wake` may run arbitrary executor code, and
        // `try_send` may block on a syscall.
        if let Some(w) = recv_waker {
            w.wake();
        }
        for w in write_wakers {
            w.wake();
        }
        if !due.is_empty() {
            forward_due(shared, due);
        }
    }
}

/// Block until there is something to release or the socket is going away.
///
/// `None` means the socket is going away.
fn wait_for_work(shared: &Arc<Shared>) -> Option<MutexGuard<'_, State>> {
    let mut st = lock(&shared.state);
    loop {
        if st.stopping {
            return None;
        }
        let now = Instant::now();
        match next_deadline(&st) {
            Some(at) if at <= now => return Some(st),
            Some(at) => {
                let (guard, _) = shared
                    .wake
                    .wait_timeout(st, at.duration_since(now))
                    .unwrap_or_else(|p| p.into_inner());
                st = guard;
            }
            None => {
                st = shared.wake.wait(st).unwrap_or_else(|p| p.into_inner());
            }
        }
    }
}

/// When the release thread next has something to do.
fn next_deadline(st: &State) -> Option<Instant> {
    let egress = st.egress.front().map(|h| h.deadline);
    let ingress = st.ingress.front().map(|h| match st.last_recv_wake {
        // The receiving task has been woken for this datagram already and has
        // not taken it, so the next look is a slice away rather than now.
        Some(w) => h.deadline.max(w + SLICE),
        None => h.deadline,
    });
    match (egress, ingress) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// Hand one wake-up's worth of datagrams to the inner socket and report the
/// batch.
///
/// Everything due goes out in one pass — that is the clumping the release
/// counters exist to make visible. The batch reported is what actually reached
/// the inner socket, so a datagram the inner socket refused is not counted as
/// released.
fn forward_due(shared: &Arc<Shared>, due: Vec<Held>) {
    let scheduled = due.iter().map(|h| h.scheduled).min().expect("non-empty");
    let deadline = due.iter().map(|h| h.deadline).min().expect("non-empty");
    let mut sent = 0usize;
    let mut refused: Vec<Held> = Vec::new();

    for (i, h) in due.into_iter().enumerate() {
        if !refused.is_empty() {
            // The inner socket refused an earlier datagram of this batch.
            // Sending the rest now would put them on the wire ahead of it.
            refused.push(h);
            continue;
        }
        let result = shared.inner.try_send(&Transmit {
            destination: h.peer,
            ecn: h.ecn,
            contents: &h.payload,
            segment_size: None,
            src_ip: h.ip,
        });
        match result {
            Ok(()) => sent += 1,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => refused.push(h),
            Err(_) => {
                // A hard error is the socket telling us this datagram will
                // never go. Dropping it here is the only option left; retrying
                // it forever would wedge everything behind it.
                let _ = i;
            }
        }
    }

    if !refused.is_empty() {
        let retry_at = Instant::now() + SLICE;
        let mut st = lock(&shared.state);
        for mut h in refused.into_iter().rev() {
            h.deadline = retry_at;
            st.egress_bytes += u64::from(h.wire_bytes);
            st.egress.push_front(h);
        }
    }

    if sent > 0 {
        let late = Instant::now().saturating_duration_since(deadline);
        let observed =
            scheduled.saturating_add_ns(u64::try_from(late.as_nanos()).unwrap_or(u64::MAX));
        let batch = u32::try_from(sent).unwrap_or(u32::MAX);
        shared.handle.record_release(batch, scheduled, observed);
    }
}

/// Lock, recovering from a previous panic rather than propagating it.
///
/// The state behind these mutexes is a queue of byte vectors and a list of
/// wakers; a panic cannot leave either in a shape that is unsafe to read.
/// Propagating the poison would turn one panicked send into a socket whose
/// every later poll also panics, which converts a lost datagram into a dead
/// connection.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

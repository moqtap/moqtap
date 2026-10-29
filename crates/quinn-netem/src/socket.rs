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
//! destination peer's queue is at its bound — and refused before any decision
//! is taken, so the retry re-decides nothing and no sequence number is consumed.
//!
//! # Every peer has its own queues
//!
//! Held datagrams are queued per peer, each bounded by that peer's profile, so a
//! full queue for one peer never holds back another. On the way in a datagram
//! from a peer whose queue is full is discarded before any decision and counted
//! in `ingress_overflow`. On the way out the connection sending to that peer
//! waits: quinn polls a connection's own poller and then calls `try_send` on the
//! same thread, so the poller that last answered ready on this thread is the one
//! a refusal is charged to, and it stays pending until that peer's queue drains.
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

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
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

thread_local! {
    /// The poller that last answered ready on this thread. A `try_send` refused
    /// for a full peer queue is charged to it; see the module docs.
    static READY: RefCell<Option<Arc<Blocked>>> = const { RefCell::new(None) };
}

/// The peer whose full queue a poller is waiting on.
#[derive(Debug, Default)]
struct Blocked(Mutex<Option<SocketAddr>>);

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
    releaser: Mutex<Option<JoinHandle<()>>>,
}

/// The state the socket and its release thread share.
#[derive(Debug)]
struct Shared {
    /// The socket being decorated.
    inner: Arc<dyn AsyncUdpSocket>,
    /// The links, the counters and the decision logs.
    handle: ImpairHandle,
    /// The held datagrams and the parked wakers.
    state: Mutex<State>,
    /// Signalled when a deadline is added, when a waker is parked, and when the
    /// socket is dropped.
    wake: Condvar,
}

/// Held datagrams and parked wakers.
///
/// Lock order: this before the handle's own lock, never the reverse.
#[derive(Debug, Default)]
struct State {
    /// Set by `Drop`. The release thread returns at its next look.
    stopping: bool,
    /// Each peer's queues. An entry is removed once it holds nothing.
    peers: HashMap<SocketAddr, Queues>,
    /// The task blocked in `poll_recv`, if any.
    recv_waker: Option<Waker>,
    /// When the release thread last woke `recv_waker` for a due datagram.
    ///
    /// Rate-limits that wake to once per slice, so a receive buffer too small
    /// for the head of the queue retries at slice granularity instead of
    /// spinning a core.
    last_recv_wake: Option<Instant>,
}

/// One peer's held datagrams.
#[derive(Debug, Default)]
struct Queues {
    /// Waiting to be handed to the inner socket, earliest first.
    egress: VecDeque<Held>,
    /// Waiting to be handed up to quinn, earliest first.
    ingress: VecDeque<Held>,
    /// On-wire bytes in `egress`.
    egress_bytes: u64,
    /// On-wire bytes in `ingress`.
    ingress_bytes: u64,
    /// Pollers waiting for `egress` to drop below its bound.
    write_wakers: Vec<Waker>,
}

impl Queues {
    fn is_empty(&self) -> bool {
        self.egress.is_empty() && self.ingress.is_empty() && self.write_wakers.is_empty()
    }
}

impl State {
    fn queues(&mut self, peer: SocketAddr) -> &mut Queues {
        self.peers.entry(peer).or_default()
    }

    fn egress_bytes(&self, peer: SocketAddr) -> u64 {
        self.peers.get(&peer).map_or(0, |q| q.egress_bytes)
    }

    fn ingress_bytes(&self, peer: SocketAddr) -> u64 {
        self.peers.get(&peer).map_or(0, |q| q.ingress_bytes)
    }

    fn holds_ingress(&self) -> bool {
        self.peers.values().any(|q| !q.ingress.is_empty())
    }

    /// The peer whose ingress head is due first, if any is due.
    fn first_due_ingress(&self, now: Instant) -> Option<SocketAddr> {
        self.peers
            .iter()
            .filter_map(|(a, q)| q.ingress.front().map(|h| (h.deadline, *a)))
            .filter(|(d, _)| *d <= now)
            .min_by_key(|(d, _)| *d)
            .map(|(_, a)| a)
    }

    fn prune(&mut self) {
        self.peers.retain(|_, q| !q.is_empty());
    }
}

/// One datagram this socket is holding.
#[derive(Debug)]
struct Held {
    /// When it may go out. A real instant rather than a tick, so datagrams
    /// held across a disarm still leave.
    deadline: Instant,
    /// The tick the decision named, for reporting the release path's lateness.
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
    /// The `IPV6_V6ONLY` option is left at the platform default, which is
    /// dual-stack on a stock Linux and IPv6-only on Windows. A caller that needs
    /// dual-stack builds the socket itself, hands it to
    /// `quinn::Runtime::wrap_udp_socket`, and passes the result to
    /// [`ImpairedUdpSocket::wrap`].
    pub fn bind(addr: SocketAddr) -> io::Result<(Arc<Self>, ImpairHandle)> {
        let socket = std::net::UdpSocket::bind(addr)?;
        let runtime =
            quinn::default_runtime().ok_or_else(|| io::Error::other("no async runtime found"))?;
        Ok(Self::wrap(runtime.wrap_udp_socket(socket)?))
    }

    /// Hand one datagram to the inner socket, as its own transmit.
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
        let Some(d) = self.shared.handle.decide(peer, Direction::Downlink, wire, now) else {
            // The peer stopped being impaired between `begin` and here; the
            // datagram was never counted.
            return self.forward(payload, peer, ecn, ip);
        };
        if d.verdict == Verdict::Drop {
            return Ok(());
        }

        // Built once and reused for the copy, so a duplicate is byte-identical.
        let outgoing = match d.corrupt {
            None => payload.to_vec(),
            Some(site) => {
                let mut v = payload.to_vec();
                // The engine bounds the offset by the smallest payload this
                // on-wire size can carry, so it is inside this payload.
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
                    // Already decided and counted, so it is held and retried
                    // rather than handed back to quinn to resend.
                    self.hold_egress(&outgoing, peer, ecn, ip, now, now, wire);
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Copy a datagram into its peer's egress queue and make sure something
    /// will drain it.
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
            let q = st.queues(peer);
            q.egress_bytes += u64::from(wire);
            insert_by_deadline(&mut q.egress, held);
        }
        self.start_releaser();
        self.shared.wake.notify_all();
    }

    /// Put datagrams back at the front of their peers' ingress queues: they
    /// arrived before everything still queued.
    fn hold_ingress_front(&self, datagrams: Vec<Held>) {
        if datagrams.is_empty() {
            return;
        }
        {
            let mut st = lock(&self.shared.state);
            for held in datagrams.into_iter().rev() {
                let q = st.queues(held.peer);
                q.ingress_bytes += u64::from(held.wire_bytes);
                q.ingress.push_front(held);
            }
        }
        self.start_releaser();
        self.shared.wake.notify_all();
    }

    /// Copy datagrams into their peers' ingress queues in deadline order.
    fn hold_ingress(&self, datagrams: Vec<Held>) {
        if datagrams.is_empty() {
            return;
        }
        {
            let mut st = lock(&self.shared.state);
            for held in datagrams {
                let q = st.queues(held.peer);
                q.ingress_bytes += u64::from(held.wire_bytes);
                insert_by_deadline(&mut q.ingress, held);
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

    /// Move due ingress datagrams that fit into `bufs`, earliest first across
    /// peers, and report the batch. Stops at the first due datagram that does
    /// not fit. Returns how many buffers were filled.
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
                let Some(peer) = st.first_due_ingress(now) else {
                    break;
                };
                let q = st.queues(peer);
                let fits =
                    q.ingress.front().is_some_and(|h| h.payload.len() <= bufs[taken.len()].len());
                if !fits {
                    break;
                }
                let h = q.ingress.pop_front().expect("front was just inspected");
                q.ingress_bytes = q.ingress_bytes.saturating_sub(u64::from(h.wire_bytes));
                taken.push(h);
            }
            if !taken.is_empty() {
                st.last_recv_wake = None;
                st.prune();
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
                // Never zero while `len` is non-zero: quinn advances its read
                // cursor by `stride`.
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
    ) -> (Vec<Held>, Vec<Held>) {
        let mut ready = Vec::new();
        let mut held = Vec::new();
        // One tick per peer per batch, so a batch is decided at one instant.
        let mut ticks: Vec<(SocketAddr, Option<Tick>)> = Vec::new();
        for i in 0..n {
            let m = meta[i];
            let filled = &bufs[i][..m.len.min(bufs[i].len())];
            // A zero or oversized stride is read as "one datagram".
            let stride =
                if m.stride == 0 || m.stride > filled.len() { filled.len() } else { m.stride };
            let datagrams: Vec<&[u8]> =
                if stride == 0 { vec![&filled[..0]] } else { filled.chunks(stride).collect() };

            let now = match ticks.iter().find(|(a, _)| *a == m.addr) {
                Some((_, t)) => *t,
                None => {
                    let t = self.shared.handle.begin(m.addr);
                    ticks.push((m.addr, t));
                    t
                }
            };

            for dg in datagrams {
                let wire = wire_bytes(dg.len(), m.addr);
                let Some(now) = now else {
                    ready.push(received(dg.to_vec(), &m, Tick(0), wire));
                    continue;
                };
                let bound = self.shared.handle.queue_bytes(m.addr, Direction::Uplink);
                let queued = lock(&self.shared.state).ingress_bytes(m.addr);
                if queued > 0 && queued >= bound {
                    self.shared.handle.record_ingress_overflow(m.addr);
                    continue;
                }
                let Some(d) = self.shared.handle.decide(m.addr, Direction::Uplink, wire, now)
                else {
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
        Box::pin(ImpairedPoller {
            shared: Arc::clone(&self.shared),
            inner,
            blocked: Arc::new(Blocked::default()),
        })
    }

    // `quinn::udp::Transmit`, which carries the bytes, not `quinn::Transmit`.
    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let peer = transmit.destination;
        let ready = READY.with(|r| r.borrow_mut().take());
        let Some(now) = self.shared.handle.begin(peer) else {
            return self.shared.inner.try_send(transmit);
        };

        // Refused before anything is decided or counted, so quinn's retry of
        // the whole transmit costs no sequence number.
        let bound = self.shared.handle.queue_bytes(peer, Direction::Downlink);
        let queued = lock(&self.shared.state).egress_bytes(peer);
        if queued > 0 && queued >= bound {
            if let Some(blocked) = ready {
                *lock(&blocked.0) = Some(peer);
            }
            return Err(io::ErrorKind::WouldBlock.into());
        }

        // quinn re-reads `max_transmit_segments` once per drive rather than per
        // datagram, so a segmented transmit can still arrive just after arming.
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
            // Held datagrams go up before anything new is read.
            let delivered = self.drain_ingress(bufs, meta);
            if delivered > 0 {
                return Poll::Ready(Ok(delivered));
            }

            if !self.shared.handle.is_impairing() {
                if !lock(&self.shared.state).holds_ingress() {
                    return self.shared.inner.poll_recv(cx, bufs, meta);
                }
                // Disarmed with datagrams still held: the release thread wakes
                // this task when they are due.
                self.park_recv(cx);
                return Poll::Pending;
            }

            let n = match self.shared.inner.poll_recv(cx, bufs, meta) {
                Poll::Ready(Ok(n)) => n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    // Registered a second time so a release deadline can wake
                    // the same task.
                    self.park_recv(cx);
                    return Poll::Pending;
                }
            };
            if n == 0 {
                return Poll::Ready(Ok(0));
            }

            let (ready, held) = self.decide_received(bufs, meta, n);
            self.hold_ingress(held);
            if ready.is_empty() {
                continue;
            }

            // Whatever does not fit the buffers quinn supplied goes to the front
            // of its queue, due immediately.
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

    /// `1` while any peer can be impaired, so every datagram arrives as its own
    /// transmit; the inner socket's value otherwise. Not the trait default,
    /// which would cap a disarmed socket at one datagram per syscall.
    fn max_transmit_segments(&self) -> usize {
        if self.shared.handle.is_impairing() {
            1
        } else {
            self.shared.inner.max_transmit_segments()
        }
    }

    /// Always the inner socket's value.
    fn max_receive_segments(&self) -> usize {
        self.shared.inner.max_receive_segments()
    }

    /// Always the inner socket's value. The trait default `true` would turn
    /// path-MTU discovery off.
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
        // A waker run on the release thread can hold the last reference, and
        // joining from there would deadlock; the stop flag is already set, so a
        // detached thread exits within a slice.
        if handle.thread().id() != std::thread::current().id() {
            let _ = handle.join();
        }
    }
}

/// A `UdpPoller` over the inner socket's, pending while the peer it was last
/// refused for has a full queue.
#[derive(Debug)]
struct ImpairedPoller {
    shared: Arc<Shared>,
    inner: Pin<Box<dyn UdpPoller>>,
    blocked: Arc<Blocked>,
}

impl UdpPoller for ImpairedPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let blocked = *lock(&this.blocked.0);
        if let Some(peer) = blocked {
            let mut st = lock(&this.shared.state);
            let bound = this.shared.handle.queue_bytes(peer, Direction::Downlink);
            if let Some(q) = st.peers.get_mut(&peer) {
                if q.egress_bytes > 0 && q.egress_bytes >= bound {
                    q.write_wakers.push(cx.waker().clone());
                    return Poll::Pending;
                }
            }
            drop(st);
            *lock(&this.blocked.0) = None;
        }
        match this.inner.as_mut().poll_writable(cx) {
            Poll::Ready(Ok(())) => {
                let blocked = Arc::clone(&this.blocked);
                READY.with(|r| *r.borrow_mut() = Some(blocked));
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

/// Insert keeping the queue ordered by deadline, and stable within one
/// deadline, so the emitted order is the decisions sorted by release tick and
/// then by sequence number.
fn insert_by_deadline(queue: &mut VecDeque<Held>, held: Held) {
    let at = queue.iter().position(|q| q.deadline > held.deadline).unwrap_or(queue.len());
    queue.insert(at, held);
}

/// The release thread's body. Touches the inner socket only outside the state
/// lock.
fn release_loop(shared: &Arc<Shared>) {
    loop {
        let Some(mut st) = wait_for_work(shared) else {
            return;
        };

        let now = Instant::now();
        let mut due: Vec<Held> = Vec::new();
        let mut write_wakers = Vec::new();
        for (peer, q) in st.peers.iter_mut() {
            while q.egress.front().is_some_and(|h| h.deadline <= now) {
                let h = q.egress.pop_front().expect("front was just inspected");
                q.egress_bytes = q.egress_bytes.saturating_sub(u64::from(h.wire_bytes));
                due.push(h);
            }
            if !q.write_wakers.is_empty()
                && q.egress_bytes < shared.handle.queue_bytes(*peer, Direction::Downlink)
            {
                write_wakers.append(&mut q.write_wakers);
            }
        }
        // Stable, so each peer's own order is kept.
        due.sort_by_key(|h| h.deadline);

        // A due ingress datagram is not moved here; only the task inside
        // `poll_recv` has buffers. It is woken, at most once per slice.
        let wake_recv = st.first_due_ingress(now).is_some()
            && st.last_recv_wake.is_none_or(|w| now.duration_since(w) >= SLICE);
        let recv_waker = if wake_recv {
            st.last_recv_wake = Some(now);
            st.recv_waker.take()
        } else {
            None
        };
        st.prune();
        drop(st);

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
    let mut next: Option<Instant> = None;
    for q in st.peers.values() {
        let egress = q.egress.front().map(|h| h.deadline);
        let ingress = q.ingress.front().map(|h| match st.last_recv_wake {
            // Already woken for and not taken: look again a slice later.
            Some(w) => h.deadline.max(w + SLICE),
            None => h.deadline,
        });
        for at in [egress, ingress].into_iter().flatten() {
            next = Some(next.map_or(at, |n| n.min(at)));
        }
    }
    next
}

/// Hand one wake-up's worth of datagrams to the inner socket and report the
/// batch. A datagram the inner socket refused is not counted as released.
fn forward_due(shared: &Arc<Shared>, due: Vec<Held>) {
    let scheduled = due.iter().map(|h| h.scheduled).min().expect("non-empty");
    let deadline = due.iter().map(|h| h.deadline).min().expect("non-empty");
    let mut sent = 0usize;
    let mut refused: Vec<Held> = Vec::new();

    for h in due {
        if !refused.is_empty() {
            // Sending the rest now would put them on the wire ahead of the
            // refused one.
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
            // A hard error means this datagram will never go; retrying it
            // would wedge everything behind it.
            Err(_) => {}
        }
    }

    if !refused.is_empty() {
        let retry_at = Instant::now() + SLICE;
        let mut st = lock(&shared.state);
        for mut h in refused.into_iter().rev() {
            h.deadline = retry_at;
            let q = st.queues(h.peer);
            q.egress_bytes += u64::from(h.wire_bytes);
            q.egress.push_front(h);
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

/// Lock, recovering from a previous panic: a poisoned queue would turn one
/// lost datagram into a dead connection.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

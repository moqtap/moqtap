//! Every peer of one socket gets its own link: its own rate budget, queue,
//! delay line and random draws.

#![cfg(feature = "quinn-socket")]

use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};

use quinn_netem::model::{DelayModel, LossModel, Prob, RateModel};
use quinn_netem::profile::{DirectionProfile, ImpairProfile};
use quinn_netem::socket::ImpairedUdpSocket;
use quinn_netem::{peer_seed, wire_bytes, Direction, Impairer, Tick, Verdict};

/// Records every datagram it is handed, with the instant it arrived.
#[derive(Debug, Default)]
struct Inner {
    sent: Mutex<Vec<(SocketAddr, Vec<u8>, Instant)>>,
}

impl Inner {
    fn to(&self, peer: SocketAddr) -> Vec<(Vec<u8>, Instant)> {
        lock(&self.sent).iter().filter(|s| s.0 == peer).map(|s| (s.1.clone(), s.2)).collect()
    }
}

impl AsyncUdpSocket for Inner {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Writable)
    }

    fn try_send(&self, t: &Transmit) -> io::Result<()> {
        lock(&self.sent).push((t.destination, t.contents.to_vec(), Instant::now()));
        Ok(())
    }

    fn poll_recv(
        &self,
        _cx: &mut Context,
        _bufs: &mut [IoSliceMut<'_>],
        _meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        Poll::Pending
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(addr(1))
    }
}

#[derive(Debug)]
struct Writable;

impl UdpPoller for Writable {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn send(socket: &ImpairedUdpSocket, to: SocketAddr, payload: &[u8]) -> io::Result<()> {
    socket.try_send(&Transmit {
        destination: to,
        ecn: None,
        contents: payload,
        segment_size: None,
        src_ip: None,
    })
}

/// A payload naming its peer and its index.
fn payload(peer: u8, seq: u16) -> Vec<u8> {
    let mut v = vec![peer; 1200];
    v[1..3].copy_from_slice(&seq.to_be_bytes());
    v
}

fn settle(limit: Duration, mut done: impl FnMut() -> bool) {
    let start = Instant::now();
    while start.elapsed() < limit && !done() {
        std::thread::sleep(Duration::from_millis(2));
    }
}

const BPS: u64 = 4_000_000;
const BURST: u64 = 3_000;
const N: u16 = 250;

fn shaped() -> ImpairProfile {
    ImpairProfile {
        downlink: DirectionProfile {
            rate: Some(RateModel { bps: BPS, burst_bytes: BURST, queue_bytes: 1_000_000 }),
            ..DirectionProfile::default()
        },
        seed: 3,
        ..ImpairProfile::default()
    }
}

/// Two peers sending at once each get the whole configured rate. One shared
/// budget would take twice as long for each.
#[test]
fn two_peers_at_once_each_get_the_full_rate() {
    let inner = Arc::new(Inner::default());
    let (socket, handle) = ImpairedUdpSocket::wrap(inner.clone());
    handle.arm(shaped()).expect("a valid profile");
    handle.record_decisions(true);
    let (a, b) = (addr(5001), addr(5002));

    let start = Instant::now();
    for seq in 0..N {
        send(&socket, a, &payload(1, seq)).expect("queued");
        send(&socket, b, &payload(2, seq)).expect("queued");
    }

    let wire = u64::from(wire_bytes(1200, a));
    let solo_ns = (u64::from(N) * wire - BURST) * 8 * 1_000_000_000 / BPS;

    // The decisions: each peer's last release is where a lone sender's is.
    for peer in [a, b] {
        let log = handle.take_log(peer);
        assert_eq!(log.records().len(), usize::from(N));
        let last = log.records().last().expect("non-empty").release_ns;
        assert!(last >= solo_ns, "{peer}: released at {last} ns, before the rate allows");
        assert!(
            last < solo_ns + solo_ns / 5,
            "{peer}: last release at {last} ns, a lone sender finishes at {solo_ns} ns"
        );
    }

    // The wire: both peers' datagrams all arrive in about a lone sender's time.
    settle(Duration::from_secs(10), || {
        inner.to(a).len() == usize::from(N) && inner.to(b).len() == usize::from(N)
    });
    let solo = Duration::from_nanos(solo_ns);
    for peer in [a, b] {
        let got = inner.to(peer);
        assert_eq!(got.len(), usize::from(N), "{peer}: every datagram arrives");
        let took = got.last().expect("non-empty").1 - start;
        assert!(took < solo + solo / 2, "{peer}: took {took:?}, a lone sender takes {solo:?}");
    }
}

fn lossy_and_delayed() -> ImpairProfile {
    ImpairProfile {
        downlink: DirectionProfile {
            loss: Some(LossModel::Bernoulli { p: Prob::from_ppb(300_000_000) }),
            delay: Some(DelayModel::Uniform { mean_ns: 20_000_000, jitter_ns: 10_000_000, rho: 0 }),
            ..DirectionProfile::default()
        },
        seed: 99,
        ..ImpairProfile::default()
    }
}

/// What a lone engine with `seed` decides for `n` datagrams: which survive,
/// and how long each is held.
fn solo(seed: u64, n: u16) -> Vec<Option<u64>> {
    let mut e = Impairer::new(lossy_and_delayed().downlink, seed, Direction::Downlink)
        .expect("a valid profile");
    (0..u64::from(n))
        .map(|seq| {
            let d = e.decide(seq, wire_bytes(1200, addr(1)), Tick(0));
            (d.verdict != Verdict::Drop).then_some(d.release.0)
        })
        .collect()
}

/// Each peer's losses and delays are its own: a peer sending three times as
/// much beside it does not move them.
#[test]
fn each_peer_has_its_own_loss_and_delay() {
    let inner = Arc::new(Inner::default());
    let (socket, handle) = ImpairedUdpSocket::wrap(inner.clone());
    handle.arm(lossy_and_delayed()).expect("a valid profile");
    handle.record_decisions(true);
    let (a, b) = (addr(5001), addr(5002));

    for seq in 0..60u16 {
        send(&socket, a, &payload(1, seq)).expect("queued");
        for k in 0..3 {
            send(&socket, b, &payload(2, seq * 3 + k)).expect("queued");
        }
    }

    // The engine's held time, from the log (decided at each datagram's own
    // tick, so compare release minus decision).
    let held = |peer: SocketAddr| -> Vec<Option<u64>> {
        handle
            .take_log(peer)
            .records()
            .iter()
            .map(|r| (r.verdict != Verdict::Drop as u8).then_some(r.release_ns - r.now_ns))
            .collect()
    };
    assert_eq!(held(a), solo(peer_seed(99, 0), 60), "a is a lone sender's run");
    assert_eq!(held(b), solo(peer_seed(99, 1), 180), "b is a lone sender's run on its own seed");

    // The wire: exactly the survivors arrive for each peer.
    let survivors = |seed: u64, n: u16, tag: u8| -> Vec<Vec<u8>> {
        solo(seed, n)
            .iter()
            .enumerate()
            .filter(|(_, s)| s.is_some())
            .map(|(i, _)| payload(tag, u16::try_from(i).expect("small")))
            .collect()
    };
    let mut want_a = survivors(peer_seed(99, 0), 60, 1);
    let mut want_b = survivors(peer_seed(99, 1), 180, 2);
    settle(Duration::from_secs(5), || {
        inner.to(a).len() == want_a.len() && inner.to(b).len() == want_b.len()
    });
    let mut got_a: Vec<Vec<u8>> = inner.to(a).into_iter().map(|s| s.0).collect();
    let mut got_b: Vec<Vec<u8>> = inner.to(b).into_iter().map(|s| s.0).collect();
    // The delay is jittered, so arrival order is not send order.
    for v in [&mut want_a, &mut want_b, &mut got_a, &mut got_b] {
        v.sort();
    }
    assert_eq!(got_a, want_a);
    assert_eq!(got_b, want_b);
}

/// Giving one peer a profile of its own leaves the other peer's link as it
/// was: same numbering, same draws, same delivery.
#[test]
fn a_profile_change_on_one_peer_leaves_the_other_unchanged() {
    let inner = Arc::new(Inner::default());
    let (socket, handle) = ImpairedUdpSocket::wrap(inner.clone());
    handle.arm(lossy_and_delayed()).expect("a valid profile");
    handle.record_decisions(true);
    let (a, b) = (addr(5001), addr(5002));

    for seq in 0..30u16 {
        send(&socket, a, &payload(1, seq)).expect("queued");
        send(&socket, b, &payload(2, seq)).expect("queued");
    }
    let blackhole = ImpairProfile {
        downlink: DirectionProfile {
            loss: Some(LossModel::Bernoulli { p: Prob::from_ppb(1_000_000_000) }),
            ..DirectionProfile::default()
        },
        ..ImpairProfile::default()
    };
    handle.arm_peer(a, blackhole).expect("a valid profile");
    for seq in 30..60u16 {
        send(&socket, a, &payload(1, seq)).expect("queued");
        send(&socket, b, &payload(2, seq)).expect("queued");
    }

    let b_log = handle.take_log(b);
    let b_held: Vec<Option<u64>> = b_log
        .records()
        .iter()
        .map(|r| (r.verdict != Verdict::Drop as u8).then_some(r.release_ns - r.now_ns))
        .collect();
    assert_eq!(b_held, solo(peer_seed(99, 1), 60), "b ran straight through the change");

    let a_log = handle.take_log(a);
    let a_after = &a_log.records()[30..];
    assert!(a_after.iter().all(|r| r.verdict == Verdict::Drop as u8), "a's own profile applies");
    assert_eq!(a_after[0].seq, 0, "a's link restarted");

    let b_survivors = b_held.iter().filter(|h| h.is_some()).count();
    settle(Duration::from_secs(5), || inner.to(b).len() == b_survivors);
    assert_eq!(inner.to(b).len(), b_survivors);
    assert!(inner.to(a).iter().all(|(p, _)| u16::from_be_bytes([p[1], p[2]]) < 30));

    // Back to the socket profile: a starts a fresh link, b is untouched.
    handle.clear_peer(a);
    send(&socket, a, &payload(1, 60)).expect("queued");
    assert_eq!(handle.take_log(a).records()[0].seq, 0);
    send(&socket, b, &payload(2, 60)).expect("queued");
    assert_eq!(handle.take_log(b).records()[0].seq, 60, "b's numbering carried on");
}

/// One peer's full queue blocks only the connection sending to it.
#[test]
fn a_full_queue_blocks_only_its_own_peer() {
    let inner = Arc::new(Inner::default());
    let (socket, handle) = ImpairedUdpSocket::wrap(inner.clone());
    handle
        .arm(ImpairProfile {
            downlink: DirectionProfile {
                rate: Some(RateModel {
                    bps: 8_000_000_000,
                    burst_bytes: 100_000,
                    queue_bytes: 3_000,
                }),
                delay: Some(DelayModel::Fixed { mean_ns: 300_000_000 }),
                ..DirectionProfile::default()
            },
            ..ImpairProfile::default()
        })
        .expect("a valid profile");
    let (a, b) = (addr(5001), addr(5002));
    let mut cx = Context::from_waker(Waker::noop());
    let mut poll_a = Arc::clone(&socket).create_io_poller();
    let mut poll_b = Arc::clone(&socket).create_io_poller();

    for seq in 0..3 {
        assert!(poll_a.as_mut().poll_writable(&mut cx).is_ready());
        send(&socket, a, &payload(1, seq)).expect("under the bound");
    }
    assert!(poll_a.as_mut().poll_writable(&mut cx).is_ready());
    let refused = send(&socket, a, &payload(1, 3)).expect_err("a is full");
    assert_eq!(refused.kind(), io::ErrorKind::WouldBlock);
    assert!(poll_a.as_mut().poll_writable(&mut cx).is_pending(), "a waits");

    for seq in 0..3 {
        assert!(poll_b.as_mut().poll_writable(&mut cx).is_ready(), "b is not held back by a");
        send(&socket, b, &payload(2, seq)).expect("b has its own queue");
    }

    settle(Duration::from_secs(5), || inner.to(a).len() == 3);
    assert!(poll_a.as_mut().poll_writable(&mut cx).is_ready(), "a drains and is writable again");
}

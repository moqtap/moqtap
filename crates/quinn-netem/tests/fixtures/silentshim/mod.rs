//! A decorator that decides everything and applies nothing. **Kept red.**
//!
//! This is not a bug to be fixed. It is a fixture, and the test that uses it
//! asserts that the wire gates fail against it. Making it forward
//! conditionally — that is, making it correct — turns those gates green and
//! reddens the test that runs them.
//!
//! # What it is for
//!
//! A statistic named `dropped_loss` counts decisions. Only a counter on the far
//! side of the adapter can show a decision was applied. A shim of this shape —
//! deciding, counting, logging, and then forwarding regardless of the verdict —
//! satisfies every assertion made about decisions while delivering all of the
//! traffic it reports as lost. That is what the wire gates encode, and this
//! fixture is what proves they encode it: a gate that cannot fail against this
//! file is decoration.
//!
//! # Why it delegates to the real decorator
//!
//! Everything except the forwarding decision is the shipped implementation,
//! reached through a second decorator whose own inner socket is a sink. A
//! hand-written imitation could fail the gates for some incidental reason — a
//! capability it got wrong, a counter it forgot — and the gates would then be
//! proven against a straw man. Here the only difference from the real thing is
//! the last line of `try_send`, so a gate that reddens against this fixture
//! reddens for exactly one reason.

use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};

use quinn_netem::socket::ImpairedUdpSocket;
use quinn_netem::ImpairHandle;

/// Build the fixture over `inner`, with the same signature the real decorator
/// is driven through, so one gate body runs against both.
pub fn wrap(inner: Arc<dyn AsyncUdpSocket>) -> (Arc<dyn AsyncUdpSocket>, ImpairHandle) {
    let (decider, handle) = ImpairedUdpSocket::wrap(Arc::new(Sink));
    (Arc::new(SendAnyway { inner, decider }), handle)
}

/// The decorator that decides and then forwards anyway.
#[derive(Debug)]
struct SendAnyway {
    /// The socket a gate counts sends on.
    inner: Arc<dyn AsyncUdpSocket>,
    /// The shipped decorator, over a sink. Every decision, every counter and
    /// every log record comes from here, which is what makes the fixture a
    /// faithful one.
    decider: Arc<ImpairedUdpSocket>,
}

impl AsyncUdpSocket for SendAnyway {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Arc::clone(&self.inner).create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        // Decide about it: the engines run, `datagrams_seen` and every drop
        // cause move, the decision log gains its record.
        let _ = self.decider.try_send(transmit);
        // …and send it anyway. This line is the fixture.
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_recv(cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.decider.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

/// Where the fixture's decider sends the datagrams it decided to send.
///
/// They are not observed: the gates count what reaches the socket the fixture
/// itself was given, which is the whole point.
#[derive(Debug)]
struct Sink;

impl AsyncUdpSocket for Sink {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(AlwaysWritable)
    }

    fn try_send(&self, _transmit: &Transmit) -> io::Result<()> {
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
        Ok("127.0.0.1:1".parse().expect("a literal address"))
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

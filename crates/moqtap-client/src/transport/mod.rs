//! Transport abstraction for QUIC and WebTransport.
//!
//! Uses enum dispatch (not trait objects) since the transport set is closed.
//! WebTransport support is behind the `webtransport` feature flag. Nothing
//! here is per-draft; every draft's connection is carried over the same two.

pub mod quic;
#[cfg(feature = "webtransport")]
pub mod webtransport;

pub use quic::{
    dial_quic, dial_quic_to, show_cipher_suite, CertificateHook, CertificateLog, DialError,
    DialPhase, QuicDialOptions, QuicTarget, TLS13_CIPHER_SUITES,
};
#[cfg(feature = "webtransport")]
pub use webtransport::{dial_webtransport, dial_webtransport_to};

use std::future::Future;

use bytes::Bytes;

/// A handshake that failed, with the codes the failure carried still intact.
///
/// The reason it is a struct and not another `String` variant: a peer's refusal
/// arrives as a *number*, and flattening it into prose is lossy in a way that
/// only shows up downstream. A TLS alert reaches QUIC as `0x0100 | alert`, so
/// `no_application_protocol` (120) is `0x178`, and a caller that wants to
/// distinguish "this relay does not speak our protocol" from "this relay's
/// certificate expired" (alert 45, `0x12D`) was left parsing error messages for
/// digits.
///
/// Every field is optional except [`reason`](Self::reason), because not every
/// failure has a code — a timeout and a DNS miss are real outcomes with nothing
/// numeric in them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeFailure {
    /// The QUIC error code, when the failure carried one.
    ///
    /// Meaningless without [`code_space`](Self::code_space) — the same integer
    /// says different things in the two spaces.
    pub code: Option<u64>,
    /// Which space [`code`](Self::code) is a number in.
    pub code_space: Option<CodeSpace>,
    /// The TLS alert, when the code was a *transport* code in QUIC's crypto
    /// range.
    ///
    /// Derived and not independently sourced: QUIC has no separate field for
    /// it, and `0x0100..=0x01ff` *is* how TLS alerts are carried.
    pub tls_alert: Option<u8>,
    /// What the stack said, for the detail no code carries — which certificate
    /// field mismatched, when it expired, which name was expected.
    ///
    /// Alert 42 (`bad_certificate`) is rustls's catch-all, so telling an expired
    /// certificate from a name mismatch still means reading this.
    pub reason: String,
}

/// Which number space a QUIC error code belongs to.
///
/// Kept because the same integer means different things in each, and a report
/// that loses the space is one that cannot be read. Transport code 271 is
/// `0x10F` — inside the range TLS alerts are carried in. Application code 271
/// is a peer's own close code and has nothing to do with TLS. Reading an alert
/// out of the second produces a finding that never happened, which is worse
/// than producing none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeSpace {
    /// QUIC's own transport errors, where TLS alerts arrive as `0x0100 | alert`.
    Transport,
    /// The application's close codes — over MoQT, a draft's own error codes.
    Application,
}

impl HandshakeFailure {
    /// A failure carrying a transport-space code, with any TLS alert recovered.
    ///
    /// Prefer this over a struct literal: it is what keeps `tls_alert`
    /// consistent with `code`, and a literal can set the two independently.
    pub fn transport(code: u64, reason: String) -> Self {
        Self {
            code: Some(code),
            code_space: Some(CodeSpace::Transport),
            tls_alert: Self::alert_of(code),
            reason,
        }
    }

    /// A failure carrying an application-space close code.
    ///
    /// Never carries a TLS alert: application codes are a separate space, and
    /// the ones that happen to land in `0x0100..=0x01ff` are the trap this
    /// constructor exists to close.
    pub fn application(code: u64, reason: String) -> Self {
        Self { code: Some(code), code_space: Some(CodeSpace::Application), tls_alert: None, reason }
    }

    /// A failure with nothing numeric in it — a timeout, a DNS miss, a reset.
    pub fn bare(reason: String) -> Self {
        Self { code: None, code_space: None, tls_alert: None, reason }
    }

    /// Recover the alert from a **transport-space** code, if it carries one.
    ///
    /// `0x0100 | alert` is the mapping TLS-over-QUIC defines, so the range is
    /// exactly one byte wide and the low byte is the alert. Applying this to an
    /// application-space code is a bug — see [`CodeSpace`].
    pub fn alert_of(code: u64) -> Option<u8> {
        (0x0100..=0x01ff).contains(&code).then_some((code & 0xff) as u8)
    }
}

impl std::fmt::Display for HandshakeFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

/// Errors from the transport layer.
///
/// `#[non_exhaustive]` so that a new failure mode is an additive change. The
/// crate matches on these internally, where the attribute does not apply;
/// downstream code that matches needs a `_` arm, which is the trade being made
/// deliberately.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransportError {
    /// Connection-level error (e.g., peer closed, timeout).
    #[error("connection error: {0}")]
    Connection(String),
    /// Error writing to a stream.
    #[error("write error: {0}")]
    Write(String),
    /// Error reading from a stream.
    #[error("read error: {0}")]
    Read(String),
    /// Stream was closed.
    #[error("stream closed")]
    StreamClosed,
    /// Error sending a datagram.
    #[error("send datagram error: {0}")]
    SendDatagram(String),
    /// Connection was lost.
    #[error("connection lost")]
    ConnectionLost,
    /// Error during connection establishment.
    #[error("connect error: {0}")]
    Connect(String),
    /// A handshake reached the peer and did not complete, with its codes kept.
    ///
    /// Distinct from [`Connect`](Self::Connect), which is the same class of
    /// event before there was anything numeric to keep — building the endpoint,
    /// binding the socket, resolving a name. Both render the same way, so this
    /// is additive to anything reading the message.
    #[error("connect error: {0}")]
    Handshake(HandshakeFailure),
    /// The peer abandoned transmission by resetting the stream. Carries
    /// the peer's application error code so a forwarder can mirror it
    /// verbatim with [`SendStream::reset`].
    #[error("stream reset by peer: code {0}")]
    StreamReset(u64),
    /// The peer is no longer accepting data on this stream
    /// (`STOP_SENDING`). Carries the peer's application error code so a
    /// forwarder can mirror it verbatim with [`RecvStream::stop`].
    #[error("stream stopped by peer: code {0}")]
    Stopped(u64),
    /// The peer closed the whole session, with the code it named.
    ///
    /// Distinct from [`StreamReset`](Self::StreamReset), which ends one stream
    /// and leaves the session alive. Over MoQT this code is a draft's own
    /// session error — `VERSION_NEGOTIATION_FAILED`, `PROTOCOL_VIOLATION` — and
    /// it is the sharpest thing a refusal says.
    ///
    /// It exists because quinn renders `ReadError::ConnectionLost` as the bare
    /// words "connection lost" and drops the cause entirely, so without this
    /// variant a relay that ends a session with a code *and* a reason phrase
    /// reaches callers as neither. The code is on the value and also in the
    /// message, spelled the way every other code this crate reports is spelled.
    #[error("{reason} (code {code})")]
    SessionClosed {
        /// The peer's application close code.
        code: u64,
        /// quinn's own rendering of the close, which is the peer's reason
        /// phrase where it sent one and the code where it did not.
        reason: String,
    },
}

/// A transport-agnostic connection (QUIC or WebTransport).
pub enum Transport {
    /// Raw QUIC via quinn.
    Quic(quic::QuicTransport),
    /// WebTransport via h3 + h3-quinn.
    #[cfg(feature = "webtransport")]
    WebTransport(webtransport::WebTransportTransport),
}

impl Transport {
    /// Open a bidirectional stream.
    pub async fn open_bi(&self) -> Result<(SendStream, RecvStream), TransportError> {
        match self {
            Transport::Quic(t) => t.open_bi().await,
            #[cfg(feature = "webtransport")]
            Transport::WebTransport(t) => t.open_bi().await,
        }
    }

    /// Accept an incoming bidirectional stream.
    pub async fn accept_bi(&self) -> Result<(SendStream, RecvStream), TransportError> {
        match self {
            Transport::Quic(t) => t.accept_bi().await,
            #[cfg(feature = "webtransport")]
            Transport::WebTransport(t) => t.accept_bi().await,
        }
    }

    /// Open a unidirectional send stream.
    pub async fn open_uni(&self) -> Result<SendStream, TransportError> {
        match self {
            Transport::Quic(t) => t.open_uni().await,
            #[cfg(feature = "webtransport")]
            Transport::WebTransport(t) => t.open_uni().await,
        }
    }

    /// Accept an incoming unidirectional stream.
    pub async fn accept_uni(&self) -> Result<RecvStream, TransportError> {
        match self {
            Transport::Quic(t) => t.accept_uni().await,
            #[cfg(feature = "webtransport")]
            Transport::WebTransport(t) => t.accept_uni().await,
        }
    }

    /// Send a datagram.
    pub fn send_datagram(&self, data: Bytes) -> Result<(), TransportError> {
        match self {
            Transport::Quic(t) => t.send_datagram(data),
            #[cfg(feature = "webtransport")]
            Transport::WebTransport(t) => t.send_datagram(data),
        }
    }

    /// Receive a datagram.
    pub async fn recv_datagram(&self) -> Result<Bytes, TransportError> {
        match self {
            Transport::Quic(t) => t.recv_datagram().await,
            #[cfg(feature = "webtransport")]
            Transport::WebTransport(t) => t.recv_datagram().await,
        }
    }

    /// Close the connection.
    pub fn close(&self, code: u32, reason: &[u8]) {
        match self {
            Transport::Quic(t) => t.close(code, reason),
            #[cfg(feature = "webtransport")]
            Transport::WebTransport(t) => t.close(code, reason),
        }
    }

    /// A future resolving when the session ends, carrying the peer's close.
    ///
    /// Borrows nothing and outlives this transport, so a caller can take it
    /// *before* handing the transport to a handshake and still be holding it
    /// when the peer's answer lands. That ordering is the whole point: a peer
    /// refusing a setup often finishes the control stream first and closes the
    /// session a round trip later, by which time the handshake has already
    /// returned end-of-stream and dropped everything it had.
    ///
    /// `None` over WebTransport. The session close there is `wtransport`'s and
    /// its code is in a private field with no accessor — the first of the
    /// README's known gaps, not a decision made here.
    pub fn closed(&self) -> Option<impl Future<Output = TransportError> + Send + 'static> {
        match self {
            Transport::Quic(t) => Some(t.closed()),
            #[cfg(feature = "webtransport")]
            Transport::WebTransport(_) => None,
        }
    }

    /// The certificate chain the peer presented, DER-encoded, leaf first.
    ///
    /// Empty when there is none to report — the handshake has not completed,
    /// the peer sent no chain — rather than an error, because none of those
    /// are failures of this connection.
    ///
    /// **This is the whole of the certificate API, and that is deliberate.**
    /// The bytes are handed over exactly as the peer sent them and nothing
    /// here parses them, dates them, or decides whether they are trustworthy.
    /// A certificate verdict is a judgement about what the caller is trying to
    /// establish: a probe grading a public relay wants to know whether the
    /// chain reaches a public root, an operator running against their own CA
    /// wants precisely the opposite answer to count as healthy, and a library
    /// that picked one would be silently wrong for the other. Whoever knows
    /// the question owns the answer; this owns the evidence.
    ///
    /// One consequence worth naming, because it is the finding this exists to
    /// make visible: the *length* of what comes back is itself a measurement.
    /// A relay that serves a leaf and no intermediate hands back a chain of
    /// one, which a client validating against a fixed root set rejects while a
    /// browser holding a cached intermediate connects to it happily. That is a
    /// misconfiguration and not a mystery — but only to a caller that can see
    /// how many certificates arrived, which is why the chain is returned whole
    /// rather than as a leaf.
    ///
    /// Read off the live connection each time — nothing is cached — so a
    /// caller that intends to keep the chain must take it while it still holds
    /// the `Transport`. Closing does not by itself erase the answer (quinn
    /// keeps the crypto session for the handle's lifetime), but dropping the
    /// handle does, and a caller that closes by value has done both.
    pub fn peer_certificates(&self) -> Vec<Vec<u8>> {
        match self {
            Transport::Quic(t) => t.peer_certificates(),
            #[cfg(feature = "webtransport")]
            Transport::WebTransport(t) => t.peer_certificates(),
        }
    }

    /// The application protocol the server selected in the CONNECT response.
    ///
    /// `None` over QUIC, where the equivalent answer is the ALPN and
    /// [`dial_quic_to`] already returns it. Over WebTransport this is
    /// `WT-Protocol`, which from draft-15 on is where MOQT settles its version
    /// on that transport. See
    /// [`WebTransportTransport::wt_protocol`](webtransport::WebTransportTransport::wt_protocol)
    /// for how the value is read, and why an unquoted one is still read.
    #[cfg(feature = "wt-protocol")]
    pub fn wt_protocol(&self) -> Option<String> {
        match self {
            Transport::Quic(_) => None,
            Transport::WebTransport(t) => t.wt_protocol(),
        }
    }
}

/// A transport-agnostic send stream.
pub enum SendStream {
    /// Raw QUIC send stream.
    Quic(quinn::SendStream),
    /// WebTransport send stream.
    #[cfg(feature = "webtransport")]
    WebTransport(webtransport::WtSendStream),
}

impl SendStream {
    /// Get the QUIC stream ID (transport-level identifier).
    pub fn stream_id(&self) -> u64 {
        match self {
            SendStream::Quic(s) => s.id().index(),
            #[cfg(feature = "webtransport")]
            SendStream::WebTransport(_) => 0, // WebTransport doesn't expose stream IDs
        }
    }

    /// Write all bytes to the stream.
    ///
    /// Fails with [`TransportError::Stopped`] carrying the peer's
    /// application error code if the peer sent `STOP_SENDING`.
    pub async fn write_all(&mut self, buf: &[u8]) -> Result<(), TransportError> {
        match self {
            SendStream::Quic(s) => s.write_all(buf).await.map_err(TransportError::from),
            #[cfg(feature = "webtransport")]
            SendStream::WebTransport(s) => s.write_all(buf).await,
        }
    }

    /// Finish the stream (send FIN).
    pub fn finish(&mut self) -> Result<(), TransportError> {
        match self {
            SendStream::Quic(s) => {
                s.finish().map_err(|_| TransportError::StreamClosed)?;
                Ok(())
            }
            #[cfg(feature = "webtransport")]
            SendStream::WebTransport(s) => s.finish(),
        }
    }

    /// Reset the stream, telling the peer transmission was abandoned and
    /// handing it `code` as the `RESET_STREAM` application error code.
    ///
    /// This is the only way to abandon a send stream truthfully: simply
    /// dropping a `SendStream` sends a FIN instead, which tells the peer
    /// the stream ended *cleanly*. A forwarder that saw the far side
    /// reset must call this with the code it received, so a truncated
    /// stream is never laundered into a complete one.
    ///
    /// # Errors
    /// - [`TransportError::StreamClosed`] if the stream was already finished or
    ///   reset.
    /// - [`TransportError::Write`] if `code` is outside the QUIC varint range
    ///   (`0..2^62`). Nothing is sent in that case and the stream stays usable.
    pub fn reset(&mut self, code: u64) -> Result<(), TransportError> {
        match self {
            SendStream::Quic(s) => {
                let code = varint_code(code)?;
                s.reset(code).map_err(|_| TransportError::StreamClosed)
            }
            #[cfg(feature = "webtransport")]
            SendStream::WebTransport(s) => s.reset(code),
        }
    }

    /// Set the stream's send priority.
    ///
    /// Streams with a higher priority have their locally buffered data
    /// transmitted first. Every stream starts at priority 0.
    ///
    /// # Errors
    /// [`TransportError::StreamClosed`] once the stream's send state has been
    /// discarded — but only on the QUIC arm, and quinn keeps that state around
    /// for a while after a `finish` or `reset`, so this is not a reliable *is
    /// the stream still live?* probe. The WebTransport arm never reports it at
    /// all: `wtransport` discards the underlying error and always succeeds. Do
    /// not treat `Ok(())` as proof the priority took effect.
    pub fn set_priority(&self, priority: i32) -> Result<(), TransportError> {
        match self {
            SendStream::Quic(s) => {
                s.set_priority(priority).map_err(|_| TransportError::StreamClosed)
            }
            #[cfg(feature = "webtransport")]
            SendStream::WebTransport(s) => s.set_priority(priority),
        }
    }

    /// Resolve when this send half stops being useful.
    ///
    /// [`write_all`](Self::write_all) only reports `STOP_SENDING` when
    /// there is something to write, so a forwarder that has gone idle —
    /// the normal state of a stream waiting on its source — never learns
    /// that the peer walked away. This is the watcher for that case: it
    /// borrows nothing, so it can sit in a `select!` beside the read
    /// branch for the stream's whole life.
    /// The four outcomes, all measured against quinn 0.11.9:
    ///
    /// - The peer sent `STOP_SENDING` → [`TransportError::Stopped`] carrying
    ///   the peer's application error code, the same typed value a failed
    ///   [`write_all`](Self::write_all) produces, so a forwarder can mirror it
    ///   verbatim with no new match arm.
    /// - The stream was finished and the peer acked every byte → `Ok(())`.
    ///   quinn cannot tell that apart from *the send state was discarded*, so
    ///   `Ok(())` means *this stream is over*, never *the peer is happy*. It
    ///   cannot fire on a live stream.
    /// - The connection was lost → [`TransportError::Connection`].
    /// - **The local side reset the stream → this future never resolves.**
    ///   quinn keeps no stopped-notification for a stream it has locally reset,
    ///   so a watcher held across a [`reset`](Self::reset) stays pending until
    ///   the connection ends and holds a `tokio::sync::Notify` alive for that
    ///   long. Retire the future *before* resetting.
    ///
    /// The returned future is `'static`: it holds a handle on the
    /// connection, not on `self`, so it may outlive this `SendStream`
    /// and be spawned or stored on its own.
    ///
    /// # WebTransport arm
    ///
    /// Reaches the same quinn future through
    /// `webtransport::WtSendStream::quic_stream` — spelled as code and not
    /// as an intra-doc link because the `webtransport` module is behind its
    /// own feature, so a link to it is broken in the default build and
    /// `just doc-check` runs `cargo doc --workspace --no-deps` without it.
    /// This bypasses `wtransport`'s own `stopped`, which collapses stopped /
    /// closed / disconnected into one error. One asymmetry the QUIC arm
    /// does not have: [`finish`](Self::finish) moves the inner
    /// `wtransport` stream out, so calling this afterwards yields a
    /// future that resolves immediately to
    /// [`TransportError::StreamClosed`] — the "finished and acked" case
    /// is unobservable there. Not yet exercised against a live
    /// WebTransport session.
    pub fn stopped(&self) -> impl Future<Output = Result<(), TransportError>> + Send + 'static {
        // Resolve the arm eagerly so the returned future borrows nothing
        // and both arms hand back the *same* quinn future type.
        let watched: Result<_, TransportError> = match self {
            SendStream::Quic(s) => Ok(s.stopped()),
            #[cfg(feature = "webtransport")]
            SendStream::WebTransport(s) => s.quic_stream().map(|q| q.stopped()),
        };
        async move { stopped_outcome(watched?.await) }
    }
}

/// Map quinn's `stopped()` result onto [`TransportError`].
///
/// `Ok(None)` is quinn's *the send state is gone*, which it reports both for a
/// finished-and-acked stream and for one whose state it discarded; neither is
/// an error, so both become `Ok(())`.
fn stopped_outcome(
    outcome: Result<Option<quinn::VarInt>, quinn::StoppedError>,
) -> Result<(), TransportError> {
    match outcome {
        Ok(Some(code)) => Err(TransportError::Stopped(code.into_inner())),
        Ok(None) => Ok(()),
        Err(e) => Err(TransportError::Connection(e.to_string())),
    }
}

/// Convert an application error code to a quinn `VarInt`.
///
/// QUIC application error codes are varints, so values above
/// 2^62 - 1 cannot be represented on the wire.
fn varint_code(code: u64) -> Result<quinn::VarInt, TransportError> {
    quinn::VarInt::from_u64(code)
        .map_err(|_| TransportError::Write(format!("error code {code} exceeds the varint range")))
}

/// A transport-agnostic receive stream.
pub enum RecvStream {
    /// Raw QUIC receive stream.
    Quic(quinn::RecvStream),
    /// WebTransport receive stream.
    #[cfg(feature = "webtransport")]
    WebTransport(webtransport::WtRecvStream),
}

impl RecvStream {
    /// Get the QUIC stream ID (transport-level identifier).
    pub fn stream_id(&self) -> u64 {
        match self {
            RecvStream::Quic(s) => s.id().index(),
            #[cfg(feature = "webtransport")]
            RecvStream::WebTransport(_) => 0,
        }
    }

    /// Read data into the buffer. Returns `Ok(Some(n))` with bytes read,
    /// `Ok(None)` on stream end, or `Err` on failure.
    ///
    /// Fails with [`TransportError::StreamReset`] carrying the peer's
    /// application error code if the peer reset the stream, which is how
    /// callers distinguish an abandoned stream from a clean FIN
    /// (`Ok(None)`).
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, TransportError> {
        match self {
            RecvStream::Quic(s) => s.read(buf).await.map_err(TransportError::from),
            #[cfg(feature = "webtransport")]
            RecvStream::WebTransport(s) => s.read(buf).await,
        }
    }

    /// Wait for the peer to reset this stream — **without reading a byte**.
    ///
    /// [`read`](Self::read) is the only other way to learn that a peer sent
    /// `RESET_STREAM`, and it is unusable by a reader that has stopped
    /// consuming on purpose: a forwarder applying backpressure holds its
    /// source unread, so the reset surfaces on a call it is deliberately
    /// not making, and the abandonment goes unobserved for as long as the
    /// backpressure lasts. This observes the same event on its own.
    ///
    /// **It consumes nothing.** No bytes leave the receive buffer, so no
    /// `MAX_STREAM_DATA` credit is granted and the peer stays flow-control
    /// blocked exactly as it was. That is the whole point: it is safe to
    /// poll *while* backpressure is being applied, which
    /// [`read`](Self::read) is not.
    ///
    /// Cancel-safe: it registers interest and consumes no state, so
    /// dropping the future loses nothing.
    ///
    /// # Returns
    /// - `Ok(Some(code))` — the peer reset the stream with this application
    ///   error code. The same code [`TransportError::StreamReset`] would have
    ///   carried out of [`read`](Self::read).
    /// - `Ok(None)` — **no reset is observable on this stream, now or ever**,
    ///   and the caller must stop asking: this resolves immediately every time,
    ///   so a caller that re-polls it in a loop spins. Either the transport
    ///   freed the stream's state (it was finished and fully read, or stopped)
    ///   or, on the WebTransport arm, `wtransport` exposes no reset-only
    ///   observable at all and this answers `Ok(None)` unconditionally.
    /// - `Err` — a connection-level failure.
    pub async fn received_reset(&mut self) -> Result<Option<u64>, TransportError> {
        match self {
            RecvStream::Quic(s) => match s.received_reset().await {
                Ok(code) => Ok(code.map(|c| c.into_inner())),
                Err(e) => Err(TransportError::Connection(e.to_string())),
            },
            // `wtransport::RecvStream` has no reset-only observable, so a
            // WebTransport forwarder keeps the pre-existing behaviour: a
            // peer reset is seen on the next `read` and not before.
            #[cfg(feature = "webtransport")]
            RecvStream::WebTransport(_) => Ok(None),
        }
    }

    /// Stop accepting data on the stream, discarding anything unread and
    /// telling the peer to stop transmitting with `code` as the
    /// `STOP_SENDING` application error code.
    ///
    /// Dropping a `RecvStream` also stops it, but with a hard-coded code
    /// of 0 — so a forwarder mirroring a peer's `STOP_SENDING` must call
    /// this explicitly to keep the original code intact.
    ///
    /// After a successful call the stream is no longer readable, and the
    /// two arms say so differently: the QUIC arm's [`read`](Self::read)
    /// returns [`TransportError::Read`], the WebTransport arm's returns
    /// [`TransportError::StreamClosed`] (the inner stream is consumed,
    /// because `wtransport::RecvStream::stop` takes `self` by value).
    /// Stop reading once you have stopped a stream rather than matching
    /// on which error comes back.
    ///
    /// # Errors
    /// - [`TransportError::StreamClosed`] if the stream was already stopped,
    ///   finished or reset.
    /// - [`TransportError::Write`] if `code` is outside the QUIC varint range
    ///   (`0..2^62`) — `Write` because what failed is the `STOP_SENDING` frame
    ///   this endpoint would have sent. Nothing is sent in that case and the
    ///   stream stays readable.
    pub fn stop(&mut self, code: u64) -> Result<(), TransportError> {
        match self {
            RecvStream::Quic(s) => {
                let code = varint_code(code)?;
                s.stop(code).map_err(|_| TransportError::StreamClosed)
            }
            #[cfg(feature = "webtransport")]
            RecvStream::WebTransport(s) => s.stop(code),
        }
    }
}

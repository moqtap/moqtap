//! Transport abstraction for QUIC and WebTransport.
//!
//! Uses enum dispatch (not trait objects) since the transport set is closed.
//! WebTransport support is behind the `webtransport` feature flag. Nothing
//! here is per-draft; every draft's connection is carried over the same two.

pub mod quic;
#[cfg(feature = "webtransport")]
pub mod webtransport;

pub use quic::{dial_quic, DialError, QuicDialOptions};

use std::future::Future;

use bytes::Bytes;

/// Errors from the transport layer.
#[derive(Debug, thiserror::Error)]
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

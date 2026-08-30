//! WebTransport transport implementation wrapping `wtransport`.

use bytes::Bytes;

use super::{RecvStream, SendStream, TransportError};

/// WebTransport send stream wrapping `wtransport::SendStream`.
pub struct WtSendStream(Option<wtransport::SendStream>);

impl WtSendStream {
    /// Write all bytes to the stream.
    pub async fn write_all(&mut self, buf: &[u8]) -> Result<(), TransportError> {
        self.0.as_mut().ok_or(TransportError::StreamClosed)?.write_all(buf).await.map_err(write_err)
    }

    /// Finish the stream (send FIN).
    ///
    /// Takes ownership of the inner stream and spawns an async task
    /// to complete the finish handshake, since `wtransport` 0.7's
    /// `finish()` is async but our trait is sync.
    pub fn finish(&mut self) -> Result<(), TransportError> {
        if let Some(mut stream) = self.0.take() {
            tokio::spawn(async move {
                let _ = stream.finish().await;
            });
        }
        Ok(())
    }

    /// Reset the stream with `code` as the application error code.
    ///
    /// Returns [`TransportError::StreamClosed`] if the stream was
    /// already finished or reset.
    pub fn reset(&mut self, code: u64) -> Result<(), TransportError> {
        self.0
            .as_mut()
            .ok_or(TransportError::StreamClosed)?
            .reset(varint_code(code)?)
            .map_err(|_| TransportError::StreamClosed)
    }

    /// Borrow the underlying quinn send stream.
    ///
    /// `wtransport`'s own `SendStream::stopped` collapses stopped,
    /// closed and disconnected into a single `StreamWriteError`, which
    /// loses the distinction [`SendStream::stopped`] exists to keep. The
    /// `quinn` feature — enabled for `wtransport` workspace-wide — hands
    /// back the real `quinn::SendStream` instead, so the WebTransport
    /// arm can await exactly the same future the QUIC arm does.
    ///
    /// # Errors
    ///
    /// [`TransportError::StreamClosed`] once [`WtSendStream::finish`]
    /// has moved the inner stream out. The QUIC arm has no such gap:
    /// there the stream survives its own `finish`.
    ///
    /// [`SendStream::stopped`]: super::SendStream::stopped
    pub fn quic_stream(&self) -> Result<&quinn::SendStream, TransportError> {
        Ok(self.0.as_ref().ok_or(TransportError::StreamClosed)?.quic_stream())
    }

    /// Set the stream's send priority.
    ///
    /// Only fails when this wrapper has already released the inner
    /// stream. `wtransport::SendStream::set_priority` returns `()` and
    /// discards quinn's `ClosedStream`, so this arm can never report
    /// that the priority failed to apply — unlike the QUIC arm, which
    /// at least surfaces [`TransportError::StreamClosed`] once quinn has
    /// discarded the stream's send state.
    pub fn set_priority(&self, priority: i32) -> Result<(), TransportError> {
        self.0.as_ref().ok_or(TransportError::StreamClosed)?.set_priority(priority);
        Ok(())
    }
}

/// WebTransport receive stream wrapping `wtransport::RecvStream`.
///
/// The inner stream is held in an `Option` because
/// `wtransport::RecvStream::stop` consumes `self` by value, so
/// [`WtRecvStream::stop`] must be able to move it out from behind a
/// `&mut self`. A `None` inner means the stream was already stopped.
pub struct WtRecvStream(Option<wtransport::RecvStream>);

impl WtRecvStream {
    /// Read data into the buffer. Returns `Ok(Some(n))` with bytes read,
    /// `Ok(None)` on stream end, or `Err` on failure.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, TransportError> {
        self.0.as_mut().ok_or(TransportError::StreamClosed)?.read(buf).await.map_err(read_err)
    }

    /// Stop the stream with `code` as the application error code.
    ///
    /// Subsequent calls return [`TransportError::StreamClosed`], since
    /// the inner stream is consumed by the first one.
    pub fn stop(&mut self, code: u64) -> Result<(), TransportError> {
        // Validate the code before taking the stream, so an out-of-range
        // code leaves the stream usable.
        let code = varint_code(code)?;
        self.0.take().ok_or(TransportError::StreamClosed)?.stop(code);
        Ok(())
    }
}

/// Convert an application error code to a `wtransport::VarInt`.
fn varint_code(code: u64) -> Result<wtransport::VarInt, TransportError> {
    wtransport::VarInt::try_from_u64(code)
        .map_err(|_| TransportError::Write(format!("error code {code} exceeds the varint range")))
}

/// Map a `wtransport` read error, keeping the peer's reset code typed.
fn read_err(e: wtransport::error::StreamReadError) -> TransportError {
    match e {
        wtransport::error::StreamReadError::Reset(code) => {
            TransportError::StreamReset(code.into_inner())
        }
        other => TransportError::Read(other.to_string()),
    }
}

/// Map a `wtransport` write error, keeping the peer's stop code typed.
fn write_err(e: wtransport::error::StreamWriteError) -> TransportError {
    match e {
        wtransport::error::StreamWriteError::Stopped(code) => {
            TransportError::Stopped(code.into_inner())
        }
        other => TransportError::Write(other.to_string()),
    }
}

/// WebTransport transport wrapping a `wtransport::Connection`.
pub struct WebTransportTransport(wtransport::Connection);

impl WebTransportTransport {
    /// Create a new WebTransport transport from an established connection.
    pub fn new(conn: wtransport::Connection) -> Self {
        Self(conn)
    }

    /// Open a bidirectional stream.
    pub async fn open_bi(&self) -> Result<(SendStream, RecvStream), TransportError> {
        let opening =
            self.0.open_bi().await.map_err(|e| TransportError::Connection(e.to_string()))?;
        let (send, recv) = opening.await.map_err(|e| TransportError::Connection(e.to_string()))?;
        Ok((
            SendStream::WebTransport(WtSendStream(Some(send))),
            RecvStream::WebTransport(WtRecvStream(Some(recv))),
        ))
    }

    /// Accept an incoming bidirectional stream.
    pub async fn accept_bi(&self) -> Result<(SendStream, RecvStream), TransportError> {
        let (send, recv) =
            self.0.accept_bi().await.map_err(|e| TransportError::Connection(e.to_string()))?;
        Ok((
            SendStream::WebTransport(WtSendStream(Some(send))),
            RecvStream::WebTransport(WtRecvStream(Some(recv))),
        ))
    }

    /// Open a unidirectional send stream.
    pub async fn open_uni(&self) -> Result<SendStream, TransportError> {
        let opening =
            self.0.open_uni().await.map_err(|e| TransportError::Connection(e.to_string()))?;
        let send = opening.await.map_err(|e| TransportError::Connection(e.to_string()))?;
        Ok(SendStream::WebTransport(WtSendStream(Some(send))))
    }

    /// Accept an incoming unidirectional stream.
    pub async fn accept_uni(&self) -> Result<RecvStream, TransportError> {
        let recv =
            self.0.accept_uni().await.map_err(|e| TransportError::Connection(e.to_string()))?;
        Ok(RecvStream::WebTransport(WtRecvStream(Some(recv))))
    }

    /// Send a datagram.
    pub fn send_datagram(&self, data: Bytes) -> Result<(), TransportError> {
        self.0.send_datagram(data).map_err(|e| TransportError::SendDatagram(e.to_string()))
    }

    /// Receive a datagram.
    pub async fn recv_datagram(&self) -> Result<Bytes, TransportError> {
        let datagram = self
            .0
            .receive_datagram()
            .await
            .map_err(|e| TransportError::Connection(e.to_string()))?;
        Ok(datagram.payload())
    }

    /// Close the connection.
    pub fn close(&self, code: u32, reason: &[u8]) {
        self.0.close(wtransport::VarInt::from_u32(code), reason);
    }

    /// Get the remote address of the peer.
    pub fn remote_address(&self) -> std::net::SocketAddr {
        self.0.remote_address()
    }
}

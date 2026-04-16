//! WebTransport transport implementation wrapping `wtransport`.

use bytes::Bytes;

use super::{RecvStream, SendStream, TransportError};

/// WebTransport send stream wrapping `wtransport::SendStream`.
pub struct WtSendStream(Option<wtransport::SendStream>);

impl WtSendStream {
    /// Write all bytes to the stream.
    pub async fn write_all(&mut self, buf: &[u8]) -> Result<(), TransportError> {
        self.0
            .as_mut()
            .ok_or(TransportError::StreamClosed)?
            .write_all(buf)
            .await
            .map_err(|e| TransportError::Write(e.to_string()))
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
}

/// WebTransport receive stream wrapping `wtransport::RecvStream`.
pub struct WtRecvStream(wtransport::RecvStream);

impl WtRecvStream {
    /// Read data into the buffer. Returns `Ok(Some(n))` with bytes read,
    /// `Ok(None)` on stream end, or `Err` on failure.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, TransportError> {
        match self.0.read(buf).await {
            Ok(Some(n)) => Ok(Some(n)),
            Ok(None) => Ok(None),
            Err(e) => Err(TransportError::Read(e.to_string())),
        }
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
            RecvStream::WebTransport(WtRecvStream(recv)),
        ))
    }

    /// Accept an incoming bidirectional stream.
    pub async fn accept_bi(&self) -> Result<(SendStream, RecvStream), TransportError> {
        let (send, recv) =
            self.0.accept_bi().await.map_err(|e| TransportError::Connection(e.to_string()))?;
        Ok((
            SendStream::WebTransport(WtSendStream(Some(send))),
            RecvStream::WebTransport(WtRecvStream(recv)),
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
        Ok(RecvStream::WebTransport(WtRecvStream(recv)))
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

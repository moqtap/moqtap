//! QUIC transport implementation wrapping quinn.

use bytes::Bytes;

use super::{RecvStream, SendStream, TransportError};

/// QUIC transport wrapping a `quinn::Connection`.
pub struct QuicTransport {
    conn: quinn::Connection,
}

impl QuicTransport {
    /// Create a new QUIC transport from a quinn connection.
    pub fn new(conn: quinn::Connection) -> Self {
        Self { conn }
    }

    /// Open a bidirectional stream.
    pub async fn open_bi(&self) -> Result<(SendStream, RecvStream), TransportError> {
        let (send, recv) = self.conn.open_bi().await.map_err(conn_err)?;
        Ok((SendStream::Quic(send), RecvStream::Quic(recv)))
    }

    /// Accept an incoming bidirectional stream.
    pub async fn accept_bi(&self) -> Result<(SendStream, RecvStream), TransportError> {
        let (send, recv) = self.conn.accept_bi().await.map_err(conn_err)?;
        Ok((SendStream::Quic(send), RecvStream::Quic(recv)))
    }

    /// Open a unidirectional send stream.
    pub async fn open_uni(&self) -> Result<SendStream, TransportError> {
        let send = self.conn.open_uni().await.map_err(conn_err)?;
        Ok(SendStream::Quic(send))
    }

    /// Accept an incoming unidirectional stream.
    pub async fn accept_uni(&self) -> Result<RecvStream, TransportError> {
        let recv = self.conn.accept_uni().await.map_err(conn_err)?;
        Ok(RecvStream::Quic(recv))
    }

    /// Send a datagram.
    pub fn send_datagram(&self, data: Bytes) -> Result<(), TransportError> {
        self.conn.send_datagram(data).map_err(|e| TransportError::SendDatagram(e.to_string()))
    }

    /// Receive a datagram.
    pub async fn recv_datagram(&self) -> Result<Bytes, TransportError> {
        self.conn.read_datagram().await.map_err(conn_err)
    }

    /// Close the connection.
    pub fn close(&self, code: u32, reason: &[u8]) {
        self.conn.close(quinn::VarInt::from_u32(code), reason);
    }
}

/// Convert a quinn connection error to a TransportError.
fn conn_err(e: quinn::ConnectionError) -> TransportError {
    TransportError::Connection(e.to_string())
}

// ── From impls for quinn error types ────────────────────────

impl From<quinn::ConnectionError> for TransportError {
    fn from(e: quinn::ConnectionError) -> Self {
        TransportError::Connection(e.to_string())
    }
}

impl From<quinn::WriteError> for TransportError {
    fn from(e: quinn::WriteError) -> Self {
        TransportError::Write(e.to_string())
    }
}

impl From<quinn::ReadExactError> for TransportError {
    fn from(e: quinn::ReadExactError) -> Self {
        TransportError::Read(e.to_string())
    }
}

impl From<quinn::ConnectError> for TransportError {
    fn from(e: quinn::ConnectError) -> Self {
        TransportError::Connect(e.to_string())
    }
}

impl From<quinn::ClosedStream> for TransportError {
    fn from(_e: quinn::ClosedStream) -> Self {
        TransportError::StreamClosed
    }
}

impl From<quinn::SendDatagramError> for TransportError {
    fn from(e: quinn::SendDatagramError) -> Self {
        TransportError::SendDatagram(e.to_string())
    }
}

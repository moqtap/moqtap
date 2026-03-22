//! Transport abstraction for QUIC and WebTransport.
//!
//! Uses enum dispatch (not trait objects) since the transport set is closed.
//! WebTransport support is behind the `webtransport` feature flag.

pub mod quic;
#[cfg(feature = "webtransport")]
pub mod webtransport;

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
    /// Write all bytes to the stream.
    pub async fn write_all(&mut self, buf: &[u8]) -> Result<(), TransportError> {
        match self {
            SendStream::Quic(s) => {
                s.write_all(buf).await.map_err(|e| TransportError::Write(e.to_string()))
            }
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
    /// Read data into the buffer. Returns `Ok(Some(n))` with bytes read,
    /// `Ok(None)` on stream end, or `Err` on failure.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, TransportError> {
        match self {
            RecvStream::Quic(s) => {
                s.read(buf).await.map_err(|e| TransportError::Read(e.to_string()))
            }
            #[cfg(feature = "webtransport")]
            RecvStream::WebTransport(s) => s.read(buf).await,
        }
    }
}

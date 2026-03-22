//! Client event types emitted by a MoQT connection.

use moqtap_codec::dispatch::AnyControlMessage;

/// Direction of a message or stream relative to this endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Sent (outgoing).
    Send,
    /// Received (incoming).
    Receive,
}

/// Data stream type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    /// Subgroup data stream.
    Subgroup,
    /// Fetch data stream.
    Fetch,
    /// Datagram.
    Datagram,
}

/// Events emitted by a MoQT connection.
#[derive(Debug, Clone)]
pub enum ClientEvent {
    /// MoQT setup handshake completed.
    SetupComplete {
        /// The negotiated MoQT version.
        negotiated_version: u64,
    },

    /// A control message was sent or received.
    ControlMessage {
        /// Whether the message was sent or received.
        direction: Direction,
        /// The decoded control message.
        message: AnyControlMessage,
    },

    /// A data stream was opened.
    StreamOpened {
        /// Whether we opened (Send) or accepted (Receive) the stream.
        direction: Direction,
        /// The type of data stream.
        stream_kind: StreamKind,
    },

    /// A data stream was closed.
    StreamClosed {
        /// Error code (0 = clean close).
        error_code: u64,
    },

    /// Session entered draining state (GOAWAY received).
    Draining {
        /// The new session URI from the GOAWAY message.
        new_session_uri: Vec<u8>,
    },

    /// Connection was closed.
    Closed {
        /// Application error code.
        code: u32,
        /// Human-readable reason.
        reason: Vec<u8>,
    },

    /// A transport or protocol error occurred.
    Error {
        /// Error description.
        error: String,
    },
}

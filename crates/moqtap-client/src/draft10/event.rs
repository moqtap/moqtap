//! Client event types emitted by a draft-10 MoQT connection.

use moqtap_codec::dispatch::{
    AnyControlMessage, AnyDatagramHeader, AnyFetchHeader, AnySubgroupHeader,
};
use moqtap_codec::draft10::data_stream::{FetchObjectHeader, ObjectHeader};

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

/// A decoded subgroup object: the object header followed by its payload.
///
/// Draft-07 subgroup objects are stateless (no delta encoding, no extension
/// headers), so each object can be decoded independently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubgroupObject {
    /// The parsed object header.
    pub header: ObjectHeader,
    /// The object payload (empty when `header.payload_length == 0`).
    pub payload: Vec<u8>,
}

/// A decoded fetch stream object: the object header followed by its payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchObject {
    /// The parsed fetch object header.
    pub header: FetchObjectHeader,
    /// The object payload (empty when `header.payload_length == 0`).
    pub payload: Vec<u8>,
}

/// Events emitted by a draft-10 MoQT connection.
///
/// This enum is `#[non_exhaustive]` — new variants may be added in minor
/// releases. Downstream `match` arms should include a wildcard `_ =>` branch.
#[non_exhaustive]
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
        /// The raw wire bytes of the framed message (type + length + payload).
        /// `None` if raw capture is not available.
        raw: Option<Vec<u8>>,
    },

    /// A data stream was opened.
    StreamOpened {
        /// Whether we opened (Send) or accepted (Receive) the stream.
        direction: Direction,
        /// The type of data stream.
        stream_kind: StreamKind,
        /// Transport-level stream identifier.
        stream_id: u64,
    },

    /// A subgroup stream header was decoded after the stream opened.
    DataStreamHeader {
        /// Transport-level stream identifier.
        stream_id: u64,
        /// Whether we opened (Send) or accepted (Receive) the stream.
        direction: Direction,
        /// The parsed subgroup header.
        header: AnySubgroupHeader,
    },

    /// A fetch response stream header was decoded.
    FetchStreamHeader {
        /// Transport-level stream identifier.
        stream_id: u64,
        /// Whether we opened (Send) or accepted (Receive) the stream.
        direction: Direction,
        /// The parsed fetch header.
        header: AnyFetchHeader,
    },

    /// A subgroup object (header + payload) was decoded on a subgroup stream.
    SubgroupObjectReceived {
        /// Transport-level stream identifier.
        stream_id: u64,
        /// Direction (Send when emitted from a writer, Receive from a reader).
        direction: Direction,
        /// The decoded subgroup object.
        object: SubgroupObject,
    },

    /// A fetch object (self-contained) was decoded on a fetch stream.
    FetchObjectReceived {
        /// Transport-level stream identifier.
        stream_id: u64,
        /// Direction (Send when emitted from a writer, Receive from a reader).
        direction: Direction,
        /// The decoded fetch object.
        object: FetchObject,
    },

    /// A datagram was sent or received.
    DatagramReceived {
        /// Whether sent or received.
        direction: Direction,
        /// The parsed datagram header.
        header: AnyDatagramHeader,
        /// Size of the payload in bytes.
        payload_len: usize,
    },

    /// A data stream was closed.
    StreamClosed {
        /// Transport-level stream identifier.
        stream_id: u64,
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

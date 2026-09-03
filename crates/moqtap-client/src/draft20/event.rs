//! Client event types emitted by a MoQT connection.

use moqtap_codec::dispatch::{
    AnyControlMessage, AnyDatagramHeader, AnyFetchHeader, AnySubgroupHeader,
};
use moqtap_codec::draft20::data_stream::{FetchHeader, SubgroupHeader, SubgroupObject};
use moqtap_codec::kvp::KeyValuePair;

/// Direction of a message or stream relative to this endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Sent (outgoing).
    Send,
    /// Received (incoming).
    Receive,
}

/// The kind of stream an event refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    /// Subgroup data stream.
    Subgroup,
    /// Fetch data stream.
    Fetch,
    /// Fill fetch stream, new in draft-20 (Section 5.1.3).
    ///
    /// Framed exactly as a fetch stream — a FETCH_HEADER and the fetch object
    /// records after it — and told apart from one only by what its Request ID
    /// names: a subscription that asked for a fill rather than a FETCH. It is
    /// a separate kind here because it belongs to a subscription's lifetime
    /// rather than to a request of its own, and because an observer that could
    /// not tell the two apart would count a subscription's fill as a fetch the
    /// application never made.
    Fill,
    /// Datagram.
    Datagram,
    /// Request stream: the bidirectional stream one request and its response
    /// travel on.
    ///
    /// Draft-20 Section 3.3 moved requests off the control plane and gave each
    /// one a bidirectional stream that begins with the request message. This
    /// is the only kind here that is not a data stream, and it is named
    /// because an observer that could not name it would see a request message
    /// with no stream to attach it to.
    Request,
}

/// Events emitted by a MoQT connection.
///
/// This enum is `#[non_exhaustive]` -- new variants may be added in minor
/// releases. Downstream `match` arms should include a wildcard `_ =>` branch.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum ClientEvent {
    /// MoQT setup handshake completed.
    SetupComplete {
        /// The negotiated MoQT version (from ALPN in draft-20).
        negotiated_version: u64,
    },

    /// A control message was sent or received.
    ControlMessage {
        /// Whether the message was sent or received.
        direction: Direction,
        /// The decoded control message.
        message: AnyControlMessage,
        /// The transport-level identifier of the stream the message travelled
        /// on when that stream is a request stream, and `None` when it is the
        /// control stream.
        ///
        /// Draft-20 responses carry no request id: the stream is the
        /// correlation. Without this an observer sees a SUBSCRIBE_OK with
        /// nothing to say which SUBSCRIBE it answers, and cannot tell a
        /// message on the control stream from one on a request stream.
        stream_id: Option<u64>,
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

    /// A data stream header was decoded after the stream opened.
    DataStreamHeader {
        /// Transport-level stream identifier.
        stream_id: u64,
        /// Whether we opened (Send) or accepted (Receive) the stream.
        direction: Direction,
        /// The parsed subgroup header.
        header: AnySubgroupHeader,
    },

    /// The publisher reported that a subscription's state changed, other than
    /// in answer to a REQUEST_UPDATE this endpoint sent.
    ///
    /// PUBLISH_STATE_NOTIFY, new in draft-20 (Section 10.10). Nothing is owed
    /// in reply — "it is a unilateral notification: the receiver does not
    /// respond with REQUEST_OK or REQUEST_ERROR, and the message is not subject
    /// to the MAX_REQUEST_UPDATES limit" — and "no action is required by the
    /// recipient". It is an event rather than a return value for that reason:
    /// there is nothing for a caller to do with it except notice.
    ///
    /// It also arrives as an ordinary [`ClientEvent::ControlMessage`], as every
    /// message does. This variant is the decoded form, so an observer does not
    /// have to reach through `AnyControlMessage` to find out which subscription
    /// changed.
    PublishStateNotify {
        /// The Request ID of the subscription whose state changed.
        ///
        /// The message itself carries no Request ID field: Section 10.10 makes
        /// the bidirectional stream the correlation, exactly as it is for
        /// SUBSCRIBE_OK, PUBLISH_DONE and FETCH_OK. This is the request that
        /// stream belongs to.
        request_id: u64,
        /// The transport-level identifier of that stream.
        stream_id: u64,
        /// The parameters whose values changed. A parameter that is absent is
        /// unchanged; the publisher "MUST include the LARGEST_OBJECT parameter"
        /// if known, so a receiver can place the change in the track.
        parameters: Vec<KeyValuePair>,
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

    /// A subgroup object header was decoded on a subgroup stream.
    SubgroupObjectReceived {
        /// Transport-level stream identifier.
        stream_id: u64,
        /// Direction (Send when emitted from a writer, Receive from a reader).
        direction: Direction,
        /// The decoded subgroup header (for context).
        subgroup_header: SubgroupHeader,
        /// The decoded subgroup object.
        object: SubgroupObject,
    },

    /// A fetch header was decoded on a fetch stream.
    FetchHeaderReceived {
        /// Transport-level stream identifier.
        stream_id: u64,
        /// Direction (Send when emitted from a writer, Receive from a reader).
        direction: Direction,
        /// The decoded fetch header.
        header: FetchHeader,
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

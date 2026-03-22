//! Proxy event types emitted by the inline parser.

use std::net::SocketAddr;

use moqtap_codec::dispatch::{
    AnyControlMessage, AnyDatagramHeader, AnyFetchHeader, AnyObjectHeader, AnySubgroupHeader,
};

/// Which side of the proxy a message originates from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxySide {
    /// Client → Proxy (downstream ingress).
    ClientToProxy,
    /// Proxy → Relay (upstream egress).
    ProxyToRelay,
    /// Relay → Proxy (upstream ingress).
    RelayToProxy,
    /// Proxy → Client (downstream egress).
    ProxyToClient,
}

/// Unique session identifier (monotonic counter assigned by the proxy).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(pub u64);

/// The kind of data stream header parsed from a unidirectional stream.
#[derive(Debug, Clone)]
pub enum DataStreamHeaderKind {
    /// Subgroup stream header.
    Subgroup(AnySubgroupHeader),
    /// Fetch response stream header.
    Fetch(AnyFetchHeader),
}

/// Events emitted by the proxy during stream forwarding.
#[derive(Debug, Clone)]
pub enum ProxyEvent {
    /// A new client connected and a session was created.
    SessionStarted {
        /// The session identifier.
        session_id: SessionId,
        /// The client's remote address.
        client_addr: SocketAddr,
    },

    /// A setup message (CLIENT_SETUP or SERVER_SETUP) was observed.
    SetupMessage {
        /// The session identifier.
        session_id: SessionId,
        /// Which side sent the message.
        side: ProxySide,
        /// The decoded setup message.
        message: AnyControlMessage,
    },

    /// A control message was parsed from the forwarded byte stream.
    ControlMessage {
        /// The session identifier.
        session_id: SessionId,
        /// Which side sent the message.
        side: ProxySide,
        /// The decoded control message.
        message: AnyControlMessage,
    },

    /// A data stream header was parsed from a unidirectional stream.
    DataStreamHeader {
        /// The session identifier.
        session_id: SessionId,
        /// Which side opened the stream.
        side: ProxySide,
        /// The parsed header.
        header: DataStreamHeaderKind,
    },

    /// An object header was parsed on a data stream.
    ObjectHeader {
        /// The session identifier.
        session_id: SessionId,
        /// Which side sent the object.
        side: ProxySide,
        /// The parsed object header.
        header: AnyObjectHeader,
    },

    /// A datagram was forwarded and its header was parsed.
    Datagram {
        /// The session identifier.
        session_id: SessionId,
        /// Which side sent the datagram.
        side: ProxySide,
        /// The parsed datagram header.
        header: AnyDatagramHeader,
        /// Size of the datagram payload in bytes.
        payload_len: usize,
    },

    /// A bidirectional stream was opened or accepted.
    BiStreamOpened {
        /// The session identifier.
        session_id: SessionId,
        /// Which side opened the stream.
        side: ProxySide,
    },

    /// A unidirectional stream was opened or accepted.
    UniStreamOpened {
        /// The session identifier.
        session_id: SessionId,
        /// Which side opened the stream.
        side: ProxySide,
    },

    /// Inline parse failed (non-fatal — bytes are still forwarded).
    ParseError {
        /// The session identifier.
        session_id: SessionId,
        /// Which side the error occurred on.
        side: ProxySide,
        /// Description of the parse error.
        error: String,
    },

    /// A stream direction was closed (FIN or reset).
    StreamClosed {
        /// The session identifier.
        session_id: SessionId,
        /// Which side closed.
        side: ProxySide,
    },

    /// The session ended.
    SessionEnded {
        /// The session identifier.
        session_id: SessionId,
        /// Reason for session termination.
        reason: String,
    },
}

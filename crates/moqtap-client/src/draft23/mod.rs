//! MoQT client implementation for draft-23.
//!
//! Each draft lives in its own top-level module with a complete, independent
//! implementation: connection, endpoint state machine, event types, observer
//! trait, and per-flow state machines (subscribe, fetch, publish, namespace,
//! track status). Enable via the `draft23` feature. The negotiated draft is
//! the ALPN, `moqt-23` on raw QUIC; there is no version on the wire.
//!
//! # What a caller feels
//!
//! * **A FETCH is answered by REQUEST_OK** (Section 1.5 and Section 9.3). Type
//!   0x18 is reserved, so
//!   [`Connection::respond_ok`](connection::Connection::respond_ok) answers a
//!   FETCH, and the first REQUEST_OK on a FETCH's stream is its FETCH_OK; a
//!   later one answers a REQUEST_UPDATE.
//! * **`PAUSED` (0x11) carries the pause**, 1 for paused (Section 9.19.18).
//!   The facade's `Forward` choice is written as PAUSED.
//! * **Overlapping namespace subscriptions are accepted**: draft-23 has no
//!   PREFIX_OVERLAP (Section 3.6, Section 4.2 and Section 12.3).
//! * **Session close codes are the draft-23 ones** (Section 12.2):
//!   [`EndpointError::session_error_code`](endpoint::EndpointError::session_error_code)
//!   and
//!   [`Connection::codec_session_error_code`](connection::Connection::codec_session_error_code)
//!   give the code each rule's sentence names.
//! * **Control messages are bounded by MAX_CONTROL_MESSAGE_SIZE** (Section
//!   9.1.8): what this endpoint reads is held to the value its own SETUP
//!   advertised, 65535 unless it advertised more, and what it writes after
//!   SETUP to the value the server's SETUP advertised.
//! * **An Object both received and signalled as not existing makes its Track
//!   malformed** (Section 12.1). The signals recorded are Prior Group ID Gap
//!   and Prior Object ID Gap properties and, on the stream answering a FETCH
//!   this endpoint sent, End of Non-Existent Range and the gaps between two
//!   entries of a FETCH with no Range Filter (Section 3.2.2).
//!
//! # What this module does not enforce
//!
//! Draft-23 lists the parameters a REQUEST_UPDATE (Section 9.5) may carry per
//! kind of request. The codec holds each message to the union of its lists,
//! and this endpoint does not narrow an update to the list for its request's
//! kind. A REQUEST_OK this endpoint receives is held to its request's own list
//! (Section 9.3).
//!
//! Fill fetch streams record nothing about which Objects exist, and neither do
//! the gaps before a FETCH stream's first entry and after its last: those are
//! measured against Section 3.2.2's End Location, the LARGEST_OBJECT in a
//! FETCH_OK that can arrive after the stream has ended.

/// Outbound MoQT connection with MoQT framing over QUIC.
pub mod connection;
pub mod endpoint;
pub mod event;
/// Fetch lifecycle state machine.
pub mod fetch;
pub mod fill;
/// Subscribe/Publish namespace state machines.
pub mod namespace;
pub mod observer;
/// Publish lifecycle state machine.
pub mod publish;
pub mod session;
/// Subscription lifecycle state machine.
pub mod subscription;
/// Track status lifecycle state machine.
pub mod track_status;

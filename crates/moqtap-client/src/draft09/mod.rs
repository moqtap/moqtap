//! MoQT client implementation for draft-09.
//!
//! Each draft lives in its own top-level module with a complete, independent
//! implementation: connection, endpoint state machine, event types, observer
//! trait, and per-flow state machines (subscribe, fetch, announce, track
//! status). No code is shared across drafts — each draft carries its own copy
//! because wire-level differences would make a shared layer leaky.
//!
//! Enable via the `draft09` feature.
//!
//! # Differences from draft-08
//!
//! * Object headers on data streams now carry `extension_headers_length`
//!   (byte count) instead of `extension_count` (item count).
//! * `Datagram` (stream type 0x01) no longer has `payload_length` or
//!   `object_status`; payload is the remaining bytes of the datagram.
//! * `DatagramStatus` (stream type 0x02) gains `extension_headers_length`.
//! * `filter_type = 1` (NextGroupStart / LatestGroup) is rejected on decode
//!   in SUBSCRIBE.

/// Outbound MoQT connection with MoQT framing over QUIC.
pub mod connection;
/// Unified endpoint state machine orchestrating all MoQT protocol flows.
pub mod endpoint;
/// Client event types emitted via the observer.
pub mod event;
/// Fetch lifecycle state machine.
pub mod fetch;
/// Announce / SubscribeAnnounces state machines.
pub mod namespace;
/// Connection observer trait for receiving client events.
pub mod observer;
/// Session state, setup validation, and subscribe ID allocation.
pub mod session;
/// Subscription lifecycle state machine.
pub mod subscription;
/// Track status lifecycle state machine.
pub mod track_status;

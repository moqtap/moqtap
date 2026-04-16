//! MoQT client implementation for draft-13.
//!
//! Each draft lives in its own top-level module with a complete, independent
//! implementation: connection, endpoint state machine, event types, observer
//! trait, and per-flow state machines (subscribe, fetch, announce, track
//! status). No code is shared across drafts — each draft carries its own copy
//! because wire-level differences would make a shared layer leaky.
//!
//! Enable via the `draft13` feature.
//!
//! # Differences from draft-12
//!
//! Draft-13 renames and restructures a few message types:
//!
//! - `SubscribeAnnounces` / `SubscribeAnnouncesOk` / `SubscribeAnnouncesError`
//!   / `UnsubscribeAnnounces` are renamed to `SubscribeNamespace` /
//!   `SubscribeNamespaceOk` / `SubscribeNamespaceError` /
//!   `UnsubscribeNamespace` (same wire IDs 0x11-0x14).
//! - `TrackStatusRequest` (0x0D) becomes `TrackStatus`: a subscribe-like
//!   request carrying `subscriber_priority`, `group_order`, `forward`, and
//!   `filter_type`.
//! - `TrackStatus` (0x0E) becomes `TrackStatusOk`: a subscribe_ok-like
//!   response carrying `track_alias`, `expires`, `group_order`,
//!   `content_exists`, and an optional `largest_location`.
//! - New `TrackStatusError` (0x0F): `request_id` + `error_code` +
//!   `reason_phrase`.
//!
//! The version varint is `0xff000000 + 13`.

/// Outbound MoQT connection with MoQT framing over QUIC.
pub mod connection;
/// Unified endpoint state machine orchestrating all MoQT protocol flows.
pub mod endpoint;
/// Client event types emitted via the observer.
pub mod event;
/// Fetch lifecycle state machine.
pub mod fetch;
/// Announce / SubscribeNamespace state machines.
pub mod namespace;
/// Connection observer trait for receiving client events.
pub mod observer;
/// Session state, setup validation, and request ID allocation.
pub mod session;
/// Subscription lifecycle state machine.
pub mod subscription;
/// Track status lifecycle state machine.
pub mod track_status;

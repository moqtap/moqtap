//! MoQT client implementation for draft-11.
//!
//! Each draft lives in its own top-level module with a complete, independent
//! implementation: connection, endpoint state machine, event types, observer
//! trait, and per-flow state machines (subscribe, fetch, announce, track
//! status). No code is shared across drafts — each draft carries its own copy
//! because wire-level differences would make a shared layer leaky.
//!
//! Enable via the `draft11` feature.
//!
//! # Differences from draft-10
//!
//! Draft-11 is a structural change from draft-10. The most visible shifts:
//!
//! - `subscribe_id` is renamed to `request_id` throughout the control plane.
//! - `MAX_SUBSCRIBE_ID` / `SUBSCRIBES_BLOCKED` become
//!   `MAX_REQUEST_ID` / `REQUESTS_BLOCKED`.
//! - `Subscribe` gains a `forward` field; `group_order` and `filter_type` are
//!   carried as VarInts rather than typed enums.
//! - `SubscribeOk` collapses the largest group/object pair into a single
//!   optional `largest_location`; `SubscribeError` gains a trailing
//!   `track_alias`; `SubscribeDone` gains `stream_count`.
//! - `Announce` / `AnnounceOk` / `AnnounceError` and `SubscribeAnnounces*`
//!   use `request_id` instead of carrying the namespace on every reply.
//! - `TrackStatusRequest` / `TrackStatus` are request-id keyed and `TrackStatus`
//!   no longer echoes the track namespace / name; it carries a
//!   `largest_location`.
//! - `Fetch` is restructured into a `FetchPayload` enum (`Standalone` vs
//!   `Joining`); `FetchOk` uses a single `end_location` and adds
//!   `end_of_track`.
//! - The data-stream layer adds subgroup variants 0x08–0x0D, datagram types
//!   0x00–0x03, and per-object extension headers.

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
/// Session state, setup validation, and request ID allocation.
pub mod session;
/// Subscription lifecycle state machine.
pub mod subscription;
/// Track status lifecycle state machine.
pub mod track_status;

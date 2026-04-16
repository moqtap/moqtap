//! MoQT client implementation for draft-08.
//!
//! Each draft lives in its own top-level module with a complete, independent
//! implementation: connection, endpoint state machine, event types, observer
//! trait, and per-flow state machines (subscribe, fetch, announce, track
//! status). No code is shared across drafts — each draft carries its own copy
//! because wire-level differences would make a shared layer leaky.
//!
//! Enable via the `draft08` feature.
//!
//! # Differences from draft-07
//!
//! * `SubscribesBlocked` (type 0x1A) is a new control message.
//! * `Subscribe` AbsoluteRange filter drops `end_object`; only `end_group`.
//! * `SubscribeUpdate` drops `end_object`.
//! * `SubscribeDone` is restructured: it now carries `stream_count` instead
//!   of the conditional `final_group` / `final_object` pair.
//! * `Fetch` has two modes (Standalone = 1, Joining = 2). Joining mode takes
//!   `joining_subscribe_id` + `preceding_group_offset`.
//! * `FetchOk` always includes `largest_group_id` and `largest_object_id`.
//! * Subgroup / datagram / fetch object headers carry `extension_count` +
//!   opaque extension bytes.
//! * New `DatagramStatus` stream type (0x02) for status-only datagrams.
//! * `ObjectStatus` value 4 is now `EndOfTrackAndGroup`, and value 5 is a new
//!   `EndOfTrack` (track ends but current group does not).

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

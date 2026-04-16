//! MoQT client implementation for draft-10.
//!
//! Each draft lives in its own top-level module with a complete, independent
//! implementation: connection, endpoint state machine, event types, observer
//! trait, and per-flow state machines (subscribe, fetch, announce, track
//! status). No code is shared across drafts — each draft carries its own copy
//! because wire-level differences would make a shared layer leaky.
//!
//! Enable via the `draft10` feature.
//!
//! # Differences from draft-09
//!
//! Wire format is identical to draft-09; only the negotiated version number
//! differs (`0xff00000a` vs `0xff000009`).

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

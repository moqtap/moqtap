//! MoQT client implementation for draft-07.
//!
//! Each draft lives in its own top-level module with a complete, independent
//! implementation: connection, endpoint state machine, event types, observer
//! trait, and per-flow state machines (subscribe, fetch, announce, track
//! status). No code is shared across drafts — each draft carries its own copy
//! because wire-level differences would make a shared layer leaky.
//!
//! Enable via the `draft07` feature.
//!
//! # Differences from later drafts
//!
//! * Request IDs are called **subscribe_id**, allocated monotonically from 0
//!   (no client/server parity rule).
//! * Namespace publication uses **ANNOUNCE / UNANNOUNCE** (instead of
//!   `PUBLISH_NAMESPACE` which appears in draft-14).
//! * There is no standalone `PUBLISH` flow — publishers announce namespaces
//!   and respond to SUBSCRIBE messages.
//! * Subgroup object IDs are **not** delta-encoded, and there are no
//!   extension headers. Subgroup/fetch/datagram decoding is stateless.

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

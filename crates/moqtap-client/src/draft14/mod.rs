//! MoQT client implementation for draft-14.
//!
//! Each draft lives in its own top-level module with a complete, independent
//! implementation: connection, endpoint state machine, event types, observer
//! trait, and per-flow state machines (subscribe, fetch, publish, namespace,
//! track status). No code is shared across drafts — each draft carries its
//! own copy because wire-level differences would make a shared layer leaky.
//!
//! Enable via the `draft14` feature.

/// Outbound MoQT connection with MoQT framing over QUIC.
pub mod connection;
/// Unified endpoint state machine orchestrating all MoQT protocol flows.
pub mod endpoint;
/// Client event types emitted via the observer.
pub mod event;
/// Fetch lifecycle state machine.
pub mod fetch;
/// Subscribe/Publish namespace state machines.
pub mod namespace;
/// Connection observer trait for receiving client events.
pub mod observer;
/// Publish lifecycle state machine.
pub mod publish;
/// Session state, setup validation, and request ID allocation.
pub mod session;
/// Subscription lifecycle state machine.
pub mod subscription;
/// Track status lifecycle state machine.
pub mod track_status;

//! MoQT client implementation for draft-17.
//!
//! Each draft lives in its own top-level module with a complete, independent
//! implementation: connection, endpoint state machine, event types, observer
//! trait, and per-flow state machines (subscribe, fetch, publish, namespace,
//! track status). No code is shared across drafts — each draft carries its
//! own copy because wire-level differences would make a shared layer leaky.
//!
//! Enable via the `draft17` feature.

/// Outbound MoQT connection with MoQT framing over QUIC.
pub mod connection;
pub mod endpoint;
pub mod event;
/// Fetch lifecycle state machine.
pub mod fetch;
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

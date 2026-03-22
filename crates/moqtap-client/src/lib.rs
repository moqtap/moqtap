#![deny(missing_docs)]

//! MoQT client library.
//!
//! Provides a full MoQT client stack: pure state machines for protocol
//! flows (subscribe, fetch, namespace, publish, track status) layered under
//! a [`connection::Connection`] type that drives real network I/O over QUIC.
//!
//! # Modules
//!
//! - [`connection`] — Outbound QUIC connection with MoQT framing
//! - [`endpoint`] — Unified endpoint state machine (no I/O)
//! - [`transport`] — Transport abstraction (QUIC)
//! - [`event`] — Client event types
//! - [`observer`] — Connection observer trait
//! - [`session`] — Session state, setup validation, request ID allocation
//! - [`subscription`] — Subscription lifecycle state machine
//! - [`fetch`] — Fetch lifecycle state machine
//! - [`namespace`] — Subscribe/Publish namespace state machines
//! - [`publish`] — Publish lifecycle state machine
//! - [`track_status`] — Track status lifecycle state machine

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
/// Transport abstraction (QUIC, with WebTransport planned).
pub mod transport;

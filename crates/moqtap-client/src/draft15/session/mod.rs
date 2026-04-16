//! MoQT session lifecycle management.
//!
//! Handles the session-level concerns of the MoQT protocol: setup
//! validation, session state machine transitions, and request ID
//! allocation with parity enforcement.
//!
//! # Modules
//!
//! - `state` -- Session state machine (Connecting -> Active -> Closed)
//! - `setup` -- CLIENT_SETUP / SERVER_SETUP validation (no version negotiation)
//! - `request_id` -- Request ID allocator with client/server parity rules

/// Request ID allocation with client/server parity enforcement.
pub mod request_id;
/// CLIENT_SETUP / SERVER_SETUP validation (ALPN-based version negotiation).
pub mod setup;
/// Session state machine (Connecting -> Active -> Closed).
pub mod state;

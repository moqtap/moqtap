//! MoQT session lifecycle management (draft-11).
//!
//! Handles the session-level concerns of the MoQT protocol: version
//! negotiation during setup, session state machine transitions, and
//! request ID allocation (monotonic, no parity rule).
//!
//! # Modules
//!
//! - `state` — Session state machine (Connecting -> Active -> Closed)
//! - `setup` — CLIENT_SETUP / SERVER_SETUP validation and version negotiation
//! - `request_id` — Monotonic request ID allocator (shared by SUBSCRIBE and FETCH)

/// Monotonic request ID allocation.
pub mod request_id;
/// CLIENT_SETUP / SERVER_SETUP validation and version negotiation.
pub mod setup;
/// Session state machine (Connecting -> Active -> Closed).
pub mod state;

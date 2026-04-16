//! MoQT session lifecycle management (draft-08).
//!
//! Handles the session-level concerns of the MoQT protocol: version
//! negotiation during setup, session state machine transitions, and
//! subscribe ID allocation (monotonic, no parity rule).
//!
//! # Modules
//!
//! - `state` — Session state machine (Connecting -> Active -> Closed)
//! - `setup` — CLIENT_SETUP / SERVER_SETUP validation and version negotiation
//! - `subscribe_id` — Monotonic subscribe ID allocator (shared by SUBSCRIBE and FETCH)

/// CLIENT_SETUP / SERVER_SETUP validation and version negotiation.
pub mod setup;
/// Session state machine (Connecting -> Active -> Closed).
pub mod state;
/// Monotonic subscribe ID allocation.
pub mod subscribe_id;

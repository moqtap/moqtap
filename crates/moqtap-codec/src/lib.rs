#![deny(missing_docs)]

//! MoQT wire codec for
//! [draft-07](https://www.ietf.org/archive/id/draft-ietf-moq-transport-07.html) and
//! [draft-14](https://www.ietf.org/archive/id/draft-ietf-moq-transport-14.html).
//!
//! Enable draft support via feature flags: `draft14` (default), `draft07`.
//!
//! # Shared modules
//!
//! - [`varint`] — QUIC variable-length integer (RFC 9000 Section 16)
//! - [`kvp`] — Key-value parameter pairs used in control messages
//! - [`types`] — Core protocol types (TrackNamespace, Location, enums)
//! - [`error`] — Codec error types and size limits
//!
//! # Draft-specific modules
//!
//! - [`draft14`] — Draft-14 control messages, data streams, and error codes
//!   (enabled via `draft14` feature, on by default)
//! - `draft07` — Draft-07 control messages and data streams
//!   (enabled via `draft07` feature)

/// Unified types and version-aware decode/encode (requires both drafts).
#[cfg(all(feature = "draft07", feature = "draft14"))]
pub mod dispatch;
/// MoQT wire codec for draft-07 (enabled via `draft07` feature).
#[cfg(feature = "draft07")]
pub mod draft07;
/// MoQT wire codec for draft-14 (enabled via `draft14` feature).
#[cfg(feature = "draft14")]
pub mod draft14;
/// Codec error types and size limits.
pub mod error;
/// Key-value parameter pair encoding and decoding.
pub mod kvp;
/// Core protocol types shared across drafts.
pub mod types;
/// QUIC variable-length integer encoding and decoding.
pub mod varint;
/// MoQT draft version enum for runtime dispatch.
pub mod version;

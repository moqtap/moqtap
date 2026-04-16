#![deny(missing_docs)]

//! MoQT wire codec for
//! [draft-07](https://www.ietf.org/archive/id/draft-ietf-moq-transport-07.html) through
//! [draft-17](https://www.ietf.org/archive/id/draft-ietf-moq-transport-17.html).
//!
//! Enable draft support via feature flags: `draft14` (default), `draft07`, `draft08`, etc.
//! Use `all-drafts` to enable every draft.
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
//! Each `draftNN` module provides control message and data stream encoding/decoding
//! for that specific draft version. Enable via the corresponding feature flag.

/// Unified types and version-aware decode/encode across drafts.
///
/// The `Any*` wrapper enums contain one variant per enabled draft feature.
/// Enable multiple draft features (e.g. `draft07` + `draft14`) for runtime
/// dispatch between drafts.
pub mod dispatch;

/// MoQT wire codec for draft-07.
#[cfg(feature = "draft07")]
pub mod draft07;
/// MoQT wire codec for draft-08.
#[cfg(feature = "draft08")]
pub mod draft08;
/// MoQT wire codec for draft-09.
#[cfg(feature = "draft09")]
pub mod draft09;
/// MoQT wire codec for draft-10.
#[cfg(feature = "draft10")]
pub mod draft10;
/// MoQT wire codec for draft-11.
#[cfg(feature = "draft11")]
pub mod draft11;
/// MoQT wire codec for draft-12.
#[cfg(feature = "draft12")]
pub mod draft12;
/// MoQT wire codec for draft-13.
#[cfg(feature = "draft13")]
pub mod draft13;
/// MoQT wire codec for draft-14.
#[cfg(feature = "draft14")]
pub mod draft14;
/// MoQT wire codec for draft-15.
#[cfg(feature = "draft15")]
pub mod draft15;
/// MoQT wire codec for draft-16.
#[cfg(feature = "draft16")]
pub mod draft16;
/// MoQT wire codec for draft-17.
#[cfg(feature = "draft17")]
pub mod draft17;

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

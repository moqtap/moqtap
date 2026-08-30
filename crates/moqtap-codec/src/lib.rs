#![deny(missing_docs)]

//! MoQT wire codec for
//! [draft-07](https://www.ietf.org/archive/id/draft-ietf-moq-transport-07.html) through
//! [draft-19](https://www.ietf.org/archive/id/draft-ietf-moq-transport-19.html).
//!
//! Each draft sits behind its own feature flag — `draft07` through `draft19`.
//! The default is `all-drafts`, which enables every one of them.
//!
//! # Shared modules
//!
//! - [`varint`] — variable-length integers, in whichever encoding the draft
//!   uses: RFC 9000 Section 16 through draft-16, MoQT's own from draft-17
//! - [`kvp`] — Key-value parameter pairs used in control messages
//! - [`types`] — Core protocol types (TrackNamespace, Location, enums)
//! - [`version`] — Draft version enum, ALPN and varint encoding per draft
//! - [`error`] — Codec error types and size limits
//! - [`auth_token`], [`subscription_filter`], [`range_filter`] — parameter
//!   values that carry a structure rather than opaque bytes
//! - [`dispatch`], [`data_dispatch`] — runtime draft dispatch and draft-neutral
//!   object framing
//!
//! # Draft-specific modules
//!
//! Each `draftNN` module provides control message and data stream encoding/decoding
//! for that specific draft version. Enable via the corresponding feature flag.
//!
//! Each also carries an `error_codes` module holding that draft's error, status and
//! termination code registries as enums. They are reached only through their draft —
//! `draft14::error_codes::SessionErrorCode` — and nothing from them is re-exported at
//! the crate root. Registry names recur across drafts while the code points behind
//! them move: every one of the thirteen defines a `SessionErrorCode`, and drafts that
//! share a spelling do not always share a value. A root-level re-export would collide
//! outright, and disambiguating it would mean coining names that appear in no draft's
//! table. The `draftNN` path is what fixes which table a code point came from.

/// Unified types and version-aware decode/encode across drafts.
///
/// The `Any*` wrapper enums contain one variant per enabled draft feature.
/// Enable multiple draft features (e.g. `draft07` + `draft14`) for runtime
/// dispatch between drafts.
pub mod dispatch;

/// Draft-neutral object framing for data streams.
///
/// Readers and a writer that address the objects on a subgroup or fetch
/// stream without exposing per-draft types. Re-exported from [`dispatch`].
pub mod data_dispatch;

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
/// MoQT wire codec for draft-18.
#[cfg(feature = "draft18")]
pub mod draft18;
/// MoQT wire codec for draft-19 (latest).
#[cfg(feature = "draft19")]
pub mod draft19;

/// The Token structure carried by the AUTHORIZATION TOKEN parameter.
///
/// Drafts 11 through 19 define one structure and require a receiver to close
/// the session when a value it understands does not match it.
pub mod auth_token;

/// The subscription filter carried by the SUBSCRIPTION_FILTER parameter, named
/// LOCATION_FILTER from draft-19.
///
/// Drafts 15 and later moved SUBSCRIBE's Filter Type, Start Location and End
/// Group into one length-prefixed parameter value.
pub mod subscription_filter;

/// The Range Filters draft-19 carries in parameter types 0x25 through 0x29.
///
/// A reader rather than a check: every rule the draft states about them is
/// answered with a REQUEST_ERROR, which is a reply an endpoint sends and not a
/// frame a decoder refuses.
pub mod range_filter;

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

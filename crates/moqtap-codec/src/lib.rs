#![deny(missing_docs)]

//! MoQT wire codec for
//! [draft-07](https://www.ietf.org/archive/id/draft-ietf-moq-transport-07.html) through
//! [draft-21](https://www.ietf.org/archive/id/draft-ietf-moq-transport-21.html).
//!
//! Each draft sits behind its own feature flag — `draft07` through `draft21`.
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
//! - [`message_names`] — the name a draft gives a control message type ID,
//!   which needs both halves because the ids are reused across the range
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
//! them move: every one of the fourteen defines a `SessionErrorCode`, and drafts that
//! share a spelling do not always share a value. A root-level re-export would collide
//! outright, and disambiguating it would mean coining names that appear in no draft's
//! table. The `draftNN` path is what fixes which table a code point came from.

pub mod dispatch;

pub mod data_dispatch;

#[cfg(feature = "draft07")]
pub mod draft07;
#[cfg(feature = "draft08")]
pub mod draft08;
#[cfg(feature = "draft09")]
pub mod draft09;
#[cfg(feature = "draft10")]
pub mod draft10;
#[cfg(feature = "draft11")]
pub mod draft11;
#[cfg(feature = "draft12")]
pub mod draft12;
#[cfg(feature = "draft13")]
pub mod draft13;
#[cfg(feature = "draft14")]
pub mod draft14;
#[cfg(feature = "draft15")]
pub mod draft15;
#[cfg(feature = "draft16")]
pub mod draft16;
#[cfg(feature = "draft17")]
pub mod draft17;
#[cfg(feature = "draft18")]
pub mod draft18;
#[cfg(feature = "draft19")]
pub mod draft19;
#[cfg(feature = "draft20")]
pub mod draft20;
#[cfg(feature = "draft21")]
pub mod draft21;

/// The Token structure carried by the AUTHORIZATION TOKEN parameter.
///
/// Drafts 11 through 21 define one structure and require a receiver to close
/// the session when a value it understands does not match it.
pub mod auth_token;

pub mod subscription_filter;

pub mod range_filter;

mod draft_table;
/// Codec error types and size limits.
pub mod error;
pub mod fields;
/// Key-value parameter pair encoding and decoding.
pub mod kvp;
pub mod message_names;
pub mod setup_option_names;
/// Core protocol types shared across drafts.
pub mod types;
/// QUIC variable-length integer encoding and decoding.
pub mod varint;
pub mod version;

pub use message_names::message_type_name;
pub use setup_option_names::setup_option_name;

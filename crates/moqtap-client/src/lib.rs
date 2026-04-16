#![deny(missing_docs)]

//! MoQT client library.
//!
//! Provides a full MoQT client stack with per-draft modules. Each enabled
//! draft lives under its own module (e.g. [`draft14`]) containing its own
//! connection, endpoint state machine, and per-flow state machines.
//!
//! The [`transport`] module is shared across drafts because it sits below
//! the MoQT protocol layer (raw QUIC / WebTransport streams and datagrams).
//!
//! # Feature flags
//!
//! Enable a draft with `--features draft14` (or any of `draft07`..`draft17`).
//! Use `all-drafts` to enable every implemented draft. Default is `draft14`.
//!
//! # Modules
//!
//! - [`dispatch`] — Multi-draft entry-point types (`AnyConnection`,
//!   `AnyClientEvent`, `AnyConnectionObserver`)
//! - [`transport`] — Transport abstraction (QUIC, WebTransport)
//! - [`draft07`] — Draft-07 client (enabled via `draft07` feature)
//! - [`draft08`] — Draft-08 client (enabled via `draft08` feature)
//! - [`draft09`] — Draft-09 client (enabled via `draft09` feature)
//! - [`draft10`] — Draft-10 client (enabled via `draft10` feature)
//! - [`draft13`] — Draft-13 client (enabled via `draft13` feature)
//! - [`draft14`] — Draft-14 client (enabled via `draft14` feature)

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

/// Transport abstraction (QUIC, with WebTransport planned). Shared across drafts.
pub mod transport;

/// Multi-draft entry-point types (`AnyConnection`, `AnyClientEvent`,
/// `AnyConnectionObserver`) for downstream consumers that need to hold
/// a connection without compile-time coupling to one draft.
pub mod dispatch;

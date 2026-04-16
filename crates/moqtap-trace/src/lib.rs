#![deny(missing_docs)]

//! MoQT session tracing — `.moqtrace` file format.
//!
//! Implements the [`.moqtrace` binary format specification](https://github.com/user/moqtap-js/blob/main/packages/trace/FORMAT.md)
//! for recording and replaying MoQT protocol sessions.
//!
//! The format uses CBOR encoding and is designed to be streamable,
//! compact, and cross-language compatible.
//!
//! # Modules
//!
//! - [`header`] — [`TraceHeader`](header::TraceHeader), [`Perspective`](header::Perspective), [`DetailLevel`](header::DetailLevel)
//! - [`event`] — [`TraceEvent`](event::TraceEvent), [`EventData`](event::EventData), [`Direction`](event::Direction)
//! - [`writer`] — [`MoqTraceWriter`](writer::MoqTraceWriter) for streaming writes
//! - [`reader`] — [`MoqTraceReader`](reader::MoqTraceReader) for streaming reads
//! - [`error`] — [`MoqTraceError`](error::MoqTraceError)
//!
//! # Re-exports
//!
//! [`ciborium::Value`] is re-exported so consumers can build opaque CBOR
//! values (e.g. for the control message `"msg"` field) without depending
//! on ciborium directly.

/// Trace error types.
pub mod error;
/// Trace event types.
pub mod event;
/// Trace file header types.
pub mod header;
/// Streaming `.moqtrace` reader.
pub mod reader;
/// Streaming `.moqtrace` writer.
pub mod writer;

/// Re-export of [`ciborium::Value`] for building opaque CBOR values.
pub use ciborium::Value;

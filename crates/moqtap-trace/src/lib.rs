#![deny(missing_docs)]

//! MoQT session tracing — `.moqtrace` file format.
//!
//! Implements the [`.moqtrace` binary format specification](https://github.com/moqtap/moqtap-js/blob/master/packages/trace/SPEC.md)
//! for recording and replaying MoQT protocol sessions.
//!
//! The format uses CBOR encoding and is designed to be streamable,
//! compact, and cross-language compatible.
//!
//! # Versions
//!
//! This crate writes format version 2 and reads versions 1 and 2. A version-1
//! file is a non-segmented version-2 trace carrying none of the keys version 2
//! added, so nothing recorded before the bump becomes unreadable.
//!
//! # Reading a trace you did not write
//!
//! Traces outlive the code that reads them, so nothing here rejects a file for
//! carrying something newer than it knows. An unrecognised event type arrives
//! as [`EventData::Unknown`](event::EventData::Unknown) with its fields
//! intact; an unrecognised perspective, detail level or drop policy is kept
//! verbatim in the matching `Other` variant. The enums are `#[non_exhaustive]`
//! for the same reason — matching on one needs a wildcard arm, and gains a
//! variant without breaking you.
//!
//! # Modules
//!
//! - [`header`] — [`TraceHeader`](header::TraceHeader), [`Perspective`](header::Perspective), [`DetailLevel`](header::DetailLevel), [`SegmentInfo`](header::SegmentInfo), [`SamplingInfo`](header::SamplingInfo)
//! - [`event`] — [`TraceEvent`](event::TraceEvent), [`EventData`](event::EventData), [`Direction`](event::Direction), [`SubscriptionRef`](event::SubscriptionRef)
//! - [`writer`] — [`MoqTraceWriter`](writer::MoqTraceWriter) for streaming and segmented writes
//! - [`reader`] — [`MoqTraceReader`](reader::MoqTraceReader) and [`ReadItem`](reader::ReadItem) for streaming and segmented reads
//! - [`error`] — [`MoqTraceError`](error::MoqTraceError)
//!
//! # Re-exports
//!
//! [`ciborium::Value`] is re-exported so consumers can build opaque CBOR
//! values (e.g. for the control message `"msg"` field) without depending
//! on ciborium directly.

/// The README's examples, compiled as doctests so they cannot rot. The item
/// exists only under `cfg(doctest)` and is not part of the public API.
#[doc = include_str!("../README.md")]
#[cfg(doctest)]
pub struct ReadmeDoctests;

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

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
//! intact; an unrecognised key on an event type this crate *does* know arrives
//! in [`TraceEvent::extra`](event::TraceEvent::extra) — as does a key it does
//! know whose value is not of a type that key can hold, since knowing more
//! about a key must not mean preserving it less; an unrecognised perspective,
//! detail level or drop policy is kept verbatim in the matching `Other`
//! variant. The enums are `#[non_exhaustive]` for the same reason —
//! matching on one needs a wildcard arm, and gains a variant without breaking
//! you.
//!
//! The header keeps its keys the same way, in three stores rather than one:
//! [`TraceHeader::extra`](header::TraceHeader::extra),
//! [`SegmentInfo::extra`](header::SegmentInfo::extra) and
//! [`SamplingInfo::extra`](header::SamplingInfo::extra). Each map keeps its
//! own, because a private key on `"segment"` and a key of the same name at the
//! top level are different keys. `"custom"` needs no store: every key in it
//! belongs to whoever wrote the trace, so it is handed back as it was found.
//!
//! All of it is kept rather than skipped because reading and writing a trace
//! back out is a normal thing to do to one — a redaction pass, a filter, a
//! re-segmentation — and a reader that drops what it did not recognise makes
//! its own ignorance permanent for every reader downstream of it.
//!
//! ## The one shape that does not survive
//!
//! CBOR `undefined` (major type 7, value 23 — the byte `0xf7`) reaches this
//! crate as `null` and is written back as `0xf6`. [`ciborium::Value`] has no
//! variant for it: ciborium's deserializer routes both `undefined` and `null`
//! through `visit_none`, so the two arrive identical and a store holds
//! [`Value::Null`] for either. Nothing above the decoder can tell them apart,
//! so nothing above it can preserve the difference or report it — seeing it
//! at all would mean decoding at the `ciborium-ll` layer against a value
//! model of this crate's own.
//!
//! SPEC.md puts that case where it belongs: where a reader cannot observe a
//! normalisation, the reader is not non-conformant and nothing may depend on
//! the outcome. `undefined` carries no meaning this format defines and no
//! conformant writer emits it. The two shapes a decoder folds away that this
//! crate *can* still act on — an integral float, and a byte string under
//! RFC 8746's tag 64 — it acts on where the rules apply, at the writer, and
//! in every value it emits that came out of a file rather than out of a typed
//! field: the header's three stores and `"custom"`, and on an event
//! [`TraceEvent::extra`](event::TraceEvent::extra), a control message's
//! `"msg"`, an annotation's `"data"` and an unknown event type's fields. See
//! [`TraceHeader::extra`](header::TraceHeader::extra) for what the rules are
//! and why a reader that preserved either shape all the way out would put the
//! two implementations back to writing different bytes for one trace.
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

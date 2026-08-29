# Changelog

All notable changes to moqtap-trace will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

**This ships as 0.2.0.** Not 0.1.1: `EventData` gained variants and a
`#[non_exhaustive]` attribute, `TraceEvent` and `TraceHeader` gained public
fields, and `Perspective` and `DetailLevel` gained an `Other` variant. Any
exhaustive `match` and any struct literal over those types stops compiling.
Under Cargo's 0.x rules the minor position *is* the major position, so `^0.1.0`
would hand that break to every current consumer under a patch number.

It implements version 2 of the `.moqtrace` format.

### Added

- **`EventData::ControlMessage::stream_id: Option<u64>`** — the QUIC stream the
  message travelled on, when the recorder knows it. Serialized as the optional
  `"sid"` key and omitted entirely when `None`.

  The field exists because of a protocol change rather than a convenience.
  From draft-17 each request occupies its own bidirectional stream and a
  response carries **no request ID**, so the stream a response arrived on is
  the only thing that pairs it with its request. A trace of a draft-17-or-later
  session without this field cannot reconstruct which request any response
  answered, and no amount of reading the rest of the record recovers it.

  `None` means *the recorder did not know*, and a reader must not read it as
  stream 0. That distinction is why the field is an `Option` rather than a
  `u64` with a sentinel: a recorder that has the stream and one that does not
  are different situations, and collapsing them would let a trace assert an
  association it never observed.

- **Segmented traces.** `SegmentInfo` on the header, and
  `MoqTraceWriter::start_segment` to begin a new one. A segment is a complete
  `.moqtrace` blob — magic, version, header, events — concatenated after the
  previous one, so a consumer can start reading at any segment without the
  ones before it. That buys capture rotation without finalizing a file, live
  carriage with a natural cut point, and recovery from a damaged region.

  `start_segment` refuses a header that carries no `SegmentInfo`. That field is
  what tells a reader the sequence numbers and timestamps it is about to see
  restart at zero; a segmented stream written without it reads as a run of
  complete files whose timeline jumps backwards at every boundary, and nothing
  downstream can detect that it happened.

- **`MoqTraceReader::read_next`** returning `ReadItem::Event` or
  `ReadItem::Segment`, and `into_item_iter` to iterate them. `read_event` and
  the default iterator are unchanged in behaviour: they advance through
  segment boundaries silently, and `header()` tracks the segment the last
  event came from.

- **`MoqTraceReader::resync_to_next_segment`** — scan forward to the next
  segment and resume there. This is the recovery that segmentation exists to
  offer: after a truncation or a decode error, one damaged segment costs that
  segment rather than the rest of the capture.

- **`MoqTraceError::Truncated { offset }`** — the stream ended part-way through
  an item. Previously indistinguishable from a clean end of file, which meant a
  crash-truncated trace read as a complete one and nothing said otherwise.
  Everything decoded before `offset` is valid and is returned.

- **`SamplingInfo` on the header**, declaring effective rate, cap, drop policy,
  drop counters, source-side filter rule, and which event types the policy was
  applied to. Its absence means the trace is complete relative to its detail
  level.

- **`Perspective::RelayTap`** and the **`peer` field on `TraceEvent`** (the
  `"p"` key), for a capture that spans many concurrent sessions rather than
  one. The identifier is source-local: the same string in two traces from
  different sources does not name the same peer.

- **`EventData::PeerConnected` (8), `PeerDisconnected` (9) and
  `SubscriptionDerivation` (10)**, with `PeerRole`, `Side`, `DerivationKind`
  and `SubscriptionRef`. Event 10 links an upstream subscription to the
  downstream ones it serves, and carries the track it targets plus four
  per-hop timestamps. Those timestamps share the event timebase — the emitting
  source's own clock — so differences between them are meaningful with no
  cross-hop clock agreement, which is the point: they measure how long one hop
  took. Nothing in this workspace emits these events yet; they are defined so
  that a reader written today does not have to be replaced by one that can
  read them.

- **`TraceEvent::new`, `TraceEvent::for_peer`, `TraceHeader::new` and
  `SegmentInfo::new`.** Constructors rather than struct literals, so the next
  field this format grows does not break every call site that only ever set the
  required ones.

- `TraceEvent::event_type`, and `as_str` on `Perspective`, `DetailLevel`,
  `DropPolicy`, `PeerRole`, `Side` and `DerivationKind`, with `Display` on the
  header enums. A consumer displaying a perspective previously had to go
  through `Debug`, which prints the Rust spelling rather than the wire one.

- `MOQTRACE_VERSIONS_SUPPORTED`, the versions this crate reads.

### Changed

- **`MOQTRACE_VERSION` is 2. Readers accept 1 and 2.**

  Every other field this revision adds would have been legal in a version-1
  file: unknown keys are ignored, and optional keys may be added to an existing
  event type. Segmentation is the exception and the sole reason for the bump. A
  segmented stream splices magic bytes, a version and a header into the middle
  of what a version-1 reader takes for an uninterrupted CBOR sequence; that
  reader decodes the `M` of `MOQTRACE` as the start of a 13-byte byte string,
  swallows part of the preamble, and desynchronizes with nothing to tell it so.
  Declaring version 2 turns that silent corruption into an explicit rejection
  at byte 8.

  Version 1 is still read because a non-segmented version-2 file *is* a
  version-1 file plus keys a version-1 reader would ignore. Accepting it costs
  a branch and keeps every capture taken before the bump openable.

- **`EventData`, `Perspective`, `DetailLevel`, `DropPolicy`, `PeerRole`, `Side`
  and `DerivationKind` are `#[non_exhaustive]`.** Matching on one now needs a
  wildcard arm, and gains a variant later without another breaking release.

- `Perspective` and `DetailLevel` are no longer `Copy`, since `Other` carries
  the value it preserved. `DetailLevel::Other` sorts above `Full`: a level this
  crate does not know might reveal anything, and a check written as
  `detail >= HeadersData` should err towards warning rather than towards
  silence.

- **The `"sid"` key on control messages is additive on the wire.** A reader
  built before it ignores the key; a file written before it decodes to
  `stream_id: None`.

### Fixed

- **An unrecognised event type no longer fails the read.** It arrives as
  `EventData::Unknown` with its fields intact, so it also survives a
  read-modify-write round trip rather than being dropped by the first tool in
  the chain that did not recognise it. Rejecting unknown types made every
  future addition to the format a breaking change — including the three this
  release adds, which is how the defect surfaced.

- **An unrecognised `perspective` or `detail` value no longer fails the read.**
  Both were hard errors raised while parsing the header, so a trace using a
  value this crate did not know was refused before a single event was read —
  even though every event in it parses. They are now preserved verbatim in the
  matching `Other` variant.

- **Event 10's trace ID is `"traceId"`, a 16-byte byte string**, and a value of
  any other length is rejected rather than padded or truncated. The identifier
  exists so two independent implementations derive byte-identical values for
  one subscription chain; a text spelling, or a reader that quietly reshapes
  the value, breaks exactly the property it is there for.

- **Traces written by the JavaScript implementation are now readable at all.**
  Two encoding conventions differed, and neither test suite could see it,
  because each side only ever read bytes it had written itself.

  A CBOR integer may legally be written as a float, and the other encoder does
  that for any value past 32 bits — which every epoch-millisecond timestamp
  is. Reading only major type 0 meant `startTime` was missing from every such
  header, and the file was rejected before a single event was read. Integer
  fields now accept the float form, refusing only a value that is fractional
  or beyond the range a float holds exactly, so that accepting it never
  becomes rounding.

  The same encoder wraps every byte string in the typed-array tag 64.
  Reading only an untagged byte string meant every payload-bearing field it
  wrote — raw wire bytes, object payloads, track names, trace ids — read as
  absent, and a payload-bearing field that reads as absent cannot be told
  apart from one the recorder deliberately did not capture. Byte strings now
  unwrap that tag.

  Both are read-side fixes because the files already exist. The specification
  now states the writing rules normatively as well.

- The crate documentation pointed at `FORMAT.md` under a placeholder
  `github.com/user/...` path. Both are corrected: the specification is
  `SPEC.md`, under the real repository. The old link resolved to nothing, so
  every reader who followed it from docs.rs got a 404.

## [0.1.0] - 2026-04-16

Initial release.

### Added

- `TraceEvent` type capturing control messages, data streams, objects, errors,
  shaped around `EventData` variants.
- `TraceHeader` with session metadata (`protocol`, `perspective`, `detail`
  level, timestamps, transport, endpoint, custom fields).
- `.moqtrace` binary file format (8-byte magic + 4-byte LE version + CBOR body
  via `ciborium`).
- `MoqTraceWriter` / `MoqTraceReader` for file I/O. `MoqTraceWriter::new` takes
  a `&TraceHeader`.
- `ciborium::Value` re-exported at the crate root for consumers building
  opaque CBOR payloads.

# Changelog

All notable changes to moqtap-trace will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`EventData::Error` carries the bytes behind the error** — `stream_id`
  (`"sid"`), `kind` (`"ek"`), `raw_len` (`"rawlen"`) and `raw` (`"raw"`), each
  optional and each written only when set, alongside a public `ERROR_RAW_CAP`
  and `EventData::error_observed`, which builds the variant from bytes a
  recorder has just observed.

  The error event held a code and a sentence and nothing else. A peer that
  sends something malformed is one of the few things a shared trace is uniquely
  good for — the recording party can see it and the sending party cannot — but
  the only field in the format able to hold bytes was a control message's
  `"raw"`, so a recorder that wanted to keep the evidence had to record the
  violation as a decodable control message in order to have somewhere to put
  it. That is a worse record than none: it asserts a message where there was a
  protocol violation, and no reader can tell the two apart. The alternative was
  to drop the bytes, and a report saying a peer's SUBSCRIBE_OK did not parse is
  an assertion where the same report carrying the bytes is evidence the other
  party can run against its own encoder.

  `"sid"` is optional on the same terms as event 0's: absent means there was no
  stream or none is known, and a reader must not read it as stream 0. `"ek"` is
  an open vocabulary — `ErrorKind` names `protocol`, `transport` and `decode`
  and keeps any other spelling in `Other`, the way `Perspective` does, because
  values may be added without a format version bump.

  The two byte-bearing keys sit at different detail levels deliberately, and
  `error_observed` is what applies that: `"rawlen"` from `headers+sizes`
  upwards, because it is a size and this format gates sizes, and `"raw"` at
  `full` alone — one level above the event's own `control`+, since an error
  naming a data stream has subgroup framing and object payload behind it, and
  inheriting the event's level would have put media into traces whose declared
  level excludes payloads outright. A level this crate cannot place yields
  neither: a guess the other way is one no later read can undo.

  **The 4096-byte cap is applied there and nowhere else.** `write_event` does
  not enforce it, and that is the point rather than an omission — a serializer
  cannot tell a freshly recorded event from one that arrived by being read, so
  a cap applied there either shortens evidence on a rewrite or refuses a file
  the reader was required to accept, and whichever it does, it does to the
  wrong events. A `"raw"` past the cap reads back at its full length and is
  written back at its full length. The one-`"raw"`-per-flow latch belongs to
  the recorder too and is not here: it is state across events, so it lives with
  whatever holds the flow. See SPEC.md, Event 6.

  **Breaking for anyone constructing or exhaustively destructuring the
  variant**, the way `TraceEvent::extra` was for 0.3.0. Reading is unaffected:
  every key is optional, and a file written before they existed carries none.

- **`EventData::StreamOpened` carries the stream's identifiers** — `track_alias`
  (`"ta"`), `subgroup_id` (`"sg"`), `fetch_request_id` (`"fri"`) and `group_id`
  (`"g"`), each `Option<u64>` and each written only when set.

  No detail level records the bytes of a `SUBGROUP_HEADER`, a fetch header or a
  datagram header, so a value carried only there had nowhere to live: the model
  could express group, object, priority and status and nothing else. A
  `"headers"` recording therefore could not say which track a stream belonged
  to, which is most of what the level exists for, and a fetch stream had nothing
  at all tying it to the FETCH that asked for it.

  `"sg"`, `"fri"` and `"g"` are each scoped to one stream type, since on the
  others they have no source. This crate does not write one outside its scope
  and does not reject one it finds there — it reads it into the field and writes
  it back, on the same rule that governs `extra`: a reader may decline to
  understand something, but not decide on the next reader's behalf that it never
  existed.

  **Breaking for anyone constructing or exhaustively destructuring the variant**,
  the way `TraceEvent::extra` was for 0.3.0. Reading is unaffected: every key is
  optional, and a file written before they existed carries none.

- **The header's three maps carry unrecognised-key stores** —
  `TraceHeader::extra`, `SegmentInfo::extra` and `SamplingInfo::extra`, each a
  `Vec<(Value, Value)>` holding the keys of that map this crate could not use,
  written back after the map's own keys.

  Three stores and not one: a private key on `"segment"` and a key of the same
  name at the top level are different keys, and re-emitting either in the
  other's map changes what the file says. `"custom"` gets none — every key in
  it belongs to whoever wrote the trace, so there is no such thing as an
  unrecognised key there.

  **Breaking for anyone constructing or exhaustively destructuring these three
  structs**, the way `TraceEvent::extra` was for 0.3.0. `TraceHeader::new` and
  `SegmentInfo::new` avoid it, and `SamplingInfo` still derives `Default`.
  `SegmentInfo` also loses its `Eq` impl, since the store holds arbitrary CBOR
  and a CBOR value may be a float; `TraceHeader` and `SamplingInfo` have never
  had `Eq` for that reason.

### Fixed

- **A header key this crate did not recognise is no longer deleted by reading
  the file.** The header decoder read the keys it knew and dropped the rest on
  the floor: an `"x-note"` was gone from the struct and absent from anything
  written back out. This is the same data loss `extra` fixed for events and
  strictly larger, because on the header it applied to *every* unknown key
  rather than only to a wrong-typed one.

  Nothing printed by `moqtap trace` changes — it never rewrites a file.
  The loss landed on the tools that do: a redaction pass, a filter, a
  re-segmentation, a download with annotations applied. Each emitted a valid
  file that looks as though it never carried the key, so one tool's ignorance
  became permanent for every reader downstream of it.

  A key the format *does* define now goes to the same store when its value is
  not one the field can hold — `"transport": 42`, an `"endTime"` with a
  fractional part — on the rule SPEC.md states for events: knowing more about
  a key must not mean preserving it less. The field reads `None`, the value is
  ignored for meaning, and the entry is written back unchanged.

  What goes to a store is decided by what the decode consumed, not by a list of
  key names kept beside it. The two differ exactly on a defined key carrying an
  unusable value, and that gap is where the event decoder had been deleting
  things. Each map answers with an exhaustive destructuring of its own fields,
  so a field added later does not compile until it is answered for.

- **A `"segment"` or `"sampling"` that is not a map no longer fails the file.**
  `MoqTraceReader::new` returned `InvalidHeader("'segment' is not a CBOR map")`
  and the file did not open, so one unreadable metadata value cost every event
  behind it. The CLI printed the error and exited 1 — visible, but the events
  were unreachable all the same.

  Such a value now goes to the header's store and the reader proceeds as though
  the key were absent, which for `"segment"` means reading the trace as
  non-segmented. `"segment.sequence"` remains the one exception: absent or
  unusable, it is still a malformed header, because it is the sole ordering key
  of a segmented stream and a default would invent an order the file never had.
  So are the four required top-level keys.

- **`"sampling.appliesTo"` is kept whole or not at all.** An array with one
  element that is not an event type ID was read as the elements that were —
  `[3, "x", 5]` became `[3, 5]`, and the entry that could not be read was gone
  from the rewritten file too.

  That is not a partial answer. The key names the event types the drop policy
  touched, and a reader may treat every type absent from it as complete, so
  shortening the array reports a sampled event type as fully recorded — the
  opposite of what the file said, stated with the same confidence. The array
  now goes to `SamplingInfo::extra` entire and `applies_to` reads `None`.

  `"effectiveRate"` is bounded the same way, on the same rule for a value
  outside the range a key's meaning allows: the key is defined as a fraction in
  `(0.0, 1.0]`, so `1.5`, `0.0`, a negative rate and a NaN now go to the store
  instead of being handed to a caller as a sampling rate.

- **An integral `"effectiveRate"` is written as a CBOR integer, not as a
  float.** The encoder emitted `Value::Float` for the key unconditionally,
  because the format declares it a float — but the normative rule is about the
  *value*: "an integral value MUST be written as a CBOR integer (major type 0
  or 1), not as a float". `"effectiveRate"` is where the distinction bites,
  since its commonest value is `1.0`, "no rate-based dropping". So the ordinary
  case — a source saying it dropped nothing — wrote a float64 here while the
  JavaScript implementation wrote the integer `1`, for the same trace, and
  neither test suite could see it because each read only bytes it had written
  itself. A fractional rate is still a float, there being no integer that
  carries it, and the reader has always taken either form.

- **The same two encoding rules now apply to a stored value, at any depth.** An
  integral float in one of the three stores — or in `"custom"` — was written
  back as a float, and a byte string wrapped in RFC 8746's tag 64 was written
  back still wrapped. Both are shapes SPEC.md forbids a writer to emit, and
  neither is one the JavaScript implementation *can* emit: `cbor-x` folds them
  away on the way in, so its store never holds either. Two writers, the same
  input file, different bytes — which is the one thing those rules exist to
  stop. An out-of-range `"effectiveRate"` of `2.0`, kept in the sampling map's
  store, wrote `fb4000000000000000` here and `02` there.

  Normalisation happens on the way out and never on the way in, so a value
  read into a store still compares equal to what the file carried, and it
  recurses through arrays, maps and map keys, since a stored value may be a
  whole tree. It changes the encoding and not the value, with the one exception
  SPEC.md names and declines to carve out: `-0.0` written as `0` loses its
  sign.

- **A store no longer emits a CBOR map carrying the same key twice.** A store
  is an ordered list of pairs rather than a map, so a caller could build one
  holding `"x-a"` twice and both entries went into the file. RFC 8949 calls
  such a map invalid and the JavaScript reader silently collapses it, keeping
  whichever entry it likes. The first entry for a key is now the one written,
  matching the first-match lookup every read in this crate goes through.

  The reading half had the mirror of that bug. A header carrying `"transport"`
  twice handed the first entry to the field, and the store — filtered by key
  *name* — then dropped **both**, so the second value reached neither the field
  nor the store and was gone from the decoded header entirely. The entry no
  field took is now kept, where a caller can see it; the rewrite still emits
  the key once, because that is all a conformant writer may emit.

- **Those same two rules, and the same one-key-once rule, now apply to the
  opaque values an *event* carries.** `TraceEvent::extra` is the half of this
  that landed with the header's stores. The rest of an event's file-provided
  CBOR was still written verbatim: a control message's `"msg"`, an
  annotation's `"data"` and the fields of an event type this crate cannot name
  each reach the serializer as a value nobody looked at, and each went to the
  file exactly as the decoder handed it over — an integral float still a
  float, a tag-64 byte string still tagged, a repeated key still repeated.

  `@moqtap/trace` cannot produce any of the three. `cbor-x` hands JavaScript a
  plain number for an integral float, strips tag 64 on decode, and has
  collapsed a duplicate key before its caller runs — so Rust was the only side
  that could emit them, which made it the only side that had to be told not
  to. Nor was this a corner: two `capture-*` cases in the shared corpus are
  nine annotations and two control messages each, and every one of those
  eleven events is an opaque value on this path.

  All four write sites now go through the one function the header's stores
  use, rather than a second copy of the rules that would have to agree with
  it. Reading is unchanged — a value read into `"msg"`, `"data"`, an unknown
  event's fields or `extra` still compares equal to what the file carried, and
  it is the serializer that applies the house style. Typed fields were never
  affected: `"raw"`, `"pl"`, `"traceId"` and `"tn"` are `Vec<u8>` by the time
  they reach the writer and go out as major type 2 by construction.

- **A key an event repeats is no longer deleted by reading the file.** The
  reading half of the duplicate-key bug above, one file over. Every getter in
  the event decoder is a first-match search, so an event carrying `"sid": 4`
  and then `"sid": 9` handed the 4 to the field — and `extra`, filtered by key
  *name*, then dropped **both** entries, so the 9 reached neither the field nor
  the store and was gone from the decoded event entirely. `ciborium` models a
  map as a list of pairs and hands back both entries, so this was a value a
  Rust reader had been shown and discarded, not one its decoder had collapsed
  before any of this crate's code ran.

  `EventData::Unknown` had the same defect in its `fields`, which is where
  every key such an event carries lives: `{"n": 0, "n": 5, "t": 100, "e": 99}`
  read back with no trace of the 5. That variant collects nothing into `extra`,
  so `fields` is the only place an entry the common fields did not take can
  land.

  The entry no field took is now kept, where a caller can see it. The rewrite
  still emits the key once — the field wins, and a map may not carry a key
  twice — so a file that carried a duplicate comes back out with one entry,
  which is the most a conformant writer may emit, and is a fixed point from
  there. The store is decided by walking the entries and tracking which
  occurrence a field consumed, the way the header's stores are, rather than by
  filtering on key names.

  One write-side hole closed with it: an unknown event type's `fields` were
  written unfiltered, so an `"n"` among them — which a caller could always
  attach by hand, and which a repeated `"n"` on input now leaves there — was
  written a second time into a map that a duplicate key makes malformed. Those
  fields now go through the same filter the store does.

- **Events after a segment header the reader cannot build are no longer
  attributed to the segment before it.** The preamble is consumed before the
  header is constructed, and `MoqTraceReader` only replaced its held header on
  success — so the next `read_next` decoded the *new* segment's events while
  `header()` still described the old one. SPEC.md requires a reader to report
  such a header and "MUST NOT present the segment as read"; handing back its
  events under the previous header does both at once, and since `"n"` and
  `"t"` are segment-local while global order is `(segment.sequence, n)`, every
  event so recovered was also silently misordered.

  The error is now returned once and the segment skipped whole: the next read
  resynchronizes to the segment after it and reports it as a `ReadItem::Segment`
  like any other, which is what `readMoqtrace`'s `recover` path does with the
  same file. `collect::<Result<Vec<_>, _>>()` still stops at the error, and a
  caller that filters errors out — the one this cost the most, since it saw no
  fault at all — now gets the segments it can trust and none of the events from
  the segment it cannot. `resync_to_next_segment` landing on such a header
  behaves the same way.

- **`"custom"` is handed back exactly, or not at all.** It is declared as a
  string-keyed map, and a `"custom"` with a non-text key was read into one by
  dropping that key — the caller got a map the file never carried, and the
  rewrite made it true. A `"custom"` that was not a map was dropped whole.

  Both are now unusable values: `custom` reads `None` and the whole thing goes
  to the header's store, where the bytes survive. Losing typed access is the
  smaller harm, since nothing in the format gives `"custom"` keys meaning. The
  same applies to a `"custom"` carrying one key twice, which a `BTreeMap` would
  silently collapse to one entry. **Callers that read `header.custom` on such a
  file used to get a partial map and now get `None`**; a conformant `"custom"`
  is unaffected.

- **A malformed header names the fault instead of reporting a present key as
  missing.** `"startTime": -5` produced `missing 'startTime'`, which sent
  anyone trying to fix the file looking for something that was right in front
  of them. The four required keys and `"segment.sequence"` now distinguish
  absent (`missing 'startTime'`) from unusable (`'startTime' is not an unsigned
  integer`, `'perspective' is not a text string`). **Anything matching on those
  strings needs updating**; the error variant is unchanged.

- **A defined key whose value has an unusable type is kept instead of deleted
  from everywhere.** An optional key read through a type-checked getter left its
  field `None` when the value was not one that field could hold. The same key
  was *also* kept out of `extra`, because what went to `extra` was decided by
  asking which keys the event **type** defines rather than which ones the decode
  had used. The entry then survived in neither place, and reading a trace and
  writing it back deleted it.

  SPEC.md: "A defined key whose value has an unusable type is treated as
  unrecognised." Such a key now lands in `extra`, is ignored for meaning, and is
  written back unchanged. The keys it applies to are `"p"` on any event — on an
  event type this crate cannot name it joins the rest in
  `EventData::Unknown::fields` — `"sid"` and `"raw"` on event 0, `"ta"`, `"sg"`,
  `"fri"` and `"g"` on event 1, `"pl"` on event 4, `"endpoint"`, `"transport"`,
  `"role"` and `"side"` on event 8, `"reason"` on event 9, and `"traceId"`,
  `"tn"`, `"tdr"`, `"tus"`, `"tuo"` and `"tdo"` on event 10.

  The hole is as old as `extra`: 0.3.0 started keeping a key this crate had
  never heard of while still dropping one it knew and could not use, so knowing
  more about a key made it preserve less. Event 1's four keys, added above, are
  four more keys falling through the same hole rather than a new one, and that
  part of it has not been released.

  Nothing changes for a value of the type its key is defined to carry: it still
  reads into its field and is still written from there, so a file whose types
  conform rewrites byte for byte as before. SPEC.md's bound on the rule is
  unchanged as well: a **required** key with an unusable type is still a
  malformed event, since there is no event to construct without it. So are the
  two optional keys that are refused rather than read through a getter that can
  answer "no" — a `"traceId"` that is not 16 bytes, and an `"ns"` that is not a
  CBOR array — both of which still make the event malformed.

  On the writing side, an `extra` entry is dropped as a duplicate only when the
  event really does write that key from one of its own fields. An entry naming
  an optional key whose field is empty is now written, which is how a value the
  reading half kept gets back out; an entry naming a key an
  `EventData::Unknown` already carries in `fields` is now dropped, where before
  it was written a second time into a map that a duplicate key makes malformed.

- **A control message with no `"msg"` key is read rather than refused.** The
  decoder required the key and returned `InvalidEvent("missing 'msg'")`
  without it. Event 0 is one of the types sampling MUST NOT drop, so requiring
  the key rejected exactly the events the format promises to keep — every
  control message from a recorder that decoded no bodies.

  How much was lost depended on the caller, and the idiomatic path was the
  worse one. `read_next` returns the error, so `collect::<Result<Vec<_>, _>>()`
  — the form this crate's own tests use — stopped at the first such event and
  yielded none of the ones after it. A caller that skips errors and keeps
  going lost only the offending events; `moqtap trace` does that and prints
  each one, so there the loss was at least visible.

  An absent `"msg"` now reads as the empty map SPEC.md tells writers to emit,
  and an event read that way is written back carrying `"msg": {}`. A `"msg"`
  that is present but not a map is still handed back verbatim, and written
  back unchanged: recordings predating the rule hold a text rendering of the
  message there, every `capture-*` case in the conformance corpus among them.
  That rewrite is deliberately not "normalised into conformance" — replacing
  it would destroy the only record of a message nobody will see again.

- **`request_id()` reads `request_id` rather than `requestId`.** It had matched
  nothing since the helper was written: not this crate's corpus, not a trace
  from any other implementation. Callers that got `None` from it on every real
  trace now get the value.

## [0.3.0] - 2026-09-02

**Breaking, which is why this is 0.3.0 and not 0.2.1.** `TraceEvent` gained a
public field, `extra`, so any struct literal over it stops compiling. Under
Cargo's 0.x rules the minor position *is* the major position, so `^0.2.0` would
hand that break to every current consumer under a patch number.

The fix at each site is one line, and `TraceEvent::new` / `TraceEvent::for_peer`
avoid it entirely — a constructor does not have to be edited every time the
struct gains a field, which is why they exist.

### Added

- **`TraceEvent::extra: Vec<(Value, Value)>`** — every key on an event that
  neither the common fields nor the event's own type owns, kept verbatim and
  written back out.

  The format lets optional keys be added to an existing event type without a
  version bump, and SPEC.md says unknown keys "MUST be ignored". That was read
  as making new keys safe. They were safe to *read past* and silently destroyed
  by any read-modify-write — a redaction pass, a filter, a re-segmentation, a
  download with annotations applied. The output is a valid file that looks like
  it never carried the key, so one tool's ignorance became permanent for every
  reader downstream of it.

  `EventData::Unknown` already gave that guarantee for an event *type* this
  crate cannot name. This is the same guarantee one level down, for a key on a
  type it can.

  An `EventData::Unknown` event does not fill `extra`: its `fields` already
  hold every non-common key, and collecting them twice writes a CBOR map with
  duplicate keys. An `extra` entry whose key collides with one the event's type
  owns is dropped on serialization for the same reason — the field is what a
  reader would have produced.

- **`TraceEvent::with_extra`** — attaches unrecognised keys, for a caller
  reconstructing an event it did not decode itself.

### Changed

- The crate is now checked against the shared `.moqtrace` corpus, in
  `tests/corpus_tests.rs`. Half its files were written by `@moqtap/trace` and a
  quarter were recorded from third-party relays, so for the first time this
  crate's reader is tested on bytes it did not write. `examples/generate_corpus`
  writes this crate's half.

  The corpus earned its place immediately: it caught the duplicate-key bug
  above on the first run of the new code, before either implementation had a
  test naming the behaviour.

  Two of its files carry the non-canonical encodings SPEC.md requires readers
  to accept — integers past 2^32 as CBOR float64, byte strings under RFC 8746
  tag 64. Both rules exist because both were broken in released code, and until
  now nothing exercised either form in this crate.

## [0.2.0] - 2026-08-29

Implements version 2 of the `.moqtrace` format.

**Breaking, which is why this is 0.2.0 and not 0.1.1.** `EventData` gained
variants and a `#[non_exhaustive]` attribute, `TraceEvent` and `TraceHeader`
gained public fields, and `Perspective` and `DetailLevel` gained an `Other`
variant. Any exhaustive `match` and any struct literal over those types stops
compiling. Under Cargo's 0.x rules the minor position *is* the major position,
so `^0.1.0` would hand that break to every current consumer under a patch
number.

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

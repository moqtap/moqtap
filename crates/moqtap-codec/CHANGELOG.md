# Changelog

All notable changes to moqtap-codec will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.0] - 2026-09-21

### Added

- **`draft21`**, a feature and a module, in `all-drafts`, with `DraftVersion::Draft21` and the ALPN `moqt-21`. Draft-21 restructures draft-20's text and changes nothing a decoder can observe - same code points, fields, registries and varint - so `draft21/` is `draft20/` under draft-21's section numbers, and the committed draft-21 corpus is draft-20's byte for byte. `vectors_draft21.rs` runs it through this codec in both directions.

### Changed

- **Breaking.** `DraftVersion` gains `Draft21`. The enum is not `#[non_exhaustive]`, so a downstream `match` that enumerates its variants stops compiling - the same break draft-20 forced, and the whole of it. No existing draft's bytes, errors or API changed.
- **Breaking.** `CodecError::InvalidTypeValue` is replaced by `CodecError::InvalidStreamTypeValue` and `CodecError::InvalidDatagramTypeValue`, same fields on each. Drafts 16 through 21 state this as two MUST-close sentences in two sections - one for a subgroup stream header's Type, one for a datagram's - and one variant carrying both could not say which sentence a frame broke. The raw number cannot decide it either, because the two Type spaces overlap. Both map to the same `invalid_type` vector category, so the corpus contract is unchanged; a consumer matching the old variant must name the two, and one that only wants the category can match either.

### Fixed

- `draft20/message.rs` cited Section 10.2.19 for the TRACK_NAMESPACE_PREFIX parameter, which is NEW GROUP REQUEST; it is 10.2.20, as three other sites in the same file already said.
- `ObjectIdOverflow`'s doc named draft-17 as the draft that states the Object ID Delta arithmetic without a consequence. Drafts 14 through 17 all do.

## [0.6.0] - 2026-09-20

### Added

- `setup_option_names`, with `setup_option_name(draft, &KeyValuePair)` re-exported at the crate root: names a setup parameter as a given draft would. It takes the whole pair because drafts 11-13 name from the key and the value's shape together.
- `CodecError::is_incomplete()` — true for the four spellings of input running out mid-value, so a caller waiting for more bytes no longer keeps its own list of them.
- `AnyControlMessage::message_type_id()` and `::message_type_name()`.
- Setup parameter names completed: draft-11 gains `0x04`, draft-12 gains `0x03` and `0x04`. Both decoders already accepted what their renderers could not name.

### Changed

- **Breaking.** `draft14::error_codes::RequestErrorCode` is now `SubscribeErrorCode`. Draft-14 has no REQUEST_ERROR message — that arrives at draft-15 — and the registry this type transcribes is SUBSCRIBE_ERROR. The old name had no callers outside this crate's own tests.
- **Breaking.** `draft16::data_stream::SubgroupHeader::encode` drives the Publisher Priority byte off the Type byte's DEFAULT_PRIORITY bit rather than off `publisher_priority` being `Some`: a `None` under a clear bit writes 128, a `Some` under a set bit writes no byte. Either mismatch shifted every later field and desynced the stream. `encode_checked` refuses the disagreement with `InvalidField`.
- **Breaking.** `fields()` on draft-16 names three types differently. `0x04`, `0x0E` and `0x30` are no longer named as Message Parameters, and `0x0B`, `0x22` and `0x30` are now named as Track Extensions. The two registries reuse numbers for different things, and `0x30` belongs to the second.
- **Breaking.** On drafts 16-20 an out-of-range track property or extension sitting after an unparseable Immutable block is now caught. The walk skips the block it cannot read instead of ending, so an unparseable block no longer shields its neighbours from the range rules.

### Fixed

- **No field renderer panics on a peer's bytes.** Every `unwrap` in the per-draft renderers is gone; a value that will not parse renders as the raw bytes. Reachable from the public `fields()` on auth tokens (drafts 11-13), subscription and location filters (15-19) and `largest_object` (17-20).
- **Auth-token rendering on drafts 11 and 12.** The second varint is the Token Alias on DELETE, REGISTER and USE_ALIAS and the Token Type only on USE_VALUE. It was labelled `token_type` on all four, so `token_alias` was never emitted and REGISTER swallowed the real Token Type into `token_value`.
- **Draft-17 token values** are no longer read behind an inner length the draft does not define, matching the corrected test vectors. Drafts 18-20 were already right.

## [0.5.0] - 2026-09-03

### Added

- **`draft20`**, a feature and a module with the same five files every other draft has, included in `all-drafts`. It is the newest draft this crate implements, a default nowhere and not the interop target: interop ran against draft-18 and the editors plan draft-22 next, so nothing here promotes draft-20 to a connection default, an advertised-preferred version or an auto-selected draft.
- **FETCH (`0x16`) is a different message**, not a variation on draft-19's: Section 10.13 deleted the `Fetch Type` field, the Standalone Fetch and Joining Fetch structures, the Fetch Type registry and the whole joining mechanism, Track Namespace and Track Name are inline fields of FETCH, and the range travels in the `LOCATION_FILTER` parameter. The codepoint did not change, so a draft-19 decoder reads the Number of Track Namespace Fields count as a Fetch Type and mis-parses in silence — there is no in-band version signal that catches it.
- **`PUBLISH_STATE_NOTIFY` (`0x22`)**, new in Section 10.10: a publisher-only, unilateral report that a subscription's state changed, with **no Request ID field**, because the message is identified by the bidirectional request stream it arrives on.
- **`FILL_PARAMETERS` (`0x23`)**, a length-prefixed parameter whose value is a nested parameter block in its own scope, read by `draft20::message::decode_fill_parameters`. Its presence on a SUBSCRIBE or a REQUEST_UPDATE is what asks the publisher to open a fill fetch stream.
- **`INCLUDE_PROPERTIES` (`0x35`)**, a uint8 restricted to 0 and 1, default 1.
- **`FetchEndOfRange::TimedOut`** and `AnyFetchEndOfRange::TimedOut`, for Table 7's new `0x20C` End of Timed-Out Range marker. Draft-19 reported the same Objects as an Unknown range, so the two are not interchangeable across a draft boundary.
- **`DraftVersion::Draft20`**, ALPN `moqt-20`, and draft-18's variable-length integer encoding unchanged.
- `tools/registries/draft-20.json`, and `tools/extract-registries.py` extended to draft-20; `--check` over all fourteen drafts confirms 07-19 are unmoved.
- **A `fields` module, and a `fields.rs` in every draft**, moved into the crate from the vector test harness. `draftNN::fields::message_fields` renders a decoded `ControlMessage` as a `fields::FieldMap`, an ordered list of `fields::FieldValue`s — `Uint`, `Bool`, `Text`, `Bytes`, `Array`, or a nested `Map` — and `AnyControlMessage::fields()` picks the arm for the draft in hand, so a reader can render a message it has never heard of without knowing which draft decoded it. Each draft keeps its own field names in the order that draft defines them, an optional field the wire did not carry is absent from the map rather than given a zero, and the tree stops short of rendering itself, so a consumer spells the leaves in whatever its own format has types for.

### Changed

- **Breaking.** `DraftVersion` gains `Draft20` and `AnyFetchEndOfRange` gains `TimedOut`. Neither enum is `#[non_exhaustive]`, so a downstream `match` that enumerates their variants stops compiling. That is the whole of the break — no existing draft's bytes, errors or API changed.
- **Ranges are inclusive at both ends, on subscriptions and on fetches** (Sections 5.1.2, 10.13, 10.14). Draft-19's fetch end was "the last Object, plus 1; or 0 to indicate the entire Group"; both conventions are deleted. This is absent from draft-20's own change log, the bytes are identical between the two drafts and nothing on the wire distinguishes them, so a draft-19 encoder ported forward with its arithmetic intact fetches one object too many, and one whose end lands on object 0 fetches a single object where it used to fetch a group. `FetchOk::end_object` carries the note.
- **`LOCATION_FILTER` (`0x21`) has a new value shape.** The Filter Type enum — draft-19's `0x1` Next Group Start, `0x2` Largest Object, `0x3` AbsoluteStart, `0x4` AbsoluteRange — is gone, and the filter's shape comes from how many `vi64` fields its value holds. `subscription_filter` reads drafts 15-19 and is not used by draft-20, which has `draft20::message::decode_location_filter`.
- **Parameter applicability moved off `PUBLISH_OK`.** Six definitions dropped it and several gained `PUBLISH`; `EXPIRES` (`0x08`) is the only one that still names it. A subscriber changes a subscription with a REQUEST_UPDATE after the PUBLISH_OK now.
- **A non-minimally encoded `Type Flags` is accepted on receive** and never emitted, on both the subgroup header and the datagram, where draft-19 refused every wide spelling. Section 11.4.2 words its third condition as "values of 128 or greater (i.e., any value that requires more than a one-byte variable-length integer encoding)", two clauses that come apart under Section 1.4.1's allowance for non-minimal encodings; this codec reads it as a bound on the value.
- **Every invalid `Type Flags` value inside the one-byte space is now `InvalidTypeValue` rather than an unknown stream or datagram type.** The set of accepted values did not move — computing Section 11.4.2's three conditions and Section 11.3.1's three gives back draft-19's enumerations byte for byte — but the draft now names each refusal, so only a value too wide to be a flags field falls back on Section 3.4's unknown-type rule.
- **`DatagramHeader::decode_object` refuses the two Properties shapes Section 11.3.1 forbids**: the PROPERTIES bit over a zero-length block, and Properties beside a status that is not Normal. `decode` still reports rather than refuses, so a captured violation stays readable.
- **End of Range markers resolve against the frame before them.** Section 11.4.4.2 says only that "the Group ID and Object ID fields are present" and settles neither reading; draft-19 read them as absolute and draft-20 applies Section 11.4.4.1's ordinary arithmetic, because a marker's flags are literally the ordinary flags.
- `PUBLISH_DONE.Stream Count`'s "unknown" sentinel moves from `2^62 - 1` to `2^64 - 1` and the count now includes fill fetch streams; `publish_done_codes::STREAM_COUNT_UNKNOWN` names it, and notes that the sentinel is no longer distinguishable from a well-formed exact count.
- `DraftVersion::version_varint`'s doc comment now says plainly that from draft-15 on there is **no** `0xff0000NN` value on the wire at all: draft-15 deleted the version field from CLIENT_SETUP and moved selection into the ALPN. The mapping is kept for continuity and `0xff000014` is not observable.
- Crate description and README: draft-07 through draft-20.

### Removed

- Three code points, each a hole rather than a renumbering and nothing else in any registry moved: `SessionErrorCode::VersionNegotiationFailed` (`0x15`); `RequestErrorCode::InvalidJoiningRequestId` (`0x32`), with the Joining Fetch; and `PublishDoneStatusCode::SubscriptionEnded` (`0x3`), with the behaviour behind it — Section 5.1.2 now says "A publisher does not end a subscription solely because the Largest Object advances past the end of the current Location Filter." A frame carrying one of the three still **decodes**, because Section 14 is explicit: "Receipt of an unknown error code in any error context … MUST be treated as equivalent to INTERNAL_ERROR for that context. An endpoint MUST NOT close the session because it received an unknown error code in a REQUEST_ERROR or PUBLISH_DONE." `from_u64` answers `None`, which is the whole of what a codec owes the rule; refusing the frame would take the INTERNAL_ERROR reading away from the caller. Two committed draft-20 vectors ask for a refusal on that ground and are recorded as wrong in `tests/vectors_draft20.rs`.
- Two whole enumerations: the Fetch Type registry (`0x1` Standalone / `0x2` Relative Joining / `0x3` Absolute Joining) and the Location Filter Type enum. Neither was an IANA registry; both were wire enums, and both are gone.

### Fixed

- **Four peer-reachable panics in field extraction**, all of one shape: a `draftNN/message.rs` decoder gates a parameter's **type** — known, not a duplicate, in scope for this message — and not the parameter **value's shape**, and the matching `draftNN/fields.rs` then parsed that value structurally with `unwrap`. A value the extractor cannot read now renders as its raw bytes, because `fields` answers for a message that has **already decoded** — the frame is valid and the peer is owed whatever reply the draft names, so there is no refusal to give and the value a peer sent is what there is to show, which is the answer `fields::params` and `auth_token_to_json_d14` already gave. **No published version is affected**, not because the paths were unreachable there but because they do not exist there: `codec-v0.4.1` has no `fields.rs` in any draft module and no `fields` module at all, field extraction being new in 0.5.0. The local CLI builds from this tree, so they were live for anyone running it.
- **Range Filters (`0x25`-`0x29`) on drafts 19 and 20 are read by `range_filter::RangeFilter::decode_moqt`,** which is what the module was written for, rather than by a second copy of the same parse inside `fields.rs`. The copy read three varints with `unwrap` where `Buf::has_remaining` promises one byte and a MoQT varint may need nine, and resolved both delta baselines with a bare `+`. Three values a peer can send reached it: a `0x28`/`0x29` with a one-byte value (thirteen bytes on the wire), any `0x25`-`0x29` whose value ends mid-varint (fourteen), and a Start delta of `u64::MAX` followed by an End delta of 1. **The third was the worse one:** debug panicked, and release *wrapped*, rendering `start: 18446744073709551615, end: 0` into the trace as though a peer had asked for it. `range_filter.rs` has used `checked_add` on both baselines since it was written and had no caller, and draft-20's `FILL_PARAMETERS` (`0x23`) admits `0x25`-`0x28`, so every trigger had a second route one level down.
- **`LARGEST_OBJECT` (`0x09`) on drafts 15 and 16 renders a value that is not two varints** instead of panicking on it. Drafts 17 and later give `0x09` the Location encoding, whose decoder re-serialises the two varints it read, so their extractors are handed two varints by construction; 15 and 16 store the bytes that arrived and check nothing about them. The whole trigger is an eight-byte SUBSCRIBE_OK, `04 00 05 01 01 01 09 00`.
- **`RangeFilter` is split by what the caller does with the answer rather than by how much checking it wants.** It also enforces the two content rules Section 5.1.3 states — a Publisher Priority range above 255, and a property filter over an odd Property Type — and both are answered with REQUEST_ERROR rather than a session close, so both are values a peer really sends and are exactly the filters whose fields a reader most needs to see. **`RangeFilter::decode_moqt`** parses and then applies both rules, which is what a decoder wants: passing a rule-breaking filter on would let an application act on a range the peer was not allowed to ask for. **`RangeFilter::decode_moqt_structure`** parses only, and **`check_its_own_types`** is now public so the caller can ask separately; the extractors use this pair to render the fields and name the broken rule under `violates`, rather than refusing and hiding the offending value inside a hex dump at the moment someone is looking for it. Both entry points refuse a value that does not parse — a truncation, a missing SetID, an overflowing delta — so the split costs no safety, and it is strictly more than either reader gave alone: the unchecked copy showed the fields but never said the value was invalid, and the checked one says so by showing nothing.
- `tests/hostile_parameter_values.rs` drives each of these from `ControlMessage::decode` with wire bytes and then calls `message_fields`, which is the order that makes them reachability tests rather than tests of a private function.

## [0.4.1] - 2026-08-31

### Fixed

- **A build with no draft feature compiles without warnings again.** `AnySubgroupHeader::encode_stream`, `encode_stream_checked` and `AnyFetchHeader::encode_stream` compile their `match` to no arms at all when no draft is enabled, which leaves their parameters read by nothing; each already allowed `unreachable_code` for exactly that shape and now allows the warnings that come with it. No effect on any build that enables a draft, which is every build that can encode anything. Reached by `cargo check -p moqtap-codec --no-default-features` under `RUSTFLAGS="-D warnings"`, and it stayed hidden because the local recipe for that row does not set the flag and CI, which does, had never run.

## [0.4.0] - 2026-08-30

### Added

- `auth_token`, `subscription_filter` and `range_filter`: draft-neutral readers and writers for values that were carried as opaque bytes — the AUTHORIZATION TOKEN structure (drafts 11-19), the SUBSCRIPTION_FILTER / LOCATION_FILTER value (drafts 15-19), and draft-19's five Range Filter parameters (`0x25`-`0x29`). `range_filter` reports rather than refuses: every rule its section states is answered with REQUEST_ERROR, which is a reply an endpoint sends and not a frame a decoder rejects.
- `data_dispatch`, re-exported from `dispatch`: object framing without per-draft types — `AnySubgroupObjectReader`, `AnySubgroupObjectWriter`, `AnyFetchObjectReader`, `AnyFetchObjectWriter`, `AnyFetchFrame`, `reemit_subgroup_object` and the `Any*Object` / `Any*ObjectMeta` values, over subgroup and fetch streams on every draft 07-19.
- A fetch object codec for drafts 15-19, per draft and behind the draft-neutral seam. From draft-15 a Serialization Flags field decides which of Group ID, Subgroup ID, Object ID and Publisher Priority reach the wire; each one omitted is taken from the object before it, and from draft-18 the two ID fields are deltas whose sign follows the fetch's Group Order. `FetchObjectWriter` on drafts 15-19 is the inverse, and `FetchReemit::Unchanged` forwards a frame's own bytes rather than re-encoding them, so a stream nothing was removed from is reproduced byte for byte.
- An `error_codes` module in all thirteen `draftNN` modules, and an `ALL` const on every error, status and termination code enum — seventy-two in total, each the set its own `from_u64` accepts, in ascending wire order.
- `VarInt::encode_moqt` / `decode_moqt` and `version::VarIntEncoding` with `DraftVersion::varint_encoding`, which state per draft which integer encoding applies, plus `encode_moqt` / `decode_moqt` on `TrackNamespace`, `Location` and `KeyValuePair`.
- Fallible encoders wherever a draft's own decoder would refuse the result: `encode_checked` on the subgroup, datagram, object and fetch-object headers that lacked one, `AnySubgroupHeader::encode_stream_checked`, and the `KeyValuePair` checked forms.
- Draft-neutral accessors: `AnySubgroupHeader::{carries_extension_block, subgroup_id_mode, track_alias, group_id, publisher_priority, subgroup_id}`, `AnyDatagramHeader::{meta, permits_payload, extensions_permitted}`, `AnyFetchHeader::request_id`, `AnyControlMessage::fetch_group_order`, and `decode_stream` on the subgroup and fetch header enums.
- **Breaking.** Nineteen `CodecError` variants, so rules that shared `InvalidField` — which no draft's session table answers — can be routed to the close each draft names: `ControlMessageLengthMismatch`, `UnknownStreamType`, `UnknownDatagramType`, `InvalidTypeValue`, `KeyValueFormatting`, `UnknownMessageParameter`, `ParameterValueOutOfRange`, `TrackPropertyValueOutOfRange`, `ParameterLengthMismatch`, `InvalidForward`, `InvalidContentExists`, `InvalidFilterType`, `SubscriptionFilterMalformed`, `FilterEndGroupOverflow`, `InvalidFetchType`, `InvalidRange`, `EndOfTrackObjectId`, `ExtensionsOnNonExistentObject` and `PayloadNotPermitted`. `CodecError` is deliberately not `#[non_exhaustive]`, so a `match` without a wildcard arm will not compile until the arms are added.
- `ObjectStatus::ALL` and `as_u64` on all thirteen drafts, `as_u8` on drafts 17-19 and the shared type, `PayloadPermission` on draft-14 and drafts 15-19, and the `permits_payload` / `extensions_permitted` / `properties_permitted` predicates that go with them.
- `types::{check_location_range, check_group_range, check_open_ended_group_range}`: three rather than one because the drafts spell a range end three ways, and one comparison refuses frames two of them permit.

### Changed

- **Breaking.** Draft-conformance release, and a behaviour change in a published crate: parameter, filter and token values stop being opaque bytes and object framing is corrected across the range, so frames 0.3.0 accepted now error, frames it wrote are now refused before they reach the wire, and several encoders emit different bytes. 0.3.0 and earlier put different bytes on the wire, so read `### Changed` and `### Fixed` before upgrading.
- **Breaking.** Toolchain: the declared MSRV moves from 1.83 to 1.88.
- **Breaking.** `AnyDatagramHeader::encode` returns `Result<(), CodecError>`.
- **Breaking.** `types::Role` is gone on drafts 08, 09 and 10, which do not define the parameter.
- **Breaking.** `draft07::types::ObjectStatus::EndOfTrack` is renamed `EndOfTrackAndGroup`; draft-07's `0x5` is End of Subgroup and not the later drafts' End of Track.
- **Breaking.** `draft14::error_codes::PublishDoneStatusCode` is renamed and renumbered.
- **Breaking.** Drafts 17-19 `data_stream::DatagramHeader` gains a public `properties: Vec<u8>` field, which its decoder always read and its encoder never wrote.
- **Breaking.** Drafts 12 and 13 rename `FetchPayload::Joining`'s first field to `joining_request_id`.
- **Breaking.** `AnyFetchObjectReader::new` and `AnyFetchObjectWriter::new` take the fetch's Group Order, and `new_with_group_order` is gone. On drafts 18 and 19 a Group ID is a difference whose sign the order decides, nothing on the data stream carries it, and a descending stream read as ascending does not fail — it decodes, under Group IDs walking the wrong way, which neither side can detect afterwards. The order was a default; it is now an argument, and `AnyControlMessage::fetch_group_order` above is what answers it. Ignored on drafts 07-17, where Group IDs are values rather than differences.
- **Breaking.** `types::ObjectStatus` is renumbered — a behaviour change, not only an API one.
- `ControlMessage::encode` on drafts 11-19 applies the value rules its own decoder applies — AUTHORIZATION TOKEN structure, subscription filter, and parameter value ranges — so a message that could be written and not read back is refused at the call that writes it; drafts 15 and 16 needed their parameter encoder split per namespace to do it.
- Test-vector submodule pinned to v0.12.1.

### Removed

- **Breaking.** Seven `KeyValuePair` entry points: `encode_checked`, and the whole MoQT-varint half of the module — `encode_moqt`, `decode_moqt`, `encode_moqt_checked`, `encode_list_moqt`, `encode_list_moqt_checked` and `decode_list_moqt`. Every draft that reaches for the MoQT varint also delta-codes the parameter type; these six wrote it absolutely, so they serialized a shape no draft reads.

### Fixed

- **Wire-incompatible.** `LARGEST_OBJECT` (`0x09`) was length-prefixed on drafts 18 and 19, which frame it as a Location. Corrects the 0.2.0 entry that recorded the change.
- **Wire-incompatible.** `TRACK_NAMESPACE_PREFIX` (`0x34`) carried an extra outer varint length on drafts 18 and 19.
- **Wire-incompatible.** Draft-12 numbered OBJECT_DATAGRAM_STATUS `0x02`/`0x03`, where draft-12 puts the payload form.
- **Wire-incompatible.** Drafts 07-13 wrote a datagram under a different type field than they read it with.
- **Wire-incompatible.** Drafts 11, 12 and 13 read a two-bit type table as independent flags, dropped a subgroup object's extension block on write and misread it on the far side, and substituted a header's Subgroup ID.
- **Wire-incompatible.** Drafts 11, 12 and 13 encoded Group Order, Forward, Content Exists and End Of Track as varints where the figures give single bytes; draft-13 likewise.
- **Wire-incompatible.** Drafts 09-13 wrote the extension-block length from the bytes rather than the declared field.
- **Wire-incompatible.** Draft-16 wrote and read absolute Key-Value-Pair types where the draft delta-encodes them.
- **Wire-incompatible.** Draft-15 wrote the Publisher Priority byte when the struct held one rather than when the type byte said the field was present.
- **Wire-incompatible.** Drafts 17-19 used RFC 9000's variable-length integer instead of MoQT's. Non-minimal encodings are accepted as required; draft-17's undefined 7-byte form is refused with `VarIntError::InvalidCodePoint`.
- **Wire-incompatible.** Draft-13 `TRACK_STATUS` carried none of the fields its Filter Type announces.
- **Now refused on the drafts that require the close:** an unread subscription filter (Filter Type, length disagreement, and drafts 18 and 19's End Group Delta running past 2^64-1), an unparsed AUTHORIZATION TOKEN value, an unknown Message Parameter on drafts 16-19, a parameter value outside its range, a parameter whose type implies a length it does not have, a repeated Parameter Type, an unassigned Fetch Type, a Content Exists other than 0 or 1, and a Forward other than 0 or 1.
- **Now refused on the drafts that require the close:** object status code points the drafts do not assign, on all thirteen drafts and on both sides; a status paired with a payload the draft gives it no room for; and extension headers beside a status that forbids them.
- **Now refused on the drafts that require the close:** stream and datagram Types no table assigns, and the Types drafts 16-19 declare invalid within a form they do define. Draft-18 padding streams and datagrams are refused rather than misread as data.
- **Now refused on the drafts that require the close:** a control message whose declared Length disagrees with its fields, in both directions — fields running past the end used to report `UnexpectedEnd`, the variant that means "still arriving".
- **Now refused on the drafts that require the close:** a requested range that ends before it starts; a Track Namespace outside its field count on encode; an end-of-track object with a non-zero Object ID on drafts 08-10; a repeated Setup Option on drafts 17-19; a draft-08 Extension Count disagreeing with its bytes.
- `AnySubgroupHeader::subgroup_id` no longer reports an ID for a draft-15 or draft-16 header whose stream type does not carry one, and `subgroup_id_mode` answers on those two drafts.
- An Object Status is no longer dropped when a payload is present on drafts 07-13, and the 65,535-byte cap is gone from the drafts 07-10 encoders, which their drafts do not state.
- Draft-16 accepts a Track Namespace Prefix of zero fields in SUBSCRIBE_NAMESPACE, and a DELIVERY_TIMEOUT of zero is refused in both namespaces.
- The duplicate-parameter rule is asymmetric on drafts 11-16 and was applied symmetrically.
- A fetch stream can be opened: `decode_stream` consumes the stream-type field the per-draft decoders used to leave in place.

### Known gaps against draft-19

- Parameter scope is not enforced: a parameter legal in one message is accepted in any message that carries parameters. Where it belongs is an open question — a decoder that refuses non-conforming traffic cannot observe it, so an opt-in validator may be the right home rather than `decode`.
- `Properties` on an Object whose status is not Normal are read and written rather than refused, and reported by `properties_permitted` instead: the frame is well formed, and one of this crate's own vectors is exactly it, so a codec that refused it could not reproduce a capture.

## [0.3.0] - 2026-07-08

### Added

- MoQT draft-19 support: a new `draft19` module behind a `draft19` feature flag, with full control message and data stream encode/decode coverage, and `all-drafts` now enables it.
- `DraftVersion::Draft19` variant, `moqt-19` ALPN, and dispatch enum (`AnyControlMessage`, `AnySubgroupHeader`, `AnyDatagramHeader`, `AnyFetchHeader`) variants for draft-19.
- Range Filter parameters (length-prefixed): `SUBGROUP_FILTER` (`0x25`), `OBJECTID_FILTER` (`0x26`), `PRIORITY_FILTER` (`0x27`), `OBJECT_PROPERTY_FILTER` (`0x28`) and `TRACK_PROPERTY_FILTER` (`0x29`).
- Setup Options `MAX_FILTER_RANGES` (`0x06`) and `MAX_REQUEST_UPDATES` (`0x08`), both even KVP types carrying a varint value.
- New `request_error_codes::CONFLICTING_FILTERS` (`0x35`) and `INVALID_FILTER` (`0x36`).

### Changed

- `GoAway` no longer carries a `request_id`; the control-stream and request-stream forms are now identical on the wire.
- `PublishBlocked` renamed to `PublishSkipped`, with message type `0x0F` unchanged and the wire layout identical.
- `SUBSCRIPTION_FILTER` renamed to `LOCATION_FILTER`, with parameter `0x21` unchanged.
- `GROUP_ORDER` (`0x22`) is now valid in `SubscribeTracks` rather than `PUBLISH_OK`.
- Test-vector submodule pinned to v0.10.0.

### Removed

- `request_error_codes::DUPLICATE_SUBSCRIPTION` (`0x19`); multiple concurrent subscriptions per Track are now allowed.

## [0.2.0] - 2026-05-13

### Added

- MoQT draft-18 support: a new `draft18` module behind a `draft18` feature flag, with full control message and data stream encode/decode coverage, and `all-drafts` now enables it.
- `DraftVersion::Draft18` variant, `moqt-18` ALPN, and dispatch enum (`AnyControlMessage`, `AnySubgroupHeader`, `AnyDatagramHeader`, `AnyFetchHeader`) variants for draft-18.
- New control messages and fields: `SubscribeTracks` (type `0x51`); `RequestOk` gains a trailing `track_properties` block; `RequestError` gains an optional `Redirect` structure; `GoAway` gains an optional `request_id` (control stream only). New `request_error_codes::REDIRECT` (`0x34`) and `UNSUPPORTED_EXTENSION` (`0x33`); `publish_done_codes::{TOO_FAR_BEHIND, EXPIRED}` constants reflect draft-18's swapped values.
- New parameters and accessors: `OBJECT_DELIVERY_TIMEOUT` (renamed from `DELIVERY_TIMEOUT`, `0x02`), `SUBGROUP_DELIVERY_TIMEOUT` (`0x06`), `FILL_TIMEOUT` (`0x0A`, FETCH only), `TRACK_NAMESPACE_PREFIX` (`0x34`).
- Subgroup data-stream `FIRST_OBJECT` bit (`0x40`) plus `is_first_object` accessor; type ranges expand to `0x10..0x1F`, `0x30..0x3F`, `0x50..0x5F`, `0x70..0x7F`.

### Changed

- `SUBSCRIBE_NAMESPACE` renumbered to `0x50` and the `subscribe_options` field removed; the previous publish-side behavior moved to the new `SubscribeTracks` (`0x51`) message, which carries the FORWARD parameter.
- `PUBLISH_OK` collapsed into `REQUEST_OK` (`0x07`).
- Required Request ID Delta field removed from every request message (`Subscribe`, `Publish`, `Fetch`, `RequestUpdate`, `TrackStatus`, `PublishNamespace`, `SubscribeNamespace`).
- ~~`LARGEST_OBJECT` (`0x09`) now length-prefixed (was two consecutive varints in draft-17).~~ **This entry was wrong and is corrected in 0.4.0.** Draft-18 did not change the encoding: Section 10.2.11 says "is a Location", the same words draft-17 uses. The 0.2.0 release shipped the length-prefixed framing described here, so a draft-18 peer talking to that version sees the bug and not the entry — struck through rather than deleted for that reason.
- Test-vector submodule pinned to v0.9.1.

## [0.1.0] - 2026-04-16

### Added

- Initial release, covering MoQT drafts draft-07 through draft-17: a per-draft module for every one of them, each behind its own feature flag (`draft07`..`draft17`), with `all-drafts` enabling every draft and set as the default.
- QUIC variable-length integer (VarInt) encoding/decoding per RFC 9000.
- Key-value parameter (KVP) encoding/decoding.
- All 30 control message types: setup, subscribe, publish, fetch, namespace, track status, goaway.
- Data stream headers: SubgroupHeader, DatagramHeader, FetchHeader, ObjectHeader.
- Core protocol types: TrackNamespace, Location, FilterType, GroupOrder, ObjectStatus.
- Session and request error codes per draft.
- `dispatch` module with runtime draft-dispatch enums: `AnyControlMessage`, `AnySubgroupHeader`, `AnyFetchHeader`, `AnyDatagramHeader`, `AnyObjectHeader`. Each variant is gated on its draft feature flag, and `decode` / `encode` select the draft from a `DraftVersion` at runtime.
- `AnyControlMessage::is_setup` helper that recognizes the setup message variant for each draft, including draft-17's unified `Setup`.

### Notes

- Draft-14 has no standalone `AnyObjectHeader::Draft14` variant — subgroup objects are delta-encoded and require the stateful `draft14::data_stream::SubgroupObjectReader`.

# Changelog

All notable changes to moqtap-codec will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-08-30

Draft-conformance release. Parameter, filter and token values stop being opaque
bytes, and object framing is corrected across the range. This is a behaviour
change in a published crate: frames 0.3.0 accepted now error, frames it wrote
are now refused before they reach the wire, and several encoders emit different
bytes. Read `### Changed` and `### Fixed` before upgrading. Test-vector
submodule pinned to v0.12.1.

### Added

- `auth_token`, `subscription_filter` and `range_filter`: draft-neutral readers
  and writers for values that were carried as opaque bytes. The AUTHORIZATION
  TOKEN structure (drafts 11-19), the SUBSCRIPTION_FILTER / LOCATION_FILTER
  value (drafts 15-19), and draft-19's five Range Filter parameters
  (`0x25`-`0x29`). `range_filter` reports rather than refuses: every rule its
  section states is answered with REQUEST_ERROR, which is a reply an endpoint
  sends and not a frame a decoder rejects.
- `data_dispatch`, re-exported from `dispatch`: object framing without per-draft
  types. `AnySubgroupObjectReader`, `AnySubgroupObjectWriter`,
  `AnyFetchObjectReader`, `AnyFetchObjectWriter`, `AnyFetchFrame`,
  `reemit_subgroup_object` and the `Any*Object` / `Any*ObjectMeta` values.
  Subgroup and fetch streams on every draft 07-19.
- A fetch object codec for drafts 15-19, per draft and behind the draft-neutral
  seam. From draft-15 a Serialization Flags field decides which of Group ID,
  Subgroup ID, Object ID and Publisher Priority reach the wire; each one omitted
  is taken from the object before it, and from draft-18 the two ID fields are
  deltas whose sign follows the fetch's Group Order. `FetchObjectWriter` on
  drafts 15-19 is the inverse, and `FetchReemit::Unchanged` forwards a frame's
  own bytes rather than re-encoding them, so a stream nothing was removed from
  is reproduced byte for byte.
- An `error_codes` module in all thirteen `draftNN` modules, and an `ALL` const
  on every error, status and termination code enum -- seventy-two in total, each
  the set its own `from_u64` accepts, in ascending wire order.
- `VarInt::encode_moqt` / `decode_moqt` and `version::VarIntEncoding` with
  `DraftVersion::varint_encoding`, which state per draft which integer encoding
  applies. `encode_moqt` / `decode_moqt` on `TrackNamespace`, `Location` and
  `KeyValuePair`.
- Fallible encoders wherever a draft's own decoder would refuse the result:
  `encode_checked` on the subgroup, datagram, object and fetch-object headers
  that lacked one, `AnySubgroupHeader::encode_stream_checked`, and the
  `KeyValuePair` checked forms.
- Draft-neutral accessors: `AnySubgroupHeader::{carries_extension_block,
  subgroup_id_mode, track_alias, group_id, publisher_priority, subgroup_id}`,
  `AnyDatagramHeader::{meta, permits_payload, extensions_permitted}`,
  `AnyFetchHeader::request_id`, `AnyControlMessage::fetch_group_order`, and
  `decode_stream` on the subgroup and fetch header enums.
- Sixteen `CodecError` variants, so rules that shared `InvalidField` -- which no
  draft's session table answers -- can be routed to the close each draft names:
  `ControlMessageLengthMismatch`, `UnknownStreamType`, `UnknownDatagramType`,
  `InvalidTypeValue`, `KeyValueFormatting`, `UnknownMessageParameter`,
  `ParameterValueOutOfRange`, `TrackPropertyValueOutOfRange`,
  `ParameterLengthMismatch`, `InvalidForward`, `InvalidContentExists`,
  `InvalidFilterType`, `SubscriptionFilterMalformed`, `FilterEndGroupOverflow`,
  `InvalidFetchType`, `InvalidRange`, `EndOfTrackObjectId`,
  `ExtensionsOnNonExistentObject` and `PayloadNotPermitted`. **Breaking**:
  `CodecError` is deliberately not `#[non_exhaustive]`, so a `match` without a
  wildcard arm will not compile until the arms are added.
- `ObjectStatus::ALL` and `as_u64` on all thirteen drafts, `as_u8` on drafts
  17-19 and the shared type, `PayloadPermission` on draft-14 and drafts 15-19,
  and the `permits_payload` / `extensions_permitted` / `properties_permitted`
  predicates that go with them.
- `types::{check_location_range, check_group_range,
  check_open_ended_group_range}`. Three rather than one because the drafts spell
  a range end three ways, and one comparison refuses frames two of them permit.

### Changed

- **Breaking (toolchain):** declared MSRV moves from 1.83 to 1.88.
- **Breaking (API):** `AnyDatagramHeader::encode` returns
  `Result<(), CodecError>`.
- **Breaking (API):** `types::Role` is gone on drafts 08, 09 and 10, which do
  not define the parameter.
- **Breaking (API):** `draft07::types::ObjectStatus::EndOfTrack` is renamed
  `EndOfTrackAndGroup`; draft-07's `0x5` is End of Subgroup and not the later
  drafts' End of Track.
- **Breaking (API):** `draft14::error_codes::PublishDoneStatusCode` is renamed
  and renumbered.
- **Breaking (API):** drafts 17-19 `data_stream::DatagramHeader` gains a public
  `properties: Vec<u8>` field, which its decoder always read and its encoder
  never wrote.
- **Breaking (API):** drafts 12 and 13 rename `FetchPayload::Joining`'s first
  field to `joining_request_id`.
- **Breaking (API):** `AnyFetchObjectReader::new` and
  `AnyFetchObjectWriter::new` take the fetch's Group Order, and
  `new_with_group_order` is gone. On drafts 18 and 19 a Group ID is a difference
  whose sign the order decides, nothing on the data stream carries it, and a
  descending stream read as ascending does not fail — it decodes, under Group
  IDs walking the wrong way, which neither side can detect afterwards. The
  order was a default; it is now an argument, and
  `AnyControlMessage::fetch_group_order` above is what answers it. Ignored on
  drafts 07-17, where Group IDs are values rather than differences.
- **Breaking (behaviour):** `types::ObjectStatus` is renumbered.
- `ControlMessage::encode` on drafts 11-19 applies the value rules its own
  decoder applies -- AUTHORIZATION TOKEN structure, subscription filter, and
  parameter value ranges -- so a message that could be written and not read back
  is refused at the call that writes it. Drafts 15 and 16 needed their parameter
  encoder split per namespace to do it.

### Removed

- **Breaking:** seven `KeyValuePair` entry points. `encode_checked`, and the
  whole MoQT-varint half of the module -- `encode_moqt`, `decode_moqt`,
  `encode_moqt_checked`, `encode_list_moqt`, `encode_list_moqt_checked` and
  `decode_list_moqt`. Every draft that reaches for the MoQT varint also
  delta-codes the parameter type; these six wrote it absolutely, so they
  serialized a shape no draft reads.

### Fixed

Wire-incompatible -- 0.3.0 and earlier put different bytes on the wire:

- `LARGEST_OBJECT` (`0x09`) was length-prefixed on drafts 18 and 19, which frame
  it as a Location. Corrects the 0.2.0 entry that recorded the change.
- `TRACK_NAMESPACE_PREFIX` (`0x34`) carried an extra outer varint length on
  drafts 18 and 19.
- Draft-12 numbered OBJECT_DATAGRAM_STATUS `0x02`/`0x03`, where draft-12 puts
  the payload form.
- Drafts 07-13 wrote a datagram under a different type field than they read it
  with.
- Drafts 11, 12 and 13 read a two-bit type table as independent flags, dropped a
  subgroup object's extension block on write and misread it on the far side, and
  substituted a header's Subgroup ID.
- Drafts 11, 12 and 13 encoded Group Order, Forward, Content Exists and End Of
  Track as varints where the figures give single bytes; draft-13 likewise.
- Drafts 09-13 wrote the extension-block length from the bytes rather than the
  declared field.
- Draft-16 wrote and read absolute Key-Value-Pair types where the draft
  delta-encodes them.
- Draft-15 wrote the Publisher Priority byte when the struct held one rather
  than when the type byte said the field was present.
- Drafts 17-19 used RFC 9000's variable-length integer instead of MoQT's.
  Non-minimal encodings are accepted as required; draft-17's undefined 7-byte
  form is refused with `VarIntError::InvalidCodePoint`.
- Draft-13 `TRACK_STATUS` carried none of the fields its Filter Type announces.

Frames that are now refused, each on the drafts that require the close:

- An unread subscription filter (Filter Type, length disagreement, and drafts 18
  and 19's End Group Delta running past 2^64-1), an unparsed AUTHORIZATION TOKEN
  value, an unknown Message Parameter on drafts 16-19, a parameter value outside
  its range, a parameter whose type implies a length it does not have, a
  repeated Parameter Type, an unassigned Fetch Type, a Content Exists other than
  0 or 1, and a Forward other than 0 or 1.
- Object status code points the drafts do not assign, on all thirteen drafts and
  on both sides; a status paired with a payload the draft gives it no room for;
  and extension headers beside a status that forbids them.
- Stream and datagram Types no table assigns, and the Types drafts 16-19 declare
  invalid within a form they do define. Draft-18 padding streams and datagrams
  are refused rather than misread as data.
- A control message whose declared Length disagrees with its fields, in both
  directions -- fields running past the end used to report `UnexpectedEnd`, the
  variant that means "still arriving".
- A requested range that ends before it starts; a Track Namespace outside its
  field count on encode; an end-of-track object with a non-zero Object ID on
  drafts 08-10; a repeated Setup Option on drafts 17-19; a draft-08 Extension
  Count disagreeing with its bytes.

Other:

- `AnySubgroupHeader::subgroup_id` no longer reports an ID for a draft-15 or
  draft-16 header whose stream type does not carry one, and
  `subgroup_id_mode` answers on those two drafts.
- An Object Status is no longer dropped when a payload is present on drafts
  07-13, and the 65,535-byte cap is gone from the drafts 07-10 encoders, which
  their drafts do not state.
- Draft-16 accepts a Track Namespace Prefix of zero fields in
  SUBSCRIBE_NAMESPACE, and a DELIVERY_TIMEOUT of zero is refused in both
  namespaces.
- The duplicate-parameter rule is asymmetric on drafts 11-16 and was applied
  symmetrically.
- A fetch stream can be opened: `decode_stream` consumes the stream-type field
  the per-draft decoders used to leave in place.

### Known gaps against draft-19

- Parameter scope is not enforced: a parameter legal in one message is accepted
  in any message that carries parameters. Where it belongs is an open question —
  a decoder that refuses non-conforming traffic cannot observe it, so an opt-in
  validator may be the right home rather than `decode`.
- `Properties` on an Object whose status is not Normal are read and written
  rather than refused. Reported by `properties_permitted` instead: the frame is
  well formed, and one of this crate's own vectors is exactly it, so a codec
  that refused it could not reproduce a capture.

## [0.3.0] - 2026-07-08

Adds MoQT draft-19 support. Test-vector submodule pinned to v0.10.0.

### Added

- New `draft19` module behind a `draft19` feature flag, with full control
  message and data stream encode/decode coverage. `all-drafts` now enables it.
- `DraftVersion::Draft19` variant, `moqt-19` ALPN, and dispatch enum
  (`AnyControlMessage`, `AnySubgroupHeader`, `AnyDatagramHeader`,
  `AnyFetchHeader`) variants for draft-19.
- Range Filter parameters (length-prefixed): `SUBGROUP_FILTER` (`0x25`),
  `OBJECTID_FILTER` (`0x26`), `PRIORITY_FILTER` (`0x27`),
  `OBJECT_PROPERTY_FILTER` (`0x28`) and `TRACK_PROPERTY_FILTER` (`0x29`).
- Setup Options `MAX_FILTER_RANGES` (`0x06`) and `MAX_REQUEST_UPDATES`
  (`0x08`), both even KVP types carrying a varint value.
- New `request_error_codes::CONFLICTING_FILTERS` (`0x35`) and
  `INVALID_FILTER` (`0x36`).

### Changed

- `GoAway` no longer carries a `request_id`; the control-stream and
  request-stream forms are now identical on the wire.
- `PublishBlocked` renamed to `PublishSkipped` (message type `0x0F`
  unchanged; wire layout identical).
- `SUBSCRIPTION_FILTER` renamed to `LOCATION_FILTER` (parameter `0x21`
  unchanged).
- `GROUP_ORDER` (`0x22`) is now valid in `SubscribeTracks` rather than
  `PUBLISH_OK`.

### Removed

- `request_error_codes::DUPLICATE_SUBSCRIPTION` (`0x19`); multiple
  concurrent subscriptions per Track are now allowed.

## [0.2.0] - 2026-05-13

Adds MoQT draft-18 support. Test-vector submodule pinned to v0.9.1.

### Added

- New `draft18` module behind a `draft18` feature flag, with full control
  message and data stream encode/decode coverage. `all-drafts` now enables it.
- `DraftVersion::Draft18` variant, `moqt-18` ALPN, and dispatch enum
  (`AnyControlMessage`, `AnySubgroupHeader`, `AnyDatagramHeader`,
  `AnyFetchHeader`) variants for draft-18.
- New control messages and fields: `SubscribeTracks` (type `0x51`);
  `RequestOk` gains a trailing `track_properties` block; `RequestError`
  gains an optional `Redirect` structure; `GoAway` gains an optional
  `request_id` (control stream only). New `request_error_codes::REDIRECT`
  (`0x34`) and `UNSUPPORTED_EXTENSION` (`0x33`); `publish_done_codes::{
  TOO_FAR_BEHIND, EXPIRED}` constants reflect draft-18's swapped values.
- New parameters and accessors: `OBJECT_DELIVERY_TIMEOUT` (renamed from
  `DELIVERY_TIMEOUT`, `0x02`), `SUBGROUP_DELIVERY_TIMEOUT` (`0x06`),
  `FILL_TIMEOUT` (`0x0A`, FETCH only), `TRACK_NAMESPACE_PREFIX` (`0x34`).
- Subgroup data-stream `FIRST_OBJECT` bit (`0x40`) plus `is_first_object`
  accessor; type ranges expand to `0x10..0x1F`, `0x30..0x3F`,
  `0x50..0x5F`, `0x70..0x7F`.

### Changed

- `SUBSCRIBE_NAMESPACE` renumbered to `0x50`; the `subscribe_options` field
  is removed. The previous publish-side behavior moved to the new
  `SubscribeTracks` (`0x51`) message, which carries the FORWARD parameter.
- `PUBLISH_OK` collapsed into `REQUEST_OK` (`0x07`).
- Required Request ID Delta field removed from every request message
  (`Subscribe`, `Publish`, `Fetch`, `RequestUpdate`, `TrackStatus`,
  `PublishNamespace`, `SubscribeNamespace`).
- ~~`LARGEST_OBJECT` (`0x09`) now length-prefixed (was two consecutive varints
  in draft-17).~~ **This entry was wrong and is corrected in 0.4.0.** Draft-18
  did not change the encoding: Section 10.2.11 says "is a Location", the same
  words draft-17 uses. The 0.2.0 release shipped the length-prefixed framing
  described here, so a draft-18 peer talking to that version sees the bug and
  not the entry — struck through rather than deleted for that reason.

## [0.1.0] - 2026-04-16

Initial release. Covers MoQT drafts draft-07 through draft-17.

### Added

- QUIC variable-length integer (VarInt) encoding/decoding per RFC 9000
- Key-value parameter (KVP) encoding/decoding
- Per-draft modules for every MoQT draft from draft-07 through draft-17, each
  behind its own feature flag (`draft07`..`draft17`). `all-drafts` enables
  every draft and is the default.
- All 30 control message types: setup, subscribe, publish, fetch, namespace, track status, goaway
- Data stream headers: SubgroupHeader, DatagramHeader, FetchHeader, ObjectHeader
- Core protocol types: TrackNamespace, Location, FilterType, GroupOrder, ObjectStatus
- Session and request error codes per draft
- `dispatch` module with runtime draft-dispatch enums: `AnyControlMessage`,
  `AnySubgroupHeader`, `AnyFetchHeader`, `AnyDatagramHeader`,
  `AnyObjectHeader`. Each variant is gated on its draft feature flag and
  `decode` / `encode` select the draft from a `DraftVersion` at runtime.
- `AnyControlMessage::is_setup` helper that recognizes the setup message
  variant for each draft (including draft-17's unified `Setup`).

### Notes

- Draft-14 has no standalone `AnyObjectHeader::Draft14` variant — subgroup
  objects are delta-encoded and require the stateful
  `draft14::data_stream::SubgroupObjectReader`.

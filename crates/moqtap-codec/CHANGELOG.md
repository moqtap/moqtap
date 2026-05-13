# Changelog

All notable changes to moqtap-codec will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- `LARGEST_OBJECT` (`0x09`) now length-prefixed (was two consecutive varints
  in draft-17).

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

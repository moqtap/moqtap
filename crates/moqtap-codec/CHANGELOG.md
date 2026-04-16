# Changelog

All notable changes to moqtap-codec will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

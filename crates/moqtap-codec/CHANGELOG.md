# Changelog

All notable changes to moqtap-codec will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-21

Initial release targeting MoQT draft-ietf-moq-transport-14.

### Added

- QUIC variable-length integer (VarInt) encoding/decoding per RFC 9000
- Key-value parameter (KVP) encoding/decoding
- All 30 control message types: setup, subscribe, publish, fetch, namespace, track status, goaway
- Data stream headers: SubgroupHeader, DatagramHeader, FetchHeader, ObjectHeader
- Core protocol types: TrackNamespace, Location, FilterType, GroupOrder, ObjectStatus
- Session and request error codes per draft-14

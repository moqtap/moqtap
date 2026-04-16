# Changelog

All notable changes to moqtap-trace will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

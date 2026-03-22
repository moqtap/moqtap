# Changelog

All notable changes to moqtap-trace will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-21

Initial release targeting MoQT draft-ietf-moq-transport-14.

### Added

- `TraceEvent` type capturing control messages, data streams, objects, errors
- `.moqtrace` binary file format (magic header + JSON-lines)
- `MoqTraceWriter` / `MoqTraceReader` for file I/O
- `SessionMetrics` aggregation: objects, bytes, control messages, duration, errors

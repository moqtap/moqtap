# Changelog

All notable changes to moqtap-client will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-21

Initial release targeting MoQT draft-ietf-moq-transport-14.

### Added

- Session state machine: Connecting -> SetupExchange -> Active -> Draining -> Closed
- CLIENT_SETUP / SERVER_SETUP validation
- Version negotiation
- Request ID allocator with client/server parity enforcement (even/odd)
- Pure endpoint state machine with all subscribe, fetch, and namespace flows
- QUIC transport layer via quinn with TLS (rustls)
- Async `Connection` type: connect, accept, send/recv control messages
- Data stream support: subgroup streams, fetch streams, datagrams
- Framed message I/O with automatic varint-length parsing

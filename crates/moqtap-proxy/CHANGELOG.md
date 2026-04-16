# Changelog

All notable changes to moqtap-proxy will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-04-16

Initial release — transparent MoQT intercepting proxy. Covers MoQT drafts
draft-07 through draft-17.

### Added

- Transparent proxy that forwards all streams and datagrams between client and relay
- Inline MoQT frame parsing for control messages, data stream headers, and datagrams
  via `moqtap-codec`'s runtime dispatch (`AnyControlMessage`,
  `AnySubgroupHeader`, `AnyFetchHeader`, `AnyDatagramHeader`). The draft
  used for parsing is selected from the observed setup exchange rather
  than a compile-time flag.
- `ProxyObserver` trait for structured event emission (11 event types)
- `ProxyHook` trait for optional frame mutation before forwarding
- QUIC listener (`Listener`) for accepting inbound client connections
- WebTransport listener (`WtListener`) behind `webtransport` feature flag
- Upstream QUIC and WebTransport connection support (`UpstreamTransportType`)
- `ListenerMode` for choosing client-facing transport (QUIC or WebTransport)
- Control stream parser with draft-aware framing
- Data stream parser for subgroup and fetch stream headers
- Self-signed certificate generation behind `cert-gen` feature flag
- Graceful shutdown via `CancellationToken`

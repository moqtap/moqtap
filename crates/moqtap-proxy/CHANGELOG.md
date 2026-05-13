# Changelog

All notable changes to moqtap-proxy will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-05-13

Adds MoQT draft-18 to the advertised ALPN set and unifies the client-facing
listener. Bumps `moqtap-codec` and `moqtap-client` to `0.2`.

### Added

- `moqt-18` ALPN is now advertised by `Listener`, so draft-18 clients can
  connect to the proxy without any further configuration.
- `AcceptedConn` enum returned by `Listener::accept` — carries either a
  raw `quinn::Connection` plus the negotiated ALPN, or a
  `wtransport::Connection` for WebTransport clients (behind the
  `webtransport` feature).
- `ProxyEvent::Connected` gains a `client_transport` field so observers
  can label per-client sessions by transport (`"QUIC"` /
  `"WebTransport"`).
- New integration tests `proxy_forward.rs` and `proxy_hook_rewrite.rs`
  covering end-to-end forwarding and `ProxyHook`-driven byte mutation
  against a fake relay; shared scaffolding lives in
  `tests/common/mod.rs`.

### Changed

- Unified the client-facing listener. `Listener` now owns a single
  `quinn::Endpoint` that advertises every supported MoQT draft ALPN
  (`moq-00`, `moqt-15`, `moqt-16`, `moqt-17`, `moqt-18`) plus `h3`
  (behind the `webtransport` feature). Each accepted connection is
  dispatched to raw QUIC or WebTransport based on the negotiated ALPN.
  No listener-mode configuration is required — clients pick their
  transport via ALPN.

### Removed

- `ListenerMode` enum and the `ProxyConfig::listener_mode` field.
- Standalone `WtListener` type. The unified `Listener` handles both
  transports when the `webtransport` feature is enabled.
- `ListenerConfig::alpn` field. ALPNs are derived from the supported
  drafts and the `webtransport` feature.

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
- WebTransport support behind `webtransport` feature flag
- Upstream QUIC and WebTransport connection support (`UpstreamTransportType`)
- Control stream parser with draft-aware framing
- Data stream parser for subgroup and fetch stream headers
- Self-signed certificate generation behind `cert-gen` feature flag
- Graceful shutdown via `CancellationToken`

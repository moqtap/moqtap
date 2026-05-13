# Changelog

All notable changes to moqtap-client will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-05-13

Adds MoQT draft-18 support and broadens the `dispatch` facade with
draft-agnostic helpers. Bumps `moqtap-codec` to `0.2`.

### Added

- New `draft18` module behind a `draft18` feature flag, with its own
  connection, endpoint, session state, per-flow state machines, event
  type, and observer trait. `all-drafts` now enables it.
- `dispatch::AnyClientConfig` and `dispatch::AnyTransportType` for
  draft-agnostic configuration; `AnyConnection::connect` constructs the
  per-draft `ClientConfig` from these and dispatches to the right draft.
- Draft-agnostic helpers on `AnyConnection`: `recv_and_dispatch`,
  `subscribe`, `unsubscribe`, `fetch`, `track_status`, `subscribe_namespace`,
  `subscribe_update`. Drafts that do not expose a given operation return
  an informative `AnyConnectionError`.
- `dispatch::NoOpObserver` for tests and bring-up code that don't need
  event delivery.
- Draft-18 client API: `Connection::subscribe_tracks` for the new
  `SUBSCRIBE_TRACKS` request type; `subscribe_namespace` no longer takes
  a `subscribe_options` argument.

### Changed

- `Connection::connect` (every draft) now buffers the CLIENT_SETUP /
  SERVER_SETUP / `SetupComplete` events that occur during the handshake
  and replays them to the observer when one is attached via
  `set_observer`. Without this, observers attached after `connect`
  returned would never see the setup exchange.

## [0.1.0] - 2026-04-16

Initial release. Covers MoQT drafts draft-07 through draft-17.

### Added

- Per-draft client modules for every MoQT draft from draft-07 through
  draft-17 (`draft07`..`draft17`), each with its own connection, endpoint,
  session state, per-flow state machines, event type, and observer trait
  (`moqtap_client::draft14::connection::Connection`, etc.). Each is behind
  its matching feature flag; `all-drafts` enables them all. `draft14` is the
  default.
- Session state machine: Connecting -> SetupExchange -> Active -> Draining -> Closed
- CLIENT_SETUP / SERVER_SETUP validation and version negotiation
- Request ID allocator with client/server parity enforcement (even/odd)
- Pure endpoint state machine with all subscribe, fetch, and namespace flows
- QUIC transport layer via quinn with TLS (rustls)
- Async `Connection` type: connect, accept, send/recv control messages
- Data stream support: subgroup streams, fetch streams, datagrams
- Framed message I/O with automatic varint-length parsing
- `dispatch` module with draft-agnostic entry-point types for downstream
  consumers: `AnyConnection`, `AnyClientEvent`, `AnyConnectionObserver`.
  Observer attachment adapts the unified observer into the per-draft trait
  on the inner connection.

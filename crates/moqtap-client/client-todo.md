# moqtap-client — Remaining Work

## Scope

moqtap-client is an **outbound MoQT client** library. It connects to relays/servers
over QUIC and performs subscriber-side and publisher-side protocol flows. It does NOT
accept inbound connections, generate certificates, or act as a proxy — those concerns
belong to [`moqtap-proxy`](../moqtap-proxy).

## What's implemented

### Pure state machines (no I/O, fully tested)

- [x] `SessionStateMachine` — Connecting → SetupExchange → Active → Draining → Closed
- [x] `RequestIdAllocator` — even/odd parity, MAX_REQUEST_ID bounds, blocking
- [x] `SubscriptionStateMachine` — subscribe/ok/error/unsubscribe/update/publish_done
- [x] `FetchStateMachine` — fetch/ok/error/cancel/stream_fin/stream_reset
- [x] `SubscribeNamespaceStateMachine` / `PublishNamespaceStateMachine`
- [x] `TrackStatusStateMachine` — track_status/ok/error
- [x] `PublishStateMachine` — publish/ok/error/done
- [x] `Endpoint` — orchestrates all state machines, dispatches inbound messages

### Connection layer (async I/O over QUIC)

- [x] `Connection::connect()` — outbound QUIC with TLS, setup handshake
- [x] Control stream send/recv with varint-length framing
- [x] Subscribe, unsubscribe, fetch, fetch_cancel flows
- [x] Subscribe namespace, publish namespace flows
- [x] Track status flow
- [x] Publish, publish_done flows
- [x] Subgroup streams (open/accept)
- [x] Datagram send/receive
- [x] `FramedSendStream` / `FramedRecvStream` — MoQT framing
- [x] Custom CA cert loading (`ca_certs` field)
- [x] Configurable ALPN (`alpn` field)
- [x] `ConnectionObserver` trait + `NoOpObserver`
- [x] `ClientEvent` enum

### Code quality

- [x] `#![deny(missing_docs)]` — all public items documented
- [x] 87+ integration tests across 11 test files (~3,000 lines)

## What's remaining

### Client-side gaps

- [ ] **WebTransport client transport.** `Connection::connect()` uses raw QUIC only.
  Need a WebTransport client path (HTTP/3 CONNECT with `:protocol = webtransport`).
  The `webtransport` feature flag exists but is a compile-time error until implemented.
  Requires `h3` + `h3-quinn` dependencies.

- [ ] **Connection integration tests.** All network I/O paths are untested
  (by design — "no test requires network access"). Consider adding loopback
  integration tests using a quinn server+client pair for:
  - `Connection::connect()` with setup handshake
  - Control message round-trip
  - Subgroup stream open/accept
  - Datagram send/receive
  - Observer event emission during real I/O

- [ ] **Graceful shutdown.** `Connection` has no `CancellationToken` integration.
  Long-running recv loops can't be cancelled cleanly. Consider adding:
  - `CancellationToken` parameter to `Connection::connect()`
  - GOAWAY → close sequence on cancellation
  - Configurable drain timeout for in-flight data streams

### Codec dependency (for proxy runtime draft detection)

- [ ] **Runtime draft dispatch in moqtap-codec.** The proxy's inline parser needs
  to select the decoder at runtime based on the setup exchange. Currently the codec
  uses compile-time feature flags. Need a version-aware decode entrypoint. This is
  tracked here because it's a codec change driven by client/proxy needs.

## What moved to moqtap-proxy

The following items from the original plan are now in the `moqtap-proxy` crate:

- Self-signed certificate generation → `moqtap-proxy::cert` (behind `cert-gen` feature)
- QUIC listener / server-side accept → `moqtap-proxy::listener`
- Inline MoQT frame parser → `moqtap-proxy::parser`
- ProxyObserver / ProxyHook traits → `moqtap-proxy::observer`, `moqtap-proxy::hook`
- ProxySession (per-connection forwarding) → `moqtap-proxy::session`
- TransparentProxy (accept loop) → `moqtap-proxy::proxy`
- ProxyEvent / ProxySide / SessionId → `moqtap-proxy::event`

## Separation of concerns

```
moqtap-client                          moqtap-proxy
─────────────                          ────────────
Outbound QUIC connections              Inbound QUIC listener
MoQT state machines                    No MoQT state (transparent forwarding)
Protocol flow methods                  Inline frame parsing (observation only)
FramedSendStream / FramedRecvStream    Raw byte piping with parser overlay
ConnectionObserver (client events)     ProxyObserver (proxy events)
                                       ProxyHook (optional mutation)
                                       Self-signed cert generation
                                       CancellationToken / graceful shutdown
```

The proxy reuses `Transport`, `QuicTransport`, `SendStream`, and `RecvStream` from
moqtap-client as its transport abstraction. It does NOT use `Connection`, `Endpoint`,
or any state machines.

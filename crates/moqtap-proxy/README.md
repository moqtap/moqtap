# moqtap-proxy

Transparent MoQT intercepting proxy — sits between a client and relay, forwarding all bytes bidirectionally while parsing MoQT frames inline to produce structured events.

The proxy does **not** participate in MoQT state management. It observes and optionally mutates, but never acts as an endpoint. Supports every MoQT wire format from **draft-07 through draft-18** at runtime via `moqtap-codec`'s dispatch layer — the draft is selected from the observed setup exchange.

## What it does

1. **Listen** on a single UDP port that accepts raw-QUIC MoQT and WebTransport clients simultaneously. The client-facing transport is chosen by ALPN: every supported MoQT draft (`moq-00`, `moqt-15`, `moqt-16`, `moqt-17`, `moqt-18`) plus `h3` for WebTransport is advertised.
2. **Connect** upstream to a MoQT relay (QUIC or WebTransport)
3. **Forward** all streams (bidirectional, unidirectional) and datagrams between the two
4. **Parse** MoQT frames inline — control messages, data stream headers, object headers, datagrams
5. **Emit** structured `ProxyEvent`s via the `ProxyObserver` trait (11 event types including setup detection)
6. **Optionally mutate** forwarded bytes via the `ProxyHook` trait (for fault injection, protocol testing)

```
Client ──QUIC/WT──▶ moqtap-proxy ──QUIC/WT──▶ Relay
                       │
                       ├─ parses frames inline (draft-07..18)
                       ├─ emits ProxyEvents
                       └─ applies ProxyHook mutations
```

## Key types

| Type | Description |
|------|-------------|
| `TransparentProxy` | Accept loop orchestrator — binds listener, spawns per-connection sessions |
| `ProxySession` | Per-connection forwarder — pipes streams + datagrams between client and relay |
| `ProxyConfig` | Top-level configuration (listener, session) |
| `Listener` | Unified server endpoint — accepts both raw-QUIC MoQT and WebTransport on the same UDP port, dispatched by ALPN |
| `AcceptedConn` | Enum returned by `Listener::accept`: `Quic { conn, alpn }` or `WebTransport(conn)` |
| `UpstreamTransportType` | Upstream relay transport: `Quic` or `WebTransport { url }` |
| `ProxyObserver` | Trait for receiving structured events (implement for logging, tracing, GUI) |
| `ProxyHook` | Trait for optional frame mutation (return `Some(bytes)` to replace, `None` to pass through) |
| `ControlStreamParser` | Stateful inline parser for control stream messages (draft-aware framing) |
| `DataStreamParser` | Stateful inline parser for data stream headers and objects |
| `GeneratedCert` | Self-signed certificate for development/testing (behind `cert-gen` feature) |

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  Caller (CLI / GUI)                                 │
│  Provides ProxyObserver + ProxyHook implementations │
└──────────────────────┬──────────────────────────────┘
                       │ drives
┌──────────────────────▼──────────────────────────────┐
│  moqtap-proxy                                       │
│                                                     │
│  TransparentProxy                                   │
│    └─ Listener (QUIC + WebTransport, ALPN dispatch) │
│    └─ ProxySession (per-connection)                 │
│         ├─ forward_control_stream (with parser)     │
│         ├─ forward_uni_streams (with parser)        │
│         └─ forward_datagrams                        │
│                                                     │
│  Parsers: ControlStreamParser, DataStreamParser     │
│  Events: ProxyEvent (11 types), ProxySide, SessionId│
└──────────────────────┬──────────────────────────────┘
        uses           │
┌──────────┐  ┌────────▼─────────┐
│ moqtap-  │  │ moqtap-client    │
│ codec    │  │ (transport only) │
│ (decode) │  │ Transport, QUIC  │
└──────────┘  └──────────────────┘
```

## Responsibility boundaries

**moqtap-proxy IS responsible for:**
- Accepting inbound connections on a single UDP port (raw QUIC and WebTransport simultaneously, dispatched by negotiated ALPN)
- Advertising ALPNs for every supported MoQT draft plus `h3` when `webtransport` is enabled
- Self-signed certificate generation (behind `cert-gen` feature)
- Connecting to upstream relays (QUIC or WebTransport)
- Stream-level forwarding (bidirectional, unidirectional, datagrams)
- Inline MoQT frame parsing for observation (drafts 07 through 18, via
  `moqtap-codec`'s dispatch enums)
- Automatic stream type detection (subgroup vs fetch) on unidirectional streams
- Setup message detection (CLIENT_SETUP / SERVER_SETUP emitted as distinct events)
- Event emission via `ProxyObserver`
- Optional byte mutation via `ProxyHook`
- Graceful shutdown via `CancellationToken`

**moqtap-proxy is NOT responsible for:**
- MoQT protocol state management (no subscribe/fetch/publish state machines)
- Deciding what to forward/filter/modify (caller provides hooks)
- Trace file I/O (caller wires events to `moqtap-trace`)
- User interface

## Feature flags

| Feature | Default | Description |
|---------|---------|-------------|
| `cert-gen` | no | Self-signed certificate generation via `rcgen` |
| `webtransport` | no | Enables the `h3` ALPN on the unified listener plus WebTransport upstream support via `wtransport` |

## License

MIT

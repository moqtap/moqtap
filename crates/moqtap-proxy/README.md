# moqtap-proxy

Transparent MoQT intercepting proxy — sits between a client and relay, forwarding all bytes bidirectionally while parsing MoQT frames inline to produce structured events.

The proxy does **not** participate in MoQT state management. It observes and optionally mutates, but never acts as an endpoint.

## What it does

1. **Listen** for inbound connections from MoQT clients (QUIC or WebTransport)
2. **Connect** upstream to a MoQT relay (QUIC or WebTransport)
3. **Forward** all streams (bidirectional, unidirectional) and datagrams between the two
4. **Parse** MoQT frames inline — control messages, data stream headers, object headers, datagrams
5. **Emit** structured `ProxyEvent`s via the `ProxyObserver` trait
6. **Optionally mutate** forwarded bytes via the `ProxyHook` trait (for fault injection, protocol testing)

```
Client ──QUIC/WT──▶ moqtap-proxy ──QUIC/WT──▶ Relay
                       │
                       ├─ parses frames inline
                       ├─ emits ProxyEvents
                       └─ applies ProxyHook mutations
```

## Key types

| Type | Description |
|------|-------------|
| `TransparentProxy` | Accept loop orchestrator — binds listener, spawns per-connection sessions |
| `ProxySession` | Per-connection forwarder — pipes streams + datagrams between client and relay |
| `ProxyConfig` | Top-level configuration (listener, session, listener mode) |
| `ListenerMode` | Client-facing transport: `Quic` or `WebTransport` |
| `Listener` | QUIC server endpoint that accepts inbound connections |
| `WtListener` | WebTransport server endpoint (behind `webtransport` feature) |
| `UpstreamTransportType` | Upstream relay transport: `Quic` or `WebTransport { url }` |
| `ProxyObserver` | Trait for receiving structured events (implement for logging, tracing, GUI) |
| `ProxyHook` | Trait for optional frame mutation (return `Some(bytes)` to replace, `None` to pass through) |
| `ControlStreamParser` | Stateful inline parser for control stream messages |
| `DataStreamParser` | Stateful inline parser for data stream headers and objects |
| `GeneratedCert` | Self-signed certificate for development/testing (behind `cert-gen` feature) |

## Architecture

```
┌────────────────────────────────────────────────────┐
│  Caller (CLI / GUI)                                 │
│  Provides ProxyObserver + ProxyHook implementations │
└──────────────────────┬─────────────────────────────┘
                       │ drives
┌──────────────────────▼─────────────────────────────┐
│  moqtap-proxy                                       │
│                                                     │
│  TransparentProxy                                   │
│    └─ Listener (QUIC) or WtListener (WebTransport)  │
│    └─ ProxySession (per-connection)                 │
│         ├─ forward_control_stream (with parser)     │
│         ├─ forward_uni_streams (with parser)        │
│         └─ forward_datagrams                        │
│                                                     │
│  Parsers: ControlStreamParser, DataStreamParser     │
│  Events: ProxyEvent, ProxySide, SessionId           │
└─────────────────────┬──────────────────────────────┘
        uses           │
┌──────────┐  ┌────────▼────────┐
│ moqtap-  │  │ moqtap-client   │
│ codec    │  │ (transport only) │
│ (decode) │  │ Transport, QUIC  │
└──────────┘  └─────────────────┘
```

## Responsibility boundaries

**moqtap-proxy IS responsible for:**
- Accepting inbound connections (QUIC or WebTransport, server-side TLS)
- Self-signed certificate generation (behind `cert-gen` feature)
- Connecting to upstream relays (QUIC or WebTransport)
- Stream-level forwarding (bidirectional, unidirectional, datagrams)
- Inline MoQT frame parsing for observation (draft-07 and draft-14)
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
| `webtransport` | no | WebTransport listener and upstream support via `wtransport` |

## License

MIT

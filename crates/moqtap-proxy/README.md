# moqtap-proxy

Transparent MoQT intercepting proxy — sits between a client and relay, forwarding all bytes bidirectionally while parsing MoQT frames inline to produce structured events.

The proxy does **not** participate in MoQT state management. It observes and optionally mutates, but never acts as an endpoint. Supports every MoQT wire format from **draft-07 through draft-20** at runtime via `moqtap-codec`'s dispatch layer — the draft is selected from the observed setup exchange.

## What it does

1. **Listen** on a single UDP port that accepts raw-QUIC MoQT and WebTransport clients simultaneously. The client-facing transport is chosen by ALPN: every supported MoQT draft (`moq-00` for drafts 07-14, then `moqt-15`, `moqt-16`, `moqt-17`, `moqt-18`, `moqt-19`, `moqt-20`) plus `h3` for WebTransport is advertised.
2. **Connect** upstream to a MoQT relay (QUIC or WebTransport)
3. **Forward** all streams (bidirectional, unidirectional) and datagrams between the two
4. **Parse** MoQT frames inline — control messages, data stream headers, individually addressable objects, datagrams
5. **Emit** structured `ProxyEvent`s via the `ProxyObserver` trait (18 event types including setup detection)
6. **Optionally act** on what it forwarded, via the `ProxyHook` trait or a `ShapeProfile` — pass, replace, delay, hold, elide, truncate, reset a stream, close the session

```
Client ──QUIC/WT──▶ moqtap-proxy ──QUIC/WT──▶ Relay
                       │
                       ├─ parses frames inline (draft-07..20)
                       ├─ emits ProxyEvents
                       ├─ executes ProxyHook actions
                       └─ paces objects through a ShapeProfile
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
| `ProxyControl` | Handle on a running proxy — census, statistics, close a session, reset a stream, inject a control message, replace a leg's settings |
| `ProxyObserver` | Trait for receiving structured events (implement for logging, tracing, or a UI) |
| `ProxyHook` | Trait for deciding what happens to a frame, object, datagram or stream. Every method is synchronous, defaulted and returns an `Action` or `StreamAction` the engine executes; `Interest` says which sites are armed at all |
| `Capabilities` | What is expressible at a site, on a draft, on a kind of stream. Ask before acting; the engine asks again and reports a `Refusal` |
| `ShapeProfile` | Named token buckets and class rules that pace media egress with no hook code — configuration rather than callbacks |
| `TransportProfile` | One leg's QUIC transport parameters as a value that can be written down, checked and stored |
| `ObjectFramer` | Frames a unidirectional data stream into individually addressable objects on every draft 07-20, preserving the exact wire bytes |
| `ControlStreamParser` | Stateful inline parser for control stream messages (draft-aware framing) |
| `GeneratedCert` | Self-signed certificate for development/testing (behind `cert-gen` feature) |

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  Caller (application code)                          │
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
│  Parsers: ControlStreamParser, ObjectFramer         │
│  Events: ProxyEvent (18 types), ProxySide, SessionId│
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
- Stream-level forwarding (bidirectional, unidirectional, datagrams). On drafts
  17 through 20, where every request opens a bidirectional stream of its own,
  each direction has an accept loop and all of them are forwarded. On drafts 07
  through 15 a session opens exactly one bidirectional stream, the control
  stream, and that is what is forwarded. Draft-16 is between the two and is
  handled as both: its control stream is the first client-initiated
  bidirectional stream, and draft-16 Section 3.3 gives SUBSCRIBE_NAMESPACE a
  bidirectional stream of its own, so every stream after the control stream is
  forwarded as a request stream — in both directions, because draft-16 Section 6.1 lets
  either endpoint be the subscriber.
- Inline MoQT frame parsing for observation (drafts 07 through 20, via
  `moqtap-codec`'s dispatch enums)
- Automatic stream type detection on unidirectional streams — subgroup, fetch, and on drafts 17-20 the control stream, which those drafts carry as a pair of unidirectional streams rather than a bidirectional one
- Reading a fetch response against the Group Order its FETCH asked for, on drafts 18, 19 and 20, where an object's Group ID is a difference and the order decides whether it counts up or down. The order is on the control plane and never on the data stream, so the session files it under the FETCH's Request ID and hands it to the framer when the response opens. A response naming a request the session never carried is forwarded untouched and reported, rather than read against a guess — the wrong guess decodes every object under Group IDs walking the wrong way
- Setup message detection (CLIENT_SETUP / SERVER_SETUP emitted as distinct events), which is also what settles the session's draft on drafts 07-14, where one ALPN covers all eight
- Event emission via `ProxyObserver`
- Executing a `ProxyHook`'s actions, and refusing the ones a draft or a site cannot express
- Pacing media egress from a `ShapeProfile`, with per-class statistics
- Graceful shutdown via `CancellationToken`

**moqtap-proxy is NOT responsible for:**
- MoQT protocol state management (no subscribe/fetch/publish state machines). The one thing it does remember across messages is what Group Order each FETCH asked for, because on drafts 18, 19 and 20 a fetch response cannot be read without it
- Deciding what to forward, filter or modify — the caller supplies a `ProxyHook` and a `ShapeProfile`
- Interpreting a run. Nothing here reads a file, schedules a change or decides what a failure is; the crate offers a pipeline and an extension point, and a consumer written against them decides the rest
- Trace file I/O (caller wires events to `moqtap-trace`)
- User interface

## Writing the configuration down

Everything above is configured in Rust, which is what a test wants and not what
an operator wants. The `serde` feature derives `Serialize` and `Deserialize` on
the configuration types — the shaping profile with its buckets, classes and
matchers, and both legs' transport parameters — so a caller can read them from a
file instead of building them in code.

It buys the types and nothing else. This crate reads no file and chooses no
format: a consumer deserializes what it wants, hands the profiles to a session,
and drives any later change through `ProxyControl` itself.

`ShapeProfile` is the one type worth knowing about before reading one from a
file. Its fields are private so that `ShapeProfile::try_new` is the only way to
build one, and its `Deserialize` is routed through a public-field mirror,
`ShapeProfileSpec`, whose `TryFrom` calls that constructor. A profile read from
a file therefore runs the same seven validations as one built in Rust — among
them the one that catches a class naming a bucket that does not exist, which
would otherwise parse, arm, report shaping and shape nothing.

## Feature flags

| Feature | Default | Description |
|---------|---------|-------------|
| `all-drafts` | **yes** | Every draft 07-20. Reduced sets are opt-in with `--no-default-features --features draftNN` |
| `draft07` … `draft20` | no | One draft each, in both `moqtap-codec` and `moqtap-client` |
| `cert-gen` | no | Self-signed certificate generation via `rcgen` |
| `webtransport` | no | Enables the `h3` ALPN on the unified listener plus WebTransport upstream support via `wtransport` |
| `impair` | no | Arm and clear a datagram impairment on a leg's socket at runtime, below QUIC, through `quinn-netem` |
| `serde` | no | `Serialize` and `Deserialize` on the configuration types, so a caller can read a shaping or transport profile from a file. No parser and no format: those are the caller's |
| `qlog` | no | A QUIC-level capture per connection, written by quinn. Each leg config carries its own `QlogSpec` |

**This crate has no `src/draftNN/` module and should not grow one.** It spans
every draft at runtime, on `DraftVersion`, because it observes the protocol
rather than implementing it — where `moqtap-codec` and `moqtap-client` use
per-draft modules behind those feature flags. A behaviour that differs by draft
is a predicate on `DraftVersion` here, and
[`ARCHITECTURE.md`](../../ARCHITECTURE.md) says how to write one that cannot
silently answer for a draft it has never met.

## License

MIT

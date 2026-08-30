# moqtap-client

MoQT client — session state, protocol flows and framed I/O over QUIC and
WebTransport, for every draft from draft-07 through draft-19.

A library with no UI: it is driven by another application that decides what to
do and presents the results.

## What it does

Connect to a MoQT relay over QUIC or WebTransport and perform subscriber-side
or publisher-side operations. The caller decides what to subscribe, fetch,
or publish; moqtap-client handles the protocol. On drafts 17, 18 and 19 it
also serves requests a peer opens on a bidirectional stream of its own.

Supports every MoQT draft from **draft-07 through draft-19**. Each draft
lives in its own top-level module (`draft07`..`draft19`) with its own
connection, endpoint state machine, event types, observer trait, and
per-flow state machines. The `transport` module (QUIC / WebTransport) is
shared across drafts.

```rust
use moqtap_client::draft14::connection::{Connection, ClientConfig, TransportType};
use moqtap_codec::version::DraftVersion;
use moqtap_codec::types::*;

let config = ClientConfig {
    draft: DraftVersion::Draft14,
    additional_versions: Vec::new(),
    transport: TransportType::Quic,
    skip_cert_verification: true,
    ca_certs: Vec::new(),
    setup_parameters: Vec::new(),
};
let mut conn = Connection::connect("127.0.0.1:4443", config).await?;

// Wait for MAX_REQUEST_ID, then subscribe
let _ = conn.recv_and_dispatch().await?;
let _req_id = conn.subscribe(
    TrackNamespace(vec![b"live".to_vec()]),
    b"video".to_vec(),
    128,
    GroupOrder::Ascending,
    FilterType::NextGroupStart,
    Vec::new(), // subscribe parameters
).await?;

conn.close(0, b"done");
```

## Draft-agnostic entry point (`dispatch`)

The `dispatch` module is the shared facade for downstream consumers that
need to hold a MoQT connection without compile-time coupling to one draft:

- `AnyConnection` — enum wrapping each enabled draft's `Connection`.
  Exposes `draft`, `set_observer`, `clear_observer`, `close`. For
  draft-specific protocol calls (`subscribe`, `fetch`, `publish`) match on
  the variant.
- `AnyClientEvent` — enum wrapping each draft's `ClientEvent`.
- `AnyConnectionObserver` — trait receiving `AnyClientEvent`.
  `AnyConnection::set_observer` installs a per-draft adapter on the inner
  connection.

## Architecture

```
┌──────────────────────────────────────────────────┐
│  Caller (CLI / GUI / web)                        │
│  Decides what to do, processes events            │
└───────────────────┬──────────────────────────────┘
                    │ drives
┌───────────────────▼──────────────────────────────┐
│  moqtap-client                                   │
│                                                  │
│  ┌────────────────────────────────────────────┐  │
│  │ dispatch                                   │  │
│  │   AnyConnection / AnyClientEvent /         │  │
│  │   AnyConnectionObserver                    │  │
│  └────────────────────┬───────────────────────┘  │
│                       │ wraps                    │
│  ┌────────────────────▼───────────────────────┐  │
│  │ draft07 | draft08 | ... | draft19          │  │
│  │   connection · endpoint · session          │  │
│  │   subscribe · fetch · publish · namespace  │  │
│  │   subgroup streams · datagrams             │  │
│  │   observer · event                         │  │
│  └────────────────────┬───────────────────────┘  │
│                       │                          │
│  ┌────────────────────▼───────────────────────┐  │
│  │ transport (shared across drafts)           │  │
│  │   QuicTransport | WebTransport             │  │
│  └────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────┘
         │ uses
┌────────▼────────┐
│  moqtap-codec   │
│  (wire format)  │
└─────────────────┘
```

## Responsibility boundaries

**moqtap-client IS responsible for:**
- Outbound QUIC and WebTransport connection lifecycle (connect, handshake, close)
- MoQT session state (setup exchange, active, draining, closed)
- All MoQT protocol flows (subscribe, fetch, publish, namespace, track status)
- Request ID allocation with parity enforcement and MAX_REQUEST_ID
- Framed message I/O (control messages with varint- or fixed-length framing,
  measured with the variable-length integer the draft uses)
- Data stream I/O (subgroup streams, fetch streams, datagrams)
- Per-draft wire formats for drafts 07 through 19
- TLS configuration (system roots, custom CAs, skip verification)
- Event emission via the per-draft `ConnectionObserver` trait and the
  draft-agnostic `AnyConnectionObserver`

**moqtap-client is NOT responsible for:**
- Accepting inbound connections — that's `moqtap-proxy`
- TLS certificate generation — that's `moqtap-proxy` (behind `cert-gen` feature)
- Intercepting proxy logic — that's `moqtap-proxy`
- Trace file I/O — that's `moqtap-trace`
- User interface — no stdout, no prompts, no progress bars
- Wire encoding/decoding — that's `moqtap-codec`

## Feature flags

| Feature | Default | Description |
|---------|---------|-------------|
| `draft07`..`draft19` | no | Enable the matching draft's module; forwards the feature to `moqtap-codec` |
| `all-drafts` | yes | Enables every draft; this is `default` |
| `webtransport` | no | WebTransport client support via `wtransport` |

## License

MIT

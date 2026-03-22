# moqtap-client

MoQT protocol engine — the outbound client stack behind moqtap's CLI tools.

This crate provides all MoQT client-side protocol machinery: session state management, protocol flows, framed message I/O, and QUIC transport. It is a pure code package with no UI — designed to be driven by another application (CLI, GUI, or web interface) that makes the decisions and presents the results.

## What it does

Connect to a MoQT relay/server over QUIC and perform subscriber-side or publisher-side operations. The caller decides what to subscribe, fetch, or publish; moqtap-client handles the protocol.

```rust
use moqtap_client::connection::{Connection, ClientConfig, TransportType};
use moqtap_codec::version::DraftVersion;
use moqtap_codec::types::*;

let config = ClientConfig {
    draft: DraftVersion::Draft14,
    transport: TransportType::Quic,
    skip_cert_verification: true,
    ca_certs: Vec::new(),
};
let mut conn = Connection::connect("127.0.0.1:4443", config).await?;

// Wait for MAX_REQUEST_ID, then subscribe
let _ = conn.recv_and_dispatch().await?;
let req_id = conn.subscribe(
    TrackNamespace(vec![b"live".to_vec()]),
    b"video".to_vec(),
    128,
    GroupOrder::Ascending,
    FilterType::NextGroupStart,
).await?;

let (header, mut stream) = conn.accept_subgroup_stream().await?;
let obj = stream.read_object_header().await?;
conn.close(0, b"done");
```

## Architecture

```
┌──────────────────────────────────────────────────┐
│  Caller (CLI / GUI / web)                        │
│  Decides what to do, processes events             │
└───────────────────┬──────────────────────────────┘
                    │ drives
┌───────────────────▼──────────────────────────────┐
│  moqtap-client                                    │
│                                                   │
│  ┌──────────────────────────────────────────┐     │
│  │ Connection (outbound QUIC)               │     │
│  │ subscribe · fetch · publish · namespace  │     │
│  │ subgroup streams · datagrams             │     │
│  └──────────────────┬───────────────────────┘     │
│                     │                             │
│  ┌──────────────────▼───────────────────────┐     │
│  │ Transport abstraction                    │     │
│  │ QuicTransport | WebTransport             │     │
│  └──────────────────┬───────────────────────┘     │
│                     │                             │
│  ┌──────────────────▼───────────────────────┐     │
│  │ Endpoint (pure state machines, no I/O)   │     │
│  │ Session · RequestId · Subscribe · Fetch  │     │
│  │ Namespace · Publish · TrackStatus        │     │
│  └──────────────────────────────────────────┘     │
└───────────────────────────────────────────────────┘
         │ uses
┌────────▼────────┐
│  moqtap-codec   │
│  (wire format)  │
└─────────────────┘
```

## Responsibility boundaries

**moqtap-client IS responsible for:**
- Outbound QUIC connection lifecycle (connect, handshake, close)
- MoQT session state (setup exchange, active, draining, closed)
- All MoQT protocol flows (subscribe, fetch, publish, namespace, track status)
- Request ID allocation with parity enforcement and MAX_REQUEST_ID
- Framed message I/O (control messages with varint-length framing)
- Data stream I/O (subgroup streams, fetch streams, datagrams)
- TLS configuration (system roots, custom CAs, skip verification)
- Event emission via the `ConnectionObserver` trait

**moqtap-client is NOT responsible for:**
- Accepting inbound connections — that's [`moqtap-proxy`](../moqtap-proxy)
- TLS certificate generation — that's `moqtap-proxy` (behind `cert-gen` feature)
- Intercepting proxy logic — that's `moqtap-proxy`
- Trace file I/O — that's `moqtap-trace`
- User interface — no stdout, no prompts, no progress bars
- Wire encoding/decoding — that's `moqtap-codec`

## Feature flags

| Feature | Default | Description |
|---------|---------|-------------|
| `webtransport` | no | WebTransport client support via `wtransport` |

## License

MIT

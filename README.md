# moqtap

A Rust implementation of [MoQT (Media over QUIC Transport)](https://datatracker.ietf.org/doc/draft-ietf-moq-transport/).

moqtap provides a modular crate ecosystem for building MoQT debugging and tracing tools: a wire codec, a QUIC-backed client, session tracing, and a CLI debugging tool.

## Crates

| Crate | Description |
|-------|-------------|
| [`moqtap-codec`](crates/moqtap-codec) | Zero-dependency wire codec — draft-conforming parser and writer for all MoQT messages |
| [`moqtap-client`](crates/moqtap-client) | MoQT protocol client — outbound QUIC transport via quinn, session state machine, subscribe/fetch/publish flows |
| [`moqtap-proxy`](crates/moqtap-proxy) | Transparent intercepting proxy — inline MoQT frame parsing, observer/hook traits, self-signed cert generation |
| [`moqtap-trace`](crates/moqtap-trace) | Trace file I/O — `.moqtrace` binary format reader/writer for integration into relays, clients, and debugging tools |

## Using as a library

Add the crates you need to your `Cargo.toml`:

```toml
[dependencies]
moqtap-codec = "0.1"
moqtap-client = "0.1"
```

Each draft is a separate feature flag on both crates (`draft07`..`draft17`). The client defaults to `draft14`; the codec defaults to `all-drafts`. Enable additional drafts to negotiate them at runtime.

### Connect and subscribe (draft-14)

```rust
use moqtap_client::draft14::connection::{Connection, ClientConfig, TransportType};
use moqtap_codec::version::DraftVersion;
use moqtap_codec::types::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ClientConfig {
        draft: DraftVersion::Draft14,
        additional_versions: Vec::new(),
        transport: TransportType::Quic,
        skip_cert_verification: true,
        ca_certs: Vec::new(),
        setup_parameters: Vec::new(),
    };
    let mut conn = Connection::connect("127.0.0.1:4443", config).await?;

    // Wait for server to grant request IDs, then subscribe
    let _ = conn.recv_and_dispatch().await?;

    let _req_id = conn.subscribe(
        TrackNamespace(vec![b"live".to_vec()]),
        b"video".to_vec(),
        128,
        GroupOrder::Ascending,
        FilterType::NextGroupStart,
    ).await?;

    // Read incoming control messages and data streams...
    Ok(())
}
```

### Draft-agnostic entry point

`moqtap_client::dispatch` provides `AnyConnection`, `AnyClientEvent`, and
`AnyConnectionObserver` — enums with one variant per enabled draft feature.
Match on the variant for draft-specific protocol calls.

### Encode/decode messages (draft-14)

```rust
use moqtap_codec::draft14::message::{ControlMessage, ClientSetup};
use moqtap_codec::varint::VarInt;

let msg = ControlMessage::ClientSetup(ClientSetup {
    supported_versions: vec![VarInt::from_u64(0xff00000e).unwrap()],
    parameters: vec![],
});

let mut buf = Vec::new();
msg.encode(&mut buf).unwrap();

let mut cursor = &buf[..];
let decoded = ControlMessage::decode(&mut cursor).unwrap();
assert_eq!(msg, decoded);
```

For runtime draft dispatch, use `moqtap_codec::dispatch::{AnyControlMessage,
AnySubgroupHeader, AnyFetchHeader, AnyDatagramHeader, AnyObjectHeader}` — each
decodes against a `DraftVersion` selected at runtime from the enabled features.

## Development

Requires Rust 1.75+ and [just](https://github.com/casey/just) (optional).

```sh
# Run all checks (what CI runs)
just check

# Run tests
just test

# Format code
just fmt

# Build release binary
just build

# Dependency audit
just deny
```

## Architecture

```
moqtap-codec          Pure codec, no I/O. Foundation for everything.
    |
    +-- moqtap-client     Outbound QUIC client, endpoint logic, session management.
    |
    +-- moqtap-proxy      Intercepting proxy (depends on codec + client transport).
    |
    +-- moqtap-trace      Event capture, .moqtrace format, metrics.
```

## Spec Compliance

This implementation covers MoQT drafts 07 through 17. Each draft is a
separate module in both `moqtap-codec` and `moqtap-client`.

## License

MIT

# moqtap

A Rust implementation of [MoQT (Media over QUIC Transport)](https://www.ietf.org/archive/id/draft-ietf-moq-transport-14.html) — draft-14.

moqtap provides a modular crate ecosystem for building MoQT debugging and tracing tools: a wire codec, a QUIC-backed client, session tracing, and a CLI debugging tool.

## Crates

| Crate | Description |
|-------|-------------|
| [`moqtap-codec`](crates/moqtap-codec) | Zero-dependency wire codec — draft-conforming parser and writer for all MoQT messages |
| [`moqtap-client`](crates/moqtap-client) | MoQT protocol client — outbound QUIC transport via quinn, session state machine, subscribe/fetch/publish flows |
| [`moqtap-proxy`](crates/moqtap-proxy) | Transparent intercepting proxy — inline MoQT frame parsing, observer/hook traits, self-signed cert generation |
| [`moqtap-trace`](crates/moqtap-trace) | Trace file I/O — `.moqtrace` binary format reader/writer for integration into relays, clients, and debugging tools |
| [`moqtap-cli`](crates/moqtap-cli) | CLI tool — `moqtap` binary for subscribing, fetching, and tracing MoQT/QUIC/WebTransport connections |

## Quick Start

### Install the CLI

```sh
cargo install moqtap-cli
```

### Subscribe to a track

```sh
moqtap subscribe -s 127.0.0.1:4443 -n live/stream -t video --insecure --trace session.moqtrace
```

### Fetch a track range

```sh
moqtap fetch -s 127.0.0.1:4443 -n live/stream -t audio --start-group 0 --insecure
```

### Inspect a trace file

```sh
moqtap trace session.moqtrace
moqtap trace session.moqtrace -f json
```

## Using as a library

Add the crates you need to your `Cargo.toml`:

```toml
[dependencies]
moqtap-codec = "0.1"
moqtap-client = "0.1"
```

### Connect and subscribe

```rust
use moqtap_client::connection::{Connection, ClientConfig};
use moqtap_codec::types::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ClientConfig {
        skip_cert_verification: true,
        ..Default::default()
    };
    let mut conn = Connection::connect("127.0.0.1:4443", config).await?;

    // Wait for server to grant request IDs, then subscribe
    let msg = conn.recv_and_dispatch().await?;

    let req_id = conn.subscribe(
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

### Encode/decode messages

```rust
use moqtap_codec::message::{ControlMessage, ClientSetup};
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

moqtap-cli            Binary that ties everything together.
```

## Spec Compliance

This implementation targets **draft-ietf-moq-transport-14**.

## License

MIT

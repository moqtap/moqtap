# moqtap

A Rust implementation of [MoQT (Media over QUIC Transport)](https://datatracker.ietf.org/doc/draft-ietf-moq-transport/).

moqtap provides a modular crate ecosystem for building MoQT debugging and tracing tools: a wire codec, a QUIC-backed client, an intercepting proxy, session tracing, and a UDP impairment engine.

## Crates

| Crate | Description |
|-------|-------------|
| [`moqtap-codec`](crates/moqtap-codec) | Zero-dependency wire codec — draft-conforming parser and writer for all MoQT messages |
| [`moqtap-client`](crates/moqtap-client) | MoQT protocol client — outbound QUIC transport via quinn, session state machine, subscribe/fetch/publish flows |
| [`moqtap-proxy`](crates/moqtap-proxy) | Transparent intercepting proxy — inline MoQT frame parsing, observer/hook traits, self-signed cert generation |
| [`moqtap-trace`](crates/moqtap-trace) | Trace file I/O — `.moqtrace` binary format reader/writer for integration into relays, clients, and debugging tools |
| [`quinn-netem`](crates/quinn-netem) | Deterministic UDP datagram impairment — loss, delay, reorder, duplication, corruption and rate shaping beneath a quinn endpoint |

## Using as a library

Add the crates you need to your `Cargo.toml`:

```toml
[dependencies]
moqtap-codec = "0.6"
moqtap-client = "0.6"
```

Each draft is a separate feature flag on both crates (`draft07`..`draft21`), and both default to `all-drafts`. Turn default features off and name only the drafts you need to build a smaller subset; a draft that is not enabled cannot be negotiated at runtime.

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

Requires Rust 1.88+ and [just](https://github.com/casey/just) (optional).

```sh
# Run all checks (what CI runs)
just check

# Run tests
just test

# Format code
just fmt

# Build documentation and open it
just doc

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

quinn-netem           Standalone UDP impairment engine, no MoQT dependency.
                      Used by moqtap-proxy behind its `impair` feature.
```

Three crates span every draft and they do it three different ways —
`moqtap-codec` and `moqtap-client` with per-draft modules behind cargo features,
`moqtap-proxy` with no draft modules at all and a runtime `match DraftVersion`.
[`ARCHITECTURE.md`](ARCHITECTURE.md) states which applies where, what may be
shared across drafts and what may not, and what to run when adding a draft.
**Read it before sharing code across drafts.**

## Spec Compliance

This implementation covers MoQT drafts 07 through 21. Each draft is a
separate module in both `moqtap-codec` and `moqtap-client`; `moqtap-proxy` has
none and spans them at runtime instead. See
[`ARCHITECTURE.md`](ARCHITECTURE.md).

Draft-20 is the newest and is not a default anywhere. It is not the interop
target — interop ran against draft-18 and the editors plan draft-22 next — so
no crate here promotes it to a connection default, an advertised-preferred
version or an auto-selected draft.

## License

MIT

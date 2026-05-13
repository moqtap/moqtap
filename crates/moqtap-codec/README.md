# moqtap-codec

Zero-dependency MoQT wire codec — draft-conforming parser and writer for every
MoQT draft from draft-07 through draft-18.

This crate handles pure encoding and decoding of MoQT protocol messages with
no I/O, no async runtime, and no network dependencies. It is the foundational
building block that every other moqtap crate depends on.

## What it does

- Encodes and decodes every MoQT control message type per each supported draft
  (setup, subscribe, publish, fetch, namespace, track status, goaway)
- Encodes and decodes data stream headers (subgroup, datagram, fetch, object)
- QUIC variable-length integer (VarInt) encoding per RFC 9000
- Key-value parameter (KVP) pairs
- Core protocol types: `TrackNamespace`, `Location`, `FilterType`, `GroupOrder`,
  `ObjectStatus`
- Session and request error codes, per-draft
- Runtime draft dispatch via the `dispatch` module (`AnyControlMessage`,
  `AnySubgroupHeader`, `AnyFetchHeader`, `AnyDatagramHeader`,
  `AnyObjectHeader`) — one enum variant per enabled draft feature, decode
  selects the draft at runtime from a `DraftVersion`

## Module layout

Each draft lives in its own module with an independent implementation; no
wire-level code is shared across drafts. Shared primitives (`varint`, `kvp`,
`types`, `version`, `error`) sit at the crate root.

```
moqtap_codec::
    varint, kvp, types, version, error   (shared)
    dispatch                             (runtime Any* enums)
    draft07, draft08, ..., draft18       (per-draft wire format)
```

## Draft selection

Each draft is behind a feature flag. Enable the ones you need. The default is
`all-drafts`.

```toml
# every draft (default)
moqtap-codec = "0.2"

# draft-14 only
moqtap-codec = { version = "0.2", default-features = false, features = ["draft14"] }

# draft-07 plus draft-14 for runtime dispatch
moqtap-codec = { version = "0.2", default-features = false, features = ["draft07", "draft14"] }
```

## Usage

### Per-draft (compile-time)

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

### Runtime dispatch across drafts

```rust
use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::version::DraftVersion;

let mut cursor: &[u8] = &wire_bytes;
let msg = AnyControlMessage::decode(DraftVersion::Draft14, &mut cursor)?;
match msg {
    AnyControlMessage::Draft14(inner) => { /* ... */ }
    _ => {}
}
```

## Benchmarks

Criterion benches live in [`benches/codec.rs`](benches/codec.rs) and exercise
varint, KVP, control-message, data-stream header, and synthetic subgroup decode
paths. The conformance test vectors under `test-vectors/transport/draft17/`
provide realistic message bytes; a synthetic generator covers larger
subgroup streams for throughput curves.

```sh
# full run (requires draft17 feature — enabled by default)
cargo bench -p moqtap-codec

# quick smoke run
cargo bench -p moqtap-codec --bench codec -- \
    --warm-up-time 1 --measurement-time 2 --sample-size 10

# only one group
cargo bench -p moqtap-codec --bench codec -- varint

# save a baseline, change code, then compare
cargo bench -p moqtap-codec --bench codec -- --save-baseline before
# … make changes …
cargo bench -p moqtap-codec --bench codec -- --baseline before
```

HTML reports are written to `target/criterion/report/index.html`.

## License

MIT

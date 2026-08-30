# moqtap-codec

MoQT wire codec — a parser and writer for every MoQT draft from draft-07
through draft-19.

Pure encoding and decoding: no I/O, no async runtime, no network dependencies.
It depends only on `bytes` and `thiserror`.

## What it does

- Encodes and decodes every MoQT control message type per each supported draft
  (setup, subscribe, publish, fetch, namespace, track status, goaway)
- Encodes and decodes data stream headers (subgroup, datagram, fetch, object)
- Variable-length integers, in whichever encoding the draft uses: RFC 9000
  Section 16 through draft-16, and MoQT's own (Section 1.4.1) from draft-17,
  where the length is the number of leading 1 bits in the first byte.
  `DraftVersion::varint_encoding` maps drafts to encodings
- Key-value parameter (KVP) pairs
- Core protocol types: `TrackNamespace`, `Location`, `FilterType`, `GroupOrder`,
  `ObjectStatus`
- Session and request error codes, per-draft
- Runtime draft dispatch via the `dispatch` module (`AnyControlMessage`,
  `AnySubgroupHeader`, `AnyFetchHeader`, `AnyDatagramHeader`,
  `AnyObjectHeader`) — one enum variant per enabled draft feature, decode
  selects the draft at runtime from a `DraftVersion`
- Draft-neutral object framing on the same seam (`AnySubgroupObjectReader`,
  `AnySubgroupObjectWriter`, `AnyFetchObjectReader`, `AnyFetchObjectWriter` and
  the values they hand back), so a caller frames a data stream into
  individually addressable objects without naming a `draftNN` type. Subgroup
  and fetch streams on every draft 07-19
- Structured parameter values, rather than opaque bytes: the AUTHORIZATION
  TOKEN structure (`auth_token`), the subscription filter
  (`subscription_filter`), and draft-19's Range Filter parameters
  (`range_filter`)

## Module layout

Each draft lives in its own module with an independent implementation; no
wire-level code is shared across drafts. Shared primitives sit at the crate
root.

```
moqtap_codec::
    varint, kvp, types, version, error   (shared primitives)
    auth_token, subscription_filter,
    range_filter                         (structured parameter values)
    dispatch, data_dispatch              (runtime Any* enums and object framing)
    draft07, draft08, ..., draft19       (per-draft wire format)
```

## Draft selection

Each draft is behind a feature flag. Enable the ones you need. The default is
`all-drafts`.

```toml
# every draft (default)
moqtap-codec = "0.4"

# draft-14 only
moqtap-codec = { version = "0.4", default-features = false, features = ["draft14"] }

# draft-07 plus draft-14 for runtime dispatch
moqtap-codec = { version = "0.4", default-features = false, features = ["draft07", "draft14"] }
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

Criterion benches in [`benches/codec.rs`](benches/codec.rs) cover varint, KVP,
control-message, data-stream header and subgroup decode paths. They need the
`draft17` feature, which is on by default.

```sh
cargo bench -p moqtap-codec
```

## License

MIT

# moqtap-codec

MoQT wire codec — a parser and writer for every MoQT draft from draft-07
through draft-22.

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
  and fetch streams on every draft 07-22
- Structured parameter values, rather than opaque bytes: the AUTHORIZATION
  TOKEN structure (`auth_token`), the subscription filter of drafts 15-19
  (`subscription_filter`), and the Range Filter parameters of drafts 19 through
  22 (`range_filter`). Drafts 20 and 21 give the LOCATION_FILTER value's shape
  by its field count and draft-22 by a `Location Filter Type` of its own, so
  each reads its filters through its own `draftNN::message::decode_location_filter`,
  and the nested parameter block of `FILL_PARAMETERS` through its own
  `draftNN::message::decode_fill_parameters`

## Module layout

Each draft's **wire format** lives in its own module with an independent
implementation. Nothing decides a draft's encoding outside that draft's module,
and a build that enables one draft compiles one draft's format.

```
moqtap_codec::
    varint, kvp, types, version, error   (shared primitives)
    auth_token, subscription_filter,
    range_filter                         (structured parameter values,
                                          each serving a stated draft subset)
    fields                               (draft-neutral rendering types:
                                          FieldValue, FieldMap)
    dispatch, data_dispatch              (per-draft dispatch: runtime Any*
                                          enums and object framing)
    draft07, draft08, ..., draft22       (per-draft wire format)
```

`dispatch` and `data_dispatch` select the draft at runtime and forward to that
draft's module. `auth_token`, `subscription_filter` and `range_filter` each
serve the drafts named in their module docs.

`FieldValue` and `FieldMap` in `fields` are draft-agnostic:
`AnyControlMessage::fields()` returns a `FieldMap` for any enabled draft.

## Draft selection

Each draft is behind a feature flag. Enable the ones you need. The default is
`all-drafts`.

```toml
# every draft (default)
moqtap-codec = "0.9"

# draft-14 only
moqtap-codec = { version = "0.9", default-features = false, features = ["draft14"] }

# draft-07 plus draft-14 for runtime dispatch
moqtap-codec = { version = "0.9", default-features = false, features = ["draft07", "draft14"] }
```

The newest draft this crate implements is not a default anywhere: it is not the
interop target, and nothing here promotes it to a connection default, an
advertised-preferred version or an auto-selected draft.

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

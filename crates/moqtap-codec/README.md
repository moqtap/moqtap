# moqtap-codec

MoQT wire codec — a parser and writer for every MoQT draft from draft-07
through draft-20.

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
  and fetch streams on every draft 07-20
- Structured parameter values, rather than opaque bytes: the AUTHORIZATION
  TOKEN structure (`auth_token`), the subscription filter of drafts 15-19
  (`subscription_filter`), and the Range Filter parameters of drafts 19 and 20
  (`range_filter`). Draft-20 rebuilt the LOCATION_FILTER value — the Filter Type
  enum is gone and the shape comes from the field count — so it reads its own
  through `draft20::message::decode_location_filter`, and reads the nested
  parameter block of the new `FILL_PARAMETERS` through
  `draft20::message::decode_fill_parameters`

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
    draft07, draft08, ..., draft20       (per-draft wire format)
```

**"No wire-level code is shared across drafts" is what the older wording here
said, and it was not true.** `dispatch` and `data_dispatch` are ~4,900 lines at
the crate root that decode and encode object headers, extension blocks,
delta-encoded object IDs and stream-type fields across all fourteen drafts — the
tree diagram above has listed them since runtime dispatch landed, so the page
contradicted itself in twelve lines. `fields/params.rs` is the sharper
counterexample: it decodes wire bytes across drafts, calling `VarInt::decode` on
a length-prefixed parameter value from a table four drafts share, and that is
exactly where a remotely-triggerable panic lived — four drafts on one table while
their own decoders disagreed about which parameter types are integers.

The rule that *is* true, and that this crate is actually built on:

- **Every draft's format is decided in that draft's module.** `dispatch` and
  `data_dispatch` contain an arm per draft that forwards to it; they choose
  which decoder runs and never what it does. `data_dispatch`'s macro families
  are grouped by wire era — `legacy_subgroup_glue!` for drafts 07-13,
  `modern_subgroup_glue!` for 14-20, `fetch_glue!` for 07-13, plus hand-written
  `fo14`..`fo20` where no macro shape captured the flags.
- **A crate-root module may be shared only where it serves a stated draft
  subset**, and the subset is a specification fact rather than a convenience:
  `subscription_filter` is drafts 15-19, `range_filter` is 19-20,
  `fields/params.rs` is 07-10 because draft-08 removed ROLE and draft-11 keeps
  its own tables.
- **Anything reachable from a single draft belongs to that draft's module.**
  This is the invariant `fields/mod.rs` is written under; violating it produced
  16 dead-code errors under a single-draft build. Draft-14's parameter handling
  was moved out of the shared file for exactly this reason.

`fields` is settled and public: `AnyControlMessage::fields()` returns a
`FieldMap`. `fields/params.rs` is `pub(crate)`, gated
`any(draft07, draft08, draft09, draft10)`, and holds only what more than one
draft shares — one non-SETUP parameter table across 07-10 and the generic
`kvp_to_json_d07_inner` that reads it. Draft-07's SETUP table is draft-07-only;
the 08-10 SETUP table, the ROLE-less cohort, is gated to those three. Every
other draft defines its own tables in its own `draftNN/fields.rs`.

The workspace-wide statement of all this — including the two other crates, which
span drafts differently — is [`ARCHITECTURE.md`](../../ARCHITECTURE.md).

## Draft selection

Each draft is behind a feature flag. Enable the ones you need. The default is
`all-drafts`.

```toml
# every draft (default)
moqtap-codec = "0.6"

# draft-14 only
moqtap-codec = { version = "0.6", default-features = false, features = ["draft14"] }

# draft-07 plus draft-14 for runtime dispatch
moqtap-codec = { version = "0.6", default-features = false, features = ["draft07", "draft14"] }
```

Draft-20 is supported and is not a default anywhere. It is the newest draft this
crate implements; it is not the interop target, and nothing here promotes it to
a connection default, an advertised-preferred version or an auto-selected
draft.

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

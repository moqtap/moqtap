# moqtap-codec

Zero-dependency MoQT wire codec — the draft-conforming parser and writer for all MoQT messages.

This crate handles pure encoding and decoding of MoQT protocol messages with no I/O, no async runtime, and no network dependencies. It is the foundational building block that all other moqtap crates depend on.

## What it does

- Encodes and decodes all 30 MoQT control message types (setup, subscribe, publish, fetch, namespace, track status, goaway)
- Encodes and decodes data stream headers (subgroup, datagram, fetch, object)
- QUIC variable-length integer (VarInt) encoding per RFC 9000
- Key-value parameter (KVP) pairs
- Core protocol types: TrackNamespace, Location, FilterType, GroupOrder, ObjectStatus
- Session and request error codes

## Draft selection

Each draft is behind a feature flag. Enable the one(s) you need:

```toml
# draft-14 only (default)
moqtap-codec = "0.1"

# draft-07 only
moqtap-codec = { version = "0.1", default-features = false, features = ["draft07"] }

# both drafts
moqtap-codec = { version = "0.1", features = ["draft07"] }
```

## Usage

```rust
use moqtap_codec::draft14::message::{ControlMessage, ClientSetup};
use moqtap_codec::varint::VarInt;

// Encode a draft-14 ClientSetup
let msg = ControlMessage::ClientSetup(ClientSetup {
    supported_versions: vec![VarInt::from_u64(0xff00000e).unwrap()],
    parameters: vec![],
});
let mut buf = Vec::new();
msg.encode(&mut buf).unwrap();

// Decode
let mut cursor = &buf[..];
let decoded = ControlMessage::decode(&mut cursor).unwrap();
assert_eq!(msg, decoded);
```

## License

MIT

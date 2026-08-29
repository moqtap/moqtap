# moqtap-trace

MoQT session trace file reader and writer.

This crate defines the `.moqtrace` binary format and provides the I/O
primitives for reading and writing trace files. Relay and client developers
can integrate moqtap-trace into their own software to emit trace files,
which can then be inspected with the moqtap CLI or in the browser.

It writes format version 2 and reads versions 1 and 2.

## What it does

- **TraceHeader**: session metadata (protocol, perspective, detail level,
  timestamps, endpoint, transport, segment and sampling metadata,
  user-defined custom fields)
- **TraceEvent / EventData**: typed events for control messages, data
  streams, objects, state changes, errors, and peer and subscription
  topology
- **`.moqtrace` format**: CBOR-encoded, streamable, segmentable,
  cross-language
- **MoqTraceWriter / MoqTraceReader**: streaming writer and reader

## Usage

```rust
use moqtap_trace::event::{EventData, TraceEvent};
use moqtap_trace::header::{DetailLevel, Perspective, TraceHeader};
use moqtap_trace::reader::MoqTraceReader;
use moqtap_trace::writer::MoqTraceWriter;

let mut header = TraceHeader::new(
    "moq-transport-19",
    Perspective::Client,
    DetailLevel::Headers,
    1_700_000_000_000,
);
header.transport = Some("raw-quic".to_string());
header.source = Some("my-client/1.0.0".to_string());
header.endpoint = Some("quic://relay.example.com:4443".to_string());

let mut writer = MoqTraceWriter::new(Vec::new(), &header).unwrap();
writer
    .write_event(&TraceEvent::new(
        0,
        1000,
        EventData::StateChange { from: "idle".into(), to: "connecting".into() },
    ))
    .unwrap();
let bytes = writer.into_inner().unwrap();

let reader = MoqTraceReader::new(&bytes[..]).unwrap();
assert_eq!(reader.header().protocol, "moq-transport-19");
assert_eq!(reader.into_iter().count(), 1);
```

Reading a trace someone else wrote, nothing is rejected for being newer than
this crate: an unrecognised event type arrives as `EventData::Unknown` with
its fields intact, and an unrecognised perspective, detail level or drop
policy is kept verbatim in the matching `Other` variant.

## License

MIT

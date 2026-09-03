# moqtap-trace

MoQT session trace file reader and writer.

This crate defines the `.moqtrace` binary format and provides the I/O
primitives for reading and writing trace files. Relay and client developers
can integrate moqtap-trace into their own software to emit trace files,
which can then be inspected in the browser.

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
- **Conformance corpus**: checked against the shared `.moqtrace` corpus, half
  of whose files were written by the JavaScript implementation rather than by
  this crate

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

## Recording an error with the bytes behind it

`EventData::Error` carries the stream the failure was seen on, what sort of
failure it was, and the bytes responsible. A report saying "your SUBSCRIBE_OK
did not parse" is an assertion; the same report carrying the bytes is evidence
the other party can run against their own encoder.

```rust
use moqtap_trace::event::{ErrorKind, EventData, ERROR_RAW_CAP};

let offending = vec![0u8; 12];
let event = EventData::Error {
    error_code: 0,
    reason: "SUBSCRIBE_OK did not parse".into(),
    stream_id: Some(4),
    kind: Some(ErrorKind::Decode),
    raw_len: Some(offending.len() as u64),
    raw: Some(offending),
};
assert!(ERROR_RAW_CAP == 4096);
let _ = event;
```

Whatever records the bytes caps them at `ERROR_RAW_CAP` and reports the
untruncated length in `raw_len`. The two disagreeing is how a reader learns a
capture is partial and by how much, so omit `raw_len` when the true length is
not known rather than guessing at it.

Reading a trace someone else wrote, nothing is rejected for being newer than
this crate: an unrecognised event type arrives as `EventData::Unknown` with
its fields intact, and an unrecognised perspective, detail level or drop
policy is kept verbatim in the matching `Other` variant. Keys are kept on the
same terms - one this version does not recognise, on the header or on any
event, is preserved in the neighbouring `extra` and written back unchanged.

## License

MIT

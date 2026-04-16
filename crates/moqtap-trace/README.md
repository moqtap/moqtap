# moqtap-trace

MoQT session trace file reader and writer.

This crate defines the `.moqtrace` binary format and provides the I/O
primitives for reading and writing trace files. Relay and client developers
can integrate moqtap-trace into their own software to emit trace files,
which can then be inspected with the moqtap CLI or GUI/web applications.

## What it does

- **TraceHeader**: session metadata (protocol, perspective, detail level,
  timestamps, endpoint, transport, user-defined custom fields)
- **TraceEvent / EventData**: typed events for control messages, data
  streams, objects, state changes, errors
- **`.moqtrace` format**: CBOR-encoded, streamable, cross-language
- **MoqTraceWriter / MoqTraceReader**: streaming writer and reader

## Usage

```rust
use moqtap_trace::event::{TraceEvent, EventData, Direction};
use moqtap_trace::header::{TraceHeader, Perspective, DetailLevel};
use moqtap_trace::writer::MoqTraceWriter;

let header = TraceHeader {
    protocol: "moq-transport-14".to_string(),
    perspective: Perspective::Client,
    detail: DetailLevel::Headers,
    start_time: 1_700_000_000_000,
    end_time: None,
    transport: Some("raw-quic".to_string()),
    source: Some("moqtap-cli".to_string()),
    endpoint: Some("quic://relay.example.com:4443".to_string()),
    session_id: None,
    custom: None,
};

let mut writer = MoqTraceWriter::new(Vec::new(), &header).unwrap();
writer.write_event(&TraceEvent {
    timestamp_us: 1000,
    direction: Direction::Send,
    data: EventData::SessionEstablished,
}).unwrap();
```

## License

MIT

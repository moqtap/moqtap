# moqtap-trace

MoQT session trace file reader and writer.

This crate defines the `.moqtrace` binary format and provides the I/O primitives for reading and writing trace files. Relay and client developers can integrate moqtap-trace into their own software to emit trace files, which can then be inspected using the moqtap CLI or GUI/web applications.

## What it does

- **TraceEvent**: Typed events for control messages, data streams, objects, state changes, errors
- **.moqtrace format**: 8-byte magic (`MOQTRACE`) + 4-byte LE version + JSON-lines (compact, streamable)
- **MoqTraceWriter / MoqTraceReader**: File I/O with iterator support
- **SessionMetrics**: Aggregate stats — objects, bytes, control messages, duration, errors

## Usage

```rust
use moqtap_trace::event::{TraceEvent, TraceEventType, Direction};
use moqtap_trace::moqtrace::MoqTraceWriter;
use moqtap_trace::metrics::SessionMetrics;

// Write events
let mut writer = MoqTraceWriter::new(Vec::new()).unwrap();
writer.write_event(&TraceEvent {
    timestamp_us: 1000,
    event_type: TraceEventType::SessionEstablished,
    direction: Direction::Send,
    message_type: None, request_id: None, track_alias: None,
    group: None, object: None, payload_size: None,
    error_code: None, reason: None,
}).unwrap();

// Compute metrics
let events = vec![/* ... */];
let metrics = SessionMetrics::compute(&events);
println!("Objects received: {}", metrics.total_objects_received);
```

## License

MIT

use std::io::Cursor;

use ciborium::Value;
use moqtap_trace::event::*;
use moqtap_trace::header::*;
use moqtap_trace::reader::MoqTraceReader;
use moqtap_trace::writer::{MoqTraceWriter, MOQTRACE_MAGIC, MOQTRACE_VERSION};

fn sample_header() -> TraceHeader {
    TraceHeader {
        protocol: "moq-transport-14".into(),
        perspective: Perspective::Client,
        detail: DetailLevel::Control,
        start_time: 1_700_000_000_000,
        end_time: None,
        transport: Some("raw-quic".into()),
        source: Some("moqtap-test/0.1.0".into()),
        endpoint: None,
        session_id: None,
        custom: None,
    }
}

fn sample_events() -> Vec<TraceEvent> {
    vec![
        TraceEvent {
            seq: 0,
            timestamp: 0,
            data: EventData::StateChange { from: "idle".into(), to: "connecting".into() },
        },
        TraceEvent {
            seq: 1,
            timestamp: 1000,
            data: EventData::ControlMessage {
                direction: Direction::Send,
                message_type: 0x20,
                message: Value::Map(vec![(
                    Value::Text("supportedVersions".into()),
                    Value::Array(vec![Value::Integer(0xff00000eu64.into())]),
                )]),
                raw: None,
            },
        },
    ]
}

#[test]
fn write_and_read_single_event() {
    let header = sample_header();
    let event = &sample_events()[0];

    let mut buf = Vec::new();
    let mut writer = MoqTraceWriter::new(&mut buf, &header).unwrap();
    writer.write_event(event).unwrap();
    writer.flush().unwrap();

    let reader = MoqTraceReader::new(Cursor::new(&buf)).unwrap();
    assert_eq!(reader.header(), &header);

    let events: Vec<TraceEvent> = reader.into_iter().collect::<Result<_, _>>().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0], *event);
}

#[test]
fn write_and_read_multiple_events() {
    let header = sample_header();
    let events = sample_events();

    let mut buf = Vec::new();
    let mut writer = MoqTraceWriter::new(&mut buf, &header).unwrap();
    for event in &events {
        writer.write_event(event).unwrap();
    }
    writer.flush().unwrap();

    let reader = MoqTraceReader::new(Cursor::new(&buf)).unwrap();
    let read_events: Vec<TraceEvent> = reader.into_iter().collect::<Result<_, _>>().unwrap();
    assert_eq!(read_events, events);
}

#[test]
fn magic_bytes_are_correct() {
    let header = sample_header();
    let mut buf = Vec::new();
    MoqTraceWriter::new(&mut buf, &header).unwrap();

    assert_eq!(&buf[..8], MOQTRACE_MAGIC);
}

#[test]
fn version_is_one() {
    assert_eq!(MOQTRACE_VERSION, 1);
}

#[test]
fn version_bytes_in_file() {
    let header = sample_header();
    let mut buf = Vec::new();
    MoqTraceWriter::new(&mut buf, &header).unwrap();

    let version = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
    assert_eq!(version, 1);
}

#[test]
fn header_length_in_file() {
    let header = sample_header();
    let mut buf = Vec::new();
    MoqTraceWriter::new(&mut buf, &header).unwrap();

    let header_len = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]) as usize;

    // The CBOR header bytes should start at offset 16
    // and the file should be exactly 16 + header_len bytes
    // (no events written)
    assert_eq!(buf.len(), 16 + header_len);
}

#[test]
fn invalid_magic_rejected() {
    let data = b"NOTMAGIC\x01\x00\x00\x00";
    let result = MoqTraceReader::new(Cursor::new(data));
    assert!(result.is_err());
}

#[test]
fn unsupported_version_rejected() {
    let mut data = Vec::new();
    data.extend_from_slice(MOQTRACE_MAGIC);
    data.extend_from_slice(&99u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes()); // zero-length header
    let result = MoqTraceReader::new(Cursor::new(data));
    assert!(result.is_err());
}

#[test]
fn empty_event_stream_yields_none() {
    let header = sample_header();
    let mut buf = Vec::new();
    MoqTraceWriter::new(&mut buf, &header).unwrap();

    let mut reader = MoqTraceReader::new(Cursor::new(&buf)).unwrap();
    let event = reader.read_event().unwrap();
    assert!(event.is_none());
}

#[test]
fn iterator_collects_all_events() {
    let header = sample_header();
    let events = sample_events();

    let mut buf = Vec::new();
    let mut writer = MoqTraceWriter::new(&mut buf, &header).unwrap();
    for event in &events {
        writer.write_event(event).unwrap();
    }
    writer.flush().unwrap();

    let reader = MoqTraceReader::new(Cursor::new(&buf)).unwrap();
    let collected: Vec<TraceEvent> = reader.into_iter().collect::<Result<_, _>>().unwrap();
    assert_eq!(collected.len(), 2);
}

#[test]
fn header_with_all_optional_fields() {
    let mut custom = std::collections::BTreeMap::new();
    custom.insert("payloadMasked".into(), Value::Bool(true));

    let header = TraceHeader {
        protocol: "moq-transport-14".into(),
        perspective: Perspective::Server,
        detail: DetailLevel::Full,
        start_time: 1_700_000_000_000,
        end_time: Some(1_700_000_060_000),
        transport: Some("webtransport".into()),
        source: Some("my-relay/2.3.1".into()),
        endpoint: Some("https://relay.example.com/moq".into()),
        session_id: Some("abc-123".into()),
        custom: Some(custom),
    };

    let mut buf = Vec::new();
    MoqTraceWriter::new(&mut buf, &header).unwrap();

    let reader = MoqTraceReader::new(Cursor::new(&buf)).unwrap();
    assert_eq!(reader.header(), &header);
}

#[test]
fn detail_level_ordering() {
    assert!(DetailLevel::Control < DetailLevel::Headers);
    assert!(DetailLevel::Headers < DetailLevel::HeadersSizes);
    assert!(DetailLevel::HeadersSizes < DetailLevel::HeadersData);
    assert!(DetailLevel::HeadersData < DetailLevel::Full);
}

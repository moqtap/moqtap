use std::io::Cursor;

use ciborium::Value;
use moqtap_trace::error::MoqTraceError;
use moqtap_trace::event::*;
use moqtap_trace::header::*;
use moqtap_trace::reader::{MoqTraceReader, ReadItem};
use moqtap_trace::writer::{
    MoqTraceWriter, MOQTRACE_MAGIC, MOQTRACE_VERSION, MOQTRACE_VERSIONS_SUPPORTED,
};

fn sample_header() -> TraceHeader {
    let mut header = TraceHeader::new(
        "moq-transport-14",
        Perspective::Client,
        DetailLevel::Control,
        1_700_000_000_000,
    );
    header.transport = Some("raw-quic".into());
    header.source = Some("moqtap-test/0.1.0".into());
    header
}

fn sample_events() -> Vec<TraceEvent> {
    vec![
        TraceEvent::new(
            0,
            0,
            EventData::StateChange { from: "idle".into(), to: "connecting".into() },
        ),
        TraceEvent::new(
            1,
            1000,
            EventData::ControlMessage {
                direction: Direction::Send,
                message_type: 0x20,
                message: Value::Map(vec![(
                    Value::Text("supportedVersions".into()),
                    Value::Array(vec![Value::Integer(0xff00000eu64.into())]),
                )]),
                stream_id: Some(0),
                raw: None,
            },
        ),
    ]
}

fn write_trace(header: &TraceHeader, events: &[TraceEvent]) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut writer = MoqTraceWriter::new(&mut buf, header).unwrap();
    for event in events {
        writer.write_event(event).unwrap();
    }
    writer.flush().unwrap();
    drop(writer);
    buf
}

#[test]
fn write_and_read_single_event() {
    let header = sample_header();
    let event = &sample_events()[0];
    let buf = write_trace(&header, std::slice::from_ref(event));

    let reader = MoqTraceReader::new(Cursor::new(&buf)).unwrap();
    assert_eq!(reader.header(), &header);

    let events: Vec<TraceEvent> = reader.into_iter().collect::<Result<_, _>>().unwrap();
    assert_eq!(events, vec![event.clone()]);
}

#[test]
fn write_and_read_multiple_events() {
    let header = sample_header();
    let events = sample_events();
    let buf = write_trace(&header, &events);

    let reader = MoqTraceReader::new(Cursor::new(&buf)).unwrap();
    let read_events: Vec<TraceEvent> = reader.into_iter().collect::<Result<_, _>>().unwrap();
    assert_eq!(read_events, events);
}

/// A whole file's worth of the rule that the cap is the recorder's alone: an
/// error event carrying more than [`ERROR_RAW_CAP`] bytes is written at that
/// length, read back at that length, and written out again at that length.
///
/// Through the file writer and the file reader rather than through one event,
/// because a cap dropped into `write_event` would pass every event-level test
/// built from short fixtures and would then quietly shorten the evidence in
/// every over-long capture a redaction pass, a filter or a re-segmentation
/// touched. Re-truncating someone else's file destroys the record to make it
/// conform to a rule it was never handed.
#[test]
fn an_over_long_raw_survives_a_write_a_read_and_a_rewrite() {
    let long: Vec<u8> = (0..ERROR_RAW_CAP + 904).map(|i| (i % 251) as u8).collect();
    assert_eq!(long.len(), 5000, "the fixture is meant to sit well past the cap");

    let event = TraceEvent::new(
        0,
        700,
        EventData::Error {
            error_code: 5,
            reason: "SUBSCRIBE_OK did not parse".into(),
            stream_id: Some(6),
            kind: Some(ErrorKind::Decode),
            raw_len: Some(5000),
            raw: Some(long.clone()),
        },
    );

    let buf = write_trace(&sample_header(), std::slice::from_ref(&event));
    let reader = MoqTraceReader::new(Cursor::new(&buf)).unwrap();
    let read: Vec<TraceEvent> = reader.into_iter().collect::<Result<_, _>>().unwrap();
    assert_eq!(read.len(), 1, "an over-long 'raw' cost the file its event");

    let EventData::Error { raw, raw_len, kind, stream_id, .. } = &read[0].data else {
        panic!("expected an error event");
    };
    assert_eq!(raw.as_deref(), Some(long.as_slice()), "the read shortened the bytes");
    assert_eq!(*raw_len, Some(5000));
    assert_eq!(*kind, Some(ErrorKind::Decode));
    assert_eq!(*stream_id, Some(6));

    // And out again, from the event the reader built rather than the one the
    // test did: a rewrite is where a serializer-side cap would bite.
    let rewritten = write_trace(&sample_header(), &read);
    let reader = MoqTraceReader::new(Cursor::new(&rewritten)).unwrap();
    let reread: Vec<TraceEvent> = reader.into_iter().collect::<Result<_, _>>().unwrap();
    let EventData::Error { raw, raw_len, .. } = &reread[0].data else {
        panic!("expected an error event");
    };
    assert_eq!(raw.as_deref(), Some(long.as_slice()), "the rewrite shortened the bytes");
    assert_eq!(*raw_len, Some(5000));
}

#[test]
fn magic_bytes_are_correct() {
    let buf = write_trace(&sample_header(), &[]);
    assert_eq!(&buf[..8], MOQTRACE_MAGIC);
}

#[test]
fn version_is_two() {
    assert_eq!(MOQTRACE_VERSION, 2);
}

#[test]
fn version_bytes_in_file() {
    let buf = write_trace(&sample_header(), &[]);
    let version = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
    assert_eq!(version, MOQTRACE_VERSION);
}

#[test]
fn header_length_in_file() {
    let buf = write_trace(&sample_header(), &[]);
    let header_len = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]) as usize;

    // The CBOR header bytes start at offset 16, and with no events written
    // the file is exactly the preamble.
    assert_eq!(buf.len(), 16 + header_len);
}

#[test]
fn invalid_magic_rejected() {
    let data = b"NOTMAGIC\x02\x00\x00\x00";
    assert!(matches!(MoqTraceReader::new(Cursor::new(data)), Err(MoqTraceError::InvalidMagic)));
}

#[test]
fn unsupported_version_rejected() {
    let mut data = Vec::new();
    data.extend_from_slice(MOQTRACE_MAGIC);
    data.extend_from_slice(&99u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes()); // zero-length header
    assert!(matches!(
        MoqTraceReader::new(Cursor::new(data)),
        Err(MoqTraceError::UnsupportedVersion(99))
    ));
}

#[test]
fn empty_event_stream_yields_none() {
    let buf = write_trace(&sample_header(), &[]);
    let mut reader = MoqTraceReader::new(Cursor::new(&buf)).unwrap();
    assert!(reader.read_event().unwrap().is_none());
}

#[test]
fn header_with_all_optional_fields() {
    let mut custom = std::collections::BTreeMap::new();
    custom.insert("payloadMasked".into(), Value::Bool(true));

    let mut header = TraceHeader::new(
        "moq-transport-14",
        Perspective::Server,
        DetailLevel::Full,
        1_700_000_000_000,
    );
    header.end_time = Some(1_700_000_060_000);
    header.transport = Some("webtransport".into());
    header.source = Some("my-relay/2.3.1".into());
    header.endpoint = Some("https://relay.example.com/moq".into());
    header.session_id = Some("abc-123".into());
    header.segment = Some(SegmentInfo {
        duration_ms: Some(1000),
        stream_id: Some("stream-9".into()),
        continues: Some(true),
        ..SegmentInfo::new(3)
    });
    header.sampling = Some(SamplingInfo {
        effective_rate: Some(0.5),
        max_events_per_sec: Some(1000),
        drop_policy: Some(DropPolicy::Tail),
        dropped_total: Some(42),
        dropped_segment: Some(7),
        rule: Some("namespace prefix=foo/bar".into()),
        rule_lang: Some("prefix".into()),
        applies_to: Some(vec![3, 4]),
        ..SamplingInfo::default()
    });
    header.custom = Some(custom);

    let buf = write_trace(&header, &[]);
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

// ── version 1 files stay readable ──────────────────────────

/// Build a version-1 file by hand: the same layout with `1` at byte 8.
///
/// Written rather than generated because the crate no longer has a code path
/// that emits version 1, and a fixture the crate produces itself could not
/// prove it reads what an older writer left behind.
fn v1_file(header: &TraceHeader, events: &[TraceEvent]) -> Vec<u8> {
    let mut header_bytes = Vec::new();
    let header_value: Value = header.into();
    ciborium::into_writer(&header_value, &mut header_bytes).unwrap();

    let mut buf = Vec::new();
    buf.extend_from_slice(MOQTRACE_MAGIC);
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(&header_bytes);
    for event in events {
        ciborium::into_writer(event, &mut buf).unwrap();
    }
    buf
}

#[test]
fn version_one_is_supported() {
    assert!(MOQTRACE_VERSIONS_SUPPORTED.contains(&1));
    assert!(MOQTRACE_VERSIONS_SUPPORTED.contains(&2));
}

#[test]
fn version_one_files_still_read() {
    // Every capture taken before the bump has to stay openable; a version bump
    // that orphans the existing corpus buys nothing.
    let header = sample_header();
    let events = sample_events();
    let buf = v1_file(&header, &events);

    let reader = MoqTraceReader::new(Cursor::new(&buf)).unwrap();
    assert_eq!(reader.version(), 1);
    assert_eq!(reader.header(), &header);

    let read_events: Vec<TraceEvent> = reader.into_iter().collect::<Result<_, _>>().unwrap();
    assert_eq!(read_events, events);
}

// ── unknown values in the header ───────────────────────────

#[test]
fn unknown_perspective_is_preserved_not_rejected() {
    // New perspectives may be added without a version bump, and every event in
    // such a file still parses — so rejecting it at the header would refuse a
    // trace this crate can otherwise read in full.
    let mut header = sample_header();
    header.perspective = Perspective::Other("satellite-tap".into());
    header.detail = DetailLevel::Other("headers+timing".into());

    let buf = write_trace(&header, &sample_events());
    let reader = MoqTraceReader::new(Cursor::new(&buf)).unwrap();

    assert_eq!(reader.header().perspective, Perspective::Other("satellite-tap".into()));
    assert_eq!(reader.header().detail.as_str(), "headers+timing");
    assert_eq!(reader.into_iter().count(), 2);
}

#[test]
fn relay_tap_perspective_roundtrips() {
    let mut header = sample_header();
    header.perspective = Perspective::RelayTap;
    let buf = write_trace(&header, &[]);
    let reader = MoqTraceReader::new(Cursor::new(&buf)).unwrap();
    assert_eq!(reader.header().perspective, Perspective::RelayTap);
    assert_eq!(reader.header().perspective.as_str(), "relay-tap");
}

// ── segmented traces ───────────────────────────────────────

fn segment_header(sequence: u64) -> TraceHeader {
    let mut header = sample_header();
    header.start_time = 1_700_000_000_000 + sequence * 1000;
    header.segment = Some(SegmentInfo {
        duration_ms: Some(1000),
        stream_id: Some("stream-1".into()),
        continues: Some(sequence > 0),
        ..SegmentInfo::new(sequence)
    });
    header
}

fn segmented_trace(segments: usize, events_per_segment: usize) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut writer = MoqTraceWriter::new(&mut buf, &segment_header(0)).unwrap();
    for segment in 0..segments {
        if segment > 0 {
            writer.start_segment(&segment_header(segment as u64)).unwrap();
        }
        for n in 0..events_per_segment {
            // Sequence numbers restart per segment, which is exactly what makes
            // a reader that ignores boundaries reconstruct a broken timeline.
            writer
                .write_event(&TraceEvent::new(
                    n as u64,
                    (n * 100) as i64,
                    EventData::Annotation {
                        label: format!("seg{segment}-ev{n}"),
                        data: Value::Null,
                    },
                ))
                .unwrap();
        }
    }
    writer.flush().unwrap();
    drop(writer);
    buf
}

#[test]
fn segments_are_seen_by_read_next() {
    let buf = segmented_trace(3, 2);
    let reader = MoqTraceReader::new(Cursor::new(&buf)).unwrap();

    let items: Vec<ReadItem> = reader.into_item_iter().collect::<Result<_, _>>().unwrap();

    // The first segment's header is consumed on construction, so only the two
    // later boundaries appear in the stream.
    let boundaries: Vec<u64> = items
        .iter()
        .filter_map(|item| match item {
            ReadItem::Segment(header) => Some(header.segment.as_ref().unwrap().sequence),
            ReadItem::Event(_) => None,
        })
        .collect();
    assert_eq!(boundaries, vec![1, 2]);
    assert_eq!(items.iter().filter(|i| matches!(i, ReadItem::Event(_))).count(), 6);
}

#[test]
fn segments_are_transparent_to_read_event() {
    let buf = segmented_trace(3, 2);
    let reader = MoqTraceReader::new(Cursor::new(&buf)).unwrap();
    let events: Vec<TraceEvent> = reader.into_iter().collect::<Result<_, _>>().unwrap();

    assert_eq!(events.len(), 6);
    let labels: Vec<String> = events
        .iter()
        .map(|e| match &e.data {
            EventData::Annotation { label, .. } => label.clone(),
            other => panic!("unexpected event: {other:?}"),
        })
        .collect();
    assert_eq!(labels, ["seg0-ev0", "seg0-ev1", "seg1-ev0", "seg1-ev1", "seg2-ev0", "seg2-ev1"]);
}

#[test]
fn each_segment_carries_a_full_preamble() {
    // The point of the format's segmentation is that a consumer can start at
    // any segment. That only holds if every segment repeats magic, version and
    // header rather than referring back to the first one.
    let buf = segmented_trace(2, 1);
    let second = buf
        .windows(MOQTRACE_MAGIC.len())
        .skip(1)
        .position(|w| w == MOQTRACE_MAGIC.as_slice())
        .map(|p| p + 1)
        .expect("a second segment preamble");

    let reader = MoqTraceReader::new(Cursor::new(&buf[second..])).unwrap();
    assert_eq!(reader.header().segment.as_ref().unwrap().sequence, 1);
    assert_eq!(reader.into_iter().count(), 1);
}

#[test]
fn the_reader_tracks_the_current_segment_header() {
    let buf = segmented_trace(2, 1);
    let mut reader = MoqTraceReader::new(Cursor::new(&buf)).unwrap();

    assert_eq!(reader.header().segment.as_ref().unwrap().sequence, 0);
    reader.read_event().unwrap().unwrap();
    assert_eq!(reader.header().segment.as_ref().unwrap().sequence, 0);
    reader.read_event().unwrap().unwrap();
    assert_eq!(reader.header().segment.as_ref().unwrap().sequence, 1);
}

#[test]
fn a_segment_header_without_segment_metadata_is_refused() {
    // Without it a reader takes each segment for a complete file and rebuilds
    // a timeline that jumps backwards at every boundary, because sequence
    // numbers and timestamps restart.
    let mut buf = Vec::new();
    let mut writer = MoqTraceWriter::new(&mut buf, &segment_header(0)).unwrap();
    let err = writer.start_segment(&sample_header()).unwrap_err();
    assert!(matches!(err, MoqTraceError::InvalidHeader(_)), "got {err:?}");
}

// ── truncation ─────────────────────────────────────────────

#[test]
fn truncation_reports_the_offset_and_keeps_what_decoded() {
    // A truncated trace is still evidence, and the events before the cut are
    // exactly as valid as they were.
    let header = sample_header();
    let events = sample_events();
    let full = write_trace(&header, &events);
    let cut = full.len() - 4;
    let truncated = &full[..cut];

    let mut reader = MoqTraceReader::new(Cursor::new(truncated)).unwrap();
    let mut decoded = Vec::new();
    let err = loop {
        match reader.read_event() {
            Ok(Some(event)) => decoded.push(event),
            Ok(None) => panic!("a truncated file must not read as a clean end of file"),
            Err(e) => break e,
        }
    };

    assert_eq!(decoded, events[..1]);
    let MoqTraceError::Truncated { offset } = err else { panic!("got {err:?}") };
    assert!(offset < cut as u64, "offset {offset} should name the start of the cut item");
}

#[test]
fn a_complete_file_is_not_reported_as_truncated() {
    // The distinction is only worth anything if a clean end of file stays
    // clean — an over-eager truncation check would call every trace damaged.
    let buf = write_trace(&sample_header(), &sample_events());
    let mut reader = MoqTraceReader::new(Cursor::new(&buf)).unwrap();
    while reader.read_event().unwrap().is_some() {}
}

#[test]
fn resync_skips_a_corrupt_segment_and_resumes_at_the_next() {
    // The recovery segmentation exists to offer: one damaged segment costs
    // that segment, not the rest of the capture.
    let good = segmented_trace(3, 2);

    // Corrupt the middle of the first segment's event stream by overwriting
    // bytes just after its preamble.
    let mut damaged = good.clone();
    let header_len =
        u32::from_le_bytes([damaged[12], damaged[13], damaged[14], damaged[15]]) as usize;
    let first_event = 16 + header_len;
    damaged[first_event] = 0x7f; // an indefinite-length text string, unterminated
    for byte in damaged[first_event + 1..first_event + 4].iter_mut() {
        *byte = 0xff;
    }

    let mut reader = MoqTraceReader::new(Cursor::new(&damaged)).unwrap();
    assert!(reader.read_event().is_err(), "the corrupt segment should fail to decode");

    let recovered = reader.resync_to_next_segment().unwrap().expect("a later segment");
    assert_eq!(recovered.segment.as_ref().unwrap().sequence, 1);

    let rest: Vec<TraceEvent> = reader.into_iter().collect::<Result<_, _>>().unwrap();
    assert_eq!(rest.len(), 4, "both events of segments 1 and 2");
}

#[test]
fn resync_returns_none_when_no_segment_follows() {
    let buf = write_trace(&sample_header(), &sample_events());
    let mut reader = MoqTraceReader::new(Cursor::new(&buf)).unwrap();
    assert!(reader.resync_to_next_segment().unwrap().is_none());
}

// ── a segment header the reader cannot build ───────────────

/// A header carrying a marker in its store, so the segment an event was
/// attributed to can be named in a failure rather than inferred.
fn marked_segment_header(sequence: u64, marker: &str) -> TraceHeader {
    let mut header = segment_header(sequence);
    header.extra = vec![(Value::Text("x-h".into()), Value::Text(marker.into()))];
    header
}

fn marker_of(header: &TraceHeader) -> String {
    header
        .extra
        .iter()
        .find(|(k, _)| k.as_text() == Some("x-h"))
        .and_then(|(_, v)| v.as_text())
        .unwrap_or("<none>")
        .to_string()
}

fn label_of(event: &TraceEvent) -> String {
    match &event.data {
        EventData::Annotation { label, .. } => label.clone(),
        other => panic!("expected an annotation, got {other:?}"),
    }
}

fn annotation(label: &str) -> TraceEvent {
    TraceEvent::new(0, 0, EventData::Annotation { label: label.into(), data: Value::Null })
}

/// Three segments, of which the middle one's header has no readable
/// `"sequence"`.
///
/// The key is renamed in place — one byte, `"sequence"` to `"sequencX"` — so
/// the preamble still declares the length it has, the header is still valid
/// CBOR, and the only thing wrong with it is the one thing SPEC.md makes fatal
/// on a segment. That is the shape a reader meets in the wild: a header it can
/// decode and cannot use.
fn three_segments_with_a_malformed_middle_header() -> Vec<u8> {
    let mut buf = Vec::new();
    let mut writer = MoqTraceWriter::new(&mut buf, &marked_segment_header(0, "A")).unwrap();
    writer.write_event(&annotation("seg0-ev0")).unwrap();
    writer.start_segment(&marked_segment_header(1, "B")).unwrap();
    writer.write_event(&annotation("seg1-ev0")).unwrap();
    writer.start_segment(&marked_segment_header(2, "C")).unwrap();
    writer.write_event(&annotation("seg2-ev0")).unwrap();
    writer.flush().unwrap();
    drop(writer);

    let mut key = vec![0x68u8]; // CBOR text(8)
    key.extend_from_slice(b"sequence");
    let second = buf
        .windows(key.len())
        .enumerate()
        .filter(|(_, window)| *window == key.as_slice())
        .map(|(at, _)| at)
        .nth(1)
        .expect("three segment headers, three 'sequence' keys");
    buf[second + 8] = b'X';
    buf
}

/// The reader must not read on from where a bad preamble left it. The preamble
/// is consumed before the header is built, so the stream is parked on the
/// *next* segment's events with no header for them — and decoding them there
/// leaves the previous segment's header standing, which presents a segment
/// SPEC.md says must not be presented as read, under a header the file never
/// gave it.
///
/// It is worse than a wrong label. `"n"` and `"t"` are segment-local and
/// global order is `(segment.sequence, n)`, so every event recovered that way
/// is also misordered, with nothing in the returned values to say so.
#[test]
fn a_malformed_segment_header_does_not_hand_its_events_to_the_previous_segment() {
    let buf = three_segments_with_a_malformed_middle_header();
    let mut reader = MoqTraceReader::new(Cursor::new(&buf)).unwrap();

    let first = reader.read_next().unwrap().expect("segment 0's event");
    let ReadItem::Event(event) = first else { panic!("expected an event, got {first:?}") };
    assert_eq!(label_of(&event), "seg0-ev0");
    assert_eq!(marker_of(reader.header()), "A");

    // Reported, exactly once, and naming the fault.
    let err = reader.read_next().unwrap_err();
    let MoqTraceError::InvalidHeader(message) = &err else { panic!("got {err:?}") };
    assert!(message.contains("segment.sequence"), "the error should name the key, got: {message}");

    // What comes next is the segment after the fault — not segment 1's event
    // under segment 0's header.
    let next = reader.read_next().unwrap().expect("segment 2");
    let ReadItem::Segment(header) = next else { panic!("expected a segment, got {next:?}") };
    assert_eq!(marker_of(&header), "C");
    assert_eq!(header.segment.as_ref().unwrap().sequence, 2);

    let last = reader.read_next().unwrap().expect("segment 2's event");
    let ReadItem::Event(event) = last else { panic!("expected an event, got {last:?}") };
    assert_eq!(label_of(&event), "seg2-ev0");
    assert_eq!(marker_of(reader.header()), "C");

    assert!(reader.read_next().unwrap().is_none(), "the stream should end cleanly");
}

/// The caller this cost the most: one that keeps the `Ok`s and drops the
/// errors sees no fault at all, so a mis-attributed event reaches it looking
/// exactly like a good one. It gets the segments it can trust and none of the
/// events from the segment it cannot.
#[test]
fn skipping_the_errors_yields_no_event_under_the_wrong_header() {
    let buf = three_segments_with_a_malformed_middle_header();
    let reader = MoqTraceReader::new(Cursor::new(&buf)).unwrap();

    let mut iterator = reader.into_event_iter();
    let mut attributed: Vec<(String, String)> = Vec::new();
    loop {
        match iterator.next() {
            None => break,
            Some(Ok(event)) => attributed.push((label_of(&event), marker_of(iterator.header()))),
            Some(Err(_)) => continue,
        }
    }

    assert_eq!(
        attributed,
        vec![("seg0-ev0".to_string(), "A".to_string()), ("seg2-ev0".to_string(), "C".to_string()),],
        "an event was attributed to a segment it did not come from"
    );
}

/// The error is not sticky, and the recovery is not silent: `collect` into a
/// `Result` — the idiom this crate's own tests use — still stops at the fault
/// rather than skipping it, so the segment lost is reported to the one caller
/// that asked to be told.
#[test]
fn a_malformed_segment_header_still_stops_a_collect_into_a_result() {
    let buf = three_segments_with_a_malformed_middle_header();
    let reader = MoqTraceReader::new(Cursor::new(&buf)).unwrap();

    let result: Result<Vec<TraceEvent>, MoqTraceError> = reader.into_iter().collect();
    let err = result.unwrap_err();
    assert!(matches!(err, MoqTraceError::InvalidHeader(_)), "got {err:?}");
}

/// The explicit recovery path has the same hole and the same fix: a resync
/// that lands on a header it cannot build must not leave that segment's events
/// readable under the header it was holding.
#[test]
fn a_resync_onto_a_malformed_header_does_not_attribute_its_events_either() {
    let buf = three_segments_with_a_malformed_middle_header();
    let mut reader = MoqTraceReader::new(Cursor::new(&buf)).unwrap();

    // Resync from the very start: the first preamble it finds is segment 1's,
    // the malformed one.
    let err = reader.resync_to_next_segment().unwrap_err();
    assert!(matches!(err, MoqTraceError::InvalidHeader(_)), "got {err:?}");

    let next = reader.read_next().unwrap().expect("segment 2");
    let ReadItem::Segment(header) = next else { panic!("expected a segment, got {next:?}") };
    assert_eq!(marker_of(&header), "C");
}

#[test]
fn a_header_written_by_the_js_encoder_reads_back() {
    // Fixed bytes rather than a description, because the risk is encoding: the
    // JS encoder writes an epoch-millisecond timestamp as a float64, and this
    // side used to read `startTime` as missing and reject the whole file
    // before a single event. Every trace the browser recorder ever wrote was
    // unopenable here, and nothing in either test suite could see it, because
    // each side only ever read its own bytes.
    const JS_HEADER: &[u8] = &[
        0xb9, 0x00, 0x05, 0x68, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x70, 0x6d, 0x6f,
        0x71, 0x2d, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2d, 0x31, 0x34, 0x6b,
        0x70, 0x65, 0x72, 0x73, 0x70, 0x65, 0x63, 0x74, 0x69, 0x76, 0x65, 0x68, 0x6f, 0x62, 0x73,
        0x65, 0x72, 0x76, 0x65, 0x72, 0x66, 0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x64, 0x66, 0x75,
        0x6c, 0x6c, 0x69, 0x73, 0x74, 0x61, 0x72, 0x74, 0x54, 0x69, 0x6d, 0x65, 0xfb, 0x42, 0x79,
        0x65, 0x9b, 0x68, 0x50, 0x00, 0x00, 0x67, 0x65, 0x6e, 0x64, 0x54, 0x69, 0x6d, 0x65, 0xfb,
        0x42, 0x79, 0x65, 0x9b, 0x72, 0x14, 0x00, 0x00,
    ];

    let mut file = Vec::new();
    file.extend_from_slice(MOQTRACE_MAGIC);
    file.extend_from_slice(&1u32.to_le_bytes());
    file.extend_from_slice(&(JS_HEADER.len() as u32).to_le_bytes());
    file.extend_from_slice(JS_HEADER);

    let reader = MoqTraceReader::new(Cursor::new(&file)).expect("a JS-written header must parse");
    assert_eq!(reader.header().start_time, 1_745_261_856_000);
    assert_eq!(reader.header().end_time, Some(1_745_261_896_000));
    assert_eq!(reader.header().perspective, Perspective::Observer);
    assert_eq!(reader.header().detail, DetailLevel::Full);
}

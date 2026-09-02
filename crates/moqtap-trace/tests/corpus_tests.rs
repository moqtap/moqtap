//! The shared `.moqtrace` corpus.
//!
//! SPEC.md claims the format's cross-language compatibility is "maintained by
//! a shared corpus of `.moqtrace` files that both implementations read and
//! write as part of their test suites". This is that suite's half of it.
//!
//! What it checks that `moqtrace_tests.rs` cannot: every other test in this
//! crate reads only bytes this crate wrote, and an encoder always agrees with
//! its own decoder — including on conventions nobody else implements. Both
//! normative encoding rules in SPEC.md exist because that blind spot hid a
//! real break in each direction. Here, half the files came from
//! `@moqtap/trace` and a quarter from third-party relays.

mod corpus;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use moqtap_trace::error::MoqTraceError;
use moqtap_trace::event::{EventData, TraceEvent};
use moqtap_trace::header::TraceHeader;
use moqtap_trace::reader::{MoqTraceReader, ReadItem};
use moqtap_trace::writer::MoqTraceWriter;
use moqtap_trace::Value;
use serde_json::Value as Json;

/// Byte offset of the format version in a segment preamble.
const VERSION_OFFSET: usize = 8;

/// One segment's header and the events under it.
#[derive(Debug, Clone, PartialEq)]
struct Segment {
    header: TraceHeader,
    events: Vec<TraceEvent>,
}

/// Read every segment of a file, keeping what decoded if it stops short.
///
/// A truncated capture is usually the only capture of whatever went wrong, so
/// the events before the cut are worth exactly as much as they were.
fn read_segments(bytes: &[u8]) -> (Vec<Segment>, bool) {
    let mut reader = MoqTraceReader::new(bytes).expect("open trace");
    let mut segments = vec![Segment { header: reader.header().clone(), events: Vec::new() }];
    let mut truncated = false;
    loop {
        match reader.read_next() {
            Ok(Some(ReadItem::Event(event))) => {
                segments.last_mut().expect("a segment is open").events.push(event);
            }
            Ok(Some(ReadItem::Segment(header))) => {
                segments.push(Segment { header, events: Vec::new() });
            }
            Ok(None) => break,
            Err(MoqTraceError::Truncated { .. }) => {
                truncated = true;
                break;
            }
            Err(e) => panic!("unexpected read error: {e}"),
        }
    }
    (segments, truncated)
}

/// Serialize segments back to bytes, for the round-trip check.
fn write_segments(segments: &[Segment]) -> Vec<u8> {
    let mut iter = segments.iter();
    let first = iter.next().expect("at least one segment");
    let mut writer = MoqTraceWriter::new(Vec::new(), &first.header).expect("write header");
    for event in &first.events {
        writer.write_event(event).expect("write event");
    }
    for segment in iter {
        writer.start_segment(&segment.header).expect("start segment");
        for event in &segment.events {
            writer.write_event(event).expect("write event");
        }
    }
    writer.into_inner().expect("flush")
}

fn declared_version(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(
        bytes[VERSION_OFFSET..VERSION_OFFSET + 4].try_into().expect("four version bytes"),
    )
}

fn event_type_counts(segments: &[Segment]) -> BTreeMap<String, u64> {
    let mut counts = BTreeMap::new();
    for segment in segments {
        for event in &segment.events {
            *counts.entry(event.event_type().to_string()).or_insert(0) += 1;
        }
    }
    counts
}

/// One case as `manifest.json` describes it.
struct ManifestCase {
    id: String,
    files: Vec<(String, u64)>,
    version: u32,
    segments: usize,
    truncated: bool,
    protocol: String,
    perspective: String,
    detail: String,
    event_count: usize,
    event_types: BTreeMap<String, u64>,
}

fn load_manifest(root: &Path) -> Vec<ManifestCase> {
    let raw = fs::read_to_string(root.join("manifest.json")).expect("read manifest.json");
    let json: Json = serde_json::from_str(&raw).expect("parse manifest.json");
    json["cases"]
        .as_array()
        .expect("manifest has a cases array")
        .iter()
        .map(|case| ManifestCase {
            id: case["id"].as_str().expect("id").to_string(),
            files: case["files"]
                .as_array()
                .expect("files")
                .iter()
                .map(|f| {
                    (
                        f["name"].as_str().expect("file name").to_string(),
                        f["bytes"].as_u64().expect("file size"),
                    )
                })
                .collect(),
            version: case["version"].as_u64().expect("version") as u32,
            segments: case["segments"].as_u64().expect("segments") as usize,
            truncated: case["truncated"].as_bool().expect("truncated"),
            protocol: case["protocol"].as_str().expect("protocol").to_string(),
            perspective: case["perspective"].as_str().expect("perspective").to_string(),
            detail: case["detail"].as_str().expect("detail").to_string(),
            event_count: case["eventCount"].as_u64().expect("eventCount") as usize,
            event_types: case["eventTypes"]
                .as_object()
                .expect("eventTypes")
                .iter()
                .map(|(k, v)| (k.clone(), v.as_u64().expect("a count")))
                .collect(),
        })
        .collect()
}

/// The corpus root, or `None` when neither location has it.
///
/// A checkout that cannot reach the corpus is a wiring gap, not a conformance
/// failure, so every test below returns rather than asserting against files it
/// does not have. [`corpus_is_reachable`] is where that state is reported, and
/// it says what to do about it.
fn root() -> Option<PathBuf> {
    corpus::corpus_dir()
}

fn case_bytes(root: &Path, id: &str, file: &str) -> Vec<u8> {
    fs::read(root.join(id).join(file)).unwrap_or_else(|e| panic!("read {id}/{file}: {e}"))
}

/// Reports whether the corpus is reachable, rather than requiring it.
///
/// The corpus lives in the `test-vectors` repository, which this workspace
/// carries as a submodule under `crates/moqtap-codec/`. Until that submodule
/// is bumped past the commit that added `trace/`, a fresh clone has the
/// submodule and not the corpus — a wiring gap, and failing on it would paint
/// every build red for a missing dependency rather than for anything this
/// crate got wrong.
///
/// It self-heals: the moment the submodule carries `trace/`, every test in
/// this file becomes live with no change here. What it does not catch is the
/// corpus being *removed* after that, which SPEC.md and the corpus README both
/// forbid and which would go equally quiet in `@moqtap/trace`. That is the
/// price of not blocking on a dependency this repository does not own.
#[test]
fn corpus_is_reachable() {
    match root() {
        Some(dir) => println!("corpus: {}", dir.display()),
        // Printed rather than asserted, and visible under `--nocapture`.
        None => eprintln!("SKIPPING every corpus test. {}", corpus::CORPUS_MISSING_MESSAGE),
    }
}

#[test]
fn every_file_matches_the_manifest() {
    let Some(root) = root() else { return };
    let cases = load_manifest(&root);
    assert!(!cases.is_empty(), "the corpus manifest lists no cases");

    for case in &cases {
        for (name, size) in &case.files {
            let bytes = case_bytes(&root, &case.id, name);
            let where_ = format!("{}/{name}", case.id);

            assert_eq!(bytes.len() as u64, *size, "{where_}: file size");
            assert_eq!(declared_version(&bytes), case.version, "{where_}: declared version");

            let (segments, truncated) = read_segments(&bytes);
            assert_eq!(truncated, case.truncated, "{where_}: truncation");
            assert_eq!(segments.len(), case.segments, "{where_}: segment count");
            assert_eq!(segments[0].header.protocol, case.protocol, "{where_}: protocol");
            assert_eq!(
                segments[0].header.perspective.as_str(),
                case.perspective,
                "{where_}: perspective"
            );
            assert_eq!(segments[0].header.detail.as_str(), case.detail, "{where_}: detail");

            let events: usize = segments.iter().map(|s| s.events.len()).sum();
            assert_eq!(events, case.event_count, "{where_}: event count");
            assert_eq!(event_type_counts(&segments), case.event_types, "{where_}: event types");
        }
    }
}

/// The claim the corpus exists for.
///
/// Two encoders wrote these files and they do not agree byte for byte —
/// `ciborium` writes an integer in the narrowest form that holds it, `cbor-x`
/// writes a BigInt in eight — so bytes are the wrong thing to compare and
/// content is the right one.
#[test]
fn files_of_one_case_carry_identical_content() {
    let Some(root) = root() else { return };
    let mut compared = 0;

    for case in load_manifest(&root) {
        if case.files.len() < 2 {
            continue;
        }
        let mut decoded = case
            .files
            .iter()
            .map(|(name, _)| (name, read_segments(&case_bytes(&root, &case.id, name)).0));
        let (first_name, first) = decoded.next().expect("at least one file");
        for (name, other) in decoded {
            assert_eq!(other, first, "{}: {name} differs from {first_name}", case.id);
            compared += 1;
        }
    }

    assert!(compared > 0, "no case had two files to compare — the corpus is only half written");
}

#[test]
fn every_file_survives_a_read_modify_write_round_trip() {
    let Some(root) = root() else { return };

    for case in load_manifest(&root) {
        if case.truncated {
            continue;
        }
        for (name, _) in &case.files {
            let (segments, _) = read_segments(&case_bytes(&root, &case.id, name));
            let (rewritten, _) = read_segments(&write_segments(&segments));
            assert_eq!(rewritten, segments, "{}/{name}: round trip", case.id);
        }
    }
}

/// The two encoding conventions SPEC.md makes normative, in the wrong form.
///
/// Both were broken, in opposite directions, by the two implementations, and
/// neither test suite could see it: each read only bytes it had written
/// itself. These two files are the shapes `cbor-x` used to write, and a
/// conformant reader takes them because files carrying them exist.
#[test]
fn the_non_canonical_encodings_read_as_the_canonical_one() {
    let Some(root) = root() else { return };
    let (canonical, _) = read_segments(&case_bytes(&root, "v2-basic", "rust.moqtrace"));

    for case in ["v2-float-ints", "v2-tag64"] {
        let (decoded, _) = read_segments(&case_bytes(&root, case, "js.moqtrace"));
        assert_eq!(decoded, canonical, "{case} does not decode to the v2-basic content");
    }
}

#[test]
fn a_truncated_file_reports_the_cut_and_keeps_what_decoded() {
    let Some(root) = root() else { return };

    for file in ["js.moqtrace", "rust.moqtrace"] {
        let bytes = case_bytes(&root, "v2-truncated", file);
        let (segments, truncated) = read_segments(&bytes);
        assert!(truncated, "{file}: the cut was not reported");

        let events: usize = segments.iter().map(|s| s.events.len()).sum();
        assert_eq!(events, 11, "{file}: events recovered before the cut");

        // And distinctly, not as a generic decode failure: a caller has to be
        // able to tell "this file stops here" from "these bytes are not a
        // trace".
        let mut reader = MoqTraceReader::new(bytes.as_slice()).expect("open trace");
        let err = loop {
            match reader.read_next() {
                Ok(Some(_)) => continue,
                Ok(None) => panic!("{file}: read to a clean end of file"),
                Err(e) => break e,
            }
        };
        assert!(
            matches!(err, MoqTraceError::Truncated { offset } if offset > 0),
            "{file}: expected Truncated, got {err}"
        );
    }
}

#[test]
fn an_unknown_event_type_keeps_its_fields_verbatim() {
    let Some(root) = root() else { return };
    let (segments, _) = read_segments(&case_bytes(&root, "v2-unknown-event", "js.moqtrace"));

    let unknown = segments[0]
        .events
        .iter()
        .find_map(|event| match &event.data {
            EventData::Unknown { event_type, fields } => Some((*event_type, fields.clone())),
            _ => None,
        })
        .expect("the corpus case carries an unknown event");

    assert_eq!(unknown.0, 99);
    let by_key: BTreeMap<&str, &Value> =
        unknown.1.iter().filter_map(|(k, v)| k.as_text().map(|k| (k, v))).collect();
    assert_eq!(by_key["note"], &Value::Text("from the future".into()));
    assert_eq!(by_key["count"], &Value::Integer(3.into()));
    assert_eq!(by_key["blob"], &Value::Bytes(vec![0xde, 0xad, 0xbe, 0xef]));

    // The point of keeping them: a tool that reads and rewrites a trace must
    // not strip what it did not recognise, or its ignorance becomes permanent
    // for every reader downstream of it.
    let (rewritten, _) = read_segments(&write_segments(&segments));
    assert_eq!(rewritten, segments);
}

/// A key no reader knows, on an event type it does.
///
/// The keys are the ones PROPOSAL-v3 §§1-3 propose. Reading them back off a
/// file written by the other implementation is what makes "additive" a checked
/// claim rather than an assumption.
#[test]
fn an_unrecognised_key_on_a_known_event_survives_a_round_trip() {
    let Some(root) = root() else { return };
    let (segments, _) = read_segments(&case_bytes(&root, "v2-extra-keys", "js.moqtrace"));
    let events = &segments[0].events;

    assert_eq!(
        events[0].extra,
        vec![
            (Value::Text("ta".into()), Value::Integer(7.into())),
            (Value::Text("sg".into()), Value::Integer(2.into())),
        ]
    );
    assert_eq!(events[1].extra, vec![(Value::Text("ta".into()), Value::Integer(7.into()))]);
    assert_eq!(
        events[2].extra,
        vec![
            (Value::Text("ek".into()), Value::Text("decode".into())),
            (Value::Text("raw".into()), Value::Bytes(vec![0x99, 0x01])),
        ]
    );

    // Ignoring an unrecognised key is allowed. Dropping one is not: this round
    // trip is the redaction pass, the filter, the annotated download.
    let (rewritten, _) = read_segments(&write_segments(&segments));
    assert_eq!(rewritten, segments);
}

/// An unknown event type keeps every non-common key in
/// [`EventData::Unknown::fields`]. Collecting them into `extra` as well writes
/// each one twice and yields a CBOR map with duplicate keys — which is what
/// the first draft of this did, and what the corpus caught.
#[test]
fn an_unknown_event_type_does_not_collect_its_fields_twice() {
    let Some(root) = root() else { return };
    let (segments, _) = read_segments(&case_bytes(&root, "v2-unknown-event", "rust.moqtrace"));

    let unknown = segments[0]
        .events
        .iter()
        .find(|event| matches!(event.data, EventData::Unknown { .. }))
        .expect("the corpus case carries an unknown event");

    assert!(unknown.extra.is_empty(), "fields were collected into extra as well");
}

/// A real draft-18 session against `cloudflare/moq-rs`, recorded by
/// `moqtap intercept`.
///
/// Draft-18 gives each request its own bidirectional stream, so these are four
/// distinct QUIC streams. The proxy does not see stream IDs and writes 0 for
/// all of them, which is the gap PROPOSAL-v3 §1 closes. The assertion pins
/// today's behaviour so the change is visible when it lands, not because the
/// behaviour is right.
#[test]
fn a_third_party_capture_shows_four_streams_all_declaring_id_zero() {
    let Some(root) = root() else { return };
    let (segments, _) =
        read_segments(&case_bytes(&root, "capture-observer-draft18-moq-rs", "capture.moqtrace"));

    let opened: Vec<u64> = segments[0]
        .events
        .iter()
        .filter_map(|event| match event.data {
            EventData::StreamOpened { stream_id, .. } => Some(stream_id),
            _ => None,
        })
        .collect();

    assert_eq!(opened, vec![0, 0, 0, 0]);
}

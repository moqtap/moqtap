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
/// Every key is `x-` prefixed, the range SPEC.md reserves for private use and
/// promises never to define. The fixture borrowed keys from this proposal's own
/// sections until §2 shipped and claimed two of them, at which point the case
/// went on passing while measuring less — which is why the reservation exists.
/// Reading them back off a file the other implementation wrote is what makes
/// "an unrecognised key survives" a checked claim rather than an assumption.
#[test]
fn an_unrecognised_key_on_a_known_event_survives_a_round_trip() {
    let Some(root) = root() else { return };
    let (segments, _) = read_segments(&case_bytes(&root, "v2-extra-keys", "js.moqtrace"));
    let events = &segments[0].events;

    assert_eq!(
        events[0].extra,
        vec![
            (Value::Text("x-ta".into()), Value::Integer(7.into())),
            (Value::Text("x-sg".into()), Value::Integer(2.into())),
        ]
    );
    assert_eq!(
        events[2].extra,
        vec![
            (Value::Text("x-ek".into()), Value::Text("decode".into())),
            (Value::Text("x-raw".into()), Value::Bytes(vec![0x99, 0x01])),
        ]
    );

    // Structural, not shallow: a copy that kept only the top level would pass
    // every assertion above and lose this one.
    let nested = events[1]
        .extra
        .iter()
        .find(|(k, _)| k.as_text() == Some("x-nested"))
        .map(|(_, v)| v)
        .expect("the object header carries a nested unrecognised key");
    assert_eq!(
        nested,
        &Value::Map(vec![
            (Value::Text("blob".into()), Value::Bytes(vec![0x0f, 0xf0])),
            (
                Value::Text("inner".into()),
                Value::Map(vec![(Value::Text("depth".into()), Value::Integer(3.into()))])
            ),
            (
                Value::Text("list".into()),
                Value::Array(vec![Value::Integer(1.into()), Value::Text("two".into())])
            ),
        ])
    );

    // Ignoring an unrecognised key is allowed. Dropping one is not: this round
    // trip is the redaction pass, the filter, the annotated download.
    let (rewritten, _) = read_segments(&write_segments(&segments));
    assert_eq!(rewritten, segments);
}

/// The three stream-header identifiers on a `headers`-level trace, on both
/// files of the case.
///
/// The case shipped with §2 and, for a session, no test named it — so its
/// documented claims were asserted nowhere and it could have decoded to
/// anything without a corpus test noticing. A fixture nothing names is a file,
/// not a check.
///
/// `detail: "headers"` records no payload and no data-stream framing bytes, so
/// these keys are the only thing in the file that says which track a stream
/// carried. All three streams share one alias deliberately: that is legal and
/// ordinary — one track delivered as a subgroup, a fetch and a datagram — and
/// it is why the alias alone cannot key a flow.
#[test]
fn a_headers_level_trace_groups_three_streams_that_share_a_track_alias() {
    let Some(root) = root() else { return };

    for file in ["js.moqtrace", "rust.moqtrace"] {
        let (segments, _) = read_segments(&case_bytes(&root, "v2-headers-level-flow", file));
        assert_eq!(segments[0].header.detail.as_str(), "headers", "{file}");

        let opened: Vec<_> = segments[0]
            .events
            .iter()
            .filter_map(|e| match &e.data {
                EventData::StreamOpened {
                    track_alias,
                    subgroup_id,
                    fetch_request_id,
                    group_id,
                    ..
                } => Some((*track_alias, *subgroup_id, *fetch_request_id, *group_id)),
                _ => None,
            })
            .collect();
        assert_eq!(opened.len(), 3, "{file}: three streams");

        // One alias across all three, and one discriminating key each — never
        // the other two. A reader that dropped any of them would leave three
        // streams of one alias that nothing in the file could tell apart,
        // which is most of what this detail level is for.
        assert_eq!(
            opened,
            vec![
                (Some(9), Some(2), None, None),
                (Some(9), None, Some(42), None),
                // Past 2^32, where the integer-not-float rule bites.
                (Some(9), None, None, Some(4_294_967_296)),
            ],
            "{file}"
        );
    }
}

/// The value a store holds under a text key, or `None`.
fn stored<'a>(store: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    store.iter().find(|(k, _)| k.as_text() == Some(key)).map(|(_, v)| v)
}

/// The three unrecognised-key stores in the header, on both files of the case.
///
/// Every other file in the corpus carries its unrecognised keys on *events*, so
/// until `v2-header-extra` existed the header's three stores could have been
/// deleted outright with this file's round-trip test still green: that test
/// reads what this crate wrote, and an encoder emitting no store agrees with a
/// decoder reading none. Reading the same claims off `js.moqtrace` — written by
/// an implementation that shares no code with this one — is what makes them
/// checked rather than assumed.
///
/// Run against both files deliberately. On `js.moqtrace` the assertions say
/// this crate reads what the other one wrote; on `rust.moqtrace` they say this
/// crate's *writer* put the values where SPEC.md requires, in the encoding it
/// requires — which is the half a decode-of-my-own-encode test cannot see.
#[test]
fn the_headers_three_stores_stay_separate_and_survive_a_round_trip() {
    let Some(root) = root() else { return };

    for file in ["js.moqtrace", "rust.moqtrace"] {
        let (segments, _) = read_segments(&case_bytes(&root, "v2-header-extra", file));
        let header = &segments[0].header;
        let segment = header.segment.as_ref().unwrap_or_else(|| panic!("{file}: no segment map"));
        let sampling =
            header.sampling.as_ref().unwrap_or_else(|| panic!("{file}: no sampling map"));

        // One key name, three maps, three values. A reader that merged the
        // stores into one would emit the segment's private key at the top
        // level, and the file would then say something it never said. Nothing
        // else in the corpus can tell the three apart.
        let scope = |store: &[(Value, Value)]| stored(store, "x-scope").cloned();
        assert_eq!(scope(&header.extra), Some(Value::Text("header".into())), "{file}: header");
        assert_eq!(scope(&segment.extra), Some(Value::Text("segment".into())), "{file}: segment");
        assert_eq!(
            scope(&sampling.extra),
            Some(Value::Text("sampling".into())),
            "{file}: sampling"
        );

        // Structural, not shallow: a copy that kept only the top level passes
        // every flat assertion here and loses this one.
        assert_eq!(
            stored(&header.extra, "x-tree"),
            Some(&Value::Map(vec![
                (
                    Value::Text("list".into()),
                    Value::Array(vec![Value::Integer(1.into()), Value::Text("two".into())])
                ),
                (Value::Text("blob".into()), Value::Bytes(vec![0x0f, 0xf0])),
                (Value::Text("gap".into()), Value::Null),
            ])),
            "{file}: the nested stored value"
        );

        // A key this format defines, carrying a value no reader can use. The
        // field reads `None` and the entry is kept — knowing more about a key
        // must not mean preserving it less.
        assert_eq!(header.transport, None, "{file}: 42 is not a transport");
        assert_eq!(
            stored(&header.extra, "transport"),
            Some(&Value::Integer(42.into())),
            "{file}: the wrong-typed defined key"
        );

        // SPEC.md's two encoding rules reach into a store, so both writers emit
        // the same bytes for these two entries however each holds them. This
        // crate's case builds `x-scale` as a `Value::Float` and `x-blob` under
        // RFC 8746's tag 64; `cbor-x` can represent neither distinction, so a
        // file still carrying one is a file only this crate could have written.
        assert_eq!(
            stored(&sampling.extra, "x-scale"),
            Some(&Value::Integer(1.into())),
            "{file}: an integral float in a store is written as an integer"
        );
        assert_eq!(
            stored(&segment.extra, "x-blob"),
            Some(&Value::Bytes(vec![0xca, 0xfe])),
            "{file}: a tag-64 byte string in a store is written as major type 2"
        );

        // Every unrecognised key in this file is in the header, so a store on
        // an event is a reader putting one where it does not belong.
        assert!(
            segments[0].events.iter().all(|event| event.extra.is_empty()),
            "{file}: an event carries a store this case never wrote"
        );

        // The round trip is the redaction pass, the filter, the annotated
        // download — and it is a fixed point, not merely lossless once.
        let (rewritten, _) = read_segments(&write_segments(&segments));
        assert_eq!(rewritten, segments, "{file}: round trip");
    }
}

/// `rust.moqtrace` is what this crate's writer produces from the case today.
///
/// The assertions above read files, and every value in them has already been
/// through a writer once: the committed bytes carry the CBOR integer and the
/// bare byte string whatever the writer would do with the float and the tag it
/// was handed. Delete the normalisation from the store serializer and every one
/// of them stays green until somebody regenerates the corpus — which is the
/// same decode-of-my-own-encode shape one level out, with the encode cached on
/// disk. This is the assertion that reads the *writer*.
///
/// It is written for this case alone because this is the only case whose
/// fixture and file differ: [`corpus::v2_header_extra`] holds a
/// [`Value::Float`] and a tag-64 byte string in its stores, SPEC.md requires
/// both to be written in another encoding, and nothing else in the corpus asks
/// a writer to change anything on the way out. A failure here means the
/// committed file no longer matches the case — regenerate it with
/// `cargo run -p moqtap-trace --example generate_corpus`, and rerun
/// `manifest.ts` — or that the store serializer stopped honouring the two
/// encoding rules.
#[test]
fn the_header_extra_file_is_what_the_writer_emits_for_the_case() {
    let Some(root) = root() else { return };
    let case = corpus::v2_header_extra();
    let written = write_segments(&[Segment { header: case.header, events: case.events }]);

    assert_eq!(
        written,
        case_bytes(&root, "v2-header-extra", "rust.moqtrace"),
        "v2-header-extra/rust.moqtrace is not what this writer emits for the case"
    );
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

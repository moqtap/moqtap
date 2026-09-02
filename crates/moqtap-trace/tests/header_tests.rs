//! The header's unrecognised-key stores.
//!
//! Every case here is a header a conformant writer would not produce and a
//! reader has to take anyway: a private key, a key from a later version of the
//! format, a key whose value is not of the type it is defined to carry. What
//! they have in common is that reading the file and writing it back must not
//! be the thing that deletes them.

use std::collections::BTreeMap;
use std::io::Cursor;

use ciborium::Value;
use moqtap_trace::error::MoqTraceError;
use moqtap_trace::header::*;
use moqtap_trace::reader::MoqTraceReader;
use moqtap_trace::writer::MoqTraceWriter;

// ── helpers ────────────────────────────────────────────────

fn uint(n: u64) -> Value {
    Value::Integer(n.into())
}

fn text(s: &str) -> Value {
    Value::Text(s.into())
}

fn cbor_map(pairs: &[(&str, Value)]) -> Value {
    Value::Map(pairs.iter().map(|(k, v)| (Value::Text((*k).into()), v.clone())).collect())
}

const START_TIME: u64 = 1_756_800_000_000;

/// The four required keys, plus whatever the case is about.
fn header_cbor(rest: &[(&str, Value)]) -> Value {
    let mut pairs = vec![
        ("protocol", text("moq-transport-19")),
        ("perspective", text("client")),
        ("detail", text("control")),
        ("startTime", uint(START_TIME)),
    ];
    pairs.extend(rest.iter().cloned());
    cbor_map(&pairs)
}

fn read(cbor: Value) -> TraceHeader {
    TraceHeader::try_from(cbor).expect("the header is readable")
}

fn read_err(cbor: Value) -> String {
    match TraceHeader::try_from(cbor) {
        Err(MoqTraceError::InvalidHeader(msg)) => msg,
        other => panic!("expected a malformed header, got {other:?}"),
    }
}

fn written(header: &TraceHeader) -> Value {
    header.into()
}

fn roundtrip(header: &TraceHeader) -> TraceHeader {
    read(written(header))
}

/// The map's keys in the order they were written, non-text keys rendered so a
/// failure names them.
fn keys(cbor: &Value) -> Vec<String> {
    let Value::Map(pairs) = cbor else { panic!("not a CBOR map") };
    pairs
        .iter()
        .map(|(k, _)| k.as_text().map(String::from).unwrap_or_else(|| format!("{k:?}")))
        .collect()
}

fn key_count(cbor: &Value, key: &str) -> usize {
    let Value::Map(pairs) = cbor else { panic!("not a CBOR map") };
    pairs.iter().filter(|(k, _)| k.as_text() == Some(key)).count()
}

fn key_of(cbor: &Value, key: &str) -> Option<Value> {
    let Value::Map(pairs) = cbor else { panic!("not a CBOR map") };
    pairs.iter().find(|(k, _)| k.as_text() == Some(key)).map(|(_, v)| v.clone())
}

fn store_of(extra: &[(Value, Value)], key: &str) -> Option<Value> {
    extra.iter().find(|(k, _)| k.as_text() == Some(key)).map(|(_, v)| v.clone())
}

/// Values that no unsigned-integer key can hold, and no text key either. Each
/// is legal CBOR some writer could leave on a header key, and none of them is
/// a value this reader can use — which makes each one unrecognised rather than
/// deletable.
fn unusable() -> Vec<(&'static str, Value)> {
    vec![
        ("a negative integer", Value::Integer((-1i64).into())),
        ("a fractional float", Value::Float(1.5)),
        ("a boolean", Value::Bool(true)),
        ("null", Value::Null),
        ("an array", Value::Array(vec![uint(1), uint(2)])),
        ("a map", cbor_map(&[("a", uint(1))])),
    ]
}

/// The same, minus the map — for the two keys a map is the *usable* shape of.
fn not_a_map() -> Vec<(&'static str, Value)> {
    unusable().into_iter().filter(|(what, _)| *what != "a map").collect()
}

// ── the header map's own store ─────────────────────────────

#[test]
fn an_unknown_header_key_survives_a_read_modify_write() {
    let header = read(header_cbor(&[("x-note", text("hello"))]));

    assert_eq!(store_of(&header.extra, "x-note"), Some(text("hello")), "the key was dropped");
    assert_eq!(key_of(&written(&header), "x-note"), Some(text("hello")));
    assert_eq!(roundtrip(&header).extra, header.extra);
}

/// A key the format defines, carrying a value this crate cannot use. Knowing
/// more about a key must not mean preserving it less: before `"transport"` was
/// defined a `"transport": 42` would have survived as an unknown key, and a
/// reader that type-checks and moves on deletes it instead.
#[test]
fn a_defined_header_key_with_an_unusable_value_is_kept_not_deleted() {
    let cases: Vec<(&str, Value)> = vec![
        ("transport", uint(42)),
        ("source", uint(42)),
        ("endpoint", Value::Bool(false)),
        ("sessionId", Value::Array(vec![])),
        ("endTime", text("later")),
        ("endTime", Value::Float(1.5)),
        ("endTime", Value::Integer((-5i64).into())),
    ];

    for (key, value) in cases {
        let header = read(header_cbor(&[(key, value.clone())]));

        assert_eq!(
            store_of(&header.extra, key),
            Some(value.clone()),
            "'{key}' carrying {value:?} reached neither its field nor the store"
        );
        let out = written(&header);
        assert_eq!(key_count(&out, key), 1, "'{key}' is not written exactly once");
        assert_eq!(key_of(&out, key), Some(value), "'{key}' was altered on the way out");
    }
}

/// A `"transport": 42` leaves the field empty. The store is where the value
/// went, and a caller reading the field must not be told 42 is a transport.
#[test]
fn a_wrong_typed_defined_key_leaves_its_field_empty() {
    let header = read(header_cbor(&[("transport", uint(42))]));
    assert_eq!(header.transport, None);
}

/// An encoder writing anything past 32 bits as a float is why this is not
/// merely tolerated: every epoch-millisecond timestamp takes that path.
#[test]
fn an_integral_float_end_time_reads_as_an_integer() {
    let header = read(header_cbor(&[("endTime", Value::Float(1_756_800_001_000.0))]));

    assert_eq!(header.end_time, Some(1_756_800_001_000));
    assert!(
        header.extra.is_empty(),
        "a usable value does not belong in the store: {:?}",
        header.extra
    );
    assert_eq!(key_of(&written(&header), "endTime"), Some(uint(1_756_800_001_000)));
}

/// The same value with a fraction is not an epoch millisecond this crate can
/// hold, and rounding it would invent a timestamp the file never carried. It
/// goes to the store whole.
#[test]
fn a_fractional_end_time_is_kept_rather_than_rounded_or_deleted() {
    let header = read(header_cbor(&[("endTime", Value::Float(1_756_800_001_000.5))]));

    assert_eq!(header.end_time, None);
    assert_eq!(store_of(&header.extra, "endTime"), Some(Value::Float(1_756_800_001_000.5)));
    assert_eq!(key_of(&written(&header), "endTime"), Some(Value::Float(1_756_800_001_000.5)));
}

/// The store is written after the map's own keys, so a file rewritten by this
/// crate stays diffable against one written without them. Written first, the
/// four required keys would no longer lead the map.
#[test]
fn the_store_is_written_after_the_headers_own_keys() {
    let header = read(header_cbor(&[
        ("x-note", text("hello")),
        ("transport", uint(42)),
        ("source", text("recorder/1.0")),
    ]));

    assert_eq!(
        keys(&written(&header)),
        vec!["protocol", "perspective", "detail", "startTime", "source", "x-note", "transport"],
        "the store did not come last"
    );
}

/// A reader never produces such an entry — a key it recognised and used is by
/// definition not unrecognised — but a caller assembling a header by hand can,
/// and a CBOR map carrying one key twice is a map no two readers need agree
/// on. The field wins.
#[test]
fn a_store_entry_naming_a_key_the_header_writes_is_dropped() {
    let mut header =
        TraceHeader::new("moq-transport-19", Perspective::Client, DetailLevel::Control, START_TIME);
    header.transport = Some("webtransport".into());
    header.extra = vec![
        (text("transport"), uint(42)),
        (text("protocol"), text("moq-transport-01")),
        (text("x-note"), text("hello")),
    ];

    let out = written(&header);
    assert_eq!(key_count(&out, "transport"), 1, "'transport' is written twice");
    assert_eq!(key_of(&out, "transport"), Some(text("webtransport")), "the store beat the field");
    assert_eq!(key_count(&out, "protocol"), 1, "'protocol' is written twice");
    assert_eq!(key_of(&out, "protocol"), Some(text("moq-transport-19")));
    assert_eq!(key_of(&out, "x-note"), Some(text("hello")), "an unrelated entry was dropped");
}

/// The other half of that rule. An entry naming an optional key whose field is
/// empty is the only copy of that key: nothing is written from the field, so
/// dropping it as a collision would delete exactly the value the reading half
/// went to the trouble of keeping.
#[test]
fn a_store_entry_for_an_empty_optional_field_is_written() {
    let mut header =
        TraceHeader::new("moq-transport-19", Perspective::Client, DetailLevel::Control, START_TIME);
    header.extra = vec![(text("transport"), uint(42))];

    assert_eq!(header.transport, None);
    assert_eq!(key_of(&written(&header), "transport"), Some(uint(42)));
}

/// A non-text key is not one this format defines, so it is unrecognised by
/// construction. SPEC.md leaves a reader free to reject the header instead;
/// this crate keeps the key verbatim, which is what the event side does with
/// one and is the only choice that loses nothing — the objection SPEC.md
/// raises is to *re-keying* `1` as `"1"`, which this does not do.
#[test]
fn a_non_text_header_key_is_kept_verbatim() {
    let mut cbor = header_cbor(&[]);
    let Value::Map(ref mut pairs) = cbor else { panic!("not a CBOR map") };
    pairs.push((uint(7), text("seven")));

    let header = read(cbor);
    assert_eq!(header.extra, vec![(uint(7), text("seven"))]);

    let Value::Map(out) = written(&header) else { panic!("not a CBOR map") };
    assert!(out.contains(&(uint(7), text("seven"))), "the integer key was dropped or re-keyed");
}

/// Preserved structurally, not shallow-copied: an unknown key may hold a whole
/// tree, and the reader has no idea which part of it mattered.
///
/// The tree the reader hands back is the one the file carried, tag 64 and all
/// — a reader that folds a shape away on the way in has invented data. The
/// writer is where the format's encoding rules apply, which is why the value
/// written back is not byte-for-byte the value read: see
/// [`a_stored_tag_64_byte_string_is_written_as_a_plain_byte_string`].
#[test]
fn a_deeply_nested_unknown_value_is_kept_structurally() {
    let deep = Value::Map(vec![
        (
            text("a"),
            Value::Array(vec![
                uint(1),
                Value::Map(vec![(text("b"), Value::Bytes(vec![0xde, 0xad]))]),
            ]),
        ),
        (text("c"), Value::Null),
        (text("d"), Value::Tag(64, Box::new(Value::Bytes(vec![0x01])))),
    ]);

    let header = read(header_cbor(&[("x-deep", deep.clone())]));
    assert_eq!(store_of(&header.extra, "x-deep"), Some(deep.clone()));

    // The same tree, with the one encoding the writer is required to change.
    let Value::Map(mut written_deep) = deep else { panic!("not a CBOR map") };
    written_deep[2].1 = Value::Bytes(vec![0x01]);
    assert_eq!(key_of(&written(&header), "x-deep"), Some(Value::Map(written_deep)));
}

// ── the "segment" map's store ──────────────────────────────

fn segment_cbor(rest: &[(&str, Value)]) -> Value {
    let mut pairs = vec![("sequence", uint(0))];
    pairs.extend(rest.iter().cloned());
    cbor_map(&pairs)
}

#[test]
fn an_unknown_key_in_segment_is_kept_in_the_segment_map() {
    let header = read(header_cbor(&[("segment", segment_cbor(&[("x-rot", text("size"))]))]));

    let segment = header.segment.as_ref().expect("the segment is readable");
    assert_eq!(store_of(&segment.extra, "x-rot"), Some(text("size")));
    assert!(header.extra.is_empty(), "the key climbed into the header's store: {:?}", header.extra);

    let out = key_of(&written(&header), "segment").expect("'segment' is written");
    assert_eq!(key_of(&out, "x-rot"), Some(text("size")));
}

#[test]
fn a_wrong_typed_key_in_segment_is_kept_in_the_segment_map() {
    let header = read(header_cbor(&[("segment", segment_cbor(&[("streamId", uint(42))]))]));

    let segment = header.segment.as_ref().expect("the segment is readable");
    assert_eq!(segment.stream_id, None);
    assert_eq!(store_of(&segment.extra, "streamId"), Some(uint(42)));

    let out = key_of(&written(&header), "segment").expect("'segment' is written");
    assert_eq!(key_count(&out, "streamId"), 1, "'streamId' is not written exactly once");
    assert_eq!(key_of(&out, "streamId"), Some(uint(42)));
}

/// One store for the whole header would not do: a private key on `"segment"`
/// and a key of the same name at the top level are different keys, and
/// re-emitting either in the other's map changes what the file says.
#[test]
fn the_three_stores_do_not_borrow_each_others_keys() {
    let header = read(header_cbor(&[
        ("x-where", text("top")),
        ("segment", segment_cbor(&[("x-where", text("segment"))])),
        ("sampling", cbor_map(&[("x-where", text("sampling"))])),
    ]));

    let segment = header.segment.as_ref().expect("the segment is readable");
    let sampling = header.sampling.as_ref().expect("the sampling map is readable");
    assert_eq!(store_of(&header.extra, "x-where"), Some(text("top")));
    assert_eq!(store_of(&segment.extra, "x-where"), Some(text("segment")));
    assert_eq!(store_of(&sampling.extra, "x-where"), Some(text("sampling")));

    let out = written(&header);
    assert_eq!(key_of(&out, "x-where"), Some(text("top")));
    assert_eq!(
        key_of(&key_of(&out, "segment").expect("'segment' is written"), "x-where"),
        Some(text("segment"))
    );
    assert_eq!(
        key_of(&key_of(&out, "sampling").expect("'sampling' is written"), "x-where"),
        Some(text("sampling"))
    );
}

#[test]
fn the_segment_store_is_written_after_the_segments_own_keys() {
    let header = read(header_cbor(&[(
        "segment",
        segment_cbor(&[
            ("x-rot", text("size")),
            ("streamId", uint(42)),
            ("durationMs", uint(1000)),
        ]),
    )]));

    let out = key_of(&written(&header), "segment").expect("'segment' is written");
    assert_eq!(
        keys(&out),
        vec!["sequence", "durationMs", "x-rot", "streamId"],
        "the store did not come last"
    );
}

#[test]
fn a_segment_store_entry_naming_a_key_the_map_writes_is_dropped() {
    let mut segment = SegmentInfo::new(3);
    segment.stream_id = Some("stream-9".into());
    segment.extra = vec![(text("streamId"), uint(42)), (text("sequence"), uint(99))];
    let mut header =
        TraceHeader::new("moq-transport-19", Perspective::Client, DetailLevel::Control, START_TIME);
    header.segment = Some(segment);

    let out = key_of(&written(&header), "segment").expect("'segment' is written");
    assert_eq!(key_count(&out, "streamId"), 1, "'streamId' is written twice");
    assert_eq!(key_of(&out, "streamId"), Some(text("stream-9")), "the store beat the field");
    assert_eq!(key_count(&out, "sequence"), 1, "'sequence' is written twice");
    assert_eq!(key_of(&out, "sequence"), Some(uint(3)));
}

/// `"segment"` is optional, and an unusable optional value must not fail the
/// file. A reader that rejects it has turned one unreadable metadata value
/// into the loss of every event behind it.
#[test]
fn a_segment_that_is_not_a_map_is_kept_and_the_trace_reads_as_non_segmented() {
    for (what, value) in not_a_map() {
        let header = read(header_cbor(&[("segment", value.clone())]));

        assert!(header.segment.is_none(), "{what}: a non-map became a segment");
        assert_eq!(store_of(&header.extra, "segment"), Some(value.clone()), "{what}: deleted");
        assert_eq!(
            key_of(&written(&header), "segment"),
            Some(value),
            "{what}: altered on the way out"
        );
    }
}

/// The one exception. `"sequence"` is the sole ordering key of a segmented
/// stream: a reader that cannot read it cannot place the segment, and a
/// default invents an order the file never had.
#[test]
fn a_segment_without_a_usable_sequence_is_a_malformed_header() {
    assert_eq!(
        read_err(header_cbor(&[("segment", cbor_map(&[("streamId", text("abc"))]))])),
        "missing 'segment.sequence'"
    );
    assert_eq!(
        read_err(header_cbor(&[("segment", cbor_map(&[("sequence", Value::Float(0.5))]))])),
        "'segment.sequence' is not an unsigned integer",
        "the message must describe the fault, not report a key that is present as missing"
    );
}

// ── the "sampling" map's store ─────────────────────────────

#[test]
fn an_unknown_key_in_sampling_is_kept_in_the_sampling_map() {
    let header = read(header_cbor(&[(
        "sampling",
        cbor_map(&[
            ("effectiveRate", Value::Float(0.5)),
            ("x-q", Value::Array(vec![uint(1), uint(2)])),
        ]),
    )]));

    let sampling = header.sampling.as_ref().expect("the sampling map is readable");
    assert_eq!(sampling.effective_rate, Some(0.5));
    assert_eq!(store_of(&sampling.extra, "x-q"), Some(Value::Array(vec![uint(1), uint(2)])));

    let out = key_of(&written(&header), "sampling").expect("'sampling' is written");
    assert_eq!(keys(&out), vec!["effectiveRate", "x-q"], "the store did not come last");
}

/// `"appliesTo"` names the event types the drop policy touched, and a reader
/// may treat every type absent from it as complete. Reading `[3, "x", 5]` as
/// `[3, 5]` therefore reports a sampled event type as fully recorded — the
/// opposite of what the file said, stated with the same confidence.
#[test]
fn an_applies_to_with_one_unusable_element_is_kept_whole() {
    let mixed = Value::Array(vec![uint(3), text("x"), uint(5)]);
    let header = read(header_cbor(&[(
        "sampling",
        cbor_map(&[("droppedTotal", uint(3)), ("appliesTo", mixed.clone())]),
    )]));

    let sampling = header.sampling.as_ref().expect("the sampling map is readable");
    assert_eq!(sampling.dropped_total, Some(3));
    assert_eq!(
        sampling.applies_to, None,
        "the array was kept in part, which is worse than not at all"
    );
    assert_eq!(store_of(&sampling.extra, "appliesTo"), Some(mixed.clone()));

    let out = key_of(&written(&header), "sampling").expect("'sampling' is written");
    assert_eq!(key_of(&out, "appliesTo"), Some(mixed));
}

#[test]
fn an_applies_to_of_usable_elements_reads_into_its_field() {
    let header = read(header_cbor(&[(
        "sampling",
        cbor_map(&[("appliesTo", Value::Array(vec![uint(3), Value::Float(4.0)]))]),
    )]));

    let sampling = header.sampling.as_ref().expect("the sampling map is readable");
    assert_eq!(sampling.applies_to, Some(vec![3, 4]));
    assert!(sampling.extra.is_empty(), "a usable array does not belong in the store");
}

/// `"effectiveRate"` is defined as a fraction in `(0.0, 1.0]`, and a value
/// outside the range a key's meaning allows is unusable on an optional key.
#[test]
fn an_effective_rate_outside_its_range_goes_to_the_store() {
    for value in [Value::Float(1.5), Value::Float(0.0), Value::Float(-0.5), Value::Float(f64::NAN)]
    {
        let header =
            read(header_cbor(&[("sampling", cbor_map(&[("effectiveRate", value.clone())]))]));

        let sampling = header.sampling.as_ref().expect("the sampling map is readable");
        assert_eq!(sampling.effective_rate, None, "{value:?} was reported as a sampling rate");
        assert_eq!(sampling.extra.len(), 1, "{value:?} was deleted");
        assert_eq!(sampling.extra[0].0, text("effectiveRate"));
    }
}

/// The interval `"effectiveRate"` is defined over is open at `0.0` and closed
/// at `1.0`, so the commonest rate there is — `1.0`, "no rate-based dropping" —
/// is a value the field takes rather than one the store keeps.
#[test]
fn an_effective_rate_at_the_top_of_its_range_reads_into_its_field() {
    let header =
        read(header_cbor(&[("sampling", cbor_map(&[("effectiveRate", Value::Float(1.0))]))]));

    let sampling = header.sampling.as_ref().expect("the sampling map is readable");
    assert_eq!(sampling.effective_rate, Some(1.0), "the closed end of the interval was refused");
    assert!(sampling.extra.is_empty(), "a rate in range does not belong in the store");
}

/// SPEC.md, Interoperability, requires an integral value to be written as a
/// CBOR integer rather than as a float. That rule is about the *value*, not
/// about the type the format gives the key — and `"effectiveRate"` is where that bites, being
/// declared a float whose commonest value is `1.0`. Writing it as a float
/// meant this crate and the JavaScript one emitted different major types for
/// the same trace, in the case that occurs most.
#[test]
fn an_integral_effective_rate_is_written_as_a_cbor_integer() {
    let sampling = SamplingInfo { effective_rate: Some(1.0), ..SamplingInfo::default() };
    let mut header =
        TraceHeader::new("moq-transport-19", Perspective::Client, DetailLevel::Control, START_TIME);
    header.sampling = Some(sampling);

    let out = key_of(&written(&header), "sampling").expect("'sampling' is written");
    assert_eq!(
        key_of(&out, "effectiveRate"),
        Some(uint(1)),
        "an integral rate was written as a float"
    );
    assert_eq!(
        roundtrip(&header).sampling.and_then(|s| s.effective_rate),
        Some(1.0),
        "the integer form did not read back as the rate it encodes"
    );
}

/// The other half of the same rule: a value that is *not* integral stays a
/// float, because there is no integer carrying it.
#[test]
fn a_fractional_effective_rate_is_written_as_a_float() {
    let sampling = SamplingInfo { effective_rate: Some(0.25), ..SamplingInfo::default() };
    let mut header =
        TraceHeader::new("moq-transport-19", Perspective::Client, DetailLevel::Control, START_TIME);
    header.sampling = Some(sampling);

    let out = key_of(&written(&header), "sampling").expect("'sampling' is written");
    assert_eq!(key_of(&out, "effectiveRate"), Some(Value::Float(0.25)));
    assert_eq!(roundtrip(&header).sampling.and_then(|s| s.effective_rate), Some(0.25));
}

/// The mirror of the writer rule, which files already exercise: a reader MUST
/// accept a CBOR integer for a key the format types as a float.
#[test]
fn an_effective_rate_written_as_a_cbor_integer_is_read_as_a_rate() {
    let header = read(header_cbor(&[("sampling", cbor_map(&[("effectiveRate", uint(1))]))]));

    let sampling = header.sampling.as_ref().expect("the sampling map is readable");
    assert_eq!(sampling.effective_rate, Some(1.0), "the integer form was refused");
    assert!(sampling.extra.is_empty(), "a rate this reader could use went to the store anyway");
}

/// The same rule as at the top level, in the map one level down.
#[test]
fn a_defined_sampling_key_with_an_unusable_value_is_kept_not_deleted() {
    let cases: Vec<(&str, Value)> = vec![
        ("dropPolicy", uint(1)),
        ("droppedTotal", Value::Integer((-1i64).into())),
        ("droppedSegment", Value::Float(1.5)),
        ("maxEventsPerSec", text("lots")),
        ("rule", Value::Bool(true)),
        ("ruleLang", Value::Null),
    ];

    for (key, value) in cases {
        let header = read(header_cbor(&[("sampling", cbor_map(&[(key, value.clone())]))]));

        let sampling = header.sampling.as_ref().expect("the sampling map is readable");
        assert_eq!(
            store_of(&sampling.extra, key),
            Some(value.clone()),
            "'{key}' carrying {value:?} reached neither its field nor the store"
        );
        let out = key_of(&written(&header), "sampling").expect("'sampling' is written");
        assert_eq!(key_count(&out, key), 1, "'{key}' is not written exactly once");
        assert_eq!(key_of(&out, key), Some(value), "'{key}' was altered on the way out");
    }
}

#[test]
fn a_sampling_that_is_not_a_map_is_kept_and_the_trace_reads_as_unsampled() {
    let header = read(header_cbor(&[("sampling", uint(5))]));

    assert!(header.sampling.is_none());
    assert_eq!(store_of(&header.extra, "sampling"), Some(uint(5)));
    assert_eq!(key_of(&written(&header), "sampling"), Some(uint(5)));
}

#[test]
fn a_sampling_store_entry_naming_a_key_the_map_writes_is_dropped() {
    let sampling = SamplingInfo {
        dropped_total: Some(7),
        extra: vec![(text("droppedTotal"), uint(99)), (text("x-q"), uint(1))],
        ..SamplingInfo::default()
    };
    let mut header =
        TraceHeader::new("moq-transport-19", Perspective::Client, DetailLevel::Control, START_TIME);
    header.sampling = Some(sampling);

    let out = key_of(&written(&header), "sampling").expect("'sampling' is written");
    assert_eq!(key_count(&out, "droppedTotal"), 1, "'droppedTotal' is written twice");
    assert_eq!(key_of(&out, "droppedTotal"), Some(uint(7)), "the store beat the field");
    assert_eq!(key_of(&out, "x-q"), Some(uint(1)), "an unrelated entry was dropped");
}

// ── "custom", which has no store of its own ────────────────

/// Every key in `"custom"` belongs to whoever wrote the trace, so there is no
/// such thing as an unrecognised key there. It is a passthrough.
#[test]
fn custom_round_trips_key_for_key() {
    let custom = cbor_map(&[("payloadMasked", Value::Bool(true)), ("note", text("n"))]);
    let header = read(header_cbor(&[("custom", custom)]));

    let held = header.custom.as_ref().expect("'custom' is readable");
    assert_eq!(held.get("payloadMasked"), Some(&Value::Bool(true)));
    assert_eq!(held.get("note"), Some(&text("n")));
    assert!(header.extra.is_empty(), "a usable 'custom' does not belong in the store");

    let out = key_of(&written(&header), "custom").expect("'custom' is written");
    assert_eq!(key_of(&out, "payloadMasked"), Some(Value::Bool(true)));
    assert_eq!(key_of(&out, "note"), Some(text("n")));
}

#[test]
fn a_custom_that_is_not_a_map_goes_to_the_headers_store() {
    let header = read(header_cbor(&[("custom", uint(5))]));

    assert!(header.custom.is_none());
    assert_eq!(store_of(&header.extra, "custom"), Some(uint(5)));
    assert_eq!(key_count(&written(&header), "custom"), 1);
    assert_eq!(key_of(&written(&header), "custom"), Some(uint(5)));
}

/// A `custom` with a non-text key cannot be held exactly by a string-keyed
/// map, and half of it is not an answer: keeping `{"a": 2}` and dropping the
/// integer key hands the caller a `"custom"` the file never carried. The whole
/// value goes to the header's store instead, where the bytes survive.
#[test]
fn a_custom_with_a_non_text_key_is_kept_whole_rather_than_in_part() {
    let custom = Value::Map(vec![(uint(1), text("x")), (text("a"), uint(2))]);
    let header = read(header_cbor(&[("custom", custom.clone())]));

    assert!(header.custom.is_none(), "a map this type cannot describe reached the field anyway");
    assert_eq!(store_of(&header.extra, "custom"), Some(custom.clone()));
    assert_eq!(key_of(&written(&header), "custom"), Some(custom));
}

/// The same reasoning one step further in: a `BTreeMap` collapses two entries
/// with the same key into one, silently, and what comes back out is not what
/// the file carried. The value goes to the header's store whole, both entries
/// intact, because that half a reader can observe and must not alter.
///
/// The writing half cannot follow it all the way. SPEC.md: "a conformant tool
/// must not *emit* [a map with a repeated key], having read one" — so the
/// rewrite emits the first entry and drops the second, which is the same trade
/// the store itself makes and the most a conformant writer can keep. RFC 8949
/// already calls the map that came in invalid.
#[test]
fn a_custom_with_a_duplicate_key_is_read_whole_and_written_once() {
    let custom = Value::Map(vec![(text("a"), uint(1)), (text("a"), uint(2))]);
    let header = read(header_cbor(&[("custom", custom.clone())]));

    assert!(header.custom.is_none());
    assert_eq!(store_of(&header.extra, "custom"), Some(custom), "the read collapsed the map");

    let out = key_of(&written(&header), "custom").expect("'custom' is written");
    assert_eq!(key_count(&out, "a"), 1, "'a' is written twice");
    assert_eq!(key_of(&out, "a"), Some(uint(1)), "the later entry won");
}

// ── required keys ──────────────────────────────────────────

/// There is no header to construct without these four, and none of them may be
/// filled in with a default: a reader that invents one reports a fabricated
/// trace as a real one.
#[test]
fn a_missing_required_key_is_a_malformed_header() {
    for key in ["protocol", "perspective", "detail", "startTime"] {
        let Value::Map(pairs) = header_cbor(&[]) else { panic!("not a CBOR map") };
        let without: Vec<_> = pairs.into_iter().filter(|(k, _)| k.as_text() != Some(key)).collect();

        assert_eq!(read_err(Value::Map(without)), format!("missing '{key}'"));
    }
}

/// A required key with an unusable value is malformed on the same terms — but
/// it is a different fault from an absent one, and saying "missing" about a
/// key that is right there sends whoever has to fix the file looking for
/// something they already have.
#[test]
fn an_unusable_required_key_is_malformed_and_the_message_says_which_fault_it_was() {
    assert_eq!(
        read_err(cbor_map(&[
            ("protocol", text("moq-transport-19")),
            ("perspective", text("client")),
            ("detail", text("control")),
            ("startTime", Value::Integer((-5i64).into())),
        ])),
        "'startTime' is not an unsigned integer"
    );
    assert_eq!(
        read_err(cbor_map(&[
            ("protocol", text("moq-transport-19")),
            ("perspective", uint(5)),
            ("detail", text("control")),
            ("startTime", uint(START_TIME)),
        ])),
        "'perspective' is not a text string"
    );
}

// ── the encoding a store is written in ─────────────────────

/// SPEC.md's first normative encoding rule reaches into a store — an integral
/// value goes out as a CBOR integer rather than as a float — and a writer that
/// emits a float from its store emits a shape the
/// other implementation cannot emit at all — `cbor-x` hands JavaScript a
/// number, and a number that is integral goes back out as an integer whatever
/// the file held. Two writers, the same input file, different bytes, which is
/// the one thing the rule exists to stop.
///
/// On the way *in* nothing changes: the value in the store is the value the
/// file carried, and only the serialiser applies the house style.
#[test]
fn a_stored_integral_float_is_written_as_a_cbor_integer() {
    let header = read(header_cbor(&[("x-f", Value::Float(3.0))]));

    assert_eq!(
        store_of(&header.extra, "x-f"),
        Some(Value::Float(3.0)),
        "the read must hand back what the file carried"
    );
    assert_eq!(key_of(&written(&header), "x-f"), Some(uint(3)), "an integral float was written");
}

/// The same rule where the reviewer found it: a rate outside `(0.0, 1.0]` is
/// unusable, so it sits in the sampling map's store — and `2.0` there was
/// written `fb4000000000000000` where the JavaScript writer writes `02`.
#[test]
fn a_stored_out_of_range_effective_rate_is_written_as_a_cbor_integer() {
    let header =
        read(header_cbor(&[("sampling", cbor_map(&[("effectiveRate", Value::Float(2.0))]))]));

    let sampling = header.sampling.as_ref().expect("the sampling map is readable");
    assert_eq!(sampling.effective_rate, None, "2.0 was reported as a sampling rate");
    assert_eq!(store_of(&sampling.extra, "effectiveRate"), Some(Value::Float(2.0)));

    let out = key_of(&written(&header), "sampling").expect("'sampling' is written");
    assert_eq!(key_of(&out, "effectiveRate"), Some(uint(2)));
}

/// SPEC.md's second normative encoding rule reaches into a store too: a byte
/// string goes out as major type 2, never wrapped in the typed-array tag 64
/// that RFC 8746 defines. A reader must accept the tag — files carrying it exist, and the
/// corpus has one — and preserve it where it can see it, but a writer must not
/// emit it. `cbor-x` cannot: the tag is gone before its code runs.
#[test]
fn a_stored_tag_64_byte_string_is_written_as_a_plain_byte_string() {
    let tagged = Value::Tag(64, Box::new(Value::Bytes(vec![0xde, 0xad])));
    let header = read(header_cbor(&[("x-b", tagged.clone())]));

    assert_eq!(store_of(&header.extra, "x-b"), Some(tagged), "the read altered the value");
    assert_eq!(
        key_of(&written(&header), "x-b"),
        Some(Value::Bytes(vec![0xde, 0xad])),
        "tag 64 was written back"
    );
}

/// A store entry may be a whole tree, and both rules are about every number
/// and every byte string in it — including the ones used as map keys, which
/// are encoded by the same rules as anything else.
#[test]
fn the_encoding_rules_reach_through_arrays_maps_and_map_keys() {
    let nested = Value::Array(vec![
        Value::Float(7.0),
        Value::Map(vec![
            // A float as a *key*, and a tagged byte string one level further
            // down again.
            (Value::Float(2.0), Value::Tag(64, Box::new(Value::Bytes(vec![0x01])))),
            (text("keep"), Value::Float(0.5)),
        ]),
    ]);
    let header = read(header_cbor(&[("x-deep", nested)]));

    assert_eq!(
        key_of(&written(&header), "x-deep"),
        Some(Value::Array(vec![
            uint(7),
            Value::Map(vec![
                (uint(2), Value::Bytes(vec![0x01])),
                // Not integral, so there is no integer carrying it and it
                // stays a float.
                (text("keep"), Value::Float(0.5)),
            ]),
        ]))
    );
}

/// The one value the rule changes rather than merely re-encoding. SPEC.md
/// calls it out and declines to carve it out — no field in a trace gives
/// negative zero a meaning — so this pins the accepted loss rather than
/// guarding against it.
#[test]
fn a_stored_negative_zero_loses_its_sign_on_the_way_out() {
    let header = read(header_cbor(&[("x-z", Value::Float(-0.0))]));

    let Some(Value::Float(stored)) = store_of(&header.extra, "x-z") else {
        panic!("the read did not keep the float");
    };
    assert!(stored.is_sign_negative(), "the read must not be the thing that loses the sign");
    assert_eq!(key_of(&written(&header), "x-z"), Some(uint(0)));
}

/// `"custom"` is a passthrough, and "written back as it was handed over" binds
/// the value rather than its encoding — the same line the stores are on. The
/// JavaScript implementation's `custom` cannot hold either shape either, so a
/// float here is the same two-writers-two-files problem in the one map this
/// crate hands back whole.
#[test]
fn the_encoding_rules_reach_into_custom_too() {
    let header = read(header_cbor(&[(
        "custom",
        cbor_map(&[
            ("count", Value::Float(4.0)),
            ("blob", Value::Tag(64, Box::new(Value::Bytes(vec![0x07])))),
        ]),
    )]));

    let held = header.custom.as_ref().expect("'custom' is readable");
    assert_eq!(held.get("count"), Some(&Value::Float(4.0)), "the read altered 'custom'");

    let out = key_of(&written(&header), "custom").expect("'custom' is written");
    assert_eq!(key_of(&out, "count"), Some(uint(4)));
    assert_eq!(key_of(&out, "blob"), Some(Value::Bytes(vec![0x07])));
}

// ── one key, never twice ───────────────────────────────────

/// A store is an ordered list of pairs and not a map, so a caller can build
/// one holding a key twice — and both entries used to go into the file. RFC
/// 8949 calls that map invalid, the JavaScript reader silently collapses it,
/// and SPEC.md forbids emitting one at all.
///
/// The first entry is the one written: every read in this crate goes through
/// a first-match lookup, so writing the first is what makes the value a caller
/// is shown the value that survives the rewrite.
#[test]
fn a_store_holding_one_key_twice_writes_it_once() {
    let mut header =
        TraceHeader::new("moq-transport-19", Perspective::Client, DetailLevel::Control, START_TIME);
    header.extra = vec![(text("x-a"), uint(1)), (text("x-a"), uint(2)), (text("x-b"), uint(3))];

    let out = written(&header);
    assert_eq!(key_count(&out, "x-a"), 1, "'x-a' is written twice");
    assert_eq!(key_of(&out, "x-a"), Some(uint(1)), "the later entry won");
    assert_eq!(key_of(&out, "x-b"), Some(uint(3)), "an unrelated entry was dropped");
}

/// The same rule in the two maps one level down, which share the code path.
#[test]
fn a_segment_or_sampling_store_holding_one_key_twice_writes_it_once() {
    let mut segment = SegmentInfo::new(0);
    segment.extra = vec![(text("x-a"), uint(1)), (text("x-a"), uint(2))];
    let sampling = SamplingInfo {
        extra: vec![(text("x-b"), uint(1)), (text("x-b"), uint(2))],
        ..SamplingInfo::default()
    };
    let mut header =
        TraceHeader::new("moq-transport-19", Perspective::Client, DetailLevel::Control, START_TIME);
    header.segment = Some(segment);
    header.sampling = Some(sampling);

    let out = written(&header);
    let segment_out = key_of(&out, "segment").expect("'segment' is written");
    let sampling_out = key_of(&out, "sampling").expect("'sampling' is written");
    assert_eq!(key_count(&segment_out, "x-a"), 1, "'x-a' is written twice");
    assert_eq!(key_of(&segment_out, "x-a"), Some(uint(1)));
    assert_eq!(key_count(&sampling_out, "x-b"), 1, "'x-b' is written twice");
    assert_eq!(key_of(&sampling_out, "x-b"), Some(uint(1)));
}

/// Two keys a store tells apart and a file cannot: normalising `Float(1.0)` to
/// `Integer(1)` is what makes them the same key, so the duplicate check has to
/// run after it rather than before.
#[test]
fn two_store_keys_that_normalise_together_are_written_once() {
    let mut header =
        TraceHeader::new("moq-transport-19", Perspective::Client, DetailLevel::Control, START_TIME);
    header.extra = vec![(Value::Float(1.0), text("first")), (uint(1), text("second"))];

    let Value::Map(out) = written(&header) else { panic!("not a CBOR map") };
    let ones: Vec<&(Value, Value)> = out.iter().filter(|(k, _)| *k == uint(1)).collect();
    assert_eq!(ones.len(), 1, "the key 1 is written twice: {out:?}");
    assert_eq!(ones[0].1, text("first"), "the later entry won");
}

/// The rule binds every map the writer emits, not only the outermost: SPEC.md
/// says a conformant tool must not emit a map with a repeated key "having read
/// one", and a store entry may be a whole tree with one somewhere inside it.
/// The read keeps both entries, since that half is observable here; the write
/// keeps the first.
#[test]
fn a_duplicate_key_inside_a_stored_value_is_written_once() {
    let nested = Value::Map(vec![(text("a"), uint(1)), (text("a"), uint(2))]);
    let header = read(header_cbor(&[("x-deep", nested.clone())]));

    assert_eq!(store_of(&header.extra, "x-deep"), Some(nested), "the read collapsed the map");

    let out = key_of(&written(&header), "x-deep").expect("'x-deep' is written");
    assert_eq!(key_count(&out, "a"), 1, "'a' is written twice");
    assert_eq!(key_of(&out, "a"), Some(uint(1)), "the later entry won");
}

/// Two NaN keys are one key in a file — both encode to the same bytes — and
/// `Value`'s equality says otherwise, following IEEE 754 rather than CBOR. It
/// is the one pair of keys a plain equality check would let through.
#[test]
fn two_nan_store_keys_are_written_once() {
    let mut header =
        TraceHeader::new("moq-transport-19", Perspective::Client, DetailLevel::Control, START_TIME);
    header.extra =
        vec![(Value::Float(f64::NAN), text("first")), (Value::Float(f64::NAN), text("second"))];

    let Value::Map(out) = written(&header) else { panic!("not a CBOR map") };
    let nans: Vec<&(Value, Value)> =
        out.iter().filter(|(k, _)| matches!(k, Value::Float(f) if f.is_nan())).collect();
    assert_eq!(nans.len(), 1, "a NaN key is written twice: {out:?}");
    assert_eq!(nans[0].1, text("first"), "the later entry won");
}

/// An input map carrying one key twice is invalid under RFC 8949, and SPEC.md
/// leaves the two readers free to disagree about which entry wins — but not to
/// lose the other one. The field takes the first entry; the second used to be
/// dropped along with it, because the store was filtered by key *name*, so a
/// value the file carried reached neither the field nor the store.
#[test]
fn a_duplicate_key_on_input_keeps_the_entry_no_field_took() {
    let header = read(cbor_map(&[
        ("protocol", text("moq-transport-19")),
        ("perspective", text("client")),
        ("detail", text("control")),
        ("startTime", uint(START_TIME)),
        ("transport", text("webtransport")),
        ("transport", uint(42)),
    ]));

    assert_eq!(header.transport.as_deref(), Some("webtransport"), "the field took the wrong entry");
    assert_eq!(
        header.extra,
        vec![(text("transport"), uint(42))],
        "the entry no field took was deleted by reading the file"
    );

    // Written once all the same: preserving the loser must not produce a map
    // that carries `"transport"` twice.
    let out = written(&header);
    assert_eq!(key_count(&out, "transport"), 1, "'transport' is written twice");
    assert_eq!(key_of(&out, "transport"), Some(text("webtransport")));

    // And the rewrite is a fixed point from there: what the file can hold is
    // one entry, and reading it back finds nothing left over.
    assert!(roundtrip(&header).extra.is_empty());
}

/// The same on a required key, where the first entry is taken whatever it
/// holds. Nothing here depends on *which* entry wins — only on the other one
/// surviving the read.
#[test]
fn a_duplicate_required_key_on_input_keeps_the_entry_no_field_took() {
    let header = read(cbor_map(&[
        ("protocol", text("moq-transport-19")),
        ("protocol", text("moq-transport-01")),
        ("perspective", text("client")),
        ("detail", text("control")),
        ("startTime", uint(START_TIME)),
    ]));

    assert_eq!(header.protocol, "moq-transport-19");
    assert_eq!(header.extra, vec![(text("protocol"), text("moq-transport-01"))]);
    assert_eq!(key_count(&written(&header), "protocol"), 1, "'protocol' is written twice");
}

// ── through a file, not just a `Value` ─────────────────────

/// The stores have to survive the encoder as bytes, not merely as a `Value`: a
/// definite-length map header that counts the wrong number of entries produces
/// a file no decoder will read past.
///
/// Asserted against the content the file was built from, key by key, and not
/// against the header decoded a moment ago. Comparing a decode with a decode
/// of one's own encode is the shape SPEC.md's Interoperability section exists
/// to warn about — "each read only bytes it had written itself" — and here it
/// was vacuous outright: delete the store mechanism entirely and both sides
/// are storeless, equal, and green.
#[test]
fn the_stores_survive_a_file_round_trip() {
    let source = read(header_cbor(&[
        ("x-note", text("hello")),
        ("transport", uint(42)),
        ("segment", segment_cbor(&[("x-rot", text("size"))])),
        ("sampling", cbor_map(&[("appliesTo", Value::Array(vec![uint(3), text("x")]))])),
        ("custom", Value::Map(vec![(uint(1), text("x"))])),
    ]));

    let mut buf = Vec::new();
    let writer = MoqTraceWriter::new(&mut buf, &source).expect("the header is writable");
    drop(writer);
    let reader = MoqTraceReader::new(Cursor::new(&buf)).expect("the file is readable");
    let read_back = reader.header();

    // The four keys no store is involved in, so that a file that lost its way
    // entirely fails here rather than further down.
    assert_eq!(read_back.protocol, "moq-transport-19");
    assert_eq!(read_back.perspective, Perspective::Client);
    assert_eq!(read_back.detail, DetailLevel::Control);
    assert_eq!(read_back.start_time, START_TIME);

    // The header's own store, in the order the file carried: an unknown key,
    // a defined key whose value no field could take, and a `"custom"` this
    // crate cannot hold exactly.
    assert_eq!(read_back.transport, None, "'transport': 42 reached the field");
    assert!(read_back.custom.is_none(), "a 'custom' with a non-text key reached the field");
    assert_eq!(
        read_back.extra,
        vec![
            (text("x-note"), text("hello")),
            (text("transport"), uint(42)),
            (text("custom"), Value::Map(vec![(uint(1), text("x"))])),
        ],
        "the header's store did not come back through the file"
    );

    // The `"segment"` map's store, which is its own and not the header's.
    let segment = read_back.segment.as_ref().expect("'segment' came back");
    assert_eq!(segment.sequence, 0);
    assert_eq!(segment.extra, vec![(text("x-rot"), text("size"))]);

    // And the `"sampling"` map's, holding an `"appliesTo"` that is kept whole
    // or not at all.
    let sampling = read_back.sampling.as_ref().expect("'sampling' came back");
    assert_eq!(sampling.applies_to, None, "a mixed 'appliesTo' reached the field");
    assert_eq!(sampling.extra, vec![(text("appliesTo"), Value::Array(vec![uint(3), text("x")]))]);
}

/// `TraceHeader::new` and the other constructors leave every store empty, so a
/// header this crate builds writes exactly the keys it holds.
#[test]
fn a_header_this_crate_builds_carries_no_store() {
    let mut header =
        TraceHeader::new("moq-transport-19", Perspective::Client, DetailLevel::Control, START_TIME);
    header.segment = Some(SegmentInfo::new(0));
    header.sampling = Some(SamplingInfo::default());
    header.custom = Some(BTreeMap::from([("payloadMasked".to_string(), Value::Bool(true))]));

    assert!(header.extra.is_empty());
    assert!(header.segment.as_ref().unwrap().extra.is_empty());
    assert!(header.sampling.as_ref().unwrap().extra.is_empty());
    assert_eq!(roundtrip(&header), header);
}

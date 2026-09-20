use ciborium::Value;
use moqtap_trace::event::*;
use moqtap_trace::header::DetailLevel;

mod corpus;

fn sample_control_event() -> TraceEvent {
    TraceEvent::new(
        0,
        1000,
        EventData::ControlMessage {
            direction: Direction::Send,
            message_type: 0x03,
            // snake_case, as the drafts name these fields and as every writer
            // of these files spells them. This fixture said `requestId` and
            // `trackName`, which no producer has ever written, so the accessor
            // it gated was free to look for a key nothing carried.
            message: Value::Map(vec![
                (Value::Text("request_id".into()), Value::Integer(42.into())),
                (Value::Text("track_name".into()), Value::Text("video".into())),
            ]),
            stream_id: None,
            raw: None,
        },
    )
}

fn roundtrip(event: &TraceEvent) -> TraceEvent {
    let cbor: Value = event.into();
    TraceEvent::try_from(cbor).unwrap()
}

#[test]
fn control_event_cbor_roundtrip() {
    let event = sample_control_event();
    assert_eq!(roundtrip(&event), event);
}

#[test]
fn control_event_with_raw_roundtrip() {
    let event = TraceEvent::new(
        1,
        2000,
        EventData::ControlMessage {
            direction: Direction::Receive,
            message_type: 0x04,
            message: Value::Map(vec![]),
            stream_id: None,
            raw: Some(vec![0x03, 0x00, 0x04]),
        },
    );
    assert_eq!(roundtrip(&event), event);
}

#[test]
fn control_event_with_stream_id_roundtrip() {
    // From draft-17 a response carries no request ID — the request stream it
    // arrives on is the only thing tying it to its request, so the trace has
    // to preserve that stream.
    let event = TraceEvent::new(
        1,
        2000,
        EventData::ControlMessage {
            direction: Direction::Receive,
            message_type: 0x04,
            message: Value::Map(vec![]),
            stream_id: Some(12),
            raw: None,
        },
    );
    assert_eq!(roundtrip(&event), event);
}

#[test]
fn control_event_stream_id_written_by_the_js_encoder_reads_back() {
    // Bytes produced by @moqtap/trace for a SUBSCRIBE_OK on stream 12. Fixed
    // here rather than described, because the risk is encoding: JS holds the
    // stream id as a BigInt, and had cbor-x written it as a bignum tag instead
    // of a CBOR uint, this side would silently read no stream id at all.
    const JS_EVENT: &[u8] = &[
        0xb9, 0x00, 0x07, 0x61, 0x6e, 0x00, 0x61, 0x74, 0x19, 0x03, 0xe8, 0x61, 0x65, 0x00, 0x61,
        0x64, 0x01, 0x62, 0x6d, 0x74, 0x04, 0x63, 0x6d, 0x73, 0x67, 0xb9, 0x00, 0x01, 0x64, 0x74,
        0x79, 0x70, 0x65, 0x6c, 0x73, 0x75, 0x62, 0x73, 0x63, 0x72, 0x69, 0x62, 0x65, 0x5f, 0x6f,
        0x6b, 0x63, 0x73, 0x69, 0x64, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c,
    ];

    let value: Value = ciborium::de::from_reader(JS_EVENT).unwrap();
    let event = TraceEvent::try_from(value).unwrap();

    let EventData::ControlMessage { stream_id, message_type, .. } = event.data else {
        panic!("expected a control message");
    };
    assert_eq!(stream_id, Some(12));
    assert_eq!(message_type, 0x04);
}

#[test]
fn control_event_without_stream_id_omits_the_key() {
    // A recorder that has no stream context must not be made to invent one,
    // and "unknown" has to stay distinguishable from stream 0.
    let cbor: Value = (&sample_control_event()).into();
    let Value::Map(pairs) = cbor else { panic!("event is not a CBOR map") };
    assert!(!pairs.iter().any(|(k, _)| k.as_text() == Some("sid")));
}

#[test]
fn stream_opened_roundtrip() {
    let event = TraceEvent::new(
        2,
        3000,
        EventData::StreamOpened {
            stream_id: 4,
            direction: Direction::Receive,
            stream_type: StreamType::Subgroup,
            track_alias: None,
            subgroup_id: None,
            fetch_request_id: None,
            group_id: None,
        },
    );
    assert_eq!(roundtrip(&event), event);
}

#[test]
fn stream_closed_roundtrip() {
    let event = TraceEvent::new(3, 4000, EventData::StreamClosed { stream_id: 4, error_code: 0 });
    assert_eq!(roundtrip(&event), event);
}

#[test]
fn object_header_roundtrip() {
    let event = TraceEvent::new(
        4,
        5000,
        EventData::ObjectHeader {
            stream_id: 4,
            group: 1,
            object: 0,
            publisher_priority: 128,
            object_status: 0,
        },
    );
    assert_eq!(roundtrip(&event), event);
}

#[test]
fn object_payload_without_bytes_roundtrip() {
    let event = TraceEvent::new(
        5,
        6000,
        EventData::ObjectPayload { stream_id: 4, group: 1, object: 0, size: 1024, payload: None },
    );
    assert_eq!(roundtrip(&event), event);
}

#[test]
fn object_payload_with_bytes_roundtrip() {
    let event = TraceEvent::new(
        6,
        7000,
        EventData::ObjectPayload {
            stream_id: 4,
            group: 1,
            object: 0,
            size: 5,
            payload: Some(vec![0x48, 0x65, 0x6c, 0x6c, 0x6f]),
        },
    );
    assert_eq!(roundtrip(&event), event);
}

#[test]
fn state_change_roundtrip() {
    let event = TraceEvent::new(
        7,
        8000,
        EventData::StateChange { from: "connecting".into(), to: "connected".into() },
    );
    assert_eq!(roundtrip(&event), event);
}

#[test]
fn error_event_roundtrip() {
    let event = TraceEvent::new(
        8,
        9000,
        EventData::Error {
            error_code: 0x01,
            reason: "protocol violation".into(),
            stream_id: None,
            kind: None,
            raw_len: None,
            raw: None,
        },
    );
    assert_eq!(roundtrip(&event), event);
}

#[test]
fn annotation_roundtrip() {
    let event = TraceEvent::new(
        9,
        10000,
        EventData::Annotation {
            label: "custom-mark".into(),
            data: Value::Text("checkpoint".into()),
        },
    );
    assert_eq!(roundtrip(&event), event);
}

#[test]
fn request_id_extracted_from_msg() {
    let event = sample_control_event();
    assert_eq!(event.request_id(), Some(42));
}

/// The accessor and the corpus have to agree on how the key is spelled.
///
/// They did not: the corpus wrote `request_id` and said in a comment that it
/// matched the shared vectors, while the accessor looked for `requestId`, so
/// `request_id()` answered `None` for every event in this crate's own canonical
/// trace. A fixture of the accessor's own making cannot catch that, because it
/// spells the key whichever way the accessor reads it. This asks the corpus.
#[test]
fn the_corpus_answers_its_own_accessor() {
    let control: Vec<_> = corpus::v2_basic()
        .events
        .into_iter()
        .filter(|e| matches!(e.data, EventData::ControlMessage { .. }))
        .collect();
    assert!(!control.is_empty(), "corpus carries no control message to ask");
    for event in control {
        assert!(
            event.request_id().is_some(),
            "corpus control event {} carries a decoded msg the accessor cannot read",
            event.seq
        );
    }
}

#[test]
fn request_id_none_for_non_control() {
    let event = TraceEvent::new(0, 0, EventData::StateChange { from: "a".into(), to: "b".into() });
    assert_eq!(event.request_id(), None);
}

#[test]
fn direction_accessor() {
    let event = sample_control_event();
    assert_eq!(event.direction(), Some(Direction::Send));
}

#[test]
fn message_type_accessor() {
    let event = sample_control_event();
    assert_eq!(event.message_type(), Some(0x03));
}

#[test]
fn stream_type_variants() {
    for st in [StreamType::Subgroup, StreamType::Datagram, StreamType::Fetch] {
        let event = TraceEvent::new(
            0,
            0,
            EventData::StreamOpened {
                stream_id: 1,
                direction: Direction::Send,
                stream_type: st,
                track_alias: None,
                subgroup_id: None,
                fetch_request_id: None,
                group_id: None,
            },
        );
        let EventData::StreamOpened { stream_type, .. } = roundtrip(&event).data else {
            panic!("wrong variant");
        };
        assert_eq!(stream_type, st);
    }
}

// ── the stream identifiers on event 1 ──────────────────────

/// An event 1 CBOR map carrying whatever a writer put on it. Built by hand
/// rather than by serializing a `TraceEvent`, because most of these cases are
/// files this crate would not write itself.
fn stream_opened_cbor(stream_type: u64, identifiers: &[(&str, u64)]) -> Value {
    let mut pairs = vec![
        (Value::Text("n".into()), Value::Integer(0.into())),
        (Value::Text("t".into()), Value::Integer(100.into())),
        (Value::Text("e".into()), Value::Integer(1.into())),
        (Value::Text("sid".into()), Value::Integer(4.into())),
        (Value::Text("d".into()), Value::Integer(1.into())),
        (Value::Text("st".into()), Value::Integer(stream_type.into())),
    ];
    for (key, value) in identifiers {
        pairs.push((Value::Text((*key).into()), Value::Integer((*value).into())));
    }
    Value::Map(pairs)
}

fn key_count(cbor: &Value, key: &str) -> usize {
    let Value::Map(pairs) = cbor else { panic!("event is not a CBOR map") };
    pairs.iter().filter(|(k, _)| k.as_text() == Some(key)).count()
}

/// No detail level records the bytes of a `SUBGROUP_HEADER`, so a track alias
/// and a subgroup ID are recorded as fields or not at all — and until these
/// fields existed, a `headers` trace could not say which track a stream
/// belonged to, which is most of what the level exists for.
#[test]
fn a_subgroup_stream_round_trips_its_track_alias_and_subgroup_id() {
    let event = TraceEvent::new(
        0,
        100,
        EventData::StreamOpened {
            stream_id: 4,
            direction: Direction::Receive,
            stream_type: StreamType::Subgroup,
            // Distinct values, so a writer that crossed the two keys is caught
            // rather than cancelling itself out on the way back.
            track_alias: Some(7),
            subgroup_id: Some(2),
            fetch_request_id: None,
            group_id: None,
        },
    );
    assert_eq!(roundtrip(&event), event);
}

/// The one identifier a writer MUST fill in. A fetch stream carries no track
/// alias to be found by instead, so the fetch request ID is the only thing
/// tying the stream to the FETCH that asked for it.
#[test]
fn a_fetch_stream_round_trips_its_request_id() {
    let event = TraceEvent::new(
        0,
        100,
        EventData::StreamOpened {
            stream_id: 8,
            direction: Direction::Send,
            stream_type: StreamType::Fetch,
            track_alias: None,
            subgroup_id: None,
            fetch_request_id: Some(19),
            group_id: None,
        },
    );
    assert_eq!(roundtrip(&event), event);
}

/// A datagram is the stream type whose group varies per event, which is why
/// `"g"` is scoped to it: on a subgroup stream every object carries the group
/// of the stream, so a copy there would have no independent source.
#[test]
fn a_datagram_stream_round_trips_its_group_id() {
    let event = TraceEvent::new(
        0,
        100,
        EventData::StreamOpened {
            stream_id: 12,
            direction: Direction::Receive,
            stream_type: StreamType::Datagram,
            track_alias: Some(7),
            subgroup_id: None,
            fetch_request_id: None,
            group_id: Some(11),
        },
    );
    assert_eq!(roundtrip(&event), event);
}

/// All four are optional and every recording made before they existed carries
/// none of them, so a reader that required one — or a writer that emitted the
/// key regardless — would be at odds with the whole back catalogue.
#[test]
fn a_stream_opened_carrying_none_of_them_still_round_trips() {
    let event = stream_opened();
    assert_eq!(roundtrip(&event), event);

    let cbor: Value = (&event).into();
    for key in ["ta", "sg", "fri", "g"] {
        assert_eq!(key_count(&cbor, key), 0, "'{key}' was written for a field that is None");
    }
}

/// The failure this guards is silent. A key read into a named field but left
/// out of the event type's key list is collected into `extra` as well, so the
/// event decodes correctly, compares equal to itself, and serializes to a CBOR
/// map with a duplicate key. It has happened here once already, on a different
/// event type.
#[test]
fn the_stream_identifiers_never_land_in_extra() {
    let mut cbor = stream_opened_cbor(0, &[("ta", 7), ("sg", 2), ("fri", 19), ("g", 11)]);
    let Value::Map(ref mut pairs) = cbor else { panic!("event is not a CBOR map") };
    pairs.push((Value::Text("zz".into()), Value::Text("from the future".into())));

    let event = TraceEvent::try_from(cbor).unwrap();
    assert_eq!(
        event.extra,
        vec![(Value::Text("zz".into()), Value::Text("from the future".into()))],
        "a key event 1 owns was collected as an unrecognised one"
    );
}

/// Through raw bytes rather than a `Value`, because both failures this catches
/// are invisible in one: a duplicate key becomes two entries in a `Vec` that a
/// reader hands back without complaint, and a definite-length map header
/// counting the wrong number of entries is never written at all.
#[test]
fn a_re_serialized_event_1_carries_each_key_once() {
    let event = TraceEvent::try_from(stream_opened_cbor(
        0,
        &[("ta", 7), ("sg", 2), ("fri", 19), ("g", 11)],
    ))
    .unwrap()
    .with_extra(vec![(Value::Text("zz".into()), Value::Integer(1.into()))]);

    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&event, &mut bytes).expect("serialization is infallible");
    let written: Value =
        ciborium::de::from_reader(bytes.as_slice()).expect("the encoded map is well-formed CBOR");

    for key in ["n", "t", "e", "sid", "d", "st", "ta", "sg", "fri", "g", "zz"] {
        assert_eq!(key_count(&written, key), 1, "'{key}' is not written exactly once");
    }
    let Value::Map(pairs) = &written else { panic!("event is not a CBOR map") };
    assert_eq!(pairs.len(), 11, "the map carries entries beyond the keys asked for: {pairs:?}");
}

/// A writer MUST NOT put a subgroup ID on a fetch stream, where it has no
/// source. A reader that met one there and rejected the event would turn one
/// writer's bug into unreadable evidence, so it is kept: "ignore" means read
/// past and hand back, the same rule that governs `extra`.
#[test]
fn a_stream_identifier_outside_its_scope_is_kept_rather_than_rejected() {
    let event = TraceEvent::try_from(stream_opened_cbor(2, &[("sg", 2), ("fri", 19)]))
        .expect("a key outside its stream type is not a malformed event");

    assert!(event.extra.is_empty());
    assert_eq!(roundtrip(&event), event, "the out-of-scope key did not survive a rewrite");

    let EventData::StreamOpened { stream_type, subgroup_id, fetch_request_id, .. } = event.data
    else {
        panic!("expected a stream open");
    };
    assert_eq!(stream_type, StreamType::Fetch);
    assert_eq!(subgroup_id, Some(2));
    assert_eq!(fetch_request_id, Some(19));
}

// ── the bytes behind an error, on event 6 ──────────────────

/// An event 6 CBOR map carrying whatever a writer put on it, built by hand
/// rather than by serializing a `TraceEvent`: most of these cases are files
/// this crate would not write itself, and the ones it would are worth pinning
/// against a value written out here rather than against its own encoder.
fn error_cbor(extra: &[(&str, Value)]) -> Value {
    let mut pairs = vec![
        (Value::Text("n".into()), Value::Integer(3.into())),
        (Value::Text("t".into()), Value::Integer(700.into())),
        (Value::Text("e".into()), Value::Integer(6.into())),
        (Value::Text("ec".into()), Value::Integer(5.into())),
        (Value::Text("reason".into()), Value::Text("SUBSCRIBE_OK did not parse".into())),
    ];
    for (key, value) in extra {
        pairs.push((Value::Text((*key).into()), value.clone()));
    }
    Value::Map(pairs)
}

/// The bytes an event is written as, decoded back into a `Value`.
///
/// Through the encoder rather than through `Value::serialized`, so the
/// definite-length map header is exercised too: a variant that gained a field
/// without gaining an entry in the count writes a header promising a different
/// number of pairs than follow, and only the byte stream can show it.
fn encoded(event: &TraceEvent) -> Value {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(event, &mut bytes).expect("serialization is infallible");
    ciborium::de::from_reader(bytes.as_slice()).expect("the encoded map is well-formed CBOR")
}

/// All four keys, written and read against values spelled out here rather than
/// against a decode of this crate's own encode.
///
/// The pairing of `rawlen` with a shorter `raw` is the ordinary case rather
/// than a corner: the length is the input the recorder held, before the cap
/// bit, so a reader comparing the two is how it learns the capture is partial
/// and by how much.
#[test]
fn an_error_writes_its_stream_kind_length_and_bytes() {
    let event = TraceEvent::new(
        3,
        700,
        EventData::Error {
            error_code: 5,
            reason: "SUBSCRIBE_OK did not parse".into(),
            stream_id: Some(6),
            kind: Some(ErrorKind::Decode),
            raw_len: Some(9),
            raw: Some(vec![0x04, 0xff, 0x03]),
        },
    );

    let written = encoded(&event);
    for (key, value) in [
        ("n", Value::Integer(3.into())),
        ("t", Value::Integer(700.into())),
        ("e", Value::Integer(6.into())),
        ("ec", Value::Integer(5.into())),
        ("reason", Value::Text("SUBSCRIBE_OK did not parse".into())),
        ("sid", Value::Integer(6.into())),
        ("ek", Value::Text("decode".into())),
        ("rawlen", Value::Integer(9.into())),
        ("raw", Value::Bytes(vec![0x04, 0xff, 0x03])),
    ] {
        assert_eq!(key_count(&written, key), 1, "'{key}' is not written exactly once");
        assert_eq!(key_of(&written, key), Some(value), "'{key}' was not written as expected");
    }
    let Value::Map(pairs) = &written else { panic!("event is not a CBOR map") };
    assert_eq!(pairs.len(), 9, "the map carries entries beyond the nine keys: {pairs:?}");

    // And back, against the same literals rather than against the event above.
    let decoded = TraceEvent::try_from(written).expect("the written event reads back");
    let EventData::Error { error_code, reason, stream_id, kind, raw_len, raw } = decoded.data
    else {
        panic!("expected an error event");
    };
    assert_eq!(error_code, 5);
    assert_eq!(reason, "SUBSCRIBE_OK did not parse");
    assert_eq!(stream_id, Some(6));
    assert_eq!(kind, Some(ErrorKind::Decode));
    assert_eq!(raw_len, Some(9));
    assert_eq!(raw, Some(vec![0x04, 0xff, 0x03]));
}

/// Every one of the four is optional, and every recording made before they
/// existed carries none of them — so a writer that emitted a key for an empty
/// field would put a `"raw"` of nothing into a `control`-level trace.
#[test]
fn an_error_carrying_none_of_them_writes_none_of_the_keys() {
    let event = TraceEvent::new(
        3,
        700,
        EventData::Error {
            error_code: 5,
            reason: "peer closed".into(),
            stream_id: None,
            kind: None,
            raw_len: None,
            raw: None,
        },
    );

    let written = encoded(&event);
    for key in ["sid", "ek", "rawlen", "raw"] {
        assert_eq!(key_count(&written, key), 0, "'{key}' was written for a field that is None");
    }
    let Value::Map(pairs) = &written else { panic!("event is not a CBOR map") };
    assert_eq!(pairs.len(), 5, "the map carries entries beyond n, t, e, ec and reason: {pairs:?}");
}

/// Absent is not zero. A recorder sitting at the session level has no stream to
/// report and says so by omitting the key, and an error that names stream 0 is
/// a different statement — the same rule event 0's `"sid"` carries.
#[test]
fn an_absent_error_stream_id_is_not_stream_zero() {
    let absent = TraceEvent::try_from(error_cbor(&[])).expect("no 'sid' is not a malformed event");
    let EventData::Error { stream_id, .. } = absent.data else { panic!("expected an error") };
    assert_eq!(stream_id, None, "an omitted 'sid' must not read as a stream");

    let zero = TraceEvent::try_from(error_cbor(&[("sid", Value::Integer(0.into()))]))
        .expect("stream 0 is a stream");
    let EventData::Error { stream_id, .. } = zero.data else { panic!("expected an error") };
    assert_eq!(stream_id, Some(0), "'sid': 0 must read as stream 0");
}

/// `"ek"` is an open vocabulary: this revision names three kinds and others may
/// be added without a version bump, so a spelling this crate has never seen is
/// kept as it was found rather than refused or renamed.
#[test]
fn an_unrecognised_error_kind_is_kept_verbatim() {
    for (spelling, kind) in [
        ("protocol", ErrorKind::Protocol),
        ("transport", ErrorKind::Transport),
        ("decode", ErrorKind::Decode),
        ("starvation", ErrorKind::Other("starvation".into())),
    ] {
        let event = TraceEvent::try_from(error_cbor(&[("ek", Value::Text(spelling.into()))]))
            .unwrap_or_else(|e| panic!("'{spelling}' is not a malformed event: {e}"));

        let EventData::Error { kind: read, .. } = &event.data else {
            panic!("expected an error event");
        };
        assert_eq!(read.as_ref(), Some(&kind), "'{spelling}' did not read as the kind it names");
        assert!(event.extra.is_empty(), "'{spelling}' was collected as an unrecognised key");
        assert_eq!(
            key_of(&encoded(&event), "ek"),
            Some(Value::Text(spelling.into())),
            "'{spelling}' was not written back as it was found"
        );
    }
}

/// The failure this guards is silent. A key read into a named field but left
/// out of the event type's key list is collected into `extra` as well, so the
/// event decodes correctly, compares equal to itself, and serializes to a CBOR
/// map with a duplicate key.
#[test]
fn the_error_keys_never_land_in_extra() {
    let event = TraceEvent::try_from(error_cbor(&[
        ("sid", Value::Integer(6.into())),
        ("ek", Value::Text("protocol".into())),
        ("rawlen", Value::Integer(9.into())),
        ("raw", Value::Bytes(vec![0x04])),
        ("zz", Value::Text("from the future".into())),
    ]))
    .expect("an event 6 carrying all four keys reads");

    assert_eq!(
        event.extra,
        vec![(Value::Text("zz".into()), Value::Text("from the future".into()))],
        "a key event 6 owns was collected as an unrecognised one"
    );
    for key in ["ec", "reason", "sid", "ek", "rawlen", "raw", "zz"] {
        assert_eq!(key_count(&encoded(&event), key), 1, "'{key}' is not written exactly once");
    }
}

/// A defined key whose value the reader cannot use is unrecognised, not
/// deletable: the field stays empty, the entry is kept, and it is written back
/// as it was found. Knowing more about a key must not mean preserving it less
/// — which is the trap every one of these four walked into the moment the crate
/// learned their names, since before that they survived as unknown keys.
#[test]
fn a_wrong_typed_error_key_is_kept_as_an_unrecognised_key() {
    let unusable_bytes = vec![
        ("text", Value::Text("0x04".into())),
        ("an integer", Value::Integer(4.into())),
        ("an array of byte values", Value::Array(vec![uint(4), uint(255)])),
        ("null", Value::Null),
    ];
    let unusable_text = vec![
        ("an integer", Value::Integer(1.into())),
        ("a byte string", Value::Bytes(vec![0x64])),
        ("a boolean", Value::Bool(false)),
        ("null", Value::Null),
    ];

    let cases: Vec<(&str, Vec<(&str, Value)>)> = vec![
        ("sid", unusable_uints()),
        ("rawlen", unusable_uints()),
        ("ek", unusable_text),
        ("raw", unusable_bytes),
    ];

    for (key, values) in cases {
        for (what, value) in values {
            let event = TraceEvent::try_from(error_cbor(&[(key, value.clone())]))
                .unwrap_or_else(|e| panic!("{what} for '{key}' is not a malformed event: {e}"));

            let EventData::Error { stream_id, kind, raw_len, raw, .. } = &event.data else {
                panic!("expected an error event");
            };
            assert_eq!(*stream_id, None, "{what} was read into a field of event 6");
            assert_eq!(kind.as_ref(), None, "{what} was read into a field of event 6");
            assert_eq!(*raw_len, None, "{what} was read into a field of event 6");
            assert_eq!(raw.as_ref(), None, "{what} was read into a field of event 6");

            assert_eq!(
                event.extra,
                vec![(Value::Text(key.into()), value.clone())],
                "{what} for '{key}' was not kept verbatim"
            );

            // The value through `Value` and the count through the bytes. A
            // tag 2 bignum goes out as it came in and comes back as the
            // integer it carries, which is ciborium folding a shape away
            // below this test rather than the writer altering anything —
            // the count is what the byte stream is here for.
            assert_eq!(
                key_of(&Value::from(&event), key),
                Some(value.clone()),
                "{what} for '{key}' was altered on the way out"
            );
            assert_eq!(key_count(&encoded(&event), key), 1, "'{key}' is not written exactly once");
        }
    }
}

/// The cap binds a recorder building an event out of bytes it just observed,
/// and nothing else. A reader meeting a longer `"raw"` must not refuse it and a
/// rewrite must not shorten it: re-truncating destroys evidence to make someone
/// else's file conform to a rule it was never handed.
///
/// The failure this catches is silent in exactly the wrong direction — a cap in
/// the serializer passes every test built from short fixtures and quietly
/// discards the bytes of every over-long capture that passes through.
#[test]
fn a_raw_longer_than_the_cap_survives_a_read_and_a_rewrite_unshortened() {
    let long: Vec<u8> = (0..ERROR_RAW_CAP + 904).map(|i| (i % 251) as u8).collect();
    assert_eq!(long.len(), 5000, "the fixture is meant to sit well past the cap");

    let event = TraceEvent::try_from(error_cbor(&[
        ("rawlen", Value::Integer(5000.into())),
        ("raw", Value::Bytes(long.clone())),
    ]))
    .expect("a 'raw' past the cap is not a malformed event");

    let EventData::Error { raw, raw_len, .. } = &event.data else {
        panic!("expected an error event");
    };
    assert_eq!(raw.as_deref(), Some(long.as_slice()), "the read shortened the bytes");
    assert_eq!(*raw_len, Some(5000));
    assert!(event.extra.is_empty(), "an over-long 'raw' was treated as unusable");

    let written = encoded(&event);
    assert_eq!(
        key_of(&written, "raw"),
        Some(Value::Bytes(long.clone())),
        "the rewrite shortened the bytes"
    );
    assert_eq!(key_of(&written, "rawlen"), Some(Value::Integer(5000.into())));
}

/// The cap the recorder does apply, at the one level the bytes are recorded at.
/// `rawlen` is the length of the input the recorder held, not the length of
/// what it kept — a `rawlen` recomputed after the truncation would say the
/// capture was complete.
#[test]
fn a_recorder_caps_the_bytes_and_records_the_length_it_had() {
    let observed: Vec<u8> = (0..ERROR_RAW_CAP + 904).map(|i| (i % 251) as u8).collect();
    let data = EventData::error_observed(
        5,
        "SUBSCRIBE_OK did not parse",
        Some(ErrorKind::Decode),
        Some(6),
        &observed,
        &DetailLevel::Full,
    );

    let EventData::Error { error_code, reason, stream_id, kind, raw_len, raw } = data else {
        panic!("expected an error event");
    };
    assert_eq!(error_code, 5);
    assert_eq!(reason, "SUBSCRIBE_OK did not parse");
    assert_eq!(stream_id, Some(6));
    assert_eq!(kind, Some(ErrorKind::Decode));
    assert_eq!(raw_len, Some(5000), "the length must be the input, not what survived the cap");
    assert_eq!(raw.as_ref().map(Vec::len), Some(4096), "the bytes were not capped at 4096");
    assert_eq!(
        raw.as_deref(),
        Some(&observed[..ERROR_RAW_CAP]),
        "the kept bytes are the first 4096, not some other 4096"
    );
}

/// An input shorter than the cap is kept whole, and the two lengths then agree
/// — which is how a reader tells a complete capture from a partial one.
#[test]
fn a_recorder_leaves_a_short_input_whole() {
    let observed = vec![0x04, 0xff, 0x03];
    let data = EventData::error_observed(5, "bad", None, None, &observed, &DetailLevel::Full);

    let EventData::Error { raw_len, raw, kind, stream_id, .. } = data else {
        panic!("expected an error event");
    };
    assert_eq!(raw_len, Some(3));
    assert_eq!(raw, Some(vec![0x04, 0xff, 0x03]));
    assert_eq!(kind, None, "nothing invented a kind the caller did not give");
    assert_eq!(stream_id, None);
}

/// The two byte-bearing keys sit at different levels on purpose. `"rawlen"` is
/// a size and this format gates sizes, so it stops at `headers+sizes`; `"raw"`
/// is payload-bearing and stops at `full`, one level above the event's own
/// `control`+, because an error naming a data stream has media framing behind
/// it.
///
/// A level this crate cannot place yields neither. A guess in the other
/// direction would put payload bytes into a trace whose declared level excludes
/// them, and that is not a mistake a later read can undo.
#[test]
fn a_recorder_writes_the_length_a_level_below_the_bytes() {
    let observed: Vec<u8> = (0..64u8).collect();
    let cases: Vec<(DetailLevel, Option<u64>, bool)> = vec![
        (DetailLevel::Control, None, false),
        (DetailLevel::Headers, None, false),
        (DetailLevel::HeadersSizes, Some(64), false),
        (DetailLevel::HeadersData, Some(64), false),
        (DetailLevel::Full, Some(64), true),
        (DetailLevel::Other("headers+timing".into()), None, false),
    ];

    for (detail, expected_len, expects_bytes) in cases {
        let data = EventData::error_observed(
            5,
            "bad",
            Some(ErrorKind::Protocol),
            Some(6),
            &observed,
            &detail,
        );
        let EventData::Error { raw_len, raw, .. } = data else { panic!("expected an error") };

        assert_eq!(raw_len, expected_len, "wrong 'rawlen' at detail level {detail}");
        assert_eq!(
            raw.as_deref(),
            expects_bytes.then_some(observed.as_slice()),
            "wrong 'raw' at detail level {detail}"
        );
    }
}

// ── forward compatibility ──────────────────────────────────

#[test]
fn unknown_event_type_is_preserved_not_rejected() {
    // New event types may be added without a version bump, so rejecting one
    // would turn every future addition into a breaking change. An earlier
    // revision of this crate did reject them, and an earlier revision of this
    // test asserted that it should.
    let cbor = Value::Map(vec![
        (Value::Text("n".into()), Value::Integer(7.into())),
        (Value::Text("t".into()), Value::Integer(1234.into())),
        (Value::Text("e".into()), Value::Integer(99.into())),
        (Value::Text("wat".into()), Value::Text("a field from the future".into())),
    ]);

    let event = TraceEvent::try_from(cbor).unwrap();

    assert_eq!(event.seq, 7);
    assert_eq!(event.timestamp, 1234);
    assert_eq!(event.event_type(), 99);
    let EventData::Unknown { event_type, fields } = &event.data else {
        panic!("expected an unknown event, got {:?}", event.data);
    };
    assert_eq!(*event_type, 99);
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].0.as_text(), Some("wat"));
}

#[test]
fn unknown_event_survives_a_read_write_round_trip() {
    // A tool that reads a trace and writes it back must not silently drop the
    // events it did not understand — that turns one reader's ignorance into
    // permanent data loss for every reader downstream of it.
    let original = Value::Map(vec![
        (Value::Text("n".into()), Value::Integer(3.into())),
        (Value::Text("t".into()), Value::Integer(500.into())),
        (Value::Text("e".into()), Value::Integer(42.into())),
        (Value::Text("p".into()), Value::Text("peer-a".into())),
        (Value::Text("alpha".into()), Value::Integer(1.into())),
        (Value::Text("beta".into()), Value::Bytes(vec![0xde, 0xad])),
    ]);

    let event = TraceEvent::try_from(original.clone()).unwrap();
    assert_eq!(event.peer.as_deref(), Some("peer-a"));

    let rewritten: Value = (&event).into();
    let Value::Map(pairs) = &rewritten else { panic!("not a map") };
    let lookup = |key: &str| pairs.iter().find(|(k, _)| k.as_text() == Some(key)).map(|(_, v)| v);

    assert_eq!(lookup("e").and_then(|v| v.as_integer()), Some(42.into()));
    assert_eq!(lookup("p").and_then(|v| v.as_text()), Some("peer-a"));
    assert_eq!(lookup("alpha").and_then(|v| v.as_integer()), Some(1.into()));
    assert_eq!(lookup("beta").and_then(|v| v.as_bytes()), Some(&vec![0xde_u8, 0xad]));

    // And it decodes back to the same thing a second time.
    assert_eq!(TraceEvent::try_from(rewritten).unwrap(), event);
}

#[test]
fn unknown_peer_role_and_side_are_preserved() {
    let event = TraceEvent::for_peer(
        0,
        0,
        "peer-a",
        EventData::PeerConnected {
            endpoint: None,
            transport: None,
            role: Some(PeerRole::Other("archivist".into())),
            side: Some(Side::Other("sideways".into())),
        },
    );
    assert_eq!(roundtrip(&event), event);
}

// ── relay-tap events ───────────────────────────────────────

#[test]
fn peer_connected_roundtrip() {
    let event = TraceEvent::for_peer(
        0,
        0,
        "peer-a",
        EventData::PeerConnected {
            endpoint: Some("https://relay.example.com/moq".into()),
            transport: Some("webtransport".into()),
            role: Some(PeerRole::Subscriber),
            side: Some(Side::Downstream),
        },
    );
    assert_eq!(roundtrip(&event), event);
}

#[test]
fn peer_connected_with_nothing_known_roundtrip() {
    let event = TraceEvent::for_peer(
        1,
        10,
        "peer-b",
        EventData::PeerConnected { endpoint: None, transport: None, role: None, side: None },
    );
    assert_eq!(roundtrip(&event), event);
}

#[test]
fn peer_disconnected_roundtrip() {
    let event = TraceEvent::for_peer(
        2,
        20,
        "peer-a",
        EventData::PeerDisconnected { error_code: 0, reason: Some("goaway".into()) },
    );
    assert_eq!(roundtrip(&event), event);
}

fn sample_derivation() -> EventData {
    EventData::SubscriptionDerivation {
        upstream: SubscriptionRef::new("peer-up", 7),
        downstream: vec![SubscriptionRef::new("peer-a", 1), SubscriptionRef::new("peer-b", 4)],
        kind: DerivationKind::Shared,
        trace_id: Some([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ]),
        namespace: Some(vec![b"example.com".to_vec(), b"live".to_vec()]),
        track_name: Some(b"video".to_vec()),
        t_downstream_received: Some(100),
        t_upstream_sent: Some(150),
        t_upstream_ok_received: Some(4300),
        t_downstream_ok_sent: Some(4350),
    }
}

#[test]
fn subscription_derivation_roundtrip() {
    let event = TraceEvent::for_peer(3, 30, "peer-up", sample_derivation());
    assert_eq!(roundtrip(&event), event);
}

#[test]
fn subscription_derivation_with_only_the_required_fields_roundtrip() {
    // A source emits the event as soon as the downstream SUBSCRIBE lands,
    // before any of the later timestamps exist.
    let event = TraceEvent::for_peer(
        4,
        40,
        "peer-up",
        EventData::SubscriptionDerivation {
            upstream: SubscriptionRef::new("peer-up", 7),
            downstream: vec![SubscriptionRef::new("peer-a", 1)],
            kind: DerivationKind::Created,
            trace_id: None,
            namespace: None,
            track_name: None,
            t_downstream_received: Some(100),
            t_upstream_sent: None,
            t_upstream_ok_received: None,
            t_downstream_ok_sent: None,
        },
    );
    assert_eq!(roundtrip(&event), event);
}

#[test]
fn trace_id_is_written_as_sixteen_raw_bytes() {
    // Stitching a subscription chain across operators only works if two
    // independent implementations produce identical bytes for the same chain.
    // A hex or base64 spelling is a place for them to disagree, so the wire
    // form is the raw byte string and nothing else.
    let event = TraceEvent::for_peer(3, 30, "peer-up", sample_derivation());
    let cbor: Value = (&event).into();
    let Value::Map(pairs) = cbor else { panic!("not a map") };

    let trace_id = pairs
        .iter()
        .find(|(k, _)| k.as_text() == Some("traceId"))
        .map(|(_, v)| v)
        .expect("traceId key");
    assert_eq!(trace_id.as_bytes().map(Vec::len), Some(16));
    assert!(pairs.iter().all(|(k, _)| k.as_text() != Some("trace")));
}

#[test]
fn trace_id_of_the_wrong_length_is_malformed() {
    // Padding or truncating would let the event assert a chain identity it
    // never carried.
    let cbor = Value::Map(vec![
        (Value::Text("n".into()), Value::Integer(0.into())),
        (Value::Text("t".into()), Value::Integer(0.into())),
        (Value::Text("e".into()), Value::Integer(10.into())),
        (
            Value::Text("u".into()),
            Value::Array(vec![Value::Text("peer-up".into()), Value::Integer(7.into())]),
        ),
        (
            Value::Text("d".into()),
            Value::Array(vec![Value::Array(vec![
                Value::Text("peer-a".into()),
                Value::Integer(1.into()),
            ])]),
        ),
        (Value::Text("kind".into()), Value::Text("created".into())),
        (Value::Text("traceId".into()), Value::Bytes(vec![0x01, 0x02, 0x03])),
    ]);

    let err = TraceEvent::try_from(cbor).unwrap_err();
    assert!(err.to_string().contains("traceId"), "error should name the field, got: {err}");
}

#[test]
fn peer_is_omitted_when_absent() {
    // A single-session trace has one peer to speak of, so saying so on every
    // event is pure weight; and an empty peer id must not be invented.
    let cbor: Value = (&sample_control_event()).into();
    let Value::Map(pairs) = cbor else { panic!("not a map") };
    assert!(!pairs.iter().any(|(k, _)| k.as_text() == Some("p")));
}

// ── bytes the other implementation actually writes ─────────

#[test]
fn a_timestamp_written_as_a_float_still_reads_as_an_integer() {
    // CBOR permits an integral value to be written as a float, and the JS
    // encoder does exactly that for anything past 32 bits — which every
    // microsecond timestamp on a capture longer than about seventy minutes is,
    // and every epoch-millisecond timestamp always. Reading only major type 0
    // made those values invisible.
    const JS_EVENT: &[u8] = &[
        0xb9, 0x00, 0x07, 0x61, 0x6e, 0x00, 0x61, 0x74, 0xfb, 0x41, 0xf0, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x61, 0x65, 0x00, 0x61, 0x64, 0x00, 0x62, 0x6d, 0x74, 0x03, 0x63, 0x6d, 0x73,
        0x67, 0xb9, 0x00, 0x00, 0x63, 0x72, 0x61, 0x77, 0xd8, 0x40, 0x43, 0x03, 0x00, 0x04,
    ];

    let value: Value = ciborium::de::from_reader(JS_EVENT).unwrap();
    let event = TraceEvent::try_from(value).unwrap();

    assert_eq!(event.timestamp, 4_294_967_296);
}

#[test]
fn raw_bytes_written_under_the_typed_array_tag_still_read() {
    // The same JS encoder wraps every byte string in tag 64. A reader that
    // accepts only an untagged byte string finds nothing — and a
    // payload-bearing field that reads as absent cannot be told apart from one
    // the recorder deliberately did not capture.
    const JS_EVENT: &[u8] = &[
        0xb9, 0x00, 0x07, 0x61, 0x6e, 0x00, 0x61, 0x74, 0xfb, 0x41, 0xf0, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x61, 0x65, 0x00, 0x61, 0x64, 0x00, 0x62, 0x6d, 0x74, 0x03, 0x63, 0x6d, 0x73,
        0x67, 0xb9, 0x00, 0x00, 0x63, 0x72, 0x61, 0x77, 0xd8, 0x40, 0x43, 0x03, 0x00, 0x04,
    ];

    let value: Value = ciborium::de::from_reader(JS_EVENT).unwrap();
    let event = TraceEvent::try_from(value).unwrap();

    let EventData::ControlMessage { raw, .. } = event.data else {
        panic!("expected a control message");
    };
    assert_eq!(raw, Some(vec![0x03, 0x00, 0x04]));
}

#[test]
fn a_fractional_float_is_not_an_unsigned_integer_either() {
    // The unsigned and signed readers each carry their own float branch, so
    // a test that exercises one says nothing about the other. This one goes
    // through the unsigned path: `mt` is a message type, and rounding 3.5 to
    // a message type would name a different message.
    let cbor = Value::Map(vec![
        (Value::Text("n".into()), Value::Integer(0.into())),
        (Value::Text("t".into()), Value::Integer(0.into())),
        (Value::Text("e".into()), Value::Integer(0.into())),
        (Value::Text("d".into()), Value::Integer(0.into())),
        (Value::Text("mt".into()), Value::Float(3.5)),
        (Value::Text("msg".into()), Value::Map(vec![])),
    ]);
    assert!(TraceEvent::try_from(cbor).is_err());
}

#[test]
fn a_float_carrying_a_fraction_is_not_an_integer() {
    // Accepting the float form must not turn into rounding: a fractional
    // timestamp is malformed, not a number to be trimmed into shape.
    let cbor = Value::Map(vec![
        (Value::Text("n".into()), Value::Integer(0.into())),
        (Value::Text("t".into()), Value::Float(1.5)),
        (Value::Text("e".into()), Value::Integer(5.into())),
        (Value::Text("from".into()), Value::Text("a".into())),
        (Value::Text("to".into()), Value::Text("b".into())),
    ]);
    assert!(TraceEvent::try_from(cbor).is_err());
}

// ── unrecognised keys on a recognised event type ───────────

fn stream_opened() -> TraceEvent {
    TraceEvent::new(
        0,
        100,
        EventData::StreamOpened {
            stream_id: 4,
            direction: Direction::Receive,
            stream_type: StreamType::Subgroup,
            track_alias: None,
            subgroup_id: None,
            fetch_request_id: None,
            group_id: None,
        },
    )
}

/// "Unknown keys MUST be ignored" is a rule about reading past them. A reader
/// that drops one turns any read-modify-write into a file that looks like it
/// never carried the key — and the tools that rewrite a trace are exactly the
/// ones it passes through on its way to someone else.
#[test]
fn an_unrecognised_key_is_kept_rather_than_dropped() {
    let extra = vec![
        (Value::Text("pp".into()), Value::Integer(128.into())),
        (Value::Text("tn".into()), Value::Text("video".into())),
    ];
    let event = stream_opened().with_extra(extra.clone());

    let read = roundtrip(&event);
    assert_eq!(read.extra, extra);
    assert_eq!(read, event);
}

#[test]
fn an_event_that_carried_none_reads_back_with_none() {
    assert!(roundtrip(&stream_opened()).extra.is_empty());
}

/// A CBOR map with a duplicate key is malformed. The field is what a reader
/// produced, so the field wins and the colliding entry is dropped.
#[test]
fn an_extra_key_never_displaces_one_the_event_type_owns() {
    let event = stream_opened().with_extra(vec![
        (Value::Text("sid".into()), Value::Integer(999.into())),
        (Value::Text("pp".into()), Value::Integer(128.into())),
    ]);

    let read = roundtrip(&event);
    assert!(matches!(read.data, EventData::StreamOpened { stream_id: 4, .. }));
    assert_eq!(read.extra, vec![(Value::Text("pp".into()), Value::Integer(128.into()))]);
}

/// `EventData::Unknown::fields` already holds every non-common key on such an
/// event. Collecting them into `extra` as well writes each one twice and
/// yields a map with duplicate keys.
#[test]
fn an_unknown_event_type_does_not_also_fill_extra() {
    let fields = vec![
        (Value::Text("note".into()), Value::Text("hi".into())),
        (Value::Text("count".into()), Value::Integer(3.into())),
    ];
    let event =
        TraceEvent::new(0, 0, EventData::Unknown { event_type: 99, fields: fields.clone() });

    let read = roundtrip(&event);
    assert!(read.extra.is_empty());
    assert!(
        matches!(read.data, EventData::Unknown { event_type: 99, fields: ref f } if *f == fields)
    );
}

/// A non-text map key is not one this format defines, so it is unrecognised by
/// construction and kept like any other.
#[test]
fn a_non_text_key_is_unrecognised_and_kept() {
    let cbor = Value::Map(vec![
        (Value::Text("n".into()), Value::Integer(0.into())),
        (Value::Text("t".into()), Value::Integer(100.into())),
        (Value::Text("e".into()), Value::Integer(2.into())),
        (Value::Text("sid".into()), Value::Integer(4.into())),
        (Value::Text("ec".into()), Value::Integer(0.into())),
        (Value::Integer(1000.into()), Value::Text("keyed by integer".into())),
    ]);

    let event = TraceEvent::try_from(cbor).unwrap();
    assert_eq!(
        event.extra,
        vec![(Value::Integer(1000.into()), Value::Text("keyed by integer".into()))]
    );
    assert_eq!(roundtrip(&event), event);
}

// ── the "msg" field on a control message ───────────────────

/// An event 0 CBOR map carrying whatever `"msg"` a writer chose to leave, if
/// any. Built by hand rather than by serializing a `TraceEvent`, because the
/// case under test is a file this crate would never write itself.
fn control_event_cbor(msg: Option<Value>) -> Value {
    let mut pairs = vec![
        (Value::Text("n".into()), Value::Integer(0.into())),
        (Value::Text("t".into()), Value::Integer(1000.into())),
        (Value::Text("e".into()), Value::Integer(0.into())),
        (Value::Text("d".into()), Value::Integer(0.into())),
        (Value::Text("mt".into()), Value::Integer(0x03.into())),
    ];
    if let Some(msg) = msg {
        pairs.push((Value::Text("msg".into()), msg));
    }
    Value::Map(pairs)
}

fn message_of(event: &TraceEvent) -> Value {
    let EventData::ControlMessage { ref message, .. } = event.data else {
        panic!("expected a control message");
    };
    message.clone()
}

fn key_of(cbor: &Value, key: &str) -> Option<Value> {
    let Value::Map(pairs) = cbor else { panic!("event is not a CBOR map") };
    pairs.iter().find(|(k, _)| k.as_text() == Some(key)).map(|(_, v)| v.clone())
}

/// Writers must emit `{}` when they decoded nothing, but files written before
/// that rule simply have no `"msg"`, and a reader that requires the key rejects
/// them. Event 0 is
/// one of the types sampling MUST NOT drop, so the reader that treats the key
/// as required throws away precisely the events the format guarantees — and
/// throws them away without saying so, since the caller drops the event on the
/// error.
#[test]
fn a_control_event_missing_msg_reads_as_an_empty_map_rather_than_failing() {
    let event = TraceEvent::try_from(control_event_cbor(None))
        .expect("an absent 'msg' is not a malformed event");
    assert_eq!(message_of(&event), Value::Map(vec![]));
}

/// Every `capture-*` case in the shared corpus holds a Rust `Debug` rendering
/// of the message in `"msg"`. Those files are not addressable by key, but they
/// are readable, and the text must reach the caller byte for byte rather than
/// being coerced into a map or discarded.
///
/// It is here as a regression pin: a present non-map value is returned
/// unchanged, and the obvious way to implement "`msg` is a map" would break
/// that.
#[test]
fn a_msg_that_is_not_a_map_is_handed_back_verbatim() {
    let text = "Subscribe { request_id: 42, track_alias: 7 }";
    let event = TraceEvent::try_from(control_event_cbor(Some(Value::Text(text.into()))))
        .expect("a non-map 'msg' is not a malformed event");
    assert_eq!(message_of(&event), Value::Text(text.into()));
}

/// Reading is tolerant; writing is not. A trace that passes through this crate
/// — a redaction pass, a filter, a re-segmentation — must come out conforming,
/// so the event that arrived without `"msg"` leaves with the empty map the
/// rule requires, and the key must be written rather than skipped as an empty
/// value.
#[test]
fn an_event_read_without_msg_is_written_back_with_an_empty_map() {
    let event = TraceEvent::try_from(control_event_cbor(None)).unwrap();

    let written: Value = (&event).into();
    assert_eq!(key_of(&written, "msg"), Some(Value::Map(vec![])));

    let reread = TraceEvent::try_from(written).unwrap();
    assert_eq!(reread, event);
}

/// The tolerance has to survive a rewrite too: a reader that preserved the
/// text and then a writer that dropped it would lose the only record of the
/// message the older recorder had.
///
/// Like the test above, this pins behaviour SPEC.md requires rather than
/// behaviour peculiar to one implementation.
#[test]
fn a_text_msg_survives_a_read_write_round_trip() {
    let text = "Subscribe { request_id: 42, track_alias: 7 }";
    let event = TraceEvent::try_from(control_event_cbor(Some(Value::Text(text.into())))).unwrap();

    let reread = roundtrip(&event);
    assert_eq!(message_of(&reread), Value::Text(text.into()));
    assert_eq!(reread, event);
}

/// `"msg"` is a key event 0 always writes, even on an event that did not
/// carry one. Were it left out of the keys event 0 writes, an incoming
/// `"msg"` would be read into the field *and* collected into `extra`, and
/// writing the event back would emit the key twice — a CBOR map with a
/// duplicate key is malformed.
#[test]
fn an_absent_msg_is_not_collected_into_extra() {
    let event = TraceEvent::try_from(control_event_cbor(None)).unwrap();
    assert!(event.extra.is_empty());

    let carried = TraceEvent::try_from(control_event_cbor(Some(Value::Text("x".into())))).unwrap();
    assert!(carried.extra.iter().all(|(k, _)| k.as_text() != Some("msg")));
    assert!(carried.extra.is_empty());
}

// ── a defined key whose value this reader cannot use ───────

/// A CBOR map with text keys, for building an event by hand.
fn cbor_map(pairs: &[(&str, Value)]) -> Value {
    Value::Map(pairs.iter().map(|(k, v)| (Value::Text((*k).into()), v.clone())).collect())
}

fn uint(n: u64) -> Value {
    Value::Integer(n.into())
}

/// Values that no unsigned-integer key can hold. Each is legal CBOR that some
/// writer could leave on `"ta"`, and none of them is a value this reader can
/// use — which under SPEC.md makes each one unrecognised, not deletable.
fn unusable_uints() -> Vec<(&'static str, Value)> {
    vec![
        ("a negative integer", Value::Integer((-1i64).into())),
        ("a fractional float", Value::Float(1.5)),
        ("text", Value::Text("hello".into())),
        ("a boolean", Value::Bool(true)),
        ("an array", Value::Array(vec![uint(1), uint(2)])),
        ("a map", Value::Map(vec![(Value::Text("a".into()), uint(1))])),
        ("a tag 2 bignum", Value::Tag(2, Box::new(Value::Bytes(vec![0x01, 0x00])))),
        ("null", Value::Null),
    ]
}

/// An event 1 map carrying `key` with whatever a writer left there.
fn stream_opened_carrying(key: &str, value: Value) -> Value {
    let mut cbor = stream_opened_cbor(0, &[]);
    let Value::Map(ref mut pairs) = cbor else { panic!("event is not a CBOR map") };
    pairs.push((Value::Text(key.into()), value));
    cbor
}

/// An event 0 map carrying `key` with whatever a writer left there.
fn control_event_carrying(key: &str, value: Value) -> Value {
    let mut cbor = control_event_cbor(Some(Value::Map(vec![])));
    let Value::Map(ref mut pairs) = cbor else { panic!("event is not a CBOR map") };
    pairs.push((Value::Text(key.into()), value));
    cbor
}

/// SPEC.md: "A defined key whose value has an unusable type is treated as
/// unrecognised." Before `"ta"` was a key this crate knew, `"ta": "hello"`
/// survived in `extra` like anything else it had never heard of. Reading the
/// key into a typed field and excluding it from `extra` on the strength of the
/// event type's vocabulary deleted it from both places at once — so learning
/// the key made the reader preserve *less* than its ignorance had.
#[test]
fn a_wrong_typed_ta_is_kept_as_an_unrecognised_key() {
    for (what, value) in unusable_uints() {
        let event = TraceEvent::try_from(stream_opened_carrying("ta", value.clone()))
            .unwrap_or_else(|e| panic!("{what} for 'ta' is not a malformed event: {e}"));

        let EventData::StreamOpened { track_alias, .. } = &event.data else {
            panic!("expected a stream open");
        };
        assert_eq!(*track_alias, None, "{what} was read into the field");
        assert_eq!(
            event.extra,
            vec![(Value::Text("ta".into()), value.clone())],
            "{what} for 'ta' was not kept verbatim"
        );
        assert_eq!(roundtrip(&event), event, "{what} for 'ta' did not survive a rewrite");
    }
}

/// An unusable `"ns"` costs the key, not the event, and not the rest of the file.
///
/// This one was the loudest instance of the rule: `get_namespace` returned an
/// error rather than `None`, and `read_next` propagates it, so a
/// `collect::<Result<Vec<_>, _>>()` — the documented idiom — stopped at that
/// event and yielded none of the ones after it. One namespace an encoder wrote
/// oddly took the rest of the recording with it. The subscriptions either side
/// of it are what make the event a derivation, and they decoded fine.
#[test]
fn an_unusable_namespace_keeps_the_event_and_the_key() {
    let event = cbor_map(&[
        ("n", uint(0)),
        ("t", uint(100)),
        ("e", uint(10)),
        ("u", Value::Array(vec![Value::Text("peer-up".into()), uint(7)])),
        ("d", Value::Array(vec![Value::Array(vec![Value::Text("peer-a".into()), uint(1)])])),
        ("kind", Value::Text("created".into())),
        // Not an array. Nothing a conformant writer emits, and exactly the
        // shape a reader that assumed one would choke on.
        ("ns", uint(5)),
    ]);
    let decoded = TraceEvent::try_from(event).expect("an unusable 'ns' is not a malformed event");

    assert!(
        matches!(decoded.data, EventData::SubscriptionDerivation { namespace: None, .. }),
        "an unusable 'ns' must not reach the field: {:?}",
        decoded.data
    );
    assert_eq!(
        decoded.extra,
        vec![(Value::Text("ns".into()), Value::Integer(5.into()))],
        "an unusable 'ns' must be kept as an unrecognised key"
    );
    assert_eq!(roundtrip(&decoded), decoded, "the kept 'ns' did not survive a rewrite");
}

/// The same rule on a different event type and on a key that predates `extra`
/// itself: nothing here is special-cased to the four keys event 1 gained. Every
/// optional key read through a type-checked getter had the same hole.
#[test]
fn a_wrong_typed_sid_on_a_control_message_is_kept_too() {
    for (what, value) in unusable_uints() {
        let event = TraceEvent::try_from(control_event_carrying("sid", value.clone()))
            .unwrap_or_else(|e| panic!("{what} for 'sid' is not a malformed event: {e}"));

        let EventData::ControlMessage { stream_id, .. } = &event.data else {
            panic!("expected a control message");
        };
        assert_eq!(*stream_id, None, "{what} was read into the field");
        assert_eq!(
            event.extra,
            vec![(Value::Text("sid".into()), value.clone())],
            "{what} for 'sid' was not kept verbatim"
        );
        assert_eq!(roundtrip(&event), event, "{what} for 'sid' did not survive a rewrite");
    }
}

/// One bound on the rule. `"sid"` is required on event 1, and an event with no
/// usable stream ID is not an event: there is nothing to construct, and nothing
/// to hang a preserved key on. Unusable and absent are the same thing there,
/// and both are malformed.
#[test]
fn a_required_key_of_the_wrong_type_is_still_a_malformed_event() {
    let event = stream_opened_cbor(0, &[]);
    let Value::Map(pairs) = event else { panic!("event is not a CBOR map") };
    let rewritten: Vec<(Value, Value)> = pairs
        .into_iter()
        .map(
            |(k, v)| {
                if k.as_text() == Some("sid") {
                    (k, Value::Text("four".into()))
                } else {
                    (k, v)
                }
            },
        )
        .collect();

    let err = TraceEvent::try_from(Value::Map(rewritten)).unwrap_err();
    assert!(err.to_string().contains("sid"), "the error should name the key, got: {err}");
}

/// Every key goes to exactly one of the two places: a field, if the value is
/// one the field can hold, or `extra`, if it is not. A key in both is written
/// twice, and a CBOR map with a duplicate key is malformed.
///
/// The mixed rows are the ones that matter — a usable and an unusable value for
/// two keys of the same event — since a reader that routes by event type gets
/// both wrong in the same direction.
#[test]
fn a_key_lands_in_a_field_or_in_extra_and_never_in_both() {
    let sub_ref = |peer: &str, id: u64| Value::Array(vec![Value::Text(peer.into()), uint(id)]);
    let cases: Vec<(&str, Value, Vec<&str>)> = vec![
        (
            "event 1, 'ta' usable and 'sg' text",
            cbor_map(&[
                ("n", uint(0)),
                ("t", uint(100)),
                ("e", uint(1)),
                ("sid", uint(4)),
                ("d", uint(1)),
                ("st", uint(0)),
                ("ta", uint(7)),
                ("sg", Value::Text("two".into())),
            ]),
            vec!["sg"],
        ),
        (
            "event 0, 'sid' a boolean",
            cbor_map(&[
                ("n", uint(0)),
                ("t", uint(100)),
                ("e", uint(0)),
                ("d", uint(0)),
                ("mt", uint(3)),
                ("msg", Value::Map(vec![])),
                ("sid", Value::Bool(true)),
                ("raw", Value::Bytes(vec![0x03])),
            ]),
            vec!["sid"],
        ),
        (
            "event 8, 'role' an integer and 'side' text",
            cbor_map(&[
                ("n", uint(0)),
                ("t", uint(100)),
                ("e", uint(8)),
                ("p", Value::Text("peer-a".into())),
                ("role", uint(1)),
                ("side", Value::Text("downstream".into())),
            ]),
            vec!["role"],
        ),
        (
            "event 10, 'traceId' text rather than bytes",
            cbor_map(&[
                ("n", uint(0)),
                ("t", uint(100)),
                ("e", uint(10)),
                ("u", sub_ref("peer-up", 7)),
                ("d", Value::Array(vec![sub_ref("peer-a", 1)])),
                ("kind", Value::Text("created".into())),
                ("traceId", Value::Text("00112233445566778899aabbccddeeff".into())),
                ("tdr", uint(100)),
            ]),
            vec!["traceId"],
        ),
        (
            "event 6, 'sid' and 'ek' usable, 'rawlen' text and 'raw' an array",
            cbor_map(&[
                ("n", uint(0)),
                ("t", uint(100)),
                ("e", uint(6)),
                ("ec", uint(5)),
                ("reason", Value::Text("SUBSCRIBE_OK did not parse".into())),
                ("sid", uint(6)),
                ("ek", Value::Text("decode".into())),
                ("rawlen", Value::Text("nine".into())),
                ("raw", Value::Array(vec![uint(4), uint(255)])),
            ]),
            vec!["rawlen", "raw"],
        ),
        (
            "event 2, a peer id written as a number",
            cbor_map(&[
                ("n", uint(0)),
                ("t", uint(100)),
                ("e", uint(2)),
                ("p", uint(5)),
                ("sid", uint(4)),
                ("ec", uint(0)),
            ]),
            vec!["p"],
        ),
    ];

    for (what, cbor, unrecognised) in cases {
        let event = TraceEvent::try_from(cbor.clone())
            .unwrap_or_else(|e| panic!("{what}: an optional key's type made the event fail: {e}"));

        let extra_keys: Vec<&str> = event.extra.iter().filter_map(|(k, _)| k.as_text()).collect();
        assert_eq!(extra_keys, unrecognised, "{what}: wrong keys in extra");

        let written: Value = (&event).into();
        let Value::Map(input) = &cbor else { panic!("event is not a CBOR map") };
        for (k, _) in input {
            let key = k.as_text().expect("the cases are keyed by text");
            assert_eq!(key_count(&written, key), 1, "{what}: '{key}' is not written exactly once");
        }
        assert_eq!(roundtrip(&event), event, "{what}: the event did not survive a rewrite");
    }
}

/// Through the raw bytes rather than a `Value`, for the same reason the
/// event 1 test above gives: a duplicate key survives decoding as two entries
/// in a `Vec` nobody complains about, and a definite-length map header that
/// counts the wrong number of entries is never even written.
#[test]
fn a_re_serialized_event_carries_a_wrong_typed_key_exactly_once() {
    let event = TraceEvent::try_from(stream_opened_carrying("ta", Value::Text("hello".into())))
        .expect("a wrong-typed optional key is not a malformed event");

    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&event, &mut bytes).expect("serialization is infallible");
    let written: Value =
        ciborium::de::from_reader(bytes.as_slice()).expect("the encoded map is well-formed CBOR");

    assert_eq!(key_count(&written, "ta"), 1, "'ta' is not written exactly once");
    assert_eq!(
        key_of(&written, "ta"),
        Some(Value::Text("hello".into())),
        "the value was altered on the way out"
    );
    let Value::Map(pairs) = &written else { panic!("event is not a CBOR map") };
    assert_eq!(pairs.len(), 7, "the map carries entries beyond the seven keys read: {pairs:?}");
}

/// The writing half of the rule. An `extra` entry naming a key whose field is
/// empty is the only copy of that key: nothing is written from the field, so
/// dropping the entry as a collision would delete exactly the value the reading
/// half went to the trouble of keeping.
#[test]
fn an_extra_entry_for_an_empty_optional_field_is_written() {
    let event =
        stream_opened().with_extra(vec![(Value::Text("ta".into()), Value::Text("hello".into()))]);

    let written: Value = (&event).into();
    assert_eq!(key_count(&written, "ta"), 1, "'ta' is not written exactly once");
    assert_eq!(key_of(&written, "ta"), Some(Value::Text("hello".into())));
    assert_eq!(roundtrip(&event), event);
}

/// `"p"` is optional as well, and an optional key can be unusable whether the
/// event type owns it or every event carries it. A relay-tap recorder that
/// writes peer ids as numbers loses the attribution either way — but deleting
/// the value too leaves nothing to work out afterwards which session the event
/// belonged to.
#[test]
fn a_wrong_typed_peer_id_is_kept_rather_than_dropped() {
    let event = TraceEvent::try_from(stream_opened_carrying("p", uint(5)))
        .expect("a wrong-typed 'p' is not a malformed event");
    assert_eq!(event.peer, None);
    assert_eq!(event.extra, vec![(Value::Text("p".into()), uint(5))]);
    assert_eq!(roundtrip(&event), event);

    // And on an event type this crate cannot name, where every key it did not
    // consume is kept in `fields` instead.
    let unknown = TraceEvent::try_from(cbor_map(&[
        ("n", uint(0)),
        ("t", uint(0)),
        ("e", uint(99)),
        ("p", uint(5)),
    ]))
    .expect("a wrong-typed 'p' is not a malformed event");
    assert_eq!(unknown.peer, None);
    let EventData::Unknown { fields, .. } = &unknown.data else {
        panic!("expected an unknown event");
    };
    assert_eq!(*fields, vec![(Value::Text("p".into()), uint(5))]);
    assert_eq!(roundtrip(&unknown), unknown);
}

// ── the encoding rules reach an event's opaque values ──────

/// The bytes an event is actually written as, decoded back into a `Value`.
///
/// Through the encoder rather than through `Value::serialized`, because part
/// of what these tests pin is the entry count in the definite-length map
/// header: a writer that drops a duplicate entry without adjusting the count
/// writes a map whose header promises more pairs than follow, and only the
/// byte encoding says so.
fn written(event: &TraceEvent) -> Value {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(event, &mut bytes).expect("serialization is infallible");
    ciborium::de::from_reader(bytes.as_slice()).expect("the encoded map is well-formed CBOR")
}

/// A byte string under RFC 8746's typed-array tag, as `cbor-x` once wrote
/// every one of them.
fn tagged(bytes: &[u8]) -> Value {
    Value::Tag(64, Box::new(Value::Bytes(bytes.to_vec())))
}

/// SPEC.md's two normative encoding rules (Interoperability) bind the bytes a
/// writer emits, so they bind every value it emits and not only the ones it
/// understood. `"msg"` is the largest opaque value an event carries: a reader
/// hands it back whatever it holds, so a writer that re-emitted it unchanged
/// would put a non-conforming encoding straight into the file.
///
/// The JavaScript side cannot produce either shape — `cbor-x` gives its code a
/// plain number for an integral float and strips tag 64 on decode — so a Rust
/// writer that re-emitted one made the two implementations write different
/// bytes for the same trace, which is the one thing these rules exist to stop.
#[test]
fn an_integral_float_in_msg_is_written_as_an_integer() {
    let event = TraceEvent::try_from(control_event_cbor(Some(cbor_map(&[
        // Past 2^32, which is where `cbor-x` reaches for a float64.
        ("request_id", Value::Float(4_294_967_296.0)),
        // Integral, and small: the rule is about the value, not its size.
        ("track_alias", Value::Float(7.0)),
        // Not integral, so no integer carries it and it stays a float.
        ("rate", Value::Float(0.25)),
    ]))))
    .expect("a float in 'msg' is not a malformed event");

    assert_eq!(
        message_of(&event),
        cbor_map(&[
            ("request_id", Value::Float(4_294_967_296.0)),
            ("track_alias", Value::Float(7.0)),
            ("rate", Value::Float(0.25)),
        ]),
        "the read altered 'msg' — the house style is the writer's business"
    );

    assert_eq!(
        key_of(&written(&event), "msg"),
        Some(cbor_map(&[
            ("request_id", uint(4_294_967_296)),
            ("track_alias", uint(7)),
            ("rate", Value::Float(0.25)),
        ]))
    );
}

/// The second rule, in the same place. A reader must accept tag 64 and
/// preserve it where it can see it — this one can — but a writer must not emit
/// it.
#[test]
fn a_tag_64_byte_string_in_msg_is_written_as_a_plain_byte_string() {
    let event = TraceEvent::try_from(control_event_cbor(Some(cbor_map(&[(
        "auth_token",
        tagged(&[0xde, 0xad]),
    )]))))
    .expect("a tagged byte string in 'msg' is not a malformed event");

    assert_eq!(
        message_of(&event),
        cbor_map(&[("auth_token", tagged(&[0xde, 0xad]))]),
        "the read stripped the tag"
    );
    assert_eq!(
        key_of(&written(&event), "msg"),
        Some(cbor_map(&[("auth_token", Value::Bytes(vec![0xde, 0xad]))]))
    );
}

/// A `"msg"` is a whole tree — the corpus carries a nested one for exactly
/// this reason — and both rules are about every number and every byte string
/// in it, map keys included, since a key is encoded by the same rules as
/// anything else.
#[test]
fn the_encoding_rules_reach_through_a_msg_tree() {
    let msg = Value::Map(vec![
        (
            Value::Text("parameters".into()),
            Value::Array(vec![
                Value::Float(3.0),
                Value::Map(vec![
                    // A float used as a key, and a tagged byte string one
                    // level further down again.
                    (Value::Float(2.0), tagged(&[0x01])),
                    (Value::Text("keep".into()), Value::Float(1.5)),
                ]),
            ]),
        ),
        (
            Value::Text("nested".into()),
            Value::Map(vec![(Value::Text("n".into()), tagged(&[0x02]))]),
        ),
    ]);
    let event = TraceEvent::try_from(control_event_cbor(Some(msg)))
        .expect("a nested 'msg' is not a malformed event");

    assert_eq!(
        key_of(&written(&event), "msg"),
        Some(Value::Map(vec![
            (
                Value::Text("parameters".into()),
                Value::Array(vec![
                    uint(3),
                    Value::Map(vec![
                        (uint(2), Value::Bytes(vec![0x01])),
                        (Value::Text("keep".into()), Value::Float(1.5)),
                    ]),
                ]),
            ),
            (
                Value::Text("nested".into()),
                Value::Map(vec![(Value::Text("n".into()), Value::Bytes(vec![0x02]))]),
            ),
        ]))
    );
}

/// An event 7 map carrying whatever a writer left on `"data"`.
fn annotation_cbor(data: Value) -> Value {
    Value::Map(vec![
        (Value::Text("n".into()), uint(0)),
        (Value::Text("t".into()), uint(1000)),
        (Value::Text("e".into()), uint(7)),
        (Value::Text("label".into()), Value::Text("note".into())),
        (Value::Text("data".into()), data),
    ])
}

/// `"data"` on an annotation is the second opaque value an event carries — any
/// CBOR type, defined by whoever wrote the trace and never looked at here —
/// and it needs the same guard `"msg"` does: it reaches the
/// serializer as a `Value`, which is handed straight to the file.
///
/// Event 7 is nine of the fifteen events in two `capture-*` cases of the
/// shared corpus, so this is not a hypothetical write site.
#[test]
fn both_encoding_rules_reach_an_annotations_data() {
    let event = TraceEvent::try_from(annotation_cbor(Value::Map(vec![
        (Value::Text("at".into()), Value::Float(1_756_800_000_000.0)),
        (Value::Text("blob".into()), tagged(&[0x07])),
        (Value::Float(4.0), Value::Array(vec![Value::Float(8.0)])),
    ])))
    .expect("an annotation with a map 'data' is not a malformed event");

    let EventData::Annotation { ref data, .. } = event.data else {
        panic!("expected an annotation");
    };
    assert_eq!(
        data.clone(),
        Value::Map(vec![
            (Value::Text("at".into()), Value::Float(1_756_800_000_000.0)),
            (Value::Text("blob".into()), tagged(&[0x07])),
            (Value::Float(4.0), Value::Array(vec![Value::Float(8.0)])),
        ]),
        "the read altered 'data'"
    );

    assert_eq!(
        key_of(&written(&event), "data"),
        Some(Value::Map(vec![
            (Value::Text("at".into()), uint(1_756_800_000_000)),
            (Value::Text("blob".into()), Value::Bytes(vec![0x07])),
            (uint(4), Value::Array(vec![uint(8)])),
        ]))
    );
}

/// A `"data"` that is not a map is opaque all the same, and a bare integral
/// float is a shape a JavaScript writer cannot produce at all.
#[test]
fn a_scalar_annotation_data_is_normalised_too() {
    let event = TraceEvent::try_from(annotation_cbor(Value::Float(12.0)))
        .expect("a scalar 'data' is not a malformed event");

    assert_eq!(key_of(&written(&event), "data"), Some(uint(12)));
}

/// An unknown event type writes every key it read straight back out of
/// `fields`, which makes that list the widest opaque write site of the four:
/// a whole event map this crate never looked at, keys included.
#[test]
fn both_encoding_rules_reach_an_unknown_events_fields() {
    let event = TraceEvent::try_from(Value::Map(vec![
        (Value::Text("n".into()), uint(0)),
        (Value::Text("t".into()), uint(1000)),
        (Value::Text("e".into()), uint(99)),
        (Value::Text("count".into()), Value::Float(4.0)),
        (Value::Text("blob".into()), tagged(&[0xbe, 0xef])),
        (Value::Text("deep".into()), Value::Array(vec![Value::Float(5.0), tagged(&[0x01])])),
        // A non-text key is unrecognised by construction, and is encoded by
        // the same rules as any other value.
        (Value::Float(1.0), Value::Text("keyed by a float".into())),
    ]))
    .expect("an unknown event type is not a malformed event");

    let EventData::Unknown { ref fields, .. } = event.data else {
        panic!("expected an unknown event");
    };
    assert_eq!(
        fields[0],
        (Value::Text("count".into()), Value::Float(4.0)),
        "the read altered the fields"
    );

    let out = written(&event);
    assert_eq!(key_of(&out, "count"), Some(uint(4)));
    assert_eq!(key_of(&out, "blob"), Some(Value::Bytes(vec![0xbe, 0xef])));
    assert_eq!(key_of(&out, "deep"), Some(Value::Array(vec![uint(5), Value::Bytes(vec![0x01])])));

    let Value::Map(pairs) = &out else { panic!("event is not a CBOR map") };
    assert_eq!(
        pairs.iter().find(|(k, _)| *k == uint(1)).map(|(_, v)| v.clone()),
        Some(Value::Text("keyed by a float".into())),
        "the float key was not written as an integer: {pairs:?}"
    );
}

/// The event's own store, which is the fourth. A key this crate could not use
/// is kept verbatim on the way in and written in the format's own encoding on
/// the way out — the same two halves the header's three stores have.
#[test]
fn both_encoding_rules_reach_an_events_store() {
    let mut cbor = stream_opened_cbor(0, &[]);
    let Value::Map(ref mut pairs) = cbor else { panic!("event is not a CBOR map") };
    pairs.push((Value::Text("x-count".into()), Value::Float(9.0)));
    pairs.push((Value::Text("x-blob".into()), tagged(&[0x05])));
    // A known key whose value this reader cannot use lands in the store too,
    // and leaves it by the same route.
    pairs.push((Value::Text("ta".into()), Value::Array(vec![Value::Float(6.0)])));
    pairs.push((Value::Float(3.0), Value::Text("keyed by a float".into())));

    let event = TraceEvent::try_from(cbor).expect("unusable keys are not a malformed event");

    assert_eq!(
        event.extra,
        vec![
            (Value::Text("x-count".into()), Value::Float(9.0)),
            (Value::Text("x-blob".into()), tagged(&[0x05])),
            (Value::Text("ta".into()), Value::Array(vec![Value::Float(6.0)])),
            (Value::Float(3.0), Value::Text("keyed by a float".into())),
        ],
        "the read altered the store"
    );

    let out = written(&event);
    assert_eq!(key_of(&out, "x-count"), Some(uint(9)));
    assert_eq!(key_of(&out, "x-blob"), Some(Value::Bytes(vec![0x05])));
    assert_eq!(key_of(&out, "ta"), Some(Value::Array(vec![uint(6)])));
    let Value::Map(pairs) = &out else { panic!("event is not a CBOR map") };
    assert_eq!(
        pairs.iter().find(|(k, _)| *k == uint(3)).map(|(_, v)| v.clone()),
        Some(Value::Text("keyed by a float".into())),
        "the float key was not written as an integer: {pairs:?}"
    );
}

/// The one value the rule changes rather than merely re-encodes. SPEC.md calls
/// it out and declines to carve it out — no field in a trace gives negative
/// zero a meaning — so this pins the accepted loss rather than guarding
/// against it. Pinned on the event side as well as the header's because the
/// carve-out, were one ever added, would go in one place and show up in both.
#[test]
fn a_negative_zero_in_msg_loses_its_sign_on_the_way_out() {
    let event =
        TraceEvent::try_from(control_event_cbor(Some(cbor_map(&[("z", Value::Float(-0.0))]))))
            .unwrap();

    let Value::Map(held) = message_of(&event) else { panic!("'msg' is not a map") };
    let Value::Float(stored) = held[0].1 else { panic!("the read did not keep the float") };
    assert!(stored.is_sign_negative(), "the read must not be the thing that loses the sign");

    assert_eq!(key_of(&written(&event), "msg"), Some(cbor_map(&[("z", uint(0))])));
}

// ── one key, never twice, inside an event ──────────────────

/// `ciborium` models a map as a list of pairs and hands back both entries of a
/// duplicate key, so a Rust reader can see this shape where the JavaScript one
/// cannot. Seeing it means preserving it — that half is observable — and
/// writing it means emitting one entry, since RFC 8949 calls a map with a
/// repeated key invalid and SPEC.md forbids a conformant tool from emitting
/// one having read one.
///
/// The first entry wins, matching every lookup in this crate: `"msg"` and the
/// stores are read through a first-match search, so writing the first is what
/// makes the value a caller is shown the value that survives a rewrite.
#[test]
fn a_duplicate_key_inside_msg_is_written_once() {
    let msg = Value::Map(vec![
        (Value::Text("request_id".into()), uint(1)),
        (Value::Text("request_id".into()), uint(2)),
        (Value::Text("track".into()), uint(3)),
    ]);
    let event = TraceEvent::try_from(control_event_cbor(Some(msg.clone())))
        .expect("a duplicate key in 'msg' is not a malformed event");

    assert_eq!(message_of(&event), msg, "the read collapsed the duplicate");

    assert_eq!(
        key_of(&written(&event), "msg"),
        Some(Value::Map(vec![
            (Value::Text("request_id".into()), uint(1)),
            (Value::Text("track".into()), uint(3)),
        ]))
    );
}

/// The same rule in an unknown event's fields, where a duplicate key survives
/// the decode for the same reason and reaches the writer as two entries of one
/// list.
#[test]
fn a_duplicate_key_in_an_unknown_events_fields_is_written_once() {
    let event = TraceEvent::try_from(Value::Map(vec![
        (Value::Text("n".into()), uint(0)),
        (Value::Text("t".into()), uint(1000)),
        (Value::Text("e".into()), uint(99)),
        (Value::Text("note".into()), Value::Text("first".into())),
        (Value::Text("note".into()), Value::Text("second".into())),
    ]))
    .expect("a duplicate key is not a malformed event");

    let out = written(&event);
    assert_eq!(key_count(&out, "note"), 1, "'note' is written twice");
    assert_eq!(key_of(&out, "note"), Some(Value::Text("first".into())), "the later entry won");
}

/// And in the store, which a caller can build by hand holding one key twice
/// whether or not a file ever did.
#[test]
fn an_event_store_holding_one_key_twice_writes_it_once() {
    let event = stream_opened().with_extra(vec![
        (Value::Text("x-a".into()), uint(1)),
        (Value::Text("x-a".into()), uint(2)),
        (Value::Text("x-b".into()), uint(3)),
    ]);

    let out = written(&event);
    assert_eq!(key_count(&out, "x-a"), 1, "'x-a' is written twice");
    assert_eq!(key_of(&out, "x-a"), Some(uint(1)), "the later entry won");
    assert_eq!(key_of(&out, "x-b"), Some(uint(3)), "an unrelated entry was dropped");
}

/// Two keys a store tells apart and a file cannot: normalising `Float(1.0)` to
/// `Integer(1)` is what makes them one key, so the duplicate check has to run
/// after the normalisation rather than before it.
#[test]
fn two_event_store_keys_that_normalise_together_are_written_once() {
    let event =
        stream_opened().with_extra(vec![(Value::Float(1.0), uint(10)), (uint(1), uint(20))]);

    let Value::Map(out) = written(&event) else { panic!("event is not a CBOR map") };
    let ones: Vec<&(Value, Value)> = out.iter().filter(|(k, _)| *k == uint(1)).collect();
    assert_eq!(ones.len(), 1, "the key 1 is written twice: {out:?}");
    assert_eq!(ones[0].1, uint(10), "the later entry won");
}

// ── a key the file repeats ─────────────────────────────────

fn text(s: &str) -> Value {
    Value::Text(s.into())
}

/// An input map carrying one key twice is invalid under RFC 8949, and SPEC.md
/// leaves the two readers free to disagree about which entry of the pair wins
/// — but not to lose the other one. `ciborium` models a map as a list of pairs
/// and hands back both, so a Rust reader can see this shape (SPEC.md,
/// Interoperability, the duplicate-key row and the Duplicate keys paragraphs
/// that close that section), and seeing it means preserving it.
///
/// Every getter here is a first-match search, so the field takes the first
/// entry. Filtering the store by key *name* would drop the second along with
/// it: a value the file carried would reach neither the field nor the store,
/// and reading the file would delete it.
#[test]
fn a_duplicate_key_on_input_keeps_the_entry_no_field_took() {
    let event = TraceEvent::try_from(cbor_map(&[
        ("n", uint(0)),
        ("t", uint(100)),
        ("e", uint(1)),
        ("sid", uint(4)),
        ("sid", uint(9)),
        ("d", uint(1)),
        ("st", uint(0)),
    ]))
    .expect("a duplicate key is not a malformed event");

    assert!(
        matches!(event.data, EventData::StreamOpened { stream_id: 4, .. }),
        "the field took the wrong entry"
    );
    assert_eq!(
        event.extra,
        vec![(text("sid"), uint(9))],
        "the entry no field took was deleted by reading the file"
    );

    // Written once all the same: keeping the loser must not produce a map that
    // carries `"sid"` twice.
    let out = written(&event);
    assert_eq!(key_count(&out, "sid"), 1, "'sid' is written twice");
    assert_eq!(key_of(&out, "sid"), Some(uint(4)));

    // And a fixed point from there: one entry is the most a conformant writer
    // may emit, and reading that back leaves nothing over.
    assert!(roundtrip(&event).extra.is_empty());
}

/// The same on one of the three keys every event carries, where the first
/// entry is the one the field took whatever the rest hold.
#[test]
fn a_duplicate_common_key_on_input_keeps_the_entry_no_field_took() {
    let event = TraceEvent::try_from(cbor_map(&[
        ("n", uint(0)),
        ("n", uint(5)),
        ("t", uint(100)),
        ("e", uint(2)),
        ("sid", uint(4)),
        ("ec", uint(0)),
    ]))
    .expect("a duplicate key is not a malformed event");

    assert_eq!(event.seq, 0, "the field took the wrong entry");
    assert_eq!(
        event.extra,
        vec![(text("n"), uint(5))],
        "the entry no field took was deleted by reading the file"
    );

    let out = written(&event);
    assert_eq!(key_count(&out, "n"), 1, "'n' is written twice");
    assert_eq!(key_of(&out, "n"), Some(uint(0)));
    assert!(roundtrip(&event).extra.is_empty());
}

/// `"p"` is the one common key that is optional, so it is the one whose
/// presence in the store means two different things: a value this reader could
/// not use, and — here — a second entry for a key the field already took.
#[test]
fn a_duplicate_peer_key_keeps_the_entry_no_field_took() {
    let event = TraceEvent::try_from(cbor_map(&[
        ("n", uint(0)),
        ("t", uint(100)),
        ("e", uint(2)),
        ("p", text("relay-a")),
        ("p", text("relay-b")),
        ("sid", uint(4)),
        ("ec", uint(0)),
    ]))
    .expect("a duplicate key is not a malformed event");

    assert_eq!(event.peer.as_deref(), Some("relay-a"), "the field took the wrong entry");
    assert_eq!(
        event.extra,
        vec![(text("p"), text("relay-b"))],
        "the entry no field took was deleted by reading the file"
    );

    let out = written(&event);
    assert_eq!(key_count(&out, "p"), 1, "'p' is written twice");
    assert_eq!(key_of(&out, "p"), Some(text("relay-a")));
    assert!(roundtrip(&event).extra.is_empty());
}

/// An unknown event type builds its `fields` the same way and had the same
/// defect. Such an event collects nothing into `extra`, so `fields` is the
/// only place an entry no common field took can land.
#[test]
fn a_duplicate_common_key_on_an_unknown_event_keeps_the_entry_no_field_took() {
    let event = TraceEvent::try_from(cbor_map(&[
        ("n", uint(0)),
        ("n", uint(5)),
        ("t", uint(100)),
        ("e", uint(99)),
    ]))
    .expect("a duplicate key is not a malformed event");

    assert_eq!(event.seq, 0, "the field took the wrong entry");
    let fields = match &event.data {
        EventData::Unknown { event_type: 99, fields } => fields.clone(),
        other => panic!("not an unknown event 99: {other:?}"),
    };
    assert_eq!(
        fields,
        vec![(text("n"), uint(5))],
        "the entry no field took was deleted by reading the file"
    );
    assert!(event.extra.is_empty(), "an unknown event type does not also fill 'extra'");

    let out = written(&event);
    assert_eq!(key_count(&out, "n"), 1, "'n' is written twice");
    assert_eq!(key_of(&out, "n"), Some(uint(0)));

    let read_back = roundtrip(&event);
    let read_back_fields = match &read_back.data {
        EventData::Unknown { fields, .. } => fields.clone(),
        other => panic!("not an unknown event: {other:?}"),
    };
    assert!(read_back_fields.is_empty(), "the rewrite is not a fixed point");
}

/// A field list is an ordered list of pairs rather than a map, so a caller can
/// put a common key in one by hand — and a file that repeats `"n"` now leaves
/// one there too. The event writes `"n"` from `seq`, so the entry is dropped
/// on the way out rather than putting that key in the map twice.
#[test]
fn an_unknown_events_fields_never_displace_a_common_key() {
    let event = TraceEvent::new(
        0,
        100,
        EventData::Unknown {
            event_type: 99,
            fields: vec![(text("n"), uint(5)), (text("note"), text("kept"))],
        },
    );

    let out = written(&event);
    assert_eq!(key_count(&out, "n"), 1, "'n' is written twice");
    assert_eq!(key_of(&out, "n"), Some(uint(0)));
    assert_eq!(key_of(&out, "note"), Some(text("kept")), "an unrelated field was dropped");
}

/// A key the event type defines whose value no field could use is not a key
/// the event *writes*, so neither entry of a repeated one is the entry a field
/// took and both stay. This guards the walk against being written against the
/// event type's vocabulary rather than against what it wrote.
///
/// Not load-bearing for the duplicate fix: filtering by key name kept both
/// entries here too, because the name filter asked the same question.
#[test]
fn a_repeated_key_no_field_could_use_keeps_both_entries() {
    let event = TraceEvent::try_from(cbor_map(&[
        ("n", uint(0)),
        ("t", uint(100)),
        ("e", uint(1)),
        ("sid", uint(4)),
        ("d", uint(1)),
        ("st", uint(0)),
        ("ta", text("not an integer")),
        ("ta", text("nor is this")),
    ]))
    .expect("an unusable 'ta' is not a malformed event");

    assert!(
        matches!(event.data, EventData::StreamOpened { track_alias: None, .. }),
        "'ta' was not usable and must have stayed empty"
    );
    assert_eq!(
        event.extra,
        vec![(text("ta"), text("not an integer")), (text("ta"), text("nor is this"))]
    );

    // One of them on the way out, like any other pair of entries sharing a key.
    let out = written(&event);
    assert_eq!(key_count(&out, "ta"), 1, "'ta' is written twice");
    assert_eq!(key_of(&out, "ta"), Some(text("not an integer")), "the later entry won");
}

use ciborium::Value;
use moqtap_trace::event::*;

fn sample_control_event() -> TraceEvent {
    TraceEvent::new(
        0,
        1000,
        EventData::ControlMessage {
            direction: Direction::Send,
            message_type: 0x03,
            message: Value::Map(vec![
                (Value::Text("requestId".into()), Value::Integer(42.into())),
                (Value::Text("trackName".into()), Value::Text("video".into())),
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
        EventData::Error { error_code: 0x01, reason: "protocol violation".into() },
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
            EventData::StreamOpened { stream_id: 1, direction: Direction::Send, stream_type: st },
        );
        let EventData::StreamOpened { stream_type, .. } = roundtrip(&event).data else {
            panic!("wrong variant");
        };
        assert_eq!(stream_type, st);
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

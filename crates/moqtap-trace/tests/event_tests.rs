use ciborium::Value;
use moqtap_trace::event::*;

fn sample_control_event() -> TraceEvent {
    TraceEvent {
        seq: 0,
        timestamp: 1000,
        data: EventData::ControlMessage {
            direction: Direction::Send,
            message_type: 0x03,
            message: Value::Map(vec![
                (Value::Text("requestId".into()), Value::Integer(42.into())),
                (Value::Text("trackName".into()), Value::Text("video".into())),
            ]),
            raw: None,
        },
    }
}

#[test]
fn control_event_cbor_roundtrip() {
    let event = sample_control_event();
    let cbor: Value = (&event).into();
    let decoded = TraceEvent::try_from(cbor).unwrap();
    assert_eq!(event, decoded);
}

#[test]
fn control_event_with_raw_roundtrip() {
    let event = TraceEvent {
        seq: 1,
        timestamp: 2000,
        data: EventData::ControlMessage {
            direction: Direction::Receive,
            message_type: 0x04,
            message: Value::Map(vec![]),
            raw: Some(vec![0x03, 0x00, 0x04]),
        },
    };
    let cbor: Value = (&event).into();
    let decoded = TraceEvent::try_from(cbor).unwrap();
    assert_eq!(event, decoded);
}

#[test]
fn stream_opened_roundtrip() {
    let event = TraceEvent {
        seq: 2,
        timestamp: 3000,
        data: EventData::StreamOpened {
            stream_id: 4,
            direction: Direction::Receive,
            stream_type: StreamType::Subgroup,
        },
    };
    let cbor: Value = (&event).into();
    let decoded = TraceEvent::try_from(cbor).unwrap();
    assert_eq!(event, decoded);
}

#[test]
fn stream_closed_roundtrip() {
    let event = TraceEvent {
        seq: 3,
        timestamp: 4000,
        data: EventData::StreamClosed { stream_id: 4, error_code: 0 },
    };
    let cbor: Value = (&event).into();
    let decoded = TraceEvent::try_from(cbor).unwrap();
    assert_eq!(event, decoded);
}

#[test]
fn object_header_roundtrip() {
    let event = TraceEvent {
        seq: 4,
        timestamp: 5000,
        data: EventData::ObjectHeader {
            stream_id: 4,
            group: 1,
            object: 0,
            publisher_priority: 128,
            object_status: 0,
        },
    };
    let cbor: Value = (&event).into();
    let decoded = TraceEvent::try_from(cbor).unwrap();
    assert_eq!(event, decoded);
}

#[test]
fn object_payload_without_bytes_roundtrip() {
    let event = TraceEvent {
        seq: 5,
        timestamp: 6000,
        data: EventData::ObjectPayload {
            stream_id: 4,
            group: 1,
            object: 0,
            size: 1024,
            payload: None,
        },
    };
    let cbor: Value = (&event).into();
    let decoded = TraceEvent::try_from(cbor).unwrap();
    assert_eq!(event, decoded);
}

#[test]
fn object_payload_with_bytes_roundtrip() {
    let event = TraceEvent {
        seq: 6,
        timestamp: 7000,
        data: EventData::ObjectPayload {
            stream_id: 4,
            group: 1,
            object: 0,
            size: 5,
            payload: Some(vec![0x48, 0x65, 0x6c, 0x6c, 0x6f]),
        },
    };
    let cbor: Value = (&event).into();
    let decoded = TraceEvent::try_from(cbor).unwrap();
    assert_eq!(event, decoded);
}

#[test]
fn state_change_roundtrip() {
    let event = TraceEvent {
        seq: 7,
        timestamp: 8000,
        data: EventData::StateChange { from: "connecting".into(), to: "connected".into() },
    };
    let cbor: Value = (&event).into();
    let decoded = TraceEvent::try_from(cbor).unwrap();
    assert_eq!(event, decoded);
}

#[test]
fn error_event_roundtrip() {
    let event = TraceEvent {
        seq: 8,
        timestamp: 9000,
        data: EventData::Error { error_code: 0x01, reason: "protocol violation".into() },
    };
    let cbor: Value = (&event).into();
    let decoded = TraceEvent::try_from(cbor).unwrap();
    assert_eq!(event, decoded);
}

#[test]
fn annotation_roundtrip() {
    let event = TraceEvent {
        seq: 9,
        timestamp: 10000,
        data: EventData::Annotation {
            label: "custom-mark".into(),
            data: Value::Text("checkpoint".into()),
        },
    };
    let cbor: Value = (&event).into();
    let decoded = TraceEvent::try_from(cbor).unwrap();
    assert_eq!(event, decoded);
}

#[test]
fn request_id_extracted_from_msg() {
    let event = sample_control_event();
    assert_eq!(event.request_id(), Some(42));
}

#[test]
fn request_id_none_for_non_control() {
    let event = TraceEvent {
        seq: 0,
        timestamp: 0,
        data: EventData::StateChange { from: "a".into(), to: "b".into() },
    };
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
fn unknown_event_type_rejected() {
    let cbor = Value::Map(vec![
        (Value::Text("n".into()), Value::Integer(0.into())),
        (Value::Text("t".into()), Value::Integer(0.into())),
        (Value::Text("e".into()), Value::Integer(99.into())),
    ]);
    let result = TraceEvent::try_from(cbor);
    assert!(result.is_err());
}

#[test]
fn stream_type_variants() {
    for (st, expected_st) in [
        (StreamType::Subgroup, StreamType::Subgroup),
        (StreamType::Datagram, StreamType::Datagram),
        (StreamType::Fetch, StreamType::Fetch),
    ] {
        let event = TraceEvent {
            seq: 0,
            timestamp: 0,
            data: EventData::StreamOpened {
                stream_id: 1,
                direction: Direction::Send,
                stream_type: st,
            },
        };
        let cbor: Value = (&event).into();
        let decoded = TraceEvent::try_from(cbor).unwrap();
        if let EventData::StreamOpened { stream_type, .. } = decoded.data {
            assert_eq!(stream_type, expected_st);
        } else {
            panic!("wrong variant");
        }
    }
}

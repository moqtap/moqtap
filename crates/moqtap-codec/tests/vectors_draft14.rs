#![cfg(feature = "draft14")]

mod test_vectors;

use moqtap_codec::draft14::message::ControlMessage;
use test_vectors::{load_vectors, vectors_dir};

fn run_message_vectors(relative_path: &str) {
    let path = vectors_dir().join(relative_path);
    let file = load_vectors(&path);

    for vector in &file.vectors {
        if let Some(expected_decoded) = &vector.decoded {
            // Valid vector: decode hex and compare JSON
            let bytes =
                hex::decode(&vector.hex).unwrap_or_else(|e| panic!("[{}] bad hex: {e}", vector.id));
            let msg = ControlMessage::decode(&mut &bytes[..])
                .unwrap_or_else(|e| panic!("[{}] decode failed: {e}", vector.id));
            let actual_json = test_vectors::draft14_json::message_to_json(&msg);
            assert_eq!(
                actual_json,
                *expected_decoded,
                "[{}] decoded JSON mismatch\nactual:   {}\nexpected: {}",
                vector.id,
                serde_json::to_string_pretty(&actual_json).unwrap(),
                serde_json::to_string_pretty(expected_decoded).unwrap()
            );

            // Re-encode canonical vectors
            if vector.is_canonical() {
                let mut buf = Vec::new();
                msg.encode(&mut buf)
                    .unwrap_or_else(|e| panic!("[{}] encode failed: {e}", vector.id));
                assert_eq!(
                    hex::encode(&buf),
                    vector.hex,
                    "[{}] re-encoded hex mismatch",
                    vector.id
                );
            }
        }

        if vector.error.is_some() {
            // Error vector: decode should fail
            let bytes =
                hex::decode(&vector.hex).unwrap_or_else(|e| panic!("[{}] bad hex: {e}", vector.id));
            let result = ControlMessage::decode(&mut &bytes[..]);
            assert!(result.is_err(), "[{}] expected error but decoded successfully", vector.id);
        }
    }
}

macro_rules! d14_test {
    ($name:ident, $file:expr) => {
        #[test]
        fn $name() {
            run_message_vectors(concat!("transport/draft14/codec/messages/", $file));
        }
    };
}

d14_test!(d14_client_setup, "client-setup.json");
d14_test!(d14_server_setup, "server-setup.json");
d14_test!(d14_goaway, "goaway.json");
d14_test!(d14_max_request_id, "max-request-id.json");
d14_test!(d14_requests_blocked, "requests-blocked.json");
d14_test!(d14_subscribe, "subscribe.json");
d14_test!(d14_subscribe_ok, "subscribe-ok.json");
d14_test!(d14_subscribe_error, "subscribe-error.json");
d14_test!(d14_subscribe_update, "subscribe-update.json");
d14_test!(d14_unsubscribe, "unsubscribe.json");
d14_test!(d14_subscribe_namespace, "subscribe-namespace.json");
d14_test!(d14_subscribe_namespace_ok, "subscribe-namespace-ok.json");
d14_test!(d14_subscribe_namespace_error, "subscribe-namespace-error.json");
d14_test!(d14_unsubscribe_namespace, "unsubscribe-namespace.json");
d14_test!(d14_publish, "publish.json");
d14_test!(d14_publish_ok, "publish-ok.json");
d14_test!(d14_publish_error, "publish-error.json");
d14_test!(d14_publish_done, "publish-done.json");
d14_test!(d14_publish_namespace, "publish-namespace.json");
d14_test!(d14_publish_namespace_ok, "publish-namespace-ok.json");
d14_test!(d14_publish_namespace_error, "publish-namespace-error.json");
d14_test!(d14_publish_namespace_done, "publish-namespace-done.json");
d14_test!(d14_publish_namespace_cancel, "publish-namespace-cancel.json");
d14_test!(d14_track_status, "track-status.json");
d14_test!(d14_track_status_ok, "track-status-ok.json");
d14_test!(d14_track_status_error, "track-status-error.json");
d14_test!(d14_fetch, "fetch.json");
d14_test!(d14_fetch_ok, "fetch-ok.json");
d14_test!(d14_fetch_error, "fetch-error.json");
d14_test!(d14_fetch_cancel, "fetch-cancel.json");
d14_test!(d14_unknown_type, "unknown-type.json");

// ─────────────────────────────────────────────────────────────
// Data-stream vectors
// ─────────────────────────────────────────────────────────────

use bytes::Buf;
use moqtap_codec::draft14::data_stream::{
    DatagramObject, FetchHeader, FetchObject, SubgroupHeader, SubgroupObjectReader,
};
fn js_str(v: &serde_json::Value, key: &str) -> String {
    v.get(key)
        .and_then(|x| x.as_str())
        .unwrap_or_else(|| panic!("missing string field {key}"))
        .to_string()
}

fn js_str_opt(v: &serde_json::Value, key: &str) -> Option<String> {
    v.get(key).and_then(|x| x.as_str()).map(|s| s.to_string())
}

fn js_u64(v: &serde_json::Value, key: &str) -> u64 {
    js_str(v, key).parse().unwrap_or_else(|e| panic!("bad integer at {key}: {e}"))
}

fn run_subgroup_vectors(relative_path: &str) {
    let path = vectors_dir().join(relative_path);
    let file = load_vectors(&path);

    for vector in &file.vectors {
        if let Some(expected) = &vector.decoded {
            let bytes =
                hex::decode(&vector.hex).unwrap_or_else(|e| panic!("[{}] bad hex: {e}", vector.id));
            let mut cursor: &[u8] = &bytes;

            let header = SubgroupHeader::decode(&mut cursor)
                .unwrap_or_else(|e| panic!("[{}] subgroup header decode failed: {e}", vector.id));

            assert_eq!(
                header.track_alias.into_inner().to_string(),
                js_str(expected, "track_alias"),
                "[{}] track_alias mismatch",
                vector.id
            );
            assert_eq!(
                header.group_id.into_inner().to_string(),
                js_str(expected, "group_id"),
                "[{}] group_id mismatch",
                vector.id
            );
            assert_eq!(
                header.publisher_priority as u64,
                js_u64(expected, "publisher_priority"),
                "[{}] publisher_priority mismatch",
                vector.id
            );
            assert_eq!(
                (header.stream_type.as_u8() as u64).to_string(),
                js_str(expected, "stream_type_id"),
                "[{}] stream_type_id mismatch",
                vector.id
            );

            // For explicit subgroup ID types, check immediately;
            // for first-object types, resolve after reading first object
            let explicit_sg = header.stream_type.has_subgroup_id_field();
            if explicit_sg {
                assert_eq!(
                    header.subgroup_id.unwrap().into_inner().to_string(),
                    js_str(expected, "subgroup_id"),
                    "[{}] explicit subgroup_id mismatch",
                    vector.id
                );
            } else if !header.stream_type.subgroup_id_is_first_object() {
                // subgroup_id = 0 (implicit)
                assert_eq!(
                    "0",
                    js_str(expected, "subgroup_id"),
                    "[{}] implicit subgroup_id mismatch",
                    vector.id
                );
            }

            let expected_objs = expected
                .get("objects")
                .and_then(|v| v.as_array())
                .unwrap_or_else(|| panic!("[{}] missing objects array", vector.id));

            let mut reader = SubgroupObjectReader::new(&header);
            let mut resolved_subgroup_id: Option<u64> = None;

            for (idx, eo) in expected_objs.iter().enumerate() {
                let obj = reader
                    .read_object(&mut cursor)
                    .unwrap_or_else(|e| panic!("[{}] object decode failed: {e}", vector.id));

                assert_eq!(
                    obj.object_id.into_inner().to_string(),
                    js_str(eo, "object_id"),
                    "[{}] object_id mismatch",
                    vector.id
                );

                if let Some(expected_delta) = js_str_opt(eo, "object_id_delta") {
                    // We can't directly check the delta from the decoded object,
                    // but we verify object_id is correct which validates the delta
                    let _ = expected_delta;
                }

                if let Some(s) = js_str_opt(eo, "payload_length") {
                    let expected_len: u64 = s.parse().unwrap();
                    let actual_len =
                        if obj.status.is_some() { 0 } else { obj.payload.len() as u64 };
                    assert_eq!(actual_len, expected_len, "[{}] payload_length mismatch", vector.id);
                }

                if let Some(s) = js_str_opt(eo, "object_status") {
                    let status = obj.status.expect("expected object_status");
                    assert_eq!(
                        status.as_u64().to_string(),
                        s,
                        "[{}] object_status mismatch",
                        vector.id
                    );
                }

                if let Some(expected_hex) = js_str_opt(eo, "payload_hex") {
                    assert_eq!(
                        hex::encode(&obj.payload),
                        expected_hex,
                        "[{}] payload_hex mismatch",
                        vector.id
                    );
                }

                // For first-object subgroup types, first object's ID = subgroup_id
                if idx == 0 && header.stream_type.subgroup_id_is_first_object() {
                    resolved_subgroup_id = Some(obj.object_id.into_inner());
                }
            }

            // Verify subgroup_id for first-object types
            if header.stream_type.subgroup_id_is_first_object() {
                if let Some(sg) = resolved_subgroup_id {
                    assert_eq!(
                        sg.to_string(),
                        js_str(expected, "subgroup_id"),
                        "[{}] subgroup_id (first-object) mismatch",
                        vector.id
                    );
                }
            }
        }

        if vector.error.is_some() {
            let bytes =
                hex::decode(&vector.hex).unwrap_or_else(|e| panic!("[{}] bad hex: {e}", vector.id));
            let mut cursor: &[u8] = &bytes;
            if let Ok(header) = SubgroupHeader::decode(&mut cursor) {
                // Header decoded — try reading an object; that should fail
                let mut reader = SubgroupObjectReader::new(&header);
                let obj_result = reader.read_object(&mut cursor);
                assert!(
                    obj_result.is_err() || cursor.has_remaining(),
                    "[{}] expected decode error but succeeded",
                    vector.id
                );
            }
        }
    }
}

fn run_datagram_vectors(relative_path: &str) {
    let path = vectors_dir().join(relative_path);
    let file = load_vectors(&path);

    for vector in &file.vectors {
        if let Some(expected) = &vector.decoded {
            let bytes =
                hex::decode(&vector.hex).unwrap_or_else(|e| panic!("[{}] bad hex: {e}", vector.id));
            let mut cursor: &[u8] = &bytes;

            let obj = DatagramObject::decode(&mut cursor)
                .unwrap_or_else(|e| panic!("[{}] datagram decode failed: {e}", vector.id));

            assert_eq!(
                (obj.datagram_type.as_u8() as u64).to_string(),
                js_str(expected, "stream_type_id"),
                "[{}] stream_type_id mismatch",
                vector.id
            );
            assert_eq!(
                obj.track_alias.into_inner().to_string(),
                js_str(expected, "track_alias"),
                "[{}] track_alias mismatch",
                vector.id
            );
            assert_eq!(
                obj.group_id.into_inner().to_string(),
                js_str(expected, "group_id"),
                "[{}] group_id mismatch",
                vector.id
            );
            if let Some(oid_str) = js_str_opt(expected, "object_id") {
                assert_eq!(
                    obj.object_id.into_inner().to_string(),
                    oid_str,
                    "[{}] object_id mismatch",
                    vector.id
                );
            }
            assert_eq!(
                obj.publisher_priority as u64,
                js_u64(expected, "publisher_priority"),
                "[{}] publisher_priority mismatch",
                vector.id
            );
            if let Some(s) = js_str_opt(expected, "object_status") {
                let status = obj.status.expect("expected object_status");
                assert_eq!(
                    status.as_u64().to_string(),
                    s,
                    "[{}] object_status mismatch",
                    vector.id
                );
            }
            if let Some(expected_hex) = js_str_opt(expected, "payload_hex") {
                assert_eq!(
                    hex::encode(&obj.payload),
                    expected_hex,
                    "[{}] payload_hex mismatch",
                    vector.id
                );
            }

            if vector.is_canonical() {
                let mut out = Vec::new();
                obj.encode(&mut out);
                // For payload datagrams, remaining cursor bytes are the payload
                // already consumed by decode, so compare full encoding
                assert_eq!(
                    hex::encode(&out),
                    vector.hex,
                    "[{}] re-encoded datagram mismatch",
                    vector.id
                );
            }
        }

        if vector.error.is_some() {
            let bytes =
                hex::decode(&vector.hex).unwrap_or_else(|e| panic!("[{}] bad hex: {e}", vector.id));
            let mut cursor: &[u8] = &bytes;
            let result = DatagramObject::decode(&mut cursor);
            assert!(result.is_err(), "[{}] expected decode error but succeeded", vector.id);
        }
    }
}

fn run_fetch_vectors(relative_path: &str) {
    let path = vectors_dir().join(relative_path);
    let file = load_vectors(&path);

    for vector in &file.vectors {
        if let Some(expected) = &vector.decoded {
            let bytes =
                hex::decode(&vector.hex).unwrap_or_else(|e| panic!("[{}] bad hex: {e}", vector.id));
            let mut cursor: &[u8] = &bytes;

            let header = FetchHeader::decode(&mut cursor)
                .unwrap_or_else(|e| panic!("[{}] fetch header decode failed: {e}", vector.id));
            assert_eq!(
                header.request_id.into_inner().to_string(),
                js_str(expected, "request_id"),
                "[{}] request_id mismatch",
                vector.id
            );

            let expected_objs = expected
                .get("objects")
                .and_then(|v| v.as_array())
                .unwrap_or_else(|| panic!("[{}] missing objects array", vector.id));

            let mut decoded_objects = Vec::new();
            for eo in expected_objs {
                let obj = FetchObject::decode(&mut cursor)
                    .unwrap_or_else(|e| panic!("[{}] fetch object decode failed: {e}", vector.id));
                assert_eq!(
                    obj.group_id.into_inner().to_string(),
                    js_str(eo, "group_id"),
                    "[{}] group_id mismatch",
                    vector.id
                );
                assert_eq!(
                    obj.subgroup_id.into_inner().to_string(),
                    js_str(eo, "subgroup_id"),
                    "[{}] subgroup_id mismatch",
                    vector.id
                );
                assert_eq!(
                    obj.object_id.into_inner().to_string(),
                    js_str(eo, "object_id"),
                    "[{}] object_id mismatch",
                    vector.id
                );
                assert_eq!(
                    obj.publisher_priority as u64,
                    js_u64(eo, "publisher_priority"),
                    "[{}] publisher_priority mismatch",
                    vector.id
                );

                if let Some(s) = js_str_opt(eo, "payload_length") {
                    let expected_len: u64 = s.parse().unwrap();
                    let actual_len =
                        if obj.status.is_some() { 0 } else { obj.payload.len() as u64 };
                    assert_eq!(actual_len, expected_len, "[{}] payload_length mismatch", vector.id);
                }

                if let Some(s) = js_str_opt(eo, "object_status") {
                    let status = obj.status.expect("expected object_status");
                    assert_eq!(
                        status.as_u64().to_string(),
                        s,
                        "[{}] object_status mismatch",
                        vector.id
                    );
                }

                if let Some(expected_hex) = js_str_opt(eo, "payload_hex") {
                    assert_eq!(
                        hex::encode(&obj.payload),
                        expected_hex,
                        "[{}] payload_hex mismatch",
                        vector.id
                    );
                }

                decoded_objects.push(obj);
            }

            if vector.is_canonical() {
                let mut out = Vec::new();
                header.encode(&mut out);
                for obj in &decoded_objects {
                    obj.encode(&mut out);
                }
                assert_eq!(
                    hex::encode(&out),
                    vector.hex,
                    "[{}] re-encoded fetch mismatch",
                    vector.id
                );
            }
        }

        if vector.error.is_some() {
            let bytes =
                hex::decode(&vector.hex).unwrap_or_else(|e| panic!("[{}] bad hex: {e}", vector.id));
            let mut cursor: &[u8] = &bytes;
            let header_ok = FetchHeader::decode(&mut cursor).is_ok();
            let obj_ok = header_ok && FetchObject::decode(&mut cursor).is_ok();
            assert!(!header_ok || !obj_ok, "[{}] expected decode error but succeeded", vector.id);
        }
    }
}

#[test]
fn d14_data_stream_subgroup() {
    run_subgroup_vectors("transport/draft14/codec/data-streams/subgroup.json");
}

#[test]
fn d14_data_stream_datagram() {
    run_datagram_vectors("transport/draft14/codec/data-streams/datagram.json");
}

#[test]
fn d14_data_stream_fetch() {
    run_fetch_vectors("transport/draft14/codec/data-streams/fetch-header.json");
}

#![cfg(feature = "draft17")]

mod test_vectors;

use moqtap_codec::draft17::message::ControlMessage;
use test_vectors::{load_vectors, vectors_dir};

fn run_message_vectors(relative_path: &str) {
    let path = vectors_dir().join(relative_path);
    let file = load_vectors(&path);

    for vector in &file.vectors {
        if let Some(expected_decoded) = &vector.decoded {
            let bytes =
                hex::decode(&vector.hex).unwrap_or_else(|e| panic!("[{}] bad hex: {e}", vector.id));
            let msg = ControlMessage::decode(&mut &bytes[..])
                .unwrap_or_else(|e| panic!("[{}] decode failed: {e}", vector.id));
            let actual_json = test_vectors::draft17_json::message_to_json(&msg);
            assert_eq!(
                actual_json,
                *expected_decoded,
                "[{}] decoded JSON mismatch\nactual:   {}\nexpected: {}",
                vector.id,
                serde_json::to_string_pretty(&actual_json).unwrap(),
                serde_json::to_string_pretty(expected_decoded).unwrap()
            );

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
            let bytes =
                hex::decode(&vector.hex).unwrap_or_else(|e| panic!("[{}] bad hex: {e}", vector.id));
            let result = ControlMessage::decode(&mut &bytes[..]);
            assert!(result.is_err(), "[{}] expected error but decoded successfully", vector.id);
        }
    }
}

macro_rules! d17_test {
    ($name:ident, $file:expr) => {
        #[test]
        fn $name() {
            run_message_vectors(concat!("transport/draft17/codec/messages/", $file));
        }
    };
}

d17_test!(d17_setup, "setup.json");
d17_test!(d17_goaway, "goaway.json");
d17_test!(d17_subscribe, "subscribe.json");
d17_test!(d17_subscribe_ok, "subscribe-ok.json");
d17_test!(d17_request_update, "request-update.json");
d17_test!(d17_publish, "publish.json");
d17_test!(d17_publish_ok, "publish-ok.json");
d17_test!(d17_publish_done, "publish-done.json");
d17_test!(d17_publish_namespace, "publish-namespace.json");
d17_test!(d17_publish_blocked, "publish-blocked.json");
d17_test!(d17_namespace, "namespace.json");
d17_test!(d17_namespace_done, "namespace-done.json");
d17_test!(d17_subscribe_namespace, "subscribe-namespace.json");
d17_test!(d17_track_status, "track-status.json");
d17_test!(d17_request_ok, "request-ok.json");
d17_test!(d17_request_error, "request-error.json");
d17_test!(d17_fetch, "fetch.json");
d17_test!(d17_fetch_ok, "fetch-ok.json");
d17_test!(d17_unknown_type, "unknown-type.json");

// ─────────────────────────────────────────────────────────────
// Data-stream vectors
// ─────────────────────────────────────────────────────────────

use bytes::Buf;
use moqtap_codec::draft17::data_stream::{DatagramHeader, FetchHeader, SubgroupHeader};
use moqtap_codec::varint::VarInt;

fn js_str(v: &serde_json::Value, key: &str) -> String {
    v.get(key)
        .and_then(|x| x.as_str())
        .unwrap_or_else(|| panic!("missing string field {key}"))
        .to_string()
}

fn js_str_opt(v: &serde_json::Value, key: &str) -> Option<String> {
    v.get(key).and_then(|x| x.as_str()).map(|s| s.to_string())
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
                format!("0x{:02x}", header.header_type),
                js_str(expected, "header_type"),
                "[{}] header_type mismatch",
                vector.id
            );
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
            // SUBGROUP_ID_MODE=0b01 means the subgroup_id is derived
            // from the first object's object_id (not transmitted); skip
            // the header-level assertion for that mode.
            let subgroup_id_mode = (header.header_type & 0x06) >> 1;
            if subgroup_id_mode != 1 {
                assert_eq!(
                    header.subgroup_id.into_inner().to_string(),
                    js_str(expected, "subgroup_id"),
                    "[{}] subgroup_id mismatch",
                    vector.id
                );
            }
            match (header.publisher_priority, js_str_opt(expected, "publisher_priority")) {
                (Some(p), Some(s)) => assert_eq!(
                    (p as u64).to_string(),
                    s,
                    "[{}] publisher_priority mismatch",
                    vector.id
                ),
                (None, None) => {}
                (actual, expected_s) => panic!(
                    "[{}] publisher_priority presence mismatch: actual={:?} expected={:?}",
                    vector.id, actual, expected_s
                ),
            }

            let expected_objs = expected
                .get("objects")
                .and_then(|v| v.as_array())
                .unwrap_or_else(|| panic!("[{}] missing objects array", vector.id));

            let has_properties = header.has_properties();
            let mut prev_object_id: Option<u64> = None;
            let mut first_object = true;

            for eo in expected_objs {
                let delta = VarInt::decode(&mut cursor)
                    .unwrap_or_else(|e| panic!("[{}] object delta decode failed: {e}", vector.id))
                    .into_inner();

                let resolved_id = match prev_object_id {
                    None => delta,
                    Some(prev) => prev + delta + 1,
                };
                prev_object_id = Some(resolved_id);

                if first_object && subgroup_id_mode == 1 {
                    assert_eq!(
                        resolved_id.to_string(),
                        js_str(expected, "subgroup_id"),
                        "[{}] subgroup_id (from first object) mismatch",
                        vector.id
                    );
                }
                first_object = false;

                assert_eq!(
                    resolved_id.to_string(),
                    js_str(eo, "object_id"),
                    "[{}] object_id mismatch",
                    vector.id
                );

                // Skip per-object properties if PROPERTIES header bit is set.
                if has_properties {
                    let props_len = VarInt::decode(&mut cursor).unwrap().into_inner() as usize;
                    cursor.advance(props_len);
                }

                let payload_len = VarInt::decode(&mut cursor)
                    .unwrap_or_else(|e| panic!("[{}] payload_length decode failed: {e}", vector.id))
                    .into_inner() as usize;

                if payload_len == 0 {
                    if let Some(s) = js_str_opt(eo, "status") {
                        let status = VarInt::decode(&mut cursor).unwrap();
                        assert_eq!(
                            status.into_inner().to_string(),
                            s,
                            "[{}] object_status mismatch",
                            vector.id
                        );
                    }
                }

                if let Some(expected_hex) = js_str_opt(eo, "payload_hex") {
                    if payload_len > 0 {
                        assert!(
                            cursor.remaining() >= payload_len,
                            "[{}] not enough bytes for payload",
                            vector.id
                        );
                        let payload = &cursor[..payload_len];
                        assert_eq!(
                            hex::encode(payload),
                            expected_hex,
                            "[{}] payload_hex mismatch",
                            vector.id
                        );
                        cursor.advance(payload_len);
                    } else {
                        assert_eq!(expected_hex, "", "[{}] expected empty payload_hex", vector.id);
                    }
                }
            }
        }

        if vector.error.is_some() {
            let bytes =
                hex::decode(&vector.hex).unwrap_or_else(|e| panic!("[{}] bad hex: {e}", vector.id));
            let mut cursor: &[u8] = &bytes;
            let result = SubgroupHeader::decode(&mut cursor);
            if result.is_ok() {
                let obj_result = VarInt::decode(&mut cursor);
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

            let hdr = DatagramHeader::decode(&mut cursor)
                .unwrap_or_else(|e| panic!("[{}] datagram decode failed: {e}", vector.id));

            assert_eq!(
                format!("0x{:02x}", hdr.datagram_type),
                js_str(expected, "datagram_type"),
                "[{}] datagram_type mismatch",
                vector.id
            );
            assert_eq!(
                hdr.track_alias.into_inner().to_string(),
                js_str(expected, "track_alias"),
                "[{}] track_alias mismatch",
                vector.id
            );
            assert_eq!(
                hdr.group_id.into_inner().to_string(),
                js_str(expected, "group_id"),
                "[{}] group_id mismatch",
                vector.id
            );
            assert_eq!(
                hdr.object_id.into_inner().to_string(),
                js_str(expected, "object_id"),
                "[{}] object_id mismatch",
                vector.id
            );
            match (hdr.publisher_priority, js_str_opt(expected, "publisher_priority")) {
                (Some(p), Some(s)) => assert_eq!(
                    (p as u64).to_string(),
                    s,
                    "[{}] publisher_priority mismatch",
                    vector.id
                ),
                (None, None) => {}
                (actual, expected_s) => panic!(
                    "[{}] publisher_priority presence mismatch: actual={:?} expected={:?}",
                    vector.id, actual, expected_s
                ),
            }
            if let Some(s) = js_str_opt(expected, "object_status") {
                let st = hdr.object_status.expect("expected object_status");
                assert_eq!((st as u64).to_string(), s, "[{}] object_status mismatch", vector.id);
            }
            if let Some(expected_hex) = js_str_opt(expected, "payload_hex") {
                assert_eq!(
                    hex::encode(cursor),
                    expected_hex,
                    "[{}] payload_hex mismatch",
                    vector.id
                );
            }
        }

        if vector.error.is_some() {
            let bytes =
                hex::decode(&vector.hex).unwrap_or_else(|e| panic!("[{}] bad hex: {e}", vector.id));
            let mut cursor: &[u8] = &bytes;
            let result = DatagramHeader::decode(&mut cursor);
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

            let mut prev_group_id: u64 = 0;
            let mut prev_subgroup_id: u64 = 0;
            let mut prev_object_id: Option<u64> = None;
            // Default publisher priority is 128 when no prior object sets it
            // via the 0x10 flag.
            let mut prev_priority: u8 = 128;

            for eo in expected_objs {
                let flags = VarInt::decode(&mut cursor).unwrap().into_inner();

                let expected_flags_str = js_str(eo, "serialization_flags");
                let expected_flags =
                    u64::from_str_radix(expected_flags_str.trim_start_matches("0x"), 16).unwrap();
                assert_eq!(flags, expected_flags, "[{}] serialization_flags mismatch", vector.id);

                let group_id = if flags & 0x04 != 0 {
                    let v = VarInt::decode(&mut cursor).unwrap().into_inner();
                    prev_group_id = v;
                    prev_subgroup_id = 0;
                    prev_object_id = None;
                    v
                } else {
                    prev_group_id
                };

                // Explicit subgroup_id when subgroup mode bits (0x01|0x02) == 0x03.
                if flags & 0x03 == 0x03 {
                    let v = VarInt::decode(&mut cursor).unwrap().into_inner();
                    prev_subgroup_id = v;
                }

                let object_id = if flags & 0x08 != 0 {
                    let v = VarInt::decode(&mut cursor).unwrap().into_inner();
                    prev_object_id = Some(v);
                    v
                } else {
                    let resolved = match prev_object_id {
                        None => 0,
                        Some(prev) => prev + 1,
                    };
                    prev_object_id = Some(resolved);
                    resolved
                };

                let priority_present = flags & 0x10 != 0;
                let priority = if priority_present {
                    assert!(cursor.remaining() >= 1);
                    let p = cursor[0];
                    cursor.advance(1);
                    prev_priority = p;
                    p
                } else {
                    prev_priority
                };

                // Properties: byte-length-prefixed blob when flag 0x20 set.
                if flags & 0x20 != 0 {
                    let props_len = VarInt::decode(&mut cursor).unwrap().into_inner() as usize;
                    cursor.advance(props_len);
                }

                let payload_length = VarInt::decode(&mut cursor).unwrap().into_inner() as usize;

                assert_eq!(
                    group_id.to_string(),
                    js_str(eo, "group_id"),
                    "[{}] group_id mismatch",
                    vector.id
                );
                if let Some(sgid) = js_str_opt(eo, "subgroup_id") {
                    assert_eq!(
                        prev_subgroup_id.to_string(),
                        sgid,
                        "[{}] subgroup_id mismatch",
                        vector.id
                    );
                }
                assert_eq!(
                    object_id.to_string(),
                    js_str(eo, "object_id"),
                    "[{}] object_id mismatch",
                    vector.id
                );
                if let Some(prio) = js_str_opt(eo, "publisher_priority") {
                    assert_eq!(
                        (priority as u64).to_string(),
                        prio,
                        "[{}] publisher_priority mismatch",
                        vector.id
                    );
                }

                if let Some(expected_hex) = js_str_opt(eo, "payload_hex") {
                    if payload_length > 0 {
                        let payload = &cursor[..payload_length];
                        assert_eq!(
                            hex::encode(payload),
                            expected_hex,
                            "[{}] payload_hex mismatch",
                            vector.id
                        );
                        cursor.advance(payload_length);
                    } else {
                        assert_eq!(expected_hex, "", "[{}] expected empty payload_hex", vector.id);
                    }
                }
            }
        }

        if vector.error.is_some() {
            let bytes =
                hex::decode(&vector.hex).unwrap_or_else(|e| panic!("[{}] bad hex: {e}", vector.id));
            let mut cursor: &[u8] = &bytes;
            let result = FetchHeader::decode(&mut cursor);
            assert!(result.is_err(), "[{}] expected decode error but succeeded", vector.id);
        }
    }
}

#[test]
fn d17_data_stream_subgroup() {
    run_subgroup_vectors("transport/draft17/codec/data-streams/subgroup.json");
}

#[test]
fn d17_data_stream_datagram() {
    run_datagram_vectors("transport/draft17/codec/data-streams/datagram.json");
}

#[test]
fn d17_data_stream_fetch() {
    run_fetch_vectors("transport/draft17/codec/data-streams/fetch-header.json");
}

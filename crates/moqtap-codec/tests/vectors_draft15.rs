#![cfg(feature = "draft15")]

mod test_vectors;

use moqtap_codec::draft15::message::ControlMessage;
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
            let actual_json = test_vectors::draft15_json::message_to_json(&msg);
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

macro_rules! d15_test {
    ($name:ident, $file:expr) => {
        #[test]
        fn $name() {
            run_message_vectors(concat!("transport/draft15/codec/messages/", $file));
        }
    };
}

d15_test!(d15_client_setup, "client-setup.json");
d15_test!(d15_server_setup, "server-setup.json");
d15_test!(d15_goaway, "goaway.json");
d15_test!(d15_max_request_id, "max-request-id.json");
d15_test!(d15_requests_blocked, "requests-blocked.json");
d15_test!(d15_subscribe, "subscribe.json");
d15_test!(d15_subscribe_ok, "subscribe-ok.json");
d15_test!(d15_subscribe_update, "subscribe-update.json");
d15_test!(d15_unsubscribe, "unsubscribe.json");
d15_test!(d15_publish, "publish.json");
d15_test!(d15_publish_ok, "publish-ok.json");
d15_test!(d15_publish_done, "publish-done.json");
d15_test!(d15_publish_namespace, "publish-namespace.json");
d15_test!(d15_publish_namespace_done, "publish-namespace-done.json");
d15_test!(d15_publish_namespace_cancel, "publish-namespace-cancel.json");
d15_test!(d15_subscribe_namespace, "subscribe-namespace.json");
d15_test!(d15_unsubscribe_namespace, "unsubscribe-namespace.json");
d15_test!(d15_track_status, "track-status.json");
d15_test!(d15_request_ok, "request-ok.json");
d15_test!(d15_request_error, "request-error.json");
d15_test!(d15_fetch, "fetch.json");
d15_test!(d15_fetch_ok, "fetch-ok.json");
d15_test!(d15_fetch_cancel, "fetch-cancel.json");
d15_test!(d15_unknown_type, "unknown-type.json");

// ─────────────────────────────────────────────────────────────
// Data-stream vectors
// ─────────────────────────────────────────────────────────────

use bytes::Buf;
use moqtap_codec::draft15::data_stream::{DatagramHeader, FetchHeader, SubgroupHeader};
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
            assert_eq!(
                header.subgroup_id.into_inner().to_string(),
                js_str(expected, "subgroup_id"),
                "[{}] subgroup_id mismatch",
                vector.id
            );
            if let Some(p) = header.publisher_priority {
                assert_eq!(
                    (p as u64).to_string(),
                    js_str(expected, "publisher_priority"),
                    "[{}] publisher_priority mismatch",
                    vector.id
                );
            } else {
                // No priority field expected in JSON
                assert!(
                    js_str_opt(expected, "publisher_priority").is_none(),
                    "[{}] expected no publisher_priority but JSON has one",
                    vector.id
                );
            }

            let expected_objs = expected
                .get("objects")
                .and_then(|v| v.as_array())
                .unwrap_or_else(|| panic!("[{}] missing objects array", vector.id));

            // Track object_id state for delta decoding
            let mut prev_object_id: Option<u64> = None;

            let has_extensions = header.has_extensions();

            for eo in expected_objs {
                // Read object_id_delta manually (ObjectHeader doesn't
                // know about extensions)
                let delta = VarInt::decode(&mut cursor)
                    .unwrap_or_else(|e| panic!("[{}] object delta decode failed: {e}", vector.id));

                let resolved_id = match prev_object_id {
                    None => delta.into_inner(),
                    Some(prev) => prev + delta.into_inner() + 1,
                };
                prev_object_id = Some(resolved_id);

                assert_eq!(
                    resolved_id.to_string(),
                    js_str(eo, "object_id"),
                    "[{}] object_id mismatch",
                    vector.id
                );

                // Skip extensions if present (byte-length-prefixed blob in draft-15+)
                if has_extensions {
                    let ext_len = VarInt::decode(&mut cursor).unwrap().into_inner() as usize;
                    cursor.advance(ext_len);
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
                // Try reading object delta — should fail or leave unconsumed bytes
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
            assert_eq!(
                (hdr.publisher_priority as u64).to_string(),
                js_str(expected, "publisher_priority"),
                "[{}] publisher_priority mismatch",
                vector.id
            );
            if let Some(s) = js_str_opt(expected, "object_status") {
                let status = hdr.object_status.expect("expected object_status");
                assert_eq!(
                    status.into_inner().to_string(),
                    s,
                    "[{}] object_status mismatch",
                    vector.id
                );
            }
            if let Some(expected_hex) = js_str_opt(expected, "payload_hex") {
                // Remaining bytes are payload
                let payload = cursor;
                assert_eq!(
                    hex::encode(payload),
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
    use moqtap_codec::varint::VarInt;

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

            // Track state for inherited / delta-decoded fields
            let mut prev_group_id: u64 = 0;
            let mut prev_subgroup_id: u64 = 0;
            let mut prev_object_id: Option<u64> = None;
            let mut prev_priority: u8 = 0;

            for eo in expected_objs {
                // Parse serialization_flags
                let flags = VarInt::decode(&mut cursor)
                    .unwrap_or_else(|e| {
                        panic!("[{}] fetch object flags decode failed: {e}", vector.id)
                    })
                    .into_inner() as u8;

                let expected_flags_str = js_str(eo, "serialization_flags");
                let expected_flags =
                    u8::from_str_radix(expected_flags_str.trim_start_matches("0x"), 16).unwrap();
                assert_eq!(flags, expected_flags, "[{}] serialization_flags mismatch", vector.id);

                // Draft-15 fetch object flags:
                //   0x02 = subgroup_id present
                //   0x04 = object_id present
                //   0x08 = group_id present
                //   0x10 = priority present (u8)
                //   0x20 = extensions present
                let group_id = if flags & 0x08 != 0 {
                    let v = VarInt::decode(&mut cursor).unwrap().into_inner();
                    prev_group_id = v;
                    // When group changes, reset subgroup and object tracking
                    prev_subgroup_id = 0;
                    prev_object_id = None;
                    v
                } else {
                    prev_group_id
                };

                // Explicit subgroup_id when flag 0x02 is set
                if flags & 0x02 != 0 {
                    let v = VarInt::decode(&mut cursor).unwrap().into_inner();
                    prev_subgroup_id = v;
                }

                let object_id = if flags & 0x04 != 0 {
                    let v = VarInt::decode(&mut cursor).unwrap().into_inner();
                    prev_object_id = Some(v);
                    v
                } else {
                    // Implicit: object_id = prev + 1
                    let resolved = match prev_object_id {
                        None => 0,
                        Some(prev) => prev + 1,
                    };
                    prev_object_id = Some(resolved);
                    resolved
                };

                let priority = if flags & 0x10 != 0 {
                    assert!(cursor.remaining() >= 1);
                    let p = cursor[0];
                    cursor.advance(1);
                    prev_priority = p;
                    p
                } else {
                    prev_priority
                };

                // Extensions (byte-length-prefixed blob) when flag 0x20 is set
                if flags & 0x20 != 0 {
                    let ext_len = VarInt::decode(&mut cursor).unwrap().into_inner() as usize;
                    cursor.advance(ext_len);
                }

                let payload_length = VarInt::decode(&mut cursor).unwrap().into_inner() as usize;

                // Skip status when payload_length == 0 (it's consumed here for delta tracking only)
                if payload_length == 0 && js_str_opt(eo, "status").is_some() {
                    let _ = VarInt::decode(&mut cursor);
                }

                assert_eq!(
                    group_id.to_string(),
                    js_str(eo, "group_id"),
                    "[{}] group_id mismatch",
                    vector.id
                );
                assert_eq!(
                    prev_subgroup_id.to_string(),
                    js_str(eo, "subgroup_id"),
                    "[{}] subgroup_id mismatch",
                    vector.id
                );
                assert_eq!(
                    object_id.to_string(),
                    js_str(eo, "object_id"),
                    "[{}] object_id mismatch",
                    vector.id
                );
                assert_eq!(
                    (priority as u64).to_string(),
                    js_str(eo, "publisher_priority"),
                    "[{}] publisher_priority mismatch",
                    vector.id
                );

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
fn d15_data_stream_subgroup() {
    run_subgroup_vectors("transport/draft15/codec/data-streams/subgroup.json");
}

#[test]
fn d15_data_stream_datagram() {
    run_datagram_vectors("transport/draft15/codec/data-streams/datagram.json");
}

#[test]
fn d15_data_stream_fetch() {
    run_fetch_vectors("transport/draft15/codec/data-streams/fetch-header.json");
}

#![cfg(feature = "draft09")]

mod test_vectors;

use bytes::{Buf, BufMut};
use moqtap_codec::draft09::data_stream::{
    DatagramHeader, DatagramStatusHeader, FetchHeader, FetchObjectHeader, ObjectHeader, StreamType,
    SubgroupHeader,
};
use moqtap_codec::draft09::message::ControlMessage;
use moqtap_codec::varint::VarInt;
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
            let actual_json = test_vectors::draft09_json::message_to_json(&msg);
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

macro_rules! d09_test {
    ($name:ident, $file:expr) => {
        #[test]
        fn $name() {
            run_message_vectors(concat!("transport/draft09/codec/messages/", $file));
        }
    };
}

d09_test!(d09_client_setup, "client-setup.json");
d09_test!(d09_server_setup, "server-setup.json");
d09_test!(d09_goaway, "goaway.json");
d09_test!(d09_max_subscribe_id, "max-subscribe-id.json");
d09_test!(d09_subscribes_blocked, "subscribes-blocked.json");
d09_test!(d09_subscribe, "subscribe.json");
d09_test!(d09_subscribe_ok, "subscribe-ok.json");
d09_test!(d09_subscribe_error, "subscribe-error.json");
d09_test!(d09_subscribe_update, "subscribe-update.json");
d09_test!(d09_subscribe_done, "subscribe-done.json");
d09_test!(d09_unsubscribe, "unsubscribe.json");
d09_test!(d09_announce, "announce.json");
d09_test!(d09_announce_ok, "announce-ok.json");
d09_test!(d09_announce_error, "announce-error.json");
d09_test!(d09_announce_cancel, "announce-cancel.json");
d09_test!(d09_unannounce, "unannounce.json");
d09_test!(d09_subscribe_announces, "subscribe-announces.json");
d09_test!(d09_subscribe_announces_ok, "subscribe-announces-ok.json");
d09_test!(d09_subscribe_announces_error, "subscribe-announces-error.json");
d09_test!(d09_unsubscribe_announces, "unsubscribe-announces.json");
d09_test!(d09_track_status_request, "track-status-request.json");
d09_test!(d09_track_status, "track-status.json");
d09_test!(d09_fetch, "fetch.json");
d09_test!(d09_fetch_ok, "fetch-ok.json");
d09_test!(d09_fetch_error, "fetch-error.json");
d09_test!(d09_fetch_cancel, "fetch-cancel.json");
d09_test!(d09_unknown_type, "unknown-type.json");

// ─────────────────────────────────────────────────────────────
// Data-stream vectors
// ─────────────────────────────────────────────────────────────

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

fn decode_stream_type(buf: &mut &[u8]) -> StreamType {
    let type_id = VarInt::decode(buf).expect("stream type varint").into_inner();
    StreamType::from_id(type_id).unwrap_or_else(|| panic!("unknown stream type {type_id:#x}"))
}

fn encode_stream_type(st: StreamType, out: &mut Vec<u8>) {
    VarInt::from_u64(st as u64).unwrap().encode(out);
}

fn run_subgroup_vectors(relative_path: &str) {
    let path = vectors_dir().join(relative_path);
    let file = load_vectors(&path);

    for vector in &file.vectors {
        if let Some(expected) = &vector.decoded {
            let bytes =
                hex::decode(&vector.hex).unwrap_or_else(|e| panic!("[{}] bad hex: {e}", vector.id));
            let mut cursor: &[u8] = &bytes;

            let st = decode_stream_type(&mut cursor);
            assert_eq!(st, StreamType::Subgroup, "[{}] expected Subgroup stream type", vector.id);
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
                header.subgroup_id.into_inner().to_string(),
                js_str(expected, "subgroup_id"),
                "[{}] subgroup_id mismatch",
                vector.id
            );
            assert_eq!(
                header.publisher_priority as u64,
                js_u64(expected, "publisher_priority"),
                "[{}] publisher_priority mismatch",
                vector.id
            );

            let expected_objs = expected
                .get("objects")
                .and_then(|v| v.as_array())
                .unwrap_or_else(|| panic!("[{}] missing objects array", vector.id));

            let mut decoded_objects = Vec::new();
            for eo in expected_objs {
                let obj = ObjectHeader::decode(&mut cursor)
                    .unwrap_or_else(|e| panic!("[{}] object decode failed: {e}", vector.id));
                assert_eq!(
                    obj.object_id.into_inner().to_string(),
                    js_str(eo, "object_id"),
                    "[{}] object_id mismatch",
                    vector.id
                );
                assert_eq!(
                    obj.extension_headers_length.into_inner().to_string(),
                    js_str(eo, "extension_headers_length"),
                    "[{}] extension_headers_length mismatch",
                    vector.id
                );
                assert_eq!(
                    obj.payload_length.into_inner().to_string(),
                    js_str(eo, "payload_length"),
                    "[{}] payload_length mismatch",
                    vector.id
                );
                if let Some(s) = js_str_opt(eo, "object_status") {
                    assert_eq!(
                        (obj.object_status as u64).to_string(),
                        s,
                        "[{}] object_status mismatch",
                        vector.id
                    );
                }

                let plen = obj.payload_length.into_inner() as usize;
                assert!(
                    cursor.remaining() >= plen,
                    "[{}] payload underrun: need {plen}, have {}",
                    vector.id,
                    cursor.remaining()
                );
                let mut payload = vec![0u8; plen];
                cursor.copy_to_slice(&mut payload);
                if let Some(expected_hex) = js_str_opt(eo, "payload_hex") {
                    assert_eq!(
                        hex::encode(&payload),
                        expected_hex,
                        "[{}] payload_hex mismatch",
                        vector.id
                    );
                }

                decoded_objects.push((obj, payload));
            }

            if vector.is_canonical() {
                let mut out = Vec::new();
                encode_stream_type(StreamType::Subgroup, &mut out);
                header.encode(&mut out);
                for (obj, payload) in &decoded_objects {
                    obj.encode(&mut out);
                    out.put_slice(payload);
                }
                assert_eq!(
                    hex::encode(&out),
                    vector.hex,
                    "[{}] re-encoded subgroup mismatch",
                    vector.id
                );
            }
        }

        if vector.error.is_some() {
            let bytes =
                hex::decode(&vector.hex).unwrap_or_else(|e| panic!("[{}] bad hex: {e}", vector.id));
            let mut cursor: &[u8] = &bytes;
            let consumed_type = VarInt::decode(&mut cursor).is_ok();
            let header_ok = consumed_type && SubgroupHeader::decode(&mut cursor).is_ok();
            assert!(!header_ok, "[{}] expected decode error but succeeded", vector.id);
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

            let st = decode_stream_type(&mut cursor);
            assert_eq!(st, StreamType::Datagram, "[{}] expected Datagram stream type", vector.id);
            let header = DatagramHeader::decode(&mut cursor)
                .unwrap_or_else(|e| panic!("[{}] datagram decode failed: {e}", vector.id));

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
                header.object_id.into_inner().to_string(),
                js_str(expected, "object_id"),
                "[{}] object_id mismatch",
                vector.id
            );
            assert_eq!(
                header.publisher_priority as u64,
                js_u64(expected, "publisher_priority"),
                "[{}] publisher_priority mismatch",
                vector.id
            );
            assert_eq!(
                header.extension_headers_length.into_inner().to_string(),
                js_str(expected, "extension_headers_length"),
                "[{}] extension_headers_length mismatch",
                vector.id
            );

            // Draft-09: datagram payload is everything remaining after header.
            let payload: Vec<u8> = cursor.to_vec();
            assert_eq!(
                hex::encode(&payload),
                js_str(expected, "payload_hex"),
                "[{}] payload_hex mismatch",
                vector.id
            );

            if vector.is_canonical() {
                let mut out = Vec::new();
                encode_stream_type(StreamType::Datagram, &mut out);
                header.encode(&mut out);
                out.put_slice(&payload);
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
            let consumed_type = VarInt::decode(&mut cursor).is_ok();
            let header_ok = consumed_type && DatagramHeader::decode(&mut cursor).is_ok();
            assert!(!header_ok, "[{}] expected decode error but succeeded", vector.id);
        }
    }
}

fn run_datagram_status_vectors(relative_path: &str) {
    let path = vectors_dir().join(relative_path);
    let file = load_vectors(&path);

    for vector in &file.vectors {
        if let Some(expected) = &vector.decoded {
            let bytes =
                hex::decode(&vector.hex).unwrap_or_else(|e| panic!("[{}] bad hex: {e}", vector.id));
            let mut cursor: &[u8] = &bytes;

            let st = decode_stream_type(&mut cursor);
            assert_eq!(
                st,
                StreamType::DatagramStatus,
                "[{}] expected DatagramStatus stream type",
                vector.id
            );
            let header = DatagramStatusHeader::decode(&mut cursor)
                .unwrap_or_else(|e| panic!("[{}] datagram-status decode failed: {e}", vector.id));

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
                header.object_id.into_inner().to_string(),
                js_str(expected, "object_id"),
                "[{}] object_id mismatch",
                vector.id
            );
            assert_eq!(
                header.publisher_priority as u64,
                js_u64(expected, "publisher_priority"),
                "[{}] publisher_priority mismatch",
                vector.id
            );
            assert_eq!(
                header.extension_headers_length.into_inner().to_string(),
                js_str(expected, "extension_headers_length"),
                "[{}] extension_headers_length mismatch",
                vector.id
            );
            assert_eq!(
                (header.object_status as u64).to_string(),
                js_str(expected, "object_status"),
                "[{}] object_status mismatch",
                vector.id
            );

            if vector.is_canonical() {
                let mut out = Vec::new();
                encode_stream_type(StreamType::DatagramStatus, &mut out);
                header.encode(&mut out);
                assert_eq!(
                    hex::encode(&out),
                    vector.hex,
                    "[{}] re-encoded datagram-status mismatch",
                    vector.id
                );
            }
        }

        if vector.error.is_some() {
            let bytes =
                hex::decode(&vector.hex).unwrap_or_else(|e| panic!("[{}] bad hex: {e}", vector.id));
            let mut cursor: &[u8] = &bytes;
            let consumed_type = VarInt::decode(&mut cursor).is_ok();
            let header_ok = consumed_type && DatagramStatusHeader::decode(&mut cursor).is_ok();
            assert!(!header_ok, "[{}] expected decode error but succeeded", vector.id);
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

            let st = decode_stream_type(&mut cursor);
            assert_eq!(st, StreamType::Fetch, "[{}] expected Fetch stream type", vector.id);
            let header = FetchHeader::decode(&mut cursor)
                .unwrap_or_else(|e| panic!("[{}] fetch header decode failed: {e}", vector.id));
            assert_eq!(
                header.subscribe_id.into_inner().to_string(),
                js_str(expected, "subscribe_id"),
                "[{}] subscribe_id mismatch",
                vector.id
            );

            let expected_objs = expected
                .get("objects")
                .and_then(|v| v.as_array())
                .unwrap_or_else(|| panic!("[{}] missing objects array", vector.id));

            let mut decoded_objects = Vec::new();
            for eo in expected_objs {
                let obj = FetchObjectHeader::decode(&mut cursor)
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
                assert_eq!(
                    obj.extension_headers_length.into_inner().to_string(),
                    js_str(eo, "extension_headers_length"),
                    "[{}] extension_headers_length mismatch",
                    vector.id
                );
                if let Some(s) = js_str_opt(eo, "object_status") {
                    assert_eq!(
                        (obj.object_status as u64).to_string(),
                        s,
                        "[{}] object_status mismatch",
                        vector.id
                    );
                }
                assert_eq!(
                    obj.payload_length.into_inner().to_string(),
                    js_str(eo, "payload_length"),
                    "[{}] payload_length mismatch",
                    vector.id
                );

                let plen = obj.payload_length.into_inner() as usize;
                assert!(cursor.remaining() >= plen, "[{}] fetch payload underrun", vector.id);
                let mut payload = vec![0u8; plen];
                cursor.copy_to_slice(&mut payload);
                assert_eq!(
                    hex::encode(&payload),
                    js_str(eo, "payload_hex"),
                    "[{}] payload_hex mismatch",
                    vector.id
                );
                decoded_objects.push((obj, payload));
            }

            if vector.is_canonical() {
                let mut out = Vec::new();
                encode_stream_type(StreamType::Fetch, &mut out);
                header.encode(&mut out);
                for (obj, payload) in &decoded_objects {
                    obj.encode(&mut out);
                    out.put_slice(payload);
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
            let consumed_type = VarInt::decode(&mut cursor).is_ok();
            let header_ok = consumed_type && FetchHeader::decode(&mut cursor).is_ok();
            assert!(!header_ok, "[{}] expected decode error but succeeded", vector.id);
        }
    }
}

#[test]
fn d09_data_stream_subgroup() {
    run_subgroup_vectors("transport/draft09/codec/data-streams/subgroup.json");
}

#[test]
fn d09_data_stream_datagram() {
    run_datagram_vectors("transport/draft09/codec/data-streams/datagram.json");
}

#[test]
fn d09_data_stream_datagram_status() {
    run_datagram_status_vectors("transport/draft09/codec/data-streams/datagram-status.json");
}

#[test]
fn d09_data_stream_fetch() {
    run_fetch_vectors("transport/draft09/codec/data-streams/fetch-header.json");
}

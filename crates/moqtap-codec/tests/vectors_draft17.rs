#![cfg(feature = "draft17")]

mod test_vectors;

use moqtap_codec::dispatch::AnySubgroupHeader;
use moqtap_codec::draft17::message::ControlMessage;
use test_vectors::{dispatch_check, load_vectors, vectors_dir};

fn run_message_vectors(relative_path: &str) {
    let path = vectors_dir().join(relative_path);
    let file = load_vectors(&path);

    for vector in &file.vectors {
        if let Some(expected_decoded) = &vector.decoded {
            let bytes =
                hex::decode(&vector.hex).unwrap_or_else(|e| panic!("[{}] bad hex: {e}", vector.id));
            let msg = ControlMessage::decode(&mut &bytes[..])
                .unwrap_or_else(|e| panic!("[{}] decode failed: {e}", vector.id));
            let actual_json = test_vectors::fields_json::to_json(
                &moqtap_codec::draft17::fields::message_fields(&msg),
            );
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
            match ControlMessage::decode(&mut &bytes[..]) {
                Ok(_) => panic!("[{}] expected error but decoded successfully", vector.id),
                Err(e) => vector.assert_error(&e),
            }
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
use moqtap_codec::draft17::data_stream::{
    DatagramHeader, FetchHeader, FetchObjectHeader, SubgroupHeader,
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

            let any_header = AnySubgroupHeader::Draft17(header.clone());
            let mut object_bytes = Vec::new();
            let objects = dispatch_check::check_subgroup_objects(
                &vector.id,
                &any_header,
                &mut cursor,
                expected_objs,
                &mut object_bytes,
            );

            for dropped in 0..objects.len() {
                dispatch_check::check_elide(&any_header, &objects, dropped);
            }

            if subgroup_id_mode == 1 {
                if let Some(first) = objects.first() {
                    assert_eq!(
                        first.object_id.to_string(),
                        js_str(expected, "subgroup_id"),
                        "[{}] subgroup_id (from first object) mismatch",
                        vector.id
                    );
                }
            }

            if vector.is_canonical() {
                let mut out = Vec::new();
                header.encode(&mut out);
                out.extend_from_slice(&object_bytes);
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
            // Whichever step failed is the failure this vector is evidence of.
            // The objects are read too, because a vector calling a subgroup
            // stream malformed says it about the stream, not its header.
            let failure = match SubgroupHeader::decode(&mut cursor) {
                Err(e) => Some(e),
                Ok(header) => dispatch_check::drain_subgroup_objects(
                    &AnySubgroupHeader::Draft17(header),
                    &mut cursor,
                ),
            };
            match failure {
                Some(e) => vector.assert_error(&e),
                None => panic!("[{}] expected decode error but succeeded", vector.id),
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

            // A datagram's payload runs to the end of the transport datagram
            // and is delimited by nothing else, so `DatagramHeader::decode`
            // stops at the header and hands the tail back. Every rule about
            // that payload belongs to a reader holding both halves, and
            // `decode_object` is it. These runners answer the endpoint
            // profile, and an endpoint reads a whole datagram.
            let (hdr, payload) = DatagramHeader::decode_object(&mut cursor)
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
                    hex::encode(&payload),
                    expected_hex,
                    "[{}] payload_hex mismatch",
                    vector.id
                );
            }

            // The vectors are the encoder's account too: what decoded from
            // these bytes has to write back as these bytes. Without it a
            // published datagram vector cannot catch an encoder and decoder
            // that disagree, because only one of the two is ever run.
            //
            // Ablation: writing the Object ID from a datagram header whose Type
            // says there is none — `[datagram-no-object-id] re-encoded datagram
            // mismatch / left: "0405640080" / right: "04056480"`, measured on
            // draft-19. The decoder honours the bit either way, so nothing else
            // in these suites notices.
            if vector.is_canonical() {
                let mut out = Vec::new();
                hdr.encode(&mut out);
                out.extend_from_slice(&payload);
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
            match DatagramHeader::decode_object(&mut cursor) {
                Ok(_) => panic!("[{}] expected decode error but succeeded", vector.id),
                Err(e) => vector.assert_error(&e),
            }
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

            // The whole stream, rebuilt from the values the codec decoded. Every
            // vector here is canonical, so this has to come back byte-identical.
            let mut re_encoded = Vec::new();
            header.encode(&mut re_encoded);

            let mut prev_group_id: u64 = 0;
            let mut prev_subgroup_id: u64 = 0;
            let mut prev_object_id: Option<u64> = None;
            // Default publisher priority is 128 when no prior object sets it
            // via the 0x10 flag.
            let mut prev_priority: u8 = 128;

            for eo in expected_objs {
                let object = FetchObjectHeader::decode(&mut cursor)
                    .unwrap_or_else(|e| panic!("[{}] fetch object decode failed: {e}", vector.id));

                let flags = object.serialization_flags.into_inner();
                let expected_flags_str = js_str(eo, "serialization_flags");
                let expected_flags =
                    u64::from_str_radix(expected_flags_str.trim_start_matches("0x"), 16).unwrap();
                assert_eq!(flags, expected_flags, "[{}] serialization_flags mismatch", vector.id);

                // Resolve the fields the flags left off the wire, per draft-17
                // Section 10.4.4.1 Tables 7 and 8.
                let group_id = match object.group_id {
                    Some(v) => {
                        prev_group_id = v.into_inner();
                        prev_group_id
                    }
                    None => prev_group_id,
                };
                prev_subgroup_id = match object.subgroup_id {
                    Some(v) => v.into_inner(),
                    None if object.is_datagram() => prev_subgroup_id,
                    None => match object.subgroup_id_mode() {
                        0x00 => 0,
                        0x01 => prev_subgroup_id,
                        _ => prev_subgroup_id + 1,
                    },
                };
                let object_id = match object.object_id {
                    Some(v) => v.into_inner(),
                    None => match prev_object_id {
                        None => 0,
                        Some(prev) => prev + 1,
                    },
                };
                prev_object_id = Some(object_id);
                let priority = match object.publisher_priority {
                    Some(p) => {
                        prev_priority = p;
                        p
                    }
                    None => prev_priority,
                };

                let payload_length = object.payload_length.into_inner() as usize;

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

                object.encode(&mut re_encoded).unwrap_or_else(|e| {
                    panic!("[{}] fetch object re-encode failed: {e}", vector.id)
                });

                assert!(
                    cursor.remaining() >= payload_length,
                    "[{}] payload runs past the end of the stream",
                    vector.id
                );
                let payload = cursor[..payload_length].to_vec();
                cursor.advance(payload_length);
                re_encoded.extend_from_slice(&payload);

                if let Some(expected_hex) = js_str_opt(eo, "payload_hex") {
                    assert_eq!(
                        hex::encode(&payload),
                        expected_hex,
                        "[{}] payload_hex mismatch",
                        vector.id
                    );
                }
            }

            assert!(
                !cursor.has_remaining(),
                "[{}] {} byte(s) left after the last object",
                vector.id,
                cursor.remaining()
            );

            if vector.is_canonical() {
                assert_eq!(
                    hex::encode(&re_encoded),
                    vector.hex,
                    "[{}] re-encoded fetch stream mismatch",
                    vector.id
                );
            }
        }

        if vector.error.is_some() {
            let bytes =
                hex::decode(&vector.hex).unwrap_or_else(|e| panic!("[{}] bad hex: {e}", vector.id));
            let mut cursor: &[u8] = &bytes;
            match FetchHeader::decode(&mut cursor) {
                Ok(_) => panic!("[{}] expected decode error but succeeded", vector.id),
                Err(e) => vector.assert_error(&e),
            }
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

/// Every committed fetch vector, decoded through the draft-17 fetch object
/// codec and rebuilt byte for byte.
///
/// The objects go through `FetchObjectHeader` rather than a copy of the layout
/// written inline here, so the vectors check the shipped codec rather than a
/// second reading of the same figure, and the re-encode closes the loop: the
/// values the codec produced have to serialize back to the vector's own bytes.
///
/// *Ablation:* swapped the Subgroup ID and Object ID reads in
/// `FetchObjectHeader::decode`, so the fields come off the wire in the wrong
/// order:
///
/// ```text
/// thread 'd17_data_stream_fetch' (64216) panicked at crates\moqtap-codec\tests\vectors_draft17.rs:
/// assertion `left == right` failed: [fetch-with-subgroup-id-present] subgroup_id mismatch
///   left: "0"
///  right: "7"
/// ```
#[test]
fn d17_data_stream_fetch() {
    run_fetch_vectors("transport/draft17/codec/data-streams/fetch-header.json");
}

#![cfg(feature = "draft18")]

mod test_vectors;

use moqtap_codec::dispatch::AnySubgroupHeader;
use moqtap_codec::draft18::message::ControlMessage;
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
                &moqtap_codec::draft18::fields::message_fields(&msg),
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

macro_rules! d18_test {
    ($name:ident, $file:expr) => {
        #[test]
        fn $name() {
            run_message_vectors(concat!("transport/draft18/codec/messages/", $file));
        }
    };
}

d18_test!(d18_setup, "setup.json");
d18_test!(d18_goaway, "goaway.json");
d18_test!(d18_subscribe, "subscribe.json");
d18_test!(d18_subscribe_ok, "subscribe-ok.json");
d18_test!(d18_request_update, "request-update.json");
d18_test!(d18_publish, "publish.json");
d18_test!(d18_publish_ok, "publish-ok.json");
d18_test!(d18_publish_done, "publish-done.json");
d18_test!(d18_publish_namespace, "publish-namespace.json");
d18_test!(d18_publish_blocked, "publish-blocked.json");
d18_test!(d18_namespace, "namespace.json");
d18_test!(d18_namespace_done, "namespace-done.json");
d18_test!(d18_subscribe_namespace, "subscribe-namespace.json");
d18_test!(d18_subscribe_tracks, "subscribe-tracks.json");
d18_test!(d18_track_status, "track-status.json");
d18_test!(d18_request_ok, "request-ok.json");
d18_test!(d18_request_error, "request-error.json");
d18_test!(d18_fetch, "fetch.json");
d18_test!(d18_fetch_ok, "fetch-ok.json");
d18_test!(d18_unknown_type, "unknown-type.json");

// ─────────────────────────────────────────────────────────────
// Data-stream vectors
// ─────────────────────────────────────────────────────────────

use bytes::Buf;
use moqtap_codec::draft18::data_stream::{
    DatagramHeader, FetchHeader, FetchObjectReader, GroupOrder, SubgroupHeader,
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

            let any_header = AnySubgroupHeader::Draft18(header.clone());
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
                    &AnySubgroupHeader::Draft18(header),
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

/// Decode a draft-18 fetch stream with the crate's own fetch object codec and
/// check every frame against the vector's stated fields.
///
/// The resolution rules are draft-18 Section 11.4.4.1's: bit 0x08 puts a Group
/// ID Delta on the wire and bit 0x04 an Object ID Delta (the layout keeps Group
/// before Object), the first Object's deltas are its absolute Group ID and
/// Object ID, and a field the flags leave out is inherited from the Object
/// before. `FetchObjectReader` is what applies them; this runner only states
/// what the corpus says the answers are.
///
/// The corpus does not name a Group Order, and its descriptions say Ascending,
/// which is also the order every multi-group vector's stated Group IDs follow.
///
/// Re-encoding is checked frame by frame and then over the whole stream, so a
/// decoder that silently dropped a field — or an encoder that wrote one the
/// flags do not announce — cannot pass by agreeing with itself.
///
/// # Ablation
///
/// Dropping the `+ 1` an absent Object ID Delta implies — returning the prior
/// Object's ID rather than the one after it — was run and gives:
///
/// ```text
/// thread 'd18_data_stream_fetch'
/// panicked at crates\moqtap-codec\tests\vectors_draft18.rs:
/// assertion `left == right` failed: [fetch-stream-two-objects] object_id mismatch
///   left: "0"
///  right: "1"
/// ```
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

            let mut reader = FetchObjectReader::new(GroupOrder::Ascending);
            let mut re_encoded = Vec::new();
            header.encode(&mut re_encoded);

            for eo in expected_objs {
                let object = reader.read_object_header(&mut cursor).unwrap_or_else(|e| {
                    panic!("[{}] fetch object header decode failed: {e}", vector.id)
                });

                let expected_flags_str = js_str(eo, "serialization_flags");
                let expected_flags =
                    u64::from_str_radix(expected_flags_str.trim_start_matches("0x"), 16).unwrap();
                assert_eq!(
                    object.header.serialization_flags, expected_flags,
                    "[{}] serialization_flags mismatch",
                    vector.id
                );

                assert_eq!(
                    object.group_id.to_string(),
                    js_str(eo, "group_id"),
                    "[{}] group_id mismatch",
                    vector.id
                );
                assert_eq!(
                    object.object_id.to_string(),
                    js_str(eo, "object_id"),
                    "[{}] object_id mismatch",
                    vector.id
                );
                if let Some(sgid) = js_str_opt(eo, "subgroup_id") {
                    assert_eq!(
                        object.subgroup_id.map(|v| v.to_string()),
                        Some(sgid),
                        "[{}] subgroup_id mismatch",
                        vector.id
                    );
                }
                if let Some(prio) = js_str_opt(eo, "publisher_priority") {
                    assert_eq!(
                        object.publisher_priority.map(|p| (p as u64).to_string()),
                        Some(prio),
                        "[{}] publisher_priority mismatch",
                        vector.id
                    );
                }

                let payload_length = object.header.payload_length.into_inner();
                if let Some(expected_length) = js_str_opt(eo, "payload_length") {
                    assert_eq!(
                        payload_length.to_string(),
                        expected_length,
                        "[{}] payload_length mismatch",
                        vector.id
                    );
                }

                object.header.encode(&mut re_encoded).unwrap_or_else(|e| {
                    panic!("[{}] fetch object header encode failed: {e}", vector.id)
                });

                let payload_length = payload_length as usize;
                assert!(
                    cursor.remaining() >= payload_length,
                    "[{}] payload runs past the end of the stream",
                    vector.id
                );
                let payload = &cursor[..payload_length];
                if let Some(expected_hex) = js_str_opt(eo, "payload_hex") {
                    assert_eq!(
                        hex::encode(payload),
                        expected_hex,
                        "[{}] payload_hex mismatch",
                        vector.id
                    );
                }
                re_encoded.extend_from_slice(payload);
                cursor.advance(payload_length);
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
fn d18_data_stream_subgroup() {
    run_subgroup_vectors("transport/draft18/codec/data-streams/subgroup.json");
}

#[test]
fn d18_data_stream_datagram() {
    run_datagram_vectors("transport/draft18/codec/data-streams/datagram.json");
}

#[test]
fn d18_data_stream_fetch() {
    run_fetch_vectors("transport/draft18/codec/data-streams/fetch-header.json");
}

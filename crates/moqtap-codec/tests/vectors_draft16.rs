#![cfg(feature = "draft16")]

mod test_vectors;

use moqtap_codec::dispatch::AnySubgroupHeader;
use moqtap_codec::draft16::message::ControlMessage;
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
            let actual_json = test_vectors::draft16_json::message_to_json(&msg);
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

macro_rules! d16_test {
    ($name:ident, $file:expr) => {
        #[test]
        fn $name() {
            run_message_vectors(concat!("transport/draft16/codec/messages/", $file));
        }
    };
}

d16_test!(d16_client_setup, "client-setup.json");
d16_test!(d16_server_setup, "server-setup.json");
d16_test!(d16_goaway, "goaway.json");
d16_test!(d16_max_request_id, "max-request-id.json");
d16_test!(d16_requests_blocked, "requests-blocked.json");
d16_test!(d16_subscribe, "subscribe.json");
d16_test!(d16_subscribe_ok, "subscribe-ok.json");
d16_test!(d16_request_update, "request-update.json");
d16_test!(d16_unsubscribe, "unsubscribe.json");
d16_test!(d16_publish, "publish.json");
d16_test!(d16_publish_ok, "publish-ok.json");
d16_test!(d16_publish_done, "publish-done.json");
d16_test!(d16_publish_namespace, "publish-namespace.json");
d16_test!(d16_publish_namespace_done, "publish-namespace-done.json");
d16_test!(d16_publish_namespace_cancel, "publish-namespace-cancel.json");
d16_test!(d16_namespace, "namespace.json");
d16_test!(d16_namespace_done, "namespace-done.json");
d16_test!(d16_subscribe_namespace, "subscribe-namespace.json");
d16_test!(d16_track_status, "track-status.json");
d16_test!(d16_request_ok, "request-ok.json");
d16_test!(d16_request_error, "request-error.json");
d16_test!(d16_fetch, "fetch.json");
d16_test!(d16_fetch_ok, "fetch-ok.json");
d16_test!(d16_fetch_cancel, "fetch-cancel.json");
d16_test!(d16_unknown_type, "unknown-type.json");

// ─────────────────────────────────────────────────────────────
// Data-stream vectors
// ─────────────────────────────────────────────────────────────

use bytes::Buf;
use moqtap_codec::draft16::data_stream::{
    DatagramHeader, FetchHeader, FetchObjectHeader, FetchObjectReader, SubgroupHeader,
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
            // When the subgroup header uses the "first object_id" mode,
            // the subgroup_id is not carried on the wire and will be
            // verified below against the first object decoded.
            if !header.subgroup_id_from_first_object() {
                assert_eq!(
                    header.subgroup_id.into_inner().to_string(),
                    js_str(expected, "subgroup_id"),
                    "[{}] subgroup_id mismatch",
                    vector.id
                );
            }
            if let Some(p) = header.publisher_priority {
                assert_eq!(
                    (p as u64).to_string(),
                    js_str(expected, "publisher_priority"),
                    "[{}] publisher_priority mismatch",
                    vector.id
                );
            } else {
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

            let any_header = AnySubgroupHeader::Draft16(header.clone());
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

            if header.subgroup_id_from_first_object() {
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
                    &AnySubgroupHeader::Draft16(header),
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
            if let Some(p) = hdr.publisher_priority {
                assert_eq!(
                    (p as u64).to_string(),
                    js_str(expected, "publisher_priority"),
                    "[{}] publisher_priority mismatch",
                    vector.id
                );
            } else {
                assert!(
                    js_str_opt(expected, "publisher_priority").is_none(),
                    "[{}] expected no publisher_priority (default)",
                    vector.id
                );
            }
            if let Some(s) = js_str_opt(expected, "object_status") {
                let status = hdr.object_status.expect("expected object_status");
                assert_eq!(
                    status.as_u64().to_string(),
                    s,
                    "[{}] object_status mismatch",
                    vector.id
                );
            }
            if let Some(expected_hex) = js_str_opt(expected, "payload_hex") {
                assert_eq!(
                    hex::encode(cursor),
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
                out.extend_from_slice(cursor);
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
            match DatagramHeader::decode(&mut cursor) {
                Ok(_) => panic!("[{}] expected decode error but succeeded", vector.id),
                Err(e) => vector.assert_error(&e),
            }
        }
    }
}

/// Drive the fetch-stream vectors through the draft-16 fetch object codec:
/// decode each object's framing, resolve its Location against the object
/// before it, and rebuild the stream byte for byte.
///
/// The re-encode is the assertion that pins the field order of draft-16
/// Section 10.4.4 Figure 31. Observed by making
/// `FetchObjectHeader::encode` write the Object ID before the Group ID, which
/// fails this with:
///
/// ```text
/// assertion `left == right` failed: [fetch-end-of-non-existent-range] re-encoded fetch stream mismatch
///   left: "0504408c0a0500"
///  right: "0504408c050a00"
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

            // Re-encoded stream, built alongside the decode so a canonical
            // vector can be compared byte for byte at the end.
            let mut out = Vec::new();
            header.encode(&mut out);

            let mut reader = FetchObjectReader::new();

            for eo in expected_objs {
                let object = FetchObjectHeader::decode(&mut cursor)
                    .unwrap_or_else(|e| panic!("[{}] fetch object decode failed: {e}", vector.id));

                let expected_flags_str = js_str(eo, "serialization_flags");
                let expected_flags =
                    u64::from_str_radix(expected_flags_str.trim_start_matches("0x"), 16).unwrap();
                assert_eq!(
                    object.serialization_flags.into_inner(),
                    expected_flags,
                    "[{}] serialization_flags mismatch",
                    vector.id
                );

                let location = reader
                    .resolve(&object)
                    .unwrap_or_else(|e| panic!("[{}] fetch object resolve failed: {e}", vector.id));

                assert_eq!(
                    location.group_id.to_string(),
                    js_str(eo, "group_id"),
                    "[{}] group_id mismatch",
                    vector.id
                );
                if let Some(sgid) = js_str_opt(eo, "subgroup_id") {
                    let resolved = location
                        .subgroup_id
                        .unwrap_or_else(|| panic!("[{}] expected a subgroup_id", vector.id));
                    assert_eq!(resolved.to_string(), sgid, "[{}] subgroup_id mismatch", vector.id);
                }
                assert_eq!(
                    location.object_id.to_string(),
                    js_str(eo, "object_id"),
                    "[{}] object_id mismatch",
                    vector.id
                );
                if let Some(prio) = js_str_opt(eo, "publisher_priority") {
                    // A stream that has not stated a priority yet leaves the
                    // resolved one unset. Draft-16 Section 11.1.1.1 gives the
                    // fallback: a subscription has Publisher Priority 128 when
                    // the DEFAULT PUBLISHER PRIORITY extension is omitted.
                    assert_eq!(
                        (location.publisher_priority.unwrap_or(128) as u64).to_string(),
                        prio,
                        "[{}] publisher_priority mismatch",
                        vector.id
                    );
                }
                assert_eq!(
                    object.extensions.is_some(),
                    eo.get("extension_headers").is_some(),
                    "[{}] extensions block presence mismatch",
                    vector.id
                );

                object
                    .encode(&mut out)
                    .unwrap_or_else(|e| panic!("[{}] fetch object encode failed: {e}", vector.id));

                let payload_length = object.payload_length.into_inner() as usize;
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
                out.extend_from_slice(payload);
                cursor.advance(payload_length);
            }

            assert!(
                !cursor.has_remaining(),
                "[{}] {} bytes left over after the last object",
                vector.id,
                cursor.remaining()
            );

            if vector.is_canonical() {
                assert_eq!(
                    hex::encode(&out),
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
fn d16_data_stream_subgroup() {
    run_subgroup_vectors("transport/draft16/codec/data-streams/subgroup.json");
}

#[test]
fn d16_data_stream_datagram() {
    run_datagram_vectors("transport/draft16/codec/data-streams/datagram.json");
}

#[test]
fn d16_data_stream_fetch() {
    run_fetch_vectors("transport/draft16/codec/data-streams/fetch-header.json");
}

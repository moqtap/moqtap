#![cfg(feature = "draft19")]

mod test_vectors;

use moqtap_codec::dispatch::AnySubgroupHeader;
use moqtap_codec::draft19::message::ControlMessage;
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
                &moqtap_codec::draft19::fields::message_fields(&msg),
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

macro_rules! d19_test {
    ($name:ident, $file:expr) => {
        #[test]
        fn $name() {
            run_message_vectors(concat!("transport/draft19/codec/messages/", $file));
        }
    };
}

d19_test!(d19_setup, "setup.json");
d19_test!(d19_goaway, "goaway.json");
d19_test!(d19_subscribe, "subscribe.json");
d19_test!(d19_subscribe_ok, "subscribe-ok.json");
d19_test!(d19_request_update, "request-update.json");
d19_test!(d19_publish, "publish.json");
d19_test!(d19_publish_ok, "publish-ok.json");
d19_test!(d19_publish_done, "publish-done.json");
d19_test!(d19_publish_namespace, "publish-namespace.json");
d19_test!(d19_publish_skipped, "publish-skipped.json");
d19_test!(d19_namespace, "namespace.json");
d19_test!(d19_namespace_done, "namespace-done.json");
d19_test!(d19_subscribe_namespace, "subscribe-namespace.json");
d19_test!(d19_subscribe_tracks, "subscribe-tracks.json");
d19_test!(d19_track_status, "track-status.json");
d19_test!(d19_request_ok, "request-ok.json");
d19_test!(d19_request_error, "request-error.json");
d19_test!(d19_fetch, "fetch.json");
d19_test!(d19_fetch_ok, "fetch-ok.json");
d19_test!(d19_unknown_type, "unknown-type.json");

// ─────────────────────────────────────────────────────────────
// Data-stream vectors
// ─────────────────────────────────────────────────────────────

use bytes::Buf;
use moqtap_codec::draft19::data_stream::{
    DatagramHeader, FetchHeader, FetchObjectHeader, SubgroupHeader,
};
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

            let any_header = AnySubgroupHeader::Draft19(header.clone());
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
                    &AnySubgroupHeader::Draft19(header),
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

/// Decode a draft-19 fetch stream and check every object against the
/// vectors.
///
/// The framing comes from [`FetchObjectHeader`], which is what the vectors are
/// here to hold to account; the Group ID, Subgroup ID, Object ID and priority
/// each object resolves to are computed here, because draft-19 Section 11.4.4
/// defines them against the *previous* object on the stream and a single
/// object header cannot see one.
///
/// The arithmetic is the section's, restated:
///
///   - The first object carries both deltas and they are absolute.
///   - Later, a Group ID Delta moves the group by `delta + 1` (Ascending
///     order, the only ordering these vectors use) and the Object ID becomes
///     the Object ID Delta; with no Group ID Delta the group is unchanged and
///     the Object ID Delta is added to the previous ID, or the previous ID
///     plus one when there is no Object ID Delta either.
///   - The Subgroup ID follows Table 8: zero, the previous object's, the
///     previous object's plus one, or an explicit field.
///   - An End of Range indicator (Section 11.4.4.2) supplies the prior Group
///     and Object ID for whatever follows it, but leaves the prior Subgroup ID
///     and priority as the last real object set them.
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
            let mut prev_priority: u8 = 128;
            let mut first_object = true;

            for eo in expected_objs {
                let before = cursor.len();
                let object = FetchObjectHeader::decode(&mut cursor)
                    .unwrap_or_else(|e| panic!("[{}] fetch object decode failed: {e}", vector.id));
                let consumed = &bytes[bytes.len() - before..bytes.len() - cursor.len()];

                let expected_flags_str = js_str(eo, "serialization_flags");
                let expected_flags =
                    u64::from_str_radix(expected_flags_str.trim_start_matches("0x"), 16).unwrap();
                assert_eq!(
                    object.flags(),
                    expected_flags,
                    "[{}] serialization_flags mismatch",
                    vector.id
                );

                // The framing the decoder chose has to be the framing the
                // publisher wrote, byte for byte, or the fields after it were
                // read from the wrong offsets.
                if vector.is_canonical() {
                    let mut reencoded = Vec::new();
                    object.encode(&mut reencoded).unwrap_or_else(|e| {
                        panic!("[{}] fetch object re-encode refused: {e}", vector.id)
                    });
                    assert_eq!(
                        hex::encode(&reencoded),
                        hex::encode(consumed),
                        "[{}] re-encoded fetch object mismatch",
                        vector.id
                    );
                }

                // End of Range indicators carry an absolute Group ID and
                // Object ID in the delta fields, and nothing else.
                if object.end_of_range().is_some() {
                    let group_id = object
                        .group_id_delta
                        .expect("an End of Range indicator states its Group ID")
                        .into_inner();
                    let object_id = object
                        .object_id_delta
                        .expect("an End of Range indicator states its Object ID")
                        .into_inner();
                    assert!(
                        object.subgroup_id.is_none()
                            && object.publisher_priority.is_none()
                            && object.properties.is_none(),
                        "[{}] an End of Range indicator carries no Subgroup ID, priority \
                         or properties",
                        vector.id
                    );
                    prev_group_id = group_id;
                    prev_object_id = Some(object_id);

                    assert_eq!(
                        group_id.to_string(),
                        js_str(eo, "group_id"),
                        "[{}] group_id mismatch",
                        vector.id
                    );
                    assert_eq!(
                        object_id.to_string(),
                        js_str(eo, "object_id"),
                        "[{}] object_id mismatch",
                        vector.id
                    );

                    if let Some(expected_hex) = js_str_opt(eo, "payload_hex") {
                        assert_eq!(
                            object.payload_length.into_inner(),
                            0,
                            "[{}] end-of-range expected zero payload",
                            vector.id
                        );
                        assert_eq!(expected_hex, "", "[{}] expected empty payload_hex", vector.id);
                    }
                    first_object = false;
                    continue;
                }

                let group_id_delta = object.group_id_delta.map(VarInt::into_inner);
                let object_id_delta = object.object_id_delta.map(VarInt::into_inner);

                let group_id = if first_object {
                    group_id_delta.expect("first fetch object must include Group ID Delta")
                } else if let Some(d) = group_id_delta {
                    prev_group_id + d + 1
                } else {
                    prev_group_id
                };
                prev_group_id = group_id;

                // Section 11.4.4.1, all four combinations. A Group ID Delta does
                // not on its own restart the Object ID: "If Object ID Delta is
                // not present, the Object ID is the prior Object's ID plus one,
                // regardless of which group it belongs to." Only an Object ID
                // Delta arriving alongside a Group ID Delta sets the Object ID
                // outright.
                //
                // Clearing `prev_object_id` on a group change and reading a
                // missing Object ID Delta as 0 is the reading the sentence above
                // rules out. `fetch-stream-new-group-object-id-continues` is the
                // one vector that tells the two apart.
                let object_id = if first_object {
                    object_id_delta.expect("first fetch object must include Object ID Delta")
                } else {
                    let prev = prev_object_id.expect("a non-first object has a predecessor");
                    match (group_id_delta.is_some(), object_id_delta) {
                        (true, Some(d)) => d,
                        (false, Some(d)) => prev + d,
                        (_, None) => prev + 1,
                    }
                };
                prev_object_id = Some(object_id);

                // Table 8. An object with the Datagram bit set has no Subgroup
                // ID at all, so the prior one is left where it was.
                let subgroup_id = if object.is_datagram() {
                    None
                } else {
                    Some(match object.subgroup_id_mode() {
                        0b00 => 0,
                        0b01 => prev_subgroup_id,
                        0b10 => prev_subgroup_id + 1,
                        _ => object
                            .subgroup_id
                            .expect("mode 0b11 puts a Subgroup ID on the wire")
                            .into_inner(),
                    })
                };
                if let Some(id) = subgroup_id {
                    prev_subgroup_id = id;
                }

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
                        subgroup_id.map(|id| id.to_string()),
                        Some(sgid),
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
                // A vector that names properties must have had them framed,
                // and one that does not must not.
                assert_eq!(
                    object.properties.is_some(),
                    eo.get("object_properties").is_some(),
                    "[{}] object_properties presence mismatch",
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

                first_object = false;
            }

            assert!(
                !cursor.has_remaining(),
                "[{}] {} byte(s) left over after the last object",
                vector.id,
                cursor.remaining()
            );
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
fn d19_data_stream_subgroup() {
    run_subgroup_vectors("transport/draft19/codec/data-streams/subgroup.json");
}

#[test]
fn d19_data_stream_datagram() {
    run_datagram_vectors("transport/draft19/codec/data-streams/datagram.json");
}

/// The committed fetch vectors, decoded by [`FetchObjectHeader`] rather than
/// by hand, and re-encoded back to the bytes they came from.
///
/// The re-encode is what makes the framing checkable rather than merely
/// plausible: a decoder that read the right number of bytes from the wrong
/// offsets can still produce field values that pass every other assertion, and
/// only writing them back out again catches it.
///
/// # What this catches, observed by making the change and running it
///
/// Swapping the Subgroup ID and Object ID Delta reads in
/// `FetchObjectHeader::decode`:
///
/// ```text
/// assertion `left == right` failed: [fetch-with-subgroup-id-present] re-encoded fetch object mismatch
///   left: "1f0000078004"
///  right: "1f0007008004"
/// ```
#[test]
fn d19_data_stream_fetch() {
    run_fetch_vectors("transport/draft19/codec/data-streams/fetch-header.json");
}

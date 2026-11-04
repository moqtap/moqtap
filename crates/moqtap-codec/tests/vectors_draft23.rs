#![cfg(feature = "draft23")]

//! The committed draft-23 corpus, run through this codec in both directions.
//!
//! Every file under `test-vectors/transport/draft23/codec/` is read by one of
//! the runners below, and each runner counts the vectors it asserted on.
//! [`d23_every_committed_vector_is_run`] adds those counts up and compares the
//! total against a walk of the directory tree, so a file nobody named fails
//! rather than being silently skipped.
//!
//! `messages/publish-ok.json` is the one file whose vectors name the request a
//! REQUEST_OK answers, so its runner also holds each one to
//! `RequestOk::check_answers(RequestOkKind::Publish)` (Section 9.3).
//!
//! Retired error codes decode: Section 13, "An endpoint MUST NOT close the
//! session because it received an unknown error code in a REQUEST_ERROR or
//! PUBLISH_DONE."

mod test_vectors;

use moqtap_codec::dispatch::AnySubgroupHeader;
use moqtap_codec::draft23::message::{ControlMessage, RequestOkKind};
use test_vectors::{dispatch_check, load_vectors, vectors_dir};

/// The request a file's REQUEST_OK vectors answer, when the file names one.
fn request_ok_kind(relative_path: &str) -> Option<RequestOkKind> {
    relative_path.ends_with("/publish-ok.json").then_some(RequestOkKind::Publish)
}

/// Decode `bytes`, and hold a REQUEST_OK to `kind` when there is one.
fn decode_as(
    bytes: &[u8],
    kind: Option<RequestOkKind>,
) -> Result<ControlMessage, moqtap_codec::error::CodecError> {
    let msg = ControlMessage::decode(&mut &bytes[..])?;
    if let (Some(kind), ControlMessage::RequestOk(ok)) = (kind, &msg) {
        ok.check_answers(kind)?;
    }
    Ok(msg)
}

fn run_message_vectors(relative_path: &str) -> usize {
    let kind = request_ok_kind(relative_path);
    let path = vectors_dir().join(relative_path);
    let file = load_vectors(&path);
    let mut run = 0;

    for vector in &file.vectors {
        if let Some(expected_decoded) = &vector.decoded {
            let bytes =
                hex::decode(&vector.hex).unwrap_or_else(|e| panic!("[{}] bad hex: {e}", vector.id));
            let msg = decode_as(&bytes, kind)
                .unwrap_or_else(|e| panic!("[{}] decode failed: {e}", vector.id));
            let actual_json = test_vectors::fields_json::to_json(
                &moqtap_codec::draft23::fields::message_fields(&msg),
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
            run += 1;
        }

        if vector.error.is_some() {
            let bytes =
                hex::decode(&vector.hex).unwrap_or_else(|e| panic!("[{}] bad hex: {e}", vector.id));
            match decode_as(&bytes, kind) {
                Ok(_) => panic!("[{}] expected error but decoded successfully", vector.id),
                Err(e) => vector.assert_error(&e),
            }
            run += 1;
        }
    }
    run
}

macro_rules! d23_test {
    ($name:ident, $file:expr) => {
        #[test]
        fn $name() {
            run_message_vectors(concat!("transport/draft23/codec/messages/", $file));
        }
    };
}

/// Every message file the draft-23 corpus carries. There is no
/// `fetch-ok.json`: Table 5 reserves 0x18.
const MESSAGE_FILES: &[&str] = &[
    "setup.json",
    "goaway.json",
    "subscribe.json",
    "subscribe-ok.json",
    "request-update.json",
    "publish.json",
    "publish-ok.json",
    "publish-state-notify.json",
    "publish-done.json",
    "publish-namespace.json",
    "publish-skipped.json",
    "namespace.json",
    "namespace-done.json",
    "subscribe-namespace.json",
    "subscribe-tracks.json",
    "track-status.json",
    "request-ok.json",
    "request-error.json",
    "fetch.json",
    "unknown-type.json",
];

d23_test!(d23_setup, "setup.json");
d23_test!(d23_goaway, "goaway.json");
d23_test!(d23_subscribe, "subscribe.json");
d23_test!(d23_subscribe_ok, "subscribe-ok.json");
d23_test!(d23_request_update, "request-update.json");
d23_test!(d23_publish, "publish.json");
d23_test!(d23_publish_ok, "publish-ok.json");
d23_test!(d23_publish_state_notify, "publish-state-notify.json");
d23_test!(d23_publish_done, "publish-done.json");
d23_test!(d23_publish_namespace, "publish-namespace.json");
d23_test!(d23_publish_skipped, "publish-skipped.json");
d23_test!(d23_namespace, "namespace.json");
d23_test!(d23_namespace_done, "namespace-done.json");
d23_test!(d23_subscribe_namespace, "subscribe-namespace.json");
d23_test!(d23_subscribe_tracks, "subscribe-tracks.json");
d23_test!(d23_track_status, "track-status.json");
d23_test!(d23_request_ok, "request-ok.json");
d23_test!(d23_request_error, "request-error.json");
d23_test!(d23_fetch, "fetch.json");
d23_test!(d23_unknown_type, "unknown-type.json");

// ─────────────────────────────────────────────────────────────
// Data-stream vectors
// ─────────────────────────────────────────────────────────────

use bytes::Buf;
use moqtap_codec::draft23::data_stream::{
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

fn run_subgroup_vectors(relative_path: &str) -> usize {
    let path = vectors_dir().join(relative_path);
    let file = load_vectors(&path);
    let mut run = 0;

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

            let any_header = AnySubgroupHeader::Draft23(header.clone());
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
            run += 1;
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
                    &AnySubgroupHeader::Draft23(header),
                    &mut cursor,
                ),
            };
            match failure {
                Some(e) => vector.assert_error(&e),
                None => panic!("[{}] expected decode error but succeeded", vector.id),
            }
            run += 1;
        }
    }
    run
}

fn run_datagram_vectors(relative_path: &str) -> usize {
    let path = vectors_dir().join(relative_path);
    let file = load_vectors(&path);
    let mut run = 0;

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
            test_vectors::properties::assert_properties(
                &vector.id,
                moqtap_codec::version::DraftVersion::Draft23,
                &hdr.properties,
                expected,
            );
            if let Some(expected_hex) = js_str_opt(expected, "payload_hex") {
                assert_eq!(
                    hex::encode(&payload),
                    expected_hex,
                    "[{}] payload_hex mismatch",
                    vector.id
                );
            }

            // What decoded from these bytes has to write back as these bytes.
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
            run += 1;
        }

        if vector.error.is_some() {
            let bytes =
                hex::decode(&vector.hex).unwrap_or_else(|e| panic!("[{}] bad hex: {e}", vector.id));
            let mut cursor: &[u8] = &bytes;
            match DatagramHeader::decode_object(&mut cursor) {
                Ok(_) => panic!("[{}] expected decode error but succeeded", vector.id),
                Err(e) => vector.assert_error(&e),
            }
            run += 1;
        }
    }
    run
}

/// Decode a draft-23 fetch stream and check every entry against the vectors.
///
/// Resolution runs through `FetchObjectReader`, the same public API a consumer
/// uses (draft-23 Section 11.4.1.1 and draft-23 Section 11.4.2.1). End of Group
/// and End of Track entries carry only their flags in the vectors.
fn run_fetch_vectors(relative_path: &str) -> usize {
    let path = vectors_dir().join(relative_path);
    let file = load_vectors(&path);
    let mut run = 0;

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

            // Resolution runs through `FetchObjectReader`, the same public API a
            // consumer uses, rather than being recomputed here. A test that
            // re-derives Group ID, Object ID, Subgroup ID and priority inline
            // compares the corpus against a second implementation living in the
            // test file and never executes the codec's own Section 11.4.1.1
            // arithmetic at all. Where the corpus has no vector for a case — a
            // new group continuing `prior + 1` rather than resetting the Object
            // ID to 0 — the shadow copy's error and the corpus gap hide each
            // other exactly.
            let mut reader = FetchObjectReader::new(GroupOrder::Ascending);

            for eo in expected_objs {
                let before = cursor.len();
                let frame = reader
                    .read_object_header(&mut cursor)
                    .unwrap_or_else(|e| panic!("[{}] fetch object decode failed: {e}", vector.id));
                let object = &frame.header;
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

                // End of Group and End of Track carry no other field.
                if object.end_marker().is_some() {
                    assert_eq!(
                        eo.as_object().map(|o| o.len()),
                        Some(1),
                        "[{}] an End of Group or End of Track entry carries only its flags",
                        vector.id
                    );
                    assert!(
                        object.group_id_delta.is_none() && object.object_id_delta.is_none(),
                        "[{}] End of Group and End of Track carry no other field",
                        vector.id
                    );
                    continue;
                }

                assert_eq!(
                    frame.group_id.to_string(),
                    js_str(eo, "group_id"),
                    "[{}] group_id mismatch",
                    vector.id
                );
                assert_eq!(
                    frame.object_id.to_string(),
                    js_str(eo, "object_id"),
                    "[{}] object_id mismatch",
                    vector.id
                );

                // An End of Range indicator carries no Subgroup ID, priority
                // or properties.
                if object.end_of_range().is_some() {
                    assert!(
                        object.subgroup_id.is_none()
                            && object.publisher_priority.is_none()
                            && object.properties.is_none(),
                        "[{}] an End of Range indicator carries no Subgroup ID, priority \
                         or properties",
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
                    continue;
                }

                let subgroup_id = frame.subgroup_id;
                let priority = frame
                    .publisher_priority
                    .expect("a non-marker frame resolves a Publisher Priority");
                let payload_length = object.payload_length.into_inner() as usize;

                if let Some(sgid) = js_str_opt(eo, "subgroup_id") {
                    assert_eq!(
                        subgroup_id.map(|id| id.to_string()),
                        Some(sgid),
                        "[{}] subgroup_id mismatch",
                        vector.id
                    );
                }
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
                test_vectors::properties::assert_properties(
                    &vector.id,
                    moqtap_codec::version::DraftVersion::Draft23,
                    object.properties.as_deref().unwrap_or_default(),
                    eo,
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

            assert!(
                !cursor.has_remaining(),
                "[{}] {} byte(s) left over after the last object",
                vector.id,
                cursor.remaining()
            );
            run += 1;
        }

        if vector.error.is_some() {
            let bytes =
                hex::decode(&vector.hex).unwrap_or_else(|e| panic!("[{}] bad hex: {e}", vector.id));
            let mut cursor: &[u8] = &bytes;
            // A vector calling a fetch stream malformed says it about the
            // stream, not its header, and an ID that overflows is only found by
            // resolving it, so the entries go through the reader.
            let failure = match FetchHeader::decode(&mut cursor) {
                Err(e) => Some(e),
                Ok(_) => {
                    let mut reader = FetchObjectReader::new(GroupOrder::Ascending);
                    let mut found = None;
                    while cursor.has_remaining() && found.is_none() {
                        match reader.read_object_header(&mut cursor).map(|frame| frame.header) {
                            Err(e) => found = Some(e),
                            Ok(object) => {
                                let len = object.payload_length.into_inner() as usize;
                                if cursor.remaining() < len {
                                    found = Some(moqtap_codec::error::CodecError::UnexpectedEnd);
                                } else {
                                    cursor.advance(len);
                                }
                            }
                        }
                    }
                    found
                }
            };
            match failure.or_else(|| {
                test_vectors::fetch_stream::first_failure(
                    moqtap_codec::version::DraftVersion::Draft23,
                    &bytes,
                )
            }) {
                Some(e) => vector.assert_error(&e),
                None => panic!("[{}] expected decode error but succeeded", vector.id),
            }
            run += 1;
        }
    }
    run
}

#[test]
fn d23_data_stream_subgroup() {
    run_subgroup_vectors("transport/draft23/codec/data-streams/subgroup.json");
}

#[test]
fn d23_data_stream_datagram() {
    run_datagram_vectors("transport/draft23/codec/data-streams/datagram.json");
}

/// The committed fetch vectors, decoded by [`FetchObjectHeader`] rather than
/// by hand, and re-encoded back to the bytes they came from.
///
/// The re-encode is what makes the framing checkable rather than merely
/// plausible: a decoder that read the right number of bytes from the wrong
/// offsets can still produce field values that pass every other assertion, and
/// only writing them back out again catches it.
#[test]
fn d23_data_stream_fetch() {
    run_fetch_vectors("transport/draft23/codec/data-streams/fetch-header.json");
}

// ─────────────────────────────────────────────────────────────
// Coverage
// ─────────────────────────────────────────────────────────────

/// Every vector in the committed draft-23 corpus is asserted on by one of the
/// runners above.
///
/// The per-file tests each name their file, which is a list that can fall
/// behind the corpus without anything noticing: a message type added upstream
/// arrives as a file no test opens, and the suite stays green over a rule it
/// never read. So the runners are driven again here, their counts summed, and
/// the total compared against a walk of the directory tree — including
/// `varint.json`, which `vectors_varint.rs` owns and which is counted here so
/// the total is the whole corpus rather than the part this file happens to
/// reach.
#[test]
fn d23_every_committed_vector_is_run() {
    use std::collections::BTreeSet;

    let root = vectors_dir().join("transport/draft23/codec");

    // What the corpus holds.
    let mut on_disk: BTreeSet<String> = BTreeSet::new();
    fn walk(dir: &std::path::Path, root: &std::path::Path, out: &mut BTreeSet<String>) {
        for entry in std::fs::read_dir(dir).expect("the draft-23 corpus directory") {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                walk(&path, root, out);
            } else if path.extension().is_some_and(|e| e == "json") {
                out.insert(
                    path.strip_prefix(root)
                        .expect("under the corpus root")
                        .to_string_lossy()
                        .replace('\\', "/"),
                );
            }
        }
    }
    walk(&root, &root, &mut on_disk);

    // What this file, plus `vectors_varint.rs`, opens.
    let mut named: BTreeSet<String> =
        MESSAGE_FILES.iter().map(|f| format!("messages/{f}")).collect();
    assert_eq!(named.len(), MESSAGE_FILES.len(), "a message file is listed twice");
    for file in ["data-streams/subgroup.json", "data-streams/datagram.json", "varint.json"] {
        named.insert(file.to_string());
    }
    named.insert("data-streams/fetch-header.json".to_string());

    let unopened: Vec<&String> = on_disk.difference(&named).collect();
    assert!(
        unopened.is_empty(),
        "these files are in the corpus and no runner above opens them: {}",
        unopened.iter().map(|f| f.as_str()).collect::<Vec<_>>().join(", ")
    );
    let missing: Vec<&String> = named.difference(&on_disk).collect();
    assert!(
        missing.is_empty(),
        "these files are named above and are not in the corpus: {}",
        missing.iter().map(|f| f.as_str()).collect::<Vec<_>>().join(", ")
    );

    // Run every one of them and count what was asserted on.
    let mut run = 0;
    for file in MESSAGE_FILES {
        run += run_message_vectors(&format!("transport/draft23/codec/messages/{file}"));
    }
    run += run_subgroup_vectors("transport/draft23/codec/data-streams/subgroup.json");
    run += run_datagram_vectors("transport/draft23/codec/data-streams/datagram.json");
    run += run_fetch_vectors("transport/draft23/codec/data-streams/fetch-header.json");

    // `varint.json` is exercised by `vectors_varint.rs`, which reads the same
    // file through the MoQT varint codec. Counting its vectors here rather than
    // re-running them keeps the total honest about the whole corpus without
    // duplicating that suite.
    let varint_path = vectors_dir().join("transport/draft23/codec/varint.json");
    let varint_count = load_vectors(&varint_path).vectors.len();
    run += varint_count;

    // What the corpus says it holds, counted straight off disk.
    let mut on_disk_count = 0;
    for file in &on_disk {
        let data = std::fs::read_to_string(root.join(file)).expect("a corpus file");
        let parsed: serde_json::Value = serde_json::from_str(&data).expect("valid JSON");
        on_disk_count += parsed["vectors"].as_array().expect("a vectors array").len();
    }

    assert_eq!(
        run, on_disk_count,
        "the runners asserted on {run} vectors and the corpus holds {on_disk_count}"
    );
    assert_eq!(
        on_disk_count,
        425,
        "the committed draft-23 corpus is 425 vectors across 24 files; it now has \
         {on_disk_count} across {}",
        on_disk.len()
    );
    assert_eq!(on_disk.len(), 24, "the committed draft-23 corpus is 24 files");
}

//! Subgroup object checks driven through the draft dispatch layer.
//!
//! Every draft's subgroup vector runner decodes objects with
//! `AnySubgroupObjectReader` and re-encodes them with
//! `AnySubgroupObjectWriter` through this helper, so the corpus measures the
//! same parser the proxy uses rather than a hand-rolled loop.
//!
//! The negative path goes through [`drain_subgroup_objects`], and all fourteen
//! runners now read a malformed subgroup stream the same way: decode the header
//! through the entry point that reads the stream type off the wire, then read
//! objects until the bytes run out, and hand the first failure to
//! `TestVector::assert_error`. Three ablations, each measured in both
//! directions:
//!
//! - Relabelling draft-19 `subgroup-truncated` from `incomplete` to
//!   `invalid_value` now fails with `[subgroup-truncated] the decoder refused
//!   this for a different reason than the vector claims: UnexpectedEnd`. Under
//!   the previous arm — which asserted only when the header *decoded* — the
//!   same relabelled vector passed, so those six suites were spending their one
//!   negative subgroup vector on nothing at all.
//! - Decoding the header with a fixed shape instead of the type's own, with
//!   everything else held constant, makes draft-12's whole and valid
//!   `subgroup-single-object` look truncated: labelled `incomplete` it passes,
//!   because a type 0x10 stream carries no Subgroup ID and reading one eats the
//!   Publisher Priority and desynchronises every object after it. Through
//!   `decode_stream` the same label fails with `[subgroup-single-object]
//!   expected decode error but succeeded`.
//! - Answering `None` for a header that decoded, rather than draining the
//!   objects, makes a stream truncated *inside its first object* — draft-12
//!   `100100800004dead` — pass as well-formed: `[subgroup-truncated] expected
//!   decode error but succeeded`.

use bytes::Buf;
use moqtap_codec::dispatch::{
    AnySubgroupHeader, AnySubgroupObject, AnySubgroupObjectReader, AnySubgroupObjectWriter,
};
use moqtap_codec::error::CodecError;

fn js_str_opt(v: &serde_json::Value, key: &str) -> Option<String> {
    v.get(key).and_then(|x| x.as_str()).map(|s| s.to_string())
}

/// Decode every object on a subgroup stream through the dispatch reader,
/// assert it against the vector's expectations, and append its re-encoding
/// to `reencoded`.
///
/// A second reader runs `read_object_meta` over the same bytes in lockstep;
/// the two must consume identical byte counts and report identical framing,
/// which also proves they leave identical delta state behind.
pub fn check_subgroup_objects(
    vector_id: &str,
    header: &AnySubgroupHeader,
    cursor: &mut &[u8],
    expected_objs: &[serde_json::Value],
    reencoded: &mut Vec<u8>,
) -> Vec<AnySubgroupObject> {
    let mut reader = AnySubgroupObjectReader::new(header)
        .unwrap_or_else(|e| panic!("[{vector_id}] object reader construction failed: {e}"));
    let mut meta_reader = reader.clone();
    let mut meta_cursor: &[u8] = cursor;
    let mut writer = AnySubgroupObjectWriter::new(header)
        .unwrap_or_else(|e| panic!("[{vector_id}] object writer construction failed: {e}"));

    let mut objects = Vec::new();
    for expected in expected_objs {
        let before = cursor.remaining();
        let object = reader
            .read_object(cursor)
            .unwrap_or_else(|e| panic!("[{vector_id}] object decode failed: {e}"));
        let consumed = before - cursor.remaining();

        let meta_before = meta_cursor.remaining();
        let meta = meta_reader
            .read_object_meta(&mut meta_cursor)
            .unwrap_or_else(|e| panic!("[{vector_id}] object meta decode failed: {e}"));
        assert_eq!(
            meta_before - meta_cursor.remaining(),
            consumed,
            "[{vector_id}] read_object_meta consumed a different byte count"
        );
        assert_eq!(meta.wire_len as usize, consumed, "[{vector_id}] wire_len mismatch");
        assert_eq!(meta.object_id, object.object_id, "[{vector_id}] meta object_id mismatch");
        assert_eq!(meta.status, object.status, "[{vector_id}] meta status mismatch");
        assert_eq!(
            meta.payload_length as usize,
            object.payload.len(),
            "[{vector_id}] meta payload_length mismatch"
        );
        assert_eq!(
            meta.extension_headers_len as usize,
            object.extension_headers.len(),
            "[{vector_id}] meta extension_headers_len mismatch"
        );

        assert_eq!(
            object.object_id.to_string(),
            js_str_opt(expected, "object_id")
                .unwrap_or_else(|| panic!("[{vector_id}] missing object_id")),
            "[{vector_id}] object_id mismatch"
        );
        if let Some(s) = js_str_opt(expected, "payload_length") {
            assert_eq!(
                object.payload.len().to_string(),
                s,
                "[{vector_id}] payload_length mismatch"
            );
        }
        if let Some(s) = js_str_opt(expected, "payload_hex") {
            assert_eq!(hex::encode(&object.payload), s, "[{vector_id}] payload_hex mismatch");
        }
        if let Some(s) = js_str_opt(expected, "extension_count") {
            assert_eq!(
                object.extension_count.map(|c| c.to_string()),
                Some(s),
                "[{vector_id}] extension_count mismatch"
            );
        }
        if let Some(s) = js_str_opt(expected, "extension_headers_length") {
            assert_eq!(
                object.extension_headers.len().to_string(),
                s,
                "[{vector_id}] extension_headers_length mismatch"
            );
        }
        let expected_status =
            js_str_opt(expected, "object_status").or_else(|| js_str_opt(expected, "status"));
        match (object.status, expected_status) {
            (Some(code), Some(s)) => {
                assert_eq!(code.to_string(), s, "[{vector_id}] object_status mismatch")
            }
            // A vector that states a status for an object carrying a payload
            // means the implicit Normal status, which the reader reports as
            // absent.
            (None, Some(s)) => assert_eq!(s, "0", "[{vector_id}] unexpected object_status"),
            (_, None) => {}
        }

        writer
            .write_object(&object, reencoded)
            .unwrap_or_else(|e| panic!("[{vector_id}] object re-encode failed: {e}"));
        objects.push(object);
    }

    objects
}

/// Read objects off a subgroup stream until the bytes run out, and report the
/// first failure.
///
/// This is the negative half of [`check_subgroup_objects`], and the two read
/// with the same parser on purpose. A vector saying a subgroup stream is
/// malformed says it about the whole stream, not about its header: the defect
/// may sit in the third object's payload length, and a runner that stops after
/// the header would call that stream well-formed.
///
/// `None` means the stream decoded cleanly to its last byte, which for a
/// negative vector is the vector being wrong.
pub fn drain_subgroup_objects(
    header: &AnySubgroupHeader,
    cursor: &mut &[u8],
) -> Option<CodecError> {
    let mut reader = match AnySubgroupObjectReader::new(header) {
        Ok(reader) => reader,
        Err(e) => return Some(e),
    };
    while cursor.has_remaining() {
        let before = cursor.remaining();
        if let Err(e) = reader.read_object(cursor) {
            return Some(e);
        }
        assert!(
            cursor.remaining() < before,
            "an object read consumed nothing and would loop forever"
        );
    }
    None
}

/// Assert the elide invariant on a stream: feeding every object but
/// `dropped` through one writer yields a stream that decodes back to exactly
/// the retained Object IDs.
pub fn check_elide(header: &AnySubgroupHeader, objects: &[AnySubgroupObject], dropped: usize) {
    let mut writer = AnySubgroupObjectWriter::new(header).expect("writer construction failed");
    let mut buf = Vec::new();
    let mut retained = Vec::new();
    for (idx, object) in objects.iter().enumerate() {
        if idx == dropped {
            continue;
        }
        writer.write_object(object, &mut buf).expect("write_object failed");
        retained.push(object.object_id);
    }

    let mut reader = AnySubgroupObjectReader::new(header).expect("reader construction failed");
    let mut cursor: &[u8] = &buf;
    let mut decoded = Vec::new();
    while cursor.has_remaining() {
        let object = reader.read_object(&mut cursor).expect("elided stream failed to decode");
        decoded.push(object.object_id);
    }
    assert_eq!(decoded, retained, "elided stream decoded to the wrong Object IDs");
}

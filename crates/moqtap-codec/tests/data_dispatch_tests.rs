//! Object framing through the draft dispatch layer, on synthetic streams.
//!
//! Each enabled draft builds its own subgroup header, then runs the same
//! draft-neutral checks: encode a five-object stream, decode it back, assert
//! the values and the byte-identity of a re-encode, assert `read_object_meta`
//! agrees with `read_object`, assert every truncation reports "need more
//! bytes", and assert the elide invariant for the first, a middle, and the
//! last object.
//!
//! With no draft enabled there is nothing to assert and the file compiles
//! away entirely, as the `vectors_draftNN.rs` runners do.

#![cfg(any(
    feature = "draft07",
    feature = "draft08",
    feature = "draft09",
    feature = "draft10",
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20"
))]

use bytes::Buf;
use moqtap_codec::dispatch::{
    reemit_subgroup_object, AnySubgroupHeader, AnySubgroupObject, AnySubgroupObjectMeta,
    AnySubgroupObjectReader, AnySubgroupObjectWriter, Reemit,
};
use moqtap_codec::error::CodecError;
use moqtap_codec::varint::{VarInt, VarIntError};
use moqtap_codec::version::DraftVersion;

/// Five objects with IDs 0..4, one of them a zero-length status object.
fn objects(extension_headers: &[u8], extension_count: Option<u64>) -> Vec<AnySubgroupObject> {
    (0..5u64)
        .map(|object_id| AnySubgroupObject {
            object_id,
            extension_headers: extension_headers.to_vec(),
            extension_count,
            status: if object_id == 3 { Some(0) } else { None },
            payload: if object_id == 3 { Vec::new() } else { vec![0xde, 0xad, object_id as u8] },
        })
        .collect()
}

fn encode(header: &AnySubgroupHeader, objects: &[AnySubgroupObject]) -> Vec<u8> {
    let mut writer = AnySubgroupObjectWriter::new(header)
        .unwrap_or_else(|e| panic!("writer construction failed: {e}"));
    assert_eq!(writer.draft(), header.draft(), "writer draft mismatch");
    let mut wire = Vec::new();
    for object in objects {
        writer
            .write_object(object, &mut wire)
            .unwrap_or_else(|e| panic!("write_object failed: {e}"));
    }
    wire
}

/// Encode, decode, re-encode: the decoded objects must equal the originals
/// and the second encoding must be byte-identical to the first.
fn roundtrip(header: &AnySubgroupHeader, objects: &[AnySubgroupObject]) {
    let wire = encode(header, objects);

    let mut reader = AnySubgroupObjectReader::new(header)
        .unwrap_or_else(|e| panic!("reader construction failed: {e}"));
    assert_eq!(reader.draft(), header.draft(), "reader draft mismatch");
    let mut cursor: &[u8] = &wire;
    let mut decoded = Vec::new();
    while cursor.has_remaining() {
        decoded.push(
            reader.read_object(&mut cursor).unwrap_or_else(|e| panic!("read_object failed: {e}")),
        );
    }
    assert_eq!(decoded, objects, "decoded objects differ from the originals");
    assert_eq!(encode(header, &decoded), wire, "re-encode is not byte-identical");
}

/// `read_object_meta` must consume the same bytes and report the same
/// framing as `read_object`.
fn meta_matches_read_object(header: &AnySubgroupHeader, objects: &[AnySubgroupObject]) {
    let wire = encode(header, objects);
    let mut reader = AnySubgroupObjectReader::new(header).expect("reader construction failed");
    let mut cursor: &[u8] = &wire;
    let mut consumed = 0;

    for expected in objects {
        let before = cursor.remaining();
        let meta = reader
            .read_object_meta(&mut cursor)
            .unwrap_or_else(|e| panic!("read_object_meta failed: {e}"));
        assert_eq!(meta.wire_len as usize, before - cursor.remaining(), "wire_len mismatch");
        assert_eq!(meta.object_id, expected.object_id, "object_id mismatch");
        assert_eq!(meta.status, expected.status, "status mismatch");
        assert_eq!(meta.payload_length as usize, expected.payload.len(), "payload_length mismatch");
        assert_eq!(
            meta.extension_headers_len as usize,
            expected.extension_headers.len(),
            "extension_headers_len mismatch"
        );
        consumed += meta.wire_len as usize;
    }

    assert_eq!(consumed, wire.len(), "meta reader did not consume the whole stream");
    assert!(!cursor.has_remaining(), "meta reader left bytes behind");
}

fn is_incomplete(error: &CodecError) -> bool {
    matches!(error, CodecError::UnexpectedEnd | CodecError::VarInt(VarIntError::UnexpectedEnd))
}

/// Every prefix of a valid stream must fail with a "need more bytes" error
/// and nothing else — the proxy distinguishes partial from malformed on that
/// discriminant alone.
fn truncation_reports_incomplete(header: &AnySubgroupHeader, objects: &[AnySubgroupObject]) {
    let wire = encode(header, objects);
    for cut in 0..wire.len() {
        let mut reader = AnySubgroupObjectReader::new(header).expect("reader construction failed");
        let mut cursor: &[u8] = &wire[..cut];
        loop {
            match reader.read_object(&mut cursor) {
                Ok(_) => {}
                Err(e) => {
                    assert!(is_incomplete(&e), "truncation at {cut} reported {e}");
                    break;
                }
            }
        }
    }
}

/// Feeding every object but `dropped` through one writer must produce a
/// stream that decodes back to exactly the retained Object IDs.
fn check_elide(header: &AnySubgroupHeader, objects: &[AnySubgroupObject], dropped: usize) {
    let retained: Vec<&AnySubgroupObject> =
        objects.iter().enumerate().filter(|(i, _)| *i != dropped).map(|(_, o)| o).collect();

    let mut writer = AnySubgroupObjectWriter::new(header).expect("writer construction failed");
    let mut wire = Vec::new();
    for object in &retained {
        writer.write_object(object, &mut wire).expect("write_object failed");
    }

    let mut reader = AnySubgroupObjectReader::new(header).expect("reader construction failed");
    let mut cursor: &[u8] = &wire;
    let mut decoded = Vec::new();
    while cursor.has_remaining() {
        decoded.push(reader.read_object(&mut cursor).expect("elided stream failed to decode"));
    }

    let expected: Vec<u64> = retained.iter().map(|o| o.object_id).collect();
    let actual: Vec<u64> = decoded.iter().map(|o| o.object_id).collect();
    assert_eq!(actual, expected, "eliding index {dropped} produced the wrong Object IDs");
}

/// Run every check against one draft's header, for a stream with and without
/// an extension block.
fn check_all(header: &AnySubgroupHeader, objects: &[AnySubgroupObject]) {
    roundtrip(header, objects);
    meta_matches_read_object(header, objects);
    truncation_reports_incomplete(header, objects);
    // First, middle and last object: the first is the case where the
    // successor's field switches from relative to absolute on drafts 14-20.
    for dropped in [0, 2, 4] {
        check_elide(header, objects, dropped);
    }
}

/// An object carrying extension bytes that the stream's header says are
/// absent has no representation on the wire. Drafts whose extension block is
/// unconditional have no such case.
#[allow(dead_code)]
fn extensions_without_a_block_are_rejected(header: &AnySubgroupHeader) {
    let mut writer = AnySubgroupObjectWriter::new(header).expect("writer construction failed");
    let object = AnySubgroupObject {
        object_id: 0,
        extension_headers: vec![0x3c, 0x02],
        extension_count: None,
        status: None,
        payload: vec![0xca, 0xfe],
    };
    assert_eq!(
        writer.write_object(&object, &mut Vec::new()),
        Err(CodecError::InvalidField),
        "expected extensions on a no-extension stream to be rejected"
    );
}

/// Object IDs on a subgroup stream are strictly increasing: two objects can
/// never share one, and a stream that walks backwards is one no publisher can
/// produce. Drafts 14-20 get this from the delta arithmetic; drafts 07-13
/// write absolute IDs, so the dispatch writer enforces it for them. Either
/// way a rejected object must leave neither bytes nor state behind.
fn non_increasing_object_ids_are_rejected(header: &AnySubgroupHeader) {
    let object = |object_id| AnySubgroupObject {
        object_id,
        extension_headers: Vec::new(),
        extension_count: None,
        status: None,
        payload: vec![0xca, 0xfe],
    };
    let mut writer = AnySubgroupObjectWriter::new(header).expect("writer construction failed");
    let mut wire = Vec::new();
    writer.write_object(&object(5), &mut wire).expect("first write failed");
    let after_first = wire.len();

    assert_eq!(
        writer.write_object(&object(5), &mut wire),
        Err(CodecError::InvalidField),
        "expected a repeated Object ID to be rejected"
    );
    assert_eq!(
        writer.write_object(&object(3), &mut wire),
        Err(CodecError::InvalidField),
        "expected a decreasing Object ID to be rejected"
    );
    assert_eq!(wire.len(), after_first, "a rejected object must not reach the buffer");

    writer.write_object(&object(6), &mut wire).expect("write after a rejection failed");
    let mut reader = AnySubgroupObjectReader::new(header).expect("reader construction failed");
    let mut cursor: &[u8] = &wire;
    let mut ids = Vec::new();
    while cursor.has_remaining() {
        ids.push(reader.read_object(&mut cursor).expect("read_object failed").object_id);
    }
    assert_eq!(ids, vec![5, 6], "the rejections must not have disturbed the delta state");
}

// ── The elide primitive: `reemit_subgroup_object` ───────────

/// Three objects whose Object IDs need a two-byte varint and whose payloads
/// are long enough that `id_field_len + 7` lands strictly inside the object.
fn wide_objects() -> Vec<AnySubgroupObject> {
    (5000..5003u64)
        .map(|object_id| AnySubgroupObject {
            object_id,
            extension_headers: Vec::new(),
            extension_count: None,
            status: None,
            payload: vec![0xa5; 16],
        })
        .collect()
}

/// Encode `objects` and report each one's framing, in stream order.
fn framed(
    header: &AnySubgroupHeader,
    objects: &[AnySubgroupObject],
) -> (Vec<u8>, Vec<AnySubgroupObjectMeta>) {
    let wire = encode(header, objects);
    let mut reader = AnySubgroupObjectReader::new(header).expect("reader construction failed");
    let mut cursor: &[u8] = &wire;
    let mut metas = Vec::new();
    while cursor.has_remaining() {
        metas.push(reader.read_object_meta(&mut cursor).expect("read_object_meta failed"));
    }
    assert_eq!(metas.len(), objects.len(), "framing did not cover every object");
    (wire, metas)
}

/// The byte range object `index` occupies in the stream [`framed`] built.
fn frame_at(metas: &[AnySubgroupObjectMeta], index: usize) -> std::ops::Range<usize> {
    let start: usize = metas[..index].iter().map(|m| m.wire_len as usize).sum();
    start..start + metas[index].wire_len as usize
}

/// The byte length of the leading varint in `raw`, read by hand from the first
/// byte rather than through the codec, so the reemit checks measure the ID
/// field independently of the code they exercise.
///
/// Drafts 07-16 put the length in a two-bit prefix (RFC 9000 §16); draft-17
/// replaced that with a count of leading 1 bits (MoQT §1.4.1).
fn leading_varint_len(draft: DraftVersion, raw: &[u8]) -> usize {
    if matches!(
        draft,
        DraftVersion::Draft17
            | DraftVersion::Draft18
            | DraftVersion::Draft19
            | DraftVersion::Draft20
    ) {
        if raw[0] == 0xFF {
            9
        } else {
            raw[0].leading_ones() as usize + 1
        }
    } else {
        1usize << (raw[0] >> 6)
    }
}

/// An object re-emitted after the object it originally followed must come
/// out byte-identical, on every draft: the absolute drafts never touch the
/// ID field and the delta drafts recompute the same delta.
///
/// *Ablation:* delete the `encoded == &raw[..id_bytes_before]` short-circuit
/// in `reemit_subgroup_object` so the rewrite path always runs; drafts 14-20
/// must fail on the returned `Reemit`.
fn reemit_is_verbatim_without_an_elide(header: &AnySubgroupHeader) {
    let draft = header.draft();
    let objects = objects(&[], None);
    let (wire, metas) = framed(header, &objects);

    for (index, object) in objects.iter().enumerate() {
        let raw = &wire[frame_at(&metas, index)];
        let prev_forwarded = index.checked_sub(1).map(|i| objects[i].object_id);
        let mut out = Vec::new();
        let what = reemit_subgroup_object(draft, prev_forwarded, object.object_id, raw, &mut out)
            .unwrap_or_else(|e| panic!("{draft:?}: object {index} was rejected: {e}"));
        assert_eq!(what, Reemit::Verbatim, "{draft:?}: object {index} was rewritten");
        assert_eq!(out, raw, "{draft:?}: object {index} did not come out byte-identical");
    }
}

/// After an elide, the successor's leading varint is the only thing that
/// changes — and every object after it stays correct, because the writer's
/// cursor has re-converged with the reader's.
///
/// Drafts 14-20 only: on 07-13 the ID field is absolute and an elide costs
/// nothing at all, which is what `reemit_is_verbatim_without_an_elide`
/// already pins there.
///
/// *Ablation:* make `reemit_subgroup_object` copy `raw` verbatim on drafts
/// 14-20 as well; the reconstructed stream decodes to `[0, 1, 2, 4]` instead
/// of `[0, 1, 3, 4]` and the test must fail.
#[allow(dead_code)]
fn reemit_rewrites_the_leading_varint(header: &AnySubgroupHeader) {
    let draft = header.draft();
    let objects = objects(&[], None);
    let (wire, metas) = framed(header, &objects);

    // Elide index 2. Index 3 was encoded against index 2 and now follows
    // index 1, so its delta — and only its delta — has to change.
    let raw = &wire[frame_at(&metas, 3)];
    let id_bytes_before_expected = leading_varint_len(draft, raw);
    let mut fixed = Vec::new();
    let what = reemit_subgroup_object(
        draft,
        Some(objects[1].object_id),
        objects[3].object_id,
        raw,
        &mut fixed,
    )
    .unwrap_or_else(|e| panic!("{draft:?}: the successor of an elide was rejected: {e}"));

    let (id_bytes_before, id_bytes_after) = match what {
        Reemit::Reencoded { id_bytes_before, id_bytes_after } => (id_bytes_before, id_bytes_after),
        Reemit::Verbatim => panic!("{draft:?}: expected the ID field to be rewritten"),
    };
    assert_eq!(id_bytes_before, id_bytes_before_expected, "{draft:?}: wrong ID field width");
    assert_eq!(
        &fixed[id_bytes_after..],
        &raw[id_bytes_before..],
        "{draft:?}: bytes after the ID field must be copied verbatim"
    );

    // The rest of the stream needs no fix-up: splice the untouched bytes of
    // objects 0, 1 and 4 around the one re-emitted object.
    let mut elided = Vec::new();
    elided.extend_from_slice(&wire[frame_at(&metas, 0)]);
    elided.extend_from_slice(&wire[frame_at(&metas, 1)]);
    elided.extend_from_slice(&fixed);
    elided.extend_from_slice(&wire[frame_at(&metas, 4)]);

    let mut reader = AnySubgroupObjectReader::new(header).expect("reader construction failed");
    let mut cursor: &[u8] = &elided;
    let mut ids = Vec::new();
    while cursor.has_remaining() {
        ids.push(
            reader.read_object(&mut cursor).expect("elided stream failed to decode").object_id,
        );
    }
    assert_eq!(ids, vec![0, 1, 3, 4], "{draft:?}: the elided stream decoded to the wrong IDs");
}

/// **The codec-side fence for the oversized-object path.** `raw` may be any
/// prefix of an object provided the whole leading Object ID field is there;
/// everything after it is copied byte-for-byte and no length field is ever
/// read, let alone checked against `raw.len()`.
///
/// *Ablation:* the obvious form — `if raw.len() < wire_len { return
/// Err(..) }` — is not expressible here, because
/// `reemit_subgroup_object` is handed no `wire_len`. The form actually run
/// is therefore the completeness walk a mistaken
/// implementer would write instead: after the ID field, read each following
/// varint as a byte count and require that many bytes to be present. Ran it;
/// all 13 `reemit_accepts_a_prefix_of_the_object` tests failed and nothing
/// else did.
fn reemit_accepts_a_prefix(header: &AnySubgroupHeader) {
    let draft = header.draft();
    let objects = wide_objects();
    let (wire, metas) = framed(header, &objects);
    let raw = &wire[frame_at(&metas, 0)];
    let id_len = leading_varint_len(draft, raw);
    assert!(id_len >= 2, "{draft:?}: the fixture needs a multi-byte ID field, got {id_len}");

    for cut in [id_len + 1, id_len + 7, raw.len()] {
        assert!(cut <= raw.len(), "{draft:?}: fixture too short for a {cut}-byte prefix");
        let prefix = &raw[..cut];
        let mut out = Vec::new();
        let what = reemit_subgroup_object(draft, None, objects[0].object_id, prefix, &mut out)
            .unwrap_or_else(|e| panic!("{draft:?}: a {cut}-byte prefix was rejected: {e}"));
        let id_after = match what {
            Reemit::Verbatim => id_len,
            Reemit::Reencoded { id_bytes_before, id_bytes_after } => {
                assert_eq!(id_bytes_before, id_len, "{draft:?}: wrong ID field width");
                id_bytes_after
            }
        };
        assert_eq!(
            &out[id_after..],
            &prefix[id_len..],
            "{draft:?}: a {cut}-byte prefix was not copied verbatim after the ID field"
        );
        assert_eq!(
            out.len(),
            prefix.len() - id_len + id_after,
            "{draft:?}: a {cut}-byte prefix produced a length that depends on the payload field"
        );
    }

    // The one shape that is an error: an ID field cut short. Both a partial
    // varint and no bytes at all.
    for short in [&raw[..id_len - 1], &raw[..0]] {
        let mut out = Vec::new();
        assert_eq!(
            reemit_subgroup_object(draft, None, objects[0].object_id, short, &mut out),
            Err(CodecError::InvalidField),
            "{draft:?}: a {}-byte prefix must not be accepted",
            short.len()
        );
        assert!(out.is_empty(), "{draft:?}: a rejected prefix must not reach the buffer");
    }
}

/// Two objects on a subgroup stream can never share an ID, so no valid
/// re-emission exists for one that does not advance.
///
/// *Ablation:* delete the `object_id <= prev` guard at the top of
/// `reemit_subgroup_object`. Ran it; drafts 07-13 failed. It is a **no-op on
/// drafts 14-20**, and deliberately so: there the delta is `id - prev - 1`,
/// so a repeated or decreasing ID underflows `checked_sub` and the same
/// `InvalidField` comes back from the arithmetic. The guard is load-bearing
/// only on the seven absolute drafts, which is exactly where the ablation
/// bites.
fn reemit_rejects_non_increasing(header: &AnySubgroupHeader) {
    let draft = header.draft();
    let objects = objects(&[], None);
    let (wire, metas) = framed(header, &objects);
    let raw = &wire[frame_at(&metas, 4)];

    let mut out = Vec::new();
    for object_id in [5u64, 3] {
        assert_eq!(
            reemit_subgroup_object(draft, Some(5), object_id, raw, &mut out),
            Err(CodecError::InvalidField),
            "{draft:?}: expected Object ID {object_id} after 5 to be rejected"
        );
    }
    assert!(out.is_empty(), "{draft:?}: a rejected object must not reach the buffer");
}

/// An object's payload is exactly the last `payload_length` bytes of its
/// wire framing, on every draft. Nothing follows it, so a caller that has
/// `wire_len` and `payload_length` can locate the payload without a
/// per-draft offset table — the invariant a payload replacement rests on.
///
/// This is an invariant pin rather than a regression fence, so no ablation
/// was prescribed for it. Two were run. Subtracting `payload_length` from
/// the reported `wire_len` fails this test but also fails `stream_framing`
/// on every draft it touches, so it does not show the test measures anything
/// new. The discriminating one does: give draft-07's glue a one-byte
/// trailing field after the payload — written by `write_object`, consumed by
/// both readers — and the encode/decode round trip, `wire_len` and
/// `read_object_meta` all stay self-consistent while the payload stops being
/// the trailing bytes. Ran it; `draft07::stream_framing` passed and only
/// `draft07::the_payload_is_the_trailing_payload_length_bytes` failed.
fn payload_is_the_trailing_bytes(header: &AnySubgroupHeader, objects: &[AnySubgroupObject]) {
    let draft = header.draft();
    let (wire, metas) = framed(header, objects);

    for (index, object) in objects.iter().enumerate() {
        let raw = &wire[frame_at(&metas, index)];
        let meta = metas[index];
        assert_eq!(
            meta.payload_length as usize,
            object.payload.len(),
            "{draft:?}: object {index} payload length mismatch"
        );
        let offset = raw.len() - meta.payload_length as usize;
        assert_eq!(
            &raw[offset..],
            object.payload.as_slice(),
            "{draft:?}: object {index} payload is not the trailing payload_length bytes"
        );
    }
}

/// The four elide-primitive checks every draft 07-20 runs. A macro so that
/// each draft module can carry the same four test names while supplying its
/// own header and object set.
macro_rules! elide_primitive_tests {
    ($header:expr, $payload_header:expr, $payload_objects:expr $(,)?) => {
        #[test]
        fn reemit_is_verbatim_when_the_id_encoding_is_unchanged() {
            reemit_is_verbatim_without_an_elide(&$header);
        }

        #[test]
        fn reemit_accepts_a_prefix_of_the_object() {
            reemit_accepts_a_prefix(&$header);
        }

        #[test]
        fn reemit_rejects_a_non_increasing_object_id() {
            reemit_rejects_non_increasing(&$header);
        }

        #[test]
        fn the_payload_is_the_trailing_payload_length_bytes() {
            payload_is_the_trailing_bytes(&$payload_header, &$payload_objects);
        }
    };
}

// ── Drafts 07-10: absolute IDs, no stream-type gating ───────

#[cfg(feature = "draft07")]
mod draft07 {
    use super::*;
    use moqtap_codec::draft07::data_stream::SubgroupHeader;

    fn header() -> AnySubgroupHeader {
        AnySubgroupHeader::Draft07(SubgroupHeader {
            track_alias: VarInt::from_usize(1),
            group_id: VarInt::from_usize(2),
            subgroup_id: VarInt::from_usize(3),
            publisher_priority: 128,
        })
    }

    #[test]
    fn stream_framing() {
        check_all(&header(), &objects(&[], None));
    }

    #[test]
    fn rejects_extensions() {
        extensions_without_a_block_are_rejected(&header());
    }

    #[test]
    fn rejects_non_increasing_object_ids() {
        non_increasing_object_ids_are_rejected(&header());
    }

    elide_primitive_tests!(header(), header(), objects(&[], None));
}

#[cfg(feature = "draft08")]
mod draft08 {
    use super::*;
    use moqtap_codec::draft08::data_stream::SubgroupHeader;

    fn header() -> AnySubgroupHeader {
        AnySubgroupHeader::Draft08(SubgroupHeader {
            track_alias: VarInt::from_usize(1),
            group_id: VarInt::from_usize(2),
            subgroup_id: VarInt::from_usize(3),
            publisher_priority: 128,
        })
    }

    /// Draft-08's extension block is count-prefixed and unconditional, so
    /// every object reports a count — zero when there are no extensions.
    #[test]
    fn stream_framing() {
        check_all(&header(), &objects(&[], Some(0)));
    }

    /// The blob is one even-typed key-value pair, carried alongside its
    /// count.
    #[test]
    fn counted_extensions() {
        check_all(&header(), &objects(&[0x02, 0x2a], Some(1)));
    }

    #[test]
    fn rejects_non_increasing_object_ids() {
        non_increasing_object_ids_are_rejected(&header());
    }

    /// Draft-08's extension block carries a count but no byte length, so the
    /// reader can only delimit it by parsing it and the blob it hands back is
    /// re-serialized rather than copied. A value that arrived as the legal
    /// non-minimal varint `4005` comes back as the minimal `05`, so a
    /// read/write cycle is semantically but not byte-identically faithful.
    /// Pinned here so the one divergence from every other draft stays
    /// deliberate; see `AnySubgroupObject::extension_headers`.
    #[test]
    fn non_minimal_extension_varints_are_re_serialized() {
        let header = header();
        // object_id 0, one extension, even type 0x02 whose value 5 is encoded
        // as a two-byte varint, payload_length 2, payload cafe.
        let wire: &[u8] = &[0x00, 0x01, 0x02, 0x40, 0x05, 0x02, 0xca, 0xfe];

        let mut reader = AnySubgroupObjectReader::new(&header).expect("reader construction failed");
        let mut cursor = wire;
        let object = reader.read_object(&mut cursor).expect("read_object failed");
        assert!(!cursor.has_remaining(), "reader left bytes behind");
        assert_eq!(object.extension_count, Some(1), "extension count mismatch");
        assert_eq!(
            object.extension_headers,
            vec![0x02, 0x05],
            "expected the extension value re-encoded minimally"
        );
        assert_eq!(object.payload, vec![0xca, 0xfe], "payload mismatch");

        let mut meta_reader =
            AnySubgroupObjectReader::new(&header).expect("reader construction failed");
        let mut meta_cursor = wire;
        let meta = meta_reader.read_object_meta(&mut meta_cursor).expect("read_object_meta failed");
        assert_eq!(meta.wire_len as usize, wire.len(), "wire_len must count the bytes on the wire");
        assert_eq!(meta.extension_headers_len, 2, "meta reports the re-serialized blob's length");

        let mut writer = AnySubgroupObjectWriter::new(&header).expect("writer construction failed");
        let mut re_encoded = Vec::new();
        writer.write_object(&object, &mut re_encoded).expect("write_object failed");
        assert_eq!(
            re_encoded,
            vec![0x00, 0x01, 0x02, 0x05, 0x02, 0xca, 0xfe],
            "expected a minimally re-encoded object"
        );
        assert_ne!(
            re_encoded.as_slice(),
            wire,
            "the draft-08 carve-out claims this cycle is not byte-identical"
        );
    }

    elide_primitive_tests!(header(), header(), objects(&[0x02, 0x2a], Some(1)));
}

#[cfg(feature = "draft09")]
mod draft09 {
    use super::*;
    use moqtap_codec::draft09::data_stream::SubgroupHeader;

    fn header() -> AnySubgroupHeader {
        AnySubgroupHeader::Draft09(SubgroupHeader {
            track_alias: VarInt::from_usize(1),
            group_id: VarInt::from_usize(2),
            subgroup_id: VarInt::from_usize(3),
            publisher_priority: 128,
        })
    }

    #[test]
    fn stream_framing() {
        check_all(&header(), &objects(&[], None));
    }

    #[test]
    fn length_prefixed_extensions() {
        check_all(&header(), &objects(&[0x3c, 0x02], None));
    }

    #[test]
    fn rejects_non_increasing_object_ids() {
        non_increasing_object_ids_are_rejected(&header());
    }

    elide_primitive_tests!(header(), header(), objects(&[0x3c, 0x02], None));
}

#[cfg(feature = "draft10")]
mod draft10 {
    use super::*;
    use moqtap_codec::draft10::data_stream::SubgroupHeader;

    fn header() -> AnySubgroupHeader {
        AnySubgroupHeader::Draft10(SubgroupHeader {
            track_alias: VarInt::from_usize(1),
            group_id: VarInt::from_usize(2),
            subgroup_id: VarInt::from_usize(3),
            publisher_priority: 128,
        })
    }

    #[test]
    fn stream_framing() {
        check_all(&header(), &objects(&[], None));
    }

    #[test]
    fn length_prefixed_extensions() {
        check_all(&header(), &objects(&[0x3c, 0x02], None));
    }

    #[test]
    fn rejects_non_increasing_object_ids() {
        non_increasing_object_ids_are_rejected(&header());
    }

    elide_primitive_tests!(header(), header(), objects(&[0x3c, 0x02], None));
}

// ── Drafts 11-13: extension presence comes from the stream type ──

/// Generates the draft-11/12/13 checks: identical apart from the module the
/// header type comes from.
macro_rules! gated_draft_tests {
    ($name:ident, $feat:literal, $draft:ident, $variant:ident) => {
        #[cfg(feature = $feat)]
        mod $name {
            use super::*;
            use moqtap_codec::$draft::data_stream::{StreamType, SubgroupHeader};

            fn header(stream_type: StreamType) -> AnySubgroupHeader {
                AnySubgroupHeader::$variant(SubgroupHeader {
                    stream_type,
                    track_alias: VarInt::from_usize(1),
                    group_id: VarInt::from_usize(2),
                    subgroup_id: VarInt::from_usize(3),
                    publisher_priority: 128,
                })
            }

            #[test]
            fn stream_framing() {
                check_all(&header(StreamType::SubgroupExplicit), &objects(&[], None));
            }

            #[test]
            fn stream_framing_with_extensions() {
                check_all(&header(StreamType::SubgroupExplicitExt), &objects(&[0x3c, 0x02], None));
            }

            /// The extensions bit lives on the stream type, so a stream
            /// without it cannot carry an extension block at all.
            #[test]
            fn rejects_extensions() {
                extensions_without_a_block_are_rejected(&header(StreamType::SubgroupExplicit));
            }

            #[test]
            fn rejects_non_increasing_object_ids() {
                non_increasing_object_ids_are_rejected(&header(StreamType::SubgroupExplicit));
            }

            /// A non-subgroup stream type is not a subgroup stream.
            #[test]
            fn rejects_non_subgroup_stream_type() {
                let header = header(StreamType::Fetch);
                assert_eq!(
                    AnySubgroupObjectReader::new(&header).err(),
                    Some(CodecError::InvalidField),
                    "expected a fetch stream type to be rejected"
                );
            }

            elide_primitive_tests!(
                header(StreamType::SubgroupExplicit),
                header(StreamType::SubgroupExplicitExt),
                objects(&[0x3c, 0x02], None),
            );
        }
    };
}

gated_draft_tests!(draft11, "draft11", draft11, Draft11);
gated_draft_tests!(draft12, "draft12", draft12, Draft12);
gated_draft_tests!(draft13, "draft13", draft13, Draft13);

// ── Drafts 14-20: delta-encoded object IDs ──────────────────

#[cfg(feature = "draft14")]
mod draft14 {
    use super::*;
    use moqtap_codec::draft14::data_stream::{SubgroupHeader, SubgroupStreamType};

    fn header(extensions: bool) -> AnySubgroupHeader {
        AnySubgroupHeader::Draft14(SubgroupHeader {
            stream_type: SubgroupStreamType::from_flags(true, false, extensions, false),
            track_alias: VarInt::from_usize(1),
            group_id: VarInt::from_usize(2),
            subgroup_id: Some(VarInt::from_usize(3)),
            publisher_priority: 128,
        })
    }

    #[test]
    fn stream_framing() {
        check_all(&header(false), &objects(&[], None));
    }

    #[test]
    fn stream_framing_with_extensions() {
        check_all(&header(true), &objects(&[0x3c, 0x02], None));
    }

    #[test]
    fn rejects_extensions() {
        extensions_without_a_block_are_rejected(&header(false));
    }

    #[test]
    fn rejects_non_increasing_object_ids() {
        non_increasing_object_ids_are_rejected(&header(false));
    }

    elide_primitive_tests!(header(false), header(true), objects(&[0x3c, 0x02], None));

    #[test]
    fn reemit_rewrites_only_the_leading_varint_after_an_elide() {
        reemit_rewrites_the_leading_varint(&header(false));
    }
}

/// Generates the draft-15..19 checks. All five share the header shape: an
/// explicit subgroup ID (`0x04`) on top of the base bit (`0x10`), plus the
/// extensions/properties bit (`0x01`).
macro_rules! modern_draft_tests {
    ($name:ident, $feat:literal, $draft:ident, $variant:ident) => {
        #[cfg(feature = $feat)]
        mod $name {
            use super::*;
            use moqtap_codec::$draft::data_stream::SubgroupHeader;

            fn header(extensions: bool) -> AnySubgroupHeader {
                AnySubgroupHeader::$variant(SubgroupHeader {
                    header_type: if extensions { 0x15 } else { 0x14 },
                    track_alias: VarInt::from_usize(1),
                    group_id: VarInt::from_usize(2),
                    subgroup_id: VarInt::from_usize(3),
                    publisher_priority: Some(128),
                })
            }

            #[test]
            fn stream_framing() {
                check_all(&header(false), &objects(&[], None));
            }

            #[test]
            fn stream_framing_with_extensions() {
                check_all(&header(true), &objects(&[0x3c, 0x02], None));
            }

            #[test]
            fn rejects_extensions() {
                extensions_without_a_block_are_rejected(&header(false));
            }

            #[test]
            fn rejects_non_increasing_object_ids() {
                non_increasing_object_ids_are_rejected(&header(false));
            }

            elide_primitive_tests!(header(false), header(true), objects(&[0x3c, 0x02], None),);

            #[test]
            fn reemit_rewrites_only_the_leading_varint_after_an_elide() {
                reemit_rewrites_the_leading_varint(&header(false));
            }
        }
    };
}

modern_draft_tests!(draft15, "draft15", draft15, Draft15);
modern_draft_tests!(draft16, "draft16", draft16, Draft16);
modern_draft_tests!(draft17, "draft17", draft17, Draft17);
modern_draft_tests!(draft18, "draft18", draft18, Draft18);
modern_draft_tests!(draft19, "draft19", draft19, Draft19);
modern_draft_tests!(draft20, "draft20", draft20, Draft20);

// ── Fetch streams ───────────────────────────────────────────

/// Fetch object framing on the drafts that define it. The bytes are built
/// with each draft's own encoder and read back through the dispatch reader.
#[cfg(feature = "draft07")]
#[test]
fn fetch_objects_draft07() {
    use moqtap_codec::dispatch::{AnyFetchGroupOrder, AnyFetchHeader, AnyFetchObjectReader};
    use moqtap_codec::draft07::data_stream::{FetchHeader, FetchObjectHeader};
    use moqtap_codec::draft07::types::ObjectStatus;

    let mut wire = Vec::new();
    FetchObjectHeader {
        group_id: VarInt::from_usize(1),
        subgroup_id: VarInt::from_usize(2),
        object_id: VarInt::from_usize(3),
        publisher_priority: 128,
        object_status: ObjectStatus::Normal,
        payload_length: VarInt::from_usize(2),
    }
    .encode(&mut wire);
    wire.extend_from_slice(&[0xca, 0xfe]);

    let header = AnyFetchHeader::Draft07(FetchHeader { subscribe_id: VarInt::from_usize(9) });
    let mut reader = AnyFetchObjectReader::new(&header, AnyFetchGroupOrder::Ascending)
        .expect("fetch reader construction failed");
    let mut cursor: &[u8] = &wire;
    let object = reader.read_object(&mut cursor).expect("fetch object decode failed");
    assert_eq!(object.group_id, 1);
    assert_eq!(object.subgroup_id, 2);
    assert_eq!(object.object_id, 3);
    assert_eq!(object.publisher_priority, 128);
    assert_eq!(object.status, None);
    assert_eq!(object.payload, vec![0xca, 0xfe]);
    assert!(!cursor.has_remaining());

    let mut meta_reader = AnyFetchObjectReader::new(&header, AnyFetchGroupOrder::Ascending)
        .expect("fetch reader failed");
    let mut meta_cursor: &[u8] = &wire;
    let meta = meta_reader.read_object_meta(&mut meta_cursor).expect("fetch meta decode failed");
    assert_eq!(meta.wire_len as usize, wire.len());
    assert_eq!(meta.payload_length, 2);
    assert_eq!(meta.extension_headers_len, 0);
}

#[cfg(feature = "draft08")]
#[test]
fn fetch_objects_draft08_carry_the_extension_count() {
    use moqtap_codec::dispatch::{AnyFetchGroupOrder, AnyFetchHeader, AnyFetchObjectReader};
    use moqtap_codec::draft08::data_stream::{FetchHeader, FetchObjectHeader};
    use moqtap_codec::draft08::types::ObjectStatus;

    let mut wire = Vec::new();
    FetchObjectHeader {
        group_id: VarInt::from_usize(1),
        subgroup_id: VarInt::from_usize(2),
        object_id: VarInt::from_usize(3),
        publisher_priority: 128,
        extension_count: VarInt::from_usize(1),
        extensions: vec![0x02, 0x2a],
        object_status: ObjectStatus::Normal,
        payload_length: VarInt::from_usize(2),
    }
    .encode(&mut wire);
    wire.extend_from_slice(&[0xca, 0xfe]);

    let header = AnyFetchHeader::Draft08(FetchHeader { subscribe_id: VarInt::from_usize(9) });
    let mut reader = AnyFetchObjectReader::new(&header, AnyFetchGroupOrder::Ascending)
        .expect("fetch reader construction failed");
    let mut cursor: &[u8] = &wire;
    let object = reader.read_object(&mut cursor).expect("fetch object decode failed");
    assert_eq!(object.extension_count, Some(1));
    assert_eq!(object.extension_headers, vec![0x02, 0x2a]);
    assert_eq!(object.payload, vec![0xca, 0xfe]);
}

#[cfg(feature = "draft11")]
#[test]
fn fetch_objects_draft11_always_carry_an_extension_block() {
    use moqtap_codec::dispatch::{AnyFetchGroupOrder, AnyFetchHeader, AnyFetchObjectReader};
    use moqtap_codec::draft11::data_stream::{FetchHeader, FetchObjectHeader};
    use moqtap_codec::draft11::types::ObjectStatus;

    let mut wire = Vec::new();
    FetchObjectHeader {
        group_id: VarInt::from_usize(1),
        subgroup_id: VarInt::from_usize(2),
        object_id: VarInt::from_usize(3),
        publisher_priority: 128,
        extension_headers_length: VarInt::from_usize(2),
        extensions: vec![0x3c, 0x02],
        payload_length: VarInt::from_usize(0),
        object_status: ObjectStatus::EndOfGroup,
    }
    .encode(&mut wire);

    let header = AnyFetchHeader::Draft11(FetchHeader { request_id: VarInt::from_usize(9) });
    let mut reader = AnyFetchObjectReader::new(&header, AnyFetchGroupOrder::Ascending)
        .expect("fetch reader construction failed");
    let mut cursor: &[u8] = &wire;
    let object = reader.read_object(&mut cursor).expect("fetch object decode failed");
    assert_eq!(object.extension_count, None);
    assert_eq!(object.extension_headers, vec![0x3c, 0x02]);
    assert_eq!(object.status, Some(ObjectStatus::EndOfGroup as u64));
    assert!(object.payload.is_empty());
}

#[cfg(feature = "draft14")]
#[test]
fn fetch_objects_draft14() {
    use moqtap_codec::dispatch::{AnyFetchGroupOrder, AnyFetchHeader, AnyFetchObjectReader};
    use moqtap_codec::draft14::data_stream::{FetchHeader, FetchObject};

    let mut wire = Vec::new();
    FetchObject {
        group_id: VarInt::from_usize(1),
        subgroup_id: VarInt::from_usize(2),
        object_id: VarInt::from_usize(3),
        publisher_priority: 128,
        extension_headers: vec![0x3c, 0x02],
        status: None,
        payload: vec![0xca, 0xfe],
    }
    .encode(&mut wire);

    let header = AnyFetchHeader::Draft14(FetchHeader { request_id: VarInt::from_usize(9) });
    let mut reader = AnyFetchObjectReader::new(&header, AnyFetchGroupOrder::Ascending)
        .expect("fetch reader construction failed");
    let mut cursor: &[u8] = &wire;
    let object = reader.read_object(&mut cursor).expect("fetch object decode failed");
    assert_eq!(object.object_id, 3);
    assert_eq!(object.extension_headers, vec![0x3c, 0x02]);
    assert_eq!(object.payload, vec![0xca, 0xfe]);

    let mut meta_reader = AnyFetchObjectReader::new(&header, AnyFetchGroupOrder::Ascending)
        .expect("fetch reader failed");
    let mut meta_cursor: &[u8] = &wire;
    let meta = meta_reader.read_object_meta(&mut meta_cursor).expect("fetch meta decode failed");
    assert_eq!(meta.wire_len as usize, wire.len());
    assert_eq!(meta.extension_headers_len, 2);
    assert_eq!(meta.payload_length, 2);
}

// ── Fetch objects on drafts 15-20 ───────────────────────────
//
// These drafts replaced the fixed field list of a fetch object with a leading
// Serialization Flags value naming the fields that follow, so an object is only
// meaningful in stream order. Each test below writes three objects through that
// draft's own encoder — one stating every field of its own, one stating none,
// and one opening the next group — pins the bytes, and requires the dispatch
// reader to hand back absolute identities for all three.
//
// The three objects are the same three every time, and the bytes are not: the
// second object is where an implicit field has to be resolved, and the third is
// where drafts 16-17, which name a new group outright, part company with drafts
// 18-20, which count to it with a Group ID Delta.

#[cfg(any(
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20"
))]
use moqtap_codec::dispatch::{
    AnyFetchGroupOrder, AnyFetchHeader, AnyFetchObject, AnyFetchObjectReader,
};

/// What the three objects must resolve to. `second` and `third` are the Object
/// Status each of the two zero-length objects carries: a code on draft-15,
/// which keeps the field, and `None` on drafts 16-20, which removed it from
/// fetch objects.
#[cfg(any(
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20"
))]
fn expected_fetch_objects(second: Option<u64>, third: Option<u64>) -> Vec<AnyFetchObject> {
    let object = |group_id, object_id, status, payload: &[u8]| AnyFetchObject {
        group_id,
        subgroup_id: 2,
        has_subgroup_id: true,
        object_id,
        publisher_priority: 128,
        extension_headers: Vec::new(),
        extension_count: None,
        status,
        end_of_range: None,
        payload: payload.to_vec(),
    };
    vec![object(1, 3, None, &[0xca, 0xfe]), object(1, 4, second, &[]), object(2, 0, third, &[])]
}

/// Decode a whole fetch stream through one reader, which is what makes the
/// implicit fields resolvable at all.
#[cfg(any(
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20"
))]
fn read_fetch_stream(header: &AnyFetchHeader, wire: &[u8]) -> Vec<AnyFetchObject> {
    let mut reader = AnyFetchObjectReader::new(header, AnyFetchGroupOrder::Ascending)
        .unwrap_or_else(|e| panic!("fetch reader construction failed: {e}"));
    assert_eq!(reader.draft(), header.draft(), "fetch reader draft mismatch");
    let mut cursor: &[u8] = wire;
    let mut decoded = Vec::new();
    while cursor.has_remaining() {
        decoded.push(
            reader
                .read_object(&mut cursor)
                .unwrap_or_else(|e| panic!("fetch object decode failed: {e}")),
        );
    }
    decoded
}

/// Draft-15 is the one of the five that still puts an Object Status behind a
/// zero payload length, so the status has to survive the trip through the
/// dispatch layer as well as the identities.
///
/// Reporting `Normal` for every status object instead of the code the wire
/// carried — `header.object_status.map(|_| ObjectStatus::Normal.as_u64())` in
/// `fo15::read_object`, in `src/data_dispatch.rs` — fails with:
///
/// ```text
/// assertion `left == right` failed: draft-15 fetch objects must resolve to absolute identities and keep their status
///   left: [AnyFetchObject { group_id: 1, subgroup_id: 2, has_subgroup_id: true, object_id: 3, publisher_priority: 128, extension_headers: [], extension_count: None, status: None, end_of_range: None, payload: [202, 254] }, AnyFetchObject { group_id: 1, subgroup_id: 2, has_subgroup_id: true, object_id: 4, publisher_priority: 128, extension_headers: [], extension_count: None, status: Some(0), end_of_range: None, payload: [] }, AnyFetchObject { group_id: 2, subgroup_id: 2, has_subgroup_id: true, object_id: 0, publisher_priority: 128, extension_headers: [], extension_count: None, status: Some(0), end_of_range: None, payload: [] }]
///  right: [AnyFetchObject { group_id: 1, subgroup_id: 2, has_subgroup_id: true, object_id: 3, publisher_priority: 128, extension_headers: [], extension_count: None, status: None, end_of_range: None, payload: [202, 254] }, AnyFetchObject { group_id: 1, subgroup_id: 2, has_subgroup_id: true, object_id: 4, publisher_priority: 128, extension_headers: [], extension_count: None, status: Some(3), end_of_range: None, payload: [] }, AnyFetchObject { group_id: 2, subgroup_id: 2, has_subgroup_id: true, object_id: 0, publisher_priority: 128, extension_headers: [], extension_count: None, status: Some(0), end_of_range: None, payload: [] }]
/// ```
///
/// Only the second object moves: the third's status is Normal already, which
/// is why the stream carries two status objects rather than one.
#[cfg(feature = "draft15")]
#[test]
fn fetch_objects_draft15_resolve_against_the_prior_object() {
    use moqtap_codec::draft15::data_stream::{FetchHeader, FetchObjectHeader, FetchObjectReader};
    use moqtap_codec::draft15::types::ObjectStatus;

    // 0x1f states the Subgroup ID, Object ID, Group ID and Priority; 0x01 takes
    // all four from the object before it; 0x0d states a new Group ID and Object
    // ID and keeps the rest. Draft-15 writes the flags as one fixed octet and
    // follows a zero payload length with an Object Status.
    let objects = [
        FetchObjectHeader {
            serialization_flags: 0x1f,
            group_id: VarInt::from_usize(1),
            subgroup_id: VarInt::from_usize(2),
            object_id: VarInt::from_usize(3),
            publisher_priority: 128,
            extension_headers: Vec::new(),
            payload_length: VarInt::from_usize(2),
            object_status: None,
        },
        FetchObjectHeader {
            serialization_flags: 0x01,
            group_id: VarInt::from_usize(1),
            subgroup_id: VarInt::from_usize(2),
            object_id: VarInt::from_usize(4),
            publisher_priority: 128,
            extension_headers: Vec::new(),
            payload_length: VarInt::from_usize(0),
            object_status: Some(ObjectStatus::EndOfGroup),
        },
        FetchObjectHeader {
            serialization_flags: 0x0d,
            group_id: VarInt::from_usize(2),
            subgroup_id: VarInt::from_usize(2),
            object_id: VarInt::from_usize(0),
            publisher_priority: 128,
            extension_headers: Vec::new(),
            payload_length: VarInt::from_usize(0),
            object_status: Some(ObjectStatus::Normal),
        },
    ];

    let mut writer = FetchObjectReader::new();
    let mut wire = Vec::new();
    for (index, object) in objects.iter().enumerate() {
        writer
            .write_object_header(object, &mut wire)
            .unwrap_or_else(|e| panic!("object {index} encode failed: {e}"));
        if object.payload_length.into_inner() == 2 {
            wire.extend_from_slice(&[0xca, 0xfe]);
        }
    }
    assert_eq!(
        wire,
        vec![
            0x1f, 0x01, 0x02, 0x03, 0x80, 0x02, 0xca, 0xfe, // group 1, subgroup 2, object 3
            0x01, 0x00, 0x03, // everything inherited, End of Group
            0x0d, 0x02, 0x00, 0x00, 0x00, // group 2, object 0, Normal
        ],
        "the draft-15 fetch stream under test"
    );

    let header = AnyFetchHeader::Draft15(FetchHeader { request_id: VarInt::from_usize(9) });
    assert_eq!(
        read_fetch_stream(&header, &wire),
        expected_fetch_objects(
            Some(ObjectStatus::EndOfGroup.as_u64()),
            Some(ObjectStatus::Normal.as_u64())
        ),
        "draft-15 fetch objects must resolve to absolute identities and keep their status"
    );
}

#[cfg(feature = "draft16")]
#[test]
fn fetch_objects_draft16_resolve_against_the_prior_object() {
    use moqtap_codec::draft16::data_stream::{FetchHeader, FetchObjectHeader};

    // The same three flag words as draft-15, now a varint, and with no Object
    // Status behind the zero payload lengths. The third object names its group.
    let objects = [
        FetchObjectHeader {
            serialization_flags: VarInt::from_usize(0x1f),
            group_id: Some(VarInt::from_usize(1)),
            subgroup_id: Some(VarInt::from_usize(2)),
            object_id: Some(VarInt::from_usize(3)),
            publisher_priority: Some(128),
            extensions: None,
            payload_length: VarInt::from_usize(2),
        },
        FetchObjectHeader {
            serialization_flags: VarInt::from_usize(0x01),
            group_id: None,
            subgroup_id: None,
            object_id: None,
            publisher_priority: None,
            extensions: None,
            payload_length: VarInt::from_usize(0),
        },
        FetchObjectHeader {
            serialization_flags: VarInt::from_usize(0x0d),
            group_id: Some(VarInt::from_usize(2)),
            subgroup_id: None,
            object_id: Some(VarInt::from_usize(0)),
            publisher_priority: None,
            extensions: None,
            payload_length: VarInt::from_usize(0),
        },
    ];

    let mut wire = Vec::new();
    for (index, object) in objects.iter().enumerate() {
        object.encode(&mut wire).unwrap_or_else(|e| panic!("object {index} encode failed: {e}"));
        if object.payload_length.into_inner() == 2 {
            wire.extend_from_slice(&[0xca, 0xfe]);
        }
    }
    assert_eq!(
        wire,
        vec![
            0x1f, 0x01, 0x02, 0x03, 0x80, 0x02, 0xca, 0xfe, // group 1, subgroup 2, object 3
            0x01, 0x00, // everything inherited
            0x0d, 0x02, 0x00, 0x00, // group 2 stated outright, object 0
        ],
        "the draft-16 fetch stream under test"
    );

    let header = AnyFetchHeader::Draft16(FetchHeader { request_id: VarInt::from_usize(9) });
    assert_eq!(
        read_fetch_stream(&header, &wire),
        expected_fetch_objects(None, None),
        "draft-16 fetch objects must resolve to absolute identities and carry no status"
    );
}

#[cfg(feature = "draft17")]
#[test]
fn fetch_objects_draft17_resolve_against_the_prior_object() {
    use moqtap_codec::draft17::data_stream::{FetchHeader, FetchObjectHeader};

    // Draft-17 renamed the extension block to Properties and kept draft-16's
    // absolute Group ID, so the bytes are draft-16's.
    let objects = [
        FetchObjectHeader {
            serialization_flags: VarInt::from_usize(0x1f),
            group_id: Some(VarInt::from_usize(1)),
            subgroup_id: Some(VarInt::from_usize(2)),
            object_id: Some(VarInt::from_usize(3)),
            publisher_priority: Some(128),
            properties: Vec::new(),
            payload_length: VarInt::from_usize(2),
        },
        FetchObjectHeader {
            serialization_flags: VarInt::from_usize(0x01),
            group_id: None,
            subgroup_id: None,
            object_id: None,
            publisher_priority: None,
            properties: Vec::new(),
            payload_length: VarInt::from_usize(0),
        },
        FetchObjectHeader {
            serialization_flags: VarInt::from_usize(0x0d),
            group_id: Some(VarInt::from_usize(2)),
            subgroup_id: None,
            object_id: Some(VarInt::from_usize(0)),
            publisher_priority: None,
            properties: Vec::new(),
            payload_length: VarInt::from_usize(0),
        },
    ];

    let mut wire = Vec::new();
    for (index, object) in objects.iter().enumerate() {
        object.encode(&mut wire).unwrap_or_else(|e| panic!("object {index} encode failed: {e}"));
        if object.payload_length.into_inner() == 2 {
            wire.extend_from_slice(&[0xca, 0xfe]);
        }
    }
    assert_eq!(
        wire,
        vec![
            0x1f, 0x01, 0x02, 0x03, 0x80, 0x02, 0xca, 0xfe, // group 1, subgroup 2, object 3
            0x01, 0x00, // everything inherited
            0x0d, 0x02, 0x00, 0x00, // group 2 stated outright, object 0
        ],
        "the draft-17 fetch stream under test"
    );

    let header = AnyFetchHeader::Draft17(FetchHeader { request_id: VarInt::from_usize(9) });
    assert_eq!(
        read_fetch_stream(&header, &wire),
        expected_fetch_objects(None, None),
        "draft-17 fetch objects must resolve to absolute identities and carry no status"
    );
}

#[cfg(feature = "draft18")]
#[test]
fn fetch_objects_draft18_resolve_deltas_against_the_prior_object() {
    use moqtap_codec::draft18::data_stream::{FetchHeader, FetchObjectHeader};

    // Draft-18 renamed both ID fields to deltas. The first object's are its
    // absolute Group ID and Object ID; the third object's Group ID Delta of
    // zero means the group after the prior one, which is where these bytes
    // stop matching draft-17's.
    let objects = [
        FetchObjectHeader {
            serialization_flags: 0x1f,
            group_id_delta: Some(VarInt::from_usize(1)),
            subgroup_id: Some(VarInt::from_usize(2)),
            object_id_delta: Some(VarInt::from_usize(3)),
            publisher_priority: Some(128),
            properties: Vec::new(),
            payload_length: VarInt::from_usize(2),
        },
        FetchObjectHeader {
            serialization_flags: 0x01,
            group_id_delta: None,
            subgroup_id: None,
            object_id_delta: None,
            publisher_priority: None,
            properties: Vec::new(),
            payload_length: VarInt::from_usize(0),
        },
        FetchObjectHeader {
            serialization_flags: 0x0d,
            group_id_delta: Some(VarInt::from_usize(0)),
            subgroup_id: None,
            object_id_delta: Some(VarInt::from_usize(0)),
            publisher_priority: None,
            properties: Vec::new(),
            payload_length: VarInt::from_usize(0),
        },
    ];

    let mut wire = Vec::new();
    for (index, object) in objects.iter().enumerate() {
        object.encode(&mut wire).unwrap_or_else(|e| panic!("object {index} encode failed: {e}"));
        if object.payload_length.into_inner() == 2 {
            wire.extend_from_slice(&[0xca, 0xfe]);
        }
    }
    assert_eq!(
        wire,
        vec![
            0x1f, 0x01, 0x02, 0x03, 0x80, 0x02, 0xca, 0xfe, // group 1, subgroup 2, object 3
            0x01, 0x00, // everything inherited
            0x0d, 0x00, 0x00, 0x00, // group delta 0 means group 2, object 0
        ],
        "the draft-18 fetch stream under test"
    );

    let header = AnyFetchHeader::Draft18(FetchHeader { request_id: VarInt::from_usize(9) });
    assert_eq!(
        read_fetch_stream(&header, &wire),
        expected_fetch_objects(None, None),
        "draft-18 fetch objects must resolve their deltas to absolute identities"
    );
}

/// Draft-19 Section 11.4.4.1: "If the Group Order is Ascending, the Group ID is
/// the prior Object's Group ID plus the Group ID Delta + 1."
///
/// Dropping that `+ 1` from the Ascending arm of `fo19::State::resolve`, in
/// `src/data_dispatch.rs`, leaves the third object in the group it was meant to
/// leave and fails with:
///
/// ```text
/// assertion `left == right` failed: draft-19 fetch objects must resolve their deltas to absolute identities
///   left: [AnyFetchObject { group_id: 1, subgroup_id: 2, has_subgroup_id: true, object_id: 3, publisher_priority: 128, extension_headers: [], extension_count: None, status: None, end_of_range: None, payload: [202, 254] }, AnyFetchObject { group_id: 1, subgroup_id: 2, has_subgroup_id: true, object_id: 4, publisher_priority: 128, extension_headers: [], extension_count: None, status: None, end_of_range: None, payload: [] }, AnyFetchObject { group_id: 1, subgroup_id: 2, has_subgroup_id: true, object_id: 0, publisher_priority: 128, extension_headers: [], extension_count: None, status: None, end_of_range: None, payload: [] }]
///  right: [AnyFetchObject { group_id: 1, subgroup_id: 2, has_subgroup_id: true, object_id: 3, publisher_priority: 128, extension_headers: [], extension_count: None, status: None, end_of_range: None, payload: [202, 254] }, AnyFetchObject { group_id: 1, subgroup_id: 2, has_subgroup_id: true, object_id: 4, publisher_priority: 128, extension_headers: [], extension_count: None, status: None, end_of_range: None, payload: [] }, AnyFetchObject { group_id: 2, subgroup_id: 2, has_subgroup_id: true, object_id: 0, publisher_priority: 128, extension_headers: [], extension_count: None, status: None, end_of_range: None, payload: [] }]
/// ```
///
/// The byte pin above is what makes that a wrong answer rather than a different
/// question: the same third object on draft-17 states its group outright and is
/// unaffected, which is the whole reason these two drafts get separate tests.
#[cfg(feature = "draft19")]
#[test]
fn fetch_objects_draft19_resolve_deltas_against_the_prior_object() {
    use moqtap_codec::draft19::data_stream::{FetchHeader, FetchObjectHeader};

    // Draft-19 keeps draft-18's deltas and distinguishes a properties block
    // that is absent from one that is present and empty, so `None` is what
    // leaves the 0x20 bit clear.
    let objects = [
        FetchObjectHeader {
            serialization_flags: VarInt::from_usize(0x1f),
            group_id_delta: Some(VarInt::from_usize(1)),
            subgroup_id: Some(VarInt::from_usize(2)),
            object_id_delta: Some(VarInt::from_usize(3)),
            publisher_priority: Some(128),
            properties: None,
            payload_length: VarInt::from_usize(2),
        },
        FetchObjectHeader {
            serialization_flags: VarInt::from_usize(0x01),
            group_id_delta: None,
            subgroup_id: None,
            object_id_delta: None,
            publisher_priority: None,
            properties: None,
            payload_length: VarInt::from_usize(0),
        },
        FetchObjectHeader {
            serialization_flags: VarInt::from_usize(0x0d),
            group_id_delta: Some(VarInt::from_usize(0)),
            subgroup_id: None,
            object_id_delta: Some(VarInt::from_usize(0)),
            publisher_priority: None,
            properties: None,
            payload_length: VarInt::from_usize(0),
        },
    ];

    let mut wire = Vec::new();
    for (index, object) in objects.iter().enumerate() {
        object.encode(&mut wire).unwrap_or_else(|e| panic!("object {index} encode failed: {e}"));
        if object.payload_length.into_inner() == 2 {
            wire.extend_from_slice(&[0xca, 0xfe]);
        }
    }
    assert_eq!(
        wire,
        vec![
            0x1f, 0x01, 0x02, 0x03, 0x80, 0x02, 0xca, 0xfe, // group 1, subgroup 2, object 3
            0x01, 0x00, // everything inherited
            0x0d, 0x00, 0x00, 0x00, // group delta 0 means group 2, object 0
        ],
        "the draft-19 fetch stream under test"
    );

    let header = AnyFetchHeader::Draft19(FetchHeader { request_id: VarInt::from_usize(9) });
    assert_eq!(
        read_fetch_stream(&header, &wire),
        expected_fetch_objects(None, None),
        "draft-19 fetch objects must resolve their deltas to absolute identities"
    );
}

/// Draft-19 Section 11.4.4.1: "If the Group Order is Ascending, the Group ID is
/// the prior Object's Group ID plus the Group ID Delta + 1."
///
/// Dropping that `+ 1` from the Ascending arm of `fo19::State::resolve`, in
/// `src/data_dispatch.rs`, leaves the third object in the group it was meant to
/// leave and fails with:
///
/// ```text
/// assertion `left == right` failed: draft-20 fetch objects must resolve their deltas to absolute identities
///   left: [AnyFetchObject { group_id: 1, subgroup_id: 2, has_subgroup_id: true, object_id: 3, publisher_priority: 128, extension_headers: [], extension_count: None, status: None, end_of_range: None, payload: [202, 254] }, AnyFetchObject { group_id: 1, subgroup_id: 2, has_subgroup_id: true, object_id: 4, publisher_priority: 128, extension_headers: [], extension_count: None, status: None, end_of_range: None, payload: [] }, AnyFetchObject { group_id: 1, subgroup_id: 2, has_subgroup_id: true, object_id: 0, publisher_priority: 128, extension_headers: [], extension_count: None, status: None, end_of_range: None, payload: [] }]
///  right: [AnyFetchObject { group_id: 1, subgroup_id: 2, has_subgroup_id: true, object_id: 3, publisher_priority: 128, extension_headers: [], extension_count: None, status: None, end_of_range: None, payload: [202, 254] }, AnyFetchObject { group_id: 1, subgroup_id: 2, has_subgroup_id: true, object_id: 4, publisher_priority: 128, extension_headers: [], extension_count: None, status: None, end_of_range: None, payload: [] }, AnyFetchObject { group_id: 2, subgroup_id: 2, has_subgroup_id: true, object_id: 0, publisher_priority: 128, extension_headers: [], extension_count: None, status: None, end_of_range: None, payload: [] }]
/// ```
///
/// The byte pin above is what makes that a wrong answer rather than a different
/// question: the same third object on draft-17 states its group outright and is
/// unaffected, which is the whole reason these drafts get separate tests.
/// Draft-20 keeps draft-19's fetch object layout unchanged, so the same bytes
/// and the same answer stand for it — which is a claim worth a test rather
/// than an assumption, since the FETCH *message* around them was rewritten.
#[cfg(feature = "draft20")]
#[test]
fn fetch_objects_draft20_resolve_deltas_against_the_prior_object() {
    use moqtap_codec::draft20::data_stream::{FetchHeader, FetchObjectHeader};

    // Draft-19 keeps draft-18's deltas and distinguishes a properties block
    // that is absent from one that is present and empty, so `None` is what
    // leaves the 0x20 bit clear.
    let objects = [
        FetchObjectHeader {
            serialization_flags: VarInt::from_usize(0x1f),
            group_id_delta: Some(VarInt::from_usize(1)),
            subgroup_id: Some(VarInt::from_usize(2)),
            object_id_delta: Some(VarInt::from_usize(3)),
            publisher_priority: Some(128),
            properties: None,
            payload_length: VarInt::from_usize(2),
        },
        FetchObjectHeader {
            serialization_flags: VarInt::from_usize(0x01),
            group_id_delta: None,
            subgroup_id: None,
            object_id_delta: None,
            publisher_priority: None,
            properties: None,
            payload_length: VarInt::from_usize(0),
        },
        FetchObjectHeader {
            serialization_flags: VarInt::from_usize(0x0d),
            group_id_delta: Some(VarInt::from_usize(0)),
            subgroup_id: None,
            object_id_delta: Some(VarInt::from_usize(0)),
            publisher_priority: None,
            properties: None,
            payload_length: VarInt::from_usize(0),
        },
    ];

    let mut wire = Vec::new();
    for (index, object) in objects.iter().enumerate() {
        object.encode(&mut wire).unwrap_or_else(|e| panic!("object {index} encode failed: {e}"));
        if object.payload_length.into_inner() == 2 {
            wire.extend_from_slice(&[0xca, 0xfe]);
        }
    }
    assert_eq!(
        wire,
        vec![
            0x1f, 0x01, 0x02, 0x03, 0x80, 0x02, 0xca, 0xfe, // group 1, subgroup 2, object 3
            0x01, 0x00, // everything inherited
            0x0d, 0x00, 0x00, 0x00, // group delta 0 means group 2, object 0
        ],
        "the draft-20 fetch stream under test"
    );

    let header = AnyFetchHeader::Draft20(FetchHeader { request_id: VarInt::from_usize(9) });
    assert_eq!(
        read_fetch_stream(&header, &wire),
        expected_fetch_objects(None, None),
        "draft-20 fetch objects must resolve their deltas to absolute identities"
    );
}

/// An End of Range marker reports the same Publisher Priority on every draft
/// that has one.
///
/// [`AnyFetchObject::publisher_priority`] is a `u8`, and a marker states no
/// Priority — draft-19 Section 11.4.4.2 lists it among the fields "not
/// present" — so the value can only be the one still in force from the Object
/// before it or the 128 a subscription that stated none is read under. Drafts
/// 16, 17 and 19 answered the first and draft-18 the second, for the same
/// stream through the same draft-neutral type, a difference none of the four
/// drafts has: what they settle is what the *next* Object inherits, and they
/// agree on that.
///
/// Each draft encodes the same two frames — one Object at priority 0x40, then
/// an End of Non-Existent Range up to group 9, object 4 — and the bytes differ
/// between them, which is why the wire is built from each draft's own header
/// type rather than written once.
///
/// # Ablation
///
/// Draft-18's own answer restored — `publisher_priority: None` in its marker
/// branch, which is what it shipped:
///
/// ```text
/// thread 'an_end_of_range_marker_reports_the_priority_in_force_on_every_draft'
/// panicked at crates\moqtap-codec\tests\data_dispatch_tests.rs:1609:9:
/// assertion `left == right` failed: draft-18: a marker reports the Priority in force, not the 128 default
///   left: 128
///  right: 64
/// ```
///
/// The other three drafts pass under it, which is the disagreement itself.
#[cfg(any(
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20"
))]
#[test]
fn an_end_of_range_marker_reports_the_priority_in_force_on_every_draft() {
    use moqtap_codec::dispatch::AnyFetchEndOfRange;

    let mut cases: Vec<(&str, AnyFetchHeader, Vec<u8>)> = Vec::new();

    #[cfg(feature = "draft16")]
    {
        use moqtap_codec::draft16::data_stream::{FetchHeader, FetchObjectHeader};
        let object = FetchObjectHeader {
            serialization_flags: VarInt::from_usize(0x1f),
            group_id: Some(VarInt::from_usize(1)),
            subgroup_id: Some(VarInt::from_usize(2)),
            object_id: Some(VarInt::from_usize(3)),
            publisher_priority: Some(0x40),
            extensions: None,
            payload_length: VarInt::from_usize(0),
        };
        let marker = FetchObjectHeader {
            serialization_flags: VarInt::from_usize(0x8c),
            group_id: Some(VarInt::from_usize(9)),
            subgroup_id: None,
            object_id: Some(VarInt::from_usize(4)),
            publisher_priority: None,
            extensions: None,
            payload_length: VarInt::from_usize(0),
        };
        let mut wire = Vec::new();
        object.encode(&mut wire).expect("the draft-16 object encodes");
        marker.encode(&mut wire).expect("the draft-16 marker encodes");
        let header = AnyFetchHeader::Draft16(FetchHeader { request_id: VarInt::from_usize(9) });
        cases.push(("draft-16", header, wire));
    }

    #[cfg(feature = "draft17")]
    {
        use moqtap_codec::draft17::data_stream::{FetchHeader, FetchObjectHeader};
        let object = FetchObjectHeader {
            serialization_flags: VarInt::from_usize(0x1f),
            group_id: Some(VarInt::from_usize(1)),
            subgroup_id: Some(VarInt::from_usize(2)),
            object_id: Some(VarInt::from_usize(3)),
            publisher_priority: Some(0x40),
            properties: Vec::new(),
            payload_length: VarInt::from_usize(0),
        };
        let marker = FetchObjectHeader {
            serialization_flags: VarInt::from_usize(0x8c),
            group_id: Some(VarInt::from_usize(9)),
            subgroup_id: None,
            object_id: Some(VarInt::from_usize(4)),
            publisher_priority: None,
            properties: Vec::new(),
            payload_length: VarInt::from_usize(0),
        };
        let mut wire = Vec::new();
        object.encode(&mut wire).expect("the draft-17 object encodes");
        marker.encode(&mut wire).expect("the draft-17 marker encodes");
        let header = AnyFetchHeader::Draft17(FetchHeader { request_id: VarInt::from_usize(9) });
        cases.push(("draft-17", header, wire));
    }

    #[cfg(feature = "draft18")]
    {
        use moqtap_codec::draft18::data_stream::{FetchHeader, FetchObjectHeader};
        let object = FetchObjectHeader {
            serialization_flags: 0x1f,
            group_id_delta: Some(VarInt::from_usize(1)),
            subgroup_id: Some(VarInt::from_usize(2)),
            object_id_delta: Some(VarInt::from_usize(3)),
            publisher_priority: Some(0x40),
            properties: Vec::new(),
            payload_length: VarInt::from_usize(0),
        };
        let marker = FetchObjectHeader {
            serialization_flags: 0x8c,
            group_id_delta: Some(VarInt::from_usize(9)),
            subgroup_id: None,
            object_id_delta: Some(VarInt::from_usize(4)),
            publisher_priority: None,
            properties: Vec::new(),
            payload_length: VarInt::from_usize(0),
        };
        let mut wire = Vec::new();
        object.encode(&mut wire).expect("the draft-18 object encodes");
        marker.encode(&mut wire).expect("the draft-18 marker encodes");
        let header = AnyFetchHeader::Draft18(FetchHeader { request_id: VarInt::from_usize(9) });
        cases.push(("draft-18", header, wire));
    }

    #[cfg(feature = "draft19")]
    {
        use moqtap_codec::draft19::data_stream::{FetchHeader, FetchObjectHeader};
        let object = FetchObjectHeader {
            serialization_flags: VarInt::from_usize(0x1f),
            group_id_delta: Some(VarInt::from_usize(1)),
            subgroup_id: Some(VarInt::from_usize(2)),
            object_id_delta: Some(VarInt::from_usize(3)),
            publisher_priority: Some(0x40),
            properties: None,
            payload_length: VarInt::from_usize(0),
        };
        let marker = FetchObjectHeader {
            serialization_flags: VarInt::from_usize(0x8c),
            group_id_delta: Some(VarInt::from_usize(9)),
            subgroup_id: None,
            object_id_delta: Some(VarInt::from_usize(4)),
            publisher_priority: None,
            properties: None,
            payload_length: VarInt::from_usize(0),
        };
        let mut wire = Vec::new();
        object.encode(&mut wire).expect("the draft-19 object encodes");
        marker.encode(&mut wire).expect("the draft-19 marker encodes");
        let header = AnyFetchHeader::Draft19(FetchHeader { request_id: VarInt::from_usize(9) });
        cases.push(("draft-19", header, wire));
    }

    #[cfg(feature = "draft20")]
    {
        use moqtap_codec::draft20::data_stream::{FetchHeader, FetchObjectHeader};
        let object = FetchObjectHeader {
            serialization_flags: VarInt::from_usize(0x1f),
            group_id_delta: Some(VarInt::from_usize(1)),
            subgroup_id: Some(VarInt::from_usize(2)),
            object_id_delta: Some(VarInt::from_usize(3)),
            publisher_priority: Some(0x40),
            properties: None,
            payload_length: VarInt::from_usize(0),
        };
        let marker = FetchObjectHeader {
            serialization_flags: VarInt::from_usize(0x8c),
            group_id_delta: Some(VarInt::from_usize(9)),
            subgroup_id: None,
            object_id_delta: Some(VarInt::from_usize(4)),
            publisher_priority: None,
            properties: None,
            payload_length: VarInt::from_usize(0),
        };
        let mut wire = Vec::new();
        object.encode(&mut wire).expect("the draft-20 object encodes");
        marker.encode(&mut wire).expect("the draft-20 marker encodes");
        let header = AnyFetchHeader::Draft20(FetchHeader { request_id: VarInt::from_usize(9) });
        cases.push(("draft-20", header, wire));
    }

    for (draft, header, wire) in &cases {
        let objects = read_fetch_stream(header, wire);
        assert_eq!(objects.len(), 2, "{draft}: an Object and a marker");
        assert_eq!(
            objects[0].publisher_priority, 0x40,
            "{draft}: the Object states its own Priority"
        );
        assert_eq!(
            objects[1].end_of_range,
            Some(AnyFetchEndOfRange::NonExistent),
            "{draft}: the second frame is the marker"
        );
        // Where the marker's two fields point is the one thing the drafts do
        // not agree on, and neither of them says so outright. Drafts 16
        // through 19 read them as the absolute Location the marker names, so a
        // Group ID Delta of 9 is group 9. Draft-20 Section 11.4.4.2 says only
        // that "the Group ID and Object ID fields are present" and this codec
        // applies Section 11.4.4.1's ordinary arithmetic to them, so the same
        // 9 after an Object in group 1 is group 1 + 9 + 1 = 11.
        //
        // Both readings are defensible from the text; what would not be
        // defensible is a draft-neutral test asserting one of them for all
        // four, which is why the expectation is per draft.
        let expected_location = if *draft == "draft-20" { (11, 4) } else { (9, 4) };
        assert_eq!(
            (objects[1].group_id, objects[1].object_id),
            expected_location,
            "{draft}: the marker's Location"
        );
        assert_eq!(
            objects[1].publisher_priority, 0x40,
            "{draft}: a marker reports the Priority in force, not the 128 default"
        );
    }
}

/// The Group Order handed to `AnyFetchObjectReader::new` decides which way a
/// draft-18 or draft-19 fetch stream's Group IDs walk.
///
/// Nothing on the stream carries the order, and both readings decode, so the
/// argument is the only thing standing between a descending fetch and Group IDs
/// resolved the wrong way. Drafts 07-17 ignore it: their Group IDs are values
/// rather than differences.
#[cfg(any(feature = "draft18", feature = "draft19", feature = "draft20"))]
#[test]
fn the_group_order_decides_a_fetch_group_id() {
    // A first object establishing group 20, then one whose Group ID Delta is 0
    // — one group along, in whichever direction the order names.
    let first: &[u8] = &[0x1C, 20, 0x00, 0x80, 0x00];
    let step: &[u8] = &[0x0C, 0x00, 0x00, 0x00];

    let mut cases: Vec<(&str, AnyFetchHeader)> = Vec::new();
    #[cfg(feature = "draft18")]
    cases.push((
        "draft-18",
        AnyFetchHeader::Draft18(moqtap_codec::draft18::data_stream::FetchHeader {
            request_id: VarInt::from_usize(9),
        }),
    ));
    #[cfg(feature = "draft19")]
    cases.push((
        "draft-19",
        AnyFetchHeader::Draft19(moqtap_codec::draft19::data_stream::FetchHeader {
            request_id: VarInt::from_usize(9),
        }),
    ));
    #[cfg(feature = "draft20")]
    cases.push((
        "draft-20",
        AnyFetchHeader::Draft20(moqtap_codec::draft20::data_stream::FetchHeader {
            request_id: VarInt::from_usize(9),
        }),
    ));

    for (draft, header) in &cases {
        let read = |order| {
            let mut reader = AnyFetchObjectReader::new(header, order).expect("reader");
            let wire = [first, step].concat();
            let mut cursor: &[u8] = &wire[..];
            reader.read_object(&mut cursor).expect("the first object decodes");
            reader.read_object(&mut cursor).expect("the second object decodes").group_id
        };
        assert_eq!(read(AnyFetchGroupOrder::Ascending), 21, "{draft}: ascending moves up");
        assert_eq!(read(AnyFetchGroupOrder::Descending), 19, "{draft}: descending moves down");
    }
}

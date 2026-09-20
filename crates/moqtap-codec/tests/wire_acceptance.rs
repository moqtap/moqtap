//! Acceptance tests, driven from independently written wire bytes.
//!
//! Everything else in this crate's suite builds a stream with
//! `AnySubgroupObjectWriter` and reads it back with
//! `AnySubgroupObjectReader`. That proves the two agree with each other, not
//! that either agrees with the wire — a reader and writer that share the
//! same misunderstanding round-trip perfectly. Two real bugs shipped green
//! underneath exactly that shape of test: drafts 17-19 read the property
//! block as count-prefixed KVPs when the wire is byte-length-prefixed, and
//! drafts 15/16 dropped the `+1` from the Object ID delta.
//!
//! So the streams here are assembled by [`Wire`], a deliberately separate
//! encoder built from each draft's documented layout, and the codec is only
//! ever the thing under test:
//!
//! - decoding `Wire`'s bytes must produce the stated objects, and
//! - re-encoding those objects must reproduce `Wire`'s bytes exactly.
//!
//! Nothing in this file names a `draftNN::` type, so it compiles unchanged
//! under any single-draft build; the enabled drafts are selected at run
//! time by [`enabled_drafts`]. With no draft at all there is nothing to
//! assert, so the file compiles away entirely — the same idiom the
//! `vectors_draftNN.rs` runners use.

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
    AnyFetchGroupOrder, AnyFetchHeader, AnyFetchObject, AnyFetchObjectReader, AnySubgroupHeader,
    AnySubgroupObject, AnySubgroupObjectReader, AnySubgroupObjectWriter,
};
use moqtap_codec::error::CodecError;
use moqtap_codec::version::DraftVersion;

/// One even-typed Key-Value-Pair: type `0x3c`, varint value `0x02`. Two
/// bytes on every draft that carries an extension/property block, so the
/// same blob serves as a byte-length of 2 and as a count of 1.
const EXT: &[u8] = &[0x3c, 0x02];

/// A zero-length object's status code. `EndOfGroup` is `0x03` on all
/// fourteen drafts, and all fourteen refuse a code their Object Status
/// section does not assign — which is what `object_status_wire.rs` gates.
/// Using an assigned code here keeps these tests about framing.
const STATUS_END_OF_GROUP: u64 = 3;

/// The drafts compiled into this build.
///
/// Selected with `cfg!` rather than `#[cfg]` so the list stays one
/// expression: every draft is named on every build and the disabled ones
/// are filtered out, which is what lets this file compile unchanged under a
/// single-draft build and under `--no-default-features`.
fn enabled_drafts() -> Vec<DraftVersion> {
    [
        (cfg!(feature = "draft07"), DraftVersion::Draft07),
        (cfg!(feature = "draft08"), DraftVersion::Draft08),
        (cfg!(feature = "draft09"), DraftVersion::Draft09),
        (cfg!(feature = "draft10"), DraftVersion::Draft10),
        (cfg!(feature = "draft11"), DraftVersion::Draft11),
        (cfg!(feature = "draft12"), DraftVersion::Draft12),
        (cfg!(feature = "draft13"), DraftVersion::Draft13),
        (cfg!(feature = "draft14"), DraftVersion::Draft14),
        (cfg!(feature = "draft15"), DraftVersion::Draft15),
        (cfg!(feature = "draft16"), DraftVersion::Draft16),
        (cfg!(feature = "draft17"), DraftVersion::Draft17),
        (cfg!(feature = "draft18"), DraftVersion::Draft18),
        (cfg!(feature = "draft19"), DraftVersion::Draft19),
        (cfg!(feature = "draft20"), DraftVersion::Draft20),
    ]
    .into_iter()
    .filter_map(|(enabled, draft)| enabled.then_some(draft))
    .collect()
}

/// Drafts with a fetch object layout this codec decodes, which is all of
/// them.
///
/// Kept as its own list rather than folded into [`enabled_drafts`] because the
/// two answer the same set only while every draft has a fetch object codec, and
/// the fetch tests below are the ones that would have to change if a future
/// draft arrived without one.
fn drafts_with_fetch_objects() -> Vec<DraftVersion> {
    enabled_drafts()
}

/// Drafts whose fetch objects are framed by a leading Serialization Flags
/// field.
///
/// From draft-15 on, that field says which of the Group ID, Subgroup ID,
/// Object ID and Priority reach the wire at all; each one it omits is taken
/// from the object before it on the stream. Through draft-14 all four are on
/// every object.
fn drafts_with_fetch_serialization_flags() -> Vec<DraftVersion> {
    enabled_drafts()
        .into_iter()
        .filter(|d| {
            matches!(
                d,
                DraftVersion::Draft15
                    | DraftVersion::Draft16
                    | DraftVersion::Draft17
                    | DraftVersion::Draft18
                    | DraftVersion::Draft19
                    | DraftVersion::Draft20
            )
        })
        .collect()
}

// ============================================================
// An encoder that shares no code with the one under test
// ============================================================

/// QUIC variable-length integer, RFC 9000 §16.
fn put_varint(out: &mut Vec<u8>, value: u64) {
    if value < 1 << 6 {
        out.push(value as u8);
    } else if value < 1 << 14 {
        out.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes());
    } else if value < 1 << 30 {
        out.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(value | 0xC000_0000_0000_0000).to_be_bytes());
    }
}

/// How a draft prefixes an object's extension/property block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExtBlock {
    /// No block on the wire at all.
    Absent,
    /// Draft-08: a count of Key-Value-Pairs, then the pairs.
    Count,
    /// Drafts 09+: a byte length, then that many bytes.
    Length,
}

/// Builds subgroup and fetch streams for one draft straight from its
/// documented wire layout.
#[derive(Debug, Clone, Copy)]
struct Wire {
    draft: DraftVersion,
    /// Whether the stream carries extensions. On drafts 11+ this selects
    /// the stream type; on 08-10 the block is unconditional and this only
    /// decides whether it is non-empty; draft-07 has no block.
    extensions: bool,
}

impl Wire {
    fn new(draft: DraftVersion, extensions: bool) -> Self {
        Self { draft, extensions }
    }

    /// Object IDs are absolute on drafts 07-13 and delta-encoded from
    /// draft-14 on, where the first object's field is its absolute ID and
    /// every later field is the gap to its predecessor biased by one.
    fn delta_encoded(&self) -> bool {
        matches!(
            self.draft,
            DraftVersion::Draft14
                | DraftVersion::Draft15
                | DraftVersion::Draft16
                | DraftVersion::Draft17
                | DraftVersion::Draft18
                | DraftVersion::Draft19
                | DraftVersion::Draft20
        )
    }

    fn subgroup_ext_block(&self) -> ExtBlock {
        match self.draft {
            DraftVersion::Draft07 => ExtBlock::Absent,
            DraftVersion::Draft08 => ExtBlock::Count,
            DraftVersion::Draft09 | DraftVersion::Draft10 => ExtBlock::Length,
            // Drafts 11+ gate the block on the stream type.
            _ if self.extensions => ExtBlock::Length,
            _ => ExtBlock::Absent,
        }
    }

    /// The fetch object extension block is unconditional from draft-09 on,
    /// even on drafts 11-13 where the *subgroup* block is gated on the
    /// stream type.
    fn fetch_ext_block(&self) -> ExtBlock {
        match self.draft {
            DraftVersion::Draft07 => ExtBlock::Absent,
            DraftVersion::Draft08 => ExtBlock::Count,
            _ => ExtBlock::Length,
        }
    }

    /// The stream type field opening a subgroup stream with an explicit
    /// subgroup ID.
    fn subgroup_stream_type(&self) -> u8 {
        match self.draft {
            // A single subgroup type; extension presence is a per-draft
            // constant rather than a type bit.
            DraftVersion::Draft07
            | DraftVersion::Draft08
            | DraftVersion::Draft09
            | DraftVersion::Draft10 => 0x04,
            // Draft-11 numbered subgroup types from 0x08; 0x0C is explicit
            // subgroup ID, 0x0D the same with extensions.
            DraftVersion::Draft11 => {
                if self.extensions {
                    0x0D
                } else {
                    0x0C
                }
            }
            // Drafts 12+ moved them to 0x10..; bit 2 selects the explicit
            // subgroup ID field and bit 0 the extension/property block.
            _ => {
                if self.extensions {
                    0x15
                } else {
                    0x14
                }
            }
        }
    }

    /// Track alias 1, group 0, subgroup 0, publisher priority 128 —
    /// including the leading stream type field.
    fn subgroup_header(&self) -> Vec<u8> {
        vec![self.subgroup_stream_type(), 0x01, 0x00, 0x00, 0x80]
    }

    fn put_ext_block(&self, out: &mut Vec<u8>, block: ExtBlock, ext: &[u8]) {
        match block {
            ExtBlock::Absent => {}
            // One KVP in `EXT`, or none when the blob is empty.
            ExtBlock::Count => {
                put_varint(out, if ext.is_empty() { 0 } else { 1 });
                out.extend_from_slice(ext);
            }
            ExtBlock::Length => {
                put_varint(out, ext.len() as u64);
                out.extend_from_slice(ext);
            }
        }
    }

    /// The extension blob carried by every object on this stream.
    fn ext(&self) -> &'static [u8] {
        if self.extensions {
            EXT
        } else {
            &[]
        }
    }

    /// `Some(count)` only on draft-08, whose block is count-prefixed.
    fn ext_count(&self, block: ExtBlock, ext: &[u8]) -> Option<u64> {
        match block {
            ExtBlock::Count => Some(if ext.is_empty() { 0 } else { 1 }),
            _ => None,
        }
    }

    /// One subgroup object. `prev` is the previous object's absolute ID, or
    /// `None` for the first object on the stream.
    fn subgroup_object(&self, prev: Option<u64>, object: &AnySubgroupObject) -> Vec<u8> {
        let mut out = Vec::new();

        let id_field = match (self.delta_encoded(), prev) {
            (true, Some(prev)) => object
                .object_id
                .checked_sub(prev)
                .and_then(|d| d.checked_sub(1))
                .expect("object IDs must strictly increase"),
            _ => object.object_id,
        };
        put_varint(&mut out, id_field);

        self.put_ext_block(&mut out, self.subgroup_ext_block(), &object.extension_headers);

        match object.status {
            Some(code) => {
                put_varint(&mut out, 0);
                put_varint(&mut out, code);
            }
            None => {
                put_varint(&mut out, object.payload.len() as u64);
                out.extend_from_slice(&object.payload);
            }
        }
        out
    }

    /// The object region of a subgroup stream — everything after the
    /// header.
    fn subgroup_objects(&self, objects: &[AnySubgroupObject]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut prev = None;
        for object in objects {
            out.extend_from_slice(&self.subgroup_object(prev, object));
            prev = Some(object.object_id);
        }
        out
    }

    /// A complete subgroup stream: header, then objects.
    fn subgroup_stream(&self, objects: &[AnySubgroupObject]) -> Vec<u8> {
        let mut out = self.subgroup_header();
        out.extend_from_slice(&self.subgroup_objects(objects));
        out
    }

    /// The objects this stream carries: IDs `ids`, each with a
    /// one-byte payload derived from its ID, and the stream's extension
    /// blob.
    fn objects(&self, ids: &[u64]) -> Vec<AnySubgroupObject> {
        let block = self.subgroup_ext_block();
        let ext = self.ext();
        ids.iter()
            .map(|&object_id| AnySubgroupObject {
                object_id,
                extension_headers: ext.to_vec(),
                extension_count: self.ext_count(block, ext),
                status: None,
                payload: vec![0xA0 | (object_id as u8 & 0x0F)],
            })
            .collect()
    }

    /// Fetch stream header: type `0x05` and request ID 9.
    fn fetch_header(&self) -> Vec<u8> {
        vec![0x05, 0x09]
    }

    /// Whether this draft frames a fetch object with a leading Serialization
    /// Flags field. Drafts 15-20; see
    /// [`drafts_with_fetch_serialization_flags`].
    fn fetch_flagged(&self) -> bool {
        matches!(
            self.draft,
            DraftVersion::Draft15
                | DraftVersion::Draft16
                | DraftVersion::Draft17
                | DraftVersion::Draft18
                | DraftVersion::Draft19
                | DraftVersion::Draft20
        )
    }

    /// Whether a fetch object's Group ID and Object ID fields carry
    /// differences from the previous object rather than values.
    ///
    /// Drafts 15-17 name the fields "Group ID" and "Object ID" and put the
    /// value there; drafts 18, 19 and 20 renamed both to "Delta" and gave them
    /// arithmetic — an Ascending-order Group ID is the previous group plus the
    /// delta plus one, and an Object ID that follows a Group ID Delta restarts
    /// from its own delta.
    fn fetch_delta_ids(&self) -> bool {
        matches!(self.draft, DraftVersion::Draft18 | DraftVersion::Draft19 | DraftVersion::Draft20)
    }

    /// Whether a fetch object carries an Object Status behind a zero payload
    /// length.
    ///
    /// Drafts 07-15 do. Drafts 16-20 removed the field from fetch objects —
    /// Object Status "is only present in objects that are delivered via a
    /// SUBSCRIPTION, and is absent in Objects delivered via a FETCH" — so a
    /// zero-length fetch object there is an object with no bytes and nothing
    /// follows the length.
    fn fetch_has_status(&self) -> bool {
        !matches!(
            self.draft,
            DraftVersion::Draft16
                | DraftVersion::Draft17
                | DraftVersion::Draft18
                | DraftVersion::Draft19
                | DraftVersion::Draft20
        )
    }

    /// One fetch object on drafts 07-14: every field spelled out, in order.
    fn fetch_object_standalone(&self, object: &AnyFetchObject) -> Vec<u8> {
        let mut out = Vec::new();
        put_varint(&mut out, object.group_id);
        put_varint(&mut out, object.subgroup_id);
        put_varint(&mut out, object.object_id);
        out.push(object.publisher_priority);
        self.put_ext_block(&mut out, self.fetch_ext_block(), &object.extension_headers);
        match object.status {
            Some(code) => {
                put_varint(&mut out, 0);
                put_varint(&mut out, code);
            }
            None => {
                put_varint(&mut out, object.payload.len() as u64);
                out.extend_from_slice(&object.payload);
            }
        }
        out
    }

    /// One fetch object on drafts 15-20, framed by Serialization Flags.
    ///
    /// The flag byte is picked from what changed since `prev`, so the stream
    /// exercises the readings the layout exists for rather than spelling every
    /// field out on every object:
    ///
    /// - the first object states its Group ID, Object ID and Priority (`0x1c`)
    ///   with the Subgroup ID mode left at `0b00`, which fixes the Subgroup ID
    ///   at zero without consulting anything. Drafts 18-20 require a first
    ///   object to carry both ID fields, and every draft allows it;
    /// - an object in the same group states nothing at all (`0x00`): the Group
    ///   ID and Priority are the previous object's, the Object ID is one past
    ///   it, the Subgroup ID is zero;
    /// - an object opening a new group states a Group ID and an Object ID
    ///   (`0x0c`) and still inherits the Priority.
    ///
    /// The extensions bit `0x20` is added, with the byte-length-prefixed block
    /// behind it, only when the stream carries extensions — the bit is what
    /// puts the block on the wire on every one of these drafts.
    ///
    /// `prev` is the previous object's absolute `(group_id, object_id)`.
    fn fetch_object_flagged(&self, prev: Option<(u64, u64)>, object: &AnyFetchObject) -> Vec<u8> {
        let (group_field, object_field, priority) = match prev {
            None => (Some(object.group_id), Some(object.object_id), true),
            Some((prev_group, prev_object)) if object.group_id == prev_group => {
                assert_eq!(
                    object.object_id,
                    prev_object + 1,
                    "[{}] a fetch object in the same group must be the next ID for the \
                     implicit form to encode it",
                    self.draft
                );
                (None, None, false)
            }
            Some((prev_group, _)) => {
                let group = if self.fetch_delta_ids() {
                    object
                        .group_id
                        .checked_sub(prev_group)
                        .and_then(|d| d.checked_sub(1))
                        .expect("fetch groups must ascend")
                } else {
                    object.group_id
                };
                // With a Group ID field present, drafts 18-20 read the Object
                // ID field as the absolute ID in the new group, which is what
                // drafts 15-17 write there anyway.
                (Some(group), Some(object.object_id), false)
            }
        };

        let mut flags = 0u8;
        if object_field.is_some() {
            flags |= 0x04;
        }
        if group_field.is_some() {
            flags |= 0x08;
        }
        if priority {
            flags |= 0x10;
        }
        if self.extensions {
            flags |= 0x20;
        }

        let mut out = vec![flags];
        // Field order: Group ID, Subgroup ID, Object ID, Priority, Extensions,
        // Object Payload Length. No Subgroup ID field is written: mode 0b00
        // states the value outright.
        if let Some(group) = group_field {
            put_varint(&mut out, group);
        }
        if let Some(id) = object_field {
            put_varint(&mut out, id);
        }
        if priority {
            out.push(object.publisher_priority);
        }
        if self.extensions {
            self.put_ext_block(&mut out, ExtBlock::Length, &object.extension_headers);
        }
        match object.status {
            Some(code) => {
                put_varint(&mut out, 0);
                put_varint(&mut out, code);
            }
            None => {
                put_varint(&mut out, object.payload.len() as u64);
                out.extend_from_slice(&object.payload);
            }
        }
        out
    }

    fn fetch_objects(&self, objects: &[AnyFetchObject]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut prev = None;
        for object in objects {
            if self.fetch_flagged() {
                out.extend_from_slice(&self.fetch_object_flagged(prev, object));
            } else {
                out.extend_from_slice(&self.fetch_object_standalone(object));
            }
            prev = Some((object.group_id, object.object_id));
        }
        out
    }

    /// Three fetch objects spanning two groups.
    ///
    /// The third is a zero-length status object on the drafts that have an
    /// Object Status on a fetch object, and an ordinary object elsewhere; see
    /// [`Self::fetch_has_status`].
    fn fetch_object_values(&self) -> Vec<AnyFetchObject> {
        let block = self.fetch_ext_block();
        let ext = self.ext();
        let base = |group_id: u64, object_id: u64| AnyFetchObject {
            group_id,
            subgroup_id: 0,
            has_subgroup_id: true,
            object_id,
            publisher_priority: 128,
            extension_headers: ext.to_vec(),
            extension_count: self.ext_count(block, ext),
            status: None,
            end_of_range: None,
            payload: vec![0xA0 | (object_id as u8 & 0x0F)],
        };
        let last = if self.fetch_has_status() {
            AnyFetchObject { status: Some(STATUS_END_OF_GROUP), payload: Vec::new(), ..base(8, 0) }
        } else {
            base(8, 0)
        };
        vec![base(7, 0), base(7, 1), last]
    }
}

// ============================================================
// Shared decoding steps
// ============================================================

/// Decode the stream header and return it with the byte count it consumed.
///
/// The count is itself an assertion target: `decode_stream` must swallow
/// the stream type field on every draft, whether the draft encodes it ahead
/// of the header (07-13) or folds it into the header (14-20).
fn decode_subgroup_header(wire: &Wire, stream: &[u8]) -> (AnySubgroupHeader, usize) {
    let mut cursor: &[u8] = stream;
    let header = AnySubgroupHeader::decode_stream(wire.draft, &mut cursor)
        .unwrap_or_else(|e| panic!("[{}] subgroup header decode failed: {e}", wire.draft));
    (header, stream.len() - cursor.remaining())
}

/// Decode every object in `bytes`, requiring the reader to consume all of
/// it.
fn read_all(
    header: &AnySubgroupHeader,
    draft: DraftVersion,
    bytes: &[u8],
) -> Vec<AnySubgroupObject> {
    let mut reader = AnySubgroupObjectReader::new(header)
        .unwrap_or_else(|e| panic!("[{draft}] reader construction failed: {e}"));
    let mut cursor: &[u8] = bytes;
    let mut objects = Vec::new();
    while cursor.has_remaining() {
        objects.push(
            reader
                .read_object(&mut cursor)
                .unwrap_or_else(|e| panic!("[{draft}] object decode failed: {e}")),
        );
    }
    objects
}

/// Encode `objects` through one writer, as a relay forwarding a subset of a
/// stream would.
fn write_all(
    header: &AnySubgroupHeader,
    draft: DraftVersion,
    objects: &[&AnySubgroupObject],
) -> Vec<u8> {
    let mut writer = AnySubgroupObjectWriter::new(header)
        .unwrap_or_else(|e| panic!("[{draft}] writer construction failed: {e}"));
    let mut out = Vec::new();
    for object in objects {
        writer
            .write_object(object, &mut out)
            .unwrap_or_else(|e| panic!("[{draft}] write_object failed: {e}"));
    }
    out
}

// ============================================================
// 1. Byte identity — the core acceptance criterion
// ============================================================

/// Decode an independently written stream, then re-encode it: the bytes
/// must come back identical, and the decoded values must be the ones the
/// wire actually states.
///
/// Catches a reader and writer that agree with each other but not with the
/// wire — the failure mode that let both bugs named in the module header
/// ship. On drafts 17-19 the extension assertion is a direct regression
/// test for the property-block one: a reader that took the `0x02` prefix
/// for a KVP *count* rather than a byte length would consume into the
/// payload-length field and desynchronize the stream.
fn assert_byte_identity(wire: &Wire) {
    let draft = wire.draft;
    let objects = wire.objects(&[0, 1, 2, 3, 4]);
    let stream = wire.subgroup_stream(&objects);
    let expected_header = wire.subgroup_header();

    let (header, header_len) = decode_subgroup_header(wire, &stream);
    assert_eq!(
        header_len,
        expected_header.len(),
        "[{draft}] decode_stream must consume exactly the stream type field and header"
    );

    let decoded = read_all(&header, draft, &stream[header_len..]);
    assert_eq!(
        decoded.len(),
        objects.len(),
        "[{draft}] every object on the stream must be decoded"
    );
    assert_eq!(decoded, objects, "[{draft}] decoded objects differ from the bytes on the wire");

    let borrowed: Vec<&AnySubgroupObject> = decoded.iter().collect();
    let reencoded = write_all(&header, draft, &borrowed);
    assert_eq!(
        reencoded,
        &stream[header_len..],
        "[{draft}] re-encoding the decoded objects must reproduce the wire bytes"
    );
}

#[test]
fn subgroup_streams_are_byte_identical_after_a_decode_and_re_encode() {
    for draft in enabled_drafts() {
        assert_byte_identity(&Wire::new(draft, false));
    }
}

#[test]
fn subgroup_streams_with_extensions_are_byte_identical() {
    for draft in enabled_drafts() {
        // Draft-07 objects have no extension block to carry them.
        if draft == DraftVersion::Draft07 {
            continue;
        }
        assert_byte_identity(&Wire::new(draft, true));
    }
}

/// A zero-length object encodes a status code in place of its payload. The
/// reader must report the code and an empty payload, and must not confuse
/// the two.
#[test]
fn status_objects_round_trip_byte_identically() {
    for draft in enabled_drafts() {
        let wire = Wire::new(draft, false);
        let block = wire.subgroup_ext_block();

        let mut objects = wire.objects(&[0, 1, 2]);
        objects[1] = AnySubgroupObject {
            object_id: 1,
            extension_headers: Vec::new(),
            extension_count: wire.ext_count(block, &[]),
            status: Some(STATUS_END_OF_GROUP),
            payload: Vec::new(),
        };

        let stream = wire.subgroup_stream(&objects);
        let (header, header_len) = decode_subgroup_header(&wire, &stream);
        let decoded = read_all(&header, draft, &stream[header_len..]);

        assert_eq!(decoded, objects, "[{draft}] status object decoded incorrectly");
        assert_eq!(
            decoded[1].status,
            Some(STATUS_END_OF_GROUP),
            "[{draft}] the status code must survive decoding"
        );
        assert!(decoded[1].payload.is_empty(), "[{draft}] a status object carries no payload");

        let borrowed: Vec<&AnySubgroupObject> = decoded.iter().collect();
        assert_eq!(
            write_all(&header, draft, &borrowed),
            &stream[header_len..],
            "[{draft}] status object re-encode is not byte-identical"
        );
    }
}

/// Drafts 07-13 encode a standalone object *header* and the payload follows
/// it; the reader must advance past that payload. The proxy's old parser
/// advanced by the header length alone, which made every object after the
/// first decode from the middle of its predecessor's payload.
///
/// A multi-byte payload is what exposes it: with one-byte payloads a reader
/// that skipped the payload would still land plausibly.
#[test]
fn readers_consume_object_payloads() {
    for draft in enabled_drafts() {
        let wire = Wire::new(draft, false);
        let block = wire.subgroup_ext_block();
        let objects: Vec<AnySubgroupObject> = (0..3u64)
            .map(|object_id| AnySubgroupObject {
                object_id,
                extension_headers: Vec::new(),
                extension_count: wire.ext_count(block, &[]),
                status: None,
                // Long enough that a reader which failed to skip it would
                // resynchronize on payload bytes, not on the next object.
                payload: vec![0x5A; 40],
            })
            .collect();

        let stream = wire.subgroup_stream(&objects);
        let (header, header_len) = decode_subgroup_header(&wire, &stream);

        let mut reader = AnySubgroupObjectReader::new(&header)
            .unwrap_or_else(|e| panic!("[{draft}] reader construction failed: {e}"));
        let mut cursor: &[u8] = &stream[header_len..];
        for expected in &objects {
            let object = reader
                .read_object(&mut cursor)
                .unwrap_or_else(|e| panic!("[{draft}] object decode failed: {e}"));
            assert_eq!(&object, expected, "[{draft}] object decoded from the wrong offset");
        }
        assert!(
            !cursor.has_remaining(),
            "[{draft}] the reader left {} bytes unconsumed — it did not advance past the payloads",
            cursor.remaining()
        );
    }
}

// ============================================================
// 2. Delta elide
// ============================================================

/// Read a five-object stream, write back every object but `dropped`, and
/// require the result to equal an independently written stream of exactly
/// the retained IDs.
///
/// Asserting on *bytes* rather than on decoded IDs is the point. A writer
/// that re-used each object's original delta, or that used the wrong bias
/// (`prev + delta` instead of `prev + delta + 1` — the drafts 15/16 bug
/// named in the module header), still round-trips through its own reader
/// and would satisfy an ID-level check.
/// Only the wire bytes distinguish them.
///
/// Concretely on drafts 14-20, with IDs 0,1,2,3,4 every delta field is
/// `0x00`. Eliding the middle object must turn object 3's field into
/// `0x01`; eliding the first must turn object 1's field from a relative
/// `0x00` into an absolute `0x01`.
fn assert_elide(wire: &Wire, dropped: usize, retained_ids: &[u64]) {
    let draft = wire.draft;
    let all_ids = [0u64, 1, 2, 3, 4];

    let objects = wire.objects(&all_ids);
    let stream = wire.subgroup_stream(&objects);
    let (header, header_len) = decode_subgroup_header(wire, &stream);
    let decoded = read_all(&header, draft, &stream[header_len..]);

    let retained: Vec<&AnySubgroupObject> =
        decoded.iter().enumerate().filter(|(i, _)| *i != dropped).map(|(_, o)| o).collect();
    let produced = write_all(&header, draft, &retained);

    let expected = wire.subgroup_objects(&wire.objects(retained_ids));
    assert_eq!(
        produced, expected,
        "[{draft}] eliding index {dropped} produced the wrong wire bytes"
    );

    // And the produced bytes must genuinely decode to the retained IDs —
    // byte equality against a stream this file also wrote would not catch
    // a shared misunderstanding of the delta rule.
    let redecoded = read_all(&header, draft, &produced);
    assert_eq!(
        redecoded.iter().map(|o| o.object_id).collect::<Vec<_>>(),
        retained_ids,
        "[{draft}] the elided stream decodes to the wrong Object IDs"
    );
}

#[test]
fn eliding_a_middle_object_renumbers_its_successor() {
    for draft in enabled_drafts() {
        assert_elide(&Wire::new(draft, false), 2, &[0, 1, 3, 4]);
        if draft != DraftVersion::Draft07 {
            assert_elide(&Wire::new(draft, true), 2, &[0, 1, 3, 4]);
        }
    }
}

/// The first object's field is absolute, every later one relative, so
/// dropping the first forces its successor to change *kind*, not just
/// value. This is where an implementation that patches deltas arithmetically
/// instead of re-encoding goes wrong.
#[test]
fn eliding_the_first_object_makes_its_successor_absolute() {
    for draft in enabled_drafts() {
        assert_elide(&Wire::new(draft, false), 0, &[1, 2, 3, 4]);
        if draft != DraftVersion::Draft07 {
            assert_elide(&Wire::new(draft, true), 0, &[1, 2, 3, 4]);
        }
    }
}

/// Dropping the last object has no successor to renumber; the retained
/// bytes must be untouched.
#[test]
fn eliding_the_last_object_leaves_the_rest_untouched() {
    for draft in enabled_drafts() {
        assert_elide(&Wire::new(draft, false), 4, &[0, 1, 2, 3]);
    }
}

/// Eliding two adjacent objects must accumulate both gaps into the
/// survivor's delta rather than applying a single correction.
#[test]
fn eliding_two_adjacent_objects_accumulates_the_gap() {
    for draft in enabled_drafts() {
        let wire = Wire::new(draft, false);
        let objects = wire.objects(&[0, 1, 2, 3, 4]);
        let stream = wire.subgroup_stream(&objects);
        let (header, header_len) = decode_subgroup_header(&wire, &stream);
        let decoded = read_all(&header, draft, &stream[header_len..]);

        // Keep 0 and 3, 4 — objects 1 and 2 are elided together.
        let retained: Vec<&AnySubgroupObject> = decoded
            .iter()
            .enumerate()
            .filter(|(i, _)| ![1, 2].contains(i))
            .map(|(_, o)| o)
            .collect();
        let produced = write_all(&header, draft, &retained);

        assert_eq!(
            produced,
            wire.subgroup_objects(&wire.objects(&[0, 3, 4])),
            "[{draft}] eliding two adjacent objects produced the wrong wire bytes"
        );
    }
}

/// A subgroup stream's object IDs strictly increase, so a repeat has no
/// representable delta and must be refused rather than silently encoded.
#[test]
fn writers_refuse_a_non_increasing_object_id() {
    for draft in enabled_drafts() {
        let wire = Wire::new(draft, false);
        // Only the delta-encoded drafts can detect this; absolute drafts
        // have a perfectly valid encoding for a repeated ID.
        if !wire.delta_encoded() {
            continue;
        }

        let stream = wire.subgroup_stream(&wire.objects(&[0]));
        let (header, _) = decode_subgroup_header(&wire, &stream);
        let objects = wire.objects(&[4]);

        let mut writer = AnySubgroupObjectWriter::new(&header)
            .unwrap_or_else(|e| panic!("[{draft}] writer construction failed: {e}"));
        let mut out = Vec::new();
        writer
            .write_object(&objects[0], &mut out)
            .unwrap_or_else(|e| panic!("[{draft}] first write failed: {e}"));
        assert_eq!(
            writer.write_object(&objects[0], &mut out),
            Err(CodecError::InvalidField),
            "[{draft}] a repeated Object ID must be refused"
        );
    }
}

// ============================================================
// 3. Fetch streams
// ============================================================

/// Fetch objects carry their own group, subgroup and object IDs. Decode an
/// independently written fetch stream and require every field back, and the
/// whole stream consumed.
#[test]
fn fetch_streams_round_trip_on_every_draft_that_defines_them() {
    for draft in drafts_with_fetch_objects() {
        for extensions in [false, true] {
            // Draft-07 fetch objects have no extension block.
            if extensions && draft == DraftVersion::Draft07 {
                continue;
            }
            let wire = Wire::new(draft, extensions);
            let objects = wire.fetch_object_values();

            let mut stream = wire.fetch_header();
            let header_len = stream.len();
            stream.extend_from_slice(&wire.fetch_objects(&objects));

            let mut cursor: &[u8] = &stream;
            let header = AnyFetchHeader::decode_stream(draft, &mut cursor)
                .unwrap_or_else(|e| panic!("[{draft}] fetch header decode failed: {e}"));
            assert_eq!(
                stream.len() - cursor.remaining(),
                header_len,
                "[{draft}] fetch decode_stream must consume the type field and header"
            );

            let mut reader = AnyFetchObjectReader::new(&header, AnyFetchGroupOrder::Ascending)
                .unwrap_or_else(|e| panic!("[{draft}] fetch reader construction failed: {e}"));
            let mut decoded = Vec::new();
            while cursor.has_remaining() {
                decoded.push(
                    reader
                        .read_object(&mut cursor)
                        .unwrap_or_else(|e| panic!("[{draft}] fetch object decode failed: {e}")),
                );
            }

            assert_eq!(
                decoded, objects,
                "[{draft}] ext={extensions} decoded fetch objects differ from the wire"
            );
            assert!(
                !cursor.has_remaining(),
                "[{draft}] the fetch reader did not consume the whole stream"
            );
        }
    }
}

/// `read_object_meta` must be interchangeable with `read_object`: same
/// bytes consumed, same framing reported. The proxy forwards payload bytes
/// verbatim and only ever calls the meta form, so a divergence here would
/// desynchronize the framer while the codec's own tests stayed green.
#[test]
fn fetch_object_meta_agrees_with_the_full_read() {
    for draft in drafts_with_fetch_objects() {
        let wire = Wire::new(draft, false);
        let objects = wire.fetch_object_values();

        let mut stream = wire.fetch_header();
        stream.extend_from_slice(&wire.fetch_objects(&objects));

        let mut cursor: &[u8] = &stream;
        let header = AnyFetchHeader::decode_stream(draft, &mut cursor)
            .unwrap_or_else(|e| panic!("[{draft}] fetch header decode failed: {e}"));

        let mut reader = AnyFetchObjectReader::new(&header, AnyFetchGroupOrder::Ascending)
            .unwrap_or_else(|e| panic!("[{draft}] fetch reader construction failed: {e}"));
        let mut meta_reader = AnyFetchObjectReader::new(&header, AnyFetchGroupOrder::Ascending)
            .unwrap_or_else(|e| panic!("[{draft}] fetch reader construction failed: {e}"));
        let mut meta_cursor: &[u8] = cursor;

        for expected in &objects {
            let before = cursor.remaining();
            let object = reader
                .read_object(&mut cursor)
                .unwrap_or_else(|e| panic!("[{draft}] fetch object decode failed: {e}"));
            let consumed = before - cursor.remaining();

            let meta_before = meta_cursor.remaining();
            let meta = meta_reader
                .read_object_meta(&mut meta_cursor)
                .unwrap_or_else(|e| panic!("[{draft}] fetch meta decode failed: {e}"));

            assert_eq!(
                meta_before - meta_cursor.remaining(),
                consumed,
                "[{draft}] read_object_meta consumed a different byte count"
            );
            assert_eq!(meta.wire_len as usize, consumed, "[{draft}] wire_len mismatch");
            assert_eq!(meta.group_id, expected.group_id, "[{draft}] meta group_id");
            assert_eq!(meta.subgroup_id, expected.subgroup_id, "[{draft}] meta subgroup_id");
            assert_eq!(meta.object_id, expected.object_id, "[{draft}] meta object_id");
            assert_eq!(
                meta.publisher_priority, expected.publisher_priority,
                "[{draft}] meta publisher_priority"
            );
            assert_eq!(meta.status, object.status, "[{draft}] meta status");
            assert_eq!(
                meta.payload_length as usize,
                object.payload.len(),
                "[{draft}] meta payload_length"
            );
        }
    }
}

/// A fetch stream on drafts 15-20 must yield its objects — identities *and*
/// payload bytes — not merely a header that decodes.
///
/// The stream is deliberately written in the implicit forms the Serialization
/// Flags layout exists for: the second object states no field at all and the
/// third states only a new group, so every Group ID, Subgroup ID, Object ID and
/// Priority below the first object is one the reader had to resolve against the
/// object before it. A reader that dropped its running state, or resolved a
/// field against the wrong predecessor, cannot produce these values.
///
/// Payloads are checked because a fetch object's framing and its bytes are read
/// by different code: every one of these drafts leaves the payload in the buffer
/// after the header, and the dispatch layer is what copies it out. Getting the
/// framing right and the payload boundary wrong desynchronizes the stream from
/// the second object onwards, which an identity-only assertion would let
/// through on a single-object stream.
///
/// Ablated twice against the draft-19 glue in `src/data_dispatch.rs`. Skipping
/// the payload instead of copying it — `conv::skip` in place of `conv::take`
/// in `fo19::read_object` — gives
///
/// ```text
/// assertion `left == right` failed: [draft-19] each object's payload must be the bytes framed under its own length
///   left: [[], [], []]
///  right: [[160], [161], [160]]
/// ```
///
/// and dropping the `+ 1` from the Ascending Group ID arithmetic in
/// `fo19::State::resolve` gives
///
/// ```text
/// assertion `left == right` failed: [draft-19] fetch group/subgroup/object/priority must resolve to absolute values
///   left: [(7, 0, 0, 128), (7, 0, 1, 128), (7, 0, 0, 128)]
///  right: [(7, 0, 0, 128), (7, 0, 1, 128), (8, 0, 0, 128)]
/// ```
#[test]
fn fetch_streams_yield_their_objects_end_to_end_on_drafts_15_to_19() {
    for draft in drafts_with_fetch_serialization_flags() {
        let wire = Wire::new(draft, false);
        let mut stream = wire.fetch_header();
        // Two objects in one group then one in the next: the case that
        // distinguishes a delta encoding from an absolute one.
        let objects = wire.fetch_objects(&wire.fetch_object_values());

        // Pin the bytes, because a hand-written encoder that shared the
        // codec's misunderstanding would round-trip perfectly and prove
        // nothing. These are the shapes the shipped corpus uses:
        // `fetch-stream-two-objects` is `1c 00 00 80 04 deadbeef 00 02 cafe`
        // on every draft 15-20, the same first-then-implicit pair as the first
        // two objects here; and `fetch-stream-cross-group-delta` on drafts
        // 18-20 opens its second group with `0c 00 00`, a Group ID Delta of
        // zero meaning "the next group", where drafts 15-17 name the group
        // outright.
        let third = match draft {
            DraftVersion::Draft15 => &[0x0c, 0x08, 0x00, 0x00, 0x03][..],
            DraftVersion::Draft16 | DraftVersion::Draft17 => &[0x0c, 0x08, 0x00, 0x01, 0xA0][..],
            _ => &[0x0c, 0x00, 0x00, 0x01, 0xA0][..],
        };
        let mut expected_bytes = vec![0x1c, 0x07, 0x00, 0x80, 0x01, 0xA0, 0x00, 0x01, 0xA1];
        expected_bytes.extend_from_slice(third);
        assert_eq!(objects, expected_bytes, "[{draft}] the fetch stream under test");

        stream.extend_from_slice(&objects);

        let mut cursor: &[u8] = &stream;
        let header = AnyFetchHeader::decode_stream(draft, &mut cursor)
            .unwrap_or_else(|e| panic!("[{draft}] fetch header decode failed: {e}"));
        let mut reader = AnyFetchObjectReader::new(&header, AnyFetchGroupOrder::Ascending)
            .unwrap_or_else(|e| panic!("[{draft}] fetch reader construction failed: {e}"));
        assert_eq!(reader.draft(), draft, "[{draft}] the reader must report its own draft");

        let mut decoded = Vec::new();
        while cursor.has_remaining() {
            decoded.push(
                reader
                    .read_object(&mut cursor)
                    .unwrap_or_else(|e| panic!("[{draft}] fetch object decode failed: {e}")),
            );
        }
        assert_eq!(decoded.len(), 3, "[{draft}] every object on the stream must be read");

        assert_eq!(
            decoded
                .iter()
                .map(|o| (o.group_id, o.subgroup_id, o.object_id, o.publisher_priority))
                .collect::<Vec<_>>(),
            vec![(7, 0, 0, 128), (7, 0, 1, 128), (8, 0, 0, 128)],
            "[{draft}] fetch group/subgroup/object/priority must resolve to absolute values"
        );
        assert_eq!(
            decoded.iter().map(|o| o.payload.clone()).collect::<Vec<_>>(),
            vec![vec![0xA0], vec![0xA1], wire.fetch_object_values()[2].payload.clone()],
            "[{draft}] each object's payload must be the bytes framed under its own length"
        );
        assert!(
            decoded.iter().all(|o| o.end_of_range.is_none() && o.has_subgroup_id),
            "[{draft}] none of these frames is an end-of-range indicator or a datagram object"
        );
        assert!(!cursor.has_remaining(), "[{draft}] the fetch reader did not consume the stream");
    }
}

/// The same stream read through `read_object_meta`, which the proxy uses when
/// it forwards payload bytes verbatim.
///
/// [`fetch_object_meta_agrees_with_the_full_read`] already sweeps every draft,
/// but only for values the full read also produced. This pins the one thing
/// that is specific to drafts 15-20: the meta path advances the *same*
/// prior-object state, so the identities it reports for the second and third
/// objects are resolved and not merely copied off the wire.
///
/// Ablated by handing the draft-19 arm of `AnyFetchObjectReader::read_object_meta`
/// a fresh `fo19::State` per call instead of the reader's own:
///
/// ```text
/// [draft-19] fetch meta decode failed: invalid field value
/// ```
///
/// The second object states no field at all, so a reader with no memory of the
/// first has nothing to resolve it against and refuses rather than guessing —
/// which is why the failure is an error and not a wrong identity.
#[test]
fn fetch_object_meta_resolves_prior_object_fields_on_drafts_15_to_19() {
    for draft in drafts_with_fetch_serialization_flags() {
        let wire = Wire::new(draft, false);
        let objects = wire.fetch_object_values();
        let mut stream = wire.fetch_header();
        stream.extend_from_slice(&wire.fetch_objects(&objects));

        let mut cursor: &[u8] = &stream;
        let header = AnyFetchHeader::decode_stream(draft, &mut cursor)
            .unwrap_or_else(|e| panic!("[{draft}] fetch header decode failed: {e}"));
        let mut reader = AnyFetchObjectReader::new(&header, AnyFetchGroupOrder::Ascending)
            .unwrap_or_else(|e| panic!("[{draft}] fetch reader construction failed: {e}"));

        let mut seen = Vec::new();
        while cursor.has_remaining() {
            let meta = reader
                .read_object_meta(&mut cursor)
                .unwrap_or_else(|e| panic!("[{draft}] fetch meta decode failed: {e}"));
            seen.push((meta.group_id, meta.object_id, meta.payload_length));
        }
        assert_eq!(
            seen,
            vec![
                (7, 0, objects[0].payload.len() as u64),
                (7, 1, objects[1].payload.len() as u64),
                (8, 0, objects[2].payload.len() as u64),
            ],
            "[{draft}] read_object_meta must resolve identities and skip exactly the payload"
        );
        assert!(!cursor.has_remaining(), "[{draft}] the meta reader did not consume the stream");
    }
}

/// A fetch stream's first object may not take a field from an object before
/// it, because there is none.
///
/// Every draft 15-20 answers that with a session close: "If the first Object in
/// the FETCH response uses a flag that references fields in the prior Object,
/// the Subscriber MUST close the session with a PROTOCOL_VIOLATION". The
/// dispatch layer's job is to report it rather than invent a zero — a reader
/// that defaulted the missing Group ID to 0 would decode this stream happily
/// and place every later object in the wrong group.
///
/// Ablated against `fo19::State::resolve` in `src/data_dispatch.rs`. Replacing
/// the two "no prior object" refusals with zeros — the Group ID arm's
/// `(None, None)` and the Object ID arm's `(None, _, _)` — was **not** enough:
/// the test still passed, because this object also inherits its Priority and
/// that arm refused independently. Only after the Priority arm was also
/// defaulted did the gate fail:
///
/// ```text
/// assertion `left == right` failed: [draft-19] a first fetch object inheriting from nothing must be refused
///   left: Ok(AnyFetchObject { group_id: 0, subgroup_id: 0, has_subgroup_id: true, object_id: 0, publisher_priority: 128, extension_headers: [], extension_count: None, status: None, end_of_range: None, payload: [160] })
///  right: Err(InvalidField)
/// ```
///
/// That three separate refusals stand behind one flags value is the point: a
/// stream whose first object states nothing is refused for each field it
/// cannot produce, so weakening any one of them alone leaves the rule standing.
#[test]
fn a_first_fetch_object_that_references_a_prior_object_is_refused_on_drafts_15_to_19() {
    for draft in drafts_with_fetch_serialization_flags() {
        let wire = Wire::new(draft, false);
        let mut stream = wire.fetch_header();
        // Serialization Flags 0x00: no Group ID, no Object ID, no Priority —
        // every one of them "the prior Object's", on a stream that has none.
        stream.extend_from_slice(&[0x00, 0x01, 0xA0]);

        let mut cursor: &[u8] = &stream;
        let header = AnyFetchHeader::decode_stream(draft, &mut cursor)
            .unwrap_or_else(|e| panic!("[{draft}] fetch header decode failed: {e}"));
        let mut reader = AnyFetchObjectReader::new(&header, AnyFetchGroupOrder::Ascending)
            .unwrap_or_else(|e| panic!("[{draft}] fetch reader construction failed: {e}"));

        assert_eq!(
            reader.read_object(&mut cursor),
            Err(CodecError::InvalidField),
            "[{draft}] a first fetch object inheriting from nothing must be refused"
        );
    }
}

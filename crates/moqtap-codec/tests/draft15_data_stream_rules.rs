#![cfg(feature = "draft15")]
//! Draft-15 data-stream rules that no vector in the shipped corpus pins down.
//!
//! Two of them:
//!
//! # The fetch object's Serialization Flags
//!
//! Draft-15 Section 10.4.4 replaced the self-describing fetch object of the
//! drafts before it with one whose leading Serialization Flags byte says which
//! fields are on the wire; the rest are taken from the object before it on the
//! stream. Tables 7 and 8 of that section assign the bits. The corpus exercises
//! four flag bytes — 0x00, 0x04, 0x1c, 0x1f, 0x3c — and several distinct
//! readings of the byte agree on all of them, so the vectors alone cannot say
//! which reading is right. The gates below are built from the tables instead,
//! and pick shapes the corpus has no vector for: a Subgroup ID mode whose
//! answer differs from the prior object's, a first object that inherits from an
//! object that does not exist, and the two bits the table reserves.
//!
//! # Which objects may carry a payload
//!
//! Section 10.2.1.1: "Any object with a status code other than zero MUST have
//! an empty payload." Applying that to a raw wire code means first deciding
//! what the code means, and the codes the draft leaves unassigned have no
//! meaning to decide — so they get no payload rule either, rather than
//! inheriting non-zero-therefore-forbidden.

use bytes::Buf;

use moqtap_codec::draft15::data_stream::{
    FetchHeader, FetchObjectHeader, FetchObjectReader, PayloadPermission, SubgroupHeader,
    SubgroupIdEncoding, SubgroupObjectReader,
};
use moqtap_codec::draft15::types::ObjectStatus;
use moqtap_codec::error::CodecError;
use moqtap_codec::varint::VarInt;

fn hex(s: &str) -> Vec<u8> {
    hex::decode(s.replace(' ', "")).expect("test hex")
}

fn vi(v: u64) -> VarInt {
    VarInt::from_u64(v).expect("value fits a varint")
}

// ── Fetch object fixtures ──────────────────────────────────

/// Every field a fetch object can state, so a test can name one shape and let
/// the flags decide which parts of it reach the wire.
#[derive(Debug, Clone)]
struct FetchObject {
    flags: u8,
    group_id: u64,
    subgroup_id: u64,
    object_id: u64,
    priority: u8,
    extensions: Vec<u8>,
    payload: Vec<u8>,
    status: Option<u64>,
}

impl FetchObject {
    /// A fully explicit object: every field on the wire, so it is legal as the
    /// first object of a stream.
    fn explicit(group_id: u64, subgroup_id: u64, object_id: u64, priority: u8) -> Self {
        Self {
            flags: 0x1f,
            group_id,
            subgroup_id,
            object_id,
            priority,
            extensions: Vec::new(),
            payload: vec![0xaa],
            status: None,
        }
    }

    fn flags(mut self, flags: u8) -> Self {
        self.flags = flags;
        self
    }

    fn payload(mut self, payload: &[u8]) -> Self {
        self.payload = payload.to_vec();
        self
    }

    /// Serialize exactly the fields `self.flags` announces, in the order of
    /// Section 10.4.4, Figure 30.
    fn bytes(&self) -> Vec<u8> {
        let mut buf = vec![self.flags];
        if self.flags & 0x08 != 0 {
            vi(self.group_id).encode(&mut buf);
        }
        if self.flags & 0x03 == 0x03 {
            vi(self.subgroup_id).encode(&mut buf);
        }
        if self.flags & 0x04 != 0 {
            vi(self.object_id).encode(&mut buf);
        }
        if self.flags & 0x10 != 0 {
            buf.push(self.priority);
        }
        if self.flags & 0x20 != 0 {
            vi(self.extensions.len() as u64).encode(&mut buf);
            buf.extend_from_slice(&self.extensions);
        }
        vi(self.payload.len() as u64).encode(&mut buf);
        if self.payload.is_empty() {
            vi(self.status.unwrap_or(0)).encode(&mut buf);
        } else {
            buf.extend_from_slice(&self.payload);
        }
        buf
    }
}

/// A whole fetch stream: the `0x05` header for request 4, then the objects.
fn fetch_stream(objects: &[FetchObject]) -> Vec<u8> {
    let mut buf = hex("0504");
    for object in objects {
        buf.extend_from_slice(&object.bytes());
    }
    buf
}

/// One object as decoded from a fetch stream: its framing, and the payload
/// bytes the framing declared.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DecodedFetchObject {
    header: FetchObjectHeader,
    payload: Vec<u8>,
}

/// Decode a fetch stream's header and then every object on it.
fn decode_fetch_stream(bytes: &[u8]) -> Result<Vec<DecodedFetchObject>, CodecError> {
    let mut cursor = bytes;
    FetchHeader::decode(&mut cursor)?;
    let mut reader = FetchObjectReader::new();
    let mut objects = Vec::new();
    while cursor.has_remaining() {
        let header = reader.read_object_header(&mut cursor)?;
        let payload_length = header.payload_length.into_inner() as usize;
        if cursor.remaining() < payload_length {
            return Err(CodecError::UnexpectedEnd);
        }
        let payload = cursor[..payload_length].to_vec();
        cursor.advance(payload_length);
        objects.push(DecodedFetchObject { header, payload });
    }
    Ok(objects)
}

/// Re-encode a decoded fetch stream: the header, then every object's framing
/// and payload.
fn encode_fetch_stream(objects: &[DecodedFetchObject]) -> Result<Vec<u8>, CodecError> {
    let mut buf = Vec::new();
    FetchHeader { request_id: vi(4) }.encode(&mut buf);
    let mut writer = FetchObjectReader::new();
    for object in objects {
        writer.write_object_header(&object.header, &mut buf)?;
        buf.extend_from_slice(&object.payload);
    }
    Ok(buf)
}

// ── Serialization flags: the Subgroup ID mode ──────────────

/// The low two bits of the Serialization Flags are one four-valued field, and
/// each of its values resolves the Subgroup ID differently.
///
/// The stream below gives the same Subgroup ID four different answers — 7 for
/// the explicit field, 7 again for the mode meaning the prior object's, 8 for
/// the mode meaning the prior object's plus one, and 0 for the mode meaning
/// zero — with no Subgroup ID field on the wire
/// after the first object. A reading that treats 0x02 as a standalone
/// "Subgroup ID present" bit, or that carries the previous Subgroup ID forward
/// whenever no field appears, gets three of the four wrong.
///
/// Observed by making `SubgroupIdEncoding::from_flags` answer `SameAsPrior` for
/// the `Zero` pattern, which fails this with:
///
/// ```text
/// assertion `left == right` failed: resolved subgroup ids
///   left: [7, 7, 8, 8]
///  right: [7, 7, 8, 0]
/// ```
#[test]
fn the_subgroup_id_mode_is_a_two_bit_field_not_two_flags() {
    let stream = fetch_stream(&[
        FetchObject::explicit(0, 7, 0, 0x80).flags(0x1f).payload(&[0xaa]),
        // 0x15: Subgroup ID mode 0x01 (the prior object's), Object ID present,
        // Group ID and Priority inherited.
        FetchObject::explicit(0, 7, 1, 0x80).flags(0x15).payload(&[0xbb]),
        // 0x16: Subgroup ID mode 0x02 (the prior object's plus one).
        FetchObject::explicit(0, 8, 2, 0x80).flags(0x16).payload(&[0xcc]),
        // 0x14: Subgroup ID mode 0x00 (zero), whatever the prior object's was.
        FetchObject::explicit(0, 0, 3, 0x80).flags(0x14).payload(&[0xdd]),
    ]);

    let objects = decode_fetch_stream(&stream).expect("stream decodes");
    let subgroups: Vec<u64> = objects.iter().map(|o| o.header.subgroup_id.into_inner()).collect();
    assert_eq!(subgroups, vec![7, 7, 8, 0], "resolved subgroup ids");

    let encodings: Vec<SubgroupIdEncoding> =
        objects.iter().map(|o| o.header.subgroup_id_encoding()).collect();
    assert_eq!(
        encodings,
        vec![
            SubgroupIdEncoding::Present,
            SubgroupIdEncoding::SameAsPrior,
            SubgroupIdEncoding::PriorPlusOne,
            SubgroupIdEncoding::Zero,
        ],
        "modes read out of the flag bytes"
    );

    assert_eq!(encode_fetch_stream(&objects).expect("re-encodes"), stream, "re-encoded stream");
}

/// Every field the flags omit comes from the object before it on the stream,
/// and the Object ID counts up by one rather than repeating.
///
/// The second object here states nothing at all: flags 0x00 leaves the Group
/// ID and Priority to be inherited, the Object ID to be the prior one's plus
/// one, and the Subgroup ID to be zero.
///
/// Observed by making the reader inherit the prior Object ID unchanged instead
/// of adding one, which fails this with:
///
/// ```text
/// assertion `left == right` failed: the second object states no field of its own
///   left: FetchObjectHeader { serialization_flags: 0, group_id: VarInt(9), subgroup_id: VarInt(0), object_id: VarInt(4), publisher_priority: 200, extension_headers: [], payload_length: VarInt(2), object_status: None }
///  right: FetchObjectHeader { serialization_flags: 0, group_id: VarInt(9), subgroup_id: VarInt(0), object_id: VarInt(5), publisher_priority: 200, extension_headers: [], payload_length: VarInt(2), object_status: None }
/// ```
#[test]
fn a_fetch_object_inherits_every_field_its_flags_omit() {
    let stream = fetch_stream(&[
        FetchObject::explicit(9, 0, 4, 200).payload(&[0xaa]),
        FetchObject::explicit(9, 0, 5, 200).flags(0x00).payload(&[0xbb, 0xcc]),
    ]);

    let objects = decode_fetch_stream(&stream).expect("stream decodes");
    assert_eq!(objects.len(), 2);
    assert_eq!(
        objects[1].header,
        FetchObjectHeader {
            serialization_flags: 0x00,
            group_id: vi(9),
            subgroup_id: vi(0),
            object_id: vi(5),
            publisher_priority: 200,
            extension_headers: Vec::new(),
            payload_length: vi(2),
            object_status: None,
        },
        "the second object states no field of its own"
    );
    assert_eq!(objects[1].payload, vec![0xbb, 0xcc]);
    assert_eq!(encode_fetch_stream(&objects).expect("re-encodes"), stream, "re-encoded stream");
}

/// The first object on a fetch stream may not inherit, because there is
/// nothing to inherit from.
///
/// Draft-15 Section 10.4.4: "If the first Object in the FETCH response uses a
/// flag that references fields in the prior Object, the Subscriber MUST close
/// the session with a PROTOCOL_VIOLATION." Four flags reference the prior
/// object — two of the Subgroup ID modes, and the cleared state of the Object
/// ID, Group ID and Priority bits — so of the sixty-four flag bytes the tables
/// assign, exactly four are legal on a first object. The same sixty-four are
/// swept again behind a legal first object, where all of them are.
///
/// Observed by having the reader fall back to a zeroed prior object instead of
/// refusing, which fails this with:
///
/// ```text
/// assertion `left == right` failed: flags 0x0 on a first object: Ok([DecodedFetchObject { header: FetchObjectHeader { serialization_flags: 0, group_id: VarInt(0), subgroup_id: VarInt(0), object_id: VarInt(1), publisher_priority: 0, extension_headers: [], payload_length: VarInt(1), object_status: None }, payload: [170] }])
///   left: true
///  right: false
/// ```
#[test]
fn the_first_fetch_object_may_not_reference_a_prior_one() {
    let mut legal_first = Vec::new();
    for flags in 0x00u8..=0x3f {
        let object = FetchObject::explicit(3, 0, 6, 0x40).flags(flags);
        let self_contained = flags & 0x1c == 0x1c && matches!(flags & 0x03, 0x00 | 0x03);

        let first = decode_fetch_stream(&fetch_stream(std::slice::from_ref(&object)));
        assert_eq!(first.is_ok(), self_contained, "flags {flags:#x} on a first object: {first:?}");
        if self_contained {
            legal_first.push(flags);
        }

        // Behind an object that does exist, every one of them parses.
        let after =
            decode_fetch_stream(&fetch_stream(&[FetchObject::explicit(3, 0, 6, 0x40), object]));
        assert!(after.is_ok(), "flags {flags:#x} behind a first object: {after:?}");
    }
    assert_eq!(legal_first, vec![0x1c, 0x1f, 0x3c, 0x3f], "flag bytes legal on a first object");
}

/// The two Serialization Flags bits draft-15 leaves unassigned are a protocol
/// violation, and the field is one byte rather than a varint.
///
/// Section 10.4.4 writes the field as "Serialization Flags (8)" and Table 8
/// gives 0x40 and 0x80 the meaning "PROTOCOL_VIOLATION" when set. The two
/// readings only part on those values, because 0x40 and 0x80 are also the
/// two- and four-byte varint prefixes: a varint reader consumes the bytes
/// after them as part of the flags and resumes on the wrong field boundary.
///
/// The last two cases are built so that the wrong reading succeeds rather than
/// running out of bytes — `40 1c` is the two-byte varint for 28, and
/// `80 00 00 1c` the four-byte one, so a varint reader sees the perfectly legal
/// flag byte 0x1c and parses the rest of the object cleanly. Without them the
/// sweep passes under either reading, since a misparsed object usually runs
/// past the end of the buffer and fails for that reason instead.
///
/// Observed by decoding the flags with `VarInt::decode` instead of `get_u8`,
/// which fails this with:
///
/// ```text
/// assertion failed: 0x40 disguised as the two-byte varint for 0x1c: expected a refusal, got Ok([DecodedFetchObject { header: FetchObjectHeader { serialization_flags: 28, group_id: VarInt(0), subgroup_id: VarInt(0), object_id: VarInt(0), publisher_priority: 128, extension_headers: [], payload_length: VarInt(1), object_status: None }, payload: [170] }])
/// ```
#[test]
fn the_unassigned_serialization_flag_bits_are_refused() {
    for flags in 0x40u8..=0xff {
        // A body carrying every field, so nothing but the reserved bits can be
        // what the reader objects to.
        let mut bytes = hex("0504");
        bytes.push(flags);
        bytes.extend_from_slice(&hex("00 02 00 80 01 aa"));
        let decoded = decode_fetch_stream(&bytes);
        assert!(decoded.is_err(), "flags {flags:#x}: expected a refusal, got {decoded:?}");
    }

    for (what, bytes) in [
        ("0x40 disguised as the two-byte varint for 0x1c", hex("0504 401c 00 00 80 01 aa")),
        ("0x80 disguised as the four-byte varint for 0x1c", hex("0504 8000001c 00 00 80 01 aa")),
    ] {
        let decoded = decode_fetch_stream(&bytes);
        assert!(decoded.is_err(), "{what}: expected a refusal, got {decoded:?}");
    }
}

// ── Fetch object framing ───────────────────────────────────

/// A fetch object states an Object Status exactly when its payload length is
/// zero, and only the codes draft-15 assigns.
///
/// Section 10.4.4: "The Object Status field is only present if the Object
/// Payload Length is zero." Section 10.2.1.1 assigns 0x0, 0x1, 0x3 and 0x4 and
/// says any other value should end the session. The sweep covers the whole
/// one-byte varint range, so it includes the gap inside the assigned set (0x2)
/// and the code a later draft added (0x5).
///
/// Observed by having the reader accept any status code rather than only the
/// assigned ones, which fails this with:
///
/// ```text
/// assertion `left == right` failed: status 0x2 on a fetch object: Ok([DecodedFetchObject { header: FetchObjectHeader { serialization_flags: 31, group_id: VarInt(1), subgroup_id: VarInt(0), object_id: VarInt(2), publisher_priority: 128, extension_headers: [], payload_length: VarInt(0), object_status: Some(Normal) }, payload: [] }])
///   left: true
///  right: false
/// ```
#[test]
fn a_fetch_object_states_a_status_only_where_it_has_no_payload() {
    for code in 0x00u64..=0x3f {
        let assigned = ObjectStatus::ALL.iter().any(|s| s.as_u64() == code);
        let mut object = FetchObject::explicit(1, 0, 2, 0x80);
        object.payload = Vec::new();
        object.status = Some(code);
        let stream = fetch_stream(&[object]);

        let decoded = decode_fetch_stream(&stream);
        assert_eq!(decoded.is_ok(), assigned, "status {code:#x} on a fetch object: {decoded:?}");

        if assigned {
            let objects = decoded.expect("assigned status decodes");
            assert_eq!(
                objects[0].header.object_status,
                ObjectStatus::from_u64(code),
                "status {code:#x} survives the decode"
            );
            assert_eq!(
                encode_fetch_stream(&objects).expect("re-encodes"),
                stream,
                "status {code:#x} re-encodes"
            );
        }
    }

    // A payload and a status field cannot both be present: with bytes under it,
    // the object states no status at all.
    let with_payload =
        decode_fetch_stream(&fetch_stream(&[FetchObject::explicit(1, 0, 2, 0x80)])).unwrap();
    assert_eq!(with_payload[0].header.object_status, None);
    assert_eq!(with_payload[0].payload, vec![0xaa]);
}

/// A fetch object's extensions block is the byte-length-prefixed blob of
/// Section 10.2.1.2, and it is present only when the flags say so.
///
/// Observed by having the reader return the block with its length prefix still
/// attached, which fails this with:
///
/// ```text
/// assertion `left == right` failed: the extensions blob excludes its length prefix
///   left: [2, 60, 1]
///  right: [60, 1]
/// ```
#[test]
fn a_fetch_object_carries_its_extensions_block_verbatim() {
    let mut object = FetchObject::explicit(0, 0, 0, 0x80).flags(0x3f);
    object.extensions = hex("3c01");
    let stream = fetch_stream(&[object]);

    let objects = decode_fetch_stream(&stream).expect("stream decodes");
    assert!(objects[0].header.has_extensions());
    assert_eq!(
        objects[0].header.extension_headers,
        hex("3c01"),
        "the extensions blob excludes its length prefix"
    );
    assert_eq!(encode_fetch_stream(&objects).expect("re-encodes"), stream, "re-encoded stream");

    // Without the bit, no block is on the wire and none is reported.
    let plain = decode_fetch_stream(&fetch_stream(&[FetchObject::explicit(0, 0, 0, 0x80)]))
        .expect("stream decodes");
    assert!(!plain[0].header.has_extensions());
    assert!(plain[0].header.extension_headers.is_empty());
}

/// Writing refuses every header whose fields disagree with its own flags,
/// before a byte reaches the buffer.
///
/// The flags decide what is written, so each disagreement below would reach the
/// peer as the value the flags imply — a different object, silently. The last
/// two are losses of a different shape: extension bytes with the extensions bit
/// clear would vanish, which Section 10.2.1.2 forbids a relay from doing, and a
/// non-zero status on an object with a payload is a pair Section 10.2.1.1 says
/// does not exist.
///
/// Observed by dropping the Subgroup ID checks from `write_object_header`,
/// which fails this with:
///
/// ```text
/// assertion failed: subgroup id 5 under the mode that means zero: expected a refusal, wrote [20, 1, 128, 1]
/// ```
#[test]
fn writing_refuses_a_fetch_header_its_flags_cannot_carry() {
    // The state every case below is written against: group 0, subgroup 7,
    // object 0, priority 0x80.
    let prior = FetchObject::explicit(0, 7, 0, 0x80);
    let template = FetchObjectHeader {
        serialization_flags: 0x1f,
        group_id: vi(0),
        subgroup_id: vi(7),
        object_id: vi(1),
        publisher_priority: 0x80,
        extension_headers: Vec::new(),
        payload_length: vi(1),
        object_status: None,
    };

    let mut disagreements: Vec<(&str, FetchObjectHeader)> = Vec::new();

    // Subgroup ID mode 0x00 means zero, so any other value is unwritable.
    let mut h = template.clone();
    h.serialization_flags = 0x14;
    h.subgroup_id = vi(5);
    disagreements.push(("subgroup id 5 under the mode that means zero", h));

    // Mode 0x01 means the prior object's, which is 7.
    let mut h = template.clone();
    h.serialization_flags = 0x15;
    h.subgroup_id = vi(5);
    disagreements.push(("subgroup id 5 under the mode that means the prior object's", h));

    // Mode 0x02 means the prior object's plus one, which is 8.
    let mut h = template.clone();
    h.serialization_flags = 0x16;
    h.subgroup_id = vi(7);
    disagreements.push(("subgroup id 7 under the mode that means the prior plus one", h));

    // Group ID omitted, so it must be the prior object's, which is 0.
    let mut h = template.clone();
    h.serialization_flags = 0x17;
    h.group_id = vi(3);
    disagreements.push(("group id 3 with the group id bit clear", h));

    // Object ID omitted, so it must be the prior object's plus one, which is 1.
    let mut h = template.clone();
    h.serialization_flags = 0x1b;
    h.object_id = vi(5);
    disagreements.push(("object id 5 with the object id bit clear", h));

    // Priority omitted, so it must be the prior object's, which is 0x80.
    let mut h = template.clone();
    h.serialization_flags = 0x0f;
    h.publisher_priority = 0x01;
    disagreements.push(("priority 0x01 with the priority bit clear", h));

    // Extension bytes with no bit to announce them.
    let mut h = template.clone();
    h.extension_headers = hex("3c01");
    disagreements.push(("extension bytes with the extensions bit clear", h));

    // A status the draft forbids alongside a payload.
    let mut h = template.clone();
    h.object_status = Some(ObjectStatus::EndOfGroup);
    disagreements.push(("End of Group status on an object with a payload", h));

    // A reserved flag bit.
    let mut h = template.clone();
    h.serialization_flags = 0x5f;
    disagreements.push(("a reserved flag bit", h));

    for (what, header) in disagreements {
        let mut writer = FetchObjectReader::new();
        let mut buf = Vec::new();
        writer.write_object_header(&prior_header(&prior), &mut buf).expect("prior object writes");
        buf.extend_from_slice(&prior.payload);
        let before = buf.len();

        let result = writer.write_object_header(&header, &mut buf);
        assert!(result.is_err(), "{what}: expected a refusal, wrote {:?}", &buf[before..]);
        assert_eq!(buf.len(), before, "{what}: a refused header wrote bytes");
    }
}

/// The fixture's header form, for the cases that need one written rather than
/// decoded.
fn prior_header(object: &FetchObject) -> FetchObjectHeader {
    FetchObjectHeader {
        serialization_flags: object.flags,
        group_id: vi(object.group_id),
        subgroup_id: vi(object.subgroup_id),
        object_id: vi(object.object_id),
        publisher_priority: object.priority,
        extension_headers: object.extensions.clone(),
        payload_length: vi(object.payload.len() as u64),
        object_status: object.status.and_then(ObjectStatus::from_u64),
    }
}

/// A fetch object reader is bound to one stream: restarting it resolves the
/// objects that follow onto whatever the stream's first object states.
///
/// Observed by making `FetchObjectReader::new` carry a zeroed prior object
/// rather than none, which fails this with:
///
/// ```text
/// assertion failed: a restarted reader accepted an inheriting object
/// ```
#[test]
fn a_restarted_fetch_reader_has_nothing_to_inherit_from() {
    let stream = fetch_stream(&[
        FetchObject::explicit(9, 0, 4, 200).payload(&[0xaa]),
        FetchObject::explicit(9, 0, 5, 200).flags(0x00).payload(&[0xbb]),
    ]);
    let mut cursor = &stream[..];
    FetchHeader::decode(&mut cursor).expect("stream header");

    let mut reader = FetchObjectReader::new();
    let first = reader.read_object_header(&mut cursor).expect("first object");
    cursor.advance(first.payload_length.into_inner() as usize);

    // The same bytes, read by a reader that has not seen the first object.
    let mut restarted = FetchObjectReader::new();
    assert!(
        restarted.read_object_header(&mut cursor.to_vec().as_slice()).is_err(),
        "a restarted reader accepted an inheriting object"
    );
    // The reader that did see it resolves the inherited fields.
    let second = reader.read_object_header(&mut cursor).expect("second object");
    assert_eq!(second.group_id.into_inner(), 9);
    assert_eq!(second.object_id.into_inner(), 5);
    assert_eq!(second.publisher_priority, 200);
}

// ── Payload permission ─────────────────────────────────────

/// Canonically encoded subgroup stream vectors from
/// `test-vectors/transport/draft15/codec/data-streams/subgroup.json`.
const SUBGROUP_VECTORS: &[&str] = &[
    "100100800004deadbeef",
    "100100800004deadbeef0002cafe",
    "3001000004deadbeef",
    "11010080000004deadbeef",
    "1101008000023c0104deadbeef",
    "100105800004deadbeef000003",
    "10010a800004deadbeef000004",
    "11010080000004deadbeef000002cafe",
    "1101008000023c0204deadbeef00023c0302cafe",
    "1101008000023c010003",
    "120105800004deadbeef",
];

/// Every object the shipped vectors carry agrees with its own payload
/// permission: the ones that hold bytes are permitted them, and the ones whose
/// permission is `Forbidden` hold none.
///
/// This is the rule of Section 10.2.1.1 — "Any object with a status code other
/// than zero MUST have an empty payload" — checked against the corpus rather
/// than restated. The corpus carries End of Group and End of Track objects, so
/// both halves have work to do.
///
/// Observed by making `PayloadPermission::for_status` answer `Permitted` for
/// End of Group, which fails this with:
///
/// ```text
/// assertion `left == right` failed: [100105800004deadbeef000003] object 1 permits a payload but the draft forbids it for status Some(3)
///   left: true
///  right: false
/// ```
#[test]
fn every_vector_object_agrees_with_its_payload_permission() {
    let mut forbidden_seen = 0;
    let mut permitted_seen = 0;
    for vector in SUBGROUP_VECTORS {
        let bytes = hex(vector);
        let mut cursor = &bytes[..];
        let header = SubgroupHeader::decode(&mut cursor).expect("subgroup header");
        let mut reader = SubgroupObjectReader::new(&header);
        let mut index = 0;
        while cursor.has_remaining() {
            let meta = reader.read_object_meta(&mut cursor).expect("object framing");
            let permission = meta
                .payload_permission()
                .unwrap_or_else(|| panic!("[{vector}] object {index}: no permission"));
            assert_eq!(
                permission.permits(),
                meta.payload_length > 0 || meta.status == Some(0),
                "[{vector}] object {index} permits a payload but the draft \
                 forbids it for status {:?}",
                meta.status
            );
            if permission.permits() {
                permitted_seen += 1;
            } else {
                assert_eq!(
                    meta.payload_length, 0,
                    "[{vector}] object {index} carries bytes under a forbidding status"
                );
                forbidden_seen += 1;
            }
            index += 1;
        }
    }
    assert!(permitted_seen > 0 && forbidden_seen > 0, "the corpus exercises both answers");
}

/// A status code draft-15 does not assign gets no payload permission, rather
/// than the one "non-zero" would imply.
///
/// The unassigned codes cannot arrive through
/// `SubgroupObjectReader::read_object_meta`, which refuses them; a meta
/// carrying one is a meta some caller built, and the accessor's answer for it
/// is that the draft has none. The two halves are checked together, so a
/// reader taught to accept an unassigned code would have to teach the accessor
/// an answer for it as well.
///
/// Observed by having `payload_permission` fall back to
/// `PayloadPermission::Forbidden` for an unrecognised code, which fails this
/// with:
///
/// ```text
/// assertion `left == right` failed: status 0x2 is unassigned, so it has no payload rule
///   left: Some(Forbidden)
///  right: None
/// ```
#[test]
fn an_unassigned_status_has_no_payload_permission() {
    let header = SubgroupHeader::decode(&mut &hex("100100800004deadbeef")[..]).expect("header");

    for code in 0x00u64..=0x3f {
        let assigned = ObjectStatus::from_u64(code);
        let meta = moqtap_codec::draft15::data_stream::SubgroupObjectMeta {
            object_id: 0,
            extension_headers_len: 0,
            payload_length: 0,
            status: Some(code),
            wire_len: 3,
        };
        let expected = assigned.map(PayloadPermission::for_status);
        assert_eq!(
            meta.payload_permission(),
            expected,
            "status {code:#x} is {}, so it has {} payload rule",
            if assigned.is_some() { "assigned" } else { "unassigned" },
            if assigned.is_some() { "one" } else { "no" }
        );

        // The wire agrees: the codes with no permission are the codes no
        // object may carry.
        let mut body = vec![0x00, 0x00];
        vi(code).encode(&mut body);
        let read = SubgroupObjectReader::new(&header).read_object_meta(&mut &body[..]);
        assert_eq!(
            read.is_ok(),
            expected.is_some(),
            "status {code:#x}: the wire and the permission disagree"
        );
    }

    // An object with no status field at all is the Normal object every
    // non-zero-length object implicitly is.
    let carrying = moqtap_codec::draft15::data_stream::SubgroupObjectMeta {
        object_id: 0,
        extension_headers_len: 0,
        payload_length: 4,
        status: None,
        wire_len: 6,
    };
    assert_eq!(carrying.payload_permission(), Some(PayloadPermission::Permitted));
}

// ── Type-byte validation ───────────────────────────────────

/// Draft-15 Section 10 requires closing the session on a datagram type the
/// draft does not define, and Section 10.3.1 Table 5 defines twenty-four.
///
/// Sixty-four byte values used to decode: every value the low bits could name,
/// whether or not Table 5 assigned it. Field presence was then inferred from
/// bits carrying no meaning, so an undefined type produced a header that looked
/// well formed.
///
/// *Ablation:* delete the `datagram_type_is_assigned` call from
/// `DatagramHeader::decode`, and this fails with:
///
/// ```text
/// draft-15 accepted undefined datagram type 0x10: DatagramHeader { datagram_type: 16, track_alias: VarInt(1), group_id: VarInt(2), object_id: VarInt(3), publisher_priority: Some(128), extension_headers: [], object_status: None }
/// ```
#[test]
fn undefined_datagram_types_are_refused() {
    use moqtap_codec::draft15::data_stream::DatagramHeader;

    // Assigned: 0x00-0x0F, plus the status types that do not also end a group.
    let assigned: Vec<u8> =
        (0x00u8..=0x2F).filter(|ty| ty & 0xD0 == 0 && ty & 0x22 != 0x22).collect();
    assert_eq!(assigned.len(), 24, "Table 5 assigns twenty-four datagram types");

    for ty in 0x00u8..=0xFF {
        // Build exactly the fields this type byte announces, so a refusal is
        // about the type and never about a short buffer.
        let mut wire = vec![ty, 0x01, 0x02];
        if ty & 0x04 == 0 {
            wire.push(0x03);
        }
        if ty & 0x08 == 0 {
            wire.push(0x80);
        }
        if ty & 0x01 != 0 {
            // A non-empty block: Section 10.3.1 makes a length of 0 here a
            // session-closing offence, so writing one would make every
            // extensions-present type fail for a reason other than its type.
            wire.push(0x02);
            wire.extend_from_slice(&[0x10, 0x2a]);
        }
        if ty & 0x20 != 0 {
            wire.push(0x00);
        }
        let mut cursor = &wire[..];
        let decoded = DatagramHeader::decode(&mut cursor);
        if assigned.contains(&ty) {
            assert!(decoded.is_ok(), "draft-15 refused assigned datagram type {ty:#04x}");
        } else {
            assert!(
                decoded.is_err(),
                "draft-15 accepted undefined datagram type {ty:#04x}: {:?}",
                decoded.unwrap()
            );
        }
    }
}

/// A type varint outside one byte must be refused, not narrowed into one.
///
/// The decoder read the type with `VarInt::decode(..).into_inner() as u8`, so
/// `0x100` became `0x00` and a datagram this draft does not define was parsed
/// as an ordinary object rather than closing the session. The same held for
/// subgroup streams, where `0x110` became `0x10`.
///
/// *Ablation:* restore the `as u8` narrowing in either decoder, and this fails
/// with:
///
/// ```text
/// draft-15 narrowed datagram type 0x100 onto a valid one instead of refusing it
/// ```
#[test]
fn out_of_range_type_varints_do_not_alias_onto_valid_types() {
    use moqtap_codec::draft15::data_stream::{DatagramHeader, SubgroupHeader};

    // 0x100 as a two-byte varint, then the fields a 0x00 datagram would carry.
    let datagram = [0x41u8, 0x00, 0x01, 0x02, 0x03, 0x80];
    let mut cursor = &datagram[..];
    assert!(
        DatagramHeader::decode(&mut cursor).is_err(),
        "draft-15 narrowed datagram type 0x100 onto a valid one instead of refusing it"
    );

    // 0x110 as a two-byte varint, then the fields a 0x10 subgroup stream carries.
    let subgroup = [0x41u8, 0x10, 0x01, 0x00, 0x80];
    let mut cursor = &subgroup[..];
    assert!(
        SubgroupHeader::decode(&mut cursor).is_err(),
        "draft-15 narrowed subgroup stream type 0x110 onto a valid one instead of refusing it"
    );
}

/// Draft-15 Section 9: a control message whose declared Length does not match
/// the bytes its fields consume is a PROTOCOL_VIOLATION.
///
/// The over-long half is the one that reads as success. The declared length
/// keeps the outer stream in sync, so trailing bytes no field consumed were
/// dropped without a word — and a peer emitting a field this codec does not
/// know about looked exactly like a peer sending nothing extra.
///
/// *Ablation:* remove the `payload.has_remaining()` check from
/// `ControlMessage::decode`, and this fails with:
///
/// ```text
/// draft-15 accepted an UNSUBSCRIBE with 3 trailing bytes inside its declared length: Unsubscribe(Unsubscribe { request_id: VarInt(7) })
/// ```
#[test]
fn a_control_message_longer_than_its_fields_is_refused() {
    use moqtap_codec::draft15::message::ControlMessage;

    // UNSUBSCRIBE(7): type 0x0a, length 1, request id 7 — and the same message
    // with its length widened to cover three bytes nothing reads.
    let clean = [0x0au8, 0x00, 0x01, 0x07];
    let mut cursor = &clean[..];
    ControlMessage::decode(&mut cursor).expect("the clean message must still decode");

    let padded = [0x0au8, 0x00, 0x04, 0x07, 0xAA, 0xBB, 0xCC];
    let mut cursor = &padded[..];
    let decoded = ControlMessage::decode(&mut cursor);
    assert!(
        decoded.is_err(),
        "draft-15 accepted an UNSUBSCRIBE with 3 trailing bytes inside its declared length: {:?}",
        decoded.unwrap()
    );
}

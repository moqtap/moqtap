//! Object Status: on drafts 15 through 20, the encode path can put a code on
//! the wire exactly when the decode path accepts that code.
//!
//! The asymmetry this gates against is a real one: every draft's decoder
//! refuses a status code the draft does not assign (draft-17 Section 10.2.1.1
//! says an unassigned status SHOULD be treated as a protocol error and the
//! session closed with PROTOCOL_VIOLATION), while the encoders once wrote
//! whatever raw code they were handed. A peer could therefore emit, from this
//! codec, bytes this codec would itself reject on the way back in.
//!
//! # The shapes covered
//!
//! Drafts 15-20 carry an Object Status in exactly three places, and all three
//! are here:
//!
//! - the subgroup object (`SubgroupObject`), written by
//!   `SubgroupObjectReader::write_object` and read by `read_object`;
//! - the subgroup object's metadata (`SubgroupObjectMeta`), read by
//!   `read_object_meta` — the payload-skipping view of the same bytes;
//! - the datagram header (`DatagramHeader`), written by `encode` and read by
//!   `decode`.
//!
//! There is no fourth. Drafts 07-14 also have fetch objects with a status of
//! their own (`FetchObject`, `FetchObjectHeader`), but drafts 15-20 have no
//! such type at all — searching those six modules for `ObjectStatus` finds
//! only the two typed fields above plus the raw code on the metadata — so a
//! fetch row here would gate nothing.
//!
//! The metadata shape has no encoder of its own: it is a decode-only view of
//! the bytes `write_object` produced. Its half of the symmetry is therefore
//! that it accepts exactly the same codes as `read_object` does, which is what
//! the sweep below requires of it. Without that, a relay that forwards objects
//! through `read_object_meta` could pass along a code the same draft's
//! `read_object` would have refused.
//!
//! # Nothing here restates the assigned set
//!
//! Every expectation is derived from the draft's own data: `ObjectStatus::ALL`
//! for what the encoder can name, and `ObjectStatus::from_u64` for what the
//! decoder claims to accept. The two are cross-checked against each other over
//! the whole sweep before either is used, so neither can drift alone. A literal
//! table of codes written into this file would stop gating the day a draft
//! reassigns one — it would just go on asserting the old set, in agreement with
//! nothing.
//!
//! The sets really do differ across this range: draft-15 assigns `0x1` (Object
//! Does Not Exist) and drafts 16-20 do not. So the same sweep body requires
//! `0x1` to be accepted on draft-15 and refused on draft-16.
//!
//! # How the wire is reached
//!
//! Each row pins one fixture: the bytes that precede the status field for that
//! shape. The encoder's own output must begin with those bytes — that is
//! asserted, so a stale fixture cannot silently pass — and whatever follows
//! them is the status field, read back as a raw number rather than as a typed
//! status. That is what makes "the code the encoder put on the wire" an
//! observation rather than a restatement of the value handed in.
//!
//! # The sweep
//!
//! Every code `0x00..=0xff`, plus values no single byte can hold: `0x100`,
//! `0x3fff`, `0x4000`, `0xffff`, `2^32`, RFC 9000's varint ceiling of `2^62-1`
//! and `u64::MAX`. The subgroup status field is a varint on all six drafts and
//! the datagram status field is a varint on drafts 15-16, so those shapes are
//! swept over the wide values too; the drafts 17-20 datagram status is a single
//! octet, which cannot express them, and those codes are skipped there rather
//! than pretended about.
//!
//! Drafts 15 and 16 frame the status with the RFC 9000 Section 16 varint,
//! draft-17 with the MoQT varint of draft-17 Section 1.4.1, and drafts 18-20
//! with the revision of it that restored the 7-byte length.
//!
//! # What this gate catches, observed by making each change and running it
//!
//! Both halves of the fix are typed fields: `SubgroupObject::object_status` and
//! `DatagramHeader::object_status` hold an `ObjectStatus`, not a raw code, so
//! the encoders cannot be handed a code their own decoder would refuse. The two
//! draft groups reached that from different starting points — drafts 15-16 held
//! the datagram status as a varint, drafts 17-20 as a single byte — so both are
//! ablated below.
//!
//! Taking the check away on draft-16 — its datagram status put back to the raw
//! `Option<VarInt>` it used to be, written verbatim with `if let Some(s) =
//! &self.object_status { s.encode(buf) }` and read back into the raw field —
//! stops this gate compiling, which is the check being enforced at the earliest
//! possible moment:
//!
//! ```text
//! error[E0308]: mismatched types
//!    --> crates\moqtap-codec\tests\object_status_symmetry.rs:494:45
//!     |
//! 494 |                         object_status: Some(ObjectStatus::ALL[index]),
//!     |                                        ---- ^^^^^^^^^^^^^^^^^^^^^^^^ expected `VarInt`, found `ObjectStatus`
//!     |                                        |
//!     |                                        arguments to this enum variant are incorrect
//! ...
//! 554 | datagram_row!(varint_status draft16_datagram_status, "draft16", draft16, Some(0x80));
//!     | ------------------------------------------------------------------------------------ in this macro invocation
//! ```
//!
//! and the same on draft-18, whose datagram status was a bare `Option<u8>`
//! written with `buf.put_u8(self.object_status.unwrap_or(0))`:
//!
//! ```text
//! error[E0308]: mismatched types
//!    --> crates\moqtap-codec\tests\object_status_symmetry.rs:536:45
//!     |
//! 536 |                         object_status: Some(ObjectStatus::ALL[index]),
//!     |                                        ---- ^^^^^^^^^^^^^^^^^^^^^^^^ expected `u8`, found `ObjectStatus`
//!     |                                        |
//!     |                                        arguments to this enum variant are incorrect
//! ...
//! 556 | datagram_row!(byte_status draft18_datagram_status, "draft18", draft18);
//!     | ---------------------------------------------------------------------- in this macro invocation
//! ```
//!
//! A compile error says nothing about behaviour, though, so both groups were
//! ablated a second way that keeps the API shape and moves the defect onto the
//! wire: the encoder emitting `0x1`, the code draft-15 assigned to Object Does
//! Not Exist and draft-16 dropped, where it should emit End of Group. That is
//! what forwarding a status between drafts without checking it looks like.
//! Draft-16, whose datagram status is a varint:
//!
//! ```text
//! thread 'draft16_datagram_status' (47776) panicked at crates\moqtap-codec\tests\object_status_symmetry.rs:296:31:
//! draft16 datagram header: decode refused the encoder's own output for status 0x1: InvalidField
//!
//! test result: FAILED. 9 passed; 1 failed
//! ```
//!
//! and draft-18, whose datagram status is one octet:
//!
//! ```text
//! thread 'draft18_datagram_status' (26244) panicked at crates\moqtap-codec\tests\object_status_symmetry.rs:296:31:
//! draft18 datagram header: decode refused the encoder's own output for status 0x1: InvalidField
//!
//! test result: FAILED. 9 passed; 1 failed
//! ```
//!
//! The metadata shape is gated in its own right, not just as a passenger of the
//! object shape. Dropping the `decoded_status(code)?` from draft-15's
//! `read_object_meta`, so that the payload-skipping view accepts what the
//! full read refuses:
//!
//! ```text
//! thread 'draft15_subgroup_status' (18096) panicked at crates\moqtap-codec\tests\object_status_symmetry.rs:319:38:
//! draft15 subgroup object: read_object_meta accepted status 0x2 as Some(2), which the draft does not assign
//!
//! test result: FAILED. 9 passed; 1 failed
//! ```

#![cfg(any(
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20"
))]

use moqtap_codec::error::CodecError;
use moqtap_codec::varint::VarInt;

// ── The sweep ──────────────────────────────────────────────────

/// Codes past what one octet can hold, for the shapes whose status field is a
/// varint: the first two-byte value, the RFC 9000 one/two-byte boundary from
/// both sides, and the ceilings of both varint encodings.
const WIDE: &[u64] =
    &[0x100, 0x3fff, 0x4000, 0xffff, 1 << 32, moqtap_codec::varint::MAX_VARINT, u64::MAX];

/// Every code this file offers to an encoder and a decoder.
fn sweep() -> impl Iterator<Item = u64> {
    (0..=u64::from(u8::MAX)).chain(WIDE.iter().copied())
}

// ── Status field framing ───────────────────────────────────────

/// Frame `code` as an RFC 9000 Section 16 varint (drafts 15 and 16), or `None`
/// when that encoding cannot hold it: it stops at 2^62-1.
#[cfg(any(feature = "draft15", feature = "draft16"))]
fn put_rfc9000(code: u64) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    VarInt::from_u64(code).ok()?.encode(&mut out);
    Some(out)
}

/// Read an RFC 9000 varint back, requiring it to be the whole field.
#[cfg(any(feature = "draft15", feature = "draft16"))]
fn take_rfc9000(bytes: &[u8]) -> Option<u64> {
    let mut cursor = bytes;
    let value = VarInt::decode(&mut cursor).ok()?;
    cursor.is_empty().then(|| value.into_inner())
}

/// Frame `code` as the MoQT varint of draft-17 Section 1.4.1.
#[cfg(feature = "draft17")]
fn put_moqt17(code: u64) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    VarInt::from_u64_moqt(code).encode_moqt::<moqtap_codec::varint::Moqt17>(&mut out);
    Some(out)
}

#[cfg(feature = "draft17")]
fn take_moqt17(bytes: &[u8]) -> Option<u64> {
    let mut cursor = bytes;
    let value = VarInt::decode_moqt::<moqtap_codec::varint::Moqt17>(&mut cursor).ok()?;
    cursor.is_empty().then(|| value.into_inner())
}

/// Frame `code` as the MoQT varint as revised in draft-18, which restored the
/// 7-byte length.
#[cfg(any(feature = "draft18", feature = "draft19", feature = "draft20"))]
fn put_moqt18(code: u64) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    VarInt::from_u64_moqt(code).encode_moqt::<moqtap_codec::varint::Moqt18>(&mut out);
    Some(out)
}

#[cfg(any(feature = "draft18", feature = "draft19", feature = "draft20"))]
fn take_moqt18(bytes: &[u8]) -> Option<u64> {
    let mut cursor = bytes;
    let value = VarInt::decode_moqt::<moqtap_codec::varint::Moqt18>(&mut cursor).ok()?;
    cursor.is_empty().then(|| value.into_inner())
}

/// Frame `code` as the single octet the drafts 17-20 datagram status is, or
/// `None` for the codes an octet cannot express.
#[cfg(any(feature = "draft17", feature = "draft18", feature = "draft19", feature = "draft20"))]
fn put_byte(code: u64) -> Option<Vec<u8>> {
    (code <= u64::from(u8::MAX)).then(|| vec![code as u8])
}

#[cfg(any(feature = "draft17", feature = "draft18", feature = "draft19", feature = "draft20"))]
fn take_byte(bytes: &[u8]) -> Option<u64> {
    (bytes.len() == 1).then(|| u64::from(bytes[0]))
}

// ── The gate ───────────────────────────────────────────────────

/// A decode path: hands it whole-shape bytes, answers the status code it read,
/// or the error it refused them with.
type Decoder = Box<dyn Fn(&[u8]) -> Result<Option<u64>, CodecError>>;

/// One status-carrying shape of one draft, reduced to what the gate needs.
struct Shape {
    /// Names the row in every failure message, e.g. "draft-17 subgroup object".
    what: String,
    /// The bytes of this shape that precede its status field.
    prefix: Vec<u8>,
    /// Frame a raw code as this shape's status field, or `None` when the field
    /// cannot express it.
    put_code: fn(u64) -> Option<Vec<u8>>,
    /// Read this shape's status field back as a raw code.
    take_code: fn(&[u8]) -> Option<u64>,
    /// The codes the draft assigns, from its own `ObjectStatus::ALL`.
    assigned: Vec<u64>,
    /// Encode this shape carrying `ObjectStatus::ALL[index]`.
    encode_assigned: Box<dyn Fn(usize) -> Vec<u8>>,
    /// Every decode path this shape has.
    decoders: Vec<(&'static str, Decoder)>,
}

/// Require, for one shape, that the set of codes the encoder can put on the
/// wire is the set of codes every decode path accepts.
fn gate(shape: Shape) {
    let Shape { what, prefix, put_code, take_code, assigned, encode_assigned, decoders } = shape;

    assert!(!assigned.is_empty(), "{what}: the draft assigns no status, so nothing is gated");
    assert!(!decoders.is_empty(), "{what}: a shape with no decode path gates nothing");

    // What the encoder can put on the wire. Read off the encoded bytes rather
    // than taken from the value handed in, so a writer that accepts a status
    // and then writes a different code is visible.
    let mut emitted: Vec<u64> = Vec::new();
    for index in 0..assigned.len() {
        let bytes = encode_assigned(index);
        assert!(
            bytes.starts_with(&prefix),
            "{what}: the encoder produced {bytes:02x?}, which does not begin with this row's \
             fixture {prefix:02x?} -- the fixture no longer describes the shape"
        );
        let field = &bytes[prefix.len()..];
        let code = take_code(field).unwrap_or_else(|| {
            panic!("{what}: the status field the encoder wrote, {field:02x?}, is not readable")
        });

        // The encoder's own output has to be output every decode path takes,
        // and every path has to read back the code that is on the wire.
        for (path, decode) in &decoders {
            match decode(&bytes) {
                Ok(Some(read)) => assert_eq!(
                    read, code,
                    "{what}: {path} read status {read:#x} off bytes carrying {code:#x}"
                ),
                Ok(None) => panic!("{what}: {path} read no status at all from {bytes:02x?}"),
                Err(error) => panic!(
                    "{what}: {path} refused the encoder's own output for status \
                     {code:#x}: {error:?}"
                ),
            }
        }
        emitted.push(code);
    }

    let mut refused_any = false;
    for code in sweep() {
        let Some(field) = put_code(code) else { continue };
        let mut bytes = prefix.clone();
        bytes.extend_from_slice(&field);

        let is_assigned = assigned.contains(&code);
        refused_any |= !is_assigned;

        for (path, decode) in &decoders {
            match (is_assigned, decode(&bytes)) {
                (true, Err(error)) => panic!(
                    "{what}: {path} refused status {code:#x}, which the draft assigns: {error:?}"
                ),
                (false, Ok(read)) => panic!(
                    "{what}: {path} accepted status {code:#x} as {read:?}, which the draft \
                     does not assign"
                ),
                (true, Ok(read)) => assert_eq!(
                    read,
                    Some(code),
                    "{what}: {path} read back {read:?} from a status field carrying {code:#x}"
                ),
                (false, Err(_)) => {}
            }

            // The symmetry itself: a code reaches the wire from the encoder
            // exactly when the decoder takes it off the wire.
            assert_eq!(
                emitted.contains(&code),
                is_assigned,
                "{what}: {path} {} status {code:#x} -- {}",
                if is_assigned { "accepted" } else { "refused" },
                if is_assigned {
                    "ObjectStatus::ALL names it, but the encoder does not put it on the wire"
                } else {
                    "yet the encoder does put it on the wire"
                }
            );
        }
    }

    assert!(
        refused_any,
        "{what}: every code in the sweep is assigned, so this row never gated a refusal"
    );
}

/// Require the draft's two statements about its own assigned set — the enum's
/// `ALL` and its `from_u64` — to agree over the whole sweep, before either is
/// used as the expectation for the wire.
fn cross_check(draft: &str, assigned: &[u64], accepts: impl Fn(u64) -> bool) {
    for code in sweep() {
        assert_eq!(
            accepts(code),
            assigned.contains(&code),
            "{draft}: ObjectStatus::from_u64 and ObjectStatus::ALL disagree about {code:#x}"
        );
    }
}

// ── Fixtures ───────────────────────────────────────────────────

/// A subgroup stream header carrying no extension/property block, an explicit
/// subgroup ID and a publisher priority: track alias 1, group 0, subgroup 0,
/// priority 128. Type `0x14` names that stream on every draft from 12 on.
#[allow(dead_code)]
const SUBGROUP_HEADER: &[u8] = &[0x14, 0x01, 0x00, 0x00, 0x80];

/// A subgroup object up to its status field: object ID 0 (the first object's
/// delta is its absolute ID) and payload length 0, which is what puts a status
/// on the wire in place of a payload.
#[allow(dead_code)]
const SUBGROUP_OBJECT_PREFIX: &[u8] = &[0x00, 0x00];

/// A status datagram up to its status field: type `0x20` (STATUS set, no
/// property block, an explicit object ID, an explicit priority), track alias 1,
/// group 0, object 0, priority 128.
#[allow(dead_code)]
const DATAGRAM_PREFIX: &[u8] = &[0x20, 0x01, 0x00, 0x00, 0x80];

// ── Rows ───────────────────────────────────────────────────────

/// Generates one draft's subgroup rows: the object itself and its metadata
/// view, which share a fixture and an encoder and differ only in the decoder.
macro_rules! subgroup_row {
    ($name:ident, $feat:literal, $draft:ident, $put:ident, $take:ident) => {
        #[cfg(feature = $feat)]
        #[test]
        fn $name() {
            use moqtap_codec::$draft::data_stream::{
                SubgroupHeader, SubgroupObject, SubgroupObjectReader,
            };
            use moqtap_codec::$draft::types::ObjectStatus;

            fn header() -> SubgroupHeader {
                SubgroupHeader::decode(&mut &SUBGROUP_HEADER[..])
                    .expect("the subgroup header fixture must decode")
            }

            let assigned: Vec<u64> = ObjectStatus::ALL.iter().map(|s| s.as_u64()).collect();
            cross_check(stringify!($draft), &assigned, |code| {
                ObjectStatus::from_u64(code).is_some()
            });

            gate(Shape {
                what: format!("{} subgroup object", stringify!($draft)),
                prefix: SUBGROUP_OBJECT_PREFIX.to_vec(),
                put_code: $put,
                take_code: $take,
                assigned,
                encode_assigned: Box::new(|index| {
                    let mut out = Vec::new();
                    SubgroupObjectReader::new(&header())
                        .write_object(
                            &SubgroupObject {
                                object_id: VarInt::from_usize(0),
                                extension_headers: Vec::new(),
                                payload_length: VarInt::from_usize(0),
                                object_status: Some(ObjectStatus::ALL[index]),
                                payload: Vec::new(),
                            },
                            &mut out,
                        )
                        .expect("write_object must accept a status object");
                    out
                }),
                decoders: vec![
                    (
                        "read_object",
                        Box::new(|bytes: &[u8]| {
                            SubgroupObjectReader::new(&header())
                                .read_object(&mut &bytes[..])
                                .map(|object| object.object_status.map(|s| s.as_u64()))
                        }),
                    ),
                    (
                        "read_object_meta",
                        Box::new(|bytes: &[u8]| {
                            SubgroupObjectReader::new(&header())
                                .read_object_meta(&mut &bytes[..])
                                .map(|meta| meta.status)
                        }),
                    ),
                ],
            });
        }
    };
}

subgroup_row!(draft15_subgroup_status, "draft15", draft15, put_rfc9000, take_rfc9000);
subgroup_row!(draft16_subgroup_status, "draft16", draft16, put_rfc9000, take_rfc9000);
subgroup_row!(draft17_subgroup_status, "draft17", draft17, put_moqt17, take_moqt17);
subgroup_row!(draft18_subgroup_status, "draft18", draft18, put_moqt18, take_moqt18);
subgroup_row!(draft19_subgroup_status, "draft19", draft19, put_moqt18, take_moqt18);
subgroup_row!(draft20_subgroup_status, "draft20", draft20, put_moqt18, take_moqt18);

/// Generates one draft's datagram row. The leading keyword selects the header's
/// shape, which differs across the range: draft-15 always carries a publisher
/// priority and a property block, draft-16 made the priority optional, and
/// drafts 17-20 dropped the property field from the type and hold the status in
/// a single octet rather than a varint.
macro_rules! datagram_row {
    (varint_status $name:ident, $feat:literal, $draft:ident, $priority:expr) => {
        #[cfg(feature = $feat)]
        #[test]
        fn $name() {
            use moqtap_codec::$draft::data_stream::DatagramHeader;
            use moqtap_codec::$draft::types::ObjectStatus;

            let assigned: Vec<u64> = ObjectStatus::ALL.iter().map(|s| s.as_u64()).collect();
            cross_check(stringify!($draft), &assigned, |code| {
                ObjectStatus::from_u64(code).is_some()
            });

            gate(Shape {
                what: format!("{} datagram header", stringify!($draft)),
                prefix: DATAGRAM_PREFIX.to_vec(),
                put_code: put_rfc9000,
                take_code: take_rfc9000,
                assigned,
                encode_assigned: Box::new(|index| {
                    let mut out = Vec::new();
                    DatagramHeader {
                        datagram_type: 0x20,
                        track_alias: VarInt::from_usize(1),
                        group_id: VarInt::from_usize(0),
                        object_id: VarInt::from_usize(0),
                        publisher_priority: $priority,
                        extension_headers: Vec::new(),
                        object_status: Some(ObjectStatus::ALL[index]),
                    }
                    .encode(&mut out);
                    out
                }),
                decoders: vec![(
                    "decode",
                    Box::new(|bytes: &[u8]| {
                        DatagramHeader::decode(&mut &bytes[..])
                            .map(|header| header.object_status.map(|s| s.as_u64()))
                    }),
                )],
            });
        }
    };

    (byte_status $name:ident, $feat:literal, $draft:ident) => {
        #[cfg(feature = $feat)]
        #[test]
        fn $name() {
            use moqtap_codec::$draft::data_stream::DatagramHeader;
            use moqtap_codec::$draft::types::ObjectStatus;

            let assigned: Vec<u64> = ObjectStatus::ALL.iter().map(|s| s.as_u64()).collect();
            cross_check(stringify!($draft), &assigned, |code| {
                ObjectStatus::from_u64(code).is_some()
            });

            gate(Shape {
                what: format!("{} datagram header", stringify!($draft)),
                prefix: DATAGRAM_PREFIX.to_vec(),
                put_code: put_byte,
                take_code: take_byte,
                assigned,
                encode_assigned: Box::new(|index| {
                    let mut out = Vec::new();
                    DatagramHeader {
                        datagram_type: 0x20,
                        track_alias: VarInt::from_usize(1),
                        group_id: VarInt::from_usize(0),
                        object_id: VarInt::from_usize(0),
                        publisher_priority: Some(0x80),
                        // Type 0x20 leaves the PROPERTIES bit clear, so the
                        // block is absent from the fixture these rows decode
                        // and must be absent from what they encode.
                        properties: Vec::new(),
                        object_status: Some(ObjectStatus::ALL[index]),
                    }
                    .encode(&mut out);
                    out
                }),
                decoders: vec![(
                    "decode",
                    Box::new(|bytes: &[u8]| {
                        DatagramHeader::decode(&mut &bytes[..])
                            .map(|header| header.object_status.map(|s| s.as_u64()))
                    }),
                )],
            });
        }
    };
}

datagram_row!(varint_status draft15_datagram_status, "draft15", draft15, Some(0x80));
datagram_row!(varint_status draft16_datagram_status, "draft16", draft16, Some(0x80));
datagram_row!(byte_status draft17_datagram_status, "draft17", draft17);
datagram_row!(byte_status draft18_datagram_status, "draft18", draft18);
datagram_row!(byte_status draft19_datagram_status, "draft19", draft19);
datagram_row!(byte_status draft20_datagram_status, "draft20", draft20);

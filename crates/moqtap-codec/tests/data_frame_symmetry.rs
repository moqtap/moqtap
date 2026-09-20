//! Every data frame the encoder can build must decode back to the value it
//! was built from.
//!
//! # Why this exists alongside `object_status_symmetry.rs`
//!
//! That file sweeps the *status-code* axis: for one fixed frame shape it
//! walks every code the draft could put in the status field and checks the
//! encoder and the decoder agree about which ones exist. It pins the shape —
//! datagram type `0x20`, subgroup header `0x14` — precisely so the code is
//! the only thing that varies.
//!
//! This file sweeps the other axis. The status code is held fixed and the
//! *frame shape* varies: every combination of the flag bits a datagram type
//! byte carries, and every relationship a subgroup object's declared
//! `payload_length` can have with the payload it is handed. A frame the
//! encoder can build and its own decoder rejects is a defect whichever axis
//! it sits on, and neither sweep can see the other's.
//!
//! Not every combination names a frame. Drafts 15 and 17-20 declare eight of
//! their datagram type bytes invalid, and those are swept as refusals rather than
//! dropped: a shape left out of a sweep is a shape nobody tests, and the two
//! halves are checked to add back up to the power set.
//!
//! # What a round trip proves here
//!
//! Encoding is not a partial function of the type byte: a bit set in
//! `datagram_type` puts a field on the wire, and the decoder reads that field
//! back because the same bit is set. So encode-then-decode is the whole
//! contract, and the failure it catches is a field the decoder expects that
//! the encoder never wrote — which desynchronises everything after it and
//! usually surfaces as `UnexpectedEnd` rather than as a wrong value.
//!
//! Draft-15 and draft-16 are swept too, though they were never in doubt: they
//! carry an `extension_headers` field for the block their type byte's `0x01`
//! bit announces, and they are the control that says the sweep is capable of
//! passing.

#![allow(clippy::needless_range_loop)]
// Every row in this file is a draft-15-or-later one, so under a narrower
// feature set the rows compile away and leave the helpers below with no
// callers. Gating the file says that outright; leaving it ungated turns a
// single-draft build into a wall of dead-code errors about helpers that are
// not dead, only unreachable from the drafts that were selected.
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

/// Contents of the property / extension-header block written whenever a frame
/// shape says the block is present. Two bytes rather than none, so a shape
/// that writes the length prefix but drops the contents is caught as well as
/// one that writes neither.
const BLOCK: &[u8] = &[0xAA, 0xBB];

/// A subgroup stream header with an explicit subgroup ID, a publisher
/// priority and no property block. Type `0x14` names that stream on every
/// draft from 12 on, and this is the header the `payload_length` rows read
/// their objects against.
const SUBGROUP_HEADER: &[u8] = &[0x14, 0x01, 0x00, 0x00, 0x80];

/// Every datagram type byte a draft's flags can produce.
///
/// `flag_bits` are the bits that draft defines; the sweep is their whole
/// power set, so a shape is included exactly when the draft can name it. Bit 4
/// is never among them — `0x10`-`0x1D` are subgroup stream types, which is why
/// a datagram type byte always leaves it clear.
fn type_bytes(flag_bits: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for mask in 0..(1u32 << flag_bits.len()) {
        let mut ty = 0u8;
        for (i, bit) in flag_bits.iter().enumerate() {
            if mask & (1 << i) != 0 {
                ty |= bit;
            }
        }
        out.push(ty);
    }
    out
}

/// The flag bits drafts 15-20 give a datagram type byte: 0x01 properties,
/// 0x02 end of group, 0x04 zero object ID, 0x08 default priority, 0x20
/// status. One list, read by the round-trip row and the refusal row alike, so
/// the two sweep the same axis and their halves add back up to it.
///
/// Draft-15 is the draft that introduced the default-priority bit, so it is
/// the first with all five.
#[cfg(any(
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20"
))]
const DATAGRAM_FLAG_BITS: &[u8] = &[0x01, 0x02, 0x04, 0x08, 0x20];

/// Whether drafts 15-20 define the datagram type byte `ty`.
///
/// The same eight bytes are excluded on every draft here, but not for the same
/// stated reason, and the rows below assert different refusals because of it.
///
/// Drafts 16 through 19 name the eight outright — draft-16 and draft-17 in
/// Section 10.3.1, drafts 18 and 19 in Section 11.3.1, all under "The following
/// Type values are invalid. If an endpoint receives a datagram with any of
/// these Type values, it MUST close the session with a PROTOCOL_VIOLATION":
///
/// - "Type values with both the STATUS bit (0x20) and END_OF_GROUP bit (0x02)
///   set: 0x22, 0x23, 0x26, 0x27, 0x2A, 0x2B, 0x2E, 0x2F. An object status
///   message cannot signal end of group."
/// - "Type values that do not match the form 0b00X0XXXX (i.e., Type values
///   outside the ranges 0x00..0x0F and 0x20..0x2F)."
///
/// Draft-15 states neither list. Its Section 10.3.1 gives the field as a set of
/// ranges and stops there, so the eight are excluded by not appearing in the
/// table rather than by being named, and what answers them is Section 10's
/// unknown-type sentence instead.
///
/// The flag bits the sweeps use never leave the form, so the STATUS and
/// END_OF_GROUP pair is the only one of the two lists that can bite here, and
/// it is the only one this answers on. A byte outside the form is not a shape a
/// draft's flags can produce, so no row asks about one.
#[cfg(any(
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20"
))]
fn datagram_type_is_valid(ty: u8) -> bool {
    ty & 0x22 != 0x22
}

/// The half of `type_bytes(flag_bits)` drafts 15-20 define, in sweep order.
#[cfg(any(
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20"
))]
fn valid_type_bytes(flag_bits: &[u8]) -> Vec<u8> {
    type_bytes(flag_bits).into_iter().filter(|&ty| datagram_type_is_valid(ty)).collect()
}

/// The half of `type_bytes(flag_bits)` drafts 15-20 declare invalid, in sweep
/// order. Together with [`valid_type_bytes`] this is the whole power set, so
/// nothing the sweep could name goes unasked.
#[cfg(any(
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20"
))]
#[cfg(any(
    feature = "draft15",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20"
))]
fn invalid_type_bytes(flag_bits: &[u8]) -> Vec<u8> {
    type_bytes(flag_bits).into_iter().filter(|&ty| !datagram_type_is_valid(ty)).collect()
}

/// Generates one draft's datagram round-trip row.
///
/// The shapes differ in what the header struct holds, not in what is being
/// asserted: drafts 15 and 16 carry an optional publisher priority behind the
/// `0x08` bit, and drafts 17-20 renamed the extension headers to properties.
///
/// # What these rows catch
///
/// The asymmetry these catch is a header with no field for the property block
/// at all: a `decode` that reads a length-prefixed block whenever the type
/// byte sets `0x01` beside an `encode` that never writes one. Removing
/// `properties` from `draft17::data_stream::DatagramHeader` — leaving the
/// decoder's skip in place — was run and gives, on each of the three drafts:
///
/// ```text
/// draft17: datagram type 0x01 encodes to [01, 01, 02, 03, 80], which its own decoder refuses: VarInt(UnexpectedEnd)
/// draft18: datagram type 0x01 encodes to [01, 01, 02, 03, 80], which its own decoder refuses: VarInt(UnexpectedEnd)
/// draft19: datagram type 0x01 encodes to [01, 01, 02, 03, 80], which its own decoder refuses: VarInt(UnexpectedEnd)
/// ```
///
/// The draft-15 and draft-16 rows passed unchanged through that same run,
/// which is what makes them the control: they carry the field.
macro_rules! datagram_row {
    (ext_headers_fixed_priority $name:ident, $feat:literal, $draft:ident) => {
        #[cfg(feature = $feat)]
        #[test]
        fn $name() {
            use moqtap_codec::$draft::data_stream::DatagramHeader;
            use moqtap_codec::$draft::types::ObjectStatus;

            // 0x01 properties, 0x02 end of group, 0x04 zero object ID,
            // 0x20 status. This draft has no default-priority bit.
            for ty in type_bytes(&[0x01, 0x02, 0x04, 0x20]) {
                let header = DatagramHeader {
                    datagram_type: ty,
                    track_alias: VarInt::from_usize(1),
                    group_id: VarInt::from_usize(2),
                    object_id: VarInt::from_usize(if ty & 0x04 != 0 { 0 } else { 3 }),
                    publisher_priority: 0x80,
                    extension_headers: if ty & 0x01 != 0 { BLOCK.to_vec() } else { Vec::new() },
                    object_status: if ty & 0x20 != 0 {
                        Some(ObjectStatus::EndOfGroup)
                    } else {
                        None
                    },
                };
                round_trip(stringify!($draft), &header);
            }

            /// Encode `header`, decode the bytes back, and require the value
            /// and the byte count to survive.
            fn round_trip(draft: &str, header: &DatagramHeader) {
                let mut bytes = Vec::new();
                header.encode(&mut bytes);
                let mut cursor = &bytes[..];
                let back = DatagramHeader::decode(&mut cursor).unwrap_or_else(|e| {
                    panic!(
                        "{draft}: datagram type {:#04x} encodes to {bytes:02x?}, \
                         which its own decoder refuses: {e:?}",
                        header.datagram_type
                    )
                });
                assert_eq!(
                    cursor.len(),
                    0,
                    "{draft}: datagram type {:#04x} left {} byte(s) unread of {bytes:02x?}",
                    header.datagram_type,
                    cursor.len()
                );
                assert_eq!(
                    back.extension_headers, header.extension_headers,
                    "{draft}: datagram type {:#04x} lost its property block",
                    header.datagram_type
                );
                assert_eq!(
                    back.object_status, header.object_status,
                    "{draft}: datagram type {:#04x} lost its status",
                    header.datagram_type
                );
                assert_eq!(
                    (back.datagram_type, back.track_alias, back.group_id, back.object_id),
                    (header.datagram_type, header.track_alias, header.group_id, header.object_id),
                    "{draft}: datagram type {:#04x} lost a header field",
                    header.datagram_type
                );
            }
        }
    };

    (ext_headers $name:ident, $feat:literal, $draft:ident) => {
        #[cfg(feature = $feat)]
        #[test]
        fn $name() {
            use moqtap_codec::$draft::data_stream::DatagramHeader;
            use moqtap_codec::$draft::types::ObjectStatus;

            // 0x01 properties, 0x02 end of group, 0x04 zero object ID,
            // 0x08 default priority, 0x20 status. Only the assigned half: a
            // status datagram cannot also end a group, so the eight types
            // setting 0x20 and 0x02 together are swept by the refusal row.
            for ty in valid_type_bytes(DATAGRAM_FLAG_BITS) {
                let header = DatagramHeader {
                    datagram_type: ty,
                    track_alias: VarInt::from_usize(1),
                    group_id: VarInt::from_usize(2),
                    object_id: VarInt::from_usize(if ty & 0x04 != 0 { 0 } else { 3 }),
                    publisher_priority: if ty & 0x08 != 0 { None } else { Some(0x80) },
                    extension_headers: if ty & 0x01 != 0 { BLOCK.to_vec() } else { Vec::new() },
                    object_status: if ty & 0x20 != 0 {
                        Some(ObjectStatus::EndOfGroup)
                    } else {
                        None
                    },
                };
                let mut bytes = Vec::new();
                header.encode(&mut bytes);
                let mut cursor = &bytes[..];
                let back = DatagramHeader::decode(&mut cursor).unwrap_or_else(|e| {
                    panic!(
                        "{}: datagram type {ty:#04x} encodes to {bytes:02x?}, \
                         which its own decoder refuses: {e:?}",
                        stringify!($draft)
                    )
                });
                assert_eq!(
                    cursor.len(),
                    0,
                    "{}: datagram type {ty:#04x} left {} byte(s) unread of {bytes:02x?}",
                    stringify!($draft),
                    cursor.len()
                );
                assert_eq!(
                    back.extension_headers,
                    header.extension_headers,
                    "{}: datagram type {ty:#04x} lost its property block",
                    stringify!($draft)
                );
                assert_eq!(
                    back.object_status,
                    header.object_status,
                    "{}: datagram type {ty:#04x} lost its status",
                    stringify!($draft)
                );
                assert_eq!(
                    (back.datagram_type, back.track_alias, back.group_id, back.object_id),
                    (header.datagram_type, header.track_alias, header.group_id, header.object_id),
                    "{}: datagram type {ty:#04x} lost a header field",
                    stringify!($draft)
                );
            }
        }
    };

    (properties $name:ident, $feat:literal, $draft:ident) => {
        #[cfg(feature = $feat)]
        #[test]
        fn $name() {
            use moqtap_codec::$draft::data_stream::DatagramHeader;
            use moqtap_codec::$draft::types::ObjectStatus;

            // The shapes the draft defines. The eight the power set holds that
            // it does not are the refusal row's, and setting a status on one
            // here would be asking the encoder for bytes no receiver may read.
            for ty in valid_type_bytes(DATAGRAM_FLAG_BITS) {
                let header = DatagramHeader {
                    datagram_type: ty,
                    track_alias: VarInt::from_usize(1),
                    group_id: VarInt::from_usize(2),
                    object_id: VarInt::from_usize(if ty & 0x04 != 0 { 0 } else { 3 }),
                    publisher_priority: if ty & 0x08 != 0 { None } else { Some(0x80) },
                    properties: if ty & 0x01 != 0 { BLOCK.to_vec() } else { Vec::new() },
                    object_status: if ty & 0x20 != 0 {
                        Some(ObjectStatus::EndOfGroup)
                    } else {
                        None
                    },
                };
                let mut bytes = Vec::new();
                header.encode(&mut bytes);
                let mut cursor = &bytes[..];
                let back = DatagramHeader::decode(&mut cursor).unwrap_or_else(|e| {
                    panic!(
                        "{}: datagram type {ty:#04x} encodes to {bytes:02x?}, \
                         which its own decoder refuses: {e:?}",
                        stringify!($draft)
                    )
                });
                assert_eq!(
                    cursor.len(),
                    0,
                    "{}: datagram type {ty:#04x} left {} byte(s) unread of {bytes:02x?}",
                    stringify!($draft),
                    cursor.len()
                );
                assert_eq!(
                    back.properties,
                    header.properties,
                    "{}: datagram type {ty:#04x} lost its property block",
                    stringify!($draft)
                );
                assert_eq!(
                    back.object_status,
                    header.object_status,
                    "{}: datagram type {ty:#04x} lost its status",
                    stringify!($draft)
                );
                assert_eq!(
                    (back.datagram_type, back.track_alias, back.group_id, back.object_id),
                    (header.datagram_type, header.track_alias, header.group_id, header.object_id),
                    "{}: datagram type {ty:#04x} lost a header field",
                    stringify!($draft)
                );
            }
        }
    };
}

datagram_row!(ext_headers draft15_datagram_shapes, "draft15", draft15);
datagram_row!(ext_headers draft16_datagram_shapes, "draft16", draft16);
datagram_row!(properties draft17_datagram_shapes, "draft17", draft17);
datagram_row!(properties draft18_datagram_shapes, "draft18", draft18);
datagram_row!(properties draft19_datagram_shapes, "draft19", draft19);
datagram_row!(properties draft20_datagram_shapes, "draft20", draft20);

/// Generates one draft's refusal row: the other half of the power set the
/// round-trip row above sweeps.
///
/// A shape excluded from a sweep is a shape nobody tests, so the eight type
/// bytes drafts 17-20 declare invalid are swept here instead, and both ends
/// of the codec are asked about each:
///
/// - `encode_checked` must refuse it and leave the buffer untouched. A
///   half-written datagram is worse than none, because its first bytes are a
///   header a receiver would parse.
/// - `decode` must refuse the bytes the unchecked `encode` writes. That is
///   what reaches a receiver when a publisher elsewhere ignores the rule, and
///   the receiver's answer to it is to close the session, so the decoder has
///   to say the type is wrong rather than hand up a datagram.
///
/// Both halves have to hold. The encoder alone refusing would leave a
/// decoder that accepts what the draft says to reject; the decoder alone
/// refusing would leave an encoder that emits what its own peer must close
/// the session over.
///
/// # What these rows catch
///
/// Deleting the type check from `datagram_type_is_valid` — the condition on
/// the STATUS and END_OF_GROUP bits, not the form — was run and gives, on
/// each of the drafts with a refusal row:
///
/// ```text
/// draft17: datagram type 0x22 sets both STATUS and END_OF_GROUP and must be refused as a type the draft lists as invalid, got Ok(())
/// draft18: datagram type 0x22 sets both STATUS and END_OF_GROUP and must be refused as a type the draft lists as invalid, got Ok(())
/// draft19: datagram type 0x22 sets both STATUS and END_OF_GROUP and must be refused as a type the draft lists as invalid, got Ok(())
/// ```
/// # Why the expected refusal differs by draft
///
/// The eight bytes are the same on every row, but what the draft says about
/// them is not. Drafts 16 through 19 list them and call them invalid — "an
/// object status message cannot signal end of group" — so the refusal names
/// that rule. Draft-15 has no such list; the bytes are simply outside the set
/// its table assigns, and the refusal is the unknown-type rule instead. Both
/// end the session, and asserting one shape for both would let a draft answer
/// under a rule it does not state.
macro_rules! invalid_datagram_row {
    ($name:ident, $feat:literal, $draft:ident, $block:ident, $expected:pat, $label:literal) => {
        #[cfg(feature = $feat)]
        #[test]
        fn $name() {
            use moqtap_codec::$draft::data_stream::DatagramHeader;
            use moqtap_codec::$draft::types::ObjectStatus;

            let draft = stringify!($draft);
            let invalid = invalid_type_bytes(DATAGRAM_FLAG_BITS);
            assert_eq!(
                invalid,
                vec![0x22, 0x23, 0x26, 0x27, 0x2A, 0x2B, 0x2E, 0x2F],
                "{draft}: the excluded half must be the eight values the draft lists, so the \
                 round-trip row keeps every shape the draft does define"
            );

            for ty in invalid {
                // Every one of the eight sets the STATUS bit, so the status
                // field is the one the type byte asks for; the type itself is
                // the only thing wrong with this header.
                let header = DatagramHeader {
                    datagram_type: ty,
                    track_alias: VarInt::from_usize(1),
                    group_id: VarInt::from_usize(2),
                    object_id: VarInt::from_usize(if ty & 0x04 != 0 { 0 } else { 3 }),
                    publisher_priority: if ty & 0x08 != 0 { None } else { Some(0x80) },
                    $block: if ty & 0x01 != 0 { BLOCK.to_vec() } else { Vec::new() },
                    object_status: Some(ObjectStatus::Normal),
                };

                let mut bytes = Vec::new();
                let outcome = header.encode_checked(&mut bytes);
                assert!(
                    matches!(outcome, Err($expected)),
                    "{draft}: datagram type {ty:#04x} sets both STATUS and END_OF_GROUP and must \
                     be refused as {}, got {outcome:?}",
                    $label
                );
                assert!(
                    bytes.is_empty(),
                    "{draft}: datagram type {ty:#04x} was refused but still wrote {bytes:02x?}"
                );

                let mut wire = Vec::new();
                header.encode(&mut wire);
                let mut cursor = &wire[..];
                let back = DatagramHeader::decode(&mut cursor);
                assert!(
                    matches!(back, Err($expected)),
                    "{draft}: datagram type {ty:#04x} arriving as {wire:02x?} must be refused \
                     as {}, got {back:?}",
                    $label
                );
            }
        }
    };
}

invalid_datagram_row!(
    draft15_invalid_datagram_types,
    "draft15",
    draft15,
    extension_headers,
    CodecError::UnknownDatagramType(_),
    "an unknown datagram type"
);
invalid_datagram_row!(
    draft17_invalid_datagram_types,
    "draft17",
    draft17,
    properties,
    CodecError::InvalidTypeValue { .. },
    "a type the draft lists as invalid"
);
invalid_datagram_row!(
    draft18_invalid_datagram_types,
    "draft18",
    draft18,
    properties,
    CodecError::InvalidTypeValue { .. },
    "a type the draft lists as invalid"
);
invalid_datagram_row!(
    draft19_invalid_datagram_types,
    "draft19",
    draft19,
    properties,
    CodecError::InvalidTypeValue { .. },
    "a type the draft lists as invalid"
);
// Draft-20 accepts and refuses the same values, and names all three of its
// refusals — Section 11.3.1's bit-4, STATUS-with-END_OF_GROUP and
// unspecified-bit conditions cover every invalid byte between them, so nothing
// in the byte space is merely an unknown datagram type any more.
invalid_datagram_row!(
    draft20_invalid_datagram_types,
    "draft20",
    draft20,
    properties,
    CodecError::InvalidTypeValue { .. },
    "a type the draft lists as invalid"
);

/// Generates one draft's `payload_length` row.
///
/// A subgroup object declares its payload's length on the wire and then
/// writes the payload. Nothing in the type system ties the two together, so
/// the encoder has to: a declared length that disagrees with the payload it
/// was handed produces a frame the same reader cannot parse, and there is no
/// byte string the caller could append to make it parse — the declared length
/// is already on the wire.
///
/// A zero declared length is not the length of an empty payload here. It is
/// the marker that puts a status code on the wire in place of the payload
/// (draft-17 Section 10.2.1.1 and the same section on the neighbouring
/// drafts), so an object carrying payload bytes under a zero length is asking
/// for two incompatible framings at once and is refused as well.
///
/// # What these rows catch
///
/// `write_object` checks `payload_length` against the payload it was handed
/// rather than copying it to the wire as given. Removing that check was run
/// and gives, on every draft in the range:
///
/// ```text
/// draft15: a length with no payload behind it (declared 4, payload 0) must be refused with InvalidField, got Ok(())
/// draft16: a length with no payload behind it (declared 4, payload 0) must be refused with InvalidField, got Ok(())
/// draft17: a length with no payload behind it (declared 4, payload 0) must be refused with InvalidField, got Ok(())
/// draft18: a length with no payload behind it (declared 4, payload 0) must be refused with InvalidField, got Ok(())
/// draft19: a length with no payload behind it (declared 4, payload 0) must be refused with InvalidField, got Ok(())
/// ```
///
/// Those bytes are `[00, 04]` — a two-byte object announcing four bytes of
/// payload that are not there, which the same draft's `read_object` answers
/// `UnexpectedEnd` on.
macro_rules! payload_length_row {
    ($name:ident, $feat:literal, $draft:ident) => {
        #[cfg(feature = $feat)]
        #[test]
        fn $name() {
            use moqtap_codec::$draft::data_stream::{
                SubgroupHeader, SubgroupObject, SubgroupObjectReader,
            };

            let draft = stringify!($draft);
            let header =
                SubgroupHeader::decode(&mut &SUBGROUP_HEADER[..]).expect("subgroup header 0x14");

            let object = |declared: usize, payload: Vec<u8>| SubgroupObject {
                object_id: VarInt::from_usize(0),
                extension_headers: Vec::new(),
                payload_length: VarInt::from_usize(declared),
                object_status: None,
                payload,
            };

            // Agreeing lengths round-trip, including the empty payload whose
            // zero length is a status marker.
            for len in 0..=8usize {
                let payload: Vec<u8> = (0..len).map(|i| i as u8).collect();
                let mut bytes = Vec::new();
                SubgroupObjectReader::new(&header)
                    .write_object(&object(len, payload.clone()), &mut bytes)
                    .unwrap_or_else(|e| {
                        panic!("{draft}: refused a payload of {len} byte(s): {e:?}")
                    });
                let mut cursor = &bytes[..];
                let back = SubgroupObjectReader::new(&header)
                    .read_object(&mut cursor)
                    .unwrap_or_else(|e| {
                        panic!(
                            "{draft}: a payload of {len} byte(s) encodes to {bytes:02x?}, \
                             which its own reader refuses: {e:?}"
                        )
                    });
                assert_eq!(
                    back.payload, payload,
                    "{draft}: payload of {len} byte(s) came back changed"
                );
                assert_eq!(cursor.len(), 0, "{draft}: payload of {len} byte(s) left bytes unread");
            }

            // A declared length the payload does not have is refused, and
            // nothing reaches the buffer: a half-written object is worse than
            // no object, because the reader would go on to parse whatever
            // followed it as this object's payload.
            for (declared, payload_len, what) in [
                (4usize, 0usize, "a length with no payload behind it"),
                (4, 3, "a length longer than its payload"),
                (2, 3, "a length shorter than its payload"),
                (0, 3, "a payload under the zero length that marks a status"),
            ] {
                let payload: Vec<u8> = (0..payload_len).map(|i| i as u8).collect();
                let mut bytes = Vec::new();
                let outcome = SubgroupObjectReader::new(&header)
                    .write_object(&object(declared, payload), &mut bytes);
                assert!(
                    matches!(outcome, Err(CodecError::InvalidField)),
                    "{draft}: {what} (declared {declared}, payload {payload_len}) \
                     must be refused with InvalidField, got {outcome:?}"
                );
                assert!(
                    bytes.is_empty(),
                    "{draft}: {what} was refused but still wrote {bytes:02x?}"
                );
            }
        }
    };
}

payload_length_row!(draft15_payload_length, "draft15", draft15);
payload_length_row!(draft16_payload_length, "draft16", draft16);
payload_length_row!(draft17_payload_length, "draft17", draft17);
payload_length_row!(draft18_payload_length, "draft18", draft18);
payload_length_row!(draft19_payload_length, "draft19", draft19);
payload_length_row!(draft20_payload_length, "draft20", draft20);

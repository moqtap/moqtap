//! Draft-19 data-stream rules that are about the frame rather than its
//! contents: which Type values may appear at all, what the Object Status
//! registry says about a payload, and the fetch object layout draft-19
//! Section 11.4.4 introduced.
//!
//! # Why these live outside `data_stream.rs`
//!
//! The module's own `mod tests` sweeps status *codes* against a fixed frame.
//! These sweep the frame itself, across every one of the 256 values a Type
//! byte can hold, and they exercise the public API a consumer of the crate
//! actually reaches for. Keeping them here also keeps the two sweeps from
//! being read as one: a Type value the draft forbids is refused whatever
//! status the frame would have carried, and a status the draft does not
//! assign is refused whatever Type framed it.

#![cfg(feature = "draft19")]

use bytes::Buf;
use moqtap_codec::draft19::data_stream::{
    DatagramHeader, FetchEndOfRange, FetchObjectHeader, SubgroupHeader, SubgroupObject,
    SubgroupObjectMeta, SubgroupObjectReader, PADDING_DATAGRAM_TYPE, PADDING_STREAM_TYPE,
};
use moqtap_codec::draft19::types::{ObjectStatus, PayloadPermission};
use moqtap_codec::error::CodecError;
use moqtap_codec::varint::Moqt18 as Wire;
use moqtap_codec::varint::VarInt;

fn vi(v: u64) -> VarInt {
    VarInt::from_u64_moqt(v)
}

// ── Subgroup header Type values ───────────────────────────────

/// Track Alias written by [`subgroup_stream`], as a one-byte varint.
const TRACK_ALIAS: u8 = 7;
/// Group ID written by [`subgroup_stream`], as a one-byte varint.
const GROUP_ID: u8 = 9;
/// The explicit Subgroup ID written whenever the Type asks for one.
const SUBGROUP_ID: u8 = 42;
/// The Publisher Priority written whenever the Type does not suppress it.
const PRIORITY: u8 = 0x80;

/// Every subgroup header Type draft-19 Section 11.4.2 names as invalid
/// because its SUBGROUP_ID_MODE is the reserved `0b11`.
///
/// Transcribed from the section's own list rather than computed from the mask,
/// so a mask that drifted would still have to disagree with sixteen literal
/// numbers.
const RESERVED_MODE_TYPES: &[u8] = &[
    0x16, 0x17, 0x1E, 0x1F, 0x36, 0x37, 0x3E, 0x3F, 0x56, 0x57, 0x5E, 0x5F, 0x76, 0x77, 0x7E, 0x7F,
];

/// A subgroup stream header with `header_type` and nothing after it, laid out
/// as that Type says: an explicit Subgroup ID only under mode `0b10`, and a
/// Publisher Priority unless the DEFAULT_PRIORITY bit (0x20) suppresses it.
fn subgroup_stream(header_type: u8) -> Vec<u8> {
    let mut wire = vec![header_type, TRACK_ALIAS, GROUP_ID];
    if (header_type & 0x06) >> 1 == 0b10 {
        wire.push(SUBGROUP_ID);
    }
    if header_type & 0x20 == 0 {
        wire.push(PRIORITY);
    }
    wire
}

/// Whether draft-19 Section 11.4.2 permits `header_type`.
///
/// Restates the section's two conditions — the 0b0XX1XXXX form, and a
/// SUBGROUP_ID_MODE other than the reserved `0b11` — so the sweep holds its
/// own copy of the rule rather than asking the code under test.
fn subgroup_type_is_valid(header_type: u8) -> bool {
    let well_formed = header_type & 0x80 == 0 && header_type & 0x10 != 0;
    well_formed && (header_type & 0x06) >> 1 != 0b11
}

/// The decoder accepts exactly the subgroup header Types draft-19 assigns.
///
/// Sweeps all 256 values a Type byte can hold. Each is handed a body laid out
/// the way that Type describes, so a refusal is a judgement about the Type and
/// not about a truncated frame; an accepted header additionally has to consume
/// its whole body and report the fields it framed.
///
/// The reserved-mode list is checked twice over: once as part of the sweep,
/// and once against the sixteen literal values the draft prints, so a rule
/// that accidentally refused a whole range would not pass by refusing those
/// sixteen among the rest.
///
/// # What this catches, observed by making each change and running it
///
/// Deleting the `validate_subgroup_type(header_type)?` call from
/// `SubgroupHeader::decode`, leaving decoding to proceed as it did before:
///
/// ```text
/// type 0x00 was accepted; draft-19 Section 11.4.2 lists it as invalid
/// ```
///
/// Keeping the form check but dropping only the reserved-mode arm — the
/// behaviour this module had before, which read a mode-3 header as though it
/// carried no Subgroup ID field:
///
/// ```text
/// type 0x16 was accepted; draft-19 Section 11.4.2 lists it as invalid
/// ```
#[test]
fn subgroup_header_types_outside_the_drafts_lists_are_refused() {
    for header_type in 0u8..=0x7F {
        let wire = subgroup_stream(header_type);
        let mut cursor: &[u8] = &wire;
        let decoded = SubgroupHeader::decode(&mut cursor);

        if subgroup_type_is_valid(header_type) {
            let header = decoded.unwrap_or_else(|e| {
                panic!("type {header_type:#04x} is valid under draft-19 but was refused: {e:?}")
            });
            assert!(
                !cursor.has_remaining(),
                "type {header_type:#04x} left {} byte(s) of its own header unread",
                cursor.remaining()
            );
            assert_eq!(header.header_type, header_type);
            assert_eq!(header.track_alias.into_inner(), TRACK_ALIAS as u64);
            assert_eq!(header.group_id.into_inner(), GROUP_ID as u64);
            if header.subgroup_id_mode() == 2 {
                assert_eq!(
                    header.subgroup_id.into_inner(),
                    SUBGROUP_ID as u64,
                    "type {header_type:#04x} lost its explicit Subgroup ID"
                );
            }
        } else {
            match decoded {
                Ok(_) => panic!(
                    "type {header_type:#04x} was accepted; \
                     draft-19 Section 11.4.2 lists it as invalid"
                ),
                Err(error) => {
                    assert_refusal(header_type, &error, expected_subgroup_refusal(header_type))
                }
            }
        }
    }

    for &header_type in RESERVED_MODE_TYPES {
        assert!(
            !subgroup_type_is_valid(header_type),
            "{header_type:#04x} is on the draft's reserved-mode list but this sweep \
             treats it as valid"
        );
        assert!(
            SubgroupHeader::decode(&mut &subgroup_stream(header_type)[..]).is_err(),
            "reserved SUBGROUP_ID_MODE type {header_type:#04x} was accepted"
        );
    }
}

/// The checked encoder will not write a subgroup header its own decoder
/// refuses, and the unchecked one still will.
///
/// Both halves are asserted so that `encode_checked` cannot pass by becoming a
/// synonym for `encode`, and so that the raw encoder's documented willingness
/// to write anything stays true.
///
/// # What this catches, observed by making each change and running it
///
/// Replacing the body of `SubgroupHeader::encode_checked` with a call to
/// `encode` followed by `Ok(())`:
///
/// ```text
/// encode_checked wrote type 0x00, which decode refuses
/// ```
///
/// Dropping only the reserved-mode arm of `validate_subgroup_type`, which
/// takes the check out of both halves at once:
///
/// ```text
/// encode_checked wrote type 0x16, which decode refuses
/// ```
#[test]
fn the_checked_subgroup_encoder_refuses_a_type_the_decoder_refuses() {
    for header_type in 0u8..=0xFF {
        let header = SubgroupHeader {
            header_type,
            track_alias: vi(TRACK_ALIAS as u64),
            group_id: vi(GROUP_ID as u64),
            subgroup_id: vi(SUBGROUP_ID as u64),
            publisher_priority: Some(PRIORITY),
        };

        let mut checked = Vec::new();
        let result = header.encode_checked(&mut checked);

        if subgroup_type_is_valid(header_type) {
            result.unwrap_or_else(|e| panic!("valid type {header_type:#04x} was refused: {e:?}"));
            let mut cursor: &[u8] = &checked;
            SubgroupHeader::decode(&mut cursor).unwrap_or_else(|e| {
                panic!("encode_checked wrote type {header_type:#04x} that decode refuses: {e:?}")
            });
        } else {
            assert_refusal(
                header_type,
                &result.expect_err(&format!(
                    "encode_checked wrote type {header_type:#04x}, which decode refuses"
                )),
                expected_subgroup_refusal(header_type),
            );
            assert!(
                checked.is_empty(),
                "a refused type {header_type:#04x} still wrote {checked:02x?}"
            );

            // The unchecked encoder is documented as taking the Type byte as
            // the authority, and that is exactly what makes it lossy here.
            let mut raw = Vec::new();
            header.encode(&mut raw);
            assert_eq!(
                raw.first().copied(),
                Some(header_type),
                "the raw encoder is supposed to write the forbidden type; if it no longer \
                 does, this test is asserting the wrong thing"
            );
        }
    }
}

// ── Datagram Type values ──────────────────────────────────────

/// Every datagram Type draft-19 Section 11.3.1 names as invalid because it
/// sets both the STATUS bit and the END_OF_GROUP bit. Transcribed from the
/// section's list.
const STATUS_WITH_END_OF_GROUP_TYPES: &[u8] = &[0x22, 0x23, 0x26, 0x27, 0x2A, 0x2B, 0x2E, 0x2F];

/// The property block written whenever a datagram Type sets the PROPERTIES
/// bit. Non-empty on purpose: draft-19 Section 11.3.1 makes a datagram that
/// sets the bit and then declares a Properties Length of zero a
/// PROTOCOL_VIOLATION, so an empty block would be testing a frame the draft
/// forbids for an unrelated reason.
const PROPERTIES: &[u8] = &[0x3C, 0x02];

/// A datagram header with `datagram_type` and nothing after it, laid out the
/// way that Type describes.
fn datagram(datagram_type: u8) -> Vec<u8> {
    let mut wire = vec![datagram_type, TRACK_ALIAS, GROUP_ID];
    if datagram_type & 0x04 == 0 {
        wire.push(3); // Object ID
    }
    if datagram_type & 0x08 == 0 {
        wire.push(PRIORITY);
    }
    if datagram_type & 0x01 != 0 {
        wire.push(PROPERTIES.len() as u8);
        wire.extend_from_slice(PROPERTIES);
    }
    if datagram_type & 0x20 != 0 {
        wire.push(ObjectStatus::EndOfTrack.as_u8());
    }
    wire
}

/// Whether draft-19 Section 11.3.1 permits `datagram_type`: the 0b00X0XXXX
/// form, and not both STATUS and END_OF_GROUP.
fn datagram_type_is_valid(datagram_type: u8) -> bool {
    let well_formed = datagram_type & 0xD0 == 0;
    well_formed && !(datagram_type & 0x20 != 0 && datagram_type & 0x02 != 0)
}

/// One of the three shapes a refused Type can take.
///
/// The sweeps would pass on "some error", and that is what is worth not
/// settling for: these are three different rules, and only two of them end the
/// session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    /// A Type no table assigns. Section 3.4 ends the session.
    Unknown,
    /// A Type inside a form the draft defines but on a list it calls invalid.
    /// Sections 11.4.2 and 11.3.1 end the session and name the code.
    NamedInvalid,
    /// A Type the draft assigns, handed to a reader that cannot read it. The
    /// session survives.
    NotThisReader,
}

/// Which answer a refused subgroup Type deserves.
fn expected_subgroup_refusal(header_type: u8) -> Refusal {
    if header_type == 0x05 {
        // FETCH_HEADER, which Table 3 assigns.
        Refusal::NotThisReader
    } else if RESERVED_MODE_TYPES.contains(&header_type) {
        Refusal::NamedInvalid
    } else {
        Refusal::Unknown
    }
}

/// Which answer a refused datagram Type deserves.
fn expected_datagram_refusal(datagram_type: u8) -> Refusal {
    if STATUS_WITH_END_OF_GROUP_TYPES.contains(&datagram_type) {
        Refusal::NamedInvalid
    } else {
        Refusal::Unknown
    }
}

fn assert_refusal(ty: u8, got: &CodecError, want: Refusal) {
    let ok = match want {
        Refusal::Unknown => {
            matches!(got, CodecError::UnknownStreamType(_) | CodecError::UnknownDatagramType(_))
        }
        Refusal::NamedInvalid => matches!(got, CodecError::InvalidTypeValue { .. }),
        Refusal::NotThisReader => matches!(got, CodecError::InvalidField),
    };
    assert!(ok, "type {ty:#04x} was refused with {got:?}, which is not {want:?}");
}

/// The decoder accepts exactly the datagram Types draft-19 assigns.
///
/// The same sweep as the subgroup one, over the other Type space. A valid
/// datagram has to consume its whole header and give its fields back; an
/// invalid one has to be refused before any of that.
///
/// # What this catches, observed by making each change and running it
///
/// Deleting the `validate_datagram_type(datagram_type)?` call from
/// `DatagramHeader::decode`, which is how this decoder behaved before:
///
/// ```text
/// type 0x10 was accepted; draft-19 Section 11.3.1 lists it as invalid
/// ```
///
/// Keeping the form check but dropping the STATUS-with-END_OF_GROUP arm:
///
/// ```text
/// type 0x22 was accepted; draft-19 Section 11.3.1 lists it as invalid
/// ```
#[test]
fn datagram_types_outside_the_drafts_lists_are_refused() {
    for datagram_type in 0u8..=0x7F {
        let wire = datagram(datagram_type);
        let mut cursor: &[u8] = &wire;
        let decoded = DatagramHeader::decode(&mut cursor);

        if datagram_type_is_valid(datagram_type) {
            let header = decoded.unwrap_or_else(|e| {
                panic!("type {datagram_type:#04x} is valid under draft-19 but was refused: {e:?}")
            });
            assert!(
                !cursor.has_remaining(),
                "type {datagram_type:#04x} left {} byte(s) of its own header unread",
                cursor.remaining()
            );
            assert_eq!(header.datagram_type, datagram_type);
            assert_eq!(header.track_alias.into_inner(), TRACK_ALIAS as u64);
            assert_eq!(header.group_id.into_inner(), GROUP_ID as u64);
            if datagram_type & 0x01 != 0 {
                assert_eq!(
                    header.properties, PROPERTIES,
                    "type {datagram_type:#04x} lost its property block"
                );
            }
        } else {
            match decoded {
                Ok(_) => panic!(
                    "type {datagram_type:#04x} was accepted; \
                     draft-19 Section 11.3.1 lists it as invalid"
                ),
                Err(error) => {
                    assert_refusal(datagram_type, &error, expected_datagram_refusal(datagram_type))
                }
            }
        }
    }

    for &datagram_type in STATUS_WITH_END_OF_GROUP_TYPES {
        assert!(
            !datagram_type_is_valid(datagram_type),
            "{datagram_type:#04x} is on the draft's invalid list but this sweep treats it \
             as valid"
        );
        assert!(
            DatagramHeader::decode(&mut &datagram(datagram_type)[..]).is_err(),
            "type {datagram_type:#04x} sets both STATUS and END_OF_GROUP and was accepted"
        );
    }
}

/// `encode_checked` will not write a datagram Type its own decoder refuses.
///
/// The status held here is `None` throughout, so the only thing that can be
/// refused is the Type: the pre-existing lossy-status rule this method also
/// applies has nothing to fire on.
///
/// # What this catches, observed by making each change and running it
///
/// Deleting the `validate_datagram_type(self.datagram_type)?` line from
/// `DatagramHeader::encode_checked`:
///
/// ```text
/// encode_checked wrote type 0x10, which decode refuses
/// ```
///
/// Dropping the STATUS-with-END_OF_GROUP arm of `validate_datagram_type`,
/// which takes the check out of both halves at once:
///
/// ```text
/// encode_checked wrote type 0x22, which decode refuses
/// ```
#[test]
fn the_checked_datagram_encoder_refuses_a_type_the_decoder_refuses() {
    for datagram_type in 0u8..=0xFF {
        let header = DatagramHeader {
            datagram_type,
            track_alias: vi(TRACK_ALIAS as u64),
            group_id: vi(GROUP_ID as u64),
            object_id: vi(3),
            publisher_priority: Some(PRIORITY),
            properties: if datagram_type & 0x01 != 0 { PROPERTIES.to_vec() } else { Vec::new() },
            object_status: None,
        };

        let mut checked = Vec::new();
        let result = header.encode_checked(&mut checked);

        if datagram_type_is_valid(datagram_type) {
            result.unwrap_or_else(|e| panic!("valid type {datagram_type:#04x} was refused: {e:?}"));
            let mut cursor: &[u8] = &checked;
            DatagramHeader::decode(&mut cursor).unwrap_or_else(|e| {
                panic!("encode_checked wrote type {datagram_type:#04x} that decode refuses: {e:?}")
            });
        } else {
            assert_refusal(
                datagram_type,
                &result.expect_err(&format!(
                    "encode_checked wrote type {datagram_type:#04x}, which decode refuses"
                )),
                expected_datagram_refusal(datagram_type),
            );
            assert!(
                checked.is_empty(),
                "a refused type {datagram_type:#04x} still wrote {checked:02x?}"
            );
        }
    }
}

/// A Type wider than one byte is refused, and refused as what it actually is.
///
/// The sweeps above stop at 0x7F because that is where one byte stops being one
/// Type: under the MoQT variable-length integer encoding a first byte of 0x80 or
/// above announces a longer field, so the bytes behind it belong to the Type
/// rather than to the header. That is not a corner of the space — it is where
/// half of what Table 3 assigns lives.
///
/// Table 3 gives four Types and two are several bytes wide: SETUP at 0x2F00 and
/// PADDING at 0x132B3E28, whose encodings lead with 0xAF and 0xF0. Neither is a
/// data stream, so both are refused; but neither is *unknown*, and reporting
/// them so would end the session — over the peer's control stream in the first
/// case, and over traffic Section 11.5.1 explicitly permits in the second.
/// Draft-19's Table 3 assigns both of those Types exactly as draft-18's does.
///
/// The last case is why a Type is decoded rather than narrowed. A two-byte
/// 0x8010 carries the value 0x10, an assigned subgroup Type, and its low octet
/// is 0x10 as well, so a decoder that truncated would read it as a valid header
/// and let a peer spell any Type it liked.
///
/// # What this catches, observed by making the change and running it
///
/// Removing the `wide_type_refusal` call from `SubgroupHeader::decode`, leaving
/// the one-byte read:
///
/// ```text
/// thread 'a_type_wider_than_one_byte_is_refused_by_what_it_is' (7580) panicked at
/// crates\moqtap-codec\tests\draft19_data_stream_rules.rs:
/// SETUP is a Type Table 3 assigns, so a subgroup reader must refuse it without naming the unknown-stream-type rule that would end the session, got UnknownStreamType(175)
/// ```
///
/// 175 is 0xAF, the first byte of SETUP's two-byte Type — so the reader both
/// ended the session over an assigned stream and named a number the peer never
/// sent.
#[test]
fn a_type_wider_than_one_byte_is_refused_by_what_it_is() {
    fn varint(v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        VarInt::from_u64_moqt(v).encode_moqt::<Wire>(&mut out);
        out
    }

    let body = [TRACK_ALIAS, GROUP_ID, SUBGROUP_ID, PRIORITY];

    for (name, ty) in [("SETUP", 0x2F00u64), ("PADDING", PADDING_STREAM_TYPE)] {
        let mut wire = varint(ty);
        wire.extend_from_slice(&body);
        match SubgroupHeader::decode(&mut &wire[..]) {
            Ok(h) => panic!("{name} is not a subgroup header, but decode accepted {h:?}"),
            Err(e) => assert!(
                matches!(e, CodecError::InvalidField),
                "{name} is a Type Table 3 assigns, so a subgroup reader must refuse it without \
                 naming the unknown-stream-type rule that would end the session, got {e:?}"
            ),
        }
    }

    let mut padding_datagram = varint(PADDING_DATAGRAM_TYPE);
    padding_datagram.extend_from_slice(&body);
    match DatagramHeader::decode(&mut &padding_datagram[..]) {
        Ok(h) => panic!("a padding datagram is not an object datagram, but decode accepted {h:?}"),
        Err(e) => assert!(
            matches!(e, CodecError::InvalidField),
            "the padding datagram Type is assigned, so it must be refused without naming the \
             unknown-datagram-type rule that would end the session, got {e:?}"
        ),
    }

    let mut unassigned = varint(0x0100);
    unassigned.extend_from_slice(&body);
    match SubgroupHeader::decode(&mut &unassigned[..]) {
        Ok(h) => panic!("0x0100 is not a Type draft-19 assigns, but decode accepted {h:?}"),
        Err(e) => assert!(
            matches!(e, CodecError::UnknownStreamType(0x0100)),
            "a Type no table assigns must be named as unknown, got {e:?}"
        ),
    }

    let non_minimal = [0x80u8, 0x10, TRACK_ALIAS, GROUP_ID, SUBGROUP_ID, PRIORITY];
    assert!(
        SubgroupHeader::decode(&mut &non_minimal[..]).is_err(),
        "a wide spelling must not be narrowed onto the assigned Type 0x10"
    );
}

// ── The registry's payload column, read off the framing ───────

/// Draft-19 Section 15.9, Table 16, "Payload" column, transcribed. A second
/// copy of the registry, so a codec that changed a row cannot agree with
/// itself into passing.
const PAYLOAD_COLUMN: &[(u64, PayloadPermission)] = &[
    (0x0, PayloadPermission::Permitted),
    (0x3, PayloadPermission::Forbidden),
    (0x4, PayloadPermission::Forbidden),
];

/// A one-object subgroup stream, header type 0x10, whose object carries
/// `payload` — or, when `payload` is empty, `status` in place of one.
fn one_object_stream(status: ObjectStatus, payload: &[u8]) -> Vec<u8> {
    let header = SubgroupHeader {
        header_type: 0x10,
        track_alias: vi(1),
        group_id: vi(0),
        subgroup_id: vi(0),
        publisher_priority: Some(PRIORITY),
    };
    let mut wire = Vec::new();
    header.encode(&mut wire);
    SubgroupObjectReader::new(&header)
        .write_object(
            &SubgroupObject {
                object_id: vi(0),
                extension_headers: Vec::new(),
                payload_length: vi(payload.len() as u64),
                object_status: Some(status),
                payload: payload.to_vec(),
            },
            &mut wire,
        )
        .unwrap_or_else(|e| panic!("could not build a {status:?} object: {e:?}"));
    wire
}

/// A framing-only read of a subgroup object reports the registry's payload
/// permission for the status that framing carries.
///
/// The metas here are decoded from bytes rather than assembled, so what is
/// being observed is what a caller forwarding a stream actually holds. The
/// permission is then tied back to a consequence: for every status the
/// registry forbids a payload, the encoder must refuse one, and for the status
/// it permits, the encoder must accept one. An accessor that reported the
/// column correctly while the encoder disagreed would fail here.
///
/// # What this catches, observed by making each change and running it
///
/// Making `SubgroupObjectMeta::payload_permission` answer `None` when the
/// framing carries no status field — the reading in which an absent status
/// means "unknown" rather than the Normal the encoding elides:
///
/// ```text
/// assertion `left == right` failed: a payload-bearing object's status is Normal, which Table 16 permits a payload
///   left: None
///  right: Some(Permitted)
/// ```
///
/// Making it report `Permitted` for every assigned status, which is what
/// moving a row into the permitting column would look like from here:
///
/// ```text
/// assertion `left == right` failed: status 0x3 reports the wrong Table 16 column
///   left: Some(Permitted)
///  right: Some(Forbidden)
/// ```
#[test]
fn a_framing_only_read_reports_the_registrys_payload_column() {
    let header = SubgroupHeader::decode(&mut &[0x10u8, 0x01, 0x00, PRIORITY][..]).unwrap();

    for &(code, permission) in PAYLOAD_COLUMN {
        let status = ObjectStatus::from_u64(code)
            .unwrap_or_else(|| panic!("draft-19 assigns status {code:#x}"));

        let wire = one_object_stream(status, &[]);
        let mut cursor = &wire[..];
        SubgroupHeader::decode(&mut cursor).unwrap();
        let meta = SubgroupObjectReader::new(&header).read_object_meta(&mut cursor).unwrap();

        assert_eq!(meta.status, Some(code), "status {code:#x} did not survive the framing");
        assert_eq!(
            meta.payload_permission(),
            Some(permission),
            "status {code:#x} reports the wrong Table 16 column"
        );

        // The column, observed as behaviour: a payload under this status is
        // accepted exactly when the row permits one.
        let mut written = Vec::new();
        let result = SubgroupObjectReader::new(&header).write_object(
            &SubgroupObject {
                object_id: vi(0),
                extension_headers: Vec::new(),
                payload_length: vi(4),
                object_status: Some(status),
                payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
            },
            &mut written,
        );
        assert_eq!(
            result.is_ok(),
            permission.permits(),
            "the encoder disagrees with the Table 16 column for status {code:#x}: {result:?}"
        );
    }

    // An object that carries bytes has no status field, and the status the
    // framing leaves out is Normal — the one row permitting the payload it is
    // carrying.
    let wire = one_object_stream(ObjectStatus::Normal, &[0xDE, 0xAD]);
    let mut cursor = &wire[..];
    SubgroupHeader::decode(&mut cursor).unwrap();
    let meta = SubgroupObjectReader::new(&header).read_object_meta(&mut cursor).unwrap();
    assert_eq!(meta.status, None, "a payload-bearing object must carry no status field");
    assert_eq!(
        meta.payload_permission(),
        Some(PayloadPermission::Permitted),
        "a payload-bearing object's status is Normal, which Table 16 permits a payload"
    );
}

/// A status code the registry has no row for gets no answer.
///
/// The reader refuses such a code, so this meta has to be assembled by hand —
/// which is precisely the case the return type exists for. A relay carrying a
/// status across from a draft that numbers the set differently can hold one,
/// and draft-19 has nothing to say about it.
///
/// # What this catches, observed by making the change and running it
///
/// Making `payload_permission` fall back to Normal's row for an unrecognised
/// code — `unwrap_or(ObjectStatus::Normal)`, the shape used elsewhere in the
/// module for the status the *encoding* elides:
///
/// ```text
/// assertion `left == right` failed: status 0x1 has no row in Table 16, so there is no permission to report
///   left: Some(Permitted)
///  right: None
/// ```
#[test]
fn a_status_the_registry_does_not_list_has_no_payload_permission() {
    for code in [0x1u64, 0x2, 0x5, 0xFF, u64::MAX] {
        assert!(
            ObjectStatus::from_u64(code).is_none(),
            "{code:#x} is an assigned status; this case is not testing what it claims"
        );
        let meta = SubgroupObjectMeta {
            object_id: 0,
            extension_headers_len: 0,
            payload_length: 0,
            status: Some(code),
            wire_len: 3,
        };
        assert_eq!(
            meta.payload_permission(),
            None,
            "status {code:#x} has no row in Table 16, so there is no permission to report"
        );
    }
}

// ── Fetch objects ─────────────────────────────────────────────

/// Serialization Flags values draft-19 Section 11.4.4 leaves undefined: bit 7
/// set and not one of the two End of Range values Table 7 assigns. The
/// section says of them, flatly, "Any other value is a PROTOCOL_VIOLATION".
const UNDEFINED_FLAGS: &[u64] = &[0x80, 0x8B, 0x8D, 0x10B, 0x10D, 0xFF, 0x100, 0x4000, u64::MAX];

/// A fetch object header carrying `flags`, with every field that value says is
/// present and none that it does not.
fn fetch_object(flags: u64) -> FetchObjectHeader {
    let end_of_range = flags == 0x8C || flags == 0x10C;
    let datagram = !end_of_range && flags & 0x40 != 0;
    FetchObjectHeader {
        serialization_flags: vi(flags),
        group_id_delta: (flags & 0x08 != 0).then(|| vi(5)),
        subgroup_id: (!datagram && !end_of_range && flags & 0x03 == 0x03).then(|| vi(7)),
        object_id_delta: (flags & 0x04 != 0).then(|| vi(2)),
        publisher_priority: (!end_of_range && flags & 0x10 != 0).then_some(PRIORITY),
        properties: (!end_of_range && flags & 0x20 != 0).then(|| PROPERTIES.to_vec()),
        payload_length: vi(0),
    }
}

/// Every fetch object shape the flags can name survives a round trip, and the
/// decoder consumes exactly the header.
///
/// Sweeps all 128 flag values that are flags, plus the two End of Range
/// indicators. A payload is appended after each header so that a decoder
/// reading one field too few would be caught by the leftover count rather than
/// running off the end.
///
/// # What this catches, observed by making each change and running it
///
/// Swapping the Subgroup ID and Object ID Delta reads in
/// `FetchObjectHeader::decode`, so the fields come off the wire in the wrong
/// order:
///
/// ```text
/// assertion `left == right` failed: flags 0x7 did not survive a round trip
///   left: FetchObjectHeader { serialization_flags: VarInt(7), group_id_delta: None, subgroup_id: Some(VarInt(2)), object_id_delta: Some(VarInt(7)), publisher_priority: None, properties: None, payload_length: VarInt(4) }
///  right: FetchObjectHeader { serialization_flags: VarInt(7), group_id_delta: None, subgroup_id: Some(VarInt(7)), object_id_delta: Some(VarInt(2)), publisher_priority: None, properties: None, payload_length: VarInt(4) }
/// ```
///
/// Ignoring the Datagram bit when deciding whether an explicit Subgroup ID is
/// present, so 0x40 stops suppressing the field. The refusal comes from the
/// encoder rather than the round trip, because the shape this test builds is
/// the one the draft describes and the ablated codec no longer agrees it
/// exists:
///
/// ```text
/// flags 0x43 could not be encoded: InvalidField
/// ```
#[test]
fn every_fetch_object_shape_the_flags_name_round_trips() {
    const PAYLOAD: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];

    for flags in (0u64..=0x7F).chain([0x8C, 0x10C]) {
        let mut header = fetch_object(flags);
        header.payload_length = vi(PAYLOAD.len() as u64);

        let mut wire = Vec::new();
        header
            .encode(&mut wire)
            .unwrap_or_else(|e| panic!("flags {flags:#x} could not be encoded: {e:?}"));
        let header_len = wire.len();
        wire.extend_from_slice(PAYLOAD);

        let mut cursor: &[u8] = &wire;
        let back = FetchObjectHeader::decode(&mut cursor)
            .unwrap_or_else(|e| panic!("flags {flags:#x} could not be decoded: {e:?}"));
        assert_eq!(back, header, "flags {flags:#x} did not survive a round trip");
        assert_eq!(
            cursor.remaining(),
            PAYLOAD.len(),
            "flags {flags:#x} left {} byte(s) of payload unread, so the header framing is wrong",
            cursor.remaining()
        );
        assert_eq!(
            header_len + PAYLOAD.len(),
            wire.len(),
            "flags {flags:#x}: the encoder wrote a payload it was not given"
        );
    }
}

/// A Serialization Flags value draft-19 does not define is refused, on both
/// sides.
///
/// Refusing on decode is what keeps an undefined value from being framed under
/// a layout nobody described: every one of these has bit 7 set, and the low
/// bits of most of them look like a perfectly ordinary flag set, so a decoder
/// that masked instead of validating would consume a plausible number of bytes
/// and carry on.
///
/// # What this catches, observed by making the change and running it
///
/// Masking the flags to their low seven bits in `FetchObjectHeader::layout`
/// instead of refusing values above 0x7F:
///
/// ```text
/// flags 0x80 are undefined but decode accepted them
/// ```
#[test]
fn fetch_serialization_flags_the_draft_does_not_define_are_refused() {
    for &flags in UNDEFINED_FLAGS {
        let mut wire = Vec::new();
        vi(flags).encode_moqt::<moqtap_codec::varint::Moqt18>(&mut wire);
        // Enough trailing bytes that no shape can run out of buffer, so a
        // refusal is about the flags and not about the length.
        wire.extend_from_slice(&[0u8; 16]);

        match FetchObjectHeader::decode(&mut &wire[..]) {
            Ok(_) => panic!("flags {flags:#x} are undefined but decode accepted them"),
            Err(error) => assert!(
                matches!(error, CodecError::InvalidField),
                "flags {flags:#x} were refused with {error:?}, not InvalidField"
            ),
        }

        let header = FetchObjectHeader {
            serialization_flags: vi(flags),
            group_id_delta: None,
            subgroup_id: None,
            object_id_delta: None,
            publisher_priority: None,
            properties: None,
            payload_length: vi(0),
        };
        let mut out = Vec::new();
        assert!(
            matches!(header.encode(&mut out), Err(CodecError::InvalidField)),
            "flags {flags:#x} are undefined but encode wrote them"
        );
        assert!(out.is_empty(), "a refused header still wrote {out:02x?}");
    }
}

/// A fetch object header whose fields disagree with its own flags is refused
/// rather than reconciled.
///
/// Both directions are swept, over every flag value: a field held while its
/// flag is clear, which a flags-are-authority encoder would silently drop, and
/// a flag set with no field behind it, which such an encoder would have to
/// invent a value for. Dropping a Group ID Delta does not corrupt the frame —
/// it re-homes the Object into the previous Object's group, and the stream
/// still parses.
///
/// # What this catches, observed by making each change and running it
///
/// Deleting the presence comparison from `FetchObjectHeader::encode`, leaving
/// it to write whichever fields the flags call for:
///
/// ```text
/// flags 0x0: an extra group_id_delta was written out rather than refused
/// ```
///
/// Ignoring the Datagram bit in the layout, so a flags value that suppresses
/// the Subgroup ID field starts calling for one:
///
/// ```text
/// flags 0x43: an extra subgroup_id was written out rather than refused
/// ```
#[test]
fn a_fetch_object_header_that_contradicts_its_flags_is_refused() {
    for flags in (0u64..=0x7F).chain([0x8C, 0x10C]) {
        let base = fetch_object(flags);

        /// One field name and a change that toggles that field's presence,
        /// turning a consistent header into a contradictory one.
        type Mutation = (&'static str, fn(&mut FetchObjectHeader));

        let mutations: [Mutation; 5] = [
            ("group_id_delta", |h| {
                h.group_id_delta = if h.group_id_delta.is_some() { None } else { Some(vi(5)) }
            }),
            ("subgroup_id", |h| {
                h.subgroup_id = if h.subgroup_id.is_some() { None } else { Some(vi(7)) }
            }),
            ("object_id_delta", |h| {
                h.object_id_delta = if h.object_id_delta.is_some() { None } else { Some(vi(2)) }
            }),
            ("publisher_priority", |h| {
                h.publisher_priority =
                    if h.publisher_priority.is_some() { None } else { Some(PRIORITY) }
            }),
            ("properties", |h| {
                h.properties = if h.properties.is_some() { None } else { Some(PROPERTIES.to_vec()) }
            }),
        ];

        for (field, mutate) in mutations {
            let mut header = base.clone();
            mutate(&mut header);
            let mut out = Vec::new();
            let result = header.encode(&mut out);
            assert!(
                matches!(result, Err(CodecError::InvalidField)),
                "flags {flags:#x}: an extra {field} was written out rather than refused"
            );
            assert!(out.is_empty(), "flags {flags:#x}: a refused header still wrote {out:02x?}");
        }
    }
}

/// The two End of Range indicators are told apart, and no other flags value
/// claims to be one.
///
/// Draft-19 Section 11.4.4.2 gives them different meanings a subscriber must
/// act on differently — Objects known not to exist, against Objects of unknown
/// status — so collapsing them would be a silent loss, and Table 7 gives them
/// whole values rather than a bit, so a mask would find them everywhere.
///
/// # What this catches, observed by making the change and running it
///
/// Making `end_of_range` answer `NonExistent` for both values:
///
/// ```text
/// assertion `left == right` failed: flags 0x10c is End of Unknown Range
///   left: Some(NonExistent)
///  right: Some(Unknown)
/// ```
#[test]
fn the_two_end_of_range_indicators_are_distinguished() {
    assert_eq!(
        fetch_object(0x8C).end_of_range(),
        Some(FetchEndOfRange::NonExistent),
        "flags 0x8c is End of Non-Existent Range"
    );
    assert_eq!(
        fetch_object(0x10C).end_of_range(),
        Some(FetchEndOfRange::Unknown),
        "flags 0x10c is End of Unknown Range"
    );
    for flags in 0u64..=0x7F {
        assert_eq!(
            fetch_object(flags).end_of_range(),
            None,
            "flags {flags:#x} is an ordinary Object, not an End of Range indicator"
        );
    }
}

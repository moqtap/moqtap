//! Draft-20 data-stream rules that are about the frame rather than its
//! contents: which `Type Flags` values may appear at all, what the Object
//! Status registry says about a payload, and the fetch object layout of
//! Section 11.4.4.
//!
//! # What draft-20 changed here
//!
//! The set of valid values did not move — computing Section 11.4.2's three
//! conditions and Section 11.3.1's three gives back draft-19's enumerations
//! byte for byte. Three things about the *receive path* did:
//!
//! * the two carriers state their conditions separately, and disagree on bit 4:
//!   a subgroup header MUST set it and a datagram MUST NOT. Neither rule set is
//!   derivable from the other, so this file restates both;
//! * every invalid value inside the one-byte space is now something the draft
//!   *names*, so a subgroup Type of 0x20 is `invalid_type` rather than an
//!   unknown stream type. Only a value too wide to be a flags field at all
//!   falls back on Section 3.4's unknown-type rule;
//! * a non-minimally encoded `Type Flags` is accepted, which draft-19 refused.
//!   See [`a_non_minimal_type_flags_value_is_accepted_on_receive`].
//!
//! On the fetch stream, Table 7 gains a third End of Range marker at `0x20C`.
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

#![cfg(feature = "draft20")]

use bytes::Buf;
use moqtap_codec::draft20::data_stream::{
    DatagramHeader, FetchEndOfRange, FetchObjectHeader, SubgroupHeader, SubgroupObject,
    SubgroupObjectMeta, SubgroupObjectReader, PADDING_DATAGRAM_TYPE, PADDING_STREAM_TYPE,
};
use moqtap_codec::draft20::types::{ObjectStatus, PayloadPermission};
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

/// Every subgroup header Type draft-20 Section 11.4.2 names as invalid
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

/// Whether draft-20 Section 11.4.2 permits `header_type`.
///
/// Restates the section's three conditions — a SUBGROUP_ID_MODE other than the
/// reserved `0b11`, bit 4 set, and a value below 128 — so the sweep holds its
/// own copy of the rule rather than asking the code under test.
///
/// Note the shape of the middle one. Section 11.3.1 reserves the same bit for a
/// datagram and requires it to be **zero**; the two carriers are opposite here,
/// and [`datagram_type_is_valid`] restates the datagram's own list rather than
/// sharing anything with this.
fn subgroup_type_is_valid(header_type: u8) -> bool {
    let below_128 = header_type & 0x80 == 0;
    below_128 && header_type & 0x10 != 0 && (header_type & 0x06) >> 1 != 0b11
}

/// The decoder accepts exactly the subgroup header Types draft-20 assigns.
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
/// type 0x00 was accepted; draft-20 Section 11.4.2 lists it as invalid
/// ```
///
/// Keeping the form check but dropping only the reserved-mode arm — the
/// behaviour this module had before, which read a mode-3 header as though it
/// carried no Subgroup ID field:
///
/// ```text
/// type 0x16 was accepted; draft-20 Section 11.4.2 lists it as invalid
/// ```
#[test]
fn subgroup_header_types_outside_the_drafts_lists_are_refused() {
    for header_type in 0u8..=0x7F {
        let wire = subgroup_stream(header_type);
        let mut cursor: &[u8] = &wire;
        let decoded = SubgroupHeader::decode(&mut cursor);

        if subgroup_type_is_valid(header_type) {
            let header = decoded.unwrap_or_else(|e| {
                panic!("type {header_type:#04x} is valid under draft-20 but was refused: {e:?}")
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
                     draft-20 Section 11.4.2 lists it as invalid"
                ),
                Err(error) => assert_refusal(
                    header_type as u64,
                    &error,
                    expected_subgroup_refusal(header_type),
                ),
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
                header_type as u64,
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

/// Every datagram Type draft-20 Section 11.3.1 names as invalid because it
/// sets both the STATUS bit and the END_OF_GROUP bit. Transcribed from the
/// section's list.
const STATUS_WITH_END_OF_GROUP_TYPES: &[u8] = &[0x22, 0x23, 0x26, 0x27, 0x2A, 0x2B, 0x2E, 0x2F];

/// The property block written whenever a datagram Type sets the PROPERTIES
/// bit. Non-empty on purpose: draft-20 Section 11.3.1 makes a datagram that
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

/// Whether draft-20 Section 11.3.1 permits `datagram_type`.
///
/// Its three conditions, restated: not both STATUS and END_OF_GROUP; bit 4
/// clear, because it "is reserved and MUST be zero"; and no bit set whose
/// meaning is not specified, which for a datagram means nothing outside
/// PROPERTIES, END_OF_GROUP, ZERO_OBJECT_ID, DEFAULT_PRIORITY and STATUS. That
/// third condition is what rules out bit 6 and everything at 128 or above, and
/// it is the one a subgroup header does not have — there bits 0 to 6 are all
/// specified, and Section 11.4.2 states an explicit "128 or greater" condition
/// in its place.
fn datagram_type_is_valid(datagram_type: u8) -> bool {
    const SPECIFIED: u8 = 0x01 | 0x02 | 0x04 | 0x08 | 0x20;
    datagram_type & !SPECIFIED == 0 && !(datagram_type & 0x20 != 0 && datagram_type & 0x02 != 0)
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

/// Which answer a refused subgroup `Type Flags` value deserves.
///
/// Every invalid value inside the one-byte space is one Section 11.4.2 names —
/// the reserved mode, bit 4 clear, or 128 or greater cover the whole of it
/// between them — so `Refusal::Unknown` has no subject here. That is the
/// change from draft-19, whose figure enumerated the valid values and left the
/// rest to Section 3.4's unknown-stream-type rule; the value set is the same
/// and the complaint is not. FETCH_HEADER is the one exception: Table 3 assigns
/// it, so a subgroup reader handed one disagrees with the caller rather than
/// with the draft, and the session survives.
fn expected_subgroup_refusal(header_type: u8) -> Refusal {
    if header_type == 0x05 {
        Refusal::NotThisReader
    } else {
        Refusal::NamedInvalid
    }
}

/// Which answer a refused datagram `Type Flags` value deserves.
///
/// As above: Section 11.3.1's three conditions cover every invalid byte, so
/// nothing in the one-byte space is merely unknown. Unlike the subgroup space
/// there is no assigned non-datagram value below 128 to except — the padding
/// datagram's type is four bytes wide.
fn expected_datagram_refusal(_datagram_type: u8) -> Refusal {
    Refusal::NamedInvalid
}

fn assert_refusal(ty: u64, got: &CodecError, want: Refusal) {
    let ok = match want {
        Refusal::Unknown => {
            matches!(got, CodecError::UnknownStreamType(_) | CodecError::UnknownDatagramType(_))
        }
        Refusal::NamedInvalid => matches!(
            got,
            CodecError::InvalidStreamTypeValue { .. } | CodecError::InvalidDatagramTypeValue { .. }
        ),
        Refusal::NotThisReader => matches!(got, CodecError::InvalidField),
    };
    assert!(ok, "type {ty:#04x} was refused with {got:?}, which is not {want:?}");
}

/// The decoder accepts exactly the datagram Types draft-20 assigns.
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
/// type 0x10 was accepted; draft-20 Section 11.3.1 lists it as invalid
/// ```
///
/// Keeping the form check but dropping the STATUS-with-END_OF_GROUP arm:
///
/// ```text
/// type 0x22 was accepted; draft-20 Section 11.3.1 lists it as invalid
/// ```
#[test]
fn datagram_types_outside_the_drafts_lists_are_refused() {
    for datagram_type in 0u8..=0x7F {
        let wire = datagram(datagram_type);
        let mut cursor: &[u8] = &wire;
        let decoded = DatagramHeader::decode(&mut cursor);

        if datagram_type_is_valid(datagram_type) {
            let header = decoded.unwrap_or_else(|e| {
                panic!("type {datagram_type:#04x} is valid under draft-20 but was refused: {e:?}")
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
                     draft-20 Section 11.3.1 lists it as invalid"
                ),
                Err(error) => assert_refusal(
                    datagram_type as u64,
                    &error,
                    expected_datagram_refusal(datagram_type),
                ),
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
                datagram_type as u64,
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

/// A `Type Flags` value wider than one byte is judged by its value, not its
/// width.
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
///
/// A value no table assigns and that is too wide to be a flags field is the one
/// case left for Section 3.4, and it is what keeps
/// [`CodecError::UnknownStreamType`] reachable at all on this draft.
///
/// # What this catches, observed by making the change and running it
///
/// Narrowing the decoded Type to its low octet in `SubgroupHeader::decode`
/// instead of judging the whole value — the shape that lets a peer spell any
/// Type it likes, since 0x2F00's low octet is 0x00 and 0x132B3E28's is 0x28:
///
/// ```text
/// SETUP is a Type Table 3 assigns, so a subgroup reader must refuse it without
/// naming the unknown-stream-type rule that would end the session, got
/// InvalidStreamTypeValue { raw: 0, detail: "bit 4 must be 1 for SUBGROUP_HEADER" }
/// ```
#[test]
fn a_type_wider_than_one_byte_is_judged_by_its_value() {
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
        Ok(h) => panic!("0x0100 is not a Type draft-20 assigns, but decode accepted {h:?}"),
        Err(e) => {
            // The one place [`Refusal::Unknown`] is still reachable on
            // draft-20: inside the byte space every invalid value is one the
            // draft names, so Section 3.4's rule has only this left to answer.
            assert_refusal(0x0100, &e, Refusal::Unknown);
            assert!(
                matches!(e, CodecError::UnknownStreamType(0x0100)),
                "the unknown Type must be named with the value the peer sent, got {e:?}"
            );
        }
    }

    // A value inside the byte space but at 128 or above is Section 11.4.2's
    // third condition, not Section 3.4's rule, even though it arrives in two
    // bytes: bit 4 is set and the mode is 0b00, so it passes the other two.
    let mut over_127 = varint(0x90);
    over_127.extend_from_slice(&body);
    match SubgroupHeader::decode(&mut &over_127[..]) {
        Ok(h) => panic!("Type Flags 144 is at or above 128, but decode accepted {h:?}"),
        Err(e) => assert!(
            matches!(e, CodecError::InvalidStreamTypeValue { raw: 0x90, .. }),
            "Type Flags 144 is Section 11.4.2's third condition, got {e:?}"
        ),
    }
}

/// A `Type Flags` value spelled in more bytes than it needs still decodes, and
/// is never written that way.
///
/// **This is a decision, and draft-20 does not settle it.** Section 1.4.1
/// permits non-minimal encodings; Section 11.4.2 words its third condition as
/// "values of 128 or greater (i.e., any value that requires more than a
/// one-byte variable-length integer encoding)". Those two clauses come apart
/// under that allowance: the two-byte `0x8010` carries the value 16, which is
/// below 128 and is an assigned Type, while its encoding is two bytes. This
/// codec reads the condition as a bound on the *value* and is therefore
/// permissive on receive and strict on send — rejecting a legal-but-wide
/// encoding risks failing a conformant peer, and emitting one risks tripping a
/// stricter peer, so the asymmetry is the safe default.
///
/// Draft-19 refused every wide spelling, and this is the one place the two
/// drafts' decoders answer differently on bytes both call well-formed.
///
/// # What this catches, observed by making the change and running it
///
/// Restoring draft-19's up-front refusal of a wide Type:
///
/// ```text
/// a non-minimal spelling of the assigned Type 0x10 must decode: InvalidField
/// ```
#[test]
fn a_non_minimal_type_flags_value_is_accepted_on_receive() {
    let non_minimal = [0x80u8, 0x10, TRACK_ALIAS, GROUP_ID, PRIORITY];
    let header = SubgroupHeader::decode(&mut &non_minimal[..]).unwrap_or_else(|e| {
        panic!(
            "a non-minimal spelling of the assigned Type 0x10 must \
                                    decode: {e:?}"
        )
    });
    assert_eq!(header.header_type, 0x10, "the value is 16, whatever its width");
    assert_eq!(header.track_alias.into_inner(), TRACK_ALIAS as u64);

    // Strict on send: what comes back out is the one-byte form.
    let mut out = Vec::new();
    header.encode(&mut out);
    assert_eq!(out[0], 0x10, "the encoder must emit the minimal spelling");
    assert_eq!(out.len(), non_minimal.len() - 1, "and no wide field with it");

    // The same, on a datagram. Section 11.4.2's "more than a one-byte
    // variable-length integer encoding" clause has no counterpart in Section
    // 11.3.1 at all, so the reading there is if anything plainer.
    let non_minimal = [0x80u8, 0x00, TRACK_ALIAS, GROUP_ID, 3, PRIORITY];
    let header = DatagramHeader::decode(&mut &non_minimal[..]).unwrap_or_else(|e| {
        panic!(
            "a non-minimal spelling of the assigned Type 0x00 must \
                                    decode: {e:?}"
        )
    });
    assert_eq!(header.datagram_type, 0x00);
    let mut out = Vec::new();
    header.encode(&mut out);
    assert_eq!(out[0], 0x00, "the encoder must emit the minimal spelling");

    // A wide spelling of a value the draft forbids is still forbidden: the
    // permissiveness is about the width and not about the value.
    let wide_invalid = [0x80u8, 0x16, TRACK_ALIAS, GROUP_ID, PRIORITY];
    assert!(
        matches!(
            SubgroupHeader::decode(&mut &wide_invalid[..]),
            Err(CodecError::InvalidStreamTypeValue { raw: 0x16, .. })
        ),
        "a wide spelling of the reserved-mode Type 0x16 is still the reserved mode"
    );
}

// ── The registry's payload column, read off the framing ───────

/// Draft-20 Section 15.9, Table 16, "Payload" column, transcribed. A second
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
            .unwrap_or_else(|| panic!("draft-20 assigns status {code:#x}"));

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
/// and draft-20 has nothing to say about it.
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

/// Serialization Flags values draft-20 Section 11.4.4 leaves undefined: at or
/// above 128 and not one of the **three** End of Range values Table 7 assigns.
/// The section says of them, flatly, "Any other value is a PROTOCOL_VIOLATION".
///
/// `0x20B` and `0x20D` are here for the marker draft-20 added: they bracket
/// `0x20C`, so a decoder that accepted a range around it rather than the one
/// value would be caught.
const UNDEFINED_FLAGS: &[u64] =
    &[0x80, 0x8B, 0x8D, 0x10B, 0x10D, 0x20B, 0x20D, 0xFF, 0x100, 0x4000, u64::MAX];

/// Every End of Range value Table 7 assigns, with the marker it names.
///
/// Draft-19 had the first two. `0x20C` End of Timed-Out Range is draft-20's
/// addition, and it is a behavioural change as much as a new value: the Objects
/// it covers are the ones draft-19 reported as an Unknown range.
const END_OF_RANGE_FLAGS: &[(u64, FetchEndOfRange)] = &[
    (0x8C, FetchEndOfRange::NonExistent),
    (0x10C, FetchEndOfRange::Unknown),
    (0x20C, FetchEndOfRange::TimedOut),
];

/// A fetch object header carrying `flags`, with every field that value says is
/// present and none that it does not.
fn fetch_object(flags: u64) -> FetchObjectHeader {
    let end_of_range = END_OF_RANGE_FLAGS.iter().any(|(v, _)| *v == flags);
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

    for flags in (0u64..=0x7F).chain(END_OF_RANGE_FLAGS.iter().map(|(v, _)| *v)) {
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

/// A Serialization Flags value draft-20 does not define is refused, on both
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
    for flags in (0u64..=0x7F).chain(END_OF_RANGE_FLAGS.iter().map(|(v, _)| *v)) {
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

/// The three End of Range indicators are told apart, and no other flags value
/// claims to be one.
///
/// Draft-20 Section 11.4.4.2 gives them different meanings a subscriber must
/// act on differently — Objects known not to exist, Objects of unknown status,
/// and Objects that timed out — so collapsing any two would be a silent loss,
/// and Table 7 gives them whole values rather than a bit, so a mask would find
/// them everywhere.
///
/// The third is draft-20's, and it is the one a codec ported forward is most
/// likely to miss: `0x20C` is not a variation on `0x10C`, it is the value a
/// relay uses when its `FILL_TIMEOUT` budget ran out, which draft-19 had no way
/// to distinguish from an unknown status at all.
///
/// # What this catches, observed by making each change and running it
///
/// Making `end_of_range` answer `NonExistent` for all three values:
///
/// ```text
/// assertion `left == right` failed: flags 0x10c is End of Unknown Range
///   left: Some(NonExistent)
///  right: Some(Unknown)
/// ```
///
/// Leaving `0x20C` out of the match, as a draft-19 codec does:
///
/// ```text
/// flags 0x20c could not be decoded: InvalidField
/// ```
#[test]
fn the_three_end_of_range_indicators_are_distinguished() {
    for &(flags, marker) in END_OF_RANGE_FLAGS {
        assert_eq!(
            fetch_object(flags).end_of_range(),
            Some(marker),
            "flags {flags:#x} is {marker:?}"
        );
    }
    assert_eq!(END_OF_RANGE_FLAGS.len(), 3, "draft-20 Table 7 assigns three End of Range values");

    for flags in 0u64..=0x7F {
        assert_eq!(
            fetch_object(flags).end_of_range(),
            None,
            "flags {flags:#x} is an ordinary Object, not an End of Range indicator"
        );
    }
}

/// An End of Range marker's two fields go through the ordinary delta
/// arithmetic, and the marker leaves the prior Subgroup ID and priority alone.
///
/// **This is a decision, and draft-20 does not settle it.** Section 11.4.4.2
/// says only that "the Group ID and Object ID fields are present. Subgroup ID,
/// Priority and Properties are not present", and says nothing about whether the
/// two present fields are absolute or deltas. This codec applies Section
/// 11.4.4.1 unchanged, because a marker's flags are literally the ordinary
/// flags — all three Table 7 values carry the low bits `0x0C`, the everyday
/// "both deltas present" pattern. Draft-19's reader read them as absolute;
/// on a first record the two readings agree, and after an Object they do not,
/// which is what this pins.
///
/// The half the draft *does* settle is checked alongside it: "Prior Subgroup
/// ID: The Subgroup ID from the last actual Object before the End of Range
/// indicator", and the same for Priority. So a marker supplies the prior Group
/// ID and Object ID and nothing else, and an Object after it inherits its
/// Subgroup ID and priority from across the marker.
///
/// # What this catches, observed by making the change and running it
///
/// Restoring draft-19's absolute reading, which resolves the marker's Group ID
/// Delta of 0 to group 0 rather than to the group after the Object's:
///
/// ```text
/// assertion `left == right` failed: a marker after an Object resolves its Group ID against that Object
///   left: 0
///  right: 6
/// ```
#[test]
fn an_end_of_range_marker_resolves_against_the_object_before_it() {
    use moqtap_codec::draft20::data_stream::{FetchObjectReader, GroupOrder};

    for &(flags, marker) in END_OF_RANGE_FLAGS {
        // An ordinary Object at {5, 0} with priority 128 and subgroup 0, then a
        // marker with both deltas 0, then an Object with no fields at all.
        let mut wire = Vec::new();
        FetchObjectHeader {
            serialization_flags: vi(0x1C),
            group_id_delta: Some(vi(5)),
            subgroup_id: None,
            object_id_delta: Some(vi(0)),
            publisher_priority: Some(PRIORITY),
            properties: None,
            payload_length: vi(0),
        }
        .encode(&mut wire)
        .unwrap();
        FetchObjectHeader {
            serialization_flags: vi(flags),
            group_id_delta: Some(vi(0)),
            subgroup_id: None,
            object_id_delta: Some(vi(9)),
            publisher_priority: None,
            properties: None,
            payload_length: vi(0),
        }
        .encode(&mut wire)
        .unwrap();
        FetchObjectHeader {
            serialization_flags: vi(0x00),
            group_id_delta: None,
            subgroup_id: None,
            object_id_delta: None,
            publisher_priority: None,
            properties: None,
            payload_length: vi(0),
        }
        .encode(&mut wire)
        .unwrap();

        let mut reader = FetchObjectReader::new(GroupOrder::Ascending);
        let mut cursor: &[u8] = &wire;

        let first = reader.read_object_header(&mut cursor).unwrap();
        assert_eq!(first.group_id, 5);
        assert_eq!(first.object_id, 0);

        let seen = reader.read_object_header(&mut cursor).unwrap();
        assert_eq!(seen.header.end_of_range(), Some(marker));
        assert_eq!(
            seen.group_id, 6,
            "a marker after an Object resolves its Group ID against that Object"
        );
        assert_eq!(
            seen.object_id, 9,
            "a Group ID Delta is present, so the Object ID Delta is the Object ID"
        );
        assert_eq!(seen.subgroup_id, None, "Section 11.4.4.2: a marker carries no Subgroup ID");
        assert_eq!(
            seen.publisher_priority,
            Some(PRIORITY),
            "a marker reports the priority still in force, from the Object before it"
        );

        let after = reader.read_object_header(&mut cursor).unwrap();
        assert_eq!(after.group_id, 6, "the marker supplied the prior Group ID");
        assert_eq!(after.object_id, 10, "and the prior Object ID");
        assert_eq!(
            after.subgroup_id,
            Some(0),
            "the prior Subgroup ID comes from the last actual Object, across the marker"
        );
        assert_eq!(after.publisher_priority, Some(PRIORITY), "and so does the prior priority");
    }

    // A marker that is the first record on the stream has no predecessor, so
    // Section 11.4.4.1's first-Object rule makes both fields absolute — which
    // is where the two readings of Section 11.4.4.2 agree.
    let mut wire = Vec::new();
    FetchObjectHeader {
        serialization_flags: vi(0x20C),
        group_id_delta: Some(vi(5)),
        subgroup_id: None,
        object_id_delta: Some(vi(10)),
        publisher_priority: None,
        properties: None,
        payload_length: vi(0),
    }
    .encode(&mut wire)
    .unwrap();
    let mut reader = FetchObjectReader::new(GroupOrder::Ascending);
    let first = reader.read_object_header(&mut &wire[..]).unwrap();
    assert_eq!((first.group_id, first.object_id), (5, 10));
    assert_eq!(
        first.publisher_priority, None,
        "no Object has stated a priority yet, and a marker states none of its own"
    );
}

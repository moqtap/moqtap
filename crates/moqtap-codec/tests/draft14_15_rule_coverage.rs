//! Wire rules the draft-14 and draft-15 codecs enforce, each observed through a
//! consequence rather than through the field that carries it.
//!
//! Six rules live here:
//!
//! * A draft-15 subgroup header writes its Publisher Priority because its own
//!   Type byte says the field is there, not because the struct happens to hold
//!   one. The two disagree in both directions, and either disagreement shifts
//!   every byte after the header.
//! * A draft-15 data stream or datagram Type is compared as the varint that
//!   arrived, not as its low octet. Truncating aliases an undefined Type onto a
//!   defined one instead of refusing it.
//! * A draft-15 datagram whose Type announces extensions must carry some. The
//!   same zero-length block is legal on a subgroup stream, and a check that
//!   refuses both breaks frames the draft spells out.
//! * A draft-15 object carrying extension headers beside a status other than
//!   Normal is reported rather than refused, except by the one encoder that has
//!   an unchecked twin. The frame is well formed, so the codec must stay able to
//!   read it, write it back byte for byte, and say that it is a violation; only
//!   `DatagramHeader::encode_checked` refuses, because `encode` still stands
//!   beside it for verbatim reproduction.
//! * A draft-15 FETCH's body must be the one its Fetch Type names.
//! * Repeating a Parameter Type is forbidden to a sender and only sometimes to a
//!   receiver, on both draft-14 and draft-15. The asymmetry is the rule, and a
//!   test here fails if either side is collapsed into the other.
//!
//! Each test's docstring records the failures observed by patching the defect
//! back into the codec and running it, so the gate is known to be load-bearing
//! rather than assumed to be. The recorded blocks give the test's own path and
//! the panic message and stop there: the file-and-line coordinate the harness
//! prints alongside them moves whenever these comments are edited, and a
//! coordinate that drifts is worse than no coordinate at all.
//!
//! The duplicate-parameter suite is generated for both drafts from one macro, so
//! each of its ablations was applied to draft-14 and draft-15 together and both
//! failures are recorded.

#![cfg(all(feature = "draft14", feature = "draft15"))]

use bytes::Buf;
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;

fn vi(v: u64) -> VarInt {
    VarInt::from_u64(v).unwrap()
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

// ── The Publisher Priority follows the Type byte ────────────

mod subgroup_priority_follows_the_type_byte {
    use super::*;
    use moqtap_codec::draft15::data_stream::{
        SubgroupHeader, SubgroupObject, SubgroupObjectReader,
    };

    fn header(header_type: u8, publisher_priority: Option<u8>) -> SubgroupHeader {
        SubgroupHeader {
            header_type,
            track_alias: vi(1),
            group_id: vi(2),
            subgroup_id: vi(0),
            publisher_priority,
        }
    }

    fn object() -> SubgroupObject {
        SubgroupObject {
            object_id: vi(9),
            extension_headers: Vec::new(),
            payload_length: vi(4),
            object_status: None,
            payload: b"beef".to_vec(),
        }
    }

    /// Write a header and one object, then read both back off the same bytes.
    ///
    /// The object is what makes this a consequence and not a field comparison.
    /// A header that spends the wrong number of bytes on its priority leaves the
    /// reader positioned inside the object that follows, and the object it
    /// returns — if it returns one — is not the object that was written.
    fn round_trip(header: &SubgroupHeader) -> (u64, Vec<u8>, usize) {
        let written = object();
        let mut bytes = Vec::new();
        header.encode(&mut bytes);
        let mut writer = SubgroupObjectReader::new(header);
        writer.write_object(&written, &mut bytes).expect("write object");

        let mut cursor = &bytes[..];
        let decoded_header = SubgroupHeader::decode(&mut cursor).expect("header decode");
        let mut reader = SubgroupObjectReader::new(&decoded_header);
        let decoded = reader.read_object(&mut cursor).expect("object decode");
        (decoded.object_id.into_inner(), decoded.payload, cursor.remaining())
    }

    /// Type 0x10 leaves the 0x20 bit clear, so a Publisher Priority byte is on
    /// the wire whatever the struct holds. A `None` beside it is written as a
    /// zero rather than dropped.
    ///
    /// Observed by making `SubgroupHeader::encode` write the byte only when the
    /// `Option` is populated — `if let Some(p) = self.publisher_priority` in
    /// place of the `has_priority` test — which fails this with:
    ///
    /// ```text
    /// ---- subgroup_priority_follows_the_type_byte::a_type_that_declares_a_priority_always_spends_a_byte_on_it stdout ----
    /// object decode: UnexpectedEnd
    /// ```
    ///
    /// The byte the header does not spend is the object's Object ID delta, so
    /// the reader takes the delta for a priority, the extension-or-length varint
    /// for a delta, and the first payload byte for a length. It asks for
    /// ninety-eight bytes of payload from a buffer holding four.
    #[test]
    fn a_type_that_declares_a_priority_always_spends_a_byte_on_it() {
        let (object_id, payload, left_over) = round_trip(&header(0x10, None));
        assert_eq!(object_id, 9, "the object after the header decoded as a different object");
        assert_eq!(
            payload, b"beef",
            "the object after the header decoded with a different payload"
        );
        assert_eq!(left_over, 0, "bytes were left over after the object");
    }

    /// Type 0x30 sets the 0x20 bit, so no Publisher Priority byte is on the
    /// wire. A populated `Option` beside it is dropped rather than written.
    ///
    /// Observed the same way, with the same one-line change, which fails this
    /// with:
    ///
    /// ```text
    /// ---- subgroup_priority_follows_the_type_byte::a_type_that_declares_no_priority_never_spends_a_byte_on_one stdout ----
    /// object decode: UnexpectedEnd
    /// ```
    ///
    /// The extra byte shifts the stream the other way: the reader takes the
    /// priority for the first object's Object ID delta and every field after it
    /// moves up one.
    #[test]
    fn a_type_that_declares_no_priority_never_spends_a_byte_on_one() {
        let (object_id, payload, left_over) = round_trip(&header(0x30, Some(7)));
        assert_eq!(object_id, 9, "the object after the header decoded as a different object");
        assert_eq!(
            payload, b"beef",
            "the object after the header decoded with a different payload"
        );
        assert_eq!(left_over, 0, "bytes were left over after the object");
    }

    /// The checked encoder refuses the disagreement outright, rather than
    /// resolving it the way the infallible one has to.
    ///
    /// Observed by dropping the `has_priority() != publisher_priority.is_some()`
    /// arm from `SubgroupHeader::encode_checked`, which fails this with:
    ///
    /// ```text
    /// ---- subgroup_priority_follows_the_type_byte::the_checked_encoder_refuses_a_header_that_disagrees_with_itself stdout ----
    /// a type declaring a priority accepted a header holding none
    /// ```
    #[test]
    fn the_checked_encoder_refuses_a_header_that_disagrees_with_itself() {
        let mut buf = Vec::new();
        assert!(
            header(0x10, None).encode_checked(&mut buf).is_err(),
            "a type declaring a priority accepted a header holding none"
        );
        assert!(buf.is_empty(), "a refused header still wrote bytes");
        assert!(
            header(0x30, Some(7)).encode_checked(&mut buf).is_err(),
            "a type declaring no priority accepted a header holding one"
        );
        assert!(buf.is_empty(), "a refused header still wrote bytes");
        assert!(
            header(0x10, Some(7)).encode_checked(&mut buf).is_ok(),
            "a header that agrees with its own type byte was refused"
        );
    }
}

// ── A Type is the varint that arrived, not its low octet ────

mod data_stream_types_are_not_truncated {
    use super::*;
    use moqtap_codec::draft15::data_stream::{DatagramHeader, SubgroupHeader};

    /// A subgroup Type of 0x110 is not a subgroup Type of 0x10.
    ///
    /// Draft-15 Section 10.4.2 Table 6 assigns twenty-four Type values and says
    /// there are twenty-four; 0x110 is not among them. It is spelled as the
    /// two-byte varint 0x41 0x10, whose low octet is 0x10, so a decoder that
    /// narrows the field to `u8` before comparing reads an undefined stream as a
    /// plain subgroup header and hands its objects to the application.
    ///
    /// The consequence is observed as the pair: the short form parses, the long
    /// form does not, and so the two cannot be confused.
    ///
    /// Observed by restoring the truncation in `SubgroupHeader::decode` —
    /// `let header_type = VarInt::decode(buf)?.into_inner() as u8;` followed by
    /// the assignment test on that byte — which fails this with:
    ///
    /// ```text
    /// ---- data_stream_types_are_not_truncated::a_long_form_subgroup_type_does_not_alias_onto_a_short_one stdout ----
    /// subgroup type 0x110 was accepted as though it were 0x10
    /// ```
    #[test]
    fn a_long_form_subgroup_type_does_not_alias_onto_a_short_one() {
        let short = hex("10010280");
        let long = hex("4110010280");

        let mut cursor = &short[..];
        let defined = SubgroupHeader::decode(&mut cursor).expect("type 0x10 is defined");
        assert_eq!(defined.header_type, 0x10);

        let mut cursor = &long[..];
        assert!(
            SubgroupHeader::decode(&mut cursor).is_err(),
            "subgroup type 0x110 was accepted as though it were 0x10"
        );
    }

    /// The reserved Subgroup ID mode is refused as part of the same check.
    ///
    /// Section 10.4.2 gives the 0x06 field four values and assigns three of
    /// them, which is what leaves 0x16, 0x17, 0x1E, 0x1F, 0x36, 0x37, 0x3E and
    /// 0x3F out of the twenty-four. The mode is worth refusing rather than
    /// ignoring because it is the field that says whether a Subgroup ID varint
    /// follows the Group ID: guessing wrong shifts every later field by that
    /// varint's width.
    ///
    /// Observed by relaxing `subgroup_type_is_assigned` to test only the base —
    /// dropping the `(ty & 0x06) != 0x06` conjunct — which fails this with:
    ///
    /// ```text
    /// ---- data_stream_types_are_not_truncated::the_reserved_subgroup_id_mode_is_refused stdout ----
    /// subgroup type 0x16 was accepted, and its Subgroup ID mode has no framing
    /// ```
    #[test]
    fn the_reserved_subgroup_id_mode_is_refused() {
        for reserved in [0x16u8, 0x17, 0x1E, 0x1F, 0x36, 0x37, 0x3E, 0x3F] {
            let mut bytes = vec![reserved];
            bytes.extend_from_slice(&hex("010280"));
            let mut cursor = &bytes[..];
            assert!(
                SubgroupHeader::decode(&mut cursor).is_err(),
                "subgroup type {reserved:#04x} was accepted, and its Subgroup ID mode \
                 has no framing"
            );

            let header = SubgroupHeader {
                header_type: reserved,
                track_alias: vi(1),
                group_id: vi(2),
                subgroup_id: vi(0),
                publisher_priority: if reserved & 0x20 == 0 { Some(0x80) } else { None },
            };
            let mut buf = Vec::new();
            assert!(
                header.encode_checked(&mut buf).is_err(),
                "the checked encoder wrote subgroup type {reserved:#04x}"
            );
        }
    }

    /// A datagram Type of 0x100 is not a datagram Type of 0x00.
    ///
    /// Section 10.3.1 Table 5 assigns twenty-four Type values; 0x100 is not one
    /// of them, and its low octet is the most ordinary Type the draft has. A
    /// truncating decoder therefore reads a greased or future datagram as a
    /// payload-bearing object with a priority and no extensions.
    ///
    /// Observed by restoring the truncation in `DatagramHeader::decode` —
    /// `let datagram_type = VarInt::decode(buf)?.into_inner() as u8;` before the
    /// assignment test — which fails this with:
    ///
    /// ```text
    /// ---- data_stream_types_are_not_truncated::a_long_form_datagram_type_does_not_alias_onto_a_short_one stdout ----
    /// datagram type 0x100 was accepted as though it were 0x00
    /// ```
    #[test]
    fn a_long_form_datagram_type_does_not_alias_onto_a_short_one() {
        let short = hex("0001020380");
        // 0x41 0x00 is the two-byte varint spelling of 0x100.
        let long = hex("410001020380");

        let mut cursor = &short[..];
        let defined = DatagramHeader::decode(&mut cursor).expect("type 0x00 is defined");
        assert_eq!(defined.datagram_type, 0x00);

        let mut cursor = &long[..];
        assert!(
            DatagramHeader::decode(&mut cursor).is_err(),
            "datagram type 0x100 was accepted as though it were 0x00"
        );
    }

    /// A datagram may not be both a status and an end-of-group marker.
    ///
    /// Table 5 lists the eight status Types it assigns — 0x20, 0x21, 0x24,
    /// 0x25, 0x28, 0x29, 0x2C and 0x2D — and every one of them leaves the
    /// end-of-group bit clear. A status datagram carries no object, so there is
    /// nothing for it to mark the end of a group with.
    ///
    /// Observed by relaxing `datagram_type_is_assigned` to test only the form
    /// bits — dropping the `ty & 0x22 != 0x22` conjunct — which fails this with:
    ///
    /// ```text
    /// ---- data_stream_types_are_not_truncated::a_status_datagram_may_not_also_end_a_group stdout ----
    /// datagram type 0x2e was accepted as both a status and an end-of-group marker
    /// ```
    ///
    /// The loop reports 0x2E rather than 0x22 because the four combined Types
    /// that keep the Object ID and Priority fields on the wire run out of bytes
    /// before reaching the status field, and are refused for that reason
    /// instead. 0x2E omits both fields, so its status parses and the datagram is
    /// accepted whole — which is the case the rule is actually about.
    #[test]
    fn a_status_datagram_may_not_also_end_a_group() {
        for combined in [0x22u8, 0x23, 0x26, 0x27, 0x2A, 0x2B, 0x2E, 0x2F] {
            let mut bytes = vec![combined];
            bytes.extend_from_slice(&hex("01020380"));
            let mut cursor = &bytes[..];
            assert!(
                DatagramHeader::decode(&mut cursor).is_err(),
                "datagram type {combined:#04x} was accepted as both a status and an \
                 end-of-group marker"
            );
        }
    }
}

// ── The datagram extension block, and the subgroup one ──────

mod datagram_extension_block {
    use super::*;
    use moqtap_codec::draft15::data_stream::{
        DatagramHeader, SubgroupHeader, SubgroupObject, SubgroupObjectReader,
    };

    fn datagram(datagram_type: u8, extension_headers: Vec<u8>) -> DatagramHeader {
        DatagramHeader {
            datagram_type,
            track_alias: vi(1),
            group_id: vi(2),
            object_id: vi(3),
            publisher_priority: Some(0x80),
            extension_headers,
            object_status: None,
        }
    }

    /// A datagram whose Type announces extensions may not carry a zero-length
    /// block.
    ///
    /// Section 10.3.1: "If an endpoint receives a datagram with Extensions
    /// Present as 'Yes' and a Extension Headers Length of 0, it MUST close the
    /// session with a PROTOCOL_VIOLATION." The two spellings of "no extensions"
    /// are not interchangeable on a datagram, because the Type byte belongs to
    /// that one datagram and can simply say so.
    ///
    /// The consequence is spelled out rather than asserted on the error alone:
    /// the infallible encoder does write those bytes, and this shows that what
    /// it writes is a frame the module's own decoder refuses. That is what makes
    /// the checked encoder's refusal a fix and not a preference.
    ///
    /// Observed by dropping the extension-block arm from
    /// `DatagramHeader::encode_checked`, which fails this with:
    ///
    /// ```text
    /// ---- datagram_extension_block::a_datagram_announcing_extensions_must_carry_some stdout ----
    /// the checked encoder wrote a datagram its own decoder refuses
    /// ```
    #[test]
    fn a_datagram_announcing_extensions_must_carry_some() {
        let empty_block = datagram(0x01, Vec::new());

        let mut unchecked = Vec::new();
        empty_block.encode(&mut unchecked);
        let mut cursor = &unchecked[..];
        assert!(
            DatagramHeader::decode(&mut cursor).is_err(),
            "the bytes this case is about are ones the decoder accepts, so it proves nothing"
        );

        let mut checked = Vec::new();
        assert!(
            empty_block.encode_checked(&mut checked).is_err(),
            "the checked encoder wrote a datagram its own decoder refuses"
        );
        assert!(checked.is_empty(), "a refused datagram still wrote bytes");
    }

    /// Extension bytes with the Type's extensions bit clear are refused rather
    /// than dropped.
    ///
    /// Observed by dropping the same arm, which fails this with:
    ///
    /// ```text
    /// ---- datagram_extension_block::extensions_the_type_byte_cannot_carry_are_refused stdout ----
    /// extension bytes were accepted under a type that cannot carry them, and the encoder would drop them in silence
    /// ```
    #[test]
    fn extensions_the_type_byte_cannot_carry_are_refused() {
        let orphaned = datagram(0x00, vec![0x3c, 0x01]);

        let mut unchecked = Vec::new();
        orphaned.encode(&mut unchecked);
        let mut cursor = &unchecked[..];
        let round_tripped = DatagramHeader::decode(&mut cursor).expect("decode");
        assert!(
            round_tripped.extension_headers.is_empty(),
            "this case is about extensions that do not reach the wire"
        );

        let mut checked = Vec::new();
        assert!(
            orphaned.encode_checked(&mut checked).is_err(),
            "extension bytes were accepted under a type that cannot carry them, and \
             the encoder would drop them in silence"
        );
    }

    /// The same zero-length block is legal on a subgroup stream, and stays so.
    ///
    /// Section 10.4.2: "When Extensions Present is Yes, the Extensions structure
    /// defined in Section 10.2.1.2 is present in all Objects in this subgroup.
    /// Objects with no extensions set Extension Headers Length to 0." The Type
    /// byte there is fixed for the whole stream, so a zero-length block is the
    /// only way one object among many can say it carries nothing.
    ///
    /// This is the guard on the fix above rather than a rule of its own: it
    /// fails if the datagram check is ever generalised to subgroup objects.
    ///
    /// Observed by adding the datagram's `extension_headers.is_empty()` refusal
    /// to `SubgroupObjectReader::write_object`, which fails this with:
    ///
    /// ```text
    /// ---- datagram_extension_block::a_subgroup_object_may_carry_a_zero_length_block stdout ----
    /// write object: InvalidField
    /// ```
    #[test]
    fn a_subgroup_object_may_carry_a_zero_length_block() {
        let header = SubgroupHeader {
            header_type: 0x11,
            track_alias: vi(1),
            group_id: vi(0),
            subgroup_id: vi(0),
            publisher_priority: Some(0x80),
        };
        let object = SubgroupObject {
            object_id: vi(0),
            extension_headers: Vec::new(),
            payload_length: vi(4),
            object_status: None,
            payload: hex("deadbeef"),
        };

        let mut bytes = Vec::new();
        header.encode(&mut bytes);
        let mut writer = SubgroupObjectReader::new(&header);
        writer.write_object(&object, &mut bytes).expect("write object");
        assert_eq!(bytes, hex("11010080000004deadbeef"));

        let mut cursor = &bytes[..];
        let back = SubgroupHeader::decode(&mut cursor).expect("header decode");
        let mut reader = SubgroupObjectReader::new(&back);
        let read = reader.read_object(&mut cursor).expect("object decode");
        assert_eq!(read.payload, hex("deadbeef"));
        assert!(read.extension_headers.is_empty());
        assert_eq!(cursor.remaining(), 0);
    }
}

// ── Extensions beside a status other than Normal ────────────

mod extensions_beside_a_non_normal_status {
    use super::*;
    use moqtap_codec::draft15::data_stream::{
        DatagramHeader, SubgroupHeader, SubgroupObject, SubgroupObjectReader,
    };
    use moqtap_codec::draft15::types::ObjectStatus;

    /// The corpus frame this rule is about, shipped as
    /// `subgroup-extensions-status-object`.
    ///
    /// Subgroup type 0x11 — extensions present, Subgroup ID mode zero, priority
    /// present — track alias 1, group 0, priority 0x80. Then one object: delta
    /// 0, a two-byte extension block `3c 01` holding Prior Group ID Gap, a
    /// payload length of 0, and status 0x3, End of Group.
    const CAPTURED_VIOLATION: &str = "1101008000023c010003";

    fn extensions_header() -> SubgroupHeader {
        SubgroupHeader {
            header_type: 0x11,
            track_alias: vi(1),
            group_id: vi(0),
            subgroup_id: vi(0),
            publisher_priority: Some(0x80),
        }
    }

    /// The frame decodes, and the object reports itself as a violation.
    ///
    /// Draft-15 Section 10.2.1.2: "Any Object with status Normal can have
    /// extension headers. If an endpoint receives extension headers on Objects
    /// with status that is not Normal, it MUST close the session with a
    /// PROTOCOL_VIOLATION." The status named is any status but Normal, which is
    /// broader than the rule drafts 11 through 14 state — there it is Object
    /// Does Not Exist alone, and extensions beside End of Group stay legal.
    /// That difference is deliberate: those drafts refuse the narrow form on
    /// decode, and drafts 15 through 19 report the broad one instead.
    ///
    /// The frame is well formed: every length is honest and every field parses.
    /// What makes it a violation is what it says, not how it is framed, so the
    /// decoder reports it and the endpoint acts on it. A decoder that refused it
    /// could not report the violation at all.
    ///
    /// Observed by making `SubgroupObjectReader::read_object` call
    /// `check_extensions_against_status_on_encode`, which fails this with:
    ///
    /// ```text
    /// ---- extensions_beside_a_non_normal_status::a_captured_violation_decodes_and_reports_itself stdout ----
    /// object decode: InvalidField
    /// ```
    ///
    /// and by inverting the comparison in
    /// `SubgroupObject::extensions_permitted` to `!=`, so the violation reports
    /// itself as permitted, which fails it with:
    ///
    /// ```text
    /// ---- extensions_beside_a_non_normal_status::a_captured_violation_decodes_and_reports_itself stdout ----
    /// the object did not report extensions beside End of Group as forbidden
    /// ```
    ///
    /// Dropping the status test the other way — leaving
    /// `self.extension_headers.is_empty()` alone, so every object carrying
    /// extensions reports forbidden — leaves this test passing and is caught by
    /// `the_rule_is_about_the_pair_and_not_about_either_half` instead, with:
    ///
    /// ```text
    /// ---- extensions_beside_a_non_normal_status::the_rule_is_about_the_pair_and_not_about_either_half stdout ----
    /// extensions at Normal are permitted
    /// ```
    #[test]
    fn a_captured_violation_decodes_and_reports_itself() {
        let bytes = hex(CAPTURED_VIOLATION);
        let mut cursor = &bytes[..];

        let header = SubgroupHeader::decode(&mut cursor).expect("header decode");
        let mut reader = SubgroupObjectReader::new(&header);
        let object = reader.read_object(&mut cursor).expect("object decode");

        assert_eq!(
            object.extension_headers,
            hex("3c01"),
            "the decoder dropped the extension bytes the capture carried"
        );
        assert_eq!(
            object.object_status,
            Some(ObjectStatus::EndOfGroup),
            "the decoder lost the status that makes this frame a violation"
        );
        assert!(
            !object.extensions_permitted(),
            "the object did not report extensions beside End of Group as forbidden"
        );
        assert_eq!(cursor.remaining(), 0, "the frame did not decode whole");
    }

    /// And it re-encodes to the bytes it came from.
    ///
    /// This is the half that keeps the codec able to reproduce a capture, and
    /// the half that fails if the subgroup writer is ever taught to refuse the
    /// object. `write_object` is the only writer a subgroup object has — there
    /// is no unchecked twin to fall back on — so a refusal there would leave a
    /// captured violation impossible to re-emit. The corpus ships this exact
    /// frame, and `vectors_re_encode_byte_identically` walks it.
    ///
    /// Observed by adding the refusal to `SubgroupObjectReader::write_object`,
    /// which fails this with:
    ///
    /// ```text
    /// ---- extensions_beside_a_non_normal_status::a_captured_violation_re_encodes_byte_for_byte stdout ----
    /// the writer must be able to reproduce a frame the reader accepts: InvalidField
    /// ```
    ///
    /// The same change takes the corpus walk down with it, which is the conflict
    /// this shape exists to avoid:
    ///
    /// ```text
    /// ---- draft15::data_stream::tests::vectors_re_encode_byte_identically stdout ----
    /// write failed: InvalidField
    /// ```
    #[test]
    fn a_captured_violation_re_encodes_byte_for_byte() {
        let bytes = hex(CAPTURED_VIOLATION);
        let mut cursor = &bytes[..];
        let header = SubgroupHeader::decode(&mut cursor).expect("header decode");
        let mut reader = SubgroupObjectReader::new(&header);
        let object = reader.read_object(&mut cursor).expect("object decode");

        let mut out = Vec::new();
        header.encode(&mut out);
        let mut writer = SubgroupObjectReader::new(&header);
        writer.write_object(&object, &mut out).unwrap_or_else(|e| {
            panic!("the writer must be able to reproduce a frame the reader accepts: {e:?}")
        });

        assert_eq!(out, bytes, "the object did not survive a decode/encode round trip");
    }

    /// The framing-only reader answers the same question without the block.
    ///
    /// A relay that forwards an object verbatim reads it through
    /// `read_object_meta` and never copies the extension bytes, so asking
    /// whether the object is a violation must not require having them. The rule
    /// turns on whether the block is empty, and the declared length says that on
    /// its own.
    ///
    /// Observed by making `SubgroupObjectReader::read_object_meta` call
    /// `check_extensions_against_status_on_encode`, which fails this with:
    ///
    /// ```text
    /// ---- extensions_beside_a_non_normal_status::the_framing_reader_reports_without_the_block stdout ----
    /// object framing: InvalidField
    /// ```
    ///
    /// and by making `SubgroupObjectMeta::extensions_permitted` ignore the
    /// status, which fails it with:
    ///
    /// ```text
    /// ---- extensions_beside_a_non_normal_status::the_framing_reader_reports_without_the_block stdout ----
    /// assertion `left == right` failed: the meta did not report extensions beside End of Group as forbidden
    /// ```
    #[test]
    fn the_framing_reader_reports_without_the_block() {
        let bytes = hex(CAPTURED_VIOLATION);
        let mut cursor = &bytes[..];

        let header = SubgroupHeader::decode(&mut cursor).expect("header decode");
        let mut reader = SubgroupObjectReader::new(&header);
        let meta = reader.read_object_meta(&mut cursor).expect("object framing");

        assert_eq!(meta.extension_headers_len, 2);
        assert_eq!(meta.status, Some(ObjectStatus::EndOfGroup.as_u64()));
        assert_eq!(
            meta.extensions_permitted(),
            Some(false),
            "the meta did not report extensions beside End of Group as forbidden"
        );
        assert_eq!(cursor.remaining(), 0, "the frame did not decode whole");
    }

    /// A datagram carrying the same violation decodes and reports it too.
    ///
    /// Observed by making `DatagramHeader::decode` call
    /// `check_extensions_against_status_on_encode`, which fails this with:
    ///
    /// ```text
    /// ---- extensions_beside_a_non_normal_status::a_captured_datagram_violation_decodes_and_reports_itself stdout ----
    /// datagram decode: InvalidField
    /// ```
    #[test]
    fn a_captured_datagram_violation_decodes_and_reports_itself() {
        // Type 0x21, track alias 1, group 2, object 3, priority 0x80, a
        // two-byte extension block, then status 0x03.
        let bytes = hex("210102038002aabb03");
        let mut cursor = &bytes[..];
        let datagram = DatagramHeader::decode(&mut cursor).expect("datagram decode");

        assert_eq!(datagram.extension_headers, hex("aabb"));
        assert_eq!(datagram.object_status, Some(ObjectStatus::EndOfGroup));
        assert!(
            !datagram.extensions_permitted(),
            "the datagram did not report extensions beside End of Group as forbidden"
        );
        assert_eq!(cursor.remaining(), 0, "the frame did not decode whole");
    }

    /// The datagram is the one carrier whose checked encoder refuses it.
    ///
    /// It is the only carrier with two encoders: `encode` reproduces bytes
    /// verbatim and `encode_checked` is opt-in strictness, so refusing in the
    /// latter costs nothing a capture needs. The consequence is spelled out —
    /// `encode` still produces the frame and `decode` still reads it back — so
    /// the refusal is a choice about what this codec originates, not a claim
    /// that the bytes are unreadable.
    ///
    /// Observed by removing the `check_extensions_against_status_on_encode` call
    /// from `DatagramHeader::encode_checked`, which fails this with:
    ///
    /// ```text
    /// ---- extensions_beside_a_non_normal_status::the_checked_datagram_encoder_refuses_the_violation stdout ----
    /// a status datagram carrying extension headers was written to the wire
    /// ```
    #[test]
    fn the_checked_datagram_encoder_refuses_the_violation() {
        // Type 0x21: status datagram, extensions present, Object ID and
        // Priority both on the wire.
        let violation = DatagramHeader {
            datagram_type: 0x21,
            track_alias: vi(1),
            group_id: vi(2),
            object_id: vi(3),
            publisher_priority: Some(0x80),
            extension_headers: hex("aabb"),
            object_status: Some(ObjectStatus::EndOfGroup),
        };

        // The unchecked encoder still reproduces it, and the decoder still
        // reads it back, so nothing about the frame is unrepresentable.
        let mut verbatim = Vec::new();
        violation.encode(&mut verbatim);
        let mut cursor = &verbatim[..];
        DatagramHeader::decode(&mut cursor).expect("the frame is well formed");

        let mut checked = Vec::new();
        assert!(
            violation.encode_checked(&mut checked).is_err(),
            "a status datagram carrying extension headers was written to the wire"
        );
        assert!(checked.is_empty(), "a refused datagram still wrote bytes");
    }

    /// The rule is about the pair, not about either half.
    ///
    /// Without this a predicate could be satisfied by one answering "forbidden"
    /// to every object carrying extensions, or to every non-Normal object.
    #[test]
    fn the_rule_is_about_the_pair_and_not_about_either_half() {
        // Extensions at Normal are fine. A non-zero payload length is what
        // makes the object Normal, per Section 10.2.1.1.
        let normal = SubgroupObject {
            object_id: vi(0),
            extension_headers: hex("3c01"),
            payload_length: vi(4),
            object_status: None,
            payload: hex("deadbeef"),
        };
        assert!(normal.extensions_permitted(), "extensions at Normal are permitted");

        for status in
            [ObjectStatus::ObjectDoesNotExist, ObjectStatus::EndOfGroup, ObjectStatus::EndOfTrack]
        {
            // No extensions is fine at any status.
            let bare = SubgroupObject {
                object_id: vi(0),
                extension_headers: Vec::new(),
                payload_length: vi(0),
                object_status: Some(status),
                payload: Vec::new(),
            };
            assert!(
                bare.extensions_permitted(),
                "an object with no extensions is permitted at {status:?}"
            );

            let violation = SubgroupObject { extension_headers: hex("3c01"), ..bare };
            assert!(
                !violation.extensions_permitted(),
                "extensions beside {status:?} are forbidden"
            );
        }

        // And the permitted shape still writes, because the writer does not
        // judge either way.
        let header = extensions_header();
        let mut buf = Vec::new();
        let mut writer = SubgroupObjectReader::new(&header);
        writer.write_object(&normal, &mut buf).expect("a Normal object writes");
        assert!(!buf.is_empty());
    }
}

// ── A FETCH's body is the one its Fetch Type names ──────────

mod fetch_discriminator {
    use super::*;
    use moqtap_codec::draft15::message::{ControlMessage, Fetch, FetchPayload, FetchType};

    fn standalone_body() -> FetchPayload {
        FetchPayload::Standalone {
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            start_group: vi(1),
            start_object: vi(0),
            end_group: vi(2),
            end_object: vi(0),
        }
    }

    fn joining_body() -> FetchPayload {
        FetchPayload::Joining { joining_request_id: vi(4), joining_start: vi(1) }
    }

    fn fetch(fetch_type: FetchType, fetch_payload: FetchPayload) -> ControlMessage {
        ControlMessage::Fetch(Fetch {
            request_id: vi(7),
            fetch_type,
            fetch_payload,
            parameters: Vec::new(),
        })
    }

    /// A Fetch Type of Standalone beside a joining body never reaches the wire.
    ///
    /// Section 9.16 gives FETCH three types and Section 9.16.3 gives it two
    /// alternative bodies that the type selects between. The encoder writes the
    /// body it holds and the decoder reads the body the type names, so a value
    /// that disagrees with itself does not survive its own round trip: the
    /// joining request id and start land where a Track Namespace and a Track
    /// Name belong.
    ///
    /// The consequence is spelled out: the mismatched pair either fails to parse
    /// or parses as a different message, and either way the fix is to refuse it
    /// before a byte is written.
    ///
    /// Observed by removing the `check_discriminators` call from
    /// `ControlMessage::encode`, which fails this with:
    ///
    /// ```text
    /// ---- fetch_discriminator::a_standalone_type_beside_a_joining_body_is_refused stdout ----
    /// a FETCH whose type and body disagree was written to the wire
    /// ```
    #[test]
    fn a_standalone_type_beside_a_joining_body_is_refused() {
        let mut buf = Vec::new();
        let message = fetch(FetchType::Standalone, joining_body());
        assert!(
            message.encode(&mut buf).is_err(),
            "a FETCH whose type and body disagree was written to the wire"
        );
        assert!(buf.is_empty(), "a refused FETCH still wrote bytes");
    }

    /// And the mirror: a joining type beside a standalone body.
    ///
    /// Observed the same way, which fails this with:
    ///
    /// ```text
    /// ---- fetch_discriminator::a_joining_type_beside_a_standalone_body_is_refused stdout ----
    /// a FETCH whose type and body disagree was written to the wire
    /// ```
    #[test]
    fn a_joining_type_beside_a_standalone_body_is_refused() {
        for fetch_type in [FetchType::RelativeJoining, FetchType::AbsoluteJoining] {
            let mut buf = Vec::new();
            assert!(
                fetch(fetch_type, standalone_body()).encode(&mut buf).is_err(),
                "a FETCH whose type and body disagree was written to the wire"
            );
            assert!(buf.is_empty(), "a refused FETCH still wrote bytes");
        }
    }

    /// Every agreeing pair still round-trips, so the gate above refuses the
    /// disagreement and not the message.
    #[test]
    fn a_fetch_whose_type_names_its_own_body_round_trips() {
        for (fetch_type, body) in [
            (FetchType::Standalone, standalone_body()),
            (FetchType::RelativeJoining, joining_body()),
            (FetchType::AbsoluteJoining, joining_body()),
        ] {
            let message = fetch(fetch_type, body);
            let mut buf = Vec::new();
            message.encode(&mut buf).expect("encode");
            let mut cursor = &buf[..];
            let back = ControlMessage::decode(&mut cursor).expect("decode");
            assert_eq!(back, message);
            assert_eq!(cursor.remaining(), 0);
        }
    }
}

// ── Duplicate parameters, sender and receiver ───────────────

/// A Parameter Type this codec has never heard of, on either draft.
///
/// Odd, so the Key-Value-Pair encoding gives it a length-prefixed value, and
/// below 0x40, so it occupies one byte as a varint and a hand-built frame stays
/// readable.
const UNKNOWN_TYPE: u64 = 0x2F;

/// AUTHORIZATION TOKEN, the one type both drafts let a sender repeat.
const AUTHORIZATION_TOKEN: u64 = 0x03;

/// A version-specific Parameter Type both drafts name: DELIVERY TIMEOUT.
const KNOWN_MESSAGE_TYPE: u64 = 0x02;

/// A setup Parameter Type both drafts name, and neither names in the
/// version-specific namespace: PATH.
const KNOWN_SETUP_TYPE: u64 = 0x01;

/// A well-formed Token structure carrying `payload`.
///
/// The AUTHORIZATION TOKEN parameter's value is a Token, not opaque bytes: an
/// Alias Type followed by the fields that Alias Type promises. USE_VALUE (0x3)
/// is the shortest complete form - no Alias, a Token Type and the value - and
/// Token Type 0 is the one the drafts reserve for a meaning the two peers settle
/// out of band, so a fixture using it commits to nothing. Both integers are
/// below 0x40 and take one byte under either variable-length integer encoding,
/// which is what lets one helper serve every draft here.
///
/// Arbitrary bytes cannot stand in for a token. A value of this type that does
/// not decode as a Token is the case the drafts require a close over, so a
/// fixture built from arbitrary bytes would be testing the refusal rather than
/// the rule beside it.
fn token_value(payload: &[u8]) -> Vec<u8> {
    let mut value = vec![0x03, 0x00];
    value.extend_from_slice(payload);
    value
}

/// A parameter with a length-prefixed value, for the odd types.
///
/// AUTHORIZATION TOKEN's value is a Token structure rather than opaque bytes,
/// and both drafts require a close over one that cannot be decoded, so it is
/// the one odd type here that cannot take the filler value.
fn bytes_param(key: u64) -> KeyValuePair {
    let value = if key == AUTHORIZATION_TOKEN { token_value(b"v") } else { b"v".to_vec() };
    KeyValuePair { key: vi(key), value: KvpValue::Bytes(value) }
}

fn varint_param(key: u64) -> KeyValuePair {
    KeyValuePair { key: vi(key), value: KvpValue::Varint(vi(9)) }
}

fn param(key: u64) -> KeyValuePair {
    if key.is_multiple_of(2) {
        varint_param(key)
    } else {
        bytes_param(key)
    }
}

/// Wrap a payload in the control-message framing both drafts share: a Type as a
/// varint, then a sixteen-bit length, then the payload.
fn frame(type_id: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    vi(type_id).encode(&mut out);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// A PUBLISH_NAMESPACE carrying `parameters` verbatim, built without going
/// through an encoder.
///
/// The receiver-side tests need frames their own encoder refuses to produce,
/// which is the whole point of the asymmetry; building the bytes by hand is the
/// only way to put one in front of the decoder.
fn publish_namespace_frame(parameters: &[KeyValuePair]) -> Vec<u8> {
    let mut payload = Vec::new();
    vi(1).encode(&mut payload);
    TrackNamespace(vec![b"ns".to_vec()]).encode(&mut payload);
    KeyValuePair::encode_list(parameters, &mut payload);
    frame(0x06, &payload)
}

/// A CLIENT_SETUP carrying `parameters` verbatim.
///
/// Draft-14 puts a list of supported versions in front of them and draft-15
/// dropped it, so the two payloads differ by that list alone.
fn client_setup_frame(parameters: &[KeyValuePair], with_versions: bool) -> Vec<u8> {
    let mut payload = Vec::new();
    if with_versions {
        vi(1).encode(&mut payload);
        vi(0xff00_000e).encode(&mut payload);
    }
    KeyValuePair::encode_list(parameters, &mut payload);
    frame(0x20, &payload)
}

macro_rules! duplicate_parameter_suite {
    ($module:ident, $draft_message:path, $with_versions:expr) => {
        mod $module {
            use super::*;
            use $draft_message::{ControlMessage, PublishNamespace};

            fn publish_namespace(parameters: Vec<KeyValuePair>) -> ControlMessage {
                ControlMessage::PublishNamespace(PublishNamespace {
                    request_id: vi(1),
                    track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
                    parameters,
                })
            }

            fn parameters_of(message: &ControlMessage) -> &[KeyValuePair] {
                match message {
                    ControlMessage::PublishNamespace(m) => &m.parameters,
                    ControlMessage::ClientSetup(m) => &m.parameters,
                    other => panic!("no parameters on {other:?}"),
                }
            }

            /// The sender's rule reaches types the receiver's does not, and a
            /// single test says so from both sides.
            ///
            /// Section 9.2 states the two halves in consecutive sentences.
            /// "Senders MUST NOT repeat the same parameter type in a message
            /// unless the parameter definition explicitly allows multiple
            /// instances of that type to be sent in a single message" names no
            /// exception for types the sender does not recognise: the sender
            /// knows what it is sending. "Receivers MUST allow duplicates of
            /// unknown parameters" is the other half, and it is narrower — a
            /// receiver may refuse a repeat only of a type it can name.
            ///
            /// Collapsing the two into one check fails this whichever way it is
            /// collapsed, which is what the test is for. Making the receiver as
            /// strict as the sender fails the first half; making the sender as
            /// lenient as the receiver fails the second.
            ///
            /// Observed by pointing `decode_parameters` at
            /// `check_no_duplicate_parameters_sent`, which fails this with:
            ///
            /// ```text
            /// ---- duplicates_draft14::an_unknown_type_may_arrive_twice_but_may_not_be_sent_twice stdout ----
            /// a repeated unknown parameter type was refused on decode: DuplicateParameter(47)
            ///
            /// ---- duplicates_draft15::an_unknown_type_may_arrive_twice_but_may_not_be_sent_twice stdout ----
            /// a repeated unknown parameter type was refused on decode: DuplicateParameter(47)
            /// ```
            ///
            /// and by pointing `encode_parameters` at
            /// `check_no_duplicate_parameters_received` with the
            /// version-specific list, which fails it with:
            ///
            /// ```text
            /// ---- duplicates_draft14::an_unknown_type_may_arrive_twice_but_may_not_be_sent_twice stdout ----
            /// a repeated unknown parameter type was written to the wire
            ///
            /// ---- duplicates_draft15::an_unknown_type_may_arrive_twice_but_may_not_be_sent_twice stdout ----
            /// a repeated unknown parameter type was written to the wire
            /// ```
            #[test]
            fn an_unknown_type_may_arrive_twice_but_may_not_be_sent_twice() {
                let repeated = vec![param(UNKNOWN_TYPE), param(UNKNOWN_TYPE)];

                let wire = publish_namespace_frame(&repeated);
                let mut cursor = &wire[..];
                let decoded = ControlMessage::decode(&mut cursor).unwrap_or_else(|e| {
                    panic!("a repeated unknown parameter type was refused on decode: {e:?}")
                });
                let carried = parameters_of(&decoded);
                assert_eq!(
                    carried.len(),
                    2,
                    "the receiver dropped one copy of a duplicate it is required to allow"
                );
                assert_eq!(carried[0].key.into_inner(), UNKNOWN_TYPE);
                assert_eq!(carried[1].key.into_inner(), UNKNOWN_TYPE);

                let mut buf = Vec::new();
                assert!(
                    publish_namespace(repeated).encode(&mut buf).is_err(),
                    "a repeated unknown parameter type was written to the wire"
                );
                assert!(buf.is_empty(), "a refused message still wrote bytes");
            }

            /// A type the draft names may not repeat in either direction.
            ///
            /// Observed by dropping the `known.contains(&key)` test from
            /// `check_no_duplicate_parameters_received`, inverting it so every
            /// named type is skipped, which fails this with:
            ///
            /// ```text
            /// ---- duplicates_draft14::a_named_type_may_not_repeat_in_either_direction stdout ----
            /// a repeated DELIVERY TIMEOUT was accepted on decode
            ///
            /// ---- duplicates_draft15::a_named_type_may_not_repeat_in_either_direction stdout ----
            /// a repeated DELIVERY TIMEOUT was accepted on decode
            /// ```
            #[test]
            fn a_named_type_may_not_repeat_in_either_direction() {
                let repeated = vec![param(KNOWN_MESSAGE_TYPE), param(KNOWN_MESSAGE_TYPE)];

                let wire = publish_namespace_frame(&repeated);
                let mut cursor = &wire[..];
                assert!(
                    ControlMessage::decode(&mut cursor).is_err(),
                    "a repeated DELIVERY TIMEOUT was accepted on decode"
                );

                let mut buf = Vec::new();
                assert!(
                    publish_namespace(repeated).encode(&mut buf).is_err(),
                    "a repeated DELIVERY TIMEOUT was written to the wire"
                );
            }

            /// AUTHORIZATION TOKEN may repeat, in both directions.
            ///
            /// Section 9.2.1.1: "The AUTHORIZATION TOKEN parameter MAY be
            /// repeated within a message." That is the carve-out Section 9.2
            /// leaves open, and on this draft it is the only one taken up.
            ///
            /// Observed by removing the `REPEATABLE_PARAMETER` skip from
            /// `check_no_duplicate_parameters_sent`, which fails this with:
            ///
            /// ```text
            /// ---- duplicates_draft14::the_authorization_token_may_repeat stdout ----
            /// a repeated AUTHORIZATION TOKEN was refused on encode: DuplicateParameter(3)
            ///
            /// ---- duplicates_draft15::the_authorization_token_may_repeat stdout ----
            /// a repeated AUTHORIZATION TOKEN was refused on encode: DuplicateParameter(3)
            /// ```
            ///
            /// The code point is 0x03 on both drafts: draft-14 Section 9.2.1.1
            /// and draft-15 Section 9.2.1.1 each assign it, and each setup
            /// namespace defines its AUTHORIZATION TOKEN by reference to that
            /// section. It is not a number that can be assumed across this era —
            /// the same parameter is 0x01 on draft-11 — so each draft's own text
            /// settles it.
            #[test]
            fn the_authorization_token_may_repeat() {
                let repeated = vec![param(AUTHORIZATION_TOKEN), param(AUTHORIZATION_TOKEN)];

                let mut buf = Vec::new();
                publish_namespace(repeated.clone()).encode(&mut buf).unwrap_or_else(|e| {
                    panic!("a repeated AUTHORIZATION TOKEN was refused on encode: {e:?}")
                });

                let mut cursor = &buf[..];
                let decoded = ControlMessage::decode(&mut cursor).unwrap_or_else(|e| {
                    panic!("a repeated AUTHORIZATION TOKEN was refused on decode: {e:?}")
                });
                assert_eq!(parameters_of(&decoded).len(), 2);
                assert_eq!(cursor.remaining(), 0);
            }

            /// A SETUP is read against the setup namespace, not the
            /// version-specific one.
            ///
            /// Section 9.2.1: "since Setup parameters use a separate namespace,
            /// it is impossible for these parameters to appear in Setup
            /// messages". PATH is 0x01 in the setup namespace and is named by
            /// neither draft in the other, so a receiver that consults the wrong
            /// list treats a repeated PATH as an unknown type and carries it.
            ///
            /// Observed by pointing the CLIENT_SETUP decode arm back at
            /// `decode_parameters`, which fails this with:
            ///
            /// ```text
            /// ---- duplicates_draft14::a_setup_is_read_against_the_setup_namespace stdout ----
            /// a repeated PATH was accepted in a CLIENT_SETUP
            ///
            /// ---- duplicates_draft15::a_setup_is_read_against_the_setup_namespace stdout ----
            /// a repeated PATH was accepted in a CLIENT_SETUP
            /// ```
            #[test]
            fn a_setup_is_read_against_the_setup_namespace() {
                let repeated = vec![param(KNOWN_SETUP_TYPE), param(KNOWN_SETUP_TYPE)];

                let wire = client_setup_frame(&repeated, $with_versions);
                let mut cursor = &wire[..];
                assert!(
                    ControlMessage::decode(&mut cursor).is_err(),
                    "a repeated PATH was accepted in a CLIENT_SETUP"
                );

                // And the same repeat of an unknown type is still carried, so
                // the list consulted is a list and not a blanket refusal.
                let unknown = vec![param(UNKNOWN_TYPE), param(UNKNOWN_TYPE)];
                let wire = client_setup_frame(&unknown, $with_versions);
                let mut cursor = &wire[..];
                let decoded = ControlMessage::decode(&mut cursor).unwrap_or_else(|e| {
                    panic!("a repeated unknown setup parameter was refused: {e:?}")
                });
                assert_eq!(parameters_of(&decoded).len(), 2);
            }

            /// A list naming each type once is carried unchanged, so none of the
            /// gates above is refusing ordinary messages.
            #[test]
            fn a_list_that_names_each_type_once_is_carried() {
                let distinct = vec![
                    param(KNOWN_MESSAGE_TYPE),
                    param(AUTHORIZATION_TOKEN),
                    param(UNKNOWN_TYPE),
                ];
                let message = publish_namespace(distinct);
                let mut buf = Vec::new();
                message.encode(&mut buf).expect("encode");
                let mut cursor = &buf[..];
                let back = ControlMessage::decode(&mut cursor).expect("decode");
                assert_eq!(back, message);
                assert_eq!(cursor.remaining(), 0);
            }

            /// And the same for a SETUP, so the namespace-aware gate is refusing
            /// the repeat and not the message.
            #[test]
            fn a_setup_naming_each_type_once_is_carried() {
                let wire = client_setup_frame(
                    &[param(KNOWN_SETUP_TYPE), param(UNKNOWN_TYPE)],
                    $with_versions,
                );
                let mut cursor = &wire[..];
                let decoded = ControlMessage::decode(&mut cursor).expect("decode");
                assert_eq!(parameters_of(&decoded).len(), 2);
                assert_eq!(cursor.remaining(), 0);
            }
        }
    };
}

duplicate_parameter_suite!(duplicates_draft14, moqtap_codec::draft14::message, true);
duplicate_parameter_suite!(duplicates_draft15, moqtap_codec::draft15::message, false);

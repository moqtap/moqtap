#![cfg(feature = "draft16")]

//! Draft-16 data-stream rules that the shipped vector corpus does not pin down.
//!
//! Every fetch object in
//! `test-vectors/transport/draft16/codec/data-streams/fetch-header.json` sets
//! the Group ID and Object ID flags together, so those vectors cannot tell the
//! two bits apart, and none of them inherits a Subgroup ID from the object
//! before it. The streams here are hand-built to separate exactly those cases,
//! from the flag tables of MoQ Transport draft-16 Section 10.4.4.1.

use bytes::Buf;
use moqtap_codec::draft16::data_stream::{
    FetchObjectHeader, FetchObjectLocation, FetchObjectReader, PayloadPermission, SubgroupHeader,
    SubgroupObjectMeta, SubgroupObjectReader,
};
use moqtap_codec::error::CodecError;
use moqtap_codec::varint::VarInt;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// One object's framing paired with the Location it resolves to.
type Resolved = (FetchObjectHeader, FetchObjectLocation);

/// Decode every object on a fetch stream body, resolving each against the one
/// before it.
///
/// `body` holds the objects only — the FETCH_HEADER is not part of it — and is
/// consumed to the last byte, payloads included. An error leaves the objects
/// decoded so far unreported, which is all any caller here needs.
fn resolve_all(body: &str) -> Result<Vec<Resolved>, CodecError> {
    let bytes = hex(body);
    let mut cursor: &[u8] = &bytes;
    let mut reader = FetchObjectReader::new();
    let mut out = Vec::new();
    while cursor.has_remaining() {
        let header = FetchObjectHeader::decode(&mut cursor)?;
        let location = reader.resolve(&header)?;
        let payload_length = header.payload_length.into_inner() as usize;
        if cursor.remaining() < payload_length {
            return Err(CodecError::UnexpectedEnd);
        }
        cursor.advance(payload_length);
        out.push((header, location));
    }
    Ok(out)
}

/// The Locations `resolve_all` produces for `body`, panicking if any object is
/// refused.
fn locations(body: &str) -> Vec<FetchObjectLocation> {
    resolve_all(body)
        .unwrap_or_else(|e| panic!("[{body}] refused: {e:?}"))
        .into_iter()
        .map(|(_, location)| location)
        .collect()
}

// ── Serialization Flags: which bit names which field ────────

/// Bit 0x08 puts a Group ID on the wire and bit 0x04 an Object ID, not the
/// other way round.
///
/// The second object here sets 0x08 alone. Draft-16 Section 10.4.4.1 Table 6
/// makes that a stated Group ID of 9, with the Object ID stepping to 8 from the
/// object before. Reading the bits the other way puts 9 in the Object ID and
/// carries group 3 forward, so the two readings disagree on both fields — which
/// no shipped vector can show, since every one of them sets both bits at once.
///
/// Observed by swapping the masks in `has_group_id` and `has_object_id`, which
/// fails this with:
///
/// ```text
/// assertion `left == right` failed: the second object's stated field is its Group ID
///   left: 3
///  right: 9
/// ```
///
/// The shipped fetch vectors all pass under that swap.
#[test]
fn a_stated_field_is_the_one_its_own_bit_names() {
    // 1c: Group ID, Object ID and Priority present, Subgroup ID zero.
    // 08: Group ID present; Object ID and Priority come from the prior object.
    let objects = locations("1c03074000080900");
    assert_eq!(objects.len(), 2);

    assert_eq!(objects[0].group_id, 3, "the first object's Group ID");
    assert_eq!(objects[0].object_id, 7, "the first object's Object ID");

    assert_eq!(objects[1].group_id, 9, "the second object's stated field is its Group ID");
    assert_eq!(objects[1].object_id, 8, "the second object's Object ID steps from the one before");
    assert_eq!(
        objects[1].publisher_priority,
        Some(0x40),
        "an absent Priority repeats the prior object's"
    );
}

/// A field that is on the wire carries its own value rather than a step from
/// the object before it.
///
/// Draft-16 spells the subgroup stream's field "Object ID Delta" by name
/// (Section 10.5) and the fetch stream's plain "Object ID" (Section 10.4.4,
/// Figure 31); Table 6 describes inheritance only for the case where the field
/// is absent. No shipped vector states an Object ID on anything but the first
/// object of a stream, where absolute and delta agree.
///
/// Observed by resolving a stated Object ID as `prior + 1 + wire value`, which is
/// the subgroup stream's rule, and which fails this with:
///
/// ```text
/// assertion `left == right` failed: a stated Object ID is absolute
///   left: 13
///  right: 9
/// ```
#[test]
fn a_stated_object_id_is_absolute_not_a_delta() {
    let objects = locations("1c000340001c00094000");
    assert_eq!(objects.len(), 2);
    assert_eq!(objects[0].object_id, 3);
    assert_eq!(objects[1].object_id, 9, "a stated Object ID is absolute");
}

/// The two least significant bits choose how the Subgroup ID is stated, per
/// draft-16 Section 10.4.4.1 Table 5: 0x00 is zero, 0x01 repeats the prior
/// object's, 0x02 adds one to it, 0x03 puts the field on the wire.
///
/// Observed by making mode 0x02 repeat the prior Subgroup ID instead of stepping
/// it, which fails this with:
///
/// ```text
/// assertion `left == right` failed: Subgroup IDs across modes 0x03, 0x01, 0x02, 0x00
///   left: [Some(4), Some(4), Some(4), Some(0)]
///  right: [Some(4), Some(4), Some(5), Some(0)]
/// ```
#[test]
fn the_low_two_bits_choose_how_the_subgroup_id_is_stated() {
    // 1f: mode 0x03, Subgroup ID present (4).
    // 1d: mode 0x01, the prior object's Subgroup ID.
    // 1e: mode 0x02, the prior object's Subgroup ID plus one.
    // 1c: mode 0x00, Subgroup ID zero.
    let objects = locations("1f00040040001d000140001e000240001c00034000");
    assert_eq!(objects.len(), 4);
    let subgroups: Vec<Option<u64>> = objects.iter().map(|l| l.subgroup_id).collect();
    assert_eq!(
        subgroups,
        vec![Some(4), Some(4), Some(5), Some(0)],
        "Subgroup IDs across modes 0x03, 0x01, 0x02, 0x00"
    );
}

/// Bit 0x40 marks an object whose Forwarding Preference is Datagram, and
/// draft-16 Section 10.4.4.1 requires the subscriber to ignore the two least
/// significant bits when it is set. Ignoring them is framing, not cosmetics:
/// reading a Subgroup ID there would swallow the varint that belongs to the
/// Object ID and push every later field along by one.
///
/// The object here spells the two bits 0b11 — the value that would otherwise
/// put a Subgroup ID on the wire — precisely because a conforming publisher
/// SHOULD zero them, so a reader that honours them is not caught by any
/// well-formed stream.
///
/// Observed by dropping the Datagram case from `subgroup_mode`, so the two bits
/// are read as mode 0x03. The Subgroup ID then eats the Object ID's varint, the
/// Object ID eats the payload length, and the payload length eats the payload —
/// which fails this with:
///
/// ```text
/// the datagram object resolves: VarInt(UnexpectedEnd)
/// ```
#[test]
fn the_datagram_bit_makes_the_low_two_bits_framing_noise() {
    // 4f = 0x40 | 0x08 | 0x04 | 0x03: Datagram, Group ID and Object ID present,
    // and two low bits that must be ignored rather than read as mode 0x03.
    let objects = resolve_all("404f070201aa").expect("the datagram object resolves");
    assert_eq!(objects.len(), 1);
    let (header, location) = &objects[0];

    assert!(header.is_datagram(), "bit 0x40 marks a Datagram-forwarded object");
    assert_eq!(header.subgroup_id, None, "no Subgroup ID field is on the wire");
    assert_eq!(location.subgroup_id, None, "a Datagram-forwarded object has no Subgroup ID");
    assert_eq!(location.group_id, 7);
    assert_eq!(location.object_id, 2);
    assert_eq!(header.payload_length.into_inner(), 1, "the payload length is the byte after 0x02");
}

// ── Serialization Flags: the values that are not flags ──────

/// Serialization Flags below 128 are a bit field and the two values of
/// Section 10.4.4 Table 4 are markers; every other value at or above 128 is a
/// PROTOCOL_VIOLATION, and the decoder refuses it rather than guessing which
/// fields follow.
///
/// Each object here is complete under the bit-field reading — the bytes after
/// the flags are exactly the fields those bits would call for — so a decoder
/// that skipped the check would accept every one of them and carry on.
///
/// Observed by dropping the refusal from `decode`, which fails this with:
///
/// ```text
/// called `Result::unwrap_err()` on an `Ok` value: FetchObjectHeader { serialization_flags: VarInt(128), group_id: None, subgroup_id: None, object_id: None, publisher_priority: None, extensions: None, payload_length: VarInt(0) }
/// ```
#[test]
fn an_unassigned_serialization_flags_value_is_refused() {
    // 0x80 and 0x1000 call for a payload length alone; 0x8d for a Group ID and
    // an Object ID before it; 0x10b for a Group ID and a Subgroup ID.
    for body in ["408000", "408d000000", "410b000000", "500000"] {
        let bytes = hex(body);
        let err = FetchObjectHeader::decode(&mut &bytes[..]).unwrap_err();
        assert!(matches!(err, CodecError::InvalidField), "[{body}] gave {err:?}");
    }
}

/// The two markers Table 4 assigns are accepted, and Section 10.4.4.2 says they
/// carry a Group ID and an Object ID and nothing else — no Subgroup ID, no
/// Priority, no Extensions.
///
/// Observed by giving an End of Range marker a Priority field, which makes it eat
/// the payload length and run off the end of the object, failing this with:
///
/// ```text
/// [408c050a00] refused: VarInt(UnexpectedEnd)
/// ```
#[test]
fn an_end_of_range_marker_carries_a_group_and_an_object_id_only() {
    for (body, marker) in [("408c050a00", 0x8c_u64), ("410c050a00", 0x10c)] {
        let objects = resolve_all(body).unwrap_or_else(|e| panic!("[{body}] refused: {e:?}"));
        assert_eq!(objects.len(), 1);
        let (header, location) = &objects[0];

        assert_eq!(
            header.end_of_range().map(|r| r.as_u64()),
            Some(marker),
            "[{body}] Table 4 marker"
        );
        assert_eq!(header.group_id.map(VarInt::into_inner), Some(5), "[{body}] Group ID");
        assert_eq!(header.object_id.map(VarInt::into_inner), Some(10), "[{body}] Object ID");
        assert_eq!(header.subgroup_id, None, "[{body}] no Subgroup ID field");
        assert_eq!(header.publisher_priority, None, "[{body}] no Priority field");
        assert_eq!(header.extensions, None, "[{body}] no Extensions field");
        assert_eq!(header.payload_length.into_inner(), 0, "[{body}] payload length");
        assert_eq!(location.group_id, 5);
        assert_eq!(location.object_id, 10);
    }
}

// ── A fetch object has no status field ──────────────────────

/// A zero Object Payload Length ends a fetch object; no status varint follows
/// it.
///
/// Draft-16 Section 10.2.1.1 says the Object Status "is only present in objects
/// that are delivered via a SUBSCRIPTION, and is absent in Objects delivered
/// via a FETCH", and Figure 31 has no field for it. So the byte after a zero
/// length belongs to the next object — here, that object's Serialization Flags.
/// This is the one place draft-16's fetch object parts company with drafts
/// 07-13, whose zero-length fetch objects do carry a status.
///
/// Observed by reading a status varint after a zero payload length, the way
/// drafts 07-13 do. That swallows the second object's flags byte and leaves its
/// payload length to be parsed out of the payload, failing this with:
///
/// ```text
/// both objects resolve: VarInt(UnexpectedEnd)
/// ```
#[test]
fn a_zero_length_fetch_object_carries_no_status() {
    // 1c: Group 0, Object 0, Priority 0x80, payload length 0.
    // 00: everything inherited, payload length 2, payload "cafe".
    let objects = resolve_all("1c000080000002cafe").expect("both objects resolve");
    assert_eq!(objects.len(), 2, "the zero-length object must not swallow the next object's flags");
    assert_eq!(objects[0].0.payload_length.into_inner(), 0);
    assert_eq!(objects[1].0.serialization_flags.into_inner(), 0x00);
    assert_eq!(objects[1].1.object_id, 1, "the second object steps from the first");
    assert_eq!(objects[1].0.payload_length.into_inner(), 2);
}

// ── The first object on a stream ────────────────────────────

/// A first object cannot read a field off an object that does not exist.
///
/// Draft-16 Section 10.4.4.1 makes it a PROTOCOL_VIOLATION for the first object
/// of a FETCH response to use a flag that references the prior object; for a
/// Group ID, an Object ID or an inherited Subgroup ID there is also no value
/// the resolver could produce.
///
/// Observed by letting an absent Group ID fall back to 0 on the first object,
/// which fails this with:
///
/// ```text
/// called `Result::unwrap_err()` on an `Ok` value: [(FetchObjectHeader { serialization_flags: VarInt(20), group_id: None, subgroup_id: None, object_id: Some(VarInt(5)), publisher_priority: Some(128), extensions: None, payload_length: VarInt(0) }, FetchObjectLocation { group_id: 0, subgroup_id: Some(0), object_id: 5, publisher_priority: Some(128), end_of_range: None })]
/// ```
#[test]
fn a_first_object_cannot_inherit_a_location() {
    // 14: Object ID and Priority present, Group ID absent.
    // 18: Group ID and Priority present, Object ID absent.
    // 1d: Subgroup mode 0x01 — the prior object's Subgroup ID.
    // 1e: Subgroup mode 0x02 — the prior object's Subgroup ID plus one.
    for body in ["14058000", "18058000", "1d00014000", "1e00024000"] {
        let err = resolve_all(body).unwrap_err();
        assert!(matches!(err, CodecError::InvalidField), "[{body}] gave {err:?}");
    }
}

/// The draft's rule is wider than what the resolver can refuse: an absent
/// Priority also references the prior object, and Section 11.1.1.1 supplies a
/// default that lets resolution continue anyway. The predicate reports the full
/// rule so a caller that must close the session can.
///
/// No shipped vector reaches it any more: `fetch-with-explicit-subgroup` and
/// `fetch-datagram-forwarding` both used to leave bit 0x10 clear on the first
/// object of their stream, and both now state a Priority. The bodies below are
/// written here for that reason — a rule the corpus stopped exercising is one
/// only a hand-written frame can hold.
///
/// Observed by dropping the Priority term from `references_prior_object`, which
/// fails this with:
///
/// ```text
/// 0x0f leaves the Priority bit clear
/// ```
#[test]
fn the_prior_object_predicate_covers_every_inheriting_flag() {
    let flags_of = |body: &str| {
        let bytes = hex(body);
        FetchObjectHeader::decode(&mut &bytes[..]).expect("decodes")
    };

    // Nothing inherited: Group ID, Object ID, Priority all stated, Subgroup ID
    // zero rather than taken from anywhere.
    assert!(!flags_of("1c00004000").references_prior_object(), "0x1c inherits nothing");
    // Both Table 4 markers state their own Location and have no Priority or
    // Extensions to inherit.
    assert!(!flags_of("408c050a00").references_prior_object(), "0x8c inherits nothing");
    assert!(!flags_of("410c050a00").references_prior_object(), "0x10c inherits nothing");

    for (body, why) in [
        ("0f02030004", "0x0f leaves the Priority bit clear"),
        ("404c000004", "0x4c leaves the Priority bit clear"),
        ("14058000", "0x14 leaves the Group ID bit clear"),
        ("18058000", "0x18 leaves the Object ID bit clear"),
        ("1d00014000", "0x1d takes the prior Subgroup ID"),
        ("1e00024000", "0x1e steps the prior Subgroup ID"),
    ] {
        assert!(flags_of(body).references_prior_object(), "{why}");
    }
}

// ── Encoding ────────────────────────────────────────────────

/// An encode whose fields disagree with its own Serialization Flags is refused
/// before a byte is written, rather than resolved one way or the other.
///
/// A field that is `Some` while its bit is clear has nowhere on the wire to go;
/// one that is `None` while its bit is set leaves a hole the reader fills from
/// the next field's bytes. Either way the bytes are not the object that was
/// handed in.
///
/// Observed by dropping the agreement check from `encode`, which fails this with:
///
/// ```text
/// called `Result::unwrap_err()` on an `Ok` value: ()
/// ```
#[test]
fn encode_refuses_a_header_that_disagrees_with_its_flags() {
    let bytes = hex("1c03074000");
    let good = FetchObjectHeader::decode(&mut &bytes[..]).expect("decodes");

    let mut round_trip = Vec::new();
    good.encode(&mut round_trip).expect("its own framing re-encodes");
    assert_eq!(round_trip, bytes, "a decoded object re-encodes byte for byte");

    let mut missing = good.clone();
    missing.publisher_priority = None;

    let mut extra = good.clone();
    extra.extensions = Some(Vec::new());

    let mut unassigned = good.clone();
    unassigned.serialization_flags = VarInt::from_usize(0x8d);

    for (header, why) in [
        (missing, "a cleared field whose bit is set"),
        (extra, "a set field whose bit is clear"),
        (unassigned, "a Serialization Flags value Table 4 does not assign"),
    ] {
        let mut buf = Vec::new();
        let err = header.encode(&mut buf).unwrap_err();
        assert!(matches!(err, CodecError::InvalidField), "{why} gave {err:?}");
        assert!(buf.is_empty(), "{why} wrote {} bytes before refusing", buf.len());
    }
}

// ── Payload permission on a subgroup object ─────────────────

/// A subgroup stream with a publisher priority and no extensions, so an object
/// on it is `delta, payload_length, [status]`.
fn plain_subgroup_header() -> SubgroupHeader {
    SubgroupHeader::decode(&mut &hex("10010080")[..]).expect("header decodes")
}

/// Read one object's framing off a stream body.
fn meta(body: &str) -> SubgroupObjectMeta {
    let bytes = hex(body);
    SubgroupObjectReader::new(&plain_subgroup_header())
        .read_object_meta(&mut &bytes[..])
        .unwrap_or_else(|e| panic!("[{body}] refused: {e:?}"))
}

/// Every status draft-16 assigns answers with the payload rule of
/// Section 10.2.1.1: Normal permits a payload, and "any object with a status
/// code other than zero MUST have an empty payload" covers the other two.
///
/// An object with no status at all carried bytes — the status field is on the
/// wire only when the payload length is zero — and the same section makes
/// Normal "implicit for any non-zero length object".
///
/// Observed by answering `Permitted` for End of Group, which fails this with:
///
/// ```text
/// assertion `left == right` failed: End of Group
///   left: Some(Permitted)
///  right: Some(Forbidden)
/// ```
#[test]
fn an_assigned_status_answers_with_the_drafts_payload_rule() {
    // Object 0, empty payload, status 0x0 / 0x3 / 0x4.
    assert_eq!(meta("000000").payload_permission(), Some(PayloadPermission::Permitted), "Normal");
    assert_eq!(
        meta("000003").payload_permission(),
        Some(PayloadPermission::Forbidden),
        "End of Group"
    );
    assert_eq!(
        meta("000004").payload_permission(),
        Some(PayloadPermission::Forbidden),
        "End of Track"
    );
    // Object 0 with a two-byte payload, so no status field at all.
    let carrying = meta("0002cafe");
    assert_eq!(carrying.status, None);
    assert_eq!(
        carrying.payload_permission(),
        Some(PayloadPermission::Permitted),
        "an object that carried bytes is Normal by implication"
    );

    assert!(
        PayloadPermission::Permitted.permits() && !PayloadPermission::Forbidden.permits(),
        "permits() agrees with the variant it is asked about"
    );
}

/// A status code draft-16 does not assign has no payload rule, and the accessor
/// says so instead of picking one.
///
/// The status field of a meta holds the raw wire code on purpose, so a value
/// another draft numbered differently can sit in it: 0x1 is Object Does Not
/// Exist on drafts 07-15 and unassigned here. Draft-16 states no payload rule
/// for it, and neither answer is safe to invent — `Permitted` waves through a
/// payload the peer may reject, `Forbidden` discards one it may accept.
///
/// Observed by falling back to Normal for a code the draft does not assign, which
/// fails this with:
///
/// ```text
/// assertion `left == right` failed: status 0x1 is not one draft-16 assigns
///   left: Some(Permitted)
///  right: None
/// ```
#[test]
fn an_unassigned_status_has_no_payload_permission() {
    let mut from_the_wire = meta("000003");
    for code in [0x1_u64, 0x2, 0x5, 0x40, u64::MAX] {
        from_the_wire.status = Some(code);
        assert_eq!(
            from_the_wire.payload_permission(),
            None,
            "status {code:#x} is not one draft-16 assigns"
        );
    }
}

/// A reserved-mode subgroup header writes no Subgroup ID field.
///
/// Draft-16 Section 10.4.2 makes the carrier one field and not two flags: "The
/// SUBGROUP_ID_MODE field (bits 1-2, mask 0x06) is a two-bit field that
/// determines the encoding of the Subgroup ID. To extract this value, perform a
/// bitwise AND with mask 0x06 and right-shift by 1 bit". Four exclusive values,
/// so the one the same section reserves is not also one of the other three:
/// "Type values with SUBGROUP_ID_MODE set to 0b11: 0x16, 0x17, 0x1E, 0x1F,
/// 0x36, 0x37, 0x3E, 0x3F. This mode is reserved for future use."
///
/// This module read those two bits one at a time, so `0x16` set both and the
/// header answered to two carriers at once — the Subgroup ID comes from the
/// first object, *and* an explicit field follows the Group ID — and `encode`
/// wrote that field. Mode 3 defines no field to write, and no neighbouring
/// draft wrote one: 15, 17, 18 and 19 all leave it off.
///
/// Observed through `encode`, because the bytes are what a caller is handed;
/// asserting the predicates would only read the flags back. `decode` refuses
/// `0x16` outright, asserted here as well so the header under test stays one
/// that had to be built by hand.
///
/// *Ablation (measured):* restore either predicate to its single-bit reading,
/// `self.header_type & 0x04 != 0`:
///
/// ```text
/// assertion `left == right` failed: a reserved SUBGROUP_ID_MODE carries no Subgroup ID field
///   left: [22, 7, 9, 5, 128]
///  right: [22, 7, 9, 128]
/// ```
#[test]
fn a_reserved_subgroup_id_mode_writes_no_subgroup_id_field() {
    // `0x16` clears `0x20`, so a priority byte is present, and sets both `0x06`
    // bits, which is the reserved mode. The Subgroup ID below is deliberately
    // non-zero: if it reaches the wire it is visible rather than absorbed.
    const RESERVED: u8 = 0x16;
    let header = SubgroupHeader {
        header_type: RESERVED,
        track_alias: VarInt::from_u64(7).unwrap(),
        group_id: VarInt::from_u64(9).unwrap(),
        subgroup_id: VarInt::from_u64(5).unwrap(),
        publisher_priority: Some(128),
    };

    let mut buf = Vec::new();
    header.encode(&mut buf);
    assert_eq!(
        buf,
        vec![RESERVED, 7, 9, 128],
        "a reserved SUBGROUP_ID_MODE carries no Subgroup ID field"
    );

    let mut cursor: &[u8] = &buf;
    assert!(
        SubgroupHeader::decode(&mut cursor).is_err(),
        "draft-16 must refuse this type on the wire, or the header above is reachable \
         by decoding and this test is measuring the wrong thing"
    );

    // Draft-15 reaches the same eight type values by leaving them out of its
    // Section 10.4.2 Table 6 rather than by reserving a mode, and has always
    // read the two bits together. The bytes agreeing is the point: one wire
    // format, described twice.
    #[cfg(feature = "draft15")]
    {
        let mut theirs = Vec::new();
        moqtap_codec::draft15::data_stream::SubgroupHeader {
            header_type: RESERVED,
            track_alias: VarInt::from_u64(7).unwrap(),
            group_id: VarInt::from_u64(9).unwrap(),
            subgroup_id: VarInt::from_u64(5).unwrap(),
            publisher_priority: Some(128),
        }
        .encode(&mut theirs);
        assert_eq!(theirs, buf, "drafts 15 and 16 write the same header for the same type");
    }
}

//! Draft-17 data stream rules that a single vector cannot pin down.
//!
//! The committed vectors are all well formed, so they show what the codec
//! accepts and never what it must refuse. These tests supply the other half:
//! the type values MoQ Transport draft-17 Sections 10.4.2 and 10.3.1 list as
//! invalid, the payload a status datagram may not carry, and the fetch object
//! layout of Section 10.4.4, whose fields are named by a flags word rather than
//! all being present.
//!
//! Each sweep builds its bytes from the draft's figures directly rather than
//! from the masks the codec uses, so a mask edited to match a wrong idea of the
//! rule does not quietly edit the test's idea of it too.

#![cfg(feature = "draft17")]

use bytes::Buf;
use moqtap_codec::draft17::data_stream::{
    DatagramHeader, EndOfRange, FetchObjectHeader, PayloadPermission, SubgroupHeader,
    SubgroupObjectReader,
};
use moqtap_codec::error::CodecError;
use moqtap_codec::varint::VarInt;

fn hex(s: &str) -> Vec<u8> {
    hex::decode(s.replace(' ', "")).expect("bad hex in test fixture")
}

// ─────────────────────────────────────────────────────────────
// Type values
// ─────────────────────────────────────────────────────────────

/// The subgroup header types draft-17 defines, read straight off Figure 24:
/// `Type (i) = 0x10..0x15 / 0x18..0x1D / 0x30..0x35 / 0x38..0x3D`.
///
/// Spelled as the figure's ranges rather than as a bit test, so it stays an
/// independent statement of the same rule.
fn subgroup_type_is_defined(ty: u8) -> bool {
    matches!(ty, 0x10..=0x15 | 0x18..=0x1D | 0x30..=0x35 | 0x38..=0x3D)
}

/// A well-formed subgroup header body for `ty`: track alias 1, group 0, an
/// explicit subgroup ID of 7 under SUBGROUP_ID_MODE `0b10`, and a publisher
/// priority of 128 unless DEFAULT_PRIORITY (0x20) omits it.
///
/// The body is complete for every type in the sweep, including the forbidden
/// ones, so a refusal is a refusal of the type and never of a short buffer.
fn subgroup_header_bytes(ty: u8) -> Vec<u8> {
    let mut bytes = vec![ty, 0x01, 0x00];
    if (ty & 0x06) >> 1 == 2 {
        bytes.push(0x07);
    }
    if ty & 0x20 == 0 {
        bytes.push(0x80);
    }
    bytes
}

/// The datagram types draft-17 defines, read straight off Figure 23:
/// `Type (i) = 0x00..0x0F / 0x20..0x21 / 0x24..0x25 / 0x28..0x29 / 0x2C..0x2D`.
fn datagram_type_is_defined(ty: u8) -> bool {
    matches!(ty, 0x00..=0x0F | 0x20 | 0x21 | 0x24 | 0x25 | 0x28 | 0x29 | 0x2C | 0x2D)
}

/// A well-formed datagram for `ty`: track alias 1, group 0, object 5, priority
/// 128, an empty properties block and an End of Group status, each present only
/// where the type says so.
fn datagram_bytes(ty: u8) -> Vec<u8> {
    let mut bytes = vec![ty, 0x01, 0x00];
    if ty & 0x04 == 0 {
        bytes.push(0x05);
    }
    if ty & 0x08 == 0 {
        bytes.push(0x80);
    }
    if ty & 0x01 != 0 {
        bytes.push(0x00);
    }
    if ty & 0x20 != 0 {
        bytes.push(0x03);
    }
    bytes
}

/// Every one-byte Type a subgroup stream can lead with is accepted or refused
/// exactly as draft-17 Section 10.4.2 says.
///
/// The sweep stops at 0x7F because that is where one byte stops being one Type:
/// under the MoQT variable-length integer encoding a first byte of 0x80 or above
/// announces a longer field, so the bytes behind it are part of the Type rather
/// than the header it introduces. Those are swept by
/// [`a_type_wider_than_one_byte_is_refused_by_what_it_is`], which has to supply
/// whole fields rather than single bytes.
///
/// The section names two ways a type is invalid — the reserved SUBGROUP_ID_MODE
/// `0b11` and any byte outside the form `0b00X1XXXX` — and of both says the
/// endpoint "MUST close the session with a PROTOCOL_VIOLATION". Reserved-mode
/// values are the dangerous half: a `0x16` that decoded would report a Subgroup
/// ID of 0, indistinguishable from the 0 that mode `0b00` genuinely means,
/// leaving a consumer no way to tell a real subgroup from an invented one.
///
/// # Ablation
///
/// Narrowed the check in `SubgroupHeader::decode` to
/// `header_type & SUBGROUP_BASE_BIT == 0`:
///
/// ```text
/// thread 'subgroup_header_types_outside_the_draft_are_refused' (13236) panicked at
/// crates\moqtap-codec\tests\draft17_data_stream_rules.rs:
/// type 0x16 is not one draft-17 defines, but decode accepted it
/// ```
#[test]
fn subgroup_header_types_outside_the_draft_are_refused() {
    for ty in 0x00u8..=0x7f {
        let bytes = subgroup_header_bytes(ty);
        let result = SubgroupHeader::decode(&mut &bytes[..]);
        if subgroup_type_is_defined(ty) {
            let header =
                result.unwrap_or_else(|e| panic!("type {ty:#04x} is one draft-17 defines: {e:?}"));
            assert_eq!(header.header_type, ty);
            assert_ne!(header.subgroup_id_mode(), 3, "type {ty:#04x} carries the reserved mode");
        } else {
            match result {
                Ok(_) => {
                    panic!("type {ty:#04x} is not one draft-17 defines, but decode accepted it")
                }
                Err(e) => assert_refusal(ty, &e, expected_subgroup_refusal(ty)),
            }
        }
    }
}

/// Which of draft-17's three answers a refused subgroup Type deserves.
///
/// The sweep would pass on "some error", and that is the thing worth not
/// settling for: the three answers are three different rules, and only two of
/// them end the session.
fn expected_subgroup_refusal(ty: u8) -> Refusal {
    if ty as u64 == 0x05 {
        // FETCH_HEADER. Table 3 assigns it, so a subgroup reader refuses it
        // without reaching for a rule about types the draft does not have.
        Refusal::NotThisReader
    } else if ty & 0xD0 == 0x10 && (ty & 0x06) >> 1 == 3 {
        // Inside the form, reserved SUBGROUP_ID_MODE: Section 10.4.2's list.
        Refusal::NamedInvalid
    } else {
        // Outside the form and unassigned: Section 3.4's unknown-type rule.
        Refusal::Unknown
    }
}

/// Which of draft-17's three answers a refused datagram Type deserves.
fn expected_datagram_refusal(ty: u8) -> Refusal {
    if ty & 0xD0 == 0 && ty & 0x22 == 0x22 {
        // Inside the form, STATUS and END_OF_GROUP together: Section 10.3.1's
        // list.
        Refusal::NamedInvalid
    } else {
        Refusal::Unknown
    }
}

/// One of the three shapes a refused Type can take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    /// A Type no table assigns. The session ends.
    Unknown,
    /// A Type inside a form the draft defines but on a list it calls invalid.
    /// The session ends, under a rule that names its own code.
    NamedInvalid,
    /// A Type the draft assigns, handed to a reader that cannot read it. The
    /// session survives.
    NotThisReader,
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

/// A Type wider than one byte is refused, and refused as what it actually is.
///
/// No subgroup header or datagram has a multi-byte Type, so every case here is
/// a refusal — but not the same refusal, and that is the point. Table 3 assigns
/// SETUP a Type of 0x2F00, so a data reader handed the peer's control stream
/// must not report it under a rule about Types the draft does not have; doing
/// so would end the session over the one stream every session needs.
///
/// The last row is the reason the Type is not simply narrowed to its low octet.
/// A two-byte 0x8010 carries the value 0x10, an assigned subgroup Type, and its
/// low octet is 0x10 as well — so a decoder that truncated would read it as a
/// valid header. It has to be refused instead, and by decoding the field rather
/// than by looking at one byte of it.
///
/// # Ablation
///
/// Removed the `wide_type_refusal` call from `SubgroupHeader::decode`, leaving
/// the one-byte read:
///
/// ```text
/// PLACEHOLDER
/// ```
#[test]
fn a_type_wider_than_one_byte_is_refused_by_what_it_is() {
    // SETUP, 0x2F00, as its two-byte MoQT varint: 0xAF 0x00.
    let setup = hex("af00 0100 0780");
    match SubgroupHeader::decode(&mut &setup[..]) {
        Ok(h) => panic!("SETUP is not a subgroup header, but decode accepted {h:?}"),
        Err(e) => assert!(
            matches!(e, CodecError::InvalidField),
            "SETUP is a Type Table 3 assigns, so a subgroup reader must refuse it without \
             naming the unknown-stream-type rule, got {e:?}"
        ),
    }

    // A two-byte Type no table assigns: 0x8100 spells 0x0100.
    let unassigned = hex("8100 0100 0780");
    match SubgroupHeader::decode(&mut &unassigned[..]) {
        Ok(h) => panic!("0x0100 is not a Type draft-17 assigns, but decode accepted {h:?}"),
        Err(e) => assert!(
            matches!(e, CodecError::UnknownStreamType(0x0100)),
            "a Type no table assigns must be named as unknown, got {e:?}"
        ),
    }

    // A non-minimal two-byte spelling of the assigned subgroup Type 0x10.
    let non_minimal = hex("8010 0100 0780");
    assert!(
        SubgroupHeader::decode(&mut &non_minimal[..]).is_err(),
        "a wide spelling must not be narrowed onto the assigned Type 0x10"
    );
}

/// The checked encoder writes exactly the subgroup types the decoder accepts.
///
/// A header value carries its type byte verbatim, so nothing stops one being
/// built with a type the draft forbids. `encode` writes it as given;
/// `encode_checked` refuses, and leaves the buffer untouched when it does.
///
/// # Ablation
///
/// Dropped the `subgroup_type_is_valid` guard from
/// `SubgroupHeader::encode_checked`:
///
/// ```text
/// thread 'the_checked_subgroup_encoder_refuses_a_type_the_decoder_would' (62756) panicked at
/// crates\moqtap-codec\tests\draft17_data_stream_rules.rs:
/// encode_checked wrote type 0x00, which decode refuses
/// ```
///
/// The sweep reports `0x00` rather than a reserved-mode value: it walks every
/// byte from zero, and the first failure is a type that is not a subgroup
/// header at all.
#[test]
fn the_checked_subgroup_encoder_refuses_a_type_the_decoder_would() {
    for ty in 0x00u8..=0xff {
        let header = SubgroupHeader {
            header_type: ty,
            track_alias: VarInt::from_u64_moqt(1),
            group_id: VarInt::from_u64_moqt(0),
            subgroup_id: VarInt::from_u64_moqt(7),
            publisher_priority: Some(128),
        };
        let mut buf = Vec::new();
        let result = header.encode_checked(&mut buf);
        if subgroup_type_is_defined(ty) {
            result.unwrap_or_else(|e| panic!("encode_checked refused type {ty:#04x}: {e:?}"));
            SubgroupHeader::decode(&mut &buf[..])
                .unwrap_or_else(|e| panic!("type {ty:#04x} did not parse back: {e:?}"));
        } else {
            assert!(result.is_err(), "encode_checked wrote type {ty:#04x}, which decode refuses");
            assert!(buf.is_empty(), "type {ty:#04x} left {} byte(s) behind", buf.len());
        }
    }
}

/// Every one of the 256 possible datagram type bytes is accepted or refused
/// exactly as draft-17 Section 10.3.1 says.
///
/// The section names two ways a type is invalid — STATUS (0x20) together with
/// END_OF_GROUP (0x02), because "an object status message cannot signal end of
/// group", and any byte outside the form `0b00X0XXXX` — and of both says the
/// endpoint "MUST close the session with a PROTOCOL_VIOLATION".
///
/// # Ablation
///
/// Deleted the `datagram_type_is_valid` guard from `DatagramHeader::decode`:
///
/// ```text
/// thread 'datagram_types_outside_the_draft_are_refused' (44368) panicked at
/// crates\moqtap-codec\tests\draft17_data_stream_rules.rs:
/// type 0x10 is not one draft-17 defines, but decode accepted it
/// ```
///
/// `0x10` is the first byte to get through: it is a subgroup header type, and
/// without the form check the datagram decoder reads it as a datagram.
#[test]
fn datagram_types_outside_the_draft_are_refused() {
    for ty in 0x00u8..=0x7f {
        let bytes = datagram_bytes(ty);
        let result = DatagramHeader::decode(&mut &bytes[..]);
        if datagram_type_is_defined(ty) {
            let header =
                result.unwrap_or_else(|e| panic!("type {ty:#04x} is one draft-17 defines: {e:?}"));
            assert_eq!(header.datagram_type, ty);
            assert!(
                !(header.has_status() && header.is_end_of_group()),
                "type {ty:#04x} claims a status and an end of group at once"
            );
        } else {
            match result {
                Ok(_) => {
                    panic!("type {ty:#04x} is not one draft-17 defines, but decode accepted it")
                }
                Err(e) => assert_refusal(ty, &e, expected_datagram_refusal(ty)),
            }
        }
    }
}

/// A properties block for the sweep below to hand a type whose PROPERTIES bit
/// (0x01) is set: one key-value pair, key 0x3C with the varint value 0x02.
///
/// Two bytes rather than none because the bit and an empty block are a pair
/// draft-17 Section 10.3.1 forbids — "If an endpoint receives a datagram with
/// the PROPERTIES bit set and an Properties Length of 0, it MUST close the
/// session with a PROTOCOL_VIOLATION" — so a header holding one is not a type
/// question at all, and a sweep that built one would be asking the encoder
/// about the wrong rule.
const PROPERTIES: &[u8] = &[0x3C, 0x02];

/// The checked datagram encoder writes exactly the types the decoder accepts.
///
/// The properties block is present exactly when the type byte says it is, so
/// the Type value is the only thing left for `encode_checked` to refuse. The
/// status is `None` throughout, which leaves both of the other rules that
/// method applies with nothing to fire on: a header with no stated status is
/// Normal, so neither the lossy-status rule nor the one forbidding properties
/// beside a status that is not Normal can reach.
///
/// # Ablation
///
/// Dropped the `datagram_type_is_valid` guard from
/// `DatagramHeader::encode_checked`:
///
/// ```text
/// thread 'the_checked_datagram_encoder_refuses_a_type_the_decoder_would' (53440) panicked at
/// crates\moqtap-codec\tests\draft17_data_stream_rules.rs:
/// encode_checked wrote type 0x10, which decode refuses
/// ```
///
/// The sweep reaches a subgroup header type before it reaches the STATUS and
/// END_OF_GROUP pair, so `0x10` is what it reports first.
#[test]
fn the_checked_datagram_encoder_refuses_a_type_the_decoder_would() {
    for ty in 0x00u8..=0xff {
        let header = DatagramHeader {
            datagram_type: ty,
            track_alias: VarInt::from_u64_moqt(1),
            group_id: VarInt::from_u64_moqt(0),
            object_id: VarInt::from_u64_moqt(5),
            publisher_priority: Some(128),
            properties: if ty & 0x01 != 0 { PROPERTIES.to_vec() } else { Vec::new() },
            object_status: None,
        };
        let mut buf = Vec::new();
        let result = header.encode_checked(&mut buf);
        if datagram_type_is_defined(ty) {
            result.unwrap_or_else(|e| panic!("encode_checked refused type {ty:#04x}: {e:?}"));
            DatagramHeader::decode(&mut &buf[..])
                .unwrap_or_else(|e| panic!("type {ty:#04x} did not parse back: {e:?}"));
        } else {
            assert!(result.is_err(), "encode_checked wrote type {ty:#04x}, which decode refuses");
            assert!(buf.is_empty(), "type {ty:#04x} left {} byte(s) behind", buf.len());
        }
    }
}

// ─────────────────────────────────────────────────────────────
// A status datagram has no payload
// ─────────────────────────────────────────────────────────────

/// Bytes after a status datagram's header are refused, whichever status it
/// carries.
///
/// Draft-17 Section 10.3.1: "When set to 1, the Object Status field is present
/// and there is no Object Payload." The header alone cannot see the tail — the
/// payload is delimited by the end of the transport datagram, not a length — so
/// the refusal belongs to `decode_object`, which is handed the whole datagram.
///
/// The Normal case is the one that slips through a naive predicate. A
/// `permits_payload` that reads only the status answers yes for a datagram
/// framed as carrying a status and carrying the code 0x0, and four bytes the
/// draft says are not part of the object reach the application as its content.
///
/// # Ablation
///
/// Reverted `permits_payload` to `match self.object_status { None => true,
/// Some(status) => status == ObjectStatus::Normal }`:
///
/// ```text
/// thread 'a_status_datagram_refuses_the_bytes_that_follow_it' (51796) panicked at
/// crates\moqtap-codec\tests\draft17_data_stream_rules.rs:
/// a status datagram carrying 0x00 accepted a payload: (32, Some(Normal), [222, 173, 190, 239])
/// ```
///
/// The tuple is the datagram that rule lets through: type 0x20 with the
/// STATUS bit set, a Normal status, and four payload bytes the draft says are
/// not there. Codes 0x03 and 0x04 are refused either way, which is why only the
/// Normal one appears.
#[test]
fn a_status_datagram_refuses_the_bytes_that_follow_it() {
    // Type 0x20 (STATUS), alias 1, group 0, object 5, priority 128, then the
    // status byte and four bytes that draft-17 leaves undefined.
    for status in ["00", "03", "04"] {
        let with_tail = hex(&format!("20 01 00 05 80 {status} deadbeef"));
        let err = DatagramHeader::decode_object(&mut &with_tail[..])
            .map(|(header, payload)| (header.datagram_type, header.object_status, payload))
            .expect_err(&format!("a status datagram carrying 0x{status} accepted a payload"));
        assert!(matches!(err, CodecError::PayloadNotPermitted { .. }), "refused with {err:?}");

        let bare = hex(&format!("20 01 00 05 80 {status}"));
        let (header, payload) = DatagramHeader::decode_object(&mut &bare[..])
            .unwrap_or_else(|e| panic!("a bare status datagram must decode: {e:?}"));
        assert!(header.has_status());
        assert!(payload.is_empty());
        assert!(!header.permits_payload(), "a status datagram permitted a payload");
    }

    // The same shape without the STATUS bit is an ordinary object, and its tail
    // is its payload.
    let normal = hex("00 01 00 05 80 deadbeef");
    let (header, payload) = DatagramHeader::decode_object(&mut &normal[..])
        .unwrap_or_else(|e| panic!("an ordinary datagram must decode: {e:?}"));
    assert!(header.permits_payload());
    assert_eq!(payload, hex("deadbeef"));
}

/// A status datagram carrying the Normal code is refused a payload just as one
/// carrying End of Group is.
///
/// Stated on its own because it is the case the two rules disagree about: the
/// status rule of Section 10.2.1.1 speaks only of "a status code other than
/// zero", while the framing rule of Section 10.3.1 removes the payload from
/// every datagram with the bit set. The framing rule is the stricter one and
/// the one that governs a decoded datagram.
///
/// # Ablation
///
/// Reverted `permits_payload` to consult only `object_status`:
///
/// ```text
/// thread 'the_status_bit_forbids_a_payload_even_for_the_normal_code' (67708) panicked at
/// crates\moqtap-codec\tests\draft17_data_stream_rules.rs:
/// the STATUS bit did not forbid a payload
/// ```
#[test]
fn the_status_bit_forbids_a_payload_even_for_the_normal_code() {
    let bytes = hex("20 01 00 05 80 00");
    let header = DatagramHeader::decode(&mut &bytes[..]).expect("status datagram");
    assert!(header.has_status());
    assert!(!header.permits_payload(), "the STATUS bit did not forbid a payload");
}

// ─────────────────────────────────────────────────────────────
// Payload permission on a subgroup object's framing
// ─────────────────────────────────────────────────────────────

/// A subgroup object's framing reports what its stated status permits.
///
/// Draft-17 Section 10.2.1.1: "Any object with a status code other than zero
/// MUST have an empty payload." An object that states no status states no
/// permission either, and the accessor answers `None` there rather than
/// guessing.
///
/// # Ablation
///
/// Made `SubgroupObjectMeta::payload_permission` answer
/// `Some(PayloadPermission::Permitted)` for every stated status:
///
/// ```text
/// thread 'object_framing_reports_the_payload_permission_of_its_status' (16444) panicked at
/// crates\moqtap-codec\tests\draft17_data_stream_rules.rs:
/// assertion `left == right` failed: status 0x3
///   left: Some(Permitted)
///  right: Some(Forbidden)
/// ```
#[test]
fn object_framing_reports_the_payload_permission_of_its_status() {
    // Header type 0x10: no properties, subgroup-ID mode 0, explicit priority.
    let header = SubgroupHeader::decode(&mut &hex("10 01 00 80")[..]).expect("subgroup header");

    for (status, expected) in [
        (0x00u8, PayloadPermission::Permitted),
        (0x03, PayloadPermission::Forbidden),
        (0x04, PayloadPermission::Forbidden),
    ] {
        // Object ID delta 0, payload length 0, then the status code.
        let object = [0x00, 0x00, status];
        let meta = SubgroupObjectReader::new(&header)
            .read_object_meta(&mut &object[..])
            .unwrap_or_else(|e| panic!("status {status:#x}: {e:?}"));
        assert_eq!(meta.payload_permission(), Some(expected), "status {status:#x}");
        assert_eq!(
            meta.payload_permission().map(PayloadPermission::permits),
            Some(expected.permits())
        );
    }

    // Object ID delta 0, payload length 4, then four payload bytes: no status
    // field on the wire, so no stated permission.
    let object = hex("00 04 deadbeef");
    let meta = SubgroupObjectReader::new(&header)
        .read_object_meta(&mut &object[..])
        .expect("payload object");
    assert_eq!(meta.payload_length, 4);
    assert_eq!(meta.payload_permission(), None, "an object with a payload states no status");
}

// ─────────────────────────────────────────────────────────────
// Fetch objects
// ─────────────────────────────────────────────────────────────

/// Which fields a fetch object puts on the wire follows draft-17
/// Section 10.4.4.1 exactly, across every flags value read as a bit set.
///
/// The fixture is built from Figure 27's field order and Tables 7 and 8's bit
/// assignments, with a distinct value in each field, and the decoder has to
/// land every one of them in the right place. Getting two bits the wrong way
/// round — Table 8 gives 0x04 to the Object ID and 0x08 to the Group ID, the
/// reverse of what an eye skimming Figure 27's field order might assume — is
/// invisible on any object that carries both fields, and every committed vector
/// carries both. Here each field is exercised alone.
///
/// The priority byte is 0xC0 on purpose: read as a variable-length integer it
/// would claim three bytes rather than one, so a decoder that mistook the field
/// for a varint desynchronizes instead of quietly agreeing.
///
/// # Ablation
///
/// Swapped `FETCH_OBJECT_ID_BIT` and `FETCH_GROUP_ID_BIT`, so 0x04 names the
/// Group ID and 0x08 the Object ID:
///
/// ```text
/// thread 'fetch_object_fields_are_present_exactly_as_the_flags_say' (55148) panicked at
/// crates\moqtap-codec\tests\draft17_data_stream_rules.rs:
/// assertion `left == right` failed: flags 0x04: group ID
///   left: Some(12)
///  right: None
/// ```
///
/// The same swap leaves every fetch vector passing, `d17_data_stream_fetch`
/// included: each of them sets both bits or neither, so the two readings agree
/// on every byte string in the corpus. This test is the only thing that parts
/// them.
#[test]
fn fetch_object_fields_are_present_exactly_as_the_flags_say() {
    for flags in 0x00u8..=0x7f {
        let group_present = flags & 0x08 != 0;
        let subgroup_present = flags & 0x40 == 0 && flags & 0x03 == 0x03;
        let object_present = flags & 0x04 != 0;
        let priority_present = flags & 0x10 != 0;
        let properties_present = flags & 0x20 != 0;

        let mut bytes = vec![flags];
        if group_present {
            bytes.push(10);
        }
        if subgroup_present {
            bytes.push(11);
        }
        if object_present {
            bytes.push(12);
        }
        if priority_present {
            bytes.push(0xC0);
        }
        if properties_present {
            bytes.extend_from_slice(&[0x02, 0x3C, 0x02]);
        }
        bytes.push(0x03);
        let framing_len = bytes.len();
        bytes.extend_from_slice(&hex("deadbe"));

        let mut cursor = &bytes[..];
        let header = FetchObjectHeader::decode(&mut cursor)
            .unwrap_or_else(|e| panic!("flags {flags:#04x}: {e:?}"));

        let field = |v: Option<VarInt>| v.map(VarInt::into_inner);
        assert_eq!(
            field(header.group_id),
            group_present.then_some(10),
            "flags {flags:#04x}: group ID"
        );
        assert_eq!(
            field(header.subgroup_id),
            subgroup_present.then_some(11),
            "flags {flags:#04x}: subgroup ID"
        );
        assert_eq!(
            field(header.object_id),
            object_present.then_some(12),
            "flags {flags:#04x}: object ID"
        );
        assert_eq!(
            header.publisher_priority,
            priority_present.then_some(0xC0),
            "flags {flags:#04x}: priority"
        );
        assert_eq!(
            header.properties,
            if properties_present { hex("3c02") } else { Vec::new() },
            "flags {flags:#04x}: properties"
        );
        assert_eq!(header.payload_length.into_inner(), 3, "flags {flags:#04x}: payload length");
        assert_eq!(
            cursor.remaining(),
            3,
            "flags {flags:#04x}: the decoder must stop at the payload"
        );

        let mut out = Vec::new();
        header.encode(&mut out).unwrap_or_else(|e| panic!("flags {flags:#04x}: encode {e:?}"));
        assert_eq!(out, bytes[..framing_len], "flags {flags:#04x}: re-encode");
    }
}

/// The fields a fetch object with these Serialization Flags puts on the wire,
/// followed by a payload length of zero.
///
/// Built from Figure 27's field order and Tables 7 and 8, with a distinct value
/// per field: group 10, subgroup 11, object 12, priority 0xC0, a two-byte
/// properties block.
fn fetch_object_body(flags: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    if flags & 0x08 != 0 {
        bytes.push(10);
    }
    if flags & 0x40 == 0 && flags & 0x03 == 0x03 {
        bytes.push(11);
    }
    if flags & 0x04 != 0 {
        bytes.push(12);
    }
    if flags & 0x10 != 0 {
        bytes.push(0xC0);
    }
    if flags & 0x20 != 0 {
        bytes.extend_from_slice(&[0x02, 0x3C, 0x02]);
    }
    bytes.push(0x00);
    bytes
}

/// The DATAGRAM bit removes the Subgroup ID field even when the mode bits ask
/// for one.
///
/// Draft-17 Section 10.4.4.1: "When 0x40 is set, it SHOULD set the two least
/// significant bits to zero and the subscriber MUST ignore the bits." A
/// publisher that ignores the SHOULD writes no Subgroup ID; a decoder that
/// honoured the mode bits anyway would read the Object ID as one and take the
/// stream apart from there.
///
/// # Ablation
///
/// Dropped the `flags & FETCH_DATAGRAM_BIT == 0` term from
/// `fetch_has_subgroup_id`:
///
/// ```text
/// thread 'the_datagram_flag_overrides_the_subgroup_mode_bits' (55812) panicked at
/// crates\moqtap-codec\tests\draft17_data_stream_rules.rs:
/// datagram-flagged object: VarInt(UnexpectedEnd)
/// ```
///
/// It fails on the buffer running out rather than on a wrong Subgroup ID, which
/// is the point: reading a field that is not there consumes the Object ID and
/// the priority in its place and then walks off the end of the object. The
/// presence sweep sees the same break as a misplaced value —
/// `flags 0x43: subgroup ID  left: Some(3)  right: None`.
#[test]
fn the_datagram_flag_overrides_the_subgroup_mode_bits() {
    // Flags 0x5F: DATAGRAM, priority, group ID, object ID, and mode bits 0b11
    // that the subscriber must ignore. Group 10, object 12, priority 0xC0,
    // payload length 0.
    let bytes = [0x5F, 10, 12, 0xC0, 0x00];
    let header = FetchObjectHeader::decode(&mut &bytes[..]).expect("datagram-flagged object");
    assert!(header.is_datagram());
    assert_eq!(header.subgroup_id, None, "a datagram object has no subgroup ID");
    assert_eq!(header.group_id.map(VarInt::into_inner), Some(10));
    assert_eq!(header.object_id.map(VarInt::into_inner), Some(12));
    assert_eq!(header.publisher_priority, Some(0xC0));
}

/// Only the Serialization Flags values draft-17 defines are accepted.
///
/// Section 10.4.4 reads the field as a bit set "when less than 128", defines
/// `0x8C` and `0x10C` in Table 6, and says of everything else: "Any other value
/// is a PROTOCOL_VIOLATION."
///
/// # Ablation
///
/// Removed the `fetch_flags_are_defined` guard from `FetchObjectHeader::decode`:
///
/// ```text
/// thread 'fetch_serialization_flags_the_draft_does_not_define_are_refused' (32144) panicked at
/// crates\moqtap-codec\tests\draft17_data_stream_rules.rs:
/// flags 0x080 are not defined, but decode accepted them
/// ```
#[test]
fn fetch_serialization_flags_the_draft_does_not_define_are_refused() {
    for flags in 0x00u64..=0x1ff {
        let defined = flags <= 0x7f || flags == 0x8c || flags == 0x10c;

        let mut bytes = Vec::new();
        VarInt::from_u64_moqt(flags).encode_moqt::<moqtap_codec::varint::Moqt17>(&mut bytes);
        // The fields the low seven bits name, so a refusal is never a short
        // buffer in disguise.
        bytes.extend_from_slice(&fetch_object_body(flags));

        let result = FetchObjectHeader::decode(&mut &bytes[..]);
        if defined {
            result.unwrap_or_else(|e| panic!("flags {flags:#05x} are defined: {e:?}"));
        } else {
            match result {
                Ok(_) => panic!("flags {flags:#05x} are not defined, but decode accepted them"),
                Err(e) => assert!(
                    matches!(e, CodecError::InvalidField),
                    "flags {flags:#05x} were refused with {e:?}, not InvalidField"
                ),
            }
        }
    }
}

/// The two end-of-range markers are recognised, and neither inherits anything
/// from the object before it.
///
/// Draft-17 Section 10.4.4.2: "the Group ID and Object ID fields are present.
/// Subgroup ID, Priority and Properties are not present." Because a marker
/// states its own Location outright, "the last serialized Object, if any"
/// allows one to open a FETCH response — so it must not be reported as
/// referencing a prior object, which is the condition Section 10.4.4 makes a
/// PROTOCOL_VIOLATION on the first object.
///
/// # Ablation
///
/// Deleted the `end_of_range().is_some()` short circuit from
/// `references_prior_object`, leaving the absent Priority field to decide:
///
/// ```text
/// thread 'the_end_of_range_markers_inherit_nothing' (57204) panicked at
/// crates\moqtap-codec\tests\draft17_data_stream_rules.rs:
/// 808c: an end-of-range marker inherits nothing
/// ```
#[test]
fn the_end_of_range_markers_inherit_nothing() {
    for (hex_bytes, expected) in
        [("808c 05 0a 00", EndOfRange::NonExistent), ("810c 05 0a 00", EndOfRange::Unknown)]
    {
        let bytes = hex(hex_bytes);
        let header = FetchObjectHeader::decode(&mut &bytes[..])
            .unwrap_or_else(|e| panic!("{hex_bytes}: {e:?}"));
        assert_eq!(header.end_of_range(), Some(expected));
        assert_eq!(header.group_id.map(VarInt::into_inner), Some(5));
        assert_eq!(header.object_id.map(VarInt::into_inner), Some(10));
        assert_eq!(header.subgroup_id, None);
        assert_eq!(header.publisher_priority, None);
        assert!(header.properties.is_empty());
        assert!(
            !header.references_prior_object(),
            "{}: an end-of-range marker inherits nothing",
            &hex_bytes[..4]
        );

        let mut out = Vec::new();
        header.encode(&mut out).expect("an end-of-range marker must re-encode");
        assert_eq!(out, bytes, "{hex_bytes}: re-encode");
    }
}

/// An object that leaves a field to the prior object says so.
///
/// Draft-17 Section 10.4.4.1: "If the first Object in the FETCH response uses a
/// flag that references fields in the prior Object, the Subscriber MUST close
/// the session with a PROTOCOL_VIOLATION." One object's bytes cannot say
/// whether it is the first, so the decoder cannot enforce that rule; this is
/// the half it can supply.
///
/// SUBGROUP mode `0b00` is the case worth pinning: it leaves the Subgroup ID
/// field off the wire like modes `0b01` and `0b10` do, but Table 7 fixes the ID
/// at zero rather than drawing it from anywhere, so it inherits nothing.
///
/// # Ablation
///
/// Added mode `0x00` to the mode arm of `references_prior_object`:
///
/// ```text
/// thread 'an_object_that_inherits_a_field_reports_it' (12736) panicked at
/// crates\moqtap-codec\tests\draft17_data_stream_rules.rs:
/// flags 0x1c: inherits nothing
/// ```
#[test]
fn an_object_that_inherits_a_field_reports_it() {
    // Group, object and priority all present; subgroup mode 0b00 fixes the
    // subgroup at zero. Nothing is drawn from a prior object.
    let bytes = [0x1C, 0, 0, 0x80, 0x00];
    let header = FetchObjectHeader::decode(&mut &bytes[..]).expect("self-contained object");
    assert!(!header.references_prior_object(), "flags 0x1c: inherits nothing");

    // Each of these leaves exactly one field to the prior object.
    for (flags, what) in [
        (0x14u8, "group ID"),
        (0x18u8, "object ID"),
        (0x0Cu8, "priority"),
        (0x1Du8, "subgroup ID, mode 0b01"),
        (0x1Eu8, "subgroup ID, mode 0b10"),
    ] {
        let mut bytes = vec![flags];
        if flags & 0x08 != 0 {
            bytes.push(0);
        }
        if flags & 0x03 == 0x03 {
            bytes.push(0);
        }
        if flags & 0x04 != 0 {
            bytes.push(0);
        }
        if flags & 0x10 != 0 {
            bytes.push(0x80);
        }
        bytes.push(0x00);
        let header = FetchObjectHeader::decode(&mut &bytes[..])
            .unwrap_or_else(|e| panic!("flags {flags:#04x}: {e:?}"));
        assert!(header.references_prior_object(), "flags {flags:#04x} inherit the {what}");
    }
}

/// The encoder refuses a value whose fields and flags disagree, and writes
/// nothing when it does.
///
/// There is no default to fall back on: a Group ID the flags announce and the
/// value omits cannot be invented, and skipping the field would slide the next
/// one into its place and desynchronize every object after it.
///
/// # Ablation
///
/// Deleted the presence-agreement check from `FetchObjectHeader::encode`:
///
/// ```text
/// thread 'the_fetch_encoder_refuses_fields_that_disagree_with_the_flags' (53584) panicked at
/// crates\moqtap-codec\tests\draft17_data_stream_rules.rs:
/// encode wrote an object whose flags announce a group ID it does not have
/// ```
#[test]
fn the_fetch_encoder_refuses_fields_that_disagree_with_the_flags() {
    let complete = FetchObjectHeader {
        serialization_flags: VarInt::from_u64_moqt(0x1C),
        group_id: Some(VarInt::from_u64_moqt(10)),
        subgroup_id: None,
        object_id: Some(VarInt::from_u64_moqt(12)),
        publisher_priority: Some(0x80),
        properties: Vec::new(),
        payload_length: VarInt::from_u64_moqt(0),
    };
    let mut buf = Vec::new();
    complete.encode(&mut buf).expect("a consistent object must encode");
    assert_eq!(buf, vec![0x1C, 10, 12, 0x80, 0x00]);

    let missing_group = FetchObjectHeader { group_id: None, ..complete.clone() };
    let mut buf = Vec::new();
    assert!(
        missing_group.encode(&mut buf).is_err(),
        "encode wrote an object whose flags announce a group ID it does not have"
    );
    assert!(buf.is_empty(), "a refused object left {} byte(s) behind", buf.len());

    // Properties held while the PROPERTIES bit is clear would be dropped
    // silently, so they are refused instead.
    let stray_properties = FetchObjectHeader { properties: hex("3c02"), ..complete.clone() };
    let mut buf = Vec::new();
    assert!(
        stray_properties.encode(&mut buf).is_err(),
        "encode dropped a properties block the flags do not carry"
    );
    assert!(buf.is_empty());

    // A subgroup ID the mode bits do not ask for is the same mistake.
    let stray_subgroup =
        FetchObjectHeader { subgroup_id: Some(VarInt::from_u64_moqt(7)), ..complete };
    let mut buf = Vec::new();
    assert!(
        stray_subgroup.encode(&mut buf).is_err(),
        "encode dropped a subgroup ID the mode bits do not carry"
    );
    assert!(buf.is_empty());
}

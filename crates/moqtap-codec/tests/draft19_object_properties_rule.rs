#![cfg(feature = "draft19")]
//! Draft-19 forbids Object Properties on an Object whose status is not Normal,
//! and this crate reports that rather than refusing to parse it.
//!
//! Section 11.2.1.2: "Any Object with status Normal can have properties
//! (Section 2.5). If an endpoint receives properties on an Object with status
//! that is not Normal, it MUST close the session with a PROTOCOL_VIOLATION."
//! Section 11.3.1 builds the datagram's Properties field out of that same
//! structure, so the rule covers both carriers.
//!
//! # Why the decoder still accepts it
//!
//! There are two rules about what may sit beside an Object Status, and they are
//! not the same kind of rule.
//!
//! A payload beside a forbidden status has no encoding. The status field and
//! the payload occupy the same position — a subgroup object carries a status
//! exactly when its Object Payload Length is zero — so no sequence of bytes
//! states both. Refusing it in the writer is refusing to write something that
//! does not exist.
//!
//! Properties beside a status encode perfectly well. The block sits between the
//! properties length and the status field and is read back byte for byte. The
//! frame is well formed and non-conforming, which is a judgement about what a
//! peer is allowed to send, not about what the bytes mean. A codec that refused
//! to decode it could not report the violation, and one that refused to encode
//! it could not reproduce a capture containing it — including the
//! `subgroup-properties-status-object` vector this crate is checked against,
//! which is exactly this frame.
//!
//! So the codec reads and writes it, `properties_permitted()` reports it, and
//! the endpoint acts on it. That split is what these tests pin: the predicate
//! must be able to say "no" while the codec still round-trips the bytes.

use moqtap_codec::draft19::data_stream::{
    DatagramHeader, SubgroupHeader, SubgroupObject, SubgroupObjectReader,
};
use moqtap_codec::draft19::types::ObjectStatus;
use moqtap_codec::varint::VarInt;

fn hex(bytes: &str) -> Vec<u8> {
    (0..bytes.len()).step_by(2).map(|i| u8::from_str_radix(&bytes[i..i + 2], 16).unwrap()).collect()
}

/// The committed `subgroup-properties-status-object` vector: a subgroup stream
/// of type 0x11 (PROPERTIES set) holding one status-only object, End of Group,
/// with a two-byte properties blob.
const PROPERTIES_ON_END_OF_GROUP: &str = "1101008000023c010003";

/// A properties block on a non-Normal status is decoded, and reported.
#[test]
fn properties_on_a_non_normal_status_decode_and_are_reported_as_forbidden() {
    let bytes = hex(PROPERTIES_ON_END_OF_GROUP);
    let mut cursor = &bytes[..];
    let header = SubgroupHeader::decode(&mut cursor).expect("the header parses");
    assert!(header.has_properties(), "the vector's type byte sets PROPERTIES");

    let mut reader = SubgroupObjectReader::new(&header);
    let object = reader.read_object(&mut cursor).expect(
        "the frame is well formed; a decoder that refused it could not report the violation",
    );

    assert_eq!(object.status(), ObjectStatus::EndOfGroup);
    assert_eq!(object.extension_headers, vec![0x3c, 0x01]);
    assert!(
        !object.properties_permitted(),
        "properties on End of Group are forbidden by draft-19 Section 11.2.1.2 and must be \
         reported as such"
    );
}

/// The same object re-encodes to the bytes it came from.
///
/// This is the half that keeps the codec able to reproduce a capture. It also
/// fails if the writer is ever taught to refuse this object, which is the change
/// the module docs argue against.
#[test]
fn a_forbidden_properties_object_still_round_trips_byte_for_byte() {
    let bytes = hex(PROPERTIES_ON_END_OF_GROUP);
    let mut cursor = &bytes[..];
    let header = SubgroupHeader::decode(&mut cursor).expect("the header parses");
    let mut reader = SubgroupObjectReader::new(&header);
    let object = reader.read_object(&mut cursor).expect("the object parses");

    let mut out = Vec::new();
    header.encode(&mut out);
    let mut writer = SubgroupObjectReader::new(&header);
    writer
        .write_object(&object, &mut out)
        .expect("the writer must be able to produce a frame the reader accepts");

    assert_eq!(out, bytes, "the object did not survive a decode/encode round trip");
}

/// Properties are fine at Normal, and absent properties are fine at any status.
///
/// Without this the predicate could be satisfied by one that answered "no" to
/// every object carrying properties, or to every non-Normal object.
#[test]
fn the_rule_is_about_the_pair_and_not_about_either_half() {
    let header_bytes = hex("1101008000");
    let mut cursor = &header_bytes[..];
    let header = SubgroupHeader::decode(&mut cursor).expect("the header parses");

    let cases = [
        // (status, properties, permitted)
        (Some(ObjectStatus::Normal), vec![0x3c, 0x01], true),
        (None, vec![0x3c, 0x01], true),
        (Some(ObjectStatus::EndOfGroup), vec![], true),
        (Some(ObjectStatus::EndOfTrack), vec![], true),
        (Some(ObjectStatus::EndOfGroup), vec![0x3c, 0x01], false),
        (Some(ObjectStatus::EndOfTrack), vec![0x3c, 0x01], false),
    ];

    for (status, properties, expected) in cases {
        let object = SubgroupObject {
            object_id: VarInt::from_u64_moqt(0),
            extension_headers: properties.clone(),
            payload_length: VarInt::from_u64_moqt(0),
            object_status: status,
            payload: Vec::new(),
        };
        assert_eq!(
            object.properties_permitted(),
            expected,
            "status {:?} with {} bytes of properties: expected permitted={expected}",
            object.status(),
            properties.len()
        );
        // A writer for each case, so the encode side is exercised too and the
        // predicate cannot drift away from what actually gets written.
        let mut writer = SubgroupObjectReader::new(&header);
        let mut out = Vec::new();
        writer.write_object(&object, &mut out).expect("every case here is representable");
    }
}

/// The datagram carrier answers the same way.
#[test]
fn a_datagram_applies_the_same_properties_rule() {
    let cases = [
        // type 0x21: PROPERTIES (0x01) and STATUS (0x20).
        (0x21u8, Some(ObjectStatus::EndOfGroup), vec![0x3c, 0x01], false),
        (0x21, Some(ObjectStatus::Normal), vec![0x3c, 0x01], true),
        // STATUS without PROPERTIES: nothing to be forbidden.
        (0x20, Some(ObjectStatus::EndOfGroup), vec![], true),
    ];

    for (datagram_type, status, properties, expected) in cases {
        let header = DatagramHeader {
            datagram_type,
            track_alias: VarInt::from_u64_moqt(1),
            group_id: VarInt::from_u64_moqt(0),
            object_id: VarInt::from_u64_moqt(0),
            publisher_priority: None,
            properties: properties.clone(),
            object_status: status,
        };
        assert_eq!(
            header.properties_permitted(),
            expected,
            "datagram type {datagram_type:#x} at status {:?} with {} bytes of properties",
            header.status(),
            properties.len()
        );

        // And the bytes still round-trip, forbidden or not.
        let mut out = Vec::new();
        header.encode(&mut out);
        let mut cursor = &out[..];
        let back = DatagramHeader::decode(&mut cursor).expect("the datagram parses back");
        assert_eq!(back.properties, properties);
        assert_eq!(back.properties_permitted(), expected);
    }
}

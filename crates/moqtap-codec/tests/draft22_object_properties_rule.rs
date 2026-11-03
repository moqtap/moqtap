#![cfg(feature = "draft22")]
//! Draft-22 forbids Object Properties on an Object whose status is not Normal.
//!
//! Section 11.1.2: "Any Object with status Normal can have properties
//! (Section 8.4). If an endpoint receives properties on an Object with status
//! that is not Normal, it MUST close the session with a PROTOCOL_VIOLATION."
//! Section 11.2.1 builds the datagram's Properties field out of that same
//! structure, so the rule covers both carriers.
//!
//! The readers that hand back a whole object refuse it, and so do the writers.
//! The framing readers a relay uses (`SubgroupObjectReader::read_object_meta`,
//! `DatagramHeader::decode`) do not judge it, and `properties_permitted()`
//! answers the question for them.

use moqtap_codec::draft22::data_stream::{
    DatagramHeader, SubgroupHeader, SubgroupObject, SubgroupObjectReader,
};
use moqtap_codec::draft22::types::ObjectStatus;
use moqtap_codec::error::CodecError;
use moqtap_codec::varint::VarInt;

fn hex(bytes: &str) -> Vec<u8> {
    (0..bytes.len()).step_by(2).map(|i| u8::from_str_radix(&bytes[i..i + 2], 16).unwrap()).collect()
}

/// The committed `subgroup-properties-status-object` vector: a subgroup stream
/// of type 0x11 (PROPERTIES set), Group 5, holding one status-only object, End
/// of Group, with a two-byte properties blob.
const PROPERTIES_ON_END_OF_GROUP: &str = "1101058000023c010003";

/// A properties block on a non-Normal status is refused by the whole-object
/// reader and framed by the meta reader.
#[test]
fn properties_on_a_non_normal_status_are_refused_and_framed() {
    let bytes = hex(PROPERTIES_ON_END_OF_GROUP);
    let mut cursor = &bytes[..];
    let header = SubgroupHeader::decode(&mut cursor).expect("the header parses");
    assert!(header.has_properties(), "the vector's type byte sets PROPERTIES");

    let mut reader = SubgroupObjectReader::new(&header);
    assert!(matches!(reader.read_object(&mut &cursor[..]), Err(CodecError::InvalidField)));

    let mut reader = SubgroupObjectReader::new(&header);
    let meta = reader.read_object_meta(&mut &cursor[..]).expect("the framing parses");
    assert_eq!(meta.extension_headers_len, 2);
    assert_eq!(meta.status, Some(ObjectStatus::EndOfGroup.as_u64()));
}

/// The writer will not produce the object the reader refuses.
#[test]
fn a_forbidden_properties_object_is_not_written() {
    let header_bytes = hex("1101008000");
    let header = SubgroupHeader::decode(&mut &header_bytes[..]).expect("the header parses");
    let object = SubgroupObject {
        object_id: VarInt::from_u64_moqt(0),
        extension_headers: vec![0x3c, 0x01],
        payload_length: VarInt::from_u64_moqt(0),
        object_status: Some(ObjectStatus::EndOfGroup),
        payload: Vec::new(),
    };
    let mut writer = SubgroupObjectReader::new(&header);
    let mut out = Vec::new();
    assert_eq!(writer.write_object(&object, &mut out), Err(CodecError::InvalidField));
    assert!(out.is_empty());
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
        // The writer agrees with the predicate.
        let mut writer = SubgroupObjectReader::new(&header);
        let mut out = Vec::new();
        assert_eq!(writer.write_object(&object, &mut out).is_ok(), expected);
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

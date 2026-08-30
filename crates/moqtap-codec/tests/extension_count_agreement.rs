#![cfg(feature = "draft08")]

//! Draft-08 states its extension block as a count, and the count must agree
//! with the bytes.
//!
//! Extension headers arrive at draft-08 — the string "Extension Header" appears
//! nowhere in draft-07 — and draft-08 is the only draft that frames the block
//! as `Extension Count (i)`, a number of headers. Draft-09 replaced it with a
//! byte length, and every encoder from there on derives that length from the
//! extension bytes beside it, so the two cannot disagree.
//!
//! On draft-08 they are two fields with nothing tying them together: the
//! encoder wrote the caller's count and then the caller's bytes. A header
//! stating two extensions while carrying three left the third where the peer
//! expects the Object Payload Length, so that field and every field after it —
//! and every object after that on the same stream — were read at the wrong
//! offset. Nothing downstream can recover from that, which is why
//! `encode_checked` refuses rather than correcting the count.
//!
//! The reader is the other half of the argument: `skip_extensions` reads
//! exactly `count` headers and stops, so it never notices the surplus. Both
//! halves are exercised below — what the checked encoder refuses, and what the
//! unchecked one produces if it is allowed to.

use moqtap_codec::draft08::data_stream::{DatagramHeader, FetchObjectHeader, ObjectHeader};
use moqtap_codec::draft08::types::ObjectStatus;
use moqtap_codec::varint::VarInt;

fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).unwrap()
}

/// Two whole extension headers: an even type with a varint value, and an odd
/// type with a length-prefixed one. Section 8.1.1.2: "even types are followed
/// by a single varint encoded value. Odd types are followed by a varint encoded
/// length and then the header value."
fn two_extensions() -> Vec<u8> {
    let mut raw = Vec::new();
    varint(0x02).encode(&mut raw);
    varint(0x2a).encode(&mut raw);
    varint(0x03).encode(&mut raw);
    varint(2).encode(&mut raw);
    raw.extend_from_slice(b"hi");
    raw
}

fn object(count: u64) -> ObjectHeader {
    ObjectHeader {
        object_id: varint(1),
        extension_count: varint(count),
        extensions: two_extensions(),
        payload_length: varint(0),
        object_status: ObjectStatus::Normal,
    }
}

/// A count that does not match the bytes has no encoding.
///
/// Dropping the check fails with:
///
/// ```text
/// 1 extension is not what these bytes hold: Ok(())
/// ```
#[test]
fn a_stated_count_below_the_bytes_never_reaches_the_wire() {
    let mut buf = Vec::new();
    let result = object(1).encode_checked(&mut buf);
    assert!(result.is_err(), "1 extension is not what these bytes hold: {result:?}");
    assert!(buf.is_empty(), "a refused header must leave the buffer untouched");
}

/// And above, which is the shape that makes the reader run past the block.
#[test]
fn a_stated_count_above_the_bytes_never_reaches_the_wire() {
    let mut buf = Vec::new();
    let result = object(3).encode_checked(&mut buf);
    assert!(result.is_err(), "3 extensions is not what these bytes hold: {result:?}");
}

/// The count that matches is carried, and reads back with its extensions
/// intact. Without this the gates above would pass on an encoder that refused
/// every object carrying extensions.
#[test]
fn the_count_the_bytes_hold_round_trips() {
    let header = object(2);
    let mut buf = Vec::new();
    header.encode_checked(&mut buf).expect("two headers is what these bytes hold");

    let decoded = ObjectHeader::decode(&mut &buf[..]).expect("what this codec wrote it must read");
    assert_eq!(decoded, header);
}

/// An empty block is a count of zero, not a count of one empty header.
#[test]
fn no_extensions_is_a_count_of_zero() {
    let header = ObjectHeader { extension_count: varint(0), extensions: Vec::new(), ..object(0) };
    let mut buf = Vec::new();
    header.encode_checked(&mut buf).expect("no extensions is a legal block");

    let mismatched =
        ObjectHeader { extension_count: varint(1), extensions: Vec::new(), ..object(0) };
    let mut other = Vec::new();
    assert!(
        mismatched.encode_checked(&mut other).is_err(),
        "an empty block holds no headers, whatever the count says",
    );
}

/// Bytes that do not tile into whole headers are refused whatever the count
/// says: an odd type whose declared value length runs past the block would be
/// read by the peer as a length reaching into the fields after it.
#[test]
fn a_block_that_does_not_tile_into_whole_headers_is_refused() {
    let mut truncated = Vec::new();
    varint(0x03).encode(&mut truncated);
    varint(8).encode(&mut truncated);
    truncated.extend_from_slice(b"four");

    for count in [0, 1, 2] {
        let header = ObjectHeader {
            extension_count: varint(count),
            extensions: truncated.clone(),
            ..object(0)
        };
        let mut buf = Vec::new();
        assert!(
            header.encode_checked(&mut buf).is_err(),
            "a header declaring 8 value bytes and carrying 4 is not a header",
        );
    }
}

/// The unchecked encoder is what the checked one exists to stand in front of.
/// It writes the stated count and the bytes beside it, and the reader stops
/// after the stated number of headers — so the surplus bytes land where the
/// Object Payload Length belongs and the object decodes to something the
/// caller never described.
#[test]
fn the_unchecked_encoder_produces_the_desynchronised_frame() {
    let mut buf = Vec::new();
    object(1).encode(&mut buf);

    // Either outcome makes the point: the frame is refused outright, or it is
    // read back as an object the caller never described. What it cannot be is
    // the object that went in.
    if let Ok(header) = ObjectHeader::decode(&mut &buf[..]) {
        assert_ne!(
            header,
            object(1),
            "the frame the unchecked encoder wrote does not read back as what it was given",
        );
    }
}

/// The datagram header carries the same pair of fields and the same rule.
#[test]
fn a_datagram_states_the_count_its_bytes_hold() {
    let header = DatagramHeader {
        track_alias: varint(4),
        group_id: varint(1),
        object_id: varint(2),
        publisher_priority: 3,
        extension_count: varint(2),
        extensions: two_extensions(),
        payload_length: varint(0),
        object_status: ObjectStatus::Normal,
    };
    let mut buf = Vec::new();
    header.encode_checked(&mut buf).expect("two headers is what these bytes hold");

    let wrong = DatagramHeader { extension_count: varint(1), ..header };
    let mut other = Vec::new();
    assert!(wrong.encode_checked(&mut other).is_err(), "1 is not 2");
}

/// And so does the fetch object header.
#[test]
fn a_fetch_object_states_the_count_its_bytes_hold() {
    let header = FetchObjectHeader {
        group_id: varint(1),
        subgroup_id: varint(0),
        object_id: varint(2),
        publisher_priority: 3,
        extension_count: varint(2),
        extensions: two_extensions(),
        payload_length: varint(0),
        object_status: ObjectStatus::Normal,
    };
    let mut buf = Vec::new();
    header.encode_checked(&mut buf).expect("two headers is what these bytes hold");

    let wrong = FetchObjectHeader { extension_count: varint(5), ..header };
    let mut other = Vec::new();
    assert!(wrong.encode_checked(&mut other).is_err(), "5 is not 2");
}

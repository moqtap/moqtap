#![cfg(feature = "draft19")]
//! What draft-19's encoders emit, its decoders accept — and what they cannot
//! emit faithfully, they refuse instead of rewriting.
//!
//! Three separate ways a codec can lie about a value, each gated below by
//! putting the value through the encoder and reading the result back rather
//! than by inspecting the encoder.
//!
//! # A frame the encoder writes and the decoder rejects
//!
//! Two of draft-19's three uint8-valued Message Parameters restrict their
//! range, and the draft answers a value outside it with a session close:
//! GROUP_ORDER (0x22) allows only Ascending and Descending (Section 10.2.8),
//! FORWARD (0x10) only 0 and 1 (Section 10.2.17). Checking that on decode alone
//! leaves the encoder free to produce a SUBSCRIBE this crate's own decoder will
//! not read — an asymmetry that turns into a session close at the far end,
//! attributed to the sender.
//!
//! # A value the encoder silently changes
//!
//! A uint8 parameter occupies one octet. A value that does not fit one has to
//! go somewhere, and truncation to the low byte is the quiet answer: GROUP_ORDER
//! 258 becomes 0x02, which is a perfectly valid Descending. The frame is well
//! formed, the receiver has no way to tell, and the value the caller asked for
//! is gone. There is no correct byte to write, so the only answer that does not
//! invent one is to refuse.
//!
//! # A field the encoder drops
//!
//! A datagram's type byte says which fields are present; the STATUS bit (0x20)
//! is what puts a status field on the wire. A header holding an object status
//! under a type byte without that bit is asking for two things at once, and
//! writing the type byte's version discards the status — an End of Group marker
//! that arrives as an ordinary payload object, indistinguishable from one that
//! never carried a status at all. `encode_checked` refuses that pair.
//!
//! Normal is the exception, and it is here so the refusal is not mistaken for a
//! refusal of any status with the bit clear. Normal is the status the encoding
//! elides
//! for every payload-bearing object, so stating it asks for exactly the bytes
//! that leaving it out asks for and nothing is lost.

use moqtap_codec::draft19::data_stream::DatagramHeader;
use moqtap_codec::draft19::message::{ControlMessage, Subscribe};
use moqtap_codec::draft19::types::ObjectStatus;
use moqtap_codec::error::CodecError;
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::types::TrackNamespace;
use moqtap_codec::varint::VarInt;

/// FORWARD, a uint8 parameter draft-19 Section 10.2.17 limits to 0 and 1.
const FORWARD: u64 = 0x10;
/// GROUP_ORDER, a uint8 parameter draft-19 Section 10.2.8 limits to 1 and 2.
const GROUP_ORDER: u64 = 0x22;
/// SUBSCRIBER_PRIORITY, the uint8 parameter that uses the whole octet
/// (Section 10.2.7) and so must survive every value a byte can hold.
const SUBSCRIBER_PRIORITY: u64 = 0x20;

/// A SUBSCRIBE carrying one parameter, the smallest message that reaches the
/// parameter codec.
fn subscribe_with(key: u64, value: u64) -> ControlMessage {
    ControlMessage::Subscribe(Subscribe {
        request_id: VarInt::from_u64_moqt(0),
        track_namespace: TrackNamespace(vec![b"a".to_vec()]),
        track_name: b"b".to_vec(),
        parameters: vec![KeyValuePair {
            key: VarInt::from_u64_moqt(key),
            value: KvpValue::Varint(VarInt::from_u64_moqt(value)),
        }],
    })
}

fn encode(msg: &ControlMessage) -> Result<Vec<u8>, CodecError> {
    let mut buf = Vec::new();
    msg.encode(&mut buf)?;
    Ok(buf)
}

// ── Encode and decode agree on which frames exist ─────────────

/// Values outside a uint8 parameter's range are refused by the encoder, not
/// just by the decoder.
///
/// Replacing the encoder's range check with a truncating one-liner
/// (`buf.put_u8(v.into_inner() as u8)`) fails this test with:
///
/// ```text
/// assertion `left == right` failed: GROUP_ORDER = 7: the encoder said Ok("ok")
/// and the decoder said false. A frame this crate writes must be one this crate
/// reads; encoded bytes were [3, 0, 9, 0, 1, 1, 97, 1, 98, 1, 34, 7]
///   left: true
///  right: false
/// ```
///
/// The trailing `34, 7` is the parameter: key 0x22, value 7 — a SUBSCRIBE this
/// crate emits and this crate will not read back.
#[test]
fn the_encoder_refuses_uint8_parameter_values_its_decoder_would_reject() {
    // In-range and out-of-range together. The assertion is not that these
    // values are refused but that the two directions agree, so an encoder that
    // refused everything fails it just as an encoder that refused nothing does.
    let cases: [(u64, &str, u64); 6] = [
        (GROUP_ORDER, "GROUP_ORDER", 1),
        (GROUP_ORDER, "GROUP_ORDER", 2),
        (GROUP_ORDER, "GROUP_ORDER", 7),
        (FORWARD, "FORWARD", 0),
        (FORWARD, "FORWARD", 1),
        (FORWARD, "FORWARD", 200),
    ];
    for (key, name, value) in cases {
        let encoded = encode(&subscribe_with(key, value));
        let decodes = match &encoded {
            Ok(bytes) => {
                let mut cursor = &bytes[..];
                ControlMessage::decode(&mut cursor).is_ok()
            }
            // Nothing was produced, so there is nothing to read back; the two
            // directions agree that this frame does not exist.
            Err(_) => false,
        };
        assert_eq!(
            encoded.is_ok(),
            decodes,
            "{name} = {value}: the encoder said {:?} and the decoder said {}. \
             A frame this crate writes must be one this crate reads; encoded bytes were {:?}",
            encoded.as_ref().map(|_| "ok"),
            decodes,
            encoded.as_deref().unwrap_or(&[])
        );
    }
}

/// Every in-range value survives the round trip unchanged, so the refusal above
/// is not the encoder simply having become hostile to parameters.
#[test]
fn in_range_uint8_parameter_values_still_round_trip() {
    let cases = [
        (GROUP_ORDER, 1u64),
        (GROUP_ORDER, 2),
        (FORWARD, 0),
        (FORWARD, 1),
        // The unrestricted one, at both ends of the octet.
        (SUBSCRIBER_PRIORITY, 0),
        (SUBSCRIBER_PRIORITY, 255),
    ];
    for (key, value) in cases {
        let bytes = encode(&subscribe_with(key, value))
            .unwrap_or_else(|e| panic!("parameter {key:#x} = {value} would not encode: {e:?}"));
        let mut cursor = &bytes[..];
        let back = ControlMessage::decode(&mut cursor)
            .unwrap_or_else(|e| panic!("parameter {key:#x} = {value} would not decode: {e:?}"));
        let ControlMessage::Subscribe(s) = back else {
            panic!("parameter {key:#x} = {value} decoded as something other than SUBSCRIBE");
        };
        let got = match &s.parameters[0].value {
            KvpValue::Varint(v) => v.into_inner(),
            other => panic!("parameter {key:#x} came back as {other:?}"),
        };
        assert_eq!(got, value, "parameter {key:#x} changed value across a round trip");
    }
}

/// A uint8 parameter value too large for its octet is refused rather than
/// truncated into a different, legal value.
///
/// This is the case the range check alone would miss. 258 is not in
/// GROUP_ORDER's range, but its low byte is 2 — Descending — so truncating
/// first and checking after produces a frame that passes every later check and
/// carries a value nobody asked for.
///
/// With that truncating one-liner in place, this test fails with the corrupted
/// value visible in the bytes:
///
/// ```text
/// GROUP_ORDER = 258 must not encode; its low byte is a valid Descending and the
/// receiver could not tell the difference: [3, 0, 9, 0, 1, 1, 97, 1, 98, 1, 34, 2]
/// ```
///
/// `34, 2` — key 0x22, value 2. The 258 the caller asked for is gone and a
/// well-formed Descending stands in its place.
#[test]
fn a_uint8_parameter_value_too_wide_for_its_octet_is_not_truncated() {
    // 258 == 0x102: low byte 0x02, which is GROUP_ORDER's Descending.
    let err = encode(&subscribe_with(GROUP_ORDER, 258)).expect_err(
        "GROUP_ORDER = 258 must not encode; its low byte is a valid Descending and \
         the receiver could not tell the difference",
    );
    assert!(matches!(err, CodecError::InvalidField), "refused with {err:?}");

    // Same shape on the parameter with no range restriction, where the only
    // thing wrong is the width. 256 truncates to 0, a legal priority.
    let err = encode(&subscribe_with(SUBSCRIBER_PRIORITY, 256))
        .expect_err("SUBSCRIBER_PRIORITY = 256 does not fit one octet and must not encode");
    assert!(matches!(err, CodecError::InvalidField), "refused with {err:?}");

    // And the value one below the overflow still works, so the boundary is
    // where it should be rather than the check being over-eager.
    let bytes = encode(&subscribe_with(SUBSCRIBER_PRIORITY, 255))
        .expect("255 fits one octet and must still encode");
    let mut cursor = &bytes[..];
    ControlMessage::decode(&mut cursor).expect("255 must decode");
}

// ── A datagram cannot lose its status ─────────────────────────

fn datagram(datagram_type: u8, object_status: Option<ObjectStatus>) -> DatagramHeader {
    DatagramHeader {
        datagram_type,
        track_alias: VarInt::from_u64_moqt(1),
        group_id: VarInt::from_u64_moqt(0),
        object_id: VarInt::from_u64_moqt(0),
        publisher_priority: None,
        properties: Vec::new(),
        object_status,
    }
}

/// A status the datagram's framing has no field for is refused, not dropped.
///
/// The unchecked `encode` still writes the type byte's version of the header,
/// and that is what makes the loss invisible: the same header goes out as an
/// ordinary payload object. Both halves are asserted, so the test fails if
/// `encode_checked` ever becomes a synonym for `encode`.
///
/// Deleting the guard from `encode_checked` — leaving it as a call to `encode`
/// that always returns `Ok` — fails this test with:
///
/// ```text
/// ---- a_datagram_status_the_framing_cannot_carry_is_refused_rather_than_dropped stdout ----
/// thread '...' panicked at crates\moqtap-codec\tests\draft19_encode_decode_symmetry.rs:
/// a status with no field on the wire must be refused: ()
/// ```
#[test]
fn a_datagram_status_the_framing_cannot_carry_is_refused_rather_than_dropped() {
    // 0x08: DEFAULT_PRIORITY set, STATUS (0x20) clear — a payload datagram.
    for status in [ObjectStatus::EndOfGroup, ObjectStatus::EndOfTrack] {
        let header = datagram(0x08, Some(status));

        let mut checked = Vec::new();
        let err = header
            .encode_checked(&mut checked)
            .expect_err("a status with no field on the wire must be refused");
        assert!(matches!(err, CodecError::InvalidField), "refused with {err:?}");
        assert!(checked.is_empty(), "a refused header must leave the buffer untouched");

        // What refusing prevents: the raw encoder writes a header that reads
        // back as a normal payload object with the marker gone.
        let mut raw = Vec::new();
        header.encode(&mut raw);
        let mut cursor = &raw[..];
        let back = DatagramHeader::decode(&mut cursor).expect("the raw header still parses");
        assert_eq!(
            back.object_status, None,
            "the unchecked encoder is expected to drop {status:?}; if it no longer does, \
             this test is asserting the wrong thing"
        );
        assert!(
            back.permits_payload(),
            "the dropped status reads back as Normal, which is why the loss is silent"
        );
    }
}

/// Normal with the STATUS bit clear is accepted, because nothing is lost.
///
/// It is the status the encoding elides for a payload-bearing object, so
/// stating it and omitting it ask for the same bytes — and the test checks they
/// really are the same bytes rather than trusting the rule.
#[test]
fn a_datagram_stating_normal_without_the_status_bit_encodes_to_the_same_bytes() {
    let stated = datagram(0x08, Some(ObjectStatus::Normal));
    let omitted = datagram(0x08, None);

    let mut a = Vec::new();
    stated.encode_checked(&mut a).expect("Normal loses nothing when the bit is clear");
    let mut b = Vec::new();
    omitted.encode_checked(&mut b).expect("no status at all is plainly fine");

    assert_eq!(a, b, "stating Normal changed the bytes, so it was not the elided status");
}

/// A status the framing does carry is written and read back intact.
///
/// Without this the refusal above could be satisfied by an encoder that refused
/// every status.
#[test]
fn a_datagram_with_the_status_bit_carries_its_status() {
    // 0x28: DEFAULT_PRIORITY (0x08) and STATUS (0x20).
    for status in [ObjectStatus::Normal, ObjectStatus::EndOfGroup, ObjectStatus::EndOfTrack] {
        let header = datagram(0x28, Some(status));
        let mut buf = Vec::new();
        header.encode_checked(&mut buf).expect("the framing has a field for this status");
        let mut cursor = &buf[..];
        let back = DatagramHeader::decode(&mut cursor).expect("must decode");
        assert_eq!(back.object_status, Some(status), "status changed across the round trip");
    }
}

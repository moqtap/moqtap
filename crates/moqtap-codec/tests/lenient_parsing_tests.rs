#![cfg(feature = "draft14")]

use bytes::{Buf, BufMut, BytesMut};
use moqtap_codec::draft14::message::ControlMessage;
use moqtap_codec::error::CodecError;
use moqtap_codec::varint::VarInt;

fn encode_varint_to(buf: &mut BytesMut, val: u64) {
    VarInt::from_u64(val).unwrap().encode(buf);
}

/// draft-14 §6: Unknown message type IDs must produce an error
#[test]
fn decode_unknown_message_type_produces_error() {
    let mut buf = BytesMut::new();
    // Type = 0xFF (unknown)
    encode_varint_to(&mut buf, 0xFF);
    // Length = 4
    encode_varint_to(&mut buf, 4);
    // Payload (4 arbitrary bytes)
    buf.put_slice(&[0x00, 0x01, 0x02, 0x03]);

    let result = ControlMessage::decode(&mut buf);
    assert!(result.is_err());
    match result.unwrap_err() {
        CodecError::UnknownMessageType(id) => assert_eq!(id, 0xFF),
        other => panic!("expected UnknownMessageType, got: {:?}", other),
    }
}

/// draft-14 §6: Truncated payload must produce a decode error
#[test]
fn decode_message_truncated_payload() {
    let mut buf = BytesMut::new();
    // Type = 0x20 (ClientSetup, draft-14 §6.1.1)
    encode_varint_to(&mut buf, 0x20);
    // Length says 100 bytes, but we only provide 2
    encode_varint_to(&mut buf, 100);
    buf.put_slice(&[0x00, 0x01]);

    let result = ControlMessage::decode(&mut buf);
    assert!(result.is_err());
}

/// draft-14 §6: Unknown KVP keys should be preserved (pass through)
#[test]
fn decode_unknown_kvp_key_preserved() {
    use moqtap_codec::kvp::{KeyValuePair, KvpValue};

    let kvp = KeyValuePair {
        key: VarInt::from_u64(0xFE).unwrap(), // unknown even key
        value: KvpValue::Varint(VarInt::from_u64(42).unwrap()),
    };
    let mut buf = BytesMut::new();
    kvp.encode(&mut buf);
    let decoded = KeyValuePair::decode(&mut buf).unwrap();
    assert_eq!(decoded.key, VarInt::from_u64(0xFE).unwrap());
}

/// draft-14 §6.4.1: Invalid FilterType values must return None
#[test]
fn decode_unknown_filter_type_error() {
    use moqtap_codec::types::FilterType;
    assert!(FilterType::from_u8(0xFF).is_none());
    assert!(FilterType::from_u8(0x00).is_none());
    assert!(FilterType::from_u8(0x05).is_none());
}

/// draft-14 §6: Invalid GroupOrder values must return None
#[test]
fn decode_unknown_group_order_error() {
    use moqtap_codec::types::GroupOrder;
    assert!(GroupOrder::from_u8(0xFF).is_none());
    assert!(GroupOrder::from_u8(0x03).is_none());
}

/// draft-14 §6: Invalid ObjectStatus values must return None
#[test]
fn decode_unknown_object_status_error() {
    use moqtap_codec::types::ObjectStatus;
    assert!(ObjectStatus::from_u8(0xFF).is_none());
    assert!(ObjectStatus::from_u8(0x04).is_none());
}

/// draft-14 §6: Invalid ForwardingPreference values must return None
#[test]
fn decode_unknown_forwarding_preference_error() {
    use moqtap_codec::types::ForwardingPreference;
    assert!(ForwardingPreference::from_u8(0xFF).is_none());
    assert!(ForwardingPreference::from_u8(0x02).is_none());
}

/// draft-14 §6.1.1: Zero-length ClientSetup payload is invalid (missing fields)
#[test]
fn decode_message_length_zero() {
    let mut buf = BytesMut::new();
    // Type = 0x20 (ClientSetup, draft-14 §6.1.1), length = 0
    encode_varint_to(&mut buf, 0x20);
    encode_varint_to(&mut buf, 0);

    let result = ControlMessage::decode(&mut buf);
    assert!(result.is_err());
}

/// draft-14 §6: Decoding from empty buffer must produce an error
#[test]
fn decode_empty_buffer() {
    let mut buf = BytesMut::new();
    let result = ControlMessage::decode(&mut buf);
    assert!(result.is_err());
}

/// draft-14 §6.2: Decoding a valid GoAway (0x10) message leaves trailing bytes in the buffer.
///
/// Draft-14 framing is `type_id(vi) + payload_length(16) + payload`.
#[test]
fn decode_message_with_trailing_bytes() {
    let mut buf = BytesMut::new();
    // Type = 0x10 (GoAway, draft-14 §6.2)
    encode_varint_to(&mut buf, 0x10);
    // Payload: URI length = 0 (varint) — total 1 byte
    buf.put_u16(1);
    buf.put_u8(0x00);
    // Trailing bytes
    buf.put_slice(&[0xDE, 0xAD]);

    ControlMessage::decode(&mut buf).expect("GoAway with empty URI must decode");
    assert_eq!(buf.remaining(), 2, "trailing bytes must remain in the buffer");
    assert_eq!(&buf[..], &[0xDE, 0xAD]);
}

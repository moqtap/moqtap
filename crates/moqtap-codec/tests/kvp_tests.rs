use bytes::{BufMut, BytesMut};
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::varint::VarInt;

fn roundtrip_kvp(kvp: &KeyValuePair) {
    let mut buf = BytesMut::new();
    kvp.encode(&mut buf);
    let decoded = KeyValuePair::decode(&mut buf).unwrap();
    assert_eq!(*kvp, decoded);
}

fn roundtrip_kvp_list(list: &[KeyValuePair]) {
    let mut buf = BytesMut::new();
    KeyValuePair::encode_list(list, &mut buf);
    let decoded = KeyValuePair::decode_list(&mut buf).unwrap();
    assert_eq!(list, &decoded[..]);
}

/// draft-14 §6.3: even key (0x02) encodes value as a single varint with no length field.
#[test]
fn kvp_even_key_varint_value_roundtrip() {
    let kvp = KeyValuePair {
        key: VarInt::from_u64(0x02).unwrap(),
        value: KvpValue::Varint(VarInt::from_u64(42).unwrap()),
    };
    roundtrip_kvp(&kvp);
}

/// draft-14 §6.3: even key (0x04) with zero varint value.
#[test]
fn kvp_even_key_zero_value() {
    let kvp = KeyValuePair {
        key: VarInt::from_u64(0x04).unwrap(),
        value: KvpValue::Varint(VarInt::from_u64(0).unwrap()),
    };
    roundtrip_kvp(&kvp);
}

/// draft-14 §6.3: even key (0x02) with a large varint value.
#[test]
fn kvp_even_key_large_varint_value() {
    let kvp = KeyValuePair {
        key: VarInt::from_u64(0x02).unwrap(),
        value: KvpValue::Varint(VarInt::from_u64(1_000_000).unwrap()),
    };
    roundtrip_kvp(&kvp);
}

/// draft-14 §6.3: odd key (0x01) encodes value as length-prefixed bytes.
#[test]
fn kvp_odd_key_bytes_value_roundtrip() {
    let kvp = KeyValuePair {
        key: VarInt::from_u64(0x01).unwrap(),
        value: KvpValue::Bytes(b"hello".to_vec()),
    };
    roundtrip_kvp(&kvp);
}

/// draft-14 §6.3: odd key (0x03) with empty byte value (zero-length).
#[test]
fn kvp_odd_key_empty_bytes() {
    let kvp = KeyValuePair { key: VarInt::from_u64(0x03).unwrap(), value: KvpValue::Bytes(vec![]) };
    roundtrip_kvp(&kvp);
}

/// draft-14 §6.3: odd key with max value length of 2^16-1 = 65535 bytes.
#[test]
fn kvp_odd_key_max_length_bytes() {
    let kvp = KeyValuePair {
        key: VarInt::from_u64(0x05).unwrap(),
        value: KvpValue::Bytes(vec![0xAB; 65535]),
    };
    roundtrip_kvp(&kvp);
}

/// draft-14 §6.3: value length exceeding 2^16-1 = 65535 bytes is a PROTOCOL_VIOLATION.
#[test]
fn kvp_odd_key_exceeds_max_length() {
    let kvp = KeyValuePair {
        key: VarInt::from_u64(0x01).unwrap(),
        value: KvpValue::Bytes(vec![0; 65536]),
    };
    // Encoding a value that exceeds the max length should fail.
    // The implementation may panic (todo!) or return an error.
    // We just verify it doesn't silently succeed by checking the encode path.
    let mut buf = BytesMut::new();
    // This should either panic or produce an error when decoded.
    // Since encode takes &mut impl BufMut with no Result, we test that
    // a decode of such oversized data would fail.
    kvp.encode(&mut buf);
    let result = KeyValuePair::decode(&mut buf);
    // If we get here, the encode didn't panic. The decode should reject it.
    assert!(
        result.is_err() || {
            // If decode succeeds, verify the value length is within limits
            let decoded = result.unwrap();
            match &decoded.value {
                KvpValue::Bytes(b) => b.len() <= 65535,
                _ => true,
            }
        }
    );
}

/// draft-14 §6.3: empty list of key-value pairs (count = 0).
#[test]
fn kvp_list_empty() {
    roundtrip_kvp_list(&[]);
}

/// draft-14 §6.3: list with a single key-value pair.
#[test]
fn kvp_list_single_element() {
    let list = vec![KeyValuePair {
        key: VarInt::from_u64(0x02).unwrap(),
        value: KvpValue::Varint(VarInt::from_u64(7).unwrap()),
    }];
    roundtrip_kvp_list(&list);
}

/// draft-14 §6.3: list with multiple even-keyed key-value pairs.
#[test]
fn kvp_list_multiple_elements() {
    let list = vec![
        KeyValuePair {
            key: VarInt::from_u64(0x02).unwrap(),
            value: KvpValue::Varint(VarInt::from_u64(1).unwrap()),
        },
        KeyValuePair {
            key: VarInt::from_u64(0x04).unwrap(),
            value: KvpValue::Varint(VarInt::from_u64(2).unwrap()),
        },
        KeyValuePair {
            key: VarInt::from_u64(0x06).unwrap(),
            value: KvpValue::Varint(VarInt::from_u64(3).unwrap()),
        },
    ];
    roundtrip_kvp_list(&list);
}

/// draft-14 §6.3: list mixing odd keys (bytes) and even keys (varint).
#[test]
fn kvp_list_mixed_even_odd_keys() {
    let list = vec![
        KeyValuePair {
            key: VarInt::from_u64(0x01).unwrap(),
            value: KvpValue::Bytes(b"value1".to_vec()),
        },
        KeyValuePair {
            key: VarInt::from_u64(0x02).unwrap(),
            value: KvpValue::Varint(VarInt::from_u64(99).unwrap()),
        },
        KeyValuePair {
            key: VarInt::from_u64(0x03).unwrap(),
            value: KvpValue::Bytes(b"value3".to_vec()),
        },
    ];
    roundtrip_kvp_list(&list);
}

/// draft-14 §6.3.1: PATH (0x01) is an odd key with bytes value (CLIENT_SETUP only).
#[test]
fn kvp_setup_param_path() {
    let kvp = KeyValuePair {
        key: VarInt::from_u64(0x01).unwrap(),
        value: KvpValue::Bytes(b"/moq".to_vec()),
    };
    roundtrip_kvp(&kvp);
}

/// draft-14 §6.3.1: MAX_REQUEST_ID (0x02) is an even key with varint value.
#[test]
fn kvp_setup_param_max_request_id() {
    let kvp = KeyValuePair {
        key: VarInt::from_u64(0x02).unwrap(),
        value: KvpValue::Varint(VarInt::from_u64(100).unwrap()),
    };
    roundtrip_kvp(&kvp);
}

/// draft-14 §6.3.1: AUTHORIZATION_TOKEN (0x03) is an odd key with bytes value.
#[test]
fn kvp_setup_param_authorization_token() {
    let kvp = KeyValuePair {
        key: VarInt::from_u64(0x03).unwrap(),
        value: KvpValue::Bytes(b"token123".to_vec()),
    };
    roundtrip_kvp(&kvp);
}

/// draft-14 §6.3.1: MAX_AUTH_TOKEN_CACHE_SIZE (0x04) is an even key with varint value.
#[test]
fn kvp_setup_param_max_auth_token_cache_size() {
    let kvp = KeyValuePair {
        key: VarInt::from_u64(0x04).unwrap(),
        value: KvpValue::Varint(VarInt::from_u64(10).unwrap()),
    };
    roundtrip_kvp(&kvp);
}

/// draft-14 §6.3.1: AUTHORITY (0x05) is an odd key with bytes value (CLIENT_SETUP).
#[test]
fn kvp_setup_param_authority() {
    let kvp = KeyValuePair {
        key: VarInt::from_u64(0x05).unwrap(),
        value: KvpValue::Bytes(b"relay.example.com".to_vec()),
    };
    roundtrip_kvp(&kvp);
}

/// draft-14 §6.3: decoding from an empty buffer should fail (no key byte).
#[test]
fn kvp_decode_truncated_key() {
    let buf = BytesMut::new();
    let mut reader = &buf[..];
    assert!(KeyValuePair::decode(&mut reader).is_err());
}

/// draft-14 §6.3: odd key requires a length field; missing length should fail.
#[test]
fn kvp_decode_truncated_value_length() {
    // Odd key (0x01) requires a length-prefixed value.
    // Provide only the key byte, no length or value bytes.
    let mut buf = BytesMut::new();
    buf.put_u8(0x01); // odd key
    let mut reader = &buf[..];
    assert!(KeyValuePair::decode(&mut reader).is_err());
}

/// draft-14 §6.3: odd key with length indicating 10 bytes but only 3 bytes available.
#[test]
fn kvp_decode_truncated_value_bytes() {
    // Odd key, length says 10, but only 3 bytes available.
    let mut buf = BytesMut::new();
    buf.put_u8(0x01); // odd key
    buf.put_u8(10); // length = 10
    buf.put_slice(&[0xAA, 0xBB, 0xCC]); // only 3 bytes
    let mut reader = &buf[..];
    assert!(KeyValuePair::decode(&mut reader).is_err());
}

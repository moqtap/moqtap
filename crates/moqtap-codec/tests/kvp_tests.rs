use bytes::{BufMut, BytesMut};
use moqtap_codec::kvp::{KeyValuePair, KvpError, KvpValue};
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

/// draft-14 Section 1.4.2: even key (0x02) encodes value as a single varint with no length field.
#[test]
fn kvp_even_key_varint_value_roundtrip() {
    let kvp = KeyValuePair {
        key: VarInt::from_u64(0x02).unwrap(),
        value: KvpValue::Varint(VarInt::from_u64(42).unwrap()),
    };
    roundtrip_kvp(&kvp);
}

/// draft-14 Section 1.4.2: even key (0x04) with zero varint value.
#[test]
fn kvp_even_key_zero_value() {
    let kvp = KeyValuePair {
        key: VarInt::from_u64(0x04).unwrap(),
        value: KvpValue::Varint(VarInt::from_u64(0).unwrap()),
    };
    roundtrip_kvp(&kvp);
}

/// draft-14 Section 1.4.2: even key (0x02) with a large varint value.
#[test]
fn kvp_even_key_large_varint_value() {
    let kvp = KeyValuePair {
        key: VarInt::from_u64(0x02).unwrap(),
        value: KvpValue::Varint(VarInt::from_u64(1_000_000).unwrap()),
    };
    roundtrip_kvp(&kvp);
}

/// draft-14 Section 1.4.2: odd key (0x01) encodes value as length-prefixed bytes.
#[test]
fn kvp_odd_key_bytes_value_roundtrip() {
    let kvp = KeyValuePair {
        key: VarInt::from_u64(0x01).unwrap(),
        value: KvpValue::Bytes(b"hello".to_vec()),
    };
    roundtrip_kvp(&kvp);
}

/// draft-14 Section 1.4.2: odd key (0x03) with empty byte value (zero-length).
#[test]
fn kvp_odd_key_empty_bytes() {
    let kvp = KeyValuePair { key: VarInt::from_u64(0x03).unwrap(), value: KvpValue::Bytes(vec![]) };
    roundtrip_kvp(&kvp);
}

/// draft-14 Section 1.4.2: odd key with max value length of 2^16-1 = 65535 bytes.
#[test]
fn kvp_odd_key_max_length_bytes() {
    let kvp = KeyValuePair {
        key: VarInt::from_u64(0x05).unwrap(),
        value: KvpValue::Bytes(vec![0xAB; 65535]),
    };
    roundtrip_kvp(&kvp);
}

/// Drafts 11 and later: a value longer than 2^16-1 bytes is a protocol
/// violation, and `decode` refuses it.
///
/// `encode` is infallible and writes the oversized value verbatim, which is
/// what [`kvp_encode_checked_refuses_what_decode_refuses`] is about.
#[test]
fn kvp_odd_key_exceeds_max_length() {
    let kvp = KeyValuePair {
        key: VarInt::from_u64(0x01).unwrap(),
        value: KvpValue::Bytes(vec![0; 65536]),
    };
    let mut buf = BytesMut::new();
    kvp.encode(&mut buf);
    assert!(
        KeyValuePair::decode(&mut buf).is_err(),
        "value length > 65535 must be rejected on decode"
    );
}

/// draft-14 Section 1.4.2: empty list of key-value pairs (count = 0).
#[test]
fn kvp_list_empty() {
    roundtrip_kvp_list(&[]);
}

/// draft-14 Section 1.4.2: list with a single key-value pair.
#[test]
fn kvp_list_single_element() {
    let list = vec![KeyValuePair {
        key: VarInt::from_u64(0x02).unwrap(),
        value: KvpValue::Varint(VarInt::from_u64(7).unwrap()),
    }];
    roundtrip_kvp_list(&list);
}

/// draft-14 Section 1.4.2: list with multiple even-keyed key-value pairs.
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

/// draft-14 Section 1.4.2: list mixing odd keys (bytes) and even keys (varint).
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

/// draft-14 Section 9.3.2.2: PATH (0x01) is an odd key with bytes value (CLIENT_SETUP only).
#[test]
fn kvp_setup_param_path() {
    let kvp = KeyValuePair {
        key: VarInt::from_u64(0x01).unwrap(),
        value: KvpValue::Bytes(b"/moq".to_vec()),
    };
    roundtrip_kvp(&kvp);
}

/// draft-14 Section 9.3.2.3: MAX_REQUEST_ID (0x02) is an even key with varint value.
#[test]
fn kvp_setup_param_max_request_id() {
    let kvp = KeyValuePair {
        key: VarInt::from_u64(0x02).unwrap(),
        value: KvpValue::Varint(VarInt::from_u64(100).unwrap()),
    };
    roundtrip_kvp(&kvp);
}

/// draft-14 Section 9.3.2.5: AUTHORIZATION TOKEN (0x03) is an odd key with bytes value.
#[test]
fn kvp_setup_param_authorization_token() {
    let kvp = KeyValuePair {
        key: VarInt::from_u64(0x03).unwrap(),
        value: KvpValue::Bytes(b"token123".to_vec()),
    };
    roundtrip_kvp(&kvp);
}

/// draft-14 Section 9.3.2.4: MAX_AUTH_TOKEN_CACHE_SIZE (0x04) is an even key with varint value.
#[test]
fn kvp_setup_param_max_auth_token_cache_size() {
    let kvp = KeyValuePair {
        key: VarInt::from_u64(0x04).unwrap(),
        value: KvpValue::Varint(VarInt::from_u64(10).unwrap()),
    };
    roundtrip_kvp(&kvp);
}

/// draft-14 Section 9.3.2.1: AUTHORITY (0x05) is an odd key with bytes value (CLIENT_SETUP).
#[test]
fn kvp_setup_param_authority() {
    let kvp = KeyValuePair {
        key: VarInt::from_u64(0x05).unwrap(),
        value: KvpValue::Bytes(b"relay.example.com".to_vec()),
    };
    roundtrip_kvp(&kvp);
}

/// draft-14 Section 1.4.2: decoding from an empty buffer should fail (no key byte).
#[test]
fn kvp_decode_truncated_key() {
    let buf = BytesMut::new();
    let mut reader = &buf[..];
    assert!(KeyValuePair::decode(&mut reader).is_err());
}

/// draft-14 Section 1.4.2: odd key requires a length field; missing length should fail.
#[test]
fn kvp_decode_truncated_value_length() {
    // Odd key (0x01) requires a length-prefixed value.
    // Provide only the key byte, no length or value bytes.
    let mut buf = BytesMut::new();
    buf.put_u8(0x01); // odd key
    let mut reader = &buf[..];
    assert!(KeyValuePair::decode(&mut reader).is_err());
}

/// draft-14 Section 1.4.2: odd key with length indicating 10 bytes but only 3 bytes available.
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

/// Drafts 07 through 10 apply no maximum to a Parameter value, because none of
/// them states one.
///
/// Those four drafts carry `Parameter { Parameter Type (i), Parameter Length
/// (i), Parameter Value (..) }` and say nothing about how long a value may be.
/// The 2^16-1 maximum arrives with the Key-Value-Pair of draft-11 — "The
/// maximum length of a value is 2^16-1 bytes. If an endpoint receives a length
/// larger than the maximum, it MUST close the session with a Protocol
/// Violation" — and reading it back into the earlier drafts refuses parameters
/// they permit.
///
/// The read stays bounded without the cap: a declared length longer than the
/// bytes actually present is refused before anything is allocated, so what was
/// removed was a rule, not a defence.
///
/// # Observed with the fix reverted
///
/// Restoring the `MAX_KVP_VALUE_LEN` check in `decode_d07`:
///
/// ```text
/// drafts 07-10 state no value cap, but a 65536-byte parameter was refused: Err(ValueTooLong(65536))
/// ```
#[test]
fn the_pre_draft_11_parameter_has_no_length_cap() {
    let oversized = KeyValuePair {
        key: VarInt::from_u64(0x01).unwrap(),
        value: KvpValue::Bytes(vec![0xCD; 65536]),
    };
    let mut buf = BytesMut::new();
    oversized.encode_d07(&mut buf);

    let got = KeyValuePair::decode_d07(&mut buf);
    let decoded = match got {
        Ok(pair) => pair,
        other => panic!(
            "drafts 07-10 state no value cap, but a 65536-byte parameter was refused: {other:?}"
        ),
    };
    assert_eq!(decoded, oversized, "the parameter did not survive its own round trip");

    // A length longer than the bytes present is still refused, so dropping the
    // cap did not drop the bound on what a peer can make this allocate.
    let mut truncated = BytesMut::new();
    VarInt::from_u64(0x01).unwrap().encode(&mut truncated);
    VarInt::from_usize(65536).encode(&mut truncated);
    truncated.extend_from_slice(&[0xCD; 16]);
    let got = KeyValuePair::decode_d07(&mut truncated);
    assert!(
        matches!(got, Err(moqtap_codec::kvp::KvpError::UnexpectedEnd)),
        "a length beyond the buffer must still be refused, got {got:?}"
    );
}

/// The writer can refuse the value the reader is required to close the session
/// over.
///
/// The maximum is written as a receiver's rule, which is why `decode` is where
/// it was applied; but a value past it is not a value a sender can send, so a
/// writer that takes it and says nothing leaves its caller to find out from the
/// peer. `encode_list_checked` answers instead, and writes nothing.
///
/// **What the refusal adds, stated so this is not read as a closed hole.**
/// Inside a control message it is never the only refusal: every draft from 11 on
/// caps a control payload at 65535 bytes as well, and states the two maxima as
/// two sentences at the same number — "The maximum length of a value is 2^16-1
/// bytes", on all nine, beside "the total length of a control message is limited
/// to 2^16-1 bytes", which is drafts 12 and later; draft-11 ends the same
/// sentence "limited to 2^16-1." and leaves the unit to be inferred. So a
/// parameter one byte over the first is already inside a payload one byte over
/// the second. What this adds is which of the two rules the error names, and it
/// is the layer that owns the one the value broke.
///
/// # What breaking the fix does, observed by making the change and running
///
/// Pointing `encode_list_checked` at `encode_list` and dropping the check:
///
/// ```text
/// a list holding one over-long value must be refused, got Ok(())
/// ```
#[test]
fn kvp_encode_list_checked_refuses_what_decode_refuses() {
    let oversized = KeyValuePair {
        key: VarInt::from_u64(0x01).unwrap(),
        value: KvpValue::Bytes(vec![0xAB; 65536]),
    };

    // A list refuses before writing any of it, so a caller is never left with
    // half a list and an error.
    let allowed = KeyValuePair {
        key: VarInt::from_u64(0x00).unwrap(),
        value: KvpValue::Varint(VarInt::from_u64(7).unwrap()),
    };
    let mut list_buf = BytesMut::new();
    let got = KeyValuePair::encode_list_checked(&[allowed.clone(), oversized], &mut list_buf);
    assert!(
        matches!(got, Err(KvpError::ValueTooLong(65536))),
        "a list holding one over-long value must be refused, got {got:?}"
    );
    assert!(list_buf.is_empty(), "and none of it must be written: {} bytes", list_buf.len());

    // The value at the maximum is written, so what the refusal above observes
    // is the length and not the shape of the pair.
    let at_the_limit = KeyValuePair {
        key: VarInt::from_u64(0x01).unwrap(),
        value: KvpValue::Bytes(vec![0xAB; 65535]),
    };
    let mut ok_buf = BytesMut::new();
    KeyValuePair::encode_list_checked(&[allowed, at_the_limit], &mut ok_buf)
        .expect("65535 bytes is the maximum, not past it");
    assert!(!ok_buf.is_empty());
}

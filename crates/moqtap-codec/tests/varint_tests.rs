use bytes::{BufMut, BytesMut};
use moqtap_codec::varint::{VarInt, MAX_VARINT};

fn encode_varint(v: VarInt) -> BytesMut {
    let mut buf = BytesMut::new();
    v.encode(&mut buf);
    buf
}

fn roundtrip(val: u64) {
    let v = VarInt::from_u64(val).unwrap();
    let mut buf = encode_varint(v);
    let decoded = VarInt::decode(&mut buf).unwrap();
    assert_eq!(v, decoded);
    assert_eq!(val, decoded.into_inner());
}

/// RFC 9000 §16: varint encoding of zero (smallest possible value).
#[test]
fn varint_roundtrip_zero() {
    roundtrip(0);
}

/// RFC 9000 §16: varint encoding of 1.
#[test]
fn varint_roundtrip_one() {
    roundtrip(1);
}

/// RFC 9000 §16: 1-byte varint max value is 63 (6 usable bits, prefix 00).
#[test]
fn varint_roundtrip_max_1byte() {
    roundtrip(63);
}

/// RFC 9000 §16: 2-byte varint min value is 64 (first value requiring prefix 01).
#[test]
fn varint_roundtrip_min_2byte() {
    roundtrip(64);
}

/// RFC 9000 §16: 2-byte varint max value is 16383 (14 usable bits, prefix 01).
#[test]
fn varint_roundtrip_max_2byte() {
    roundtrip(16383);
}

/// RFC 9000 §16: 4-byte varint min value is 16384 (first value requiring prefix 10).
#[test]
fn varint_roundtrip_min_4byte() {
    roundtrip(16384);
}

/// RFC 9000 §16: 4-byte varint max value is 1073741823 (30 usable bits, prefix 10).
#[test]
fn varint_roundtrip_max_4byte() {
    roundtrip(1073741823);
}

/// RFC 9000 §16: 8-byte varint min value is 1073741824 (first value requiring prefix 11).
#[test]
fn varint_roundtrip_min_8byte() {
    roundtrip(1073741824);
}

/// RFC 9000 §16: varint max value is 2^62 - 1 = 4611686018427387903 (62 usable bits, prefix 11).
#[test]
fn varint_roundtrip_max() {
    roundtrip(MAX_VARINT);
}

/// RFC 9000 §16: 1-byte encoding (prefix 00) for values 0 and 63.
#[test]
fn varint_encoded_len_1byte() {
    let v0 = VarInt::from_u64(0).unwrap();
    assert_eq!(v0.encoded_len(), 1);
    let v63 = VarInt::from_u64(63).unwrap();
    assert_eq!(v63.encoded_len(), 1);
}

/// RFC 9000 §16: 2-byte encoding (prefix 01) starts at value 64.
#[test]
fn varint_encoded_len_2byte() {
    let v = VarInt::from_u64(64).unwrap();
    assert_eq!(v.encoded_len(), 2);
}

/// RFC 9000 §16: 4-byte encoding (prefix 10) starts at value 16384.
#[test]
fn varint_encoded_len_4byte() {
    let v = VarInt::from_u64(16384).unwrap();
    assert_eq!(v.encoded_len(), 4);
}

/// RFC 9000 §16: 8-byte encoding (prefix 11) starts at value 1073741824.
#[test]
fn varint_encoded_len_8byte() {
    let v = VarInt::from_u64(1073741824).unwrap();
    assert_eq!(v.encoded_len(), 8);
}

/// RFC 9000 §16: 1-byte varint has 00 prefix in the two most significant bits.
#[test]
fn varint_1byte_has_00_prefix() {
    let v = VarInt::from_u64(0).unwrap();
    let buf = encode_varint(v);
    assert_eq!(buf[0] & 0xC0, 0x00);
}

/// RFC 9000 §16: 2-byte varint has 01 prefix in the two most significant bits.
#[test]
fn varint_2byte_has_01_prefix() {
    let v = VarInt::from_u64(64).unwrap();
    let buf = encode_varint(v);
    assert_eq!(buf[0] & 0xC0, 0x40);
}

/// RFC 9000 §16: 4-byte varint has 10 prefix in the two most significant bits.
#[test]
fn varint_4byte_has_10_prefix() {
    let v = VarInt::from_u64(16384).unwrap();
    let buf = encode_varint(v);
    assert_eq!(buf[0] & 0xC0, 0x80);
}

/// RFC 9000 §16: 8-byte varint has 11 prefix in the two most significant bits.
#[test]
fn varint_8byte_has_11_prefix() {
    let v = VarInt::from_u64(1073741824).unwrap();
    let buf = encode_varint(v);
    assert_eq!(buf[0] & 0xC0, 0xC0);
}

/// RFC 9000 §16: u64::MAX exceeds the varint range (max is 2^62 - 1).
#[test]
fn varint_overflow_u64_max() {
    assert!(VarInt::from_u64(u64::MAX).is_err());
}

/// RFC 9000 §16: 2^62 is one past the maximum varint value (2^62 - 1).
#[test]
fn varint_overflow_2pow62() {
    assert!(VarInt::from_u64(MAX_VARINT + 1).is_err());
}

/// RFC 9000 §16: decoding from an empty buffer should fail with UnexpectedEnd.
#[test]
fn varint_decode_empty_buffer() {
    let mut buf = BytesMut::new();
    assert!(VarInt::decode(&mut buf).is_err());
}

/// RFC 9000 §16: truncated 2-byte varint (prefix 01 but only 1 byte provided).
#[test]
fn varint_decode_truncated_2byte() {
    // First byte with 01 prefix indicates 2-byte encoding, but only 1 byte provided
    let mut buf = BytesMut::new();
    buf.put_u8(0x40); // 01 prefix, would need 2 bytes total
    let mut reader = &buf[..];
    assert!(VarInt::decode(&mut reader).is_err());
}

/// RFC 9000 §16: truncated 4-byte varint (prefix 10 but only 2 bytes provided).
#[test]
fn varint_decode_truncated_4byte() {
    // First byte with 10 prefix indicates 4-byte encoding, but only 2 bytes provided
    let mut buf = BytesMut::new();
    buf.put_u8(0x80); // 10 prefix
    buf.put_u8(0x00);
    let mut reader = &buf[..];
    assert!(VarInt::decode(&mut reader).is_err());
}

/// RFC 9000 §16: truncated 8-byte varint (prefix 11 but only 4 bytes provided).
#[test]
fn varint_decode_truncated_8byte() {
    // First byte with 11 prefix indicates 8-byte encoding, but only 4 bytes provided
    let mut buf = BytesMut::new();
    buf.put_u8(0xC0); // 11 prefix
    buf.put_u8(0x00);
    buf.put_u8(0x00);
    buf.put_u8(0x00);
    let mut reader = &buf[..];
    assert!(VarInt::decode(&mut reader).is_err());
}

/// RFC 9000 §16: VarInt can be constructed from u32 (always within range).
#[test]
fn varint_from_u32() {
    let v = VarInt::from(42u32);
    assert_eq!(v.into_inner(), 42);
}

/// RFC 9000 §16: TryFrom<u64> succeeds for values within the varint range.
#[test]
fn varint_try_from_u64_valid() {
    assert!(VarInt::try_from(100u64).is_ok());
    let v = VarInt::try_from(100u64).unwrap();
    assert_eq!(v.into_inner(), 100);
}

/// RFC 9000 §16: TryFrom<u64> fails for u64::MAX (exceeds 2^62 - 1).
#[test]
fn varint_try_from_u64_overflow() {
    assert!(VarInt::try_from(u64::MAX).is_err());
}

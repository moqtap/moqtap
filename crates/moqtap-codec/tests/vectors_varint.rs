mod test_vectors;

use moqtap_codec::varint::{Moqt17, Moqt18, MoqtProfile, VarInt, VarIntError};

/// Drafts 07-16 use the RFC 9000 variable-length integer; draft-17 replaced it
/// with MoQT's own (Section 1.4.1). Each draft's vectors are run through the
/// encoding that draft actually uses.
type Decode = fn(&mut &[u8]) -> Result<VarInt, VarIntError>;
type Encode = fn(&VarInt, &mut Vec<u8>);

fn run_varint_vectors(relative_path: &str) {
    run_vectors(relative_path, |c| VarInt::decode(c), |v, b| v.encode(b));
}

fn run_moqt_varint_vectors<P: MoqtProfile>(relative_path: &str) {
    run_vectors(relative_path, |c| VarInt::decode_moqt::<P>(c), |v, b| v.encode_moqt::<P>(b));
}

fn run_vectors(relative_path: &str, decode: Decode, encode: Encode) {
    let path = test_vectors::vectors_dir().join(relative_path);
    let file = test_vectors::load_vectors(&path);
    assert_eq!(file.message_type, "varint");

    for vector in &file.vectors {
        let bytes = hex::decode(&vector.hex).unwrap_or_else(|e| {
            panic!("vector {}: invalid hex '{}': {e}", vector.id, vector.hex);
        });

        if let Some(ref decoded) = vector.decoded {
            // Success case: decode and check value
            let mut cursor = &bytes[..];
            let varint = decode(&mut cursor).unwrap_or_else(|e| {
                panic!("vector {}: decode failed: {e}", vector.id);
            });

            let expected_value = decoded["value"]
                .as_str()
                .unwrap_or_else(|| panic!("vector {}: missing decoded.value", vector.id));

            assert_eq!(
                varint.into_inner().to_string(),
                expected_value,
                "vector {}: value mismatch",
                vector.id,
            );

            // If canonical, re-encode and verify hex matches
            if vector.is_canonical() {
                let mut buf = Vec::new();
                encode(&varint, &mut buf);
                let re_encoded_hex = hex::encode(&buf);
                assert_eq!(
                    re_encoded_hex, vector.hex,
                    "vector {}: canonical re-encode mismatch",
                    vector.id,
                );
            }
        } else if vector.error.is_some() {
            // Error case: decode should fail
            let mut cursor = &bytes[..];
            let result = decode(&mut cursor);
            assert!(
                result.is_err(),
                "vector {}: expected error but decode succeeded with {:?}",
                vector.id,
                result.unwrap(),
            );
        } else {
            panic!("vector {}: has neither 'decoded' nor 'error' field", vector.id,);
        }
    }
}

#[test]
fn varint_draft14() {
    run_varint_vectors("transport/draft14/codec/varint.json");
}

#[test]
fn varint_draft07() {
    run_varint_vectors("transport/draft07/codec/varint.json");
}

#[test]
fn varint_draft17() {
    run_moqt_varint_vectors::<Moqt17>("transport/draft17/codec/varint.json");
}

#[test]
fn varint_draft18() {
    run_moqt_varint_vectors::<Moqt18>("transport/draft18/codec/varint.json");
}

#[test]
fn varint_draft19() {
    run_moqt_varint_vectors::<Moqt18>("transport/draft19/codec/varint.json");
}

/// Draft-17 omits the 7-byte length and calls 11111100 an invalid code point,
/// while draft-18 restored it. The same bytes must therefore be rejected on a
/// draft-17 session and accepted on a later one.
#[test]
fn seven_byte_form_splits_draft17_from_draft18() {
    let bytes = hex::decode("fc8998abc66bc0").unwrap();

    let mut cursor = &bytes[..];
    assert_eq!(VarInt::decode_moqt::<Moqt17>(&mut cursor), Err(VarIntError::InvalidCodePoint),);

    let mut cursor = &bytes[..];
    let v = VarInt::decode_moqt::<Moqt18>(&mut cursor).expect("draft-18 defines 7 bytes");
    assert_eq!(v.into_inner(), 151_288_809_941_952);

    // Draft-17 encodes the same value in eight bytes, skipping the gap.
    let mut buf = Vec::new();
    v.encode_moqt::<Moqt17>(&mut buf);
    assert_eq!(hex::encode(&buf), "fe008998abc66bc0");
}

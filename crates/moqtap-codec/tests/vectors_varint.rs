mod test_vectors;

use moqtap_codec::varint::VarInt;

fn run_varint_vectors(relative_path: &str) {
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
            let varint = VarInt::decode(&mut cursor).unwrap_or_else(|e| {
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
                varint.encode(&mut buf);
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
            let result = VarInt::decode(&mut cursor);
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

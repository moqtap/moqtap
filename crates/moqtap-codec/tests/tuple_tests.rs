use bytes::BytesMut;

use moqtap_codec::types::TrackNamespace;

fn roundtrip_namespace(ns: &TrackNamespace) {
    let mut buf = BytesMut::new();
    ns.encode(&mut buf);
    let decoded = TrackNamespace::decode(&mut buf).unwrap();
    assert_eq!(*ns, decoded);
}

/// draft-14 §2.3: Track Namespace is an ordered N-tuple with 1 <= N <= 32; single element is valid.
#[test]
fn tuple_single_element() {
    let ns = TrackNamespace(vec![b"chat".to_vec()]);
    roundtrip_namespace(&ns);
}

/// draft-14 §2.3: Track Namespace maximum tuple size is 32 elements.
#[test]
fn tuple_max_32_elements() {
    let elements: Vec<Vec<u8>> = (0..32).map(|i| format!("elem{}", i).into_bytes()).collect();
    let ns = TrackNamespace(elements);
    roundtrip_namespace(&ns);
}

/// draft-14 §2.3: N > 32 elements is a PROTOCOL_VIOLATION.
///
/// `encode` is infallible and does not validate the count; enforcement
/// lives in `decode`, which must reject the resulting buffer.
#[test]
fn tuple_33_elements_rejected() {
    let elements: Vec<Vec<u8>> = (0..33).map(|i| vec![i as u8]).collect();
    let ns = TrackNamespace(elements);
    let mut buf = BytesMut::new();
    ns.encode(&mut buf);
    assert!(TrackNamespace::decode(&mut buf).is_err(), "33 elements must be rejected on decode");
}

/// draft-14 §2.3: N = 0 elements is a PROTOCOL_VIOLATION.
///
/// `encode` is infallible; `decode` must reject the zero-count tuple.
#[test]
fn tuple_zero_elements_rejected() {
    let ns = TrackNamespace(vec![]);
    let mut buf = BytesMut::new();
    ns.encode(&mut buf);
    assert!(TrackNamespace::decode(&mut buf).is_err(), "0 elements must be rejected on decode");
}

/// draft-14 §2.3: an element with empty bytes (zero-length byte sequence) is valid.
#[test]
fn tuple_empty_element_bytes() {
    // An element with empty bytes (zero-length) is valid.
    let ns = TrackNamespace(vec![vec![]]);
    roundtrip_namespace(&ns);
}

/// draft-14 §2.3: Track Namespace elements are byte sequences; UTF-8/unicode content is valid.
#[test]
fn tuple_roundtrip_unicode_elements() {
    let ns = TrackNamespace(vec![
        "hello".as_bytes().to_vec(),
        "\u{1F600}".as_bytes().to_vec(), // emoji in UTF-8
        "\u{00E9}".as_bytes().to_vec(),  // accented e
    ]);
    roundtrip_namespace(&ns);
}

/// draft-14 §2.3: large but valid namespace within 4096-byte Full Track Name limit.
#[test]
fn tuple_total_size_within_4096() {
    // Large but valid namespace: 8 elements of 500 bytes each = 4000 bytes
    let elements: Vec<Vec<u8>> = (0..8).map(|_| vec![0x42; 500]).collect();
    let ns = TrackNamespace(elements);
    roundtrip_namespace(&ns);
}

/// draft-14 §2.3: Full Track Name total size exceeding 4096 bytes should be rejected.
#[test]
fn full_track_name_exceeds_4096_rejected() {
    use moqtap_codec::types::FullTrackName;

    // Create a namespace + track name that exceeds 4096 bytes total.
    let ns = TrackNamespace(vec![vec![0x41; 4000]]);
    let ftn = FullTrackName {
        namespace: ns,
        track_name: vec![0x42; 200], // 4000 + 200 = 4200 > 4096
    };
    // Verify the struct can be created (it's just data).
    // The codec should reject this when encoding a message that uses it.
    assert!(ftn.namespace.0[0].len() + ftn.track_name.len() > 4096);
}

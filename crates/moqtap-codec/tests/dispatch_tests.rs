//! Tests for runtime draft dispatch (version.rs + dispatch.rs).

use moqtap_codec::dispatch::*;
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

// ============================================================
// DraftVersion
// ============================================================

#[test]
fn draft_version_varint_draft07() {
    let v = DraftVersion::Draft07.version_varint();
    assert_eq!(v.into_inner(), 0xff000000 + 7);
}

#[test]
fn draft_version_varint_draft14() {
    let v = DraftVersion::Draft14.version_varint();
    assert_eq!(v.into_inner(), 0xff000000 + 14);
}

#[test]
fn draft_version_quic_alpn() {
    assert_eq!(DraftVersion::Draft07.quic_alpn(), b"moq-00");
    assert_eq!(DraftVersion::Draft14.quic_alpn(), b"moq-00");
}

#[test]
fn draft_version_copy_eq_hash() {
    use std::collections::HashSet;
    let a = DraftVersion::Draft07;
    let b = a;
    assert_eq!(a, b);
    assert_ne!(DraftVersion::Draft07, DraftVersion::Draft14);

    let mut set = HashSet::new();
    set.insert(DraftVersion::Draft07);
    set.insert(DraftVersion::Draft14);
    assert_eq!(set.len(), 2);
}

// ============================================================
// AnyControlMessage — Draft-14
// ============================================================

#[test]
fn any_control_message_draft14_round_trip() {
    use moqtap_codec::draft14::message::{ControlMessage, GoAway};

    let msg = ControlMessage::GoAway(GoAway { new_session_uri: b"https://new.example".to_vec() });

    let any = AnyControlMessage::Draft14(msg);
    assert_eq!(any.draft(), DraftVersion::Draft14);

    let mut buf = Vec::new();
    any.encode(&mut buf).unwrap();

    let mut cursor = &buf[..];
    let decoded = AnyControlMessage::decode(DraftVersion::Draft14, &mut cursor).unwrap();

    match decoded {
        AnyControlMessage::Draft14(ControlMessage::GoAway(ga)) => {
            assert_eq!(ga.new_session_uri, b"https://new.example");
        }
        _ => panic!("expected Draft14 GoAway"),
    }
}

#[test]
fn any_control_message_draft14_max_request_id() {
    use moqtap_codec::draft14::message::{ControlMessage, MaxRequestId};

    let msg =
        ControlMessage::MaxRequestId(MaxRequestId { request_id: VarInt::from_u64(42).unwrap() });

    let any = AnyControlMessage::Draft14(msg);
    let mut buf = Vec::new();
    any.encode(&mut buf).unwrap();

    let mut cursor = &buf[..];
    let decoded = AnyControlMessage::decode(DraftVersion::Draft14, &mut cursor).unwrap();

    match decoded {
        AnyControlMessage::Draft14(ControlMessage::MaxRequestId(m)) => {
            assert_eq!(m.request_id.into_inner(), 42);
        }
        _ => panic!("expected Draft14 MaxRequestId"),
    }
}

// ============================================================
// AnyControlMessage — Draft-07
// ============================================================

#[test]
fn any_control_message_draft07_round_trip() {
    use moqtap_codec::draft07::message::{ControlMessage, GoAway};

    let msg = ControlMessage::GoAway(GoAway { new_session_uri: b"https://old.example".to_vec() });

    let any = AnyControlMessage::Draft07(msg);
    assert_eq!(any.draft(), DraftVersion::Draft07);

    let mut buf = Vec::new();
    any.encode(&mut buf).unwrap();

    let mut cursor = &buf[..];
    let decoded = AnyControlMessage::decode(DraftVersion::Draft07, &mut cursor).unwrap();

    match decoded {
        AnyControlMessage::Draft07(ControlMessage::GoAway(ga)) => {
            assert_eq!(ga.new_session_uri, b"https://old.example");
        }
        _ => panic!("expected Draft07 GoAway"),
    }
}

// ============================================================
// AnySubgroupHeader
// ============================================================

#[test]
fn any_subgroup_header_draft14_round_trip() {
    use moqtap_codec::draft14::data_stream::SubgroupHeader;

    let header = SubgroupHeader {
        track_alias: VarInt::from_u64(1).unwrap(),
        group: VarInt::from_u64(0).unwrap(),
        subgroup: VarInt::from_u64(0).unwrap(),
        publisher_priority: 128,
    };

    let any = AnySubgroupHeader::Draft14(header);
    let mut buf = Vec::new();
    any.encode(&mut buf);

    let mut cursor = &buf[..];
    let decoded = AnySubgroupHeader::decode(DraftVersion::Draft14, &mut cursor).unwrap();

    match decoded {
        AnySubgroupHeader::Draft14(h) => {
            assert_eq!(h.track_alias.into_inner(), 1);
            assert_eq!(h.publisher_priority, 128);
        }
        _ => panic!("expected Draft14"),
    }
}

#[test]
fn any_subgroup_header_draft07_round_trip() {
    use moqtap_codec::draft07::data_stream::SubgroupHeader;

    let header = SubgroupHeader {
        track_alias: VarInt::from_u64(5).unwrap(),
        group_id: VarInt::from_u64(10).unwrap(),
        subgroup_id: VarInt::from_u64(2).unwrap(),
        publisher_priority: 64,
    };

    let any = AnySubgroupHeader::Draft07(header);
    let mut buf = Vec::new();
    any.encode(&mut buf);

    let mut cursor = &buf[..];
    let decoded = AnySubgroupHeader::decode(DraftVersion::Draft07, &mut cursor).unwrap();

    match decoded {
        AnySubgroupHeader::Draft07(h) => {
            assert_eq!(h.track_alias.into_inner(), 5);
            assert_eq!(h.group_id.into_inner(), 10);
        }
        _ => panic!("expected Draft07"),
    }
}

// ============================================================
// AnyDatagramHeader
// ============================================================

#[test]
fn any_datagram_header_draft14_round_trip() {
    use moqtap_codec::draft14::data_stream::DatagramHeader;

    let header = DatagramHeader {
        track_alias: VarInt::from_u64(3).unwrap(),
        group: VarInt::from_u64(1).unwrap(),
        object: VarInt::from_u64(0).unwrap(),
        publisher_priority: 200,
    };

    let any = AnyDatagramHeader::Draft14(header);
    let mut buf = Vec::new();
    any.encode(&mut buf);

    let mut cursor = &buf[..];
    let decoded = AnyDatagramHeader::decode(DraftVersion::Draft14, &mut cursor).unwrap();

    match decoded {
        AnyDatagramHeader::Draft14(h) => {
            assert_eq!(h.track_alias.into_inner(), 3);
            assert_eq!(h.publisher_priority, 200);
        }
        _ => panic!("expected Draft14"),
    }
}

// ============================================================
// AnyFetchHeader
// ============================================================

#[test]
fn any_fetch_header_draft14_round_trip() {
    use moqtap_codec::draft14::data_stream::FetchHeader;

    let header = FetchHeader {
        track_alias: VarInt::from_u64(7).unwrap(),
        group: VarInt::from_u64(3).unwrap(),
        subgroup: VarInt::from_u64(1).unwrap(),
        publisher_priority: 50,
    };

    let any = AnyFetchHeader::Draft14(header);
    let mut buf = Vec::new();
    any.encode(&mut buf);

    let mut cursor = &buf[..];
    let decoded = AnyFetchHeader::decode(DraftVersion::Draft14, &mut cursor).unwrap();

    match decoded {
        AnyFetchHeader::Draft14(h) => {
            assert_eq!(h.track_alias.into_inner(), 7);
            assert_eq!(h.publisher_priority, 50);
        }
        _ => panic!("expected Draft14"),
    }
}

#[test]
fn any_fetch_header_draft07_round_trip() {
    use moqtap_codec::draft07::data_stream::FetchHeader;

    let header = FetchHeader { subscribe_id: VarInt::from_u64(99).unwrap() };

    let any = AnyFetchHeader::Draft07(header);
    let mut buf = Vec::new();
    any.encode(&mut buf);

    let mut cursor = &buf[..];
    let decoded = AnyFetchHeader::decode(DraftVersion::Draft07, &mut cursor).unwrap();

    match decoded {
        AnyFetchHeader::Draft07(h) => {
            assert_eq!(h.subscribe_id.into_inner(), 99);
        }
        _ => panic!("expected Draft07"),
    }
}

// ============================================================
// Draft mismatch detection
// ============================================================

#[test]
fn draft14_bytes_decoded_with_draft07_produces_error_or_wrong_message() {
    use moqtap_codec::draft14::message::{ControlMessage, GoAway};

    // Encode a draft-14 GoAway
    let msg = ControlMessage::GoAway(GoAway { new_session_uri: vec![] });
    let mut buf = Vec::new();
    msg.encode(&mut buf).unwrap();

    // Try to decode as draft-07 — should fail or produce a different message
    let mut cursor = &buf[..];
    let result = AnyControlMessage::decode(DraftVersion::Draft07, &mut cursor);
    // Draft-14 GoAway type ID (0x16) is SubscribeOk in draft-07,
    // and the framing differs (draft-14 has scope field). Either way
    // the result should NOT be a valid draft-07 GoAway.
    match result {
        Err(_) => {} // expected: decode error due to framing mismatch
        Ok(AnyControlMessage::Draft07(moqtap_codec::draft07::message::ControlMessage::GoAway(
            _,
        ))) => {
            panic!("should not produce a matching GoAway from wrong draft")
        }
        Ok(_) => {} // decoded as a different message type — also acceptable
    }
}

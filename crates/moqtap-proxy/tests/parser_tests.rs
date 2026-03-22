use moqtap_codec::dispatch::{AnyControlMessage, AnySubgroupHeader};
use moqtap_codec::draft14::data_stream::SubgroupHeader;
use moqtap_codec::draft14::message::{ControlMessage, GoAway, MaxRequestId};
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

use moqtap_proxy::parser::control::*;
use moqtap_proxy::parser::data::*;

// ============================================================
// Control stream parser — Draft-14
// ============================================================

/// Helper: encode a draft-14 ControlMessage to wire bytes.
fn encode_control_d14(msg: &ControlMessage) -> Vec<u8> {
    let mut buf = Vec::new();
    msg.encode(&mut buf).unwrap();
    buf
}

#[test]
fn control_parser_complete_message() {
    let msg = ControlMessage::GoAway(GoAway { new_session_uri: b"https://new.example".to_vec() });
    let bytes = encode_control_d14(&msg);

    let mut parser = ControlStreamParser::new(DraftVersion::Draft14);
    match parser.feed(&bytes) {
        ParseResult::Messages(frames) => {
            assert_eq!(frames.len(), 1);
            assert!(matches!(
                frames[0].message,
                AnyControlMessage::Draft14(ControlMessage::GoAway(_))
            ));
            assert_eq!(frames[0].raw_bytes.len(), bytes.len());
        }
        ParseResult::NeedMore => panic!("expected Messages, got NeedMore"),
    }
}

#[test]
fn control_parser_partial_then_rest() {
    let msg = ControlMessage::GoAway(GoAway { new_session_uri: b"https://relay.test".to_vec() });
    let bytes = encode_control_d14(&msg);
    let mid = bytes.len() / 2;

    let mut parser = ControlStreamParser::new(DraftVersion::Draft14);

    // Feed first half — should need more
    match parser.feed(&bytes[..mid]) {
        ParseResult::NeedMore => {}
        ParseResult::Messages(_) => panic!("should need more data"),
    }

    // Feed second half — should decode
    match parser.feed(&bytes[mid..]) {
        ParseResult::Messages(frames) => {
            assert_eq!(frames.len(), 1);
            assert!(matches!(
                frames[0].message,
                AnyControlMessage::Draft14(ControlMessage::GoAway(_))
            ));
        }
        ParseResult::NeedMore => {
            panic!("expected Messages after completing data")
        }
    }
}

#[test]
fn control_parser_multiple_messages_in_one_chunk() {
    let msg1 = ControlMessage::GoAway(GoAway { new_session_uri: vec![] });
    let msg2 =
        ControlMessage::MaxRequestId(MaxRequestId { request_id: VarInt::from_u64(10).unwrap() });

    let mut bytes = encode_control_d14(&msg1);
    bytes.extend(encode_control_d14(&msg2));

    let mut parser = ControlStreamParser::new(DraftVersion::Draft14);
    match parser.feed(&bytes) {
        ParseResult::Messages(frames) => {
            assert_eq!(frames.len(), 2);
            assert!(matches!(
                frames[0].message,
                AnyControlMessage::Draft14(ControlMessage::GoAway(_))
            ));
            assert!(matches!(
                frames[1].message,
                AnyControlMessage::Draft14(ControlMessage::MaxRequestId(_))
            ));
        }
        ParseResult::NeedMore => panic!("expected 2 messages"),
    }
}

#[test]
fn control_parser_single_byte_feeds() {
    let msg = ControlMessage::GoAway(GoAway { new_session_uri: vec![] });
    let bytes = encode_control_d14(&msg);

    let mut parser = ControlStreamParser::new(DraftVersion::Draft14);
    let mut found = false;

    for &b in &bytes {
        match parser.feed(&[b]) {
            ParseResult::Messages(frames) => {
                assert_eq!(frames.len(), 1);
                found = true;
            }
            ParseResult::NeedMore => {}
        }
    }

    assert!(found, "should have decoded the message eventually");
}

#[test]
fn control_parser_empty_feed() {
    let mut parser = ControlStreamParser::new(DraftVersion::Draft14);
    match parser.feed(&[]) {
        ParseResult::NeedMore => {}
        ParseResult::Messages(_) => panic!("empty feed should return NeedMore"),
    }
}

#[test]
fn control_parser_default() {
    // Verify Default impl works (defaults to Draft14)
    let mut parser = ControlStreamParser::default();
    assert_eq!(parser.draft(), DraftVersion::Draft14);
    let _ = format!("{:?}", parser.feed(&[]));
}

#[test]
fn control_parser_raw_bytes_match_input() {
    let msg =
        ControlMessage::MaxRequestId(MaxRequestId { request_id: VarInt::from_u64(42).unwrap() });
    let bytes = encode_control_d14(&msg);

    let mut parser = ControlStreamParser::new(DraftVersion::Draft14);
    if let ParseResult::Messages(frames) = parser.feed(&bytes) {
        assert_eq!(frames[0].raw_bytes.as_ref(), &bytes[..]);
    } else {
        panic!("expected Messages");
    }
}

// ============================================================
// Control stream parser — Draft-07
// ============================================================

/// Helper: encode a draft-07 ControlMessage to wire bytes.
fn encode_control_d07(msg: &moqtap_codec::draft07::message::ControlMessage) -> Vec<u8> {
    let mut buf = Vec::new();
    msg.encode(&mut buf).unwrap();
    buf
}

#[test]
fn control_parser_draft07_goaway() {
    use moqtap_codec::draft07::message::{
        ControlMessage as D07ControlMessage, GoAway as D07GoAway,
    };

    let msg =
        D07ControlMessage::GoAway(D07GoAway { new_session_uri: b"https://new.example".to_vec() });
    let bytes = encode_control_d07(&msg);

    let mut parser = ControlStreamParser::new(DraftVersion::Draft07);
    match parser.feed(&bytes) {
        ParseResult::Messages(frames) => {
            assert_eq!(frames.len(), 1);
            assert!(matches!(frames[0].message, AnyControlMessage::Draft07(_)));
            assert_eq!(frames[0].raw_bytes.len(), bytes.len());
        }
        ParseResult::NeedMore => panic!("expected Messages, got NeedMore"),
    }
}

#[test]
fn control_parser_draft07_shorter_than_draft14() {
    // Draft-07 has no scope varint, so the same GoAway encodes shorter
    use moqtap_codec::draft07::message::{
        ControlMessage as D07ControlMessage, GoAway as D07GoAway,
    };

    let d14_bytes = encode_control_d14(&ControlMessage::GoAway(GoAway { new_session_uri: vec![] }));
    let d07_bytes =
        encode_control_d07(&D07ControlMessage::GoAway(D07GoAway { new_session_uri: vec![] }));

    // Draft-14 has an extra scope varint (1 byte for value 0)
    assert!(
        d07_bytes.len() < d14_bytes.len(),
        "draft-07 ({}) should be shorter than draft-14 ({})",
        d07_bytes.len(),
        d14_bytes.len()
    );
}

#[test]
fn control_parser_draft07_partial_then_rest() {
    use moqtap_codec::draft07::message::{
        ControlMessage as D07ControlMessage, GoAway as D07GoAway,
    };

    let msg =
        D07ControlMessage::GoAway(D07GoAway { new_session_uri: b"https://relay.test".to_vec() });
    let bytes = encode_control_d07(&msg);
    let mid = bytes.len() / 2;

    let mut parser = ControlStreamParser::new(DraftVersion::Draft07);

    match parser.feed(&bytes[..mid]) {
        ParseResult::NeedMore => {}
        ParseResult::Messages(_) => panic!("should need more data"),
    }

    match parser.feed(&bytes[mid..]) {
        ParseResult::Messages(frames) => {
            assert_eq!(frames.len(), 1);
            assert!(matches!(frames[0].message, AnyControlMessage::Draft07(_)));
        }
        ParseResult::NeedMore => {
            panic!("expected Messages after completing data")
        }
    }
}

// ============================================================
// Data stream parser — subgroup
// ============================================================

/// Helper: encode a SubgroupHeader to wire bytes.
fn encode_subgroup_header(header: &SubgroupHeader) -> Vec<u8> {
    let mut buf = Vec::new();
    header.encode(&mut buf);
    buf
}

#[test]
fn data_parser_subgroup_header() {
    let header = SubgroupHeader {
        track_alias: VarInt::from_u64(1).unwrap(),
        group: VarInt::from_u64(0).unwrap(),
        subgroup: VarInt::from_u64(0).unwrap(),
        publisher_priority: 128,
    };
    let bytes = encode_subgroup_header(&header);

    let mut parser = DataStreamParser::new(DataStreamType::Subgroup, DraftVersion::Draft14);
    let results = parser.feed(&bytes);

    assert!(!results.is_empty());
    assert!(matches!(results[0], DataParseResult::Header(..)));
    if let DataParseResult::Header(ref kind, ref raw) = results[0] {
        assert!(matches!(
            kind,
            moqtap_proxy::event::DataStreamHeaderKind::Subgroup(AnySubgroupHeader::Draft14(_))
        ));
        assert_eq!(raw.len(), bytes.len());
    }
}

#[test]
fn data_parser_subgroup_partial_header() {
    let header = SubgroupHeader {
        track_alias: VarInt::from_u64(1000).unwrap(),
        group: VarInt::from_u64(500).unwrap(),
        subgroup: VarInt::from_u64(0).unwrap(),
        publisher_priority: 64,
    };
    let bytes = encode_subgroup_header(&header);

    let mut parser = DataStreamParser::new(DataStreamType::Subgroup, DraftVersion::Draft14);

    // Feed just 1 byte
    let results = parser.feed(&bytes[..1]);
    assert!(matches!(results[0], DataParseResult::NeedMore));

    // Feed rest
    let results = parser.feed(&bytes[1..]);
    assert!(!results.is_empty());
    assert!(matches!(results[0], DataParseResult::Header(..)));
}

#[test]
fn data_parser_empty_feed() {
    let mut parser = DataStreamParser::new(DataStreamType::Subgroup, DraftVersion::Draft14);
    let results = parser.feed(&[]);
    assert!(results.is_empty() || matches!(results[0], DataParseResult::NeedMore));
}

#[test]
fn data_stream_type_debug() {
    assert_eq!(format!("{:?}", DataStreamType::Subgroup), "Subgroup");
    assert_eq!(format!("{:?}", DataStreamType::Fetch), "Fetch");
}

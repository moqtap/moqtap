//! Parser and framer unit tests, split by the draft their fixtures name.
//!
//! Two sections name a draft (`Draft-14`, `Draft-07`) and one — the
//! `DataStreamType` Debug check — names none. Each item is gated on the
//! draft it actually needs, so a `--features draft07` build keeps the
//! draft-07 section and the draft-agnostic test and drops the rest,
//! instead of the whole file failing to compile.

#[cfg(any(feature = "draft07", feature = "draft14"))]
use moqtap_codec::dispatch::AnyControlMessage;
#[cfg(feature = "draft14")]
use moqtap_codec::dispatch::AnySubgroupHeader;
#[cfg(feature = "draft14")]
use moqtap_codec::draft14::data_stream::{SubgroupHeader, SubgroupStreamType};
#[cfg(feature = "draft14")]
use moqtap_codec::draft14::message::{ControlMessage, GoAway, MaxRequestId};
#[cfg(feature = "draft14")]
use moqtap_codec::varint::VarInt;
#[cfg(any(feature = "draft07", feature = "draft14"))]
use moqtap_codec::version::DraftVersion;

#[cfg(feature = "draft14")]
use moqtap_proxy::framer::{FramerConfig, FramerOut, ObjectFramer};
#[cfg(any(feature = "draft07", feature = "draft14"))]
use moqtap_proxy::parser::control::*;
use moqtap_proxy::parser::data::*;

// ============================================================
// Control stream parser — Draft-14
// ============================================================

/// Helper: encode a draft-14 ControlMessage to wire bytes.
#[cfg(feature = "draft14")]
fn encode_control_d14(msg: &ControlMessage) -> Vec<u8> {
    let mut buf = Vec::new();
    msg.encode(&mut buf).unwrap();
    buf
}

/// The decoded frame behind one parsed item.
///
/// Every fixture in this file feeds bytes an encoder produced, so a
/// `Refused` here is the failure and not a case to handle: the panic names
/// the Message Type the decoder would not read, which is the one fact a
/// refused frame still carries.
///
/// Gated on the two drafts whose sections use it, like everything else
/// here — a build with neither has no control fixture to unwrap.
#[cfg(any(feature = "draft07", feature = "draft14"))]
fn frame(item: &ParsedItem) -> &ParsedFrame {
    match item {
        ParsedItem::Frame(f) => f,
        ParsedItem::Refused(r) => {
            panic!("the decoder refused a frame this fixture encoded; type {:#x}", r.type_id)
        }
    }
}

#[test]
#[cfg(feature = "draft14")]
fn control_parser_complete_message() {
    let msg = ControlMessage::GoAway(GoAway { new_session_uri: b"https://new.example".to_vec() });
    let bytes = encode_control_d14(&msg);

    let mut parser = ControlStreamParser::new(DraftVersion::Draft14);
    match parser.feed(&bytes) {
        ParseResult::Framed(frames) => {
            assert_eq!(frames.len(), 1);
            assert!(matches!(
                frame(&frames[0]).message,
                AnyControlMessage::Draft14(ControlMessage::GoAway(_))
            ));
            // Default parser is non-capturing; raw_bytes is None.
            assert!(frame(&frames[0]).raw_bytes.is_none());
        }
        ParseResult::NeedMore => panic!("expected Messages, got NeedMore"),
    }
}

#[test]
#[cfg(feature = "draft14")]
fn control_parser_partial_then_rest() {
    let msg = ControlMessage::GoAway(GoAway { new_session_uri: b"https://relay.test".to_vec() });
    let bytes = encode_control_d14(&msg);
    let mid = bytes.len() / 2;

    let mut parser = ControlStreamParser::new(DraftVersion::Draft14);

    // Feed first half — should need more
    match parser.feed(&bytes[..mid]) {
        ParseResult::NeedMore => {}
        ParseResult::Framed(_) => panic!("should need more data"),
    }

    // Feed second half — should decode
    match parser.feed(&bytes[mid..]) {
        ParseResult::Framed(frames) => {
            assert_eq!(frames.len(), 1);
            assert!(matches!(
                frame(&frames[0]).message,
                AnyControlMessage::Draft14(ControlMessage::GoAway(_))
            ));
        }
        ParseResult::NeedMore => {
            panic!("expected Messages after completing data")
        }
    }
}

#[test]
#[cfg(feature = "draft14")]
fn control_parser_multiple_messages_in_one_chunk() {
    let msg1 = ControlMessage::GoAway(GoAway { new_session_uri: vec![] });
    let msg2 =
        ControlMessage::MaxRequestId(MaxRequestId { request_id: VarInt::from_u64(10).unwrap() });

    let mut bytes = encode_control_d14(&msg1);
    bytes.extend(encode_control_d14(&msg2));

    let mut parser = ControlStreamParser::new(DraftVersion::Draft14);
    match parser.feed(&bytes) {
        ParseResult::Framed(frames) => {
            assert_eq!(frames.len(), 2);
            assert!(matches!(
                frame(&frames[0]).message,
                AnyControlMessage::Draft14(ControlMessage::GoAway(_))
            ));
            assert!(matches!(
                frame(&frames[1]).message,
                AnyControlMessage::Draft14(ControlMessage::MaxRequestId(_))
            ));
        }
        ParseResult::NeedMore => panic!("expected 2 messages"),
    }
}

#[test]
#[cfg(feature = "draft14")]
fn control_parser_single_byte_feeds() {
    let msg = ControlMessage::GoAway(GoAway { new_session_uri: vec![] });
    let bytes = encode_control_d14(&msg);

    let mut parser = ControlStreamParser::new(DraftVersion::Draft14);
    let mut found = false;

    for &b in &bytes {
        match parser.feed(&[b]) {
            ParseResult::Framed(frames) => {
                assert_eq!(frames.len(), 1);
                found = true;
            }
            ParseResult::NeedMore => {}
        }
    }

    assert!(found, "should have decoded the message eventually");
}

#[test]
#[cfg(feature = "draft14")]
fn control_parser_empty_feed() {
    let mut parser = ControlStreamParser::new(DraftVersion::Draft14);
    match parser.feed(&[]) {
        ParseResult::NeedMore => {}
        ParseResult::Framed(_) => panic!("empty feed should return NeedMore"),
    }
}

#[test]
#[cfg(feature = "draft14")]
fn control_parser_default() {
    // Verify Default impl works (defaults to Draft14)
    let mut parser = ControlStreamParser::default();
    assert_eq!(parser.draft(), DraftVersion::Draft14);
    let _ = format!("{:?}", parser.feed(&[]));
}

#[test]
#[cfg(feature = "draft14")]
fn control_parser_raw_bytes_match_input() {
    let msg =
        ControlMessage::MaxRequestId(MaxRequestId { request_id: VarInt::from_u64(42).unwrap() });
    let bytes = encode_control_d14(&msg);

    // Capturing parser exposes the original wire bytes so a hook can
    // rewrite a frame before the proxy forwards it.
    let mut parser = ControlStreamParser::new_capturing(DraftVersion::Draft14);
    if let ParseResult::Framed(frames) = parser.feed(&bytes) {
        assert_eq!(frame(&frames[0]).raw_bytes.as_ref().unwrap().as_ref(), &bytes[..]);
    } else {
        panic!("expected Messages");
    }
}

#[test]
#[cfg(feature = "draft14")]
fn control_parser_non_capturing_omits_raw_bytes() {
    let msg = ControlMessage::GoAway(GoAway { new_session_uri: b"https://x".to_vec() });
    let bytes = encode_control_d14(&msg);

    let mut parser = ControlStreamParser::new(DraftVersion::Draft14);
    if let ParseResult::Framed(frames) = parser.feed(&bytes) {
        assert!(frame(&frames[0]).raw_bytes.is_none());
    } else {
        panic!("expected Messages");
    }
}

// ============================================================
// Control stream parser — Draft-07
// ============================================================

/// Helper: encode a draft-07 ControlMessage to wire bytes.
#[cfg(feature = "draft07")]
fn encode_control_d07(msg: &moqtap_codec::draft07::message::ControlMessage) -> Vec<u8> {
    let mut buf = Vec::new();
    msg.encode(&mut buf).unwrap();
    buf
}

#[test]
#[cfg(feature = "draft07")]
fn control_parser_draft07_goaway() {
    use moqtap_codec::draft07::message::{
        ControlMessage as D07ControlMessage, GoAway as D07GoAway,
    };

    let msg =
        D07ControlMessage::GoAway(D07GoAway { new_session_uri: b"https://new.example".to_vec() });
    let bytes = encode_control_d07(&msg);

    let mut parser = ControlStreamParser::new(DraftVersion::Draft07);
    match parser.feed(&bytes) {
        ParseResult::Framed(frames) => {
            assert_eq!(frames.len(), 1);
            assert!(matches!(frame(&frames[0]).message, AnyControlMessage::Draft07(_)));
        }
        ParseResult::NeedMore => panic!("expected Messages, got NeedMore"),
    }
}

#[test]
#[cfg(all(feature = "draft07", feature = "draft14"))]
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
#[cfg(feature = "draft07")]
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
        ParseResult::Framed(_) => panic!("should need more data"),
    }

    match parser.feed(&bytes[mid..]) {
        ParseResult::Framed(frames) => {
            assert_eq!(frames.len(), 1);
            assert!(matches!(frame(&frames[0]).message, AnyControlMessage::Draft07(_)));
        }
        ParseResult::NeedMore => {
            panic!("expected Messages after completing data")
        }
    }
}

// ============================================================
// Data stream framing — subgroup
// ============================================================

/// Helper: encode a SubgroupHeader to wire bytes.
#[cfg(feature = "draft14")]
fn encode_subgroup_header(header: &SubgroupHeader) -> Vec<u8> {
    let mut buf = Vec::new();
    header.encode(&mut buf);
    buf
}

#[cfg(feature = "draft14")]
fn d14_header() -> SubgroupHeader {
    SubgroupHeader {
        stream_type: SubgroupStreamType::from_u8(0x14).unwrap(),
        track_alias: VarInt::from_u64(1).unwrap(),
        group_id: VarInt::from_u64(0).unwrap(),
        subgroup_id: Some(VarInt::from_u64(0).unwrap()),
        publisher_priority: 128,
    }
}

#[test]
#[cfg(feature = "draft14")]
fn framer_reports_subgroup_header() {
    let bytes = encode_subgroup_header(&d14_header());

    let mut framer =
        ObjectFramer::new(DataStreamType::Subgroup, DraftVersion::Draft14, FramerConfig::default());
    framer.feed(&bytes);

    match framer.poll() {
        FramerOut::Header { header, raw } => {
            assert!(matches!(
                header,
                moqtap_proxy::event::DataStreamHeaderKind::Subgroup(AnySubgroupHeader::Draft14(_))
            ));
            assert_eq!(&raw[..], &bytes[..], "header raw bytes must equal the wire bytes");
        }
        other => panic!("expected Header, got {other:?}"),
    }
    assert!(matches!(framer.poll(), FramerOut::NeedMore));
}

#[test]
#[cfg(feature = "draft14")]
fn framer_needs_more_on_partial_header() {
    let bytes = encode_subgroup_header(&SubgroupHeader {
        track_alias: VarInt::from_u64(1000).unwrap(),
        group_id: VarInt::from_u64(500).unwrap(),
        ..d14_header()
    });

    let mut framer =
        ObjectFramer::new(DataStreamType::Subgroup, DraftVersion::Draft14, FramerConfig::default());

    framer.feed(&bytes[..1]);
    assert!(matches!(framer.poll(), FramerOut::NeedMore));

    framer.feed(&bytes[1..]);
    assert!(matches!(framer.poll(), FramerOut::Header { .. }));
}

#[test]
#[cfg(feature = "draft14")]
fn framer_empty_feed_needs_more() {
    let mut framer =
        ObjectFramer::new(DataStreamType::Subgroup, DraftVersion::Draft14, FramerConfig::default());
    framer.feed(&[]);
    assert!(matches!(framer.poll(), FramerOut::NeedMore));
    assert_eq!(framer.buffered(), 0);
}

#[test]
fn data_stream_type_debug() {
    assert_eq!(format!("{:?}", DataStreamType::Subgroup), "Subgroup");
    assert_eq!(format!("{:?}", DataStreamType::Fetch), "Fetch");
}

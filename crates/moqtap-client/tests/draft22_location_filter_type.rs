#![cfg(feature = "draft22")]
//! Draft-22 Section 9.20.9: "Any other Location Filter Type is a
//! PROTOCOL_VIOLATION."
//!
//! # Why the rule is back
//!
//! Drafts 20 and 21 give `LOCATION_FILTER` no type: the value is a length and
//! up to four fields, and the length says which fields arrived. Draft-22
//! replaces the length with a `Location Filter Type` that names them, so the
//! value carries a number a reader can fail to recognise again — and, because
//! the parameter carries no length any more, a reader that does not recognise
//! it cannot find where the next parameter starts either. The codec refuses the
//! frame with `CodecError::InvalidFilterType`, the error drafts 14 through 19
//! raise for their own Filter Type.
//!
//! # What these gates hold
//!
//! The three places the rule has to land in this crate: the codec refuses the
//! frame, this draft's close table answers the refusal with PROTOCOL_VIOLATION,
//! and the citation table publishes draft-22's sentence for it where drafts 20
//! and 21 publish none.
//!
//! # What they do not
//!
//! A close on the wire. Every message that may carry `LOCATION_FILTER` on this
//! draft travels on a request stream, and a request stream whose message does
//! not decode is reset by this crate with the session left open, on every
//! draft from 17 on. The table below is what that path would consult.

use moqtap_client::above_codec_rules::CodecRule;
use moqtap_client::draft22::connection::Connection;
use moqtap_client::draft22::fill::LocationFilter;
use moqtap_codec::draft22::error_codes::SessionErrorCode;
use moqtap_codec::draft22::message::{ControlMessage, PublishStateNotify, LOCATION_FILTER};
use moqtap_codec::error::CodecError;
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::varint::VarInt;

/// A PUBLISH_STATE_NOTIFY carrying one `LOCATION_FILTER` of Next Object, as
/// this codec's own encoder writes it.
///
/// PUBLISH_STATE_NOTIFY because it is the shortest message the parameter may
/// appear in — Section 9.20.9 names it beside FETCH, SUBSCRIBE, PUBLISH and
/// REQUEST_UPDATE — so the filter type is the last byte of the frame.
fn notify_with_next_object() -> Vec<u8> {
    let filter = LocationFilter::next_object().parameter().expect("Next Object encodes");
    let message =
        ControlMessage::PublishStateNotify(PublishStateNotify { parameters: vec![filter] });
    let mut out = Vec::new();
    message.encode(&mut out).expect("the notify encodes");
    out
}

/// The same frame with its `Location Filter Type` replaced, one byte for one,
/// so nothing else in it moves.
fn notify_with_filter_type(filter_type: u8) -> Vec<u8> {
    let mut frame = notify_with_next_object();
    let last = frame.last_mut().expect("the frame ends with the filter type");
    assert_eq!(*last, 0x05, "the frame should end with Next Object's type");
    *last = filter_type;
    frame
}

fn decode(frame: &[u8]) -> Result<ControlMessage, CodecError> {
    let mut cursor = frame;
    ControlMessage::decode(&mut cursor)
}

/// Next Object is the type alone, so the parameter is two bytes and the frame
/// ends with them: Type Delta 0x21, then 0x05.
#[test]
fn the_fixture_is_a_frame_the_codec_reads() {
    let frame = notify_with_next_object();
    assert!(frame.ends_with(&[0x21, 0x05]), "{frame:02x?}");
    let ControlMessage::PublishStateNotify(notify) = decode(&frame).expect("it decodes") else {
        panic!("what was encoded was a PUBLISH_STATE_NOTIFY");
    };
    assert_eq!(notify.parameters.len(), 1);
    assert_eq!(notify.parameters[0].key.into_inner(), LOCATION_FILTER);
}

/// A type Section 9.20.9 does not assign is refused as one, and not as a
/// malformed parameter. 0x06 is the first unassigned value; 0x3F is the largest
/// a one-byte vi64 holds, so the swap moves no other byte of the frame.
#[test]
fn an_unassigned_filter_type_is_refused_as_a_filter_type() {
    for filter_type in [0x06u8, 0x07, 0x3F] {
        match decode(&notify_with_filter_type(filter_type)) {
            Err(CodecError::InvalidFilterType(t)) => assert_eq!(t, u64::from(filter_type)),
            other => panic!("Location Filter Type {filter_type:#x} must be refused: {other:?}"),
        }
    }
}

/// The six assigned types are not refused. None and Next Object are the two
/// that end the frame on the type, and the other four would need fields after
/// it, so their absence is the other refusal — a parameter that is not the
/// structure its type names — and never the filter-type one.
#[test]
fn an_assigned_filter_type_is_not_refused_as_a_filter_type() {
    for filter_type in [0x00u8, 0x05] {
        assert!(
            decode(&notify_with_filter_type(filter_type)).is_ok(),
            "Location Filter Type {filter_type:#x} carries no fields and must decode"
        );
    }
    for filter_type in [0x01u8, 0x02, 0x03, 0x04] {
        match decode(&notify_with_filter_type(filter_type)) {
            Err(CodecError::InvalidFilterType(_)) => {
                panic!("Location Filter Type {filter_type:#x} is assigned")
            }
            Err(_) => {}
            Ok(m) => panic!("type {filter_type:#x} names fields this frame does not have: {m:?}"),
        }
    }
}

/// The refusal closes the session with PROTOCOL_VIOLATION, the code the
/// sentence names.
#[test]
fn an_unassigned_filter_type_is_a_protocol_violation() {
    assert_eq!(
        Connection::codec_session_error_code(&CodecError::InvalidFilterType(0x06)),
        Some(SessionErrorCode::ProtocolViolation)
    );
}

/// The sentence a consumer publishes for the close is draft-22's own, filed
/// under the section that states it; drafts 20 and 21, whose filter has no
/// type, publish nothing.
#[test]
fn the_rule_is_cited_on_draft22_and_not_on_the_drafts_with_no_filter_type() {
    let cite = CodecRule::InvalidFilterType
        .citation(22)
        .expect("draft-22 states the rule, so the table must cite it");
    assert_eq!(cite.section, "9.20.9");
    assert_eq!(cite.sentence, "Any other Location Filter Type is a PROTOCOL_VIOLATION.");
    assert!(CodecRule::InvalidFilterType.citation(20).is_none());
    assert!(CodecRule::InvalidFilterType.citation(21).is_none());
}

/// The encoder holds a filter value to its own type, so the refusal is not
/// something this crate can be talked into writing: a hand-built value whose
/// type is unassigned is not encoded.
#[test]
fn this_crate_does_not_write_an_unassigned_filter_type() {
    let value = KvpValue::Bytes(vec![0x06]);
    let message = ControlMessage::PublishStateNotify(PublishStateNotify {
        parameters: vec![KeyValuePair { key: VarInt::from_u64_moqt(LOCATION_FILTER), value }],
    });
    let mut out = Vec::new();
    assert!(message.encode(&mut out).is_err(), "an unassigned type must not reach the wire");
}

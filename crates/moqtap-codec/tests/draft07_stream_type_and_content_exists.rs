#![cfg(feature = "draft07")]
//! Two draft-07 rules that used to arrive as `CodecError::InvalidField`, and the
//! one case next to each of them that must not.
//!
//!   - Section 7: "An endpoint that receives an unknown stream type MUST close
//!     the session." Every draft from 07 to 20 states this, in one of two
//!     phrasings. Draft-07 names streams alone because it numbers its datagrams
//!     in the very same table, Table 5; drafts 08 through 16 split the table in
//!     two and say "an unknown stream or datagram type" to cover both; drafts
//!     17 through 20 give each table a sentence of its own.
//!   - Sections 6.15 and 6.19, of the ContentExists field in SUBSCRIBE_OK and
//!     SUBSCRIBE_ERROR: "Any other value is a protocol error and MUST terminate
//!     the session with a Protocol Violation". Draft-08 replaced the field, so
//!     this one is draft-07's alone.
//!
//! `InvalidField` is shared by a dozen unrelated malformations, only some of
//! which the draft answers with a close, so a session cannot be ended on it
//! without ending sessions the draft does not ask to be ended. Each rule now has
//! a variant of its own, which is what lets the connection answer it.
//!
//! The near-miss cases are the point of the file as much as the rules are. A
//! split that reports too much is as wrong as one that reports too little, and
//! in the more dangerous direction: it closes sessions over traffic the draft
//! permits.

use moqtap_codec::draft07::data_stream::{FetchHeader, SubgroupHeader};
use moqtap_codec::draft07::message::ControlMessage;
use moqtap_codec::error::CodecError;
use moqtap_codec::varint::VarInt;

/// A value draft-07's type table does not assign. Table 5 assigns 0x01, 0x04
/// and 0x05, so 0x02 is a hole among assigned neighbours rather than a number
/// past the end of everything — a reader that merely range-checked would take
/// it.
const UNASSIGNED: u64 = 0x02;

/// OBJECT_DATAGRAM, which draft-07 assigns in the *same* table as its stream
/// types. Table 5 is headed "Stream Type" and holds all three assignments,
/// under one sentence: "All unidirectional MOQT streams, as well as all
/// datagrams, start with a variable-length integer indicating the type of the
/// stream in question."
const DATAGRAM_TYPE: u64 = 0x01;

const SUBGROUP_TYPE: u64 = 0x04;
const FETCH_TYPE: u64 = 0x05;

fn stream_beginning_with(stream_type: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    VarInt::from_u64(stream_type).expect("fits a varint").encode(&mut buf);
    // Enough plausible header bytes behind it that a reader which accepted the
    // type would get somewhere, so a refusal cannot be an accident of running
    // out of input.
    buf.extend_from_slice(&[0x01, 0x02, 0x03, 0x80]);
    buf
}

#[test]
fn an_unassigned_stream_type_is_named_as_one() {
    for reader in ["subgroup", "fetch"] {
        let bytes = stream_beginning_with(UNASSIGNED);
        let got = if reader == "subgroup" {
            SubgroupHeader::decode_stream(&mut &bytes[..]).map(|_| ())
        } else {
            FetchHeader::decode_stream(&mut &bytes[..]).map(|_| ())
        };
        assert!(
            matches!(got, Err(CodecError::UnknownStreamType(UNASSIGNED))),
            "the {reader} reader should report an unassigned stream type as one, got {got:?}"
        );
    }
}

/// A datagram type at the head of a unidirectional stream is refused, but it is
/// not unknown.
///
/// Draft-07 is the only draft where this is so, and the reason is Table 5:
/// streams and datagrams share one number space here, so 0x01 is a value the
/// table assigns and the unknown-type sentence is not about it. The stream is
/// still refused — a datagram type says nothing about how to read a stream —
/// but under the rule that governs a reader handed the wrong carrier, which
/// does not end the session.
///
/// From draft-08 on the tables are separate and the answer inverts: a datagram
/// type at the head of a stream is then genuinely unknown there. Getting this
/// backwards on draft-07 means closing sessions over a value the draft assigns.
#[test]
fn a_datagram_type_at_the_head_of_a_stream_is_not_called_unknown() {
    let bytes = stream_beginning_with(DATAGRAM_TYPE);
    let got = SubgroupHeader::decode_stream(&mut &bytes[..]).map(|_| ());
    assert!(
        matches!(got, Err(CodecError::InvalidField)),
        "draft-07 assigns 0x01 in the same table as its stream types, so a subgroup reader \
         must refuse it without naming the unknown-stream-type rule, got {got:?}"
    );
}

/// The other assigned stream type is refused without being called unknown.
///
/// This is the case a careless split gets wrong. FETCH_HEADER at a subgroup
/// reader is a stream this reader cannot read; the draft defines the value, and
/// the disagreement is with the caller rather than with the draft. Reporting it
/// as unknown would close a session over a stream draft-07 permits.
#[test]
fn the_other_assigned_stream_type_is_not_called_unknown() {
    let got =
        SubgroupHeader::decode_stream(&mut &stream_beginning_with(FETCH_TYPE)[..]).map(|_| ());
    assert!(
        matches!(got, Err(CodecError::InvalidField)),
        "a subgroup reader handed a fetch stream must refuse it without naming the \
         unknown-stream-type rule, got {got:?}"
    );

    let got =
        FetchHeader::decode_stream(&mut &stream_beginning_with(SUBGROUP_TYPE)[..]).map(|_| ());
    assert!(
        matches!(got, Err(CodecError::InvalidField)),
        "a fetch reader handed a subgroup stream must refuse it without naming the \
         unknown-stream-type rule, got {got:?}"
    );
}

/// SUBSCRIBE_OK (0x04) with a ContentExists byte of `value`.
///
/// Draft-07 frames a control message as a varint Type, a varint Length, then the
/// payload: Subscribe ID, Expires, Group Order, ContentExists, and — when
/// ContentExists says so — a Largest Group and Object, then a parameter list.
fn subscribe_ok_with_content_exists(value: u8) -> Vec<u8> {
    let mut body = Vec::new();
    VarInt::from_usize(1).encode(&mut body); // Subscribe ID
    VarInt::from_usize(0).encode(&mut body); // Expires
    body.push(0x01); // Group Order: Ascending
    body.push(value);
    if value == 1 {
        VarInt::from_usize(9).encode(&mut body); // Largest Group ID
        VarInt::from_usize(3).encode(&mut body); // Largest Object ID
    }
    VarInt::from_usize(0).encode(&mut body); // no parameters

    let mut out = Vec::new();
    VarInt::from_usize(0x04).encode(&mut out);
    VarInt::from_usize(body.len()).encode(&mut out);
    out.extend_from_slice(&body);
    out
}

#[test]
fn a_content_exists_that_is_neither_zero_nor_one_is_named() {
    let bytes = subscribe_ok_with_content_exists(2);
    let got = ControlMessage::decode(&mut &bytes[..]);
    assert!(
        matches!(got, Err(CodecError::InvalidContentExists(2))),
        "the refusal should name the value it saw, not merely that one was wrong, got {got:?}"
    );

    // Both legal values decode, each with the fields its own value promises.
    // Zero is the one that decides no Largest Location follows, so it is what a
    // check written as `!= 1` would break.
    for legal in [0u8, 1] {
        let bytes = subscribe_ok_with_content_exists(legal);
        let got = ControlMessage::decode(&mut &bytes[..]);
        assert!(got.is_ok(), "ContentExists {legal} is legal and must decode, got {got:?}");
    }
}

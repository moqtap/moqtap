//! The Reason Phrase and New Session URI caps, on the drafts that state them.
//!
//! Drafts 11 through 19 cap a Reason Phrase at 1,024 bytes and a New Session
//! URI at 8,192, and both sentences are written about a receiver. Drafts 14
//! through 19 word it: "If an endpoint receives a length exceeding the maximum,
//! it MUST close the session with a PROTOCOL_VIOLATION." Drafts 11, 12 and 13
//! say a Protocol Violation instead, and drafts 07 through 10 state neither
//! cap.
//!
//! The codec had both facts backwards. Every draft from 07 on refused an
//! over-long value when *writing* one, and accepted one when reading — so the
//! four drafts that state no cap enforced one their peers may exceed, and the
//! nine that do state one let it through in the only direction the sentence
//! talks about. A control message may be 65,535 bytes, so an unguarded reader
//! took sixty-four reason phrases' worth on every error message in the
//! protocol.
//!
//! Both directions are gated here, because a cap in the wrong place is not a
//! milder version of the same bug: refusing what a draft permits breaks
//! interoperability just as surely as accepting what it forbids, and only a
//! test that names the draft can tell the two apart.
//!
//! Drafts 17 through 19 read these fields with the other variable-length
//! integer encoding and already applied both caps; they are covered by their
//! own draft's tests.

#[cfg(any(
    feature = "draft07",
    feature = "draft08",
    feature = "draft09",
    feature = "draft10",
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16"
))]
use moqtap_codec::error::CodecError;
#[cfg(any(
    feature = "draft07",
    feature = "draft08",
    feature = "draft09",
    feature = "draft10",
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16"
))]
use moqtap_codec::varint::VarInt;

#[cfg(any(
    feature = "draft07",
    feature = "draft08",
    feature = "draft09",
    feature = "draft10",
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16"
))]
fn vi(v: u64) -> VarInt {
    VarInt::from_u64(v).expect("value fits a varint")
}

/// Frame a payload the way drafts 11 through 16 do: type, 16-bit Length, payload.
#[cfg(any(
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16"
))]
fn framed_u16(type_id: u8, payload: &[u8]) -> Vec<u8> {
    let mut wire = vec![type_id];
    wire.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    wire.extend_from_slice(payload);
    wire
}

/// Frame a payload the way drafts 07 through 10 do: type, varint Length, payload.
#[cfg(any(feature = "draft07", feature = "draft08", feature = "draft09", feature = "draft10"))]
fn framed_varint(type_id: u8, payload: &[u8]) -> Vec<u8> {
    let mut wire = vec![type_id];
    VarInt::from_usize(payload.len()).encode(&mut wire);
    wire.extend_from_slice(payload);
    wire
}

/// The error message at type 0x05, with a Reason Phrase of the given length.
///
/// `leading` counts the varints before the phrase: a request identifier and an
/// error code on most drafts, and a retry interval as well on draft-16.
#[cfg(any(
    feature = "draft07",
    feature = "draft08",
    feature = "draft09",
    feature = "draft10",
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16"
))]
fn error_payload(leading: usize, reason_len: usize) -> Vec<u8> {
    let mut payload = Vec::new();
    for _ in 0..leading {
        vi(1).encode(&mut payload);
    }
    VarInt::from_usize(reason_len).encode(&mut payload);
    payload.extend(std::iter::repeat_n(b'r', reason_len));
    payload
}

/// GOAWAY's payload: a length-prefixed New Session URI and nothing else.
#[cfg(any(
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16"
))]
fn goaway_payload(uri_len: usize) -> Vec<u8> {
    let mut payload = Vec::new();
    VarInt::from_usize(uri_len).encode(&mut payload);
    payload.extend(std::iter::repeat_n(b'u', uri_len));
    payload
}

/// Gate a draft that states both caps: the reader must refuse an over-long value.
///
/// # What this catches, observed by removing each check and running it
///
/// Dropping the length check from `read_reason_phrase`, with the 1,025 bytes
/// of phrase elided:
///
/// ```text
/// a 1025-byte reason phrase must be refused, got Ok(SubscribeError(SubscribeError { request_id: VarInt(1), error_code: VarInt(1), reason_phrase: [114, 114, ...] }))
/// ```
///
/// Dropping it from the GOAWAY decoder:
///
/// ```text
/// an 8193-byte New Session URI must be refused, got Ok(GoAway(GoAway { new_session_uri: [117, 117, ...] }))
/// ```
macro_rules! caps_bind_the_reader {
    ($fname:ident, $feat:literal, $draft:ident, $leading:expr) => {
        #[cfg(feature = $feat)]
        #[test]
        fn $fname() {
            use moqtap_codec::$draft::message::ControlMessage;

            let wire = framed_u16(0x05, &error_payload($leading, 1025));
            let got = ControlMessage::decode(&mut &wire[..]);
            assert!(
                matches!(got, Err(CodecError::ReasonPhraseTooLong)),
                "a 1025-byte reason phrase must be refused, got {got:?}"
            );

            // One byte shorter is inside the cap, so the gate observes the cap
            // and not the length of the buffer.
            let wire = framed_u16(0x05, &error_payload($leading, 1024));
            let got = ControlMessage::decode(&mut &wire[..]);
            assert!(
                !matches!(got, Err(CodecError::ReasonPhraseTooLong)),
                "a 1024-byte reason phrase is within the cap, got {got:?}"
            );

            let wire = framed_u16(0x10, &goaway_payload(8193));
            let got = ControlMessage::decode(&mut &wire[..]);
            assert!(
                matches!(got, Err(CodecError::GoAwayUriTooLong)),
                "an 8193-byte New Session URI must be refused, got {got:?}"
            );

            let wire = framed_u16(0x10, &goaway_payload(8192));
            let got = ControlMessage::decode(&mut &wire[..]);
            assert!(
                !matches!(got, Err(CodecError::GoAwayUriTooLong)),
                "an 8192-byte New Session URI is within the cap, got {got:?}"
            );
        }
    };
}

/// Gate a draft that states neither cap: it must not invent one, in either
/// direction.
///
/// # What this catches, observed by adding the checks and running it
///
/// Giving draft-07's reader the 1,024-byte cap that draft-11 introduced:
///
/// ```text
/// draft-07 states no reason phrase cap but refused to read 1025 bytes: Err(ReasonPhraseTooLong)
/// ```
///
/// Putting the URI check back on the encode side, where it used to be:
///
/// ```text
/// draft-07 states no URI cap but refused to write 8193 bytes: Err(GoAwayUriTooLong)
/// ```
macro_rules! no_cap_is_invented {
    ($fname:ident, $feat:literal, $draft:ident, $dnum:literal) => {
        #[cfg(feature = $feat)]
        #[test]
        fn $fname() {
            use moqtap_codec::$draft::message::{ControlMessage, GoAway};

            // Reading: an over-long phrase is not this draft's business.
            let wire = framed_varint(0x05, &error_payload(2, 1025));
            let got = ControlMessage::decode(&mut &wire[..]);
            assert!(
                !matches!(got, Err(CodecError::ReasonPhraseTooLong)),
                concat!(
                    "draft-",
                    $dnum,
                    " states no reason phrase cap but refused to read 1025 bytes: {:?}"
                ),
                got
            );

            // Writing: the same, and this is the direction the codec got wrong.
            let message = ControlMessage::GoAway(GoAway {
                new_session_uri: std::iter::repeat_n(b'u', 8193).collect(),
            });
            let mut out = Vec::new();
            let got = message.encode(&mut out);
            assert!(
                got.is_ok(),
                concat!(
                    "draft-",
                    $dnum,
                    " states no URI cap but refused to write 8193 bytes: {:?}"
                ),
                got
            );

            // And what it wrote, it reads back.
            let round_tripped = ControlMessage::decode(&mut &out[..]);
            assert!(
                matches!(round_tripped, Ok(ControlMessage::GoAway(_))),
                concat!("draft-", $dnum, " could not read back its own GOAWAY: {:?}"),
                round_tripped
            );
        }
    };
}

// ── Drafts that state both caps ────────────────────────────

caps_bind_the_reader!(draft11_caps_bind_the_reader, "draft11", draft11, 2);
caps_bind_the_reader!(draft12_caps_bind_the_reader, "draft12", draft12, 2);
caps_bind_the_reader!(draft13_caps_bind_the_reader, "draft13", draft13, 2);
caps_bind_the_reader!(draft14_caps_bind_the_reader, "draft14", draft14, 2);
caps_bind_the_reader!(draft15_caps_bind_the_reader, "draft15", draft15, 2);
// Draft-16 puts a Retry Interval between the error code and the phrase.
caps_bind_the_reader!(draft16_caps_bind_the_reader, "draft16", draft16, 3);

// ── Drafts that state neither ──────────────────────────────

no_cap_is_invented!(draft07_invents_no_cap, "draft07", draft07, "07");
no_cap_is_invented!(draft08_invents_no_cap, "draft08", draft08, "08");
no_cap_is_invented!(draft09_invents_no_cap, "draft09", draft09, "09");
no_cap_is_invented!(draft10_invents_no_cap, "draft10", draft10, "10");

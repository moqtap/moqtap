//! The declared Length of a control message is part of the message.
//!
//! Every draft from 07 through 19 carries the same sentence in its control
//! message section: control messages have a length to make parsing easier, but
//! no control message is intended to be ignored, and if the length does not
//! match the length of the message payload the receiver MUST close the session.
//!
//! A reader that stops when its own fields run out, and ignores whatever is
//! left inside the frame, cannot tell a peer speaking a longer dialect from a
//! peer speaking its own. It drops the trailing field and reports success,
//! which is the outcome that sentence exists to prevent.
//!
//! Each gate drives the sentence both ways, because "does not match" has two
//! sides and they arrive as different failures. A Length larger than the fields
//! leaves bytes unread. A Length smaller than them makes the fields run past the
//! end of a buffer that cannot grow — which reads like an incomplete message and
//! is not one: the frame is entirely present, and it is the number describing it
//! that is wrong. Reporting the second as "still arriving" would leave a reader
//! waiting for bytes that are already there.
//!
//! A round trip cannot find this. The encoder writes a Length that matches
//! what the encoder wrote, so the decoder never sees a frame it did not
//! produce, and the corpus is silent for the same reason: it was generated
//! from these encoders. Only a frame built to disagree with itself reaches the
//! rule, which is why every gate below writes one by hand.
//!
//! The gates are one per draft rather than one shared gate because the framing
//! is not shared. Drafts 07 through 10 carry a variable-length Length; drafts
//! 11 onward carry a fixed 16-bit one.

use moqtap_codec::error::CodecError;
use moqtap_codec::varint::VarInt;

/// Re-frame an encoded control message with one unread byte inside its Length.
///
/// The byte is appended and the Length raised to cover it, so the frame stays
/// self-consistent: the outer buffer is exactly as long as it claims to be, and
/// the only disagreement is between the declared payload and the fields the
/// decoder reads out of it. Nothing but the rule under test can reject it.
#[allow(dead_code)]
fn one_byte_longer(encoded: &[u8], len_width: usize) -> Vec<u8> {
    let mut out = encoded.to_vec();
    match len_width {
        1 => {
            // Every payload here is far below 63 bytes, so its Length is a
            // one-byte varint and raising it cannot widen the field.
            assert!(out[1] < 0x3e, "the Length must stay a one-byte varint");
            out[1] += 1;
        }
        2 => {
            let raised = u16::from_be_bytes([out[1], out[2]]) + 1;
            out[1..3].copy_from_slice(&raised.to_be_bytes());
        }
        _ => unreachable!("the drafts use only these two framings"),
    }
    out.push(0x00);
    out
}

/// Re-frame an encoded control message with a Length `cut` bytes short of its
/// fields.
///
/// The frame keeps every byte it had; only the number describing them changes.
/// The decoder therefore hands its body parser fewer bytes than the fields need,
/// and the parser runs out inside a buffer that cannot grow — which is the same
/// disagreement as [`one_byte_longer`], seen from the sender's side.
///
/// The bytes the shortened Length excludes are left in the outer buffer and
/// never read. That is deliberate: the rule is about the Length disagreeing with
/// the fields, not about what follows the frame.
///
/// `cut` is one byte everywhere except draft-18, whose GOAWAY ends in a
/// genuinely optional Request ID. Removing one byte there deletes that field
/// instead of truncating a required one, and the result is a well-formed message
/// rather than a violation — so draft-18 gives up two, which reaches the timeout
/// behind it.
#[allow(dead_code)]
fn shorter_by(encoded: &[u8], len_width: usize, cut: u16) -> Vec<u8> {
    let mut out = encoded.to_vec();
    match len_width {
        1 => {
            assert!(u16::from(out[1]) >= cut, "the Length must have bytes to give up");
            out[1] -= cut as u8;
        }
        2 => {
            let lowered = u16::from_be_bytes([out[1], out[2]]) - cut;
            out[1..3].copy_from_slice(&lowered.to_be_bytes());
        }
        _ => unreachable!("the drafts use only these two framings"),
    }
    out
}

#[allow(dead_code)]
fn vi(v: u64) -> VarInt {
    VarInt::from_u64(v).expect("value fits a varint")
}

/// Build one gate for a draft, given its Length width and any extra GOAWAY fields.
///
/// GOAWAY is the vehicle because every draft from 07 to 19 assigns it type
/// 0x10 and gives it a length-prefixed URI, so the same shape reaches every
/// decoder under test.
///
/// # What this catches, observed by removing the check from each draft and running it
///
/// Every draft returned the same shape of answer — a well-formed message, and
/// no sign that a byte had been thrown away:
///
/// ```text
/// a byte left unread inside the declared Length must be refused, got Ok(GoAway(GoAway { new_session_uri: [109, 111, 113, 116, ...] }))
/// ```
macro_rules! declared_length_gate {
    ($fname:ident, $feat:literal, $draft:ident, $width:expr, $cut:expr $(, $field:ident : $value:expr)* $(,)?) => {
        #[cfg(feature = $feat)]
        #[test]
        fn $fname() {
            use moqtap_codec::$draft::message::{ControlMessage, GoAway};

            let message = ControlMessage::GoAway(GoAway {
                new_session_uri: b"moqt://example/next".to_vec(),
                $($field: $value,)*
            });
            let mut encoded = Vec::new();
            message.encode(&mut encoded).expect("GOAWAY encodes");
            ControlMessage::decode(&mut &encoded[..]).expect("the frame it wrote decodes");

            let longer = one_byte_longer(&encoded, $width);
            let decoded = ControlMessage::decode(&mut &longer[..]);
            assert!(
                matches!(
                    decoded,
                    Err(CodecError::ControlMessageLengthMismatch {
                        detail: "its fields left bytes unread",
                        ..
                    })
                ),
                "a byte left unread inside the declared Length must be refused, got {decoded:?}"
            );

            // The other direction of the same sentence: a Length short of the
            // fields. Nothing is appended, so the frame's own bytes are
            // untouched and the only change is the number describing them.
            let shorter = shorter_by(&encoded, $width, $cut);
            let decoded = ControlMessage::decode(&mut &shorter[..]);
            assert!(
                matches!(
                    decoded,
                    Err(CodecError::ControlMessageLengthMismatch {
                        detail: "its fields ran past the end",
                        ..
                    })
                ),
                "fields running past a short declared Length must be refused, got {decoded:?}"
            );
        }
    };
}

// ── Variable-length Length ─────────────────────────────────

declared_length_gate!(draft07_reads_its_whole_declared_payload, "draft07", draft07, 1, 1);
declared_length_gate!(draft08_reads_its_whole_declared_payload, "draft08", draft08, 1, 1);
declared_length_gate!(draft09_reads_its_whole_declared_payload, "draft09", draft09, 1, 1);
declared_length_gate!(draft10_reads_its_whole_declared_payload, "draft10", draft10, 1, 1);

// ── 16-bit Length ──────────────────────────────────────────

declared_length_gate!(draft11_reads_its_whole_declared_payload, "draft11", draft11, 2, 1);
declared_length_gate!(draft12_reads_its_whole_declared_payload, "draft12", draft12, 2, 1);
declared_length_gate!(draft13_reads_its_whole_declared_payload, "draft13", draft13, 2, 1);
declared_length_gate!(draft14_reads_its_whole_declared_payload, "draft14", draft14, 2, 1);
declared_length_gate!(draft15_reads_its_whole_declared_payload, "draft15", draft15, 2, 1);
declared_length_gate!(draft16_reads_its_whole_declared_payload, "draft16", draft16, 2, 1);
declared_length_gate!(
    draft17_reads_its_whole_declared_payload,
    "draft17",
    draft17,
    2, 1,
    timeout: vi(0),
);
declared_length_gate!(
    draft18_reads_its_whole_declared_payload,
    "draft18",
    draft18,
    2, 2,
    // Draft-18 gives GOAWAY a genuinely optional trailing Request ID, read
    // only when bytes remain. Leaving it out would let the spare byte below be
    // read as that field, and the frame would be well-formed rather than
    // over-long. Filling it in is what makes the spare byte unread.
    timeout: vi(0),
    request_id: Some(vi(7)),
);
declared_length_gate!(
    draft19_reads_its_whole_declared_payload,
    "draft19",
    draft19,
    2, 1,
    timeout: vi(0),
);

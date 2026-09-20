//! One value rewritten inside a frame this codec wrote.
//!
//! Several files here drive a decode rule by handing the decoder a frame whose
//! single wrong value is the rule's subject. The frame cannot come straight
//! from the encoder with the wrong value passed in, for a reason worth stating:
//! the encoder refuses every value the decoder refuses. A value that is not the
//! serialization its Type defines is one the receiver must close the session
//! over, so writing it is not a way to send it, and the tests that read the rule
//! from the receiver's side cannot ask the sender to produce their fixture.
//!
//! So the frame is written around a value the encoder will write, and the value
//! alone is rewritten afterwards. Everything else is still the encoder's: the
//! message type, every field ahead of the parameters, the parameter count, the
//! parameter type, and — where the two values are the same length — every
//! length in the frame as well. Where the lengths differ, exactly two move, the
//! value's own and the message's declared Length, and both are recomputed here
//! rather than copied from anywhere.
//!
//! Every draft from 11 to 20 frames a control message the same way: a type as a
//! varint, a 16-bit big-endian Length, then the body. That is what makes one
//! function enough for all ten.
//!
//! The value has to be the last thing in the frame, which for a parameter means
//! the last parameter of a message whose parameters come last. That is asserted
//! rather than assumed — a frame whose tail is not the value it was told to
//! find fails here rather than testing something else quietly.

#![allow(dead_code)]

use moqtap_codec::varint::VarInt;

/// The bytes this codec writes for `value` as a varint.
fn varint_bytes(value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    VarInt::from_u64(value).expect("fixture value fits a varint").encode(&mut out);
    out
}

/// A length-prefixed value, as an odd-typed parameter carries it.
fn length_prefixed(value: &[u8]) -> Vec<u8> {
    assert!(
        value.len() < 64,
        "a length under 64 is one byte in every varint profile these drafts use, \
         which is what lets this run alongside the encoder's own; {} is not",
        value.len(),
    );
    let mut out = varint_bytes(value.len() as u64);
    out.extend_from_slice(value);
    out
}

/// `frame` with its trailing length-prefixed value replaced by `bad`.
///
/// Both the value and its length prefix are rewritten, so `bad` need not be the
/// same length as `good`.
pub fn with_length_prefixed_value(frame: &[u8], good: &[u8], bad: &[u8]) -> Vec<u8> {
    replace_tail(frame, &length_prefixed(good), &length_prefixed(bad))
}

/// `frame` with its trailing bare varint value replaced by `bad`.
///
/// The shape an even-typed parameter carries: no length ahead of the value, so
/// the only length that can move is the message's.
pub fn with_varint_value(frame: &[u8], good: u64, bad: u64) -> Vec<u8> {
    replace_tail(frame, &varint_bytes(good), &varint_bytes(bad))
}

/// The number of bytes in a varint that begins with `first`.
///
/// The two most significant bits carry the length, which is the one part of the
/// encoding every profile in this codec spells the same way.
fn varint_len(first: u8) -> usize {
    1usize << (first >> 6)
}

fn replace_tail(frame: &[u8], good: &[u8], bad: &[u8]) -> Vec<u8> {
    let body = varint_len(frame[0]) + 2;
    let declared = u16::from_be_bytes([frame[body - 2], frame[body - 1]]) as usize;
    assert_eq!(
        declared,
        frame.len() - body,
        "the frame handed here is not one this codec wrote: it declares {declared} bytes \
         of body and carries {}",
        frame.len() - body,
    );
    assert!(
        frame.ends_with(good),
        "the value to rewrite must be the last thing in the frame; {good:?} is not the \
         tail of {frame:?}",
    );

    let mut out = frame[..frame.len() - good.len()].to_vec();
    out.extend_from_slice(bad);
    let length = u16::try_from(out.len() - body).expect("the rewritten body fits the Length field");
    out[body - 2..body].copy_from_slice(&length.to_be_bytes());
    out
}

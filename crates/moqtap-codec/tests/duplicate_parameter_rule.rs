//! One message may not name the same Parameter Type twice.
//!
//! Every draft says it, and the wording only grows a carve-out: "Senders MUST
//! NOT repeat the same parameter type in a message. Receivers SHOULD check that
//! there are no duplicate parameters and close the session as a 'Protocol
//! Violation' if found" on drafts 07 through 10, with "unless the parameter
//! definition explicitly allows multiple instances of that type to be sent in a
//! single message" added from draft-11 on.
//!
//! A duplicate that goes unchecked matters because nothing downstream agrees on
//! which copy wins: code that scans a parameter list for a key takes whichever
//! it meets first, so one frame carrying two values for one type is read two
//! ways by two conforming implementations. That is why the sender's half is a
//! MUST NOT rather than advice.
//!
//! # Which drafts hold an exemption
//!
//! From draft-11 on the carve-out is not hypothetical. AUTHORIZATION TOKEN is
//! the type whose own definition takes it up — "The AUTHORIZATION TOKEN
//! parameter MAY be repeated within a message" on drafts 11 through 14, which
//! drafts 15 through 19 qualify with "as long as the combination of Token Type
//! and Token Value are unique after resolving any aliases" — and it is exempt
//! on every draft from 11 through 19. It is numbered 0x01 on draft-11 and 0x03
//! on drafts 12 through 19.
//!
//! Drafts 07 through 10 state neither the carve-out nor the sentence that
//! accompanies it from draft-11 on, "Receivers MUST allow duplicates of unknown
//! parameters". On those four the rule really is symmetric: no type may be
//! repeated and there is no exemption to test. Their checks below say exactly
//! that, and are right to.
//!
//! # What the checks below do not reach
//!
//! Only the draft-17, draft-18 and draft-19 modules exercise the exemption
//! directly. The drafts 11 through 16 modules build their repeats out of
//! `FIRST`, which is 0x02 — DELIVERY TIMEOUT, a type each of those drafts names
//! and none of them permits repeating. So those modules assert that a
//! non-repeatable type may not be repeated, which is true, and never put the
//! question the carve-out raises.
//!
//! This is written down rather than left implicit because the file was green
//! and wrong at the same time: the drafts 11 through 13 checks passed while
//! this docstring claimed no draft below 17 had an exemption at all, and their
//! passing was no evidence either way. A later edit that reads that green as
//! coverage of the carve-out would put the same gap back.
//!
//! The failure messages recorded below are draft-09's. Every draft fails the
//! same way; the frames differ because the field lists in front of the
//! parameters are not the same on any two of them.

#![allow(clippy::items_after_test_module)]

use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::varint::VarInt;

fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).unwrap()
}

/// The first of the two parameter types the fixtures carry.
const FIRST: u64 = 0x02;
/// The second. Chosen so that the byte it (or its delta) occupies appears
/// exactly once in an encoded frame and can be found again by value.
const SECOND: u64 = 0x32;

/// A well-formed Token structure carrying `payload`.
///
/// The AUTHORIZATION TOKEN parameter's value is a Token, not opaque bytes: an
/// Alias Type followed by the fields that Alias Type promises. USE_VALUE (0x3)
/// is the shortest complete form - no Alias, a Token Type and the value - and
/// Token Type 0 is the one the drafts reserve for a meaning the two peers settle
/// out of band, so a fixture using it commits to nothing. Both integers are
/// below 0x40 and take one byte under either variable-length integer encoding,
/// which is what lets one helper serve every draft here.
///
/// Arbitrary bytes cannot stand in for a token. A value of this type that does
/// not decode as a Token is the case the drafts require a close over, so a
/// fixture built from arbitrary bytes would be testing the refusal rather than
/// the rule beside it.
#[cfg(any(feature = "draft17", feature = "draft18", feature = "draft19"))]
fn token_value(payload: &[u8]) -> Vec<u8> {
    let mut value = vec![0x03, 0x00];
    value.extend_from_slice(payload);
    value
}

fn param(key: u64, value: u64) -> KeyValuePair {
    KeyValuePair { key: varint(key), value: KvpValue::Varint(varint(value)) }
}

#[cfg(feature = "draft07")]
mod draft07 {
    use super::{param, varint, FIRST, SECOND};
    use moqtap_codec::draft07::message::*;
    use moqtap_codec::kvp::KeyValuePair;
    #[allow(unused_imports)]
    use moqtap_codec::kvp::KvpValue;
    #[allow(unused_imports)]
    use moqtap_codec::types::*;

    fn subscribe(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            subscribe_id: varint(1),
            track_alias: varint(4),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            subscriber_priority: 5,
            group_order: GroupOrder::Ascending,
            filter_type: FilterType::LargestObject,
            start_location: None,
            end_group: None,
            end_object: None,
            parameters,
        })
    }

    fn encode(message: &ControlMessage) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message.encode(&mut buf)?;
        Ok(buf)
    }

    /// Turn the second parameter of an encoded frame into a repeat of the
    /// first, by moving the one byte that names it.
    ///
    /// The frame is one this codec built with two different types, so
    /// everything around that byte is exactly what the encoder would have
    /// written. The byte is asserted unique before it is moved, so a fixture
    /// whose other fields happened to collide with it would fail here rather
    /// than quietly patch the wrong place.
    fn repeat_the_first_type(mut buf: Vec<u8>) -> Vec<u8> {
        let on_wire = SECOND;
        let repeated = FIRST;
        assert_eq!(
            buf.iter().filter(|b| u64::from(**b) == on_wire).count(),
            1,
            "the byte naming the second parameter must be the only one of its value",
        );
        let at = buf.iter().position(|b| u64::from(*b) == on_wire).expect("it is in the frame");
        buf[at] = u8::try_from(repeated).unwrap();
        buf
    }

    /// A repeated Parameter Type has no encoding.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// one message cannot state a type twice:
    /// Ok([3, 18, 1, 4, 1, 2, 110, 115, 1, 116, 5, 1, 2, 2, 2, 1, 11, 2, 1, 12])
    /// ```
    #[test]
    fn a_message_repeating_a_parameter_type_never_reaches_the_wire() {
        let result = encode(&subscribe(vec![param(FIRST, 11), param(FIRST, 12)]));
        assert!(result.is_err(), "one message cannot state a type twice: {result:?}");
    }

    /// And one that arrives anyway is refused rather than carried inwards.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a repeated type is not two parameters: Ok(Subscribe(Subscribe {
    /// subscribe_id: VarInt(1), ..., parameters: [KeyValuePair { key: VarInt(2),
    /// value: Bytes([11]) }, KeyValuePair { key: VarInt(2), value: Bytes([12]) }] }))
    /// ```
    #[test]
    fn a_message_repeating_a_parameter_type_is_refused_on_decode() {
        let buf = encode(&subscribe(vec![param(FIRST, 11), param(SECOND, 12)]))
            .expect("two different types are a legal list");
        let repeated = repeat_the_first_type(buf);

        let decoded = ControlMessage::decode(&mut &repeated[..]);
        assert!(decoded.is_err(), "a repeated type is not two parameters: {decoded:?}");
    }

    /// Two different types, and an empty list, are both carried. Without this
    /// the gates above would pass on an encoder that refused every parameter.
    #[test]
    fn a_list_that_names_each_type_once_is_carried() {
        for parameters in
            [vec![], vec![param(FIRST, 11)], vec![param(FIRST, 11), param(SECOND, 12)]]
        {
            let buf = encode(&subscribe(parameters.clone()))
                .unwrap_or_else(|e| panic!("{} distinct types is a list: {e:?}", parameters.len()));
            let decoded = ControlMessage::decode(&mut &buf[..]);
            assert!(decoded.is_ok(), "what this codec wrote it must read: {decoded:?}");
        }
    }
}

#[cfg(feature = "draft08")]
mod draft08 {
    use super::{param, varint, FIRST, SECOND};
    use moqtap_codec::draft08::message::*;
    use moqtap_codec::kvp::KeyValuePair;
    #[allow(unused_imports)]
    use moqtap_codec::kvp::KvpValue;
    #[allow(unused_imports)]
    use moqtap_codec::types::*;

    fn subscribe(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            subscribe_id: varint(1),
            track_alias: varint(4),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            subscriber_priority: 5,
            group_order: GroupOrder::Ascending,
            filter_type: FilterType::LargestObject,
            start_location: None,
            end_group: None,
            parameters,
        })
    }

    fn encode(message: &ControlMessage) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message.encode(&mut buf)?;
        Ok(buf)
    }

    /// Turn the second parameter of an encoded frame into a repeat of the
    /// first, by moving the one byte that names it.
    ///
    /// The frame is one this codec built with two different types, so
    /// everything around that byte is exactly what the encoder would have
    /// written. The byte is asserted unique before it is moved, so a fixture
    /// whose other fields happened to collide with it would fail here rather
    /// than quietly patch the wrong place.
    fn repeat_the_first_type(mut buf: Vec<u8>) -> Vec<u8> {
        let on_wire = SECOND;
        let repeated = FIRST;
        assert_eq!(
            buf.iter().filter(|b| u64::from(**b) == on_wire).count(),
            1,
            "the byte naming the second parameter must be the only one of its value",
        );
        let at = buf.iter().position(|b| u64::from(*b) == on_wire).expect("it is in the frame");
        buf[at] = u8::try_from(repeated).unwrap();
        buf
    }

    /// A repeated Parameter Type has no encoding.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// one message cannot state a type twice:
    /// Ok([3, 18, 1, 4, 1, 2, 110, 115, 1, 116, 5, 1, 2, 2, 2, 1, 11, 2, 1, 12])
    /// ```
    #[test]
    fn a_message_repeating_a_parameter_type_never_reaches_the_wire() {
        let result = encode(&subscribe(vec![param(FIRST, 11), param(FIRST, 12)]));
        assert!(result.is_err(), "one message cannot state a type twice: {result:?}");
    }

    /// And one that arrives anyway is refused rather than carried inwards.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a repeated type is not two parameters: Ok(Subscribe(Subscribe {
    /// subscribe_id: VarInt(1), ..., parameters: [KeyValuePair { key: VarInt(2),
    /// value: Bytes([11]) }, KeyValuePair { key: VarInt(2), value: Bytes([12]) }] }))
    /// ```
    #[test]
    fn a_message_repeating_a_parameter_type_is_refused_on_decode() {
        let buf = encode(&subscribe(vec![param(FIRST, 11), param(SECOND, 12)]))
            .expect("two different types are a legal list");
        let repeated = repeat_the_first_type(buf);

        let decoded = ControlMessage::decode(&mut &repeated[..]);
        assert!(decoded.is_err(), "a repeated type is not two parameters: {decoded:?}");
    }

    /// Two different types, and an empty list, are both carried. Without this
    /// the gates above would pass on an encoder that refused every parameter.
    #[test]
    fn a_list_that_names_each_type_once_is_carried() {
        for parameters in
            [vec![], vec![param(FIRST, 11)], vec![param(FIRST, 11), param(SECOND, 12)]]
        {
            let buf = encode(&subscribe(parameters.clone()))
                .unwrap_or_else(|e| panic!("{} distinct types is a list: {e:?}", parameters.len()));
            let decoded = ControlMessage::decode(&mut &buf[..]);
            assert!(decoded.is_ok(), "what this codec wrote it must read: {decoded:?}");
        }
    }
}

#[cfg(feature = "draft09")]
mod draft09 {
    use super::{param, varint, FIRST, SECOND};
    use moqtap_codec::draft09::message::*;
    use moqtap_codec::kvp::KeyValuePair;
    #[allow(unused_imports)]
    use moqtap_codec::kvp::KvpValue;
    #[allow(unused_imports)]
    use moqtap_codec::types::*;

    fn subscribe(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            subscribe_id: varint(1),
            track_alias: varint(4),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            subscriber_priority: 5,
            group_order: GroupOrder::Ascending,
            filter_type: FilterType::LargestObject,
            start_location: None,
            end_group: None,
            parameters,
        })
    }

    fn encode(message: &ControlMessage) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message.encode(&mut buf)?;
        Ok(buf)
    }

    /// Turn the second parameter of an encoded frame into a repeat of the
    /// first, by moving the one byte that names it.
    ///
    /// The frame is one this codec built with two different types, so
    /// everything around that byte is exactly what the encoder would have
    /// written. The byte is asserted unique before it is moved, so a fixture
    /// whose other fields happened to collide with it would fail here rather
    /// than quietly patch the wrong place.
    fn repeat_the_first_type(mut buf: Vec<u8>) -> Vec<u8> {
        let on_wire = SECOND;
        let repeated = FIRST;
        assert_eq!(
            buf.iter().filter(|b| u64::from(**b) == on_wire).count(),
            1,
            "the byte naming the second parameter must be the only one of its value",
        );
        let at = buf.iter().position(|b| u64::from(*b) == on_wire).expect("it is in the frame");
        buf[at] = u8::try_from(repeated).unwrap();
        buf
    }

    /// A repeated Parameter Type has no encoding.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// one message cannot state a type twice:
    /// Ok([3, 18, 1, 4, 1, 2, 110, 115, 1, 116, 5, 1, 2, 2, 2, 1, 11, 2, 1, 12])
    /// ```
    #[test]
    fn a_message_repeating_a_parameter_type_never_reaches_the_wire() {
        let result = encode(&subscribe(vec![param(FIRST, 11), param(FIRST, 12)]));
        assert!(result.is_err(), "one message cannot state a type twice: {result:?}");
    }

    /// And one that arrives anyway is refused rather than carried inwards.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a repeated type is not two parameters: Ok(Subscribe(Subscribe {
    /// subscribe_id: VarInt(1), ..., parameters: [KeyValuePair { key: VarInt(2),
    /// value: Bytes([11]) }, KeyValuePair { key: VarInt(2), value: Bytes([12]) }] }))
    /// ```
    #[test]
    fn a_message_repeating_a_parameter_type_is_refused_on_decode() {
        let buf = encode(&subscribe(vec![param(FIRST, 11), param(SECOND, 12)]))
            .expect("two different types are a legal list");
        let repeated = repeat_the_first_type(buf);

        let decoded = ControlMessage::decode(&mut &repeated[..]);
        assert!(decoded.is_err(), "a repeated type is not two parameters: {decoded:?}");
    }

    /// Two different types, and an empty list, are both carried. Without this
    /// the gates above would pass on an encoder that refused every parameter.
    #[test]
    fn a_list_that_names_each_type_once_is_carried() {
        for parameters in
            [vec![], vec![param(FIRST, 11)], vec![param(FIRST, 11), param(SECOND, 12)]]
        {
            let buf = encode(&subscribe(parameters.clone()))
                .unwrap_or_else(|e| panic!("{} distinct types is a list: {e:?}", parameters.len()));
            let decoded = ControlMessage::decode(&mut &buf[..]);
            assert!(decoded.is_ok(), "what this codec wrote it must read: {decoded:?}");
        }
    }
}

#[cfg(feature = "draft10")]
mod draft10 {
    use super::{param, varint, FIRST, SECOND};
    use moqtap_codec::draft10::message::*;
    use moqtap_codec::kvp::KeyValuePair;
    #[allow(unused_imports)]
    use moqtap_codec::kvp::KvpValue;
    #[allow(unused_imports)]
    use moqtap_codec::types::*;

    fn subscribe(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            subscribe_id: varint(1),
            track_alias: varint(4),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            subscriber_priority: 5,
            group_order: GroupOrder::Ascending,
            filter_type: FilterType::LargestObject,
            start_location: None,
            end_group: None,
            parameters,
        })
    }

    fn encode(message: &ControlMessage) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message.encode(&mut buf)?;
        Ok(buf)
    }

    /// Turn the second parameter of an encoded frame into a repeat of the
    /// first, by moving the one byte that names it.
    ///
    /// The frame is one this codec built with two different types, so
    /// everything around that byte is exactly what the encoder would have
    /// written. The byte is asserted unique before it is moved, so a fixture
    /// whose other fields happened to collide with it would fail here rather
    /// than quietly patch the wrong place.
    fn repeat_the_first_type(mut buf: Vec<u8>) -> Vec<u8> {
        let on_wire = SECOND;
        let repeated = FIRST;
        assert_eq!(
            buf.iter().filter(|b| u64::from(**b) == on_wire).count(),
            1,
            "the byte naming the second parameter must be the only one of its value",
        );
        let at = buf.iter().position(|b| u64::from(*b) == on_wire).expect("it is in the frame");
        buf[at] = u8::try_from(repeated).unwrap();
        buf
    }

    /// A repeated Parameter Type has no encoding.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// one message cannot state a type twice:
    /// Ok([3, 18, 1, 4, 1, 2, 110, 115, 1, 116, 5, 1, 2, 2, 2, 1, 11, 2, 1, 12])
    /// ```
    #[test]
    fn a_message_repeating_a_parameter_type_never_reaches_the_wire() {
        let result = encode(&subscribe(vec![param(FIRST, 11), param(FIRST, 12)]));
        assert!(result.is_err(), "one message cannot state a type twice: {result:?}");
    }

    /// And one that arrives anyway is refused rather than carried inwards.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a repeated type is not two parameters: Ok(Subscribe(Subscribe {
    /// subscribe_id: VarInt(1), ..., parameters: [KeyValuePair { key: VarInt(2),
    /// value: Bytes([11]) }, KeyValuePair { key: VarInt(2), value: Bytes([12]) }] }))
    /// ```
    #[test]
    fn a_message_repeating_a_parameter_type_is_refused_on_decode() {
        let buf = encode(&subscribe(vec![param(FIRST, 11), param(SECOND, 12)]))
            .expect("two different types are a legal list");
        let repeated = repeat_the_first_type(buf);

        let decoded = ControlMessage::decode(&mut &repeated[..]);
        assert!(decoded.is_err(), "a repeated type is not two parameters: {decoded:?}");
    }

    /// Two different types, and an empty list, are both carried. Without this
    /// the gates above would pass on an encoder that refused every parameter.
    #[test]
    fn a_list_that_names_each_type_once_is_carried() {
        for parameters in
            [vec![], vec![param(FIRST, 11)], vec![param(FIRST, 11), param(SECOND, 12)]]
        {
            let buf = encode(&subscribe(parameters.clone()))
                .unwrap_or_else(|e| panic!("{} distinct types is a list: {e:?}", parameters.len()));
            let decoded = ControlMessage::decode(&mut &buf[..]);
            assert!(decoded.is_ok(), "what this codec wrote it must read: {decoded:?}");
        }
    }
}

#[cfg(feature = "draft11")]
mod draft11 {
    use super::{param, varint, FIRST, SECOND};
    use moqtap_codec::draft11::message::*;
    use moqtap_codec::kvp::KeyValuePair;
    #[allow(unused_imports)]
    use moqtap_codec::kvp::KvpValue;
    #[allow(unused_imports)]
    use moqtap_codec::types::*;

    fn subscribe(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            request_id: varint(1),
            track_alias: varint(4),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            subscriber_priority: 5,
            group_order: GroupOrder::Ascending,
            forward: Forward::Forward,
            filter_type: varint(0x2),
            start_group: None,
            start_object: None,
            end_group: None,
            parameters,
        })
    }

    fn encode(message: &ControlMessage) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message.encode(&mut buf)?;
        Ok(buf)
    }

    /// Turn the second parameter of an encoded frame into a repeat of the
    /// first, by moving the one byte that names it.
    ///
    /// The frame is one this codec built with two different types, so
    /// everything around that byte is exactly what the encoder would have
    /// written. The byte is asserted unique before it is moved, so a fixture
    /// whose other fields happened to collide with it would fail here rather
    /// than quietly patch the wrong place.
    fn repeat_the_first_type(mut buf: Vec<u8>) -> Vec<u8> {
        let on_wire = SECOND;
        let repeated = FIRST;
        assert_eq!(
            buf.iter().filter(|b| u64::from(**b) == on_wire).count(),
            1,
            "the byte naming the second parameter must be the only one of its value",
        );
        let at = buf.iter().position(|b| u64::from(*b) == on_wire).expect("it is in the frame");
        buf[at] = u8::try_from(repeated).unwrap();
        buf
    }

    /// A repeated Parameter Type has no encoding.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// one message cannot state a type twice:
    /// Ok([3, 18, 1, 4, 1, 2, 110, 115, 1, 116, 5, 1, 2, 2, 2, 1, 11, 2, 1, 12])
    /// ```
    #[test]
    fn a_message_repeating_a_parameter_type_never_reaches_the_wire() {
        let result = encode(&subscribe(vec![param(FIRST, 11), param(FIRST, 12)]));
        assert!(result.is_err(), "one message cannot state a type twice: {result:?}");
    }

    /// And one that arrives anyway is refused rather than carried inwards.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a repeated type is not two parameters: Ok(Subscribe(Subscribe {
    /// subscribe_id: VarInt(1), ..., parameters: [KeyValuePair { key: VarInt(2),
    /// value: Bytes([11]) }, KeyValuePair { key: VarInt(2), value: Bytes([12]) }] }))
    /// ```
    #[test]
    fn a_message_repeating_a_parameter_type_is_refused_on_decode() {
        let buf = encode(&subscribe(vec![param(FIRST, 11), param(SECOND, 12)]))
            .expect("two different types are a legal list");
        let repeated = repeat_the_first_type(buf);

        let decoded = ControlMessage::decode(&mut &repeated[..]);
        assert!(decoded.is_err(), "a repeated type is not two parameters: {decoded:?}");
    }

    /// Two different types, and an empty list, are both carried. Without this
    /// the gates above would pass on an encoder that refused every parameter.
    #[test]
    fn a_list_that_names_each_type_once_is_carried() {
        for parameters in
            [vec![], vec![param(FIRST, 11)], vec![param(FIRST, 11), param(SECOND, 12)]]
        {
            let buf = encode(&subscribe(parameters.clone()))
                .unwrap_or_else(|e| panic!("{} distinct types is a list: {e:?}", parameters.len()));
            let decoded = ControlMessage::decode(&mut &buf[..]);
            assert!(decoded.is_ok(), "what this codec wrote it must read: {decoded:?}");
        }
    }
}

#[cfg(feature = "draft12")]
mod draft12 {
    use super::{param, varint, FIRST, SECOND};
    use moqtap_codec::draft12::message::*;
    use moqtap_codec::kvp::KeyValuePair;
    #[allow(unused_imports)]
    use moqtap_codec::kvp::KvpValue;
    #[allow(unused_imports)]
    use moqtap_codec::types::*;

    fn subscribe(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            request_id: varint(1),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            subscriber_priority: 5,
            group_order: GroupOrder::Ascending,
            forward: Forward::Forward,
            filter_type: varint(0x2),
            start_group: None,
            start_object: None,
            end_group: None,
            parameters,
        })
    }

    fn encode(message: &ControlMessage) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message.encode(&mut buf)?;
        Ok(buf)
    }

    /// Turn the second parameter of an encoded frame into a repeat of the
    /// first, by moving the one byte that names it.
    ///
    /// The frame is one this codec built with two different types, so
    /// everything around that byte is exactly what the encoder would have
    /// written. The byte is asserted unique before it is moved, so a fixture
    /// whose other fields happened to collide with it would fail here rather
    /// than quietly patch the wrong place.
    fn repeat_the_first_type(mut buf: Vec<u8>) -> Vec<u8> {
        let on_wire = SECOND;
        let repeated = FIRST;
        assert_eq!(
            buf.iter().filter(|b| u64::from(**b) == on_wire).count(),
            1,
            "the byte naming the second parameter must be the only one of its value",
        );
        let at = buf.iter().position(|b| u64::from(*b) == on_wire).expect("it is in the frame");
        buf[at] = u8::try_from(repeated).unwrap();
        buf
    }

    /// A repeated Parameter Type has no encoding.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// one message cannot state a type twice:
    /// Ok([3, 18, 1, 4, 1, 2, 110, 115, 1, 116, 5, 1, 2, 2, 2, 1, 11, 2, 1, 12])
    /// ```
    #[test]
    fn a_message_repeating_a_parameter_type_never_reaches_the_wire() {
        let result = encode(&subscribe(vec![param(FIRST, 11), param(FIRST, 12)]));
        assert!(result.is_err(), "one message cannot state a type twice: {result:?}");
    }

    /// And one that arrives anyway is refused rather than carried inwards.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a repeated type is not two parameters: Ok(Subscribe(Subscribe {
    /// subscribe_id: VarInt(1), ..., parameters: [KeyValuePair { key: VarInt(2),
    /// value: Bytes([11]) }, KeyValuePair { key: VarInt(2), value: Bytes([12]) }] }))
    /// ```
    #[test]
    fn a_message_repeating_a_parameter_type_is_refused_on_decode() {
        let buf = encode(&subscribe(vec![param(FIRST, 11), param(SECOND, 12)]))
            .expect("two different types are a legal list");
        let repeated = repeat_the_first_type(buf);

        let decoded = ControlMessage::decode(&mut &repeated[..]);
        assert!(decoded.is_err(), "a repeated type is not two parameters: {decoded:?}");
    }

    /// Two different types, and an empty list, are both carried. Without this
    /// the gates above would pass on an encoder that refused every parameter.
    #[test]
    fn a_list_that_names_each_type_once_is_carried() {
        for parameters in
            [vec![], vec![param(FIRST, 11)], vec![param(FIRST, 11), param(SECOND, 12)]]
        {
            let buf = encode(&subscribe(parameters.clone()))
                .unwrap_or_else(|e| panic!("{} distinct types is a list: {e:?}", parameters.len()));
            let decoded = ControlMessage::decode(&mut &buf[..]);
            assert!(decoded.is_ok(), "what this codec wrote it must read: {decoded:?}");
        }
    }
}

#[cfg(feature = "draft13")]
mod draft13 {
    use super::{param, varint, FIRST, SECOND};
    use moqtap_codec::draft13::message::*;
    use moqtap_codec::kvp::KeyValuePair;
    #[allow(unused_imports)]
    use moqtap_codec::kvp::KvpValue;
    #[allow(unused_imports)]
    use moqtap_codec::types::*;

    fn subscribe(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            request_id: varint(1),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            subscriber_priority: 5,
            group_order: GroupOrder::Ascending,
            forward: Forward::Forward,
            filter_type: FilterType::LargestObject,
            start_group: None,
            start_object: None,
            end_group: None,
            parameters,
        })
    }

    fn encode(message: &ControlMessage) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message.encode(&mut buf)?;
        Ok(buf)
    }

    /// Turn the second parameter of an encoded frame into a repeat of the
    /// first, by moving the one byte that names it.
    ///
    /// The frame is one this codec built with two different types, so
    /// everything around that byte is exactly what the encoder would have
    /// written. The byte is asserted unique before it is moved, so a fixture
    /// whose other fields happened to collide with it would fail here rather
    /// than quietly patch the wrong place.
    fn repeat_the_first_type(mut buf: Vec<u8>) -> Vec<u8> {
        let on_wire = SECOND;
        let repeated = FIRST;
        assert_eq!(
            buf.iter().filter(|b| u64::from(**b) == on_wire).count(),
            1,
            "the byte naming the second parameter must be the only one of its value",
        );
        let at = buf.iter().position(|b| u64::from(*b) == on_wire).expect("it is in the frame");
        buf[at] = u8::try_from(repeated).unwrap();
        buf
    }

    /// A repeated Parameter Type has no encoding.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// one message cannot state a type twice:
    /// Ok([3, 18, 1, 4, 1, 2, 110, 115, 1, 116, 5, 1, 2, 2, 2, 1, 11, 2, 1, 12])
    /// ```
    #[test]
    fn a_message_repeating_a_parameter_type_never_reaches_the_wire() {
        let result = encode(&subscribe(vec![param(FIRST, 11), param(FIRST, 12)]));
        assert!(result.is_err(), "one message cannot state a type twice: {result:?}");
    }

    /// And one that arrives anyway is refused rather than carried inwards.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a repeated type is not two parameters: Ok(Subscribe(Subscribe {
    /// subscribe_id: VarInt(1), ..., parameters: [KeyValuePair { key: VarInt(2),
    /// value: Bytes([11]) }, KeyValuePair { key: VarInt(2), value: Bytes([12]) }] }))
    /// ```
    #[test]
    fn a_message_repeating_a_parameter_type_is_refused_on_decode() {
        let buf = encode(&subscribe(vec![param(FIRST, 11), param(SECOND, 12)]))
            .expect("two different types are a legal list");
        let repeated = repeat_the_first_type(buf);

        let decoded = ControlMessage::decode(&mut &repeated[..]);
        assert!(decoded.is_err(), "a repeated type is not two parameters: {decoded:?}");
    }

    /// Two different types, and an empty list, are both carried. Without this
    /// the gates above would pass on an encoder that refused every parameter.
    #[test]
    fn a_list_that_names_each_type_once_is_carried() {
        for parameters in
            [vec![], vec![param(FIRST, 11)], vec![param(FIRST, 11), param(SECOND, 12)]]
        {
            let buf = encode(&subscribe(parameters.clone()))
                .unwrap_or_else(|e| panic!("{} distinct types is a list: {e:?}", parameters.len()));
            let decoded = ControlMessage::decode(&mut &buf[..]);
            assert!(decoded.is_ok(), "what this codec wrote it must read: {decoded:?}");
        }
    }
}

#[cfg(feature = "draft14")]
mod draft14 {
    use super::{param, varint, FIRST, SECOND};
    use moqtap_codec::draft14::message::*;
    use moqtap_codec::kvp::KeyValuePair;
    #[allow(unused_imports)]
    use moqtap_codec::kvp::KvpValue;
    #[allow(unused_imports)]
    use moqtap_codec::types::*;

    fn subscribe(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            request_id: varint(1),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            subscriber_priority: 5,
            group_order: GroupOrder::Ascending,
            forward: Forward::Forward,
            filter_type: FilterType::LargestObject,
            start_location: None,
            end_group: None,
            parameters,
        })
    }

    fn encode(message: &ControlMessage) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message.encode(&mut buf)?;
        Ok(buf)
    }

    /// Turn the second parameter of an encoded frame into a repeat of the
    /// first, by moving the one byte that names it.
    ///
    /// The frame is one this codec built with two different types, so
    /// everything around that byte is exactly what the encoder would have
    /// written. The byte is asserted unique before it is moved, so a fixture
    /// whose other fields happened to collide with it would fail here rather
    /// than quietly patch the wrong place.
    fn repeat_the_first_type(mut buf: Vec<u8>) -> Vec<u8> {
        let on_wire = SECOND;
        let repeated = FIRST;
        assert_eq!(
            buf.iter().filter(|b| u64::from(**b) == on_wire).count(),
            1,
            "the byte naming the second parameter must be the only one of its value",
        );
        let at = buf.iter().position(|b| u64::from(*b) == on_wire).expect("it is in the frame");
        buf[at] = u8::try_from(repeated).unwrap();
        buf
    }

    /// A repeated Parameter Type has no encoding.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// one message cannot state a type twice:
    /// Ok([3, 18, 1, 4, 1, 2, 110, 115, 1, 116, 5, 1, 2, 2, 2, 1, 11, 2, 1, 12])
    /// ```
    #[test]
    fn a_message_repeating_a_parameter_type_never_reaches_the_wire() {
        let result = encode(&subscribe(vec![param(FIRST, 11), param(FIRST, 12)]));
        assert!(result.is_err(), "one message cannot state a type twice: {result:?}");
    }

    /// And one that arrives anyway is refused rather than carried inwards.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a repeated type is not two parameters: Ok(Subscribe(Subscribe {
    /// subscribe_id: VarInt(1), ..., parameters: [KeyValuePair { key: VarInt(2),
    /// value: Bytes([11]) }, KeyValuePair { key: VarInt(2), value: Bytes([12]) }] }))
    /// ```
    #[test]
    fn a_message_repeating_a_parameter_type_is_refused_on_decode() {
        let buf = encode(&subscribe(vec![param(FIRST, 11), param(SECOND, 12)]))
            .expect("two different types are a legal list");
        let repeated = repeat_the_first_type(buf);

        let decoded = ControlMessage::decode(&mut &repeated[..]);
        assert!(decoded.is_err(), "a repeated type is not two parameters: {decoded:?}");
    }

    /// Two different types, and an empty list, are both carried. Without this
    /// the gates above would pass on an encoder that refused every parameter.
    #[test]
    fn a_list_that_names_each_type_once_is_carried() {
        for parameters in
            [vec![], vec![param(FIRST, 11)], vec![param(FIRST, 11), param(SECOND, 12)]]
        {
            let buf = encode(&subscribe(parameters.clone()))
                .unwrap_or_else(|e| panic!("{} distinct types is a list: {e:?}", parameters.len()));
            let decoded = ControlMessage::decode(&mut &buf[..]);
            assert!(decoded.is_ok(), "what this codec wrote it must read: {decoded:?}");
        }
    }
}

#[cfg(feature = "draft15")]
mod draft15 {
    use super::{param, varint, FIRST, SECOND};
    use moqtap_codec::draft15::message::*;
    use moqtap_codec::kvp::KeyValuePair;
    #[allow(unused_imports)]
    use moqtap_codec::kvp::KvpValue;
    #[allow(unused_imports)]
    use moqtap_codec::types::*;

    fn subscribe(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            request_id: varint(1),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            parameters,
        })
    }

    fn encode(message: &ControlMessage) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message.encode(&mut buf)?;
        Ok(buf)
    }

    /// Turn the second parameter of an encoded frame into a repeat of the
    /// first, by moving the one byte that names it.
    ///
    /// The frame is one this codec built with two different types, so
    /// everything around that byte is exactly what the encoder would have
    /// written. The byte is asserted unique before it is moved, so a fixture
    /// whose other fields happened to collide with it would fail here rather
    /// than quietly patch the wrong place.
    fn repeat_the_first_type(mut buf: Vec<u8>) -> Vec<u8> {
        let on_wire = SECOND;
        let repeated = FIRST;
        assert_eq!(
            buf.iter().filter(|b| u64::from(**b) == on_wire).count(),
            1,
            "the byte naming the second parameter must be the only one of its value",
        );
        let at = buf.iter().position(|b| u64::from(*b) == on_wire).expect("it is in the frame");
        buf[at] = u8::try_from(repeated).unwrap();
        buf
    }

    /// A repeated Parameter Type has no encoding.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// one message cannot state a type twice:
    /// Ok([3, 18, 1, 4, 1, 2, 110, 115, 1, 116, 5, 1, 2, 2, 2, 1, 11, 2, 1, 12])
    /// ```
    #[test]
    fn a_message_repeating_a_parameter_type_never_reaches_the_wire() {
        let result = encode(&subscribe(vec![param(FIRST, 11), param(FIRST, 12)]));
        assert!(result.is_err(), "one message cannot state a type twice: {result:?}");
    }

    /// And one that arrives anyway is refused rather than carried inwards.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a repeated type is not two parameters: Ok(Subscribe(Subscribe {
    /// subscribe_id: VarInt(1), ..., parameters: [KeyValuePair { key: VarInt(2),
    /// value: Bytes([11]) }, KeyValuePair { key: VarInt(2), value: Bytes([12]) }] }))
    /// ```
    #[test]
    fn a_message_repeating_a_parameter_type_is_refused_on_decode() {
        let buf = encode(&subscribe(vec![param(FIRST, 11), param(SECOND, 12)]))
            .expect("two different types are a legal list");
        let repeated = repeat_the_first_type(buf);

        let decoded = ControlMessage::decode(&mut &repeated[..]);
        assert!(decoded.is_err(), "a repeated type is not two parameters: {decoded:?}");
    }

    /// Two different types, and an empty list, are both carried. Without this
    /// the gates above would pass on an encoder that refused every parameter.
    #[test]
    fn a_list_that_names_each_type_once_is_carried() {
        for parameters in
            [vec![], vec![param(FIRST, 11)], vec![param(FIRST, 11), param(SECOND, 12)]]
        {
            let buf = encode(&subscribe(parameters.clone()))
                .unwrap_or_else(|e| panic!("{} distinct types is a list: {e:?}", parameters.len()));
            let decoded = ControlMessage::decode(&mut &buf[..]);
            assert!(decoded.is_ok(), "what this codec wrote it must read: {decoded:?}");
        }
    }
}

#[cfg(feature = "draft16")]
mod draft16 {
    use super::{param, varint, FIRST, SECOND};
    use moqtap_codec::draft16::message::*;
    use moqtap_codec::kvp::KeyValuePair;
    #[allow(unused_imports)]
    use moqtap_codec::kvp::KvpValue;
    #[allow(unused_imports)]
    use moqtap_codec::types::*;

    fn subscribe(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            request_id: varint(1),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            parameters,
        })
    }

    fn encode(message: &ControlMessage) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message.encode(&mut buf)?;
        Ok(buf)
    }

    /// Turn the second parameter of an encoded frame into a repeat of the
    /// first, by moving the one byte that names it.
    ///
    /// The frame is one this codec built with two different types, so
    /// everything around that byte is exactly what the encoder would have
    /// written. The byte is asserted unique before it is moved, so a fixture
    /// whose other fields happened to collide with it would fail here rather
    /// than quietly patch the wrong place.
    fn repeat_the_first_type(mut buf: Vec<u8>) -> Vec<u8> {
        // Draft-16 writes a parameter list's Types as deltas from the previous
        // one, so the byte naming the second parameter holds the gap between
        // the two types and not the type itself, and a repeat is spelled as a
        // gap of zero. Drafts 07 through 15 write each Type outright, which is
        // why their copies of this helper look for `SECOND` and write `FIRST`.
        let on_wire = SECOND - FIRST;
        let repeated = 0;
        assert_eq!(
            buf.iter().filter(|b| u64::from(**b) == on_wire).count(),
            1,
            "the byte naming the second parameter must be the only one of its value",
        );
        let at = buf.iter().position(|b| u64::from(*b) == on_wire).expect("it is in the frame");
        buf[at] = u8::try_from(repeated).unwrap();
        buf
    }

    /// A repeated Parameter Type has no encoding.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// one message cannot state a type twice:
    /// Ok([3, 18, 1, 4, 1, 2, 110, 115, 1, 116, 5, 1, 2, 2, 2, 1, 11, 2, 1, 12])
    /// ```
    #[test]
    fn a_message_repeating_a_parameter_type_never_reaches_the_wire() {
        let result = encode(&subscribe(vec![param(FIRST, 11), param(FIRST, 12)]));
        assert!(result.is_err(), "one message cannot state a type twice: {result:?}");
    }

    /// And one that arrives anyway is refused rather than carried inwards.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a repeated type is not two parameters: Ok(Subscribe(Subscribe {
    /// subscribe_id: VarInt(1), ..., parameters: [KeyValuePair { key: VarInt(2),
    /// value: Bytes([11]) }, KeyValuePair { key: VarInt(2), value: Bytes([12]) }] }))
    /// ```
    #[test]
    fn a_message_repeating_a_parameter_type_is_refused_on_decode() {
        let buf = encode(&subscribe(vec![param(FIRST, 11), param(SECOND, 12)]))
            .expect("two different types are a legal list");
        let repeated = repeat_the_first_type(buf);

        let decoded = ControlMessage::decode(&mut &repeated[..]);
        assert!(decoded.is_err(), "a repeated type is not two parameters: {decoded:?}");
    }

    /// Two different types, and an empty list, are both carried. Without this
    /// the gates above would pass on an encoder that refused every parameter.
    #[test]
    fn a_list_that_names_each_type_once_is_carried() {
        for parameters in
            [vec![], vec![param(FIRST, 11)], vec![param(FIRST, 11), param(SECOND, 12)]]
        {
            let buf = encode(&subscribe(parameters.clone()))
                .unwrap_or_else(|e| panic!("{} distinct types is a list: {e:?}", parameters.len()));
            let decoded = ControlMessage::decode(&mut &buf[..]);
            assert!(decoded.is_ok(), "what this codec wrote it must read: {decoded:?}");
        }
    }
}

#[cfg(feature = "draft17")]
mod draft17 {
    use super::{param, varint, FIRST, SECOND};
    use moqtap_codec::draft17::message::*;
    use moqtap_codec::kvp::KeyValuePair;
    #[allow(unused_imports)]
    use moqtap_codec::kvp::KvpValue;
    #[allow(unused_imports)]
    use moqtap_codec::types::*;

    fn subscribe(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            request_id: varint(1),
            required_request_id_delta: varint(0),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            parameters,
        })
    }

    fn encode(message: &ControlMessage) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message.encode(&mut buf)?;
        Ok(buf)
    }

    /// Turn the second parameter of an encoded frame into a repeat of the
    /// first, by moving the one byte that names it.
    ///
    /// The frame is one this codec built with two different types, so
    /// everything around that byte is exactly what the encoder would have
    /// written. The byte is asserted unique before it is moved, so a fixture
    /// whose other fields happened to collide with it would fail here rather
    /// than quietly patch the wrong place.
    fn repeat_the_first_type(mut buf: Vec<u8>) -> Vec<u8> {
        let on_wire = SECOND - FIRST;
        let repeated = 0;
        assert_eq!(
            buf.iter().filter(|b| u64::from(**b) == on_wire).count(),
            1,
            "the byte naming the second parameter must be the only one of its value",
        );
        let at = buf.iter().position(|b| u64::from(*b) == on_wire).expect("it is in the frame");
        buf[at] = u8::try_from(repeated).unwrap();
        buf
    }

    /// A repeated Parameter Type has no encoding.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// one message cannot state a type twice:
    /// Ok([3, 18, 1, 4, 1, 2, 110, 115, 1, 116, 5, 1, 2, 2, 2, 1, 11, 2, 1, 12])
    /// ```
    #[test]
    fn a_message_repeating_a_parameter_type_never_reaches_the_wire() {
        let result = encode(&subscribe(vec![param(FIRST, 11), param(FIRST, 12)]));
        assert!(result.is_err(), "one message cannot state a type twice: {result:?}");
    }

    /// And one that arrives anyway is refused rather than carried inwards.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a repeated type is not two parameters: Ok(Subscribe(Subscribe {
    /// subscribe_id: VarInt(1), ..., parameters: [KeyValuePair { key: VarInt(2),
    /// value: Bytes([11]) }, KeyValuePair { key: VarInt(2), value: Bytes([12]) }] }))
    /// ```
    #[test]
    fn a_message_repeating_a_parameter_type_is_refused_on_decode() {
        let buf = encode(&subscribe(vec![param(FIRST, 11), param(SECOND, 12)]))
            .expect("two different types are a legal list");
        let repeated = repeat_the_first_type(buf);

        let decoded = ControlMessage::decode(&mut &repeated[..]);
        assert!(decoded.is_err(), "a repeated type is not two parameters: {decoded:?}");
    }

    /// Two different types, and an empty list, are both carried. Without this
    /// the gates above would pass on an encoder that refused every parameter.
    #[test]
    fn a_list_that_names_each_type_once_is_carried() {
        for parameters in
            [vec![], vec![param(FIRST, 11)], vec![param(FIRST, 11), param(SECOND, 12)]]
        {
            let buf = encode(&subscribe(parameters.clone()))
                .unwrap_or_else(|e| panic!("{} distinct types is a list: {e:?}", parameters.len()));
            let decoded = ControlMessage::decode(&mut &buf[..]);
            assert!(decoded.is_ok(), "what this codec wrote it must read: {decoded:?}");
        }
    }

    /// The one type this draft's own definition lets a message repeat.
    ///
    /// Section 9.3.2: "The AUTHORIZATION TOKEN parameter MAY be repeated within
    /// a message as long as the combination of Token Type and Token Value are
    /// unique after resolving any aliases." A check that refused every repeat would refuse this, which is
    /// what makes the carve-out worth a gate of its own.
    ///
    /// Dropping the carve-out fails with:
    ///
    /// ```text
    /// this type is allowed more than one instance: DuplicateParameter(3)
    /// ```
    #[test]
    fn an_authorization_token_may_be_repeated() {
        let token = |value: &[u8]| KeyValuePair {
            key: varint(0x03),
            value: KvpValue::Bytes(super::token_value(value)),
        };
        let message = subscribe(vec![token(b"one"), token(b"two")]);
        let buf = encode(&message).expect("this type is allowed more than one instance");
        let decoded = ControlMessage::decode(&mut &buf[..]);
        assert_eq!(decoded.ok().as_ref(), Some(&message), "what this codec wrote it must read");
    }
}

#[cfg(feature = "draft18")]
mod draft18 {
    use super::{param, varint, FIRST, SECOND};
    use moqtap_codec::draft18::message::*;
    use moqtap_codec::kvp::KeyValuePair;
    #[allow(unused_imports)]
    use moqtap_codec::kvp::KvpValue;
    #[allow(unused_imports)]
    use moqtap_codec::types::*;

    fn subscribe(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            request_id: varint(1),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            parameters,
        })
    }

    fn encode(message: &ControlMessage) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message.encode(&mut buf)?;
        Ok(buf)
    }

    /// Turn the second parameter of an encoded frame into a repeat of the
    /// first, by moving the one byte that names it.
    ///
    /// The frame is one this codec built with two different types, so
    /// everything around that byte is exactly what the encoder would have
    /// written. The byte is asserted unique before it is moved, so a fixture
    /// whose other fields happened to collide with it would fail here rather
    /// than quietly patch the wrong place.
    fn repeat_the_first_type(mut buf: Vec<u8>) -> Vec<u8> {
        let on_wire = SECOND - FIRST;
        let repeated = 0;
        assert_eq!(
            buf.iter().filter(|b| u64::from(**b) == on_wire).count(),
            1,
            "the byte naming the second parameter must be the only one of its value",
        );
        let at = buf.iter().position(|b| u64::from(*b) == on_wire).expect("it is in the frame");
        buf[at] = u8::try_from(repeated).unwrap();
        buf
    }

    /// A repeated Parameter Type has no encoding.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// one message cannot state a type twice:
    /// Ok([3, 18, 1, 4, 1, 2, 110, 115, 1, 116, 5, 1, 2, 2, 2, 1, 11, 2, 1, 12])
    /// ```
    #[test]
    fn a_message_repeating_a_parameter_type_never_reaches_the_wire() {
        let result = encode(&subscribe(vec![param(FIRST, 11), param(FIRST, 12)]));
        assert!(result.is_err(), "one message cannot state a type twice: {result:?}");
    }

    /// And one that arrives anyway is refused rather than carried inwards.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a repeated type is not two parameters: Ok(Subscribe(Subscribe {
    /// subscribe_id: VarInt(1), ..., parameters: [KeyValuePair { key: VarInt(2),
    /// value: Bytes([11]) }, KeyValuePair { key: VarInt(2), value: Bytes([12]) }] }))
    /// ```
    #[test]
    fn a_message_repeating_a_parameter_type_is_refused_on_decode() {
        let buf = encode(&subscribe(vec![param(FIRST, 11), param(SECOND, 12)]))
            .expect("two different types are a legal list");
        let repeated = repeat_the_first_type(buf);

        let decoded = ControlMessage::decode(&mut &repeated[..]);
        assert!(decoded.is_err(), "a repeated type is not two parameters: {decoded:?}");
    }

    /// Two different types, and an empty list, are both carried. Without this
    /// the gates above would pass on an encoder that refused every parameter.
    #[test]
    fn a_list_that_names_each_type_once_is_carried() {
        for parameters in
            [vec![], vec![param(FIRST, 11)], vec![param(FIRST, 11), param(SECOND, 12)]]
        {
            let buf = encode(&subscribe(parameters.clone()))
                .unwrap_or_else(|e| panic!("{} distinct types is a list: {e:?}", parameters.len()));
            let decoded = ControlMessage::decode(&mut &buf[..]);
            assert!(decoded.is_ok(), "what this codec wrote it must read: {decoded:?}");
        }
    }

    /// The one type this draft's own definition lets a message repeat.
    ///
    /// Section 9.3.2: "The AUTHORIZATION TOKEN parameter MAY be repeated within
    /// a message as long as the combination of Token Type and Token Value are
    /// unique after resolving any aliases." A check that refused every repeat would refuse this, which is
    /// what makes the carve-out worth a gate of its own.
    ///
    /// Dropping the carve-out fails with:
    ///
    /// ```text
    /// this type is allowed more than one instance: DuplicateParameter(3)
    /// ```
    #[test]
    fn an_authorization_token_may_be_repeated() {
        let token = |value: &[u8]| KeyValuePair {
            key: varint(0x03),
            value: KvpValue::Bytes(super::token_value(value)),
        };
        let message = subscribe(vec![token(b"one"), token(b"two")]);
        let buf = encode(&message).expect("this type is allowed more than one instance");
        let decoded = ControlMessage::decode(&mut &buf[..]);
        assert_eq!(decoded.ok().as_ref(), Some(&message), "what this codec wrote it must read");
    }
}

#[cfg(feature = "draft19")]
mod draft19 {
    use super::{param, varint, FIRST, SECOND};
    use moqtap_codec::draft19::message::*;
    use moqtap_codec::kvp::KeyValuePair;
    #[allow(unused_imports)]
    use moqtap_codec::kvp::KvpValue;
    #[allow(unused_imports)]
    use moqtap_codec::types::*;

    fn subscribe(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            request_id: varint(1),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            parameters,
        })
    }

    fn encode(message: &ControlMessage) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message.encode(&mut buf)?;
        Ok(buf)
    }

    /// Turn the second parameter of an encoded frame into a repeat of the
    /// first, by moving the one byte that names it.
    ///
    /// The frame is one this codec built with two different types, so
    /// everything around that byte is exactly what the encoder would have
    /// written. The byte is asserted unique before it is moved, so a fixture
    /// whose other fields happened to collide with it would fail here rather
    /// than quietly patch the wrong place.
    fn repeat_the_first_type(mut buf: Vec<u8>) -> Vec<u8> {
        let on_wire = SECOND - FIRST;
        let repeated = 0;
        assert_eq!(
            buf.iter().filter(|b| u64::from(**b) == on_wire).count(),
            1,
            "the byte naming the second parameter must be the only one of its value",
        );
        let at = buf.iter().position(|b| u64::from(*b) == on_wire).expect("it is in the frame");
        buf[at] = u8::try_from(repeated).unwrap();
        buf
    }

    /// A repeated Parameter Type has no encoding.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// one message cannot state a type twice:
    /// Ok([3, 18, 1, 4, 1, 2, 110, 115, 1, 116, 5, 1, 2, 2, 2, 1, 11, 2, 1, 12])
    /// ```
    #[test]
    fn a_message_repeating_a_parameter_type_never_reaches_the_wire() {
        let result = encode(&subscribe(vec![param(FIRST, 11), param(FIRST, 12)]));
        assert!(result.is_err(), "one message cannot state a type twice: {result:?}");
    }

    /// And one that arrives anyway is refused rather than carried inwards.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a repeated type is not two parameters: Ok(Subscribe(Subscribe {
    /// subscribe_id: VarInt(1), ..., parameters: [KeyValuePair { key: VarInt(2),
    /// value: Bytes([11]) }, KeyValuePair { key: VarInt(2), value: Bytes([12]) }] }))
    /// ```
    #[test]
    fn a_message_repeating_a_parameter_type_is_refused_on_decode() {
        let buf = encode(&subscribe(vec![param(FIRST, 11), param(SECOND, 12)]))
            .expect("two different types are a legal list");
        let repeated = repeat_the_first_type(buf);

        let decoded = ControlMessage::decode(&mut &repeated[..]);
        assert!(decoded.is_err(), "a repeated type is not two parameters: {decoded:?}");
    }

    /// Two different types, and an empty list, are both carried. Without this
    /// the gates above would pass on an encoder that refused every parameter.
    #[test]
    fn a_list_that_names_each_type_once_is_carried() {
        for parameters in
            [vec![], vec![param(FIRST, 11)], vec![param(FIRST, 11), param(SECOND, 12)]]
        {
            let buf = encode(&subscribe(parameters.clone()))
                .unwrap_or_else(|e| panic!("{} distinct types is a list: {e:?}", parameters.len()));
            let decoded = ControlMessage::decode(&mut &buf[..]);
            assert!(decoded.is_ok(), "what this codec wrote it must read: {decoded:?}");
        }
    }

    /// The one type this draft's own definition lets a message repeat.
    ///
    /// Section 9.3.2: "The AUTHORIZATION TOKEN parameter MAY be repeated within
    /// a message as long as the combination of Token Type and Token Value are
    /// unique after resolving any aliases." A check that refused every repeat would refuse this, which is
    /// what makes the carve-out worth a gate of its own.
    ///
    /// Dropping the carve-out fails with:
    ///
    /// ```text
    /// this type is allowed more than one instance: DuplicateParameter(3)
    /// ```
    #[test]
    fn an_authorization_token_may_be_repeated() {
        let token = |value: &[u8]| KeyValuePair {
            key: varint(0x03),
            value: KvpValue::Bytes(super::token_value(value)),
        };
        let message = subscribe(vec![token(b"one"), token(b"two")]);
        let buf = encode(&message).expect("this type is allowed more than one instance");
        let decoded = ControlMessage::decode(&mut &buf[..]);
        assert_eq!(decoded.ok().as_ref(), Some(&message), "what this codec wrote it must read");
    }
}

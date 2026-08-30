//! A Track Namespace this codec writes must be one this codec will read.
//!
//! Section 2.4.1 "Track Naming" bounds the field count, and every reader in
//! this crate applies it. The writers did not: eight drafts encoded a namespace
//! without looking at it at all, so a namespace of 33 fields - or of none -
//! went out on the wire and the codec's own decoder then refused it. A
//! conforming peer closes the session with a Protocol Violation, and the
//! sender's only symptom is the close.
//!
//! The bound is not the same on every draft, which is why this is driven on all
//! thirteen rather than on one. Drafts 07 through 16 define a Track Namespace
//! as between 1 and 32 fields. Draft-17 redefines it as between 0 and 32 and
//! states only the upper half as a violation, so an empty namespace is legal
//! there and refusing it would be the same defect pointing the other way.
//!
//! Each gate drives `ControlMessage::encode`, not the check underneath it: the
//! defect was never that the rule was wrong, it was that nothing called it.

#![allow(clippy::items_after_test_module)]

use moqtap_codec::types::TrackNamespace;

/// A namespace of `n` fields, each one byte, so that the field count is the
/// only thing under test - drafts 16 and later also refuse a zero-length field,
/// and an empty field here would fail those for the wrong reason.
fn fields(n: usize) -> TrackNamespace {
    TrackNamespace(vec![b"x".to_vec(); n])
}

#[cfg(feature = "draft07")]
mod draft07 {
    use super::fields;
    use moqtap_codec::draft07::message::{ControlMessage, Unannounce};
    #[allow(unused_imports)]
    use moqtap_codec::varint::VarInt;

    fn message(namespace: moqtap_codec::types::TrackNamespace) -> ControlMessage {
        ControlMessage::Unannounce(Unannounce { track_namespace: namespace })
    }

    fn encode(n: usize) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message(fields(n)).encode(&mut buf)?;
        Ok(buf)
    }

    /// More fields than Section 2.4.1 permits, refused before the bytes exist.
    ///
    /// Dropping the check from this draft's encoder fails with:
    ///
    /// ```text
    /// 33 fields is more than this draft permits: Ok([9, 64, 67, 33, 1, 120, ...])
    /// ```
    ///
    /// The `Ok` carries the frame the encoder just built, which is the whole
    /// point: those bytes were about to go out. The list is elided here and
    /// its leading bytes differ per draft; the message above was taken from
    /// draft-09 with its check removed.
    #[test]
    fn a_namespace_of_33_fields_never_reaches_the_wire() {
        let result = encode(33);
        assert!(result.is_err(), "33 fields is more than this draft permits: {result:?}");
    }

    /// The boundary on the other side of the same rule. Without this the gate
    /// above would pass on an encoder that refused every namespace.
    #[test]
    fn a_namespace_of_32_fields_round_trips() {
        let buf = encode(32).expect("32 fields is the most this draft permits");
        let decoded = ControlMessage::decode(&mut &buf[..]);
        assert!(decoded.is_ok(), "what this codec wrote it must read: {decoded:?}");
    }

    /// A namespace of no fields at all, which this draft does not define.
    ///
    /// Section 2.4.1 calls a Track Namespace "between 1 and 32" here, and
    /// this draft's own reader refuses a field count of zero.
    ///
    /// Dropping the check from this draft's encoder fails with:
    ///
    /// ```text
    /// this draft defines no empty namespace: Ok([9, 1, 0])
    /// ```
    ///
    /// Three bytes: the message type, a length of one, and a field
    /// count of zero. That is the whole frame, and no reader in this
    /// crate accepts it.
    #[test]
    fn an_empty_namespace_never_reaches_the_wire() {
        let result = encode(0);
        assert!(result.is_err(), "this draft defines no empty namespace: {result:?}");
    }
}

#[cfg(feature = "draft08")]
mod draft08 {
    use super::fields;
    use moqtap_codec::draft08::message::{ControlMessage, Unannounce};
    #[allow(unused_imports)]
    use moqtap_codec::varint::VarInt;

    fn message(namespace: moqtap_codec::types::TrackNamespace) -> ControlMessage {
        ControlMessage::Unannounce(Unannounce { track_namespace: namespace })
    }

    fn encode(n: usize) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message(fields(n)).encode(&mut buf)?;
        Ok(buf)
    }

    /// More fields than Section 2.4.1 permits, refused before the bytes exist.
    ///
    /// Dropping the check from this draft's encoder fails with:
    ///
    /// ```text
    /// 33 fields is more than this draft permits: Ok([9, 64, 67, 33, 1, 120, ...])
    /// ```
    ///
    /// The `Ok` carries the frame the encoder just built, which is the whole
    /// point: those bytes were about to go out. The list is elided here and
    /// its leading bytes differ per draft; the message above was taken from
    /// draft-09 with its check removed.
    #[test]
    fn a_namespace_of_33_fields_never_reaches_the_wire() {
        let result = encode(33);
        assert!(result.is_err(), "33 fields is more than this draft permits: {result:?}");
    }

    /// The boundary on the other side of the same rule. Without this the gate
    /// above would pass on an encoder that refused every namespace.
    #[test]
    fn a_namespace_of_32_fields_round_trips() {
        let buf = encode(32).expect("32 fields is the most this draft permits");
        let decoded = ControlMessage::decode(&mut &buf[..]);
        assert!(decoded.is_ok(), "what this codec wrote it must read: {decoded:?}");
    }

    /// A namespace of no fields at all, which this draft does not define.
    ///
    /// Section 2.4.1 calls a Track Namespace "between 1 and 32" here, and
    /// this draft's own reader refuses a field count of zero.
    ///
    /// Dropping the check from this draft's encoder fails with:
    ///
    /// ```text
    /// this draft defines no empty namespace: Ok([9, 1, 0])
    /// ```
    ///
    /// Three bytes: the message type, a length of one, and a field
    /// count of zero. That is the whole frame, and no reader in this
    /// crate accepts it.
    #[test]
    fn an_empty_namespace_never_reaches_the_wire() {
        let result = encode(0);
        assert!(result.is_err(), "this draft defines no empty namespace: {result:?}");
    }
}

#[cfg(feature = "draft09")]
mod draft09 {
    use super::fields;
    use moqtap_codec::draft09::message::{ControlMessage, Unannounce};
    #[allow(unused_imports)]
    use moqtap_codec::varint::VarInt;

    fn message(namespace: moqtap_codec::types::TrackNamespace) -> ControlMessage {
        ControlMessage::Unannounce(Unannounce { track_namespace: namespace })
    }

    fn encode(n: usize) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message(fields(n)).encode(&mut buf)?;
        Ok(buf)
    }

    /// More fields than Section 2.4.1 permits, refused before the bytes exist.
    ///
    /// Dropping the check from this draft's encoder fails with:
    ///
    /// ```text
    /// 33 fields is more than this draft permits: Ok([9, 64, 67, 33, 1, 120, ...])
    /// ```
    ///
    /// The `Ok` carries the frame the encoder just built, which is the whole
    /// point: those bytes were about to go out. The list is elided here and
    /// its leading bytes differ per draft; the message above was taken from
    /// draft-09 with its check removed.
    #[test]
    fn a_namespace_of_33_fields_never_reaches_the_wire() {
        let result = encode(33);
        assert!(result.is_err(), "33 fields is more than this draft permits: {result:?}");
    }

    /// The boundary on the other side of the same rule. Without this the gate
    /// above would pass on an encoder that refused every namespace.
    #[test]
    fn a_namespace_of_32_fields_round_trips() {
        let buf = encode(32).expect("32 fields is the most this draft permits");
        let decoded = ControlMessage::decode(&mut &buf[..]);
        assert!(decoded.is_ok(), "what this codec wrote it must read: {decoded:?}");
    }

    /// A namespace of no fields at all, which this draft does not define.
    ///
    /// Section 2.4.1 calls a Track Namespace "between 1 and 32" here, and
    /// this draft's own reader refuses a field count of zero.
    ///
    /// Dropping the check from this draft's encoder fails with:
    ///
    /// ```text
    /// this draft defines no empty namespace: Ok([9, 1, 0])
    /// ```
    ///
    /// Three bytes: the message type, a length of one, and a field
    /// count of zero. That is the whole frame, and no reader in this
    /// crate accepts it.
    #[test]
    fn an_empty_namespace_never_reaches_the_wire() {
        let result = encode(0);
        assert!(result.is_err(), "this draft defines no empty namespace: {result:?}");
    }
}

#[cfg(feature = "draft10")]
mod draft10 {
    use super::fields;
    use moqtap_codec::draft10::message::{ControlMessage, Unannounce};
    #[allow(unused_imports)]
    use moqtap_codec::varint::VarInt;

    fn message(namespace: moqtap_codec::types::TrackNamespace) -> ControlMessage {
        ControlMessage::Unannounce(Unannounce { track_namespace: namespace })
    }

    fn encode(n: usize) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message(fields(n)).encode(&mut buf)?;
        Ok(buf)
    }

    /// More fields than Section 2.4.1 permits, refused before the bytes exist.
    ///
    /// Dropping the check from this draft's encoder fails with:
    ///
    /// ```text
    /// 33 fields is more than this draft permits: Ok([9, 64, 67, 33, 1, 120, ...])
    /// ```
    ///
    /// The `Ok` carries the frame the encoder just built, which is the whole
    /// point: those bytes were about to go out. The list is elided here and
    /// its leading bytes differ per draft; the message above was taken from
    /// draft-09 with its check removed.
    #[test]
    fn a_namespace_of_33_fields_never_reaches_the_wire() {
        let result = encode(33);
        assert!(result.is_err(), "33 fields is more than this draft permits: {result:?}");
    }

    /// The boundary on the other side of the same rule. Without this the gate
    /// above would pass on an encoder that refused every namespace.
    #[test]
    fn a_namespace_of_32_fields_round_trips() {
        let buf = encode(32).expect("32 fields is the most this draft permits");
        let decoded = ControlMessage::decode(&mut &buf[..]);
        assert!(decoded.is_ok(), "what this codec wrote it must read: {decoded:?}");
    }

    /// A namespace of no fields at all, which this draft does not define.
    ///
    /// Section 2.4.1 calls a Track Namespace "between 1 and 32" here, and
    /// this draft's own reader refuses a field count of zero.
    ///
    /// Dropping the check from this draft's encoder fails with:
    ///
    /// ```text
    /// this draft defines no empty namespace: Ok([9, 1, 0])
    /// ```
    ///
    /// Three bytes: the message type, a length of one, and a field
    /// count of zero. That is the whole frame, and no reader in this
    /// crate accepts it.
    #[test]
    fn an_empty_namespace_never_reaches_the_wire() {
        let result = encode(0);
        assert!(result.is_err(), "this draft defines no empty namespace: {result:?}");
    }
}

#[cfg(feature = "draft11")]
mod draft11 {
    use super::fields;
    use moqtap_codec::draft11::message::{ControlMessage, Unannounce};
    #[allow(unused_imports)]
    use moqtap_codec::varint::VarInt;

    fn message(namespace: moqtap_codec::types::TrackNamespace) -> ControlMessage {
        ControlMessage::Unannounce(Unannounce { track_namespace: namespace })
    }

    fn encode(n: usize) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message(fields(n)).encode(&mut buf)?;
        Ok(buf)
    }

    /// More fields than Section 2.4.1 permits, refused before the bytes exist.
    ///
    /// Dropping the check from this draft's encoder fails with:
    ///
    /// ```text
    /// 33 fields is more than this draft permits: Ok([9, 64, 67, 33, 1, 120, ...])
    /// ```
    ///
    /// The `Ok` carries the frame the encoder just built, which is the whole
    /// point: those bytes were about to go out. The list is elided here and
    /// its leading bytes differ per draft; the message above was taken from
    /// draft-09 with its check removed.
    #[test]
    fn a_namespace_of_33_fields_never_reaches_the_wire() {
        let result = encode(33);
        assert!(result.is_err(), "33 fields is more than this draft permits: {result:?}");
    }

    /// The boundary on the other side of the same rule. Without this the gate
    /// above would pass on an encoder that refused every namespace.
    #[test]
    fn a_namespace_of_32_fields_round_trips() {
        let buf = encode(32).expect("32 fields is the most this draft permits");
        let decoded = ControlMessage::decode(&mut &buf[..]);
        assert!(decoded.is_ok(), "what this codec wrote it must read: {decoded:?}");
    }

    /// A namespace of no fields at all, which this draft does not define.
    ///
    /// Section 2.4.1 calls a Track Namespace "between 1 and 32" here, and
    /// this draft's own reader refuses a field count of zero.
    ///
    /// Dropping the check from this draft's encoder fails with:
    ///
    /// ```text
    /// this draft defines no empty namespace: Ok([9, 1, 0])
    /// ```
    ///
    /// Three bytes: the message type, a length of one, and a field
    /// count of zero. That is the whole frame, and no reader in this
    /// crate accepts it.
    #[test]
    fn an_empty_namespace_never_reaches_the_wire() {
        let result = encode(0);
        assert!(result.is_err(), "this draft defines no empty namespace: {result:?}");
    }
}

#[cfg(feature = "draft12")]
mod draft12 {
    use super::fields;
    use moqtap_codec::draft12::message::{ControlMessage, Unannounce};
    #[allow(unused_imports)]
    use moqtap_codec::varint::VarInt;

    fn message(namespace: moqtap_codec::types::TrackNamespace) -> ControlMessage {
        ControlMessage::Unannounce(Unannounce { track_namespace: namespace })
    }

    fn encode(n: usize) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message(fields(n)).encode(&mut buf)?;
        Ok(buf)
    }

    /// More fields than Section 2.4.1 permits, refused before the bytes exist.
    ///
    /// Dropping the check from this draft's encoder fails with:
    ///
    /// ```text
    /// 33 fields is more than this draft permits: Ok([9, 64, 67, 33, 1, 120, ...])
    /// ```
    ///
    /// The `Ok` carries the frame the encoder just built, which is the whole
    /// point: those bytes were about to go out. The list is elided here and
    /// its leading bytes differ per draft; the message above was taken from
    /// draft-09 with its check removed.
    #[test]
    fn a_namespace_of_33_fields_never_reaches_the_wire() {
        let result = encode(33);
        assert!(result.is_err(), "33 fields is more than this draft permits: {result:?}");
    }

    /// The boundary on the other side of the same rule. Without this the gate
    /// above would pass on an encoder that refused every namespace.
    #[test]
    fn a_namespace_of_32_fields_round_trips() {
        let buf = encode(32).expect("32 fields is the most this draft permits");
        let decoded = ControlMessage::decode(&mut &buf[..]);
        assert!(decoded.is_ok(), "what this codec wrote it must read: {decoded:?}");
    }

    /// A namespace of no fields at all, which this draft does not define.
    ///
    /// Section 2.4.1 calls a Track Namespace "between 1 and 32" here, and
    /// this draft's own reader refuses a field count of zero.
    ///
    /// Dropping the check from this draft's encoder fails with:
    ///
    /// ```text
    /// this draft defines no empty namespace: Ok([9, 1, 0])
    /// ```
    ///
    /// Three bytes: the message type, a length of one, and a field
    /// count of zero. That is the whole frame, and no reader in this
    /// crate accepts it.
    #[test]
    fn an_empty_namespace_never_reaches_the_wire() {
        let result = encode(0);
        assert!(result.is_err(), "this draft defines no empty namespace: {result:?}");
    }
}

#[cfg(feature = "draft13")]
mod draft13 {
    use super::fields;
    use moqtap_codec::draft13::message::{ControlMessage, Unannounce};
    #[allow(unused_imports)]
    use moqtap_codec::varint::VarInt;

    fn message(namespace: moqtap_codec::types::TrackNamespace) -> ControlMessage {
        ControlMessage::Unannounce(Unannounce { track_namespace: namespace })
    }

    fn encode(n: usize) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message(fields(n)).encode(&mut buf)?;
        Ok(buf)
    }

    /// More fields than Section 2.4.1 permits, refused before the bytes exist.
    ///
    /// Dropping the check from this draft's encoder fails with:
    ///
    /// ```text
    /// 33 fields is more than this draft permits: Ok([9, 64, 67, 33, 1, 120, ...])
    /// ```
    ///
    /// The `Ok` carries the frame the encoder just built, which is the whole
    /// point: those bytes were about to go out. The list is elided here and
    /// its leading bytes differ per draft; the message above was taken from
    /// draft-09 with its check removed.
    #[test]
    fn a_namespace_of_33_fields_never_reaches_the_wire() {
        let result = encode(33);
        assert!(result.is_err(), "33 fields is more than this draft permits: {result:?}");
    }

    /// The boundary on the other side of the same rule. Without this the gate
    /// above would pass on an encoder that refused every namespace.
    #[test]
    fn a_namespace_of_32_fields_round_trips() {
        let buf = encode(32).expect("32 fields is the most this draft permits");
        let decoded = ControlMessage::decode(&mut &buf[..]);
        assert!(decoded.is_ok(), "what this codec wrote it must read: {decoded:?}");
    }

    /// A namespace of no fields at all, which this draft does not define.
    ///
    /// Section 2.4.1 calls a Track Namespace "between 1 and 32" here, and
    /// this draft's own reader refuses a field count of zero.
    ///
    /// Dropping the check from this draft's encoder fails with:
    ///
    /// ```text
    /// this draft defines no empty namespace: Ok([9, 1, 0])
    /// ```
    ///
    /// Three bytes: the message type, a length of one, and a field
    /// count of zero. That is the whole frame, and no reader in this
    /// crate accepts it.
    #[test]
    fn an_empty_namespace_never_reaches_the_wire() {
        let result = encode(0);
        assert!(result.is_err(), "this draft defines no empty namespace: {result:?}");
    }
}

#[cfg(feature = "draft14")]
mod draft14 {
    use super::fields;
    use moqtap_codec::draft14::message::{ControlMessage, PublishNamespaceDone};
    #[allow(unused_imports)]
    use moqtap_codec::varint::VarInt;

    fn message(namespace: moqtap_codec::types::TrackNamespace) -> ControlMessage {
        ControlMessage::PublishNamespaceDone(PublishNamespaceDone { track_namespace: namespace })
    }

    fn encode(n: usize) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message(fields(n)).encode(&mut buf)?;
        Ok(buf)
    }

    /// More fields than Section 2.4.1 permits, refused before the bytes exist.
    ///
    /// Dropping the check from this draft's encoder fails with:
    ///
    /// ```text
    /// 33 fields is more than this draft permits: Ok([9, 64, 67, 33, 1, 120, ...])
    /// ```
    ///
    /// The `Ok` carries the frame the encoder just built, which is the whole
    /// point: those bytes were about to go out. The list is elided here and
    /// its leading bytes differ per draft; the message above was taken from
    /// draft-09 with its check removed.
    #[test]
    fn a_namespace_of_33_fields_never_reaches_the_wire() {
        let result = encode(33);
        assert!(result.is_err(), "33 fields is more than this draft permits: {result:?}");
    }

    /// The boundary on the other side of the same rule. Without this the gate
    /// above would pass on an encoder that refused every namespace.
    #[test]
    fn a_namespace_of_32_fields_round_trips() {
        let buf = encode(32).expect("32 fields is the most this draft permits");
        let decoded = ControlMessage::decode(&mut &buf[..]);
        assert!(decoded.is_ok(), "what this codec wrote it must read: {decoded:?}");
    }

    /// A namespace of no fields at all, which this draft does not define.
    ///
    /// Section 2.4.1 calls a Track Namespace "between 1 and 32" here, and
    /// this draft's own reader refuses a field count of zero.
    ///
    /// Dropping the check from this draft's encoder fails with:
    ///
    /// ```text
    /// this draft defines no empty namespace: Ok([9, 1, 0])
    /// ```
    ///
    /// Three bytes: the message type, a length of one, and a field
    /// count of zero. That is the whole frame, and no reader in this
    /// crate accepts it.
    #[test]
    fn an_empty_namespace_never_reaches_the_wire() {
        let result = encode(0);
        assert!(result.is_err(), "this draft defines no empty namespace: {result:?}");
    }
}

#[cfg(feature = "draft15")]
mod draft15 {
    use super::fields;
    use moqtap_codec::draft15::message::{ControlMessage, PublishNamespaceDone};
    #[allow(unused_imports)]
    use moqtap_codec::varint::VarInt;

    fn message(namespace: moqtap_codec::types::TrackNamespace) -> ControlMessage {
        ControlMessage::PublishNamespaceDone(PublishNamespaceDone { track_namespace: namespace })
    }

    fn encode(n: usize) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message(fields(n)).encode(&mut buf)?;
        Ok(buf)
    }

    /// More fields than Section 2.4.1 permits, refused before the bytes exist.
    ///
    /// Dropping the check from this draft's encoder fails with:
    ///
    /// ```text
    /// 33 fields is more than this draft permits: Ok([9, 64, 67, 33, 1, 120, ...])
    /// ```
    ///
    /// The `Ok` carries the frame the encoder just built, which is the whole
    /// point: those bytes were about to go out. The list is elided here and
    /// its leading bytes differ per draft; the message above was taken from
    /// draft-09 with its check removed.
    #[test]
    fn a_namespace_of_33_fields_never_reaches_the_wire() {
        let result = encode(33);
        assert!(result.is_err(), "33 fields is more than this draft permits: {result:?}");
    }

    /// The boundary on the other side of the same rule. Without this the gate
    /// above would pass on an encoder that refused every namespace.
    #[test]
    fn a_namespace_of_32_fields_round_trips() {
        let buf = encode(32).expect("32 fields is the most this draft permits");
        let decoded = ControlMessage::decode(&mut &buf[..]);
        assert!(decoded.is_ok(), "what this codec wrote it must read: {decoded:?}");
    }

    /// A namespace of no fields at all, which this draft does not define.
    ///
    /// Section 2.4.1 calls a Track Namespace "between 1 and 32" here, and
    /// this draft's own reader refuses a field count of zero.
    ///
    /// Dropping the check from this draft's encoder fails with:
    ///
    /// ```text
    /// this draft defines no empty namespace: Ok([9, 1, 0])
    /// ```
    ///
    /// Three bytes: the message type, a length of one, and a field
    /// count of zero. That is the whole frame, and no reader in this
    /// crate accepts it.
    #[test]
    fn an_empty_namespace_never_reaches_the_wire() {
        let result = encode(0);
        assert!(result.is_err(), "this draft defines no empty namespace: {result:?}");
    }
}

#[cfg(feature = "draft16")]
mod draft16 {
    use super::fields;
    use moqtap_codec::draft16::message::{ControlMessage, PublishNamespace};
    #[allow(unused_imports)]
    use moqtap_codec::varint::VarInt;

    fn message(namespace: moqtap_codec::types::TrackNamespace) -> ControlMessage {
        ControlMessage::PublishNamespace(PublishNamespace {
            request_id: VarInt::from_u64(0).unwrap(),
            track_namespace: namespace,
            parameters: vec![],
        })
    }

    fn encode(n: usize) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message(fields(n)).encode(&mut buf)?;
        Ok(buf)
    }

    /// More fields than Section 2.4.1 permits, refused before the bytes exist.
    ///
    /// Dropping the check from this draft's encoder fails with:
    ///
    /// ```text
    /// 33 fields is more than this draft permits: Ok([9, 64, 67, 33, 1, 120, ...])
    /// ```
    ///
    /// The `Ok` carries the frame the encoder just built, which is the whole
    /// point: those bytes were about to go out. The list is elided here and
    /// its leading bytes differ per draft; the message above was taken from
    /// draft-09 with its check removed.
    #[test]
    fn a_namespace_of_33_fields_never_reaches_the_wire() {
        let result = encode(33);
        assert!(result.is_err(), "33 fields is more than this draft permits: {result:?}");
    }

    /// The boundary on the other side of the same rule. Without this the gate
    /// above would pass on an encoder that refused every namespace.
    #[test]
    fn a_namespace_of_32_fields_round_trips() {
        let buf = encode(32).expect("32 fields is the most this draft permits");
        let decoded = ControlMessage::decode(&mut &buf[..]);
        assert!(decoded.is_ok(), "what this codec wrote it must read: {decoded:?}");
    }

    /// A namespace of no fields at all, which this draft does not define.
    ///
    /// Section 2.4.1 calls a Track Namespace "between 1 and 32" here, and
    /// this draft's own reader refuses a field count of zero.
    ///
    /// Dropping the check from this draft's encoder fails with:
    ///
    /// ```text
    /// this draft defines no empty namespace: Ok([9, 1, 0])
    /// ```
    ///
    /// Three bytes: the message type, a length of one, and a field
    /// count of zero. That is the whole frame, and no reader in this
    /// crate accepts it.
    #[test]
    fn an_empty_namespace_never_reaches_the_wire() {
        let result = encode(0);
        assert!(result.is_err(), "this draft defines no empty namespace: {result:?}");
    }
}

#[cfg(feature = "draft17")]
mod draft17 {
    use super::fields;
    use moqtap_codec::draft17::message::{ControlMessage, PublishNamespace};
    #[allow(unused_imports)]
    use moqtap_codec::varint::VarInt;

    fn message(namespace: moqtap_codec::types::TrackNamespace) -> ControlMessage {
        ControlMessage::PublishNamespace(PublishNamespace {
            request_id: VarInt::from_u64(0).unwrap(),
            required_request_id_delta: VarInt::from_u64(0).unwrap(),
            track_namespace: namespace,
            parameters: vec![],
        })
    }

    fn encode(n: usize) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message(fields(n)).encode(&mut buf)?;
        Ok(buf)
    }

    /// More fields than Section 2.4.1 permits, refused before the bytes exist.
    ///
    /// Dropping the check from this draft's encoder fails with:
    ///
    /// ```text
    /// 33 fields is more than this draft permits: Ok([9, 64, 67, 33, 1, 120, ...])
    /// ```
    ///
    /// The `Ok` carries the frame the encoder just built, which is the whole
    /// point: those bytes were about to go out. The list is elided here and
    /// its leading bytes differ per draft; the message above was taken from
    /// draft-09 with its check removed.
    #[test]
    fn a_namespace_of_33_fields_never_reaches_the_wire() {
        let result = encode(33);
        assert!(result.is_err(), "33 fields is more than this draft permits: {result:?}");
    }

    /// The boundary on the other side of the same rule. Without this the gate
    /// above would pass on an encoder that refused every namespace.
    #[test]
    fn a_namespace_of_32_fields_round_trips() {
        let buf = encode(32).expect("32 fields is the most this draft permits");
        let decoded = ControlMessage::decode(&mut &buf[..]);
        assert!(decoded.is_ok(), "what this codec wrote it must read: {decoded:?}");
    }

    /// A namespace of no fields, which this draft does define.
    ///
    /// Section 2.4.1 changed at draft-17 to "between 0 and 32 Track Namespace
    /// Fields", and states only the upper bound as a violation. Refusing the
    /// empty namespace here would reject traffic the draft permits, so the
    /// gate is that it goes out and comes back.
    #[test]
    fn an_empty_namespace_is_carried() {
        let result = encode(0);
        let buf = result.expect("this draft defines the empty namespace");
        let decoded = ControlMessage::decode(&mut &buf[..]);
        assert!(decoded.is_ok(), "what this codec wrote it must read: {decoded:?}");
    }
}

#[cfg(feature = "draft18")]
mod draft18 {
    use super::fields;
    use moqtap_codec::draft18::message::{ControlMessage, PublishNamespace};
    #[allow(unused_imports)]
    use moqtap_codec::varint::VarInt;

    fn message(namespace: moqtap_codec::types::TrackNamespace) -> ControlMessage {
        ControlMessage::PublishNamespace(PublishNamespace {
            request_id: VarInt::from_u64(0).unwrap(),
            track_namespace: namespace,
            parameters: vec![],
        })
    }

    fn encode(n: usize) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message(fields(n)).encode(&mut buf)?;
        Ok(buf)
    }

    /// More fields than Section 2.4.1 permits, refused before the bytes exist.
    ///
    /// Dropping the check from this draft's encoder fails with:
    ///
    /// ```text
    /// 33 fields is more than this draft permits: Ok([9, 64, 67, 33, 1, 120, ...])
    /// ```
    ///
    /// The `Ok` carries the frame the encoder just built, which is the whole
    /// point: those bytes were about to go out. The list is elided here and
    /// its leading bytes differ per draft; the message above was taken from
    /// draft-09 with its check removed.
    #[test]
    fn a_namespace_of_33_fields_never_reaches_the_wire() {
        let result = encode(33);
        assert!(result.is_err(), "33 fields is more than this draft permits: {result:?}");
    }

    /// The boundary on the other side of the same rule. Without this the gate
    /// above would pass on an encoder that refused every namespace.
    #[test]
    fn a_namespace_of_32_fields_round_trips() {
        let buf = encode(32).expect("32 fields is the most this draft permits");
        let decoded = ControlMessage::decode(&mut &buf[..]);
        assert!(decoded.is_ok(), "what this codec wrote it must read: {decoded:?}");
    }

    /// A namespace of no fields, which this draft does define.
    ///
    /// Section 2.4.1 changed at draft-17 to "between 0 and 32 Track Namespace
    /// Fields", and states only the upper bound as a violation. Refusing the
    /// empty namespace here would reject traffic the draft permits, so the
    /// gate is that it goes out and comes back.
    #[test]
    fn an_empty_namespace_is_carried() {
        let result = encode(0);
        let buf = result.expect("this draft defines the empty namespace");
        let decoded = ControlMessage::decode(&mut &buf[..]);
        assert!(decoded.is_ok(), "what this codec wrote it must read: {decoded:?}");
    }
}

#[cfg(feature = "draft19")]
mod draft19 {
    use super::fields;
    use moqtap_codec::draft19::message::{ControlMessage, PublishNamespace};
    #[allow(unused_imports)]
    use moqtap_codec::varint::VarInt;

    fn message(namespace: moqtap_codec::types::TrackNamespace) -> ControlMessage {
        ControlMessage::PublishNamespace(PublishNamespace {
            request_id: VarInt::from_u64(0).unwrap(),
            track_namespace: namespace,
            parameters: vec![],
        })
    }

    fn encode(n: usize) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message(fields(n)).encode(&mut buf)?;
        Ok(buf)
    }

    /// More fields than Section 2.4.1 permits, refused before the bytes exist.
    ///
    /// Dropping the check from this draft's encoder fails with:
    ///
    /// ```text
    /// 33 fields is more than this draft permits: Ok([9, 64, 67, 33, 1, 120, ...])
    /// ```
    ///
    /// The `Ok` carries the frame the encoder just built, which is the whole
    /// point: those bytes were about to go out. The list is elided here and
    /// its leading bytes differ per draft; the message above was taken from
    /// draft-09 with its check removed.
    #[test]
    fn a_namespace_of_33_fields_never_reaches_the_wire() {
        let result = encode(33);
        assert!(result.is_err(), "33 fields is more than this draft permits: {result:?}");
    }

    /// The boundary on the other side of the same rule. Without this the gate
    /// above would pass on an encoder that refused every namespace.
    #[test]
    fn a_namespace_of_32_fields_round_trips() {
        let buf = encode(32).expect("32 fields is the most this draft permits");
        let decoded = ControlMessage::decode(&mut &buf[..]);
        assert!(decoded.is_ok(), "what this codec wrote it must read: {decoded:?}");
    }

    /// A namespace of no fields, which this draft does define.
    ///
    /// Section 2.4.1 changed at draft-17 to "between 0 and 32 Track Namespace
    /// Fields", and states only the upper bound as a violation. Refusing the
    /// empty namespace here would reject traffic the draft permits, so the
    /// gate is that it goes out and comes back.
    #[test]
    fn an_empty_namespace_is_carried() {
        let result = encode(0);
        let buf = result.expect("this draft defines the empty namespace");
        let decoded = ControlMessage::decode(&mut &buf[..]);
        assert!(decoded.is_ok(), "what this codec wrote it must read: {decoded:?}");
    }
}

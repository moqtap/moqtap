//! An Object Status a caller sets must reach the wire or be refused.
//!
//! On a subgroup stream and on a fetch stream the status and the payload share
//! a wire position: "The Object Status field is only sent if the Object Payload
//! Length is zero", and "Any object with a status code other than zero MUST
//! have an empty payload". So a header that states both has no encoding at all.
//!
//! The infallible encoder resolves that by writing the payload length and
//! dropping the status, which is the worst of the three possible answers: the
//! peer reads an ordinary object, the caller is told nothing, and the object
//! that was meant to end the group simply never ends it. The datagram types on
//! these drafts already refused the pairing; the two stream object types - the
//! ones a publisher writes on every stream - did not.
//!
//! Each gate below drives both halves. The refusal is the fix; the assertion
//! that the plain encoder still drops the status is what says why the fix is
//! needed, and it is the reason a round trip alone could never have found this.

#![allow(clippy::items_after_test_module)]

#[cfg(any(
    feature = "draft07",
    feature = "draft08",
    feature = "draft09",
    feature = "draft10",
    feature = "draft11",
    feature = "draft12",
    feature = "draft13"
))]
use moqtap_codec::varint::VarInt;

#[cfg(any(
    feature = "draft07",
    feature = "draft08",
    feature = "draft09",
    feature = "draft10",
    feature = "draft11",
    feature = "draft12",
    feature = "draft13"
))]
fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).unwrap()
}

#[cfg(feature = "draft07")]
mod draft07 {
    use super::varint;
    use moqtap_codec::draft07::data_stream::{FetchObjectHeader, ObjectHeader};
    use moqtap_codec::draft07::types::ObjectStatus;
    use moqtap_codec::error::CodecError;

    fn subgroup_object(status: ObjectStatus, payload_length: u64) -> ObjectHeader {
        ObjectHeader {
            object_id: varint(0),
            payload_length: varint(payload_length),
            object_status: status,
        }
    }

    fn fetch_object(status: ObjectStatus, payload_length: u64) -> FetchObjectHeader {
        FetchObjectHeader {
            group_id: varint(1),
            subgroup_id: varint(0),
            object_id: varint(0),
            publisher_priority: 128,
            payload_length: varint(payload_length),
            object_status: status,
        }
    }

    /// A status paired with a payload is refused rather than resolved.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a subgroup object cannot state both a status and a payload: Ok(())
    /// ```
    #[test]
    fn a_status_carried_with_a_payload_is_refused() {
        let mut buf = Vec::new();
        let result = subgroup_object(ObjectStatus::EndOfGroup, 4).encode_checked(&mut buf);
        assert!(
            matches!(result, Err(CodecError::InvalidField)),
            "a subgroup object cannot state both a status and a payload: {result:?}",
        );

        let mut buf = Vec::new();
        let result = fetch_object(ObjectStatus::EndOfGroup, 4).encode_checked(&mut buf);
        assert!(
            matches!(result, Err(CodecError::InvalidField)),
            "a fetch object cannot state both a status and a payload: {result:?}",
        );
    }

    /// What the refusal is protecting against, stated as a fact about the
    /// unchecked encoder. Without this the gate above would look like a
    /// tightening for its own sake.
    #[test]
    fn the_unchecked_encoder_drops_the_status_instead() {
        let mut buf = Vec::new();
        subgroup_object(ObjectStatus::EndOfGroup, 4).encode(&mut buf);
        buf.extend_from_slice(b"abcd");

        let decoded = ObjectHeader::decode(&mut &buf[..]).expect("the bytes are a valid object");
        assert_eq!(
            decoded.object_status as usize,
            ObjectStatus::Normal as usize,
            "the status the caller set is not on the wire, which is the defect",
        );
    }

    /// The status is carried when the framing has room for it, so the refusal
    /// is a boundary and not a ban.
    #[test]
    fn a_status_with_no_payload_round_trips() {
        let mut buf = Vec::new();
        subgroup_object(ObjectStatus::EndOfGroup, 0)
            .encode_checked(&mut buf)
            .expect("an empty payload is where a status belongs");

        let decoded = ObjectHeader::decode(&mut &buf[..]).expect("what was written must read");
        assert_eq!(decoded.object_status as usize, ObjectStatus::EndOfGroup as usize);
    }

    /// And an ordinary object with a payload is untouched.
    #[test]
    fn a_normal_object_with_a_payload_is_unaffected() {
        let mut buf = Vec::new();
        subgroup_object(ObjectStatus::Normal, 4)
            .encode_checked(&mut buf)
            .expect("a normal object carrying a payload is the common case");
        assert!(!buf.is_empty());
    }
}

#[cfg(feature = "draft08")]
mod draft08 {
    use super::varint;
    use moqtap_codec::draft08::data_stream::{FetchObjectHeader, ObjectHeader};
    use moqtap_codec::draft08::types::ObjectStatus;
    use moqtap_codec::error::CodecError;

    fn subgroup_object(status: ObjectStatus, payload_length: u64) -> ObjectHeader {
        ObjectHeader {
            object_id: varint(0),
            extension_count: varint(0),
            extensions: Vec::new(),
            payload_length: varint(payload_length),
            object_status: status,
        }
    }

    fn fetch_object(status: ObjectStatus, payload_length: u64) -> FetchObjectHeader {
        FetchObjectHeader {
            group_id: varint(1),
            subgroup_id: varint(0),
            object_id: varint(0),
            publisher_priority: 128,
            extension_count: varint(0),
            extensions: Vec::new(),
            payload_length: varint(payload_length),
            object_status: status,
        }
    }

    /// A status paired with a payload is refused rather than resolved.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a subgroup object cannot state both a status and a payload: Ok(())
    /// ```
    #[test]
    fn a_status_carried_with_a_payload_is_refused() {
        let mut buf = Vec::new();
        let result = subgroup_object(ObjectStatus::EndOfGroup, 4).encode_checked(&mut buf);
        assert!(
            matches!(result, Err(CodecError::InvalidField)),
            "a subgroup object cannot state both a status and a payload: {result:?}",
        );

        let mut buf = Vec::new();
        let result = fetch_object(ObjectStatus::EndOfGroup, 4).encode_checked(&mut buf);
        assert!(
            matches!(result, Err(CodecError::InvalidField)),
            "a fetch object cannot state both a status and a payload: {result:?}",
        );
    }

    /// What the refusal is protecting against, stated as a fact about the
    /// unchecked encoder. Without this the gate above would look like a
    /// tightening for its own sake.
    #[test]
    fn the_unchecked_encoder_drops_the_status_instead() {
        let mut buf = Vec::new();
        subgroup_object(ObjectStatus::EndOfGroup, 4).encode(&mut buf);
        buf.extend_from_slice(b"abcd");

        let decoded = ObjectHeader::decode(&mut &buf[..]).expect("the bytes are a valid object");
        assert_eq!(
            decoded.object_status as usize,
            ObjectStatus::Normal as usize,
            "the status the caller set is not on the wire, which is the defect",
        );
    }

    /// The status is carried when the framing has room for it, so the refusal
    /// is a boundary and not a ban.
    #[test]
    fn a_status_with_no_payload_round_trips() {
        let mut buf = Vec::new();
        subgroup_object(ObjectStatus::EndOfGroup, 0)
            .encode_checked(&mut buf)
            .expect("an empty payload is where a status belongs");

        let decoded = ObjectHeader::decode(&mut &buf[..]).expect("what was written must read");
        assert_eq!(decoded.object_status as usize, ObjectStatus::EndOfGroup as usize);
    }

    /// And an ordinary object with a payload is untouched.
    #[test]
    fn a_normal_object_with_a_payload_is_unaffected() {
        let mut buf = Vec::new();
        subgroup_object(ObjectStatus::Normal, 4)
            .encode_checked(&mut buf)
            .expect("a normal object carrying a payload is the common case");
        assert!(!buf.is_empty());
    }
}

#[cfg(feature = "draft09")]
mod draft09 {
    use super::varint;
    use moqtap_codec::draft09::data_stream::{FetchObjectHeader, ObjectHeader};
    use moqtap_codec::draft09::types::ObjectStatus;
    use moqtap_codec::error::CodecError;

    fn subgroup_object(status: ObjectStatus, payload_length: u64) -> ObjectHeader {
        ObjectHeader {
            object_id: varint(0),
            extension_headers_length: varint(0),
            extensions: Vec::new(),
            payload_length: varint(payload_length),
            object_status: status,
        }
    }

    fn fetch_object(status: ObjectStatus, payload_length: u64) -> FetchObjectHeader {
        FetchObjectHeader {
            group_id: varint(1),
            subgroup_id: varint(0),
            object_id: varint(0),
            publisher_priority: 128,
            extension_headers_length: varint(0),
            extensions: Vec::new(),
            payload_length: varint(payload_length),
            object_status: status,
        }
    }

    /// A status paired with a payload is refused rather than resolved.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a subgroup object cannot state both a status and a payload: Ok(())
    /// ```
    #[test]
    fn a_status_carried_with_a_payload_is_refused() {
        let mut buf = Vec::new();
        let result = subgroup_object(ObjectStatus::EndOfGroup, 4).encode_checked(&mut buf);
        assert!(
            matches!(result, Err(CodecError::InvalidField)),
            "a subgroup object cannot state both a status and a payload: {result:?}",
        );

        let mut buf = Vec::new();
        let result = fetch_object(ObjectStatus::EndOfGroup, 4).encode_checked(&mut buf);
        assert!(
            matches!(result, Err(CodecError::InvalidField)),
            "a fetch object cannot state both a status and a payload: {result:?}",
        );
    }

    /// What the refusal is protecting against, stated as a fact about the
    /// unchecked encoder. Without this the gate above would look like a
    /// tightening for its own sake.
    #[test]
    fn the_unchecked_encoder_drops_the_status_instead() {
        let mut buf = Vec::new();
        subgroup_object(ObjectStatus::EndOfGroup, 4).encode(&mut buf);
        buf.extend_from_slice(b"abcd");

        let decoded = ObjectHeader::decode(&mut &buf[..]).expect("the bytes are a valid object");
        assert_eq!(
            decoded.object_status as usize,
            ObjectStatus::Normal as usize,
            "the status the caller set is not on the wire, which is the defect",
        );
    }

    /// The status is carried when the framing has room for it, so the refusal
    /// is a boundary and not a ban.
    #[test]
    fn a_status_with_no_payload_round_trips() {
        let mut buf = Vec::new();
        subgroup_object(ObjectStatus::EndOfGroup, 0)
            .encode_checked(&mut buf)
            .expect("an empty payload is where a status belongs");

        let decoded = ObjectHeader::decode(&mut &buf[..]).expect("what was written must read");
        assert_eq!(decoded.object_status as usize, ObjectStatus::EndOfGroup as usize);
    }

    /// And an ordinary object with a payload is untouched.
    #[test]
    fn a_normal_object_with_a_payload_is_unaffected() {
        let mut buf = Vec::new();
        subgroup_object(ObjectStatus::Normal, 4)
            .encode_checked(&mut buf)
            .expect("a normal object carrying a payload is the common case");
        assert!(!buf.is_empty());
    }
}

#[cfg(feature = "draft10")]
mod draft10 {
    use super::varint;
    use moqtap_codec::draft10::data_stream::{FetchObjectHeader, ObjectHeader};
    use moqtap_codec::draft10::types::ObjectStatus;
    use moqtap_codec::error::CodecError;

    fn subgroup_object(status: ObjectStatus, payload_length: u64) -> ObjectHeader {
        ObjectHeader {
            object_id: varint(0),
            extension_headers_length: varint(0),
            extensions: Vec::new(),
            payload_length: varint(payload_length),
            object_status: status,
        }
    }

    fn fetch_object(status: ObjectStatus, payload_length: u64) -> FetchObjectHeader {
        FetchObjectHeader {
            group_id: varint(1),
            subgroup_id: varint(0),
            object_id: varint(0),
            publisher_priority: 128,
            extension_headers_length: varint(0),
            extensions: Vec::new(),
            payload_length: varint(payload_length),
            object_status: status,
        }
    }

    /// A status paired with a payload is refused rather than resolved.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a subgroup object cannot state both a status and a payload: Ok(())
    /// ```
    #[test]
    fn a_status_carried_with_a_payload_is_refused() {
        let mut buf = Vec::new();
        let result = subgroup_object(ObjectStatus::EndOfGroup, 4).encode_checked(&mut buf);
        assert!(
            matches!(result, Err(CodecError::InvalidField)),
            "a subgroup object cannot state both a status and a payload: {result:?}",
        );

        let mut buf = Vec::new();
        let result = fetch_object(ObjectStatus::EndOfGroup, 4).encode_checked(&mut buf);
        assert!(
            matches!(result, Err(CodecError::InvalidField)),
            "a fetch object cannot state both a status and a payload: {result:?}",
        );
    }

    /// What the refusal is protecting against, stated as a fact about the
    /// unchecked encoder. Without this the gate above would look like a
    /// tightening for its own sake.
    #[test]
    fn the_unchecked_encoder_drops_the_status_instead() {
        let mut buf = Vec::new();
        subgroup_object(ObjectStatus::EndOfGroup, 4).encode(&mut buf);
        buf.extend_from_slice(b"abcd");

        let decoded = ObjectHeader::decode(&mut &buf[..]).expect("the bytes are a valid object");
        assert_eq!(
            decoded.object_status as usize,
            ObjectStatus::Normal as usize,
            "the status the caller set is not on the wire, which is the defect",
        );
    }

    /// The status is carried when the framing has room for it, so the refusal
    /// is a boundary and not a ban.
    #[test]
    fn a_status_with_no_payload_round_trips() {
        let mut buf = Vec::new();
        subgroup_object(ObjectStatus::EndOfGroup, 0)
            .encode_checked(&mut buf)
            .expect("an empty payload is where a status belongs");

        let decoded = ObjectHeader::decode(&mut &buf[..]).expect("what was written must read");
        assert_eq!(decoded.object_status as usize, ObjectStatus::EndOfGroup as usize);
    }

    /// And an ordinary object with a payload is untouched.
    #[test]
    fn a_normal_object_with_a_payload_is_unaffected() {
        let mut buf = Vec::new();
        subgroup_object(ObjectStatus::Normal, 4)
            .encode_checked(&mut buf)
            .expect("a normal object carrying a payload is the common case");
        assert!(!buf.is_empty());
    }
}

#[cfg(feature = "draft11")]
mod draft11 {
    use super::varint;
    use moqtap_codec::draft11::data_stream::{FetchObjectHeader, ObjectHeader};
    use moqtap_codec::draft11::types::ObjectStatus;
    use moqtap_codec::error::CodecError;

    fn subgroup_object(status: ObjectStatus, payload_length: u64) -> ObjectHeader {
        ObjectHeader {
            object_id: varint(0),
            extension_headers_length: varint(0),
            extensions: Vec::new(),
            payload_length: varint(payload_length),
            object_status: status,
        }
    }

    fn fetch_object(status: ObjectStatus, payload_length: u64) -> FetchObjectHeader {
        FetchObjectHeader {
            group_id: varint(1),
            subgroup_id: varint(0),
            object_id: varint(0),
            publisher_priority: 128,
            extension_headers_length: varint(0),
            extensions: Vec::new(),
            payload_length: varint(payload_length),
            object_status: status,
        }
    }

    /// A status paired with a payload is refused rather than resolved.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a subgroup object cannot state both a status and a payload: Ok(())
    /// ```
    #[test]
    fn a_status_carried_with_a_payload_is_refused() {
        let mut buf = Vec::new();
        let result = subgroup_object(ObjectStatus::EndOfGroup, 4).encode_checked(&mut buf);
        assert!(
            matches!(result, Err(CodecError::InvalidField)),
            "a subgroup object cannot state both a status and a payload: {result:?}",
        );

        let mut buf = Vec::new();
        let result = fetch_object(ObjectStatus::EndOfGroup, 4).encode_checked(&mut buf);
        assert!(
            matches!(result, Err(CodecError::InvalidField)),
            "a fetch object cannot state both a status and a payload: {result:?}",
        );
    }

    /// What the refusal is protecting against, stated as a fact about the
    /// unchecked encoder. Without this the gate above would look like a
    /// tightening for its own sake.
    #[test]
    fn the_unchecked_encoder_drops_the_status_instead() {
        let mut buf = Vec::new();
        subgroup_object(ObjectStatus::EndOfGroup, 4).encode(&mut buf);
        buf.extend_from_slice(b"abcd");

        let decoded = ObjectHeader::decode(&mut &buf[..]).expect("the bytes are a valid object");
        assert_eq!(
            decoded.object_status as usize,
            ObjectStatus::Normal as usize,
            "the status the caller set is not on the wire, which is the defect",
        );
    }

    /// The status is carried when the framing has room for it, so the refusal
    /// is a boundary and not a ban.
    #[test]
    fn a_status_with_no_payload_round_trips() {
        let mut buf = Vec::new();
        subgroup_object(ObjectStatus::EndOfGroup, 0)
            .encode_checked(&mut buf)
            .expect("an empty payload is where a status belongs");

        let decoded = ObjectHeader::decode(&mut &buf[..]).expect("what was written must read");
        assert_eq!(decoded.object_status as usize, ObjectStatus::EndOfGroup as usize);
    }

    /// And an ordinary object with a payload is untouched.
    #[test]
    fn a_normal_object_with_a_payload_is_unaffected() {
        let mut buf = Vec::new();
        subgroup_object(ObjectStatus::Normal, 4)
            .encode_checked(&mut buf)
            .expect("a normal object carrying a payload is the common case");
        assert!(!buf.is_empty());
    }
}

#[cfg(feature = "draft12")]
mod draft12 {
    use super::varint;
    use moqtap_codec::draft12::data_stream::{FetchObjectHeader, ObjectHeader};
    use moqtap_codec::draft12::types::ObjectStatus;
    use moqtap_codec::error::CodecError;

    fn subgroup_object(status: ObjectStatus, payload_length: u64) -> ObjectHeader {
        ObjectHeader {
            object_id: varint(0),
            extension_headers_length: varint(0),
            extensions: Vec::new(),
            payload_length: varint(payload_length),
            object_status: status,
        }
    }

    fn fetch_object(status: ObjectStatus, payload_length: u64) -> FetchObjectHeader {
        FetchObjectHeader {
            group_id: varint(1),
            subgroup_id: varint(0),
            object_id: varint(0),
            publisher_priority: 128,
            extension_headers_length: varint(0),
            extensions: Vec::new(),
            payload_length: varint(payload_length),
            object_status: status,
        }
    }

    /// A status paired with a payload is refused rather than resolved.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a subgroup object cannot state both a status and a payload: Ok(())
    /// ```
    #[test]
    fn a_status_carried_with_a_payload_is_refused() {
        let mut buf = Vec::new();
        let result = subgroup_object(ObjectStatus::EndOfGroup, 4).encode_checked(&mut buf);
        assert!(
            matches!(result, Err(CodecError::InvalidField)),
            "a subgroup object cannot state both a status and a payload: {result:?}",
        );

        let mut buf = Vec::new();
        let result = fetch_object(ObjectStatus::EndOfGroup, 4).encode_checked(&mut buf);
        assert!(
            matches!(result, Err(CodecError::InvalidField)),
            "a fetch object cannot state both a status and a payload: {result:?}",
        );
    }

    /// What the refusal is protecting against, stated as a fact about the
    /// unchecked encoder. Without this the gate above would look like a
    /// tightening for its own sake.
    #[test]
    fn the_unchecked_encoder_drops_the_status_instead() {
        let mut buf = Vec::new();
        subgroup_object(ObjectStatus::EndOfGroup, 4).encode(&mut buf);
        buf.extend_from_slice(b"abcd");

        let decoded = ObjectHeader::decode(&mut &buf[..]).expect("the bytes are a valid object");
        assert_eq!(
            decoded.object_status as usize,
            ObjectStatus::Normal as usize,
            "the status the caller set is not on the wire, which is the defect",
        );
    }

    /// The status is carried when the framing has room for it, so the refusal
    /// is a boundary and not a ban.
    #[test]
    fn a_status_with_no_payload_round_trips() {
        let mut buf = Vec::new();
        subgroup_object(ObjectStatus::EndOfGroup, 0)
            .encode_checked(&mut buf)
            .expect("an empty payload is where a status belongs");

        let decoded = ObjectHeader::decode(&mut &buf[..]).expect("what was written must read");
        assert_eq!(decoded.object_status as usize, ObjectStatus::EndOfGroup as usize);
    }

    /// And an ordinary object with a payload is untouched.
    #[test]
    fn a_normal_object_with_a_payload_is_unaffected() {
        let mut buf = Vec::new();
        subgroup_object(ObjectStatus::Normal, 4)
            .encode_checked(&mut buf)
            .expect("a normal object carrying a payload is the common case");
        assert!(!buf.is_empty());
    }
}

#[cfg(feature = "draft13")]
mod draft13 {
    use super::varint;
    use moqtap_codec::draft13::data_stream::{FetchObjectHeader, ObjectHeader};
    use moqtap_codec::draft13::types::ObjectStatus;
    use moqtap_codec::error::CodecError;

    fn subgroup_object(status: ObjectStatus, payload_length: u64) -> ObjectHeader {
        ObjectHeader {
            object_id: varint(0),
            extension_headers_length: varint(0),
            extensions: Vec::new(),
            payload_length: varint(payload_length),
            object_status: status,
        }
    }

    fn fetch_object(status: ObjectStatus, payload_length: u64) -> FetchObjectHeader {
        FetchObjectHeader {
            group_id: varint(1),
            subgroup_id: varint(0),
            object_id: varint(0),
            publisher_priority: 128,
            extension_headers_length: varint(0),
            extensions: Vec::new(),
            payload_length: varint(payload_length),
            object_status: status,
        }
    }

    /// A status paired with a payload is refused rather than resolved.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a subgroup object cannot state both a status and a payload: Ok(())
    /// ```
    #[test]
    fn a_status_carried_with_a_payload_is_refused() {
        let mut buf = Vec::new();
        let result = subgroup_object(ObjectStatus::EndOfGroup, 4).encode_checked(&mut buf);
        assert!(
            matches!(result, Err(CodecError::InvalidField)),
            "a subgroup object cannot state both a status and a payload: {result:?}",
        );

        let mut buf = Vec::new();
        let result = fetch_object(ObjectStatus::EndOfGroup, 4).encode_checked(&mut buf);
        assert!(
            matches!(result, Err(CodecError::InvalidField)),
            "a fetch object cannot state both a status and a payload: {result:?}",
        );
    }

    /// What the refusal is protecting against, stated as a fact about the
    /// unchecked encoder. Without this the gate above would look like a
    /// tightening for its own sake.
    #[test]
    fn the_unchecked_encoder_drops_the_status_instead() {
        let mut buf = Vec::new();
        subgroup_object(ObjectStatus::EndOfGroup, 4).encode(&mut buf);
        buf.extend_from_slice(b"abcd");

        let decoded = ObjectHeader::decode(&mut &buf[..]).expect("the bytes are a valid object");
        assert_eq!(
            decoded.object_status as usize,
            ObjectStatus::Normal as usize,
            "the status the caller set is not on the wire, which is the defect",
        );
    }

    /// The status is carried when the framing has room for it, so the refusal
    /// is a boundary and not a ban.
    #[test]
    fn a_status_with_no_payload_round_trips() {
        let mut buf = Vec::new();
        subgroup_object(ObjectStatus::EndOfGroup, 0)
            .encode_checked(&mut buf)
            .expect("an empty payload is where a status belongs");

        let decoded = ObjectHeader::decode(&mut &buf[..]).expect("what was written must read");
        assert_eq!(decoded.object_status as usize, ObjectStatus::EndOfGroup as usize);
    }

    /// And an ordinary object with a payload is untouched.
    #[test]
    fn a_normal_object_with_a_payload_is_unaffected() {
        let mut buf = Vec::new();
        subgroup_object(ObjectStatus::Normal, 4)
            .encode_checked(&mut buf)
            .expect("a normal object carrying a payload is the common case");
        assert!(!buf.is_empty());
    }
}

//! An end-of-track object ends at object zero.
//!
//! Drafts 08, 09 and 10 describe Object Status 0x5 the same way: "Indicates end
//! of Track. GroupID is one greater than the largest group produced in this
//! track and the ObjectId is zero. An object with this status that has a Group
//! ID less than or equal to any other Group ID, or an Object ID other than
//! zero, is a protocol error, and the receiver MUST terminate the session."
//! **The Object ID half is the one this file is about.**
//!
//! Those three drafts and no others. Draft-07 assigns 0x5 to End of Subgroup,
//! whose "Object ID is one greater than the largest normal object ID in the
//! Subgroup" - the opposite convention, and a non-zero Object ID there is
//! correct rather than a violation. Drafts 11 and later merged End of Track and
//! Group into 0x4 and dropped the sentence, and assign no 0x5 at all.
//!
//! # Only half the sentence is here
//!
//! The Group ID half compares against "any other Group ID" produced on the
//! track. No header carries that, and a reader of one header cannot know it, so
//! it belongs to a session-scoped conformance suite rather than to the codec.
//! The Object ID half needs nothing but the header it is written on, and is
//! settled here on both sides.
//!
//! # The status this is not about
//!
//! 0x4, End of Track and Group, states the *other* convention on the same three
//! drafts: "the ObjectId is one greater than the largest object produced in that
//! group". A check that held every terminal status to object zero would refuse a
//! legal end-of-track-and-group marker, so `an_end_of_track_and_group_marker_
//! ends_one_past_the_last_object` is asserted beside it on every draft.
//!
//! # Recorded failures
//!
//! Each was produced by making the change and running the tests, on draft-08.
//!
//! Dropping the check:
//!
//! ```text
//! an end of track ends at object zero: Ok([1, 0, 0, 5])
//! ```
//!
//! Leaving the reader unchecked, so only the writer holds the rule:
//!
//! ```text
//! the reader refuses it too: Ok(ObjectHeader { object_id: VarInt(1),
//! extension_count: VarInt(0), extensions: [], payload_length: VarInt(0),
//! object_status: EndOfTrack })
//! ```
//!
//! Widening the check to every terminal status rather than 0x5 alone, and -
//! separately - pointing it at 0x4 instead of 0x5, both fail with:
//!
//! ```text
//! end of track and group ends one past the last object, not at zero:
//! Err(EndOfTrackObjectId(1))
//! ```

#[cfg(any(feature = "draft08", feature = "draft09", feature = "draft10"))]
use moqtap_codec::varint::VarInt;

#[cfg(any(feature = "draft08", feature = "draft09", feature = "draft10"))]
fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).unwrap()
}

#[cfg(feature = "draft08")]
mod draft08 {
    use super::varint;
    use moqtap_codec::draft08::data_stream::*;
    use moqtap_codec::draft08::types::ObjectStatus;
    use moqtap_codec::error::CodecError;

    fn object(id: u64, status: ObjectStatus) -> ObjectHeader {
        ObjectHeader {
            object_id: varint(id),
            extension_count: varint(0),
            extensions: Vec::new(),
            payload_length: varint(0),
            object_status: status,
        }
    }

    fn status_datagram(id: u64, status: ObjectStatus) -> DatagramStatusHeader {
        DatagramStatusHeader {
            track_alias: varint(1),
            group_id: varint(11),
            object_id: varint(id),
            publisher_priority: 128,
            object_status: status,
        }
    }

    fn fetch_object(id: u64, status: ObjectStatus) -> FetchObjectHeader {
        FetchObjectHeader {
            group_id: varint(11),
            subgroup_id: varint(0),
            object_id: varint(id),
            publisher_priority: 128,
            extension_count: varint(0),
            extensions: Vec::new(),
            payload_length: varint(0),
            object_status: status,
        }
    }

    fn encoded(header: &ObjectHeader) -> Result<Vec<u8>, CodecError> {
        let mut buf = Vec::new();
        header.encode_checked(&mut buf)?;
        Ok(buf)
    }

    /// Section 8.1.1.1: an end-of-track object "has ... an Object ID other than
    /// zero" is a protocol error.
    #[test]
    fn an_end_of_track_object_at_a_non_zero_id_has_no_encoding() {
        let refused = encoded(&object(1, ObjectStatus::EndOfTrack));
        assert!(
            matches!(refused, Err(CodecError::EndOfTrackObjectId(1))),
            "an end of track ends at object zero: {refused:?}",
        );
    }

    /// And the reader is where the draft puts the consequence - "the receiver
    /// MUST terminate the session" - so a frame built by hand is refused there
    /// too.
    #[test]
    fn the_reader_refuses_an_end_of_track_at_a_non_zero_id() {
        // Written with the unchecked encoder, which is exactly the frame a
        // non-conforming peer would put on the wire.
        let mut buf = Vec::new();
        object(1, ObjectStatus::EndOfTrack).encode(&mut buf);

        let refused = ObjectHeader::decode(&mut &buf[..]);
        assert!(
            matches!(refused, Err(CodecError::EndOfTrackObjectId(1))),
            "the reader refuses it too: {refused:?}",
        );
    }

    /// Object zero is what an end of track is written at, and it round-trips.
    /// Without this the tests above would pass on a codec that refused every
    /// end-of-track object there is.
    #[test]
    fn an_end_of_track_object_at_zero_round_trips() {
        let header = object(0, ObjectStatus::EndOfTrack);
        let buf = encoded(&header).expect("object zero is where an end of track sits");
        let decoded = ObjectHeader::decode(&mut &buf[..]).expect("and it reads back");
        assert_eq!(decoded, header);
    }

    /// Section 8.1.1.1 gives 0x4 the opposite convention: "the ObjectId is one
    /// greater than the largest object produced in that group". A check that
    /// held every terminal status to zero would refuse this legal marker.
    #[test]
    fn an_end_of_track_and_group_marker_ends_one_past_the_last_object() {
        let allowed = encoded(&object(1, ObjectStatus::EndOfTrackAndGroup));
        assert!(
            allowed.is_ok(),
            "end of track and group ends one past the last object, not at zero: {allowed:?}",
        );
    }

    /// So does end of group, on the same reasoning.
    #[test]
    fn an_end_of_group_marker_ends_one_past_the_last_object() {
        encoded(&object(1, ObjectStatus::EndOfGroup))
            .expect("end of group ends one past the last object");
    }

    /// A normal object at a non-zero id is untouched by any of this.
    #[test]
    fn a_normal_object_is_not_held_to_the_rule() {
        encoded(&object(9, ObjectStatus::Normal)).expect("a normal object has no such rule");
    }

    /// The status datagram carries the same status field and the same rule, and
    /// had no checked entry point at all before this.
    #[test]
    fn a_status_datagram_states_the_rule_too() {
        let mut buf = Vec::new();
        let refused = status_datagram(1, ObjectStatus::EndOfTrack).encode_checked(&mut buf);
        assert!(
            matches!(refused, Err(CodecError::EndOfTrackObjectId(1))),
            "a datagram end of track ends at object zero: {refused:?}",
        );
        assert!(buf.is_empty(), "a refused header leaves the buffer untouched");

        let mut ok = Vec::new();
        status_datagram(0, ObjectStatus::EndOfTrack)
            .encode_checked(&mut ok)
            .expect("object zero is legal");
    }

    /// And so does the fetch object header.
    #[test]
    fn a_fetch_object_states_the_rule_too() {
        let mut buf = Vec::new();
        let refused = fetch_object(1, ObjectStatus::EndOfTrack).encode_checked(&mut buf);
        assert!(
            matches!(refused, Err(CodecError::EndOfTrackObjectId(1))),
            "a fetched end of track ends at object zero: {refused:?}",
        );

        let mut ok = Vec::new();
        fetch_object(0, ObjectStatus::EndOfTrack)
            .encode_checked(&mut ok)
            .expect("object zero is legal");
    }
}

#[cfg(feature = "draft09")]
mod draft09 {
    use super::varint;
    use moqtap_codec::draft09::data_stream::*;
    use moqtap_codec::draft09::types::ObjectStatus;
    use moqtap_codec::error::CodecError;

    fn object(id: u64, status: ObjectStatus) -> ObjectHeader {
        ObjectHeader {
            object_id: varint(id),
            extension_headers_length: varint(0),
            extensions: Vec::new(),
            payload_length: varint(0),
            object_status: status,
        }
    }

    fn status_datagram(id: u64, status: ObjectStatus) -> DatagramStatusHeader {
        DatagramStatusHeader {
            track_alias: varint(1),
            group_id: varint(11),
            object_id: varint(id),
            publisher_priority: 128,
            extension_headers_length: varint(0),
            extensions: Vec::new(),
            object_status: status,
        }
    }

    fn fetch_object(id: u64, status: ObjectStatus) -> FetchObjectHeader {
        FetchObjectHeader {
            group_id: varint(11),
            subgroup_id: varint(0),
            object_id: varint(id),
            publisher_priority: 128,
            extension_headers_length: varint(0),
            extensions: Vec::new(),
            payload_length: varint(0),
            object_status: status,
        }
    }

    fn encoded(header: &ObjectHeader) -> Result<Vec<u8>, CodecError> {
        let mut buf = Vec::new();
        header.encode_checked(&mut buf)?;
        Ok(buf)
    }

    /// Section 8.1.1.1: an end-of-track object "has ... an Object ID other than
    /// zero" is a protocol error.
    #[test]
    fn an_end_of_track_object_at_a_non_zero_id_has_no_encoding() {
        let refused = encoded(&object(1, ObjectStatus::EndOfTrack));
        assert!(
            matches!(refused, Err(CodecError::EndOfTrackObjectId(1))),
            "an end of track ends at object zero: {refused:?}",
        );
    }

    /// And the reader is where the draft puts the consequence - "the receiver
    /// MUST terminate the session" - so a frame built by hand is refused there
    /// too.
    #[test]
    fn the_reader_refuses_an_end_of_track_at_a_non_zero_id() {
        // Written with the unchecked encoder, which is exactly the frame a
        // non-conforming peer would put on the wire.
        let mut buf = Vec::new();
        object(1, ObjectStatus::EndOfTrack).encode(&mut buf);

        let refused = ObjectHeader::decode(&mut &buf[..]);
        assert!(
            matches!(refused, Err(CodecError::EndOfTrackObjectId(1))),
            "the reader refuses it too: {refused:?}",
        );
    }

    /// Object zero is what an end of track is written at, and it round-trips.
    /// Without this the tests above would pass on a codec that refused every
    /// end-of-track object there is.
    #[test]
    fn an_end_of_track_object_at_zero_round_trips() {
        let header = object(0, ObjectStatus::EndOfTrack);
        let buf = encoded(&header).expect("object zero is where an end of track sits");
        let decoded = ObjectHeader::decode(&mut &buf[..]).expect("and it reads back");
        assert_eq!(decoded, header);
    }

    /// Section 8.1.1.1 gives 0x4 the opposite convention: "the ObjectId is one
    /// greater than the largest object produced in that group". A check that
    /// held every terminal status to zero would refuse this legal marker.
    #[test]
    fn an_end_of_track_and_group_marker_ends_one_past_the_last_object() {
        let allowed = encoded(&object(1, ObjectStatus::EndOfTrackAndGroup));
        assert!(
            allowed.is_ok(),
            "end of track and group ends one past the last object, not at zero: {allowed:?}",
        );
    }

    /// So does end of group, on the same reasoning.
    #[test]
    fn an_end_of_group_marker_ends_one_past_the_last_object() {
        encoded(&object(1, ObjectStatus::EndOfGroup))
            .expect("end of group ends one past the last object");
    }

    /// A normal object at a non-zero id is untouched by any of this.
    #[test]
    fn a_normal_object_is_not_held_to_the_rule() {
        encoded(&object(9, ObjectStatus::Normal)).expect("a normal object has no such rule");
    }

    /// The status datagram carries the same status field and the same rule, and
    /// had no checked entry point at all before this.
    #[test]
    fn a_status_datagram_states_the_rule_too() {
        let mut buf = Vec::new();
        let refused = status_datagram(1, ObjectStatus::EndOfTrack).encode_checked(&mut buf);
        assert!(
            matches!(refused, Err(CodecError::EndOfTrackObjectId(1))),
            "a datagram end of track ends at object zero: {refused:?}",
        );
        assert!(buf.is_empty(), "a refused header leaves the buffer untouched");

        let mut ok = Vec::new();
        status_datagram(0, ObjectStatus::EndOfTrack)
            .encode_checked(&mut ok)
            .expect("object zero is legal");
    }

    /// And so does the fetch object header.
    #[test]
    fn a_fetch_object_states_the_rule_too() {
        let mut buf = Vec::new();
        let refused = fetch_object(1, ObjectStatus::EndOfTrack).encode_checked(&mut buf);
        assert!(
            matches!(refused, Err(CodecError::EndOfTrackObjectId(1))),
            "a fetched end of track ends at object zero: {refused:?}",
        );

        let mut ok = Vec::new();
        fetch_object(0, ObjectStatus::EndOfTrack)
            .encode_checked(&mut ok)
            .expect("object zero is legal");
    }
}

#[cfg(feature = "draft10")]
mod draft10 {
    use super::varint;
    use moqtap_codec::draft10::data_stream::*;
    use moqtap_codec::draft10::types::ObjectStatus;
    use moqtap_codec::error::CodecError;

    fn object(id: u64, status: ObjectStatus) -> ObjectHeader {
        ObjectHeader {
            object_id: varint(id),
            extension_headers_length: varint(0),
            extensions: Vec::new(),
            payload_length: varint(0),
            object_status: status,
        }
    }

    fn status_datagram(id: u64, status: ObjectStatus) -> DatagramStatusHeader {
        DatagramStatusHeader {
            track_alias: varint(1),
            group_id: varint(11),
            object_id: varint(id),
            publisher_priority: 128,
            extension_headers_length: varint(0),
            extensions: Vec::new(),
            object_status: status,
        }
    }

    fn fetch_object(id: u64, status: ObjectStatus) -> FetchObjectHeader {
        FetchObjectHeader {
            group_id: varint(11),
            subgroup_id: varint(0),
            object_id: varint(id),
            publisher_priority: 128,
            extension_headers_length: varint(0),
            extensions: Vec::new(),
            payload_length: varint(0),
            object_status: status,
        }
    }

    fn encoded(header: &ObjectHeader) -> Result<Vec<u8>, CodecError> {
        let mut buf = Vec::new();
        header.encode_checked(&mut buf)?;
        Ok(buf)
    }

    /// Section 9.1.1.1: an end-of-track object "has ... an Object ID other than
    /// zero" is a protocol error.
    #[test]
    fn an_end_of_track_object_at_a_non_zero_id_has_no_encoding() {
        let refused = encoded(&object(1, ObjectStatus::EndOfTrack));
        assert!(
            matches!(refused, Err(CodecError::EndOfTrackObjectId(1))),
            "an end of track ends at object zero: {refused:?}",
        );
    }

    /// And the reader is where the draft puts the consequence - "the receiver
    /// MUST terminate the session" - so a frame built by hand is refused there
    /// too.
    #[test]
    fn the_reader_refuses_an_end_of_track_at_a_non_zero_id() {
        // Written with the unchecked encoder, which is exactly the frame a
        // non-conforming peer would put on the wire.
        let mut buf = Vec::new();
        object(1, ObjectStatus::EndOfTrack).encode(&mut buf);

        let refused = ObjectHeader::decode(&mut &buf[..]);
        assert!(
            matches!(refused, Err(CodecError::EndOfTrackObjectId(1))),
            "the reader refuses it too: {refused:?}",
        );
    }

    /// Object zero is what an end of track is written at, and it round-trips.
    /// Without this the tests above would pass on a codec that refused every
    /// end-of-track object there is.
    #[test]
    fn an_end_of_track_object_at_zero_round_trips() {
        let header = object(0, ObjectStatus::EndOfTrack);
        let buf = encoded(&header).expect("object zero is where an end of track sits");
        let decoded = ObjectHeader::decode(&mut &buf[..]).expect("and it reads back");
        assert_eq!(decoded, header);
    }

    /// Section 9.1.1.1 gives 0x4 the opposite convention: "the ObjectId is one
    /// greater than the largest object produced in that group". A check that
    /// held every terminal status to zero would refuse this legal marker.
    #[test]
    fn an_end_of_track_and_group_marker_ends_one_past_the_last_object() {
        let allowed = encoded(&object(1, ObjectStatus::EndOfTrackAndGroup));
        assert!(
            allowed.is_ok(),
            "end of track and group ends one past the last object, not at zero: {allowed:?}",
        );
    }

    /// So does end of group, on the same reasoning.
    #[test]
    fn an_end_of_group_marker_ends_one_past_the_last_object() {
        encoded(&object(1, ObjectStatus::EndOfGroup))
            .expect("end of group ends one past the last object");
    }

    /// A normal object at a non-zero id is untouched by any of this.
    #[test]
    fn a_normal_object_is_not_held_to_the_rule() {
        encoded(&object(9, ObjectStatus::Normal)).expect("a normal object has no such rule");
    }

    /// The status datagram carries the same status field and the same rule, and
    /// had no checked entry point at all before this.
    #[test]
    fn a_status_datagram_states_the_rule_too() {
        let mut buf = Vec::new();
        let refused = status_datagram(1, ObjectStatus::EndOfTrack).encode_checked(&mut buf);
        assert!(
            matches!(refused, Err(CodecError::EndOfTrackObjectId(1))),
            "a datagram end of track ends at object zero: {refused:?}",
        );
        assert!(buf.is_empty(), "a refused header leaves the buffer untouched");

        let mut ok = Vec::new();
        status_datagram(0, ObjectStatus::EndOfTrack)
            .encode_checked(&mut ok)
            .expect("object zero is legal");
    }

    /// And so does the fetch object header.
    #[test]
    fn a_fetch_object_states_the_rule_too() {
        let mut buf = Vec::new();
        let refused = fetch_object(1, ObjectStatus::EndOfTrack).encode_checked(&mut buf);
        assert!(
            matches!(refused, Err(CodecError::EndOfTrackObjectId(1))),
            "a fetched end of track ends at object zero: {refused:?}",
        );

        let mut ok = Vec::new();
        fetch_object(0, ObjectStatus::EndOfTrack)
            .encode_checked(&mut ok)
            .expect("object zero is legal");
    }
}

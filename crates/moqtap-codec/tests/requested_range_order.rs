//! A requested range may not end before it starts.
//!
//! FETCH carries the rule on every draft: "Fetch specifies an inclusive range
//! of Objects starting at Start Location and ending at End Location. End
//! Location MUST specify the same or a larger Location than Start Location",
//! spelled with the field names each draft happens to use. SUBSCRIBE's
//! AbsoluteRange filter and SUBSCRIBE_UPDATE say the same of their own ends,
//! for as long as those messages carry the range as fields of their own.
//!
//! Nothing applied any of it, on either side, so a FETCH from group 100 to
//! group 5 was written and read without complaint. A range that ends before it
//! starts selects nothing, and the publisher's only answers are an error
//! response or a session close, so writing one is not a way to ask for
//! anything.
//!
//! Three field conventions meet here and the gates keep them apart. A SUBSCRIBE
//! End Group is inclusive. A SUBSCRIBE_UPDATE End Group is the last group plus
//! one, and zero means open ended. A FETCH End Object is the last object plus
//! one, and zero asks for the rest of the group. Each is exercised at the
//! boundary its own convention creates, so a check that collapsed the three
//! into one comparison would fail here rather than pass.
//!
//! The failure messages recorded in the tests below are draft-09's. Every draft
//! fails the same way; only the leading bytes of the frame differ, because the
//! field lists in front of the range are not the same on any two of them.

#![allow(clippy::items_after_test_module)]

use moqtap_codec::varint::VarInt;

fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).unwrap()
}

/// The group both ends of a legal range sit in, chosen so that it appears
/// exactly once in an encoded frame and can be found again by value.
const GROUP: u64 = 42;

#[cfg(feature = "draft07")]
mod draft07 {
    use super::{varint, GROUP};
    use moqtap_codec::draft07::message::*;
    #[allow(unused_imports)]
    use moqtap_codec::types::*;

    fn fetch(
        start_group: u64,
        start_object: u64,
        end_group: u64,
        end_object: u64,
    ) -> ControlMessage {
        ControlMessage::Fetch(Fetch {
            subscribe_id: varint(1),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            subscriber_priority: 2,
            group_order: GroupOrder::Ascending,
            start_group: varint(start_group),
            start_object: varint(start_object),
            end_group: varint(end_group),
            end_object: varint(end_object),
            parameters: vec![],
        })
    }

    fn encode(message: &ControlMessage) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message.encode(&mut buf)?;
        Ok(buf)
    }

    /// Move the end group of an encoded frame to a group before the start.
    ///
    /// The frame is one this codec built with both ends in the same group, so
    /// every byte around the one being moved is exactly what the encoder would
    /// have written. [`GROUP`] appears nowhere else in it, and the end group is
    /// the later of its two occurrences.
    fn move_end_before_start(mut buf: Vec<u8>) -> Vec<u8> {
        let at = buf
            .iter()
            .rposition(|b| u64::from(*b) == GROUP)
            .expect("the end group is in the frame");
        buf[at] = 7;
        buf
    }

    /// A FETCH whose end is in an earlier group than its start has no encoding.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a fetch cannot end in a group before its start:
    /// Ok([22, 15, 1, 2, 1, 1, 1, 2, 110, 115, 1, 116, 42, 0, 7, 0, 0])
    /// ```
    #[test]
    fn a_fetch_whose_range_ends_before_it_starts_never_reaches_the_wire() {
        let result = encode(&fetch(GROUP, 0, 7, 0));
        assert!(result.is_err(), "a fetch cannot end in a group before its start: {result:?}");
    }

    /// The end object is the last object plus one, so within one group an end
    /// object at or below the start selects nothing.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a fetch cannot end before the object it starts at:
    /// Ok([22, 15, 1, 2, 1, 1, 1, 2, 110, 115, 1, 116, 42, 9, 42, 4, 0])
    /// ```
    #[test]
    fn a_fetch_that_ends_at_an_earlier_object_in_the_start_group_never_reaches_the_wire() {
        let result = encode(&fetch(GROUP, 9, GROUP, 4));
        assert!(result.is_err(), "a fetch cannot end before the object it starts at: {result:?}");
    }

    /// And one that arrives anyway is refused rather than carried inwards.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// an inverted range is not a request: Ok(Fetch(Fetch { subscribe_id:
    /// VarInt(1), ..., start_group: Some(VarInt(42)), ..., end_group:
    /// Some(VarInt(7)), ... }))
    /// ```
    #[test]
    fn a_fetch_whose_range_ends_before_it_starts_is_refused_on_decode() {
        let buf = encode(&fetch(GROUP, 0, GROUP, 0)).expect("a range inside one group is legal");
        let moved = move_end_before_start(buf);

        let decoded = ControlMessage::decode(&mut &moved[..]);
        assert!(decoded.is_err(), "an inverted range is not a request: {decoded:?}");
    }

    /// The two shapes a legal range takes at the boundary: both ends in one
    /// group, and an end object of 0 asking for the rest of the start group.
    /// Without this the gates above would pass on an encoder that refused every
    /// FETCH.
    #[test]
    fn a_fetch_that_ends_where_it_starts_is_carried() {
        for (start_object, end_object) in [(0, 0), (4, 9), (9, 0)] {
            let message = fetch(GROUP, start_object, GROUP, end_object);
            let buf = encode(&message)
                .unwrap_or_else(|e| panic!("{start_object}..{end_object} is a range: {e:?}"));
            let decoded = ControlMessage::decode(&mut &buf[..]);
            assert_eq!(decoded.ok().as_ref(), Some(&message), "what this codec wrote it must read");
        }
    }

    fn subscribe(start_group: u64, start_object: u64, end_group: u64) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            subscribe_id: varint(1),
            track_alias: varint(2),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            subscriber_priority: 3,
            group_order: GroupOrder::Ascending,
            filter_type: FilterType::AbsoluteRange,
            start_location: Some(Location {
                group: varint(start_group),
                object: varint(start_object),
            }),
            end_group: Some(varint(end_group)),
            end_object: Some(varint(0)),
            parameters: vec![],
        })
    }

    fn subscribe_update(start_group: u64, start_object: u64, end_group: u64) -> ControlMessage {
        ControlMessage::SubscribeUpdate(SubscribeUpdate {
            subscribe_id: varint(1),
            start_group: varint(start_group),
            start_object: varint(start_object),
            end_group: varint(end_group),
            end_object: varint(0),
            subscriber_priority: 3,
            parameters: vec![],
        })
    }

    /// An AbsoluteRange subscription cannot end in a group before its start.
    ///
    /// Its End Group is inclusive rather than plus one, so an end group equal
    /// to the start group is the remainder of that group and is legal - the
    /// draft says so in as many words. Only a smaller one is refused.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a subscription cannot end before it starts:
    /// Ok([3, 15, 1, 2, 1, 2, 110, 115, 1, 116, 3, 1, 4, 42, 0, 7, 0])
    /// ```
    #[test]
    fn a_subscription_whose_end_group_precedes_its_start_never_reaches_the_wire() {
        let result = encode(&subscribe(GROUP, 0, 7));
        assert!(result.is_err(), "a subscription cannot end before it starts: {result:?}");

        let same = subscribe(GROUP, 0, GROUP);
        let buf = encode(&same).expect("an end group equal to the start group is the rest of it");
        let decoded = ControlMessage::decode(&mut &buf[..]);
        assert_eq!(decoded.ok().as_ref(), Some(&same), "what this codec wrote it must read");
    }

    /// And one that arrives anyway is refused rather than carried inwards.
    #[test]
    fn a_subscription_whose_end_group_precedes_its_start_is_refused_on_decode() {
        let buf = encode(&subscribe(GROUP, 0, GROUP)).expect("the same group is a range");
        let moved = move_end_before_start(buf);

        let decoded = ControlMessage::decode(&mut &moved[..]);
        assert!(decoded.is_err(), "an inverted filter is not a subscription: {decoded:?}");
    }

    /// SUBSCRIBE_UPDATE spells its End Group as the last group plus one, and a
    /// zero there is an open end rather than a bound at group zero.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// an update cannot end before it starts: Ok([2, 6, 1, 42, 0, 7, 3, 0])
    /// ```
    #[test]
    fn an_update_whose_end_group_precedes_its_start_never_reaches_the_wire() {
        let result = encode(&subscribe_update(GROUP, 0, 7));
        assert!(result.is_err(), "an update cannot end before it starts: {result:?}");
    }

    /// The zero that means "open ended" is not a range ending at group zero,
    /// and a check that read it as one would refuse every open update.
    ///
    /// Dropping the exemption fails with:
    ///
    /// ```text
    /// zero is an open end, not a bound: InvalidRange(42, 0, 0, 0)
    /// ```
    #[test]
    fn an_open_ended_update_is_carried() {
        let message = subscribe_update(GROUP, 0, 0);
        let buf = encode(&message).expect("zero is an open end, not a bound");
        let decoded = ControlMessage::decode(&mut &buf[..]);
        assert_eq!(decoded.ok().as_ref(), Some(&message), "what this codec wrote it must read");
    }
}

#[cfg(feature = "draft08")]
mod draft08 {
    use super::{varint, GROUP};
    use moqtap_codec::draft08::message::*;
    #[allow(unused_imports)]
    use moqtap_codec::types::*;

    fn fetch(
        start_group: u64,
        start_object: u64,
        end_group: u64,
        end_object: u64,
    ) -> ControlMessage {
        ControlMessage::Fetch(Fetch {
            subscribe_id: varint(1),
            subscriber_priority: 2,
            group_order: GroupOrder::Ascending,
            fetch_type: FetchType::Standalone,
            track_namespace: Some(TrackNamespace(vec![b"ns".to_vec()])),
            track_name: Some(b"t".to_vec()),
            start_group: Some(varint(start_group)),
            start_object: Some(varint(start_object)),
            end_group: Some(varint(end_group)),
            end_object: Some(varint(end_object)),
            joining_subscribe_id: None,
            preceding_group_offset: None,
            parameters: vec![],
        })
    }

    fn encode(message: &ControlMessage) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message.encode(&mut buf)?;
        Ok(buf)
    }

    /// Move the end group of an encoded frame to a group before the start.
    ///
    /// The frame is one this codec built with both ends in the same group, so
    /// every byte around the one being moved is exactly what the encoder would
    /// have written. [`GROUP`] appears nowhere else in it, and the end group is
    /// the later of its two occurrences.
    fn move_end_before_start(mut buf: Vec<u8>) -> Vec<u8> {
        let at = buf
            .iter()
            .rposition(|b| u64::from(*b) == GROUP)
            .expect("the end group is in the frame");
        buf[at] = 7;
        buf
    }

    /// A FETCH whose end is in an earlier group than its start has no encoding.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a fetch cannot end in a group before its start:
    /// Ok([22, 15, 1, 2, 1, 1, 1, 2, 110, 115, 1, 116, 42, 0, 7, 0, 0])
    /// ```
    #[test]
    fn a_fetch_whose_range_ends_before_it_starts_never_reaches_the_wire() {
        let result = encode(&fetch(GROUP, 0, 7, 0));
        assert!(result.is_err(), "a fetch cannot end in a group before its start: {result:?}");
    }

    /// The end object is the last object plus one, so within one group an end
    /// object at or below the start selects nothing.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a fetch cannot end before the object it starts at:
    /// Ok([22, 15, 1, 2, 1, 1, 1, 2, 110, 115, 1, 116, 42, 9, 42, 4, 0])
    /// ```
    #[test]
    fn a_fetch_that_ends_at_an_earlier_object_in_the_start_group_never_reaches_the_wire() {
        let result = encode(&fetch(GROUP, 9, GROUP, 4));
        assert!(result.is_err(), "a fetch cannot end before the object it starts at: {result:?}");
    }

    /// And one that arrives anyway is refused rather than carried inwards.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// an inverted range is not a request: Ok(Fetch(Fetch { subscribe_id:
    /// VarInt(1), ..., start_group: Some(VarInt(42)), ..., end_group:
    /// Some(VarInt(7)), ... }))
    /// ```
    #[test]
    fn a_fetch_whose_range_ends_before_it_starts_is_refused_on_decode() {
        let buf = encode(&fetch(GROUP, 0, GROUP, 0)).expect("a range inside one group is legal");
        let moved = move_end_before_start(buf);

        let decoded = ControlMessage::decode(&mut &moved[..]);
        assert!(decoded.is_err(), "an inverted range is not a request: {decoded:?}");
    }

    /// The two shapes a legal range takes at the boundary: both ends in one
    /// group, and an end object of 0 asking for the rest of the start group.
    /// Without this the gates above would pass on an encoder that refused every
    /// FETCH.
    #[test]
    fn a_fetch_that_ends_where_it_starts_is_carried() {
        for (start_object, end_object) in [(0, 0), (4, 9), (9, 0)] {
            let message = fetch(GROUP, start_object, GROUP, end_object);
            let buf = encode(&message)
                .unwrap_or_else(|e| panic!("{start_object}..{end_object} is a range: {e:?}"));
            let decoded = ControlMessage::decode(&mut &buf[..]);
            assert_eq!(decoded.ok().as_ref(), Some(&message), "what this codec wrote it must read");
        }
    }

    fn subscribe(start_group: u64, start_object: u64, end_group: u64) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            subscribe_id: varint(1),
            track_alias: varint(2),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            subscriber_priority: 3,
            group_order: GroupOrder::Ascending,
            filter_type: FilterType::AbsoluteRange,
            start_location: Some(Location {
                group: varint(start_group),
                object: varint(start_object),
            }),
            end_group: Some(varint(end_group)),
            parameters: vec![],
        })
    }

    fn subscribe_update(start_group: u64, start_object: u64, end_group: u64) -> ControlMessage {
        ControlMessage::SubscribeUpdate(SubscribeUpdate {
            subscribe_id: varint(1),
            start_group: varint(start_group),
            start_object: varint(start_object),
            end_group: varint(end_group),
            subscriber_priority: 3,
            parameters: vec![],
        })
    }

    /// An AbsoluteRange subscription cannot end in a group before its start.
    ///
    /// Its End Group is inclusive rather than plus one, so an end group equal
    /// to the start group is the remainder of that group and is legal - the
    /// draft says so in as many words. Only a smaller one is refused.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a subscription cannot end before it starts:
    /// Ok([3, 15, 1, 2, 1, 2, 110, 115, 1, 116, 3, 1, 4, 42, 0, 7, 0])
    /// ```
    #[test]
    fn a_subscription_whose_end_group_precedes_its_start_never_reaches_the_wire() {
        let result = encode(&subscribe(GROUP, 0, 7));
        assert!(result.is_err(), "a subscription cannot end before it starts: {result:?}");

        let same = subscribe(GROUP, 0, GROUP);
        let buf = encode(&same).expect("an end group equal to the start group is the rest of it");
        let decoded = ControlMessage::decode(&mut &buf[..]);
        assert_eq!(decoded.ok().as_ref(), Some(&same), "what this codec wrote it must read");
    }

    /// And one that arrives anyway is refused rather than carried inwards.
    #[test]
    fn a_subscription_whose_end_group_precedes_its_start_is_refused_on_decode() {
        let buf = encode(&subscribe(GROUP, 0, GROUP)).expect("the same group is a range");
        let moved = move_end_before_start(buf);

        let decoded = ControlMessage::decode(&mut &moved[..]);
        assert!(decoded.is_err(), "an inverted filter is not a subscription: {decoded:?}");
    }

    /// SUBSCRIBE_UPDATE spells its End Group as the last group plus one, and a
    /// zero there is an open end rather than a bound at group zero.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// an update cannot end before it starts: Ok([2, 6, 1, 42, 0, 7, 3, 0])
    /// ```
    #[test]
    fn an_update_whose_end_group_precedes_its_start_never_reaches_the_wire() {
        let result = encode(&subscribe_update(GROUP, 0, 7));
        assert!(result.is_err(), "an update cannot end before it starts: {result:?}");
    }

    /// The zero that means "open ended" is not a range ending at group zero,
    /// and a check that read it as one would refuse every open update.
    ///
    /// Dropping the exemption fails with:
    ///
    /// ```text
    /// zero is an open end, not a bound: InvalidRange(42, 0, 0, 0)
    /// ```
    #[test]
    fn an_open_ended_update_is_carried() {
        let message = subscribe_update(GROUP, 0, 0);
        let buf = encode(&message).expect("zero is an open end, not a bound");
        let decoded = ControlMessage::decode(&mut &buf[..]);
        assert_eq!(decoded.ok().as_ref(), Some(&message), "what this codec wrote it must read");
    }
}

#[cfg(feature = "draft09")]
mod draft09 {
    use super::{varint, GROUP};
    use moqtap_codec::draft09::message::*;
    #[allow(unused_imports)]
    use moqtap_codec::types::*;

    fn fetch(
        start_group: u64,
        start_object: u64,
        end_group: u64,
        end_object: u64,
    ) -> ControlMessage {
        ControlMessage::Fetch(Fetch {
            subscribe_id: varint(1),
            subscriber_priority: 2,
            group_order: GroupOrder::Ascending,
            fetch_type: FetchType::Standalone,
            track_namespace: Some(TrackNamespace(vec![b"ns".to_vec()])),
            track_name: Some(b"t".to_vec()),
            start_group: Some(varint(start_group)),
            start_object: Some(varint(start_object)),
            end_group: Some(varint(end_group)),
            end_object: Some(varint(end_object)),
            joining_subscribe_id: None,
            preceding_group_offset: None,
            parameters: vec![],
        })
    }

    fn encode(message: &ControlMessage) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message.encode(&mut buf)?;
        Ok(buf)
    }

    /// Move the end group of an encoded frame to a group before the start.
    ///
    /// The frame is one this codec built with both ends in the same group, so
    /// every byte around the one being moved is exactly what the encoder would
    /// have written. [`GROUP`] appears nowhere else in it, and the end group is
    /// the later of its two occurrences.
    fn move_end_before_start(mut buf: Vec<u8>) -> Vec<u8> {
        let at = buf
            .iter()
            .rposition(|b| u64::from(*b) == GROUP)
            .expect("the end group is in the frame");
        buf[at] = 7;
        buf
    }

    /// A FETCH whose end is in an earlier group than its start has no encoding.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a fetch cannot end in a group before its start:
    /// Ok([22, 15, 1, 2, 1, 1, 1, 2, 110, 115, 1, 116, 42, 0, 7, 0, 0])
    /// ```
    #[test]
    fn a_fetch_whose_range_ends_before_it_starts_never_reaches_the_wire() {
        let result = encode(&fetch(GROUP, 0, 7, 0));
        assert!(result.is_err(), "a fetch cannot end in a group before its start: {result:?}");
    }

    /// The end object is the last object plus one, so within one group an end
    /// object at or below the start selects nothing.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a fetch cannot end before the object it starts at:
    /// Ok([22, 15, 1, 2, 1, 1, 1, 2, 110, 115, 1, 116, 42, 9, 42, 4, 0])
    /// ```
    #[test]
    fn a_fetch_that_ends_at_an_earlier_object_in_the_start_group_never_reaches_the_wire() {
        let result = encode(&fetch(GROUP, 9, GROUP, 4));
        assert!(result.is_err(), "a fetch cannot end before the object it starts at: {result:?}");
    }

    /// And one that arrives anyway is refused rather than carried inwards.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// an inverted range is not a request: Ok(Fetch(Fetch { subscribe_id:
    /// VarInt(1), ..., start_group: Some(VarInt(42)), ..., end_group:
    /// Some(VarInt(7)), ... }))
    /// ```
    #[test]
    fn a_fetch_whose_range_ends_before_it_starts_is_refused_on_decode() {
        let buf = encode(&fetch(GROUP, 0, GROUP, 0)).expect("a range inside one group is legal");
        let moved = move_end_before_start(buf);

        let decoded = ControlMessage::decode(&mut &moved[..]);
        assert!(decoded.is_err(), "an inverted range is not a request: {decoded:?}");
    }

    /// The two shapes a legal range takes at the boundary: both ends in one
    /// group, and an end object of 0 asking for the rest of the start group.
    /// Without this the gates above would pass on an encoder that refused every
    /// FETCH.
    #[test]
    fn a_fetch_that_ends_where_it_starts_is_carried() {
        for (start_object, end_object) in [(0, 0), (4, 9), (9, 0)] {
            let message = fetch(GROUP, start_object, GROUP, end_object);
            let buf = encode(&message)
                .unwrap_or_else(|e| panic!("{start_object}..{end_object} is a range: {e:?}"));
            let decoded = ControlMessage::decode(&mut &buf[..]);
            assert_eq!(decoded.ok().as_ref(), Some(&message), "what this codec wrote it must read");
        }
    }

    fn subscribe(start_group: u64, start_object: u64, end_group: u64) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            subscribe_id: varint(1),
            track_alias: varint(2),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            subscriber_priority: 3,
            group_order: GroupOrder::Ascending,
            filter_type: FilterType::AbsoluteRange,
            start_location: Some(Location {
                group: varint(start_group),
                object: varint(start_object),
            }),
            end_group: Some(varint(end_group)),
            parameters: vec![],
        })
    }

    fn subscribe_update(start_group: u64, start_object: u64, end_group: u64) -> ControlMessage {
        ControlMessage::SubscribeUpdate(SubscribeUpdate {
            subscribe_id: varint(1),
            start_group: varint(start_group),
            start_object: varint(start_object),
            end_group: varint(end_group),
            subscriber_priority: 3,
            parameters: vec![],
        })
    }

    /// An AbsoluteRange subscription cannot end in a group before its start.
    ///
    /// Its End Group is inclusive rather than plus one, so an end group equal
    /// to the start group is the remainder of that group and is legal - the
    /// draft says so in as many words. Only a smaller one is refused.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a subscription cannot end before it starts:
    /// Ok([3, 15, 1, 2, 1, 2, 110, 115, 1, 116, 3, 1, 4, 42, 0, 7, 0])
    /// ```
    #[test]
    fn a_subscription_whose_end_group_precedes_its_start_never_reaches_the_wire() {
        let result = encode(&subscribe(GROUP, 0, 7));
        assert!(result.is_err(), "a subscription cannot end before it starts: {result:?}");

        let same = subscribe(GROUP, 0, GROUP);
        let buf = encode(&same).expect("an end group equal to the start group is the rest of it");
        let decoded = ControlMessage::decode(&mut &buf[..]);
        assert_eq!(decoded.ok().as_ref(), Some(&same), "what this codec wrote it must read");
    }

    /// And one that arrives anyway is refused rather than carried inwards.
    #[test]
    fn a_subscription_whose_end_group_precedes_its_start_is_refused_on_decode() {
        let buf = encode(&subscribe(GROUP, 0, GROUP)).expect("the same group is a range");
        let moved = move_end_before_start(buf);

        let decoded = ControlMessage::decode(&mut &moved[..]);
        assert!(decoded.is_err(), "an inverted filter is not a subscription: {decoded:?}");
    }

    /// SUBSCRIBE_UPDATE spells its End Group as the last group plus one, and a
    /// zero there is an open end rather than a bound at group zero.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// an update cannot end before it starts: Ok([2, 6, 1, 42, 0, 7, 3, 0])
    /// ```
    #[test]
    fn an_update_whose_end_group_precedes_its_start_never_reaches_the_wire() {
        let result = encode(&subscribe_update(GROUP, 0, 7));
        assert!(result.is_err(), "an update cannot end before it starts: {result:?}");
    }

    /// The zero that means "open ended" is not a range ending at group zero,
    /// and a check that read it as one would refuse every open update.
    ///
    /// Dropping the exemption fails with:
    ///
    /// ```text
    /// zero is an open end, not a bound: InvalidRange(42, 0, 0, 0)
    /// ```
    #[test]
    fn an_open_ended_update_is_carried() {
        let message = subscribe_update(GROUP, 0, 0);
        let buf = encode(&message).expect("zero is an open end, not a bound");
        let decoded = ControlMessage::decode(&mut &buf[..]);
        assert_eq!(decoded.ok().as_ref(), Some(&message), "what this codec wrote it must read");
    }
}

#[cfg(feature = "draft10")]
mod draft10 {
    use super::{varint, GROUP};
    use moqtap_codec::draft10::message::*;
    #[allow(unused_imports)]
    use moqtap_codec::types::*;

    fn fetch(
        start_group: u64,
        start_object: u64,
        end_group: u64,
        end_object: u64,
    ) -> ControlMessage {
        ControlMessage::Fetch(Fetch {
            subscribe_id: varint(1),
            subscriber_priority: 2,
            group_order: GroupOrder::Ascending,
            fetch_type: FetchType::Standalone,
            track_namespace: Some(TrackNamespace(vec![b"ns".to_vec()])),
            track_name: Some(b"t".to_vec()),
            start_group: Some(varint(start_group)),
            start_object: Some(varint(start_object)),
            end_group: Some(varint(end_group)),
            end_object: Some(varint(end_object)),
            joining_subscribe_id: None,
            preceding_group_offset: None,
            parameters: vec![],
        })
    }

    fn encode(message: &ControlMessage) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message.encode(&mut buf)?;
        Ok(buf)
    }

    /// Move the end group of an encoded frame to a group before the start.
    ///
    /// The frame is one this codec built with both ends in the same group, so
    /// every byte around the one being moved is exactly what the encoder would
    /// have written. [`GROUP`] appears nowhere else in it, and the end group is
    /// the later of its two occurrences.
    fn move_end_before_start(mut buf: Vec<u8>) -> Vec<u8> {
        let at = buf
            .iter()
            .rposition(|b| u64::from(*b) == GROUP)
            .expect("the end group is in the frame");
        buf[at] = 7;
        buf
    }

    /// A FETCH whose end is in an earlier group than its start has no encoding.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a fetch cannot end in a group before its start:
    /// Ok([22, 15, 1, 2, 1, 1, 1, 2, 110, 115, 1, 116, 42, 0, 7, 0, 0])
    /// ```
    #[test]
    fn a_fetch_whose_range_ends_before_it_starts_never_reaches_the_wire() {
        let result = encode(&fetch(GROUP, 0, 7, 0));
        assert!(result.is_err(), "a fetch cannot end in a group before its start: {result:?}");
    }

    /// The end object is the last object plus one, so within one group an end
    /// object at or below the start selects nothing.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a fetch cannot end before the object it starts at:
    /// Ok([22, 15, 1, 2, 1, 1, 1, 2, 110, 115, 1, 116, 42, 9, 42, 4, 0])
    /// ```
    #[test]
    fn a_fetch_that_ends_at_an_earlier_object_in_the_start_group_never_reaches_the_wire() {
        let result = encode(&fetch(GROUP, 9, GROUP, 4));
        assert!(result.is_err(), "a fetch cannot end before the object it starts at: {result:?}");
    }

    /// And one that arrives anyway is refused rather than carried inwards.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// an inverted range is not a request: Ok(Fetch(Fetch { subscribe_id:
    /// VarInt(1), ..., start_group: Some(VarInt(42)), ..., end_group:
    /// Some(VarInt(7)), ... }))
    /// ```
    #[test]
    fn a_fetch_whose_range_ends_before_it_starts_is_refused_on_decode() {
        let buf = encode(&fetch(GROUP, 0, GROUP, 0)).expect("a range inside one group is legal");
        let moved = move_end_before_start(buf);

        let decoded = ControlMessage::decode(&mut &moved[..]);
        assert!(decoded.is_err(), "an inverted range is not a request: {decoded:?}");
    }

    /// The two shapes a legal range takes at the boundary: both ends in one
    /// group, and an end object of 0 asking for the rest of the start group.
    /// Without this the gates above would pass on an encoder that refused every
    /// FETCH.
    #[test]
    fn a_fetch_that_ends_where_it_starts_is_carried() {
        for (start_object, end_object) in [(0, 0), (4, 9), (9, 0)] {
            let message = fetch(GROUP, start_object, GROUP, end_object);
            let buf = encode(&message)
                .unwrap_or_else(|e| panic!("{start_object}..{end_object} is a range: {e:?}"));
            let decoded = ControlMessage::decode(&mut &buf[..]);
            assert_eq!(decoded.ok().as_ref(), Some(&message), "what this codec wrote it must read");
        }
    }

    fn subscribe(start_group: u64, start_object: u64, end_group: u64) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            subscribe_id: varint(1),
            track_alias: varint(2),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            subscriber_priority: 3,
            group_order: GroupOrder::Ascending,
            filter_type: FilterType::AbsoluteRange,
            start_location: Some(Location {
                group: varint(start_group),
                object: varint(start_object),
            }),
            end_group: Some(varint(end_group)),
            parameters: vec![],
        })
    }

    fn subscribe_update(start_group: u64, start_object: u64, end_group: u64) -> ControlMessage {
        ControlMessage::SubscribeUpdate(SubscribeUpdate {
            subscribe_id: varint(1),
            start_group: varint(start_group),
            start_object: varint(start_object),
            end_group: varint(end_group),
            subscriber_priority: 3,
            parameters: vec![],
        })
    }

    /// An AbsoluteRange subscription cannot end in a group before its start.
    ///
    /// Its End Group is inclusive rather than plus one, so an end group equal
    /// to the start group is the remainder of that group and is legal - the
    /// draft says so in as many words. Only a smaller one is refused.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a subscription cannot end before it starts:
    /// Ok([3, 15, 1, 2, 1, 2, 110, 115, 1, 116, 3, 1, 4, 42, 0, 7, 0])
    /// ```
    #[test]
    fn a_subscription_whose_end_group_precedes_its_start_never_reaches_the_wire() {
        let result = encode(&subscribe(GROUP, 0, 7));
        assert!(result.is_err(), "a subscription cannot end before it starts: {result:?}");

        let same = subscribe(GROUP, 0, GROUP);
        let buf = encode(&same).expect("an end group equal to the start group is the rest of it");
        let decoded = ControlMessage::decode(&mut &buf[..]);
        assert_eq!(decoded.ok().as_ref(), Some(&same), "what this codec wrote it must read");
    }

    /// And one that arrives anyway is refused rather than carried inwards.
    #[test]
    fn a_subscription_whose_end_group_precedes_its_start_is_refused_on_decode() {
        let buf = encode(&subscribe(GROUP, 0, GROUP)).expect("the same group is a range");
        let moved = move_end_before_start(buf);

        let decoded = ControlMessage::decode(&mut &moved[..]);
        assert!(decoded.is_err(), "an inverted filter is not a subscription: {decoded:?}");
    }

    /// SUBSCRIBE_UPDATE spells its End Group as the last group plus one, and a
    /// zero there is an open end rather than a bound at group zero.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// an update cannot end before it starts: Ok([2, 6, 1, 42, 0, 7, 3, 0])
    /// ```
    #[test]
    fn an_update_whose_end_group_precedes_its_start_never_reaches_the_wire() {
        let result = encode(&subscribe_update(GROUP, 0, 7));
        assert!(result.is_err(), "an update cannot end before it starts: {result:?}");
    }

    /// The zero that means "open ended" is not a range ending at group zero,
    /// and a check that read it as one would refuse every open update.
    ///
    /// Dropping the exemption fails with:
    ///
    /// ```text
    /// zero is an open end, not a bound: InvalidRange(42, 0, 0, 0)
    /// ```
    #[test]
    fn an_open_ended_update_is_carried() {
        let message = subscribe_update(GROUP, 0, 0);
        let buf = encode(&message).expect("zero is an open end, not a bound");
        let decoded = ControlMessage::decode(&mut &buf[..]);
        assert_eq!(decoded.ok().as_ref(), Some(&message), "what this codec wrote it must read");
    }
}

#[cfg(feature = "draft11")]
mod draft11 {
    use super::{varint, GROUP};
    use moqtap_codec::draft11::message::*;
    #[allow(unused_imports)]
    use moqtap_codec::types::*;

    fn fetch(
        start_group: u64,
        start_object: u64,
        end_group: u64,
        end_object: u64,
    ) -> ControlMessage {
        ControlMessage::Fetch(Fetch {
            request_id: varint(1),
            subscriber_priority: 2,
            group_order: GroupOrder::Ascending,
            fetch_type: FetchType::Standalone,
            fetch_payload: FetchPayload::Standalone {
                track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
                track_name: b"t".to_vec(),
                start_group: varint(start_group),
                start_object: varint(start_object),
                end_group: varint(end_group),
                end_object: varint(end_object),
            },
            parameters: vec![],
        })
    }

    fn encode(message: &ControlMessage) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message.encode(&mut buf)?;
        Ok(buf)
    }

    /// Move the end group of an encoded frame to a group before the start.
    ///
    /// The frame is one this codec built with both ends in the same group, so
    /// every byte around the one being moved is exactly what the encoder would
    /// have written. [`GROUP`] appears nowhere else in it, and the end group is
    /// the later of its two occurrences.
    fn move_end_before_start(mut buf: Vec<u8>) -> Vec<u8> {
        let at = buf
            .iter()
            .rposition(|b| u64::from(*b) == GROUP)
            .expect("the end group is in the frame");
        buf[at] = 7;
        buf
    }

    /// A FETCH whose end is in an earlier group than its start has no encoding.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a fetch cannot end in a group before its start:
    /// Ok([22, 15, 1, 2, 1, 1, 1, 2, 110, 115, 1, 116, 42, 0, 7, 0, 0])
    /// ```
    #[test]
    fn a_fetch_whose_range_ends_before_it_starts_never_reaches_the_wire() {
        let result = encode(&fetch(GROUP, 0, 7, 0));
        assert!(result.is_err(), "a fetch cannot end in a group before its start: {result:?}");
    }

    /// The end object is the last object plus one, so within one group an end
    /// object at or below the start selects nothing.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a fetch cannot end before the object it starts at:
    /// Ok([22, 15, 1, 2, 1, 1, 1, 2, 110, 115, 1, 116, 42, 9, 42, 4, 0])
    /// ```
    #[test]
    fn a_fetch_that_ends_at_an_earlier_object_in_the_start_group_never_reaches_the_wire() {
        let result = encode(&fetch(GROUP, 9, GROUP, 4));
        assert!(result.is_err(), "a fetch cannot end before the object it starts at: {result:?}");
    }

    /// And one that arrives anyway is refused rather than carried inwards.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// an inverted range is not a request: Ok(Fetch(Fetch { subscribe_id:
    /// VarInt(1), ..., start_group: Some(VarInt(42)), ..., end_group:
    /// Some(VarInt(7)), ... }))
    /// ```
    #[test]
    fn a_fetch_whose_range_ends_before_it_starts_is_refused_on_decode() {
        let buf = encode(&fetch(GROUP, 0, GROUP, 0)).expect("a range inside one group is legal");
        let moved = move_end_before_start(buf);

        let decoded = ControlMessage::decode(&mut &moved[..]);
        assert!(decoded.is_err(), "an inverted range is not a request: {decoded:?}");
    }

    /// The two shapes a legal range takes at the boundary: both ends in one
    /// group, and an end object of 0 asking for the rest of the start group.
    /// Without this the gates above would pass on an encoder that refused every
    /// FETCH.
    #[test]
    fn a_fetch_that_ends_where_it_starts_is_carried() {
        for (start_object, end_object) in [(0, 0), (4, 9), (9, 0)] {
            let message = fetch(GROUP, start_object, GROUP, end_object);
            let buf = encode(&message)
                .unwrap_or_else(|e| panic!("{start_object}..{end_object} is a range: {e:?}"));
            let decoded = ControlMessage::decode(&mut &buf[..]);
            assert_eq!(decoded.ok().as_ref(), Some(&message), "what this codec wrote it must read");
        }
    }

    fn subscribe(start_group: u64, start_object: u64, end_group: u64) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            request_id: varint(1),
            track_alias: varint(2),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            subscriber_priority: 3,
            group_order: GroupOrder::Ascending,
            forward: Forward::Forward,
            filter_type: varint(0x4),
            start_group: Some(varint(start_group)),
            start_object: Some(varint(start_object)),
            end_group: Some(varint(end_group)),
            parameters: vec![],
        })
    }

    fn subscribe_update(start_group: u64, start_object: u64, end_group: u64) -> ControlMessage {
        ControlMessage::SubscribeUpdate(SubscribeUpdate {
            request_id: varint(1),
            start_group: varint(start_group),
            start_object: varint(start_object),
            end_group: varint(end_group),
            subscriber_priority: 3,
            forward: Forward::Forward,
            parameters: vec![],
        })
    }

    /// An AbsoluteRange subscription cannot end in a group before its start.
    ///
    /// Its End Group is inclusive rather than plus one, so an end group equal
    /// to the start group is the remainder of that group and is legal - the
    /// draft says so in as many words. Only a smaller one is refused.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a subscription cannot end before it starts:
    /// Ok([3, 15, 1, 2, 1, 2, 110, 115, 1, 116, 3, 1, 4, 42, 0, 7, 0])
    /// ```
    #[test]
    fn a_subscription_whose_end_group_precedes_its_start_never_reaches_the_wire() {
        let result = encode(&subscribe(GROUP, 0, 7));
        assert!(result.is_err(), "a subscription cannot end before it starts: {result:?}");

        let same = subscribe(GROUP, 0, GROUP);
        let buf = encode(&same).expect("an end group equal to the start group is the rest of it");
        let decoded = ControlMessage::decode(&mut &buf[..]);
        assert_eq!(decoded.ok().as_ref(), Some(&same), "what this codec wrote it must read");
    }

    /// And one that arrives anyway is refused rather than carried inwards.
    #[test]
    fn a_subscription_whose_end_group_precedes_its_start_is_refused_on_decode() {
        let buf = encode(&subscribe(GROUP, 0, GROUP)).expect("the same group is a range");
        let moved = move_end_before_start(buf);

        let decoded = ControlMessage::decode(&mut &moved[..]);
        assert!(decoded.is_err(), "an inverted filter is not a subscription: {decoded:?}");
    }

    /// SUBSCRIBE_UPDATE spells its End Group as the last group plus one, and a
    /// zero there is an open end rather than a bound at group zero.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// an update cannot end before it starts: Ok([2, 6, 1, 42, 0, 7, 3, 0])
    /// ```
    #[test]
    fn an_update_whose_end_group_precedes_its_start_never_reaches_the_wire() {
        let result = encode(&subscribe_update(GROUP, 0, 7));
        assert!(result.is_err(), "an update cannot end before it starts: {result:?}");
    }

    /// The zero that means "open ended" is not a range ending at group zero,
    /// and a check that read it as one would refuse every open update.
    ///
    /// Dropping the exemption fails with:
    ///
    /// ```text
    /// zero is an open end, not a bound: InvalidRange(42, 0, 0, 0)
    /// ```
    #[test]
    fn an_open_ended_update_is_carried() {
        let message = subscribe_update(GROUP, 0, 0);
        let buf = encode(&message).expect("zero is an open end, not a bound");
        let decoded = ControlMessage::decode(&mut &buf[..]);
        assert_eq!(decoded.ok().as_ref(), Some(&message), "what this codec wrote it must read");
    }
}

#[cfg(feature = "draft12")]
mod draft12 {
    use super::{varint, GROUP};
    use moqtap_codec::draft12::message::*;
    #[allow(unused_imports)]
    use moqtap_codec::types::*;

    fn fetch(
        start_group: u64,
        start_object: u64,
        end_group: u64,
        end_object: u64,
    ) -> ControlMessage {
        ControlMessage::Fetch(Fetch {
            request_id: varint(1),
            subscriber_priority: 2,
            group_order: GroupOrder::Ascending,
            fetch_type: FetchType::Standalone,
            fetch_payload: FetchPayload::Standalone {
                track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
                track_name: b"t".to_vec(),
                start_group: varint(start_group),
                start_object: varint(start_object),
                end_group: varint(end_group),
                end_object: varint(end_object),
            },
            parameters: vec![],
        })
    }

    fn encode(message: &ControlMessage) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message.encode(&mut buf)?;
        Ok(buf)
    }

    /// Move the end group of an encoded frame to a group before the start.
    ///
    /// The frame is one this codec built with both ends in the same group, so
    /// every byte around the one being moved is exactly what the encoder would
    /// have written. [`GROUP`] appears nowhere else in it, and the end group is
    /// the later of its two occurrences.
    fn move_end_before_start(mut buf: Vec<u8>) -> Vec<u8> {
        let at = buf
            .iter()
            .rposition(|b| u64::from(*b) == GROUP)
            .expect("the end group is in the frame");
        buf[at] = 7;
        buf
    }

    /// A FETCH whose end is in an earlier group than its start has no encoding.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a fetch cannot end in a group before its start:
    /// Ok([22, 15, 1, 2, 1, 1, 1, 2, 110, 115, 1, 116, 42, 0, 7, 0, 0])
    /// ```
    #[test]
    fn a_fetch_whose_range_ends_before_it_starts_never_reaches_the_wire() {
        let result = encode(&fetch(GROUP, 0, 7, 0));
        assert!(result.is_err(), "a fetch cannot end in a group before its start: {result:?}");
    }

    /// The end object is the last object plus one, so within one group an end
    /// object at or below the start selects nothing.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a fetch cannot end before the object it starts at:
    /// Ok([22, 15, 1, 2, 1, 1, 1, 2, 110, 115, 1, 116, 42, 9, 42, 4, 0])
    /// ```
    #[test]
    fn a_fetch_that_ends_at_an_earlier_object_in_the_start_group_never_reaches_the_wire() {
        let result = encode(&fetch(GROUP, 9, GROUP, 4));
        assert!(result.is_err(), "a fetch cannot end before the object it starts at: {result:?}");
    }

    /// And one that arrives anyway is refused rather than carried inwards.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// an inverted range is not a request: Ok(Fetch(Fetch { subscribe_id:
    /// VarInt(1), ..., start_group: Some(VarInt(42)), ..., end_group:
    /// Some(VarInt(7)), ... }))
    /// ```
    #[test]
    fn a_fetch_whose_range_ends_before_it_starts_is_refused_on_decode() {
        let buf = encode(&fetch(GROUP, 0, GROUP, 0)).expect("a range inside one group is legal");
        let moved = move_end_before_start(buf);

        let decoded = ControlMessage::decode(&mut &moved[..]);
        assert!(decoded.is_err(), "an inverted range is not a request: {decoded:?}");
    }

    /// The two shapes a legal range takes at the boundary: both ends in one
    /// group, and an end object of 0 asking for the rest of the start group.
    /// Without this the gates above would pass on an encoder that refused every
    /// FETCH.
    #[test]
    fn a_fetch_that_ends_where_it_starts_is_carried() {
        for (start_object, end_object) in [(0, 0), (4, 9), (9, 0)] {
            let message = fetch(GROUP, start_object, GROUP, end_object);
            let buf = encode(&message)
                .unwrap_or_else(|e| panic!("{start_object}..{end_object} is a range: {e:?}"));
            let decoded = ControlMessage::decode(&mut &buf[..]);
            assert_eq!(decoded.ok().as_ref(), Some(&message), "what this codec wrote it must read");
        }
    }

    fn subscribe(start_group: u64, start_object: u64, end_group: u64) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            request_id: varint(1),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            subscriber_priority: 3,
            group_order: GroupOrder::Ascending,
            forward: Forward::Forward,
            filter_type: varint(0x4),
            start_group: Some(varint(start_group)),
            start_object: Some(varint(start_object)),
            end_group: Some(varint(end_group)),
            parameters: vec![],
        })
    }

    fn subscribe_update(start_group: u64, start_object: u64, end_group: u64) -> ControlMessage {
        ControlMessage::SubscribeUpdate(SubscribeUpdate {
            request_id: varint(1),
            start_group: varint(start_group),
            start_object: varint(start_object),
            end_group: varint(end_group),
            subscriber_priority: 3,
            forward: Forward::Forward,
            parameters: vec![],
        })
    }

    /// An AbsoluteRange subscription cannot end in a group before its start.
    ///
    /// Its End Group is inclusive rather than plus one, so an end group equal
    /// to the start group is the remainder of that group and is legal - the
    /// draft says so in as many words. Only a smaller one is refused.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a subscription cannot end before it starts:
    /// Ok([3, 15, 1, 2, 1, 2, 110, 115, 1, 116, 3, 1, 4, 42, 0, 7, 0])
    /// ```
    #[test]
    fn a_subscription_whose_end_group_precedes_its_start_never_reaches_the_wire() {
        let result = encode(&subscribe(GROUP, 0, 7));
        assert!(result.is_err(), "a subscription cannot end before it starts: {result:?}");

        let same = subscribe(GROUP, 0, GROUP);
        let buf = encode(&same).expect("an end group equal to the start group is the rest of it");
        let decoded = ControlMessage::decode(&mut &buf[..]);
        assert_eq!(decoded.ok().as_ref(), Some(&same), "what this codec wrote it must read");
    }

    /// And one that arrives anyway is refused rather than carried inwards.
    #[test]
    fn a_subscription_whose_end_group_precedes_its_start_is_refused_on_decode() {
        let buf = encode(&subscribe(GROUP, 0, GROUP)).expect("the same group is a range");
        let moved = move_end_before_start(buf);

        let decoded = ControlMessage::decode(&mut &moved[..]);
        assert!(decoded.is_err(), "an inverted filter is not a subscription: {decoded:?}");
    }

    /// SUBSCRIBE_UPDATE spells its End Group as the last group plus one, and a
    /// zero there is an open end rather than a bound at group zero.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// an update cannot end before it starts: Ok([2, 6, 1, 42, 0, 7, 3, 0])
    /// ```
    #[test]
    fn an_update_whose_end_group_precedes_its_start_never_reaches_the_wire() {
        let result = encode(&subscribe_update(GROUP, 0, 7));
        assert!(result.is_err(), "an update cannot end before it starts: {result:?}");
    }

    /// The zero that means "open ended" is not a range ending at group zero,
    /// and a check that read it as one would refuse every open update.
    ///
    /// Dropping the exemption fails with:
    ///
    /// ```text
    /// zero is an open end, not a bound: InvalidRange(42, 0, 0, 0)
    /// ```
    #[test]
    fn an_open_ended_update_is_carried() {
        let message = subscribe_update(GROUP, 0, 0);
        let buf = encode(&message).expect("zero is an open end, not a bound");
        let decoded = ControlMessage::decode(&mut &buf[..]);
        assert_eq!(decoded.ok().as_ref(), Some(&message), "what this codec wrote it must read");
    }
}

#[cfg(feature = "draft13")]
mod draft13 {
    use super::{varint, GROUP};
    use moqtap_codec::draft13::message::*;
    #[allow(unused_imports)]
    use moqtap_codec::types::*;

    fn fetch(
        start_group: u64,
        start_object: u64,
        end_group: u64,
        end_object: u64,
    ) -> ControlMessage {
        ControlMessage::Fetch(Fetch {
            request_id: varint(1),
            subscriber_priority: 2,
            group_order: GroupOrder::Ascending,
            fetch_type: FetchType::Standalone,
            fetch_payload: FetchPayload::Standalone {
                track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
                track_name: b"t".to_vec(),
                start_group: varint(start_group),
                start_object: varint(start_object),
                end_group: varint(end_group),
                end_object: varint(end_object),
            },
            parameters: vec![],
        })
    }

    fn encode(message: &ControlMessage) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message.encode(&mut buf)?;
        Ok(buf)
    }

    /// Move the end group of an encoded frame to a group before the start.
    ///
    /// The frame is one this codec built with both ends in the same group, so
    /// every byte around the one being moved is exactly what the encoder would
    /// have written. [`GROUP`] appears nowhere else in it, and the end group is
    /// the later of its two occurrences.
    fn move_end_before_start(mut buf: Vec<u8>) -> Vec<u8> {
        let at = buf
            .iter()
            .rposition(|b| u64::from(*b) == GROUP)
            .expect("the end group is in the frame");
        buf[at] = 7;
        buf
    }

    /// A FETCH whose end is in an earlier group than its start has no encoding.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a fetch cannot end in a group before its start:
    /// Ok([22, 15, 1, 2, 1, 1, 1, 2, 110, 115, 1, 116, 42, 0, 7, 0, 0])
    /// ```
    #[test]
    fn a_fetch_whose_range_ends_before_it_starts_never_reaches_the_wire() {
        let result = encode(&fetch(GROUP, 0, 7, 0));
        assert!(result.is_err(), "a fetch cannot end in a group before its start: {result:?}");
    }

    /// The end object is the last object plus one, so within one group an end
    /// object at or below the start selects nothing.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a fetch cannot end before the object it starts at:
    /// Ok([22, 15, 1, 2, 1, 1, 1, 2, 110, 115, 1, 116, 42, 9, 42, 4, 0])
    /// ```
    #[test]
    fn a_fetch_that_ends_at_an_earlier_object_in_the_start_group_never_reaches_the_wire() {
        let result = encode(&fetch(GROUP, 9, GROUP, 4));
        assert!(result.is_err(), "a fetch cannot end before the object it starts at: {result:?}");
    }

    /// And one that arrives anyway is refused rather than carried inwards.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// an inverted range is not a request: Ok(Fetch(Fetch { subscribe_id:
    /// VarInt(1), ..., start_group: Some(VarInt(42)), ..., end_group:
    /// Some(VarInt(7)), ... }))
    /// ```
    #[test]
    fn a_fetch_whose_range_ends_before_it_starts_is_refused_on_decode() {
        let buf = encode(&fetch(GROUP, 0, GROUP, 0)).expect("a range inside one group is legal");
        let moved = move_end_before_start(buf);

        let decoded = ControlMessage::decode(&mut &moved[..]);
        assert!(decoded.is_err(), "an inverted range is not a request: {decoded:?}");
    }

    /// The two shapes a legal range takes at the boundary: both ends in one
    /// group, and an end object of 0 asking for the rest of the start group.
    /// Without this the gates above would pass on an encoder that refused every
    /// FETCH.
    #[test]
    fn a_fetch_that_ends_where_it_starts_is_carried() {
        for (start_object, end_object) in [(0, 0), (4, 9), (9, 0)] {
            let message = fetch(GROUP, start_object, GROUP, end_object);
            let buf = encode(&message)
                .unwrap_or_else(|e| panic!("{start_object}..{end_object} is a range: {e:?}"));
            let decoded = ControlMessage::decode(&mut &buf[..]);
            assert_eq!(decoded.ok().as_ref(), Some(&message), "what this codec wrote it must read");
        }
    }

    fn subscribe(start_group: u64, start_object: u64, end_group: u64) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            request_id: varint(1),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            subscriber_priority: 3,
            group_order: GroupOrder::Ascending,
            forward: Forward::Forward,
            filter_type: FilterType::AbsoluteRange,
            start_group: Some(varint(start_group)),
            start_object: Some(varint(start_object)),
            end_group: Some(varint(end_group)),
            parameters: vec![],
        })
    }

    fn subscribe_update(start_group: u64, start_object: u64, end_group: u64) -> ControlMessage {
        ControlMessage::SubscribeUpdate(SubscribeUpdate {
            request_id: varint(1),
            start_group: varint(start_group),
            start_object: varint(start_object),
            end_group: varint(end_group),
            subscriber_priority: 3,
            forward: Forward::Forward,
            parameters: vec![],
        })
    }

    /// An AbsoluteRange subscription cannot end in a group before its start.
    ///
    /// Its End Group is inclusive rather than plus one, so an end group equal
    /// to the start group is the remainder of that group and is legal - the
    /// draft says so in as many words. Only a smaller one is refused.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a subscription cannot end before it starts:
    /// Ok([3, 15, 1, 2, 1, 2, 110, 115, 1, 116, 3, 1, 4, 42, 0, 7, 0])
    /// ```
    #[test]
    fn a_subscription_whose_end_group_precedes_its_start_never_reaches_the_wire() {
        let result = encode(&subscribe(GROUP, 0, 7));
        assert!(result.is_err(), "a subscription cannot end before it starts: {result:?}");

        let same = subscribe(GROUP, 0, GROUP);
        let buf = encode(&same).expect("an end group equal to the start group is the rest of it");
        let decoded = ControlMessage::decode(&mut &buf[..]);
        assert_eq!(decoded.ok().as_ref(), Some(&same), "what this codec wrote it must read");
    }

    /// And one that arrives anyway is refused rather than carried inwards.
    #[test]
    fn a_subscription_whose_end_group_precedes_its_start_is_refused_on_decode() {
        let buf = encode(&subscribe(GROUP, 0, GROUP)).expect("the same group is a range");
        let moved = move_end_before_start(buf);

        let decoded = ControlMessage::decode(&mut &moved[..]);
        assert!(decoded.is_err(), "an inverted filter is not a subscription: {decoded:?}");
    }

    /// SUBSCRIBE_UPDATE spells its End Group as the last group plus one, and a
    /// zero there is an open end rather than a bound at group zero.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// an update cannot end before it starts: Ok([2, 6, 1, 42, 0, 7, 3, 0])
    /// ```
    #[test]
    fn an_update_whose_end_group_precedes_its_start_never_reaches_the_wire() {
        let result = encode(&subscribe_update(GROUP, 0, 7));
        assert!(result.is_err(), "an update cannot end before it starts: {result:?}");
    }

    /// The zero that means "open ended" is not a range ending at group zero,
    /// and a check that read it as one would refuse every open update.
    ///
    /// Dropping the exemption fails with:
    ///
    /// ```text
    /// zero is an open end, not a bound: InvalidRange(42, 0, 0, 0)
    /// ```
    #[test]
    fn an_open_ended_update_is_carried() {
        let message = subscribe_update(GROUP, 0, 0);
        let buf = encode(&message).expect("zero is an open end, not a bound");
        let decoded = ControlMessage::decode(&mut &buf[..]);
        assert_eq!(decoded.ok().as_ref(), Some(&message), "what this codec wrote it must read");
    }
}

#[cfg(feature = "draft14")]
mod draft14 {
    use super::{varint, GROUP};
    use moqtap_codec::draft14::message::*;
    #[allow(unused_imports)]
    use moqtap_codec::types::*;

    fn fetch(
        start_group: u64,
        start_object: u64,
        end_group: u64,
        end_object: u64,
    ) -> ControlMessage {
        ControlMessage::Fetch(Fetch {
            request_id: varint(1),
            subscriber_priority: 2,
            group_order: GroupOrder::Ascending,
            fetch_type: FetchType::Standalone,
            fetch_payload: FetchPayload::Standalone {
                track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
                track_name: b"t".to_vec(),
                start_group: varint(start_group),
                start_object: varint(start_object),
                end_group: varint(end_group),
                end_object: varint(end_object),
            },
            parameters: vec![],
        })
    }

    fn encode(message: &ControlMessage) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message.encode(&mut buf)?;
        Ok(buf)
    }

    /// Move the end group of an encoded frame to a group before the start.
    ///
    /// The frame is one this codec built with both ends in the same group, so
    /// every byte around the one being moved is exactly what the encoder would
    /// have written. [`GROUP`] appears nowhere else in it, and the end group is
    /// the later of its two occurrences.
    fn move_end_before_start(mut buf: Vec<u8>) -> Vec<u8> {
        let at = buf
            .iter()
            .rposition(|b| u64::from(*b) == GROUP)
            .expect("the end group is in the frame");
        buf[at] = 7;
        buf
    }

    /// A FETCH whose end is in an earlier group than its start has no encoding.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a fetch cannot end in a group before its start:
    /// Ok([22, 15, 1, 2, 1, 1, 1, 2, 110, 115, 1, 116, 42, 0, 7, 0, 0])
    /// ```
    #[test]
    fn a_fetch_whose_range_ends_before_it_starts_never_reaches_the_wire() {
        let result = encode(&fetch(GROUP, 0, 7, 0));
        assert!(result.is_err(), "a fetch cannot end in a group before its start: {result:?}");
    }

    /// The end object is the last object plus one, so within one group an end
    /// object at or below the start selects nothing.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a fetch cannot end before the object it starts at:
    /// Ok([22, 15, 1, 2, 1, 1, 1, 2, 110, 115, 1, 116, 42, 9, 42, 4, 0])
    /// ```
    #[test]
    fn a_fetch_that_ends_at_an_earlier_object_in_the_start_group_never_reaches_the_wire() {
        let result = encode(&fetch(GROUP, 9, GROUP, 4));
        assert!(result.is_err(), "a fetch cannot end before the object it starts at: {result:?}");
    }

    /// And one that arrives anyway is refused rather than carried inwards.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// an inverted range is not a request: Ok(Fetch(Fetch { subscribe_id:
    /// VarInt(1), ..., start_group: Some(VarInt(42)), ..., end_group:
    /// Some(VarInt(7)), ... }))
    /// ```
    #[test]
    fn a_fetch_whose_range_ends_before_it_starts_is_refused_on_decode() {
        let buf = encode(&fetch(GROUP, 0, GROUP, 0)).expect("a range inside one group is legal");
        let moved = move_end_before_start(buf);

        let decoded = ControlMessage::decode(&mut &moved[..]);
        assert!(decoded.is_err(), "an inverted range is not a request: {decoded:?}");
    }

    /// The two shapes a legal range takes at the boundary: both ends in one
    /// group, and an end object of 0 asking for the rest of the start group.
    /// Without this the gates above would pass on an encoder that refused every
    /// FETCH.
    #[test]
    fn a_fetch_that_ends_where_it_starts_is_carried() {
        for (start_object, end_object) in [(0, 0), (4, 9), (9, 0)] {
            let message = fetch(GROUP, start_object, GROUP, end_object);
            let buf = encode(&message)
                .unwrap_or_else(|e| panic!("{start_object}..{end_object} is a range: {e:?}"));
            let decoded = ControlMessage::decode(&mut &buf[..]);
            assert_eq!(decoded.ok().as_ref(), Some(&message), "what this codec wrote it must read");
        }
    }

    fn subscribe(start_group: u64, start_object: u64, end_group: u64) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            request_id: varint(1),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            subscriber_priority: 3,
            group_order: GroupOrder::Ascending,
            forward: Forward::Forward,
            filter_type: FilterType::AbsoluteRange,
            start_location: Some(Location {
                group: varint(start_group),
                object: varint(start_object),
            }),
            end_group: Some(varint(end_group)),
            parameters: vec![],
        })
    }

    fn subscribe_update(start_group: u64, start_object: u64, end_group: u64) -> ControlMessage {
        ControlMessage::SubscribeUpdate(SubscribeUpdate {
            request_id: varint(1),
            subscription_request_id: varint(2),
            start_location: Location { group: varint(start_group), object: varint(start_object) },
            end_group: varint(end_group),
            subscriber_priority: 3,
            forward: Forward::Forward,
            parameters: vec![],
        })
    }

    /// An AbsoluteRange subscription cannot end in a group before its start.
    ///
    /// Its End Group is inclusive rather than plus one, so an end group equal
    /// to the start group is the remainder of that group and is legal - the
    /// draft says so in as many words. Only a smaller one is refused.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a subscription cannot end before it starts:
    /// Ok([3, 15, 1, 2, 1, 2, 110, 115, 1, 116, 3, 1, 4, 42, 0, 7, 0])
    /// ```
    #[test]
    fn a_subscription_whose_end_group_precedes_its_start_never_reaches_the_wire() {
        let result = encode(&subscribe(GROUP, 0, 7));
        assert!(result.is_err(), "a subscription cannot end before it starts: {result:?}");

        let same = subscribe(GROUP, 0, GROUP);
        let buf = encode(&same).expect("an end group equal to the start group is the rest of it");
        let decoded = ControlMessage::decode(&mut &buf[..]);
        assert_eq!(decoded.ok().as_ref(), Some(&same), "what this codec wrote it must read");
    }

    /// And one that arrives anyway is refused rather than carried inwards.
    #[test]
    fn a_subscription_whose_end_group_precedes_its_start_is_refused_on_decode() {
        let buf = encode(&subscribe(GROUP, 0, GROUP)).expect("the same group is a range");
        let moved = move_end_before_start(buf);

        let decoded = ControlMessage::decode(&mut &moved[..]);
        assert!(decoded.is_err(), "an inverted filter is not a subscription: {decoded:?}");
    }

    /// SUBSCRIBE_UPDATE spells its End Group as the last group plus one, and a
    /// zero there is an open end rather than a bound at group zero.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// an update cannot end before it starts: Ok([2, 6, 1, 42, 0, 7, 3, 0])
    /// ```
    #[test]
    fn an_update_whose_end_group_precedes_its_start_never_reaches_the_wire() {
        let result = encode(&subscribe_update(GROUP, 0, 7));
        assert!(result.is_err(), "an update cannot end before it starts: {result:?}");
    }

    /// The zero that means "open ended" is not a range ending at group zero,
    /// and a check that read it as one would refuse every open update.
    ///
    /// Dropping the exemption fails with:
    ///
    /// ```text
    /// zero is an open end, not a bound: InvalidRange(42, 0, 0, 0)
    /// ```
    #[test]
    fn an_open_ended_update_is_carried() {
        let message = subscribe_update(GROUP, 0, 0);
        let buf = encode(&message).expect("zero is an open end, not a bound");
        let decoded = ControlMessage::decode(&mut &buf[..]);
        assert_eq!(decoded.ok().as_ref(), Some(&message), "what this codec wrote it must read");
    }
}

#[cfg(feature = "draft15")]
mod draft15 {
    use super::{varint, GROUP};
    use moqtap_codec::draft15::message::*;
    #[allow(unused_imports)]
    use moqtap_codec::types::*;

    fn fetch(
        start_group: u64,
        start_object: u64,
        end_group: u64,
        end_object: u64,
    ) -> ControlMessage {
        ControlMessage::Fetch(Fetch {
            request_id: varint(1),
            fetch_type: FetchType::Standalone,
            fetch_payload: FetchPayload::Standalone {
                track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
                track_name: b"t".to_vec(),
                start_group: varint(start_group),
                start_object: varint(start_object),
                end_group: varint(end_group),
                end_object: varint(end_object),
            },
            parameters: vec![],
        })
    }

    fn encode(message: &ControlMessage) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message.encode(&mut buf)?;
        Ok(buf)
    }

    /// Move the end group of an encoded frame to a group before the start.
    ///
    /// The frame is one this codec built with both ends in the same group, so
    /// every byte around the one being moved is exactly what the encoder would
    /// have written. [`GROUP`] appears nowhere else in it, and the end group is
    /// the later of its two occurrences.
    fn move_end_before_start(mut buf: Vec<u8>) -> Vec<u8> {
        let at = buf
            .iter()
            .rposition(|b| u64::from(*b) == GROUP)
            .expect("the end group is in the frame");
        buf[at] = 7;
        buf
    }

    /// A FETCH whose end is in an earlier group than its start has no encoding.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a fetch cannot end in a group before its start:
    /// Ok([22, 15, 1, 2, 1, 1, 1, 2, 110, 115, 1, 116, 42, 0, 7, 0, 0])
    /// ```
    #[test]
    fn a_fetch_whose_range_ends_before_it_starts_never_reaches_the_wire() {
        let result = encode(&fetch(GROUP, 0, 7, 0));
        assert!(result.is_err(), "a fetch cannot end in a group before its start: {result:?}");
    }

    /// The end object is the last object plus one, so within one group an end
    /// object at or below the start selects nothing.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a fetch cannot end before the object it starts at:
    /// Ok([22, 15, 1, 2, 1, 1, 1, 2, 110, 115, 1, 116, 42, 9, 42, 4, 0])
    /// ```
    #[test]
    fn a_fetch_that_ends_at_an_earlier_object_in_the_start_group_never_reaches_the_wire() {
        let result = encode(&fetch(GROUP, 9, GROUP, 4));
        assert!(result.is_err(), "a fetch cannot end before the object it starts at: {result:?}");
    }

    /// And one that arrives anyway is refused rather than carried inwards.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// an inverted range is not a request: Ok(Fetch(Fetch { subscribe_id:
    /// VarInt(1), ..., start_group: Some(VarInt(42)), ..., end_group:
    /// Some(VarInt(7)), ... }))
    /// ```
    #[test]
    fn a_fetch_whose_range_ends_before_it_starts_is_refused_on_decode() {
        let buf = encode(&fetch(GROUP, 0, GROUP, 0)).expect("a range inside one group is legal");
        let moved = move_end_before_start(buf);

        let decoded = ControlMessage::decode(&mut &moved[..]);
        assert!(decoded.is_err(), "an inverted range is not a request: {decoded:?}");
    }

    /// The two shapes a legal range takes at the boundary: both ends in one
    /// group, and an end object of 0 asking for the rest of the start group.
    /// Without this the gates above would pass on an encoder that refused every
    /// FETCH.
    #[test]
    fn a_fetch_that_ends_where_it_starts_is_carried() {
        for (start_object, end_object) in [(0, 0), (4, 9), (9, 0)] {
            let message = fetch(GROUP, start_object, GROUP, end_object);
            let buf = encode(&message)
                .unwrap_or_else(|e| panic!("{start_object}..{end_object} is a range: {e:?}"));
            let decoded = ControlMessage::decode(&mut &buf[..]);
            assert_eq!(decoded.ok().as_ref(), Some(&message), "what this codec wrote it must read");
        }
    }
}

#[cfg(feature = "draft16")]
mod draft16 {
    use super::{varint, GROUP};
    use moqtap_codec::draft16::message::*;
    #[allow(unused_imports)]
    use moqtap_codec::types::*;

    fn fetch(
        start_group: u64,
        start_object: u64,
        end_group: u64,
        end_object: u64,
    ) -> ControlMessage {
        ControlMessage::Fetch(Fetch {
            request_id: varint(1),
            fetch_type: FetchType::Standalone,
            fetch_payload: FetchPayload::Standalone {
                track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
                track_name: b"t".to_vec(),
                start_group: varint(start_group),
                start_object: varint(start_object),
                end_group: varint(end_group),
                end_object: varint(end_object),
            },
            parameters: vec![],
        })
    }

    fn encode(message: &ControlMessage) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message.encode(&mut buf)?;
        Ok(buf)
    }

    /// Move the end group of an encoded frame to a group before the start.
    ///
    /// The frame is one this codec built with both ends in the same group, so
    /// every byte around the one being moved is exactly what the encoder would
    /// have written. [`GROUP`] appears nowhere else in it, and the end group is
    /// the later of its two occurrences.
    fn move_end_before_start(mut buf: Vec<u8>) -> Vec<u8> {
        let at = buf
            .iter()
            .rposition(|b| u64::from(*b) == GROUP)
            .expect("the end group is in the frame");
        buf[at] = 7;
        buf
    }

    /// A FETCH whose end is in an earlier group than its start has no encoding.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a fetch cannot end in a group before its start:
    /// Ok([22, 15, 1, 2, 1, 1, 1, 2, 110, 115, 1, 116, 42, 0, 7, 0, 0])
    /// ```
    #[test]
    fn a_fetch_whose_range_ends_before_it_starts_never_reaches_the_wire() {
        let result = encode(&fetch(GROUP, 0, 7, 0));
        assert!(result.is_err(), "a fetch cannot end in a group before its start: {result:?}");
    }

    /// The end object is the last object plus one, so within one group an end
    /// object at or below the start selects nothing.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a fetch cannot end before the object it starts at:
    /// Ok([22, 15, 1, 2, 1, 1, 1, 2, 110, 115, 1, 116, 42, 9, 42, 4, 0])
    /// ```
    #[test]
    fn a_fetch_that_ends_at_an_earlier_object_in_the_start_group_never_reaches_the_wire() {
        let result = encode(&fetch(GROUP, 9, GROUP, 4));
        assert!(result.is_err(), "a fetch cannot end before the object it starts at: {result:?}");
    }

    /// And one that arrives anyway is refused rather than carried inwards.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// an inverted range is not a request: Ok(Fetch(Fetch { subscribe_id:
    /// VarInt(1), ..., start_group: Some(VarInt(42)), ..., end_group:
    /// Some(VarInt(7)), ... }))
    /// ```
    #[test]
    fn a_fetch_whose_range_ends_before_it_starts_is_refused_on_decode() {
        let buf = encode(&fetch(GROUP, 0, GROUP, 0)).expect("a range inside one group is legal");
        let moved = move_end_before_start(buf);

        let decoded = ControlMessage::decode(&mut &moved[..]);
        assert!(decoded.is_err(), "an inverted range is not a request: {decoded:?}");
    }

    /// The two shapes a legal range takes at the boundary: both ends in one
    /// group, and an end object of 0 asking for the rest of the start group.
    /// Without this the gates above would pass on an encoder that refused every
    /// FETCH.
    #[test]
    fn a_fetch_that_ends_where_it_starts_is_carried() {
        for (start_object, end_object) in [(0, 0), (4, 9), (9, 0)] {
            let message = fetch(GROUP, start_object, GROUP, end_object);
            let buf = encode(&message)
                .unwrap_or_else(|e| panic!("{start_object}..{end_object} is a range: {e:?}"));
            let decoded = ControlMessage::decode(&mut &buf[..]);
            assert_eq!(decoded.ok().as_ref(), Some(&message), "what this codec wrote it must read");
        }
    }
}

#[cfg(feature = "draft17")]
mod draft17 {
    use super::{varint, GROUP};
    use moqtap_codec::draft17::message::*;
    #[allow(unused_imports)]
    use moqtap_codec::types::*;

    fn fetch(
        start_group: u64,
        start_object: u64,
        end_group: u64,
        end_object: u64,
    ) -> ControlMessage {
        ControlMessage::Fetch(Fetch {
            request_id: varint(1),
            required_request_id_delta: varint(0),
            fetch_type: FetchType::Standalone,
            fetch_payload: FetchPayload::Standalone {
                track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
                track_name: b"t".to_vec(),
                start_group: varint(start_group),
                start_object: varint(start_object),
                end_group: varint(end_group),
                end_object: varint(end_object),
            },
            parameters: vec![],
        })
    }

    fn encode(message: &ControlMessage) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message.encode(&mut buf)?;
        Ok(buf)
    }

    /// Move the end group of an encoded frame to a group before the start.
    ///
    /// The frame is one this codec built with both ends in the same group, so
    /// every byte around the one being moved is exactly what the encoder would
    /// have written. [`GROUP`] appears nowhere else in it, and the end group is
    /// the later of its two occurrences.
    fn move_end_before_start(mut buf: Vec<u8>) -> Vec<u8> {
        let at = buf
            .iter()
            .rposition(|b| u64::from(*b) == GROUP)
            .expect("the end group is in the frame");
        buf[at] = 7;
        buf
    }

    /// A FETCH whose end is in an earlier group than its start has no encoding.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a fetch cannot end in a group before its start:
    /// Ok([22, 15, 1, 2, 1, 1, 1, 2, 110, 115, 1, 116, 42, 0, 7, 0, 0])
    /// ```
    #[test]
    fn a_fetch_whose_range_ends_before_it_starts_never_reaches_the_wire() {
        let result = encode(&fetch(GROUP, 0, 7, 0));
        assert!(result.is_err(), "a fetch cannot end in a group before its start: {result:?}");
    }

    /// The end object is the last object plus one, so within one group an end
    /// object at or below the start selects nothing.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a fetch cannot end before the object it starts at:
    /// Ok([22, 15, 1, 2, 1, 1, 1, 2, 110, 115, 1, 116, 42, 9, 42, 4, 0])
    /// ```
    #[test]
    fn a_fetch_that_ends_at_an_earlier_object_in_the_start_group_never_reaches_the_wire() {
        let result = encode(&fetch(GROUP, 9, GROUP, 4));
        assert!(result.is_err(), "a fetch cannot end before the object it starts at: {result:?}");
    }

    /// And one that arrives anyway is refused rather than carried inwards.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// an inverted range is not a request: Ok(Fetch(Fetch { subscribe_id:
    /// VarInt(1), ..., start_group: Some(VarInt(42)), ..., end_group:
    /// Some(VarInt(7)), ... }))
    /// ```
    #[test]
    fn a_fetch_whose_range_ends_before_it_starts_is_refused_on_decode() {
        let buf = encode(&fetch(GROUP, 0, GROUP, 0)).expect("a range inside one group is legal");
        let moved = move_end_before_start(buf);

        let decoded = ControlMessage::decode(&mut &moved[..]);
        assert!(decoded.is_err(), "an inverted range is not a request: {decoded:?}");
    }

    /// The two shapes a legal range takes at the boundary: both ends in one
    /// group, and an end object of 0 asking for the rest of the start group.
    /// Without this the gates above would pass on an encoder that refused every
    /// FETCH.
    #[test]
    fn a_fetch_that_ends_where_it_starts_is_carried() {
        for (start_object, end_object) in [(0, 0), (4, 9), (9, 0)] {
            let message = fetch(GROUP, start_object, GROUP, end_object);
            let buf = encode(&message)
                .unwrap_or_else(|e| panic!("{start_object}..{end_object} is a range: {e:?}"));
            let decoded = ControlMessage::decode(&mut &buf[..]);
            assert_eq!(decoded.ok().as_ref(), Some(&message), "what this codec wrote it must read");
        }
    }
}

#[cfg(feature = "draft18")]
mod draft18 {
    use super::{varint, GROUP};
    use moqtap_codec::draft18::message::*;
    #[allow(unused_imports)]
    use moqtap_codec::types::*;

    fn fetch(
        start_group: u64,
        start_object: u64,
        end_group: u64,
        end_object: u64,
    ) -> ControlMessage {
        ControlMessage::Fetch(Fetch {
            request_id: varint(1),
            fetch_type: FetchType::Standalone,
            fetch_payload: FetchPayload::Standalone {
                track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
                track_name: b"t".to_vec(),
                start_group: varint(start_group),
                start_object: varint(start_object),
                end_group: varint(end_group),
                end_object: varint(end_object),
            },
            parameters: vec![],
        })
    }

    fn encode(message: &ControlMessage) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message.encode(&mut buf)?;
        Ok(buf)
    }

    /// Move the end group of an encoded frame to a group before the start.
    ///
    /// The frame is one this codec built with both ends in the same group, so
    /// every byte around the one being moved is exactly what the encoder would
    /// have written. [`GROUP`] appears nowhere else in it, and the end group is
    /// the later of its two occurrences.
    fn move_end_before_start(mut buf: Vec<u8>) -> Vec<u8> {
        let at = buf
            .iter()
            .rposition(|b| u64::from(*b) == GROUP)
            .expect("the end group is in the frame");
        buf[at] = 7;
        buf
    }

    /// A FETCH whose end is in an earlier group than its start has no encoding.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a fetch cannot end in a group before its start:
    /// Ok([22, 15, 1, 2, 1, 1, 1, 2, 110, 115, 1, 116, 42, 0, 7, 0, 0])
    /// ```
    #[test]
    fn a_fetch_whose_range_ends_before_it_starts_never_reaches_the_wire() {
        let result = encode(&fetch(GROUP, 0, 7, 0));
        assert!(result.is_err(), "a fetch cannot end in a group before its start: {result:?}");
    }

    /// The end object is the last object plus one, so within one group an end
    /// object at or below the start selects nothing.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a fetch cannot end before the object it starts at:
    /// Ok([22, 15, 1, 2, 1, 1, 1, 2, 110, 115, 1, 116, 42, 9, 42, 4, 0])
    /// ```
    #[test]
    fn a_fetch_that_ends_at_an_earlier_object_in_the_start_group_never_reaches_the_wire() {
        let result = encode(&fetch(GROUP, 9, GROUP, 4));
        assert!(result.is_err(), "a fetch cannot end before the object it starts at: {result:?}");
    }

    /// And one that arrives anyway is refused rather than carried inwards.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// an inverted range is not a request: Ok(Fetch(Fetch { subscribe_id:
    /// VarInt(1), ..., start_group: Some(VarInt(42)), ..., end_group:
    /// Some(VarInt(7)), ... }))
    /// ```
    #[test]
    fn a_fetch_whose_range_ends_before_it_starts_is_refused_on_decode() {
        let buf = encode(&fetch(GROUP, 0, GROUP, 0)).expect("a range inside one group is legal");
        let moved = move_end_before_start(buf);

        let decoded = ControlMessage::decode(&mut &moved[..]);
        assert!(decoded.is_err(), "an inverted range is not a request: {decoded:?}");
    }

    /// The two shapes a legal range takes at the boundary: both ends in one
    /// group, and an end object of 0 asking for the rest of the start group.
    /// Without this the gates above would pass on an encoder that refused every
    /// FETCH.
    #[test]
    fn a_fetch_that_ends_where_it_starts_is_carried() {
        for (start_object, end_object) in [(0, 0), (4, 9), (9, 0)] {
            let message = fetch(GROUP, start_object, GROUP, end_object);
            let buf = encode(&message)
                .unwrap_or_else(|e| panic!("{start_object}..{end_object} is a range: {e:?}"));
            let decoded = ControlMessage::decode(&mut &buf[..]);
            assert_eq!(decoded.ok().as_ref(), Some(&message), "what this codec wrote it must read");
        }
    }
}

#[cfg(feature = "draft19")]
mod draft19 {
    use super::{varint, GROUP};
    use moqtap_codec::draft19::message::*;
    #[allow(unused_imports)]
    use moqtap_codec::types::*;

    fn fetch(
        start_group: u64,
        start_object: u64,
        end_group: u64,
        end_object: u64,
    ) -> ControlMessage {
        ControlMessage::Fetch(Fetch {
            request_id: varint(1),
            fetch_type: FetchType::Standalone,
            fetch_payload: FetchPayload::Standalone {
                track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
                track_name: b"t".to_vec(),
                start_group: varint(start_group),
                start_object: varint(start_object),
                end_group: varint(end_group),
                end_object: varint(end_object),
            },
            parameters: vec![],
        })
    }

    fn encode(message: &ControlMessage) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message.encode(&mut buf)?;
        Ok(buf)
    }

    /// Move the end group of an encoded frame to a group before the start.
    ///
    /// The frame is one this codec built with both ends in the same group, so
    /// every byte around the one being moved is exactly what the encoder would
    /// have written. [`GROUP`] appears nowhere else in it, and the end group is
    /// the later of its two occurrences.
    fn move_end_before_start(mut buf: Vec<u8>) -> Vec<u8> {
        let at = buf
            .iter()
            .rposition(|b| u64::from(*b) == GROUP)
            .expect("the end group is in the frame");
        buf[at] = 7;
        buf
    }

    /// A FETCH whose end is in an earlier group than its start has no encoding.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a fetch cannot end in a group before its start:
    /// Ok([22, 15, 1, 2, 1, 1, 1, 2, 110, 115, 1, 116, 42, 0, 7, 0, 0])
    /// ```
    #[test]
    fn a_fetch_whose_range_ends_before_it_starts_never_reaches_the_wire() {
        let result = encode(&fetch(GROUP, 0, 7, 0));
        assert!(result.is_err(), "a fetch cannot end in a group before its start: {result:?}");
    }

    /// The end object is the last object plus one, so within one group an end
    /// object at or below the start selects nothing.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// a fetch cannot end before the object it starts at:
    /// Ok([22, 15, 1, 2, 1, 1, 1, 2, 110, 115, 1, 116, 42, 9, 42, 4, 0])
    /// ```
    #[test]
    fn a_fetch_that_ends_at_an_earlier_object_in_the_start_group_never_reaches_the_wire() {
        let result = encode(&fetch(GROUP, 9, GROUP, 4));
        assert!(result.is_err(), "a fetch cannot end before the object it starts at: {result:?}");
    }

    /// And one that arrives anyway is refused rather than carried inwards.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// an inverted range is not a request: Ok(Fetch(Fetch { subscribe_id:
    /// VarInt(1), ..., start_group: Some(VarInt(42)), ..., end_group:
    /// Some(VarInt(7)), ... }))
    /// ```
    #[test]
    fn a_fetch_whose_range_ends_before_it_starts_is_refused_on_decode() {
        let buf = encode(&fetch(GROUP, 0, GROUP, 0)).expect("a range inside one group is legal");
        let moved = move_end_before_start(buf);

        let decoded = ControlMessage::decode(&mut &moved[..]);
        assert!(decoded.is_err(), "an inverted range is not a request: {decoded:?}");
    }

    /// The two shapes a legal range takes at the boundary: both ends in one
    /// group, and an end object of 0 asking for the rest of the start group.
    /// Without this the gates above would pass on an encoder that refused every
    /// FETCH.
    #[test]
    fn a_fetch_that_ends_where_it_starts_is_carried() {
        for (start_object, end_object) in [(0, 0), (4, 9), (9, 0)] {
            let message = fetch(GROUP, start_object, GROUP, end_object);
            let buf = encode(&message)
                .unwrap_or_else(|e| panic!("{start_object}..{end_object} is a range: {e:?}"));
            let decoded = ControlMessage::decode(&mut &buf[..]);
            assert_eq!(decoded.ok().as_ref(), Some(&message), "what this codec wrote it must read");
        }
    }
}

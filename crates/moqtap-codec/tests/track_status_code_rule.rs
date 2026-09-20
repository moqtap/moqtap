//! TRACK_STATUS carries a Status Code the draft closes the list on.
//!
//! "The 'Status Code' field provides additional information about the status of
//! the track. It MUST hold one of the following values. Any other value is a
//! malformed message." Five values are assigned, and two of them - 0x01 and
//! 0x02 - add "Subsequent fields MUST be zero, and any other value is a
//! malformed message".
//!
//! Both halves have to be applied. Carried as an opaque varint the Status Code
//! admits a peer's 0xff, and admits a "track does not exist" that carries a
//! live location - a message that says in one field that the track is absent
//! and in the next where its newest object is.
//!
//! Both directions are gated. A malformed message is one this codec must not
//! read and equally must not write: emitting an unassigned code hands a
//! conforming peer a message it is required to reject, and finding out about it
//! through a session close is finding out too late.
//!
//! Drafts 13 and later drop the sentence, so the series stops at draft-12.

#![allow(clippy::items_after_test_module)]

#[cfg(any(
    feature = "draft07",
    feature = "draft08",
    feature = "draft09",
    feature = "draft10",
    feature = "draft11",
    feature = "draft12"
))]
use moqtap_codec::varint::VarInt;

#[cfg(any(
    feature = "draft07",
    feature = "draft08",
    feature = "draft09",
    feature = "draft10",
    feature = "draft11",
    feature = "draft12"
))]
fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).unwrap()
}

#[cfg(feature = "draft07")]
mod draft07 {
    use super::varint;
    use moqtap_codec::draft07::message::{ControlMessage, TrackStatus};
    #[allow(unused_imports)]
    use moqtap_codec::types::*;

    /// A TRACK_STATUS with `code` and a location of `group`/`object`.
    fn message(code: u64, group: u64, object: u64) -> ControlMessage {
        ControlMessage::TrackStatus(TrackStatus {
            track_namespace: TrackNamespace(vec![b"live".to_vec()]),
            track_name: b"video".to_vec(),
            status_code: varint(code),
            last_group_id: varint(group),
            last_object_id: varint(object),
        })
    }

    fn encode(
        code: u64,
        group: u64,
        object: u64,
    ) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message(code, group, object).encode(&mut buf)?;
        Ok(buf)
    }

    /// A code the draft does not assign has no encoding.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// this draft assigns no Status Code 0x5: Ok([...])
    /// ```
    ///
    /// The byte list is elided here; in the real output it is the frame the
    /// encoder had just finished building, which is the point.
    #[test]
    fn an_unassigned_status_code_never_reaches_the_wire() {
        for code in [0x05, 0xff] {
            let result = encode(code, 0, 0);
            assert!(result.is_err(), "this draft assigns no Status Code {code:#x}: {result:?}");
        }
    }

    /// And one that arrives anyway is refused rather than carried inwards.
    ///
    /// The byte is moved in a message the encoder built, so everything around
    /// it is exactly what the codec would have written - the frame is a real
    /// one and only the Status Code is out of range.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// an unassigned Status Code is a malformed message: Ok(TrackStatus(TrackStatus { .. }))
    /// ```
    ///
    /// The decoded message is elided; it comes back with the out-of-range code
    /// in place, which is what "carried inwards" means.
    #[test]
    fn an_unassigned_status_code_is_refused_on_decode() {
        let mut buf = encode(0x04, 0, 0).expect("0x04 is assigned");
        let at = buf.iter().rposition(|b| *b == 0x04).expect("the status code is in there");
        assert_eq!(buf[at], 0x04, "the byte being moved is the Status Code");
        buf[at] = 0x05;

        let decoded = ControlMessage::decode(&mut &buf[..]);
        assert!(decoded.is_err(), "an unassigned Status Code is a malformed message: {decoded:?}");
    }

    /// 0x01 says the track does not exist, so a location beside it contradicts
    /// it. The draft says the fields after such a code MUST be zero.
    ///
    /// Dropping the second half of the check fails with:
    ///
    /// ```text
    /// Status Code 0x1 requires the fields after it to be zero: Ok([...])
    /// ```
    ///
    /// Byte list elided. It carries `1, 7, 0`: the code that says the track
    /// does not exist, followed by a group that says where its data is.
    #[test]
    fn a_code_that_requires_zero_fields_refuses_a_location() {
        for code in [0x01, 0x02] {
            for (group, object) in [(7, 0), (0, 3)] {
                let result = encode(code, group, object);
                assert!(
                    result.is_err(),
                    "Status Code {code:#x} requires the fields after it to be zero: {result:?}",
                );
            }
        }
    }

    /// The same codes with zeros are legal, and the three codes that describe a
    /// real location carry one. Without this the gates above would pass on an
    /// encoder that refused every TRACK_STATUS.
    #[test]
    fn the_assigned_codes_still_round_trip() {
        for (code, group, object) in
            [(0x00, 9, 4), (0x01, 0, 0), (0x02, 0, 0), (0x03, 9, 4), (0x04, 9, 4)]
        {
            let buf = encode(code, group, object)
                .unwrap_or_else(|e| panic!("Status Code {code:#x} is assigned: {e:?}"));
            let decoded = ControlMessage::decode(&mut &buf[..]);
            assert!(decoded.is_ok(), "what this codec wrote it must read: {decoded:?}");
        }
    }
}

#[cfg(feature = "draft08")]
mod draft08 {
    use super::varint;
    use moqtap_codec::draft08::message::{ControlMessage, TrackStatus};
    #[allow(unused_imports)]
    use moqtap_codec::types::*;

    /// A TRACK_STATUS with `code` and a location of `group`/`object`.
    fn message(code: u64, group: u64, object: u64) -> ControlMessage {
        ControlMessage::TrackStatus(TrackStatus {
            track_namespace: TrackNamespace(vec![b"live".to_vec()]),
            track_name: b"video".to_vec(),
            status_code: varint(code),
            last_group_id: varint(group),
            last_object_id: varint(object),
        })
    }

    fn encode(
        code: u64,
        group: u64,
        object: u64,
    ) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message(code, group, object).encode(&mut buf)?;
        Ok(buf)
    }

    /// A code the draft does not assign has no encoding.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// this draft assigns no Status Code 0x5: Ok([...])
    /// ```
    ///
    /// The byte list is elided here; in the real output it is the frame the
    /// encoder had just finished building, which is the point.
    #[test]
    fn an_unassigned_status_code_never_reaches_the_wire() {
        for code in [0x05, 0xff] {
            let result = encode(code, 0, 0);
            assert!(result.is_err(), "this draft assigns no Status Code {code:#x}: {result:?}");
        }
    }

    /// And one that arrives anyway is refused rather than carried inwards.
    ///
    /// The byte is moved in a message the encoder built, so everything around
    /// it is exactly what the codec would have written - the frame is a real
    /// one and only the Status Code is out of range.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// an unassigned Status Code is a malformed message: Ok(TrackStatus(TrackStatus { .. }))
    /// ```
    ///
    /// The decoded message is elided; it comes back with the out-of-range code
    /// in place, which is what "carried inwards" means.
    #[test]
    fn an_unassigned_status_code_is_refused_on_decode() {
        let mut buf = encode(0x04, 0, 0).expect("0x04 is assigned");
        let at = buf.iter().rposition(|b| *b == 0x04).expect("the status code is in there");
        assert_eq!(buf[at], 0x04, "the byte being moved is the Status Code");
        buf[at] = 0x05;

        let decoded = ControlMessage::decode(&mut &buf[..]);
        assert!(decoded.is_err(), "an unassigned Status Code is a malformed message: {decoded:?}");
    }

    /// 0x01 says the track does not exist, so a location beside it contradicts
    /// it. The draft says the fields after such a code MUST be zero.
    ///
    /// Dropping the second half of the check fails with:
    ///
    /// ```text
    /// Status Code 0x1 requires the fields after it to be zero: Ok([...])
    /// ```
    ///
    /// Byte list elided. It carries `1, 7, 0`: the code that says the track
    /// does not exist, followed by a group that says where its data is.
    #[test]
    fn a_code_that_requires_zero_fields_refuses_a_location() {
        for code in [0x01, 0x02] {
            for (group, object) in [(7, 0), (0, 3)] {
                let result = encode(code, group, object);
                assert!(
                    result.is_err(),
                    "Status Code {code:#x} requires the fields after it to be zero: {result:?}",
                );
            }
        }
    }

    /// The same codes with zeros are legal, and the three codes that describe a
    /// real location carry one. Without this the gates above would pass on an
    /// encoder that refused every TRACK_STATUS.
    #[test]
    fn the_assigned_codes_still_round_trip() {
        for (code, group, object) in
            [(0x00, 9, 4), (0x01, 0, 0), (0x02, 0, 0), (0x03, 9, 4), (0x04, 9, 4)]
        {
            let buf = encode(code, group, object)
                .unwrap_or_else(|e| panic!("Status Code {code:#x} is assigned: {e:?}"));
            let decoded = ControlMessage::decode(&mut &buf[..]);
            assert!(decoded.is_ok(), "what this codec wrote it must read: {decoded:?}");
        }
    }
}

#[cfg(feature = "draft09")]
mod draft09 {
    use super::varint;
    use moqtap_codec::draft09::message::{ControlMessage, TrackStatus};
    #[allow(unused_imports)]
    use moqtap_codec::types::*;

    /// A TRACK_STATUS with `code` and a location of `group`/`object`.
    fn message(code: u64, group: u64, object: u64) -> ControlMessage {
        ControlMessage::TrackStatus(TrackStatus {
            track_namespace: TrackNamespace(vec![b"live".to_vec()]),
            track_name: b"video".to_vec(),
            status_code: varint(code),
            last_group_id: varint(group),
            last_object_id: varint(object),
        })
    }

    fn encode(
        code: u64,
        group: u64,
        object: u64,
    ) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message(code, group, object).encode(&mut buf)?;
        Ok(buf)
    }

    /// A code the draft does not assign has no encoding.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// this draft assigns no Status Code 0x5: Ok([...])
    /// ```
    ///
    /// The byte list is elided here; in the real output it is the frame the
    /// encoder had just finished building, which is the point.
    #[test]
    fn an_unassigned_status_code_never_reaches_the_wire() {
        for code in [0x05, 0xff] {
            let result = encode(code, 0, 0);
            assert!(result.is_err(), "this draft assigns no Status Code {code:#x}: {result:?}");
        }
    }

    /// And one that arrives anyway is refused rather than carried inwards.
    ///
    /// The byte is moved in a message the encoder built, so everything around
    /// it is exactly what the codec would have written - the frame is a real
    /// one and only the Status Code is out of range.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// an unassigned Status Code is a malformed message: Ok(TrackStatus(TrackStatus { .. }))
    /// ```
    ///
    /// The decoded message is elided; it comes back with the out-of-range code
    /// in place, which is what "carried inwards" means.
    #[test]
    fn an_unassigned_status_code_is_refused_on_decode() {
        let mut buf = encode(0x04, 0, 0).expect("0x04 is assigned");
        let at = buf.iter().rposition(|b| *b == 0x04).expect("the status code is in there");
        assert_eq!(buf[at], 0x04, "the byte being moved is the Status Code");
        buf[at] = 0x05;

        let decoded = ControlMessage::decode(&mut &buf[..]);
        assert!(decoded.is_err(), "an unassigned Status Code is a malformed message: {decoded:?}");
    }

    /// 0x01 says the track does not exist, so a location beside it contradicts
    /// it. The draft says the fields after such a code MUST be zero.
    ///
    /// Dropping the second half of the check fails with:
    ///
    /// ```text
    /// Status Code 0x1 requires the fields after it to be zero: Ok([...])
    /// ```
    ///
    /// Byte list elided. It carries `1, 7, 0`: the code that says the track
    /// does not exist, followed by a group that says where its data is.
    #[test]
    fn a_code_that_requires_zero_fields_refuses_a_location() {
        for code in [0x01, 0x02] {
            for (group, object) in [(7, 0), (0, 3)] {
                let result = encode(code, group, object);
                assert!(
                    result.is_err(),
                    "Status Code {code:#x} requires the fields after it to be zero: {result:?}",
                );
            }
        }
    }

    /// The same codes with zeros are legal, and the three codes that describe a
    /// real location carry one. Without this the gates above would pass on an
    /// encoder that refused every TRACK_STATUS.
    #[test]
    fn the_assigned_codes_still_round_trip() {
        for (code, group, object) in
            [(0x00, 9, 4), (0x01, 0, 0), (0x02, 0, 0), (0x03, 9, 4), (0x04, 9, 4)]
        {
            let buf = encode(code, group, object)
                .unwrap_or_else(|e| panic!("Status Code {code:#x} is assigned: {e:?}"));
            let decoded = ControlMessage::decode(&mut &buf[..]);
            assert!(decoded.is_ok(), "what this codec wrote it must read: {decoded:?}");
        }
    }
}

#[cfg(feature = "draft10")]
mod draft10 {
    use super::varint;
    use moqtap_codec::draft10::message::{ControlMessage, TrackStatus};
    #[allow(unused_imports)]
    use moqtap_codec::types::*;

    /// A TRACK_STATUS with `code` and a location of `group`/`object`.
    fn message(code: u64, group: u64, object: u64) -> ControlMessage {
        ControlMessage::TrackStatus(TrackStatus {
            track_namespace: TrackNamespace(vec![b"live".to_vec()]),
            track_name: b"video".to_vec(),
            status_code: varint(code),
            last_group_id: varint(group),
            last_object_id: varint(object),
        })
    }

    fn encode(
        code: u64,
        group: u64,
        object: u64,
    ) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message(code, group, object).encode(&mut buf)?;
        Ok(buf)
    }

    /// A code the draft does not assign has no encoding.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// this draft assigns no Status Code 0x5: Ok([...])
    /// ```
    ///
    /// The byte list is elided here; in the real output it is the frame the
    /// encoder had just finished building, which is the point.
    #[test]
    fn an_unassigned_status_code_never_reaches_the_wire() {
        for code in [0x05, 0xff] {
            let result = encode(code, 0, 0);
            assert!(result.is_err(), "this draft assigns no Status Code {code:#x}: {result:?}");
        }
    }

    /// And one that arrives anyway is refused rather than carried inwards.
    ///
    /// The byte is moved in a message the encoder built, so everything around
    /// it is exactly what the codec would have written - the frame is a real
    /// one and only the Status Code is out of range.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// an unassigned Status Code is a malformed message: Ok(TrackStatus(TrackStatus { .. }))
    /// ```
    ///
    /// The decoded message is elided; it comes back with the out-of-range code
    /// in place, which is what "carried inwards" means.
    #[test]
    fn an_unassigned_status_code_is_refused_on_decode() {
        let mut buf = encode(0x04, 0, 0).expect("0x04 is assigned");
        let at = buf.iter().rposition(|b| *b == 0x04).expect("the status code is in there");
        assert_eq!(buf[at], 0x04, "the byte being moved is the Status Code");
        buf[at] = 0x05;

        let decoded = ControlMessage::decode(&mut &buf[..]);
        assert!(decoded.is_err(), "an unassigned Status Code is a malformed message: {decoded:?}");
    }

    /// 0x01 says the track does not exist, so a location beside it contradicts
    /// it. The draft says the fields after such a code MUST be zero.
    ///
    /// Dropping the second half of the check fails with:
    ///
    /// ```text
    /// Status Code 0x1 requires the fields after it to be zero: Ok([...])
    /// ```
    ///
    /// Byte list elided. It carries `1, 7, 0`: the code that says the track
    /// does not exist, followed by a group that says where its data is.
    #[test]
    fn a_code_that_requires_zero_fields_refuses_a_location() {
        for code in [0x01, 0x02] {
            for (group, object) in [(7, 0), (0, 3)] {
                let result = encode(code, group, object);
                assert!(
                    result.is_err(),
                    "Status Code {code:#x} requires the fields after it to be zero: {result:?}",
                );
            }
        }
    }

    /// The same codes with zeros are legal, and the three codes that describe a
    /// real location carry one. Without this the gates above would pass on an
    /// encoder that refused every TRACK_STATUS.
    #[test]
    fn the_assigned_codes_still_round_trip() {
        for (code, group, object) in
            [(0x00, 9, 4), (0x01, 0, 0), (0x02, 0, 0), (0x03, 9, 4), (0x04, 9, 4)]
        {
            let buf = encode(code, group, object)
                .unwrap_or_else(|e| panic!("Status Code {code:#x} is assigned: {e:?}"));
            let decoded = ControlMessage::decode(&mut &buf[..]);
            assert!(decoded.is_ok(), "what this codec wrote it must read: {decoded:?}");
        }
    }
}

#[cfg(feature = "draft11")]
mod draft11 {
    use super::varint;
    use moqtap_codec::draft11::message::{ControlMessage, TrackStatus};
    #[allow(unused_imports)]
    use moqtap_codec::types::*;

    /// A TRACK_STATUS with `code` and a location of `group`/`object`.
    fn message(code: u64, group: u64, object: u64) -> ControlMessage {
        ControlMessage::TrackStatus(TrackStatus {
            request_id: varint(0),
            status_code: varint(code),
            largest_location: Location { group: varint(group), object: varint(object) },
            parameters: vec![],
        })
    }

    fn encode(
        code: u64,
        group: u64,
        object: u64,
    ) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message(code, group, object).encode(&mut buf)?;
        Ok(buf)
    }

    /// A code the draft does not assign has no encoding.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// this draft assigns no Status Code 0x5: Ok([...])
    /// ```
    ///
    /// The byte list is elided here; in the real output it is the frame the
    /// encoder had just finished building, which is the point.
    #[test]
    fn an_unassigned_status_code_never_reaches_the_wire() {
        for code in [0x05, 0xff] {
            let result = encode(code, 0, 0);
            assert!(result.is_err(), "this draft assigns no Status Code {code:#x}: {result:?}");
        }
    }

    /// And one that arrives anyway is refused rather than carried inwards.
    ///
    /// The byte is moved in a message the encoder built, so everything around
    /// it is exactly what the codec would have written - the frame is a real
    /// one and only the Status Code is out of range.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// an unassigned Status Code is a malformed message: Ok(TrackStatus(TrackStatus { .. }))
    /// ```
    ///
    /// The decoded message is elided; it comes back with the out-of-range code
    /// in place, which is what "carried inwards" means.
    #[test]
    fn an_unassigned_status_code_is_refused_on_decode() {
        let mut buf = encode(0x04, 0, 0).expect("0x04 is assigned");
        let at = buf.iter().rposition(|b| *b == 0x04).expect("the status code is in there");
        assert_eq!(buf[at], 0x04, "the byte being moved is the Status Code");
        buf[at] = 0x05;

        let decoded = ControlMessage::decode(&mut &buf[..]);
        assert!(decoded.is_err(), "an unassigned Status Code is a malformed message: {decoded:?}");
    }

    /// 0x01 says the track does not exist, so a location beside it contradicts
    /// it. The draft says the fields after such a code MUST be zero.
    ///
    /// Dropping the second half of the check fails with:
    ///
    /// ```text
    /// Status Code 0x1 requires the fields after it to be zero: Ok([...])
    /// ```
    ///
    /// Byte list elided. It carries `1, 7, 0`: the code that says the track
    /// does not exist, followed by a group that says where its data is.
    #[test]
    fn a_code_that_requires_zero_fields_refuses_a_location() {
        for code in [0x01, 0x02] {
            for (group, object) in [(7, 0), (0, 3)] {
                let result = encode(code, group, object);
                assert!(
                    result.is_err(),
                    "Status Code {code:#x} requires the fields after it to be zero: {result:?}",
                );
            }
        }
    }

    /// The same codes with zeros are legal, and the three codes that describe a
    /// real location carry one. Without this the gates above would pass on an
    /// encoder that refused every TRACK_STATUS.
    #[test]
    fn the_assigned_codes_still_round_trip() {
        for (code, group, object) in
            [(0x00, 9, 4), (0x01, 0, 0), (0x02, 0, 0), (0x03, 9, 4), (0x04, 9, 4)]
        {
            let buf = encode(code, group, object)
                .unwrap_or_else(|e| panic!("Status Code {code:#x} is assigned: {e:?}"));
            let decoded = ControlMessage::decode(&mut &buf[..]);
            assert!(decoded.is_ok(), "what this codec wrote it must read: {decoded:?}");
        }
    }
}

#[cfg(feature = "draft12")]
mod draft12 {
    use super::varint;
    use moqtap_codec::draft12::message::{ControlMessage, TrackStatus};
    #[allow(unused_imports)]
    use moqtap_codec::types::*;

    /// A TRACK_STATUS with `code` and a location of `group`/`object`.
    fn message(code: u64, group: u64, object: u64) -> ControlMessage {
        ControlMessage::TrackStatus(TrackStatus {
            request_id: varint(0),
            status_code: varint(code),
            largest_location: Location { group: varint(group), object: varint(object) },
            parameters: vec![],
        })
    }

    fn encode(
        code: u64,
        group: u64,
        object: u64,
    ) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message(code, group, object).encode(&mut buf)?;
        Ok(buf)
    }

    /// A code the draft does not assign has no encoding.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// this draft assigns no Status Code 0x5: Ok([...])
    /// ```
    ///
    /// The byte list is elided here; in the real output it is the frame the
    /// encoder had just finished building, which is the point.
    #[test]
    fn an_unassigned_status_code_never_reaches_the_wire() {
        for code in [0x05, 0xff] {
            let result = encode(code, 0, 0);
            assert!(result.is_err(), "this draft assigns no Status Code {code:#x}: {result:?}");
        }
    }

    /// And one that arrives anyway is refused rather than carried inwards.
    ///
    /// The byte is moved in a message the encoder built, so everything around
    /// it is exactly what the codec would have written - the frame is a real
    /// one and only the Status Code is out of range.
    ///
    /// Dropping the check fails with:
    ///
    /// ```text
    /// an unassigned Status Code is a malformed message: Ok(TrackStatus(TrackStatus { .. }))
    /// ```
    ///
    /// The decoded message is elided; it comes back with the out-of-range code
    /// in place, which is what "carried inwards" means.
    #[test]
    fn an_unassigned_status_code_is_refused_on_decode() {
        let mut buf = encode(0x04, 0, 0).expect("0x04 is assigned");
        let at = buf.iter().rposition(|b| *b == 0x04).expect("the status code is in there");
        assert_eq!(buf[at], 0x04, "the byte being moved is the Status Code");
        buf[at] = 0x05;

        let decoded = ControlMessage::decode(&mut &buf[..]);
        assert!(decoded.is_err(), "an unassigned Status Code is a malformed message: {decoded:?}");
    }

    /// 0x01 says the track does not exist, so a location beside it contradicts
    /// it. The draft says the fields after such a code MUST be zero.
    ///
    /// Dropping the second half of the check fails with:
    ///
    /// ```text
    /// Status Code 0x1 requires the fields after it to be zero: Ok([...])
    /// ```
    ///
    /// Byte list elided. It carries `1, 7, 0`: the code that says the track
    /// does not exist, followed by a group that says where its data is.
    #[test]
    fn a_code_that_requires_zero_fields_refuses_a_location() {
        for code in [0x01, 0x02] {
            for (group, object) in [(7, 0), (0, 3)] {
                let result = encode(code, group, object);
                assert!(
                    result.is_err(),
                    "Status Code {code:#x} requires the fields after it to be zero: {result:?}",
                );
            }
        }
    }

    /// The same codes with zeros are legal, and the three codes that describe a
    /// real location carry one. Without this the gates above would pass on an
    /// encoder that refused every TRACK_STATUS.
    #[test]
    fn the_assigned_codes_still_round_trip() {
        for (code, group, object) in
            [(0x00, 9, 4), (0x01, 0, 0), (0x02, 0, 0), (0x03, 9, 4), (0x04, 9, 4)]
        {
            let buf = encode(code, group, object)
                .unwrap_or_else(|e| panic!("Status Code {code:#x} is assigned: {e:?}"));
            let decoded = ControlMessage::decode(&mut &buf[..]);
            assert!(decoded.is_ok(), "what this codec wrote it must read: {decoded:?}");
        }
    }
}

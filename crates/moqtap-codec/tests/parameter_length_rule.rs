//! A parameter whose type implies a length must carry a value of that length.
//!
//! Drafts 07 through 10 each state it once, in the section that gives the
//! Parameter format: "If a receiver understands a parameter type, and the
//! parameter length implied by that type does not match the Parameter Length
//! field, the receiver MUST terminate the session with error code 'Parameter
//! Length Mismatch'." Each of those four drafts assigns that code a number of
//! its own in the session termination registry, and this codec transcribed every
//! one of them - but nothing constructed the error, so the code point was a
//! number no path could reach. Drafts 11 and later drop the sentence along with
//! the Parameter framing it describes, and have nothing here.
//!
//! # The two namespaces
//!
//! Setup parameters and version-specific parameters use separate namespaces, and
//! the drafts say so plainly: "the integer '1' can refer to different parameters
//! for Setup messages and for all other message types". Type 0x02 is the case
//! that bites - MAX_SUBSCRIBE_ID, an integer, in a setup message, and
//! AUTHORIZATION INFO, "an ASCII string", everywhere else. A check that read one
//! list for both would refuse every authorization string that is not by accident
//! a well-formed varint, which is nearly all of them.
//!
//! `the_two_namespaces_are_read_separately` is the test that says so: it puts
//! the *same bytes* under the *same key* in a setup message and in a SUBSCRIBE,
//! and requires opposite answers.
//!
//! # Recorded failures
//!
//! Each was produced by making the change and running the tests, on draft-09.
//!
//! Dropping the check entirely, and - separately - reading the first varint of
//! the value and ignoring whatever follows it, both fail with:
//!
//! ```text
//! a DELIVERY TIMEOUT with a byte after its varint is not a DELIVERY TIMEOUT:
//! Ok([3, 16, 1, 4, 1, 2, 110, 115, 1, 116, 5, 1, 2, 1, 3, 2, 1, 2])
//! ```
//!
//! Applying the setup list to version-specific parameters as well:
//!
//! ```text
//! an authorization string is not a number, whatever its bytes look like:
//! Err(ParameterLengthMismatch(2))
//! ```
//!
//! Applying the version-specific list to setup parameters instead:
//!
//! ```text
//! a MAX_SUBSCRIBE_ID with a byte after its varint is not a MAX_SUBSCRIBE_ID:
//! Ok([64, 64, 25, 1, 192, 0, 0, 0, 255, 0, 0, 9, 1, 2, 13, 97, 45, 116, 111,
//! 107, 101, 110, 45, 118, 97, 108, 117, 101])
//! ```
//!
//! Leaving the reader unchecked, so only the writer holds the rule:
//!
//! ```text
//! the reader must refuse what the writer would not have written:
//! Ok(Subscribe(Subscribe { subscribe_id: VarInt(1), ..., parameters:
//! [KeyValuePair { key: VarInt(3), value: Bytes([2, 3]) }] }))
//! ```

#[cfg(any(
    feature = "draft07",
    feature = "draft08",
    feature = "draft09",
    feature = "draft10"
))]
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
#[cfg(any(
    feature = "draft07",
    feature = "draft08",
    feature = "draft09",
    feature = "draft10"
))]
use moqtap_codec::varint::VarInt;

#[cfg(any(feature = "draft07", feature = "draft08", feature = "draft09", feature = "draft10"))]
fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).unwrap()
}

/// A parameter carrying raw bytes, which is the shape every parameter has on
/// these four drafts once it has come off the wire: `decode_d07` reads a length
/// and that many bytes and never consults a per-key table.
#[cfg(any(feature = "draft07", feature = "draft08", feature = "draft09", feature = "draft10"))]
fn bytes(key: u64, value: &[u8]) -> KeyValuePair {
    KeyValuePair { key: varint(key), value: KvpValue::Bytes(value.to_vec()) }
}

#[cfg(feature = "draft07")]
mod draft07 {
    use super::{bytes, varint};
    use moqtap_codec::draft07::message::*;
    use moqtap_codec::error::CodecError;
    use moqtap_codec::kvp::KeyValuePair;
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

    fn client_setup(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::ClientSetup(ClientSetup {
            supported_versions: vec![varint(0xff00_0007)],
            parameters,
        })
    }

    fn encode(message: &ControlMessage) -> Result<Vec<u8>, CodecError> {
        let mut buf = Vec::new();
        message.encode(&mut buf)?;
        Ok(buf)
    }

    /// Section 6.1.1.2 gives DELIVERY TIMEOUT (0x03) as "the duration in
    /// milliseconds", so its value is one varint and the length that varint
    /// occupies is the length the type implies.
    #[test]
    fn a_delivery_timeout_value_must_be_one_varint() {
        let refused = encode(&subscribe(vec![bytes(0x03, &[0x01, 0x02])]));
        assert!(
            matches!(refused, Err(CodecError::ParameterLengthMismatch(0x03))),
            "a DELIVERY TIMEOUT with a byte after its varint is not a DELIVERY TIMEOUT: {refused:?}",
        );
    }

    /// And an empty value is no varint at all, which is the other way the two
    /// lengths disagree.
    #[test]
    fn a_delivery_timeout_value_may_not_be_empty() {
        let refused = encode(&subscribe(vec![bytes(0x03, &[])]));
        assert!(
            matches!(refused, Err(CodecError::ParameterLengthMismatch(0x03))),
            "no bytes is not one varint: {refused:?}",
        );
    }

    /// Section 6.1.1.3 gives MAX CACHE DURATION (0x04) as "An integer
    /// expressing a number of milliseconds", and it is held to the same rule.
    #[test]
    fn a_max_cache_duration_value_must_be_one_varint() {
        let refused = encode(&subscribe(vec![bytes(0x04, &[0x0a, 0x0b, 0x0c])]));
        assert!(
            matches!(refused, Err(CodecError::ParameterLengthMismatch(0x04))),
            "three bytes are not one varint: {refused:?}",
        );
    }

    /// The value that does fit round-trips. Without this the tests above would
    /// pass on a codec that refused every DELIVERY TIMEOUT ever written.
    #[test]
    fn a_one_varint_value_round_trips() {
        let message = subscribe(vec![bytes(0x03, &[0x40, 0xc8])]);
        let buf = encode(&message).expect("one varint is a legal DELIVERY TIMEOUT");
        let decoded = ControlMessage::decode(&mut &buf[..]).expect("and it reads back");
        assert_eq!(decoded, message);
    }

    /// The rule is a receiver's, so the reader applies it too - a frame built
    /// by hand and put on the wire is refused where it is read, not only where
    /// it would have been written.
    #[test]
    fn the_reader_refuses_the_same_value() {
        let honest = encode(&subscribe(vec![bytes(0x03, &[0x02])])).expect("a legal frame");
        // Widen the parameter from one byte to two, and its declared length
        // with it: the frame stays well-formed under the figure, and the only
        // thing wrong with it is the rule under test.
        let at = honest.len() - 2;
        assert_eq!(honest[at], 0x01, "the parameter length byte should be here");
        let mut tampered = honest.clone();
        tampered[at] = 0x02;
        tampered.push(0x03);
        tampered[1] += 1;

        let refused = ControlMessage::decode(&mut &tampered[..]);
        assert!(
            matches!(refused, Err(CodecError::ParameterLengthMismatch(0x03))),
            "the reader must refuse what the writer would not have written: {refused:?}",
        );
    }

    /// Type 0x02 in a setup message is MAX_SUBSCRIBE_ID, an integer, and in
    /// every other message it is AUTHORIZATION INFO, "an ASCII string". The same
    /// bytes under the same key must therefore be answered two different ways,
    /// and this is the test that fails if the two namespaces are collapsed into
    /// one list.
    #[test]
    fn the_two_namespaces_are_read_separately() {
        let value: &[u8] = b"a-token-value";

        let in_a_subscribe = encode(&subscribe(vec![bytes(0x02, value)]));
        assert!(
            in_a_subscribe.is_ok(),
            "an authorization string is not a number, whatever its bytes look like: {in_a_subscribe:?}",
        );

        let in_a_setup = encode(&client_setup(vec![bytes(0x02, value)]));
        assert!(
            matches!(in_a_setup, Err(CodecError::ParameterLengthMismatch(0x02))),
            "a MAX_SUBSCRIBE_ID with a byte after its varint is not a MAX_SUBSCRIBE_ID: {in_a_setup:?}",
        );
    }

    /// A setup MAX_SUBSCRIBE_ID that is one varint is carried, so the test above
    /// is about the value and not about the message.
    #[test]
    fn a_well_formed_setup_max_subscribe_id_is_carried() {
        encode(&client_setup(vec![bytes(0x02, &[0x40, 0x64])]))
            .expect("one varint is a legal MAX_SUBSCRIBE_ID");
    }

    /// PATH is a URI string and its definition implies no length, so a PATH of
    /// any shape is carried. A check that held every setup parameter to the
    /// varint rule would refuse this.
    #[test]
    fn a_path_is_not_held_to_a_length() {
        encode(&client_setup(vec![bytes(0x01, b"/live/stream?x=1")]))
            .expect("a PATH carries a URI, not a number");
    }

    /// A type neither list names is one this draft does not define, and
    /// "receivers ignore unrecognized parameters" - so nothing is implied about
    /// its length and nothing is checked.
    #[test]
    fn an_unrecognised_type_is_carried_whatever_it_holds() {
        encode(&subscribe(vec![bytes(0x7b, &[0xde, 0xad, 0xbe, 0xef])]))
            .expect("an unknown parameter implies no length");
    }

    /// The ROLE parameter is draft-07's, and Section 6.2.2.1 gives its three
    /// values as "of type varint" - so it carries an implied length too. No
    /// later draft defines the parameter at all.
    #[test]
    fn a_role_value_must_be_one_varint() {
        let refused = encode(&client_setup(vec![bytes(0x00, &[0x03, 0x00])]));
        assert!(
            matches!(refused, Err(CodecError::ParameterLengthMismatch(0x00))),
            "a ROLE with a byte after its varint is not a ROLE: {refused:?}",
        );
        encode(&client_setup(vec![bytes(0x00, &[0x03])])).expect("one varint is a ROLE");
    }
}

#[cfg(feature = "draft08")]
mod draft08 {
    use super::{bytes, varint};
    use moqtap_codec::draft08::message::*;
    use moqtap_codec::error::CodecError;
    use moqtap_codec::kvp::KeyValuePair;
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

    fn client_setup(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::ClientSetup(ClientSetup {
            supported_versions: vec![varint(0xff00_0008)],
            parameters,
        })
    }

    fn encode(message: &ControlMessage) -> Result<Vec<u8>, CodecError> {
        let mut buf = Vec::new();
        message.encode(&mut buf)?;
        Ok(buf)
    }

    /// Section 7.1.1.2 gives DELIVERY TIMEOUT (0x03) as "the duration in
    /// milliseconds", so its value is one varint and the length that varint
    /// occupies is the length the type implies.
    #[test]
    fn a_delivery_timeout_value_must_be_one_varint() {
        let refused = encode(&subscribe(vec![bytes(0x03, &[0x01, 0x02])]));
        assert!(
            matches!(refused, Err(CodecError::ParameterLengthMismatch(0x03))),
            "a DELIVERY TIMEOUT with a byte after its varint is not a DELIVERY TIMEOUT: {refused:?}",
        );
    }

    /// And an empty value is no varint at all, which is the other way the two
    /// lengths disagree.
    #[test]
    fn a_delivery_timeout_value_may_not_be_empty() {
        let refused = encode(&subscribe(vec![bytes(0x03, &[])]));
        assert!(
            matches!(refused, Err(CodecError::ParameterLengthMismatch(0x03))),
            "no bytes is not one varint: {refused:?}",
        );
    }

    /// Section 7.1.1.3 gives MAX CACHE DURATION (0x04) as "An integer
    /// expressing a number of milliseconds", and it is held to the same rule.
    #[test]
    fn a_max_cache_duration_value_must_be_one_varint() {
        let refused = encode(&subscribe(vec![bytes(0x04, &[0x0a, 0x0b, 0x0c])]));
        assert!(
            matches!(refused, Err(CodecError::ParameterLengthMismatch(0x04))),
            "three bytes are not one varint: {refused:?}",
        );
    }

    /// The value that does fit round-trips. Without this the tests above would
    /// pass on a codec that refused every DELIVERY TIMEOUT ever written.
    #[test]
    fn a_one_varint_value_round_trips() {
        let message = subscribe(vec![bytes(0x03, &[0x40, 0xc8])]);
        let buf = encode(&message).expect("one varint is a legal DELIVERY TIMEOUT");
        let decoded = ControlMessage::decode(&mut &buf[..]).expect("and it reads back");
        assert_eq!(decoded, message);
    }

    /// The rule is a receiver's, so the reader applies it too - a frame built
    /// by hand and put on the wire is refused where it is read, not only where
    /// it would have been written.
    #[test]
    fn the_reader_refuses_the_same_value() {
        let honest = encode(&subscribe(vec![bytes(0x03, &[0x02])])).expect("a legal frame");
        // Widen the parameter from one byte to two, and its declared length
        // with it: the frame stays well-formed under the figure, and the only
        // thing wrong with it is the rule under test.
        let at = honest.len() - 2;
        assert_eq!(honest[at], 0x01, "the parameter length byte should be here");
        let mut tampered = honest.clone();
        tampered[at] = 0x02;
        tampered.push(0x03);
        tampered[1] += 1;

        let refused = ControlMessage::decode(&mut &tampered[..]);
        assert!(
            matches!(refused, Err(CodecError::ParameterLengthMismatch(0x03))),
            "the reader must refuse what the writer would not have written: {refused:?}",
        );
    }

    /// Type 0x02 in a setup message is MAX_SUBSCRIBE_ID, an integer, and in
    /// every other message it is AUTHORIZATION INFO, "an ASCII string". The same
    /// bytes under the same key must therefore be answered two different ways,
    /// and this is the test that fails if the two namespaces are collapsed into
    /// one list.
    #[test]
    fn the_two_namespaces_are_read_separately() {
        let value: &[u8] = b"a-token-value";

        let in_a_subscribe = encode(&subscribe(vec![bytes(0x02, value)]));
        assert!(
            in_a_subscribe.is_ok(),
            "an authorization string is not a number, whatever its bytes look like: {in_a_subscribe:?}",
        );

        let in_a_setup = encode(&client_setup(vec![bytes(0x02, value)]));
        assert!(
            matches!(in_a_setup, Err(CodecError::ParameterLengthMismatch(0x02))),
            "a MAX_SUBSCRIBE_ID with a byte after its varint is not a MAX_SUBSCRIBE_ID: {in_a_setup:?}",
        );
    }

    /// A setup MAX_SUBSCRIBE_ID that is one varint is carried, so the test above
    /// is about the value and not about the message.
    #[test]
    fn a_well_formed_setup_max_subscribe_id_is_carried() {
        encode(&client_setup(vec![bytes(0x02, &[0x40, 0x64])]))
            .expect("one varint is a legal MAX_SUBSCRIBE_ID");
    }

    /// PATH is a URI string and its definition implies no length, so a PATH of
    /// any shape is carried. A check that held every setup parameter to the
    /// varint rule would refuse this.
    #[test]
    fn a_path_is_not_held_to_a_length() {
        encode(&client_setup(vec![bytes(0x01, b"/live/stream?x=1")]))
            .expect("a PATH carries a URI, not a number");
    }

    /// A type neither list names is one this draft does not define, and
    /// "receivers ignore unrecognized parameters" - so nothing is implied about
    /// its length and nothing is checked.
    #[test]
    fn an_unrecognised_type_is_carried_whatever_it_holds() {
        encode(&subscribe(vec![bytes(0x7b, &[0xde, 0xad, 0xbe, 0xef])]))
            .expect("an unknown parameter implies no length");
    }
}

#[cfg(feature = "draft09")]
mod draft09 {
    use super::{bytes, varint};
    use moqtap_codec::draft09::message::*;
    use moqtap_codec::error::CodecError;
    use moqtap_codec::kvp::KeyValuePair;
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

    fn client_setup(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::ClientSetup(ClientSetup {
            supported_versions: vec![varint(0xff00_0009)],
            parameters,
        })
    }

    fn encode(message: &ControlMessage) -> Result<Vec<u8>, CodecError> {
        let mut buf = Vec::new();
        message.encode(&mut buf)?;
        Ok(buf)
    }

    /// Section 7.1.1.2 gives DELIVERY TIMEOUT (0x03) as "the duration in
    /// milliseconds", so its value is one varint and the length that varint
    /// occupies is the length the type implies.
    #[test]
    fn a_delivery_timeout_value_must_be_one_varint() {
        let refused = encode(&subscribe(vec![bytes(0x03, &[0x01, 0x02])]));
        assert!(
            matches!(refused, Err(CodecError::ParameterLengthMismatch(0x03))),
            "a DELIVERY TIMEOUT with a byte after its varint is not a DELIVERY TIMEOUT: {refused:?}",
        );
    }

    /// And an empty value is no varint at all, which is the other way the two
    /// lengths disagree.
    #[test]
    fn a_delivery_timeout_value_may_not_be_empty() {
        let refused = encode(&subscribe(vec![bytes(0x03, &[])]));
        assert!(
            matches!(refused, Err(CodecError::ParameterLengthMismatch(0x03))),
            "no bytes is not one varint: {refused:?}",
        );
    }

    /// Section 7.1.1.3 gives MAX CACHE DURATION (0x04) as "An integer
    /// expressing a number of milliseconds", and it is held to the same rule.
    #[test]
    fn a_max_cache_duration_value_must_be_one_varint() {
        let refused = encode(&subscribe(vec![bytes(0x04, &[0x0a, 0x0b, 0x0c])]));
        assert!(
            matches!(refused, Err(CodecError::ParameterLengthMismatch(0x04))),
            "three bytes are not one varint: {refused:?}",
        );
    }

    /// The value that does fit round-trips. Without this the tests above would
    /// pass on a codec that refused every DELIVERY TIMEOUT ever written.
    #[test]
    fn a_one_varint_value_round_trips() {
        let message = subscribe(vec![bytes(0x03, &[0x40, 0xc8])]);
        let buf = encode(&message).expect("one varint is a legal DELIVERY TIMEOUT");
        let decoded = ControlMessage::decode(&mut &buf[..]).expect("and it reads back");
        assert_eq!(decoded, message);
    }

    /// The rule is a receiver's, so the reader applies it too - a frame built
    /// by hand and put on the wire is refused where it is read, not only where
    /// it would have been written.
    #[test]
    fn the_reader_refuses_the_same_value() {
        let honest = encode(&subscribe(vec![bytes(0x03, &[0x02])])).expect("a legal frame");
        // Widen the parameter from one byte to two, and its declared length
        // with it: the frame stays well-formed under the figure, and the only
        // thing wrong with it is the rule under test.
        let at = honest.len() - 2;
        assert_eq!(honest[at], 0x01, "the parameter length byte should be here");
        let mut tampered = honest.clone();
        tampered[at] = 0x02;
        tampered.push(0x03);
        tampered[1] += 1;

        let refused = ControlMessage::decode(&mut &tampered[..]);
        assert!(
            matches!(refused, Err(CodecError::ParameterLengthMismatch(0x03))),
            "the reader must refuse what the writer would not have written: {refused:?}",
        );
    }

    /// Type 0x02 in a setup message is MAX_SUBSCRIBE_ID, an integer, and in
    /// every other message it is AUTHORIZATION INFO, "an ASCII string". The same
    /// bytes under the same key must therefore be answered two different ways,
    /// and this is the test that fails if the two namespaces are collapsed into
    /// one list.
    #[test]
    fn the_two_namespaces_are_read_separately() {
        let value: &[u8] = b"a-token-value";

        let in_a_subscribe = encode(&subscribe(vec![bytes(0x02, value)]));
        assert!(
            in_a_subscribe.is_ok(),
            "an authorization string is not a number, whatever its bytes look like: {in_a_subscribe:?}",
        );

        let in_a_setup = encode(&client_setup(vec![bytes(0x02, value)]));
        assert!(
            matches!(in_a_setup, Err(CodecError::ParameterLengthMismatch(0x02))),
            "a MAX_SUBSCRIBE_ID with a byte after its varint is not a MAX_SUBSCRIBE_ID: {in_a_setup:?}",
        );
    }

    /// A setup MAX_SUBSCRIBE_ID that is one varint is carried, so the test above
    /// is about the value and not about the message.
    #[test]
    fn a_well_formed_setup_max_subscribe_id_is_carried() {
        encode(&client_setup(vec![bytes(0x02, &[0x40, 0x64])]))
            .expect("one varint is a legal MAX_SUBSCRIBE_ID");
    }

    /// PATH is a URI string and its definition implies no length, so a PATH of
    /// any shape is carried. A check that held every setup parameter to the
    /// varint rule would refuse this.
    #[test]
    fn a_path_is_not_held_to_a_length() {
        encode(&client_setup(vec![bytes(0x01, b"/live/stream?x=1")]))
            .expect("a PATH carries a URI, not a number");
    }

    /// A type neither list names is one this draft does not define, and
    /// "receivers ignore unrecognized parameters" - so nothing is implied about
    /// its length and nothing is checked.
    #[test]
    fn an_unrecognised_type_is_carried_whatever_it_holds() {
        encode(&subscribe(vec![bytes(0x7b, &[0xde, 0xad, 0xbe, 0xef])]))
            .expect("an unknown parameter implies no length");
    }
}

#[cfg(feature = "draft10")]
mod draft10 {
    use super::{bytes, varint};
    use moqtap_codec::draft10::message::*;
    use moqtap_codec::error::CodecError;
    use moqtap_codec::kvp::KeyValuePair;
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

    fn client_setup(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::ClientSetup(ClientSetup {
            supported_versions: vec![varint(0xff00_0010)],
            parameters,
        })
    }

    fn encode(message: &ControlMessage) -> Result<Vec<u8>, CodecError> {
        let mut buf = Vec::new();
        message.encode(&mut buf)?;
        Ok(buf)
    }

    /// Section 8.1.1.2 gives DELIVERY TIMEOUT (0x03) as "the duration in
    /// milliseconds", so its value is one varint and the length that varint
    /// occupies is the length the type implies.
    #[test]
    fn a_delivery_timeout_value_must_be_one_varint() {
        let refused = encode(&subscribe(vec![bytes(0x03, &[0x01, 0x02])]));
        assert!(
            matches!(refused, Err(CodecError::ParameterLengthMismatch(0x03))),
            "a DELIVERY TIMEOUT with a byte after its varint is not a DELIVERY TIMEOUT: {refused:?}",
        );
    }

    /// And an empty value is no varint at all, which is the other way the two
    /// lengths disagree.
    #[test]
    fn a_delivery_timeout_value_may_not_be_empty() {
        let refused = encode(&subscribe(vec![bytes(0x03, &[])]));
        assert!(
            matches!(refused, Err(CodecError::ParameterLengthMismatch(0x03))),
            "no bytes is not one varint: {refused:?}",
        );
    }

    /// Section 8.1.1.3 gives MAX CACHE DURATION (0x04) as "An integer
    /// expressing a number of milliseconds", and it is held to the same rule.
    #[test]
    fn a_max_cache_duration_value_must_be_one_varint() {
        let refused = encode(&subscribe(vec![bytes(0x04, &[0x0a, 0x0b, 0x0c])]));
        assert!(
            matches!(refused, Err(CodecError::ParameterLengthMismatch(0x04))),
            "three bytes are not one varint: {refused:?}",
        );
    }

    /// The value that does fit round-trips. Without this the tests above would
    /// pass on a codec that refused every DELIVERY TIMEOUT ever written.
    #[test]
    fn a_one_varint_value_round_trips() {
        let message = subscribe(vec![bytes(0x03, &[0x40, 0xc8])]);
        let buf = encode(&message).expect("one varint is a legal DELIVERY TIMEOUT");
        let decoded = ControlMessage::decode(&mut &buf[..]).expect("and it reads back");
        assert_eq!(decoded, message);
    }

    /// The rule is a receiver's, so the reader applies it too - a frame built
    /// by hand and put on the wire is refused where it is read, not only where
    /// it would have been written.
    #[test]
    fn the_reader_refuses_the_same_value() {
        let honest = encode(&subscribe(vec![bytes(0x03, &[0x02])])).expect("a legal frame");
        // Widen the parameter from one byte to two, and its declared length
        // with it: the frame stays well-formed under the figure, and the only
        // thing wrong with it is the rule under test.
        let at = honest.len() - 2;
        assert_eq!(honest[at], 0x01, "the parameter length byte should be here");
        let mut tampered = honest.clone();
        tampered[at] = 0x02;
        tampered.push(0x03);
        tampered[1] += 1;

        let refused = ControlMessage::decode(&mut &tampered[..]);
        assert!(
            matches!(refused, Err(CodecError::ParameterLengthMismatch(0x03))),
            "the reader must refuse what the writer would not have written: {refused:?}",
        );
    }

    /// Type 0x02 in a setup message is MAX_SUBSCRIBE_ID, an integer, and in
    /// every other message it is AUTHORIZATION INFO, "an ASCII string". The same
    /// bytes under the same key must therefore be answered two different ways,
    /// and this is the test that fails if the two namespaces are collapsed into
    /// one list.
    #[test]
    fn the_two_namespaces_are_read_separately() {
        let value: &[u8] = b"a-token-value";

        let in_a_subscribe = encode(&subscribe(vec![bytes(0x02, value)]));
        assert!(
            in_a_subscribe.is_ok(),
            "an authorization string is not a number, whatever its bytes look like: {in_a_subscribe:?}",
        );

        let in_a_setup = encode(&client_setup(vec![bytes(0x02, value)]));
        assert!(
            matches!(in_a_setup, Err(CodecError::ParameterLengthMismatch(0x02))),
            "a MAX_SUBSCRIBE_ID with a byte after its varint is not a MAX_SUBSCRIBE_ID: {in_a_setup:?}",
        );
    }

    /// A setup MAX_SUBSCRIBE_ID that is one varint is carried, so the test above
    /// is about the value and not about the message.
    #[test]
    fn a_well_formed_setup_max_subscribe_id_is_carried() {
        encode(&client_setup(vec![bytes(0x02, &[0x40, 0x64])]))
            .expect("one varint is a legal MAX_SUBSCRIBE_ID");
    }

    /// PATH is a URI string and its definition implies no length, so a PATH of
    /// any shape is carried. A check that held every setup parameter to the
    /// varint rule would refuse this.
    #[test]
    fn a_path_is_not_held_to_a_length() {
        encode(&client_setup(vec![bytes(0x01, b"/live/stream?x=1")]))
            .expect("a PATH carries a URI, not a number");
    }

    /// A type neither list names is one this draft does not define, and
    /// "receivers ignore unrecognized parameters" - so nothing is implied about
    /// its length and nothing is checked.
    #[test]
    fn an_unrecognised_type_is_carried_whatever_it_holds() {
        encode(&subscribe(vec![bytes(0x7b, &[0xde, 0xad, 0xbe, 0xef])]))
            .expect("an unknown parameter implies no length");
    }
}

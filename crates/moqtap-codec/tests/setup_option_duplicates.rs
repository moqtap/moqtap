//! A SETUP message may not repeat a Setup Option type, and a receiver may only
//! say so about the types it knows.
//!
//! Drafts 17, 18 and 19 state it in the SETUP section: "Senders MUST NOT repeat
//! the same Option Type in a message unless the option definition explicitly
//! allows multiple instances. Receivers MUST allow duplicates of unknown Setup
//! Options."
//!
//! # The two halves are not mirrors of each other
//!
//! This is the only duplicate rule in these drafts that is asymmetric, and the
//! asymmetry is the whole point of the second sentence. A sender may not repeat
//! *any* type, including one it does not recognise. A receiver may refuse a
//! repeat only of a type it can name - because a repeat of an option some
//! extension defined is something the peer may legitimately be doing, and
//! closing the session over it would break exactly the extensibility the SETUP
//! exchange exists to negotiate.
//!
//! A symmetric check would pass every test here except
//! `an_unknown_option_may_be_repeated_by_a_peer`, which is why that one is
//! written the way it is: it builds the frame with the codec's own writer -
//! under a key the writer *does* allow to repeat - and then rewrites one delta
//! byte, so the bytes handed to the reader are otherwise exactly what this codec
//! produces.
//!
//! # Track Properties share the wire shape and not the rule
//!
//! Setup Options and Track Properties are both delta-encoded key-value lists,
//! and before this they went through one pair of helpers. Only Setup Options
//! carry the rule; nothing in these drafts forbids a repeated Track Property. So
//! `a_repeated_track_property_is_not_this_rules_business` holds the shared path
//! where it was.
//!
//! # Recorded failures
//!
//! Each was produced by making the change and running the tests, on draft-17.
//!
//! Dropping the sender's check:
//!
//! ```text
//! a sender may not repeat an option type:
//! Ok([175, 0, 0, 8, 1, 2, 47, 97, 0, 2, 47, 98])
//! ```
//!
//! Dropping the receiver's check:
//!
//! ```text
//! a repeated PATH is one the reader can name, and must refuse:
//! Ok(Setup(Setup { options: [KeyValuePair { key: VarInt(1), value:
//! Bytes([97, 97]) }, KeyValuePair { key: VarInt(1), value: Bytes([98, 98]) }] }))
//! ```
//!
//! Making the receiver refuse every repeat rather than only known types:
//!
//! ```text
//! a receiver must allow duplicates of options it cannot name:
//! Err(DuplicateParameter(65))
//! ```
//!
//! Dropping the AUTHORIZATION TOKEN carve-out:
//!
//! ```text
//! an endpoint can specify one or more tokens in SETUP:
//! Err(DuplicateParameter(3))
//! ```
//!
//! Pointing the rule at Track Properties as well:
//!
//! ```text
//! the Setup Option rule is stated about Setup Options:
//! Err(DuplicateParameter(2))
//! ```

#[cfg(any(feature = "draft17", feature = "draft18", feature = "draft19"))]
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
#[cfg(any(feature = "draft17", feature = "draft18", feature = "draft19"))]
use moqtap_codec::varint::VarInt;

/// PATH, Option Type 0x01: a known option, length-prefixed, and one whose
/// definition says nothing about multiple instances.
#[cfg(any(feature = "draft17", feature = "draft18", feature = "draft19"))]
const PATH: u64 = 0x01;
/// AUTHORIZATION TOKEN, Option Type 0x03: the one option whose definition lets
/// an endpoint "specify one or more tokens in SETUP".
#[cfg(any(feature = "draft17", feature = "draft18", feature = "draft19"))]
const AUTHORIZATION_TOKEN: u64 = 0x03;
/// A type no draft here assigns. Odd, so it is length-prefixed like PATH and the
/// two frames differ only in the key.
#[cfg(any(feature = "draft17", feature = "draft18", feature = "draft19"))]
const UNKNOWN: u64 = 0x41;

#[cfg(any(feature = "draft17", feature = "draft18", feature = "draft19"))]
fn varint(v: u64) -> VarInt {
    VarInt::from_u64_moqt(v)
}

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

#[cfg(any(feature = "draft17", feature = "draft18", feature = "draft19"))]
fn option(key: u64, value: &[u8]) -> KeyValuePair {
    KeyValuePair { key: varint(key), value: KvpValue::Bytes(value.to_vec()) }
}

#[cfg(feature = "draft17")]
mod draft17 {
    use super::{option, token_value, varint, AUTHORIZATION_TOKEN, PATH, UNKNOWN};
    use moqtap_codec::draft17::message::*;
    use moqtap_codec::error::CodecError;
    use moqtap_codec::kvp::{KeyValuePair, KvpValue};

    fn subscribe_ok(track_properties: Vec<KeyValuePair>) -> SubscribeOk {
        SubscribeOk { track_alias: varint(4), parameters: Vec::new(), track_properties }
    }

    fn setup(options: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::Setup(Setup { options })
    }

    fn encode(message: &ControlMessage) -> Result<Vec<u8>, CodecError> {
        let mut buf = Vec::new();
        message.encode(&mut buf)?;
        Ok(buf)
    }

    /// Section 9.4: "Senders MUST NOT repeat the same Option Type in a
    /// message unless the option definition explicitly allows multiple
    /// instances."
    #[test]
    fn a_repeated_known_option_has_no_encoding() {
        let refused = encode(&setup(vec![option(PATH, b"/a"), option(PATH, b"/b")]));
        assert!(
            matches!(refused, Err(CodecError::DuplicateParameter(PATH))),
            "a sender may not repeat an option type: {refused:?}",
        );
    }

    /// The sender's half names no exception for types the sender does not
    /// recognise, so an unknown type may not be repeated either. This is the
    /// half that is *wider* than the receiver's.
    #[test]
    fn a_repeated_unknown_option_has_no_encoding_either() {
        let refused = encode(&setup(vec![option(UNKNOWN, b"x"), option(UNKNOWN, b"y")]));
        assert!(
            matches!(refused, Err(CodecError::DuplicateParameter(UNKNOWN))),
            "the sender's half has no carve-out for unknown types: {refused:?}",
        );
    }

    /// The reader refuses a repeat of a type this draft assigns.
    #[test]
    fn a_repeated_known_option_has_no_decoding() {
        let bytes = repeated_frame(PATH);
        let refused = ControlMessage::decode(&mut &bytes[..]);
        assert!(
            matches!(refused, Err(CodecError::DuplicateParameter(PATH))),
            "a repeated PATH is one the reader can name, and must refuse: {refused:?}",
        );
    }

    /// And carries a repeat of a type it cannot name. Section 9.4:
    /// "Receivers MUST allow duplicates of unknown Setup Options."
    ///
    /// This is the test a symmetric check fails.
    #[test]
    fn an_unknown_option_may_be_repeated_by_a_peer() {
        let bytes = repeated_frame(UNKNOWN);
        let decoded = ControlMessage::decode(&mut &bytes[..]);
        assert!(
            decoded.is_ok(),
            "a receiver must allow duplicates of options it cannot name: {decoded:?}",
        );
        let ControlMessage::Setup(Setup { options }) = decoded.unwrap() else {
            panic!("a SETUP decodes as a SETUP");
        };
        assert_eq!(options.len(), 2, "and carries both copies rather than folding them");
    }

    /// Section 9.4.1.4: "The endpoint can specify one or more tokens in
    /// SETUP that the peer can use to authorize MOQT session establishment."
    /// That is the "unless the option definition explicitly allows multiple
    /// instances" carve-out, and this draft has exactly one.
    #[test]
    fn an_authorization_token_may_be_repeated() {
        let message = setup(vec![
            option(AUTHORIZATION_TOKEN, &token_value(b"first")),
            option(AUTHORIZATION_TOKEN, &token_value(b"second")),
        ]);
        let bytes = encode(&message);
        assert!(bytes.is_ok(), "an endpoint can specify one or more tokens in SETUP: {bytes:?}",);
        let decoded = ControlMessage::decode(&mut &bytes.unwrap()[..]);
        assert!(decoded.is_ok(), "and the reader takes both back: {decoded:?}");
    }

    /// Distinct known options are the ordinary case, and go both ways.
    #[test]
    fn distinct_options_round_trip() {
        let message = setup(vec![option(PATH, b"/live"), option(0x05, b"example.test")]);
        let bytes = encode(&message).expect("two different option types are fine");
        let decoded = ControlMessage::decode(&mut &bytes[..]).expect("and read back");
        assert_eq!(decoded, message);
    }

    /// Track Properties share the delta-encoded wire shape and the helpers
    /// underneath, and carry no duplicate rule of their own - so a repeat there
    /// is not this rule's business.
    #[test]
    fn a_repeated_track_property_is_not_this_rules_business() {
        let message = ControlMessage::SubscribeOk(subscribe_ok(vec![
            KeyValuePair { key: varint(0x02), value: KvpValue::Varint(varint(1)) },
            KeyValuePair { key: varint(0x02), value: KvpValue::Varint(varint(2)) },
        ]));
        let written = encode(&message);
        assert!(
            written.is_ok(),
            "the Setup Option rule is stated about Setup Options: {written:?}",
        );
    }

    /// A SETUP frame carrying `key` twice, built by this codec and then edited
    /// in one place.
    ///
    /// The writer will not repeat a type - that is the rule above - so the frame
    /// is written under AUTHORIZATION TOKEN, which it will, and the two key
    /// deltas are then rewritten to name `key` instead. Everything else in the
    /// frame is exactly what this codec produces, so the only thing the reader
    /// can object to is the repeat.
    fn repeated_frame(key: u64) -> Vec<u8> {
        let message = setup(vec![
            option(AUTHORIZATION_TOKEN, &token_value(b"aa")),
            option(AUTHORIZATION_TOKEN, &token_value(b"bb")),
        ]);
        let mut bytes = encode(&message).expect("a repeated token is legal to write");
        let first = bytes
            .iter()
            .position(|b| u64::from(*b) == AUTHORIZATION_TOKEN)
            .expect("the first option's delta names the token type");
        // The value is a Token structure - Alias Type, Token Type, then the two
        // payload bytes - so it is four bytes long, not the two the payload has.
        assert_eq!(bytes[first + 1], 4, "and is followed by its four-byte Token");
        assert_eq!(bytes[first + 6], 0, "the repeat is a zero delta");
        bytes[first] = u8::try_from(key).expect("the fixture keys are one byte");
        bytes
    }
}

#[cfg(feature = "draft18")]
mod draft18 {
    use super::{option, token_value, varint, AUTHORIZATION_TOKEN, PATH, UNKNOWN};
    use moqtap_codec::draft18::message::*;
    use moqtap_codec::error::CodecError;
    use moqtap_codec::kvp::{KeyValuePair, KvpValue};

    fn subscribe_ok(track_properties: Vec<KeyValuePair>) -> SubscribeOk {
        SubscribeOk { track_alias: varint(4), parameters: Vec::new(), track_properties }
    }

    fn setup(options: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::Setup(Setup { options })
    }

    fn encode(message: &ControlMessage) -> Result<Vec<u8>, CodecError> {
        let mut buf = Vec::new();
        message.encode(&mut buf)?;
        Ok(buf)
    }

    /// Section 10.3: "Senders MUST NOT repeat the same Option Type in a
    /// message unless the option definition explicitly allows multiple
    /// instances."
    #[test]
    fn a_repeated_known_option_has_no_encoding() {
        let refused = encode(&setup(vec![option(PATH, b"/a"), option(PATH, b"/b")]));
        assert!(
            matches!(refused, Err(CodecError::DuplicateParameter(PATH))),
            "a sender may not repeat an option type: {refused:?}",
        );
    }

    /// The sender's half names no exception for types the sender does not
    /// recognise, so an unknown type may not be repeated either. This is the
    /// half that is *wider* than the receiver's.
    #[test]
    fn a_repeated_unknown_option_has_no_encoding_either() {
        let refused = encode(&setup(vec![option(UNKNOWN, b"x"), option(UNKNOWN, b"y")]));
        assert!(
            matches!(refused, Err(CodecError::DuplicateParameter(UNKNOWN))),
            "the sender's half has no carve-out for unknown types: {refused:?}",
        );
    }

    /// The reader refuses a repeat of a type this draft assigns.
    #[test]
    fn a_repeated_known_option_has_no_decoding() {
        let bytes = repeated_frame(PATH);
        let refused = ControlMessage::decode(&mut &bytes[..]);
        assert!(
            matches!(refused, Err(CodecError::DuplicateParameter(PATH))),
            "a repeated PATH is one the reader can name, and must refuse: {refused:?}",
        );
    }

    /// And carries a repeat of a type it cannot name. Section 10.3:
    /// "Receivers MUST allow duplicates of unknown Setup Options."
    ///
    /// This is the test a symmetric check fails.
    #[test]
    fn an_unknown_option_may_be_repeated_by_a_peer() {
        let bytes = repeated_frame(UNKNOWN);
        let decoded = ControlMessage::decode(&mut &bytes[..]);
        assert!(
            decoded.is_ok(),
            "a receiver must allow duplicates of options it cannot name: {decoded:?}",
        );
        let ControlMessage::Setup(Setup { options }) = decoded.unwrap() else {
            panic!("a SETUP decodes as a SETUP");
        };
        assert_eq!(options.len(), 2, "and carries both copies rather than folding them");
    }

    /// Section 10.3.1.4: "The endpoint can specify one or more tokens in
    /// SETUP that the peer can use to authorize MOQT session establishment."
    /// That is the "unless the option definition explicitly allows multiple
    /// instances" carve-out, and this draft has exactly one.
    #[test]
    fn an_authorization_token_may_be_repeated() {
        let message = setup(vec![
            option(AUTHORIZATION_TOKEN, &token_value(b"first")),
            option(AUTHORIZATION_TOKEN, &token_value(b"second")),
        ]);
        let bytes = encode(&message);
        assert!(bytes.is_ok(), "an endpoint can specify one or more tokens in SETUP: {bytes:?}",);
        let decoded = ControlMessage::decode(&mut &bytes.unwrap()[..]);
        assert!(decoded.is_ok(), "and the reader takes both back: {decoded:?}");
    }

    /// Distinct known options are the ordinary case, and go both ways.
    #[test]
    fn distinct_options_round_trip() {
        let message = setup(vec![option(PATH, b"/live"), option(0x05, b"example.test")]);
        let bytes = encode(&message).expect("two different option types are fine");
        let decoded = ControlMessage::decode(&mut &bytes[..]).expect("and read back");
        assert_eq!(decoded, message);
    }

    /// Track Properties share the delta-encoded wire shape and the helpers
    /// underneath, and carry no duplicate rule of their own - so a repeat there
    /// is not this rule's business.
    #[test]
    fn a_repeated_track_property_is_not_this_rules_business() {
        let message = ControlMessage::SubscribeOk(subscribe_ok(vec![
            KeyValuePair { key: varint(0x02), value: KvpValue::Varint(varint(1)) },
            KeyValuePair { key: varint(0x02), value: KvpValue::Varint(varint(2)) },
        ]));
        let written = encode(&message);
        assert!(
            written.is_ok(),
            "the Setup Option rule is stated about Setup Options: {written:?}",
        );
    }

    /// A SETUP frame carrying `key` twice, built by this codec and then edited
    /// in one place.
    ///
    /// The writer will not repeat a type - that is the rule above - so the frame
    /// is written under AUTHORIZATION TOKEN, which it will, and the two key
    /// deltas are then rewritten to name `key` instead. Everything else in the
    /// frame is exactly what this codec produces, so the only thing the reader
    /// can object to is the repeat.
    fn repeated_frame(key: u64) -> Vec<u8> {
        let message = setup(vec![
            option(AUTHORIZATION_TOKEN, &token_value(b"aa")),
            option(AUTHORIZATION_TOKEN, &token_value(b"bb")),
        ]);
        let mut bytes = encode(&message).expect("a repeated token is legal to write");
        let first = bytes
            .iter()
            .position(|b| u64::from(*b) == AUTHORIZATION_TOKEN)
            .expect("the first option's delta names the token type");
        // The value is a Token structure - Alias Type, Token Type, then the two
        // payload bytes - so it is four bytes long, not the two the payload has.
        assert_eq!(bytes[first + 1], 4, "and is followed by its four-byte Token");
        assert_eq!(bytes[first + 6], 0, "the repeat is a zero delta");
        bytes[first] = u8::try_from(key).expect("the fixture keys are one byte");
        bytes
    }
}

#[cfg(feature = "draft19")]
mod draft19 {
    use super::{option, token_value, varint, AUTHORIZATION_TOKEN, PATH, UNKNOWN};
    use moqtap_codec::draft19::message::*;
    use moqtap_codec::error::CodecError;
    use moqtap_codec::kvp::{KeyValuePair, KvpValue};

    fn subscribe_ok(track_properties: Vec<KeyValuePair>) -> SubscribeOk {
        SubscribeOk { track_alias: varint(4), parameters: Vec::new(), track_properties }
    }

    fn setup(options: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::Setup(Setup { options })
    }

    fn encode(message: &ControlMessage) -> Result<Vec<u8>, CodecError> {
        let mut buf = Vec::new();
        message.encode(&mut buf)?;
        Ok(buf)
    }

    /// Section 10.3: "Senders MUST NOT repeat the same Option Type in a
    /// message unless the option definition explicitly allows multiple
    /// instances."
    #[test]
    fn a_repeated_known_option_has_no_encoding() {
        let refused = encode(&setup(vec![option(PATH, b"/a"), option(PATH, b"/b")]));
        assert!(
            matches!(refused, Err(CodecError::DuplicateParameter(PATH))),
            "a sender may not repeat an option type: {refused:?}",
        );
    }

    /// The sender's half names no exception for types the sender does not
    /// recognise, so an unknown type may not be repeated either. This is the
    /// half that is *wider* than the receiver's.
    #[test]
    fn a_repeated_unknown_option_has_no_encoding_either() {
        let refused = encode(&setup(vec![option(UNKNOWN, b"x"), option(UNKNOWN, b"y")]));
        assert!(
            matches!(refused, Err(CodecError::DuplicateParameter(UNKNOWN))),
            "the sender's half has no carve-out for unknown types: {refused:?}",
        );
    }

    /// The reader refuses a repeat of a type this draft assigns.
    #[test]
    fn a_repeated_known_option_has_no_decoding() {
        let bytes = repeated_frame(PATH);
        let refused = ControlMessage::decode(&mut &bytes[..]);
        assert!(
            matches!(refused, Err(CodecError::DuplicateParameter(PATH))),
            "a repeated PATH is one the reader can name, and must refuse: {refused:?}",
        );
    }

    /// And carries a repeat of a type it cannot name. Section 10.3:
    /// "Receivers MUST allow duplicates of unknown Setup Options."
    ///
    /// This is the test a symmetric check fails.
    #[test]
    fn an_unknown_option_may_be_repeated_by_a_peer() {
        let bytes = repeated_frame(UNKNOWN);
        let decoded = ControlMessage::decode(&mut &bytes[..]);
        assert!(
            decoded.is_ok(),
            "a receiver must allow duplicates of options it cannot name: {decoded:?}",
        );
        let ControlMessage::Setup(Setup { options }) = decoded.unwrap() else {
            panic!("a SETUP decodes as a SETUP");
        };
        assert_eq!(options.len(), 2, "and carries both copies rather than folding them");
    }

    /// Section 10.3.1.4: "The endpoint can specify one or more tokens in
    /// SETUP that the peer can use to authorize MOQT session establishment."
    /// That is the "unless the option definition explicitly allows multiple
    /// instances" carve-out, and this draft has exactly one.
    #[test]
    fn an_authorization_token_may_be_repeated() {
        let message = setup(vec![
            option(AUTHORIZATION_TOKEN, &token_value(b"first")),
            option(AUTHORIZATION_TOKEN, &token_value(b"second")),
        ]);
        let bytes = encode(&message);
        assert!(bytes.is_ok(), "an endpoint can specify one or more tokens in SETUP: {bytes:?}",);
        let decoded = ControlMessage::decode(&mut &bytes.unwrap()[..]);
        assert!(decoded.is_ok(), "and the reader takes both back: {decoded:?}");
    }

    /// Distinct known options are the ordinary case, and go both ways.
    #[test]
    fn distinct_options_round_trip() {
        let message = setup(vec![option(PATH, b"/live"), option(0x05, b"example.test")]);
        let bytes = encode(&message).expect("two different option types are fine");
        let decoded = ControlMessage::decode(&mut &bytes[..]).expect("and read back");
        assert_eq!(decoded, message);
    }

    /// Track Properties share the delta-encoded wire shape and the helpers
    /// underneath, and carry no duplicate rule of their own - so a repeat there
    /// is not this rule's business.
    #[test]
    fn a_repeated_track_property_is_not_this_rules_business() {
        let message = ControlMessage::SubscribeOk(subscribe_ok(vec![
            KeyValuePair { key: varint(0x02), value: KvpValue::Varint(varint(1)) },
            KeyValuePair { key: varint(0x02), value: KvpValue::Varint(varint(2)) },
        ]));
        let written = encode(&message);
        assert!(
            written.is_ok(),
            "the Setup Option rule is stated about Setup Options: {written:?}",
        );
    }

    /// A SETUP frame carrying `key` twice, built by this codec and then edited
    /// in one place.
    ///
    /// The writer will not repeat a type - that is the rule above - so the frame
    /// is written under AUTHORIZATION TOKEN, which it will, and the two key
    /// deltas are then rewritten to name `key` instead. Everything else in the
    /// frame is exactly what this codec produces, so the only thing the reader
    /// can object to is the repeat.
    fn repeated_frame(key: u64) -> Vec<u8> {
        let message = setup(vec![
            option(AUTHORIZATION_TOKEN, &token_value(b"aa")),
            option(AUTHORIZATION_TOKEN, &token_value(b"bb")),
        ]);
        let mut bytes = encode(&message).expect("a repeated token is legal to write");
        let first = bytes
            .iter()
            .position(|b| u64::from(*b) == AUTHORIZATION_TOKEN)
            .expect("the first option's delta names the token type");
        // The value is a Token structure - Alias Type, Token Type, then the two
        // payload bytes - so it is four bytes long, not the two the payload has.
        assert_eq!(bytes[first + 1], 4, "and is followed by its four-byte Token");
        assert_eq!(bytes[first + 6], 0, "the repeat is a zero delta");
        bytes[first] = u8::try_from(key).expect("the fixture keys are one byte");
        bytes
    }
}

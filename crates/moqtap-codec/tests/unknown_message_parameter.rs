//! An unknown Message Parameter ends the session from draft-16 on, and is
//! carried before it.
//!
//! Drafts 16, 17, 18 and 19 all state it in the paragraph that introduces
//! parameters: "All Message Parameters MUST be defined in the negotiated version
//! of MOQT or negotiated via Setup Options. An endpoint that receives an unknown
//! Message Parameter MUST close the session with PROTOCOL_VIOLATION." Drafts 17
//! and later add the reasoning — "Because the receiver has to understand every
//! Message Parameter, there is no need for a mechanism to skip unknown
//! parameters" — and draft-19 draws the consequence for the framing: "Because
//! unknown parameters cannot be skipped, the block is bounded by a parameter
//! count rather than a length."
//!
//! # The rule changed direction, and a blanket implementation is wrong somewhere
//!
//! Drafts 11 through 15 say the opposite about the same parameters: "Receivers
//! MUST allow duplicates of unknown parameters", which presumes an unknown
//! parameter arrives and is carried. Draft-16 narrows that sentence to "unknown
//! **Setup** Parameters" and adds the close beside it, in the same paragraph —
//! one edit with both halves. So the same frame is ordinary traffic on draft-15
//! and a session close on draft-16, and both directions are gated here.
//!
//! # One namespace, not two
//!
//! The narrowing is what makes this a rule about Message Parameters alone. Every
//! draft from 16 to 20 still says a receiver ignores an unrecognised Setup
//! Option or Setup Parameter, so an unknown type in a SETUP is carried on
//! exactly the drafts where an unknown type anywhere else ends the session. A
//! codec that applied one rule to both namespaces would close sessions over the
//! extension mechanism the drafts kept.
//!
//! # Why the registry has to be complete rather than convenient
//!
//! Before this rule the list of known types was consulted for one thing: whether
//! a repeat could be refused. A missing entry made the codec tolerant of a
//! repeat it could have refused, which costs nothing. The same list now decides
//! whether a session ends, so a missing entry closes sessions over parameters
//! the draft assigns. `every_type_the_registry_assigns_is_carried` is the gate
//! that says the list is the draft's and not the one this codec happened to
//! need.

#![cfg(any(
    feature = "draft15",
    feature = "draft16",
    feature = "draft19",
    feature = "draft20",
    feature = "draft21"
))]

use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::varint::VarInt;

fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).expect("fixture value fits a varint")
}

/// A parameter type no draft in this range assigns, in either namespace.
///
/// Odd, so its value is length-prefixed bytes under every one of these drafts
/// and the frame around it is well-formed whatever the reader decides about the
/// type itself. That matters: a gate built on a type whose value could not be
/// parsed would pass for the wrong reason.
const AN_EXTENSION_TYPE: u64 = 0x41;

fn extension_parameter() -> KeyValuePair {
    KeyValuePair { key: varint(AN_EXTENSION_TYPE), value: KvpValue::Bytes(b"\xde\xad".to_vec()) }
}

#[cfg(feature = "draft15")]
mod draft15 {
    use super::{extension_parameter, varint};
    use moqtap_codec::draft15::message::*;
    use moqtap_codec::types::*;

    /// Draft-15 carries the parameter this draft's successor closes over.
    ///
    /// Section 9.2: "Receivers MUST allow duplicates of unknown parameters."
    /// A rule about duplicates of a thing is a rule that presumes the thing
    /// arrives, and draft-15 has no sentence anywhere requiring a close for an
    /// unknown Message Parameter — the close and the narrowed duplicate sentence
    /// arrive together at draft-16.
    ///
    /// Applying draft-16's rule here fails with:
    ///
    /// ```text
    /// assertion `left == right` failed: an unknown parameter must be carried on
    /// this draft: Err(UnknownMessageParameter(65))
    /// ```
    #[test]
    fn an_unknown_message_parameter_is_carried() {
        let message = ControlMessage::Subscribe(Subscribe {
            request_id: varint(1),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            parameters: vec![extension_parameter()],
        });
        let mut buf = Vec::new();
        message.encode(&mut buf).expect("encode");
        let back = ControlMessage::decode(&mut &buf[..]);
        assert_eq!(
            back.as_ref().ok(),
            Some(&message),
            "an unknown parameter must be carried on this draft: {back:?}",
        );
    }
}

#[cfg(feature = "draft16")]
mod draft16 {
    use super::{extension_parameter, varint, AN_EXTENSION_TYPE};
    use moqtap_codec::draft16::message::*;
    use moqtap_codec::error::CodecError;
    use moqtap_codec::kvp::{KeyValuePair, KvpValue};
    use moqtap_codec::types::*;

    /// Every Message Parameter type draft-16 Section 13.2 assigns, with the name
    /// the registry gives it.
    ///
    /// Not the list this codec found convenient — the list the draft publishes.
    /// Value shapes follow from the type's parity, which is the whole of what
    /// Section 1.4.3 says about them: "A single varint encoded value when Type is
    /// even, otherwise a sequence of Length bytes."
    const REGISTRY: &[(u64, &str)] = &[
        (0x02, "DELIVERY_TIMEOUT"),
        (0x03, "AUTHORIZATION_TOKEN"),
        (0x08, "EXPIRES"),
        (0x09, "LARGEST_OBJECT"),
        (0x10, "FORWARD"),
        (0x20, "SUBSCRIBER_PRIORITY"),
        (0x21, "SUBSCRIPTION_FILTER"),
        (0x22, "GROUP_ORDER"),
        (0x32, "NEW_GROUP_REQUEST"),
    ];

    /// A parameter of `key` whose value is the shape its parity implies.
    ///
    /// Two of the types have bytes that are more than opaque, and both are
    /// checked against their own structure, so neither can be filled with
    /// arbitrary bytes here. AUTHORIZATION_TOKEN's value is a Token structure —
    /// USE_VALUE with Token Type 0 is the shortest complete form.
    /// SUBSCRIPTION_FILTER's is a Subscription Filter, and Largest Object (0x2)
    /// is the shortest: one byte, with no Start Location and no End Group after
    /// it.
    fn parameter(key: u64) -> KeyValuePair {
        let value = if key.is_multiple_of(2) {
            KvpValue::Varint(varint(1))
        } else if key == 0x03 {
            KvpValue::Bytes(vec![0x03, 0x00])
        } else if key == 0x21 {
            KvpValue::Bytes(vec![0x02])
        } else {
            KvpValue::Bytes(b"v".to_vec())
        };
        KeyValuePair { key: varint(key), value }
    }

    fn subscribe(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            request_id: varint(1),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            parameters,
        })
    }

    fn client_setup(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::ClientSetup(ClientSetup { parameters })
    }

    fn roundtrip(message: &ControlMessage) -> Result<ControlMessage, CodecError> {
        let mut buf = Vec::new();
        message.encode(&mut buf).expect("the encoder writes the parameters it is given");
        ControlMessage::decode(&mut &buf[..])
    }

    /// A Message Parameter type this draft does not define ends the session.
    ///
    /// Removing the check fails with:
    ///
    /// ```text
    /// a type this draft does not define was carried: Ok(Subscribe(Subscribe {
    /// request_id: VarInt(1), track_namespace: TrackNamespace([[110, 115]]),
    /// track_name: [116], parameters: [KeyValuePair { key: VarInt(65),
    /// value: Bytes([222, 173]) }] }))
    /// ```
    #[test]
    fn an_unknown_message_parameter_is_refused() {
        let got = roundtrip(&subscribe(vec![extension_parameter()]));
        assert!(
            matches!(got, Err(CodecError::UnknownMessageParameter(AN_EXTENSION_TYPE))),
            "a type this draft does not define was carried: {got:?}",
        );
    }

    /// The same type in a SETUP is carried, because the other half of the same
    /// paragraph kept it.
    ///
    /// Section 9.2: "Receivers ignore unrecognized Setup Parameters." This is the
    /// asymmetry the rule above is only half of, and the direction where being
    /// wrong is expensive: a codec applying the message rule to both namespaces
    /// closes sessions over the extension mechanism this draft deliberately
    /// keeps.
    ///
    /// Applying the message-namespace rule to setup parameters fails with:
    ///
    /// ```text
    /// assertion `left == right` failed: an unrecognised Setup Parameter must be
    /// ignored, not refused: Err(UnknownMessageParameter(65))
    /// ```
    #[test]
    fn an_unknown_setup_parameter_is_carried() {
        let message = client_setup(vec![extension_parameter()]);
        let back = roundtrip(&message);
        assert_eq!(
            back.as_ref().ok(),
            Some(&message),
            "an unrecognised Setup Parameter must be ignored, not refused: {back:?}",
        );
    }

    /// Every type the registry assigns survives the check, one message each.
    ///
    /// The list that decides whether a session ends has to be the draft's. A
    /// codec whose list is short by one entry refuses a parameter a conforming
    /// peer may send, and the peer learns about it as a closed session rather
    /// than as an ignored field.
    ///
    /// Dropping NEW_GROUP_REQUEST from the codec's list fails with:
    ///
    /// ```text
    /// assertion `left == right` failed: NEW_GROUP_REQUEST (0x32) is in this
    /// draft's registry: Err(UnknownMessageParameter(50))
    /// ```
    #[test]
    fn every_type_the_registry_assigns_is_carried() {
        for (key, name) in REGISTRY {
            let message = subscribe(vec![parameter(*key)]);
            let back = roundtrip(&message);
            assert_eq!(
                back.as_ref().ok(),
                Some(&message),
                "{name} ({key:#04x}) is in this draft's registry: {back:?}",
            );
        }
    }

    /// And all nine together in one message, which is also the ascending-order
    /// path through the delta encoding.
    #[test]
    fn the_whole_registry_fits_in_one_message() {
        let message = subscribe(REGISTRY.iter().map(|(key, _)| parameter(*key)).collect());
        let back = roundtrip(&message);
        assert_eq!(back.as_ref().ok(), Some(&message), "nine known types are a list: {back:?}");
    }
}

#[cfg(feature = "draft19")]
mod draft19 {
    use super::{extension_parameter, varint, AN_EXTENSION_TYPE};
    use moqtap_codec::draft19::message::*;
    use moqtap_codec::error::CodecError;
    use moqtap_codec::kvp::KeyValuePair;
    use moqtap_codec::types::*;

    fn roundtrip(message: &ControlMessage) -> Result<ControlMessage, CodecError> {
        let mut buf = Vec::new();
        message.encode(&mut buf).expect("the encoder writes the parameters it is given");
        ControlMessage::decode(&mut &buf[..])
    }

    fn subscribe(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            request_id: varint(1),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            parameters,
        })
    }

    /// The newest draft states the rule in the same words and answers the same
    /// way.
    ///
    /// Draft-19 goes further than draft-16 about why: "Because unknown
    /// parameters cannot be skipped, the block is bounded by a parameter count
    /// rather than a length." The framing itself assumes every type is known, so
    /// there is nowhere for an unknown one to go.
    ///
    /// Reporting this as an ordinary malformation instead — which is what it did
    /// before it had a variant — fails with:
    ///
    /// ```text
    /// a type this draft does not define was not named as unknown:
    /// Err(InvalidField)
    /// ```
    #[test]
    fn an_unknown_message_parameter_is_refused() {
        let got = roundtrip(&subscribe(vec![extension_parameter()]));
        assert!(
            matches!(got, Err(CodecError::UnknownMessageParameter(AN_EXTENSION_TYPE))),
            "a type this draft does not define was not named as unknown: {got:?}",
        );
    }

    /// A Setup Option this draft does not name is still carried.
    ///
    /// Section 10.3: "Receivers MUST ignore unrecognized Setup Options." The
    /// namespaces have not converged; only the message one closes.
    ///
    /// Applying the message-namespace rule to setup options fails with:
    ///
    /// ```text
    /// assertion `left == right` failed: an unrecognised Setup Option must be
    /// ignored, not refused: Err(UnknownMessageParameter(65))
    /// ```
    #[test]
    fn an_unknown_setup_option_is_carried() {
        let message = ControlMessage::Setup(Setup { options: vec![extension_parameter()] });
        let back = roundtrip(&message);
        assert_eq!(
            back.as_ref().ok(),
            Some(&message),
            "an unrecognised Setup Option must be ignored, not refused: {back:?}",
        );
    }
}

#[cfg(feature = "draft20")]
mod draft20 {
    use super::{extension_parameter, varint, AN_EXTENSION_TYPE};
    use moqtap_codec::draft20::message::*;
    use moqtap_codec::error::CodecError;
    use moqtap_codec::kvp::KeyValuePair;
    use moqtap_codec::types::*;

    fn roundtrip(message: &ControlMessage) -> Result<ControlMessage, CodecError> {
        let mut buf = Vec::new();
        message.encode(&mut buf).expect("the encoder writes the parameters it is given");
        ControlMessage::decode(&mut &buf[..])
    }

    fn subscribe(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            request_id: varint(1),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            parameters,
        })
    }

    /// The newest draft states the rule in the same words and answers the same
    /// way.
    ///
    /// Draft-19 goes further than draft-16 about why: "Because unknown
    /// parameters cannot be skipped, the block is bounded by a parameter count
    /// rather than a length." The framing itself assumes every type is known, so
    /// there is nowhere for an unknown one to go.
    ///
    /// Reporting this as an ordinary malformation instead — which is what it did
    /// before it had a variant — fails with:
    ///
    /// ```text
    /// a type this draft does not define was not named as unknown:
    /// Err(InvalidField)
    /// ```
    #[test]
    fn an_unknown_message_parameter_is_refused() {
        let got = roundtrip(&subscribe(vec![extension_parameter()]));
        assert!(
            matches!(got, Err(CodecError::UnknownMessageParameter(AN_EXTENSION_TYPE))),
            "a type this draft does not define was not named as unknown: {got:?}",
        );
    }

    /// A Setup Option this draft does not name is still carried.
    ///
    /// Section 10.3: "Receivers MUST ignore unrecognized Setup Options." The
    /// namespaces have not converged; only the message one closes.
    ///
    /// Applying the message-namespace rule to setup options fails with:
    ///
    /// ```text
    /// assertion `left == right` failed: an unrecognised Setup Option must be
    /// ignored, not refused: Err(UnknownMessageParameter(65))
    /// ```
    #[test]
    fn an_unknown_setup_option_is_carried() {
        let message = ControlMessage::Setup(Setup { options: vec![extension_parameter()] });
        let back = roundtrip(&message);
        assert_eq!(
            back.as_ref().ok(),
            Some(&message),
            "an unrecognised Setup Option must be ignored, not refused: {back:?}",
        );
    }
}
#[cfg(feature = "draft21")]
mod draft21 {
    use super::{extension_parameter, varint, AN_EXTENSION_TYPE};
    use moqtap_codec::draft21::message::*;
    use moqtap_codec::error::CodecError;
    use moqtap_codec::kvp::KeyValuePair;
    use moqtap_codec::types::*;

    fn roundtrip(message: &ControlMessage) -> Result<ControlMessage, CodecError> {
        let mut buf = Vec::new();
        message.encode(&mut buf).expect("the encoder writes the parameters it is given");
        ControlMessage::decode(&mut &buf[..])
    }

    fn subscribe(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            request_id: varint(1),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            parameters,
        })
    }

    /// The newest draft states the rule in the same words and answers the same
    /// way.
    ///
    /// Draft-19 goes further than draft-16 about why: "Because unknown
    /// parameters cannot be skipped, the block is bounded by a parameter count
    /// rather than a length." The framing itself assumes every type is known, so
    /// there is nowhere for an unknown one to go.
    ///
    /// Reporting this as an ordinary malformation instead — which is what it did
    /// before it had a variant — fails with:
    ///
    /// ```text
    /// a type this draft does not define was not named as unknown:
    /// Err(InvalidField)
    /// ```
    #[test]
    fn an_unknown_message_parameter_is_refused() {
        let got = roundtrip(&subscribe(vec![extension_parameter()]));
        assert!(
            matches!(got, Err(CodecError::UnknownMessageParameter(AN_EXTENSION_TYPE))),
            "a type this draft does not define was not named as unknown: {got:?}",
        );
    }

    /// A Setup Option this draft does not name is still carried.
    ///
    /// Section 9.1: "Receivers MUST ignore unrecognized Setup Options." The
    /// namespaces have not converged; only the message one closes.
    ///
    /// Applying the message-namespace rule to setup options fails with:
    ///
    /// ```text
    /// assertion `left == right` failed: an unrecognised Setup Option must be
    /// ignored, not refused: Err(UnknownMessageParameter(65))
    /// ```
    #[test]
    fn an_unknown_setup_option_is_carried() {
        let message = ControlMessage::Setup(Setup { options: vec![extension_parameter()] });
        let back = roundtrip(&message);
        assert_eq!(
            back.as_ref().ok(),
            Some(&message),
            "an unrecognised Setup Option must be ignored, not refused: {back:?}",
        );
    }
}

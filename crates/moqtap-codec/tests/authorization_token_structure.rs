//! The AUTHORIZATION TOKEN parameter carries a structure, not opaque bytes.
//!
//! Drafts 11 through 19 all define it the same way:
//!
//! ```text
//! Token {
//!   Alias Type (i),
//!   [Token Alias (i),]
//!   [Token Type (i),]
//!   [Token Value (..)]
//! }
//! ```
//!
//! and the Alias Type is what says which of the bracketed fields follow — "an
//! integer defining both the serialization and the processing behavior of the
//! receiver". A receiver that cannot parse the structure cannot act on the
//! parameter at all, so from draft-12 on each draft gives the case its own
//! sentence: "If the Token structure cannot be decoded, the receiver MUST close
//! the Session with KEY_VALUE_FORMATTING_ERROR." Draft-11 reaches the same
//! answer through the general rule its Section 1.3.2 states about every Type:
//! "If a receiver understands a Type, and the following Value or Length/Value
//! does not match the serialization defined by that Type, the receiver MUST
//! terminate the session with error code 'Key-Value Formatting Error'."
//!
//! Every fixture here is framed by this codec's own encoder: the message
//! framing, the parameter count and the key are exactly what it writes. The
//! only thing the reader can object to is the token itself.
//!
//! The token is written into the frame afterwards, and the reason is the same
//! rule read from the other side. A Token that cannot be decoded is one the
//! receiver must close the session over, so writing one is not a way to send it
//! — the encoder refuses every token the gates below hand the decoder, which is
//! what `a_token_the_reader_refuses_is_one_the_writer_will_not_write` is about.
//! So each frame is written around a well-formed token and the token alone is
//! replaced. Where the malformed token is the same length, every length in the
//! frame is still the encoder's; where it is not, two are recomputed — the
//! value's own and the message's declared Length — and nothing else moves.
//!
//! Two boundaries are gated as carefully as the refusals, because both are the
//! expensive direction:
//!
//! - **Every form the drafts define is carried.** Four Alias Types, two of them
//!   carrying no Token Value at all. A reader that demanded a Token Type would
//!   refuse the two forms an alias exists for.
//! - **The number is not the rule.** Draft-11 numbers the token 0x01 among
//!   version-specific parameters, where drafts 12 and later number it 0x03 in
//!   both namespaces. A draft-11 setup 0x01 is a PATH, and reading one as a
//!   token would refuse paths the draft permits.
//!
//! Drafts 07 through 10 have no Token and no Key-Value-Pair. Their gate is at
//! the bottom, and it is a negative one: the same bytes travel unread.

#![allow(clippy::items_after_test_module)]

mod frames;

#[cfg(any(
    feature = "draft10",
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19"
))]
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
#[cfg(any(
    feature = "draft10",
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19"
))]
use moqtap_codec::varint::VarInt;

#[cfg(any(
    feature = "draft10",
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19"
))]
fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).expect("fixture value fits a varint")
}

#[cfg(any(
    feature = "draft10",
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19"
))]
fn pair(key: u64, value: Vec<u8>) -> KeyValuePair {
    KeyValuePair { key: varint(key), value: KvpValue::Bytes(value) }
}

/// The shortest well-formed Token: USE_ALIAS, then the alias.
///
/// What every frame below is written around. Two bytes, no Token Type and no
/// Token Value, which is the whole of the structure for this Alias Type.
#[cfg(any(
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19"
))]
const WELL_FORMED: &[u8] = &[0x02, 0x07];

/// The five malformed tokens the gates below hand the decoder, in the order
/// they appear there.
///
/// Each has a gate of its own naming what is wrong with it. Together they are
/// what the sender-side gate walks, because the rule it checks is one rule and
/// not five.
#[cfg(any(
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19"
))]
const MALFORMED: &[&[u8]] = &[
    // No Alias Type at all.
    &[],
    // An Alias Type outside the four the draft assigns.
    &[0x04, 0x01],
    // REGISTER, promising an Alias that never arrives.
    &[0x01],
    // REGISTER again, stopping before its Token Type.
    &[0x01, 0x07],
    // DELETE, with a byte after the Alias that belongs to no field.
    &[0x00, 0x07, 0x63],
];

/// A Token that carries an Alias and nothing else: DELETE and USE_ALIAS.
///
/// Both are the whole structure — "There is an Alias but no Type or Value" —
/// so a byte after the Alias belongs to no field the draft defines.
#[cfg(any(
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19"
))]
fn alias_only(alias_type: u8, alias: u8) -> Vec<u8> {
    vec![alias_type, alias]
}

/// A Token that carries a Token Type and a Token Value: REGISTER and USE_VALUE.
///
/// REGISTER carries an Alias in front of them and USE_VALUE does not, which is
/// the only difference between the two on the wire.
#[cfg(any(
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19"
))]
fn with_value(alias_type: u8, alias: Option<u8>, token_type: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![alias_type];
    out.extend(alias);
    out.push(token_type);
    out.extend_from_slice(value);
    out
}

/// The gates every draft from 11 to 19 states in the same structure.
///
/// Each expansion needs `subscribe`, `encode` and `decode` from the module it
/// lands in: the fields in front of the parameters are not the same on any two
/// of these drafts, and drafts 16 and later delta-encode the parameter types on
/// top of that.
///
/// `$key` is the parameter type this draft numbers the token, which is the
/// second half of the rule. The refusal must name the number the frame actually
/// carried, or a reader chasing it consults the wrong table.
///
/// The ablations recorded below were run on every draft in the range and fail on
/// all of them — nine drafts, 11 through 19, with no gaps. The structure is read
/// by one shared parser, so an ablation of it is visible from every expansion at
/// once: removing the Alias Type check fails
/// `an_unassigned_alias_type_is_refused` on all nine and nothing else. The
/// message quoted in each is draft-13's, with the fixture's own unchanging
/// fields elided where they are the same in every one; the parameter at the end
/// is what the gate is about.
#[cfg(any(
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19"
))]
macro_rules! token_structure_gates {
    ($draft:ident, $key:expr) => {
        use super::{alias_only, pair, with_value, MALFORMED, WELL_FORMED};
        use moqtap_codec::error::CodecError;

        /// The frame this codec writes for a SUBSCRIBE carrying a well-formed
        /// token, with the token replaced by `bad`.
        ///
        /// See the note at the top of the file: the encoder will not write a
        /// token the decoder refuses, so the frame is built around one it will
        /// write and the token alone is rewritten.
        fn carrying(bad: &[u8]) -> Vec<u8> {
            super::frames::with_length_prefixed_value(
                &encode(&subscribe(vec![pair($key, WELL_FORMED.to_vec())])),
                WELL_FORMED,
                bad,
            )
        }

        /// A Token whose value is empty has no Alias Type, so nothing about it
        /// can be parsed.
        ///
        /// The shortest possible malformation, and the one a length field alone
        /// would let through: the parameter is well-formed as a key-value pair
        /// and states a value length of zero.
        ///
        /// Removing the check fails with:
        ///
        /// ```text
        /// a token with no Alias Type was carried: Ok(Subscribe(Subscribe {
        /// request_id: VarInt(1), track_namespace: TrackNamespace([[110, 115]]),
        /// track_name: [116], subscriber_priority: 5, group_order: Ascending,
        /// forward: Forward, filter_type: NextGroupStart, start_group: None,
        /// start_object: None, end_group: None, parameters: [KeyValuePair {
        /// key: VarInt(3), value: Bytes([]) }] }))
        /// ```
        #[test]
        fn a_token_with_no_alias_type_is_refused() {
            let got = decode(&carrying(&[]));
            assert!(
                matches!(got, Err(CodecError::KeyValueFormatting { key, .. }) if key == $key),
                "a token with no Alias Type was carried: {got:?}",
            );
        }

        /// An Alias Type outside the four the draft assigns cannot be parsed
        /// past.
        ///
        /// This is why an unassigned Alias Type is not something to skip. The
        /// Alias Type is what says how many fields follow, so a reader meeting
        /// an unknown one does not know where the token ends, let alone what it
        /// holds.
        ///
        /// Removing the check fails with:
        ///
        /// ```text
        /// an unassigned Alias Type was carried: Ok(Subscribe(Subscribe {
        /// ... parameters: [KeyValuePair { key: VarInt(3), value: Bytes([4, 1]) }] }))
        /// ```
        #[test]
        fn an_unassigned_alias_type_is_refused() {
            let got = decode(&carrying(&[0x04, 0x01]));
            assert!(
                matches!(got, Err(CodecError::KeyValueFormatting { key, .. }) if key == $key),
                "an unassigned Alias Type was carried: {got:?}",
            );
        }

        /// An Alias Type that promises a Token Alias, with the value ending
        /// first.
        ///
        /// Removing the check fails with:
        ///
        /// ```text
        /// a token promising an Alias it does not carry was carried: Ok(Subscribe(
        /// Subscribe { ... parameters: [KeyValuePair { key: VarInt(3),
        /// value: Bytes([1]) }] }))
        /// ```
        #[test]
        fn a_promised_alias_that_never_arrives_is_refused() {
            let got = decode(&carrying(&[0x01]));
            assert!(
                matches!(got, Err(CodecError::KeyValueFormatting { key, .. }) if key == $key),
                "a token promising an Alias it does not carry was carried: {got:?}",
            );
        }

        /// A REGISTER that stops after its Alias, with no Token Type behind it.
        ///
        /// The field that is missing here is one field further in than the gate
        /// above, which is what separates a truncated token from an empty one.
        ///
        /// Removing the check fails with:
        ///
        /// ```text
        /// a token promising a Token Type it does not carry was carried: Ok(Subscribe(
        /// Subscribe { ... parameters: [KeyValuePair { key: VarInt(3),
        /// value: Bytes([1, 7]) }] }))
        /// ```
        #[test]
        fn a_promised_token_type_that_never_arrives_is_refused() {
            let got = decode(&carrying(&[0x01, 0x07]));
            assert!(
                matches!(got, Err(CodecError::KeyValueFormatting { key, .. }) if key == $key),
                "a token promising a Token Type it does not carry was carried: {got:?}",
            );
        }

        /// A form that carries no Token Value, followed by bytes.
        ///
        /// The other direction of the same disagreement, and the one only a
        /// bounded value can see: the Token Value has no length of its own and
        /// runs to the end of the parameter, so on DELETE and USE_ALIAS — which
        /// have no Token Value — the parameter must end where the Alias does. A
        /// reader that stopped at the last field it wanted would take these
        /// bytes for a value the draft says is not there.
        ///
        /// Removing the check fails with:
        ///
        /// ```text
        /// bytes after a token that ends at its Alias were carried: Ok(Subscribe(
        /// Subscribe { ... parameters: [KeyValuePair { key: VarInt(3),
        /// value: Bytes([0, 7, 99]) }] }))
        /// ```
        #[test]
        fn bytes_after_a_token_that_carries_no_value_are_refused() {
            let got = decode(&carrying(&[0x00, 0x07, 0x63]));
            assert!(
                matches!(got, Err(CodecError::KeyValueFormatting { key, .. }) if key == $key),
                "bytes after a token that ends at its Alias were carried: {got:?}",
            );
        }

        /// Every token the reader refuses is one the writer will not write.
        ///
        /// The five gates above read the rule from the receiver's side, which
        /// is the side every draft states it for — drafts 15 through 19 as "If
        /// the Token structure cannot be decoded, the receiver MUST close the
        /// Session with KEY_VALUE_FORMATTING_ERROR", drafts 12, 13 and 14 in
        /// those words with the code named in prose, and draft-11 through the
        /// general rule about every Type that the file's own header quotes.
        /// This is the same rule from the sender's side. A caller that builds a
        /// token the receiver cannot decode has written a message that ends the
        /// session, and would find that out from the far end rather than from
        /// the call that wrote it.
        ///
        /// It is also what the frames above are built the way they are for.
        ///
        /// # What it catches
        ///
        /// Dropping the `check_authorization_tokens` call from this draft's
        /// parameter encoder — which is where every draft in this range had it
        /// missing:
        ///
        /// ```text
        /// the writer produced a token the reader refuses: [] gave Ok(())
        /// ```
        #[test]
        fn a_token_the_reader_refuses_is_one_the_writer_will_not_write() {
            for bad in MALFORMED {
                let mut buf = Vec::new();
                let result = subscribe(vec![pair($key, bad.to_vec())]).encode(&mut buf);
                assert!(
                    matches!(result, Err(CodecError::KeyValueFormatting { key, .. })
                             if key == $key),
                    "the writer produced a token the reader refuses: {bad:?} gave {result:?}",
                );
                assert!(
                    buf.is_empty(),
                    "a refused message must leave the caller's buffer alone, and {bad:?} \
                     wrote {} bytes",
                    buf.len(),
                );
            }
        }

        /// All four Alias Types are carried, so none of the gates above is
        /// passing because every token is refused.
        ///
        /// DELETE and USE_ALIAS end at the Alias; REGISTER and USE_VALUE carry
        /// a Token Type and a Token Value, and REGISTER alone carries all three
        /// fields. A reader that insisted on a Token Type would refuse the two
        /// forms the Alias exists for, and one that insisted on an Alias would
        /// refuse the only form a sender can use before registering anything.
        #[test]
        fn every_form_the_draft_defines_is_carried() {
            let forms: Vec<(&str, Vec<u8>)> = vec![
                ("DELETE", alias_only(0x00, 0x07)),
                ("REGISTER", with_value(0x01, Some(0x07), 0x00, b"secret")),
                ("USE_ALIAS", alias_only(0x02, 0x07)),
                ("USE_VALUE", with_value(0x03, None, 0x00, b"secret")),
                // A Token Value may be empty: the field runs to the end of the
                // parameter, and no draft states a minimum for it.
                ("USE_VALUE, empty value", with_value(0x03, None, 0x00, b"")),
            ];
            for (name, value) in forms {
                let message = subscribe(vec![pair($key, value)]);
                let back = decode(&encode(&message))
                    .unwrap_or_else(|e| panic!("{name} is a form this draft defines: {e:?}"));
                assert_eq!(back, message, "{name} must read back as it was written");
            }
        }
    };
    ($draft:ident, $key:expr, setup) => {
        token_structure_gates!($draft, $key);

        /// The setup namespace carries the token too, and its writer is held to
        /// the same structure.
        ///
        /// Draft-12 is where the token joins the setup registry — draft-11
        /// numbers 0x01 PATH there, which is what
        /// `a_setup_path_is_not_read_as_a_token` is about — so from draft-12 on
        /// both namespaces define it and both readers hold it to the structure.
        /// The writers are two functions on most of these drafts, and a gate on
        /// one of them says nothing about the other.
        ///
        /// # What it catches
        ///
        /// Dropping the `check_authorization_tokens` call from this draft's
        /// setup-parameter encoder, leaving the message-namespace one in place:
        ///
        /// ```text
        /// the writer produced a setup token the reader refuses: [] gave Ok(())
        /// ```
        #[test]
        fn a_setup_token_the_reader_refuses_is_one_the_writer_will_not_write() {
            for bad in MALFORMED {
                let mut buf = Vec::new();
                let result = setup(vec![pair($key, bad.to_vec())]).encode(&mut buf);
                assert!(
                    matches!(result, Err(CodecError::KeyValueFormatting { key, .. })
                             if key == $key),
                    "the writer produced a setup token the reader refuses: {bad:?} \
                     gave {result:?}",
                );
            }
        }
    };
}

#[cfg(feature = "draft11")]
mod draft11 {
    use moqtap_codec::draft11::message::*;
    use moqtap_codec::kvp::KeyValuePair;
    use moqtap_codec::types::*;

    /// Section 8.2.1.1: "The AUTHORIZATION TOKEN parameter (Parameter Type
    /// 0x01)". Draft-12 moves it to 0x03 and adds it to the setup namespace.
    const AUTHORIZATION_TOKEN: u64 = 0x01;

    fn subscribe(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            request_id: super::varint(1),
            track_alias: super::varint(4),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            subscriber_priority: 5,
            group_order: GroupOrder::Ascending,
            forward: Forward::Forward,
            filter_type: super::varint(0x2),
            start_group: None,
            start_object: None,
            end_group: None,
            parameters,
        })
    }

    fn client_setup(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::ClientSetup(ClientSetup {
            supported_versions: vec![super::varint(0xff00_000b)],
            parameters,
        })
    }

    fn encode(message: &ControlMessage) -> Vec<u8> {
        let mut buf = Vec::new();
        message.encode(&mut buf).expect("the encoder writes the value it is given");
        buf
    }

    fn decode(bytes: &[u8]) -> Result<ControlMessage, moqtap_codec::error::CodecError> {
        ControlMessage::decode(&mut &bytes[..])
    }

    token_structure_gates!(draft11, AUTHORIZATION_TOKEN);

    /// The same number, in the namespace where it is not a token.
    ///
    /// This is the whole of draft-11's namespace trap in one frame. Section
    /// 8.3.2.1 gives Setup Parameter 0x01 to PATH, whose value is a URI and
    /// whose first byte is whatever the URI starts with. Section 8.2.1.1 gives
    /// Version Specific Parameter 0x01 to AUTHORIZATION TOKEN. A codec holding
    /// one token-type list across both namespaces reads a PATH as a Token and
    /// closes the session over the letter the path happens to begin with.
    ///
    /// The path here begins with `h`, which is 0x68 and no Alias Type at all,
    /// so a reader that consulted the wrong namespace refuses it outright.
    ///
    /// Sharing one list across the two namespaces fails with:
    ///
    /// ```text
    /// assertion `left == right` failed: a setup PATH was read as a Token:
    /// Err(KeyValueFormatting { key: 1, detail: "its Alias Type is not one this
    /// draft assigns" })
    /// ```
    #[test]
    fn a_setup_path_is_not_read_as_a_token() {
        const SETUP_PATH: u64 = 0x01;
        let message =
            client_setup(vec![super::pair(SETUP_PATH, b"https://relay.example/x".to_vec())]);
        let got = decode(&encode(&message));
        assert_eq!(got.as_ref().ok(), Some(&message), "a setup PATH was read as a Token: {got:?}",);
    }
}

#[cfg(feature = "draft12")]
mod draft12 {
    use moqtap_codec::draft12::message::*;
    use moqtap_codec::kvp::KeyValuePair;
    use moqtap_codec::types::*;

    const AUTHORIZATION_TOKEN: u64 = 0x03;

    fn subscribe(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            request_id: super::varint(1),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            subscriber_priority: 5,
            group_order: GroupOrder::Ascending,
            forward: Forward::Forward,
            filter_type: super::varint(0x2),
            start_group: None,
            start_object: None,
            end_group: None,
            parameters,
        })
    }

    fn setup(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::ClientSetup(ClientSetup {
            supported_versions: vec![super::varint(0xff00_000c)],
            parameters,
        })
    }

    fn encode(message: &ControlMessage) -> Vec<u8> {
        let mut buf = Vec::new();
        message.encode(&mut buf).expect("the encoder writes the value it is given");
        buf
    }

    fn decode(bytes: &[u8]) -> Result<ControlMessage, moqtap_codec::error::CodecError> {
        ControlMessage::decode(&mut &bytes[..])
    }

    token_structure_gates!(draft12, AUTHORIZATION_TOKEN, setup);
}

#[cfg(feature = "draft13")]
mod draft13 {
    use moqtap_codec::draft13::message::*;
    use moqtap_codec::kvp::KeyValuePair;
    use moqtap_codec::types::*;

    const AUTHORIZATION_TOKEN: u64 = 0x03;

    /// A type draft-13 does not name, and could not have a serialization for.
    ///
    /// Section 8.2.1 lists the version-specific parameters this draft defines;
    /// this is not among them, and it is odd, so its value is length-prefixed
    /// bytes exactly as the token's is.
    const AN_EXTENSION_TYPE: u64 = 0x33;

    fn subscribe(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            request_id: super::varint(1),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            subscriber_priority: 5,
            group_order: GroupOrder::Ascending,
            forward: Forward::Forward,
            filter_type: FilterType::NextGroupStart,
            start_group: None,
            start_object: None,
            end_group: None,
            parameters,
        })
    }

    fn setup(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::ClientSetup(ClientSetup {
            supported_versions: vec![super::varint(0xff00_000d)],
            parameters,
        })
    }

    fn encode(message: &ControlMessage) -> Vec<u8> {
        let mut buf = Vec::new();
        message.encode(&mut buf).expect("the encoder writes the value it is given");
        buf
    }

    fn decode(bytes: &[u8]) -> Result<ControlMessage, moqtap_codec::error::CodecError> {
        ControlMessage::decode(&mut &bytes[..])
    }

    token_structure_gates!(draft13, AUTHORIZATION_TOKEN, setup);

    /// The rule is conditional on understanding the Type, and this is the
    /// condition.
    ///
    /// Section 1.3.2 opens with "If a receiver understands a Type". A parameter
    /// this draft does not define has no serialization here to disagree with, so
    /// the bytes below — which are refused outright under the token's number —
    /// travel untouched under a number the draft has never assigned. Applying
    /// the token's structure to every length-prefixed parameter would close
    /// sessions over extensions the drafts leave room for.
    ///
    /// Dropping the condition fails with:
    ///
    /// ```text
    /// assertion `left == right` failed: an extension parameter was held to the
    /// token's structure: Err(KeyValueFormatting { key: 51, detail: "its Alias Type
    /// is not one this draft assigns" })
    /// ```
    #[test]
    fn a_type_this_draft_cannot_name_is_not_held_to_the_token_structure() {
        let message = subscribe(vec![super::pair(AN_EXTENSION_TYPE, vec![0x04, 0x01])]);
        let got = decode(&encode(&message));
        assert_eq!(
            got.as_ref().ok(),
            Some(&message),
            "an extension parameter was held to the token's structure: {got:?}",
        );
    }
}

#[cfg(feature = "draft14")]
mod draft14 {
    use moqtap_codec::draft14::message::*;
    use moqtap_codec::kvp::KeyValuePair;
    use moqtap_codec::types::*;

    const AUTHORIZATION_TOKEN: u64 = 0x03;

    fn subscribe(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            request_id: super::varint(1),
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

    fn setup(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::ClientSetup(ClientSetup {
            supported_versions: vec![super::varint(0xff00_000e)],
            parameters,
        })
    }

    fn encode(message: &ControlMessage) -> Vec<u8> {
        let mut buf = Vec::new();
        message.encode(&mut buf).expect("the encoder writes the value it is given");
        buf
    }

    fn decode(bytes: &[u8]) -> Result<ControlMessage, moqtap_codec::error::CodecError> {
        ControlMessage::decode(&mut &bytes[..])
    }

    token_structure_gates!(draft14, AUTHORIZATION_TOKEN, setup);
}

#[cfg(feature = "draft15")]
mod draft15 {
    use moqtap_codec::draft15::message::*;
    use moqtap_codec::kvp::KeyValuePair;
    use moqtap_codec::types::*;

    const AUTHORIZATION_TOKEN: u64 = 0x03;

    fn subscribe(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            request_id: super::varint(1),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            parameters,
        })
    }

    fn setup(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::ClientSetup(ClientSetup { parameters })
    }

    fn encode(message: &ControlMessage) -> Vec<u8> {
        let mut buf = Vec::new();
        message.encode(&mut buf).expect("the encoder writes the value it is given");
        buf
    }

    fn decode(bytes: &[u8]) -> Result<ControlMessage, moqtap_codec::error::CodecError> {
        ControlMessage::decode(&mut &bytes[..])
    }

    token_structure_gates!(draft15, AUTHORIZATION_TOKEN, setup);
}

#[cfg(feature = "draft16")]
mod draft16 {
    use moqtap_codec::draft16::message::*;
    use moqtap_codec::kvp::KeyValuePair;
    use moqtap_codec::types::*;

    const AUTHORIZATION_TOKEN: u64 = 0x03;

    fn subscribe(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            request_id: super::varint(1),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            parameters,
        })
    }

    fn setup(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::ClientSetup(ClientSetup { parameters })
    }

    fn encode(message: &ControlMessage) -> Vec<u8> {
        let mut buf = Vec::new();
        message.encode(&mut buf).expect("the encoder writes the value it is given");
        buf
    }

    fn decode(bytes: &[u8]) -> Result<ControlMessage, moqtap_codec::error::CodecError> {
        ControlMessage::decode(&mut &bytes[..])
    }

    token_structure_gates!(draft16, AUTHORIZATION_TOKEN, setup);
}

#[cfg(feature = "draft17")]
mod draft17 {
    use moqtap_codec::draft17::message::*;
    use moqtap_codec::kvp::KeyValuePair;
    use moqtap_codec::types::*;

    const AUTHORIZATION_TOKEN: u64 = 0x03;

    fn subscribe(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            request_id: super::varint(1),
            required_request_id_delta: super::varint(0),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            parameters,
        })
    }

    fn setup(options: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::Setup(Setup { options })
    }

    fn encode(message: &ControlMessage) -> Vec<u8> {
        let mut buf = Vec::new();
        message.encode(&mut buf).expect("the encoder writes the value it is given");
        buf
    }

    fn decode(bytes: &[u8]) -> Result<ControlMessage, moqtap_codec::error::CodecError> {
        ControlMessage::decode(&mut &bytes[..])
    }

    token_structure_gates!(draft17, AUTHORIZATION_TOKEN, setup);
}

#[cfg(feature = "draft18")]
mod draft18 {
    use moqtap_codec::draft18::message::*;
    use moqtap_codec::kvp::KeyValuePair;
    use moqtap_codec::types::*;

    const AUTHORIZATION_TOKEN: u64 = 0x03;

    fn subscribe(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            request_id: super::varint(1),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            parameters,
        })
    }

    fn setup(options: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::Setup(Setup { options })
    }

    fn encode(message: &ControlMessage) -> Vec<u8> {
        let mut buf = Vec::new();
        message.encode(&mut buf).expect("the encoder writes the value it is given");
        buf
    }

    fn decode(bytes: &[u8]) -> Result<ControlMessage, moqtap_codec::error::CodecError> {
        ControlMessage::decode(&mut &bytes[..])
    }

    token_structure_gates!(draft18, AUTHORIZATION_TOKEN, setup);
}

#[cfg(feature = "draft19")]
mod draft19 {
    use moqtap_codec::draft19::message::*;
    use moqtap_codec::kvp::KeyValuePair;
    use moqtap_codec::types::*;

    const AUTHORIZATION_TOKEN: u64 = 0x03;

    fn subscribe(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            request_id: super::varint(1),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            parameters,
        })
    }

    fn setup(options: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::Setup(Setup { options })
    }

    fn encode(message: &ControlMessage) -> Vec<u8> {
        let mut buf = Vec::new();
        message.encode(&mut buf).expect("the encoder writes the value it is given");
        buf
    }

    fn decode(bytes: &[u8]) -> Result<ControlMessage, moqtap_codec::error::CodecError> {
        ControlMessage::decode(&mut &bytes[..])
    }

    token_structure_gates!(draft19, AUTHORIZATION_TOKEN, setup);
}

/// Drafts 07 through 10 have no Token, and the same bytes travel unread.
///
/// The four earliest drafts have no Key-Value-Pair at all. Their Parameter is
/// `{ Parameter Type (i), Parameter Length (i), Parameter Value (..) }`, every
/// value is opaque bytes, and no parameter they define has a structure inside
/// it. The rule these four state in its place is the Parameter Length Mismatch
/// one, about a declared length disagreeing with the type — a different
/// sentence about a different field.
///
/// The parameter here is AUTHORIZATION INFO, version-specific type 0x02 and the
/// ancestor of the token: Section 8.1.1.1 calls it "an ASCII string", which is
/// the whole of what these drafts say about its contents. Draft-11 replaced it
/// with a structure, and that is where the rule begins.
///
/// So the bytes that end a session from draft-11 on are ordinary here. Applying
/// the token's structure to these drafts would refuse parameters a conforming
/// peer may send, which is the costly direction to be wrong in.
#[cfg(feature = "draft10")]
#[test]
fn an_early_draft_carries_the_bytes_that_are_a_malformed_token_later() {
    use moqtap_codec::draft10::message::*;
    use moqtap_codec::types::*;

    let message = ControlMessage::Subscribe(Subscribe {
        subscribe_id: varint(1),
        track_alias: varint(4),
        track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
        track_name: b"t".to_vec(),
        subscriber_priority: 5,
        group_order: GroupOrder::Ascending,
        filter_type: FilterType::LargestObject,
        start_location: None,
        end_group: None,
        // Bytes that are an unassigned Alias Type from draft-11 on, and an
        // ordinary two-character authorization string here.
        parameters: vec![pair(0x02, vec![0x04, 0x01])],
    });

    let mut buf = Vec::new();
    message.encode(&mut buf).expect("encode");
    let back = ControlMessage::decode(&mut &buf[..]);
    assert_eq!(
        back.as_ref().ok(),
        Some(&message),
        "a draft that defines no Token read one anyway: {back:?}",
    );
}

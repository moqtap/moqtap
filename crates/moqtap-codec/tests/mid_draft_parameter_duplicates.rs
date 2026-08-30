//! Drafts 11, 12 and 13: the repeat rule is asymmetric, and the length of an
//! extension block is a fact about the block.
//!
//! Three rules are gated here, all of them stated by drafts 11, 12 and 13 in
//! the same words.
//!
//! Section 8.2 "Parameters" carries the repeat rule in three sentences, and
//! each sentence reaches a different distance:
//!
//! > Senders MUST NOT repeat the same parameter type in a message unless the
//! > parameter definition explicitly allows multiple instances of that type to
//! > be sent in a single message. Receivers SHOULD check that there are no
//! > unauthorized duplicate parameters and close the session as a 'Protocol
//! > Violation' if found. Receivers MUST allow duplicates of unknown
//! > parameters.
//!
//! The sender's half names no exception for types the sender does not
//! recognise, so it refuses every repeat but the one the draft allows. The
//! receiver's half does name one, and it is a MUST: a repeat of a type this
//! draft cannot name has to be carried. A codec that mirrored the send-side
//! check onto the read side would close sessions over parameters some extension
//! defined, which is traffic these drafts require an endpoint to tolerate.
//! `a_receiver_carries_a_repeated_extension_defined_parameter_type` is the gate
//! that fails if the two sides are ever made symmetric.
//!
//! The carve-out is AUTHORIZATION TOKEN, Section 8.2.1.1: "The AUTHORIZATION
//! TOKEN parameter MAY be repeated within a message." Its number is not the
//! same across this era. Draft-11 assigns it "Parameter Type 0x01"; drafts 12
//! and 13 assign it "Parameter Type 0x03" and leave 0x01 to PATH on the setup
//! side. So the exemption cannot be one number applied to all three drafts, and
//! it cannot be one list applied to both parameter namespaces of one draft:
//! on draft-11, 0x01 is the repeatable AUTHORIZATION TOKEN among Version
//! Specific Parameters and the non-repeatable PATH among Setup Parameters. The
//! pair of gates named for the setup namespace is what catches a single shared
//! list.
//!
//! Section 9 frames every extension block as an Extension Headers Length
//! followed by that many bytes. The length an encoder writes has to come from
//! the bytes it is about to write, not from a field a caller filled in: the
//! peer reads exactly the stated number of bytes and then expects the next
//! field, so a length that disagrees with the block moves every field after it
//! and every object after that on the same stream. The four gates named for
//! headers below hand each encoder a header whose stated length is a lie and
//! read the result back with this codec's own decoder.
//!
//! Section 8.10 gives SUBSCRIBE_UPDATE an End Group that is not spelled the way
//! SUBSCRIBE spells it: "End Group: The end Group ID, plus 1. A value of 0
//! means the subscription is open-ended." The ordering MUST that applies to
//! SUBSCRIBE's AbsoluteRange filter and to a standalone FETCH therefore cannot
//! be applied to an update unchanged - a plain "end is at least start" reading
//! refuses the legal open-ended form, whose End Group is zero.
//! `an_open_ended_update_is_not_a_range_that_ends_at_group_zero` is the gate
//! that fails if that check is ever extended to SUBSCRIBE_UPDATE.

#[cfg(any(feature = "draft11", feature = "draft12", feature = "draft13"))]
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
#[cfg(any(feature = "draft11", feature = "draft12", feature = "draft13"))]
use moqtap_codec::varint::VarInt;

#[cfg(any(feature = "draft11", feature = "draft12", feature = "draft13"))]
fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).unwrap()
}

/// DELIVERY TIMEOUT, Section 8.2.1.2, at Parameter Type 0x02 on all three
/// drafts. A type each draft names and none lets repeat, so it is what a
/// refused repeat is built from.
#[cfg(any(feature = "draft11", feature = "draft12", feature = "draft13"))]
const DELIVERY_TIMEOUT: u64 = 0x02;

/// PATH, Section 8.3.2.1, at Parameter Type 0x01 on all three drafts.
///
/// Draft-11 puts AUTHORIZATION TOKEN at that same 0x01 in the other namespace,
/// which is what makes a repeated PATH worth its own gate.
#[cfg(any(feature = "draft11", feature = "draft12", feature = "draft13"))]
const SETUP_PATH: u64 = 0x01;

/// Two Parameter Types no draft in this era assigns, standing in for types an
/// extension defined. Both are even, so each carries a varint value and one can
/// be rewritten into the other by moving a single byte.
#[cfg(any(feature = "draft11", feature = "draft12", feature = "draft13"))]
const EXTENSION_A: u64 = 0x32;
/// The second of them.
#[cfg(any(feature = "draft11", feature = "draft12", feature = "draft13"))]
const EXTENSION_B: u64 = 0x34;

/// A group far enough from zero that an end group below it is unambiguous.
#[cfg(any(feature = "draft11", feature = "draft12", feature = "draft13"))]
const GROUP: u64 = 42;

#[cfg(any(feature = "draft11", feature = "draft12", feature = "draft13"))]
fn param(key: u64, value: u64) -> KeyValuePair {
    KeyValuePair { key: varint(key), value: KvpValue::Varint(varint(value)) }
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
#[cfg(any(feature = "draft11", feature = "draft12", feature = "draft13"))]
fn token_value(payload: &[u8]) -> Vec<u8> {
    let mut value = vec![0x03, 0x00];
    value.extend_from_slice(payload);
    value
}

#[cfg(any(feature = "draft11", feature = "draft12", feature = "draft13"))]
fn token(key: u64, value: &[u8]) -> KeyValuePair {
    KeyValuePair { key: varint(key), value: KvpValue::Bytes(value.to_vec()) }
}

/// An extension block of five bytes. Its contents are never parsed - every
/// reader here takes the Extension Headers Length and reads that many bytes -
/// so what matters is only that the length is five and nothing else says so.
#[cfg(any(feature = "draft11", feature = "draft12", feature = "draft13"))]
const EXTENSION_BLOCK: &[u8] = &[0x02, 0x2a, 0x0b, 0x01, 0x63];

/// A length no header below actually carries, written into the
/// `extension_headers_length` field of every fixture. An encoder that wrote
/// this field instead of measuring the block would state 99 bytes and then
/// write 5.
#[cfg(any(feature = "draft11", feature = "draft12", feature = "draft13"))]
const A_LENGTH_NOTHING_CARRIES: u64 = 99;

/// Turn one parameter of an encoded frame into a repeat of another, by moving
/// the single byte that names it.
///
/// The frame is one this codec built with two different types, so everything
/// around that byte is exactly what the encoder would have written, and both
/// types are even so both values are encoded the same way. The byte is asserted
/// unique before it is moved, so a fixture whose other fields happened to
/// collide with it fails here rather than quietly patching the wrong place.
#[cfg(any(feature = "draft11", feature = "draft12", feature = "draft13"))]
fn rewrite_type(mut buf: Vec<u8>, on_wire: u64, becomes: u64) -> Vec<u8> {
    assert_eq!(
        buf.iter().filter(|b| u64::from(**b) == on_wire).count(),
        1,
        "the byte naming the parameter to be rewritten must be the only one of its value",
    );
    let at = buf.iter().position(|b| u64::from(*b) == on_wire).expect("it is in the frame");
    buf[at] = u8::try_from(becomes).unwrap();
    buf
}

/// The gates every one of these three drafts states in the same words.
///
/// Each expansion needs `subscribe`, `client_setup` and `subscribe_update` from
/// the module it lands in, because the field lists in front of the parameters
/// are not the same on any two of these drafts.
///
/// The trailing `field: value` pairs are spliced into the datagram header
/// fixture. Drafts 12 and 13 carry an End of Group flag there that draft-11
/// does not, and it is not a body field on any of them - it is read out of the
/// datagram type - so it plays no part in what these gates measure.
#[cfg(any(feature = "draft11", feature = "draft12", feature = "draft13"))]
macro_rules! mid_draft_gates {
    (
        $draft:ident,
        $authorization_token:expr
        $(, $datagram_field:ident : $datagram_value:expr)* $(,)?
    ) => {
        /// A repeat of a type this draft names has no encoding.
        ///
        /// Section 8.2: "Senders MUST NOT repeat the same parameter type in a
        /// message unless the parameter definition explicitly allows multiple
        /// instances of that type to be sent in a single message." DELIVERY
        /// TIMEOUT's definition says nothing of the sort.
        ///
        /// Dropping the sender check fails with:
        ///
        /// ```text
        /// one message cannot state a named type twice:
        /// Ok([3, 0, 17, 1, 4, 1, 2, 110, 115, 1, 116, 5, 1, 1, 2, 2, 2, 11, 2, 12])
        /// ```
        #[test]
        fn a_sender_may_not_repeat_a_named_parameter_type() {
            let result = encode(&subscribe(vec![
                param(DELIVERY_TIMEOUT, 11),
                param(DELIVERY_TIMEOUT, 12),
            ]));
            assert!(result.is_err(), "one message cannot state a named type twice: {result:?}");
        }

        /// And neither does a repeat of a type this draft has never heard of.
        ///
        /// This is the half of the rule that does not soften. "Senders MUST NOT
        /// repeat the same parameter type in a message" names no exception for
        /// types the sender does not recognise, and the reason it does not is
        /// that the ambiguity a repeat creates does not depend on who defined
        /// the type: code that scans a parameter list for a key takes whichever
        /// copy it meets first, so one frame carrying two values for one type is
        /// read differently by two conforming implementations.
        ///
        /// Giving the sender the receiver's tolerance for unknown types fails
        /// with:
        ///
        /// ```text
        /// the sender rule has no exception for types it cannot name:
        /// Ok([3, 0, 17, 1, 4, 1, 2, 110, 115, 1, 116, 5, 1, 1, 2, 2, 50, 11, 50, 12])
        /// ```
        #[test]
        fn a_sender_may_not_repeat_an_extension_defined_parameter_type() {
            let result =
                encode(&subscribe(vec![param(EXTENSION_A, 11), param(EXTENSION_A, 12)]));
            assert!(
                result.is_err(),
                "the sender rule has no exception for types it cannot name: {result:?}",
            );
        }

        /// A repeat of a named type that arrives anyway is refused rather than
        /// carried inwards.
        ///
        /// Section 8.2: "Receivers SHOULD check that there are no unauthorized
        /// duplicate parameters and close the session as a 'Protocol Violation'
        /// if found."
        ///
        /// Dropping the receiver check fails with:
        ///
        /// ```text
        /// a repeated named type is not two parameters: Ok(Subscribe(Subscribe {
        /// request_id: VarInt(1), track_alias: VarInt(4), track_namespace:
        /// TrackNamespace([[110, 115]]), track_name: [116], subscriber_priority: 5,
        /// group_order: Ascending, forward: Forward, filter_type: VarInt(2),
        /// start_group: None, start_object: None, end_group: None, parameters:
        /// [KeyValuePair { key: VarInt(2), value: Varint(VarInt(11)) }, KeyValuePair
        /// { key: VarInt(2), value: Varint(VarInt(12)) }] }))
        /// ```
        #[test]
        fn a_receiver_refuses_a_repeated_named_parameter_type() {
            let buf = encode(&subscribe(vec![
                param(DELIVERY_TIMEOUT, 11),
                param(EXTENSION_A, 12),
            ]))
            .expect("two different types are a legal list");
            let repeated = rewrite_type(buf, EXTENSION_A, DELIVERY_TIMEOUT);

            let decoded = ControlMessage::decode(&mut &repeated[..]);
            assert!(decoded.is_err(), "a repeated named type is not two parameters: {decoded:?}");
        }

        /// A repeat of a type this draft cannot name is carried.
        ///
        /// Section 8.2: "Receivers MUST allow duplicates of unknown
        /// parameters." This is the sentence that makes the rule asymmetric,
        /// and it is a MUST rather than the SHOULD that governs the sentence
        /// before it. A parameter type absent from this draft is one some
        /// extension defined, and refusing it closes a session over traffic the
        /// draft requires an endpoint to accept.
        ///
        /// Mirroring the sender's check onto the read side fails with:
        ///
        /// ```text
        /// an unknown type may repeat on the wire: DuplicateParameter(50)
        /// ```
        #[test]
        fn a_receiver_carries_a_repeated_extension_defined_parameter_type() {
            let buf = encode(&subscribe(vec![param(EXTENSION_A, 11), param(EXTENSION_B, 12)]))
                .expect("two different types are a legal list");
            let repeated = rewrite_type(buf, EXTENSION_B, EXTENSION_A);

            let decoded = ControlMessage::decode(&mut &repeated[..])
                .expect("an unknown type may repeat on the wire");
            let ControlMessage::Subscribe(message) = decoded else {
                panic!("a SUBSCRIBE decodes as one");
            };
            assert_eq!(
                message.parameters,
                vec![param(EXTENSION_A, 11), param(EXTENSION_A, 12)],
                "both copies reach the caller, which is the only way it can tell them apart",
            );
        }

        /// The one type whose own definition lets a message repeat it.
        ///
        /// Section 8.2.1.1: "The AUTHORIZATION TOKEN parameter MAY be repeated
        /// within a message." The number this draft gives it is not the number
        /// its neighbours give it, so this gate fails both if the carve-out is
        /// dropped and if it is applied to the wrong type.
        ///
        /// Dropping the carve-out fails with:
        ///
        /// ```text
        /// this type is allowed more than one instance: DuplicateParameter(1)
        /// ```
        #[test]
        fn an_authorization_token_may_be_repeated() {
            let message = subscribe(vec![
                token($authorization_token, &token_value(b"one")),
                token($authorization_token, &token_value(b"two")),
            ]);
            let buf = encode(&message).expect("this type is allowed more than one instance");
            let decoded = ControlMessage::decode(&mut &buf[..]);
            assert_eq!(
                decoded.ok().as_ref(),
                Some(&message),
                "what this codec wrote it must read",
            );
        }

        /// A Setup Parameter namespace does not borrow the other namespace's
        /// carve-out.
        ///
        /// PATH is Section 8.3.2.1 Parameter Type 0x01 and its definition never
        /// says it may repeat. On draft-11 that same 0x01 is the repeatable
        /// AUTHORIZATION TOKEN among Version Specific Parameters, so a codec
        /// holding one exemption list for both namespaces lets a CLIENT_SETUP
        /// state PATH twice.
        ///
        /// Sharing one exemption list across the two namespaces fails with:
        ///
        /// ```text
        /// a setup message cannot state PATH twice:
        /// Ok([32, 0, 16, 1, 192, 0, 0, 0, 255, 0, 0, 11, 2, 1, 1, 97, 1, 1, 98])
        /// ```
        #[test]
        fn a_repeated_path_is_refused_in_a_setup_message() {
            let result =
                encode(&client_setup(vec![token(SETUP_PATH, b"a"), token(SETUP_PATH, b"b")]));
            assert!(result.is_err(), "a setup message cannot state PATH twice: {result:?}");
        }

        /// Two different types, and an empty list, are both carried. Without
        /// this the gates above would pass on an encoder that refused every
        /// parameter.
        #[test]
        fn a_list_that_names_each_type_once_is_carried() {
            for parameters in [
                vec![],
                vec![param(DELIVERY_TIMEOUT, 11)],
                vec![param(DELIVERY_TIMEOUT, 11), param(EXTENSION_A, 12)],
            ] {
                let message = subscribe(parameters.clone());
                let buf = encode(&message).unwrap_or_else(|e| {
                    panic!("{} distinct types is a list: {e:?}", parameters.len())
                });
                let decoded = ControlMessage::decode(&mut &buf[..]);
                assert_eq!(
                    decoded.ok().as_ref(),
                    Some(&message),
                    "what this codec wrote it must read",
                );
            }
        }

        /// An open-ended SUBSCRIBE_UPDATE is not a range that ends at group
        /// zero.
        ///
        /// Section 8.10: "End Group: The end Group ID, plus 1. A value of 0
        /// means the subscription is open-ended." SUBSCRIBE's AbsoluteRange
        /// filter and a standalone FETCH both carry an ordering MUST, and
        /// neither spells its end the way this message does, so extending
        /// either check here refuses every open subscription update.
        ///
        /// Applying the plain ordering check to SUBSCRIBE_UPDATE fails with:
        ///
        /// ```text
        /// zero is an open end, not a bound: InvalidRange(42, 0, 0, 0)
        /// ```
        #[test]
        fn an_open_ended_update_is_not_a_range_that_ends_at_group_zero() {
            let message = subscribe_update(GROUP, 0, 0);
            let buf = encode(&message).expect("zero is an open end, not a bound");
            let decoded = ControlMessage::decode(&mut &buf[..]);
            assert_eq!(
                decoded.ok().as_ref(),
                Some(&message),
                "what this codec wrote it must read",
            );
        }

        /// A bounded update is still held to its order, so the gate above
        /// cannot be satisfied by leaving SUBSCRIBE_UPDATE unchecked
        /// altogether.
        ///
        /// Section 8.10: "Like SUBSCRIBE, End Group MUST be greater than or
        /// equal to the Group specified in Start."
        ///
        /// Dropping the check fails with:
        ///
        /// ```text
        /// a bounded update cannot end before it starts: Ok([2, 0, 7, 1, 42, 0, 7, 3, 1, 0])
        /// ```
        #[test]
        fn a_bounded_update_is_still_held_to_its_order() {
            let result = encode(&subscribe_update(GROUP, 0, 7));
            assert!(result.is_err(), "a bounded update cannot end before it starts: {result:?}");
        }

        /// An object header on a subgroup stream states the length of the block
        /// it carries.
        ///
        /// The fixture's `extension_headers_length` says 99 and its extensions
        /// are five bytes. What the encoder writes has to be the five, because
        /// the reader takes the stated length and then expects the Object
        /// Payload Length at the byte after the block.
        ///
        /// Writing the field instead of measuring the block fails with:
        ///
        /// ```text
        /// the encoder must not state a length its own reader cannot satisfy:
        /// UnexpectedEnd
        /// ```
        #[test]
        fn an_object_header_states_the_length_of_the_block_it_carries() {
            let header = moqtap_codec::$draft::data_stream::ObjectHeader {
                object_id: varint(1),
                extension_headers_length: varint(A_LENGTH_NOTHING_CARRIES),
                extensions: EXTENSION_BLOCK.to_vec(),
                payload_length: varint(3),
                object_status: moqtap_codec::$draft::types::ObjectStatus::Normal,
            };
            let mut buf = Vec::new();
            header.encode_with_extensions(true, &mut buf);

            let decoded = moqtap_codec::$draft::data_stream::ObjectHeader::decode_with_extensions(
                true,
                &mut &buf[..],
            )
            .expect("the encoder must not state a length its own reader cannot satisfy");
            assert_eq!(decoded.extensions, EXTENSION_BLOCK, "the block arrives whole");
            assert_eq!(
                decoded.payload_length.into_inner(),
                3,
                "the field after the block is where the peer expects it",
            );
        }

        /// So does a datagram header.
        ///
        /// A datagram carries its payload as whatever remains after the header,
        /// so the length of the extension block decides where the payload
        /// begins. The bytes appended below stand in for that payload.
        ///
        /// Writing the field instead of measuring the block fails with:
        ///
        /// ```text
        /// the encoder must not state a length its own reader cannot satisfy:
        /// UnexpectedEnd
        /// ```
        #[test]
        fn a_datagram_header_states_the_length_of_the_block_it_carries() {
            let header = moqtap_codec::$draft::data_stream::DatagramHeader {
                track_alias: varint(4),
                group_id: varint(GROUP),
                object_id: varint(1),
                publisher_priority: 7,
                extension_headers_length: varint(A_LENGTH_NOTHING_CARRIES),
                extensions: EXTENSION_BLOCK.to_vec(),
                $($datagram_field: $datagram_value,)*
            };
            let mut buf = Vec::new();
            header.encode_with_extensions(true, &mut buf);
            buf.extend_from_slice(b"payload");

            let mut rest = &buf[..];
            let decoded =
                moqtap_codec::$draft::data_stream::DatagramHeader::decode_with_extensions(
                    true, &mut rest,
                )
                .expect("the encoder must not state a length its own reader cannot satisfy");
            assert_eq!(decoded.extensions, EXTENSION_BLOCK, "the block arrives whole");
            assert_eq!(rest, b"payload", "the payload begins where the peer expects it");
        }

        /// So does a datagram status header, whose Object Status sits directly
        /// after the block.
        ///
        /// Writing the field instead of measuring the block fails with:
        ///
        /// ```text
        /// the encoder must not state a length its own reader cannot satisfy:
        /// UnexpectedEnd
        /// ```
        #[test]
        fn a_datagram_status_header_states_the_length_of_the_block_it_carries() {
            let header = moqtap_codec::$draft::data_stream::DatagramStatusHeader {
                track_alias: varint(4),
                group_id: varint(GROUP),
                object_id: varint(1),
                publisher_priority: 7,
                extension_headers_length: varint(A_LENGTH_NOTHING_CARRIES),
                extensions: EXTENSION_BLOCK.to_vec(),
                object_status: moqtap_codec::$draft::types::ObjectStatus::EndOfGroup,
            };
            let mut buf = Vec::new();
            header.encode_with_extensions(true, &mut buf);

            let decoded =
                moqtap_codec::$draft::data_stream::DatagramStatusHeader::decode_with_extensions(
                    true,
                    &mut &buf[..],
                )
                .expect("the encoder must not state a length its own reader cannot satisfy");
            assert_eq!(decoded.extensions, EXTENSION_BLOCK, "the block arrives whole");
            assert_eq!(
                decoded.object_status,
                moqtap_codec::$draft::types::ObjectStatus::EndOfGroup,
                "the field after the block is where the peer expects it",
            );
        }

        /// And so does an object header on a fetch stream, which writes its
        /// block unconditionally.
        ///
        /// Writing the field instead of measuring the block fails with:
        ///
        /// ```text
        /// the encoder must not state a length its own reader cannot satisfy:
        /// UnexpectedEnd
        /// ```
        #[test]
        fn a_fetch_object_header_states_the_length_of_the_block_it_carries() {
            let header = moqtap_codec::$draft::data_stream::FetchObjectHeader {
                group_id: varint(GROUP),
                subgroup_id: varint(0),
                object_id: varint(1),
                publisher_priority: 7,
                extension_headers_length: varint(A_LENGTH_NOTHING_CARRIES),
                extensions: EXTENSION_BLOCK.to_vec(),
                payload_length: varint(3),
                object_status: moqtap_codec::$draft::types::ObjectStatus::Normal,
            };
            let mut buf = Vec::new();
            header.encode(&mut buf);

            let decoded =
                moqtap_codec::$draft::data_stream::FetchObjectHeader::decode(&mut &buf[..])
                    .expect("the encoder must not state a length its own reader cannot satisfy");
            assert_eq!(decoded.extensions, EXTENSION_BLOCK, "the block arrives whole");
            assert_eq!(
                decoded.payload_length.into_inner(),
                3,
                "the field after the block is where the peer expects it",
            );
        }
    };
}

#[cfg(feature = "draft11")]
mod draft11 {
    use super::{
        param, rewrite_type, token, token_value, varint, A_LENGTH_NOTHING_CARRIES,
        DELIVERY_TIMEOUT, EXTENSION_A, EXTENSION_B, EXTENSION_BLOCK, GROUP, SETUP_PATH,
    };
    use moqtap_codec::draft11::message::*;
    use moqtap_codec::kvp::KeyValuePair;
    #[allow(unused_imports)]
    use moqtap_codec::types::*;

    /// AUTHORIZATION TOKEN, Section 8.2.1.1: "The AUTHORIZATION TOKEN parameter
    /// (Parameter Type 0x01)". Draft-12 moves it to 0x03.
    const AUTHORIZATION_TOKEN: u64 = 0x01;

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

    fn client_setup(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::ClientSetup(ClientSetup {
            supported_versions: vec![varint(0xff00_000b)],
            parameters,
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

    fn encode(message: &ControlMessage) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message.encode(&mut buf)?;
        Ok(buf)
    }

    mid_draft_gates!(draft11, AUTHORIZATION_TOKEN);

    /// One type number, repeatable in one namespace and not in the other.
    ///
    /// This is the whole of the namespace trap in a single frame pair. On
    /// draft-11 the number 0x01 is AUTHORIZATION TOKEN among Version Specific
    /// Parameters, which Section 8.2.1.1 lets a message repeat, and it is PATH
    /// among Setup Parameters, which Section 8.3.2.1 does not. Section 8.3.2
    /// names three Setup Parameters on this draft - PATH, MAX_REQUEST_ID and
    /// MAX_AUTH_TOKEN_CACHE_SIZE - and none of them says it may be sent more
    /// than once; AUTHORIZATION TOKEN reaches the setup side only at draft-12,
    /// in Section 8.3.2.4.
    ///
    /// So the exemption cannot be a set of numbers consulted without asking
    /// which namespace the number was read in. A codec holding one list for
    /// both would send a CLIENT_SETUP stating PATH twice.
    ///
    /// Giving the setup namespace the message namespace's carve-out fails with:
    ///
    /// ```text
    /// this number is PATH here, and PATH does not repeat:
    /// Ok([32, 0, 20, 1, 192, 0, 0, 0, 255, 0, 0, 11, 2, 1, 3, 111, 110, 101, 1, 3, 116, 119, 111])
    /// ```
    #[test]
    fn one_type_number_repeats_in_a_subscribe_and_not_in_a_setup() {
        assert_eq!(
            AUTHORIZATION_TOKEN, SETUP_PATH,
            "on this draft the two namespaces really do collide at one number",
        );
        let repeated = vec![
            token(AUTHORIZATION_TOKEN, &token_value(b"one")),
            token(AUTHORIZATION_TOKEN, &token_value(b"two")),
        ];

        encode(&subscribe(repeated.clone()))
            .expect("this number is AUTHORIZATION TOKEN here, and it may be repeated");

        let result = encode(&client_setup(repeated));
        assert!(result.is_err(), "this number is PATH here, and PATH does not repeat: {result:?}");
    }
}

#[cfg(feature = "draft12")]
mod draft12 {
    use super::{
        param, rewrite_type, token, token_value, varint, A_LENGTH_NOTHING_CARRIES,
        DELIVERY_TIMEOUT, EXTENSION_A, EXTENSION_B, EXTENSION_BLOCK, GROUP, SETUP_PATH,
    };
    use moqtap_codec::draft12::message::*;
    use moqtap_codec::kvp::KeyValuePair;
    #[allow(unused_imports)]
    use moqtap_codec::types::*;

    /// AUTHORIZATION TOKEN, Section 8.2.1.1: "The AUTHORIZATION TOKEN parameter
    /// (Parameter Type 0x03)". Draft-11 had it at 0x01.
    const AUTHORIZATION_TOKEN: u64 = 0x03;

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

    fn client_setup(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::ClientSetup(ClientSetup {
            supported_versions: vec![varint(0xff00_000c)],
            parameters,
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

    fn encode(message: &ControlMessage) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message.encode(&mut buf)?;
        Ok(buf)
    }

    mid_draft_gates!(draft12, AUTHORIZATION_TOKEN, end_of_group: false);

    /// Draft-12 gives the setup side its own AUTHORIZATION TOKEN, and it
    /// repeats.
    ///
    /// Section 8.3.2.4 defines it by reference - "See Section 8.2.1.1" - and
    /// adds "The endpoint can specify one or more tokens in CLIENT_SETUP or
    /// SERVER_SETUP that the peer can use to authorize MOQT session
    /// establishment." So this namespace has a carve-out where draft-11's had
    /// none, and it is the same number the message namespace uses.
    ///
    /// Leaving the setup namespace without its carve-out fails with:
    ///
    /// ```text
    /// a setup message may carry more than one token: DuplicateParameter(3)
    /// ```
    #[test]
    fn a_setup_message_may_carry_more_than_one_authorization_token() {
        let message = client_setup(vec![
            token(AUTHORIZATION_TOKEN, &token_value(b"one")),
            token(AUTHORIZATION_TOKEN, &token_value(b"two")),
        ]);
        let buf = encode(&message).expect("a setup message may carry more than one token");
        let decoded = ControlMessage::decode(&mut &buf[..]);
        assert_eq!(decoded.ok().as_ref(), Some(&message), "what this codec wrote it must read");
    }
}

#[cfg(feature = "draft13")]
mod draft13 {
    use super::{
        param, rewrite_type, token, token_value, varint, A_LENGTH_NOTHING_CARRIES,
        DELIVERY_TIMEOUT, EXTENSION_A, EXTENSION_B, EXTENSION_BLOCK, GROUP, SETUP_PATH,
    };
    use moqtap_codec::draft13::message::*;
    use moqtap_codec::kvp::KeyValuePair;
    #[allow(unused_imports)]
    use moqtap_codec::types::*;

    /// AUTHORIZATION TOKEN, Section 8.2.1.1: "The AUTHORIZATION TOKEN parameter
    /// (Parameter Type 0x03)". Draft-11 had it at 0x01.
    const AUTHORIZATION_TOKEN: u64 = 0x03;

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

    fn client_setup(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::ClientSetup(ClientSetup {
            supported_versions: vec![varint(0xff00_000d)],
            parameters,
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

    fn encode(message: &ControlMessage) -> Result<Vec<u8>, moqtap_codec::error::CodecError> {
        let mut buf = Vec::new();
        message.encode(&mut buf)?;
        Ok(buf)
    }

    mid_draft_gates!(draft13, AUTHORIZATION_TOKEN, end_of_group: false);

    /// Draft-13 keeps draft-12's setup-side AUTHORIZATION TOKEN, and it still
    /// repeats.
    ///
    /// Section 8.3.2.4: "See Section 8.2.1.1. The endpoint can specify one or
    /// more tokens in CLIENT_SETUP or SERVER_SETUP that the peer can use to
    /// authorize MOQT session establishment."
    ///
    /// Leaving the setup namespace without its carve-out fails with:
    ///
    /// ```text
    /// a setup message may carry more than one token: DuplicateParameter(3)
    /// ```
    #[test]
    fn a_setup_message_may_carry_more_than_one_authorization_token() {
        let message = client_setup(vec![
            token(AUTHORIZATION_TOKEN, &token_value(b"one")),
            token(AUTHORIZATION_TOKEN, &token_value(b"two")),
        ]);
        let buf = encode(&message).expect("a setup message may carry more than one token");
        let decoded = ControlMessage::decode(&mut &buf[..]);
        assert_eq!(decoded.ok().as_ref(), Some(&message), "what this codec wrote it must read");
    }
}

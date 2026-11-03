//! The Key-Value-Pair value maximum, on the side that writes.
//!
//! Every draft from 11 to 20 states it of the Length field, in the same words:
//! "The maximum length of a value is 2^16-1 bytes. If an endpoint receives a
//! length larger than the maximum, it MUST close the session with a Protocol
//! Violation." Drafts 16 and later spell the code `PROTOCOL_VIOLATION` and
//! change nothing else about the sentence. A value past the maximum is one the
//! receiver must end the session over, so writing it is not a way to send it —
//! the sender's first sign of trouble would be the session going.
//!
//! # The refusal is never the only one, and that is the whole subtlety
//!
//! The same section states a second maximum in the next breath. Drafts 12
//! through 16: "The number of parameters in a message is not specifically
//! limited, but the total length of a control message is limited to 2^16-1
//! bytes." Drafts 17, 18 and 19 rename the subject and keep the rule — "The
//! number of Message Parameters is not specifically limited, but..." — and
//! draft-11 ends it "limited to 2^16-1." with no unit, which is the only draft
//! that leaves the reader to infer bytes.
//!
//! Two sentences, two rules, the same number — and the value sits inside the
//! message, so a value one byte over the first is already inside a payload one
//! byte over the second. No frame is written either way.
//!
//! What differs is which of the two rules the error names, and the drafts name
//! them separately. A writer that does not apply the value rule builds the whole
//! payload and reports the message rule instead, which on drafts 11 through 15
//! would diverge from drafts 16 through 20, whose parameter encoders report the
//! value rule from inside themselves — a difference in the codec, on a sentence
//! the ten drafts share word for word.
//! The gates below are the same defect put to all ten, and they read the error,
//! not just the refusal.
//!
//! # Why drafts 17 through 20 are driven through both of their namespaces
//!
//! Those four keep two parameter encoders, and the maximum has to be applied in
//! both. Setup Options take their value shape from the type's parity; Message
//! Parameters take theirs from a table, and a table-driven encoder that writes a
//! value of any length while the decoder ten lines below it refuses one holds
//! the rule in one namespace and not in its neighbour, inside a single module.
//!
//! It is worth saying why the table's rows look exempt and are not. The
//! table's length-prefixed
//! rows both carry structure rules of their own — AUTHORIZATION TOKEN must
//! decode as a Token, SUBSCRIPTION FILTER as a filter — which reads like a
//! reason an over-long opaque value cannot be spelled there at all. It is not
//! one. A type the table does not know falls through to a parity arm that writes
//! whatever it is given, and a *well-formed* USE_VALUE Token can be as long as
//! it likes: its Token Value has no length of its own and runs to the end of the
//! parameter, so the structure rule is satisfied by construction. Both routes
//! reach the length, and both have to be stopped.
//!
//! Drafts 11 through 16 have one parameter encoder per namespace and no table,
//! so a SUBSCRIBE carrying an unassigned odd type is enough there.

#![cfg(any(
    feature = "draft11",
    feature = "draft12",
    feature = "draft13",
    feature = "draft14",
    feature = "draft15",
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20",
    feature = "draft21",
    feature = "draft22",
    feature = "draft23"
))]

use moqtap_codec::varint::VarInt;

#[allow(dead_code)]
fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).expect("fixture value fits a varint")
}

/// An odd type, so the value is length-prefixed bytes, and one no draft in range
/// assigns in either namespace — the gate is about the length of the value and
/// nothing else about the pair.
#[allow(dead_code)]
const AN_UNASSIGNED_ODD_TYPE: u64 = 0x0b;

/// One byte past the maximum the ten drafts state.
#[allow(dead_code)]
const PAST_THE_MAXIMUM: usize = 65536;

/// The maximum itself, which is a length the drafts permit.
#[allow(dead_code)]
const AT_THE_MAXIMUM: usize = 65535;

// Draft-23 has its own module below, so a draft-23-only build uses none of it.
#[allow(unused_macros)]
macro_rules! kvp_value_maximum_gates {
    ($draft:ident, $carrier:ident) => {
        use moqtap_codec::error::CodecError;
        use moqtap_codec::kvp::{KvpError, KvpValue};

        fn opaque(len: usize) -> KeyValuePair {
            KeyValuePair {
                key: super::varint(super::AN_UNASSIGNED_ODD_TYPE),
                value: KvpValue::Bytes(vec![0xAB; len]),
            }
        }

        /// The writer names the rule the value broke, not the one the payload
        /// broke on its way past it.
        ///
        /// Both maxima are 2^16-1 and the value is inside the message, so the
        /// payload is over its limit the moment the value is over its own. A
        /// writer that builds the payload first and measures it afterwards
        /// answers truthfully and unhelpfully: the message is indeed too long,
        /// and the caller is left to work out which of the parameters did it.
        ///
        /// Fails if drafts 11 through 15's parameter encoders, or drafts 17
        /// through 19's Message Parameter encoder, stop applying the value
        /// maximum: the refusal then names the message rule instead. That is
        /// never *wrong*, only less specific than the layering the drafts state.
        #[test]
        fn a_value_past_the_maximum_is_refused_by_the_rule_it_broke() {
            let message = $carrier(vec![opaque(super::PAST_THE_MAXIMUM)]);
            let mut buf = Vec::new();
            let got = message.encode(&mut buf);

            assert!(
                matches!(got, Err(CodecError::Kvp(KvpError::ValueTooLong(super::PAST_THE_MAXIMUM)))),
                "a value past the maximum must be refused as a value, got {got:?}"
            );
            assert!(buf.is_empty(), "and nothing must reach the caller's buffer: {} bytes", buf.len());
        }

        /// And the maximum itself is a length the drafts permit, so what the
        /// refusal above observes is the length and not the shape of the pair.
        ///
        /// A value of exactly 2^16-1 is legal by the value rule and still makes
        /// the payload longer than a control message may be, so this one is
        /// refused by the *other* rule — which is the clearest statement there
        /// is that the two are separate and that the codec applies both.
        ///
        /// Fails if the length is compared with `>=` rather than `>`: the value
        /// rule would then reach a length the drafts permit, and the two rules
        /// stop being separable.
        #[test]
        fn the_maximum_itself_is_refused_by_the_message_rule_instead() {
            let message = $carrier(vec![opaque(super::AT_THE_MAXIMUM)]);
            let mut buf = Vec::new();
            let got = message.encode(&mut buf);

            assert!(
                matches!(got, Err(CodecError::MessageTooLong(_))),
                "a value at the maximum breaks the message rule and not the value rule, got {got:?}"
            );
            assert!(buf.is_empty(), "and nothing must reach the caller's buffer: {} bytes", buf.len());
        }
    };

    ($draft:ident, $carrier:ident, $setup:ident) => {
        kvp_value_maximum_gates!($draft, $carrier);

        /// The neighbouring namespace answers the same way, which on these three
        /// drafts is a claim about two different encoders rather than one.
        ///
        /// Setup Options take their value shape from the type's parity; Message
        /// Parameters take theirs from a table. A codec that bounds the value in
        /// one and not the other is the state this pair of gates exists to
        /// refuse. Fails if the Setup Option encoder stops applying the maximum.
        #[test]
        fn a_value_past_the_maximum_is_refused_in_the_other_namespace_too() {
            let message = $setup(vec![opaque(super::PAST_THE_MAXIMUM)]);
            let mut buf = Vec::new();
            let got = message.encode(&mut buf);

            assert!(
                matches!(got, Err(CodecError::Kvp(KvpError::ValueTooLong(super::PAST_THE_MAXIMUM)))),
                "a value past the maximum must be refused as a value here as well, got {got:?}"
            );
            assert!(buf.is_empty(), "and nothing must reach the caller's buffer: {} bytes", buf.len());
        }
    };
}

#[cfg(feature = "draft11")]
mod draft11 {
    use moqtap_codec::draft11::message::*;
    use moqtap_codec::kvp::KeyValuePair;
    use moqtap_codec::types::*;

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

    kvp_value_maximum_gates!(draft11, subscribe);
}

#[cfg(feature = "draft12")]
mod draft12 {
    use moqtap_codec::draft12::message::*;
    use moqtap_codec::kvp::KeyValuePair;
    use moqtap_codec::types::*;

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

    kvp_value_maximum_gates!(draft12, subscribe);
}

#[cfg(feature = "draft13")]
mod draft13 {
    use moqtap_codec::draft13::message::*;
    use moqtap_codec::kvp::KeyValuePair;
    use moqtap_codec::types::*;

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

    kvp_value_maximum_gates!(draft13, subscribe);
}

#[cfg(feature = "draft14")]
mod draft14 {
    use moqtap_codec::draft14::message::*;
    use moqtap_codec::kvp::KeyValuePair;
    use moqtap_codec::types::*;

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

    kvp_value_maximum_gates!(draft14, subscribe);
}

#[cfg(feature = "draft15")]
mod draft15 {
    use moqtap_codec::draft15::message::*;
    use moqtap_codec::kvp::KeyValuePair;
    use moqtap_codec::types::*;

    fn subscribe(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            request_id: super::varint(1),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            parameters,
        })
    }

    kvp_value_maximum_gates!(draft15, subscribe);
}

#[cfg(feature = "draft16")]
mod draft16 {
    use moqtap_codec::draft16::message::*;
    use moqtap_codec::kvp::KeyValuePair;
    use moqtap_codec::types::*;

    fn subscribe(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            request_id: super::varint(1),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            parameters,
        })
    }

    kvp_value_maximum_gates!(draft16, subscribe);
}

#[cfg(feature = "draft17")]
mod draft17 {
    use moqtap_codec::draft17::message::*;
    use moqtap_codec::kvp::KeyValuePair;
    use moqtap_codec::types::*;

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

    kvp_value_maximum_gates!(draft17, subscribe, setup);
}

#[cfg(feature = "draft18")]
mod draft18 {
    use moqtap_codec::draft18::message::*;
    use moqtap_codec::kvp::KeyValuePair;
    use moqtap_codec::types::*;

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

    kvp_value_maximum_gates!(draft18, subscribe, setup);
}

#[cfg(feature = "draft19")]
mod draft19 {
    use moqtap_codec::draft19::message::*;
    use moqtap_codec::kvp::KeyValuePair;
    use moqtap_codec::types::*;

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

    kvp_value_maximum_gates!(draft19, subscribe, setup);
}

#[cfg(feature = "draft20")]
mod draft20 {
    use moqtap_codec::draft20::message::*;
    use moqtap_codec::kvp::KeyValuePair;
    use moqtap_codec::types::*;

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

    kvp_value_maximum_gates!(draft20, subscribe, setup);
}
#[cfg(feature = "draft21")]
mod draft21 {
    use moqtap_codec::draft21::message::*;
    use moqtap_codec::kvp::KeyValuePair;
    use moqtap_codec::types::*;

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

    kvp_value_maximum_gates!(draft21, subscribe, setup);
}

#[cfg(feature = "draft22")]
mod draft22 {
    use moqtap_codec::draft22::message::*;
    use moqtap_codec::kvp::KeyValuePair;
    use moqtap_codec::types::*;

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

    kvp_value_maximum_gates!(draft22, subscribe, setup);
}
#[cfg(feature = "draft23")]
mod draft23 {
    use moqtap_codec::draft23::message::*;
    use moqtap_codec::error::CodecError;
    use moqtap_codec::kvp::{KeyValuePair, KvpError, KvpValue};
    use moqtap_codec::types::*;

    fn opaque(len: usize) -> KeyValuePair {
        KeyValuePair {
            key: super::varint(super::AN_UNASSIGNED_ODD_TYPE),
            value: KvpValue::Bytes(vec![0xAB; len]),
        }
    }

    fn subscribe(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            request_id: super::varint(1),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            parameters,
        })
    }

    /// Draft-23 Section 8.3: "The maximum length of a value is 2^16-1 bytes."
    /// Setup Options are Key-Value-Pairs, so their writer holds the value to
    /// it.
    #[test]
    fn a_setup_option_past_the_maximum_is_refused_by_the_rule_it_broke() {
        let message =
            ControlMessage::Setup(Setup { options: vec![opaque(super::PAST_THE_MAXIMUM)] });
        let mut buf = Vec::new();
        let got = message.encode_with_limit(&mut buf, u64::MAX);
        assert_eq!(got, Err(CodecError::Kvp(KvpError::ValueTooLong(super::PAST_THE_MAXIMUM))));
        assert!(buf.is_empty());
    }

    /// Message Parameters are not Key-Value-Pairs, and draft-23 Section 9.19
    /// bounds them by the message alone: "the total length of a control message
    /// is limited by MAX_CONTROL_MESSAGE_SIZE (Section 9.1.8)."
    #[test]
    fn a_message_parameter_is_bounded_by_the_message_alone() {
        let message = subscribe(vec![opaque(super::PAST_THE_MAXIMUM)]);
        let mut buf = Vec::new();
        assert!(matches!(
            message.encode(&mut buf),
            Err(CodecError::ControlMessageExceedsLimit { limit: 65535, .. })
        ));
        assert!(buf.is_empty());
        message.encode_with_limit(&mut buf, 1 << 20).expect("a larger limit admits it");
    }
}

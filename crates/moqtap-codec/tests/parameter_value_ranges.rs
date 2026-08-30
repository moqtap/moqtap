//! Values the drafts give a range, and the close they require outside it.
//!
//! From draft-15 on, several Message Parameters carry a stated range and a
//! stated consequence. GROUP_ORDER: "The allowed values are Ascending (0x1) or
//! Descending (0x2). If an endpoint receives a value outside this range, it MUST
//! close the session with PROTOCOL_VIOLATION." FORWARD says the same of 0 and 1.
//! Drafts 15 and 16 add SUBSCRIBER_PRIORITY — "The range is restricted to
//! 0-255" — and draft-15 alone adds DYNAMIC_GROUPS, whose "Values larger than 1
//! are a Protocol Violation" says it in different words.
//!
//! # The rule reverses, and Group Order is where it reverses
//!
//! Drafts 07 through 14 carry Group Order as a message field, and there 0x0 is
//! legal in a request: "A value of 0x0 indicates the original publisher's Group
//! Order SHOULD be used." Only the replies forbid it. From draft-15 the field
//! becomes a parameter, and the parameter has no such value — a subscriber with
//! no preference omits the parameter instead, and the range sentence admits
//! nothing but 0x1 and 0x2 in any message that carries it.
//!
//! So the same intent, spelled the way each draft spells it, is ordinary traffic
//! on draft-14 and a session close on draft-15. Both halves are driven below,
//! because an implementation that carried the field asymmetry forward into the
//! parameter would accept 0x0 everywhere, and one that carried the parameter
//! rule backward would refuse the requests drafts 07 through 14 permit.
//!
//! # The half that is easy to get wrong by over-reaching
//!
//! Draft-15's PUBLISHER_PRIORITY says "The value is from 0 to 255 and lower
//! numbers get higher priority. Priorities above 255 are invalid." — and names
//! no consequence, where each of the four parameters above names one in the
//! following clause. The contrast sits inside a single section, so the omission
//! is the draft's. A table assembled from "which parameters mention a range"
//! rather than "which parameters state a consequence" would close sessions over
//! it, and `a_priority_the_draft_calls_invalid_without_saying_more_is_carried`
//! is what fails when one does.
//!
//! Draft-17 drops the SUBSCRIBER_PRIORITY sentence for the opposite reason: it
//! makes the parameter a uint8, so a value above 255 can no longer be spelled
//! and the rule has nothing left to forbid.

#![cfg(any(feature = "draft14", feature = "draft15", feature = "draft16"))]

mod frames;

#[cfg(any(feature = "draft15", feature = "draft16"))]
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
use moqtap_codec::varint::VarInt;

fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).expect("fixture value fits a varint")
}

#[cfg(any(feature = "draft15", feature = "draft16"))]
fn parameter(key: u64, value: u64) -> KeyValuePair {
    KeyValuePair { key: varint(key), value: KvpValue::Varint(varint(value)) }
}

/// FORWARD, an even type and so a bare varint value on drafts 15 and 16.
#[cfg(any(feature = "draft15", feature = "draft16"))]
const FORWARD: u64 = 0x10;
/// SUBSCRIBER_PRIORITY.
#[cfg(any(feature = "draft15", feature = "draft16"))]
const SUBSCRIBER_PRIORITY: u64 = 0x20;
/// GROUP_ORDER.
#[cfg(any(feature = "draft15", feature = "draft16"))]
const GROUP_ORDER: u64 = 0x22;

#[cfg(feature = "draft15")]
mod draft15 {
    use super::{parameter, varint, FORWARD, GROUP_ORDER, SUBSCRIBER_PRIORITY};
    use moqtap_codec::draft15::message::*;
    use moqtap_codec::error::CodecError;
    use moqtap_codec::types::*;

    /// DYNAMIC_GROUPS, a Message Parameter on this draft alone. Draft-16 moves it
    /// into the extension header registry.
    const DYNAMIC_GROUPS: u64 = 0x30;

    /// PUBLISHER_PRIORITY, Section 9.2.1.4. Draft-16 does not define it.
    const PUBLISHER_PRIORITY: u64 = 0x0E;

    /// Each of the four parameters this draft gives a range: the type, a value
    /// inside the range, and one outside it.
    ///
    /// The legal value is there because it is what the frame is written around
    /// — the encoder will not write the illegal one. It is chosen to be a
    /// varint of the same length, so replacing one with the other moves nothing
    /// else in the frame.
    const CASES: &[(u64, u64, u64)] = &[
        // Group Order 0x0 is the reversal: a request may send it as a field
        // on draft-14 and may not send it as a parameter here.
        (GROUP_ORDER, 1, 0),
        (GROUP_ORDER, 1, 3),
        (FORWARD, 1, 2),
        (SUBSCRIBER_PRIORITY, 255, 256),
        (DYNAMIC_GROUPS, 1, 2),
    ];

    fn subscribe(parameters: Vec<moqtap_codec::kvp::KeyValuePair>) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            request_id: varint(1),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            parameters,
        })
    }

    fn subscribe_with(parameters: Vec<moqtap_codec::kvp::KeyValuePair>) -> Vec<u8> {
        let mut out = Vec::new();
        subscribe(parameters).encode(&mut out).expect("the encoder writes a value in range");
        out
    }

    /// The frame this codec writes for `parameters`, with the last value
    /// rewritten from `legal` to `illegal`.
    ///
    /// The encoder will not write `illegal`: a value outside the range its type
    /// allows is one the receiver must close the session over, so writing it is
    /// not a way to send it. That is the same rule these gates read from the
    /// receiver's side, and it is gated from the sender's below.
    ///
    /// Each pair of values is a varint of the same length, so the rewrite moves
    /// nothing — every length in the frame is still the encoder's.
    fn with_last_value(
        parameters: Vec<moqtap_codec::kvp::KeyValuePair>,
        legal: u64,
        illegal: u64,
    ) -> Vec<u8> {
        super::frames::with_varint_value(&subscribe_with(parameters), legal, illegal)
    }

    /// Each of the four parameters draft-15 gives a range, refused outside it.
    ///
    /// The frames are written by this codec's own encoder, so everything except
    /// the one value under test — the framing, the declared length, the
    /// parameter count, the key — is exactly what it writes.
    ///
    /// # What it catches
    ///
    /// Without `check_parameter_value_ranges` in `decode_parameters` the value
    /// is handed up as an ordinary parameter:
    ///
    /// ```text
    /// assertion `left == right` failed: parameter 0x22 value 0 must be refused
    ///   left: Ok(Subscribe(Subscribe { request_id: VarInt(1), track_namespace: TrackNamespace([[110, 115]]), track_name: [116], parameters: [KeyValuePair { key: VarInt(34), value: Varint(VarInt(0)) }] }))
    ///  right: Err(ParameterValueOutOfRange { key: 34, value: 0 })
    /// ```
    #[test]
    fn a_parameter_outside_the_range_its_type_allows_is_refused() {
        for &(key, legal, value) in CASES {
            let bytes = with_last_value(vec![parameter(key, legal)], legal, value);
            assert_eq!(
                ControlMessage::decode(&mut &bytes[..]),
                Err(CodecError::ParameterValueOutOfRange { key, value }),
                "parameter {key:#x} value {value} must be refused",
            );
        }
    }

    /// A value the reader refuses is one the writer will not write.
    ///
    /// The same five cases from the other side. Each range sentence names a
    /// close, so a caller that puts one of these values in a parameter has
    /// written a message that ends the session and would learn of it from the
    /// far end rather than from the call that wrote it.
    ///
    /// # What it catches
    ///
    /// Dropping the `check_parameter_value_ranges` call from this draft's
    /// `encode_parameters`, which is where it was missing:
    ///
    /// ```text
    /// assertion `left == right` failed: the writer produced parameter 0x22 value 0, which the reader refuses
    ///   left: Ok(())
    ///  right: Err(ParameterValueOutOfRange { key: 34, value: 0 })
    /// ```
    #[test]
    fn a_value_the_reader_refuses_is_one_the_writer_will_not_write() {
        for &(key, _, value) in CASES {
            let mut buf = Vec::new();
            let result = subscribe(vec![parameter(key, value)]).encode(&mut buf);
            assert_eq!(
                result,
                Err(CodecError::ParameterValueOutOfRange { key, value }),
                "the writer produced parameter {key:#x} value {value}, \
                 which the reader refuses",
            );
            assert!(
                buf.is_empty(),
                "a refused message must leave the caller's buffer alone, and it wrote {} bytes",
                buf.len(),
            );
        }
    }

    /// The values inside each range still decode, which is the half a table that
    /// over-reached would break.
    #[test]
    fn every_value_the_ranges_admit_is_carried() {
        let cases: &[(u64, u64)] = &[
            (GROUP_ORDER, 1),
            (GROUP_ORDER, 2),
            (FORWARD, 0),
            (FORWARD, 1),
            (SUBSCRIBER_PRIORITY, 0),
            (SUBSCRIBER_PRIORITY, 128),
            (SUBSCRIBER_PRIORITY, 255),
            (DYNAMIC_GROUPS, 0),
            (DYNAMIC_GROUPS, 1),
        ];
        for &(key, value) in cases {
            let bytes = subscribe_with(vec![parameter(key, value)]);
            assert!(
                ControlMessage::decode(&mut &bytes[..]).is_ok(),
                "parameter {key:#x} value {value} is inside the range and must decode",
            );
        }
    }

    /// PUBLISHER_PRIORITY names a range and no consequence, so it is carried.
    ///
    /// Section 9.2.1.4: "The value is from 0 to 255 and lower numbers get higher
    /// priority. Priorities above 255 are invalid." Every parameter this test
    /// file refuses states a close in the clause after its range; this one
    /// stops. Adding `0x0E => value <= 255` to `parameter_value_in_range` is the
    /// natural over-reach, and it fails here with:
    ///
    /// ```text
    /// assertion failed: a range the draft states without a consequence is not a
    /// close: Err(ParameterValueOutOfRange { key: 14, value: 300 })
    /// ```
    #[test]
    fn a_priority_the_draft_calls_invalid_without_saying_more_is_carried() {
        let bytes = subscribe_with(vec![parameter(PUBLISHER_PRIORITY, 300)]);
        let got = ControlMessage::decode(&mut &bytes[..]);
        assert!(
            got.is_ok(),
            "a range the draft states without a consequence is not a close: {got:?}",
        );
    }

    /// The rules are stated for Message Parameters, and a SETUP is the other
    /// namespace.
    ///
    /// Draft-15's setup registry assigns 0x01 through 0x05 and 0x07; it does not
    /// define 0x22, so a CLIENT_SETUP carrying that type is carrying something
    /// the draft has given no range to. Applying the message-namespace table to
    /// `decode_setup_parameters` closes the session on it instead.
    ///
    /// Both sides of the codec are held here. The setup arms of `encode_payload`
    /// have to reach the encoder that leaves the version-specific rules out, and
    /// pointing them at the other one refuses a CLIENT_SETUP the draft permits:
    ///
    /// ```text
    /// a setup 0x22 has no range on this draft: ParameterValueOutOfRange { key: 34, value: 0 }
    /// ```
    #[test]
    fn the_ranges_do_not_reach_into_a_setup() {
        let message = ControlMessage::ClientSetup(ClientSetup {
            parameters: vec![parameter(GROUP_ORDER, 0)],
        });
        let mut bytes = Vec::new();
        message.encode(&mut bytes).expect("a setup 0x22 has no range on this draft");
        let got = ControlMessage::decode(&mut &bytes[..]);
        assert!(
            got.is_ok(),
            "a setup parameter is not a Message Parameter and has no range here: {got:?}",
        );
    }
}

#[cfg(feature = "draft16")]
mod draft16 {
    use super::{parameter, varint, FORWARD, GROUP_ORDER, SUBSCRIBER_PRIORITY};

    /// DELIVERY_TIMEOUT, ranged by draft-16 alone.
    const DELIVERY_TIMEOUT: u64 = 0x02;

    /// This draft's ranged parameters: the type, a value inside the range, and
    /// one outside it. See draft-15's `CASES` for why the legal value is here.
    const CASES: &[(u64, u64, u64)] = &[
        (GROUP_ORDER, 1, 0),
        (GROUP_ORDER, 1, 3),
        (FORWARD, 1, 2),
        (SUBSCRIBER_PRIORITY, 255, 256),
        (DELIVERY_TIMEOUT, 1, 0),
    ];

    use moqtap_codec::draft16::message::*;
    use moqtap_codec::error::CodecError;
    use moqtap_codec::types::*;

    fn subscribe(parameters: Vec<moqtap_codec::kvp::KeyValuePair>) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            request_id: varint(1),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            parameters,
        })
    }

    fn subscribe_with(parameters: Vec<moqtap_codec::kvp::KeyValuePair>) -> Vec<u8> {
        let mut out = Vec::new();
        subscribe(parameters).encode(&mut out).expect("the encoder writes a value in range");
        out
    }

    /// The frame this codec writes for `parameters`, with the last value
    /// rewritten from `legal` to `illegal`.
    ///
    /// The encoder will not write `illegal`: a value outside the range its type
    /// allows is one the receiver must close the session over, so writing it is
    /// not a way to send it. That is the same rule these gates read from the
    /// receiver's side, and it is gated from the sender's below.
    ///
    /// Each pair of values is a varint of the same length, so the rewrite moves
    /// nothing — every length in the frame is still the encoder's.
    fn with_last_value(
        parameters: Vec<moqtap_codec::kvp::KeyValuePair>,
        legal: u64,
        illegal: u64,
    ) -> Vec<u8> {
        super::frames::with_varint_value(&subscribe_with(parameters), legal, illegal)
    }

    /// Draft-16's three ranged parameters, refused outside their ranges.
    ///
    /// The key reported is the absolute type, after the delta encoding this
    /// draft applies to parameter types is resolved. A check that read the delta
    /// instead would name 0x22 correctly here, where it is the first parameter
    /// and the delta equals the type, and misname it in any message carrying a
    /// parameter before it.
    #[test]
    fn a_parameter_outside_the_range_its_type_allows_is_refused() {
        for &(key, legal, value) in CASES {
            let bytes = with_last_value(vec![parameter(key, legal)], legal, value);
            assert_eq!(
                ControlMessage::decode(&mut &bytes[..]),
                Err(CodecError::ParameterValueOutOfRange { key, value }),
                "parameter {key:#x} value {value} must be refused",
            );
        }
    }

    /// A value the reader refuses is one the writer will not write.
    ///
    /// Draft-15's gate of the same name, on this draft's table — which is the
    /// same table with DELIVERY_TIMEOUT in place of DYNAMIC_GROUPS.
    ///
    /// # What it catches
    ///
    /// Dropping the `check_parameter_value_ranges` call from this draft's
    /// `encode_parameters_in`:
    ///
    /// ```text
    /// assertion `left == right` failed: the writer produced parameter 0x22 value 0, which the reader refuses
    ///   left: Ok(())
    ///  right: Err(ParameterValueOutOfRange { key: 34, value: 0 })
    /// ```
    #[test]
    fn a_value_the_reader_refuses_is_one_the_writer_will_not_write() {
        for &(key, _, value) in CASES {
            let mut buf = Vec::new();
            let result = subscribe(vec![parameter(key, value)]).encode(&mut buf);
            assert_eq!(
                result,
                Err(CodecError::ParameterValueOutOfRange { key, value }),
                "the writer produced parameter {key:#x} value {value}, \
                 which the reader refuses",
            );
            assert!(
                buf.is_empty(),
                "a refused message must leave the caller's buffer alone, and it wrote {} bytes",
                buf.len(),
            );
        }
    }

    /// DELIVERY_TIMEOUT, whose range has one forbidden value and it is zero.
    ///
    /// Section 9.2.2.2: "DELIVERY_TIMEOUT, if present, MUST contain a value
    /// greater than 0. If an endpoint receives a DELIVERY_TIMEOUT equal to 0 it
    /// MUST close the session with PROTOCOL_VIOLATION." Draft-16 is the only
    /// draft that states this, in this namespace or the extension header one
    /// beside it: draft-15 has no such sentence, and draft-17 renamed the type
    /// to OBJECT_DELIVERY_TIMEOUT and gives it no range.
    ///
    /// The forbidden value is the one an implementation is most likely to emit
    /// by accident. Zero is what a timeout field holds when nothing has been
    /// configured, and it reads to a receiver that has not been told otherwise
    /// as "no timeout" — which is the opposite of what a delivery timeout of
    /// zero would mean if the draft allowed it.
    ///
    /// # What it catches
    ///
    /// Without DELIVERY_TIMEOUT in `parameter_value_in_range`:
    ///
    /// ```text
    /// assertion `left == right` failed: a DELIVERY_TIMEOUT of zero must be refused
    ///   left: Ok(Subscribe(Subscribe { request_id: VarInt(1), track_namespace: TrackNamespace([[110, 115]]), track_name: [116], parameters: [KeyValuePair { key: VarInt(2), value: Varint(VarInt(0)) }] }))
    ///  right: Err(ParameterValueOutOfRange { key: 2, value: 0 })
    /// ```
    #[test]
    fn a_delivery_timeout_of_zero_is_refused() {
        let bytes = with_last_value(vec![parameter(DELIVERY_TIMEOUT, 1)], 1, 0);
        assert_eq!(
            ControlMessage::decode(&mut &bytes[..]),
            Err(CodecError::ParameterValueOutOfRange { key: DELIVERY_TIMEOUT, value: 0 }),
            "a DELIVERY_TIMEOUT of zero must be refused",
        );

        // Every other value the type can hold is a legal timeout, including the
        // largest one a varint spells.
        for value in [1, 2, 30_000, (1u64 << 62) - 1] {
            let bytes = subscribe_with(vec![parameter(DELIVERY_TIMEOUT, value)]);
            assert!(
                ControlMessage::decode(&mut &bytes[..]).is_ok(),
                "a DELIVERY_TIMEOUT of {value} is above zero and must decode",
            );
        }
    }

    /// The absolute type is what the refusal names, driven from a message where
    /// the delta and the type differ.
    ///
    /// FORWARD (0x10) then GROUP_ORDER (0x22) is a delta of 0x12 on the second
    /// parameter. Reporting the delta would name type 18.
    #[test]
    fn the_refusal_names_the_type_and_not_the_delta() {
        let bytes = with_last_value(vec![parameter(FORWARD, 1), parameter(GROUP_ORDER, 1)], 1, 9);
        assert_eq!(
            ControlMessage::decode(&mut &bytes[..]),
            Err(CodecError::ParameterValueOutOfRange { key: GROUP_ORDER, value: 9 }),
        );
    }

    /// The values inside each range still decode.
    #[test]
    fn every_value_the_ranges_admit_is_carried() {
        let cases: &[(u64, u64)] = &[
            (GROUP_ORDER, 1),
            (GROUP_ORDER, 2),
            (FORWARD, 0),
            (FORWARD, 1),
            (SUBSCRIBER_PRIORITY, 0),
            (SUBSCRIBER_PRIORITY, 255),
        ];
        for &(key, value) in cases {
            let bytes = subscribe_with(vec![parameter(key, value)]);
            assert!(
                ControlMessage::decode(&mut &bytes[..]).is_ok(),
                "parameter {key:#x} value {value} is inside the range and must decode",
            );
        }
    }

    /// The rules are stated for Message Parameters, and a SETUP is the other
    /// namespace.
    ///
    /// Draft-15's gate of the same name, on this draft. Both sides of the
    /// encoder are held here: the setup arms of `encode_payload` have to reach
    /// the encoder that leaves the version-specific rules out, and pointing
    /// them at the other one refuses a CLIENT_SETUP the draft permits.
    ///
    /// # What it catches
    ///
    /// Pointing this draft's ClientSetup arm at `encode_parameters`:
    ///
    /// ```text
    /// a setup 0x22 has no range on this draft: ParameterValueOutOfRange { key: 34, value: 0 }
    /// ```
    #[test]
    fn the_ranges_do_not_reach_into_a_setup() {
        let message = ControlMessage::ClientSetup(ClientSetup {
            parameters: vec![parameter(GROUP_ORDER, 0)],
        });
        let mut bytes = Vec::new();
        message.encode(&mut bytes).expect("a setup 0x22 has no range on this draft");
        let got = ControlMessage::decode(&mut &bytes[..]);
        assert!(
            got.is_ok(),
            "a setup parameter is not a Message Parameter and has no range here: {got:?}",
        );
    }

    /// DYNAMIC_GROUPS is not a Message Parameter on this draft.
    ///
    /// Draft-15 assigns 0x30 to it in the parameter registry; draft-16 moves it
    /// to the extension header registry as a Track Extension. Carrying
    /// draft-15's entry forward would not merely mis-scope the range — 0x30 is
    /// not in draft-16's parameter registry at all, so the frame is refused one
    /// step earlier, as an unknown Message Parameter.
    #[test]
    fn the_parameter_draft_15_ranged_here_is_not_a_parameter_at_all() {
        let bytes = subscribe_with(vec![parameter(0x30, 2)]);
        assert_eq!(
            ControlMessage::decode(&mut &bytes[..]),
            Err(CodecError::UnknownMessageParameter(0x30)),
        );
    }
}

#[cfg(feature = "draft14")]
mod draft14 {
    use super::varint;
    use moqtap_codec::draft14::message::*;
    use moqtap_codec::types::*;

    /// The other side of the reversal: draft-14 permits Group Order 0x0 in a
    /// request.
    ///
    /// Section 9.7: "A value of 0x0 indicates the original publisher's Group
    /// Order SHOULD be used. Values larger than 0x2 are a protocol error." The
    /// draft-15 gate above refuses exactly this intent, spelled as a parameter.
    /// One implementation cannot satisfy both without knowing which draft it is
    /// reading, which is what this pair is here to hold.
    #[test]
    fn a_request_may_still_defer_the_group_order_to_the_publisher() {
        let message = ControlMessage::Subscribe(Subscribe {
            request_id: varint(1),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            subscriber_priority: 128,
            group_order: GroupOrder::Publisher,
            forward: Forward::Forward,
            filter_type: FilterType::LargestObject,
            start_location: None,
            end_group: None,
            parameters: Vec::new(),
        });
        let mut bytes = Vec::new();
        message.encode(&mut bytes).expect("encode");
        let back = ControlMessage::decode(&mut &bytes[..]);
        assert_eq!(
            back.as_ref().ok(),
            Some(&message),
            "0x0 is how a draft-14 request says it has no preference: {back:?}",
        );
    }
}

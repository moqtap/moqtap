//! Drafts 17 to 23 check a Message Parameter's scope when its type is read,
//! before its value.
//!
//! draft-17 Section 9.3.1: "Each Message Parameter definition indicates the
//! message types in which it can appear. If it appears in some other type of
//! message, the receiving endpoint MUST close the connection with a
//! PROTOCOL_VIOLATION." draft-23 Section 9.19.1 closes with INVALID_PARAMETER.
//! A parameter outside its scope is refused for where it is, whatever its value:
//! a value its type's range refuses, and a LOCATION_FILTER type no reader can
//! read past (draft-22 Section 9.20.9, draft-23 Section 9.19.9), are both
//! `ParameterOutOfScope`, never the value's own error. The encoder applies the
//! same order.
//!
//! Each frame is a SUBSCRIBE_OK the encoder writes around a parameter type no
//! draft defines (0x0C), which it carries, with that one type byte then
//! rewritten. None of the types driven here may appear in SUBSCRIBE_OK.

#![cfg(any(
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20",
    feature = "draft21",
    feature = "draft22",
    feature = "draft23"
))]

/// A Parameter Type none of these drafts defines, which every encoder here
/// writes and no scope excludes.
const UNDEFINED_PARAMETER: u8 = 0x0C;

/// `frame` with the parameter block `[count 1, type 0x0C]` retyped to `to`.
fn retyped(mut frame: Vec<u8>, to: u8) -> Vec<u8> {
    let at: Vec<usize> = (0..frame.len().saturating_sub(1))
        .filter(|&i| frame[i..i + 2] == [0x01, UNDEFINED_PARAMETER])
        .collect();
    assert_eq!(at.len(), 1, "the count-and-type pair is not unique in {frame:02x?}");
    frame[at[0] + 1] = to;
    frame
}

macro_rules! scope_before_value {
    ($module:ident, $feature:literal, cases = $cases:expr) => {
        #[cfg(feature = $feature)]
        mod $module {
            use super::{retyped, UNDEFINED_PARAMETER};
            use moqtap_codec::error::CodecError;
            use moqtap_codec::kvp::{KeyValuePair, KvpValue};
            use moqtap_codec::varint::VarInt;
            use moqtap_codec::$module::message::*;

            fn vi(v: u64) -> VarInt {
                VarInt::from_u64(v).expect("fixture value fits a varint")
            }

            fn subscribe_ok(parameters: Vec<KeyValuePair>) -> ControlMessage {
                ControlMessage::SubscribeOk(SubscribeOk {
                    track_alias: vi(5),
                    parameters,
                    track_properties: Vec::new(),
                })
            }

            /// Each case: the type, a value outside what it allows, and whether
            /// the value is stored as bytes rather than a varint.
            const CASES: &[(u64, u8, bool)] = $cases;

            fn stored(key: u64, value: u8, bytes: bool) -> KeyValuePair {
                let value = if bytes {
                    KvpValue::Bytes(vec![value])
                } else {
                    KvpValue::Varint(vi(value.into()))
                };
                KeyValuePair { key: vi(key), value }
            }

            fn out_of_scope(key: u64) -> CodecError {
                CodecError::ParameterOutOfScope { key, message_type: MessageType::SubscribeOk.id() }
            }

            #[test]
            fn a_misplaced_parameter_is_out_of_scope_whatever_its_value() {
                for &(key, value, _) in CASES {
                    let mut frame = Vec::new();
                    subscribe_ok(vec![KeyValuePair {
                        key: vi(UNDEFINED_PARAMETER.into()),
                        value: KvpValue::Varint(vi(value.into())),
                    }])
                    .encode(&mut frame)
                    .expect("an undefined type is written and carried");
                    let frame = retyped(frame, key as u8);
                    assert_eq!(
                        ControlMessage::decode(&mut &frame[..]),
                        Err(out_of_scope(key)),
                        "type {key:#x} value {value} in SUBSCRIBE_OK",
                    );
                }
            }

            #[test]
            fn the_encoder_refuses_it_for_its_place_too() {
                for &(key, value, bytes) in CASES {
                    let mut out = Vec::new();
                    assert_eq!(
                        subscribe_ok(vec![stored(key, value, bytes)]).encode(&mut out),
                        Err(out_of_scope(key)),
                        "type {key:#x} value {value} in SUBSCRIBE_OK",
                    );
                    assert!(out.is_empty(), "a refused message writes no bytes");
                }
            }
        }
    };
}

scope_before_value!(draft17, "draft17", cases = &[(0x22, 7, false), (0x10, 9, false)]);
scope_before_value!(draft18, "draft18", cases = &[(0x22, 7, false), (0x10, 9, false)]);
scope_before_value!(draft19, "draft19", cases = &[(0x22, 7, false), (0x10, 9, false)]);
scope_before_value!(
    draft20,
    "draft20",
    cases = &[(0x22, 7, false), (0x10, 9, false), (0x35, 7, false)]
);
scope_before_value!(
    draft21,
    "draft21",
    cases = &[(0x22, 7, false), (0x10, 9, false), (0x35, 7, false)]
);
// 0x21 is LOCATION_FILTER, and 0x06 a Location Filter Type draft-22 does not
// assign.
scope_before_value!(
    draft22,
    "draft22",
    cases = &[(0x22, 7, false), (0x10, 9, false), (0x35, 7, false), (0x21, 6, true)]
);
// draft-23 defines no FORWARD; 0x11 is PAUSED.
scope_before_value!(
    draft23,
    "draft23",
    cases = &[(0x22, 7, false), (0x11, 2, false), (0x35, 7, false), (0x21, 6, true)]
);

/// The scope lists these modules rely on, read from the drafts' own tables
/// where the codec exposes them.
#[cfg(any(feature = "draft20", feature = "draft21", feature = "draft22", feature = "draft23"))]
mod preconditions {
    macro_rules! none_in_subscribe_ok {
        ($module:ident, $feature:literal, $keys:expr) => {
            #[cfg(feature = $feature)]
            #[test]
            fn $module() {
                use moqtap_codec::$module::message::{parameter_in_scope, MessageType};
                for key in $keys {
                    assert!(
                        !parameter_in_scope(key, MessageType::SubscribeOk),
                        "type {key:#x} may appear in SUBSCRIBE_OK, so it tests nothing here"
                    );
                }
            }
        };
    }
    none_in_subscribe_ok!(draft20, "draft20", [0x22, 0x10, 0x35]);
    none_in_subscribe_ok!(draft21, "draft21", [0x22, 0x10, 0x35]);
    none_in_subscribe_ok!(draft22, "draft22", [0x22, 0x10, 0x35, 0x21]);
    none_in_subscribe_ok!(draft23, "draft23", [0x22, 0x11, 0x35, 0x21]);
}

/// FILL_PARAMETERS is a parameter, not a message, so a refusal inside it names
/// the message that carries it.
#[cfg(any(feature = "draft20", feature = "draft21", feature = "draft22", feature = "draft23"))]
macro_rules! fill_names_its_carrier {
    ($module:ident, $feature:literal) => {
        #[cfg(feature = $feature)]
        mod $module {
            use moqtap_codec::error::CodecError;
            use moqtap_codec::kvp::{KeyValuePair, KvpValue};
            use moqtap_codec::types::TrackNamespace;
            use moqtap_codec::varint::VarInt;
            use moqtap_codec::$module::message::*;

            fn subscribe_with_fill(inner: &[u8]) -> ControlMessage {
                ControlMessage::Subscribe(Subscribe {
                    request_id: VarInt::from_u64(1).unwrap(),
                    track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
                    track_name: b"t".to_vec(),
                    parameters: vec![KeyValuePair {
                        key: VarInt::from_u64(FILL_PARAMETERS).unwrap(),
                        value: KvpValue::Bytes(inner.to_vec()),
                    }],
                })
            }

            fn encoded(message: &ControlMessage) -> Result<Vec<u8>, CodecError> {
                let mut out = Vec::new();
                message.encode(&mut out)?;
                Ok(out)
            }

            /// One nested GROUP_ORDER (0x22), Descending.
            const LEGAL: [u8; 3] = [0x01, 0x22, 0x02];

            #[test]
            fn a_nested_value_out_of_range_names_the_carrier() {
                let refusal = CodecError::ParameterValueOutOfRange {
                    key: 0x22,
                    value: 7,
                    message_type: MessageType::Subscribe.id(),
                };
                let mut frame = encoded(&subscribe_with_fill(&LEGAL)).expect("legal");
                let last = frame.len() - 1;
                assert_eq!(frame[last], 0x02, "the nested value is the last byte");
                frame[last] = 0x07;
                assert_eq!(ControlMessage::decode(&mut &frame[..]), Err(refusal.clone()));
                assert_eq!(encoded(&subscribe_with_fill(&[0x01, 0x22, 0x07])), Err(refusal));
            }

            /// INCLUDE_PROPERTIES (0x35) is not one of the types FILL_PARAMETERS
            /// may carry.
            #[test]
            fn a_nested_parameter_out_of_scope_names_the_carrier() {
                let refusal = CodecError::ParameterOutOfScope {
                    key: 0x35,
                    message_type: MessageType::Subscribe.id(),
                };
                let mut frame = encoded(&subscribe_with_fill(&LEGAL)).expect("legal");
                let at = frame.len() - 2;
                assert_eq!(frame[at], 0x22, "the nested type is the second-last byte");
                frame[at] = 0x35;
                assert_eq!(ControlMessage::decode(&mut &frame[..]), Err(refusal.clone()));
                assert_eq!(encoded(&subscribe_with_fill(&[0x01, 0x35, 0x01])), Err(refusal));
            }
        }
    };
}

#[cfg(any(feature = "draft20", feature = "draft21", feature = "draft22", feature = "draft23"))]
mod fill {
    fill_names_its_carrier!(draft20, "draft20");
    fill_names_its_carrier!(draft21, "draft21");
    fill_names_its_carrier!(draft22, "draft22");
    fill_names_its_carrier!(draft23, "draft23");
}

/// draft-23 Section 12.2: "When more than one code applies, an endpoint uses
/// DELTA_ENCODING_OVERFLOW or FIELD_LENGTH_EXCEEDED in preference to the other
/// codes." A misplaced parameter does not hide an overflow later in the message,
/// and does hide any other error after it.
#[cfg(feature = "draft23")]
mod draft23_preference {
    use moqtap_codec::draft23::message::*;
    use moqtap_codec::error::CodecError;
    use moqtap_codec::kvp::{KeyValuePair, KvpError, KvpValue};
    use moqtap_codec::varint::{Moqt18, VarInt};

    /// A SUBSCRIBE_OK, track alias 5, whose parameter block is `block`.
    fn subscribe_ok(block: &[u8]) -> Vec<u8> {
        let mut body = vec![0x05];
        body.extend_from_slice(block);
        let mut frame = vec![0x04];
        VarInt::from_usize(body.len()).encode_moqt::<Moqt18>(&mut frame);
        frame.extend_from_slice(&body);
        frame
    }

    #[test]
    fn an_overflow_after_a_misplaced_parameter_is_the_one_reported() {
        // GROUP_ORDER Descending, then a Type Delta of 2^64 - 1.
        let mut block = vec![0x02, 0x22, 0x02];
        VarInt::from_u64_moqt(u64::MAX).encode_moqt::<Moqt18>(&mut block);
        assert_eq!(
            ControlMessage::decode(&mut &subscribe_ok(&block)[..]),
            Err(CodecError::KeyDeltaOverflow(0x22, u64::MAX))
        );
    }

    #[test]
    fn any_other_error_after_a_misplaced_parameter_reports_the_misplaced_one() {
        let out_of_scope = Err(CodecError::ParameterOutOfScope {
            key: 0x22,
            message_type: MessageType::SubscribeOk.id(),
        });
        // A repeat of GROUP_ORDER, which draft-23 Section 9.19 refuses too.
        let repeated = [0x02, 0x22, 0x02, 0x00, 0x01];
        assert_eq!(ControlMessage::decode(&mut &subscribe_ok(&repeated)[..]), out_of_scope);
        // 0x40, a type draft-23 does not define.
        let unknown = [0x02, 0x22, 0x02, 0x1E, 0x00];
        assert_eq!(ControlMessage::decode(&mut &subscribe_ok(&unknown)[..]), out_of_scope);
        // Its own value out of range.
        let own_value = [0x01, 0x22, 0x07];
        assert_eq!(ControlMessage::decode(&mut &subscribe_ok(&own_value)[..]), out_of_scope);
    }

    #[test]
    fn an_overflow_in_the_track_properties_is_still_the_one_reported() {
        // GROUP_ORDER Descending, then Track Properties.
        let mut delta = vec![0x01, 0x22, 0x02, 0x02, 0x01];
        VarInt::from_u64_moqt(u64::MAX).encode_moqt::<Moqt18>(&mut delta);
        assert_eq!(
            ControlMessage::decode(&mut &subscribe_ok(&delta)[..]),
            Err(CodecError::KeyDeltaOverflow(0x02, u64::MAX))
        );
        let mut too_long = vec![0x01, 0x22, 0x02, 0x01];
        VarInt::from_usize(0x1_0000).encode_moqt::<Moqt18>(&mut too_long);
        assert_eq!(
            ControlMessage::decode(&mut &subscribe_ok(&too_long)[..]),
            Err(CodecError::Kvp(KvpError::ValueTooLong(0x1_0000)))
        );
    }

    #[test]
    fn a_misplaced_parameter_inside_fill_parameters_does_not_hide_a_later_overflow() {
        // FILL_PARAMETERS holding INCLUDE_PROPERTIES, outside Table 7.
        let mut block = vec![0x01, 0x23, 0x01, 0x35, 0x01, 0x02, 0x01];
        VarInt::from_u64_moqt(u64::MAX).encode_moqt::<Moqt18>(&mut block);
        assert_eq!(
            ControlMessage::decode(&mut &subscribe_ok(&block)[..]),
            Err(CodecError::KeyDeltaOverflow(0x02, u64::MAX))
        );
    }

    #[test]
    fn the_encoder_prefers_the_same_codes() {
        let message = ControlMessage::SubscribeOk(SubscribeOk {
            track_alias: VarInt::from_u64_moqt(5),
            parameters: vec![KeyValuePair {
                key: VarInt::from_u64_moqt(0x22),
                value: KvpValue::Varint(VarInt::from_u64_moqt(2)),
            }],
            track_properties: vec![KeyValuePair {
                key: VarInt::from_u64_moqt(0x01),
                value: KvpValue::Bytes(vec![0; 0x1_0000]),
            }],
        });
        assert_eq!(
            message.encode(&mut Vec::new()),
            Err(CodecError::Kvp(KvpError::ValueTooLong(0x1_0000)))
        );
    }
}

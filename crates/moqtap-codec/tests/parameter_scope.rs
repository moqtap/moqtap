//! Where a Message Parameter is allowed to appear, and what happens when it
//! appears anywhere else.
//!
//! Draft-17 Section 9.3.1, and drafts 18 and 19 Section 10.2.1: "Each Message
//! Parameter definition indicates the message types in which it can appear. If
//! it appears in some other type of message, the receiving endpoint MUST close
//! the connection with a PROTOCOL_VIOLATION."
//!
//! Every draft before them states the first sentence and reverses the second.
//! Draft-16 Section 9.2.2, and drafts 07 through 15 under the older name Version
//! Specific Parameters, end it "it MUST be ignored". Ten drafts oblige an
//! endpoint to carry exactly what three oblige it to close over, so the last
//! test in this file is on draft-16 and asserts the opposite of the first.
//!
//! # How a frame carrying an out-of-scope parameter is built
//!
//! Not by the encoder, which refuses one too — that is the other half of the
//! rule and is asserted alongside every refusal here. Each such frame is
//! written by the encoder carrying something it will write, and then one byte is
//! changed: either the Parameter Type, or the message type the parameters sit
//! in. The frame is otherwise the encoder's own work, so its framing, declared
//! Length, parameter count and delta encoding are exactly what this codec
//! produces, and the byte that differs is the one the rule is about.

#[cfg(any(
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20",
    feature = "draft21"
))]
use moqtap_codec::kvp::{KeyValuePair, KvpValue};
#[cfg(any(
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20",
    feature = "draft21"
))]
use moqtap_codec::varint::VarInt;

/// A Parameter Type none of these drafts defines.
///
/// The three registries between them assign 0x02, 0x03, 0x04, 0x06, 0x08, 0x09,
/// 0x0A, 0x10, 0x20, 0x21, 0x22, 0x25 through 0x29, 0x32 and 0x34. A type
/// outside all of them has no scope to be outside of, so the encoder writes it
/// and the scope check carries it; that is what makes it usable as the stand-in
/// a frame is built from.
#[cfg(any(
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20",
    feature = "draft21"
))]
const UNDEFINED_PARAMETER: u64 = 0x0C;

#[cfg(any(
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20",
    feature = "draft21"
))]
fn vi(v: u64) -> VarInt {
    VarInt::from_u64(v).expect("fixture value fits a varint")
}

/// A varint-valued Message Parameter.
#[cfg(any(
    feature = "draft16",
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20",
    feature = "draft21"
))]
fn varint_parameter(key: u64, value: u64) -> KeyValuePair {
    KeyValuePair { key: vi(key), value: KvpValue::Varint(vi(value)) }
}

/// A length-prefixed Message Parameter.
#[cfg(any(feature = "draft19", feature = "draft20", feature = "draft21"))]
fn bytes_parameter(key: u64, value: &[u8]) -> KeyValuePair {
    KeyValuePair { key: vi(key), value: KvpValue::Bytes(value.to_vec()) }
}

/// The same frame with its one Parameter Type changed from `from` to `to`.
///
/// A message carrying a single parameter writes its Number of Parameters as
/// `01` and then the Type Delta, which for the first parameter is the Type
/// itself — so the two bytes `01 from` locate it, and one substitution produces
/// the frame under test. Both types must share a value encoding, or the change
/// would be answered by the encoding rule rather than the scope rule.
///
/// The count of matches is asserted rather than assumed: `01` is a common byte
/// and a fixture that happened to repeat the pair would otherwise be patched in
/// the wrong place and still decode.
#[cfg(any(
    feature = "draft17",
    feature = "draft18",
    feature = "draft19",
    feature = "draft20",
    feature = "draft21"
))]
fn retyped(mut frame: Vec<u8>, from: u8, to: u8) -> Vec<u8> {
    let matches = frame.windows(2).filter(|w| *w == [0x01, from]).count();
    assert_eq!(
        matches,
        1,
        "the parameter block's count-and-type pair {:02x?} is not unique in {:02x?}, so the \
         substitution would not be the one this fixture describes",
        [0x01, from],
        frame
    );
    let at =
        frame.windows(2).position(|w| w == [0x01, from]).expect("the pair was just counted once");
    frame[at + 1] = to;
    frame
}

/// The same frame under a different message type.
///
/// Only useful where the two types carry the same body, which on draft-17 is
/// true of REQUEST_OK and PUBLISH_OK: both are a parameter block and nothing
/// else. The bytes that follow are legal in either message, so the type byte is
/// the whole of the difference between a frame that must be carried and one that
/// must end the session.
#[cfg(feature = "draft17")]
fn remessaged(mut frame: Vec<u8>, from: u8, to: u8) -> Vec<u8> {
    assert_eq!(frame[0], from, "the fixture does not start with the message type it claims");
    frame[0] = to;
    frame
}

// ─────────────────────────────────────────────────────────────
// draft-17
// ─────────────────────────────────────────────────────────────

#[cfg(feature = "draft17")]
mod draft17 {
    use moqtap_codec::draft17::message::{
        ControlMessage, FetchOk, PublishOk, RequestOk, Subscribe, SubscribeOk,
    };
    use moqtap_codec::error::CodecError;
    use moqtap_codec::kvp::KeyValuePair;
    use moqtap_codec::types::TrackNamespace;

    use super::{remessaged, retyped, varint_parameter, vi, UNDEFINED_PARAMETER};

    /// EXPIRES, Section 9.3.8. A varint, and named for four messages of which
    /// SUBSCRIBE is not one.
    const EXPIRES: u64 = 0x08;
    /// DELIVERY TIMEOUT, Section 9.3.3. A varint, and named for SUBSCRIBE.
    const DELIVERY_TIMEOUT: u64 = 0x02;
    /// LARGEST OBJECT, Section 9.3.9. Named for REQUEST_OK and not for the
    /// PUBLISH_OK that is a separate message on this draft.
    const LARGEST_OBJECT: u64 = 0x09;

    const SUBSCRIBE_TYPE: u8 = 0x03;
    const REQUEST_OK_TYPE: u8 = 0x07;
    const PUBLISH_OK_TYPE: u8 = 0x1E;
    const FETCH_OK_TYPE: u8 = 0x18;

    fn subscribe(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            request_id: vi(2),
            required_request_id_delta: vi(0),
            track_namespace: TrackNamespace(vec![b"live".to_vec()]),
            track_name: b"video".to_vec(),
            parameters,
        })
    }

    fn fetch_ok(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::FetchOk(FetchOk {
            end_of_track: 0,
            end_group: vi(10),
            end_object: vi(3),
            parameters,
            track_properties: Vec::new(),
        })
    }

    fn encoded(message: &ControlMessage) -> Vec<u8> {
        let mut out = Vec::new();
        message.encode(&mut out).expect("the fixture is a frame this codec writes");
        out
    }

    /// Section 9.3.3 names SUBSCRIBE, so a SUBSCRIBE carrying DELIVERY TIMEOUT
    /// survives both directions unchanged.
    ///
    /// The control for every refusal below: without it, a decoder that refused
    /// all parameters everywhere would pass them all.
    #[test]
    fn a_parameter_named_for_the_message_it_arrives_in_is_carried() {
        let message = subscribe(vec![varint_parameter(DELIVERY_TIMEOUT, 5_000)]);
        let frame = encoded(&message);

        let decoded = ControlMessage::decode(&mut &frame[..]).expect(
            "Section 9.3.3 names SUBSCRIBE among the messages this parameter may appear in",
        );
        assert_eq!(decoded, message);
    }

    /// Section 9.3.8 names SUBSCRIBE_OK, PUBLISH, PUBLISH_OK and REQUEST_OK, and
    /// SUBSCRIBE is none of them.
    ///
    /// # What it catches, observed by making the change and running it
    ///
    /// Returning `true` from every arm of draft-17's `parameter_in_scope`, which
    /// is the state the codec was in before the table existed:
    ///
    /// ```text
    /// ---- draft17::an_out_of_scope_parameter_ends_the_session stdout ----
    ///
    /// thread 'draft17::an_out_of_scope_parameter_ends_the_session' (8140) panicked at crates\moqtap-codec\tests\parameter_scope.rs:
    /// EXPIRES is not named for SUBSCRIBE: Subscribe(Subscribe { request_id: VarInt(2), required_request_id_delta: VarInt(0), track_namespace: TrackNamespace([[108, 105, 118, 101]]), track_name: [118, 105, 100, 101, 111], parameters: [KeyValuePair { key: VarInt(8), value: Varint(VarInt(30)) }] })
    /// ```
    #[test]
    fn an_out_of_scope_parameter_ends_the_session() {
        let carried = encoded(&subscribe(vec![varint_parameter(UNDEFINED_PARAMETER, 30)]));
        let frame = retyped(carried, UNDEFINED_PARAMETER as u8, EXPIRES as u8);

        let err = ControlMessage::decode(&mut &frame[..])
            .expect_err("EXPIRES is not named for SUBSCRIBE");
        assert_eq!(
            err,
            CodecError::ParameterOutOfScope {
                key: EXPIRES,
                message_type: u64::from(SUBSCRIBE_TYPE)
            }
        );
    }

    /// The encoder refuses the same message, so the two directions accept the
    /// same set of frames and a caller cannot write one the peer must close over.
    #[test]
    fn the_encoder_refuses_what_the_decoder_refuses() {
        let mut out = Vec::new();
        let err = subscribe(vec![varint_parameter(EXPIRES, 30)])
            .encode(&mut out)
            .expect_err("EXPIRES is not named for SUBSCRIBE");
        assert_eq!(
            err,
            CodecError::ParameterOutOfScope {
                key: EXPIRES,
                message_type: u64::from(SUBSCRIBE_TYPE)
            }
        );
    }

    /// Section 9.15 gives FETCH_OK a Parameters field and no parameter
    /// definition in Section 9.3 names FETCH_OK, so every type this draft
    /// defines is "some other type of message" there.
    #[test]
    fn a_fetch_ok_admits_no_parameter_this_draft_defines() {
        let carried = encoded(&fetch_ok(vec![varint_parameter(UNDEFINED_PARAMETER, 30)]));
        let frame = retyped(carried, UNDEFINED_PARAMETER as u8, EXPIRES as u8);

        let err = ControlMessage::decode(&mut &frame[..])
            .expect_err("no parameter definition names FETCH_OK");
        assert_eq!(
            err,
            CodecError::ParameterOutOfScope {
                key: EXPIRES,
                message_type: u64::from(FETCH_OK_TYPE)
            }
        );
    }

    /// PUBLISH_OK is a message type of its own on this draft (0x1E), and Section
    /// 9.3.9 does not name it.
    ///
    /// The two frames differ in one byte, and both are otherwise this codec's own
    /// output: REQUEST_OK and PUBLISH_OK carry the same body, so the bytes that
    /// follow the type are legal in either. Drafts 18 and 19 fold PUBLISH_OK into
    /// REQUEST_OK, where the same parameter is in scope — which is why this test
    /// has no counterpart there.
    #[test]
    fn largest_object_is_carried_by_a_request_ok_and_refused_by_a_publish_ok() {
        let message = ControlMessage::RequestOk(RequestOk {
            parameters: vec![KeyValuePair {
                key: vi(LARGEST_OBJECT),
                // A Location: two bare varints, group then object.
                value: moqtap_codec::kvp::KvpValue::Bytes(vec![0x0A, 0x03]),
            }],
        });
        let frame = encoded(&message);
        let decoded =
            ControlMessage::decode(&mut &frame[..]).expect("Section 9.3.9 names REQUEST_OK");
        assert_eq!(decoded, message);

        let moved = remessaged(frame, REQUEST_OK_TYPE, PUBLISH_OK_TYPE);
        let err = ControlMessage::decode(&mut &moved[..])
            .expect_err("Section 9.3.9 does not name PUBLISH_OK, which is its own message here");
        assert_eq!(
            err,
            CodecError::ParameterOutOfScope {
                key: LARGEST_OBJECT,
                message_type: u64::from(PUBLISH_OK_TYPE)
            }
        );

        let mut out = Vec::new();
        let err = ControlMessage::PublishOk(PublishOk {
            parameters: vec![KeyValuePair {
                key: vi(LARGEST_OBJECT),
                value: moqtap_codec::kvp::KvpValue::Bytes(vec![0x0A, 0x03]),
            }],
        })
        .encode(&mut out)
        .expect_err("the encoder holds PUBLISH_OK to the same table");
        assert_eq!(
            err,
            CodecError::ParameterOutOfScope {
                key: LARGEST_OBJECT,
                message_type: u64::from(PUBLISH_OK_TYPE)
            }
        );
    }

    /// The parameter refused in a SUBSCRIBE above is carried in a SUBSCRIBE_OK,
    /// which Section 9.3.8 does name.
    ///
    /// One parameter, two messages, opposite outcomes: what decides is the pair
    /// and not either half of it.
    #[test]
    fn the_same_parameter_is_carried_where_its_definition_names_the_message() {
        let message = ControlMessage::SubscribeOk(SubscribeOk {
            track_alias: vi(4),
            parameters: vec![varint_parameter(EXPIRES, 30)],
            track_properties: Vec::new(),
        });
        let frame = encoded(&message);

        let decoded =
            ControlMessage::decode(&mut &frame[..]).expect("Section 9.3.8 names SUBSCRIBE_OK");
        assert_eq!(decoded, message);
    }
}

// ─────────────────────────────────────────────────────────────
// draft-18
// ─────────────────────────────────────────────────────────────

#[cfg(feature = "draft18")]
mod draft18 {
    use moqtap_codec::draft18::message::{
        ControlMessage, FetchOk, RequestOk, Subscribe, SubscribeTracks,
    };
    use moqtap_codec::error::CodecError;
    use moqtap_codec::kvp::KeyValuePair;
    use moqtap_codec::types::TrackNamespace;

    use super::{retyped, varint_parameter, vi, UNDEFINED_PARAMETER};

    /// EXPIRES, Section 10.2.10.
    const EXPIRES: u64 = 0x08;
    /// OBJECT_DELIVERY_TIMEOUT, Section 10.2.4. Named for SUBSCRIBE.
    const OBJECT_DELIVERY_TIMEOUT: u64 = 0x02;
    /// RENDEZVOUS TIMEOUT, Section 10.2.6. Named for SUBSCRIBE and nothing else.
    const RENDEZVOUS_TIMEOUT: u64 = 0x04;

    const SUBSCRIBE_TYPE: u8 = 0x03;
    const FETCH_OK_TYPE: u8 = 0x18;
    const SUBSCRIBE_TRACKS_TYPE: u64 = 0x51;

    fn subscribe(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            request_id: vi(2),
            track_namespace: TrackNamespace(vec![b"live".to_vec()]),
            track_name: b"video".to_vec(),
            parameters,
        })
    }

    fn subscribe_tracks(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::SubscribeTracks(SubscribeTracks {
            request_id: vi(2),
            namespace_prefix: TrackNamespace(vec![b"live".to_vec()]),
            parameters,
        })
    }

    fn encoded(message: &ControlMessage) -> Vec<u8> {
        let mut out = Vec::new();
        message.encode(&mut out).expect("the fixture is a frame this codec writes");
        out
    }

    /// Section 10.2.4 names SUBSCRIBE.
    #[test]
    fn a_parameter_named_for_the_message_it_arrives_in_is_carried() {
        let message = subscribe(vec![varint_parameter(OBJECT_DELIVERY_TIMEOUT, 5_000)]);
        let frame = encoded(&message);

        let decoded =
            ControlMessage::decode(&mut &frame[..]).expect("Section 10.2.4 names SUBSCRIBE");
        assert_eq!(decoded, message);
    }

    /// Section 10.2.10 names SUBSCRIBE_OK, PUBLISH, PUBLISH_OK and
    /// REQUEST_UPDATE_OK, and SUBSCRIBE is none of them.
    #[test]
    fn an_out_of_scope_parameter_ends_the_session() {
        let carried = encoded(&subscribe(vec![varint_parameter(UNDEFINED_PARAMETER, 30)]));
        let frame = retyped(carried, UNDEFINED_PARAMETER as u8, EXPIRES as u8);

        let err = ControlMessage::decode(&mut &frame[..])
            .expect_err("EXPIRES is not named for SUBSCRIBE");
        assert_eq!(
            err,
            CodecError::ParameterOutOfScope {
                key: EXPIRES,
                message_type: u64::from(SUBSCRIBE_TYPE)
            }
        );
    }

    /// The encoder refuses the same message.
    #[test]
    fn the_encoder_refuses_what_the_decoder_refuses() {
        let mut out = Vec::new();
        let err = subscribe(vec![varint_parameter(EXPIRES, 30)])
            .encode(&mut out)
            .expect_err("EXPIRES is not named for SUBSCRIBE");
        assert_eq!(
            err,
            CodecError::ParameterOutOfScope {
                key: EXPIRES,
                message_type: u64::from(SUBSCRIBE_TYPE)
            }
        );
    }

    /// Section 10.13 gives FETCH_OK a Parameters field and no parameter
    /// definition names FETCH_OK.
    #[test]
    fn a_fetch_ok_admits_no_parameter_this_draft_defines() {
        let carried = encoded(&ControlMessage::FetchOk(FetchOk {
            end_of_track: 0,
            end_group: vi(10),
            end_object: vi(3),
            parameters: vec![varint_parameter(UNDEFINED_PARAMETER, 30)],
            track_properties: Vec::new(),
        }));
        let frame = retyped(carried, UNDEFINED_PARAMETER as u8, EXPIRES as u8);

        let err = ControlMessage::decode(&mut &frame[..])
            .expect_err("no parameter definition names FETCH_OK");
        assert_eq!(
            err,
            CodecError::ParameterOutOfScope {
                key: EXPIRES,
                message_type: u64::from(FETCH_OK_TYPE)
            }
        );
    }

    /// SUBSCRIBE_TRACKS admits what its own definitions name and nothing more.
    ///
    /// Section 10.2.6 names SUBSCRIBE for RENDEZVOUS TIMEOUT, and this draft has
    /// no sentence extending a SUBSCRIBE's parameters to a SUBSCRIBE_TRACKS.
    /// Draft-19 Section 10.19.1 adds one, and the draft-19 test of the same name
    /// asserts the opposite outcome from the same parameter and the same message.
    #[test]
    fn subscribe_tracks_does_not_inherit_a_subscribes_parameters() {
        let carried = encoded(&subscribe_tracks(vec![varint_parameter(UNDEFINED_PARAMETER, 30)]));
        let frame = retyped(carried, UNDEFINED_PARAMETER as u8, RENDEZVOUS_TIMEOUT as u8);

        let err =
            ControlMessage::decode(&mut &frame[..]).expect_err("this draft names SUBSCRIBE only");
        assert_eq!(
            err,
            CodecError::ParameterOutOfScope {
                key: RENDEZVOUS_TIMEOUT,
                message_type: SUBSCRIBE_TRACKS_TYPE
            }
        );
    }

    /// A REQUEST_OK is held to the union of the responses it carries.
    ///
    /// Section 10.5 makes PUBLISH_OK, REQUEST_UPDATE_OK, TRACK_STATUS_OK,
    /// SUBSCRIBE_NAMESPACE_OK and PUBLISH_NAMESPACE_OK all one wire type, and
    /// which one a given REQUEST_OK is depends on the request it answers. So
    /// EXPIRES is carried — Section 10.2.10 names PUBLISH_OK — while
    /// RENDEZVOUS TIMEOUT, which no response names, is not.
    #[test]
    fn a_request_ok_admits_what_any_of_its_responses_name() {
        let message = ControlMessage::RequestOk(RequestOk {
            parameters: vec![varint_parameter(EXPIRES, 30)],
            track_properties: Vec::new(),
        });
        let frame = encoded(&message);
        let decoded = ControlMessage::decode(&mut &frame[..])
            .expect("Section 10.2.10 names PUBLISH_OK, which is a REQUEST_OK on the wire");
        assert_eq!(decoded, message);

        let mut out = Vec::new();
        let err = ControlMessage::RequestOk(RequestOk {
            parameters: vec![varint_parameter(RENDEZVOUS_TIMEOUT, 30)],
            track_properties: Vec::new(),
        })
        .encode(&mut out)
        .expect_err("no response this type carries names RENDEZVOUS TIMEOUT");
        assert_eq!(
            err,
            CodecError::ParameterOutOfScope { key: RENDEZVOUS_TIMEOUT, message_type: 0x07 }
        );
    }
}

// ─────────────────────────────────────────────────────────────
// draft-19
// ─────────────────────────────────────────────────────────────

#[cfg(feature = "draft19")]
mod draft19 {
    use moqtap_codec::draft19::message::{ControlMessage, FetchOk, Subscribe, SubscribeTracks};
    use moqtap_codec::error::CodecError;
    use moqtap_codec::kvp::KeyValuePair;
    use moqtap_codec::types::TrackNamespace;

    use super::{bytes_parameter, retyped, varint_parameter, vi, UNDEFINED_PARAMETER};

    /// EXPIRES, Section 10.2.15.
    const EXPIRES: u64 = 0x08;
    /// OBJECT_DELIVERY_TIMEOUT, Section 10.2.4. Named for SUBSCRIBE.
    const OBJECT_DELIVERY_TIMEOUT: u64 = 0x02;
    /// RENDEZVOUS TIMEOUT, Section 10.2.6. Named for SUBSCRIBE.
    const RENDEZVOUS_TIMEOUT: u64 = 0x04;
    /// SUBGROUP_FILTER, Section 10.2.10, scoped by Section 5.1.3.
    const SUBGROUP_FILTER: u64 = 0x25;
    /// TRACK_PROPERTY_FILTER, Section 10.2.14, scoped by Section 5.1.3 to
    /// SUBSCRIBE_TRACKS and the REQUEST_UPDATE for one.
    const TRACK_PROPERTY_FILTER: u64 = 0x29;

    const SUBSCRIBE_TYPE: u8 = 0x03;
    const FETCH_OK_TYPE: u8 = 0x18;

    fn subscribe(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            request_id: vi(2),
            track_namespace: TrackNamespace(vec![b"live".to_vec()]),
            track_name: b"video".to_vec(),
            parameters,
        })
    }

    fn subscribe_tracks(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::SubscribeTracks(SubscribeTracks {
            request_id: vi(2),
            namespace_prefix: TrackNamespace(vec![b"live".to_vec()]),
            parameters,
        })
    }

    fn encoded(message: &ControlMessage) -> Vec<u8> {
        let mut out = Vec::new();
        message.encode(&mut out).expect("the fixture is a frame this codec writes");
        out
    }

    /// Section 10.2.4 names SUBSCRIBE.
    #[test]
    fn a_parameter_named_for_the_message_it_arrives_in_is_carried() {
        let message = subscribe(vec![varint_parameter(OBJECT_DELIVERY_TIMEOUT, 5_000)]);
        let frame = encoded(&message);

        let decoded =
            ControlMessage::decode(&mut &frame[..]).expect("Section 10.2.4 names SUBSCRIBE");
        assert_eq!(decoded, message);
    }

    /// Section 10.2.15 names SUBSCRIBE_OK, PUBLISH and five response types, and
    /// SUBSCRIBE is none of them.
    #[test]
    fn an_out_of_scope_parameter_ends_the_session() {
        let carried = encoded(&subscribe(vec![varint_parameter(UNDEFINED_PARAMETER, 30)]));
        let frame = retyped(carried, UNDEFINED_PARAMETER as u8, EXPIRES as u8);

        let err = ControlMessage::decode(&mut &frame[..])
            .expect_err("EXPIRES is not named for SUBSCRIBE");
        assert_eq!(
            err,
            CodecError::ParameterOutOfScope {
                key: EXPIRES,
                message_type: u64::from(SUBSCRIBE_TYPE)
            }
        );
    }

    /// The encoder refuses the same message.
    #[test]
    fn the_encoder_refuses_what_the_decoder_refuses() {
        let mut out = Vec::new();
        let err = subscribe(vec![varint_parameter(EXPIRES, 30)])
            .encode(&mut out)
            .expect_err("EXPIRES is not named for SUBSCRIBE");
        assert_eq!(
            err,
            CodecError::ParameterOutOfScope {
                key: EXPIRES,
                message_type: u64::from(SUBSCRIBE_TYPE)
            }
        );
    }

    /// Section 10.13 gives FETCH_OK a Parameters field and no parameter
    /// definition names FETCH_OK.
    #[test]
    fn a_fetch_ok_admits_no_parameter_this_draft_defines() {
        let carried = encoded(&ControlMessage::FetchOk(FetchOk {
            end_of_track: 0,
            end_group: vi(10),
            end_object: vi(3),
            parameters: vec![varint_parameter(UNDEFINED_PARAMETER, 30)],
            track_properties: Vec::new(),
        }));
        let frame = retyped(carried, UNDEFINED_PARAMETER as u8, EXPIRES as u8);

        let err = ControlMessage::decode(&mut &frame[..])
            .expect_err("no parameter definition names FETCH_OK");
        assert_eq!(
            err,
            CodecError::ParameterOutOfScope {
                key: EXPIRES,
                message_type: u64::from(FETCH_OK_TYPE)
            }
        );
    }

    /// Section 10.19.1: "Any Parameter that can be specified on a Subscription
    /// (ie: in SUBSCRIBE) is valid in SUBSCRIBE_TRACKS, unless otherwise
    /// specified."
    ///
    /// RENDEZVOUS TIMEOUT names SUBSCRIBE and nothing else, and arrives in a
    /// SUBSCRIBE_TRACKS unrefused because of that sentence alone. Draft-18 has no
    /// such sentence and refuses the same parameter in the same message, which is
    /// what its `subscribe_tracks_does_not_inherit_a_subscribes_parameters`
    /// asserts.
    #[test]
    fn subscribe_tracks_inherits_a_subscribes_parameters() {
        let message = subscribe_tracks(vec![varint_parameter(RENDEZVOUS_TIMEOUT, 30)]);
        let frame = encoded(&message);

        let decoded = ControlMessage::decode(&mut &frame[..])
            .expect("Section 10.19.1 extends SUBSCRIBE's parameters to SUBSCRIBE_TRACKS");
        assert_eq!(decoded, message);
    }

    /// The one Range Filter a SUBSCRIBE may not carry.
    ///
    /// Section 5.1.3 scopes four of the five to "a FETCH, SUBSCRIBE,
    /// SUBSCRIBE_TRACKS, PUBLISH_OK, or REQUEST_UPDATE" and the Track Property
    /// filter to "a SUBSCRIBE_TRACKS message or REQUEST_UPDATE for it" — it
    /// selects tracks rather than objects, and a SUBSCRIBE has already named its
    /// track. Both are length-prefixed and neither has a value rule, so the two
    /// frames here differ in the Parameter Type and nothing else.
    #[test]
    fn a_track_property_filter_is_refused_where_the_other_filters_are_carried() {
        let message = subscribe(vec![bytes_parameter(SUBGROUP_FILTER, &[0x00, 0x03, 0x02])]);
        let frame = encoded(&message);
        let decoded = ControlMessage::decode(&mut &frame[..])
            .expect("Section 5.1.3 names SUBSCRIBE for this filter");
        assert_eq!(decoded, message);

        let moved = retyped(frame, SUBGROUP_FILTER as u8, TRACK_PROPERTY_FILTER as u8);
        let err = ControlMessage::decode(&mut &moved[..])
            .expect_err("Section 5.1.3 names SUBSCRIBE_TRACKS and REQUEST_UPDATE for this one");
        assert_eq!(
            err,
            CodecError::ParameterOutOfScope {
                key: TRACK_PROPERTY_FILTER,
                message_type: u64::from(SUBSCRIBE_TYPE)
            }
        );

        let carried =
            subscribe_tracks(vec![bytes_parameter(TRACK_PROPERTY_FILTER, &[0x00, 0x03, 0x02])]);
        let frame = encoded(&carried);
        let decoded = ControlMessage::decode(&mut &frame[..])
            .expect("a SUBSCRIBE_TRACKS is where this filter belongs");
        assert_eq!(decoded, carried);
    }
}

// ─────────────────────────────────────────────────────────────
// draft-20
// ─────────────────────────────────────────────────────────────

#[cfg(feature = "draft20")]
mod draft20 {
    use moqtap_codec::draft20::message::{ControlMessage, FetchOk, Subscribe, SubscribeTracks};
    use moqtap_codec::error::CodecError;
    use moqtap_codec::kvp::KeyValuePair;
    use moqtap_codec::types::TrackNamespace;

    use super::{bytes_parameter, retyped, varint_parameter, vi, UNDEFINED_PARAMETER};

    /// EXPIRES, Section 10.2.16 — draft-19's 10.2.15, renumbered.
    const EXPIRES: u64 = 0x08;
    /// OBJECT_DELIVERY_TIMEOUT, Section 10.2.4. Named for SUBSCRIBE.
    const OBJECT_DELIVERY_TIMEOUT: u64 = 0x02;
    /// RENDEZVOUS TIMEOUT, Section 10.2.6. Named for SUBSCRIBE.
    const RENDEZVOUS_TIMEOUT: u64 = 0x04;
    /// SUBGROUP_FILTER, Section 10.2.10, scoped by Section 5.1.4 —
    /// draft-19's 5.1.3.
    const SUBGROUP_FILTER: u64 = 0x25;
    /// TRACK_PROPERTY_FILTER, Section 10.2.14, scoped by Section 5.1.4 to
    /// SUBSCRIBE_TRACKS and the REQUEST_UPDATE for one.
    const TRACK_PROPERTY_FILTER: u64 = 0x29;

    const SUBSCRIBE_TYPE: u8 = 0x03;
    const FETCH_OK_TYPE: u8 = 0x18;

    fn subscribe(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            request_id: vi(2),
            track_namespace: TrackNamespace(vec![b"live".to_vec()]),
            track_name: b"video".to_vec(),
            parameters,
        })
    }

    fn subscribe_tracks(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::SubscribeTracks(SubscribeTracks {
            request_id: vi(2),
            namespace_prefix: TrackNamespace(vec![b"live".to_vec()]),
            parameters,
        })
    }

    fn encoded(message: &ControlMessage) -> Vec<u8> {
        let mut out = Vec::new();
        message.encode(&mut out).expect("the fixture is a frame this codec writes");
        out
    }

    /// Section 10.2.4 names SUBSCRIBE.
    #[test]
    fn a_parameter_named_for_the_message_it_arrives_in_is_carried() {
        let message = subscribe(vec![varint_parameter(OBJECT_DELIVERY_TIMEOUT, 5_000)]);
        let frame = encoded(&message);

        let decoded =
            ControlMessage::decode(&mut &frame[..]).expect("Section 10.2.4 names SUBSCRIBE");
        assert_eq!(decoded, message);
    }

    /// Section 10.2.15 names SUBSCRIBE_OK, PUBLISH and five response types, and
    /// SUBSCRIBE is none of them.
    #[test]
    fn an_out_of_scope_parameter_ends_the_session() {
        let carried = encoded(&subscribe(vec![varint_parameter(UNDEFINED_PARAMETER, 30)]));
        let frame = retyped(carried, UNDEFINED_PARAMETER as u8, EXPIRES as u8);

        let err = ControlMessage::decode(&mut &frame[..])
            .expect_err("EXPIRES is not named for SUBSCRIBE");
        assert_eq!(
            err,
            CodecError::ParameterOutOfScope {
                key: EXPIRES,
                message_type: u64::from(SUBSCRIBE_TYPE)
            }
        );
    }

    /// The encoder refuses the same message.
    #[test]
    fn the_encoder_refuses_what_the_decoder_refuses() {
        let mut out = Vec::new();
        let err = subscribe(vec![varint_parameter(EXPIRES, 30)])
            .encode(&mut out)
            .expect_err("EXPIRES is not named for SUBSCRIBE");
        assert_eq!(
            err,
            CodecError::ParameterOutOfScope {
                key: EXPIRES,
                message_type: u64::from(SUBSCRIBE_TYPE)
            }
        );
    }

    /// Section 10.13 gives FETCH_OK a Parameters field and no parameter
    /// definition names FETCH_OK.
    #[test]
    fn a_fetch_ok_admits_no_parameter_this_draft_defines() {
        let carried = encoded(&ControlMessage::FetchOk(FetchOk {
            end_of_track: 0,
            end_group: vi(10),
            end_object: vi(3),
            parameters: vec![varint_parameter(UNDEFINED_PARAMETER, 30)],
            track_properties: Vec::new(),
        }));
        let frame = retyped(carried, UNDEFINED_PARAMETER as u8, EXPIRES as u8);

        let err = ControlMessage::decode(&mut &frame[..])
            .expect_err("no parameter definition names FETCH_OK");
        assert_eq!(
            err,
            CodecError::ParameterOutOfScope {
                key: EXPIRES,
                message_type: u64::from(FETCH_OK_TYPE)
            }
        );
    }

    /// Section 10.19.1: "Any Parameter that can be specified on a Subscription
    /// (ie: in SUBSCRIBE) is valid in SUBSCRIBE_TRACKS, unless otherwise
    /// specified."
    ///
    /// RENDEZVOUS TIMEOUT names SUBSCRIBE and nothing else, and arrives in a
    /// SUBSCRIBE_TRACKS unrefused because of that sentence alone. Draft-18 has no
    /// such sentence and refuses the same parameter in the same message, which is
    /// what its `subscribe_tracks_does_not_inherit_a_subscribes_parameters`
    /// asserts.
    #[test]
    fn subscribe_tracks_inherits_a_subscribes_parameters() {
        let message = subscribe_tracks(vec![varint_parameter(RENDEZVOUS_TIMEOUT, 30)]);
        let frame = encoded(&message);

        let decoded = ControlMessage::decode(&mut &frame[..])
            .expect("Section 10.19.1 extends SUBSCRIBE's parameters to SUBSCRIBE_TRACKS");
        assert_eq!(decoded, message);
    }

    /// The one Range Filter a SUBSCRIBE may not carry.
    ///
    /// Section 5.1.3 scopes four of the five to "a FETCH, SUBSCRIBE,
    /// SUBSCRIBE_TRACKS, PUBLISH_OK, or REQUEST_UPDATE" and the Track Property
    /// filter to "a SUBSCRIBE_TRACKS message or REQUEST_UPDATE for it" — it
    /// selects tracks rather than objects, and a SUBSCRIBE has already named its
    /// track. Both are length-prefixed and neither has a value rule, so the two
    /// frames here differ in the Parameter Type and nothing else.
    #[test]
    fn a_track_property_filter_is_refused_where_the_other_filters_are_carried() {
        let message = subscribe(vec![bytes_parameter(SUBGROUP_FILTER, &[0x00, 0x03, 0x02])]);
        let frame = encoded(&message);
        let decoded = ControlMessage::decode(&mut &frame[..])
            .expect("Section 5.1.3 names SUBSCRIBE for this filter");
        assert_eq!(decoded, message);

        let moved = retyped(frame, SUBGROUP_FILTER as u8, TRACK_PROPERTY_FILTER as u8);
        let err = ControlMessage::decode(&mut &moved[..])
            .expect_err("Section 5.1.3 names SUBSCRIBE_TRACKS and REQUEST_UPDATE for this one");
        assert_eq!(
            err,
            CodecError::ParameterOutOfScope {
                key: TRACK_PROPERTY_FILTER,
                message_type: u64::from(SUBSCRIBE_TYPE)
            }
        );

        let carried =
            subscribe_tracks(vec![bytes_parameter(TRACK_PROPERTY_FILTER, &[0x00, 0x03, 0x02])]);
        let frame = encoded(&carried);
        let decoded = ControlMessage::decode(&mut &frame[..])
            .expect("a SUBSCRIBE_TRACKS is where this filter belongs");
        assert_eq!(decoded, carried);
    }
}
#[cfg(feature = "draft21")]
mod draft21 {
    use moqtap_codec::draft21::message::{ControlMessage, FetchOk, Subscribe, SubscribeTracks};
    use moqtap_codec::error::CodecError;
    use moqtap_codec::kvp::KeyValuePair;
    use moqtap_codec::types::TrackNamespace;

    use super::{bytes_parameter, retyped, varint_parameter, vi, UNDEFINED_PARAMETER};

    /// EXPIRES, Section 9.20.17 — draft-19's 10.2.15, renumbered.
    const EXPIRES: u64 = 0x08;
    /// OBJECT_DELIVERY_TIMEOUT, Section 9.20.5. Named for SUBSCRIBE.
    const OBJECT_DELIVERY_TIMEOUT: u64 = 0x02;
    /// RENDEZVOUS TIMEOUT, Section 9.20.7. Named for SUBSCRIBE.
    const RENDEZVOUS_TIMEOUT: u64 = 0x04;
    /// SUBGROUP_FILTER, Section 9.20.11, scoped by Section 3.3.2 —
    /// draft-19's 5.1.3.
    const SUBGROUP_FILTER: u64 = 0x25;
    /// TRACK_PROPERTY_FILTER, Section 9.20.15, scoped by Section 3.3.2 to
    /// SUBSCRIBE_TRACKS and the REQUEST_UPDATE for one.
    const TRACK_PROPERTY_FILTER: u64 = 0x29;

    const SUBSCRIBE_TYPE: u8 = 0x03;
    const FETCH_OK_TYPE: u8 = 0x18;

    fn subscribe(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::Subscribe(Subscribe {
            request_id: vi(2),
            track_namespace: TrackNamespace(vec![b"live".to_vec()]),
            track_name: b"video".to_vec(),
            parameters,
        })
    }

    fn subscribe_tracks(parameters: Vec<KeyValuePair>) -> ControlMessage {
        ControlMessage::SubscribeTracks(SubscribeTracks {
            request_id: vi(2),
            namespace_prefix: TrackNamespace(vec![b"live".to_vec()]),
            parameters,
        })
    }

    fn encoded(message: &ControlMessage) -> Vec<u8> {
        let mut out = Vec::new();
        message.encode(&mut out).expect("the fixture is a frame this codec writes");
        out
    }

    /// Section 9.20.5 names SUBSCRIBE.
    #[test]
    fn a_parameter_named_for_the_message_it_arrives_in_is_carried() {
        let message = subscribe(vec![varint_parameter(OBJECT_DELIVERY_TIMEOUT, 5_000)]);
        let frame = encoded(&message);

        let decoded =
            ControlMessage::decode(&mut &frame[..]).expect("Section 9.20.5 names SUBSCRIBE");
        assert_eq!(decoded, message);
    }

    /// Section 9.20.16 names SUBSCRIBE_OK, PUBLISH and five response types, and
    /// SUBSCRIBE is none of them.
    #[test]
    fn an_out_of_scope_parameter_ends_the_session() {
        let carried = encoded(&subscribe(vec![varint_parameter(UNDEFINED_PARAMETER, 30)]));
        let frame = retyped(carried, UNDEFINED_PARAMETER as u8, EXPIRES as u8);

        let err = ControlMessage::decode(&mut &frame[..])
            .expect_err("EXPIRES is not named for SUBSCRIBE");
        assert_eq!(
            err,
            CodecError::ParameterOutOfScope {
                key: EXPIRES,
                message_type: u64::from(SUBSCRIBE_TYPE)
            }
        );
    }

    /// The encoder refuses the same message.
    #[test]
    fn the_encoder_refuses_what_the_decoder_refuses() {
        let mut out = Vec::new();
        let err = subscribe(vec![varint_parameter(EXPIRES, 30)])
            .encode(&mut out)
            .expect_err("EXPIRES is not named for SUBSCRIBE");
        assert_eq!(
            err,
            CodecError::ParameterOutOfScope {
                key: EXPIRES,
                message_type: u64::from(SUBSCRIBE_TYPE)
            }
        );
    }

    /// Section 9.11 gives FETCH_OK a Parameters field and no parameter
    /// definition names FETCH_OK.
    #[test]
    fn a_fetch_ok_admits_no_parameter_this_draft_defines() {
        let carried = encoded(&ControlMessage::FetchOk(FetchOk {
            end_of_track: 0,
            end_group: vi(10),
            end_object: vi(3),
            parameters: vec![varint_parameter(UNDEFINED_PARAMETER, 30)],
            track_properties: Vec::new(),
        }));
        let frame = retyped(carried, UNDEFINED_PARAMETER as u8, EXPIRES as u8);

        let err = ControlMessage::decode(&mut &frame[..])
            .expect_err("no parameter definition names FETCH_OK");
        assert_eq!(
            err,
            CodecError::ParameterOutOfScope {
                key: EXPIRES,
                message_type: u64::from(FETCH_OK_TYPE)
            }
        );
    }

    /// Section 10.19.1: "Any Parameter that can be specified on a Subscription
    /// (ie: in SUBSCRIBE) is valid in SUBSCRIBE_TRACKS, unless otherwise
    /// specified."
    ///
    /// RENDEZVOUS TIMEOUT names SUBSCRIBE and nothing else, and arrives in a
    /// SUBSCRIBE_TRACKS unrefused because of that sentence alone. Draft-18 has no
    /// such sentence and refuses the same parameter in the same message, which is
    /// what its `subscribe_tracks_does_not_inherit_a_subscribes_parameters`
    /// asserts.
    #[test]
    fn subscribe_tracks_inherits_a_subscribes_parameters() {
        let message = subscribe_tracks(vec![varint_parameter(RENDEZVOUS_TIMEOUT, 30)]);
        let frame = encoded(&message);

        let decoded = ControlMessage::decode(&mut &frame[..])
            .expect("Section 10.19.1 extends SUBSCRIBE's parameters to SUBSCRIBE_TRACKS");
        assert_eq!(decoded, message);
    }

    /// The one Range Filter a SUBSCRIBE may not carry.
    ///
    /// Section 3.4 scopes four of the five to "a FETCH, SUBSCRIBE,
    /// SUBSCRIBE_TRACKS, PUBLISH_OK, or REQUEST_UPDATE" and the Track Property
    /// filter to "a SUBSCRIBE_TRACKS message or REQUEST_UPDATE for it" — it
    /// selects tracks rather than objects, and a SUBSCRIBE has already named its
    /// track. Both are length-prefixed and neither has a value rule, so the two
    /// frames here differ in the Parameter Type and nothing else.
    #[test]
    fn a_track_property_filter_is_refused_where_the_other_filters_are_carried() {
        let message = subscribe(vec![bytes_parameter(SUBGROUP_FILTER, &[0x00, 0x03, 0x02])]);
        let frame = encoded(&message);
        let decoded = ControlMessage::decode(&mut &frame[..])
            .expect("Section 3.4 names SUBSCRIBE for this filter");
        assert_eq!(decoded, message);

        let moved = retyped(frame, SUBGROUP_FILTER as u8, TRACK_PROPERTY_FILTER as u8);
        let err = ControlMessage::decode(&mut &moved[..])
            .expect_err("Section 3.4 names SUBSCRIBE_TRACKS and REQUEST_UPDATE for this one");
        assert_eq!(
            err,
            CodecError::ParameterOutOfScope {
                key: TRACK_PROPERTY_FILTER,
                message_type: u64::from(SUBSCRIBE_TYPE)
            }
        );

        let carried =
            subscribe_tracks(vec![bytes_parameter(TRACK_PROPERTY_FILTER, &[0x00, 0x03, 0x02])]);
        let frame = encoded(&carried);
        let decoded = ControlMessage::decode(&mut &frame[..])
            .expect("a SUBSCRIBE_TRACKS is where this filter belongs");
        assert_eq!(decoded, carried);
    }
}

// ─────────────────────────────────────────────────────────────
// draft-16, the draft below the boundary
// ─────────────────────────────────────────────────────────────

#[cfg(feature = "draft16")]
mod draft16 {
    use moqtap_codec::draft16::message::{ControlMessage, Subscribe};
    use moqtap_codec::types::TrackNamespace;

    use super::{varint_parameter, vi};

    /// EXPIRES, Section 9.2.2.6: it "MAY appear in SUBSCRIBE_OK, PUBLISH or
    /// PUBLISH_OK". SUBSCRIBE is not among them, on this draft either.
    const EXPIRES: u64 = 0x08;

    /// Section 9.2.2: "Each message parameter definition indicates the message
    /// types in which it can appear. If it appears in some other type of message,
    /// it MUST be ignored."
    ///
    /// The same frame draft-17 ends a session over, on the draft immediately
    /// below it, carried in both directions. Ten drafts say this and three say
    /// the opposite, so a check that reached one draft too far would be a session
    /// closed over traffic those ten oblige an endpoint to tolerate — and this
    /// test is the only thing between the table above and that.
    ///
    /// "Ignored" and "carried" are not the same thing, and this codec does the
    /// second: the parameter reaches the caller rather than being dropped. What
    /// the draft rules out is refusing it, and refusing it is what the three
    /// newest drafts require.
    #[test]
    fn an_out_of_scope_parameter_is_carried_rather_than_refused() {
        let message = ControlMessage::Subscribe(Subscribe {
            request_id: vi(2),
            track_namespace: TrackNamespace(vec![b"live".to_vec()]),
            track_name: b"video".to_vec(),
            parameters: vec![varint_parameter(EXPIRES, 30)],
        });

        let mut frame = Vec::new();
        message.encode(&mut frame).expect("this draft names no consequence for writing one");

        let decoded = ControlMessage::decode(&mut &frame[..])
            .expect("Section 9.2.2 says to ignore an out-of-scope parameter, not to refuse it");
        assert_eq!(decoded, message);
    }
}

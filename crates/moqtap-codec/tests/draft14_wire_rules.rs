#![cfg(feature = "draft14")]
//! Draft-14 rules the shipped corpus does not pin down, on both sides of the wire.
//!
//! What these have in common is that the codec and the corpus agreed with each
//! other and both were wrong: several of these vectors were generated from this
//! codec, so a defect and its fixture matched byte for byte and the suite passed
//! *because* they matched. A rule taken from the draft rather than from a
//! recorded byte string is the only thing that separates the two.
//!
//! # A message carrying a field its draft does not define
//!
//! Sections 9.24 and 9.29 give PUBLISH_NAMESPACE_OK and SUBSCRIBE_NAMESPACE_OK
//! a Type, a Length and a Request ID, and nothing else. Both ends of a
//! namespace handshake read these, so a codec that appends a field to them
//! cannot complete a handshake with anyone but itself.
//!
//! # The declared Length is part of the message
//!
//! Draft-14 frames every control message with a 16-bit Length. A reader that
//! stops when its fields run out and ignores what is left over cannot tell a
//! peer speaking a longer dialect from a peer speaking its own.
//!
//! # Extension headers, and the two rules that pull in opposite directions
//!
//! Section 10.3.1 makes an extension block of length 0 a session-closing
//! offence on a datagram; Section 10.4.2 requires exactly that encoding on a
//! subgroup stream, where the type byte is fixed for the whole stream and an
//! object with no extensions has no other way to say so. The rules are not in
//! conflict — they are about different carriers — but a single check applied to
//! both breaks one of them, so each is gated against the other here.
//!
//! Section 10.2.1.2 adds a rule that cuts across all three carriers: an object
//! with status Object Does Not Exist may not carry extensions at all.

use moqtap_codec::draft14::data_stream::{
    DatagramObject, DatagramType, FetchObject, SubgroupHeader, SubgroupObject,
    SubgroupObjectReader, SubgroupStreamType,
};
use moqtap_codec::draft14::message::{
    ControlMessage, Fetch, FetchOk, FetchPayload, FetchType, PublishNamespaceOk, Subscribe,
    SubscribeNamespaceOk, SubscribeOk,
};
use moqtap_codec::draft14::types::ObjectStatus;
use moqtap_codec::error::CodecError;
use moqtap_codec::types::{
    ContentExists, FilterType, Forward, GroupOrder, Location, TrackNamespace,
};
use moqtap_codec::varint::VarInt;

fn hex(s: &str) -> Vec<u8> {
    hex::decode(s.replace(' ', "")).expect("test hex")
}

fn vi(v: u64) -> VarInt {
    VarInt::from_u64(v).expect("value fits a varint")
}

// ── Control messages ───────────────────────────────────────

/// The two namespace acknowledgements carry a Request ID and stop.
///
/// Figures 23 and 28 give both messages the same three fields: Type, Length,
/// Request ID, and nothing else. A codec that appends a parameter list sends
/// PUBLISH_NAMESPACE_OK for request 1 as `07 00 02 01 00` — a declared payload
/// of two bytes where the draft calls for one. A conforming peer reads the
/// Request ID, finds the message over, and has a spare byte it must treat as a
/// protocol violation.
///
/// Both directions of a namespace handshake pass through these two messages, so
/// the failure is symmetric: such a codec cannot accept a conforming peer's
/// acknowledgement either.
///
/// # What this catches, observed by making each change and running it
///
/// Restoring the parameter list on PUBLISH_NAMESPACE_OK's encoder:
///
/// ```text
/// assertion `left == right` failed: PUBLISH_NAMESPACE_OK must be Type, Length, Request ID and nothing else
///   left: [7, 0, 2, 1, 0]
///  right: [7, 0, 1, 1]
/// ```
#[test]
fn the_namespace_acknowledgements_carry_only_a_request_id() {
    let mut publish = Vec::new();
    ControlMessage::PublishNamespaceOk(PublishNamespaceOk { request_id: vi(1) })
        .encode(&mut publish)
        .expect("PUBLISH_NAMESPACE_OK encodes");
    assert_eq!(
        publish,
        hex("07 00 01 01"),
        "PUBLISH_NAMESPACE_OK must be Type, Length, Request ID and nothing else"
    );

    let mut subscribe = Vec::new();
    ControlMessage::SubscribeNamespaceOk(SubscribeNamespaceOk { request_id: vi(1) })
        .encode(&mut subscribe)
        .expect("SUBSCRIBE_NAMESPACE_OK encodes");
    assert_eq!(
        subscribe,
        hex("12 00 01 01"),
        "SUBSCRIBE_NAMESPACE_OK must be Type, Length, Request ID and nothing else"
    );

    // And each decodes back from the draft's byte string, which is the half a
    // conforming peer exercises.
    for (wire, expected) in [
        (
            hex("07 00 01 01"),
            ControlMessage::PublishNamespaceOk(PublishNamespaceOk { request_id: vi(1) }),
        ),
        (
            hex("12 00 01 01"),
            ControlMessage::SubscribeNamespaceOk(SubscribeNamespaceOk { request_id: vi(1) }),
        ),
    ] {
        let decoded = ControlMessage::decode(&mut &wire[..])
            .unwrap_or_else(|e| panic!("the draft's own bytes {wire:02x?} must decode: {e:?}"));
        assert_eq!(decoded, expected);
    }
}

/// A control message whose fields end before its declared Length does is refused.
///
/// The five-byte PUBLISH_NAMESPACE_OK is the case that matters here, because it
/// is what a peer that appends a parameter list sends. Its Length says two bytes
/// of payload; the Request ID accounts for one. Silently keeping the message
/// would let two implementations disagree about a message's shape forever
/// without either noticing.
///
/// # What this catches, observed by making each change and running it
///
/// Dropping the leftover-bytes check at the end of `ControlMessage::decode`:
///
/// ```text
/// a message with a byte left over must be refused, got Ok(PublishNamespaceOk(PublishNamespaceOk { request_id: VarInt(1) }))
/// ```
#[test]
fn a_control_message_with_bytes_left_over_is_refused() {
    for wire in [
        // A declared Length of 2 over one byte of Request ID and one byte of
        // parameter count: what a codec that appends a parameter list emits.
        hex("07 00 02 01 00"),
        hex("12 00 02 01 00"),
        // A Request ID followed by three bytes of nothing in particular.
        hex("07 00 04 01 aa bb cc"),
    ] {
        let decoded = ControlMessage::decode(&mut &wire[..]);
        assert!(
            matches!(
                decoded,
                Err(CodecError::ControlMessageLengthMismatch {
                    detail: "its fields left bytes unread",
                    ..
                })
            ),
            "a message with a byte left over must be refused, got {decoded:?}"
        );
    }

    // The same messages at their true length still decode, so the check is
    // about the leftover and not about the message.
    assert!(ControlMessage::decode(&mut &hex("07 00 01 01")[..]).is_ok());
}

/// A Full Track Name over 4,096 bytes is refused in both directions.
///
/// Section 2.4.1: "The maximum total length of a Full Track Name is 4,096
/// bytes, computed as the sum of the lengths of each Track Namespace tuple
/// field and the Track Name length field."
///
/// The two halves arrive as separate fields and each is legal alone — the
/// namespace here is 4,000 bytes and the name 97 — so nothing below the message
/// can catch this. Draft-14 states no separate cap on a Track Namespace by
/// itself, which is why the namespace decoder lets the 4,000-byte half through.
///
/// A control message may be 65,535 bytes, so the unchecked ceiling was sixteen
/// times the permitted one.
///
/// # What this catches, observed by making each change and running it
///
/// Removing the check from the decoders that read a namespace and a name
/// together — SUBSCRIBE and TRACK_STATUS share the shape, so the two go at
/// once — prints the whole 4,097-byte name back, elided here:
///
/// ```text
/// a 4097-byte Full Track Name must be refused on decode, got Ok(Subscribe(Subscribe { request_id: VarInt(1), track_namespace: TrackNamespace([[110, 110, ... ]]), track_name: [116, 116, ... ], subscriber_priority: 128, group_order: Ascending, forward: Forward, filter_type: NextGroupStart, start_location: None, end_group: None, parameters: [] }))
/// ```
///
/// Removing it from SUBSCRIBE's encoder:
///
/// ```text
/// a 4097-byte Full Track Name must be refused on encode, got Ok(())
/// ```
#[test]
fn a_full_track_name_over_the_cap_is_refused() {
    let namespace = TrackNamespace(vec![vec![b'n'; 4000]]);
    let track_name = vec![b't'; 97];
    assert_eq!(namespace.field_bytes_len() + track_name.len(), 4097);

    let message = ControlMessage::Subscribe(Subscribe {
        request_id: vi(1),
        track_namespace: namespace.clone(),
        track_name: track_name.clone(),
        subscriber_priority: 128,
        group_order: GroupOrder::Ascending,
        forward: Forward::Forward,
        filter_type: FilterType::NextGroupStart,
        start_location: None,
        end_group: None,
        parameters: vec![],
    });
    let mut refused = Vec::new();
    let encoded = message.encode(&mut refused);
    assert!(
        matches!(encoded, Err(CodecError::TrackNameTooLong)),
        "a 4097-byte Full Track Name must be refused on encode, got {encoded:?}"
    );

    // Build the same message on the wire by hand, since the encoder now refuses
    // to, and hand it to the decoder.
    let mut payload = Vec::new();
    vi(1).encode(&mut payload);
    namespace.encode(&mut payload);
    VarInt::from_usize(track_name.len()).encode(&mut payload);
    payload.extend_from_slice(&track_name);
    payload.extend_from_slice(&[128, 0x1, 0x1, 0x1]);
    VarInt::from_u64(0).unwrap().encode(&mut payload);
    let mut wire = vec![0x03];
    wire.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    wire.extend_from_slice(&payload);

    let decoded = ControlMessage::decode(&mut &wire[..]);
    assert!(
        matches!(decoded, Err(CodecError::TrackNameTooLong)),
        "a 4097-byte Full Track Name must be refused on decode, got {decoded:?}"
    );

    // One byte shorter is legal, so the gate is about the cap and not about the
    // shape of the message.
    let mut ok = Vec::new();
    ControlMessage::Subscribe(Subscribe {
        request_id: vi(1),
        track_namespace: TrackNamespace(vec![vec![b'n'; 4000]]),
        track_name: vec![b't'; 96],
        subscriber_priority: 128,
        group_order: GroupOrder::Ascending,
        forward: Forward::Forward,
        filter_type: FilterType::NextGroupStart,
        start_location: None,
        end_group: None,
        parameters: vec![],
    })
    .encode(&mut ok)
    .expect("a 4096-byte Full Track Name is legal");
}

// ── Data plane ─────────────────────────────────────────────

fn subgroup_header(stream_type: u8) -> SubgroupHeader {
    SubgroupHeader {
        stream_type: SubgroupStreamType::from_u8(stream_type).expect("assigned stream type"),
        track_alias: vi(1),
        group_id: vi(0),
        subgroup_id: None,
        publisher_priority: 128,
    }
}

/// A datagram that announces extensions must carry some; a subgroup object need not.
///
/// Section 10.3.1: "If an endpoint receives a datagram with Extensions Present
/// as 'Yes' and a Extension Headers Length of 0, it MUST close the session with
/// PROTOCOL_VIOLATION." A datagram carries its own type byte, so "no
/// extensions" already has a spelling — type 0x00 rather than 0x01 — and the
/// zero-length block is a second spelling of the same thing that the draft
/// refuses to accept.
///
/// Section 10.4.2 requires the opposite on a subgroup stream: "When Extensions
/// Present is Yes, Extension Headers Length is present in all Objects in this
/// subgroup. Objects with no extensions set Extension Headers Length to 0." The
/// type byte there belongs to the stream, not the object, so an individual
/// object has no other way to say it has none — and the draft's own worked
/// example in Section 10.5 sends exactly that on a type 0x15 stream.
///
/// Both halves are gated together because the tempting fix for one breaks the
/// other.
///
/// # What this catches, observed by making each change and running it
///
/// Removing the zero-length check from `DatagramObject::decode`:
///
/// ```text
/// a datagram announcing extensions must carry some, got Ok(DatagramObject { datagram_type: DatagramType(1), track_alias: VarInt(1), group_id: VarInt(2), object_id: VarInt(0), publisher_priority: 128, extension_headers: [], status: None, payload: [222, 173] })
/// ```
///
/// Extending that check to subgroup objects as well:
///
/// ```text
/// a subgroup object with no extensions must still be accepted: InvalidField
/// ```
#[test]
fn a_zero_length_extension_block_is_a_datagram_rule_only() {
    // 01 = extensions present, alias 1, group 2, object 0, priority 128,
    // extension block of length 0, then payload.
    let wire = hex("01 01 02 00 80 00 de ad");
    let decoded = DatagramObject::decode(&mut &wire[..]);
    assert!(
        matches!(decoded, Err(CodecError::InvalidField)),
        "a datagram announcing extensions must carry some, got {decoded:?}"
    );

    // The same datagram with one byte of extension is fine.
    let carried = hex("01 01 02 00 80 01 3c de ad");
    DatagramObject::decode(&mut &carried[..]).expect("a non-empty extension block is ordinary");

    // The encoder refuses to build the refused shape rather than emitting bytes
    // its own decoder rejects.
    let announced = DatagramObject {
        datagram_type: DatagramType::from_u8(0x01).unwrap(),
        track_alias: vi(1),
        group_id: vi(2),
        object_id: vi(0),
        publisher_priority: 128,
        extension_headers: vec![],
        status: None,
        payload: vec![0xDE, 0xAD],
    };
    let mut refused = Vec::new();
    let encoded = announced.encode_checked(&mut refused);
    assert!(
        matches!(encoded, Err(CodecError::InvalidField)),
        "encoding an empty block under an extensions type must be refused, got {encoded:?}"
    );
    assert!(refused.is_empty(), "a refused datagram still wrote {refused:02x?}");

    // A subgroup object on an extensions-present stream may declare 0, and must.
    let header = subgroup_header(0x11);
    let mut writer = SubgroupObjectReader::new(&header);
    let mut stream = Vec::new();
    writer
        .write_object(
            &SubgroupObject {
                object_id: vi(0),
                extension_headers: vec![],
                status: None,
                payload: vec![0xDE, 0xAD],
            },
            &mut stream,
        )
        .expect("a subgroup object with no extensions is ordinary");
    assert_eq!(stream, hex("00 00 02 de ad"), "the empty block is written as a length of 0");

    let mut reader = SubgroupObjectReader::new(&header);
    let object = reader.read_object(&mut &stream[..]).unwrap_or_else(|e| {
        panic!("a subgroup object with no extensions must still be accepted: {e:?}")
    });
    assert!(object.extension_headers.is_empty());
    assert_eq!(object.payload, vec![0xDE, 0xAD]);
}

/// An object that does not exist cannot carry extension headers, on any carrier.
///
/// Section 10.2.1.2: "Any Object may have extension headers except those with
/// Object Status 'Object Does Not Exist'. If an endpoint receives a non-existent
/// Object containing extension headers it MUST close the session with a
/// PROTOCOL_VIOLATION."
///
/// The rule names one status, so this checks the other two statuses keep their
/// extensions — a check that refused every status would pass a test written only
/// against the forbidden one.
///
/// All three carriers are here because all three pair a status with an extension
/// block, and the rule is about the pair rather than about the carrier.
///
/// # What this catches, observed by making each change and running it
///
/// Removing the check from `DatagramObject::decode`:
///
/// ```text
/// a non-existent object with extensions must be refused on the datagram, got Ok(DatagramObject { datagram_type: DatagramType(33), track_alias: VarInt(1), group_id: VarInt(2), object_id: VarInt(0), publisher_priority: 128, extension_headers: [60, 1], status: Some(ObjectDoesNotExist), payload: [] })
/// ```
///
/// Widening it to every non-Normal status:
///
/// ```text
/// EndOfGroup keeps its extensions: InvalidField
/// ```
#[test]
fn a_non_existent_object_cannot_carry_extensions() {
    // Datagram: type 0x21 is status-bearing with extensions present.
    let wire = hex("21 01 02 00 80 02 3c 01 01");
    let decoded = DatagramObject::decode(&mut &wire[..]);
    assert!(
        matches!(decoded, Err(CodecError::ExtensionsOnNonExistentObject(2))),
        "a non-existent object with extensions must be refused on the datagram, got {decoded:?}"
    );

    // Fetch stream: the extension block is always present, so only its contents
    // decide.
    let mut fetch = Vec::new();
    FetchObject {
        group_id: vi(0),
        subgroup_id: vi(0),
        object_id: vi(0),
        publisher_priority: 128,
        extension_headers: vec![0x3C, 0x01],
        status: Some(ObjectStatus::ObjectDoesNotExist),
        payload: vec![],
    }
    .encode(&mut fetch);
    let decoded = FetchObject::decode(&mut &fetch[..]);
    assert!(
        matches!(decoded, Err(CodecError::ExtensionsOnNonExistentObject(2))),
        "a non-existent object with extensions must be refused on the fetch stream, got {decoded:?}"
    );
    let meta = FetchObject::decode_meta(&mut &fetch[..]);
    assert!(
        matches!(meta, Err(CodecError::ExtensionsOnNonExistentObject(2))),
        "the framing-only reader must refuse it too, got {meta:?}"
    );

    // Subgroup stream, on an extensions-present type.
    let header = subgroup_header(0x11);
    let mut stream = Vec::new();
    // Written by hand: the writer now refuses to build this.
    stream.extend_from_slice(&hex("00 02 3c 01 00 01"));
    let mut reader = SubgroupObjectReader::new(&header);
    let object = reader.read_object(&mut &stream[..]);
    assert!(
        matches!(object, Err(CodecError::ExtensionsOnNonExistentObject(2))),
        "a non-existent object with extensions must be refused on the subgroup stream, got {object:?}"
    );

    // Every writer refuses to produce it in the first place.
    let mut writer = SubgroupObjectReader::new(&header);
    let mut written = Vec::new();
    let result = writer.write_object(
        &SubgroupObject {
            object_id: vi(0),
            extension_headers: vec![0x3C, 0x01],
            status: Some(ObjectStatus::ObjectDoesNotExist),
            payload: vec![],
        },
        &mut written,
    );
    assert!(
        matches!(result, Err(CodecError::ExtensionsOnNonExistentObject(2))),
        "the subgroup writer must refuse it, got {result:?}"
    );

    let result = FetchObject {
        group_id: vi(0),
        subgroup_id: vi(0),
        object_id: vi(0),
        publisher_priority: 128,
        extension_headers: vec![0x3C, 0x01],
        status: Some(ObjectStatus::ObjectDoesNotExist),
        payload: vec![],
    }
    .encode_checked(&mut Vec::new());
    assert!(
        matches!(result, Err(CodecError::ExtensionsOnNonExistentObject(2))),
        "the fetch writer must refuse it, got {result:?}"
    );

    // The statuses the rule does not name keep their extensions.
    for status in [ObjectStatus::EndOfGroup, ObjectStatus::EndOfTrack] {
        let mut writer = SubgroupObjectReader::new(&header);
        let mut buf = Vec::new();
        writer
            .write_object(
                &SubgroupObject {
                    object_id: vi(0),
                    extension_headers: vec![0x3C, 0x01],
                    status: Some(status),
                    payload: vec![],
                },
                &mut buf,
            )
            .unwrap_or_else(|e| panic!("{status:?} keeps its extensions: {e:?}"));
        let mut reader = SubgroupObjectReader::new(&header);
        let object = reader
            .read_object(&mut &buf[..])
            .unwrap_or_else(|e| panic!("{status:?} keeps its extensions: {e:?}"));
        assert_eq!(object.status, Some(status));
        assert_eq!(object.extension_headers, vec![0x3C, 0x01]);
    }
}

/// A payload beside a status is refused, not quietly dropped.
///
/// Section 10.2.1.1: "Any object with a status code other than zero MUST have an
/// empty payload." A value holding both is a caller's mistake either way, but
/// the two ways of answering it are not equally good: writing the status and
/// dropping the payload produces a well-formed object that the receiver cannot
/// tell was ever truncated, and the bytes are gone by the time anything could
/// notice.
///
/// Normal is exempt on both carriers, since it is the status a payload-bearing
/// object already has — naming it asks for the same bytes as leaving it out. A
/// Normal status with an *empty* payload keeps the explicit status form, which
/// is the only way to send a zero-length object at all.
///
/// # What this catches, observed by making each change and running it
///
/// Giving `write_object` an `if let Some(status)` branch that takes the status
/// and writes a payload length of 0:
///
/// ```text
/// a payload beside ObjectDoesNotExist must be refused, got Ok(())
/// ```
///
/// Extending the refusal to Normal as well:
///
/// ```text
/// Normal beside a payload asks for an ordinary object: InvalidField
/// ```
#[test]
fn a_payload_beside_a_status_is_refused_not_dropped() {
    let header = subgroup_header(0x10);

    for status in
        [ObjectStatus::ObjectDoesNotExist, ObjectStatus::EndOfGroup, ObjectStatus::EndOfTrack]
    {
        let mut writer = SubgroupObjectReader::new(&header);
        let mut buf = Vec::new();
        let result = writer.write_object(
            &SubgroupObject {
                object_id: vi(0),
                extension_headers: vec![],
                status: Some(status),
                payload: vec![0xDE, 0xAD],
            },
            &mut buf,
        );
        assert!(
            matches!(result, Err(CodecError::InvalidField)),
            "a payload beside {status:?} must be refused, got {result:?}"
        );
        assert!(buf.is_empty(), "a refused object still wrote {buf:02x?}");

        let result = FetchObject {
            group_id: vi(0),
            subgroup_id: vi(0),
            object_id: vi(0),
            publisher_priority: 128,
            extension_headers: vec![],
            status: Some(status),
            payload: vec![0xDE, 0xAD],
        }
        .encode_checked(&mut Vec::new());
        assert!(
            matches!(result, Err(CodecError::InvalidField)),
            "a payload beside {status:?} must be refused on the fetch stream, got {result:?}"
        );
    }

    // Normal beside a payload is an ordinary object and writes the ordinary
    // bytes.
    let mut named = Vec::new();
    SubgroupObjectReader::new(&header)
        .write_object(
            &SubgroupObject {
                object_id: vi(0),
                extension_headers: vec![],
                status: Some(ObjectStatus::Normal),
                payload: vec![0xDE, 0xAD],
            },
            &mut named,
        )
        .unwrap_or_else(|e| panic!("Normal beside a payload asks for an ordinary object: {e:?}"));
    let mut unnamed = Vec::new();
    SubgroupObjectReader::new(&header)
        .write_object(
            &SubgroupObject {
                object_id: vi(0),
                extension_headers: vec![],
                status: None,
                payload: vec![0xDE, 0xAD],
            },
            &mut unnamed,
        )
        .unwrap();
    assert_eq!(named, unnamed, "naming Normal must ask for the bytes leaving it out asks for");

    // Normal beside an empty payload keeps the status form: length 0, status 0.
    let mut zero_length = Vec::new();
    SubgroupObjectReader::new(&header)
        .write_object(
            &SubgroupObject {
                object_id: vi(0),
                extension_headers: vec![],
                status: Some(ObjectStatus::Normal),
                payload: vec![],
            },
            &mut zero_length,
        )
        .unwrap();
    assert_eq!(zero_length, hex("00 00 00"), "a zero-length Normal object states its status");
}

/// Extension headers that the stream cannot carry are refused, not dropped.
///
/// A subgroup stream's type byte fixes for every object on it whether an
/// extension block is present. An object handed to a writer on a stream with no
/// extension block has nowhere to put them, and writing the object anyway loses
/// them without a word.
///
/// # What this catches, observed by making each change and running it
///
/// Removing the check from `write_object`:
///
/// ```text
/// extensions on a stream that cannot carry them must be refused, got Ok(())
/// ```
#[test]
fn extensions_a_stream_cannot_carry_are_refused() {
    // 0x10: no extension block anywhere on this stream.
    let header = subgroup_header(0x10);
    let mut writer = SubgroupObjectReader::new(&header);
    let mut buf = Vec::new();
    let result = writer.write_object(
        &SubgroupObject {
            object_id: vi(0),
            extension_headers: vec![0x3C, 0x01],
            status: None,
            payload: vec![0xDE, 0xAD],
        },
        &mut buf,
    );
    assert!(
        matches!(result, Err(CodecError::InvalidField)),
        "extensions on a stream that cannot carry them must be refused, got {result:?}"
    );
    assert!(buf.is_empty(), "a refused object still wrote {buf:02x?}");

    // The same object on a stream whose type carries them is fine.
    let header = subgroup_header(0x11);
    SubgroupObjectReader::new(&header)
        .write_object(
            &SubgroupObject {
                object_id: vi(0),
                extension_headers: vec![0x3C, 0x01],
                status: None,
                payload: vec![0xDE, 0xAD],
            },
            &mut Vec::new(),
        )
        .expect("a stream that announces extensions carries them");
}

// ── Caps the draft states for the receiver ─────────────────

/// Frame a control message payload the way draft-14 does, without the encoder.
///
/// Needed because every shape below is one the encoder now refuses to build, so
/// the only way to hand it to the decoder is to write the bytes directly.
fn framed(type_id: u8, payload: &[u8]) -> Vec<u8> {
    let mut wire = vec![type_id];
    wire.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    wire.extend_from_slice(payload);
    wire
}

/// The Reason Phrase and New Session URI caps bind the reader, not just the writer.
///
/// Section 1.4.3: "The reason phrase length has a maximum length of 1024 bytes.
/// If an endpoint receives a length exceeding the maximum, it MUST close the
/// session with a PROTOCOL_VIOLATION". Section 9.4 says the same of the URI at
/// 8,192 bytes. Both sentences are written about what an endpoint *receives*,
/// and receiving was the direction neither was applied to: the encoders refused
/// an over-long value on nine messages, and the decoders accepted one on all of
/// them.
///
/// A control message may be 65,535 bytes, so the gap was sixty-four reason
/// phrases' worth on every error message in the protocol.
///
/// # What this catches, observed by making each change and running it
///
/// Removing the length check from `read_reason_phrase`, with the phrase elided:
///
/// ```text
/// a 1025-byte reason phrase must be refused, got Ok(SubscribeError(SubscribeError { request_id: VarInt(1), error_code: VarInt(0), reason_phrase: [110, 110, ...] }))
/// ```
///
/// Removing it from the GOAWAY decoder, with the URI elided the same way:
///
/// ```text
/// an 8193-byte New Session URI must be refused, got Ok(GoAway(GoAway { new_session_uri: [110, 110, ...] }))
/// ```
#[test]
fn the_reason_phrase_and_uri_caps_bind_the_reader() {
    // SUBSCRIBE_ERROR: Request ID, Error Code, then the Reason Phrase.
    let mut over = Vec::new();
    vi(1).encode(&mut over);
    vi(0).encode(&mut over);
    VarInt::from_usize(1025).encode(&mut over);
    over.extend(std::iter::repeat_n(b'n', 1025));
    let decoded = ControlMessage::decode(&mut &framed(0x05, &over)[..]);
    assert!(
        matches!(decoded, Err(CodecError::ReasonPhraseTooLong)),
        "a 1025-byte reason phrase must be refused, got {decoded:?}"
    );

    // One byte shorter is legal, so the gate is about the cap.
    let mut at_cap = Vec::new();
    vi(1).encode(&mut at_cap);
    vi(0).encode(&mut at_cap);
    VarInt::from_usize(1024).encode(&mut at_cap);
    at_cap.extend(std::iter::repeat_n(b'n', 1024));
    ControlMessage::decode(&mut &framed(0x05, &at_cap)[..])
        .expect("a 1024-byte reason phrase is legal");

    // GOAWAY: New Session URI Length, then the URI.
    let mut over = Vec::new();
    VarInt::from_usize(8193).encode(&mut over);
    over.extend(std::iter::repeat_n(b'n', 8193));
    let decoded = ControlMessage::decode(&mut &framed(0x10, &over)[..]);
    assert!(
        matches!(decoded, Err(CodecError::GoAwayUriTooLong)),
        "an 8193-byte New Session URI must be refused, got {decoded:?}"
    );

    let mut at_cap = Vec::new();
    VarInt::from_usize(8192).encode(&mut at_cap);
    at_cap.extend(std::iter::repeat_n(b'n', 8192));
    ControlMessage::decode(&mut &framed(0x10, &at_cap)[..])
        .expect("an 8192-byte New Session URI is legal");
}

/// A discriminator that disagrees with the fields beside it is refused.
///
/// FETCH's Fetch Type, SUBSCRIBE's Filter Type and SUBSCRIBE_OK's Content Exists
/// each say which of the following fields are on the wire. This codec keeps the
/// optional halves in `Option`s and an enum, so the two can disagree — and the
/// encoder and the decoder resolved that disagreement differently. The encoder
/// followed the body; the decoder follows the discriminator. A value that
/// disagreed with itself therefore did not survive its own round trip, and the
/// bytes that came out were a well-formed message of a different shape.
///
/// # What this catches, observed by making each change and running it
///
/// Removing the FETCH arm from the discriminator check:
///
/// ```text
/// a Standalone fetch type with a joining body must be refused, got Ok(())
/// ```
///
/// Removing the SUBSCRIBE arm:
///
/// ```text
/// a filter that takes no start location must not carry one, got Ok(())
/// ```
///
/// Removing the SUBSCRIBE_OK arm:
///
/// ```text
/// content_exists with no location must be refused, got Ok(())
/// ```
#[test]
fn a_discriminator_that_disagrees_with_its_body_is_refused() {
    let joining_body = FetchPayload::Joining { joining_request_id: vi(1), joining_start: vi(0) };
    let standalone_body = FetchPayload::Standalone {
        track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
        track_name: b"t".to_vec(),
        start_group: vi(0),
        start_object: vi(0),
        end_group: vi(1),
        end_object: vi(0),
    };

    let fetch = |fetch_type, fetch_payload| {
        ControlMessage::Fetch(Fetch {
            request_id: vi(1),
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            fetch_type,
            fetch_payload,
            parameters: vec![],
        })
    };

    let result = fetch(FetchType::Standalone, joining_body.clone()).encode(&mut Vec::new());
    assert!(
        matches!(result, Err(CodecError::InvalidField)),
        "a Standalone fetch type with a joining body must be refused, got {result:?}"
    );
    let result = fetch(FetchType::RelativeJoining, standalone_body.clone()).encode(&mut Vec::new());
    assert!(
        matches!(result, Err(CodecError::InvalidField)),
        "a joining fetch type with a standalone body must be refused, got {result:?}"
    );
    // The two agreeing combinations still encode.
    fetch(FetchType::Standalone, standalone_body).encode(&mut Vec::new()).expect("agreeing");
    fetch(FetchType::AbsoluteJoining, joining_body).encode(&mut Vec::new()).expect("agreeing");

    let subscribe = |filter_type, start_location, end_group| {
        ControlMessage::Subscribe(Subscribe {
            request_id: vi(1),
            track_namespace: TrackNamespace(vec![b"ns".to_vec()]),
            track_name: b"t".to_vec(),
            subscriber_priority: 128,
            group_order: GroupOrder::Ascending,
            forward: Forward::Forward,
            filter_type,
            start_location,
            end_group,
            parameters: vec![],
        })
    };
    let here = Location { group: vi(0), object: vi(0) };

    let result = subscribe(FilterType::NextGroupStart, Some(here), None).encode(&mut Vec::new());
    assert!(
        matches!(result, Err(CodecError::InvalidField)),
        "a filter that takes no start location must not carry one, got {result:?}"
    );
    let result = subscribe(FilterType::AbsoluteStart, None, None).encode(&mut Vec::new());
    assert!(
        matches!(result, Err(CodecError::InvalidField)),
        "a filter that requires a start location must carry one, got {result:?}"
    );
    let result = subscribe(FilterType::AbsoluteRange, Some(here), None).encode(&mut Vec::new());
    assert!(
        matches!(result, Err(CodecError::InvalidField)),
        "AbsoluteRange must carry an end group, got {result:?}"
    );
    subscribe(FilterType::AbsoluteRange, Some(here), Some(vi(4)))
        .encode(&mut Vec::new())
        .expect("agreeing");
    subscribe(FilterType::LargestObject, None, None).encode(&mut Vec::new()).expect("agreeing");

    let subscribe_ok = |content_exists, largest_location| {
        ControlMessage::SubscribeOk(SubscribeOk {
            request_id: vi(1),
            track_alias: vi(1),
            expires: vi(0),
            group_order: GroupOrder::Ascending,
            content_exists,
            largest_location,
            parameters: vec![],
        })
    };
    let result = subscribe_ok(ContentExists::HasLargestLocation, None).encode(&mut Vec::new());
    assert!(
        matches!(result, Err(CodecError::InvalidField)),
        "content_exists with no location must be refused, got {result:?}"
    );
    let result = subscribe_ok(ContentExists::NoLargestLocation, Some(here)).encode(&mut Vec::new());
    assert!(
        matches!(result, Err(CodecError::InvalidField)),
        "a location with content_exists clear must be refused, got {result:?}"
    );
    subscribe_ok(ContentExists::HasLargestLocation, Some(here))
        .encode(&mut Vec::new())
        .expect("agreeing");
    subscribe_ok(ContentExists::NoLargestLocation, None).encode(&mut Vec::new()).expect("agreeing");
}

/// Filter Type is a varint and End Of Track is a byte, as the figures write them.
///
/// Figure 12 gives SUBSCRIBE a `Filter Type (i)`; Figure 39 gives FETCH_OK an
/// `End Of Track (8)`. This codec had both the other way round. Neither showed
/// up in a round trip, because a varint of 1 through 4 and a bare byte of 1
/// through 4 are the same byte, and a flag of 0 or 1 is one byte either way.
///
/// The difference is what a *peer* may send. A varint has more than one legal
/// encoding of the same value, so `40 02` is a lawful Filter Type of 2 that a
/// byte reader sees as 0x40 — an unassigned filter — and refuses. Nothing in
/// this codec's own output would ever have produced it, which is why a round
/// trip could not find it.
///
/// # What this catches, observed by making each change and running it
///
/// Reading Filter Type as a byte again:
///
/// ```text
/// the two-byte form of filter type 2 is lawful: InvalidField
/// ```
///
/// End Of Track needs the same treatment for the same reason, but only on the
/// reading side. Writing it as a varint again changes nothing at all — a varint
/// of 1 is the byte `01`, so the encoder's output is identical and the byte
/// assertion below stays green. That is worth stating plainly: the encode half
/// of this gate documents the shape, it does not defend it. What a varint reader
/// gets wrong is a byte the draft allows the field to hold and the flag's two
/// values do not reach, so the gate feeds it `40` and watches the field boundary
/// move.
///
/// Reading End Of Track as a varint again:
///
/// ```text
/// End Of Track is one byte, so the location after it starts at 05: Kvp(VarInt(UnexpectedEnd))
/// ```
///
/// The error arrives at the parameter count rather than at End Of Track itself,
/// which is the point: every field after the mis-sized one is read from the
/// wrong offset, and the message only falls apart once it runs out of bytes.
#[test]
fn the_field_widths_match_the_figures() {
    // SUBSCRIBE with Filter Type 2 written as a two-byte varint.
    let mut payload = Vec::new();
    vi(1).encode(&mut payload);
    TrackNamespace(vec![b"ns".to_vec()]).encode(&mut payload);
    VarInt::from_usize(1).encode(&mut payload);
    payload.push(b't');
    payload.extend_from_slice(&[128, 0x1, 0x1]);
    payload.extend_from_slice(&hex("40 02")); // Filter Type 2, the long way
    VarInt::from_u64(0).unwrap().encode(&mut payload);

    let decoded = ControlMessage::decode(&mut &framed(0x03, &payload)[..])
        .unwrap_or_else(|e| panic!("the two-byte form of filter type 2 is lawful: {e:?}"));
    match decoded {
        ControlMessage::Subscribe(m) => {
            assert_eq!(m.filter_type, FilterType::LargestObject);
            assert!(m.start_location.is_none());
        }
        other => panic!("expected a SUBSCRIBE, got {other:?}"),
    }

    // FETCH_OK: Request ID, Group Order (8), End Of Track (8), End Location.
    let mut encoded = Vec::new();
    ControlMessage::FetchOk(FetchOk {
        request_id: vi(1),
        group_order: GroupOrder::Ascending,
        end_of_track: 1,
        end_location: Location { group: vi(0), object: vi(0) },
        parameters: vec![],
    })
    .encode(&mut encoded)
    .expect("FETCH_OK encodes");
    assert_eq!(
        encoded,
        hex("18 00 06 01 01 01 00 00 00"),
        "FETCH_OK writes one byte per (8) field"
    );

    // The reading side is where the width is load-bearing. `40` is a byte the
    // field can hold and a varint reader cannot stop after: it takes the `05`
    // beside it as the rest of a two-byte varint, and every field from there on
    // is read one byte late.
    let decoded = ControlMessage::decode(&mut &framed(0x18, &hex("01 01 40 05 06 00"))[..])
        .unwrap_or_else(|e| {
            panic!("End Of Track is one byte, so the location after it starts at 05: {e:?}")
        });
    match decoded {
        ControlMessage::FetchOk(m) => {
            assert_eq!(m.end_of_track, 0x40);
            assert_eq!(m.end_location.group.into_inner(), 5);
            assert_eq!(m.end_location.object.into_inner(), 6);
        }
        other => panic!("expected a FETCH_OK, got {other:?}"),
    }
}

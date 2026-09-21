//! Tests for runtime draft dispatch (version.rs + dispatch.rs).

#[allow(unused_imports)]
use moqtap_codec::dispatch::*;
#[allow(unused_imports)]
use moqtap_codec::error::CodecError;
#[allow(unused_imports)]
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

// ============================================================
// DraftVersion
// ============================================================

#[test]
fn draft_version_varint_draft07() {
    let v = DraftVersion::Draft07.version_varint();
    assert_eq!(v.into_inner(), 0xff000000 + 7);
}

#[test]
fn draft_version_varint_draft14() {
    let v = DraftVersion::Draft14.version_varint();
    assert_eq!(v.into_inner(), 0xff000000 + 14);
}

#[test]
fn draft_version_quic_alpn() {
    assert_eq!(DraftVersion::Draft07.quic_alpn(), b"moq-00");
    assert_eq!(DraftVersion::Draft14.quic_alpn(), b"moq-00");
}

#[test]
fn draft_version_copy_eq_hash() {
    use std::collections::HashSet;
    let a = DraftVersion::Draft07;
    let b = a;
    assert_eq!(a, b);
    assert_ne!(DraftVersion::Draft07, DraftVersion::Draft14);

    let mut set = HashSet::new();
    set.insert(DraftVersion::Draft07);
    set.insert(DraftVersion::Draft14);
    assert_eq!(set.len(), 2);
}

// ============================================================
// AnyControlMessage — Draft-14
// ============================================================

#[cfg(feature = "draft14")]
#[test]
fn any_control_message_draft14_round_trip() {
    use moqtap_codec::draft14::message::{ControlMessage, GoAway};

    let msg = ControlMessage::GoAway(GoAway { new_session_uri: b"https://new.example".to_vec() });

    let any = AnyControlMessage::Draft14(msg);
    assert_eq!(any.draft(), DraftVersion::Draft14);

    let mut buf = Vec::new();
    any.encode(&mut buf).unwrap();

    let mut cursor = &buf[..];
    let decoded = AnyControlMessage::decode(DraftVersion::Draft14, &mut cursor).unwrap();

    #[allow(unreachable_patterns)]
    match decoded {
        AnyControlMessage::Draft14(ControlMessage::GoAway(ga)) => {
            assert_eq!(ga.new_session_uri, b"https://new.example");
        }
        _ => panic!("expected Draft14 GoAway"),
    }
}

#[cfg(feature = "draft14")]
#[test]
fn any_control_message_draft14_max_request_id() {
    use moqtap_codec::draft14::message::{ControlMessage, MaxRequestId};

    let msg =
        ControlMessage::MaxRequestId(MaxRequestId { request_id: VarInt::from_u64(42).unwrap() });

    let any = AnyControlMessage::Draft14(msg);
    let mut buf = Vec::new();
    any.encode(&mut buf).unwrap();

    let mut cursor = &buf[..];
    let decoded = AnyControlMessage::decode(DraftVersion::Draft14, &mut cursor).unwrap();

    #[allow(unreachable_patterns)]
    match decoded {
        AnyControlMessage::Draft14(ControlMessage::MaxRequestId(m)) => {
            assert_eq!(m.request_id.into_inner(), 42);
        }
        _ => panic!("expected Draft14 MaxRequestId"),
    }
}

/// A message names itself the same way the draft-and-id table names it.
///
/// The two are separate transcriptions of the same fact —
/// `AnyControlMessage::message_type_name` reads the message's own
/// `MessageType`, `message_type_name` looks the id up — and this is what stops
/// them drifting apart.
///
/// Type 0x07 is the case that makes the pairing necessary rather than tidy: it
/// is ANNOUNCE_OK on draft-07, PUBLISH_NAMESPACE_OK on draft-14 and REQUEST_OK
/// on draft-20. An accessor answering from the id alone would have to pick one
/// of the three and be wrong about the other two.
#[cfg(all(feature = "draft07", feature = "draft14", feature = "draft20"))]
#[test]
fn a_message_names_itself_as_its_own_draft_names_the_id() {
    use moqtap_codec::message_type_name;
    use moqtap_codec::types::TrackNamespace;

    let announce_ok =
        AnyControlMessage::Draft07(moqtap_codec::draft07::message::ControlMessage::AnnounceOk(
            moqtap_codec::draft07::message::AnnounceOk {
                track_namespace: TrackNamespace(vec![b"example".to_vec()]),
            },
        ));
    let publish_namespace_ok = AnyControlMessage::Draft14(
        moqtap_codec::draft14::message::ControlMessage::PublishNamespaceOk(
            moqtap_codec::draft14::message::PublishNamespaceOk {
                request_id: VarInt::from_u64(1).unwrap(),
            },
        ),
    );
    let request_ok =
        AnyControlMessage::Draft20(moqtap_codec::draft20::message::ControlMessage::RequestOk(
            moqtap_codec::draft20::message::RequestOk {
                parameters: Vec::new(),
                track_properties: Vec::new(),
            },
        ));

    for (message, expected) in [
        (&announce_ok, "announce_ok"),
        (&publish_namespace_ok, "publish_namespace_ok"),
        (&request_ok, "request_ok"),
    ] {
        assert_eq!(message.message_type_id(), 0x07, "{expected} is type 0x07 on its draft");
        assert_eq!(message.message_type_name(), expected);
        assert_eq!(
            Some(message.message_type_name()),
            message_type_name(message.draft().number(), message.message_type_id()),
            "the accessor and the table disagree about draft-{} {:#04x}",
            message.draft().number(),
            message.message_type_id(),
        );
    }
}

// ============================================================
// AnyControlMessage — Draft-07
// ============================================================

#[cfg(feature = "draft07")]
#[test]
fn any_control_message_draft07_round_trip() {
    use moqtap_codec::draft07::message::{ControlMessage, GoAway};

    let msg = ControlMessage::GoAway(GoAway { new_session_uri: b"https://old.example".to_vec() });

    let any = AnyControlMessage::Draft07(msg);
    assert_eq!(any.draft(), DraftVersion::Draft07);

    let mut buf = Vec::new();
    any.encode(&mut buf).unwrap();

    let mut cursor = &buf[..];
    let decoded = AnyControlMessage::decode(DraftVersion::Draft07, &mut cursor).unwrap();

    #[allow(unreachable_patterns)]
    match decoded {
        AnyControlMessage::Draft07(ControlMessage::GoAway(ga)) => {
            assert_eq!(ga.new_session_uri, b"https://old.example");
        }
        _ => panic!("expected Draft07 GoAway"),
    }
}

// ============================================================
// AnySubgroupHeader
// ============================================================

#[cfg(feature = "draft14")]
#[test]
fn any_subgroup_header_draft14_round_trip() {
    use moqtap_codec::draft14::data_stream::{SubgroupHeader, SubgroupStreamType};

    // Type 0x14: SG field present + contains_end_of_group, no extensions.
    let stream_type = SubgroupStreamType::from_u8(0x14).unwrap();
    let header = SubgroupHeader {
        stream_type,
        track_alias: VarInt::from_u64(1).unwrap(),
        group_id: VarInt::from_u64(0).unwrap(),
        subgroup_id: Some(VarInt::from_u64(0).unwrap()),
        publisher_priority: 128,
    };

    let any = AnySubgroupHeader::Draft14(header);
    let mut buf = Vec::new();
    any.encode(&mut buf);

    let mut cursor = &buf[..];
    let decoded = AnySubgroupHeader::decode(DraftVersion::Draft14, &mut cursor).unwrap();

    #[allow(unreachable_patterns)]
    match decoded {
        AnySubgroupHeader::Draft14(h) => {
            assert_eq!(h.track_alias.into_inner(), 1);
            assert_eq!(h.publisher_priority, 128);
            assert_eq!(h.subgroup_id.map(|v| v.into_inner()), Some(0));
        }
        _ => panic!("expected Draft14"),
    }
}

#[cfg(feature = "draft07")]
#[test]
fn any_subgroup_header_draft07_round_trip() {
    use moqtap_codec::draft07::data_stream::SubgroupHeader;

    let header = SubgroupHeader {
        track_alias: VarInt::from_u64(5).unwrap(),
        group_id: VarInt::from_u64(10).unwrap(),
        subgroup_id: VarInt::from_u64(2).unwrap(),
        publisher_priority: 64,
    };

    let any = AnySubgroupHeader::Draft07(header);
    let mut buf = Vec::new();
    any.encode(&mut buf);

    let mut cursor = &buf[..];
    let decoded = AnySubgroupHeader::decode(DraftVersion::Draft07, &mut cursor).unwrap();

    #[allow(unreachable_patterns)]
    match decoded {
        AnySubgroupHeader::Draft07(h) => {
            assert_eq!(h.track_alias.into_inner(), 5);
            assert_eq!(h.group_id.into_inner(), 10);
        }
        _ => panic!("expected Draft07"),
    }
}

/// A subgroup header whose type no draft assigns determines no Subgroup ID.
///
/// The uniform accessor exists so a caller that did not decode a header still
/// gets a trustworthy answer out of it, and the one input it cannot vet is a
/// hand-built one: `SubgroupHeader`'s fields are `pub`, so a caller can name a
/// type value its draft leaves out. Drafts 15 and 16 both leave the fourth
/// combination of the `0x06` bits without a meaning — draft-16 reserving those
/// eight type values by name, draft-15 by omitting them from Section 10.4.2
/// Table 6, which assigns twenty-four and stops — and neither decoder accepts
/// one, which is asserted below so this stays a claim about construction and
/// not about the wire.
///
/// `None` is the answer that keeps the accessor's stated contract, that it
/// answers `None` when the header does not determine a Subgroup ID.
/// Answering `Some(0)` would hand a caller subgroup zero for a stream no draft
/// defines — and a caller believing an ID is pinned is a caller that will
/// elide the first object of it. Drafts 17-21 answer `None` for the same
/// combination, so it would also split the answer across drafts that agree on
/// the bytes.
///
/// *Ablation (measured):* drop the unassigned arm, so both drafts reach
/// `Some(0)` again:
///
/// ```text
/// assertion `left == right` failed: draft-15 determines no Subgroup ID from a type Table 6 does not assign
///   left: Some(0)
///  right: None
/// ```
///
/// *Ablation (measured, and since made unreproducible — recorded for what it
/// caught):* keep the arm but test it after `has_explicit_subgroup_id()`
/// instead of before. When this test was written draft-15 passed and draft-16
/// did not, because draft-16 read its two mode bits one at a time and so
/// answered `true` for `0x16`, where draft-15 read them together and answered
/// `false`:
///
/// ```text
/// assertion `left == right` failed: draft-16 determines no Subgroup ID from its reserved SUBGROUP_ID_MODE
///   left: Some(0)
///  right: None
/// ```
///
/// Draft-16 now reads the pair, so both orders pass and the ordering is no
/// longer load-bearing. What that ablation showed is still the reason to keep
/// this test two drafts wide: the two drafts describe one wire format in
/// different words, and a gate on either alone stops checking that they agree.
#[cfg(any(feature = "draft15", feature = "draft16"))]
#[test]
fn an_unassigned_subgroup_type_determines_no_subgroup_id() {
    // A `0x10` base with both `0x06` bits set: the combination neither draft
    // gives a row to, and the low byte of every one of the eight.
    const UNASSIGNED: u8 = 0x16;
    // Type, track alias, group ID, publisher priority. `0x16` clears `0x20`,
    // so a priority byte is present, and clears `0x04`, so no Subgroup ID
    // field follows the group ID. The decode is expected to fail on the type
    // before any of it is read.
    const WIRE: &[u8] = &[UNASSIGNED, 7, 9, 128];

    #[cfg(feature = "draft15")]
    {
        use moqtap_codec::draft15::data_stream::SubgroupHeader;
        let any = AnySubgroupHeader::Draft15(SubgroupHeader {
            header_type: UNASSIGNED,
            track_alias: VarInt::from_u64(7).unwrap(),
            group_id: VarInt::from_u64(9).unwrap(),
            subgroup_id: VarInt::from_u64(0).unwrap(),
            publisher_priority: Some(128),
        });
        assert_eq!(
            any.subgroup_id(),
            None,
            "draft-15 determines no Subgroup ID from a type Table 6 does not assign"
        );
        let mut cursor = WIRE;
        assert!(
            AnySubgroupHeader::decode(DraftVersion::Draft15, &mut cursor).is_err(),
            "draft-15 must refuse this type on the wire, or the header above is reachable \
             by decoding and this test is measuring the wrong thing"
        );
    }

    #[cfg(feature = "draft16")]
    {
        use moqtap_codec::draft16::data_stream::SubgroupHeader;
        let any = AnySubgroupHeader::Draft16(SubgroupHeader {
            header_type: UNASSIGNED,
            track_alias: VarInt::from_u64(7).unwrap(),
            group_id: VarInt::from_u64(9).unwrap(),
            subgroup_id: VarInt::from_u64(0).unwrap(),
            publisher_priority: Some(128),
        });
        assert_eq!(
            any.subgroup_id(),
            None,
            "draft-16 determines no Subgroup ID from its reserved SUBGROUP_ID_MODE"
        );
        let mut cursor = WIRE;
        assert!(
            AnySubgroupHeader::decode(DraftVersion::Draft16, &mut cursor).is_err(),
            "draft-16 must refuse this type on the wire, or the header above is reachable \
             by decoding and this test is measuring the wrong thing"
        );
    }
}

// ============================================================
// AnyDatagramHeader
// ============================================================

#[cfg(feature = "draft14")]
#[test]
fn any_datagram_header_draft14_round_trip() {
    use moqtap_codec::draft14::data_stream::{DatagramObject, DatagramType};

    // Type 0x00: payload-carrying, no extensions, object_id present, no EoG.
    let dt = DatagramType::from_u8(0x00).unwrap();
    let obj = DatagramObject {
        datagram_type: dt,
        track_alias: VarInt::from_u64(3).unwrap(),
        group_id: VarInt::from_u64(1).unwrap(),
        object_id: VarInt::from_u64(0).unwrap(),
        publisher_priority: 200,
        extension_headers: Vec::new(),
        status: None,
        payload: b"hello".to_vec(),
    };

    let any = AnyDatagramHeader::Draft14(obj);
    let mut buf = Vec::new();
    // `encode` dispatches to the draft's `encode_checked`, which refuses a
    // header whose framing cannot carry what it holds. Type 0x00 carries a
    // payload and states no status, so it has nothing to refuse, and a
    // failure here would mean the check had grown past the drafts.
    any.encode(&mut buf).expect("type 0x00 with a payload and no status is encodable");

    let mut cursor = &buf[..];
    let decoded = AnyDatagramHeader::decode(DraftVersion::Draft14, &mut cursor).unwrap();

    #[allow(unreachable_patterns)]
    match decoded {
        AnyDatagramHeader::Draft14(h) => {
            assert_eq!(h.track_alias.into_inner(), 3);
            assert_eq!(h.publisher_priority, 200);
            assert_eq!(h.payload, b"hello");
        }
        _ => panic!("expected Draft14"),
    }
}

// ============================================================
// AnyFetchHeader
// ============================================================

#[cfg(feature = "draft14")]
#[test]
fn any_fetch_header_draft14_round_trip() {
    use moqtap_codec::draft14::data_stream::FetchHeader;

    let header = FetchHeader { request_id: VarInt::from_u64(7).unwrap() };

    let any = AnyFetchHeader::Draft14(header);
    let mut buf = Vec::new();
    any.encode(&mut buf);

    let mut cursor = &buf[..];
    let decoded = AnyFetchHeader::decode(DraftVersion::Draft14, &mut cursor).unwrap();

    #[allow(unreachable_patterns)]
    match decoded {
        AnyFetchHeader::Draft14(h) => {
            assert_eq!(h.request_id.into_inner(), 7);
        }
        _ => panic!("expected Draft14"),
    }
}

#[cfg(feature = "draft07")]
#[test]
fn any_fetch_header_draft07_round_trip() {
    use moqtap_codec::draft07::data_stream::FetchHeader;

    let header = FetchHeader { subscribe_id: VarInt::from_u64(99).unwrap() };

    let any = AnyFetchHeader::Draft07(header);
    let mut buf = Vec::new();
    any.encode(&mut buf);

    let mut cursor = &buf[..];
    let decoded = AnyFetchHeader::decode(DraftVersion::Draft07, &mut cursor).unwrap();

    #[allow(unreachable_patterns)]
    match decoded {
        AnyFetchHeader::Draft07(h) => {
            assert_eq!(h.subscribe_id.into_inner(), 99);
        }
        _ => panic!("expected Draft07"),
    }
}

// ============================================================
// Draft mismatch detection
// ============================================================

#[cfg(all(feature = "draft07", feature = "draft14"))]
#[test]
fn draft14_bytes_decoded_with_draft07_produces_error_or_wrong_message() {
    use moqtap_codec::draft14::message::{ControlMessage, GoAway};

    // Encode a draft-14 GoAway
    let msg = ControlMessage::GoAway(GoAway { new_session_uri: vec![] });
    let mut buf = Vec::new();
    msg.encode(&mut buf).unwrap();

    // Try to decode as draft-07 — should fail or produce a different message
    let mut cursor = &buf[..];
    let result = AnyControlMessage::decode(DraftVersion::Draft07, &mut cursor);
    // Draft-14 GoAway type ID (0x16) is SubscribeOk in draft-07,
    // and the framing differs (draft-14 has scope field). Either way
    // the result should NOT be a valid draft-07 GoAway.
    match result {
        Err(_) => {} // expected: decode error due to framing mismatch
        Ok(AnyControlMessage::Draft07(moqtap_codec::draft07::message::ControlMessage::GoAway(
            _,
        ))) => {
            panic!("should not produce a matching GoAway from wrong draft")
        }
        Ok(_) => {} // decoded as a different message type — also acceptable
    }
}

// ============================================================
// AnySubgroupHeader — the uniform accessors
// ============================================================
//
// Every fixture below is built by hand from the draft's wire layout, not by
// the codec's own encoder, and is then read back through
// `AnySubgroupHeader::decode_stream`. Each case asserts that the decoder
// consumed exactly the bytes the fixture wrote, so the accessors are checked
// against fields the decoder really read rather than against defaults it
// invented.

/// A QUIC varint (RFC 9000 Section 16) written by hand.
#[allow(dead_code)]
fn put_varint(v: u64, out: &mut Vec<u8>) {
    if v < 1 << 6 {
        out.push(v as u8);
    } else if v < 1 << 14 {
        out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes());
    } else if v < 1 << 30 {
        out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(v | 0xC000_0000_0000_0000).to_be_bytes());
    }
}

/// One hand-built subgroup header and everything the uniform accessors owe
/// a caller for it.
#[allow(dead_code)]
struct HeaderCase {
    what: &'static str,
    wire: Vec<u8>,
    track_alias: u64,
    group_id: u64,
    publisher_priority: Option<u8>,
    subgroup_id: Option<u64>,
    subgroup_id_mode: Option<u8>,
}

/// A MoQT variable-length integer (drafts 17 and later) written by hand.
///
/// Drafts 17 and later replaced the RFC 9000 encoding with one whose length is
/// the number of leading 1 bits in the first byte plus one, so a single byte
/// carries 0 through 127 rather than 0 through 63. The two agree below 0x40 and
/// disagree above it, which is why a fixture that writes the wrong one is
/// invisible until it writes a Type of 0x40 or more — as drafts 18 and 19 do,
/// their reserved-mode list reaching 0x56, 0x76 and 0x7E.
#[allow(dead_code)]
fn put_varint_moqt(v: u64, out: &mut Vec<u8>) {
    let len = (1..=8).find(|len| v < 1u64 << (7 * len)).expect("fixture values are small");
    let prefix = (((1u16 << (len - 1)) - 1) << (9 - len)) as u8;
    let combined = ((prefix as u64) << (8 * (len - 1))) | v;
    for i in (0..len).rev() {
        out.push((combined >> (8 * i)) as u8);
    }
}

/// Write `v` in the variable-length integer encoding `version` uses.
#[allow(dead_code)]
fn put_varint_for(version: DraftVersion, v: u64, out: &mut Vec<u8>) {
    match version {
        DraftVersion::Draft17
        | DraftVersion::Draft18
        | DraftVersion::Draft19
        | DraftVersion::Draft20
        | DraftVersion::Draft21 => put_varint_moqt(v, out),
        _ => put_varint(v, out),
    }
}

/// The bytes of a header whose leading type field is `header_type`, with a
/// track alias of 7 and a group ID of 9, in `version`'s varint encoding.
///
/// `explicit_subgroup_id` is the varint the type says follows the group ID,
/// or `None` when the type carries no such field; `priority` is the trailing
/// octet, or `None` when the type suppresses it.
#[allow(dead_code)]
fn header_wire(
    version: DraftVersion,
    header_type: u8,
    explicit_subgroup_id: Option<u64>,
    priority: Option<u8>,
) -> Vec<u8> {
    let mut wire = Vec::new();
    put_varint_for(version, header_type as u64, &mut wire);
    put_varint_for(version, 7, &mut wire);
    put_varint_for(version, 9, &mut wire);
    if let Some(id) = explicit_subgroup_id {
        put_varint_for(version, id, &mut wire);
    }
    if let Some(p) = priority {
        wire.push(p);
    }
    wire
}

/// Build a header whose leading type field is `header_type`, with a track
/// alias of 7 and a group ID of 9.
///
/// `explicit_subgroup_id` and `priority` describe what the *fixture writes*;
/// the expectations are stated separately, so a case cannot be satisfied by
/// the builder and the accessor sharing a mistake.
#[allow(dead_code)]
fn header_case(
    version: DraftVersion,
    what: &'static str,
    header_type: u8,
    explicit_subgroup_id: Option<u64>,
    priority: Option<u8>,
    expect_subgroup_id: Option<u64>,
    expect_subgroup_id_mode: Option<u8>,
) -> HeaderCase {
    HeaderCase {
        what,
        wire: header_wire(version, header_type, explicit_subgroup_id, priority),
        track_alias: 7,
        group_id: 9,
        publisher_priority: priority,
        subgroup_id: expect_subgroup_id,
        subgroup_id_mode: expect_subgroup_id_mode,
    }
}

/// Decode one case and assert every accessor against it.
///
/// `unused_variables` is allowed for the zero-draft build: with no variant
/// enabled `AnySubgroupHeader` is uninhabited, so everything after the
/// `decode_stream` call is unreachable and `header` reads as unused.
#[allow(dead_code, unused_variables)]
fn check_header_case(version: DraftVersion, case: &HeaderCase) -> AnySubgroupHeader {
    let what = case.what;
    let mut cursor: &[u8] = &case.wire;
    let header = AnySubgroupHeader::decode_stream(version, &mut cursor)
        .unwrap_or_else(|e| panic!("{version:?} [{what}]: header decode failed: {e}"));
    assert!(
        cursor.is_empty(),
        "{version:?} [{what}]: the decoder left {} of {} bytes unread, so this fixture does \
         not exercise the layout it claims to",
        cursor.len(),
        case.wire.len()
    );
    assert_eq!(header.draft(), version, "{version:?} [{what}]: wrong draft");
    assert_eq!(header.track_alias(), case.track_alias, "{version:?} [{what}]: track_alias");
    assert_eq!(header.group_id(), case.group_id, "{version:?} [{what}]: group_id");
    assert_eq!(
        header.publisher_priority(),
        case.publisher_priority,
        "{version:?} [{what}]: publisher_priority"
    );
    assert_eq!(header.subgroup_id(), case.subgroup_id, "{version:?} [{what}]: subgroup_id");
    assert_eq!(
        header.subgroup_id_mode(),
        case.subgroup_id_mode,
        "{version:?} [{what}]: subgroup_id_mode"
    );
    header
}

/// Build a header of type `header_type` and require the decoder to refuse it as
/// a Type the draft lists as invalid.
///
/// The body is written in full — track alias, group ID and, unless bit 5
/// suppresses it, the priority octet — so the refusal is the type byte's
/// doing and not a truncated fixture the decoder ran off the end of. The
/// error has to be a named one rather than any error at all, for the same
/// reason: `UnexpectedEnd` would say the fixture was short.
///
/// Every caller passes a reserved-SUBGROUP_ID_MODE byte, which each of these
/// drafts lists outright and answers with a close naming PROTOCOL_VIOLATION.
/// That is a different rule from a Type no table assigns, so accepting either
/// shape here would let one stand in for the other.
#[allow(dead_code)]
fn check_header_refused(version: DraftVersion, what: &str, header_type: u8) {
    // Bit 5 is DEFAULT_PRIORITY on every draft with a mode field: set, it
    // takes the priority octet off the wire.
    let priority = (header_type & 0x20 == 0).then_some(128u8);
    let wire = header_wire(version, header_type, None, priority);
    let mut cursor: &[u8] = &wire;
    let outcome = AnySubgroupHeader::decode_stream(version, &mut cursor);
    assert!(
        matches!(outcome, Err(CodecError::InvalidStreamTypeValue { .. })),
        "{version:?} [{what}]: header type {header_type:#04x} written as {wire:02x?} must be \
         refused as a Type the draft lists as invalid, got {outcome:?}"
    );
}

/// Drafts 07-10: the subgroup ID is always an explicit varint, and the
/// stream type (0x04) precedes the header body.
///
/// *Ablation:* return `None` from `subgroup_id()` on these drafts, or read
/// `group_id` where `track_alias` belongs; must fail.
macro_rules! legacy_accessor_tests {
    ($name:ident, $feat:literal, $variant:ident) => {
        #[cfg(feature = $feat)]
        mod $name {
            use super::*;

            #[test]
            fn subgroup_header_accessors_agree_with_the_decoder() {
                let mut wire = Vec::new();
                put_varint(0x04, &mut wire);
                put_varint(7, &mut wire);
                put_varint(9, &mut wire);
                put_varint(42, &mut wire);
                wire.push(128);
                check_header_case(
                    DraftVersion::$variant,
                    &HeaderCase {
                        what: "explicit subgroup id",
                        wire,
                        track_alias: 7,
                        group_id: 9,
                        publisher_priority: Some(128),
                        subgroup_id: Some(42),
                        subgroup_id_mode: None,
                    },
                );
            }
        }
    };
}

legacy_accessor_tests!(subgroup_accessors_draft07, "draft07", Draft07);
legacy_accessor_tests!(subgroup_accessors_draft08, "draft08", Draft08);
legacy_accessor_tests!(subgroup_accessors_draft09, "draft09", Draft09);
legacy_accessor_tests!(subgroup_accessors_draft10, "draft10", Draft10);

/// Drafts 11-13: the stream type selects between an implicit zero, the
/// first object's ID, and an explicit varint. The three type bytes moved
/// between draft-11 and draft-12, so they are parameters.
///
/// *Ablation:* drop the first-object arm from `subgroup_id()` so it reports
/// the decoder's placeholder zero; must fail.
macro_rules! stream_typed_accessor_tests {
    ($name:ident, $feat:literal, $variant:ident, $zero:expr, $first:expr, $explicit:expr) => {
        #[cfg(feature = $feat)]
        mod $name {
            use super::*;

            #[test]
            fn subgroup_header_accessors_agree_with_the_decoder() {
                for case in [
                    header_case(
                        DraftVersion::$variant,
                        "implicit zero",
                        $zero,
                        None,
                        Some(128),
                        Some(0),
                        None,
                    ),
                    header_case(
                        DraftVersion::$variant,
                        "first object's id",
                        $first,
                        None,
                        Some(128),
                        None,
                        None,
                    ),
                    header_case(
                        DraftVersion::$variant,
                        "explicit",
                        $explicit,
                        Some(42),
                        Some(64),
                        Some(42),
                        None,
                    ),
                ] {
                    check_header_case(DraftVersion::$variant, &case);
                }
            }
        }
    };
}

stream_typed_accessor_tests!(subgroup_accessors_draft11, "draft11", Draft11, 0x08, 0x0A, 0x0C);
stream_typed_accessor_tests!(subgroup_accessors_draft12, "draft12", Draft12, 0x10, 0x12, 0x14);
stream_typed_accessor_tests!(subgroup_accessors_draft13, "draft13", Draft13, 0x10, 0x12, 0x14);

/// Draft-14 folds the type into the header. Bit 2 is "Subgroup ID Field
/// Present" and bit 1 says the Subgroup ID is the Object ID of the first
/// object on the stream — and bit 1 only means anything when bit 2 is
/// clear, which is the guard the uniform accessor imposes on every draft.
///
/// *Ablation:* key `subgroup_id()` off bit 1 alone, ignoring bit 2; the
/// `first object's id` case still passes, so ablate by swapping the
/// explicit and first-object arms — the `explicit` case must fail.
#[cfg(feature = "draft14")]
mod subgroup_accessors_draft14 {
    use super::*;

    #[test]
    fn subgroup_header_accessors_agree_with_the_decoder() {
        for case in [
            header_case(
                DraftVersion::Draft14,
                "implicit zero",
                0x10,
                None,
                Some(128),
                Some(0),
                None,
            ),
            header_case(
                DraftVersion::Draft14,
                "first object's id",
                0x12,
                None,
                Some(128),
                None,
                None,
            ),
            header_case(
                DraftVersion::Draft14,
                "explicit",
                0x14,
                Some(42),
                Some(64),
                Some(42),
                None,
            ),
            header_case(
                DraftVersion::Draft14,
                "explicit + end of group",
                0x1D,
                Some(42),
                Some(64),
                Some(42),
                None,
            ),
        ] {
            check_header_case(DraftVersion::Draft14, &case);
        }
    }
}

/// Draft-15 Section 10.4.2 Table 6 gives the subgroup type byte a two-bit
/// Subgroup ID mode at `0x06` and an end-of-group marker at `0x08` — the same
/// layout as draft-14 below it and draft-16 above it.
///
/// Reading `0x02` as the end-of-group marker, or draft-15 as having no
/// first-object mode, is wrong in a way subtle enough to survive a suite:
/// field presence is unaffected, so every frame still decodes to the right
/// number of bytes and only the *meaning* of two accessors changes. `0x12` is
/// first-object mode, where the ID is not on the wire and `subgroup_id()` must
/// answer `None`; `0x18` is the end-of-group type.
///
/// *Ablation:* read the end-of-group marker at `0x02`; the `first object`
/// case reports `Some(0)` where it must report `None`, and fails with:
///
/// ```text
/// assertion `left == right` failed: Draft15 [first object]: subgroup_id
///   left: Some(0)
///  right: None
/// ```
#[cfg(feature = "draft15")]
mod subgroup_accessors_draft15 {
    use super::*;

    #[test]
    fn subgroup_header_accessors_agree_with_the_decoder() {
        for case in [
            header_case(
                DraftVersion::Draft15,
                "implicit zero",
                0x10,
                None,
                Some(128),
                Some(0),
                Some(0),
            ),
            header_case(
                DraftVersion::Draft15,
                "first object",
                0x12,
                None,
                Some(128),
                None,
                Some(1),
            ),
            header_case(
                DraftVersion::Draft15,
                "explicit",
                0x14,
                Some(42),
                Some(64),
                Some(42),
                Some(2),
            ),
            header_case(
                DraftVersion::Draft15,
                "end of group, implicit zero",
                0x18,
                None,
                Some(128),
                Some(0),
                Some(0),
            ),
            header_case(
                DraftVersion::Draft15,
                "end of group, explicit",
                0x1C,
                Some(42),
                Some(64),
                Some(42),
                Some(2),
            ),
            header_case(
                DraftVersion::Draft15,
                "default priority",
                0x30,
                None,
                None,
                Some(0),
                Some(0),
            ),
            header_case(
                DraftVersion::Draft15,
                "default priority, explicit",
                0x34,
                Some(42),
                None,
                Some(42),
                Some(2),
            ),
        ] {
            check_header_case(DraftVersion::Draft15, &case);
        }
    }

    /// Table 6 assigns twenty-four types and gives the bit pair `0b11` no row
    /// at all, so `0x16`, `0x17`, `0x1E`, `0x1F`, `0x36`, `0x37`, `0x3E` and
    /// `0x3F` name no stream. Section 10 requires closing the session on a
    /// stream type the draft does not define.
    ///
    /// Accepting one was not inert, and the observed ablation shows why more
    /// clearly than the argument does. Mode `0b11` is neither explicit nor
    /// first-object, so the decoder reads no Subgroup ID field and then takes
    /// the *next* byte as the publisher priority — the byte the sender wrote as
    /// the Subgroup ID. Every field after it is off by one.
    ///
    /// *Ablation:* drop the mode check from `subgroup_type_is_assigned`, and
    /// this fails with:
    ///
    /// ```text
    /// draft-15 reserved subgroup type 0x16 was accepted: Ok(SubgroupHeader { header_type: 22, track_alias: VarInt(7), group_id: VarInt(9), subgroup_id: VarInt(0), publisher_priority: Some(42) })
    /// ```
    ///
    /// `subgroup_id` is 0 and `publisher_priority` is 42 — the 42 was written
    /// as the Subgroup ID.
    #[test]
    fn reserved_subgroup_id_mode_is_refused() {
        use moqtap_codec::draft15::data_stream::SubgroupHeader;

        for ty in [0x16u8, 0x17, 0x1E, 0x1F, 0x36, 0x37, 0x3E, 0x3F] {
            let wire =
                header_wire(DraftVersion::Draft15, ty, Some(42), (ty & 0x20 == 0).then_some(128));
            let mut cursor = &wire[..];
            let decoded = SubgroupHeader::decode(&mut cursor);
            assert!(
                decoded.is_err(),
                "draft-15 reserved subgroup type {ty:#04x} was accepted: {decoded:?}"
            );
        }
    }

    /// `subgroup_id()` answers `None` for two different headers on this draft,
    /// and `subgroup_id_mode()` is the only thing that tells them apart.
    ///
    /// Type `0x12` takes the Subgroup ID from the first object; type `0x16`
    /// sets both bits, which Table 6 gives no row. Neither header determines a
    /// Subgroup ID, so `None` is the honest answer for both — but *the first
    /// object defines the subgroup* and *this header names no stream the draft
    /// defines* are different sentences about the wire, and a caller deciding
    /// whether index 0 may be elided has to know which one it is holding.
    ///
    /// The `0x16` header is built rather than decoded, because the sweep above
    /// is the decoder refusing every byte of that shape. Building one is the
    /// only way to hold it, and a caller holding one is the case this accessor
    /// exists for.
    ///
    /// *Ablation (measured):* answer `None` from the drafts 15-16 arm of
    /// `subgroup_id_mode` — that is, put the two drafts in the arm that
    /// reports nothing:
    ///
    /// ```text
    /// assertion `left == right` failed: the first-object carrier must be distinguishable from the combination the draft assigns nothing
    ///   left: None
    ///  right: Some(1)
    /// ```
    ///
    /// Four tests fail under it, not one: the case tables above fail too, on
    /// the first mode they state. They are the wider fence and this is the
    /// sharper one — a table row says the accessor reports the mode it should,
    /// and this says the report is what separates two headers that would
    /// otherwise be one. Neither implies the other, because a case table can
    /// only name types the decoder returns, and the type this test needs is
    /// one it refuses.
    #[test]
    fn the_mode_separates_the_two_headers_that_determine_no_subgroup_id() {
        use moqtap_codec::draft15::data_stream::SubgroupHeader;

        let built = |header_type: u8| {
            AnySubgroupHeader::Draft15(SubgroupHeader {
                header_type,
                track_alias: VarInt::from_usize(7),
                group_id: VarInt::from_usize(9),
                subgroup_id: VarInt::from_usize(0),
                publisher_priority: Some(128),
            })
        };

        let first_object = built(0x12);
        let unassigned = built(0x16);

        assert_eq!(first_object.subgroup_id(), None, "the first object carries it");
        assert_eq!(unassigned.subgroup_id(), None, "no row in Table 6 carries it");

        assert_eq!(
            first_object.subgroup_id_mode(),
            Some(1),
            "the first-object carrier must be distinguishable from the combination the \
             draft assigns nothing"
        );
        assert_eq!(
            unassigned.subgroup_id_mode(),
            Some(3),
            "the unassigned combination must be distinguishable from the first-object \
             carrier"
        );
    }
}

/// Draft-16 is where a per-draft accessor and its own decoder could disagree:
/// for a header type with **both** `0x02` and `0x04` set, a decoder reading the
/// explicit varint and a `subgroup_id_from_first_object()` claiming the ID
/// comes from the first object give two answers about one set of bytes. Type
/// `0x16` is where that discrepancy would sit, and a uniform accessor that
/// follows the decoder is one fence against it.
///
/// The discrepancy is unreachable, and why is worth keeping. Those two bits
/// are not independent flags on draft-16 but a two-bit SUBGROUP_ID_MODE field,
/// and both of them set is mode `0b11`, which Section 10.4.2 reserves. It names
/// the eight type bytes that carry it — `0x16`, `0x17`, `0x1E`, `0x1F`, `0x36`,
/// `0x37`, `0x3E`, `0x3F` — and says an endpoint receiving a stream header with
/// any of them "MUST close the session with a PROTOCOL_VIOLATION". The decoder
/// refuses all eight, so no header reaches the accessors with both bits set and
/// the two have nothing left to disagree about.
///
/// So the fence sits at the refusal rather than at the accessor. The refusal
/// sweep is what keeps a both-bits header from reaching an accessor at all, and
/// the case list keeps the accessors and the decoder agreeing across the three
/// modes that remain. Dropping either half leaves the other unable to see a
/// regression in it: refusals say nothing about what a valid header reports,
/// and the case list cannot name a type the decoder will not return.
///
/// *Ablation:* drop the reserved-mode arm from `subgroup_type_is_valid`, so
/// mode `0b11` decodes again. The refusal sweep fails on the first of the
/// eight:
///
/// ```text
/// Draft16 [reserved subgroup ID mode]: header type 0x16 written as [16, 07, 09, 80] must be refused as a Type the draft lists as invalid, got Err(VarInt(UnexpectedEnd))
/// ```
///
/// The shape of that failure is the reason the arm exists. Mode `0b11` states
/// no Subgroup ID and gives no rule for deriving one, and draft-16's decoder
/// reads an explicit one when bit 2 is set — which `0x16` sets — so it takes
/// the next byte, the publisher priority, as a field the header never carried.
/// Every field after it shifts, and the header runs off the end of a fixture
/// that was complete.
#[cfg(feature = "draft16")]
mod subgroup_accessors_draft16 {
    use super::*;

    #[test]
    fn subgroup_header_accessors_agree_with_the_decoder() {
        for case in [
            header_case(
                DraftVersion::Draft16,
                "implicit zero",
                0x10,
                None,
                Some(128),
                Some(0),
                Some(0),
            ),
            header_case(
                DraftVersion::Draft16,
                "first object's id",
                0x12,
                None,
                Some(128),
                None,
                Some(1),
            ),
            header_case(
                DraftVersion::Draft16,
                "explicit",
                0x14,
                Some(42),
                Some(64),
                Some(42),
                Some(2),
            ),
            header_case(
                DraftVersion::Draft16,
                "default priority",
                0x30,
                None,
                None,
                Some(0),
                Some(0),
            ),
        ] {
            check_header_case(DraftVersion::Draft16, &case);
        }
    }

    /// Every type byte draft-16 lists under the reserved mode is refused, and
    /// the list is swept whole rather than sampled: the mode sits in bits 1-2,
    /// so it recurs under every combination of the bits around it, and a check
    /// written against one type byte can miss the rest.
    #[test]
    fn reserved_subgroup_id_mode_is_refused() {
        for header_type in [0x16u8, 0x17, 0x1E, 0x1F, 0x36, 0x37, 0x3E, 0x3F] {
            check_header_refused(DraftVersion::Draft16, "reserved subgroup ID mode", header_type);
        }
    }

    /// The same two readings of `None` draft-15 has, reached through the field
    /// draft-16 gives a name.
    ///
    /// Mode 1 takes the Subgroup ID from the first object and mode 3 is
    /// reserved; neither determines one, so `subgroup_id()` is `None` for
    /// both. The reserved header is built rather than decoded, for the reason
    /// the sweep above states: all eight of its bytes are refused.
    ///
    /// Kept beside the draft-15 case rather than folded into it, because the
    /// two drafts reach the same wire from different vocabulary — draft-16
    /// names the mode and reserves the fourth value, draft-15 names neither
    /// and omits it from a table — and a gate on either alone stops checking
    /// that they still agree.
    #[test]
    fn the_mode_separates_the_two_headers_that_determine_no_subgroup_id() {
        use moqtap_codec::draft16::data_stream::SubgroupHeader;

        let built = |header_type: u8| {
            AnySubgroupHeader::Draft16(SubgroupHeader {
                header_type,
                track_alias: VarInt::from_usize(7),
                group_id: VarInt::from_usize(9),
                subgroup_id: VarInt::from_usize(0),
                publisher_priority: Some(128),
            })
        };

        let first_object = built(0x12);
        let reserved = built(0x16);

        assert_eq!(first_object.subgroup_id(), None, "the first object carries it");
        assert_eq!(reserved.subgroup_id(), None, "a reserved mode carries nothing");

        assert_eq!(
            first_object.subgroup_id_mode(),
            Some(1),
            "the first-object mode must be distinguishable from the reserved one"
        );
        assert_eq!(
            reserved.subgroup_id_mode(),
            Some(3),
            "the reserved mode must be distinguishable from the first-object one"
        );
    }
}

/// Drafts 17-21 carry the same two-bit SUBGROUP_ID_MODE field draft-16 named,
/// taking three defined values: 0 puts no field on the wire and the ID is
/// zero, 1 takes it from the first object, and 2 carries an explicit varint
/// after the Group ID. Only mode 1 leaves the decoder without an ID, so
/// `subgroup_id()` is `None` there and `Some` for the other two.
///
/// The fourth value is reserved and no header may carry it. Each draft says
/// so in its own words and with its own list of type bytes — draft-17
/// Section 10.4.2, drafts 18 and 19 Section 11.4.2, all three under "The
/// following Type values are invalid. If an endpoint receives a stream header
/// with any of these Type values, it MUST close the session with a
/// PROTOCOL_VIOLATION". Draft-17's list has eight entries; drafts 18 and 19
/// added the FIRST_OBJECT bit (0x40) to the header form and so list sixteen.
/// The lists are the `$reserved` parameter, spelled out per draft rather than
/// recomputed from the mask, so a wrong mask cannot agree with itself.
///
/// A reserved-mode header states no Subgroup ID and gives no rule for
/// deriving one, so decoding it can only invent a value; refusing it is what
/// keeps `subgroup_id()`'s `Some(0)` meaning a zero the header stands behind.
///
/// *Ablation:* drop the reserved-mode arm of the per-draft type check, so
/// `0x16` and its fellows decode again. Run on all three drafts, this gives:
///
/// ```text
/// Draft17 [reserved subgroup ID mode]: header type 0x16 written as [16, 07, 09, 80] must be refused as a Type the draft lists as invalid, got Ok(Draft17(SubgroupHeader { header_type: 22, track_alias: VarInt(7), group_id: VarInt(9), subgroup_id: VarInt(0), publisher_priority: Some(128) }))
/// Draft18 [reserved subgroup ID mode]: header type 0x16 written as [16, 07, 09, 80] must be refused as a Type the draft lists as invalid, got Ok(Draft18(SubgroupHeader { header_type: 22, track_alias: VarInt(7), group_id: VarInt(9), subgroup_id: VarInt(0), publisher_priority: Some(128) }))
/// Draft19 [reserved subgroup ID mode]: header type 0x16 written as [16, 07, 09, 80] must be refused as a Type the draft lists as invalid, got Ok(Draft19(SubgroupHeader { header_type: 22, track_alias: VarInt(7), group_id: VarInt(9), subgroup_id: VarInt(0), publisher_priority: Some(128) }))
/// ```
///
/// The `subgroup_id: VarInt(0)` in each is the whole point: four bytes of
/// header, no Subgroup ID among them, and a zero handed up regardless — one
/// a caller cannot tell from the zero mode 0 states outright.
///
/// *Second ablation:* return `None` from `subgroup_id_mode()` on these
/// drafts — that is, leave the per-draft accessor unwritten and the
/// module-private mask unreadable; every mode case must fail.
macro_rules! modal_accessor_tests {
    ($name:ident, $feat:literal, $variant:ident, [$($reserved:expr),+ $(,)?]) => {
        #[cfg(feature = $feat)]
        mod $name {
            use super::*;

            #[test]
            fn subgroup_header_reports_the_mode_field() {
                for case in [
                    header_case(DraftVersion::$variant,"mode 0, implicit zero", 0x10, None, Some(128), Some(0), Some(0)),
                    header_case(DraftVersion::$variant,"mode 1, first object", 0x12, None, Some(128), None, Some(1)),
                    header_case(DraftVersion::$variant,"mode 2, explicit", 0x14, Some(42), Some(64), Some(42), Some(2)),
                    header_case(DraftVersion::$variant,"mode 0, default priority", 0x30, None, None, Some(0), Some(0)),
                ] {
                    check_header_case(DraftVersion::$variant, &case);
                }
            }

            /// Every type byte this draft lists under the reserved mode is
            /// refused, and the list is swept whole rather than sampled: the
            /// mode sits in bits 1-2, so it recurs under every combination of
            /// the bits around it, and a check written against one type byte
            /// can miss the rest.
            #[test]
            fn reserved_subgroup_id_mode_is_refused() {
                for header_type in [$($reserved),+] {
                    check_header_refused(
                        DraftVersion::$variant,
                        "reserved subgroup ID mode",
                        header_type,
                    );
                }
            }

            /// A subgroup ID of zero reaches a caller two ways — mode 0, where
            /// the header carries no field and the draft defines the ID as
            /// zero, and mode 2 carrying an explicit zero — and
            /// `subgroup_id()` answers `Some(0)` for both. The mode field is
            /// the only thing that tells them apart, which is the whole reason
            /// it is exposed.
            #[test]
            fn subgroup_header_accessors_agree_with_the_decoder() {
                let implicit =
                    header_case(DraftVersion::$variant,"mode 0, implicit zero", 0x10, None, Some(128), Some(0), Some(0));
                let explicit_zero =
                    header_case(DraftVersion::$variant,"mode 2, explicit zero", 0x14, Some(0), Some(64), Some(0), Some(2));
                let a = check_header_case(DraftVersion::$variant, &implicit);
                let b = check_header_case(DraftVersion::$variant, &explicit_zero);
                assert_eq!(
                    a.subgroup_id(),
                    b.subgroup_id(),
                    "both modes put the subgroup ID at zero"
                );
                assert_ne!(
                    a.subgroup_id_mode(),
                    b.subgroup_id_mode(),
                    "the mode field must tell a defined zero from a stated one"
                );
            }
        }
    };
}

modal_accessor_tests!(
    subgroup_accessors_draft17,
    "draft17",
    Draft17,
    [0x16, 0x17, 0x1E, 0x1F, 0x36, 0x37, 0x3E, 0x3F]
);
modal_accessor_tests!(
    subgroup_accessors_draft18,
    "draft18",
    Draft18,
    [
        0x16, 0x17, 0x1E, 0x1F, 0x36, 0x37, 0x3E, 0x3F, 0x56, 0x57, 0x5E, 0x5F, 0x76, 0x77, 0x7E,
        0x7F
    ]
);
modal_accessor_tests!(
    subgroup_accessors_draft19,
    "draft19",
    Draft19,
    [
        0x16, 0x17, 0x1E, 0x1F, 0x36, 0x37, 0x3E, 0x3F, 0x56, 0x57, 0x5E, 0x5F, 0x76, 0x77, 0x7E,
        0x7F
    ]
);
modal_accessor_tests!(
    subgroup_accessors_draft20,
    "draft20",
    Draft20,
    [
        0x16, 0x17, 0x1E, 0x1F, 0x36, 0x37, 0x3E, 0x3F, 0x56, 0x57, 0x5E, 0x5F, 0x76, 0x77, 0x7E,
        0x7F
    ]
);
modal_accessor_tests!(
    subgroup_accessors_draft21,
    "draft21",
    Draft21,
    [
        0x16, 0x17, 0x1E, 0x1F, 0x36, 0x37, 0x3E, 0x3F, 0x56, 0x57, 0x5E, 0x5F, 0x76, 0x77, 0x7E,
        0x7F
    ]
);

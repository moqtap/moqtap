#![cfg(all(feature = "draft17", feature = "draft18", feature = "draft19", feature = "draft20"))]
//! Rules drafts 17 through 20 state and this codec must hold itself to.
//!
//! Four rules, each pinned by what a caller can observe rather than by reading
//! a field back:
//!
//! - A datagram whose type sets the PROPERTIES bit must carry a non-empty
//!   properties block, while a subgroup object with no properties must spell
//!   that as a zero-length one. The same block, the opposite requirement, and
//!   the carrier is what decides which.
//! - Properties may not sit beside an Object Status other than Normal.
//! - A control message whose discriminator disagrees with the fields beside it
//!   encodes to bytes its own decoder reads as another message.
//! - A datagram that states an Object Status has no Object Payload, so bytes
//!   after its header are not a payload and must not reach the application as
//!   one.
//!
//! Each test's `# What this catches` block lists changes that were made to the
//! source, run, and reverted; the text under each is the failure the suite
//! actually printed.

use moqtap_codec::error::CodecError;
use moqtap_codec::varint::VarInt;

use moqtap_codec::draft17::data_stream as d17;
use moqtap_codec::draft17::message as m17;
use moqtap_codec::draft17::types::ObjectStatus as Status17;
use moqtap_codec::draft18::data_stream as d18;
use moqtap_codec::draft18::message as m18;
use moqtap_codec::draft18::types::ObjectStatus as Status18;
use moqtap_codec::draft19::data_stream as d19;
use moqtap_codec::draft19::message as m19;
use moqtap_codec::draft19::types::ObjectStatus as Status19;
use moqtap_codec::draft20::data_stream as d20;
use moqtap_codec::draft20::message as m20;
use moqtap_codec::draft20::types::ObjectStatus as Status20;

fn vi(v: u64) -> VarInt {
    VarInt::from_u64_moqt(v)
}

// ─────────────────────────────────────────────────────────────
// A datagram's PROPERTIES bit and a zero-length block
// ─────────────────────────────────────────────────────────────

/// Datagram type 0x21: PROPERTIES (0x01) and STATUS (0x20).
const DATAGRAM_PROPERTIES_AND_STATUS: u8 = 0x21;
/// Datagram type 0x01: PROPERTIES (0x01) and nothing else.
const DATAGRAM_PROPERTIES_ONLY: u8 = 0x01;
/// Subgroup header type 0x11: PROPERTIES (0x01) over the 0x10 base bit.
const SUBGROUP_WITH_PROPERTIES: u8 = 0x11;

/// A datagram may not announce properties and then carry none, and a subgroup
/// object with no properties must say so with a zero-length block.
///
/// Draft-17 Section 10.3.1, draft-18 and draft-19 Section 11.3.1, all three
/// word for word: "If an endpoint receives a datagram with the PROPERTIES bit
/// set and an Properties Length of 0, it MUST close the session with a
/// PROTOCOL_VIOLATION."
///
/// The subgroup stream says the opposite, and says it in the section next door
/// — draft-17 Section 10.4.2, drafts 18 and 19 Section 11.4.2: "Objects with no
/// properties set Properties Length to 0." There the PROPERTIES bit belongs to
/// the stream header and is fixed for every object on it, so an object with no
/// properties has nowhere but the length to say so. On a datagram the bit is
/// per-frame, so a datagram with no properties has a type byte that says so and
/// the empty block is a byte the type byte already saved.
///
/// The gate is therefore two-sided on purpose: refusing the datagram is only
/// correct if the subgroup object is still written.
///
/// # What this catches, observed by making each change and running it
///
/// Dropping the `properties_block_well_formed()` term from
/// `DatagramHeader::encode_checked` in draft-17, which is how the method
/// behaved before:
///
/// ```text
/// thread 'the_zero_length_properties_block_is_a_datagram_rule_and_not_a_subgroup_one'
/// panicked at crates\moqtap-codec\tests\late_draft_rule_coverage.rs:
/// draft-17 wrote a datagram with the PROPERTIES bit and an empty block
/// ```
///
/// Applying the datagram rule to the subgroup writer as well, by refusing a
/// zero-length block in `SubgroupObjectReader::write_object` on draft-19:
///
/// ```text
/// thread 'the_zero_length_properties_block_is_a_datagram_rule_and_not_a_subgroup_one'
/// panicked at crates\moqtap-codec\tests\late_draft_rule_coverage.rs:
/// draft-19 refused a zero-length properties block on a subgroup stream, which
/// Section 11.4.2 requires of an object with no properties: InvalidField
/// ```
#[test]
fn the_zero_length_properties_block_is_a_datagram_rule_and_not_a_subgroup_one() {
    // ── Datagrams: the block must not be empty ──
    let mut buf = Vec::new();
    let d17_header = d17::DatagramHeader {
        datagram_type: DATAGRAM_PROPERTIES_ONLY,
        track_alias: vi(1),
        group_id: vi(0),
        object_id: vi(3),
        publisher_priority: Some(0x80),
        properties: Vec::new(),
        object_status: None,
    };
    let result = d17_header.encode_checked(&mut buf);
    assert!(
        result.is_err(),
        "draft-17 wrote a datagram with the PROPERTIES bit and an empty block"
    );
    assert!(buf.is_empty(), "a refused draft-17 datagram left {buf:02x?} behind");

    let mut buf = Vec::new();
    let d18_header = d18::DatagramHeader {
        datagram_type: DATAGRAM_PROPERTIES_ONLY,
        track_alias: vi(1),
        group_id: vi(0),
        object_id: vi(3),
        publisher_priority: Some(0x80),
        properties: Vec::new(),
        object_status: None,
    };
    assert!(
        d18_header.encode_checked(&mut buf).is_err(),
        "draft-18 wrote a datagram with the PROPERTIES bit and an empty block"
    );
    assert!(buf.is_empty(), "a refused draft-18 datagram left {buf:02x?} behind");

    let mut buf = Vec::new();
    let d19_header = d19::DatagramHeader {
        datagram_type: DATAGRAM_PROPERTIES_ONLY,
        track_alias: vi(1),
        group_id: vi(0),
        object_id: vi(3),
        publisher_priority: Some(0x80),
        properties: Vec::new(),
        object_status: None,
    };
    assert!(
        d19_header.encode_checked(&mut buf).is_err(),
        "draft-19 wrote a datagram with the PROPERTIES bit and an empty block"
    );
    assert!(buf.is_empty(), "a refused draft-19 datagram left {buf:02x?} behind");

    let mut buf = Vec::new();
    let d20_header = d20::DatagramHeader {
        datagram_type: DATAGRAM_PROPERTIES_ONLY,
        track_alias: vi(1),
        group_id: vi(0),
        object_id: vi(3),
        publisher_priority: Some(0x80),
        properties: Vec::new(),
        object_status: None,
    };
    assert!(
        d20_header.encode_checked(&mut buf).is_err(),
        "draft-20 wrote a datagram with the PROPERTIES bit and an empty block"
    );
    assert!(buf.is_empty(), "a refused draft-20 datagram left {buf:02x?} behind");

    // Draft-20 goes further than its predecessors and refuses the same
    // datagram on the way *in*, at the whole-datagram read. `decode` still
    // reports rather than refuses on all four, which is what keeps a captured
    // violation readable; `decode_object` is where an endpoint accepting an
    // Object draws the line.
    let mut wire = Vec::new();
    d20::DatagramHeader { properties: vec![0x3c, 0x02], ..d20_header.clone() }
        .encode_checked(&mut wire)
        .expect("a datagram with real properties is writable");
    // Rewrite the block's length to zero, which is the frame the rule names.
    let empty_block: Vec<u8> = vec![DATAGRAM_PROPERTIES_ONLY, 0x01, 0x00, 0x03, 0x80, 0x00];
    d20::DatagramHeader::decode(&mut &empty_block[..])
        .expect("the header alone is well framed, which is why decode reports rather than refuses");
    assert!(
        d20::DatagramHeader::decode_object(&mut &empty_block[..]).is_err(),
        "draft-20's whole-datagram read must refuse a PROPERTIES bit over an empty block"
    );

    // The same datagram with a block in it is written, and parses back with the
    // block intact — the rule is about the empty block, not about properties.
    let mut buf = Vec::new();
    let filled = d19::DatagramHeader { properties: vec![0x3c, 0x02], ..d19_header };
    filled.encode_checked(&mut buf).expect("a datagram with real properties is writable");
    let back = d19::DatagramHeader::decode(&mut &buf[..]).expect("and parses back");
    assert_eq!(back.properties, vec![0x3c, 0x02], "the block did not survive the round trip");

    // ── Subgroup streams: the block must be there and may be empty ──
    let d17_stream =
        d17::SubgroupHeader::decode(&mut &[SUBGROUP_WITH_PROPERTIES, 0x01, 0x00, 0x80][..])
            .expect("a draft-17 PROPERTIES subgroup header");
    let mut out = Vec::new();
    d17::SubgroupObjectReader::new(&d17_stream)
        .write_object(
            &d17::SubgroupObject {
                object_id: vi(0),
                extension_headers: Vec::new(),
                payload_length: vi(4),
                object_status: None,
                payload: vec![0xde, 0xad, 0xbe, 0xef],
            },
            &mut out,
        )
        .unwrap_or_else(|e| {
            panic!(
                "draft-17 refused a zero-length properties block on a subgroup stream, \
                 which Section 10.4.2 requires of an object with no properties: {e:?}"
            )
        });
    // The zero-length block is on the wire: delta 0x00, length 0x00, payload
    // length 0x04, then the payload.
    assert_eq!(out, vec![0x00, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef], "unexpected subgroup bytes");

    let d19_stream =
        d19::SubgroupHeader::decode(&mut &[SUBGROUP_WITH_PROPERTIES, 0x01, 0x00, 0x80][..])
            .expect("a draft-19 PROPERTIES subgroup header");
    let mut out = Vec::new();
    d19::SubgroupObjectReader::new(&d19_stream)
        .write_object(
            &d19::SubgroupObject {
                object_id: vi(0),
                extension_headers: Vec::new(),
                payload_length: vi(4),
                object_status: None,
                payload: vec![0xde, 0xad, 0xbe, 0xef],
            },
            &mut out,
        )
        .unwrap_or_else(|e| {
            panic!(
                "draft-19 refused a zero-length properties block on a subgroup stream, \
                 which Section 11.4.2 requires of an object with no properties: {e:?}"
            )
        });
    let object = d19::SubgroupObjectReader::new(&d19_stream)
        .read_object(&mut &out[..])
        .expect("and reads it back");
    assert!(object.extension_headers.is_empty(), "the zero-length block gained bytes");
    assert_eq!(object.payload, vec![0xde, 0xad, 0xbe, 0xef], "the object lost its payload");

    // Draft-20 keeps the subgroup half of the rule exactly as draft-19 has it:
    // the datagram's opposite requirement is what makes this worth restating
    // per draft rather than deriving one carrier's answer from the other's.
    let d20_stream =
        d20::SubgroupHeader::decode(&mut &[SUBGROUP_WITH_PROPERTIES, 0x01, 0x00, 0x80][..])
            .expect("a draft-20 PROPERTIES subgroup header");
    let mut out = Vec::new();
    d20::SubgroupObjectReader::new(&d20_stream)
        .write_object(
            &d20::SubgroupObject {
                object_id: vi(0),
                extension_headers: Vec::new(),
                payload_length: vi(4),
                object_status: None,
                payload: vec![0xde, 0xad, 0xbe, 0xef],
            },
            &mut out,
        )
        .unwrap_or_else(|e| {
            panic!(
                "draft-20 refused a zero-length properties block on a subgroup stream, \
                 which Section 11.4.2 requires of an object with no properties: {e:?}"
            )
        });
    assert_eq!(out, vec![0x00, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef], "unexpected subgroup bytes");
}

// ─────────────────────────────────────────────────────────────
// Properties beside a non-Normal Object Status
// ─────────────────────────────────────────────────────────────

/// No carrier writes properties beside a status other than Normal.
///
/// Draft-17 Section 10.2.1.2, drafts 18 and 19 Section 11.2.1.2, identical in
/// all three: "Any Object with status Normal can have properties (Section 2.5).
/// If an endpoint receives properties on an Object with status that is not
/// Normal, it MUST close the session with a PROTOCOL_VIOLATION." The datagram
/// section
/// states it a second time in terms of the two type bits: "If an Object
/// Datagram includes both the STATUS bit and PROPERTIES bit, and the Object
/// Status is not Normal (0x0), the endpoint MUST close the session with a
/// PROTOCOL_VIOLATION, because only Normal Objects can have Properties."
///
/// Normal beside properties is the case that has to keep working, and it is
/// what separates this rule from "a status datagram may not carry properties":
/// a status datagram carrying the Normal code is entitled to its block.
///
/// # What this catches, observed by making each change and running it
///
/// Dropping the rule from `DatagramHeader::properties_permitted` on draft-18,
/// so that it always answers yes:
///
/// ```text
/// thread 'properties_are_not_written_beside_a_status_other_than_normal'
/// panicked at crates\moqtap-codec\tests\late_draft_rule_coverage.rs:
/// draft-18 wrote properties beside End of Track
/// ```
///
/// Answering `properties_permitted` from the framing instead of the status —
/// `self.properties.is_empty() || !self.has_status()` — on draft-19, which
/// refuses the Normal status datagram the draft permits its block:
///
/// ```text
/// thread 'properties_are_not_written_beside_a_status_other_than_normal'
/// panicked at crates\moqtap-codec\tests\late_draft_rule_coverage.rs:
/// draft-19 refused properties beside Normal, which Section 11.2.1.2 permits:
/// InvalidField
/// ```
#[test]
fn properties_are_not_written_beside_a_status_other_than_normal() {
    let properties = vec![0x3c, 0x01];

    // ── draft-17 ──
    let mut buf = Vec::new();
    let forbidden = d17::DatagramHeader {
        datagram_type: DATAGRAM_PROPERTIES_AND_STATUS,
        track_alias: vi(1),
        group_id: vi(0),
        object_id: vi(0),
        publisher_priority: Some(0x80),
        properties: properties.clone(),
        object_status: Some(Status17::EndOfGroup),
    }
    .encode_checked(&mut buf);
    assert!(forbidden.is_err(), "draft-17 wrote properties beside End of Group");
    assert!(buf.is_empty(), "a refused draft-17 datagram left {buf:02x?} behind");

    // ── draft-18 ──
    let mut buf = Vec::new();
    let forbidden = d18::DatagramHeader {
        datagram_type: DATAGRAM_PROPERTIES_AND_STATUS,
        track_alias: vi(1),
        group_id: vi(0),
        object_id: vi(0),
        publisher_priority: Some(0x80),
        properties: properties.clone(),
        object_status: Some(Status18::EndOfTrack),
    }
    .encode_checked(&mut buf);
    assert!(forbidden.is_err(), "draft-18 wrote properties beside End of Track");
    assert!(buf.is_empty(), "a refused draft-18 datagram left {buf:02x?} behind");

    // ── draft-19 ──
    let mut buf = Vec::new();
    let forbidden = d19::DatagramHeader {
        datagram_type: DATAGRAM_PROPERTIES_AND_STATUS,
        track_alias: vi(1),
        group_id: vi(0),
        object_id: vi(0),
        publisher_priority: Some(0x80),
        properties: properties.clone(),
        object_status: Some(Status19::EndOfGroup),
    }
    .encode_checked(&mut buf);
    assert!(forbidden.is_err(), "draft-19 wrote properties beside End of Group");
    assert!(buf.is_empty(), "a refused draft-19 datagram left {buf:02x?} behind");

    // ── draft-20 ──
    let mut buf = Vec::new();
    let forbidden = d20::DatagramHeader {
        datagram_type: DATAGRAM_PROPERTIES_AND_STATUS,
        track_alias: vi(1),
        group_id: vi(0),
        object_id: vi(0),
        publisher_priority: Some(0x80),
        properties: properties.clone(),
        object_status: Some(Status20::EndOfGroup),
    }
    .encode_checked(&mut buf);
    assert!(forbidden.is_err(), "draft-20 wrote properties beside End of Group");
    assert!(buf.is_empty(), "a refused draft-20 datagram left {buf:02x?} behind");

    // And on draft-20 the same shape is refused on the way in as well, at the
    // whole-datagram read: Section 11.3.1 states the rule of an endpoint that
    // *receives* one, and `decode_object` is where an endpoint accepts an
    // Object. `decode` still hands the header back on every draft.
    let mut wire = Vec::new();
    d20::DatagramHeader {
        datagram_type: DATAGRAM_PROPERTIES_AND_STATUS,
        track_alias: vi(1),
        group_id: vi(0),
        object_id: vi(0),
        publisher_priority: Some(0x80),
        properties: properties.clone(),
        object_status: Some(Status20::Normal),
    }
    .encode_checked(&mut wire)
    .expect("Normal is the status the rule exempts");
    // Flip the trailing status byte from Normal (0x0) to End of Group (0x3).
    *wire.last_mut().expect("a status byte") = 0x03;
    d20::DatagramHeader::decode(&mut &wire[..])
        .expect("the header is well framed, which is why decode reports rather than refuses");
    assert!(
        d20::DatagramHeader::decode_object(&mut &wire[..]).is_err(),
        "draft-20's whole-datagram read must refuse properties beside a non-Normal status"
    );

    // Normal is the status the rule exempts, and its datagram still goes out.
    let mut buf = Vec::new();
    d19::DatagramHeader {
        datagram_type: DATAGRAM_PROPERTIES_AND_STATUS,
        track_alias: vi(1),
        group_id: vi(0),
        object_id: vi(0),
        publisher_priority: Some(0x80),
        properties: properties.clone(),
        object_status: Some(Status19::Normal),
    }
    .encode_checked(&mut buf)
    .unwrap_or_else(|e| {
        panic!("draft-19 refused properties beside Normal, which Section 11.2.1.2 permits: {e:?}")
    });
    let back = d19::DatagramHeader::decode(&mut &buf[..]).expect("the Normal datagram parses back");
    assert_eq!(back.properties, properties, "the permitted block did not survive");

    // The subgroup carrier reports the same rule rather than refusing it: the
    // frame is well formed, so a codec that could not carry it could not
    // reproduce a capture containing one.
    let stream =
        d19::SubgroupHeader::decode(&mut &[SUBGROUP_WITH_PROPERTIES, 0x01, 0x00, 0x80][..])
            .expect("a draft-19 PROPERTIES subgroup header");
    let object = d19::SubgroupObject {
        object_id: vi(0),
        extension_headers: properties.clone(),
        payload_length: vi(0),
        object_status: Some(Status19::EndOfGroup),
        payload: Vec::new(),
    };
    assert!(
        !object.properties_permitted(),
        "properties beside End of Group must be reported as forbidden"
    );
    let mut out = Vec::new();
    d19::SubgroupObjectReader::new(&stream)
        .write_object(&object, &mut out)
        .expect("the subgroup carrier still writes the frame so a capture can be reproduced");
    let back = d19::SubgroupObjectReader::new(&stream)
        .read_object(&mut &out[..])
        .expect("and reads it back");
    assert!(!back.properties_permitted(), "the decoded object stopped reporting the violation");
}

// ─────────────────────────────────────────────────────────────
// Discriminators that disagree with the fields beside them
// ─────────────────────────────────────────────────────────────

fn namespace_17() -> moqtap_codec::types::TrackNamespace {
    moqtap_codec::types::TrackNamespace(vec![b"ns".to_vec()])
}

/// A FETCH whose Fetch Type disagrees with its body is refused before it is
/// written.
///
/// The Fetch Type says which fields follow it, and this codec holds the
/// alternatives in a `FetchPayload` enum, so a value can name Standalone and
/// carry a joining pair. The encoder writes the body and the decoder believes
/// the type, so such a message encodes to a joining request id and a joining
/// start where a Track Namespace and a Track Name belong.
///
/// **Drafts 17, 18 and 19 only, and draft-20 is why that is worth saying.**
/// Draft-20 Section 10.13 deleted the Fetch Type field, the Standalone Fetch
/// and Joining Fetch structures and the whole joining mechanism, so its FETCH
/// has one shape and nothing to disagree with itself about. Its
/// `check_discriminators` is down to the REQUEST_ERROR arm, which
/// [`a_request_error_redirect_must_match_its_error_code`] drives. A draft-20
/// row here would have nothing to construct.
///
/// # What this catches, observed by making each change and running it
///
/// Deleting the `check_discriminators(self)?` call from
/// `ControlMessage::encode` on draft-17, which is how the method behaved
/// before:
///
/// ```text
/// thread 'a_fetch_type_that_disagrees_with_its_body_is_refused'
/// panicked at crates\moqtap-codec\tests\late_draft_rule_coverage.rs:
/// draft-17 encoded a Standalone FETCH holding a joining body; it decodes as
/// Err(VarInt(UnexpectedEnd))
/// ```
///
/// The decode error is the honest half of the damage and not the whole of it:
/// the joining request id and joining start were written where a Track
/// Namespace field count and a field length belong, so what the peer refuses is
/// a truncated namespace rather than the fetch that was asked for.
///
/// Comparing the body against the wrong arm — `FetchType::RelativeJoining` in
/// place of `FetchType::Standalone` — on draft-19, which lets the mismatched
/// pair through:
///
/// ```text
/// thread 'a_fetch_type_that_disagrees_with_its_body_is_refused'
/// panicked at crates\moqtap-codec\tests\late_draft_rule_coverage.rs:
/// draft-19 encoded a Standalone FETCH holding a joining body; it decodes as
/// Err(VarInt(UnexpectedEnd))
/// ```
#[test]
fn a_fetch_type_that_disagrees_with_its_body_is_refused() {
    // draft-17: Standalone type, joining body.
    let mismatched = m17::ControlMessage::Fetch(m17::Fetch {
        request_id: vi(4),
        required_request_id_delta: vi(0),
        fetch_type: m17::FetchType::Standalone,
        fetch_payload: m17::FetchPayload::Joining {
            joining_request_id: vi(2),
            joining_start: vi(1),
        },
        parameters: Vec::new(),
    });
    let mut buf = Vec::new();
    let result = mismatched.encode(&mut buf);
    assert!(
        result.is_err(),
        "draft-17 encoded a Standalone FETCH holding a joining body; it decodes as {:?}",
        m17::ControlMessage::decode(&mut &buf[..])
    );
    assert!(buf.is_empty(), "a refused draft-17 FETCH left {buf:02x?} behind");

    // draft-18: joining type, standalone body — the mirror case.
    let mismatched = m18::ControlMessage::Fetch(m18::Fetch {
        request_id: vi(4),
        fetch_type: m18::FetchType::RelativeJoining,
        fetch_payload: m18::FetchPayload::Standalone {
            track_namespace: namespace_17(),
            track_name: b"t".to_vec(),
            start_group: vi(0),
            start_object: vi(0),
            end_group: vi(1),
            end_object: vi(0),
        },
        parameters: Vec::new(),
    });
    let mut buf = Vec::new();
    assert!(
        mismatched.encode(&mut buf).is_err(),
        "draft-18 encoded a joining FETCH holding a standalone body; it decodes as {:?}",
        m18::ControlMessage::decode(&mut &buf[..])
    );
    assert!(buf.is_empty(), "a refused draft-18 FETCH left {buf:02x?} behind");

    // draft-19: the agreeing message still goes out and comes back the same.
    let agreeing = m19::ControlMessage::Fetch(m19::Fetch {
        request_id: vi(4),
        fetch_type: m19::FetchType::AbsoluteJoining,
        fetch_payload: m19::FetchPayload::Joining {
            joining_request_id: vi(2),
            joining_start: vi(1),
        },
        parameters: Vec::new(),
    });
    let mut buf = Vec::new();
    agreeing
        .encode(&mut buf)
        .unwrap_or_else(|e| panic!("draft-19 refused a FETCH whose type and body agree: {e:?}"));
    let back = m19::ControlMessage::decode(&mut &buf[..]).expect("and it parses back");
    assert_eq!(back, agreeing, "the agreeing FETCH did not survive its round trip");

    let mismatched = m19::ControlMessage::Fetch(m19::Fetch {
        request_id: vi(4),
        fetch_type: m19::FetchType::Standalone,
        fetch_payload: m19::FetchPayload::Joining {
            joining_request_id: vi(2),
            joining_start: vi(1),
        },
        parameters: Vec::new(),
    });
    let mut buf = Vec::new();
    assert!(
        mismatched.encode(&mut buf).is_err(),
        "draft-19 encoded a Standalone FETCH holding a joining body; it decodes as {:?}",
        m19::ControlMessage::decode(&mut &buf[..])
    );
}

/// A REQUEST_ERROR whose Error Code disagrees with its Redirect body is refused
/// before it is written.
///
/// The REDIRECT code (0x34) is what puts the Redirect structure on the wire, so
/// the decoder reads one exactly when it sees that code. With the code and no
/// body the message ends where the decoder expects a Connect URI length; with a
/// body under any other code the bytes are written and then never read, and the
/// sender believes it redirected a peer that never saw a redirect.
///
/// New in draft-18 and carried into drafts 19 and 20; draft-17's REQUEST_ERROR
/// has no Redirect field at all, which is why it is absent here.
///
/// On draft-20 this is the *only* discriminator left in a control message —
/// Section 10.13 deleted FETCH's Fetch Type — so the arm this drives is the
/// whole of that draft's `check_discriminators`.
///
/// # What this catches, observed by making each change and running it
///
/// Deleting the `ControlMessage::RequestError` arm from
/// `check_discriminators` on draft-18, which is how the function looked before
/// the arm was added:
///
/// ```text
/// thread 'a_request_error_redirect_must_match_its_error_code'
/// panicked at crates\moqtap-codec\tests\late_draft_rule_coverage.rs:
/// draft-18 encoded a REDIRECT error with no Redirect body; it decodes as
/// Err(VarInt(UnexpectedEnd))
/// ```
///
/// Checking only one direction — `code_is_redirect && m.redirect.is_none()` in
/// place of the inequality — on draft-19, which lets a Redirect body through
/// under an unrelated code:
///
/// ```text
/// thread 'a_request_error_redirect_must_match_its_error_code'
/// panicked at crates\moqtap-codec\tests\late_draft_rule_coverage.rs:
/// draft-19 encoded a Redirect body under error code 0x1; it decodes as
/// Err(InvalidField)
/// ```
///
/// That second error is the message length disagreeing with the fields, not the
/// redirect being noticed: the Redirect bytes were written and the decoder,
/// told by the code that there is no Redirect to read, ran into them.
#[test]
fn a_request_error_redirect_must_match_its_error_code() {
    const REDIRECT: u64 = 0x34;

    // draft-18: the REDIRECT code with nothing to redirect to.
    let mut buf = Vec::new();
    let missing = m18::ControlMessage::RequestError(m18::RequestError {
        error_code: vi(REDIRECT),
        retry_interval: vi(0),
        reason_phrase: Vec::new(),
        redirect: None,
    });
    assert!(
        missing.encode(&mut buf).is_err(),
        "draft-18 encoded a REDIRECT error with no Redirect body; it decodes as {:?}",
        m18::ControlMessage::decode(&mut &buf[..])
    );
    assert!(buf.is_empty(), "a refused draft-18 REQUEST_ERROR left {buf:02x?} behind");

    // draft-19: a Redirect body under a code that does not carry one.
    let mut buf = Vec::new();
    let stowaway = m19::ControlMessage::RequestError(m19::RequestError {
        error_code: vi(0x1),
        retry_interval: vi(0),
        reason_phrase: Vec::new(),
        redirect: Some(m19::Redirect {
            connect_uri: b"https://example".to_vec(),
            track_namespace: namespace_17(),
            track_name: b"t".to_vec(),
        }),
    });
    assert!(
        stowaway.encode(&mut buf).is_err(),
        "draft-19 encoded a Redirect body under error code 0x1; it decodes as {:?}",
        m19::ControlMessage::decode(&mut &buf[..])
    );
    assert!(buf.is_empty(), "a refused draft-19 REQUEST_ERROR left {buf:02x?} behind");

    // draft-20: both directions, because this is the one discriminator the
    // draft still has and nothing else here exercises it.
    let mut buf = Vec::new();
    let missing = m20::ControlMessage::RequestError(m20::RequestError {
        error_code: vi(REDIRECT),
        retry_interval: vi(0),
        reason_phrase: Vec::new(),
        redirect: None,
    });
    assert!(
        missing.encode(&mut buf).is_err(),
        "draft-20 encoded a REDIRECT error with no Redirect body; it decodes as {:?}",
        m20::ControlMessage::decode(&mut &buf[..])
    );
    assert!(buf.is_empty(), "a refused draft-20 REQUEST_ERROR left {buf:02x?} behind");

    let mut buf = Vec::new();
    let stowaway = m20::ControlMessage::RequestError(m20::RequestError {
        error_code: vi(0x1),
        retry_interval: vi(0),
        reason_phrase: Vec::new(),
        redirect: Some(m20::Redirect {
            connect_uri: b"https://example".to_vec(),
            track_namespace: namespace_17(),
            track_name: b"t".to_vec(),
        }),
    });
    assert!(
        stowaway.encode(&mut buf).is_err(),
        "draft-20 encoded a Redirect body under error code 0x1; it decodes as {:?}",
        m20::ControlMessage::decode(&mut &buf[..])
    );
    assert!(buf.is_empty(), "a refused draft-20 REQUEST_ERROR left {buf:02x?} behind");

    // Draft-20 also changed what an empty Redirect target means, without
    // changing a byte: draft-19 read an empty Track Namespace and Track Name
    // as "reuse the original request's", and draft-20 deleted that sentence so
    // the pair is the literal target. Nothing in a codec can act on the
    // difference — the frame is identical — so this only records that the
    // empty pair still encodes and reads back as itself.
    let mut buf = Vec::new();
    let empty_target = m20::ControlMessage::RequestError(m20::RequestError {
        error_code: vi(REDIRECT),
        retry_interval: vi(0),
        reason_phrase: Vec::new(),
        redirect: Some(m20::Redirect {
            connect_uri: b"https://example".to_vec(),
            track_namespace: moqtap_codec::types::TrackNamespace(Vec::new()),
            track_name: Vec::new(),
        }),
    });
    empty_target
        .encode(&mut buf)
        .expect("an empty Redirect target is a literal target, not a malformation");
    assert_eq!(
        m20::ControlMessage::decode(&mut &buf[..]).expect("and it parses back"),
        empty_target
    );

    // The matching pair still round-trips, in both spellings.
    for message in [
        m19::ControlMessage::RequestError(m19::RequestError {
            error_code: vi(REDIRECT),
            retry_interval: vi(0),
            reason_phrase: Vec::new(),
            redirect: Some(m19::Redirect {
                connect_uri: b"https://example".to_vec(),
                track_namespace: namespace_17(),
                track_name: b"t".to_vec(),
            }),
        }),
        m19::ControlMessage::RequestError(m19::RequestError {
            error_code: vi(0x1),
            retry_interval: vi(0),
            reason_phrase: b"nope".to_vec(),
            redirect: None,
        }),
    ] {
        let mut buf = Vec::new();
        message
            .encode(&mut buf)
            .unwrap_or_else(|e| panic!("a matching REQUEST_ERROR was refused: {e:?}"));
        let back = m19::ControlMessage::decode(&mut &buf[..]).expect("and it parses back");
        assert_eq!(back, message, "a matching REQUEST_ERROR did not survive its round trip");
    }
}

// ─────────────────────────────────────────────────────────────
// A status datagram has no Object Payload
// ─────────────────────────────────────────────────────────────

/// Bytes after a status datagram's header never reach the application as a
/// payload, whichever status the datagram states.
///
/// Draft-17 Section 10.3.1 and drafts 18 and 19 Section 11.3.1: "The STATUS bit
/// (0x20) indicates whether the datagram contains an Object Status or Object
/// Payload. When set to 1, the Object Status field is present and there is no
/// Object Payload." There is no payload field at all in such a datagram, so
/// trailing bytes are not a short payload or an odd one — they are bytes the
/// frame does not define.
///
/// The Normal code is the case that matters and the one that reads wrongly if
/// the question is put to the status alone: Normal is the one status that
/// permits an Object a payload, so a status datagram carrying it looks
/// payload-bearing to anything that consults the status and not the framing.
/// A datagram's payload runs to the end of the transport datagram, so those
/// bytes are exactly what a caller would hand on as content.
///
/// # What this catches, observed by making each change and running it
///
/// Answering `DatagramHeader::permits_payload` from the status alone on
/// draft-19 — `self.status().permits_payload()` without the `has_status()`
/// guard, which is how the method behaved before:
///
/// ```text
/// thread 'a_status_datagram_never_yields_a_payload'
/// panicked at crates\moqtap-codec\tests\late_draft_rule_coverage.rs:
/// draft-19 permitted a payload on a status datagram carrying status 0x00
/// ```
///
/// Dropping the trailing-bytes refusal from `DatagramHeader::decode_object` on
/// draft-17, leaving the header decode to stand for the whole datagram:
///
/// ```text
/// thread 'a_status_datagram_never_yields_a_payload'
/// panicked at crates\moqtap-codec\tests\late_draft_rule_coverage.rs:
/// draft-17 accepted 4 trailing byte(s) on a status 0x00 datagram and handed
/// them back as [de, ad, be, ef]
/// ```
#[test]
fn a_status_datagram_never_yields_a_payload() {
    // Type 0x28: STATUS (0x20) and DEFAULT_PRIORITY (0x08), so the datagram is
    // a type byte, a track alias, a group id, an object id and a status byte.
    const STATUS_DATAGRAM: u8 = 0x28;
    let trailing = [0xde, 0xad, 0xbe, 0xefu8];

    for status in [0x00u8, 0x03, 0x04] {
        let mut whole = vec![STATUS_DATAGRAM, 0x01, 0x00, 0x03, status];
        whole.extend_from_slice(&trailing);

        let header = d17::DatagramHeader::decode(&mut &whole[..]).expect("the header parses");
        assert!(
            !header.permits_payload(),
            "draft-17 permitted a payload on a status datagram carrying status {status:#04x}"
        );
        match d17::DatagramHeader::decode_object(&mut &whole[..]) {
            Err(CodecError::PayloadNotPermitted { .. }) => {}
            Ok((_, payload)) => panic!(
                "draft-17 accepted {} trailing byte(s) on a status {status:#04x} datagram \
                 and handed them back as {payload:02x?}",
                payload.len()
            ),
            Err(other) => panic!("draft-17 refused the trailing bytes with {other:?}"),
        }

        let header = d18::DatagramHeader::decode(&mut &whole[..]).expect("the header parses");
        assert!(
            !header.permits_payload(),
            "draft-18 permitted a payload on a status datagram carrying status {status:#04x}"
        );
        assert!(
            matches!(
                d18::DatagramHeader::decode_object(&mut &whole[..]),
                Err(CodecError::PayloadNotPermitted { .. })
            ),
            "draft-18 accepted trailing bytes on a status {status:#04x} datagram"
        );

        let header = d19::DatagramHeader::decode(&mut &whole[..]).expect("the header parses");
        assert!(
            !header.permits_payload(),
            "draft-19 permitted a payload on a status datagram carrying status {status:#04x}"
        );
        assert!(
            matches!(
                d19::DatagramHeader::decode_object(&mut &whole[..]),
                Err(CodecError::PayloadNotPermitted { .. })
            ),
            "draft-19 accepted trailing bytes on a status {status:#04x} datagram"
        );

        let header = d20::DatagramHeader::decode(&mut &whole[..]).expect("the header parses");
        assert!(
            !header.permits_payload(),
            "draft-20 permitted a payload on a status datagram carrying status {status:#04x}"
        );
        assert!(
            matches!(
                d20::DatagramHeader::decode_object(&mut &whole[..]),
                Err(CodecError::PayloadNotPermitted { .. })
            ),
            "draft-20 accepted trailing bytes on a status {status:#04x} datagram"
        );
    }

    // The Normal code is the one a status-only reading gets wrong, so it is
    // named on its own as well as swept above.
    let mut normal = vec![STATUS_DATAGRAM, 0x01, 0x00, 0x03, 0x00];
    normal.extend_from_slice(&trailing);
    let header = d19::DatagramHeader::decode(&mut &normal[..]).expect("the header parses");
    assert_eq!(header.status(), Status19::Normal, "the datagram lost its status");
    assert!(
        header.status().permits_payload(),
        "Normal is the registry row that permits an Object a payload; \
         the framing is what forbids this one"
    );
    assert!(!header.permits_payload(), "draft-19 permitted a payload on a Normal status datagram");

    // A datagram without the STATUS bit is all payload, and keeps it. Type
    // 0x08: DEFAULT_PRIORITY only.
    let mut plain = vec![0x08u8, 0x01, 0x00, 0x03];
    plain.extend_from_slice(&trailing);
    let (header, payload) =
        d19::DatagramHeader::decode_object(&mut &plain[..]).expect("a payload datagram decodes");
    assert!(header.permits_payload(), "a payload datagram must be permitted its payload");
    assert_eq!(payload, trailing, "the payload datagram lost its payload");
}

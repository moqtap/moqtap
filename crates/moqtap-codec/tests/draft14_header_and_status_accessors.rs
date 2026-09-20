//! Two entry points draft-14 must offer, and what a caller gets wrong without them.
//!
//! # The header that could disagree with its own type byte
//!
//! Draft-14 gives SUBGROUP_HEADER a type table with a Subgroup ID Field Present
//! column (Section 10.4.2) and models the field as an `Option`. The encoder
//! follows the type byte, so an `Option` that disagrees with it is not written
//! as the caller built it: a `None` under a type that carries the field goes out
//! as zero, which names subgroup 0 rather than no subgroup, and a `Some` under a
//! type that does not carry it is dropped. Both produce a well-formed stream
//! describing something else.
//!
//! Every draft from 15 on refuses that shape at an `encode_checked`. Draft-14
//! has the same shape, so it refuses it at the same entry point: without
//! `SubgroupHeader::encode_checked` its header is the one a caller can get
//! silently wrong.
//!
//! # The object that could not say whether it may carry a payload
//!
//! Section 10.2.1.1: "Any object with a status code other than zero MUST have an
//! empty payload." Drafts 15 through 19 answer that question on the object and
//! on its meta, so a relay forwarding an object verbatim can ask without
//! restating the rule. Draft-14's `SubgroupObject`, `SubgroupObjectMeta`,
//! `FetchObject` and `FetchObjectMeta` answer it as well, so no caller holding
//! one has to re-derive that non-zero means forbidden — which is the step
//! that goes wrong on a code the draft does not assign, where the answer is that
//! there is no rule rather than that the payload is forbidden.

#![cfg(feature = "draft14")]

use moqtap_codec::draft14::data_stream::{
    FetchObject, FetchObjectMeta, PayloadPermission, SubgroupHeader, SubgroupObject,
    SubgroupObjectMeta, SubgroupStreamType,
};
use moqtap_codec::draft14::types::ObjectStatus;
use moqtap_codec::error::CodecError;
use moqtap_codec::varint::VarInt;

fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).expect("fixture value fits a varint")
}

/// A subgroup stream type that carries an explicit Subgroup ID field, and one
/// that does not.
fn types() -> (SubgroupStreamType, SubgroupStreamType) {
    let explicit = SubgroupStreamType::from_flags(true, false, false, false);
    let implicit = SubgroupStreamType::from_flags(false, false, false, false);
    assert!(explicit.has_subgroup_id_field(), "fixture: this type must carry the field");
    assert!(!implicit.has_subgroup_id_field(), "fixture: this type must not carry the field");
    (explicit, implicit)
}

fn header(stream_type: SubgroupStreamType, subgroup_id: Option<VarInt>) -> SubgroupHeader {
    SubgroupHeader {
        stream_type,
        track_alias: varint(1),
        group_id: varint(2),
        subgroup_id,
        publisher_priority: 128,
    }
}

/// A missing Subgroup ID under a type that carries the field is refused, not
/// filled in.
///
/// The substitution is what makes this worth refusing rather than tolerating.
/// Zero is a legal Subgroup ID, so a header written this way is not malformed
/// and the peer has no way to notice: it reads a perfectly good stream for
/// subgroup 0.
///
/// Ablation: dropping the check from `SubgroupHeader::encode_checked` fails with
///
/// ```text
/// a header with no Subgroup ID under a type that carries the field must be
/// refused rather than written as subgroup 0; it wrote [14, 01, 02, 00, 80]
/// ```
#[test]
fn a_missing_subgroup_id_is_not_written_as_zero() {
    let (explicit, _) = types();
    let mut wrote = Vec::new();
    let result = header(explicit, None).encode_checked(&mut wrote);
    assert!(
        matches!(result, Err(CodecError::InvalidField)),
        "a header with no Subgroup ID under a type that carries the field must be \
         refused rather than written as subgroup 0; it wrote {wrote:02x?}"
    );

    // What it would have written, and why nothing downstream could tell.
    let mut anyway = Vec::new();
    header(explicit, None).encode(&mut anyway);
    let decoded = SubgroupHeader::decode(&mut &anyway[..])
        .expect("the substituted header is well formed, which is the problem");
    assert_eq!(
        decoded.subgroup_id.map(|id| id.into_inner()),
        Some(0),
        "the peer reads a stream for subgroup 0 and has no way to know it was not asked for"
    );
}

/// A Subgroup ID under a type that has no field for it is refused, not dropped.
///
/// The other direction, and the one that loses information outright rather than
/// substituting for it.
///
/// Ablation: the same removal fails here with
///
/// ```text
/// a Subgroup ID this type has nowhere to put must be refused rather than
/// dropped; it wrote [10, 01, 02, 80]
/// ```
#[test]
fn a_subgroup_id_the_type_cannot_carry_is_not_dropped() {
    let (_, implicit) = types();
    let mut wrote = Vec::new();
    let result = header(implicit, Some(varint(7))).encode_checked(&mut wrote);
    assert!(
        matches!(result, Err(CodecError::InvalidField)),
        "a Subgroup ID this type has nowhere to put must be refused rather than \
         dropped; it wrote {wrote:02x?}"
    );
}

/// The two shapes that agree are written, including a Subgroup ID of zero.
///
/// Zero is a legal Subgroup ID, so the check has to be about presence and not
/// about the value. A check that refused `Some(0)` would refuse the first
/// subgroup of every group.
#[test]
fn a_header_that_agrees_with_its_type_is_written() {
    let (explicit, implicit) = types();
    for (label, built) in [
        ("an explicit zero", header(explicit, Some(varint(0)))),
        ("an explicit id", header(explicit, Some(varint(7)))),
        ("no id, on a type with no field", header(implicit, None)),
    ] {
        let mut wire = Vec::new();
        built
            .encode_checked(&mut wire)
            .unwrap_or_else(|e| panic!("{label} must be written: {e:?}"));
        let back = SubgroupHeader::decode(&mut &wire[..])
            .unwrap_or_else(|e| panic!("{label} must survive its own reader: {e:?}"));
        assert_eq!(back, built, "{label} did not come back as it went out");
    }
}

/// The decoder never produces a header the checked encoder would refuse.
///
/// This is what makes the check a caller-error check rather than a wire rule: it
/// fires only on a value assembled by hand. Every assigned subgroup type is
/// walked, so a type added to the table has to keep the property.
#[test]
fn no_decoded_header_is_one_the_checked_encoder_refuses() {
    let mut seen = 0;
    for raw in 0x00u8..=0xFFu8 {
        let Some(stream_type) = SubgroupStreamType::from_u8(raw) else { continue };
        seen += 1;
        let built = header(stream_type, stream_type.has_subgroup_id_field().then(|| varint(3)));
        let mut wire = Vec::new();
        built.encode(&mut wire);
        let decoded = SubgroupHeader::decode(&mut &wire[..])
            .unwrap_or_else(|e| panic!("type {raw:#04x} did not survive encode/decode: {e:?}"));
        decoded.encode_checked(&mut Vec::new()).unwrap_or_else(|e| {
            panic!("type {raw:#04x}: the decoder produced a header its own checked encoder refuses: {e:?}")
        });
    }
    assert_eq!(seen, 12, "draft-14 assigns twelve subgroup stream types; the table found {seen}");
}

// ── Payload permission ──────────────────────────────────────

/// Every assigned status answers, and Normal is the only one that permits.
///
/// Read off the statuses rather than off the numbers: a test written as
/// zero-permits-non-zero-forbids would restate the very inference the accessor
/// exists to stop callers making.
#[test]
fn only_normal_permits_a_payload() {
    for (status, permits) in [
        (ObjectStatus::Normal, true),
        (ObjectStatus::ObjectDoesNotExist, false),
        (ObjectStatus::EndOfGroup, false),
        (ObjectStatus::EndOfTrack, false),
    ] {
        assert_eq!(
            PayloadPermission::for_status(status).permits(),
            permits,
            "{status:?} answered the wrong way"
        );
    }
}

/// An object and its meta give the same answer, from different evidence.
///
/// The object has its bytes; the meta has a declared length and a raw wire code
/// and never sees the payload. A relay reads the second and must not have to
/// reconstruct the first to ask.
#[test]
fn the_object_and_its_meta_agree() {
    for status in [
        ObjectStatus::Normal,
        ObjectStatus::ObjectDoesNotExist,
        ObjectStatus::EndOfGroup,
        ObjectStatus::EndOfTrack,
    ] {
        let object = SubgroupObject {
            object_id: varint(0),
            extension_headers: Vec::new(),
            status: Some(status),
            payload: Vec::new(),
        };
        let meta = SubgroupObjectMeta {
            object_id: 0,
            extension_headers_len: 0,
            payload_length: 0,
            status: Some(status.as_u64()),
            wire_len: 3,
        };
        assert_eq!(
            Some(PayloadPermission::for_status(status)),
            meta.payload_permission(),
            "{status:?}: the meta disagreed with the registry"
        );
        assert_eq!(
            object.permits_payload(),
            meta.payload_permission().expect("an assigned status has an answer").permits(),
            "{status:?}: the object and its meta disagreed"
        );
    }
}

/// A status this draft does not assign has no answer, rather than the answer
/// "forbidden".
///
/// The distinction is the reason the accessor returns an `Option`. A relay
/// carrying an object across from a draft that numbers statuses differently can
/// hold a code draft-14 never assigned, and non-zero-therefore-forbidden is an
/// inference about the number rather than a rule the draft states.
#[test]
fn an_unassigned_status_has_no_payload_rule() {
    let meta = SubgroupObjectMeta {
        object_id: 0,
        extension_headers_len: 0,
        payload_length: 0,
        status: Some(0x2),
        wire_len: 3,
    };
    assert!(
        ObjectStatus::from_u64(0x2).is_none(),
        "fixture: 0x2 must be a code this draft leaves unassigned"
    );
    assert_eq!(
        meta.payload_permission(),
        None,
        "an unassigned status must answer that the draft has no rule, not that the \
         payload is forbidden"
    );
}

/// An absent status is Normal, not unknown.
///
/// A meta has no status only where its payload length is non-zero, and such an
/// object has a status — the encoding just does not spell it. Answering `None`
/// there would make the ordinary payload-bearing object look like the
/// unassigned-code case.
#[test]
fn an_absent_status_is_the_implicit_normal() {
    let meta = SubgroupObjectMeta {
        object_id: 0,
        extension_headers_len: 0,
        payload_length: 4,
        status: None,
        wire_len: 6,
    };
    assert_eq!(meta.payload_permission(), Some(PayloadPermission::Permitted));

    let object = SubgroupObject {
        object_id: varint(0),
        extension_headers: Vec::new(),
        status: None,
        payload: vec![1, 2, 3, 4],
    };
    assert!(object.permits_payload());
}

/// The fetch stream answers on the same terms as the subgroup stream.
///
/// Two object shapes, one rule. A fetch object that answered differently would
/// mean a relay forwarding between the two had to know which stream it came off
/// to interpret the answer.
#[test]
fn the_fetch_object_answers_the_same_way() {
    for status in [ObjectStatus::Normal, ObjectStatus::EndOfGroup, ObjectStatus::EndOfTrack] {
        let object = FetchObject {
            group_id: varint(1),
            subgroup_id: varint(0),
            object_id: varint(0),
            publisher_priority: 128,
            extension_headers: Vec::new(),
            status: Some(status),
            payload: Vec::new(),
        };
        let meta = FetchObjectMeta {
            group_id: 1,
            subgroup_id: 0,
            object_id: 0,
            publisher_priority: 128,
            extension_headers_len: 0,
            payload_length: 0,
            status: Some(status.as_u64()),
            wire_len: 7,
        };
        assert_eq!(
            object.permits_payload(),
            PayloadPermission::for_status(status).permits(),
            "{status:?}: the fetch object disagreed with the registry"
        );
        assert_eq!(
            meta.payload_permission(),
            Some(PayloadPermission::for_status(status)),
            "{status:?}: the fetch meta disagreed with the registry"
        );
    }
}

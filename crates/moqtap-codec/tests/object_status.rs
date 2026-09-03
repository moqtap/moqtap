//! Every draft's `ObjectStatus` decoder answers `None` for code points that
//! draft does not assign, and `Some` for every one it does.
//!
//! Each draft's Object Status section lists the values `Status` may take and
//! then says that any other value SHOULD be treated as a protocol error and the
//! session terminated with a protocol violation. A decoder that answers
//! `Some(variant)` for an unlisted value reports a defined status to its caller
//! for bytes the peer was not allowed to send, and the caller has no way to
//! tell the two apart afterwards.
//!
//! The assigned set moves between drafts — drafts 07 through 10 assign 0x5,
//! drafts 11 through 15 do not, and drafts 16 onward also drop 0x1 — so each
//! draft is checked against its own module. The expected set is read from that
//! module's `ObjectStatus::ALL`, never restated here: a list written out in
//! this file would be a second copy free to drift away from the enum it is
//! supposed to be pinning.
//!
//! The sweep runs over every value from 0x0 to 0x1f, which covers the gaps
//! inside and just past each draft's assigned range (0x2 in every draft, 0x5
//! from draft-11 on, 0x1 from draft-16 on), and then over a handful of larger
//! values that cross each varint width boundary.
//!
//! # How far this reaches
//!
//! What is gated here is `ObjectStatus::from_u64` — the conversion, and only
//! the conversion. Every draft's decoders now route the wire code through it:
//! drafts 07-14 call it directly from each status read, and drafts 15-20 call
//! it from their `data_stream` module's `checked_status`, which is how the
//! raw-coded `SubgroupObject::object_status` and `DatagramHeader::
//! object_status` fields on those drafts come to hold only assigned values.
//!
//! That composition is *not* asserted here. A green row below says the
//! function answers correctly; it says nothing about whether any decoder calls
//! it, which is exactly the gap drafts 15-19 sat in — thirteen rows passed
//! while a draft-19 datagram carrying status 0x2 decoded clean. The wire side
//! is gated separately, per draft and per decoder, in `object_status_wire.rs`.
//! Both files are needed: this one catches a wrong assigned set, that one
//! catches a decoder that does not consult it.
//!
//! What these tests catch, observed by making each change and running them:
//!
//! Adding `5 => Some(ObjectStatus::EndOfTrack)` to draft-11's `from_u64`, the
//! shape of the defect these tests exist for, fails `draft11_object_status`
//! with "draft-11: 0x5 decoded to Some(EndOfTrack), but the draft does not
//! assign it".
//!
//! Deleting the `0x03 => Some(ObjectStatus::EndOfGroup)` arm from draft-16's
//! `from_u64`, so that an assigned code point becomes unreachable, fails
//! `draft16_object_status` with "draft-16: assigned status EndOfGroup (0x3)
//! does not round-trip", left `None`, right `Some(EndOfGroup)`.

/// Values every draft is swept over: the low code points, where an unassigned
/// value is most likely to be waved through because its neighbours are
/// assigned, plus one value at each varint length and the top of the range.
fn sweep() -> Vec<u64> {
    let mut values: Vec<u64> = (0x00..=0x1f).collect();
    values.extend([0x3f, 0x40, 0x7f, 0x80, 0x3fff, 0x4000, 0x3fff_ffff, u64::MAX]);
    values
}

/// Assert that `from_wire` accepts exactly the code points in `all` and refuses
/// everything else, and that each accepted one comes back as the same variant.
fn gate<S, W>(
    draft: &str,
    all: &[S],
    as_wire: impl Fn(S) -> W,
    from_wire: impl Fn(u64) -> Option<S>,
) where
    S: Copy + PartialEq + std::fmt::Debug,
    W: Into<u64>,
{
    let assigned: Vec<u64> = all.iter().map(|status| as_wire(*status).into()).collect();

    let mut sorted = assigned.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        sorted, assigned,
        "{draft}: ObjectStatus::ALL must list each assigned code point once, in ascending order"
    );

    for status in all {
        let code = as_wire(*status).into();
        assert_eq!(
            from_wire(code),
            Some(*status),
            "{draft}: assigned status {status:?} (0x{code:x}) does not round-trip"
        );
    }

    for code in sweep() {
        let expected = assigned.contains(&code);
        let decoded = from_wire(code);
        assert_eq!(
            decoded.is_some(),
            expected,
            "{draft}: 0x{code:x} decoded to {decoded:?}, but the draft {} it",
            if expected { "assigns" } else { "does not assign" }
        );
    }
}

macro_rules! per_draft_gate {
    ($name:ident, $feature:literal, $module:ident, $draft:literal) => {
        #[cfg(feature = $feature)]
        #[test]
        fn $name() {
            use moqtap_codec::$module::types::ObjectStatus;
            gate($draft, ObjectStatus::ALL, ObjectStatus::as_u64, ObjectStatus::from_u64);
        }
    };
}

per_draft_gate!(draft07_object_status, "draft07", draft07, "draft-07");
per_draft_gate!(draft08_object_status, "draft08", draft08, "draft-08");
per_draft_gate!(draft09_object_status, "draft09", draft09, "draft-09");
per_draft_gate!(draft10_object_status, "draft10", draft10, "draft-10");
per_draft_gate!(draft11_object_status, "draft11", draft11, "draft-11");
per_draft_gate!(draft12_object_status, "draft12", draft12, "draft-12");
per_draft_gate!(draft13_object_status, "draft13", draft13, "draft-13");
per_draft_gate!(draft14_object_status, "draft14", draft14, "draft-14");
per_draft_gate!(draft15_object_status, "draft15", draft15, "draft-15");
per_draft_gate!(draft16_object_status, "draft16", draft16, "draft-16");
per_draft_gate!(draft17_object_status, "draft17", draft17, "draft-17");
per_draft_gate!(draft18_object_status, "draft18", draft18, "draft-18");
per_draft_gate!(draft19_object_status, "draft19", draft19, "draft-19");
per_draft_gate!(draft20_object_status, "draft20", draft20, "draft-20");

/// The draft-neutral `ObjectStatus` in the shared `types` module, which follows
/// draft-14's assignment and takes a `u8` rather than a varint.
#[test]
fn shared_object_status() {
    use moqtap_codec::types::ObjectStatus;
    gate("types", ObjectStatus::ALL, ObjectStatus::as_u8, |code| {
        u8::try_from(code).ok().and_then(ObjectStatus::from_u8)
    });
}

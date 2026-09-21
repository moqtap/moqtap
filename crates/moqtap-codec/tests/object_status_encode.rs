//! Every draft's draft-neutral *encoder* refuses an Object Status code that
//! draft does not assign, and reproduces on the wire every one it does.
//!
//! `object_status_wire.rs` is the decode half of this pair: it sweeps status
//! codes into each draft's decoders and requires `Ok` exactly for the codes
//! that draft assigns. This file sweeps the same codes out through the
//! encoder, so the two directions are pinned against the same source of truth
//! and cannot drift apart.
//!
//! # Why the encoder needs a gate of its own
//!
//! Each draft's own `SubgroupObject` now carries a typed `ObjectStatus`, so
//! within one draft an unassigned status cannot be built and therefore cannot
//! be encoded — that half is a compile-time property with nothing to assert at
//! run time.
//!
//! [`AnySubgroupObject`] is the exception, and the reason this file exists. It
//! is draft-neutral, so its `status` is a bare `u64`: it has to be, because
//! the code points move between drafts and a single type cannot name all of
//! them. [`AnySubgroupObjectWriter::write_object`] is therefore the one place
//! left where a status code the target draft does not assign can still be
//! offered to an encoder at run time. That happens for real whenever an object
//! is read on one draft and written on another — relaying a draft-15 object,
//! which may carry Object Does Not Exist (`0x1`), onto a draft-16 stream,
//! which assigns no such code.
//!
//! # The expected set is never restated
//!
//! Each row reads its own draft's `ObjectStatus::ALL` and requires acceptance
//! exactly for the codes in it. A table written out here would be a second
//! copy free to drift from the enum it is meant to be pinning, and the sets
//! genuinely differ: drafts 07-10 assign `0x5`, drafts 11-15 do not, and
//! drafts 16-21 also drop `0x1`. So the same sweep accepts `0x1` on draft-15
//! and refuses it on draft-16, from one body of code.
//!
//! # Accepting is not enough — the bytes are checked too
//!
//! An encoder that answered `Ok` and then wrote the wrong status would pass a
//! refusal-only gate. So for every accepted code this file also re-reads the
//! encoder's own output through [`AnySubgroupObjectReader`] and requires the
//! status to come back unchanged. Reading back through the draft-neutral
//! reader rather than comparing hand-built bytes keeps one body of code
//! correct for all the drafts, whose object layouts differ; the exact
//! byte layouts are pinned per draft by the inline tests in each
//! `draftNN/data_stream.rs` and by the test vectors.
//!
//! # Why the sweep stops at 0x3f
//!
//! Codes `0x00..=0x3f` encode as a single byte under RFC 9000's varint and
//! under MoQT's (draft-17 Section 1.4.1) alike, and the range contains every
//! code that discriminates one draft from another (`0x1`, `0x5`) as well as a
//! gap inside the assigned range (`0x2`). Wider values are `object_status.rs`'
//! sweep to make.
//!
//! # What this gate catches, observed by making each change and running it
//!
//! The status field being typed means the *literal* pre-typing encode path —
//! converting the draft-neutral `u64` straight to a `VarInt` — no longer
//! compiles, so it cannot be ablated. What can be, and what a "just make it
//! compile" fix actually looks like, is silently defaulting a code the target
//! draft does not assign instead of refusing it:
//! `ObjectStatus::from_u64(code).unwrap_or(ObjectStatus::Normal)` in the
//! `explicit_length` arm of `modern_subgroup_glue!` in `src/data_dispatch.rs`.
//! That fails exactly the five rows for the drafts that arm covers:
//!
//! ```text
//! thread 'draft16_object_status_through_the_encoder' (39200) panicked at
//! crates\moqtap-codec\tests\object_status_encode.rs:
//! draft-16: write_object accepted status 0x1, which the draft does not assign
//!
//! thread 'draft15_object_status_through_the_encoder' (28912) panicked at
//! crates\moqtap-codec\tests\object_status_encode.rs:
//! draft-15: write_object accepted status 0x2, which the draft does not assign
//!
//! test result: FAILED. 8 passed; 5 failed
//! ```
//!
//! The two messages differ because the sets do: `0x1` is assigned on draft-15
//! and not on draft-16, so draft-15's row catches the same defect one code
//! later. That is the per-draft claim working.
//!
//! Validating the code but then writing a different one — `.map(|_|
//! ObjectStatus::Normal)` after the `from_u64` in that same arm, which no
//! refusal-only gate would notice — fails the same five rows on the read-back
//! half instead:
//!
//! ```text
//! thread 'draft16_object_status_through_the_encoder' (67152) panicked at
//! crates\moqtap-codec\tests\object_status_encode.rs:
//! assertion `left == right` failed: draft-16: write_object was handed status 0x3 and wrote something else
//!   left: Some(0)
//!  right: Some(3)
//! ```
//!
//! And narrowing the other way — deleting `0x01 => Some(ObjectDoesNotExist)`
//! from draft-15's `ObjectStatus::from_u64` while leaving `ALL` alone, so a
//! code the draft does assign is refused — fails the draft-15 row with:
//!
//! ```text
//! thread 'draft15_object_status_through_the_encoder' (48544) panicked at
//! crates\moqtap-codec\tests\object_status_encode.rs:
//! draft-15: write_object refused status 0x1, which the draft assigns: InvalidField
//! ```

#![cfg(any(
    feature = "draft07",
    feature = "draft08",
    feature = "draft09",
    feature = "draft10",
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
    feature = "draft21"
))]

use moqtap_codec::dispatch::{
    AnySubgroupHeader, AnySubgroupObject, AnySubgroupObjectReader, AnySubgroupObjectWriter,
};
use moqtap_codec::version::DraftVersion;

/// The codes every draft is swept over: the whole assigned range and the gaps
/// inside it, the first few values past it, and the top of the one-byte varint
/// range.
const SWEEP: &[u64] = &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x3f];

/// The stream type opening a subgroup stream with an explicit subgroup ID and
/// no extension block. Drafts 07-10 have one subgroup type; draft-11 numbered
/// them from 0x08; drafts 12+ moved them to 0x10.
fn subgroup_stream_type(draft: DraftVersion) -> u8 {
    match draft {
        DraftVersion::Draft07
        | DraftVersion::Draft08
        | DraftVersion::Draft09
        | DraftVersion::Draft10 => 0x04,
        DraftVersion::Draft11 => 0x0C,
        _ => 0x14,
    }
}

/// A subgroup stream header with no objects after it: track alias 1, group 0,
/// subgroup 0, publisher priority 128.
fn subgroup_header(draft: DraftVersion) -> AnySubgroupHeader {
    let bytes = [subgroup_stream_type(draft), 0x01, 0x00, 0x00, 0x80];
    let mut cursor: &[u8] = &bytes;
    let header = AnySubgroupHeader::decode_stream(draft, &mut cursor)
        .unwrap_or_else(|e| panic!("{draft}: subgroup header decode failed: {e}"));
    assert!(cursor.is_empty(), "{draft}: the header fixture must be exactly one header");
    header
}

/// A status-carrying object: an empty payload is what puts a status on the
/// wire on every draft.
fn status_object(status: u64) -> AnySubgroupObject {
    AnySubgroupObject {
        object_id: 0,
        extension_headers: Vec::new(),
        extension_count: None,
        status: Some(status),
        payload: Vec::new(),
    }
}

/// Sweep one draft's encoder and require it to accept exactly the codes that
/// draft assigns — and, for each accepted code, to put that same code back on
/// the wire.
fn gate_encoder(draft: DraftVersion, assigned: &[u64]) {
    for &status in SWEEP {
        let header = subgroup_header(draft);
        let mut writer = AnySubgroupObjectWriter::new(&header)
            .unwrap_or_else(|e| panic!("{draft}: subgroup writer construction failed: {e}"));

        let mut encoded = Vec::new();
        let result = writer.write_object(&status_object(status), &mut encoded);

        match (assigned.contains(&status), result) {
            (true, Err(error)) => panic!(
                "{draft}: write_object refused status {status:#x}, \
                 which the draft assigns: {error:?}"
            ),
            (false, Ok(())) => panic!(
                "{draft}: write_object accepted status {status:#x}, \
                 which the draft does not assign"
            ),
            (false, Err(_)) => {}
            (true, Ok(())) => {
                // Accepting is not the whole claim: the code the encoder was
                // handed has to be the code that reaches the wire.
                let mut reader = AnySubgroupObjectReader::new(&header).unwrap_or_else(|e| {
                    panic!("{draft}: subgroup reader construction failed: {e}")
                });
                let decoded = reader
                    .read_object(&mut &encoded[..])
                    .unwrap_or_else(|e| panic!("{draft}: own output refused for {status:#x}: {e}"));
                assert_eq!(
                    decoded.status,
                    Some(status),
                    "{draft}: write_object was handed status {status:#x} and wrote something else"
                );
            }
        }
    }
}

/// Generates one draft's row.
macro_rules! draft_row {
    ($name:ident, $feat:literal, $module:ident, $version:ident) => {
        #[cfg(feature = $feat)]
        #[test]
        fn $name() {
            use moqtap_codec::$module::types::ObjectStatus;

            let draft = DraftVersion::$version;
            let assigned: Vec<u64> = ObjectStatus::ALL.iter().map(|s| s.as_u64()).collect();
            assert!(
                SWEEP.iter().any(|code| !assigned.contains(code)),
                "{draft}: the sweep must contain a code the draft does not assign, \
                 or this row asserts nothing about refusal"
            );
            assert!(
                !assigned.is_empty(),
                "{draft}: the sweep must contain a code the draft does assign, \
                 or this row asserts nothing about acceptance"
            );

            gate_encoder(draft, &assigned);
        }
    };
}

draft_row!(draft07_object_status_through_the_encoder, "draft07", draft07, Draft07);
draft_row!(draft08_object_status_through_the_encoder, "draft08", draft08, Draft08);
draft_row!(draft09_object_status_through_the_encoder, "draft09", draft09, Draft09);
draft_row!(draft10_object_status_through_the_encoder, "draft10", draft10, Draft10);
draft_row!(draft11_object_status_through_the_encoder, "draft11", draft11, Draft11);
draft_row!(draft12_object_status_through_the_encoder, "draft12", draft12, Draft12);
draft_row!(draft13_object_status_through_the_encoder, "draft13", draft13, Draft13);
draft_row!(draft14_object_status_through_the_encoder, "draft14", draft14, Draft14);
draft_row!(draft15_object_status_through_the_encoder, "draft15", draft15, Draft15);
draft_row!(draft16_object_status_through_the_encoder, "draft16", draft16, Draft16);
draft_row!(draft17_object_status_through_the_encoder, "draft17", draft17, Draft17);
draft_row!(draft18_object_status_through_the_encoder, "draft18", draft18, Draft18);
draft_row!(draft19_object_status_through_the_encoder, "draft19", draft19, Draft19);
draft_row!(draft20_object_status_through_the_encoder, "draft20", draft20, Draft20);
draft_row!(draft21_object_status_through_the_encoder, "draft21", draft21, Draft21);

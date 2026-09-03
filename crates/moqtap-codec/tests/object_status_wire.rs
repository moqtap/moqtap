//! Every draft's data path refuses an Object Status code that draft does not
//! assign, and accepts every one it does.
//!
//! `object_status.rs` gates each draft's `ObjectStatus::from_u64`. That is the
//! *conversion*, and a conversion nothing calls proves nothing about what the
//! codec decodes — which is exactly the state drafts 15-19 were in. Those five
//! decoders kept the status as a raw wire code and never compared it against
//! the assigned set, so a draft-19 datagram carrying status `0x02` decoded
//! clean and handed `object_status: Some(2)` to its caller, with 0 bytes left
//! over and no error, while draft-19 Section 11.2.1.1 assigns only `0x0`,
//! `0x3` and `0x4` and says any other value SHOULD be treated as a protocol
//! error. Drafts 07-14 refused the same byte. This file is the gate over the
//! decoders themselves, so the two halves cannot drift apart again.
//!
//! # What "the data path" means here
//!
//! Three places carry an Object Status, and each draft is checked on all of
//! the ones it has:
//!
//! - **Subgroup objects**, through both
//!   [`AnySubgroupObjectReader::read_object`] and
//!   [`AnySubgroupObjectReader::read_object_meta`]. They are separate decoders
//!   with separate status reads, and a relay only ever calls the second, so
//!   gating one would leave the path the proxy actually uses uncovered.
//! - **Status datagrams**, whose layout differs enough between drafts that
//!   each draft's own type is named below — drafts 09-13 put the status on a
//!   `DatagramStatusHeader` that the draft-neutral `AnyDatagramHeader` does
//!   not reach at all.
//! - **Fetch objects**, on every draft. Drafts 07-15 put an Object Status
//!   behind a zero Object Payload Length and are swept like the rest. Drafts
//!   16-20 took the field off the fetch object — draft-19 Section 11.2.1.1:
//!   the status "is only present in objects that are delivered via a
//!   SUBSCRIPTION, and is absent in Objects delivered via a FETCH" — so what
//!   is gated there is that nothing is read in its place, whatever the next
//!   byte on the stream says.
//!
//! # The expected set is never restated
//!
//! Each per-draft test reads its own module's `ObjectStatus::ALL` and asserts
//! `Ok` exactly for the codes in it. A table written out here would be a
//! second copy free to drift from the enum it is supposed to be pinning, and
//! the sets genuinely differ: drafts 07-10 assign `0x5`, drafts 11-15 do not,
//! and drafts 16-20 also drop `0x1`. So `0x1` and `0x5` are each accepted on
//! some rows and refused on others, from the same sweep — which is what makes
//! this a per-draft gate rather than fourteen copies of one assertion.
//!
//! # Why the sweep stops at 0x3f
//!
//! Codes `0x00..=0x3f` encode as a single byte under RFC 9000's varint and
//! under MoQT's (draft-17 Section 1.4.1) alike, so one builder produces valid
//! bytes for all fourteen drafts. Above that the two disagree, and on drafts
//! 17-20 the datagram status is a bare byte with no encoding for a code over
//! `0xff` at all. The range still contains every code that discriminates one
//! draft from another (`0x1`, `0x5`) and every gap inside the assigned range
//! (`0x2`); `from_u64`'s behaviour on wider values is `object_status.rs`'s
//! sweep to make.
//!
//! # What these tests catch, observed by making each change and running them
//!
//! Dropping the `checked_status(status.into_inner())?;` line from
//! `draft19::data_stream::SubgroupObjectReader::read_object` — putting back
//! the exact defect this file exists for — fails
//! `draft19_object_status_on_the_wire` with:
//!
//! ```text
//! draft-19: subgroup read_object accepted status 0x1, which the draft does not assign
//! ```
//!
//! Dropping it from `read_object_meta` instead, leaving `read_object` correct,
//! fails the same test with:
//!
//! ```text
//! draft-19: subgroup read_object_meta accepted status 0x1, which the draft does not assign
//! ```
//!
//! Dropping it from that draft's `DatagramHeader::decode` fails it with:
//!
//! ```text
//! draft-19: status datagram accepted status 0x1, which the draft does not assign
//! ```
//!
//! And the other direction — draft-15 validating against draft-16's narrower
//! set, so an assigned code is refused — fails
//! `draft15_object_status_on_the_wire` with:
//!
//! ```text
//! draft-15: subgroup read_object refused status 0x1, which the draft assigns: InvalidField
//! ```
//!
//! On the fetch side, letting `draft15::data_stream::FetchObjectReader`'s
//! status read fall back to Normal instead of refusing an unassigned code —
//! `ObjectStatus::from_u64(..).unwrap_or(ObjectStatus::Normal)` in place of
//! `decoded_status(..)?` — fails `draft15_object_status_on_the_wire` with:
//!
//! ```text
//! assertion `left == right` failed: draft-15: fetch read_object reported a status the wire did not carry
//!   left: Some(0)
//!  right: Some(2)
//! ```
//!
//! The typed status field is what makes that the failure: draft-15's enum
//! cannot hold `0x2`, so an unvalidated read cannot report the code it saw and
//! is caught for mis-reporting before it is caught for accepting.
//!
//! For drafts 16-20 the fetch gate is the absence of the field. Reading a
//! status varint after a zero payload length in `fo19::read_object`, in
//! `src/data_dispatch.rs`, fails `draft19_object_status_on_the_wire` with:
//!
//! ```text
//! assertion `left == right` failed: draft-19: fetch read_object consumed the byte after a zero-length object
//!   left: []
//!  right: [0]
//! ```
//!
//! and reporting a status for an empty payload instead — `status: None` in
//! `Resolved::into_object` replaced by `payload.is_empty().then_some(0)` —
//! fails `draft16_object_status_on_the_wire` with:
//!
//! ```text
//! assertion `left == right` failed: draft-16: fetch read_object reported a status, which the draft does not put on a fetch object
//!   left: Some(0)
//!  right: None
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
    feature = "draft20"
))]

use moqtap_codec::dispatch::{
    AnyFetchGroupOrder, AnyFetchHeader, AnyFetchObjectReader, AnySubgroupHeader,
    AnySubgroupObjectReader,
};
use moqtap_codec::error::CodecError;
use moqtap_codec::version::DraftVersion;

/// The codes every draft is swept over: the whole assigned range and the gaps
/// inside it, the first few values past it, and the top of the one-byte varint
/// range. Every value is a single wire byte on all fourteen drafts.
const SWEEP: &[u64] = &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x3f];

/// How a draft prefixes an object's extension/property block: absent, a count
/// of Key-Value-Pairs (draft-08), or a byte length (drafts 09+).
///
/// The streams built here never carry extensions, so the only thing this
/// decides is whether a zero prefix byte is written at all.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ExtBlock {
    Absent,
    Zero,
}

impl ExtBlock {
    fn put(self, out: &mut Vec<u8>) {
        if self == ExtBlock::Zero {
            out.push(0x00);
        }
    }
}

/// Subgroup objects carry no extension block on draft-07, and on drafts 11-20
/// carry one only when the stream type says so — which the streams here never
/// ask for. Drafts 08-10 carry it unconditionally.
fn subgroup_ext_block(draft: DraftVersion) -> ExtBlock {
    match draft {
        DraftVersion::Draft08 | DraftVersion::Draft09 | DraftVersion::Draft10 => ExtBlock::Zero,
        _ => ExtBlock::Absent,
    }
}

/// The fetch object extension block is unconditional from draft-08 on, even on
/// drafts 11-13 where the *subgroup* block is gated on the stream type. Drafts
/// 15-20 gate it on a flag bit instead, and the streams here never set it.
fn fetch_ext_block(draft: DraftVersion) -> ExtBlock {
    match draft {
        DraftVersion::Draft07 => ExtBlock::Absent,
        _ => ExtBlock::Zero,
    }
}

/// Whether a fetch object on this draft is prefixed by a Serialization Flags
/// field naming the fields that follow it.
///
/// Drafts 07-14 give every fetch object the same fixed field list. Draft-15
/// Section 10.4.4 replaced it with per-object flags, and drafts 16-20 kept that
/// shape, so their objects are built from a different layout below.
fn fetch_serialization_flags(draft: DraftVersion) -> bool {
    matches!(
        draft,
        DraftVersion::Draft15
            | DraftVersion::Draft16
            | DraftVersion::Draft17
            | DraftVersion::Draft18
            | DraftVersion::Draft19
            | DraftVersion::Draft20
    )
}

/// Whether this draft's fetch objects carry an Object Status field at all.
///
/// Drafts 07-15 put one after a zero Object Payload Length — draft-15
/// Section 10.4.4: "The Object Status field is only present if the Object
/// Payload Length is zero." Drafts 16-20 dropped it: Figure 27 of draft-19
/// Section 11.4.4 runs from Object Payload Length straight to Object Payload,
/// and Section 11.2.1.1 states the field is "absent in Objects delivered via a
/// FETCH".
fn fetch_carries_a_status(draft: DraftVersion) -> bool {
    !matches!(
        draft,
        DraftVersion::Draft16
            | DraftVersion::Draft17
            | DraftVersion::Draft18
            | DraftVersion::Draft19
            | DraftVersion::Draft20
    )
}

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

/// A one-object subgroup stream whose object has a zero-length payload and
/// carries `status`: header, then Object ID 0, then the object's status.
fn subgroup_stream(draft: DraftVersion, status: u64) -> Vec<u8> {
    // Track alias 1, group 0, subgroup 0, publisher priority 128.
    let mut out = vec![subgroup_stream_type(draft), 0x01, 0x00, 0x00, 0x80];
    out.push(0x00); // Object ID field: absolute 0, or a delta of 0 from nothing.
    subgroup_ext_block(draft).put(&mut out);
    out.push(0x00); // Payload length 0, which is what makes a status follow.
    out.push(status as u8);
    out
}

/// A one-object fetch stream whose object has a zero-length payload, followed
/// by the byte `status`.
///
/// On drafts 07-15 that byte is the object's Object Status field. On drafts
/// 16-20 the object ends at its payload length and the byte is the next thing
/// on the stream, which is exactly what makes it worth writing: a decoder that
/// still read a status there would consume it.
///
/// The Serialization Flags value `0x1c` puts the Group ID, Object ID and
/// Priority on the wire and leaves the Subgroup ID implicitly zero (draft-19
/// Section 11.4.4.1, Tables 8 and 9). That is the only shape a stream's first
/// object may take: every other combination names a field of a prior object,
/// which the first object does not have. It is under `0x40` on every draft, so
/// the same byte is the whole field whether the draft spells it as a fixed
/// octet (draft-15) or a variable-length integer (drafts 16-20). Drafts 18-20
/// read the two ID fields as differences, but the same section makes the first
/// object's deltas its absolute Group ID and Object ID, so the bytes are
/// unchanged.
fn fetch_stream(draft: DraftVersion, status: u64) -> Vec<u8> {
    // Fetch stream type 0x05, request ID 9.
    let mut out = vec![0x05, 0x09];
    if fetch_serialization_flags(draft) {
        out.push(0x1c);
        out.extend_from_slice(&[0x07, 0x00, 0x80]); // group 7, object 0, priority 128
    } else {
        // group 7, subgroup 0, object 0, priority 128
        out.extend_from_slice(&[0x07, 0x00, 0x00, 0x80]);
        fetch_ext_block(draft).put(&mut out);
    }
    out.push(0x00); // Payload length 0.
    out.push(status as u8);
    out
}

/// Assert one decode answered the way `assigned` says it should have.
///
/// `site` names the decoder, so a failure says which of the several status
/// reads on a draft let the code through rather than only naming the draft.
fn check(
    draft: DraftVersion,
    site: &str,
    status: u64,
    assigned: &[u64],
    result: Result<(), CodecError>,
) {
    match (assigned.contains(&status), result) {
        (true, Err(error)) => {
            panic!("{draft}: {site} refused status {status:#x}, which the draft assigns: {error:?}")
        }
        (false, Ok(())) => {
            panic!("{draft}: {site} accepted status {status:#x}, which the draft does not assign")
        }
        _ => {}
    }
}

/// Gate both subgroup object decoders. They read the status independently, and
/// the proxy's forwarding path only ever calls `read_object_meta`.
fn gate_subgroup(draft: DraftVersion, assigned: &[u64]) {
    for &status in SWEEP {
        let stream = subgroup_stream(draft, status);

        let mut cursor: &[u8] = &stream;
        let header = AnySubgroupHeader::decode_stream(draft, &mut cursor)
            .unwrap_or_else(|e| panic!("{draft}: subgroup header decode failed: {e}"));
        let objects = cursor;

        let mut reader = AnySubgroupObjectReader::new(&header)
            .unwrap_or_else(|e| panic!("{draft}: subgroup reader construction failed: {e}"));
        check(
            draft,
            "subgroup read_object",
            status,
            assigned,
            reader.read_object(&mut { objects }).map(|_| ()),
        );

        let mut meta_reader = AnySubgroupObjectReader::new(&header)
            .unwrap_or_else(|e| panic!("{draft}: subgroup reader construction failed: {e}"));
        check(
            draft,
            "subgroup read_object_meta",
            status,
            assigned,
            meta_reader.read_object_meta(&mut { objects }).map(|_| ()),
        );
    }
}

/// Gate one draft's fetch object decoder.
///
/// Drafts 07-15 read an Object Status behind a zero payload length and are
/// swept exactly as the subgroup decoders are, with the accepted code required
/// back so that "accepted" means "decoded", not "skipped".
///
/// Drafts 16-20 have no such field, so the assertion there is the other one
/// worth making: the object ends at its payload length, and the byte after it
/// is still on the stream. A decoder that read one anyway would swallow the
/// next object's Serialization Flags and desynchronise everything behind it.
fn gate_fetch(draft: DraftVersion, assigned: &[u64]) {
    for &status in SWEEP {
        let stream = fetch_stream(draft, status);
        let mut cursor: &[u8] = &stream;
        let header = AnyFetchHeader::decode_stream(draft, &mut cursor)
            .unwrap_or_else(|e| panic!("{draft}: fetch header decode failed: {e}"));
        let mut reader = AnyFetchObjectReader::new(&header, AnyFetchGroupOrder::Ascending)
            .unwrap_or_else(|e| panic!("{draft}: fetch reader construction failed: {e}"));
        let read = reader.read_object(&mut cursor);

        if !fetch_carries_a_status(draft) {
            let object = read.unwrap_or_else(|e| {
                panic!(
                    "{draft}: fetch object with a trailing {status:#x} byte failed to decode: {e}"
                )
            });
            assert_eq!(
                object.status, None,
                "{draft}: fetch read_object reported a status, which the draft does not put on a \
                 fetch object"
            );
            assert_eq!(
                cursor,
                &[status as u8],
                "{draft}: fetch read_object consumed the byte after a zero-length object"
            );
            continue;
        }

        if let Ok(object) = &read {
            assert_eq!(
                object.status,
                Some(status),
                "{draft}: fetch read_object reported a status the wire did not carry"
            );
        }
        check(draft, "fetch read_object", status, assigned, read.map(|_| ()));
    }
}

/// Gate one draft's status-datagram decoder.
///
/// `prefix` is that draft's datagram bytes up to but excluding the status
/// code, and `decode` is that draft's decoder — the layouts differ too much
/// for a shared builder, and on drafts 09-13 the type carrying the status is
/// not the one `AnyDatagramHeader` holds.
fn gate_datagram(
    draft: DraftVersion,
    assigned: &[u64],
    prefix: &[u8],
    decode: impl Fn(&[u8]) -> Result<(), CodecError>,
) {
    for &status in SWEEP {
        let mut bytes = prefix.to_vec();
        bytes.push(status as u8);
        check(draft, "status datagram", status, assigned, decode(&bytes));
    }
}

/// Generates one draft's row.
///
/// `$prefix` is the status datagram's bytes before the status code and
/// `$decode` that draft's datagram decoder; everything else is draft-neutral.
macro_rules! draft_row {
    ($name:ident, $feat:literal, $module:ident, $version:ident, $decode:path, $prefix:expr) => {
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

            gate_subgroup(draft, &assigned);
            gate_fetch(draft, &assigned);
            gate_datagram(draft, &assigned, $prefix, |bytes| $decode(&mut { bytes }).map(|_| ()));
        }
    };
}

// Track alias 1, group 0, object 0, publisher priority 128 on every row; the
// leading byte, where present, is the datagram type.
//
// Drafts 07/08 fold the status into the ordinary datagram header behind a zero
// payload length; drafts 09-13 give it a header of its own, with an
// extension-length field on 09/10 only; drafts 14-20 select it with a type
// byte.
draft_row!(
    draft07_object_status_on_the_wire,
    "draft07",
    draft07,
    Draft07,
    moqtap_codec::draft07::data_stream::DatagramHeader::decode,
    &[0x01, 0x00, 0x00, 0x80, 0x00]
);
draft_row!(
    draft08_object_status_on_the_wire,
    "draft08",
    draft08,
    Draft08,
    moqtap_codec::draft08::data_stream::DatagramHeader::decode,
    &[0x01, 0x00, 0x00, 0x80, 0x00, 0x00]
);
draft_row!(
    draft09_object_status_on_the_wire,
    "draft09",
    draft09,
    Draft09,
    moqtap_codec::draft09::data_stream::DatagramStatusHeader::decode,
    &[0x01, 0x00, 0x00, 0x80, 0x00]
);
draft_row!(
    draft10_object_status_on_the_wire,
    "draft10",
    draft10,
    Draft10,
    moqtap_codec::draft10::data_stream::DatagramStatusHeader::decode,
    &[0x01, 0x00, 0x00, 0x80, 0x00]
);
draft_row!(
    draft11_object_status_on_the_wire,
    "draft11",
    draft11,
    Draft11,
    moqtap_codec::draft11::data_stream::DatagramStatusHeader::decode,
    &[0x01, 0x00, 0x00, 0x80]
);
draft_row!(
    draft12_object_status_on_the_wire,
    "draft12",
    draft12,
    Draft12,
    moqtap_codec::draft12::data_stream::DatagramStatusHeader::decode,
    &[0x01, 0x00, 0x00, 0x80]
);
draft_row!(
    draft13_object_status_on_the_wire,
    "draft13",
    draft13,
    Draft13,
    moqtap_codec::draft13::data_stream::DatagramStatusHeader::decode,
    &[0x01, 0x00, 0x00, 0x80]
);
draft_row!(
    draft14_object_status_on_the_wire,
    "draft14",
    draft14,
    Draft14,
    moqtap_codec::draft14::data_stream::DatagramObject::decode,
    &[0x20, 0x01, 0x00, 0x00, 0x80]
);
draft_row!(
    draft15_object_status_on_the_wire,
    "draft15",
    draft15,
    Draft15,
    moqtap_codec::draft15::data_stream::DatagramHeader::decode,
    &[0x20, 0x01, 0x00, 0x00, 0x80]
);
draft_row!(
    draft16_object_status_on_the_wire,
    "draft16",
    draft16,
    Draft16,
    moqtap_codec::draft16::data_stream::DatagramHeader::decode,
    &[0x20, 0x01, 0x00, 0x00, 0x80]
);
draft_row!(
    draft17_object_status_on_the_wire,
    "draft17",
    draft17,
    Draft17,
    moqtap_codec::draft17::data_stream::DatagramHeader::decode,
    &[0x20, 0x01, 0x00, 0x00, 0x80]
);
draft_row!(
    draft18_object_status_on_the_wire,
    "draft18",
    draft18,
    Draft18,
    moqtap_codec::draft18::data_stream::DatagramHeader::decode,
    &[0x20, 0x01, 0x00, 0x00, 0x80]
);
draft_row!(
    draft19_object_status_on_the_wire,
    "draft19",
    draft19,
    Draft19,
    moqtap_codec::draft19::data_stream::DatagramHeader::decode,
    &[0x20, 0x01, 0x00, 0x00, 0x80]
);
draft_row!(
    draft20_object_status_on_the_wire,
    "draft20",
    draft20,
    Draft20,
    moqtap_codec::draft20::data_stream::DatagramHeader::decode,
    &[0x20, 0x01, 0x00, 0x00, 0x80]
);

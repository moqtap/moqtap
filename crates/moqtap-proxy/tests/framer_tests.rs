//! `ObjectFramer` behaviour on every draft.
//!
//! The property under test throughout is byte identity: whatever the
//! framer decides about object boundaries, concatenating everything it
//! emits must reproduce the bytes it was fed. Framing changes nothing on
//! the wire, so a framer that ever loses or reorders a byte is a defect
//! no matter how good its framing is.

//! # Which drafts this file covers
//!
//! `DRAFTS`, `COPYING_DRAFTS` and `SKIPPING_DRAFTS` are cfg-built, so each
//! sweep is over the drafts this build compiled. With none of them the
//! codec has no subgroup writer to build a fixture with —
//! `AnySubgroupHeader` is uninhabited and `build_stream` stops
//! type-checking — so the file is gated out of that one row rather than
//! kept alive by `#[allow]`.

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

use bytes::Bytes;

use moqtap_codec::dispatch::{AnySubgroupHeader, AnySubgroupObject, AnySubgroupObjectWriter};
use moqtap_codec::version::DraftVersion;

use moqtap_proxy::framer::{BypassReason, FramerConfig, FramerOut, ObjectFramer};
use moqtap_proxy::parser::data::DataStreamType;

/// A [`FramerConfig`] with an explicit buffer cap.
///
/// `FramerConfig` is `#[non_exhaustive]`, so a struct literal does not
/// compile from this crate; this wrapper keeps the call sites below short.
fn capped(max_buffered_object_bytes: usize) -> FramerConfig {
    FramerConfig::new().with_max_buffered_object_bytes(max_buffered_object_bytes)
}

const DRAFTS: &[DraftVersion] = &[
    #[cfg(feature = "draft07")]
    DraftVersion::Draft07,
    #[cfg(feature = "draft08")]
    DraftVersion::Draft08,
    #[cfg(feature = "draft09")]
    DraftVersion::Draft09,
    #[cfg(feature = "draft10")]
    DraftVersion::Draft10,
    #[cfg(feature = "draft11")]
    DraftVersion::Draft11,
    #[cfg(feature = "draft12")]
    DraftVersion::Draft12,
    #[cfg(feature = "draft13")]
    DraftVersion::Draft13,
    #[cfg(feature = "draft14")]
    DraftVersion::Draft14,
    #[cfg(feature = "draft15")]
    DraftVersion::Draft15,
    #[cfg(feature = "draft16")]
    DraftVersion::Draft16,
    #[cfg(feature = "draft17")]
    DraftVersion::Draft17,
    #[cfg(feature = "draft18")]
    DraftVersion::Draft18,
    #[cfg(feature = "draft19")]
    DraftVersion::Draft19,
    #[cfg(feature = "draft20")]
    DraftVersion::Draft20,
    #[cfg(feature = "draft21")]
    DraftVersion::Draft21,
];

/// Drafts whose object headers the codec decodes by copying the extension
/// block out of the buffer, which bounds how far ahead the framer can
/// measure an object that has not fully arrived.
const COPYING_DRAFTS: &[DraftVersion] = &[
    #[cfg(feature = "draft07")]
    DraftVersion::Draft07,
    #[cfg(feature = "draft08")]
    DraftVersion::Draft08,
    #[cfg(feature = "draft09")]
    DraftVersion::Draft09,
    #[cfg(feature = "draft10")]
    DraftVersion::Draft10,
    #[cfg(feature = "draft11")]
    DraftVersion::Draft11,
    #[cfg(feature = "draft12")]
    DraftVersion::Draft12,
    #[cfg(feature = "draft13")]
    DraftVersion::Draft13,
];

/// Drafts whose objects are measured purely by advancing the buffer, so no
/// declared object size is out of measuring reach.
const SKIPPING_DRAFTS: &[DraftVersion] = &[
    #[cfg(feature = "draft14")]
    DraftVersion::Draft14,
    #[cfg(feature = "draft15")]
    DraftVersion::Draft15,
    #[cfg(feature = "draft16")]
    DraftVersion::Draft16,
    #[cfg(feature = "draft17")]
    DraftVersion::Draft17,
    #[cfg(feature = "draft18")]
    DraftVersion::Draft18,
    #[cfg(feature = "draft19")]
    DraftVersion::Draft19,
    #[cfg(feature = "draft20")]
    DraftVersion::Draft20,
    #[cfg(feature = "draft21")]
    DraftVersion::Draft21,
];

/// Drafts 17-21, which are the drafts whose subgroup header type carries a
/// two-bit subgroup-ID *mode* field rather than a present/absent flag.
const MODE_FIELD_DRAFTS: &[DraftVersion] = &[
    #[cfg(feature = "draft17")]
    DraftVersion::Draft17,
    #[cfg(feature = "draft18")]
    DraftVersion::Draft18,
    #[cfg(feature = "draft19")]
    DraftVersion::Draft19,
    #[cfg(feature = "draft20")]
    DraftVersion::Draft20,
    #[cfg(feature = "draft21")]
    DraftVersion::Draft21,
];

/// Drafts whose subgroup stream table has a type meaning "the Subgroup ID is
/// the Object ID of the first object on the stream, and is not transmitted",
/// paired with the type value that says so.
///
/// The pairing is why this is a list of tuples rather than of drafts: draft-11
/// spells it `0x0A` and every draft after it spells it `0x12`.
///
/// # It lives up here for a reason
///
/// This was an array written inline in the one test that reads it, eight
/// hundred lines down, and it was the only per-draft enumeration in this file
/// that was not a named constant beside its siblings. It was also the only one
/// with holes in it. Draft-15 was missing, though draft-15 Section 10.4.2 Table
/// 6 assigns `0x12` to a first-object stream exactly as its neighbours do, and
/// draft-20 was missing because the port that added `DraftVersion::Draft20` to
/// the four constants above never reached a literal that far from them.
///
/// Neither omission could fail. A draft left out of a sweep is a draft the
/// sweep says nothing about, and a test that says nothing passes.
///
/// # Ablations, measured
///
/// Both new members were cut separately, because a sweep stops at its first
/// failed assertion and one cut covering both would only ever prove the
/// earlier one. Draft-15's `subgroup_id_from_first_object` forced to `false`:
///
/// ```text
/// assertion `left == right` failed: [draft-15] first-object subgroup ID
/// ```
///
/// Then reverted, and draft-20's `subgroup_id_mode` made to report mode 1 as
/// mode 0:
///
/// ```text
/// assertion `left == right` failed: [draft-20] first-object subgroup ID
/// ```
///
/// Each reddens one test — 16 passed, 1 failed. The mode-0 sweep above stays
/// green under the draft-20 cut, which is what says the two modes are being
/// told apart rather than both read off one branch.
const FIRST_OBJECT_SUBGROUP_STREAMS: &[(DraftVersion, u8)] = &[
    #[cfg(feature = "draft11")]
    (DraftVersion::Draft11, 0x0A),
    #[cfg(feature = "draft12")]
    (DraftVersion::Draft12, 0x12),
    #[cfg(feature = "draft13")]
    (DraftVersion::Draft13, 0x12),
    #[cfg(feature = "draft14")]
    (DraftVersion::Draft14, 0x12),
    #[cfg(feature = "draft15")]
    (DraftVersion::Draft15, 0x12),
    #[cfg(feature = "draft16")]
    (DraftVersion::Draft16, 0x12),
    #[cfg(feature = "draft17")]
    (DraftVersion::Draft17, 0x12),
    #[cfg(feature = "draft18")]
    (DraftVersion::Draft18, 0x12),
    #[cfg(feature = "draft19")]
    (DraftVersion::Draft19, 0x12),
    #[cfg(feature = "draft20")]
    (DraftVersion::Draft20, 0x12),
    #[cfg(feature = "draft21")]
    (DraftVersion::Draft21, 0x12),
];

/// A draft this build compiled, for the handful of claims below that are
/// about the framer rather than about a draft.
///
/// Those tests used to name a draft outright, which made them pass or fail
/// on whether that one draft happened to be in the build's feature set
/// rather than on the framer. `DRAFTS` is cfg-built and the file-level
/// gate guarantees it is not empty.
fn a_compiled_draft() -> DraftVersion {
    DRAFTS[0]
}

/// The stream-type field opening a subgroup stream that carries an
/// explicit subgroup ID and no extensions, per draft.
fn subgroup_stream_type(draft: DraftVersion) -> u8 {
    match draft {
        // Drafts 07-10 have a single subgroup stream type.
        DraftVersion::Draft07
        | DraftVersion::Draft08
        | DraftVersion::Draft09
        | DraftVersion::Draft10 => 0x04,
        // Draft-11 renumbered the type space; 0x0C states the subgroup ID
        // and carries no extensions.
        DraftVersion::Draft11 => 0x0C,
        // Drafts 12+ moved subgroup types to 0x10..; bit 2 selects the
        // explicit subgroup ID field.
        _ => 0x14,
    }
}

/// A subgroup stream type from a *different* draft's type space than
/// `draft`'s — the leading byte of a stream `draft`'s framer cannot open.
///
/// The three type spaces are disjoint: 07-10 open at `0x04`, draft-11 at
/// `0x0C`, and 12-21 at `0x14`. Any draft therefore has another space to
/// borrow from, which is what lets the wrong-draft case be put to a build
/// that compiled only one draft — the alternative, encoding a real stream
/// on a second draft, needs a second codec and so cannot be asked there at
/// all.
fn foreign_stream_type(draft: DraftVersion) -> u8 {
    match subgroup_stream_type(draft) {
        0x04 => 0x14,
        _ => 0x04,
    }
}

/// Wire bytes of a subgroup header: track alias 1, group 0, subgroup 0,
/// publisher priority 128, no extensions.
fn header_bytes(draft: DraftVersion) -> Vec<u8> {
    vec![subgroup_stream_type(draft), 0x01, 0x00, 0x00, 0x80]
}

fn decode_header(draft: DraftVersion, bytes: &[u8]) -> AnySubgroupHeader {
    let mut cursor = bytes;
    AnySubgroupHeader::decode_stream(draft, &mut cursor)
        .unwrap_or_else(|e| panic!("[{draft}] header decode: {e}"))
}

fn object(object_id: u64, payload: Vec<u8>) -> AnySubgroupObject {
    AnySubgroupObject {
        object_id,
        extension_headers: Vec::new(),
        extension_count: None,
        status: None,
        payload,
    }
}

/// Encode a whole subgroup stream: header plus `objects`, on `draft`.
fn build_stream(draft: DraftVersion, objects: &[AnySubgroupObject]) -> Vec<u8> {
    let head = header_bytes(draft);
    let header = decode_header(draft, &head);
    let mut writer =
        AnySubgroupObjectWriter::new(&header).unwrap_or_else(|e| panic!("[{draft}] writer: {e}"));

    let mut out = head;
    for obj in objects {
        writer
            .write_object(obj, &mut out)
            .unwrap_or_else(|e| panic!("[{draft}] write object {}: {e}", obj.object_id));
    }
    out
}

/// Everything one framer run produced, in order.
#[derive(Default)]
struct Drained {
    /// Concatenation of every emitted byte, in emission order.
    bytes: Vec<u8>,
    /// Object IDs of the objects that were framed individually.
    object_ids: Vec<u64>,
    /// One entry per `FramerOut::Error`.
    errors: Vec<String>,
    /// One entry per `FramerOut::Bypassed`, which carries no bytes and so
    /// cannot disturb the byte-identity assertions below.
    bypasses: Vec<(BypassReason, bool)>,
    headers: usize,
    /// Highest `buffered()` observed across the run.
    peak_buffered: usize,
}

impl Drained {
    fn drain(&mut self, framer: &mut ObjectFramer) {
        loop {
            self.peak_buffered = self.peak_buffered.max(framer.buffered());
            match framer.poll() {
                FramerOut::NeedMore => break,
                FramerOut::Header { raw, .. } => {
                    self.headers += 1;
                    self.push(raw);
                }
                FramerOut::Object { meta, raw } => {
                    self.object_ids.push(meta.object_id);
                    self.push(raw);
                }
                FramerOut::Passthrough(raw) => self.push(raw),
                FramerOut::Bypassed { reason, fixup_owed } => {
                    self.bypasses.push((reason, fixup_owed))
                }
                FramerOut::Error(e) => self.errors.push(e),
                // `FramerOut` is `#[non_exhaustive]`, so a catch-all is
                // required. It panics rather than being ignored: a new
                // variant that carries bytes would otherwise silently
                // break every byte-identity assertion in this file by
                // dropping them.
                other => panic!("unhandled FramerOut variant: {other:?}"),
            }
        }
        self.peak_buffered = self.peak_buffered.max(framer.buffered());
    }

    fn push(&mut self, raw: Bytes) {
        self.bytes.extend_from_slice(&raw);
    }
}

/// Feed `stream` to a framer in `chunk` sized pieces and collect
/// everything it emits, including the end-of-stream flush.
fn run_framer(draft: DraftVersion, stream: &[u8], chunk: usize, config: FramerConfig) -> Drained {
    let mut framer = ObjectFramer::new(DataStreamType::Subgroup, draft, config);
    let mut out = Drained::default();

    for piece in stream.chunks(chunk.max(1)) {
        framer.feed(piece);
        out.drain(&mut framer);
    }
    if let Some(tail) = framer.finish() {
        out.push(tail);
    }
    out
}

// ============================================================
// Byte identity across drafts and chunkings
// ============================================================

#[test]
fn framing_is_byte_identical_on_every_draft() {
    for &draft in DRAFTS {
        let objects = [
            object(0, b"deadbeef".to_vec()),
            object(1, b"cafe".to_vec()),
            object(2, vec![0xAB; 300]),
        ];
        let stream = build_stream(draft, &objects);

        for chunk in [1usize, 3, stream.len()] {
            let out = run_framer(draft, &stream, chunk, FramerConfig::default());
            assert_eq!(
                out.bytes, stream,
                "[{draft}] chunk {chunk}: framed output must equal the input byte for byte"
            );
            assert_eq!(out.headers, 1, "[{draft}] chunk {chunk}: one header");
            assert_eq!(
                out.object_ids,
                vec![0, 1, 2],
                "[{draft}] chunk {chunk}: object IDs resolve to absolute values"
            );
            assert!(out.errors.is_empty(), "[{draft}] chunk {chunk}: {:?}", out.errors);
            assert!(
                out.bypasses.is_empty(),
                "[{draft}] chunk {chunk}: a well-formed stream must not bypass: {:?}",
                out.bypasses
            );
        }
    }
}

#[test]
fn status_object_is_framed() {
    for &draft in DRAFTS {
        let objects = [
            object(0, b"payload".to_vec()),
            AnySubgroupObject { status: Some(0), ..object(1, Vec::new()) },
            object(2, b"more".to_vec()),
        ];
        let stream = build_stream(draft, &objects);
        let out = run_framer(draft, &stream, stream.len(), FramerConfig::default());

        assert_eq!(out.bytes, stream, "[{draft}] byte identity with a status object");
        assert_eq!(out.object_ids, vec![0, 1, 2], "[{draft}] status object is addressable");
    }
}

#[test]
fn wrong_draft_degrades_to_one_error_then_passthrough() {
    // A stream opening with another draft's subgroup stream type, handed
    // to this draft's framer. The proxy freezes the draft at session
    // start, so this really happens; it must cost observability, never
    // bytes. The header bytes are written by hand rather than encoded,
    // which is what keeps the case answerable in a build that compiled a
    // single draft — the framer never gets past the type field, so the
    // rest of the stream is only there to be forwarded.
    for &draft in DRAFTS {
        let mut stream = vec![foreign_stream_type(draft), 0x01, 0x00, 0x00, 0x80];
        stream.extend_from_slice(b"deadbeef");

        for chunk in [1usize, 3, stream.len()] {
            let out = run_framer(draft, &stream, chunk, FramerConfig::default());
            assert_eq!(
                out.bytes, stream,
                "[{draft}] chunk {chunk}: wrong draft must still forward every byte"
            );
            assert_eq!(
                out.errors.len(),
                1,
                "[{draft}] chunk {chunk}: exactly one error, got {:?}",
                out.errors
            );
            assert!(out.object_ids.is_empty(), "[{draft}] chunk {chunk}: nothing is addressable");
            assert_eq!(
                out.bypasses,
                vec![(BypassReason::DecodeError, false)],
                "[{draft}] chunk {chunk}: one bypass, reported once, owing no elide fix-up"
            );
        }
    }
}

#[test]
fn header_that_never_completes_is_bypassed_at_the_cap() {
    // Two bytes is short of every draft's subgroup header, so the draft
    // here only decides which type byte opens the stream.
    let draft = a_compiled_draft();
    let type_byte = subgroup_stream_type(draft);
    let mut framer = ObjectFramer::new(DataStreamType::Subgroup, draft, capped(2));

    framer.feed(&[type_byte]);
    assert!(matches!(framer.poll(), FramerOut::NeedMore));
    assert!(!framer.is_bypassed());

    framer.feed(&[0x01]);
    match framer.poll() {
        FramerOut::Passthrough(raw) => assert_eq!(&raw[..], &[type_byte, 0x01]),
        other => panic!("[{draft}] expected Passthrough, got {other:?}"),
    }
    assert!(framer.is_bypassed(), "[{draft}] a header that outgrows the cap latches bypass");
}

/// A stream whose *header* decodes and whose first *object* does not.
///
/// The wrong-draft and junk-stream cases above both fail during header
/// decode, so without this the framer's object-level error arm — the one
/// that turns a corrupt object into the operator's only diagnostic — is
/// never reached.
fn corrupt_object_stream(draft: DraftVersion) -> Vec<u8> {
    // Written by the codec as a status object with status 0 — the one
    // status every draft assigns — and then corrupted in its last byte.
    //
    // A zero-length payload is what makes a status field present at all,
    // and the status is the object's final field, so the last byte is the
    // status and nothing else. `0x3F` is a one-byte code under both the
    // RFC 9000 varint drafts 07-16 use and the MoQT varint of 17-21, and
    // no draft assigns it — a hard parse failure rather than a short read.
    // Building it this way rather than by hand is what makes the fixture
    // hold on every draft instead of only on the one whose object layout
    // was written out.
    let status_object = AnySubgroupObject { status: Some(0), ..object(0, Vec::new()) };
    let mut stream = build_stream(draft, &[status_object]);
    *stream.last_mut().expect("the encoded object is not empty") = 0x3F;
    stream
}

#[test]
fn a_corrupt_object_errors_once_then_passes_the_stream_through() {
    for &draft in DRAFTS {
        let stream = corrupt_object_stream(draft);

        for chunk in [1usize, stream.len()] {
            let mut framer =
                ObjectFramer::new(DataStreamType::Subgroup, draft, FramerConfig::default());
            let mut out = Drained::default();
            for piece in stream.chunks(chunk) {
                framer.feed(piece);
                out.drain(&mut framer);
            }
            if let Some(tail) = framer.finish() {
                out.push(tail);
            }

            assert_eq!(
                out.bytes, stream,
                "[{draft}] chunk {chunk}: a corrupt object still forwards every byte"
            );
            assert_eq!(
                out.headers, 1,
                "[{draft}] chunk {chunk}: the header decoded before the object failed"
            );
            assert!(out.object_ids.is_empty(), "[{draft}] chunk {chunk}: nothing is addressable");
            assert_eq!(
                out.errors.len(),
                1,
                "[{draft}] chunk {chunk}: exactly one error, got {:?}",
                out.errors
            );
            assert!(
                out.errors[0].starts_with("object decode:"),
                "[{draft}] chunk {chunk}: the error names the object, not the header: {}",
                out.errors[0]
            );
            assert!(
                framer.is_bypassed(),
                "[{draft}] chunk {chunk}: a corrupt object latches bypass"
            );
            assert_eq!(
                out.bypasses,
                vec![(BypassReason::DecodeError, false)],
                "[{draft}] chunk {chunk}: the bypass is reported exactly once, and names the decode"
            );
        }
    }
}

#[test]
fn a_corrupt_object_never_reports_a_second_error() {
    // Bypass is irreversible, so more bytes after the failure must be
    // forwarded silently rather than re-reported per poll.
    for &draft in DRAFTS {
        let mut stream = corrupt_object_stream(draft);
        stream.extend_from_slice(&[0xAB; 4096]);

        let out = run_framer(draft, &stream, 8192, capped(64 * 1024));

        assert_eq!(out.bytes, stream, "[{draft}] the trailing bytes are forwarded too");
        assert_eq!(
            out.errors.len(),
            1,
            "[{draft}] one error for the whole stream: {:?}",
            out.errors
        );
        assert_eq!(
            out.bypasses.len(),
            1,
            "[{draft}] bypass is latched once, not re-reported per poll: {:?}",
            out.bypasses
        );
    }
}

// ============================================================
// Oversized objects
// ============================================================

#[test]
fn oversized_object_passes_through_and_framing_resumes() {
    const CAP: usize = 64 * 1024;

    for &draft in DRAFTS {
        let objects = [
            object(0, b"small".to_vec()),
            // Within the framer's measuring reach — roughly twice the cap.
            object(1, vec![0x5A; CAP + CAP / 2]),
            object(2, b"after".to_vec()),
        ];
        let stream = build_stream(draft, &objects);
        let out = run_framer(draft, &stream, 8192, capped(CAP));

        assert_eq!(out.bytes, stream, "[{draft}] oversized object must not disturb the bytes");
        assert!(out.errors.is_empty(), "[{draft}] oversized is not an error: {:?}", out.errors);
        assert_eq!(
            out.object_ids,
            vec![0, 2],
            "[{draft}] the oversized object is skipped, the one after it is still framed"
        );
        assert!(
            out.peak_buffered <= CAP + 8192,
            "[{draft}] buffering stayed bounded: peak {}",
            out.peak_buffered
        );
    }
}

#[test]
fn an_object_many_times_the_cap_still_lets_framing_resume() {
    const CAP: usize = 64 * 1024;

    // Drafts 14-21 measure an object without copying anything out of the
    // buffer, so no declared size puts one out of measuring reach.
    for &draft in SKIPPING_DRAFTS {
        let objects = [
            object(0, b"small".to_vec()),
            object(1, vec![0x5A; 8 * CAP]),
            object(2, b"after".to_vec()),
        ];
        let stream = build_stream(draft, &objects);
        let out = run_framer(draft, &stream, 8192, capped(CAP));

        assert_eq!(out.bytes, stream, "[{draft}] an oversized object must not disturb the bytes");
        assert!(out.errors.is_empty(), "[{draft}] oversized is not an error: {:?}", out.errors);
        assert_eq!(
            out.object_ids,
            vec![0, 2],
            "[{draft}] framing resumes after the oversized object"
        );
        assert!(
            out.peak_buffered <= CAP + 8192,
            "[{draft}] buffering stayed bounded: peak {}",
            out.peak_buffered
        );
    }
}

/// The exact shape a real publisher produces: a normal object, one keyframe
/// far larger than the default cap, then a normal object, arriving in the
/// 8 KiB reads `pipe_data_framed` performs.
///
/// This used to latch bypass on the middle object and silently cost every
/// later object on the stream its addressability, without so much as an
/// error to say so: one oversized object degraded the whole stream instead
/// of only itself.
///
/// One draft rather than a sweep — ten mebibytes per draft is the whole
/// draft set's worth of cost for one claim — and it has to come from
/// [`SKIPPING_DRAFTS`], because ten mebibytes is past the measuring reach
/// of 07-13 and resuming is exactly what those drafts cannot do. The case
/// they *do* answer is
/// [`object_beyond_measuring_reach_bypasses_but_keeps_every_byte`].
#[test]
fn a_ten_mebibyte_object_costs_only_its_own_addressability() {
    let Some(&draft) = SKIPPING_DRAFTS.first() else {
        return;
    };
    let objects = [
        object(0, vec![0x11; 16]),
        object(1, vec![0x5A; 10 * 1024 * 1024]),
        object(2, vec![0x22; 16]),
    ];
    let stream = build_stream(draft, &objects);

    let mut framer = ObjectFramer::new(DataStreamType::Subgroup, draft, FramerConfig::default());
    let mut out = Drained::default();
    for piece in stream.chunks(8192) {
        framer.feed(piece);
        out.drain(&mut framer);
    }
    assert!(framer.finish().is_none(), "[{draft}] the stream ended on an object boundary");

    assert_eq!(out.bytes, stream, "[{draft}] every byte still reaches the destination");
    assert_eq!(out.object_ids, vec![0, 2], "[{draft}] only the huge object loses addressability");
    assert!(
        out.errors.is_empty(),
        "[{draft}] an object larger than the cap is not an error: {:?}",
        out.errors
    );
    assert!(
        !framer.is_bypassed(),
        "[{draft}] an object the framer understood must not latch bypass"
    );
    assert!(
        out.peak_buffered <= FramerConfig::default().max_buffered_object_bytes + 8192,
        "[{draft}] buffering stayed bounded: peak {}",
        out.peak_buffered
    );
}

#[test]
fn object_beyond_measuring_reach_bypasses_but_keeps_every_byte() {
    const CAP: usize = 64 * 1024;

    // Drafts 07-13 decode an object's extension block by copying it out of
    // the buffer, so the pad that lets the framer measure an unarrived
    // payload also bounds that copy. An object longer than `buffered + cap`
    // is therefore not measurable on those drafts and the stream degrades
    // to passthrough — bytes intact, addressability gone. Lifting this
    // needs the codec to reject an extension length longer than the bytes
    // present; until then it is a documented limit, not an accident.
    for &draft in COPYING_DRAFTS {
        let objects = [
            object(0, b"small".to_vec()),
            object(1, vec![0x5A; 8 * CAP]),
            object(2, b"after".to_vec()),
        ];
        let stream = build_stream(draft, &objects);
        let out = run_framer(draft, &stream, 8192, capped(CAP));

        assert_eq!(out.bytes, stream, "[{draft}] bypass must still forward every byte");
        assert_eq!(out.object_ids, vec![0], "[{draft}] addressability stops at the bypass");
        assert_eq!(
            out.bypasses,
            vec![(BypassReason::ObjectBeyondMeasuringReach, false)],
            "[{draft}] the bypass names the measuring limit, not a decode failure"
        );
        assert!(
            out.peak_buffered <= CAP + 8192,
            "[{draft}] buffering stayed bounded: peak {}",
            out.peak_buffered
        );
    }
}

// ============================================================
// Bypass drains its buffer
// ============================================================

#[test]
fn unparseable_stream_errors_once_and_stays_bounded() {
    const CAP: usize = 64 * 1024;
    // 0xFF opens an 8-byte varint whose value is no subgroup stream type.
    let stream = vec![0xFFu8; 1024 * 1024];

    let out = run_framer(DraftVersion::Draft14, &stream, 8192, capped(CAP));

    assert_eq!(out.bytes, stream, "unparseable bytes are still forwarded verbatim");
    assert_eq!(out.errors.len(), 1, "exactly one error for the whole stream: {:?}", out.errors);
    assert_eq!(
        out.bypasses,
        vec![(BypassReason::DecodeError, false)],
        "exactly one bypass for the whole stream"
    );
    assert!(
        out.peak_buffered < CAP,
        "bypass must drain rather than accumulate: peak {}",
        out.peak_buffered
    );
}

// ============================================================
// Truncated streams
// ============================================================

#[test]
fn finish_flushes_a_truncated_final_object() {
    for &draft in DRAFTS {
        let stream =
            build_stream(draft, &[object(0, b"deadbeef".to_vec()), object(1, vec![7; 64])]);
        // Cut the last object in half — the peer FINed mid-object.
        let truncated = &stream[..stream.len() - 32];

        let out = run_framer(draft, truncated, 7, FramerConfig::default());
        assert_eq!(
            out.bytes, truncated,
            "[{draft}] a truncated final object must still reach the destination"
        );
        assert_eq!(out.object_ids, vec![0], "[{draft}] only the complete object is framed");
    }
}

// ============================================================
// Header identity
// ============================================================

#[test]
fn header_raw_includes_the_stream_type_field() {
    for &draft in DRAFTS {
        let head = header_bytes(draft);
        let stream = build_stream(draft, &[object(0, b"x".to_vec())]);

        let mut framer =
            ObjectFramer::new(DataStreamType::Subgroup, draft, FramerConfig::default());
        framer.feed(&stream);

        match framer.poll() {
            FramerOut::Header { raw, .. } => {
                assert_eq!(&raw[..], &head[..], "[{draft}] header raw bytes");
            }
            other => panic!("[{draft}] expected Header, got {other:?}"),
        }
    }
}

#[test]
fn subgroup_identity_is_reported_from_the_header() {
    for &draft in DRAFTS {
        let stream = build_stream(draft, &[object(0, b"x".to_vec())]);
        let mut framer =
            ObjectFramer::new(DataStreamType::Subgroup, draft, FramerConfig::default());
        framer.feed(&stream);
        let _ = framer.poll();

        match framer.poll() {
            FramerOut::Object { meta, .. } => {
                assert_eq!(meta.draft, draft, "[{draft}] draft");
                assert_eq!(meta.track_alias, Some(1), "[{draft}] track alias");
                assert_eq!(meta.group_id, 0, "[{draft}] group id");
                assert_eq!(meta.subgroup_id, Some(0), "[{draft}] explicit subgroup id");
                assert_eq!(meta.publisher_priority, Some(128), "[{draft}] publisher priority");
                assert_eq!(meta.index_in_stream, 0, "[{draft}] index");
                assert_eq!(meta.payload_len, 1, "[{draft}] payload length");
                assert_eq!(meta.status, None, "[{draft}] status");
            }
            other => panic!("[{draft}] expected Object, got {other:?}"),
        }
    }
}

/// Build a stream from a header with no subgroup-ID field, carrying one
/// object with ID `object_id`.
fn stream_without_a_subgroup_id_field(
    draft: DraftVersion,
    stream_type: u8,
    object_id: u64,
) -> Vec<u8> {
    // Same layout as `header_bytes` minus the subgroup ID varint, which
    // these stream types do not carry.
    let head = vec![stream_type, 0x01, 0x00, 0x80];
    let header = decode_header(draft, &head);
    let mut writer =
        AnySubgroupObjectWriter::new(&header).unwrap_or_else(|e| panic!("[{draft}] writer: {e}"));
    let mut stream = head;
    writer
        .write_object(&object(object_id, b"x".to_vec()), &mut stream)
        .unwrap_or_else(|e| panic!("[{draft}] write: {e}"));
    stream
}

#[test]
fn subgroup_id_mode_zero_is_reported_as_zero() {
    // Header type 0x10 on drafts 17-21: subgroup-ID mode 0, which *defines*
    // the ID as zero rather than leaving it unresolved. It is the commonest
    // header shape in the vector corpus, so reporting `None` here would
    // hide the majority of live traffic from any subgroup matcher.
    //
    // Swept over the compiled members of those four rather than named, for
    // the same reason its sibling below is: no other draft has a mode
    // field to report, and a build without 17-20 has no decoder to ask.
    for &draft in MODE_FIELD_DRAFTS {
        let stream = stream_without_a_subgroup_id_field(draft, 0x10, 7);

        let mut framer =
            ObjectFramer::new(DataStreamType::Subgroup, draft, FramerConfig::default());
        framer.feed(&stream);
        let _ = framer.poll();

        match framer.poll() {
            FramerOut::Object { meta, .. } => {
                assert_eq!(meta.subgroup_id, Some(0), "[{draft}] mode-0 subgroup ID");
                assert_eq!(meta.object_id, 7, "[{draft}] object id");
            }
            other => panic!("[{draft}] expected Object, got {other:?}"),
        }
    }
}

#[test]
fn implicit_subgroup_id_is_reported_as_unresolved() {
    // Drafts whose Subgroup ID is the Object ID of the first object on the
    // stream store a zero the framer must not pass off as a real subgroup
    // ID.
    //
    // Drafts 17-21's reserved mode 3 (header type 0x16) stores that same
    // zero and is deliberately not swept here: draft-20 Section 11.4.2 and
    // its three predecessors list every mode-3 type value as invalid, so no
    // such header decodes and the framer has nothing to report a subgroup
    // ID for. What it does with one instead is
    // [`a_reserved_mode_header_is_refused_and_every_byte_still_forwarded`].
    //
    // The list is [`FIRST_OBJECT_SUBGROUP_STREAMS`], up with the other
    // per-draft sweeps rather than written out here, because written out here
    // is how it came to be missing two of them.
    for &(draft, stream_type) in FIRST_OBJECT_SUBGROUP_STREAMS {
        let stream = stream_without_a_subgroup_id_field(draft, stream_type, 4);

        let mut framer =
            ObjectFramer::new(DataStreamType::Subgroup, draft, FramerConfig::default());
        framer.feed(&stream);
        let _ = framer.poll();

        match framer.poll() {
            FramerOut::Object { meta, .. } => {
                assert_eq!(meta.subgroup_id, None, "[{draft}] first-object subgroup ID");
                assert_eq!(meta.object_id, 4, "[{draft}] object id");
            }
            other => panic!("[{draft}] expected Object, got {other:?}"),
        }
    }
}

/// A header carrying drafts 17-21's reserved subgroup-ID mode costs
/// addressability and not one byte.
///
/// Draft-20 Section 11.4.2, and the same list in 19, 18 and 17, gives eight
/// type values — `0x16`, `0x17`, `0x1E`, `0x1F`, `0x36`, `0x37`, `0x3E`,
/// `0x3F` — as invalid, and tells the endpoint receiving one to close the
/// session with a PROTOCOL_VIOLATION. This proxy is not that endpoint. It
/// carries traffic between peers that may be broken on purpose, so a header
/// it cannot read has to reach the far side intact for the peer to answer
/// as the draft says. Refusing here would take the violation off the wire
/// and make an induced error untestable end to end.
///
/// `0x16` is mode 3 with no properties, no end-of-group and the priority
/// present, so the bytes after the type field are laid out exactly as the
/// mode-1 header in the test above — only the mode differs, which is what
/// attributes the outcome to the mode.
///
/// *Ablation, measured:* clear the buffer alongside latching the bypass, so
/// the bytes the framer could not read are dropped rather than released
/// uninterpreted:
///
/// ```text
/// assertion `left == right` failed: [draft-17] chunk 1: a reserved-mode header costs addressability, not bytes
///   left: [1, 0, 128, 100, 101, 97, 100, 98, 101, 101, 102]
///  right: [22, 1, 0, 128, 100, 101, 97, 100, 98, 101, 101, 102]
/// ```
#[test]
fn a_reserved_mode_header_is_refused_and_every_byte_still_forwarded() {
    for &draft in MODE_FIELD_DRAFTS {
        // Type, track alias 1, group 0, publisher priority 128 — mode 3
        // puts no Subgroup ID on the wire. Written by hand because no
        // encoder in the workspace will emit a type value its own decoder
        // refuses, which is the whole point of the fixture.
        let mut stream = vec![0x16u8, 0x01, 0x00, 0x80];
        stream.extend_from_slice(b"deadbeef");

        for chunk in [1usize, 3, stream.len()] {
            let out = run_framer(draft, &stream, chunk, FramerConfig::default());
            assert_eq!(
                out.bytes, stream,
                "[{draft}] chunk {chunk}: a reserved-mode header costs addressability, not bytes"
            );
            assert_eq!(
                out.headers, 0,
                "[{draft}] chunk {chunk}: no header is reported, because none decoded"
            );
            assert!(
                out.object_ids.is_empty(),
                "[{draft}] chunk {chunk}: nothing on the stream is addressable"
            );
            assert_eq!(
                out.errors.len(),
                1,
                "[{draft}] chunk {chunk}: exactly one error, got {:?}",
                out.errors
            );
            assert_eq!(
                out.bypasses,
                vec![(BypassReason::DecodeError, false)],
                "[{draft}] chunk {chunk}: one bypass, owing no elide fix-up"
            );
        }
    }
}

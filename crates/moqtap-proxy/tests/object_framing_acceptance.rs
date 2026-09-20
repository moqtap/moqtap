//! Object framing acceptance tests.
//!
//! Two properties the rest of the proxy suite does not pin down:
//!
//! 1. **The buffering cap is a boundary, not a hint.** `framer_tests`
//!    exercises objects far above and far below
//!    `max_buffered_object_bytes`; nothing asserts what happens *at* it.
//!    An off-by-one there is invisible until a production stream lands on
//!    the wrong side of it.
//! 2. **Streams the framer does not address still arrive intact.** Fetch
//!    streams on drafts 18 and 19 are not addressable, on the explicit
//!    promise that no fidelity is lost. Nothing tested that promise.
//! 3. **The three drafts in between are addressable and their frames are
//!    not all objects.** Drafts 15, 16 and 17 let a fetch object leave a
//!    field off and take the previous object's, and 16 and 17 add frames
//!    that are not objects at all. What the framer reports about those is
//!    asserted here.
//!
//! The streams here are assembled by a local encoder written from each
//! draft's documented layout rather than by `AnySubgroupObjectWriter`, so
//! the framer is measured against the wire rather than against the codec's
//! own idea of it — the same discipline as
//! `moqtap-codec/tests/wire_acceptance.rs`.

// Section 5 alone drives a live session, and a live session is refused
// before it dials unless the build holds the codec for the draft it is
// configured with. Everything that section needs — the harness, the
// observer it installs and the types they are written in — is therefore
// compiled with it, so a build without draft-19 has no unused import to
// answer for and the remaining four sections stay compiled.
#[cfg(feature = "draft19")]
mod common;

#[cfg(feature = "draft19")]
use std::sync::{Arc, Mutex};
#[cfg(feature = "draft19")]
use std::time::Duration;

use bytes::Bytes;

use moqtap_codec::version::DraftVersion;

#[cfg(feature = "draft19")]
use moqtap_proxy::event::ProxyEvent;
use moqtap_proxy::framer::{BypassReason, FramerConfig, FramerOut, ObjectFramer, ObjectMeta};
#[cfg(feature = "draft19")]
use moqtap_proxy::hook::NoOpHook;
#[cfg(feature = "draft19")]
use moqtap_proxy::observer::ProxyObserver;
use moqtap_proxy::parser::data::DataStreamType;

/// A [`FramerConfig`] with an explicit buffer cap.
///
/// `FramerConfig` is `#[non_exhaustive]`, so a struct literal does not
/// compile from this crate. The boundary these tests assert on is the
/// number the builder sets.
fn capped(max_buffered_object_bytes: usize) -> FramerConfig {
    FramerConfig::new().with_max_buffered_object_bytes(max_buffered_object_bytes)
}

// ============================================================
// A stream encoder independent of the codec under test
// ============================================================

/// QUIC variable-length integer, RFC 9000 §16.
fn put_varint(draft: DraftVersion, out: &mut Vec<u8>, value: u64) {
    if draft.uses_moqt_varint() {
        // MoQT (draft-17 Section 1.4.1): the length is the number of leading
        // 1 bits in the first byte, and one byte carries 0-127.
        let width = (1..=8usize).find(|w| value < 1u64 << (7 * w)).unwrap_or(9);
        if width == 9 {
            out.push(0xFF);
            out.extend_from_slice(&value.to_be_bytes());
            return;
        }
        let prefix = (((1u16 << (width - 1)) - 1) << (9 - width)) as u8;
        let combined = ((prefix as u64) << (8 * (width - 1))) | value;
        for i in (0..width).rev() {
            out.push((combined >> (8 * i)) as u8);
        }
    } else if value < 1 << 6 {
        out.push(value as u8);
    } else if value < 1 << 14 {
        out.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes());
    } else if value < 1 << 30 {
        out.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(value | 0xC000_0000_0000_0000).to_be_bytes());
    }
}

/// A fetch object's Serialization Flags, which is a variable-length integer
/// and not a byte.
///
/// Worth its own function because the two encodings disagree exactly where
/// these values live. Under the QUIC encoding drafts 07-16 use, the first
/// byte's top two bits are the field's *length*, so a flag word with bit
/// `0x40` set — the Datagram bit — cannot be one byte at all and has to be
/// spelled `0x40 0x44`. Under the MoQT encoding from draft-17 the same word
/// is the single byte `0x44`. Pushing the word as a byte therefore builds a
/// valid stream on one draft and a two-byte integer of 1028 on the other,
/// which is a Serialization Flags value no draft assigns.
#[cfg(any(feature = "draft15", feature = "draft16", feature = "draft17"))]
fn put_flags(draft: DraftVersion, out: &mut Vec<u8>, flags: u64) {
    put_varint(draft, out, flags);
}

/// One even-typed Key-Value-Pair: type `0x3c`, varint value `0x02`.
const EXT: &[u8] = &[0x3c, 0x02];

/// How long a stream is given to cross the proxy before the test that is
/// waiting for it says so.
///
/// A failure ceiling, never spent by a correct build: the wait it bounds
/// ends as soon as the far end holds the stream.
#[cfg(feature = "draft19")]
const ARRIVAL: Duration = Duration::from_secs(10);

/// Object IDs are absolute on drafts 07-13 and delta-encoded from draft-14.
fn delta_encoded(draft: DraftVersion) -> bool {
    matches!(
        draft,
        DraftVersion::Draft14
            | DraftVersion::Draft15
            | DraftVersion::Draft16
            | DraftVersion::Draft17
            | DraftVersion::Draft18
            | DraftVersion::Draft19
            | DraftVersion::Draft20
    )
}

/// The stream type field for a subgroup stream with an explicit subgroup
/// ID, with or without the extension/property block.
fn subgroup_stream_type(draft: DraftVersion, extensions: bool) -> u8 {
    match draft {
        DraftVersion::Draft07
        | DraftVersion::Draft08
        | DraftVersion::Draft09
        | DraftVersion::Draft10 => 0x04,
        DraftVersion::Draft11 => {
            if extensions {
                0x0D
            } else {
                0x0C
            }
        }
        _ => {
            if extensions {
                0x15
            } else {
                0x14
            }
        }
    }
}

/// Track alias 1, group 0, subgroup 0, publisher priority 128, including
/// the leading stream type field.
fn subgroup_header(draft: DraftVersion, extensions: bool) -> Vec<u8> {
    vec![subgroup_stream_type(draft, extensions), 0x01, 0x00, 0x00, 0x80]
}

/// Append one subgroup object's wire bytes.
///
/// Draft-07 has no extension block; draft-08's is count-prefixed and
/// unconditional; drafts 09/10 carry a byte-length-prefixed block
/// unconditionally; drafts 11+ gate it on the stream type.
fn put_subgroup_object(
    out: &mut Vec<u8>,
    draft: DraftVersion,
    extensions: bool,
    prev: Option<u64>,
    object_id: u64,
    payload: &[u8],
) {
    let id_field = match (delta_encoded(draft), prev) {
        (true, Some(prev)) => object_id - prev - 1,
        _ => object_id,
    };
    put_varint(draft, out, id_field);

    let ext: &[u8] = if extensions { EXT } else { &[] };
    match draft {
        DraftVersion::Draft07 => {}
        DraftVersion::Draft08 => {
            put_varint(draft, out, if ext.is_empty() { 0 } else { 1 });
            out.extend_from_slice(ext);
        }
        DraftVersion::Draft09 | DraftVersion::Draft10 => {
            put_varint(draft, out, ext.len() as u64);
            out.extend_from_slice(ext);
        }
        _ if extensions => {
            put_varint(draft, out, ext.len() as u64);
            out.extend_from_slice(ext);
        }
        _ => {}
    }

    put_varint(draft, out, payload.len() as u64);
    out.extend_from_slice(payload);
}

/// A whole subgroup stream: header, then one object per `(id, payload)`.
fn subgroup_stream(draft: DraftVersion, extensions: bool, objects: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut out = subgroup_header(draft, extensions);
    let mut prev = None;
    for (object_id, payload) in objects {
        put_subgroup_object(&mut out, draft, extensions, prev, *object_id, payload);
        prev = Some(*object_id);
    }
    out
}

/// The wire length of a single object with `payload_len` payload bytes.
fn object_wire_len(draft: DraftVersion, extensions: bool, payload_len: usize) -> usize {
    let payload = vec![0x5A; payload_len];
    let stream = subgroup_stream(draft, extensions, &[(0, payload)]);
    stream.len() - subgroup_header(draft, extensions).len()
}

/// A draft-19 fetch stream: type `0x05`, request ID 9, then objects laid
/// out the way drafts 07-14 do. The exact object bytes are immaterial — the
/// framer does not address fetch objects on drafts 15-19, so it must
/// forward the whole stream without interpreting any of it.
fn fetch_stream() -> Vec<u8> {
    let draft = DraftVersion::Draft19;
    let mut out = vec![0x05, 0x09];
    for (group_id, object_id) in [(7u64, 0u64), (7, 1), (8, 0)] {
        put_varint(draft, &mut out, group_id);
        put_varint(draft, &mut out, 0); // subgroup
        put_varint(draft, &mut out, object_id);
        out.push(128); // publisher priority
        put_varint(draft, &mut out, 0); // extension block length
        put_varint(draft, &mut out, 4); // payload length
        out.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    }
    out
}

// ============================================================
// Framer harness
// ============================================================

/// Everything one framer run produced, in order.
#[derive(Default)]
struct Drained {
    /// Concatenation of every emitted byte, in emission order.
    bytes: Vec<u8>,
    /// Metadata of the objects that were framed individually.
    objects: Vec<ObjectMeta>,
    errors: Vec<String>,
    /// One entry per `FramerOut::Bypassed`. The variant carries no bytes,
    /// so recording it cannot disturb the byte-identity assertions.
    bypasses: Vec<BypassReason>,
    /// Highest `buffered()` observed across the run.
    peak_buffered: usize,
}

impl Drained {
    fn object_ids(&self) -> Vec<u64> {
        self.objects.iter().map(|m| m.object_id).collect()
    }

    fn drain(&mut self, framer: &mut ObjectFramer) {
        loop {
            self.peak_buffered = self.peak_buffered.max(framer.buffered());
            match framer.poll() {
                FramerOut::NeedMore => break,
                FramerOut::Header { raw, .. } => self.push(raw),
                FramerOut::Object { meta, raw } => {
                    self.objects.push(meta);
                    self.push(raw);
                }
                FramerOut::Passthrough(raw) => self.push(raw),
                FramerOut::Bypassed { reason, .. } => self.bypasses.push(reason),
                FramerOut::Error(e) => self.errors.push(e),
                // `FramerOut` is `#[non_exhaustive]`; the catch-all panics
                // rather than ignoring, so a future byte-carrying variant
                // cannot silently void this file's byte-identity claims.
                other => panic!("unhandled FramerOut variant: {other:?}"),
            }
        }
        self.peak_buffered = self.peak_buffered.max(framer.buffered());
    }

    fn push(&mut self, raw: Bytes) {
        self.bytes.extend_from_slice(&raw);
    }
}

fn run_framer(
    kind: DataStreamType,
    draft: DraftVersion,
    stream: &[u8],
    chunk: usize,
    config: FramerConfig,
) -> Drained {
    let mut framer = ObjectFramer::new(kind, draft, config);
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
];

// ============================================================
// 3. Oversized passthrough — the cap is an exact boundary
// ============================================================

/// The framer decides an object is oversized only when the object is still
/// incomplete as buffering reaches `max_buffered_object_bytes`. With bytes
/// arriving one at a time that makes the boundary exact: an object of
/// exactly the cap's wire length is framed, one byte more is not.
///
/// Catches an off-by-one in the cap comparison, which nothing else can see
/// — `framer_tests` uses objects at 1.5x and 8x the cap, where `<` and
/// `<=` are indistinguishable. It also pins the promise that an oversized
/// object costs addressability for itself alone: the object *after* it must
/// still be framed with the correct ID, which on drafts 14-20 requires the
/// framer to have advanced its delta state across an object it never
/// framed.
///
/// [`the_cap_bounds_object_size_independently_of_arrival_pattern`] pins the
/// same boundary for the other arrival patterns.
#[test]
fn the_buffering_cap_is_an_exact_boundary_byte_at_a_time() {
    for &draft in DRAFTS {
        let exact = object_wire_len(draft, false, 4096);
        let stream =
            subgroup_stream(draft, false, &[(0, vec![0x11; 4096]), (1, b"after".to_vec())]);

        // An object of exactly `cap` wire bytes completes before the cap is
        // reached, so it is framed.
        let out = run_framer(DataStreamType::Subgroup, draft, &stream, 1, capped(exact));
        assert_eq!(out.bytes, stream, "[{draft}] at the cap: bytes must be unchanged");
        assert_eq!(
            out.object_ids(),
            vec![0, 1],
            "[{draft}] an object of exactly the cap size must still be framed"
        );

        // One byte over, and the object is still incomplete when buffering
        // reaches the cap, so it is passed through instead.
        let out = run_framer(DataStreamType::Subgroup, draft, &stream, 1, capped(exact - 1));
        assert_eq!(out.bytes, stream, "[{draft}] over the cap: bytes must be unchanged");
        assert_eq!(
            out.object_ids(),
            vec![1],
            "[{draft}] an object one byte over the cap is passed through, \
             and the object after it is still framed with the right ID"
        );
        assert!(
            out.errors.is_empty(),
            "[{draft}] an oversized object is a framing limit, not an error: {:?}",
            out.errors
        );
    }
}

/// `FramerConfig::max_buffered_object_bytes` is documented as "the largest
/// object the framer will buffer whole", which is a property of the object,
/// not of the caller's read size. An object arriving in one large read
/// completes before buffering ever reaches the cap, so a framer that
/// consulted the cap only on an incomplete decode would frame it anyway and
/// the effective limit would be `cap + chunk - 1`.
///
/// Feeding the same over-cap object one byte at a time, in 512-byte pieces
/// and in a single piece must therefore reach the same verdict — the object
/// is not framed, and the one after it is.
#[test]
fn the_cap_bounds_object_size_independently_of_arrival_pattern() {
    for &draft in DRAFTS {
        let exact = object_wire_len(draft, false, 4096);
        let stream =
            subgroup_stream(draft, false, &[(0, vec![0x11; 4096]), (1, b"after".to_vec())]);

        for chunk in [1usize, 512, stream.len()] {
            let out =
                run_framer(DataStreamType::Subgroup, draft, &stream, chunk, capped(exact - 1));
            assert_eq!(out.bytes, stream, "[{draft}] chunk {chunk}: bytes must be unchanged");
            assert_eq!(
                out.object_ids(),
                vec![1],
                "[{draft}] chunk {chunk}: an object over the cap must not be framed, \
                 however the bytes happened to arrive"
            );
        }
    }
}

/// An oversized object must not cost more memory than the cap allows.
/// Reported separately from byte identity because a framer that buffered
/// the whole object anyway would still forward every byte correctly — it
/// would just be an unbounded-memory bug wearing a passing test.
#[test]
fn an_oversized_object_keeps_buffering_bounded() {
    const CAP: usize = 32 * 1024;
    const CHUNK: usize = 4096;

    for &draft in DRAFTS {
        let stream = subgroup_stream(
            draft,
            false,
            &[(0, b"small".to_vec()), (1, vec![0x5A; 40 * CAP]), (2, b"after".to_vec())],
        );
        let out = run_framer(DataStreamType::Subgroup, draft, &stream, CHUNK, capped(CAP));

        assert_eq!(out.bytes, stream, "[{draft}] a 40x-oversized object must arrive intact");
        assert!(
            out.peak_buffered <= CAP + CHUNK,
            "[{draft}] buffering must stay within the cap: peak {} > {}",
            out.peak_buffered,
            CAP + CHUNK
        );
    }
}

// ============================================================
// Streams with extensions, framed from independent bytes
// ============================================================

/// Objects carrying an extension/property block must frame correctly from
/// bytes the codec did not write.
///
/// This is the framer-level guard against one specific misreading: on
/// drafts 17-20 the property block is byte-length-prefixed, and a reader
/// that took the
/// prefix for a KVP count would consume past the payload-length field and
/// mis-frame every following object. Because the framer forwards raw
/// slices, byte identity would *still* hold — only the object IDs and
/// payload lengths reveal it, so those are what this asserts.
#[test]
fn objects_with_extensions_frame_correctly_from_independent_bytes() {
    for &draft in DRAFTS {
        if draft == DraftVersion::Draft07 {
            continue; // no extension block exists on draft-07 objects
        }

        let payloads: Vec<(u64, Vec<u8>)> =
            vec![(0, vec![0xA0; 3]), (1, vec![0xA1; 17]), (2, vec![0xA2; 5])];
        let stream = subgroup_stream(draft, true, &payloads);

        for chunk in [1usize, 5, stream.len()] {
            let out = run_framer(
                DataStreamType::Subgroup,
                draft,
                &stream,
                chunk,
                FramerConfig::default(),
            );

            assert_eq!(out.bytes, stream, "[{draft}] chunk {chunk}: byte identity");
            assert!(out.errors.is_empty(), "[{draft}] chunk {chunk}: {:?}", out.errors);
            assert_eq!(
                out.object_ids(),
                vec![0, 1, 2],
                "[{draft}] chunk {chunk}: extension block must not shift object framing"
            );
            assert_eq!(
                out.objects.iter().map(|m| m.payload_len).collect::<Vec<_>>(),
                vec![3, 17, 5],
                "[{draft}] chunk {chunk}: payload lengths must survive the extension block"
            );
        }
    }
}

// ============================================================
// 4. Fetch streams that are not addressed are forwarded intact
// ============================================================

/// A fetch stream a framer was told nothing about is forwarded
/// byte-for-byte, on the explicit promise that giving one up costs the
/// session nothing but the reporting. That promise is the reason the gap is
/// acceptable, so it is worth a test.
///
/// The framers here are built with [`ObjectFramer::new`], which hands over no
/// fetch Group Order at all, so on drafts 18, 19 and 20 every stream below is
/// the case a session reaches when a publisher opens a response to a request
/// nobody made. Every other draft resolves such a stream from its own bytes
/// and is framed rather than forwarded, which is why only three appear here.
///
/// Catches a framer that dropped, truncated, or duplicated bytes on the
/// path it takes when a stream is not addressed — the least-exercised path
/// in the module, and the one a stub would most plausibly get wrong by
/// emitting nothing at all.
#[test]
fn fetch_streams_whose_group_order_is_unknown_are_forwarded_intact() {
    let stream = fetch_stream();

    for &draft in &[
        #[cfg(feature = "draft18")]
        DraftVersion::Draft18,
        #[cfg(feature = "draft19")]
        DraftVersion::Draft19,
        #[cfg(feature = "draft20")]
        DraftVersion::Draft20,
    ] {
        for chunk in [1usize, 7, stream.len()] {
            let out =
                run_framer(DataStreamType::Fetch, draft, &stream, chunk, FramerConfig::default());

            assert_eq!(
                out.bytes, stream,
                "[{draft}] chunk {chunk}: an unframeable fetch stream must arrive byte-identical"
            );
            assert!(
                out.objects.is_empty(),
                "[{draft}] chunk {chunk}: nothing on this stream is addressable"
            );
            // Exactly one bypass per stream: "not addressable" must be
            // *reported*, not merely observed as an absence of objects — an
            // absence is also what a framer that silently dropped everything
            // would produce.
            assert_eq!(
                out.bypasses,
                vec![BypassReason::FetchGroupOrderUnknown],
                "[{draft}] chunk {chunk}: exactly one bypass, naming the fact that is missing"
            );
        }
    }
}

// ============================================================
// 3. Fetch streams that omit fields — drafts 15, 16 and 17
// ============================================================

/// A fetch stream whose objects state some fields and inherit the rest.
///
/// One byte sequence serves all three drafts, because all three read the
/// Serialization Flags the same way: the two low bits pick the Subgroup ID's
/// meaning, `0x04` puts the Object ID on the wire, `0x08` the Group ID and
/// `0x10` the Priority, and the fields follow in that order. Only the flags'
/// own width differs, and every value below is one byte either way.
///
/// Three objects: one stating everything, one stating only its Object ID,
/// and one stating a new Group ID and restarting its Object IDs in it.
/// Resolved, they are the same `(group, object)` sequence the drafts 07-14
/// stream above carries — `(7, 0)`, `(7, 1)`, `(8, 0)` — which is what makes
/// the two framing paths comparable.
#[cfg(any(feature = "draft15", feature = "draft16", feature = "draft17"))]
fn omitting_fetch_stream(draft: DraftVersion) -> Vec<u8> {
    let mut out = vec![0x05, 0x09];

    // Everything present: subgroup mode 3, object, group, priority.
    put_flags(draft, &mut out, 0x03 | 0x04 | 0x08 | 0x10);
    put_varint(draft, &mut out, 7); // group
    put_varint(draft, &mut out, 0); // subgroup
    put_varint(draft, &mut out, 0); // object
    out.push(128); // priority
    put_varint(draft, &mut out, 4);
    out.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

    // Subgroup from the prior object, object stated, group and priority
    // inherited.
    put_flags(draft, &mut out, 0x01 | 0x04);
    put_varint(draft, &mut out, 1); // object
    put_varint(draft, &mut out, 4);
    out.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

    // A new group, so the object IDs start again inside it.
    put_flags(draft, &mut out, 0x01 | 0x04 | 0x08);
    put_varint(draft, &mut out, 8); // group
    put_varint(draft, &mut out, 0); // object
    put_varint(draft, &mut out, 4);
    out.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

    out
}

/// The three drafts that resolve a fetch object against its predecessor
/// **are** framed, and every field the framer reports is the resolved one.
///
/// The object IDs are the sharp end. Two of the three objects never state a
/// Group ID and one never states an Object ID; a framer that reported the
/// wire's own values would produce `(7, 0)`, `(0, 1)`, `(8, 0)` and the
/// middle group would be a group nobody published.
///
/// *Ablation (measured):* put drafts 15, 16 and 17 back under
/// `capability::fetch_group_order_is_needed`, so their streams are given up
/// for want of an order nothing hands over:
///
/// ```text
/// [draft-15] chunk 1: this stream is addressable, so nothing is bypassed
/// ```
///
/// Exactly two tests redden — this one and
/// [`a_fetch_frame_with_no_subgroup_of_its_own_reports_none`] — while the
/// drafts 07-14 and 18-20 gates stay green, so the cut is attributable to
/// the three drafts it names. It also shows why byte identity is not on its
/// own a measurement of anything: the byte-identity assertion above the
/// bypass one passes under the ablation, because a bypassed stream is
/// forwarded perfectly.
#[test]
#[cfg(any(feature = "draft15", feature = "draft16", feature = "draft17"))]
fn fetch_streams_that_omit_fields_are_framed() {
    for &draft in &[
        #[cfg(feature = "draft15")]
        DraftVersion::Draft15,
        #[cfg(feature = "draft16")]
        DraftVersion::Draft16,
        #[cfg(feature = "draft17")]
        DraftVersion::Draft17,
    ] {
        let stream = omitting_fetch_stream(draft);
        for chunk in [1usize, 7, stream.len()] {
            let out =
                run_framer(DataStreamType::Fetch, draft, &stream, chunk, FramerConfig::default());

            assert_eq!(out.bytes, stream, "[{draft}] chunk {chunk}: byte identity");
            assert!(
                out.bypasses.is_empty(),
                "[{draft}] chunk {chunk}: this stream is addressable, so nothing is bypassed"
            );
            assert_eq!(
                out.object_ids(),
                vec![0, 1, 0],
                "[{draft}] chunk {chunk}: an omitted Object ID is the prior object's plus one"
            );
            assert_eq!(
                out.objects.iter().map(|m| m.group_id).collect::<Vec<_>>(),
                vec![7, 7, 8],
                "[{draft}] chunk {chunk}: an omitted Group ID is the prior object's"
            );
            assert_eq!(
                out.objects.iter().map(|m| m.subgroup_id).collect::<Vec<_>>(),
                vec![Some(0), Some(0), Some(0)],
                "[{draft}] chunk {chunk}: subgroup mode 1 is the prior object's subgroup"
            );
            assert_eq!(
                out.objects.iter().map(|m| m.publisher_priority).collect::<Vec<_>>(),
                vec![Some(128), Some(128), Some(128)],
                "[{draft}] chunk {chunk}: an omitted Priority is the prior object's"
            );
            assert!(
                out.objects.iter().all(|m| m.end_of_range.is_none()),
                "[{draft}] chunk {chunk}: every frame on this stream is an object"
            );
        }
    }
}

/// A fetch stream carrying the two frame shapes that are **not** an object
/// with a subgroup: one forwarded over a datagram, and an End of Range
/// indicator.
///
/// Drafts 16 and 17 only. Draft-15 assigns neither flag.
#[cfg(any(feature = "draft16", feature = "draft17"))]
fn unsubgrouped_fetch_stream(draft: DraftVersion) -> Vec<u8> {
    let mut out = vec![0x05, 0x09];

    // An ordinary object first, so the frames after it have a predecessor
    // to inherit a Group ID and a Priority from.
    put_flags(draft, &mut out, 0x03 | 0x04 | 0x08 | 0x10);
    put_varint(draft, &mut out, 7);
    put_varint(draft, &mut out, 2); // subgroup 2, so a placeholder zero shows
    put_varint(draft, &mut out, 0);
    out.push(128);
    put_varint(draft, &mut out, 4);
    out.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

    // Forwarding Preference Datagram (0x40), which has no Subgroup ID
    // anywhere in its framing, with only its Object ID stated.
    put_flags(draft, &mut out, 0x40 | 0x04);
    put_varint(draft, &mut out, 1);
    put_varint(draft, &mut out, 4);
    out.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

    // End of Non-Existent Range: Serialization Flags 0x8C, whose bits put a
    // Group ID and an Object ID on the wire and nothing else.
    put_flags(draft, &mut out, 0x8C);
    put_varint(draft, &mut out, 7);
    put_varint(draft, &mut out, 9);
    put_varint(draft, &mut out, 0);

    out
}

/// Neither of those two frames is reported as a subgroup-bearing object, and
/// the indicator is not reported as an object at all.
///
/// Both halves are the same mistake in two places: a placeholder the codec
/// fills a field with is not a value the publisher sent. Zero is a real
/// Subgroup ID, so a datagram-forwarded object reported under subgroup zero
/// would be claimed by a shaping rule keyed on subgroup zero; and an End of
/// Range indicator counted among the objects makes every count of them
/// wrong.
///
/// *Ablation (measured):* restore `subgroup_id: Some(m.subgroup_id)` in
/// `ObjectFramer::object_meta`. Fails on both drafts with
/// `left: [Some(2), Some(0), Some(0)]`, `right: [Some(2), None, None]` — the
/// placeholder arriving as subgroup zero.
#[test]
#[cfg(any(feature = "draft16", feature = "draft17"))]
fn a_fetch_frame_with_no_subgroup_of_its_own_reports_none() {
    for &draft in &[
        #[cfg(feature = "draft16")]
        DraftVersion::Draft16,
        #[cfg(feature = "draft17")]
        DraftVersion::Draft17,
    ] {
        let stream = unsubgrouped_fetch_stream(draft);
        for chunk in [1usize, 7, stream.len()] {
            let out =
                run_framer(DataStreamType::Fetch, draft, &stream, chunk, FramerConfig::default());

            assert_eq!(out.bytes, stream, "[{draft}] chunk {chunk}: byte identity");
            assert!(
                out.bypasses.is_empty(),
                "[{draft}] chunk {chunk}: addressable, so nothing is bypassed. errors={:?}",
                out.errors
            );
            assert_eq!(
                out.objects.iter().map(|m| m.subgroup_id).collect::<Vec<_>>(),
                vec![Some(2), None, None],
                "[{draft}] chunk {chunk}: only the first frame states a subgroup"
            );
            assert_eq!(
                out.objects.iter().map(|m| m.end_of_range.is_some()).collect::<Vec<_>>(),
                vec![false, false, true],
                "[{draft}] chunk {chunk}: the third frame is an indicator, not an object"
            );
            assert_eq!(
                out.objects.iter().map(|m| (m.group_id, m.object_id)).collect::<Vec<_>>(),
                vec![(7, 0), (7, 1), (7, 9)],
                "[{draft}] chunk {chunk}: the indicator names the Location its range ends at"
            );
        }
    }
}

/// Fetch streams on drafts 07-14 *do* have a codec, so they must frame into
/// individually addressable objects rather than falling back to
/// passthrough. Without this, a framer that bypassed every fetch stream
/// would satisfy the test above and lose all fetch observability silently.
#[test]
fn fetch_streams_with_a_codec_are_framed() {
    let stream = fetch_stream();

    for &draft in &[
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
    ] {
        for chunk in [1usize, 7, stream.len()] {
            let out =
                run_framer(DataStreamType::Fetch, draft, &stream, chunk, FramerConfig::default());

            assert_eq!(out.bytes, stream, "[{draft}] chunk {chunk}: byte identity");
            assert_eq!(
                out.object_ids(),
                vec![0, 1, 0],
                "[{draft}] chunk {chunk}: fetch object IDs come from the objects themselves"
            );
            assert_eq!(
                out.objects.iter().map(|m| m.group_id).collect::<Vec<_>>(),
                vec![7, 7, 8],
                "[{draft}] chunk {chunk}: fetch group IDs must be reported per object"
            );
            assert_eq!(
                out.objects.iter().map(|m| m.track_alias).collect::<Vec<_>>(),
                vec![None, None, None],
                "[{draft}] chunk {chunk}: fetch headers carry a request ID, not a track alias"
            );
            assert!(
                out.bypasses.is_empty(),
                "[{draft}] chunk {chunk}: a draft whose fetch objects are addressed must not                  bypass: {:?}",
                out.bypasses
            );
        }
    }
}

// ============================================================
// 5. End to end through a live proxy
// ============================================================

/// Collects object events and parse errors from a live session.
#[cfg(feature = "draft19")]
#[derive(Default)]
struct ObjectCollector {
    objects: Mutex<Vec<ObjectMeta>>,
    errors: Mutex<Vec<String>>,
}

#[cfg(feature = "draft19")]
impl ProxyObserver for ObjectCollector {
    fn on_event(&self, event: &ProxyEvent) {
        match event {
            ProxyEvent::Object { meta, .. } => {
                self.objects.lock().expect("objects lock").push(*meta)
            }
            ProxyEvent::ParseError { error, .. } => {
                self.errors.lock().expect("errors lock").push(error.clone())
            }
            _ => {}
        }
    }
}

/// A subgroup stream and an unframeable fetch stream, both on draft-19,
/// through a real proxy session with an observer attached.
///
/// Asserts the two acceptance properties together: the bytes arriving
/// upstream are identical to those sent, and one `ProxyEvent::Object`
/// fires per object with the values the *wire* states — the stream is
/// built by this file's encoder, not by the codec, so a reader and writer
/// that share a misunderstanding cannot both hide inside a passing result.
///
/// The fetch stream rides the same session to prove the forwarding-fidelity
/// promise end to end: unframeable, therefore unaddressable, but not one
/// byte different.
///
/// Gated on draft-19 rather than swept, because the claim is about
/// draft-19's own header: the property block prefixed by a byte length,
/// and the fetch stream that draft has no object codec for. A session
/// configured for a draft the build holds no codec for is refused by
/// `ProxyError::DraftNotCompiled` before it dials, so running this on
/// draft-19 in a build without draft-19 would time out on the upstream
/// connection rather than say anything about framing.
#[cfg(feature = "draft19")]
#[tokio::test]
async fn objects_are_reported_and_bytes_preserved_end_to_end() {
    common::init_crypto();

    let draft = DraftVersion::Draft19;
    // Extensions on: this is the draft-17+ byte-length-prefixed property
    // block, the field a framer is most likely to misread as a KVP count.
    let subgroup = subgroup_stream(
        draft,
        true,
        &[(0, b"deadbeef".to_vec()), (1, b"cafe".to_vec()), (2, vec![0xAB; 5000])],
    );
    let fetch = fetch_stream();

    let (upstream_ep, upstream_addr) = common::spawn_quic_server(&[b"moq-00"]);
    let (got_tx, got_rx) = tokio::sync::oneshot::channel::<Vec<Vec<u8>>>();

    // How many streams the upstream has read whole. Read from the test
    // task between opens, so the second stream is not started until the
    // first has arrived — see the loop below.
    let read_whole = Arc::new(Mutex::new(0usize));
    let counted = Arc::clone(&read_whole);

    let upstream_task = tokio::spawn(async move {
        let incoming = upstream_ep.accept().await.expect("upstream accept");
        let conn = incoming.await.expect("upstream tls");

        let mut streams = Vec::new();
        for _ in 0..2 {
            let mut recv = conn.accept_uni().await.expect("upstream accept_uni");
            streams.push(recv.read_to_end(1024 * 1024).await.expect("upstream read_to_end"));
            *counted.lock().expect("read whole") += 1;
        }
        let _ = got_tx.send(streams);
        let _ = conn.closed().await;
    });

    let observer = Arc::new(ObjectCollector::default());
    let proxy = common::spawn_proxy_with(
        common::session_config(draft, upstream_addr),
        b"moq-00",
        Arc::clone(&observer) as Arc<dyn ProxyObserver>,
        Arc::new(NoOpHook),
    );

    let (_client_ep, client_conn) = common::connect_client(proxy.addr, b"moq-00").await;

    // One stream at a time, so the upstream reads them in a known order.
    for (i, stream) in [&subgroup, &fetch].into_iter().enumerate() {
        let mut send = client_conn.open_uni().await.expect("open_uni");
        // Small writes, so the framer is exercised across chunk boundaries
        // rather than handed a whole object at once.
        for piece in stream.chunks(64) {
            send.write_all(piece).await.expect("write");
        }
        send.finish().expect("finish");
        // The next stream is not opened until the upstream holds this one
        // whole, which makes "a known order" an order rather than a bet on
        // how long a forward takes. Bounded, so a stream that never arrives
        // is reported here rather than as two streams in the wrong order
        // three assertions further down.
        let deadline = tokio::time::Instant::now() + ARRIVAL;
        let read = || *read_whole.lock().expect("read whole");
        while read() <= i && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert!(read() > i, "the upstream never read stream {i} whole");
    }

    let got = tokio::time::timeout(Duration::from_secs(10), got_rx)
        .await
        .expect("upstream received both streams")
        .expect("oneshot");

    assert_eq!(got.len(), 2, "both streams must reach the upstream");
    assert_eq!(got[0], subgroup, "the subgroup stream must be forwarded byte-identically");
    assert_eq!(
        got[1], fetch,
        "the fetch stream must be forwarded byte-identically even though it cannot be framed"
    );

    let objects = observer.objects.lock().expect("objects lock").clone();
    let errors = observer.errors.lock().expect("errors lock").clone();

    assert!(errors.is_empty(), "unexpected parse errors: {errors:?}");
    assert_eq!(
        objects.iter().map(|m| m.object_id).collect::<Vec<_>>(),
        vec![0, 1, 2],
        "one Object event per subgroup object, in order, and none for the fetch stream"
    );
    assert_eq!(
        objects.iter().map(|m| m.payload_len).collect::<Vec<_>>(),
        vec![8, 4, 5000],
        "payload lengths must match the wire, not the framer's idea of it"
    );
    assert_eq!(
        objects.iter().map(|m| m.stream_kind).collect::<Vec<_>>(),
        vec![DataStreamType::Subgroup; 3],
        "every reported object came from the subgroup stream"
    );
    for meta in &objects {
        assert_eq!(meta.draft, draft, "reported draft");
        assert_eq!(meta.track_alias, Some(1), "track alias comes from the stream header");
        assert_eq!(meta.group_id, 0, "group id comes from the stream header");
        assert_eq!(meta.subgroup_id, Some(0), "explicit subgroup id");
        assert_eq!(meta.publisher_priority, Some(128), "publisher priority");
    }
    assert_eq!(
        objects.iter().map(|m| m.index_in_stream).collect::<Vec<_>>(),
        vec![0, 1, 2],
        "index_in_stream numbers objects within their own stream"
    );

    client_conn.close(0u32.into(), b"done");
    proxy.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), upstream_task).await;
}

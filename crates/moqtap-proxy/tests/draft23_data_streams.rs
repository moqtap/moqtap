//! Draft-23 data streams through the framer: the fetch End of Group, End of
//! Track and End of Gone Range indicators, the delta-encoded End of Range, the
//! same-group Object ID Delta that counts from two, and repeated Properties.
//!
//! The streams are written out byte by byte from the draft's rules rather than
//! with the codec's writer, so a wrong reading in the codec shows up here as a
//! wrong Location instead of agreeing with itself.

#![cfg(feature = "draft23")]

use std::sync::Arc;

use bytes::Bytes;
use moqtap_codec::dispatch::{AnyDatagramHeader, AnyFetchEndOfRange, AnyFetchGroupOrder};
use moqtap_codec::version::DraftVersion;
use moqtap_proxy::framer::{
    BypassReason, FetchGroupOrders, FramerConfig, FramerOut, ObjectFramer, ObjectMeta,
};
use moqtap_proxy::parser::data::DataStreamType;

const DRAFT: DraftVersion = DraftVersion::Draft23;

/// The Request ID every stream here answers.
const REQUEST_ID: u8 = 9;

/// A framer for `kind`. A fetch stream answers [`REQUEST_ID`], ascending.
fn framer(kind: DataStreamType) -> ObjectFramer {
    let framer = ObjectFramer::new(kind, DRAFT, FramerConfig::default());
    match kind {
        DataStreamType::Subgroup => framer,
        DataStreamType::Fetch => {
            let orders = Arc::new(FetchGroupOrders::default());
            orders.record(u64::from(REQUEST_ID), AnyFetchGroupOrder::Ascending);
            framer.with_fetch_group_orders(orders)
        }
    }
}

#[derive(Default)]
struct Run {
    bytes: Vec<u8>,
    frames: Vec<ObjectMeta>,
    errors: Vec<String>,
    bypasses: Vec<(BypassReason, bool)>,
    /// Set by a bypass that owes a fix-up, where the session resets the
    /// destination and writes nothing more.
    reset: bool,
}

impl Run {
    fn locations(&self) -> Vec<(u64, u64, Option<AnyFetchEndOfRange>)> {
        self.frames.iter().map(|m| (m.group_id, m.object_id, m.end_of_range)).collect()
    }

    fn push(&mut self, raw: &Bytes) {
        if !self.reset {
            self.bytes.extend_from_slice(raw);
        }
    }
}

/// Feed `stream` in `chunk`-byte pieces, eliding the frames at the indices
/// in `elide`, and keep what the session would write.
fn run(kind: DataStreamType, stream: &[u8], chunk: usize, elide: &[u64]) -> Run {
    let mut framer = framer(kind);
    let mut out = Run::default();
    let mut index = 0;
    for piece in stream.chunks(chunk.max(1)) {
        framer.feed(piece);
        loop {
            match framer.poll() {
                FramerOut::NeedMore => break,
                FramerOut::Header { raw, .. } | FramerOut::Passthrough(raw) => out.push(&raw),
                FramerOut::Object { meta, raw } => {
                    if elide.contains(&index) {
                        framer.note_elided(&meta);
                    } else {
                        out.push(&raw);
                    }
                    out.frames.push(meta);
                    index += 1;
                }
                FramerOut::Bypassed { reason, fixup_owed } => {
                    out.bypasses.push((reason, fixup_owed));
                    out.reset |= fixup_owed;
                }
                FramerOut::Error(e) => out.errors.push(e),
                other => panic!("unhandled FramerOut variant: {other:?}"),
            }
        }
    }
    if let Some(tail) = framer.finish() {
        out.push(&tail);
    }
    out
}

/// FETCH_HEADER: type 0x05, then the Request ID.
fn header() -> Vec<u8> {
    vec![0x05, REQUEST_ID]
}

/// Object {5,0}, subgroup 0, priority 128: every field stated (flags 0x1F).
fn first_object() -> Vec<u8> {
    vec![0x1F, 0x05, 0x00, 0x00, 0x80, 0x02, 0xA0, 0xA1]
}

/// The next Object ID in the same Group, same subgroup and priority: flags
/// 0x01 and no ID fields.
fn next_object(payload: u8) -> Vec<u8> {
    vec![0x01, 0x01, payload]
}

/// A stream with every indicator draft-23 adds, between ordinary Objects.
///
/// - `{5,0}`, `{5,1}`, then End of Group (0x80, `80 80`).
/// - `{6,0}`: a Group ID Delta of 0 is the next Group, and the Object ID Delta
///   is required, because after End of Group the prior Object ID is 2^64-1.
/// - End of Unknown Range (0x10C, `81 0C`) through `{6,5}`: a Group ID Delta
///   of 0, so the Object ID is the prior one plus the delta of 4, plus one.
/// - End of Gone Range (0x40C, `84 0C`) through `{9,30}`: a nonzero Group ID
///   Delta of 3, the Object ID stated absolutely, and an Object Payload Length
///   of 0, which every End of Range here keeps.
/// - `{10,0}`, then End of Track (0x81, `80 81`).
fn indicator_stream() -> Vec<u8> {
    let mut s = header();
    s.extend(first_object());
    s.extend(next_object(0xB0));
    s.extend([0x80, 0x80]);
    s.extend([0x0D, 0x00, 0x00, 0x01, 0xC0]);
    s.extend([0x81, 0x0C, 0x00, 0x04, 0x00]);
    s.extend([0x84, 0x0C, 0x03, 0x1E, 0x00]);
    s.extend([0x0D, 0x00, 0x00, 0x01, 0xD0]);
    s.extend([0x80, 0x81]);
    s
}

/// Every indicator is framed and reported as what it is, at the Location the
/// draft gives it, and the stream is forwarded byte for byte.
///
/// Draft-23 Section 11.4.2.2: "When Serialization Flags is 0x80 (End of
/// Group) or 0x81 (End of Track), no other fields are present. The prior
/// Object is the last Object in its Group, or in the Track, respectively."
/// Draft-23 Section 11.4.2.1: "For subsequent indicators, the Group ID is the
/// prior Group ID plus Group ID Delta for Ascending Group Order" and "When
/// Group ID Delta is nonzero, the Object ID Delta field contains the absolute
/// Object ID in the new Group." and "If Group ID Delta is zero, the Object ID
/// is the prior Object ID plus Object ID Delta + 1."
#[test]
fn each_indicator_is_framed_at_its_location() {
    let stream = indicator_stream();
    for chunk in [1, 3, stream.len()] {
        let out = run(DataStreamType::Fetch, &stream, chunk, &[]);
        assert!(out.errors.is_empty(), "chunk {chunk}: {:?}", out.errors);
        assert!(out.bypasses.is_empty(), "chunk {chunk}: {:?}", out.bypasses);
        assert_eq!(out.bytes, stream, "chunk {chunk}: byte identity");
        assert_eq!(
            out.locations(),
            vec![
                (5, 0, None),
                (5, 1, None),
                (5, 1, Some(AnyFetchEndOfRange::EndOfGroup)),
                (6, 0, None),
                (6, 5, Some(AnyFetchEndOfRange::Unknown)),
                (9, 30, Some(AnyFetchEndOfRange::Gone)),
                (10, 0, None),
                (10, 0, Some(AnyFetchEndOfRange::EndOfTrack)),
            ],
            "chunk {chunk}"
        );
        assert!(
            out.frames.iter().filter(|m| m.end_of_range.is_some()).all(|m| m.payload_len == 0),
            "chunk {chunk}: an indicator carries no payload"
        );
    }
}

/// Eliding an Object re-encodes the survivor with draft-23's same-group
/// arithmetic.
///
/// Draft-23 Section 11.4.1.1: "When the Group ID Delta field is not present,
/// the Object ID is the prior Object's ID plus the Object ID Delta + 2 if
/// present." With `{5,1}` removed, `{5,2}` follows `{5,0}`: an advance of two,
/// so an Object ID Delta of 0. Draft-22's arithmetic would have written 2.
#[test]
fn an_elided_object_leaves_its_successor_counted_from_two() {
    let mut stream = header();
    stream.extend(first_object());
    stream.extend(next_object(0xB0));
    stream.extend(next_object(0xB1));

    let mut expected = header();
    expected.extend(first_object());
    expected.extend([0x05, 0x00, 0x01, 0xB1]);

    for chunk in [1, stream.len()] {
        let out = run(DataStreamType::Fetch, &stream, chunk, &[1]);
        assert!(out.errors.is_empty(), "chunk {chunk}: {:?}", out.errors);
        assert_eq!(out.bytes, expected, "chunk {chunk}");
        assert_eq!(
            out.locations(),
            vec![(5, 0, None), (5, 1, None), (5, 2, None)],
            "chunk {chunk}: the framer reports what arrived"
        );
    }
}

/// An End of Group whose Object was elided has no encoding, so the stream is
/// given up rather than forwarded with the marker on another Object.
///
/// Draft-23 Section 11.4.2.2: "The prior Object is the last Object in its
/// Group". After the elide the prior Object on the wire is `{5,0}`, and the
/// marker would say that `{5,0}` ends Group 5. The framer reports the error and
/// bypasses the stream with a fix-up owed, which is what makes the session
/// reset the destination instead of forwarding the rest.
#[test]
fn an_end_of_group_whose_object_was_elided_is_not_forwarded() {
    let mut stream = header();
    stream.extend(first_object());
    stream.extend(next_object(0xB0));
    stream.extend([0x80, 0x80]);

    let out = run(DataStreamType::Fetch, &stream, stream.len(), &[1]);
    assert_eq!(out.errors.len(), 1, "{:?}", out.errors);
    assert_eq!(out.bypasses, vec![(BypassReason::DecodeError, true)]);
    let mut forwarded = header();
    forwarded.extend(first_object());
    assert_eq!(out.bytes, forwarded, "the destination is reset after the surviving Object");
}

/// Object Properties: PRIOR_GROUP_ID_GAP (0x3C) = 2 twice, then an unknown
/// even type 0x50 twice, as Delta Types 0x3C, 0, 0x14, 0. Eight bytes.
const REPEATED: [u8; 8] = [0x3C, 0x02, 0x00, 0x02, 0x14, 0x07, 0x00, 0x08];

/// A Property repeated on an Object is forwarded as it arrived, on a subgroup
/// stream, on a fetch stream and in a datagram's header.
///
/// Draft-23 Section 8.4: "If a Relay does not support a Property, unless it is
/// a Mandatory Track Property as described in Section 3.7, the Relay:", and
/// the last item of that list: "MUST allow multiple instances of the
/// Property." This proxy supports no Property, so the repeat of a type the
/// codec knows (0x3C) is forwarded as well as the unknown one.
#[test]
fn a_repeated_property_is_forwarded_untouched() {
    // SUBGROUP_HEADER type 0x11 (PROPERTIES), Track Alias 1, Group 5,
    // priority 128, then Object 1 with the block and a two-byte payload.
    let mut subgroup = vec![0x11, 0x01, 0x05, 0x80, 0x01, 0x08];
    subgroup.extend(REPEATED);
    subgroup.extend([0x02, 0xAA, 0xBB]);

    // Flags 0x3F: every field stated, and PROPERTIES (0x20).
    let mut fetch = header();
    fetch.extend([0x3F, 0x05, 0x00, 0x01, 0x80, 0x08]);
    fetch.extend(REPEATED);
    fetch.extend([0x02, 0xAA, 0xBB]);

    for (kind, stream) in [(DataStreamType::Subgroup, subgroup), (DataStreamType::Fetch, fetch)] {
        for chunk in [1, stream.len()] {
            let out = run(kind, &stream, chunk, &[]);
            assert!(out.errors.is_empty(), "{kind:?} chunk {chunk}: {:?}", out.errors);
            assert!(out.bypasses.is_empty(), "{kind:?} chunk {chunk}: {:?}", out.bypasses);
            assert_eq!(out.bytes, stream, "{kind:?} chunk {chunk}: byte identity");
            assert_eq!(out.locations(), vec![(5, 1, None)], "{kind:?} chunk {chunk}");
        }
    }

    // OBJECT_DATAGRAM type 0x01 (PROPERTIES), Track Alias 1, Group 5, Object
    // 1, priority 128, then the block and the payload.
    let mut datagram = vec![0x01, 0x01, 0x05, 0x01, 0x80, 0x08];
    datagram.extend(REPEATED);
    datagram.extend([0xAA, 0xBB]);
    let mut cursor = &datagram[..];
    let decoded = AnyDatagramHeader::decode(DRAFT, &mut cursor);
    assert!(decoded.is_ok(), "the header the datagram path reads: {decoded:?}");
    assert_eq!(cursor, &[0xAA, 0xBB], "the payload starts after the block");
}

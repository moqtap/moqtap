//! Re-emitting a fetch stream through the draft-neutral dispatch layer.
//!
//! `AnyFetchObjectWriter` is the inverse of `AnyFetchObjectReader`, and the
//! caller it exists for is a relay that reads one fetch stream and writes
//! another from the same frames with some of them removed. On drafts 07 to 14
//! that is byte deletion: every field of a fetch object is on the wire
//! outright. On drafts 15 to 19 nearly every field is defined against the
//! frame before it, so a survivor that follows a removed run was encoded
//! against something that is no longer there.
//!
//! # Why these run on the corpus rather than on frames built here
//!
//! `tests/fetch_object_reemit.rs` builds its streams field by field, per
//! draft, so that what each object puts on the wire is chosen rather than
//! derived. That is the right shape for holding one draft's writer to one
//! draft's rules, and the wrong shape for this file: the claim here is that
//! **one** call sequence works on all thirteen drafts, and a fixture written
//! thirteen times is thirteen chances to write it in the shape the code
//! already has. The corpus's fetch streams are bytes nothing in this crate
//! produced.
//!
//! It also buys the non-canonical vectors. A stream whose bytes do not
//! survive a minimal-width re-encode is reproduced here anyway, because a
//! frame nothing changed under is forwarded rather than re-encoded — which is
//! the difference between "the writer is a valid encoder" and "the writer is
//! the reader's inverse".
//!
//! # What each gate observes
//!
//! Three claims, and the third is what keeps the second honest:
//!
//! 1. A stream with nothing removed re-emits to **itself**, byte for byte,
//!    with every frame reported `Unchanged`.
//! 2. A stream with one frame removed decodes back to exactly the survivors'
//!    original Locations and priorities.
//! 3. Removing a frame reframes at least one survivor on **every** draft 15
//!    to 19 and **no** survivor on any draft 07 to 14. Without it, gate 2
//!    passes just as well for a writer that deleted the bytes and re-encoded
//!    nothing — which is the bug this whole path exists to prevent, and which
//!    is byte-perfect right up to the moment a survivor is renumbered.
//!
//! # Ablation, measured
//!
//! `AnyFetchObjectWriter::reemit_object` answering `Unchanged` for every
//! frame — byte deletion, which is what this path replaced. Three of the five
//! gates fail and **the byte-identity gate is not one of them**, which is the
//! whole reason gate 3 exists:
//!
//! ```text
//! ---- a_removal_reframes_exactly_on_the_drafts_that_encode_against_a_predecessor stdout ----
//! Draft15: no survivor of any removal was reframed, though this draft writes
//! every frame against the one before it
//!
//! ---- removing_a_frame_leaves_every_survivor_where_it_was stdout ----
//! [Draft15 fetch-stream-two-objects] re-emitted frame 0: invalid field value
//!
//! ---- the_framing_is_re_emitted_from_a_prefix_of_the_frame stdout ----
//! Draft15: no fetch stream in the corpus reframes its second frame, so this
//! gate observed nothing
//! ```
//!
//! The second message is worth reading twice. The survivor of a removed first
//! frame does not merely arrive under the wrong Location — on this stream it
//! does not decode at all, because it inherits from an object that is no
//! longer there. `tests/actions_objects.rs` has the other half, where the
//! survivor decodes cleanly and is simply somebody else.

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
    feature = "draft19"
))]

mod test_vectors;

use moqtap_codec::dispatch::{
    AnyFetchFrame, AnyFetchGroupOrder, AnyFetchHeader, AnyFetchObjectReader, AnyFetchObjectWriter,
    FetchReemit,
};
use moqtap_codec::version::DraftVersion;
use test_vectors::{load_vectors, vectors_dir};

/// Every draft this build compiled, oldest first. Each element carries its
/// own `#[cfg]`, so the array is the enabled set.
const COMPILED_DRAFTS: &[DraftVersion] = &[
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
];

/// The drafts whose fetch objects are written against the frame before them.
///
/// Drafts 15 to 19: from 15 a Serialization Flags field decides which of an
/// object's Group ID, Subgroup ID, Object ID and Priority reach the wire at
/// all, and from 18 the two ID fields that remain are differences. The list is
/// by draft **number**, so it answers for drafts this build did not compile
/// and cannot fall out of step with the enabled set.
fn frames_are_written_against_each_other(draft: DraftVersion) -> bool {
    matches!(
        draft,
        DraftVersion::Draft15
            | DraftVersion::Draft16
            | DraftVersion::Draft17
            | DraftVersion::Draft18
            | DraftVersion::Draft19
    )
}

/// The corpus directory one draft's vectors live in.
fn corpus_dir(draft: DraftVersion) -> &'static str {
    match draft {
        DraftVersion::Draft07 => "draft07",
        DraftVersion::Draft08 => "draft08",
        DraftVersion::Draft09 => "draft09",
        DraftVersion::Draft10 => "draft10",
        DraftVersion::Draft11 => "draft11",
        DraftVersion::Draft12 => "draft12",
        DraftVersion::Draft13 => "draft13",
        DraftVersion::Draft14 => "draft14",
        DraftVersion::Draft15 => "draft15",
        DraftVersion::Draft16 => "draft16",
        DraftVersion::Draft17 => "draft17",
        DraftVersion::Draft18 => "draft18",
        DraftVersion::Draft19 => "draft19",
    }
}

/// One fetch stream from the corpus: its identifier, its stream header bytes
/// and the frames behind them, each with the bytes it occupied.
struct Stream {
    id: String,
    draft: DraftVersion,
    header: AnyFetchHeader,
    header_bytes: Vec<u8>,
    frames: Vec<Frame>,
}

struct Frame {
    frame: AnyFetchFrame,
    raw: Vec<u8>,
}

/// What a frame is, independently of how it was written.
///
/// This is the whole of what a subscriber sees, and the whole of what a
/// removal must leave alone. Compared as a tuple rather than field by field so
/// that a failure prints the survivors beside each other.
type Identity = (u64, Option<u64>, u64, u8, Option<u64>, u64);

fn identity(frame: &AnyFetchFrame) -> Identity {
    let meta = frame.meta;
    (
        meta.group_id,
        meta.has_subgroup_id.then_some(meta.subgroup_id),
        meta.object_id,
        meta.publisher_priority,
        meta.status,
        meta.payload_length,
    )
}

/// Read every fetch stream the corpus has for `draft`.
///
/// Negative vectors are left out: a stream that does not decode has no frames
/// to re-emit, and what it proves belongs to the per-draft runners.
fn streams(draft: DraftVersion) -> Vec<Stream> {
    let path = vectors_dir()
        .join("transport")
        .join(corpus_dir(draft))
        .join("codec")
        .join("data-streams")
        .join("fetch-header.json");
    let file = load_vectors(&path);

    let mut out = Vec::new();
    for vector in &file.vectors {
        if vector.error.is_some() {
            continue;
        }
        let wire = hex::decode(&vector.hex)
            .unwrap_or_else(|e| panic!("[{draft:?} {}] bad hex: {e}", vector.id));

        let mut cursor: &[u8] = &wire;
        let header = AnyFetchHeader::decode_stream(draft, &mut cursor)
            .unwrap_or_else(|e| panic!("[{draft:?} {}] stream header: {e}", vector.id));
        let header_len = wire.len() - cursor.len();

        let mut reader = AnyFetchObjectReader::new(&header, AnyFetchGroupOrder::Ascending)
            .unwrap_or_else(|e| panic!("[{draft:?} {}] reader: {e}", vector.id));
        let mut frames = Vec::new();
        while !cursor.is_empty() {
            let before = cursor.len();
            let frame = reader.read_object_frame(&mut cursor).unwrap_or_else(|e| {
                panic!("[{draft:?} {}] frame {}: {e}", vector.id, frames.len())
            });
            let taken = before - cursor.len();
            let start = wire.len() - before;
            assert_eq!(
                taken as u64,
                frame.meta.wire_len,
                "[{draft:?} {}] frame {} consumed a different number of bytes than it reports",
                vector.id,
                frames.len()
            );
            frames.push(Frame { frame, raw: wire[start..start + taken].to_vec() });
        }

        out.push(Stream {
            id: vector.id.clone(),
            draft,
            header,
            header_bytes: wire[..header_len].to_vec(),
            frames,
        });
    }
    assert!(!out.is_empty(), "{draft:?}: the corpus has no fetch stream to read");
    out
}

/// Re-emit `keep` of a stream's frames, in order, through one writer.
///
/// Returns the whole stream — header included — and what the writer had to do
/// to each frame.
fn reemit(stream: &Stream, keep: impl Fn(usize) -> bool) -> (Vec<u8>, Vec<FetchReemit>) {
    let mut writer = AnyFetchObjectWriter::new(&stream.header, AnyFetchGroupOrder::Ascending)
        .unwrap_or_else(|e| panic!("[{:?} {}] writer: {e}", stream.draft, stream.id));
    assert_eq!(
        writer.draft(),
        stream.draft,
        "[{:?} {}] writer built for the wrong draft",
        stream.draft,
        stream.id
    );

    let mut wire = stream.header_bytes.clone();
    let mut outcomes = Vec::new();
    for (index, frame) in stream.frames.iter().enumerate() {
        if !keep(index) {
            continue;
        }
        let mut reframed = Vec::new();
        let outcome =
            writer.reemit_object(&frame.frame, &frame.raw, &mut reframed).unwrap_or_else(|e| {
                panic!("[{:?} {}] re-emitting frame {index}: {e}", stream.draft, stream.id)
            });
        match outcome {
            FetchReemit::Unchanged => {
                assert!(
                    reframed.is_empty(),
                    "[{:?} {}] frame {index} reported Unchanged and still wrote bytes",
                    stream.draft,
                    stream.id
                );
                wire.extend_from_slice(&frame.raw);
            }
            FetchReemit::Reframed { .. } => wire.extend_from_slice(&reframed),
        }
        outcomes.push(outcome);
    }
    (wire, outcomes)
}

/// Decode a re-emitted stream back into the identities a subscriber would see.
fn identities(draft: DraftVersion, wire: &[u8], id: &str) -> Vec<Identity> {
    let mut cursor: &[u8] = wire;
    let header = AnyFetchHeader::decode_stream(draft, &mut cursor)
        .unwrap_or_else(|e| panic!("[{draft:?} {id}] re-emitted stream header: {e}"));
    let mut reader = AnyFetchObjectReader::new(&header, AnyFetchGroupOrder::Ascending)
        .unwrap_or_else(|e| panic!("[{draft:?} {id}] re-emitted reader: {e}"));
    let mut out = Vec::new();
    while !cursor.is_empty() {
        let frame = reader
            .read_object_frame(&mut cursor)
            .unwrap_or_else(|e| panic!("[{draft:?} {id}] re-emitted frame {}: {e}", out.len()));
        out.push(identity(&frame));
    }
    out
}

/// A stream nothing was removed from is written back byte for byte, and every
/// frame says so rather than being re-encoded into the same bytes by accident.
///
/// The `Unchanged` half is the sharper of the two. Byte identity would also
/// hold for a writer that re-encoded every frame and happened to land on the
/// same bytes — but only for the canonically encoded vectors, and the corpus
/// carries fetch streams that are not canonically encoded on purpose.
///
/// This is the gate the file header's ablation leaves **passing**, which is
/// what it is there to show: verbatim forwarding reproduces an untouched
/// stream perfectly.
#[test]
fn a_stream_nothing_was_removed_from_re_emits_to_itself() {
    for &draft in COMPILED_DRAFTS {
        for stream in streams(draft) {
            let original: Vec<u8> = stream
                .header_bytes
                .iter()
                .copied()
                .chain(stream.frames.iter().flat_map(|f| f.raw.iter().copied()))
                .collect();
            let (wire, outcomes) = reemit(&stream, |_| true);
            assert_eq!(
                hex::encode(&wire),
                hex::encode(&original),
                "[{draft:?} {}] re-emitting every frame did not reproduce the stream",
                stream.id
            );
            assert!(
                outcomes.iter().all(|o| *o == FetchReemit::Unchanged),
                "[{draft:?} {}] a frame was reframed on a stream nothing was removed from: {:?}",
                stream.id,
                outcomes
            );
        }
    }
}

/// Removing one frame leaves every survivor decoding to exactly what it was.
///
/// This is the corruption the fix-up exists to prevent, and it is invisible in
/// the bytes: a survivor that decodes to a different Object ID is not a
/// dropped object, it is a renumbered stream, and nothing about it looks
/// short or malformed.
#[test]
fn removing_a_frame_leaves_every_survivor_where_it_was() {
    for &draft in COMPILED_DRAFTS {
        for stream in streams(draft) {
            if stream.frames.len() < 2 {
                continue;
            }
            for removed in 0..stream.frames.len() {
                let expected: Vec<Identity> = stream
                    .frames
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| *index != removed)
                    .map(|(_, f)| identity(&f.frame))
                    .collect();
                let (wire, _) = reemit(&stream, |index| index != removed);
                assert_eq!(
                    identities(draft, &wire, &stream.id),
                    expected,
                    "[{draft:?} {}] removing frame {removed} moved a survivor",
                    stream.id
                );
            }
        }
    }
}

/// A removal reframes on the drafts that write frames against each other, and
/// on no other draft.
///
/// Both halves are load-bearing. Without the first, the gate above passes for
/// a writer that deleted bytes and re-encoded nothing. Without the second, it
/// passes for one that re-encodes every frame on every draft, which would
/// throw away the absolute drafts' one guarantee — that a fetch object's bytes
/// mean the same thing wherever they land.
#[test]
fn a_removal_reframes_exactly_on_the_drafts_that_encode_against_a_predecessor() {
    for &draft in COMPILED_DRAFTS {
        let mut reframed = 0usize;
        let mut removals = 0usize;
        for stream in streams(draft) {
            if stream.frames.len() < 2 {
                continue;
            }
            for removed in 0..stream.frames.len() {
                removals += 1;
                let (_, outcomes) = reemit(&stream, |index| index != removed);
                reframed +=
                    outcomes.iter().filter(|o| !matches!(o, FetchReemit::Unchanged)).count();
            }
        }
        assert!(removals > 0, "{draft:?}: the corpus has no fetch stream with two frames");
        if frames_are_written_against_each_other(draft) {
            assert!(
                reframed > 0,
                "{draft:?}: no survivor of any removal was reframed, though this draft writes \
                 every frame against the one before it"
            );
        } else {
            assert_eq!(
                reframed, 0,
                "{draft:?}: a survivor was reframed on a draft whose fetch objects state every \
                 field outright"
            );
        }
    }
}

/// The framing may be re-emitted from a prefix of the frame.
///
/// A frame too large to buffer is forwarded in chunks and only the first
/// carries the framing, so the fix-up has to run against a chunk rather than
/// against the whole object. Nothing behind the framing is read: the bytes are
/// copied, however few of them there are.
#[test]
fn the_framing_is_re_emitted_from_a_prefix_of_the_frame() {
    for &draft in COMPILED_DRAFTS.iter().filter(|d| frames_are_written_against_each_other(**d)) {
        let mut probed = 0usize;
        for stream in streams(draft) {
            if stream.frames.len() < 2 {
                continue;
            }
            // The survivor of a removed first frame, which is the frame a
            // removal is guaranteed to reframe.
            let survivor = &stream.frames[1];
            let framing =
                (survivor.frame.meta.wire_len - survivor.frame.meta.payload_length) as usize;
            if framing >= survivor.raw.len() {
                continue;
            }

            let mut writer =
                AnyFetchObjectWriter::new(&stream.header, AnyFetchGroupOrder::Ascending)
                    .expect("writer");
            let mut whole = Vec::new();
            let full = writer
                .reemit_object(&survivor.frame, &survivor.raw, &mut whole)
                .expect("re-emit the whole frame");

            let mut writer =
                AnyFetchObjectWriter::new(&stream.header, AnyFetchGroupOrder::Ascending)
                    .expect("writer");
            let mut chunk = Vec::new();
            let prefix = writer
                .reemit_object(&survivor.frame, &survivor.raw[..framing + 1], &mut chunk)
                .expect("re-emit the framing from a prefix");

            assert_eq!(
                full, prefix,
                "[{draft:?} {}] the outcome changed when the payload was withheld",
                stream.id
            );
            if let FetchReemit::Reframed { framing_bytes_after, .. } = prefix {
                assert_eq!(
                    chunk.len(),
                    framing_bytes_after + 1,
                    "[{draft:?} {}] a prefix wrote something other than the new framing and the \
                     one byte behind it",
                    stream.id
                );
                assert_eq!(
                    chunk[..],
                    whole[..chunk.len()],
                    "[{draft:?} {}] the prefix and the whole frame disagree on the framing",
                    stream.id
                );
                probed += 1;
            }
        }
        assert!(
            probed > 0,
            "{draft:?}: no fetch stream in the corpus reframes its second frame, so this gate \
             observed nothing"
        );
    }
}

/// A frame is refused by a writer for another draft rather than re-encoded.
///
/// Every ordered pair of compiled drafts, and the pairs that matter are the
/// ones inside a family rather than across it. A draft-07 frame handed to a
/// draft-19 writer is told apart by the shape it carries; a draft-07 frame
/// handed to a **draft-10** writer is not, because drafts 07 to 14 state every
/// field outright and carry no shape at all. Nothing but the draft the frame
/// was read off separates those two, and the mistake would produce bytes that
/// decode — the extension block alone moves three times across that range.
///
/// *Ablation (measured):* drop the draft comparison at the top of
/// `reemit_object` and leave the match's catch-all arm to refuse what it can.
///
/// ```text
/// ---- a_frame_from_another_draft_is_refused stdout ----
/// a frame from another draft must not be re-encoded: Unchanged
/// ```
///
/// The catch-all still refuses every pair that crosses the draft-15 boundary,
/// where the two sides carry different shapes. It cannot refuse a pair inside
/// drafts 07-14, where both sides are the same shapeless variant — and that is
/// the pair this test failed on.
#[test]
fn a_frame_from_another_draft_is_refused() {
    if COMPILED_DRAFTS.len() < 2 {
        return;
    }
    let first: Vec<(DraftVersion, Stream)> = COMPILED_DRAFTS
        .iter()
        .map(|&draft| {
            let stream = streams(draft).into_iter().next().expect("a fetch stream on every draft");
            (draft, stream)
        })
        .collect();

    for (source_draft, source) in &first {
        for (target_draft, target) in &first {
            if source_draft == target_draft {
                continue;
            }
            let frame = &source.frames[0];
            let mut writer =
                AnyFetchObjectWriter::new(&target.header, AnyFetchGroupOrder::Ascending)
                    .expect("writer");
            let mut out = Vec::new();
            let err = writer
                .reemit_object(&frame.frame, &frame.raw, &mut out)
                .expect_err("a frame from another draft must not be re-encoded");
            assert!(
                matches!(err, moqtap_codec::error::CodecError::UnsupportedDraft(_)),
                "{source_draft:?} frame onto a {target_draft:?} stream reported {err:?}"
            );
            assert!(
                out.is_empty(),
                "{source_draft:?} onto {target_draft:?}: a refusal wrote bytes"
            );
        }
    }
}

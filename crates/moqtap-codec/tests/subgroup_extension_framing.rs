//! Whose fact is it that a subgroup object carries an extension block?
//!
//! The stream's. Section 9.4.2 gives the SUBGROUP_HEADER type table an
//! Extensions Present column on drafts 11, 12 and 13, and every object on the
//! stream follows it — an object with nothing to put in the block still writes
//! a length of zero on a stream that carries one, and an object holding
//! extensions writes none at all on a stream that does not. So the answer is
//! not a property of the object, and an encoder holding only the object cannot
//! work it out.
//!
//! The codec's draft-neutral writer is handed the header, keeps the answer, and
//! refuses an object that disagrees with it. The per-draft
//! `ObjectHeader::encode` beside it does not take a header, so it has no answer
//! to keep: an entry point built on it can only guess, and "absent" on every
//! call is the guess `encode_checked` is left with. That is the path the client
//! writes objects through.
//!
//! On a stream whose header said otherwise the guess is worse than lossy. The
//! reader is looking for an Extension Headers Length and takes the Object
//! Payload Length in its place, then reads the payload as extension bytes.
//! Where the object is the last thing on the stream that runs off the end and
//! the decode fails; where another object follows — the ordinary case — there
//! are bytes to take, so the decode *succeeds* and hands back an object whose
//! extension block is the payload. Nothing said so at either end: the write
//! returned `Ok` and so did the read.
//!
//! Drafts 07 through 10 cannot reach this. Draft-07 has no extension block, and
//! drafts 08 through 10 give every object one unconditionally, so no header
//! type can disagree with an object and there is nothing to guess. Drafts 14
//! and later hold the framing in a reader object the write path threads
//! through, so the answer reaches the write path rather than being guessed.
//!
//! # What is gated here
//!
//! * that the entry point which cannot know the framing refuses what it would
//!   otherwise drop, and that what it would have written is bytes the stream's
//!   own reader rejects;
//! * that the entry point which is told writes a block that survives the round
//!   trip, and that the legal direction — an empty block on a stream that
//!   carries one — is not refused with it;
//! * that the framing is now reachable from a header without naming its draft,
//!   and that the answer agrees on all the drafts with the writer that
//!   already had it.

#![cfg(all(feature = "draft11", feature = "draft12", feature = "draft13"))]

use moqtap_codec::dispatch::AnySubgroupHeader;
use moqtap_codec::error::CodecError;
use moqtap_codec::varint::VarInt;

fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).expect("fixture value fits a varint")
}

/// Extension bytes chosen so that reading them as anything else is visible.
///
/// None of the three is a plausible length or status, so a decoder that lands
/// on them by mistake produces a value this test can print rather than a
/// coincidentally legal frame.
const EXTENSIONS: [u8; 3] = [0xAA, 0xBB, 0xCC];

/// A draft-11 object holding extensions and a two-byte payload.
fn object_11() -> moqtap_codec::draft11::data_stream::ObjectHeader {
    use moqtap_codec::draft11::data_stream::ObjectHeader;
    use moqtap_codec::draft11::types::ObjectStatus;
    ObjectHeader {
        object_id: varint(0),
        extension_headers_length: varint(EXTENSIONS.len() as u64),
        extensions: EXTENSIONS.to_vec(),
        payload_length: varint(2),
        object_status: ObjectStatus::Normal,
    }
}

/// The write that cannot know the framing refuses the extensions it would lose.
///
/// The refusal is the point, not the error value. `encode_checked` writes the
/// no-extension framing by construction — it is the entry point for a caller
/// who has not been told otherwise — so extensions handed to it have nowhere to
/// go, and the choice is between refusing and putting an unreadable object on
/// the wire.
///
/// Ablation: dropping the `!has_extensions && !self.extensions.is_empty()` arm
/// from draft-11's `encode_checked_with_extensions` fails with
///
/// ```text
/// an object carrying extensions has no encoding in the framing that omits
/// them, so the checked writer must refuse it; it wrote [00, 02]
/// ```
#[test]
fn the_writer_that_was_not_told_refuses_the_extensions_it_would_lose() {
    let mut wrote = Vec::new();
    let result = object_11().encode_checked(&mut wrote);
    assert!(
        matches!(result, Err(CodecError::InvalidField)),
        "an object carrying extensions has no encoding in the framing that omits \
         them, so the checked writer must refuse it; it wrote {wrote:02x?}"
    );
    assert!(wrote.is_empty(), "a refused object must leave the buffer untouched; got {wrote:02x?}");
}

/// An object with nothing to put in the block is still written on a stream that
/// carries one.
///
/// The rule is one-directional and this is the direction that stays legal.
/// Section 9.4.2 fixes the framing for the whole stream, so an object with no
/// extensions writes a length of zero rather than omitting the field, and a
/// check that refused both directions would refuse the ordinary case.
#[test]
fn an_empty_block_is_written_where_the_stream_carries_one() {
    use moqtap_codec::draft11::data_stream::ObjectHeader;
    use moqtap_codec::draft11::types::ObjectStatus;

    let bare = ObjectHeader {
        object_id: varint(4),
        extension_headers_length: varint(0),
        extensions: Vec::new(),
        payload_length: varint(1),
        object_status: ObjectStatus::Normal,
    };
    let mut wire = Vec::new();
    bare.encode_checked_with_extensions(true, &mut wire)
        .expect("an object with no extensions is legal on a stream that carries a block");
    wire.push(0x7F);

    let mut cursor: &[u8] = &wire;
    let back = ObjectHeader::decode_with_extensions(true, &mut cursor)
        .expect("what the writer wrote for this stream is what its reader expects");
    assert_eq!(back.extension_headers_length.into_inner(), 0);
    assert!(back.extensions.is_empty());
    assert_eq!(cursor, [0x7F], "the payload must begin where the header ends");
}

/// Told the framing, the write survives its own reader.
///
/// The whole object goes out and comes back: the extension block is not merely
/// present but the same bytes, and the payload begins where the header ends.
/// Reading the length back alone would pass on a writer that emitted a length
/// and no block.
#[test]
fn told_the_framing_the_object_survives_its_own_reader() {
    use moqtap_codec::draft11::data_stream::ObjectHeader;

    let mut wire = Vec::new();
    object_11()
        .encode_checked_with_extensions(true, &mut wire)
        .expect("a stream that carries a block can hold this object");
    wire.extend_from_slice(&[0xDE, 0xAD]);

    let mut cursor: &[u8] = &wire;
    let back = ObjectHeader::decode_with_extensions(true, &mut cursor)
        .expect("the object the writer produced must be one its reader accepts");
    assert_eq!(back.extensions, EXTENSIONS, "the extension bytes must survive the round trip");
    assert_eq!(back.payload_length.into_inner(), 2);
    assert_eq!(cursor, [0xDE, 0xAD], "the payload must begin where the header ends");
}

/// The guessed framing does not read back as the object that was written, and
/// on a stream with more than one object it does not fail either.
///
/// This is what the refusal is worth, stated as a fact about the wire rather
/// than about an API — and it is worth more than "the decode errors", because
/// in the ordinary case it does not.
///
/// Alone on a stream the object runs out of bytes and the decode fails, which
/// is the benign half. Followed by another object there are bytes to take, so
/// the reader consumes the payload as the extension block, returns `Ok`, and
/// hands back an object whose extension headers are its own payload. Nothing
/// at either end says anything is wrong.
#[test]
fn the_guessed_framing_is_read_back_as_a_different_object() {
    use moqtap_codec::draft11::data_stream::ObjectHeader;

    // What a writer that omits the block emits: the object's own fields, in
    // the framing that leaves the extension block out.
    let mut alone = Vec::new();
    object_11().encode_with_extensions(false, &mut alone);
    alone.extend_from_slice(&[0xDE, 0xAD]);

    let mut cursor: &[u8] = &alone;
    let last_on_the_stream = ObjectHeader::decode_with_extensions(true, &mut cursor);
    assert!(
        last_on_the_stream.is_err(),
        "the last object on the stream has no bytes to borrow, so this one at least \
         fails outright; it produced {last_on_the_stream:02x?}"
    );

    // The same object with a second one behind it, which is what a stream looks
    // like. The Object ID advances, as a subgroup stream requires — and that is
    // what the misframed read reaches for when it goes looking for a payload
    // length, which is why an id of 1 and not 0 is what makes the read succeed.
    let mut followed = alone.clone();
    let mut next = object_11();
    next.object_id = varint(1);
    next.encode_with_extensions(false, &mut followed);
    followed.extend_from_slice(&[0xDE, 0xAD]);

    let mut cursor: &[u8] = &followed;
    let misread = ObjectHeader::decode_with_extensions(true, &mut cursor)
        .expect("with an object behind it the misframed read finds bytes and succeeds");
    assert_ne!(
        misread.extensions, EXTENSIONS,
        "this decode is not supposed to be correct - if it ever is, the guessed \
         framing was not lossy after all and this whole file is arguing with nothing"
    );
    assert_eq!(
        misread.extensions,
        vec![0xDE, 0xAD],
        "the reader takes the payload as the extension block, which is the shape that \
         makes this silent rather than fatal"
    );
}

/// Drafts 12 and 13 carry the same fix, on their own type tables.
///
/// Their type tables are twice the size of draft-11's — an End of Group column
/// doubles every row — so the extensions bit sits somewhere else in the byte,
/// and a fix written against draft-11's numbering alone could pass there and
/// fail here.
#[test]
fn drafts_12_and_13_refuse_and_carry_on_their_own_terms() {
    macro_rules! check {
        ($draft:ident, $label:literal) => {{
            use moqtap_codec::$draft::data_stream::ObjectHeader;
            use moqtap_codec::$draft::types::ObjectStatus;
            let object = ObjectHeader {
                object_id: varint(0),
                extension_headers_length: varint(EXTENSIONS.len() as u64),
                extensions: EXTENSIONS.to_vec(),
                payload_length: varint(2),
                object_status: ObjectStatus::Normal,
            };

            let mut dropped = Vec::new();
            assert!(
                object.encode_checked(&mut dropped).is_err(),
                "{}: the untold writer must refuse extensions it cannot place; it wrote {dropped:02x?}",
                $label
            );

            let mut wire = Vec::new();
            object
                .encode_checked_with_extensions(true, &mut wire)
                .unwrap_or_else(|e| panic!("{}: a stream carrying a block must accept this object: {e:?}", $label));
            wire.extend_from_slice(&[0xDE, 0xAD]);
            let mut cursor: &[u8] = &wire;
            let back = ObjectHeader::decode_with_extensions(true, &mut cursor)
                .unwrap_or_else(|e| panic!("{}: its own reader rejected it: {e:?}", $label));
            assert_eq!(back.extensions, EXTENSIONS, "{}: extension bytes lost", $label);
            assert_eq!(cursor, [0xDE, 0xAD], "{}: payload does not start where the header ends", $label);
        }};
    }

    check!(draft12, "draft-12");
    check!(draft13, "draft-13");
}

// ── The draft-neutral accessor ──────────────────────────────

/// One header per draft per framing, built the way each draft spells it.
///
/// The second element is what that draft's own machinery says the framing is,
/// stated here rather than computed, so a change to a type table has to argue
/// with this list.
fn headers() -> Vec<(&'static str, AnySubgroupHeader, bool)> {
    let mut cases: Vec<(&'static str, AnySubgroupHeader, bool)> = Vec::new();

    {
        use moqtap_codec::draft07::data_stream::SubgroupHeader;
        cases.push((
            "draft-07, which has no extension block at all",
            AnySubgroupHeader::Draft07(SubgroupHeader {
                track_alias: varint(1),
                group_id: varint(2),
                subgroup_id: varint(3),
                publisher_priority: 128,
            }),
            false,
        ));
    }

    macro_rules! always_on {
        ($draft:ident, $variant:ident, $label:literal) => {{
            use moqtap_codec::$draft::data_stream::SubgroupHeader;
            cases.push((
                $label,
                AnySubgroupHeader::$variant(SubgroupHeader {
                    track_alias: varint(1),
                    group_id: varint(2),
                    subgroup_id: varint(3),
                    publisher_priority: 128,
                }),
                true,
            ));
        }};
    }
    always_on!(draft08, Draft08, "draft-08, where every object carries a block");
    always_on!(draft09, Draft09, "draft-09, where every object carries a block");
    always_on!(draft10, Draft10, "draft-10, where every object carries a block");

    macro_rules! gated {
        ($draft:ident, $variant:ident, $label:literal) => {{
            use moqtap_codec::$draft::data_stream::{StreamType, SubgroupHeader};
            for (stream_type, carries, label) in [
                (StreamType::SubgroupExplicit, false, concat!($label, " without extensions")),
                (StreamType::SubgroupExplicitExt, true, concat!($label, " with extensions")),
            ] {
                cases.push((
                    label,
                    AnySubgroupHeader::$variant(SubgroupHeader {
                        stream_type,
                        track_alias: varint(1),
                        group_id: varint(2),
                        subgroup_id: varint(3),
                        publisher_priority: 128,
                    }),
                    carries,
                ));
            }
        }};
    }
    gated!(draft11, Draft11, "draft-11");
    gated!(draft12, Draft12, "draft-12");
    gated!(draft13, Draft13, "draft-13");

    {
        use moqtap_codec::draft14::data_stream::{SubgroupHeader, SubgroupStreamType};
        for (carries, label) in
            [(false, "draft-14 without extensions"), (true, "draft-14 with extensions")]
        {
            cases.push((
                label,
                AnySubgroupHeader::Draft14(SubgroupHeader {
                    stream_type: SubgroupStreamType::from_flags(true, false, carries, false),
                    track_alias: varint(1),
                    group_id: varint(2),
                    subgroup_id: Some(varint(3)),
                    publisher_priority: 128,
                }),
                carries,
            ));
        }
    }

    macro_rules! typed {
        ($draft:ident, $variant:ident, $label:literal) => {{
            use moqtap_codec::$draft::data_stream::SubgroupHeader;
            // An explicit subgroup ID (0x04) on the base bit (0x10), plus the
            // extensions/properties bit (0x01) for the second case.
            for (header_type, carries, label) in [
                (0x14u8, false, concat!($label, " without properties")),
                (0x15u8, true, concat!($label, " with properties")),
            ] {
                cases.push((
                    label,
                    AnySubgroupHeader::$variant(SubgroupHeader {
                        header_type,
                        track_alias: varint(1),
                        group_id: varint(2),
                        subgroup_id: varint(3),
                        publisher_priority: Some(128),
                    }),
                    carries,
                ));
            }
        }};
    }
    typed!(draft15, Draft15, "draft-15");
    typed!(draft16, Draft16, "draft-16");
    typed!(draft17, Draft17, "draft-17");
    typed!(draft18, Draft18, "draft-18");
    typed!(draft19, Draft19, "draft-19");
    typed!(draft20, Draft20, "draft-20");
    typed!(draft21, Draft21, "draft-21");

    cases
}

/// The accessor answers what the header fixes, and the answer survives the
/// wire.
///
/// Twenty-four headers: drafts, both columns of the Extensions Present
/// table on the ten drafts that have one. Encoding and re-decoding each header
/// is what makes this a test of the type byte rather than of a struct field a
/// caller happened to set.
///
/// Ablation: flipping the drafts 11-13 arm of `carries_extension_block` to
/// `!h.stream_type.has_extensions()` fails with
///
/// ```text
/// assertion `left == right` failed: draft-11 without extensions: the accessor
/// disagrees with the framing this header fixes
///   left: true
///  right: false
/// ```
#[test]
fn the_accessor_reports_the_framing_the_header_fixes() {
    for (name, header, expected) in headers() {
        assert_eq!(
            header.carries_extension_block(),
            expected,
            "{name}: the accessor disagrees with the framing this header fixes"
        );

        let mut wire = Vec::new();
        header.encode_stream(&mut wire);
        let mut cursor: &[u8] = &wire;
        let reopened = AnySubgroupHeader::decode_stream(header.draft(), &mut cursor)
            .unwrap_or_else(|e| panic!("{name}: the header did not survive its own writer: {e:?}"));
        assert_eq!(
            reopened.carries_extension_block(),
            expected,
            "{name}: the framing did not survive the wire"
        );
    }
}

/// The accessor agrees with the writer that already held the answer.
///
/// `AnySubgroupObjectWriter` takes the header, keeps the framing and refuses an
/// object that disagrees with it. That behaviour predates this accessor and is
/// gated elsewhere, which makes it an independent authority: if the accessor
/// says a stream carries no block, the writer must refuse an object holding
/// extensions, and if it says the stream carries one, the writer must accept.
///
/// Draft-08 is excluded from the accepting half. Its block is count-prefixed
/// rather than length-prefixed, so a raw blob without a matching
/// `extension_count` is not something the writer can place, and the refusal
/// there says nothing about the framing.
#[test]
fn the_accessor_predicts_what_the_draft_neutral_writer_accepts() {
    use moqtap_codec::data_dispatch::{AnySubgroupObject, AnySubgroupObjectWriter};
    use moqtap_codec::version::DraftVersion;

    for (name, header, carries) in headers() {
        let mut writer = AnySubgroupObjectWriter::new(&header)
            .unwrap_or_else(|e| panic!("{name}: the writer would not open this stream: {e:?}"));
        let object = AnySubgroupObject {
            object_id: 0,
            extension_headers: EXTENSIONS.to_vec(),
            extension_count: None,
            status: None,
            payload: vec![0xDE, 0xAD],
        };
        let wrote = writer.write_object(&object, &mut Vec::new());

        if carries {
            if header.draft() == DraftVersion::Draft08 {
                continue;
            }
            assert!(
                wrote.is_ok(),
                "{name}: the accessor says this stream carries a block, but the writer \
                 that holds the same fact refused an object with one: {wrote:?}"
            );
        } else {
            assert!(
                wrote.is_err(),
                "{name}: the accessor says this stream carries no block, but the writer \
                 that holds the same fact accepted an object with extensions"
            );
        }
    }
}

// ── The Subgroup ID the type decides not to write ───────────

/// A Subgroup ID under a type that names the subgroup itself is refused, not
/// dropped.
///
/// The same shape as the extension block one column over: Section 9.4.2's type
/// table has a Subgroup ID Field Present column, and where it reads No the
/// value in hand goes nowhere. What comes back is the subgroup the *type* names
/// — zero, or the first Object's ID — so the peer reads a perfectly good stream
/// for a subgroup nobody asked for, and no length or checksum is wrong.
///
/// A zero is accepted under every type, because a zero is what the decoder
/// produces for the types that carry no field, and refusing it would refuse
/// every header that has been round-tripped.
///
/// Ablation: dropping the check from draft-11's `SubgroupHeader::encode_checked`
/// fails with
///
/// ```text
/// draft-11: a Subgroup ID this stream type has nowhere to put must be refused
/// rather than dropped; it wrote [01, 02, 80]
/// ```
#[test]
fn a_subgroup_id_the_stream_type_cannot_carry_is_refused() {
    macro_rules! check {
        ($draft:ident, $label:literal) => {{
            use moqtap_codec::$draft::data_stream::{StreamType, SubgroupHeader};
            let build = |stream_type, subgroup_id| SubgroupHeader {
                stream_type,
                track_alias: varint(1),
                group_id: varint(2),
                subgroup_id: varint(subgroup_id),
                publisher_priority: 128,
            };

            let mut wrote = Vec::new();
            let refused = build(StreamType::SubgroupZero, 7).encode_checked(&mut wrote);
            assert!(
                refused.is_err(),
                "{}: a Subgroup ID this stream type has nowhere to put must be refused \
                 rather than dropped; it wrote {wrote:02x?}",
                $label
            );

            // What it would have written, and why nothing downstream could tell.
            let mut anyway = Vec::new();
            build(StreamType::SubgroupZero, 7).encode(&mut anyway);
            let mut cursor: &[u8] = &anyway;
            let decoded = SubgroupHeader::decode_with_type(StreamType::SubgroupZero, &mut cursor)
                .unwrap_or_else(|e| panic!("{}: the substituted header is well formed, which is the problem: {e:?}", $label));
            assert_eq!(
                decoded.subgroup_id.into_inner(),
                0,
                "{}: the peer reads subgroup 0 and has no way to know it was not asked for",
                $label
            );

            // The two shapes that agree are written, zero included.
            for (stream_type, subgroup_id, which) in [
                (StreamType::SubgroupZero, 0, "an implicit-zero type with a zero"),
                (StreamType::SubgroupExplicit, 0, "an explicit type with a zero"),
                (StreamType::SubgroupExplicit, 7, "an explicit type with an id"),
            ] {
                build(stream_type, subgroup_id)
                    .encode_checked(&mut Vec::new())
                    .unwrap_or_else(|e| panic!("{}: {which} must be written: {e:?}", $label));
            }
        }};
    }

    check!(draft11, "draft-11");
    check!(draft12, "draft-12");
    check!(draft13, "draft-13");
}

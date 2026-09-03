//! Re-encoding a fetch stream's objects against a predecessor that changed.
//!
//! Drafts 15 through 20 encode a fetch object's Group ID, Subgroup ID, Object
//! ID and Priority against the object before it, so removing one object from
//! such a stream is not byte deletion: the object that follows the gap was
//! encoded against something that is no longer there. Drafts 07 through 14
//! write those fields absolutely on a fetch stream and need none of this.
//!
//! # Why the survivors have to be re-encoded and not just re-checked
//!
//! What changes is not one field's value. An object that carried no Group ID
//! Delta because it shared its predecessor's group needs one once that
//! predecessor is gone, and from draft-19 that means a flag bit is set that was
//! clear and a field appears where there was none. The subgroup stream's
//! counterpart, `reemit_subgroup_object`, rewrites exactly one leading varint
//! and copies the rest — nothing about that shape transfers here.
//!
//! # What each gate observes
//!
//! Two consequences, and the second is the one that matters. A stream written
//! back with nothing removed is reproduced **byte for byte**, which is what
//! says the writer is the reader's inverse rather than merely a valid encoder.
//! Then a stream with one object removed is decoded again from the bytes the
//! writer produced, and every survivor must resolve to the same Group ID,
//! Subgroup ID, Object ID and Priority it had on the original stream. That
//! second gate is the corruption the proxy would otherwise ship: a survivor
//! that decodes to a different Object ID is not a dropped object, it is a
//! renumbered stream, and nothing about the bytes looks wrong.
//!
//! # Ablation, measured
//!
//! Forwarding each object's own header instead of re-encoding it - which is
//! exactly what byte deletion does - cut in all five drafts at once. Thirteen
//! of the twenty-three gates fail, and **the five byte-identity gates are
//! among the ones that still pass**, which is the whole reason the second
//! gate exists: verbatim forwarding is byte-perfect on a stream with nothing
//! removed.
//!
//! ```text
//! assertion `left == right` failed: a survivor was renumbered by the removal
//!   left: [(10, Some(3), 0, Some(128)), (10, Some(3), 1, Some(128)),
//!          (11, Some(3), 0, Some(128))]
//!  right: [(10, Some(3), 0, Some(128)), (10, Some(3), 2, Some(128)),
//!          (11, Some(3), 0, Some(128))]
//! ```
//!
//! Object 2 arrives at the subscriber as object 1. Nothing errors, nothing
//! looks short, and the stream is one object's worth of numbering out for the
//! rest of its life.

// ─────────────────────────────────────────────────────────────
// Draft-19: signed group deltas, and the fullest flag set
// ─────────────────────────────────────────────────────────────

#[cfg(feature = "draft19")]
mod draft19 {
    use moqtap_codec::draft19::data_stream::{
        FetchObject, FetchObjectHeader, FetchObjectReader, FetchObjectWriter, GroupOrder,
    };
    use moqtap_codec::varint::VarInt;

    fn v(n: u64) -> VarInt {
        VarInt::from_u64(n).unwrap()
    }

    /// A header with nothing on the wire but its flags and payload length.
    fn header(flags: u64, payload_length: u64) -> FetchObjectHeader {
        FetchObjectHeader {
            serialization_flags: v(flags),
            group_id_delta: None,
            subgroup_id: None,
            object_id_delta: None,
            publisher_priority: None,
            properties: None,
            payload_length: v(payload_length),
        }
    }

    /// A four-object draft-19 fetch stream, built one header at a time so that what
    /// each object puts on the wire is chosen here rather than derived.
    ///
    /// Objects B and C inherit everything they can from their predecessors, which
    /// is what makes them the interesting survivors: neither carries a Group ID,
    /// neither carries a Priority, and C carries no Object ID Delta either.
    fn sample_stream() -> Vec<u8> {
        let mut wire = Vec::new();

        // A: the first object, which must state both deltas absolutely. Group 10,
        // subgroup 3 explicitly, object 0, priority 128.
        let mut a = header(0x08 | 0x04 | 0x10 | 0b11, 2);
        a.group_id_delta = Some(v(10));
        a.subgroup_id = Some(v(3));
        a.object_id_delta = Some(v(0));
        a.publisher_priority = Some(128);
        a.encode(&mut wire).unwrap();
        wire.extend_from_slice(&[0xca, 0xfe]);

        // B: same group, subgroup inherited, priority inherited, object 1 by way of
        // an explicit delta of 1.
        let mut b = header(0x04 | 0b01, 1);
        b.object_id_delta = Some(v(1));
        b.encode(&mut wire).unwrap();
        wire.extend_from_slice(&[0x01]);

        // C: everything inherited and no Object ID Delta at all, which reads as the
        // predecessor's object plus one - object 2.
        let c = header(0b01, 1);
        c.encode(&mut wire).unwrap();
        wire.extend_from_slice(&[0x02]);

        // D: a new group. Delta 0 means "the next group along" under Ascending, so
        // group 11, and the Object ID restarts from its own delta.
        let mut d = header(0x08 | 0x04 | 0b01, 1);
        d.group_id_delta = Some(v(0));
        d.object_id_delta = Some(v(0));
        d.encode(&mut wire).unwrap();
        wire.extend_from_slice(&[0x03]);

        wire
    }

    /// Every frame on `wire`, with its payload, resolved by one reader.
    fn read_all(wire: &[u8]) -> Vec<(FetchObject, Vec<u8>)> {
        let mut reader = FetchObjectReader::new(GroupOrder::Ascending);
        let mut cursor: &[u8] = wire;
        let mut out = Vec::new();
        while !cursor.is_empty() {
            let frame = reader.read_object_header(&mut cursor).expect("decode");
            let len = frame.header.payload_length.into_inner() as usize;
            let (payload, rest) = cursor.split_at(len);
            let payload = payload.to_vec();
            cursor = rest;
            out.push((frame, payload));
        }
        out
    }

    /// Write `frames` back onto a fresh stream.
    fn write_all(frames: &[(FetchObject, Vec<u8>)]) -> Vec<u8> {
        let mut writer = FetchObjectWriter::new(GroupOrder::Ascending);
        let mut out = Vec::new();
        for (frame, payload) in frames {
            writer.write_object_header(frame, &mut out).expect("encode");
            out.extend_from_slice(payload);
        }
        out
    }

    /// The identity a survivor must still have after the stream is rewritten.
    fn identity(frame: &FetchObject) -> (u64, Option<u64>, u64, Option<u8>) {
        (frame.group_id, frame.subgroup_id, frame.object_id, frame.publisher_priority)
    }

    /// A stream with nothing removed comes back byte for byte.
    ///
    /// This is what says the writer is the reader's inverse and not merely some
    /// valid encoder: a proxy that rewrote every object it forwarded would pass a
    /// gate that only checked what the bytes decode to, while changing the bytes of
    /// every stream it touched.
    ///
    /// Choosing a canonical shape instead of the frame's own - always writing the
    /// Object ID Delta rather than keeping C's omission - fails with:
    ///
    /// ```text
    /// assertion `left == right` failed: a stream with nothing removed was
    /// rewritten
    /// ```
    #[test]
    fn a_stream_written_back_unchanged_is_byte_identical() {
        let wire = sample_stream();
        let frames = read_all(&wire);
        assert_eq!(frames.len(), 4, "the sample stream is four objects");
        assert_eq!(write_all(&frames), wire, "a stream with nothing removed was rewritten");
    }

    /// The sample stream decodes to the identities the builder above intended.
    ///
    /// Without this the gates below would hold a rewrite against whatever the
    /// original happened to mean, which is a comparison that passes even when both
    /// sides are wrong.
    #[test]
    fn the_sample_stream_says_what_it_was_built_to_say() {
        let frames = read_all(&sample_stream());
        let ids: Vec<_> = frames.iter().map(|(f, _)| identity(f)).collect();
        assert_eq!(
            ids,
            vec![
                (10, Some(3), 0, Some(128)),
                (10, Some(3), 1, Some(128)),
                (10, Some(3), 2, Some(128)),
                (11, Some(3), 0, Some(128)),
            ],
        );
    }

    /// Removing an object leaves every survivor resolving to itself.
    ///
    /// Object B is removed, so C - which carried no Object ID Delta and meant "one
    /// past my predecessor" - now follows A and has to say 2 outright. D follows C,
    /// whose identity did not change, so D's own bytes are untouched.
    ///
    /// Dropping the re-encode and deleting B's bytes instead is the shape this
    /// exists to refuse:
    ///
    /// ```text
    /// assertion `left == right` failed: a survivor was renumbered by the removal
    ///   left: [(10, Some(3), 0, Some(128)), (10, Some(3), 1, Some(128)),
    ///          (11, Some(3), 0, Some(128))]
    ///  right: [(10, Some(3), 0, Some(128)), (10, Some(3), 2, Some(128)),
    ///          (11, Some(3), 0, Some(128))]
    /// ```
    #[test]
    fn a_survivor_after_a_removed_object_still_resolves_to_itself() {
        let frames = read_all(&sample_stream());
        let want: Vec<_> = frames
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != 1)
            .map(|(_, (f, _))| identity(f))
            .collect();

        let kept: Vec<_> =
            frames.into_iter().enumerate().filter(|(i, _)| *i != 1).map(|(_, f)| f).collect();
        let rewritten = write_all(&kept);

        let got: Vec<_> = read_all(&rewritten).iter().map(|(f, _)| identity(f)).collect();
        assert_eq!(got, want, "a survivor was renumbered by the removal");
    }

    /// Removing the *first* object works the same way, which is the case the
    /// subgroup stream refuses.
    ///
    /// A subgroup stream may define its Subgroup ID as the first object's ID, so
    /// eliding index 0 there redefines it for the receiver. A fetch object names
    /// its subgroup by its own flags, so there is nothing for the first object to
    /// define and B simply becomes the object that states both deltas absolutely.
    #[test]
    fn removing_the_first_object_promotes_the_second() {
        let frames = read_all(&sample_stream());
        let want: Vec<_> = frames.iter().skip(1).map(|(f, _)| identity(f)).collect();

        let kept: Vec<_> = frames.into_iter().skip(1).collect();
        let got: Vec<_> = read_all(&write_all(&kept)).iter().map(|(f, _)| identity(f)).collect();
        assert_eq!(got, want, "a survivor was renumbered by the removal");
    }

    /// An object that does not advance past its predecessor has no encoding, and is
    /// refused rather than given one.
    ///
    /// The Object ID is the predecessor's plus the delta, or plus one with no delta
    /// at all, so there is no field value that says "the same object again". A
    /// writer that clamped to a delta of zero would put a duplicate Object ID on
    /// the wire.
    #[test]
    fn an_object_that_does_not_advance_is_refused() {
        let frames = read_all(&sample_stream());
        let mut writer = FetchObjectWriter::new(GroupOrder::Ascending);
        let mut out = Vec::new();
        writer.write_object_header(&frames[2].0, &mut out).expect("the first object is free");
        let err = writer
            .write_object_header(&frames[0].0, &mut out)
            .expect_err("object 0 cannot follow object 2");
        assert!(matches!(err, moqtap_codec::error::CodecError::InvalidField), "got {err:?}");
    }

    /// A Group ID that moves against the FETCH's Group Order is refused too.
    ///
    /// Under Descending a delta subtracts, so a group that increased cannot be
    /// expressed at all. Writing the ascending delta anyway would decode, on the
    /// subscriber's side, to a group walking the wrong way.
    #[test]
    fn a_group_moving_against_the_group_order_is_refused() {
        let frames = read_all(&sample_stream());
        let mut writer = FetchObjectWriter::new(GroupOrder::Descending);
        let mut out = Vec::new();
        writer.write_object_header(&frames[0].0, &mut out).expect("the first object is free");
        let err = writer
            .write_object_header(&frames[3].0, &mut out)
            .expect_err("group 11 cannot follow group 10 while descending");
        assert!(matches!(err, moqtap_codec::error::CodecError::InvalidField), "got {err:?}");
    }
}

// ─────────────────────────────────────────────────────────────
// Draft-20: the same flag set, plus a third End of Range marker
// ─────────────────────────────────────────────────────────────

#[cfg(feature = "draft20")]
mod draft20 {
    use moqtap_codec::draft20::data_stream::{
        FetchObject, FetchObjectHeader, FetchObjectReader, FetchObjectWriter, GroupOrder,
    };
    use moqtap_codec::varint::VarInt;

    fn v(n: u64) -> VarInt {
        VarInt::from_u64(n).unwrap()
    }

    /// A header with nothing on the wire but its flags and payload length.
    fn header(flags: u64, payload_length: u64) -> FetchObjectHeader {
        FetchObjectHeader {
            serialization_flags: v(flags),
            group_id_delta: None,
            subgroup_id: None,
            object_id_delta: None,
            publisher_priority: None,
            properties: None,
            payload_length: v(payload_length),
        }
    }

    /// A four-object draft-20 fetch stream, built one header at a time so that what
    /// each object puts on the wire is chosen here rather than derived.
    ///
    /// Objects B and C inherit everything they can from their predecessors, which
    /// is what makes them the interesting survivors: neither carries a Group ID,
    /// neither carries a Priority, and C carries no Object ID Delta either.
    fn sample_stream() -> Vec<u8> {
        let mut wire = Vec::new();

        // A: the first object, which must state both deltas absolutely. Group 10,
        // subgroup 3 explicitly, object 0, priority 128.
        let mut a = header(0x08 | 0x04 | 0x10 | 0b11, 2);
        a.group_id_delta = Some(v(10));
        a.subgroup_id = Some(v(3));
        a.object_id_delta = Some(v(0));
        a.publisher_priority = Some(128);
        a.encode(&mut wire).unwrap();
        wire.extend_from_slice(&[0xca, 0xfe]);

        // B: same group, subgroup inherited, priority inherited, object 1 by way of
        // an explicit delta of 1.
        let mut b = header(0x04 | 0b01, 1);
        b.object_id_delta = Some(v(1));
        b.encode(&mut wire).unwrap();
        wire.extend_from_slice(&[0x01]);

        // C: everything inherited and no Object ID Delta at all, which reads as the
        // predecessor's object plus one - object 2.
        let c = header(0b01, 1);
        c.encode(&mut wire).unwrap();
        wire.extend_from_slice(&[0x02]);

        // D: a new group. Delta 0 means "the next group along" under Ascending, so
        // group 11, and the Object ID restarts from its own delta.
        let mut d = header(0x08 | 0x04 | 0b01, 1);
        d.group_id_delta = Some(v(0));
        d.object_id_delta = Some(v(0));
        d.encode(&mut wire).unwrap();
        wire.extend_from_slice(&[0x03]);

        wire
    }

    /// Every frame on `wire`, with its payload, resolved by one reader.
    fn read_all(wire: &[u8]) -> Vec<(FetchObject, Vec<u8>)> {
        let mut reader = FetchObjectReader::new(GroupOrder::Ascending);
        let mut cursor: &[u8] = wire;
        let mut out = Vec::new();
        while !cursor.is_empty() {
            let frame = reader.read_object_header(&mut cursor).expect("decode");
            let len = frame.header.payload_length.into_inner() as usize;
            let (payload, rest) = cursor.split_at(len);
            let payload = payload.to_vec();
            cursor = rest;
            out.push((frame, payload));
        }
        out
    }

    /// Write `frames` back onto a fresh stream.
    fn write_all(frames: &[(FetchObject, Vec<u8>)]) -> Vec<u8> {
        let mut writer = FetchObjectWriter::new(GroupOrder::Ascending);
        let mut out = Vec::new();
        for (frame, payload) in frames {
            writer.write_object_header(frame, &mut out).expect("encode");
            out.extend_from_slice(payload);
        }
        out
    }

    /// The identity a survivor must still have after the stream is rewritten.
    fn identity(frame: &FetchObject) -> (u64, Option<u64>, u64, Option<u8>) {
        (frame.group_id, frame.subgroup_id, frame.object_id, frame.publisher_priority)
    }

    /// A stream with nothing removed comes back byte for byte.
    ///
    /// This is what says the writer is the reader's inverse and not merely some
    /// valid encoder: a proxy that rewrote every object it forwarded would pass a
    /// gate that only checked what the bytes decode to, while changing the bytes of
    /// every stream it touched.
    ///
    /// Choosing a canonical shape instead of the frame's own - always writing the
    /// Object ID Delta rather than keeping C's omission - fails with:
    ///
    /// ```text
    /// assertion `left == right` failed: a stream with nothing removed was
    /// rewritten
    /// ```
    #[test]
    fn a_stream_written_back_unchanged_is_byte_identical() {
        let wire = sample_stream();
        let frames = read_all(&wire);
        assert_eq!(frames.len(), 4, "the sample stream is four objects");
        assert_eq!(write_all(&frames), wire, "a stream with nothing removed was rewritten");
    }

    /// The sample stream decodes to the identities the builder above intended.
    ///
    /// Without this the gates below would hold a rewrite against whatever the
    /// original happened to mean, which is a comparison that passes even when both
    /// sides are wrong.
    #[test]
    fn the_sample_stream_says_what_it_was_built_to_say() {
        let frames = read_all(&sample_stream());
        let ids: Vec<_> = frames.iter().map(|(f, _)| identity(f)).collect();
        assert_eq!(
            ids,
            vec![
                (10, Some(3), 0, Some(128)),
                (10, Some(3), 1, Some(128)),
                (10, Some(3), 2, Some(128)),
                (11, Some(3), 0, Some(128)),
            ],
        );
    }

    /// Removing an object leaves every survivor resolving to itself.
    ///
    /// Object B is removed, so C - which carried no Object ID Delta and meant "one
    /// past my predecessor" - now follows A and has to say 2 outright. D follows C,
    /// whose identity did not change, so D's own bytes are untouched.
    ///
    /// Dropping the re-encode and deleting B's bytes instead is the shape this
    /// exists to refuse:
    ///
    /// ```text
    /// assertion `left == right` failed: a survivor was renumbered by the removal
    ///   left: [(10, Some(3), 0, Some(128)), (10, Some(3), 1, Some(128)),
    ///          (11, Some(3), 0, Some(128))]
    ///  right: [(10, Some(3), 0, Some(128)), (10, Some(3), 2, Some(128)),
    ///          (11, Some(3), 0, Some(128))]
    /// ```
    #[test]
    fn a_survivor_after_a_removed_object_still_resolves_to_itself() {
        let frames = read_all(&sample_stream());
        let want: Vec<_> = frames
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != 1)
            .map(|(_, (f, _))| identity(f))
            .collect();

        let kept: Vec<_> =
            frames.into_iter().enumerate().filter(|(i, _)| *i != 1).map(|(_, f)| f).collect();
        let rewritten = write_all(&kept);

        let got: Vec<_> = read_all(&rewritten).iter().map(|(f, _)| identity(f)).collect();
        assert_eq!(got, want, "a survivor was renumbered by the removal");
    }

    /// Removing the *first* object works the same way, which is the case the
    /// subgroup stream refuses.
    ///
    /// A subgroup stream may define its Subgroup ID as the first object's ID, so
    /// eliding index 0 there redefines it for the receiver. A fetch object names
    /// its subgroup by its own flags, so there is nothing for the first object to
    /// define and B simply becomes the object that states both deltas absolutely.
    #[test]
    fn removing_the_first_object_promotes_the_second() {
        let frames = read_all(&sample_stream());
        let want: Vec<_> = frames.iter().skip(1).map(|(f, _)| identity(f)).collect();

        let kept: Vec<_> = frames.into_iter().skip(1).collect();
        let got: Vec<_> = read_all(&write_all(&kept)).iter().map(|(f, _)| identity(f)).collect();
        assert_eq!(got, want, "a survivor was renumbered by the removal");
    }

    /// An object that does not advance past its predecessor has no encoding, and is
    /// refused rather than given one.
    ///
    /// The Object ID is the predecessor's plus the delta, or plus one with no delta
    /// at all, so there is no field value that says "the same object again". A
    /// writer that clamped to a delta of zero would put a duplicate Object ID on
    /// the wire.
    #[test]
    fn an_object_that_does_not_advance_is_refused() {
        let frames = read_all(&sample_stream());
        let mut writer = FetchObjectWriter::new(GroupOrder::Ascending);
        let mut out = Vec::new();
        writer.write_object_header(&frames[2].0, &mut out).expect("the first object is free");
        let err = writer
            .write_object_header(&frames[0].0, &mut out)
            .expect_err("object 0 cannot follow object 2");
        assert!(matches!(err, moqtap_codec::error::CodecError::InvalidField), "got {err:?}");
    }

    /// A Group ID that moves against the FETCH's Group Order is refused too.
    ///
    /// Under Descending a delta subtracts, so a group that increased cannot be
    /// expressed at all. Writing the ascending delta anyway would decode, on the
    /// subscriber's side, to a group walking the wrong way.
    #[test]
    fn a_group_moving_against_the_group_order_is_refused() {
        let frames = read_all(&sample_stream());
        let mut writer = FetchObjectWriter::new(GroupOrder::Descending);
        let mut out = Vec::new();
        writer.write_object_header(&frames[0].0, &mut out).expect("the first object is free");
        let err = writer
            .write_object_header(&frames[3].0, &mut out)
            .expect_err("group 11 cannot follow group 10 while descending");
        assert!(matches!(err, moqtap_codec::error::CodecError::InvalidField), "got {err:?}");
    }

    /// An End of Range marker survives a removal in front of it, because the
    /// writer re-derives its two fields against the new predecessor.
    ///
    /// Draft-19's writer reproduced a marker's bytes verbatim, on the reading
    /// that its Group ID and Object ID are absolute. Draft-20's corpus reads
    /// them as ordinary deltas — Section 11.4.4.2 says only that the two
    /// fields "are present" and settles neither — so a marker after a removed
    /// object is exactly the frame that needs reframing, and forwarding its
    /// bytes would move the Location it names.
    ///
    /// # Ablation
    ///
    /// Restoring draft-19's verbatim marker arm in
    /// `FetchObjectWriter::header_for`:
    ///
    /// ```text
    /// assertion `left == right` failed: the marker was moved by a removal in front of it
    ///   left: [(10, None, 9, Some(128))]
    ///  right: [(11, None, 9, Some(128))]
    /// ```
    #[test]
    fn an_end_of_range_marker_is_reframed_against_the_new_predecessor() {
        for flags in [0x8Cu64, 0x10C, 0x20C] {
            let mut wire = Vec::new();

            // Two ordinary objects in groups 10 and 11, then a marker whose
            // Group ID Delta of 0 puts it in group 12.
            let mut a = header(0x08 | 0x04 | 0x10 | 0b11, 1);
            a.group_id_delta = Some(v(10));
            a.subgroup_id = Some(v(3));
            a.object_id_delta = Some(v(0));
            a.publisher_priority = Some(128);
            a.encode(&mut wire).unwrap();
            wire.push(0xaa);

            let mut b = header(0x08 | 0x04 | 0b01, 1);
            b.group_id_delta = Some(v(0));
            b.object_id_delta = Some(v(0));
            b.encode(&mut wire).unwrap();
            wire.push(0xbb);

            let mut marker = header(flags, 0);
            marker.group_id_delta = Some(v(0));
            marker.object_id_delta = Some(v(9));
            marker.encode(&mut wire).unwrap();

            let frames = read_all(&wire);
            assert_eq!(frames.len(), 3);
            let marker_identity = identity(&frames[2].0);
            assert_eq!(
                marker_identity.0, 12,
                "flags {flags:#x}: the marker resolves against the object before it"
            );

            // A stream with nothing removed is reproduced byte for byte.
            assert_eq!(write_all(&frames), wire, "flags {flags:#x}: an untouched stream moved");

            // Drop the middle object. The marker must keep naming {12, 9}.
            let kept: Vec<_> =
                frames.into_iter().enumerate().filter(|(i, _)| *i != 1).map(|(_, f)| f).collect();
            let got: Vec<_> = read_all(&write_all(&kept)).iter().map(identity_of).collect();
            assert_eq!(
                got.last().copied(),
                Some(marker_identity),
                "flags {flags:#x}: the marker was moved by a removal in front of it"
            );
        }
    }

    fn identity_of(frame: &(FetchObject, Vec<u8>)) -> (u64, Option<u64>, u64, Option<u8>) {
        identity(&frame.0)
    }
}

// ─────────────────────────────────────────────────────────────
// Draft-18: the same deltas, and the same Group Order behind them
// ─────────────────────────────────────────────────────────────

#[cfg(feature = "draft18")]
mod draft18 {
    use moqtap_codec::draft18::data_stream::{
        FetchObject, FetchObjectHeader, FetchObjectReader, FetchObjectWriter, GroupOrder,
    };
    use moqtap_codec::varint::VarInt;

    fn v(n: u64) -> VarInt {
        VarInt::from_u64(n).unwrap()
    }

    fn header(flags: u64, payload_length: u64) -> FetchObjectHeader {
        FetchObjectHeader {
            serialization_flags: flags,
            group_id_delta: None,
            subgroup_id: None,
            object_id_delta: None,
            publisher_priority: None,
            properties: Vec::new(),
            payload_length: v(payload_length),
        }
    }

    /// Four objects: A states everything, B and C inherit what they can, and D
    /// opens a new group.
    fn sample_stream() -> Vec<u8> {
        let mut wire = Vec::new();

        let mut a = header(0x08 | 0x04 | 0x10 | 0b11, 2);
        a.group_id_delta = Some(v(10));
        a.subgroup_id = Some(v(3));
        a.object_id_delta = Some(v(0));
        a.publisher_priority = Some(128);
        a.encode(&mut wire).unwrap();
        wire.extend_from_slice(&[0xca, 0xfe]);

        let mut b = header(0x04 | 0b01, 1);
        b.object_id_delta = Some(v(1));
        b.encode(&mut wire).unwrap();
        wire.extend_from_slice(&[0x01]);

        let c = header(0b01, 1);
        c.encode(&mut wire).unwrap();
        wire.extend_from_slice(&[0x02]);

        let mut d = header(0x08 | 0x04 | 0b01, 1);
        d.group_id_delta = Some(v(0));
        d.object_id_delta = Some(v(0));
        d.encode(&mut wire).unwrap();
        wire.extend_from_slice(&[0x03]);

        wire
    }

    fn read_all(wire: &[u8]) -> Vec<(FetchObject, Vec<u8>)> {
        let mut reader = FetchObjectReader::new(GroupOrder::Ascending);
        let mut cursor: &[u8] = wire;
        let mut out = Vec::new();
        while !cursor.is_empty() {
            let frame = reader.read_object_header(&mut cursor).expect("decode");
            let len = frame.header.payload_length.into_inner() as usize;
            let (payload, rest) = cursor.split_at(len);
            let payload = payload.to_vec();
            cursor = rest;
            out.push((frame, payload));
        }
        out
    }

    fn write_all(frames: &[(FetchObject, Vec<u8>)]) -> Vec<u8> {
        let mut writer = FetchObjectWriter::new(GroupOrder::Ascending);
        let mut out = Vec::new();
        for (frame, payload) in frames {
            writer.write_object_header(frame, &mut out).expect("encode");
            out.extend_from_slice(payload);
        }
        out
    }

    fn identity(frame: &FetchObject) -> (u64, Option<u64>, u64, Option<u8>) {
        (frame.group_id, frame.subgroup_id, frame.object_id, frame.publisher_priority)
    }

    #[test]
    fn a_stream_written_back_unchanged_is_byte_identical() {
        let wire = sample_stream();
        let frames = read_all(&wire);
        assert_eq!(frames.len(), 4);
        assert_eq!(write_all(&frames), wire, "a stream with nothing removed was rewritten");
    }

    #[test]
    fn the_sample_stream_says_what_it_was_built_to_say() {
        let ids: Vec<_> = read_all(&sample_stream()).iter().map(|(f, _)| identity(f)).collect();
        assert_eq!(
            ids,
            vec![
                (10, Some(3), 0, Some(128)),
                (10, Some(3), 1, Some(128)),
                (10, Some(3), 2, Some(128)),
                (11, Some(3), 0, Some(128)),
            ],
        );
    }

    #[test]
    fn a_survivor_after_a_removed_object_still_resolves_to_itself() {
        let frames = read_all(&sample_stream());
        let want: Vec<_> = frames
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != 1)
            .map(|(_, (f, _))| identity(f))
            .collect();
        let kept: Vec<_> =
            frames.into_iter().enumerate().filter(|(i, _)| *i != 1).map(|(_, f)| f).collect();
        let got: Vec<_> = read_all(&write_all(&kept)).iter().map(|(f, _)| identity(f)).collect();
        assert_eq!(got, want, "a survivor was renumbered by the removal");
    }

    #[test]
    fn removing_the_first_object_promotes_the_second() {
        let frames = read_all(&sample_stream());
        let want: Vec<_> = frames.iter().skip(1).map(|(f, _)| identity(f)).collect();
        let kept: Vec<_> = frames.into_iter().skip(1).collect();
        let got: Vec<_> = read_all(&write_all(&kept)).iter().map(|(f, _)| identity(f)).collect();
        assert_eq!(got, want, "a survivor was renumbered by the removal");
    }

    #[test]
    fn a_group_moving_against_the_group_order_is_refused() {
        let frames = read_all(&sample_stream());
        let mut writer = FetchObjectWriter::new(GroupOrder::Descending);
        let mut out = Vec::new();
        writer.write_object_header(&frames[0].0, &mut out).expect("the first object is free");
        let err = writer
            .write_object_header(&frames[3].0, &mut out)
            .expect_err("group 11 cannot follow group 10 while descending");
        assert!(matches!(err, moqtap_codec::error::CodecError::InvalidField), "got {err:?}");
    }
}

// ─────────────────────────────────────────────────────────────
// Draft-17: absolute values, stateful omission
// ─────────────────────────────────────────────────────────────

#[cfg(feature = "draft17")]
mod draft17 {
    use moqtap_codec::draft17::data_stream::{
        FetchObject, FetchObjectHeader, FetchObjectReader, FetchObjectWriter,
    };
    use moqtap_codec::varint::VarInt;

    fn v(n: u64) -> VarInt {
        VarInt::from_u64(n).unwrap()
    }

    fn header(flags: u64, payload_length: u64) -> FetchObjectHeader {
        FetchObjectHeader {
            serialization_flags: v(flags),
            group_id: None,
            subgroup_id: None,
            object_id: None,
            publisher_priority: None,
            properties: Vec::new(),
            payload_length: v(payload_length),
        }
    }

    fn sample_stream() -> Vec<u8> {
        let mut wire = Vec::new();

        let mut a = header(0x08 | 0x04 | 0x10 | 0x03, 2);
        a.group_id = Some(v(10));
        a.subgroup_id = Some(v(3));
        a.object_id = Some(v(0));
        a.publisher_priority = Some(128);
        a.encode(&mut wire).unwrap();
        wire.extend_from_slice(&[0xca, 0xfe]);

        let mut b = header(0x04 | 0x01, 1);
        b.object_id = Some(v(1));
        b.encode(&mut wire).unwrap();
        wire.extend_from_slice(&[0x01]);

        let c = header(0x01, 1);
        c.encode(&mut wire).unwrap();
        wire.extend_from_slice(&[0x02]);

        let mut d = header(0x08 | 0x04 | 0x01, 1);
        d.group_id = Some(v(11));
        d.object_id = Some(v(0));
        d.encode(&mut wire).unwrap();
        wire.extend_from_slice(&[0x03]);

        wire
    }

    fn read_all(wire: &[u8]) -> Vec<(FetchObject, Vec<u8>)> {
        let mut reader = FetchObjectReader::new();
        let mut cursor: &[u8] = wire;
        let mut out = Vec::new();
        while !cursor.is_empty() {
            let frame = reader.read_object_header(&mut cursor).expect("decode");
            let len = frame.header.payload_length.into_inner() as usize;
            let (payload, rest) = cursor.split_at(len);
            let payload = payload.to_vec();
            cursor = rest;
            out.push((frame, payload));
        }
        out
    }

    fn write_all(frames: &[(FetchObject, Vec<u8>)]) -> Vec<u8> {
        let mut writer = FetchObjectWriter::new();
        let mut out = Vec::new();
        for (frame, payload) in frames {
            writer.write_object_header(frame, &mut out).expect("encode");
            out.extend_from_slice(payload);
        }
        out
    }

    fn identity(frame: &FetchObject) -> (u64, Option<u64>, u64, Option<u8>) {
        (frame.group_id, frame.subgroup_id, frame.object_id, frame.publisher_priority)
    }

    #[test]
    fn a_stream_written_back_unchanged_is_byte_identical() {
        let wire = sample_stream();
        let frames = read_all(&wire);
        assert_eq!(frames.len(), 4);
        assert_eq!(write_all(&frames), wire, "a stream with nothing removed was rewritten");
    }

    #[test]
    fn the_sample_stream_says_what_it_was_built_to_say() {
        let ids: Vec<_> = read_all(&sample_stream()).iter().map(|(f, _)| identity(f)).collect();
        assert_eq!(
            ids,
            vec![
                (10, Some(3), 0, Some(128)),
                (10, Some(3), 1, Some(128)),
                (10, Some(3), 2, Some(128)),
                (11, Some(3), 0, Some(128)),
            ],
        );
    }

    #[test]
    fn a_survivor_after_a_removed_object_still_resolves_to_itself() {
        let frames = read_all(&sample_stream());
        let want: Vec<_> = frames
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != 1)
            .map(|(_, (f, _))| identity(f))
            .collect();
        let kept: Vec<_> =
            frames.into_iter().enumerate().filter(|(i, _)| *i != 1).map(|(_, f)| f).collect();
        let got: Vec<_> = read_all(&write_all(&kept)).iter().map(|(f, _)| identity(f)).collect();
        assert_eq!(got, want, "a survivor was renumbered by the removal");
    }

    #[test]
    fn removing_the_first_object_promotes_the_second() {
        let frames = read_all(&sample_stream());
        let want: Vec<_> = frames.iter().skip(1).map(|(f, _)| identity(f)).collect();
        let kept: Vec<_> = frames.into_iter().skip(1).collect();
        let got: Vec<_> = read_all(&write_all(&kept)).iter().map(|(f, _)| identity(f)).collect();
        assert_eq!(got, want, "a survivor was renumbered by the removal");
    }
}

// ─────────────────────────────────────────────────────────────
// Draft-16: the header and its resolution are two calls
// ─────────────────────────────────────────────────────────────

#[cfg(feature = "draft16")]
mod draft16 {
    use moqtap_codec::draft16::data_stream::{
        FetchObjectHeader, FetchObjectLocation, FetchObjectReader, FetchObjectWriter,
    };
    use moqtap_codec::varint::VarInt;

    fn v(n: u64) -> VarInt {
        VarInt::from_u64(n).unwrap()
    }

    fn header(flags: u64, payload_length: u64) -> FetchObjectHeader {
        FetchObjectHeader {
            serialization_flags: v(flags),
            group_id: None,
            subgroup_id: None,
            object_id: None,
            publisher_priority: None,
            extensions: None,
            payload_length: v(payload_length),
        }
    }

    fn sample_stream() -> Vec<u8> {
        let mut wire = Vec::new();

        let mut a = header(0x08 | 0x04 | 0x10 | 0x03, 2);
        a.group_id = Some(v(10));
        a.subgroup_id = Some(v(3));
        a.object_id = Some(v(0));
        a.publisher_priority = Some(128);
        a.encode(&mut wire).unwrap();
        wire.extend_from_slice(&[0xca, 0xfe]);

        let mut b = header(0x04 | 0x01, 1);
        b.object_id = Some(v(1));
        b.encode(&mut wire).unwrap();
        wire.extend_from_slice(&[0x01]);

        let c = header(0x01, 1);
        c.encode(&mut wire).unwrap();
        wire.extend_from_slice(&[0x02]);

        let mut d = header(0x08 | 0x04 | 0x01, 1);
        d.group_id = Some(v(11));
        d.object_id = Some(v(0));
        d.encode(&mut wire).unwrap();
        wire.extend_from_slice(&[0x03]);

        wire
    }

    #[allow(clippy::type_complexity)]
    fn read_all(wire: &[u8]) -> Vec<(FetchObjectHeader, FetchObjectLocation, Vec<u8>)> {
        let mut reader = FetchObjectReader::new();
        let mut cursor: &[u8] = wire;
        let mut out = Vec::new();
        while !cursor.is_empty() {
            let header = FetchObjectHeader::decode(&mut cursor).expect("decode");
            let location = reader.resolve(&header).expect("resolve");
            let len = header.payload_length.into_inner() as usize;
            let (payload, rest) = cursor.split_at(len);
            let payload = payload.to_vec();
            cursor = rest;
            out.push((header, location, payload));
        }
        out
    }

    fn write_all(frames: &[(FetchObjectHeader, FetchObjectLocation, Vec<u8>)]) -> Vec<u8> {
        let mut writer = FetchObjectWriter::new();
        let mut out = Vec::new();
        for (header, location, payload) in frames {
            writer.write_object_header(header, location, &mut out).expect("encode");
            out.extend_from_slice(payload);
        }
        out
    }

    fn identity(location: &FetchObjectLocation) -> (u64, Option<u64>, u64, Option<u8>) {
        (location.group_id, location.subgroup_id, location.object_id, location.publisher_priority)
    }

    #[test]
    fn a_stream_written_back_unchanged_is_byte_identical() {
        let wire = sample_stream();
        let frames = read_all(&wire);
        assert_eq!(frames.len(), 4);
        assert_eq!(write_all(&frames), wire, "a stream with nothing removed was rewritten");
    }

    #[test]
    fn the_sample_stream_says_what_it_was_built_to_say() {
        let ids: Vec<_> = read_all(&sample_stream()).iter().map(|(_, l, _)| identity(l)).collect();
        assert_eq!(
            ids,
            vec![
                (10, Some(3), 0, Some(128)),
                (10, Some(3), 1, Some(128)),
                (10, Some(3), 2, Some(128)),
                (11, Some(3), 0, Some(128)),
            ],
        );
    }

    #[test]
    fn a_survivor_after_a_removed_object_still_resolves_to_itself() {
        let frames = read_all(&sample_stream());
        let want: Vec<_> = frames
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != 1)
            .map(|(_, (_, l, _))| identity(l))
            .collect();
        let kept: Vec<_> =
            frames.into_iter().enumerate().filter(|(i, _)| *i != 1).map(|(_, f)| f).collect();
        let got: Vec<_> = read_all(&write_all(&kept)).iter().map(|(_, l, _)| identity(l)).collect();
        assert_eq!(got, want, "a survivor was renumbered by the removal");
    }

    #[test]
    fn removing_the_first_object_promotes_the_second() {
        let frames = read_all(&sample_stream());
        let want: Vec<_> = frames.iter().skip(1).map(|(_, l, _)| identity(l)).collect();
        let kept: Vec<_> = frames.into_iter().skip(1).collect();
        let got: Vec<_> = read_all(&write_all(&kept)).iter().map(|(_, l, _)| identity(l)).collect();
        assert_eq!(got, want, "a survivor was renumbered by the removal");
    }
}

// ─────────────────────────────────────────────────────────────
// Draft-15: the reader resolves into the header, and for a long time
// there was no encoder at all
// ─────────────────────────────────────────────────────────────

#[cfg(feature = "draft15")]
mod draft15 {
    use moqtap_codec::draft15::data_stream::{
        FetchObjectHeader, FetchObjectReader, FetchObjectWriter,
    };
    use moqtap_codec::varint::VarInt;

    fn v(n: u64) -> VarInt {
        VarInt::from_u64(n).unwrap()
    }

    /// Draft-15 holds every field resolved rather than optional, so what a
    /// header leaves off the wire is said by its flags alone.
    fn header(flags: u8, group: u64, subgroup: u64, object: u64, len: u64) -> FetchObjectHeader {
        FetchObjectHeader {
            serialization_flags: flags,
            group_id: v(group),
            subgroup_id: v(subgroup),
            object_id: v(object),
            publisher_priority: 128,
            extension_headers: Vec::new(),
            payload_length: v(len),
            object_status: None,
        }
    }

    fn sample_stream() -> Vec<u8> {
        let mut wire = Vec::new();
        header(0x08 | 0x04 | 0x10 | 0x03, 10, 3, 0, 2).encode(&mut wire).unwrap();
        wire.extend_from_slice(&[0xca, 0xfe]);
        header(0x04 | 0x01, 10, 3, 1, 1).encode(&mut wire).unwrap();
        wire.extend_from_slice(&[0x01]);
        header(0x01, 10, 3, 2, 1).encode(&mut wire).unwrap();
        wire.extend_from_slice(&[0x02]);
        header(0x08 | 0x04 | 0x01, 11, 3, 0, 1).encode(&mut wire).unwrap();
        wire.extend_from_slice(&[0x03]);
        wire
    }

    fn read_all(wire: &[u8]) -> Vec<(FetchObjectHeader, Vec<u8>)> {
        let mut reader = FetchObjectReader::new();
        let mut cursor: &[u8] = wire;
        let mut out = Vec::new();
        while !cursor.is_empty() {
            let header = reader.read_object_header(&mut cursor).expect("decode");
            let len = header.payload_length.into_inner() as usize;
            let (payload, rest) = cursor.split_at(len);
            let payload = payload.to_vec();
            cursor = rest;
            out.push((header, payload));
        }
        out
    }

    fn write_all(frames: &[(FetchObjectHeader, Vec<u8>)]) -> Vec<u8> {
        let mut writer = FetchObjectWriter::new();
        let mut out = Vec::new();
        for (header, payload) in frames {
            writer.write_object_header(header, &mut out).expect("encode");
            out.extend_from_slice(payload);
        }
        out
    }

    fn identity(header: &FetchObjectHeader) -> (u64, u64, u64, u8) {
        (
            header.group_id.into_inner(),
            header.subgroup_id.into_inner(),
            header.object_id.into_inner(),
            header.publisher_priority,
        )
    }

    /// The encoder is the reader's inverse, which is what this asserts before
    /// anything is removed: draft-15 had a fetch object reader and no way at
    /// all to put one back on a stream.
    #[test]
    fn a_stream_written_back_unchanged_is_byte_identical() {
        let wire = sample_stream();
        let frames = read_all(&wire);
        assert_eq!(frames.len(), 4);
        assert_eq!(write_all(&frames), wire, "a stream with nothing removed was rewritten");
    }

    #[test]
    fn the_sample_stream_says_what_it_was_built_to_say() {
        let ids: Vec<_> = read_all(&sample_stream()).iter().map(|(h, _)| identity(h)).collect();
        assert_eq!(ids, vec![(10, 3, 0, 128), (10, 3, 1, 128), (10, 3, 2, 128), (11, 3, 0, 128)]);
    }

    #[test]
    fn a_survivor_after_a_removed_object_still_resolves_to_itself() {
        let frames = read_all(&sample_stream());
        let want: Vec<_> = frames
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != 1)
            .map(|(_, (h, _))| identity(h))
            .collect();
        let kept: Vec<_> =
            frames.into_iter().enumerate().filter(|(i, _)| *i != 1).map(|(_, f)| f).collect();
        let got: Vec<_> = read_all(&write_all(&kept)).iter().map(|(h, _)| identity(h)).collect();
        assert_eq!(got, want, "a survivor was renumbered by the removal");
    }

    #[test]
    fn removing_the_first_object_promotes_the_second() {
        let frames = read_all(&sample_stream());
        let want: Vec<_> = frames.iter().skip(1).map(|(h, _)| identity(h)).collect();
        let kept: Vec<_> = frames.into_iter().skip(1).collect();
        let got: Vec<_> = read_all(&write_all(&kept)).iter().map(|(h, _)| identity(h)).collect();
        assert_eq!(got, want, "a survivor was renumbered by the removal");
    }
}

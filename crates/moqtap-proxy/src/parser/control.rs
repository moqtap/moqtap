//! Inline control stream parser.
//!
//! Buffers raw bytes from the forwarding loop and decodes complete MoQT
//! control messages without modifying the forwarded data.
//!
//! Everything the parser framed comes back, decoded or not. A frame whose
//! declared length is intact but whose body the decoder refuses is a
//! [`ParsedItem::Refused`] carrying its bytes, not a gap: on the mutating
//! control pipe this parser *is* the forwarding path, so a refusal it kept
//! to itself would delete a control message from the wire and desynchronize
//! the peer's view of the session.

use bytes::{Buf, Bytes, BytesMut};

use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::version::DraftVersion;

/// A successfully parsed control frame.
///
/// `raw_bytes` is populated only when the parser was constructed with
/// [`ControlStreamParser::new_capturing`]; the default observation-only
/// parser leaves it as `None` to avoid copying bytes that already flow
/// through the forwarding path.
#[derive(Debug, Clone)]
pub struct ParsedFrame {
    /// The decoded control message.
    pub message: AnyControlMessage,
    /// The original wire bytes of this frame — only set when the parser
    /// is in capturing mode (used by hook-driven mutation).
    pub raw_bytes: Option<Bytes>,
}

/// A frame the parser located but the decoder refused.
///
/// The frame header decoded — that is what said where this frame ends and
/// the next begins — and nothing inside it did, so the Message Type is the
/// whole of what it can still say about itself.
#[derive(Debug, Clone)]
pub struct RefusedFrame {
    /// The Message Type varint the frame declared.
    pub type_id: u64,
    /// The original wire bytes of this frame — set on the same terms as
    /// [`ParsedFrame::raw_bytes`], and for the same caller.
    ///
    /// A caller that owns the forwarding path **must still write these**.
    /// The proxy could not read the message; the peer it was addressed to
    /// may well be able to, and a message dropped in transit is a fault
    /// the two endpoints have no way to attribute.
    pub raw_bytes: Option<Bytes>,
}

/// One thing the parser framed, in wire order.
///
/// Order is the reason this is one sequence rather than two collections.
/// A chunk holding a good frame, a refused one and a second good one has
/// to be forwarded in that order; a caller handed the good frames and the
/// refused bytes separately would write them in whichever order it chose,
/// which for a control stream is a reordering the peer decodes as a
/// different session.
#[derive(Debug, Clone)]
pub enum ParsedItem {
    /// A frame the decoder read.
    Frame(ParsedFrame),
    /// A frame the decoder refused.
    Refused(RefusedFrame),
}

/// Result of feeding bytes to the control stream parser.
#[derive(Debug)]
pub enum ParseResult {
    /// One or more complete frames were located. Not every one of them
    /// decoded — see [`ParsedItem`].
    Framed(Vec<ParsedItem>),
    /// Need more data — bytes are buffered internally.
    NeedMore,
}

/// Stateful inline parser for a MoQT control stream.
///
/// Accepts raw byte chunks (as they arrive from `RecvStream::read`),
/// buffers them, and emits complete `ParsedFrame`s. In the default
/// (non-capturing) mode the parser does not clone the frame bytes; in
/// capturing mode it does, so a hook can rewrite the frame before the
/// proxy forwards it.
pub struct ControlStreamParser {
    buf: BytesMut,
    draft: DraftVersion,
    capture_raw: bool,
}

impl ControlStreamParser {
    /// Create a new observation-only parser.
    ///
    /// `ParsedFrame::raw_bytes` will be `None`; use
    /// [`Self::new_capturing`] when a hook needs to mutate frames.
    pub fn new(draft: DraftVersion) -> Self {
        Self { buf: BytesMut::with_capacity(4096), draft, capture_raw: false }
    }

    /// Create a new parser that captures the raw wire bytes of each frame.
    ///
    /// Use this variant only when a hook may rewrite frames; the extra
    /// `Bytes::copy_from_slice` per frame is unnecessary for pure
    /// pass-through forwarding.
    pub fn new_capturing(draft: DraftVersion) -> Self {
        Self { buf: BytesMut::with_capacity(4096), draft, capture_raw: true }
    }

    /// Feed raw bytes into the parser.
    ///
    /// Returns [`ParseResult::Framed`] if one or more complete frames were
    /// located, or [`ParseResult::NeedMore`] if more data is needed.
    /// Partial frames are buffered internally.
    ///
    /// A located frame the decoder refuses is [`ParsedItem::Refused`] and
    /// not an omission, so a chunk carrying nothing but a refused frame is
    /// `Framed`, never `NeedMore`: nothing more is coming that would make
    /// that frame readable, and a caller told to wait would hold bytes it
    /// is supposed to be forwarding.
    pub fn feed(&mut self, data: &[u8]) -> ParseResult {
        self.buf.extend_from_slice(data);
        let mut items = Vec::new();

        loop {
            // Need at least 1 byte to determine type varint length
            if self.buf.is_empty() {
                break;
            }

            // Read type_id varint length from first byte
            let type_len = self.draft.varint_len(self.buf[0]);
            if self.buf.len() < type_len {
                break;
            }

            // Peek at type_id (don't advance buf yet). Kept rather than
            // discarded: it is the only thing a refused frame can still say
            // about itself, since by definition nothing inside it decoded.
            let mut cursor = &self.buf[..type_len];
            let type_id = match self.draft.decode_varint(&mut cursor) {
                Ok(v) => v.into_inner(),
                Err(_) => break,
            };

            // Read payload length. Draft-11+ uses 16-bit BE; earlier drafts
            // use a QUIC varint.
            let (payload_len, total) = if self.draft.uses_fixed_length_framing() {
                // Draft-11+: type_id(vi) + length(u16 BE) + payload
                if self.buf.len() < type_len + 2 {
                    break;
                }
                let hi = self.buf[type_len] as usize;
                let lo = self.buf[type_len + 1] as usize;
                let payload_len = (hi << 8) | lo;
                (payload_len, type_len + 2 + payload_len)
            } else {
                // Draft-07..10: type_id(vi) + length(vi) + payload
                if self.buf.len() <= type_len {
                    break;
                }
                let payload_len_varint_len = self.draft.varint_len(self.buf[type_len]);
                if self.buf.len() < type_len + payload_len_varint_len {
                    break;
                }
                let mut cursor = &self.buf[type_len..type_len + payload_len_varint_len];
                let payload_len = match self.draft.decode_varint(&mut cursor) {
                    Ok(v) => v.into_inner() as usize,
                    Err(_) => break,
                };
                (payload_len, type_len + payload_len_varint_len + payload_len)
            };
            let _ = payload_len; // used via total

            // Check if we have the full frame
            if self.buf.len() < total {
                break;
            }

            // Only clone the wire bytes when a hook might rewrite them;
            // the observation-only path forwards the original buffer.
            let raw_bytes = if self.capture_raw {
                Some(Bytes::copy_from_slice(&self.buf[..total]))
            } else {
                None
            };

            // Decode from a clone (so we don't corrupt the buffer on error)
            let mut decode_buf = &self.buf[..total];
            match AnyControlMessage::decode(self.draft, &mut decode_buf) {
                Ok(message) => {
                    self.buf.advance(total);
                    items.push(ParsedItem::Frame(ParsedFrame { message, raw_bytes }));
                }
                Err(_) => {
                    // Skip this frame and keep going. The declared length told
                    // us where the next frame starts, so one frame the decoder
                    // refuses says nothing about the frames behind it.
                    //
                    // Stopping here instead would discard every frame already
                    // buffered after this one, which is the opposite of what a
                    // proxy that exists to observe traffic should do with a
                    // malformed message: the stricter the decoder gets, the
                    // more of the stream a single refusal would take with it.
                    //
                    // `advance` is what rules out the infinite loop, not the
                    // exit: `total` is at least the type varint plus the length
                    // field, so it is always positive and the buffer always
                    // shrinks.
                    self.buf.advance(total);

                    // Handed back rather than swallowed, in the position it
                    // held. A skip that said nothing cost two things: an
                    // observer could not tell a message this proxy failed to
                    // read from one the peer never sent, and on the mutating
                    // pipe — where this parser is the forwarding path — the
                    // frame left the session entirely.
                    items.push(ParsedItem::Refused(RefusedFrame { type_id, raw_bytes }));
                    continue;
                }
            }
        }

        if items.is_empty() {
            ParseResult::NeedMore
        } else {
            ParseResult::Framed(items)
        }
    }

    /// Returns the draft version this parser is configured for.
    pub fn draft(&self) -> DraftVersion {
        self.draft
    }
}

impl Default for ControlStreamParser {
    fn default() -> Self {
        Self::new(DraftVersion::Draft14)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The type field is measured from its first byte before the rest has
    /// arrived, so the parser has to know which encoding the draft uses:
    /// RFC 9000's two-bit prefix through draft-16, MoQT's leading-1s count
    /// from draft-17.
    #[test]
    fn varint_len_follows_the_draft() {
        let old = DraftVersion::Draft14;
        assert_eq!(old.varint_len(0x00), 1);
        assert_eq!(old.varint_len(0x3F), 1);
        assert_eq!(old.varint_len(0x40), 2);
        assert_eq!(old.varint_len(0x80), 4);
        assert_eq!(old.varint_len(0xC0), 8);

        let new = DraftVersion::Draft19;
        assert_eq!(new.varint_len(0x00), 1);
        assert_eq!(new.varint_len(0x7F), 1);
        // SETUP's type id, 0x2F00, is `af00`: two bytes, not four.
        assert_eq!(new.varint_len(0xAF), 2);
        assert_eq!(new.varint_len(0xC0), 3);
        assert_eq!(new.varint_len(0xFF), 9);
    }

    // ── the draft-19 fixtures ───────────────────────────────────────
    //
    // Every constant and test below is draft-19 wire bytes, and each is
    // gated on that draft rather than on the module. A build without it
    // has no decoder for these frames, so `GOOD_FRAME` is refused like
    // everything else and each assertion below would measure the feature
    // set instead of the parser. The end-to-end coverage that survives a
    // reduced build is `tests/control_undecodable.rs`, which drives
    // whichever draft the build compiled.

    /// A SUBSCRIBE whose declared Message Length overruns its body by two
    /// bytes. Draft-19 Section 10 answers the mismatch with a session close, so
    /// the codec refuses it — which makes it the shortest frame that reaches
    /// this parser's decode-failure path.
    #[cfg(feature = "draft19")]
    const BAD_FRAME: &[u8] =
        &[0x03, 0x00, 0x09, 0x00, 0x01, 0x01, 0x61, 0x01, 0x62, 0x00, 0xff, 0xff];

    /// A frame carrying a Message Type no draft assigns, with an honest
    /// zero length.
    ///
    /// `0x3A` is unassigned on all fourteen drafts and is below `0x40`, so
    /// it is a single byte under RFC 9000's encoding and under MoQT's
    /// alike; the two-byte big-endian length is draft-11-and-later framing,
    /// which is what draft-19 uses. Nothing about it is malformed — the
    /// parser can say exactly where it ends — and the decoder still has
    /// nowhere to send it.
    #[cfg(feature = "draft19")]
    const UNKNOWN_TYPE_FRAME: &[u8] = &[0x3A, 0x00, 0x00];

    /// The same, one type along, so "the first refusal" is a claim about
    /// which one rather than about the only one.
    #[cfg(feature = "draft19")]
    const OTHER_UNKNOWN_TYPE_FRAME: &[u8] = &[0x3B, 0x00, 0x00];

    /// Everything one feed framed, as `Ok(type_id)` for a decoded frame and
    /// `Err(type_id)` for a refused one — in wire order.
    ///
    /// A shape assertions can compare in one piece. Reading counts off two
    /// filtered collections would say how many of each arrived and nothing
    /// about the order they arrived in, and the order is the half a
    /// forwarding caller depends on.
    #[cfg(feature = "draft19")]
    fn outcomes(result: ParseResult) -> Vec<Result<u64, u64>> {
        match result {
            ParseResult::Framed(items) => items
                .into_iter()
                .map(|item| match item {
                    ParsedItem::Frame(_) => Ok(0),
                    ParsedItem::Refused(r) => Err(r.type_id),
                })
                .collect(),
            ParseResult::NeedMore => Vec::new(),
        }
    }

    /// A well-formed SUBSCRIBE: same shape, honest length, no parameters.
    ///
    /// Namespace `["a"]`, track name `"b"`, request id 0.
    #[cfg(feature = "draft19")]
    const GOOD_FRAME: &[u8] = &[0x03, 0x00, 0x07, 0x00, 0x01, 0x01, 0x61, 0x01, 0x62, 0x00];

    /// A frame the decoder refuses costs that frame and no more.
    ///
    /// The parser used to `break` out of the loop on a decode error, having
    /// already advanced past the frame. Everything buffered behind the bad
    /// frame was dropped on the floor with it — so one malformed message could
    /// cost an arbitrary number of good ones, and the stricter the codec became
    /// about draft-19's MUSTs, the more of the stream a single refusal took
    /// with it. That is backwards for a proxy whose purpose is to report the
    /// traffic it sees.
    ///
    /// *Ablation (measured):* restore `continue` to `break`.
    ///
    /// ```text
    /// ---- parser::control::tests::a_refused_frame_does_not_cost_the_frames_behind_it stdout ----
    /// assertion `left == right` failed: a bad frame must not swallow the good
    /// frames behind it, and must keep its place among them
    ///   left: [Ok(0), Err(3)]
    ///  right: [Ok(0), Err(3), Ok(0), Ok(0)]
    /// ```
    ///
    /// The frame ahead of the bad one survives and the refusal is still
    /// reported; both frames behind it are gone.
    #[cfg(feature = "draft19")]
    #[test]
    fn a_refused_frame_does_not_cost_the_frames_behind_it() {
        let mut parser = ControlStreamParser::new(DraftVersion::Draft19);

        let mut wire = Vec::new();
        wire.extend_from_slice(GOOD_FRAME);
        wire.extend_from_slice(BAD_FRAME);
        wire.extend_from_slice(GOOD_FRAME);
        wire.extend_from_slice(GOOD_FRAME);

        // The refused frame in its own position, not merely absent: a
        // caller that forwards this sequence writes it in this order, and a
        // refusal collected to one side would be written after the two good
        // frames that followed it on the wire.
        assert_eq!(
            outcomes(parser.feed(&wire)),
            vec![Ok(0), Err(0x03), Ok(0), Ok(0)],
            "a bad frame must not swallow the good frames behind it, and must keep its place \
             among them"
        );
    }

    /// A refused frame comes back, with its bytes and its type.
    ///
    /// The parser used to step over one in silence. Two things were lost with
    /// it. An observer could not tell a control message this proxy failed to
    /// read from one the peer never sent — opposite conclusions, and for a
    /// tool whose product is the account of the traffic, the wrong one to
    /// default to. And on the mutating control pipe, where this parser *is*
    /// the forwarding path, the frame was deleted from the session: the peer
    /// received a stream with a message missing from the middle of it, and
    /// neither endpoint had anything to attribute that to.
    ///
    /// Capturing mode is what the second half needs, so both modes are
    /// checked here — the observation-only parser must not start copying
    /// bytes it has no forwarding use for.
    ///
    /// *Ablation (measured):* drop the `items.push(ParsedItem::Refused(..))`
    /// and step over the frame in silence, as the parser used to.
    ///
    /// ```text
    /// ---- parser::control::tests::a_refused_frame_comes_back_with_its_bytes_and_its_type stdout ----
    /// a whole frame arrived and the decoder refused it; waiting for more bytes
    /// would hold a frame nothing will ever complete
    /// ```
    ///
    /// `NeedMore` for a frame that is entirely present, which is the shape
    /// of the original defect: nothing is coming that would make it
    /// readable, and a caller told to wait holds bytes it is meant to be
    /// forwarding. Three of this module's four refusal tests redden under
    /// that cut, each in its own place.
    #[cfg(feature = "draft19")]
    #[test]
    fn a_refused_frame_comes_back_with_its_bytes_and_its_type() {
        let mut watching = ControlStreamParser::new(DraftVersion::Draft19);
        match watching.feed(UNKNOWN_TYPE_FRAME) {
            ParseResult::Framed(items) => match &items[..] {
                [ParsedItem::Refused(r)] => {
                    assert_eq!(r.type_id, 0x3A, "the type the frame declared");
                    assert!(
                        r.raw_bytes.is_none(),
                        "the observation-only parser copies no frame it is not asked to forward"
                    );
                }
                other => panic!("expected one refused frame, got {other:?}"),
            },
            ParseResult::NeedMore => panic!(
                "a whole frame arrived and the decoder refused it; waiting for more bytes would \
                 hold a frame nothing will ever complete"
            ),
        }

        let mut forwarding = ControlStreamParser::new_capturing(DraftVersion::Draft19);
        match forwarding.feed(UNKNOWN_TYPE_FRAME) {
            ParseResult::Framed(items) => match &items[..] {
                [ParsedItem::Refused(r)] => assert_eq!(
                    r.raw_bytes.as_deref(),
                    Some(UNKNOWN_TYPE_FRAME),
                    "the capturing parser owns the forwarding path, so it must hand back every \
                     byte it consumed"
                ),
                other => panic!("expected one refused frame, got {other:?}"),
            },
            ParseResult::NeedMore => panic!("a whole frame arrived and the decoder refused it"),
        }
    }

    /// Two refusals of different types, each in its own place.
    /// The interesting half is that the second is not folded into the first. A
    /// caller reports the loss once per direction and counts every occurrence,
    /// and it can only do both if the sequence distinguishes them; a parser
    /// that recorded *something was refused* would make the count and the
    /// report the same number.
    ///
    /// *Ablation (measured):* step over a refused frame in silence.
    ///
    /// ```text
    /// ---- parser::control::tests::refusals_are_distinguished_from_each_other stdout ----
    /// assertion `left == right` failed
    ///   left: [Ok(0)]
    ///  right: [Err(58), Ok(0), Err(59)]
    /// ```
    #[cfg(feature = "draft19")]
    #[test]
    fn refusals_are_distinguished_from_each_other() {
        let mut parser = ControlStreamParser::new(DraftVersion::Draft19);

        let mut wire = Vec::new();
        wire.extend_from_slice(UNKNOWN_TYPE_FRAME);
        wire.extend_from_slice(GOOD_FRAME);
        wire.extend_from_slice(OTHER_UNKNOWN_TYPE_FRAME);

        assert_eq!(outcomes(parser.feed(&wire)), vec![Err(0x3A), Ok(0), Err(0x3B)]);
    }

    /// The buffer is left in a state the next feed can use.
    ///
    /// Skipping a frame has to consume exactly its declared length: consume too
    /// little and the parser resynchronises on payload bytes, too much and it
    /// eats the frame behind it. Feeding the tail separately is what checks the
    /// boundary, since a wrong skip leaves the good frame unparseable.
    #[cfg(feature = "draft19")]
    #[test]
    fn a_refused_frame_leaves_the_parser_aligned_for_the_next_feed() {
        let mut parser = ControlStreamParser::new(DraftVersion::Draft19);

        // The bad frame alone: nothing decodes, and the parser says which
        // frame it was rather than asking for bytes that would not help.
        assert_eq!(outcomes(parser.feed(BAD_FRAME)), vec![Err(0x03)]);

        // The next frame arrives on its own and must be found intact, which is
        // only true if the skip landed on the frame boundary.
        // `Ok` and not merely one item: a skip that landed a byte early
        // or late still frames *something* out of the bytes that follow,
        // and a length assertion alone would take that for the message.
        match parser.feed(GOOD_FRAME) {
            ParseResult::Framed(items) => assert_eq!(
                outcomes(ParseResult::Framed(items)),
                vec![Ok(0)],
                "the frame after a refused one was lost or misread; the skip missed the boundary"
            ),
            ParseResult::NeedMore => {
                panic!("the parser resynchronised in the wrong place after skipping a bad frame")
            }
        }
    }
}

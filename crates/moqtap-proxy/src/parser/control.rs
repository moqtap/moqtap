//! Inline control stream parser.
//!
//! Buffers raw bytes from the forwarding loop and decodes complete MoQT
//! control messages without modifying the forwarded data.

use bytes::{Buf, Bytes, BytesMut};

use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::varint::VarInt;
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

/// Result of feeding bytes to the control stream parser.
#[derive(Debug)]
pub enum ParseResult {
    /// One or more complete messages were decoded.
    Messages(Vec<ParsedFrame>),
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
    /// Returns `ParseResult::Messages` if one or more complete frames
    /// could be decoded, or `ParseResult::NeedMore` if more data is
    /// needed. Partial frames are buffered internally.
    pub fn feed(&mut self, data: &[u8]) -> ParseResult {
        self.buf.extend_from_slice(data);
        let mut frames = Vec::new();

        loop {
            // Need at least 1 byte to determine type varint length
            if self.buf.is_empty() {
                break;
            }

            // Read type_id varint length from first byte
            let type_len = varint_len(self.buf[0]);
            if self.buf.len() < type_len {
                break;
            }

            // Peek at type_id (don't advance buf yet)
            let mut cursor = &self.buf[..type_len];
            if VarInt::decode(&mut cursor).is_err() {
                break;
            }

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
                let payload_len_varint_len = varint_len(self.buf[type_len]);
                if self.buf.len() < type_len + payload_len_varint_len {
                    break;
                }
                let mut cursor = &self.buf[type_len..type_len + payload_len_varint_len];
                let payload_len = match VarInt::decode(&mut cursor) {
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
                    frames.push(ParsedFrame { message, raw_bytes });
                }
                Err(_) => {
                    // Skip this frame on decode error — advance past it
                    // so we don't get stuck in an infinite loop.
                    self.buf.advance(total);
                    break;
                }
            }
        }

        if frames.is_empty() {
            ParseResult::NeedMore
        } else {
            ParseResult::Messages(frames)
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

/// Determine the encoded length of a QUIC varint from its first byte.
fn varint_len(first_byte: u8) -> usize {
    1 << (first_byte >> 6)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_len_values() {
        assert_eq!(varint_len(0x00), 1);
        assert_eq!(varint_len(0x3F), 1);
        assert_eq!(varint_len(0x40), 2);
        assert_eq!(varint_len(0x80), 4);
        assert_eq!(varint_len(0xC0), 8);
    }
}

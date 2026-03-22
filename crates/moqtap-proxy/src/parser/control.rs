//! Inline control stream parser.
//!
//! Buffers raw bytes from the forwarding loop and decodes complete MoQT
//! control messages without modifying the forwarded data.

use bytes::{Buf, Bytes, BytesMut};

use moqtap_codec::dispatch::AnyControlMessage;
use moqtap_codec::varint::VarInt;
use moqtap_codec::version::DraftVersion;

/// A successfully parsed control frame with its raw wire bytes.
#[derive(Debug, Clone)]
pub struct ParsedFrame {
    /// The decoded control message.
    pub message: AnyControlMessage,
    /// The original wire bytes of this frame (for forwarding).
    pub raw_bytes: Bytes,
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
/// buffers them, and emits complete `ParsedFrame`s. The parser clones
/// bytes before decoding so the original data can be forwarded unchanged.
pub struct ControlStreamParser {
    buf: BytesMut,
    draft: DraftVersion,
}

impl ControlStreamParser {
    /// Create a new parser for the given draft version.
    pub fn new(draft: DraftVersion) -> Self {
        Self { buf: BytesMut::with_capacity(4096), draft }
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

            // Draft-14 has a scope varint between type and payload length.
            // Draft-07 does not.
            let payload_len_start = match self.draft {
                DraftVersion::Draft14 => {
                    let scope_start = type_len;
                    if self.buf.len() <= scope_start {
                        break;
                    }
                    let scope_len = varint_len(self.buf[scope_start]);
                    if self.buf.len() < scope_start + scope_len {
                        break;
                    }
                    scope_start + scope_len
                }
                DraftVersion::Draft07 => type_len,
            };

            // Read payload length varint
            if self.buf.len() <= payload_len_start {
                break;
            }
            let payload_len_varint_len = varint_len(self.buf[payload_len_start]);
            if self.buf.len() < payload_len_start + payload_len_varint_len {
                break;
            }

            let mut cursor =
                &self.buf[payload_len_start..payload_len_start + payload_len_varint_len];
            let payload_len = match VarInt::decode(&mut cursor) {
                Ok(v) => v.into_inner() as usize,
                Err(_) => break,
            };

            // Check if we have the full frame
            let total = payload_len_start + payload_len_varint_len + payload_len;
            if self.buf.len() < total {
                break;
            }

            // Clone the raw bytes for forwarding
            let raw_bytes = Bytes::copy_from_slice(&self.buf[..total]);

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

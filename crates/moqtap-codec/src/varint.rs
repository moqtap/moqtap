use bytes::{Buf, BufMut};

/// Maximum varint value: 2^62 - 1 (RFC 9000 Section 16)
pub const MAX_VARINT: u64 = 4_611_686_018_427_387_903;

/// A QUIC variable-length integer (RFC 9000 Section 16).
///
/// Uses 2-bit prefix encoding:
/// - 00: 1 byte, values 0-63
/// - 01: 2 bytes, values 0-16383
/// - 10: 4 bytes, values 0-1073741823
/// - 11: 8 bytes, values 0-4611686018427387903
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VarInt(u64);

/// Errors produced when encoding or decoding a variable-length integer.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum VarIntError {
    /// Value exceeds the maximum varint value (2^62 - 1).
    #[error("value {0} exceeds maximum varint value (2^62 - 1)")]
    Overflow(u64),
    /// Not enough bytes in the buffer to decode a varint.
    #[error("insufficient bytes for varint decoding")]
    UnexpectedEnd,
}

impl VarInt {
    /// Create a VarInt from a u64, returning an error if it exceeds the maximum.
    pub fn from_u64(v: u64) -> Result<Self, VarIntError> {
        if v > MAX_VARINT {
            Err(VarIntError::Overflow(v))
        } else {
            Ok(VarInt(v))
        }
    }

    /// Get the inner u64 value.
    pub fn into_inner(self) -> u64 {
        self.0
    }

    /// Return the number of bytes needed to encode this varint.
    pub fn encoded_len(&self) -> usize {
        if self.0 <= 63 {
            1
        } else if self.0 <= 16383 {
            2
        } else if self.0 <= 1073741823 {
            4
        } else {
            8
        }
    }

    /// Encode this varint into the given buffer.
    pub fn encode(&self, buf: &mut impl BufMut) {
        match self.encoded_len() {
            1 => {
                buf.put_u8(self.0 as u8);
            }
            2 => {
                buf.put_u16((self.0 as u16) | 0x4000);
            }
            4 => {
                buf.put_u32((self.0 as u32) | 0x80000000);
            }
            8 => {
                buf.put_u64(self.0 | 0xC000000000000000);
            }
            _ => unreachable!(),
        }
    }

    /// Decode a varint from the given buffer.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, VarIntError> {
        if buf.remaining() < 1 {
            return Err(VarIntError::UnexpectedEnd);
        }
        let first = buf.chunk()[0];
        let prefix = first >> 6;
        let len = 1usize << prefix;
        if buf.remaining() < len {
            return Err(VarIntError::UnexpectedEnd);
        }
        let val = match len {
            1 => {
                buf.advance(1);
                (first & 0x3F) as u64
            }
            2 => {
                let v = buf.get_u16();
                (v & 0x3FFF) as u64
            }
            4 => {
                let v = buf.get_u32();
                (v & 0x3FFFFFFF) as u64
            }
            8 => {
                let v = buf.get_u64();
                v & 0x3FFFFFFFFFFFFFFF
            }
            _ => unreachable!(),
        };
        Ok(VarInt(val))
    }
}

impl TryFrom<u64> for VarInt {
    type Error = VarIntError;
    fn try_from(v: u64) -> Result<Self, Self::Error> {
        Self::from_u64(v)
    }
}

impl From<VarInt> for u64 {
    fn from(v: VarInt) -> u64 {
        v.0
    }
}

impl From<u32> for VarInt {
    fn from(v: u32) -> Self {
        VarInt(v as u64)
    }
}

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
    /// A 7-byte encoding was received on a draft-17 session, where the length
    /// is undefined. Draft-17 Section 1.4.1 requires closing the session with
    /// PROTOCOL_VIOLATION.
    #[error("7-byte varint is not a defined encoding length in draft-17")]
    InvalidCodePoint,
}

impl VarInt {
    /// Create a VarInt from a u64, returning an error if it exceeds the maximum.
    #[inline]
    pub fn from_u64(v: u64) -> Result<Self, VarIntError> {
        if v > MAX_VARINT {
            Err(VarIntError::Overflow(v))
        } else {
            Ok(VarInt(v))
        }
    }

    /// Get the inner u64 value.
    #[inline]
    pub fn into_inner(self) -> u64 {
        self.0
    }

    /// Return the number of bytes needed to encode this varint.
    #[inline]
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
    #[inline]
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
    #[inline]
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

/// Maximum MoQT varint value (draft-17 Section 1.4.1): 2^64 - 1.
pub const MAX_MOQT_VARINT: u64 = u64::MAX;

impl VarInt {
    /// Create a VarInt from a u64 under the MoQT encoding, which reaches the
    /// full 64-bit range and so cannot fail.
    #[inline]
    pub fn from_u64_moqt(v: u64) -> Self {
        VarInt(v)
    }

    /// Number of bytes needed to encode this varint under the MoQT encoding.
    ///
    /// `seven_byte` is false for draft-17, which omits that length, so values
    /// that take seven bytes elsewhere take eight there.
    #[inline]
    fn encoded_len_moqt(&self, seven_byte: bool) -> usize {
        for len in 1..=8 {
            if (len != 7 || seven_byte) && self.0 < 1u64 << (7 * len) {
                return len;
            }
        }
        9
    }

    #[inline]
    fn encode_moqt_inner(&self, buf: &mut impl BufMut, seven_byte: bool) {
        let len = self.encoded_len_moqt(seven_byte);
        if len == 9 {
            buf.put_u8(0xFF);
            buf.put_u64(self.0);
            return;
        }
        // (len - 1) leading 1 bits, then a 0, in the top `len` bits.
        let prefix = (((1u16 << (len - 1)) - 1) << (9 - len)) as u8;
        let combined = ((prefix as u64) << (8 * (len - 1))) | self.0;
        for i in (0..len).rev() {
            buf.put_u8((combined >> (8 * i)) as u8);
        }
    }

    #[inline]
    fn decode_moqt_inner(buf: &mut impl Buf, seven_byte: bool) -> Result<Self, VarIntError> {
        if buf.remaining() < 1 {
            return Err(VarIntError::UnexpectedEnd);
        }
        let first = buf.chunk()[0];

        if first == 0xFF {
            if buf.remaining() < 9 {
                return Err(VarIntError::UnexpectedEnd);
            }
            buf.advance(1);
            return Ok(VarInt(buf.get_u64()));
        }

        let len = first.leading_ones() as usize + 1;
        if len == 7 && !seven_byte {
            return Err(VarIntError::InvalidCodePoint);
        }
        if buf.remaining() < len {
            return Err(VarIntError::UnexpectedEnd);
        }
        let mut val = (first & ((1u16 << (8 - len)) - 1) as u8) as u64;
        buf.advance(1);
        for _ in 1..len {
            val = (val << 8) | buf.get_u8() as u64;
        }
        Ok(VarInt(val))
    }

    /// Encode using the MoQT variable-length integer (drafts 17 and later).
    ///
    /// Draft-17 replaced the RFC 9000 encoding with one whose length comes from
    /// the number of leading 1 bits in the first byte: one byte carries 0-127,
    /// and nine bytes carry the full 64-bit range. The shortest form that holds
    /// the value is always used.
    #[inline]
    pub fn encode_moqt<P: MoqtProfile>(&self, buf: &mut impl BufMut) {
        self.encode_moqt_inner(buf, P::SEVEN_BYTE);
    }

    /// Decode a MoQT variable-length integer (drafts 17 and later).
    ///
    /// Non-minimal encodings are accepted, as draft-19 Section 1.4.1 requires:
    /// 0 may arrive as 0x00, 0x8000, 0xC00000 or any longer form. On a
    /// [`Moqt17`] session a 7-byte encoding is [`VarIntError::InvalidCodePoint`].
    #[inline]
    pub fn decode_moqt<P: MoqtProfile>(buf: &mut impl Buf) -> Result<Self, VarIntError> {
        Self::decode_moqt_inner(buf, P::SEVEN_BYTE)
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Moqt17 {}
    impl Sealed for super::Moqt18 {}
}

/// One revision of MoQT's variable-length integer.
///
/// Named for the draft that introduced the revision, not the range of drafts
/// using it — [`crate::version::DraftVersion::varint_encoding`] is the one
/// place that says which draft uses which.
pub trait MoqtProfile: sealed::Sealed {
    /// Whether the 7-byte length is defined.
    const SEVEN_BYTE: bool;
}

/// The encoding as introduced in draft-17, whose Table 1 omits the 7-byte
/// length and which calls 11111100 an invalid code point. Values needing seven
/// bytes under [`Moqt18`] take eight here.
pub struct Moqt17;

/// The encoding as revised in draft-18, which restored the 7-byte length so
/// that all nine are defined.
pub struct Moqt18;

impl MoqtProfile for Moqt17 {
    const SEVEN_BYTE: bool = false;
}

impl MoqtProfile for Moqt18 {
    const SEVEN_BYTE: bool = true;
}

impl TryFrom<u64> for VarInt {
    type Error = VarIntError;
    #[inline]
    fn try_from(v: u64) -> Result<Self, Self::Error> {
        Self::from_u64(v)
    }
}

impl From<VarInt> for u64 {
    #[inline]
    fn from(v: VarInt) -> u64 {
        v.0
    }
}

impl VarInt {
    /// Create a VarInt from a usize. Infallible because practical memory sizes
    /// are always well below the 2^62 varint maximum.
    #[inline]
    pub fn from_usize(v: usize) -> Self {
        VarInt(v as u64)
    }
}

impl From<u32> for VarInt {
    #[inline]
    fn from(v: u32) -> Self {
        VarInt(v as u64)
    }
}

use crate::varint::VarInt;
use bytes::{Buf, BufMut};

#[inline]
#[allow(clippy::uninit_vec)]
fn read_bytes_kvp(buf: &mut impl Buf, len: usize) -> Result<Vec<u8>, KvpError> {
    if buf.remaining() < len {
        return Err(KvpError::UnexpectedEnd);
    }
    let mut v = Vec::with_capacity(len);
    // Safety: set_len(len) then overwrite all `len` bytes via copy_to_slice.
    unsafe {
        v.set_len(len);
    }
    buf.copy_to_slice(&mut v);
    Ok(v)
}

/// Maximum value length for a Key-Value Pair: 2^16 - 1 bytes.
pub const MAX_KVP_VALUE_LEN: usize = 65535;

/// Value of a Key-Value Pair.
/// Even key type -> varint value (no length field).
/// Odd key type -> length-prefixed bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KvpValue {
    /// Varint value (used with even key types).
    Varint(VarInt),
    /// Length-prefixed byte string (used with odd key types).
    Bytes(Vec<u8>),
}

/// A MoQT Key-Value Pair (used for parameters in control messages).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyValuePair {
    /// Parameter key (even = varint value, odd = byte string value).
    pub key: VarInt,
    /// Parameter value.
    pub value: KvpValue,
}

/// Errors produced when encoding or decoding key-value pairs.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum KvpError {
    /// Odd key type was not followed by a length-prefixed value.
    #[error("odd key type requires length-prefixed value")]
    MissingLength,
    /// Value length exceeds [`MAX_KVP_VALUE_LEN`].
    #[error("value length {0} exceeds maximum ({MAX_KVP_VALUE_LEN})")]
    ValueTooLong(usize),
    /// Not enough bytes in the buffer to complete decoding.
    #[error("insufficient bytes")]
    UnexpectedEnd,
    /// Variable-length integer encoding/decoding error.
    #[error("varint error: {0}")]
    VarInt(#[from] crate::varint::VarIntError),
}

impl KeyValuePair {
    /// Encode a single key-value pair.
    pub fn encode(&self, buf: &mut impl BufMut) {
        self.key.encode(buf);
        match &self.value {
            KvpValue::Varint(v) => {
                // Even key: write varint value directly
                v.encode(buf);
            }
            KvpValue::Bytes(bytes) => {
                // Odd key: write length-prefixed bytes
                VarInt::from_usize(bytes.len()).encode(buf);
                buf.put_slice(bytes);
            }
        }
    }

    /// Decode a single key-value pair.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, KvpError> {
        let key = VarInt::decode(buf)?;
        let key_val = key.into_inner();

        if key_val % 2 == 0 {
            // Even key: value is a varint
            let value = VarInt::decode(buf)?;
            Ok(KeyValuePair { key, value: KvpValue::Varint(value) })
        } else {
            // Odd key: value is length-prefixed bytes
            let len = VarInt::decode(buf)?.into_inner() as usize;
            if len > MAX_KVP_VALUE_LEN {
                return Err(KvpError::ValueTooLong(len));
            }
            let bytes = read_bytes_kvp(buf, len)?;
            Ok(KeyValuePair { key, value: KvpValue::Bytes(bytes) })
        }
    }

    /// Encode a list of key-value pairs (count-prefixed).
    pub fn encode_list(pairs: &[KeyValuePair], buf: &mut impl BufMut) {
        VarInt::from_usize(pairs.len()).encode(buf);
        for pair in pairs {
            pair.encode(buf);
        }
    }

    /// Decode a list of key-value pairs (count-prefixed).
    pub fn decode_list(buf: &mut impl Buf) -> Result<Vec<KeyValuePair>, KvpError> {
        let count = VarInt::decode(buf)?.into_inner() as usize;
        let mut pairs = Vec::with_capacity(count);
        for _ in 0..count {
            pairs.push(KeyValuePair::decode(buf)?);
        }
        Ok(pairs)
    }

    /// Decode a single KVP using draft-07 format (all values are length-prefixed bytes).
    pub fn decode_d07(buf: &mut impl Buf) -> Result<Self, KvpError> {
        let key = VarInt::decode(buf)?;
        let len = VarInt::decode(buf)?.into_inner() as usize;
        if len > MAX_KVP_VALUE_LEN {
            return Err(KvpError::ValueTooLong(len));
        }
        let bytes = read_bytes_kvp(buf, len)?;
        Ok(KeyValuePair { key, value: KvpValue::Bytes(bytes) })
    }

    /// Encode a single KVP using draft-07 format (all values are length-prefixed).
    pub fn encode_d07(&self, buf: &mut impl BufMut) {
        self.key.encode(buf);
        match &self.value {
            KvpValue::Varint(v) => {
                VarInt::from_usize(v.encoded_len()).encode(buf);
                v.encode(buf);
            }
            KvpValue::Bytes(bytes) => {
                VarInt::from_usize(bytes.len()).encode(buf);
                buf.put_slice(bytes);
            }
        }
    }

    /// Decode a list of KVPs using draft-07 format.
    pub fn decode_list_d07(buf: &mut impl Buf) -> Result<Vec<KeyValuePair>, KvpError> {
        let count = VarInt::decode(buf)?.into_inner() as usize;
        let mut pairs = Vec::with_capacity(count);
        for _ in 0..count {
            pairs.push(KeyValuePair::decode_d07(buf)?);
        }
        Ok(pairs)
    }

    /// Encode a list of KVPs using draft-07 format.
    pub fn encode_list_d07(pairs: &[KeyValuePair], buf: &mut impl BufMut) {
        VarInt::from_usize(pairs.len()).encode(buf);
        for pair in pairs {
            pair.encode_d07(buf);
        }
    }
}

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
///
/// Drafts 11 through 15 state it of the Key-Value-Pair Length field: "The
/// maximum length of a value is 2^16-1 bytes. If an endpoint receives a length
/// larger than the maximum, it MUST close the session with a Protocol
/// Violation." Drafts 16 and later spell the code `PROTOCOL_VIOLATION` and
/// change nothing else. It is a receiver's rule, which is why it is applied
/// when decoding.
///
/// Drafts 07 through 10 have no Key-Value-Pair. They carry a Parameter with an
/// unbounded length and state no maximum, so [`KeyValuePair::decode_d07`] does
/// not apply this.
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

        if key_val.is_multiple_of(2) {
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

    /// The half of [`Self::encode_list_checked`] that does not write, so a list
    /// can check every pair before committing any of them.
    fn check_value_len(&self) -> Result<(), KvpError> {
        if let KvpValue::Bytes(bytes) = &self.value {
            if bytes.len() > MAX_KVP_VALUE_LEN {
                return Err(KvpError::ValueTooLong(bytes.len()));
            }
        }
        Ok(())
    }

    /// Encode a list of key-value pairs (count-prefixed).
    pub fn encode_list(pairs: &[KeyValuePair], buf: &mut impl BufMut) {
        VarInt::from_usize(pairs.len()).encode(buf);
        for pair in pairs {
            pair.encode(buf);
        }
    }

    /// Encode a count-prefixed list, refusing a value no peer may accept.
    ///
    /// [`Self::encode_list`] writes whatever it is given. The length maximum in
    /// [`MAX_KVP_VALUE_LEN`] is written as a receiver's rule, and it is applied
    /// on decode for that reason — but a value past it is one the receiver is
    /// required to close the session over, so writing it is not a way to send
    /// it. This is the entry point that says so before any byte is written, and
    /// it is what the parameter encoders of drafts 11 through 15 write through.
    ///
    /// Every pair is checked before the first is written, so a refused list
    /// leaves `buf` untouched rather than half a list followed by an error.
    ///
    /// **The refusal is never the only one.** Those drafts also limit a control
    /// message to 2^16-1 bytes, and the two maxima are the same number, so a
    /// value one byte past this one is already inside a payload one byte past
    /// that one. What this adds is which of the two rules the error names, at
    /// the layer that owns it, rather than whether the message is written.
    ///
    /// Drafts 07 through 10 have no Key-Value-Pair and state no maximum; their
    /// [`Self::encode_list_d07`] is unaffected and stays infallible.
    pub fn encode_list_checked(
        pairs: &[KeyValuePair],
        buf: &mut impl BufMut,
    ) -> Result<(), KvpError> {
        for pair in pairs {
            pair.check_value_len()?;
        }
        Self::encode_list(pairs, buf);
        Ok(())
    }

    /// Decode a list of key-value pairs (count-prefixed).
    pub fn decode_list(buf: &mut impl Buf) -> Result<Vec<KeyValuePair>, KvpError> {
        let count = VarInt::decode(buf)?.into_inner() as usize;
        let mut pairs = crate::types::reserve_bounded(count, buf);
        for _ in 0..count {
            pairs.push(KeyValuePair::decode(buf)?);
        }
        Ok(pairs)
    }

    /// Decode a single Parameter using the drafts 07 through 10 format, where
    /// every value is length-prefixed.
    ///
    /// No cap is applied to the length. Those four drafts describe a Parameter
    /// as `{ Parameter Type (i), Parameter Length (i), Parameter Value (..) }`
    /// and say nothing about how long a value may be; the 2^16-1 maximum in
    /// [`MAX_KVP_VALUE_LEN`] arrives with the Key-Value-Pair of draft-11, and
    /// applying it here refuses parameters these drafts permit.
    ///
    /// The read is still bounded: the reader refuses a length longer than the
    /// bytes actually present, so a declared length cannot make this allocate
    /// more than the peer really sent.
    pub fn decode_d07(buf: &mut impl Buf) -> Result<Self, KvpError> {
        let key = VarInt::decode(buf)?;
        let len = VarInt::decode(buf)?.into_inner() as usize;
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
        let mut pairs = crate::types::reserve_bounded(count, buf);
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

    // No MoQT-varint form of a Key-Value-Pair lives here, and the drafts are why.
    //
    // Every draft that reaches for the MoQT varint delta-codes the parameter
    // type: it writes the difference from the previous type rather than the type
    // itself, which makes a pair unreadable outside the list it sits in and a
    // list unreadable outside the message. So the unit these drafts serialize is
    // the list-in-a-message, not the pair, and each of them serializes it in its
    // own module — drafts 17, 18 and 19 with two rules for the value shape, one
    // reading a table and one reading the type's parity, in two parameter
    // namespaces that do not agree.
    //
    // A pair-at-a-time encoder over the MoQT varint would have to write the type
    // absolutely to be callable at all, and no draft reads that.
}

use crate::varint::VarInt;
use bytes::{Buf, BufMut};

/// Read exactly `len` bytes from `buf`, returning them as a `Vec<u8>`.
#[inline]
#[allow(clippy::uninit_vec)]
pub fn read_bytes(buf: &mut impl Buf, len: usize) -> Result<Vec<u8>, crate::error::CodecError> {
    if buf.remaining() < len {
        return Err(crate::error::CodecError::UnexpectedEnd);
    }
    let mut v = Vec::with_capacity(len);
    // Safety: `set_len(len)` with capacity `len` exposes `len` uninitialized
    // `u8`s. `copy_to_slice` immediately overwrites all of them before any
    // read. `u8` has no drop, so no leaks on panic beyond the `Vec` itself.
    unsafe {
        v.set_len(len);
    }
    buf.copy_to_slice(&mut v);
    Ok(v)
}

/// Track Namespace: ordered N-tuple of byte-string elements (1 <= N <= 32).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackNamespace(pub Vec<Vec<u8>>);

/// Full Track Name: namespace + track name.
/// Maximum total size: 4096 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullTrackName {
    /// The track namespace tuple.
    pub namespace: TrackNamespace,
    /// The track name within the namespace.
    pub track_name: Vec<u8>,
}

/// Location within a track: (Group, Object).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Location {
    /// Group identifier.
    pub group: VarInt,
    /// Object identifier within the group.
    pub object: VarInt,
}

/// Object status values (draft-14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ObjectStatus {
    /// Object payload follows normally.
    Normal = 0x0,
    /// Last object in the group.
    EndOfGroup = 0x1,
    /// Last object in the track.
    EndOfTrack = 0x2,
    /// The referenced object does not exist.
    DoesNotExist = 0x3,
}

/// Group ordering preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GroupOrder {
    /// Publisher determines the order.
    Publisher = 0x0,
    /// Groups delivered in ascending order.
    Ascending = 0x1,
    /// Groups delivered in descending order.
    Descending = 0x2,
}

/// Forwarding preference for objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ForwardingPreference {
    /// Object forwarding (sent on a subgroup stream).
    Object = 0x0,
    /// Datagram forwarding (sent as a QUIC datagram).
    Datagram = 0x1,
}

/// Whether content exists (used in SUBSCRIBE_OK).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ContentExists {
    /// No largest location is provided.
    NoLargestLocation = 0,
    /// A largest location follows.
    HasLargestLocation = 1,
}

/// Forward state (0 = don't forward, 1 = forward).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Forward {
    /// Do not forward.
    DontForward = 0,
    /// Forward enabled.
    Forward = 1,
}

/// Subscription filter types (draft-14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FilterType {
    /// Start from the next group.
    NextGroupStart = 0x1,
    /// Start from the largest available object.
    LargestObject = 0x2,
    /// Start from an absolute location.
    AbsoluteStart = 0x3,
    /// Absolute range with start and end locations.
    AbsoluteRange = 0x4,
}

/// Authorization token alias types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TokenAliasType {
    /// Delete a previously registered alias.
    Delete = 0x0,
    /// Register a new alias.
    Register = 0x1,
    /// Use an existing alias.
    UseAlias = 0x2,
    /// Use a literal token value.
    UseValue = 0x3,
}

impl TrackNamespace {
    /// Encode the namespace tuple into the buffer.
    pub fn encode(&self, buf: &mut impl BufMut) {
        VarInt::from_usize(self.0.len()).encode(buf);
        for elem in &self.0 {
            VarInt::from_usize(elem.len()).encode(buf);
            buf.put_slice(elem);
        }
    }

    /// Decode a namespace tuple from the buffer.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, crate::error::CodecError> {
        let n = VarInt::decode(buf)?.into_inner() as usize;
        if n == 0 || n > crate::error::MAX_NAMESPACE_TUPLE_SIZE {
            return Err(crate::error::CodecError::InvalidNamespaceTupleSize(n));
        }
        Self::decode_elements(buf, n)
    }

    /// Decode a namespace tuple that may have zero elements (for suffix types).
    pub fn decode_allow_empty(buf: &mut impl Buf) -> Result<Self, crate::error::CodecError> {
        let n = VarInt::decode(buf)?.into_inner() as usize;
        if n > crate::error::MAX_NAMESPACE_TUPLE_SIZE {
            return Err(crate::error::CodecError::InvalidNamespaceTupleSize(n));
        }
        Self::decode_elements(buf, n)
    }

    fn decode_elements(buf: &mut impl Buf, n: usize) -> Result<Self, crate::error::CodecError> {
        let mut elements = Vec::with_capacity(n);
        for _ in 0..n {
            let len = VarInt::decode(buf)?.into_inner() as usize;
            elements.push(read_bytes(buf, len)?);
        }
        Ok(TrackNamespace(elements))
    }
}

impl Location {
    /// Encode the location (group, object) into the buffer.
    pub fn encode(&self, buf: &mut impl BufMut) {
        self.group.encode(buf);
        self.object.encode(buf);
    }

    /// Decode a location from the buffer.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, crate::error::CodecError> {
        let group = VarInt::decode(buf)?;
        let object = VarInt::decode(buf)?;
        Ok(Location { group, object })
    }
}

impl ObjectStatus {
    /// Convert a raw byte to an `ObjectStatus`, if valid.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x0 => Some(ObjectStatus::Normal),
            0x1 => Some(ObjectStatus::EndOfGroup),
            0x2 => Some(ObjectStatus::EndOfTrack),
            0x3 => Some(ObjectStatus::DoesNotExist),
            _ => None,
        }
    }
}

impl GroupOrder {
    /// Convert a raw byte to a `GroupOrder`, if valid.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x0 => Some(GroupOrder::Publisher),
            0x1 => Some(GroupOrder::Ascending),
            0x2 => Some(GroupOrder::Descending),
            _ => None,
        }
    }
}

impl ForwardingPreference {
    /// Convert a raw byte to a `ForwardingPreference`, if valid.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x0 => Some(ForwardingPreference::Object),
            0x1 => Some(ForwardingPreference::Datagram),
            _ => None,
        }
    }
}

impl FilterType {
    /// Convert a raw byte to a `FilterType`, if valid.
    pub fn from_u8(v: u8) -> Option<Self> {
        Self::from_u64(v as u64)
    }

    /// Convert a raw u64 to a `FilterType`, if valid.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0x1 => Some(FilterType::NextGroupStart),
            0x2 => Some(FilterType::LargestObject),
            0x3 => Some(FilterType::AbsoluteStart),
            0x4 => Some(FilterType::AbsoluteRange),
            _ => None,
        }
    }
}

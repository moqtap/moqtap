use crate::varint::VarInt;
use bytes::{Buf, BufMut};

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
        let n = self.0.len();
        VarInt::from_u64(n as u64).unwrap().encode(buf);
        for elem in &self.0 {
            VarInt::from_u64(elem.len() as u64).unwrap().encode(buf);
            buf.put_slice(elem);
        }
    }

    /// Decode a namespace tuple from the buffer.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, crate::error::CodecError> {
        let n = VarInt::decode(buf)?.into_inner() as usize;
        if n == 0 || n > crate::error::MAX_NAMESPACE_TUPLE_SIZE {
            return Err(crate::error::CodecError::InvalidNamespaceTupleSize(n));
        }
        let mut elements = Vec::with_capacity(n);
        for _ in 0..n {
            let len = VarInt::decode(buf)?.into_inner() as usize;
            if buf.remaining() < len {
                return Err(crate::error::CodecError::UnexpectedEnd);
            }
            let mut data = vec![0u8; len];
            buf.copy_to_slice(&mut data);
            elements.push(data);
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
        match v {
            0x1 => Some(FilterType::NextGroupStart),
            0x2 => Some(FilterType::LargestObject),
            0x3 => Some(FilterType::AbsoluteStart),
            0x4 => Some(FilterType::AbsoluteRange),
            _ => None,
        }
    }
}

use super::types::ObjectStatus;
use crate::error::CodecError;
use crate::varint::VarInt;
use bytes::{Buf, BufMut};

/// Stream type IDs for draft-07 data streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum StreamType {
    /// Datagram stream type (0x01).
    Datagram = 0x01,
    /// Subgroup stream type (0x04).
    Subgroup = 0x04,
    /// Fetch stream type (0x05).
    Fetch = 0x05,
}

impl StreamType {
    /// Convert a raw stream type ID to a `StreamType`, if valid.
    pub fn from_id(id: u64) -> Option<Self> {
        match id {
            0x01 => Some(StreamType::Datagram),
            0x04 => Some(StreamType::Subgroup),
            0x05 => Some(StreamType::Fetch),
            _ => None,
        }
    }
}

// ============================================================
// Subgroup stream (type 0x04)
// ============================================================

/// Subgroup stream header (follows the stream type varint).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubgroupHeader {
    /// Track alias identifying the subscription.
    pub track_alias: VarInt,
    /// Group identifier.
    pub group_id: VarInt,
    /// Subgroup identifier within the group.
    pub subgroup_id: VarInt,
    /// Publisher priority for delivery ordering.
    pub publisher_priority: u8,
}

/// Object within a subgroup stream.
///
/// Encoding: object_id(vi), payload_length(vi),
///   if payload_length == 0: object_status(vi)
///   else: payload bytes (status is implicitly Normal)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectHeader {
    /// Object identifier within the subgroup.
    pub object_id: VarInt,
    /// Length of the object payload in bytes.
    pub payload_length: VarInt,
    /// Status of this object.
    pub object_status: ObjectStatus,
}

impl SubgroupHeader {
    /// Encode the subgroup header into the buffer.
    pub fn encode(&self, buf: &mut impl BufMut) {
        self.track_alias.encode(buf);
        self.group_id.encode(buf);
        self.subgroup_id.encode(buf);
        buf.put_u8(self.publisher_priority);
    }

    /// Decode a subgroup header from the buffer.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let track_alias = VarInt::decode(buf)?;
        let group_id = VarInt::decode(buf)?;
        let subgroup_id = VarInt::decode(buf)?;
        if buf.remaining() < 1 {
            return Err(CodecError::UnexpectedEnd);
        }
        let publisher_priority = buf.get_u8();
        Ok(Self { track_alias, group_id, subgroup_id, publisher_priority })
    }
}

impl ObjectHeader {
    /// Encode the object header into the buffer.
    pub fn encode(&self, buf: &mut impl BufMut) {
        self.object_id.encode(buf);
        self.payload_length.encode(buf);
        if self.payload_length.into_inner() == 0 {
            VarInt::from_usize(self.object_status as usize).encode(buf);
        }
    }

    /// Decode an object header from the buffer.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let object_id = VarInt::decode(buf)?;
        let payload_length = VarInt::decode(buf)?;
        let object_status = if payload_length.into_inner() == 0 {
            let status_val = VarInt::decode(buf)?.into_inner();
            ObjectStatus::from_u64(status_val).ok_or(CodecError::InvalidField)?
        } else {
            ObjectStatus::Normal
        };
        Ok(Self { object_id, payload_length, object_status })
    }
}

// ============================================================
// Datagram (type 0x01)
// ============================================================

/// Datagram header (draft-07).
///
/// Encoding (after the type varint):
///   track_alias(vi), group_id(vi), object_id(vi),
///   publisher_priority(u8), payload_length(vi),
///   [object_status(vi) if payload_length==0],
///   payload bytes
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatagramHeader {
    /// Track alias identifying the subscription.
    pub track_alias: VarInt,
    /// Group identifier.
    pub group_id: VarInt,
    /// Object identifier within the group.
    pub object_id: VarInt,
    /// Publisher priority for delivery ordering.
    pub publisher_priority: u8,
    /// Status of this object.
    pub object_status: ObjectStatus,
    /// Length of the object payload in bytes.
    pub payload_length: VarInt,
}

impl DatagramHeader {
    /// Encode the datagram header into the buffer.
    pub fn encode(&self, buf: &mut impl BufMut) {
        self.track_alias.encode(buf);
        self.group_id.encode(buf);
        self.object_id.encode(buf);
        buf.put_u8(self.publisher_priority);
        self.payload_length.encode(buf);
        if self.payload_length.into_inner() == 0 {
            VarInt::from_usize(self.object_status as usize).encode(buf);
        }
    }

    /// Decode a datagram header from the buffer.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let track_alias = VarInt::decode(buf)?;
        let group_id = VarInt::decode(buf)?;
        let object_id = VarInt::decode(buf)?;
        if buf.remaining() < 1 {
            return Err(CodecError::UnexpectedEnd);
        }
        let publisher_priority = buf.get_u8();
        let payload_length = VarInt::decode(buf)?;
        let object_status = if payload_length.into_inner() == 0 {
            let status_val = VarInt::decode(buf)?.into_inner();
            ObjectStatus::from_u64(status_val).ok_or(CodecError::InvalidField)?
        } else {
            ObjectStatus::Normal
        };
        Ok(Self {
            track_alias,
            group_id,
            object_id,
            publisher_priority,
            object_status,
            payload_length,
        })
    }
}

// ============================================================
// Fetch stream (type 0x05)
// ============================================================

/// Fetch stream header (follows the stream type varint).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchHeader {
    /// Subscribe ID this fetch responds to.
    pub subscribe_id: VarInt,
}

/// Object within a fetch stream.
///
/// Encoding: group_id(vi), subgroup_id(vi), object_id(vi),
///   publisher_priority(u8), payload_length(vi),
///   [object_status(vi) if payload_length==0],
///   payload bytes
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchObjectHeader {
    /// Group identifier.
    pub group_id: VarInt,
    /// Subgroup identifier within the group.
    pub subgroup_id: VarInt,
    /// Object identifier within the subgroup.
    pub object_id: VarInt,
    /// Publisher priority for delivery ordering.
    pub publisher_priority: u8,
    /// Status of this object.
    pub object_status: ObjectStatus,
    /// Length of the object payload in bytes.
    pub payload_length: VarInt,
}

impl FetchHeader {
    /// Encode the fetch header into the buffer.
    pub fn encode(&self, buf: &mut impl BufMut) {
        self.subscribe_id.encode(buf);
    }

    /// Decode a fetch header from the buffer.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let subscribe_id = VarInt::decode(buf)?;
        Ok(Self { subscribe_id })
    }
}

impl FetchObjectHeader {
    /// Encode the fetch object header into the buffer.
    pub fn encode(&self, buf: &mut impl BufMut) {
        self.group_id.encode(buf);
        self.subgroup_id.encode(buf);
        self.object_id.encode(buf);
        buf.put_u8(self.publisher_priority);
        self.payload_length.encode(buf);
        if self.payload_length.into_inner() == 0 {
            VarInt::from_usize(self.object_status as usize).encode(buf);
        }
    }

    /// Decode a fetch object header from the buffer.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let group_id = VarInt::decode(buf)?;
        let subgroup_id = VarInt::decode(buf)?;
        let object_id = VarInt::decode(buf)?;
        if buf.remaining() < 1 {
            return Err(CodecError::UnexpectedEnd);
        }
        let publisher_priority = buf.get_u8();
        let payload_length = VarInt::decode(buf)?;
        let object_status = if payload_length.into_inner() == 0 {
            let status_val = VarInt::decode(buf)?.into_inner();
            ObjectStatus::from_u64(status_val).ok_or(CodecError::InvalidField)?
        } else {
            ObjectStatus::Normal
        };
        Ok(Self {
            group_id,
            subgroup_id,
            object_id,
            publisher_priority,
            object_status,
            payload_length,
        })
    }
}

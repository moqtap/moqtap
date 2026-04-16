//! Draft-09 data stream header encoding and decoding.
//!
//! Changes from draft-08:
//! - `extension_count` → `extension_headers_length` (byte length, not count)
//! - Datagram (0x01): no `payload_length` or `object_status`; payload is remaining bytes
//! - DatagramStatus (0x02): gains `extension_headers_length` field

use super::types::ObjectStatus;
use crate::error::CodecError;
use crate::types::read_bytes;
use crate::varint::VarInt;
use bytes::{Buf, BufMut};

/// Stream type IDs for draft-09 data streams (same IDs as draft-08).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum StreamType {
    /// Datagram with payload (0x01).
    Datagram = 0x01,
    /// Datagram with status only, no payload (0x02).
    DatagramStatus = 0x02,
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
            0x02 => Some(StreamType::DatagramStatus),
            0x04 => Some(StreamType::Subgroup),
            0x05 => Some(StreamType::Fetch),
            _ => None,
        }
    }
}

// ── Extension helpers (length-based, not count-based) ─────────

/// Read `byte_len` bytes of raw extension data from the buffer.
fn read_extension_bytes(buf: &mut impl Buf, byte_len: u64) -> Result<Vec<u8>, CodecError> {
    read_bytes(buf, byte_len as usize)
}

/// Encode extension bytes to the buffer (just writes the raw bytes).
fn encode_extensions(extensions: &[u8], buf: &mut impl BufMut) {
    buf.put_slice(extensions);
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

/// Object within a subgroup stream (draft-09).
///
/// Encoding: object_id(vi), extension_headers_length(vi), [extensions...],
///   payload_length(vi),
///   if payload_length == 0: object_status(vi)
///   else: payload bytes
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectHeader {
    /// Object identifier within the subgroup.
    pub object_id: VarInt,
    /// Total byte length of extension headers.
    pub extension_headers_length: VarInt,
    /// Raw extension bytes (opaque).
    pub extensions: Vec<u8>,
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
        self.extension_headers_length.encode(buf);
        encode_extensions(&self.extensions, buf);
        self.payload_length.encode(buf);
        if self.payload_length.into_inner() == 0 {
            VarInt::from_usize(self.object_status as usize).encode(buf);
        }
    }

    /// Decode an object header from the buffer.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let object_id = VarInt::decode(buf)?;
        let extension_headers_length = VarInt::decode(buf)?;
        let extensions = read_extension_bytes(buf, extension_headers_length.into_inner())?;
        let payload_length = VarInt::decode(buf)?;
        let object_status = if payload_length.into_inner() == 0 {
            let status_val = VarInt::decode(buf)?.into_inner();
            ObjectStatus::from_u64(status_val).ok_or(CodecError::InvalidField)?
        } else {
            ObjectStatus::Normal
        };
        Ok(Self { object_id, extension_headers_length, extensions, payload_length, object_status })
    }
}

// ============================================================
// Datagram (type 0x01)
// ============================================================

/// Datagram header with payload (draft-09, type 0x01).
///
/// Draft-09 change: no `payload_length` or `object_status` fields.
/// Payload is the remaining bytes in the datagram.
///
/// Encoding (after type varint):
///   track_alias(vi), group_id(vi), object_id(vi),
///   publisher_priority(u8), extension_headers_length(vi), [extensions...],
///   [remaining bytes = payload]
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
    /// Total byte length of extension headers.
    pub extension_headers_length: VarInt,
    /// Raw extension bytes (opaque).
    pub extensions: Vec<u8>,
}

impl DatagramHeader {
    /// Encode the datagram header into the buffer.
    pub fn encode(&self, buf: &mut impl BufMut) {
        self.track_alias.encode(buf);
        self.group_id.encode(buf);
        self.object_id.encode(buf);
        buf.put_u8(self.publisher_priority);
        self.extension_headers_length.encode(buf);
        encode_extensions(&self.extensions, buf);
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
        let extension_headers_length = VarInt::decode(buf)?;
        let extensions = read_extension_bytes(buf, extension_headers_length.into_inner())?;
        Ok(Self {
            track_alias,
            group_id,
            object_id,
            publisher_priority,
            extension_headers_length,
            extensions,
        })
    }
}

// ============================================================
// Datagram Status (type 0x02)
// ============================================================

/// Datagram status header (draft-09, type 0x02).
///
/// Draft-09 change: gains `extension_headers_length` field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatagramStatusHeader {
    /// Track alias identifying the subscription.
    pub track_alias: VarInt,
    /// Group identifier.
    pub group_id: VarInt,
    /// Object identifier within the group.
    pub object_id: VarInt,
    /// Publisher priority for delivery ordering.
    pub publisher_priority: u8,
    /// Total byte length of extension headers.
    pub extension_headers_length: VarInt,
    /// Raw extension bytes (opaque).
    pub extensions: Vec<u8>,
    /// Object status code.
    pub object_status: ObjectStatus,
}

impl DatagramStatusHeader {
    /// Encode the datagram status header into the buffer.
    pub fn encode(&self, buf: &mut impl BufMut) {
        self.track_alias.encode(buf);
        self.group_id.encode(buf);
        self.object_id.encode(buf);
        buf.put_u8(self.publisher_priority);
        self.extension_headers_length.encode(buf);
        encode_extensions(&self.extensions, buf);
        VarInt::from_usize(self.object_status as usize).encode(buf);
    }

    /// Decode a datagram status header from the buffer.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let track_alias = VarInt::decode(buf)?;
        let group_id = VarInt::decode(buf)?;
        let object_id = VarInt::decode(buf)?;
        if buf.remaining() < 1 {
            return Err(CodecError::UnexpectedEnd);
        }
        let publisher_priority = buf.get_u8();
        let extension_headers_length = VarInt::decode(buf)?;
        let extensions = read_extension_bytes(buf, extension_headers_length.into_inner())?;
        let status_val = VarInt::decode(buf)?.into_inner();
        let object_status = ObjectStatus::from_u64(status_val).ok_or(CodecError::InvalidField)?;
        Ok(Self {
            track_alias,
            group_id,
            object_id,
            publisher_priority,
            extension_headers_length,
            extensions,
            object_status,
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

/// Object within a fetch stream (draft-09).
///
/// Uses `extension_headers_length` instead of `extension_count`.
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
    /// Total byte length of extension headers.
    pub extension_headers_length: VarInt,
    /// Raw extension bytes (opaque).
    pub extensions: Vec<u8>,
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
        self.extension_headers_length.encode(buf);
        encode_extensions(&self.extensions, buf);
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
        let extension_headers_length = VarInt::decode(buf)?;
        let extensions = read_extension_bytes(buf, extension_headers_length.into_inner())?;
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
            extension_headers_length,
            extensions,
            object_status,
            payload_length,
        })
    }
}

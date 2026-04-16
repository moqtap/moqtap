//! Draft-11 data stream header encoding and decoding.
//!
//! Changes from draft-09/10:
//! - Datagram stream type IDs: 0x00 (no ext), 0x01 (with ext), 0x02 (status, no ext),
//!   0x03 (status, with ext)
//! - Subgroup stream types: 0x08-0x0D (6 variants based on subgroup_id encoding and extensions)
//! - Fetch stream type: 0x05 (request_id only in header)
//! - Object within subgroup: object_id + [ext_headers_length + extensions] + payload_length
//!   + [object_status if payload_length=0]

use super::types::ObjectStatus;
use crate::error::CodecError;
use crate::types::read_bytes;
use crate::varint::VarInt;
use bytes::{Buf, BufMut};

/// Stream type IDs for draft-11 data streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum StreamType {
    /// Object datagram, no extensions (0x00).
    Datagram = 0x00,
    /// Object datagram, with extensions (0x01).
    DatagramExt = 0x01,
    /// Object datagram status, no extensions (0x02).
    DatagramStatus = 0x02,
    /// Object datagram status, with extensions (0x03).
    DatagramStatusExt = 0x03,
    /// Fetch response stream (0x05).
    Fetch = 0x05,
    /// Subgroup: subgroup_id=0, no extensions (0x08).
    SubgroupZero = 0x08,
    /// Subgroup: subgroup_id=0, with extensions (0x09).
    SubgroupZeroExt = 0x09,
    /// Subgroup: subgroup_id=first object ID, no extensions (0x0A).
    SubgroupFirstObj = 0x0A,
    /// Subgroup: subgroup_id=first object ID, with extensions (0x0B).
    SubgroupFirstObjExt = 0x0B,
    /// Subgroup: explicit subgroup_id, no extensions (0x0C).
    SubgroupExplicit = 0x0C,
    /// Subgroup: explicit subgroup_id, with extensions (0x0D).
    SubgroupExplicitExt = 0x0D,
}

impl StreamType {
    /// Convert a raw stream type ID to a `StreamType`, if valid.
    pub fn from_id(id: u64) -> Option<Self> {
        match id {
            0x00 => Some(StreamType::Datagram),
            0x01 => Some(StreamType::DatagramExt),
            0x02 => Some(StreamType::DatagramStatus),
            0x03 => Some(StreamType::DatagramStatusExt),
            0x05 => Some(StreamType::Fetch),
            0x08 => Some(StreamType::SubgroupZero),
            0x09 => Some(StreamType::SubgroupZeroExt),
            0x0A => Some(StreamType::SubgroupFirstObj),
            0x0B => Some(StreamType::SubgroupFirstObjExt),
            0x0C => Some(StreamType::SubgroupExplicit),
            0x0D => Some(StreamType::SubgroupExplicitExt),
            _ => None,
        }
    }

    /// Whether this stream type is a subgroup variant.
    pub fn is_subgroup(&self) -> bool {
        matches!(
            self,
            StreamType::SubgroupZero
                | StreamType::SubgroupZeroExt
                | StreamType::SubgroupFirstObj
                | StreamType::SubgroupFirstObjExt
                | StreamType::SubgroupExplicit
                | StreamType::SubgroupExplicitExt
        )
    }

    /// Whether this stream type includes extension headers on objects.
    pub fn has_extensions(&self) -> bool {
        matches!(
            self,
            StreamType::DatagramExt
                | StreamType::DatagramStatusExt
                | StreamType::SubgroupZeroExt
                | StreamType::SubgroupFirstObjExt
                | StreamType::SubgroupExplicitExt
        )
    }
}

// ── Extension helpers ─────────────────────────────────────────

fn read_extension_bytes(buf: &mut impl Buf, byte_len: u64) -> Result<Vec<u8>, CodecError> {
    read_bytes(buf, byte_len as usize)
}

// ============================================================
// Subgroup stream header
// ============================================================

/// Subgroup stream header (unified across all 6 stream type variants).
///
/// Decoded representation includes `stream_type` to preserve the variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubgroupHeader {
    /// The stream type variant used for encoding.
    pub stream_type: StreamType,
    /// Track alias identifying the subscription.
    pub track_alias: VarInt,
    /// Group identifier.
    pub group_id: VarInt,
    /// Subgroup identifier within the group.
    pub subgroup_id: VarInt,
    /// Publisher priority for delivery ordering.
    pub publisher_priority: u8,
}

impl SubgroupHeader {
    /// Encode the subgroup header (always as explicit subgroup_id format).
    pub fn encode(&self, buf: &mut impl BufMut) {
        self.track_alias.encode(buf);
        self.group_id.encode(buf);
        match self.stream_type {
            StreamType::SubgroupExplicit | StreamType::SubgroupExplicitExt => {
                self.subgroup_id.encode(buf);
            }
            _ => {}
        }
        buf.put_u8(self.publisher_priority);
    }

    /// Decode a subgroup header (assumes explicit subgroup_id format).
    ///
    /// For stream-type-aware decoding, use [`Self::decode_with_type`].
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        Self::decode_with_type(StreamType::SubgroupExplicit, buf)
    }

    /// Decode a subgroup header with the specific stream type variant.
    pub fn decode_with_type(
        stream_type: StreamType,
        buf: &mut impl Buf,
    ) -> Result<Self, CodecError> {
        let track_alias = VarInt::decode(buf)?;
        let group_id = VarInt::decode(buf)?;
        let subgroup_id = match stream_type {
            StreamType::SubgroupZero | StreamType::SubgroupZeroExt => VarInt::from_usize(0),
            StreamType::SubgroupExplicit | StreamType::SubgroupExplicitExt => VarInt::decode(buf)?,
            // For FirstObj variants, subgroup_id is the first object's ID.
            // We read it later from the first object. Set to 0 for now;
            // the caller should update after reading the first object.
            StreamType::SubgroupFirstObj | StreamType::SubgroupFirstObjExt => VarInt::from_usize(0),
            _ => return Err(CodecError::InvalidField),
        };
        if buf.remaining() < 1 {
            return Err(CodecError::UnexpectedEnd);
        }
        let publisher_priority = buf.get_u8();
        Ok(Self { stream_type, track_alias, group_id, subgroup_id, publisher_priority })
    }
}

// ============================================================
// Object header within subgroup
// ============================================================

/// Object within a subgroup stream (draft-11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectHeader {
    /// Object identifier within the subgroup.
    pub object_id: VarInt,
    /// Total byte length of extension headers (0 if no extensions).
    pub extension_headers_length: VarInt,
    /// Raw extension bytes (opaque).
    pub extensions: Vec<u8>,
    /// Length of the object payload in bytes.
    pub payload_length: VarInt,
    /// Object status (Normal unless payload_length == 0).
    pub object_status: ObjectStatus,
}

impl ObjectHeader {
    /// Encode the object header (no extensions).
    ///
    /// For extension-aware encoding, use [`Self::encode_with_extensions`].
    pub fn encode(&self, buf: &mut impl BufMut) {
        self.encode_with_extensions(false, buf);
    }

    /// Encode the object header with extensions control.
    pub fn encode_with_extensions(&self, has_extensions: bool, buf: &mut impl BufMut) {
        self.object_id.encode(buf);
        if has_extensions {
            self.extension_headers_length.encode(buf);
            buf.put_slice(&self.extensions);
        }
        self.payload_length.encode(buf);
        if self.payload_length.into_inner() == 0 {
            VarInt::from_usize(self.object_status as usize).encode(buf);
        }
    }

    /// Decode an object header (no extensions).
    ///
    /// For extension-aware decoding, use [`Self::decode_with_extensions`].
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        Self::decode_with_extensions(false, buf)
    }

    /// Decode an object header with extensions control.
    pub fn decode_with_extensions(
        has_extensions: bool,
        buf: &mut impl Buf,
    ) -> Result<Self, CodecError> {
        let object_id = VarInt::decode(buf)?;
        let (extension_headers_length, extensions) = if has_extensions {
            let ehl = VarInt::decode(buf)?;
            let ext = read_extension_bytes(buf, ehl.into_inner())?;
            (ehl, ext)
        } else {
            (VarInt::from_usize(0), Vec::new())
        };
        let payload_length = VarInt::decode(buf)?;
        let object_status = if payload_length.into_inner() == 0 {
            let sv = VarInt::decode(buf)?.into_inner();
            ObjectStatus::from_u64(sv).ok_or(CodecError::InvalidField)?
        } else {
            ObjectStatus::Normal
        };
        Ok(Self { object_id, extension_headers_length, extensions, payload_length, object_status })
    }
}

// ============================================================
// Datagram (types 0x00, 0x01)
// ============================================================

/// Datagram header (draft-11, types 0x00/0x01).
///
/// Payload is the remaining bytes in the datagram after the header.
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
    /// Total byte length of extension headers (0 for type 0x00).
    pub extension_headers_length: VarInt,
    /// Raw extension bytes.
    pub extensions: Vec<u8>,
}

impl DatagramHeader {
    /// Encode the datagram header (no extensions).
    pub fn encode(&self, buf: &mut impl BufMut) {
        self.encode_with_extensions(false, buf);
    }

    /// Encode the datagram header with extensions control.
    pub fn encode_with_extensions(&self, has_extensions: bool, buf: &mut impl BufMut) {
        self.track_alias.encode(buf);
        self.group_id.encode(buf);
        self.object_id.encode(buf);
        buf.put_u8(self.publisher_priority);
        if has_extensions {
            self.extension_headers_length.encode(buf);
            buf.put_slice(&self.extensions);
        }
    }

    /// Decode a datagram header (no extensions).
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        Self::decode_with_extensions(false, buf)
    }

    /// Decode a datagram header with extensions control.
    pub fn decode_with_extensions(
        has_extensions: bool,
        buf: &mut impl Buf,
    ) -> Result<Self, CodecError> {
        let track_alias = VarInt::decode(buf)?;
        let group_id = VarInt::decode(buf)?;
        let object_id = VarInt::decode(buf)?;
        if buf.remaining() < 1 {
            return Err(CodecError::UnexpectedEnd);
        }
        let publisher_priority = buf.get_u8();
        let (extension_headers_length, extensions) = if has_extensions {
            let ehl = VarInt::decode(buf)?;
            let ext = read_extension_bytes(buf, ehl.into_inner())?;
            (ehl, ext)
        } else {
            (VarInt::from_usize(0), Vec::new())
        };
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
// Datagram Status (types 0x02, 0x03)
// ============================================================

/// Datagram status header (draft-11, types 0x02/0x03).
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
    /// Total byte length of extension headers (0 for type 0x02).
    pub extension_headers_length: VarInt,
    /// Raw extension bytes.
    pub extensions: Vec<u8>,
    /// Object status code.
    pub object_status: ObjectStatus,
}

impl DatagramStatusHeader {
    /// Encode the datagram status header (no extensions).
    pub fn encode(&self, buf: &mut impl BufMut) {
        self.encode_with_extensions(false, buf);
    }

    /// Encode the datagram status header with extensions control.
    pub fn encode_with_extensions(&self, has_extensions: bool, buf: &mut impl BufMut) {
        self.track_alias.encode(buf);
        self.group_id.encode(buf);
        self.object_id.encode(buf);
        buf.put_u8(self.publisher_priority);
        if has_extensions {
            self.extension_headers_length.encode(buf);
            buf.put_slice(&self.extensions);
        }
        VarInt::from_usize(self.object_status as usize).encode(buf);
    }

    /// Decode a datagram status header (no extensions).
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        Self::decode_with_extensions(false, buf)
    }

    /// Decode a datagram status header with extensions control.
    pub fn decode_with_extensions(
        has_extensions: bool,
        buf: &mut impl Buf,
    ) -> Result<Self, CodecError> {
        let track_alias = VarInt::decode(buf)?;
        let group_id = VarInt::decode(buf)?;
        let object_id = VarInt::decode(buf)?;
        if buf.remaining() < 1 {
            return Err(CodecError::UnexpectedEnd);
        }
        let publisher_priority = buf.get_u8();
        let (extension_headers_length, extensions) = if has_extensions {
            let ehl = VarInt::decode(buf)?;
            let ext = read_extension_bytes(buf, ehl.into_inner())?;
            (ehl, ext)
        } else {
            (VarInt::from_usize(0), Vec::new())
        };
        let sv = VarInt::decode(buf)?.into_inner();
        let object_status = ObjectStatus::from_u64(sv).ok_or(CodecError::InvalidField)?;
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

/// Fetch stream header (draft-11, type 0x05).
///
/// Contains only the request_id. Objects follow inline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchHeader {
    /// Request ID this fetch responds to.
    pub request_id: VarInt,
}

/// Object within a fetch stream (draft-11).
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
    /// Raw extension bytes.
    pub extensions: Vec<u8>,
    /// Length of the object payload in bytes.
    pub payload_length: VarInt,
    /// Object status (Normal unless payload_length == 0).
    pub object_status: ObjectStatus,
}

impl FetchHeader {
    /// Encode the fetch header.
    pub fn encode(&self, buf: &mut impl BufMut) {
        self.request_id.encode(buf);
    }

    /// Decode a fetch header.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let request_id = VarInt::decode(buf)?;
        Ok(Self { request_id })
    }
}

impl FetchObjectHeader {
    /// Encode the fetch object header.
    pub fn encode(&self, buf: &mut impl BufMut) {
        self.group_id.encode(buf);
        self.subgroup_id.encode(buf);
        self.object_id.encode(buf);
        buf.put_u8(self.publisher_priority);
        self.extension_headers_length.encode(buf);
        buf.put_slice(&self.extensions);
        self.payload_length.encode(buf);
        if self.payload_length.into_inner() == 0 {
            VarInt::from_usize(self.object_status as usize).encode(buf);
        }
    }

    /// Decode a fetch object header.
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
            let sv = VarInt::decode(buf)?.into_inner();
            ObjectStatus::from_u64(sv).ok_or(CodecError::InvalidField)?
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
            payload_length,
            object_status,
        })
    }
}

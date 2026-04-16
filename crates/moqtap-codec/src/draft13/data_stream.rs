//! Draft-13 data stream header encoding and decoding.
//!
//! - Subgroup stream type IDs: 0x10-0x15, 0x18-0x1D
//! - Fetch stream type: 0x05
//! - Datagram types (separate namespace): 0x00-0x05

use super::types::ObjectStatus;
use crate::error::CodecError;
use crate::types::read_bytes;
use crate::varint::VarInt;
use bytes::{Buf, BufMut};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum StreamType {
    Fetch = 0x05,
    SubgroupZero = 0x10,
    SubgroupZeroExt = 0x11,
    SubgroupFirstObj = 0x12,
    SubgroupFirstObjExt = 0x13,
    SubgroupExplicit = 0x14,
    SubgroupExplicitExt = 0x15,
    SubgroupZeroEog = 0x18,
    SubgroupZeroEogExt = 0x19,
    SubgroupFirstObjEog = 0x1A,
    SubgroupFirstObjEogExt = 0x1B,
    SubgroupExplicitEog = 0x1C,
    SubgroupExplicitEogExt = 0x1D,
}

impl StreamType {
    pub fn from_id(id: u64) -> Option<Self> {
        match id {
            0x05 => Some(StreamType::Fetch),
            0x10 => Some(StreamType::SubgroupZero),
            0x11 => Some(StreamType::SubgroupZeroExt),
            0x12 => Some(StreamType::SubgroupFirstObj),
            0x13 => Some(StreamType::SubgroupFirstObjExt),
            0x14 => Some(StreamType::SubgroupExplicit),
            0x15 => Some(StreamType::SubgroupExplicitExt),
            0x18 => Some(StreamType::SubgroupZeroEog),
            0x19 => Some(StreamType::SubgroupZeroEogExt),
            0x1A => Some(StreamType::SubgroupFirstObjEog),
            0x1B => Some(StreamType::SubgroupFirstObjEogExt),
            0x1C => Some(StreamType::SubgroupExplicitEog),
            0x1D => Some(StreamType::SubgroupExplicitEogExt),
            _ => None,
        }
    }

    pub fn is_subgroup(&self) -> bool {
        matches!(
            self,
            StreamType::SubgroupZero
                | StreamType::SubgroupZeroExt
                | StreamType::SubgroupFirstObj
                | StreamType::SubgroupFirstObjExt
                | StreamType::SubgroupExplicit
                | StreamType::SubgroupExplicitExt
                | StreamType::SubgroupZeroEog
                | StreamType::SubgroupZeroEogExt
                | StreamType::SubgroupFirstObjEog
                | StreamType::SubgroupFirstObjEogExt
                | StreamType::SubgroupExplicitEog
                | StreamType::SubgroupExplicitEogExt
        )
    }

    pub fn has_extensions(&self) -> bool {
        matches!(
            self,
            StreamType::SubgroupZeroExt
                | StreamType::SubgroupFirstObjExt
                | StreamType::SubgroupExplicitExt
                | StreamType::SubgroupZeroEogExt
                | StreamType::SubgroupFirstObjEogExt
                | StreamType::SubgroupExplicitEogExt
        )
    }

    pub fn contains_end_of_group(&self) -> bool {
        matches!(
            self,
            StreamType::SubgroupZeroEog
                | StreamType::SubgroupZeroEogExt
                | StreamType::SubgroupFirstObjEog
                | StreamType::SubgroupFirstObjEogExt
                | StreamType::SubgroupExplicitEog
                | StreamType::SubgroupExplicitEogExt
        )
    }
}

/// Datagram wire types (separate namespace from QUIC stream types).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum DatagramType {
    Datagram = 0x00,
    DatagramExt = 0x01,
    DatagramEog = 0x02,
    DatagramEogExt = 0x03,
    DatagramStatus = 0x04,
    DatagramStatusExt = 0x05,
}

impl DatagramType {
    pub fn from_id(id: u64) -> Option<Self> {
        match id {
            0x00 => Some(DatagramType::Datagram),
            0x01 => Some(DatagramType::DatagramExt),
            0x02 => Some(DatagramType::DatagramEog),
            0x03 => Some(DatagramType::DatagramEogExt),
            0x04 => Some(DatagramType::DatagramStatus),
            0x05 => Some(DatagramType::DatagramStatusExt),
            _ => None,
        }
    }

    pub fn has_extensions(&self) -> bool {
        matches!(
            self,
            DatagramType::DatagramExt
                | DatagramType::DatagramEogExt
                | DatagramType::DatagramStatusExt
        )
    }

    pub fn is_status(&self) -> bool {
        matches!(self, DatagramType::DatagramStatus | DatagramType::DatagramStatusExt)
    }

    pub fn is_end_of_group(&self) -> bool {
        matches!(self, DatagramType::DatagramEog | DatagramType::DatagramEogExt)
    }
}

fn read_extension_bytes(buf: &mut impl Buf, byte_len: u64) -> Result<Vec<u8>, CodecError> {
    read_bytes(buf, byte_len as usize)
}

// ============================================================
// Subgroup stream header
// ============================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubgroupHeader {
    pub stream_type: StreamType,
    pub track_alias: VarInt,
    pub group_id: VarInt,
    pub subgroup_id: VarInt,
    pub publisher_priority: u8,
}

impl SubgroupHeader {
    pub fn encode(&self, buf: &mut impl BufMut) {
        self.track_alias.encode(buf);
        self.group_id.encode(buf);
        match self.stream_type {
            StreamType::SubgroupExplicit
            | StreamType::SubgroupExplicitExt
            | StreamType::SubgroupExplicitEog
            | StreamType::SubgroupExplicitEogExt => {
                self.subgroup_id.encode(buf);
            }
            _ => {}
        }
        buf.put_u8(self.publisher_priority);
    }

    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        Self::decode_with_type(StreamType::SubgroupExplicit, buf)
    }

    pub fn decode_with_type(
        stream_type: StreamType,
        buf: &mut impl Buf,
    ) -> Result<Self, CodecError> {
        let track_alias = VarInt::decode(buf)?;
        let group_id = VarInt::decode(buf)?;
        let subgroup_id = match stream_type {
            StreamType::SubgroupZero
            | StreamType::SubgroupZeroExt
            | StreamType::SubgroupZeroEog
            | StreamType::SubgroupZeroEogExt => VarInt::from_usize(0),
            StreamType::SubgroupExplicit
            | StreamType::SubgroupExplicitExt
            | StreamType::SubgroupExplicitEog
            | StreamType::SubgroupExplicitEogExt => VarInt::decode(buf)?,
            StreamType::SubgroupFirstObj
            | StreamType::SubgroupFirstObjExt
            | StreamType::SubgroupFirstObjEog
            | StreamType::SubgroupFirstObjEogExt => VarInt::from_usize(0),
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectHeader {
    pub object_id: VarInt,
    pub extension_headers_length: VarInt,
    pub extensions: Vec<u8>,
    pub payload_length: VarInt,
    pub object_status: ObjectStatus,
}

impl ObjectHeader {
    pub fn encode(&self, buf: &mut impl BufMut) {
        self.encode_with_extensions(false, buf);
    }

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

    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        Self::decode_with_extensions(false, buf)
    }

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatagramHeader {
    pub track_alias: VarInt,
    pub group_id: VarInt,
    pub object_id: VarInt,
    pub publisher_priority: u8,
    pub extension_headers_length: VarInt,
    pub extensions: Vec<u8>,
    pub end_of_group: bool,
}

impl DatagramHeader {
    pub fn encode(&self, buf: &mut impl BufMut) {
        self.encode_with_extensions(false, buf);
    }

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

    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        Self::decode_with_extensions(false, buf)
    }

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
            end_of_group: false,
        })
    }
}

// ============================================================
// Datagram Status (types 0x04, 0x05)
// ============================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatagramStatusHeader {
    pub track_alias: VarInt,
    pub group_id: VarInt,
    pub object_id: VarInt,
    pub publisher_priority: u8,
    pub extension_headers_length: VarInt,
    pub extensions: Vec<u8>,
    pub object_status: ObjectStatus,
}

impl DatagramStatusHeader {
    pub fn encode(&self, buf: &mut impl BufMut) {
        self.encode_with_extensions(false, buf);
    }

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

    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        Self::decode_with_extensions(false, buf)
    }

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchHeader {
    pub request_id: VarInt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchObjectHeader {
    pub group_id: VarInt,
    pub subgroup_id: VarInt,
    pub object_id: VarInt,
    pub publisher_priority: u8,
    pub extension_headers_length: VarInt,
    pub extensions: Vec<u8>,
    pub payload_length: VarInt,
    pub object_status: ObjectStatus,
}

impl FetchHeader {
    pub fn encode(&self, buf: &mut impl BufMut) {
        self.request_id.encode(buf);
    }

    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let request_id = VarInt::decode(buf)?;
        Ok(Self { request_id })
    }
}

impl FetchObjectHeader {
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

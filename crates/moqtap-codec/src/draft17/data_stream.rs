//! Draft-17 data stream header encoding and decoding.
//!
//! Subgroup header type byte: 0b00X1XXXX (bit 4 always set)
//!   - bit 0 (0x01): PROPERTIES
//!   - bits 1-2 (0x06): SUBGROUP_ID_MODE (0=zero, 1=first_obj, 2=explicit, 3=reserved)
//!   - bit 3 (0x08): END_OF_GROUP
//!   - bit 5 (0x20): DEFAULT_PRIORITY (no priority byte)
//!
//! Datagram type byte: 0b00X0XXXX (bit 4 always 0)
//!   - bit 0 (0x01): PROPERTIES
//!   - bit 1 (0x02): END_OF_GROUP
//!   - bit 2 (0x04): ZERO_OBJECT_ID (object_id=0, field omitted)
//!   - bit 3 (0x08): DEFAULT_PRIORITY (no priority byte)
//!   - bit 5 (0x20): STATUS (status byte replaces payload)
//!
//! Fetch header: stream type 0x05 + request_id.

use bytes::{Buf, BufMut};

use crate::error::CodecError;
use crate::varint::VarInt;

// ── Subgroup ──────────────────────────────────────────────────

const SUBGROUP_PROPERTIES_BIT: u8 = 0x01;
const SUBGROUP_ID_MODE_MASK: u8 = 0x06;
const SUBGROUP_END_OF_GROUP_BIT: u8 = 0x08;
const SUBGROUP_BASE_BIT: u8 = 0x10;
const SUBGROUP_DEFAULT_PRIORITY_BIT: u8 = 0x20;

#[derive(Debug, Clone)]
pub struct SubgroupHeader {
    pub header_type: u8,
    pub track_alias: VarInt,
    pub group_id: VarInt,
    pub subgroup_id: VarInt,
    pub publisher_priority: Option<u8>,
}

impl SubgroupHeader {
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        if buf.remaining() < 1 {
            return Err(CodecError::UnexpectedEnd);
        }
        let header_type = buf.get_u8();

        // Validate: bit 4 must be set
        if header_type & SUBGROUP_BASE_BIT == 0 {
            return Err(CodecError::InvalidField);
        }

        let track_alias = VarInt::decode(buf)?;
        let group_id = VarInt::decode(buf)?;

        let subgroup_id_mode = (header_type & SUBGROUP_ID_MODE_MASK) >> 1;
        let subgroup_id = match subgroup_id_mode {
            0 => VarInt::from_u64(0).unwrap(),
            2 => VarInt::decode(buf)?,
            // Modes 1 and 3: mode 1 = first object's ID (resolved later),
            // mode 3 = reserved. Store 0 for now.
            _ => VarInt::from_u64(0).unwrap(),
        };

        let publisher_priority = if header_type & SUBGROUP_DEFAULT_PRIORITY_BIT == 0 {
            if buf.remaining() < 1 {
                return Err(CodecError::UnexpectedEnd);
            }
            Some(buf.get_u8())
        } else {
            None
        };

        Ok(SubgroupHeader { header_type, track_alias, group_id, subgroup_id, publisher_priority })
    }

    pub fn encode(&self, buf: &mut impl BufMut) {
        buf.put_u8(self.header_type);
        self.track_alias.encode(buf);
        self.group_id.encode(buf);

        let subgroup_id_mode = (self.header_type & SUBGROUP_ID_MODE_MASK) >> 1;
        if subgroup_id_mode == 2 {
            self.subgroup_id.encode(buf);
        }

        if self.header_type & SUBGROUP_DEFAULT_PRIORITY_BIT == 0 {
            buf.put_u8(self.publisher_priority.unwrap_or(128));
        }
    }

    pub fn has_properties(&self) -> bool {
        self.header_type & SUBGROUP_PROPERTIES_BIT != 0
    }

    pub fn is_end_of_group(&self) -> bool {
        self.header_type & SUBGROUP_END_OF_GROUP_BIT != 0
    }
}

// ── Subgroup objects (stateful) ───────────────────────────────

/// One object within a draft-17 subgroup stream. Object IDs are
/// delta-encoded and the presence of a "properties" block (the
/// draft-17 equivalent of extension headers) is determined by the
/// PROPERTIES bit on the enclosing [`SubgroupHeader`]. Use
/// [`SubgroupObjectReader`] to encode/decode.
#[derive(Debug, Clone)]
pub struct SubgroupObject {
    pub object_id: VarInt,
    /// Raw properties bytes (empty unless the subgroup header sets the
    /// PROPERTIES bit). When present, holds the `ext_count` varint
    /// followed by each property's `key`, `vlen`, and value.
    pub extension_headers: Vec<u8>,
    pub payload_length: VarInt,
    pub object_status: Option<VarInt>,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SubgroupObjectReader {
    extensions_present: bool,
    prev_object_id: Option<u64>,
}

impl SubgroupObjectReader {
    pub fn new(header: &SubgroupHeader) -> Self {
        Self { extensions_present: header.has_properties(), prev_object_id: None }
    }

    pub fn read_object(&mut self, buf: &mut impl Buf) -> Result<SubgroupObject, CodecError> {
        let delta = VarInt::decode(buf)?.into_inner();
        let object_id_val = match self.prev_object_id {
            None => delta,
            Some(prev) => prev
                .checked_add(1)
                .and_then(|v| v.checked_add(delta))
                .ok_or(CodecError::InvalidField)?,
        };
        self.prev_object_id = Some(object_id_val);
        let object_id = VarInt::from_u64(object_id_val).map_err(|_| CodecError::InvalidField)?;

        let extension_headers = if self.extensions_present {
            let mut out: Vec<u8> = Vec::new();
            let ext_count = VarInt::decode(buf)?;
            ext_count.encode(&mut out);
            let count = ext_count.into_inner();
            for _ in 0..count {
                let key = VarInt::decode(buf)?;
                let vlen = VarInt::decode(buf)?;
                let vlen_usize = vlen.into_inner() as usize;
                if buf.remaining() < vlen_usize {
                    return Err(CodecError::UnexpectedEnd);
                }
                key.encode(&mut out);
                vlen.encode(&mut out);
                let value = buf.copy_to_bytes(vlen_usize);
                out.extend_from_slice(&value);
            }
            out
        } else {
            Vec::new()
        };

        let payload_length_vi = VarInt::decode(buf)?;
        let payload_length_val = payload_length_vi.into_inner() as usize;
        let (object_status, payload) = if payload_length_val == 0 {
            let status = VarInt::decode(buf)?;
            (Some(status), Vec::new())
        } else {
            let payload = crate::types::read_bytes(buf, payload_length_val)?;
            (None, payload)
        };

        Ok(SubgroupObject {
            object_id,
            extension_headers,
            payload_length: payload_length_vi,
            object_status,
            payload,
        })
    }

    pub fn write_object(
        &mut self,
        object: &SubgroupObject,
        buf: &mut impl BufMut,
    ) -> Result<(), CodecError> {
        let oid = object.object_id.into_inner();
        let delta = match self.prev_object_id {
            None => oid,
            Some(prev) => oid
                .checked_sub(prev)
                .and_then(|v| v.checked_sub(1))
                .ok_or(CodecError::InvalidField)?,
        };
        VarInt::from_u64(delta).map_err(|_| CodecError::InvalidField)?.encode(buf);
        if self.extensions_present {
            buf.put_slice(&object.extension_headers);
        }
        object.payload_length.encode(buf);
        if object.payload_length.into_inner() == 0 {
            if let Some(s) = &object.object_status {
                s.encode(buf);
            } else {
                VarInt::from_u64(0).unwrap().encode(buf);
            }
        } else {
            buf.put_slice(&object.payload);
        }
        self.prev_object_id = Some(oid);
        Ok(())
    }
}

// ── Datagram ──────────────────────────────────────────────────

const DATAGRAM_PROPERTIES_BIT: u8 = 0x01;
const DATAGRAM_END_OF_GROUP_BIT: u8 = 0x02;
const DATAGRAM_ZERO_OBJECT_ID_BIT: u8 = 0x04;
const DATAGRAM_DEFAULT_PRIORITY_BIT: u8 = 0x08;
const DATAGRAM_STATUS_BIT: u8 = 0x20;

#[derive(Debug, Clone)]
pub struct DatagramHeader {
    pub datagram_type: u8,
    pub track_alias: VarInt,
    pub group_id: VarInt,
    pub object_id: VarInt,
    pub publisher_priority: Option<u8>,
    pub object_status: Option<u8>,
}

impl DatagramHeader {
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        if buf.remaining() < 1 {
            return Err(CodecError::UnexpectedEnd);
        }
        let datagram_type = buf.get_u8();

        let track_alias = VarInt::decode(buf)?;
        let group_id = VarInt::decode(buf)?;

        let object_id = if datagram_type & DATAGRAM_ZERO_OBJECT_ID_BIT != 0 {
            VarInt::from_usize(0)
        } else {
            VarInt::decode(buf)?
        };

        let publisher_priority = if datagram_type & DATAGRAM_DEFAULT_PRIORITY_BIT == 0 {
            if buf.remaining() < 1 {
                return Err(CodecError::UnexpectedEnd);
            }
            Some(buf.get_u8())
        } else {
            None
        };

        // Skip properties if present
        if datagram_type & DATAGRAM_PROPERTIES_BIT != 0 {
            let props_len = VarInt::decode(buf)?.into_inner() as usize;
            if buf.remaining() < props_len {
                return Err(CodecError::UnexpectedEnd);
            }
            buf.advance(props_len);
        }

        let object_status = if datagram_type & DATAGRAM_STATUS_BIT != 0 {
            if buf.remaining() < 1 {
                return Err(CodecError::UnexpectedEnd);
            }
            Some(buf.get_u8())
        } else {
            None
        };

        Ok(DatagramHeader {
            datagram_type,
            track_alias,
            group_id,
            object_id,
            publisher_priority,
            object_status,
        })
    }

    pub fn encode(&self, buf: &mut impl BufMut) {
        buf.put_u8(self.datagram_type);
        self.track_alias.encode(buf);
        self.group_id.encode(buf);

        if self.datagram_type & DATAGRAM_ZERO_OBJECT_ID_BIT == 0 {
            self.object_id.encode(buf);
        }

        if self.datagram_type & DATAGRAM_DEFAULT_PRIORITY_BIT == 0 {
            buf.put_u8(self.publisher_priority.unwrap_or(128));
        }

        if self.datagram_type & DATAGRAM_STATUS_BIT != 0 {
            buf.put_u8(self.object_status.unwrap_or(0));
        }
    }

    pub fn is_end_of_group(&self) -> bool {
        self.datagram_type & DATAGRAM_END_OF_GROUP_BIT != 0
    }

    pub fn has_status(&self) -> bool {
        self.datagram_type & DATAGRAM_STATUS_BIT != 0
    }
}

// ── Fetch Header ──────────────────────────────────────────────

const FETCH_STREAM_TYPE: u64 = 0x05;

#[derive(Debug, Clone)]
pub struct FetchHeader {
    pub request_id: VarInt,
}

impl FetchHeader {
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let stream_type = VarInt::decode(buf)?.into_inner();
        if stream_type != FETCH_STREAM_TYPE {
            return Err(CodecError::InvalidField);
        }
        let request_id = VarInt::decode(buf)?;
        Ok(FetchHeader { request_id })
    }

    pub fn encode(&self, buf: &mut impl BufMut) {
        VarInt::from_usize(FETCH_STREAM_TYPE as usize).encode(buf);
        self.request_id.encode(buf);
    }
}

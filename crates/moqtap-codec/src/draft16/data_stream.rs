//! Draft-16 data stream header encoding and decoding.
//!
//! Draft-16 subgroup type-byte flag layout (differs from draft-15):
//! - `& 0x01`: extensions present on objects
//! - `& 0x02`: subgroup_id_mode bit — when set, subgroup_id = first object_id
//! - `& 0x04`: explicit subgroup_id present on the wire
//! - `& 0x08`: end-of-group marker
//! - `& 0x20`: no publisher_priority (0x30+ types)
//!
//! Draft-16 datagram type-byte flag layout:
//! - `0x01`: extensions present (byte-length-prefixed blob)
//! - `0x02`: end-of-group
//! - `0x04`: no object_id (object_id = 0 implied)
//! - `0x08`: default priority (priority omitted, inherited)
//! - `0x20`: status datagram (carries object_status instead of payload)
//!
//! Extension headers in draft-16 are byte-length-prefixed opaque blobs
//! (not count-prefixed as in draft-14).

use crate::error::CodecError;
use crate::varint::VarInt;
use bytes::{Buf, BufMut};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubgroupHeader {
    pub header_type: u8,
    pub track_alias: VarInt,
    pub group_id: VarInt,
    pub subgroup_id: VarInt,
    pub publisher_priority: Option<u8>,
}

impl SubgroupHeader {
    pub fn has_extensions(&self) -> bool {
        self.header_type & 0x01 != 0
    }

    /// When set, the subgroup_id is implicitly the first object's ID
    /// (not transmitted on the wire).
    pub fn subgroup_id_from_first_object(&self) -> bool {
        self.header_type & 0x02 != 0
    }

    pub fn has_explicit_subgroup_id(&self) -> bool {
        self.header_type & 0x04 != 0
    }

    pub fn has_end_of_group(&self) -> bool {
        self.header_type & 0x08 != 0
    }

    pub fn has_priority(&self) -> bool {
        self.header_type & 0x20 == 0
    }

    pub fn encode(&self, buf: &mut impl BufMut) {
        VarInt::from_usize(self.header_type as usize).encode(buf);
        self.track_alias.encode(buf);
        self.group_id.encode(buf);
        if self.has_explicit_subgroup_id() {
            self.subgroup_id.encode(buf);
        }
        if let Some(p) = self.publisher_priority {
            buf.put_u8(p);
        }
    }

    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let header_type = VarInt::decode(buf)?.into_inner() as u8;
        let base = header_type & 0xD0;
        if base != 0x10 && base != 0x30 {
            return Err(CodecError::InvalidField);
        }
        let track_alias = VarInt::decode(buf)?;
        let group_id = VarInt::decode(buf)?;
        let subgroup_id =
            if header_type & 0x04 != 0 { VarInt::decode(buf)? } else { VarInt::from_usize(0) };
        let publisher_priority = if header_type & 0x20 == 0 {
            if buf.remaining() < 1 {
                return Err(CodecError::UnexpectedEnd);
            }
            Some(buf.get_u8())
        } else {
            None
        };
        Ok(Self { header_type, track_alias, group_id, subgroup_id, publisher_priority })
    }
}

/// One object within a draft-16 subgroup stream with its Object ID
/// already resolved from the delta encoding. See
/// [`SubgroupObjectReader`] for stateful encode/decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubgroupObject {
    pub object_id: VarInt,
    pub extension_headers: Vec<u8>,
    pub payload_length: VarInt,
    pub object_status: Option<VarInt>,
    pub payload: Vec<u8>,
}

/// Stateful reader/writer for draft-16 subgroup objects. Mirrors the
/// draft-15 semantics (delta-encoded object IDs and header-typed
/// extension presence).
#[derive(Debug, Clone)]
pub struct SubgroupObjectReader {
    extensions_present: bool,
    prev_object_id: Option<u64>,
}

impl SubgroupObjectReader {
    pub fn new(header: &SubgroupHeader) -> Self {
        Self { extensions_present: header.has_extensions(), prev_object_id: None }
    }

    pub fn read_object(&mut self, buf: &mut impl Buf) -> Result<SubgroupObject, CodecError> {
        let delta = VarInt::decode(buf)?.into_inner();
        // Draft-16 subgroup object delta encoding:
        // - First object: `delta` is the absolute object_id.
        // - Subsequent objects (no extensions): `delta` gap to next id,
        //   resolved as `prev + delta + 1`.
        // - Subsequent objects (extensions flag set): `delta` is the
        //   already-adjusted offset, resolved as `prev + delta`.
        let object_id_val = match self.prev_object_id {
            None => delta,
            Some(prev) => {
                if self.extensions_present {
                    prev.checked_add(delta).ok_or(CodecError::InvalidField)?
                } else {
                    prev.checked_add(1)
                        .and_then(|v| v.checked_add(delta))
                        .ok_or(CodecError::InvalidField)?
                }
            }
        };
        self.prev_object_id = Some(object_id_val);
        let object_id = VarInt::from_u64(object_id_val).map_err(|_| CodecError::InvalidField)?;

        // Draft-16: extensions are a byte-length-prefixed opaque blob.
        let extension_headers = if self.extensions_present {
            let ext_len = VarInt::decode(buf)?.into_inner() as usize;
            crate::types::read_bytes(buf, ext_len)?
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
            Some(prev) => {
                if self.extensions_present {
                    oid.checked_sub(prev).ok_or(CodecError::InvalidField)?
                } else {
                    oid.checked_sub(prev)
                        .and_then(|v| v.checked_sub(1))
                        .ok_or(CodecError::InvalidField)?
                }
            }
        };
        VarInt::from_u64(delta).map_err(|_| CodecError::InvalidField)?.encode(buf);
        if self.extensions_present {
            let ext_len = object.extension_headers.len();
            VarInt::from_usize(ext_len).encode(buf);
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatagramHeader {
    pub datagram_type: u8,
    pub track_alias: VarInt,
    pub group_id: VarInt,
    pub object_id: VarInt,
    /// Publisher priority — `None` when the DEFAULT_PRIORITY flag is set and
    /// the priority is inherited from the subscription's control message.
    pub publisher_priority: Option<u8>,
    /// Opaque extension-headers blob (only when flag 0x01 is set).
    pub extension_headers: Vec<u8>,
    pub object_status: Option<VarInt>,
}

impl DatagramHeader {
    pub fn has_extensions(&self) -> bool {
        self.datagram_type & 0x01 != 0
    }

    pub fn is_end_of_group(&self) -> bool {
        self.datagram_type & 0x02 != 0
    }

    pub fn has_object_id(&self) -> bool {
        self.datagram_type & 0x04 == 0
    }

    /// When set, publisher_priority is omitted on the wire and inherited
    /// from the subscription / control-message context.
    pub fn has_default_priority(&self) -> bool {
        self.datagram_type & 0x08 != 0
    }

    pub fn is_status(&self) -> bool {
        self.datagram_type & 0x20 != 0
    }

    pub fn encode(&self, buf: &mut impl BufMut) {
        VarInt::from_usize(self.datagram_type as usize).encode(buf);
        self.track_alias.encode(buf);
        self.group_id.encode(buf);
        if self.has_object_id() {
            self.object_id.encode(buf);
        }
        if !self.has_default_priority() {
            buf.put_u8(self.publisher_priority.unwrap_or(128));
        }
        if self.has_extensions() {
            VarInt::from_usize(self.extension_headers.len()).encode(buf);
            buf.put_slice(&self.extension_headers);
        }
        if self.is_status() {
            if let Some(s) = &self.object_status {
                s.encode(buf);
            }
        }
    }

    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let datagram_type = VarInt::decode(buf)?.into_inner() as u8;
        let track_alias = VarInt::decode(buf)?;
        let group_id = VarInt::decode(buf)?;
        let object_id =
            if datagram_type & 0x04 == 0 { VarInt::decode(buf)? } else { VarInt::from_usize(0) };
        let publisher_priority = if datagram_type & 0x08 != 0 {
            None
        } else {
            if buf.remaining() < 1 {
                return Err(CodecError::UnexpectedEnd);
            }
            Some(buf.get_u8())
        };
        let extension_headers = if datagram_type & 0x01 != 0 {
            let ext_len = VarInt::decode(buf)?.into_inner() as usize;
            crate::types::read_bytes(buf, ext_len)?
        } else {
            Vec::new()
        };
        let object_status =
            if datagram_type & 0x20 != 0 { Some(VarInt::decode(buf)?) } else { None };
        Ok(Self {
            datagram_type,
            track_alias,
            group_id,
            object_id,
            publisher_priority,
            extension_headers,
            object_status,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchHeader {
    pub request_id: VarInt,
}

impl FetchHeader {
    pub fn encode(&self, buf: &mut impl BufMut) {
        VarInt::from_usize(0x05).encode(buf);
        self.request_id.encode(buf);
    }

    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let stream_type = VarInt::decode(buf)?.into_inner();
        if stream_type != 0x05 {
            return Err(CodecError::InvalidField);
        }
        let request_id = VarInt::decode(buf)?;
        Ok(Self { request_id })
    }
}

//! Draft-15 data stream header encoding and decoding.
//!
//! Draft-15 data streams differ significantly from draft-14:
//! - Subgroup stream types encode flags in the type byte (0x10-0x17, 0x30-0x37)
//! - Priority is optional (absent when type & 0x20)
//! - Subgroup ID is optional (present when type & 0x04)
//! - Extensions flag (type & 0x01) affects per-object parsing
//! - Datagram types: 0x00 (normal), 0x02 (end-of-group), 0x04 (no object_id),
//!   0x20 (status)
//! - Fetch objects use serialization_flags for delta encoding
//! - Object IDs in subgroups use delta encoding (first=absolute, subsequent=delta+1)

use crate::error::CodecError;
use crate::varint::VarInt;
use bytes::{Buf, BufMut};

// ── Subgroup streams ───────────────────────────────────────

/// Subgroup stream header for draft-15.
///
/// The `header_type` byte encodes several flags:
/// - `& 0x01`: extensions present on objects
/// - `& 0x02`: end-of-group marker
/// - `& 0x04`: explicit subgroup_id present
/// - `& 0x20`: no publisher_priority (0x30+ types)
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

    pub fn has_end_of_group(&self) -> bool {
        self.header_type & 0x02 != 0
    }

    pub fn has_explicit_subgroup_id(&self) -> bool {
        self.header_type & 0x04 != 0
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
        let base = header_type & 0xD0; // mask out lower flag bits
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

// ── Subgroup objects (stateful) ─────────────────────────────

/// One object within a draft-15 subgroup stream with its Object ID
/// already resolved from the delta encoding.
///
/// Draft-15 object framing requires context from the enclosing
/// [`SubgroupHeader`] (specifically, whether extension headers are
/// present and the running delta state), so decoding/encoding uses a
/// stateful [`SubgroupObjectReader`] rather than a standalone method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubgroupObject {
    /// Resolved absolute Object ID.
    pub object_id: VarInt,
    /// Raw extension-header bytes. Empty when the stream header does
    /// not set the extensions-present bit. When present, holds the
    /// entire on-wire extension block starting with the `ext_count`
    /// varint followed by each extension's `key`, `vlen`, and value.
    pub extension_headers: Vec<u8>,
    /// Payload length as encoded on the wire. Zero when the object is
    /// a status-only object.
    pub payload_length: VarInt,
    /// Object status; `Some` when `payload_length == 0`.
    pub object_status: Option<VarInt>,
    /// Payload bytes; empty when `object_status` is `Some`.
    pub payload: Vec<u8>,
}

/// Stateful reader/writer for draft-15 subgroup objects.
///
/// Carries the running delta state for object IDs and remembers whether
/// extension headers are present on this stream.
#[derive(Debug, Clone)]
pub struct SubgroupObjectReader {
    extensions_present: bool,
    prev_object_id: Option<u64>,
}

impl SubgroupObjectReader {
    /// Build a reader seeded from the enclosing subgroup header.
    pub fn new(header: &SubgroupHeader) -> Self {
        Self { extensions_present: header.has_extensions(), prev_object_id: None }
    }

    /// Decode the next object from `buf`.
    pub fn read_object(&mut self, buf: &mut impl Buf) -> Result<SubgroupObject, CodecError> {
        let delta = VarInt::decode(buf)?.into_inner();
        // Draft-15 subgroup object delta encoding:
        // - First object: `delta` is the absolute object_id.
        // - Subsequent objects (no extensions): `delta` is the gap to the
        //   next object; the resolved id is `prev + delta + 1`.
        // - Subsequent objects (extensions flag set): `delta` is the
        //   already-adjusted offset; the resolved id is `prev + delta`.
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

        let extension_headers = if self.extensions_present {
            // Draft-15+: extensions are a byte-length-prefixed opaque
            // blob. We copy the blob verbatim; callers that want
            // structured extensions can parse the returned bytes.
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

    /// Serialize an object, producing the correct delta encoding.
    pub fn write_object(
        &mut self,
        object: &SubgroupObject,
        buf: &mut impl BufMut,
    ) -> Result<(), CodecError> {
        let oid = object.object_id.into_inner();
        let delta = match self.prev_object_id {
            None => oid,
            Some(prev) => oid.checked_sub(prev).ok_or(CodecError::InvalidField)?,
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
                // Default to status 0 when none supplied.
                VarInt::from_u64(0).unwrap().encode(buf);
            }
        } else {
            buf.put_slice(&object.payload);
        }
        self.prev_object_id = Some(oid);
        Ok(())
    }
}

// ── Datagram headers ───────────────────────────────────────

/// Datagram header for draft-15.
///
/// The `datagram_type` byte encodes flags:
/// - `0x02`: end-of-group
/// - `0x04`: no object_id (object_id = 0 implied)
/// - `0x20`: status datagram (carries object_status instead of payload)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatagramHeader {
    /// Raw datagram-type byte encoding flags + kind.
    pub datagram_type: u8,
    /// Track alias identifying the track.
    pub track_alias: VarInt,
    /// Group ID for the contained object.
    pub group_id: VarInt,
    /// Object ID (zero when the `no-object-id` flag is set).
    pub object_id: VarInt,
    /// Publisher priority.
    pub publisher_priority: u8,
    /// Opaque extension-headers blob (only when the `0x01` flag is set).
    pub extension_headers: Vec<u8>,
    /// Object status (only when the `0x20` status flag is set).
    pub object_status: Option<VarInt>,
}

impl DatagramHeader {
    /// Whether the datagram carries an explicit object_id.
    pub fn has_object_id(&self) -> bool {
        self.datagram_type & 0x04 == 0
    }

    /// Whether this datagram marks the end of its group.
    pub fn is_end_of_group(&self) -> bool {
        self.datagram_type & 0x02 != 0
    }

    /// Whether this datagram carries an object_status instead of payload.
    pub fn is_status(&self) -> bool {
        self.datagram_type & 0x20 != 0
    }

    /// Whether this datagram carries extension headers.
    pub fn has_extensions(&self) -> bool {
        self.datagram_type & 0x01 != 0
    }

    /// Encode the datagram header to `buf`.
    pub fn encode(&self, buf: &mut impl BufMut) {
        VarInt::from_usize(self.datagram_type as usize).encode(buf);
        self.track_alias.encode(buf);
        self.group_id.encode(buf);
        if self.has_object_id() {
            self.object_id.encode(buf);
        }
        buf.put_u8(self.publisher_priority);
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

    /// Decode a datagram header from `buf`.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let datagram_type = VarInt::decode(buf)?.into_inner() as u8;
        let track_alias = VarInt::decode(buf)?;
        let group_id = VarInt::decode(buf)?;
        let object_id =
            if datagram_type & 0x04 == 0 { VarInt::decode(buf)? } else { VarInt::from_usize(0) };
        if buf.remaining() < 1 {
            return Err(CodecError::UnexpectedEnd);
        }
        let publisher_priority = buf.get_u8();
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

// ── Fetch stream headers ───────────────────────────────────

/// Fetch stream header for draft-15.
///
/// Stream type is 0x05. Only contains a request_id.
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

//! Draft-14 data streams (§10): subgroup streams, fetch streams, datagrams.
//!
//! This module follows the draft-14 spec exactly. Key shapes:
//!
//! * **Subgroup stream** (§10.4.2): starts with a Type byte `0x10..=0x1D`
//!   whose bit-flags determine whether a Subgroup ID field is present,
//!   whether the subgroup ID is zero or the first Object ID, whether
//!   extension headers are present, and whether the stream ends at a
//!   group boundary. Object IDs are delta-encoded relative to the
//!   previous Object ID in the same stream.
//!
//! * **Fetch stream** (§10.4.4): Type `0x05`, Request ID, then a sequence
//!   of self-describing objects until FIN.
//!
//! * **Datagram** (§10.3.1): Type byte `0x00..=0x07` or `0x20..=0x21`
//!   with bit-flags for End of Group, Extensions Present, Object ID
//!   Present, and Status vs Payload.

use bytes::{Buf, BufMut};

use super::types::ObjectStatus;
use crate::error::CodecError;
use crate::varint::VarInt;

// ============================================================
// Subgroup stream (Type 0x10..=0x1D)
// ============================================================

/// Subgroup stream type byte (§10.4.2, Table 7).
///
/// The 12 defined types encode four independent boolean fields in the
/// low nibble:
///
/// * bit 0 (`0x01`) — Extensions Present
/// * bit 1 (`0x02`) — Subgroup ID derives from first Object ID
///   (only meaningful when bit 2 is clear)
/// * bit 2 (`0x04`) — Subgroup ID Field Present (explicit Subgroup ID varint)
/// * bit 3 (`0x08`) — Contains End of Group
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubgroupStreamType(u8);

impl SubgroupStreamType {
    /// The raw wire byte.
    pub fn as_u8(self) -> u8 {
        self.0
    }

    /// Create a [`SubgroupStreamType`] from its raw byte, validating
    /// that it is one of the 12 defined values in Table 7.
    pub fn from_u8(v: u8) -> Option<Self> {
        if (0x10..=0x15).contains(&v) || (0x18..=0x1D).contains(&v) {
            Some(SubgroupStreamType(v))
        } else {
            None
        }
    }

    /// Build a subgroup stream type from its component flags.
    ///
    /// `subgroup_id_is_first_object` and `subgroup_id_field_present` are
    /// mutually exclusive — if both are set, the resulting type has the
    /// "Subgroup ID Field Present" bit set (bit 2 wins).
    pub fn from_flags(
        subgroup_id_field_present: bool,
        subgroup_id_is_first_object: bool,
        extensions_present: bool,
        end_of_group: bool,
    ) -> Self {
        let mut v: u8 = 0x10;
        if extensions_present {
            v |= 0x01;
        }
        if subgroup_id_field_present {
            v |= 0x04;
        } else if subgroup_id_is_first_object {
            v |= 0x02;
        }
        if end_of_group {
            v |= 0x08;
        }
        SubgroupStreamType(v)
    }

    /// True if the header carries an explicit Subgroup ID varint.
    pub fn has_subgroup_id_field(self) -> bool {
        self.0 & 0x04 != 0
    }

    /// True if the subgroup ID is defined to equal the first Object ID
    /// in the stream (applies only when [`Self::has_subgroup_id_field`]
    /// is false).
    pub fn subgroup_id_is_first_object(self) -> bool {
        !self.has_subgroup_id_field() && (self.0 & 0x02 != 0)
    }

    /// True if every object in the stream carries extension headers.
    pub fn extensions_present(self) -> bool {
        self.0 & 0x01 != 0
    }

    /// True if the last object on the stream (prior to FIN) is the end
    /// of its group.
    pub fn contains_end_of_group(self) -> bool {
        self.0 & 0x08 != 0
    }
}

/// Subgroup stream header (§10.4.2, Figure 32).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubgroupHeader {
    /// Type byte identifying the flag set for this stream.
    pub stream_type: SubgroupStreamType,
    /// Track alias (Section 10.1).
    pub track_alias: VarInt,
    /// Group ID.
    pub group_id: VarInt,
    /// Explicit Subgroup ID — present only when the stream type sets
    /// `Subgroup ID Field Present = Yes`. For types where the subgroup
    /// ID is implicit (0 or the first Object ID), the effective
    /// subgroup ID is resolved on the receive side by the reader.
    pub subgroup_id: Option<VarInt>,
    /// Publisher priority (Section 7).
    pub publisher_priority: u8,
}

impl SubgroupHeader {
    /// Encode the header including the leading stream type byte.
    pub fn encode(&self, buf: &mut impl BufMut) {
        VarInt::from_u64(self.stream_type.as_u8() as u64).unwrap().encode(buf);
        self.track_alias.encode(buf);
        self.group_id.encode(buf);
        if self.stream_type.has_subgroup_id_field() {
            let sg = self.subgroup_id.unwrap_or_else(|| VarInt::from_u64(0).unwrap());
            sg.encode(buf);
        }
        buf.put_u8(self.publisher_priority);
    }

    /// Decode a subgroup header (leading type byte + remaining fields).
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let type_val = VarInt::decode(buf)?.into_inner();
        if type_val > 0xFF {
            return Err(CodecError::InvalidField);
        }
        let stream_type =
            SubgroupStreamType::from_u8(type_val as u8).ok_or(CodecError::InvalidField)?;
        let track_alias = VarInt::decode(buf)?;
        let group_id = VarInt::decode(buf)?;
        let subgroup_id =
            if stream_type.has_subgroup_id_field() { Some(VarInt::decode(buf)?) } else { None };
        if buf.remaining() < 1 {
            return Err(CodecError::UnexpectedEnd);
        }
        let publisher_priority = buf.get_u8();
        Ok(SubgroupHeader { stream_type, track_alias, group_id, subgroup_id, publisher_priority })
    }
}

/// One object within a subgroup stream, with the Object ID already
/// resolved from its delta encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubgroupObject {
    /// Resolved Object ID (delta decoded to an absolute value).
    pub object_id: VarInt,
    /// Raw extension-header bytes. Empty when the stream type has
    /// `Extensions Present = No`, or when present but the length was 0.
    /// The content is a sequence of Key-Value-Pairs (§10.2.1.2) but is
    /// left opaque here — relays and subscribers that do not understand
    /// specific extensions must forward or ignore the bytes unchanged.
    pub extension_headers: Vec<u8>,
    /// Object Status when `payload.is_empty()` and the object was sent
    /// with an explicit status code; `None` when a non-empty payload
    /// follows (status is implicitly [`ObjectStatus::Normal`]).
    pub status: Option<ObjectStatus>,
    /// Object payload. Empty when `status` is `Some(..)`.
    pub payload: Vec<u8>,
}

/// Stateful reader for the object fields on a subgroup stream.
///
/// Object IDs on a subgroup stream are delta-encoded against the
/// previous Object ID, and whether extension headers are present is
/// fixed by the enclosing [`SubgroupHeader`]'s stream type. This reader
/// carries that context across successive `read_object` calls.
#[derive(Debug, Clone)]
pub struct SubgroupObjectReader {
    extensions_present: bool,
    prev_object_id: Option<u64>,
}

impl SubgroupObjectReader {
    /// Create a reader from a parsed subgroup header.
    pub fn new(header: &SubgroupHeader) -> Self {
        Self { extensions_present: header.stream_type.extensions_present(), prev_object_id: None }
    }

    /// Decode the next object from `buf`. Caller is responsible for
    /// ensuring the buffer contains a complete object (draft-14 objects
    /// are length-delimited by the payload-length field, so the buffer
    /// boundary is known once the header portion has been consumed).
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
            let ext_len = VarInt::decode(buf)?.into_inner() as usize;
            crate::types::read_bytes(buf, ext_len)?
        } else {
            Vec::new()
        };

        let payload_length = VarInt::decode(buf)?.into_inner() as usize;
        let (status, payload) = if payload_length == 0 {
            let status_val = VarInt::decode(buf)?.into_inner();
            let status = ObjectStatus::from_u64(status_val).ok_or(CodecError::InvalidField)?;
            (Some(status), Vec::new())
        } else {
            let payload = crate::types::read_bytes(buf, payload_length)?;
            (None, payload)
        };

        Ok(SubgroupObject { object_id, extension_headers, status, payload })
    }

    /// Serialize a subgroup object using the reader's delta state. Intended
    /// for senders that want to build a stream incrementally — tracks
    /// `prev_object_id` so successive calls produce correct deltas.
    ///
    /// Returns an error if `object.object_id <= prev_object_id`, which
    /// would produce an invalid delta.
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
            VarInt::from_u64(object.extension_headers.len() as u64)
                .map_err(|_| CodecError::InvalidField)?
                .encode(buf);
            buf.put_slice(&object.extension_headers);
        }
        if let Some(status) = object.status {
            VarInt::from_u64(0).unwrap().encode(buf);
            VarInt::from_u64(status.as_u64()).unwrap().encode(buf);
        } else {
            VarInt::from_u64(object.payload.len() as u64)
                .map_err(|_| CodecError::InvalidField)?
                .encode(buf);
            buf.put_slice(&object.payload);
        }
        self.prev_object_id = Some(oid);
        Ok(())
    }
}

// ============================================================
// Fetch stream (Type 0x05)
// ============================================================

/// Draft-14 fetch stream type byte.
pub const FETCH_STREAM_TYPE: u8 = 0x05;

/// Fetch stream header (§10.4.4, Figure 34).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchHeader {
    /// Request ID from the originating FETCH control message.
    pub request_id: VarInt,
}

impl FetchHeader {
    /// Encode the header including the leading type byte.
    pub fn encode(&self, buf: &mut impl BufMut) {
        VarInt::from_u64(FETCH_STREAM_TYPE as u64).unwrap().encode(buf);
        self.request_id.encode(buf);
    }

    /// Decode the header. Errors if the type byte is not `0x05`.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let type_val = VarInt::decode(buf)?.into_inner();
        if type_val != FETCH_STREAM_TYPE as u64 {
            return Err(CodecError::InvalidField);
        }
        let request_id = VarInt::decode(buf)?;
        Ok(FetchHeader { request_id })
    }
}

/// One object carried on a fetch stream (§10.4.4, Figure 35).
///
/// Every object on a fetch stream is self-describing — unlike subgroup
/// streams, there is no delta encoding and extension headers are always
/// length-prefixed (the length is zero when absent).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchObject {
    /// Group ID.
    pub group_id: VarInt,
    /// Subgroup ID. For objects whose Forwarding Preference is Datagram,
    /// this is set to the Object ID.
    pub subgroup_id: VarInt,
    /// Object ID.
    pub object_id: VarInt,
    /// Publisher priority.
    pub publisher_priority: u8,
    /// Raw extension-header bytes (opaque sequence of Key-Value-Pairs).
    pub extension_headers: Vec<u8>,
    /// Object status when `payload.is_empty()`, otherwise `None`.
    pub status: Option<ObjectStatus>,
    /// Object payload.
    pub payload: Vec<u8>,
}

impl FetchObject {
    /// Encode one fetch object.
    pub fn encode(&self, buf: &mut impl BufMut) {
        self.group_id.encode(buf);
        self.subgroup_id.encode(buf);
        self.object_id.encode(buf);
        buf.put_u8(self.publisher_priority);
        VarInt::from_u64(self.extension_headers.len() as u64).unwrap().encode(buf);
        buf.put_slice(&self.extension_headers);
        if let Some(status) = self.status {
            VarInt::from_u64(0).unwrap().encode(buf);
            VarInt::from_u64(status.as_u64()).unwrap().encode(buf);
        } else {
            VarInt::from_u64(self.payload.len() as u64).unwrap().encode(buf);
            buf.put_slice(&self.payload);
        }
    }

    /// Decode one fetch object.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let group_id = VarInt::decode(buf)?;
        let subgroup_id = VarInt::decode(buf)?;
        let object_id = VarInt::decode(buf)?;
        if buf.remaining() < 1 {
            return Err(CodecError::UnexpectedEnd);
        }
        let publisher_priority = buf.get_u8();
        let ext_len = VarInt::decode(buf)?.into_inner() as usize;
        let extension_headers = crate::types::read_bytes(buf, ext_len)?;
        let payload_length = VarInt::decode(buf)?.into_inner() as usize;
        let (status, payload) = if payload_length == 0 {
            let status_val = VarInt::decode(buf)?.into_inner();
            let status = ObjectStatus::from_u64(status_val).ok_or(CodecError::InvalidField)?;
            (Some(status), Vec::new())
        } else {
            (None, crate::types::read_bytes(buf, payload_length)?)
        };
        Ok(FetchObject {
            group_id,
            subgroup_id,
            object_id,
            publisher_priority,
            extension_headers,
            status,
            payload,
        })
    }
}

// ============================================================
// Datagram (Type 0x00..=0x07, 0x20..=0x21)
// ============================================================

/// Datagram type byte (§10.3.1, Table 6).
///
/// Bit layout (low nibble):
///
/// * bit 0 (`0x01`) — Extensions Present
/// * bit 1 (`0x02`) — End of Group
/// * bit 2 (`0x04`) — Object ID **absent** (when set, Object ID = 0)
///
/// Status variants use the high nibble (`0x20..=0x21`). Only types
/// `0x00..=0x07`, `0x20`, `0x21` are defined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatagramType(u8);

impl DatagramType {
    /// Raw wire byte.
    pub fn as_u8(self) -> u8 {
        self.0
    }

    /// Validate and wrap a raw wire byte.
    pub fn from_u8(v: u8) -> Option<Self> {
        if (0x00..=0x07).contains(&v) || v == 0x20 || v == 0x21 {
            Some(DatagramType(v))
        } else {
            None
        }
    }

    /// Build a payload-bearing datagram type (`0x00..=0x07`).
    pub fn payload(object_id_present: bool, extensions_present: bool, end_of_group: bool) -> Self {
        let mut v: u8 = 0x00;
        if extensions_present {
            v |= 0x01;
        }
        if end_of_group {
            v |= 0x02;
        }
        if !object_id_present {
            v |= 0x04;
        }
        DatagramType(v)
    }

    /// Build a status-only datagram type (`0x20` or `0x21`).
    pub fn status(extensions_present: bool) -> Self {
        if extensions_present {
            DatagramType(0x21)
        } else {
            DatagramType(0x20)
        }
    }

    /// True when the datagram carries an Object Status instead of a
    /// payload (types `0x20` / `0x21`).
    pub fn is_status(self) -> bool {
        self.0 >= 0x20
    }

    /// True when the datagram carries an explicit Object ID field.
    pub fn object_id_present(self) -> bool {
        // Bit 2 is only meaningful in the 0x00..=0x07 range; status
        // variants (0x20/0x21) always carry an Object ID per Table 6.
        if self.is_status() {
            true
        } else {
            self.0 & 0x04 == 0
        }
    }

    /// True if the last object of the group is conveyed.
    pub fn end_of_group(self) -> bool {
        !self.is_status() && (self.0 & 0x02 != 0)
    }

    /// True if extension headers are present in this datagram.
    pub fn extensions_present(self) -> bool {
        self.0 & 0x01 != 0
    }
}

/// Datagram carrying a single object (§10.3.1, Figure 31).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatagramObject {
    /// Datagram type byte.
    pub datagram_type: DatagramType,
    /// Track alias.
    pub track_alias: VarInt,
    /// Group ID.
    pub group_id: VarInt,
    /// Object ID. Defaults to 0 when
    /// [`DatagramType::object_id_present`] is false.
    pub object_id: VarInt,
    /// Publisher priority.
    pub publisher_priority: u8,
    /// Raw extension-header bytes (empty unless
    /// [`DatagramType::extensions_present`] is true).
    pub extension_headers: Vec<u8>,
    /// Object status (only present for status-type datagrams).
    pub status: Option<ObjectStatus>,
    /// Object payload (empty for status-type datagrams).
    pub payload: Vec<u8>,
}

impl DatagramObject {
    /// Encode the datagram in full.
    pub fn encode(&self, buf: &mut impl BufMut) {
        VarInt::from_u64(self.datagram_type.as_u8() as u64).unwrap().encode(buf);
        self.track_alias.encode(buf);
        self.group_id.encode(buf);
        if self.datagram_type.object_id_present() {
            self.object_id.encode(buf);
        }
        buf.put_u8(self.publisher_priority);
        if self.datagram_type.extensions_present() {
            VarInt::from_u64(self.extension_headers.len() as u64).unwrap().encode(buf);
            buf.put_slice(&self.extension_headers);
        }
        if self.datagram_type.is_status() {
            let status = self.status.unwrap_or(ObjectStatus::Normal);
            VarInt::from_u64(status.as_u64()).unwrap().encode(buf);
        } else {
            buf.put_slice(&self.payload);
        }
    }

    /// Decode a datagram. The buffer must contain the full datagram —
    /// payload-bearing types extend to the end of the QUIC datagram,
    /// which the caller is responsible for delimiting.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let type_val = VarInt::decode(buf)?.into_inner();
        if type_val > 0xFF {
            return Err(CodecError::InvalidField);
        }
        let datagram_type =
            DatagramType::from_u8(type_val as u8).ok_or(CodecError::InvalidField)?;
        let track_alias = VarInt::decode(buf)?;
        let group_id = VarInt::decode(buf)?;
        let object_id = if datagram_type.object_id_present() {
            VarInt::decode(buf)?
        } else {
            VarInt::from_u64(0).unwrap()
        };
        if buf.remaining() < 1 {
            return Err(CodecError::UnexpectedEnd);
        }
        let publisher_priority = buf.get_u8();
        let extension_headers = if datagram_type.extensions_present() {
            let ext_len = VarInt::decode(buf)?.into_inner() as usize;
            crate::types::read_bytes(buf, ext_len)?
        } else {
            Vec::new()
        };
        let (status, payload) = if datagram_type.is_status() {
            let status_val = VarInt::decode(buf)?.into_inner();
            let status = ObjectStatus::from_u64(status_val).ok_or(CodecError::InvalidField)?;
            (Some(status), Vec::new())
        } else {
            let remaining = buf.remaining();
            (None, crate::types::read_bytes(buf, remaining)?)
        };
        Ok(DatagramObject {
            datagram_type,
            track_alias,
            group_id,
            object_id,
            publisher_priority,
            extension_headers,
            status,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vi(v: u64) -> VarInt {
        VarInt::from_u64(v).unwrap()
    }

    // ── SubgroupStreamType flag helpers ─────────────────────

    #[test]
    fn subgroup_type_0x10_all_off() {
        let t = SubgroupStreamType::from_u8(0x10).unwrap();
        assert!(!t.has_subgroup_id_field());
        assert!(!t.subgroup_id_is_first_object());
        assert!(!t.extensions_present());
        assert!(!t.contains_end_of_group());
    }

    #[test]
    fn subgroup_type_0x15_explicit_with_ext() {
        let t = SubgroupStreamType::from_u8(0x15).unwrap();
        assert!(t.has_subgroup_id_field());
        assert!(!t.subgroup_id_is_first_object());
        assert!(t.extensions_present());
        assert!(!t.contains_end_of_group());
    }

    #[test]
    fn subgroup_type_0x1d_all_on() {
        let t = SubgroupStreamType::from_u8(0x1D).unwrap();
        assert!(t.has_subgroup_id_field());
        assert!(t.extensions_present());
        assert!(t.contains_end_of_group());
    }

    #[test]
    fn subgroup_type_0x12_first_object() {
        let t = SubgroupStreamType::from_u8(0x12).unwrap();
        assert!(!t.has_subgroup_id_field());
        assert!(t.subgroup_id_is_first_object());
        assert!(!t.extensions_present());
    }

    #[test]
    fn subgroup_type_rejects_undefined() {
        for bad in [0x00u8, 0x0F, 0x16, 0x17, 0x1E, 0x1F, 0x20] {
            assert!(SubgroupStreamType::from_u8(bad).is_none(), "0x{bad:02x} should be rejected");
        }
    }

    #[test]
    fn subgroup_type_from_flags_roundtrip() {
        for &f_sg in &[false, true] {
            for &f_first in &[false, true] {
                for &f_ext in &[false, true] {
                    for &f_eog in &[false, true] {
                        let t = SubgroupStreamType::from_flags(f_sg, f_first, f_ext, f_eog);
                        assert_eq!(t.has_subgroup_id_field(), f_sg);
                        // subgroup_id_is_first_object only meaningful when
                        // explicit field is absent
                        if !f_sg {
                            assert_eq!(t.subgroup_id_is_first_object(), f_first);
                        }
                        assert_eq!(t.extensions_present(), f_ext);
                        assert_eq!(t.contains_end_of_group(), f_eog);
                    }
                }
            }
        }
    }

    // ── SubgroupHeader round-trip ───────────────────────────

    #[test]
    fn subgroup_header_roundtrip_0x10() {
        let h = SubgroupHeader {
            stream_type: SubgroupStreamType::from_u8(0x10).unwrap(),
            track_alias: vi(1),
            group_id: vi(0),
            subgroup_id: None,
            publisher_priority: 128,
        };
        let mut buf = Vec::new();
        h.encode(&mut buf);
        assert_eq!(buf[0], 0x10);
        let decoded = SubgroupHeader::decode(&mut &buf[..]).unwrap();
        assert_eq!(decoded, h);
    }

    #[test]
    fn subgroup_header_roundtrip_explicit_subgroup() {
        let h = SubgroupHeader {
            stream_type: SubgroupStreamType::from_u8(0x14).unwrap(),
            track_alias: vi(5),
            group_id: vi(10),
            subgroup_id: Some(vi(2)),
            publisher_priority: 64,
        };
        let mut buf = Vec::new();
        h.encode(&mut buf);
        let decoded = SubgroupHeader::decode(&mut &buf[..]).unwrap();
        assert_eq!(decoded, h);
    }

    #[test]
    fn subgroup_header_decode_rejects_bad_type() {
        // type byte 0x16 is undefined
        let buf = [0x16u8, 0x01, 0x00, 0x80];
        let err = SubgroupHeader::decode(&mut &buf[..]).unwrap_err();
        assert!(matches!(err, CodecError::InvalidField));
    }

    // ── Subgroup object reader (delta + extensions) ─────────

    #[test]
    fn subgroup_reader_delta_sequential_ids() {
        // Type 0x10: no subgroup field, no extensions, no eog
        let header = SubgroupHeader {
            stream_type: SubgroupStreamType::from_u8(0x10).unwrap(),
            track_alias: vi(1),
            group_id: vi(0),
            subgroup_id: None,
            publisher_priority: 0,
        };

        let mut write = SubgroupObjectReader::new(&header);
        let mut buf = Vec::new();
        for i in 0..3u64 {
            let obj = SubgroupObject {
                object_id: vi(i),
                extension_headers: vec![],
                status: None,
                payload: vec![0xAA + i as u8; 4],
            };
            write.write_object(&obj, &mut buf).unwrap();
        }

        let mut read = SubgroupObjectReader::new(&header);
        let mut cursor = &buf[..];
        let o0 = read.read_object(&mut cursor).unwrap();
        assert_eq!(o0.object_id.into_inner(), 0);
        assert_eq!(o0.payload, vec![0xAA; 4]);
        let o1 = read.read_object(&mut cursor).unwrap();
        assert_eq!(o1.object_id.into_inner(), 1);
        let o2 = read.read_object(&mut cursor).unwrap();
        assert_eq!(o2.object_id.into_inner(), 2);
    }

    #[test]
    fn subgroup_reader_delta_sparse_ids() {
        // Object IDs 5, 10, 11 — deltas are 5, 4, 0
        let header = SubgroupHeader {
            stream_type: SubgroupStreamType::from_u8(0x10).unwrap(),
            track_alias: vi(1),
            group_id: vi(0),
            subgroup_id: None,
            publisher_priority: 0,
        };
        let mut write = SubgroupObjectReader::new(&header);
        let mut buf = Vec::new();
        for &id in &[5u64, 10, 11] {
            write
                .write_object(
                    &SubgroupObject {
                        object_id: vi(id),
                        extension_headers: vec![],
                        status: None,
                        payload: vec![1, 2, 3],
                    },
                    &mut buf,
                )
                .unwrap();
        }
        let mut read = SubgroupObjectReader::new(&header);
        let mut cursor = &buf[..];
        assert_eq!(read.read_object(&mut cursor).unwrap().object_id.into_inner(), 5);
        assert_eq!(read.read_object(&mut cursor).unwrap().object_id.into_inner(), 10);
        assert_eq!(read.read_object(&mut cursor).unwrap().object_id.into_inner(), 11);
    }

    #[test]
    fn subgroup_reader_with_extensions() {
        // Type 0x11: extensions present
        let header = SubgroupHeader {
            stream_type: SubgroupStreamType::from_u8(0x11).unwrap(),
            track_alias: vi(1),
            group_id: vi(0),
            subgroup_id: None,
            publisher_priority: 0,
        };
        let mut write = SubgroupObjectReader::new(&header);
        let mut buf = Vec::new();
        write
            .write_object(
                &SubgroupObject {
                    object_id: vi(0),
                    extension_headers: vec![0x01, 0x02, 0x03],
                    status: None,
                    payload: vec![0xFF],
                },
                &mut buf,
            )
            .unwrap();
        let mut read = SubgroupObjectReader::new(&header);
        let o = read.read_object(&mut &buf[..]).unwrap();
        assert_eq!(o.extension_headers, vec![0x01, 0x02, 0x03]);
        assert_eq!(o.payload, vec![0xFF]);
    }

    #[test]
    fn subgroup_reader_status_object() {
        let header = SubgroupHeader {
            stream_type: SubgroupStreamType::from_u8(0x10).unwrap(),
            track_alias: vi(1),
            group_id: vi(0),
            subgroup_id: None,
            publisher_priority: 0,
        };
        let mut write = SubgroupObjectReader::new(&header);
        let mut buf = Vec::new();
        write
            .write_object(
                &SubgroupObject {
                    object_id: vi(7),
                    extension_headers: vec![],
                    status: Some(ObjectStatus::EndOfGroup),
                    payload: vec![],
                },
                &mut buf,
            )
            .unwrap();
        let mut read = SubgroupObjectReader::new(&header);
        let o = read.read_object(&mut &buf[..]).unwrap();
        assert_eq!(o.object_id.into_inner(), 7);
        assert_eq!(o.status, Some(ObjectStatus::EndOfGroup));
        assert!(o.payload.is_empty());
    }

    // ── FetchHeader + FetchObject ───────────────────────────

    #[test]
    fn fetch_header_roundtrip() {
        let h = FetchHeader { request_id: vi(99) };
        let mut buf = Vec::new();
        h.encode(&mut buf);
        assert_eq!(buf[0], 0x05);
        assert_eq!(FetchHeader::decode(&mut &buf[..]).unwrap(), h);
    }

    #[test]
    fn fetch_header_rejects_wrong_type() {
        let buf = [0x10u8, 0x05];
        assert!(FetchHeader::decode(&mut &buf[..]).is_err());
    }

    #[test]
    fn fetch_object_roundtrip_with_payload() {
        let obj = FetchObject {
            group_id: vi(3),
            subgroup_id: vi(1),
            object_id: vi(7),
            publisher_priority: 200,
            extension_headers: vec![0xAA, 0xBB],
            status: None,
            payload: vec![1, 2, 3, 4],
        };
        let mut buf = Vec::new();
        obj.encode(&mut buf);
        assert_eq!(FetchObject::decode(&mut &buf[..]).unwrap(), obj);
    }

    #[test]
    fn fetch_object_roundtrip_status() {
        let obj = FetchObject {
            group_id: vi(3),
            subgroup_id: vi(1),
            object_id: vi(8),
            publisher_priority: 200,
            extension_headers: vec![],
            status: Some(ObjectStatus::ObjectDoesNotExist),
            payload: vec![],
        };
        let mut buf = Vec::new();
        obj.encode(&mut buf);
        assert_eq!(FetchObject::decode(&mut &buf[..]).unwrap(), obj);
    }

    // ── DatagramType ────────────────────────────────────────

    #[test]
    fn datagram_type_variants() {
        let t0 = DatagramType::from_u8(0x00).unwrap();
        assert!(t0.object_id_present());
        assert!(!t0.extensions_present());
        assert!(!t0.end_of_group());
        assert!(!t0.is_status());

        let t7 = DatagramType::from_u8(0x07).unwrap();
        assert!(!t7.object_id_present()); // bit 2 set
        assert!(t7.extensions_present());
        assert!(t7.end_of_group());
        assert!(!t7.is_status());

        let t20 = DatagramType::from_u8(0x20).unwrap();
        assert!(t20.is_status());
        assert!(!t20.extensions_present());
        // Status datagrams always carry Object ID
        assert!(t20.object_id_present());

        let t21 = DatagramType::from_u8(0x21).unwrap();
        assert!(t21.is_status());
        assert!(t21.extensions_present());
    }

    #[test]
    fn datagram_type_rejects_undefined() {
        for bad in [0x08u8, 0x10, 0x1F, 0x22, 0x80] {
            assert!(DatagramType::from_u8(bad).is_none(), "0x{bad:02x}");
        }
    }

    // ── DatagramObject round-trip ───────────────────────────

    #[test]
    fn datagram_object_0x00_roundtrip() {
        let d = DatagramObject {
            datagram_type: DatagramType::from_u8(0x00).unwrap(),
            track_alias: vi(1),
            group_id: vi(2),
            object_id: vi(3),
            publisher_priority: 100,
            extension_headers: vec![],
            status: None,
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let mut buf = Vec::new();
        d.encode(&mut buf);
        assert_eq!(DatagramObject::decode(&mut &buf[..]).unwrap(), d);
    }

    #[test]
    fn datagram_object_0x04_no_object_id() {
        // 0x04: no object id field, implicit 0
        let d = DatagramObject {
            datagram_type: DatagramType::from_u8(0x04).unwrap(),
            track_alias: vi(1),
            group_id: vi(2),
            object_id: vi(0),
            publisher_priority: 100,
            extension_headers: vec![],
            status: None,
            payload: vec![0xAA],
        };
        let mut buf = Vec::new();
        d.encode(&mut buf);
        let decoded = DatagramObject::decode(&mut &buf[..]).unwrap();
        assert_eq!(decoded, d);
    }

    #[test]
    fn datagram_object_0x21_status_with_extensions() {
        let d = DatagramObject {
            datagram_type: DatagramType::from_u8(0x21).unwrap(),
            track_alias: vi(9),
            group_id: vi(4),
            object_id: vi(11),
            publisher_priority: 50,
            extension_headers: vec![0xCA, 0xFE],
            status: Some(ObjectStatus::EndOfTrack),
            payload: vec![],
        };
        let mut buf = Vec::new();
        d.encode(&mut buf);
        assert_eq!(DatagramObject::decode(&mut &buf[..]).unwrap(), d);
    }
}

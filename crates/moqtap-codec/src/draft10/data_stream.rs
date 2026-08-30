//! Draft-10 data stream header encoding and decoding.
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

/// Every type ID this draft's data plane assigns, from two separate tables.
///
/// The draft keeps unidirectional stream types and datagram types in different
/// tables and different number spaces: SUBGROUP_HEADER and FETCH_HEADER name
/// unidirectional streams, OBJECT_DATAGRAM and OBJECT_DATAGRAM_STATUS name
/// datagrams. The numbers happen not to collide on this draft, which is what
/// lets one enum hold all four.
///
/// [`StreamType::from_id`] therefore answers across both tables and cannot say
/// which one a value came from, which makes it the wrong question to ask about
/// a stream or a datagram in hand. `stream_type_error` and
/// `datagram_type_error` ask it per table, and the difference is not
/// cosmetic: a value assigned in the other table is unknown in this one, and
/// this draft answers an unknown type by ending the session.
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

/// Which failure a leading unidirectional stream type that is not the one a
/// reader wants is.
///
/// Section 9: "An endpoint that receives an unknown stream or datagram type
/// MUST close the session." One sentence, two tables. The stream table assigns
/// SUBGROUP_HEADER and FETCH_HEADER; everything outside those two is unknown at
/// the head of a stream, and the session ends.
///
/// The datagram types are among the values outside them. This draft is the
/// first to give datagrams a table of their own, with numbering independent of
/// the stream table, so a datagram type says nothing about a stream and is not
/// a value the stream table assigns. Draft-07, which numbered both in one
/// table, is the only draft where that is not so.
///
/// A stream announcing the *other* assigned stream type is a different matter
/// and not that rule. The value is one this draft defines, and the disagreement
/// is with the reader that was called rather than with the draft, so the
/// session survives it.
fn stream_type_error(raw: u64) -> CodecError {
    if raw == StreamType::Subgroup as u64 || raw == StreamType::Fetch as u64 {
        CodecError::InvalidField
    } else {
        CodecError::UnknownStreamType(raw)
    }
}

/// Which failure a leading datagram type that is not one a reader wants is.
///
/// The datagram half of the sentence quoted on `stream_type_error`, read
/// against the other table: OBJECT_DATAGRAM and OBJECT_DATAGRAM_STATUS are what
/// it assigns, and everything else arriving as a datagram is unknown.
///
/// Both assigned values are decodable here, so the [`CodecError::InvalidField`]
/// arm is reached only by the stream types — 0x04 and 0x05 — delivered as
/// datagrams. Those are values this draft defines, and refusing them without
/// closing is the same judgement the stream side makes about a datagram type.
fn datagram_type_error(raw: u64) -> CodecError {
    if raw == StreamType::Datagram as u64 || raw == StreamType::DatagramStatus as u64 {
        CodecError::InvalidField
    } else {
        CodecError::UnknownDatagramType(raw)
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

/// Object within a subgroup stream (draft-10).
///
/// Encoding: object_id(vi), extension_headers_length(vi), [extensions...],
///   payload_length(vi),
///   if payload_length == 0: object_status(vi)
///   else: payload bytes
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectHeader {
    /// Object identifier within the subgroup.
    pub object_id: VarInt,
    /// Total byte length of extension headers, as it arrived.
    ///
    /// Advisory on encode. Every encoder here writes
    /// `VarInt::from_usize(self.extensions.len())` and never reads this field,
    /// so a hand-built header whose stated length disagrees with the bytes
    /// beside it goes on the wire with the derived length and is read back
    /// consistent. Decoding always sets the two together, so a value that came
    /// off the wire never disagrees.
    ///
    /// It is kept because it is what the peer stated, which is not always
    /// recoverable from the bytes: a non-minimal varint length encodes the same
    /// number in more bytes, and a relay that must forward the block unchanged
    /// has to know which it saw.
    pub extension_headers_length: VarInt,
    /// Raw extension bytes (opaque).
    pub extensions: Vec<u8>,
    /// Length of the object payload in bytes.
    pub payload_length: VarInt,
    /// Status of this object.
    pub object_status: ObjectStatus,
}

impl SubgroupHeader {
    /// Encode a subgroup stream header including its leading stream-type
    /// field, so the bytes form the start of a data stream a peer can read.
    ///
    /// [`Self::encode`] writes the body alone, which is what a caller wants
    /// once the stream is already open and what a caller must not use for its
    /// first write.
    pub fn encode_stream(&self, buf: &mut impl BufMut) {
        VarInt::from_usize(StreamType::Subgroup as usize).encode(buf);
        self.encode(buf);
    }

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

    /// Decode a subgroup header from the start of a data stream, consuming
    /// the leading stream type varint.
    ///
    /// Errors with [`CodecError::UnknownStreamType`] when the stream type is
    /// one the stream table does not assign, which this draft answers with a
    /// close, and with [`CodecError::InvalidField`] when it is assigned but is
    /// not [`StreamType::Subgroup`]. `stream_type_error` draws that line.
    pub fn decode_stream(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let stream_type = VarInt::decode(buf)?.into_inner();
        if stream_type != StreamType::Subgroup as u64 {
            return Err(stream_type_error(stream_type));
        }
        Self::decode(buf)
    }
}

/// Refuse an end-of-track object that does not end at object zero.
///
/// Section 9.1.1.1 describes Object Status 0x5 as "end of Track. GroupID is one
/// greater than the largest group produced in this track and the ObjectId is
/// zero", and states the consequence: "An object with this status that has a
/// Group ID less than or equal to any other Group ID, or an Object ID other
/// than zero, is a protocol error, and the receiver MUST terminate the
/// session."
///
/// Only the Object ID half is answerable here. The Group ID half compares
/// against the largest group produced on the track, which no single header
/// carries and no reader of one header can know.
///
/// Applied on both sides. A receiver is required to close the session over
/// this, so writing one is not a way to send it.
fn check_end_of_track(object_id: VarInt, status: ObjectStatus) -> Result<(), CodecError> {
    if status == ObjectStatus::EndOfTrack && object_id.into_inner() != 0 {
        return Err(CodecError::EndOfTrackObjectId(object_id.into_inner()));
    }
    Ok(())
}

impl ObjectHeader {
    /// Encode the object header into the buffer.
    pub fn encode(&self, buf: &mut impl BufMut) {
        self.object_id.encode(buf);
        VarInt::from_usize(self.extensions.len()).encode(buf);
        encode_extensions(&self.extensions, buf);
        self.payload_length.encode(buf);
        if self.payload_length.into_inner() == 0 {
            VarInt::from_usize(self.object_status as usize).encode(buf);
        }
    }

    /// Encode the header, refusing a status the framing cannot carry.
    ///
    /// Section 9.4.2 puts the Object Status field on the wire only when the
    /// Object Payload Length is zero, and Section 9.1.1.1 says "Any object
    /// with a status code other than zero MUST have an empty payload". A
    /// non-zero status paired with a non-zero payload length therefore has no
    /// encoding at all: [`Self::encode`] drops the status and the peer reads an
    /// ordinary object, which is a different object from the one the caller
    /// described. This refuses instead.
    ///
    /// The datagram types on this draft already refuse the same pairing. These
    /// two did not, and they are the ones a publisher writes on every stream.
    ///
    /// # Errors
    ///
    /// [`CodecError::InvalidField`] if a non-zero Object Status is paired with
    /// a non-zero Object Payload Length.
    pub fn encode_checked(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        check_end_of_track(self.object_id, self.object_status)?;
        if self.payload_length.into_inner() != 0 && self.object_status as usize != 0 {
            return Err(CodecError::InvalidField);
        }
        self.encode(buf);
        Ok(())
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
        check_end_of_track(object_id, object_status)?;
        Ok(Self { object_id, extension_headers_length, extensions, payload_length, object_status })
    }
}

// ============================================================
// Datagram (type 0x01)
// ============================================================

/// Datagram header with payload (draft-10, type 0x01).
///
/// Draft-09 dropped these two fields and draft-10 keeps them dropped: no
/// `payload_length` and no `object_status`.
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
    /// Total byte length of extension headers, as it arrived.
    ///
    /// Advisory on encode. Every encoder here writes
    /// `VarInt::from_usize(self.extensions.len())` and never reads this field,
    /// so a hand-built header whose stated length disagrees with the bytes
    /// beside it goes on the wire with the derived length and is read back
    /// consistent. Decoding always sets the two together, so a value that came
    /// off the wire never disagrees.
    ///
    /// It is kept because it is what the peer stated, which is not always
    /// recoverable from the bytes: a non-minimal varint length encodes the same
    /// number in more bytes, and a relay that must forward the block unchanged
    /// has to know which it saw.
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
        VarInt::from_usize(self.extensions.len()).encode(buf);
        encode_extensions(&self.extensions, buf);
    }

    /// Encode the datagram header, refusing a status the framing cannot carry.
    ///
    /// Nothing here is ever refused, and that is a fact about draft-10 rather
    /// than a check left out. This is the OBJECT_DATAGRAM of Section 9.2, whose
    /// layout carries no Object Status field at all; a datagram that states a
    /// status is the separate OBJECT_DATAGRAM_STATUS message of Section 9.3,
    /// modelled here as [`DatagramStatusHeader`]. So there is no status for
    /// [`Self::encode`] to drop, and nothing for Section 9.1.1.1's "Any object
    /// with a status code other than zero MUST have an empty payload" to rule
    /// on: an object framed this way has status zero by construction.
    ///
    /// The fallible signature is what lets one entry point span every draft.
    /// `dispatch::AnyDatagramHeader::encode` calls this on all thirteen, and
    /// the drafts whose payload-bearing datagram *does* carry a status field
    /// need somewhere to say no.
    pub fn encode_checked(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        self.encode(buf);
        Ok(())
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

/// Datagram status header (draft-10, type 0x02).
///
/// Draft-09 added `extension_headers_length` here and draft-10 keeps it.
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
    /// Total byte length of extension headers, as it arrived.
    ///
    /// Advisory on encode. Every encoder here writes
    /// `VarInt::from_usize(self.extensions.len())` and never reads this field,
    /// so a hand-built header whose stated length disagrees with the bytes
    /// beside it goes on the wire with the derived length and is read back
    /// consistent. Decoding always sets the two together, so a value that came
    /// off the wire never disagrees.
    ///
    /// It is kept because it is what the peer stated, which is not always
    /// recoverable from the bytes: a non-minimal varint length encodes the same
    /// number in more bytes, and a relay that must forward the block unchanged
    /// has to know which it saw.
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
        VarInt::from_usize(self.extensions.len()).encode(buf);
        encode_extensions(&self.extensions, buf);
        VarInt::from_usize(self.object_status as usize).encode(buf);
    }

    /// Encode the datagram status header, refusing an end-of-track object that
    /// does not end at object zero.
    ///
    /// # Errors
    ///
    /// [`CodecError::EndOfTrackObjectId`] if an end-of-track status is paired
    /// with a non-zero Object ID.
    pub fn encode_checked(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        check_end_of_track(self.object_id, self.object_status)?;
        self.encode(buf);
        Ok(())
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
        check_end_of_track(object_id, object_status)?;
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
// Datagram framing
// ============================================================

/// One datagram, of whichever shape its type field names.
///
/// A MoQT datagram opens with a variable-length integer naming its type, and
/// that integer is what says which of the layouts above follows it.
/// Neither [`DatagramHeader`] nor [`DatagramStatusHeader`] reads or writes it, so neither can be handed
/// the first byte of a datagram a peer sent, and neither produces bytes a peer
/// can read. This is the entry point that does both.
///
/// The payload of a payload-bearing datagram runs to the end of the QUIC
/// datagram, so it is not part of this value: [`Self::decode`] stops at the end
/// of the header and leaves the payload in the buffer, and a caller appends the
/// payload after [`Self::encode`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Datagram {
    /// An object carrying a payload.
    Payload(DatagramHeader),
    /// An object stating a status, with no payload.
    Status(DatagramStatusHeader),
}

impl Datagram {
    /// Whether this datagram states an Object Status instead of carrying a
    /// payload.
    pub fn is_status(&self) -> bool {
        matches!(self, Self::Status(_))
    }

    /// The type field this value writes.
    pub fn datagram_type(&self) -> StreamType {
        match self {
            Self::Payload(_) => StreamType::Datagram,
            Self::Status(_) => StreamType::DatagramStatus,
        }
    }

    /// Decode a datagram from its first byte, type field included.
    ///
    /// Errors with [`CodecError::UnknownDatagramType`] when the leading type is
    /// one the datagram table does not assign, which this draft answers with a
    /// close, and with [`CodecError::InvalidField`] for the stream types, which
    /// it does assign but not to a datagram. `datagram_type_error` draws that
    /// line.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let raw = VarInt::decode(buf)?.into_inner();
        match StreamType::from_id(raw) {
            Some(StreamType::Datagram) => Ok(Self::Payload(DatagramHeader::decode(buf)?)),
            Some(StreamType::DatagramStatus) => {
                Ok(Self::Status(DatagramStatusHeader::decode(buf)?))
            }
            _ => Err(datagram_type_error(raw)),
        }
    }

    /// Encode the datagram, type field included.
    pub fn encode(&self, buf: &mut impl BufMut) {
        VarInt::from_usize(self.datagram_type() as usize).encode(buf);
        match self {
            Self::Payload(header) => header.encode(buf),
            Self::Status(header) => header.encode(buf),
        }
    }

    /// Encode the datagram, refusing a header the framing it names cannot
    /// carry.
    ///
    /// The body is built before anything reaches `buf`, so a refused datagram
    /// leaves `buf` untouched rather than a type field with no body under it.
    pub fn encode_checked(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        let mut body = Vec::with_capacity(64);
        match self {
            Self::Payload(header) => header.encode_checked(&mut body)?,
            Self::Status(header) => header.encode_checked(&mut body)?,
        }
        VarInt::from_usize(self.datagram_type() as usize).encode(buf);
        buf.put_slice(&body);
        Ok(())
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

/// Object within a fetch stream (draft-10).
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
    /// Total byte length of extension headers, as it arrived.
    ///
    /// Advisory on encode. Every encoder here writes
    /// `VarInt::from_usize(self.extensions.len())` and never reads this field,
    /// so a hand-built header whose stated length disagrees with the bytes
    /// beside it goes on the wire with the derived length and is read back
    /// consistent. Decoding always sets the two together, so a value that came
    /// off the wire never disagrees.
    ///
    /// It is kept because it is what the peer stated, which is not always
    /// recoverable from the bytes: a non-minimal varint length encodes the same
    /// number in more bytes, and a relay that must forward the block unchanged
    /// has to know which it saw.
    pub extension_headers_length: VarInt,
    /// Raw extension bytes (opaque).
    pub extensions: Vec<u8>,
    /// Status of this object.
    pub object_status: ObjectStatus,
    /// Length of the object payload in bytes.
    pub payload_length: VarInt,
}

impl FetchHeader {
    /// Encode a fetch stream header including its leading stream-type field,
    /// so the bytes form the start of a data stream a peer can read.
    ///
    /// [`Self::encode`] writes the body alone, which is what a caller wants
    /// once the stream is already open and what a caller must not use for its
    /// first write. The read side has had [`Self::decode_stream`] all along,
    /// so without this the codec could not round-trip its own fetch stream
    /// through its own reader.
    pub fn encode_stream(&self, buf: &mut impl BufMut) {
        VarInt::from_usize(StreamType::Fetch as usize).encode(buf);
        self.encode(buf);
    }

    /// Encode the fetch header into the buffer.
    pub fn encode(&self, buf: &mut impl BufMut) {
        self.subscribe_id.encode(buf);
    }

    /// Decode a fetch header from the buffer.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let subscribe_id = VarInt::decode(buf)?;
        Ok(Self { subscribe_id })
    }

    /// Decode a fetch header from the start of a data stream, consuming the
    /// leading stream type varint.
    ///
    /// Errors with [`CodecError::UnknownStreamType`] when the stream type is
    /// one the stream table does not assign, which this draft answers with a
    /// close, and with [`CodecError::InvalidField`] when it is assigned but is
    /// not [`StreamType::Fetch`]. `stream_type_error` draws that line.
    pub fn decode_stream(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let stream_type = VarInt::decode(buf)?.into_inner();
        if stream_type != StreamType::Fetch as u64 {
            return Err(stream_type_error(stream_type));
        }
        Self::decode(buf)
    }
}

impl FetchObjectHeader {
    /// Encode the fetch object header into the buffer.
    pub fn encode(&self, buf: &mut impl BufMut) {
        self.group_id.encode(buf);
        self.subgroup_id.encode(buf);
        self.object_id.encode(buf);
        buf.put_u8(self.publisher_priority);
        VarInt::from_usize(self.extensions.len()).encode(buf);
        encode_extensions(&self.extensions, buf);
        self.payload_length.encode(buf);
        if self.payload_length.into_inner() == 0 {
            VarInt::from_usize(self.object_status as usize).encode(buf);
        }
    }

    /// Encode the header, refusing a status the framing cannot carry.
    ///
    /// Section 9.4.4 puts the Object Status field on the wire only when the
    /// Object Payload Length is zero, and Section 9.1.1.1 says "Any object
    /// with a status code other than zero MUST have an empty payload". A
    /// non-zero status paired with a non-zero payload length therefore has no
    /// encoding at all: [`Self::encode`] drops the status and the peer reads an
    /// ordinary object, which is a different object from the one the caller
    /// described. This refuses instead.
    ///
    /// The datagram types on this draft already refuse the same pairing. These
    /// two did not, and they are the ones a publisher writes on every stream.
    ///
    /// # Errors
    ///
    /// [`CodecError::InvalidField`] if a non-zero Object Status is paired with
    /// a non-zero Object Payload Length.
    pub fn encode_checked(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        check_end_of_track(self.object_id, self.object_status)?;
        if self.payload_length.into_inner() != 0 && self.object_status as usize != 0 {
            return Err(CodecError::InvalidField);
        }
        self.encode(buf);
        Ok(())
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
        check_end_of_track(object_id, object_status)?;
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

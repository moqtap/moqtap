//! Draft-08 data stream header encoding and decoding.
//!
//! Differences from draft-07:
//! - Object headers include `extension_count` (varint) + raw extension bytes
//! - Separate DatagramStatus type (0x02) for status-only datagrams
//! - Datagram (0x01) includes extension_count + payload

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
/// Section 8: "An endpoint that receives an unknown stream or datagram type
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

// ── Extension helpers ───────────────────────────────────────

/// Skip over extensions in the buffer, reading extension_count varints.
///
/// Extension encoding: for each extension, read type (varint).
/// - Even type: value is a single varint
/// - Odd type: value is length-prefixed bytes (varint length + bytes)
fn skip_extensions(buf: &mut impl Buf, count: u64) -> Result<Vec<u8>, CodecError> {
    let mut raw = Vec::new();
    for _ in 0..count {
        let ext_type = VarInt::decode(buf)?;
        ext_type.encode(&mut raw);
        if ext_type.into_inner().is_multiple_of(2) {
            let val = VarInt::decode(buf)?;
            val.encode(&mut raw);
        } else {
            let len = VarInt::decode(buf)?.into_inner() as usize;
            VarInt::from_usize(len).encode(&mut raw);
            let bytes = read_bytes(buf, len)?;
            raw.extend_from_slice(&bytes);
        }
    }
    Ok(raw)
}

/// Count the extension headers in a raw block, or `None` if the bytes do not
/// tile into whole headers.
///
/// The block is stored opaque, so the number of headers in it is not something
/// the value carries - it is a property of the bytes, recovered by walking them
/// with the same rule [`skip_extensions`] reads them by. This is the only draft
/// that needs it: draft-08 states the field as "Extension Count", a number of
/// headers, and every later draft states a byte length that
/// `extensions.len()` supplies directly.
fn count_extensions(raw: &[u8]) -> Option<u64> {
    let mut buf = raw;
    let mut count: u64 = 0;
    while buf.has_remaining() {
        let ext_type = VarInt::decode(&mut buf).ok()?;
        if ext_type.into_inner().is_multiple_of(2) {
            VarInt::decode(&mut buf).ok()?;
        } else {
            let len = VarInt::decode(&mut buf).ok()?.into_inner() as usize;
            if buf.remaining() < len {
                return None;
            }
            buf.advance(len);
        }
        count = count.checked_add(1)?;
    }
    Some(count)
}

/// Refuse an Extension Count that disagrees with the extension bytes beside it.
///
/// The count and the bytes are two fields with nothing tying them together, and
/// [`skip_extensions`] reads exactly `count` headers on the way back in. A
/// header that states two and carries three leaves the third where the peer
/// expects the Object Payload Length, so every field after it - and every
/// object after that on the same stream - is read at the wrong offset. There is
/// no recovery downstream, which is why this is refused rather than corrected.
fn check_extension_count(stated: VarInt, raw: &[u8]) -> Result<(), CodecError> {
    match count_extensions(raw) {
        Some(actual) if actual == stated.into_inner() => Ok(()),
        _ => Err(CodecError::InvalidField),
    }
}

/// Encode extension bytes back to the buffer.
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

/// Object within a subgroup stream (draft-08).
///
/// Encoding: object_id(vi), extension_count(vi), [extensions...],
///   payload_length(vi),
///   if payload_length == 0: object_status(vi)
///   else: payload bytes
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectHeader {
    /// Object identifier within the subgroup.
    pub object_id: VarInt,
    /// Number of extensions.
    pub extension_count: VarInt,
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
/// Section 8.1.1.1 describes Object Status 0x5 as "end of Track. GroupID is one
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
        self.extension_count.encode(buf);
        encode_extensions(&self.extensions, buf);
        self.payload_length.encode(buf);
        if self.payload_length.into_inner() == 0 {
            VarInt::from_usize(self.object_status as usize).encode(buf);
        }
    }

    /// Encode the header, refusing a status the framing cannot carry.
    ///
    /// Section 8.4.1 puts the Object Status field on the wire only when the
    /// Object Payload Length is zero, and Section 8.1.1.1 says "Any object
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
        check_extension_count(self.extension_count, &self.extensions)?;
        self.encode(buf);
        Ok(())
    }

    /// Decode an object header from the buffer.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let object_id = VarInt::decode(buf)?;
        let extension_count = VarInt::decode(buf)?;
        let extensions = skip_extensions(buf, extension_count.into_inner())?;
        let payload_length = VarInt::decode(buf)?;
        let object_status = if payload_length.into_inner() == 0 {
            let status_val = VarInt::decode(buf)?.into_inner();
            ObjectStatus::from_u64(status_val).ok_or(CodecError::InvalidField)?
        } else {
            ObjectStatus::Normal
        };
        check_end_of_track(object_id, object_status)?;
        Ok(Self { object_id, extension_count, extensions, payload_length, object_status })
    }
}

// ============================================================
// Datagram (type 0x01)
// ============================================================

/// Datagram header with payload (draft-08, type 0x01).
///
/// Encoding (after type varint):
///   track_alias(vi), group_id(vi), object_id(vi),
///   publisher_priority(u8), extension_count(vi), [extensions...],
///   payload_length(vi),
///   if payload_length == 0: object_status(vi),
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
    /// Number of extensions.
    pub extension_count: VarInt,
    /// Raw extension bytes (opaque).
    pub extensions: Vec<u8>,
    /// Status of this object.
    pub object_status: ObjectStatus,
    /// Length of the object payload in bytes.
    pub payload_length: VarInt,
}

impl DatagramHeader {
    /// Encode the datagram header into the buffer.
    ///
    /// The declared payload length is taken as the authority on framing: the
    /// status field is written exactly when that length is zero, because that
    /// is the condition under which the OBJECT_DATAGRAM layout in draft-08
    /// Section 8.2 carries one. That is what makes this infallible — and what
    /// makes it lossy when the struct disagrees with itself. An
    /// `object_status` set alongside a non-zero `payload_length` is discarded
    /// here without a word. Prefer [`Self::encode_checked`], which refuses that
    /// combination instead of resolving it.
    pub fn encode(&self, buf: &mut impl BufMut) {
        self.track_alias.encode(buf);
        self.group_id.encode(buf);
        self.object_id.encode(buf);
        buf.put_u8(self.publisher_priority);
        self.extension_count.encode(buf);
        encode_extensions(&self.extensions, buf);
        self.payload_length.encode(buf);
        if self.payload_length.into_inner() == 0 {
            VarInt::from_usize(self.object_status as usize).encode(buf);
        }
    }

    /// Encode the datagram header, refusing a status the framing cannot carry.
    ///
    /// A datagram states its Object Status only when its Object Payload Length
    /// is zero. With a non-zero length there is no status field on the wire, so
    /// an `object_status` of anything but [`ObjectStatus::Normal`] has nowhere
    /// to go: [`Self::encode`] drops it and the datagram parses back as an
    /// ordinary payload object. An End of Group marker written that way does
    /// not arrive late or malformed — it does not arrive at all, and the
    /// receiver sees a normal object in its place.
    ///
    /// That pair is also the frame draft-08 Section 8.1.1.1 forbids outright:
    /// "Any object with a status code other than zero MUST have an empty
    /// payload." So the refusal here is not merely about what this encoder can
    /// express; there is no conforming datagram to express.
    ///
    /// [`ObjectStatus::Normal`] beside a payload is not that case and is
    /// accepted. It is the status every payload-bearing object has under the
    /// rule above, and the one the encoding elides, so stating it asks for
    /// exactly the bytes leaving it out asks for and nothing is lost.
    ///
    /// Errors with [`CodecError::InvalidField`] on the lossy combination,
    /// before any byte is written, so a refused header leaves `buf` untouched.
    pub fn encode_checked(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        check_end_of_track(self.object_id, self.object_status)?;
        if self.payload_length.into_inner() != 0 && self.object_status != ObjectStatus::Normal {
            return Err(CodecError::InvalidField);
        }
        check_extension_count(self.extension_count, &self.extensions)?;
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
        let extension_count = VarInt::decode(buf)?;
        let extensions = skip_extensions(buf, extension_count.into_inner())?;
        let payload_length = VarInt::decode(buf)?;
        let object_status = if payload_length.into_inner() == 0 {
            let status_val = VarInt::decode(buf)?.into_inner();
            ObjectStatus::from_u64(status_val).ok_or(CodecError::InvalidField)?
        } else {
            ObjectStatus::Normal
        };
        check_end_of_track(object_id, object_status)?;
        Ok(Self {
            track_alias,
            group_id,
            object_id,
            publisher_priority,
            extension_count,
            extensions,
            object_status,
            payload_length,
        })
    }
}

// ============================================================
// Datagram Status (type 0x02)
// ============================================================

/// Datagram status header (draft-08, type 0x02).
///
/// Status-only datagram with no payload or extensions.
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
        let status_val = VarInt::decode(buf)?.into_inner();
        let object_status = ObjectStatus::from_u64(status_val).ok_or(CodecError::InvalidField)?;
        check_end_of_track(object_id, object_status)?;
        Ok(Self { track_alias, group_id, object_id, publisher_priority, object_status })
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
    ///
    /// Draft-08 can say it two ways: on the dedicated status message, and on
    /// the payload message with a declared payload length of zero, which
    /// draft-09 removed.
    pub fn is_status(&self) -> bool {
        match self {
            Self::Payload(header) => header.payload_length.into_inner() == 0,
            Self::Status(_) => true,
        }
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

/// Object within a fetch stream (draft-08).
///
/// Encoding: group_id(vi), subgroup_id(vi), object_id(vi),
///   publisher_priority(u8), extension_count(vi), [extensions...],
///   payload_length(vi),
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
    /// Number of extensions.
    pub extension_count: VarInt,
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
        self.extension_count.encode(buf);
        encode_extensions(&self.extensions, buf);
        self.payload_length.encode(buf);
        if self.payload_length.into_inner() == 0 {
            VarInt::from_usize(self.object_status as usize).encode(buf);
        }
    }

    /// Encode the header, refusing a status the framing cannot carry.
    ///
    /// Section 8.4.3 puts the Object Status field on the wire only when the
    /// Object Payload Length is zero, and Section 8.1.1.1 says "Any object
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
        check_extension_count(self.extension_count, &self.extensions)?;
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
        let extension_count = VarInt::decode(buf)?;
        let extensions = skip_extensions(buf, extension_count.into_inner())?;
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
            extension_count,
            extensions,
            object_status,
            payload_length,
        })
    }
}

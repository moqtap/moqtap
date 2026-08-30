use super::types::ObjectStatus;
use crate::error::CodecError;
use crate::varint::VarInt;
use bytes::{Buf, BufMut};

/// Every type ID this draft's data plane assigns, from the single table it
/// keeps them in.
///
/// Draft-07 Section 7 numbers streams and datagrams together. Its Table 5 is
/// headed "Stream Type" and holds all three assignments — 0x1 OBJECT_DATAGRAM,
/// 0x4 STREAM_HEADER_SUBGROUP, 0x5 FETCH_HEADER — under one sentence: "All
/// unidirectional MOQT streams, as well as all datagrams, start with a
/// variable-length integer indicating the type of the stream in question."
/// Draft-08 is where the two split into tables of their own, after which the
/// numbers are reused across them independently.
///
/// One shared space is what makes 0x1 an assigned value at the head of a
/// unidirectional stream rather than an unknown one. Such a stream is still
/// refused — a datagram type says nothing about how to read a stream — but it
/// is refused as a stream this reader cannot read, not under the
/// unknown-stream-type rule, which would end the session.
///
/// [`StreamType::from_id`] answers over that one table. Callers that need the
/// narrower question, which of these a particular reader will accept, ask
/// `stream_type_error` instead.
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

/// Which failure a leading type that is not the one a reader wants is.
///
/// Section 7: "An endpoint that receives an unknown stream type MUST close the
/// session." That sentence is about values Table 5 does not assign, and Table 5
/// assigns three: OBJECT_DATAGRAM, STREAM_HEADER_SUBGROUP and FETCH_HEADER.
/// Everything outside those three is unknown, and the session ends.
///
/// All three of them, on the other hand, are values this draft defines. A
/// reader handed one it was not written for — a fetch stream at the subgroup
/// reader, or a datagram type at either — is refused, but the disagreement is
/// with the caller rather than with the draft, and the session survives it.
///
/// Draft-07 is the only draft where the datagram types fall on this side of the
/// split, and the reason is the shared table described on [`StreamType`]. From
/// draft-08 on the two tables are separate, and a datagram type at the head of
/// a stream is then genuinely unknown there.
fn stream_type_error(raw: u64) -> CodecError {
    if StreamType::from_id(raw).is_some() {
        CodecError::InvalidField
    } else {
        CodecError::UnknownStreamType(raw)
    }
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
    /// Errors with [`CodecError::UnknownStreamType`] when the leading type is
    /// not one this draft's stream table assigns, and with
    /// [`CodecError::InvalidField`] when it is the other assigned type — a
    /// stream this reader cannot read, but not one the draft asks a session to
    /// be closed over.
    pub fn decode_stream(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let stream_type = VarInt::decode(buf)?.into_inner();
        if stream_type != StreamType::Subgroup as u64 {
            return Err(stream_type_error(stream_type));
        }
        Self::decode(buf)
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

    /// Encode the header, refusing a status the framing cannot carry.
    ///
    /// Section 7.3.1 puts the Object Status field on the wire only when the
    /// Object Payload Length is zero, and Section 7.1.1.1 says "Any object
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
        if self.payload_length.into_inner() != 0 && self.object_status as usize != 0 {
            return Err(CodecError::InvalidField);
        }
        self.encode(buf);
        Ok(())
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
    ///
    /// The declared payload length is taken as the authority on framing: the
    /// status field is written exactly when that length is zero, because that
    /// is the condition under which the OBJECT_DATAGRAM layout in draft-07
    /// Section 7.2 carries one. That is what makes this infallible — and what
    /// makes it lossy when the struct disagrees with itself. An
    /// `object_status` set alongside a non-zero `payload_length` is discarded
    /// here without a word. Prefer [`Self::encode_checked`], which refuses that
    /// combination instead of resolving it.
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
    /// That pair is also the frame draft-07 Section 7.1.1.1 forbids outright:
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
        if self.payload_length.into_inner() != 0 && self.object_status != ObjectStatus::Normal {
            return Err(CodecError::InvalidField);
        }
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
// Datagram framing
// ============================================================

/// One datagram, of whichever shape its type field names.
///
/// A MoQT datagram opens with a variable-length integer naming its type, and
/// that integer is what says which of the layouts above follows it — draft-07 names one datagram type, and this is it.
/// Neither [`DatagramHeader`] nor its type field reads or writes it, so neither can be handed
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
}

impl Datagram {
    /// Whether this datagram states an Object Status instead of carrying a
    /// payload.
    ///
    /// Draft-07 has one datagram layout and hangs the status off a declared
    /// payload length of zero, so the answer is in the body rather than in the
    /// type field.
    pub fn is_status(&self) -> bool {
        match self {
            Self::Payload(header) => header.payload_length.into_inner() == 0,
        }
    }

    /// The type field this value writes.
    pub fn datagram_type(&self) -> StreamType {
        match self {
            Self::Payload(_) => StreamType::Datagram,
        }
    }

    /// Decode a datagram from its first byte, type field included.
    ///
    /// Errors with [`CodecError::UnknownStreamType`] when the leading type is
    /// one Table 5 does not assign, which Section 7 answers with a close, and
    /// with [`CodecError::InvalidField`] when it assigns the value but to a
    /// stream rather than a datagram. `stream_type_error` draws that line, and
    /// names the stream rule for both because draft-07 numbers datagrams in the
    /// stream table.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let raw = VarInt::decode(buf)?.into_inner();
        match StreamType::from_id(raw) {
            Some(StreamType::Datagram) => Ok(Self::Payload(DatagramHeader::decode(buf)?)),
            _ => Err(stream_type_error(raw)),
        }
    }

    /// Encode the datagram, type field included.
    pub fn encode(&self, buf: &mut impl BufMut) {
        VarInt::from_usize(self.datagram_type() as usize).encode(buf);
        match self {
            Self::Payload(header) => header.encode(buf),
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
    /// Errors with [`CodecError::UnknownStreamType`] when the leading type is
    /// not one this draft's stream table assigns, and with
    /// [`CodecError::InvalidField`] when it is the other assigned type — a
    /// stream this reader cannot read, but not one the draft asks a session to
    /// be closed over.
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
        self.payload_length.encode(buf);
        if self.payload_length.into_inner() == 0 {
            VarInt::from_usize(self.object_status as usize).encode(buf);
        }
    }

    /// Encode the header, refusing a status the framing cannot carry.
    ///
    /// Section 7.3.2 puts the Object Status field on the wire only when the
    /// Object Payload Length is zero, and Section 7.1.1.1 says "Any object
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A datagram header for track 1, group 0, object 0, priority 128, holding
    /// `status` and declaring `payload_length` bytes of payload after it.
    fn datagram(status: ObjectStatus, payload_length: u64) -> DatagramHeader {
        DatagramHeader {
            track_alias: VarInt::from_usize(1),
            group_id: VarInt::from_usize(0),
            object_id: VarInt::from_usize(0),
            publisher_priority: 128,
            object_status: status,
            payload_length: VarInt::from_usize(payload_length as usize),
        }
    }

    /// A status a payload-bearing datagram cannot state is refused, not
    /// dropped.
    ///
    /// Draft-07 puts the Object Status field on a datagram only when its Object
    /// Payload Length is zero, so a header holding End of Group under a
    /// non-zero length asks for two framings at once. [`DatagramHeader::encode`]
    /// resolves that by writing the length and leaving the status out, which is
    /// the loss this gate exists for: the datagram that comes back is an
    /// ordinary object and the marker is simply gone, indistinguishable from
    /// one that never carried a status. The second half of the test observes
    /// exactly that, so the gate states the old behaviour as well as the new.
    ///
    /// The statuses are read from `ObjectStatus::ALL` rather than listed here,
    /// so the sweep follows the draft's registry instead of a copy of it.
    /// Normal is exempt and checked separately: draft-07 Section 7.1.1.1 says
    /// "Any object with a status code other than zero MUST have an empty
    /// payload", so Normal is the status every payload-bearing object already
    /// has, and naming it asks for the same bytes as leaving it out.
    ///
    /// # What this catches, observed by making each change and running it
    ///
    /// Dropping the check from `encode_checked`, leaving the payload length to
    /// decide on its own as it did before:
    ///
    /// ```text
    /// encode_checked must refuse ObjectDoesNotExist beside a payload; got Ok(())
    /// ```
    ///
    /// Widening the check to refuse every payload-bearing header, Normal
    /// included:
    ///
    /// ```text
    /// encode_checked refused a Normal object carrying a payload: InvalidField
    /// ```
    #[test]
    fn encode_checked_refuses_a_status_a_payload_hides() {
        for &status in ObjectStatus::ALL {
            if status == ObjectStatus::Normal {
                continue;
            }

            let header = datagram(status, 4);
            let mut refused = Vec::new();
            let result = header.encode_checked(&mut refused);
            assert!(
                matches!(result, Err(CodecError::InvalidField)),
                "encode_checked must refuse {status:?} beside a payload; got {result:?}"
            );
            assert!(refused.is_empty(), "a refused {status:?} header still wrote {refused:?}");

            // What the refusal replaces: the infallible encode writes the
            // header without the status, and it decodes back as Normal.
            let mut dropped = Vec::new();
            header.encode(&mut dropped);
            let decoded = DatagramHeader::decode(&mut &dropped[..])
                .unwrap_or_else(|e| panic!("the lossy encoding of {status:?} must parse: {e:?}"));
            assert_eq!(
                decoded.object_status,
                ObjectStatus::Normal,
                "{status:?} beside a payload is exactly the status `encode` loses"
            );

            // The same status with an empty payload is representable, so it is
            // written and read back unchanged.
            let mut empty = Vec::new();
            datagram(status, 0)
                .encode_checked(&mut empty)
                .unwrap_or_else(|e| panic!("encode_checked refused an empty {status:?}: {e:?}"));
            let decoded = DatagramHeader::decode(&mut &empty[..]).unwrap();
            assert_eq!(decoded.object_status, status, "empty {status:?} lost its status");
        }

        // Normal beside a payload asks for the bytes the encoding already
        // writes for an object with no status field, so it is accepted.
        let mut normal = Vec::new();
        datagram(ObjectStatus::Normal, 4).encode_checked(&mut normal).unwrap_or_else(|e| {
            panic!("encode_checked refused a Normal object carrying a payload: {e:?}")
        });
        let mut plain = Vec::new();
        datagram(ObjectStatus::Normal, 4).encode(&mut plain);
        assert_eq!(normal, plain, "a permitted header must encode exactly as `encode` writes it");
        let decoded = DatagramHeader::decode(&mut &normal[..]).unwrap();
        assert_eq!(decoded.payload_length.into_inner(), 4);
        assert_eq!(decoded.object_status, ObjectStatus::Normal);
    }
}

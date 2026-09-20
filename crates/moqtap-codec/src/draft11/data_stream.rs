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

/// Hold an object to the rule that a non-existent object carries no extensions.
///
/// Section 9.1.1.2: "Any Object may have extension headers except those with
/// Object Status 'Object Does Not Exist'. If an endpoint receives a non-existent
/// Object containing extension headers it MUST close the session with a Protocol
/// Violation."
///
/// The sentence is about a receiver, and it reaches all three carriers that can
/// announce a status: an object on a subgroup stream, an object on a fetch
/// stream, and a status datagram. A plain datagram has no status field, so it
/// is the only carrier that cannot break the rule.
///
/// Reported under [`CodecError::ExtensionsOnNonExistentObject`], which is this
/// rule and nothing else. [`CodecError::InvalidField`] is too coarse for it:
/// shared with a dozen unrelated malformations the draft does not answer with a
/// close, it leaves a caller unable to act on the sentence above.
fn check_extensions_against_status(
    status: ObjectStatus,
    extensions: &[u8],
) -> Result<(), CodecError> {
    if status == ObjectStatus::ObjectDoesNotExist && !extensions.is_empty() {
        return Err(CodecError::ExtensionsOnNonExistentObject(extensions.len()));
    }
    Ok(())
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

    /// True if this subgroup stream type puts an explicit Subgroup ID on the
    /// wire.
    ///
    /// The Subgroup ID Field Present column of the SUBGROUP_HEADER type table
    /// in Section 9.4.2. The other two columns of that row say what the
    /// Subgroup ID *is* where the field is absent — zero, or the first
    /// Object's ID — so this is only about the field, never about the value.
    pub fn writes_subgroup_id(&self) -> bool {
        matches!(self, StreamType::SubgroupExplicit | StreamType::SubgroupExplicitExt)
    }
}

/// Which failure a leading unidirectional stream type that is not the one a
/// reader wants is.
///
/// Section 9: "An endpoint that receives an unknown stream or datagram type
/// MUST close the session." One sentence, two tables. The stream table assigns
/// 0x05 for FETCH_HEADER and the range 0x08 to 0x0D for SUBGROUP_HEADER;
/// everything outside those is unknown at the head of a stream, and the session
/// ends.
///
/// The six subgroup values are one type spread over the combinations of two
/// choices, which is why the range has no holes in it and why a value just past
/// its end — 0x0E — is unknown rather than a subgroup variant this decoder has
/// not learned yet.
///
/// [`StreamType`] holds both tables in one enum because draft-11's numbers do
/// not collide across them, so membership in it is not the question. A datagram
/// type at the head of a stream is unknown there, and this is where that is
/// decided.
fn stream_type_error(raw: u64) -> CodecError {
    match StreamType::from_id(raw) {
        Some(t) if t.is_subgroup() || t == StreamType::Fetch => CodecError::InvalidField,
        _ => CodecError::UnknownStreamType(raw),
    }
}

/// Which failure a leading datagram type that is not one a reader wants is.
///
/// The datagram half of the sentence quoted on `stream_type_error`, read
/// against the other table: 0x00 to 0x03 are what it assigns, and everything
/// else arriving as a datagram is unknown.
///
/// Every assigned datagram value is decodable here, so the
/// [`CodecError::InvalidField`] arm is reached only by the stream types
/// delivered as datagrams — the mirror image of the case above, and refused the
/// same way, without ending the session over a number this draft defines.
fn datagram_type_error(raw: u64) -> CodecError {
    if StreamType::from_id(raw).is_some() {
        CodecError::InvalidField
    } else {
        CodecError::UnknownDatagramType(raw)
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
    /// Encode a subgroup stream header including its leading stream-type
    /// field, so the bytes form the start of a data stream a peer can read.
    ///
    /// [`Self::encode`] writes the body alone, which is what a caller wants
    /// once the stream is already open and what a caller must not use for its
    /// first write. It is also the half that cannot stand on its own here,
    /// because the stream type is what says whether a Subgroup ID follows it
    /// and whether the objects on the stream carry extension headers.
    pub fn encode_stream(&self, buf: &mut impl BufMut) {
        VarInt::from_usize(self.stream_type as usize).encode(buf);
        self.encode(buf);
    }

    /// Encode the subgroup header (always as explicit subgroup_id format).
    /// Encode the header body, without its leading stream-type field.
    ///
    /// Driven by the stream type, and silent about a `subgroup_id` it decides
    /// not to write: on a type whose Subgroup ID Field Present column reads No
    /// the field is dropped, and the peer reads the subgroup the *type* names -
    /// zero, or the first Object's ID - rather than the one in hand. Nothing is
    /// malformed about the result, which is what makes it worth refusing rather
    /// than tolerating. [`Self::encode_checked`] refuses it.
    pub fn encode(&self, buf: &mut impl BufMut) {
        self.track_alias.encode(buf);
        self.group_id.encode(buf);
        if self.stream_type.writes_subgroup_id() {
            self.subgroup_id.encode(buf);
        }
        buf.put_u8(self.publisher_priority);
    }

    /// Encode the header body, refusing a Subgroup ID this stream type has
    /// nowhere to put.
    ///
    /// [`Self::decode_with_type`] leaves the field at zero for every type that
    /// does not carry it, so a decoded header always passes: the refusal is for
    /// a header assembled by hand, where a caller set an ID the type will
    /// discard.
    ///
    /// A zero is accepted under any type. It is what the decoder produces, and
    /// on a Subgroup ID Value column reading `0` it is also the truth, so
    /// refusing it would refuse the ordinary case to catch nothing.
    ///
    /// # Errors
    ///
    /// [`CodecError::InvalidField`] if a non-zero Subgroup ID sits under a
    /// stream type that writes no Subgroup ID field.
    pub fn encode_checked(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        if !self.stream_type.writes_subgroup_id() && self.subgroup_id.into_inner() != 0 {
            return Err(CodecError::InvalidField);
        }
        self.encode(buf);
        Ok(())
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

    /// Decode a subgroup header from the start of a data stream, consuming
    /// the leading stream type varint and using it to select the variant.
    ///
    /// Errors with [`CodecError::UnknownStreamType`] when the stream table does
    /// not assign the leading type, which this draft answers with a close, and
    /// with [`CodecError::InvalidField`] when it does assign it but not to a
    /// subgroup. `stream_type_error` draws that line.
    pub fn decode_stream(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let raw = VarInt::decode(buf)?.into_inner();
        let stream_type = StreamType::from_id(raw).ok_or_else(|| stream_type_error(raw))?;
        if !stream_type.is_subgroup() {
            return Err(stream_type_error(raw));
        }
        Self::decode_with_type(stream_type, buf)
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
    /// Encode the object header in the framing that carries no extension
    /// block.
    ///
    /// Lossy, and lossy in a way the caller cannot see: an object holding
    /// extension headers is written without them and without a word. Which
    /// framing is correct is not a property of the object at all - Section
    /// 9.4.2 gives the stream's type an Extensions Present column, and every
    /// object on the stream follows it - so this entry point can only guess,
    /// and it guesses "absent". Prefer [`Self::encode_with_extensions`], which
    /// is told, or [`Self::encode_checked`], which refuses what it would
    /// otherwise drop.
    pub fn encode(&self, buf: &mut impl BufMut) {
        self.encode_with_extensions(false, buf);
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
    /// Extension headers are refused here rather than dropped, for a reason
    /// the status rule does not share: this entry point writes the framing
    /// that has no Extension Headers Length field, so the bytes have nowhere
    /// to go. Writing them anyway is not an option and losing them silently
    /// puts a stream on the wire that no reader can follow - a reader on an
    /// extensions-bearing stream takes the Object Payload Length as the
    /// extension length and every object after it is misread. A caller that
    /// knows the stream's framing wants
    /// [`Self::encode_checked_with_extensions`].
    ///
    /// # Errors
    ///
    /// [`CodecError::InvalidField`] if a non-zero Object Status is paired with
    /// a non-zero Object Payload Length, or if the object carries extension
    /// headers this framing cannot write.
    pub fn encode_checked(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        self.encode_checked_with_extensions(false, buf)
    }

    /// Encode the object header into a stream whose type has already settled
    /// whether objects carry an extension block, refusing what that framing
    /// cannot express.
    ///
    /// `has_extensions` is the stream's answer, not the object's: Section
    /// 9.4.2 fixes it for the whole stream from the SUBGROUP_HEADER type, so
    /// an object with no extensions on a stream that carries them still writes
    /// a length of zero, and that is the one direction not refused here. The
    /// other direction has no encoding, so it is refused.
    ///
    /// # Errors
    ///
    /// [`CodecError::InvalidField`] if a non-zero Object Status is paired with
    /// a non-zero Object Payload Length, or if `has_extensions` is `false`
    /// while the object carries extension headers.
    pub fn encode_checked_with_extensions(
        &self,
        has_extensions: bool,
        buf: &mut impl BufMut,
    ) -> Result<(), CodecError> {
        if self.payload_length.into_inner() != 0 && self.object_status as usize != 0 {
            return Err(CodecError::InvalidField);
        }
        if !has_extensions && !self.extensions.is_empty() {
            return Err(CodecError::InvalidField);
        }
        self.encode_with_extensions(has_extensions, buf);
        Ok(())
    }

    /// Encode the object header, writing the extension block only when the
    /// stream's type says objects carry one.
    ///
    /// Infallible, and so unable to say that a `false` here discards the
    /// extension headers the object holds. [`Self::encode_checked_with_extensions`]
    /// is the same write with that refusal in front of it.
    pub fn encode_with_extensions(&self, has_extensions: bool, buf: &mut impl BufMut) {
        self.object_id.encode(buf);
        if has_extensions {
            VarInt::from_usize(self.extensions.len()).encode(buf);
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
        check_extensions_against_status(object_status, &extensions)?;
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
    /// Encode the datagram header in the framing that carries no extension
    /// block.
    ///
    /// Lossy in the same way the subgroup object header is: an extension block
    /// this value holds is dropped, because the framing being written has no
    /// field for it. The type byte decides which framing is right, and this
    /// entry point does not write the type byte, so it cannot consult it.
    /// [`Datagram::encode`] does both together and never disagrees with itself;
    /// this is the piece for a caller that has already written the type.
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
            VarInt::from_usize(self.extensions.len()).encode(buf);
            buf.put_slice(&self.extensions);
        }
    }

    /// Encode the datagram header, refusing what this framing cannot carry.
    ///
    /// No status is ever refused, and that is a fact about this draft rather
    /// than a check left out. This is the OBJECT_DATAGRAM of Section 9.2,
    /// whose layout carries no Object Status field at all; a datagram that
    /// states a status is the separate OBJECT_DATAGRAM_STATUS message, modelled
    /// here as [`DatagramStatusHeader`]. So there is no status for
    /// [`Self::encode`] to drop, and nothing for Section 9.1.1.1's "Any object
    /// with a status code other than zero MUST have an empty payload" to rule
    /// on: an object framed this way has status zero by construction.
    ///
    /// The extension block is a different matter. [`Self::encode`] writes the
    /// framing without one, so a block this value holds has nowhere to go, and
    /// dropping it silently is what puts a datagram on the wire describing
    /// something other than what the caller built. That is refused here.
    ///
    /// The fallible signature is also what lets one entry point span every
    /// draft. `dispatch::AnyDatagramHeader::encode` calls this on all thirteen,
    /// and the drafts whose payload-bearing datagram *does* carry a status field
    /// need somewhere to say no.
    ///
    /// # Errors
    ///
    /// [`CodecError::InvalidField`] if the value carries extension headers,
    /// which this framing has no field for.
    pub fn encode_checked(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        if !self.extensions.is_empty() {
            return Err(CodecError::InvalidField);
        }
        self.encode(buf);
        Ok(())
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
            // A datagram whose type says extensions are present must actually carry
            // some: receiving one with an Extension Headers Length of 0 closes the
            // session. The opposite holds on a subgroup stream, where the type byte is
            // fixed for the whole stream and an object with no extensions has no other
            // way to say so, which is why this check belongs to the datagram readers
            // alone.
            if ehl.into_inner() == 0 {
                return Err(CodecError::InvalidField);
            }
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

    /// Encode the status datagram header, refusing an extension block this
    /// framing cannot carry.
    ///
    /// The same one-sided rule the payload-bearing header obeys, and the same
    /// reason for it: [`Self::encode`] writes the framing without a block, so
    /// bytes held here would be dropped rather than written.
    ///
    /// # Errors
    ///
    /// [`CodecError::InvalidField`] if the value carries extension headers.
    pub fn encode_checked(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        if !self.extensions.is_empty() {
            return Err(CodecError::InvalidField);
        }
        self.encode(buf);
        Ok(())
    }

    /// Encode the datagram status header with extensions control.
    pub fn encode_with_extensions(&self, has_extensions: bool, buf: &mut impl BufMut) {
        self.track_alias.encode(buf);
        self.group_id.encode(buf);
        self.object_id.encode(buf);
        buf.put_u8(self.publisher_priority);
        if has_extensions {
            VarInt::from_usize(self.extensions.len()).encode(buf);
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
            // A datagram whose type says extensions are present must actually carry
            // some: receiving one with an Extension Headers Length of 0 closes the
            // session. The opposite holds on a subgroup stream, where the type byte is
            // fixed for the whole stream and an object with no extensions has no other
            // way to say so, which is why this check belongs to the datagram readers
            // alone.
            if ehl.into_inner() == 0 {
                return Err(CodecError::InvalidField);
            }
            let ext = read_extension_bytes(buf, ehl.into_inner())?;
            (ehl, ext)
        } else {
            (VarInt::from_usize(0), Vec::new())
        };
        let sv = VarInt::decode(buf)?.into_inner();
        let object_status = ObjectStatus::from_u64(sv).ok_or(CodecError::InvalidField)?;
        check_extensions_against_status(object_status, &extensions)?;
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
/// that integer is what says which of the layouts above follows it, and whether an extension block sits inside it.
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
    ///
    /// The extensions bit is taken from the extension bytes themselves rather
    /// than from the declared length beside them, which is what keeps the type
    /// and the body from contradicting each other: a datagram whose type
    /// announces extensions and then declares a length of 0 closes the session
    /// on receipt, and one that announces none has nowhere to put them.
    pub fn datagram_type(&self) -> StreamType {
        match self {
            Self::Payload(header) => {
                if header.extensions.is_empty() {
                    StreamType::Datagram
                } else {
                    StreamType::DatagramExt
                }
            }
            Self::Status(header) => {
                if header.extensions.is_empty() {
                    StreamType::DatagramStatus
                } else {
                    StreamType::DatagramStatusExt
                }
            }
        }
    }

    /// Decode a datagram from its first byte, type field included.
    ///
    /// Errors with [`CodecError::UnknownDatagramType`] when the datagram table
    /// does not assign the leading type, which this draft answers with a close,
    /// and with [`CodecError::InvalidField`] for the stream types, which it
    /// does assign but not to a datagram. `datagram_type_error` draws that
    /// line.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let raw = VarInt::decode(buf)?.into_inner();
        let stream_type = StreamType::from_id(raw).ok_or_else(|| datagram_type_error(raw))?;
        let has_extensions = stream_type.has_extensions();
        match stream_type {
            StreamType::Datagram | StreamType::DatagramExt => {
                Ok(Self::Payload(DatagramHeader::decode_with_extensions(has_extensions, buf)?))
            }
            StreamType::DatagramStatus | StreamType::DatagramStatusExt => {
                Ok(Self::Status(DatagramStatusHeader::decode_with_extensions(has_extensions, buf)?))
            }
            _ => Err(datagram_type_error(raw)),
        }
    }

    /// Encode the datagram, type field included.
    pub fn encode(&self, buf: &mut impl BufMut) {
        let stream_type = self.datagram_type();
        let has_extensions = stream_type.has_extensions();
        VarInt::from_usize(stream_type as usize).encode(buf);
        match self {
            Self::Payload(header) => header.encode_with_extensions(has_extensions, buf),
            Self::Status(header) => header.encode_with_extensions(has_extensions, buf),
        }
    }

    /// Encode the datagram, refusing a header the framing it names cannot
    /// carry.
    ///
    /// The body is built before anything reaches `buf`, so a refused datagram
    /// leaves `buf` untouched rather than a type field with no body under it.
    pub fn encode_checked(&self, buf: &mut impl BufMut) -> Result<(), CodecError> {
        let mut body = Vec::with_capacity(64);
        let stream_type = self.datagram_type();
        let has_extensions = stream_type.has_extensions();
        match self {
            Self::Payload(header) => header.encode_with_extensions(has_extensions, &mut body),
            Self::Status(header) => {
                check_extensions_against_status(header.object_status, &header.extensions)?;
                header.encode_with_extensions(has_extensions, &mut body);
            }
        }
        VarInt::from_usize(stream_type as usize).encode(buf);
        buf.put_slice(&body);
        Ok(())
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
    /// Raw extension bytes.
    pub extensions: Vec<u8>,
    /// Length of the object payload in bytes.
    pub payload_length: VarInt,
    /// Object status (Normal unless payload_length == 0).
    pub object_status: ObjectStatus,
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

    /// Encode the fetch header.
    pub fn encode(&self, buf: &mut impl BufMut) {
        self.request_id.encode(buf);
    }

    /// Decode a fetch header.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let request_id = VarInt::decode(buf)?;
        Ok(Self { request_id })
    }

    /// Decode a fetch header from the start of a data stream, consuming the
    /// leading stream type varint.
    ///
    /// Errors with [`CodecError::UnknownStreamType`] when the stream table does
    /// not assign the leading type, which this draft answers with a close, and
    /// with [`CodecError::InvalidField`] when it is assigned but is not
    /// [`StreamType::Fetch`]. `stream_type_error` draws that line.
    pub fn decode_stream(buf: &mut impl Buf) -> Result<Self, CodecError> {
        let stream_type = VarInt::decode(buf)?.into_inner();
        if stream_type != StreamType::Fetch as u64 {
            return Err(stream_type_error(stream_type));
        }
        Self::decode(buf)
    }
}

impl FetchObjectHeader {
    /// Encode the fetch object header.
    pub fn encode(&self, buf: &mut impl BufMut) {
        self.group_id.encode(buf);
        self.subgroup_id.encode(buf);
        self.object_id.encode(buf);
        buf.put_u8(self.publisher_priority);
        VarInt::from_usize(self.extensions.len()).encode(buf);
        buf.put_slice(&self.extensions);
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
        if self.payload_length.into_inner() != 0 && self.object_status as usize != 0 {
            return Err(CodecError::InvalidField);
        }
        self.encode(buf);
        Ok(())
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
        check_extensions_against_status(object_status, &extensions)?;
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
